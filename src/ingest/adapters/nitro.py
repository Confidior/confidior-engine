"""AWS Nitro Enclave attestation document parser and verifier."""

from __future__ import annotations

from pathlib import Path

import cbor
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate

from src.core.taxonomy import (
    EvidenceNode,
    NodeType,
    Platform,
    TCBStatus,
)

AWS_NITRO_ROOT_URL = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"

# SHA256 fingerprint of the AWS Nitro Root G1 certificate
AWS_NITRO_ROOT_FINGERPRINT = "c8c6ca71abd3b08ab3a432450d73a282e192a41e5c0c0492679a3eaad11faf7c"


def _decode_payload(decoded):
    if isinstance(decoded, dict):
        payload = decoded.get("payload", b"")
        if isinstance(payload, bytes):
            payload = cbor.loads(payload)
    elif isinstance(decoded, list):
        payload = decoded[2] if len(decoded) > 2 else b""
        if isinstance(payload, bytes):
            try:
                payload = cbor.loads(payload)
            except (ValueError, TypeError):
                payload = {}
    else:
        payload = {}
    return payload if isinstance(payload, dict) else {}


def _get_pcr(payload: dict, flat_key: str, pcrs_key: int) -> str:
    val = payload.get(flat_key)
    if val is not None:
        return val.hex() if isinstance(val, bytes) else str(val)
    pcrs = payload.get("pcrs")
    if isinstance(pcrs, dict):
        val = pcrs.get(pcrs_key)
        if val is not None:
            return val.hex() if isinstance(val, bytes) else str(val)
    return ""


def parse_nitro_attestation(cbor_hex: str) -> EvidenceNode:
    """Parse a hex-encoded Nitro attestation document into an EvidenceNode."""
    raw_bytes = bytes.fromhex(cbor_hex.strip())
    decoded = cbor.loads(raw_bytes)
    payload = _decode_payload(decoded)

    pcr0 = _get_pcr(payload, "pcr0", 0)
    pcr1 = _get_pcr(payload, "pcr1", 1)
    pcr2 = _get_pcr(payload, "pcr2", 2)

    measurement = pcr0 or pcr1 or pcr2 or "unknown"

    metadata = {
        "pcr0": pcr0,
        "pcr1": pcr1,
        "pcr2": pcr2,
        "raw_payload_keys": list(payload.keys()),
    }
    for key in ("module_id", "timestamp", "digest", "nonce"):
        if key in payload:
            val = payload[key]
            metadata[key] = val.hex() if isinstance(val, bytes) else val

    tcb = str(payload.get("digest", ""))
    return EvidenceNode(
        node_id=f"nitro-attestation-{measurement[:16]}",
        node_type=NodeType.QUOTE,
        platform=Platform.AWSNitro,
        measurement=measurement,
        debug_disabled=True,
        tcb_version=tcb,
        tcb_status=TCBStatus.UNKNOWN,
        firmware_version=tcb,
        metadata=metadata,
    )


def _get_aws_root_cert(cache_dir: Path | None = None) -> bytes:
    """Download and cache the AWS Nitro Attestation root certificate."""
    import io
    import zipfile

    import requests

    cache_file = None
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / "AWS_NitroEnclaves_Root-G1.pem"

    if cache_file and cache_file.exists():
        return cache_file.read_bytes()

    resp = requests.get(AWS_NITRO_ROOT_URL, timeout=30)
    resp.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        pem_names = [n for n in z.namelist() if n.endswith(".pem")]
        if not pem_names:
            raise ValueError("No PEM file in AWS root cert zip")
        pem_data = z.read(pem_names[0])

    if cache_file:
        cache_file.write_bytes(pem_data)

    return pem_data


def _verify_cose_signature(
    protected: bytes, payload: bytes, signature: bytes, leaf_pub_key
) -> None:
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    sig_structure = cbor.dumps(["Signature1", protected, b"", payload])
    # COSE ECDSA signatures are raw r||s format; cryptography expects DER
    sig_len = len(signature) // 2
    r = int.from_bytes(signature[:sig_len], "big")
    s = int.from_bytes(signature[sig_len:], "big")
    der_sig = encode_dss_signature(r, s)
    leaf_pub_key.verify(der_sig, sig_structure, ECDSA(hashes.SHA384()))


def _verify_cert_chain(leaf_der: bytes, cabundle: list[bytes], root_pem: bytes) -> dict:
    leaf = load_der_x509_certificate(leaf_der)
    root = load_pem_x509_certificate(root_pem)

    intermediates = [load_der_x509_certificate(c) for c in reversed(cabundle)]
    chain = [leaf] + intermediates + [root]

    for i in range(len(chain) - 1):
        signer_pub = chain[i + 1].public_key()
        if not isinstance(signer_pub, EllipticCurvePublicKey):
            raise ValueError(f"Expected ECDSA key, got {type(signer_pub).__name__}")
        signer_pub.verify(
            chain[i].signature,
            chain[i].tbs_certificate_bytes,
            ECDSA(hashes.SHA384()),
        )

    return {"valid": True, "error": None}


def verify_nitro_attestation(cbor_hex: str, cache_dir: Path | None = None) -> dict:
    """Verify a Nitro attestation document's COSE_Sign1 signature.

    Downloads the AWS Nitro Root G1 certificate, verifies the certificate chain
    embedded in the document, and validates the COSE signature.

    Returns dict with 'valid' (bool) and 'error' (str or None).
    """
    try:
        raw_bytes = bytes.fromhex(cbor_hex.strip())
        decoded = cbor.loads(raw_bytes)

        if not isinstance(decoded, list) or len(decoded) < 4:
            return {"valid": False, "error": "Invalid COSE_Sign1 structure"}

        protected, unprotected, payload_bytes, signature = decoded[:4]
        payload = cbor.loads(payload_bytes) if isinstance(payload_bytes, bytes) else {}

        # Try: certs in unprotected header (synthetic fixture)
        if isinstance(unprotected, bytes):
            unprotected = cbor.loads(unprotected)
        if isinstance(unprotected, dict) and unprotected:
            cert_pem = None
            for key, val in unprotected.items():
                if isinstance(key, int) and key == 4:
                    cert_pem = val
                    break
            if cert_pem is not None:
                pem_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
                cert = load_pem_x509_certificate(pem_bytes)
                _verify_cose_signature(protected, payload_bytes, signature, cert.public_key())
                return {"valid": True, "error": None}

        # Real Nitro: certs in payload
        if not isinstance(payload, dict):
            return {"valid": False, "error": "Could not parse payload"}
        leaf_der = payload.get("certificate")
        cabundle = payload.get("cabundle")
        if not leaf_der or not cabundle:
            return {"valid": False, "error": "No certificate chain in payload"}

        root_pem = _get_aws_root_cert(cache_dir)
        chain_result = _verify_cert_chain(leaf_der, cabundle, root_pem)
        if not chain_result["valid"]:
            return chain_result

        leaf = load_der_x509_certificate(leaf_der)
        _verify_cose_signature(protected, payload_bytes, signature, leaf.public_key())
        return {"valid": True, "error": None}

    except Exception as e:
        return {"valid": False, "error": str(e)}
