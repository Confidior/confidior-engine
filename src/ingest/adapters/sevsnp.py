from __future__ import annotations

import json
import re
import tempfile
import urllib.request
import warnings
from contextlib import contextmanager
from pathlib import Path

from sev_pytools.attestation_report import AttestationReport
from sev_pytools.fetch import CertFormat, ProcType, fetch_vcek

from src.core.taxonomy import (
    EvidenceNode,
    NodeType,
    Platform,
    TCBStatus,
)

_PRODUCT_MAP = {
    "milan": ProcType.MILAN,
    "genoa": ProcType.GENOA,
    "turin": ProcType.TURIN,
}

# AMD KDS endpoint uses PascalCase product names
_VLEK_PRODUCT_MAP = {
    "milan": "Milan",
    "genoa": "Genoa",
    "turin": "Turin",
}


@contextmanager
def _suppress_amd_cert_warning():
    """Suppress cryptography UserWarning for AMD SEV-SNP cert serial=0."""
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", category=UserWarning,
            message=".*serial number.*",
        )
        yield


def parse_sevsnp_report(hex_data: str) -> EvidenceNode:
    raw_bytes = bytes.fromhex(hex_data.strip())
    report = AttestationReport.unpack(raw_bytes)

    tcb_version = f"{report.current_tcb.bootloader}.{report.current_tcb.tee}.{report.current_tcb.snp}.{report.current_tcb.microcode}"

    return EvidenceNode(
        node_id=f"sevsnp-report-{report.measurement[:8].hex()}",
        node_type=NodeType.QUOTE,
        platform=Platform.AMDSEVSNP,
        measurement=report.measurement.hex(),
        debug_disabled=(report.policy.value & 0x01) == 0,
        tcb_version=tcb_version,
        tcb_status=TCBStatus.UNKNOWN,
        firmware_version=tcb_version,
        metadata={
            "version": report.version,
            "guest_svn": report.guest_svn,
            "vmpl": report.vmpl,
            "chip_id": report.chip_id.hex() if report.chip_id else None,
            "report_id": report.report_id.hex(),
            "host_data": report.host_data.hex(),
        },
    )


def verify_sevsnp_report(
    hex_data: str,
    product: str = "genoa",
    cert_dir: Path | None = None,
    vlek_cert: Path | None = None,
) -> dict:
    """Verify an SEV-SNP attestation report against AMD's certificate chain.

    For AWS instances (VLEK), pass a vlek_cert path to skip VCEK KDS lookup
    and use the platform-wide VLEK cert chain instead.

    Returns dict with 'valid' (bool) and 'error' (str or None).
    """
    raw_bytes = bytes.fromhex(hex_data.strip())

    proc = _PRODUCT_MAP.get(product)
    if proc is None:
        return {"valid": False, "error": f"Unknown processor model: {product}"}

    tmpdir = cert_dir or Path(tempfile.mkdtemp())
    tmpdir.mkdir(parents=True, exist_ok=True)

    report_path = tmpdir / "guest_report.bin"
    report_path.write_bytes(raw_bytes)

    if vlek_cert is not None:
        err = _prepare_vlek_certs(tmpdir, product, vlek_cert)
        if err:
            return {"valid": False, "error": err}
    else:
        try:
            fetch_vcek(CertFormat.DER, proc, str(tmpdir), str(report_path))
        except Exception as e:
            return {"valid": False, "error": f"Failed to fetch VCEK: {e}"}

    try:
        from sev_pytools.certs import load_certificates

        with _suppress_amd_cert_warning():
            certs = load_certificates(tmpdir)

        if vlek_cert is not None:
            err = _verify_report_vlek(raw_bytes, certs)
        else:
            from sev_pytools import cert_verify_attestation_report
            from sev_pytools.certs import load_crl

            crl_path = tmpdir / "crl.pem"
            if crl_path.exists():
                crl = load_crl(tmpdir)
            else:
                crl = None

            report = AttestationReport.unpack(raw_bytes)
            cert_verify_attestation_report(report, certs, crl)
            err = None

        if err:
            return {"valid": False, "error": err}
        return {"valid": True, "error": None}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def _prepare_vlek_certs(
    tmpdir: Path,
    product: str,
    vlek_cert: Path,
    chain_path: Path | None = None,
) -> str | None:
    """Set up VLEK certs for verification: download chain, place VLEK.

    Downloads the VLEK cert chain (ARK + ASK) from AMD KDS, splits into
    separate PEM files, and copies the VLEK cert as ``vcek.pem`` so
    ``sev_pytools.certs.load_certificates`` can find all three.

    If *chain_path* is provided, reads the chain from disk instead of
    fetching from AMD KDS (useful for offline/cached use).
    """
    vlek_data = vlek_cert.read_bytes()
    (tmpdir / "vcek.pem").write_bytes(vlek_data)

    if chain_path is not None:
        chain_pem = chain_path.read_bytes()
    else:
        sidecar = vlek_cert.parent / "vlek_chain.pem"
        if sidecar.exists():
            chain_pem = sidecar.read_bytes()
        else:
            kds_product = _VLEK_PRODUCT_MAP.get(product, product)
            url = f"https://kdsintf.amd.com/vlek/v1/{kds_product}/cert_chain"
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req) as resp:
                    chain_pem = resp.read()
            except Exception as e:
                return f"Failed to download VLEK cert chain: {e}"

    pem_certs = re.findall(
        b"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
        chain_pem,
        re.DOTALL,
    )
    if len(pem_certs) < 2:
        return f"VLEK chain has {len(pem_certs)} certs, expected >= 2 (ARK + ASK)"

    ark_saved = False
    ask_saved = False
    for cert_pem in pem_certs:
        from cryptography import x509
        with _suppress_amd_cert_warning():
            cert = x509.load_pem_x509_certificate(cert_pem)
        if cert.issuer == cert.subject:
            (tmpdir / "ark.pem").write_bytes(cert_pem)
            ark_saved = True
        else:
            (tmpdir / "ask.pem").write_bytes(cert_pem)
            ask_saved = True

    if not ark_saved:
        return "No self-signed (ARK) certificate found in VLEK chain"
    if not ask_saved:
        return "No intermediate (ASK) certificate found in VLEK chain"
    return None


def _verify_report_vlek(raw_bytes: bytes, certs: dict) -> str | None:
    """Verify an SEV-SNP report using a VLEK certificate (VCEK-free path).

    AWS instances use platform-wide VLEK certs that lack the chip-ID extension
    required by ``sev_pytools.cert_verify_report_components``. This function
    performs the same cryptographic checks without the chip-ID match:

    1. Certificate chain trust: ARK → ASK → VLEK
    2. ECDSA P-384 signature on the first 672 bytes of the report
    """
    from sev_pytools.verify import verify_certificate_chain
    from sev_pytools.attestation_report import AttestationReport

    try:
        with _suppress_amd_cert_warning():
            verify_certificate_chain(certs)
    except Exception as e:
        return f"Certificate chain verification failed: {e}"

    vcek_cert = certs["vcek"]
    public_key = vcek_cert.public_key()

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.exceptions import InvalidSignature

    report = AttestationReport.unpack(raw_bytes)
    report_bytes = report.to_bytes()
    signed_bytes = report_bytes[:672]

    r = int.from_bytes(report.signature.get_trimmed_r(), "little")
    s = int.from_bytes(report.signature.get_trimmed_s(), "little")
    signature = utils.encode_dss_signature(r, s)

    try:
        public_key.verify(signature, signed_bytes, ec.ECDSA(hashes.SHA384()))
        return None
    except InvalidSignature:
        return "ECDSA P-384 signature verification failed"
    except Exception as e:
        return f"Signature verification error: {e}"
