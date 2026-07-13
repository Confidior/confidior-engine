"""DSSE (Dead Simple Signing Envelope) bundle creation, signing, and Rekor anchoring."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.core.attacks import compute_attack_db_snapshot
from src.core.taxonomy import (
    AssuranceEvaluation,
    EvidenceBundle,
    EvidenceGraph,
    PolicyEvaluation,
    RekorEntry,
    Signature,
)

logger = logging.getLogger(__name__)

DSSE_PAYLOAD_TYPE = "application/vnd.confidior.evidence-bundle+json"


def generate_ed25519_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def load_or_create_keypair(
    key_path: str | Path,
) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, bool]:
    """Load an Ed25519 keypair from disk, or create + save one if missing.

    Storage format (JSON):
        {
          "algorithm": "Ed25519",
          "private_key_hex": "...",
          "public_key_hex": "...",
          "created_at": "2026-06-21T..."
        }

    File permissions are restricted to 0o600 (owner read/write only) on POSIX.

    Returns (private_key, public_key, is_new). The third value indicates whether
    a new keypair was generated (True) or an existing one was loaded (False).
    """
    key_path = Path(key_path)
    if key_path.exists():
        data = json.loads(key_path.read_text())
        private_bytes = bytes.fromhex(data["private_key_hex"])
        public_bytes = bytes.fromhex(data["public_key_hex"])
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        return private_key, public_key, False

    private_key, public_key = generate_ed25519_keypair()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(json.dumps({
        "algorithm": "Ed25519",
        "private_key_hex": private_bytes.hex(),
        "public_key_hex": public_bytes.hex(),
        "created_at": datetime.now().isoformat(),
    }, indent=2))
    try:
        key_path.chmod(0o600)
    except (OSError, NotImplementedError):
        pass
    return private_key, public_key, True


def serialize_bundle_for_signing(bundle: EvidenceBundle) -> bytes:
    payload = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "bundle": bundle.to_dict(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _serialize_signed_payload(bundle: EvidenceBundle) -> bytes:
    """Serialize the bundle as it was when signed (signatures field empty).

    Used for Rekor submission — we anchor the signed payload, not the bundle
    with its own signature appended (which would create a self-referential loop).
    """
    bundle_dict = bundle.to_dict()
    bundle_dict["signatures"] = []
    payload = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "bundle": bundle_dict,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_bundle(bundle: EvidenceBundle, private_key: ed25519.Ed25519PrivateKey) -> EvidenceBundle:
    pre_auth = serialize_bundle_for_signing(bundle)
    signature = private_key.sign(pre_auth)

    sig = Signature(
        key_id=private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex(),
        algorithm="Ed25519",
        signature_hex=signature.hex(),
    )
    bundle.signatures.append(sig)
    return bundle


def anchor_to_rekor(
    bundle: EvidenceBundle,
    signature_index: int = 0,
    rekor_url: str | None = None,
    poster: Any = None,
    timeout: float = 10.0,
) -> EvidenceBundle:
    """Anchor a signed bundle to Sigstore Rekor.

    Builds a DSSE entry from the signed payload + signature bytes, submits to
    Rekor, and attaches the resulting RekorEntry to the signature.

    Fails soft: if Rekor submission errors, the bundle is returned unchanged
    (signed but unanchored) and a warning is logged. The bundle is still valid;
    the inclusion proof is just missing.
    """
    from src.export.rekor import RekorError, build_dsse_entry, get_rekor_url, submit_entry

    if not bundle.signatures:
        raise ValueError("Bundle has no signatures; cannot anchor to Rekor")

    sig = bundle.signatures[signature_index]
    signed_bytes = _serialize_signed_payload(bundle)
    signature_bytes = bytes.fromhex(sig.signature_hex)
    entry = build_dsse_entry(signed_bytes, signature_bytes)

    try:
        if rekor_url is None:
            rekor_url = get_rekor_url()
        result = submit_entry(entry, rekor_url, poster=poster, timeout=timeout)
    except RekorError as e:
        logger.warning("Rekor submission failed: %s. Bundle is signed but not anchored.", e)
        return bundle

    new_rekor = RekorEntry(
        log_index=result["logIndex"],
        log_id=result.get("logID", ""),
        entry_uuid=result["uuid"],
        integrated_time=datetime.fromtimestamp(result["integratedTime"]),
    )

    new_sig = Signature(
        key_id=sig.key_id,
        algorithm=sig.algorithm,
        signature_hex=sig.signature_hex,
        rekor_entry=new_rekor,
    )
    bundle.signatures[signature_index] = new_sig
    return bundle


def create_signed_bundle(
    graph: EvidenceGraph,
    policy_eval: PolicyEvaluation | None,
    assurance: AssuranceEvaluation,
    workload: str = "unknown",
    ttl_days: int = 30,
    private_key: ed25519.Ed25519PrivateKey | None = None,
    enable_rekor_anchoring: bool = False,
    rekor_url: str | None = None,
    rekor_poster: Any = None,
) -> tuple[EvidenceBundle, ed25519.Ed25519PrivateKey]:
    """Create + sign an evidence bundle.

    Args:
        graph, policy_eval, assurance, workload, ttl_days: standard bundle inputs.
        private_key: if provided, sign with this key (for key persistence). If None,
            generate an ephemeral key.
        enable_rekor_anchoring: if True, submit the signed bundle to Sigstore Rekor
            and attach the inclusion proof. Defaults to False (no network call).
        rekor_url: override the Rekor URL (default: fetched from TUF SigningConfig).
        rekor_poster: test hook for the HTTP poster.

    Returns (bundle, private_key).
    """
    now = datetime.now()
    if private_key is None:
        private_key, _ = generate_ed25519_keypair()

    bundle = EvidenceBundle(
        bundle_id=f"bundle-{now.strftime('%Y%m%d%H%M%S')}",
        timestamp=now,
        expires_at=now + timedelta(days=ttl_days),
        workload=workload,
        evidence_graph_summary={
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "platforms": list(set(
                n.platform.value for n in graph.nodes.values()
                if n.platform is not None
            )),
        },
        policy_evaluation=policy_eval,
        assurance=assurance,
        attack_db_snapshot=compute_attack_db_snapshot(),
    )

    sign_bundle(bundle, private_key)

    if enable_rekor_anchoring:
        bundle = anchor_to_rekor(
            bundle,
            rekor_url=rekor_url,
            poster=rekor_poster,
        )

    return bundle, private_key
