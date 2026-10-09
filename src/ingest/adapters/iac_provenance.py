"""DSSE / in-toto provenance statement parser for IaC evidence.

This module converts signed in-toto attestation envelopes (SLSA-style
provenance) into a Confidior ``IaCProvenance`` record that can be attached to
an evidence graph node. Verification is **structural / best-effort** for Phase 0:
we parse the envelope and extract the signer's `kid` or `x509` subject as the
identity claim, but we do **not** perform full cryptographic signature
verification here. Signature verification is deferred to Phase 1 where the
trust root (Sigstore Fulcio cert, raw public key, etc.) is configured.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from src.core.taxonomy import IaCProvenance
from src.core.trust import TrustRoot, TrustRootError  # noqa: F401  (re-exported for callers)

INTOTO_PREDICATE_TYPES = (
    "https://slsa.dev/provenance/v0.2",
    "https://slsa.dev/provenance/v1",
    "https://in-toto.io/Statement/v0.1",
    "https://in-toto.io/Statement/v1",
)


def _b64_decode(payload_b64: str) -> bytes:
    """URL-safe or standard base64 decode with padding fix."""
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return base64.b64decode(padded)


def _extract_signer_identity(signatures: list[dict[str, Any]]) -> str:
    """Return a stable signer identity string from DSSE signatures.

    Preference order:
    1. `keyid` field
    2. First 16 hex chars of `sig`
    3. x509 certificate subject if `x509` present and parseable
    """
    if not signatures:
        return "unknown"
    sig = signatures[0]
    if "keyid" in sig and sig["keyid"]:
        return str(sig["keyid"])
    raw_sig = sig.get("sig", "")
    if raw_sig:
        return f"sig:{raw_sig[:16]}"
    return "unknown"


def verify_envelope_signature(
    envelope: dict[str, Any],
    payload: bytes,
    trust_root: TrustRoot,
) -> bool | None:
    """Check the envelope's signature over ``payload`` against the trust root.

    DSSE signs the pre-authentication encoding, ``PAE(payloadType, payload)``,
    not the payload alone, so the ``payloadType`` is part of what is verified.

    Returns ``None`` when the named key is not in the trust root: the signature
    is not *wrong*, it is unjudged, and reporting it as verified would be a
    claim this engine cannot support.
    """
    signatures = envelope.get("signatures", [])
    if not signatures:
        return None
    payload_type = str(envelope.get("payloadType", ""))
    pae = b"DSSEv1 " + str(len(payload_type)).encode() + b" " + payload_type.encode()
    pae += b" " + str(len(payload)).encode() + b" " + payload
    signature = signatures[0]
    key_id = str(signature.get("keyid", "")) or None
    sig_b64 = str(signature.get("sig", ""))
    if not sig_b64:
        return None
    return trust_root.verify(key_id, pae, _b64_decode(sig_b64))


def parse_iac_provenance(
    envelope_json: str | bytes, trust_root: TrustRoot | None = None
) -> IaCProvenance:
    """Parse a DSSE JSON envelope into an ``IaCProvenance`` record.

    Supports both the canonical DSSE form:
      {"payloadType": "...", "payload": "base64...", "signatures": [...]}
    and the already-decoded payload form:
      {"type": "...", "predicate": {...}, "subject": [...]}

    When ``trust_root`` is supplied the envelope's signature is checked against
    it and the result recorded on ``signature_verified``. Without one the record
    says ``None`` -- parsed, not verified -- rather than implying a check that
    did not happen.
    """
    if isinstance(envelope_json, bytes):
        envelope_json = envelope_json.decode("utf-8", errors="replace")

    envelope = json.loads(envelope_json)

    # Canonical DSSE envelope
    payload_b64 = envelope.get("payload")
    signature_verified: bool | None = None
    if payload_b64 and isinstance(payload_b64, str):
        payload_bytes = _b64_decode(payload_b64)
        statement = json.loads(payload_bytes)
        signatures = envelope.get("signatures", [])
        if trust_root is not None:
            signature_verified = verify_envelope_signature(envelope, payload_bytes, trust_root)
    else:
        statement = envelope
        signatures = envelope.get("signatures", [])

    predicate_type = statement.get("predicateType") or statement.get("type", "unknown")
    subject_list = statement.get("subject", [])
    subject = subject_list[0] if subject_list else {}
    subject_name = subject.get("name", "unknown")
    subject_digest = subject.get("digest", {})

    predicate = statement.get("predicate", {})
    slsa_level = None
    build_commit = None
    builder_id = None
    if predicate:
        # SLSA v0.2 / v1 provenance fields
        if isinstance(predicate.get("buildType"), str):
            builder_id = (
        predicate.get("builder", {}).get("id")
        if isinstance(predicate.get("builder"), dict)
        else None
    )
        build_def = predicate.get("buildDefinition", {})
        if isinstance(build_def, dict):
            resolved_deps = build_def.get("resolvedDependencies", [])
            for dep in resolved_deps or []:
                if isinstance(dep, dict) and dep.get("uri", "").startswith("git+"):
                    build_commit = dep.get("digest", {}).get("gitCommit")
        run_details = predicate.get("runDetails", {})
        if isinstance(run_details.get("builder"), dict):
            builder_id = builder_id or run_details["builder"].get("id")
        metadata = predicate.get("metadata", {})
        if isinstance(metadata, dict):
            build_commit = build_commit or metadata.get("buildInvocationId")

    signer_identity = _extract_signer_identity(signatures)

    return IaCProvenance(
        predicate_type=predicate_type,
        subject_name=subject_name,
        subject_digest=subject_digest,
        signer_identity=signer_identity,
        slsa_level=slsa_level,
        build_commit=build_commit,
        builder_id=builder_id,
        predicate=predicate,
        signature_verified=signature_verified,
    )
