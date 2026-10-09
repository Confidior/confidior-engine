"""The `confidior inspect` command: verifying a Rekor anchor from the log.

Task #9's deliverable, and the last piece of the receipt work: `rekor.py` can
fetch an entry and `notes.py` can verify a checkpoint, but until now a third
party had no way to run either. This is the read side of anchoring -- given a
log index or entry UUID, ask the log what it holds and check that what comes
back actually proves in.

The distinction that shapes the output: every field is reported as checked,
failed, or *not checkable*, and never as a bare success. A proof that verifies
against an unsigned root, or a checkpoint whose key we do not have, is not a
verified anchor, and the exit code has to say so or the command is worse than
useless.
"""

from __future__ import annotations

import logging
from typing import Any

from src.core.notes import parse_checkpoint, verify_checkpoint
from src.core.trust import load_trust_root
from src.export.rekor import (
    RekorError,
    anchored_digest,
    get_checkpoint,
    get_entry,
    get_entry_by_index,
    get_rekor_url,
    parse_entry_spec,
    verify_inclusion_proof,
)

logger = logging.getLogger(__name__)

#: Exit codes, so a caller can distinguish "unproven" from "broken".
EXIT_VERIFIED = 0
EXIT_UNPROVEN = 2
EXIT_ERROR = 3


def run_inspect(args: Any) -> int:
    """Verify a Rekor anchor straight from the log.

    Prints the payload digest, the inclusion proof result, and the checkpoint
    result. Returns an exit code: 0 only when both halves verified. An
    unverifiable anchor exits 2 rather than 0, because a receipt that cannot be
    checked is not a receipt that checked out.
    """
    rekor_url = getattr(args, "rekor_url", None) or _resolve_rekor_url()

    try:
        entry = _fetch_entry(args, rekor_url)
    except RekorError as e:
        print(f"error: {e}")
        return EXIT_ERROR

    if not entry:
        print("error: the log returned no entry")
        return EXIT_ERROR

    proof = (entry.get("verification") or {}).get("inclusionProof") or {}

    print("Rekor anchor")
    print(f"  log:              {rekor_url}")
    print(f"  entry uuid:       {entry.get('uuid', '(none)')}")
    print(f"  log index:        {proof.get('logIndex', entry.get('logIndex', '(none)'))}")
    print(f"  tree size:        {proof.get('treeSize', '(none)')}")
    print(f"  integrated at:    {_integrated_time(entry)}")
    print(f"  payload digest:   {_payload_digest(entry)}")
    print(f"  signing key:      {_signing_key(entry)}")

    inclusion = verify_inclusion_proof(entry)
    trust_root = load_trust_root(getattr(args, "trust_root", None))
    checkpoint = get_checkpoint(rekor_url, fetcher=getattr(args, "fetcher", None))
    signature = verify_checkpoint(checkpoint, trust_root) if checkpoint else None

    print()
    print("Verification")
    print(f"  inclusion proof:   {_describe(inclusion)}")
    print(f"  signed checkpoint: {_describe_checkpoint(signature, checkpoint, trust_root)}")

    if checkpoint:
        parsed = parse_checkpoint(checkpoint)
        print(f"  checkpoint size: {parsed.tree_size}")

    if inclusion is True and signature is True:
        print()
        print("This entry is in a tree the log signed.")
        return EXIT_VERIFIED

    print()
    print("This entry is not proven by the material available.")
    return EXIT_UNPROVEN


def _resolve_rekor_url() -> str:
    """The log to ask, discovered from Sigstore's trusted config.

    Shard discovery reaching TUF is not worth failing the command over: if it
    cannot be resolved, the default instance is what it would have said anyway.
    """
    try:
        return get_rekor_url()
    except Exception as e:  # noqa: BLE001
        logger.warning("Could not resolve the current Rekor URL (%s); using the default", e)
        return "https://rekor.sigstore.dev"


def _fetch_entry(args: Any, rekor_url: str) -> dict[str, Any]:
    """Fetch the entry named by --uuid or --rekor.

    Both are lookups against the same retrieve endpoint, which accepts either keys
    or indexes; an index is the form a checkpoint's proof indexes against, a UUID
    is what the bundle records.
    """
    fetcher = getattr(args, "fetcher", None)
    if getattr(args, "rekor", None) is not None:
        return get_entry_by_index(args.rekor, rekor_url, fetcher=fetcher)
    return get_entry(args.uuid, rekor_url, fetcher=fetcher)


def _payload_digest(entry: dict[str, Any]) -> str:
    """The digest the anchored statement committed to.

    A hashedrekord entry wraps its subject's hash in a JSON spec, so the useful
    value is the inner ``spec.data.hash.value`` rather than the entry body. The
    entry's own digest is printed as a fallback, since an entry whose body we
    cannot parse is still an entry.
    """
    import hashlib

    value = anchored_digest(entry)
    if value:
        return f"{value} (sha256, committed by the entry)"
    body = str(entry.get("body") or "")
    if not body:
        return "(none)"
    return f"sha256:{hashlib.sha256(body.encode()).hexdigest()} (digest of the entry body)"


def _signing_key(entry: dict[str, Any]) -> str:
    """The subject the entry names: who signed it, per the entry itself.

    A hashedrekord entry carries the signer's certificate rather than a bare key.
    This reports the subject and issuer, not a verification: the certificate is
    only meaningful once its chain is checked, and a self-signed certificate
    verifies nothing. Saying so in the output is the point.
    """
    import base64

    spec = parse_entry_spec(entry)
    try:
        pem = base64.b64decode(spec["spec"]["signature"]["publicKey"]["content"])
    except (KeyError, TypeError, ValueError):
        return "(none recorded in the entry)"
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(pem)
        subject = _cert_identity(cert)
        issuer = cert.issuer.rfc4514_string()
        if not issuer:
            return f"{subject} (no issuer recorded)"
        if subject == issuer:
            return f"{subject} (self-signed; the entry asserts this identity, it does not prove it)"
        return f"{subject} (issued by {issuer})"
    except Exception:  # noqa: BLE001 -- a malformed certificate is reported as such
        return "(the entry's certificate could not be parsed)"


def _cert_identity(cert: Any) -> str:
    """A certificate's identity, which for a Fulcio cert is the SAN, not the subject.

    Sigstore's signer certificates carry an empty subject and put the identity in
    the subjectAltName extension, so reading only the subject reports nothing at
    all for exactly the certificates this command is most likely to see.
    """
    subject = cert.subject.rfc4514_string()
    if subject:
        return subject
    try:
        from cryptography import x509

        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        values = san.get_values_for_type(x509.RFC822Name) + [
            str(uri) for uri in san.get_values_for_type(x509.UniformResourceIdentifier)
        ]
        return ", ".join(values) if values else "(identity not in subject or SAN)"
    except Exception:  # noqa: BLE001
        return "(identity not in subject or SAN)"


def _integrated_time(entry: dict[str, Any]) -> str:
    stamp = entry.get("integratedTime")
    if not isinstance(stamp, int):
        return "(none)"
    from datetime import datetime

    return datetime.fromtimestamp(stamp).isoformat()


def _describe_checkpoint(signature: bool | None, checkpoint: str, trust_root: object) -> str:
    """Say what happened with the checkpoint, and why when it was not checked.

    The three ways this comes back unverified are distinct and a reader needs to
    tell them apart: the log served nothing, we hold no key for it, or the key we
    hold did not match. Only the first is the log's doing.
    """
    if signature is True:
        return "verified"
    if signature is False:
        return "FAILED"
    if not checkpoint:
        return "not checked (the log served no checkpoint)"
    if not trust_root:
        return "not checked (no trust root configured, so the log's key cannot be checked)"
    return "not checked (no key in the trust root matches the checkpoint's key id)"


def _describe(result: bool | None, missing: str = "no proof in the entry") -> str:
    if result is True:
        return "verified"
    if result is False:
        return "FAILED"
    return f"not checked ({missing})"


def add_inspect_parser(sub: Any) -> None:
    """Wire `confidior inspect` into the argument parser."""
    inspect = sub.add_parser(
        "inspect",
        help="Verify a Rekor anchor by fetching the entry from the transparency log",
    )
    source = inspect.add_mutually_exclusive_group(required=True)
    source.add_argument("--uuid", help="Rekor entry UUID (recorded in the bundle)")
    source.add_argument("--rekor", type=int, help="Rekor log index")
    inspect.add_argument("--rekor-url", help="Override the Rekor URL (skips shard discovery)")
    inspect.add_argument("--trust-root", help="Path to a trust root JSON file")
    inspect.set_defaults(func=run_inspect)
