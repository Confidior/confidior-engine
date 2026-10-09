"""SCITT: verifying transparency receipts, and emitting signed statements.

SCITT -- Supply Chain Integrity, Transparency, and Trust -- is the IETF standard
(RFC 9943, June 2026) for the transparency service pattern this engine's
anchoring layer copies. Rekor is the deployed instance of it: a Transparency
Service (TS) takes a Signed Statement, appends it to a Verifiable Data
Structure, and returns a Receipt. The roadmap registers SCITT as "Align + Emit"
(docs/INTEGRATION-ROADMAP.md), and this module is that alignment.

Two directions, and only one of them is ours:

* **Verify a Receipt.** A receipt is a COSE_Sign1 (RFC 9942) whose payload is a
  Merkle tree root, whose protected header names the VDS (395 = RFC9162_SHA256),
  and whose unprotected header carries the inclusion proof. This is where the
  two halves that matter come together: the proof shows the statement is in the
  tree, and the signature -- checked against a key the operator named -- shows
  the TS said so. Neither half alone means inclusion in *the log*.

* **Emit a Signed Statement.** The engine is an Issuer, not a TS: it has no log
  and issues no receipts. What it can do is say something in the standard's
  shape, so a real TS can register it and return a receipt. Per RFC 9943 §6.2 a
  statement over the *hash* of a large payload is explicitly supported, which is
  the position Confidior is in -- it commits to an evidence digest, never the
  raw evidence.

The receipts here are verified; the statements are ours and are signed with our own
key, so verifying one proves what we said, not that a log saw it.

Two limits worth knowing before relying on this:

* **Detached-payload receipts are not verified.** RFC 9942 §4.4 permits a receipt to
  leave its payload (the Merkle root) out of the object, in which case the root has
  to come from somewhere else. :func:`verify_receipt` reports that as unproven
  rather than guessing, since a proof checked against a caller-supplied root only
  proves what that caller already believed. Supporting it means taking the root as
  a parameter, which is a decision about who is authoritative, not a code change.
* **Nothing here consumes a live transparency service.** The verification is real
  and exercised against RFC-shaped receipts, but the only deployed instance reached
  today is Sigstore's Rekor, whose transparency artifacts are C2SP checkpoints rather
  than COSE receipts -- those are handled by :mod:`src.core.notes`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import cbor

from src.core.merkle import leaf_hash, verify_inclusion
from src.core.trust import TrustedKey, TrustRoot

logger = logging.getLogger(__name__)

#: RFC 9942 §2: COSE header parameter labels.
HEADER_RECEIPTS = 394
HEADER_VDS = 395
HEADER_VDP = 396

#: RFC 9942 §8.2.2.2: proof types within the VDP map.
PROOF_INCLUSION = -1
PROOF_CONSISTENCY = -2

#: RFC 9942 §8.2.2.1: verifiable data structure algorithms.
VDS_RFC9162_SHA256 = 1

#: COSE_Sign1, RFC 9052 §4.2.
COSE_SIGN1_TAG = 18

#: RFC 9943 §10.1/§10.2: the media types for the two objects.
MEDIA_TYPE_STATEMENT = "application/scitt-statement+cose"
MEDIA_TYPE_RECEIPT = "application/scitt-receipt+cose"

#: RFC 9052 §3.1: COSE algorithm identifiers we will verify a receipt with.
ALG_EDDSA = -8
ALG_ES256 = -7
ALG_ES384 = -35
ALG_ES512 = -36

#: COSE alg -> the curve name, so a receipt's own `alg` picks the hash.
_ALG_CURVES = {
    ALG_EDDSA: "ed25519",
    ALG_ES256: "p256",
    ALG_ES384: "p384",
    ALG_ES512: "p521",
}


class ScittError(Exception):
    """Raised when a receipt or statement cannot be parsed as one at all."""


@dataclass(frozen=True)
class ReceiptVerification:
    """The outcome of checking one receipt, with the halves kept apart.

    ``inclusion`` and ``signature`` are each three-valued, for the reason the
    rest of this engine is: a check that could not be performed is not a check
    that passed. ``verified`` is True only when *both* halves came back True.

    ``reason`` is set only when something actually failed, and says which half.
    """

    verified: bool
    inclusion: bool | None
    signature: bool | None
    tree_size: int | None = None
    leaf_index: int | None = None
    root: bytes | None = None
    reason: str = ""

    def __bool__(self) -> bool:
        return self.verified


def verify_receipt(
    receipt: bytes,
    leaf_data: bytes,
    trust_root: TrustRoot,
) -> ReceiptVerification:
    """Verify a SCITT receipt for ``leaf_data`` against a trust root.

    ``receipt`` is the CBOR-encoded Receipt (a COSE_Sign1, tagged or not --
    tag 18 is optional on the wire and both forms appear in the wild).
    ``leaf_data`` is the statement bytes the receipt is supposed to cover;
    per RFC 9942 §5.2 the receipt's payload is a Merkle *root*, not the input
    to the leaf hash, so the caller has to supply the leaf.

    Returns a :class:`ReceiptVerification`. This never raises for a bad receipt
    -- a caller asking "is this valid" gets a result, not a stack trace -- but
    it does not paper over the difference between the two failure modes:
    "the proof says no" and "there was no proof to check" are different, and
    the result records which happened.
    """
    try:
        decoded = _decode_cose_sign1(receipt)
    except Exception as e:  # noqa: BLE001 -- any parse failure is one outcome
        return ReceiptVerification(
            verified=False, inclusion=None, signature=None, reason=f"unparseable receipt: {e}"
        )
    protected, unprotected, payload, signature = decoded

    # The proof's shape depends on the data structure it was built over, so this
    # has to be established before the audit path is read as an RFC 9162 tree --
    # otherwise a proof from some other structure reads as a failed proof rather
    # than as one we cannot interpret.
    vds = _vds_from_protected(protected)
    if vds != VDS_RFC9162_SHA256:
        return ReceiptVerification(
            verified=False,
            inclusion=None,
            signature=None,
            reason=(
                f"receipt names verifiable data structure {vds!r}, "
                "which this engine does not verify"
            ),
        )

    proof = _extract_inclusion_proof(unprotected)
    if proof is None:
        return ReceiptVerification(
            verified=False,
            inclusion=None,
            signature=None,
            reason="receipt carries no RFC9162_SHA256 inclusion proof",
        )
    tree_size, leaf_index, audit_path = proof

    if payload is None:
        return ReceiptVerification(
            verified=False,
            inclusion=None,
            signature=None,
            tree_size=tree_size,
            leaf_index=leaf_index,
            reason="receipt has a detached payload, so it names no root to prove against",
        )
    root = payload

    inclusion = verify_inclusion(
        leaf_hash(leaf_data), leaf_index, tree_size, audit_path, root
    )
    if not inclusion:
        return ReceiptVerification(
            verified=False,
            inclusion=False,
            signature=None,
            tree_size=tree_size,
            leaf_index=leaf_index,
            root=root,
            reason="inclusion proof does not rebuild the receipt's root",
        )

    signature_result = _verify_receipt_signature(protected, payload, signature, trust_root)
    verified = signature_result is True
    reason = ""
    if signature_result is False:
        reason = "receipt signature is invalid for a key in the trust root"
    elif signature_result is None:
        reason = "no key in the trust root matches the receipt's signing key"
    return ReceiptVerification(
        verified=verified,
        inclusion=True,
        signature=signature_result,
        tree_size=tree_size,
        leaf_index=leaf_index,
        root=root,
        reason=reason,
    )


def extract_receipts(signed_statement: bytes) -> list[bytes]:
    """Pull the CBOR-encoded receipts out of a Transparent Statement (RFC 9943 §7).

    A Transparent Statement is a Signed Statement with its receipts added to the
    unprotected header under label 394. This returns the receipt blobs, each of
    which is a CBOR object for :func:`verify_receipt`. Returns an empty list for
    a statement with no receipts -- which is the normal state before
    registration, not an error.
    """
    try:
        decoded = _decode_cose_sign1(signed_statement)
    except Exception as e:  # noqa: BLE001
        raise ScittError(f"not a COSE_Sign1 object: {e}") from e
    _, unprotected, _, _ = decoded
    if not isinstance(unprotected, dict):
        return []
    raw = unprotected.get(HEADER_RECEIPTS)
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ScittError("receipts header (394) is not a CBOR array")
    return [item for item in raw if isinstance(item, bytes)]


def verify_as_leaf(
    leaf_data: bytes,
    receipts: list[bytes],
    rekor_entry: dict[str, Any] | None,
    trust_root: TrustRoot,
) -> list[ReceiptVerification]:
    """Verify a piece of evidence against every transparency record we hold.

    The two transparency mechanisms are the same tree with different plumbing:
    Rekor's JSON inclusion proof is the RFC 9162 proof, and a SCITT receipt is
    the same proof inside a COSE_Sign1. A bundle anchored through both is one
    commitment, so this is the operation a caller actually wants -- "is this
    digest in the logs I was told about" -- rather than either half of it.

    Returns one result per receipt, in order. The Rekor entry is checked first
    and included in the same list as a :class:`ReceiptVerification` whose
    signature half is the log's checkpoint. The leaf passed to the SCITT side is
    recomputed from ``leaf_data``; the Rekor side is checked against the entry's
    own recorded proof, since that proof was taken over the anchored bytes.
    """
    from src.core.notes import verify_checkpoint
    from src.core.trust import EMPTY_TRUST_ROOT
    from src.export.rekor import verify_inclusion_proof

    results: list[ReceiptVerification] = []

    if rekor_entry:
        inclusion = verify_inclusion_proof(rekor_entry)
        checkpoint = str(rekor_entry.get("checkpoint") or "")
        signature: bool | None = None
        reason = ""
        if checkpoint:
            signature = verify_checkpoint(checkpoint, trust_root or EMPTY_TRUST_ROOT)
            if signature is None:
                reason = "no key in the trust root matches the checkpoint's signing key"
            elif not signature:
                reason = "checkpoint signature is invalid for a key in the trust root"
        else:
            reason = "Rekor entry carries no signed checkpoint, so the log's root is unsigned"
        proof = (rekor_entry.get("verification") or {}).get("inclusionProof") or {}
        results.append(
            ReceiptVerification(
                verified=inclusion is True and signature is True,
                inclusion=inclusion,
                signature=signature,
                tree_size=proof.get("treeSize"),
                leaf_index=proof.get("logIndex"),
                reason=reason,
            )
        )

    for receipt in receipts:
        results.append(verify_receipt(receipt, leaf_data, trust_root))

    return results


def _decode_cose_sign1(blob: bytes) -> tuple[bytes, Any, bytes | None, bytes]:
    """Decode a COSE_Sign1 into (protected, unprotected, payload, signature).

    The tag is optional: RFC 9052 §4.2 says a COSE_Sign1 is tag 18, but
    implementations are permitted to omit it, so both are accepted and the
    bare 4-element array is treated as the same thing.
    """
    decoded = cbor.loads(blob)
    if isinstance(decoded, cbor.Tag):
        if decoded.tag != COSE_SIGN1_TAG:
            raise ScittError(f"expected COSE_Sign1 (tag 18), got tag {decoded.tag}")
        decoded = decoded.value
    if not isinstance(decoded, list) or len(decoded) != 4:
        raise ScittError("expected a 4-element COSE_Sign1 array")
    protected, unprotected, payload, signature = decoded
    if not isinstance(protected, bytes) or not isinstance(signature, bytes):
        raise ScittError("protected header and signature must be byte strings")
    if payload is not None and not isinstance(payload, bytes):
        raise ScittError("payload must be a byte string or detached (null)")
    if isinstance(unprotected, bytes):
        unprotected = _maybe_decode(unprotected)
    return protected, unprotected, payload, signature


def _maybe_decode(value: bytes) -> Any:
    try:
        return cbor.loads(value)
    except Exception:  # noqa: BLE001 -- a non-CBOR blob is left as bytes
        return value


def _vds_from_protected(protected: bytes) -> Any:
    """The ``vds`` (label 395) out of a receipt's protected header, or ``None``."""
    try:
        header = cbor.loads(protected) if protected else {}
    except Exception:  # noqa: BLE001
        return None
    return header.get(HEADER_VDS) if isinstance(header, dict) else None


def _extract_inclusion_proof(unprotected: Any) -> tuple[int, int, list[bytes]] | None:
    """The first RFC9162_SHA256 inclusion proof in a receipt, or None.

    RFC 9942 §4.3: the vds lives in the *protected* header and the proofs in the
    unprotected one; here the caller has already established the receipt shape,
    so this only pulls the numbers out and leaves the vds check to the caller's
    signature verification.
    """
    if not isinstance(unprotected, dict):
        return None
    proofs = unprotected.get(HEADER_VDP)
    if not isinstance(proofs, dict):
        return None
    inclusions = proofs.get(PROOF_INCLUSION)
    if not isinstance(inclusions, list) or not inclusions:
        return None
    first = inclusions[0]
    if isinstance(first, bytes):
        first = _maybe_decode(first)
    if not isinstance(first, list) or len(first) != 3:
        return None
    tree_size, leaf_index, path = first
    if not isinstance(tree_size, int) or not isinstance(leaf_index, int):
        return None
    if not isinstance(path, list) or not all(isinstance(h, bytes) for h in path):
        return None
    return tree_size, leaf_index, path


def _verify_receipt_signature(
    protected: bytes,
    payload: bytes,
    signature: bytes,
    trust_root: TrustRoot,
) -> bool | None:
    """Check a receipt's COSE signature against the trust root.

    The signed bytes are a ``COSE_Sign1`` Sig_structure (RFC 9052 §4.4):
    ``["Signature1", protected, external_aad, payload]``. The key is chosen by
    the protected header's key id (label 4) when there is one; with no key id
    there is nothing to look up, and an empty trust root yields ``None``.

    Returns ``True``/``False``/``None`` with the same meaning as everywhere else
    in the trust layer: not checked is not verified.
    """
    if not trust_root:
        return None
    try:
        header = cbor.loads(protected) if protected else {}
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(header, dict):
        return None

    vds = header.get(HEADER_VDS)
    if vds is not None and vds != VDS_RFC9162_SHA256:
        # A proof we cannot interpret is not a proof we checked.
        logger.debug("receipt names VDS %r, which this engine does not verify", vds)
        return None

    to_be_signed = cbor.dumps(["Signature1", protected, b"", payload])
    key_id = _key_id_from_header(header)
    candidate = trust_root.key(key_id)
    if candidate is None:
        return None
    return _verify_with_alg(candidate, header, to_be_signed, signature)


def _key_id_from_header(header: dict[Any, Any]) -> str | None:
    """The signing key id from a COSE protected header (label 4, kid).

    A COSE ``kid`` is an opaque byte string, but a trust root names keys with
    human-readable strings, so the bridge is a UTF-8 decode, falling back to hex
    for ids that are not text. That fallback is a rendering, not a lookup
    convention: an operator with a non-text kid has to write it as hex.
    """
    kid = header.get(4)
    if isinstance(kid, str):
        return kid
    if isinstance(kid, bytes):
        try:
            return kid.decode("utf-8")
        except UnicodeDecodeError:
            return kid.hex()
    return None


def _verify_with_alg(
    key: TrustedKey, header: dict[Any, Any], to_be_signed: bytes, signature: bytes
) -> bool:
    """Verify with the curve the receipt declares, then fall back to the key's own.

    A receipt carries its own ``alg`` (protected label 1). Preferring it, then
    falling back, is deliberate: a receipt that says ES256 while the trust root
    lists the key as P-384 should fail, not quietly succeed under a different
    algorithm than it claimed.
    """
    alg = header.get(1)
    curve = _ALG_CURVES.get(alg) if isinstance(alg, int) else None
    if curve is not None:
        return _verify_as(key, curve, to_be_signed, signature)
    return key.verify(to_be_signed, signature)


def _verify_as(key: TrustedKey, curve: str, message: bytes, signature: bytes) -> bool:
    from dataclasses import replace

    declared = key
    if key.algorithm.strip().lower() != curve:
        declared = replace(key, algorithm=curve)
    return declared.verify(message, signature)


def decode_statement(statement: bytes) -> dict[str, Any]:
    """Decode a Signed Statement into its parts, without verifying anything.

    For inspection: returns ``protected``, ``unprotected``, ``payload``,
    ``signature``, and ``receipts``. The payload is the statement bytes, which
    is what :func:`verify_receipt` takes as ``leaf_data``.
    """
    protected, unprotected, payload, signature = _decode_cose_sign1(statement)
    return {
        "protected": _maybe_decode(protected) if protected else {},
        "unprotected": unprotected,
        "payload": payload,
        "signature": signature,
        "receipts": extract_receipts(statement) if unprotected else [],
    }


def encode_signed_statement(
    payload: bytes,
    private_key: Any,
    key_id: bytes | None = None,
    vds: int = VDS_RFC9162_SHA256,
    algorithm: int = ALG_EDDSA,
    receipts: list[bytes] | None = None,
    extra_protected: dict[Any, Any] | None = None,
) -> bytes:
    """Sign a statement as a COSE_Sign1, in SCITT's shape.

    The payload is carried inline rather than detached: it is a digest, not the
    evidence, so there is nothing to withhold and an inline payload needs no
    second convention about what the leaf preimage is. To register this with a
    real TS, hash the returned bytes' payload -- ``leaf_hash(payload)`` -- into
    the Merkle tree the TS maintains.

    ``private_key`` is an Ed25519 or ECDSA private key; ``algorithm`` is the
    matching COSE algorithm id and must agree with the key type. ``vds`` is
    recorded in the protected header so a receiving TS knows which structure to
    build its proof against.

    ``extra_protected`` merges into the protected header -- CWT claims (label
    15, with 1 = issuer, 2 = subject; RFC 8392) are the usual use, so a TS can
    tell who is asserting what.
    """
    header: dict[Any, Any] = {1: algorithm, HEADER_VDS: vds}
    if key_id is not None:
        header[4] = key_id
    if extra_protected:
        header.update(extra_protected)
    protected = cbor.dumps(header)

    unprotected: dict[Any, Any] = {}
    if receipts:
        # RFC 9943 §7: the receipts header (394) holds receipts, each itself a
        # CBOR-encoded COSE_Sign1. The encoder accepts them already encoded and
        # passes them through unchanged -- re-encoding here would wrap a
        # receipt in a bstr and hand the TS something that is not a receipt.
        unprotected[HEADER_RECEIPTS] = list(receipts)

    to_be_signed = cbor.dumps(["Signature1", protected, b"", payload])
    signature = _sign(algorithm, private_key, to_be_signed)
    return cbor.dumps(cbor.Tag(COSE_SIGN1_TAG, [protected, unprotected, payload, signature]))


def _sign(algorithm: int, private_key: Any, message: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    if algorithm == ALG_EDDSA:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ScittError("alg EdDSA requires an Ed25519 private key")
        return private_key.sign(message)

    hash_for = {
        ALG_ES256: hashes.SHA256,
        ALG_ES384: hashes.SHA384,
        ALG_ES512: hashes.SHA512,
    }.get(algorithm)
    if hash_for is None or not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ScittError(f"alg {algorithm} requires an ECDSA private key")
    der = private_key.sign(message, ec.ECDSA(hash_for()))
    r, s = decode_dss_signature(der)
    width = (private_key.curve.key_size + 7) // 8
    return r.to_bytes(width, "big") + s.to_bytes(width, "big")
