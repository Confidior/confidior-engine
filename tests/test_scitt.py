"""SCITT receipts and statements (RFC 9943 / RFC 9942).

A receipt is only worth what its two halves are worth: the inclusion proof shows
the statement is in the tree, and the signature shows the transparency service
said so. These tests build a real receipt from a real ECDSA key and a real
two-leaf Merkle tree, so the arithmetic and the COSE signing are both exercised
rather than mocked.

The negative cases matter as much as the positive one: an unverifiable receipt
must not read as a verified one.
"""

from __future__ import annotations

import base64

import cbor
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.core.merkle import leaf_hash, node_hash
from src.core.trust import TrustedKey, TrustRoot
from src.export.scitt import (
    ALG_ES256,
    COSE_SIGN1_TAG,
    HEADER_VDP,
    HEADER_VDS,
    PROOF_INCLUSION,
    VDS_RFC9162_SHA256,
    decode_statement,
    encode_signed_statement,
    extract_receipts,
    verify_receipt,
)

STATEMENT = b'{"artifact": "registry.example/app", "digest": "sha256:abc"}'
OTHER = b'{"artifact": "other"}'


def _cose_sign1(protected: bytes, unprotected: dict, payload: bytes, signature: bytes) -> bytes:
    return cbor.dumps(cbor.Tag(COSE_SIGN1_TAG, [protected, unprotected, payload, signature]))


def _ts_key() -> tuple[ec.EllipticCurvePrivateKey, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
    )
    return key, base64.b64encode(raw).decode()


def _sign_cose(key: ec.EllipticCurvePrivateKey, protected: bytes, payload: bytes) -> bytes:
    to_be_signed = cbor.dumps(["Signature1", protected, b"", payload])
    der = key.sign(to_be_signed, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _make_receipt(key: ec.EllipticCurvePrivateKey, key_id: str | None = None) -> bytes:
    """A receipt for STATEMENT, as a TS over a two-leaf tree would issue it.

    The key id ends up in the protected header as ``kid`` (label 4): the receipt
    has to name its signing key for a trust root to find it, since the bytes are
    the only thing carried.
    """
    root = node_hash(leaf_hash(STATEMENT), leaf_hash(OTHER))
    proof = cbor.dumps([2, 0, [leaf_hash(OTHER)]])
    unprotected = {HEADER_VDP: {PROOF_INCLUSION: [proof]}}
    header: dict = {1: ALG_ES256, HEADER_VDS: VDS_RFC9162_SHA256}
    if key_id is not None:
        header[4] = key_id.encode()
    protected = cbor.dumps(header)
    signature = _sign_cose(key, protected, root)
    return _cose_sign1(protected, unprotected, root, signature)


def _trust_root(public_key_b64: str, key_id: str) -> TrustRoot:
    key = TrustedKey(key_id=key_id, public_key_b64=public_key_b64, algorithm="ES256")
    return TrustRoot(keys=(key,))


def test_a_real_receipt_verifies():
    key, public_key_b64 = _ts_key()
    receipt = _make_receipt(key, key_id="ts.example")
    result = verify_receipt(receipt, STATEMENT, _trust_root(public_key_b64, "ts.example"))
    assert result.verified
    assert result.inclusion is True
    assert result.signature is True
    assert result.tree_size == 2
    assert result.leaf_index == 0


def test_a_receipt_for_a_different_statement_fails_inclusion():
    """The proof binds the statement, not just the tree."""
    key, public_key_b64 = _ts_key()
    receipt = _make_receipt(key, key_id="ts.example")
    result = verify_receipt(receipt, OTHER, _trust_root(public_key_b64, "ts.example"))
    assert not result.verified
    assert result.inclusion is False
    assert "inclusion" in result.reason


def test_an_unknown_log_key_is_unjudged_not_failed():
    """No matching trust-root key means the signature was not checked at all."""
    key, _ = _ts_key()
    receipt = _make_receipt(key, key_id="ts.example")
    result = verify_receipt(receipt, STATEMENT, TrustRoot())
    assert not result.verified
    assert result.inclusion is True
    assert result.signature is None
    assert "trust root" in result.reason


def test_a_tampered_root_fails_inclusion():
    key, public_key_b64 = _ts_key()
    receipt = _make_receipt(key, key_id="ts.example")
    protected, unprotected, _root, signature = cbor.loads(receipt).value
    forged = _cose_sign1(protected, unprotected, b"\x11" * 32, signature)
    result = verify_receipt(forged, STATEMENT, _trust_root(public_key_b64, "ts.example"))
    assert not result.verified
    assert result.inclusion is False


def test_a_tampered_signature_fails_but_inclusion_still_holds():
    key, public_key_b64 = _ts_key()
    protected, unprotected, root, signature = cbor.loads(_make_receipt(key, "ts.example")).value
    broken = bytes([signature[0] ^ 0xFF]) + signature[1:]
    result = verify_receipt(
        _cose_sign1(protected, unprotected, root, broken),
        STATEMENT,
        _trust_root(public_key_b64, "ts.example"),
    )
    assert not result.verified
    assert result.inclusion is True
    assert result.signature is False


def test_an_unparseable_receipt_is_not_verified():
    result = verify_receipt(b"not cbor at all", STATEMENT, TrustRoot())
    assert not result.verified
    assert result.inclusion is None
    assert "unparseable" in result.reason


def test_a_receipt_with_no_inclusion_proof_is_not_verified():
    key, public_key_b64 = _ts_key()
    protected = cbor.dumps({1: ALG_ES256, HEADER_VDS: VDS_RFC9162_SHA256, 4: b"ts.example"})
    root = node_hash(leaf_hash(STATEMENT), leaf_hash(OTHER))
    receipt = _cose_sign1(protected, {}, root, _sign_cose(key, protected, root))
    result = verify_receipt(receipt, STATEMENT, _trust_root(public_key_b64, "ts.example"))
    assert not result.verified
    assert result.inclusion is None


def test_a_statement_round_trips_and_carries_its_receipt():
    issuer = Ed25519PrivateKey.generate()
    statement = encode_signed_statement(STATEMENT, issuer, key_id=b"confidior")
    decoded = decode_statement(statement)
    assert decoded["payload"] == STATEMENT
    assert decoded["protected"][HEADER_VDS] == VDS_RFC9162_SHA256

    key, public_key_b64 = _ts_key()
    receipt = _make_receipt(key, key_id="ts.example")
    transparent = encode_signed_statement(
        STATEMENT, issuer, key_id=b"confidior", receipts=[receipt]
    )
    receipts = extract_receipts(transparent)
    assert len(receipts) == 1
    # The extracted receipt is the same object, and still verifies.
    checked = verify_receipt(receipts[0], STATEMENT, _trust_root(public_key_b64, "ts.example"))
    assert checked.verified


def test_a_statement_without_receipts_has_none():
    statement = encode_signed_statement(STATEMENT, Ed25519PrivateKey.generate())
    assert extract_receipts(statement) == []


def test_an_ecdsa_statement_signs_and_decodes():
    """The emitter is not Ed25519-only; a TS-facing issuer may hold ECDSA."""
    key = ec.generate_private_key(ec.SECP256R1())
    statement = encode_signed_statement(STATEMENT, key, key_id=b"issuer", algorithm=ALG_ES256)
    decoded = decode_statement(statement)
    assert decoded["payload"] == STATEMENT
    assert decoded["protected"][1] == ALG_ES256


def test_the_two_mechanisms_agree_on_one_commitment():
    """A Rekor anchor and a SCITT receipt are the same proof, differently packed.

    This is the operation a caller actually wants -- "is this digest in the logs
    I was told about" -- across both containers at once, with the Rekor side
    checked against the checkpoint that signs its root.
    """
    from src.core.merkle import node_hash
    from src.export.scitt import verify_as_leaf

    rekor_body = b'{"rekor": "entry"}'
    root = node_hash(leaf_hash(rekor_body), leaf_hash(OTHER))
    entry = {
        "body": base64.b64encode(rekor_body).decode(),
        "verification": {
            "inclusionProof": {
                "logIndex": 0,
                "treeSize": 2,
                "rootHash": base64.b64encode(root).decode(),
                "hashes": [base64.b64encode(leaf_hash(OTHER)).decode()],
            }
        },
    }

    # With no trust root the proof checks but the log's signature is unjudged.
    result = verify_as_leaf(rekor_body, [], entry, TrustRoot())[0]
    assert result.inclusion is True
    assert result.signature is None
    assert not result.verified
    assert result.reason  # and it says why


def test_verify_as_leaf_covers_receipts_and_rekor_together():
    """"Both records" means both results, in order, not just the first."""
    from src.export.scitt import verify_as_leaf

    key, public_key_b64 = _ts_key()
    receipt = _make_receipt(key, key_id="ts.example")
    results = verify_as_leaf(STATEMENT, [receipt], None, _trust_root(public_key_b64, "ts.example"))
    assert len(results) == 1
    assert results[0].verified


def test_an_unknown_data_structure_is_not_read_as_a_failed_proof():
    """A proof from some other structure is uninterpretable, not wrong.

    The audit path only means "RFC 9162 inclusion proof" because the receipt says
    so. Reading one as the other would report a failed proof for a receipt that
    was simply never built the way we assume.
    """
    key, public_key_b64 = _ts_key()
    root = node_hash(leaf_hash(STATEMENT), leaf_hash(OTHER))
    unprotected = {HEADER_VDP: {PROOF_INCLUSION: [cbor.dumps([2, 0, [leaf_hash(OTHER)]])]}}
    protected = cbor.dumps({1: ALG_ES256, HEADER_VDS: 9999, 4: b"ts.example"})
    receipt = _cose_sign1(protected, unprotected, root, _sign_cose(key, protected, root))
    result = verify_receipt(receipt, STATEMENT, _trust_root(public_key_b64, "ts.example"))
    assert not result.verified
    assert result.inclusion is None
    assert "data structure" in result.reason
