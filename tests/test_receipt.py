"""The Rekor anchor receipt: verifying an inclusion proof.

An anchor is only checkable if the bundle carries the proof that came back with
it, so this covers the proof half -- the audit path must rebuild exactly the
root the log named. The other half, the signed checkpoint that makes that root
the *log's* root, is C2SP's signed-note format and lives in ``test_notes.py``.

The fixture is a real two-leaf Merkle tree, so the hash arithmetic is exercised
rather than mocked.
"""

from __future__ import annotations

import base64
import hashlib

from src.export.rekor import verify_inclusion_proof


def _leaf(body: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + body).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _make_tree() -> tuple[str, dict]:
    """Two leaves, their Merkle root, and the entry Rekor would return for leaf 0."""
    body_a, body_b = b'{"a":1}', b'{"b":2}'
    root = _node(_leaf(body_a), _leaf(body_b))
    entry = {
        "body": base64.b64encode(body_a).decode(),
        "verification": {
            "inclusionProof": {
                "logIndex": 0,
                "treeSize": 2,
                "rootHash": base64.b64encode(root).decode(),
                "hashes": [base64.b64encode(_leaf(body_b)).decode()],
            }
        },
    }
    return base64.b64encode(root).decode(), entry




def test_a_valid_inclusion_proof_verifies():
    _, entry = _make_tree()
    assert verify_inclusion_proof(entry) is True


def test_a_proof_for_a_different_root_fails():
    _, entry = _make_tree()
    entry["verification"]["inclusionProof"]["rootHash"] = base64.b64encode(b"x" * 32).decode()
    assert verify_inclusion_proof(entry) is False


def test_a_tampered_body_fails():
    _, entry = _make_tree()
    entry["body"] = base64.b64encode(b'{"a":999}').decode()
    assert verify_inclusion_proof(entry) is False


def test_no_proof_is_none_not_verified():
    """An unanchored or proof-less entry must not read as checked."""
    assert verify_inclusion_proof({"body": "eyJhIjoxfQ=="}) is None
    assert verify_inclusion_proof({"body": "x", "verification": {}}) is None


# --- A real Rekor entry, pinned ----------------------------------------------
# From https://rekor.sigstore.dev/api/v1/log/entries/retrieve (2026-10-09),
# captured so the encoding details do not depend on the network. This is the
# only test that catches Rekor's mixed encodings: body is base64, while the
# audit path and rootHash are hex. Decoding all three the same way fails
# silently -- the proof simply reports as unverified rather than as unparseable.


def _real_entry() -> dict:
    import json
    from pathlib import Path

    path = Path(__file__).parent / "fixtures" / "rekor-entry.json"
    return json.loads(path.read_text())


def test_a_real_rekor_entry_verifies():
    """The live log's 27-element hex proof, decoded and checked end to end."""
    assert verify_inclusion_proof(_real_entry()) is True


def test_a_real_entry_with_a_corrupted_leaf_fails():
    """The same proof against a different leaf: evaluated, and wrong."""
    entry = _real_entry()
    entry["body"] = base64.b64encode(b"different bytes entirely").decode()
    assert verify_inclusion_proof(entry) is False


def test_a_proof_whose_fields_do_not_decode_is_not_checkable():
    """Undecodable proof material is not-checked, not a failed proof."""
    assert verify_inclusion_proof({"body": "!!not base64!!", "verification": {}}) is None


def test_a_bundle_anchor_can_be_verified_from_the_bundle_alone():
    """The whole point of keeping the body and proof: verification needs no network.

    Round-trips a real entry through ``RekorEntry`` and checks the proof from what
    the bundle holds. Dropping the entry body would make this impossible while
    leaving the proof in place, which is the kind of half-record that looks
    verifiable and is not.
    """
    from datetime import datetime

    from src.core.taxonomy import RekorEntry

    entry = _real_entry()
    proof = entry["verification"]["inclusionProof"]
    rekor_entry = RekorEntry(
        log_index=proof["logIndex"],
        log_id="",
        entry_uuid=entry["uuid"],
        integrated_time=datetime.fromtimestamp(entry["integratedTime"]),
        body=entry["body"],
        inclusion_proof=proof,
    )
    from_bundle = {"body": rekor_entry.body, "verification": {"inclusionProof": proof}}
    assert verify_inclusion_proof(from_bundle) is True
    # And the same proof with no body kept is not-checkable, not verified.
    assert verify_inclusion_proof({"verification": {"inclusionProof": proof}}) is None


def test_verify_reports_the_anchor_state_not_just_its_presence():
    """`confidior verify` must say whether the anchor checks out, not that one exists.

    It used to print "rekor: index=… (anchored)" for any entry, which is a claim
    about a record's existence rather than about its validity. The three phrasings
    below are deliberately distinct, because "verified", "unjudged" and "failed"
    are three different situations and only the first is good news.
    """
    from datetime import datetime

    from src.cli.main import _anchor_state
    from src.core.taxonomy import RekorEntry

    entry = _real_entry()
    proof = entry["verification"]["inclusionProof"]
    common = {
        "log_index": proof["logIndex"],
        "log_id": "",
        "entry_uuid": entry["uuid"],
        "integrated_time": datetime.fromtimestamp(entry["integratedTime"]),
    }

    with_proof = _anchor_state(
        RekorEntry(**common, body=entry["body"], inclusion_proof=proof)
    )
    assert with_proof == "proof ok, no checkpoint"

    without_body = _anchor_state(RekorEntry(**common, inclusion_proof=proof))
    assert "uncheckable" in without_body

    without_proof = _anchor_state(
        RekorEntry(**common, body=entry["body"], inclusion_proof={})
    )
    assert without_proof == "no proof recorded"
