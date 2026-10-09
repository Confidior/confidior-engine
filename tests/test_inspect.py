"""`confidior inspect`: verifying a Rekor anchor from the log.

The command's whole job is to distinguish a verified anchor from an unproven one,
so the tests are mostly about the exit codes and the three-valued results: an
anchor whose proof checks but whose checkpoint cannot be judged must not exit 0.

Everything here runs offline against a captured real entry and a stub fetcher;
`pytest -m live` style network tests are deliberately absent, since the point of
pinning the fixture is that the suite does not need the log.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.cli.inspect import EXIT_ERROR, EXIT_UNPROVEN, EXIT_VERIFIED, run_inspect


class _Args:
    def __init__(self, uuid: str | None = "the-uuid", trust_root=None, fetcher=None, rekor=None):
        self.uuid = uuid
        self.rekor = rekor
        self.rekor_url = "https://example.com/rekor"
        self.trust_root = trust_root
        self.fetcher = fetcher


@pytest.fixture
def real_entry() -> dict:
    return json.loads((Path(__file__).parent / "fixtures" / "rekor-entry.json").read_text())


def _entry_fetcher(entry: dict):
    def fetcher(url: str, body: bytes) -> list:
        return [{entry.get("uuid", "the-uuid"): entry}]

    return fetcher


def test_a_real_entry_with_a_real_checkpoint_verifies(real_entry, capsys):
    """The whole path: fetch the entry, check the proof, check the checkpoint.

    Uses the same captured entry as the receipt tests and the live Rekor
    checkpoint, so the two halves are the ones the log actually serves.
    """
    checkpoint = _rekor_checkpoint()
    args = _Args(
        uuid=real_entry["uuid"],
        trust_root=_write_trust_root(),
        fetcher=_combined_fetcher(real_entry, checkpoint),
    )
    code = run_inspect(args)
    out = capsys.readouterr().out
    assert code == EXIT_VERIFIED
    assert "inclusion proof:   verified" in out
    assert "signed checkpoint: verified" in out
    assert "This entry is in a tree the log signed." in out


def test_a_proof_without_a_trust_root_is_unproven_not_verified(real_entry, capsys):
    """The proof checks, but nobody can judge the log's signature: exit 2.

    This is the failure mode worth guarding: the arithmetic all passes, and the
    anchor is still not verified, because we hold no key that says the log meant
    it.
    """
    fetcher = _combined_fetcher(real_entry, _rekor_checkpoint())
    args = _Args(uuid=real_entry["uuid"], fetcher=fetcher)
    code = run_inspect(args)
    out = capsys.readouterr().out
    assert code == EXIT_UNPROVEN
    assert "inclusion proof:   verified" in out
    assert "not checked (no trust root configured" in out
    assert "is not proven" in out


def test_a_log_that_serves_no_checkpoint_is_unproven(real_entry, capsys):
    args = _Args(
        uuid=real_entry["uuid"],
        fetcher=_combined_fetcher(real_entry, None),
    )
    code = run_inspect(args)
    out = capsys.readouterr().out
    assert code == EXIT_UNPROVEN
    assert "the log served no checkpoint" in out


def test_a_retrieval_failure_exits_with_an_error(capsys):
    def fetcher(url: str, body: bytes):
        raise FileNotFoundError("no such entry")

    code = run_inspect(_Args(fetcher=fetcher))
    assert code == EXIT_ERROR
    assert "error:" in capsys.readouterr().out


def test_the_entry_uuid_is_reported(real_entry, capsys):
    """The entry must name itself, since the bundle records the UUID."""
    args = _Args(uuid=real_entry["uuid"], fetcher=_combined_fetcher(real_entry, None))
    run_inspect(args)
    assert real_entry["uuid"] in capsys.readouterr().out


# --- Fixtures for the real Rekor material ------------------------------------
# Kept here (rather than imported from test_notes) so this file stands alone.


def _rekor_checkpoint() -> str:
    from tests.test_notes import REKOR_CHECKPOINT

    return REKOR_CHECKPOINT


def _write_trust_root() -> str:
    """A trust root file naming the real Rekor key, for --trust-root."""
    import base64
    import tempfile

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    from tests.test_notes import REKOR_SPKI_DER_B64

    key = load_der_public_key(base64.b64decode(REKOR_SPKI_DER_B64))
    point = key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    document = {
        "keys": [
            {
                "key_id": "rekor.sigstore.dev",
                "algorithm": "ES256",
                "public_key": base64.b64encode(point).decode(),
            }
        ]
    }
    path = Path(tempfile.mkdtemp()) / "trust-roots.json"
    path.write_text(json.dumps(document))
    return str(path)


def _combined_fetcher(entry: dict, checkpoint: str | None):
    """One fetcher for both calls, dispatched on the URL."""

    def fetcher(url: str, body: bytes | None = None):
        if url.endswith("/api/v1/log"):
            return {"signedTreeHead": checkpoint} if checkpoint else {}
        return [{entry.get("uuid", "the-uuid"): entry}]

    return fetcher


def test_an_entry_can_be_named_by_log_index(real_entry, capsys):
    """A log index is the form a checkpoint's proof indexes against."""
    seen: dict = {}

    def fetcher(url: str, body: bytes | None = None):
        # Called once with a body (POST retrieve) and once without (GET checkpoint).
        if body is not None:
            seen["query"] = json.loads(body)
        return [{real_entry["uuid"]: real_entry}]

    args = _Args(uuid=None, rekor=95836569, fetcher=fetcher)
    run_inspect(args)
    assert seen["query"] == {"logIndexes": [95836569]}
    assert "inclusion proof:   verified" in capsys.readouterr().out


def test_the_signing_key_is_reported_from_the_real_entry(real_entry, capsys):
    """The entry names its signer, and the report says what that is worth.

    A Fulcio certificate carries an empty subject and puts the identity in the
    SAN, so a report that reads only the subject shows nothing for exactly the
    certificates this command meets. The chain is *not* verified here, and the
    output must not imply it was.
    """
    args = _Args(uuid=real_entry["uuid"], fetcher=_combined_fetcher(real_entry, None))
    run_inspect(args)
    out = capsys.readouterr().out
    assert "signing key:" in out
    assert "sigstore-intermediate" in out  # the issuer
    assert "could not be parsed" not in out
