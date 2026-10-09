"""C2SP signed notes -- the format of a Rekor checkpoint.

Two of these tests are worth more than the others: the ones that run against the
live Rekor checkpoint. The format has details that a self-consistent fixture
would happily get wrong -- an em dash rather than two hyphens, and a key id that
is a hash of a key's DER encoding rather than of its raw bytes -- and only a real
checkpoint signed by a real key catches those.

The Rekor key and checkpoint below are public values from the live log, captured
once so the suite does not need the network.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.core.notes import (
    parse_checkpoint,
    verify_checkpoint,
)
from src.core.trust import TrustedKey, TrustRoot


def _rekor_point() -> bytes:
    """The Rekor log key's raw uncompressed point, as a trust root holds it.

    Derived from the published SPKI rather than hardcoded, so the test is
    exercising the same encoding a real trust root would use.
    """
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    key = load_der_public_key(base64.b64decode(REKOR_SPKI_DER_B64))
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


# --- The live Rekor log ------------------------------------------------------
# https://rekor.sigstore.dev/api/v1/log, 2026-10-09
REKOR_CHECKPOINT = (
    "rekor.sigstore.dev - 1193050959916656506\n"
    "3032193267\n"
    "Hkea1qNb20RitYVq0FpLZVQ/X4vOdNUtej6T3A+q+ZQ=\n"
    "\n"
    "\u2014 rekor.sigstore.dev "
    "wNI9ajBFAiEA7vP6QDSEfVwEEZVPhcBvjtDT4AocKT8/Bt8QNqwYnJECICrPy9LAPNzeDEeEI0X5+r8"
    "D6cf3DwkCBOtPy8xk+TyB\n"
)

# The Rekor log's public key, from sigstore/root-signing targets/rekor.pub (P-256),
# as the base64 DER that PEM wraps.
REKOR_SPKI_DER_B64 = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6"
    "yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw=="
)


# --- Building notes synthetically -------------------------------------------


def _ed25519_key() -> tuple[Ed25519PrivateKey, TrustedKey]:
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    trusted = TrustedKey(
        key_id="log.example", public_key_b64=base64.b64encode(raw).decode(), algorithm="ed25519"
    )
    return key, trusted


def _ecdsa_key() -> tuple[ec.EllipticCurvePrivateKey, TrustedKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
    )
    trusted = TrustedKey(
        key_id="log.example", public_key_b64=base64.b64encode(raw).decode(), algorithm="ES256"
    )
    return key, trusted


def _unsigned_note(text_body: str = "log.example - 12345\n7\ncm9vdA==\n") -> str:
    """Note text, already ending in its newline; the divider is added at signing."""
    return text_body


def _key_id_for(name: str, trusted: TrustedKey) -> bytes:
    """The C2SP key id, computed here independently of the code under test."""
    if trusted.algorithm == "ed25519":
        material = base64.b64decode(trusted.public_key_b64)
        digest = hashlib.sha256(name.encode() + b"\x0a\x01" + material).digest()
    else:
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), base64.b64decode(trusted.public_key_b64)
        )
        spki = key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashlib.sha256(spki).digest()  # no name, no type byte: ECDSA hashes the SPKI alone
    return digest[:4]


def _sign_note(name: str, trusted: TrustedKey, private_key, body: str) -> str:
    if isinstance(private_key, Ed25519PrivateKey):
        signature = private_key.sign(body.encode())
    else:
        # C2SP note signatures are ASN.1 DER, unlike COSE's raw r || s.
        signature = private_key.sign(body.encode(), ec.ECDSA(hashes.SHA256()))
    blob = _key_id_for(name, trusted) + signature
    return body + "\n" + f"\u2014 {name} {base64.b64encode(blob).decode()}\n"


def test_the_live_rekor_checkpoint_verifies():
    """The format details that a synthetic fixture would get wrong."""
    root = TrustRoot(
        keys=(
                TrustedKey(
                key_id="rekor.sigstore.dev",
                public_key_b64=base64.b64encode(_rekor_point()).decode(),
                algorithm="ES256",
            ),
        )
    )
    assert verify_checkpoint(REKOR_CHECKPOINT, root) is True


def test_the_live_checkpoint_parses_its_tree_state():
    parsed = parse_checkpoint(REKOR_CHECKPOINT)
    assert parsed.tree_size == 3032193267
    assert parsed.root_hash_b64 == "Hkea1qNb20RitYVq0FpLZVQ/X4vOdNUtej6T3A+q+ZQ="


def test_a_tampered_live_checkpoint_fails():
    root = TrustRoot(
        keys=(
                TrustedKey(
                key_id="rekor.sigstore.dev",
                public_key_b64=base64.b64encode(_rekor_point()).decode(),
                algorithm="ES256",
            ),
        )
    )
    tampered = REKOR_CHECKPOINT.replace("3032193267", "3032193268")
    assert verify_checkpoint(tampered, root) is False


def test_an_ed25519_note_round_trips():
    key, trusted = _ed25519_key()
    body = _unsigned_note()
    note = _sign_note("log.example", trusted, key, body)
    assert verify_checkpoint(note, TrustRoot(keys=(trusted,))) is True


def test_an_ecdsa_note_round_trips():
    key, trusted = _ecdsa_key()
    note = _sign_note("log.example", trusted, key, _unsigned_note())
    assert verify_checkpoint(note, TrustRoot(keys=(trusted,))) is True


def test_a_note_from_an_unknown_key_is_unjudged():
    key, trusted = _ed25519_key()
    note = _sign_note("log.example", trusted, key, _unsigned_note())
    assert verify_checkpoint(note, TrustRoot()) is None


def test_a_wrong_name_does_not_match_a_trusted_key():
    """Name and key id must both match, per the spec."""
    key, trusted = _ed25519_key()
    note = _sign_note("other.example", trusted, key, _unsigned_note())
    assert verify_checkpoint(note, TrustRoot(keys=(trusted,))) is None


def test_a_note_with_no_signature_line_is_not_verified():
    """A malformed note is unjudged, not an exception."""
    assert verify_checkpoint("just some text\n", TrustRoot(keys=(_ed25519_key()[1],))) is None


def test_blank_lines_in_the_note_do_not_break_parsing():
    """Note text may contain empty lines; only the last one separates."""
    key, trusted = _ed25519_key()
    body = "log.example - 1\n5\ncm9vdA==\n\nan extra paragraph\n"
    note = _sign_note("log.example", trusted, key, body)
    parsed = parse_checkpoint(note)
    assert "an extra paragraph" in parsed.text
    assert verify_checkpoint(note, TrustRoot(keys=(trusted,))) is True
