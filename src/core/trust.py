"""The keys the engine will accept a signature from.

Phase 0 verified the *structure* of a signed statement and then reported the
signer's claimed identity. That is a claim about a name, not about who signed:
anyone can write ``"keyid": "release-bot"`` into an envelope. This module holds
the configured trust root, so a signature is checked against a key the operator
named rather than against the identity the envelope asserts about itself.

Two things use it: DSSE/in-toto provenance statements (``src/verify/iac.py``)
and Rekor signed checkpoints (``src/export/rekor.py``).

Deliberately small. One key type (Ed25519), one file format (JSON), one env
override. A trust root that guesses is worse than none, so an unknown key id
verifies as ``None``, "not checked", and never as ``True``.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

#: Curve name -> the curve object, for the ECDSA algorithms we accept. The keys
#: name the curve the way COSE does, because that is where these keys come from.
_CURVES: dict[str, Any] = {
    "es256": ec.SECP256R1,
    "p256": ec.SECP256R1,
    "es384": ec.SECP384R1,
    "p384": ec.SECP384R1,
    "es512": ec.SECP521R1,
    "p521": ec.SECP521R1,
}

_HASHES: dict[str, Any] = {
    "secp256r1": hashes.SHA256,
    "secp384r1": hashes.SHA384,
    "secp521r1": hashes.SHA512,
}


def _normalise_algorithm(algorithm: str) -> str:
    return algorithm.strip().lower()


class SignatureEncoding(StrEnum):
    """How an ECDSA signature is wrapped on the wire.

    Ed25519 signatures are the same either way; only ECDSA differs, and the two
    conventions both appear in the formats this engine reads. COSE (RFC 9052)
    carries ``r || s`` as two fixed-width big-endian integers; C2SP signed notes
    carry the ASN.1 DER form that ``cryptography`` produces natively. Passing the
    wrong one is a verification failure, not a guess, which is why it is a
    parameter rather than auto-detection.
    """

    RAW = "raw"
    ASN1 = "asn1"


def _raw_ecdsa_to_der(signature: bytes) -> bytes:
    """Convert a COSE-style raw ``r || s`` ECDSA signature to the DER form.

    COSE (and therefore every receipt this engine reads) carries ECDSA
    signatures as two fixed-width big-endian integers, not ASN.1. An odd-length
    signature is left alone so that it fails verification rather than being
    silently reinterpreted.
    """
    if len(signature) % 2:
        return signature
    half = len(signature) // 2
    return encode_dss_signature(
        int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big")
    )

#: Environment override, so a deployment can point at its own trust root
#: without editing a checked-in file. An absolute path; relative paths resolve
#: against the process working directory.
TRUST_ROOT_ENV = "CONFIDIOR_TRUST_ROOT"

#: Where a trust root is looked for when none is passed and the env is unset.
DEFAULT_TRUST_ROOT_FILENAME = "trust-roots.json"


class TrustRootError(Exception):
    """Raised when a trust root file exists but cannot be read as one."""


@dataclass(frozen=True)
class TrustedKey:
    """One key the operator has decided to accept signatures from.

    ``algorithm`` names the curve, not one wire format. Both of the things this
    engine checks carry COSE-style signatures -- Ed25519 as raw bytes, ECDSA as
    concatenated ``r || s`` with no ASN.1 wrapper -- so ``verify`` takes that
    encoding and converts to DER internally, which is what ``cryptography``
    wants. A caller holding a DER signature would have to unwrap it first.

    Recognised values: ``ed25519``, ``es256``/``p256``, ``es384``/``p384``,
    ``es512``/``p521``.
    """

    key_id: str
    public_key_b64: str
    algorithm: str = "ed25519"

    def public_key(self) -> Any:
        """The parsed public key, or ``None`` when this key cannot be read.

        ``None`` covers an unknown algorithm, bad base64, and a point that is not
        on the named curve. All three are "this trust root entry is unusable"
        rather than a reason to crash a verification that was asked a yes/no
        question.
        """
        try:
            raw = base64.b64decode(self.public_key_b64)
        except (binascii.Error, ValueError):
            return None
        algorithm = _normalise_algorithm(self.algorithm)
        if algorithm == "ed25519":
            try:
                return Ed25519PublicKey.from_public_bytes(raw)
            except ValueError:
                return None
        curve = _CURVES.get(algorithm)
        if curve is None:
            return None
        try:
            return EllipticCurvePublicKey.from_encoded_point(curve(), raw)
        except ValueError:
            return None

    def verify(
        self, message: bytes, signature: bytes, encoding: SignatureEncoding = SignatureEncoding.RAW
    ) -> bool:
        """True when ``signature`` is this key's signature over ``message``.

        A malformed key or signature is a failed verification, not an exception:
        a caller asking "did this verify" should get a no, not a stack trace.
        """
        try:
            key = self.public_key()
            if isinstance(key, Ed25519PublicKey):
                key.verify(signature, message)
            elif isinstance(key, EllipticCurvePublicKey):
                der = (
                    signature
                    if encoding is SignatureEncoding.ASN1
                    else _raw_ecdsa_to_der(signature)
                )
                key.verify(der, message, ec.ECDSA(_HASHES[key.curve.name]()))
            else:
                return False
        except (InvalidSignature, ValueError):
            return False
        return True

    def signature_type_byte(self) -> int | None:
        """The C2SP signed-note signature type this key signs with (0x01/0x02).

        ``None`` for an algorithm with no assigned type, which makes the key
        unusable for a note rather than ambiguously usable.
        """
        algorithm = _normalise_algorithm(self.algorithm)
        if algorithm == "ed25519":
            return 0x01
        return 0x02 if algorithm in _CURVES else None

    def spki_der(self) -> bytes | None:
        """The key in DER SubjectPublicKeyInfo form, or ``None``.

        Needed because the C2SP note key id for ECDSA keys is a hash of this
        encoding specifically, not of the raw point.
        """
        from cryptography.hazmat.primitives.serialization import Encoding as _Enc
        from cryptography.hazmat.primitives.serialization import PublicFormat as _Fmt

        key = self.public_key()
        if not isinstance(key, EllipticCurvePublicKey):
            return None
        return key.public_bytes(_Enc.DER, _Fmt.SubjectPublicKeyInfo)


@dataclass(frozen=True)
class TrustRoot:
    """The set of keys the engine accepts, keyed by the id an envelope names."""

    keys: tuple[TrustedKey, ...] = ()

    def key(self, key_id: str | None) -> TrustedKey | None:
        if not key_id:
            return None
        for candidate in self.keys:
            if candidate.key_id == key_id:
                return candidate
        return None

    def verify(
        self,
        key_id: str | None,
        message: bytes,
        signature: bytes,
        encoding: SignatureEncoding = SignatureEncoding.RAW,
    ) -> bool | None:
        """Verify a signature, or ``None`` when the key is not in the trust root.

        The three-valued result is the point. ``False`` means the signature is
        wrong; ``None`` means this engine was not configured to judge it. A
        caller that collapses the two is claiming a verification it did not do.
        """
        trusted = self.key(key_id)
        if trusted is None:
            return None
        return trusted.verify(message, signature, encoding)

    def __bool__(self) -> bool:
        return bool(self.keys)


EMPTY_TRUST_ROOT = TrustRoot()


def load_trust_root(path: str | Path | None = None) -> TrustRoot:
    """Load a trust root from JSON.

    Resolution order: the explicit ``path``, then ``$CONFIDIOR_TRUST_ROOT``, then
    ``trust-roots.json`` next to the package (the engine root). A missing file
    is an empty trust root, not an error: running unconfigured is the Phase 0
    behaviour and must stay available. A file that exists but is malformed
    raises, because silently ignoring a trust root is how a misconfiguration
    goes unnoticed.

    Format::

        {"keys": [
            {"key_id": "release-bot", "algorithm": "ed25519", "public_key": "<base64 raw>"},
            {"key_id": "rekor.sigstore.dev", "algorithm": "ES256",
             "public_key": "<base64 uncompressed point>"}
        ]}

    ``algorithm`` selects how the public key is encoded, not one wire format:
    ``ed25519`` keys are raw 32-byte values, ``es256``/``es384``/``es512`` (or the
    equivalent ``p256``/``p384``/``p521``) are uncompressed SEC1 points. A log
    checkpoint signed by a P-256 key, which is what Sigstore publishes, needs the
    latter.
    """
    resolved = _resolve_path(path)
    if resolved is None or not resolved.exists():
        return EMPTY_TRUST_ROOT
    try:
        data = json.loads(resolved.read_text())
    except json.JSONDecodeError as e:
        raise TrustRootError(f"{resolved} is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise TrustRootError(f"{resolved} must contain a JSON object")

    keys: list[TrustedKey] = []
    for raw in data.get("keys", []):
        if not isinstance(raw, dict) or "key_id" not in raw or "public_key" not in raw:
            raise TrustRootError(f"{resolved}: every key needs key_id and public_key")
        keys.append(
            TrustedKey(
                key_id=str(raw["key_id"]),
                public_key_b64=str(raw["public_key"]),
                algorithm=str(raw.get("algorithm", "ed25519")),
            )
        )
    return TrustRoot(keys=tuple(keys))


def _resolve_path(path: str | Path | None) -> Path | None:
    if path is not None:
        return Path(path)
    override = os.environ.get(TRUST_ROOT_ENV)
    if override:
        return Path(override)
    # src/core/trust.py -> the engine root is two parents up.
    return Path(__file__).resolve().parent.parent.parent / DEFAULT_TRUST_ROOT_FILENAME
