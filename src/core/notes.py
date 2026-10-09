"""C2SP signed notes: the format of a transparency log's checkpoint.

A checkpoint is the log's periodic signed statement of "my Merkle tree has this
root, at this size". Verifying one is what turns "this statement is in *a* tree"
into "this statement is in *the log*": the inclusion proof is only as good as the
root it proves against, and the checkpoint is what signs that root.

The format is C2SP's "signed note": UTF-8 text ending in a newline, a blank line,
then one or more signature lines. Two details are easy to get wrong and both are
tested against the live Rekor log rather than a fixture:

* the separator is an **em dash** (U+2014), not two hyphens;
* the signature line is ``— <name> <base64(4-byte key id || signature)>``, and for
  ECDSA keys the key id is the first four bytes of ``sha256(DER SubjectPublicKeyInfo)``
  -- a hash of the key's DER encoding, with no name and no separator.

Rekor is the deployed instance, so this is what actually appears on
``GET /api/v1/log``. RFC 9942's COSE receipts are a different container for the
same two facts; :mod:`src.export.scitt` handles those.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

from src.core.trust import SignatureEncoding, TrustedKey, TrustRoot

#: The separator before the signature lines: em dash, space.
SIGNATURE_PREFIX = "\u2014 "

#: C2SP assigns 0x01 to Ed25519 notes and 0x02 to ECDSA notes.
SIGNATURE_TYPE_ED25519 = 0x01
SIGNATURE_TYPE_ECDSA = 0x02


@dataclass(frozen=True)
class Checkpoint:
    """A parsed checkpoint: the signed text and the signatures over it."""

    #: The note text, including its final newline and excluding the blank line.
    text: str
    #: ``(key_name, key_id, signature_bytes)`` for each signature line.
    signatures: tuple[tuple[str, bytes, bytes], ...]

    @property
    def tree_size(self) -> int | None:
        """The tree size a Rekor checkpoint states, or ``None`` if unparseable."""
        lines = self.text.rstrip("\n").split("\n")
        if len(lines) < 2:
            return None
        try:
            return int(lines[1])
        except ValueError:
            return None

    @property
    def root_hash_b64(self) -> str:
        """The base64 root hash a Rekor checkpoint states, or ``""``."""
        lines = self.text.rstrip("\n").split("\n")
        return lines[2] if len(lines) >= 3 else ""


def parse_checkpoint(checkpoint: str | bytes) -> Checkpoint:
    """Parse a C2SP signed note into its text and signatures.

    The text is everything up to the *last* empty line -- the spec says so
    explicitly, because note text may itself contain blank lines, so the first
    blank line is not necessarily the divider.

    Raises :class:`ValueError` for a note with no signature line at all; that is
    a malformed note, not a note that failed verification.
    """
    raw = checkpoint.decode("utf-8") if isinstance(checkpoint, bytes) else checkpoint
    normalized = raw.replace("\r\n", "\n")
    lines = normalized.split("\n")

    signature_lines: list[tuple[str, bytes, bytes]] = []
    divider = None
    for i, line in enumerate(lines):
        if line.startswith(SIGNATURE_PREFIX):
            if divider is None:
                divider = i
            parts = line.split(" ")
            if len(parts) < 3:
                continue
            name = parts[1]
            try:
                blob = base64.b64decode(parts[2], validate=True)
            except (binascii.Error, ValueError):
                continue
            if len(blob) < 5:
                continue
            signature_lines.append((name, blob[:4], blob[4:]))

    if divider is None or not signature_lines:
        raise ValueError("not a signed note: no signature line")

    # The note text ends at the blank line before the first signature, which is
    # the last empty line in the note.
    text_end = divider
    while text_end > 0 and lines[text_end - 1] == "":
        text_end -= 1
    text = "\n".join(lines[:text_end]) + "\n"
    return Checkpoint(text=text, signatures=tuple(signature_lines))


def note_key_id(name: str, trusted: TrustedKey) -> bytes | None:
    """The C2SP note key id for a key, or ``None`` when the key cannot sign a note.

    The two signature types hash different things, which is the part worth
    reading twice:

    * Ed25519 (0x01) hashes ``name || 0x0a || 0x01 || raw public key``;
    * ECDSA (0x02) hashes the DER SubjectPublicKeyInfo **alone** -- no name, no
      type byte, no separator.

    The asymmetry is the spec's, not a simplification here, and it is the reason
    this cannot be one shared formula.
    """
    type_byte = trusted.signature_type_byte()
    if type_byte == SIGNATURE_TYPE_ED25519:
        try:
            raw = base64.b64decode(trusted.public_key_b64, validate=True)
        except (binascii.Error, ValueError):
            return None
        digest = hashlib.sha256(name.encode() + b"\x0a" + bytes([type_byte]) + raw).digest()
        return digest[:4]
    if type_byte == SIGNATURE_TYPE_ECDSA:
        spki = trusted.spki_der()
        if spki is None:
            return None
        return hashlib.sha256(spki).digest()[:4]
    return None


def verify_checkpoint(checkpoint: str | bytes, trust_root: TrustRoot) -> bool | None:
    """Verify a checkpoint against a trust root.

    Returns ``True`` when a signature from a key in the trust root verifies,
    ``False`` when a trusted key's signature is present but wrong, and ``None``
    when the note carries no signature from any trusted key. That last case is
    the important one: a checkpoint we have no key for is unjudged, and a caller
    must not read it as verified.

    Note names are matched alongside key ids, per the spec: a signature is only
    considered from a known key if *both* the name and the id match.
    """
    try:
        parsed = parse_checkpoint(checkpoint)
    except ValueError:
        return None

    if not trust_root:
        return None

    saw_trusted_key = False
    for name, key_id, signature in parsed.signatures:
        for trusted in trust_root.keys:
            if trusted.key_id != name:
                continue
            if note_key_id(name, trusted) != key_id:
                continue
            saw_trusted_key = True
            if trusted.verify(
                parsed.text.encode(), signature, encoding=SignatureEncoding.ASN1
            ):
                return True
    # A trusted key was named but every signature failed; that is a rejection,
    # not an absence of judgement.
    return False if saw_trusted_key else None
