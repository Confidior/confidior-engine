"""Sigstore Rekor transparency log client for evidence anchoring."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import urllib.error
import urllib.request
from typing import Any, cast

from src.core.merkle import leaf_hash, root_from_inclusion_proof

logger = logging.getLogger(__name__)

SIGNING_CONFIG_URL = (
    "https://raw.githubusercontent.com/sigstore/root-signing/main/"
    "targets/signing_config.v0.2.json"
)

MAX_ATTESTATION_SIZE = 100_000

DEFAULT_GET_TIMEOUT = 5.0
DEFAULT_POST_TIMEOUT = 10.0


class RekorError(Exception):
    """Raised on any Rekor interaction failure (network, parsing, size)."""


def _http_get_json(url: str, timeout: float = DEFAULT_GET_TIMEOUT) -> dict[str, Any]:
    """GET a URL and return parsed JSON. Module-level for easy test patching."""
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return cast(dict[str, Any], json.loads(resp.read().decode("utf-8")))


def _http_post_json(url: str, body: bytes, timeout: float = DEFAULT_POST_TIMEOUT) -> dict[str, Any]:
    """POST JSON body to URL and return parsed JSON response."""
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return cast(dict[str, Any], json.loads(resp.read().decode("utf-8")))


def hash_payload(payload: bytes) -> str:
    """Return hex SHA-256 of payload bytes."""
    return hashlib.sha256(payload).hexdigest()


def verify_inclusion_proof(entry: dict[str, Any]) -> bool | None:
    """Check that a Rekor entry's inclusion proof recomputes to its root hash.

    This validates the entry against the *tree it names*: the audit path must
    rebuild exactly the ``rootHash`` the log reported. It does not prove the log
    signed that root -- that is the checkpoint's job, and it is the half that
    needs the log's public key (see :func:`src.core.notes.verify_checkpoint`).

    The encodings are Rekor's and they are not uniform, which is worth stating
    because getting it wrong fails silently: ``body`` is base64, while the
    ``rootHash`` and every entry in ``hashes`` are hex. They are decoded
    accordingly, and by byte length rather than by assumption.

    Returns ``None`` when the entry carries no proof to check (an unanchored
    bundle, or a log that returned none). "Not checked" is not "verified".
    """
    proof = (entry.get("verification") or {}).get("inclusionProof")
    if not proof:
        # Some entries carry the proof at the top level instead (the shape the
        # search endpoint returns).
        proof = entry.get("inclusionProof")
    if not proof:
        return None
    body = entry.get("body")
    if not body:
        # No leaf preimage means nothing to check, which is not a failed proof.
        return None
    try:
        leaf = leaf_hash(base64.b64decode(str(body)))
        audit_path = [_decode_hash(h) for h in proof.get("hashes", [])]
        index = int(proof.get("logIndex", -1))
        size = int(proof.get("treeSize", 0))
        stated_root = _decode_hash(str(proof["rootHash"]))
    except (KeyError, TypeError, ValueError):
        return None
    if any(h is None for h in audit_path):
        return None
    recomputed = root_from_inclusion_proof(leaf, index, size, audit_path)
    return recomputed == stated_root


def _decode_hash(value: str) -> bytes | None:
    """Decode one 32-byte hash from Rekor, which sends these as hex.

    Accepts base64 too, because the field's encoding is not part of any contract
    and a silent misdecode here reads as a failed proof rather than as a parsing
    error. Length is the tie-breaker: a SHA-256 digest is 32 bytes and the two
    encodings of it are not confusable at that length.
    """
    text = value.strip()
    try:
        raw = bytes.fromhex(text)
        if len(raw) == 32:
            return raw
    except ValueError:
        pass
    try:
        raw = base64.b64decode(text, validate=True)
        if len(raw) == 32:
            return raw
    except (binascii.Error, ValueError):
        pass
    return None


def get_rekor_url(
    *,
    fetcher: Any = None,
    timeout: float = DEFAULT_GET_TIMEOUT,
) -> str:
    """Fetch the current Rekor URL from the TUF SigningConfig.

    Args:
        fetcher: Optional override for the HTTP GET. Defaults to
            :func:`_http_get_json`. Tests pass a mock.
        timeout: HTTP timeout in seconds (ignored if fetcher is provided).

    Returns:
        The currently-active Rekor log URL.

    Raises:
        RekorError: If the SigningConfig can't be fetched or contains no URLs.
    """
    if fetcher is None:

        def _default_fetcher(url: str) -> dict[str, Any]:
            return _http_get_json(url, timeout=timeout)

        fetcher = _default_fetcher
    try:
        config = fetcher(SIGNING_CONFIG_URL)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        raise RekorError(f"Failed to fetch Rekor SigningConfig: {e}") from e
    except json.JSONDecodeError as e:
        raise RekorError(f"Rekor SigningConfig is not valid JSON: {e}") from e

    urls = config.get("rekorTlogUrls", [])
    if not urls:
        raise RekorError("Rekor SigningConfig contains no rekorTlogUrls")
    return cast(str, urls[0]["url"])


def build_hashedrekord_entry(
    payload: bytes,
    signature: bytes,
    public_key: bytes,
    hash_algorithm: str = "sha256",
) -> dict[str, Any]:
    """Build a Rekor v1 hashedrekord entry for a signed artifact.

    Hashedrekord stores only the payload hash, signature, and public key --
    the payload content is never revealed to Rekor. No x509 certificates,
    DSSE envelopes, or PAE computation required.

    Args:
        payload: The bytes that were signed (e.g. serialized bundle JSON).
        signature: The signature bytes.
        public_key: The raw public key bytes (e.g. Ed25519).
        hash_algorithm: Hash algorithm for the payload digest.
            One of ``"sha256"``, ``"sha384"``, ``"sha512"``.
    """
    h = hashlib.new(hash_algorithm, payload)
    return {
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": hash_algorithm,
                    "value": h.hexdigest(),
                },
            },
            "signature": {
                "content": base64.b64encode(signature).decode("ascii"),
                "publicKey": {
                    "content": base64.b64encode(public_key).decode("ascii"),
                },
            },
        },
    }


def submit_entry(
    entry: dict[str, Any],
    rekor_url: str,
    *,
    poster: Any = None,
    timeout: float = DEFAULT_POST_TIMEOUT,
) -> dict[str, Any]:
    """Submit a built Rekor entry to the specified Rekor log URL.

    The entry is submitted directly (not UUID-wrapped). Rekor v1 returns
    ``{"<uuid>": <log_entry>}``.

    Args:
        entry: A Rekor entry dict, typically from :func:`build_hashedrekord_entry`.
        rekor_url: The Rekor log URL (e.g. from :func:`get_rekor_url`).
        poster: Optional override for the HTTP POST. Defaults to
            :func:`_http_post_json`. Tests pass a mock.
        timeout: HTTP timeout in seconds (ignored if poster is provided).

    Returns:
        The created log entry dict including ``logIndex``, ``uuid``, etc.

    Raises:
        RekorError: If the entry exceeds the size limit or the submission fails.
    """
    body = json.dumps(entry).encode("utf-8")
    if len(body) > MAX_ATTESTATION_SIZE:
        raise RekorError(
            f"Entry size {len(body)} bytes exceeds Rekor public instance limit "
            f"({MAX_ATTESTATION_SIZE} bytes)"
        )

    if poster is None:

        def _default_poster(url: str, body: bytes) -> dict[str, Any]:
            return _http_post_json(url, body, timeout=timeout)

        poster = _default_poster

    url = rekor_url.rstrip("/") + "/api/v1/log/entries"
    try:
        result = cast(dict[str, Any], poster(url, body))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        raise RekorError(f"Rekor submission failed: {e}") from e
    except json.JSONDecodeError as e:
        raise RekorError(f"Rekor response is not valid JSON: {e}") from e

    uuid = next(iter(result))
    log_entry: dict[str, Any] = result[uuid]
    log_entry["uuid"] = uuid
    return log_entry


def retrieve_entries(
    query: dict[str, Any],
    rekor_url: str,
    *,
    fetcher: Any = None,
    timeout: float = DEFAULT_GET_TIMEOUT,
) -> list[dict[str, Any]]:
    """Search the log via its retrieve endpoint, returning the matching entries.

    The endpoint is POST-only and takes a JSON body; the GET form with a query
    string is rejected with a 422, so the request is built here rather than through
    the shared GET helper. It accepts either ``{"entryUUIDs": [...]}`` or
    ``{"logIndexes": [...]}``, which is why this is the shared implementation
    behind both lookups.

    Args:
        query: The retrieve body, e.g. ``{"entryUUIDs": [uuid]}``.
        rekor_url: The Rekor log URL.
        fetcher: Optional HTTP override for tests; receives ``(url, body)``.
        timeout: HTTP timeout in seconds (ignored if fetcher is provided).
    """
    payload = json.dumps(query).encode("utf-8")
    if fetcher is None:

        def _default_fetcher(url: str, body: bytes) -> Any:
            request = urllib.request.Request(
                url, data=body, headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                return json.loads(response.read().decode("utf-8"))

        fetcher = _default_fetcher
    url = rekor_url.rstrip("/") + "/api/v1/log/entries/retrieve"
    try:
        result = fetcher(url, payload)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        raise RekorError(f"Rekor retrieval failed: {e}") from e
    except json.JSONDecodeError as e:
        raise RekorError(f"Rekor response is not valid JSON: {e}") from e

    if not isinstance(result, list):
        return []
    entries: list[dict[str, Any]] = []
    for match in result:
        if not isinstance(match, dict) or len(match) != 1:
            continue
        entry_uuid, body = next(iter(match.items()))
        if not isinstance(body, dict):
            continue
        # The response keys each entry by its UUID rather than repeating it
        # inside, so put it back: a caller reading an entry wants to know which.
        body.setdefault("uuid", entry_uuid)
        entries.append(body)
    return entries


def get_entry(
    uuid: str,
    rekor_url: str,
    *,
    fetcher: Any = None,
    timeout: float = DEFAULT_GET_TIMEOUT,
) -> dict[str, Any]:
    """Retrieve a Rekor log entry by UUID, for inclusion proof verification.

    Args:
        uuid: The Rekor entry UUID returned by :func:`submit_entry`.
        rekor_url: The Rekor log URL.
        fetcher: Optional HTTP override for tests.
        timeout: HTTP timeout in seconds (ignored if fetcher is provided).
    """
    matches = retrieve_entries(
        {"entryUUIDs": [uuid]}, rekor_url, fetcher=fetcher, timeout=timeout
    )
    return matches[0] if matches else {}


def get_entry_by_index(
    log_index: int,
    rekor_url: str,
    *,
    fetcher: Any = None,
    timeout: float = DEFAULT_GET_TIMEOUT,
) -> dict[str, Any]:
    """Retrieve a Rekor log entry by its index in the log.

    The index is what a reader is most likely to have to hand, since it is the
    position a checkpoint's Merkle proof indexes into.
    """
    matches = retrieve_entries(
        {"logIndexes": [log_index]}, rekor_url, fetcher=fetcher, timeout=timeout
    )
    return matches[0] if matches else {}


def get_checkpoint(
    rekor_url: str,
    *,
    fetcher: Any = None,
    timeout: float = DEFAULT_GET_TIMEOUT,
) -> str:
    """Fetch the log's current signed checkpoint (a C2SP signed note).

    ``/api/v1/log`` returns the checkpoint under ``signedTreeHead``; a log that
    does not expose one returns an empty string rather than raising, because an
    anchor without a checkpoint is still a valid entry -- it is just not
    independently checkable, and the record says so by staying empty.
    """
    if fetcher is None:

        def _default_fetcher(url: str) -> dict[str, Any]:
            return _http_get_json(url, timeout=timeout)

        fetcher = _default_fetcher
    try:
        payload = fetcher(rekor_url.rstrip("/") + "/api/v1/log")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return ""
    except json.JSONDecodeError:
        return ""
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("signedTreeHead", "") or "")


def parse_entry_spec(entry: dict[str, Any]) -> dict[str, Any]:
    """The hashedrekord spec inside an entry body, or an empty dict.

    An entry's ``body`` is base64 JSON describing what was anchored, and it is
    where the committed digest, signature and public key live -- none of which
    appear at the top level of the entry. An unparseable body yields an empty dict
    so a caller reports "no digest recorded" rather than raising.
    """
    try:
        spec = json.loads(base64.b64decode(str(entry.get("body") or "")))
    except (TypeError, ValueError, binascii.Error):
        return {}
    return spec if isinstance(spec, dict) else {}


def anchored_digest(entry: dict[str, Any]) -> str | None:
    """The SHA-256 digest the entry committed to, or ``None`` if it records none.

    This is the value a verifier compares a candidate artifact against, so it is
    returned as a bare hex string with no algorithm label: a caller comparing two
    digests should not have to parse prose to do it.
    """
    spec = parse_entry_spec(entry)
    try:
        value = spec["spec"]["data"]["hash"]["value"]
    except (KeyError, TypeError):
        return None
    return str(value) if value else None
