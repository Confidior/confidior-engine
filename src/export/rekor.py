"""Sigstore Rekor transparency log client for evidence anchoring."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import urllib.error
import urllib.request
from typing import Any, cast

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
        fetcher = lambda url: _http_get_json(url, timeout=timeout)
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
        poster = lambda url, b: _http_post_json(url, b, timeout=timeout)

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


def get_entry(
    uuid: str,
    rekor_url: str,
    *,
    fetcher: Any = None,
    timeout: float = DEFAULT_GET_TIMEOUT,
) -> dict[str, Any]:
    """Retrieve a Rekor log entry by UUID (e.g. for inclusion proof verification).

    Args:
        uuid: The Rekor entry UUID returned by :func:`submit_entry`.
        rekor_url: The Rekor log URL.
        fetcher: Optional HTTP GET override for tests.
        timeout: HTTP timeout in seconds (ignored if fetcher is provided).
    """
    if fetcher is None:
        fetcher = lambda url: _http_get_json(url, timeout=timeout)
    url = rekor_url.rstrip("/") + f"/api/v1/log/entries/retrieve?entryUUID={uuid}"
    try:
        return cast(dict[str, Any], fetcher(url))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        raise RekorError(f"Rekor retrieval failed: {e}") from e
    except json.JSONDecodeError as e:
        raise RekorError(f"Rekor response is not valid JSON: {e}") from e
