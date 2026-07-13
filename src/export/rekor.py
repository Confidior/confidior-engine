"""Sigstore Rekor transparency log client for evidence anchoring.

Submits signed bundles to the public Rekor instance for existence proof. The
returned log index and UUID can be stored alongside the bundle so verifiers
can confirm the bundle was anchored to a public transparency log.

The public Rekor URL is discovered via the TUF-distributed SigningConfig
(`signing_config.v0.2.json`), NOT hardcoded. Rekor shards ~every 6 months;
a hardcoded URL breaks when the shard rotates. Use :func:`get_rekor_url` on
every submission.

Public instance limits (verified 2026-06-21):
- 100KB max entry body size (`MAX_ATTESTATION_SIZE`)
- 99.5% availability SLO
- Endpoints: /api/v1/log, /api/v1/log/entries, /api/v1/log/entries/retrieve
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import urllib.error
import urllib.request
from typing import Any, cast

logger = logging.getLogger(__name__)

# TUF-distributed SigningConfig. Rekor shards ~every 6 months, so the URL
# inside this file rotates; clients should always fetch fresh.
SIGNING_CONFIG_URL = (
    "https://raw.githubusercontent.com/sigstore/root-signing/main/"
    "targets/signing_config.v0.2.json"
)

# Public Rekor instance limit (bytes). Enforced server-side; we pre-check
# to give a friendlier error than the upstream 413.
MAX_ATTESTATION_SIZE = 100_000

DEFAULT_GET_TIMEOUT = 5.0
DEFAULT_POST_TIMEOUT = 10.0


class RekorError(Exception):
    """Raised on any Rekor interaction failure (network, parsing, size)."""


def _http_get_json(url: str, timeout: float = DEFAULT_GET_TIMEOUT) -> dict[str, Any]:
    """GET a URL and return parsed JSON. Module-level for easy test patching."""
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - public URL
        return cast(dict[str, Any], json.loads(resp.read().decode("utf-8")))


def _http_post_json(url: str, body: bytes, timeout: float = DEFAULT_POST_TIMEOUT) -> dict[str, Any]:
    """POST JSON body to URL and return parsed JSON response."""
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - public URL
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
        fetcher = lambda url: _http_get_json(url, timeout=timeout)  # noqa: E731
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


def build_dsse_entry(
    payload: bytes,
    signature: bytes,
    payload_hash: str | None = None,
) -> dict[str, Any]:
    """Build a Rekor DSSE entry for a signed artifact.

    The DSSE entry type wraps an existing signed payload (e.g. a DSSE envelope
    from ``src.export.dsse``) without re-signing it. Rekor stores the payload
    hash and signature, producing a publicly-verifiable log entry.

    Args:
        payload: The bytes that were signed (canonical JSON of the bundle).
        signature: The signature bytes (e.g. Ed25519 over the payload).
        payload_hash: Optional pre-computed SHA-256 hex. Computed if not given.
    """
    if payload_hash is None:
        payload_hash = hash_payload(payload)
    return {
        "kind": "dsse",
        "apiVersion": "0.0.1",
        "spec": {
            "payloadHash": {"algorithm": "sha256", "value": payload_hash},
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [
                {
                    "keyid": "",
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        },
    }


def _rekor_entry_uuid(entry: dict[str, Any]) -> str:
    """Compute the Rekor v1 entry UUID for a DSSE entry.

    Rekor v1 API requires entries submitted as ``{"<uuid>": <entry>}`` where
    the UUID is the SHA-256 hash of the base64-decoded ``spec.payload``.
    """
    payload = base64.b64decode(entry["spec"]["payload"])
    return hashlib.sha256(payload).hexdigest()


def submit_entry(
    entry: dict[str, Any],
    rekor_url: str,
    *,
    poster: Any = None,
    timeout: float = DEFAULT_POST_TIMEOUT,
) -> dict[str, Any]:
    """Submit a built Rekor entry to the specified Rekor log URL.

    Args:
        entry: A Rekor entry dict, typically from :func:`build_dsse_entry`.
        rekor_url: The Rekor log URL (e.g. from :func:`get_rekor_url`).
        poster: Optional override for the HTTP POST. Defaults to
            :func:`_http_post_json`. Tests pass a mock.
        timeout: HTTP timeout in seconds (ignored if poster is provided).

    Returns:
        The created log entry (includes uuid, logIndex, integratedTime, body).

    Raises:
        RekorError: If the entry exceeds the size limit or the submission fails.
    """
    uuid = _rekor_entry_uuid(entry)
    wrapped = {uuid: entry}
    body = json.dumps(wrapped).encode("utf-8")
    if len(body) > MAX_ATTESTATION_SIZE:
        raise RekorError(
            f"Entry size {len(body)} bytes exceeds Rekor public instance limit "
            f"({MAX_ATTESTATION_SIZE} bytes)"
        )

    if poster is None:
        poster = lambda url, b: _http_post_json(url, b, timeout=timeout)  # noqa: E731

    url = rekor_url.rstrip("/") + "/api/v1/log/entries"
    try:
        return cast(dict[str, Any], poster(url, body))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        raise RekorError(f"Rekor submission failed: {e}") from e
    except json.JSONDecodeError as e:
        raise RekorError(f"Rekor response is not valid JSON: {e}") from e


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
        fetcher = lambda url: _http_get_json(url, timeout=timeout)  # noqa: E731
    url = rekor_url.rstrip("/") + f"/api/v1/log/entries/retrieve?entryUUID={uuid}"
    try:
        return cast(dict[str, Any], fetcher(url))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        raise RekorError(f"Rekor retrieval failed: {e}") from e
    except json.JSONDecodeError as e:
        raise RekorError(f"Rekor response is not valid JSON: {e}") from e
