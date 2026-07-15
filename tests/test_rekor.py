from __future__ import annotations

import hashlib
import json
import urllib.error

import pytest

from src.export.rekor import (
    MAX_ATTESTATION_SIZE,
    RekorError,
    build_hashedrekord_entry,
    get_entry,
    get_rekor_url,
    hash_payload,
    submit_entry,
)

SAMPLE_SIGNING_CONFIG = {
    "rekorTlogUrls": [
        {
            "url": "https://rekor.sigstore.dev",
            "majorApiVersion": 1,
            "validFor": {"start": "2026-01-01T00:00:00Z"},
        }
    ]
}


def test_hash_payload_matches_stdlib():
    assert hash_payload(b"hello") == hashlib.sha256(b"hello").hexdigest()
    assert hash_payload(b"") == hashlib.sha256(b"").hexdigest()


def test_build_hashedrekord_entry_contains_hash_signature_and_key():
    payload = b'{"workload":"test"}'
    sig = b"x" * 64
    pubkey = b"y" * 32
    entry = build_hashedrekord_entry(payload, sig, pubkey)

    assert entry["kind"] == "hashedrekord"
    assert entry["apiVersion"] == "0.0.1"

    spec = entry["spec"]
    assert spec["data"]["hash"]["algorithm"] == "sha256"
    assert spec["data"]["hash"]["value"] == hashlib.sha256(payload).hexdigest()

    import base64
    assert base64.b64decode(spec["signature"]["content"]) == sig
    assert base64.b64decode(spec["signature"]["publicKey"]["content"]) == pubkey


def test_build_hashedrekord_entry_custom_hash():
    payload = b"test"
    entry = build_hashedrekord_entry(payload, b"sig", b"key", hash_algorithm="sha512")
    assert entry["spec"]["data"]["hash"]["algorithm"] == "sha512"
    assert entry["spec"]["data"]["hash"]["value"] == hashlib.sha512(payload).hexdigest()


def test_submit_entry_posts_to_rekor_endpoint():
    captured: dict = {}

    def poster(url: str, body: bytes) -> dict:
        captured["url"] = url
        captured["body"] = body
        return {
            "abc-123": {
                "logIndex": 42,
                "logID": "log-id",
                "integratedTime": 1234567890,
                "body": {},
                "verification": {"signedEntryTimestamp": "fake"},
            }
        }

    entry = build_hashedrekord_entry(b"test-payload", b"t" * 64, b"k" * 32)
    result = submit_entry(entry, "https://example.com/rekor", poster=poster)

    assert captured["url"] == "https://example.com/rekor/api/v1/log/entries"
    posted = json.loads(captured["body"])
    assert posted["kind"] == "hashedrekord"
    assert result["uuid"] == "abc-123"
    assert result["logIndex"] == 42


def test_submit_entry_strips_trailing_slash():
    captured: dict = {}

    def poster(url: str, body: bytes) -> dict:
        captured["url"] = url
        return {"u": {"logIndex": 0, "integratedTime": 0, "body": {}, "verification": {}}}

    submit_entry(
        build_hashedrekord_entry(b"x", b"y" * 64, b"z" * 32),
        "https://example.com/rekor/",
        poster=poster,
    )
    assert captured["url"] == "https://example.com/rekor/api/v1/log/entries"


def test_submit_entry_calls_poster_with_entry_body():
    """Hashedrekord entries are always small (hash only), so the
    size-limit check is a safety net that never triggers in practice."""
    entry = build_hashedrekord_entry(b"small", b"s" * 64, b"k" * 32)
    posted = json.dumps(entry).encode("utf-8")
    assert len(posted) < MAX_ATTESTATION_SIZE  # sanity: entry is tiny

    captured: dict = {}

    def poster(url: str, body: bytes) -> dict:
        captured["body"] = body
        return {"u": {"logIndex": 1, "integratedTime": 0, "body": {}, "verification": {}}}

    submit_entry(entry, "https://example.com/rekor", poster=poster)
    assert captured["body"] == posted


def test_submit_entry_propagates_url_error():
    def poster(url: str, body: bytes) -> dict:
        raise urllib.error.HTTPError(url, 500, "Server Error", {}, None)

    with pytest.raises(RekorError, match="submission failed"):
        submit_entry(
            build_hashedrekord_entry(b"x", b"y" * 64, b"z" * 32),
            "https://example.com/rekor",
            poster=poster,
        )


def test_get_rekor_url_fetches_signing_config():
    def fetcher(url: str) -> dict:
        assert "signing_config" in url
        return SAMPLE_SIGNING_CONFIG

    assert get_rekor_url(fetcher=fetcher) == "https://rekor.sigstore.dev"


def test_get_rekor_url_picks_first_when_multiple():
    config = {
        "rekorTlogUrls": [
            {"url": "https://rekor-new.example.com", "validFor": {"start": "2026-06-01Z"}},
            {"url": "https://rekor-old.example.com", "validFor": {"start": "2025-01-01Z"}},
        ]
    }
    assert get_rekor_url(fetcher=lambda u: config) == "https://rekor-new.example.com"


def test_get_rekor_url_raises_on_empty_config():
    with pytest.raises(RekorError, match="no rekorTlogUrls"):
        get_rekor_url(fetcher=lambda u: {"rekorTlogUrls": []})


def test_get_rekor_url_raises_on_url_error():
    def fetcher(url: str) -> dict:
        raise urllib.error.URLError("network down")

    with pytest.raises(RekorError, match="Failed to fetch"):
        get_rekor_url(fetcher=fetcher)


def test_get_rekor_url_raises_on_invalid_json():
    def fetcher(url: str) -> dict:
        raise json.JSONDecodeError("not json", "", 0)

    with pytest.raises(RekorError, match="not valid JSON"):
        get_rekor_url(fetcher=fetcher)


def test_get_entry_retrieves_by_uuid():
    captured: dict = {}

    def fetcher(url: str) -> dict:
        captured["url"] = url
        return {"uuid": "the-uuid", "body": {"kind": "hashedrekord"}, "verification": {}}

    result = get_entry("the-uuid", "https://example.com/rekor", fetcher=fetcher)

    assert "entryUUID=the-uuid" in captured["url"]
    assert "retrieve" in captured["url"]
    assert result["uuid"] == "the-uuid"


def test_get_entry_propagates_url_error():
    def fetcher(url: str) -> dict:
        raise urllib.error.URLError("not found")

    with pytest.raises(RekorError, match="retrieval failed"):
        get_entry("x", "https://example.com/rekor", fetcher=fetcher)
