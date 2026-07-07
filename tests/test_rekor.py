from __future__ import annotations

import base64
import hashlib
import json
import urllib.error

import pytest

from src.export.rekor import (
    MAX_ATTESTATION_SIZE,
    RekorError,
    build_dsse_entry,
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


class _FakeResponse:
    """Minimal urllib response stand-in for test injection."""

    def __init__(self, payload: dict, status: int = 200):
        self._payload = payload
        self.status = status

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_hash_payload_matches_stdlib():
    assert hash_payload(b"hello") == hashlib.sha256(b"hello").hexdigest()
    assert hash_payload(b"") == hashlib.sha256(b"").hexdigest()


def test_build_dsse_entry_encodes_payload_and_signature():
    payload = b'{"workload":"test"}'
    sig = b"x" * 64
    entry = build_dsse_entry(payload, sig)

    assert entry["kind"] == "dsse"
    assert entry["apiVersion"] == "0.0.1"

    spec = entry["spec"]
    assert spec["payloadHash"]["algorithm"] == "sha256"
    assert spec["payloadHash"]["value"] == hashlib.sha256(payload).hexdigest()
    assert base64.b64decode(spec["payload"]) == payload

    sigs = spec["signatures"]
    assert len(sigs) == 1
    assert sigs[0]["keyid"] == ""
    assert base64.b64decode(sigs[0]["sig"]) == sig


def test_build_dsse_entry_accepts_precomputed_hash():
    payload = b"abc"
    precomputed = hashlib.sha256(payload).hexdigest()
    entry = build_dsse_entry(payload, b"sig", payload_hash=precomputed)
    assert entry["spec"]["payloadHash"]["value"] == precomputed


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


def test_submit_entry_posts_to_rekor_endpoint():
    captured: dict = {}

    def poster(url: str, body: bytes) -> dict:
        captured["url"] = url
        captured["body"] = body
        return {
            "uuid": "abc-123",
            "logIndex": 42,
            "integratedTime": 1234567890,
            "body": json.loads(body.decode()),
            "verification": {"signedEntryTimestamp": "fake"},
        }

    entry = build_dsse_entry(b"payload", b"sig")
    result = submit_entry(entry, "https://example.com/rekor", poster=poster)

    assert captured["url"] == "https://example.com/rekor/api/v1/log/entries"
    wrapped = json.loads(captured["body"])
    assert len(wrapped) == 1
    uuid = list(wrapped.keys())[0]
    assert wrapped[uuid]["kind"] == "dsse"
    assert result["uuid"] == "abc-123"
    assert result["logIndex"] == 42


def test_submit_entry_uuid_is_deterministic():
    entry = build_dsse_entry(b"hello", b"sig")
    from src.export.rekor import _rekor_entry_uuid
    assert _rekor_entry_uuid(entry) == _rekor_entry_uuid(entry)
    assert len(_rekor_entry_uuid(entry)) == 64


def test_submit_entry_uuid_changes_with_payload():
    entry1 = build_dsse_entry(b"hello", b"sig")
    entry2 = build_dsse_entry(b"world", b"sig")
    from src.export.rekor import _rekor_entry_uuid
    assert _rekor_entry_uuid(entry1) != _rekor_entry_uuid(entry2)


def test_submit_entry_strips_trailing_slash_from_url():
    captured: dict = {}

    def poster(url: str, body: bytes) -> dict:
        captured["url"] = url
        return {"uuid": "x", "logIndex": 0, "integratedTime": 0, "body": {}, "verification": {}}

    submit_entry(
        build_dsse_entry(b"x", b"y"),
        "https://example.com/rekor/",
        poster=poster,
    )
    assert captured["url"] == "https://example.com/rekor/api/v1/log/entries"


def test_submit_entry_rejects_oversized_entry():
    big = b"x" * (MAX_ATTESTATION_SIZE + 1)
    entry = build_dsse_entry(big, b"sig")
    with pytest.raises(RekorError, match="exceeds Rekor"):
        submit_entry(entry, "https://example.com/rekor", poster=lambda u, b: {})


def test_submit_entry_propagates_url_error():
    def poster(url: str, body: bytes) -> dict:
        raise urllib.error.HTTPError(url, 500, "Server Error", {}, None)

    with pytest.raises(RekorError, match="submission failed"):
        submit_entry(
            build_dsse_entry(b"x", b"y"),
            "https://example.com/rekor",
            poster=poster,
        )


def test_get_entry_retrieves_by_uuid():
    captured: dict = {}

    def fetcher(url: str) -> dict:
        captured["url"] = url
        return {"uuid": "the-uuid", "body": {"kind": "dsse"}, "verification": {}}

    result = get_entry("the-uuid", "https://example.com/rekor", fetcher=fetcher)

    assert "entryUUID=the-uuid" in captured["url"]
    assert "retrieve" in captured["url"]
    assert result["uuid"] == "the-uuid"


def test_get_entry_propagates_url_error():
    def fetcher(url: str) -> dict:
        raise urllib.error.URLError("not found")

    with pytest.raises(RekorError, match="retrieval failed"):
        get_entry("x", "https://example.com/rekor", fetcher=fetcher)
