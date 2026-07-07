from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport

from src.core.attacks import TEE_ATTACKS
from src.tools.archaeology import ArchaeologyDB, seed_attacks_from_list
from src.web.app import app

TDX_FIXTURE = Path("tests/fixtures/tdx/sample_quote.hex").read_text().strip()


@pytest.fixture(autouse=True)
def _seed_attacks_db(tmp_path: Path):
    db_path = tmp_path / "archaeology.db"
    import src.web.app as web_app

    web_app.ARCHAEOLOGY_DB_PATH = db_path
    db = ArchaeologyDB(db_path=db_path)
    seed_attacks_from_list(db, TEE_ATTACKS)
    db.close()


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestDashboard:
    async def test_get_index(self, client: httpx.AsyncClient):
        resp = await client.get("/")
        assert resp.status_code == 200

    async def test_index_has_title(self, client: httpx.AsyncClient):
        resp = await client.get("/")
        assert "Confidior" in resp.text
        assert "Dashboard" in resp.text


class TestSubmit:
    async def test_get_submit_form(self, client: httpx.AsyncClient):
        resp = await client.get("/submit")
        assert resp.status_code == 200
        assert "TEE Platform" in resp.text

    async def test_submit_with_tdx_quote(self, client: httpx.AsyncClient):
        resp = await client.post("/submit", data={
            "platform": "tdx",
            "quote_data": TDX_FIXTURE,
            "workload": "test-webui",
        })
        assert resp.status_code == 200
        assert "Evaluation Result" in resp.text
        assert "test-webui" in resp.text
        assert "Bundle JSON" in resp.text

    async def test_submit_empty_quote_returns_error(self, client: httpx.AsyncClient):
        resp = await client.post("/submit", data={
            "platform": "tdx",
            "quote_data": "",
        })
        assert resp.status_code == 200
        assert "No quote data provided" in resp.text

    async def test_submit_unknown_platform_returns_error(self, client: httpx.AsyncClient):
        resp = await client.post("/submit", data={
            "platform": "nonexistent",
            "quote_data": "deadbeef",
        })
        assert resp.status_code == 200
        assert "Unknown platform" in resp.text


class TestVerify:
    async def test_get_verify_form(self, client: httpx.AsyncClient):
        resp = await client.get("/verify")
        assert resp.status_code == 200
        assert "Upload" in resp.text

    async def test_verify_roundtrip(self, client: httpx.AsyncClient):
        sub_resp = await client.post("/submit", data={
            "platform": "tdx",
            "quote_data": TDX_FIXTURE,
            "workload": "verify-roundtrip",
        })
        assert sub_resp.status_code == 200
        bundle_path = _extract_bundle_path(sub_resp.text)
        bundle_resp = await client.get(bundle_path)
        assert bundle_resp.status_code == 200

        verify_resp = await client.post("/verify", files={
            "bundle_file": ("bundle.json", bundle_resp.content, "application/json"),
        })
        assert verify_resp.status_code == 200
        assert "Verification Result" in verify_resp.text

    async def test_verify_invalid_json_returns_error(self, client: httpx.AsyncClient):
        resp = await client.post("/verify", files={
            "bundle_file": ("bad.json", b"not json at all", "application/json"),
        })
        assert resp.status_code == 200
        assert "Invalid JSON" in resp.text

    async def test_verify_malformed_bundle_returns_error(self, client: httpx.AsyncClient):
        resp = await client.post("/verify", files={
            "bundle_file": ("bad.json", json.dumps({"foo": "bar"}).encode(), "application/json"),
        })
        assert resp.status_code == 200
        assert "Failed to parse bundle" in resp.text


class TestArchaeology:
    async def test_get_archaeology_page(self, client: httpx.AsyncClient):
        resp = await client.get("/archaeology")
        assert resp.status_code == 200
        assert "TEE Attack Database" in resp.text

    async def test_archaeology_shows_attacks(self, client: httpx.AsyncClient):
        resp = await client.get("/archaeology")
        assert "TEE.fail" in resp.text
        assert "BadRAM" in resp.text


class TestSignatureVerification:
    async def test_submit_bundle_has_valid_signature(self, client: httpx.AsyncClient):
        sub_resp = await client.post("/submit", data={
            "platform": "tdx",
            "quote_data": TDX_FIXTURE,
            "workload": "sig-test",
        })
        bundle_path = _extract_bundle_path(sub_resp.text)
        bundle_resp = await client.get(bundle_path)
        bundle = json.loads(bundle_resp.content)
        assert len(bundle["signatures"]) == 1
        assert bundle["signatures"][0]["algorithm"] == "Ed25519"

    async def test_verify_shows_valid_signature(self, client: httpx.AsyncClient):
        sub_resp = await client.post("/submit", data={
            "platform": "tdx",
            "quote_data": TDX_FIXTURE,
            "workload": "sig-verify",
        })
        bundle_path = _extract_bundle_path(sub_resp.text)
        bundle_resp = await client.get(bundle_path)
        verify_resp = await client.post("/verify", files={
            "bundle_file": ("bundle.json", bundle_resp.content, "application/json"),
        })
        assert "VALID" in verify_resp.text


class TestNotFound:
    async def test_unknown_route_returns_html_404(self, client: httpx.AsyncClient):
        resp = await client.get("/this-route-does-not-exist")
        assert resp.status_code == 404
        assert "text/html" in resp.headers["content-type"]
        assert "Not Found" in resp.text
        assert "/this-route-does-not-exist" in resp.text
        assert "Dashboard" in resp.text

    async def test_missing_static_file_returns_html_404(self, client: httpx.AsyncClient):
        resp = await client.get(
            "/static/nonexistent-badge.svg",
            headers={"Accept": "text/html"},
        )
        assert resp.status_code == 404
        assert "text/html" in resp.headers["content-type"]


def _extract_bundle_path(html: str) -> str:
    match = re.search(r'href="(/static/bundle-[^"]+\.json)"', html)
    if not match:
        raise AssertionError("Could not find bundle path in result page")
    return match.group(1)
