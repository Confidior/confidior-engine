"""Tests for live CVE sync and bundle re-score trigger."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.cli.main import main
from src.core.attacks import TEE_ATTACKS
from src.core.taxonomy import (
    AssuranceEvaluation,
    AssuranceLevel,
    EvidenceBundle,
    ResidualRiskTier,
    ScoreResult,
)
from src.tools.archaeology import ArchaeologyDB, TCBRecord, seed_attacks_from_list
from src.tools.cve_sync import find_affected_bundles, sync_cves


@pytest.fixture(autouse=True)
def _reset_global_db_path():
    """sync_cves sets the global archaeology DB path; restore it so later
    tests (test_scoring) don't read this file's temp DB with its NULL min_svn."""
    yield
    from src.core.risk import set_archaeology_db_path

    set_archaeology_db_path("")  # clear; empty string is falsy for exists() checks


def _make_db(tmp_path: Path) -> ArchaeologyDB:
    db_path = tmp_path / "archaeology.db"
    db = ArchaeologyDB(db_path=db_path)
    seed_attacks_from_list(db, TEE_ATTACKS)
    conn = db._get_conn()
    conn.execute("UPDATE attack_records SET min_svn = NULL WHERE name = 'BadRAM'")
    conn.commit()
    db.insert(
        TCBRecord(
            platform="AMD-SEV-SNP",
            version="0.0.1.25",
            status="current",
            cve_id="CVE-2024-21944",
        )
    )
    return db


def test_sync_cves_inserts_new_cve_and_maps_tcb(tmp_path: Path):
    db = _make_db(tmp_path)
    db.close()

    fake_cve = {
        "cve_id": "CVE-2025-99999",
        "description": "Synthetic high-severity TEE vulnerability",
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z",
    }

    with patch("src.tools.cve_sync.fetch_tee_cves") as mock_fetch:
        mock_fetch.return_value = [(fake_cve, "amd", "secrets")]
        summary = sync_cves(db_path=tmp_path / "archaeology.db", dry_run=False)

    assert summary["fetched"] == 1
    assert summary["inserted"] == 1
    assert any(m.attack_name == "BadRAM" for m in summary["tcb_mappings_applied"])


def test_sync_cves_dry_run_does_not_insert(tmp_path: Path):
    db = _make_db(tmp_path)
    db.close()

    fake_cve = {
        "cve_id": "CVE-2025-99998",
        "description": "Another synthetic CVE",
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z",
    }

    with patch("src.tools.cve_sync.fetch_tee_cves") as mock_fetch:
        mock_fetch.return_value = [(fake_cve, "intel", "tdx_module_software")]
        summary = sync_cves(db_path=tmp_path / "archaeology.db", dry_run=True)

    assert summary["fetched"] == 1
    assert summary["inserted"] == 0


def test_find_affected_bundles_flags_snapshot_change(tmp_path: Path):
    db = _make_db(tmp_path)
    db.close()

    bundle_path = tmp_path / "evidence_bundle.json"
    bundle = EvidenceBundle(
        bundle_id="bundle-1",
        timestamp=__import__("datetime").datetime.now(),
        expires_at=__import__("datetime").datetime.now()
        + __import__("datetime").timedelta(days=30),
        workload="test",
        evidence_graph_summary={
            "platforms": ["AMD-SEV-SNP"],
            "tcb_versions": [{"platform": "AMD-SEV-SNP", "tcb_version": "0.0.1.10"}],
        },
        assurance=AssuranceEvaluation(
            level=AssuranceLevel.HARDWARE_ATTESTED,
            residual_risk=ResidualRiskTier.HIGH,
            boundary_statement="test",
            score=ScoreResult(total=50, subscores={}, grade="C"),
        ),
        attack_db_snapshot="old-snapshot-hash",
    )
    bundle_path.write_text(json.dumps(bundle.to_dict(), indent=2, default=str))

    affected = find_affected_bundles(tmp_path / "archaeology.db", tmp_path)
    assert len(affected) == 1
    assert affected[0]["bundle_id"] == "bundle-1"
    assert affected[0]["snapshot_changed"] is True
    assert affected[0]["attack_count"] >= 1


def test_cli_attacks_map_cve_tcb(tmp_path: Path):
    db = _make_db(tmp_path)
    db.close()
    rc = main(["attacks", "map-cve-tcb", "--db-path", str(tmp_path / "archaeology.db")])
    assert rc == 0


def test_cli_attacks_sync_dry_run(tmp_path: Path):
    db = _make_db(tmp_path)
    db.close()

    fake_cve = {
        "cve_id": "CVE-2025-99997",
        "description": "CLI dry-run CVE",
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z",
    }

    with patch("src.tools.cve_sync.fetch_tee_cves") as mock_fetch:
        mock_fetch.return_value = [(fake_cve, "amd", "secrets")]
        rc = main(
            [
                "attacks",
                "sync",
                "--db-path",
                str(tmp_path / "archaeology.db"),
                "--dry-run",
            ]
        )
    assert rc == 0


def test_nvd_to_attack_record_maps_platform(monkeypatch):
    """NVD-fetched CVE converts to an AttackRecord with the platform tag."""
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "fetch_tee_cves", Path("scripts/fetch_tee_cves.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rec = mod.nvd_to_attack_record({
        "cve_id": "CVE-2024-99999",
        "summary": "Test TEE vulnerability",
        "published": "2024-05-01T00:00:00",
        "cvss": 9.8,
        "platform_tag": "AMDSEVSNP",
    })
    assert rec.cve_id == "CVE-2024-99999"
    assert rec.year == 2024
    assert any(p.name == "AMDSEVSNP" for p in rec.affected_platforms)
    assert "fix version not machine-readable" in rec.boundary_statement


def test_nvd_fetch_filters_below_high(monkeypatch):
    """NVD fetch skips CVEs with baseScore below 7.0."""
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "fetch_tee_cves", Path("scripts/fetch_tee_cves.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Fake the HTTP layer: return one high + one low CVE
    class FakeResp:
        status_code = 200
        def json(self):
            return {
                "vulnerabilities": [
                    {"cve": {
                        "id": "CVE-2024-0001",
                        "descriptions": [{"lang": "en", "value": "high"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                        "published": "2024-01-01T00:00:00",
                    }},
                    {"cve": {
                        "id": "CVE-2024-0002",
                        "descriptions": [{"lang": "en", "value": "low"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.1}}]},
                        "published": "2024-01-02T00:00:00",
                    }},
                ]
            }

    monkeypatch.setattr(mod, "_request_with_retry", lambda *a, **k: FakeResp())
    cves = mod.fetch_cves_nvd()
    ids = [c["cve_id"] for c in cves]
    assert "CVE-2024-0001" in ids
    assert "CVE-2024-0002" not in ids


def _load_fetch_module():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "fetch_tee_cves", Path("scripts/fetch_tee_cves.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cve_to_tcb_record_extracts_fix(tmp_path):
    """A CVE description carrying a fix version seeds a tcb_record."""
    mod = _load_fetch_module()
    rec = mod.cve_to_tcb_record({
        "cve_id": "CVE-2023-45745",
        "summary": "Improper input validation in Intel TDX module software before version 1.5.05.46.698",  # noqa: E501
        "published": "2023-10-01T00:00:00",
    }, "IntelTDX")
    assert rec is not None
    assert rec.version == "1.5.05.46.698"
    assert rec.platform == "Intel-TDX"
    assert rec.cve_id == "CVE-2023-45745"
    assert rec.status == "current"


def test_cve_to_tcb_record_none_without_fix():
    """No fix version in the description -> no tcb_record."""
    mod = _load_fetch_module()
    rec = mod.cve_to_tcb_record({
        "cve_id": "CVE-2024-0001",
        "summary": "No fix version stated in this prose.",
        "published": "2024-01-01T00:00:00",
    }, "AMDSEVSNP")
    assert rec is None


def test_seed_tcb_records_wires_into_db(tmp_path):
    """_seed_tcb_records inserts extracted fix versions into the archaeology DB."""
    mod = _load_fetch_module()
    from src.tools.archaeology import ArchaeologyDB

    db = ArchaeologyDB(db_path=tmp_path / "arch.db")
    try:
        cves = [{
            "cve_id": "CVE-2023-45745",
            "summary": "Intel TDX module software before version 1.5.05.46.698",
            "published": "2023-10-01T00:00:00",
            "platform_tag": "IntelTDX",
        }]
        count = mod._seed_tcb_records(db, cves)
        assert count == 1
        rows = db._get_conn().execute("SELECT cve_id, version, platform FROM tcb_records").fetchall()  # noqa: E501
        assert len(rows) == 1
        assert rows[0]["cve_id"] == "CVE-2023-45745"
    finally:
        db.close()
