"""Tests for live CVE sync and bundle re-score trigger."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

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
