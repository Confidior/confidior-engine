"""Tests for CVE → TCB/firmware version mapping."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.attacks import TEE_ATTACKS
from src.core.taxonomy import Platform
from src.tools.archaeology import ArchaeologyDB, TCBRecord, seed_attacks_from_list
from src.tools.cve_tcb_mapper import (
    apply_cve_tcb_mappings,
    map_cve_to_tcb_versions,
)


@pytest.fixture
def mapped_db(tmp_path: Path) -> ArchaeologyDB:
    db_path = tmp_path / "archaeology.db"
    db = ArchaeologyDB(db_path=db_path)
    seed_attacks_from_list(db, TEE_ATTACKS)
    # Clear the hardcoded sample threshold so the mapping has room to apply.
    conn = db._get_conn()
    conn.execute("UPDATE attack_records SET min_svn = NULL WHERE name = 'BadRAM'")
    conn.commit()
    # BadRAM has CVE-2024-21944 on AMD SEV-SNP.
    db.insert(
        TCBRecord(
            platform="AMD-SEV-SNP",
            version="0.0.1.25",
            status="current",
            cve_id="CVE-2024-21944",
            advisory_url="https://example.com/badram-fix",
        )
    )
    return db


def test_map_cve_to_tcb_versions_finds_badram_fix(mapped_db: ArchaeologyDB):
    mappings = map_cve_to_tcb_versions(mapped_db)
    assert any(
        m.cve_id == "CVE-2024-21944"
        and m.attack_name == "BadRAM"
        and m.platform == Platform.AMDSEVSNP
        and m.fixed_version == "0.0.1.25"
        for m in mappings
    )


def test_apply_cve_tcb_mappings_updates_min_svn(mapped_db: ArchaeologyDB):
    applied, skipped = apply_cve_tcb_mappings(mapped_db, dry_run=False)
    assert any(m.attack_name == "BadRAM" for m in applied)

    record = [r for r in mapped_db.query_attacks() if r.name == "BadRAM"][0]
    assert record.min_svn == {Platform.AMDSEVSNP.name: "0.0.1.25"}


def test_apply_cve_tcb_mappings_dry_run_does_not_write(mapped_db: ArchaeologyDB):
    applied, _ = apply_cve_tcb_mappings(mapped_db, dry_run=True)
    assert any(m.attack_name == "BadRAM" for m in applied)

    record = [r for r in mapped_db.query_attacks() if r.name == "BadRAM"][0]
    assert record.min_svn is None


def test_apply_cve_tcb_mappings_skips_existing_min_svn(mapped_db: ArchaeologyDB):
    # Pre-seed a human-curated min_svn for BadRAM.
    conn = mapped_db._get_conn()
    conn.execute(
        "UPDATE attack_records SET min_svn = ? WHERE name = ?",
        (json.dumps({Platform.AMDSEVSNP.name: "0.0.1.20"}, sort_keys=True), "BadRAM"),
    )
    conn.commit()

    applied, skipped = apply_cve_tcb_mappings(mapped_db, dry_run=False)
    assert not any(m.attack_name == "BadRAM" for m in applied)
    assert any(m.attack_name == "BadRAM" for m in skipped)

    record = [r for r in mapped_db.query_attacks() if r.name == "BadRAM"][0]
    assert record.min_svn == {Platform.AMDSEVSNP.name: "0.0.1.20"}


def test_map_cve_to_tcb_versions_ignores_non_matching_platform(mapped_db: ArchaeologyDB):
    # Insert a TCB record for a platform the attack does not claim.
    mapped_db.insert(
        TCBRecord(
            platform="Intel-TDX",
            version="03050000",
            status="current",
            cve_id="CVE-2024-21944",
        )
    )
    mappings = map_cve_to_tcb_versions(mapped_db)
    assert not any(m.platform == Platform.IntelTDX for m in mappings)


def test_map_cve_to_tcb_versions_ignores_non_current_status(mapped_db: ArchaeologyDB):
    mapped_db.insert(
        TCBRecord(
            platform="AMD-SEV-SNP",
            version="0.0.1.5",
            status="expired",
            cve_id="CVE-2024-21944",
        )
    )
    mappings = map_cve_to_tcb_versions(mapped_db)
    assert all(m.fixed_version != "0.0.1.5" for m in mappings)
