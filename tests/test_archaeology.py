import tempfile
from pathlib import Path

from src.core.attacks import (
    TEE_ATTACKS,
    get_unmitigated_attacks,
    set_attacks_db_path,
)
from src.core.taxonomy import Platform
from src.tools.archaeology import ArchaeologyDB, TCBRecord, seed_attacks_from_list


def test_insert_and_query():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = ArchaeologyDB(Path(tmpdir) / "tcb.db")
        db.insert(TCBRecord(
            platform="Intel-TDX",
            version="1.5.0",
            release_date="2025-01-15",
            status="current",
            cve_id=None,
            advisory_url="https://example.com/advisory-1",
        ))
        db.insert(TCBRecord(
            platform="Intel-TDX",
            version="1.4.0",
            release_date="2024-06-01",
            status="expired",
            cve_id="CVE-2025-1234",
            advisory_url="https://example.com/advisory-2",
        ))

        all_records = db.query()
        assert len(all_records) == 2

        current = db.query(platform="Intel-TDX", status="current")
        assert len(current) == 1
        assert current[0].version == "1.5.0"

        by_cve = db.query(cve_id="CVE-2025-1234")
        assert len(by_cve) == 1
        assert by_cve[0].status == "expired"

        db.close()


def test_is_firmware_current():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = ArchaeologyDB(Path(tmpdir) / "tcb.db")
        db.insert(TCBRecord(
            platform="AMD-SEV-SNP",
            version="2.0.0",
            status="current",
        ))

        assert db.is_firmware_current("AMD-SEV-SNP", "2.0.0") is True
        assert db.is_firmware_current("AMD-SEV-SNP", "1.0.0") is False
        assert db.is_firmware_current("Unknown-Platform", "1.0.0") is False

        db.close()


def test_db_creates_schema_on_init():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "tcb.db"
        db = ArchaeologyDB(db_path)
        db.insert(TCBRecord(platform="test", version="1.0"))
        assert db_path.exists()

        conn = db._get_conn()
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [t["name"] for t in tables]
        assert "tcb_records" in table_names

        db.close()


def test_mark_patched_updates_record():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = ArchaeologyDB(Path(tmpdir) / "tcb.db")
        seed_attacks_from_list(db, TEE_ATTACKS)

        # Baseline: BadRAM is unpatched in the seed
        badram = [r for r in db.query_attacks() if r.name == "BadRAM"][0]
        assert badram.patched is False

        # Mark as patched
        updated = db.mark_patched("BadRAM", patched=True)
        assert updated is True

        badram = [r for r in db.query_attacks() if r.name == "BadRAM"][0]
        assert badram.patched is True
        assert badram.last_checked is not None

        # unpatched_only filter now excludes BadRAM
        unpatched_sev = db.query_attacks(platform=Platform.AMDSEVSNP, unpatched_only=True)
        unpatched_names = [r.name for r in unpatched_sev]
        assert "BadRAM" not in unpatched_names
        assert "TEE.fail" in unpatched_names  # still unpatched

        # Mark unknown name returns False, doesn't raise
        assert db.mark_patched("NoSuchAttack") is False

        # Toggle back
        assert db.mark_patched("BadRAM", patched=False) is True
        badram = [r for r in db.query_attacks() if r.name == "BadRAM"][0]
        assert badram.patched is False

        db.close()


def test_get_unmitigated_attacks_honors_patched_field(tmp_path: Path):
    """End-to-end: marking BadRAM patched in DB excludes it from unmitigated list."""
    db_path = tmp_path / "test.db"
    db = ArchaeologyDB(db_path=db_path)
    seed_attacks_from_list(db, TEE_ATTACKS)
    db.mark_patched("BadRAM", patched=True)
    db.mark_patched("Plundervolt", patched=True)
    db.close()

    set_attacks_db_path(db_path)
    try:
        sev = get_unmitigated_attacks(Platform.AMDSEVSNP)
        sev_names = [a.name for a in sev]
        assert "BadRAM" not in sev_names, "Patched BadRAM should be excluded from unmitigated list"
        assert "TEE.fail" in sev_names, "Unpatched TEE.fail should remain"

        # TDX list excludes Plundervolt (which is now frozenset() / SGX-only)
        tdx = get_unmitigated_attacks(Platform.IntelTDX)
        assert not any(a.name == "Plundervolt" for a in tdx)
    finally:
        set_attacks_db_path(None)


def test_get_unmitigated_attacks_db_unavailable_uses_hardcoded():
    """Without a DB, all hardcoded attacks are unpatched (patched=False default)."""
    set_attacks_db_path(None)
    sev = get_unmitigated_attacks(Platform.AMDSEVSNP)
    sev_names = [a.name for a in sev]
    assert "BadRAM" in sev_names  # present because hardcoded list has patched=False
