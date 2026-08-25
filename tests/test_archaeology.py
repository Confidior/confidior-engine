import tempfile
from pathlib import Path

from src.core.attacks import (
    TEE_ATTACKS,
    _parse_svn,
    get_unmitigated_attacks,
)
from src.core.risk import _check_firmware_patched, set_archaeology_db_path
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


def test_get_unmitigated_attacks_uses_curated_source(tmp_path: Path):
    """get_unmitigated_attacks always uses the curated taxonomy.

    The archaeology DB path previously swapped in NVD-synced records; the
    curated JSON is now the only source. A DB path must not change the
    result.
    """
    sev = get_unmitigated_attacks(Platform.AMDSEVSNP)
    sev_names = [a.name for a in sev]
    assert "BadRAM" in sev_names  # curated list, unpatched default
    assert "TEE.fail" in sev_names
    # Plundervolt is SGX-only per its curated affected_platforms
    tdx = get_unmitigated_attacks(Platform.IntelTDX)
    assert not any(a.name == "Plundervolt" for a in tdx)
    # Setting a DB path must not change the source
    set_archaeology_db_path("unused.db")
    try:
        assert get_unmitigated_attacks(Platform.AMDSEVSNP) == sev
    finally:
        set_archaeology_db_path("")


def test_parse_svn_formats():
    assert _parse_svn("0.0.1.20") == (0, 0, 1, 20)
    assert _parse_svn("3.5.1.128") == (3, 5, 1, 128)
    assert _parse_svn("04001f00") == (4, 0, 31, 0)
    assert _parse_svn("03050000") == (3, 5, 0, 0)
    assert _parse_svn("123") == (123,)
    assert _parse_svn("v1-alpha") == ("v1-alpha",)


def test_svn_per_attack_filter_excludes_when_threshold_met():
    badram = [a for a in TEE_ATTACKS if a.name == "BadRAM"][0]
    assert badram.min_svn is not None

    # Below the patch threshold: BadRAM remains unmitigated
    low = get_unmitigated_attacks(Platform.AMDSEVSNP, tcb_version="0.0.1.10")
    assert "BadRAM" in [a.name for a in low]

    # At the threshold: still unmitigated (requires strictly greater? no, >=)
    at = get_unmitigated_attacks(Platform.AMDSEVSNP, tcb_version="0.0.1.20")
    assert "BadRAM" not in [a.name for a in at]

    # Above the threshold: BadRAM is filtered out
    high = get_unmitigated_attacks(Platform.AMDSEVSNP, tcb_version="0.0.1.30")
    assert "BadRAM" not in [a.name for a in high]


def test_svn_filter_ignores_other_platforms():
    """BadRAM's SEV-SNP min_svn must not affect TDX filtering."""
    tdx = get_unmitigated_attacks(Platform.IntelTDX, tcb_version="03050000")
    assert not any(a.name == "BadRAM" for a in tdx)
    # BadRAM doesn't affect TDX anyway, so this just confirms no cross-platform leak.


def test_svn_filter_works_without_db():
    """The min_svn filter works from the curated source alone."""
    sev = get_unmitigated_attacks(Platform.AMDSEVSNP, tcb_version="0.0.1.30")
    names = [a.name for a in sev]
    assert "BadRAM" not in names  # filtered by curated min_svn


def test_check_firmware_patched_with_tcb_version(tmp_path: Path):
    # Below patch threshold: not fully patched
    assert _check_firmware_patched(Platform.AMDSEVSNP, "0.0.1.10") is False
    # At/above patch threshold for BadRAM; other attacks may still be unpatched
    # so this asserts the specific behavior, not full platform patching.
    patched_attacks = get_unmitigated_attacks(Platform.AMDSEVSNP, tcb_version="0.0.1.30")
    assert "BadRAM" not in [a.name for a in patched_attacks]
