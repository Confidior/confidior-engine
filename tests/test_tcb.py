"""TCB liveness resolution tests.

Verifies that a quote's TCB version is correctly resolved to CURRENT / EXPIRED /
UNKNOWN against a reference, and that no reference yields an honest UNKNOWN
with a reason (never a guessed status).
"""

from src.core.taxonomy import TCBStatus
from src.core.tcb import resolve_tcb_status


def test_current_when_quoted_at_or_above_reference():
    # SEV-SNP dotted-decimal: quoted == current
    r = resolve_tcb_status("4.0.22.219", "4.0.22.219")
    assert r.status == TCBStatus.CURRENT

    # quoted strictly above current
    r2 = resolve_tcb_status("4.0.22.220", "4.0.22.219")
    assert r2.status == TCBStatus.CURRENT


def test_expired_when_quoted_below_reference():
    r = resolve_tcb_status("4.0.20.100", "4.0.22.219")
    assert r.status == TCBStatus.EXPIRED
    assert r.reference_version == "4.0.22.219"


def test_current_tdx_hex_byte_comparison():
    # TDX tee_tcb_svn is a hex byte string, e.g. "0b010500"
    r = resolve_tcb_status("0b010500", "0b010500")
    assert r.status == TCBStatus.CURRENT
    r2 = resolve_tcb_status("0a010500", "0b010500")  # 0x0a < 0x0b
    assert r2.status == TCBStatus.EXPIRED


def test_unknown_when_no_reference():
    r = resolve_tcb_status("4.0.22.219", None)
    assert r.status == TCBStatus.UNKNOWN
    assert "reference" in r.reason.lower()
    # quoted version preserved for the report
    assert r.quoted_version == "4.0.22.219"


def test_unknown_when_no_quoted_version():
    r = resolve_tcb_status(None, "4.0.22.219")
    assert r.status == TCBStatus.UNKNOWN


def test_unknown_when_incomparable_formats():
    # A dotted-decimal vs an opaque non-hex token that _parse_svn can't align
    r = resolve_tcb_status("4.0.22.219", "not-a-version-token")
    assert r.status == TCBStatus.UNKNOWN


def test_platform_label_in_reason():
    r = resolve_tcb_status("4.0.22.219", None, platform="AMD-SEV-SNP")
    assert "AMD-SEV-SNP" in r.reason


def test_load_current_tcb_reference_from_seeded_db(tmp_path):
    """load_current_tcb_reference returns the newest current record from the DB."""
    from src.core.tcb import load_current_tcb_reference
    from src.tools.archaeology import ArchaeologyDB, TCBRecord

    db_path = tmp_path / "tcb.db"
    db = ArchaeologyDB(db_path=db_path)
    db.insert(
        TCBRecord(
            platform="AMD-SEV-SNP",
            version="4.0.20.100",
            status="current",
            release_date="2024-01-01",
        )
    )
    db.insert(
        TCBRecord(
            platform="AMD-SEV-SNP",
            version="4.0.22.219",
            status="current",
            release_date="2025-06-01",
        )
    )
    # Non-current and other-platform records must be ignored.
    db.insert(
        TCBRecord(
            platform="AMD-SEV-SNP", version="9.9.9.9", status="expired", release_date="2026-01-01"
        )
    )
    db.insert(
        TCBRecord(
            platform="Intel-TDX", version="99999999", status="current", release_date="2026-01-01"
        )
    )
    db.close()

    ref = load_current_tcb_reference("AMD-SEV-SNP", db_path=str(db_path))
    assert ref == "4.0.22.219"  # newest current, not the expired or other-platform one

    # Wire the reference into a full resolution.
    r = resolve_tcb_status("4.0.22.219", ref)
    assert r.status == TCBStatus.CURRENT


def test_load_current_tcb_reference_none_when_db_missing(tmp_path):
    from src.core.tcb import load_current_tcb_reference

    assert load_current_tcb_reference("AMD-SEV-SNP", db_path=str(tmp_path / "nope.db")) is None
