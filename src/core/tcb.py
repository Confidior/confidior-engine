"""TCB (Trusted Computing Base) liveness resolution.

Determines whether a quote's reported TCB/firmware version is current, expired,
or unknown, by comparing it against a *reference* of the current TCB version
for the platform.

Important: this module does NOT fabricate a reference. It only compares the
quoted version against a reference that is supplied by the caller (e.g. from
the archaeology DB `tcb_records` table or a live vendor TCB-info lookup). When
no reference is available it returns ``UNKNOWN`` with an explicit reason rather
than guessing. Guessing a reference would repeat the failure mode that produced
the inaccurate attack-DB platform tags.

Status semantics (matching the temporal model):
- CURRENT: quoted TCB is at or above the current reference (firmware is current).
- EXPIRED: quoted TCB is below the current reference (firmware is out of date).
- UNKNOWN: no reference available, or the versions are not comparable.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.core.attacks import _parse_svn
from src.core.taxonomy import TCBStatus


@dataclass(frozen=True)
class TCBResolution:
    """Result of resolving a quoted TCB version against a reference."""

    status: TCBStatus
    quoted_version: Optional[str] = None
    reference_version: Optional[str] = None
    reason: str = ""

    def __str__(self) -> str:
        return (
            f"TCB {self.status.value}"
            + (f" (quoted {self.quoted_version}" if self.quoted_version else "")
            + (f" vs current {self.reference_version}" if self.reference_version else "")
            + (")" if self.quoted_version else "")
            + (f": {self.reason}" if self.reason else "")
        )


def _comparable(a: tuple, b: tuple) -> bool:
    """Return True if two parsed-SVN tuples are lexicographically comparable.

    Components are either all ints or a fallback string. Mixed int/str at the
    same position (or different lengths with mismatched types) cannot be safely
    ordered, so treat as incomparable.
    """
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if type(x) is not type(y):
            return False
    return True


def resolve_tcb_status(
    quoted_version: str | None,
    current_reference: str | None,
    *,
    platform: str | None = None,
) -> TCBResolution:
    """Resolve a quote's TCB version against a current reference version.

    Args:
        quoted_version: The TCB version reported by the quote (e.g. "0b010500"
            for Intel TDX, "4.0.22.219" for AMD SEV-SNP).
        current_reference: The current TCB version for the platform, from a
            trusted reference (archaeology DB tcb_records or vendor TCB-info).
            None means no reference is available.
        platform: Optional platform label used only in the reason string.

    Returns:
        TCBResolution with status CURRENT, EXPIRED, or UNKNOWN.
    """
    ctx = f" ({platform})" if platform else ""

    if not quoted_version:
        return TCBResolution(
            TCBStatus.UNKNOWN,
            reason=f"No TCB version present in quote{ctx}.",
        )

    if not current_reference:
        return TCBResolution(
            TCBStatus.UNKNOWN,
            quoted_version=quoted_version,
            reason=(
                f"No current TCB reference available{ctx}; status cannot be determined. "
                "Seed tcb_records (or wire a vendor TCB-info lookup) to resolve liveness."
            ),
        )

    try:
        quoted = _parse_svn(quoted_version)
        reference = _parse_svn(current_reference)
        # Compare component-wise (lexicographic tuple compare). Types may not
        # align (int vs str) for incomparable formats; treat as unknown.
        if not _comparable(quoted, reference):
            return TCBResolution(
                TCBStatus.UNKNOWN,
                quoted_version=quoted_version,
                reference_version=current_reference,
                reason=f"Incomparable TCB version formats{ctx}.",
            )
    except (TypeError, ValueError):
        return TCBResolution(
            TCBStatus.UNKNOWN,
            quoted_version=quoted_version,
            reference_version=current_reference,
            reason=f"Incomparable TCB version formats{ctx}.",
        )

    if quoted >= reference:
        return TCBResolution(
            TCBStatus.CURRENT,
            quoted_version=quoted_version,
            reference_version=current_reference,
            reason=f"Quoted TCB is at or above the current reference{ctx}.",
        )
    return TCBResolution(
        TCBStatus.EXPIRED,
        quoted_version=quoted_version,
        reference_version=current_reference,
        reason=f"Quoted TCB is below the current reference{ctx}; firmware is out of date.",
    )


def load_current_tcb_reference(
    platform: str,
    db_path: str | None = None,
) -> str | None:
    """Return the current TCB version for a platform from the archaeology DB.

    Reads the ``tcb_records`` table for a record with ``status='current'`` and
    a matching platform. Returns None if the DB is unavailable or no current
    record exists. The caller decides how to treat None (see
    :func:`resolve_tcb_status`).

    The engine's configured archaeology DB path is respected if ``db_path`` is
    omitted.
    """
    from src.tools.archaeology import ArchaeologyDB

    path = db_path or _get_default_archaeology_path()
    if not path or not Path(path).exists():
        return None
    db = ArchaeologyDB(db_path=path)
    try:
        rows = db.query(platform=platform, status="current")
        if not rows:
            return None
        # Prefer the newest current record (by release_date if present).
        rows = sorted(rows, key=lambda r: r.release_date or "", reverse=True)
        return rows[0].version
    finally:
        db.close()


def _get_default_archaeology_path() -> str | None:
    """Resolve the engine's default archaeology DB path, if configured."""
    try:
        from src.core.risk import _ARCHAEOLOGY_DB_PATH

        if _ARCHAEOLOGY_DB_PATH:
            return str(_ARCHAEOLOGY_DB_PATH)
    except ImportError:
        pass
    # Fall back to the default data/archaeology.db next to the project.
    return str(Path(__file__).resolve().parent.parent.parent / "data" / "archaeology.db")
