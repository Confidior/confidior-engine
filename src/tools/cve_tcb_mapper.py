"""Map CVE IDs to TCB/firmware fix versions for per-attack SVN thresholds.

The archaeology DB has two relevant tables:
- ``tcb_records``, vendor TCB releases with platform, version, status, and CVE IDs.
- ``attack_records``, curated attacks with CVE IDs and affected platforms.

This module joins them to derive ``min_svn`` thresholds: if a TCB record lists
a CVE ID and the record's platform matches one of the attack's affected
platforms, the record's version becomes the minimum safe SVN for that attack.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from src.core.clock import utc_now
from src.core.taxonomy import Platform
from src.tools.archaeology import ArchaeologyDB


@dataclass(frozen=True)
class CVEToTCBMapping:
    cve_id: str
    attack_name: str
    platform: Platform
    fixed_version: str
    advisory_url: str | None = None


def _platform_from_string(value: str) -> Platform | None:
    """Match a TCB record platform string to a Platform enum value."""
    for p in Platform:
        if p.value.lower() == value.lower():
            return p
    # Common aliases
    aliases = {
        "intel-tdx": Platform.IntelTDX,
        "amd-sev-snp": Platform.AMDSEVSNP,
        "amd-sev": Platform.AMDSEVSNP,
        "aws-nitro": Platform.AWSNitro,
        "nvidia-gpu-cc": Platform.NVIDIAGPUCC,
        "nvidia": Platform.NVIDIAGPUCC,
        "apple-pcc": Platform.ApplePCC,
        "arm-cca": Platform.ARMCCA,
        "ibm-secure-execution": Platform.IBMSecureExecution,
        "hygon-csv": Platform.HygonCSV,
        "risc-v-cove": Platform.RISCVCoVE,
    }
    return aliases.get(value.lower())


def map_cve_to_tcb_versions(db: ArchaeologyDB) -> list[CVEToTCBMapping]:
    """Return all CVE→TCB mappings implied by the current archaeology DB.

    Only TCB records with status ``current`` are treated as fixed versions.
    Revoked/expired records are ignored for threshold derivation.
    """
    conn = db._get_conn()
    rows = conn.execute(
        "SELECT a.name, a.affected_platforms, a.cve_id, t.platform, t.version, t.advisory_url "
        "FROM attack_records a "
        "JOIN tcb_records t ON t.cve_id = a.cve_id "
        "WHERE a.cve_id IS NOT NULL AND a.cve_id != '' AND t.status = 'current'"
    ).fetchall()

    mappings: list[CVEToTCBMapping] = []
    for row in rows:
        affected = json.loads(row["affected_platforms"])
        platform = _platform_from_string(row["platform"])
        if platform is None:
            continue
        if platform.name not in affected:
            continue
        mappings.append(
            CVEToTCBMapping(
                cve_id=row["cve_id"],
                attack_name=row["name"],
                platform=platform,
                fixed_version=row["version"],
                advisory_url=row["advisory_url"],
            )
        )
    return mappings


def apply_cve_tcb_mappings(
    db: ArchaeologyDB,
    dry_run: bool = False,
) -> tuple[list[CVEToTCBMapping], list[CVEToTCBMapping]]:
    """Apply CVE→TCB mappings to attack_records.min_svn.

    Returns (applied, duplicates/skipped).
    """
    mappings = map_cve_to_tcb_versions(db)
    conn = db._get_conn()
    applied: list[CVEToTCBMapping] = []
    skipped: list[CVEToTCBMapping] = []

    current_min_svn_rows = conn.execute(
        "SELECT name, min_svn FROM attack_records WHERE min_svn IS NOT NULL"
    ).fetchall()
    current_min_svn: dict[str, dict[str, str]] = {
        row["name"]: json.loads(row["min_svn"]) for row in current_min_svn_rows
    }

    for m in mappings:
        existing = current_min_svn.get(m.attack_name, {})
        # Prefer the existing threshold if already present (human-curated wins).
        if m.platform.name in existing:
            skipped.append(m)
            continue

        updated = dict(existing)
        updated[m.platform.name] = m.fixed_version
        applied.append(m)

        if not dry_run:
            conn.execute(
                "UPDATE attack_records SET min_svn = ? WHERE name = ?",
                (json.dumps(updated, sort_keys=True), m.attack_name),
            )
            current_min_svn[m.attack_name] = updated

    if not dry_run:
        conn.commit()
    return applied, skipped


def map_cve_tcb_for_db(
    db_path: str | Path, dry_run: bool = False
) -> tuple[list[CVEToTCBMapping], list[CVEToTCBMapping]]:
    """Convenience wrapper that opens the DB, applies mappings, and closes it."""
    db = ArchaeologyDB(db_path=db_path)
    try:
        return apply_cve_tcb_mappings(db, dry_run=dry_run)
    finally:
        db.close()


@dataclass
class TCBVulnerability:
    """A CVE whose fixed TCB version is above the quote's current TCB version."""
    cve_id: str
    attack_name: str
    platform: Platform
    fixed_version: str
    release_date: str | None
    advisory_url: str | None
    months_behind: float | None


def check_tcb_lag(
    db: "ArchaeologyDB", platform: Platform, tcb_version: str
) -> list[TCBVulnerability]:
    """Cross-reference a quote's TCB version against CVE records.

    Returns every CVE whose fixed TCB version is above the given TCB version
    (i.e. the quote is behind the fix threshold), with the lag in months.
    This is the temporal-lag check: "your TCB is N months behind."
    """
    from datetime import datetime, timezone

    from src.core.attacks import _parse_svn

    vulnerabilities: list[TCBVulnerability] = []
    conn = db._get_conn()
    rows = conn.execute(
        "SELECT a.name, a.cve_id, t.platform, t.version, t.release_date, t.advisory_url "
        "FROM attack_records a "
        "JOIN tcb_records t ON t.cve_id = a.cve_id "
        "WHERE a.cve_id IS NOT NULL AND a.cve_id != '' AND t.status = 'current'"
    ).fetchall()
    for row in rows:
        row_platform = _platform_from_string(row["platform"])
        if row_platform is None or row_platform != platform:
            continue
        fixed = row["version"].lstrip(">= ").strip()
        try:
            if _parse_svn(tcb_version) >= _parse_svn(fixed):
                continue  # patched at this TCB
        except TypeError:
            continue  # incomparable formats -> skip (conservative: don't claim lag)
        months = None
        if row["release_date"]:
            try:
                rd = datetime.fromisoformat(row["release_date"].replace("Z", "+00:00"))
                if rd.tzinfo is None:
                    rd = rd.replace(tzinfo=timezone.utc)
                months = round((utc_now() - rd).days / 30.44, 1)
            except ValueError:
                pass
        vulnerabilities.append(
            TCBVulnerability(
                cve_id=row["cve_id"],
                attack_name=row["name"],
                platform=platform,
                fixed_version=row["version"],
                release_date=row["release_date"],
                advisory_url=row["advisory_url"],
                months_behind=months,
            )
        )
    return vulnerabilities


# ---------------------------------------------------------------------------
# Fix-version extraction from CVE descriptions: 2026-08-15
# Some CVE descriptions carry the fix version in prose ("before version
# 1.5.05.46.698", "versions before 3.1.80 and 4.0.30"). This parses those
# patterns so tcb_records can be seeded from the feed instead of hand curation.
# ---------------------------------------------------------------------------

_FIX_PATTERNS = [
    r"before\s+version\s+([0-9][0-9a-zA-Z._-]*)",
    r"versions?\s+before\s+([0-9][0-9a-zA-Z._-]*)",
    r"prior\s+to\s+version\s+([0-9][0-9a-zA-Z._-]*)",
    r"fixed\s+in\s+version\s+([0-9][0-9a-zA-Z._-]*)",
]


def extract_fix_version(description: str) -> str | None:
    """Extract the first fix version mentioned in a CVE description.

    Returns the version string (e.g. "1.5.05.46.698") or None if the
    description doesn't carry one. This is the automation seed for the
    tcb_records fix thresholds.
    """
    import re

    for pattern in _FIX_PATTERNS:
        m = re.search(pattern, description, re.IGNORECASE)
        if m:
            return m.group(1)
    return None
