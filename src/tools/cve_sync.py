"""Live CVE sync from OpenCVE and bundle re-score trigger.

This module reuses the vendor/product targets and fetch helpers from
``scripts/fetch_tee_cves.py``. It inserts new high/critical CVEs into the
archaeology DB, applies CVE→TCB mappings, and identifies evidence bundles that
need re-evaluation because the attack DB has changed.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import Any

from src.core.attacks import Platform
from src.core.taxonomy import EvidenceBundle
from src.tools.archaeology import ArchaeologyDB
from src.tools.cve_tcb_mapper import apply_cve_tcb_mappings

_SCRIPT_PATH = Path(__file__).resolve().parent.parent.parent / "scripts" / "fetch_tee_cves.py"


def _load_fetch_module():
    spec = importlib.util.spec_from_file_location("fetch_tee_cves", str(_SCRIPT_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _dedupe_cves(
    cves: list[tuple[dict[str, Any], str, str]],
) -> list[tuple[dict[str, Any], str, str]]:
    seen: dict[str, tuple[dict[str, Any], str, str]] = {}
    for cve, vendor, product in cves:
        cid = cve["cve_id"]
        if cid not in seen:
            seen[cid] = (cve, vendor, product)
    return list(seen.values())


def fetch_tee_cves(
    max_pages: int = 3,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> list[tuple[dict[str, Any], str, str]]:
    """Fetch high/critical TEE CVEs from OpenCVE.

    Credentials are read from arguments or from the environment:
    ``OPENCVE_API_TOKEN`` (preferred) or ``OPENCVE_USERNAME`` + ``OPENCVE_PASSWORD``.
    """
    token = token or os.environ.get("OPENCVE_API_TOKEN")
    username = username or os.environ.get("OPENCVE_USERNAME")
    password = password or os.environ.get("OPENCVE_PASSWORD")
    if not token and (not username or not password):
        raise RuntimeError(
            "OpenCVE credentials required. Set OPENCVE_API_TOKEN "
            "or OPENCVE_USERNAME + OPENCVE_PASSWORD."
        )

    mod = _load_fetch_module()
    all_cves: list[tuple[dict[str, Any], str, str]] = []
    for vendor, product, platform_tag in mod.TEE_TARGETS:
        cves = mod.fetch_cves(
            vendor,
            product,
            username=username,
            password=password,
            token=token,
            max_pages=max_pages,
        )
        for cve in cves:
            all_cves.append((cve, vendor, product))
    return _dedupe_cves(all_cves)


def insert_new_cves(
    db: ArchaeologyDB,
    cves: list[tuple[dict[str, Any], str, str]],
) -> int:
    """Insert CVEs that are not already present in the attack_records table."""
    mod = _load_fetch_module()
    existing = {r.cve_id for r in db.query_attacks() if r.cve_id}
    inserted = 0
    for cve, vendor, product in cves:
        if cve["cve_id"] in existing:
            continue
        rec = mod.cve_to_attack_record(cve, vendor, product)
        db.insert_attack(rec)
        existing.add(cve["cve_id"])
        inserted += 1
    return inserted


def sync_cves(
    db_path: str | Path,
    max_pages: int = 3,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """End-to-end sync: fetch, insert, and map CVEs to TCB fix versions.

    Returns a summary dict:
        - fetched: number of unique high/critical CVEs from OpenCVE
        - inserted: number of new CVE attack_records added
        - tcb_mappings_applied: list of CVEToTCBMapping objects
        - tcb_mappings_skipped: list of CVEToTCBMapping objects
    """
    db = ArchaeologyDB(db_path=db_path)
    try:
        cves = fetch_tee_cves(
            max_pages=max_pages, token=token, username=username, password=password
        )
        inserted = 0
        if not dry_run:
            inserted = insert_new_cves(db, cves)
        applied, skipped = apply_cve_tcb_mappings(db, dry_run=dry_run)
        return {
            "fetched": len(cves),
            "inserted": inserted,
            "tcb_mappings_applied": applied,
            "tcb_mappings_skipped": skipped,
        }
    finally:
        db.close()


def _platform_from_bundle_summary(summary: dict[str, Any]) -> tuple[Platform | None, str | None]:
    platforms = summary.get("platforms") or []
    tcb_versions = summary.get("tcb_versions") or []
    if not platforms:
        return None, None
    platform_value = platforms[0]
    tcb_version = None
    for tv in tcb_versions:
        if tv.get("platform") == platform_value:
            tcb_version = tv.get("tcb_version")
            break
    try:
        platform = Platform(platform_value)
    except ValueError:
        platform = None
    return platform, tcb_version


def find_affected_bundles(
    db_path: str | Path,
    bundle_dir: str | Path,
) -> list[dict[str, Any]]:
    """Return bundles whose current score would differ under the current attack DB.

    This is a re-score trigger, not a full re-evaluation. We compare the bundle's
    stored attack_db_snapshot with the current snapshot, and list the unmitigated
    attacks that now apply to the bundle's platform/TCB version.
    """
    from src.core.attacks import (
        compute_attack_db_snapshot,
        get_unmitigated_attacks,
        set_attacks_db_path,
    )
    from src.core.risk import set_archaeology_db_path

    db_path = Path(db_path)
    set_attacks_db_path(db_path)
    set_archaeology_db_path(db_path)

    db = ArchaeologyDB(db_path=db_path)
    try:
        current_snapshot = compute_attack_db_snapshot()
        affected: list[dict[str, Any]] = []
        bundle_dir = Path(bundle_dir)
        if not bundle_dir.exists():
            return affected
        for path in bundle_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text())
                bundle = EvidenceBundle.from_dict(data)
            except Exception:
                continue
            summary = bundle.evidence_graph_summary or {}
            platform, tcb_version = _platform_from_bundle_summary(summary)
            if platform is None:
                continue
            attacks = get_unmitigated_attacks(platform, tcb_version=tcb_version)
            attack_names = sorted(a.name for a in attacks)
            snapshot_changed = (bundle.attack_db_snapshot or "") != current_snapshot
            affected.append(
                {
                    "path": str(path),
                    "bundle_id": bundle.bundle_id,
                    "platform": platform.value,
                    "tcb_version": tcb_version,
                    "snapshot_changed": snapshot_changed,
                    "attack_count": len(attack_names),
                    "unmitigated_attacks": attack_names,
                    "old_score_total": bundle.assurance.score.total
                    if bundle.assurance and bundle.assurance.score
                    else None,
                    "old_score_grade": bundle.assurance.score.grade
                    if bundle.assurance and bundle.assurance.score
                    else None,
                    "recommendation": "re-run `confidior verify` to get an updated score",
                }
            )
        return affected
    finally:
        db.close()
