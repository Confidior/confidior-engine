"""Fetch TEE-relevant CVEs from OpenCVE API and insert into archaeology DB.

Usage:
    export OPENCVE_USERNAME=your@email.com
    export OPENCVE_PASSWORD=your_password
    uv run --no-project --with python-dotenv --with requests python scripts/fetch_tee_cves.py

What it does:
    1. Queries OpenCVE API for HIGH/CRITICAL CVEs matching TEE vendor/products
    2. Uses API-side cvss filter (list endpoint doesn't return CVSS data)
    3. Inserts new CVEs into the archaeology DB attack_records table
    4. Prints a summary of what was added

API note:
    GET /api/cve list endpoint only returns: cve_id, description, created_at, updated_at.
    CVSS data requires a separate detail call per CVE. We use the `cvss` query param to
    filter server-side, avoiding 1000s of detail calls.
"""

from __future__ import annotations

import os
import sys
import time
from argparse import ArgumentParser
from pathlib import Path
from typing import TYPE_CHECKING

import requests
from dotenv import load_dotenv

if TYPE_CHECKING:
    from src.core.taxonomy import Platform
    from src.tools.archaeology import ArchaeologyDB, AttackRecord, TCBRecord

load_dotenv()

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "archaeology.db"

OPENCVE_API = "https://app.opencve.io/api"

# Each entry: (vendor_name, product_name, platform_tag)
# Vendor/product names matching OpenCVE's taxonomy (found via /api/vendors and /api/products).
# These are NOT CPE names -- OpenCVE has its own vendor/product hierarchy.
TEE_TARGETS: list[tuple[str, str, str]] = [
    ("intel", "trusted_execution_engine", "IntelTDX"),       # Intel TXE / TDX module
    ("intel", "sgx_dcap_software", "IntelTDX"),              # Intel SGX DCAP
    ("intel", "tdx_module_software", "IntelTDX"),            # Intel TDX module
    ("amd", "secrets", "AMDSEVSNP"),                         # AMD SEV firmware
    ("amd", "epyc", "AMDSEVSNP"),                            # AMD EPYC
    ("nvidia", "gpu", "NVIDIAGPUCC"),                        # NVIDIA GPU
    ("arm", "trustzone", "ARMCCA"),                          # ARM TrustZone
    ("arm", "cca", "ARMCCA"),                                # ARM CCA
    ("apple", "private_cloud_compute", "ApplePCC"),          # Apple PCC
    ("ibm", "secure_execution", "IBMSecureExecution"),       # IBM SE
    ("hygon", "csv", "HygonCSV"),                            # Hygon CSV
    ("linaro", "op-tee", "ARMCCA"),                          # OP-TEE
]

_LAST_REQUEST = 0.0


def _rate_limit(delay: float = 2.0):
    global _LAST_REQUEST
    elapsed = time.time() - _LAST_REQUEST
    if elapsed < delay:
        time.sleep(delay - elapsed)
    _LAST_REQUEST = time.time()


def _request_with_retry(
    url: str, params: dict, auth: tuple[str, str] | None = None, token: str | None = None, retries: int = 3
) -> requests.Response | None:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for attempt in range(retries):
        try:
            resp = requests.get(url, params=params, headers=headers, auth=auth, timeout=30)
            if resp.status_code == 429:
                wait = 15 * (attempt + 1)
                print(f"rate limited, waiting {wait}s...", end=" ", flush=True)
                time.sleep(wait)
                continue
            if resp.status_code == 401:
                print("\nAuth failed: check OPENCVE_API_TOKEN or OPENCVE_USERNAME/OPENCVE_PASSWORD")
                sys.exit(1)
            return resp
        except requests.RequestException as e:
            if attempt < retries - 1:
                wait = 5 * (attempt + 1)
                print(f"error, retrying in {wait}s...", end=" ", flush=True)
                time.sleep(wait)
                continue
            print(f"\nFailed after {retries} attempts: {e}")
            return None
    return None


def fetch_cves(
    vendor: str, product: str,
    username: str | None = None, password: str | None = None,
    token: str | None = None, max_pages: int = 5,
) -> list[dict]:
    """Fetch HIGH + CRITICAL CVEs for a vendor/product from OpenCVE.

    Supports both Basic Auth (username/password) and Bearer token (preferred).
    The list endpoint only returns cve_id, description, created_at, updated_at.
    We use the api-side cvss filter to get only high/critical results.
    """
    auth = (username, password) if username and password else None
    all_results: dict[str, dict] = {}
    seen: set[str] = set()

    for cvss_filter in ("high", "critical"):
        params: dict[str, str | int] = {
            "vendor": vendor,
            "product": product,
            "cvss": cvss_filter,
            "page": 1,
        }
        while True:
            print(f"  {cvss_filter} page {params['page']}...", end=" ", flush=True)
            _rate_limit(delay=2.0)

            resp = _request_with_retry(f"{OPENCVE_API}/cve", params, auth=auth, token=token)
            if resp is None:
                break
            if resp.status_code == 404:
                print("(no results)")
                break

            data = resp.json()
            results = data.get("results", [])
            if not results:
                print("(done)")
                break

            for c in results:
                cid = c["cve_id"]
                if cid not in seen:
                    seen.add(cid)
                    all_results[cid] = c

            print(f"{len(results)} CVEs (total unique: {len(seen)})")
            if data.get("next") is None:
                break
            if params["page"] >= max_pages:
                print(f"(stopped at {max_pages} pages)")
                break
            params["page"] += 1

    return list(all_results.values())


def cve_to_attack_record(cve: dict, vendor: str, product: str) -> "AttackRecord":
    """Convert an OpenCVE list entry to an AttackRecord."""
    from src.tools.archaeology import AttackRecord
    from src.core.taxonomy import Platform

    cve_id = cve["cve_id"]
    desc = cve.get("description", "")

    # Map vendor -> Platform
    PLATFORM_MAP = {
        "intel": Platform.IntelTDX,
        "amd": Platform.AMDSEVSNP,
        "nvidia": Platform.NVIDIAGPUCC,
        "arm": Platform.ARMCCA,
        "apple": Platform.ApplePCC,
        "ibm": Platform.IBMSecureExecution,
        "hygon": Platform.HygonCSV,
        "linaro": Platform.ARMCCA,
    }
    platform = PLATFORM_MAP.get(vendor, Platform.IntelTDX)

    return AttackRecord(
        name=cve_id,
        year=int(cve_id.split("-")[1]),
        affected_platforms=frozenset({platform}),
        category="architectural",
        cost_to_attack="Unknown",
        impact=desc[:200] if desc else f"TEE-relevant vulnerability ({vendor}/{product})",
        mitigation="Vendor patch required (High/Critical severity)",
        mitigation_difficulty="firmware_patch_available",
        cve_id=cve_id,
        paper_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        boundary_statement=f"{cve_id}: {desc[:300]} [severity: high/critical from OpenCVE API filter]",
        patched=False,
    )


def main():
    parser = ArgumentParser(description="Fetch TEE-relevant CVEs (OpenCVE or NVD)")
    parser.add_argument("--source", choices=["opencve", "nvd"], default="opencve", help="CVE source (default: opencve; nvd = free, no credentials)")
    parser.add_argument("--username", help="OpenCVE username (or OPENCVE_USERNAME env)")
    parser.add_argument("--password", help="OpenCVE password (or OPENCVE_PASSWORD env)")
    parser.add_argument("--token", help="OpenCVE API token (or OPENCVE_API_TOKEN env) -- preferred over username/password")
    parser.add_argument("--max-pages", type=int, default=5, help="Max pages per vendor/product (default: 5, 0 = unlimited)")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be added, don't insert")
    args = parser.parse_args()

    if args.source == "nvd":
        print("Fetching TEE-relevant CVEs from NVD (free, no credentials)...")
        cves = fetch_cves_nvd()
        records = [nvd_to_attack_record(c) for c in cves]
        print(f"\n=== Summary ===")
        print(f"Total high/critical TEE-relevant CVEs from NVD: {len(records)}")
        if not args.dry_run:
            from src.tools.archaeology import ArchaeologyDB, seed_attacks_from_list
            db = ArchaeologyDB(db_path=DB_PATH)
            try:
                count = seed_attacks_from_list(db, records)
                print(f"Inserted {count} new attacks into {DB_PATH}")
                _seed_tcb_records(db, cves)
            finally:
                db.close()
        else:
            for r in records[:10]:
                print(f"  {r.cve_id} ({r.year}): {r.impact[:60]}")
        return

    username = args.username or os.environ.get("OPENCVE_USERNAME")
    password = args.password or os.environ.get("OPENCVE_PASSWORD")
    token = args.token or os.environ.get("OPENCVE_API_TOKEN")

    if not token and (not username or not password):
        print("Set OPENCVE_API_TOKEN (preferred) or OPENCVE_USERNAME + OPENCVE_PASSWORD")
        print("Register at https://app.opencve.io/signup/ if you don't have an account")
        sys.exit(1)

    all_cves: list[tuple[dict, str, str]] = []

    for vendor, product, platform_tag in TEE_TARGETS:
        print(f"\n{vendor} / {product} ({platform_tag}):")
        cves = fetch_cves(vendor, product, username=username, password=password, token=token, max_pages=args.max_pages)
        for c in cves:
            all_cves.append((c, vendor, product))
        print(f"  → {len(cves)} high/critical CVEs")

    # Deduplicate across vendor/product overlaps
    unique: dict[str, tuple[dict, str, str]] = {}
    for c, v, p in all_cves:
        cid = c["cve_id"]
        if cid not in unique:
            unique[cid] = (c, v, p)

    cves_list = list(unique.values())

    print(f"\n=== Summary ===")
    print(f"Total unique high/critical CVEs across all TEE vendors: {len(cves_list)}")

    # Show recent samples
    cves_list.sort(key=lambda x: x[0]["cve_id"], reverse=True)
    print("\nMost recent (up to 10):")
    for c, v, p in cves_list[:10]:
        desc = (c.get("description") or "")[:120]
        print(f"  {c['cve_id']} [{v}/{p}]: {desc}")

    # Insert into archaeology DB
    if not args.dry_run and cves_list:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
            from src.tools.archaeology import ArchaeologyDB  # noqa: F811

            db = ArchaeologyDB(db_path=str(DB_PATH))
            count = 0
            for c, v, p in cves_list:
                rec = cve_to_attack_record(c, v, p)
                db.insert_attack(rec)
                count += 1
            _seed_tcb_records_from_opencve(db, cves_list)
            db.close()
            print(f"\nInserted {count} CVEs into {DB_PATH}")
        except Exception as e:
            print(f"\nInsert failed: {e}")
            import traceback
            traceback.print_exc()
            print(f"Would have inserted {len(cves_list)} CVEs")

    if args.dry_run:
        print(f"\nDry-run: {len(cves_list)} CVEs ready for insertion")

    print("\nDone.")




# ---------------------------------------------------------------------------
# NVD-backed fetch (free, no credentials) — 2026-08-15
# NVD gives: CVE id, published date, CVSS, description. No fix versions for
# TEE firmware (configurations are empty for these CVEs). Keeps the attack DB
# current: "growing as disclosed" without an OpenCVE key.
# ---------------------------------------------------------------------------

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# (keyword, platform_tag) — NVD keyword search terms for TEE-relevant CVEs
NVD_QUERIES: list[tuple[str, str]] = [
    ("SEV-SNP", "AMDSEVSNP"),
    ("AMD SEV", "AMDSEVSNP"),
    ("Intel TDX", "IntelTDX"),
    ("Intel SGX", "IntelTDX"),
    ("AWS Nitro", "AWSNitro"),
    ("NVIDIA confidential", "NVIDIAGPUCC"),
    ("ARM CCA", "ARMCCA"),
    ("confidential computing", "AMDSEVSNP"),
    ("Trusted Execution Environment", "AMDSEVSNP"),
]


def fetch_cves_nvd() -> list[dict]:
    """Fetch high/critical TEE-relevant CVEs from NVD (free, no auth).

    Returns CVE dicts: {cve_id, summary, published, cvss, platform_tag}.
    NVD's keyword search may miss CVEs that don't mention the keyword in the
    description; it is a complement to the OpenCVE vendor/product fetch, not a
    replacement.
    """
    import urllib.parse

    seen: dict[str, dict] = {}
    for keyword, platform_tag in NVD_QUERIES:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 50,
        }
        _rate_limit(6.0)  # NVD free tier: ~5 req / 30s
        resp = _request_with_retry(NVD_API, params)
        if not resp or resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        for v in data.get("vulnerabilities", []):
            c = v.get("cve", {})
            cve_id = c.get("id", "")
            if not cve_id:
                continue
            desc = next(
                (x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"),
                "",
            )
            cvss = None
            metrics = c.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                    break
            if cvss is not None and cvss < 7.0:
                continue
            seen[cve_id] = {
                "cve_id": cve_id,
                "summary": desc,
                "published": c.get("published", ""),
                "cvss": cvss,
                "platform_tag": platform_tag,
            }
    return list(seen.values())


def nvd_to_attack_record(cve: dict) -> "AttackRecord":
    """Convert an NVD-fetched CVE into an AttackRecord for the archaeology DB."""
    from src.tools.archaeology import AttackRecord
    from src.core.attacks import Platform

    tag = cve["platform_tag"]
    platform = next((p for p in Platform if p.name == tag), Platform.AMDSEVSNP)
    return AttackRecord(
        name=f"NVD {cve['cve_id']}",
        year=int((cve.get("published") or "2000-01-01")[:4]),
        affected_platforms=frozenset({platform}),
        category="cve_feed",
        cost_to_attack="unknown",
        impact=cve.get("summary", "")[:200],
        mitigation="unknown",
        mitigation_difficulty="unknown",
        cve_id=cve["cve_id"],
        boundary_statement="Imported from NVD keyword search (free feed); fix version not machine-readable in the CVE record.",
        patched=False,
    )


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------------------
# Fix-version → tcb_records auto-seed — 2026-08-15
# When a fetched CVE's description carries a fix version ("before version X"),
# seed a TCBRecord so the temporal lag check picks it up automatically.
# No hand curation for these entries.
# ---------------------------------------------------------------------------

def cve_to_tcb_record(cve: dict, platform_tag: str) -> "TCBRecord | None":
    """Create a TCBRecord from a CVE if its description carries a fix version.

    Returns None when no fix version is extractable (the common case — most
    TEE CVE descriptions don't state one).
    """
    from src.tools.cve_tcb_mapper import extract_fix_version
    from src.tools.archaeology import TCBRecord
    from src.core.attacks import Platform

    fix = extract_fix_version(cve.get("summary", "") or "")
    if not fix:
        return None
    platform = next((p for p in Platform if p.name == platform_tag), None)
    if platform is None:
        return None
    return TCBRecord(
        platform=platform.value,
        version=fix,
        release_date=(cve.get("published") or "")[:10] or None,
        status="current",
        cve_id=cve.get("cve_id", ""),
        advisory_url=None,
    )


def _seed_tcb_records(db: "ArchaeologyDB", cves: list[dict]) -> int:
    """Auto-seed tcb_records from fetched CVEs whose descriptions carry fix versions."""
    from src.tools.cve_tcb_mapper import extract_fix_version

    seeded = 0
    for c in cves:
        rec = cve_to_tcb_record(c, c.get("platform_tag", "AMDSEVSNP"))
        if rec is not None:
            db.insert(rec)
            seeded += 1
            print(f"  tcb: {rec.cve_id} -> {rec.platform} >= {rec.version} (from description)")
    print(f"Seeded {seeded} tcb_records from fix versions in descriptions")
    return seeded


def _seed_tcb_records_from_opencve(db: "ArchaeologyDB", cves_list: list[tuple[dict, str, str]]) -> int:
    """Auto-seed tcb_records from OpenCVE-fetched CVEs (description field)."""
    seeded = 0
    for c, _vendor, _product in cves_list:
        normalized = {
            "cve_id": c.get("cve_id", ""),
            "summary": c.get("description", ""),
            "published": c.get("created_at", ""),
            "platform_tag": c.get("platform_tag", "AMDSEVSNP"),
        }
        rec = cve_to_tcb_record(normalized, normalized["platform_tag"])
        if rec is not None:
            db.insert(rec)
            seeded += 1
            print(f"  tcb: {rec.cve_id} -> {rec.platform} >= {rec.version} (from description)")
    if seeded:
        print(f"Seeded {seeded} tcb_records from OpenCVE descriptions")
    return seeded
