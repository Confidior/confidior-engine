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

import requests
from dotenv import load_dotenv

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
    parser = ArgumentParser(description="Fetch TEE-relevant CVEs from OpenCVE API")
    parser.add_argument("--username", help="OpenCVE username (or OPENCVE_USERNAME env)")
    parser.add_argument("--password", help="OpenCVE password (or OPENCVE_PASSWORD env)")
    parser.add_argument("--token", help="OpenCVE API token (or OPENCVE_API_TOKEN env) -- preferred over username/password")
    parser.add_argument("--max-pages", type=int, default=5, help="Max pages per vendor/product (default: 5, 0 = unlimited)")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be added, don't insert")
    args = parser.parse_args()

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


if __name__ == "__main__":
    main()
