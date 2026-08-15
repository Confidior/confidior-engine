"""Seed TCB fix-version records into the archaeology DB.

Task-11 data: CVE → fixed TCB version per platform. Each record says "this CVE
is patched at TCB version X on platform Y." The temporal lag check
(`confidior measure --tcb`) compares a quote's TCB against these thresholds.

Currently seeded: BadRAM (CVE-2024-21944) → AMD SEV-SNP fix at TCB >= 0.0.1.20
(AMD-SB-6010). TODO(2026-08-15): validate 0.0.1.20 against the bulletin's actual
fixed version; add more records as CVEs are curated.
"""

from pathlib import Path

from src.tools.archaeology import ArchaeologyDB, TCBRecord

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "archaeology.db"

SEEDS = [
    TCBRecord(
        platform="AMD-SEV-SNP",
        version="0.0.1.20",
        release_date="2024-12-11",
        status="current",
        cve_id="CVE-2024-21944",
        advisory_url="https://www.amd.com/en/resources/product-security/bulletin/amd-sb-6010.html",
    ),
]


def main() -> None:
    db = ArchaeologyDB(db_path=DB_PATH)
    try:
        for record in SEEDS:
            db.insert(record)
            print(f"Seeded {record.cve_id} -> {record.platform} >= {record.version}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
