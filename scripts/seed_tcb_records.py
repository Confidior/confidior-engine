"""Seed TCB reference records into the archaeology DB.

Two sources:
1. Curated YAML files in data/tcb/ (e.g. amd-current.yaml): current-TCB
   references per product family, sourced from vendor security bulletins.
2. A small hardcoded seed for CVE fix thresholds (BadRAM).

Each record says "the current/fixed TCB for this platform (and product family,
when given) is version X." The liveness check compares a quote's TCB against
these references.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

from src.tools.archaeology import ArchaeologyDB, TCBRecord

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "archaeology.db"
TCB_DIR = DATA_DIR / "tcb"

# Legacy hardcoded seed: CVE fix thresholds.
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


def _load_curated_yaml(path: Path) -> list[TCBRecord]:
    """Load a curated TCB YAML file into TCBRecord objects."""
    data = yaml.safe_load(path.read_text()) or {}
    platform = data.get("platform")
    records: list[TCBRecord] = []
    for rec in data.get("records", []):
        records.append(
            TCBRecord(
                platform=platform,
                version=rec["version"],
                release_date=rec.get("release_date"),
                status=rec.get("status", "current"),
                cve_id=rec.get("cve_id"),
                advisory_url=rec.get("advisory_url"),
                product=rec.get("product"),
            )
        )
    return records


def main() -> None:
    db = ArchaeologyDB(db_path=DB_PATH)
    try:
        for record in SEEDS:
            db.insert(record)
            print(f"Seeded {record.cve_id} -> {record.platform} >= {record.version}")
        if TCB_DIR.exists():
            for path in sorted(TCB_DIR.glob("*.yaml")):
                for record in _load_curated_yaml(path):
                    db.insert(record)
                    label = f"{record.platform}/{record.product or '*'}"
                    print(f"Seeded {label} >= {record.version} ({record.advisory_url})")
    finally:
        db.close()


if __name__ == "__main__":
    main()
