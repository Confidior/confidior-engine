"""Mark known-patched attacks in the archaeology DB.

Updates the seeded `attack_records.patched` flag for attacks with publicly
documented vendor fixes. Run after `seed_attacks_db.py` and after any
`attacks.py` change that requires a re-seed.

Idempotent: safe to re-run; sets patched=1 each time.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.tools.archaeology import ArchaeologyDB

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "archaeology.db"

KNOWN_PATCHED: list[tuple[str, str]] = [
    ("BadRAM", "AMD issued firmware patches to validate SPD metadata (CVE-2024-21944)"),
    (
        "Plundervolt",
        "BIOS/firmware voltage-control lock (Intel SGX mitigation; microcode/firmware patch)",
    ),
]


def main() -> None:
    if not DB_PATH.exists():
        raise SystemExit(f"DB not found at {DB_PATH}. Run scripts/seed_attacks_db.py first.")
    db = ArchaeologyDB(db_path=DB_PATH)
    for name, note in KNOWN_PATCHED:
        updated = db.mark_patched(name, patched=True)
        status = "marked" if updated else "already"
        print(f"  [{status}] {name}: {note}")
    db.close()
    print(f"Done. DB: {DB_PATH}")


if __name__ == "__main__":
    main()
