"""One-time seed of the archaeology DB with attacks from attacks.py."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.core.attacks import TEE_ATTACKS
from src.tools.archaeology import ArchaeologyDB, seed_attacks_from_list

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "archaeology.db"


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db = ArchaeologyDB(db_path=DB_PATH)
    count = seed_attacks_from_list(db, TEE_ATTACKS)
    db.close()
    print(f"Seeded {count} attacks into {DB_PATH}")


if __name__ == "__main__":
    main()
