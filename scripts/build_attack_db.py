"""Build/validate the curated attack database from JSON source files.

Usage:
    uv run python scripts/build_attack_db.py validate
    uv run python scripts/build_attack_db.py build [--db-path data/archaeology.db]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from jsonschema import validate

# ruff: noqa: E402
from src.core.attacks import AttackCategory, MitigationDifficulty
from src.core.taxonomy import Platform
from src.tools.archaeology import ArchaeologyDB, AttackRecord

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ATTACK_DIR = PROJECT_ROOT / "data" / "attacks"
SCHEMA_PATH = PROJECT_ROOT / "data" / "schemas" / "attack.json"
AGGREGATE_PATH = PROJECT_ROOT / "data" / "attacks.json"


KNOWN_PLATFORMS = {p.value for p in Platform}
KNOWN_CATEGORIES = {c.value for c in AttackCategory}
KNOWN_DIFFICULTIES = {d.value for d in MitigationDifficulty}


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def load_attack_records() -> list[dict]:
    records = []
    if not ATTACK_DIR.exists():
        return records
    for path in sorted(ATTACK_DIR.glob("*.json")):
        records.append(json.loads(path.read_text()))
    return records


def validate_records(records: list[dict], schema: dict) -> list[str]:
    errors: list[str] = []
    names: set[str] = set()
    for rec in records:
        name = rec.get("name", "<unknown>")
        if name in names:
            errors.append(f"duplicate attack name: {name}")
        names.add(name)
        try:
            validate(instance=rec, schema=schema)
        except Exception as e:
            errors.append(f"{name}: {e}")
            continue

        # Extra semantic checks beyond JSON Schema
        for platform in rec.get("affected_platforms", []):
            if platform not in KNOWN_PLATFORMS:
                errors.append(f"{name}: unknown platform {platform}")
        if rec.get("category") not in KNOWN_CATEGORIES:
            errors.append(f"{name}: unknown category {rec.get('category')}")
        if rec.get("mitigation_difficulty") not in KNOWN_DIFFICULTIES:
            errors.append(
                f"{name}: unknown mitigation_difficulty {rec.get('mitigation_difficulty')}"
            )
        for key in rec.get("min_svn", {}):
            if key not in KNOWN_PLATFORMS:
                errors.append(f"{name}: unknown min_svn platform {key}")
    return errors


def build_aggregate(records: list[dict]) -> None:
    aggregate = {
        "version": "1.0",
        "attack_count": len(records),
        "attacks": records,
    }
    AGGREGATE_PATH.write_text(json.dumps(aggregate, indent=2, ensure_ascii=False) + "\n")


def record_to_attack_record(rec: dict) -> AttackRecord:
    return AttackRecord(
        name=rec["name"],
        year=rec["year"],
        affected_platforms=frozenset(Platform(p) for p in rec.get("affected_platforms", [])),
        category=rec["category"],
        cost_to_attack=rec["cost_to_attack"],
        impact=rec["impact"],
        mitigation=rec["mitigation"],
        mitigation_difficulty=rec["mitigation_difficulty"],
        cve_id=rec["cve_ids"][0] if rec.get("cve_ids") else None,
        paper_url=rec.get("paper_url"),
        boundary_statement=rec.get("boundary_statement", ""),
        patched=rec.get("patched", False),
        min_svn=rec.get("min_svn") if rec.get("min_svn") else None,
        compliance_controls=rec.get("compliance_controls", {}),
    )


def build_db(db_path: Path | None = None) -> None:
    if db_path is None:
        db_path = PROJECT_ROOT / "data" / "archaeology.db"
    schema = load_schema()
    records = load_attack_records()
    errors = validate_records(records, schema)
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        raise SystemExit(1)

    build_aggregate(records)
    db = ArchaeologyDB(db_path=db_path)
    for rec in records:
        db.insert_attack(record_to_attack_record(rec))
    db.close()
    print(f"Built {AGGREGATE_PATH} and seeded {db_path} with {len(records)} attacks")


def validate_only() -> int:
    schema = load_schema()
    records = load_attack_records()
    if not records:
        print("No attack records found.", file=sys.stderr)
        return 1
    errors = validate_records(records, schema)
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1
    print(f"OK: {len(records)} attack records valid")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and validate the attack database")
    sub = parser.add_subparsers(dest="command", required=True)

    validate_cmd = sub.add_parser("validate", help="Validate all attack JSON files")
    validate_cmd.set_defaults(func=lambda args: validate_only())

    build_cmd = sub.add_parser("build", help="Validate, regenerate aggregate, and seed SQLite")
    build_cmd.add_argument("--db-path", type=Path, default=None, help="Path to SQLite DB")
    build_cmd.set_defaults(func=lambda args: (build_db(args.db_path), 0)[1])

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
