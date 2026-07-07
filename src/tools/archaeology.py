from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from src.core.taxonomy import Platform

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS tcb_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL,
    version TEXT NOT NULL,
    release_date TEXT,
    status TEXT CHECK(status IN ('current', 'expired', 'revoked', 'unknown')),
    cve_id TEXT,
    advisory_url TEXT,
    parsed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_platform ON tcb_records(platform);
CREATE INDEX IF NOT EXISTS idx_cve_id ON tcb_records(cve_id);
CREATE INDEX IF NOT EXISTS idx_status ON tcb_records(status);

CREATE TABLE IF NOT EXISTS attack_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    year INTEGER NOT NULL,
    affected_platforms TEXT NOT NULL,
    category TEXT NOT NULL,
    cost_to_attack TEXT NOT NULL,
    impact TEXT NOT NULL,
    mitigation TEXT NOT NULL,
    mitigation_difficulty TEXT NOT NULL,
    cve_id TEXT,
    paper_url TEXT,
    boundary_statement TEXT,
    patched INTEGER DEFAULT 0,
    last_checked TEXT
);
CREATE INDEX IF NOT EXISTS idx_attack_platform ON attack_records(affected_platforms);
CREATE INDEX IF NOT EXISTS idx_attack_category ON attack_records(category);
CREATE INDEX IF NOT EXISTS idx_attack_patched ON attack_records(patched);
"""


@dataclass(frozen=True)
class TCBRecord:
    platform: str
    version: str
    release_date: str | None = None
    status: str = "unknown"
    cve_id: str | None = None
    advisory_url: str | None = None
    parsed_at: str | None = None


@dataclass(frozen=True)
class AttackRecord:
    name: str
    year: int
    affected_platforms: frozenset[Platform]
    category: str
    cost_to_attack: str
    impact: str
    mitigation: str
    mitigation_difficulty: str
    cve_id: str | None = None
    paper_url: str | None = None
    boundary_statement: str = ""
    patched: bool = False
    last_checked: str | None = None


def _platforms_from_json(json_str: str) -> frozenset[Platform]:
    names = json.loads(json_str)
    return frozenset(Platform[n] for n in names)


def _platforms_to_json(platforms: frozenset[Platform]) -> str:
    return json.dumps([p.name for p in platforms])


@dataclass
class ArchaeologyDB:
    db_path: Path
    conn: sqlite3.Connection | None = field(default=None, repr=False)

    def __post_init__(self):
        self.db_path = Path(self.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_conn(self) -> sqlite3.Connection:
        if self.conn is None:
            self.conn = sqlite3.connect(str(self.db_path))
            self.conn.row_factory = sqlite3.Row
            self.conn.executescript(DB_SCHEMA)
        return self.conn

    def insert(self, record: TCBRecord) -> None:
        conn = self._get_conn()
        parsed_at = record.parsed_at or datetime.now().isoformat()
        conn.execute(
            "INSERT INTO tcb_records (platform, version, release_date, status, cve_id, advisory_url, parsed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                record.platform,
                record.version,
                record.release_date,
                record.status,
                record.cve_id,
                record.advisory_url,
                parsed_at,
            ),
        )
        conn.commit()

    def query(self, platform: str | None = None, status: str | None = None, cve_id: str | None = None, version: str | None = None) -> list[TCBRecord]:
        conn = self._get_conn()
        conditions = []
        params: list[Any] = []

        if platform:
            conditions.append("platform = ?")
            params.append(platform)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if cve_id:
            conditions.append("cve_id = ?")
            params.append(cve_id)
        if version:
            conditions.append("version = ?")
            params.append(version)

        query = "SELECT * FROM tcb_records"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        rows = conn.execute(query, params).fetchall()
        return [
            TCBRecord(
                platform=row["platform"],
                version=row["version"],
                release_date=row["release_date"],
                status=row["status"],
                cve_id=row["cve_id"],
                advisory_url=row["advisory_url"],
                parsed_at=row["parsed_at"],
            )
            for row in rows
        ]

    def is_firmware_current(self, platform: str, version: str) -> bool:
        records = self.query(platform=platform, version=version)
        if not records:
            return False
        return all(r.status == "current" for r in records)

    def insert_attack(self, attack: AttackRecord) -> None:
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO attack_records "
            "(name, year, affected_platforms, category, cost_to_attack, impact, mitigation, "
            "mitigation_difficulty, cve_id, paper_url, boundary_statement, patched, last_checked) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                attack.name,
                attack.year,
                _platforms_to_json(attack.affected_platforms),
                attack.category,
                attack.cost_to_attack,
                attack.impact,
                attack.mitigation,
                attack.mitigation_difficulty,
                attack.cve_id,
                attack.paper_url,
                attack.boundary_statement,
                1 if attack.patched else 0,
                attack.last_checked or datetime.now().isoformat(),
            ),
        )
        conn.commit()

    def query_attacks(
        self, platform: Platform | None = None, category: str | None = None, unpatched_only: bool = False
    ) -> list[AttackRecord]:
        conn = self._get_conn()
        conditions = []
        params: list[Any] = []

        if platform:
            conditions.append("affected_platforms LIKE ?")
            params.append(f"%{platform.name}%")
        if category:
            conditions.append("category = ?")
            params.append(category)
        if unpatched_only:
            conditions.append("patched = ?")
            params.append(0)

        query = "SELECT * FROM attack_records"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY year DESC, name"

        rows = conn.execute(query, params).fetchall()
        return [
            AttackRecord(
                name=row["name"],
                year=row["year"],
                affected_platforms=_platforms_from_json(row["affected_platforms"]),
                category=row["category"],
                cost_to_attack=row["cost_to_attack"],
                impact=row["impact"],
                mitigation=row["mitigation"],
                mitigation_difficulty=row["mitigation_difficulty"],
                cve_id=row["cve_id"],
                paper_url=row["paper_url"],
                boundary_statement=row["boundary_statement"] or "",
                patched=bool(row["patched"]),
                last_checked=row["last_checked"],
            )
            for row in rows
        ]

    def mark_patched(self, name: str, patched: bool = True) -> bool:
        """Mark an attack as patched (or unpatched) by name. Returns True if updated."""
        conn = self._get_conn()
        cursor = conn.execute(
            "UPDATE attack_records SET patched = ?, last_checked = ? WHERE name = ?",
            (1 if patched else 0, datetime.now().isoformat(), name),
        )
        conn.commit()
        return cursor.rowcount > 0

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None


def seed_attacks_from_list(db: ArchaeologyDB, attacks: list[Any]) -> int:
    """Seed attack_records from a list of TEEAttack-like objects. Returns count inserted."""
    count = 0
    for a in attacks:
        record = AttackRecord(
            name=a.name,
            year=a.year,
            affected_platforms=a.affected_platforms,
            category=a.category.value if hasattr(a.category, "value") else a.category,
            cost_to_attack=a.cost_to_attack,
            impact=a.impact,
            mitigation=a.mitigation,
            mitigation_difficulty=a.mitigation_difficulty.value if hasattr(a.mitigation_difficulty, "value") else a.mitigation_difficulty,
            cve_id=a.cve_id,
            paper_url=a.paper_url,
            boundary_statement=a.boundary_statement,
        )
        db.insert_attack(record)
        count += 1
    return count
