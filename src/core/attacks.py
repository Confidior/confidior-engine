"""TEE attack taxonomy with 43 documented attacks and attack DB snapshot computation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from src.core.taxonomy import Platform


class AttackCategory(str, Enum):
    MEMORY_BUS = "memory_bus_interposition"
    ROGUE_MEMORY = "rogue_memory_module"
    PERFORMANCE_COUNTER = "performance_counter_side_channel"
    CHOSEN_PLAINTEXT = "chosen_plaintext_attack"
    INTERRUPT_SIGNAL = "interrupt_signal_ahoi"
    CACHE_SIDE_CHANNEL = "cache_side_channel"
    SPECULATIVE_EXECUTION = "speculative_execution"
    MEMORY_CORRUPTION = "memory_corruption"
    ARCHITECTURAL = "architectural"
    ROWHAMMER = "rowhammer"
    VOLTAGE_MANIPULATION = "voltage_manipulation"
    SYNCHRONIZATION = "synchronization_bug"


class MitigationDifficulty(str, Enum):
    HARDWARE_REDESIGN = "hardware_redesign_required"
    FIRMWARE_PATCH = "firmware_patch_available"
    MICROCODE_UPDATE = "microcode_update_available"
    SOFTWARE_FIX = "software_fix_available"
    NO_MITIGATION = "no_mitigation_available"


@dataclass(frozen=True)
class TEEAttack:
    name: str
    year: int
    affected_platforms: frozenset[Platform]
    category: AttackCategory
    cost_to_attack: str
    impact: str
    mitigation: str
    mitigation_difficulty: MitigationDifficulty
    cve_id: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    paper_url: str | None = None
    boundary_statement: str = ""
    patched: bool = False
    min_svn: dict[Platform, str] | None = None
    compliance_controls: dict[str, list[str]] = field(default_factory=dict)
    mapping_sources: dict[str, dict] = field(default_factory=dict)


def _parse_svn(svn: str) -> tuple[int | str, ...]:
    """Parse a TCB SVN string into a comparable tuple of integers.

    Supports:
    - Dotted-decimal versions like "0.0.1.20" (AMD SEV-SNP) -> (0, 0, 1, 20)
    - Hex byte strings like "04001f00" (Intel TDX) -> (4, 31, 0, 0)
    - Plain integers
    Falls back to string comparison for unknown formats.
    """
    svn = svn.strip()
    if "." in svn:
        parts = svn.split(".")
        try:
            return tuple(int(p) for p in parts)
        except ValueError:
            return (svn,)
    # Treat even-length hex strings of >= 4 chars as byte sequences
    if len(svn) >= 4 and len(svn) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in svn):
        try:
            return tuple(int(svn[i : i + 2], 16) for i in range(0, len(svn), 2))
        except ValueError:
            return (svn,)
    try:
        return (int(svn),)
    except ValueError:
        return (svn,)


def _is_attack_patched_by_svn(attack: TEEAttack, platform: Platform, tcb_version: str) -> bool:
    """Return True if the attack is patched for platform at the given TCB version."""
    if not attack.min_svn or platform not in attack.min_svn:
        return False
    try:
        return _parse_svn(tcb_version) >= _parse_svn(attack.min_svn[platform])
    except TypeError:
        # Incomparable formats -> conservative: not patched
        return False


# Comprehensive TEE attack database from academic literature (2016-2026)


def _load_attacks_from_json(path: Path | None = None) -> list[TEEAttack]:
    """Load attacks from the JSON source of truth (data/attacks/*.json).

    If ``path`` is omitted, searches ``data/attacks/`` next to this file
    (project root) and falls back to ``data/attacks.json`` aggregate.
    """
    if path is None:
        project_root = Path(__file__).resolve().parent.parent.parent
        attack_dir = project_root / "data" / "attacks"
        aggregate = project_root / "data" / "attacks.json"
    else:
        path = Path(path)
        if path.is_dir():
            attack_dir = path
            aggregate = path.parent / "attacks.json"
        else:
            attack_dir = path.parent / "attacks"
            aggregate = path

    records: list[dict] = []
    if attack_dir.exists():
        for file in sorted(attack_dir.glob("*.json")):
            records.append(json.loads(file.read_text()))
    elif aggregate.exists():
        data = json.loads(aggregate.read_text())
        records = data.get("attacks", [])

    attacks: list[TEEAttack] = []
    for rec in records:
        try:
            cat = AttackCategory(rec["category"])
        except (KeyError, ValueError):
            cat = AttackCategory.MEMORY_BUS
        try:
            diff = MitigationDifficulty(rec["mitigation_difficulty"])
        except (KeyError, ValueError):
            diff = MitigationDifficulty.NO_MITIGATION
        platforms = {Platform(p) for p in rec.get("affected_platforms", [])}
        cve_ids = rec.get("cve_ids") or []
        if not cve_ids and rec.get("cve_id"):
            cve_ids = [rec["cve_id"]]
        attacks.append(
            TEEAttack(
                name=rec["name"],
                year=rec["year"],
                affected_platforms=frozenset(platforms),
                category=cat,
                cost_to_attack=rec["cost_to_attack"],
                impact=rec["impact"],
                mitigation=rec["mitigation"],
                mitigation_difficulty=diff,
                cve_id=cve_ids[0] if cve_ids else None,
                cve_ids=cve_ids,
                paper_url=rec.get("paper_url"),
                boundary_statement=rec.get("boundary_statement", ""),
                patched=rec.get("patched", False),
                min_svn={Platform(k): v for k, v in rec.get("min_svn", {}).items()}
                if rec.get("min_svn")
                else None,
                compliance_controls=dict(rec.get("compliance_controls", {})),
                mapping_sources=dict(rec.get("mapping_sources", {})),
            )
        )
    return attacks


TEE_ATTACKS: list[TEEAttack] = _load_attacks_from_json()


def get_attacks_for_platform(platform: Platform) -> list[TEEAttack]:
    """Return attacks affecting a platform from the curated taxonomy.

    The archaeology DB's attack_records are the NVD-synced CVE feed for the
    temporal lag check; they are not the attack taxonomy and must not
    replace the curated list. The DB path previously swapped in generic
    NVD records, dropping curated attacks like Heckler and TEE.fail from
    the assessment.
    """
    return [a for a in TEE_ATTACKS if platform in a.affected_platforms]


def get_unmitigated_attacks(
    platform: Platform,
    tcb_version: str | None = None,
    firmware_patched: bool = False,
) -> list[TEEAttack]:
    """Return attacks applicable to a platform that have not been mitigated.

    Excludes attacks flagged ``patched=True`` in the archaeology DB.
    When ``tcb_version`` is provided, additionally excludes attacks whose
    per-platform ``min_svn`` threshold is met by the quoted TCB version.
    The legacy ``firmware_patched`` heuristic is used only when no
    ``tcb_version`` is supplied.
    """
    attacks = get_attacks_for_platform(platform)
    result: list[TEEAttack] = []
    for attack in attacks:
        if attack.patched:
            continue
        if tcb_version is not None and _is_attack_patched_by_svn(attack, platform, tcb_version):
            continue
        if firmware_patched and tcb_version is None:
            if attack.mitigation_difficulty in (
                MitigationDifficulty.FIRMWARE_PATCH,
                MitigationDifficulty.MICROCODE_UPDATE,
            ):
                continue
        result.append(attack)
    return result


def compute_attack_db_snapshot() -> str:
    """Compute a deterministic hash of the current TEE_ATTACKS list for freshness comparison."""
    """Return a SHA-256 hash of the current attack database state.

    The hash captures all attack names and their patched status. Any change
    (new attack, status update) produces a different digest, which lets a
    downstream freshness check determine whether an evidence bundle was
    evaluated against a different DB than the current one.
    """
    attacks = list(TEE_ATTACKS)
    entries = sorted((a.name, a.patched) for a in attacks)
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()


def get_attack_compliance_mappings(
    attacks: list[TEEAttack],
) -> list[tuple[str, str, str]]:
    """Return (framework, control_id, attack_name) tuples for mapped controls.

    ``compliance_controls`` is keyed by framework name (C5, SOC2, PCI_DSS)
    with a list of control IDs. The same control can be required by multiple
    attacks; callers deduplicate if needed.
    """
    mappings: list[tuple[str, str, str]] = []
    for attack in attacks:
        for framework, controls in attack.compliance_controls.items():
            for control_id in controls:
                mappings.append((framework, control_id, attack.name))
    return mappings


def compute_attack_risk(
    platforms: set[Platform], firmware_patched: bool = False
) -> tuple[str, list[TEEAttack]]:
    """Compute residual risk from TEE attacks.

    Returns:
        Tuple of (risk_statement, list_of_applicable_attacks)
    """
    applicable_attacks: list[TEEAttack] = []
    for platform in platforms:
        applicable_attacks.extend(
            get_unmitigated_attacks(platform, firmware_patched=firmware_patched)
        )

    if not applicable_attacks:
        return "", []

    risk_parts = []
    for attack in applicable_attacks:
        risk_parts.append(
            f"{attack.name} ({attack.year}): {attack.impact} "
            f"[Cost: {attack.cost_to_attack}, Mitigation: {attack.mitigation_difficulty.value}]"
        )

    return "\n".join(risk_parts), applicable_attacks
