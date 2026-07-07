from __future__ import annotations

from pathlib import Path

from src.core.taxonomy import (
    AssuranceEvaluation,
    AssuranceLevel,
    EvidenceGraph,
    NodeType,
    Platform,
    ResidualRiskTier,
    TCBStatus,
    TEE_FAIL_BOUNDARY_STATEMENT,
)
from src.core.attacks import (
    TEEAttack,
    MitigationDifficulty,
    get_attacks_for_platform,
    get_unmitigated_attacks,
)

_ARCHAEOLOGY_DB_PATH: Path | None = None


def set_archaeology_db_path(path: str | Path) -> None:
    global _ARCHAEOLOGY_DB_PATH
    _ARCHAEOLOGY_DB_PATH = Path(path)

_SINGLE_VENDOR_CLOUD_TEES = {
    Platform.IntelTDX,
    Platform.AMDSEVSNP,
    Platform.AWSNitro,
    Platform.ApplePCC,
}

_LEVEL_LABELS = {
    AssuranceLevel.NONE: "Level 0 | None",
    AssuranceLevel.CONFIG_VERIFIED: "Level 1 | Config-Verified",
    AssuranceLevel.HARDWARE_ATTESTED: "Level 2 | Hardware-Attested",
    AssuranceLevel.OPERATIONAL_ASSURANCE: "Level 3 | Operational Assurance",
    AssuranceLevel.DISTRIBUTED_TRUST: "Level 4 | Distributed Trust",
    AssuranceLevel.CRYPTOGRAPHIC_PRIVACY: "Level 5 | Cryptographic Privacy",
}


def _has_quote_for_platform(graph: EvidenceGraph, platform: Platform) -> bool:
    for node in graph.nodes.values():
        if node.node_type == NodeType.QUOTE and node.platform == platform:
            return True
    return False


def _all_quotes_debug_disabled(graph: EvidenceGraph) -> bool:
    for node in graph.nodes.values():
        if node.node_type == NodeType.QUOTE:
            if node.debug_disabled is not True:
                return False
    return True


def _all_firmware_current(graph: EvidenceGraph) -> bool:
    for node in graph.nodes.values():
        if node.node_type == NodeType.QUOTE:
            if node.tcb_status not in (TCBStatus.CURRENT, None):
                return False
    return True


def _has_build_provenance(graph: EvidenceGraph) -> bool:
    for node in graph.nodes.values():
        if node.node_type == NodeType.BUILD_PROVENANCE:
            return True
    return False


def _platforms_in_graph(graph: EvidenceGraph) -> set[Platform]:
    platforms = set()
    for node in graph.nodes.values():
        if node.node_type == NodeType.QUOTE and node.platform is not None:
            platforms.add(node.platform)
    return platforms


def _check_firmware_patched(platform: Platform) -> bool:
    """Check if firmware patches are applied for known attacks.

    Queries the archaeology DB's attack_records table.
    If DB is unavailable, returns False (conservative assumption).
    """
    if _ARCHAEOLOGY_DB_PATH is None or not _ARCHAEOLOGY_DB_PATH.exists():
        return False
    try:
        from src.tools.archaeology import ArchaeologyDB
        db = ArchaeologyDB(db_path=_ARCHAEOLOGY_DB_PATH)
        unpatched = db.query_attacks(platform=platform, unpatched_only=True)
        db.close()
        return len(unpatched) == 0
    except Exception:
        return False


def _collect_attack_boundaries(platforms: set[Platform]) -> list[str]:
    """Collect boundary statements from all applicable TEE attacks."""
    boundaries = []
    for platform in platforms:
        firmware_patched = _check_firmware_patched(platform)
        attacks = get_unmitigated_attacks(platform, firmware_patched)
        for attack in attacks:
            if attack.boundary_statement:
                boundaries.append(f"[{attack.name}] {attack.boundary_statement}")
    return boundaries


def _compute_residual_risk_from_attacks(
    platforms: set[Platform],
    base_risk: ResidualRiskTier,
) -> tuple[ResidualRiskTier, list[TEEAttack]]:
    """Upgrade residual risk based on applicable TEE attacks.

    Attack cost and mitigation difficulty determine risk escalation:
    - $10 attacks (BadRAM) -> CRITICAL if unmitigated
    - $50-$1,000 attacks (TEE.fail, Battering RAM) -> HIGH if unmitigated
    - Unknown cost attacks -> escalate by one tier
    """
    applicable_attacks: list[TEEAttack] = []
    for platform in platforms:
        firmware_patched = _check_firmware_patched(platform)
        applicable_attacks.extend(get_unmitigated_attacks(platform, firmware_patched))

    if not applicable_attacks:
        return base_risk, []

    has_cheap_attack = any(a.cost_to_attack.startswith("~$1") or a.cost_to_attack.startswith("~$5") or a.cost_to_attack.startswith("~$10") or a.cost_to_attack.startswith("~$50") for a in applicable_attacks)
    has_no_mitigation = any(a.mitigation_difficulty == MitigationDifficulty.NO_MITIGATION for a in applicable_attacks)
    has_hardware_redesign = any(a.mitigation_difficulty == MitigationDifficulty.HARDWARE_REDESIGN for a in applicable_attacks)

    if has_cheap_attack or has_no_mitigation:
        return ResidualRiskTier.CRITICAL, applicable_attacks

    if has_hardware_redesign:
        if base_risk == ResidualRiskTier.LOW:
            return ResidualRiskTier.MEDIUM, applicable_attacks
        elif base_risk == ResidualRiskTier.MEDIUM:
            return ResidualRiskTier.HIGH, applicable_attacks
        else:
            return ResidualRiskTier.CRITICAL, applicable_attacks

    if base_risk == ResidualRiskTier.LOW:
        return ResidualRiskTier.MEDIUM, applicable_attacks

    return base_risk, applicable_attacks


def compute_assurance_level(graph: EvidenceGraph) -> AssuranceEvaluation:
    platforms = _platforms_in_graph(graph)
    single_vendor_cloud = platforms & _SINGLE_VENDOR_CLOUD_TEES

    if not platforms:
        return AssuranceEvaluation(
            level=AssuranceLevel.NONE,
            residual_risk=ResidualRiskTier.HIGH,
            boundary_statement="No attestation evidence provided.",
            label=_LEVEL_LABELS[AssuranceLevel.NONE],
        )

    has_quote = any(_has_quote_for_platform(graph, p) for p in platforms)
    debug_ok = _all_quotes_debug_disabled(graph)
    firmware_ok = _all_firmware_current(graph)
    has_build_prov = _has_build_provenance(graph)

    if has_quote and debug_ok:
        if len(platforms) >= 2 and has_build_prov:
            level = AssuranceLevel.DISTRIBUTED_TRUST
            residual_risk = ResidualRiskTier.MEDIUM
            boundary = "Multiple independent hardware roots with build provenance."
        elif single_vendor_cloud:
            level = AssuranceLevel.HARDWARE_ATTESTED
            residual_risk = ResidualRiskTier.HIGH
            boundary = TEE_FAIL_BOUNDARY_STATEMENT
        else:
            level = AssuranceLevel.HARDWARE_ATTESTED
            residual_risk = ResidualRiskTier.HIGH
            boundary = TEE_FAIL_BOUNDARY_STATEMENT
    elif has_quote and not debug_ok:
        level = AssuranceLevel.CONFIG_VERIFIED
        residual_risk = ResidualRiskTier.HIGH
        boundary = "Debug mode enabled; hardware quote not trusted."
    else:
        level = AssuranceLevel.CONFIG_VERIFIED
        residual_risk = ResidualRiskTier.HIGH
        boundary = "Cloud API configuration only; no hardware quote parsed."

    if has_build_prov and level == AssuranceLevel.HARDWARE_ATTESTED:
        level = AssuranceLevel.OPERATIONAL_ASSURANCE
        residual_risk = ResidualRiskTier.MEDIUM
        boundary = "Hardware attestation with build provenance and operational controls."

    residual_risk, applicable_attacks = _compute_residual_risk_from_attacks(platforms, residual_risk)

    attack_boundaries = _collect_attack_boundaries(platforms)
    if attack_boundaries:
        boundary += "\n\nKnown unmitigated attacks:\n" + "\n".join(f"- {b}" for b in attack_boundaries)

    return AssuranceEvaluation(
        level=level,
        residual_risk=residual_risk,
        boundary_statement=boundary,
        label=_LEVEL_LABELS[level],
    )
