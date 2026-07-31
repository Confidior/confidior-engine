"""Assurance level computation based on evidence graph analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from src.core.attacks import (
    MitigationDifficulty,
    TEEAttack,
    get_attack_compliance_mappings,
    get_unmitigated_attacks,
)
from src.core.taxonomy import (
    TEE_FAIL_BOUNDARY_STATEMENT,
    AssuranceEvaluation,
    AssuranceLevel,
    EvidenceGraph,
    NodeType,
    Platform,
    ResidualRiskTier,
    ScoreProfile,
    ScoreResult,
    TCBStatus,
    TemporalFreshness,
)
from src.verify import compute_provenance_dimension

_ARCHAEOLOGY_DB_PATH: Path | None = None


def set_archaeology_db_path(path: str | Path) -> None:
    global _ARCHAEOLOGY_DB_PATH
    _ARCHAEOLOGY_DB_PATH = Path(path)
    # Keep the attack DB path in sync so per-attack SVN filtering uses the same source.
    from src.core.attacks import set_attacks_db_path
    set_attacks_db_path(path)

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


def _check_firmware_patched(platform: Platform, tcb_version: str | None = None) -> bool:
    """Check whether the quoted firmware level patches all known firmware-fixable attacks.

    Uses per-attack ``min_svn`` thresholds when ``tcb_version`` is supplied.
    Falls back to the archaeology DB ``patched`` flags otherwise.
    If DB is unavailable, returns False (conservative assumption).
    """
    if _ARCHAEOLOGY_DB_PATH is None or not _ARCHAEOLOGY_DB_PATH.exists():
        return False
    try:
        unpatched = get_unmitigated_attacks(platform, tcb_version=tcb_version)
        return len(unpatched) == 0
    except Exception:
        return False


def _get_tcb_version_for_platform(graph: EvidenceGraph, platform: Platform) -> str | None:
    """Return the TCB version reported by a QUOTE node for the given platform."""
    for node in graph.nodes.values():
        if node.node_type == NodeType.QUOTE and node.platform == platform:
            return node.tcb_version
    return None


def _collect_attack_boundaries(graph: EvidenceGraph) -> list[str]:
    """Collect boundary statements from all applicable TEE attacks."""
    boundaries = []
    for platform in _platforms_in_graph(graph):
        tcb_version = _get_tcb_version_for_platform(graph, platform)
        firmware_patched = _check_firmware_patched(platform, tcb_version)
        attacks = get_unmitigated_attacks(platform, tcb_version=tcb_version, firmware_patched=firmware_patched)
        for attack in attacks:
            if attack.boundary_statement:
                boundaries.append(f"[{attack.name}] {attack.boundary_statement}")
    return boundaries


def _compute_residual_risk_from_attacks(
    graph: EvidenceGraph,
    base_risk: ResidualRiskTier,
) -> tuple[ResidualRiskTier, list[TEEAttack]]:
    """Upgrade residual risk based on applicable TEE attacks.

    Attack cost and mitigation difficulty determine risk escalation:
    - $10-$50 attacks (BadRAM, Battering Ram) -> CRITICAL if unmitigated
    - $1,000+ attacks (TEE.fail) or unknown cost -> escalates by one tier
    - Hardware redesign required -> escalates by one additional tier
    """
    applicable_attacks: list[TEEAttack] = []
    for platform in _platforms_in_graph(graph):
        tcb_version = _get_tcb_version_for_platform(graph, platform)
        firmware_patched = _check_firmware_patched(platform, tcb_version)
        applicable_attacks.extend(
            get_unmitigated_attacks(platform, tcb_version=tcb_version, firmware_patched=firmware_patched)
        )

    if not applicable_attacks:
        return base_risk, []

    _CHEAP_COST = frozenset({"~$10", "~$50"})
    has_cheap_attack = any(a.cost_to_attack in _CHEAP_COST for a in applicable_attacks)
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


_DEFAULT_TTL_SECONDS = 1800  # 30 minutes

_COST_PENALTY = {
    "~$10": 10,
    "~$50": 8,
    "~$1,000": 4,
    "Unknown": 5,
}

_DIFFICULTY_PENALTY = {
    MitigationDifficulty.NO_MITIGATION: 10,
    MitigationDifficulty.HARDWARE_REDESIGN: 6,
    MitigationDifficulty.FIRMWARE_PATCH: 2,
    MitigationDifficulty.MICROCODE_UPDATE: 2,
    MitigationDifficulty.SOFTWARE_FIX: 1,
}

_FRESHNESS_SCORE = {
    TemporalFreshness.FRESH: 20,
    TemporalFreshness.AGING: 12,
    TemporalFreshness.STALE: 0,
}

_SCORE_PROFILES: dict[str, ScoreProfile] = {
    "default": ScoreProfile(
        name="default",
        weights={
            "attestation": 20,
            "trust": 20,
            "threat": 20,
            "freshness": 20,
            "compliance": 20,
        },
        grade_thresholds={"A": 90, "B": 75, "C": 60, "D": 45},
    ),
    "finance": ScoreProfile(
        name="finance",
        weights={
            "attestation": 15,
            "trust": 25,
            "freshness": 25,
            "compliance": 20,
            "threat": 15,
        },
        grade_thresholds={"A": 92, "B": 80, "C": 65, "D": 50},
    ),
    "gpu-tee": ScoreProfile(
        name="gpu-tee",
        weights={
            "attestation": 15,
            "trust": 25,
            "threat": 25,
            "freshness": 20,
            "compliance": 15,
        },
        grade_thresholds={"A": 88, "B": 75, "C": 60, "D": 45},
    ),
}


def _get_score_profile(profile: str) -> ScoreProfile:
    if profile not in _SCORE_PROFILES:
        return _SCORE_PROFILES["default"]
    return _SCORE_PROFILES[profile]


def _apply_profile(raw_subscores: dict[str, int], profile: ScoreProfile) -> dict[str, int]:
    weighted: dict[str, int] = {}
    for dim, raw in raw_subscores.items():
        weight = profile.weights.get(dim, 20)
        weighted[dim] = int(round(raw / 20 * weight))
    return weighted


def _grade_from_thresholds(total: int, thresholds: dict[str, int]) -> str:
    if total >= thresholds["A"]:
        return "A"
    if total >= thresholds["B"]:
        return "B"
    if total >= thresholds["C"]:
        return "C"
    if total >= thresholds["D"]:
        return "D"
    return "F"


def compute_numeric_score(
    graph: EvidenceGraph,
    assurance: AssuranceEvaluation,
    applicable_attacks: list[TEEAttack],
    score_profile: str = "default",
) -> ScoreResult:
    """Compute a 0-100 composite score using a configurable profile.

    Dimensions are first scored on a 0-20 raw scale, then weighted by the
    active ScoreProfile. Subscores in ScoreResult are the weighted points.
    """
    profile = _get_score_profile(score_profile)

    attestation = min(assurance.level.value * 4, 20)

    quote_nodes = [n for n in graph.nodes.values() if n.node_type == NodeType.QUOTE]
    platforms = {n.platform for n in quote_nodes if n.platform}
    all_nodes = list(graph.nodes.values())

    if not quote_nodes:
        # No attestation evidence: dimensions other than the explicit level are unknown.
        weighted = _apply_profile({"attestation": attestation}, profile)
        weighted.update({dim: 0 for dim in ("trust", "threat", "freshness", "compliance")})
        total = sum(weighted.values())
        return ScoreResult(
            total=total,
            subscores=weighted,
            grade=_grade_from_thresholds(total, profile.grade_thresholds),
            profile=profile.name,
        )

    trust = 0
    if quote_nodes and all(n.debug_disabled is True for n in quote_nodes):
        trust += 5
    if quote_nodes and all(n.tcb_status in (TCBStatus.CURRENT, None) for n in quote_nodes):
        trust += 5
    if any(n.node_type == NodeType.BUILD_PROVENANCE for n in all_nodes):
        trust += 5
    if assurance.dimensions.get("provenance") == "chained":
        trust += 5
    if len(platforms) >= 2:
        trust += 5
    trust = min(trust, 20)

    threat = 20
    for attack in applicable_attacks:
        threat -= _COST_PENALTY.get(attack.cost_to_attack, 5)
        threat -= _DIFFICULTY_PENALTY.get(attack.mitigation_difficulty, 5)
    threat = max(threat, 0)

    freshness_state = compute_temporal_freshness(graph)
    freshness = _FRESHNESS_SCORE.get(freshness_state, 0)

    all_controls: set[tuple[str, str]] = set()
    gap_controls: set[tuple[str, str]] = set()
    for attack in applicable_attacks:
        for framework, controls in attack.compliance_controls.items():
            for control_id in controls:
                pair = (framework, control_id)
                all_controls.add(pair)
                if not attack.patched:
                    gap_controls.add(pair)
    compliance = 20 if not all_controls else int(round((1 - len(gap_controls) / len(all_controls)) * 20))

    raw_subscores = {
        "attestation": attestation,
        "trust": trust,
        "threat": threat,
        "freshness": freshness,
        "compliance": compliance,
    }
    weighted = _apply_profile(raw_subscores, profile)
    total = sum(weighted.values())
    total = max(0, min(100, total))

    grade = _grade_from_thresholds(total, profile.grade_thresholds)

    return ScoreResult(
        total=total,
        subscores=weighted,
        grade=grade,
        profile=profile.name,
    )


def compute_temporal_freshness(graph: EvidenceGraph, default_ttl: int = _DEFAULT_TTL_SECONDS) -> TemporalFreshness:
    """Evaluate evidence freshness based on node timestamps and TTLs.

    Returns FRESH (all nodes within TTL), AGING (some past 80% TTL),
    or STALE (any node past TTL). Nodes without timestamps are skipped.
    """
    now = datetime.now(timezone.utc)
    has_aging = False
    for node in graph.nodes.values():
        ts = node.timestamp
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        ttl = node.ttl_seconds if node.ttl_seconds is not None else default_ttl
        age = (now - ts).total_seconds()
        if age >= ttl:
            return TemporalFreshness.STALE
        if age >= ttl * 0.8:
            has_aging = True
    if has_aging:
        return TemporalFreshness.AGING
    return TemporalFreshness.FRESH


def compute_assurance_level(
    graph: EvidenceGraph,
    score_profile: str = "default",
) -> AssuranceEvaluation:
    """Evaluate the evidence graph and derive an assurance level (0-5) with residual risk tier."""
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
    provenance_dim = compute_provenance_dimension(graph)

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
    if provenance_dim == "chained" and level == AssuranceLevel.OPERATIONAL_ASSURANCE:
        boundary += "\nIaC provenance is chained to the workload measurement."

    residual_risk, applicable_attacks = _compute_residual_risk_from_attacks(graph, residual_risk)

    attack_boundaries = _collect_attack_boundaries(graph)
    if attack_boundaries:
        boundary += "\n\nKnown unmitigated attacks:\n" + "\n".join(f"- {b}" for b in attack_boundaries)

    temporal_freshness = compute_temporal_freshness(graph)
    evaluation = AssuranceEvaluation(
        level=level,
        residual_risk=residual_risk,
        boundary_statement=boundary,
        label=_LEVEL_LABELS[level],
        temporal_freshness=temporal_freshness,
        dimensions={"provenance": provenance_dim},
        score_profile=score_profile,
    )
    score = compute_numeric_score(graph, evaluation, applicable_attacks, score_profile=score_profile)
    # ``evaluation`` is frozen; construct a new instance with the score attached.
    return AssuranceEvaluation(
        level=evaluation.level,
        residual_risk=evaluation.residual_risk,
        boundary_statement=evaluation.boundary_statement,
        label=evaluation.label,
        temporal_freshness=evaluation.temporal_freshness,
        dimensions=dict(evaluation.dimensions),
        score=score,
        score_profile=score_profile,
    )
