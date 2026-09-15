"""Assurance level computation based on evidence graph analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, TypeAlias

from src.core.attacks import (
    MitigationDifficulty,
    TEEAttack,
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
    ThreatModelTier,
)
from src.verify import compute_provenance_dimension

# A threat scope is either a preset ThreatModelTier or a custom category set.
# Imported under TYPE_CHECKING to avoid a runtime circular import.
if TYPE_CHECKING:
    from src.core.threat_scope import CustomThreatScope

ThreatScope: TypeAlias = "ThreatModelTier | CustomThreatScope"

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

# Default threat model: software-only (matches the engine's stated boundary).
# The layer-set derivation lives in src/core/threat_scope.py.
DEFAULT_THREAT_MODEL = ThreatModelTier.CLOUD_ADMIN


def _attacks_in_threat_model(
    attacks: list[TEEAttack], threat_model: ThreatModelTier | "CustomThreatScope"
) -> list[TEEAttack]:
    """Filter attacks to those the threat scope can mount.

    For a preset tier the filter is by *adversary position*: an attack counts
    when every position it requires is granted by the model. That is what makes
    software-operator and cloud-admin differ — the host position is granted by
    one and not the other, so hypervisor-required attacks drop out under a
    model that declares the host trusted (docs/THREAT-MODELS.md).

    For a custom scope the filter remains by attack category, so a buyer can
    reason about mechanisms directly.

    Attacks with no position and no category are kept: unclassified attacks
    conservatively count under every model.
    """
    from src.core.threat_scope import (
        CustomThreatScope,
        categories_for_scope,
        positions_for_threat_model,
    )

    if isinstance(threat_model, CustomThreatScope):
        included = categories_for_scope(threat_model)
        return [a for a in attacks if a.category is None or a.category in included]

    granted = positions_for_threat_model(threat_model)
    return [
        a
        for a in attacks
        if not a.adversary_position or a.adversary_position.issubset(granted)
    ]


def _resolve_tcb_statuses(
    graph: EvidenceGraph, tcb_db_path: str | None = None, tcb_fmspc: str | None = None
) -> dict[str, TCBStatus]:
    """Resolve each platform's TCB status against a reference.

    Reference sources, in order: the explicit local reference DB (seeded
    archaeology DB), then the live vendor TCB lookup (Intel PCS v4, keyed by
    the platform FMSPC). When no reference is available the status is UNKNOWN
    (honest default; the mechanism never fabricates a reference). The DB path
    is explicit, never read from ambient global state.
    """
    from src.core.tcb import load_current_tcb_reference, resolve_tcb_status

    resolutions: dict[str, TCBStatus] = {}
    for node in graph.nodes.values():
        if node.node_type != NodeType.QUOTE or not node.platform:
            continue
        platform = node.platform.value
        if platform in resolutions:
            continue
        reference = None
        if tcb_db_path:
            reference = load_current_tcb_reference(platform, db_path=tcb_db_path)
        if reference is None:
            # Fall back to the live vendor lookup (Intel TDX only; AMD has no
            # public current-TCB endpoint). Requires the platform FMSPC.
            from src.tools.tcb_lookup import fetch_current_tcb

            fetched = fetch_current_tcb(node.platform, fmspc=tcb_fmspc)
            if fetched is not None:
                reference = fetched.version
        resolution = resolve_tcb_status(node.tcb_version, reference, platform=platform)
        resolutions[platform] = resolution.status
    return resolutions


def _known_attack_count(graph: EvidenceGraph) -> int:
    """Count known attacks for the platforms present in the graph.

    This is the coverage signal: how many attacks the engine knows about for
    the platform(s) under evaluation. A low count means the platform is less
    measured, not safer. Used to frame the boundary statement honestly.
    """
    from src.core.attacks import get_attacks_for_platform

    platforms = _platforms_in_graph(graph)
    known: set[str] = set()
    for p in platforms:
        for a in get_attacks_for_platform(p):
            known.add(a.name)
    return len(known)


# Platforms whose TCB is a firmware SVN (monotonic, comparable against a
# vendor reference). Nitro is the exception: its TCB is an image-identity
# digest, not an SVN, so the liveness comparison does not apply.
_NON_SVN_PLATFORMS = frozenset({Platform.AWSNitro})


def _is_svn_platform(platform: Platform) -> bool:
    return platform not in _NON_SVN_PLATFORMS


def _tcb_temporal_summary(
    graph: EvidenceGraph, tcb_db_path: str | None = None, tcb_fmspc: str | None = None
) -> str:
    """Report TCB liveness and patched-ness separately, per platform.

    Liveness: is the quoted TCB current vs the reference (local DB or live
    lookup). Patched-ness: how many known attacks the quoted TCB is patched
    against (quoted SVN >= the attack's fix threshold). Newness and patched
    status are different axes; both are reported.

    Non-SVN platforms (Nitro) get "not applicable": the temporal signal is
    measurement match, not firmware liveness.
    """
    from src.core.attacks import get_attacks_for_platform, get_unmitigated_attacks

    lines: list[str] = []
    resolutions = _resolve_tcb_statuses(graph, tcb_db_path=tcb_db_path, tcb_fmspc=tcb_fmspc)
    for node in graph.nodes.values():
        if node.node_type != NodeType.QUOTE or not node.platform:
            continue
        platform = node.platform
        if not _is_svn_platform(platform):
            lines.append(
                f"{platform.value}: TCB liveness not applicable (no SVN); "
                "temporal signal is measurement match"
            )
            continue
        status = resolutions.get(platform.value, TCBStatus.UNKNOWN)
        quoted = node.tcb_version or "unknown"
        # Patched-ness: unmitigated attacks given the quoted TCB version.
        unmitigated = get_unmitigated_attacks(platform, tcb_version=node.tcb_version)
        known = get_attacks_for_platform(platform)
        patched = len(known) - len(unmitigated)
        lines.append(
            f"{platform.value}: TCB {status.value} (quoted {quoted}); "
            f"patched against {patched} of {len(known)} known attacks"
        )
    return "\n".join(lines)


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
        attacks = get_unmitigated_attacks(
            platform, tcb_version=tcb_version, firmware_patched=firmware_patched
        )
        for attack in attacks:
            if attack.boundary_statement:
                boundaries.append(f"[{attack.name}] {attack.boundary_statement}")
    return boundaries


def _compute_residual_risk_from_attacks(
    graph: EvidenceGraph,
    base_risk: ResidualRiskTier,
    threat_model: ThreatScope = DEFAULT_THREAT_MODEL,
) -> tuple[ResidualRiskTier, list[TEEAttack]]:
    """Upgrade residual risk based on applicable software-applicable TEE attacks.

    Physical-layer attacks are excluded unless the threat model grants physical
    access. For the remaining software-applicable attacks, cost and mitigation
    difficulty determine risk escalation:
    - $10-$50 or unknown-cost attacks -> escalate by one tier
    - $1,000+ attacks (TEE.fail) or unknown cost -> escalates by one tier
    - Hardware redesign required -> escalates by one additional tier
    """
    applicable_attacks: list[TEEAttack] = []
    for platform in _platforms_in_graph(graph):
        tcb_version = _get_tcb_version_for_platform(graph, platform)
        firmware_patched = _check_firmware_patched(platform, tcb_version)
        applicable_attacks.extend(
            get_unmitigated_attacks(
                platform, tcb_version=tcb_version, firmware_patched=firmware_patched
            )
        )

    # Physical-layer attacks escalate residual risk only for threat models that
    # grant physical access; software-only threat models exclude them.
    applicable_attacks = _attacks_in_threat_model(applicable_attacks, threat_model)

    if not applicable_attacks:
        return base_risk, []

    _CHEAP_COST = frozenset({"~$10", "~$50"})
    has_cheap_attack = any(a.cost_to_attack in _CHEAP_COST for a in applicable_attacks)
    has_no_mitigation = any(
        a.mitigation_difficulty == MitigationDifficulty.NO_MITIGATION for a in applicable_attacks
    )
    has_hardware_redesign = any(
        a.mitigation_difficulty == MitigationDifficulty.HARDWARE_REDESIGN
        for a in applicable_attacks
    )

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
    threat_model: ThreatScope = DEFAULT_THREAT_MODEL,
    tcb_resolutions: dict[str, TCBStatus] | None = None,
) -> ScoreResult:
    """Compute a 0-100 composite score using a configurable profile.

    Dimensions are first scored on a 0-20 raw scale, then weighted by the
    active ScoreProfile. Subscores in ScoreResult are the weighted points.

    Physical-layer attacks are excluded from the threat/compliance dimensions
    when ``threat_model`` is software-only (the default), and included when the
    threat model grants physical access.
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
        platform_score = int(round((weighted["threat"] + weighted["compliance"]) / 40 * 100))
        quote_score = int(round(
            (weighted["attestation"] + weighted["trust"] + weighted["freshness"]) / 60 * 100
        ))
        return ScoreResult(
            total=total,
            subscores=weighted,
            grade=_grade_from_thresholds(total, profile.grade_thresholds),
            profile=profile.name,
            platform_score=platform_score,
            quote_score=quote_score,
        )

    trust = 0
    if quote_nodes and all(n.debug_disabled is True for n in quote_nodes):
        trust += 5
    # TCB liveness: use the resolved status (from the archaeology DB reference)
    # when available; fall back to the node's own status otherwise.
    resolutions = tcb_resolutions or {}
    tcb_current = True
    for n in quote_nodes:
        status = resolutions.get(n.platform.value) if n.platform else None
        if status is None:
            status = n.tcb_status
        if status not in (TCBStatus.CURRENT, None):
            tcb_current = False
            break
    if quote_nodes and tcb_current:
        trust += 5
    if any(n.node_type == NodeType.BUILD_PROVENANCE for n in all_nodes):
        trust += 5
    if assurance.dimensions.get("provenance") == "chained":
        trust += 5
    if len(platforms) >= 2:
        trust += 5
    trust = min(trust, 20)

    # Attacks that count against this threat model, derived from its layer set.
    software_attacks = _attacks_in_threat_model(applicable_attacks, threat_model)

    # Penalty scales by the attack's verified mitigation coverage: an attack
    # whose vectors are only partly mitigated counts as less than a whole one.
    # Unverified mitigation keeps coverage at 1.0 (docs/GRADING.md).
    threat = 20
    for attack in software_attacks:
        penalty = _COST_PENALTY.get(attack.cost_to_attack, 5) + _DIFFICULTY_PENALTY.get(
            attack.mitigation_difficulty, 5
        )
        threat -= round(penalty * attack.mitigation_coverage)
    threat = max(threat, 0)

    freshness_state = compute_temporal_freshness(graph)
    freshness = _FRESHNESS_SCORE.get(freshness_state, 0)

    # Compliance is framework-relative (2026-09-15): coverage over the C5
    # criteria attestation evidence can actually speak to (the technical
    # families). Organizational criteria — does a policy document exist, was a
    # human audit performed — are counted separately, never scored as gaps,
    # because a quote is not evidence about them. Falls back to the
    # attack→control ratio when the C5 control data is unavailable.
    from src.export.c5 import summarize_c5_coverage

    coverage = summarize_c5_coverage(graph)
    if coverage is not None:
        compliance = int(round(float(coverage["ratio"]) * 20))
    else:
        all_controls: set[tuple[str, str]] = set()
        gap_controls: set[tuple[str, str]] = set()
        for attack in software_attacks:
            for framework, controls in attack.compliance_controls.items():
                for control_id in controls:
                    pair = (framework, control_id)
                    all_controls.add(pair)
                    if not attack.patched:
                        gap_controls.add(pair)
        compliance = (
            20 if not all_controls else int(round((1 - len(gap_controls) / len(all_controls)) * 20))
        )

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

    # T1.2 platform-vs-quote split: the attack-DB-derived dimensions are the
    # platform's inherent attack surface; the quote-specific dimensions are
    # this attestation's state. Each side is normalized to 0-100.
    platform_raw = raw_subscores["threat"] + raw_subscores["compliance"]
    quote_raw = (
        raw_subscores["attestation"]
        + raw_subscores["trust"]
        + raw_subscores["freshness"]
    )
    platform_score = int(round(platform_raw / 40 * 100))
    quote_score = int(round(quote_raw / 60 * 100))

    grade = _grade_from_thresholds(total, profile.grade_thresholds)

    return ScoreResult(
        total=total,
        subscores=weighted,
        grade=grade,
        profile=profile.name,
        platform_score=platform_score,
        quote_score=quote_score,
        compliance_coverage=coverage,
    )


def compute_temporal_freshness(
    graph: EvidenceGraph, default_ttl: int = _DEFAULT_TTL_SECONDS
) -> TemporalFreshness:
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
    threat_model: ThreatScope = DEFAULT_THREAT_MODEL,
    tcb_db_path: str | None = None,
    tcb_fmspc: str | None = None,
) -> AssuranceEvaluation:
    """Evaluate the evidence graph and derive an assurance level (0-5) with residual risk tier.

    ``threat_model`` selects which attacks count: software-only models exclude
    physical-layer attacks; physical-capable models include them. The same
    evidence can grade differently per threat model.
    """
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
    _all_firmware_current(graph)
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

    residual_risk, applicable_attacks = _compute_residual_risk_from_attacks(
        graph, residual_risk, threat_model=threat_model
    )

    attack_boundaries = _collect_attack_boundaries(graph)
    if attack_boundaries:
        boundary += "\n\nKnown unmitigated attacks:\n" + "\n".join(
            f"- {b}" for b in attack_boundaries
        )

    # Coverage signal: how many known attacks the engine grades against for the
    # platform(s) under evaluation. A low count means less measured, not safer.
    known_count = _known_attack_count(graph)
    if known_count:
        boundary += (
            f"\n\nGraded against {known_count} known attack(s) for the platform(s) "
            "under evaluation; undisclosed vulnerabilities cannot be detected from a quote."
        )

    # TCB temporal summary: liveness and patched-ness reported separately.
    temporal = _tcb_temporal_summary(graph, tcb_db_path=tcb_db_path, tcb_fmspc=tcb_fmspc)
    if temporal:
        boundary += "\n\n" + temporal

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
    score = compute_numeric_score(
        graph,
        evaluation,
        applicable_attacks,
        score_profile=score_profile,
        threat_model=threat_model,
        tcb_resolutions=_resolve_tcb_statuses(graph, tcb_db_path=tcb_db_path, tcb_fmspc=tcb_fmspc),
    )
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
