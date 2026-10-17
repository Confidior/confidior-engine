"""The 0-100 composite score: profiles, per-dimension points, grade.

Split out of ``risk.py`` (docs/CODEBASE-REVIEW-2026-10-03.md gap 4) -- the module
the review called "the scoring function small enough to encode", so a ZK circuit
can mirror it. Depends on ``binding``, ``freshness`` and ``residual``."""

from __future__ import annotations

from src.core.attacks import (
    MitigationDifficulty,
    TEEAttack,
)
from src.core.binding import (
    has_verified_cross_platform_binding,
)
from src.core.freshness import (
    _FRESHNESS_SCORE,
    compute_temporal_freshness,
)
from src.core.residual import (
    DEFAULT_THREAT_MODEL,
    ThreatScope,
    _attacks_in_threat_model,
    weakest_evidence_class,
)
from src.core.taxonomy import (
    AssuranceEvaluation,
    EvidenceClass,
    EvidenceGraph,
    NodeType,
    ScoreProfile,
    ScoreResult,
    ScoringAttack,
    TCBStatus,
)

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

#: Threat-dimension half-life in raw penalty points. The dimension is
#: ``20 * H / (H + raw_penalty)`` so it is strictly decreasing in the penalty
#: and bounded by 20, which keeps the weighted sum in range while preserving
#: the ordering between threat models that a hard clamp at zero discards.
_THREAT_HALF_LIFE = 20


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
    # Platform diversity (2026-09-15): a second platform corroborates only when
    # the two attestations are bound to the same session. Counting platforms
    # alone credited an unrelated quote from another platform.
    platforms_bound = has_verified_cross_platform_binding(graph)
    if platforms_bound:
        trust += 5
    # Evidence class (2026-09-15): a verdict is only as strong as the weakest
    # evidence it rests on. Independently derived golden values, or runtime
    # evidence anchored into the TEE's extend-only registers, add confidence in
    # the chain itself; weaker classes (point-in-time reports, vendor-published
    # values) add nothing here and are reported for what they are.
    evidence_class = weakest_evidence_class(graph)
    if evidence_class in (EvidenceClass.COMPUTED_GOLDEN, EvidenceClass.RUNTIME_ANCHORED):
        trust += 5
    trust = min(trust, 20)

    # Attacks that count against this threat model, derived from its layer set.
    software_attacks = _attacks_in_threat_model(applicable_attacks, threat_model)

    # Penalty scales by the attack's verified mitigation coverage: an attack
    # whose vectors are only partly mitigated counts as less than a whole one.
    # Unverified mitigation keeps coverage at 1.0 (docs/GRADING.md).
    #
    # The dimension saturates rather than clamping at zero (docs/GRADING.md,
    # "Why the threat dimension saturates"). A hard clamp throws away the
    # ordering between two threat models once both exceed the 20-point range,
    # which silently turns "grades differently per threat model" into "grades
    # the same". The curve is strictly decreasing, so a heavier penalty always
    # scores lower, and it is bounded by 20 so the weighted sum still holds.
    raw_penalty = 0
    scored_attacks: list[ScoringAttack] = []
    for attack in software_attacks:
        penalty = _COST_PENALTY.get(attack.cost_to_attack, 5) + _DIFFICULTY_PENALTY.get(
            attack.mitigation_difficulty, 5
        )
        applied = round(penalty * attack.mitigation_coverage)
        raw_penalty += applied
        scored_attacks.append(
            ScoringAttack(
                name=attack.name,
                # Where the attacker must stand; the attack only applied because
                # the threat model grants every position it requires.
                position=attack.adversary_position_label,
                coverage=attack.mitigation_coverage,
                penalty=applied,
                cve_ids=tuple(attack.cve_ids),
            )
        )
    # 20 / (1 + raw/20): no in-scope attacks -> 20 (full marks), raw == 20 ->
    # 10, and the value approaches 0 as the penalty grows without ever
    # reaching it, so ordering is preserved at every level.
    threat = (20 * _THREAT_HALF_LIFE) / (_THREAT_HALF_LIFE + raw_penalty)

    freshness_state = compute_temporal_freshness(graph)
    freshness = _FRESHNESS_SCORE.get(freshness_state, 0)

    # Compliance is framework-relative (2026-09-15): coverage over the C5
    # criteria attestation evidence can actually speak to (the technical
    # families). Organizational criteria: does a policy document exist, was a
    # human audit performed: are counted separately, never scored as gaps,
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
        evidence_class=weakest_evidence_class(graph),
        scoring_attacks=tuple(scored_attacks),
        platform_count=len(platforms),
        platforms_bound=platforms_bound,
    )
