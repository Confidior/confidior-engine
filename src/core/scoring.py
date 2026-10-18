"""The 0-100 composite score: profiles, per-dimension points, grade.

Split out of ``risk.py`` (docs/CODEBASE-REVIEW-2026-10-03.md gap 4) -- the module
the review called "the scoring function small enough to encode", so a ZK circuit
can mirror it. Depends on ``binding``, ``freshness`` and ``residual``."""

from __future__ import annotations

from typing import Any

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


def _apply_profile(raw_subscores: dict[str, float], profile: ScoreProfile) -> dict[str, int]:
    """Each dimension's 0-20 raw points as that dimension's weighted points."""
    weighted: dict[str, int] = {}
    for dim, raw in raw_subscores.items():
        weight = profile.weights.get(dim, 20)
        weighted[dim] = int(round(raw / 20 * weight))
    return weighted


def _renormalized_total(weighted: dict[str, int], profile: ScoreProfile) -> int:
    """The weighted sum, rescaled to 0-100 over the dimensions that exist.

    A dimension the evidence could not speak to is absent rather than
    credited or charged: scoring it full marks would reward silence, and
    scoring it zero would punish evidence for a question it was never asked.
    With every dimension present the weights sum to 100 and this is the plain
    weighted sum.
    """
    present_weight = sum(profile.weights.get(dim, 20) for dim in weighted) or 100
    return max(0, min(100, int(round(sum(weighted.values()) * 100 / present_weight))))


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
    policy_conformance: dict[str, Any] | None = None,
) -> ScoreResult:
    """Compute a 0-100 composite score using a configurable profile.

    Dimensions are first scored on a 0-20 raw scale, then weighted by the
    active ScoreProfile. Subscores in ScoreResult are the weighted points.

    Physical-layer attacks are excluded from the threat dimension when
    ``threat_model`` is software-only (the default), and included when the
    threat model grants physical access.

    ``policy_conformance`` is the severity-weighted share of the policy the
    evidence satisfies (``src.core.policy.policy_conformance``). It drives the
    ``compliance`` subscore, which measures policy conformance rather than
    framework coverage. ``None`` means no policy was evaluated.
    """
    profile = _get_score_profile(score_profile)

    attestation = min(assurance.level.value * 4, 20)

    quote_nodes = [n for n in graph.nodes.values() if n.node_type == NodeType.QUOTE]
    platforms = {n.platform for n in quote_nodes if n.platform}
    all_nodes = list(graph.nodes.values())

    if not quote_nodes:
        # No attestation evidence: every dimension except the explicit level is
        # unknown, so only the level is scored and the total is a share of the
        # weight that dimension carries.
        weighted = _apply_profile({"attestation": attestation}, profile)
        weighted.update({dim: 0 for dim in ("trust", "threat", "freshness", "compliance")})
        total = _renormalized_total(weighted, profile)
        platform_score = 0
        quote_score = int(round(attestation / 20 * 100))
        return ScoreResult(
            total=total,
            subscores=weighted,
            grade=_grade_from_thresholds(total, profile.grade_thresholds),
            profile=profile.name,
            platform_score=platform_score,
            quote_score=quote_score,
            policy_conformance=policy_conformance,
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

    # Policy conformance replaced the framework-compliance dimension on
    # 2026-10-18. The old dimension measured coverage over a framework's
    # checklist, most of which a quote cannot speak to: 20% of the grade moved
    # on a hand-written table of control rules that mostly returned "no rule
    # defined". The replacement asks the question the evidence can answer: how
    # much of the policy this evidence is actually judged against does it
    # satisfy, weighted by rule severity. A policy's important rules move the
    # number more than its advisory ones, and a rule that could not be decided
    # earns no credit.
    raw_subscores: dict[str, float] = {
        "attestation": attestation,
        "trust": trust,
        "threat": threat,
        "freshness": freshness,
    }
    # Without a policy the dimension is absent, not perfect. Crediting it would
    # raise every grade the moment no policy was supplied, which is the
    # opposite of what honest grading means.
    if policy_conformance is not None:
        raw_subscores["compliance"] = int(round(float(policy_conformance["ratio"]) * 20))
    weighted = _apply_profile(raw_subscores, profile)
    total = _renormalized_total(weighted, profile)

    # T1.2 platform-vs-quote split: the attack-database dimension is the
    # platform's inherent attack surface; the rest describe this evidence.
    # Policy conformance moved to the quote side on 2026-10-18: a framework's
    # coverage was a property of the platform (the same control data applied to
    # every quote), but whether this evidence satisfies the policy is a
    # property of the evidence, like attestation. Each side is normalized to
    # 0-100 over its own total.
    quote_dims = ("attestation", "trust", "freshness", "compliance")
    quote_present = [dim for dim in quote_dims if dim in raw_subscores]
    platform_score = int(round(raw_subscores["threat"] / 20 * 100))
    quote_score = int(round(
        sum(raw_subscores[dim] for dim in quote_present) / (20 * len(quote_present)) * 100
    ))

    grade = _grade_from_thresholds(total, profile.grade_thresholds)

    return ScoreResult(
        total=total,
        subscores=weighted,
        grade=grade,
        profile=profile.name,
        platform_score=platform_score,
        quote_score=quote_score,
        policy_conformance=policy_conformance,
        evidence_class=weakest_evidence_class(graph),
        scoring_attacks=tuple(scored_attacks),
        platform_count=len(platforms),
        platforms_bound=platforms_bound,
    )
