"""Assurance level (0-5), boundary statement, and the composed evaluation.

Split out of ``risk.py`` (docs/CODEBASE-REVIEW-2026-10-03.md gap 4). The top of the
package: it assembles the level, the boundary statement and the score."""

from __future__ import annotations

from typing import Any

from src.core.binding import (
    _platforms_in_graph,
    has_verified_cross_platform_binding,
)
from src.core.freshness import (
    compute_temporal_freshness,
)
from src.core.residual import (
    DEFAULT_THREAT_MODEL,
    ThreatScope,
    _collect_attack_boundaries,
    _collect_out_of_scope_attack_names,
    _compute_residual_risk_from_attacks,
    _known_attack_count,
    _resolve_tcb_statuses,
    _tcb_temporal_summary,
)
from src.core.scoring import (
    compute_numeric_score,
)
from src.core.taxonomy import (
    TEE_FAIL_BOUNDARY_STATEMENT,
    AssuranceEvaluation,
    AssuranceLevel,
    EvidenceGraph,
    NodeType,
    Platform,
    ResidualRiskTier,
    TCBStatus,
)
from src.verify import (
    compute_provenance_dimension,
)

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


def _scope_assumptions(scope) -> list[str]:
    """Standing exclusions declared by the scope, in structured form.

    The prose boundary statement already says these; this is the same claim in
    a shape a re-grader can act on. Derived from the scope rather than a
    hardcoded table, so a scope the engine has never seen reports its own
    exclusions instead of inheriting a preset's.
    """
    from src.core.threat_scope import (
        PHYSICAL_LAYER_CATEGORIES,
        categories_for_scope,
        positions_for_scope,
    )

    assumptions: list[str] = []
    included = categories_for_scope(scope)
    if not PHYSICAL_LAYER_CATEGORIES & included:
        assumptions.append(
            "physical DRAM interposition excluded (no physical-layer attack in scope)"
        )
    if not any(p.value == "supply_chain" for p in positions_for_scope(scope)):
        assumptions.append("supply-chain adversary not granted by this scope")
    return assumptions


def _has_build_provenance(graph: EvidenceGraph) -> bool:
    for node in graph.nodes.values():
        if node.node_type == NodeType.BUILD_PROVENANCE:
            return True
    return False


def compute_assurance_level(
    graph: EvidenceGraph,
    score_profile: str = "default",
    threat_model: ThreatScope = DEFAULT_THREAT_MODEL,
    tcb_db_path: str | None = None,
    tcb_fmspc: str | None = None,
    policy_conformance: dict[str, Any] | None = None,
) -> AssuranceEvaluation:
    """Evaluate the evidence graph and derive an assurance level (0-5) with residual risk tier.

    ``threat_model`` selects which attacks count: software-only models exclude
    physical-layer attacks; physical-capable models include them. The same
    evidence can grade differently per threat model.

    ``policy_conformance`` is the severity-weighted share of the policy the
    evidence satisfies, and drives the score's ``compliance`` dimension. Pass
    None when no policy was evaluated; the dimension then records nothing
    rather than scoring the evidence down for a question it was never asked.
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

    # The scope selects which attacks count, so a verdict must record it or the
    # grade is unreproducible. Recorded by *semantics*, not by label: a preset
    # is identified by its enum value, and a custom scope by a hash over the
    # positions and categories it declares. Two scopes may share a name and
    # select different attack sets, so the name alone would not be enough.
    from src.core.threat_scope import scope_description, scope_identity

    threat_model_name = scope_identity(threat_model)
    threat_scope_detail = scope_description(threat_model)

    has_quote = any(_has_quote_for_platform(graph, p) for p in platforms)
    debug_ok = _all_quotes_debug_disabled(graph)
    _all_firmware_current(graph)
    has_build_prov = _has_build_provenance(graph)
    provenance_dim = compute_provenance_dimension(graph)
    platforms_bound = has_verified_cross_platform_binding(graph)

    if has_quote and debug_ok:
        if platforms_bound and has_build_prov:
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

    attack_boundaries = _collect_attack_boundaries(graph, threat_model=threat_model)
    if attack_boundaries:
        boundary += "\n\nKnown unmitigated attacks in scope:\n" + "\n".join(
            f"- {b}" for b in attack_boundaries
        )

    # Narrowing a scope must stay visible. A scope that excludes attacks raises
    # the threat dimension (fewer penalties), which is a legitimate use — an
    # attack outside the model genuinely should not count — but it must not
    # read as "fewer problems discovered". The excluded ones are named.
    out_of_scope = _collect_out_of_scope_attack_names(graph, threat_model=threat_model)
    if out_of_scope:
        boundary += (
            f"\n\nExcluded by this threat scope, not counted in the grade: "
            f"{', '.join(out_of_scope)}. A narrower scope scores higher on the "
            "threat dimension because fewer attacks apply; that is a statement "
            "about the model chosen, not about the platform."
        )

    # Coverage signal: how many known attacks the engine grades against for the
    # platform(s) under evaluation. A low count means less measured, not safer.
    in_scope_count, known_count = _known_attack_count(graph, threat_model=threat_model)
    if known_count:
        boundary += (
            f"\n\nGraded against {in_scope_count} of {known_count} known attack(s) for "
            "the platform(s) under evaluation; undisclosed vulnerabilities cannot be "
            "detected from a quote."
        )

    # The same statements, structured. A boundary statement is part of the
    # verdict, not commentary: a re-grader or a UI must be able to check which
    # attacks were counted without parsing prose.
    boundary_constraints = {
        "attacks_in_scope": in_scope_count,
        "attacks_known": known_count,
        "attacks_excluded_by_scope": out_of_scope,
        "assumptions": _scope_assumptions(threat_model),
        "threat_scope_identity": threat_model_name,
    }

    # TCB temporal summary: liveness and patched-ness reported separately.
    temporal = _tcb_temporal_summary(
        graph, tcb_db_path=tcb_db_path, tcb_fmspc=tcb_fmspc, threat_model=threat_model
    )
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
        threat_model=threat_model_name,
        threat_scope=threat_scope_detail,
        boundary_constraints=boundary_constraints,
    )
    score = compute_numeric_score(
        graph,
        evaluation,
        applicable_attacks,
        score_profile=score_profile,
        threat_model=threat_model,
        tcb_resolutions=_resolve_tcb_statuses(graph, tcb_db_path=tcb_db_path, tcb_fmspc=tcb_fmspc),
        policy_conformance=policy_conformance,
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
        threat_model=threat_model_name,
        threat_scope=threat_scope_detail,
        boundary_constraints=boundary_constraints,
    )
