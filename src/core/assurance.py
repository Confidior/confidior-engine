"""Assurance level (0-5), boundary statement, and the composed evaluation.

Split out of ``risk.py`` (docs/CODEBASE-REVIEW-2026-10-03.md gap 4). The top of the
package: it assembles the level, the boundary statement and the score."""

from __future__ import annotations

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
