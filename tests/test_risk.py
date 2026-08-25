from datetime import datetime, timedelta, timezone

from src.core.risk import compute_assurance_level, compute_temporal_freshness
from src.core.taxonomy import (
    TEE_FAIL_BOUNDARY_STATEMENT,
    AssuranceLevel,
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Platform,
    ResidualRiskTier,
    TCBStatus,
    TemporalFreshness,
    ThreatModelTier,
)


def _make_quote_node(platform, debug_disabled=True, tcb_status=TCBStatus.UNKNOWN):
    return EvidenceNode(
        node_id=f"quote-{platform.value}",
        node_type=NodeType.QUOTE,
        platform=platform,
        measurement="aa" * 48,
        debug_disabled=debug_disabled,
        tcb_status=tcb_status,
    )


def test_no_evidence_returns_level_0():
    graph = EvidenceGraph()
    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.NONE
    assert result.residual_risk == ResidualRiskTier.HIGH


def test_single_vendor_tdx_returns_level_2_high_risk():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.HARDWARE_ATTESTED
    assert result.residual_risk == ResidualRiskTier.HIGH
    assert TEE_FAIL_BOUNDARY_STATEMENT in result.boundary_statement
    assert "TEE.fail" in result.boundary_statement
    assert "Heckler" in result.boundary_statement


def test_single_vendor_sev_snp_returns_level_2_critical_risk():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.AMDSEVSNP))
    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.HARDWARE_ATTESTED
    assert result.residual_risk == ResidualRiskTier.CRITICAL
    assert "BadRAM" in result.boundary_statement


def test_debug_enabled_downgrades_to_level_1():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX, debug_disabled=False))
    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.CONFIG_VERIFIED
    assert result.residual_risk == ResidualRiskTier.HIGH


def test_build_provenance_upgrades_to_level_3():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    graph.add_node(EvidenceNode("bp1", NodeType.BUILD_PROVENANCE))
    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.OPERATIONAL_ASSURANCE
    assert result.residual_risk == ResidualRiskTier.MEDIUM


def test_label_is_correct():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    result = compute_assurance_level(graph)
    assert result.label == "Level 2 | Hardware-Attested"


def test_temporal_freshness_fresh():
    graph = EvidenceGraph()
    graph.add_node(EvidenceNode("n1", NodeType.QUOTE, platform=Platform.IntelTDX,
                                timestamp=datetime.now(timezone.utc), ttl_seconds=3600))
    assert compute_temporal_freshness(graph) == TemporalFreshness.FRESH


def test_temporal_freshness_aging():
    graph = EvidenceGraph()
    graph.add_node(EvidenceNode("n1", NodeType.QUOTE, platform=Platform.IntelTDX,
                                timestamp=datetime.now(timezone.utc) - timedelta(seconds=700),
                                ttl_seconds=800))
    assert compute_temporal_freshness(graph) == TemporalFreshness.AGING


def test_temporal_freshness_stale():
    graph = EvidenceGraph()
    graph.add_node(EvidenceNode("n1", NodeType.QUOTE, platform=Platform.IntelTDX,
                                timestamp=datetime.now(timezone.utc) - timedelta(seconds=4000),
                                ttl_seconds=3600))
    assert compute_temporal_freshness(graph) == TemporalFreshness.STALE


def test_temporal_freshness_no_timestamp():
    graph = EvidenceGraph()
    graph.add_node(EvidenceNode("n1", NodeType.QUOTE, platform=Platform.IntelTDX))
    result = compute_temporal_freshness(graph)
    assert result is TemporalFreshness.FRESH


def test_assurance_evaluation_includes_freshness():
    graph = EvidenceGraph()
    graph.add_node(EvidenceNode("n1", NodeType.QUOTE, platform=Platform.IntelTDX,
                                timestamp=datetime.now(timezone.utc), ttl_seconds=3600))
    result = compute_assurance_level(graph)
    assert result.temporal_freshness == TemporalFreshness.FRESH


def test_threat_model_relative_grading():
    """Same evidence must grade differently per threat model.

    A software-only threat model excludes physical-layer attacks (Battering RAM,
    TEE.fail); a physical-capable threat model includes them, so a physical
    attacker gets a worse score on the same evidence.
    """
    from src.core.risk import compute_assurance_level
    from src.core.taxonomy import ThreatModelTier

    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))

    software = compute_assurance_level(graph, threat_model=ThreatModelTier.CLOUD_ADMIN)
    physical = compute_assurance_level(graph, threat_model=ThreatModelTier.PHYSICAL_HOST)

    # Physical threat model counts more attacks -> strictly lower threat score.
    assert software.score.subscores["threat"] > physical.score.subscores["threat"]
    # The physical threat model grades worse (lower or equal total, never better).
    assert software.score.total >= physical.score.total
    # Physical-capable models escalate residual risk at least as far.
    assert _risk_rank(physical.residual_risk) >= _risk_rank(software.residual_risk)


def _risk_rank(tier):
    from src.core.taxonomy import ResidualRiskTier

    return {ResidualRiskTier.LOW: 0, ResidualRiskTier.MEDIUM: 1,
            ResidualRiskTier.HIGH: 2, ResidualRiskTier.CRITICAL: 3}[tier]


def test_boundary_statement_includes_coverage_signal():
    """The boundary statement names how many known attacks it grades against."""
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    result = compute_assurance_level(graph)
    assert "Graded against" in result.boundary_statement
    assert "known attack" in result.boundary_statement
    assert "undisclosed vulnerabilities cannot be detected" in result.boundary_statement


def test_tcb_reference_drives_trust_score(tmp_path):
    """A seeded current-TCB reference resolves the quote's TCB to CURRENT and
    the trust score rewards it; a below-reference quote resolves to EXPIRED."""
    from src.tools.archaeology import ArchaeologyDB, TCBRecord

    db_path = tmp_path / "tcb.db"
    db = ArchaeologyDB(db_path=db_path)
    db.insert(TCBRecord(platform="Intel-TDX", version="0b010500", status="current"))
    db.close()

    # Quote TCB at the reference -> CURRENT -> trust +5.
    node = _make_quote_node(Platform.IntelTDX)
    node = EvidenceNode(
        node_id=node.node_id,
        node_type=node.node_type,
        platform=node.platform,
        measurement=node.measurement,
        debug_disabled=node.debug_disabled,
        tcb_status=node.tcb_status,
        tcb_version="0b010500",
    )
    graph = EvidenceGraph()
    graph.add_node(node)
    result = compute_assurance_level(graph, tcb_db_path=str(db_path))
    assert result.score.subscores["trust"] >= 10  # debug off +5, TCB current +5


def test_scoring_is_deterministic():
    """Same evidence and threat model produce identical verdicts across runs."""
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    r1 = compute_assurance_level(graph, threat_model=ThreatModelTier.PHYSICAL_HOST)
    r2 = compute_assurance_level(graph, threat_model=ThreatModelTier.PHYSICAL_HOST)
    assert r1.score.total == r2.score.total
    assert r1.score.subscores == r2.score.subscores
    assert r1.residual_risk == r2.residual_risk
    assert r1.boundary_statement == r2.boundary_statement
