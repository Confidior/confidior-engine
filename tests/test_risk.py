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


def test_single_vendor_tdx_returns_level_2_critical_risk():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.HARDWARE_ATTESTED
    assert result.residual_risk == ResidualRiskTier.CRITICAL
    assert TEE_FAIL_BOUNDARY_STATEMENT in result.boundary_statement
    assert "TEE.fail" in result.boundary_statement
    assert "Battering RAM" in result.boundary_statement


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
    assert result.residual_risk == ResidualRiskTier.CRITICAL


def test_build_provenance_upgrades_to_level_3():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    graph.add_node(EvidenceNode("bp1", NodeType.BUILD_PROVENANCE))
    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.OPERATIONAL_ASSURANCE
    assert result.residual_risk == ResidualRiskTier.CRITICAL


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
