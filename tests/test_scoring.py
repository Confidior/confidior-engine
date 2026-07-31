"""Scoring engine test suite: numeric composite score, subscores, SVN effects, compliance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.core.attacks import (
    TEEAttack,
    get_attack_compliance_mappings,
    get_unmitigated_attacks,
)
from src.core.risk import compute_numeric_score
from src.core.taxonomy import (
    AssuranceEvaluation,
    AssuranceLevel,
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Platform,
    ResidualRiskTier,
    ScoreResult,
    TCBStatus,
    TemporalFreshness,
)


def _quote_node(
    platform: Platform,
    debug_disabled: bool = True,
    tcb_status: TCBStatus = TCBStatus.UNKNOWN,
    tcb_version: str | None = None,
    timestamp: datetime | None = None,
    ttl_seconds: int = 3600,
) -> EvidenceNode:
    return EvidenceNode(
        node_id=f"quote-{platform.value}",
        node_type=NodeType.QUOTE,
        platform=platform,
        measurement="aa" * 48,
        debug_disabled=debug_disabled,
        tcb_status=tcb_status,
        tcb_version=tcb_version,
        timestamp=timestamp,
        ttl_seconds=ttl_seconds,
    )


def _make_assurance(
    level: AssuranceLevel = AssuranceLevel.HARDWARE_ATTESTED,
    risk: ResidualRiskTier = ResidualRiskTier.HIGH,
    freshness: TemporalFreshness = TemporalFreshness.FRESH,
    dimensions: dict[str, str] | None = None,
) -> AssuranceEvaluation:
    return AssuranceEvaluation(
        level=level,
        residual_risk=risk,
        boundary_statement="test boundary",
        label=f"Level {level.value}",
        temporal_freshness=freshness,
        dimensions=dimensions or {},
    )


def test_score_has_all_subscores_and_sums_to_total():
    graph = EvidenceGraph()
    graph.add_node(_quote_node(Platform.IntelTDX))
    assurance = _make_assurance()
    score = compute_numeric_score(graph, assurance, [])
    assert isinstance(score, ScoreResult)
    assert 0 <= score.total <= 100
    assert set(score.subscores) == {"attestation", "trust", "threat", "freshness", "compliance"}
    assert sum(score.subscores.values()) == score.total


def test_no_evidence_scores_zero():
    graph = EvidenceGraph()
    assurance = _make_assurance(AssuranceLevel.NONE)
    score = compute_numeric_score(graph, assurance, [])
    assert score.total == 0
    assert score.grade == "F"


def test_level_increases_attestation_subscore():
    graph = EvidenceGraph()
    graph.add_node(_quote_node(Platform.IntelTDX))
    for level in AssuranceLevel:
        assurance = _make_assurance(level)
        score = compute_numeric_score(graph, assurance, [])
        expected = min(level.value * 4, 20)
        assert score.subscores["attestation"] == expected


def test_cheap_unmitigated_attack_cuts_threat_and_compliance():
    graph = EvidenceGraph()
    graph.add_node(_quote_node(Platform.AMDSEVSNP))
    assurance = _make_assurance()
    badram = TEEAttack(
        name="BadRAM",
        year=2024,
        affected_platforms=frozenset({Platform.AMDSEVSNP}),
        category=None,  # type: ignore[arg-type]
        cost_to_attack="~$10",
        impact="rogue SPD",
        mitigation="firmware",
        mitigation_difficulty=None,  # type: ignore[arg-type]
        compliance_controls={"C5": ["CRY-01.02B"]},
    )
    score = compute_numeric_score(graph, assurance, [badram])
    assert score.subscores["threat"] < 20
    assert score.subscores["compliance"] < 20


def test_svn_patch_restores_threat_and_compliance_score():
    """When TCB version exceeds the per-attack min_svn, the attack is excluded."""
    unpatched = get_unmitigated_attacks(Platform.AMDSEVSNP, tcb_version="0.0.1.10")
    patched = get_unmitigated_attacks(Platform.AMDSEVSNP, tcb_version="0.0.1.25")
    assert any(a.name == "BadRAM" for a in unpatched)
    assert not any(a.name == "BadRAM" for a in patched)


def test_freshness_affects_score():
    now = datetime.now(timezone.utc)
    graph_fresh = EvidenceGraph()
    graph_fresh.add_node(_quote_node(Platform.IntelTDX, timestamp=now, ttl_seconds=3600))
    graph_aging = EvidenceGraph()
    graph_aging.add_node(_quote_node(Platform.IntelTDX, timestamp=now - timedelta(seconds=3000), ttl_seconds=3600))
    graph_stale = EvidenceGraph()
    graph_stale.add_node(_quote_node(Platform.IntelTDX, timestamp=now - timedelta(seconds=4000), ttl_seconds=3600))
    fresh = compute_numeric_score(graph_fresh, _make_assurance(freshness=TemporalFreshness.FRESH), [])
    aging = compute_numeric_score(graph_aging, _make_assurance(freshness=TemporalFreshness.AGING), [])
    stale = compute_numeric_score(graph_stale, _make_assurance(freshness=TemporalFreshness.STALE), [])
    assert fresh.subscores["freshness"] == 20
    assert aging.subscores["freshness"] == 12
    assert stale.subscores["freshness"] == 0
    assert fresh.total > stale.total


def test_trust_bonuses_capped_at_20():
    graph = EvidenceGraph()
    graph.add_node(_quote_node(Platform.IntelTDX, debug_disabled=True, tcb_status=TCBStatus.CURRENT))
    graph.add_node(EvidenceNode("bp1", NodeType.BUILD_PROVENANCE))
    graph.add_node(_quote_node(Platform.AMDSEVSNP, debug_disabled=True, tcb_status=TCBStatus.CURRENT))
    assurance = _make_assurance(dimensions={"provenance": "chained"})
    score = compute_numeric_score(graph, assurance, [])
    assert score.subscores["trust"] == 20


def test_compliance_coverage_with_mixed_attack_status():
    """A control required by both an unmitigated and a mitigated attack is still a gap."""
    a1 = TEEAttack(
        name="a1",
        year=2024,
        affected_platforms=frozenset(),
        category=None,  # type: ignore[arg-type]
        cost_to_attack="Unknown",
        impact="x",
        mitigation="y",
        mitigation_difficulty=None,  # type: ignore[arg-type]
        compliance_controls={"C5": ["OPS-33.01B"]},
    )
    a2 = TEEAttack(
        name="a2",
        year=2024,
        affected_platforms=frozenset(),
        category=None,  # type: ignore[arg-type]
        cost_to_attack="Unknown",
        impact="x",
        mitigation="y",
        mitigation_difficulty=None,  # type: ignore[arg-type]
        compliance_controls={"C5": ["OPS-33.01B"], "SOC2": ["CC6.6"]},
        patched=True,
    )
    graph = EvidenceGraph()
    graph.add_node(_quote_node(Platform.IntelTDX))
    assurance = _make_assurance()
    score = compute_numeric_score(graph, assurance, [a1, a2])
    # One unique control is gap (OPS-33.01B), one satisfied (SOC2 CC6.6) -> 50% coverage
    assert score.subscores["compliance"] == 10


def test_attack_compliance_mapping_returns_controls():
    a = TEEAttack(
        name="BadRAM",
        year=2024,
        affected_platforms=frozenset(),
        category=None,  # type: ignore[arg-type]
        cost_to_attack="~$10",
        impact="x",
        mitigation="y",
        mitigation_difficulty=None,  # type: ignore[arg-type]
        compliance_controls={"C5": ["CRY-01.02B"], "PCI_DSS": ["3.4"]},
    )
    mappings = get_attack_compliance_mappings([a])
    assert ("C5", "CRY-01.02B", "BadRAM") in mappings
    assert ("PCI_DSS", "3.4", "BadRAM") in mappings


def test_grade_boundaries():
    empty_graph = EvidenceGraph()
    assert compute_numeric_score(empty_graph, _make_assurance(AssuranceLevel.NONE), []).grade == "F"

    graph = EvidenceGraph()
    graph.add_node(_quote_node(Platform.IntelTDX))
    assert compute_numeric_score(graph, _make_assurance(AssuranceLevel.HARDWARE_ATTESTED), []).grade in ("C", "D")


def test_timestamp_does_not_affect_default_freshness_score():
    """Nodes without timestamps default to FRESH, so freshness subscore is full."""
    graph = EvidenceGraph()
    graph.add_node(_quote_node(Platform.IntelTDX))
    score = compute_numeric_score(graph, _make_assurance(), [])
    assert score.subscores["freshness"] == 20


def test_stale_quote_lowers_freshness_and_total():
    graph = EvidenceGraph()
    graph.add_node(
        EvidenceNode(
            "old-quote",
            NodeType.QUOTE,
            platform=Platform.IntelTDX,
            measurement="aa" * 48,
            debug_disabled=True,
            timestamp=datetime.now(timezone.utc) - timedelta(seconds=4000),
            ttl_seconds=3600,
        )
    )
    assurance = _make_assurance()
    score = compute_numeric_score(graph, assurance, [])
    assert score.subscores["freshness"] == 0


def test_cve_id_maps_to_score_boundary_statement():
    """Score computation preserves attack metadata like CVE IDs used in boundary statements."""
    a = TEEAttack(
        name="BadRAM",
        year=2024,
        affected_platforms=frozenset({Platform.AMDSEVSNP}),
        category=None,  # type: ignore[arg-type]
        cost_to_attack="~$10",
        impact="x",
        mitigation="y",
        mitigation_difficulty=None,  # type: ignore[arg-type]
        cve_id="CVE-2024-21944",
        compliance_controls={"PCI_DSS": ["3.4"]},
    )
    assert a.cve_id == "CVE-2024-21944"
    mappings = get_attack_compliance_mappings([a])
    assert any(m[2] == "BadRAM" and m[0] == "PCI_DSS" for m in mappings)
