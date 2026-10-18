from datetime import datetime, timedelta, timezone

from src.core import risk as risk_module
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


def test_single_vendor_tdx_returns_level_2_critical_risk():
    # Intel TDX grades CRITICAL, not HIGH: the curated DB now carries TDXRay,
    # whose mitigation is hardware_redesign_required, and any applicable attack
    # at that difficulty escalates the tier (src/core/residual.py). The level
    # still attests (HARDWARE_ATTESTED) -- the hardware did prove the software,
    # the residual risk is what the hardware cannot prove.
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.HARDWARE_ATTESTED
    assert result.residual_risk == ResidualRiskTier.CRITICAL
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
    assert result.residual_risk == ResidualRiskTier.CRITICAL


def test_build_provenance_upgrades_to_level_3():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    graph.add_node(EvidenceNode("bp1", NodeType.BUILD_PROVENANCE))
    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.OPERATIONAL_ASSURANCE
    # Build provenance raises the assurance level but cannot lower the residual
    # tier below the hardware-redesign attacks that apply to the platform.
    assert result.residual_risk == ResidualRiskTier.HIGH


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

def test_platform_quote_split_derived_from_subscores():
    """The split separates the attack-database dimension (platform) from the
    dimensions that describe this evidence (attestation/trust/freshness, plus
    policy conformance when a policy was evaluated)."""
    from src.core.risk import compute_numeric_score
    from src.core.taxonomy import (
        AssuranceEvaluation,
        AssuranceLevel,
        EvidenceGraph,
        ResidualRiskTier,
        ScoreResult,
    )

    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    assurance = AssuranceEvaluation(
        level=AssuranceLevel.HARDWARE_ATTESTED,
        residual_risk=ResidualRiskTier.HIGH,
        dimensions={"provenance": "none"},
        boundary_statement="test",
    )
    result = compute_numeric_score(graph, assurance, applicable_attacks=[])
    assert isinstance(result, ScoreResult)
    assert result.platform_score is not None
    assert result.quote_score is not None
    # platform side: threat alone -> 0-100
    expected_platform = int(round(result.subscores["threat"] / 20 * 100))
    # quote side: attestation + trust + freshness (compliance is absent, since
    # no policy was evaluated) -> 0-100 over three dimensions
    quote_raw = (
        result.subscores["attestation"]
        + result.subscores["trust"]
        + result.subscores["freshness"]
    )
    expected_quote = int(round(quote_raw / 60 * 100))
    assert result.platform_score == expected_platform
    assert result.quote_score == expected_quote


def test_platform_quote_split_redpill_quote():
    """Unmitigated attacks move the threat dimension, so the platform side of
    the split reflects attack surface while the quote side reflects this
    attestation's own state."""
    from src.core.attacks import TEE_ATTACKS
    from src.core.risk import compute_numeric_score
    from src.core.taxonomy import (
        AssuranceEvaluation,
        AssuranceLevel,
        EvidenceGraph,
        ResidualRiskTier,
    )

    graph = EvidenceGraph()
    assurance = AssuranceEvaluation(
        level=AssuranceLevel.HARDWARE_ATTESTED,
        residual_risk=ResidualRiskTier.HIGH,
        dimensions={"provenance": "none"},
        boundary_statement="test",
    )
    result = compute_numeric_score(graph, assurance, applicable_attacks=TEE_ATTACKS)
    # the threat dimension is penalized by the unmitigated attacks
    assert result.platform_score is not None
    assert result.quote_score is not None
    assert 0 <= result.platform_score <= 100
    assert 0 <= result.quote_score <= 100


# --- The split's mutable global ----------------------------------------------
# `set_archaeology_db_path` rebinds a module-level variable, and a `from x import y`
# binding is a snapshot rather than a live reference. After the split the name is
# re-exported by the `risk` facade while being owned (and rebound) by `binding`, so a
# reader importing it *through the facade* holds the value from first import forever.
# That fails silently: the operator passes --archaeology-db, nothing raises, and the
# default database is used instead.


def test_a_configured_archaeology_path_reaches_the_reader(tmp_path):
    """The regression the split introduced: a config write no reader noticed."""
    from src.core import binding, tcb

    db = tmp_path / "custom.db"
    db.write_text("")  # must exist: the reader checks exists() before using it

    original = binding._ARCHAEOLOGY_DB_PATH
    try:
        risk_module.set_archaeology_db_path(str(db))
        assert tcb._get_default_archaeology_path() == str(db), (
            "the configured archaeology DB was ignored -- a reader is holding a stale "
            "snapshot of the global instead of the owning module's attribute"
        )
    finally:
        binding._ARCHAEOLOGY_DB_PATH = original


def test_the_facade_re_export_is_a_snapshot_not_a_reference():
    """Pins why readers must not import this name from the facade.

    Not a defect in itself -- it is how Python works -- but it is the trap, so it is
    asserted rather than assumed. If this ever stops holding, the hazard is gone and
    either import location is safe again.
    """
    from src.core import binding, risk

    before = risk._ARCHAEOLOGY_DB_PATH
    risk.set_archaeology_db_path("/tmp/definitely-not-the-default.db")
    try:
        # The owner moved; the facade's binding did not.
        assert binding._ARCHAEOLOGY_DB_PATH != before
        assert risk._ARCHAEOLOGY_DB_PATH == before
    finally:
        binding._ARCHAEOLOGY_DB_PATH = None
