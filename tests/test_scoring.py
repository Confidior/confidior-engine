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
    PolicyDecision,
    ResidualRiskTier,
    ScoreResult,
    TCBStatus,
    TemporalFreshness,
)

#: A half-satisfied policy, so the compliance dimension is present.
_CONFORMANCE = {
    "satisfied": 5,
    "failed": 5,
    "not_evaluated": 0,
    "total": 10,
    "ratio": 0.5,
    "rules_passed": 1,
    "rules_failed": 1,
    "rules_not_evaluated": 0,
}


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
    """With every dimension present the weighted subscores sum to the total."""
    graph = EvidenceGraph()
    graph.add_node(_quote_node(Platform.IntelTDX))
    assurance = _make_assurance()
    score = compute_numeric_score(graph, assurance, [], policy_conformance=_CONFORMANCE)
    assert isinstance(score, ScoreResult)
    assert 0 <= score.total <= 100
    assert set(score.subscores) == {
        "attestation",
        "trust",
        "threat",
        "freshness",
        "compliance",
    }
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


def test_cheap_unmitigated_attack_cuts_threat():
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
    graph_aging.add_node(
        _quote_node(Platform.IntelTDX, timestamp=now - timedelta(seconds=3000), ttl_seconds=3600)
    )
    graph_stale = EvidenceGraph()
    graph_stale.add_node(
        _quote_node(Platform.IntelTDX, timestamp=now - timedelta(seconds=4000), ttl_seconds=3600)
    )
    fresh = compute_numeric_score(
        graph_fresh, _make_assurance(freshness=TemporalFreshness.FRESH), []
    )
    aging = compute_numeric_score(
        graph_aging, _make_assurance(freshness=TemporalFreshness.AGING), []
    )
    stale = compute_numeric_score(
        graph_stale, _make_assurance(freshness=TemporalFreshness.STALE), []
    )
    assert fresh.subscores["freshness"] == 20
    assert aging.subscores["freshness"] == 12
    assert stale.subscores["freshness"] == 0
    assert fresh.total > stale.total


def test_trust_bonuses_capped_at_20():
    graph = EvidenceGraph()
    graph.add_node(
        _quote_node(Platform.IntelTDX, debug_disabled=True, tcb_status=TCBStatus.CURRENT)
    )
    graph.add_node(EvidenceNode("bp1", NodeType.BUILD_PROVENANCE))
    graph.add_node(
        _quote_node(Platform.AMDSEVSNP, debug_disabled=True, tcb_status=TCBStatus.CURRENT)
    )
    assurance = _make_assurance(dimensions={"provenance": "chained"})
    score = compute_numeric_score(graph, assurance, [])
    assert score.subscores["trust"] == 20


def test_compliance_subscore_comes_from_policy_conformance():
    """The compliance dimension measures how much of the policy this evidence
    satisfies, weighted by rule severity, not framework coverage."""
    graph = EvidenceGraph()
    graph.add_node(_quote_node(Platform.IntelTDX))
    assurance = _make_assurance()

    conformance = {
        "satisfied": 3,
        "failed": 6,
        "not_evaluated": 0,
        "total": 9,
        "ratio": 1 / 3,
        "rules_passed": 1,
        "rules_failed": 2,
        "rules_not_evaluated": 0,
    }
    score = compute_numeric_score(graph, assurance, [], policy_conformance=conformance)
    assert score.policy_conformance == conformance
    assert score.subscores["compliance"] == int(round((1 / 3) * 20))


def test_compliance_dimension_is_absent_without_a_policy():
    """No policy means the dimension was never asked a question, so it is left
    out entirely. Crediting it would raise every grade the moment no policy was
    supplied; charging it would punish evidence for a question it was not
    asked. The other dimensions are renormalized over the graded weight."""
    graph = EvidenceGraph()
    graph.add_node(_quote_node(Platform.IntelTDX))
    score = compute_numeric_score(graph, _make_assurance(), [])
    assert score.policy_conformance is None
    assert "compliance" not in score.subscores
    # The graded weight is 80 of the profile's 100, so the total is rescaled.
    assert sum(score.subscores.values()) != score.total


def test_policy_conformance_weights_by_severity():
    """A high-severity rule outweighs a low-severity one in the ratio."""
    from src.core.policy import policy_conformance
    from src.core.taxonomy import PolicyEvaluation, PolicyRule

    policy = type(
        "P",
        (),
        {
            "rules": [
                PolicyRule("must", "must", severity="high"),
                PolicyRule("should", "should", severity="low"),
            ]
        },
    )()
    passed_high = PolicyEvaluation(
        decision=PolicyDecision.ALLOW, rules_passed=["must"], rules_failed=["should"]
    )
    passed_low = PolicyEvaluation(
        decision=PolicyDecision.DENY, rules_passed=["should"], rules_failed=["must"]
    )
    high = policy_conformance(passed_high, policy)
    low = policy_conformance(passed_low, policy)
    assert high is not None and low is not None
    # 3 of 4 weighted points vs 1 of 4
    assert high["ratio"] == 0.75
    assert low["ratio"] == 0.25


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
    assert compute_numeric_score(
        graph, _make_assurance(AssuranceLevel.HARDWARE_ATTESTED), []
    ).grade in ("C", "D")


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


def test_score_profile_changes_weights():
    """Finance and GPU-TEE profiles produce different totals than default."""
    graph = EvidenceGraph()
    graph.add_node(
        _quote_node(Platform.IntelTDX, debug_disabled=True, tcb_status=TCBStatus.CURRENT)
    )
    graph.add_node(EvidenceNode("bp1", NodeType.BUILD_PROVENANCE))
    assurance = _make_assurance()
    default = compute_numeric_score(graph, assurance, [], score_profile="default")
    finance = compute_numeric_score(graph, assurance, [], score_profile="finance")
    gpu = compute_numeric_score(graph, assurance, [], score_profile="gpu-tee")
    assert default.profile == "default"
    assert finance.profile == "finance"
    assert gpu.profile == "gpu-tee"
    assert default.subscores != finance.subscores
    assert default.total != finance.total or default.grade != finance.grade


def test_unknown_score_profile_falls_back_to_default():
    graph = EvidenceGraph()
    graph.add_node(_quote_node(Platform.IntelTDX))
    assurance = _make_assurance()
    score = compute_numeric_score(graph, assurance, [], score_profile="nonexistent")
    assert score.profile == "default"


def test_score_profile_recorded_in_assurance():
    from src.core.risk import compute_assurance_level

    graph = EvidenceGraph()
    graph.add_node(_quote_node(Platform.IntelTDX, debug_disabled=True))
    eval_ = compute_assurance_level(graph, score_profile="finance")
    assert eval_.score_profile == "finance"
    assert eval_.score is not None
    assert eval_.score.profile == "finance"


def test_no_quote_nodes_scores_attestation_only():
    """Without quote nodes, only the explicit assurance level counts."""
    graph = EvidenceGraph()
    assurance = _make_assurance(AssuranceLevel.HARDWARE_ATTESTED)
    score = compute_numeric_score(graph, assurance, [])
    # attestation = level * 4 = 8; all other dims are 0.
    assert score.subscores["attestation"] == 8
    assert score.subscores["trust"] == 0
    assert score.subscores["threat"] == 0
    assert score.subscores["freshness"] == 0
    assert score.subscores["compliance"] == 0


def test_evidence_class_ladder_and_trust_contribution():
    """A verdict is as strong as its weakest evidence class, and only the
    strongest classes (computed golden, runtime-anchored) add trust."""
    import dataclasses

    from src.core.taxonomy import EvidenceClass

    base_node = _quote_node(Platform.IntelTDX, debug_disabled=True, tcb_status=TCBStatus.CURRENT)
    assurance = _make_assurance()

    def score_for(cls):
        node = dataclasses.replace(base_node, evidence_class=cls)
        g = EvidenceGraph()
        g.add_node(node)
        return compute_numeric_score(g, assurance, []).subscores["trust"]

    baseline = score_for(None)
    # Weaker classes add nothing.
    assert score_for(EvidenceClass.POINT_IN_TIME) == baseline
    assert score_for(EvidenceClass.VENDOR_PUBLISHED) == baseline
    # The strongest classes add 5.
    assert score_for(EvidenceClass.COMPUTED_GOLDEN) == baseline + 5
    assert score_for(EvidenceClass.RUNTIME_ANCHORED) == baseline + 5


def test_evidence_class_axis_is_provenance_not_strength():
    """The ladder is one axis, how evidence was obtained, and says so.

    `strength` collapsed provenance rank with institutional standing, so a
    vendor-published auditor's letter read as weaker evidence than an
    inadmissible computed value. The accessor is `provenance_rank`, and the
    rank must not be reachable under the old name. See docs/VERIFIABILITY.md.
    """
    from src.core.taxonomy import EvidenceClass

    assert not hasattr(EvidenceClass.COMPUTED_GOLDEN, "strength")

    order = EvidenceClass.provenance_order()
    ranks = [c.provenance_rank for c in order]
    assert ranks == sorted(ranks)
    assert ranks[0] == EvidenceClass.UNKNOWN.provenance_rank == 0
    assert (
        EvidenceClass.RUNTIME_ANCHORED.provenance_rank == len(order) - 1
    )
    # The order is total and strict: every class has a distinct rank and the
    # ladder lists every member exactly once.
    assert len(set(ranks)) == len(order) == len(list(EvidenceClass))


def test_weakest_evidence_class_is_the_verdict_class():
    """The reported class is the minimum across nodes: one weak input weakens
    the whole verdict."""
    import dataclasses

    from src.core.risk import weakest_evidence_class
    from src.core.taxonomy import EvidenceClass, EvidenceNode, NodeType

    strong = dataclasses.replace(
        _quote_node(Platform.IntelTDX), evidence_class=EvidenceClass.COMPUTED_GOLDEN
    )
    g = EvidenceGraph()
    g.add_node(strong)
    g.add_node(
        EvidenceNode("bp", NodeType.BUILD_PROVENANCE, evidence_class=EvidenceClass.POINT_IN_TIME)
    )
    assert weakest_evidence_class(g) == EvidenceClass.POINT_IN_TIME
    score = compute_numeric_score(g, _make_assurance(), [])
    assert score.evidence_class == EvidenceClass.POINT_IN_TIME


def _bound_graph(binding_a, binding_b, edge=True, same_platform=False):
    """Two quote nodes, optionally bound by a shared challenge."""

    from src.core.taxonomy import EdgeType, EvidenceEdge, EvidenceNode, NodeType

    def quote(node_id, platform, binding):
        return EvidenceNode(
            node_id,
            NodeType.QUOTE,
            platform=platform,
            debug_disabled=True,
            tcb_status=TCBStatus.CURRENT,
            metadata={"binding": binding} if binding else {},
        )

    a = quote("q-a", Platform.IntelTDX, binding_a)
    b = quote("q-b", Platform.IntelTDX if same_platform else Platform.AMDSEVSNP, binding_b)
    graph = EvidenceGraph()
    graph.add_node(a)
    graph.add_node(b)
    if edge:
        graph.add_edge(EvidenceEdge("q-a", "q-b", EdgeType.BOUND_TO))
    return graph


def test_two_platform_bonus_requires_a_verified_binding():
    """A second platform corroborates only when the two attestations cover the
    same session. Counting platforms alone credited an unrelated quote."""
    assurance = _make_assurance()

    def trust_for(graph):
        return compute_numeric_score(graph, assurance, []).subscores["trust"]

    baseline = trust_for(_bound_graph(None, None))          # two platforms, unbound
    assert trust_for(_bound_graph("abc123", "abc123")) == baseline + 5
    # Different challenges, a missing challenge, or no edge all mean unbound.
    assert trust_for(_bound_graph("abc123", "def456")) == baseline
    assert trust_for(_bound_graph("abc123", None)) == baseline
    assert trust_for(_bound_graph("abc123", "abc123", edge=False)) == baseline
    # Two claims about the same platform corroborate nothing about a second root.
    assert trust_for(_bound_graph("abc123", "abc123", same_platform=True)) == baseline


def test_unbound_platforms_are_reported_without_being_credited():
    """The distinction is disclosed rather than silent: the verdict says how many
    platforms are present and whether they are bound."""
    from src.export.display import explain_lines

    bound = compute_numeric_score(
        _bound_graph("abc123", "abc123"), _make_assurance(), []
    )
    unbound = compute_numeric_score(_bound_graph(None, None), _make_assurance(), [])

    assert bound.platform_count == 2 and bound.platforms_bound is True
    assert unbound.platform_count == 2 and unbound.platforms_bound is False

    from src.core.taxonomy import AssuranceEvaluation, AssuranceLevel, ResidualRiskTier

    def evaluation(score):
        return AssuranceEvaluation(
            level=AssuranceLevel.HARDWARE_ATTESTED,
            residual_risk=ResidualRiskTier.HIGH,
            boundary_statement="test",
            score=score,
        )

    assert "bound to the same session" in "\n".join(explain_lines(evaluation(bound)))
    assert "no verified binding" in "\n".join(explain_lines(evaluation(unbound)))


def test_replayed_binding_does_not_count_when_a_challenge_is_set():
    """A binding must answer *this* verifier's challenge, not just any challenge.

    report_data is the field the relying party controls, which is what makes a
    cross-platform pair a statement about one session rather than two. Mutual
    agreement on a value the quotes themselves chose proves only that they were
    co-attested at some point: a pair recorded earlier satisfies the check
    forever, so a replayed pair is indistinguishable from a fresh one. When the
    verifier names the challenge it issued, the shared value must equal it.
    """
    from src.core.binding import has_verified_cross_platform_binding

    replayed = _bound_graph("abc123", "abc123")
    assert has_verified_cross_platform_binding(replayed) is True, (
        "without an expected challenge, the stored-bundle case still holds"
    )

    replayed.expected_challenge = "the-challenge-we-issued-now"
    assert has_verified_cross_platform_binding(replayed) is False, (
        "a pair that answered a different challenge is a replay, not a binding"
    )

    fresh = _bound_graph("abc123", "abc123")
    fresh.expected_challenge = "abc123"
    assert has_verified_cross_platform_binding(fresh) is True


def test_a_challenge_the_quotes_disagree_on_is_not_a_binding():
    """Both quotes must answer the same challenge; one matching is not enough."""
    from src.core.binding import has_verified_cross_platform_binding

    graph = _bound_graph("abc123", "def456")
    graph.expected_challenge = "abc123"

    assert has_verified_cross_platform_binding(graph) is False
