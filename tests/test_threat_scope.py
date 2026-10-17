"""Threat-scope model tests: label definitions and layer-set derivation."""
from src.core.attacks import AttackCategory
from src.core.taxonomy import AdversaryPosition, ThreatModelTier
from src.core.threat_scope import (
    PHYSICAL_LAYER_CATEGORIES,
    THREAT_MODEL_LAYERS,
    categories_for_threat_model,
    threat_model_includes_physical,
)


def test_software_only_models_exclude_physical_layers():
    for tm in (ThreatModelTier.SOFTWARE_OPERATOR, ThreatModelTier.CLOUD_ADMIN):
        layers = categories_for_threat_model(tm)
        assert not PHYSICAL_LAYER_CATEGORIES.issubset(layers)
        assert not threat_model_includes_physical(tm)


def test_physical_models_include_physical_layers():
    for tm in (ThreatModelTier.PHYSICAL_HOST, ThreatModelTier.NATION_STATE_PHYSICAL):
        layers = categories_for_threat_model(tm)
        assert PHYSICAL_LAYER_CATEGORIES.issubset(layers)
        assert threat_model_includes_physical(tm)


def test_software_and_cloud_share_layer_set():
    assert (
        categories_for_threat_model(ThreatModelTier.SOFTWARE_OPERATOR)
        == categories_for_threat_model(ThreatModelTier.CLOUD_ADMIN)
    )


def test_physical_and_nation_state_share_layer_set():
    assert (
        categories_for_threat_model(ThreatModelTier.PHYSICAL_HOST)
        == categories_for_threat_model(ThreatModelTier.NATION_STATE_PHYSICAL)
    )


def test_every_threat_model_has_a_defined_layer_set():
    for tm in ThreatModelTier:
        assert tm in THREAT_MODEL_LAYERS


def test_physical_categories_are_a_subset_of_all():
    assert PHYSICAL_LAYER_CATEGORIES.issubset(frozenset(AttackCategory))


def test_custom_scope_includes_only_specified_categories():
    from src.core.threat_scope import CustomThreatScope, categories_for_scope

    scope = CustomThreatScope(
        name="bank-physical",
        includes=frozenset(
            {
                AttackCategory.SPECULATIVE_EXECUTION,
                AttackCategory.CACHE_SIDE_CHANNEL,
                AttackCategory.MEMORY_BUS,
            }
        ),
    )
    cats = categories_for_scope(scope)
    assert AttackCategory.SPECULATIVE_EXECUTION in cats
    assert AttackCategory.MEMORY_BUS in cats
    assert AttackCategory.ROWHAMMER not in cats


def test_load_threat_scope_from_yaml(tmp_path):
    from src.core.threat_scope import load_threat_scope

    p = tmp_path / "scope.yaml"
    p.write_text(
        "name: bank-physical\n"
        "includes:\n"
        "  - speculative_execution\n"
        "  - memory_bus_interposition\n"
        "excludes: []\n"
    )
    scope = load_threat_scope(str(p))
    assert scope.name == "bank-physical"
    assert AttackCategory.SPECULATIVE_EXECUTION in scope.categories()
    assert AttackCategory.MEMORY_BUS in scope.categories()
    assert AttackCategory.ROWHAMMER not in scope.categories()


def test_load_threat_scope_excludes_subtract_from_all(tmp_path):
    from src.core.threat_scope import load_threat_scope

    p = tmp_path / "scope.yaml"
    p.write_text(
        "name: no-physical\n"
        "includes: []\n"
        "excludes:\n"
        "  - memory_bus_interposition\n"
        "  - rowhammer\n"
    )
    scope = load_threat_scope(str(p))
    assert AttackCategory.MEMORY_BUS not in scope.categories()
    assert AttackCategory.ROWHAMMER not in scope.categories()
    assert AttackCategory.SPECULATIVE_EXECUTION in scope.categories()


def test_load_threat_scope_rejects_unknown_category(tmp_path):
    from src.core.threat_scope import load_threat_scope

    p = tmp_path / "scope.yaml"
    p.write_text("name: bad\nincludes:\n  - not_a_category\n")
    try:
        load_threat_scope(str(p))
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_custom_scope_changes_verdict_threat_score():
    """A custom scope passed to the verdict changes the threat score.

    A custom scope replaces the layer set outright, so scoping to only
    physical-layer attacks (or to nothing) grades a different attack set than
    the default software scope does.
    """
    from src.core.risk import compute_assurance_level
    from src.core.taxonomy import EvidenceGraph, EvidenceNode, NodeType, Platform, TCBStatus
    from src.core.threat_scope import CustomThreatScope, PHYSICAL_LAYER_CATEGORIES

    def _quote():
        return EvidenceNode(
            node_id="q1",
            node_type=NodeType.QUOTE,
            platform=Platform.IntelTDX,
            measurement="aa" * 48,
            debug_disabled=True,
            tcb_status=TCBStatus.CURRENT,
        )

    graph = EvidenceGraph()
    graph.add_node(_quote())

    # Default (software-only) threat model: the full software layer set.
    default = compute_assurance_level(graph)

    # A custom scope selects its layer set outright, so a physical-only scope
    # grades a different (here, smaller) attack set, while an empty scope
    # leaves nothing to penalise.
    physical_scope = CustomThreatScope(name="physical", includes=frozenset(PHYSICAL_LAYER_CATEGORIES))
    physical = compute_assurance_level(graph, threat_model=physical_scope)

    empty_scope = CustomThreatScope(name="none", includes=frozenset())
    empty_result = compute_assurance_level(graph, threat_model=empty_scope)

    # The empty scope has no attacks in it, so the threat dimension is perfect.
    # The default software scope carries the software-layer TDX attacks, so it
    # is strictly worse on that dimension.
    assert empty_result.score.subscores["threat"] > default.score.subscores["threat"]
    # The physical-only scope carries only physical-layer attacks. For TDX that
    # is TEE.fail alone, which is a lighter penalty than the four software-layer
    # attacks, so it also lands above the default.
    assert physical.score.subscores["threat"] > default.score.subscores["threat"]
    # Both custom scopes therefore sit strictly above the default.
    assert empty_result.score.subscores["threat"] >= physical.score.subscores["threat"]


def test_positions_distinguish_software_operator_from_cloud_admin():
    """The host position is what separates the two software-only models:
    hypervisor-required attacks drop out when the host is declared trusted."""
    from src.core.attacks import TEE_ATTACKS
    from src.core.risk import _attacks_in_threat_model
    from src.core.taxonomy import ThreatModelTier

    heckler = [a for a in TEE_ATTACKS if a.name == "Heckler"][0]
    assert heckler.adversary_position == frozenset({AdversaryPosition.HOST})

    so = _attacks_in_threat_model([heckler], ThreatModelTier.SOFTWARE_OPERATOR)
    ca = _attacks_in_threat_model([heckler], ThreatModelTier.CLOUD_ADMIN)
    assert so == [], "a host-required attack must not count when the host is trusted"
    assert ca == [heckler], "the cloud-admin model grants the host position"


def test_positions_grant_the_expected_attacks_per_model():
    """Each model grants a superset of the previous one's positions."""
    from src.core.taxonomy import ThreatModelTier
    from src.core.threat_scope import positions_for_threat_model

    so = positions_for_threat_model(ThreatModelTier.SOFTWARE_OPERATOR)
    ca = positions_for_threat_model(ThreatModelTier.CLOUD_ADMIN)
    ph = positions_for_threat_model(ThreatModelTier.PHYSICAL_HOST)
    ns = positions_for_threat_model(ThreatModelTier.NATION_STATE_PHYSICAL)

    assert so == frozenset({AdversaryPosition.IN_GUEST})
    assert so < ca < ph < ns


def test_unclassified_attacks_count_conservatively():
    """An attack with no position set counts under every model."""
    from src.core.attacks import MitigationDifficulty, TEEAttack
    from src.core.risk import _attacks_in_threat_model
    from src.core.taxonomy import ThreatModelTier

    unclassified = TEEAttack(
        name="unclassified",
        year=2026,
        affected_platforms=frozenset(),
        category=None,
        cost_to_attack="unknown",
        impact="test",
        mitigation="none",
        mitigation_difficulty=MitigationDifficulty.NO_MITIGATION,
    )
    for tm in ThreatModelTier:
        assert _attacks_in_threat_model([unclassified], tm) == [unclassified]
