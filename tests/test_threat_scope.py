"""Threat-scope model tests: label definitions and layer-set derivation."""
from src.core.attacks import TEE_ATTACKS, AttackCategory
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


def test_custom_scope_applies_the_position_gate():
    """A custom scope narrows by position as well as by category.

    Before this, a custom scope filtered on category alone, so a buyer who
    wrote their own scope lost the position gate the presets apply and was
    charged for attacks their model had declared unreachable. This is that
    regression: the same category set, at two different position budgets,
    must produce two different attack sets.
    """
    from src.core.risk import _attacks_in_threat_model
    from src.core.threat_scope import CustomThreatScope

    all_cats = frozenset(AttackCategory)

    # Every category, every position: the widest possible scope.
    wide = CustomThreatScope(name="wide", includes=all_cats, positions=None)
    # Every category, but the host is declared trusted.
    narrow = CustomThreatScope(
        name="narrow",
        includes=all_cats,
        positions=frozenset({AdversaryPosition.IN_GUEST}),
    )

    wide_attacks = _attacks_in_threat_model(TEE_ATTACKS, wide)
    narrow_attacks = _attacks_in_threat_model(TEE_ATTACKS, narrow)

    assert len(narrow_attacks) < len(wide_attacks), (
        "narrowing positions must narrow the attack set even when the category "
        "set is unchanged"
    )
    # The position gate must match the preset that grants the same positions.
    preset = _attacks_in_threat_model(TEE_ATTACKS, ThreatModelTier.SOFTWARE_OPERATOR)
    assert {a.name for a in narrow_attacks} == {a.name for a in preset}


def test_custom_scope_category_and_position_both_apply():
    """An attack must pass the position gate AND be in the category set."""
    from src.core.risk import _attacks_in_threat_model
    from src.core.threat_scope import CustomThreatScope

    scope = CustomThreatScope(
        name="both",
        includes=frozenset({AttackCategory.CACHE_SIDE_CHANNEL}),
        positions=frozenset({AdversaryPosition.IN_GUEST}),
    )
    kept = _attacks_in_threat_model(TEE_ATTACKS, scope)
    for attack in kept:
        assert attack.category == AttackCategory.CACHE_SIDE_CHANNEL
        assert attack.adversary_position.issubset({AdversaryPosition.IN_GUEST})


def test_custom_scope_omitting_positions_stays_category_only():
    """Backwards compatibility: no positions stated means every position."""
    from src.core.risk import _attacks_in_threat_model
    from src.core.threat_scope import CustomThreatScope

    scope = CustomThreatScope(
        name="legacy", includes=frozenset({AttackCategory.MEMORY_BUS})
    )
    assert scope.granted_positions() == frozenset(AdversaryPosition)
    kept = _attacks_in_threat_model(TEE_ATTACKS, scope)
    assert kept, "a physical category must still match when positions are unstated"


def test_load_threat_scope_reads_positions(tmp_path):
    from src.core.threat_scope import load_threat_scope

    p = tmp_path / "scope.yaml"
    p.write_text(
        "name: bank\n"
        "positions:\n"
        "  - in-guest\n"
        "  - host\n"
        "includes:\n"
        "  - cache_side_channel\n"
    )
    scope = load_threat_scope(str(p))
    assert scope.name == "bank"
    assert scope.granted_positions() == frozenset(
        {AdversaryPosition.IN_GUEST, AdversaryPosition.HOST}
    )


def test_load_threat_scope_rejects_unknown_position(tmp_path):
    from src.core.threat_scope import load_threat_scope

    p = tmp_path / "scope.yaml"
    p.write_text("name: bad\npositions:\n  - datacenter-roof\n")
    try:
        load_threat_scope(str(p))
    except ValueError as exc:
        assert "datacenter-roof" in str(exc)
    else:
        raise AssertionError("an unknown position must raise, not be ignored")


def test_load_threat_scope_defaults_positions_to_all(tmp_path):
    from src.core.threat_scope import load_threat_scope

    p = tmp_path / "scope.yaml"
    p.write_text("name: legacy\nincludes:\n  - rowhammer\n")
    scope = load_threat_scope(str(p))
    assert scope.granted_positions() == frozenset(AdversaryPosition)


def test_scope_identity_is_semantic_not_a_label():
    """Two scopes may share a name and select different attacks.

    A custom scope's name is user-chosen, so recording it in a verdict does not
    say which attack set produced the grade. Identity is a hash over the
    positions granted and the categories included, which is what actually
    decides the attack set.
    """
    from src.core.threat_scope import CustomThreatScope, scope_identity

    narrow = CustomThreatScope(
        "bank", frozenset({AttackCategory.ROWHAMMER}), frozenset(AdversaryPosition)
    )
    wide = CustomThreatScope(
        "bank",
        frozenset({AttackCategory.ROWHAMMER, AttackCategory.MEMORY_BUS}),
        frozenset(AdversaryPosition),
    )

    assert narrow.name == wide.name
    assert scope_identity(narrow) != scope_identity(wide)
    assert scope_identity(narrow).startswith("custom:")


def test_preset_identity_is_its_name():
    """A preset is fixed by the engine, so its name is a sufficient identity."""
    from src.core.threat_scope import scope_identity

    assert scope_identity(ThreatModelTier.CLOUD_ADMIN) == "cloud-admin"


def test_scope_description_is_enough_to_replay_the_scope():
    """A stored verdict must be re-gradable without the scope's source file."""
    from src.core.threat_scope import CustomThreatScope, scope_description

    scope = CustomThreatScope(
        "bank-physical",
        frozenset({AttackCategory.ROWHAMMER}),
        frozenset({AdversaryPosition.PHYSICAL}),
    )
    described = scope_description(scope)

    assert described["kind"] == "custom"
    assert described["name"] == "bank-physical"
    assert described["positions"] == ["physical"]
    assert described["categories"] == ["rowhammer"]
    assert described["identity"] == f"custom:{scope.digest()}"
