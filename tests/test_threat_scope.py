"""Threat-scope model tests: label definitions and layer-set derivation."""
from src.core.attacks import AttackCategory
from src.core.taxonomy import ThreatModelTier
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
