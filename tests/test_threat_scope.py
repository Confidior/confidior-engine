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
