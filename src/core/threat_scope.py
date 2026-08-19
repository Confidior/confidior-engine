"""Threat-scope model: each threat model is an attacker capability profile.

A threat model is not a flat flag; it is a definition of which attack layers
count against a verdict. This module derives the included attack-category set
from the threat model, so the same evidence grades differently per threat model
without hardcoding a single physical-attack filter.

Label definitions (APPENDIX A, plan/2026-08-16_alpha-speedrun-v2.md):

- software-operator: remote attacker, controls guest OS/software in the CVM,
  no host access. Excludes physical layers.
- cloud-admin: cloud provider admin, host + management plane + hypervisor, no
  hardware access. Excludes physical layers.
- physical-host: physical access to host, can interpose memory, probe buses.
  Includes physical layers.
- nation-state-physical: physical access + advanced capabilities (fabrication,
  supply chain, multi-key). Includes all layers.

Design decision: software-operator and cloud-admin differ in TCB/trust
assumptions, not in physical access; both exclude physical-layer attacks. The
physical tiers include them.
"""

from __future__ import annotations

from src.core.attacks import AttackCategory
from src.core.taxonomy import ThreatModelTier

# Attack categories that require physical access to the host hardware.
PHYSICAL_LAYER_CATEGORIES = frozenset(
    {
        AttackCategory.MEMORY_BUS,
        AttackCategory.ROGUE_MEMORY,
        AttackCategory.ROWHAMMER,
    }
)

# The full set of attack categories the engine can grade.
ALL_CATEGORIES = frozenset(AttackCategory)

# Software-only layer set: everything except physical-layer attacks.
_SOFTWARE_LAYERS = ALL_CATEGORIES - PHYSICAL_LAYER_CATEGORIES

# Per-threat-model included attack categories. This is the derivation: the
# threat model selects a layer set, and the score counts only attacks in it.
THREAT_MODEL_LAYERS: dict[ThreatModelTier, frozenset[AttackCategory]] = {
    ThreatModelTier.SOFTWARE_OPERATOR: _SOFTWARE_LAYERS,
    ThreatModelTier.CLOUD_ADMIN: _SOFTWARE_LAYERS,
    ThreatModelTier.PHYSICAL_HOST: ALL_CATEGORIES,
    ThreatModelTier.NATION_STATE_PHYSICAL: ALL_CATEGORIES,
}

# Default threat model: software-only (matches the engine's stated boundary).
DEFAULT_THREAT_MODEL = ThreatModelTier.CLOUD_ADMIN


def categories_for_threat_model(
    threat_model: ThreatModelTier,
) -> frozenset[AttackCategory]:
    """Return the attack categories that count under a threat model."""
    return THREAT_MODEL_LAYERS.get(threat_model, _SOFTWARE_LAYERS)


def threat_model_includes_physical(threat_model: ThreatModelTier) -> bool:
    """Return True if the threat model grants physical access to the host."""
    return PHYSICAL_LAYER_CATEGORIES.issubset(categories_for_threat_model(threat_model))


class CustomThreatScope:
    """A user-defined threat scope: an explicit set of attack categories to count.

    This lets a buyer express their own threat model beyond the four presets.
    The included set is the layer set; the score counts only attacks in it.
    """

    def __init__(self, name: str, includes: frozenset[AttackCategory]) -> None:
        self.name = name
        self.includes = includes

    def categories(self) -> frozenset[AttackCategory]:
        return self.includes


def load_threat_scope(yaml_path: str) -> CustomThreatScope:
    """Load a custom threat scope from a YAML file.

    Format:
        name: bank-physical
        includes:        # attack categories that count
          - speculative_execution
          - cache_side_channel
          - memory_bus_interposition
          - rowhammer
        excludes: []     # optional explicit exclusions

    ``excludes`` is subtracted from ``includes`` (or from all categories if
    ``includes`` is empty).
    """
    import yaml

    with open(yaml_path) as fh:
        data = yaml.safe_load(fh) or {}

    name = data.get("name", "custom")
    includes_raw = data.get("includes") or []
    excludes_raw = data.get("excludes") or []

    def _parse_cat(value: str) -> AttackCategory:
        try:
            return AttackCategory(value)
        except ValueError:
            raise ValueError(f"Unknown attack category '{value}' in {yaml_path}") from None

    includes = frozenset(_parse_cat(v) for v in includes_raw)
    excludes = frozenset(_parse_cat(v) for v in excludes_raw)

    if includes:
        included = includes - excludes
    else:
        # No explicit includes: start from all categories, subtract excludes.
        included = ALL_CATEGORIES - excludes

    return CustomThreatScope(name=name, includes=included)


def categories_for_scope(
    scope: ThreatModelTier | CustomThreatScope,
) -> frozenset[AttackCategory]:
    """Return the included attack categories for a preset or custom scope."""
    if isinstance(scope, CustomThreatScope):
        return scope.categories()
    return categories_for_threat_model(scope)
