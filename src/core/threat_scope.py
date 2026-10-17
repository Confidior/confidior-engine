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
from src.core.taxonomy import AdversaryPosition, ThreatModelTier

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

#: Per-threat-model granted adversary positions (docs/THREAT-MODELS.md).
#: An attack counts when every position it requires is granted. This is the
#: dimension that distinguishes software-operator from cloud-admin: the host
#: position is granted by one and not the other, so hypervisor-required
#: attacks drop out under a model that declares the host trusted.
THREAT_MODEL_POSITIONS: dict[ThreatModelTier, frozenset[AdversaryPosition]] = {
    ThreatModelTier.SOFTWARE_OPERATOR: frozenset({AdversaryPosition.IN_GUEST}),
    ThreatModelTier.CLOUD_ADMIN: frozenset(
        {AdversaryPosition.IN_GUEST, AdversaryPosition.HOST}
    ),
    ThreatModelTier.PHYSICAL_HOST: frozenset(
        {AdversaryPosition.IN_GUEST, AdversaryPosition.HOST, AdversaryPosition.PHYSICAL}
    ),
    ThreatModelTier.NATION_STATE_PHYSICAL: frozenset(AdversaryPosition),
}

# Default threat model: software-only (matches the engine's stated boundary).
DEFAULT_THREAT_MODEL = ThreatModelTier.CLOUD_ADMIN


def positions_for_threat_model(
    threat_model: ThreatModelTier,
) -> frozenset[AdversaryPosition]:
    """Return the adversary positions a threat model grants."""
    return THREAT_MODEL_POSITIONS.get(threat_model, THREAT_MODEL_POSITIONS[DEFAULT_THREAT_MODEL])


def categories_for_threat_model(
    threat_model: ThreatModelTier,
) -> frozenset[AttackCategory]:
    """Return the attack categories that count under a threat model."""
    return THREAT_MODEL_LAYERS.get(threat_model, _SOFTWARE_LAYERS)


def threat_model_includes_physical(threat_model: ThreatModelTier) -> bool:
    """Return True if the threat model grants physical access to the host."""
    return PHYSICAL_LAYER_CATEGORIES.issubset(categories_for_threat_model(threat_model))


class CustomThreatScope:
    """A user-defined threat scope: which positions are granted, and which
    attack categories count.

    This lets a buyer express their own threat model beyond the four presets.
    It carries both dimensions the presets use, because the presets gate on
    *two* things and a custom scope that kept only one was strictly blunter
    than the thing it replaced:

    ``positions`` — where the attacker must stand (docs/THREAT-MODELS.md).
    An attack counts only when every position it requires is granted. This is
    the dimension that separates a model declaring the host trusted from one
    that does not.

    ``categories`` — the mechanism a buyer may additionally scope away
    (e.g. "we do not care about speculative-execution classes").

    Both filters apply: an attack must pass the position gate *and* be in the
    category set. Defaulting ``positions`` to every position keeps the old
    category-only behaviour available, but the caller has to say so.
    """

    def __init__(
        self,
        name: str,
        includes: frozenset[AttackCategory],
        positions: frozenset[AdversaryPosition] | None = None,
    ) -> None:
        self.name = name
        self.includes = includes
        self.positions = (
            frozenset(AdversaryPosition) if positions is None else frozenset(positions)
        )

    def categories(self) -> frozenset[AttackCategory]:
        return self.includes

    def granted_positions(self) -> frozenset[AdversaryPosition]:
        return self.positions


def load_threat_scope(yaml_path: str) -> CustomThreatScope:
    """Load a custom threat scope from a YAML file.

    Format:
        name: bank-physical
        positions:            # where the attacker stands (required to narrow)
          - in-guest
          - host
          - physical
        includes:             # attack categories that count
          - speculative_execution
          - cache_side_channel
          - memory_bus_interposition
          - rowhammer
        excludes: []          # optional explicit exclusions

    ``positions`` defaults to every position, which keeps a category-only
    scope working as it did before. Stating positions is what makes a custom
    scope as precise as the presets: omitting them is the only way to get an
    attack set wider than any preset.

    ``excludes`` is subtracted from ``includes`` (or from all categories if
    ``includes`` is empty).
    """
    import yaml

    with open(yaml_path) as fh:
        data = yaml.safe_load(fh) or {}

    name = data.get("name", "custom")
    includes_raw = data.get("includes") or []
    excludes_raw = data.get("excludes") or []
    positions_raw = data.get("positions")

    def _parse_cat(value: str) -> AttackCategory:
        try:
            return AttackCategory(value)
        except ValueError:
            raise ValueError(f"Unknown attack category '{value}' in {yaml_path}") from None

    def _parse_pos(value: str) -> AdversaryPosition:
        try:
            return AdversaryPosition(value)
        except ValueError:
            raise ValueError(f"Unknown adversary position '{value}' in {yaml_path}") from None

    includes = frozenset(_parse_cat(v) for v in includes_raw)
    excludes = frozenset(_parse_cat(v) for v in excludes_raw)
    positions = (
        frozenset(AdversaryPosition)
        if positions_raw is None
        else frozenset(_parse_pos(v) for v in positions_raw)
    )

    if includes:
        included = includes - excludes
    else:
        # No explicit includes: start from all categories, subtract excludes.
        included = ALL_CATEGORIES - excludes

    return CustomThreatScope(name=name, includes=included, positions=positions)


def categories_for_scope(
    scope: ThreatModelTier | CustomThreatScope,
) -> frozenset[AttackCategory]:
    """Return the included attack categories for a preset or custom scope."""
    if isinstance(scope, CustomThreatScope):
        return scope.categories()
    return categories_for_threat_model(scope)
