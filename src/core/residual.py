"""Residual-risk and threat-scope analysis: what remains after mitigations.

Split out of ``risk.py`` (docs/CODEBASE-REVIEW-2026-10-03.md gap 4). Holds the
threat-scope filter, TCB liveness, known-attack coverage and residual-risk
escalation. Depends on ``binding``."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeAlias

from src.core.attacks import (
    MitigationDifficulty,
    TEEAttack,
    get_unmitigated_attacks,
)
from src.core.binding import (
    _check_firmware_patched,
    _get_tcb_version_for_platform,
    _platforms_in_graph,
)
from src.core.taxonomy import (
    EvidenceClass,
    EvidenceGraph,
    NodeType,
    Platform,
    ResidualRiskTier,
    TCBStatus,
    ThreatModelTier,
)

# A threat scope is either a preset ThreatModelTier or a custom category set.
# Imported under TYPE_CHECKING to avoid a runtime circular import.
if TYPE_CHECKING:
    from src.core.threat_scope import CustomThreatScope


ThreatScope: TypeAlias = "ThreatModelTier | CustomThreatScope"


# Default threat model: software-only (matches the engine's stated boundary).
# The layer-set derivation lives in src/core/threat_scope.py.
DEFAULT_THREAT_MODEL = ThreatModelTier.CLOUD_ADMIN


def weakest_evidence_class(graph: EvidenceGraph) -> EvidenceClass:
    """The weakest evidence class across the graph's nodes.

    A verdict is only as strong as its weakest input, so the class reported for
    a whole verdict is the minimum on the provenance ladder. Nodes that state
    no class count as UNKNOWN, an unstated provenance never reads as strong.
    """
    classes = [
        n.evidence_class if n.evidence_class is not None else EvidenceClass.UNKNOWN
        for n in graph.nodes.values()
    ]
    if not classes:
        return EvidenceClass.UNKNOWN
    return min(classes, key=lambda c: c.provenance_rank)


def _attacks_in_threat_model(
    attacks: list[TEEAttack], threat_model: ThreatModelTier | "CustomThreatScope"
) -> list[TEEAttack]:
    """Filter attacks to those the threat scope can mount.

    A scope is two filters, and both apply. An attack counts only when:

    1. **Position.** Every adversary position it requires is granted. This is
       the dimension that makes software-operator and cloud-admin differ: the
       host position is granted by one and not the other, so hypervisor-
       required attacks drop out under a model that declares the host trusted
       (docs/THREAT-MODELS.md).
    2. **Category.** The attack's mechanism is in the scope's category set,
       where the scope narrows by mechanism at all.

    Presets define positions and take every category. A custom scope defines
    both, so it can be at least as precise as a preset. It used to apply only
    the category filter, which meant the extensible path was blunter than the
    fixed one: a buyer who wrote their own scope silently lost the position
    gate and paid for attacks their model had declared unreachable.

    Attacks with no position and no category are kept: unclassified attacks
    conservatively count under every model.
    """
    from src.core.threat_scope import (
        CustomThreatScope,
        positions_for_threat_model,
    )

    if isinstance(threat_model, CustomThreatScope):
        granted = threat_model.granted_positions()
        included = threat_model.categories()
        return [
            a
            for a in attacks
            if (not a.adversary_position or a.adversary_position.issubset(granted))
            and (a.category is None or a.category in included)
        ]

    granted = positions_for_threat_model(threat_model)
    return [
        a
        for a in attacks
        if not a.adversary_position or a.adversary_position.issubset(granted)
    ]


def _resolve_tcb_statuses(
    graph: EvidenceGraph, tcb_db_path: str | None = None, tcb_fmspc: str | None = None
) -> dict[str, TCBStatus]:
    """Resolve each platform's TCB status against a reference.

    Reference sources, in order: the explicit local reference DB (seeded
    archaeology DB), then the live vendor TCB lookup (Intel PCS v4, keyed by
    the platform FMSPC). When no reference is available the status is UNKNOWN
    (honest default; the mechanism never fabricates a reference). The DB path
    is explicit, never read from ambient global state.
    """
    from src.core.tcb import load_current_tcb_reference, resolve_tcb_status

    resolutions: dict[str, TCBStatus] = {}
    for node in graph.nodes.values():
        if node.node_type != NodeType.QUOTE or not node.platform:
            continue
        platform = node.platform.value
        if platform in resolutions:
            continue
        reference = None
        if tcb_db_path:
            reference = load_current_tcb_reference(platform, db_path=tcb_db_path)
        if reference is None:
            # Fall back to the live vendor lookup (Intel TDX only; AMD has no
            # public current-TCB endpoint). Requires the platform FMSPC.
            from src.tools.tcb_lookup import fetch_current_tcb

            fetched = fetch_current_tcb(node.platform, fmspc=tcb_fmspc)
            if fetched is not None:
                reference = fetched.version
        resolution = resolve_tcb_status(node.tcb_version, reference, platform=platform)
        resolutions[platform] = resolution.status
    return resolutions


def _known_attack_count(
    graph: EvidenceGraph, threat_model: ThreatScope = DEFAULT_THREAT_MODEL
) -> tuple[int, int]:
    """Count known attacks for the platforms present in the graph.

    This is the coverage signal: how many attacks the engine knows about for
    the platform(s) under evaluation. A low count means the platform is less
    measured, not safer. Used to frame the boundary statement honestly.

    Returns ``(in_scope, known_total)``. Both are reported because they answer
    different questions: the total says how much research exists for the
    platform, and the in-scope count says how much of it the grade actually
    used. Reporting only the total next to a score that used none of them is
    the contradiction this shape exists to make impossible.
    """
    from src.core.attacks import get_attacks_for_platform

    platforms = _platforms_in_graph(graph)
    known: set[str] = set()
    in_scope: set[str] = set()
    for p in platforms:
        attacks = get_attacks_for_platform(p)
        known.update(a.name for a in attacks)
        in_scope.update(a.name for a in _attacks_in_threat_model(attacks, threat_model))
    return len(in_scope), len(known)


# Platforms whose TCB is a firmware SVN (monotonic, comparable against a
# vendor reference). Nitro is the exception: its TCB is an image-identity
# digest, not an SVN, so the liveness comparison does not apply.
_NON_SVN_PLATFORMS = frozenset({Platform.AWSNitro})


def _is_svn_platform(platform: Platform) -> bool:
    return platform not in _NON_SVN_PLATFORMS


def _tcb_temporal_summary(
    graph: EvidenceGraph,
    tcb_db_path: str | None = None,
    tcb_fmspc: str | None = None,
    threat_model: ThreatScope = DEFAULT_THREAT_MODEL,
) -> str:
    """Report TCB liveness and patched-ness separately, per platform.

    Liveness: is the quoted TCB current vs the reference (local DB or live
    lookup). Patched-ness: how many known attacks the quoted TCB is patched
    against (quoted SVN >= the attack's fix threshold). Newness and patched
    status are different axes; both are reported.

    Non-SVN platforms (Nitro) get "not applicable": the temporal signal is
    measurement match, not firmware liveness.
    """
    from src.core.attacks import get_attacks_for_platform, get_unmitigated_attacks

    lines: list[str] = []
    resolutions = _resolve_tcb_statuses(graph, tcb_db_path=tcb_db_path, tcb_fmspc=tcb_fmspc)
    for node in graph.nodes.values():
        if node.node_type != NodeType.QUOTE or not node.platform:
            continue
        platform = node.platform
        if not _is_svn_platform(platform):
            lines.append(
                f"{platform.value}: TCB liveness not applicable (no SVN); "
                "temporal signal is measurement match"
            )
            continue
        status = resolutions.get(platform.value, TCBStatus.UNKNOWN)
        quoted = node.tcb_version or "unknown"
        # Patched-ness: unmitigated attacks given the quoted TCB version.
        # Scoped: "patched against 0 of 5" is a claim about what the verdict
        # measured, so it must count the same attacks the score counted.
        unmitigated = _attacks_in_threat_model(
            get_unmitigated_attacks(platform, tcb_version=node.tcb_version), threat_model
        )
        known = _attacks_in_threat_model(get_attacks_for_platform(platform), threat_model)
        patched = len(known) - len(unmitigated)
        lines.append(
            f"{platform.value}: TCB {status.value} (quoted {quoted}); "
            f"patched against {patched} of {len(known)} known attacks"
        )
    return "\n".join(lines)


def _collect_attack_boundaries(
    graph: EvidenceGraph,
    threat_model: ThreatScope = DEFAULT_THREAT_MODEL,
) -> list[str]:
    """Collect boundary statements from applicable TEE attacks.

    Applicability is the threat scope's, not the platform's. A scope that
    declares an attack unreachable must not narrate it: a verdict that scored 0
    of 5 attacks while listing all 5 as unmitigated is internally contradictory,
    and the narrative is the part a human reads. The excluded ones are reported
    separately as out-of-scope, so narrowing a scope stays visible rather than
    silently shrinking the disclosure.
    """
    boundaries = []
    for platform in _platforms_in_graph(graph):
        tcb_version = _get_tcb_version_for_platform(graph, platform)
        firmware_patched = _check_firmware_patched(platform, tcb_version)
        attacks = _attacks_in_threat_model(
            get_unmitigated_attacks(
                platform, tcb_version=tcb_version, firmware_patched=firmware_patched
            ),
            threat_model,
        )
        for attack in attacks:
            if attack.boundary_statement:
                boundaries.append(f"[{attack.name}] {attack.boundary_statement}")
    return boundaries


def _collect_out_of_scope_attack_names(
    graph: EvidenceGraph,
    threat_model: ThreatScope = DEFAULT_THREAT_MODEL,
) -> list[str]:
    """Known attacks the scope excluded, named so the narrowing is disclosed."""
    excluded: list[str] = []
    for platform in _platforms_in_graph(graph):
        tcb_version = _get_tcb_version_for_platform(graph, platform)
        firmware_patched = _check_firmware_patched(platform, tcb_version)
        known = get_unmitigated_attacks(
            platform, tcb_version=tcb_version, firmware_patched=firmware_patched
        )
        in_scope = set(id(a) for a in _attacks_in_threat_model(known, threat_model))
        excluded.extend(a.name for a in known if id(a) not in in_scope)
    return sorted(set(excluded))


def _compute_residual_risk_from_attacks(
    graph: EvidenceGraph,
    base_risk: ResidualRiskTier,
    threat_model: ThreatScope = DEFAULT_THREAT_MODEL,
) -> tuple[ResidualRiskTier, list[TEEAttack]]:
    """Upgrade residual risk based on applicable software-applicable TEE attacks.

    Physical-layer attacks are excluded unless the threat model grants physical
    access. For the remaining software-applicable attacks, cost and mitigation
    difficulty determine risk escalation:
    - $10-$50 or unknown-cost attacks -> escalate by one tier
    - $1,000+ attacks (TEE.fail) or unknown cost -> escalates by one tier
    - Hardware redesign required -> escalates by one additional tier
    """
    applicable_attacks: list[TEEAttack] = []
    for platform in _platforms_in_graph(graph):
        tcb_version = _get_tcb_version_for_platform(graph, platform)
        firmware_patched = _check_firmware_patched(platform, tcb_version)
        applicable_attacks.extend(
            get_unmitigated_attacks(
                platform, tcb_version=tcb_version, firmware_patched=firmware_patched
            )
        )

    # Physical-layer attacks escalate residual risk only for threat models that
    # grant physical access; software-only threat models exclude them.
    applicable_attacks = _attacks_in_threat_model(applicable_attacks, threat_model)

    if not applicable_attacks:
        return base_risk, []

    _CHEAP_COST = frozenset({"~$10", "~$50"})
    has_cheap_attack = any(a.cost_to_attack in _CHEAP_COST for a in applicable_attacks)
    has_no_mitigation = any(
        a.mitigation_difficulty == MitigationDifficulty.NO_MITIGATION for a in applicable_attacks
    )
    has_hardware_redesign = any(
        a.mitigation_difficulty == MitigationDifficulty.HARDWARE_REDESIGN
        for a in applicable_attacks
    )

    if has_cheap_attack or has_no_mitigation:
        return ResidualRiskTier.CRITICAL, applicable_attacks

    if has_hardware_redesign:
        if base_risk == ResidualRiskTier.LOW:
            return ResidualRiskTier.MEDIUM, applicable_attacks
        elif base_risk == ResidualRiskTier.MEDIUM:
            return ResidualRiskTier.HIGH, applicable_attacks
        else:
            return ResidualRiskTier.CRITICAL, applicable_attacks

    if base_risk == ResidualRiskTier.LOW:
        return ResidualRiskTier.MEDIUM, applicable_attacks

    return base_risk, applicable_attacks
