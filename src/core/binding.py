"""Cross-platform binding, archaeology-DB location, and platform enumeration.

Split out of ``risk.py`` (docs/CODEBASE-REVIEW-2026-10-03.md gap 4). This is the
lowest layer: it answers "may these two attestations be combined, and what does
the reference database say" and depends on nothing else in the package."""

from __future__ import annotations

from pathlib import Path

from src.core.attacks import (
    get_unmitigated_attacks,
)
from src.core.taxonomy import (
    EdgeType,
    EvidenceGraph,
    NodeType,
    Platform,
)

_ARCHAEOLOGY_DB_PATH: Path | None = None


def set_archaeology_db_path(path: str | Path) -> None:
    global _ARCHAEOLOGY_DB_PATH
    _ARCHAEOLOGY_DB_PATH = Path(path)


def _platforms_in_graph(graph: EvidenceGraph) -> set[Platform]:
    platforms = set()
    for node in graph.nodes.values():
        if node.node_type == NodeType.QUOTE and node.platform is not None:
            platforms.add(node.platform)
    return platforms


#: Node metadata key holding the shared challenge a quote covers. Two quotes
#: bound to the same session carry the same value; see EdgeType.BOUND_TO.
BINDING_METADATA_KEY = "binding"


def _binding_value(node) -> str | None:
    """The shared challenge a quote records, when it records one."""
    value = (node.metadata or {}).get(BINDING_METADATA_KEY)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def has_verified_cross_platform_binding(graph: EvidenceGraph) -> bool:
    """True when two quote nodes on different platforms attest the same session.

    Sharing material is what makes a second platform corroboration rather than a
    second unrelated quote. Two attestations that cover nothing in common say
    nothing about each other, so platform diversity earns no trust credit and
    the distributed-trust level is out of reach until a binding is present and
    verified. The result is reported either way (see `platform_count` and
    `platforms_bound` on ScoreResult), so an unbound second platform is visible
    without being credited.
    """
    for edge in graph.edges:
        if edge.edge_type != EdgeType.BOUND_TO:
            continue
        source = graph.nodes.get(edge.source_id)
        target = graph.nodes.get(edge.target_id)
        if source is None or target is None:
            continue
        if source.node_type != NodeType.QUOTE or target.node_type != NodeType.QUOTE:
            continue
        if source.platform is None or target.platform is None:
            continue
        if source.platform == target.platform:
            continue
        shared = _binding_value(source)
        if shared is not None and shared == _binding_value(target):
            return True
    return False


def _check_firmware_patched(platform: Platform, tcb_version: str | None = None) -> bool:
    """Check whether the quoted firmware level patches all known firmware-fixable attacks.

    Uses per-attack ``min_svn`` thresholds when ``tcb_version`` is supplied.
    Falls back to the archaeology DB ``patched`` flags otherwise.
    If DB is unavailable, returns False (conservative assumption).
    """
    if _ARCHAEOLOGY_DB_PATH is None or not _ARCHAEOLOGY_DB_PATH.exists():
        return False
    try:
        unpatched = get_unmitigated_attacks(platform, tcb_version=tcb_version)
        return len(unpatched) == 0
    except Exception:
        return False


def _get_tcb_version_for_platform(graph: EvidenceGraph, platform: Platform) -> str | None:
    """Return the TCB version reported by a QUOTE node for the given platform."""
    for node in graph.nodes.values():
        if node.node_type == NodeType.QUOTE and node.platform == platform:
            return node.tcb_version
    return None
