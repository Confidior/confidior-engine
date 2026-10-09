"""Temporal freshness evaluation for an evidence graph.

Split out of ``risk.py`` (docs/CODEBASE-REVIEW-2026-10-03.md gap 4). Answers only
"is this evidence still current", from node timestamps and TTLs."""

from __future__ import annotations

from datetime import timezone

from src.core.clock import (
    utc_now,
)
from src.core.taxonomy import (
    EvidenceGraph,
    TemporalFreshness,
)

_DEFAULT_TTL_SECONDS = 1800  # 30 minutes


_FRESHNESS_SCORE = {
    TemporalFreshness.FRESH: 20,
    TemporalFreshness.AGING: 12,
    TemporalFreshness.STALE: 0,
}


def compute_temporal_freshness(
    graph: EvidenceGraph, default_ttl: int = _DEFAULT_TTL_SECONDS
) -> TemporalFreshness:
    """Evaluate evidence freshness based on node timestamps and TTLs.

    Returns FRESH (all nodes within TTL), AGING (some past 80% TTL),
    or STALE (any node past TTL). Nodes without timestamps are skipped.
    """
    now = utc_now()
    has_aging = False
    for node in graph.nodes.values():
        ts = node.timestamp
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        ttl = node.ttl_seconds if node.ttl_seconds is not None else default_ttl
        age = (now - ts).total_seconds()
        if age >= ttl:
            return TemporalFreshness.STALE
        if age >= ttl * 0.8:
            has_aging = True
    if has_aging:
        return TemporalFreshness.AGING
    return TemporalFreshness.FRESH
