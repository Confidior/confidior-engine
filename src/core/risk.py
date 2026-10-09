"""Assurance level computation -- facade over the five modules below.

The implementation lives in ``binding``, ``freshness``, ``residual``,
``scoring`` and ``assurance`` (split out of this file, see
docs/CODEBASE-REVIEW-2026-10-03.md gap 4). This module re-exports the
public API so every existing import keeps working.

One caveat about the re-exports, because it is a real hazard rather than a
technicality: ``_ARCHAEOLOGY_DB_PATH`` is rebound by
``binding.set_archaeology_db_path``, and a ``from x import y`` binding is a
*snapshot*. Reading it from here therefore yields whatever the value was when
this module was first imported, which is ``None`` for the normal startup order.
Anything that needs the current value must read ``binding._ARCHAEOLOGY_DB_PATH``
-- the module attribute, not the re-export. The name stays in ``__all__`` only so
that existing imports of this facade keep resolving.
"""

from __future__ import annotations

from src.core.assurance import (
    compute_assurance_level,
)
from src.core.binding import (
    _ARCHAEOLOGY_DB_PATH,
    BINDING_METADATA_KEY,
    _check_firmware_patched,
    has_verified_cross_platform_binding,
    set_archaeology_db_path,
)
from src.core.freshness import (
    compute_temporal_freshness,
)
from src.core.residual import (
    DEFAULT_THREAT_MODEL,
    ThreatScope,
    _attacks_in_threat_model,
    _resolve_tcb_statuses,
    _tcb_temporal_summary,
    weakest_evidence_class,
)
from src.core.scoring import (
    _get_score_profile,
    compute_numeric_score,
)

__all__ = [
    "BINDING_METADATA_KEY",
    "DEFAULT_THREAT_MODEL",
    "ThreatScope",
    "_ARCHAEOLOGY_DB_PATH",
    "_attacks_in_threat_model",
    "_check_firmware_patched",
    "_get_score_profile",
    "_resolve_tcb_statuses",
    "_tcb_temporal_summary",
    "compute_assurance_level",
    "compute_numeric_score",
    "compute_temporal_freshness",
    "has_verified_cross_platform_binding",
    "set_archaeology_db_path",
    "weakest_evidence_class",
]
