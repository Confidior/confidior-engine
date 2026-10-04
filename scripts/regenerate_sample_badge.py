"""Regenerate the sample badge for the web UI early-access page.

Builds a synthetic AssuranceEvaluation shaped like a RedPill-style verdict
(Level 2, HIGH, D/46 under the default cloud-admin threat model) and renders
it with the current badge generator, so the sample matches the confidior.com
aesthetic. The numbers are a frozen illustration, not the live verdict for
the RedPill quote (see `data/registry.yaml` for the current one).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.core.taxonomy import (
    AssuranceEvaluation,
    AssuranceLevel,
    ResidualRiskTier,
    ScoreResult,
)
from src.export.badge import generate_badge_svg

OUT = Path(__file__).resolve().parent.parent / "src" / "web" / "static" / "badge-sample.svg"

assurance = AssuranceEvaluation(
    level=AssuranceLevel.HARDWARE_ATTESTED,
    residual_risk=ResidualRiskTier.HIGH,
    boundary_statement="Sample badge for the early-access page.",
    score=ScoreResult(total=46, subscores={}, grade="D", profile="default"),
    dimensions={
        "platform": "Intel TDX",
        "measure": "match",
        "attacks": "2 unmitigated",
        "captured": "2026-08-14",
        "debug": "OFF",
        "provenance": "absent",
        "score": "D · 46/100",
    },
)

svg = generate_badge_svg(
    assurance,
    bundle_id="sample",
    signature_hex="",
    dimensions=assurance.dimensions,
)
OUT.write_text(svg)
print(f"wrote {OUT} ({len(svg)} bytes)")
