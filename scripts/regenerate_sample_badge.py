"""Regenerate the sample badge for the web UI early-access page.

Builds a realistic AssuranceEvaluation (the RedPill-style verdict: Level 2,
CRITICAL, F/33) and renders it with the current badge generator, so the
sample matches the confidior.com aesthetic.
"""

from pathlib import Path

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
    residual_risk=ResidualRiskTier.CRITICAL,
    boundary_statement="Sample badge for the early-access page.",
    score=ScoreResult(total=33, subscores={}, grade="F", profile="default"),
    dimensions={
        "platform": "Intel TDX",
        "measure": "match",
        "attacks": "6 unmitigated",
        "captured": "2026-08-14",
        "debug": "OFF",
        "provenance": "absent",
        "score": "F · 33/100",
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
