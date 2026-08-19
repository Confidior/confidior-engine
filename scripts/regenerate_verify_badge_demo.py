"""Regenerate the verify-badge CLI demo fixture.

Builds a deterministic AssuranceEvaluation (the RedPill-style sample:
Level 2, HIGH, D/46 under the default cloud-admin threat model) and renders
the badge with a reproducible signature, so `confidior verify-badge --from-fixture
tests/fixtures/verify-badge-demo` demonstrates the verification path
end-to-end without requiring a real bundle.

The signature and bundle_id here are FIXTURE values, not real
attestation data. The fixture exists to make the CLI's
verify-badge flow copy-paste-runnable.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.core.taxonomy import (
    AssuranceEvaluation,
    AssuranceLevel,
    ResidualRiskTier,
    ScoreResult,
)
from src.export.badge import generate_badge_svg

FIXTURE_DIR = (
    Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "verify-badge-demo"
)
BUNDLE_ID = "bundle-demo-20260101000000"
LEVEL = AssuranceLevel.HARDWARE_ATTESTED  # 2
SIGNATURE = "a" * 128  # 64-byte fixture signature (not a real attestation)

DIMENSIONS = {
    "platform": "Intel TDX",
    "measure": "match",
    "attacks": "2 unmitigated",
    "captured": "2026-08-14",
    "debug": "OFF",
    "provenance": "absent",
    "score": "D · 46/100",
}


def _build_assurance() -> AssuranceEvaluation:
    return AssuranceEvaluation(
        level=LEVEL,
        residual_risk=ResidualRiskTier.HIGH,
        boundary_statement="Demo fixture for the verify-badge CLI flow.",
        score=ScoreResult(total=46, subscores={}, grade="D", profile="default"),
        dimensions=DIMENSIONS,
    )


def main() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    assurance = _build_assurance()

    svg = generate_badge_svg(
        assurance,
        bundle_id=BUNDLE_ID,
        signature_hex=SIGNATURE,
        dimensions=DIMENSIONS,
    )
    badge_path = FIXTURE_DIR / "badge.svg"
    badge_path.write_text(svg)
    print(f"wrote {badge_path} ({len(svg)} bytes)")

    manifest = {
        "bundle_id": BUNDLE_ID,
        "level": int(LEVEL),
        "signature": SIGNATURE,
        "dimensions": DIMENSIONS,
        "note": (
            "Fixture signature ('a' * 128) is not a real attestation. "
            "Real verifications supply the actual bundle signature hex."
        ),
    }
    manifest_path = FIXTURE_DIR / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"wrote {manifest_path}")


if __name__ == "__main__":
    main()
