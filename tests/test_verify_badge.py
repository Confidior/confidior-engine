"""Tests for badge commitment verification and SVG attribute extraction."""

from __future__ import annotations

from src.core.risk import compute_assurance_level
from src.core.taxonomy import AssuranceEvaluation, AssuranceLevel, EvidenceGraph, EvidenceNode, NodeType, Platform, ResidualRiskTier, ScoreResult, TemporalFreshness
from pathlib import Path

from src.cli.main import main
from src.export.badge import (
    compute_badge_commitment,
    extract_badge_attributes,
    generate_badge_svg,
    verify_badge,
)


def _simple_assurance(level: AssuranceLevel = AssuranceLevel.HARDWARE_ATTESTED) -> AssuranceEvaluation:
    return AssuranceEvaluation(
        level=level,
        residual_risk=ResidualRiskTier.HIGH,
        boundary_statement="test",
        label=f"Level {level.value}",
        temporal_freshness=TemporalFreshness.FRESH,
        dimensions={"measurement": "verified", "debug": "OFF"},
        score=ScoreResult(total=60, subscores={"attestation": 8, "trust": 12, "threat": 10, "freshness": 20, "compliance": 10}, grade="C"),
    )


def test_verify_badge_matches_with_correct_inputs():
    bundle_id = "bundle-20250101000000"
    level = 2
    signature_hex = "a" * 128
    dimensions = {"measurement": "verified", "debug": "OFF"}
    commitment = compute_badge_commitment(bundle_id, level, signature_hex, dimensions)
    assert verify_badge(commitment, bundle_id, level, signature_hex, dimensions) is True


def test_verify_badge_fails_with_wrong_signature():
    bundle_id = "bundle-20250101000001"
    level = 2
    signature_hex = "a" * 128
    dimensions = {"measurement": "verified"}
    commitment = compute_badge_commitment(bundle_id, level, signature_hex, dimensions)
    assert verify_badge(commitment, bundle_id, level, "b" * 128, dimensions) is False


def test_verify_badge_fails_with_missing_dimensions():
    bundle_id = "bundle-20250101000002"
    level = 2
    signature_hex = "a" * 128
    dimensions = {"measurement": "verified"}
    commitment = compute_badge_commitment(bundle_id, level, signature_hex, dimensions)
    assert verify_badge(commitment, bundle_id, level, signature_hex) is False


def test_extract_badge_attributes_from_generated_svg():
    assurance = _simple_assurance()
    bundle_id = "bundle-abc"
    signature_hex = "c" * 128
    svg = generate_badge_svg(assurance, bundle_id, signature_hex, dimensions={"measurement": "verified", "debug": "OFF"})
    attrs = extract_badge_attributes(svg)
    assert attrs["commitment"] == compute_badge_commitment(bundle_id, assurance.level.value, signature_hex, {"measurement": "verified", "debug": "OFF"})
    assert attrs["bundle_id"] == bundle_id
    assert attrs["level"] == assurance.level.value
    assert attrs["score"] == 60
    assert attrs["grade"] == "C"
    assert attrs["score_profile"] == "default"
    assert attrs["measurement_verified"] is True
    assert attrs["debug_disabled"] is True
    assert attrs["dimensions"] == {"measurement": "verified", "debug": "OFF"}


def test_extract_badge_attributes_empty_svg():
    attrs = extract_badge_attributes("<svg></svg>")
    assert "commitment" not in attrs


def test_generated_badge_round_trip_through_verify_badge():
    graph = EvidenceGraph()
    graph.add_node(EvidenceNode("q1", NodeType.QUOTE, platform=Platform.IntelTDX, measurement="aa" * 48, debug_disabled=True))
    assurance = compute_assurance_level(graph)
    bundle_id = "bundle-roundtrip"
    signature_hex = "d" * 128
    svg = generate_badge_svg(assurance, bundle_id, signature_hex, dimensions=assurance.dimensions)
    attrs = extract_badge_attributes(svg)
    assert verify_badge(
        str(attrs["commitment"]),
        str(attrs["bundle_id"]),
        int(attrs["level"]),  # type: ignore[arg-type]
        signature_hex,
        attrs.get("dimensions"),
    ) is True


def test_cli_verify_badge_with_explicit_args(tmp_path: Path):
    assurance = _simple_assurance()
    bundle_id = "bundle-cli"
    signature_hex = "e" * 128
    dimensions = {"measurement": "verified", "debug": "OFF"}
    svg = generate_badge_svg(assurance, bundle_id, signature_hex, dimensions=dimensions)
    badge_path = tmp_path / "badge.svg"
    badge_path.write_text(svg)

    rc = main([
        "verify-badge",
        "--badge-svg", str(badge_path),
        "--signature", signature_hex,
    ])
    assert rc == 0


def test_cli_verify_badge_fails_with_wrong_signature(tmp_path: Path):
    assurance = _simple_assurance()
    bundle_id = "bundle-cli-fail"
    signature_hex = "f" * 128
    dimensions = {"measurement": "verified"}
    svg = generate_badge_svg(assurance, bundle_id, signature_hex, dimensions=dimensions)
    badge_path = tmp_path / "badge.svg"
    badge_path.write_text(svg)

    rc = main([
        "verify-badge",
        "--badge-svg", str(badge_path),
        "--signature", "00" * 64,
    ])
    assert rc == 1


def test_cli_verify_badge_explicit_dimensions():
    bundle_id = "bundle-cli-dims"
    level = 2
    signature_hex = "aa" * 64
    dimensions = {"measurement": "verified", "debug": "OFF"}
    commitment = compute_badge_commitment(bundle_id, level, signature_hex, dimensions)
    rc = main([
        "verify-badge",
        "--commitment", commitment,
        "--bundle-id", bundle_id,
        "--level", str(level),
        "--signature", signature_hex,
        "--dimension", "measurement=verified",
        "--dimension", "debug=OFF",
    ])
    assert rc == 0
