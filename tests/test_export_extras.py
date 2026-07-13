from datetime import datetime, timedelta

from src.core.taxonomy import (
    AssuranceEvaluation,
    AssuranceLevel,
    ComplianceMapping,
    ComplianceStatus,
    ControlFamily,
    EvidenceBundle,
    ResidualRiskTier,
)
from src.export.badge import generate_badge_svg


def test_generate_badge_svg_for_each_level():
    for level in AssuranceLevel:
        assurance = AssuranceEvaluation(
            level=level,
            residual_risk=ResidualRiskTier.HIGH,
            boundary_statement="test",
        )
        svg = generate_badge_svg(assurance)
        assert "<svg" in svg
        assert f"Level {level.value}" in svg
        assert "</svg>" in svg


def test_badge_svg_contains_color():
    assurance = AssuranceEvaluation(
        level=AssuranceLevel.HARDWARE_ATTESTED,
        residual_risk=ResidualRiskTier.HIGH,
        boundary_statement="test",
    )
    svg = generate_badge_svg(assurance)
    assert "#df3c30" in svg


def test_badge_svg_attestation_dimensions():
    assurance = AssuranceEvaluation(
        level=AssuranceLevel.HARDWARE_ATTESTED,
        residual_risk=ResidualRiskTier.HIGH,
        boundary_statement="test",
    )
    svg = generate_badge_svg(assurance, measurement_verified=True, freshness="FRESH", debug_disabled=False, tcb_version="v2.1")
    assert 'data-measurement-verified="true"' in svg
    assert 'data-freshness="FRESH"' in svg
    assert 'data-debug-disabled="false"' in svg
    assert 'data-tcb-version="v2.1"' in svg
    assert "measurement=✓" in svg
    assert "freshness=FRESH" in svg
    assert "debug=ON" in svg
    assert "tcb=v2.1" in svg


def test_badge_svg_attestation_no_dimensions():
    assurance = AssuranceEvaluation(
        level=AssuranceLevel.NONE,
        residual_risk=ResidualRiskTier.LOW,
        boundary_statement="test",
    )
    svg = generate_badge_svg(assurance)
    assert "data-measurement" not in svg
    assert "data-freshness" not in svg


def test_badge_svg_data_attributes():
    assurance = AssuranceEvaluation(
        level=AssuranceLevel.NONE,
        residual_risk=ResidualRiskTier.LOW,
        boundary_statement="test",
    )
    svg = generate_badge_svg(assurance, bundle_id="b-1", signature_hex="abc", debug_disabled=True)
    assert 'data-commitment="' in svg
    assert 'data-bundle-id="b-1"' in svg
    assert 'data-debug-disabled="true"' in svg
    assert "debug=OFF" in svg


def test_compliance_mapping_roundtrip_preserves_family():
    bundle = EvidenceBundle(
        bundle_id="test-family",
        timestamp=datetime.now(),
        expires_at=datetime.now() + timedelta(days=1),
        workload="test",
        compliance_mappings=[
            ComplianceMapping(
                control_id="OPS-32.01B",
                control_family=ControlFamily.INFRASTRUCTURE,
                status=ComplianceStatus.SATISFIED,
                gap_description=None,
            ),
            ComplianceMapping(
                control_id="CRY-01.01B",
                control_family=ControlFamily.CRYPTOGRAPHY,
                status=ComplianceStatus.PARTIAL,
                gap_description="Missing key rotation evidence",
            ),
        ],
    )

    d = bundle.to_dict()
    restored = EvidenceBundle.from_dict(d)

    assert len(restored.compliance_mappings) == 2
    assert restored.compliance_mappings[0].control_family == ControlFamily.INFRASTRUCTURE
    assert restored.compliance_mappings[1].control_family == ControlFamily.CRYPTOGRAPHY
    assert restored.compliance_mappings[1].gap_description == "Missing key rotation evidence"
