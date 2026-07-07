from src.core.taxonomy import (
    AssuranceEvaluation,
    AssuranceLevel,
    ComplianceMapping,
    ComplianceStatus,
    ControlFamily,
    EvidenceBundle,
    PolicyEvaluation,
    PolicyDecision,
    ResidualRiskTier,
)
from src.export.badge import generate_badge_svg
from datetime import datetime, timedelta


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
