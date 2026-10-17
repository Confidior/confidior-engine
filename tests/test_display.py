"""Tests for the display model: the values every surface reads.

The point of these tests is not the phrasing; it is that the badge, the report,
and the explain lines are derived from one place and therefore cannot disagree
about a number.
"""

from __future__ import annotations

from pathlib import Path

from src.core.risk import compute_assurance_level
from src.core.taxonomy import EvidenceGraph, ThreatModelTier
from src.export.display import (
    BAD,
    GOOD,
    WARN,
    badge_dims,
    badge_items,
    coverage_items,
    explain_lines,
    report_items,
)

FIXTURE = Path(__file__).parent / "fixtures" / "tdx" / "redpill-gateway-quote.hex"


def _evaluation(threat_model: ThreatModelTier = ThreatModelTier.CLOUD_ADMIN):
    graph = EvidenceGraph()
    from src.ingest.adapters.tdx import parse_tdx_quote

    graph.add_node(parse_tdx_quote(FIXTURE.read_text()))
    return compute_assurance_level(graph, threat_model=threat_model)


def test_badge_carries_the_five_items():
    items = badge_items(_evaluation())
    assert [i.key for i in items] == ["grade", "risk", "split", "evidence", "attacks"]

    by_key = {i.key: i for i in items}
    assert by_key["grade"].value.endswith("/100")
    assert by_key["grade"].tone == BAD
    assert by_key["risk"].value in ("HIGH", "CRITICAL", "MEDIUM", "LOW")
    # The split is what a buyer acts on: which half of the claim is weak.
    assert "/" in by_key["split"].value
    # A verdict never claims stronger provenance than its weakest input.
    assert by_key["evidence"].value == "unknown"
    # The attacks that counted, with the position they required.
    assert "Heckler" in by_key["attacks"].value
    assert "(host)" in by_key["attacks"].value


def test_badge_tone_tracks_severity():
    items = {i.key: i for i in badge_items(_evaluation())}
    assert items["grade"].tone == BAD  # D grade
    assert items["risk"].tone == BAD  # HIGH residual risk
    # Heckler is half-mitigated and fully applicable attacks would be worse.
    assert items["attacks"].tone in (WARN, BAD)


def test_report_adds_subscores_with_meanings_and_the_coverage_denominator():
    evaluation = _evaluation()
    rows = {i.key: i for i in report_items(evaluation)}

    assert set(rows) >= {"attestation", "trust", "threat", "freshness", "compliance"}
    for key in ("attestation", "trust", "threat", "freshness", "compliance"):
        assert "/20 weighted" in rows[key].value
        assert " - " in rows[key].value  # a meaning follows the number

    coverage = rows["compliance_coverage"].value
    # The denominator is the honest part: criteria this evidence can speak to.
    assert "assessable criteria" in coverage
    assert "organizational, not scored" in coverage


def test_explain_lines_show_the_arithmetic_per_attack():
    lines = explain_lines(_evaluation())
    text = "\n".join(lines)

    assert "Total" in lines[0]
    assert "Platform half" in text
    assert "Heckler" in text
    assert "CVE-2024-25743" in text  # the CVEs travel with the deduction
    assert "host position" in text  # the reason it applied
    assert "-3 from the threat subscore" in text  # the cost, in points
    assert "Boundary:" in text


def test_explain_lines_track_the_threat_model():
    """The same evidence explains itself differently under a host-granting
    model, which is the point of the adversary-position dimension."""
    cloud = "\n".join(explain_lines(_evaluation(ThreatModelTier.CLOUD_ADMIN)))
    physical = "\n".join(explain_lines(_evaluation(ThreatModelTier.PHYSICAL_HOST)))
    software = "\n".join(explain_lines(_evaluation(ThreatModelTier.SOFTWARE_OPERATOR)))

    # The boundary prose mentions TEE.fail as an assumption; what matters is
    # whether it was *scored*, which the deduction line states explicitly.
    assert "TEE.fail requires the physical position" not in cloud
    assert "TEE.fail requires the physical position" in physical
    # Heckler's line carries its CVEs between the name and the position.
    assert "Heckler (CVE-2024-25743" in cloud
    assert "host position" in cloud
    assert "No known attack applied" in software


def test_badge_dims_use_the_row_vocabulary():
    """The dims feed the badge's row renderer, so the keys are the badge's."""
    dims = badge_dims(_evaluation())
    assert set(dims) == {"split", "evidence", "attacks"}
    assert dims["split"].startswith("platform ")
    assert "Heckler" in dims["attacks"]
    # The row vocabulary is "N: name (position), ..." once anything applies.
    assert dims["attacks"] == "none applied" or dims["attacks"].split(":")[0].isdigit()


def test_ungraded_evidence_says_so():
    """No score means no claims: the badge shows one honest item."""
    from src.core.taxonomy import AssuranceEvaluation, AssuranceLevel, ResidualRiskTier

    evaluation = AssuranceEvaluation(
        level=AssuranceLevel.NONE,
        residual_risk=ResidualRiskTier.LOW,
        boundary_statement="no evidence",
    )
    items = badge_items(evaluation)
    assert len(items) == 1
    assert items[0].value == "ungraded"
    assert coverage_items(evaluation) == ()


def test_no_attacks_reads_as_good():
    """An empty threat set is a real result, not a rendering of zero."""
    evaluation = _evaluation(ThreatModelTier.SOFTWARE_OPERATOR)
    items = {i.key: i for i in badge_items(evaluation)}
    assert items["attacks"].value == "none applied"
    assert items["attacks"].tone == GOOD
