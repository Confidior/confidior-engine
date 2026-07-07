from src.core.taxonomy import (
    ComplianceStatus,
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Platform,
    TCBStatus,
)
from src.export.c5 import evaluate_c5_compliance, generate_c5_report


def _make_quote_node(platform, debug_disabled=True):
    return EvidenceNode(
        node_id=f"quote-{platform.value}",
        node_type=NodeType.QUOTE,
        platform=platform,
        measurement="aa" * 48,
        debug_disabled=debug_disabled,
        tcb_status=TCBStatus.CURRENT,
    )


def test_evaluate_c5_with_tdx_evidence():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    mappings = evaluate_c5_compliance(graph)
    assert len(mappings) > 0
    ops_32_mappings = [m for m in mappings if m.control_id.startswith("OPS-32")]
    assert len(ops_32_mappings) >= 3


def test_evaluate_c5_without_evidence():
    graph = EvidenceGraph()
    mappings = evaluate_c5_compliance(graph)
    gap_mappings = [m for m in mappings if m.status == ComplianceStatus.GAP]
    assert len(gap_mappings) > 0


def test_evaluate_c5_all_families_covered():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    mappings = evaluate_c5_compliance(graph)

    covered_families = set()
    for m in mappings:
        family_id = m.control_id.split("-")[0]
        covered_families.add(family_id)

    # 17 of 18 families have basic subcriteria. GC has 6 criteria but no basic subcriteria.
    assert len(covered_families) == 17
    assert "GC" not in covered_families


def test_organizational_controls_are_gap():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    mappings = evaluate_c5_compliance(graph)

    hr_mappings = [m for m in mappings if m.control_id.startswith("HR-")]
    ps_mappings = [m for m in mappings if m.control_id.startswith("PS-")]
    bcm_mappings = [m for m in mappings if m.control_id.startswith("BCM-")]

    for mapping in hr_mappings + ps_mappings + bcm_mappings:
        assert mapping.status == ComplianceStatus.GAP
        assert mapping.gap_description is not None


def test_generate_c5_report():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    mappings = evaluate_c5_compliance(graph)
    report = generate_c5_report(graph, mappings)
    assert "C5:2026 Compliance Report" in report
    assert "OPS-32" in report
    assert "OPS-33" in report
    assert "Summary" in report
    assert "SATISFIED" in report


def test_c5_report_contains_summary_counts():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    mappings = evaluate_c5_compliance(graph)
    report = generate_c5_report(graph, mappings)
    assert "PARTIAL:" in report
    assert "GAP:" in report


def test_no_rule_controls_default_to_gap():
    """Controls without automated evaluation rules should default to GAP, not PARTIAL."""
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    mappings = evaluate_c5_compliance(graph)

    no_rule_mappings = [
        m for m in mappings
        if m.gap_description == "No automated evaluation rule defined for this sub-criterion"
    ]
    for m in no_rule_mappings:
        assert m.status == ComplianceStatus.GAP


def test_technical_controls_with_quote_are_satisfied_or_partial():
    """OPS-32 and OPS-33 controls should be SATISFIED or PARTIAL when quote is present."""
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    mappings = evaluate_c5_compliance(graph)

    ops_32 = [m for m in mappings if m.control_id.startswith("OPS-32")]
    ops_33 = [m for m in mappings if m.control_id.startswith("OPS-33")]

    for m in ops_32 + ops_33:
        assert m.status in (ComplianceStatus.SATISFIED, ComplianceStatus.PARTIAL)
        assert m.status != ComplianceStatus.GAP


def test_gap_count_dominates_over_partial():
    """Most controls should be GAP (org controls + no-rule technical controls)."""
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    mappings = evaluate_c5_compliance(graph)

    gap_count = sum(1 for m in mappings if m.status == ComplianceStatus.GAP)
    partial_count = sum(1 for m in mappings if m.status == ComplianceStatus.PARTIAL)
    satisfied_count = sum(1 for m in mappings if m.status == ComplianceStatus.SATISFIED)

    assert gap_count > partial_count
    assert gap_count > satisfied_count


def test_evaluate_c5_missing_data_returns_empty():
    """When C5 data directory is missing, evaluate_c5_compliance returns empty."""
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    mappings = evaluate_c5_compliance(graph, c5_dir="/tmp/nonexistent-c5-dir")
    assert mappings == []


def test_generate_c5_report_missing_data_returns_fallback():
    """When C5 data directory is missing, generate_c5_report returns fallback message."""
    graph = EvidenceGraph()
    report = generate_c5_report(graph, [], c5_dir="/tmp/nonexistent-c5-dir")
    assert "not available" in report
    assert "download from BSI" in report
