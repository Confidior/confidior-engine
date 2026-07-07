import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from src.core.policy import evaluate, load_policy
from src.core.risk import compute_assurance_level
from src.core.taxonomy import (
    AssuranceLevel,
    ComplianceMapping,
    ComplianceStatus,
    ControlFamily,
    EdgeType,
    EvidenceBundle,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Platform,
    PolicyDecision,
    ResidualRiskTier,
    TCBStatus,
)
from src.export.c5 import evaluate_c5_compliance, generate_c5_report
from src.export.dsse import create_signed_bundle


def _make_quote_node(platform, debug_disabled=True, tcb_status=TCBStatus.UNKNOWN, measurement=None):
    return EvidenceNode(
        node_id=f"quote-{platform.value}",
        node_type=NodeType.QUOTE,
        platform=platform,
        measurement=measurement or ("aa" * 48),
        debug_disabled=debug_disabled,
        tcb_status=tcb_status,
    )


def test_multi_platform_graph_with_edges():
    graph = EvidenceGraph()
    tdx_node = _make_quote_node(Platform.IntelTDX)
    sev_node = _make_quote_node(Platform.AMDSEVSNP)
    build_node = EvidenceNode("build-1", NodeType.BUILD_PROVENANCE)
    tcb_node = EvidenceNode("tcb-1", NodeType.TCB_RECORD, tcb_version="v2.1")

    graph.add_node(tdx_node)
    graph.add_node(sev_node)
    graph.add_node(build_node)
    graph.add_node(tcb_node)
    graph.add_edge(EvidenceEdge(tdx_node.node_id, build_node.node_id, EdgeType.PRODUCES))
    graph.add_edge(EvidenceEdge(tcb_node.node_id, tdx_node.node_id, EdgeType.AFFECTS))

    assert graph.get_node(tdx_node.node_id) is not None
    assert graph.get_node(sev_node.node_id) is not None
    assert len(graph.edges) == 2

    producers = graph.traverse(tdx_node.node_id, EdgeType.PRODUCES)
    assert len(producers) == 1
    assert producers[0].node_id == "build-1"

    affected = graph.traverse(tcb_node.node_id, EdgeType.AFFECTS)
    assert len(affected) == 1
    assert affected[0].node_id == tdx_node.node_id


def test_assurance_level_with_two_independent_roots():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    graph.add_node(_make_quote_node(Platform.AMDSEVSNP))
    graph.add_node(EvidenceNode("bp1", NodeType.BUILD_PROVENANCE))

    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.DISTRIBUTED_TRUST
    assert result.residual_risk == ResidualRiskTier.CRITICAL


def test_policy_deny_when_any_quote_has_debug_enabled():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX, debug_disabled=True))
    graph.add_node(_make_quote_node(Platform.AMDSEVSNP, debug_disabled=False))

    policy = load_policy("tests/fixtures/policy/default.yaml")
    result = evaluate(graph, policy)
    assert result.decision == PolicyDecision.DENY
    assert "rule-no-debug" in result.rules_failed


def test_full_bundle_roundtrip_with_compliance_mappings():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    policy_eval = evaluate(graph, load_policy("tests/fixtures/policy/default.yaml"))
    assurance = compute_assurance_level(graph)
    compliance = evaluate_c5_compliance(graph)

    bundle, _ = create_signed_bundle(
        graph=graph,
        policy_eval=policy_eval,
        assurance=assurance,
        workload="full-roundtrip-test",
    )
    bundle.compliance_mappings = compliance

    d = bundle.to_dict()
    restored = EvidenceBundle.from_dict(d)

    assert restored.bundle_id == bundle.bundle_id
    assert restored.workload == bundle.workload
    assert restored.assurance.level == AssuranceLevel.HARDWARE_ATTESTED
    assert restored.assurance.residual_risk == ResidualRiskTier.CRITICAL
    assert restored.policy_evaluation.decision == PolicyDecision.ALLOW
    assert len(restored.signatures) == 1
    assert len(restored.compliance_mappings) > 0


def test_c5_compliance_with_mixed_evidence():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX, measurement="real-measurement-abc"))
    graph.add_node(EvidenceNode("bp1", NodeType.BUILD_PROVENANCE))

    mappings = evaluate_c5_compliance(graph)
    ops_32 = [m for m in mappings if m.control_id.startswith("OPS-32")]
    ops_33 = [m for m in mappings if m.control_id.startswith("OPS-33")]

    assert len(ops_32) >= 3
    assert len(ops_33) >= 3

    statuses = {m.status for m in mappings}
    assert ComplianceStatus.SATISFIED in statuses


def test_c5_report_with_gaps():
    graph = EvidenceGraph()
    mappings = evaluate_c5_compliance(graph)
    report = generate_c5_report(graph, mappings)

    assert "**GAP:**" in report
    summary_gap_line = [l for l in report.split("\n") if "**GAP:**" in l][0]
    gap_num = int(summary_gap_line.split("**GAP:**")[1].strip())
    assert gap_num > 0


def test_cli_verify_sevsnp_fixture():
    from src.cli.main import main

    with tempfile.TemporaryDirectory() as tmpdir:
        exit_code = main([
            "verify",
            "--input", "tests/fixtures/sevsnp/sample_report.hex",
            "--platform", "sevsnp",
            "--policy", "tests/fixtures/policy/default.yaml",
            "--output-dir", tmpdir,
            "--workload", "sev-e2e",
        ])

        assert exit_code == 0
        bundle_path = Path(tmpdir) / "evidence_bundle.json"
        assert bundle_path.exists()

        with open(bundle_path) as f:
            data = json.load(f)

        assert data["workload"] == "sev-e2e"
        assert data["assurance"]["level"] == 2
        assert "AMD-SEV-SNP" in Path(tmpdir).joinpath("report.md").read_text()


def test_cli_verify_nitro_fixture():
    from src.cli.main import main

    with tempfile.TemporaryDirectory() as tmpdir:
        exit_code = main([
            "verify",
            "--input", "tests/fixtures/nitro/sample_attestation.hex",
            "--platform", "nitro",
            "--policy", "tests/fixtures/policy/default.yaml",
            "--output-dir", tmpdir,
            "--workload", "nitro-e2e",
        ])

        assert exit_code == 0
        bundle_path = Path(tmpdir) / "evidence_bundle.json"
        assert bundle_path.exists()

        with open(bundle_path) as f:
            data = json.load(f)

        assert data["workload"] == "nitro-e2e"
        assert data["assurance"]["level"] == 2
        assert "AWS-Nitro" in Path(tmpdir).joinpath("report.md").read_text()


def test_bundle_expires_at_is_after_timestamp():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    policy_eval = evaluate(graph, load_policy("tests/fixtures/policy/default.yaml"))
    assurance = compute_assurance_level(graph)

    bundle, _ = create_signed_bundle(
        graph=graph,
        policy_eval=policy_eval,
        assurance=assurance,
        ttl_days=90,
    )

    assert bundle.expires_at > bundle.timestamp
    assert (bundle.expires_at - bundle.timestamp).days == 90


def test_graph_traverse_with_no_matching_edges():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    graph.add_node(EvidenceNode("m1", NodeType.MEASUREMENT))
    graph.add_edge(EvidenceEdge("quote-Intel-TDX", "m1", EdgeType.MATCHED_BY))

    results = graph.traverse("quote-Intel-TDX", EdgeType.AFFECTS)
    assert results == []

    results = graph.traverse("m1", EdgeType.MATCHED_BY)
    assert results == []


def test_risk_level_0_has_no_platform_info():
    graph = EvidenceGraph()
    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.NONE
    assert "No attestation evidence" in result.boundary_statement


def test_risk_level_1_when_debug_enabled():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX, debug_disabled=False))
    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.CONFIG_VERIFIED
    assert result.residual_risk == ResidualRiskTier.CRITICAL


def test_all_three_platforms_in_single_graph():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    graph.add_node(_make_quote_node(Platform.AMDSEVSNP))
    graph.add_node(_make_quote_node(Platform.AWSNitro))

    platforms = set()
    for node in graph.nodes.values():
        if node.node_type == NodeType.QUOTE and node.platform:
            platforms.add(node.platform)

    assert len(platforms) == 3
    assert Platform.IntelTDX in platforms
    assert Platform.AMDSEVSNP in platforms
    assert Platform.AWSNitro in platforms

    result = compute_assurance_level(graph)
    assert result.level == AssuranceLevel.HARDWARE_ATTESTED
    assert result.residual_risk == ResidualRiskTier.CRITICAL
