"""The policy language: a Rego module over the evidence graph.

Covers the input contract, rule severity, findings, and the fail-closed
behaviour the default policy declares explicitly.
"""

from src.core.policy import (
    PolicyError,
    evaluate,
    load_policy,
    policy_conformance,
    policy_input,
)
from src.core.taxonomy import (
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Platform,
    PolicyDecision,
    TCBStatus,
)


def _make_quote_node(platform, debug_disabled=True):
    return EvidenceNode(
        node_id=f"quote-{platform.value}",
        node_type=NodeType.QUOTE,
        platform=platform,
        measurement="aa" * 48,
        debug_disabled=debug_disabled,
        tcb_status=TCBStatus.CURRENT,
    )


def _graph(*nodes):
    graph = EvidenceGraph()
    for node in nodes:
        graph.add_node(node)
    return graph


def test_load_policy_reads_rules_and_severity():
    policy = load_policy("tests/fixtures/policy/default.rego")
    assert policy.package == "confidior.appraisal"
    ids = [r.rule_id for r in policy.rules]
    assert "deny_debug" in ids
    assert "deny_missing_quote" in ids
    # Severity comes from the policy's own rule_meta document.
    assert all(r.severity == "high" for r in policy.rules)
    assert policy.rules[0].description


def test_allow_when_policy_satisfied():
    graph = _graph(_make_quote_node(Platform.IntelTDX))
    result = evaluate(graph, load_policy("tests/fixtures/policy/default.rego"))
    assert result.decision == PolicyDecision.ALLOW
    assert result.rules_failed == []
    assert set(result.rules_passed) == {"deny_missing_quote", "deny_low_level", "deny_debug"}


def test_deny_when_debug_enabled():
    graph = _graph(_make_quote_node(Platform.IntelTDX, debug_disabled=False))
    result = evaluate(graph, load_policy("tests/fixtures/policy/default.rego"))
    assert result.decision == PolicyDecision.DENY
    assert "deny_debug" in result.rules_failed
    # Debug on also drops the assurance level, so the level rule fails too.
    assert "deny_low_level" in result.rules_failed


def test_findings_carry_the_rule_own_reason():
    graph = _graph(_make_quote_node(Platform.IntelTDX, debug_disabled=False))
    result = evaluate(graph, load_policy("tests/fixtures/policy/default.rego"))
    assert "debug is enabled on Intel-TDX" in result.findings["deny_debug"]


def test_deny_when_no_evidence():
    """A set rule on an empty graph is vacuously empty, which would read as a
    pass. The default policy states absent evidence as a failure instead."""
    result = evaluate(EvidenceGraph(), load_policy("tests/fixtures/policy/default.rego"))
    assert result.decision == PolicyDecision.DENY
    assert "deny_missing_quote" in result.rules_failed
    assert result.findings["deny_missing_quote"] == ["no attestation evidence"]


def test_input_contract_shape():
    graph = _graph(_make_quote_node(Platform.IntelTDX))
    document = policy_input(graph)
    assert set(document) == {"evidence", "assurance"}
    evidence = document["evidence"]
    assert set(evidence) == {
        "nodes",
        "edges",
        "quote",
        "platforms",
        "node_count",
        "edge_count",
    }
    assert evidence["platforms"] == ["Intel-TDX"]
    assert len(evidence["quote"]) == 1
    # The level is computed from the graph, not supplied by the caller.
    assert document["assurance"]["level"] == 2


def test_conformance_is_none_for_a_policy_with_no_rules():
    policy = type("P", (), {"rules": []})()
    assert policy_conformance(
        type("E", (), {"rules_passed": [], "rules_failed": [], "rules_not_evaluated": []})(),
        policy,
    ) is None


def test_yaml_policy_is_rejected_with_a_pointer():
    """The flag is unchanged, the format is not. Say so where it fails."""
    import pytest

    with pytest.raises(PolicyError, match="policies are Rego modules now"):
        load_policy("tests/fixtures/policy/legacy.yaml")


def test_invalid_rego_is_rejected():
    import pytest

    with pytest.raises(Exception):
        load_policy("tests/fixtures/policy/broken.rego")
