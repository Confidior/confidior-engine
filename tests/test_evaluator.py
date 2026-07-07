from src.core.policy import evaluate, load_policy
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


def test_load_policy():
    policy = load_policy("tests/fixtures/policy/default.yaml")
    assert len(policy.rules) == 2
    assert policy.rules[0].rule_id == "rule-min-level"
    assert policy.rules[1].rule_id == "rule-no-debug"


def test_allow_when_policy_satisfied():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    policy = load_policy("tests/fixtures/policy/default.yaml")
    result = evaluate(graph, policy)
    assert result.decision == PolicyDecision.ALLOW
    assert "rule-min-level" in result.rules_passed
    assert "rule-no-debug" in result.rules_passed
    assert result.rules_failed == []


def test_deny_when_debug_enabled():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX, debug_disabled=False))
    policy = load_policy("tests/fixtures/policy/default.yaml")
    result = evaluate(graph, policy)
    assert result.decision == PolicyDecision.DENY
    assert "rule-min-level" in result.rules_failed
    assert "rule-no-debug" in result.rules_failed


def test_deny_when_no_evidence():
    graph = EvidenceGraph()
    policy = load_policy("tests/fixtures/policy/default.yaml")
    result = evaluate(graph, policy)
    assert result.decision == PolicyDecision.DENY
    assert "rule-min-level" in result.rules_failed
