"""The policy language: a Rego module over the evidence graph.

Covers the input contract, rule severity, findings, and the fail-closed
behaviour the default policy declares explicitly.
"""

import json

import regopy

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


def test_missing_debug_field_fails_closed():
    """A dropped field must not relax the policy.

    Rego leaves a body referencing a missing field undefined, so the obvious
    spelling (``q.debug_disabled != true``) reports the rule satisfied when the
    field is simply absent. An evidence producer that stops emitting the field
    would then silently widen the policy, which is the wrong direction for a
    verifier.
    """
    policy = load_policy("tests/fixtures/policy/default.rego")
    interpreter = regopy.Interpreter()
    interpreter.add_module("policy.rego", policy.source)
    interpreter.set_input(
        {"evidence": {"quote": [{"platform": "tdx"}]}, "assurance": {"level": 3}}
    )

    envelope = json.loads(str(interpreter.query("data.confidior.appraisal.deny_debug")))
    reasons = (envelope.get("expressions") or [[]])[0]

    assert reasons, "an absent debug_disabled must not read as satisfied"
    assert any("missing" in reason or "not a boolean" in reason for reason in reasons)


def test_missing_assurance_level_fails_closed():
    """An absent level is input the engine cannot judge, and it says so.

    Exercised against the policy text directly, because the engine's own input
    builder always supplies the field; this is the shape a foreign or
    hand-written policy input would take.
    """
    policy = load_policy("tests/fixtures/policy/default.rego")
    interpreter = regopy.Interpreter()
    interpreter.add_module("policy.rego", policy.source)
    interpreter.set_input(
        {"evidence": {"quote": [{"platform": "tdx", "debug_disabled": True}]}, "assurance": {}}
    )

    envelope = json.loads(str(interpreter.query("data.confidior.appraisal.deny_low_level")))
    reasons = (envelope.get("expressions") or [[]])[0]

    assert reasons, "a missing assurance level must not read as satisfied"
    assert any("missing" in reason for reason in reasons)


def test_absent_input_is_a_denial_not_a_pass():
    """No input at all must deny. Rego's vacuous-truth case is the hazard."""
    policy = load_policy("tests/fixtures/policy/default.rego")
    interpreter = regopy.Interpreter()
    interpreter.add_module("policy.rego", policy.source)
    interpreter.set_input({})

    envelope = json.loads(str(interpreter.query("data.confidior.appraisal.deny_missing_quote")))
    reasons = (envelope.get("expressions") or [[]])[0]

    assert reasons, "an empty input must fail deny_missing_quote"


def test_non_terminating_rule_is_a_policy_error(tmp_path):
    """A rule that never resolves must not surface as an engine crash.

    rego-cpp does not reject recursion when the module is parsed, and when
    evaluation of a recursive rule fails it can hand back an empty payload
    instead of raising. The wrapper decodes that payload itself, so the
    failure arrives as a JSONDecodeError from inside ``query()``; uncaught it
    escapes as an opaque traceback that reads like an engine bug rather than
    a bad policy.
    """
    import pytest

    module = (
        "package confidior.appraisal\n"
        "import rego.v1\n"
        "loop(x) := loop(x) if { true }\n"
        'deny_loop contains "never resolves" if { loop(1) }\n'
    )
    path = tmp_path / "loop.rego"
    path.write_text(module)

    with pytest.raises(PolicyError, match="may not terminate"):
        load_policy(str(path))
