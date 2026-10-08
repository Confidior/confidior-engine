from src.core.policy import _evaluate_expression
from src.core.taxonomy import (
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Platform,
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


def test_and_expression():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    assert _evaluate_expression("level >= 2 and debug_disabled == true", graph) is True


def test_and_expression_one_false():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX, debug_disabled=False))
    assert _evaluate_expression("level >= 2 and debug_disabled == true", graph) is False


def test_or_expression():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    assert _evaluate_expression("level >= 5 or level >= 2", graph) is True


def test_or_expression_both_false():
    graph = EvidenceGraph()
    assert _evaluate_expression("level >= 5 or platform == Intel-TDX", graph) is False


def test_not_expression():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    assert _evaluate_expression("not level >= 5", graph) is True
    assert _evaluate_expression("not level >= 2", graph) is False


def test_in_expression():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    assert _evaluate_expression("platform IN (Intel-TDX, AMD-SEV-SNP)", graph) is True
    assert _evaluate_expression("platform IN (AWS-Nitro)", graph) is False


def test_nested_parentheses():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    expr = "(level >= 2 and debug_disabled == true) or level >= 5"
    assert _evaluate_expression(expr, graph) is True


def test_complex_expression():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    graph.add_node(_make_quote_node(Platform.AMDSEVSNP))
    expr = "(platform IN (Intel-TDX, AMD-SEV-SNP) and level >= 2) and not level >= 5"
    assert _evaluate_expression(expr, graph) is True


def test_not_with_and():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX, debug_disabled=False))
    assert _evaluate_expression("level >= 1 and not debug_disabled == true", graph) is True
    assert _evaluate_expression("level >= 2 and not debug_disabled == true", graph) is False


def test_debug_field_is_named_for_the_value_it_reads():
    """`debug_disabled`, not `debug`.

    The field reads `node.debug_disabled`, so under the old name `debug` the
    expression `debug == true` passed when debug was *disabled* — the opposite
    of how it reads. A careful author writing `debug == false`, which the words
    suggest, got a policy that failed every clean quote.
    """
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX, debug_disabled=True))

    assert _evaluate_expression("debug_disabled == true", graph) is True


def test_the_old_debug_token_no_longer_resolves():
    """`debug` now falls through to node metadata and finds nothing.

    A policy still carrying the old spelling fails closed rather than being
    read with the wrong polarity. `debug == true` used to mean "debug is off"
    and passed a clean quote; it must not any more.
    """
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX, debug_disabled=True))

    assert _evaluate_expression("debug == true", graph) is False
    assert _evaluate_expression("debug == false", graph) is False
