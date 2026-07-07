from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

import yaml

from src.core.taxonomy import (
    AssuranceLevel,
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Platform,
    PolicyDecision,
    PolicyEvaluation,
    PolicyOperator,
    PolicyRule,
    ResidualRiskTier,
    TCBStatus,
)


@dataclass(frozen=True)
class Policy:
    rules: list[PolicyRule] = field(default_factory=list)
    description: str = ""


def load_policy(yaml_path: str) -> Policy:
    with open(yaml_path) as f:
        data = yaml.safe_load(f)
    rules = []
    for r in data.get("rules", []):
        rules.append(PolicyRule(
            rule_id=r["id"],
            expression=r["expression"],
            description=r.get("description", ""),
        ))
    return Policy(rules=rules, description=data.get("description", ""))


class _Tokenizer:
    def __init__(self, text: str):
        self.tokens = self._tokenize(text)
        self.pos = 0

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        tokens = []
        pattern = r'(>=|<=|==|!=|IN|in|AND|and|OR|or|NOT|not|TRUE|true|FALSE|false|\(|\)|[a-zA-Z_][a-zA-Z0-9_\-]*|"[^"]*"|\'[^\']*\'|\d+)'
        for match in re.finditer(pattern, text):
            tokens.append(match.group())
        return tokens

    def peek(self) -> str | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def consume(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def at_end(self) -> bool:
        return self.pos >= len(self.tokens)


class _ASTNode:
    pass


@dataclass(frozen=True)
class _Comparison(_ASTNode):
    field: str
    op: str
    value: str


@dataclass(frozen=True)
class _UnaryOp(_ASTNode):
    operator: str
    operand: _ASTNode


@dataclass(frozen=True)
class _BinaryOp(_ASTNode):
    operator: str
    left: _ASTNode
    right: _ASTNode


def _parse_expression(text: str) -> _ASTNode:
    tokenizer = _Tokenizer(text)
    return _parse_or(tokenizer)


def _parse_or(tokenizer: _Tokenizer) -> _ASTNode:
    left = _parse_and(tokenizer)
    while tokenizer.peek() and tokenizer.peek().lower() == "or":
        tokenizer.consume()
        right = _parse_and(tokenizer)
        left = _BinaryOp(operator="OR", left=left, right=right)
    return left


def _parse_and(tokenizer: _Tokenizer) -> _ASTNode:
    left = _parse_not(tokenizer)
    while tokenizer.peek() and tokenizer.peek().lower() == "and":
        tokenizer.consume()
        right = _parse_not(tokenizer)
        left = _BinaryOp(operator="AND", left=left, right=right)
    return left


def _parse_not(tokenizer: _Tokenizer) -> _ASTNode:
    if tokenizer.peek() and tokenizer.peek().lower() == "not":
        tokenizer.consume()
        operand = _parse_not(tokenizer)
        return _UnaryOp(operator="NOT", operand=operand)
    return _parse_comparison(tokenizer)


def _parse_comparison(tokenizer: _Tokenizer) -> _ASTNode:
    if tokenizer.peek() == "(":
        tokenizer.consume()
        node = _parse_or(tokenizer)
        if tokenizer.peek() == ")":
            tokenizer.consume()
        return node

    field = tokenizer.consume()
    op = tokenizer.consume()

    if op.upper() == "IN":
        values = []
        if tokenizer.peek() == "(":
            tokenizer.consume()
            while tokenizer.peek() and tokenizer.peek() != ")":
                values.append(_strip_quotes(tokenizer.consume()))
                if tokenizer.peek() == ",":
                    tokenizer.consume()
            if tokenizer.peek() == ")":
                tokenizer.consume()
        return _Comparison(field=field, op="IN", value=",".join(values))

    value = tokenizer.consume()
    return _Comparison(field=field, op=op, value=_strip_quotes(value))


def _strip_quotes(s: str) -> str:
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s


def _extract_field(node: EvidenceNode, field_path: str) -> Any:
    if field_path == "level":
        return None
    if field_path == "platform":
        return node.platform.value if node.platform else None
    if field_path == "debug":
        return node.debug_disabled
    if field_path == "tcb_status":
        return node.tcb_status.value if node.tcb_status else None
    if field_path == "measurement":
        return node.measurement
    return node.metadata.get(field_path)


def _evaluate_ast(node: _ASTNode, graph: EvidenceGraph) -> bool:
    if isinstance(node, _Comparison):
        return _evaluate_comparison(node, graph)
    if isinstance(node, _UnaryOp):
        if node.operator.upper() == "NOT":
            return not _evaluate_ast(node.operand, graph)
    if isinstance(node, _BinaryOp):
        if node.operator.upper() == "AND":
            return _evaluate_ast(node.left, graph) and _evaluate_ast(node.right, graph)
        if node.operator.upper() == "OR":
            return _evaluate_ast(node.left, graph) or _evaluate_ast(node.right, graph)
    return False


def _evaluate_comparison(node: _Comparison, graph: EvidenceGraph) -> bool:
    if node.field == "level":
        from src.core.risk import compute_assurance_level
        result = compute_assurance_level(graph)
        if node.op == ">=":
            return result.level.value >= int(node.value)
        if node.op == "<=":
            return result.level.value <= int(node.value)
        if node.op == "==":
            return result.level.value == int(node.value)
        if node.op == "!=":
            return result.level.value != int(node.value)
        return False

    if node.op == "IN":
        allowed = [v.strip() for v in node.value.split(",")]
        for n in graph.nodes.values():
            if n.node_type == NodeType.QUOTE and n.platform and n.platform.value in allowed:
                return True
        return False

    quote_nodes = [n for n in graph.nodes.values() if n.node_type == NodeType.QUOTE]
    if not quote_nodes:
        return False

    if node.field == "debug":
        target = node.value.lower() == "true"
        if node.op == "==":
            return all(n.debug_disabled == target for n in quote_nodes)
        if node.op == "!=":
            return any(n.debug_disabled != target for n in quote_nodes)
        return False

    for n in quote_nodes:
        val = _extract_field(n, node.field)
        if val is None:
            continue

        str_val = str(val).lower()
        target = node.value.lower()
        if node.op == "==":
            if str_val == target:
                return True
        elif node.op == "!=":
            if str_val != target:
                return True
        elif node.op == ">=":
            try:
                if float(str_val) >= float(target):
                    return True
            except ValueError:
                pass

    return False


def _evaluate_expression(expr: str, graph: EvidenceGraph) -> bool:
    ast = _parse_expression(expr)
    return _evaluate_ast(ast, graph)


def evaluate(graph: EvidenceGraph, policy: Policy) -> PolicyEvaluation:
    passed = []
    failed = []

    for rule in policy.rules:
        expr = rule.expression
        if _evaluate_expression(expr, graph):
            passed.append(rule.rule_id)
        else:
            failed.append(rule.rule_id)

    if not failed and passed:
        decision = PolicyDecision.ALLOW
    elif failed:
        decision = PolicyDecision.DENY
    else:
        decision = PolicyDecision.REQUIRE_THRESHOLD

    return PolicyEvaluation(
        decision=decision,
        rules_passed=passed,
        rules_failed=failed,
    )
