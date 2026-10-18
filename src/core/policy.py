"""Rego policy evaluation over the evidence graph.

A policy is a Rego module, evaluated in-process against the evidence graph.
``confidior verify --policy <path.rego>`` evaluates it and returns
ALLOW / DENY / REQUIRE_THRESHOLD.

Rego is used because it is the policy language the attestation ecosystem
already converged on: Trustee, Keylime, Veraison and Intel Trust Authority all
express appraisal policy in it, and the published control libraries are Rego.
A bespoke expression language could not consume any of that. Rego is also
guaranteed to terminate under OPA, which matters when the policy runs inside
the thing that must produce a verdict.

The interpreter is ``regopy``, a wrapper around Microsoft's rego-cpp, not OPA
itself. It accepts the rule vocabulary our policies use, but it does not
enforce ``import rego.v1`` and does not reject recursion at parse time; see
``_query`` and ``docs/COMPLIANCE.md`` for what that costs and how it is
contained.

The input document
------------------

Every rule reads one document. The graph is passed as JSON:

.. code-block:: json

    {
      "evidence": {
        "nodes": [ ... every node, as EvidenceNode.to_dict() ... ],
        "edges": [ ... every edge ... ],
        "quote": [ ... the nodes whose node_type is "quote" ... ],
        "platforms": ["Intel-TDX"],
        "node_count": 1,
        "edge_count": 0
      },
      "assurance": { "level": 2 }
    }

``quote`` and ``platforms`` are conveniences over ``nodes``, so the common case
(``some q in input.evidence.quote``) does not need a filter. ``assurance.level``
is the 0-5 assurance level; it is computed from the graph and does not depend on
the policy, so a rule can gate on it without a cycle.

Writing a rule
--------------

A rule is a rule. The engine reads the module's package document, so every rule
in it is evaluated in one query:

``deny_*`` / ``warn_*``
    A partial set rule. **Non-empty means the rule failed**; each element is a
    human-readable reason, which is carried into the report.
``allow``
    A complete rule. It must be ``true`` for the policy to allow.

Rules declare their severity in a ``rule_meta`` document, because Rego's
``METADATA`` annotations are not readable through the embedded interpreter::

    rule_meta := {
      "deny_debug": {"severity": "high", "title": "Debug mode must be disabled"},
      "warn_tcb":   {"severity": "low",  "title": "TCB should be current"},
    }

Severity weights the rule in the conformance score (high 3, medium 2, low 1).
A rule absent from ``rule_meta`` counts as medium.

The ``allow``/findings split means a rule written as a bare set does not, by
itself, fail closed: given no evidence, ``deny_x contains msg if { some q in
input.evidence.quote ... }`` yields the empty set, which reads as a pass. A
policy that must deny absent evidence has to say so::

    deny_missing_quote contains "no attestation evidence" if {
      count(object.get(object.get(input, "evidence", {}), "quote", [])) == 0
    }

This is a property of the language, not of the engine, so it is stated here
rather than papered over. The fixture policy in
``tests/fixtures/policy/default.rego`` is the worked example.

What a rule cannot do
---------------------

An unknown field is not an error, and it does **not** read as "not satisfied".
A rule body that references a missing field is *undefined*, so the body never
fires, and a partial set rule whose bodies never fire yields the empty set,
which reads as a **pass**::

    # Wrong. With no ``debug_disabled`` this reports the rule satisfied.
    deny_debug contains msg if {
      some q in input.evidence.quote
      q.debug_disabled != true
      msg := sprintf("debug is enabled on %v", [q.platform])
    }

An evidence producer that stops emitting a field therefore relaxes the policy
silently, which is the opposite of what a verifier should do. Read every field
through ``object.get`` with a default that fails the rule, and report a missing
field as its own finding so the reader can tell "the value is bad" from "the
value was never there"::

    deny_debug contains msg if {
      some q in object.get(object.get(input, "evidence", {}), "quote", [])
      object.get(q, "debug_disabled", false) == false
      msg := sprintf("debug is enabled on %v", [object.get(q, "platform", "unknown")])
    }

    deny_debug contains msg if {
      some q in object.get(object.get(input, "evidence", {}), "quote", [])
      not is_boolean(object.get(q, "debug_disabled", null))
      msg := sprintf("debug_disabled is missing or not a boolean on %v", [q.platform])
    }

The same hazard applies to a misspelled *field*: it is indistinguishable from an
absent one, so the rule passes when it should have failed. A misspelled *rule*
name is different: a rule in the package that is not in ``rule_meta`` still
evaluates, so check the rule ids in the report if a policy surprises you.

This is the "Rego tax" in its sharpest form. Rego does not check a policy
against the shape of its input at authoring time, so the failure mode of a
drifting schema is a policy that quietly widens. ``COMPLIANCE.md`` records the
three places this was found in the default policy before it shipped fail-closed.

"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import regopy

from src.core.taxonomy import (
    EvidenceGraph,
    NodeType,
    PolicyDecision,
    PolicyEvaluation,
    PolicyRule,
)

#: Severity weights used by the conformance score. A rule absent from
#: ``rule_meta`` counts as medium.
_SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1}
_DEFAULT_SEVERITY = "medium"

_PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z_][A-Za-z0-9_.]*)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class Policy:
    """A Rego module, plus what the engine needs to name and score it."""

    rules: list[PolicyRule] = field(default_factory=list)
    description: str = ""
    #: The module source. This is the artifact a verdict is judged against, so
    #: it is what gets hashed into the bundle's derivation list.
    source: str = ""
    path: str = ""
    package: str = ""


class PolicyError(ValueError):
    """A policy that cannot be loaded or evaluated."""


def _package_of(source: str) -> str:
    match = _PACKAGE_RE.search(source)
    if not match:
        raise PolicyError("policy has no `package` declaration")
    return match.group(1)


def _declared_rules(source: str) -> list[str]:
    """Rule names declared in ``rule_meta``, if the module carries it."""
    interp = regopy.Interpreter()
    interp.add_module("policy.rego", source)
    try:
        document = _query(interp, "data.rule_meta", required=False)
    except PolicyError:
        return []
    if not isinstance(document, dict):
        return []
    return list(document)


def _query(interp: regopy.Interpreter, path: str, *, required: bool = True) -> Any:
    """Run one query, returning the value or None when undefined."""
    try:
        raw = str(interp.query(path))
    except regopy.RegoError as exc:
        raise PolicyError(f"{path} failed to evaluate: {exc}") from exc
    except json.JSONDecodeError as exc:
        # rego-cpp can return an empty payload instead of a RegoError when
        # evaluation does not terminate, e.g. a recursive rule. The wrapper
        # decodes that payload itself, so the failure arrives as a
        # JSONDecodeError from inside query() rather than as a RegoError.
        # Left uncaught it escapes as an opaque traceback instead of a policy
        # error, so a malformed policy looks like an engine bug.
        raise PolicyError(
            f"{path} did not produce a result; a rule may not terminate "
            "(rego-cpp does not reject recursion at parse time)"
        ) from exc
    if raw == "undefined":
        if required:
            raise PolicyError(f"{path} is undefined")
        return None
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{path} returned a non-JSON result: {raw[:120]}") from exc
    expressions = envelope.get("expressions") or []
    if not expressions:
        return None
    return expressions[0]


def load_policy(yaml_path: str) -> Policy:
    """Load a Rego policy module from ``path``.

    The parameter keeps its historical name so callers and the ``--policy``
    flag need no churn, but the file must contain Rego. A YAML policy is
    rejected with a message that says what happened, because silently reading
    it as Rego would fail at a confusing distance from the cause.
    """
    path = Path(yaml_path)
    if not path.exists():
        raise PolicyError(f"policy file not found: {path}")
    source = path.read_text()
    if path.suffix in (".yaml", ".yml"):
        raise PolicyError(
            f"{path} is a YAML policy; policies are Rego modules now (see "
            "src/core/policy.py for the input contract and a worked example)"
        )

    package = _package_of(source)
    interp = regopy.Interpreter()
    interp.add_module(path.name, source)

    # The module's own view of its rules: every rule name under its package.
    interp.set_input({})
    document = _query(interp, f"data.{package}", required=False)
    if not isinstance(document, dict):
        raise PolicyError(f"{path}: package {package} defines no rules")

    meta = document.get("rule_meta") or {}
    if not isinstance(meta, dict):
        meta = {}

    rules: list[PolicyRule] = []
    for name in document:
        if name == "rule_meta":
            continue
        entry = meta.get(name) or {}
        rules.append(
            PolicyRule(
                rule_id=name,
                expression=name,
                description=str(entry.get("title", "")),
                severity=str(entry.get("severity", _DEFAULT_SEVERITY)),
            )
        )
    if not rules:
        raise PolicyError(f"{path}: package {package} defines no rules")

    return Policy(
        rules=rules,
        description=str(meta.get("description", "")),
        source=source,
        path=str(path),
        package=package,
    )


def policy_input(graph: EvidenceGraph) -> dict[str, Any]:
    """The document every rule reads. See the module docstring for its shape."""
    nodes = [n.to_dict() for n in graph.nodes.values()]
    quote = [n.to_dict() for n in graph.nodes.values() if n.node_type == NodeType.QUOTE]
    edges = [
        {
            "source_id": e.source_id,
            "target_id": e.target_id,
            "edge_type": e.edge_type.value,
        }
        for e in graph.edges
    ]

    # The level is computed from the graph alone, so a rule can gate on it
    # without depending on the policy's own verdict. Imported here rather than
    # at module scope: the assurance chain reaches back into this module.
    from src.core.risk import compute_assurance_level

    level = compute_assurance_level(graph).level.value

    return {
        "evidence": {
            "nodes": nodes,
            "edges": edges,
            "quote": quote,
            "platforms": sorted({n["platform"] for n in nodes if n["platform"]}),
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
        "assurance": {"level": level},
    }


def _rule_outcome(value: Any) -> tuple[bool, list[str]]:
    """Read one rule's value as (satisfied, findings).

    A set of messages is the findings shape; ``true`` is the assertion shape.
    Anything else (including an undefined rule) is not satisfied, and says so
    rather than passing quietly.
    """
    if isinstance(value, list):
        return (not value), [str(v) for v in value]
    if isinstance(value, bool):
        return value, []
    return False, ["rule did not produce a verdict"]


def evaluate(graph: EvidenceGraph, policy: Policy) -> PolicyEvaluation:
    """Evaluate ``policy`` against ``graph``."""
    interp = regopy.Interpreter()
    interp.add_module(Path(policy.path).name or "policy.rego", policy.source)
    interp.set_input(policy_input(graph))

    document = _query(interp, f"data.{policy.package}", required=False) or {}
    if not isinstance(document, dict):
        raise PolicyError(f"package {policy.package} did not evaluate to an object")

    passed: list[str] = []
    failed: list[str] = []
    not_evaluated: list[str] = []
    findings: dict[str, list[str]] = {}

    for rule in policy.rules:
        if rule.rule_id not in document:
            not_evaluated.append(rule.rule_id)
            continue
        satisfied, reasons = _rule_outcome(document[rule.rule_id])
        if satisfied:
            passed.append(rule.rule_id)
        else:
            failed.append(rule.rule_id)
            findings[rule.rule_id] = reasons

    if failed:
        decision = PolicyDecision.DENY
    elif passed and not not_evaluated:
        decision = PolicyDecision.ALLOW
    else:
        decision = PolicyDecision.REQUIRE_THRESHOLD

    return PolicyEvaluation(
        decision=decision,
        rules_passed=passed,
        rules_failed=failed,
        rules_not_evaluated=not_evaluated,
        findings=findings,
    )


def policy_conformance(policy_eval: PolicyEvaluation, policy: Policy) -> dict[str, Any] | None:
    """Severity-weighted share of the policy this evidence satisfies.

    Each rule's weight comes from its severity, so a policy's important rules
    move the number more than its advisory ones. A rule that did not evaluate
    earns no credit: the honest reading of "the engine could not decide" is not
    "it passed".

    Returns None when the policy has no rules, so the caller can tell "no
    policy" apart from "a policy this evidence fully satisfies".
    """
    weights = {r.rule_id: _SEVERITY_WEIGHT.get(r.severity.lower(), 2) for r in policy.rules}
    total = sum(weights.values())
    if not total:
        return None

    satisfied = sum(weights[rid] for rid in policy_eval.rules_passed if rid in weights)
    failed = sum(weights[rid] for rid in policy_eval.rules_failed if rid in weights)
    not_evaluated = sum(weights[rid] for rid in policy_eval.rules_not_evaluated if rid in weights)

    return {
        "satisfied": satisfied,
        "failed": failed,
        "not_evaluated": not_evaluated,
        "total": total,
        "ratio": satisfied / total,
        "rules_passed": len(policy_eval.rules_passed),
        "rules_failed": len(policy_eval.rules_failed),
        "rules_not_evaluated": len(policy_eval.rules_not_evaluated),
    }
