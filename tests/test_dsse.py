import ast
from pathlib import Path

from src.core.policy import evaluate, load_policy
from src.core.risk import compute_assurance_level
from src.core.taxonomy import (
    AssuranceEvaluation,
    AssuranceLevel,
    EvidenceBundle,
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Platform,
    PolicyDecision,
    PolicyEvaluation,
    ResidualRiskTier,
    TCBStatus,
)
from src.export.dsse import create_signed_bundle


def _make_quote_node(platform, debug_disabled=True):
    return EvidenceNode(
        node_id=f"quote-{platform.value}",
        node_type=NodeType.QUOTE,
        platform=platform,
        measurement="aa" * 48,
        debug_disabled=debug_disabled,
        tcb_status=TCBStatus.CURRENT,
    )


def test_create_signed_bundle():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    policy = load_policy("tests/fixtures/policy/default.yaml")
    policy_eval = evaluate(graph, policy)
    assurance = compute_assurance_level(graph)

    bundle, private_key = create_signed_bundle(
        graph=graph,
        policy_eval=policy_eval,
        assurance=assurance,
        workload="test-workload",
    )

    assert bundle.bundle_id.startswith("bundle-")
    assert len(bundle.signatures) == 1
    assert bundle.signatures[0].algorithm == "Ed25519"
    assert bundle.workload == "test-workload"
    assert bundle.assurance.level == AssuranceLevel.HARDWARE_ATTESTED
    assert bundle.assurance.residual_risk == ResidualRiskTier.HIGH
    assert bundle.policy_evaluation.decision == PolicyDecision.ALLOW
    assert bundle.attack_db_snapshot is not None
    assert len(bundle.attack_db_snapshot) == 64


def test_bundle_json_roundtrip_with_signature():
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    policy = load_policy("tests/fixtures/policy/default.yaml")
    policy_eval = evaluate(graph, policy)
    assurance = compute_assurance_level(graph)

    bundle, private_key = create_signed_bundle(
        graph=graph,
        policy_eval=policy_eval,
        assurance=assurance,
        workload="roundtrip-test",
    )

    d = bundle.to_dict()
    restored = type(bundle).from_dict(d)

    assert restored.bundle_id == bundle.bundle_id
    assert restored.workload == bundle.workload
    assert restored.assurance.level == bundle.assurance.level
    assert restored.policy_evaluation.decision == bundle.policy_evaluation.decision
    assert len(restored.signatures) == 1
    assert restored.attack_db_snapshot == bundle.attack_db_snapshot


def test_bundle_roundtrip_preserves_attack_db_snapshot():
    bundle, _ = create_signed_bundle(
        graph=EvidenceGraph(),
        policy_eval=PolicyEvaluation(
            decision=PolicyDecision.ALLOW, rules_passed=[], rules_failed=[]
        ),
        assurance=AssuranceEvaluation(
            level=AssuranceLevel.NONE, residual_risk=ResidualRiskTier.LOW,
            boundary_statement="test", label="test",
        ),
        workload="snapshot-test",
    )
    d = bundle.to_dict()
    assert "attack_db_snapshot" in d
    assert len(d["attack_db_snapshot"]) == 64
    restored = EvidenceBundle.from_dict(d)
    assert restored.attack_db_snapshot == bundle.attack_db_snapshot


def test_attack_db_snapshot_is_deterministic():
    from src.core.attacks import compute_attack_db_snapshot
    assert compute_attack_db_snapshot() == compute_attack_db_snapshot()
    assert len(compute_attack_db_snapshot()) == 64
    assert isinstance(compute_attack_db_snapshot(), str)


def test_sign_bundle_is_idempotent_on_payload():
    from datetime import datetime, timedelta

    from src.core.taxonomy import EvidenceBundle
    from src.export.dsse import serialize_bundle_for_signing

    bundle = EvidenceBundle(
        bundle_id="test-id",
        timestamp=datetime.now(),
        expires_at=datetime.now() + timedelta(days=1),
        workload="test",
    )

    payload1 = serialize_bundle_for_signing(bundle)
    payload2 = serialize_bundle_for_signing(bundle)
    assert payload1 == payload2


#: Fields the bundle model carries but which are not written after signing:
#: ``signatures`` is appended by ``sign_bundle`` itself, and ``bundle_id``,
#: ``timestamp`` and friends are fixed at construction.
_SIGNED_PAYLOAD_EXEMPT = ("signatures",)


def _signed_payload_fields() -> tuple[str, ...]:
    """Every field ``to_dict()`` serializes, minus the signing field itself.

    Derived rather than listed so a field added to ``to_dict()`` later is
    guarded automatically, the whole hazard is that the guard would otherwise
    have to be remembered.
    """
    from src.core.taxonomy import EvidenceBundle

    keys = EvidenceBundle.from_dict(
        {
            "bundle_id": "bundle-x",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "expires_at": "2026-01-01T00:00:00+00:00",
            "workload": "x",
            "assurance": {
                "level": 2,
                "residual_risk": "HIGH",
                "boundary_statement": "",
                "label": "",
            },
        }
    ).to_dict()
    return tuple(k for k in keys if k not in _SIGNED_PAYLOAD_EXEMPT)


#: Modules that create bundles and are allowed to touch them afterwards.
_BUNDLE_WRITERS = ("cli/main.py", "web/app.py")


def _post_signing_assignments(path: Path) -> list[str]:
    """Assignments to signed payload fields in *path*, as source lines.

    A bundle is signed over ``to_dict()``. Assigning one of these fields after
    ``create_signed_bundle()`` returns leaves a bundle whose own signature does
    not verify, the defect that made every CLI and web bundle unverifiable.
    """
    guarded = set(_signed_payload_fields())
    tree = ast.parse(path.read_text(), filename=str(path))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if not isinstance(target, ast.Attribute) or target.attr not in guarded:
                continue
            if isinstance(target.value, ast.Name) and target.value.id == "bundle":
                found.append(f"{path}:{node.lineno}: bundle.{target.attr} = ...")
    return found


def test_no_bundle_is_mutated_after_it_is_signed():
    """Signed artifacts must be complete when they are signed.

    Adding a field to ``to_dict()`` silently re-opens this: the writer signs,
    then fills the field in, and the signature stops describing the bundle.
    This guard is why the defect cannot come back unnoticed.
    """
    offenders: list[str] = []
    for relative in _BUNDLE_WRITERS:
        module = Path(__file__).resolve().parent.parent / "src" / relative
        offenders.extend(_post_signing_assignments(module))

    assert offenders == [], (
        "assign signed payload fields before signing, not after:\n" + "\n".join(offenders)
    )
