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
    assert bundle.assurance.residual_risk == ResidualRiskTier.CRITICAL
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
        policy_eval=PolicyEvaluation(decision=PolicyDecision.ALLOW, rules_passed=[], rules_failed=[]),
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
