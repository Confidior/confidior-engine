import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.core.identity import (
    BUNDLE_SCHEMA_VERSION,
    UNSPECIFIED,
    engine_version,
    rubric_version,
)
from src.core.policy import evaluate, load_policy
from src.core.risk import compute_assurance_level
from src.core.taxonomy import (
    EvidenceBundle,
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Platform,
    TCBStatus,
)
from src.export.dsse import (
    create_signed_bundle,
    generate_ed25519_keypair,
    serialize_bundle_for_signing,
)

ENGINE_ROOT = Path(__file__).resolve().parent.parent
FIXED_NOW = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
MANIFEST_FIELDS = (
    "engine_version",
    "schema_version",
    "weight_profile",
    "policy_version",
    "rubric_version",
    "knowledge_base_version",
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


def _make_bundle(now=FIXED_NOW, private_key=None):
    graph = EvidenceGraph()
    graph.add_node(_make_quote_node(Platform.IntelTDX))
    policy = load_policy("tests/fixtures/policy/default.yaml")
    policy_eval = evaluate(graph, policy)
    assurance = compute_assurance_level(graph)
    bundle, _ = create_signed_bundle(
        graph=graph,
        policy_eval=policy_eval,
        assurance=assurance,
        workload="test-workload",
        now=now,
        private_key=private_key,
    )
    return bundle


def test_manifest_is_recorded_on_new_bundles():
    bundle = _make_bundle()

    assert bundle.engine_version.startswith("0.1.0")
    assert bundle.schema_version == str(BUNDLE_SCHEMA_VERSION)
    assert bundle.weight_profile == "default"
    assert bundle.policy_version == UNSPECIFIED
    assert bundle.rubric_version.startswith("docs/GRADING.md@sha256:")
    assert len(bundle.rubric_version.split("@sha256:")[1]) == 64
    assert bundle.knowledge_base_version.startswith("data/attacks@sha256:")


def test_manifest_survives_a_roundtrip():
    bundle = _make_bundle()
    restored = EvidenceBundle.from_dict(bundle.to_dict())

    for field_name in MANIFEST_FIELDS:
        assert getattr(restored, field_name) == getattr(bundle, field_name)


def test_bundle_without_a_manifest_loads_with_empty_values():
    data = _make_bundle().to_dict()
    for field_name in MANIFEST_FIELDS:
        data.pop(field_name)

    restored = EvidenceBundle.from_dict(data)

    for field_name in MANIFEST_FIELDS:
        assert getattr(restored, field_name) == ""


def test_signing_payload_covers_the_manifest():
    payload = serialize_bundle_for_signing(_make_bundle()).decode("utf-8")

    for field_name in MANIFEST_FIELDS:
        assert f'"{field_name}":' in payload


def test_bundle_is_reproducible_with_a_fixed_instant():
    private_key, _ = generate_ed25519_keypair()

    first = _make_bundle(private_key=private_key)
    second = _make_bundle(private_key=private_key)

    assert first.bundle_id == second.bundle_id
    assert first.timestamp == second.timestamp
    assert serialize_bundle_for_signing(first) == serialize_bundle_for_signing(second)


def test_engine_version_names_the_engine():
    version = engine_version()

    assert version != "unknown"
    assert version.startswith("0.1.0")


def test_rubric_version_matches_the_published_commitment():
    published = json.loads((ENGINE_ROOT / "commitments.json").read_text())
    rubric = next(a for a in published["artifacts"] if a["role"] == "rubric")

    assert rubric_version() == f"{rubric['label']}@sha256:{rubric['sha256']}"


def test_published_commitments_match_the_tree():
    result = subprocess.run(
        [sys.executable, "scripts/publish_commitments.py", "--check"],
        cwd=ENGINE_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
