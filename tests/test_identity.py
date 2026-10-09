import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

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


def _make_bundle(now=FIXED_NOW, private_key=None, raw_input=None, policy_rules=None):
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
        policy_rules=tuple(policy.rules) if policy_rules is None else policy_rules,
        raw_input=raw_input,
    )
    return bundle


def test_manifest_is_recorded_on_new_bundles():
    bundle = _make_bundle()

    assert bundle.engine_version.startswith("0.1.0")
    assert bundle.schema_version == str(BUNDLE_SCHEMA_VERSION)
    assert bundle.weight_profile == "default"
    # The policy is now named: a hash over the rules actually evaluated, not
    # the bare "unspecified" a bundle used to carry while its ALLOW/DENY came
    # from rules the signature did not cover.
    assert bundle.policy_version.startswith("sha256:")
    assert len(bundle.policy_version.split("sha256:")[1]) == 64
    assert bundle.rubric_version.startswith("docs/GRADING.md@sha256:")
    assert len(bundle.rubric_version.split("@sha256:")[1]) == 64
    assert bundle.knowledge_base_version.startswith("data/attacks@sha256:")


def test_policy_version_is_unspecified_only_when_no_rules_were_evaluated():
    """A bundle with no policy run says so; one with a policy names it."""
    assert _make_bundle(policy_rules=()).policy_version == UNSPECIFIED


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


REFERENCE_ROLES = (
    "engine",
    "schema",
    "weights",
    "rubric",
    "knowledge_base",
    "policy",
    "input",
)


def test_every_derivation_role_is_named():
    """One reference per role, so the derivation can be reconstructed."""
    bundle = _make_bundle()
    roles = [r.role.value for r in bundle.references]

    assert roles == list(REFERENCE_ROLES)


def test_references_survive_a_roundtrip():
    bundle = _make_bundle(raw_input=b"\x01\x02\x03")
    restored = EvidenceBundle.from_dict(bundle.to_dict())

    assert restored.references == bundle.references
    for ref in restored.references:
        assert ref.id
        assert ref.hash.startswith("sha256:")
        assert len(ref.hash.split("sha256:")[1]) == 64


def test_signing_payload_covers_the_references():
    """The signature must cover the derivation list, not only the verdict."""
    payload = serialize_bundle_for_signing(_make_bundle()).decode("utf-8")

    assert '"references":' in payload
    for role in REFERENCE_ROLES:
        assert f'"role":"{role}"' in payload


def test_the_input_reference_hashes_the_bytes_it_was_given():
    raw = b"\xab\xcd\xef"
    bundle = _make_bundle(raw_input=raw, policy_rules=())
    input_ref = next(r for r in bundle.references if r.role.value == "input")

    import hashlib

    assert input_ref.hash == f"sha256:{hashlib.sha256(raw).hexdigest()}"


def test_every_reference_resolves():
    """A reference that resolves to nothing is a defect, not an omission."""
    bundle = _make_bundle(raw_input=b"\x01")

    for ref in bundle.references:
        assert ref.resolves_to() in ("inline", "published", "hash-only")
        # hash-only is the weakest form and is still a resolution: the hash
        # names the artifact even when no location is published.
        assert ref.hash or ref.inline or ref.location


def test_bundle_without_references_loads():
    """Bundles signed before the derivation list existed still parse."""
    data = _make_bundle().to_dict()
    data.pop("references")

    restored = EvidenceBundle.from_dict(data)

    assert restored.references == []


def test_weights_hash_is_stable_and_profile_specific():
    from src.core.identity import weights_hash

    assert weights_hash("default") == weights_hash("default")
    assert weights_hash("default") != weights_hash("finance")


def test_policy_hash_tracks_the_rules_not_the_file():
    from src.core.identity import policy_hash

    policy = load_policy("tests/fixtures/policy/default.yaml")
    edited = list(policy.rules)[:-1]

    assert policy_hash(policy.rules) == policy_hash(policy.rules)
    assert policy_hash(policy.rules) != policy_hash(edited)


def test_a_malformed_commitments_file_is_not_silently_read_as_empty(tmp_path, monkeypatch):
    """An absent file means "nothing published"; a broken one must not.

    The distinction matters because both used to collapse to the same empty
    mapping, which made a bundle report an unset rubric version when a malformed
    `commitments.json` was sitting on disk -- an assertion about the bundle's
    provenance that was simply false. `load_trust_root` raises for the same reason.
    """
    import src.core.identity as identity

    broken = tmp_path / "commitments.json"
    broken.write_text('{"artifacts": [ this is not json')
    monkeypatch.setattr(identity, "COMMITMENTS_PATH", broken)
    identity.commitments.cache_clear()
    try:
        with pytest.raises(ValueError, match=f"{broken}"):
            identity.commitments()
    finally:
        identity.commitments.cache_clear()


def test_an_absent_commitments_file_is_still_fine(tmp_path, monkeypatch):
    """The unconfigured state must stay available."""
    import src.core.identity as identity

    monkeypatch.setattr(identity, "COMMITMENTS_PATH", tmp_path / "nope.json")
    identity.commitments.cache_clear()
    try:
        assert identity.commitments() == {}
    finally:
        identity.commitments.cache_clear()
