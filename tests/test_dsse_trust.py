from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from src.core.taxonomy import (
    AssuranceEvaluation,
    AssuranceLevel,
    EvidenceBundle,
    EvidenceGraph,
    PolicyDecision,
    PolicyEvaluation,
    ResidualRiskTier,
)
from src.export.dsse import (
    anchor_to_rekor,
    create_signed_bundle,
    generate_ed25519_keypair,
    load_or_create_keypair,
    serialize_bundle_for_signing,
    sign_bundle,
)


def _public_key_hex(private_key) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _private_key_hex(private_key) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()


def _make_unsigned_bundle(workload: str = "test") -> EvidenceBundle:
    now = datetime.now()
    return EvidenceBundle(
        bundle_id=f"bundle-{now.strftime('%Y%m%d%H%M%S')}",
        timestamp=now,
        expires_at=now + timedelta(days=30),
        workload=workload,
        evidence_graph_summary={"node_count": 1, "edge_count": 0, "platforms": ["Intel-TDX"]},
        policy_evaluation=PolicyEvaluation(decision=PolicyDecision.ALLOW),
        assurance=AssuranceEvaluation(
            level=AssuranceLevel.HARDWARE_ATTESTED,
            residual_risk=ResidualRiskTier.HIGH,
            boundary_statement="test",
        ),
    )


def test_load_or_create_keypair_creates_new(tmp_path: Path):
    key_path = tmp_path / "op-key.json"
    private_key, public_key, is_new = load_or_create_keypair(key_path)
    assert is_new is True
    assert key_path.exists()
    data = json.loads(key_path.read_text())
    assert data["algorithm"] == "Ed25519"
    assert "private_key_hex" in data
    assert "public_key_hex" in data
    assert data["public_key_hex"] == _public_key_hex(private_key)
    assert data["public_key_hex"] == public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def test_load_or_create_keypair_loads_existing(tmp_path: Path):
    key_path = tmp_path / "op-key.json"
    private_key_1, _, _ = load_or_create_keypair(key_path)
    private_key_2, _, is_new_2 = load_or_create_keypair(key_path)
    assert is_new_2 is False
    assert _private_key_hex(private_key_1) == _private_key_hex(private_key_2)


def test_load_or_create_keypair_round_trip(tmp_path: Path):
    """A key created, saved, and reloaded signs the same payload the same way."""
    key_path = tmp_path / "op-key.json"
    private_key, _, _ = load_or_create_keypair(key_path)
    bundle = _make_unsigned_bundle()
    pre_auth = serialize_bundle_for_signing(bundle)
    sig_1 = private_key.sign(pre_auth).hex()

    private_key_2, _, _ = load_or_create_keypair(key_path)
    sig_2 = private_key_2.sign(pre_auth).hex()
    assert sig_1 == sig_2


def test_anchor_to_rekor_attaches_entry():
    """Anchor with a mock poster attaches RekorEntry to the signature."""
    bundle = _make_unsigned_bundle(workload="anchor-test")
    private_key, _ = generate_ed25519_keypair()
    sign_bundle(bundle, private_key)
    assert bundle.signatures[0].rekor_entry is None

    mock_response = {
        "uuid": "test-uuid-1234",
        "logIndex": 42,
        "logID": "test-log-id",
        "integratedTime": 1718900000,
        "body": {},
        "verification": {},
    }

    def mock_poster(url: str, body: bytes) -> dict:
        return mock_response

    bundle = anchor_to_rekor(bundle, rekor_url="https://example.com/rekor", poster=mock_poster)
    re = bundle.signatures[0].rekor_entry
    assert re is not None
    assert re.entry_uuid == "test-uuid-1234"
    assert re.log_index == 42
    assert re.log_id == "test-log-id"
    assert re.integrated_time == datetime.fromtimestamp(1718900000)


def test_anchor_to_rekor_fails_soft():
    """If Rekor submission errors, bundle is returned unchanged, no exception."""
    bundle = _make_unsigned_bundle(workload="fail-soft-test")
    private_key, _ = generate_ed25519_keypair()
    sign_bundle(bundle, private_key)

    from src.export.rekor import RekorError

    def mock_poster(url: str, body: bytes) -> dict:
        raise RekorError("simulated network failure")

    bundle = anchor_to_rekor(bundle, rekor_url="https://example.com/rekor", poster=mock_poster)
    assert bundle.signatures[0].rekor_entry is None
    assert len(bundle.signatures) == 1


def test_create_signed_bundle_with_persistent_key(tmp_path: Path):
    """create_signed_bundle with a passed private_key uses that key."""
    key_path = tmp_path / "op-key.json"
    private_key, _, _ = load_or_create_keypair(key_path)

    bundle_out, _ = create_signed_bundle(
        graph=EvidenceGraph(),
        policy_eval=PolicyEvaluation(decision=PolicyDecision.ALLOW),
        assurance=AssuranceEvaluation(
            level=AssuranceLevel.HARDWARE_ATTESTED,
            residual_risk=ResidualRiskTier.HIGH,
            boundary_statement="test",
        ),
        workload="persistent-key-test",
        private_key=private_key,
    )
    assert bundle_out.signatures[0].key_id == _public_key_hex(private_key)
    assert bundle_out.signatures[0].rekor_entry is None


def test_create_signed_bundle_with_anchor_to_rekor():
    """create_signed_bundle with enable_rekor_anchoring=True attaches a RekorEntry."""
    mock_response = {
        "uuid": "test-uuid-anchor",
        "logIndex": 99,
        "logID": "log-id",
        "integratedTime": 1718900000,
        "body": {},
        "verification": {},
    }

    def mock_poster(url: str, body: bytes) -> dict:
        return mock_response

    bundle, _ = create_signed_bundle(
        graph=EvidenceGraph(),
        policy_eval=PolicyEvaluation(decision=PolicyDecision.ALLOW),
        assurance=AssuranceEvaluation(
            level=AssuranceLevel.HARDWARE_ATTESTED,
            residual_risk=ResidualRiskTier.HIGH,
            boundary_statement="test",
        ),
        workload="anchor-via-create",
        enable_rekor_anchoring=True,
        rekor_url="https://example.com/rekor",
        rekor_poster=mock_poster,
    )
    assert bundle.signatures[0].rekor_entry is not None
    assert bundle.signatures[0].rekor_entry.entry_uuid == "test-uuid-anchor"


def test_bundle_with_rekor_entry_roundtrips_through_dict():
    """Bundles with RekorEntry serialize and deserialize cleanly."""
    bundle = _make_unsigned_bundle()
    sign_bundle(bundle, generate_ed25519_keypair()[0])

    mock_response = {
        "uuid": "roundtrip-uuid",
        "logIndex": 7,
        "logID": "log-x",
        "integratedTime": 1718900000,
        "body": {},
        "verification": {},
    }
    bundle = anchor_to_rekor(
        bundle,
        rekor_url="https://example.com/rekor",
        poster=lambda u, b: mock_response,
    )

    data = bundle.to_dict()
    assert "rekor_entry" in data["signatures"][0]
    assert data["signatures"][0]["rekor_entry"]["entry_uuid"] == "roundtrip-uuid"

    bundle_2 = EvidenceBundle.from_dict(data)
    re_2 = bundle_2.signatures[0].rekor_entry
    assert re_2 is not None
    assert re_2.entry_uuid == "roundtrip-uuid"
    assert re_2.log_index == 7


def test_bundle_without_rekor_entry_roundtrips():
    """Backwards compat: bundles without rekor_entry still roundtrip."""
    bundle = _make_unsigned_bundle()
    sign_bundle(bundle, generate_ed25519_keypair()[0])

    data = bundle.to_dict()
    assert data["signatures"][0]["rekor_entry"] is None

    bundle_2 = EvidenceBundle.from_dict(data)
    assert bundle_2.signatures[0].rekor_entry is None

