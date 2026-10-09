import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.core.taxonomy import EvidenceGraph, EvidenceNode, NodeType, Platform
from src.core.trust import TrustedKey, TrustRoot, TrustRootError, load_trust_root
from src.ingest.adapters.iac_provenance import parse_iac_provenance
from src.verify import compute_provenance_dimension, ingest_iac_provenance


def _make_dsse(predicate_type: str, subject: dict, predicate: dict, keyid: str = "test-key") -> str:
    statement = {
        "type": "https://in-toto.io/Statement/v0.1",
        "predicateType": predicate_type,
        "subject": [subject],
        "predicate": predicate,
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": payload,
        "signatures": [{"keyid": keyid, "sig": "a" * 32}],
    }
    return json.dumps(envelope)


def test_parse_slsa_v1_provenance():
    subject = {"name": "pkg:docker/app@sha256:abcd", "digest": {"sha256": "abcd1234"}}
    predicate = {
        "buildDefinition": {
            "buildType": "https://github.com/slsa-framework/slsa@v1",
            "resolvedDependencies": [
                {"uri": "git+https://github.com/org/repo@abc123", "digest": {"gitCommit": "abc123"}}
            ],
        },
        "runDetails": {"builder": {"id": "https://github.com/org/repo/.github/workflows/build.yml"}},
    }
    envelope = _make_dsse("https://slsa.dev/provenance/v1", subject, predicate)
    prov = parse_iac_provenance(envelope)
    assert prov.predicate_type == "https://slsa.dev/provenance/v1"
    assert prov.subject_name == "pkg:docker/app@sha256:abcd"
    assert prov.subject_digest == {"sha256": "abcd1234"}
    assert prov.signer_identity == "test-key"
    assert prov.build_commit == "abc123"
    assert prov.builder_id == "https://github.com/org/repo/.github/workflows/build.yml"


def test_ingest_iac_provenance_node():
    subject = {"name": "app", "digest": {"sha256": "deadbeef"}}
    envelope = _make_dsse("https://slsa.dev/provenance/v0.2", subject, {"metadata": {}})
    node = ingest_iac_provenance("prov-1", envelope)
    assert node.node_id == "prov-1"
    assert node.node_type == NodeType.IAC_PROVENANCE
    assert node.iac_provenance is not None
    assert node.iac_provenance.subject_digest == {"sha256": "deadbeef"}


def test_compute_provenance_dimension_absent():
    graph = EvidenceGraph()
    assert compute_provenance_dimension(graph) == "absent"


def test_compute_provenance_dimension_signed():
    graph = EvidenceGraph()
    node = ingest_iac_provenance(
        "prov-1",
        _make_dsse("https://slsa.dev/provenance/v0.2", {"name": "app", "digest": {}}, {}),
    )
    graph.add_node(node)
    assert compute_provenance_dimension(graph) == "signed"


def test_compute_provenance_dimension_chained():
    graph = EvidenceGraph()
    graph.add_node(
        EvidenceNode("quote-1", NodeType.QUOTE, platform=Platform.AWSNitro, measurement="deadbeef")
    )
    prov = ingest_iac_provenance(
        "prov-1",
        _make_dsse(
            "https://slsa.dev/provenance/v0.2",
            {"name": "app", "digest": {"sha256": "deadbeef"}},
            {},
        ),
    )
    graph.add_node(prov)
    assert compute_provenance_dimension(graph, measurement_node_id="quote-1") == "chained"


def test_compute_provenance_dimension_signed_when_digest_mismatches():
    graph = EvidenceGraph()
    graph.add_node(
        EvidenceNode("quote-1", NodeType.QUOTE, platform=Platform.AWSNitro, measurement="abcd")
    )
    prov = ingest_iac_provenance(
        "prov-1",
        _make_dsse(
            "https://slsa.dev/provenance/v0.2",
            {"name": "app", "digest": {"sha256": "deadbeef"}},
            {},
        ),
    )
    graph.add_node(prov)
    assert compute_provenance_dimension(graph, measurement_node_id="quote-1") == "signed"


def test_ingest_decoded_statement():
    """Some CI systems hand us the already-decoded statement, not a DSSE envelope."""
    statement = {
        "type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [{"name": "app", "digest": {"sha256": "0000"}}],
        "predicate": {"builder": {"id": "https://github.com/org/.github/workflows/ci.yml"}},
    }
    node = ingest_iac_provenance("prov-2", json.dumps(statement))
    assert node.iac_provenance is not None
    assert node.iac_provenance.predicate_type == "https://slsa.dev/provenance/v0.2"
    assert node.iac_provenance.signer_identity == "unknown"


def test_evidence_node_roundtrip_with_iac_provenance():
    statement = {
        "type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [{"name": "app", "digest": {"sha256": "0000"}}],
        "predicate": {},
    }
    node = ingest_iac_provenance("prov-rt", json.dumps(statement))
    d = node.to_dict()
    restored = EvidenceNode.from_dict(d)
    assert restored.iac_provenance is not None
    assert restored.iac_provenance.predicate_type == node.iac_provenance.predicate_type
    assert restored.iac_provenance.subject_digest == node.iac_provenance.subject_digest


def test_compute_assurance_level_includes_provenance_dimension():
    from src.core.risk import compute_assurance_level
    from src.core.taxonomy import EdgeType, EvidenceEdge

    graph = EvidenceGraph()
    graph.add_node(
        EvidenceNode(
            "quote-1",
            NodeType.QUOTE,
            platform=Platform.IntelTDX,
            measurement="deadbeef",
            debug_disabled=True,
        )
    )
    graph.add_node(EvidenceNode("build-1", NodeType.BUILD_PROVENANCE))
    prov = ingest_iac_provenance(
        "prov-1",
        _make_dsse(
            "https://slsa.dev/provenance/v0.2",
            {"name": "app", "digest": {"sha256": "deadbeef"}},
            {},
        ),
    )
    graph.add_node(prov)
    graph.add_edge(EvidenceEdge("prov-1", "quote-1", EdgeType.DERIVED_FROM))
    eval_ = compute_assurance_level(graph)
    assert eval_.dimensions.get("provenance") == "chained"
    assert "IaC provenance is chained" in eval_.boundary_statement


# --- Trust root: signature verification (docs/CODEBASE-REVIEW-2026-10-03.md gap 5) ---


def _signed_dsse(private_key, keyid: str = "release-bot") -> str:
    """A real DSSE envelope: signature over the PAE of the payload."""
    statement = {
        "type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": "pkg:docker/app@sha256:abcd", "digest": {"sha256": "abcd1234"}}],
        "predicate": {},
    }
    payload = json.dumps(statement).encode()
    payload_type = "application/vnd.in-toto+json"
    pae = b"DSSEv1 " + str(len(payload_type)).encode() + b" " + payload_type.encode()
    pae += b" " + str(len(payload)).encode() + b" " + payload
    signature = private_key.sign(pae)
    return json.dumps(
        {
            "payloadType": payload_type,
            "payload": base64.b64encode(payload).decode(),
            "signatures": [
                {"keyid": keyid, "sig": base64.b64encode(signature).decode()}
            ],
        }
    )


def _root_for(private_key, keyid: str = "release-bot") -> TrustRoot:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return TrustRoot(
        keys=(TrustedKey(key_id=keyid, public_key_b64=base64.b64encode(raw).decode()),)
    )


def test_signature_verified_true_against_matching_trust_root():
    key = Ed25519PrivateKey.generate()
    prov = parse_iac_provenance(_signed_dsse(key), trust_root=_root_for(key))
    assert prov.signature_verified is True


def test_signature_verified_false_when_key_is_wrong():
    signer, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    prov = parse_iac_provenance(_signed_dsse(signer), trust_root=_root_for(other))
    assert prov.signature_verified is False


def test_signature_verified_none_when_key_not_in_trust_root():
    """An unknown key id is unjudged, not verified."""
    key = Ed25519PrivateKey.generate()
    prov = parse_iac_provenance(_signed_dsse(key, keyid="stranger"), trust_root=_root_for(key))
    assert prov.signature_verified is None


def test_signature_verified_none_without_a_trust_root():
    key = Ed25519PrivateKey.generate()
    prov = parse_iac_provenance(_signed_dsse(key))
    assert prov.signature_verified is None


def test_tampered_payload_fails_verification():
    """Flipping a byte of the payload invalidates the signature over its PAE."""
    key = Ed25519PrivateKey.generate()
    envelope = json.loads(_signed_dsse(key))
    statement = json.loads(base64.b64decode(envelope["payload"]))
    statement["predicate"] = {"backdoor": True}
    envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    prov = parse_iac_provenance(json.dumps(envelope), trust_root=_root_for(key))
    assert prov.signature_verified is False


def test_signature_verified_survives_a_bundle_round_trip():
    key = Ed25519PrivateKey.generate()
    prov = parse_iac_provenance(_signed_dsse(key), trust_root=_root_for(key))
    again = type(prov).from_dict(prov.to_dict())
    assert again.signature_verified is True


def test_ingest_threads_the_trust_root_through():
    key = Ed25519PrivateKey.generate()
    node = ingest_iac_provenance("n1", _signed_dsse(key), trust_root=_root_for(key))
    assert node.iac_provenance is not None
    assert node.iac_provenance.signature_verified is True


def test_load_trust_root_missing_file_is_empty_not_an_error(tmp_path):
    """Running unconfigured is the Phase 0 behaviour and must stay available."""
    root = load_trust_root(tmp_path / "does-not-exist.json")
    assert not root
    assert root.verify("anything", b"msg", b"sig") is None


def test_load_trust_root_reads_keys(tmp_path):
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    path = tmp_path / "trust-roots.json"
    path.write_text(
        json.dumps({"keys": [{"key_id": "k", "public_key": base64.b64encode(raw).decode()}]})
    )
    root = load_trust_root(path)
    assert root.key("k") is not None
    assert root.key("other") is None


def test_load_trust_root_rejects_a_malformed_file(tmp_path):
    """A trust root that exists but is unreadable must not be silently ignored."""
    path = tmp_path / "trust-roots.json"
    path.write_text("{not json")
    try:
        load_trust_root(path)
    except TrustRootError:
        return
    raise AssertionError("malformed trust root should raise")
