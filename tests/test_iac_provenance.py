import base64
import json

import pytest

from src.core.taxonomy import EvidenceGraph, EvidenceNode, NodeType, Platform
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
    graph.add_node(EvidenceNode("quote-1", NodeType.QUOTE, platform=Platform.AWSNitro, measurement="deadbeef"))
    prov = ingest_iac_provenance(
        "prov-1",
        _make_dsse("https://slsa.dev/provenance/v0.2", {"name": "app", "digest": {"sha256": "deadbeef"}}, {}),
    )
    graph.add_node(prov)
    assert compute_provenance_dimension(graph, measurement_node_id="quote-1") == "chained"


def test_compute_provenance_dimension_signed_when_digest_mismatches():
    graph = EvidenceGraph()
    graph.add_node(EvidenceNode("quote-1", NodeType.QUOTE, platform=Platform.AWSNitro, measurement="abcd"))
    prov = ingest_iac_provenance(
        "prov-1",
        _make_dsse("https://slsa.dev/provenance/v0.2", {"name": "app", "digest": {"sha256": "deadbeef"}}, {}),
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
    from src.core.taxonomy import EvidenceEdge, EdgeType

    graph = EvidenceGraph()
    graph.add_node(EvidenceNode("quote-1", NodeType.QUOTE, platform=Platform.IntelTDX, measurement="deadbeef", debug_disabled=True))
    graph.add_node(EvidenceNode("build-1", NodeType.BUILD_PROVENANCE))
    prov = ingest_iac_provenance(
        "prov-1",
        _make_dsse("https://slsa.dev/provenance/v0.2", {"name": "app", "digest": {"sha256": "deadbeef"}}, {}),
    )
    graph.add_node(prov)
    graph.add_edge(EvidenceEdge("prov-1", "quote-1", EdgeType.DERIVED_FROM))
    eval_ = compute_assurance_level(graph)
    assert eval_.dimensions.get("provenance") == "chained"
    assert "IaC provenance is chained" in eval_.boundary_statement
