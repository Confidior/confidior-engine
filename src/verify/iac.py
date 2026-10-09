"""Verify IaC provenance statements and derive a badge dimension.

Signature verification is available against a configured trust root
(``src/core/trust.py``). When no trust root is configured, the envelope is
parsed structurally and the record reports ``signature_verified = None`` --
parsed, not verified. A key that is in the trust root and rejects the signature
reports ``False``; the two are never collapsed.

Dimension values:
- ``chained``   : provenance present, signed, and linked to a TEE measurement
- ``signed``    : provenance present and signed, but not linked to measurement
- ``absent``    : no provenance evidence
"""

from __future__ import annotations

from src.core.taxonomy import EvidenceGraph, EvidenceNode, NodeType
from src.core.trust import TrustRoot
from src.ingest.adapters.iac_provenance import parse_iac_provenance

ProvenanceDimension = str  # "chained" | "signed" | "absent"


def ingest_iac_provenance(
    node_id: str, envelope_json: str | bytes, trust_root: TrustRoot | None = None
) -> EvidenceNode:
    """Parse a DSSE envelope and return an ``IAC_PROVENANCE`` evidence node.

    Pass ``trust_root`` to have the envelope's signature checked against a
    configured key; the result is carried on the record as ``signature_verified``.
    """
    provenance = parse_iac_provenance(envelope_json, trust_root=trust_root)
    return EvidenceNode(
        node_id=node_id,
        node_type=NodeType.IAC_PROVENANCE,
        iac_provenance=provenance,
        evidence_type=provenance.predicate_type,
        verifier=provenance.signer_identity,
    )


def compute_provenance_dimension(
    graph: EvidenceGraph,
    measurement_node_id: str | None = None,
) -> ProvenanceDimension:
    """Derive the provenance badge dimension for an evidence graph.

    If ``measurement_node_id`` is supplied, a provenance node whose subject
    digest matches the measurement is considered ``chained``. Otherwise the
    first QUOTE node's measurement is used as the default anchor.
    """
    provenance_nodes = graph.nodes_by_type(NodeType.IAC_PROVENANCE)
    if not provenance_nodes:
        return "absent"

    measurement = None
    if measurement_node_id and measurement_node_id in graph.nodes:
        measurement = graph.nodes[measurement_node_id].measurement
    if measurement is None:
        for node in graph.nodes_by_type(NodeType.QUOTE):
            if node.measurement:
                measurement = node.measurement
                break

    for node in provenance_nodes:
        if not node.iac_provenance:
            continue
        if measurement and node.iac_provenance.subject_digest:
            for algo, digest in node.iac_provenance.subject_digest.items():
                if digest and digest.lower() == measurement.lower():
                    return "chained"
    return "signed"
