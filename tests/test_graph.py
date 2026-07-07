from src.core.taxonomy import (
    EdgeType,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeType,
    Platform,
)


def test_add_and_get_node():
    graph = EvidenceGraph()
    node = EvidenceNode("n1", NodeType.QUOTE, platform=Platform.IntelTDX)
    graph.add_node(node)
    assert graph.get_node("n1") == node


def test_add_edge():
    graph = EvidenceGraph()
    graph.add_node(EvidenceNode("n1", NodeType.QUOTE, platform=Platform.IntelTDX))
    graph.add_node(EvidenceNode("n2", NodeType.MEASUREMENT, measurement="0xabc"))
    graph.add_edge(EvidenceEdge("n1", "n2", EdgeType.MATCHED_BY))
    assert len(graph.edges) == 1


def test_traverse_by_type():
    graph = EvidenceGraph()
    graph.add_node(EvidenceNode("n1", NodeType.QUOTE, platform=Platform.IntelTDX))
    graph.add_node(EvidenceNode("n2", NodeType.MEASUREMENT, measurement="0xabc"))
    graph.add_node(EvidenceNode("n3", NodeType.TCB_RECORD, tcb_version="v1"))
    graph.add_edge(EvidenceEdge("n1", "n2", EdgeType.MATCHED_BY))
    graph.add_edge(EvidenceEdge("n1", "n3", EdgeType.AFFECTS))

    matched = graph.traverse("n1", EdgeType.MATCHED_BY)
    assert len(matched) == 1
    assert matched[0].node_id == "n2"

    affected = graph.traverse("n1", EdgeType.AFFECTS)
    assert len(affected) == 1
    assert affected[0].node_id == "n3"


def test_traverse_all_edges():
    graph = EvidenceGraph()
    graph.add_node(EvidenceNode("n1", NodeType.QUOTE, platform=Platform.IntelTDX))
    graph.add_node(EvidenceNode("n2", NodeType.MEASUREMENT, measurement="0xabc"))
    graph.add_node(EvidenceNode("n3", NodeType.TCB_RECORD, tcb_version="v1"))
    graph.add_edge(EvidenceEdge("n1", "n2", EdgeType.MATCHED_BY))
    graph.add_edge(EvidenceEdge("n1", "n3", EdgeType.AFFECTS))

    all_results = graph.traverse("n1")
    assert len(all_results) == 2


def test_traverse_empty():
    graph = EvidenceGraph()
    assert graph.traverse("nonexistent") == []


def test_multi_platform_nodes():
    graph = EvidenceGraph()
    graph.add_node(EvidenceNode("tdx", NodeType.QUOTE, platform=Platform.IntelTDX))
    graph.add_node(EvidenceNode("sev", NodeType.QUOTE, platform=Platform.AMDSEVSNP))
    graph.add_node(EvidenceNode("nitro", NodeType.QUOTE, platform=Platform.AWSNitro))

    assert graph.get_node("tdx").platform == Platform.IntelTDX
    assert graph.get_node("sev").platform == Platform.AMDSEVSNP
    assert graph.get_node("nitro").platform == Platform.AWSNitro
