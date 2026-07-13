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


def _make_graph():
    g = EvidenceGraph()
    g.add_node(EvidenceNode("n1", NodeType.QUOTE, platform=Platform.IntelTDX))
    g.add_node(EvidenceNode("n2", NodeType.MEASUREMENT, measurement="0xabc"))
    g.add_node(EvidenceNode("n3", NodeType.TCB_RECORD, tcb_version="v1"))
    g.add_node(EvidenceNode("n4", NodeType.QUOTE, platform=Platform.AMDSEVSNP))
    g.add_edge(EvidenceEdge("n1", "n2", EdgeType.MATCHED_BY))
    g.add_edge(EvidenceEdge("n1", "n3", EdgeType.AFFECTS))
    g.add_edge(EvidenceEdge("n3", "n4", EdgeType.EVALUATES))
    return g


def test_nodes_by_type():
    graph = _make_graph()
    quotes = graph.nodes_by_type(NodeType.QUOTE)
    assert len(quotes) == 2
    assert all(n.node_type == NodeType.QUOTE for n in quotes)


def test_nodes_by_platform():
    graph = _make_graph()
    tdx = graph.nodes_by_platform(Platform.IntelTDX)
    assert len(tdx) == 1
    assert tdx[0].node_id == "n1"


def test_incoming_edges():
    graph = _make_graph()
    edges = graph.incoming_edges("n2")
    assert len(edges) == 1
    assert edges[0].source_id == "n1"


def test_edges_of_type():
    graph = _make_graph()
    matched = graph.edges_of_type(EdgeType.MATCHED_BY)
    assert len(matched) == 1
    assert matched[0].target_id == "n2"


def test_subgraph():
    graph = _make_graph()
    sg = graph.subgraph({"n1", "n2"})
    assert len(sg.nodes) == 2
    assert "n3" not in sg.nodes
    assert len(sg.edges) == 1
    assert sg.edges[0].edge_type == EdgeType.MATCHED_BY


def test_to_dict_round_trip():
    graph = _make_graph()
    data = graph.to_dict()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) == 4
    assert len(data["edges"]) == 3
    restored = EvidenceGraph.from_dict(data)
    assert restored.get_node("n1") == graph.get_node("n1")
    assert len(restored.edges) == 3


def test_to_dict_from_dict_empty():
    graph = EvidenceGraph()
    data = graph.to_dict()
    assert data == {"nodes": {}, "edges": []}
    restored = EvidenceGraph.from_dict(data)
    assert len(restored.nodes) == 0
    assert len(restored.edges) == 0
