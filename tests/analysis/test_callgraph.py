from binary_agent.analysis.callgraph import CallGraph, build_call_graph
from tests.utils import make_function_node


def test_find_paths_returns_multiple_simple_paths():
    edges = {
        "entry": {"A", "B"},
        "A": {"target"},
        "B": {"target"},
        "target": set(),
    }
    reverse = {
        "entry": set(),
        "A": {"entry"},
        "B": {"entry"},
        "target": {"A", "B"},
    }
    order = {"entry": 0, "A": 1, "B": 2, "target": 3}
    graph = CallGraph(edges=edges, reverse_edges=reverse, order=order)

    paths = graph.find_paths(["entry"], "target", max_depth=4, limit=2)

    assert paths == [["entry", "A", "target"], ["entry", "B", "target"]]


def test_find_paths_to_targets_runs_single_bfs():
    edges = {
        "entry": {"A", "B"},
        "A": {"t1"},
        "B": {"mid"},
        "mid": {"t2"},
        "t1": set(),
        "t2": set(),
    }
    reverse = {
        "entry": set(),
        "A": {"entry"},
        "B": {"entry"},
        "mid": {"B"},
        "t1": {"A"},
        "t2": {"mid"},
    }
    order = {name: idx for idx, name in enumerate(edges)}
    graph = CallGraph(edges=edges, reverse_edges=reverse, order=order)

    targets = {"t1", "t2"}
    paths = graph.find_paths_to_targets(["entry"], targets, max_depth=4)

    assert paths["t1"] == ["entry", "A", "t1"]
    assert paths["t2"] == ["entry", "B", "mid", "t2"]


def test_find_reverse_path_walks_toward_entrypoints():
    edges = {
        "entry": {"A"},
        "A": {"B"},
        "B": {"sink"},
        "sink": set(),
    }
    reverse = {
        "entry": set(),
        "A": {"entry"},
        "B": {"A"},
        "sink": {"B"},
    }
    order = {name: idx for idx, name in enumerate(edges)}
    graph = CallGraph(edges=edges, reverse_edges=reverse, order=order)

    path = graph.find_reverse_path("sink", ["entry"], max_depth=4)

    assert path == ["entry", "A", "B", "sink"]


def test_build_call_graph_contracts_wrappers():
    main = make_function_node(name="main", text="int main(){ wrapper(); }", callees=["wrapper"], callers=[])
    wrapper = make_function_node(
        name="wrapper",
        text="int wrapper(){ target(); }",
        callees=["target"],
        callers=["main"],
        wrapper_type="single_call_wrapper",
    )
    target = make_function_node(name="target", text="int target(){ return 0; }", callees=[], callers=["wrapper"])

    graph = build_call_graph([main, wrapper, target])

    assert "wrapper" in graph.transparent_nodes
    assert "target" in graph.neighbors("main")


def test_build_call_graph_contracts_unlabeled_one_call_forwarder():
    main = make_function_node(name="main", text="int main(){ wrapper(); }", callees=["wrapper"], callers=[])
    wrapper = make_function_node(
        name="wrapper",
        text="int wrapper(int value){ return target(value); }",
        callees=["target"],
        callers=["main"],
    )
    target = make_function_node(name="target", text="int target(int value){ return value; }", callees=[], callers=["wrapper"])

    graph = build_call_graph([main, wrapper, target])

    assert "wrapper" in graph.transparent_nodes
    assert "target" in graph.neighbors("main")
