import json
from pathlib import Path

from binary_agent.analysis.callgraph import build_call_graph, load_cached_call_graph
from binary_agent.data.manifest import FunctionRecord, Manifest
from binary_agent.ingest.loader import FunctionNode


def _record(name: str, ordinal: int) -> FunctionRecord:
    return FunctionRecord(
        address="0x0",
        relative_address=0,
        name=name,
        relative_path="",
        source_exists=True,
        ordinal=ordinal,
        size_addresses=0,
        body_size_bytes=0,
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=0,
        line_count=0,
        return_type="",
        prototype="",
        parameters=[],
        emit_c=True,
        stack_regions=[],
        string_refs=[],
    )


def test_load_cached_call_graph_merges_text_edges(tmp_path: Path) -> None:
    callgraph_path = tmp_path / "callgraph.json"
    callgraph_path.write_text(json.dumps({"image_base": 0, "edges": {"main": []}}))

    manifest = Manifest(
        binary="test",
        generated_at="now",
        export_dir=str(tmp_path),
        image_base=0,
        ghidra_manifest=str(tmp_path / "manifest.jsonl"),
        callgraph_path="callgraph.json",
        functions=[_record("main", 0), _record("sink", 1)],
    )

    nodes = [
        FunctionNode(record=manifest.functions[0], text="sink();", metadata={}, path=None, record_index=0),
        FunctionNode(record=manifest.functions[1], text="", metadata={}, path=None, record_index=1),
    ]

    graph = load_cached_call_graph(manifest, nodes)
    assert graph is not None
    assert "sink" in graph.edges.get("main", set())


def test_load_cached_call_graph_optionally_merges_pcode_edges(tmp_path: Path) -> None:
    manifest = Manifest(
        binary="test",
        generated_at="now",
        export_dir=str(tmp_path),
        image_base=0,
        ghidra_manifest=str(tmp_path / "manifest.jsonl"),
        callgraph_path=None,
        functions=[_record("main", 0), _record("sink", 1)],
    )
    caller = manifest.functions[0]
    caller = FunctionRecord.from_dict(
        {
            **caller.to_dict(),
            "pcode_calls": [{"callee": "sink"}],
        }
    )
    nodes = [
        FunctionNode(record=caller, text="", metadata={}, path=None, record_index=0),
        FunctionNode(record=manifest.functions[1], text="", metadata={}, path=None, record_index=1),
    ]

    graph = build_call_graph(nodes, include_pcode_edges=True)
    assert "sink" in graph.edges.get("main", set())
