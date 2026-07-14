import json
from pathlib import Path

from binary_agent.data.manifest import FunctionRecord, Manifest
from scripts.trace_static_target import build_trace


def _record(
    *,
    name: str,
    address: str,
    ordinal: int,
    relative_path: str,
    text: str,
    stack_regions: list[dict] | None = None,
    pcode_calls: list[dict] | None = None,
    pcode_stores: list[dict] | None = None,
) -> FunctionRecord:
    return FunctionRecord(
        address=address,
        relative_address=int(address, 16),
        name=name,
        relative_path=relative_path,
        source_exists=True,
        ordinal=ordinal,
        size_addresses=16,
        body_size_bytes=16,
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=len(text.encode("utf-8")),
        line_count=len(text.splitlines()),
        return_type="void",
        prototype=f"void {name}(database_dyn *db, request_header *req, char *key)",
        parameters=[
            {"name": "db", "data_type": "database_dyn *", "storage": "RDI:8"},
            {"name": "req", "data_type": "request_header *", "storage": "RSI:8"},
            {"name": "key", "data_type": "char *", "storage": "RDX:8"},
        ],
        emit_c=True,
        stack_regions=stack_regions or [],
        string_refs=[],
        pcode_calls=pcode_calls or [],
        pcode_stores=pcode_stores or [],
        ambiguous_callsites=[],
    )


def _stack_region(name: str = "local_20", size: int = 16, start: int = -0x20) -> dict:
    return {
        "start_offset": start,
        "end_offset": start + size,
        "size_bytes": size,
        "var_names": [name],
        "data_types": ["char"],
    }


def _write_export(tmp_path: Path, records: list[FunctionRecord], sources: dict[str, str]) -> Path:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    for relative_path, text in sources.items():
        (export_dir / relative_path).write_text(text)
    manifest = Manifest(
        binary="demo.bin",
        generated_at="2026-05-10T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=records,
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))
    return export_dir


def test_trace_static_target_explains_heap_backed_non_candidate(tmp_path: Path) -> None:
    text = """
void addinnetgrX(database_dyn *db, request_header *req, char *key) {
  indataset *packet;
  char local_20[16];
  packet = mempool_alloc(db,(long)req->key_len + 0x28,1);
  packet->head.allocsize = req->key_len + 0x28;
  FUN_00105010(packet + 1,key,(long)req->key_len);
}
"""
    record = _record(
        name="addinnetgrX",
        address="0x116410",
        ordinal=0,
        relative_path="00116410_addinnetgrX.c",
        text=text,
        stack_regions=[_stack_region()],
        pcode_calls=[
            {
                "function": "addinnetgrX",
                "callee": "FUN_00105010",
                "callee_address": "0x105010",
                "call_address": "0x1165A3",
                "arg_count": 3,
                "args": ["packet + 1", "key", "req->key_len"],
            }
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"00116410_addinnetgrX.c": text})

    trace = build_trace(export_dir, "addinnetgrX")

    assert trace["analyzer_totals"]["target_candidates"] == 0
    function_trace = trace["matched_functions"][0]
    categories = {
        category
        for entry in function_trace["interesting_c_lines"]
        for category in entry["categories"]
    }
    assert {"allocation", "field_write", "unresolved_call"}.issubset(categories)
    assert any("no p-code store facts" in note for note in trace["assessment"])
    assert any("allocation-backed memory activity" in note for note in trace["assessment"])
