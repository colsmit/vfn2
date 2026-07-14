import json
from pathlib import Path

import pytest

from binary_agent.data.manifest import FunctionRecord, Manifest, ManifestError
from binary_agent.ingest import load_function_nodes


def _write_manifest(export_dir: Path, manifest: Manifest) -> None:
    manifest_path = export_dir / "manifest_normalized.json"
    manifest_path.write_text(json.dumps(manifest.to_dict()))


def test_load_function_nodes(tmp_path: Path) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()

    source_path = export_dir / "00001000_test.c"
    source_content = "int test() { return 7; }\n"
    source_path.write_text(source_content)

    record = FunctionRecord(
        address="0x1000",
        relative_address=0x1000,
        name="test",
        relative_path=source_path.name,
        source_exists=False,
        ordinal=0,
        size_addresses=4,
        body_size_bytes=4,
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=len(source_content.encode("utf-8")),
        line_count=len(source_content.splitlines()),
        return_type="int",
        prototype="int test(void)",
        parameters=[],
        emit_c=True,
        stack_regions=[],
        string_refs=[],
    )
    manifest = Manifest(
        binary="demo.bin",
        generated_at="2024-01-01T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=[record],
    )
    _write_manifest(export_dir, manifest)

    loaded_manifest, nodes = load_function_nodes(export_dir)
    assert loaded_manifest.binary == "demo.bin"
    assert len(nodes) == 1
    fn_node = nodes[0]
    assert fn_node.path == source_path
    assert fn_node.text == source_content
    assert fn_node.metadata["function_name"] == "test"
    assert fn_node.metadata["pcode_calls"] == []
    assert fn_node.metadata["ambiguous_callsites"] == []


def test_load_function_nodes_uses_requested_export_dir_for_relocated_manifest(tmp_path: Path) -> None:
    stale_dir = tmp_path / "stale" / "decompiled"
    export_dir = tmp_path / "current" / "decompiled"
    export_dir.mkdir(parents=True)

    source_path = export_dir / "00001000_test.c"
    source_content = "int test() { return 7; }\n"
    source_path.write_text(source_content)

    record = FunctionRecord(
        address="0x1000",
        relative_address=0x1000,
        name="test",
        relative_path=source_path.name,
        source_exists=True,
        ordinal=0,
        size_addresses=4,
        body_size_bytes=4,
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=len(source_content.encode("utf-8")),
        line_count=len(source_content.splitlines()),
        return_type="int",
        prototype="int test(void)",
        parameters=[],
        emit_c=True,
        stack_regions=[],
        string_refs=[],
    )
    manifest = Manifest(
        binary="demo.bin",
        generated_at="2024-01-01T00:00:00Z",
        export_dir=str(stale_dir),
        image_base=0,
        ghidra_manifest=str(stale_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=[record],
    )
    _write_manifest(export_dir, manifest)

    loaded_manifest, nodes = load_function_nodes(export_dir)

    assert loaded_manifest.export_dir == str(export_dir.resolve())
    assert nodes[0].path == source_path
    assert nodes[0].text == source_content


def test_missing_source_file_raises(tmp_path: Path) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()

    record = FunctionRecord(
        address="0x1000",
        relative_address=0x1000,
        name="missing",
        relative_path="missing.c",
        source_exists=False,
        ordinal=0,
        size_addresses=4,
        body_size_bytes=4,
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=0,
        line_count=0,
        return_type="void",
        prototype="void missing(void)",
        parameters=[],
        emit_c=True,
        stack_regions=[],
        string_refs=[],
        pcode_calls=[{"callee": "recv", "arg_count": 3, "pcode": "CALL ..."}],
        ambiguous_callsites=[{"call_address": "0x1008", "ambiguity_reasons": ["indirect_call"], "disasm_window": []}],
    )
    manifest = Manifest(
        binary="demo.bin",
        generated_at="2024-01-01T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=[record],
    )
    _write_manifest(export_dir, manifest)

    loaded_manifest, nodes = load_function_nodes(export_dir)
    assert loaded_manifest.binary == "demo.bin"
    assert len(nodes) == 1
    node = nodes[0]
    assert node.path is None
    assert node.text == ""
    assert node.record.source_exists is False
    assert node.metadata["pcode_calls"][0]["callee"] == "recv"
    assert node.metadata["ambiguous_callsites"][0]["call_address"] == "0x1008"


def test_load_function_nodes_uses_internal_pcode_edges(tmp_path: Path) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()

    caller = FunctionRecord(
        address="0x1000",
        relative_address=0x1000,
        name="caller_fn",
        relative_path="",
        source_exists=False,
        ordinal=0,
        size_addresses=4,
        body_size_bytes=4,
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=0,
        line_count=0,
        return_type="void",
        prototype="void caller_fn(void)",
        parameters=[],
        emit_c=False,
        stack_regions=[],
        string_refs=[],
        pcode_calls=[{"callee": "callee_fn", "arg_count": 1, "args": ["(const,0x1,4)"]}],
    )
    callee = FunctionRecord(
        address="0x1010",
        relative_address=0x1010,
        name="callee_fn",
        relative_path="",
        source_exists=False,
        ordinal=1,
        size_addresses=4,
        body_size_bytes=4,
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=0,
        line_count=0,
        return_type="void",
        prototype="void callee_fn(void)",
        parameters=[],
        emit_c=False,
        stack_regions=[],
        string_refs=[],
        pcode_calls=[],
    )
    manifest = Manifest(
        binary="demo.bin",
        generated_at="2024-01-01T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=[caller, callee],
    )
    _write_manifest(export_dir, manifest)

    _, nodes = load_function_nodes(export_dir)
    by_name = {node.record.name: node for node in nodes}
    assert by_name["caller_fn"].metadata["callees"] == []
    assert by_name["callee_fn"].metadata["callers"] == []
    assert by_name["caller_fn"].metadata["callees_pcode"] == ["callee_fn"]
    assert by_name["callee_fn"].metadata["callers_pcode"] == ["caller_fn"]
