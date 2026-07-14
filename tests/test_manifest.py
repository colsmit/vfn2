import json
from pathlib import Path

import pytest

from binary_agent.data.manifest import ManifestError, normalize_manifest, write_normalized_manifest


def _write_manifest_entry(target: Path, entry: dict) -> None:
    with target.open("a") as fout:
        fout.write(json.dumps(entry))
        fout.write("\n")


def test_write_normalized_manifest(tmp_path: Path) -> None:
    export_dir = tmp_path / "sample.bin" / "20240101-000000" / "decompiled"
    export_dir.mkdir(parents=True)

    func_source = export_dir / "00001000_test.c"
    func_source.write_text("// Function: test\n// Address: 0x1000\n\nint test() { return 42; }\n")

    raw_manifest = export_dir / "manifest.jsonl"
    _write_manifest_entry(
        raw_manifest,
        {
            "address": "0x1000",
            "name": "test",
            "filename": func_source.name,
            "is_thunk": False,
            "stack_purge": 0,
            "call_fixup": None,
            "decompile_completed": True,
            "size": 4,
            "ordinal": 1,
        },
    )

    manifest_path = write_normalized_manifest(export_dir)
    data = json.loads(manifest_path.read_text())

    assert data["binary"] == "sample.bin"
    assert data["ghidra_manifest"].endswith("manifest.jsonl")
    assert len(data["functions"]) == 1

    record = data["functions"][0]
    assert record["name"] == "test"
    assert record["relative_path"] == func_source.name
    assert record["byte_length"] > 0
    assert record["line_count"] == 4
    assert record["stack_regions"] == []
    assert record["pcode_calls"] == []
    assert record["pcode_stores"] == []
    assert record["ambiguous_callsites"] == []


def test_missing_manifest_file_raises(tmp_path: Path) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()

    with pytest.raises(ManifestError):
        normalize_manifest(export_dir)


def test_stack_regions_preserved(tmp_path: Path) -> None:
    export_dir = tmp_path / "sample.bin" / "20240101-000000" / "decompiled"
    export_dir.mkdir(parents=True)

    func_source = export_dir / "00001000_test.c"
    func_source.write_text("// Function: test\n// Address: 0x1000\n\nint test() { return 42; }\n")

    raw_manifest = export_dir / "manifest.jsonl"
    _write_manifest_entry(
        raw_manifest,
        {
            "address": "0x1000",
            "name": "test",
            "filename": func_source.name,
            "is_thunk": False,
            "stack_purge": 0,
            "call_fixup": None,
            "decompile_completed": True,
            "size": 4,
            "ordinal": 1,
            "stack_regions": [
                {
                    "start_offset": -32,
                    "end_offset": -8,
                    "size_bytes": 24,
                    "var_names": ["local_20", "local_18", "local_10"],
                    "data_types": ["undefined8"],
                }
            ],
        },
    )

    manifest = normalize_manifest(export_dir)
    record = manifest.functions[0]
    assert record.stack_regions
    region = record.stack_regions[0]
    assert region["size_bytes"] == 24
    assert "local_20" in region["var_names"]
    assert record.wrapper_type is None


def test_stack_regions_expand_single_undefined_array_from_source(tmp_path: Path) -> None:
    export_dir = tmp_path / "sample.bin" / "20240101-000000" / "decompiled"
    export_dir.mkdir(parents=True)

    func_source = export_dir / "00001000_test.c"
    func_source.write_text(
        "// Function: test\n// Address: 0x1000\n\nvoid test(void)\n{\n  char local_36 [14];\n}\n"
    )

    raw_manifest = export_dir / "manifest.jsonl"
    _write_manifest_entry(
        raw_manifest,
        {
            "address": "0x1000",
            "name": "test",
            "filename": func_source.name,
            "is_thunk": False,
            "stack_purge": 0,
            "call_fixup": None,
            "decompile_completed": True,
            "size": 4,
            "ordinal": 1,
            "stack_regions": [
                {
                    "start_offset": -54,
                    "end_offset": -53,
                    "size_bytes": 1,
                    "var_names": ["local_36"],
                    "data_types": ["undefined"],
                }
            ],
        },
    )

    manifest = normalize_manifest(export_dir)
    region = manifest.functions[0].stack_regions[0]
    assert region["size_bytes"] == 14
    assert region["end_offset"] == -40


def test_stack_regions_expand_abi_scoped_stat64_array_from_source(tmp_path: Path) -> None:
    export_dir = tmp_path / "sample.bin" / "20240101-000000" / "decompiled"
    export_dir.mkdir(parents=True)

    func_source = export_dir / "00001000_test.c"
    func_source.write_text(
        "// Function: test\n// Address: 0x1000\n\nvoid test(void)\n{\n  stat64 local_848 [14];\n}\n"
    )
    (export_dir / "callgraph.json").write_text(
        json.dumps(
            {
                "image_base": 0,
                "language_id": "x86:LE:64:default",
                "processor": "x86",
                "pointer_size_bytes": 8,
                "endianness": "little",
                "executable_format": "Executable and Linking Format (ELF)",
                "compiler": "gcc",
                "edges": {},
            }
        )
    )

    raw_manifest = export_dir / "manifest.jsonl"
    _write_manifest_entry(
        raw_manifest,
        {
            "address": "0x1000",
            "name": "test",
            "filename": func_source.name,
            "is_thunk": False,
            "stack_purge": 0,
            "call_fixup": None,
            "decompile_completed": True,
            "size": 4,
            "ordinal": 1,
            "stack_regions": [
                {
                    "start_offset": -0x848,
                    "end_offset": -0x847,
                    "size_bytes": 1,
                    "var_names": ["local_848"],
                    "data_types": ["undefined"],
                }
            ],
        },
    )

    manifest = normalize_manifest(export_dir)
    region = manifest.functions[0].stack_regions[0]
    assert region["size_bytes"] == 2016
    assert region["end_offset"] == -0x68
    assert region["data_types"] == ["stat64[14]"]
    assert region["capacity_source"] == "declared_local_array"
    assert region["declared_element_size_bytes"] == 144
    assert region["declared_array_size_source"] == "x86_64_elf_stat64"


def test_stack_regions_do_not_expand_stat64_array_without_abi(tmp_path: Path) -> None:
    export_dir = tmp_path / "sample.bin" / "20240101-000000" / "decompiled"
    export_dir.mkdir(parents=True)

    func_source = export_dir / "00001000_test.c"
    func_source.write_text(
        "// Function: test\n// Address: 0x1000\n\nvoid test(void)\n{\n  stat64 local_848 [14];\n}\n"
    )

    raw_manifest = export_dir / "manifest.jsonl"
    _write_manifest_entry(
        raw_manifest,
        {
            "address": "0x1000",
            "name": "test",
            "filename": func_source.name,
            "is_thunk": False,
            "stack_purge": 0,
            "call_fixup": None,
            "decompile_completed": True,
            "size": 4,
            "ordinal": 1,
            "stack_regions": [
                {
                    "start_offset": -0x848,
                    "end_offset": -0x847,
                    "size_bytes": 1,
                    "var_names": ["local_848"],
                    "data_types": ["undefined"],
                }
            ],
        },
    )

    manifest = normalize_manifest(export_dir)
    region = manifest.functions[0].stack_regions[0]
    assert region["size_bytes"] == 1
    assert region["end_offset"] == -0x847
    assert "capacity_source" not in region


def test_wrapper_type_preserved(tmp_path: Path) -> None:
    export_dir = tmp_path / "sample.bin" / "20240101-000000" / "decompiled"
    export_dir.mkdir(parents=True)

    func_source = export_dir / "00001020_stub.c"
    func_source.write_text(
        "// Function: _sprintf\n// Address: 0x1020\n\nint _sprintf(char *p){return (*(code *)PTR__sprintf(p));}\n"
    )

    raw_manifest = export_dir / "manifest.jsonl"
    _write_manifest_entry(
        raw_manifest,
        {
            "address": "0x1020",
            "name": "_sprintf",
            "filename": func_source.name,
            "is_thunk": True,
            "stack_purge": 0,
            "call_fixup": None,
            "decompile_completed": True,
            "size": 4,
            "ordinal": 1,
            "wrapper_type": "plt_thunk",
        },
    )

    manifest = normalize_manifest(export_dir)
    record = manifest.functions[0]
    assert record.wrapper_type == "plt_thunk"


def test_pcode_calls_preserved(tmp_path: Path) -> None:
    export_dir = tmp_path / "sample.bin" / "20240101-000000" / "decompiled"
    export_dir.mkdir(parents=True)

    func_source = export_dir / "00001000_test.c"
    func_source.write_text("// Function: test\n// Address: 0x1000\n\nvoid test(){ helper(x); }\n")

    raw_manifest = export_dir / "manifest.jsonl"
    _write_manifest_entry(
        raw_manifest,
        {
            "address": "0x1000",
            "name": "test",
            "filename": func_source.name,
            "is_thunk": False,
            "stack_purge": 0,
            "call_fixup": None,
            "decompile_completed": True,
            "size": 4,
            "ordinal": 1,
            "pcode_calls": [
                {
                    "function": "test",
                    "callee": "helper",
                    "callee_address": "0x2000",
                    "arg_count": 1,
                    "args": ["unique, 0x10000000, 4"],
                    "pcode": "CALL ram[0x2000], unique, 0x10000000, 4",
                }
            ],
        },
    )

    manifest = normalize_manifest(export_dir)
    record = manifest.functions[0]
    assert len(record.pcode_calls) == 1
    assert record.pcode_calls[0]["callee"] == "helper"


def test_pcode_stores_preserved(tmp_path: Path) -> None:
    export_dir = tmp_path / "sample.bin" / "20240101-000000" / "decompiled"
    export_dir.mkdir(parents=True)

    func_source = export_dir / "00001000_test.c"
    func_source.write_text("// Function: test\n// Address: 0x1000\n\nvoid test(){ }\n")

    raw_manifest = export_dir / "manifest.jsonl"
    _write_manifest_entry(
        raw_manifest,
        {
            "address": "0x1000",
            "name": "test",
            "filename": func_source.name,
            "is_thunk": False,
            "stack_purge": 0,
            "call_fixup": None,
            "decompile_completed": True,
            "size": 4,
            "ordinal": 1,
            "pcode_stores": [
                {
                    "operation_address": "0x1010",
                    "base_var": "local_20",
                    "constant_index": -1,
                    "write_width": 1,
                }
            ],
        },
    )

    manifest = normalize_manifest(export_dir)
    record = manifest.functions[0]
    assert len(record.pcode_stores) == 1
    assert record.pcode_stores[0]["operation_address"] == "0x1010"


def test_symbol_sidecar_preserved_by_relative_address(tmp_path: Path) -> None:
    export_dir = tmp_path / "sample.bin" / "20240101-000000" / "decompiled"
    export_dir.mkdir(parents=True)

    func_source = export_dir / "00001000_fun.c"
    func_source.write_text("// Function: FUN_00001000\n// Address: 0x401000\n\nvoid FUN_00001000(void) {}\n")

    raw_manifest = export_dir / "manifest.jsonl"
    _write_manifest_entry(
        raw_manifest,
        {
            "address": "0x401000",
            "relative_address": 0x1000,
            "name": "FUN_00001000",
            "filename": func_source.name,
            "is_thunk": False,
            "stack_purge": 0,
            "call_fixup": None,
            "decompile_completed": True,
            "size": 4,
            "ordinal": 1,
        },
    )
    (export_dir / "callgraph.json").write_text(json.dumps({"image_base": 0x400000, "edges": {}}))
    (export_dir / "source_symbols.json").write_text(
        json.dumps(
            {
                "symbols": [
                    {
                        "address": "0x401000",
                        "symbol_name": "_ZN3Foo6actionEv",
                        "demangled_name": "Foo::action()",
                        "source_symbol": "action",
                        "source_object": "case.cpp.o",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    manifest = normalize_manifest(export_dir)
    record = manifest.functions[0]
    assert record.source_symbol == "action"
    assert record.demangled_name == "Foo::action()"
    assert record.source_object == "case.cpp.o"


def test_ambiguous_callsites_preserved(tmp_path: Path) -> None:
    export_dir = tmp_path / "sample.bin" / "20240101-000000" / "decompiled"
    export_dir.mkdir(parents=True)

    func_source = export_dir / "00001000_test.c"
    func_source.write_text("// Function: test\n// Address: 0x1000\n\nvoid test(){ helper(x); }\n")

    raw_manifest = export_dir / "manifest.jsonl"
    _write_manifest_entry(
        raw_manifest,
        {
            "address": "0x1000",
            "name": "test",
            "filename": func_source.name,
            "is_thunk": False,
            "stack_purge": 0,
            "call_fixup": None,
            "decompile_completed": True,
            "size": 4,
            "ordinal": 1,
            "ambiguous_callsites": [
                {
                    "call_address": "0x1010",
                    "callee": "helper",
                    "ambiguity_reasons": ["mostly_unresolved_args"],
                    "disasm_window": [{"address": "0x100C", "instruction": "MOV EAX,EBX", "is_call": False}],
                }
            ],
        },
    )

    manifest = normalize_manifest(export_dir)
    record = manifest.functions[0]
    assert len(record.ambiguous_callsites) == 1
    assert record.ambiguous_callsites[0]["call_address"] == "0x1010"
