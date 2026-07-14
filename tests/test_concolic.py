import gzip
import io
import json
import os
import shutil
import tarfile
import zipfile
import zlib
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

import pytest

import binary_agent.analysis.concolic as concolic_module
from binary_agent.analysis.concolic import (
    CONCOLIC_TOOL_NAME,
    CONCOLIC_ANGR_TRACE_FILENAME,
    CONCOLIC_DYNAMIC_PROOF_FILENAME,
    CONCOLIC_DYNAMIC_PROOF_UNSUPPORTED_FILENAME,
    CONCOLIC_LLM_ACTIONS_FILENAME,
    CONCOLIC_PCODE_UNSUPPORTED_FILENAME,
    CONCOLIC_REPLAY_FILENAME,
    CONCOLIC_REQUEST_FILENAME,
    CONCOLIC_VERDICT_FILENAME,
    CrashWitness,
    ConcolicRequest,
    ConcolicToolConfig,
    ConcolicVerdict,
    build_dynamic_overflow_proof_request,
    build_pcode_trace_request,
    build_concolic_request,
    concolic_confirmation_dict,
    concolic_request_from_tool_request,
    load_concolic_dynamic_proofs,
    run_concolic_evidence_dir,
    translate_ghidra_to_loader_address,
    unsupported_pcode_trace,
)
from binary_agent.analysis.confirmation import build_evidence_pack_v3, load_candidate_confirmations
from binary_agent.data.manifest import FunctionRecord, Manifest
from binary_agent.pipeline import CandidateState, CandidateStatus, candidate_state_from_static_candidate


def _pack(candidate_id: str = "demo:0x1010:main:4:memcpy:local_20") -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "deterministic_candidate": {
            "candidate_id": candidate_id,
            "binary": "demo.bin",
            "function_name": "main",
            "address": "0x1000",
            "operation_address": "0x1010",
            "kind": "call",
            "sink": "memcpy",
            "target_buffer": "local_20",
            "destination_kind": "stack",
            "capacity_bytes": 16,
            "write_relation": "proven_overflow",
            "verdict": "overflow",
        },
        "facts_available_to_llm": {
            "write_table": [{"operation_address": "0x1010"}],
            "reproducer_hypothesis": {"input_surface": "cli_argument", "allowed_stubs": ["memcpy"]},
            "pcode_slice": {"operation_address": "0x1010"},
            "allowed_stubs": ["memcpy"],
        },
        "proof_obligation": {
            "relation": "proven_overflow",
            "evidence_refs": ["object:0", "write:0", "reachability:0"],
        },
    }


def _write_pack_dir(tmp_path: Path, pack: Mapping[str, Any]) -> Path:
    evidence_dir = tmp_path / "packs"
    evidence_dir.mkdir()
    (evidence_dir / "pack.json").write_text(json.dumps(pack))
    (evidence_dir / "index.json").write_text(
        json.dumps({"evidence_packs": [{"candidate_id": pack["candidate_id"], "path": "pack.json"}]})
    )
    return evidence_dir


def _write_pack_dir_many(tmp_path: Path, packs: list[Mapping[str, Any]]) -> Path:
    evidence_dir = tmp_path / "packs"
    evidence_dir.mkdir()
    index = []
    for idx, pack in enumerate(packs, start=1):
        path = f"pack_{idx}.json"
        (evidence_dir / path).write_text(json.dumps(pack))
        index.append({"candidate_id": pack["candidate_id"], "path": path})
    (evidence_dir / "index.json").write_text(json.dumps({"evidence_packs": index}))
    return evidence_dir


def _binary(tmp_path: Path) -> Path:
    binary = tmp_path / "demo.bin"
    binary.write_bytes(b"\x7fELF")
    return binary


def _fake_overflow_proof(proof_request) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "proof_kind": "ghidra_dynamic_overflow",
        "candidate_id": proof_request.candidate_id,
        "status": "overflow_proven",
        "proof_scope": proof_request.proof_scope,
        "input_model": proof_request.input_model,
        "sink_reached": True,
        "exact_sink_reached": True,
        "sink_address": proof_request.sink_address,
        "write_size_bytes": proof_request.write_size_bytes,
        "capacity_bytes": proof_request.capacity_bytes,
        "overflow_bytes": max(0, proof_request.write_size_bytes - proof_request.capacity_bytes),
        "write_range": {
            "base": proof_request.target_buffer,
            "start_offset": 0,
            "end_offset_exclusive": proof_request.write_size_bytes,
            "size_bytes": proof_request.write_size_bytes,
        },
        "object_range": {
            "base": proof_request.target_buffer,
            "start_offset": 0,
            "end_offset_exclusive": proof_request.capacity_bytes,
            "size_bytes": proof_request.capacity_bytes,
        },
        "harness_model": {
            "input_model": proof_request.input_model,
            "concrete_input_hex": proof_request.concrete_input_hex,
        },
        "process_input_setup": {
            "status": "configured",
            "input_model": proof_request.input_model,
            "argv_values": list(proof_request.argv_values),
            "file_name": proof_request.file_name,
            "stdin_size_bytes": len(proof_request.stdin_input_hex) // 2,
            "file_size_bytes": len(proof_request.file_input_hex) // 2,
            "process_input_source": proof_request.process_input_source,
            "process_input_evidence": dict(proof_request.process_input_evidence),
        },
        "process_replay": {"status": "reached"},
        "native_replay": {"status": "not_run"},
        "request": proof_request.to_dict(),
    }


def test_concrete_angr_replay_accepts_target_inside_current_basic_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class History:
        bbl_addrs = [0x1000]

    class State:
        addr = 0x1000
        history = History()

    class Simgr:
        active = [State()]
        errored: list[Any] = []
        unconstrained: list[Any] = []

        def step(self) -> None:
            self.active = []

    class Block:
        instruction_addrs = [0x1000, 0x1004]

    class Factory:
        def simulation_manager(self, _state: Any, *, save_unconstrained: bool) -> Simgr:
            assert save_unconstrained is True
            return Simgr()

        def block(self, _address: int) -> Block:
            return Block()

    class Project:
        factory = Factory()

    request = ConcolicRequest(
        candidate_id="demo",
        binary_path=_binary(tmp_path),
        target_address="0x1004",
        sink_address="0x1004",
        input_model="argv",
        timeout_seconds=0.1,
    )
    monkeypatch.setattr(
        concolic_module,
        "_make_angr_concrete_state",
        lambda *_args, **_kwargs: {"state": State()},
    )

    replay = concolic_module._replay_angr_witness(
        Project(),
        object(),
        request,
        {},
        concrete=b"AAAA",
        target_loader_address=0x1004,
        expect_crash=False,
    )

    assert replay["concrete_angr_replay"]["status"] == "replayed"


def test_ghidra_project_location_avoids_hidden_artifact_paths(tmp_path: Path) -> None:
    hidden_output = tmp_path / ".ai" / "runs" / "candidate"
    hidden_output.mkdir(parents=True)
    project_dir, cleanup_root = concolic_module._ghidra_project_location(hidden_output, "proof")

    assert cleanup_root is not None
    assert cleanup_root in project_dir.parents
    assert all(not part.startswith(".") for part in project_dir.resolve().parts if part not in {".", ".."})

    shutil.rmtree(cleanup_root)


def _function_record(
    name: str,
    address: str,
    *,
    size: int = 0x40,
    pcode_calls: list[dict[str, Any]] | None = None,
    pcode_stores: list[dict[str, Any]] | None = None,
    ambiguous_callsites: list[dict[str, Any]] | None = None,
    wrapper_type: str | None = None,
    stub_kind: str | None = None,
    source_symbol: str = "",
    demangled_name: str = "",
) -> FunctionRecord:
    return FunctionRecord(
        address=address,
        relative_address=int(address, 0) - 0x100000,
        name=name,
        relative_path="",
        source_exists=False,
        ordinal=0,
        size_addresses=size,
        body_size_bytes=size,
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=0,
        line_count=0,
        return_type="void",
        prototype="",
        parameters=[],
        emit_c=False,
        source_symbol=source_symbol,
        demangled_name=demangled_name,
        pcode_calls=pcode_calls or [],
        pcode_stores=pcode_stores or [],
        ambiguous_callsites=ambiguous_callsites or [],
        wrapper_type=wrapper_type,
        stub_kind=stub_kind,
    )


def _write_minimal_export(tmp_path: Path, records: list[FunctionRecord], *, image_base: int = 0x100000) -> Path:
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    manifest = Manifest(
        binary="demo",
        generated_at="2026-06-16T00:00:00Z",
        export_dir=str(export_dir),
        image_base=image_base,
        ghidra_manifest="manifest.jsonl",
        callgraph_path=None,
        functions=records,
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))
    return export_dir


def _pack_with_entrypoint(input_model: str = "stdin") -> dict[str, Any]:
    pack = _pack()
    entrypoint = {
        "schema_version": 2,
        "status": "derived",
        "entry_function": "main",
        "entry_address": "0x800",
        "target_function": "main",
        "target_address": "0x1000",
        "input_model": input_model,
        "process_input_supported": True,
        "call_path": ["main"],
        "entry_surface": {"function": "main", "address": "0x800", "kind": "program_entry"},
        "source_to_sink_trace": {"schema_version": 1, "status": "blocked"},
        "no_text_matching": True,
    }
    pack["entrypoint_derivation"] = entrypoint
    pack.setdefault("facts_available_to_llm", {})["entrypoint_derivation"] = entrypoint
    return pack


def test_concolic_request_validation_uses_pack_addresses(tmp_path: Path) -> None:
    pack = _pack()

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), symbolic_bytes=32)

    assert request.candidate_id == pack["candidate_id"]
    assert request.backend == "angr"
    assert request.input_model == "argv"
    assert request.target_address == "0x1010"


def test_reached_unbounded_sink_requires_payload_beyond_capacity(tmp_path: Path) -> None:
    pack = _pack("demo:0x1010:main:4:strcpy:local_20:0:unbounded")
    pack["deterministic_candidate"].update(
        {
            "sink": "strcpy",
            "capacity_bytes": 16,
            "write_relation": "unbounded",
            "verdict": "unbounded",
            "write_size_bytes": 0,
        }
    )
    pack["proof_obligation"]["relation"] = "unbounded"
    assert concolic_module._reached_sink_proves_memory_overflow(pack, b"A" * 16) is False
    assert concolic_module._reached_sink_proves_memory_overflow(pack, b"A" * 17) is True


def test_stripped_argv_export_resolves_exact_sink_callsite_from_disassembly(tmp_path: Path) -> None:
    pytest.importorskip("capstone")
    pytest.importorskip("elftools")
    binary = Path("samples/vuln_demo/build/vuln_demo_fortified_stripped")
    if not binary.exists():
        pytest.skip("vuln_demo_stripped sample is not built")
    pack = _pack("vuln_demo:0x1011E0:FUN_001011e0:11:strcpy_chk:auStack_18:0:unbounded")
    pack["deterministic_candidate"].update(
        {
            "function_name": "FUN_001011e0",
            "address": "0x1011e0",
            "operation_address": "",
            "sink": "strcpy_chk",
        }
    )
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": ""}]
    pack["facts_available_to_llm"]["pcode_slice"] = {}
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record("FUN_001011e0", "0x1011e0", size=0x40),
            _function_record("__strcpy_chk", "0x101080", size=0x10),
        ],
    )

    request = build_concolic_request(pack, binary_path=binary, export_dir=export_dir, symbolic_bytes=32)

    assert int(request.target_address, 16) > 0
    assert request.sink_address == request.target_address
    assert request.target_resolution["target_kind"] == "disassembly_callsite"
    assert request.target_resolution["callee_name"] == "__strcpy_chk"
    assert request.target_resolution["sink_site"]["key"] == f"addr:{request.target_address}"
    assert request.target_resolution["sink_site"]["address"] == request.target_address


def test_source_read_request_resolves_unique_exact_sink_callsite_from_disassembly(tmp_path: Path) -> None:
    if shutil.which("objdump") is None:
        pytest.skip("objdump is required for disassembly fallback validation")
    binary = Path("samples/vuln_demo/build/vuln_demo_fortified_stripped")
    if not binary.exists():
        pytest.skip("vuln_demo_stripped sample is not built")
    line_text = "uVar1 = __strcpy_chk(auStack_18,param_1,0x10);"
    source = "\n".join(
        [
            "void FUN_001011e0(void) {",
            "  int local_1;",
            "  int local_2;",
            "  int local_3;",
            "  int local_4;",
            "  int local_5;",
            "  int local_6;",
            "  int local_7;",
            "  int local_8;",
            "  int local_9;",
            f"  {line_text}",
            "}",
        ]
    )
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    relative_path = "001011e0_FUN_001011e0.c"
    (export_dir / relative_path).write_text(source)
    manifest = Manifest(
        binary="vuln_demo",
        generated_at="2026-06-18T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0x100000,
        ghidra_manifest="manifest.jsonl",
        callgraph_path=None,
        functions=[
            FunctionRecord(
                address="0x1011e0",
                relative_address=0x11E0,
                name="FUN_001011e0",
                relative_path=relative_path,
                source_exists=True,
                ordinal=0,
                size_addresses=0x40,
                body_size_bytes=0x40,
                is_thunk=False,
                stack_purge=None,
                call_fixup=None,
                decompile_completed=True,
                byte_length=len(source.encode("utf-8")),
                line_count=len(source.splitlines()),
                return_type="void",
                prototype="void FUN_001011e0(void)",
                parameters=[],
                emit_c=True,
                source_symbol="",
            ),
            _function_record("__strcpy_chk", "0x101080", size=0x10, source_symbol="__strcpy_chk"),
        ],
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))
    pack = _pack("vuln_demo:0x1011E0:FUN_001011e0:11:strcpy_chk_source_read:auStack_18:0:unbounded")
    pack["deterministic_candidate"].update(
        {
            "candidate_id": pack["candidate_id"],
            "function_name": "FUN_001011e0",
            "address": "0x1011e0",
            "operation_address": "",
            "kind": "source_read",
            "sink": "strcpy_chk_source_read",
            "vulnerability_type": "out_of_bounds_read",
            "line_text": line_text,
        }
    )
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": ""}]
    pack["facts_available_to_llm"].pop("pcode_slice", None)
    pack["facts_available_to_llm"].pop("exact_sink_address", None)

    request = build_concolic_request(pack, binary_path=binary, export_dir=export_dir, symbolic_bytes=32)

    assert int(request.target_address, 16) > 0
    assert request.sink_address == request.target_address
    assert request.target_resolution["target_kind"] == "disassembly_unique_source_read_callsite"
    assert request.target_resolution["decompiled_line_number"] == 11
    assert request.target_resolution["callee_name"] == "__strcpy_chk"


def test_decompiled_sink_occurrence_uses_candidate_line_and_offset(tmp_path: Path) -> None:
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (export_dir / "001000_FUN_1000.c").write_text(
        "\n".join(
            [
                "// Function: FUN_1000",
                "void FUN_1000(void) {",
                "  strcpy(&DAT_1000 + DAT_2000,a);",
                "  strcpy(&DAT_1000,b);",
                "  strcpy(&DAT_1000 + DAT_2000,c);",
                "}",
            ]
        )
    )
    pack = _pack("demo:0x1000:FUN_1000:5:strcpy:DAT_1000:DAT_2000:unbounded")
    pack["deterministic_candidate"].update(
        {
            "function_name": "FUN_1000",
            "address": "0x1000",
            "operation_address": "",
            "sink": "strcpy",
            "target_buffer": "DAT_1000",
        }
    )

    occurrence = concolic_module._decompiled_sink_occurrence(pack, export_dir=export_dir, sink_names={"strcpy"})

    assert occurrence["line_number"] == 5
    assert occurrence["occurrence_index"] == 1
    assert occurrence["line_text"] == "strcpy(&DAT_1000 + DAT_2000,c);"


def test_local_line_aware_disassembly_uses_source_order_without_data_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = "\n".join(
        [
            "void FUN_1000(void) {",
            "  if (buf) {",
            "    strcpy(buf,a);",
            "  }",
            "  strcpy(buf + n,b);",
            "}",
        ]
    )
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record("FUN_1000", "0x1000", size=0x80),
            _function_record("strcpy", "0x3000", size=0x10),
        ],
    )
    (export_dir / "001000_FUN_1000.c").write_text(source)
    pack = _pack("demo:0x1000:FUN_1000:5:strcpy:buf:n:unbounded")
    pack["deterministic_candidate"].update(
        {
            "function_name": "FUN_1000",
            "address": "0x1000",
            "operation_address": "",
            "sink": "strcpy",
            "target_buffer": "buf",
        }
    )
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": "0x1000"}]
    pack["facts_available_to_llm"]["pcode_slice"] = {"operation_address": "0x1000"}

    def fake_callsites(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        return [
            {"call_address": "0x1010", "data_references": []},
            {"call_address": "0x1020", "data_references": []},
        ]

    monkeypatch.setattr(concolic_module, "_direct_callsites_to_address", fake_callsites)

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), export_dir=export_dir, symbolic_bytes=32)

    assert request.target_address == "0x1020"
    assert request.sink_address == "0x1020"
    assert request.target_resolution["target_kind"] == "disassembly_line_callsite"
    assert request.target_resolution["decompiled_sink_source_order_index"] == 1
    assert request.target_resolution["no_decompiled_text_matching"] is False
    assert request.target_resolution["sink_site"]["key"] == "addr:0x1020"
    assert request.target_resolution["sink_site"]["source_order_index"] == "1"


def test_repeated_sink_refinement_supersedes_stale_evidence_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record("FUN_1000", "0x1000", size=0x80),
            _function_record("strcpy", "0x3000", size=0x10),
        ],
    )
    (export_dir / "001000_FUN_1000.c").write_text(
        "\n".join(
            [
                "void FUN_1000(void) {",
                "  strcpy(buf + first,a);",
                "  strcpy(buf + second,b);",
                "}",
            ]
        )
    )
    pack = _pack("demo:0x1000:FUN_1000:3:strcpy:buf:second:unbounded")
    pack["deterministic_candidate"].update(
        {
            "function_name": "FUN_1000",
            "address": "0x1000",
            "operation_address": "0x1010",
            "sink": "strcpy",
            "target_buffer": "buf",
        }
    )
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": "0x1010"}]
    pack["facts_available_to_llm"]["pcode_slice"] = {"operation_address": "0x1010"}

    monkeypatch.setattr(
        concolic_module,
        "_direct_callsites_to_address",
        lambda *_args, **_kwargs: [
            {"call_address": "0x1010", "data_references": []},
            {"call_address": "0x1020", "data_references": []},
        ],
    )

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), export_dir=export_dir)

    assert request.target_address == "0x1020"
    assert request.sink_address == "0x1020"
    assert request.target_resolution["superseded_evidence_address"] == "0x1010"
    assert request.target_resolution["derivation_method"] == "elf_disassembly_decompiled_line"


def test_export_resolves_indirect_sink_callsite_from_ambiguous_call_facts(tmp_path: Path) -> None:
    pack = _pack()
    pack["deterministic_candidate"].update({"operation_address": "", "sink": "memcpy"})
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": ""}]
    pack["facts_available_to_llm"]["pcode_slice"] = {}
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record(
                "main",
                "0x1000",
                ambiguous_callsites=[
                    {
                        "call_address": "0x1018",
                        "callee": "memcpy",
                        "ambiguity_reasons": ["indirect_call"],
                    }
                ],
            ),
        ],
    )

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), export_dir=export_dir, symbolic_bytes=32)

    assert request.target_address == "0x1018"
    assert request.sink_address == "0x1018"
    assert request.target_resolution["target_kind"] == "exact_indirect_callsite"
    assert request.target_resolution["target_source"] == "ambiguous_callsites"


def test_export_resolves_inlined_store_sink_from_pcode_store(tmp_path: Path) -> None:
    pack = _pack("demo:0x1000:main:4:array_store:local_20")
    pack["deterministic_candidate"].update(
        {
            "operation_address": "",
            "sink": "array_store",
            "kind": "store",
            "target_buffer": "local_20",
        }
    )
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": ""}]
    pack["facts_available_to_llm"]["pcode_slice"] = {}
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record(
                "main",
                "0x1000",
                pcode_stores=[
                    {
                        "operation_address": "0x1020",
                        "base_var": "local_20",
                        "stack_ref": {"var_name": "local_20"},
                    }
                ],
            ),
        ],
    )

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), export_dir=export_dir, symbolic_bytes=32)

    assert request.target_address == "0x1020"
    assert request.sink_address == "0x1020"
    assert request.target_resolution["target_kind"] == "exact_pcode_store"
    assert request.target_resolution["store"]["base_var"] == "local_20"


def test_export_resolves_exact_sink_through_transparent_wrapper_chain(tmp_path: Path) -> None:
    pack = _pack()
    pack["deterministic_candidate"].update({"operation_address": "", "sink": "memcpy"})
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": ""}]
    pack["facts_available_to_llm"]["pcode_slice"] = {}
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record("main", "0x1000", pcode_calls=[{"callee": "copy_wrapper", "call_address": "0x1008"}]),
            _function_record(
                "copy_wrapper",
                "0x2000",
                pcode_calls=[{"callee": "memcpy", "call_address": "0x2014"}],
                wrapper_type="single_call_wrapper",
            ),
        ],
    )

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), export_dir=export_dir, symbolic_bytes=32)

    assert request.target_address == "0x2014"
    assert request.sink_address == "0x2014"
    assert request.target_resolution["target_kind"] == "wrapper_chain_callsite"
    assert request.target_resolution["wrapper_chain"] == ["copy_wrapper"]


def test_export_resolves_cpp_sink_by_demangled_method_name(tmp_path: Path) -> None:
    pack = _pack("demo:0x1000:main:4:copy:local_20")
    pack["deterministic_candidate"].update(
        {
            "operation_address": "",
            "sink": "std::char_traits<char>::copy(char *, char const *, unsigned long)",
        }
    )
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": ""}]
    pack["facts_available_to_llm"]["pcode_slice"] = {}
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record("main", "0x1000", pcode_calls=[{"callee": "FUN_003000", "call_address": "0x101c"}]),
            _function_record(
                "FUN_003000",
                "0x3000",
                source_symbol="copy",
                demangled_name="std::char_traits<char>::copy(char *, char const *, unsigned long)",
            ),
        ],
    )

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), export_dir=export_dir, symbolic_bytes=32)

    assert request.target_address == "0x101c"
    assert request.sink_address == "0x101c"
    assert request.target_resolution["target_kind"] == "exact_pcode_callsite"
    assert request.target_resolution["callee_name"] == "FUN_003000"


def test_export_resolves_stripped_import_by_callee_address(tmp_path: Path) -> None:
    pack = _pack()
    pack["deterministic_candidate"].update(
        {
            "operation_address": "",
            "sink": "memcpy",
            "sink_callee_address": "0x3000",
        }
    )
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": ""}]
    pack["facts_available_to_llm"]["pcode_slice"] = {}
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record(
                "main",
                "0x1000",
                pcode_calls=[
                    {
                        "callee": "",
                        "callee_address": "0x3000",
                        "call_address": "0x1024",
                        "pcode": "CALL",
                    }
                ],
            ),
        ],
    )

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), export_dir=export_dir, symbolic_bytes=32)

    assert request.target_address == "0x1024"
    assert request.sink_address == "0x1024"
    assert request.target_resolution["target_kind"] == "exact_pcode_callsite"
    assert request.target_resolution["callee_address"] == "0x3000"


def test_schema_v3_semantic_pack_builds_concolic_request(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    state = CandidateState(
        candidate_id="semantic:cmd",
        vulnerability_type="command_injection",
        status=CandidateStatus.PROOF_READY.value,
        target={"binary": "demo.bin", "path": str(binary)},
        location={"function_name": "handle", "address": "0x4010"},
        source={"kind": "argv", "expression": "argv[1]"},
        sink={"name": "system", "operation_address": "0x4020"},
        type_facts={
            "semantic_seed": {"seed_id": "cmd", "vulnerability_type": "command_injection"},
            "replay_hints": {
                "input": {"argv": ["$(id)"]},
                "expected_result": {"proof_oracle": {"kind": "command_effect", "marker": "uid="}},
            },
        },
        proof_obligations=[],
        blockers=[],
        metadata={"provenance": "llm_semantic_seed"},
    )
    pack = build_evidence_pack_v3(
        state.to_dict(),
        entrypoint_derivation={
            "schema_version": 2,
            "status": "derived",
            "entry_function": "main",
            "entry_address": "0x4000",
            "target_function": "handle",
            "target_address": "0x4010",
            "input_model": "argv",
            "process_input_supported": True,
            "call_path": ["main", "handle"],
            "entry_surface": {"function": "main", "address": "0x4000", "kind": "program_entry"},
            "entry_reachability": {
                "schema_version": 1,
                "status": "complete",
                "entry_function": "main",
                "target_function": "handle",
                "call_path": ["main", "handle"],
            },
            "source_to_sink_trace": {"schema_version": 1, "status": "blocked"},
            "no_text_matching": True,
        },
    )

    request = build_concolic_request(pack, binary_path=binary, symbolic_bytes=32)

    assert pack["candidate_id"] == "semantic:cmd"
    assert pack["deterministic_candidate"]["vulnerability_type"] == "command_injection"
    assert pack["proof_oracle_facts"]["kind"] == "command_effect"
    assert pack["proof_oracle_facts"]["syscall_observation"] is True
    assert request.candidate_id == "semantic:cmd"
    assert request.target_address == "0x4020"
    assert request.sink_address == "0x4020"
    assert request.input_model == "argv"


def test_concolic_tool_request_rejects_unbounded_llm_address(tmp_path: Path) -> None:
    pack = _pack()
    config = ConcolicToolConfig(binary_path=_binary(tmp_path), output_dir=tmp_path / "concolic")

    with pytest.raises(ValueError, match="not present in the evidence pack"):
        concolic_request_from_tool_request(
            pack,
            {
                "tool": CONCOLIC_TOOL_NAME,
                "target_address": "0x41414141",
                "symbolic_byte_budget": 64,
            },
            config,
        )


def test_concolic_tool_request_rejects_oversized_symbolic_budget(tmp_path: Path) -> None:
    pack = _pack()
    config = ConcolicToolConfig(
        binary_path=_binary(tmp_path),
        output_dir=tmp_path / "concolic",
        max_symbolic_bytes=32,
    )

    with pytest.raises(ValueError, match="symbolic_bytes"):
        concolic_request_from_tool_request(
            pack,
            {"tool": CONCOLIC_TOOL_NAME, "target_address": "0x1010", "symbolic_byte_budget": 64},
            config,
        )


def test_concolic_tool_request_rejects_wrong_candidate_id(tmp_path: Path) -> None:
    pack = _pack()
    config = ConcolicToolConfig(binary_path=_binary(tmp_path), output_dir=tmp_path / "concolic")

    with pytest.raises(ValueError, match="does not match evidence pack"):
        concolic_request_from_tool_request(
            pack,
            {
                "tool": CONCOLIC_TOOL_NAME,
                "candidate_id": "other",
                "target_address": "0x1010",
                "symbolic_byte_budget": 16,
            },
            config,
        )


def test_concolic_tool_request_rejects_disallowed_stub(tmp_path: Path) -> None:
    pack = _pack()
    config = ConcolicToolConfig(binary_path=_binary(tmp_path), output_dir=tmp_path / "concolic")

    with pytest.raises(ValueError, match="allowed_stub"):
        concolic_request_from_tool_request(
            pack,
            {
                "tool": CONCOLIC_TOOL_NAME,
                "target_address": "0x1010",
                "symbolic_byte_budget": 16,
                "allowed_stubs": ["system"],
            },
            config,
        )


def test_concolic_tool_request_accepts_bounded_llm_controls(tmp_path: Path) -> None:
    pack = _pack()
    config = ConcolicToolConfig(binary_path=_binary(tmp_path), output_dir=tmp_path / "concolic")

    request = concolic_request_from_tool_request(
        pack,
        {
            "tool": CONCOLIC_TOOL_NAME,
            "target_address": "0x1010",
            "input_model": "stdin",
            "symbolic_byte_budget": 16,
            "allowed_stubs": ["memcpy"],
            "seed_mutations": ["AAAA"],
        },
        config,
    )

    assert request.input_model == "stdin"
    assert request.symbolic_bytes == 16
    assert request.allowed_stubs == ("memcpy",)
    assert request.seed_mutations == ("AAAA",)


@pytest.mark.parametrize(
    ("input_model", "process_input"),
    [
        ("stdin", {"input_model": "stdin"}),
        ("file", {"input_model": "file", "file_name": "input.txt"}),
        ("env", {"input_model": "env", "env_key": "HTTP_USER_AGENT"}),
        ("argv_file_stdin", {"input_model": "argv_file_stdin", "file_name": "input.txt"}),
        ("line_file", {"input_model": "line_file", "file_name": "records.txt"}),
        ("text_record", {"input_model": "text_record"}),
    ],
)
def test_concolic_request_uses_witness_plan_trial_input_as_seed(
    tmp_path: Path,
    input_model: str,
    process_input: Mapping[str, Any],
) -> None:
    pack = _pack()
    pack["type_facts"] = {
        "capacity_bytes": 8,
        "process_input": process_input,
        "source_to_sink_trace": {"input_model": input_model},
    }

    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        input_model=input_model,
        symbolic_bytes=16,
    )
    candidates = concolic_module._hybrid_witness_candidates(request, pack)

    assert request.seed_mutations
    assert request.seed_mutations[0].startswith("A")
    assert candidates[0]["source"] == "seed_mutation:0"
    assert candidates[0]["bytes"].startswith(b"A" * 8)


def test_explicit_reproducer_file_is_not_truncated_to_symbolic_budget(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("file")
    payload = b"record\n" * 1000
    pack["facts_available_to_llm"]["reproducer_hypothesis"] = {
        "input_surface": "file",
        "input_hex": payload.hex(),
    }
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="file", symbolic_bytes=32)

    candidates = concolic_module._hybrid_witness_candidates(request, pack)

    explicit = next(candidate for candidate in candidates if candidate["source"] == "reproducer:input_hex")
    assert explicit["bytes"] == payload


@pytest.mark.parametrize(
    ("declared_model", "expected_model", "source_evidence"),
    [
        ("line_file", "file", "line file record reaches parser"),
        ("text_record", "stdin", "text record parser reads one line"),
        ("archive_text_record", "file", "zip archive record reaches parser"),
    ],
)
def test_concolic_request_maps_witness_only_input_models_to_supported_process_models(
    tmp_path: Path,
    declared_model: str,
    expected_model: str,
    source_evidence: str,
) -> None:
    pack = _pack()
    pack["type_facts"] = {
        "capacity_bytes": 8,
        "process_input": {"input_model": declared_model, "file_name": "payload.dat"},
        "source_to_sink_trace": {"input_model": declared_model},
    }
    pack["source"] = {"evidence": [source_evidence]}

    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        symbolic_bytes=512 if declared_model == "archive_text_record" else 16,
    )
    candidates = concolic_module._hybrid_witness_candidates(request, pack)

    assert request.input_model == expected_model
    assert request.seed_mutations
    assert candidates[0]["source"] == "seed_mutation:0"
    if declared_model == "archive_text_record":
        assert request.seed_mutations[0].startswith("hex:504b")
        with zipfile.ZipFile(io.BytesIO(candidates[0]["bytes"])) as archive:
            assert archive.read("payload.txt").startswith(b"A")
    else:
        assert request.seed_mutations[0].startswith("A")
        assert candidates[0]["bytes"].startswith(b"A" * 8)


def test_concolic_request_normalizes_entrypoint_witness_only_input_model(tmp_path: Path) -> None:
    pack = _pack()
    pack["type_facts"] = {
        "capacity_bytes": 8,
        "entrypoint_derivation": {
            "status": "derived",
            "process_input_supported": True,
            "input_model": "line_file",
            "entry_address": "0x1000",
            "target_address": "0x1010",
        },
    }
    pack["source"] = {"evidence": ["line file record reaches parser"]}

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), symbolic_bytes=16)
    candidates = concolic_module._hybrid_witness_candidates(request, pack)

    assert request.input_model == "file"
    assert request.seed_mutations[0].startswith("A")
    assert candidates[0]["source"] == "seed_mutation:0"


def test_candidate_linked_file_reader_overrides_incidental_argv_model(tmp_path: Path) -> None:
    pack = _pack("demo:0x1010:parse:8:pointer_read:table:index*4")
    pack["deterministic_candidate"].update(
        {
            "function_name": "parse",
            "kind": "pointer_read",
            "sink": "pointer_load",
            "destination_kind": "heap",
            "write_relation": "symbolic_read_offset",
        }
    )
    pack["type_facts"] = {
        "classification_trace": {
            "source_to_write": {
                "roles": {
                    "write_offset": {
                        "classification": "source_controlled",
                        "evidence": ["source_call:fgetc:line 7"],
                    }
                }
            }
        }
    }
    pack["entrypoint_derivation"] = {
        "status": "derived",
        "process_input_supported": True,
        "input_model": "argv",
        "entry_address": "0x1000",
        "target_address": "0x1010",
    }

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), symbolic_bytes=64)

    assert request.input_model == "file"


def test_binary_file_input_is_not_constrained_to_printable_bytes() -> None:
    assert concolic_module._input_model_requires_printable_bytes("argv") is True
    assert concolic_module._input_model_requires_printable_bytes("file") is False
    assert concolic_module._input_model_requires_printable_bytes("stdin") is False


def test_concolic_request_uses_config_witness_plan_as_file_seed(tmp_path: Path) -> None:
    pack = _pack()
    pack["type_facts"] = {
        "capacity_bytes": 8,
        "process_input": {"input_model": "config", "config_key": "diagnostic_cmd"},
        "source_to_sink_trace": {"input_model": "config"},
    }
    pack["source"] = {"evidence": ["configuration key diagnostic_cmd reaches the sink"]}

    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        input_model="config",
        symbolic_bytes=16,
    )
    candidates = concolic_module._hybrid_witness_candidates(request, pack)

    assert request.seed_mutations
    assert request.seed_mutations[0].startswith("diagnostic_cmd=")
    assert candidates == []


def test_concolic_request_uses_archive_witness_plan_as_file_seed(tmp_path: Path) -> None:
    pack = _pack()
    pack["type_facts"] = {
        "capacity_bytes": 8,
        "process_input": {"input_model": "file", "file_name": "payload.zip"},
        "source_to_sink_trace": {"input_model": "file"},
    }
    pack["source"] = {"evidence": ["zip archive record reaches parser"]}

    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        input_model="file",
        symbolic_bytes=512,
    )
    candidates = concolic_module._hybrid_witness_candidates(request, pack)

    assert request.seed_mutations
    assert request.seed_mutations[0].startswith("hex:504b")
    assert candidates[0]["source"] == "seed_mutation:0"
    with zipfile.ZipFile(io.BytesIO(candidates[0]["bytes"])) as archive:
        assert archive.read("payload.txt").startswith(b"A")


def test_explicit_concolic_seed_stays_ahead_of_witness_plan_seed(tmp_path: Path) -> None:
    pack = _pack()
    pack["type_facts"] = {
        "capacity_bytes": 8,
        "process_input": {"input_model": "stdin"},
        "source_to_sink_trace": {"input_model": "stdin"},
    }

    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        input_model="stdin",
        symbolic_bytes=16,
        seed_mutations=["USER-SEED"],
    )
    candidates = concolic_module._hybrid_witness_candidates(request, pack)

    assert request.seed_mutations[0] == "USER-SEED"
    assert request.seed_mutations[1].startswith("A")
    assert candidates[0]["bytes"].startswith(b"USER-SEED")


def test_address_translation_uses_export_relative_address() -> None:
    translated = translate_ghidra_to_loader_address("0x401234", image_base=0x400000, loader_base=0x500000)

    assert translated.relative_address == 0x1234
    assert translated.loader_address == 0x501234


def test_concolic_verdicts_convert_to_confirmation_statuses() -> None:
    confirmed = concolic_confirmation_dict(
        ConcolicVerdict(
            candidate_id="demo",
            verdict="overflow_witness",
            evidence_refs=("object:0", "write:0"),
            artifact_paths=("demo/replay.json", "demo/ghidra_dynamic_proof.json", "demo/verdict.json"),
            witness=CrashWitness(input_model="stdin", stdin=b"A" * 32),
            replay_result={"concrete_angr_replay": {"status": "replayed"}},
            ghidra_dynamic_proof={
                "status": "overflow_proven",
                "sink_address": "0x401000",
                "destination_kind": "stack",
                "write_size_bytes": 32,
                "capacity_bytes": 16,
                "overflow_bytes": 16,
                "write_range": {"start_offset": 0, "end_offset_exclusive": 32},
                "object_range": {"start_offset": 0, "end_offset_exclusive": 16},
                "harness_model": {"input_model": "stdin"},
            },
            )
        )
    heap_confirmed = concolic_confirmation_dict(
        ConcolicVerdict(
            candidate_id="demo_heap",
            verdict="overflow_witness",
            artifact_paths=("heap/replay.json", "heap/ghidra_dynamic_proof.json", "heap/verdict.json"),
            replay_result={"concrete_angr_replay": {"status": "replayed"}},
            ghidra_dynamic_proof={
                "status": "overflow_proven",
                "destination_kind": "heap",
                "sink_address": "0x401100",
                "write_size_bytes": 128,
                "capacity_bytes": 1,
                "overflow_bytes": 127,
            },
        )
    )
    oob_read_confirmed = concolic_confirmation_dict(
        ConcolicVerdict(
            candidate_id="demo_oob_read",
            verdict="overflow_witness",
            artifact_paths=("oob/replay.json", "oob/ghidra_dynamic_proof.json", "oob/verdict.json"),
            replay_result={"concrete_angr_replay": {"status": "replayed"}},
            ghidra_dynamic_proof={
                "status": "oob_read_proven",
                "destination_kind": "stack",
                "sink_address": "0x401200",
                "read_size_bytes": 4,
                "capacity_bytes": 16,
                "oob_bytes": 4,
                "read_range": {"start_offset": 20, "end_offset_exclusive": 24},
                "object_range": {"start_offset": 0, "end_offset_exclusive": 16},
            },
        )
    )
    heap_alias_confirmed = concolic_confirmation_dict(
        ConcolicVerdict(
            candidate_id="demo_heap_alias",
            verdict="overflow_witness",
            artifact_paths=("heap_alias/replay.json", "heap_alias/ghidra_dynamic_proof.json", "heap_alias/verdict.json"),
            replay_result={"concrete_angr_replay": {"status": "replayed"}},
            ghidra_dynamic_proof={
                "status": "heap_overflow_proven",
                "destination_kind": "heap",
                "sink_address": "0x401300",
                "write_size_bytes": 64,
                "capacity_bytes": 16,
                "overflow_bytes": 48,
            },
        )
    )
    oob_write_confirmed = concolic_confirmation_dict(
        ConcolicVerdict(
            candidate_id="demo_oob_write",
            verdict="overflow_witness",
            artifact_paths=("oob_write/replay.json", "oob_write/ghidra_dynamic_proof.json", "oob_write/verdict.json"),
            replay_result={"concrete_angr_replay": {"status": "replayed"}},
            ghidra_dynamic_proof={
                "status": "oob_write_proven",
                "destination_kind": "global",
                "sink_address": "0x401400",
                "write_size_bytes": 4,
                "capacity_bytes": 16,
                "overflow_bytes": 4,
                "write_range": {"start_offset": 20, "end_offset_exclusive": 24},
                "object_range": {"start_offset": 0, "end_offset_exclusive": 16},
            },
        )
    )
    lifetime_confirmed = concolic_confirmation_dict(
        ConcolicVerdict(
            candidate_id="demo_uaf",
            verdict="memory_violation_witness",
            artifact_paths=("uaf/replay.json", "uaf/ghidra_dynamic_proof.json", "uaf/verdict.json"),
            ghidra_dynamic_proof={
                "proof_kind": "ghidra_dynamic_memory_safety",
                "status": "lifetime_violation_proven",
                "sink_address": "0x401500",
                "exact_sink_reached": True,
                "lifetime_violation": {
                    "vulnerability": "use_after_free",
                    "object_id": 3,
                    "object_base_address": "0x70000000",
                    "object_size_bytes": 32,
                },
            },
        )
    )
    missing_replay = concolic_confirmation_dict(
        ConcolicVerdict(
            candidate_id="demo",
            verdict="overflow_witness",
            evidence_refs=("object:0", "write:0"),
            artifact_paths=("demo/verdict.json",),
        )
    )
    missing_replay_artifact = concolic_confirmation_dict(
        ConcolicVerdict(
            candidate_id="demo",
            verdict="overflow_witness",
            artifact_paths=("demo/verdict.json",),
            replay_result={"concrete_angr_replay": {"status": "replayed"}},
        )
    )
    missing_exact_sink = concolic_confirmation_dict(
        ConcolicVerdict(
            candidate_id="demo",
            verdict="overflow_witness",
            artifact_paths=("demo/replay.json", "demo/pcode_trace.json", "demo/verdict.json"),
            replay_result={"concrete_angr_replay": {"status": "replayed"}},
            pcode_trace={
                "status": "reached",
                "replay": {"status": "reached"},
                "sink_trace": {"exact_sink_reached": False, "reason": "missing_exact_operation_address"},
            },
        )
    )
    non_overflow_proof = concolic_confirmation_dict(
        ConcolicVerdict(
            candidate_id="demo",
            verdict="overflow_witness",
            artifact_paths=("demo/replay.json", "demo/ghidra_dynamic_proof.json", "demo/verdict.json"),
            replay_result={"concrete_angr_replay": {"status": "replayed"}},
            ghidra_dynamic_proof={
                "status": "no_overflow",
                "sink_address": "0x401000",
                "write_size_bytes": 8,
                "capacity_bytes": 16,
                "overflow_bytes": 0,
            },
        )
    )
    safe = concolic_confirmation_dict(ConcolicVerdict(candidate_id="demo", verdict="path_unsat"))
    timeout = concolic_confirmation_dict(ConcolicVerdict(candidate_id="demo", verdict="timeout"))
    unsupported = concolic_confirmation_dict(
        ConcolicVerdict(candidate_id="demo", verdict="backend_error", errors=("unsupported_input_model:file",))
    )

    assert confirmed["status"] == "confirmed_bug"
    assert confirmed["reason_codes"] == ["ghidra_dynamic_overflow_proven"]
    assert "concolic_artifact:demo/replay.json" in confirmed["evidence_refs"]
    assert confirmed["memory_safety_argument"]["native_replay"]["status"] == "not_run"
    assert confirmed["memory_safety_argument"]["overflow_bytes"] == 16
    assert confirmed["bug_class"] == "stack_buffer_overflow"
    assert heap_confirmed["status"] == "confirmed_bug"
    assert heap_confirmed["bug_class"] == "heap_buffer_overflow"
    assert oob_read_confirmed["status"] == "confirmed_bug"
    assert oob_read_confirmed["reason_codes"] == ["ghidra_dynamic_oob_read_proven"]
    assert oob_read_confirmed["bug_class"] == "out_of_bounds_read"
    assert oob_read_confirmed["memory_safety_argument"]["read_range"]["start_offset"] == 20
    assert oob_read_confirmed["memory_safety_argument"]["oob_bytes"] == 4
    assert heap_alias_confirmed["status"] == "confirmed_bug"
    assert heap_alias_confirmed["reason_codes"] == ["ghidra_dynamic_heap_overflow_proven"]
    assert heap_alias_confirmed["bug_class"] == "heap_buffer_overflow"
    assert oob_write_confirmed["status"] == "confirmed_bug"
    assert lifetime_confirmed["status"] == "confirmed_bug"
    assert lifetime_confirmed["reason_codes"] == ["ghidra_dynamic_lifetime_violation_proven"]
    assert lifetime_confirmed["bug_class"] == "use_after_free"
    assert oob_write_confirmed["reason_codes"] == ["ghidra_dynamic_oob_write_proven"]
    assert oob_write_confirmed["memory_safety_argument"]["write_range"]["start_offset"] == 20
    assert missing_replay["status"] == "needs_dynamic_confirmation"
    assert missing_replay["reason_codes"] == ["ghidra_dynamic_proof_missing"]
    assert missing_replay_artifact["status"] == "needs_dynamic_confirmation"
    assert missing_exact_sink["status"] == "needs_dynamic_confirmation"
    assert missing_exact_sink["reason_codes"] == ["ghidra_dynamic_proof_missing"]
    assert non_overflow_proof["status"] == "needs_dynamic_confirmation"
    assert non_overflow_proof["reason_codes"] == ["ghidra_dynamic_no_overflow"]
    assert safe["status"] == "not_a_bug"
    assert timeout["status"] == "needs_dynamic_confirmation"
    assert unsupported["status"] == "needs_dynamic_confirmation"


def test_waypoints_are_ordered_intersection_and_request_round_trips(tmp_path: Path) -> None:
    assert concolic_module.derive_waypoint_addresses(
        ["0x1000", "0x1020", "0x1010", "0x1020", "0x2000"],
        ["0x1010", "0x1020", "0x2000"],
        process_entry_address="0x1000",
        sink_address="0x2000",
    ) == ("0x1020", "0x1010")
    request = ConcolicRequest(
        candidate_id="waypoints",
        binary_path=_binary(tmp_path),
        waypoint_addresses=("0x1020", "0x1010"),
        extra_branch_goal="0x9999",
    )
    assert ConcolicRequest.from_dict(request.to_dict()).waypoint_addresses == ("0x1020", "0x1010")


def test_trace_waypoints_use_nested_replay_instructions_and_verified_static_path(tmp_path: Path) -> None:
    pack = _pack("demo:0x1210:target:4:memcpy:local_20")
    pack["deterministic_candidate"].update(
        {
            "function_name": "target",
            "address": "0x1200",
            "operation_address": "0x1210",
        }
    )
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": "0x1210"}]
    pack["facts_available_to_llm"]["pcode_slice"] = {"operation_address": "0x1210"}
    entrypoint = {
        "schema_version": 2,
        "status": "derived",
        "entry_function": "main",
        "entry_address": "0x1000",
        "target_function": "target",
        "target_address": "0x1200",
        "input_model": "stdin",
        "process_input_supported": True,
        "call_path": ["main", "worker", "target"],
    }
    pack["entrypoint_derivation"] = entrypoint
    pack["facts_available_to_llm"]["entrypoint_derivation"] = entrypoint
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record("main", "0x1000", pcode_calls=[{"callee": "worker", "call_address": "0x1008"}]),
            _function_record("worker", "0x1100", pcode_calls=[{"callee": "target", "call_address": "0x1108"}]),
            _function_record("target", "0x1200"),
        ],
    )
    request = ConcolicRequest(
        candidate_id=pack["candidate_id"],
        binary_path=_binary(tmp_path),
        export_dir=export_dir,
        target_address="0x1210",
        sink_address="0x1210",
        input_model="stdin",
    )

    static_path = concolic_module._static_candidate_path_addresses(
        pack,
        request,
        entrypoint=entrypoint,
    )
    assert static_path == ("0x1000", "0x1008", "0x1100", "0x1108", "0x1200", "0x1210")

    guided = concolic_module._request_with_trace_waypoints(
        request,
        pack,
        {
            "proof_scope": "process_entrypoint",
            "exact_sink_reached": False,
            "process_replay": {
                "status": "step_limit",
                "instructions": [
                    {"address": "0x1000"},
                    {"address": "0x1008"},
                    {"address": "0x1100"},
                    {"address": "0x1108"},
                    {"address": "0x1200"},
                    {"address": "0x1210"},
                ],
            },
        },
    )

    assert guided.waypoint_addresses == ("0x1008", "0x1100", "0x1108", "0x1200")
    assert guided.target_resolution["trace_guidance"] == {
        "source": "seeded_ghidra_process_replay",
        "static_path_addresses": list(static_path),
        "executed_address_count": 6,
        "waypoint_addresses": ["0x1008", "0x1100", "0x1108", "0x1200"],
        "instructions_truncated": 0,
    }
    assert concolic_module.validate_concolic_request(pack, guided) == guided


def test_trace_waypoints_preserve_legacy_single_goal_alias(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    request = ConcolicRequest(
        candidate_id="demo:0x1010:main:4:memcpy:local_20",
        binary_path=_binary(tmp_path),
        target_address="0x1010",
        sink_address="0x1010",
        input_model="stdin",
        extra_branch_goal="0x1008",
    )

    def static_path_should_not_be_derived(*_args: Any, **_kwargs: Any) -> tuple[str, ...]:
        raise AssertionError("legacy extra_branch_goal must not be overwritten by automatic waypoints")

    monkeypatch.setattr(concolic_module, "_static_candidate_path_addresses", static_path_should_not_be_derived)
    result = concolic_module._request_with_trace_waypoints(
        request,
        _pack_with_entrypoint("stdin"),
        {
            "proof_scope": "process_entrypoint",
            "process_replay": {
                "status": "timeout",
                "instructions": [{"address": "0x1008"}],
            },
        },
    )

    assert result is request
    assert result.extra_branch_goal == "0x1008"
    assert result.waypoint_addresses == ()


def test_guided_checkpoint_timeout_has_structured_exploration_diagnostic() -> None:
    payload = ConcolicVerdict(
        candidate_id="guided",
        verdict="timeout",
        rationale="guided_checkpoint_unreached",
        logs=("guided_checkpoint_unreached",),
    ).to_dict()

    assert payload["diagnostic"]["stage"] == "exploration"
    assert payload["diagnostic"]["reason"] == "guided_checkpoint_unreached"


def test_waypoint_guidance_comparison_uses_identical_budget_and_records_state_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = ConcolicRequest(
        candidate_id="demo:0x1010:main:4:memcpy:local_20",
        binary_path=_binary(tmp_path),
        target_address="0x1010",
        sink_address="0x1010",
        input_model="stdin",
        timeout_seconds=15,
        extra_branch_goal="0x1008",
    )
    observed: list[ConcolicRequest] = []

    def fake_backend(current: ConcolicRequest, _pack: Mapping[str, Any]) -> ConcolicVerdict:
        observed.append(current)
        guided = bool(current.waypoint_addresses)
        return ConcolicVerdict(
            candidate_id=current.candidate_id,
            verdict="timeout",
            backend="angr",
            request=current.to_dict(),
            angr_trace={
                "status": "timeout",
                "stash_counts": {"active": 2 if guided else 8},
                "exploration_metrics": {
                    "simgr_steps": 3,
                    "peak_active_states": 2 if guided else 8,
                    "peak_total_states": 3 if guided else 12,
                    "reached_waypoint_count": 1 if guided else 0,
                },
            },
            elapsed_seconds=1.0,
        )

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_backend)
    comparison = concolic_module.compare_waypoint_guidance(request, _pack(), ["0x1008"])

    assert [item.timeout_seconds for item in observed] == [15, 15]
    assert observed[0].waypoint_addresses == ()
    assert observed[0].extra_branch_goal == ""
    assert observed[1].waypoint_addresses == ("0x1008",)
    assert comparison["unguided"]["peak_total_states"] == 12
    assert comparison["guided"]["peak_total_states"] == 3
    assert comparison["proof_requirements"]["exact_sink_proof_required"] is True


def test_function_harness_overflow_is_downgraded_when_known_callsites_are_bounded(tmp_path: Path) -> None:
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    callee_source = """// Function: helper
// Address: 0x1000

void helper(undefined4 param_1,char *param_2,char *param_3)
{
  char local_1d8 [128];
  local_1d8[0] = '\\0';
  strcat(local_1d8,param_2);
  strcat(local_1d8,param_3);
}
"""
    caller_source = """// Function: caller
// Address: 0x1100

void caller(void)
{
  helper(0,"/app/war","/export/core/");
  helper(0,"/app/war","/export/core1/");
}
"""
    (export_dir / "helper.c").write_text(callee_source)
    (export_dir / "caller.c").write_text(caller_source)
    line_number = next(
        index for index, line in enumerate(callee_source.splitlines(), start=1) if "strcat(local_1d8,param_3)" in line
    )
    pack = _pack("demo:0x1000:helper:9:strcat:local_1d8")
    pack["deterministic_candidate"].update(
        {
            "function_name": "helper",
            "address": "0x1000",
            "relative_path": "helper.c",
            "operation_address": "0x1010",
            "sink": "strcat",
            "line_number": line_number,
            "line_text": "strcat(local_1d8,param_3);",
            "target_buffer": "local_1d8",
            "capacity_bytes": 128,
            "destination_kind": "stack",
        }
    )
    request = concolic_module.ConcolicRequest(
        candidate_id=pack["candidate_id"],
        binary_path=_binary(tmp_path),
        export_dir=export_dir,
        target_address="0x1010",
        sink_address="0x1010",
        input_model="function_harness",
    )
    proof = {
        "status": "overflow_proven",
        "sink_name": "strcat",
        "destination_kind": "stack",
        "capacity_bytes": 128,
        "write_size_bytes": 256,
        "overflow_bytes": 128,
        "write_range": {"start_offset": 0, "end_offset_exclusive": 256, "size_bytes": 256},
        "object_range": {"start_offset": 0, "end_offset_exclusive": 128, "size_bytes": 128},
    }

    gated = concolic_module._apply_call_context_feasibility_gate(pack, request, proof)

    assert gated["status"] == "no_overflow"
    assert gated["reason"] == "known_callsite_arguments_bound_write"
    assert gated["write_size_bytes"] == len("/app/war") + len("/export/core1/") + 1
    assert gated["overflow_bytes"] == 0
    assert gated["function_harness_dynamic_proof"]["status"] == "overflow_proven"
    assert gated["call_context_feasibility"]["callsite_count"] == 2
    assert gated["call_context_feasibility"]["status"] == "no_overflow_in_known_call_context"


def test_function_harness_overflow_stays_promoted_when_callsite_arg_is_unknown(tmp_path: Path) -> None:
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    callee_source = """// Function: helper
void helper(undefined4 param_1,char *param_2)
{
  char local_1d8 [128];
  local_1d8[0] = '\\0';
  strcat(local_1d8,param_2);
}
"""
    caller_source = """// Function: caller
void caller(char *param_1)
{
  helper(0,param_1);
}
"""
    (export_dir / "helper.c").write_text(callee_source)
    (export_dir / "caller.c").write_text(caller_source)
    line_number = next(
        index for index, line in enumerate(callee_source.splitlines(), start=1) if "strcat(local_1d8,param_2)" in line
    )
    pack = _pack("demo:0x1000:helper:6:strcat:local_1d8")
    pack["deterministic_candidate"].update(
        {
            "function_name": "helper",
            "relative_path": "helper.c",
            "sink": "strcat",
            "line_number": line_number,
            "line_text": "strcat(local_1d8,param_2);",
            "target_buffer": "local_1d8",
            "capacity_bytes": 128,
            "destination_kind": "stack",
        }
    )
    request = concolic_module.ConcolicRequest(
        candidate_id=pack["candidate_id"],
        binary_path=_binary(tmp_path),
        export_dir=export_dir,
        target_address="0x1010",
        sink_address="0x1010",
        input_model="function_harness",
    )
    proof = {
        "status": "overflow_proven",
        "sink_name": "strcat",
        "destination_kind": "stack",
        "capacity_bytes": 128,
        "write_size_bytes": 256,
        "overflow_bytes": 128,
        "write_range": {"start_offset": 0, "end_offset_exclusive": 256, "size_bytes": 256},
        "object_range": {"start_offset": 0, "end_offset_exclusive": 128, "size_bytes": 128},
    }

    gated = concolic_module._apply_call_context_feasibility_gate(pack, request, proof)

    assert gated["status"] == "overflow_proven"
    assert gated["call_context_feasibility"]["status"] == "unknown"
    assert gated["call_context_feasibility"]["evaluations"][0]["reason"] == "source_length_unknown"


def test_function_harness_overflow_is_not_promoted_without_reachable_call_context(tmp_path: Path) -> None:
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    callee_source = """// Function: helper
void helper(char *param_1)
{
  char local_1d8 [128];
  local_1d8[0] = '\\0';
  strcat(local_1d8,param_1);
}
"""
    (export_dir / "helper.c").write_text(callee_source)
    line_number = next(
        index for index, line in enumerate(callee_source.splitlines(), start=1) if "strcat(local_1d8,param_1)" in line
    )
    pack = _pack("demo:0x1000:helper:6:strcat:local_1d8")
    pack["deterministic_candidate"].update(
        {
            "function_name": "helper",
            "relative_path": "helper.c",
            "sink": "strcat",
            "line_number": line_number,
            "line_text": "strcat(local_1d8,param_1);",
            "target_buffer": "local_1d8",
            "capacity_bytes": 128,
            "destination_kind": "stack",
        }
    )
    pack["reachability"] = {
        "caller_count": 0,
        "input_reaches_sink": False,
        "path_is_valid": False,
        "is_public": False,
        "is_exported": False,
        "is_root_like": False,
        "is_entry": False,
        "is_thread_start": False,
        "has_callback_evidence": False,
        "complete_unreachable_candidate": True,
    }
    request = concolic_module.ConcolicRequest(
        candidate_id=pack["candidate_id"],
        binary_path=_binary(tmp_path),
        export_dir=export_dir,
        target_address="0x1010",
        sink_address="0x1010",
        input_model="function_harness",
    )
    proof = {
        "status": "overflow_proven",
        "sink_name": "strcat",
        "destination_kind": "stack",
        "capacity_bytes": 128,
        "write_size_bytes": 256,
        "overflow_bytes": 128,
    }

    gated = concolic_module._apply_call_context_feasibility_gate(pack, request, proof)

    assert gated["status"] == "unsupported"
    assert gated["reason"] == "function_harness_call_context_unresolved"
    assert gated["call_context_feasibility"]["reason"] == "no_known_direct_callsites"


def test_run_concolic_output_loads_as_confirmations(tmp_path: Path) -> None:
    evidence_dir = _write_pack_dir(tmp_path, _pack())
    output_dir = tmp_path / "concolic"

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=output_dir,
        continue_on_error=True,
        jobs=2,
    )
    confirmations = load_candidate_confirmations(output_dir)

    assert result.written_count == 1
    assert result.verdict_counts["backend_error"] == 1
    artifact_dir = output_dir / "demo_0x1010_main_4_memcpy_local_20"
    assert (artifact_dir / CONCOLIC_REQUEST_FILENAME).exists()
    assert (artifact_dir / CONCOLIC_ANGR_TRACE_FILENAME).exists()
    assert (artifact_dir / CONCOLIC_PCODE_UNSUPPORTED_FILENAME).exists()
    assert (artifact_dir / CONCOLIC_DYNAMIC_PROOF_UNSUPPORTED_FILENAME).exists()
    assert (artifact_dir / CONCOLIC_LLM_ACTIONS_FILENAME).exists()
    assert (artifact_dir / CONCOLIC_REPLAY_FILENAME).exists()
    assert (artifact_dir / CONCOLIC_VERDICT_FILENAME).exists()
    confirmation = confirmations[_pack()["candidate_id"]]
    assert confirmation.status == "needs_more_evidence"
    assert confirmation.reason_codes == ["concolic_backend_error"]


def test_run_concolic_attempts_every_explicit_candidate_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _pack("demo:0x1010:first:4:memcpy:local_20")
    second = _pack("demo:0x1020:second:4:memcpy:local_20")
    third = _pack("demo:0x1030:third:4:memcpy:local_20")
    evidence_dir = _write_pack_dir_many(tmp_path, [first, second, third])
    seen: list[str] = []

    def fake_angr_backend(request, evidence_pack):
        seen.append(request.candidate_id)
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="path_unsat",
            backend=request.backend,
            request=request.to_dict(),
        )

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=tmp_path / "concolic",
        target_candidate_ids=[third["candidate_id"], first["candidate_id"], second["candidate_id"]],
    )

    assert seen == [third["candidate_id"], first["candidate_id"], second["candidate_id"]]
    assert result.eligible_count == 3
    assert result.scheduled_count == 3
    assert result.attempted_count == 3
    assert result.written_count == 3
    assert result.to_dict()["attempt_coverage"] == 1.0


def test_concolic_verdict_diagnostics_identify_failure_stage() -> None:
    request = {"target_address": "0x1010", "sink_address": "0x1010", "input_model": "file"}
    disconnected = ConcolicVerdict(
        candidate_id="disconnected",
        verdict="path_unsat",
        request=request,
        angr_trace={
            "constraints_summary": {"count": 0},
            "stash_counts": {"active": 0, "deadended": 1},
        },
    ).to_dict()
    reached = ConcolicVerdict(
        candidate_id="reached",
        verdict="target_reached",
        request=request,
        reached_addresses=("0x1010",),
    ).to_dict()
    harness = ConcolicVerdict(
        candidate_id="harness",
        verdict="timeout",
        request=request,
        angr_trace={"status": "trivial_function_harness_entry"},
    ).to_dict()

    assert disconnected["diagnostic"]["stage"] == "input_model"
    assert disconnected["diagnostic"]["reason"] == "symbolic_input_not_connected"
    assert disconnected["diagnostic"]["progress"]["deadended_states"] == 1
    assert reached["diagnostic"]["reason"] == "target_reached_without_violation"
    assert reached["diagnostic"]["progress"]["target_reached"] is True
    assert harness["diagnostic"]["reason"] == "target_equals_harness_entry"


def test_concolic_verdict_diagnostic_classifies_backend_oom_as_resource_limit() -> None:
    verdict = ConcolicVerdict(
        candidate_id="oom",
        verdict="backend_error",
        rationale="angr backend failed: b'out of memory'",
        errors=("b'out of memory'",),
    )

    assert verdict.diagnostic["stage"] == "resource"
    assert verdict.diagnostic["reason"] == "memory_limit"


def test_isolated_worker_timeout_is_killed_before_next_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slow = _pack("demo:0x1010:slow:4:memcpy:local_20")
    fast = _pack("demo:0x1020:fast:4:memcpy:local_20")
    evidence_dir = _write_pack_dir_many(tmp_path, [slow, fast])
    child_pid_path = tmp_path / "slow_worker.pid"

    def fake_worker(task):
        candidate_id = task["evidence_pack"]["candidate_id"]
        if candidate_id == slow["candidate_id"]:
            child_pid_path.write_text(str(os.getpid()), encoding="utf-8")
            import time

            time.sleep(5)
        return concolic_module._isolated_worker_failure_result(
            task,
            verdict="backend_error",
            reason="fast_worker_completed",
        )

    monkeypatch.setattr(concolic_module, "_run_concolic_worker", fake_worker)
    monkeypatch.setattr(concolic_module, "ISOLATED_WORKER_GRACE_SECONDS", 0.05)
    monkeypatch.setattr(concolic_module, "ISOLATED_BACKEND_SETUP_GRACE_SECONDS", 0.0)

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=tmp_path / "concolic",
        target_candidate_ids=[slow["candidate_id"], fast["candidate_id"]],
        timeout_seconds=0.05,
        continue_on_error=True,
        isolate_candidates=True,
    )

    slow_pid = int(child_pid_path.read_text(encoding="utf-8"))
    with pytest.raises(ProcessLookupError):
        os.kill(slow_pid, 0)
    assert result.eligible_count == 2
    assert result.attempted_count == 2
    assert result.written_count == 2
    assert result.timed_out_count == 1
    assert result.verdict_counts["backend_error"] == 1
    assert result.diagnostic_counts == {
        "backend_setup:backend_error": 1,
        "exploration:wall_timeout": 1,
    }
    timeout_payload = json.loads(
        (tmp_path / "concolic" / "demo_0x1010_slow_4_memcpy_local_20" / "verdict.json").read_text()
    )
    assert timeout_payload["concolic_verdict"] == "timeout"
    assert timeout_payload["diagnostic"]["reason"] == "wall_timeout"


def test_isolated_worker_timeout_accounts_for_enabled_bounded_phases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(concolic_module, "ISOLATED_BACKEND_SETUP_GRACE_SECONDS", 3.0)
    monkeypatch.setattr(concolic_module, "ISOLATED_WORKER_GRACE_SECONDS", 1.0)
    monkeypatch.setattr(concolic_module, "GHIDRA_SUBPROCESS_STARTUP_GRACE_SECONDS", 4.0)
    monkeypatch.setattr(concolic_module, "GHIDRA_SUBPROCESS_MIN_TIMEOUT_SECONDS", 5.0)

    wall_timeout = concolic_module._isolated_worker_timeout_seconds(
        {
            "timeout_seconds": 2.0,
            "pcode_trace": True,
            "ghidra_dynamic_proof": True,
        }
    )

    assert wall_timeout == 38.0


def test_isolated_worker_receives_hard_memory_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _pack()
    evidence_dir = _write_pack_dir(tmp_path, pack)
    observed_limit = tmp_path / "worker_limit.txt"

    def fake_worker(task):
        import resource

        observed_limit.write_text(str(resource.getrlimit(resource.RLIMIT_AS)[0]), encoding="utf-8")
        raise MemoryError

    monkeypatch.setattr(concolic_module, "_run_concolic_worker", fake_worker)

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=tmp_path / "concolic",
        continue_on_error=True,
        isolate_candidates=True,
        memory_limit_mb=4096,
    )

    assert int(observed_limit.read_text(encoding="utf-8")) == 4096 * 1024 * 1024
    assert result.attempted_count == 1
    assert result.memory_limited_count == 1
    assert next(iter(result.errors.values())) == "worker_memory_limit_exceeded:4096MiB"


def test_run_concolic_request_rejects_unsupported_directory_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _pack()
    pack["type_facts"] = {
        "semantic_seed": {"kind": "process_input_overflow"},
        "entrypoint_derivation": {
            "status": "derived",
            "process_input_supported": True,
            "input_model": "argv",
            "entry_address": "0x1000",
            "source_to_sink_trace": {
                "argument_roles": [
                    {
                        "role": "write_source",
                        "expr": "pdVar5->d_name",
                        "classification": "parameter_controlled",
                        "evidence": ["readdir", "struct dirent d_name"],
                    }
                ],
                "input_observations": [{"input_model": "argv"}],
            },
        },
    }

    def fail_angr_backend(request, evidence_pack):
        raise AssertionError("angr backend should not run for unsupported directory sources")

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fail_angr_backend)
    request = ConcolicRequest(
        candidate_id=pack["candidate_id"],
        binary_path=_binary(tmp_path),
        target_address="0x1010",
        sink_address="0x1010",
        input_model="argv",
        symbolic_bytes=64,
    )

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
    )

    assert verdict.verdict == "backend_error"
    assert verdict.errors == ("unsupported_directory_iteration_source:readdir",)
    assert verdict.ghidra_dynamic_proof["status"] == "unsupported"
    assert verdict.ghidra_dynamic_proof["reason"] == "unsupported_directory_iteration_source:readdir"


def test_directory_entry_source_defaults_to_argv_directory_model(tmp_path: Path) -> None:
    pack = _pack()
    pack["type_facts"] = {
        "semantic_seed": {"kind": "process_input_overflow"},
        "entrypoint_derivation": {
            "status": "derived",
            "process_input_supported": True,
            "input_model": "argv",
            "entry_address": "0x1000",
            "source_to_sink_trace": {
                "argument_roles": [
                    {
                        "role": "write_source",
                        "expr": "pdVar5->d_name",
                        "classification": "parameter_controlled",
                        "evidence": ["opendir", "readdir", "struct dirent d_name"],
                    }
                ],
                "input_observations": [{"input_model": "argv"}],
            },
        },
    }

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), symbolic_bytes=256)
    process_input = concolic_module.infer_process_input_fact(pack)

    assert request.input_model == "argv_directory"
    assert process_input["input_model"] == "argv_directory"
    assert process_input["process_input_source"] == "inferred_from_directory_entry_source"
    assert process_input["process_input_evidence"]["directory_seed_reason"] == "readdir_d_name"
    assert process_input["argv_values"][1].endswith("/*")
    assert concolic_module._hybrid_witness_candidates(request, pack)[0]["source"] == "directory_entry_name_pattern"


def test_process_dynamic_proof_records_argv_directory_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "list_dir.sh"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    pack = _pack()
    pack["type_facts"] = {
        "semantic_seed": {"kind": "process_input_overflow"},
        "entrypoint_derivation": {
            "status": "derived",
            "process_input_supported": True,
            "input_model": "argv",
            "entry_address": "0x1000",
            "source_to_sink_trace": {
                "argument_roles": [
                    {
                        "role": "write_source",
                        "expr": "pdVar5->d_name",
                        "classification": "parameter_controlled",
                        "evidence": ["opendir", "readdir", "struct dirent d_name"],
                    }
                ],
                "input_observations": [{"input_model": "argv"}],
            },
        },
    }

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="timeout",
            backend=request.backend,
            request=request.to_dict(),
            rationale="angr timed out before producing a concrete directory-entry witness.",
        )

    def fake_dynamic_proof(proof_request):
        assert proof_request.input_model == "argv_directory"
        assert proof_request.file_name
        assert proof_request.argv_values[1].endswith("/*")
        return {
            "status": "overflow_proven",
            "proof_scope": "process_entrypoint",
            "sink_reached": True,
            "exact_sink_reached": True,
            "sink_address": "0x1010",
            "write_size_bytes": 32,
            "capacity_bytes": 16,
            "overflow_bytes": 16,
            "process_input_setup": {
                "status": "configured",
                "input_model": "argv_directory",
                "argv_values": list(proof_request.argv_values),
                "file_name": proof_request.file_name,
                "process_input_source": proof_request.process_input_source,
            },
            "process_replay": {"status": "reached", "reached_target": True},
            "local_sink_probe": {"status": "reached", "reached_target": True},
        }

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    request = build_concolic_request(pack, binary_path=binary, symbolic_bytes=32)

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / "artifacts",
    )

    attempt_path = next((tmp_path / "artifacts").rglob(concolic_module.CONCOLIC_PROCESS_WITNESS_ATTEMPT_FILENAME))
    attempt_payload = json.loads(attempt_path.read_text())

    assert verdict.verdict == "overflow_witness"
    assert attempt_payload["status"] == "observed"
    assert attempt_payload["input_model_counts"] == {"argv_directory": 1}
    assert attempt_payload["attempts"][0]["attempt_source"] == "directory_entry_name_pattern"
    assert attempt_payload["attempts"][0]["process_input_setup"]["file_name"]


def test_run_concolic_llm_controller_records_accepted_action(tmp_path: Path) -> None:
    pack = _pack()
    pack["llm_concolic_requests"] = [
        {
            "tool": CONCOLIC_TOOL_NAME,
            "target_address": "0x1010",
            "input_model": "stdin",
            "symbolic_byte_budget": 16,
        }
    ]
    evidence_dir = _write_pack_dir(tmp_path, pack)
    output_dir = tmp_path / "concolic"

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=output_dir,
        llm_controller=True,
        continue_on_error=True,
    )

    actions_path = output_dir / "demo_0x1010_main_4_memcpy_local_20" / CONCOLIC_LLM_ACTIONS_FILENAME
    actions = json.loads(actions_path.read_text())
    assert result.written_count == 1
    assert actions["enabled"] is True
    assert actions["accepted_requests"][0]["input_model"] == "stdin"


def test_run_concolic_llm_controller_does_not_invent_request(tmp_path: Path) -> None:
    evidence_dir = _write_pack_dir(tmp_path, _pack())
    output_dir = tmp_path / "concolic"

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=output_dir,
        llm_controller=True,
        continue_on_error=True,
    )

    actions_path = output_dir / "demo_0x1010_main_4_memcpy_local_20" / CONCOLIC_LLM_ACTIONS_FILENAME
    actions = json.loads(actions_path.read_text())
    assert result.written_count == 1
    assert actions["enabled"] is True
    assert actions["accepted_requests"] == []


def test_proof_ready_memory_selector_includes_wrapper_and_global_memory_packs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fgets_pack = _pack("demo:0x1010:main:301:fgets:local_848:0:0x800")
    fgets_pack["deterministic_candidate"].update(
        {
            "kind": "interprocedural_call",
            "sink": "fgets",
            "target_buffer": "local_848",
            "destination_kind": "stack",
            "capacity_bytes": 0x800,
            "write_relation": "proven_overflow",
        }
    )
    global_pack = _pack("demo:0x1020:main:310:strcat:DAT_404020:0:unbounded")
    global_pack["deterministic_candidate"].update(
        {
            "sink": "strcat",
            "target_buffer": "DAT_404020",
            "destination_kind": "global",
            "capacity_bytes": 128,
            "write_relation": "unbounded",
        }
    )
    bounded_pack = _pack("demo:0x1030:main:320:memcpy:local_20:0:bounded")
    bounded_pack["deterministic_candidate"].update(
        {
            "sink": "memcpy",
            "destination_kind": "stack",
            "capacity_bytes": 64,
            "write_size_bytes": 16,
            "write_relation": "bounded",
            "verdict": "bounded",
        }
    )
    bounded_pack["proof_obligation"]["relation"] = "bounded"
    evidence_dir = _write_pack_dir_many(tmp_path, [fgets_pack, global_pack, bounded_pack])
    output_dir = tmp_path / "concolic"

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="path_unsat",
            backend=request.backend,
            request=request.to_dict(),
        )

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=output_dir,
        target_selector="proof_ready_memory",
        continue_on_error=True,
    )

    assert result.written_count == 2
    assert sorted(path.name for path in output_dir.glob("demo_*.json")) == [
        "demo_0x1010_main_301_fgets_local_848_0_0x800.json",
        "demo_0x1020_main_310_strcat_DAT_404020_0_unbounded.json",
    ]


def _stale_nonbyte_array_capacity_pack(tmp_path: Path) -> tuple[dict[str, Any], Path, str]:
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (export_dir / "001000_main.c").write_text(
        """
void main(void) {
  stat64 local_848 [14];
  pcVar18 = (char *)FUN_00102000(local_848);
}
"""
    )
    pack = _pack_with_entrypoint("argv")
    candidate_id = "demo:0x1000:main:301:fgets:local_848:0:0x800"
    pack["candidate_id"] = candidate_id
    pack["decompiler_context"] = {"export_dir": str(export_dir)}
    candidate = pack["deterministic_candidate"]
    candidate.update(
        {
            "candidate_id": candidate_id,
            "function_name": "main",
            "address": "0x1000",
            "operation_address": "0x1024",
            "kind": "interprocedural_call",
            "sink": "fgets",
            "target_buffer": "local_848",
            "destination_kind": "stack",
            "capacity_bytes": 14,
            "capacity_basis": "local_848: declared local stack object, stack[-0x848..-0x83a], 14 bytes",
            "write_size_bytes": 0x800,
            "write_relation": "proven_overflow",
            "verdict": "overflow",
        }
    )
    static_candidate = dict(candidate)
    static_candidate["capacity_source"] = "declared_local_array"
    pack["type_facts"] = {"static_candidate": static_candidate}
    pack["proof_obligation"]["relation"] = "proven_overflow"
    return pack, export_dir, candidate_id


def test_proof_ready_memory_selector_excludes_stale_nonbyte_array_capacity_pack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack, _export_dir, _candidate_id = _stale_nonbyte_array_capacity_pack(tmp_path)
    evidence_dir = _write_pack_dir(tmp_path, pack)
    output_dir = tmp_path / "concolic"

    def fake_angr_backend(request, evidence_pack):
        raise AssertionError("stale non-byte array capacity pack should not be selected")

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=output_dir,
        target_selector="proof_ready_memory",
        continue_on_error=True,
    )

    assert result.written_count == 0


def test_dynamic_proof_request_demotes_stale_nonbyte_array_capacity(tmp_path: Path) -> None:
    pack, export_dir, candidate_id = _stale_nonbyte_array_capacity_pack(tmp_path)
    request = ConcolicRequest(
        candidate_id=candidate_id,
        binary_path=_binary(tmp_path),
        export_dir=export_dir,
        target_address="0x1024",
        sink_address="0x1024",
        input_model="argv",
        symbolic_bytes=64,
    )
    verdict = ConcolicVerdict(
        candidate_id=candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model="argv", argv=(b"A" * 64,)),
    )

    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "ghidra_dynamic_proof.json",
    )

    assert proof_request.capacity_bytes == 0
    assert proof_request.capacity_source == "direct_object_extent_unknown"
    assert proof_request.write_relation == "symbolic_capacity"
    assert concolic_module._reached_sink_proves_memory_overflow(
        pack,
        b"A" * 0x800,
        export_dir=export_dir,
    ) is False


def test_candidate_state_preserves_non_stack_memory_families() -> None:
    heap = candidate_state_from_static_candidate(
        {
            "candidate_id": "heap-demo",
            "vulnerability_type": "heap_overflow",
            "sink": "memcpy",
            "destination_kind": "heap",
            "capacity_bytes": 8,
            "write_relation": "proven_overflow",
            "verdict": "overflow",
            "path_is_valid": True,
            "input_reaches_sink": True,
        }
    )
    write = candidate_state_from_static_candidate(
        {
            "candidate_id": "write-demo",
            "vulnerability_type": "out_of_bounds_write",
            "sink": "memcpy",
            "destination_kind": "global",
            "capacity_bytes": 8,
            "write_relation": "proven_overflow",
            "verdict": "overflow",
            "path_is_valid": True,
            "input_reaches_sink": True,
        }
    )
    integer_risk = candidate_state_from_static_candidate(
        {
            "candidate_id": "integer-demo",
            "vulnerability_type": "integer_overflow_to_memory_access",
            "sink": "memcpy",
            "destination_kind": "heap",
            "capacity_bytes": 8,
            "write_relation": "integer_overflow_risk",
            "path_is_valid": True,
            "input_reaches_sink": True,
        }
    )
    implicit_heap = candidate_state_from_static_candidate(
        {
            "candidate_id": "implicit-heap-demo",
            "sink": "memcpy",
            "destination_kind": "heap",
            "capacity_bytes": 8,
            "write_relation": "proven_overflow",
            "verdict": "overflow",
            "path_is_valid": True,
            "input_reaches_sink": True,
        }
    )
    implicit_global = candidate_state_from_static_candidate(
        {
            "candidate_id": "implicit-global-demo",
            "sink": "strcpy",
            "destination_kind": "global",
            "capacity_bytes": 8,
            "write_relation": "unbounded",
            "verdict": "unbounded",
            "path_is_valid": True,
            "input_reaches_sink": True,
        }
    )

    assert heap.vulnerability_type == "heap_overflow"
    assert write.vulnerability_type == "out_of_bounds_write"
    assert integer_risk.vulnerability_type == "integer_overflow_to_memory_access"
    assert implicit_heap.vulnerability_type == "heap_overflow"
    assert implicit_global.vulnerability_type == "out_of_bounds_write"


def test_proof_ready_memory_selector_includes_symbolic_heap_allocation_packs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    heap_pack = _pack("demo:0x1010:join:8:strcpy:buf:0:unbounded")
    heap_pack["deterministic_candidate"].update(
        {
            "function_name": "join",
            "sink": "strcpy",
            "target_buffer": "buf",
            "destination_kind": "heap",
            "capacity_bytes": 0,
            "capacity_source": "local_malloc",
            "capacity_model": {
                "fixed_bytes": None,
                "symbolic_expr": "left_len + right_len + 2",
                "source": "local_malloc",
                "trust": "symbolic",
            },
            "write_relation": "unbounded",
            "verdict": "unbounded",
        }
    )
    heap_pack["proof_obligation"]["relation"] = "unbounded"
    stack_symbolic_pack = _pack("demo:0x1020:main:9:strcpy:local_20:0:unbounded")
    stack_symbolic_pack["deterministic_candidate"].update(
        {
            "sink": "strcpy",
            "target_buffer": "local_20",
            "destination_kind": "stack",
            "capacity_bytes": 0,
            "capacity_model": {
                "fixed_bytes": None,
                "symbolic_expr": "unknown_stack_extent",
                "source": "direct_object_extent_unknown",
                "trust": "symbolic",
            },
            "write_relation": "unbounded",
            "verdict": "unbounded",
        }
    )
    evidence_dir = _write_pack_dir_many(tmp_path, [heap_pack, stack_symbolic_pack])
    output_dir = tmp_path / "concolic"

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="path_unsat",
            backend=request.backend,
            request=request.to_dict(),
        )

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=output_dir,
        target_selector="proof_ready_memory",
        continue_on_error=True,
    )

    assert result.written_count == 1
    assert sorted(path.name for path in output_dir.glob("demo_*.json")) == [
        "demo_0x1010_join_8_strcpy_buf_0_unbounded.json"
    ]


def test_proof_ready_memory_selector_includes_oob_read_source_read_packs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oob_pack = _pack("demo:0x1010:main:24:memcpy_source_read:local_20:0:n")
    oob_pack["deterministic_candidate"].update(
        {
            "kind": "source_read",
            "sink": "memcpy_source_read",
            "target_buffer": "local_20",
            "destination_kind": "stack",
            "capacity_bytes": 8,
            "write_relation": "symbolic_size",
            "write_size_expr": "n",
            "vulnerability_type": "out_of_bounds_read",
            "verdict": "candidate",
        }
    )
    oob_pack["proof_obligation"]["relation"] = "symbolic_size"
    bounded_pack = _pack("demo:0x1020:main:320:memcpy:local_40:0:bounded")
    bounded_pack["deterministic_candidate"].update(
        {
            "sink": "memcpy",
            "destination_kind": "stack",
            "capacity_bytes": 64,
            "write_size_bytes": 16,
            "write_relation": "bounded",
            "verdict": "bounded",
        }
    )
    bounded_pack["proof_obligation"]["relation"] = "bounded"
    evidence_dir = _write_pack_dir_many(tmp_path, [oob_pack, bounded_pack])
    output_dir = tmp_path / "concolic"

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="path_unsat",
            backend=request.backend,
            request=request.to_dict(),
        )

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=output_dir,
        target_selector="proof_ready_memory",
        continue_on_error=True,
    )

    assert result.written_count == 1
    assert sorted(path.name for path in output_dir.glob("demo_*.json")) == [
        "demo_0x1010_main_24_memcpy_source_read_local_20_0_n.json"
    ]


def test_proof_ready_memory_selector_excludes_addressless_array_load_oob_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    array_pack = _pack("demo:0x1010:main:24:array_load:local_20:i:i")
    array_pack["deterministic_candidate"].update(
        {
            "kind": "indexed_read",
            "sink": "array_load",
            "operation_address": "",
            "target_buffer": "local_20",
            "destination_kind": "stack",
            "capacity_bytes": 8,
            "write_relation": "symbolic_read_offset",
            "write_size_bytes": 1,
            "offset_expr": "i",
            "vulnerability_type": "out_of_bounds_read",
            "verdict": "candidate",
        }
    )
    array_pack["proof_obligation"]["relation"] = "symbolic_read_offset"
    source_pack = _pack("demo:0x1020:main:24:memcpy_source_read:local_40:0:n")
    source_pack["deterministic_candidate"].update(
        {
            "kind": "source_read",
            "sink": "memcpy_source_read",
            "operation_address": "",
            "target_buffer": "local_40",
            "destination_kind": "stack",
            "capacity_bytes": 8,
            "write_relation": "symbolic_size",
            "write_size_expr": "n",
            "vulnerability_type": "out_of_bounds_read",
            "verdict": "candidate",
        }
    )
    source_pack["proof_obligation"]["relation"] = "symbolic_size"
    evidence_dir = _write_pack_dir_many(tmp_path, [array_pack, source_pack])
    output_dir = tmp_path / "concolic"

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="path_unsat",
            backend=request.backend,
            request=request.to_dict(),
        )

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=output_dir,
        target_selector="proof_ready_memory",
        continue_on_error=True,
    )

    assert result.written_count == 1
    assert sorted(path.name for path in output_dir.glob("demo_*.json")) == [
        "demo_0x1020_main_24_memcpy_source_read_local_40_0_n.json"
    ]


def test_file_model_hybrid_witness_prefers_evidence_driven_format_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        concolic_module,
        "_combined_process_decompiled_text",
        lambda evidence_pack: ("reads a tar archive with ustar headers", "/tmp/tar.c"),
    )
    request = ConcolicRequest(
        candidate_id="tar-oob",
        binary_path=_binary(tmp_path),
        input_model="file",
        symbolic_bytes=1024,
    )

    seeds = concolic_module._hybrid_witness_candidates(request, _pack("tar-oob"))

    assert seeds[0]["source"] == "file_format:tar_format_text"


def test_bmp_file_seed_is_structural_and_exercises_palette_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        concolic_module,
        "_combined_process_decompiled_text",
        lambda evidence_pack: ('error("cannot handle BMP planes")', "/tmp/bmp.c"),
    )
    pack = _pack("bmp-oob")

    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        input_model="file",
        symbolic_bytes=64,
    )
    payload = bytes.fromhex(request.seed_mutations[0].removeprefix("hex:"))

    assert payload[:2] == b"BM"
    assert len(payload) == 62
    assert int.from_bytes(payload[46:50], "little") == 1
    assert payload[58] == 0xFF


def test_file_model_hybrid_witness_uses_export_format_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    (export_dir / "target.c").write_text("void target(void) { parse(input); }\n")
    (export_dir / "archive_reader.c").write_text('void reader(void) { puts("This does not look like a tar archive"); }\n')
    monkeypatch.setattr(
        concolic_module,
        "_combined_process_decompiled_text",
        lambda evidence_pack: ("void target(void) { parse(input); }", str(export_dir / "target.c")),
    )
    request = ConcolicRequest(
        candidate_id="tar-oob",
        binary_path=_binary(tmp_path),
        input_model="file",
        symbolic_bytes=1024,
    )
    pack = _pack("tar-oob")
    pack["entrypoint_derivation"] = {"evidence": {"export_dir": str(export_dir)}}

    seeds = concolic_module._hybrid_witness_candidates(request, pack)

    assert seeds[0]["source"] == "file_format:tar_format_text"


def test_file_process_input_spec_uses_tar_list_mode_for_tar_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    (export_dir / "target.c").write_text("void target(void) { parse(input); }\n")
    (export_dir / "archive_reader.c").write_text('void reader(void) { puts("This does not look like a tar archive"); }\n')
    monkeypatch.setattr(
        concolic_module,
        "_combined_process_decompiled_text",
        lambda evidence_pack: ("void target(void) { parse(input); }", str(export_dir / "target.c")),
    )
    pack = _pack("tar-oob")
    pack["entrypoint_derivation"] = {"evidence": {"export_dir": str(export_dir)}}

    seed_hex, _file_name, _file_reason, _unsupported_reason, _source_path = concolic_module._infer_file_seed_from_evidence(
        pack
    )
    spec = concolic_module._file_process_input_spec(pack, input_hex=seed_hex)

    assert spec["argv_values"] == ("program", "-tf", "concolic_input.tar")
    assert spec["process_input_source"] == "inferred_file_seed"
    assert spec["process_input_evidence"]["file_seed_reason"] == "tar_format_text"


def test_file_witness_concrete_input_uses_file_content_before_filename(tmp_path: Path) -> None:
    request = ConcolicRequest(
        candidate_id="file-candidate",
        binary_path=_binary(tmp_path),
        input_model="file",
        symbolic_bytes=32,
    )
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="backend_error",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model="file", argv=(b"concolic_input",), file_inputs={"concolic_input": b"PAYLOAD"}),
    )

    concrete = concolic_module._concrete_input_from_verdict(verdict)

    assert concrete["source"] == "file:concolic_input"
    assert concrete["input_hex"] == b"PAYLOAD".hex()


def test_proof_ready_memory_selector_prioritizes_reachable_packs_before_target_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack_pack = _pack("demo:0x1010:main:24:strcpy:local_48:0:unbounded")
    stack_pack["deterministic_candidate"].update(
        {
            "sink": "strcpy",
            "destination_kind": "stack",
            "capacity_bytes": 44,
            "write_relation": "unbounded",
        }
    )
    stack_pack["entrypoint_derivation"] = {
        "call_path": ["entry", "main", "wrapper", "sink"],
        "entry_reachability": {"path_length": 4},
    }
    global_pack = _pack("demo:0x1020:main:16:strcpy:DAT_404020:0:unbounded")
    global_pack["deterministic_candidate"].update(
        {
            "sink": "strcpy",
            "target_buffer": "DAT_404020",
            "destination_kind": "global",
            "capacity_bytes": 1024,
            "write_relation": "unbounded",
        }
    )
    global_pack["entrypoint_derivation"] = {
        "call_path": ["entry", "main", "sink"],
        "entry_reachability": {"path_length": 3},
        "source_to_sink_trace": {
            "status": "complete",
            "confidence": "proven",
            "attacker_control_reaches_sink_role": True,
            "blockers": [],
        },
    }
    blocked_pack = _pack("demo:0x1000:main:10:strcpy:DAT_404000:0:unbounded")
    blocked_pack["deterministic_candidate"].update(
        {
            "sink": "strcpy",
            "target_buffer": "DAT_404000",
            "destination_kind": "global",
            "capacity_bytes": 32,
            "write_relation": "unbounded",
        }
    )
    blocked_pack["entrypoint_derivation"] = {
        "call_path": ["entry"],
        "entry_reachability": {"path_length": 1},
        "source_to_sink_trace": {
            "status": "blocked",
            "confidence": "blocked",
            "attacker_control_reaches_sink_role": False,
            "blockers": ["no_controlled_sink_role"],
        },
    }
    evidence_dir = _write_pack_dir_many(tmp_path, [blocked_pack, stack_pack, global_pack])
    output_dir = tmp_path / "concolic"
    seen: list[str] = []

    def fake_angr_backend(request, evidence_pack):
        seen.append(request.candidate_id)
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="path_unsat",
            backend=request.backend,
            request=request.to_dict(),
        )

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=output_dir,
        target_selector="proof_ready_memory",
        target_limit=1,
        continue_on_error=True,
    )

    assert result.written_count == 1
    assert seen == [global_pack["candidate_id"]]


def test_pcode_trace_request_and_unsupported_shape(tmp_path: Path) -> None:
    pack = _pack()
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="function_harness", symbolic_bytes=32)
    trace_request = build_pcode_trace_request(pack, request, output_path=tmp_path / "pcode_trace.json")

    assert trace_request.candidate_id == pack["candidate_id"]
    assert trace_request.function_address == "0x1000"
    assert trace_request.target_address == "0x1010"

    unsupported = unsupported_pcode_trace(pack["candidate_id"], "unit_test", request=trace_request)
    assert unsupported["status"] == "unsupported"
    assert unsupported["unsupported"] is True
    assert unsupported["pcode_ops"] == []


def test_process_pcode_trace_requires_entry_replay_for_exact_sink(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="argv", symbolic_bytes=32)

    payload = concolic_module._annotate_pcode_sink_trace(
        pack,
        request,
        {
            "status": "stopped",
            "target_address": "0x1010",
            "exact_sink_resolution": {"resolved": True, "exact_sink_address": "0x1010"},
            "replay": {"status": "stopped"},
            "exact_sink_replay": {"status": "reached"},
        },
    )

    sink_trace = payload["sink_trace"]
    assert sink_trace["exact_sink_reached"] is False
    assert sink_trace["local_exact_sink_replayed"] is True
    assert sink_trace["reason"] == "pcode_replay_did_not_reach_exact_sink"
    assert concolic_module._has_exact_pcode_sink_trace(payload) is False


def test_process_pcode_trace_request_starts_at_derived_entrypoint(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("stdin")
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="stdin", symbolic_bytes=32)

    trace_request = build_pcode_trace_request(pack, request, output_path=tmp_path / "pcode_trace.json")

    assert trace_request.start_address == "0x800"
    assert trace_request.function_address == "0x1000"
    assert trace_request.target_address == "0x1010"


def test_process_pcode_trace_allows_resolved_exact_sink_address(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    request = ConcolicRequest(
        candidate_id=pack["candidate_id"],
        binary_path=_binary(tmp_path),
        backend="angr",
        target_address="0x1011f6",
        sink_address="0x1011f6",
        input_model="argv",
        symbolic_bytes=32,
        target_resolution={
            "status": "derived",
            "target_address": "0x1011f6",
            "sink_address": "0x1011f6",
            "callsite_address": "0x1011f6",
            "function_address": "0x1000",
        },
    )

    trace_request = build_pcode_trace_request(pack, request, output_path=tmp_path / "pcode_trace.json")

    assert trace_request.start_address == "0x800"
    assert trace_request.target_address == "0x1011f6"


def test_process_pcode_trace_request_blocks_without_entrypoint(tmp_path: Path) -> None:
    pack = _pack()
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="stdin", symbolic_bytes=32)

    with pytest.raises(ValueError, match="requires a derived entrypoint start address"):
        build_pcode_trace_request(pack, request, output_path=tmp_path / "pcode_trace.json")


def test_process_dynamic_proof_request_starts_at_derived_entrypoint(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("stdin")
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="stdin", symbolic_bytes=32)
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model="stdin", stdin=b"A" * 32),
    )

    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "ghidra_dynamic_proof.json",
    )

    assert proof_request.start_address == "0x800"
    assert proof_request.function_address == "0x1000"
    assert proof_request.sink_address == "0x1010"
    assert proof_request.proof_scope == "process_entrypoint"


def test_env_dynamic_proof_request_uses_declared_environment_key(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("env")
    pack["type_facts"] = {"process_input": {"input_model": "env", "env_key": "HTTP_USER_AGENT"}}
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="env", symbolic_bytes=32)
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="timeout",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model="env", env={"HTTP_USER_AGENT": b"A" * 32}),
    )

    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "ghidra_dynamic_proof.json",
    )

    assert proof_request.env_name == "HTTP_USER_AGENT"
    assert proof_request.process_input_evidence["env_name"] == "HTTP_USER_AGENT"


def test_candidate_local_env_selected_file_becomes_compound_proof_input(tmp_path: Path) -> None:
    sources = {
        "main.c": 'void main(void) { char *q = getenv("QUOTING_STYLE"); open_patch(DAT_0013c448); target(); }\n',
        "target.c": """
void target(void) {
  char *dir = getenv("CHARSETALIASDIR");
  size_t n = strlen("charset.alias");
  memcpy(path, "charset.alias", n + 1);
  int fd = open(path, 0);
  FILE *stream = fdopen(fd, "r");
  __isoc23_fscanf(stream, "%50s %50s", first, second);
  strcpy(dst, second);
}
""",
        "parser.c": """
void parser(void) {
  int option = getopt_long(argc, argv, "i:", options, 0);
  switch (option) { case 0x69: DAT_0013c448 = copy(optarg); break; default: break; }
}
""",
        "open_patch.c": 'void open_patch(char *param_1) { FILE *f = fopen(param_1, "r"); error("Can\'t open patch file %s", param_1); }\n',
    }
    records = [
        replace(_function_record("main", "0x1000"), relative_path="main.c", source_exists=True),
        replace(_function_record("target", "0x1200"), relative_path="target.c", source_exists=True),
        replace(_function_record("parser", "0x1300"), relative_path="parser.c", source_exists=True),
        replace(_function_record("open_patch", "0x1400"), relative_path="open_patch.c", source_exists=True),
    ]
    export_dir = _write_minimal_export(tmp_path, records)
    for name, text in sources.items():
        (export_dir / name).write_text(text)
    pack = _pack_with_entrypoint("env")
    pack["export_dir"] = str(export_dir)
    pack["deterministic_candidate"].update(
        {"function_name": "target", "address": "0x1200", "operation_address": "0x1210"}
    )
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": "0x1210"}]
    pack["facts_available_to_llm"]["pcode_slice"] = {"operation_address": "0x1210"}
    static_candidate = dict(pack["deterministic_candidate"])
    static_candidate["classification_trace"] = {
        "source_to_write": {
            "roles": {
                "write_source": {
                    "classification": "source_controlled",
                    "evidence": ["source_call:fscanf:line 7"],
                }
            }
        }
    }
    pack["type_facts"] = {"static_candidate": static_candidate}
    entrypoint = pack["entrypoint_derivation"]
    entrypoint.update({"target_function": "target", "target_address": "0x1200", "call_path": ["main", "target"]})
    pack["facts_available_to_llm"]["entrypoint_derivation"] = entrypoint

    spec = concolic_module._env_selected_file_input_spec(pack)
    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        export_dir=export_dir,
        target_address="0x1210",
        sink_address="0x1210",
        symbolic_bytes=128,
    )
    witness = concolic_module._witness_for_input("env_file", b"A B\n", evidence_pack=pack)
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="timeout",
        backend=request.backend,
        request=request.to_dict(),
        witness=witness,
    )
    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "ghidra_dynamic_proof.json",
    )

    assert request.input_model == "env_file"
    assert bytes.fromhex(spec["seed_hex"]) == (b"A" * 50) + b" " + (b"B" * 50) + b"\n"
    assert spec["env_values"] == {"CHARSETALIASDIR": ".", "QUOTING_STYLE": "locale"}
    assert spec["argv_values"] == ["program", "-i", "/__binary_agent_missing_input__"]
    assert witness.file_inputs == {"charset.alias": b"A B\n"}
    assert witness.env["CHARSETALIASDIR"] == b"."
    assert witness.argv == (b"-i", b"/__binary_agent_missing_input__")
    assert proof_request.env_values == {"CHARSETALIASDIR": ".", "QUOTING_STYLE": "locale"}
    assert proof_request.file_name == "charset.alias"
    assert proof_request.argv_values == ("program", "-i", "/__binary_agent_missing_input__")


def test_env_selected_file_requires_candidate_local_stream_source() -> None:
    pack = _pack_with_entrypoint("env")
    pack["deterministic_candidate"]["classification_trace"] = {
        "source_to_write": {
            "roles": {
                "write_source": {
                    "classification": "source_controlled",
                    "evidence": ["source_call:getenv"],
                }
            }
        }
    }

    assert concolic_module._env_selected_file_input_spec(pack) == {}


def test_oob_read_dynamic_proof_request_carries_read_metadata(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("stdin")
    candidate = pack["deterministic_candidate"]
    candidate.update(
        {
            "kind": "source_read",
            "sink": "memcpy_source_read",
            "vulnerability_type": "out_of_bounds_read",
            "write_relation": "symbolic_read_offset",
            "target_buffer": "src",
            "destination_kind": "stack",
            "capacity_bytes": 8,
            "write_size_bytes": 4,
            "offset_expr": "12",
            "line_text": "memcpy(dst, src + 12, 4);",
        }
    )
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="stdin", symbolic_bytes=32)
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model="stdin", stdin=b"A" * 32),
    )

    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "ghidra_dynamic_proof.json",
    )

    assert proof_request.vulnerability_type == "out_of_bounds_read"
    assert proof_request.write_relation == "symbolic_read_offset"
    assert proof_request.offset_expr == "12"
    assert proof_request.write_size_bytes == 4


def test_cursor_limit_read_uses_function_harness_and_concrete_bounds(tmp_path: Path) -> None:
    pack = _pack("demo:0x1200:from_header:12:cursor_limit_read:param_1_0_param_2:param_2:1")
    pack["deterministic_candidate"].update(
        {
            "address": "0x1200",
            "operation_address": "",
            "kind": "source_read",
            "sink": "cursor_limit_read",
            "vulnerability_type": "out_of_bounds_read",
            "write_relation": "symbolic_read_offset",
            "target_buffer": "param_1[0:param_2]",
            "destination_kind": "source_buffer",
            "capacity_bytes": 0,
            "capacity_source": "function_length_argument",
            "capacity_basis": "cursor limit local_20 = param_1 + param_2",
            "capacity_model": {
                "fixed_bytes": None,
                "symbolic_expr": "param_2",
                "source": "function_length_argument",
                "trust": "symbolic",
            },
            "offset_expr": "param_2",
            "write_size_bytes": 1,
            "classification_trace": {
                "cursor_limit_read": {
                    "cursor": "local_18",
                    "limit": "local_20",
                    "base_param": "param_1",
                    "length_param": "param_2",
                },
                "replay_hints": {"mode": "function_harness"},
                "function_harness": {
                    "function_address": "0x1200",
                    "arg_count": 7,
                    "input_address": 0x70000000,
                    "input_arg_index": 0,
                    "length_arg": True,
                    "length_arg_index": 1,
                    "constant_args": {"2": 0, "3": 0, "4": 0, "5": 0, "6": 0},
                },
                "dynamic_proof": {
                    "capacity_from_concrete_input": True,
                    "offset_from_concrete_input": True,
                },
            },
        }
    )
    pack["proof_obligation"]["relation"] = "symbolic_read_offset"
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), symbolic_bytes=16)
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model="function_harness", solver_model={"symbolic_buffer_hex": "20" * 15 + "80"}),
    )

    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "ghidra_dynamic_proof.json",
    )

    assert request.input_model == "function_harness"
    assert request.seed_mutations[0].startswith("hex:")
    assert request.seed_mutations[0].endswith("80")
    assert proof_request.proof_scope == "function_harness"
    assert proof_request.function_harness["length_arg_index"] == 1
    assert proof_request.capacity_bytes == 16
    assert proof_request.offset_expr == "16"
    assert proof_request.to_dict()["function_harness"]["arg_count"] == 7


def test_local_memory_proof_defaults_to_function_harness_with_seed(tmp_path: Path) -> None:
    pack = _pack("demo:0x1200:join:8:strcpy:buf:0:unbounded")
    pack["deterministic_candidate"].update(
        {
            "address": "0x1200",
            "operation_address": "0x1230",
            "function_name": "join",
            "sink": "strcpy",
            "target_buffer": "buf",
            "destination_kind": "heap",
            "vulnerability_type": "heap_overflow",
            "capacity_bytes": 0,
            "write_relation": "unbounded",
            "verdict": "unbounded",
        }
    )
    pack["facts_available_to_llm"]["reproducer_hypothesis"] = {
        "input_surface": "environment",
        "allowed_stubs": ["strcpy"],
    }
    pack["proof_obligation"]["relation"] = "unbounded"

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), symbolic_bytes=32)

    assert request.input_model == "function_harness"
    assert request.seed_mutations == ("hex:" + (b"A" * 32).hex(),)


def test_derived_process_input_wins_over_inferred_memory_function_harness(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("env")
    pack["deterministic_candidate"].update(
        {
            "destination_kind": "heap",
            "capacity_bytes": 0,
            "write_relation": "unbounded",
            "verdict": "unbounded",
        }
    )

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), symbolic_bytes=32)

    assert request.input_model == "env"


def test_seeded_process_result_is_reused_when_backend_has_no_new_witness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _pack_with_entrypoint("env")
    proof_requests = []

    def fake_dynamic_proof(proof_request):
        proof_requests.append(proof_request)
        return {
            "status": "sink_unreached",
            "reason": "exact_sink_not_reached",
            "proof_scope": "process_entrypoint",
            "sink_reached": False,
            "exact_sink_reached": False,
            "sink_address": proof_request.sink_address,
            "process_replay": {"status": "stopped", "reached_target": False},
            "local_sink_probe": {"status": "not_run", "reached_target": False},
        }

    def fake_angr(request, _evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="timeout",
            backend=request.backend,
            request=request.to_dict(),
            rationale="bounded exploration exhausted",
        )

    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr)
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), symbolic_bytes=32)

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / "artifacts",
    )

    assert len(proof_requests) == 1
    assert verdict.verdict == "timeout"
    assert verdict.witness is not None
    assert verdict.ghidra_dynamic_proof["status"] == "sink_unreached"
    assert len(verdict.ghidra_dynamic_proof["hybrid_witness_attempts"]) == 1


def test_function_harness_spec_uses_all_controlled_parameter_args() -> None:
    pack = _pack("demo:0x1200:join:8:strcpy:buf:n:unbounded")
    pack["deterministic_candidate"].update(
        {
            "address": "0x1200",
            "function_name": "join",
            "sink": "strcpy",
            "destination_kind": "heap",
            "vulnerability_type": "heap_overflow",
            "write_relation": "unbounded",
            "verdict": "unbounded",
        }
    )
    pack["facts_available_to_llm"]["source_to_sink_trace"] = {
        "argument_roles": [
            {"role": "write_source", "expr": "param_1", "classification": "parameter_controlled"},
            {
                "role": "destination_pointer",
                "expr": "local_20 + local_24",
                "classification": "parameter_controlled",
                "evidence": ["parameter:param_1", "parameter:param_2"],
            },
        ]
    }

    spec = concolic_module._function_harness_spec(pack)

    assert spec["arg_count"] == 2
    assert spec["input_address"] == 0x71000000
    assert spec["input_arg_index"] == 0
    assert spec["input_arg_indices"] == [0, 1]
    assert spec["constant_args"] == {}


def test_cursor_limit_objdump_sink_parser_returns_post_marker_load() -> None:
    disassembly = """
  41fb70: 0f b6 00              movzx  eax,BYTE PTR [rax]
  41fb73: 3c 80                 cmp    al,0x80
  41fb7b: 0f b6 00              movzx  eax,BYTE PTR [rax]
  41fb7e: 3c ff                 cmp    al,0xff
  41fb8a: 0f b6 00              movzx  eax,BYTE PTR [rax]
  41fba5: 48 8b 45 f0           mov    rax,QWORD PTR [rbp-0x10]
  41fbad: 48 89 55 f0           mov    QWORD PTR [rbp-0x10],rdx
  41fbb1: 0f b6 00              movzx  eax,BYTE PTR [rax]
  41fbce: 48 8b 45 f0           mov    rax,QWORD PTR [rbp-0x10]
  41fbd2: 48 8d 50 01           lea    rdx,[rax+0x1]
  41fbda: 0f b6 00              movzx  eax,BYTE PTR [rax]
"""

    assert concolic_module._cursor_limit_sink_from_objdump(disassembly) == "0x41fbda"


def test_dynamic_proof_request_can_start_from_recorded_entry_surface_when_callgraph_blocked(tmp_path: Path) -> None:
    pack = _pack("demo:0x1200:parse:24:memcpy_source_read:local_20:0:n")
    pack["deterministic_candidate"].update(
        {
            "address": "0x1200",
            "operation_address": "",
            "kind": "source_read",
            "sink": "memcpy_source_read",
            "vulnerability_type": "out_of_bounds_read",
            "write_relation": "symbolic_size",
            "target_buffer": "local_20[1:]",
            "destination_kind": "stack",
            "capacity_bytes": 7,
            "write_size_expr": "n",
        }
    )
    pack["entrypoint_derivation"] = {
        "status": "blocked",
        "input_model": "",
        "process_input_supported": False,
        "blockers": ["target_not_reachable_from_explicit_entry_surface"],
        "evidence": {
            "entry_surfaces": [
                {"function": "entry", "address": "0x800", "kind": "program_entry", "evidence": {"symbol": "entry"}},
                {
                    "function": "main",
                    "address": "0x1000",
                    "kind": "program_entry",
                    "evidence": {"source": "__libc_start_main_handoff", "registered_by": "entry"},
                },
            ]
        },
    }
    request = ConcolicRequest(
        candidate_id=pack["candidate_id"],
        binary_path=_binary(tmp_path),
        input_model="file",
        target_address="0x1210",
        sink_address="0x1210",
        target_resolution={"sink_address": "0x1210", "callsite_address": "0x1210"},
    )
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="backend_error",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model="file", file_inputs={"concolic_input": b"A" * 16}),
    )

    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "proof.json",
    )

    assert proof_request.start_address == "0x1000"
    assert proof_request.proof_scope == "process_entrypoint"


def test_argv_optarg_sink_infers_option_argument_process_setup(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    pack["candidate_id"] = "demo:0x1000:main:27:strcpy:DAT_0040c300:0:unbounded"
    candidate = pack["deterministic_candidate"]
    candidate.update(
        {
            "candidate_id": pack["candidate_id"],
            "function_name": "main",
            "address": "0x1000",
            "operation_address": "0x1010",
            "sink": "strcpy",
            "target_buffer": "DAT_0040c300",
            "destination_kind": "global",
            "capacity_bytes": 64,
            "write_size_bytes": 80,
            "line_text": "strcpy(&DAT_0040c300,optarg);",
        }
    )
    entrypoint = pack["entrypoint_derivation"]
    entrypoint.update(
        {
            "source_to_sink_trace": {
                "argument_roles": [
                    {"role": "write_source", "expr": "optarg", "classification": "unknown"},
                ]
            }
        }
    )
    pack["facts_available_to_llm"]["entrypoint_derivation"] = entrypoint
    pack["facts_available_to_llm"]["source_to_sink_trace"] = entrypoint["source_to_sink_trace"]
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": "0x1010"}]
    pack["facts_available_to_llm"].pop("pcode_slice", None)
    export_dir = _write_minimal_export(tmp_path, [_function_record("main", "0x1000", size=0x200)])
    entrypoint["evidence"] = {"export_dir": str(export_dir)}
    pack["facts_available_to_llm"]["entrypoint_derivation"] = entrypoint
    (export_dir / "001000_main.c").write_text(
        """
void main(int argc,char **argv) {
  int optchar;
  fatal("gzip input file required");
  do {
    optchar = getopt_long(argc,argv,"+o:p",&longopts,0);
    switch(optchar) {
    case 0x6f:
      strcpy(&DAT_0040c300,optarg);
      break;
    case 0x70:
      break;
    }
  } while (true);
}
""",
        encoding="utf-8",
    )
    process_input = concolic_module.infer_process_input_fact(pack)
    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        export_dir=export_dir,
        symbolic_bytes=80,
    )
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="timeout",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model=request.input_model, argv=(b"B" * 80,)),
    )

    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "ghidra_dynamic_proof.json",
    )

    assert process_input["input_model"] == "argv"
    assert process_input["argv_values"] == ["program", "-o", "A" * 80]
    assert process_input["process_input_source"] == "inferred_from_optarg_sink"
    assert process_input["process_input_evidence"]["mode_flag"] == "o"
    assert process_input["process_input_evidence"]["argv_seed_reason"] == "optarg_option_argument"
    assert proof_request.input_model == "argv"
    assert proof_request.argv_values == ("program", "-o", "A" * 80)
    assert proof_request.process_input_source == "inferred_from_optarg_sink"
    assert proof_request.process_input_evidence["mode_flag"] == "o"
    assert proof_request.process_input_evidence["argv_seed_reason"] == "optarg_option_argument"


def test_process_dynamic_proof_rejects_function_entry_as_exact_sink(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    candidate = pack["deterministic_candidate"]
    candidate["operation_address"] = candidate["address"]
    candidate["sink"] = "fgets"
    candidate["kind"] = "interprocedural_call"
    facts = pack["facts_available_to_llm"]
    facts["write_table"] = [{"operation_address": candidate["address"]}]
    facts.pop("pcode_slice", None)
    with pytest.raises(ValueError, match="distinct from the function entry"):
        build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="argv", symbolic_bytes=32)


def test_interprocedural_wrapper_resolves_exact_sink_callsite(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    pack["candidate_id"] = "demo:0x101000:main:301:fgets:local_848:0:0x800"
    candidate = pack["deterministic_candidate"]
    candidate.update(
        {
            "candidate_id": pack["candidate_id"],
            "function_name": "main",
            "address": "0x101000",
            "operation_address": "0x101000",
            "kind": "interprocedural_call",
            "sink": "fgets",
            "target_buffer": "local_848",
            "destination_kind": "stack",
            "capacity_bytes": 16,
            "write_size_bytes": 0x800,
            "line_text": "pcVar18 = (char *)FUN_00102000(local_848);",
        }
    )
    entrypoint = pack["entrypoint_derivation"]
    entrypoint.update({"entry_address": "0x100800", "target_address": "0x101000"})
    pack["facts_available_to_llm"]["entrypoint_derivation"] = entrypoint
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": "0x101000"}]
    pack["facts_available_to_llm"]["source_to_sink_trace"] = {
        "argument_roles": [
            {
                "role": "write_source",
                "evidence": ["FUN_00102000 calls input source fgets"],
            }
        ],
        "transformations": ["line 12: __s = fgets(param_1,0x800,*(FILE **)stdin);"],
    }
    pack["facts_available_to_llm"].pop("pcode_slice", None)
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record("main", "0x101000", size=0x100),
            _function_record(
                "FUN_00102000",
                "0x102000",
                size=0x80,
                pcode_calls=[
                    {
                        "call_address": "0x102024",
                        "callee": "fgets",
                        "callee_address": "0x103000",
                    }
                ],
            ),
            _function_record("fgets", "0x103000", source_symbol="fgets"),
        ],
    )

    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        export_dir=export_dir,
        input_model="argv",
        symbolic_bytes=32,
    )
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model="argv", argv=(b"A" * 32,)),
    )
    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "ghidra_dynamic_proof.json",
    )

    assert request.target_address == "0x102024"
    assert request.sink_address == "0x102024"
    assert request.target_resolution["target_kind"] == "interprocedural_wrapper_callsite"
    assert request.target_resolution["wrapper_chain"] == ["FUN_00102000"]
    assert proof_request.sink_address == "0x102024"
    assert proof_request.start_address == "0x100800"


def test_argv_file_stdin_process_model_is_derived_for_file_backed_fgets_wrapper(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    pack["candidate_id"] = "demo:0x101000:main:301:fgets:local_848:0:0x800"
    candidate = pack["deterministic_candidate"]
    candidate.update(
        {
            "candidate_id": pack["candidate_id"],
            "function_name": "main",
            "address": "0x101000",
            "operation_address": "0x101000",
            "kind": "interprocedural_call",
            "sink": "fgets",
            "target_buffer": "local_848",
            "destination_kind": "stack",
            "capacity_bytes": 16,
            "write_size_bytes": 0x800,
            "line_text": "pcVar18 = (char *)FUN_00102000(local_848);",
        }
    )
    entrypoint = pack["entrypoint_derivation"]
    entrypoint.update({"entry_address": "0x100800", "target_address": "0x101000"})
    pack["facts_available_to_llm"]["entrypoint_derivation"] = entrypoint
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": "0x101000"}]
    pack["facts_available_to_llm"]["source_to_sink_trace"] = {
        "argument_roles": [
            {
                "role": "write_source",
                "evidence": ["FUN_00102000 calls input source fgets"],
            }
        ],
        "transformations": [
            "line 12: __s = fgets(param_1,0x800,*(FILE **)stdin);",
            "line 599: sVar19 = fread(&local_868,0x1a,1,DAT_001115a0);",
            "line 200: pFVar22 = fopen64(pcVar18,\"r\");",
        ],
    }
    pack["facts_available_to_llm"]["process_input"] = {
        "argv_values": ["program", "--edit", "archive.dat"],
        "file_name": "archive.dat",
        "file_input_hex": "46494c45534545440a",
    }
    pack["facts_available_to_llm"].pop("pcode_slice", None)
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record("main", "0x101000", size=0x100),
            _function_record(
                "FUN_00102000",
                "0x102000",
                size=0x80,
                pcode_calls=[
                    {
                        "call_address": "0x102024",
                        "callee": "fgets",
                        "callee_address": "0x103000",
                    }
                ],
            ),
            _function_record("fgets", "0x103000", source_symbol="fgets"),
        ],
    )

    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        export_dir=export_dir,
        symbolic_bytes=32,
    )
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model=request.input_model, stdin=b"A" * 32),
    )
    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "ghidra_dynamic_proof.json",
    )

    assert request.input_model == "argv_file_stdin"
    assert proof_request.input_model == "argv_file_stdin"
    assert proof_request.argv_values == ("program", "--edit", "archive.dat")
    assert proof_request.stdin_input_hex == "41" * 32
    assert proof_request.file_name == "archive.dat"
    assert bytes.fromhex(proof_request.file_input_hex) == b"FILESEED\n"


def test_argv_file_stdin_missing_file_seed_blocks_process_proof(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    candidate = pack["deterministic_candidate"]
    candidate.update(
        {
            "kind": "call",
            "sink": "fgets",
            "operation_address": "0x1010",
            "target_buffer": "local_848",
            "destination_kind": "stack",
            "capacity_bytes": 16,
            "write_size_bytes": 0x800,
        }
    )
    pack["facts_available_to_llm"]["source_to_sink_trace"] = {
        "argument_roles": [{"role": "write_source", "evidence": ["FUN_00102000 calls input source fgets"]}],
        "transformations": [
            "line 12: __s = fgets(param_1,0x800,*(FILE **)stdin);",
            "line 599: sVar19 = fread(&local_868,0x1a,1,DAT_001115a0);",
            "line 200: pFVar22 = fopen64(pcVar18,\"r\");",
        ],
    }

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), symbolic_bytes=32)
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model=request.input_model, stdin=b"A" * 32),
    )
    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "ghidra_dynamic_proof.json",
    )
    proof = concolic_module.run_ghidra_dynamic_overflow_proof(proof_request)

    assert request.input_model == "argv_file_stdin"
    assert proof_request.file_input_hex == ""
    assert proof_request.process_input_setup_reason == "unsupported_process_input_setup:missing_file_input_hex"
    assert proof["status"] == "unsupported"
    assert proof["reason"] == "unsupported_process_input_setup:missing_file_input_hex"
    assert proof["process_input_setup"]["status"] == "unsupported"
    assert proof["process_input_setup"]["process_input_source"] == "missing_process_input_fact"


def test_argv_file_stdin_process_input_is_inferred_from_entry_decompile(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    pack["candidate_id"] = "demo:0x101000:main:301:fgets:local_848:0:0x800"
    candidate = pack["deterministic_candidate"]
    candidate.update(
        {
            "candidate_id": pack["candidate_id"],
            "function_name": "main",
            "address": "0x101000",
            "operation_address": "0x101000",
            "kind": "interprocedural_call",
            "sink": "fgets",
            "target_buffer": "local_848",
            "destination_kind": "stack",
            "capacity_bytes": 16,
            "write_size_bytes": 0x800,
            "line_text": "pcVar18 = (char *)FUN_00102000(local_848);",
        }
    )
    entrypoint = pack["entrypoint_derivation"]
    entrypoint.update({"entry_address": "0x100800", "entry_function": "main", "target_address": "0x101000"})
    pack["facts_available_to_llm"]["entrypoint_derivation"] = entrypoint
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": "0x101000"}]
    pack["facts_available_to_llm"]["source_to_sink_trace"] = {
        "argument_roles": [
            {
                "role": "write_source",
                "evidence": ["FUN_00102000 calls input source fgets"],
            }
        ],
        "transformations": [
            "line 12: __s = fgets(param_1,0x800,*(FILE **)stdin);",
            "line 599: sVar19 = fread(&local_868,0x1a,1,DAT_001115a0);",
            "line 200: pFVar22 = fopen64(pcVar18,\"r\");",
        ],
    }
    pack["facts_available_to_llm"].pop("pcode_slice", None)
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record("main", "0x101000", size=0x100),
            _function_record(
                "FUN_00102000",
                "0x102000",
                size=0x80,
                pcode_calls=[
                    {
                        "call_address": "0x102024",
                        "callee": "fgets",
                        "callee_address": "0x103000",
                    }
                ],
            ),
            _function_record("fgets", "0x103000", source_symbol="fgets"),
        ],
    )
    entrypoint.setdefault("evidence", {})["export_dir"] = str(export_dir)
    (export_dir / "00101000_main.c").write_text(
        """
undefined8 main(int param_1,long param_2)
{
  char cVar1;
  int local_mode;
  stat64 local_848 [14];
  local_mode = 0;
  if (param_1 < 2) {
    fatal("need to specify zip file");
  }
  switch(cVar1) {
  case 'w':
    local_mode = 1;
    break;
  default:
    break;
  }
  if (local_mode == 0) {
    exit(0);
  }
  FUN_00102000(local_848);
}
""".strip()
    )

    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        export_dir=export_dir,
        symbolic_bytes=32,
    )
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model=request.input_model, stdin=b"A" * 32),
    )
    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "ghidra_dynamic_proof.json",
    )

    assert request.input_model == "argv_file_stdin"
    assert proof_request.argv_values == ("program", "-w", "concolic_input.zip")
    assert proof_request.stdin_input_hex == "41" * 32
    assert proof_request.file_name == "concolic_input.zip"
    assert proof_request.process_input_source == "inferred_from_entry_decompile"
    assert proof_request.process_input_evidence["mode_flag"] == "w"
    assert proof_request.process_input_evidence["file_seed_reason"] == "zip_format_text"
    assert proof_request.process_input_evidence["source_path"] == "00101000_main.c"
    with zipfile.ZipFile(io.BytesIO(bytes.fromhex(proof_request.file_input_hex))) as archive:
        assert archive.read("seed.txt") == b"seed\n"


def _pack_for_process_input_inference(tmp_path: Path, decompiled_text: str) -> tuple[dict[str, Any], Path]:
    pack = _pack_with_entrypoint("argv")
    pack["candidate_id"] = "demo:0x101000:main:301:fgets:local_848:0:0x800"
    candidate = pack["deterministic_candidate"]
    candidate.update(
        {
            "candidate_id": pack["candidate_id"],
            "function_name": "main",
            "address": "0x101000",
            "operation_address": "0x101000",
            "kind": "interprocedural_call",
            "sink": "fgets",
            "target_buffer": "local_848",
            "destination_kind": "stack",
            "capacity_bytes": 16,
            "write_size_bytes": 0x800,
            "line_text": "pcVar18 = (char *)FUN_00102000(local_848);",
        }
    )
    entrypoint = pack["entrypoint_derivation"]
    entrypoint.update({"entry_address": "0x100800", "entry_function": "main", "target_address": "0x101000"})
    pack["facts_available_to_llm"]["entrypoint_derivation"] = entrypoint
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": "0x101000"}]
    pack["facts_available_to_llm"]["source_to_sink_trace"] = {
        "argument_roles": [{"role": "write_source", "evidence": ["FUN_00102000 calls input source fgets"]}],
        "transformations": [
            "line 12: __s = fgets(param_1,0x800,*(FILE **)stdin);",
            "line 599: sVar19 = fread(&local_868,0x1a,1,DAT_001115a0);",
            "line 200: pFVar22 = fopen64(pcVar18,\"r\");",
        ],
    }
    pack["facts_available_to_llm"].pop("pcode_slice", None)
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record("main", "0x101000", size=0x100),
            _function_record(
                "FUN_00102000",
                "0x102000",
                size=0x80,
                pcode_calls=[{"call_address": "0x102024", "callee": "fgets", "callee_address": "0x103000"}],
            ),
            _function_record("fgets", "0x103000", source_symbol="fgets"),
        ],
    )
    entrypoint.setdefault("evidence", {})["export_dir"] = str(export_dir)
    (export_dir / "00101000_main.c").write_text(decompiled_text)
    return pack, export_dir


def test_argv_file_stdin_dynamic_proof_runs_before_angr_for_zipnote_style_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack, export_dir = _pack_for_process_input_inference(
        tmp_path,
        """
undefined8 main(int param_1,long param_2)
{
  int local_mode;
  stat64 local_848 [14];
  local_mode = 0;
  switch(param_1) {
  case 'w':
    local_mode = 1;
    break;
  }
  fatal("need zip file");
  if (local_mode == 0) {
    exit(0);
  }
  FUN_00102000(local_848);
}
""".strip(),
    )
    evidence_dir = _write_pack_dir(tmp_path, pack)
    output_dir = tmp_path / "concolic"
    proof_requests = []

    def fail_angr_backend(*_args, **_kwargs):
        raise AssertionError("angr backend should not run before seeded argv_file_stdin proof")

    def fake_dynamic_proof(proof_request):
        proof_requests.append(proof_request)
        return _fake_overflow_proof(proof_request)

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fail_angr_backend)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)

    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=_binary(tmp_path),
        output_dir=output_dir,
        export_dir=export_dir,
        symbolic_bytes=4096,
        ghidra_dynamic_proof=True,
    )
    confirmations = load_candidate_confirmations(output_dir)
    proofs = load_concolic_dynamic_proofs(output_dir)

    assert result.written_count == 1
    assert proof_requests
    proof_request = proof_requests[0]
    assert proof_request.input_model == "argv_file_stdin"
    assert proof_request.argv_values == ("program", "-w", "concolic_input.zip")
    assert len(proof_request.stdin_input_hex) // 2 == 0x800
    assert proof_request.process_input_evidence["file_seed_reason"] == "zip_format_text"
    assert confirmations[pack["candidate_id"]].status == "confirmed_bug"
    assert proofs[pack["candidate_id"]]["status"] == "overflow_proven"
    assert (output_dir / "demo_0x101000_main_301_fgets_local_848_0_0x800" / CONCOLIC_DYNAMIC_PROOF_FILENAME).exists()


@pytest.mark.parametrize(
    ("marker_text", "reason", "file_name"),
    [
        ("fatal(\"need gzip input\"); gzopen(path,\"rb\"); gzread(file,buf,4);", "gzip_format_text", "concolic_input.gz"),
        ("fatal(\"need tar file\"); parse tar archive with ustar header;", "tar_format_text", "concolic_input.tar"),
        ("fatal(\"UNARJ e archive[.arj]\"); error(\"not an ARJ archive\");", "arj_format_filename", "concolic_input.arj"),
        ("fatal(\"need json config\"); json_object_from_file(path);", "json_config_format_text", "concolic_input.json"),
        ("fatal(\"need config file\"); parse key=value entries from .conf;", "text_config_format_text", "concolic_input.conf"),
        ("fatal(\"need script file\"); read line-oriented commands;", "line_script_format_text", "concolic_input.sh"),
    ],
)
def test_process_input_inference_persists_generalized_file_format_seed(
    tmp_path: Path,
    marker_text: str,
    reason: str,
    file_name: str,
) -> None:
    pack, _export_dir = _pack_for_process_input_inference(
        tmp_path,
        f"""
undefined8 main(int param_1,long param_2)
{{
  int local_mode;
  local_mode = 0;
  switch(param_1) {{
  case 'w':
    local_mode = 1;
    break;
  }}
  {marker_text}
  FUN_00102000(local_848);
}}
""".strip(),
    )

    process_input = concolic_module.infer_process_input_fact(pack)

    assert process_input["inferred"] is True
    assert process_input["input_model"] == "argv_file_stdin"
    assert process_input["file_name"] == file_name
    assert process_input["process_input_source"] == "inferred_from_entry_decompile"
    assert process_input["process_input_evidence"]["file_seed_reason"] == reason
    assert process_input["process_input_evidence"]["decompile_source_file"] == "00101000_main.c"
    data = bytes.fromhex(process_input["file_input_hex"])
    if reason == "gzip_format_text":
        assert gzip.decompress(data) == b"seed\n"
    elif reason == "tar_format_text":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            assert archive.extractfile("seed.txt").read() == b"seed\n"  # type: ignore[union-attr]
    elif reason == "arj_format_filename":
        assert process_input["argv_values"] == ["program", "e", "concolic_input.arj"]
        first_size = int.from_bytes(data[2:4], "little")
        second_offset = 4 + first_size + 4 + 2
        second_size = int.from_bytes(data[second_offset + 2 : second_offset + 4], "little")
        second_body = data[second_offset + 4 : second_offset + 4 + second_size]
        second_crc = int.from_bytes(data[second_offset + 4 + second_size : second_offset + 8 + second_size], "little")
        assert data[:2] == b"\x60\xea"
        assert data[second_offset : second_offset + 2] == b"\x60\xea"
        assert zlib.crc32(second_body) & 0xFFFFFFFF == second_crc
        assert second_body[30:541] == b"A" * 511
    elif reason == "json_config_format_text":
        assert json.loads(data.decode("utf-8"))["seed"] == "seed"
    elif reason == "text_config_format_text":
        assert data == b"seed=seed\nname=seed\n"
    else:
        assert data == b"echo seed\n"


def test_structured_file_seed_upgrades_file_backed_memory_sink(tmp_path: Path) -> None:
    pack, _export_dir = _pack_for_process_input_inference(
        tmp_path,
        """
undefined8 main(int param_1,long param_2)
{
  fatal("UNARJ e archive[.arj]");
  error("not an ARJ archive");
  pFVar1 = fopen64(pcVar18,"rb");
  sVar2 = fread(&local_868,0x1a,1,pFVar1);
  FUN_00102000(local_848);
}
""".strip(),
    )
    pack["candidate_id"] = "demo:0x101000:main:301:strcpy:local_848:0:unbounded"
    pack["deterministic_candidate"].update(
        {
            "candidate_id": pack["candidate_id"],
            "sink": "strcpy",
            "operation_address": "0x102024",
            "write_size_bytes": 0,
        }
    )
    pack["facts_available_to_llm"]["write_table"] = [{"operation_address": "0x102024"}]

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), symbolic_bytes=32)
    process_input = concolic_module.infer_process_input_fact(pack)

    assert request.input_model == "argv_file_stdin"
    assert process_input["input_model"] == "argv_file_stdin"
    assert process_input["argv_values"] == ["program", "e", "concolic_input.arj"]
    assert process_input["process_input_evidence"]["file_seed_reason"] == "arj_format_filename"


def test_process_input_inference_prefers_entry_decompile_over_sink_decompile(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    pack["candidate_id"] = "demo:0x1000:FUN_sink:18:strcpy:local_218:0:unbounded"
    pack["deterministic_candidate"].update(
        {
            "candidate_id": pack["candidate_id"],
            "function_name": "FUN_sink",
            "address": "0x1000",
            "operation_address": "0x1000",
            "kind": "call",
            "sink": "strcpy",
            "target_buffer": "local_218",
            "destination_kind": "stack",
            "capacity_bytes": 520,
            "write_size_bytes": 0,
        }
    )
    entrypoint = pack["entrypoint_derivation"]
    entrypoint.update(
        {
            "entry_address": "0x2000",
            "entry_function": "FUN_entry",
            "target_address": "0x1000",
            "target_function": "FUN_sink",
            "call_path": ["FUN_entry", "FUN_sink"],
        }
    )
    export_dir = _write_minimal_export(
        tmp_path,
        [
            _function_record("FUN_sink", "0x1000", size=0x100),
            _function_record("FUN_entry", "0x2000", size=0x100),
        ],
    )
    entrypoint.setdefault("evidence", {})["export_dir"] = str(export_dir)
    (export_dir / "001000_FUN_sink.c").write_text("strcpy(local_218,&DAT_00407560);")
    (export_dir / "002000_FUN_entry.c").write_text(
        """
undefined8 FUN_entry(int argc,char **argv)
{
  fatal("UNARJ e archive[.arj]");
  error("not an ARJ archive");
  FUN_sink();
}
""".strip()
    )

    process_input = concolic_module.infer_process_input_fact(pack)

    assert process_input["file_name"] == "concolic_input.arj"
    assert process_input["argv_values"] == ["program", "e", "concolic_input.arj"]
    assert process_input["process_input_evidence"]["decompile_source_file"] == "002000_FUN_entry.c"


def test_seeded_process_file_gets_bounded_dynamic_attempt_after_unsat(tmp_path: Path) -> None:
    pack, export_dir = _pack_for_process_input_inference(
        tmp_path,
        """
undefined8 main(int param_1,long param_2)
{
  fatal("need to specify zip file");
  fgets(local_848,0x800,stdin);
  FUN_00102000(local_848);
}
""".strip(),
    )
    process_input = concolic_module.infer_process_input_fact(pack)
    pack["facts_available_to_llm"]["process_input"] = process_input
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), export_dir=export_dir, symbolic_bytes=32)
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="path_unsat",
        backend=request.backend,
        request=request.to_dict(),
    )

    attempts = concolic_module._dynamic_proof_verdict_attempts(request, pack, verdict)

    assert len(attempts) == 1
    attempt_verdict, attempt = attempts[0]
    assert attempt["source"] == "deterministic_overflow_pattern"
    assert attempt_verdict.witness is not None
    assert attempt_verdict.witness.input_model == "argv_file_stdin"
    assert "concolic_input.zip" in attempt_verdict.witness.file_inputs


def test_persisted_process_input_fact_drives_dynamic_proof_without_decompile(tmp_path: Path) -> None:
    pack, export_dir = _pack_for_process_input_inference(
        tmp_path,
        """
undefined8 main(int param_1,long param_2)
{
  int local_mode;
  local_mode = 0;
  switch(param_1) {
  case 'w':
    local_mode = 1;
    break;
  }
  fatal("need to specify zip file");
  FUN_00102000(local_848);
}
""".strip(),
    )
    process_input = concolic_module.infer_process_input_fact(pack)
    pack.setdefault("type_facts", {})["process_input"] = process_input
    pack["facts_available_to_llm"]["process_input"] = process_input
    (export_dir / "00101000_main.c").unlink()

    request = build_concolic_request(pack, binary_path=_binary(tmp_path), export_dir=export_dir, symbolic_bytes=32)
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model=request.input_model, stdin=b"A" * 32),
    )
    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "ghidra_dynamic_proof.json",
    )

    assert proof_request.process_input_source == "inferred_from_entry_decompile"
    assert proof_request.process_input_evidence["file_seed_reason"] == "zip_format_text"
    assert proof_request.process_input_evidence["decompile_source_file"] == "00101000_main.c"
    with zipfile.ZipFile(io.BytesIO(bytes.fromhex(proof_request.file_input_hex))) as archive:
        assert archive.read("seed.txt") == b"seed\n"


def test_cached_process_input_fact_uses_stable_decompile_source_file(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    pack["type_facts"] = {}
    pack["type_facts"]["process_input"] = {
        "input_model": "argv_file_stdin",
        "argv_values": ["program", "concolic_input.zip"],
        "file_name": "concolic_input.zip",
        "file_input_hex": "504b0304",
        "process_input_source": "inferred_from_entry_decompile",
        "process_input_evidence": {
            "source_path": "/old/run/decompiled/00101000_main.c",
            "decompile_source_file": "/old/run/decompiled/00101000_main.c",
            "file_seed_reason": "zip_format_text",
        },
        "inferred": True,
    }

    spec = concolic_module._combined_process_input_spec(pack)

    assert spec["process_input_evidence"]["source_path"] == "00101000_main.c"
    assert spec["process_input_evidence"]["decompile_source_file"] == "00101000_main.c"


def test_file_format_seed_does_not_replace_direct_argv_sink_source(tmp_path: Path) -> None:
    pack, export_dir = _pack_for_process_input_inference(
        tmp_path,
        """
undefined8 main(int argc,char **argv)
{
  fatal("gzip compressed data");
  FUN_00102000(argv[1]);
}
""".strip(),
    )
    pack["candidate_id"] = "demo:0x102000:FUN_00102000:16:strcpy:DAT_0045ed00:0:unbounded"
    candidate = pack["deterministic_candidate"]
    candidate.update(
        {
            "candidate_id": pack["candidate_id"],
            "function_name": "FUN_00102000",
            "address": "0x102000",
            "operation_address": "0x102010",
            "kind": "call",
            "sink": "strcpy",
            "target_buffer": "DAT_0045ed00",
            "destination_kind": "global",
            "capacity_bytes": 1024,
        }
    )
    entrypoint = pack["entrypoint_derivation"]
    entrypoint["source_to_sink_trace"] = {
        "argument_roles": [
            {
                "role": "write_source",
                "classification": "parameter_controlled",
                "expr": "param_1",
                "evidence": ["parameter:param_1"],
            }
        ],
        "evidence": {"input_observations": [{"input_model": "argv"}]},
    }
    pack["facts_available_to_llm"]["entrypoint_derivation"] = entrypoint
    pack["facts_available_to_llm"]["source_to_sink_trace"] = entrypoint["source_to_sink_trace"]

    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        export_dir=export_dir,
        symbolic_bytes=1025,
    )

    assert request.input_model == "argv"
    assert concolic_module.infer_process_input_fact(pack) == {}


def test_argv_absolute_path_guard_adds_deterministic_seed(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    pack["candidate_id"] = "demo:0x101000:main:42:strcpy:local_428:0:unbounded"
    candidate = pack["deterministic_candidate"]
    candidate.update(
        {
            "candidate_id": pack["candidate_id"],
            "function_name": "main",
            "address": "0x101000",
            "operation_address": "0x101040",
            "sink": "strcpy",
            "target_buffer": "local_428",
            "capacity_bytes": 1024,
            "line_number": 8,
            "line_text": "strcpy(local_428,(char *)param_2[optind]);",
            "relative_path": "00101000_main.c",
        }
    )
    export_dir = _write_minimal_export(tmp_path, [_function_record("main", "0x101000", size=0x100)])
    (export_dir / "00101000_main.c").write_text(
        """
void main(int param_1,undefined8 *param_2)
{
  if (optind < param_1) {
    if (*(char *)param_2[optind] == '/') {
      strcpy(local_428,(char *)param_2[optind]);
    }
  }
}
""".strip()
    )
    pack["entrypoint_derivation"].setdefault("evidence", {})["export_dir"] = str(export_dir)
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), export_dir=export_dir, symbolic_bytes=2048)

    candidates = concolic_module._hybrid_witness_candidates(request, pack)

    assert candidates[0]["source"] == "argv_absolute_path_guard"
    assert candidates[0]["bytes"].startswith(b"/")
    assert len(candidates[0]["bytes"]) == 1025


def test_argv_absolute_path_guard_uses_trace_source_when_candidate_line_is_missing(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    pack["candidate_id"] = "demo:0x101000:main:42:strcpy:local_428:0:unbounded"
    candidate = pack["deterministic_candidate"]
    candidate.update(
        {
            "candidate_id": pack["candidate_id"],
            "function_name": "main",
            "address": "0x101000",
            "operation_address": "0x101040",
            "sink": "strcpy",
            "target_buffer": "local_428",
            "capacity_bytes": 1024,
            "line_number": 8,
            "relative_path": "00101000_main.c",
        }
    )
    pack["entrypoint_derivation"]["source_to_sink_trace"] = {
        "argument_roles": [{"role": "write_source", "expr": "param_2[optind]"}],
        "input_observations": [{"input_model": "argv"}],
    }
    export_dir = _write_minimal_export(tmp_path, [_function_record("main", "0x101000", size=0x100)])
    (export_dir / "00101000_main.c").write_text(
        """
void main(int param_1,undefined8 *param_2)
{
  if (optind < param_1) {
    if (*(char *)param_2[optind] == '/') {
      strcpy(local_428,(char *)param_2[optind]);
    }
  }
}
""".strip()
    )
    pack["entrypoint_derivation"].setdefault("evidence", {})["export_dir"] = str(export_dir)
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), export_dir=export_dir, symbolic_bytes=2048)

    candidates = concolic_module._hybrid_witness_candidates(request, pack)

    assert candidates[0]["source"] == "argv_absolute_path_guard"
    assert candidates[0]["bytes"].startswith(b"/")
    assert len(candidates[0]["bytes"]) == 1025


def test_ambiguous_process_file_format_is_explicitly_unsupported(tmp_path: Path) -> None:
    pack, _export_dir = _pack_for_process_input_inference(
        tmp_path,
        """
undefined8 main(int param_1,long param_2)
{
  switch(param_1) {
  case 'w':
    local_mode = 1;
    break;
  }
  fatal("input may be a zip file or tar archive");
  if (local_mode == 0) {
    exit(0);
  }
  fgets(local_848,0x800,stdin);
  FUN_00102000(local_848);
}
""".strip(),
    )

    process_input = concolic_module.infer_process_input_fact(pack)

    assert process_input["file_input_hex"] == ""
    assert process_input["unsupported_reason"] == "unsupported_process_input_setup:ambiguous_file_format"
    assert process_input["process_input_evidence"]["file_seed_reason"] == "unsupported_ambiguous_file_format"


def test_process_pcode_trace_does_not_treat_function_entry_as_exact_sink(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    candidate = pack["deterministic_candidate"]
    candidate["operation_address"] = candidate["address"]
    candidate["sink"] = "fgets"
    candidate["kind"] = "interprocedural_call"
    facts = pack["facts_available_to_llm"]
    facts["write_table"] = [{"operation_address": candidate["address"]}]
    facts.pop("pcode_slice", None)
    request = ConcolicRequest(
        candidate_id=pack["candidate_id"],
        binary_path=_binary(tmp_path),
        input_model="argv",
        target_address="0x1000",
        sink_address="0x1000",
    )

    payload = concolic_module._annotate_pcode_sink_trace(
        pack,
        request,
        {
            "status": "reached",
            "target_address": "0x1000",
            "exact_sink_resolution": {"resolved": False, "reason": "candidate_line_not_found"},
            "replay": {"status": "reached"},
        },
    )

    assert payload["sink_trace"]["exact_sink_reached"] is False
    assert payload["sink_trace"]["reason"] == "function_entry_is_not_exact_sink"


def _fake_ghidra_install(tmp_path: Path) -> tuple[Path, Path]:
    ghidra_dir = tmp_path / "ghidra_12.1_PUBLIC"
    support = ghidra_dir / "support"
    support.mkdir(parents=True)
    headless = support / "analyzeHeadless"
    headless.write_text("#!/bin/sh\nexit 0\n")
    headless.chmod(0o755)
    return ghidra_dir, headless


def test_default_ghidra_dir_resolves_path_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ghidra_dir, headless = _fake_ghidra_install(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    wrapper = bin_dir / "analyzeHeadless"
    wrapper.write_text(f"#!/bin/sh\nexec \"{headless}\" \"$@\"\n")
    wrapper.chmod(0o755)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setenv("PATH", str(bin_dir))

    assert concolic_module._resolve_ghidra_dir(None) == ghidra_dir.resolve()


def test_default_ghidra_search_prefers_repo_local_downloads() -> None:
    roots = concolic_module._default_ghidra_search_roots()
    repo_ghidra = Path(concolic_module.__file__).resolve().parents[3] / "ghidra_downloads"

    assert roots[0] == repo_ghidra


def test_ghidra_runner_prefers_pyghidra_for_python_scripts(tmp_path: Path) -> None:
    ghidra_dir, headless = _fake_ghidra_install(tmp_path)
    pyghidra = ghidra_dir / "support" / "pyGhidraRun"
    pyghidra.write_text("#!/bin/sh\nexit 1\n")
    pyghidra.chmod(0o755)

    runner, prefix = concolic_module._resolve_ghidra_runner(ghidra_dir)

    assert runner == pyghidra
    assert prefix == ["-H"]


def test_ghidra_subprocess_env_discovers_local_java_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    java_home = tmp_path / "jdk-21"
    java_bin = java_home / "bin"
    java_bin.mkdir(parents=True)
    java = java_bin / "java"
    java.write_text("#!/bin/sh\nexit 0\n")
    java.chmod(0o755)
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(concolic_module, "_candidate_java_homes", lambda: [java_home])

    env = concolic_module._ghidra_subprocess_env()

    assert env["JAVA_HOME"] == str(java_home)
    assert str(java_bin) in env["PATH"].split(os.pathsep)


def test_objdump_callsite_fallback_preserves_recent_data_references(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Completed:
        stdout = "\n".join(
            [
                "  418733:\tmov    eax,DWORD PTR [rip+0x1dd27]        # 436460 <x>",
                "  41873b:\tlea    rcx,[rip+0x1cd16]        # 435458 <y>",
                "  41874b:\tcall   402410 <strcpy@plt>",
            ]
        )

    monkeypatch.setattr(concolic_module.shutil, "which", lambda _name: "/usr/bin/objdump")
    monkeypatch.setattr(concolic_module.subprocess, "run", lambda *args, **kwargs: Completed())

    callsites = concolic_module._objdump_direct_callsites_to_address(
        tmp_path / "binary",
        function_address="0x4184a4",
        function_size=1124,
        callee_address="0x402410",
    )

    assert callsites == (
        {
            "call_address": "0x41874b",
            "data_references": (0x435458, 0x436460),
        },
    )


def test_dynamic_proof_uses_default_ghidra_dir_when_not_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ghidra_dir, headless = _fake_ghidra_install(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    wrapper = bin_dir / "analyzeHeadless"
    wrapper.write_text(f"#!/bin/sh\nexec \"{headless}\" \"$@\"\n")
    wrapper.chmod(0o755)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setenv("PATH", str(bin_dir))
    pack = _pack_with_entrypoint("argv")

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="overflow_witness",
            backend=request.backend,
            request=request.to_dict(),
            witness=CrashWitness(input_model="argv", argv=(b"A" * 32,)),
            replay_result={"concrete_angr_replay": {"status": "replayed", "input_hex": "41" * 32}},
        )

    def fake_dynamic_proof(proof_request):
        assert proof_request.ghidra_dir == ghidra_dir.resolve()
        return {
            "status": "overflow_proven",
            "proof_scope": "process_entrypoint",
            "sink_reached": True,
            "exact_sink_reached": True,
            "sink_address": "0x1010",
            "write_size_bytes": 32,
            "capacity_bytes": 16,
            "overflow_bytes": 16,
            "process_replay": {"status": "reached", "reached_target": True},
            "local_sink_probe": {"status": "reached", "reached_target": True},
        }

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="argv", symbolic_bytes=32)

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / "artifacts",
    )

    assert verdict.ghidra_dynamic_proof["status"] == "overflow_proven"


def test_process_dynamic_proof_promotes_backend_crash_to_overflow_witness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _pack_with_entrypoint("argv")

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="crash_reproduced",
            backend=request.backend,
            request=request.to_dict(),
            witness=CrashWitness(input_model="argv", argv=(b"A" * 32,)),
            replay_result={"concrete_angr_replay": {"status": "crashed", "input_hex": "41" * 32}},
            rationale="backend crash before exact overflow classification",
        )

    def fake_dynamic_proof(proof_request):
        return {
            "status": "overflow_proven",
            "proof_scope": "process_entrypoint",
            "sink_reached": True,
            "exact_sink_reached": True,
            "sink_address": "0x1010",
            "write_size_bytes": 32,
            "capacity_bytes": 16,
            "overflow_bytes": 16,
            "process_replay": {"status": "reached", "reached_target": True},
            "local_sink_probe": {"status": "reached", "reached_target": True},
        }

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="argv", symbolic_bytes=32)

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / "artifacts",
    )

    assert verdict.verdict == "overflow_witness"
    assert verdict.ghidra_dynamic_proof["status"] == "overflow_proven"
    assert "ghidra_dynamic_proof_promoted_verdict" in verdict.logs


def test_process_dynamic_proof_downgrades_local_only_overflow(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("argv")
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="argv", symbolic_bytes=32)
    proof = {
        "status": "overflow_proven",
        "proof_scope": "process_entrypoint",
        "sink_reached": True,
        "exact_sink_reached": True,
        "sink_address": "0x1010",
        "write_size_bytes": 32,
        "capacity_bytes": 16,
        "overflow_bytes": 16,
        "process_replay": {"status": "stopped", "reached_target": False},
        "local_sink_probe": {"status": "reached", "reached_target": True},
    }

    annotated = concolic_module._annotate_dynamic_overflow_proof(pack, request, proof)

    assert annotated["status"] == "sink_unreached"
    assert annotated["reason"] == "process_replay_did_not_reach_exact_sink"
    assert annotated["exact_sink_reached"] is False
    assert concolic_module._has_dynamic_overflow_proof(annotated) is False


def test_process_dynamic_proof_drives_timeout_verdict_and_records_native_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "native_echo.sh"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    pack = _pack_with_entrypoint("argv")

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="timeout",
            backend=request.backend,
            request=request.to_dict(),
            witness=CrashWitness(input_model="argv", argv=(b"A" * 32,)),
            replay_result={"concrete_angr_replay": {"status": "replayed", "input_model": "argv", "input_hex": "41" * 32}},
            rationale="angr timed out before proving the sink.",
        )

    def fake_dynamic_proof(proof_request):
        assert proof_request.input_model == "argv"
        return {
            "status": "overflow_proven",
            "proof_scope": "process_entrypoint",
            "sink_reached": True,
            "exact_sink_reached": True,
            "sink_address": "0x1010",
            "write_size_bytes": 32,
            "capacity_bytes": 16,
            "overflow_bytes": 16,
            "process_replay": {"status": "reached", "reached_target": True, "process_input_setup": {"status": "configured"}},
            "local_sink_probe": {"status": "reached", "reached_target": True},
        }

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    request = build_concolic_request(pack, binary_path=binary, input_model="argv", symbolic_bytes=32)

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / "artifacts",
    )

    assert verdict.verdict == "overflow_witness"
    assert "Original angr verdict was timeout" in verdict.rationale
    assert verdict.ghidra_dynamic_proof["status"] == "overflow_proven"
    assert verdict.ghidra_dynamic_proof["native_replay"]["status"] == "replayed"
    assert verdict.replay_result["native_replay"]["status"] == "replayed"


def test_native_fortify_abort_refutes_modeled_memory_proof() -> None:
    assert concolic_module._native_replay_refutes_memory_proof(
        {
            "status": "replayed",
            "returncode": -6,
            "stderr_tail": "*** buffer overflow detected ***: terminated",
        }
    )
    assert not concolic_module._native_replay_refutes_memory_proof(
        {"status": "replayed", "returncode": -11, "stderr_tail": ""}
    )


def test_hybrid_witness_generation_uses_seed_after_angr_timeout_without_witness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "native_echo.sh"
    binary.write_text("#!/bin/sh\nprintf '%s' \"$1\"\n")
    binary.chmod(0o755)
    pack = _pack_with_entrypoint("argv")

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="timeout",
            backend=request.backend,
            request=request.to_dict(),
            replay_result={"concrete_angr_replay": {"status": "not_run", "reason": "timeout"}},
            rationale="angr timed out without producing a concrete witness.",
        )

    def fake_dynamic_proof(proof_request):
        assert proof_request.concrete_input_hex.startswith("42424242")
        assert len(bytes.fromhex(proof_request.concrete_input_hex)) == 32
        return {
            "status": "overflow_proven",
            "proof_scope": "process_entrypoint",
            "sink_reached": True,
            "exact_sink_reached": True,
            "sink_address": "0x1010",
            "write_size_bytes": 32,
            "capacity_bytes": 16,
            "overflow_bytes": 16,
            "process_replay": {"status": "reached", "reached_target": True, "process_input_setup": {"status": "configured"}},
            "local_sink_probe": {"status": "reached", "reached_target": True},
        }

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    request = build_concolic_request(
        pack,
        binary_path=binary,
        input_model="argv",
        symbolic_bytes=32,
        seed_mutations=["BBBB"],
    )

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / "artifacts",
    )

    assert verdict.verdict == "overflow_witness"
    assert verdict.witness is not None
    assert verdict.witness.argv[0].startswith(b"BBBB")
    assert verdict.replay_result["hybrid_witness_generation"]["source"] == "seed_mutation:0"
    assert verdict.ghidra_dynamic_proof["hybrid_witness_attempts"][0]["source"] == "seed_mutation:0"
    assert verdict.ghidra_dynamic_proof["native_replay"]["status"] == "replayed"


def test_hybrid_witness_generation_tries_multiple_seeds_until_ghidra_proves(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _pack_with_entrypoint("argv")
    seen_inputs: list[str] = []

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="timeout",
            backend=request.backend,
            request=request.to_dict(),
            rationale="timeout",
        )

    def fake_dynamic_proof(proof_request):
        seen_inputs.append(proof_request.concrete_input_hex)
        if proof_request.concrete_input_hex.startswith("424144"):
            return {
                "status": "sink_unreached",
                "proof_scope": "process_entrypoint",
                "sink_reached": False,
                "exact_sink_reached": False,
                "sink_address": "0x1010",
                "process_replay": {"status": "stopped", "reached_target": False},
                "local_sink_probe": {"status": "reached", "reached_target": True},
            }
        return {
            "status": "overflow_proven",
            "proof_scope": "process_entrypoint",
            "sink_reached": True,
            "exact_sink_reached": True,
            "sink_address": "0x1010",
            "write_size_bytes": 32,
            "capacity_bytes": 16,
            "overflow_bytes": 16,
            "process_replay": {"status": "reached", "reached_target": True, "process_input_setup": {"status": "configured"}},
            "local_sink_probe": {"status": "reached", "reached_target": True},
        }

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        input_model="argv",
        symbolic_bytes=32,
        seed_mutations=["BAD", "GOOD"],
    )

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / "artifacts",
    )

    assert verdict.verdict == "overflow_witness"
    assert len(seen_inputs) == 2
    assert seen_inputs[0].startswith("424144")
    assert seen_inputs[1].startswith("474f4f44")
    assert verdict.witness is not None
    assert verdict.witness.argv[0].startswith(b"GOOD")
    attempts = verdict.ghidra_dynamic_proof["hybrid_witness_attempts"]
    assert [attempt["proof_status"] for attempt in attempts] == ["sink_unreached", "overflow_proven"]


def test_hybrid_witness_generation_checks_path_unsat_with_concrete_seeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _pack_with_entrypoint("argv")

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="path_unsat",
            backend=request.backend,
            request=request.to_dict(),
            rationale="bounded symbolic search refuted the requested path.",
        )

    attempted_inputs: list[str] = []

    def fake_dynamic_proof(proof_request):
        attempted_inputs.append(proof_request.concrete_input_hex)
        return {
            "status": "sink_unreached",
            "reason": "exact_sink_not_reached",
            "proof_scope": "process_entrypoint",
            "process_input_setup": {"status": "configured", "input_model": "argv"},
            "process_replay": {"status": "sink_unreached"},
        }

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    request = build_concolic_request(
        pack,
        binary_path=_binary(tmp_path),
        input_model="argv",
        symbolic_bytes=32,
        seed_mutations=["GOOD"],
    )

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / "artifacts",
    )

    assert verdict.verdict == "path_unsat"
    attempts = verdict.ghidra_dynamic_proof["hybrid_witness_attempts"]
    assert attempted_inputs
    assert attempts[0]["source"] == "seed_mutation:0"
    assert attempts[0]["proof_status"] == "sink_unreached"


def test_process_dynamic_proof_passes_stdin_to_ghidra_instead_of_preblocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _pack_with_entrypoint("stdin")

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="timeout",
            backend=request.backend,
            request=request.to_dict(),
            witness=CrashWitness(input_model="stdin", stdin=b"A" * 32),
            replay_result={"concrete_angr_replay": {"status": "replayed", "input_model": "stdin", "input_hex": "41" * 32}},
        )

    def fake_dynamic_proof(proof_request):
        assert proof_request.input_model == "stdin"
        return {
            "status": "unsupported",
            "proof_scope": "process_entrypoint",
            "reason": "test_stdin_model_reached_ghidra",
            "process_input_setup": {"status": "unsupported", "reason": "test_stdin_model_reached_ghidra"},
            "process_replay": {"status": "unsupported", "reason": "test_stdin_model_reached_ghidra", "reached_target": False},
            "local_sink_probe": {"status": "not_run", "reached_target": False},
        }

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="stdin", symbolic_bytes=32)

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / "artifacts",
    )
    attempt_path = next((tmp_path / "artifacts").rglob(concolic_module.CONCOLIC_PROCESS_WITNESS_ATTEMPT_FILENAME))
    attempt_payload = json.loads(attempt_path.read_text())

    assert verdict.ghidra_dynamic_proof["reason"] == "test_stdin_model_reached_ghidra"
    assert verdict.verdict == "timeout"
    assert attempt_payload["status"] == "unsupported"
    assert attempt_payload["unsupported_count"] == 1
    assert attempt_payload["input_model_counts"] == {"stdin": 1}


def test_stdin_process_topology_carries_explicit_argv_through_witness_and_dynamic_request(tmp_path: Path) -> None:
    pack = _pack_with_entrypoint("stdin")
    pack["type_facts"] = {
        "process_input": {
            "input_model": "stdin",
            "argv_values": ["program", "-R", "-f"],
            "process_input_source": "synthetic_cli_stdin_topology",
            "process_input_evidence": {"option_parser": "getopt", "stdin_reader": "fread"},
        }
    }
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="stdin", symbolic_bytes=8)
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="timeout",
        backend=request.backend,
        request=request.to_dict(),
        witness=concolic_module._witness_for_input("stdin", b"PAYLOAD", evidence_pack=pack),
    )

    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "dynamic.json",
    )

    assert verdict.witness is not None
    assert verdict.witness.argv == (b"-R", b"-f")
    assert proof_request.input_model == "stdin"
    assert proof_request.argv_values == ("program", "-R", "-f")
    assert proof_request.stdin_input_hex == b"PAYLOAD".hex()
    assert proof_request.process_input_source == "synthetic_cli_stdin_topology"


def test_native_stdin_replay_preserves_proof_argv_values(tmp_path: Path) -> None:
    binary = tmp_path / "read_stdin_with_args.sh"
    binary.write_text("#!/bin/sh\nprintf '%s|%s|' \"$1\" \"$2\"\ncat\n")
    binary.chmod(0o755)
    request = build_concolic_request(
        _pack_with_entrypoint("stdin"),
        binary_path=binary,
        input_model="stdin",
        symbolic_bytes=8,
    )
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model="stdin", stdin=b"DATA", argv=(b"-R", b"-f")),
    )
    proof = {
        "status": "overflow_proven",
        "proof_scope": "process_entrypoint",
        "sink_reached": True,
        "exact_sink_reached": True,
        "process_replay": {"status": "reached", "reached_target": True},
        "request": {
            "argv_values": ["program", "-R", "-f"],
            "stdin_input_hex": b"PROOF-DATA".hex(),
        },
    }

    replay = concolic_module._native_process_replay(request, verdict, proof)

    assert replay["status"] == "replayed"
    assert replay["stdout_tail"] == "-R|-f|PROOF-DATA"
    assert replay["input_source"] == "ghidra_process_input_setup"


def test_process_dynamic_proof_passes_file_to_ghidra_and_records_native_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "read_file.sh"
    binary.write_text("#!/bin/sh\ncat \"$1\"\n")
    binary.chmod(0o755)
    pack = _pack_with_entrypoint("file")

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="timeout",
            backend=request.backend,
            request=request.to_dict(),
            witness=CrashWitness(input_model=request.input_model, file_inputs={"concolic_input": b"A" * 32}),
            replay_result={"concrete_angr_replay": {"status": "replayed", "input_hex": "41" * 32}},
        )

    def fake_dynamic_proof(proof_request):
        assert proof_request.input_model == "file"
        assert proof_request.max_steps == 12345
        return {
            "status": "overflow_proven",
            "proof_scope": "process_entrypoint",
            "sink_reached": True,
            "exact_sink_reached": True,
            "sink_address": "0x1010",
            "write_size_bytes": 32,
            "capacity_bytes": 16,
            "overflow_bytes": 16,
            "process_input_setup": {
                "status": "configured",
                "input_model": "file",
                "file_name": "concolic_input",
                "modeled_file_calls": [{"function_model": "fread", "written_bytes": 32}],
            },
            "process_replay": {"status": "reached", "reached_target": True, "process_input_setup": {"status": "configured"}},
            "local_sink_probe": {"status": "reached", "reached_target": True},
        }

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    request = build_concolic_request(pack, binary_path=binary, input_model="file", symbolic_bytes=32)
    artifact_root = tmp_path / "artifacts"
    artifact_dir = concolic_module._artifact_run_dir(artifact_root, request.candidate_id)

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        ghidra_dynamic_max_steps=12345,
        artifact_dir=artifact_dir,
    )

    proof = verdict.ghidra_dynamic_proof
    verdict_path, persisted_verdict = concolic_module._write_concolic_artifacts(
        artifact_root,
        request,
        verdict,
        pcode_trace_enabled=False,
        ghidra_dynamic_proof_enabled=True,
        compatibility_path=artifact_root / "compat.json",
    )
    attempt_path = next(artifact_root.rglob(concolic_module.CONCOLIC_PROCESS_WITNESS_ATTEMPT_FILENAME))
    attempt_payload = json.loads(attempt_path.read_text())
    verdict_payload = json.loads(verdict_path.read_text())
    assert verdict.verdict == "overflow_witness"
    assert proof["status"] == "overflow_proven"
    assert proof["proof_scope"] == "process_entrypoint"
    assert proof["process_input_setup"]["status"] == "configured"
    assert proof["process_witness_attempt_artifact"] == concolic_module.CONCOLIC_PROCESS_WITNESS_ATTEMPT_FILENAME
    assert attempt_payload["artifact_kind"] == "process_witness_attempt"
    assert attempt_payload["status"] == "observed"
    assert attempt_payload["observed_count"] == 1
    assert attempt_payload["attempts"][0]["input_model"] == "file"
    assert attempt_payload["attempts"][0]["dynamic_proof_artifact"] == CONCOLIC_DYNAMIC_PROOF_FILENAME
    assert any(
        path.endswith(concolic_module.CONCOLIC_PROCESS_WITNESS_ATTEMPT_FILENAME)
        for path in persisted_verdict.artifact_paths
    )
    assert any(
        path.endswith(concolic_module.CONCOLIC_PROCESS_WITNESS_ATTEMPT_FILENAME)
        for path in verdict_payload["artifact_paths"]
    )
    assert proof["native_replay"]["status"] == "replayed"
    assert proof["native_replay"]["file_name"] == "concolic_input"
    assert "A" * 32 in proof["native_replay"]["stdout_tail"]


def test_process_dynamic_proof_passes_env_to_ghidra_and_records_native_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "read_env.sh"
    binary.write_text("#!/bin/sh\nprintf '%s' \"$CONCOLIC_INPUT\"\n")
    binary.chmod(0o755)
    pack = _pack_with_entrypoint("env")

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="timeout",
            backend=request.backend,
            request=request.to_dict(),
            witness=CrashWitness(input_model=request.input_model, env={"CONCOLIC_INPUT": b"A" * 32}),
            replay_result={"concrete_angr_replay": {"status": "replayed", "input_hex": "41" * 32}},
        )

    def fake_dynamic_proof(proof_request):
        assert proof_request.input_model == "env"
        return {
            "status": "overflow_proven",
            "proof_scope": "process_entrypoint",
            "sink_reached": True,
            "exact_sink_reached": True,
            "sink_address": "0x1010",
            "write_size_bytes": 32,
            "capacity_bytes": 16,
            "overflow_bytes": 16,
            "process_input_setup": {
                "status": "configured",
                "input_model": "env",
                "env_name": "CONCOLIC_INPUT",
                "modeled_env_calls": [
                    {
                        "function_model": "getenv",
                        "variable_name": "CONCOLIC_INPUT",
                        "environment_model": "configured",
                    }
                ],
            },
            "process_replay": {"status": "reached", "reached_target": True, "process_input_setup": {"status": "configured"}},
            "local_sink_probe": {"status": "reached", "reached_target": True},
        }

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    request = build_concolic_request(pack, binary_path=binary, input_model="env", symbolic_bytes=32)

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / "artifacts",
    )

    proof = verdict.ghidra_dynamic_proof
    assert verdict.verdict == "overflow_witness"
    assert proof["status"] == "overflow_proven"
    assert proof["process_input_setup"]["status"] == "configured"
    assert proof["native_replay"]["status"] == "replayed"
    assert proof["native_replay"]["env_name"] == "CONCOLIC_INPUT"
    assert "A" * 32 in proof["native_replay"]["stdout_tail"]


def test_native_env_file_replay_reconstructs_environment_file_and_argv(tmp_path: Path) -> None:
    binary = tmp_path / "read_env_file.sh"
    binary.write_text(
        "#!/bin/sh\nprintf '%s|' \"$QUOTING_STYLE\"\ncat \"$CHARSETALIASDIR/charset.alias\"\nprintf '|%s|%s' \"$1\" \"$2\"\n"
    )
    binary.chmod(0o755)
    request = build_concolic_request(
        _pack_with_entrypoint("env"),
        binary_path=binary,
        input_model="env_file",
        symbolic_bytes=8,
    )
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(
            input_model="env_file",
            env={"CHARSETALIASDIR": b".", "QUOTING_STYLE": b"locale"},
            file_inputs={"charset.alias": b"DATA"},
            argv=(b"-i", b"/missing"),
        ),
    )
    proof = {
        "status": "overflow_proven",
        "proof_scope": "process_entrypoint",
        "sink_address": "0x1010",
        "sink_reached": True,
        "exact_sink_reached": True,
        "process_input_setup": {
            "status": "configured",
            "env_name": "CHARSETALIASDIR",
            "file_name": "charset.alias",
        },
        "process_replay": {"status": "reached", "reached_target": True},
        "request": {
            "env_values": {"CHARSETALIASDIR": ".", "QUOTING_STYLE": "locale"},
            "file_name": "charset.alias",
            "file_input_hex": b"DATA".hex(),
            "argv_values": ["program", "-i", "/missing"],
        },
    }

    replay = concolic_module._native_process_replay(request, verdict, proof)

    assert replay["status"] == "replayed"
    assert replay["file_name"] == "charset.alias"
    assert replay["env_name"] == "CHARSETALIASDIR"
    assert replay["stdout_tail"] == "locale|DATA|-i|/missing"


def test_process_dynamic_proof_known_unsupported_model_returns_explicit_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _pack_with_entrypoint("network")

    def fake_angr_backend(request, evidence_pack):
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="timeout",
            backend=request.backend,
            request=request.to_dict(),
            witness=CrashWitness(input_model=request.input_model, argv=(b"A" * 32,)),
            replay_result={"concrete_angr_replay": {"status": "replayed", "input_hex": "41" * 32}},
        )

    def unexpected_dynamic_proof(proof_request):
        raise AssertionError("unsupported process input model should not launch Ghidra")

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fake_angr_backend)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", unexpected_dynamic_proof)
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="network", symbolic_bytes=32)

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / "artifacts",
    )

    proof = verdict.ghidra_dynamic_proof
    assert verdict.verdict == "timeout"
    assert proof["status"] == "unsupported"
    assert proof["proof_scope"] == "process_entrypoint"
    assert proof["reason"] == "unsupported_process_input_setup:input_model_network"
    assert proof["process_input_setup"]["status"] == "unsupported"
    assert proof["local_sink_probe"]["status"] == "not_run"


@pytest.mark.parametrize("input_model", ["socket_service", "http_daemon"])
def test_service_input_models_run_seeded_dynamic_proof_before_angr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    input_model: str,
) -> None:
    pack = _pack_with_entrypoint(input_model)
    pack.setdefault("type_facts", {})["process_input"] = {
        "input_model": input_model,
        input_model: {"host": "127.0.0.1", "port": 19091},
    }
    proof_requests = []

    def fail_angr(*_args, **_kwargs):
        raise AssertionError("service proof should use the deterministic Ghidra process path first")

    def fake_dynamic_proof(proof_request):
        proof_requests.append(proof_request)
        return _fake_overflow_proof(proof_request)

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fail_angr)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    monkeypatch.setattr(concolic_module, "_native_process_replay", lambda *_args: {"status": "replayed"})
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model=input_model, symbolic_bytes=32)

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / input_model,
    )

    assert verdict.verdict == "overflow_witness"
    assert proof_requests[0].input_model == input_model
    assert proof_requests[0].process_input_evidence["host"] == "127.0.0.1"
    assert proof_requests[0].process_input_evidence["port"] == 19091


def test_exact_sink_no_overflow_skips_symbolic_backend_without_claiming_safety(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack = _pack_with_entrypoint("stdin")

    def fail_angr(*_args: Any, **_kwargs: Any) -> ConcolicVerdict:
        raise AssertionError("exact deterministic process replay should finish before angr")

    def fake_dynamic_proof(proof_request: Any) -> dict[str, Any]:
        return {
            "proof_kind": "ghidra_dynamic_overflow",
            "candidate_id": proof_request.candidate_id,
            "status": "no_overflow",
            "reason": "concrete_write_does_not_exceed_capacity",
            "proof_scope": "process_entrypoint",
            "sink_address": proof_request.sink_address,
            "sink_reached": True,
            "exact_sink_reached": True,
            "capacity_bytes": 32,
            "write_size_bytes": 16,
            "overflow_bytes": 0,
            "process_input_setup": {"status": "configured", "input_model": "stdin"},
            "process_replay": {"status": "reached", "reached_target": True},
        }

    monkeypatch.setattr(concolic_module, "_run_angr_backend", fail_angr)
    monkeypatch.setattr(concolic_module, "run_ghidra_dynamic_overflow_proof", fake_dynamic_proof)
    request = build_concolic_request(pack, binary_path=_binary(tmp_path), input_model="stdin", symbolic_bytes=32)

    verdict = concolic_module.run_concolic_request(
        request,
        pack,
        ghidra_dynamic_proof=True,
        artifact_dir=tmp_path / "artifacts",
    )
    confirmation = concolic_confirmation_dict(verdict)

    assert verdict.verdict == "target_reached"
    assert verdict.ghidra_dynamic_proof["status"] == "no_overflow"
    assert confirmation["status"] == "needs_more_evidence"
    assert confirmation["reason_codes"] == ["ghidra_dynamic_no_overflow"]
