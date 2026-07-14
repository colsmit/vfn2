import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from binary_agent.analysis.confirmation import build_evidence_pack_v3, validate_helper_output_grounding
from binary_agent.analysis.candidates import extract_static_candidates
from binary_agent.analysis.concolic import ConcolicRunResult
import binary_agent.cli.toolchain as toolchain_cli
from binary_agent.cli.run_refinement import main as run_refinement_main
from binary_agent.data.manifest import FunctionRecord, Manifest
from binary_agent.discovery import discover_candidates, load_discovery_context
from binary_agent.ingest.loader import load_function_nodes
from binary_agent.intake import run_intake
from binary_agent.pipeline import (
    ArtifactIndex,
    CandidateState,
    CandidateStatus,
    build_source_to_sink_trace,
    has_reportable_source_to_sink,
    write_candidate_states,
)
from binary_agent.promotion import apply_replay_results, promote_for_replay, promote_for_report, promote_proof_ready
from binary_agent.replay import ReplayRequest, build_replay_requests, import_concolic_replay_results, run_replay_request
import binary_agent.replay.runners as replay_runners
from binary_agent.reporting import (
    build_lean_reports,
    check_report_claims,
    write_lean_reports,
    write_vendor_evidence_bundles,
)


def _record(
    *,
    name: str,
    address: str,
    ordinal: int,
    relative_path: str,
    text: str,
    stack_regions: list[dict] | None = None,
    global_refs: list[dict] | None = None,
    pcode_calls: list[dict] | None = None,
    pcode_loads: list[dict] | None = None,
    c_line_addresses: list[dict] | None = None,
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
        prototype=f"void {name}(void)",
        parameters=[],
        emit_c=True,
        stack_regions=stack_regions or [],
        string_refs=[],
        pcode_calls=pcode_calls or [],
        pcode_stores=[],
        pcode_loads=pcode_loads or [],
        c_line_addresses=c_line_addresses or [],
        ambiguous_callsites=[],
        global_refs=global_refs or [],
    )


def _stack_region(name: str = "local_20", size: int = 16, start: int = -0x20) -> dict:
    return {
        "start_offset": start,
        "end_offset": start + size,
        "size_bytes": size,
        "var_names": [name],
        "data_types": ["char"],
    }


def _write_export(tmp_path: Path, sources: dict[str, str], stack_paths: set[str] | None = None) -> Path:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    records = []
    for index, (relative_path, text) in enumerate(sources.items()):
        (export_dir / relative_path).write_text(text)
        records.append(
            _record(
                name=relative_path.removesuffix(".c"),
                address=f"0x{0x1000 + index * 0x100:x}",
                ordinal=index,
                relative_path=relative_path,
                text=text,
                stack_regions=[_stack_region()] if relative_path in (stack_paths or set()) else [],
            )
        )
    manifest = Manifest(
        binary="demo.bin",
        generated_at="2026-05-15T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=records,
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))
    return export_dir


def test_decompilation_cache_fingerprint_tracks_exporter_inputs(tmp_path: Path) -> None:
    decompile_script = tmp_path / "decompile.py"
    decompile_script.write_text("print('first')\n")

    first = toolchain_cli._decompilation_cache_fingerprint(decompile_script)
    decompile_script.write_text("print('second')\n")
    second = toolchain_cli._decompilation_cache_fingerprint(decompile_script)

    assert first != second


def _state(status: str = "proof_ready", candidate_id: str = "cand-1") -> CandidateState:
    return CandidateState(
        candidate_id=candidate_id,
        vulnerability_type="stack_overflow",
        status=status,
        target={"binary": "demo.bin"},
        location={"function_name": "vulnerable_copy", "relative_path": "demo.c", "line_number": 4},
        source={"kind": "attacker_input", "call_path": ["main", "vulnerable_copy"]},
        sink={"name": "strcpy", "target_buffer": "buf", "operation_address": "0x1010"},
        type_facts={
            "capacity_bytes": 16,
            "write_relation": "unbounded",
            "verdict": "unbounded",
            "overflow_condition": "strcpy has no destination bound",
            "source_to_sink_trace": {
                "schema_version": 1,
                "status": "complete",
                "attacker_control_reaches_sink_role": True,
                "evidence": {"source_to_write_complete": True},
                "entry_function": "main",
                "entry_surface_kind": "program_entry",
                "target_function": "vulnerable_copy",
                "target_address": "0x1000",
                "sink_name": "strcpy",
                "call_path": ["main", "vulnerable_copy"],
                "input_model": "argv",
                "controlled_roles": ["write_source:parameter_controlled"],
                "blockers": [],
            },
        },
        proof_obligations=[
            {
                "obligation_id": "cand-1:bounds",
                "description": "bounds",
                "condition": "strcpy has no destination bound",
                "status": "satisfied",
            }
        ],
        blockers=[],
    )


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | 0o111)
    return path


def _with_source_to_sink_override(state: CandidateState, tmp_path: Path) -> CandidateState:
    path = tmp_path / f"{state.candidate_id.replace(':', '_')}_source_to_sink_override.json"
    path.write_text(json.dumps({"artifact_kind": "source_to_sink_override", "status": "approved", "reason": "test fixture"}))
    return state.with_updates(validation_artifacts=[*state.validation_artifacts, str(path)])


def _with_reportable_process_evidence(state: CandidateState, tmp_path: Path) -> CandidateState:
    proof = _write_ghidra_process_proof(
        tmp_path / f"{state.candidate_id.replace(':', '_')}_ghidra_dynamic_proof.json",
        state.candidate_id,
    )
    return state.with_updates(replay_artifacts=[*state.replay_artifacts, str(proof)])


def _write_ghidra_process_proof(
    path: Path,
    candidate_id: str,
    *,
    input_model: str = "argv",
    process_input_source: str = "",
    process_input_evidence: dict | None = None,
    status: str = "overflow_proven",
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    process_setup = {"status": "configured", "input_model": input_model}
    if process_input_source:
        process_setup["process_input_source"] = process_input_source
    if process_input_evidence:
        process_setup["process_input_evidence"] = process_input_evidence
    memory_fields = (
        {
            "capacity_bytes": 5,
            "read_size_bytes": 32,
            "oob_bytes": 27,
            "read_range": {
                "range_kind": "modeled_stack_object_offsets",
                "base": "heartbeat_record[3:]",
                "start_offset": 0,
                "end_offset_exclusive": 32,
                "size_bytes": 32,
            },
            "object_range": {
                "range_kind": "modeled_stack_object_offsets",
                "base": "heartbeat_record[3:]",
                "start_offset": 0,
                "end_offset_exclusive": 5,
                "size_bytes": 5,
            },
        }
        if status == "oob_read_proven"
        else {
            "capacity_bytes": 16,
            "overflow_bytes": 16,
        }
    )
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "proof_kind": "ghidra_dynamic_overflow",
                "candidate_id": candidate_id,
                "status": status,
                "proof_scope": "process_entrypoint",
                "sink_reached": True,
                "exact_sink_reached": True,
                "process_input_setup": process_setup,
                "process_replay": {"status": "reached", "reached_target": True},
                **memory_fields,
            }
        )
    )
    return path


def _write_ghidra_function_harness_oob_proof(path: Path, candidate_id: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "proof_kind": "ghidra_dynamic_overflow",
                "candidate_id": candidate_id,
                "status": "oob_read_proven",
                "proof_scope": "function_harness",
                "sink_reached": True,
                "exact_sink_reached": True,
                "sink_address": "0x41fbda",
                "capacity_bytes": 1,
                "read_size_bytes": 1,
                "oob_bytes": 1,
                "process_input_setup": {
                    "status": "configured",
                    "input_model": "function_harness",
                    "proof_scope": "function_harness",
                    "concrete_input_hex": "80",
                    "input_size_bytes": 1,
                    "input_arg_index": 0,
                    "length_arg_index": 1,
                },
            }
        )
    )
    return path


def _write_ghidra_function_harness_overflow_proof(path: Path, candidate_id: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "proof_kind": "ghidra_dynamic_overflow",
                "candidate_id": candidate_id,
                "status": "overflow_proven",
                "proof_scope": "function_harness",
                "sink_reached": True,
                "exact_sink_reached": True,
                "sink_address": "0x1020",
                "capacity_bytes": 16,
                "write_size_bytes": 40,
                "overflow_bytes": 24,
                "process_input_setup": {
                    "status": "configured",
                    "input_model": "function_harness",
                    "proof_scope": "function_harness",
                    "concrete_input_hex": "41" * 40,
                    "input_size_bytes": 40,
                    "input_arg_index": 0,
                },
            }
        )
    )
    return path


def test_intake_artifacts_for_binary_and_rootfs(tmp_path: Path) -> None:
    binary = _script(tmp_path / "demo.sh", "echo ok\n")
    result = run_intake(binary, tmp_path / "binary_intake")
    binaries = json.loads(result.binaries_path.read_text())

    assert (tmp_path / "binary_intake" / "target.json").exists()
    assert binaries["binaries"][0]["path"] == str(binary)
    assert binaries["binaries"][0]["evidence"][0]["kind"] == "filesystem_path"

    rootfs = tmp_path / "rootfs"
    (rootfs / "etc" / "init.d").mkdir(parents=True)
    (rootfs / "etc" / "init.d" / "web").write_text("/usr/bin/httpd -p 8080\n")
    (rootfs / "etc" / "app.conf").write_text("API_KEY=demo\nGET /admin\n")
    (rootfs / "usr" / "bin").mkdir(parents=True)
    _script(rootfs / "usr" / "bin" / "httpd", "echo httpd\n")

    root_result = run_intake(rootfs, tmp_path / "root_intake")
    services = json.loads(root_result.services_path.read_text())["services"]
    routes = json.loads(root_result.routes_path.read_text())["routes"]
    configs = json.loads(root_result.configs_path.read_text())["configs"]

    assert services[0]["ports"] == [8080]
    assert routes[0]["route"] == "/admin"
    assert configs[0]["evidence"][0]["path"].endswith("app.conf")


def test_discovery_backends_emit_initial_terminal_vulnerability_types(tmp_path: Path) -> None:
    sources = {
        "stack.c": "void stack(void){ char local_20[16]; fgets(local_20, 64, stdin); }\n",
        "heap.c": "void heap(char *input){ char *buf; buf = malloc(16); strcpy(buf, input); }\n",
        "cmd.c": "void cmd(char **argv){ system(argv[1]); }\n",
        "path.c": "void path(char **argv){ fopen(argv[1], \"r\"); }\n",
        "fmt.c": "void fmt(char *input){ printf(input); }\n",
        "write.c": "void writefile(char **argv){ fopen(argv[1], \"w\"); }\n",
        "cred.c": "void cred(void){ char *admin_password = \"secret123\"; }\n",
        "auth.c": "int auth_check(void){ return 1; }\n",
        "intov.c": "void intov(int input_len){ int total = input_len * 64; malloc(total); }\n",
        "uaf.c": "void uaf(void){ char *buf; buf = malloc(16); free(buf); puts(buf); }\n",
        "double.c": "void double_free_path(void){ char *ptr; ptr = malloc(16); free(ptr); free(ptr); }\n",
        "invalid.c": "void invalid_free_path(void){ char *ptr; ptr = malloc(16); free(ptr + 1); }\n",
    }
    export_dir = _write_export(tmp_path, sources, stack_paths={"stack.c"})

    states = discover_candidates(load_discovery_context(export_dir))
    vulnerability_types = {state.vulnerability_type for state in states}

    assert {
        "stack_overflow",
        "heap_overflow",
        "command_injection",
        "path_traversal",
        "format_string",
        "unsafe_file_write",
        "hardcoded_credential",
        "auth_bypass",
        "use_after_free",
        "double_free",
        "invalid_free",
    } <= vulnerability_types
    assert all(state.proof_obligations for state in states)
    uaf_state = next(state for state in states if state.vulnerability_type == "use_after_free")
    assert uaf_state.type_facts["stale_alias"] == "buf"
    assert uaf_state.type_facts["free_site"]["release"] == "free"
    assert uaf_state.type_facts["use_site"]["use_kind"] == "stale_pointer_call_argument"
    assert "same_object_identity" in uaf_state.proof_obligations[0]["required_evidence"]
    assert "attacker_controlled_reallocation" in uaf_state.type_facts["llm_may_not_prove"]
    format_state = next(state for state in states if state.vulnerability_type == "format_string")
    assert format_state.type_facts["argument_roles"]["format"] == "input"
    assert format_state.source == {"kind": "attacker_input", "expression": "input"}


def test_use_after_free_discovery_covers_deref_refcount_and_callback_patterns(tmp_path: Path) -> None:
    sources = {
        "deref.c": "void deref(void){ char *buf; buf = malloc(16); free(buf); buf->field = 1; }\n",
        "ref.c": "void ref(void){ char *obj; obj = malloc(16); kref_put(obj); consume(obj); }\n",
        "callback.c": "void callback(void){ char *ctx; ctx = malloc(16); free(ctx); register_callback(cb, ctx); }\n",
        "terminated.c": "void stopped(int kind){ char *buf; buf = malloc(16); if (kind) { free(buf); return; } consume(buf); }\n",
    }
    export_dir = _write_export(tmp_path, sources)

    states = discover_candidates(
        load_discovery_context(export_dir),
        backend_names=["memory_lifetime"],
        vulnerability_types=["use_after_free"],
    )

    use_kinds = {state.type_facts["use_site"]["use_kind"] for state in states}
    releases = {state.type_facts["free_site"]["release"] for state in states}
    assert {"stale_pointer_dereference", "stale_pointer_call_argument", "callback_stale_pointer"} <= use_kinds
    assert {"free", "kref_put"} <= releases
    assert all("same_object_identity" in state.proof_obligations[0]["required_evidence"] for state in states)
    assert all(state.location["relative_path"] != "terminated.c" for state in states)


def test_cross_function_global_lifetime_candidate_uses_exact_load_address(tmp_path: Path) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    sources = {
        "alloc.c": "void alloc(void){ DAT_00405000 = FUN_00402000(); }\n",
        "release.c": "void release(void){ free(ptr); }\n",
        "use.c": "void use(void){ value = *(long *)(DAT_00405000 + 0x10); }\n",
    }
    for path, text in sources.items():
        (export_dir / path).write_text(text)
    records = [
        _record(name="alloc", address="0x1000", ordinal=0, relative_path="alloc.c", text=sources["alloc.c"]),
        _record(
            name="release",
            address="0x1100",
            ordinal=1,
            relative_path="release.c",
            text=sources["release.c"],
            pcode_calls=[{"call_address": "0x1110", "callee": "free"}],
        ),
        _record(
            name="use",
            address="0x1200",
            ordinal=2,
            relative_path="use.c",
            text=sources["use.c"],
            global_refs=[{"var_display": "DAT_00405000", "size_bytes": 8}],
            pcode_loads=[
                {
                    "operation_address": "0x1210",
                    "read_width": 8,
                    "address_vars": ["DAT_00405000"],
                }
            ],
            c_line_addresses=[{"line_number": 1, "addresses": ["0x1210"], "load_addresses": ["0x1210"]}],
        ),
    ]
    manifest = Manifest(
        binary="demo.bin",
        generated_at="2026-05-15T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=records,
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))

    states = discover_candidates(
        load_discovery_context(export_dir),
        backend_names=["memory_lifetime"],
        vulnerability_types=["use_after_free"],
    )
    cross = [state for state in states if state.source["kind"] == "cross_function_heap_lifetime"]
    promoted, _, _ = promote_proof_ready(cross)

    assert len(promoted) == 1
    assert promoted[0].status == CandidateStatus.PROOF_READY.value
    assert promoted[0].sink["operation_address"] == "0x1210"


def test_double_free_discovery_requires_one_unchanged_local_object_on_one_path(tmp_path: Path) -> None:
    sources = {
        "vulnerable.c": """
void vulnerable(void) {
  char *ptr;
  ptr = malloc(16);
  free(ptr);
  observe();
  free(ptr);
}
""",
        "nulled.c": "void nulled(void){ char *ptr; ptr = malloc(16); free(ptr); ptr = 0; free(ptr); }\n",
        "reallocated.c": "void changed(void){ char *ptr; ptr = malloc(16); free(ptr); ptr = malloc(8); free(ptr); }\n",
        "reassigned.c": "void changed(void){ char *ptr; ptr = malloc(16); ptr = other; free(ptr); free(ptr); }\n",
        "mutated.c": "void changed(void){ char *ptr; ptr = malloc(16); free(ptr); ptr += 1; free(ptr); }\n",
        "terminated.c": "void stopped(void){ char *ptr; ptr = malloc(16); free(ptr); return; free(ptr); }\n",
        "exclusive.c": "void split(int flag){ char *ptr; ptr = malloc(16); if (flag) free(ptr); else free(ptr); }\n",
    }
    export_dir = _write_export(tmp_path, sources)

    states = discover_candidates(
        load_discovery_context(export_dir),
        backend_names=["memory_lifetime"],
        vulnerability_types=["double_free"],
    )

    assert len(states) == 1
    state = states[0]
    assert state.location["relative_path"] == "vulnerable.c"
    assert state.status == CandidateStatus.NEEDS_REFINEMENT.value
    assert state.blockers == ["dynamic_same_object_lifetime_unproven", "exact_lifetime_sink_unresolved"]
    assert state.type_facts["same_local_object_identity"]["variable"] == "ptr"
    assert state.type_facts["path_is_valid"] is False
    assert [event["event"] for event in state.type_facts["trigger_sequence"]] == [
        "allocation",
        "release",
        "release",
    ]
    assert "dynamic_lifetime_confirmation" in state.proof_obligations[0]["required_evidence"]
    promoted, events, _ = promote_proof_ready([state])
    assert promoted[0].status == CandidateStatus.NEEDS_REFINEMENT.value
    assert events == []


def test_double_free_discovery_recovers_repeated_indexed_ownership_slot(tmp_path: Path) -> None:
    sources = {
        "indexed.c": """
void indexed(void) {
  void **slots;
  long index;
  free((void *)slots[index]);
  observe();
  free((void *)slots[index]);
}
""",
        "reinitialized.c": """
void reinitialized(void) {
  void **slots;
  long index;
  free(slots[index]);
  slots[index] = replacement;
  free(slots[index]);
}
""",
    }
    export_dir = _write_export(tmp_path, sources)

    states = discover_candidates(
        load_discovery_context(export_dir),
        backend_names=["memory_lifetime"],
        vulnerability_types=["double_free"],
    )

    indexed = [state for state in states if state.location["relative_path"] == "indexed.c"]
    assert len(indexed) == 1
    state = indexed[0]
    assert state.type_facts["same_indexed_slot_identity"]["slot"] == "slots[index]"
    assert state.sink["released_object"] == "slots[index]"
    assert state.blockers[:2] == [
        "dynamic_indexed_slot_object_identity_unproven",
        "indexed_slot_path_feasibility_unproven",
    ]
    assert not [state for state in states if state.location["relative_path"] == "reinitialized.c"]


def test_double_free_discovery_requires_unguarded_owner_alias_lookback(tmp_path: Path) -> None:
    vulnerable = """void vulnerable(void) {
  owners[dst] = owners[src];
  if (metadata[index - 1] != 0) { observe(); }
  free(owners[index]);
}
"""
    fixed = """void fixed(void) {
  owners[dst] = owners[src];
  if ((long)index < 1 || metadata[index - 1] != 0) { observe(); }
  free(owners[index]);
}
"""
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    (export_dir / "vulnerable.c").write_text(vulnerable)
    (export_dir / "fixed.c").write_text(fixed)
    records = [
        _record(
            name="vulnerable",
            address="0x1000",
            ordinal=0,
            relative_path="vulnerable.c",
            text=vulnerable,
            pcode_calls=[{"callee": "free", "call_address": "0x1010", "callee_address": "0x9000"}],
            c_line_addresses=[{"line_number": 4, "addresses": ["0x1010"]}],
        ),
        _record(
            name="fixed",
            address="0x1100",
            ordinal=1,
            relative_path="fixed.c",
            text=fixed,
            pcode_calls=[{"callee": "free", "call_address": "0x1110", "callee_address": "0x9000"}],
            c_line_addresses=[{"line_number": 4, "addresses": ["0x1110"]}],
        ),
    ]
    manifest = Manifest(
        binary="owner-table-demo.bin",
        generated_at="2026-07-10T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=records,
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))

    states = discover_candidates(
        load_discovery_context(export_dir),
        backend_names=["memory_lifetime"],
        vulnerability_types=["double_free"],
    )

    assert len(states) == 1
    state = states[0]
    assert state.location["relative_path"] == "vulnerable.c"
    assert state.sink["operation_address"] == "0x1010"
    assert state.type_facts["indexed_owner_alias"]["table"] == "owners"
    assert state.type_facts["unguarded_index_minus_one_lookup"]["lower_bound_guard"] == "absent"
    assert "owner_alias_range_overlap_unproven" in state.blockers


def test_invalid_free_discovery_requires_allocation_derived_non_base_pointer(tmp_path: Path) -> None:
    sources = {
        "direct.c": "void direct(void){ char *base; base = malloc(32); free(base + 1); }\n",
        "alias.c": "void alias(void){ char *base; char *shifted; base = malloc(32); shifted = base + 4; free(shifted); }\n",
        "base.c": "void valid(void){ char *base; base = malloc(32); free(base); }\n",
        "zero.c": "void zero(void){ char *base; base = malloc(32); free(base + 0); }\n",
        "stack.c": "void stack(void){ char local[8]; free(local + 1); }\n",
    }
    export_dir = _write_export(tmp_path, sources)

    states = discover_candidates(
        load_discovery_context(export_dir),
        backend_names=["memory_lifetime"],
        vulnerability_types=["invalid_free"],
    )

    assert {state.location["relative_path"] for state in states} == {"direct.c", "alias.c"}
    assert all(state.blockers == ["dynamic_non_base_release_unproven", "exact_lifetime_sink_unresolved"] for state in states)
    by_path = {state.location["relative_path"]: state for state in states}
    assert by_path["direct.c"].type_facts["derived_pointer"]["offset_expression"] == "1"
    assert by_path["alias.c"].type_facts["derived_pointer"]["derived_variable"] == "shifted"
    assert "runtime_object_identity" in by_path["alias.c"].proof_obligations[0]["required_evidence"]
    assert "release_address_is_not_object_base" in by_path["alias.c"].type_facts["llm_may_not_prove"]


def test_invalid_free_with_exact_release_callsite_promotes_for_dynamic_proof(tmp_path: Path) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    source = """void invalid(void) {
  char *base;
  base = malloc(32);
  free(base + 1);
}
"""
    (export_dir / "invalid.c").write_text(source)
    record = _record(
        name="invalid",
        address="0x1000",
        ordinal=0,
        relative_path="invalid.c",
        text=source,
        pcode_calls=[{"call_address": "0x1010", "callee": "free"}],
        c_line_addresses=[{"line_number": 4, "addresses": ["0x1010"]}],
    )
    manifest = Manifest(
        binary="demo.bin",
        generated_at="2026-05-15T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=[record],
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))

    states = discover_candidates(
        load_discovery_context(export_dir),
        backend_names=["memory_lifetime"],
        vulnerability_types=["invalid_free"],
    )
    promoted, events, _ = promote_proof_ready(states)

    assert len(promoted) == 1
    assert promoted[0].status == CandidateStatus.PROOF_READY.value
    assert promoted[0].sink["operation_address"] == "0x1010"
    assert promoted[0].blockers == []
    assert len(events) == 1


def test_invalid_free_report_gate_requires_exact_non_base_identity_and_native_event(tmp_path: Path) -> None:
    proof_path = tmp_path / "ghidra_dynamic_proof.json"
    proof = {
        "proof_kind": "ghidra_dynamic_memory_safety",
        "status": "lifetime_violation_proven",
        "proof_scope": "process_entrypoint",
        "sink_reached": True,
        "exact_sink_reached": True,
        "sink_address": "0x1010",
        "process_input_setup": {"status": "configured", "input_model": "argv"},
        "process_replay": {"status": "reached", "reached_target": True},
        "lifetime_violation": {
            "vulnerability": "invalid_free",
            "reason": "release_address_is_not_object_base",
            "object_id": 1,
            "address": "0x70000001",
            "object_base_address": "0x70000000",
            "object_size_bytes": 32,
        },
        "native_replay": {"status": "replayed", "lifetime_event_observed": True},
    }
    state = _state(status="replay_confirmed", candidate_id="invalid-report").with_updates(
        vulnerability_type="invalid_free",
        source={"kind": "allocation_derived_pointer", "expression": "base"},
        sink={"name": "free", "kind": "non_base_release", "operation_address": "0x1010"},
        type_facts={"allocation_site": {"variable": "base"}, "derived_pointer": {"offset_expression": "1"}},
        replay_artifacts=[str(proof_path)],
    )

    proof_path.write_text(json.dumps(proof))
    assert has_reportable_source_to_sink(state) is True

    proof["native_replay"]["lifetime_event_observed"] = False
    proof_path.write_text(json.dumps(proof))
    assert has_reportable_source_to_sink(state) is False

    proof["native_replay"]["lifetime_event_observed"] = True
    proof["lifetime_violation"]["reason"] = "pointer_is_not_a_modeled_allocation"
    proof["lifetime_violation"].pop("object_id")
    proof_path.write_text(json.dumps(proof))
    assert has_reportable_source_to_sink(state) is False


def test_evidence_pack_v3_rejects_ungrounded_helper_facts() -> None:
    state = _state()
    intake = {
        "routes": {"routes": [{"route": "/admin", "evidence": [{"path": "/etc/app.conf"}]}]},
        "configs": {"configs": [{"env_keys": ["API_KEY"], "evidence": [{"path": "/etc/app.conf"}]}]},
    }
    pack = build_evidence_pack_v3(state.to_dict(), intake_facts=intake)

    accepted = validate_helper_output_grounding(
        pack,
        {"role": "triage", "paths": ["demo.c"], "routes": ["/admin"], "env": ["API_KEY"], "sinks": ["strcpy"]},
    )
    rejected = validate_helper_output_grounding(
        pack,
        {
            "role": "triage",
            "paths": ["/tmp/invented"],
            "routes": ["/debug"],
            "env": ["ROOT_PASSWORD"],
            "sinks": ["system"],
            "impact": "RCE",
            "reachability": {"unauthenticated": True},
        },
    )

    assert pack["schema_version"] == 3
    assert accepted.accepted is True
    assert rejected.accepted is False
    assert "ungrounded_route:/debug" in rejected.reasons
    assert "unsupported_impact" in rejected.reasons


def test_refinement_persists_generalized_file_format_process_input_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "00101000_main.c": """
undefined8 main(int param_1,long param_2)
{
  int local_mode;
  local_mode = 0;
  switch(param_1) {
  case 'x':
    local_mode = 1;
    break;
  }
  fatal("need tar file with ustar header");
  pFVar1 = fopen64(pcVar18,"r");
  fgets(local_848,0x800,stdin);
}
""",
        },
    )
    state = _state(
        status="needs_refinement",
        candidate_id="demo:0x101000:main:88:fgets:local_848:0:0x800",
    ).with_updates(
        location={
            "function_name": "main",
            "address": "0x101000",
            "relative_path": "00101000_main.c",
            "line_number": 88,
            "line_text": "fgets(local_848,0x800,stdin);",
        },
        sink={"name": "fgets", "target_buffer": "local_848", "operation_address": "0x101020"},
        type_facts={
            "capacity_bytes": 16,
            "write_relation": "symbolic_capacity",
            "verdict": "candidate",
            "write_size_bytes": 0x800,
            "entrypoint_derivation": {
                "status": "derived",
                "entry_function": "main",
                "entry_address": "0x101000",
                "target_function": "main",
                "target_address": "0x101000",
                "input_model": "argv",
                "process_input_supported": True,
                "evidence": {"export_dir": str(export_dir)},
                "source_to_sink_trace": {
                    "argument_roles": [{"role": "write_source", "evidence": ["main calls input source fgets"]}],
                    "transformations": [
                        "line 12: fgets(local_848,0x800,stdin);",
                        "line 20: pFVar1 = fopen64(pcVar18,\"r\");",
                    ],
                },
            },
        },
        blockers=["overflow_condition_proof"],
    )
    states_path = write_candidate_states([state], tmp_path / "candidate_states.json")
    evidence_dir = tmp_path / "evidence"
    promotion_dir = tmp_path / "promotion"
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_refinement",
            str(states_path),
            "--evidence-dir",
            str(evidence_dir),
            "--promotion-dir",
            str(promotion_dir),
        ],
    )

    run_refinement_main()

    promoted = json.loads((promotion_dir / "candidate_states.json").read_text())["candidate_states"][0]
    evidence_index = json.loads((evidence_dir / "index.json").read_text())["evidence_packs"][0]
    pack = json.loads((evidence_dir / evidence_index["path"]).read_text())
    process_input = promoted["type_facts"]["process_input"]
    pack_process_input = pack["facts_available_to_llm"]["process_input"]
    assert process_input["input_model"] == "argv_file_stdin"
    assert process_input["file_name"] == "concolic_input.tar"
    assert process_input["process_input_evidence"]["file_seed_reason"] == "tar_format_text"
    assert process_input["process_input_evidence"]["decompile_source_file"].endswith("00101000_main.c")
    assert pack_process_input == process_input


def test_replay_classification_statuses(tmp_path: Path) -> None:
    confirmed = _script(tmp_path / "confirmed.sh", "echo vulnerable_copy\n echo '*** buffer overflow detected ***' >&2\n exit 134\n")
    no_bug = _script(tmp_path / "no_bug.sh", "echo vulnerable_copy\n exit 0\n")
    no_sink = _script(tmp_path / "no_sink.sh", "echo ok\n exit 0\n")
    crash = _script(tmp_path / "crash.sh", "echo boom >&2\n exit 134\n")
    non_crash_error = _script(tmp_path / "non_crash_error.sh", "echo unable to open file >&2\n exit 255\n")

    def request(binary: Path, marker: str = "vulnerable_copy") -> ReplayRequest:
        return ReplayRequest(
            candidate_id=binary.stem,
            mode="native",
            setup={"binary_path": str(binary), "sink": "strcpy"},
            input={"argv": ["A" * 128]},
            expected_result={"sink_output_contains": marker, "expect_crash": True},
        )

    assert run_replay_request(request(confirmed), tmp_path / "replay").result == "confirmed"
    assert run_replay_request(request(no_bug), tmp_path / "replay").result == "sink_reached_no_bug"
    assert run_replay_request(request(no_sink), tmp_path / "replay").result == "sink_not_reached"
    assert run_replay_request(request(crash), tmp_path / "replay").result == "crash_unclassified"
    assert run_replay_request(request(non_crash_error), tmp_path / "replay").result == "sink_not_reached"
    assert run_replay_request(request(tmp_path / "missing"), tmp_path / "replay").result == "setup_invalid"
    blocked = ReplayRequest("blocked", "qemu_system", {}, {}, {})
    assert run_replay_request(blocked, tmp_path / "replay").result == "blocked"


def test_qemu_user_searches_process_recipes_for_function_harness_witness(tmp_path: Path, monkeypatch) -> None:
    qemu = _script(
        tmp_path / "qemu-arm",
        "trace=''\n"
        "while [ \"$1\" ]; do\n"
        "  case \"$1\" in\n"
        "    -L) shift 2 ;;\n"
        "    -E) shift 2 ;;\n"
        "    -d) shift 2 ;;\n"
        "    -dfilter) shift 2 ;;\n"
        "    -D) trace=\"$2\"; shift 2 ;;\n"
        "    -one-insn-per-tb) shift ;;\n"
        "    *) break ;;\n"
        "  esac\n"
        "done\n"
        "if [ \"$2\" = \"AA\" ]; then echo 'Segmentation fault' >&2; exit 139; fi\n"
        "if [ -f \"$2\" ]; then printf '%s\\n' '0x00001000: nop' > \"$trace\"; fi\n"
        "exit 0\n",
    )
    binary = _script(tmp_path / "arm_target", "echo target\n")
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)
    monkeypatch.setenv("QEMU_USER_BIN", str(qemu))
    request = ReplayRequest(
        candidate_id="function-harness",
        mode="qemu_user",
        setup={"binary_path": str(binary), "rootfs_path": str(rootfs)},
        input={"input_model": "function_harness", "input_hex": "4141"},
        expected_result={"target_address": "0x1000"},
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "sink_reached_no_bug"
    assert result.sink_reached is True
    assert result.crash_observed is False
    assert result.control_result["original_input_model"] == "function_harness"
    assert result.control_result["process_recipe_source"] == "deterministic_generic_launch_search"
    attempts = result.control_result["function_harness_process_attempts"]
    assert attempts[0]["crash_observed"] is True
    assert attempts[-1]["trace_reached_expected_address"] is True
    assert (tmp_path / "replay" / "function-harness" / "function_harness_process_attempts.json").exists()


def test_qemu_user_replay_executes_configured_tool(tmp_path: Path, monkeypatch) -> None:
    qemu = _script(
        tmp_path / "qemu-arm",
        "shift\n"
        "while [ \"$1\" ]; do\n"
        "  case \"$1\" in\n"
        "    -L) shift 2 ;;\n"
        "    -E) shift 2 ;;\n"
        "    -d) shift 2 ;;\n"
        "    -D) shift 2 ;;\n"
        "    *) break ;;\n"
        "  esac\n"
        "done\n"
        "echo vulnerable_copy\n"
        "echo '*** buffer overflow detected ***' >&2\n"
        "exit 134\n",
    )
    binary = _script(tmp_path / "arm_target", "echo target\n")
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)
    monkeypatch.setenv("QEMU_USER_BIN", str(qemu))
    request = ReplayRequest(
        candidate_id="qemu-confirmed",
        mode="qemu_user",
        setup={"binary_path": str(binary), "rootfs_path": str(rootfs), "env": {"REQUEST_METHOD": "POST"}},
        input={"form": {"payload": "A" * 32}},
        expected_result={"sink_output_contains": "vulnerable_copy", "expect_crash": True},
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "confirmed"
    assert result.mode == "qemu_user"
    assert result.sink_reached is True
    assert any(path.endswith("qemu_user_transcript.json") for path in result.artifacts)


def test_qemu_user_timeout_keeps_target_trace_evidence(tmp_path: Path, monkeypatch) -> None:
    qemu = _script(
        tmp_path / "qemu-arm",
        "trace=''\n"
        "while [ \"$1\" ]; do\n"
        "  case \"$1\" in\n"
        "    -L) shift 2 ;;\n"
        "    -E) shift 2 ;;\n"
        "    -d) shift 2 ;;\n"
        "    -dfilter) shift 2 ;;\n"
        "    -D) trace=\"$2\"; shift 2 ;;\n"
        "    -one-insn-per-tb) shift ;;\n"
        "    *) break ;;\n"
        "  esac\n"
        "done\n"
        "if [ \"$trace\" ]; then printf '%s\\n' '0x00001000: nop' > \"$trace\"; fi\n"
        "while :; do :; done\n",
    )
    binary = _script(tmp_path / "arm_target", "echo target\n")
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)
    monkeypatch.setenv("QEMU_USER_BIN", str(qemu))
    request = ReplayRequest(
        candidate_id="qemu-timeout-target",
        mode="qemu_user",
        setup={"binary_path": str(binary), "rootfs_path": str(rootfs), "timeout_seconds": 0.05},
        input={"stdin": "payload"},
        expected_result={"target_address": "0x1000"},
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "sink_reached_no_bug"
    assert result.sink_reached is True
    assert result.crash_observed is False
    assert result.control_result["timed_out"] is True
    assert result.control_result["trace_reached_expected_address"] is True
    assert any(path.endswith("qemu_user_transcript.json") for path in result.artifacts)


def test_qemu_rootfs_inference_ignores_unreadable_children(tmp_path: Path) -> None:
    firmware_root = tmp_path / "rootfs"
    base = firmware_root / "gxp1600base"
    binary_dir = base / "bin"
    binary_dir.mkdir(parents=True)
    (base / "lib").mkdir()
    (base / "etc").mkdir()
    blocked = base / "dev"
    (blocked / "bin").mkdir(parents=True)
    binary = binary_dir / "target"
    binary.write_text("#!/bin/sh\n")
    blocked.chmod(0)
    try:
        assert replay_runners._infer_firmware_root(binary) == firmware_root
    finally:
        blocked.chmod(0o755)


def test_qemu_user_replay_derives_cgi_env_from_route(tmp_path: Path, monkeypatch) -> None:
    capture = tmp_path / "env_capture"
    qemu = _script(
        tmp_path / "qemu-arm",
        "while [ \"$1\" ]; do\n"
        "  case \"$1\" in\n"
        "    -L) shift 2 ;;\n"
        "    -E) echo \"$2\" >> " + str(capture) + "; shift 2 ;;\n"
        "    -d) shift 2 ;;\n"
        "    -D) shift 2 ;;\n"
        "    *) break ;;\n"
        "  esac\n"
        "done\n"
        "echo ok\n",
    )
    binary = _script(tmp_path / "arm_target", "echo target\n")
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)
    monkeypatch.setenv("QEMU_USER_BIN", str(qemu))
    request = ReplayRequest(
        candidate_id="qemu-cgi-route",
        mode="qemu_user",
        setup={"binary_path": str(binary), "rootfs_path": str(rootfs), "routes": [{"method": "POST", "path": "/cgi-bin/api.values.post"}]},
        input={"form": {"P196": "1"}},
        expected_result={"sink_output_contains": "ok", "expect_crash": False},
    )

    result = run_replay_request(request, tmp_path / "replay")
    env_lines = set(capture.read_text().splitlines())

    assert result.result == "sink_reached_no_bug"
    assert "REQUEST_METHOD=POST" in env_lines
    assert "SCRIPT_NAME=/cgi-bin/api.values.post" in env_lines
    assert "REQUEST_URI=/cgi-bin/api.values.post" in env_lines
    assert "CONTENT_TYPE=application/x-www-form-urlencoded" in env_lines
    assert "FORM_P196=1" in env_lines


def test_qemu_user_replay_inherits_comma_env_values(tmp_path: Path, monkeypatch) -> None:
    capture = tmp_path / "env_capture"
    qemu = _script(
        tmp_path / "qemu-arm",
        "while [ \"$1\" ]; do\n"
        "  case \"$1\" in\n"
        "    -L) shift 2 ;;\n"
        "    -E) echo \"arg:$2\" >> " + str(capture) + "; shift 2 ;;\n"
        "    *) break ;;\n"
        "  esac\n"
        "done\n"
        "echo \"env:$FORM_P64\" >> " + str(capture) + "\n"
        "echo ok\n",
    )
    binary = _script(tmp_path / "arm_target", "echo target\n")
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)
    monkeypatch.setenv("QEMU_USER_BIN", str(qemu))
    value = "IST-2IDT,M3.4.4/26,M10.5.0"
    request = ReplayRequest(
        candidate_id="qemu-comma-env",
        mode="qemu_user",
        setup={"binary_path": str(binary), "rootfs_path": str(rootfs), "routes": [{"method": "POST", "path": "/cgi-bin/api.values.post"}]},
        input={"form": {"P64": value}},
        expected_result={"sink_output_contains": "ok", "expect_crash": False},
    )

    result = run_replay_request(request, tmp_path / "replay")
    lines = set(capture.read_text().splitlines())

    assert result.result == "sink_reached_no_bug"
    assert f"env:{value}" in lines
    assert not any(line == f"arg:FORM_P64={value}" for line in lines)


def test_qemu_user_deterministic_route_and_filesystem_from_core_literals(tmp_path: Path, monkeypatch) -> None:
    binary = _script(tmp_path / "gs_web", "echo target\n")
    monkeypatch.setattr(
        replay_runners,
        "_function_literal_strings",
        lambda _path, _address: ["core.", "name", "url", "lastmodified", "size", "/app/war", "/export/core/"],
    )
    monkeypatch.setattr(
        replay_runners,
        "_binary_ascii_strings",
        lambda _path: ["/cgi-bin/api.values.post", "/cgi-bin/api-gen_core_dump", "/cgi-bin/api-get_dump_list"],
    )
    state = _state(
        status="replay_ready",
        candidate_id="gs_web:0x1329C:FUN_0001329c:34:strcat:local_158:0:unbounded",
    ).with_updates(
        location={"address": "0x1329C", "function_name": "FUN_0001329c", "line_text": "strcat(local_158,__s1);"},
        sink={"name": "strcat", "target_buffer": "local_158"},
    )

    request = build_replay_requests([state], binary_path=binary, mode="qemu_user")[0]

    assert request.setup["routes"] == [{"method": "GET", "path": "/cgi-bin/api-get_dump_list"}]
    assert request.setup["filesystem"][0]["directory"] == "/app/war/export/core/"
    assert request.setup["filesystem"][0]["pattern"] == "core.*"
    assert len(request.setup["filesystem"]) == 1


def test_qemu_user_deterministic_route_prefers_config_post_for_time_literals(tmp_path: Path, monkeypatch) -> None:
    binary = _script(tmp_path / "gs_web", "echo target\n")
    monkeypatch.setattr(
        replay_runners,
        "_function_literal_strings",
        lambda _path, _address: ["143", "override_time_zone", "64", "autoTimezone", "core.", "/export/core/"],
    )
    monkeypatch.setattr(
        replay_runners,
        "_binary_ascii_strings",
        lambda _path: ["/cgi-bin/api-get_dump_list", "/cgi-bin/api.values.post"],
    )
    state = _state(
        status="replay_ready",
        candidate_id="gs_web:0x155C4:FUN_000155c4:35:snprintf:s:0:0x80",
    ).with_updates(
        location={"address": "0x155C4", "function_name": "FUN_000155c4", "line_text": "snprintf(__s,0x80,fmt);"},
        sink={"name": "snprintf", "target_buffer": "__s"},
    )

    request = build_replay_requests([state], binary_path=binary, mode="qemu_user")[0]

    assert request.setup["routes"] == [{"method": "POST", "path": "/cgi-bin/api.values.post"}]
    assert request.input["form"]["P143"] == "1"
    assert request.input["form"]["Poverride_time_zone"] == "3600"


def test_qemu_user_replay_seeds_nvram_shim_and_preserves_form_case(tmp_path: Path, monkeypatch) -> None:
    capture = tmp_path / "env_capture"
    qemu = _script(
        tmp_path / "qemu-arm",
        "while [ \"$1\" ]; do\n"
        "  case \"$1\" in\n"
        "    -L) shift 2 ;;\n"
        "    -E) echo \"$2\" >> " + str(capture) + "; shift 2 ;;\n"
        "    -d) shift 2 ;;\n"
        "    -D) shift 2 ;;\n"
        "    *) break ;;\n"
        "  esac\n"
        "done\n"
        "echo ok\n",
    )
    compiler = _script(
        tmp_path / "arm-none-eabi-gcc",
        "out=\n"
        "while [ \"$1\" ]; do\n"
        "  if [ \"$1\" = -o ]; then shift; out=\"$1\"; fi\n"
        "  shift || break\n"
        "done\n"
        "mkdir -p \"$(dirname \"$out\")\"\n"
        ": > \"$out\"\n",
    )
    binary = _script(tmp_path / "arm_target", "echo target\n")
    rootfs = tmp_path / "rootfs"
    (rootfs / "usr" / "lib").mkdir(parents=True)
    monkeypatch.setenv("QEMU_USER_BIN", str(qemu))
    monkeypatch.setenv("REPLAY_ARM_CC", str(compiler))
    request = ReplayRequest(
        candidate_id="qemu-nvram-shim",
        mode="qemu_user",
        setup={
            "binary_path": str(binary),
            "rootfs_path": str(rootfs),
            "qemu_nvram": True,
            "auth": {"role": "admin", "session_id": "sid", "remote_addr": "127.0.0.1"},
            "config": {"DataStorage:143": "1"},
        },
        input={"form": {"Poverride_time_zone": "-999999999"}},
        expected_result={"sink_output_contains": "ok", "expect_crash": False},
    )

    result = run_replay_request(request, tmp_path / "replay")
    env_lines = set(capture.read_text().splitlines())

    assert result.result == "sink_reached_no_bug"
    assert "FORM_Poverride_time_zone=-999999999" in env_lines
    assert "COOKIE_session-identity=sid" in env_lines
    assert "NVRAM__session_id=sid" in env_lines
    assert "NVRAM_143=1" in env_lines
    assert any(path.endswith("qemu_rootfs_overlay/usr/lib/libnvram.so") for path in result.artifacts)


def test_qemu_user_pre_sink_crash_is_not_candidate_bug_observed(tmp_path: Path, monkeypatch) -> None:
    qemu = _script(
        tmp_path / "qemu-arm",
        "shift\n"
        "while [ \"$1\" ]; do\n"
        "  case \"$1\" in\n"
        "    -L) shift 2 ;;\n"
        "    -E) shift 2 ;;\n"
        "    -d) shift 2 ;;\n"
        "    -D) shift 2 ;;\n"
        "    *) break ;;\n"
        "  esac\n"
        "done\n"
        "echo startup crash >&2\n"
        "exit 139\n",
    )
    binary = _script(tmp_path / "arm_target", "echo target\n")
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)
    monkeypatch.setenv("QEMU_USER_BIN", str(qemu))
    request = ReplayRequest(
        candidate_id="qemu-presink-crash",
        mode="qemu_user",
        setup={"binary_path": str(binary), "rootfs_path": str(rootfs)},
        input={},
        expected_result={"sink_output_contains": "expected_sink_marker", "expect_crash": True},
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "crash_unclassified"
    assert result.sink_reached is False
    assert result.crash_observed is True
    assert result.bug_observed is False


def test_qemu_user_command_oracle_confirms_from_strace_exec_marker(tmp_path: Path, monkeypatch) -> None:
    qemu = _script(
        tmp_path / "qemu-arm",
        "trace=\n"
        "strace=0\n"
        "while [ \"$1\" ]; do\n"
        "  case \"$1\" in\n"
        "    -L) shift 2 ;;\n"
        "    -strace) strace=1; shift ;;\n"
        "    -E) shift 2 ;;\n"
        "    -d) shift 2 ;;\n"
        "    -D) shift; trace=\"$1\"; shift ;;\n"
        "    -dfilter) shift 2 ;;\n"
        "    -one-insn-per-tb) shift ;;\n"
        "    *) break ;;\n"
        "  esac\n"
        "done\n"
        "printf '%s\\n' '0x00001000: nop' > \"$trace\"\n"
        "if [ \"$strace\" = 1 ]; then echo '123 execve(\"/bin/sh\",[\"sh\",\"-c\",\"echo SEMANTIC_MARKER\"],0) = 0' >&2; fi\n",
    )
    binary = _script(tmp_path / "arm_target", "echo target\n")
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)
    monkeypatch.setenv("QEMU_USER_BIN", str(qemu))
    request = ReplayRequest(
        candidate_id="qemu-command-oracle",
        mode="qemu_user",
        setup={"binary_path": str(binary), "rootfs_path": str(rootfs)},
        input={},
        expected_result={
            "target_address": "0x1000",
            "expect_crash": False,
            "proof_oracle": {"kind": "command_effect", "marker": "SEMANTIC_MARKER"},
        },
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "confirmed"
    assert result.bug_observed is True
    assert result.crash_observed is False
    proof = result.control_result["proof_observation"]
    assert proof["status"] == "command_effect_observed"
    assert proof["syscall_observation"]["status"] == "command_exec_observed_with_replay_input"
    assert result.control_result["qemu_strace_enabled"] is True


def test_qemu_user_filesystem_oracle_confirms_escape_from_strace_path(tmp_path: Path, monkeypatch) -> None:
    qemu = _script(
        tmp_path / "qemu-arm",
        "trace=\n"
        "strace=0\n"
        "while [ \"$1\" ]; do\n"
        "  case \"$1\" in\n"
        "    -L) shift 2 ;;\n"
        "    -strace) strace=1; shift ;;\n"
        "    -E) shift 2 ;;\n"
        "    -d) shift 2 ;;\n"
        "    -D) shift; trace=\"$1\"; shift ;;\n"
        "    -dfilter) shift 2 ;;\n"
        "    -one-insn-per-tb) shift ;;\n"
        "    *) break ;;\n"
        "  esac\n"
        "done\n"
        "printf '%s\\n' '0x00001000: nop' > \"$trace\"\n"
        "if [ \"$strace\" = 1 ]; then echo '123 openat(AT_FDCWD,\"../secret.txt\",O_RDONLY) = 3' >&2; fi\n",
    )
    binary = _script(tmp_path / "arm_target", "echo target\n")
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)
    monkeypatch.setenv("QEMU_USER_BIN", str(qemu))
    request = ReplayRequest(
        candidate_id="qemu-path-oracle",
        mode="qemu_user",
        setup={"binary_path": str(binary), "rootfs_path": str(rootfs)},
        input={},
        expected_result={
            "target_address": "0x1000",
            "expect_crash": False,
            "proof_oracle": {"kind": "filesystem_read_escape"},
        },
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "confirmed"
    assert result.bug_observed is True
    proof = result.control_result["proof_observation"]
    assert proof["status"] == "filesystem_read_escape_observed"
    assert proof["syscall_observation"]["path_events"][0]["escape_reason"] == "parent_traversal"


def test_qemu_user_overflow_oracle_confirms_non_crashing_bug(tmp_path: Path, monkeypatch) -> None:
    qemu = _script(
        tmp_path / "qemu-arm",
        "trace=\n"
        "while [ \"$1\" ]; do\n"
        "  case \"$1\" in\n"
        "    -L) shift 2 ;;\n"
        "    -E) shift 2 ;;\n"
        "    -d) shift 2 ;;\n"
        "    -D) shift; trace=\"$1\"; shift ;;\n"
        "    -dfilter) shift 2 ;;\n"
        "    -one-insn-per-tb) shift ;;\n"
        "    *) break ;;\n"
        "  esac\n"
        "done\n"
        "cat > \"$trace\" <<'TRACE'\n"
        "IN:\n"
        "0x000155e0:  ebffd97b  bl       #0xbbd4\n"
        "R00=00000001 R01=00000028 R02=19999999 R03=00000001\n"
        "R04=00000001 R05=407ff867 R06=00000000 R07=407ffbb8\n"
        "R08=00023180 R09=00000000 R10=00023430 R11=00000000\n"
        "R12=00000028 R13=407ff720 R14=40d91c94 R15=000155e0\n"
        "PSR=60000010 -ZC- A usr32\n"
        "IN:\n"
        "0x000155e4:  e3e0307f  mvn      r3, #0x7f\n"
        "R00=00023228 R01=00000000 R02=40da622c R03=00000001\n"
        "R04=00000001 R05=407ff867 R06=00000000 R07=407ffbb8\n"
        "R08=00023180 R09=00000000 R10=00023430 R11=00000000\n"
        "R12=40da5ed0 R13=407ff720 R14=408221b4 R15=000155e4\n"
        "PSR=20000010 --C- A usr32\n"
        "IN:\n"
        "0x0001566c:  ebffd8bf  bl       #0xb970\n"
        "R00=00023228 R01=00000080 R02=00018bb0 R03=00018b95\n"
        "R04=00023228 R05=00023460 R06=00018b95 R07=3b9ac9ff\n"
        "R08=00023180 R09=00000000 R10=00023430 R11=00000000\n"
        "R12=3b9ac9c3 R13=407ff720 R14=00015658 R15=0001566c\n"
        "PSR=20000010 --C- A usr32\n"
        "TRACE\n"
        "echo ok\n"
    )
    binary = _script(tmp_path / "arm_target", "echo target\n")
    rootfs = tmp_path / "rootfs"
    (rootfs / "lib").mkdir(parents=True)
    monkeypatch.setenv("QEMU_USER_BIN", str(qemu))
    request = ReplayRequest(
        candidate_id="qemu-overflow-oracle",
        mode="qemu_user",
        setup={"binary_path": str(binary), "rootfs_path": str(rootfs)},
        input={},
        expected_result={
            "sink_address": "0x155c4",
            "expect_crash": False,
            "proof_oracle": {
                "kind": "bounded_write_overflow",
                "allocation_call_address": "0x155e0",
                "allocation_return_address": "0x155e4",
                "sink_call_address": "0x1566c",
                "allocation_size_register": "r0",
                "allocation_pointer_register": "r0",
                "sink_pointer_register": "r0",
                "sink_bound_register": "r1",
            },
        },
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "confirmed"
    assert result.sink_reached is True
    assert result.bug_observed is True
    assert result.crash_observed is False
    proof = result.control_result["proof_observation"]
    assert proof["status"] == "overflow_proven"
    assert proof["capacity_bytes"] == 1
    assert proof["write_bound_bytes"] == 128
    assert proof["allocation_pointer"] == "0x23228"
    assert proof["sink_pointer"] == "0x23228"
    assert proof["overflow_bytes"] == 127


def test_qemu_user_target_memory_observation_confirms_non_crashing_bug(tmp_path: Path, monkeypatch) -> None:
    qemu = _script(
        tmp_path / "qemu-arm",
        "proof=\n"
        "while [ \"$1\" ]; do\n"
        "  case \"$1\" in\n"
        "    -L) shift 2 ;;\n"
        "    -plugin)\n"
        "      proof=\"$(printf '%s' \"$2\" | sed -n 's/.*out=\\([^,]*\\).*/\\1/p')\"\n"
        "      shift 2 ;;\n"
        "    -E)\n"
        "      case \"$2\" in REPLAY_OVERFLOW_PROOF_PATH=*) proof=\"${2#REPLAY_OVERFLOW_PROOF_PATH=}\" ;; esac\n"
        "      shift 2 ;;\n"
        "    -d) shift 2 ;;\n"
        "    -D) shift 2 ;;\n"
        "    -dfilter) shift 2 ;;\n"
        "    -one-insn-per-tb) shift ;;\n"
        "    *) break ;;\n"
        "  esac\n"
        "done\n"
        "mkdir -p \"$(dirname \"$proof\")\"\n"
        "cat > \"$proof\" <<'JSON'\n"
        "{\"status\":\"out_of_bounds_write_observed\",\"bug_observed\":true,\"redzone_modified\":true,"
        "\"capacity_bytes\":1,\"snprintf_bound_bytes\":128,\"formatted_length\":15,"
        "\"bytes_written_including_nul\":16,\"overflow_bytes_observed\":15,"
        "\"allocation_pointer\":\"0x23228\",\"destination_pointer\":\"0x23228\"}\n"
        "JSON\n"
        "echo ok\n",
    )
    compiler = _script(
        tmp_path / "arm-none-eabi-gcc",
        "out=\n"
        "while [ \"$1\" ]; do\n"
        "  if [ \"$1\" = -o ]; then shift; out=\"$1\"; fi\n"
        "  shift || break\n"
        "done\n"
        "mkdir -p \"$(dirname \"$out\")\"\n"
        ": > \"$out\"\n",
    )
    binary = _script(tmp_path / "arm_target", "echo target\n")
    rootfs = tmp_path / "rootfs"
    (rootfs / "usr" / "lib").mkdir(parents=True)
    monkeypatch.setenv("QEMU_USER_BIN", str(qemu))
    monkeypatch.setenv("REPLAY_HOST_CC", str(compiler))
    monkeypatch.setenv("QEMU_PLUGIN_INCLUDE", str(tmp_path))
    monkeypatch.setattr(replay_runners, "_pkg_config_flags", lambda _package: ["-DGLIB_TEST_STUB=1"])
    (tmp_path / "qemu-plugin.h").write_text("")
    request = ReplayRequest(
        candidate_id="qemu-memory-oracle",
        mode="qemu_user",
        setup={"binary_path": str(binary), "rootfs_path": str(rootfs)},
        input={},
        expected_result={
            "sink_address": "0x155c4",
            "expect_crash": False,
            "proof_oracle": {
                "kind": "bounded_write_overflow",
                "observe_memory_write": True,
                "allocation_call_address": "0x155e0",
                "allocation_return_address": "0x155e4",
                "sink_call_address": "0x1566c",
                "sink_return_address": "0x15670",
            },
        },
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "confirmed"
    assert result.bug_observed is True
    assert result.crash_observed is False
    proof = result.control_result["proof_observation"]
    assert proof["status"] == "out_of_bounds_write_observed"
    assert proof["redzone_modified"] is True
    assert proof["overflow_bytes_observed"] == 15
    assert any(path.endswith("target_overflow_observation.json") for path in result.artifacts)
    assert any(path.endswith("qemu_memory_write_plugin.so") for path in result.artifacts)


def test_concolic_verdicts_import_as_qemu_replay_requests(tmp_path: Path, monkeypatch) -> None:
    candidate_id = "firmware:0x1000:func:7:sprintf:buf:0:unbounded"
    verdict_dir = tmp_path / "verdicts" / "firmware" / "firmware_0x1000_func"
    verdict_dir.mkdir(parents=True)
    (verdict_dir / "request.json").write_text(json.dumps({"candidate_id": candidate_id}))
    (verdict_dir / "replay.json").write_text(
        json.dumps(
            {
                "concrete_angr_replay": {
                    "status": "replayed",
                    "input_model": "stdin",
                    "target_loader_address": "0x1000",
                    "input_hex": "41424344",
                },
                "ghidra_pcode_replay": {"status": "reached", "reached_target": True},
            }
        )
    )
    (verdict_dir / "verdict.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "concolic_verdict": "overflow_witness",
                "backend": "angr",
                "request": {"binary_path": "/firmware/bin/demo", "target_address": "0x1000", "input_model": "stdin"},
                "witness": {"input_model": "stdin", "stdin_hex": "41424344"},
                "artifact_paths": ["firmware_0x1000_func/replay.json", "firmware_0x1000_func/verdict.json"],
            }
        )
    )

    observed_requests = []

    def fake_run_replay_request(request: ReplayRequest, output_dir: Path):
        observed_requests.append(request)
        candidate_dir = output_dir / "firmware_0x1000_func_7_sprintf_buf_0_unbounded"
        candidate_dir.mkdir(parents=True, exist_ok=True)
        request_path = candidate_dir / "request.json"
        request_path.write_text(json.dumps(request.to_dict()))
        result_path = candidate_dir / "result.json"
        result = replay_runners.ReplayResult(
            candidate_id=request.candidate_id,
            result="confirmed",
            mode=request.mode,
            sink_reached=True,
            bug_observed=True,
            crash_observed=False,
            control_result={"qemu": "ok"},
            artifacts=[str(request_path), str(result_path)],
        )
        replay_runners.write_replay_result(result, result_path)
        return result

    monkeypatch.setattr(replay_runners, "run_replay_request", fake_run_replay_request)

    results = import_concolic_replay_results(tmp_path / "verdicts", tmp_path / "replay")

    assert len(results) == 1
    assert results[0].candidate_id == candidate_id
    assert results[0].result == "confirmed"
    assert results[0].mode == "qemu_user"
    assert results[0].sink_reached is True
    assert observed_requests[0].input["stdin"] == "ABCD"
    assert observed_requests[0].input["input_hex"] == "41424344"
    assert (tmp_path / "replay" / "firmware_0x1000_func_7_sprintf_buf_0_unbounded" / "result.json").exists()

    skipped = import_concolic_replay_results(
        tmp_path / "verdicts",
        tmp_path / "filtered_replay",
        candidate_ids={"other:candidate"},
    )

    assert skipped == []
    assert not (tmp_path / "filtered_replay" / "firmware_0x1000_func_7_sprintf_buf_0_unbounded").exists()


def test_concolic_verdicts_import_as_native_for_host_elf(tmp_path: Path, monkeypatch) -> None:
    candidate_id = "host:0x1000:func:7:strcpy:buf:0:unbounded"
    verdict_dir = tmp_path / "verdicts" / "host" / "host_0x1000_func"
    verdict_dir.mkdir(parents=True)
    binary = tmp_path / "host_target"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    (verdict_dir / "replay.json").write_text(
        json.dumps(
            {
                "concrete_angr_replay": {
                    "status": "replayed",
                    "input_model": "argv",
                    "target_loader_address": "0x1000",
                    "input_hex": "41424344",
                }
            }
        )
    )
    (verdict_dir / "verdict.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "concolic_verdict": "overflow_witness",
                "backend": "angr",
                "request": {"binary_path": str(binary), "target_address": "0x1000", "input_model": "argv"},
                "witness": {"input_model": "argv", "argv_hex": ["41424344"]},
                "artifact_paths": ["host_0x1000_func/replay.json", "host_0x1000_func/verdict.json"],
            }
        )
    )
    monkeypatch.setattr(replay_runners, "_elf_machine", lambda _path: "Advanced Micro Devices X86-64")
    monkeypatch.setattr(replay_runners.platform, "machine", lambda: "x86_64")
    observed_modes = []

    def fake_run_replay_request(request: ReplayRequest, output_dir: Path):
        observed_modes.append(request.mode)
        candidate_dir = output_dir / "host_0x1000_func_7_strcpy_buf_0_unbounded"
        candidate_dir.mkdir(parents=True, exist_ok=True)
        result_path = candidate_dir / "result.json"
        result = replay_runners.ReplayResult(
            candidate_id=request.candidate_id,
            result="sink_reached_no_bug",
            mode=request.mode,
            sink_reached=True,
            bug_observed=False,
            crash_observed=False,
            control_result={},
            artifacts=[str(result_path)],
        )
        replay_runners.write_replay_result(result, result_path)
        return result

    monkeypatch.setattr(replay_runners, "run_replay_request", fake_run_replay_request)

    results = import_concolic_replay_results(tmp_path / "verdicts", tmp_path / "replay")

    assert len(results) == 1
    assert observed_modes == ["native"]
    assert results[0].mode == "native"


def test_qemu_user_tool_resolution_does_not_guess_arm_for_x86(tmp_path: Path, monkeypatch) -> None:
    qemu = _script(tmp_path / "qemu-arm", "exit 0\n")
    monkeypatch.setenv("PATH", str(qemu.parent))
    monkeypatch.setattr(replay_runners, "_elf_machine", lambda _path: "Advanced Micro Devices X86-64")
    request = ReplayRequest(
        candidate_id="x86-qemu",
        mode="qemu_user",
        setup={"binary_path": str(tmp_path / "target")},
        input={},
        expected_result={},
    )

    assert replay_runners._resolve_qemu_user_tool(request) == ""


def test_qemu_address_normalization_rejects_decompiler_line_decoration() -> None:
    assert replay_runners._normalize_address("0x42618C:line:86") == ""


def test_apply_replay_results_does_not_promote_concolic_only_overflow_artifact(tmp_path: Path) -> None:
    candidate_id = "host:0x1000:func:7:strcpy:buf:0:unbounded"
    state = _state(status="replay_ready", candidate_id=candidate_id)
    verdict_path = tmp_path / "proof" / "verdict.json"
    verdict_path.parent.mkdir(parents=True)
    verdict_path.write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "concolic_verdict": "overflow_witness",
                "backend": "angr",
                "sink_reached": True,
                "request": {"target_address": "0x1000", "sink_address": "0x1000", "input_model": "argv"},
                "witness": {"input_model": "argv", "argv_hex": ["41414141"]},
                "replay_result": {"concrete_angr_replay": {"status": "replayed"}},
            }
        )
    )
    result = replay_runners.ReplayResult(
        candidate_id=candidate_id,
        result="sink_not_reached",
        mode="native",
        sink_reached=False,
        bug_observed=False,
        crash_observed=False,
        control_result={},
        artifacts=[str(verdict_path)],
    )

    promoted, events, lift = apply_replay_results([state], [result])

    assert promoted[0].status == CandidateStatus.REPLAY_READY.value
    assert has_reportable_source_to_sink(promoted[0]) is False
    assert events == []
    assert lift == []


def test_concolic_import_accepts_process_ghidra_overflow_proof(tmp_path: Path, monkeypatch) -> None:
    candidate_id = "demo:0x1000:func:7:strcpy:buf:0:unbounded"
    verdict_dir = tmp_path / "verdicts" / "demo"
    verdict_dir.mkdir(parents=True)
    (verdict_dir / "request.json").write_text(json.dumps({"candidate_id": candidate_id}))
    _write_ghidra_process_proof(verdict_dir / "ghidra_dynamic_proof.json", candidate_id)
    (verdict_dir / "verdict.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "concolic_verdict": "overflow_witness",
                "backend": "angr",
                "request": {"binary_path": "/bin/demo", "target_address": "0x1000", "input_model": "argv"},
                "witness": {"input_model": "argv", "argv_hex": ["41414141"]},
                "ghidra_dynamic_proof": json.loads((verdict_dir / "ghidra_dynamic_proof.json").read_text()),
                "artifact_paths": ["request.json", "ghidra_dynamic_proof.json", "verdict.json"],
            }
        )
    )
    monkeypatch.setattr(
        replay_runners,
        "run_replay_request",
        lambda _request, _output_dir: pytest.fail("Ghidra process proof import must not require QEMU replay"),
    )

    results = import_concolic_replay_results(tmp_path / "verdicts", tmp_path / "replay")

    assert len(results) == 1
    assert results[0].result == "confirmed"
    assert results[0].mode == "ghidra_process"
    assert results[0].sink_reached is True
    assert any(path.endswith("ghidra_dynamic_proof.json") for path in results[0].artifacts)
    assert (tmp_path / "replay" / "demo_0x1000_func_7_strcpy_buf_0_unbounded" / "result.json").exists()


@pytest.mark.parametrize("native_confirmed", [False, True])
def test_service_ghidra_proof_requires_connected_native_crash(tmp_path: Path, native_confirmed: bool) -> None:
    candidate_id = f"service-{native_confirmed}:0x1000:main:7:recv:buf:0:512"
    verdict_dir = tmp_path / "verdicts" / str(native_confirmed)
    verdict_dir.mkdir(parents=True)
    proof_path = _write_ghidra_process_proof(
        verdict_dir / "ghidra_dynamic_proof.json",
        candidate_id,
        input_model="socket_service",
    )
    proof = json.loads(proof_path.read_text())
    proof["native_replay"] = {
        "status": "replayed" if native_confirmed else "timeout",
        "connected": native_confirmed,
        "crash_observed": native_confirmed,
    }
    proof_path.write_text(json.dumps(proof))
    (verdict_dir / "verdict.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "concolic_verdict": "overflow_witness",
                "backend": "ghidra",
                "request": {"binary_path": "/bin/service", "target_address": "0x1010", "input_model": "socket_service"},
                "witness": {"input_model": "socket_service", "argv_hex": ["41" * 512]},
                "ghidra_dynamic_proof": proof,
                "artifact_paths": ["ghidra_dynamic_proof.json", "verdict.json"],
            }
        )
    )

    result = import_concolic_replay_results(tmp_path / "verdicts", tmp_path / "replay")[0]

    assert result.result == ("confirmed" if native_confirmed else "blocked")
    assert result.bug_observed is native_confirmed


def test_imported_process_ghidra_oob_read_proof_survives_report(tmp_path: Path, monkeypatch) -> None:
    candidate_id = "demo:0x1000:main:7:memcpy_source_read:heartbeat_record_3:0:payload"
    candidate = _state(status="proof_ready", candidate_id=candidate_id).with_updates(
        vulnerability_type="out_of_bounds_read",
        location={"function_name": "main", "relative_path": "main.c", "line_number": 7, "address": "0x1000"},
        source={"kind": "attacker_input", "evidence": ["line 4: read(0, heartbeat_record, 8);"]},
        sink={"name": "memcpy_source_read", "target_buffer": "heartbeat_record[3:]", "operation_address": "0x1020"},
        type_facts={
            "capacity_bytes": 5,
            "capacity_source": "inferred_packet_slice_remaining",
            "capacity_basis": "heartbeat_record: inferred packet slice after 3 byte cursor advance, 5 bytes remain",
            "destination_kind": "stack",
            "write_relation": "symbolic_size",
            "verdict": "candidate",
            "source_to_sink_trace": {
                "schema_version": 2,
                "status": "complete",
                "attacker_control_reaches_sink_role": True,
                "entry_function": "main",
                "entry_surface_kind": "program_entry",
                "target_function": "main",
                "target_address": "0x1000",
                "sink_name": "memcpy_source_read",
                "call_path": ["main"],
                "input_model": "stdin",
                "argument_roles": [
                    {
                        "role": "write_size",
                        "expr": "payload",
                        "classification": "source_controlled",
                        "controlled": True,
                        "complete": True,
                    }
                ],
                "blockers": [],
            },
        },
    )
    verdict_dir = tmp_path / "verdicts" / "demo"
    verdict_dir.mkdir(parents=True)
    (verdict_dir / "request.json").write_text(json.dumps({"candidate_id": candidate_id}))
    _write_ghidra_process_proof(
        verdict_dir / "ghidra_dynamic_proof.json",
        candidate_id,
        input_model="stdin",
        status="oob_read_proven",
    )
    (verdict_dir / "verdict.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "concolic_verdict": "overflow_witness",
                "backend": "angr",
                "request": {"binary_path": "/bin/demo", "target_address": "0x1020", "input_model": "stdin"},
                "witness": {"input_model": "stdin", "stdin_hex": "0100204845415254"},
                "ghidra_dynamic_proof": json.loads((verdict_dir / "ghidra_dynamic_proof.json").read_text()),
                "artifact_paths": ["request.json", "ghidra_dynamic_proof.json", "verdict.json"],
            }
        )
    )
    monkeypatch.setattr(
        replay_runners,
        "run_replay_request",
        lambda _request, _output_dir: pytest.fail("Ghidra process proof import must not require QEMU replay"),
    )

    results = import_concolic_replay_results(tmp_path / "verdicts", tmp_path / "replay")
    replay_ready, _ = promote_for_replay(
        [candidate],
        request_artifacts={candidate_id: str(verdict_dir / "request.json")},
    )
    replay_confirmed, _, _ = apply_replay_results(replay_ready, results)
    reports = build_lean_reports(replay_confirmed)

    assert len(results) == 1
    assert results[0].result == "confirmed"
    assert results[0].mode == "ghidra_process"
    assert len(reports) == 1
    assert reports[0].vulnerability == "out_of_bounds_read"
    assert reports[0].proof_details["ghidra_dynamic_proof_status"] == "oob_read_proven"
    assert reports[0].proof_details["dynamic_oob_bytes"] == 27


def test_imported_function_harness_cursor_oob_proof_stays_non_reportable(tmp_path: Path) -> None:
    candidate_id = "tar_stripped:0x41F596:FUN_0041f596:220:cursor_limit_read:param_1_0_param_2:param_2:1"
    candidate = _state(status="proof_ready", candidate_id=candidate_id).with_updates(
        vulnerability_type="out_of_bounds_read",
        location={
            "function_name": "FUN_0041f596",
            "relative_path": "0041F596_FUN_0041f596.c",
            "line_number": 220,
            "address": "0x41f596",
        },
        source={"kind": "attacker_input", "call_path": ["FUN_00430bd3", "FUN_0041e2e7", "FUN_0041f596"]},
        sink={"kind": "source_read", "name": "cursor_limit_read", "target_buffer": "param_1[0:param_2]"},
        type_facts={
            "capacity_bytes": 0,
            "capacity_source": "function_length_argument",
            "capacity_basis": "cursor limit local_20 = param_1 + param_2",
            "destination_kind": "source_buffer",
            "write_relation": "symbolic_read_offset",
            "verdict": "candidate",
            "overflow_condition": (
                "base-256 marker branch advances local_18 before reading *local_18; "
                "the pbVar2 == local_20 limit check occurs after that byte read"
            ),
            "static_candidate": {
                "sink": "cursor_limit_read",
                "destination_kind": "source_buffer",
                "classification_trace": {
                    "cursor_limit_read": {
                        "cursor": "local_18",
                        "limit": "local_20",
                        "length_param": "param_2",
                    },
                    "object_resolution": {"destination_kind": "source_buffer"},
                },
            },
            "source_to_sink_trace": {
                "schema_version": 2,
                "status": "complete",
                "attacker_control_reaches_sink_role": True,
                "entry_function": "FUN_00430bd3",
                "entry_surface_kind": "program_entry",
                "target_function": "FUN_0041f596",
                "target_address": "0x41f596",
                "sink_name": "cursor_limit_read",
                "call_path": ["FUN_00430bd3", "FUN_0041e2e7", "FUN_0041f596"],
                "input_model": "argv",
                "argument_roles": [
                    {
                        "role": "write_offset",
                        "expr": "param_2",
                        "classification": "parameter_controlled",
                        "controlled": True,
                        "complete": True,
                    },
                    {
                        "role": "destination_pointer",
                        "expr": "param_1[0:param_2]",
                        "classification": "parameter_controlled",
                        "controlled": True,
                        "complete": True,
                    },
                ],
                "propagation_path": [
                    {"kind": "function", "function": "FUN_00430bd3", "role": "entry"},
                    {"kind": "function", "function": "FUN_0041e2e7", "role": "intermediate"},
                    {"kind": "function", "function": "FUN_0041f596", "role": "sink_function"},
                ],
                "blockers": [],
            },
        },
    )
    verdict_dir = tmp_path / "verdicts" / "tar"
    verdict_dir.mkdir(parents=True)
    (verdict_dir / "request.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "input_model": "function_harness",
                "target_address": "0x41fbda",
                "sink_address": "0x41fbda",
            }
        )
    )
    proof = _write_ghidra_function_harness_oob_proof(verdict_dir / "ghidra_dynamic_proof.json", candidate_id)
    (verdict_dir / "verdict.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "concolic_verdict": "overflow_witness",
                "backend": "angr",
                "request": {
                    "binary_path": "/bin/tar",
                    "target_address": "0x41fbda",
                    "input_model": "function_harness",
                },
                "witness": {"input_model": "function_harness", "function_args": {"arg_count": 7}},
                "ghidra_dynamic_proof": json.loads(proof.read_text()),
                "artifact_paths": ["request.json", "ghidra_dynamic_proof.json", "verdict.json"],
            }
        )
    )

    results = import_concolic_replay_results(tmp_path / "verdicts", tmp_path / "replay")
    request_refs = {candidate_id: next(path for path in results[0].artifacts if Path(path).name == "request.json")}
    replay_ready, _ = promote_for_replay([candidate], request_artifacts=request_refs)
    replay_confirmed, _, _ = apply_replay_results(replay_ready, results)
    trace = build_source_to_sink_trace(replay_confirmed[0])
    reports = build_lean_reports(replay_confirmed)

    assert results[0].result == "confirmed"
    assert results[0].mode == "ghidra_function_harness"
    assert any(path.endswith("ghidra_dynamic_proof.json") for path in results[0].artifacts)
    assert replay_confirmed[0].status == "replay_confirmed"
    assert trace.status == "blocked"
    assert trace.blockers == ["boundary_replay_missing"]
    assert reports == []


def test_imported_function_harness_heap_overflow_proof_stays_non_reportable(tmp_path: Path) -> None:
    candidate_id = "demo:0x1000:copy_name:9:strcpy:heap_buf:0:unbounded"
    candidate = _state(status="proof_ready", candidate_id=candidate_id).with_updates(
        vulnerability_type="heap_overflow",
        location={"function_name": "copy_name", "relative_path": "demo.c", "line_number": 9, "address": "0x1000"},
        source={"kind": "attacker_input", "call_path": ["main", "copy_name"]},
        sink={"kind": "copy", "name": "strcpy", "target_buffer": "heap_buf", "operation_address": "0x1020"},
        type_facts={
            "capacity_bytes": 16,
            "destination_kind": "heap",
            "write_relation": "unbounded",
            "verdict": "unbounded",
            "overflow_condition": "strcpy writes beyond the allocated heap buffer",
            "static_candidate": {"sink": "strcpy", "destination_kind": "heap"},
            "source_to_sink_trace": {
                "schema_version": 2,
                "status": "complete",
                "attacker_control_reaches_sink_role": True,
                "entry_function": "main",
                "entry_surface_kind": "program_entry",
                "target_function": "copy_name",
                "target_address": "0x1000",
                "sink_name": "strcpy",
                "call_path": ["main", "copy_name"],
                "input_model": "argv",
                "argument_roles": [
                    {
                        "role": "write_source",
                        "expr": "argv[1]",
                        "classification": "source_controlled",
                        "controlled": True,
                        "complete": True,
                    }
                ],
                "propagation_path": [
                    {"kind": "function", "function": "main", "role": "entry"},
                    {"kind": "function", "function": "copy_name", "role": "sink_function"},
                ],
                "blockers": [],
            },
        },
    )
    verdict_dir = tmp_path / "verdicts" / "heap"
    verdict_dir.mkdir(parents=True)
    (verdict_dir / "request.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "input_model": "function_harness",
                "target_address": "0x1020",
                "sink_address": "0x1020",
            }
        )
    )
    proof = _write_ghidra_function_harness_overflow_proof(verdict_dir / "ghidra_dynamic_proof.json", candidate_id)
    (verdict_dir / "verdict.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "concolic_verdict": "overflow_witness",
                "backend": "angr",
                "request": {
                    "binary_path": "/bin/demo",
                    "target_address": "0x1020",
                    "input_model": "function_harness",
                },
                "witness": {"input_model": "function_harness", "function_args": {"arg_count": 2}},
                "ghidra_dynamic_proof": json.loads(proof.read_text()),
                "artifact_paths": ["request.json", "ghidra_dynamic_proof.json", "verdict.json"],
            }
        )
    )

    results = import_concolic_replay_results(tmp_path / "verdicts", tmp_path / "replay")
    request_refs = {candidate_id: next(path for path in results[0].artifacts if Path(path).name == "request.json")}
    replay_ready, _ = promote_for_replay([candidate], request_artifacts=request_refs)
    replay_confirmed, _, _ = apply_replay_results(replay_ready, results)
    reports = build_lean_reports(replay_confirmed)

    assert results[0].result == "confirmed"
    assert results[0].mode == "ghidra_function_harness"
    assert replay_confirmed[0].status == "replay_confirmed"
    assert reports == []


def test_function_harness_overflow_proof_requires_positive_overrun(tmp_path: Path) -> None:
    candidate_id = "demo:0x1000:copy_name:9:strcpy:heap_buf:0:unbounded"
    proof = _write_ghidra_function_harness_overflow_proof(
        tmp_path / "replay" / "heap" / "ghidra_dynamic_proof.json",
        candidate_id,
    )
    payload = json.loads(proof.read_text())
    payload["overflow_bytes"] = 0
    proof.write_text(json.dumps(payload))
    candidate = _state(status="replay_confirmed", candidate_id=candidate_id).with_updates(
        vulnerability_type="heap_overflow",
        sink={"name": "strcpy", "target_buffer": "heap_buf"},
        type_facts={
            **dict(_state().type_facts),
            "destination_kind": "heap",
            "static_candidate": {"sink": "strcpy", "destination_kind": "heap"},
        },
        replay_artifacts=[str(proof)],
    )

    assert build_lean_reports([candidate]) == []


def test_imported_process_input_provenance_survives_reports(tmp_path: Path) -> None:
    candidate_id = "demo:0x1000:func:7:strcpy:buf:0:unbounded"
    base_candidate = _state(status="proof_ready", candidate_id=candidate_id)
    candidate = base_candidate.with_updates(
        type_facts={
            **dict(base_candidate.type_facts),
            "static_candidate": {
                "evidence_sources": [
                    "source_read_wrapper_call:heartbeat_wrapper->tls1_process_heartbeat",
                    "source_read_wrapper_call:heartbeat_outer->heartbeat_wrapper",
                ]
            },
        }
    )
    verdict_dir = tmp_path / "verdicts" / "demo"
    verdict_dir.mkdir(parents=True)
    (verdict_dir / "request.json").write_text(json.dumps({"candidate_id": candidate_id}))
    evidence = {
        "mode_flag": "w",
        "file_seed_reason": "zip_format_text",
        "decompile_source_file": "/exports/00101000_main.c",
    }
    proof_path = _write_ghidra_process_proof(
        verdict_dir / "ghidra_dynamic_proof.json",
        candidate_id,
        input_model="argv_file_stdin",
        process_input_source="inferred_from_entry_decompile",
        process_input_evidence=evidence,
    )
    proof_payload = json.loads(proof_path.read_text())
    proof_payload["process_input_setup"].update(
        {
            "stdin_input_hex": "2a2a0a",
            "argv_values": ["program", "-w"],
        }
    )
    proof_path.write_text(json.dumps(proof_payload))
    (verdict_dir / "verdict.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "concolic_verdict": "overflow_witness",
                "backend": "angr",
                "request": {"binary_path": "/bin/demo", "target_address": "0x1000", "input_model": "argv_file_stdin"},
                "witness": {"input_model": "argv_file_stdin", "stdin_hex": "41414141"},
                "ghidra_dynamic_proof": json.loads((verdict_dir / "ghidra_dynamic_proof.json").read_text()),
                "artifact_paths": ["request.json", "ghidra_dynamic_proof.json", "verdict.json"],
            }
        )
    )

    results = import_concolic_replay_results(tmp_path / "verdicts", tmp_path / "replay")
    request_refs = {candidate_id: next(path for path in results[0].artifacts if Path(path).name == "request.json")}
    replay_ready, _ = promote_for_replay([candidate], request_artifacts=request_refs)
    replay_confirmed, _, _ = apply_replay_results(replay_ready, results)
    reports = build_lean_reports(replay_confirmed)
    written = write_lean_reports(reports, tmp_path / "report")
    bundles = write_vendor_evidence_bundles(replay_confirmed, tmp_path / "vendor")

    assert len(reports) == 1
    assert reports[0].proof_details["process_input_source"] == "inferred_from_entry_decompile"
    assert reports[0].proof_details["process_input_inferred"] is True
    assert reports[0].proof_details["process_input_file_seed_reason"] == "zip_format_text"
    assert reports[0].proof_details["process_input_decompile_source_file"] == "/exports/00101000_main.c"
    assert reports[0].proof_details["bug_bounty_evidence"]["concrete_poc"] == {
        "source": "ghidra_dynamic_proof.process_input_setup",
        "input_model": "argv_file_stdin",
        "stdin_input_hex": "2a2a0a",
        "argv_values": ["program", "-w"],
        "process_input_source": "inferred_from_entry_decompile",
        "process_input_evidence": evidence,
    }
    assert (
        reports[0].proof_details["source_read_wrapper_chain_text"]
        == "heartbeat_outer -> heartbeat_wrapper -> tls1_process_heartbeat"
    )
    rendered = Path(written[reports[0].candidate_id]).read_text()
    assert "process_input_source: `inferred_from_entry_decompile`" in rendered
    assert "process_input_file_seed_reason: `zip_format_text`" in rendered
    assert "source_read_wrapper_chain_text: `heartbeat_outer -> heartbeat_wrapper -> tls1_process_heartbeat`" in rendered
    vendor_rendered = bundles[0].report_path.read_text()
    assert "Process input source: `inferred_from_entry_decompile`" in vendor_rendered
    assert "File seed reason: `zip_format_text`" in vendor_rendered
    assert "Decompile source file: `/exports/00101000_main.c`" in vendor_rendered
    assert "Source-read wrapper chain: `heartbeat_outer -> heartbeat_wrapper -> tls1_process_heartbeat`" in vendor_rendered


def test_semantic_concolic_import_blocks_function_anchor_targets(tmp_path: Path) -> None:
    candidate_id = "semantic:cmd"
    verdict_dir = tmp_path / "verdicts" / "semantic_cmd"
    verdict_dir.mkdir(parents=True)
    (verdict_dir / "replay.json").write_text(
        json.dumps(
            {
                "concrete_angr_replay": {
                    "status": "replayed",
                    "input_model": "stdin",
                    "target_loader_address": "0x1000",
                    "input_hex": "41424344",
                },
                "ghidra_pcode_replay": {"status": "unsupported"},
            }
        )
    )
    (verdict_dir / "verdict.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "concolic_verdict": "target_reached",
                "backend": "angr",
                "request": {"binary_path": "/firmware/bin/demo", "target_address": "0x1000", "input_model": "stdin"},
                "witness": {"input_model": "stdin", "stdin_hex": "41424344"},
            }
        )
    )
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "semantic_cmd.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "deterministic_candidate": {
                    "candidate_id": candidate_id,
                    "vulnerability_type": "command_injection",
                    "address": "0x1000",
                    "operation_address": "0x1000",
                    "sink": "system",
                },
                "location": {"address": "0x1000", "function_name": "FUN_00001000"},
                "sink": {"name": "system"},
                "type_facts": {
                    "semantic_seed": {"seed_id": "cmd", "vulnerability_type": "command_injection"},
                    "replay_hints": {
                        "mode": "qemu_user",
                        "expected_result": {"proof_oracle": {"kind": "command_effect"}},
                    },
                },
            }
        )
    )

    results = import_concolic_replay_results(tmp_path / "verdicts", tmp_path / "replay", evidence_dir=evidence_dir)

    assert len(results) == 1
    assert results[0].result == "blocked"
    assert "concrete sink callsite" in results[0].control_result["reason"]
    assert (tmp_path / "replay" / "semantic_cmd" / "blocked.json").exists()


def test_qemu_semantic_pre_target_crash_is_not_replay_failure() -> None:
    request = ReplayRequest(
        candidate_id="semantic:file-write",
        mode="qemu_user",
        setup={},
        input={"argv": ["payload"]},
        expected_result={"proof_oracle": {"kind": "filesystem_write_escape", "syscall_observation": True}},
    )
    result = replay_runners._classify_process_result(
        request,
        {
            "returncode": -11,
            "stderr": "qemu: uncaught target signal 11 (Segmentation fault) - core dumped",
            "stdout": "",
            "trace_reached_expected_address": False,
            "proof_observation": {
                "kind": "filesystem_write_escape",
                "bug_observed": False,
                "sink_reached": False,
            },
        },
        artifacts=["request.json", "qemu_user_transcript.json"],
    )

    assert result.result == "sink_not_reached"
    assert result.crash_observed is False
    assert result.control_result["pre_target_crash_observed"] is True


def test_semantic_oracle_requires_bug_observation_not_just_sink_reach() -> None:
    request = ReplayRequest(
        candidate_id="semantic:cmd",
        mode="qemu_user",
        setup={},
        input={"argv": ["payload"]},
        expected_result={"proof_oracle": {"kind": "command_effect", "syscall_observation": True}},
    )
    result = replay_runners._classify_process_result(
        request,
        {
            "returncode": 0,
            "stderr": "",
            "stdout": "",
            "trace_reached_expected_address": True,
            "proof_observation": {
                "kind": "command_effect",
                "sink_reached": True,
                "bug_observed": False,
            },
        },
        artifacts=["request.json", "qemu_user_transcript.json"],
    )

    assert result.result == "sink_reached_no_bug"
    assert result.sink_reached is True
    assert result.bug_observed is False
    assert result.crash_observed is False


def test_concolic_file_witness_materializes_for_qemu(tmp_path: Path) -> None:
    replay_input = replay_runners._concolic_witness_replay_input(
        {
            "input_model": "file",
            "file_inputs_hex": {"concolic_input": "41424344"},
        },
        {},
        {"input_model": "file"},
    )

    artifacts = replay_runners._materialize_qemu_input_files(replay_input, tmp_path)

    assert replay_input["argv"] == [str((tmp_path / "qemu_input_files" / "concolic_input").resolve())]
    assert Path(artifacts[0]).read_bytes() == b"ABCD"


def test_toolchain_all_includes_proof_and_derives_proof_budget_from_reportable_capacity(tmp_path: Path) -> None:
    assert "proof" in toolchain_cli._parse_stages("all")
    assert toolchain_cli._parse_stages("proof") == {"proof"}

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "large_but_bounded.json").write_text(
        json.dumps(
            {
                "candidate_id": "bounded",
                "deterministic_candidate": {
                    "sink": "strcpy",
                    "destination_kind": "stack",
                    "capacity_bytes": 10000,
                    "write_size_bytes": 1,
                    "write_relation": "bounded",
                    "verdict": "safe",
                },
            }
        )
    )
    (evidence_dir / "overflow.json").write_text(
        json.dumps(
            {
                "candidate_id": "overflow",
                "deterministic_candidate": {
                    "sink": "strcpy",
                    "destination_kind": "stack",
                    "capacity_bytes": 1024,
                    "write_size_bytes": 0,
                    "write_relation": "unbounded",
                    "verdict": "unbounded",
                },
            }
        )
    )

    assert toolchain_cli._derive_proof_symbolic_bytes(evidence_dir, max_bytes=4096) == 1025


def test_toolchain_proof_forwards_complete_candidate_set_to_isolated_workers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    candidate_ids = ("demo:first", "demo:second", "demo:third")
    for candidate_id in candidate_ids:
        (evidence_dir / f"{candidate_id.replace(':', '_')}.json").write_text(
            json.dumps({"candidate_id": candidate_id, "deterministic_candidate": {"capacity_bytes": 16}}),
            encoding="utf-8",
        )
    captured = {}

    def fake_run(evidence_path, **kwargs):
        captured.update(kwargs)
        return ConcolicRunResult(
            output_dir=kwargs["output_dir"],
            eligible_count=len(candidate_ids),
            scheduled_count=len(candidate_ids),
            attempted_count=len(candidate_ids),
        )

    monkeypatch.setattr(toolchain_cli, "run_concolic_evidence_dir", fake_run)
    proof_dir = tmp_path / "proof"
    toolchain_cli._run_concolic_proof_stage(
        binary_path=tmp_path / "binary",
        export_dir=tmp_path / "export",
        evidence_dir=evidence_dir,
        proof_dir=proof_dir,
        args=SimpleNamespace(
            proof_target_candidate_id="",
            proof_symbolic_bytes=32,
            proof_max_symbolic_bytes=4096,
            proof_backend="angr",
            proof_timeout_seconds=10.0,
            proof_dynamic_max_steps=1000,
            ghidra_dir=None,
            overwrite=False,
            proof_jobs=2,
            proof_memory_limit_mb=2048,
        ),
        artifact_index=ArtifactIndex(),
        target_candidate_ids=candidate_ids,
    )

    assert captured["target_candidate_ids"] == candidate_ids
    assert captured["isolate_candidates"] is True
    assert captured["jobs"] == 2
    assert captured["memory_limit_mb"] == 2048
    assert "target_selector" not in captured
    assert "target_limit" not in captured


def test_candidate_extraction_recovers_adjacent_bss_global_extent(tmp_path: Path) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    source = "void copy_name(char *src) {\n    strcpy(&DAT_00401000,src);\n}\n"
    (export_dir / "copy_name.c").write_text(source)
    records = [
        _record(
            name="copy_name",
            address="0x401100",
            ordinal=0,
            relative_path="copy_name.c",
            text=source,
            global_refs=[
                {
                    "address": "0x401000",
                    "label": "DAT_00401000",
                    "var_display": "DAT_00401000",
                    "block": ".bss",
                    "size_bytes": 1,
                    "destination_kind": "global",
                    "capacity_source": "ghidra_data_reference",
                },
                {
                    "address": "0x401004",
                    "label": "DAT_00401004",
                    "var_display": "DAT_00401004",
                    "block": ".bss",
                    "size_bytes": 1,
                    "destination_kind": "global",
                    "capacity_source": "ghidra_data_reference",
                },
                {
                    "address": "0x401400",
                    "label": "DAT_00401400",
                    "var_display": "DAT_00401400",
                    "block": ".bss",
                    "size_bytes": 4,
                    "destination_kind": "global",
                    "capacity_source": "ghidra_data_reference",
                },
            ],
        )
    ]
    manifest = Manifest(
        binary="global-demo",
        generated_at="2026-05-15T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=records,
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))

    loaded_manifest, nodes = load_function_nodes(export_dir)
    candidates = extract_static_candidates(loaded_manifest, nodes)
    candidate = next(item for item in candidates if item.target_buffer == "DAT_00401000")

    assert candidate.capacity_bytes == 1024
    assert candidate.capacity_source == "ghidra_adjacent_global_extent"
    assert candidate.destination_kind == "global"


def test_native_replay_materializes_long_argv_payload_as_existing_path(tmp_path: Path) -> None:
    executable = _script(
        tmp_path / "path_replay.sh",
        "test -f \"$1\" || { echo missing-file >&2; exit 2; }\n"
        "printf '%s\\n' vulnerable_copy\n"
        "exit 139\n",
    )
    request = ReplayRequest(
        candidate_id="long-path",
        mode="native",
        setup={"binary_path": str(executable), "function_name": "vulnerable_copy", "sink": "strcpy"},
        input={"argv": ["A" * 600], "payload_length": 600, "argv_materialization": "existing_long_path"},
        expected_result={"sink_output_contains": "vulnerable_copy", "expect_crash": True},
    )

    result = run_replay_request(request, tmp_path / "replay")
    transcript = json.loads((tmp_path / "replay" / "long-path" / "native_transcript.json").read_text())
    materialized_path = Path(transcript["argv"][1])

    assert result.result == "confirmed"
    assert materialized_path.exists()
    assert len(str(materialized_path)) >= 600
    assert transcript["materialized_argv"][0]["requested_length"] == 600
    assert "File name too long" not in transcript["stderr"]


def test_promotion_gates_and_lean_reports_require_replay(tmp_path: Path) -> None:
    executable = _script(tmp_path / "confirmed.sh", "echo vulnerable_copy\n echo '*** buffer overflow detected ***' >&2\n exit 134\n")
    candidate = _state(status="candidate")
    proof_ready, proof_events, _ = promote_proof_ready([candidate])
    requests = build_replay_requests(proof_ready, binary_path=executable, mode="native")
    request_refs = {request.candidate_id: str(tmp_path / "replay" / request.candidate_id / "request.json") for request in requests}
    replay_ready, replay_ready_events = promote_for_replay(proof_ready, request_artifacts=request_refs)
    results = [run_replay_request(requests[0], tmp_path / "replay")]
    replay_confirmed, replay_events, _ = apply_replay_results(replay_ready, results)
    proof_path = _write_ghidra_process_proof(
        tmp_path / "replay" / candidate.candidate_id / "ghidra_dynamic_proof.json",
        candidate.candidate_id,
        input_model="argv_file_stdin",
    )
    replay_confirmed = [
        replay_confirmed[0].with_updates(replay_artifacts=[*replay_confirmed[0].replay_artifacts, str(proof_path)])
    ]

    assert proof_ready[0].status == "proof_ready"
    assert replay_ready[0].status == "replay_ready"
    assert replay_confirmed[0].status == "replay_confirmed"
    assert build_lean_reports([_state(status="candidate")]) == []
    assert build_lean_reports([_state(status="proof_ready")]) == []
    assert build_lean_reports([_state(status="replay_ready")]) == []

    reports = build_lean_reports(replay_confirmed)
    written = write_lean_reports(reports, tmp_path / "report")
    report_ready, report_events = promote_for_report(
        replay_confirmed,
        report_artifacts={reports[0].candidate_id: str(written[reports[0].candidate_id])},
    )

    assert reports
    assert reports[0].proof_details["process_input_model"] == "argv_file_stdin"
    assert report_ready[0].status == "report_ready"
    assert proof_events and replay_ready_events and replay_events and report_events


def test_artifact_confirmed_process_proof_can_enter_replay_from_refinement(tmp_path: Path) -> None:
    candidate = _state(status="needs_refinement", candidate_id="lifetime-candidate").with_updates(
        blockers=["same_object_identity_unproven"],
        proof_obligations=[
            {
                "obligation_id": "lifetime-candidate:lifetime",
                "description": "prove repeated release",
                "condition": "same object reaches the sink twice",
                "status": "open",
            }
        ],
    )
    request_path = tmp_path / "verdicts" / "lifetime-candidate" / "request.json"
    request_path.parent.mkdir(parents=True)
    request_path.write_text("{}")

    unchanged, unchanged_events = promote_for_replay(
        [candidate],
        request_artifacts={candidate.candidate_id: str(request_path)},
    )
    promoted, events = promote_for_replay(
        [candidate],
        request_artifacts={candidate.candidate_id: str(request_path)},
        artifact_confirmed_candidate_ids=[candidate.candidate_id],
    )

    assert unchanged[0].status == "needs_refinement"
    assert unchanged_events == []
    assert promoted[0].status == "replay_ready"
    assert promoted[0].blockers == []
    assert promoted[0].proof_obligations[0]["status"] == "satisfied"
    assert promoted[0].proof_obligations[0]["evidence_refs"] == [str(request_path)]
    assert events[0].reason == "artifact_confirmed_process_proof_available"


def test_proof_gate_requires_causal_input_evidence() -> None:
    unsupported = _state(status="candidate").with_updates(
        type_facts={"write_relation": "unbounded", "verdict": "unbounded"},
        source={"kind": "attacker_input", "expression": "input_buffer"},
    )
    supported = unsupported.with_updates(
        candidate_id="supported",
        type_facts={
            "write_relation": "unbounded",
            "verdict": "unbounded",
            "entrypoint_derivation": {
                "status": "derived",
                "process_input_supported": True,
                "entry_address": "0x1000",
            },
            "static_candidate": {
                "classification_trace": {
                    "source_to_write": {
                        "roles": {
                            "write_source": {
                                "classification": "source_controlled",
                                "complete": True,
                            }
                        }
                    }
                }
            },
        },
    )
    incidental_process_input = supported.with_updates(
        candidate_id="incidental",
        type_facts={
            **supported.type_facts,
            "static_candidate": {
                "classification_trace": {
                    "source_to_write": {
                        "roles": {
                            "write_source": {
                                "classification": "parameter_controlled",
                                "complete": True,
                            }
                        }
                    }
                }
            },
        },
    )

    promoted, events, _ = promote_proof_ready([unsupported, incidental_process_input, supported])

    assert [state.status for state in promoted] == ["candidate", "candidate", "proof_ready"]
    assert [event.candidate_id for event in events] == ["supported"]


def test_memory_proof_gate_requires_exact_operation_distinct_from_function_entry() -> None:
    unresolved = _state(status="candidate").with_updates(
        candidate_id="unresolved",
        sink={"name": "strcpy", "target_buffer": "buf"},
    )
    function_entry = unresolved.with_updates(
        candidate_id="function-entry",
        sink={"name": "strcpy", "target_buffer": "buf", "operation_address": "0x1000"},
        location={**unresolved.location, "address": "0x1000"},
    )
    exact = unresolved.with_updates(
        candidate_id="exact",
        sink={"name": "strcpy", "target_buffer": "buf", "operation_address": "0x1010"},
        location={**unresolved.location, "address": "0x1000"},
    )

    promoted, events, _ = promote_proof_ready([unresolved, function_entry, exact])

    assert [state.status for state in promoted] == ["candidate", "candidate", "proof_ready"]
    assert [event.candidate_id for event in events] == ["exact"]


def test_semantic_token_name_alone_does_not_satisfy_proof_gate() -> None:
    state = _state(status="candidate").with_updates(
        vulnerability_type="path_traversal",
        type_facts={"path_expr": "input_path"},
        proof_obligations=[{"status": "satisfied"}],
    )

    promoted, events, _ = promote_proof_ready([state])

    assert promoted[0].status == "candidate"
    assert events == []


def test_report_gate_requires_source_to_sink_trace_or_override(tmp_path: Path) -> None:
    replay_dir = tmp_path / "replay" / "cand-1"
    replay_dir.mkdir(parents=True)
    request_path = replay_dir / "request.json"
    result_path = replay_dir / "result.json"
    report_path = tmp_path / "report.md"
    request_path.write_text(json.dumps({"candidate_id": "cand-1", "mode": "native", "input": {"argv": ["A" * 64]}}))
    result_path.write_text(
        json.dumps(
            {
                "candidate_id": "cand-1",
                "result": "confirmed",
                "mode": "native",
                "sink_reached": True,
                "bug_observed": True,
                "crash_observed": True,
                "control_result": {},
                "artifacts": [str(request_path)],
            }
        )
    )
    report_path.write_text("report")
    state = _state(status="replay_confirmed", candidate_id="cand-1").with_updates(
        type_facts={
            "capacity_bytes": 16,
            "write_relation": "unbounded",
            "verdict": "unbounded",
            "overflow_condition": "strcpy has no destination bound",
        },
        replay_artifacts=[str(request_path)],
    )

    report_ready, events = promote_for_report([state], report_artifacts={"cand-1": str(report_path)})

    assert build_lean_reports([state]) == []
    assert report_ready[0].status == "replay_confirmed"
    assert events == []


def test_source_to_sink_trace_records_argument_roles_and_propagation(tmp_path: Path) -> None:
    proof_path = _write_ghidra_process_proof(
        tmp_path / "replay" / "cand-env" / "ghidra_dynamic_proof.json",
        "cand-env",
        input_model="env",
    )
    state = _state(status="replay_confirmed", candidate_id="cand-env").with_updates(
        replay_artifacts=[str(proof_path)],
        type_facts={
            "capacity_bytes": 16,
            "destination_kind": "stack",
            "write_relation": "unbounded",
            "verdict": "unbounded",
            "source_to_sink_trace": {
                "schema_version": 2,
                "status": "complete",
                "attacker_control_reaches_sink_role": True,
                "entry_function": "main",
                "entry_surface_kind": "program_entry",
                "target_function": "copy_env",
                "target_address": "0x1200",
                "sink_name": "strcpy",
                "call_path": ["main", "load_env", "copy_env"],
                "input_model": "env",
                "controlled_roles": ["write_source:source_controlled"],
                "execution_limitations": [
                    {"kind": "async_event_loop", "function": "main", "callee": "epoll_wait"},
                ],
                "blockers": [],
                "evidence": {
                    "input_observations": [{"callee": "getenv", "address": "0x1010", "variable": "PAYLOAD"}],
                    "source_to_write_roles": {
                        "write_source": {
                            "role": "write_source",
                            "expr": "payload",
                            "classification": "source_controlled",
                            "complete": True,
                            "evidence": ["payload receives getenv(\"PAYLOAD\")"],
                        },
                        "destination_pointer": {
                            "role": "destination_pointer",
                            "expr": "buf",
                            "classification": "internal_local",
                            "complete": True,
                        },
                    },
                },
            },
            "classification_trace": {
                "bounds": {
                    "rejected": [{"source": "guard", "relation": "missing upper bound", "reason": "copy is unbounded"}],
                },
                "guards": {"accepted": [], "rejected": ["if (payload) strcpy(buf, payload);"]},
                "aliases": ["payload_alias"],
            },
        },
    )

    trace = build_source_to_sink_trace(state).to_dict()

    assert trace["artifact_kind"] == "source_to_sink_trace"
    assert trace["schema_version"] == 2
    assert trace["status"] == "proven"
    assert trace["confidence"] == "proven"
    assert trace["input_model"] == "env"
    assert trace["sink_argument"]["role"] == "write_source"
    assert trace["sink_argument"]["expr"] == "payload"
    assert trace["propagation_path"][-1]["function"] == "copy_env"
    assert trace["source_artifacts"][0]["callee"] == "getenv"
    assert trace["bounds_checks"][0]["relation"] == "missing upper bound"
    assert trace["sanitizer_checks"][0]["condition"] == "if (payload) strcpy(buf, payload);"
    assert trace["transformations"][0]["evidence"] == "payload_alias"
    assert trace["execution_limitations"][0]["kind"] == "async_event_loop"


def test_source_to_sink_gate_requires_controlled_argument_role(tmp_path: Path) -> None:
    replay_dir = tmp_path / "replay" / "cand-no-role"
    replay_dir.mkdir(parents=True)
    request_path = replay_dir / "request.json"
    result_path = replay_dir / "result.json"
    report_path = tmp_path / "report.md"
    request_path.write_text(json.dumps({"candidate_id": "cand-no-role", "mode": "native", "input": {"argv": ["A" * 32]}}))
    result_path.write_text(
        json.dumps(
            {
                "candidate_id": "cand-no-role",
                "result": "confirmed",
                "mode": "native",
                "sink_reached": True,
                "bug_observed": True,
            }
        )
    )
    report_path.write_text("report")
    state = _state(status="replay_confirmed", candidate_id="cand-no-role").with_updates(
        replay_artifacts=[str(request_path)],
        type_facts={
            "capacity_bytes": 16,
            "write_relation": "unbounded",
            "verdict": "unbounded",
            "source_to_sink_trace": {
                "schema_version": 2,
                "status": "complete",
                "attacker_control_reaches_sink_role": True,
                "entry_function": "main",
                "target_function": "copy",
                "target_address": "0x1200",
                "sink_name": "strcpy",
                "call_path": ["main", "copy"],
                "input_model": "argv",
                "controlled_roles": [],
                "blockers": [],
            },
        },
    )

    trace = build_source_to_sink_trace(state)
    promoted, events = promote_for_report([state], report_artifacts={"cand-no-role": str(report_path)})

    assert trace.status == "blocked"
    assert "missing_controlled_argument_role" in trace.blockers
    assert promoted[0].status == "replay_confirmed"
    assert events == []


def test_optarg_process_proof_completes_source_to_sink_gate(tmp_path: Path) -> None:
    candidate_id = "demo:0x1000:main:42:strcpy:global_buf:0:unbounded"
    proof_path = tmp_path / "replay" / "optarg" / "ghidra_dynamic_proof.json"
    proof_path.parent.mkdir(parents=True)
    proof_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "proof_kind": "ghidra_dynamic_overflow",
                "candidate_id": candidate_id,
                "status": "overflow_proven",
                "proof_scope": "process_entrypoint",
                "sink_reached": True,
                "exact_sink_reached": True,
                "process_input_setup": {
                    "status": "configured",
                    "input_model": "argv",
                    "process_input_source": "inferred_from_optarg_sink",
                    "process_input_evidence": {
                        "argv_seed_reason": "optarg_option_argument",
                        "mode_flag": "o",
                        "decompile_source_file": "/exports/main.c",
                    },
                },
                "process_replay": {
                    "status": "reached",
                    "reached_target": True,
                    "modeled_runtime_calls": [
                        {
                            "function_model": "getopt_long",
                            "option": "o",
                            "optarg_write_status": "written",
                        }
                    ],
                },
                "capacity_bytes": 64,
                "overflow_bytes": 192,
            }
        )
    )
    state = _state(status="replay_confirmed", candidate_id=candidate_id).with_updates(
        replay_artifacts=[str(proof_path)],
        sink={"name": "strcpy", "target_buffer": "global_buf"},
        type_facts={
            "capacity_bytes": 64,
            "destination_kind": "global",
            "write_relation": "unbounded",
            "verdict": "unbounded",
            "overflow_condition": "strcpy has no destination bound",
            "source_to_sink_trace": {
                "schema_version": 2,
                "status": "blocked",
                "attacker_control_reaches_sink_role": False,
                "entry_function": "main",
                "entry_surface_kind": "program_entry",
                "target_function": "main",
                "target_address": "0x1000",
                "sink_name": "strcpy",
                "call_path": ["main"],
                "input_model": "argv",
                "argument_roles": [
                    {
                        "role": "write_source",
                        "expr": "optarg",
                        "classification": "unknown",
                        "controlled": False,
                        "complete": False,
                        "evidence": ["optarg has no recovered local definition before the write"],
                    },
                    {
                        "role": "destination_pointer",
                        "expr": "&global_buf",
                        "classification": "internal_local",
                        "controlled": False,
                        "complete": True,
                    },
                ],
                "blockers": ["source_to_write_roles_incomplete", "no_controlled_sink_role"],
            },
        },
    )

    trace = build_source_to_sink_trace(state)
    reports = build_lean_reports([state])

    assert trace.status == "proven"
    assert trace.sink_argument["role"] == "write_source"
    assert trace.sink_argument["classification"] == "source_controlled"
    assert trace.sink_argument["controlled"] is True
    assert trace.dynamic_artifacts == [str(proof_path)]
    assert has_reportable_source_to_sink(state) is True
    assert len(reports) == 1
    assert reports[0].proof_details["process_input_source"] == "inferred_from_optarg_sink"


def test_memory_source_to_sink_requires_ghidra_process_proof_not_native_replay(tmp_path: Path) -> None:
    replay_dir = tmp_path / "replay" / "cand-native-only"
    replay_dir.mkdir(parents=True)
    request_path = replay_dir / "request.json"
    result_path = replay_dir / "result.json"
    request_path.write_text(json.dumps({"candidate_id": "cand-native-only", "mode": "native", "input": {"argv": ["A" * 32]}}))
    result_path.write_text(
        json.dumps(
            {
                "candidate_id": "cand-native-only",
                "result": "confirmed",
                "mode": "native",
                "sink_reached": True,
                "bug_observed": True,
            }
        )
    )
    state = _state(status="replay_confirmed", candidate_id="cand-native-only").with_updates(
        replay_artifacts=[str(request_path)],
    )

    trace = build_source_to_sink_trace(state)

    assert trace.status == "blocked"
    assert "boundary_replay_missing" in trace.blockers
    assert has_reportable_source_to_sink(state) is False


def test_report_gate_revalidates_written_source_to_sink_trace_artifact(tmp_path: Path) -> None:
    invalid_artifact = tmp_path / "source_to_sink_trace_invalid.json"
    invalid_artifact.write_text(
        json.dumps(
            {
                "artifact_kind": "source_to_sink_trace",
                "schema_version": 1,
                "status": "proven",
                "input_model": "argv",
                "dynamic_artifacts": ["dynamic.json"],
            }
        )
    )
    invalid_state = _state(status="replay_confirmed").with_updates(
        validation_artifacts=[str(invalid_artifact)],
        type_facts={
            "capacity_bytes": 16,
            "write_relation": "unbounded",
            "verdict": "unbounded",
        },
    )
    proof_path = _write_ghidra_process_proof(tmp_path / "replay" / "cand-1" / "ghidra_dynamic_proof.json", "cand-1")
    valid_artifact = tmp_path / "source_to_sink_trace_valid.json"
    valid_artifact.write_text(
        json.dumps(
            {
                "artifact_kind": "source_to_sink_trace",
                "schema_version": 2,
                "status": "proven",
                "input_model": "argv",
                "argument_roles": [{"role": "write_source", "classification": "source_controlled", "controlled": True}],
                "propagation_path": [
                    {"kind": "function", "function": "main", "role": "entry"},
                    {"kind": "function", "function": "copy", "role": "sink_function"},
                ],
                "dynamic_artifacts": [str(proof_path)],
            }
        )
    )
    valid_state = invalid_state.with_updates(validation_artifacts=[str(valid_artifact)], replay_artifacts=[str(proof_path)])

    assert has_reportable_source_to_sink(invalid_state) is False
    assert has_reportable_source_to_sink(valid_state) is True


def test_lean_reports_dedupe_same_function_sink_buffer(tmp_path: Path) -> None:
    base = _state(status="replay_confirmed", candidate_id="demo:0x1000:fun:10:strcat:buf:0:unbounded").with_updates(
        target={"binary": "demo.bin", "relative_path": "usr/bin/demo"},
        location={"address": "0x1000", "function_name": "fun", "relative_path": "fun.c", "line_number": 10},
        source={"kind": "unknown"},
        sink={"name": "strcat", "target_buffer": "buf"},
    )
    duplicate_callsite = base.with_updates(
        candidate_id="demo:0x1000:fun:11:strcat:buf:0:unbounded",
        location={"address": "0x1000", "function_name": "fun", "relative_path": "fun.c", "line_number": 11},
    )
    separate_buffer = base.with_updates(
        candidate_id="demo:0x1000:fun:12:strcat:other:0:unbounded",
        location={"address": "0x1000", "function_name": "fun", "relative_path": "fun.c", "line_number": 12},
        sink={"name": "strcat", "target_buffer": "other"},
    )
    states = [
        _with_reportable_process_evidence(_with_source_to_sink_override(state, tmp_path), tmp_path)
        for state in [base, duplicate_callsite, separate_buffer]
    ]

    reports = build_lean_reports(states)

    assert [report.candidate_id for report in reports] == [base.candidate_id, separate_buffer.candidate_id]


def test_lean_reports_use_destination_kind_for_memory_corruption_label(tmp_path: Path) -> None:
    heap_state = _state(status="replay_confirmed", candidate_id="heap-cand").with_updates(
        type_facts={
            "capacity_bytes": 1,
            "destination_kind": "heap",
            "write_relation": "proven_overflow",
            "verdict": "overflow",
            "overflow_condition": "write size exceeds heap object",
        }
    )
    global_state = _state(status="replay_confirmed", candidate_id="global-cand").with_updates(
        type_facts={
            "capacity_bytes": 4,
            "destination_kind": "global",
            "write_relation": "proven_overflow",
            "verdict": "overflow",
            "overflow_condition": "write size exceeds global object",
        }
    )
    heap_state = _with_reportable_process_evidence(_with_source_to_sink_override(heap_state, tmp_path), tmp_path)
    global_state = _with_reportable_process_evidence(_with_source_to_sink_override(global_state, tmp_path), tmp_path)

    heap_report, global_report = build_lean_reports([heap_state, global_state])

    assert heap_report.vulnerability == "heap_overflow"
    assert heap_report.title == "Heap Overflow in vulnerable_copy"
    assert global_report.vulnerability == "out_of_bounds_write"
    assert global_report.title == "Out Of Bounds Write in vulnerable_copy"


def test_vendor_evidence_bundle_contains_reproducer_and_manifest(tmp_path: Path) -> None:
    executable = _script(tmp_path / "confirmed.sh", "echo vulnerable_copy\n echo '*** buffer overflow detected ***' >&2\n exit 134\n")
    candidate = _state(status="proof_ready")
    candidate = candidate.with_updates(
        type_facts={**dict(candidate.type_facts), "process_input": {"config_path": "etc/app.conf", "env_key": "UPLOAD_DIR"}}
    )
    request = build_replay_requests([candidate], binary_path=executable, mode="native")[0]
    replay_ready, _ = promote_for_replay(
        [candidate],
        request_artifacts={request.candidate_id: str(tmp_path / "replay" / request.candidate_id / "request.json")},
    )
    result = run_replay_request(request, tmp_path / "replay")
    replay_confirmed, _, _ = apply_replay_results(replay_ready, [result])
    proof_path = _write_ghidra_process_proof(
        tmp_path / "replay" / candidate.candidate_id / "ghidra_dynamic_proof.json",
        candidate.candidate_id,
    )
    replay_confirmed = [
        replay_confirmed[0].with_updates(replay_artifacts=[*replay_confirmed[0].replay_artifacts, str(proof_path)])
    ]
    intake_dir = tmp_path / "intake"
    intake_dir.mkdir()
    (intake_dir / "binaries.json").write_text(
        json.dumps(
            {
                "binaries": [
                    {
                        "path": str(executable),
                        "relative_path": executable.name,
                        "sha256": "abc123",
                        "size_bytes": executable.stat().st_size,
                        "architecture": "script",
                        "source_target": "/firmware/rootfs",
                    }
                ]
            }
        )
    )
    (intake_dir / "target.json").write_text(json.dumps({"product": "DemoRouter", "version": "1.2.3"}))
    (intake_dir / "services.json").write_text(
        json.dumps(
            {
                "services": [
                    {
                        "service_id": "svc-demo",
                        "name": "demo",
                        "relative_path": "etc/init.d/demo",
                        "exec": str(executable),
                        "ports": [8080],
                    }
                ]
            }
        )
    )
    (intake_dir / "routes.json").write_text(
        json.dumps({"routes": [{"route_id": "route-diag", "route": "/diag", "method": "POST", "relative_path": "www/diag.cgi"}]})
    )
    (intake_dir / "configs.json").write_text(
        json.dumps({"configs": [{"config_id": "cfg-app", "relative_path": "etc/app.conf", "env_keys": ["UPLOAD_DIR"]}]})
    )

    bundles = write_vendor_evidence_bundles(replay_confirmed, tmp_path / "vendor", intake_dir=intake_dir)

    assert len(bundles) == 1
    bundle = bundles[0]
    assert bundle.report_path.exists()
    assert bundle.reproducer_path.exists()
    assert bundle.manifest_path.exists()
    rendered = bundle.report_path.read_text()
    manifest = json.loads(bundle.manifest_path.read_text())
    index = json.loads((tmp_path / "vendor" / "index.json").read_text())
    assert index["artifact_kind"] == "vendor_evidence_bundle_index"
    assert manifest["artifact_kind"] == "vendor_evidence_bundle_manifest"
    assert "Reproduction Steps" in rendered
    assert "Source-to-Sink Trace" in rendered
    assert "Trace confidence: `proven`" in rendered
    assert "Sink role `write_source`" in rendered
    assert "Dynamic replay source: argv payload" in rendered
    assert "Observed stderr" in rendered
    assert "abc123" in rendered
    assert "Product: `DemoRouter`" in rendered
    assert "Version: `1.2.3`" in rendered
    assert "Matched service" in rendered
    provenance = manifest["target_provenance"]
    assert provenance["product"] == "DemoRouter"
    assert provenance["version"] == "1.2.3"
    assert provenance["services"][0]["exec"] == str(executable)
    assert provenance["routes"][0]["route"] == "/diag"
    assert provenance["configs"][0]["relative_path"] == "etc/app.conf"
    assert provenance["reproduction_environment"]["rootfs_path"] == "/firmware/rootfs"
    assert manifest["reproduction_environment"]["rootfs_path"] == "/firmware/rootfs"
    assert any(item["path"] == "vendor_report.md" for item in manifest["files"])
    artifact_roles = {(item["role"], item["path"]) for item in manifest["environment_artifacts"]}
    assert ("vendor_report", "vendor_report.md") in artifact_roles
    assert ("reproducer", "reproduce.sh") in artifact_roles
    assert ("expected_observation", "expected_observation.txt") in artifact_roles
    assert ("replay_request", "artifacts/request.json") in artifact_roles
    assert ("replay_result", "artifacts/result.json") in artifact_roles
    assert ("replay_transcript", "artifacts/native_transcript.json") in artifact_roles
    assert ("dynamic_proof", "artifacts/ghidra_dynamic_proof.json") in artifact_roles
    assert all(item["sha256"] and item["size_bytes"] >= 0 for item in manifest["environment_artifacts"])
    assert (bundle.directory / "expected_observation.txt").exists()


def test_vendor_evidence_bundle_describes_non_crashing_dynamic_observation(tmp_path: Path) -> None:
    replay_dir = tmp_path / "replay" / "cand-1"
    replay_dir.mkdir(parents=True)
    request_path = replay_dir / "request.json"
    transcript_path = replay_dir / "qemu_user_transcript.json"
    observation_path = replay_dir / "dynamic_overflow_observation.json"
    result_path = replay_dir / "result.json"
    request_path.write_text(json.dumps({"candidate_id": "cand-1", "mode": "qemu_user", "setup": {}, "input": {}, "expected_result": {}}))
    transcript_path.write_text(json.dumps({"returncode": 0, "stdout": "", "stderr": ""}))
    observation_path.write_text(
        json.dumps({"kind": "bounded_write_overflow", "status": "out_of_bounds_write_observed", "bug_observed": True})
    )
    result_path.write_text(
        json.dumps(
            {
                "candidate_id": "cand-1",
                "result": "confirmed",
                "mode": "qemu_user",
                "sink_reached": True,
                "bug_observed": True,
                "crash_observed": False,
                "control_result": {"proof_observation": {"kind": "bounded_write_overflow", "status": "out_of_bounds_write_observed"}},
                "artifacts": [str(request_path), str(transcript_path), str(observation_path)],
            }
        )
    )
    proof_path = _write_ghidra_process_proof(replay_dir / "ghidra_dynamic_proof.json", "cand-1")
    state = _state(status="report_ready").with_updates(
        replay_artifacts=[str(request_path), str(transcript_path), str(observation_path), str(proof_path)]
    )

    bundles = write_vendor_evidence_bundles([state], tmp_path / "vendor")

    rendered = bundles[0].report_path.read_text()
    assert "without requiring a process crash" in rendered
    assert "process abort" not in rendered
    assert "Process return code: `0`" in rendered


def test_vendor_evidence_bundle_includes_http_daemon_observation_channel(tmp_path: Path) -> None:
    replay_dir = tmp_path / "replay" / "http-command"
    replay_dir.mkdir(parents=True)
    request_path = replay_dir / "request.json"
    transcript_path = replay_dir / "native_transcript.json"
    result_path = replay_dir / "result.json"
    response = "HTTP/1.0 200 OK\r\n\r\nHTTP_DAEMON_EFFECT\n"
    request_path.write_text(
        json.dumps(
            {
                "candidate_id": "http-command",
                "mode": "native",
                "setup": {"binary_path": "/bin/httpd"},
                "input": {"input_model": "http_daemon", "method": "GET", "path": "/diag"},
                "expected_result": {},
            }
        )
    )
    transcript_path.write_text(
        json.dumps({"returncode": 0, "stdout": "", "stderr": "", "http_response": response})
    )
    result_path.write_text(
        json.dumps(
            {
                "candidate_id": "http-command",
                "result": "confirmed",
                "mode": "native",
                "sink_reached": True,
                "bug_observed": True,
                "crash_observed": False,
                "control_result": {
                    "proof_observation": {
                        "kind": "command_effect",
                        "status": "command_effect_observed",
                        "bug_observed": True,
                    },
                    "http_response": response,
                },
                "artifacts": [str(request_path), str(transcript_path)],
            }
        )
    )
    state = _state(status="report_ready", candidate_id="http-command").with_updates(
        vulnerability_type="command_injection",
        type_facts={
            **_state().type_facts,
            "process_input": {"input_model": "http_daemon"},
            "source_to_sink_trace": {
                **_state().type_facts["source_to_sink_trace"],
                "input_model": "http_daemon",
                "controlled_roles": ["command_argument:parameter_controlled"],
            },
        },
        replay_artifacts=[str(request_path), str(transcript_path)],
    )

    bundles = write_vendor_evidence_bundles([state], tmp_path / "vendor")

    rendered = bundles[0].report_path.read_text()
    expected = (bundles[0].directory / "expected_observation.txt").read_text()
    assert "Observed HTTP response" in rendered
    assert "HTTP_DAEMON_EFFECT" in rendered
    assert "http_response:" in expected
    assert "HTTP_DAEMON_EFFECT" in expected


def test_vendor_evidence_bundle_handles_concolic_witness(tmp_path: Path, monkeypatch) -> None:
    candidate_id = "firmware:0x1000:func:7:sprintf:buf:0:unbounded"
    candidate = _state(status="proof_ready", candidate_id=candidate_id)
    verdict_dir = tmp_path / "verdicts" / "firmware" / "firmware_0x1000_func"
    verdict_dir.mkdir(parents=True)
    (verdict_dir / "request.json").write_text(json.dumps({"candidate_id": candidate_id}))
    (verdict_dir / "replay.json").write_text(
        json.dumps(
            {
                "concrete_angr_replay": {
                    "status": "replayed",
                    "input_model": "stdin",
                    "target_loader_address": "0x1000",
                    "input_hex": "41424344",
                },
                "ghidra_pcode_replay": {"status": "reached", "reached_target": True},
            }
        )
    )
    _write_ghidra_process_proof(verdict_dir / "ghidra_dynamic_proof.json", candidate_id, input_model="stdin")
    (verdict_dir / "verdict.json").write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "concolic_verdict": "overflow_witness",
                "backend": "angr",
                "request": {"binary_path": "/firmware/bin/demo", "target_address": "0x1000", "input_model": "stdin"},
                "witness": {"input_model": "stdin", "stdin_hex": "41424344"},
                "ghidra_dynamic_proof": json.loads((verdict_dir / "ghidra_dynamic_proof.json").read_text()),
                "artifact_paths": ["request.json", "replay.json", "ghidra_dynamic_proof.json", "verdict.json"],
            }
        )
    )
    def fake_run_replay_request(request: ReplayRequest, output_dir: Path):
        candidate_dir = output_dir / "firmware_0x1000_func_7_sprintf_buf_0_unbounded"
        candidate_dir.mkdir(parents=True, exist_ok=True)
        request_path = candidate_dir / "request.json"
        request_path.write_text(json.dumps(request.to_dict()))
        result_path = candidate_dir / "result.json"
        result = replay_runners.ReplayResult(
            candidate_id=request.candidate_id,
            result="confirmed",
            mode=request.mode,
            sink_reached=True,
            bug_observed=True,
            crash_observed=False,
            control_result={"qemu": "ok"},
            artifacts=[str(request_path), str(result_path)],
        )
        replay_runners.write_replay_result(result, result_path)
        return result

    monkeypatch.setattr(replay_runners, "run_replay_request", fake_run_replay_request)

    results = import_concolic_replay_results(tmp_path / "verdicts", tmp_path / "replay")
    request_refs = {results[0].candidate_id: next(path for path in results[0].artifacts if Path(path).name == "request.json")}
    replay_ready, _ = promote_for_replay([candidate], request_artifacts=request_refs)
    replay_confirmed, _, _ = apply_replay_results(replay_ready, results)
    intake_dir = tmp_path / "intake"
    intake_dir.mkdir()
    (intake_dir / "binaries.json").write_text(
        json.dumps(
            {
                "binaries": [
                    {
                        "path": "/firmware/bin/demo",
                        "relative_path": "bin/demo",
                        "sha256": "def456",
                        "size_bytes": 1234,
                        "architecture": "ELF 32-bit executable",
                    }
                ]
            }
        )
    )

    bundles = write_vendor_evidence_bundles(replay_confirmed, tmp_path / "vendor", intake_dir=intake_dir)

    assert len(bundles) == 1
    rendered = bundles[0].report_path.read_text()
    assert (bundles[0].directory / "poc_input.bin").read_bytes() == b"ABCD"
    assert "Concolic verdict: `overflow_witness`" in rendered
    assert "P-code replay status: `reached`" in rendered
    assert "poc_input.bin" in rendered


def test_report_claim_checker_rejects_unsupported_high_impact_claims() -> None:
    state = _state(status="replay_confirmed")
    report = {
        "impact": "Unauthenticated remote code execution affects all affected versions and is exploitable over the network.",
        "replay_steps": [],
    }

    result = check_report_claims(report, state)

    assert result.accepted is False
    assert "unauthenticated_access" in result.unsupported_claims
    assert "network_reachability" in result.unsupported_claims
    assert "remote_code_execution" in result.unsupported_claims
    assert "affected_versions" in result.unsupported_claims


def test_candidate_states_round_trip(tmp_path: Path) -> None:
    path = write_candidate_states([_state()], tmp_path / "candidate_states.json")
    payload = json.loads(path.read_text())

    assert payload["candidate_states"][0]["status"] == CandidateStatus.PROOF_READY.value
