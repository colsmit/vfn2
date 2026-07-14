import json
from dataclasses import replace
from pathlib import Path

import pytest

from binary_agent.analysis.program_index import IndexedOperation, build_program_index
from binary_agent.data.manifest import Manifest
from binary_agent.data.operation_specs import load_operation_specs
from binary_agent.discovery.backends import MemoryAccessBackend, MemoryLifetimeBackend, merge_candidates
from binary_agent.discovery.base import DiscoveryContext
from binary_agent.ingest.loader import FunctionNode
from binary_agent.pipeline import (
    CandidateState,
    CandidateStatus,
    load_candidate_states,
    semantic_candidate_id,
)
from binary_agent.promotion import promote_proof_ready
from binary_agent.proof import dispatch_proof, proof_result_reportable, proof_results_from_replay
from binary_agent.proof import render_backend_finding
from binary_agent.replay import ReplayResult
from binary_agent.reporting import write_lean_reports
from binary_agent.taxonomy import (
    ACTIVE_BACKENDS,
    VULNERABILITY_SPECS,
    validate_taxonomy,
    vulnerability_types_for_backend,
)
from tests.test_end_to_end_pipeline import _record, _write_export


def _manifest() -> Manifest:
    return Manifest(
        binary="fixture.bin",
        generated_at="2026-07-11T00:00:00Z",
        export_dir="/tmp/fixture",
        image_base=0,
        ghidra_manifest="manifest.jsonl",
        callgraph_path=None,
        functions=[],
    )


def _context() -> DiscoveryContext:
    manifest = _manifest()
    index = build_program_index(manifest, ())
    return DiscoveryContext(Path("/tmp/fixture"), manifest, (), index)


def _state(backend: str = "memory_access", vulnerability_type: str = "stack_overflow") -> CandidateState:
    spec = VULNERABILITY_SPECS[vulnerability_type]
    operation = {"name": "memcpy", "kind": "call", "address": "0x1010"}
    return CandidateState(
        candidate_id=semantic_candidate_id(
            binary_identity="fixture.bin",
            backend=backend,
            vulnerability_type=vulnerability_type,
            function_address="0x1000",
            operation_address="0x1010",
            affected_object_identity="stack:buf",
            mechanism=spec.mechanism,
        ),
        backend=backend,
        vulnerability_type=vulnerability_type,
        mechanism=spec.mechanism,
        status=CandidateStatus.CANDIDATE.value,
        target={"binary": "fixture.bin"},
        location={"function_name": "main", "address": "0x1000", "line_text": "unstable"},
        source={"kind": "argv"},
        sink=operation,
        operation=operation,
        affected_object={"identity": "stack:buf", "kind": "stack"},
        root_causes=("integer_overflow",),
        type_facts={"evidence": ["c_text"]},
        proof_obligations=[],
        blockers=[],
    )


def test_taxonomy_is_complete_and_arithmetic_is_not_terminal() -> None:
    validate_taxonomy()
    assert {spec.backend for spec in VULNERABILITY_SPECS.values()} == ACTIVE_BACKENDS
    assert all(spec.proof_policy == spec.backend for spec in VULNERABILITY_SPECS.values())
    assert not {
        "integer_overflow",
        "integer_underflow",
        "signed_conversion",
        "truncation",
        "off_by_one",
    } & VULNERABILITY_SPECS.keys()


def test_operation_aliases_resolve_to_one_canonical_operation() -> None:
    specs = load_operation_specs()
    assert specs.version == 12
    assert specs.normalize_name("__builtin___memcpy_chk") == "memcpy_chk"
    assert len(dict(specs.alias_items)) == len(specs.alias_items)
    assert specs.get("isoc99_sscanf").name == "sscanf"
    assert specs.get("fopen").name == "fopen"
    assert specs.get("closedir").name == "closedir"
    assert specs.get("closesocket").name == "closesocket"
    assert specs.get("_Znwm").name == "operator_new"
    assert specs.get("uci_get_errorstr").output_pointer_args == (1,)
    assert specs.get("uci_get_errorstr").output_write_guarantee == "always"
    assert specs.get("abort").semantics == "process_terminate"
    assert specs.get("fprintf").role_index("format") == 1
    assert specs.get("syslog").role_index("message") == 1


def test_semantic_output_literals_are_not_tainted_credentials_or_formats(
    tmp_path: Path,
) -> None:
    (tmp_path / "fixed").mkdir()
    fixed_dir = _write_export(
        tmp_path / "fixed",
        {
            "main.c": """void main(char *program) {
  fprintf(stderr, "Usage: --password=<password> %s", program);
  printf("Unable to launch the requested CGI program");
}"""
        },
    )
    assert (
        discover_candidates_for_type(
            fixed_dir,
            "semantic_effect",
            "credential_disclosure",
        )
        == []
    )
    assert (
        discover_candidates_for_type(
            fixed_dir,
            "semantic_effect",
            "format_string",
        )
        == []
    )

    (tmp_path / "vulnerable").mkdir()
    vulnerable_dir = _write_export(
        tmp_path / "vulnerable",
        {"main.c": 'void main(char *password) { fprintf(stderr, "%s", password); }'},
    )
    credentials = discover_candidates_for_type(
        vulnerable_dir,
        "semantic_effect",
        "credential_disclosure",
    )
    assert len(credentials) == 1
    assert credentials[0].operation["name"] == "fprintf"


def test_semantic_variable_format_remains_candidate(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {"main.c": "void main(char *request) { printf(request); }"},
    )
    states = discover_candidates_for_type(
        export_dir,
        "semantic_effect",
        "format_string",
    )
    assert len(states) == 1
    assert states[0].source["expression"] == "request"


def test_semantic_format_ignores_controlled_non_format_roles(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {"main.c": 'void main(FILE *request_stream) { fprintf(request_stream, "%d\\n", 7); }'},
    )
    assert (
        discover_candidates_for_type(
            export_dir,
            "semantic_effect",
            "format_string",
        )
        == []
    )


def test_program_index_preserves_typed_resource_families(tmp_path: Path) -> None:
    text = """void main(char *buf) {
  FILE *stream = fopen("input", "r");
  DIR *directory = opendir(".");
  int sock = socket(2, 1, 0);
  fclose(stream);
  closedir(directory);
  close(sock);
  recv(sock, buf, 4);
}"""
    export_dir = _write_export(tmp_path, {"main.c": text})
    from binary_agent.discovery import load_discovery_context

    events = load_discovery_context(export_dir).index.lifecycle_events
    by_operation = {event.operation_name: event for event in events}
    assert (by_operation["fopen"].event_kind, by_operation["fopen"].resource_kind, by_operation["fopen"].allocator_family) == (
        "allocate",
        "stream",
        "stdio_stream",
    )
    assert (by_operation["opendir"].resource_kind, by_operation["closedir"].allocator_family) == (
        "directory",
        "directory",
    )
    assert by_operation["socket"].resource_kind == "socket"
    assert by_operation["close"].resource_kind == "socket"
    assert by_operation["recv"].resource_kind == "socket"


def test_typed_resource_mismatch_and_socket_close_sequence(tmp_path: Path) -> None:
    mismatch = "void main(void){ FILE *stream = fopen(\"x\", \"r\"); closedir(stream); }"
    socket_uac = "void main(char *buf){ int sock = socket(2, 1, 0); close(sock); recv(sock, buf, 4); }"
    (tmp_path / "mismatch").mkdir()
    (tmp_path / "socket").mkdir()
    mismatch_dir = _write_export(tmp_path / "mismatch", {"main.c": mismatch})
    socket_dir = _write_export(tmp_path / "socket", {"main.c": socket_uac})
    mismatch_states = discover_candidates_for_type(
        mismatch_dir,
        "memory_lifetime",
        "mismatched_deallocator",
    )
    socket_states = discover_candidates_for_type(
        socket_dir,
        "memory_lifetime",
        "use_after_close",
    )
    assert len(mismatch_states) == 1
    assert mismatch_states[0].type_facts["allocator_family"] == "stdio_stream"
    assert mismatch_states[0].type_facts["deallocator_family"] == "directory"
    assert len(socket_states) == 1
    assert socket_states[0].affected_object["kind"] == "socket"


def test_cfg_event_order_suppresses_mutually_exclusive_double_close() -> None:
    state_rows = _cfg_double_close_states(
        [
            {"start": "0x1000", "end": "0x100f", "successors": ["0x1010", "0x1020"]},
            {"start": "0x1010", "end": "0x101f", "successors": ["0x1030"]},
            {"start": "0x1020", "end": "0x102f", "successors": ["0x1030"]},
            {"start": "0x1030", "end": "0x103f", "successors": []},
        ]
    )
    assert state_rows == []


def test_cfg_event_order_records_dominance_for_sequential_double_close() -> None:
    state_rows = _cfg_double_close_states(
        [
            {"start": "0x1000", "end": "0x100f", "successors": ["0x1010"]},
            {"start": "0x1010", "end": "0x101f", "successors": ["0x1020"]},
            {"start": "0x1020", "end": "0x102f", "successors": ["0x1030"]},
            {"start": "0x1030", "end": "0x103f", "successors": []},
        ]
    )
    assert len(state_rows) == 1
    assert state_rows[0].type_facts["path_relation"] == "cfg_dominates"
    assert state_rows[0].type_facts["control_flow"]["before_dominates_after"] is True


def _cfg_double_close_states(blocks: list[dict]) -> list[CandidateState]:
    text = "void main(void) {}"
    record = replace(
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text),
        pcode_calls=[
            {"call_address": "0x1010", "callee": "close", "args": [{"constant": 42}]},
            {"call_address": "0x1020", "callee": "close", "args": [{"constant": 42}]},
        ],
        basic_blocks=blocks,
    )
    manifest = replace(_manifest(), functions=[record])
    node = FunctionNode(record=record, text=text, metadata={"callees": [], "callers": []}, path=None, record_index=0)
    index = build_program_index(manifest, [node])
    context = DiscoveryContext(Path("/tmp/fixture"), manifest, (node,), index)
    return list(MemoryLifetimeBackend().discover(context, index, frozenset({"double_close"})))


def test_memory_backend_calls_spatial_extractor_once(monkeypatch: pytest.MonkeyPatch) -> None:
    class Raw:
        def to_dict(self):
            return {
                "binary": "fixture.bin",
                "address": "0x1000",
                "operation_address": "0x1010",
                "function_name": "main",
                "destination_kind": "stack",
                "target_buffer": "buf",
                "kind": "memcpy",
                "sink": "memcpy",
                "vulnerability_type": "memory_overflow",
                "path_is_valid": True,
                "input_reaches_sink": True,
                "write_relation": "proven_overflow",
                "verdict": "overflow",
                "capacity_bytes": 8,
                "evidence_sources": ["pcode_call"],
            }

    calls = []
    monkeypatch.setattr(
        "binary_agent.discovery.backends.extract_static_candidates",
        lambda *_args: calls.append(1) or [Raw()],
    )
    backend = MemoryAccessBackend()
    states = list(
        backend.discover(
            _context(),
            _context().index,
            vulnerability_types_for_backend("memory_access"),
        )
    )
    assert len(calls) == 1
    assert {state.vulnerability_type for state in states} == {"stack_overflow"}


def test_memory_filter_does_not_emit_stack_and_root_cause_attaches(monkeypatch: pytest.MonkeyPatch) -> None:
    class Raw:
        def __init__(self, destination: str, vulnerability_type: str):
            self.destination = destination
            self.vulnerability_type = vulnerability_type

        def to_dict(self):
            return {
                "binary": "fixture.bin",
                "address": "0x1000",
                "operation_address": "0x1010",
                "function_name": "main",
                "destination_kind": self.destination,
                "target_buffer": "buf",
                "kind": "memcpy",
                "sink": "memcpy",
                "vulnerability_type": self.vulnerability_type,
                "path_is_valid": True,
                "input_reaches_sink": True,
                "write_relation": "integer_overflow_risk" if self.vulnerability_type.startswith("integer_") else "proven_overflow",
                "verdict": "overflow",
                "capacity_bytes": 8,
                "evidence_sources": ["pcode_call"],
            }

    monkeypatch.setattr(
        "binary_agent.discovery.backends.extract_static_candidates",
        lambda *_args: [
            Raw("stack", "memory_overflow"),
            Raw("heap", "memory_overflow"),
            Raw("heap", "integer_overflow_to_memory_access"),
        ],
    )
    context = _context()
    states = list(MemoryAccessBackend().discover(context, context.index, frozenset({"heap_overflow"})))
    assert [state.vulnerability_type for state in states] == ["heap_overflow"]
    assert states[0].root_causes == ("integer_overflow",)


def test_memory_backend_uses_exact_indexed_callsite_in_candidate_key(monkeypatch: pytest.MonkeyPatch) -> None:
    class Raw:
        def to_dict(self):
            return {
                "binary": "fixture.bin",
                "address": "0x1000",
                "operation_address": "",
                "function_name": "main",
                "line_number": 7,
                "destination_kind": "stack",
                "target_buffer": "buf",
                "kind": "recv",
                "sink": "recv",
                "vulnerability_type": "memory_overflow",
                "path_is_valid": True,
                "input_reaches_sink": True,
                "write_relation": "proven_overflow",
                "verdict": "overflow",
                "capacity_bytes": 8,
                "evidence_sources": ["c_text"],
            }

    operation = IndexedOperation(
        kind="call",
        name="recv",
        backend="memory_access",
        semantics="bounded_write",
        effect_kind="memory_write",
        function_name="main",
        function_address="0x1000",
        operation_address="0x1018",
        line_number=7,
        evidence_source="pcode_call",
    )
    base = _context()
    index = replace(base.index, operations=(operation,))
    context = DiscoveryContext(base.export_dir, base.manifest, base.nodes, index)
    monkeypatch.setattr("binary_agent.discovery.backends.extract_static_candidates", lambda *_args: [Raw()])
    state = list(MemoryAccessBackend().discover(context, index, frozenset({"stack_overflow"})))[0]
    assert state.operation["address"] == "0x1018"
    assert state.candidate_id == semantic_candidate_id(
        binary_identity="fixture.bin",
        backend="memory_access",
        vulnerability_type="stack_overflow",
        function_address="0x1000",
        operation_address="0x1018",
        affected_object_identity="stack:buf",
        mechanism="out_of_bounds_write",
    )


def test_memory_backend_correlates_one_direct_store_by_exported_line(monkeypatch: pytest.MonkeyPatch) -> None:
    class Raw:
        def to_dict(self):
            return {
                "binary": "fixture.bin",
                "address": "0x1000",
                "operation_address": "",
                "function_name": "main",
                "line_number": 12,
                "destination_kind": "heap",
                "target_buffer": "ptr",
                "kind": "pointer_store",
                "sink": "pointer_store",
                "vulnerability_type": "memory_overflow",
                "write_relation": "symbolic_capacity",
                "verdict": "candidate",
                "evidence_sources": ["c_text"],
            }

    operation = IndexedOperation(
        kind="store",
        name="pcode_store",
        backend="memory_access",
        semantics="direct_memory_store",
        effect_kind="memory_store",
        function_name="main",
        function_address="0x1000",
        operation_address="0x1024",
        line_number=12,
        arguments=("ptr",),
        evidence_source="pcode_store",
    )
    base = _context()
    index = replace(base.index, operations=(operation,))
    context = DiscoveryContext(base.export_dir, base.manifest, base.nodes, index)
    monkeypatch.setattr("binary_agent.discovery.backends.extract_static_candidates", lambda *_args: [Raw()])

    state = list(MemoryAccessBackend().discover(context, index, frozenset({"heap_overflow"})))[0]

    assert state.operation["address"] == "0x1024"
    assert "pcode_store" in state.type_facts["static_candidate"]["evidence_sources"]


def test_program_index_normalizes_heap_object_and_assignment_alias() -> None:
    text = "void main(void) { void *p; void *q; p = malloc(32); q = p; free(q); }"
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    node = FunctionNode(record, text, {}, None, 0)
    index = build_program_index(_manifest(), (node,))

    heap_object = next(item for item in index.memory_objects if item.kind == "heap")
    allocation = next(item for item in index.lifecycle_events if item.event_kind == "allocate")
    release = next(item for item in index.lifecycle_events if item.event_kind == "release")
    assert heap_object.label == "p"
    assert heap_object.size_bytes == 32
    assert allocation.resource_identity == release.resource_identity == "0x1000:p"


def test_program_index_recovers_strict_allocator_wrapper_results() -> None:
    wrapper_text = "void *alloc(size_t size) { void *p; p = malloc(size); return p; }"
    main_text = "void main(void) { void *buffer; buffer = alloc(64); }"
    wrapper = _record(name="alloc", address="0x1000", ordinal=0, relative_path="alloc.c", text=wrapper_text)
    main = _record(name="main", address="0x1100", ordinal=1, relative_path="main.c", text=main_text)
    index = build_program_index(
        replace(_manifest(), functions=[wrapper, main]),
        (FunctionNode(wrapper, wrapper_text, {}, None, 0), FunctionNode(main, main_text, {}, None, 1)),
    )

    memory_object = next(item for item in index.memory_objects if item.function_name == "main")
    assert memory_object.kind == "heap"
    assert memory_object.label == "buffer"
    assert memory_object.size_bytes == 64
    assert memory_object.source == "alloc:64"


def test_lifetime_index_instantiates_exact_release_wrapper_callsites(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "release_wrapper.c": "void release_wrapper(char *param_1) { free(param_1); }\n",
            "main.c": (
                "void main(void) {\n"
                "  char *ptr;\n"
                "  ptr = malloc(16);\n"
                "  release_wrapper(ptr);\n"
                "  release_wrapper(ptr);\n"
                "}\n"
            ),
        },
    )
    states = discover_candidates_for_type(export_dir, "memory_lifetime", "double_free")

    assert len(states) == 1
    state = states[0]
    assert state.location["function_name"] == "release_wrapper"
    assert ":line:1:" in state.operation["address"]
    instantiated = [
        item
        for item in state.type_facts["events"]
        if item["instantiation_source"] == "direct_parameter_call"
    ]
    assert len(instantiated) == 2
    assert {item["operation_address"] for item in instantiated} == {
        state.operation["address"]
    }
    assert len({item["context_operation_address"] for item in instantiated}) == 2
    assert all(item["call_path"] == ["main", "release_wrapper"] for item in instantiated)
    assert state.type_facts["control_flow"]["evidence"].startswith(
        "interprocedural_callsite:"
    )


@pytest.mark.parametrize(
    "main_body",
    [
        "char *ptr; ptr = malloc(16); release_wrapper(ptr);",
        "char *ptr; ptr = malloc(16); release_wrapper(ptr + 1); release_wrapper(ptr + 1);",
        (
            "char *left; char *right; left = malloc(16); right = malloc(16); "
            "release_wrapper(left); release_wrapper(right);"
        ),
    ],
)
def test_lifetime_index_suppresses_fixed_or_ambiguous_wrapper_controls(
    tmp_path: Path,
    main_body: str,
) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "release_wrapper.c": "void release_wrapper(char *param_1) { free(param_1); }\n",
            "main.c": f"void main(void) {{ {main_body} }}\n",
        },
    )
    assert discover_candidates_for_type(
        export_dir, "memory_lifetime", "double_free"
    ) == []


def test_lifetime_index_wrapper_release_suppresses_memory_leak(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "release_wrapper.c": "void release_wrapper(char *param_1) { free(param_1); }\n",
            "main.c": (
                "void main(void) { char *ptr; ptr = malloc(16); "
                "release_wrapper(ptr); }\n"
            ),
        },
    )
    assert discover_candidates_for_type(
        export_dir, "memory_lifetime", "memory_leak"
    ) == []


def test_lifetime_backend_suppresses_mutually_exclusive_free_and_realloc(tmp_path: Path) -> None:
    text = """void main(void *param_2, size_t param_3) {
  void *result;
  if (param_3 == 0) {
    free(param_2);
    result = 0;
  } else {
    result = realloc(param_2, param_3);
  }
}
"""
    export_dir = _write_export(tmp_path, {"main.c": text})

    states = discover_candidates_for_type(export_dir, "memory_lifetime", "use_after_free")

    assert states == []


def test_lifetime_index_skips_import_thunks_and_alias_release_leaks() -> None:
    thunk_text = "void * malloc(size_t size) { return imported_malloc(size); }"
    thunk_record = replace(
        _record(name="malloc", address="0x1000", ordinal=0, relative_path="malloc.c", text=thunk_text),
        is_thunk=True,
    )
    main_text = "void main(void) { char *ptr; ptr = malloc(16); free((void *)(ptr + 1)); }"
    main_record = _record(name="main", address="0x1100", ordinal=1, relative_path="main.c", text=main_text)
    manifest = replace(_manifest(), functions=[thunk_record, main_record])
    nodes = (
        FunctionNode(thunk_record, thunk_text, {}, None, 0),
        FunctionNode(main_record, main_text, {}, None, 1),
    )
    index = build_program_index(manifest, nodes)
    context = DiscoveryContext(Path("/tmp/fixture"), manifest, nodes, index)
    assert not [item for item in index.lifecycle_events if item.function_name == "malloc"]
    states = list(MemoryLifetimeBackend().discover(context, index, frozenset({"memory_leak"})))
    assert states == []


def test_candidate_identity_does_not_include_decompiled_line_text() -> None:
    state = _state()
    changed = state.with_updates(location={**state.location, "line_text": "different decompilation"})
    assert state.candidate_id == changed.candidate_id
    different = semantic_candidate_id(
        binary_identity="fixture.bin",
        backend="memory_access",
        vulnerability_type="stack_overflow",
        function_address="0x1000",
        operation_address="0x1011",
        affected_object_identity="stack:buf",
        mechanism="out_of_bounds_write",
    )
    assert different != state.candidate_id


def test_semantic_merge_preserves_root_causes_and_prefers_pcode() -> None:
    text = _state().with_updates(operation={**_state().operation, "evidence_source": "c_text"})
    pcode = _state().with_updates(
        operation={**_state().operation, "evidence_source": "pcode_call"},
        root_causes=("truncation",),
        type_facts={"evidence": ["pcode_call"]},
    )
    merged, count = merge_candidates([text, pcode])
    assert count == 1
    assert merged[0].operation["evidence_source"] == "pcode_call"
    assert set(merged[0].root_causes) == {"integer_overflow", "truncation"}


def test_schema_v1_candidates_are_rejected_explicitly(tmp_path: Path) -> None:
    artifact = tmp_path / "candidate_states.json"
    artifact.write_text(json.dumps({"schema_version": 1, "candidate_states": []}))
    with pytest.raises(ValueError, match="schema v2 is required"):
        load_candidate_states(artifact)


def test_removed_discovery_flag_is_rejected_explicitly(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from binary_agent.cli.run_discovery import parse_args

    monkeypatch.setattr(
        "sys.argv",
        ["run_discovery", "/tmp/export", "--output-dir", "/tmp/output", "--modules", "stack_overflow"],
    )
    with pytest.raises(SystemExit):
        parse_args()
    assert "unrecognized arguments: --modules" in capsys.readouterr().err


def test_memory_report_gate_requires_exact_correlated_object_range() -> None:
    state = _state()
    uncorrelated = dispatch_proof(
        state,
        {
            "scope": "function_harness",
            "exact_operation_reached": True,
            "operation_address": "0x9999",
            "memory_access": {"same_object": True, "object_range": [0, 8], "access_range": [0, 16], "out_of_bounds": True},
        },
    )
    assert uncorrelated.status == "inconclusive"
    assert not proof_result_reportable(state, uncorrelated)
    proven = dispatch_proof(
        state,
        {
            "scope": "function_harness",
            "exact_operation_reached": True,
            "operation_address": "0x1010",
            "memory_access": {"same_object": True, "object_range": [0, 8], "access_range": [0, 16], "out_of_bounds": True},
        },
    )
    assert proven.status == "proven"
    assert proof_result_reportable(state, proven)


def test_semantic_and_static_policies_have_distinct_replay_rules() -> None:
    semantic = _state("semantic_effect", "command_injection")
    effect = dispatch_proof(
        semantic,
        {
            "scope": "process_entrypoint",
            "exact_operation_reached": True,
            "operation_address": "0x1010",
            "concrete_input": {"argv": [";id"]},
            "process_setup": {"status": "configured"},
            "native_replay": {"status": "observed"},
            "effect_observation": {"status": "observed", "kind": "command_effect"},
        },
    )
    assert proof_result_reportable(semantic, effect)

    static = _state("static_evidence", "embedded_api_token")
    presence = dispatch_proof(
        static,
        {"static_evidence": {"exact": True, "reachable": True, "kind": "api_token_literal"}},
    )
    assert presence.scope == "static"
    assert proof_result_reportable(static, presence)


def test_legacy_engine_artifact_normalizes_to_schema_v2_proof(tmp_path: Path) -> None:
    state = _state("memory_lifetime", "invalid_free")
    proof_path = tmp_path / "ghidra_dynamic_proof.json"
    proof_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "lifetime_violation_proven",
                "proof_scope": "process_entrypoint",
                "exact_sink_reached": True,
                "sink_address": "0x1010",
                "process_input_setup": {
                    "status": "configured",
                    "input_model": "argv",
                    "argv_values": ["program", "payload"],
                },
                "native_replay": {"status": "replayed"},
                "lifetime_violation": {
                    "vulnerability": "invalid_free",
                    "object_id": 1,
                    "reason": "release_address_is_not_object_base",
                },
            }
        )
    )
    replay = ReplayResult(
        candidate_id=state.candidate_id,
        result="confirmed",
        mode="ghidra_process",
        sink_reached=True,
        bug_observed=True,
        crash_observed=True,
        control_result={},
        artifacts=[str(proof_path)],
    )
    result = proof_results_from_replay([state], [replay])[0]
    assert result.status == "proven"
    assert result.scope == "process_entrypoint"
    assert result.exact_operation_reached is True
    assert result.lifetime_violation["same_resource"] is True
    assert result.to_dict()["schema_version"] == 2


def test_reentrant_copy_native_exact_trace_completes_same_owner_proof(tmp_path: Path) -> None:
    state = _state("memory_lifetime", "use_after_free").with_updates(
        mechanism="reentrant_copy_invalidation",
        type_facts={
            "resource_identity": "owner:stack",
            "resource_lineage": {
                "same_resource": True,
                "path_relation": "copy_branch_feasible",
                "borrow_expression": "stack + offset",
                "invalidating_operation": "0x1010",
            },
            "callee_summary": {"may_allocate": True, "allocation_evidence": ["callee:grow"]},
            "ordered_events": ["borrow", "invalidating_allocation", "copy_read"],
        },
    )
    proof_path = tmp_path / "ghidra_dynamic_proof.json"
    proof_path.write_text(
        json.dumps(
            {
                "status": "sink_unreached",
                "proof_scope": "process_entrypoint",
                "sink_address": "0x1010",
                "process_input_setup": {
                    "status": "configured",
                    "input_model": "argv_file_stdin",
                    "argv_values": ["program", "witness.rb"],
                    "file_input_hex": "4142",
                },
                "native_replay": {
                    "status": "replayed",
                    "exact_operation_trace": {"status": "reached", "operation_address": "0x1010"},
                },
            }
        )
    )
    replay = ReplayResult(
        candidate_id=state.candidate_id,
        result="blocked",
        mode="ghidra_process",
        sink_reached=False,
        bug_observed=False,
        crash_observed=False,
        control_result={},
        artifacts=[str(proof_path)],
    )

    result = proof_results_from_replay([state], [replay])[0]

    assert result.status == "proven"
    assert result.scope == "process_entrypoint"
    assert result.exact_operation_reached is True
    assert result.lifetime_violation["same_resource"] is True
    assert result.lifetime_violation["violation"] is True
    assert result.lifetime_violation["events"] == ["borrow", "invalidating_allocation", "copy_read"]


def test_indexed_owner_double_free_can_enter_dynamic_proof() -> None:
    state = _state("memory_lifetime", "double_free").with_updates(
        sink={"name": "free", "operation_address": "0x1010"},
        blockers=[
            "dynamic_indexed_owner_identity_unproven",
            "owner_alias_range_overlap_unproven",
            "process_trigger_reaches_cleanup_unproven",
        ],
        type_facts={
            "trigger_sequence": [
                {"event": "owner_alias_copy"},
                {"event": "owner_cleanup_release"},
            ],
            "entrypoint_derivation": {
                "status": "derived",
                "process_input_supported": True,
            },
        },
    )
    promoted, _, _ = promote_proof_ready([state])
    assert promoted[0].status == "proof_ready"


@pytest.mark.parametrize(
    ("backend", "vulnerability_type", "mechanism", "facts", "blocker"),
    [
        (
            "memory_access",
            "out_of_bounds_read",
            "rounded_stride_miscalculation",
            {"range_relation": "factor_applied_after_rounded_byte_conversion"},
            "concrete_object_range_replay_required",
        ),
        (
            "memory_lifetime",
            "use_after_free",
            "reentrant_copy_invalidation",
            {
                "resource_lineage": {"same_resource": True, "path_relation": "copy_branch_feasible"},
                "callee_summary": {"may_allocate": True},
            },
            "concrete_reentrant_invalidation_replay_required",
        ),
    ],
)
def test_indexed_schema2_operation_with_concrete_process_input_enters_proof(
    backend: str,
    vulnerability_type: str,
    mechanism: str,
    facts: dict,
    blocker: str,
) -> None:
    state = _state(backend, vulnerability_type).with_updates(
        mechanism=mechanism,
        operation={"name": "indexed_operation", "kind": "load", "address": "0x1010"},
        sink={"name": "indexed_operation", "kind": "load", "address": "0x1010"},
        blockers=[blocker],
        type_facts={
            **facts,
            "entrypoint_derivation": {
                "status": "derived",
                "process_input_supported": True,
                "entry_address": "0x1000",
            },
            "process_input": {
                "inferred": False,
                "argv_values": ["program", "witness.bin"],
                "file_input_hex": "4142",
            },
        },
    )

    promoted, _, _ = promote_proof_ready([state])

    assert promoted[0].status == "proof_ready"
    assert promoted[0].blockers == []


def test_process_input_override_materializes_concrete_bytes(tmp_path: Path) -> None:
    from binary_agent.cli.toolchain import _load_process_input_override

    witness = tmp_path / "witness.bin"
    witness.write_bytes(b"PATCH\n")
    config = tmp_path / "input.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "input_model": "stdin",
                "argv_values": ["program", "-Rf"],
                "stdin_path": str(witness),
            }
        )
    )
    normalized = _load_process_input_override(config)
    assert normalized["input_model"] == "stdin"
    assert normalized["argv_values"] == ["program", "-Rf"]
    assert normalized["stdin_input_hex"] == witness.read_bytes().hex()


def test_report_envelope_is_schema_v2(tmp_path: Path) -> None:
    written = write_lean_reports([], tmp_path)
    assert json.loads(written["json"].read_text())["schema_version"] == 2


@pytest.mark.parametrize(
    ("backend", "vulnerability_type", "vulnerable", "fixed"),
    [
        ("memory_access", "overlapping_memory_copy", "void main(char *buf){ memcpy(buf + 1, buf, 4); }", "void main(char *a, char *b){ memcpy(a, b, 4); }"),
        ("memory_lifetime", "memory_leak", "void main(void){ char *ptr; ptr = malloc(16); }", "void main(void){ char *ptr; ptr = malloc(16); free(ptr); }"),
        ("memory_lifetime", "mismatched_deallocator", "void main(void){ char *ptr; ptr = operator_new(16); free(ptr); }", "void main(void){ char *ptr; ptr = operator_new(16); operator_delete(ptr); }"),
        ("memory_lifetime", "double_close", "void main(int fd){ close(fd); close(fd); }", "void main(int fd){ close(fd); }"),
        ("memory_lifetime", "use_after_close", "void main(int fd, char *buf){ close(fd); read(fd, buf, 4); }", "void main(int fd, char *buf){ read(fd, buf, 4); close(fd); }"),
        ("semantic_effect", "sql_injection", "void main(void *db, char *user_query){ sqlite3_exec(db, user_query); }", "void main(void *db){ sqlite3_exec(db, \"SELECT 1\"); }"),
        ("semantic_effect", "argument_injection", "void main(char *program, char **user_argv){ execve(program, user_argv); }", "void main(char *program){ execve(program, fixed_args); }"),
        ("semantic_effect", "code_injection", "void main(char *user_code){ eval(user_code); }", "void main(void){ eval(\"return 1\"); }"),
        ("semantic_effect", "server_side_request_forgery", "void main(int sock, char *user_url){ connect(sock, user_url); }", "void main(int sock){ connect(sock, fixed_address); }"),
        ("semantic_effect", "http_header_injection", "void main(char *user_header){ set_header(user_header); }", "void main(void){ set_header(\"X-Safe: yes\"); }"),
        ("semantic_effect", "log_injection", "void main(char *user_message){ log_message(user_message); }", "void main(void){ log_message(\"fixed event\"); }"),
        ("semantic_effect", "open_redirect", "void main(char *user_url){ redirect(user_url); }", "void main(void){ redirect(\"/home\"); }"),
        ("static_evidence", "default_credential", "void main(void){ authenticate(\"admin\", \"Firmware#42\"); }", "void main(char *user, char *password){ authenticate(user, password); }"),
        ("static_evidence", "embedded_private_key", "void main(void){ load_private_key(\"-----BEGIN PRIVATE KEY-----\\nMDECAQMEBQYHCAkKCwwNDg8Q\\n-----END PRIVATE KEY-----\"); }", "void main(void){ load_key_from_keystore(); }"),
        ("static_evidence", "embedded_api_token", "void main(void){ set_api_token(\"AbCDef_1234567890-ghIJ\"); }", "void main(void){ set_api_token(getenv(\"API_KEY\")); }"),
        ("static_evidence", "weak_cryptography", "void main(char *data){ md5(data); }", "void main(char *data){ sha256(data); }"),
        ("static_evidence", "insecure_randomness", "void main(void){ int nonce = rand(); consume_nonce(nonce); }", "void main(void){ getrandom(buf, 16); consume_nonce(buf); }"),
        ("static_evidence", "disabled_certificate_validation", "void main(void *ctx){ ssl_ctx_set_verify(ctx, 0, 0); }", "void main(void *ctx){ ssl_ctx_set_verify(ctx, 1, 0); }"),
    ],
)
def test_expansion_discovery_vulnerable_fixed_pairs(
    tmp_path: Path,
    backend: str,
    vulnerability_type: str,
    vulnerable: str,
    fixed: str,
) -> None:
    vulnerable_root = tmp_path / "vulnerable"
    fixed_root = tmp_path / "fixed"
    vulnerable_root.mkdir()
    fixed_root.mkdir()
    vulnerable_dir = _write_export(vulnerable_root, {"main.c": vulnerable})
    fixed_dir = _write_export(fixed_root, {"main.c": fixed})
    vulnerable_states = discover_candidates_for_type(vulnerable_dir, backend, vulnerability_type)
    fixed_states = discover_candidates_for_type(fixed_dir, backend, vulnerability_type)
    assert any(item.vulnerability_type == vulnerability_type for item in vulnerable_states)
    assert not [item for item in fixed_states if item.vulnerability_type == vulnerability_type]


def test_null_dereference_requires_exact_pcode_zero_address() -> None:
    vulnerable_text = "void main(void) { *(volatile int *)0 = 1; }"
    vulnerable_record = replace(
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=vulnerable_text),
        pcode_stores=[
            {
                "operation_address": "0x1010",
                "write_width": 4,
                "address_constants": [0],
                "address_constant": 0,
            }
        ],
    )
    fixed_text = "void main(int *ptr) { *ptr = 1; }"
    fixed_record = replace(
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=fixed_text),
        pcode_stores=[
            {
                "operation_address": "0x1010",
                "write_width": 4,
                "address_vars": ["ptr"],
            }
        ],
    )

    def states(record, text):
        manifest = replace(_manifest(), functions=[record])
        node = FunctionNode(record, text, {"callees": [], "callers": []}, None, 0)
        index = build_program_index(manifest, (node,))
        context = DiscoveryContext(Path("/tmp/fixture"), manifest, (node,), index)
        return list(
            MemoryAccessBackend().discover(
                context,
                index,
                frozenset({"null_pointer_dereference"}),
            )
        )

    vulnerable = states(vulnerable_record, vulnerable_text)
    assert len(vulnerable) == 1
    assert vulnerable[0].operation["address"] == "0x1010"
    assert vulnerable[0].type_facts["pointer_value"] == 0
    assert states(fixed_record, fixed_text) == []


def discover_candidates_for_type(export_dir: Path, backend: str, vulnerability_type: str):
    from binary_agent.discovery import discover_candidates, load_discovery_context

    return discover_candidates(
        load_discovery_context(export_dir),
        backend_names=[backend],
        vulnerability_types=[vulnerability_type],
    )


def test_uninitialized_memory_use_vulnerable_fixed_pair(tmp_path: Path) -> None:
    def export(root: Path, *, with_store: bool) -> Path:
        root.mkdir()
        export_dir = root / "decompiled"
        export_dir.mkdir()
        text = "void main(void){ consume(local_20); }"
        (export_dir / "main.c").write_text(text)
        record = _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=text,
            pcode_loads=[{
                "operation_address": "0x1010",
                "read_width": 4,
                "address_vars": ["local_20"],
                "definedness": "undefined",
                "defined_byte_ranges": [[-32, -30]],
                "undefined_byte_ranges": [[-30, -28]],
                "stack_offset": -32,
            }],
        )
        if with_store:
            record = record.__class__.from_dict(
                {**record.to_dict(), "pcode_stores": [{"operation_address": "0x1008", "write_width": 4, "address_vars": ["local_20"]}]}
            )
        manifest = Manifest(
            binary="fixture.bin",
            generated_at="2026-07-11T00:00:00Z",
            export_dir=str(export_dir),
            image_base=0,
            ghidra_manifest="manifest.jsonl",
            callgraph_path=None,
            functions=[record],
        )
        (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))
        return export_dir

    vulnerable = discover_candidates_for_type(export(tmp_path / "vulnerable", with_store=False), "memory_access", "uninitialized_memory_use")
    fixed = discover_candidates_for_type(export(tmp_path / "fixed", with_store=True), "memory_access", "uninitialized_memory_use")
    assert len(vulnerable) == 1
    assert vulnerable[0].type_facts["defined_byte_ranges"] == [[-32, -30]]
    assert vulnerable[0].type_facts["undefined_byte_ranges"] == [[-30, -28]]
    assert fixed == []


def test_uninitialized_fallback_honors_unconditional_indirect_output_contract(
    tmp_path: Path,
) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "main.c": """void main(void) {
  undefined8 local_a0;
  (*(code *)PTR_uci_get_errorstr_00438e70)(ctx,&local_a0,0);
  consume(local_a0);
}"""
        },
    )

    from binary_agent.discovery import load_discovery_context

    context = load_discovery_context(export_dir)
    operation = next(
        item for item in context.index.operations if item.name == "uci_get_errorstr"
    )
    assert operation.arguments == ("ctx", "&local_a0", "0")
    assert operation.output_pointer_args == (1,)
    assert operation.output_write_guarantee == "always"
    assert (
        discover_candidates_for_type(
            export_dir,
            "memory_access",
            "uninitialized_memory_use",
        )
        == []
    )


def test_program_index_maps_adjacent_indirect_imports_by_exact_export_line(
    tmp_path: Path,
) -> None:
    text = """// Function: main
// Address: 0x1000

void main(void) {
  undefined8 local_a0;
  (*(code *)PTR_uci_get_errorstr_00438e70)(ctx,&local_a0,0);
  consume(local_a0);
  (*(code *)PTR_free_00438ec8)(local_a0);
}"""
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    (export_dir / "main.c").write_text(text)
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        pcode_calls=[
            {
                "call_address": "0x1010",
                "callee": "",
                "args": ["ctx", "local_a0", "0"],
            },
            {"call_address": "0x1020", "callee": "", "args": ["local_a0"]},
        ],
        c_line_addresses=[
            {"line_number": 3, "addresses": ["0x1010"]},
            {"line_number": 5, "addresses": ["0x1020"]},
        ],
    )
    manifest = Manifest(
        binary="fixture.bin",
        generated_at="2026-07-13T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest="manifest.jsonl",
        callgraph_path=None,
        functions=[record],
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))

    from binary_agent.discovery import load_discovery_context

    operations = {
        item.operation_address: item
        for item in load_discovery_context(export_dir).index.operations
        if item.operation_address in {"0x1010", "0x1020"}
    }
    assert operations["0x1010"].name == "uci_get_errorstr"
    assert operations["0x1010"].arguments == ("ctx", "&local_a0", "0")
    assert operations["0x1020"].name == "free"
    assert operations["0x1020"].arguments == ("local_a0",)


def test_program_index_maps_repeated_calls_by_line_not_machine_order(
    tmp_path: Path,
) -> None:
    text = """// Function: main
// Address: 0x1000

void main(void) {
  (*(code *)PTR_close_00407010)(fd_b);
  (*(code *)PTR_close_00407010)(fd_a);
}"""
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    (export_dir / "main.c").write_text(text)
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        pcode_calls=[
            {"call_address": "0x1010", "callee": "", "args": [{"var_name": "fd_a"}]},
            {"call_address": "0x1030", "callee": "", "args": [{"var_name": "fd_b"}]},
        ],
        c_line_addresses=[
            {"line_number": 2, "addresses": ["0x1030"]},
            {"line_number": 3, "addresses": ["0x1010"]},
        ],
    )
    manifest = replace(_manifest(), export_dir=str(export_dir), functions=[record])
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))

    from binary_agent.discovery import load_discovery_context

    operations = {
        item.operation_address: item
        for item in load_discovery_context(export_dir).index.operations
        if item.name == "close"
    }
    assert operations["0x1010"].arguments == ("fd_a",)
    assert operations["0x1010"].role("resource") == "fd_a"
    assert operations["0x1030"].arguments == ("fd_b",)
    assert operations["0x1030"].role("resource") == "fd_b"


def test_uninitialized_pcode_pointer_name_basis_is_not_stack_proof(
    tmp_path: Path,
) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    text = "void main(char *local_20) { consume(*local_20); }"
    (export_dir / "main.c").write_text(text)
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        pcode_loads=[
            {
                "operation_address": "0x1010",
                "read_width": 1,
                "address_vars": ["local_20"],
                "definedness": "undefined",
                "undefined_byte_ranges": [[0, 1]],
                "definedness_basis": "prior_pcode_store_variable_byte_ranges",
            }
        ],
    )
    manifest = replace(_manifest(), export_dir=str(export_dir), functions=[record])
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))

    from binary_agent.discovery import load_discovery_context

    operation = next(
        item
        for item in load_discovery_context(export_dir).index.operations
        if item.operation_address == "0x1010"
    )
    assert operation.definedness == ""
    assert operation.undefined_byte_ranges == ()
    assert (
        discover_candidates_for_type(
            export_dir,
            "memory_access",
            "uninitialized_memory_use",
        )
        == []
    )


def test_uninitialized_pcode_no_store_is_not_machine_proof(tmp_path: Path) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    text = "void main(void) { local_20 = source; consume(local_20); }"
    (export_dir / "main.c").write_text(text)
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        pcode_loads=[
            {
                "operation_address": "0x1010",
                "read_width": 8,
                "address_vars": ["local_20"],
                "stack_offset": -32,
                "definedness": "undefined",
                "defined_byte_ranges": [],
                "undefined_byte_ranges": [[-32, -24]],
                "definedness_basis": "prior_pcode_store_byte_ranges",
            }
        ],
    )
    manifest = replace(_manifest(), export_dir=str(export_dir), functions=[record])
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))

    from binary_agent.discovery import load_discovery_context

    operation = next(
        item
        for item in load_discovery_context(export_dir).index.operations
        if item.operation_address == "0x1010"
    )
    assert operation.definedness == ""
    assert (
        discover_candidates_for_type(
            export_dir,
            "memory_access",
            "uninitialized_memory_use",
        )
        == []
    )


def test_lifetime_aliases_reject_dereferenced_assignment_lhs(tmp_path: Path) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    text = """// Function: main
// Address: 0x1000

void main(void) {
  fd = open("input", 0);
  close(fd);
  *cursor = fd;
}"""
    (export_dir / "main.c").write_text(text)
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        pcode_calls=[
            {"call_address": "0x1010", "callee": "open", "args": ['"input"', "0"]},
            {"call_address": "0x1020", "callee": "close", "args": ["fd"]},
        ],
        c_line_addresses=[
            {"line_number": 2, "addresses": ["0x1010"]},
            {"line_number": 3, "addresses": ["0x1020"]},
            {"line_number": 4, "addresses": ["0x1030"]},
        ],
    )
    record = record.__class__.from_dict(
        {
            **record.to_dict(),
            "pcode_stores": [
                {
                    "operation_address": "0x1030",
                    "write_width": 4,
                    "address_vars": ["cursor"],
                }
            ],
        }
    )
    manifest = replace(_manifest(), export_dir=str(export_dir), functions=[record])
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))

    from binary_agent.discovery import load_discovery_context

    events = load_discovery_context(export_dir).index.lifecycle_events
    cursor_use = next(item for item in events if item.operation_address == "0x1030")
    assert cursor_use.resource_identity.endswith(":cursor")
    assert cursor_use.resource_kind == "memory"
    assert (
        discover_candidates_for_type(export_dir, "memory_lifetime", "use_after_close")
        == []
    )


def test_lifetime_cfg_does_not_continue_after_process_termination(tmp_path: Path) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    text = """// Function: main
// Address: 0x1000

void main(void) {
  fd = open("input", 0);
  if (child) {
    close(fd);
    exit(0);
  }
  read(fd, buffer, 4);
}"""
    (export_dir / "main.c").write_text(text)
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        pcode_calls=[
            {"call_address": "0x1010", "callee": "open", "args": ['"input"', "0"]},
            {"call_address": "0x1020", "callee": "close", "args": ["fd"]},
            {"call_address": "0x1030", "callee": "exit", "args": ["0"]},
            {"call_address": "0x1050", "callee": "read", "args": ["fd", "buffer", "4"]},
        ],
        c_line_addresses=[
            {"line_number": 2, "addresses": ["0x1010"]},
            {"line_number": 4, "addresses": ["0x1020"]},
            {"line_number": 5, "addresses": ["0x1030"]},
            {"line_number": 7, "addresses": ["0x1050"]},
        ],
    )
    record = record.__class__.from_dict(
        {
            **record.to_dict(),
            "basic_blocks": [
                {"start": "0x1010", "end": "0x101f", "successors": ["0x1020", "0x1050"]},
                {"start": "0x1020", "end": "0x102f", "successors": ["0x1030"]},
                # Model a conservative decompiler edge after noreturn exit().
                {"start": "0x1030", "end": "0x103f", "successors": ["0x1050"]},
                {"start": "0x1050", "end": "0x105f", "successors": []},
            ],
        }
    )
    manifest = replace(_manifest(), export_dir=str(export_dir), functions=[record])
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))

    from binary_agent.discovery import load_discovery_context

    context = load_discovery_context(export_dir)
    release = next(item for item in context.index.lifecycle_events if item.operation_address == "0x1020")
    use = next(item for item in context.index.lifecycle_events if item.operation_address == "0x1050")
    assert context.index.event_relation(release, use).relation == "cfg_process_terminated_before_after"
    assert (
        discover_candidates_for_type(export_dir, "memory_lifetime", "use_after_close")
        == []
    )


def test_uninitialized_fallback_does_not_assume_unknown_pointer_call_writes(
    tmp_path: Path,
) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "main.c": """void main(void) {
  undefined8 local_a0;
  unknown_call(&local_a0);
  consume(local_a0);
}"""
        },
    )

    states = discover_candidates_for_type(
        export_dir,
        "memory_access",
        "uninitialized_memory_use",
    )
    assert len(states) == 1
    assert states[0].source["expression"] == "local_a0"
    assert states[0].location["line_number"] == 4
    assert states[0].blockers == ["machine_definedness_unresolved"]


def test_uninitialized_fallback_recovers_multiline_output_array_call(
    tmp_path: Path,
) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "main.c": """void main(void) {
  long local_20;
  (*(code *)PTR_blobmsg_parse_00438fb8)
      (&policy,1,&local_20,data,length);
  consume(local_20);
}"""
        },
    )

    from binary_agent.discovery import load_discovery_context

    operation = next(
        item
        for item in load_discovery_context(export_dir).index.operations
        if item.name == "blobmsg_parse"
    )
    assert operation.arguments == ("&policy", "1", "&local_20", "data", "length")
    assert operation.output_pointer_args == (2,)
    assert (
        discover_candidates_for_type(
            export_dir,
            "memory_access",
            "uninitialized_memory_use",
        )
        == []
    )


def test_uninitialized_fallback_understands_sequenced_assignment_and_local_output(
    tmp_path: Path,
) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "main.c": """void main(void) {
  long local_20;
  long local_18;
  if ((local_18 = source, local_18 != 0)) consume(local_18);
  helper(&local_20);
  consume(local_20);
}""",
            "helper.c": """void helper(long *param_1) {
  *param_1 = 7;
  return;
}""",
        },
    )

    from binary_agent.discovery import load_discovery_context

    operation = next(
        item
        for item in load_discovery_context(export_dir).index.operations
        if item.function_name == "main" and item.name == "helper"
    )
    assert operation.output_pointer_args == (0,)
    assert operation.output_write_guarantee == "always"
    assert (
        discover_candidates_for_type(
            export_dir,
            "memory_access",
            "uninitialized_memory_use",
        )
        == []
    )


def test_uninitialized_fallback_keeps_conditional_local_output_and_self_read(
    tmp_path: Path,
) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "main.c": """void main(void) {
  long local_20;
  local_20 = local_20 + 1;
  helper(&local_20);
  consume(local_20);
}""",
            "helper.c": """void helper(long *param_1) {
  if (flag) { *param_1 = 7; }
}""",
        },
    )
    states = discover_candidates_for_type(
        export_dir,
        "memory_access",
        "uninitialized_memory_use",
    )
    assert len(states) == 1
    assert states[0].source["expression"] == "local_20"


@pytest.mark.parametrize("name", ["in_RAX", "in_FS_OFFSET", "unaff_RBX", "extraout_RDX"])
def test_uninitialized_fallback_ignores_decompiler_incoming_registers(
    tmp_path: Path,
    name: str,
) -> None:
    export_dir = _write_export(
        tmp_path,
        {"main.c": f"void main(void) {{\n  long {name};\n  consume({name});\n}}"},
    )
    assert (
        discover_candidates_for_type(
            export_dir,
            "memory_access",
            "uninitialized_memory_use",
        )
        == []
    )


def test_lifetime_generation_reacquire_breaks_release_to_use_loop(
    tmp_path: Path,
) -> None:
    text = """void main(void) {
  FILE *stream;
loop:
  stream = fopen("input", "r");
  fgets(buffer, 4, stream);
  fclose(stream);
  goto loop;
}"""
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    (export_dir / "main.c").write_text(text)
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        pcode_calls=[
            {"call_address": "0x1010", "callee": "fopen", "args": ['"input"', '"r"']},
            {"call_address": "0x1020", "callee": "fgets", "args": ["buffer", "4", "stream"]},
            {"call_address": "0x1030", "callee": "fclose", "args": ["stream"]},
        ],
        c_line_addresses=[
            {"line_number": 4, "addresses": ["0x1010"]},
            {"line_number": 5, "addresses": ["0x1020"]},
            {"line_number": 6, "addresses": ["0x1030"]},
        ],
    )
    record = record.__class__.from_dict(
        {
            **record.to_dict(),
            "basic_blocks": [
                {"start": "0x1010", "end": "0x101f", "successors": ["0x1020"]},
                {"start": "0x1020", "end": "0x102f", "successors": ["0x1030"]},
                {"start": "0x1030", "end": "0x103f", "successors": ["0x1010"]},
            ],
        }
    )
    manifest = Manifest(
        binary="fixture.bin",
        generated_at="2026-07-13T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest="manifest.jsonl",
        callgraph_path=None,
        functions=[record],
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))

    from binary_agent.discovery import load_discovery_context

    context = load_discovery_context(export_dir)
    fopen = next(item for item in context.index.operations if item.name == "fopen")
    assert fopen.role("result") == "stream"
    events = [item for item in context.index.lifecycle_events if item.resource_identity.endswith(":stream")]
    allocation = next(item for item in events if item.event_kind == "allocate")
    release = next(item for item in events if item.event_kind == "release")
    use = next(item for item in events if item.event_kind == "use")
    assert context.index.event_relation(release, use).feasible is True
    assert context.index.event_path_avoiding(release, use, (allocation,)) is False
    assert (
        discover_candidates_for_type(
            export_dir,
            "memory_lifetime",
            "use_after_close",
        )
        == []
    )


def test_symbolic_memcpy_ranges_defer_to_concrete_native_overlap_proof(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "main.c": (
                "void main(char *user_destination, char *user_source, size_t user_size) { "
                "memcpy(user_destination, user_source, user_size); }"
            )
        },
    )
    states = discover_candidates_for_type(export_dir, "memory_access", "overlapping_memory_copy")
    assert len(states) == 1
    assert states[0].type_facts["range_proof"] == "native_concrete_ranges_required"
    assert states[0].blockers == ["concrete_range_replay_required"]


@pytest.mark.parametrize("vulnerability_type", sorted(VULNERABILITY_SPECS))
def test_every_taxonomy_type_has_proof_and_report_rendering(vulnerability_type: str) -> None:
    spec = VULNERABILITY_SPECS[vulnerability_type]
    state = _state(spec.backend, vulnerability_type)
    evidence = {
        "scope": "function_harness",
        "exact_operation_reached": True,
        "operation_address": "0x1010",
    }
    if spec.backend == "memory_access":
        if vulnerability_type == "null_pointer_dereference":
            payload = {"pointer_value": 0, "accessed": True}
        elif vulnerability_type == "uninitialized_memory_use":
            payload = {"definedness": "undefined", "read": True, "undefined_byte_ranges": [[0, 4]]}
        elif vulnerability_type == "overlapping_memory_copy":
            payload = {"ranges_overlap": True, "operation": "memcpy"}
        else:
            payload = {"same_object": True, "object_range": [0, 8], "access_range": [0, 16], "out_of_bounds": True}
        evidence["memory_access"] = payload
    elif spec.backend == "memory_lifetime":
        if vulnerability_type == "memory_leak":
            payload = {
                "same_resource": True,
                "path_local": True,
                "escaped": False,
                "live_at_scope_exit": True,
                "resource_generation": 1,
                "scope_exit": "main_return",
                "events": [{"action": "scope_exit", "generation": 1}],
            }
        elif vulnerability_type == "mismatched_deallocator":
            payload = {"same_resource": True, "allocator_family": "cpp_scalar", "deallocator_family": "c_heap"}
        else:
            payload = {"same_resource": True, "events": ["release", "use"], "violation": True}
        evidence["lifetime_violation"] = payload
    elif spec.backend == "semantic_effect":
        evidence.update(
            {
                "scope": "process_entrypoint",
                "concrete_input": {"stdin": "attacker value"},
                "process_setup": {"status": "configured"},
                "native_replay": {"status": "observed"},
                "effect_observation": {"status": "observed", "kind": spec.effect_kind},
            }
        )
    else:
        evidence = {"static_evidence": {"exact": True, "reachable": True, "kind": spec.effect_kind}}
    result = dispatch_proof(state, evidence)
    assert result.status == "proven"
    rendered = render_backend_finding(state, result)
    assert rendered["vulnerability_type"] == vulnerability_type
    assert rendered["backend"] == spec.backend
