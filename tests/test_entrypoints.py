import json
from pathlib import Path

import pytest

from binary_agent.analysis.concolic import build_concolic_request
from binary_agent.analysis.confirmation import build_evidence_pack_v3
from binary_agent.analysis.entrypoints import EntryPointDeriver
from binary_agent.analysis.program_index import build_program_index
from binary_agent.data.manifest import FunctionRecord, Manifest
from binary_agent.pipeline import CandidateState


def _record(
    name: str,
    address: str,
    relative_path: str,
    *,
    text: str = "",
    pcode_calls: list[dict] | None = None,
    ambiguous_callsites: list[dict] | None = None,
    source_symbol: str = "",
    parameters: list[dict] | None = None,
    global_refs: list[dict] | None = None,
) -> FunctionRecord:
    return FunctionRecord(
        address=address,
        relative_address=int(address, 16),
        name=name,
        relative_path=relative_path,
        source_exists=True,
        ordinal=int(address, 16),
        size_addresses=32,
        body_size_bytes=len(text.encode("utf-8")),
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=len(text.encode("utf-8")),
        line_count=max(1, len(text.splitlines())),
        return_type="void",
        prototype=f"void {name}(void)",
        parameters=parameters or [],
        emit_c=True,
        source_symbol=source_symbol,
        pcode_calls=pcode_calls or [],
        ambiguous_callsites=ambiguous_callsites or [],
        global_refs=global_refs or [],
    )


def _write_export(tmp_path: Path, records: list[FunctionRecord], *, callgraph: dict[str, list[str]] | None) -> Path:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    for record in records:
        (export_dir / record.relative_path).write_text(f"void {record.name}(void) {{}}\n")
    if callgraph is not None:
        (export_dir / "callgraph.json").write_text(json.dumps({"image_base": 0, "edges": callgraph}))
    manifest = Manifest(
        binary="demo",
        generated_at="2026-05-19T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path="callgraph.json" if callgraph is not None else None,
        functions=records,
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))
    return export_dir


def _candidate() -> dict:
    return {
        "candidate_id": "cand-entry",
        "vulnerability_type": "command_injection",
        "status": "proof_ready",
        "target": {"binary": "demo"},
        "location": {"function_name": "target", "address": "0x1200", "relative_path": "target.c"},
        "source": {"kind": "attacker_input"},
        "sink": {"name": "system"},
        "type_facts": {
            "semantic_seed": {"seed_id": "seed-entry", "vulnerability_type": "command_injection"},
            "replay_hints": {
                "mode": "function_harness",
                "input": {"param": "payload"},
            }
        },
        "proof_obligations": [],
        "blockers": [],
    }


def _candidate_with_source_to_sink_trace() -> dict:
    candidate = _candidate()
    candidate["classification_trace"] = {
        "source_to_write": {
            "complete": True,
            "roles": {
                "write_source": {
                    "classification": "source_controlled",
                    "expr": "argv[1]",
                },
                "destination_pointer": {
                    "classification": "local_stack_object",
                    "expr": "local_20",
                },
            },
        }
    }
    return candidate


def test_entrypoint_derivation_uses_structured_callgraph_and_pcode_sources(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", pcode_calls=[{"callee": "read", "address": "0x1004"}]),
            _record("parse", "0x1100", "parse.c"),
            _record("target", "0x1200", "target.c"),
        ],
        callgraph={"main": ["parse"], "parse": ["target"], "target": []},
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(_candidate()).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["entry_surface"]["kind"] == "program_entry"
    assert derivation["call_path"] == ["main", "parse", "target"]
    assert derivation["input_model"] == "stdin"
    assert derivation["no_text_matching"] is True
    assert derivation["evidence"]["input_observations"][0]["callee"] == "read"
    assert derivation["source_to_sink_trace"]["status"] == "blocked"
    assert "missing_source_to_write_trace" in derivation["source_to_sink_trace"]["blockers"]


def test_entrypoint_derivation_records_complete_source_to_sink_trace(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", pcode_calls=[{"callee": "read", "address": "0x1004"}]),
            _record("target", "0x1200", "target.c"),
        ],
        callgraph={"main": ["target"], "target": []},
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(_candidate_with_source_to_sink_trace()).to_dict()

    assert derivation["status"] == "derived"
    trace = derivation["source_to_sink_trace"]
    assert trace["status"] == "complete"
    assert trace["attacker_control_reaches_sink_role"] is True
    assert trace["entry_function"] == "main"
    assert trace["controlled_roles"] == ["write_source:source_controlled"]
    assert trace["schema_version"] == 2
    assert trace["argument_roles"][0]["role"] == "write_source"
    assert trace["argument_roles"][0]["expr"] == "argv[1]"
    assert trace["sink_argument"]["role"] == "write_source"
    assert trace["propagation_path"] == [
        {"kind": "function", "function": "main", "index": 0, "role": "entry"},
        {"kind": "function", "function": "target", "index": 1, "role": "sink_function"},
    ]
    assert trace["source_artifacts"][0]["kind"] == "entry_surface"


def test_reused_entrypoint_deriver_keeps_candidate_specific_trace(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", pcode_calls=[{"callee": "read", "address": "0x1004"}]),
            _record("target", "0x1200", "target.c"),
        ],
        callgraph={"main": ["target"], "target": []},
    )
    deriver = EntryPointDeriver.from_export_dir(export_dir)

    incomplete = deriver.derive_for_candidate(_candidate()).to_dict()
    complete = deriver.derive_for_candidate(_candidate_with_source_to_sink_trace()).to_dict()

    assert incomplete["call_path"] == complete["call_path"] == ["main", "target"]
    assert incomplete["source_to_sink_trace"]["status"] == "blocked"
    assert complete["source_to_sink_trace"]["status"] == "complete"
    assert complete["source_to_sink_trace"]["controlled_roles"] == ["write_source:source_controlled"]


def test_entrypoint_derivation_accepts_program_entry_local_stdin_oob_read(tmp_path: Path) -> None:
    text = """
int main(void) {
  unsigned char heartbeat_record[8];
  unsigned char dst[64];
  unsigned int payload;
  read(0, heartbeat_record, 8);
  payload = CONCAT11(heartbeat_record[1], heartbeat_record[2]);
  memcpy(dst, heartbeat_record + 3, payload);
}
"""
    export_dir = _write_export(
        tmp_path,
        [
            _record(
                "main",
                "0x1000",
                "main.c",
                text=text,
                source_symbol="main",
            )
        ],
        callgraph={"main": []},
    )
    candidate = {
        "candidate_id": "heartbleed-shaped",
        "vulnerability_type": "out_of_bounds_read",
        "location": {"function_name": "main", "address": "0x1000", "relative_path": "main.c"},
        "sink": "memcpy_source_read",
        "write_relation": "symbolic_size",
        "source_evidence": ["line 6: read(0, heartbeat_record, 8);"],
        "classification_trace": {
            "reachability_dataflow": {
                "graph": {
                    "has_real_path": True,
                    "path_is_valid": True,
                    "input_reaches_sink": True,
                    "call_path": ["main"],
                },
                "source_link": {"local_source_sources": ["source_call:read:line 6"]},
            },
            "source_to_write": {
                "complete": False,
                "roles": {
                    "write_source": {"classification": "unknown", "expr": "", "complete": False},
                    "write_size": {
                        "classification": "source_controlled",
                        "expr": "CONCAT11(heartbeat_record[1], heartbeat_record[2])",
                        "complete": True,
                    },
                    "write_offset": {"classification": "constant_or_literal", "expr": "0", "complete": True},
                },
            },
        },
    }

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(candidate).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["input_model"] == "stdin"
    trace = derivation["source_to_sink_trace"]
    assert trace["status"] == "complete"
    assert trace["input_model"] == "stdin"
    assert trace["sink_argument"]["role"] == "write_size"
    assert trace["blockers"] == []


def test_entrypoint_derivation_accepts_entry_stdin_evidence_for_interprocedural_oob_read(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", source_symbol="main"),
            _record("tls1_process_heartbeat", "0x2000", "tls.c"),
        ],
        callgraph={"main": ["tls1_process_heartbeat"], "tls1_process_heartbeat": []},
    )
    candidate = {
        "candidate_id": "interprocedural-heartbleed-shaped",
        "vulnerability_type": "out_of_bounds_read",
        "location": {
            "function_name": "tls1_process_heartbeat",
            "address": "0x2000",
            "relative_path": "tls.c",
        },
        "sink": "memcpy_source_read",
        "write_relation": "symbolic_size",
        "source_evidence": ["line 6: read(0, heartbeat_record, 8);"],
        "classification_trace": {
            "reachability_dataflow": {
                "graph": {
                    "has_real_path": True,
                    "path_is_valid": True,
                    "input_reaches_sink": True,
                    "call_path": ["main", "tls1_process_heartbeat"],
                },
                "source_link": {"local_source_sources": ["source_call:read:line 6"]},
            },
            "source_to_write": {
                "complete": False,
                "roles": {
                    "write_source": {"classification": "unknown", "expr": "", "complete": False},
                    "write_size": {
                        "classification": "source_controlled",
                        "expr": "uVar6",
                        "complete": True,
                    },
                    "write_offset": {"classification": "constant_or_literal", "expr": "0", "complete": True},
                },
            },
        },
    }

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(candidate).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["entry_function"] == "main"
    assert derivation["target_function"] == "tls1_process_heartbeat"
    assert derivation["input_model"] == "stdin"
    assert derivation["evidence"]["input_observations"][0]["source"] == "candidate_source_evidence"
    assert derivation["source_to_sink_trace"]["status"] == "complete"


def test_entrypoint_derivation_rejects_interprocedural_stdin_evidence_without_entry_path(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", source_symbol="main"),
            _record("tls1_process_heartbeat", "0x2000", "tls.c"),
        ],
        callgraph={"main": ["tls1_process_heartbeat"], "tls1_process_heartbeat": []},
    )
    candidate = {
        "candidate_id": "interprocedural-heartbleed-shaped",
        "vulnerability_type": "out_of_bounds_read",
        "location": {
            "function_name": "tls1_process_heartbeat",
            "address": "0x2000",
            "relative_path": "tls.c",
        },
        "sink": "memcpy_source_read",
        "write_relation": "symbolic_size",
        "source_evidence": ["line 6: read(0, heartbeat_record, 8);"],
        "classification_trace": {
            "reachability_dataflow": {"graph": {"has_real_path": True, "path_is_valid": True}},
            "source_to_write": {
                "complete": False,
                "roles": {
                    "write_size": {"classification": "source_controlled", "expr": "uVar6", "complete": True},
                },
            },
        },
    }

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(candidate).to_dict()

    assert derivation["status"] == "blocked"
    assert derivation["input_model"] == ""
    assert "no_structured_process_input_source" in derivation["blockers"]


def test_entrypoint_derivation_follows_libc_start_main_handoff(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record(
                "entry",
                "0x1000",
                "entry.c",
                global_refs=[
                    {"address": "0x1100", "label": "FUN_00001100", "block": ".text"},
                    {"address": "0x3000", "label": "PTR___libc_start_main_00003000", "block": ".got"},
                ],
            ),
            _record("FUN_00001100", "0x1100", "main.c"),
            _record("target", "0x1200", "target.c"),
            _record("__libc_start_main", "0x1300", "libc.c"),
        ],
        callgraph={"entry": ["__libc_start_main"], "FUN_00001100": ["target"], "target": [], "__libc_start_main": []},
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(
        _candidate_with_source_to_sink_trace()
    ).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["entry_function"] == "FUN_00001100"
    assert derivation["entry_address"] == "0x1100"
    assert derivation["call_path"] == ["FUN_00001100", "target"]
    assert derivation["input_model"] == "argv"
    assert derivation["source_to_sink_trace"]["status"] == "complete"
    assert derivation["source_to_sink_trace"]["source_artifacts"][0]["evidence"]["source"] == "__libc_start_main_handoff"


def test_entrypoint_derivation_recovers_main_from_libc_pcode_argument(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record(
                "entry",
                "0x1000",
                "entry.c",
                pcode_calls=[
                    {
                        "callee": "__libc_start_main",
                        "call_address": "0x1008",
                        "args": [{"address": "0x1100", "address_space": "ram"}],
                    }
                ],
            ),
            _record("FUN_00001100", "0x1100", "main.c"),
            _record("target", "0x1200", "target.c"),
            _record("__libc_start_main", "0x1300", "libc.c"),
        ],
        callgraph={"entry": ["__libc_start_main"], "FUN_00001100": ["target"], "target": [], "__libc_start_main": []},
    )

    deriver = EntryPointDeriver.from_export_dir(export_dir)
    derivation = deriver.derive_for_candidate(_candidate_with_source_to_sink_trace()).to_dict()
    index = build_program_index(deriver.manifest, deriver.nodes)

    assert derivation["entry_function"] == "FUN_00001100"
    assert derivation["call_path"] == ["FUN_00001100", "target"]
    assert any(
        item.function_name == "FUN_00001100" and item.kind == "process_main"
        for item in index.entry_surfaces
    )


@pytest.mark.parametrize(
    ("family", "expected_kind", "protocol"),
    [
        ("uloop", "uloop_callback", "uloop"),
        ("runqueue", "runqueue_callback", "runqueue"),
        ("http", "http_handler", "http"),
        ("cgi", "cgi_handler", "cgi"),
    ],
)
def test_entrypoint_derivation_recovers_structured_callback_families(
    tmp_path: Path,
    family: str,
    expected_kind: str,
    protocol: str,
) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record(
                "register_callbacks",
                "0x1000",
                "register.c",
                pcode_calls=[
                    {
                        "callee": f"{family}_register",
                        "call_address": "0x1008",
                        "callback_registration": {
                            "family": family,
                            "callback": "event_handler",
                            "event": "request",
                            "registration_address": "0x1008",
                        },
                    }
                ],
            ),
            _record("event_handler", "0x1100", "handler.c"),
        ],
        callgraph={"register_callbacks": [], "event_handler": []},
    )

    deriver = EntryPointDeriver.from_export_dir(export_dir)
    surfaces = deriver._entry_surfaces()
    index = build_program_index(deriver.manifest, deriver.nodes)

    surface = next(item for item in surfaces if item.function == "event_handler")
    assert surface.kind == expected_kind
    assert surface.evidence["protocol"] == protocol
    assert surface.evidence["registration_address"] == "0x1008"
    indexed = next(
        item
        for item in index.entry_surfaces
        if item.function_name == "event_handler" and item.kind == expected_kind
    )
    assert indexed.protocol == protocol
    assert indexed.event_name == "request"
    assert indexed.registration_address == "0x1008"


def test_entrypoint_derivation_uses_cached_callgraph_api_source_edges(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c"),
            _record("target", "0x1200", "target.c"),
            _record("getopt_long", "0x1300", "getopt_long.c"),
        ],
        callgraph={"main": ["getopt_long", "target"], "target": [], "getopt_long": []},
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(_candidate()).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["call_path"] == ["main", "target"]
    assert derivation["input_model"] == "argv"
    assert derivation["evidence"]["input_observations"][0]["source"] == "structured_callgraph_edge"
    assert derivation["evidence"]["input_observations"][0]["callee"] == "getopt_long"


def test_entrypoint_derivation_prefers_explicit_input_api_over_main_argv_shape(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record(
                "main",
                "0x1000",
                "main.c",
                pcode_calls=[{"callee": "getenv", "address": "0x1008"}],
                parameters=[
                    {"name": "argc", "data_type": "int"},
                    {"name": "argv", "data_type": "char **"},
                ],
            ),
            _record("target", "0x1200", "target.c"),
            _record("getenv", "0x1300", "getenv.c"),
        ],
        callgraph={"main": ["getenv", "target"], "target": [], "getenv": []},
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(_candidate()).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["input_model"] == "env"
    assert derivation["evidence"]["input_observations"][0]["callee"] == "getenv"


def test_entrypoint_derivation_uses_supported_env_source(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c"),
            _record("parse", "0x1100", "parse.c"),
            _record("target", "0x1200", "target.c"),
            _record("getenv", "0x1300", "getenv.c"),
            _record("read", "0x1400", "read.c"),
        ],
        callgraph={"main": ["getenv", "parse"], "parse": ["read", "target"], "target": [], "getenv": [], "read": []},
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(_candidate()).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["input_model"] == "env"
    assert [item["callee"] for item in derivation["evidence"]["input_observations"]] == ["getenv"]


@pytest.mark.parametrize(
    ("callee", "input_model"),
    [
        ("mq_receive", "ipc"),
        ("ioctl", "device"),
        ("nvram_get", "config"),
    ],
)
def test_entrypoint_derivation_blocks_known_unsupported_process_surfaces(
    tmp_path: Path,
    callee: str,
    input_model: str,
) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", pcode_calls=[{"callee": callee, "address": "0x1004"}]),
            _record("target", "0x1200", "target.c"),
            _record(callee, "0x1300", f"{callee}.c"),
        ],
        callgraph={"main": [callee, "target"], "target": [], callee: []},
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(
        _candidate_with_source_to_sink_trace()
    ).to_dict()

    assert derivation["status"] == "blocked"
    assert derivation["input_model"] == ""
    assert derivation["process_input_supported"] is False
    assert derivation["evidence"]["input_observations"][0]["input_model"] == input_model
    assert f"unsupported_process_input_model:{input_model}" in derivation["blockers"]
    trace = derivation["source_to_sink_trace"]
    assert trace["status"] == "blocked"
    assert trace["evidence"]["observed_input_model"] == input_model
    assert f"unsupported_process_input_model:{input_model}" in trace["blockers"]


@pytest.mark.parametrize("callee", ["recv", "accept"])
def test_entrypoint_derivation_uses_supported_socket_service_source(tmp_path: Path, callee: str) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", pcode_calls=[{"callee": callee, "address": "0x1004"}]),
            _record("target", "0x1200", "target.c"),
            _record(callee, "0x1300", f"{callee}.c"),
        ],
        callgraph={"main": [callee, "target"], "target": [], callee: []},
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(
        _candidate_with_source_to_sink_trace()
    ).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["input_model"] == "socket_service"
    assert derivation["process_input_supported"] is True
    assert derivation["evidence"]["input_observations"][0]["input_model"] == "socket_service"
    assert derivation["source_to_sink_trace"]["input_model"] == "socket_service"


def test_entrypoint_derivation_recognizes_http_protocol_over_recv(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", pcode_calls=[{"callee": "recv", "address": "0x1004"}]),
            _record("target", "0x1200", "target.c"),
            _record("recv", "0x1300", "recv.c"),
        ],
        callgraph={"main": ["recv", "target"], "target": [], "recv": []},
    )
    (export_dir / "main.c").write_text(
        'void main(void) { recv(fd, request, 512, 0); strstr(request, "GET /"); strstr(request, "HTTP/1.1"); }\n'
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(
        _candidate_with_source_to_sink_trace()
    ).to_dict()

    assert derivation["input_model"] == "http_daemon"
    assert derivation["evidence"]["input_observations"][0]["input_model"] == "http_daemon"


@pytest.mark.parametrize("callee", ["http_parser_execute", "httpd_parse_request", "mg_http_parse"])
def test_entrypoint_derivation_uses_supported_http_daemon_source(tmp_path: Path, callee: str) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", pcode_calls=[{"callee": callee, "address": "0x1004"}]),
            _record("target", "0x1200", "target.c"),
            _record(callee, "0x1300", f"{callee}.c"),
        ],
        callgraph={"main": [callee, "target"], "target": [], callee: []},
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(
        _candidate_with_source_to_sink_trace()
    ).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["input_model"] == "http_daemon"
    assert derivation["process_input_supported"] is True
    assert derivation["evidence"]["input_observations"][0]["input_model"] == "http_daemon"
    assert derivation["source_to_sink_trace"]["input_model"] == "http_daemon"


def test_entrypoint_derivation_records_async_indirect_and_devirtualization_limitations(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record(
                "main",
                "0x1000",
                "main.c",
                pcode_calls=[
                    {"callee": "epoll_wait", "address": "0x1004"},
                    {"callee": "recv", "address": "0x1008"},
                ],
            ),
            _record(
                "target",
                "0x1200",
                "target.c",
                pcode_calls=[{"target_kind": "indirect", "address": "0x1208"}],
                ambiguous_callsites=[
                    {
                        "call_address": "0x1210",
                        "ambiguity_reasons": ["vtable_dispatch", "indirect_call"],
                    }
                ],
            ),
            _record("recv", "0x1300", "recv.c"),
            _record("epoll_wait", "0x1400", "epoll_wait.c"),
        ],
        callgraph={"main": ["recv", "epoll_wait", "target"], "target": [], "recv": [], "epoll_wait": []},
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(
        _candidate_with_source_to_sink_trace()
    ).to_dict()

    limitations = derivation["evidence"]["execution_limitations"]
    kinds = {item["kind"] for item in limitations}
    assert {"async_event_loop", "unresolved_indirect_target", "arbitrary_devirtualization_required"} <= kinds
    assert derivation["source_to_sink_trace"]["execution_limitations"] == limitations


def test_entrypoint_derivation_records_intake_service_launch_surface(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", pcode_calls=[{"callee": "read", "address": "0x1004"}]),
            _record("target", "0x1200", "target.c"),
            _record("read", "0x1300", "read.c"),
        ],
        callgraph={"main": ["target"], "target": [], "read": []},
    )
    candidate = _candidate()
    candidate["target"] = {"path": "/rootfs/usr/bin/httpd", "relative_path": "usr/bin/httpd", "binary": "httpd"}
    intake = {
        "binaries": {"binaries": [{"path": "/rootfs/usr/bin/httpd", "relative_path": "usr/bin/httpd"}]},
        "services": {
            "services": [
                {
                    "service_id": "service:web",
                    "name": "web",
                    "relative_path": "etc/init.d/web",
                    "path": "/rootfs/etc/init.d/web",
                    "exec": "/usr/bin/httpd -p 8080",
                    "ports": [8080],
                    "evidence": [{"kind": "service_file", "path": "/rootfs/etc/init.d/web"}],
                }
            ]
        },
    }

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(candidate, intake_facts=intake).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["entry_surface"]["kind"] == "daemon_launch"
    assert derivation["entry_surface"]["evidence"]["services"][0]["exec"] == "/usr/bin/httpd -p 8080"
    assert derivation["entry_reachability"]["entry_surface_kind"] == "daemon_launch"
    assert derivation["input_model"] == "stdin"


def test_entrypoint_derivation_records_cgi_route_surface(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", pcode_calls=[{"callee": "getenv", "address": "0x1004"}]),
            _record("target", "0x1200", "target.c"),
            _record("getenv", "0x1300", "getenv.c"),
        ],
        callgraph={"main": ["target"], "target": [], "getenv": []},
    )
    candidate = _candidate()
    candidate["target"] = {
        "path": "/rootfs/www/cgi-bin/diag",
        "relative_path": "www/cgi-bin/diag",
        "binary": "diag",
    }
    candidate["source"] = {"kind": "route", "expression": "/cgi-bin/diag"}
    intake = {
        "binaries": {"binaries": [{"path": "/rootfs/www/cgi-bin/diag", "relative_path": "www/cgi-bin/diag"}]},
        "routes": {
            "routes": [
                {
                    "route_id": "route:diag",
                    "route": "/cgi-bin/diag",
                    "method": "POST",
                    "relative_path": "etc/httpd.conf",
                    "path": "/rootfs/etc/httpd.conf",
                    "evidence": [{"kind": "route_table_row", "path": "/rootfs/etc/httpd.conf"}],
                }
            ]
        },
    }

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(candidate, intake_facts=intake).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["entry_surface"]["kind"] == "cgi_handler"
    assert derivation["entry_surface"]["evidence"]["routes"][0]["route"] == "/cgi-bin/diag"
    assert derivation["source_to_sink_trace"]["entry_surface_kind"] == "cgi_handler"
    assert derivation["input_model"] == "http_cgi"


def test_entrypoint_derivation_records_busybox_applet_surface(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", pcode_calls=[{"callee": "read", "address": "0x1004"}]),
            _record("target", "0x1200", "target.c"),
            _record("read", "0x1300", "read.c"),
        ],
        callgraph={"main": ["target"], "target": [], "read": []},
    )
    candidate = _candidate()
    candidate["target"] = {"path": "/rootfs/bin/busybox", "relative_path": "bin/busybox", "binary": "busybox"}
    intake = {
        "binaries": {"binaries": [{"path": "/rootfs/bin/busybox", "relative_path": "bin/busybox"}]},
        "services": {
            "services": [
                {
                    "service_id": "service:httpd",
                    "relative_path": "etc/init.d/httpd",
                    "path": "/rootfs/etc/init.d/httpd",
                    "exec": "/bin/busybox httpd -f -p 8080",
                    "ports": [8080],
                }
            ]
        },
    }

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(candidate, intake_facts=intake).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["entry_surface"]["kind"] == "busybox_applet"
    assert derivation["entry_surface"]["evidence"]["busybox_applet"] == "httpd"


def test_entrypoint_derivation_ignores_target_local_read_or_file_api_as_source(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c"),
            _record(
                "target",
                "0x1200",
                "target.c",
                pcode_calls=[
                    {"callee": "read", "address": "0x1210"},
                    {"callee": "open", "address": "0x1218"},
                ],
            ),
            _record("read", "0x1300", "read.c"),
            _record("open", "0x1400", "open.c"),
        ],
        callgraph={"main": ["target"], "target": ["read", "open"], "read": [], "open": []},
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(_candidate()).to_dict()

    assert derivation["status"] == "blocked"
    assert derivation["input_model"] == ""
    assert "no_structured_process_input_source" in derivation["blockers"]
    assert derivation["evidence"]["input_observations"] == []


def test_entrypoint_derivation_checks_multiple_structured_paths(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("env_root", "0x1000", "env_root.c", source_symbol="env_root"),
            _record("stdin_root", "0x1100", "stdin_root.c", source_symbol="stdin_root"),
            _record("target", "0x1200", "target.c"),
            _record("getenv", "0x1300", "getenv.c"),
            _record("read", "0x1400", "read.c"),
        ],
        callgraph={
            "env_root": ["getenv", "target"],
            "stdin_root": ["read", "target"],
            "target": [],
            "getenv": [],
            "read": [],
        },
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(_candidate()).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["call_path"] == ["env_root", "target"]
    assert derivation["input_model"] == "env"
    assert derivation["evidence"]["candidate_path_count"] == 2
    assert derivation["evidence"]["candidate_paths"][0]["input_model"] == "env"
    assert derivation["evidence"]["candidate_paths"][1]["input_model"] == "stdin"


def test_entrypoint_derivation_prefers_shortest_supported_path(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        [
            _record("long_root", "0x1000", "long_root.c", source_symbol="long_root"),
            _record("middle", "0x1100", "middle.c"),
            _record("short_root", "0x1200", "short_root.c", source_symbol="short_root"),
            _record("target", "0x1300", "target.c"),
            _record("read", "0x1400", "read.c"),
        ],
        callgraph={
            "long_root": ["read", "middle"],
            "middle": ["target"],
            "short_root": ["read", "target"],
            "target": [],
            "read": [],
        },
    )

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(_candidate()).to_dict()

    assert derivation["status"] == "derived"
    assert derivation["call_path"] == ["short_root", "target"]
    assert derivation["input_model"] == "stdin"


def test_entrypoint_derivation_does_not_use_decompiled_text_call_edges(tmp_path: Path) -> None:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    root = _record("main", "0x1000", "main.c", pcode_calls=[{"callee": "read", "address": "0x1004"}])
    target = _record("target", "0x1200", "target.c")
    (export_dir / "main.c").write_text("void main(void) { target(); }\n")
    (export_dir / "target.c").write_text("void target(void) {}\n")
    manifest = Manifest(
        binary="demo",
        generated_at="2026-05-19T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=[root, target],
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))

    derivation = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(_candidate()).to_dict()

    assert derivation["status"] == "blocked"
    assert derivation["call_path"] == []
    assert "target_not_reachable_from_explicit_entry_surface" in derivation["blockers"]


def test_derived_entrypoint_overrides_function_harness_hint_in_evidence_pack() -> None:
    state = CandidateState.from_dict(_candidate())
    derivation = {
        "schema_version": 1,
        "status": "derived",
        "entry_function": "main",
        "entry_address": "0x1000",
        "input_model": "stdin",
        "process_input_supported": True,
        "call_path": ["main", "target"],
        "entry_surface": {"function": "main", "address": "0x1000", "kind": "program_entry"},
        "no_text_matching": True,
    }

    pack = build_evidence_pack_v3(state.to_dict(), entrypoint_derivation=derivation)

    assert pack["entrypoint_derivation"]["status"] == "derived"
    assert pack["facts_available_to_llm"]["reproducer_hypothesis"]["input_surface"] == "stdin"


def test_semantic_function_harness_concolic_blocks_when_entrypoint_is_blocked(tmp_path: Path) -> None:
    state = CandidateState.from_dict(_candidate())
    binary = tmp_path / "demo.bin"
    binary.write_bytes(b"\x7fELF")
    derivation = {
        "schema_version": 1,
        "status": "blocked",
        "blockers": ["no_structured_process_input_source"],
        "no_text_matching": True,
    }
    pack = build_evidence_pack_v3(state.to_dict(), entrypoint_derivation=derivation)

    with pytest.raises(ValueError, match="requires a derived supported entrypoint"):
        build_concolic_request(pack, binary_path=binary, input_model="function_harness", symbolic_bytes=32)


def test_concolic_prefers_derived_semantic_input_model_over_stale_reproducer_surface(tmp_path: Path) -> None:
    state = CandidateState.from_dict(_candidate())
    binary = tmp_path / "demo.bin"
    binary.write_bytes(b"\x7fELF")
    derivation = {
        "schema_version": 1,
        "status": "derived",
        "entry_function": "main",
        "entry_address": "0x1000",
        "input_model": "file",
        "process_input_supported": True,
        "call_path": ["main", "target"],
        "entry_surface": {"function": "main", "address": "0x1000", "kind": "program_entry"},
        "no_text_matching": True,
    }
    pack = build_evidence_pack_v3(state.to_dict(), entrypoint_derivation=derivation)
    pack["facts_available_to_llm"]["reproducer_hypothesis"]["input_surface"] = "argv"

    request = build_concolic_request(pack, binary_path=binary, symbolic_bytes=32)

    assert request.input_model == "file"


def test_semantic_function_harness_concolic_fails_validation_when_entrypoint_missing(tmp_path: Path) -> None:
    state = CandidateState.from_dict(_candidate())
    binary = tmp_path / "demo.bin"
    binary.write_bytes(b"\x7fELF")
    pack = build_evidence_pack_v3(state.to_dict())

    with pytest.raises(ValueError, match="requires a derived supported entrypoint"):
        build_concolic_request(pack, binary_path=binary, input_model="function_harness", symbolic_bytes=32)


def test_semantic_concolic_derives_structured_sink_target_from_export(tmp_path: Path) -> None:
    state = CandidateState.from_dict(_candidate()).with_updates(
        type_facts={
            "semantic_seed": {"seed_id": "seed-entry", "vulnerability_type": "command_injection"},
            "replay_hints": {
                "mode": "qemu_user",
                "input": {"stdin": "payload"},
                "expected_result": {"proof_oracle": {"kind": "command_effect"}},
            },
        }
    )
    binary = tmp_path / "demo.bin"
    binary.write_bytes(b"\x7fELF")
    pack = build_evidence_pack_v3(state.to_dict())
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", pcode_calls=[{"callee": "read", "address": "0x1004"}]),
            _record("target", "0x1200", "target.c"),
            _record("system", "0x1300", "system.c"),
        ],
        callgraph={"main": ["target"], "target": ["system"], "system": []},
    )

    request = build_concolic_request(pack, binary_path=binary, export_dir=export_dir, input_model="stdin", symbolic_bytes=32)

    assert request.target_address == "0x1300"
    assert request.sink_address == "0x1300"
    assert request.target_resolution["target_kind"] == "structured_sink_callee"
    assert request.target_resolution["entrypoint_derivation"]["entry_address"] == "0x1000"


def test_semantic_concolic_prefers_pcode_callsite_target(tmp_path: Path) -> None:
    state = CandidateState.from_dict(_candidate()).with_updates(
        type_facts={
            "semantic_seed": {"seed_id": "seed-entry", "vulnerability_type": "command_injection"},
            "replay_hints": {"mode": "qemu_user", "input": {"stdin": "payload"}},
        }
    )
    binary = tmp_path / "demo.bin"
    binary.write_bytes(b"\x7fELF")
    pack = build_evidence_pack_v3(state.to_dict())
    export_dir = _write_export(
        tmp_path,
        [
            _record("main", "0x1000", "main.c", pcode_calls=[{"callee": "read", "address": "0x1004"}]),
            _record("target", "0x1200", "target.c", pcode_calls=[{"callee": "system", "call_address": "0x1214"}]),
            _record("system", "0x1300", "system.c"),
        ],
        callgraph={"main": ["target"], "target": ["system"], "system": []},
    )

    request = build_concolic_request(pack, binary_path=binary, export_dir=export_dir, input_model="stdin", symbolic_bytes=32)

    assert request.target_address == "0x1214"
    assert request.target_resolution["target_kind"] == "exact_pcode_callsite"
    assert request.target_resolution["callee_address"] == "0x1300"
