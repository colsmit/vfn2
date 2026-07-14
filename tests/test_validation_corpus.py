import json
from pathlib import Path

from binary_agent.pipeline import CandidateState, build_source_to_sink_trace, has_reportable_source_to_sink, write_candidate_states
from binary_agent.reporting import build_lean_reports, write_lean_reports
from binary_agent.validation import summarize_validation_corpus, write_validation_summary


def _state(
    candidate_id: str,
    *,
    vulnerability_type: str = "stack_overflow",
    status: str = "replay_confirmed",
    input_model: str = "argv",
    role: str = "write_source",
    blockers: list[str] | None = None,
) -> CandidateState:
    return CandidateState(
        candidate_id=candidate_id,
        vulnerability_type=vulnerability_type,
        status=status,
        target={"binary": "demo.bin"},
        location={"function_name": "handler", "relative_path": "demo.c", "line_number": 7, "address": "0x1200"},
        source={"kind": "attacker_input", "expression": input_model},
        sink={"name": "system" if vulnerability_type == "command_injection" else "strcpy", "target_buffer": "buf", "operation_address": "0x1200"},
        type_facts={
            "capacity_bytes": 16,
            "destination_kind": "stack",
            "write_relation": "unbounded",
            "verdict": "unbounded",
            "overflow_condition": "attacker input reaches sink",
            "source_to_sink_trace": {
                "schema_version": 2,
                "status": "complete",
                "attacker_control_reaches_sink_role": True,
                "entry_function": "main",
                "entry_surface_kind": "program_entry",
                "target_function": "handler",
                "target_address": "0x1200",
                "sink_name": "system" if vulnerability_type == "command_injection" else "strcpy",
                "call_path": ["main", "handler"],
                "input_model": input_model,
                "argument_roles": [
                    {
                        "role": role,
                        "expr": "payload",
                        "classification": "source_controlled",
                        "controlled": True,
                        "complete": True,
                    }
                ],
                "blockers": blockers or [],
            },
        },
        proof_obligations=[
            {
                "obligation_id": f"{candidate_id}:proof",
                "description": "source reaches sink",
                "condition": "attacker-controlled input reaches exact sink",
                "status": "satisfied",
            }
        ],
        blockers=[],
    )


def _write_ghidra_process_proof(
    path: Path,
    candidate_id: str,
    *,
    input_model: str = "argv",
    sink_address: str = "0x1200",
    status: str = "overflow_proven",
) -> Path:
    memory_fields = (
        {
            "capacity_bytes": 16,
            "oob_bytes": 4,
            "read_size_bytes": 4,
            "read_range": {"start_offset": 20, "end_offset_exclusive": 24},
        }
        if status == "oob_read_proven"
        else {
            "capacity_bytes": 16,
            "overflow_bytes": 32,
        }
    )
    path.parent.mkdir(parents=True, exist_ok=True)
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
                "sink_address": sink_address,
                "process_input_setup": {"status": "configured", "input_model": input_model},
                "process_replay": {"status": "reached", "reached_target": True},
                **memory_fields,
            }
        )
    )
    return path


def _write_ghidra_function_harness_proof(
    path: Path,
    candidate_id: str,
    *,
    status: str = "overflow_proven",
) -> Path:
    memory_fields = (
        {
            "capacity_bytes": 16,
            "oob_bytes": 4,
            "read_size_bytes": 4,
            "read_range": {"start_offset": 20, "end_offset_exclusive": 24},
        }
        if status == "oob_read_proven"
        else {
            "capacity_bytes": 16,
            "write_size_bytes": 40,
            "overflow_bytes": 24,
        }
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "proof_kind": "ghidra_dynamic_overflow",
                "candidate_id": candidate_id,
                "status": status,
                "proof_scope": "function_harness",
                "sink_reached": True,
                "exact_sink_reached": True,
                "sink_address": "0x1200",
                "process_input_setup": {"status": "configured", "input_model": "function_harness"},
                **memory_fields,
            }
        )
    )
    return path


def _write_replay_result(
    path: Path,
    candidate_id: str,
    *,
    result: str = "confirmed",
    mode: str = "qemu_user",
    sink_reached: bool = True,
    bug_observed: bool = True,
    proof_observation: dict | None = None,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    request_path = path.parent / "request.json"
    input_model = "http_cgi" if mode == "qemu_user" else "argv"
    request_path.write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "mode": mode,
                "setup": {"binary_path": "/tmp/demo.bin"},
                "input": {
                    "input_model": input_model,
                    "argv": ["BINARY_AGENT_POC"],
                    "body": "cmd=BINARY_AGENT_POC" if input_model == "http_cgi" else "",
                },
                "expected_result": {"candidate_id": candidate_id},
            }
        )
    )
    payload = {
        "candidate_id": candidate_id,
        "result": result,
        "mode": mode,
        "sink_reached": sink_reached,
        "bug_observed": bug_observed,
        "crash_observed": False,
        "control_result": {},
        "artifacts": [str(request_path), str(path)],
    }
    if proof_observation:
        payload["control_result"] = {"proof_observation": proof_observation}
    path.write_text(json.dumps(payload))
    return path


def _write_concolic_verdict(
    path: Path,
    candidate_id: str,
    *,
    verdict: str = "overflow_witness",
    replay_status: str = "replayed",
    input_model: str = "argv",
    sink_address: str = "0x1200",
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "concolic_verdict": verdict,
                "backend": "angr",
                "sink_reached": True,
                "request": {
                    "target_address": sink_address,
                    "sink_address": sink_address,
                    "input_model": input_model,
                },
                "witness": {"input_model": input_model, "argv_hex": ["41414141"]},
                "replay_result": {
                    "concrete_angr_replay": {"status": replay_status, "target_loader_address": sink_address}
                },
                "angr_trace": {"status": "target_reached"},
            }
        )
    )
    return path


def test_validation_corpus_summarizes_process_proofs_and_blockers(tmp_path: Path) -> None:
    states: list[CandidateState] = []
    for input_model in ("argv", "stdin", "file", "env"):
        state = _state(f"memory-{input_model}", input_model=input_model)
        proof = _write_ghidra_process_proof(
            tmp_path / "replay" / state.candidate_id / "ghidra_dynamic_proof.json",
            state.candidate_id,
            input_model=input_model,
        )
        states.append(state.with_updates(replay_artifacts=[str(proof)]))

    native_only = _state("native-only")
    native_result = _write_replay_result(
        tmp_path / "replay" / "native-only" / "result.json",
        "native-only",
        mode="native",
    )
    states.append(native_only.with_updates(replay_artifacts=[str(native_result)]))

    rejected = _state("reachable-safe", status="rejected")
    safe_result = _write_replay_result(
        tmp_path / "replay" / "reachable-safe" / "result.json",
        "reachable-safe",
        result="sink_reached_no_bug",
        bug_observed=False,
    )
    states.append(rejected.with_updates(replay_artifacts=[str(safe_result)]))

    command = _state("command-positive", vulnerability_type="command_injection", input_model="http_cgi", role="command_argument")
    command_result = _write_replay_result(
        tmp_path / "replay" / "command-positive" / "result.json",
        "command-positive",
        proof_observation={"kind": "command_effect", "status": "command_effect_observed", "bug_observed": True},
    )
    states.append(command.with_updates(replay_artifacts=[str(command_result)]))

    for model in ("network", "http", "ipc", "device", "protocol"):
        states.append(_state(f"unsupported-{model}", input_model=model, blockers=[f"unsupported_process_input_model:{model}"]))

    summary = summarize_validation_corpus(states)

    assert summary["candidate_count"] == 12
    assert summary["totals"]["ghidra_process_overflow_proven"] == 4
    assert summary["totals"]["semantic_process_proven"] == 1
    assert summary["totals"]["reportable_source_to_sink"] == 5
    assert summary["totals"]["rejected_negatives"] == 1
    assert summary["totals"]["unsupported_blockers"] >= 5
    assert summary["by_vulnerability_type"]["command_injection"]["reportable_source_to_sink"] == 1
    assert summary["unsupported_reason_dashboard"]["total"] >= 10
    assert summary["unsupported_reason_dashboard"]["by_category"]["process_input_model"] >= 10
    assert summary["unsupported_reason_dashboard"]["top_reasons"][0] == {
        "reason": "unsupported_or_missing_process_input_model",
        "count": 5,
    }
    assert summary["blocker_stage_dashboard"]["by_stage"]["process_input"] >= 10
    assert {
        "stage": "process_input",
        "reason": "unsupported_or_missing_process_input_model",
        "count": 5,
    } in summary["blocker_stage_dashboard"]["top_reasons"]
    assert "http_cgi" in summary["supported_process_input_models"]
    assert "http_daemon" in summary["supported_process_input_models"]
    assert "socket_service" in summary["supported_process_input_models"]

    output = write_validation_summary(states, tmp_path / "validation_summary.json")
    assert json.loads(output.read_text())["totals"]["reportable_source_to_sink"] == 5

    candidate_path = write_candidate_states(states, tmp_path / "candidate_states.json")
    assert json.loads(candidate_path.read_text())["candidate_states"][0]["candidate_id"] == "memory-argv"


def test_validation_corpus_promotes_replay_blocker_reasons(tmp_path: Path) -> None:
    state = _state("socket-blocked", vulnerability_type="command_injection", input_model="socket_service", role="command_argument")
    result = _write_replay_result(
        tmp_path / "replay" / "socket-blocked" / "result.json",
        "socket-blocked",
        result="blocked",
        sink_reached=False,
        bug_observed=False,
    )
    payload = json.loads(result.read_text())
    payload["control_result"] = {
        "reason": "socket_service replay requires a concrete TCP port or deterministic port materialization"
    }
    result.write_text(json.dumps(payload))
    summary = summarize_validation_corpus([state.with_updates(replay_artifacts=[str(result)])])

    assert summary["replay_blocker_dashboard"]["total"] == 1
    assert summary["replay_blocker_dashboard"]["top_reasons"][0]["reason"].startswith("socket_service replay requires")
    assert summary["blocker_stage_dashboard"]["by_stage"]["replay"] >= 1


def test_validation_corpus_counts_oob_read_process_proofs(tmp_path: Path) -> None:
    state = _state("oob-read", vulnerability_type="out_of_bounds_read", input_model="argv", role="write_offset")
    proof = _write_ghidra_process_proof(
        tmp_path / "replay" / "oob-read" / "ghidra_dynamic_proof.json",
        "oob-read",
        status="oob_read_proven",
    )
    state = state.with_updates(replay_artifacts=[str(proof)])

    summary = summarize_validation_corpus([state])

    assert summary["totals"]["ghidra_process_oob_read_proven"] == 1
    assert summary["totals"]["ghidra_process_memory_safety_proven"] == 1
    assert "ghidra_process_overflow_proven" not in summary["totals"]
    assert summary["by_vulnerability_type"]["out_of_bounds_read"]["ghidra_process_oob_read_proven"] == 1


def test_validation_corpus_counts_function_harness_memory_proofs(tmp_path: Path) -> None:
    state = _state("heap-function-harness", vulnerability_type="heap_overflow", input_model="argv")
    proof = _write_ghidra_function_harness_proof(
        tmp_path / "replay" / "heap-function-harness" / "ghidra_dynamic_proof.json",
        "heap-function-harness",
    )
    result = _write_replay_result(
        tmp_path / "replay" / "heap-function-harness" / "result.json",
        "heap-function-harness",
        mode="ghidra_function_harness",
    )
    state = state.with_updates(replay_artifacts=[str(proof), str(result)])

    summary = summarize_validation_corpus([state])

    assert summary["totals"]["ghidra_function_harness_overflow_proven"] == 1
    assert summary["totals"]["ghidra_function_harness_memory_safety_proven"] == 1
    assert summary["totals"]["process_replay_confirmed"] == 1
    assert summary["by_vulnerability_type"]["heap_overflow"]["ghidra_function_harness_overflow_proven"] == 1


def test_command_injection_process_replay_is_reportable_without_memory_proof(tmp_path: Path) -> None:
    state = _state("command-positive", vulnerability_type="command_injection", input_model="http_cgi", role="command_argument")
    observed = tmp_path / "replay" / "command-positive" / "dynamic_command_effect_observation.json"
    observed.parent.mkdir(parents=True)
    observed.write_text(
        json.dumps({"kind": "command_effect", "status": "command_effect_observed", "bug_observed": True})
    )
    not_observed = tmp_path / "replay" / "command-positive" / "dynamic_command_effect_safe_observation.json"
    not_observed.write_text(
        json.dumps({"kind": "command_effect", "status": "command_effect_not_observed", "bug_observed": False})
    )
    result = _write_replay_result(
        tmp_path / "replay" / "command-positive" / "result.json",
        "command-positive",
        proof_observation={"kind": "command_effect", "status": "command_effect_observed", "bug_observed": True},
    )
    payload = json.loads(result.read_text())
    payload["artifacts"] = [str(result), str(observed), str(not_observed)]
    result.write_text(json.dumps(payload))
    state = state.with_updates(replay_artifacts=[str(result)])

    trace = build_source_to_sink_trace(state)
    reports = build_lean_reports([state])
    written = write_lean_reports(reports, tmp_path / "report")
    payload = json.loads(written["json"].read_text())

    assert trace.status == "proven"
    assert str(observed) in trace.dynamic_artifacts
    assert str(not_observed) not in trace.dynamic_artifacts
    assert has_reportable_source_to_sink(state) is True
    assert len(reports) == 1
    assert reports[0].vulnerability == "command_injection"
    assert reports[0].proof_details["dynamic_observation_kind"] == "command_effect"
    assert reports[0].proof_details["dynamic_observation_status"] == "command_effect_observed"
    assert reports[0].confidence_level == "real_binary_replay_confirmed"
    assert "http_cgi" in reports[0].attacker_controlled_input
    assert payload["vulnerabilities"][0]["proof_details"]["replay_mode"] == "qemu_user"
    assert payload["vulnerabilities"][0]["confidence_level"] == "real_binary_replay_confirmed"


def test_qemu_system_semantic_replay_is_not_report_ready_without_process_replay(tmp_path: Path) -> None:
    state = _state("qemu-system-command", vulnerability_type="command_injection", input_model="http_cgi", role="command_argument")
    result = _write_replay_result(
        tmp_path / "replay" / "qemu-system-command" / "result.json",
        "qemu-system-command",
        mode="qemu_system",
        proof_observation={"kind": "command_effect", "status": "command_effect_observed", "bug_observed": True},
    )
    state = state.with_updates(replay_artifacts=[str(result)])

    trace = build_source_to_sink_trace(state)
    summary = summarize_validation_corpus([state])
    reports = build_lean_reports([state])

    assert trace.status == "blocked"
    assert trace.blockers == ["boundary_replay_missing"]
    assert has_reportable_source_to_sink(state) is False
    assert "semantic_process_proven" not in summary["totals"]
    assert reports == []


def test_format_string_process_replay_is_reportable_without_memory_proof(tmp_path: Path) -> None:
    state = _state("format-positive", vulnerability_type="format_string", input_model="argv", role="format_argument")
    state = state.with_updates(
        sink={"name": "printf", "target_buffer": "format", "operation_address": "0x1200"},
        type_facts={
            **dict(state.type_facts),
            "overflow_condition": "attacker input reaches printf format argument",
        },
    )
    result = _write_replay_result(
        tmp_path / "replay" / "format-positive" / "result.json",
        "format-positive",
        mode="native",
        proof_observation={
            "kind": "format_string_effect",
            "status": "format_string_effect_observed",
            "bug_observed": True,
            "marker": "FORMAT_PROBE_%x_END",
            "format_string_observation": {
                "literal_marker_observed": False,
                "expanded_marker_observed": True,
            },
        },
    )
    state = state.with_updates(replay_artifacts=[str(result)])

    trace = build_source_to_sink_trace(state)
    summary = summarize_validation_corpus([state])
    reports = build_lean_reports([state])

    assert trace.status == "proven"
    assert has_reportable_source_to_sink(state) is True
    assert summary["totals"]["semantic_process_proven"] == 1
    assert summary["by_vulnerability_type"]["format_string"]["semantic_process_proven"] == 1
    assert len(reports) == 1
    assert reports[0].vulnerability == "format_string"
    assert reports[0].proof_details["dynamic_observation_kind"] == "format_string_effect"
    assert reports[0].proof_details["dynamic_observation_status"] == "format_string_effect_observed"
    assert reports[0].proof_details["sink_role"] == "format_argument"


def test_socket_service_process_replay_is_reportable_supported_input(tmp_path: Path) -> None:
    state = _state("socket-command", vulnerability_type="command_injection", input_model="socket_service", role="command_argument")
    result = _write_replay_result(
        tmp_path / "replay" / "socket-command" / "result.json",
        "socket-command",
        mode="native",
        proof_observation={"kind": "command_effect", "status": "command_effect_observed", "bug_observed": True},
    )
    state = state.with_updates(replay_artifacts=[str(result)])

    trace = build_source_to_sink_trace(state)
    summary = summarize_validation_corpus([state])
    reports = build_lean_reports([state])

    assert trace.status == "proven"
    assert trace.input_model == "socket_service"
    assert has_reportable_source_to_sink(state) is True
    assert summary["totals"]["semantic_process_proven"] == 1
    assert reports[0].proof_details["input_model"] == "socket_service"


def test_http_daemon_process_replay_is_reportable_with_effect_channel(tmp_path: Path) -> None:
    state = _state("http-command", vulnerability_type="command_injection", input_model="http_daemon", role="command_argument")
    result = _write_replay_result(
        tmp_path / "replay" / "http-command" / "result.json",
        "http-command",
        mode="native",
        proof_observation={"kind": "command_effect", "status": "command_effect_observed", "bug_observed": True},
    )
    payload = json.loads(result.read_text())
    payload["control_result"]["http_response"] = "HTTP/1.0 200 OK\r\n\r\nHTTP_DAEMON_EFFECT\n"
    result.write_text(json.dumps(payload))
    state = state.with_updates(replay_artifacts=[str(result)])

    reports = build_lean_reports([state])
    summary = summarize_validation_corpus([state])

    assert summary["totals"]["semantic_process_proven"] == 1
    assert reports[0].proof_details["input_model"] == "http_daemon"
    assert "http_response" in reports[0].proof_details["effect_channels_observed"]


def test_memory_report_proof_details_use_dynamic_exact_sink_address(tmp_path: Path) -> None:
    state = _state("memory-exact-sink", input_model="argv")
    proof = _write_ghidra_process_proof(
        tmp_path / "replay" / "memory-exact-sink" / "ghidra_dynamic_proof.json",
        "memory-exact-sink",
        sink_address="0x1210",
    )
    state = state.with_updates(replay_artifacts=[str(proof)])

    reports = build_lean_reports([state])

    assert reports[0].proof_details["sink_address"] == "0x1210"


def test_concolic_overflow_witness_without_process_ghidra_proof_is_not_reportable(tmp_path: Path) -> None:
    state = _state("concolic-memory", input_model="argv")
    verdict = _write_concolic_verdict(
        tmp_path / "proof" / "concolic-memory" / "verdict.json",
        "concolic-memory",
        sink_address="0x1210",
    )
    state = state.with_updates(replay_artifacts=[str(verdict)])

    trace = build_source_to_sink_trace(state)
    reports = build_lean_reports([state])

    assert trace.status == "blocked"
    assert trace.blockers == ["boundary_replay_missing"]
    assert has_reportable_source_to_sink(state) is False
    assert reports == []


def test_concolic_crash_and_unmodeled_optarg_do_not_report(tmp_path: Path) -> None:
    crash = _state("concolic-crash", input_model="argv").with_updates(
        replay_artifacts=[
            str(
                _write_concolic_verdict(
                    tmp_path / "proof" / "concolic-crash" / "verdict.json",
                    "concolic-crash",
                    verdict="crash_reproduced",
                )
            )
        ]
    )
    optarg = _state("concolic-optarg", input_model="argv").with_updates(
        replay_artifacts=[
            str(
                _write_concolic_verdict(
                    tmp_path / "proof" / "concolic-optarg" / "verdict.json",
                    "concolic-optarg",
                )
            )
        ],
        type_facts={
            **dict(_state("concolic-optarg", input_model="argv").type_facts),
            "source_to_sink_trace": {
                **dict(_state("concolic-optarg", input_model="argv").type_facts["source_to_sink_trace"]),
                "argument_roles": [
                    {
                        "role": "write_source",
                        "expr": "optarg",
                        "classification": "source_controlled",
                        "controlled": True,
                        "complete": True,
                    }
                ],
            },
        },
    )

    assert build_source_to_sink_trace(crash).blockers == ["boundary_replay_missing"]
    assert has_reportable_source_to_sink(crash) is False
    assert build_source_to_sink_trace(optarg).blockers == ["boundary_replay_missing"]
    assert has_reportable_source_to_sink(optarg) is False


def test_report_confidence_levels_are_explicit_and_derived(tmp_path: Path) -> None:
    reviewed_result = _write_ghidra_process_proof(
        tmp_path / "source-reviewed" / "ghidra_dynamic_proof.json",
        "source-reviewed",
    )
    reviewed = _state("source-reviewed").with_updates(
        target={"binary": "source-reviewed.bin"},
        replay_artifacts=[str(reviewed_result)],
        metadata={
            "report_confidence_level": "source_reviewed",
            "report_confidence_evidence": ["reviewed upstream source around sink"],
        }
    )
    native_proof = _write_ghidra_process_proof(
        tmp_path / "native-crash" / "ghidra_dynamic_proof.json",
        "native-crash",
    )
    native = _state("native-crash").with_updates(
        target={"binary": "native-crash.bin"},
        replay_artifacts=[str(native_proof)],
    )
    native_result = _write_replay_result(
        tmp_path / "native-crash" / "result.json",
        "native-crash",
        mode="native",
    )
    native_payload = json.loads(native_result.read_text())
    native_payload["crash_observed"] = True
    native_result.write_text(json.dumps(native_payload))
    native = native.with_updates(replay_artifacts=[str(native_proof), str(native_result)])
    known_result = _write_ghidra_process_proof(
        tmp_path / "known_overflow_corpus" / "case" / "ghidra_dynamic_proof.json",
        "known-corpus",
    )
    known = _state("known-corpus").with_updates(
        target={"binary": "known-corpus.bin"},
        replay_artifacts=[str(known_result)]
    )

    reports = {report.candidate_id: report for report in build_lean_reports([reviewed, native, known])}

    assert reports["source-reviewed"].confidence_level == "source_reviewed"
    assert reports["source-reviewed"].confidence_evidence == ["reviewed upstream source around sink"]
    assert reports["native-crash"].confidence_level == "native_reproducer_confirmed"
    assert reports["known-corpus"].confidence_level == "known_corpus_confirmed"


def test_http_cgi_path_and_file_semantic_replays_are_reportable(tmp_path: Path) -> None:
    path_state = _state(
        "path-positive",
        vulnerability_type="path_traversal",
        input_model="http_cgi",
        role="path_argument",
    )
    path_result = _write_replay_result(
        tmp_path / "replay" / "path-positive" / "result.json",
        "path-positive",
        proof_observation={
            "kind": "filesystem_read_escape",
            "status": "filesystem_read_escape_observed",
            "bug_observed": True,
        },
    )
    write_state = _state(
        "write-positive",
        vulnerability_type="unsafe_file_write",
        input_model="http_cgi",
        role="file_path",
    )
    write_result = _write_replay_result(
        tmp_path / "replay" / "write-positive" / "result.json",
        "write-positive",
        proof_observation={
            "kind": "filesystem_write_escape",
            "status": "filesystem_write_escape_observed",
            "bug_observed": True,
        },
    )
    states = [
        path_state.with_updates(replay_artifacts=[str(path_result)]),
        write_state.with_updates(replay_artifacts=[str(write_result)]),
    ]

    reports = build_lean_reports(states)

    assert [report.vulnerability for report in reports] == ["path_traversal", "unsafe_file_write"]
    assert all(report.proof_details["input_model"] == "http_cgi" for report in reports)
    assert [report.proof_details["dynamic_observation_kind"] for report in reports] == [
        "filesystem_read_escape",
        "filesystem_write_escape",
    ]


def test_written_source_to_sink_trace_requires_live_dynamic_artifact(tmp_path: Path) -> None:
    state = _state("stale-trace")
    stale_trace = tmp_path / "source_to_sink_trace.json"
    stale_trace.write_text(
        json.dumps(
            {
                "artifact_kind": "source_to_sink_trace",
                "status": "proven",
                "input_model": "argv",
                "argument_roles": [{"role": "write_source", "classification": "source_controlled", "controlled": True}],
                "propagation_path": [{"kind": "function", "function": "main"}, {"kind": "function", "function": "handler"}],
                "dynamic_artifacts": ["missing_ghidra_dynamic_proof.json"],
            }
        )
    )
    stale_state = state.with_updates(validation_artifacts=[str(stale_trace)])

    proof = _write_ghidra_process_proof(tmp_path / "replay" / "stale-trace" / "ghidra_dynamic_proof.json", "stale-trace")
    live_trace = tmp_path / "source_to_sink_trace_live.json"
    live_trace.write_text(
        json.dumps(
            {
                "artifact_kind": "source_to_sink_trace",
                "status": "proven",
                "input_model": "argv",
                "argument_roles": [{"role": "write_source", "classification": "source_controlled", "controlled": True}],
                "propagation_path": [{"kind": "function", "function": "main"}, {"kind": "function", "function": "handler"}],
                "dynamic_artifacts": [str(proof)],
            }
        )
    )
    live_state = state.with_updates(validation_artifacts=[str(live_trace)], replay_artifacts=[str(proof)])

    assert has_reportable_source_to_sink(stale_state) is False
    assert has_reportable_source_to_sink(live_state) is True
