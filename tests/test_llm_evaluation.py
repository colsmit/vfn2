import json
from pathlib import Path
from typing import Any, Mapping

from binary_agent.analysis.concolic import CONCOLIC_TOOL_NAME, ConcolicToolConfig
from binary_agent.analysis.llm_evaluation import (
    LLM_EVAL_LIFT_SUMMARY,
    build_lift_summary,
    extract_preconditions,
    run_offline_llm_evaluation,
    validate_hypothesis,
)
from binary_agent.replay.models import ReplayResult, ReplayStatus


def _pack(
    candidate_id: str = "demo_eval",
    *,
    vulnerability_type: str = "",
    function_name: str = "main",
    sink: str = "memcpy",
    address: str = "0x1000",
    operation_address: str = "0x1010",
    capacity_bytes: int = 16,
    write_size_bytes: int = 64,
    write_relation: str = "candidate",
    verdict: str = "candidate",
    line_text: str = "memcpy(local_20, input, len);",
) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "deterministic_candidate": {
            "candidate_id": candidate_id,
            "binary": "demo.bin",
            "vulnerability_type": vulnerability_type,
            "function_name": function_name,
            "address": address,
            "operation_address": operation_address,
            "kind": "call",
            "sink": sink,
            "target_buffer": "local_20",
            "destination_kind": "stack",
            "capacity_bytes": capacity_bytes,
            "write_size_bytes": write_size_bytes,
            "write_relation": write_relation,
            "verdict": verdict,
            "line_text": line_text,
        },
        "facts_available_to_llm": {
            "write_table": [{"operation_address": operation_address}],
            "reproducer_hypothesis": {"input_surface": "cgi_route", "allowed_stubs": [sink]},
            "pcode_slice": {"operation_address": operation_address},
            "allowed_stubs": [sink],
        },
        "proof_obligation": {
            "relation": write_relation,
            "evidence_refs": ["object:0", "write:0", "reachability:0"],
        },
    }


def _binary(tmp_path: Path) -> Path:
    binary = tmp_path / "demo.bin"
    binary.write_bytes(b"\x7fELF")
    return binary


def _write_pack_dir(tmp_path: Path, pack: Mapping[str, Any]) -> Path:
    evidence_dir = tmp_path / "packs"
    evidence_dir.mkdir()
    (evidence_dir / "pack.json").write_text(json.dumps(pack))
    (evidence_dir / "index.json").write_text(
        json.dumps({"evidence_packs": [{"candidate_id": pack["candidate_id"], "path": "pack.json"}]})
    )
    return evidence_dir


def _valid_replay_hypothesis(candidate_id: str = "demo_eval") -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "hypothesis_kind": "replay",
        "proposed_setup": {
            "routes": [{"method": "POST", "path": "/cgi-bin/upload"}],
            "env": {"REQUEST_METHOD": "POST", "FORM_payload": "A" * 64},
            "filesystem": [{"path": "/tmp/core.AAAA", "min_length": 4096}],
            "validation_command": "REQUEST_METHOD=POST FORM_payload=$(python -c 'print(\"A\"*64)') ./gs_web",
        },
        "proposed_inputs": {"body": "payload=" + ("A" * 64)},
        "expected_sink": {"function_name": "main", "sink": "memcpy", "operation_address": "0x1010"},
        "assumptions": ["CGI variables are passed through the web launcher."],
        "cost_metadata": {"model_calls": 1, "input_tokens": 200, "output_tokens": 80},
    }


def test_valid_replay_hypothesis_is_accepted_by_schema() -> None:
    artifact = validate_hypothesis(_pack(), _valid_replay_hypothesis())

    assert artifact.accepted
    assert artifact.hypothesis_kind == "replay"
    assert artifact.validator_result["details"]["replay_ready"] is True
    assert artifact.failure_reason == ""


def test_process_replay_hypothesis_requires_class_proof_oracle() -> None:
    pack = _pack(
        "cmd_eval",
        vulnerability_type="command_injection",
        function_name="handle_http",
        sink="system",
        operation_address="0x1210",
    )
    hypothesis = {
        "candidate_id": "cmd_eval",
        "hypothesis_kind": "replay",
        "proposed_setup": {"routes": [{"method": "GET", "path": "/diag"}]},
        "proposed_inputs": {"input_model": "http_daemon", "path": "/diag", "query": {"cmd": "id"}},
        "expected_sink": {"function_name": "handle_http", "sink": "system", "operation_address": "0x1210"},
        "assumptions": ["The /diag route reaches handle_http."],
    }

    missing = validate_hypothesis(pack, hypothesis)
    wrong = validate_hypothesis(
        pack,
        {
            **hypothesis,
            "expected_sink": {
                **hypothesis["expected_sink"],
                "proof_oracle": {"kind": "filesystem_read_escape"},
            },
        },
    )
    accepted = validate_hypothesis(
        pack,
        {
            **hypothesis,
            "expected_sink": {
                **hypothesis["expected_sink"],
                "proof_oracle": {"kind": "command_effect", "marker": "uid="},
            },
        },
    )

    assert not missing.accepted
    assert "missing_class_proof_oracle" in missing.failure_reason
    assert not wrong.accepted
    assert "proof_oracle_kind_mismatch" in wrong.failure_reason
    assert accepted.accepted
    assert accepted.validator_result["details"]["proof_oracle"]["kind"] == "command_effect"


def test_generalized_process_replay_surfaces_are_accepted() -> None:
    pack = _pack(
        "socket_eval",
        vulnerability_type="command_injection",
        function_name="handle_socket",
        sink="system",
        operation_address="0x2020",
    )
    artifact = validate_hypothesis(
        pack,
        {
            "candidate_id": "socket_eval",
            "hypothesis_kind": "replay",
            "proposed_setup": {
                "services": [{"protocol": "tcp", "host": "127.0.0.1", "port": "31337"}],
                "env": {"CONFIG_PATH": "/tmp/app.conf"},
                "filesystem": [{"path": "/tmp/app.conf", "content": "enabled=1\n"}],
                "config": {"mode": "diagnostic"},
            },
            "proposed_inputs": {
                "input_model": "socket_service",
                "payload": "RUN id\n",
                "config_path": "/tmp/app.conf",
            },
            "expected_sink": {
                "function_name": "handle_socket",
                "sink": "system",
                "operation_address": "0x2020",
                "proof_oracle": {"kind": "command_effect", "marker": "uid="},
            },
            "assumptions": ["The socket payload reaches the command sink."],
        },
    )

    preconditions = artifact.validator_result["details"]["preconditions"]
    assert artifact.accepted
    assert preconditions["services"][0]["port"] == "31337"
    assert preconditions["inputs"][0]["kind"] == "payload"
    assert preconditions["config"]["mode"] == "diagnostic"


def test_socket_service_replay_requires_concrete_input_not_only_endpoint() -> None:
    pack = _pack(
        "socket_eval",
        vulnerability_type="command_injection",
        function_name="handle_socket",
        sink="system",
        operation_address="0x2020",
    )
    artifact = validate_hypothesis(
        pack,
        {
            "candidate_id": "socket_eval",
            "hypothesis_kind": "replay",
            "proposed_setup": {"services": [{"protocol": "tcp", "host": "127.0.0.1", "port": "31337"}]},
            "proposed_inputs": {"input_model": "socket_service"},
            "expected_sink": {
                "function_name": "handle_socket",
                "sink": "system",
                "operation_address": "0x2020",
                "proof_oracle": {"kind": "command_effect", "marker": "uid="},
            },
            "assumptions": ["The socket service reaches the command sink."],
        },
    )

    assert not artifact.accepted
    assert "missing_concrete_replay_surface" in artifact.failure_reason


def test_malformed_or_overbroad_replay_hypothesis_is_rejected() -> None:
    artifact = validate_hypothesis(
        _pack(),
        {
            "candidate_id": "demo_eval",
            "hypothesis_kind": "replay",
            "proposed_setup": {"routes": ["*"], "env": {"*": "anything"}},
            "proposed_inputs": {"body": "payload"},
            "expected_sink": {"sink": "memcpy"},
            "assumptions": [],
        },
    )

    assert not artifact.accepted
    assert "overbroad_preconditions" in artifact.failure_reason


def test_route_env_filesystem_precondition_extraction() -> None:
    preconditions = extract_preconditions(
        {
            "routes": [{"method": "POST", "path": "/cgi-bin/config"}],
            "env": {"FORM_*": "form fields", "REQUEST_METHOD": "POST"},
            "filesystem": [{"directory": "/tmp", "pattern": "core.*"}],
            "config": {"nvram.web_enabled": "1"},
            "auth": {"session": "admin"},
        },
        {"argv": ["--factory", "web"]},
    )

    assert preconditions["routes"][0]["path"] == "/cgi-bin/config"
    assert preconditions["env"]["REQUEST_METHOD"] == "POST"
    assert preconditions["filesystem"][0]["pattern"] == "core.*"
    assert preconditions["config"]["nvram.web_enabled"] == "1"
    assert preconditions["auth"]["session"] == "admin"
    assert preconditions["inputs"][0]["kind"] == "argv"


def test_branch_guidance_json_converts_to_bounded_concolic_request(tmp_path: Path) -> None:
    pack = _pack(write_relation="proven_overflow", verdict="overflow")
    config = ConcolicToolConfig(binary_path=_binary(tmp_path), output_dir=tmp_path / "concolic")

    artifact = validate_hypothesis(
        pack,
        {
            "candidate_id": "demo_eval",
            "hypothesis_kind": "branch_guidance",
            "branch_guidance": {
                "target_address": "0x1010",
                "sink_address": "0x1010",
                "input_model": "stdin",
                "symbolic_bytes": 32,
                "constraints": ["byte[0] == 0x41"],
                "allowed_stubs": ["memcpy"],
                "seed_mutations": ["AAAA"],
            },
            "proposed_setup": {},
            "proposed_inputs": {"stdin": "AAAA"},
            "expected_sink": {"sink": "memcpy", "operation_address": "0x1010"},
            "assumptions": ["stdin reaches the harness entry."],
        },
        concolic_config=config,
    )

    assert artifact.accepted
    request = artifact.validator_result["details"]["concolic_request"]
    assert request["input_model"] == "stdin"
    assert request["symbolic_bytes"] == 32
    assert request["constraints"] == ["byte[0] == 0x41"]


def test_false_positive_triage_does_not_override_deterministic_proof() -> None:
    pack = _pack(write_relation="proven_overflow", verdict="overflow")

    artifact = validate_hypothesis(
        pack,
        {
            "candidate_id": "demo_eval",
            "hypothesis_kind": "triage",
            "triage": {
                "decision": "not_a_bug",
                "rationale": "The model thinks this is only a harness artifact.",
            },
            "proposed_setup": {},
            "proposed_inputs": {},
            "expected_sink": {"sink": "memcpy", "operation_address": "0x1010"},
            "assumptions": [],
        },
    )

    assert not artifact.accepted
    assert artifact.failure_reason == "deterministic_proof_overrides_llm_triage"
    assert artifact.validator_result["details"]["deterministic_override"] is True


def test_curated_triage_label_can_score_deterministic_false_positive_without_promoting() -> None:
    pack = _pack("bounded_gold", sink="snprintf", write_relation="proven_overflow", verdict="overflow")

    artifact = validate_hypothesis(
        pack,
        {
            "candidate_id": "bounded_gold",
            "hypothesis_kind": "triage",
            "triage": {
                "decision": "bounded_format",
                "rationale": "Manual review labels this snprintf format as bounded despite the size argument.",
            },
            "proposed_setup": {},
            "proposed_inputs": {},
            "expected_sink": {"sink": "snprintf", "operation_address": "0x1010"},
            "assumptions": [],
        },
        gold_labels={
            "bounded_gold": {
                "triage": {
                    "expected_false_positive": True,
                    "expected_decision": "bounded_format",
                }
            }
        },
    )

    assert artifact.accepted
    details = artifact.validator_result["details"]
    assert details["deterministic_override"] is True
    assert details["pipeline_override"] is False


def test_fixed_firmware_smoke_hypotheses_cover_expected_cases() -> None:
    cases = [
        (
            _pack("FUN_000155c4", function_name="FUN_000155c4", sink="strcpy"),
            {
                "candidate_id": "FUN_000155c4",
                "hypothesis_kind": "environment",
                "proposed_setup": {
                    "routes": [{"method": "POST", "path": "/cgi-bin/api"}],
                    "env": {"REQUEST_METHOD": "POST", "FORM_user": "A" * 128},
                },
                "proposed_inputs": {"form": {"user": "A" * 128}},
                "expected_sink": {"function_name": "FUN_000155c4", "sink": "strcpy", "operation_address": "0x1010"},
                "assumptions": ["CGI launcher exports FORM_* variables."],
            },
            {"FUN_000155c4": {"environment": {"routes": ["/cgi-bin/api"], "env": ["REQUEST_METHOD", "FORM_*"]}}},
        ),
        (
            _pack("FUN_0001329c", function_name="FUN_0001329c", sink="strcat"),
            {
                "candidate_id": "FUN_0001329c",
                "hypothesis_kind": "environment",
                "proposed_setup": {"filesystem": [{"directory": "/tmp", "pattern": "core.*", "min_length": 512}]},
                "proposed_inputs": {},
                "expected_sink": {"function_name": "FUN_0001329c", "sink": "strcat", "operation_address": "0x1010"},
                "assumptions": ["The crash scanner concatenates core.* filenames."],
            },
            {"FUN_0001329c": {"environment": {"filesystem": ["core.*"]}}},
        ),
        (
            _pack("FUN_00010af8", function_name="FUN_00010af8", sink="strcpy", write_relation="candidate"),
            {
                "candidate_id": "FUN_00010af8",
                "hypothesis_kind": "triage",
                "triage": {
                    "decision": "harness_only",
                    "rationale": "No recovered route, caller, callback, thread start, or exported entry reaches this sink.",
                },
                "proposed_setup": {},
                "proposed_inputs": {},
                "expected_sink": {"function_name": "FUN_00010af8", "sink": "strcpy", "operation_address": "0x1010"},
                "assumptions": ["Function-harness proof is not enough without firmware call context."],
            },
            {},
        ),
        (
            _pack(
                "FUN_0000e2fc",
                function_name="FUN_0000e2fc",
                sink="snprintf",
                capacity_bytes=32,
                write_size_bytes=20,
                write_relation="bounded_by_size",
                verdict="bounded",
                line_text='snprintf(local_20,0x20,"%lde%ld",a,b);',
            ),
            {
                "candidate_id": "FUN_0000e2fc",
                "hypothesis_kind": "triage",
                "triage": {
                    "decision": "bounded_format",
                    "rationale": "The %lde%ld output is bounded by snprintf size 0x20 and fits the 32-byte target.",
                },
                "proposed_setup": {},
                "proposed_inputs": {},
                "expected_sink": {"function_name": "FUN_0000e2fc", "sink": "snprintf", "operation_address": "0x1010"},
                "assumptions": ["No deterministic overflow proof exists for this bounded call."],
            },
            {},
        ),
    ]

    for pack, hypothesis, gold_labels in cases:
        artifact = validate_hypothesis(pack, hypothesis, gold_labels=gold_labels)
        assert artifact.accepted, artifact.to_dict()


def test_offline_evaluation_writes_summary_and_per_candidate_artifacts(tmp_path: Path) -> None:
    pack = _pack()
    evidence_dir = _write_pack_dir(tmp_path, pack)
    fixtures_dir = tmp_path / "fixtures"
    for system in ("L1", "L2", "L3"):
        (fixtures_dir / system).mkdir(parents=True)

    (fixtures_dir / "L1" / "demo_eval.json").write_text(
        json.dumps(
            {
                "candidate_id": "demo_eval",
                "hypothesis_kind": "branch_guidance",
                "branch_guidance": {
                    "tool": CONCOLIC_TOOL_NAME,
                    "target_address": "0x1010",
                    "sink_address": "0x1010",
                    "input_model": "stdin",
                    "symbolic_byte_budget": 32,
                    "allowed_stubs": ["memcpy"],
                },
                "proposed_setup": {},
                "proposed_inputs": {"stdin": "AAAA"},
                "expected_sink": {"sink": "memcpy", "operation_address": "0x1010"},
                "assumptions": [],
            }
        )
    )
    (fixtures_dir / "L2" / "demo_eval.json").write_text(json.dumps(_valid_replay_hypothesis()))
    (fixtures_dir / "L3" / "demo_eval.json").write_text(
        json.dumps(
            {
                "attempts": [
                    {
                        "candidate_id": "demo_eval",
                        "hypothesis_kind": "replay",
                        "proposed_setup": {"routes": ["*"]},
                        "proposed_inputs": {"body": "payload"},
                        "expected_sink": {"sink": "memcpy"},
                        "assumptions": [],
                    },
                    _valid_replay_hypothesis(),
                ]
            }
        )
    )

    result = run_offline_llm_evaluation(
        evidence_dir,
        tmp_path / "eval",
        fixtures_dir=fixtures_dir,
        systems=("D0", "L1", "L2", "L3"),
        concolic_config=ConcolicToolConfig(binary_path=_binary(tmp_path), output_dir=tmp_path / "concolic"),
    )

    assert result.summary_path.exists()
    assert result.lift_summary_path.exists()
    assert result.lift_summary_path.name == LLM_EVAL_LIFT_SUMMARY
    assert result.summary["systems"]["D0"]["accepted"] == 1
    assert result.summary["systems"]["L1"]["branch_guidance_valid"] == 1
    assert result.summary["systems"]["L2"]["replay_ready"] == 1
    assert result.summary["systems"]["L3"]["accepted"] == 1
    l3_artifact = json.loads((tmp_path / "eval" / "L3" / "demo_eval_replay.json").read_text())
    assert l3_artifact["validator_result"]["accepted_iteration"] == 2
    l2_lift = [
        record
        for record in result.lift_summary["records"]
        if record["system"] == "L2" and record["candidate_id"] == "demo_eval"
    ][0]
    assert l2_lift["lift"] == "schema_lift_only"

    stale = tmp_path / "eval" / "L3" / "stale.json"
    stale.write_text("{}")
    run_offline_llm_evaluation(
        evidence_dir,
        tmp_path / "eval",
        fixtures_dir=fixtures_dir,
        systems=("L3",),
        concolic_config=ConcolicToolConfig(binary_path=_binary(tmp_path), output_dir=tmp_path / "concolic"),
    )

    assert not stale.exists()


def test_lift_summary_distinguishes_schema_environment_replay_triage_and_proof_lift() -> None:
    baseline = {
        "candidate_id": "demo_eval",
        "hypothesis_kind": "triage",
        "validator_result": {
            "accepted": True,
            "system": "D0",
            "deterministic_summary": {"verdict": "candidate", "write_relation": "candidate"},
        },
    }
    replay_artifact = validate_hypothesis(_pack(), _valid_replay_hypothesis())
    env_artifact = validate_hypothesis(
        _pack("env_eval"),
        {
            "candidate_id": "env_eval",
            "hypothesis_kind": "environment",
            "proposed_setup": {"filesystem": [{"directory": "/tmp", "pattern": "core.*"}]},
            "proposed_inputs": {},
            "expected_sink": {"sink": "memcpy", "operation_address": "0x1010"},
            "assumptions": [],
        },
        gold_labels={"env_eval": {"environment": {"filesystem": ["core.*"]}}},
    )
    triage_artifact = validate_hypothesis(
        _pack("triage_eval", write_relation="proven_overflow", verdict="overflow"),
        {
            "candidate_id": "triage_eval",
            "hypothesis_kind": "triage",
            "triage": {"decision": "false_positive", "rationale": "Curated benchmark marks this as bounded."},
            "expected_sink": {"sink": "memcpy", "operation_address": "0x1010"},
        },
        gold_labels={"triage_eval": {"triage": {"expected_false_positive": True}}},
    )
    proof_artifact = validate_hypothesis(_pack("proof_eval"), _valid_replay_hypothesis("proof_eval"))
    branch_artifact = {
        "candidate_id": "branch_eval",
        "hypothesis_kind": "branch_guidance",
        "validator_result": {"accepted": True, "reason_codes": ["branch_guidance_bounded"]},
    }

    summary = build_lift_summary(
        {
            "D0": [baseline],
            "L2": [replay_artifact, env_artifact, triage_artifact, proof_artifact, branch_artifact],
        },
        replay_results=[
            ReplayResult(
                candidate_id="demo_eval",
                result=ReplayStatus.SINK_NOT_REACHED.value,
                mode="function_harness",
                sink_reached=False,
                bug_observed=False,
                crash_observed=False,
                control_result={},
                artifacts=["/tmp/demo/request.json"],
            ),
            ReplayResult(
                candidate_id="proof_eval",
                result=ReplayStatus.CONFIRMED.value,
                mode="function_harness",
                sink_reached=True,
                bug_observed=True,
                crash_observed=True,
                control_result={},
                artifacts=["/tmp/proof/result.json"],
            ),
            ReplayResult(
                candidate_id="branch_eval",
                result=ReplayStatus.SINK_REACHED_NO_BUG.value,
                mode="concolic_angr",
                sink_reached=True,
                bug_observed=False,
                crash_observed=False,
                control_result={},
                artifacts=["/tmp/branch/replay.json"],
            ),
        ],
    )

    by_candidate = {record["candidate_id"]: record["lift"] for record in summary["records"]}
    assert by_candidate["demo_eval"] == "replay_lift"
    assert by_candidate["env_eval"] == "environment_lift"
    assert by_candidate["triage_eval"] == "triage_lift"
    assert by_candidate["proof_eval"] == "proof_lift"
    assert by_candidate["branch_eval"] == "branch_lift"
    assert summary["counts"]["schema_lift_only"] == 0
