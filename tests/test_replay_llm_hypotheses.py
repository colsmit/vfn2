import json
from pathlib import Path
from typing import Any, Mapping

from binary_agent.analysis.llm_evaluation import validate_hypothesis
from binary_agent.replay import (
    ReplayPlan,
    ReplayPlanEntry,
    ReplayRequest,
    ReplayResult,
    ReplayStatus,
    repair_replay,
    replay_request_from_llm_artifact,
    run_replay_plan,
)


def _pack(candidate_id: str = "repair-cand") -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "deterministic_candidate": {
            "candidate_id": candidate_id,
            "binary": "demo.bin",
            "function_name": "vulnerable",
            "address": "0x1000",
            "operation_address": "0x1010",
            "sink": "strcpy",
            "capacity_bytes": 16,
            "write_size_bytes": 64,
            "write_relation": "candidate",
            "verdict": "candidate",
        },
        "facts_available_to_llm": {"write_table": [{"operation_address": "0x1010"}], "allowed_stubs": ["strcpy"]},
        "proof_obligation": {"relation": "candidate"},
    }


def _http_pack(candidate_id: str = "http-cand") -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "candidate": {
            "candidate_id": candidate_id,
            "vulnerability_type": "command_injection",
            "function_name": "handle_http",
            "address": "0x1200",
            "operation_address": "0x1210",
            "sink": "system",
        },
        "facts_available_to_llm": {
            "process_input": {"input_model": "http_daemon"},
            "source_to_sink_trace": {"input_model": "http_daemon"},
        },
    }


def _accepted_replay_hypothesis(candidate_id: str = "repair-cand") -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "hypothesis_kind": "replay",
        "proposed_setup": {
            "mode": "function_harness",
            "routes": [{"method": "POST", "path": "/cgi-bin/demo"}],
            "simulate_result": {
                "result": "confirmed",
                "sink_reached": True,
                "bug_observed": True,
                "crash_observed": True,
                "negative_control_passed": True,
            },
        },
        "proposed_inputs": {"body": "payload=" + ("A" * 64)},
        "expected_sink": {"function_name": "vulnerable", "sink": "strcpy", "operation_address": "0x1010"},
        "assumptions": ["The route reaches the function harness."],
    }


def test_llm_replay_hypothesis_can_supply_http_daemon_exercise_strategy() -> None:
    hypothesis = {
        "candidate_id": "http-cand",
        "hypothesis_kind": "replay",
        "proposed_setup": {"mode": "native", "routes": [{"method": "GET", "path": "/diag"}]},
        "proposed_inputs": {
            "input_model": "http_daemon",
            "method": "GET",
            "path": "/diag",
            "query": {"cmd": "echo HTTP_LLM_EFFECT"},
        },
        "expected_sink": {
            "function_name": "handle_http",
            "sink": "system",
            "operation_address": "0x1210",
            "proof_oracle": {"kind": "command_effect", "marker": "HTTP_LLM_EFFECT"},
        },
        "assumptions": ["Route and query parameter are inferred from decompile evidence."],
    }

    artifact = validate_hypothesis(_http_pack(), hypothesis)
    request = replay_request_from_llm_artifact(artifact, binary_path="/tmp/httpd")

    assert artifact.accepted is True
    assert request.setup["llm_derived_setup"] is True
    assert request.input["input_model"] == "http_daemon"
    assert request.input["query"]["cmd"] == "echo HTTP_LLM_EFFECT"
    assert request.expected_result["proof_oracle"]["kind"] == "command_effect"


def test_accepted_llm_replay_artifact_converts_to_replay_request() -> None:
    artifact = validate_hypothesis(_pack(), _accepted_replay_hypothesis())

    request = replay_request_from_llm_artifact(artifact, binary_path="/tmp/demo")

    assert request.candidate_id == "repair-cand"
    assert request.mode == "function_harness"
    assert request.setup["binary_path"] == "/tmp/demo"
    assert request.setup["llm_derived_setup"] is True
    assert request.expected_result["llm_derived_setup"] is True
    assert request.expected_result["sink"] == "strcpy"


def test_llm_replay_conversion_preserves_dynamic_proof_oracle() -> None:
    hypothesis = _accepted_replay_hypothesis()
    hypothesis["expected_sink"]["proof_oracle"] = {
        "kind": "bounded_write_overflow",
        "allocation_call_address": "0x155e0",
        "allocation_return_address": "0x155e4",
        "sink_call_address": "0x1566c",
    }
    artifact = validate_hypothesis(_pack(), hypothesis)

    request = replay_request_from_llm_artifact(artifact, binary_path="/tmp/demo")

    assert request.expected_result["proof_oracle"]["kind"] == "bounded_write_overflow"
    assert request.expected_result["proof_oracle"]["sink_call_address"] == "0x1566c"


def test_replay_repair_loop_validates_hypothesis_and_records_attempts(tmp_path: Path) -> None:
    class FakeRepairProvider:
        def propose_repair(self, failure_summary: Mapping[str, Any]) -> Mapping[str, Any]:
            assert failure_summary["failure"]["status"] == "sink_not_reached"
            return _accepted_replay_hypothesis()

    initial_request = ReplayRequest(
        candidate_id="repair-cand",
        mode="function_harness",
        setup={"simulate_result": {"result": "sink_not_reached"}},
        input={},
        expected_result={"candidate_id": "repair-cand"},
    )
    initial_result = ReplayResult(
        candidate_id="repair-cand",
        result=ReplayStatus.SINK_NOT_REACHED.value,
        mode="function_harness",
        sink_reached=False,
        bug_observed=False,
        crash_observed=False,
        control_result={"reason": "missing route"},
        artifacts=["/tmp/initial/result.json"],
    )

    result = repair_replay(_pack(), initial_request, initial_result, FakeRepairProvider(), tmp_path)

    assert result.final_result["result"] == "confirmed"
    assert result.final_result["negative_control_passed"] is True
    assert len(result.attempts) == 1
    attempts_path = Path(result.attempts_path)
    assert attempts_path.exists()
    payload = json.loads(attempts_path.read_text())
    assert payload["attempts"][0]["accepted"] is True
    assert payload["attempts"][0]["replay_result"]["result"] == "confirmed"


def test_replay_plan_records_repair_provider_errors_without_failing(tmp_path: Path) -> None:
    class FailingRepairProvider:
        def propose_repair(self, failure_summary: Mapping[str, Any]) -> Mapping[str, Any]:
            raise RuntimeError("provider returned malformed JSON")

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "pack.json").write_text(json.dumps(_pack()))
    (evidence_dir / "index.json").write_text(
        json.dumps({"evidence_packs": [{"candidate_id": "repair-cand", "path": "pack.json"}]})
    )
    request = ReplayRequest(
        candidate_id="repair-cand",
        mode="function_harness",
        setup={"simulate_result": {"result": "sink_not_reached"}},
        input={},
        expected_result={"candidate_id": "repair-cand"},
    )
    plan = ReplayPlan(
        (
            ReplayPlanEntry(
                candidate_id="repair-cand",
                request=request,
                provenance="deterministic",
                selected=True,
                reason="test",
            ),
        )
    )

    results = run_replay_plan(
        plan,
        tmp_path / "replay",
        evidence_dir=evidence_dir,
        repair_provider=FailingRepairProvider(),
    )

    assert results[0].result == ReplayStatus.SINK_NOT_REACHED.value
    repair_error = tmp_path / "replay" / "repair-cand" / "repair" / "repair_error.json"
    assert repair_error.exists()
    payload = json.loads(repair_error.read_text())
    assert payload["error_type"] == "RuntimeError"
    assert "malformed JSON" in payload["error"]


def test_replay_plan_skips_repair_for_pre_target_crashes(tmp_path: Path) -> None:
    class FailingRepairProvider:
        calls = 0

        def propose_repair(self, failure_summary: Mapping[str, Any]) -> Mapping[str, Any]:
            self.calls += 1
            raise RuntimeError("repair should not be called")

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "pack.json").write_text(json.dumps(_pack()))
    (evidence_dir / "index.json").write_text(
        json.dumps({"evidence_packs": [{"candidate_id": "repair-cand", "path": "pack.json"}]})
    )
    request = ReplayRequest(
        candidate_id="repair-cand",
        mode="function_harness",
        setup={"simulate_result": {"result": "crash_unclassified", "sink_reached": False, "crash_observed": True}},
        input={},
        expected_result={"candidate_id": "repair-cand"},
    )
    plan = ReplayPlan(
        (
            ReplayPlanEntry(
                candidate_id="repair-cand",
                request=request,
                provenance="deterministic",
                selected=True,
                reason="test",
            ),
        )
    )
    provider = FailingRepairProvider()

    results = run_replay_plan(plan, tmp_path / "replay", evidence_dir=evidence_dir, repair_provider=provider)

    assert results[0].result == ReplayStatus.CRASH_UNCLASSIFIED.value
    assert provider.calls == 0
    assert not (tmp_path / "replay" / "repair-cand" / "repair" / "repair_error.json").exists()
