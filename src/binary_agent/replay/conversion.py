"""Adapters from validated LLM hypothesis artifacts to replay requests."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.replay.models import ReplayRequest


SUPPORTED_LLM_REPLAY_KINDS = {"replay", "environment"}


def replay_request_from_llm_artifact(
    artifact: Mapping[str, Any] | Any,
    *,
    binary_path: Path | str | None = None,
    default_mode: str = "native",
) -> ReplayRequest:
    """Convert an accepted replay/environment hypothesis artifact into a request.

    The converter is intentionally mechanical: it preserves concrete setup and
    input proposed by the model, records that the setup was LLM-derived, and
    leaves proof to the replay runner and promotion gates.
    """

    payload = _artifact_mapping(artifact)
    validator = payload.get("validator_result") if isinstance(payload.get("validator_result"), Mapping) else {}
    if not bool(validator.get("accepted", False)):
        raise ValueError("LLM hypothesis artifact must be validator-accepted before replay conversion")
    hypothesis_kind = str(payload.get("hypothesis_kind") or "")
    if hypothesis_kind not in SUPPORTED_LLM_REPLAY_KINDS:
        raise ValueError(f"Unsupported LLM replay hypothesis kind: {hypothesis_kind!r}")

    candidate_id = str(payload.get("candidate_id") or "")
    proposed_setup = dict(payload.get("proposed_setup") or {}) if isinstance(payload.get("proposed_setup"), Mapping) else {}
    proposed_inputs = dict(payload.get("proposed_inputs") or {}) if isinstance(payload.get("proposed_inputs"), Mapping) else {}
    expected_sink = dict(payload.get("expected_sink") or {}) if isinstance(payload.get("expected_sink"), Mapping) else {}
    mode = _first_text(
        proposed_setup.get("replay_mode"),
        proposed_setup.get("mode"),
        proposed_inputs.get("replay_mode"),
        proposed_inputs.get("mode"),
        default_mode,
    )
    setup = dict(proposed_setup)
    if binary_path is not None and not setup.get("binary_path"):
        setup["binary_path"] = str(binary_path)
    setup["llm_derived_setup"] = True
    setup["llm_hypothesis_kind"] = hypothesis_kind
    setup["validator_reason_codes"] = list(validator.get("reason_codes", []) or [])
    if isinstance(validator.get("details"), Mapping):
        preconditions = validator["details"].get("preconditions")
        if isinstance(preconditions, Mapping):
            setup["validated_preconditions"] = dict(preconditions)

    replay_input = {
        key: value
        for key, value in proposed_inputs.items()
        if key not in {"mode", "replay_mode"}
    }
    expected_result = _expected_result_from_sink(expected_sink, payload)
    expected_result["llm_derived_setup"] = True
    expected_result["hypothesis_kind"] = hypothesis_kind
    return ReplayRequest(
        candidate_id=candidate_id,
        mode=mode,
        setup=setup,
        input=replay_input,
        expected_result=expected_result,
    )


def replay_requests_from_llm_artifacts(
    artifacts: Sequence[Mapping[str, Any] | Any],
    *,
    binary_path: Path | str | None = None,
    default_mode: str = "native",
) -> list[ReplayRequest]:
    """Convert all accepted replay/environment artifacts, skipping others."""

    requests: list[ReplayRequest] = []
    for artifact in artifacts:
        payload = _artifact_mapping(artifact)
        if str(payload.get("hypothesis_kind") or "") not in SUPPORTED_LLM_REPLAY_KINDS:
            continue
        validator = payload.get("validator_result") if isinstance(payload.get("validator_result"), Mapping) else {}
        if not bool(validator.get("accepted", False)):
            continue
        requests.append(
            replay_request_from_llm_artifact(
                payload,
                binary_path=binary_path,
                default_mode=default_mode,
            )
        )
    return requests


def _artifact_mapping(artifact: Mapping[str, Any] | Any) -> dict[str, Any]:
    if isinstance(artifact, Mapping):
        return dict(artifact)
    if hasattr(artifact, "to_dict"):
        value = artifact.to_dict()
        return dict(value) if isinstance(value, Mapping) else {}
    return {
        "candidate_id": getattr(artifact, "candidate_id", ""),
        "hypothesis_kind": getattr(artifact, "hypothesis_kind", ""),
        "proposed_setup": getattr(artifact, "proposed_setup", {}),
        "proposed_inputs": getattr(artifact, "proposed_inputs", {}),
        "expected_sink": getattr(artifact, "expected_sink", {}),
        "validator_result": getattr(artifact, "validator_result", {}),
    }


def _expected_result_from_sink(expected_sink: Mapping[str, Any], artifact: Mapping[str, Any]) -> dict[str, Any]:
    sink = str(expected_sink.get("sink") or expected_sink.get("sink_name") or "")
    function_name = str(expected_sink.get("function_name") or expected_sink.get("function") or "")
    marker = str(expected_sink.get("sink_output_contains") or function_name or sink or "")
    result = {
        "candidate_id": str(artifact.get("candidate_id") or ""),
        "sink": sink,
        "function_name": function_name,
        "sink_address": str(
            expected_sink.get("operation_address")
            or expected_sink.get("sink_address")
            or expected_sink.get("target_address")
            or expected_sink.get("address")
            or ""
        ),
        "sink_output_contains": marker,
    }
    if "expect_crash" in expected_sink:
        result["expect_crash"] = bool(expected_sink.get("expect_crash"))
    else:
        result["expect_crash"] = bool(artifact.get("expect_crash", True))
    for key in ("proof_oracle", "overflow_oracle", "dynamic_overflow_oracle"):
        oracle = expected_sink.get(key) or artifact.get(key)
        if isinstance(oracle, Mapping):
            result[key] = dict(oracle)
    return result


def _first_text(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return "native"
