"""Compact validation summaries for proof-gated pipeline runs."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.dynamic_proof import DynamicProofView, iter_ghidra_dynamic_proofs
from binary_agent.pipeline import CandidateState, build_source_to_sink_trace, has_reportable_source_to_sink
from binary_agent.taxonomy import VULNERABILITY_SPECS, vulnerability_types_for_backend


SEMANTIC_PROCESS_TYPES = vulnerability_types_for_backend("semantic_effect")
SEMANTIC_PROCESS_ORACLE_KINDS = {
    spec.effect_kind
    for spec in VULNERABILITY_SPECS.values()
    if spec.backend == "semantic_effect" and spec.effect_kind
}
PROCESS_REPLAY_MODES = {
    "native",
    "qemu_user",
    "container_service",
    "ghidra_process",
    "ghidra_function_harness",
}
SUPPORTED_PROCESS_INPUT_MODELS = {
    "argv",
    "stdin",
    "file",
    "env",
    "argv_file_stdin",
    "argv_directory",
    "line_file",
    "text_record",
    "config",
    "archive",
    "archive_text_record",
    "http_cgi",
    "http_daemon",
    "socket_service",
}
UNSUPPORTED_PROCESS_INPUT_MODELS = {"network", "socket", "http", "ipc", "device", "protocol"}
NEXT_INPUT_MODEL_DECISION = {
    "selected": "http_daemon",
    "reason": "HTTP daemon replay is implemented for deterministic request/response setup over a concrete service endpoint. Ambiguous HTTP protocol state, IPC, device, and config-derived inputs remain unsupported until evidence can model their setup.",
}
GHIDRA_MEMORY_PROOF_SCOPES = ("process_entrypoint", "function_harness")
GHIDRA_MEMORY_PROOF_STATUS_COUNTERS = {
    ("process_entrypoint", "overflow_proven"): "ghidra_process_overflow_proven",
    ("process_entrypoint", "heap_overflow_proven"): "ghidra_process_heap_overflow_proven",
    ("process_entrypoint", "oob_write_proven"): "ghidra_process_oob_write_proven",
    ("process_entrypoint", "oob_read_proven"): "ghidra_process_oob_read_proven",
    ("function_harness", "overflow_proven"): "ghidra_function_harness_overflow_proven",
    ("function_harness", "heap_overflow_proven"): "ghidra_function_harness_heap_overflow_proven",
    ("function_harness", "oob_write_proven"): "ghidra_function_harness_oob_write_proven",
    ("function_harness", "oob_read_proven"): "ghidra_function_harness_oob_read_proven",
}
GHIDRA_MEMORY_PROOF_SCOPE_COUNTERS = {
    "process_entrypoint": "ghidra_process_memory_safety_proven",
    "function_harness": "ghidra_function_harness_memory_safety_proven",
}


def summarize_validation_corpus(states: Sequence[CandidateState]) -> dict[str, Any]:
    """Return regression-oriented counts for proof-gated validation cases."""
    status_counts: Counter[str] = Counter()
    unsupported_reasons: Counter[str] = Counter()
    blocker_reasons: Counter[str] = Counter()
    replay_blockers: Counter[str] = Counter()
    by_vuln: dict[str, Counter[str]] = defaultdict(Counter)
    totals: Counter[str] = Counter()

    for state in states:
        status_counts[state.status] += 1
        by_vuln[state.vulnerability_type]["candidates"] += 1
        if has_reportable_source_to_sink(state):
            totals["reportable_source_to_sink"] += 1
            by_vuln[state.vulnerability_type]["reportable_source_to_sink"] += 1
        if state.status == "report_ready":
            totals["report_ready"] += 1
            by_vuln[state.vulnerability_type]["report_ready"] += 1
        if state.status == "rejected":
            totals["rejected_negatives"] += 1

        trace = build_source_to_sink_trace(state)
        if trace.status == "blocked":
            totals["blocked_source_to_sink"] += 1
        input_model = str(trace.input_model or "")
        if input_model in UNSUPPORTED_PROCESS_INPUT_MODELS:
            reason = f"unsupported_process_input_model:{input_model}"
            unsupported_reasons[reason] += 1
            blocker_reasons[reason] += 1
            totals["unsupported_blockers"] += 1
        for blocker in [*state.blockers, *trace.blockers]:
            blocker_reasons[str(blocker)] += 1
            if "unsupported" in str(blocker):
                unsupported_reasons[str(blocker)] += 1

        artifacts = _json_artifacts_for_state(state)
        for counter in _ghidra_memory_proof_counters(artifacts):
            totals[counter] += 1
            by_vuln[state.vulnerability_type][counter] += 1
        if any(_is_confirmed_process_replay(payload) for payload in artifacts):
            totals["process_replay_confirmed"] += 1
            by_vuln[state.vulnerability_type]["process_replay_confirmed"] += 1
        if state.vulnerability_type in SEMANTIC_PROCESS_TYPES and any(_is_semantic_process_proof(payload) for payload in artifacts):
            totals["semantic_process_proven"] += 1
            by_vuln[state.vulnerability_type]["semantic_process_proven"] += 1
        if any(_is_unsupported_artifact(payload) for payload in artifacts):
            totals["unsupported_blockers"] += 1
            for reason in _unsupported_artifact_reasons(artifacts):
                unsupported_reasons[reason] += 1
                blocker_reasons[reason] += 1
        for reason in _replay_blocker_reasons(artifacts):
            replay_blockers[reason] += 1
            blocker_reasons[reason] += 1

    return {
        "schema_version": 1,
        "candidate_count": len(states),
        "status_counts": dict(sorted(status_counts.items())),
        "totals": dict(sorted(totals.items())),
        "by_vulnerability_type": {
            vulnerability_type: dict(sorted(counter.items()))
            for vulnerability_type, counter in sorted(by_vuln.items())
        },
        "unsupported_reasons": dict(sorted(unsupported_reasons.items())),
        "unsupported_reason_dashboard": _unsupported_reason_dashboard(unsupported_reasons),
        "replay_blocker_dashboard": _replay_blocker_dashboard(replay_blockers),
        "blocker_stage_dashboard": _blocker_stage_dashboard(blocker_reasons),
        "supported_process_input_models": sorted(SUPPORTED_PROCESS_INPUT_MODELS),
        "unsupported_process_input_models": sorted(UNSUPPORTED_PROCESS_INPUT_MODELS),
        "next_input_model_decision": dict(NEXT_INPUT_MODEL_DECISION),
    }


def write_validation_summary(states: Sequence[CandidateState], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summarize_validation_corpus(states), indent=2, sort_keys=True))
    return output_path


def _json_artifacts_for_state(state: CandidateState) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for raw in _state_artifact_paths(state):
        path = Path(raw)
        if not path.exists() or path.suffix.lower() != ".json":
            continue
        try:
            payload = json.loads(path.read_text() or "{}")
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, Mapping):
            payloads.append(dict(payload))
    return payloads


def _state_artifact_paths(state: CandidateState) -> list[str]:
    paths = [*state.validation_artifacts, *state.replay_artifacts, *state.report_artifacts]
    for raw in list(paths):
        sibling = Path(raw).parent / "result.json"
        if sibling.exists():
            paths.append(str(sibling))
    seen: set[str] = set()
    result: list[str] = []
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        result.append(path)
    return result


def _ghidra_memory_proof_counters(artifacts: Sequence[Mapping[str, Any]]) -> list[str]:
    hits: dict[str, set[str]] = {scope: set() for scope in GHIDRA_MEMORY_PROOF_SCOPES}
    for payload in artifacts:
        for proof in iter_ghidra_dynamic_proofs(payload):
            view = DynamicProofView(proof)
            if view.scope in hits and view.is_memory_safety_proof(
                scope=view.scope,
                require_setup=True,
                require_sink=False,
            ):
                hits[view.scope].add(view.status)

    counters: set[str] = set()
    for scope, statuses in hits.items():
        if statuses:
            counters.add(GHIDRA_MEMORY_PROOF_SCOPE_COUNTERS[scope])
        for status in statuses:
            counters.add(GHIDRA_MEMORY_PROOF_STATUS_COUNTERS[(scope, status)])
    return sorted(counters)


def _is_confirmed_process_replay(payload: Mapping[str, Any]) -> bool:
    return (
        str(payload.get("result") or "") == "confirmed"
        and str(payload.get("mode") or "") in PROCESS_REPLAY_MODES
        and bool(payload.get("sink_reached"))
        and bool(payload.get("bug_observed"))
    )


def _is_semantic_process_proof(payload: Mapping[str, Any]) -> bool:
    if str(payload.get("result") or "") == "confirmed":
        if not _is_confirmed_process_replay(payload):
            return False
        control = payload.get("control_result") if isinstance(payload.get("control_result"), Mapping) else {}
        observation = control.get("proof_observation") if isinstance(control.get("proof_observation"), Mapping) else {}
        return _semantic_observation_proven(observation)
    return _semantic_observation_proven(payload)


def _semantic_observation_proven(payload: Mapping[str, Any]) -> bool:
    return (
        str(payload.get("kind") or "") in SEMANTIC_PROCESS_ORACLE_KINDS
        and bool(payload.get("bug_observed"))
    )


def _unsupported_reason_dashboard(reasons: Counter[str]) -> dict[str, Any]:
    by_category: Counter[str] = Counter()
    for reason, count in reasons.items():
        by_category[_unsupported_reason_category(reason)] += count
    return {
        "total": sum(reasons.values()),
        "top_reasons": [
            {"reason": reason, "count": count}
            for reason, count in sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:10]
        ],
        "by_category": dict(sorted(by_category.items())),
    }


def _unsupported_reason_category(reason: str) -> str:
    text = str(reason or "")
    if text.startswith("unsupported_process_input_model:"):
        return "process_input_model"
    if "unsupported_process_input_setup" in text:
        return "process_input_setup"
    if "unsupported_process_input_source" in text:
        return "process_input_source"
    if "ambiguous" in text:
        return "ambiguous"
    return text.partition(":")[0] or "unsupported"


def _blocker_stage_dashboard(reasons: Counter[str]) -> dict[str, Any]:
    by_stage: Counter[str] = Counter()
    for reason, count in reasons.items():
        by_stage[_blocker_stage(reason)] += count
    return {
        "total": sum(reasons.values()),
        "top_reasons": [
            {"stage": _blocker_stage(reason), "reason": reason, "count": count}
            for reason, count in sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:10]
        ],
        "by_stage": dict(sorted(by_stage.items())),
    }


def _blocker_stage(reason: str) -> str:
    text = str(reason or "")
    if not text:
        return "unknown"
    if "process_input" in text or text in {"unsupported_or_missing_process_input_model", "no_entry_input_source"}:
        return "process_input"
    if "entrypoint" in text or "call_path" in text or "reachability_path" in text:
        return "entrypoint"
    if "source_to_sink" in text or "controlled" in text or "sink_role" in text or "attacker_input_reaches_sink" in text:
        return "source_to_sink"
    if "replay" in text or "boundary" in text or "concrete" in text:
        return "replay"
    if "proof" in text or "backend" in text or "timeout" in text or "unsat" in text:
        return "proof"
    if "unsupported" in text or "ambiguous" in text:
        return "unsupported"
    return "other"


def _is_unsupported_artifact(payload: Mapping[str, Any]) -> bool:
    if bool(payload.get("unsupported")):
        return True
    if str(payload.get("status") or "") in {"unsupported", "blocked"}:
        return True
    if str(payload.get("result") or "") in {"blocked", "setup_invalid"}:
        return True
    reason = json.dumps(payload, sort_keys=True).lower()
    return "unsupported" in reason


def _unsupported_artifact_reasons(artifacts: Sequence[Mapping[str, Any]]) -> list[str]:
    reasons: list[str] = []
    for payload in artifacts:
        for key in ("reason", "blocked_reason", "failure_reason"):
            value = payload.get(key)
            if value and "unsupported" in str(value):
                reasons.append(str(value))
        control = payload.get("control_result") if isinstance(payload.get("control_result"), Mapping) else {}
        value = control.get("reason")
        if value and "unsupported" in str(value):
            reasons.append(str(value))
    return reasons or ["unsupported_artifact"]


def _replay_blocker_reasons(artifacts: Sequence[Mapping[str, Any]]) -> list[str]:
    reasons: list[str] = []
    for payload in artifacts:
        if str(payload.get("result") or "") not in {"blocked", "setup_invalid"} and str(payload.get("status") or "") not in {"blocked", "unsupported"}:
            continue
        control = payload.get("control_result") if isinstance(payload.get("control_result"), Mapping) else {}
        reason = payload.get("reason") or payload.get("blocked_reason") or control.get("reason")
        if reason:
            reasons.append(str(reason))
    return reasons


def _replay_blocker_dashboard(reasons: Counter[str]) -> dict[str, Any]:
    return {
        "total": sum(reasons.values()),
        "top_reasons": [
            {"reason": reason, "count": count}
            for reason, count in sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:10]
        ],
    }
