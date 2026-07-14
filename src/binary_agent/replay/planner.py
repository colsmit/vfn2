"""Replay planning, proof-oracle derivation, and plan execution."""

from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.analysis.confirmation import iter_evidence_packs
from binary_agent.analysis.hypothesis_generation import load_hypothesis_artifacts
from binary_agent.analysis.llm_evaluation import HypothesisArtifact
from binary_agent.pipeline import CandidateState
from binary_agent.replay.conversion import replay_request_from_llm_artifact
from binary_agent.replay.models import ReplayRequest, ReplayResult, ReplayStatus, write_replay_result
from binary_agent.replay.repair import ReplayRepairProvider, repair_replay
from binary_agent.replay.runners import build_replay_requests, run_replay_request
from binary_agent.sink_sites import sink_site_key
from binary_agent.taxonomy import VULNERABILITY_SPECS, vulnerability_types_for_backend


MEMORY_CORRUPTION_TYPES = vulnerability_types_for_backend("memory_access")
SEMANTIC_PROCESS_TYPES = vulnerability_types_for_backend("semantic_effect")
SEMANTIC_PROCESS_ORACLE_KINDS = {
    spec.effect_kind
    for spec in VULNERABILITY_SPECS.values()
    if spec.backend == "semantic_effect" and spec.effect_kind
}
_SUPPORTED_REPLAY_MODES = {"auto", "native", "function_harness", "qemu_user", "qemu_system", "container_service", "off"}
_DISASSEMBLY_CACHE: dict[tuple[str, str, str], str] = {}


@dataclass(frozen=True)
class ReplayPlanEntry:
    candidate_id: str
    request: ReplayRequest
    provenance: str
    selected: bool
    reason: str
    source_artifact: str = ""
    blocked_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["request"] = self.request.to_dict()
        return payload


@dataclass(frozen=True)
class ReplayPlan:
    entries: tuple[ReplayPlanEntry, ...] = field(default_factory=tuple)

    @property
    def requests(self) -> list[ReplayRequest]:
        return [entry.request for entry in self.entries if entry.selected]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "entries": [entry.to_dict() for entry in self.entries],
            "selected_request_count": sum(1 for entry in self.entries if entry.selected),
        }

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))
        return path


def build_replay_plan(
    states: Sequence[CandidateState],
    *,
    binary_path: Path | None = None,
    mode: str = "auto",
    hypothesis_artifacts: Sequence[HypothesisArtifact | Mapping[str, Any]] | None = None,
    hypothesis_artifacts_dir: Path | None = None,
    evidence_dir: Path | None = None,
    max_requests_per_candidate: int = 3,
) -> ReplayPlan:
    """Build ordered replay requests from LLM artifacts plus deterministic fallback."""

    ranked_states = _rank_states_for_replay(states)
    evidence_by_id = _load_evidence_by_id(evidence_dir)
    artifacts = list(hypothesis_artifacts or [])
    if hypothesis_artifacts_dir is not None:
        artifacts.extend(load_hypothesis_artifacts(Path(hypothesis_artifacts_dir)))

    entries: list[ReplayPlanEntry] = []
    seen: set[tuple[str, ...]] = set()
    counts: dict[str, int] = {}

    for artifact in artifacts:
        artifact_payload = _artifact_mapping(artifact)
        if not bool(_validator(artifact_payload).get("accepted", False)):
            continue
        kind = str(artifact_payload.get("hypothesis_kind") or "")
        if kind not in {"replay", "environment"}:
            continue
        try:
            request = replay_request_from_llm_artifact(
                artifact_payload,
                binary_path=binary_path or _state_binary_path(states, str(artifact_payload.get("candidate_id") or "")),
                default_mode="native" if mode == "auto" else mode,
            )
        except ValueError:
            continue
        request = _coerce_requested_replay_mode(request, mode)
        provenance = "llm_environment" if kind == "environment" else "llm_replay"
        request = _with_provenance(request, provenance)
        state = _state_by_id(ranked_states, request.candidate_id)
        evidence_pack = evidence_by_id.get(request.candidate_id, {})
        request = _attach_derived_oracle_if_available(
            request,
            state,
            evidence_pack,
            states=states,
            block_on_missing=False,
        )
        entries.append(
            _select_entry(
                request,
                provenance,
                "accepted_llm_hypothesis",
                counts,
                seen,
                max_requests_per_candidate,
                state=state,
            )
        )

    for request in _http_cgi_replay_requests(
        ranked_states,
        evidence_by_id=evidence_by_id,
        binary_path=binary_path,
        default_mode="native" if mode == "auto" else mode,
    ):
        state = _state_by_id(ranked_states, request.candidate_id)
        request = _with_provenance(request, "deterministic_http_cgi")
        entries.append(
            _select_entry(
                request,
                "deterministic_http_cgi",
                "deterministic_http_cgi_replay_request",
                counts,
                seen,
                max_requests_per_candidate,
                state=state,
            )
        )

    for request in _http_daemon_replay_requests(
        ranked_states,
        evidence_by_id=evidence_by_id,
        binary_path=binary_path,
        default_mode="native" if mode == "auto" else mode,
    ):
        state = _state_by_id(ranked_states, request.candidate_id)
        request = _with_provenance(request, "deterministic_http_daemon")
        entries.append(
            _select_entry(
                request,
                "deterministic_http_daemon",
                "deterministic_http_daemon_replay_request",
                counts,
                seen,
                max_requests_per_candidate,
                state=state,
            )
        )

    deterministic = build_replay_requests(ranked_states, binary_path=binary_path, mode=mode)
    for request in deterministic:
        state = _state_by_id(ranked_states, request.candidate_id)
        evidence_pack = evidence_by_id.get(request.candidate_id, {})
        request = _with_provenance(request, "deterministic")
        request = _attach_derived_oracle_if_available(request, state, evidence_pack, states=states)
        entries.append(
            _select_entry(
                request,
                "deterministic",
                "deterministic_replay_request",
                counts,
                seen,
                max_requests_per_candidate,
                state=state,
            )
        )

    return ReplayPlan(tuple(entries))


def run_replay_plan(
    plan: ReplayPlan,
    output_dir: Path,
    *,
    evidence_dir: Path | None = None,
    repair_provider: ReplayRepairProvider | None = None,
    repair_max_attempts: int = 2,
) -> list[ReplayResult]:
    """Run selected plan entries and stop each candidate after confirmation."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_by_id = _load_evidence_by_id(evidence_dir)
    final_results: dict[str, ReplayResult] = {}
    confirmed: set[str] = set()
    for index, entry in enumerate(plan.entries, start=1):
        candidate_dir = output_dir / _safe_name(entry.candidate_id)
        if not entry.selected:
            _write_skipped(candidate_dir, index, entry, entry.reason)
            continue
        if entry.candidate_id in confirmed:
            _write_skipped(candidate_dir, index, entry, "candidate_already_confirmed")
            continue
        previous = final_results.get(entry.candidate_id)
        if entry.request.mode == "off" and previous is not None and _replay_result_rank(previous) > 10:
            _write_skipped(candidate_dir, index, entry, "candidate_prior_attempt_retained")
            continue
        result = run_replay_request(entry.request, output_dir)
        if (
            repair_provider is not None
            and _should_attempt_replay_repair(entry, result)
        ):
            evidence_pack = evidence_by_id.get(entry.candidate_id, {})
            if evidence_pack:
                try:
                    repair = repair_replay(
                        evidence_pack,
                        entry.request,
                        result,
                        repair_provider,
                        candidate_dir / "repair",
                        max_attempts=repair_max_attempts,
                    )
                except Exception as exc:  # provider failures should not discard replay evidence
                    _write_repair_error(candidate_dir / "repair", entry, result, exc)
                else:
                    repaired = ReplayResult.from_dict(repair.final_result)
                    if repaired.result != result.result or repaired.bug_observed != result.bug_observed:
                        result = repaired
                        root_result_path = candidate_dir / "result.json"
                        write_replay_result(result, root_result_path)
        final_results[entry.candidate_id] = _preferred_replay_result(previous, result)
        if previous is not None and final_results[entry.candidate_id] is previous:
            write_replay_result(previous, candidate_dir / "result.json")
        if result.result == ReplayStatus.CONFIRMED.value and result.sink_reached and result.bug_observed:
            confirmed.add(entry.candidate_id)
    return list(final_results.values())


def derive_proof_oracle(
    candidate: CandidateState | Mapping[str, Any],
    evidence_pack: Mapping[str, Any] | None = None,
    *,
    binary_path: Path | str | None = None,
    callsite_rank: int = 1,
) -> dict[str, Any] | None:
    """Derive a bounded-write proof oracle from deterministic candidate facts."""

    data = candidate.to_dict() if hasattr(candidate, "to_dict") else dict(candidate)
    vulnerability_type = str(data.get("vulnerability_type") or _nested(data, "candidate", "vulnerability_type") or "")
    facts = _mapping(data.get("type_facts"))
    static_candidate = _mapping(facts.get("static_candidate"))
    sink = _mapping(data.get("sink"))
    location = _mapping(data.get("location"))
    evidence = dict(evidence_pack or {})
    proof_facts = _proof_facts(evidence)
    destination_kind = str(
        proof_facts.get("destination_kind")
        or facts.get("destination_kind")
        or static_candidate.get("destination_kind")
        or ""
    ).lower()
    target_buffer = str(sink.get("target_buffer") or facts.get("target_buffer") or static_candidate.get("target_buffer") or "")
    capacity = _first_int(
        facts.get("capacity_bytes"),
        static_candidate.get("capacity_bytes"),
        proof_facts.get("capacity_bytes"),
    )
    write_bound = _first_int(
        facts.get("write_size_bytes"),
        facts.get("write_bound_bytes"),
        static_candidate.get("write_size_bytes"),
        proof_facts.get("write_size_bytes"),
        proof_facts.get("write_bound_bytes"),
    )
    explicit_sink_call = _first_address(
        proof_facts.get("sink_call_address"),
        sink.get("operation_address"),
        facts.get("operation_address"),
        static_candidate.get("operation_address"),
    )
    sink_call = explicit_sink_call or _first_address(location.get("address"))
    sink_ret = _first_address(proof_facts.get("sink_return_address"), _next_address(sink_call))
    alloc_call = _first_address(
        proof_facts.get("allocation_call_address"),
        facts.get("allocation_call_address"),
        static_candidate.get("allocation_call_address"),
        _nested(proof_facts, "allocation_site", "call_address"),
        _nested(proof_facts, "allocation_site", "address"),
    )
    alloc_ret = _first_address(
        proof_facts.get("allocation_return_address"),
        facts.get("allocation_return_address"),
        static_candidate.get("allocation_return_address"),
        _nested(proof_facts, "allocation_site", "return_address"),
        _next_address(alloc_call),
    )

    disassembly_facts = _derive_disassembly_oracle_facts(
        binary_path,
        function_address=location.get("address") or static_candidate.get("address"),
        sink_name=sink.get("name") or static_candidate.get("sink"),
        destination_kind=destination_kind,
        callsite_rank=callsite_rank,
    )
    if disassembly_facts:
        if not explicit_sink_call:
            sink_call = _first_address(disassembly_facts.get("sink_call_address"), sink_call)
            sink_ret = _first_address(disassembly_facts.get("sink_return_address"), _next_address(sink_call), sink_ret)
        elif not sink_ret:
            sink_ret = _first_address(disassembly_facts.get("sink_return_address"), _next_address(sink_call))
        if destination_kind != "stack":
            alloc_call = alloc_call or _first_address(disassembly_facts.get("allocation_call_address"))
            alloc_ret = alloc_ret or _first_address(disassembly_facts.get("allocation_return_address"), _next_address(alloc_call))

    allowed = sorted(_allowed_proof_addresses(data, evidence, [sink_call, sink_ret, alloc_call, alloc_ret]))
    if vulnerability_type and vulnerability_type not in MEMORY_CORRUPTION_TYPES and not proof_facts:
        return None
    missing = []
    if destination_kind != "stack":
        if not alloc_call:
            missing.append("allocation_call_address")
        if not alloc_ret:
            missing.append("allocation_return_address")
    if not sink_call:
        missing.append("sink_call_address")
    if not sink_ret:
        missing.append("sink_return_address")
    if destination_kind == "stack" and capacity is None:
        missing.append("capacity_bytes")
    if missing:
        return {
            "kind": "stack_bounded_write_overflow" if destination_kind == "stack" else "bounded_write_overflow",
            "blocked": True,
            "blocked_reason": "missing_oracle_facts:" + ",".join(missing),
            "missing_facts": missing,
            "allowed_proof_addresses": allowed,
            "destination_kind": destination_kind,
            "target_buffer": target_buffer,
            "capacity_bytes": capacity,
            "write_bound_bytes": write_bound,
        }
    if destination_kind == "stack":
        oracle = {
            "kind": "stack_bounded_write_overflow",
            "observe_memory_write": True,
            "destination_kind": destination_kind,
            "target_buffer": target_buffer,
            "sink_call_address": sink_call,
            "sink_return_address": sink_ret,
            "sink_pointer_register": str(proof_facts.get("sink_pointer_register") or "r0"),
            "sink_bound_register": str(proof_facts.get("sink_bound_register") or proof_facts.get("write_size_register") or "r1"),
            "allowed_proof_addresses": allowed,
        }
        if capacity is not None:
            oracle["capacity_bytes"] = capacity
        if write_bound is not None:
            oracle["write_bound_bytes"] = write_bound
        return oracle
    oracle = {
        "kind": "bounded_write_overflow",
        "observe_memory_write": True,
        "destination_kind": destination_kind,
        "target_buffer": target_buffer,
        "allocation_call_address": alloc_call,
        "allocation_return_address": alloc_ret,
        "sink_call_address": sink_call,
        "sink_return_address": sink_ret,
        "allocation_size_register": str(proof_facts.get("allocation_size_register") or "r0"),
        "allocation_pointer_register": str(proof_facts.get("allocation_pointer_register") or "r0"),
        "sink_pointer_register": str(proof_facts.get("sink_pointer_register") or "r0"),
        "sink_bound_register": str(proof_facts.get("sink_bound_register") or proof_facts.get("write_size_register") or "r1"),
        "allowed_proof_addresses": allowed,
    }
    if capacity is not None:
        oracle["capacity_bytes"] = capacity
    if write_bound is not None:
        oracle["write_bound_bytes"] = write_bound
    return oracle


def _select_entry(
    request: ReplayRequest,
    provenance: str,
    reason: str,
    counts: dict[str, int],
    seen: set[tuple[str, ...]],
    max_requests_per_candidate: int,
    *,
    state: CandidateState | None = None,
) -> ReplayPlanEntry:
    signature = _canonical_proof_obligation_key(request, state)
    if signature in seen:
        return ReplayPlanEntry(request.candidate_id, request, provenance, False, "duplicate_proof_obligation")
    seen.add(signature)
    count = counts.get(request.candidate_id, 0)
    if count >= max(0, max_requests_per_candidate):
        return ReplayPlanEntry(request.candidate_id, request, provenance, False, "per_candidate_limit")
    counts[request.candidate_id] = count + 1
    blocked_reason = str(request.setup.get("blocked_reason") or "")
    return ReplayPlanEntry(
        request.candidate_id,
        request,
        provenance,
        True,
        reason,
        blocked_reason=blocked_reason,
    )


def _preferred_replay_result(previous: ReplayResult | None, current: ReplayResult) -> ReplayResult:
    if previous is None:
        return current
    if _replay_result_rank(current) > _replay_result_rank(previous):
        return current
    return previous


def _should_attempt_replay_repair(entry: ReplayPlanEntry, result: ReplayResult) -> bool:
    if result.result == ReplayStatus.CONFIRMED.value:
        return False
    if entry.provenance not in {"llm_replay", "llm_environment", "llm_semantic_seed", "deterministic", "deterministic_http_cgi", "deterministic_http_daemon"}:
        return False
    if result.result in {
        ReplayStatus.BLOCKED.value,
        ReplayStatus.SETUP_INVALID.value,
        ReplayStatus.SINK_NOT_REACHED.value,
    }:
        return True
    if result.result == ReplayStatus.SINK_REACHED_NO_BUG.value:
        return True
    if result.result == ReplayStatus.CRASH_UNCLASSIFIED.value:
        return result.sink_reached
    return False


def _write_repair_error(
    output_dir: Path,
    entry: ReplayPlanEntry,
    result: ReplayResult,
    exc: Exception,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "repair_error.json"
    payload = {
        "candidate_id": entry.candidate_id,
        "provenance": entry.provenance,
        "error_type": type(exc).__name__,
        "error": str(exc),
        "request": entry.request.to_dict(),
        "initial_result": result.to_dict(),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


def _replay_result_rank(result: ReplayResult) -> int:
    if result.result == ReplayStatus.CONFIRMED.value and result.sink_reached and result.bug_observed:
        return 70
    if result.result == ReplayStatus.SINK_REACHED_NO_BUG.value or result.sink_reached:
        return 50
    if result.result == ReplayStatus.CRASH_UNCLASSIFIED.value:
        return 40
    if result.result == ReplayStatus.SINK_NOT_REACHED.value:
        return 30
    if result.result == ReplayStatus.SETUP_INVALID.value:
        return 20
    if result.result == ReplayStatus.BLOCKED.value:
        return 10
    return 0


def _request_signature(request: ReplayRequest) -> dict[str, Any]:
    setup = {
        key: value
        for key, value in dict(request.setup).items()
        if key
        not in {
            "provenance",
            "llm_derived_setup",
            "llm_hypothesis_kind",
            "validator_reason_codes",
            "validated_preconditions",
        }
    }
    expected = {
        key: value
        for key, value in dict(request.expected_result).items()
        if key not in {"provenance", "llm_derived_setup", "hypothesis_kind"}
    }
    return {
        "mode": request.mode,
        "setup": setup,
        "input": dict(request.input),
        "expected_result": expected,
    }


def _canonical_proof_obligation_key(request: ReplayRequest, state: CandidateState | None) -> tuple[str, ...]:
    expected = dict(request.expected_result)
    setup = dict(request.setup)
    oracle = expected.get("proof_oracle") if isinstance(expected.get("proof_oracle"), Mapping) else {}
    location = dict(state.location) if state is not None else {}
    sink = dict(state.sink) if state is not None else {}
    target = dict(state.target) if state is not None else {}
    vulnerability_type = str(
        expected.get("vulnerability_type")
        or (state.vulnerability_type if state is not None else "")
        or ""
    )
    binary = str(
        setup.get("binary_path")
        or target.get("path")
        or target.get("relative_path")
        or target.get("binary")
        or ""
    )
    function_address = _normalize_address(
        expected.get("function_address")
        or expected.get("target_address")
        or location.get("address")
        or _nested(dict(state.type_facts) if state is not None else {}, "static_candidate", "address")
    )
    sink_address = _normalize_address(
        expected.get("sink_address")
        or expected.get("operation_address")
        or sink.get("operation_address")
        or oracle.get("sink_call_address")
        or _nested(dict(state.type_facts) if state is not None else {}, "static_candidate", "operation_address")
    )
    sink_name = str(expected.get("sink") or sink.get("name") or "")
    if sink_address and sink_address == function_address and sink_name and not sink.get("operation_address"):
        sink_address = ""
    static_candidate = _mapping(_nested(dict(state.type_facts) if state is not None else {}, "static_candidate"))
    sink_identity = sink_site_key(
        {
            "sink_address": sink_address,
            "function_address": function_address,
            "sink_name": sink_name or static_candidate.get("sink"),
            "target_buffer": (
                expected.get("target_buffer")
                or sink.get("target_buffer")
                or oracle.get("target_buffer")
                or static_candidate.get("target_buffer")
            ),
            "offset_expr": (
                expected.get("offset_expr")
                or sink.get("offset_expr")
                or oracle.get("offset_expr")
                or static_candidate.get("offset_expr")
                or _candidate_id_field(request.candidate_id, 6)
            ),
            "line_number": (
                expected.get("line_number")
                or sink.get("line_number")
                or static_candidate.get("line_number")
                or _candidate_id_field(request.candidate_id, 3)
            ),
        }
    )
    oracle_kind = str(oracle.get("kind") or expected.get("proof_oracle_kind") or "")
    if not oracle_kind:
        oracle_kind = _default_oracle_kind_for_vulnerability_type(vulnerability_type)
    return (
        binary,
        function_address or str(location.get("function_name") or ""),
        sink_identity or sink_name,
        vulnerability_type,
        oracle_kind,
    )


def _candidate_id_field(candidate_id: str, index: int) -> str:
    parts = str(candidate_id or "").split(":")
    if 0 <= index < len(parts):
        return str(parts[index] or "")
    return ""


def _source_exercise_key(request: ReplayRequest) -> str:
    source: dict[str, Any] = {}
    for container_name, container in (("setup", request.setup), ("input", request.input)):
        if not isinstance(container, Mapping):
            continue
        for key in ("route", "routes", "env", "environment", "config", "nvram", "argv", "stdin", "body", "form", "query", "params", "method", "path", "headers", "port", "port_env", "port_arg_index"):
            if key in container:
                source[f"{container_name}.{key}"] = container[key]
    if not source:
        return ""
    return hashlib.sha256(json.dumps(source, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


def _default_oracle_kind_for_vulnerability_type(vulnerability_type: str) -> str:
    if vulnerability_type == "command_injection":
        return "command_effect"
    if vulnerability_type == "path_traversal":
        return "filesystem_read_escape"
    if vulnerability_type == "unsafe_file_write":
        return "filesystem_write_escape"
    if vulnerability_type == "format_string":
        return "format_string_effect"
    if vulnerability_type in {"credential_disclosure", "hardcoded_credential"}:
        return "credential_disclosure"
    if vulnerability_type == "auth_bypass":
        return "auth_bypass_effect"
    return ""


def _rank_states_for_replay(states: Sequence[CandidateState]) -> list[CandidateState]:
    return sorted(states, key=lambda state: (-_candidate_replay_score(state), state.candidate_id))


def _candidate_replay_score(state: CandidateState) -> int:
    score = 0
    facts = dict(state.type_facts)
    metadata = dict(state.metadata)
    static_candidate = _mapping(facts.get("static_candidate"))
    if state.status in {"proof_ready", "replay_ready"}:
        score += 100
    if _has_oracle_facts(state):
        score += 80
    if metadata.get("provenance") == "llm_semantic_seed" or "semantic_seed" in facts:
        score += 50
    if metadata.get("source_model") == "StaticCandidate" or static_candidate:
        score += 25
    if state.candidate_id.startswith("semantic:"):
        score -= 20
    if str(static_candidate.get("verdict") or facts.get("verdict") or "") in {"overflow", "unbounded"}:
        score += 30
    if str(static_candidate.get("write_relation") or facts.get("write_relation") or "") in {"proven_overflow", "unbounded"}:
        score += 25
    if facts.get("input_reaches_sink") or not state.blockers:
        score += 20
    if facts.get("path_is_valid"):
        score += 10
    if isinstance(facts.get("replay_hints"), Mapping):
        score += 15
    return score


def _has_oracle_facts(state: CandidateState) -> bool:
    facts = dict(state.type_facts)
    static_candidate = _mapping(facts.get("static_candidate"))
    if state.vulnerability_type in SEMANTIC_PROCESS_TYPES:
        return True
    if facts.get("capacity_bytes") or static_candidate.get("capacity_bytes"):
        return True
    if facts.get("write_size_bytes") or static_candidate.get("write_size_bytes"):
        return True
    if any(str(key).endswith("_address") for key in facts):
        return True
    return False


def _with_provenance(request: ReplayRequest, provenance: str) -> ReplayRequest:
    setup = dict(request.setup)
    setup.setdefault("provenance", provenance)
    expected = dict(request.expected_result)
    expected.setdefault("provenance", provenance)
    return ReplayRequest(
        candidate_id=request.candidate_id,
        mode=request.mode,
        setup=setup,
        input=dict(request.input),
        expected_result=expected,
    )


def _coerce_requested_replay_mode(request: ReplayRequest, requested_mode: str) -> ReplayRequest:
    if requested_mode == "auto":
        return request
    if request.mode == requested_mode:
        return request
    setup = dict(request.setup)
    setup.setdefault("provider_requested_mode", request.mode)
    return ReplayRequest(
        candidate_id=request.candidate_id,
        mode=requested_mode,
        setup=setup,
        input=dict(request.input),
        expected_result=dict(request.expected_result),
    )


def _semantic_seed_replay_requests(
    states: Sequence[CandidateState],
    *,
    binary_path: Path | None,
    default_mode: str,
) -> list[ReplayRequest]:
    requests: list[ReplayRequest] = []
    for state in states:
        if state.status not in {"proof_ready", "replay_ready"}:
            continue
        metadata = dict(state.metadata)
        facts = dict(state.type_facts)
        if metadata.get("provenance") != "llm_semantic_seed" and "semantic_seed" not in facts:
            continue
        semantic_seed = facts.get("semantic_seed") if isinstance(facts.get("semantic_seed"), Mapping) else {}
        if (
            state.vulnerability_type in MEMORY_CORRUPTION_TYPES
            or str(semantic_seed.get("vulnerability_type") or "") == "fs_config_memory_corruption"
            or bool(semantic_seed.get("deterministic_enrichment_only"))
            or bool(metadata.get("semantic_enrichment_only"))
        ):
            continue
        hints = facts.get("replay_hints")
        if not isinstance(hints, Mapping):
            hints = semantic_seed.get("replay_hints") if isinstance(semantic_seed.get("replay_hints"), Mapping) else {}
        request = _replay_request_from_semantic_hints(
            state,
            dict(hints or {}),
            binary_path=binary_path,
            default_mode=default_mode,
        )
        if request is not None:
            requests.append(request)
    return requests


def _http_cgi_replay_requests(
    states: Sequence[CandidateState],
    *,
    evidence_by_id: Mapping[str, Mapping[str, Any]],
    binary_path: Path | None,
    default_mode: str,
) -> list[ReplayRequest]:
    requests: list[ReplayRequest] = []
    for state in states:
        if state.status not in {"proof_ready", "replay_ready"}:
            continue
        if state.vulnerability_type not in SEMANTIC_PROCESS_TYPES:
            continue
        evidence_pack = evidence_by_id.get(state.candidate_id, {})
        request = _http_cgi_replay_request_from_state(
            state,
            evidence_pack,
            binary_path=binary_path,
            default_mode=default_mode,
        )
        if request is not None:
            requests.append(request)
    return requests


def _http_daemon_replay_requests(
    states: Sequence[CandidateState],
    *,
    evidence_by_id: Mapping[str, Mapping[str, Any]],
    binary_path: Path | None,
    default_mode: str,
) -> list[ReplayRequest]:
    requests: list[ReplayRequest] = []
    for state in states:
        if state.status not in {"proof_ready", "replay_ready"}:
            continue
        if state.vulnerability_type not in SEMANTIC_PROCESS_TYPES:
            continue
        evidence_pack = evidence_by_id.get(state.candidate_id, {})
        request = _http_daemon_replay_request_from_state(
            state,
            evidence_pack,
            binary_path=binary_path,
            default_mode=default_mode,
        )
        if request is not None:
            requests.append(request)
    return requests


def _http_daemon_replay_request_from_state(
    state: CandidateState,
    evidence_pack: Mapping[str, Any],
    *,
    binary_path: Path | None,
    default_mode: str,
) -> ReplayRequest | None:
    route = _http_cgi_route(state, evidence_pack)
    if not _has_http_daemon_process_model(state, evidence_pack):
        return None
    mode = _process_replay_mode(default_mode)
    if mode == "off":
        return None
    target_binary = str(
        binary_path
        or state.target.get("path")
        or _nested(_mapping(evidence_pack.get("candidate")), "target", "path")
        or ""
    )
    if not target_binary:
        return None
    service = _http_daemon_service_facts(state, evidence_pack)
    hints = _http_cgi_replay_hints(state, evidence_pack)
    route = route or _explicit_http_route(hints, service)
    if not route:
        return _llm_required_request(state, "ambiguous_http_replay_requires_llm:missing_route", target_binary)
    hints.setdefault("marker", _http_cgi_default_marker(state))
    proof_oracle = _semantic_proof_oracle_from_hints(hints, state)
    if not proof_oracle:
        return _llm_required_request(state, "ambiguous_http_replay_requires_llm:missing_proof_oracle", target_binary)
    proof_oracle = dict(proof_oracle)
    proof_oracle.setdefault("marker", str(hints.get("marker") or _http_cgi_default_marker(state)))
    replay_input = _explicit_http_replay_input(hints, service, input_model="http_daemon")
    if not replay_input:
        return _llm_required_request(
            state,
            "ambiguous_http_replay_requires_llm:missing_explicit_input_surface",
            target_binary,
        )
    replay_input.setdefault("method", str(route.get("method") or "GET").upper() or "GET")
    replay_input.setdefault("path", str(route.get("path") or route.get("route") or "/"))
    for key in ("host", "port", "port_env", "port_env_key", "port_arg", "port_arg_index", "argv", "argv_template", "headers"):
        value = service.get(key) or hints.get(key)
        if value not in (None, ""):
            replay_input[key] = value
    setup: dict[str, Any] = {
        "binary_path": target_binary,
        "routes": [dict(route)],
        "http_daemon_derived_setup": True,
        "process_input_setup": {
            "status": "configured",
            "input_model": "http_daemon",
            "route": dict(route),
        },
    }
    if service:
        setup["http_daemon"] = dict(service)
    expected = {
        "candidate_id": state.candidate_id,
        "vulnerability_type": state.vulnerability_type,
        "function_name": str(state.location.get("function_name") or ""),
        "sink": str(state.sink.get("name") or ""),
        "sink_address": str(state.sink.get("operation_address") or state.location.get("address") or ""),
        "sink_output_contains": str(proof_oracle.get("marker") or ""),
        "expect_crash": False,
        "proof_oracle": proof_oracle,
        "hypothesis_kind": "deterministic_http_daemon",
        "process_input_model": "http_daemon",
    }
    return ReplayRequest(
        candidate_id=state.candidate_id,
        mode=mode,
        setup=setup,
        input=replay_input,
        expected_result=expected,
    )


def _http_cgi_replay_request_from_state(
    state: CandidateState,
    evidence_pack: Mapping[str, Any],
    *,
    binary_path: Path | None,
    default_mode: str,
) -> ReplayRequest | None:
    route = _http_cgi_route(state, evidence_pack)
    if not route:
        return None
    if _ungrounded_semantic_seed_route(state, evidence_pack):
        return None
    if not _has_http_cgi_process_model(state, evidence_pack, route):
        return None
    mode = _process_replay_mode(default_mode)
    if mode == "off":
        return None
    target_binary = str(
        binary_path
        or state.target.get("path")
        or _nested(_mapping(evidence_pack.get("candidate")), "target", "path")
        or ""
    )
    if not target_binary:
        return None
    hints = _http_cgi_replay_hints(state, evidence_pack)
    hints.setdefault("marker", _http_cgi_default_marker(state))
    proof_oracle = _semantic_proof_oracle_from_hints(hints, state)
    if not proof_oracle:
        target_binary = str(
            binary_path
            or state.target.get("path")
            or _nested(_mapping(evidence_pack.get("candidate")), "target", "path")
            or ""
        )
        return _llm_required_request(state, "ambiguous_http_replay_requires_llm:missing_proof_oracle", target_binary)
    proof_oracle = dict(proof_oracle)
    proof_oracle.setdefault("marker", str(hints.get("marker") or _http_cgi_default_marker(state)))
    replay_input = _explicit_http_replay_input(hints, {}, input_model="http_cgi")
    if not replay_input:
        return _llm_required_request(
            state,
            "ambiguous_http_replay_requires_llm:missing_explicit_input_surface",
            target_binary,
        )
    replay_input.setdefault("method", str(route.get("method") or "POST").upper() or "POST")
    setup: dict[str, Any] = {
        "binary_path": target_binary,
        "routes": [dict(route)],
        "http_cgi_derived_setup": True,
        "process_input_setup": {
            "status": "configured",
            "input_model": "http_cgi",
            "route": dict(route),
        },
    }
    auth = _http_cgi_auth_setup(state, evidence_pack)
    if auth:
        setup["auth"] = auth
    expected = {
        "candidate_id": state.candidate_id,
        "vulnerability_type": state.vulnerability_type,
        "function_name": str(state.location.get("function_name") or ""),
        "sink": str(state.sink.get("name") or ""),
        "sink_address": str(state.sink.get("operation_address") or state.location.get("address") or ""),
        "sink_output_contains": str(proof_oracle.get("marker") or ""),
        "expect_crash": False,
        "proof_oracle": proof_oracle,
        "hypothesis_kind": "deterministic_http_cgi",
        "process_input_model": "http_cgi",
    }
    return ReplayRequest(
        candidate_id=state.candidate_id,
        mode=mode,
        setup=setup,
        input=replay_input,
        expected_result=expected,
    )


def _process_replay_mode(default_mode: str) -> str:
    mode = str(default_mode or "native")
    if mode in {"auto", ""}:
        return "native"
    if mode in {"native", "qemu_user", "off"}:
        return mode
    return "off"


def _http_cgi_replay_hints(state: CandidateState, evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    facts = dict(state.type_facts)
    semantic_seed = _mapping(facts.get("semantic_seed"))
    hints: dict[str, Any] = {}
    for source in (
        facts.get("replay_hints"),
        semantic_seed.get("replay_hints"),
        facts.get("deterministic_replay_intent"),
        _mapping(evidence_pack.get("proof_oracle_facts")),
        _mapping(_mapping(evidence_pack.get("facts_available_to_llm")).get("proof_oracle_facts")),
    ):
        if isinstance(source, Mapping):
            _merge_nested_mapping(hints, source)
    for source in (facts, semantic_seed, _mapping(evidence_pack.get("candidate"))):
        oracle = source.get("proof_oracle") if isinstance(source.get("proof_oracle"), Mapping) else None
        if isinstance(oracle, Mapping) and "proof_oracle" not in hints:
            hints["proof_oracle"] = dict(oracle)
    if state.vulnerability_type == "path_traversal":
        hints.setdefault("marker", "root:x")
    elif state.vulnerability_type == "unsafe_file_write":
        hints.setdefault("marker", "BINARY_AGENT_HTTP_CGI_WRITE")
    return hints


def _merge_nested_mapping(target: dict[str, Any], source: Mapping[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, Mapping) and isinstance(target.get(key), Mapping):
            merged = dict(target[key])
            _merge_nested_mapping(merged, value)
            target[key] = merged
        else:
            target.setdefault(str(key), value)


def _has_http_daemon_process_model(state: CandidateState, evidence_pack: Mapping[str, Any]) -> bool:
    return "http_daemon" in _http_process_models(state, evidence_pack)


def _http_daemon_service_facts(state: CandidateState, evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    facts = dict(state.type_facts)
    sources = [
        _nested(facts, "process_input", "http_daemon"),
        _nested(facts, "replay_hints", "http_daemon"),
        _nested(evidence_pack, "candidate", "type_facts", "process_input", "http_daemon"),
        _nested(evidence_pack, "facts_available_to_llm", "process_input", "http_daemon"),
    ]
    result: dict[str, Any] = {}
    for source in sources:
        if isinstance(source, Mapping):
            _merge_nested_mapping(result, source)
    return result


def _explicit_http_route(*sources: Mapping[str, Any]) -> dict[str, Any] | None:
    for source in sources:
        route = source.get("route") if isinstance(source.get("route"), Mapping) else None
        if isinstance(route, Mapping) and (route.get("path") or route.get("route")):
            return dict(route)
        routes = source.get("routes")
        if isinstance(routes, Sequence) and not isinstance(routes, (str, bytes, bytearray)):
            for item in routes:
                if isinstance(item, Mapping) and (item.get("path") or item.get("route")):
                    return dict(item)
        path = source.get("path") or source.get("url") or source.get("uri")
        if path:
            return {"method": str(source.get("method") or "GET").upper(), "path": str(path)}
    return None


def _explicit_http_replay_input(
    hints: Mapping[str, Any],
    service: Mapping[str, Any],
    *,
    input_model: str,
) -> dict[str, Any]:
    for source in _explicit_http_input_sources(hints, service, input_model=input_model):
        request = {
            key: value
            for key, value in source.items()
            if key
            in {
                "argv",
                "argv_template",
                "body",
                "body_bytes_hex",
                "content_type",
                "cookies",
                "cookie",
                "form",
                "headers",
                "host",
                "host_header",
                "input_hex",
                "method",
                "params",
                "path",
                "payload",
                "port",
                "port_arg",
                "port_arg_index",
                "port_env",
                "port_env_key",
                "query",
                "read_timeout_seconds",
                "request",
                "route",
                "stdin",
            }
            and value not in (None, "")
        }
        if _has_explicit_http_input_surface(request):
            request["input_model"] = input_model
            return request
    return {}


def _explicit_http_input_sources(
    hints: Mapping[str, Any],
    service: Mapping[str, Any],
    *,
    input_model: str,
) -> list[Mapping[str, Any]]:
    sources: list[Mapping[str, Any]] = []
    for container in (hints, service):
        for key in ("input", "inputs", "proposed_inputs", "request"):
            value = container.get(key)
            if isinstance(value, Mapping):
                sources.append(value)
        value = container.get(input_model)
        if isinstance(value, Mapping):
            sources.append(value)
            for key in ("input", "inputs", "proposed_inputs", "request"):
                nested = value.get(key)
                if isinstance(nested, Mapping):
                    sources.append(nested)
    sources.extend(source for source in (hints, service) if isinstance(source, Mapping))
    return sources


def _has_explicit_http_input_surface(request: Mapping[str, Any]) -> bool:
    if any(key in request for key in ("body", "body_bytes_hex", "form", "input_hex", "params", "payload", "query", "request", "stdin")):
        return True
    path = str(request.get("path") or request.get("route") or "")
    return "{payload}" in path


def _llm_required_request(state: CandidateState, reason: str, binary_path: str = "") -> ReplayRequest:
    setup = {
        "binary_path": binary_path or str(state.target.get("path") or ""),
        "blocked_reason": reason,
        "llm_handoff_required": True,
    }
    return ReplayRequest(
        candidate_id=state.candidate_id,
        mode="off",
        setup=setup,
        input={},
        expected_result={
            "candidate_id": state.candidate_id,
            "vulnerability_type": state.vulnerability_type,
            "hypothesis_kind": "llm_required",
        },
    )


def _http_cgi_default_marker(state: CandidateState) -> str:
    digest = hashlib.sha256(state.candidate_id.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"BINARY_AGENT_HTTP_CGI_{digest}"


def _http_cgi_auth_setup(state: CandidateState, evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    facts = dict(state.type_facts)
    for source in (
        facts.get("auth"),
        _nested(facts, "replay_hints", "setup", "auth"),
        _nested(facts, "semantic_seed", "replay_hints", "setup", "auth"),
        _nested(evidence_pack, "facts_available_to_llm", "auth"),
    ):
        if isinstance(source, Mapping):
            return dict(source)
    return {}


def _ungrounded_semantic_seed_route(state: CandidateState, evidence_pack: Mapping[str, Any]) -> bool:
    facts = dict(state.type_facts)
    metadata = dict(state.metadata)
    if metadata.get("provenance") != "llm_semantic_seed" and "semantic_seed" not in facts:
        return False
    if facts.get("static_candidate") or metadata.get("source_model") == "StaticCandidate":
        return False
    if _entry_surface_kinds(state, evidence_pack) or "http_cgi" in _http_process_models(state, evidence_pack):
        return False
    if isinstance(_nested(evidence_pack, "intake_facts", "routes"), Mapping):
        return False
    return True


def _has_http_cgi_process_model(
    state: CandidateState,
    evidence_pack: Mapping[str, Any],
    route: Mapping[str, Any],
) -> bool:
    models = {model for model in _http_process_models(state, evidence_pack) if model}
    if "http_cgi" in models:
        return True
    surfaces = {surface for surface in _entry_surface_kinds(state, evidence_pack) if surface}
    if "cgi_handler" in surfaces:
        return True
    source_kind = str(state.source.get("kind") or "").lower()
    if source_kind == "cgi_route":
        return True
    if models:
        return False
    return _route_looks_cgi(route)


def _http_process_models(state: CandidateState, evidence_pack: Mapping[str, Any]) -> set[str]:
    facts = dict(state.type_facts)
    values = [
        facts.get("input_model"),
        _nested(facts, "process_input", "input_model"),
        _nested(facts, "process_input", "model"),
        _nested(facts, "source_to_sink_trace", "input_model"),
        _nested(facts, "entrypoint_derivation", "input_model"),
        _nested(facts, "entrypoint_derivation", "source_to_sink_trace", "input_model"),
        _nested(facts, "entrypoint_derivation", "entry_surface", "evidence", "input_model"),
        _nested(facts, "static_candidate", "entrypoint_derivation", "input_model"),
        _nested(evidence_pack, "input_model"),
        _nested(evidence_pack, "process_input", "input_model"),
        _nested(evidence_pack, "entrypoint_derivation", "input_model"),
        _nested(evidence_pack, "entrypoint_derivation", "source_to_sink_trace", "input_model"),
        _nested(evidence_pack, "facts_available_to_llm", "entrypoint_derivation", "input_model"),
        _nested(evidence_pack, "candidate", "type_facts", "source_to_sink_trace", "input_model"),
        _nested(evidence_pack, "candidate", "type_facts", "entrypoint_derivation", "input_model"),
        _nested(evidence_pack, "candidate", "type_facts", "process_input", "input_model"),
    ]
    source_model = str(state.source.get("input_model") or "")
    if source_model:
        values.append(source_model)
    return {str(value).strip().lower() for value in values if value not in (None, "")}


def _entry_surface_kinds(state: CandidateState, evidence_pack: Mapping[str, Any]) -> set[str]:
    facts = dict(state.type_facts)
    values = [
        _nested(facts, "entrypoint_derivation", "entry_surface", "kind"),
        _nested(facts, "source_to_sink_trace", "entry_surface_kind"),
        _nested(facts, "static_candidate", "entrypoint_derivation", "entry_surface", "kind"),
        _nested(evidence_pack, "entrypoint_derivation", "entry_surface", "kind"),
        _nested(evidence_pack, "facts_available_to_llm", "entrypoint_derivation", "entry_surface", "kind"),
        _nested(evidence_pack, "candidate", "type_facts", "entrypoint_derivation", "entry_surface", "kind"),
    ]
    return {str(value).strip().lower() for value in values if value not in (None, "")}


def _http_cgi_route(state: CandidateState, evidence_pack: Mapping[str, Any]) -> dict[str, str]:
    candidates: list[Mapping[str, Any]] = []
    facts = dict(state.type_facts)
    for source in (
        _nested(facts, "entrypoint_derivation", "entry_surface", "evidence"),
        _nested(facts, "entrypoint_derivation", "entry_surface"),
        _nested(facts, "entrypoint_derivation"),
        _nested(facts, "static_candidate", "entrypoint_derivation", "entry_surface", "evidence"),
        _nested(facts, "source_to_sink_trace"),
        _nested(evidence_pack, "entrypoint_derivation", "entry_surface", "evidence"),
        _nested(evidence_pack, "entrypoint_derivation", "entry_surface"),
        _nested(evidence_pack, "entrypoint_derivation"),
        _nested(evidence_pack, "facts_available_to_llm", "entrypoint_derivation", "entry_surface", "evidence"),
        _nested(evidence_pack, "intake_facts", "routes"),
        _nested(evidence_pack, "candidate", "source"),
        state.source,
    ):
        if isinstance(source, Mapping):
            candidates.extend(_route_rows(source))
    for row in candidates:
        route = _normalize_http_route(row)
        if route:
            return route
    return {}


def _route_rows(source: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows: list[Mapping[str, Any]] = []
    routes = source.get("routes")
    if isinstance(routes, Mapping):
        rows.append(routes)
        nested = routes.get("routes")
        if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes, bytearray)):
            rows.extend(item for item in nested if isinstance(item, Mapping))
    elif isinstance(routes, Sequence) and not isinstance(routes, (str, bytes, bytearray)):
        rows.extend(item for item in routes if isinstance(item, Mapping))
    if any(key in source for key in ("route", "path", "uri", "endpoint", "expression")):
        rows.append(source)
    return rows


def _normalize_http_route(row: Mapping[str, Any]) -> dict[str, str]:
    path = str(row.get("route") or row.get("uri") or row.get("endpoint") or row.get("expression") or row.get("path") or "").strip()
    if not path.startswith("/"):
        return {}
    method = str(row.get("method") or "POST").strip().upper()
    if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
        method = "POST"
    return {"method": method, "path": path}


def _route_looks_cgi(route: Mapping[str, Any]) -> bool:
    path = str(route.get("path") or route.get("route") or "").lower()
    return "/cgi-bin/" in path or path.endswith(".cgi") or "/cgi/" in path


def _replay_request_from_semantic_hints(
    state: CandidateState,
    hints: Mapping[str, Any],
    *,
    binary_path: Path | None,
    default_mode: str,
) -> ReplayRequest | None:
    setup_source = _mapping(hints.get("setup") or hints.get("proposed_setup"))
    input_source = _mapping(hints.get("input") or hints.get("inputs") or hints.get("proposed_inputs"))
    expected_source = _mapping(hints.get("expected_result") or hints.get("expected_sink"))
    mode = str(hints.get("mode") or setup_source.get("mode") or setup_source.get("replay_mode") or default_mode or "native")
    if not mode or mode == "auto" or "|" in mode or mode not in _SUPPORTED_REPLAY_MODES:
        mode = default_mode or "native"
    setup = dict(setup_source)
    setup.pop("mode", None)
    setup.pop("replay_mode", None)
    setup.setdefault("binary_path", str(binary_path or state.target.get("path") or ""))
    setup["llm_derived_setup"] = True
    setup["semantic_seed_id"] = str(state.metadata.get("semantic_seed_id") or _nested(facts := dict(state.type_facts), "semantic_seed", "seed_id") or "")
    setup["llm_hypothesis_kind"] = "semantic_seed"
    replay_input = dict(input_source)
    expected = dict(expected_source)
    expected.setdefault("candidate_id", state.candidate_id)
    expected.setdefault("vulnerability_type", state.vulnerability_type)
    expected.setdefault("function_name", str(state.location.get("function_name") or ""))
    expected.setdefault("sink", str(state.sink.get("name") or ""))
    expected.setdefault(
        "sink_address",
        str(state.sink.get("operation_address") or state.location.get("address") or ""),
    )
    expected.setdefault(
        "sink_output_contains",
        str(expected.get("function_name") or expected.get("sink") or state.location.get("function_name") or state.sink.get("name") or ""),
    )
    expected.setdefault("llm_derived_setup", True)
    expected.setdefault("hypothesis_kind", "semantic_seed")
    expected.setdefault("expect_crash", state.vulnerability_type in MEMORY_CORRUPTION_TYPES)
    proof_oracle = _semantic_proof_oracle_from_hints(hints, state)
    if isinstance(proof_oracle, Mapping):
        expected["proof_oracle"] = dict(proof_oracle)
        if str(proof_oracle.get("kind") or "") in SEMANTIC_PROCESS_ORACLE_KINDS:
            expected["expect_crash"] = False
    elif state.vulnerability_type in SEMANTIC_PROCESS_TYPES:
        expected["proof_oracle"] = _default_semantic_oracle(state, hints)
        expected["expect_crash"] = False
    if not setup.get("binary_path") and mode != "function_harness":
        return None
    return ReplayRequest(
        candidate_id=state.candidate_id,
        mode=mode,
        setup=setup,
        input=replay_input,
        expected_result=expected,
    )


def _semantic_proof_oracle_from_hints(hints: Mapping[str, Any], state: CandidateState) -> Mapping[str, Any] | None:
    setup = _mapping(hints.get("setup") or hints.get("proposed_setup"))
    expected = _mapping(hints.get("expected_result") or hints.get("expected_sink"))
    for source in (hints, setup, expected):
        for key in ("proof_oracle", "overflow_oracle", "dynamic_overflow_oracle"):
            oracle = source.get(key)
            if isinstance(oracle, Mapping):
                return _normalize_semantic_proof_oracle(dict(oracle), state)
    for key in (
        "command_effect",
        "filesystem_read_escape",
        "filesystem_write_escape",
        "format_string_effect",
        "credential_disclosure",
        "auth_bypass_effect",
        "bounded_write_overflow",
    ):
        value = expected.get(key) or hints.get(key)
        if not value:
            continue
        if isinstance(value, Mapping):
            oracle = dict(value)
            oracle.setdefault("kind", key)
            return _normalize_semantic_proof_oracle(oracle, state)
        marker = str(
            hints.get("marker")
            or expected.get("marker")
            or expected.get("sink_output_contains")
            or _nested(hints, "input", "marker")
            or _nested(hints, "proposed_inputs", "marker")
            or ""
        )
        oracle = {"kind": key}
        if marker:
            oracle["marker"] = marker
        if key == "bounded_write_overflow":
            oracle.setdefault("observe_memory_write", True)
            if state.location.get("address"):
                oracle.setdefault("sink_call_address", str(state.location.get("address")))
        return _normalize_semantic_proof_oracle(oracle, state)
    return None


def _normalize_semantic_proof_oracle(oracle: Mapping[str, Any], state: CandidateState) -> dict[str, Any]:
    normalized = dict(oracle)
    kind = str(normalized.get("kind") or normalized.get("type") or "")
    if _is_semantic_memory_corruption_oracle_kind(kind):
        normalized["kind"] = "bounded_write_overflow"
        normalized.setdefault("observe_memory_write", True)
    if normalized.get("kind") in SEMANTIC_PROCESS_ORACLE_KINDS:
        normalized.setdefault("syscall_observation", True)
        normalized.setdefault("vulnerability_type", state.vulnerability_type)
        normalized.setdefault("sink", str(state.sink.get("name") or ""))
        normalized.setdefault("source_expression", str(state.source.get("expression") or ""))
        normalized.setdefault("source_kind", str(state.source.get("kind") or ""))
    if normalized.get("kind") == "format_string_effect":
        normalized["syscall_observation"] = False
        normalized.setdefault("format_directive", "%x")
        normalized.setdefault("marker", _default_format_string_probe(state))
    if normalized.get("kind") == "bounded_write_overflow" and state.location.get("address"):
        normalized.setdefault("sink_call_address", str(state.location.get("address")))
        normalized.setdefault("observe_memory_write", True)
    return normalized


def _is_semantic_memory_corruption_oracle_kind(kind: str) -> bool:
    normalized = str(kind or "").strip().lower()
    return normalized in {
        "fs_config_memory_corruption",
        "fs_config_memory_corruption_oracle",
        "memory_corruption",
        "memory_corruption_oracle",
    } or normalized.endswith("_memory_corruption_oracle")


def _default_semantic_oracle(state: CandidateState, hints: Mapping[str, Any]) -> dict[str, Any]:
    marker = str(
        hints.get("marker")
        or _nested(hints, "expected_result", "marker")
        or _nested(hints, "expected_sink", "marker")
        or f"semantic_seed_{state.candidate_id[:8]}"
    )
    if state.vulnerability_type == "command_injection":
        return {"kind": "command_effect", "marker": marker, "syscall_observation": True}
    if state.vulnerability_type == "path_traversal":
        return {"kind": "filesystem_read_escape", "marker": marker, "syscall_observation": True}
    if state.vulnerability_type == "unsafe_file_write":
        return {"kind": "filesystem_write_escape", "marker": marker, "syscall_observation": True}
    if state.vulnerability_type == "format_string":
        return {
            "kind": "format_string_effect",
            "marker": _default_format_string_probe(state),
            "format_directive": "%x",
            "syscall_observation": False,
        }
    if state.vulnerability_type in {"credential_disclosure", "hardcoded_credential"}:
        return {"kind": "credential_disclosure", "marker": marker, "syscall_observation": False}
    if state.vulnerability_type == "auth_bypass":
        return {"kind": "auth_bypass_effect", "marker": marker, "syscall_observation": False}
    return {}


def _default_format_string_probe(state: CandidateState) -> str:
    digest = hashlib.sha256(state.candidate_id.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"BINARY_AGENT_FMT_{digest}_%x_END"


def _format_string_probe(oracle: Mapping[str, Any], state: CandidateState) -> str:
    marker = str(oracle.get("marker") or "")
    directive = str(oracle.get("format_directive") or "%x")
    if directive and directive in marker:
        return marker
    return _default_format_string_probe(state)


def _attach_derived_oracle_if_available(
    request: ReplayRequest,
    state: CandidateState | None,
    evidence_pack: Mapping[str, Any],
    *,
    states: Sequence[CandidateState] = (),
    block_on_missing: bool = True,
) -> ReplayRequest:
    if state is None:
        return request
    if request.mode != "qemu_user":
        return request
    if state.vulnerability_type == "uninitialized_memory_use":
        expected = dict(request.expected_result)
        expected["target_address"] = str(
            state.operation.get("address")
            or state.sink.get("operation_address")
            or state.location.get("operation_address")
            or ""
        )
        expected["qemu_observation_scope"] = "exact_reach_only_no_definedness_claim"
        return ReplayRequest(
            request.candidate_id,
            request.mode,
            dict(request.setup),
            dict(request.input),
            expected,
        )
    oracle = derive_proof_oracle(
        state,
        evidence_pack,
        binary_path=request.setup.get("binary_path"),
        callsite_rank=_callsite_rank(states, state),
    )
    if not oracle:
        return request
    setup = dict(request.setup)
    expected = dict(request.expected_result)
    if oracle.get("blocked"):
        if not block_on_missing:
            return request
        setup["blocked_reason"] = oracle.get("blocked_reason", "proof_oracle_blocked")
        expected["proof_oracle_blocked"] = oracle
        return ReplayRequest(request.candidate_id, "off", setup, dict(request.input), expected)
    existing_oracle = expected.get("proof_oracle")
    if isinstance(existing_oracle, Mapping):
        expected["proof_oracle"] = _merge_proof_oracles(existing_oracle, oracle)
    else:
        expected["proof_oracle"] = oracle
    return ReplayRequest(request.candidate_id, request.mode, setup, dict(request.input), expected)


def _merge_proof_oracles(existing: Mapping[str, Any], derived: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    existing_kind = str(existing.get("kind") or existing.get("type") or "")
    for key, value in derived.items():
        if value in (None, "", []):
            continue
        if key == "kind" and _is_semantic_memory_corruption_oracle_kind(existing_kind):
            merged[key] = value
            continue
        if key.endswith("_address") or key in {
            "allowed_proof_addresses",
            "destination_kind",
            "target_buffer",
            "observe_memory_write",
            "sink_pointer_register",
            "sink_bound_register",
            "allocation_size_register",
            "allocation_pointer_register",
        }:
            merged[key] = value
        else:
            merged.setdefault(key, value)
    return merged


def _load_evidence_by_id(evidence_dir: Path | None) -> dict[str, Mapping[str, Any]]:
    if evidence_dir is None or not Path(evidence_dir).exists():
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for path, pack in iter_evidence_packs(Path(evidence_dir)):
        candidate_id = _candidate_id_from_evidence(pack) or path.stem
        result[candidate_id] = pack
    return result


def _candidate_id_from_evidence(pack: Mapping[str, Any]) -> str:
    candidate = pack.get("candidate")
    if isinstance(candidate, Mapping) and candidate.get("candidate_id"):
        return str(candidate["candidate_id"])
    legacy = pack.get("deterministic_candidate")
    if isinstance(legacy, Mapping) and legacy.get("candidate_id"):
        return str(legacy["candidate_id"])
    return str(pack.get("candidate_id") or "")


def _state_by_id(states: Sequence[CandidateState], candidate_id: str) -> CandidateState | None:
    for state in states:
        if state.candidate_id == candidate_id:
            return state
    return None


def _state_binary_path(states: Sequence[CandidateState], candidate_id: str) -> Path | None:
    state = _state_by_id(states, candidate_id)
    if state is None:
        return None
    path = str(state.target.get("path") or "")
    return Path(path) if path else None


def _callsite_rank(states: Sequence[CandidateState], state: CandidateState | None) -> int:
    if state is None:
        return 1
    function_name = str(state.location.get("function_name") or "")
    sink_name = str(state.sink.get("name") or "")
    line_number = _first_int(state.location.get("line_number"))
    if not function_name or not sink_name or line_number is None:
        return 1
    earlier_lines = {
        int(other_line)
        for other in states
        if str(other.location.get("function_name") or "") == function_name
        and str(other.sink.get("name") or "") == sink_name
        for other_line in [_first_int(other.location.get("line_number"))]
        if other_line is not None and int(other_line) < int(line_number)
    }
    return max(1, len(earlier_lines) + 1)


def _derive_disassembly_oracle_facts(
    binary_path: Path | str | None,
    *,
    function_address: Any,
    sink_name: Any,
    destination_kind: str,
    callsite_rank: int,
) -> dict[str, str]:
    path = Path(str(binary_path or ""))
    function_start = _normalize_address(function_address)
    sink = str(sink_name or "")
    if not path.exists() or not function_start or not sink:
        return {}
    text = _disassemble_function_window(path, function_start)
    calls = _parse_disassembly_calls(text)
    if not calls:
        return {}
    sink_calls = [call for call in calls if _call_target_matches(call["target"], sink)]
    if not sink_calls:
        return {}
    index = min(max(callsite_rank, 1), len(sink_calls)) - 1
    sink_call = sink_calls[index]
    facts = {
        "sink_call_address": sink_call["address"],
        "sink_return_address": _next_address(sink_call["address"]),
    }
    if destination_kind != "stack":
        alloc_calls = [call for call in calls if _is_allocation_call(call["target"]) and _address_less(call["address"], sink_call["address"])]
        if alloc_calls:
            alloc_call = alloc_calls[-1]
            facts["allocation_call_address"] = alloc_call["address"]
            facts["allocation_return_address"] = _next_address(alloc_call["address"])
    return facts


def _disassemble_function_window(binary_path: Path, function_start: str) -> str:
    tool = _resolve_objdump()
    if not tool:
        return ""
    start = int(function_start, 16)
    stop = start + 0x1000
    key = (str(binary_path), function_start, tool)
    cached = _DISASSEMBLY_CACHE.get(key)
    if cached is not None:
        return cached
    command = [
        tool,
        "-d",
        f"--start-address=0x{start:x}",
        f"--stop-address=0x{stop:x}",
        str(binary_path),
    ]
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5.0, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    text = completed.stdout if completed.returncode == 0 else ""
    _DISASSEMBLY_CACHE[key] = text
    return text


def _resolve_objdump() -> str:
    configured = os.getenv("OBJDUMP") or ""
    for name in (
        configured,
        "arm-none-eabi-objdump",
        "arm-linux-gnueabi-objdump",
        "arm-linux-gnueabihf-objdump",
        "objdump",
    ):
        if not name:
            continue
        resolved = shutil.which(name)
        if resolved:
            return resolved
    return ""


def _parse_disassembly_calls(text: str) -> list[dict[str, str]]:
    calls: list[dict[str, str]] = []
    pattern = re.compile(r"^\s*([0-9a-fA-F]+):\s+[0-9a-fA-F]+\s+\b(?:bl|blx)\b\s+[^<]*(?:<([^>]+)>)?")
    for line in text.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        target = match.group(2) or line.rsplit(None, 1)[-1]
        calls.append({"address": _normalize_address("0x" + match.group(1)), "target": target})
    return calls


def _call_target_matches(target: str, sink_name: str) -> bool:
    target_text = _demangled_target_name(target)
    sink = str(sink_name or "").lower()
    return bool(sink and sink in target_text)


def _is_allocation_call(target: str) -> bool:
    target_text = _demangled_target_name(target)
    return any(token in target_text for token in ("_znwj", "_znaj", "operator new", "malloc", "calloc", "realloc", "strdup", "strndup"))


def _demangled_target_name(target: str) -> str:
    return str(target or "").split("@", 1)[0].lower()


def _address_less(left: str, right: str) -> bool:
    try:
        return int(_normalize_address(left), 16) < int(_normalize_address(right), 16)
    except ValueError:
        return False


def _artifact_mapping(artifact: HypothesisArtifact | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(artifact, HypothesisArtifact):
        return artifact.to_dict()
    return dict(artifact)


def _validator(artifact: Mapping[str, Any]) -> Mapping[str, Any]:
    validator = artifact.get("validator_result")
    return validator if isinstance(validator, Mapping) else {}


def _write_skipped(candidate_dir: Path, index: int, entry: ReplayPlanEntry, reason: str) -> Path:
    candidate_dir.mkdir(parents=True, exist_ok=True)
    path = candidate_dir / f"skipped_{index:03d}.json"
    payload = {
        "candidate_id": entry.candidate_id,
        "result": ReplayStatus.NOT_ATTEMPTED.value,
        "reason": reason,
        "provenance": entry.provenance,
        "request": entry.request.to_dict(),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


def _proof_facts(evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for source in (evidence_pack, _mapping(evidence_pack.get("facts_available_to_llm"))):
        facts = source.get("proof_oracle_facts")
        if isinstance(facts, Mapping):
            result.update(facts)
        for key in ("allocation_facts", "capacity_facts", "dynamic_proof_facts"):
            value = source.get(key)
            if isinstance(value, Mapping):
                result.update(value)
    return result


def _allowed_proof_addresses(
    candidate: Mapping[str, Any],
    evidence_pack: Mapping[str, Any],
    derived_addresses: Sequence[Any],
) -> set[str]:
    addresses = {_normalize_address(item) for item in derived_addresses if _normalize_address(item)}
    for source in (evidence_pack, _mapping(evidence_pack.get("facts_available_to_llm"))):
        for key in ("allowed_proof_addresses", "proof_allowed_addresses"):
            for item in _coerce_sequence(source.get(key, [])):
                address = _normalize_address(item)
                if address:
                    addresses.add(address)
        facts = source.get("proof_oracle_facts")
        if isinstance(facts, Mapping):
            addresses.update(_collect_address_values(facts))
    facts = _mapping(candidate.get("type_facts"))
    addresses.update(_collect_address_values(facts))
    return {address for address in addresses if address}


def _collect_address_values(value: Any) -> set[str]:
    addresses: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            if key_text.endswith("_address") or key_text in {"address", "call_address", "return_address"}:
                address = _normalize_address(item)
                if address:
                    addresses.add(address)
            elif isinstance(item, (Mapping, list, tuple)):
                addresses.update(_collect_address_values(item))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            addresses.update(_collect_address_values(item))
    return addresses


def _nested(mapping: Mapping[str, Any], *keys: str) -> Any:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _first_int(*values: Any) -> int | None:
    for value in values:
        if value in (None, ""):
            continue
        try:
            return int(value, 0) if isinstance(value, str) else int(value)
        except (TypeError, ValueError):
            continue
    return None


def _first_address(*values: Any) -> str:
    for value in values:
        address = _normalize_address(value)
        if address:
            return address
    return ""


def _normalize_address(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, int):
        return f"0x{value:x}" if value >= 0 else ""
    text = str(value).strip().lower()
    if not text:
        return ""
    try:
        parsed = int(text, 16 if text.startswith("0x") else 10)
    except ValueError:
        return ""
    return f"0x{parsed:x}" if parsed >= 0 else ""


def _next_address(value: Any, increment: int = 4) -> str:
    address = _normalize_address(value)
    if not address:
        return ""
    return f"0x{int(address, 16) + increment:x}"


def _coerce_sequence(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray)):
        return [value]
    if isinstance(value, Sequence):
        return list(value)
    return [value]


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)[:120] or "candidate"
