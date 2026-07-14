"""Concolic verification artifacts for confirmation evidence packs.

The concolic layer is deliberately artifact-first: every backend decision is
recorded as a bounded verdict that can be converted into strict confirmation
JSON.  The first backend is optional angr support; environments without angr
still get deterministic ``backend_error`` records instead of import-time
failures.
"""

from __future__ import annotations

import ast
import ctypes
import gzip
import hashlib
import io
import json
import logging
import multiprocessing
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
import zlib
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from binary_agent.analysis.concolic_models import (
    AddressTranslation,
    ConcolicRequest,
    ConcolicRunResult,
    ConcolicToolConfig,
    CrashWitness,
    GhidraDynamicProofRequest,
    PcodeTraceRequest,
)
from binary_agent.analysis.witness import build_witness_plan
from binary_agent.dynamic_proof import DYNAMIC_MEMORY_PROOF_STATUSES, DynamicProofView
from binary_agent.sink_sites import sink_site_identity
from binary_agent.taxonomy import get_vulnerability_spec


CONCOLIC_VERDICTS = {
    "crash_reproduced",
    "overflow_witness",
    "memory_violation_witness",
    "target_reached",
    "path_unsat",
    "guard_refuted",
    "timeout",
    "backend_error",
}
REPORTABLE_CONCOLIC_VERDICTS = {"crash_reproduced", "overflow_witness", "memory_violation_witness"}
SAFE_CONCOLIC_VERDICTS = {"path_unsat", "guard_refuted"}
SUPPORTED_CONCOLIC_BACKENDS = {"angr", "deterministic_seed"}
PROCESS_DYNAMIC_INPUT_MODELS = {
    "argv",
    "stdin",
    "file",
    "env",
    "env_file",
    "argv_file_stdin",
    "argv_directory",
    "socket_service",
    "http_daemon",
}
UNSUPPORTED_PROCESS_INPUT_MODELS = {"network", "socket", "http", "ipc", "config", "device", "daemon"}
KNOWN_PROCESS_INPUT_MODELS = PROCESS_DYNAMIC_INPUT_MODELS | UNSUPPORTED_PROCESS_INPUT_MODELS
SUPPORTED_INPUT_MODELS = KNOWN_PROCESS_INPUT_MODELS | {"function_harness"}
CONCOLIC_INPUT_MODEL_ALIASES = {
    "line_file": "file",
    "text_record": "stdin",
    "archive": "file",
    "archive_text_record": "file",
}
CONCOLIC_RUN_SUMMARY = "_concolic_run_summary.json"
CONCOLIC_TOOL_NAME = "run_concolic_poc"
CONCOLIC_VERDICT_FILENAME = "verdict.json"
CONCOLIC_REQUEST_FILENAME = "request.json"
CONCOLIC_ANGR_TRACE_FILENAME = "angr_trace.json"
CONCOLIC_PCODE_TRACE_FILENAME = "pcode_trace.json"
CONCOLIC_PCODE_UNSUPPORTED_FILENAME = "pcode_trace_unsupported.json"
CONCOLIC_DYNAMIC_PROOF_FILENAME = "ghidra_dynamic_proof.json"
CONCOLIC_DYNAMIC_PROOF_UNSUPPORTED_FILENAME = "ghidra_dynamic_proof_unsupported.json"
CONCOLIC_PROCESS_WITNESS_ATTEMPT_FILENAME = "process_witness_attempt.json"
CONCOLIC_LLM_ACTIONS_FILENAME = "llm_actions.json"
CONCOLIC_REPLAY_FILENAME = "replay.json"
CONCOLIC_ARTIFACT_FILENAMES = {
    CONCOLIC_VERDICT_FILENAME,
    CONCOLIC_REQUEST_FILENAME,
    CONCOLIC_ANGR_TRACE_FILENAME,
    CONCOLIC_PCODE_TRACE_FILENAME,
    CONCOLIC_PCODE_UNSUPPORTED_FILENAME,
    CONCOLIC_DYNAMIC_PROOF_FILENAME,
    CONCOLIC_DYNAMIC_PROOF_UNSUPPORTED_FILENAME,
    CONCOLIC_PROCESS_WITNESS_ATTEMPT_FILENAME,
    CONCOLIC_LLM_ACTIONS_FILENAME,
    CONCOLIC_REPLAY_FILENAME,
}
CONCOLIC_DYNAMIC_PROOF_STATUSES = {
    "overflow_proven",
    "heap_overflow_proven",
    "oob_write_proven",
    "oob_read_proven",
    "lifetime_violation_proven",
    "no_overflow",
    "no_oob_read",
    "no_lifetime_violation",
    "sink_unreached",
    "unsupported",
    "backend_error",
}
TARGET_SELECTORS = {
    "",
    "all",
    "direct_stack_overflow",
    "direct_heap_overflow",
    "direct_memory_overflow",
    "proof_ready_memory",
}
ISOLATED_WORKER_GRACE_SECONDS = 1.0
ISOLATED_WORKER_POLL_SECONDS = 0.05
ISOLATED_BACKEND_SETUP_GRACE_SECONDS = 30.0
GHIDRA_SUBPROCESS_STARTUP_GRACE_SECONDS = 30.0
GHIDRA_SUBPROCESS_MIN_TIMEOUT_SECONDS = 45.0
MAX_DYNAMIC_PROOF_ATTEMPTS = 4
MAX_NATIVE_REPLAY_SECONDS = 10.0
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]+$|^[0-9]+$")
_DAT_TOKEN_RE = re.compile(r"\b(?:DAT|PTR|PTR_s|PTR_DAT|s_[A-Za-z0-9_.$]+)_0*([0-9a-fA-F]{4,})\b")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CANDIDATE_ID_FIELDS = (
    "binary",
    "function_address",
    "function_name",
    "line_number",
    "sink",
    "target_buffer",
    "offset_expr",
    "write_relation",
)
_FUNCTION_HARNESS_INPUT_ADDRESS = 0x71000000


class _AngrExplorationDeadline(BaseException):
    """Interrupt one symbolic step that exceeds the exploration wall budget."""






def derive_waypoint_addresses(
    executed_addresses: Sequence[object],
    static_call_path_addresses: Sequence[object],
    *,
    process_entry_address: object = "",
    sink_address: object = "",
    limit: int = 8,
) -> tuple[str, ...]:
    """Return ordered, concretely executed addresses also present on the static path."""

    allowed = {_normalize_address(item) for item in static_call_path_addresses if _normalize_address(item)}
    excluded = {_normalize_address(process_entry_address), _normalize_address(sink_address), ""}
    result: list[str] = []
    for item in executed_addresses:
        address = _normalize_address(item)
        if address in excluded or address not in allowed or address in result:
            continue
        result.append(address)
        if len(result) >= max(0, min(int(limit), 8)):
            break
    return tuple(result)


def compare_waypoint_guidance(
    request: ConcolicRequest,
    evidence_pack: Mapping[str, Any],
    waypoint_addresses: Sequence[str],
) -> dict[str, Any]:
    """Run the same bounded symbolic request with and without checkpoints.

    This is deliberately a measurement helper, not a proof shortcut.  Both
    requests use the caller's timeout and all ordinary concrete/exact-sink
    promotion gates still run after either backend verdict.  Keeping the two
    request payloads in the artifact makes a later comparison reproducible.
    """

    normalized = tuple(_normalize_address(item) for item in waypoint_addresses if _normalize_address(item))
    if not normalized:
        raise ValueError("Waypoint guidance comparison requires at least one waypoint address")
    if len(normalized) > 8:
        raise ValueError("Waypoint guidance comparison accepts at most eight waypoint addresses")
    if len(set(normalized)) != len(normalized):
        raise ValueError("Waypoint guidance comparison requires unique waypoint addresses")

    # An explicit empty tuple prevents the baseline from inheriting an alias
    # supplied by a caller that is measuring a newer tuple-based request.
    unguided_request = replace(request, waypoint_addresses=(), extra_branch_goal="")
    guided_request = replace(request, waypoint_addresses=normalized, extra_branch_goal="")
    unguided = _run_angr_backend(unguided_request, evidence_pack)
    guided = _run_angr_backend(guided_request, evidence_pack)
    return {
        "schema_version": 1,
        "comparison_kind": "guided_vs_unguided_angr",
        "timeout_seconds": request.timeout_seconds,
        "waypoint_addresses": list(normalized),
        "unguided": _waypoint_comparison_result(unguided),
        "guided": _waypoint_comparison_result(guided),
        "proof_requirements": {
            "concrete_replay_required": True,
            "exact_sink_proof_required": True,
            "guidance_is_exploration_only": True,
        },
    }


def _waypoint_comparison_result(verdict: ConcolicVerdict) -> dict[str, Any]:
    trace = verdict.angr_trace if isinstance(verdict.angr_trace, Mapping) else {}
    metrics = trace.get("exploration_metrics") if isinstance(trace.get("exploration_metrics"), Mapping) else {}
    return {
        "verdict": verdict.verdict,
        "elapsed_seconds": verdict.elapsed_seconds,
        "target_reached": bool(verdict.target_address_reached),
        "sink_reached": bool(verdict.sink_address_reached),
        "simgr_steps": _safe_int(metrics.get("simgr_steps")),
        "peak_active_states": _safe_int(metrics.get("peak_active_states")),
        "peak_total_states": _safe_int(metrics.get("peak_total_states")),
        "reached_waypoint_count": _safe_int(metrics.get("reached_waypoint_count")),
        "stash_counts": dict(trace.get("stash_counts") or {}) if isinstance(trace.get("stash_counts"), Mapping) else {},
    }


def _request_with_trace_waypoints(
    request: ConcolicRequest,
    evidence_pack: Mapping[str, Any],
    proof: Mapping[str, Any],
) -> ConcolicRequest:
    if request.waypoint_addresses or request.extra_branch_goal:
        return request
    replay = proof.get("process_replay") if isinstance(proof.get("process_replay"), Mapping) else {}
    if not _should_derive_trace_waypoints(proof, replay):
        return request
    executed: list[object] = []
    for container in (proof, replay):
        for key in ("executed_addresses", "reached_addresses", "visited_addresses", "reached_blocks"):
            executed.extend(_coerce_sequence(container.get(key, [])))
    for instruction in _coerce_sequence(replay.get("instructions", [])):
        if isinstance(instruction, Mapping):
            executed.append(instruction.get("address"))
    executed.extend(_coerce_sequence(replay.get("static_path_hits", [])))
    entrypoint = _derived_process_entrypoint(evidence_pack, request)
    static_addresses = _static_candidate_path_addresses(evidence_pack, request, entrypoint=entrypoint)
    if not static_addresses:
        return request
    waypoints = derive_waypoint_addresses(
        executed,
        static_addresses,
        process_entry_address=str(entrypoint.get("entry_address") or "") if isinstance(entrypoint, Mapping) else "",
        sink_address=request.sink_address or request.target_address,
    )
    if not waypoints:
        return request
    return replace(
        request,
        waypoint_addresses=waypoints,
        target_resolution={
            **dict(request.target_resolution),
            "trace_guidance": {
                "source": "seeded_ghidra_process_replay",
                "static_path_addresses": list(static_addresses),
                "executed_address_count": len(executed),
                "waypoint_addresses": list(waypoints),
                "instructions_truncated": _safe_int(replay.get("instructions_truncated"), default=0),
            },
        },
    )


def _should_derive_trace_waypoints(proof: Mapping[str, Any], replay: Mapping[str, Any]) -> bool:
    if str(proof.get("proof_scope") or "") != "process_entrypoint":
        return False
    if bool(proof.get("exact_sink_reached")) or bool(replay.get("reached_target")):
        return False
    status = str(replay.get("status") or "").lower()
    return status in {"timeout", "step_limit", "stopped", "interrupted"}


def _static_candidate_path_addresses(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
    *,
    entrypoint: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    """Recover a verified sequence of function entries and direct callsites."""

    if request.export_dir is None:
        return ()
    export = _load_semantic_export(request.export_dir)
    path = [str(item) for item in _coerce_sequence((entrypoint or {}).get("call_path", [])) if str(item)]
    candidate = _candidate(evidence_pack)
    target_name = str(candidate.get("function_name") or candidate.get("name") or "")
    if not path and target_name:
        path = [target_name]
    nodes = [_static_path_node(export, item) for item in path]
    if not path or any(node is None for node in nodes):
        return ()
    addresses: list[str] = []
    for index, node in enumerate(nodes):
        if node is None:  # Narrowing for type checkers; guarded above.
            return ()
        entry_address = _normalize_address(node.record.address)
        if not entry_address:
            return ()
        addresses.append(entry_address)
        if index + 1 >= len(path):
            continue
        next_node = nodes[index + 1]
        if next_node is None:
            return ()
        next_address = _normalize_address(next_node.record.address)
        matches = [
            call
            for call in _coerce_sequence(node.record.pcode_calls or [])
            if isinstance(call, Mapping)
            and (
                _normalize_address(call.get("callee_address")) == next_address
                or str(call.get("callee") or "") == str(next_node.record.name)
            )
            and str(call.get("target_kind") or "").lower() not in {"indirect", "callind"}
            and _normalize_address(call.get("call_address"))
        ]
        if len(matches) != 1:
            return ()
        addresses.append(_normalize_address(matches[0].get("call_address")))
    sink = _normalize_address(request.sink_address or request.target_address)
    if sink:
        addresses.append(sink)
    return tuple(_unique_strings(addresses))


def _static_path_node(export: Mapping[str, Any], name_or_address: str) -> Any | None:
    """Resolve one static route element only when it identifies one function."""

    value = str(name_or_address or "")
    address = _normalize_address(value)
    if address:
        by_address = export.get("by_address") if isinstance(export.get("by_address"), Mapping) else {}
        return by_address.get(address)
    nodes = [
        node
        for node in _coerce_sequence(export.get("nodes", []))
        if getattr(getattr(node, "record", None), "name", "") == value
    ]
    return nodes[0] if len(nodes) == 1 else None


@dataclass(frozen=True)
class ConcolicVerdict:
    """Backend decision for one concolic request."""

    candidate_id: str
    verdict: str
    backend: str = "angr"
    request: Mapping[str, Any] = field(default_factory=dict)
    witness: CrashWitness | None = None
    artifact_paths: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    angr_trace: Mapping[str, Any] = field(default_factory=dict)
    pcode_trace: Mapping[str, Any] = field(default_factory=dict)
    ghidra_dynamic_proof: Mapping[str, Any] = field(default_factory=dict)
    replay_result: Mapping[str, Any] = field(default_factory=dict)
    llm_actions: Mapping[str, Any] = field(default_factory=dict)
    rationale: str = ""
    reached_addresses: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    logs: tuple[str, ...] = ()
    elapsed_seconds: float = 0.0

    @property
    def reportable(self) -> bool:
        return (
            self.verdict in REPORTABLE_CONCOLIC_VERDICTS
            and _has_dynamic_memory_safety_proof(self.ghidra_dynamic_proof)
            and _has_dynamic_proof_artifact(self.artifact_paths)
        )

    @property
    def diagnostic(self) -> dict[str, Any]:
        """Explain where this attempt stopped without changing its verdict."""

        return _concolic_diagnostic(self)

    def to_dict(self) -> dict[str, Any]:
        if self.verdict not in CONCOLIC_VERDICTS:
            raise ValueError(f"Invalid concolic verdict: {self.verdict!r}")
        sink_reached = bool(self.sink_address_reached)
        target_address_reached = bool(self.target_address_reached)
        input_generated = self.witness is not None and (
            self.witness.stdin is not None
            or bool(self.witness.argv)
            or bool(self.witness.file_inputs)
            or bool(self.witness.env)
            or bool(self.witness.function_args)
        )
        timeout = self.verdict == "timeout"
        return {
            "candidate_id": self.candidate_id,
            "concolic_verdict": self.verdict,
            "backend": self.backend,
            "concolic_ran": True,
            "target_address_reached": target_address_reached,
            "sink_reached": sink_reached,
            "input_generated": input_generated,
            "iterations": _concolic_iteration_count(self),
            "timeout": timeout,
            "artifact_refs": list(self.artifact_paths),
            "request": dict(self.request),
            "witness": self.witness.to_dict() if self.witness is not None else {},
            "artifact_paths": list(self.artifact_paths),
            "evidence_refs": list(self.evidence_refs),
            "angr_trace": dict(self.angr_trace),
            "pcode_trace": dict(self.pcode_trace),
            "ghidra_dynamic_proof": dict(self.ghidra_dynamic_proof),
            "replay_result": dict(self.replay_result),
            "llm_actions": dict(self.llm_actions),
            "rationale": self.rationale,
            "reached_addresses": list(self.reached_addresses),
            "errors": list(self.errors),
            "logs": list(self.logs),
            "elapsed_seconds": self.elapsed_seconds,
            "diagnostic": self.diagnostic,
        }

    @property
    def target_address_reached(self) -> bool:
        target = str(self.request.get("target_address") or "")
        return bool(target and target in set(self.reached_addresses))

    @property
    def sink_address_reached(self) -> bool:
        sink = str(self.request.get("sink_address") or "")
        if sink and sink in set(self.reached_addresses):
            return True
        proof_status = str(self.ghidra_dynamic_proof.get("status") or "")
        return proof_status in DYNAMIC_MEMORY_PROOF_STATUSES or self.verdict in REPORTABLE_CONCOLIC_VERDICTS

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ConcolicVerdict":
        verdict = str(data.get("concolic_verdict") or data.get("verdict") or "").strip()
        if verdict not in CONCOLIC_VERDICTS:
            raise ValueError(f"Invalid concolic verdict: {verdict!r}")
        witness_data = data.get("witness")
        return cls(
            candidate_id=str(data.get("candidate_id") or ""),
            verdict=verdict,
            backend=str(data.get("backend") or "angr"),
            request=dict(data.get("request") or {}) if isinstance(data.get("request"), Mapping) else {},
            witness=CrashWitness.from_dict(witness_data) if isinstance(witness_data, Mapping) and witness_data else None,
            artifact_paths=tuple(str(item) for item in _coerce_sequence(data.get("artifact_paths", []))),
            evidence_refs=tuple(str(item) for item in _coerce_sequence(data.get("evidence_refs", []))),
            angr_trace=dict(data.get("angr_trace") or {}) if isinstance(data.get("angr_trace"), Mapping) else {},
            pcode_trace=dict(data.get("pcode_trace") or {}) if isinstance(data.get("pcode_trace"), Mapping) else {},
            ghidra_dynamic_proof=dict(data.get("ghidra_dynamic_proof") or {})
            if isinstance(data.get("ghidra_dynamic_proof"), Mapping)
            else {},
            replay_result=dict(data.get("replay_result") or {}) if isinstance(data.get("replay_result"), Mapping) else {},
            llm_actions=dict(data.get("llm_actions") or {}) if isinstance(data.get("llm_actions"), Mapping) else {},
            rationale=str(data.get("rationale") or ""),
            reached_addresses=tuple(str(item) for item in _coerce_sequence(data.get("reached_addresses", []))),
            errors=tuple(str(item) for item in _coerce_sequence(data.get("errors", []))),
            logs=tuple(str(item) for item in _coerce_sequence(data.get("logs", []))),
            elapsed_seconds=float(data.get("elapsed_seconds") or 0.0),
        )






def _concolic_diagnostic(verdict: ConcolicVerdict) -> dict[str, Any]:
    trace = verdict.angr_trace if isinstance(verdict.angr_trace, Mapping) else {}
    stashes = trace.get("stash_counts") if isinstance(trace.get("stash_counts"), Mapping) else {}
    constraints = trace.get("constraints_summary") if isinstance(trace.get("constraints_summary"), Mapping) else {}
    dynamic = verdict.ghidra_dynamic_proof if isinstance(verdict.ghidra_dynamic_proof, Mapping) else {}
    replay = verdict.replay_result if isinstance(verdict.replay_result, Mapping) else {}
    concrete_replay = replay.get("concrete_angr_replay") if isinstance(replay.get("concrete_angr_replay"), Mapping) else {}
    rationale = str(verdict.rationale or "")
    errors = [str(item) for item in verdict.errors]
    text = " ".join([rationale, *errors]).lower()
    target_reached = verdict.target_address_reached or str(trace.get("status") or "") == "target_reached"

    if verdict.reportable:
        stage, reason = "complete", "memory_violation_proven"
    elif verdict.verdict == "guard_refuted":
        stage, reason = "complete", "guard_refuted"
    elif verdict.verdict == "backend_error":
        if "memory_limit" in text or "memoryerror" in text or "out of memory" in text:
            stage, reason = "resource", "memory_limit"
        elif str(trace.get("status") or "") == "execution_error":
            stage, reason = "exploration", "errored_before_target"
        elif "input_model" in text or "input setup" in text or "process_input" in text:
            stage, reason = "input_setup", "unsupported_input_model"
        elif "missing target" in text or "missing_target" in text or "target_address" in text:
            stage, reason = "target_resolution", "target_unresolved"
        else:
            stage, reason = "backend_setup", "backend_error"
    elif verdict.verdict == "path_unsat":
        if int(constraints.get("count") or 0) == 0:
            stage, reason = "input_model", "symbolic_input_not_connected"
        else:
            stage, reason = "reachability", "path_exhausted"
    elif verdict.verdict == "timeout":
        if "guided_checkpoint_unreached" in text:
            stage, reason = "exploration", "guided_checkpoint_unreached"
        elif "isolated_worker_timeout" in text:
            stage, reason = "exploration", "wall_timeout"
        elif str(trace.get("status") or "") == "trivial_function_harness_entry":
            stage, reason = "target_resolution", "target_equals_harness_entry"
        elif "replay" in text or str(concrete_replay.get("status") or "") in {"timeout", "unsupported"}:
            stage, reason = "replay", "concrete_replay_mismatch"
        elif target_reached:
            stage, reason = "violation_check", "target_reached_without_violation"
        elif int(stashes.get("errored") or 0) or int(stashes.get("unconstrained") or 0):
            stage, reason = "exploration", "errored_before_target"
        else:
            stage, reason = "exploration", "wall_timeout"
    elif verdict.verdict == "target_reached":
        stage, reason = "violation_check", "target_reached_without_violation"
    elif verdict.verdict in {"overflow_witness", "memory_violation_witness", "crash_reproduced"}:
        stage, reason = "replay", "dynamic_proof_incomplete"
    else:
        stage, reason = "unknown", "unclassified"

    return {
        "schema_version": 1,
        "stage": stage,
        "reason": reason,
        "progress": {
            "input_model": str(verdict.request.get("input_model") or ""),
            "target_reached": bool(target_reached),
            "sink_reached": bool(verdict.sink_address_reached),
            "constraint_count": int(constraints.get("count") or 0),
            "active_states": int(stashes.get("active") or 0),
            "deadended_states": int(stashes.get("deadended") or 0),
            "errored_states": int(stashes.get("errored") or 0),
            "unconstrained_states": int(stashes.get("unconstrained") or 0),
            "dynamic_proof_status": str(dynamic.get("status") or ""),
            "dynamic_proof_reason": str(dynamic.get("reason") or ""),
            "concrete_replay_status": str(concrete_replay.get("status") or ""),
        },
    }








@dataclass(frozen=True)
class _StringBound:
    length: int | None = None
    source: str = ""
    expr: str = ""

    @property
    def known(self) -> bool:
        return self.length is not None and self.length >= 0


@dataclass(frozen=True)
class _CallsiteContext:
    caller_function: str
    relative_path: str
    line_number: int
    line_text: str
    args: tuple[str, ...]
    assignments: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "caller_function": self.caller_function,
            "relative_path": self.relative_path,
            "line_number": self.line_number,
            "line_text": self.line_text,
            "args": list(self.args),
        }


def build_concolic_request(
    evidence_pack: Mapping[str, Any],
    *,
    binary_path: Path,
    export_dir: Path | None = None,
    backend: str = "angr",
    target_address: str = "",
    sink_address: str = "",
    input_model: str = "",
    symbolic_bytes: int = 256,
    constraints: Sequence[str] = (),
    timeout_seconds: float = 30.0,
    extra_branch_goal: str = "",
    waypoint_addresses: Sequence[str] = (),
    allowed_stubs: Sequence[str] = (),
    seed_mutations: Sequence[str] = (),
    max_symbolic_bytes: int = 4096,
) -> ConcolicRequest:
    """Build and validate a request from an evidence pack and bounded options."""

    resolved_export_dir = Path(export_dir) if export_dir is not None else None
    candidate_id = _candidate_id_from_pack(evidence_pack)
    candidate = _candidate_for_memory_proof(evidence_pack, export_dir=resolved_export_dir)
    target_resolution = _semantic_concolic_target_resolution(
        evidence_pack,
        binary_path=Path(binary_path),
        export_dir=resolved_export_dir,
    )
    if not target_resolution:
        target_resolution = resolve_memory_safety_target(
            evidence_pack,
            binary_path=Path(binary_path),
            export_dir=resolved_export_dir,
        )
    target_resolution = _refine_repeated_sink_target_resolution(
        evidence_pack,
        target_resolution,
        binary_path=Path(binary_path),
        export_dir=resolved_export_dir,
    )
    target_resolution = _target_resolution_with_sink_site(evidence_pack, target_resolution)
    if not input_model:
        input_model = _default_input_model(evidence_pack, target_resolution=target_resolution)
    input_model = _normalize_concolic_input_model(input_model)
    trace = _candidate_classification_trace(evidence_pack)
    replay_hints = trace.get("replay_hints") if isinstance(trace.get("replay_hints"), Mapping) else {}
    force_function_harness = str(replay_hints.get("mode") or "").lower() == "function_harness"
    if input_model == "function_harness" and not force_function_harness:
        derived_model = _derived_semantic_process_input_model(evidence_pack, target_resolution=target_resolution)
        if derived_model:
            input_model = _effective_process_input_model(evidence_pack, derived_model)
    if not target_address:
        target_address = _default_target_address(evidence_pack, target_resolution=target_resolution)
    if not sink_address:
        sink_address = str(target_resolution.get("sink_address") or candidate.get("operation_address") or target_address)
    requested_seed_mutations = [str(item) for item in seed_mutations]
    derived_seed_mutations = [
        *_file_format_seed_mutations(evidence_pack, input_model=input_model),
        *_witness_plan_seed_mutations(evidence_pack, input_model=input_model),
        *_deterministic_seed_mutations(evidence_pack, symbolic_bytes),
    ]
    if len(requested_seed_mutations) > 16:
        resolved_seed_mutations = tuple(requested_seed_mutations)
    else:
        resolved_seed_mutations = tuple(_unique_strings([*requested_seed_mutations, *derived_seed_mutations])[:16])
    request = ConcolicRequest(
        candidate_id=candidate_id,
        binary_path=Path(binary_path),
        export_dir=resolved_export_dir,
        backend=backend,
        target_address=_normalize_address(target_address),
        sink_address=_normalize_address(sink_address),
        input_model=input_model,
        symbolic_bytes=int(symbolic_bytes),
        constraints=tuple(str(item) for item in constraints),
        timeout_seconds=float(timeout_seconds),
        extra_branch_goal=_normalize_address(extra_branch_goal) if extra_branch_goal else "",
        waypoint_addresses=tuple(_normalize_address(item) for item in waypoint_addresses if item)[:8],
        allowed_stubs=tuple(str(item) for item in allowed_stubs),
        seed_mutations=resolved_seed_mutations,
        target_resolution=target_resolution,
    )
    return validate_concolic_request(
        evidence_pack,
        request,
        max_symbolic_bytes=max_symbolic_bytes,
    )


def validate_concolic_request(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
    *,
    max_symbolic_bytes: int = 4096,
) -> ConcolicRequest:
    """Validate that a backend request is bounded by the current evidence pack."""

    candidate_id = _candidate_id_from_pack(evidence_pack)
    if not candidate_id:
        raise ValueError("Evidence pack is missing candidate_id")
    if request.candidate_id != candidate_id:
        raise ValueError(f"Concolic request candidate_id {request.candidate_id!r} does not match {candidate_id!r}")
    if request.backend not in SUPPORTED_CONCOLIC_BACKENDS:
        raise ValueError(f"Unsupported concolic backend: {request.backend!r}")
    if not request.binary_path.exists() or not request.binary_path.is_file():
        raise FileNotFoundError(f"Binary path not found: {request.binary_path}")
    if request.export_dir is not None and (not request.export_dir.exists() or not request.export_dir.is_dir()):
        raise FileNotFoundError(f"Export directory not found: {request.export_dir}")
    if request.input_model not in SUPPORTED_INPUT_MODELS:
        raise ValueError(f"Unsupported input model: {request.input_model!r}")
    unresolved_entrypoint = _unresolved_semantic_function_harness_entrypoint(evidence_pack, request)
    if unresolved_entrypoint:
        raise ValueError(unresolved_entrypoint)
    unresolved_semantic_sink = _unresolved_semantic_sink_target(evidence_pack, request)
    if unresolved_semantic_sink:
        raise ValueError(unresolved_semantic_sink)
    unresolved_memory_sink = _unresolved_memory_safety_target(evidence_pack, request)
    if unresolved_memory_sink:
        raise ValueError(unresolved_memory_sink)
    if request.symbolic_bytes <= 0 or request.symbolic_bytes > max_symbolic_bytes:
        raise ValueError(
            f"symbolic_bytes must be between 1 and {max_symbolic_bytes}; got {request.symbolic_bytes}"
        )
    if request.timeout_seconds <= 0 or request.timeout_seconds > 600:
        raise ValueError(f"timeout_seconds must be between 0 and 600; got {request.timeout_seconds}")
    if not request.target_address:
        raise ValueError("Concolic request is missing target_address")
    allowed_addresses = _allowed_addresses(
        evidence_pack,
        export_dir=request.export_dir,
        target_resolution=request.target_resolution,
    )
    entrypoint = _derived_process_entrypoint(evidence_pack, request)
    static_path_addresses = _static_candidate_path_addresses(evidence_pack, request, entrypoint=entrypoint)
    allowed_addresses.update(static_path_addresses)
    for field_name, address in (("target_address", request.target_address), ("sink_address", request.sink_address)):
        if address and address not in allowed_addresses:
            allowed = ", ".join(sorted(allowed_addresses)) or "(none)"
            raise ValueError(f"{field_name} {address!r} is not present in the evidence pack; allowed: {allowed}")
    if request.extra_branch_goal:
        if not _is_address_string(request.extra_branch_goal):
            raise ValueError(f"extra_branch_goal must be an address, got {request.extra_branch_goal!r}")
        if request.extra_branch_goal not in allowed_addresses:
            allowed = ", ".join(sorted(allowed_addresses)) or "(none)"
            raise ValueError(
                f"extra_branch_goal {request.extra_branch_goal!r} is not present in the evidence pack; allowed: {allowed}"
            )
    if len(request.waypoint_addresses) > 8:
        raise ValueError("At most eight waypoint addresses may be supplied")
    if len(set(request.waypoint_addresses)) != len(request.waypoint_addresses):
        raise ValueError("Waypoint addresses must be unique")
    if request.waypoint_addresses and not static_path_addresses:
        raise ValueError("Waypoint addresses require a verified static candidate path")
    waypoint_positions = {address: index for index, address in enumerate(static_path_addresses)}
    entry_address = _normalize_address(entrypoint.get("entry_address")) if isinstance(entrypoint, Mapping) else ""
    sink_addresses = {
        _normalize_address(request.sink_address),
        _normalize_address(request.target_address),
    }
    previous_waypoint_position = -1
    for address in request.waypoint_addresses:
        if not _is_address_string(address):
            raise ValueError(f"waypoint address must be an address, got {address!r}")
        if address not in allowed_addresses:
            allowed = ", ".join(sorted(allowed_addresses)) or "(none)"
            raise ValueError(f"waypoint address {address!r} is not present in the evidence pack; allowed: {allowed}")
        if address == entry_address or address in sink_addresses:
            raise ValueError("Waypoint addresses may not be the process entrypoint or final sink")
        position = waypoint_positions.get(address)
        if position is None:
            raise ValueError("Waypoint address is not on the verified static candidate path")
        if position <= previous_waypoint_position:
            raise ValueError("Waypoint addresses must follow static candidate-path order")
        previous_waypoint_position = position
    if len(request.constraints) > 16:
        raise ValueError("At most 16 concolic constraints may be supplied")
    for constraint in request.constraints:
        if len(constraint) > 240:
            raise ValueError("Concolic constraints are limited to 240 characters each")
    if len(request.allowed_stubs) > 16:
        raise ValueError("At most 16 allowed stubs may be supplied")
    allowed_stub_names = _allowed_stub_names(evidence_pack)
    for stub in request.allowed_stubs:
        if stub not in allowed_stub_names:
            allowed = ", ".join(sorted(allowed_stub_names)) or "(none)"
            raise ValueError(f"allowed_stub {stub!r} is not listed in the evidence pack; allowed: {allowed}")
    if len(request.seed_mutations) > 16:
        raise ValueError("At most 16 seed mutations may be supplied")
    for seed in request.seed_mutations:
        if len(seed.encode("utf-8", errors="ignore")) > 4096:
            raise ValueError("Seed mutations are limited to 4096 bytes each")
    return request


def concolic_request_from_tool_request(
    evidence_pack: Mapping[str, Any],
    tool_request: Mapping[str, Any],
    config: ConcolicToolConfig,
) -> ConcolicRequest:
    """Validate an LLM controller-loop ``run_concolic_poc`` request."""

    tool_name = str(tool_request.get("tool") or "")
    if tool_name != CONCOLIC_TOOL_NAME:
        raise ValueError(f"Unsupported concolic tool: {tool_name!r}")
    requested_candidate_id = str(tool_request.get("candidate_id") or "")
    pack_candidate_id = _candidate_id_from_pack(evidence_pack)
    if requested_candidate_id and requested_candidate_id != pack_candidate_id:
        raise ValueError(
            f"Concolic tool candidate_id {requested_candidate_id!r} does not match evidence pack {pack_candidate_id!r}"
        )
    symbolic_bytes = tool_request.get("symbolic_bytes", tool_request.get("symbolic_byte_budget", 256))
    return build_concolic_request(
        evidence_pack,
        binary_path=config.binary_path,
        export_dir=config.export_dir,
        backend=str(tool_request.get("backend") or config.backend),
        target_address=str(tool_request.get("target_address") or ""),
        sink_address=str(tool_request.get("sink_address") or tool_request.get("write_address") or ""),
        input_model=str(tool_request.get("input_model") or ""),
        symbolic_bytes=int(symbolic_bytes or 256),
        constraints=[str(item) for item in _coerce_sequence(tool_request.get("constraints", []))],
        timeout_seconds=float(tool_request.get("timeout_seconds") or config.timeout_seconds),
        extra_branch_goal=str(tool_request.get("extra_branch_goal") or ""),
        waypoint_addresses=[str(item) for item in _coerce_sequence(tool_request.get("waypoint_addresses", []))],
        allowed_stubs=[str(item) for item in _coerce_sequence(tool_request.get("allowed_stubs", []))],
        seed_mutations=[str(item) for item in _coerce_sequence(tool_request.get("seed_mutations", []))],
        max_symbolic_bytes=config.max_symbolic_bytes,
    )


def _unresolved_semantic_function_harness_entrypoint(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
) -> str:
    if not _is_semantic_process_candidate(evidence_pack):
        return ""
    entrypoint = _semantic_entrypoint_derivation(
        evidence_pack,
        target_resolution=request.target_resolution if isinstance(request.target_resolution, Mapping) else {},
    )
    status = str(entrypoint.get("status") or "").lower() if isinstance(entrypoint, Mapping) else ""
    derived_model = str(entrypoint.get("input_model") or "").strip() if isinstance(entrypoint, Mapping) else ""
    if status != "derived" or not entrypoint.get("process_input_supported"):
        blockers = ", ".join(str(item) for item in _coerce_sequence(entrypoint.get("blockers", []))) if isinstance(entrypoint, Mapping) else ""
        suffix = f": {blockers}" if blockers else ""
        return f"semantic process proof requires a derived supported entrypoint{suffix}"
    if not _normalize_address(entrypoint.get("entry_address")):
        return "semantic process proof requires a derived entrypoint address"
    if request.input_model == "function_harness":
        return "semantic process proof cannot use a local function_harness without upgrading to a derived process input"
    if (
        request.input_model in PROCESS_DYNAMIC_INPUT_MODELS
        and derived_model
        and not _process_input_model_matches_entrypoint(request.input_model, derived_model)
    ):
        return f"semantic process input_model {request.input_model!r} does not match derived entrypoint model {derived_model!r}"
    return ""


def _process_input_model_matches_entrypoint(input_model: str, derived_model: str) -> bool:
    if input_model == derived_model:
        return True
    if input_model == "argv_file_stdin" and derived_model == "argv":
        return True
    if input_model == "argv_directory" and derived_model == "argv":
        return True
    if input_model == "env_file" and derived_model == "env":
        return True
    return False


def _unresolved_semantic_sink_target(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
) -> str:
    if not _is_semantic_process_candidate(evidence_pack):
        return ""
    exact_sink = _semantic_exact_sink_address(evidence_pack)
    if not exact_sink:
        return ""
    resolution = request.target_resolution if isinstance(request.target_resolution, Mapping) else {}
    resolution_target = _normalize_address(resolution.get("target_address"))
    if resolution_target and request.target_address == resolution_target:
        return ""
    if request.target_address != exact_sink:
        return f"semantic concolic target_address {request.target_address!r} must be the concrete sink callsite {exact_sink!r}"
    if request.sink_address and request.sink_address != exact_sink:
        return f"semantic concolic sink_address {request.sink_address!r} must be the concrete sink callsite {exact_sink!r}"
    return ""


def _unresolved_memory_safety_target(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
) -> str:
    candidate = _candidate_for_memory_proof(evidence_pack, export_dir=request.export_dir)
    vulnerability_type = str(candidate.get("vulnerability_type") or evidence_pack.get("vulnerability_type") or "")
    memory_types = {
        "stack_overflow",
        "heap_overflow",
        "out_of_bounds_write",
        "out_of_bounds_read",
        "use_after_free",
        "double_free",
        "invalid_free",
        "uninitialized_memory_use",
        "overlapping_memory_copy",
        "mismatched_deallocator",
        "double_close",
        "use_after_close",
    }
    inferred_memory_candidate = bool(
        candidate.get("destination_kind")
        or candidate.get("write_relation")
        or candidate.get("capacity_bytes")
        or candidate.get("allocation_site")
    )
    if vulnerability_type not in memory_types and not (not vulnerability_type and inferred_memory_candidate):
        return ""
    function_address = _normalize_address(candidate.get("address"))
    if not function_address:
        return ""
    if request.target_address == function_address or request.sink_address == function_address:
        return "memory-safety proof requires an exact sink address distinct from the function entry"
    return ""


def _is_semantic_process_candidate(evidence_pack: Mapping[str, Any]) -> bool:
    type_facts = evidence_pack.get("type_facts")
    if not isinstance(type_facts, Mapping):
        return False
    semantic_seed = type_facts.get("semantic_seed")
    if not isinstance(semantic_seed, Mapping):
        return False
    vulnerability_type = str(
        _candidate(evidence_pack).get("vulnerability_type")
        or semantic_seed.get("vulnerability_type")
        or evidence_pack.get("vulnerability_type")
        or ""
    )
    return _is_semantic_vulnerability_type(vulnerability_type)


def _is_semantic_vulnerability_type(vulnerability_type: str) -> bool:
    try:
        return get_vulnerability_spec(vulnerability_type).backend == "semantic_effect"
    except (KeyError, ValueError):
        return False


def _semantic_exact_sink_address(evidence_pack: Mapping[str, Any]) -> str:
    type_facts = evidence_pack.get("type_facts")
    type_facts = type_facts if isinstance(type_facts, Mapping) else {}
    semantic_seed = type_facts.get("semantic_seed")
    semantic_seed = semantic_seed if isinstance(semantic_seed, Mapping) else {}
    semantic_target = semantic_seed.get("semantic_target")
    semantic_target = semantic_target if isinstance(semantic_target, Mapping) else {}
    intent = type_facts.get("deterministic_replay_intent")
    if not isinstance(intent, Mapping):
        intent = semantic_seed.get("deterministic_replay_intent") if isinstance(semantic_seed.get("deterministic_replay_intent"), Mapping) else {}
    location = evidence_pack.get("location") if isinstance(evidence_pack.get("location"), Mapping) else {}
    function_anchor = _normalize_address(
        location.get("address")
        or _candidate(evidence_pack).get("address")
        or semantic_target.get("function_address")
    )
    sink = evidence_pack.get("sink") if isinstance(evidence_pack.get("sink"), Mapping) else {}
    for value in (
        sink.get("operation_address"),
        sink.get("callsite"),
        sink.get("address"),
        semantic_target.get("sink_address"),
        semantic_target.get("sink_callsite"),
        intent.get("sink_callsite"),
    ):
        address = _normalize_address(value)
        if address and address != function_anchor:
            return address
    return ""


def _semantic_concolic_target_resolution(
    evidence_pack: Mapping[str, Any],
    *,
    binary_path: Path | None = None,
    export_dir: Path | None,
) -> dict[str, Any]:
    if not _is_semantic_process_candidate(evidence_pack):
        return {}
    exact_sink = _semantic_exact_sink_address(evidence_pack)
    if exact_sink:
        return {
            "schema_version": 1,
            "status": "derived",
            "target_address": exact_sink,
            "sink_address": exact_sink,
            "target_kind": "exact_sink_callsite",
            "derivation_method": "evidence_pack",
            "no_decompiled_text_matching": True,
        }
    if export_dir is None or not Path(export_dir).exists():
        return {}
    export = _load_semantic_export(export_dir)
    if not export:
        return {}
    node = _semantic_target_node(evidence_pack, export)
    if node is None:
        return {}
    sink_names = _semantic_sink_names(evidence_pack)
    if not sink_names:
        return {}
    entrypoint = _derive_semantic_entrypoint(evidence_pack, export_dir=Path(export_dir))
    pcode_match = _semantic_pcode_sink_call(node, sink_names, export, evidence_pack=evidence_pack)
    if pcode_match:
        pcode_match.update(
            {
                "schema_version": 1,
                "status": "derived",
                "function_name": node.record.name,
                "function_address": _normalize_address(node.record.address),
                "entrypoint_derivation": entrypoint,
                "derivation_method": "ghidra_pcode_calls",
                "no_decompiled_text_matching": True,
            }
        )
        return pcode_match
    wrapper_match = _wrapper_chain_sink_call(node, sink_names, export, evidence_pack=evidence_pack)
    if wrapper_match:
        wrapper_match.update(
            {
                "schema_version": 1,
                "status": "derived",
                "function_name": node.record.name,
                "function_address": _normalize_address(node.record.address),
                "entrypoint_derivation": entrypoint,
                "derivation_method": "ghidra_pcode_wrapper_chain",
                "no_decompiled_text_matching": True,
            }
        )
        return wrapper_match
    graph = export.get("graph")
    if graph is None:
        return {}
    for callee in sorted(graph.neighbors(node.record.name), key=graph._order_key):
        if _semantic_api_name(callee) not in sink_names:
            continue
        callee_node = export["by_name"].get(callee)
        if callee_node is None:
            continue
        callee_address = _normalize_address(callee_node.record.address)
        if not callee_address:
            continue
        disassembly_match = _semantic_disassembly_sink_call(
            binary_path,
            node,
            callee_address=callee_address,
            callee_name=callee_node.record.name,
            image_base=_safe_int(getattr(export.get("manifest"), "image_base", 0), default=0),
        )
        if disassembly_match:
            disassembly_match.update(
                {
                    "schema_version": 1,
                    "status": "derived",
                    "function_name": node.record.name,
                    "function_address": _normalize_address(node.record.address),
                    "entrypoint_derivation": entrypoint,
                    "derivation_method": "elf_disassembly_direct_call",
                    "no_decompiled_text_matching": True,
                }
            )
            return disassembly_match
        return {
            "schema_version": 1,
            "status": "derived",
            "target_address": callee_address,
            "sink_address": callee_address,
            "callee_address": callee_address,
            "callee_name": callee_node.record.name,
            "function_name": node.record.name,
            "function_address": _normalize_address(node.record.address),
            "target_kind": "structured_sink_callee",
            "entrypoint_derivation": entrypoint,
            "derivation_method": "ghidra_cached_callgraph",
            "no_decompiled_text_matching": True,
        }
    return {}


def _memory_safety_concolic_target_resolution(
    evidence_pack: Mapping[str, Any],
    *,
    binary_path: Path | None = None,
    export_dir: Path | None,
) -> dict[str, Any]:
    candidate = _candidate_for_memory_proof(evidence_pack, export_dir=export_dir)
    if not candidate:
        return {}
    vulnerability_type = str(candidate.get("vulnerability_type") or evidence_pack.get("vulnerability_type") or "")
    if _is_semantic_vulnerability_type(vulnerability_type):
        return {}
    exact_sink = _exact_sink_address_from_pack(evidence_pack)
    function_address = _normalize_address(candidate.get("address"))
    if exact_sink and exact_sink != function_address:
        return {
            "schema_version": 1,
            "status": "derived",
            "target_address": exact_sink,
            "sink_address": exact_sink,
            "callsite_address": exact_sink,
            "function_name": str(candidate.get("function_name") or ""),
            "function_address": function_address,
            "target_kind": "exact_sink_callsite",
            "derivation_method": "evidence_pack",
            "no_decompiled_text_matching": True,
        }
    if export_dir is None or not Path(export_dir).exists():
        return {}
    export = _load_semantic_export(Path(export_dir))
    if not export:
        return {}
    node = _semantic_target_node(evidence_pack, export)
    if node is None:
        return {}
    cursor_limit_match = _cursor_limit_read_disassembly_sink(
        binary_path,
        node,
        evidence_pack,
        image_base=_safe_int(getattr(export.get("manifest"), "image_base", 0), default=0),
    )
    if cursor_limit_match:
        cursor_limit_match.update(
            {
                "schema_version": 1,
                "status": "derived",
                "function_name": node.record.name,
                "function_address": _normalize_address(node.record.address),
                "derivation_method": "elf_disassembly_cursor_limit_read",
                "no_decompiled_text_matching": True,
            }
        )
        return cursor_limit_match
    store_match = _pcode_store_sink(node, evidence_pack)
    if store_match:
        store_match.update(
            {
                "schema_version": 1,
                "status": "derived",
                "function_name": node.record.name,
                "function_address": _normalize_address(node.record.address),
                "derivation_method": "ghidra_pcode_store",
                "no_decompiled_text_matching": True,
            }
        )
        return store_match
    sink_names = _semantic_sink_names(evidence_pack)
    if not sink_names:
        return {}
    pcode_match = _semantic_pcode_sink_call(node, sink_names, export, evidence_pack=evidence_pack)
    if pcode_match:
        pcode_match.update(
            {
                "schema_version": 1,
                "status": "derived",
                "function_name": node.record.name,
                "function_address": _normalize_address(node.record.address),
                "derivation_method": "ghidra_pcode_calls",
                "no_decompiled_text_matching": True,
            }
        )
        return pcode_match
    wrapper_match = _wrapper_chain_sink_call(node, sink_names, export, evidence_pack=evidence_pack)
    if wrapper_match:
        wrapper_match.update(
            {
                "schema_version": 1,
                "status": "derived",
                "function_name": node.record.name,
                "function_address": _normalize_address(node.record.address),
                "derivation_method": "ghidra_pcode_wrapper_chain",
                "no_decompiled_text_matching": True,
            }
        )
        return wrapper_match
    interprocedural_match = _interprocedural_wrapper_sink_call(
        evidence_pack,
        node,
        sink_names,
        export,
        binary_path=binary_path,
    )
    if interprocedural_match:
        interprocedural_match.update(
            {
                "schema_version": 1,
                "status": "derived",
                "function_name": node.record.name,
                "function_address": _normalize_address(node.record.address),
                "derivation_method": "ghidra_interprocedural_wrapper",
                "no_decompiled_text_matching": True,
            }
        )
        return interprocedural_match
    callee_node = _sink_callee_node(export, sink_names)
    if callee_node is None:
        return {}
    callee_address = _normalize_address(callee_node.record.address)
    if not callee_address:
        return {}
    image_base = _safe_int(getattr(export.get("manifest"), "image_base", 0), default=0)
    source_read_match = _source_read_disassembly_sink_call(
        binary_path,
        node,
        evidence_pack,
        sink_names=sink_names,
        export=export,
    )
    if source_read_match:
        source_read_match.update(
            {
                "schema_version": 1,
                "status": "derived",
                "function_name": node.record.name,
                "function_address": _normalize_address(node.record.address),
                "derivation_method": "elf_disassembly_unique_source_read_call",
                "no_decompiled_text_matching": False,
            }
        )
        return source_read_match
    line_disassembly_match = _line_aware_disassembly_sink_call(
        binary_path,
        node,
        evidence_pack,
        export_dir=Path(export_dir),
        sink_names=sink_names,
        callee_address=callee_address,
        callee_name=callee_node.record.name,
        image_base=image_base,
    )
    if line_disassembly_match:
        line_disassembly_match.update(
            {
                "schema_version": 1,
                "status": "derived",
                "function_name": node.record.name,
                "function_address": _normalize_address(node.record.address),
                "derivation_method": "elf_disassembly_decompiled_line",
                "no_decompiled_text_matching": False,
            }
        )
        return line_disassembly_match
    disassembly_match = _semantic_disassembly_sink_call(
        binary_path,
        node,
        callee_address=callee_address,
        callee_name=callee_node.record.name,
        image_base=image_base,
    )
    if not disassembly_match:
        return {}
    disassembly_match.update(
        {
            "schema_version": 1,
            "status": "derived",
            "function_name": node.record.name,
            "function_address": _normalize_address(node.record.address),
            "derivation_method": "elf_disassembly_direct_call",
            "no_decompiled_text_matching": True,
        }
    )
    return disassembly_match


def resolve_memory_safety_target(
    evidence_pack: Mapping[str, Any],
    *,
    binary_path: Path | None = None,
    export_dir: Path | None = None,
) -> dict[str, Any]:
    """Resolve and identify an exact memory operation before proof promotion."""

    resolution = _memory_safety_concolic_target_resolution(
        evidence_pack,
        binary_path=Path(binary_path) if binary_path is not None else None,
        export_dir=Path(export_dir) if export_dir is not None else None,
    )
    return _target_resolution_with_sink_site(evidence_pack, resolution)


def _target_resolution_with_sink_site(
    evidence_pack: Mapping[str, Any],
    target_resolution: Mapping[str, Any],
) -> dict[str, Any]:
    if not target_resolution:
        return {}
    candidate = _candidate(evidence_pack)
    result = dict(target_resolution)
    site = sink_site_identity(
        {
            "function_address": candidate.get("address"),
            "sink_name": candidate.get("sink"),
            "target_buffer": candidate.get("target_buffer"),
            "offset_expr": candidate.get("offset_expr"),
            "line_number": candidate.get("line_number"),
            "operation_address": candidate.get("operation_address"),
        },
        result,
    )
    if site:
        result["sink_site"] = site
    return result


def _refine_repeated_sink_target_resolution(
    evidence_pack: Mapping[str, Any],
    target_resolution: Mapping[str, Any],
    *,
    binary_path: Path,
    export_dir: Path | None,
) -> dict[str, Any]:
    """Disambiguate repeated calls that share one stale evidence address."""

    result = dict(target_resolution)
    if export_dir is None or not export_dir.exists() or not binary_path.exists():
        return result
    export = _load_semantic_export(export_dir)
    node = _semantic_target_node(evidence_pack, export) if export else None
    sink_names = _semantic_sink_names(evidence_pack)
    if node is None or not sink_names:
        return result
    callee_node = _sink_callee_node(export, sink_names)
    if callee_node is None:
        return result
    callee_address = _normalize_address(callee_node.record.address)
    if not callee_address:
        return result
    refined = _line_aware_disassembly_sink_call(
        binary_path,
        node,
        evidence_pack,
        export_dir=export_dir,
        sink_names=sink_names,
        callee_address=callee_address,
        callee_name=callee_node.record.name,
        image_base=_safe_int(getattr(export.get("manifest"), "image_base", 0), default=0),
    )
    if not refined:
        return result
    original_address = _normalize_address(result.get("sink_address") or result.get("target_address"))
    refined_address = _normalize_address(refined.get("sink_address") or refined.get("target_address"))
    result.update(refined)
    result.update(
        {
            "schema_version": 1,
            "status": "derived",
            "function_name": node.record.name,
            "function_address": _normalize_address(node.record.address),
            "derivation_method": "elf_disassembly_decompiled_line",
            "no_decompiled_text_matching": False,
        }
    )
    if original_address and original_address != refined_address:
        result["superseded_evidence_address"] = original_address
    return result


def _sink_callee_node(export: Mapping[str, Any], sink_names: set[str]) -> Any | None:
    nodes = _sink_callee_nodes(export, sink_names)
    return nodes[0] if nodes else None


def _sink_callee_nodes(export: Mapping[str, Any], sink_names: set[str]) -> list[Any]:
    by_name = export.get("by_name") if isinstance(export.get("by_name"), Mapping) else {}
    nodes: list[Any] = []
    for name in sorted(by_name):
        node = by_name[name]
        if _function_api_names(node) & sink_names:
            nodes.append(node)
    return nodes


@lru_cache(maxsize=32)
def _load_semantic_export(export_dir: Path) -> dict[str, Any]:
    try:
        from binary_agent.analysis.callgraph import load_cached_call_graph
        from binary_agent.ingest.loader import load_function_nodes

        manifest, nodes = load_function_nodes(Path(export_dir))
        graph = load_cached_call_graph(
            manifest,
            nodes,
            include_text_edges=False,
            include_pcode_edges=True,
        )
        return {
            "manifest": manifest,
            "nodes": tuple(nodes),
            "graph": graph,
            "by_name": {node.record.name: node for node in nodes},
            "by_address": {_normalize_address(node.record.address): node for node in nodes},
        }
    except Exception:
        return {}


def _derive_semantic_entrypoint(evidence_pack: Mapping[str, Any], *, export_dir: Path) -> dict[str, Any]:
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    entrypoint = type_facts.get("entrypoint_derivation")
    if isinstance(entrypoint, Mapping) and entrypoint:
        return dict(entrypoint)
    entrypoint = evidence_pack.get("entrypoint_derivation")
    if isinstance(entrypoint, Mapping) and entrypoint:
        return dict(entrypoint)
    try:
        from binary_agent.analysis.entrypoints import EntryPointDeriver

        return EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(evidence_pack).to_dict()
    except Exception as exc:
        return {
            "schema_version": 1,
            "status": "blocked",
            "blockers": [f"entrypoint_derivation_failed:{exc}"],
            "no_text_matching": True,
            "evidence": {"export_dir": str(export_dir)},
        }


def _semantic_target_node(evidence_pack: Mapping[str, Any], export: Mapping[str, Any]) -> Any | None:
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    semantic_seed = type_facts.get("semantic_seed") if isinstance(type_facts.get("semantic_seed"), Mapping) else {}
    semantic_target = type_facts.get("semantic_target")
    if not isinstance(semantic_target, Mapping):
        semantic_target = semantic_seed.get("semantic_target") if isinstance(semantic_seed.get("semantic_target"), Mapping) else {}
    location = evidence_pack.get("location") if isinstance(evidence_pack.get("location"), Mapping) else {}
    candidate = _candidate(evidence_pack)
    by_name = export.get("by_name") if isinstance(export.get("by_name"), Mapping) else {}
    by_address = export.get("by_address") if isinstance(export.get("by_address"), Mapping) else {}
    for value in (
        semantic_target.get("function_name"),
        location.get("function_name"),
        candidate.get("function_name"),
    ):
        name = str(value or "")
        if name and name in by_name:
            return by_name[name]
    for value in (
        semantic_target.get("function_address"),
        location.get("address"),
        candidate.get("address"),
    ):
        address = _normalize_address(value)
        if address and address in by_address:
            return by_address[address]
    return None


def _semantic_sink_names(evidence_pack: Mapping[str, Any]) -> set[str]:
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    semantic_seed = type_facts.get("semantic_seed") if isinstance(type_facts.get("semantic_seed"), Mapping) else {}
    semantic_target = type_facts.get("semantic_target")
    if not isinstance(semantic_target, Mapping):
        semantic_target = semantic_seed.get("semantic_target") if isinstance(semantic_seed.get("semantic_target"), Mapping) else {}
    intent = type_facts.get("deterministic_replay_intent")
    if not isinstance(intent, Mapping):
        intent = semantic_seed.get("deterministic_replay_intent") if isinstance(semantic_seed.get("deterministic_replay_intent"), Mapping) else {}
    sink = evidence_pack.get("sink") if isinstance(evidence_pack.get("sink"), Mapping) else {}
    candidate = _candidate(evidence_pack)
    names = {
        _semantic_api_name(value)
        for value in (
            semantic_target.get("sink_name"),
            intent.get("sink"),
            sink.get("name"),
            sink.get("sink"),
            candidate.get("sink"),
        )
    }
    normalized = {name for name in names if name}
    for name in tuple(normalized):
        if name.endswith("_source_read"):
            base = name.removesuffix("_source_read")
            if base:
                normalized.add(base)
    return normalized


def _semantic_pcode_sink_call(
    node: Any,
    sink_names: set[str],
    export: Mapping[str, Any],
    *,
    evidence_pack: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return _sink_callsite_from_node(
        node,
        sink_names,
        export,
        evidence_pack=evidence_pack,
        source="pcode_calls",
        wrapper_path=(),
    )


def _sink_callsite_from_node(
    node: Any,
    sink_names: set[str],
    export: Mapping[str, Any],
    *,
    evidence_pack: Mapping[str, Any] | None = None,
    source: str,
    wrapper_path: tuple[str, ...],
) -> dict[str, Any]:
    by_name = export.get("by_name") if isinstance(export.get("by_name"), Mapping) else {}
    sink_callee_addresses = _sink_callee_addresses(evidence_pack or {}, export, sink_names)
    rows = [
        *((row, "pcode_calls") for row in list(node.record.pcode_calls or [])),
        *((row, "ambiguous_callsites") for row in list(node.record.ambiguous_callsites or [])),
    ]
    for call, row_source in rows:
        if not isinstance(call, Mapping):
            continue
        callee_name = str(call.get("callee") or call.get("function") or call.get("target_function") or "")
        if not _call_row_matches_sink(call, sink_names, export, sink_callee_addresses):
            continue
        call_address = _normalize_address(call.get("call_address") or call.get("address") or call.get("operation_address"))
        callee_node = by_name.get(callee_name)
        callee_address = _normalize_address(
            call.get("callee_address")
            or call.get("target_function_address")
            or (callee_node.record.address if callee_node is not None else "")
        )
        target_kind = _target_kind_for_call_row(
            call,
            "exact_ambiguous_callsite" if row_source == "ambiguous_callsites" else "exact_pcode_callsite",
        )
        target_source = row_source if source == "pcode_calls" else source
        if call_address:
            result = {
                "target_address": call_address,
                "sink_address": call_address,
                "callsite_address": call_address,
                "callee_address": callee_address,
                "callee_name": callee_name,
                "target_kind": target_kind,
                "target_source": target_source,
            }
            if wrapper_path:
                result["wrapper_chain"] = list(wrapper_path)
            return result
        if callee_address:
            result = {
                "target_address": callee_address,
                "sink_address": callee_address,
                "callee_address": callee_address,
                "callee_name": callee_name,
                "target_kind": "pcode_sink_callee",
                "target_source": target_source,
            }
            if wrapper_path:
                result["wrapper_chain"] = list(wrapper_path)
            return result
    return {}


def _target_kind_for_call_row(row: Mapping[str, Any], default: str) -> str:
    pcode = str(row.get("pcode") or row.get("mnemonic") or "").upper()
    reasons = {str(item).lower() for item in _coerce_sequence(row.get("ambiguity_reasons", []))}
    if pcode == "CALLIND" or "indirect_call" in reasons or str(row.get("target_kind") or "").lower() == "indirect":
        return "exact_indirect_callsite"
    return default


def _wrapper_chain_sink_call(
    node: Any,
    sink_names: set[str],
    export: Mapping[str, Any],
    *,
    evidence_pack: Mapping[str, Any] | None = None,
    max_depth: int = 4,
) -> dict[str, Any]:
    by_name = export.get("by_name") if isinstance(export.get("by_name"), Mapping) else {}
    by_address = export.get("by_address") if isinstance(export.get("by_address"), Mapping) else {}
    visited: set[str] = set()

    def resolve_callee(row: Mapping[str, Any]) -> Any | None:
        name = str(row.get("callee") or row.get("function") or row.get("target_function") or "")
        if name and name in by_name:
            return by_name[name]
        for key in ("callee_address", "target_function_address", "target_address"):
            address = _normalize_address(row.get(key))
            if address and address in by_address:
                return by_address[address]
        return None

    def search(current: Any, path: tuple[str, ...], depth: int) -> dict[str, Any]:
        if depth > max_depth:
            return {}
        current_name = str(current.record.name)
        if current_name in visited:
            return {}
        visited.add(current_name)
        direct = _sink_callsite_from_node(
            current,
            sink_names,
            export,
            evidence_pack=evidence_pack,
            source="wrapper_chain",
            wrapper_path=path,
        )
        if direct and path:
            direct["target_kind"] = "wrapper_chain_callsite"
            return direct
        for call in [*list(current.record.pcode_calls or []), *list(current.record.ambiguous_callsites or [])]:
            if not isinstance(call, Mapping):
                continue
            callee = resolve_callee(call)
            if callee is None or not _is_transparent_sink_wrapper(callee):
                continue
            result = search(callee, (*path, str(callee.record.name)), depth + 1)
            if result:
                return result
        return {}

    return search(node, (), 0)


def _interprocedural_wrapper_sink_call(
    evidence_pack: Mapping[str, Any],
    caller_node: Any,
    sink_names: set[str],
    export: Mapping[str, Any],
    *,
    binary_path: Path | None = None,
) -> dict[str, Any]:
    candidate = _candidate(evidence_pack)
    kind = str(candidate.get("kind") or "").lower()
    if "interprocedural" not in kind:
        return {}
    by_name = export.get("by_name") if isinstance(export.get("by_name"), Mapping) else {}
    callee_node = _sink_callee_node(export, sink_names)
    callee_address = _normalize_address(callee_node.record.address) if callee_node is not None else ""
    callee_name = str(callee_node.record.name) if callee_node is not None else sorted(sink_names)[0]
    image_base = _safe_int(getattr(export.get("manifest"), "image_base", 0), default=0)
    caller_name = str(caller_node.record.name)

    for wrapper_name in _interprocedural_wrapper_names(evidence_pack, export, caller_name=caller_name):
        wrapper_node = by_name.get(wrapper_name)
        if wrapper_node is None:
            continue
        match = _sink_callsite_from_node(
            wrapper_node,
            sink_names,
            export,
            evidence_pack=evidence_pack,
            source="interprocedural_wrapper",
            wrapper_path=(wrapper_name,),
        )
        if not match and callee_address:
            match = _semantic_disassembly_sink_call(
                binary_path,
                wrapper_node,
                callee_address=callee_address,
                callee_name=callee_name,
                image_base=image_base,
            )
        if not match:
            continue
        match["target_kind"] = "interprocedural_wrapper_callsite"
        match["target_source"] = match.get("target_source") or "interprocedural_wrapper"
        match["wrapper_chain"] = [wrapper_name]
        match["wrapper_function"] = wrapper_name
        match["wrapper_function_address"] = _normalize_address(wrapper_node.record.address)
        return match
    return {}


def _interprocedural_wrapper_names(
    evidence_pack: Mapping[str, Any],
    export: Mapping[str, Any],
    *,
    caller_name: str,
) -> list[str]:
    by_name = export.get("by_name") if isinstance(export.get("by_name"), Mapping) else {}
    sink_names = _semantic_sink_names(evidence_pack)
    names: list[str] = []
    seen: set[str] = set()
    for text in _nested_strings(evidence_pack):
        for match in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_$.@]*\b(?=\s*\()", text):
            name = match.group(0)
            api_name = _semantic_api_name(name)
            if name == caller_name or api_name in sink_names or name not in by_name or name in seen:
                continue
            seen.add(name)
            names.append(name)
        for match in re.finditer(r"\bFUN_[0-9A-Fa-f]+\b", text):
            name = match.group(0)
            if name == caller_name or name not in by_name or name in seen:
                continue
            seen.add(name)
            names.append(name)
    return names[:8]


def _nested_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        strings: list[str] = []
        for item in value.values():
            strings.extend(_nested_strings(item))
        return strings
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        strings = []
        for item in value:
            strings.extend(_nested_strings(item))
        return strings
    return []


def _is_transparent_sink_wrapper(node: Any) -> bool:
    record = node.record
    if getattr(record, "is_thunk", False):
        return True
    if getattr(record, "wrapper_type", None) in {"plt_thunk", "single_call_wrapper", "indirect_forward"}:
        return True
    if getattr(record, "stub_kind", None) in {"wrapper", "single_call_wrapper"}:
        return True
    if getattr(record, "stub_kind", None) == "tiny_body" and len(record.pcode_calls or []) == 1 and not (record.pcode_stores or []):
        return True
    return False


def _pcode_store_sink(node: Any, evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    candidate = _candidate(evidence_pack)
    sink_name = _semantic_api_name(candidate.get("sink"))
    target_buffer = str(candidate.get("target_buffer") or candidate.get("source_object") or "").strip()
    if sink_name not in {"pointer_store", "array_store", "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat"} and not target_buffer:
        return {}
    matches = []
    for row in node.record.pcode_stores or []:
        if not isinstance(row, Mapping):
            continue
        address = _normalize_address(row.get("operation_address") or row.get("address") or row.get("instruction_address"))
        if not address:
            continue
        names = {
            str(row.get("base_var") or ""),
            str(row.get("var_name") or ""),
            str(row.get("target_buffer") or ""),
        }
        stack_ref = row.get("stack_ref") if isinstance(row.get("stack_ref"), Mapping) else {}
        names.add(str(stack_ref.get("var_name") or ""))
        if target_buffer and target_buffer not in names:
            continue
        matches.append((address, row))
    if len(matches) != 1:
        return {}
    address, row = matches[0]
    return {
        "target_address": address,
        "sink_address": address,
        "callsite_address": address,
        "target_kind": "exact_pcode_store",
        "target_source": "pcode_stores",
        "store": dict(row),
    }


def _call_row_matches_sink(
    row: Mapping[str, Any],
    sink_names: set[str],
    export: Mapping[str, Any],
    sink_callee_addresses: set[str],
) -> bool:
    by_name = export.get("by_name") if isinstance(export.get("by_name"), Mapping) else {}
    by_address = export.get("by_address") if isinstance(export.get("by_address"), Mapping) else {}
    names = {
        _semantic_api_name(row.get("callee")),
        _semantic_api_name(row.get("function")),
        _semantic_api_name(row.get("target_function")),
    }
    for raw_name in (row.get("callee"), row.get("function"), row.get("target_function")):
        node = by_name.get(str(raw_name or ""))
        if node is not None:
            names.update(_function_api_names(node))
    for key in ("callee_address", "target_function_address", "target_address"):
        address = _normalize_address(row.get(key))
        if not address:
            continue
        if address in sink_callee_addresses:
            return True
        node = by_address.get(address)
        if node is not None:
            names.update(_function_api_names(node))
    return bool(names & sink_names)


def _sink_callee_addresses(evidence_pack: Mapping[str, Any], export: Mapping[str, Any], sink_names: set[str]) -> set[str]:
    addresses: set[str] = set()
    candidate = _candidate(evidence_pack)
    for key in ("callee_address", "sink_callee_address", "target_callee_address"):
        address = _normalize_address(candidate.get(key))
        if address:
            addresses.add(address)
    sink = evidence_pack.get("sink") if isinstance(evidence_pack.get("sink"), Mapping) else {}
    for key in ("callee_address", "sink_callee_address", "target_callee_address"):
        address = _normalize_address(sink.get(key))
        if address:
            addresses.add(address)
    facts = _facts(evidence_pack)
    for key in ("callee_address", "sink_callee_address", "target_callee_address"):
        address = _normalize_address(facts.get(key))
        if address:
            addresses.add(address)
    for row_key in ("write_table", "pcode_sink_catalog", "call_catalog"):
        for row in _coerce_sequence(facts.get(row_key, [])):
            if not isinstance(row, Mapping):
                continue
            for key in ("callee_address", "sink_callee_address", "target_callee_address"):
                address = _normalize_address(row.get(key))
                if address:
                    addresses.add(address)
    for node in (export.get("by_name") or {}).values() if isinstance(export.get("by_name"), Mapping) else []:
        if _function_api_names(node) & sink_names:
            address = _normalize_address(node.record.address)
            if address:
                addresses.add(address)
    return addresses


def _function_api_names(node: Any) -> set[str]:
    record = node.record
    return {
        name
        for name in (
            _semantic_api_name(getattr(record, "name", "")),
            _semantic_api_name(getattr(record, "source_symbol", "")),
            _semantic_api_name(getattr(record, "demangled_name", "")),
        )
        if name
    }


def _semantic_disassembly_sink_call(
    binary_path: Path | None,
    node: Any,
    *,
    callee_address: str,
    callee_name: str,
    image_base: int = 0,
) -> dict[str, Any]:
    if binary_path is None:
        return {}
    callsite = _direct_callsite_to_address(
        Path(binary_path),
        function_address=_normalize_address(node.record.address),
        function_size=_safe_int(getattr(node.record, "size_addresses", 0), default=0)
        or _safe_int(getattr(node.record, "body_size_bytes", 0), default=0),
        callee_address=callee_address,
        image_base=int(image_base or 0),
    )
    if not callsite:
        return {}
    return {
        "target_address": callsite,
        "sink_address": callsite,
        "callsite_address": callsite,
        "callee_address": callee_address,
        "callee_name": callee_name,
        "target_kind": "disassembly_callsite",
    }


def _line_aware_disassembly_sink_call(
    binary_path: Path | None,
    node: Any,
    evidence_pack: Mapping[str, Any],
    *,
    export_dir: Path,
    sink_names: set[str],
    callee_address: str,
    callee_name: str,
    image_base: int = 0,
) -> dict[str, Any]:
    if binary_path is None:
        return {}
    occurrence = _decompiled_sink_occurrence(evidence_pack, export_dir=export_dir, sink_names=sink_names)
    if not occurrence:
        return {}
    target_address = _symbolic_storage_address(str(occurrence.get("target_buffer") or ""))
    offset_address = _symbolic_storage_address(str(occurrence.get("offset_expr") or ""))
    callsites = _direct_callsites_to_address(
        Path(binary_path),
        function_address=_normalize_address(node.record.address),
        function_size=_safe_int(getattr(node.record, "size_addresses", 0), default=0)
        or _safe_int(getattr(node.record, "body_size_bytes", 0), default=0),
        callee_address=callee_address,
        image_base=int(image_base or 0),
    )
    if not callsites:
        return {}
    if target_address is None:
        matches = callsites
        index = _safe_int(occurrence.get("sink_occurrence_index"), default=-1)
    else:
        matches = [
            callsite
            for callsite in callsites
            if target_address in set(callsite.get("data_references") or ())
            and (offset_address is None or offset_address in set(callsite.get("data_references") or ()))
        ]
        index = _safe_int(occurrence.get("occurrence_index"), default=-1)
    if index < 0 or index >= len(matches):
        return {}
    selected = matches[index]
    callsite_address = _normalize_address(selected.get("call_address"))
    if not callsite_address:
        return {}
    return {
        "target_address": callsite_address,
        "sink_address": callsite_address,
        "callsite_address": callsite_address,
        "callee_address": callee_address,
        "callee_name": callee_name,
        "target_kind": "disassembly_line_callsite",
        "decompiled_line_number": occurrence.get("line_number"),
        "decompiled_line_text": occurrence.get("line_text"),
        "decompiled_sink_occurrence_index": index,
        "decompiled_sink_source_order_index": occurrence.get("sink_occurrence_index"),
        "target_data_reference": _normalize_address(target_address),
        "offset_data_reference": _normalize_address(offset_address),
    }


def _source_read_disassembly_sink_call(
    binary_path: Path | None,
    node: Any,
    evidence_pack: Mapping[str, Any],
    *,
    sink_names: set[str],
    export: Mapping[str, Any],
) -> dict[str, Any]:
    if binary_path is None:
        return {}
    candidate = _candidate(evidence_pack)
    if str(candidate.get("kind") or "") != "source_read":
        return {}
    occurrence = _decompiled_call_occurrence_for_node(node, evidence_pack, sink_names=sink_names)
    if not occurrence:
        return {}
    matches: list[tuple[Any, Mapping[str, Any]]] = []
    for callee_node in _sink_callee_nodes(export, sink_names):
        callee_address = _normalize_address(callee_node.record.address)
        if not callee_address:
            continue
        for callsite in _direct_callsites_to_address(
            Path(binary_path),
            function_address=_normalize_address(node.record.address),
            function_size=_safe_int(getattr(node.record, "size_addresses", 0), default=0)
            or _safe_int(getattr(node.record, "body_size_bytes", 0), default=0),
            callee_address=callee_address,
            image_base=_safe_int(getattr(export.get("manifest"), "image_base", 0), default=0),
        ):
            matches.append((callee_node, callsite))
    if len(matches) != 1:
        return {}
    callee_node, callsite = matches[0]
    callee_address = _normalize_address(callee_node.record.address)
    if not callee_address:
        return {}
    callsite_address = _normalize_address(callsite.get("call_address"))
    if not callsite_address:
        return {}
    return {
        "target_address": callsite_address,
        "sink_address": callsite_address,
        "callsite_address": callsite_address,
        "callee_address": callee_address,
        "callee_name": callee_node.record.name,
        "target_kind": "disassembly_unique_source_read_callsite",
        "decompiled_line_number": occurrence.get("line_number"),
        "decompiled_line_text": occurrence.get("line_text"),
        "decompiled_sink_occurrence_index": occurrence.get("occurrence_index"),
    }


def _cursor_limit_read_disassembly_sink(
    binary_path: Path | None,
    node: Any,
    evidence_pack: Mapping[str, Any],
    *,
    image_base: int = 0,
) -> dict[str, Any]:
    if binary_path is None or shutil.which("objdump") is None:
        return {}
    candidate = _candidate(evidence_pack)
    if str(candidate.get("sink") or "") != "cursor_limit_read":
        return {}
    trace = _candidate_classification_trace(evidence_pack)
    if not isinstance(trace.get("cursor_limit_read"), Mapping):
        return {}
    function_int = _parse_address(_normalize_address(node.record.address))
    function_size = (
        _safe_int(getattr(node.record, "size_addresses", 0), default=0)
        or _safe_int(getattr(node.record, "body_size_bytes", 0), default=0)
    )
    if function_int is None or function_size <= 0:
        return {}
    candidates = [(function_int, 0)]
    if image_base and function_int >= image_base:
        candidates.append((function_int - image_base, image_base))
    for function_candidate, result_bias in candidates:
        try:
            completed = subprocess.run(
                [
                    "objdump",
                    "-d",
                    "-M",
                    "intel",
                    f"--start-address=0x{function_candidate:x}",
                    f"--stop-address=0x{function_candidate + function_size:x}",
                    str(binary_path),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except Exception:
            continue
        sink_address = _cursor_limit_sink_from_objdump(completed.stdout, result_bias=result_bias)
        if sink_address:
            return {
                "target_address": sink_address,
                "sink_address": sink_address,
                "callsite_address": sink_address,
                "target_kind": "disassembly_cursor_limit_read",
            }
    return {}


def _cursor_limit_sink_from_objdump(disassembly: str, *, result_bias: int = 0) -> str:
    marker_seen = False
    armed = False
    byte_loads_after_marker = 0
    instructions_after_marker = 0
    for line in disassembly.splitlines():
        match = re.match(r"^\s*(?P<address>[0-9A-Fa-f]+):\s+(?P<bytes>(?:[0-9A-Fa-f]{2}\s)+)\s*(?P<insn>.*)$", line)
        if not match:
            continue
        insn = match.group("insn")
        if not marker_seen:
            if re.search(r"\bcmp\b.*0x80\b", insn):
                marker_seen = True
                instructions_after_marker = 0
            continue
        if not armed:
            if re.search(r"\bcmp\b.*0xff\b", insn):
                armed = True
                instructions_after_marker = 0
            elif instructions_after_marker > 24:
                marker_seen = False
                instructions_after_marker = 0
            else:
                instructions_after_marker += 1
            continue
        instructions_after_marker += 1
        if instructions_after_marker > 48:
            marker_seen = False
            armed = False
            byte_loads_after_marker = 0
            instructions_after_marker = 0
            continue
        if not re.search(r"\bmovz\w*\b.*\bBYTE PTR\s*\[", insn):
            continue
        byte_loads_after_marker += 1
        if byte_loads_after_marker < 3:
            continue
        try:
            return _normalize_address(int(match.group("address"), 16) + int(result_bias or 0))
        except ValueError:
            return ""
    return ""


def _decompiled_call_occurrence_for_node(
    node: Any,
    evidence_pack: Mapping[str, Any],
    *,
    sink_names: set[str],
) -> dict[str, Any]:
    candidate = _candidate(evidence_pack)
    line_number = _candidate_line_number(candidate, _candidate_id_from_pack(evidence_pack))
    if line_number <= 0:
        return {}
    lines = str(getattr(node, "text", "") or "").splitlines()
    if line_number > len(lines):
        return {}
    expected_line = _strip_line_comment(lines[line_number - 1]).strip()
    candidate_line = " ".join(str(candidate.get("line_text") or "").split())
    if candidate_line and " ".join(expected_line.split()) != candidate_line:
        return {}
    matches: list[dict[str, Any]] = []
    for current_line, raw_line in enumerate(lines, start=1):
        stripped = _strip_line_comment(raw_line).strip()
        if not stripped:
            continue
        for call_name, _args in _iter_c_calls(stripped):
            if _semantic_api_name(call_name) not in sink_names:
                continue
            match = {"line_number": current_line, "line_text": stripped}
            if current_line == line_number:
                match["occurrence_index"] = len(matches)
                return match
            matches.append(match)
    return {}


def _decompiled_sink_occurrence(
    evidence_pack: Mapping[str, Any],
    *,
    export_dir: Path,
    sink_names: set[str],
) -> dict[str, Any]:
    candidate = _candidate(evidence_pack)
    candidate_id = _candidate_id_from_pack(evidence_pack)
    line_number = _candidate_line_number(candidate, candidate_id)
    if line_number <= 0:
        return {}
    target_buffer = _candidate_field(evidence_pack, "target_buffer")
    offset_expr = _candidate_field(evidence_pack, "offset_expr")
    if not target_buffer:
        return {}
    function_name = str(candidate.get("function_name") or "")
    function_address = _normalize_address(candidate.get("address"))
    names = {function_name} if function_name else set()
    address_tokens = {function_address[2:].lower()} if function_address else set()
    paths = _candidate_decompile_paths(Path(export_dir), names, address_tokens)
    if not paths:
        names, address_tokens = _combined_process_entry_identifiers(evidence_pack)
        paths = _candidate_decompile_paths(Path(export_dir), names, address_tokens)
    if not paths:
        return {}
    wanted_offset = offset_expr and offset_expr not in {"0", "0x0"}
    for path in paths:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        matches: list[dict[str, Any]] = []
        sink_matches: list[dict[str, Any]] = []
        for current_line, raw_line in enumerate(lines, start=1):
            stripped = _strip_line_comment(raw_line).strip()
            if not stripped:
                continue
            for call_name, args in _iter_c_calls(stripped):
                if _semantic_api_name(call_name) not in sink_names or len(args) < 1:
                    continue
                sink_occurrence_index = len(sink_matches)
                sink_matches.append({"line_number": current_line, "line_text": stripped})
                dest = _clean_c_expr(args[0])
                if target_buffer not in dest:
                    continue
                # Candidate ids normalize punctuation in offset expressions,
                # so an exact source line is stronger than literal spelling.
                if wanted_offset and offset_expr not in dest and current_line != line_number:
                    continue
                match = {
                    "line_number": current_line,
                    "line_text": stripped,
                    "target_buffer": target_buffer,
                    "offset_expr": offset_expr if wanted_offset else "",
                }
                if current_line == line_number:
                    match["occurrence_index"] = len(matches)
                    match["sink_occurrence_index"] = sink_occurrence_index
                    return match
                matches.append(match)
        if len(lines) >= line_number:
            stripped = _strip_line_comment(lines[line_number - 1]).strip()
            if stripped:
                return {}
    return {}


def _candidate_field(evidence_pack: Mapping[str, Any], field_name: str) -> str:
    candidate = _candidate(evidence_pack)
    value = str(candidate.get(field_name) or "")
    if value:
        return value
    try:
        index = _CANDIDATE_ID_FIELDS.index(field_name)
    except ValueError:
        return ""
    parts = str(_candidate_id_from_pack(evidence_pack) or "").split(":")
    if len(parts) > index:
        return str(parts[index] or "")
    return ""


def _symbolic_storage_address(expr: str) -> int | None:
    match = _DAT_TOKEN_RE.search(str(expr or ""))
    if not match:
        return None
    try:
        return int(match.group(1), 16)
    except ValueError:
        return None


@lru_cache(maxsize=256)
def _direct_callsite_to_address(
    binary_path: Path,
    *,
    function_address: str,
    function_size: int,
    callee_address: str,
    image_base: int = 0,
) -> str:
    callsites = _direct_callsites_to_address(
        binary_path,
        function_address=function_address,
        function_size=function_size,
        callee_address=callee_address,
        image_base=image_base,
    )
    if callsites:
        return _normalize_address(callsites[0].get("call_address"))
    return ""


@lru_cache(maxsize=256)
def _direct_callsites_to_address(
    binary_path: Path,
    *,
    function_address: str,
    function_size: int,
    callee_address: str,
    image_base: int = 0,
) -> tuple[dict[str, Any], ...]:
    function_int = _parse_address(function_address)
    callee_int = _parse_address(callee_address)
    if function_int is None or callee_int is None or function_size <= 0:
        return ()
    try:
        from capstone import (  # type: ignore
            CS_ARCH_ARM,
            CS_ARCH_MIPS,
            CS_ARCH_X86,
            CS_MODE_32,
            CS_MODE_64,
            CS_MODE_ARM,
            CS_MODE_BIG_ENDIAN,
            CS_MODE_LITTLE_ENDIAN,
            CS_MODE_MIPS32,
            CS_MODE_THUMB,
            Cs,
        )
        from elftools.elf.elffile import ELFFile  # type: ignore
    except Exception:
        return _objdump_direct_callsites_to_address(
            binary_path,
            function_address=function_address,
            function_size=function_size,
            callee_address=callee_address,
            image_base=image_base,
        )
    candidates = [(function_int, callee_int, 0)]
    if image_base and function_int >= image_base and callee_int >= image_base:
        candidates.append((function_int - image_base, callee_int - image_base, image_base))
    try:
        with Path(binary_path).open("rb") as stream:
            elf = ELFFile(stream)
            machine = str(elf["e_machine"])
            endian = CS_MODE_LITTLE_ENDIAN if elf.little_endian else CS_MODE_BIG_ENDIAN
            modes: list[tuple[int, int]] = []
            if machine == "EM_ARM":
                modes = [(CS_ARCH_ARM, CS_MODE_ARM | endian), (CS_ARCH_ARM, CS_MODE_THUMB | endian)]
            elif machine == "EM_MIPS":
                modes = [(CS_ARCH_MIPS, CS_MODE_MIPS32 | endian)]
            elif machine == "EM_386":
                modes = [(CS_ARCH_X86, CS_MODE_32 | endian)]
            elif machine == "EM_X86_64":
                modes = [(CS_ARCH_X86, CS_MODE_64 | endian)]
            if not modes:
                return ()
            for function_candidate, callee_candidate, result_bias in candidates:
                section = _elf_section_for_address(elf, function_candidate)
                if section is None:
                    continue
                section_addr = int(section["sh_addr"])
                section_offset = int(section["sh_offset"])
                section_size = int(section["sh_size"])
                offset = section_offset + (function_candidate - section_addr)
                max_size = max(0, min(int(function_size), section_addr + section_size - function_candidate))
                if max_size <= 0:
                    continue
                stream.seek(offset)
                code = stream.read(max_size)
                for arch, mode in modes:
                    try:
                        disassembler = Cs(arch, mode)
                        disassembler.detail = True
                        window: list[set[int]] = []
                        callsites: list[dict[str, Any]] = []
                        for instruction in disassembler.disasm(code, function_candidate):
                            refs = _instruction_data_references(instruction)
                            if not _instruction_is_call_to(instruction, callee_candidate):
                                window.append(refs)
                                if len(window) > 8:
                                    del window[0]
                                continue
                            data_references: set[int] = set()
                            for item in window:
                                data_references.update(item)
                            callsites.append(
                                {
                                    "call_address": _normalize_address(instruction.address + result_bias),
                                    "data_references": tuple(sorted(data_references)),
                                }
                            )
                            window.append(refs)
                            if len(window) > 8:
                                del window[0]
                        if callsites:
                            return tuple(callsites)
                    except Exception:
                        continue
    except Exception:
        return _objdump_direct_callsites_to_address(
            binary_path,
            function_address=function_address,
            function_size=function_size,
            callee_address=callee_address,
            image_base=image_base,
        )
    return ()


def _objdump_direct_callsites_to_address(
    binary_path: Path,
    *,
    function_address: str,
    function_size: int,
    callee_address: str,
    image_base: int = 0,
) -> tuple[dict[str, Any], ...]:
    if shutil.which("objdump") is None:
        return ()
    function_int = _parse_address(function_address)
    callee_int = _parse_address(callee_address)
    if function_int is None or callee_int is None or function_size <= 0:
        return ()
    candidates = [(function_int, callee_int, 0)]
    if image_base and function_int >= image_base and callee_int >= image_base:
        candidates.append((function_int - image_base, callee_int - image_base, image_base))
    for function_candidate, callee_candidate, result_bias in candidates:
        try:
            completed = subprocess.run(
                [
                    "objdump",
                    "-d",
                    f"--start-address=0x{function_candidate:x}",
                    f"--stop-address=0x{function_candidate + int(function_size):x}",
                    str(binary_path),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except Exception:
            continue
        window: list[set[int]] = []
        callsites: list[dict[str, Any]] = []
        for line in completed.stdout.splitlines():
            refs = _objdump_line_data_references(line)
            match = re.match(
                r"^\s*(?P<address>[0-9A-Fa-f]+):.*\bcall\w*\s+(?P<target>[0-9A-Fa-f]+)\b",
                line,
            )
            if not match:
                window.append(refs)
                if len(window) > 8:
                    del window[0]
                continue
            try:
                target = int(match.group("target"), 16)
                address = int(match.group("address"), 16)
            except ValueError:
                window.append(refs)
                if len(window) > 8:
                    del window[0]
                continue
            if target != callee_candidate:
                window.append(refs)
                if len(window) > 8:
                    del window[0]
                continue
            data_references: set[int] = set()
            for item in window:
                data_references.update(item)
            callsites.append(
                {
                    "call_address": _normalize_address(address + result_bias),
                    "data_references": tuple(sorted(data_references)),
                }
            )
            window.append(refs)
            if len(window) > 8:
                del window[0]
        if callsites:
            return tuple(callsites)
    return ()


def _objdump_line_data_references(line: str) -> set[int]:
    refs: set[int] = set()
    for match in re.finditer(r"#\s*([0-9A-Fa-f]+)\b", line):
        try:
            refs.add(int(match.group(1), 16))
        except ValueError:
            continue
    return refs


def _instruction_data_references(instruction: Any) -> set[int]:
    refs: set[int] = set()
    reg_name = getattr(instruction, "reg_name", None)
    for operand in getattr(instruction, "operands", []) or []:
        immediate = getattr(operand, "imm", None)
        if isinstance(immediate, int) and immediate > 0:
            refs.add(int(immediate))
        mem = getattr(operand, "mem", None)
        if mem is None:
            continue
        disp = getattr(mem, "disp", 0)
        try:
            displacement = int(disp)
        except Exception:
            continue
        base = getattr(mem, "base", 0)
        name = ""
        if callable(reg_name):
            try:
                name = str(reg_name(base)).lower()
            except Exception:
                name = ""
        if name == "rip":
            refs.add(int(instruction.address) + int(instruction.size) + displacement)
        elif not base and displacement > 0:
            refs.add(displacement)
    return refs


def _elf_section_for_address(elf: Any, address: int) -> Any | None:
    for section in elf.iter_sections():
        try:
            start = int(section["sh_addr"])
            size = int(section["sh_size"])
            flags = int(section["sh_flags"])
        except Exception:
            continue
        if not (flags & 0x2):
            continue
        if start <= address < start + size:
            return section
    return None


def _instruction_is_call_to(instruction: Any, callee_address: int) -> bool:
    mnemonic = str(getattr(instruction, "mnemonic", "") or "").lower()
    if not (
        mnemonic.startswith("bl")
        or mnemonic in {"jal", "jalr", "bal"}
        or mnemonic.startswith("call")
    ):
        return False
    for operand in getattr(instruction, "operands", []) or []:
        immediate = getattr(operand, "imm", None)
        if immediate is None:
            continue
        try:
            value = int(immediate)
        except Exception:
            continue
        if value == callee_address or (value & ~1) == callee_address:
            return True
    return False


def _semantic_process_input_model(
    evidence_pack: Mapping[str, Any],
    *,
    target_resolution: Mapping[str, Any] | None = None,
) -> str:
    entrypoint = _semantic_entrypoint_derivation(evidence_pack, target_resolution=target_resolution)
    model = (
        _normalize_concolic_input_model(str(entrypoint.get("input_model") or "").strip())
        if isinstance(entrypoint, Mapping)
        else ""
    )
    if (
        isinstance(entrypoint, Mapping)
        and str(entrypoint.get("status") or "").lower() == "derived"
        and entrypoint.get("process_input_supported") is not False
        and model in PROCESS_DYNAMIC_INPUT_MODELS
    ):
        return model
    return ""


def _derived_semantic_process_input_model(
    evidence_pack: Mapping[str, Any],
    *,
    target_resolution: Mapping[str, Any] | None = None,
) -> str:
    entrypoint = _semantic_entrypoint_derivation(evidence_pack, target_resolution=target_resolution)
    if not isinstance(entrypoint, Mapping):
        return ""
    if str(entrypoint.get("status") or "").lower() != "derived":
        return ""
    if entrypoint.get("process_input_supported") is False:
        return ""
    model = _normalize_concolic_input_model(str(entrypoint.get("input_model") or "").strip())
    return model if model in PROCESS_DYNAMIC_INPUT_MODELS else ""


def _candidate_linked_file_input_model(
    evidence_pack: Mapping[str, Any],
    *,
    base_model: str,
) -> str:
    """Prefer file bytes when the candidate's controlled role comes from a FILE reader."""

    if base_model == "env" and _env_selected_file_input_spec(evidence_pack):
        return "env_file"
    if base_model not in {"", "argv", "file"}:
        return ""
    trace = _candidate_classification_trace(evidence_pack)
    source_to_write = trace.get("source_to_write") if isinstance(trace, Mapping) else {}
    roles = source_to_write.get("roles") if isinstance(source_to_write, Mapping) else {}
    if not isinstance(roles, Mapping):
        return ""
    for role_name in ("write_offset", "write_size", "write_source"):
        role = roles.get(role_name)
        if not isinstance(role, Mapping) or str(role.get("classification") or "") != "source_controlled":
            continue
        evidence = " ".join(_nested_strings(role)).lower()
        if any(f"source_call:{name}" in evidence for name in ("fgetc", "getc", "fread", "fscanf")):
            return "file"
    return ""


def _env_selected_file_input_spec(
    evidence_pack: Mapping[str, Any],
    *,
    input_hex: str = "",
) -> dict[str, Any]:
    """Derive one candidate-local environment-selected stream input."""

    trace_text = " ".join(_nested_strings(_candidate_classification_trace(evidence_pack))).lower()
    if "source_call:fscanf" not in trace_text and "fscanf" not in trace_text:
        return {}
    decompiled_text, source_path = _candidate_decompiled_text(evidence_pack)
    if not decompiled_text or not re.search(r"\b(?:open|open64|fopen|fopen64)\s*\(", decompiled_text):
        return {}
    if not re.search(r"\bfdopen\s*\(", decompiled_text) or not re.search(r"\b\w*fscanf\s*\(", decompiled_text):
        return {}
    env_names = _unique_strings(
        [
            match.group(1)
            for match in re.finditer(r'\b(?:getenv|secure_getenv)\s*\(\s*"([A-Za-z_][A-Za-z0-9_]*)"', decompiled_text)
        ]
    )
    if len(env_names) != 1:
        return {}
    file_names = _unique_strings(
        [
            Path(match.group(1)).name
            for match in re.finditer(r'\bstrlen\s*\(\s*"([^"\\]*(?:\\.[^"\\]*)*)"\s*\)', decompiled_text)
            if "." in Path(match.group(1)).name
            and decompiled_text.count('"' + match.group(1) + '"') >= 2
        ]
    )
    if len(file_names) != 1:
        return {}
    format_match = re.search(r'\b\w*fscanf\s*\([^;]*?"((?:\\.|[^"\\])*)"', decompiled_text, re.S)
    if format_match is None:
        return {}
    format_text = bytes(format_match.group(1), "utf-8").decode("unicode_escape")
    conversions = re.findall(r"%(?!%)(?:\*?)(\d*)([A-Za-z])", format_text)
    if not conversions or any(kind != "s" or not width for width, kind in conversions):
        return {}
    widths = [int(width) for width, _kind in conversions]
    if any(width <= 0 or width > 4096 for width in widths):
        return {}
    env_name = env_names[0]
    file_name = file_names[0]
    entry_text, entry_source_path = _combined_process_decompiled_text(evidence_pack)
    argv_values, trigger_evidence = _env_file_error_trigger(evidence_pack, entry_text)
    env_values = {env_name: "."}
    if re.search(r'\bgetenv\s*\(\s*"QUOTING_STYLE"\s*\)', entry_text):
        env_values["QUOTING_STYLE"] = "locale"
    seed = b" ".join((b"A" if index == 0 else b"B") * width for index, width in enumerate(widths)) + b"\n"
    return {
        "input_model": "env_file",
        "env_name": env_name,
        "env_values": env_values,
        "file_name": file_name,
        "file_input_hex": str(input_hex or ""),
        "argv_values": argv_values or ["program"],
        "seed_hex": seed.hex(),
        "process_input_source": "candidate_local_env_selected_file",
        "process_input_evidence": {
            "input_model": "env_file",
            "source_path": source_path,
            "decompile_source_file": source_path,
            "entry_source_path": entry_source_path,
            "env_name": env_name,
            "file_name": file_name,
            "scan_format": format_text,
            "scan_widths": widths,
            **trigger_evidence,
        },
    }


def _candidate_decompiled_text(evidence_pack: Mapping[str, Any]) -> tuple[str, str]:
    candidate = _candidate(evidence_pack)
    names = {str(candidate.get("function_name") or "")}
    address = _normalize_address(candidate.get("address"))
    address_tokens = {address[2:].lower()} if address else set()
    for export_dir in _process_export_dirs(evidence_pack):
        for path in _candidate_decompile_paths(export_dir, {item for item in names if item}, address_tokens)[:1]:
            try:
                return (path.read_text(errors="replace")[:512 * 1024], str(path))
            except OSError:
                continue
    return ("", "")


def _env_file_error_trigger(
    evidence_pack: Mapping[str, Any],
    entry_text: str,
) -> tuple[list[str], dict[str, Any]]:
    """Infer a short option that deliberately opens one absent ordinary input file."""

    if not entry_text:
        return ([], {})
    matches: list[tuple[str, str, str]] = []
    for export_dir in _process_export_dirs(evidence_pack):
        try:
            paths = sorted(Path(export_dir).glob("*.c"))
        except OSError:
            continue
        sources: dict[str, str] = {}
        for path in paths[:1000]:
            try:
                text = path.read_text(errors="replace")[:512 * 1024]
            except OSError:
                continue
            sources[path.stem.lower()] = text
        for parser_path, parser_text in sources.items():
            if "getopt_long" not in parser_text:
                continue
            for label, body in _switch_case_bodies(parser_text):
                flag = _switch_case_label_to_option_flag(label)
                if not flag or not _getopt_optstring_takes_argument(parser_text, flag) or "optarg" not in body:
                    continue
                global_match = re.search(r"\b(DAT_[0-9A-Fa-f]+)\s*=\s*[^;]*\boptarg\b", body)
                if global_match is None:
                    continue
                global_name = global_match.group(1)
                callee_match = re.search(rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*{re.escape(global_name)}\s*\)", entry_text)
                if callee_match is None:
                    continue
                callee = callee_match.group(1)
                callee_text = next((text for stem, text in sources.items() if callee.lower() in stem), "")
                if not re.search(r"\bfopen\s*\(\s*param_1\s*,", callee_text):
                    continue
                if not re.search(r"(?:open|read)[^\n\"]*file", callee_text, re.IGNORECASE):
                    continue
                matches.append((flag, parser_path, callee))
    unique = {(flag, parser_path, callee) for flag, parser_path, callee in matches}
    if len(unique) != 1:
        return ([], {})
    flag, parser_path, callee = next(iter(unique))
    missing_path = "/__binary_agent_missing_input__"
    return (
        ["program", f"-{flag}", missing_path],
        {
            "trigger_kind": "missing_ordinary_input_file",
            "trigger_option": flag,
            "trigger_path": missing_path,
            "trigger_parser": parser_path,
            "trigger_callee": callee,
        },
    )


def _effective_process_input_model(
    evidence_pack: Mapping[str, Any],
    base_model: str,
) -> str:
    if base_model == "argv" and _candidate_uses_optarg_source(evidence_pack):
        return "argv"
    if base_model == "argv" and _source_trace_has_directory_entry_source(evidence_pack):
        return "argv_directory"
    if base_model in {"argv", "stdin"} and _requires_argv_file_stdin_model(evidence_pack):
        return "argv_file_stdin"
    return base_model


def _requires_argv_file_stdin_model(evidence_pack: Mapping[str, Any]) -> bool:
    candidate = _candidate(evidence_pack)
    sink = _semantic_api_name(candidate.get("sink"))
    if sink in {"fgets", "gets", "read"}:
        return _combined_process_uses_stdin(evidence_pack) and _combined_process_uses_file(evidence_pack)
    if _source_trace_has_direct_argv_write_source(evidence_pack):
        return False
    decompiled_text, _source_path = _combined_process_decompiled_text(evidence_pack)
    file_seed_hex, _file_name, _file_reason, _unsupported_reason = _infer_file_seed_from_process_text(decompiled_text)
    return bool(file_seed_hex)


def _source_trace_has_direct_argv_write_source(evidence_pack: Mapping[str, Any]) -> bool:
    trace = _source_trace_for_process_inputs(evidence_pack)
    input_models = _source_trace_input_models(trace)
    if input_models != {"argv"}:
        return False
    for role in _coerce_sequence(trace.get("argument_roles")):
        if not isinstance(role, Mapping) or str(role.get("role") or "") != "write_source":
            continue
        classification = str(role.get("classification") or "").lower()
        expr = str(role.get("expr") or "").lower()
        evidence = " ".join(str(item).lower() for item in _nested_strings(role))
        if (
            classification == "parameter_controlled"
            or expr.startswith("param_")
            or "parameter:" in evidence
            or "argv" in evidence
        ):
            return True
    return False


def _source_trace_has_directory_entry_source(evidence_pack: Mapping[str, Any]) -> bool:
    strings = _source_trace_strings(_source_trace_for_process_inputs(evidence_pack))
    return any(
        marker in str(text or "").lower()
        for text in strings
        for marker in ("readdir", "opendir", "dirent", "d_name")
    )


def _source_trace_input_models(trace: Mapping[str, Any]) -> set[str]:
    observations = list(_coerce_sequence(trace.get("input_observations")))
    evidence = trace.get("evidence") if isinstance(trace.get("evidence"), Mapping) else {}
    observations.extend(_coerce_sequence(evidence.get("input_observations")))
    return {
        str(item.get("input_model") or "").strip()
        for item in observations
        if isinstance(item, Mapping) and str(item.get("input_model") or "").strip()
    }


def _combined_process_uses_stdin(evidence_pack: Mapping[str, Any]) -> bool:
    trace = _source_trace_for_process_inputs(evidence_pack)
    strings = _source_trace_strings(trace) or _nested_strings(evidence_pack)
    return any(_text_mentions_stdin_source(text) for text in strings)


def _combined_process_uses_file(evidence_pack: Mapping[str, Any]) -> bool:
    trace = _source_trace_for_process_inputs(evidence_pack)
    strings = _source_trace_strings(trace) or _nested_strings(evidence_pack)
    return any(_text_mentions_file_input(text) for text in strings)


def _unsupported_process_input_source_reason(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
) -> str:
    if request.input_model not in PROCESS_DYNAMIC_INPUT_MODELS or request.input_model == "argv_directory":
        return ""
    trace = _source_trace_for_process_inputs(evidence_pack)
    strings = _source_trace_strings(trace)
    if not strings:
        return ""
    for marker in ("readdir", "opendir", "dirent", "d_name"):
        if any(marker in str(text or "").lower() for text in strings):
            return f"unsupported_directory_iteration_source:{marker}"
    return ""


def _source_trace_for_process_inputs(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    entrypoint = _semantic_entrypoint_derivation(evidence_pack)
    trace = entrypoint.get("source_to_sink_trace") if isinstance(entrypoint, Mapping) else {}
    if isinstance(trace, Mapping):
        return trace
    facts = _facts(evidence_pack)
    trace = facts.get("source_to_sink_trace")
    if isinstance(trace, Mapping):
        return trace
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    static_candidate = type_facts.get("static_candidate") if isinstance(type_facts.get("static_candidate"), Mapping) else {}
    trace = static_candidate.get("classification_trace") if isinstance(static_candidate.get("classification_trace"), Mapping) else {}
    return trace if isinstance(trace, Mapping) else {}


def _source_trace_strings(trace: Mapping[str, Any]) -> list[str]:
    if not trace:
        return []
    keys = (
        "argument_roles",
        "controlled_roles",
        "sink_argument",
        "source_artifacts",
        "sources",
        "source_flow",
        "transformations",
        "evidence",
    )
    values: list[str] = []
    for key in keys:
        values.extend(_nested_strings(trace.get(key)))
    return values


def _text_mentions_stdin_source(text: str) -> bool:
    lowered = str(text or "").lower()
    return (
        "stdin" in lowered
        or "fgets" in lowered
        or "gets(" in lowered
        or re.search(r"\bread\s*\(\s*0\s*,", lowered) is not None
        or "fd 0" in lowered
        or "file descriptor 0" in lowered
    )


def _text_mentions_file_input(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(
        marker in lowered
        for marker in (
            "fopen",
            "open64",
            "openat",
            "fread",
            "getc",
            "fgetc",
            "fseeko",
            "ftello",
            "fileno",
            "stat(",
        )
    )


def _semantic_entrypoint_derivation(
    evidence_pack: Mapping[str, Any],
    *,
    target_resolution: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    resolution = target_resolution if isinstance(target_resolution, Mapping) else {}
    entrypoint = resolution.get("entrypoint_derivation")
    if isinstance(entrypoint, Mapping):
        return entrypoint
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    entrypoint = type_facts.get("entrypoint_derivation")
    if isinstance(entrypoint, Mapping):
        return entrypoint
    entrypoint = evidence_pack.get("entrypoint_derivation")
    return entrypoint if isinstance(entrypoint, Mapping) else {}


def _derived_process_entrypoint(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
) -> Mapping[str, Any]:
    if request.input_model == "function_harness":
        return {}
    entrypoint = _semantic_entrypoint_derivation(
        evidence_pack,
        target_resolution=request.target_resolution if isinstance(request.target_resolution, Mapping) else {},
    )
    if not isinstance(entrypoint, Mapping):
        return {}
    if str(entrypoint.get("status") or "").lower() != "derived":
        return {}
    if entrypoint.get("process_input_supported") is False:
        return {}
    if _normalize_concolic_input_model(str(entrypoint.get("input_model") or "")) not in KNOWN_PROCESS_INPUT_MODELS:
        return {}
    return entrypoint


def _process_start_address(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
) -> str:
    if request.input_model == "function_harness":
        return ""
    entrypoint = _derived_process_entrypoint(evidence_pack, request)
    if entrypoint:
        return _normalize_address(entrypoint.get("entry_address"))
    return _fallback_process_entry_surface_address(evidence_pack, request)


def _fallback_process_entry_surface_address(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
) -> str:
    if request.input_model not in PROCESS_DYNAMIC_INPUT_MODELS:
        return ""
    candidate = _candidate(evidence_pack)
    sink_address = _normalize_address(request.sink_address or request.target_address)
    function_address = _normalize_address(candidate.get("address"))
    if not sink_address or sink_address == function_address:
        return ""
    entrypoint = _semantic_entrypoint_derivation(
        evidence_pack,
        target_resolution=request.target_resolution if isinstance(request.target_resolution, Mapping) else {},
    )
    if not isinstance(entrypoint, Mapping):
        return ""
    evidence = entrypoint.get("evidence") if isinstance(entrypoint.get("evidence"), Mapping) else {}
    surfaces = [item for item in _coerce_sequence(evidence.get("entry_surfaces")) if isinstance(item, Mapping)]
    if not surfaces:
        return ""
    ranked = sorted(
        surfaces,
        key=lambda item: (
            0
            if isinstance(item.get("evidence"), Mapping)
            and str(item["evidence"].get("source") or "") == "__libc_start_main_handoff"
            else 1,
            0 if str(item.get("kind") or "") == "program_entry" else 1,
        ),
    )
    for surface in ranked:
        address = _normalize_address(surface.get("address"))
        if address:
            return address
    return ""


def _semantic_api_name(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.split("@", 1)[0]
    text = text.split("(", 1)[0].strip()
    if "::" in text:
        text = text.rsplit("::", 1)[-1]
    for prefix in ("__imp_", "_imp_", "imp_"):
        lowered = text.lower()
        if lowered.startswith(prefix):
            text = text[len(prefix) :]
            break
    if text.startswith("thunk_"):
        text = text.removeprefix("thunk_")
    normalized = text.strip("_").lower()
    if normalized.endswith("_alias"):
        return normalized.removesuffix("_alias")
    return normalized


def _candidate_line_number(candidate: Mapping[str, Any], candidate_id: str = "") -> int:
    line_number = _safe_int(candidate.get("line_number"), default=0)
    if line_number > 0:
        return line_number
    parts = str(candidate_id or candidate.get("candidate_id") or "").split(":")
    if len(parts) >= 4:
        return _safe_int(parts[3], default=0)
    return 0


def run_concolic_request(
    request: ConcolicRequest,
    evidence_pack: Mapping[str, Any],
    *,
    pcode_trace: bool = False,
    ghidra_dynamic_proof: bool = False,
    ghidra_dynamic_max_steps: int = 2048,
    ghidra_dir: Path | None = None,
    artifact_dir: Path | None = None,
    llm_actions: Mapping[str, Any] | None = None,
    native_replay: bool = True,
) -> ConcolicVerdict:
    """Run a validated concolic request with the selected backend."""

    request = validate_concolic_request(evidence_pack, request)
    effective_request = request
    deterministic_candidate = (
        evidence_pack.get("deterministic_candidate")
        if isinstance(evidence_pack.get("deterministic_candidate"), Mapping)
        else {}
    )
    native_exact_lifetime = bool(
        deterministic_candidate.get("mechanism") == "reentrant_copy_invalidation"
        and deterministic_candidate.get("vulnerability_type") == "use_after_free"
    )
    effective_dynamic_max_steps = min(ghidra_dynamic_max_steps, 5000) if native_exact_lifetime else ghidra_dynamic_max_steps
    pcode_payload: Mapping[str, Any] | None = None
    if pcode_trace:
        resolved_ghidra_dir = _resolve_ghidra_dir(ghidra_dir)
        pcode_output = (
            Path(artifact_dir) / CONCOLIC_PCODE_TRACE_FILENAME
            if artifact_dir is not None
            else Path(CONCOLIC_PCODE_TRACE_FILENAME)
        )
        try:
            pcode_request = build_pcode_trace_request(
                evidence_pack,
                request,
                output_path=pcode_output,
                ghidra_dir=resolved_ghidra_dir,
            )
            pcode_payload = run_ghidra_pcode_trace(pcode_request)
            resolution = (
                pcode_payload.get("exact_sink_resolution")
                if isinstance(pcode_payload.get("exact_sink_resolution"), Mapping)
                else {}
            )
            exact_sink_address = _normalize_address(resolution.get("exact_sink_address"))
            if exact_sink_address:
                if request.input_model == "function_harness":
                    effective_request = replace(request, sink_address=exact_sink_address)
                else:
                    effective_request = replace(
                        request,
                        target_address=exact_sink_address,
                        sink_address=exact_sink_address,
                    )
        except Exception as exc:
            pcode_payload = unsupported_pcode_trace(
                request.candidate_id,
                f"pcode_trace_failed:{exc}",
                request=request,
            )

    unsupported_source_reason = _unsupported_process_input_source_reason(evidence_pack, effective_request)
    prebackend_dynamic_proof: Mapping[str, Any] | None = None
    prebackend_proof_verdict: ConcolicVerdict | None = None
    if (
        ghidra_dynamic_proof
        and not unsupported_source_reason
        and _should_try_seeded_process_dynamic_proof_before_backend(effective_request, evidence_pack)
    ):
        resolved_ghidra_dir = _resolve_ghidra_dir(ghidra_dir)
        proof_output = (
            Path(artifact_dir) / CONCOLIC_DYNAMIC_PROOF_FILENAME
            if artifact_dir is not None
            else Path(CONCOLIC_DYNAMIC_PROOF_FILENAME)
        )
        seed_verdict = ConcolicVerdict(
            candidate_id=effective_request.candidate_id,
            verdict="timeout",
            backend=effective_request.backend,
            request=effective_request.to_dict(),
            rationale="Trying deterministic process-input replay before symbolic backend exploration.",
            replay_result=_empty_replay_result("not_run", "Symbolic backend not run before seeded dynamic proof."),
        )
        allowed_sources = {"argv_absolute_path_guard"} if effective_request.input_model == "argv" else None
        prebackend_dynamic_proof, prebackend_proof_verdict = _run_dynamic_overflow_proof_attempts(
            evidence_pack,
            effective_request,
            seed_verdict,
            output_path=proof_output,
            ghidra_dir=resolved_ghidra_dir,
            max_steps=effective_dynamic_max_steps,
            allowed_sources=allowed_sources,
        )

    if prebackend_dynamic_proof is not None and not _has_decisive_dynamic_process_result(prebackend_dynamic_proof):
        effective_request = _request_with_trace_waypoints(
            effective_request,
            evidence_pack,
            prebackend_dynamic_proof,
        )

    if unsupported_source_reason:
        verdict = ConcolicVerdict(
            candidate_id=effective_request.candidate_id,
            verdict="backend_error",
            backend=effective_request.backend,
            request=effective_request.to_dict(),
            rationale=unsupported_source_reason,
            errors=(unsupported_source_reason,),
            angr_trace=_backend_error_trace(effective_request, unsupported_source_reason),
        )
    elif prebackend_dynamic_proof is not None and (
        _has_decisive_dynamic_process_result(prebackend_dynamic_proof) or native_exact_lifetime
    ):
        verdict = prebackend_proof_verdict or ConcolicVerdict(
            candidate_id=effective_request.candidate_id,
            verdict="timeout",
            backend=effective_request.backend,
            request=effective_request.to_dict(),
        )
    elif request.backend == "angr":
        verdict = _run_angr_backend(effective_request, evidence_pack)
    elif request.backend == "deterministic_seed":
        verdict = ConcolicVerdict(
            candidate_id=effective_request.candidate_id,
            verdict="timeout",
            backend=effective_request.backend,
            request=effective_request.to_dict(),
            rationale="Symbolic exploration disabled for an isolated Ghidra route; deterministic evidence seeds only.",
            replay_result=_empty_replay_result("not_run", "No symbolic backend was executed."),
            logs=("route_profile:deterministic_seed",),
        )
    else:
        verdict = ConcolicVerdict(
            candidate_id=effective_request.candidate_id,
            verdict="backend_error",
            backend=effective_request.backend,
            request=effective_request.to_dict(),
            rationale=f"Unsupported backend {effective_request.backend!r}",
            errors=[f"Unsupported backend {effective_request.backend!r}"],
        )

    if pcode_payload is None:
        pcode_payload = unsupported_pcode_trace(
            effective_request.candidate_id,
            "pcode_trace_disabled",
            request=effective_request,
        )

    pcode_payload = _annotate_pcode_sink_trace(evidence_pack, effective_request, pcode_payload)
    replay_result = dict(verdict.replay_result or _empty_replay_result("not_run", "No replay result."))
    pcode_replay = pcode_payload.get("replay") if isinstance(pcode_payload, Mapping) else None
    if isinstance(pcode_replay, Mapping):
        replay_result["ghidra_pcode_replay"] = dict(pcode_replay)
    dynamic_proof_payload: Mapping[str, Any] = unsupported_dynamic_overflow_proof(
        effective_request.candidate_id,
        "ghidra_dynamic_proof_disabled",
        request=effective_request,
    )
    proof_verdict = verdict
    if ghidra_dynamic_proof and unsupported_source_reason:
        dynamic_proof_payload = unsupported_dynamic_overflow_proof(
            effective_request.candidate_id,
            unsupported_source_reason,
            request=effective_request,
        )
        dynamic_proof_payload = dict(dynamic_proof_payload)
        dynamic_proof_payload["hybrid_witness_attempts"] = [
            {
                "source": "unsupported_process_input_source",
                "proof_status": "unsupported",
                "proof_reason": unsupported_source_reason,
            }
        ]
    elif prebackend_dynamic_proof is not None and (
        _has_decisive_dynamic_process_result(prebackend_dynamic_proof) or native_exact_lifetime
    ):
        dynamic_proof_payload = prebackend_dynamic_proof
        proof_verdict = prebackend_proof_verdict or verdict
    elif ghidra_dynamic_proof and prebackend_dynamic_proof is not None and not _concrete_input_from_verdict(verdict).get(
        "input_hex"
    ):
        dynamic_proof_payload = prebackend_dynamic_proof
        proof_verdict = _merge_seeded_witness(verdict, prebackend_proof_verdict)
    elif ghidra_dynamic_proof:
        resolved_ghidra_dir = _resolve_ghidra_dir(ghidra_dir)
        proof_output = (
            Path(artifact_dir) / CONCOLIC_DYNAMIC_PROOF_FILENAME
            if artifact_dir is not None
            else Path(CONCOLIC_DYNAMIC_PROOF_FILENAME)
        )
        dynamic_proof_payload, proof_verdict = _run_dynamic_overflow_proof_attempts(
            evidence_pack,
            effective_request,
            verdict,
            output_path=proof_output,
            ghidra_dir=resolved_ghidra_dir,
            max_steps=effective_dynamic_max_steps,
        )
    dynamic_proof_payload = _annotate_dynamic_overflow_proof(evidence_pack, effective_request, dynamic_proof_payload)
    proof_replay_result = proof_verdict.replay_result if isinstance(proof_verdict.replay_result, Mapping) else {}
    if isinstance(proof_replay_result.get("hybrid_witness_generation"), Mapping):
        replay_result["hybrid_witness_generation"] = dict(proof_replay_result["hybrid_witness_generation"])
    native_replay = (
        _native_process_replay(effective_request, proof_verdict, dynamic_proof_payload)
        if native_replay
        else {**_native_replay_not_run(), "reason": "native_replay_disabled_by_route_profile"}
    )
    dynamic_proof_payload = dict(dynamic_proof_payload)
    dynamic_proof_payload["native_replay"] = native_replay
    replay_result["native_replay"] = native_replay
    if _native_replay_refutes_memory_proof(native_replay):
        original_status = str(dynamic_proof_payload.get("status") or "")
        dynamic_proof_payload.update(
            {
                "status": "guard_refuted",
                "reason": "native_fortify_guard_prevented_memory_write",
                "modeled_status_before_native_replay": original_status,
                "overflow_bytes": 0,
                "oob_bytes": 0,
            }
        )
        proof_verdict = replace(
            proof_verdict,
            verdict="guard_refuted",
            rationale="Native replay reached a fortify guard that terminated the process before the modeled memory write.",
            logs=tuple(_unique_strings([*proof_verdict.logs, "native_fortify_guard_refuted_modeled_overflow"])),
        )
    final_verdict = _promote_ghidra_process_overflow_verdict(effective_request, proof_verdict, dynamic_proof_payload)

    return replace(
        final_verdict,
        pcode_trace=dict(pcode_payload),
        ghidra_dynamic_proof=dict(dynamic_proof_payload),
        replay_result=replay_result,
        llm_actions=dict(llm_actions or _default_llm_actions(enabled=False)),
    )


def run_native_exact_route(
    evidence_pack: Mapping[str, Any],
    *,
    binary_path: Path,
    export_dir: Path | None,
    timeout_seconds: float,
    symbolic_bytes: int = 256,
) -> dict[str, Any]:
    """Run only deterministic native replay plus the exact GDB operation tracer."""

    request, _llm_actions = _request_for_evidence_pack(
        evidence_pack,
        binary_path=Path(binary_path),
        output_dir=Path(binary_path).parent,
        export_dir=Path(export_dir) if export_dir is not None else None,
        backend="deterministic_seed",
        input_model="",
        symbolic_bytes=max(1, int(symbolic_bytes)),
        timeout_seconds=max(0.1, float(timeout_seconds)),
        llm_controller=False,
    )
    request = validate_concolic_request(evidence_pack, request)
    base_verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="timeout",
        backend="deterministic_seed",
        request=request.to_dict(),
        rationale="Native route uses deterministic evidence seeds without angr or Ghidra execution.",
        replay_result=_empty_replay_result("not_run", "No symbolic or Ghidra backend executed."),
        logs=("route_profile:native_exact_only",),
    )
    seeded = _seeded_process_dynamic_proof_attempts(request, evidence_pack, base_verdict)
    if not seeded:
        candidates = _hybrid_witness_candidates(request, evidence_pack)[:1]
        seeded = [
            (
                _verdict_with_hybrid_witness(request, evidence_pack, base_verdict, candidate),
                {"source": str(candidate.get("source") or "deterministic_native_seed")},
            )
            for candidate in candidates
        ]
    if not seeded:
        payload = unsupported_dynamic_overflow_proof(
            request.candidate_id,
            "native_route_concrete_seed_unavailable",
            request=request,
        )
        payload["native_replay"] = {
            **_native_replay_not_run(),
            "reason": "native_route_concrete_seed_unavailable",
        }
        return payload
    seeded_verdict, seed_metadata = seeded[0]
    try:
        proof_request = build_dynamic_overflow_proof_request(
            evidence_pack,
            request,
            seeded_verdict,
            output_path=Path(binary_path).parent / f".{request.candidate_id}.native-route-unused.json",
            ghidra_dir=None,
            max_steps=1,
        )
    except Exception as exc:
        payload = unsupported_dynamic_overflow_proof(
            request.candidate_id,
            f"native_route_setup_failed:{exc}",
            request=request,
        )
        payload["native_replay"] = {
            **_native_replay_not_run(),
            "reason": f"native_route_setup_failed:{exc}",
        }
        return payload
    payload = unsupported_dynamic_overflow_proof(
        request.candidate_id,
        "native_exact_route_pending",
        request=proof_request,
    )
    payload.update(
        {
            "proof_kind": "native_exact_route",
            "proof_scope": proof_request.proof_scope,
            "sink_address": proof_request.sink_address,
            "process_input_setup": {
                "status": "configured" if not proof_request.process_input_setup_reason else "unsupported",
                "reason": proof_request.process_input_setup_reason,
                "input_model": proof_request.input_model,
                "concrete_input_hex": proof_request.concrete_input_hex,
                "stdin_input_hex": proof_request.stdin_input_hex,
                "file_input_hex": proof_request.file_input_hex,
                "file_name": proof_request.file_name,
                "process_input_source": proof_request.process_input_source,
                "process_input_evidence": dict(proof_request.process_input_evidence),
            },
            "seed": dict(seed_metadata),
            "angr_executed": False,
            "ghidra_executed": False,
            "qemu_executed": False,
        }
    )
    native = _native_process_replay(request, seeded_verdict, payload)
    payload["native_replay"] = native
    trace = native.get("exact_operation_trace") if isinstance(native.get("exact_operation_trace"), Mapping) else {}
    exact = bool(trace.get("status") == "reached" and trace.get("operation_address"))
    payload["exact_sink_reached"] = exact
    payload["sink_reached"] = exact
    if exact:
        payload["sink_address"] = str(trace.get("operation_address") or proof_request.sink_address)
        payload["status"] = "native_exact_reached"
        payload["reason"] = "native_exact_operation_trace_reached"
    else:
        payload["status"] = "sink_unreached"
        payload["reason"] = str(trace.get("reason") or native.get("reason") or "native_exact_operation_unreached")
    return payload


def _merge_seeded_witness(
    backend_verdict: ConcolicVerdict,
    seeded_verdict: ConcolicVerdict | None,
) -> ConcolicVerdict:
    if seeded_verdict is None or seeded_verdict.witness is None:
        return backend_verdict
    replay_result = dict(backend_verdict.replay_result or {})
    seeded_replay = seeded_verdict.replay_result if isinstance(seeded_verdict.replay_result, Mapping) else {}
    if isinstance(seeded_replay.get("hybrid_witness_generation"), Mapping):
        replay_result["hybrid_witness_generation"] = dict(seeded_replay["hybrid_witness_generation"])
    return replace(
        backend_verdict,
        witness=seeded_verdict.witness,
        replay_result=replay_result,
        logs=tuple(_unique_strings([*backend_verdict.logs, *seeded_verdict.logs])),
    )


def _dynamic_proof_verdict_attempts(
    request: ConcolicRequest,
    evidence_pack: Mapping[str, Any],
    verdict: ConcolicVerdict,
) -> list[tuple[ConcolicVerdict, dict[str, Any]]]:
    concrete = _concrete_input_from_verdict(verdict)
    if concrete.get("input_hex"):
        return [(verdict, {"source": "angr_witness"})]
    if verdict.verdict in SAFE_CONCOLIC_VERDICTS and request.input_model == "argv":
        attempts = _seeded_process_dynamic_proof_attempts(request, evidence_pack, verdict)
        return attempts or [(verdict, {"source": "no_concrete_witness"})]
    if verdict.verdict != "timeout":
        attempts = _seeded_process_dynamic_proof_attempts(request, evidence_pack, verdict)
        if attempts:
            return attempts
        if request.input_model == "function_harness" and _deterministic_seed_mutations(
            evidence_pack,
            request.symbolic_bytes,
        ):
            attempts = []
            for candidate in _hybrid_witness_candidates(request, evidence_pack)[:2]:
                attempt_verdict = _verdict_with_hybrid_witness(request, evidence_pack, verdict, candidate)
                attempts.append((attempt_verdict, {"source": str(candidate.get("source") or "hybrid_witness")}))
            if attempts:
                return attempts
        return [(verdict, {"source": "no_concrete_witness"})]
    if request.input_model in PROCESS_DYNAMIC_INPUT_MODELS and not (
        request.input_model == "argv" and _argv_absolute_path_guard_prefix(evidence_pack)
    ):
        attempts = _seeded_process_dynamic_proof_attempts(request, evidence_pack, verdict)
        return attempts or [(verdict, {"source": "no_concrete_witness"})]
    attempts: list[tuple[ConcolicVerdict, dict[str, Any]]] = []
    for candidate in _hybrid_witness_candidates(request, evidence_pack):
        attempt_verdict = _verdict_with_hybrid_witness(request, evidence_pack, verdict, candidate)
        attempts.append((attempt_verdict, {"source": str(candidate.get("source") or "hybrid_witness")}))
    if attempts:
        return attempts
    return [(verdict, {"source": "no_concrete_witness"})]


def _run_dynamic_overflow_proof_attempts(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
    verdict: ConcolicVerdict,
    *,
    output_path: Path,
    ghidra_dir: Path | None,
    max_steps: int,
    allowed_sources: set[str] | None = None,
) -> tuple[Mapping[str, Any], ConcolicVerdict]:
    dynamic_proof_payload: Mapping[str, Any] = unsupported_dynamic_overflow_proof(
        request.candidate_id,
        "ghidra_dynamic_proof_disabled",
        request=request,
    )
    proof_verdict = verdict
    proof_attempts = []
    process_witness_attempts = []
    for attempt_verdict, attempt in _dynamic_proof_verdict_attempts(request, evidence_pack, verdict):
        attempt_source = str(attempt.get("source") or "")
        if allowed_sources is not None and attempt_source not in allowed_sources:
            continue
        proof_request: GhidraDynamicProofRequest | None = None
        try:
            proof_request = build_dynamic_overflow_proof_request(
                evidence_pack,
                request,
                attempt_verdict,
                output_path=output_path,
                ghidra_dir=ghidra_dir,
                max_steps=max_steps,
            )
            attempt_summary = dict(attempt)
            attempt_summary["concrete_input_hex"] = proof_request.concrete_input_hex
            setup_blocker = _process_input_setup_blocker(proof_request)
            if (
                proof_request.proof_scope == "process_entrypoint"
                and proof_request.input_model not in PROCESS_DYNAMIC_INPUT_MODELS
            ):
                reason = f"unsupported_process_input_setup:input_model_{proof_request.input_model}"
                dynamic_proof_payload = unsupported_dynamic_overflow_proof(
                    request.candidate_id,
                    reason,
                    request=proof_request,
                )
            elif setup_blocker:
                dynamic_proof_payload = unsupported_dynamic_overflow_proof(
                    request.candidate_id,
                    setup_blocker,
                    request=proof_request,
                )
            else:
                dynamic_proof_payload = run_ghidra_dynamic_overflow_proof(proof_request)
                dynamic_proof_payload = _apply_call_context_feasibility_gate(
                    evidence_pack,
                    request,
                    dynamic_proof_payload,
                )
            attempt_summary["proof_status"] = str(dynamic_proof_payload.get("status") or "")
            attempt_summary["proof_reason"] = str(dynamic_proof_payload.get("reason") or "")
            proof_attempts.append(attempt_summary)
            row = _process_witness_attempt_row(
                request,
                proof_request=proof_request,
                attempt=attempt_summary,
                proof_payload=dynamic_proof_payload,
            )
            if row:
                process_witness_attempts.append(row)
            proof_verdict = attempt_verdict
            if _has_decisive_dynamic_process_result(dynamic_proof_payload):
                break
        except Exception as exc:
            dynamic_proof_payload = unsupported_dynamic_overflow_proof(
                request.candidate_id,
                f"ghidra_dynamic_proof_failed:{exc}",
                request=request,
            )
            proof_attempts.append(
                {
                    "source": attempt_source,
                    "proof_status": "unsupported",
                    "proof_reason": str(exc),
                }
            )
            row = _process_witness_attempt_row(
                request,
                proof_request=proof_request,
                attempt={"source": attempt_source, "proof_status": "unsupported", "proof_reason": str(exc)},
                proof_payload=dynamic_proof_payload,
                error=str(exc),
            )
            if row:
                process_witness_attempts.append(row)
            if attempt_source == "angr_witness":
                break
    if proof_attempts:
        dynamic_proof_payload = dict(dynamic_proof_payload)
        dynamic_proof_payload["hybrid_witness_attempts"] = proof_attempts
    if process_witness_attempts:
        attempt_path = _write_process_witness_attempt_artifact(
            output_path.parent / CONCOLIC_PROCESS_WITNESS_ATTEMPT_FILENAME,
            request,
            attempts=process_witness_attempts,
        )
        dynamic_proof_payload = dict(dynamic_proof_payload)
        dynamic_proof_payload["process_witness_attempt_artifact"] = attempt_path.name
    return dynamic_proof_payload, proof_verdict


def _process_witness_attempt_row(
    request: ConcolicRequest,
    *,
    proof_request: GhidraDynamicProofRequest | None,
    attempt: Mapping[str, Any],
    proof_payload: Mapping[str, Any],
    error: str = "",
) -> dict[str, Any]:
    if request.input_model not in PROCESS_DYNAMIC_INPUT_MODELS:
        return {}
    proof_scope = str((proof_request.to_dict() if proof_request is not None else {}).get("proof_scope") or "")
    if proof_scope and proof_scope != "process_entrypoint":
        return {}
    proof_status = str(proof_payload.get("status") or attempt.get("proof_status") or "")
    proof_reason = str(proof_payload.get("reason") or attempt.get("proof_reason") or error or "")
    process_setup = (
        dict(proof_payload.get("process_input_setup"))
        if isinstance(proof_payload.get("process_input_setup"), Mapping)
        else {}
    )
    request_payload = proof_request.to_dict() if proof_request is not None else request.to_dict()
    if proof_request is not None:
        process_setup.setdefault("input_model", proof_request.input_model)
        process_setup.setdefault("argv_values", list(proof_request.argv_values))
        process_setup.setdefault("stdin_input_hex", proof_request.stdin_input_hex)
        process_setup.setdefault("file_input_hex", proof_request.file_input_hex)
        process_setup.setdefault("file_name", proof_request.file_name)
        process_setup.setdefault("env_name", proof_request.env_name)
        process_setup.setdefault("env_values", dict(proof_request.env_values))
        process_setup.setdefault("process_input_source", proof_request.process_input_source)
        process_setup.setdefault("process_input_evidence", dict(proof_request.process_input_evidence))
        if not process_setup.get("status"):
            process_setup["status"] = (
                "configured" if not proof_reason.startswith("unsupported_process_input_setup") else "unsupported"
            )
    dynamic_proof_artifact = proof_request.output_path.name if proof_request is not None else ""
    blockers = [
        item
        for item in _unique_strings(
            [
                proof_reason if _looks_like_process_witness_blocker(proof_reason) else "",
                error,
                *[str(value) for value in _coerce_sequence(process_setup.get("blockers")) if str(value)],
            ]
        )
        if item
    ]
    observed = _has_dynamic_memory_safety_proof(proof_payload)
    status = _process_witness_attempt_status(observed, proof_status, proof_reason, blockers)
    return {
        "attempt_source": str(attempt.get("source") or ""),
        "status": status,
        "candidate_id": request.candidate_id,
        "input_model": request.input_model,
        "proof_scope": proof_scope
        or ("function_harness" if request.input_model == "function_harness" else "process_entrypoint"),
        "dynamic_proof_status": proof_status,
        "dynamic_proof_reason": proof_reason,
        "dynamic_proof_observed": observed,
        "dynamic_proof_artifact": dynamic_proof_artifact,
        "setup_configured": str(process_setup.get("status") or "") == "configured",
        "process_input_setup": process_setup,
        "blockers": blockers,
        "request": dict(request_payload),
    }


def _process_witness_attempt_status(
    observed: bool,
    proof_status: str,
    proof_reason: str,
    blockers: Sequence[str],
) -> str:
    if observed:
        return "observed"
    if proof_status == "unsupported" or proof_reason.startswith("unsupported_process_input_setup"):
        return "unsupported"
    if blockers:
        return "blocked"
    return "attempted"


def _looks_like_process_witness_blocker(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(marker in lowered for marker in ("unsupported", "missing", "failed", "blocked", "unavailable", "invalid"))


def _write_process_witness_attempt_artifact(
    path: Path,
    request: ConcolicRequest,
    *,
    attempts: Sequence[Mapping[str, Any]],
) -> Path:
    rows = [dict(row) for row in attempts if isinstance(row, Mapping)]
    status_counts: dict[str, int] = {}
    input_model_counts: dict[str, int] = {}
    blockers: list[str] = []
    for row in rows:
        status = str(row.get("status") or "")
        if status:
            status_counts[status] = status_counts.get(status, 0) + 1
        model = str(row.get("input_model") or request.input_model)
        if model:
            input_model_counts[model] = input_model_counts.get(model, 0) + 1
        blockers.extend(str(item) for item in _coerce_sequence(row.get("blockers")) if str(item))
    payload = {
        "artifact_kind": "process_witness_attempt",
        "schema_version": 1,
        "candidate_id": request.candidate_id,
        "input_model": request.input_model,
        "proof_scope": "process_entrypoint",
        "status": "observed"
        if any(row.get("status") == "observed" for row in rows)
        else "unsupported"
        if any(row.get("status") == "unsupported" for row in rows)
        else "blocked"
        if any(row.get("status") == "blocked" for row in rows)
        else "attempted",
        "attempt_count": len(rows),
        "observed_count": sum(1 for row in rows if row.get("status") == "observed"),
        "unsupported_count": sum(1 for row in rows if row.get("status") == "unsupported"),
        "blocked_count": sum(1 for row in rows if row.get("status") == "blocked"),
        "status_counts": status_counts,
        "input_model_counts": input_model_counts,
        "blockers": _unique_strings(blockers),
        "attempts": rows,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


def _should_try_seeded_process_dynamic_proof_before_backend(
    request: ConcolicRequest,
    evidence_pack: Mapping[str, Any],
) -> bool:
    if request.input_model == "argv":
        return any(
            str(candidate.get("source") or "") == "argv_absolute_path_guard"
            for candidate in _hybrid_witness_candidates(request, evidence_pack)
        )
    if request.input_model == "file":
        seed_hex, _file_name, _file_reason, unsupported_reason, _source_path = _infer_file_seed_from_evidence(
            evidence_pack
        )
        return bool(seed_hex) and not unsupported_reason
    if request.input_model in {"socket_service", "http_daemon"}:
        return True
    if request.input_model in {"stdin", "env", "env_file"}:
        return bool(_hybrid_witness_candidates(request, evidence_pack))
    if request.input_model != "argv_file_stdin":
        return False
    spec = _combined_process_input_spec(evidence_pack)
    return bool(str(spec.get("file_input_hex") or "")) and not str(spec.get("unsupported_reason") or "")


def _seeded_process_dynamic_proof_attempts(
    request: ConcolicRequest,
    evidence_pack: Mapping[str, Any],
    verdict: ConcolicVerdict,
) -> list[tuple[ConcolicVerdict, dict[str, Any]]]:
    if request.input_model == "argv":
        attempts: list[tuple[ConcolicVerdict, dict[str, Any]]] = []
        for candidate in _hybrid_witness_candidates(request, evidence_pack)[:2]:
            attempt_verdict = _verdict_with_hybrid_witness(request, evidence_pack, verdict, candidate)
            attempts.append((attempt_verdict, {"source": str(candidate.get("source") or "seeded_argv_replay")}))
        return attempts
    if request.input_model == "argv_directory":
        attempts: list[tuple[ConcolicVerdict, dict[str, Any]]] = []
        for candidate in _hybrid_witness_candidates(request, evidence_pack)[:1]:
            attempt_verdict = _verdict_with_hybrid_witness(request, evidence_pack, verdict, candidate)
            attempts.append((attempt_verdict, {"source": str(candidate.get("source") or "seeded_directory_entry_replay")}))
        return attempts
    if request.input_model == "file":
        attempts: list[tuple[ConcolicVerdict, dict[str, Any]]] = []
        for candidate in _hybrid_witness_candidates(request, evidence_pack)[:2]:
            attempt_verdict = _verdict_with_hybrid_witness(request, evidence_pack, verdict, candidate)
            attempts.append((attempt_verdict, {"source": str(candidate.get("source") or "seeded_file_replay")}))
        return attempts
    if request.input_model in {"socket_service", "http_daemon"}:
        return [
            (
                _verdict_with_hybrid_witness(request, evidence_pack, verdict, candidate),
                {"source": str(candidate.get("source") or "deterministic_service_request")},
            )
            for candidate in _hybrid_witness_candidates(request, evidence_pack)[:1]
        ]
    if request.input_model in {"stdin", "env", "env_file"}:
        candidates = _hybrid_witness_candidates(request, evidence_pack)[:1]
        return [
            (
                _verdict_with_hybrid_witness(request, evidence_pack, verdict, candidate),
                {"source": str(candidate.get("source") or "deterministic_process_input")},
            )
            for candidate in candidates
        ]
    if request.input_model != "argv_file_stdin":
        return []
    spec = _combined_process_input_spec(evidence_pack)
    if not str(spec.get("file_input_hex") or ""):
        return []
    attempts: list[tuple[ConcolicVerdict, dict[str, Any]]] = []
    for candidate in _hybrid_witness_candidates(request, evidence_pack)[:1]:
        attempt_verdict = _verdict_with_hybrid_witness(request, evidence_pack, verdict, candidate)
        attempts.append((attempt_verdict, {"source": str(candidate.get("source") or "seeded_process_file_replay")}))
    return attempts


def _verdict_with_hybrid_witness(
    request: ConcolicRequest,
    evidence_pack: Mapping[str, Any],
    verdict: ConcolicVerdict,
    candidate: Mapping[str, Any],
) -> ConcolicVerdict:
    concrete = bytes(candidate.get("bytes") or b"")
    source = str(candidate.get("source") or "hybrid_witness")
    witness = _witness_for_input(
        request.input_model,
        concrete,
        evidence_pack=evidence_pack,
        function_args=dict(_function_harness_spec(evidence_pack) or {}),
    )
    replay_result = dict(verdict.replay_result or _empty_replay_result("not_run", "No concrete witness was produced."))
    replay_result["hybrid_witness_generation"] = {
        "status": "generated",
        "source": source,
        "input_model": request.input_model,
        "input_hex": concrete.hex(),
        "original_verdict": verdict.verdict,
        "reason": "Generated a bounded concrete input for Ghidra process replay after symbolic execution did not produce a witness.",
    }
    return replace(
        verdict,
        witness=witness,
        replay_result=replay_result,
        logs=tuple(_unique_strings([*verdict.logs, f"hybrid_witness:{source}"])),
    )


def _hybrid_witness_candidates(request: ConcolicRequest, evidence_pack: Mapping[str, Any]) -> list[dict[str, Any]]:
    if request.input_model not in PROCESS_DYNAMIC_INPUT_MODELS and request.input_model != "function_harness":
        return []
    size = _hybrid_witness_size(request, evidence_pack)
    candidates: list[dict[str, Any]] = []

    def add(raw: bytes, source: str, *, preserve_size: bool = False) -> None:
        if not raw:
            return
        if preserve_size:
            concrete = raw[: 1024 * 1024]
        else:
            concrete = raw[: request.symbolic_bytes]
            if len(concrete) < size:
                concrete = concrete + (b"A" * (size - len(concrete)))
            concrete = concrete[: request.symbolic_bytes]
        if not concrete:
            return
        if any(item["bytes"] == concrete for item in candidates):
            return
        candidates.append({"bytes": concrete, "source": source})

    for index, seed in enumerate(request.seed_mutations):
        add(_seed_bytes(seed), f"seed_mutation:{index}")
        if len(candidates) >= 4:
            return candidates
    for constraint in request.constraints:
        prefix = _constraint_prefix_bytes(constraint)
        if prefix:
            add(prefix, "constraint_prefix")
            if len(candidates) >= 4:
                return candidates
    reproducer = _facts(evidence_pack).get("reproducer_hypothesis")
    if isinstance(reproducer, Mapping):
        for key in ("input_hex", "concrete_input_hex", "seed_hex"):
            value = str(reproducer.get(key) or "")
            if value:
                add(_seed_bytes("hex:" + value), f"reproducer:{key}", preserve_size=True)
                if len(candidates) >= 4:
                    return candidates
        for key in ("seed", "input", "argv", "stdin"):
            value = reproducer.get(key)
            if isinstance(value, str) and value:
                add(_seed_bytes(value), f"reproducer:{key}", preserve_size=True)
                if len(candidates) >= 4:
                    return candidates
    absolute_guard_prefix = _argv_absolute_path_guard_prefix(evidence_pack) if request.input_model == "argv" else b""
    if absolute_guard_prefix:
        add(absolute_guard_prefix, "argv_absolute_path_guard")
        if len(candidates) >= 4:
            return candidates
    if request.input_model == "env_file":
        spec = _env_selected_file_input_spec(evidence_pack)
        seed_hex = str(spec.get("seed_hex") or "")
        if seed_hex:
            add(_seed_bytes("hex:" + seed_hex), "env_selected_file_format", preserve_size=True)
            return candidates[:4]
    if request.input_model == "file":
        seed_hex, _file_name, file_reason, unsupported_reason, _source_path = _infer_file_seed_from_evidence(
            evidence_pack
        )
        if seed_hex:
            add(_seed_bytes("hex:" + seed_hex), f"file_format:{file_reason}")
            return candidates[:4]
        elif unsupported_reason:
            return candidates[:4]
    default_source = "directory_entry_name_pattern" if request.input_model == "argv_directory" else "deterministic_overflow_pattern"
    add(b"A" * size, default_source)
    return candidates[:4]


def _witness_plan_seed_mutations(evidence_pack: Mapping[str, Any], *, input_model: str) -> tuple[str, ...]:
    if input_model == "argv_directory":
        return ()
    if input_model == "argv" and _argv_absolute_path_guard_prefix(evidence_pack):
        return ()
    try:
        plan = build_witness_plan(evidence_pack)
    except Exception:
        return ()
    seeds: list[str] = []
    for replay_input in plan.replay_request_inputs:
        if isinstance(replay_input, Mapping):
            seeds.extend(_witness_replay_input_seed_values(replay_input, input_model=input_model))
    return tuple(_unique_strings(seeds))


def _file_format_seed_mutations(evidence_pack: Mapping[str, Any], *, input_model: str) -> tuple[str, ...]:
    if input_model == "env_file":
        seed_hex = str(_env_selected_file_input_spec(evidence_pack).get("seed_hex") or "")
        return (f"hex:{seed_hex}",) if seed_hex else ()
    if input_model != "file":
        return ()
    seed_hex, _file_name, _file_reason, unsupported_reason, _source_path = _infer_file_seed_from_evidence(
        evidence_pack
    )
    return (f"hex:{seed_hex}",) if seed_hex and not unsupported_reason else ()


def _witness_replay_input_seed_values(replay_input: Mapping[str, Any], *, input_model: str) -> list[str]:
    replay_model = str(replay_input.get("input_model") or "")
    values: list[str] = []

    def add(value: Any) -> None:
        text = str(value or "")
        if text:
            values.append(text[:4096])

    if input_model == "argv":
        if replay_model != "argv":
            return []
        argv = [str(item) for item in _coerce_sequence(replay_input.get("argv")) if str(item)]
        if argv:
            add(max(argv, key=len))
        return values
    if input_model == "stdin":
        if replay_model not in {"stdin", "argv_file_stdin"}:
            return []
        add(replay_input.get("stdin"))
        return values
    if input_model in {"file", "config"}:
        if replay_model != "file":
            return []
        for key in ("file_input_hex", "file_hex", "file_seed_hex", "file_content_hex", "file_bytes_hex"):
            value = str(replay_input.get(key) or "").strip()
            if not value:
                continue
            try:
                bytes.fromhex(value)
            except ValueError:
                continue
            add("hex:" + value)
            return values
        add(replay_input.get("file_content") or replay_input.get("content") or replay_input.get("payload"))
        return values
    if input_model == "env":
        if replay_model != "env" or not isinstance(replay_input.get("env"), Mapping):
            return []
        for value in replay_input["env"].values():
            add(value)
        return values
    if input_model == "argv_file_stdin":
        if replay_model != "argv_file_stdin":
            return []
        add(replay_input.get("stdin"))
        return values
    if input_model == "argv_directory":
        if replay_model != "argv_directory":
            return []
        for entry in _coerce_sequence(replay_input.get("directory_entries")):
            if isinstance(entry, Mapping):
                add(entry.get("name") or entry.get("content"))
        return values
    return values


def _deterministic_seed_mutations(evidence_pack: Mapping[str, Any], symbolic_bytes: int) -> tuple[str, ...]:
    trace = _candidate_classification_trace(evidence_pack)
    if isinstance(trace.get("cursor_limit_read"), Mapping):
        seeds: list[str] = []
        for marker in (0x80, 0xFF):
            seeds.append("hex:" + bytes([marker]).hex())
        return tuple(seeds)
    if not _memory_candidate_prefers_function_harness(evidence_pack):
        return ()
    seed_len = max(1, min(_safe_int(symbolic_bytes, default=32), 64))
    return ("hex:" + (b"A" * seed_len).hex(),)


def _argv_absolute_path_guard_prefix(evidence_pack: Mapping[str, Any]) -> bytes:
    candidate = _candidate(evidence_pack)
    line_text = str(candidate.get("line_text") or "")
    argv_exprs = _argv_index_source_exprs(line_text)
    trace = _source_trace_for_process_inputs(evidence_pack)
    for role in _coerce_sequence(trace.get("argument_roles")):
        if isinstance(role, Mapping) and str(role.get("role") or "") == "write_source":
            argv_exprs.extend(_argv_index_source_exprs(str(role.get("expr") or "")))
    argv_exprs = _unique_strings(argv_exprs)
    if not argv_exprs:
        return b""
    line_number = _candidate_line_number(candidate, str(candidate.get("candidate_id") or _candidate_id_from_pack(evidence_pack)))
    source_text, _source_path = _combined_process_decompiled_text(evidence_pack)
    if not source_text:
        return b""
    lines = source_text.splitlines()
    if line_number <= 0 or line_number > len(lines):
        window = "\n".join(lines)
    else:
        window = "\n".join(lines[max(0, line_number - 12) : line_number])
    normalized = re.sub(r"\s+", "", window)
    for expr in argv_exprs:
        escaped = re.escape(re.sub(r"\s+", "", expr))
        if re.search(rf"(?:\*\(char\*\){escaped}|\*{escaped}|{escaped}\[0\])==(?:'/'|0x2[fF])", normalized):
            return b"/"
    return b""


def _argv_index_source_exprs(line_text: str) -> list[str]:
    text = str(line_text or "")
    exprs = re.findall(r"\b(?:argv|param_\d+)\s*\[[^\]]+\]", text)
    return _unique_strings(exprs)


def _hybrid_witness_size(request: ConcolicRequest, evidence_pack: Mapping[str, Any]) -> int:
    candidate = _candidate(evidence_pack)
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    trace = _candidate_classification_trace(evidence_pack)
    if request.input_model == "function_harness" and isinstance(trace.get("cursor_limit_read"), Mapping):
        return 1
    if request.input_model == "argv_directory":
        return max(1, min(int(request.symbolic_bytes or 1), 255))
    wanted = max(
        _candidate_write_size_bytes(evidence_pack, None),
        capacity + 1 if capacity > 0 else 0,
        min(max(request.symbolic_bytes, 1), 32),
    )
    return max(1, min(int(request.symbolic_bytes or 1), wanted))


def _constraint_prefix_bytes(constraint: str) -> bytes:
    match = re.match(r"^(?:prefix|starts_with)\s*[:=]\s*(.+)$", str(constraint or "").strip(), re.IGNORECASE)
    if not match:
        return b""
    return _seed_bytes(match.group(1).strip())


def build_pcode_trace_request(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
    *,
    output_path: Path,
    ghidra_dir: Path | None = None,
    max_steps: int = 2048,
) -> PcodeTraceRequest:
    """Build and validate a Ghidra concrete p-code trace request."""

    validate_concolic_request(evidence_pack, request)
    candidate = _candidate(evidence_pack)
    function_address = _normalize_address(candidate.get("address"))
    target_address = _normalize_address(request.target_address)
    process_start_address = _process_start_address(evidence_pack, request)
    if request.input_model != "function_harness" and not process_start_address:
        raise ValueError("P-code trace for process input requires a derived entrypoint start address")
    start_address = process_start_address or function_address or target_address
    if not target_address:
        raise ValueError("P-code trace request is missing target_address")
    allowed_addresses = _allowed_addresses(
        evidence_pack,
        export_dir=request.export_dir,
        target_resolution=request.target_resolution,
    )
    if target_address not in allowed_addresses:
        raise ValueError(f"P-code target_address {target_address!r} is not present in the evidence pack")
    if ghidra_dir is not None and not Path(ghidra_dir).exists():
        raise FileNotFoundError(f"Ghidra directory not found: {ghidra_dir}")
    max_steps = int(max_steps or 2048)
    if max_steps <= 0 or max_steps > 100000:
        raise ValueError(f"max_steps must be between 1 and 100000; got {max_steps}")
    return PcodeTraceRequest(
        candidate_id=request.candidate_id,
        binary_path=request.binary_path,
        output_path=Path(output_path),
        ghidra_dir=Path(ghidra_dir) if ghidra_dir is not None else None,
        function_address=function_address,
        start_address=start_address,
        target_address=target_address,
        input_model=request.input_model,
        max_steps=max_steps,
        timeout_seconds=request.timeout_seconds,
        sink_name=str(candidate.get("sink") or ""),
        target_buffer=str(candidate.get("target_buffer") or candidate.get("source_object") or ""),
        offset_expr=str(candidate.get("offset_expr") or ""),
        line_text=str(candidate.get("line_text") or ""),
        line_number=_candidate_line_number(candidate, request.candidate_id),
    )


def unsupported_pcode_trace(
    candidate_id: str,
    reason: str,
    *,
    request: ConcolicRequest | PcodeTraceRequest | None = None,
) -> dict[str, Any]:
    """Return a stable unsupported p-code trace artifact."""

    request_payload: Mapping[str, Any] = request.to_dict() if request is not None else {}
    return {
        "schema_version": 1,
        "trace_kind": "ghidra_pcode",
        "candidate_id": candidate_id,
        "status": "unsupported",
        "unsupported": True,
        "reason": str(reason),
        "request": dict(request_payload),
        "pcode_ops": [],
        "instructions": [],
        "memory_writes": [],
        "store_catalog": [],
        "call_catalog": [],
        "replay": {"status": "unsupported", "reason": str(reason)},
    }


def build_dynamic_overflow_proof_request(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
    verdict: ConcolicVerdict,
    *,
    output_path: Path,
    ghidra_dir: Path | None = None,
    max_steps: int = 2048,
) -> GhidraDynamicProofRequest:
    """Build and validate a Ghidra concrete memory-safety proof request."""

    allowed_addresses = _allowed_addresses(evidence_pack)
    if request.target_address in allowed_addresses and (not request.sink_address or request.sink_address in allowed_addresses):
        validate_concolic_request(evidence_pack, request)
    elif not _is_address_string(request.target_address) or (request.sink_address and not _is_address_string(request.sink_address)):
        raise ValueError(
            f"Invalid dynamic proof address: target={request.target_address!r}, sink={request.sink_address!r}"
        )
    candidate = _candidate_for_memory_proof(evidence_pack, export_dir=request.export_dir)
    concrete = _concrete_input_from_verdict(verdict)
    if not concrete.get("input_hex"):
        raise ValueError("Ghidra dynamic proof requires a concrete witness input")
    if ghidra_dir is not None and not Path(ghidra_dir).exists():
        raise FileNotFoundError(f"Ghidra directory not found: {ghidra_dir}")
    sink_address = _normalize_address(request.sink_address or request.target_address or candidate.get("operation_address"))
    if not sink_address:
        raise ValueError("Ghidra dynamic proof requires an exact sink address")
    function_address = _normalize_address(candidate.get("address"))
    if request.input_model != "function_harness" and function_address and sink_address == function_address:
        resolution = request.target_resolution if isinstance(request.target_resolution, Mapping) else {}
        exact_from_resolution = _normalize_address(
            resolution.get("sink_address") or resolution.get("callsite_address") or resolution.get("target_address")
        )
        if not (exact_from_resolution and exact_from_resolution != function_address):
            raise ValueError("Ghidra dynamic proof requires an exact sink address distinct from the function entry")
    process_start_address = _process_start_address(evidence_pack, request)
    if request.input_model != "function_harness" and not process_start_address:
        raise ValueError("Ghidra dynamic proof for process input requires a derived entrypoint start address")
    start_address = process_start_address or function_address or sink_address
    max_steps = int(max_steps or 2048)
    if max_steps <= 0 or max_steps > 100000:
        raise ValueError(f"max_steps must be between 1 and 100000; got {max_steps}")
    proof_scope = "function_harness" if request.input_model == "function_harness" else "process_entrypoint"
    process_inputs = _dynamic_process_input_payload(evidence_pack, request, concrete)
    process_input_evidence = (
        dict(process_inputs.get("process_input_evidence") or {})
        if isinstance(process_inputs.get("process_input_evidence"), Mapping)
        else {}
    )
    dynamic_hints = _candidate_dynamic_proof_hints(evidence_pack)
    concrete_len = len(str(concrete.get("input_hex") or "")) // 2
    capacity_bytes = _safe_int(candidate.get("capacity_bytes"), default=0)
    if capacity_bytes <= 0 and bool(dynamic_hints.get("capacity_from_concrete_input")):
        capacity_bytes = concrete_len
    offset_expr = str(candidate.get("offset_expr") or "0")
    if bool(dynamic_hints.get("offset_from_concrete_input")):
        offset_expr = str(concrete_len)
    return GhidraDynamicProofRequest(
        candidate_id=request.candidate_id,
        binary_path=request.binary_path,
        output_path=Path(output_path),
        ghidra_dir=Path(ghidra_dir) if ghidra_dir is not None else None,
        function_address=function_address,
        start_address=start_address,
        sink_address=sink_address,
        proof_scope=proof_scope,
        input_model=request.input_model,
        env_name=str(process_inputs.get("env_name") or ""),
        env_values={str(key): str(value) for key, value in dict(process_inputs.get("env_values") or {}).items()},
        concrete_input_hex=str(concrete.get("input_hex") or ""),
        argv_values=tuple(str(item) for item in process_inputs.get("argv_values", ())),
        stdin_input_hex=str(process_inputs.get("stdin_input_hex") or ""),
        file_input_hex=str(process_inputs.get("file_input_hex") or ""),
        file_name=str(process_inputs.get("file_name") or ""),
        process_input_source=str(process_inputs.get("process_input_source") or ""),
        process_input_evidence=process_input_evidence,
        process_input_setup_reason=str(process_inputs.get("unsupported_reason") or ""),
        static_path_addresses=_static_candidate_path_addresses(
            evidence_pack,
            request,
            entrypoint=_derived_process_entrypoint(evidence_pack, request),
        ),
        function_harness=dict(_function_harness_spec(evidence_pack) or {}),
        max_steps=max_steps,
        timeout_seconds=request.timeout_seconds,
        sink_name=str(candidate.get("sink") or ""),
        vulnerability_type=str(candidate.get("vulnerability_type") or "memory_overflow"),
        write_relation=str(candidate.get("write_relation") or ""),
        target_buffer=str(candidate.get("target_buffer") or candidate.get("source_object") or ""),
        destination_kind=str(candidate.get("destination_kind") or ""),
        capacity_bytes=capacity_bytes,
        capacity_source=str(candidate.get("capacity_source") or ""),
        capacity_basis=str(candidate.get("capacity_basis") or ""),
        offset_expr=offset_expr,
        write_size_bytes=_candidate_write_size_bytes(evidence_pack, verdict),
        line_text=str(candidate.get("line_text") or ""),
        line_number=_candidate_line_number(candidate, request.candidate_id),
    )


def _dynamic_process_input_payload(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
    concrete: Mapping[str, Any],
) -> dict[str, Any]:
    if request.input_model == "argv":
        return _argv_option_process_input_spec(evidence_pack, input_hex=str(concrete.get("input_hex") or ""))
    if request.input_model == "stdin":
        return _stdin_process_input_spec(evidence_pack, stdin_input_hex=str(concrete.get("input_hex") or ""))
    if request.input_model == "argv_directory":
        return _directory_process_input_spec(evidence_pack)
    if request.input_model == "file":
        return _file_process_input_spec(evidence_pack, input_hex=str(concrete.get("input_hex") or ""))
    if request.input_model in {"socket_service", "http_daemon"}:
        return _service_process_input_spec(evidence_pack, request.input_model)
    if request.input_model == "env_file":
        return _env_selected_file_input_spec(
            evidence_pack,
            input_hex=str(concrete.get("input_hex") or ""),
        )
    if request.input_model == "env":
        name = _env_process_input_name(evidence_pack)
        unsupported_reason = ""
        if not name or "=" in name or "\x00" in name:
            unsupported_reason = "unsupported_process_input_setup:invalid_env_name"
        return {
            "env_name": name,
            "process_input_source": "derived_environment_variable",
            "process_input_evidence": {"input_model": "env", "env_name": name},
            "unsupported_reason": unsupported_reason,
        }
    if request.input_model != "argv_file_stdin":
        return {}
    return _combined_process_input_spec(evidence_pack, stdin_input_hex=str(concrete.get("input_hex") or ""))


def _stdin_process_input_spec(
    evidence_pack: Mapping[str, Any],
    *,
    stdin_input_hex: str = "",
) -> dict[str, Any]:
    """Resolve optional command-line setup for a real stdin process path.

    A process may need ordinary no-argument command-line modes before it reads
    its data from stdin.  This keeps that topology as ``stdin`` rather than
    misclassifying it as a file-plus-stdin model.  Flags are accepted only from
    structured process-input evidence; discovery never imports a benchmark
    reproducer or package-specific option list.
    """

    config = _stdin_process_input_config(evidence_pack)
    raw_values = (
        config.get("argv_values")
        if config.get("argv_values") is not None
        else config.get("argv")
        if config.get("argv") is not None
        else config.get("args")
    )
    values = [str(item) for item in _coerce_sequence(raw_values) if str(item)]
    if not values:
        values = ["program"]
    if values[0] not in {"program", "$program", "${program}"}:
        values.insert(0, "program")
    source = str(config.get("process_input_source") or config.get("source") or "")
    if config and not source:
        source = "explicit_stdin_argv_topology"
    return {
        "argv_values": tuple(values),
        "stdin_input_hex": str(
            _first_nonempty(config, ("stdin_input_hex", "stdin_hex", "input_hex", "concrete_input_hex"))
            or stdin_input_hex
            or ""
        ),
        "process_input_source": source,
        "process_input_evidence": _process_input_evidence_from_config(config),
        **({"unsupported_reason": str(config.get("unsupported_reason"))} if config.get("unsupported_reason") else {}),
    }


def _stdin_process_input_config(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    """Find only explicit stdin topology facts, avoiding unrelated argv data."""

    facts = _facts(evidence_pack)
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    containers: list[Mapping[str, Any]] = []
    for value in (
        evidence_pack.get("process_input"),
        evidence_pack.get("process_inputs"),
        facts.get("process_input"),
        facts.get("process_inputs"),
        type_facts.get("process_input"),
        type_facts.get("process_inputs"),
    ):
        if not isinstance(value, Mapping):
            continue
        nested = value.get("stdin")
        if isinstance(nested, Mapping):
            containers.append(nested)
        if _normalize_concolic_input_model(str(value.get("input_model") or "")) == "stdin":
            containers.append(value)
    for config in containers:
        if _first_nonempty(config, ("argv_values", "argv", "args", "stdin_input_hex", "stdin_hex")):
            return config
    return {}


def _env_process_input_name(evidence_pack: Mapping[str, Any]) -> str:
    """Use the same concrete environment key emitted by the witness plan."""

    try:
        plan = build_witness_plan(evidence_pack)
    except Exception:
        return "CONCOLIC_INPUT"
    for replay_input in plan.replay_request_inputs:
        if not isinstance(replay_input, Mapping) or replay_input.get("input_model") != "env":
            continue
        env = replay_input.get("env")
        if isinstance(env, Mapping) and env:
            return str(next(iter(env))).strip()
    return "CONCOLIC_INPUT"


def _service_process_input_spec(evidence_pack: Mapping[str, Any], input_model: str) -> dict[str, Any]:
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    facts = _facts(evidence_pack)
    trace = _candidate_classification_trace(evidence_pack)
    candidates = [
        type_facts.get("process_input"),
        facts.get("process_input"),
        evidence_pack.get("process_input"),
        trace.get("replay_hints"),
    ]
    config: dict[str, Any] = {}
    for raw in candidates:
        if not isinstance(raw, Mapping):
            continue
        nested = raw.get(input_model)
        if isinstance(nested, Mapping):
            config.update(nested)
        for key in ("host", "port", "port_arg", "port_arg_index", "port_env", "protocol"):
            if raw.get(key) not in (None, ""):
                config[key] = raw[key]
    if not config.get("port"):
        decompiled_text, _source_path = _combined_process_decompiled_text(evidence_pack)
        match = re.search(r"\bhtons\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)", decompiled_text)
        if match:
            config["port"] = int(match.group(1), 0)
            config["port_source"] = "decompiled_htons_constant"
    return {
        "process_input_source": "derived_service_entrypoint",
        "process_input_evidence": {"input_model": input_model, **config},
    }


def _argv_option_process_input_spec(evidence_pack: Mapping[str, Any], *, input_hex: str) -> dict[str, Any]:
    config = _infer_argv_option_process_input_config(evidence_pack, input_hex=input_hex)
    if not config:
        return {}
    return {
        "argv_values": tuple(str(item) for item in _coerce_sequence(config.get("argv_values"))),
        "process_input_source": str(config.get("process_input_source") or ""),
        "process_input_evidence": _process_input_evidence_from_config(config),
    }


def _candidate_uses_optarg_source(evidence_pack: Mapping[str, Any]) -> bool:
    candidate = _candidate(evidence_pack)
    if "optarg" in str(candidate.get("line_text") or ""):
        return True
    for item in _coerce_sequence(_source_trace_for_process_inputs(evidence_pack).get("argument_roles")):
        if not isinstance(item, Mapping):
            continue
        if str(item.get("role") or "") == "write_source" and str(item.get("expr") or "") == "optarg":
            return True
    return False


def _infer_optarg_option_flag(evidence_pack: Mapping[str, Any], decompiled_text: str) -> str:
    if not decompiled_text:
        return ""
    target_buffer = str(_candidate(evidence_pack).get("target_buffer") or "")
    for label, body in _switch_case_bodies(decompiled_text):
        if "optarg" not in body:
            continue
        if target_buffer and target_buffer not in body:
            continue
        flag = _switch_case_label_to_option_flag(label)
        if flag and _getopt_optstring_takes_argument(decompiled_text, flag):
            return flag
    return ""


def _switch_case_bodies(text: str) -> list[tuple[str, str]]:
    pattern = re.compile(
        r"case\s+(?P<label>0x[0-9a-fA-F]+|\d+|'(?:\\.|[^'])')\s*:\s*(?P<body>.*?)(?=\n\s*(?:case\s+(?:0x[0-9a-fA-F]+|\d+|'(?:\\.|[^'])')|default)\s*:|\n\s*}\s*while|\Z)",
        re.S,
    )
    return [(match.group("label"), match.group("body")) for match in pattern.finditer(text)]


def _switch_case_label_to_option_flag(label: str) -> str:
    text = str(label or "").strip()
    if len(text) >= 3 and text.startswith("'") and text.endswith("'"):
        value = bytes(text[1:-1], "utf-8").decode("unicode_escape")
        return value if len(value) == 1 and value.isprintable() else ""
    try:
        number = int(text, 0)
    except ValueError:
        return ""
    if 0x21 <= number <= 0x7E:
        return chr(number)
    return ""


def _getopt_optstring_takes_argument(text: str, flag: str) -> bool:
    if not flag:
        return False
    for literal in re.findall(r'"((?:\\.|[^"\\])*)"', text):
        try:
            decoded = bytes(literal, "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            continue
        index = decoded.find(flag)
        while index >= 0:
            if index + 1 < len(decoded) and decoded[index + 1] == ":":
                return True
            index = decoded.find(flag, index + 1)
    return False


def infer_process_input_fact(evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    """Infer reusable process-input setup facts from evidence and entrypoint context."""

    stdin_config = _stdin_process_input_config(evidence_pack)
    if stdin_config:
        config = {**dict(stdin_config), "input_model": "stdin"}
    else:
        config = (
            _env_selected_file_input_spec(evidence_pack)
            or _infer_argv_option_process_input_config(evidence_pack)
            or _infer_directory_process_input_config(evidence_pack)
            or _infer_combined_process_input_config(evidence_pack)
        )
    if not config:
        return {}
    return _process_input_fact_from_config(config)


def _infer_argv_option_process_input_config(
    evidence_pack: Mapping[str, Any],
    *,
    input_hex: str = "",
) -> Mapping[str, Any]:
    if not _candidate_uses_optarg_source(evidence_pack):
        return {}
    decompiled_text, source_path = _combined_process_decompiled_text(evidence_pack)
    flag = _infer_optarg_option_flag(evidence_pack, decompiled_text)
    if not flag:
        return {}
    payload = "A" * _optarg_payload_size(evidence_pack, input_hex=input_hex)
    return {
        "argv_values": ["program", f"-{flag}", payload],
        "process_input_source": "inferred_from_optarg_sink",
        "input_model": "argv",
        "inferred": True,
        "process_input_evidence": {
            "source_path": source_path,
            "decompile_source_file": source_path,
            "mode_flag": flag,
            "argv_seed_reason": "optarg_option_argument",
        },
    }


def _optarg_payload_size(evidence_pack: Mapping[str, Any], *, input_hex: str = "") -> int:
    input_bytes = _bytes_from_hex(input_hex) if input_hex else None
    if input_bytes is not None:
        return max(1, len(input_bytes))
    candidate = _candidate(evidence_pack)
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    wanted = max(
        _candidate_write_size_bytes(evidence_pack, None),
        capacity + 1 if capacity > 0 else 0,
        32,
    )
    return max(1, min(wanted, 4096))


def _directory_process_input_spec(evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    config = _directory_process_input_config(evidence_pack)
    directory_name = str(config.get("file_name") or "concolic_dir")
    argv_values = _combined_argv_values(config, directory_name)
    source = str(config.get("process_input_source") or config.get("source") or "")
    if config and not source:
        source = "explicit_process_input_fact"
    return {
        "argv_values": tuple(argv_values),
        "stdin_input_hex": "",
        "file_input_hex": "",
        "file_name": directory_name,
        "process_input_source": source,
        "process_input_evidence": _process_input_evidence_from_config(config),
    }


def _file_process_input_spec(evidence_pack: Mapping[str, Any], *, input_hex: str) -> dict[str, Any]:
    seed_hex, file_name, file_reason, unsupported_reason, source_path = _infer_file_seed_from_evidence(evidence_pack)
    if seed_hex:
        input_normalized = str(input_hex or "").lower()
        seed_normalized = str(seed_hex or "").lower()
        if not (
            input_normalized
            and (input_normalized.startswith(seed_normalized) or seed_normalized.startswith(input_normalized))
        ):
            file_reason = ""
            file_name = ""
    config = {
        "process_input_evidence": {
            "source_path": source_path,
            "decompile_source_file": source_path,
            "file_seed_reason": file_reason or "concrete_file_witness",
        }
    }
    if unsupported_reason:
        config["unsupported_reason"] = unsupported_reason
    resolved_file_name = file_name or "concolic_input"
    argv_values = (
        ("program", "-tf", resolved_file_name)
        if file_reason == "tar_format_text"
        else ("program", resolved_file_name)
    )
    return {
        "argv_values": argv_values,
        "stdin_input_hex": "",
        "file_input_hex": str(input_hex or ""),
        "file_name": resolved_file_name,
        "process_input_source": "inferred_file_seed" if file_reason else "concrete_file_witness",
        "process_input_evidence": _process_input_evidence_from_config(config),
        "unsupported_reason": unsupported_reason,
    }


def _combined_process_input_spec(
    evidence_pack: Mapping[str, Any],
    *,
    stdin_input_hex: str = "",
) -> dict[str, Any]:
    config = _combined_process_input_config(evidence_pack)
    if str(config.get("input_model") or "") == "argv_directory":
        return _directory_process_input_spec(evidence_pack)
    file_name = _safe_process_file_name(_first_nonempty(config, ("file_name", "path", "filename")), "concolic_input")
    argv_values = _combined_argv_values(config, file_name)
    file_input_hex = _combined_file_input_hex(config)
    configured_stdin = _first_nonempty(config, ("stdin_input_hex", "stdin_hex", "input_hex", "concrete_input_hex"))
    source = str(config.get("process_input_source") or config.get("source") or "")
    if config and not source:
        source = "explicit_process_input_fact"
    evidence = _process_input_evidence_from_config(config)
    unsupported_reason = str(config.get("unsupported_reason") or "")
    if not unsupported_reason and not file_input_hex:
        unsupported_reason = "unsupported_process_input_setup:missing_file_input_hex"
    if unsupported_reason and not source:
        source = "missing_process_input_fact"
    result: dict[str, Any] = {
        "argv_values": tuple(argv_values),
        "stdin_input_hex": str(configured_stdin or stdin_input_hex or ""),
        "file_input_hex": file_input_hex,
        "file_name": file_name,
        "process_input_source": source,
        "process_input_evidence": evidence,
    }
    if unsupported_reason:
        result["unsupported_reason"] = unsupported_reason
    return result


def _process_input_fact_from_config(config: Mapping[str, Any]) -> dict[str, Any]:
    input_model = str(config.get("input_model") or "argv_file_stdin")
    if input_model == "argv_directory":
        file_name = str(_first_nonempty(config, ("file_name", "path", "filename")) or "concolic_dir")
    else:
        file_name = _safe_process_file_name(_first_nonempty(config, ("file_name", "path", "filename")), "concolic_input")
    fact = {
        "input_model": input_model,
        "argv_values": _combined_argv_values(config, file_name),
        "file_name": file_name,
        "file_input_hex": _combined_file_input_hex(config),
        "process_input_source": str(config.get("process_input_source") or config.get("source") or ""),
        "process_input_evidence": _process_input_evidence_from_config(config),
        "inferred": bool(config.get("inferred", False)),
    }
    if input_model == "env_file":
        fact["env_name"] = str(config.get("env_name") or "")
        fact["env_values"] = dict(config.get("env_values") or {})
        fact["seed_hex"] = str(config.get("seed_hex") or "")
    unsupported_reason = str(config.get("unsupported_reason") or "")
    if unsupported_reason:
        fact["unsupported_reason"] = unsupported_reason
    stdin_hex = _first_nonempty(config, ("stdin_input_hex", "stdin_hex", "input_hex", "concrete_input_hex"))
    if stdin_hex:
        fact["stdin_input_hex"] = str(stdin_hex)
    return fact


def _process_input_evidence_from_config(config: Mapping[str, Any]) -> dict[str, Any]:
    evidence = (
        dict(config.get("process_input_evidence") or {})
        if isinstance(config.get("process_input_evidence"), Mapping)
        else {}
    )
    for key in ("source_path", "decompile_source_file"):
        value = str(evidence.get(key) or "")
        if value:
            evidence[key] = Path(value).name
    if evidence.get("source_path") and not evidence.get("decompile_source_file"):
        evidence["decompile_source_file"] = evidence["source_path"]
    if evidence.get("decompile_source_file") and not evidence.get("source_path"):
        evidence["source_path"] = evidence["decompile_source_file"]
    return evidence


def _combined_process_input_config(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    facts = _facts(evidence_pack)
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    containers: list[Mapping[str, Any]] = []
    for value in (
        evidence_pack.get("process_input"),
        evidence_pack.get("process_inputs"),
        evidence_pack.get("replay_hypothesis"),
        facts.get("process_input"),
        facts.get("process_inputs"),
        facts.get("reproducer_hypothesis"),
        type_facts.get("process_input"),
        type_facts.get("process_inputs"),
    ):
        if isinstance(value, Mapping):
            containers.append(value)
            for key in ("process_input", "process_inputs", "combined_input", "argv_file_stdin"):
                nested = value.get(key)
                if isinstance(nested, Mapping):
                    containers.append(nested)
    for item in containers:
        if _first_nonempty(
            item,
            (
                "argv_values",
                "argv",
                "args",
                "file_name",
                "path",
                "file_input_hex",
                "file_hex",
                "file_seed_hex",
                "file_content_hex",
                "file_bytes_hex",
                "file_input",
                "file_seed",
                "file_content",
                "file_text",
                "stdin_input_hex",
                "stdin_hex",
            ),
        ):
            return item
    return _infer_directory_process_input_config(evidence_pack) or _infer_combined_process_input_config(evidence_pack)


def _directory_process_input_config(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    config = _combined_process_input_config(evidence_pack)
    if str(config.get("input_model") or "") == "argv_directory":
        return config
    return _infer_directory_process_input_config(evidence_pack)


def _infer_directory_process_input_config(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    if not _source_trace_has_directory_entry_source(evidence_pack):
        return {}
    candidate = _candidate(evidence_pack)
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    directory_name = _directory_name_for_overflow_offset(capacity)
    source_path = _source_trace_source_path(evidence_pack)
    return {
        "argv_values": ["program", f"{directory_name}/*"],
        "file_name": directory_name,
        "process_input_source": "inferred_from_directory_entry_source",
        "input_model": "argv_directory",
        "inferred": True,
        "process_input_evidence": {
            "source_path": source_path,
            "decompile_source_file": source_path,
            "directory_seed_reason": "readdir_d_name",
            "directory_name_length": len(directory_name),
            "argv_wildcard_pattern": f"{directory_name}/*",
        },
    }


def _source_trace_source_path(evidence_pack: Mapping[str, Any]) -> str:
    entrypoint = _semantic_entrypoint_derivation(evidence_pack)
    for value in (
        entrypoint.get("source_path") if isinstance(entrypoint, Mapping) else "",
        entrypoint.get("decompile_source_file") if isinstance(entrypoint, Mapping) else "",
        _facts(evidence_pack).get("source_path"),
    ):
        if value:
            return str(value)
    return ""


def _directory_name_for_overflow_offset(capacity: int) -> str:
    target_length = max(1, int(capacity or 0) - 16)
    target_length = min(target_length, 4080)
    segment = "d" * 120
    parts: list[str] = []
    remaining = target_length
    while remaining > 120:
        parts.append(segment)
        remaining -= 121
    if remaining > 0:
        parts.append("d" * remaining)
    name = "/".join(parts) or "concolic_dir"
    if len(name) > target_length:
        name = name[:target_length]
    while len(name) < target_length:
        suffix = min(120, target_length - len(name) - 1)
        if suffix <= 0:
            name += "d" * (target_length - len(name))
        else:
            name += "/" + ("d" * suffix)
    return name


def _infer_combined_process_input_config(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    if not _requires_argv_file_stdin_model(evidence_pack):
        return {}
    decompiled_text, source_path = _combined_process_decompiled_text(evidence_pack)
    source_markers = _stdin_source_markers(evidence_pack)
    mode_flag = _infer_stdin_mode_flag_from_decompiled(decompiled_text, source_markers) if decompiled_text else ""
    file_seed_hex, file_name, file_reason, unsupported_reason = _infer_file_seed_from_process_text(decompiled_text)
    if not mode_flag and not file_seed_hex:
        return {}
    file_name = file_name or "concolic_input"
    argv_values = ["program", file_name]
    if mode_flag:
        argv_values = ["program", f"-{mode_flag}", file_name]
    elif file_reason == "arj_format_filename":
        argv_values = ["program", "e", file_name]
    config: dict[str, Any] = {
        "argv_values": argv_values,
        "file_name": file_name,
        "process_input_source": "inferred_from_entry_decompile",
        "input_model": "argv_file_stdin",
        "inferred": True,
        "process_input_evidence": {
            "source_path": source_path,
            "decompile_source_file": source_path,
            "mode_flag": mode_flag,
            "file_seed_reason": file_reason,
            "source_markers": sorted(source_markers),
        },
    }
    if file_seed_hex:
        config["file_input_hex"] = file_seed_hex
    if unsupported_reason:
        config["unsupported_reason"] = unsupported_reason
    return config


def _combined_process_decompiled_text(evidence_pack: Mapping[str, Any]) -> tuple[str, str]:
    identifier_groups = _combined_process_decompile_identifier_groups(evidence_pack)
    seen_paths: set[str] = set()
    for export_dir in _process_export_dirs(evidence_pack):
        for names, address_tokens in identifier_groups:
            candidates = _candidate_decompile_paths(export_dir, names, address_tokens)
            for path in candidates[:4]:
                path_key = str(path)
                if path_key in seen_paths:
                    continue
                seen_paths.add(path_key)
                try:
                    return (path.read_text(errors="replace")[:512 * 1024], str(path))
                except OSError:
                    continue
    return ("", "")


def _combined_process_decompile_identifier_groups(evidence_pack: Mapping[str, Any]) -> list[tuple[set[str], set[str]]]:
    entrypoint = _semantic_entrypoint_derivation(evidence_pack)
    candidate = _candidate(evidence_pack)
    groups: list[tuple[set[str], set[str]]] = []

    def add(name: Any, address: Any) -> None:
        names = {str(name or "")}
        normalized = _normalize_address(address)
        tokens = {normalized[2:].lower()} if normalized else set()
        names = {item for item in names if item}
        tokens = {item for item in tokens if item}
        if names or tokens:
            groups.append((names, tokens))

    if isinstance(entrypoint, Mapping):
        add(entrypoint.get("entry_function"), entrypoint.get("entry_address"))
        add(entrypoint.get("target_function"), entrypoint.get("target_address"))
    add(candidate.get("function_name"), candidate.get("address"))
    if not groups:
        groups.append(_combined_process_entry_identifiers(evidence_pack))
    return groups


def _combined_process_entry_identifiers(evidence_pack: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    entrypoint = _semantic_entrypoint_derivation(evidence_pack)
    candidate = _candidate(evidence_pack)
    names = {
        str(entrypoint.get("entry_function") or ""),
        str(entrypoint.get("target_function") or ""),
        str(candidate.get("function_name") or ""),
    }
    addresses = {
        _normalize_address(entrypoint.get("entry_address")),
        _normalize_address(entrypoint.get("target_address")),
        _normalize_address(candidate.get("address")),
    }
    address_tokens = {address[2:].lower() for address in addresses if address}
    return ({name for name in names if name}, {token for token in address_tokens if token})


def _process_export_dirs(value: Any) -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                if key == "export_dir" and nested:
                    path = Path(str(nested))
                    key_text = str(path)
                    if key_text not in seen and path.exists() and path.is_dir():
                        seen.add(key_text)
                        found.append(path)
                else:
                    visit(nested)
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for nested in item:
                visit(nested)

    visit(value)
    return found


def _candidate_decompile_paths(export_dir: Path, names: set[str], address_tokens: set[str]) -> list[Path]:
    exact: list[Path] = []
    loose: list[Path] = []
    try:
        directory = Path(export_dir)
        path_index = _decompile_path_index(str(directory), directory.stat().st_mtime_ns)
    except OSError:
        return []
    lowered_names = {name.lower() for name in names}
    for path, stem in path_index:
        if any(name and name in stem for name in lowered_names) or any(token and token in stem for token in address_tokens):
            exact.append(path)
        elif len(loose) < 4:
            loose.append(path)
    if exact or lowered_names or address_tokens:
        return exact
    return loose


@lru_cache(maxsize=64)
def _decompile_path_index(export_dir: str, directory_mtime_ns: int) -> tuple[tuple[Path, str], ...]:
    del directory_mtime_ns
    return tuple((path, path.stem.lower()) for path in sorted(Path(export_dir).glob("*.c")))


def _stdin_source_markers(evidence_pack: Mapping[str, Any]) -> set[str]:
    markers = {"fgets", "gets", "read"}
    strings = _source_trace_strings(_source_trace_for_process_inputs(evidence_pack))
    strings.extend(_nested_strings(evidence_pack))
    for text in strings:
        for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s+calls input source\s+(?:fgets|gets|read)\b", text):
            markers.add(match.group(1))
    return markers


def _infer_stdin_mode_flag_from_decompiled(text: str, source_markers: set[str]) -> str:
    if not text:
        return ""
    for match in re.finditer(r"case\s+'(?P<flag>[A-Za-z0-9])'\s*:(?P<body>.*?)(?=case\s+'|default\s*:|}\s*while|\n\s*}\n)", text, re.S):
        flag = match.group("flag")
        body = match.group("body")
        assigned_vars = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:true|1)\s*;", body)
        for var_name in assigned_vars:
            if _mode_variable_guards_stdin_source(text[match.end() : match.end() + 16000], var_name, source_markers):
                return flag
    return ""


def _mode_variable_guards_stdin_source(text: str, var_name: str, source_markers: set[str]) -> bool:
    if not text or not var_name:
        return False
    source_positions = [
        match.start()
        for marker in source_markers
        for match in re.finditer(rf"\b{re.escape(marker)}\b", text)
    ]
    if not source_positions:
        return False
    first_source = min(source_positions)
    before_source = text[:first_source]
    return re.search(rf"\bif\s*\([^)]*\b{re.escape(var_name)}\b[^)]*\)", before_source) is not None


def _infer_file_seed_from_process_text(text: str) -> tuple[str, str, str, str]:
    lowered = str(text or "").lower()
    candidates: list[tuple[bytes, str, str]] = []

    candidates.extend(
        _file_seed_candidates(
            lowered,
            (
                (
                    ("bmp file", "bitmap", "cannot handle bmp", ".bmp", "dib header"),
                    _minimal_bmp_file_bytes,
                    "concolic_input.bmp",
                    "bmp_format_text",
                ),
                (
                    ("zip file", "central directory", "end signature", "info-zip"),
                    _minimal_zip_file_bytes,
                    "concolic_input.zip",
                    "zip_format_text",
                ),
                (
                    ("unarj", "arj archive", ".arj"),
                    _minimal_arj_file_bytes,
                    "concolic_input.arj",
                    "arj_format_filename",
                ),
                (
                    ("gzip", "gzopen", "gzread", ".gz"),
                    _minimal_gzip_file_bytes,
                    "concolic_input.gz",
                    "gzip_format_text",
                ),
                (
                    ("tar file", "tar archive", "ustar"),
                    _minimal_tar_file_bytes,
                    "concolic_input.tar",
                    "tar_format_text",
                ),
            ),
        )
    )
    json_markers = ("json file", "json config", "json_object", "cjson", "jansson")
    json_hit = any(marker in lowered for marker in json_markers)
    if json_hit:
        candidates.append((_minimal_json_config_bytes(), "concolic_input.json", "json_config_format_text"))
    if not json_hit:
        candidates.extend(
            _file_seed_candidates(
                lowered,
                (
                    (
                        ("ini file", ".ini", ".conf", "key=value", "config file", "configuration file"),
                        _minimal_text_config_bytes,
                        "concolic_input.conf",
                        "text_config_format_text",
                    ),
                ),
            )
        )
    candidates.extend(
        _file_seed_candidates(
            lowered,
            (
                (
                    ("script file", "shell script", "command file", "line-oriented", "line oriented"),
                    _minimal_line_script_bytes,
                    "concolic_input.sh",
                    "line_script_format_text",
                ),
            ),
        )
    )

    if len(candidates) == 1:
        payload, file_name, reason = candidates[0]
        return (payload.hex(), file_name, reason, "")
    if len(candidates) > 1:
        return ("", "", "unsupported_ambiguous_file_format", "unsupported_process_input_setup:ambiguous_file_format")
    return ("", "", "", "")


def _file_seed_candidates(
    lowered_text: str,
    rules: Sequence[tuple[Sequence[str], Callable[[], bytes], str, str]],
) -> list[tuple[bytes, str, str]]:
    return [
        (payload_factory(), file_name, reason)
        for markers, payload_factory, file_name, reason in rules
        if any(marker in lowered_text for marker in markers)
    ]


def _infer_file_seed_from_evidence(evidence_pack: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    decompiled_text, source_path = _combined_process_decompiled_text(evidence_pack)
    seed_hex, file_name, file_reason, unsupported_reason = _infer_file_seed_from_process_text(decompiled_text)
    if seed_hex or unsupported_reason:
        return (seed_hex, file_name, file_reason, unsupported_reason, source_path)
    hits: dict[str, tuple[str, str, str, str]] = {}
    for export_dir in _process_export_dirs(evidence_pack):
        try:
            paths = sorted(Path(export_dir).glob("*.c"))
        except OSError:
            continue
        for path in paths[:1000]:
            if source_path and str(path) == str(source_path):
                continue
            try:
                text = path.read_text(errors="replace")[:128 * 1024]
            except OSError:
                continue
            seed_hex, file_name, file_reason, unsupported_reason = _infer_file_seed_from_process_text(text)
            if unsupported_reason:
                return ("", "", "unsupported_ambiguous_file_format", unsupported_reason, str(path))
            if not seed_hex:
                continue
            hits[file_reason] = (seed_hex, file_name, file_reason, str(path))
            if len(hits) > 1:
                return (
                    "",
                    "",
                    "unsupported_ambiguous_file_format",
                    "unsupported_process_input_setup:ambiguous_file_format",
                    str(path),
                )
    if len(hits) == 1:
        seed_hex, file_name, file_reason, hit_path = next(iter(hits.values()))
        return (seed_hex, file_name, file_reason, "", hit_path)
    return ("", "", "", "", source_path)


def _combined_argv_values(config: Mapping[str, Any], file_name: str) -> list[str]:
    raw = None
    for key in ("argv_values", "argv", "args"):
        if key in config:
            raw = config.get(key)
            break
    if isinstance(raw, str):
        try:
            values = [str(item) for item in shlex.split(raw) if str(item)]
        except ValueError:
            values = [raw] if raw else []
    else:
        values = [str(item) for item in _coerce_sequence(raw) if str(item)]
    if not values:
        return ["program", file_name]
    if bool(config.get("argv_includes_program")):
        return values
    if values[0] in {"program", "$program", "${program}"}:
        return values
    if len(values) > 1 and not values[0].startswith("-") and values[0] != file_name:
        return values
    return ["program", *values]


def _combined_file_input_hex(config: Mapping[str, Any]) -> str:
    for key in ("file_input_hex", "file_hex", "file_seed_hex", "file_content_hex", "file_bytes_hex"):
        value = str(config.get(key) or "").strip()
        if not value:
            continue
        try:
            bytes.fromhex(value)
        except ValueError:
            continue
        return value.lower()
    for key in ("file_input", "file_seed", "file_content", "file_text"):
        value = config.get(key)
        if isinstance(value, str) and value:
            return value.encode("utf-8").hex()
    return ""


def _safe_process_file_name(value: Any, default: str) -> str:
    name = Path(str(value or default)).name
    if not name or name in {".", ".."} or "\x00" in name:
        return default
    return name


def _first_nonempty(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value:
            return value
    return ""


@lru_cache(maxsize=1)
def _minimal_zip_file_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("seed.txt", b"seed\n")
    return buffer.getvalue()


@lru_cache(maxsize=1)
def _minimal_bmp_file_bytes() -> bytes:
    """One-pixel indexed BMP whose palette index exceeds its one-entry table."""

    payload = bytearray(b"BM")
    payload.extend((62).to_bytes(4, "little"))
    payload.extend(b"\x00\x00\x00\x00")
    payload.extend((58).to_bytes(4, "little"))
    payload.extend((40).to_bytes(4, "little"))
    payload.extend((1).to_bytes(4, "little", signed=True))
    payload.extend((1).to_bytes(4, "little", signed=True))
    payload.extend((1).to_bytes(2, "little"))
    payload.extend((8).to_bytes(2, "little"))
    payload.extend((0).to_bytes(4, "little"))
    payload.extend((4).to_bytes(4, "little"))
    payload.extend((0).to_bytes(4, "little", signed=True) * 2)
    payload.extend((1).to_bytes(4, "little"))
    payload.extend((0).to_bytes(4, "little"))
    payload.extend(b"\xff\xff\xff\x00")
    payload.extend(b"\xff\x00\x00\x00")
    return bytes(payload)


@lru_cache(maxsize=1)
def _minimal_gzip_file_bytes() -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as archive:
        archive.write(b"seed\n")
    return buffer.getvalue()


@lru_cache(maxsize=1)
def _minimal_tar_file_bytes() -> bytes:
    payload = b"seed\n"
    buffer = io.BytesIO()
    info = tarfile.TarInfo("seed.txt")
    info.size = len(payload)
    info.mtime = 0
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


@lru_cache(maxsize=1)
def _minimal_arj_file_bytes() -> bytes:
    main_header = _arj_header(
        _arj_first_header(method=0, file_type=2, compressed_size=0, original_size=0, file_crc=0),
        b"",
        b"seed",
    )
    file_header = _arj_header(
        _arj_first_header(method=0, file_type=0, compressed_size=0, original_size=0, file_crc=0),
        b"A" * 511,
        b"",
    )
    return main_header + file_header + b"\x60\xea\x00\x00"


def _arj_first_header(
    *,
    method: int,
    file_type: int,
    compressed_size: int,
    original_size: int,
    file_crc: int,
    entry_pos: int = 0,
) -> bytes:
    header = bytearray([30, 3, 3, 2, 0, method & 0xFF, file_type & 0xFF, 0])
    header.extend((0).to_bytes(4, "little"))
    header.extend(int(compressed_size).to_bytes(4, "little", signed=False))
    header.extend(int(original_size).to_bytes(4, "little", signed=False))
    header.extend(int(file_crc).to_bytes(4, "little", signed=False))
    header.extend(int(entry_pos).to_bytes(2, "little", signed=False))
    header.extend((0o644).to_bytes(2, "little", signed=False))
    header.extend((0).to_bytes(2, "little", signed=False))
    if len(header) != 30:
        raise AssertionError("ARJ fixed header must be 30 bytes")
    return bytes(header)


def _arj_header(first_header: bytes, filename: bytes, comment: bytes) -> bytes:
    body = bytes(first_header) + bytes(filename) + b"\x00" + bytes(comment) + b"\x00"
    return (
        b"\x60\xea"
        + len(body).to_bytes(2, "little", signed=False)
        + body
        + (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
        + b"\x00\x00"
    )


def _minimal_json_config_bytes() -> bytes:
    return b'{"seed":"seed","items":["seed"]}\n'


def _minimal_text_config_bytes() -> bytes:
    return b"seed=seed\nname=seed\n"


def _minimal_line_script_bytes() -> bytes:
    return b"echo seed\n"


def _apply_call_context_feasibility_gate(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
    proof: Mapping[str, Any],
) -> dict[str, Any]:
    """Downgrade function-harness-only string overflows disproven by known callsites.

    The Ghidra proof is intentionally local to the harness.  If the harness proves
    an overflow only by making callee parameters huge, but every recovered direct
    callsite binds those parameters to bounded strings that fit the destination,
    the result is not a reportable firmware-context overflow.
    """

    payload = dict(proof or {})
    if str(payload.get("status") or "") != "overflow_proven":
        return payload
    if str(request.input_model or "") != "function_harness":
        return payload
    model = _call_context_feasibility_model(evidence_pack, request, payload)
    if not model:
        return payload
    payload["call_context_feasibility"] = model
    if (
        model.get("status") == "unknown"
        and model.get("reason") == "no_known_direct_callsites"
        and _function_harness_context_is_unresolved(evidence_pack)
    ):
        payload["function_harness_dynamic_proof"] = {
            "status": payload.get("status"),
            "write_size_bytes": payload.get("write_size_bytes"),
            "overflow_bytes": payload.get("overflow_bytes"),
            "write_range": dict(payload.get("write_range") or {}) if isinstance(payload.get("write_range"), Mapping) else {},
        }
        payload["status"] = "unsupported"
        payload["unsupported"] = True
        payload["reason"] = "function_harness_call_context_unresolved"
        return payload
    if model.get("status") != "no_overflow_in_known_call_context":
        return payload

    original = {
        "status": payload.get("status"),
        "write_size_bytes": payload.get("write_size_bytes"),
        "overflow_bytes": payload.get("overflow_bytes"),
        "write_range": dict(payload.get("write_range") or {}) if isinstance(payload.get("write_range"), Mapping) else {},
    }
    capacity = _safe_int(payload.get("capacity_bytes"), default=_safe_int(model.get("capacity_bytes"), default=0))
    write_end = _safe_int(model.get("max_write_end_offset_bytes"), default=0)
    payload["function_harness_dynamic_proof"] = original
    payload["status"] = "no_overflow"
    payload["reason"] = "known_callsite_arguments_bound_write"
    payload["write_size_bytes"] = write_end
    payload["write_size_source"] = "known_callsite_string_bound"
    payload["capacity_bytes"] = capacity
    payload["overflow_bytes"] = 0
    write_range = dict(payload.get("write_range") or {}) if isinstance(payload.get("write_range"), Mapping) else {}
    write_range.update(
        {
            "start_offset": 0,
            "end_offset_exclusive": write_end,
            "size_bytes": write_end,
        }
    )
    payload["write_range"] = write_range
    object_range = dict(payload.get("object_range") or {}) if isinstance(payload.get("object_range"), Mapping) else {}
    if capacity > 0:
        object_range.update({"start_offset": 0, "end_offset_exclusive": capacity, "size_bytes": capacity})
        payload["object_range"] = object_range
    return payload


def _function_harness_context_is_unresolved(evidence_pack: Mapping[str, Any]) -> bool:
    reachability = evidence_pack.get("reachability")
    if not isinstance(reachability, Mapping):
        candidate = _candidate(evidence_pack)
        trace = candidate.get("classification_trace") if isinstance(candidate, Mapping) else {}
        dataflow = trace.get("reachability_dataflow") if isinstance(trace, Mapping) else {}
        reachability = dataflow.get("graph") if isinstance(dataflow, Mapping) else {}
    if not isinstance(reachability, Mapping):
        return False
    if bool(reachability.get("complete_unreachable_candidate")):
        return True
    return (
        _safe_int(reachability.get("caller_count"), default=0) == 0
        and not bool(reachability.get("input_reaches_sink"))
        and not bool(reachability.get("path_is_valid"))
        and not bool(reachability.get("is_public"))
        and not bool(reachability.get("is_exported"))
        and not bool(reachability.get("is_root_like"))
        and not bool(reachability.get("is_entry"))
        and not bool(reachability.get("is_thread_start"))
        and not bool(reachability.get("has_callback_evidence"))
    )


def _call_context_feasibility_model(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
    proof: Mapping[str, Any],
) -> dict[str, Any]:
    candidate = _candidate(evidence_pack)
    sink = str(candidate.get("sink") or proof.get("sink_name") or "").lower()
    if sink not in {"strcat", "strcpy"}:
        return {}
    export_dir = request.export_dir
    if export_dir is None or not Path(export_dir).exists():
        return {}
    relative_path = str(candidate.get("relative_path") or "")
    source_path = Path(export_dir) / relative_path if relative_path else Path()
    if not source_path.exists() or not source_path.is_file():
        return {}
    function_name = str(candidate.get("function_name") or "")
    if not function_name:
        return {}
    function_text = source_path.read_text(errors="replace")
    param_names = _function_param_names(function_text, function_name)
    if not param_names:
        return {}
    capacity = _safe_int(proof.get("capacity_bytes"), default=_safe_int(candidate.get("capacity_bytes"), default=0))
    if capacity <= 0:
        return {}
    callsites = _known_callsite_contexts(str(Path(export_dir)), function_name)
    if not callsites:
        return {
            "status": "unknown",
            "reason": "no_known_direct_callsites",
            "input_model": request.input_model,
        }
    resolver = _BinaryStringResolver(request.binary_path)
    evaluations: list[dict[str, Any]] = []
    max_write_end = 0
    for callsite in callsites:
        evaluation = _evaluate_string_write_in_call_context(
            function_text,
            candidate,
            param_names,
            callsite,
            resolver,
            capacity,
        )
        evaluations.append(evaluation)
        if evaluation.get("status") != "bounded_no_overflow":
            return {
                "status": "unknown",
                "reason": str(evaluation.get("reason") or "unbounded_or_overflowing_call_context"),
                "input_model": request.input_model,
                "callsite_count": len(callsites),
                "evaluations": evaluations,
            }
        max_write_end = max(max_write_end, _safe_int(evaluation.get("write_end_offset_bytes"), default=0))

    return {
        "status": "no_overflow_in_known_call_context",
        "reason": "all_known_direct_callsites_bound_the_target_write_below_capacity",
        "input_model": request.input_model,
        "callsite_count": len(callsites),
        "bounded_callsite_count": len(evaluations),
        "capacity_bytes": capacity,
        "max_write_end_offset_bytes": max_write_end,
        "evaluations": evaluations,
    }


def _evaluate_string_write_in_call_context(
    function_text: str,
    candidate: Mapping[str, Any],
    param_names: Sequence[str],
    callsite: _CallsiteContext,
    resolver: "_BinaryStringResolver",
    capacity: int,
) -> dict[str, Any]:
    if len(callsite.args) < len(param_names):
        return {
            "status": "unknown",
            "reason": "callsite_arg_count_mismatch",
            "callsite": callsite.to_dict(),
        }
    param_env = {param: callsite.args[index] for index, param in enumerate(param_names) if index < len(callsite.args)}
    eval_env = _StringEvalEnv(param_env, callsite.assignments, {}, resolver)
    target_line = _safe_int(candidate.get("line_number"), default=0)
    target_buffer = str(candidate.get("target_buffer") or "")
    sink = str(candidate.get("sink") or "").lower()
    if target_line <= 0 or not target_buffer:
        return {"status": "unknown", "reason": "missing_candidate_line_or_target", "callsite": callsite.to_dict()}

    local_lengths: dict[str, int | None] = {}
    lines = function_text.splitlines()
    for line_number, raw_line in enumerate(lines, start=1):
        stripped = _strip_line_comment(raw_line).strip()
        if not stripped:
            continue
        reset = re.match(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*0\s*\]\s*=\s*'\\0'\s*;", stripped)
        if reset:
            local_lengths[reset.group("name")] = 0
            eval_env.local_lengths = local_lengths

        for call_name, args in _iter_c_calls(stripped):
            call_sink = call_name.lower()
            if call_sink not in {"strcat", "strcpy"} or len(args) < 2:
                continue
            dest = _clean_c_expr(args[0])
            source = args[1]
            is_target = line_number == target_line and call_sink == sink and dest == target_buffer
            if call_sink == "strcpy":
                source_bound = _string_length_bound(source, eval_env)
                if is_target:
                    return _string_write_evaluation(callsite, capacity, source_bound, 0)
                local_lengths[dest] = source_bound.length if source_bound.known else None
                eval_env.local_lengths = local_lengths
                continue

            if call_sink == "strcat":
                current = local_lengths.get(dest)
                source_bound = _string_length_bound(source, eval_env)
                if is_target:
                    if current is None:
                        return {
                            "status": "unknown",
                            "reason": "destination_current_length_unknown",
                            "callsite": callsite.to_dict(),
                            "source_expr": source,
                        }
                    return _string_write_evaluation(callsite, capacity, source_bound, current)
                if current is not None and source_bound.known:
                    local_lengths[dest] = current + int(source_bound.length or 0)
                else:
                    local_lengths[dest] = None
                eval_env.local_lengths = local_lengths
        if line_number >= target_line:
            break
    return {"status": "unknown", "reason": "target_write_not_recovered", "callsite": callsite.to_dict()}


def _string_write_evaluation(
    callsite: _CallsiteContext,
    capacity: int,
    source_bound: _StringBound,
    current_length: int,
) -> dict[str, Any]:
    if not source_bound.known:
        return {
            "status": "unknown",
            "reason": "source_length_unknown",
            "callsite": callsite.to_dict(),
            "source_expr": source_bound.expr,
            "source": source_bound.source,
        }
    source_length = int(source_bound.length or 0)
    write_end = current_length + source_length + 1
    status = "bounded_no_overflow" if write_end <= capacity else "overflow_possible_in_known_call_context"
    return {
        "status": status,
        "reason": "bounded_callsite_string_write" if status == "bounded_no_overflow" else "bounded_callsite_still_overflows",
        "callsite": callsite.to_dict(),
        "source_expr": source_bound.expr,
        "source": source_bound.source,
        "current_length_bytes": current_length,
        "source_length_bytes": source_length,
        "write_end_offset_bytes": write_end,
        "capacity_bytes": capacity,
    }


@dataclass
class _StringEvalEnv:
    param_env: Mapping[str, str]
    caller_assignments: Mapping[str, str]
    local_lengths: dict[str, int | None]
    resolver: "_BinaryStringResolver"
    depth: int = 0


def _string_length_bound(expr: str, env: _StringEvalEnv) -> _StringBound:
    cleaned = _clean_c_expr(expr)
    if not cleaned:
        return _StringBound(None, "empty_expression", expr)
    literal = _literal_string_value(cleaned)
    if literal is not None:
        return _StringBound(len(literal), "string_literal", cleaned)
    if cleaned in env.local_lengths:
        value = env.local_lengths.get(cleaned)
        return _StringBound(value, "local_string_state" if value is not None else "unknown_local_string_state", cleaned)
    if _IDENTIFIER_RE.match(cleaned):
        if cleaned in env.param_env:
            if env.depth > 8:
                return _StringBound(None, "param_resolution_depth_limit", cleaned)
            nested = _StringEvalEnv(env.param_env, env.caller_assignments, env.local_lengths, env.resolver, env.depth + 1)
            result = _string_length_bound(env.param_env[cleaned], nested)
            return _StringBound(result.length, f"callee_parameter:{cleaned}->{result.source}", cleaned)
        if cleaned in env.caller_assignments:
            if env.depth > 8:
                return _StringBound(None, "assignment_resolution_depth_limit", cleaned)
            nested = _StringEvalEnv(env.param_env, env.caller_assignments, env.local_lengths, env.resolver, env.depth + 1)
            result = _string_length_bound(env.caller_assignments[cleaned], nested)
            return _StringBound(result.length, f"caller_assignment:{cleaned}->{result.source}", cleaned)
    resolved = env.resolver.resolve(cleaned)
    if resolved is not None:
        return _StringBound(len(resolved), "binary_string_reference", cleaned)
    return _StringBound(None, "unresolved_expression", cleaned)


def _function_param_names(source_text: str, function_name: str) -> tuple[str, ...]:
    match = re.search(rf"\b{re.escape(function_name)}\s*\((?P<args>.*?)\)", source_text, flags=re.DOTALL)
    if not match:
        return ()
    names: list[str] = []
    for raw_arg in _split_c_arguments(match.group("args")):
        arg = raw_arg.strip()
        if not arg or arg == "void":
            continue
        name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?$", arg)
        if name_match:
            names.append(name_match.group(1))
    return tuple(names)


@lru_cache(maxsize=512)
def _known_callsite_contexts(export_dir: str, function_name: str) -> tuple[_CallsiteContext, ...]:
    root = Path(export_dir)
    if not root.exists():
        return ()
    contexts: list[_CallsiteContext] = []
    for path in sorted(root.glob("*.c")):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        caller = _source_function_name(text, path)
        assignments: dict[str, str] = {}
        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            stripped = _strip_line_comment(raw_line).strip()
            if not stripped:
                continue
            for call_name, args in _iter_c_calls(stripped):
                if call_name != function_name:
                    continue
                if _looks_like_function_definition(stripped, function_name):
                    continue
                contexts.append(
                    _CallsiteContext(
                        caller_function=caller,
                        relative_path=path.name,
                        line_number=line_number,
                        line_text=stripped,
                        args=tuple(args),
                        assignments=dict(assignments),
                    )
                )
            lhs, rhs = _split_c_assignment(stripped)
            variable = _assignment_variable(lhs)
            if variable and rhs:
                assignments[variable] = rhs
    return tuple(contexts)


def _source_function_name(source_text: str, path: Path) -> str:
    match = re.search(r"^\s*//\s*Function:\s*(?P<name>\S+)", source_text, flags=re.MULTILINE)
    if match:
        return match.group("name")
    stem = path.stem
    if "_" in stem:
        return stem.split("_", 1)[1]
    return stem


def _looks_like_function_definition(line: str, function_name: str) -> bool:
    index = line.find(function_name)
    if index < 0:
        return False
    if line.strip().startswith(f"{function_name}(") and not line.rstrip().endswith(";"):
        return True
    prefix = line[:index].strip()
    if not prefix or prefix in {"return", "if", "while", "for", "switch"}:
        return False
    if any(token in prefix for token in ("=", ",", ";", "(", ")")):
        return False
    return not line.rstrip().endswith(";")


def _iter_c_calls(line: str) -> list[tuple[str, list[str]]]:
    calls: list[tuple[str, list[str]]] = []
    ignored = {"if", "for", "while", "switch", "return", "sizeof"}
    index = 0
    quote = ""
    escaped = False
    while index < len(line):
        char = line[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if not (char.isalpha() or char == "_"):
            index += 1
            continue
        start = index
        index += 1
        while index < len(line) and (line[index].isalnum() or line[index] == "_"):
            index += 1
        name = line[start:index]
        open_index = index
        while open_index < len(line) and line[open_index].isspace():
            open_index += 1
        if name in ignored or open_index >= len(line) or line[open_index] != "(":
            continue
        close_index = _find_c_matching_paren(line, open_index)
        if close_index < 0:
            continue
        calls.append((name, _split_c_arguments(line[open_index + 1 : close_index])))
        index = close_index + 1
    return calls


def _find_c_matching_paren(text: str, open_index: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(open_index, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _split_c_arguments(raw: str) -> list[str]:
    args: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(raw):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            continue
        if char == "," and depth == 0:
            args.append(raw[start:index].strip())
            start = index + 1
    tail = raw[start:].strip()
    if tail:
        args.append(tail)
    return args


def _split_c_assignment(line: str) -> tuple[str, str]:
    quote = ""
    escaped = False
    for index, char in enumerate(line):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char != "=":
            continue
        prev_char = line[index - 1] if index > 0 else ""
        next_char = line[index + 1] if index + 1 < len(line) else ""
        if prev_char in {"=", "!", "<", ">"} or next_char == "=":
            continue
        lhs = line[:index].strip()
        rhs = line[index + 1 :].split(";", 1)[0].strip()
        return lhs, rhs
    return "", ""


def _assignment_variable(lhs: str) -> str:
    text = str(lhs or "").strip()
    if not text:
        return ""
    text = re.sub(r"\[[^\]]*\]\s*$", "", text).strip()
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", text)
    return match.group(1) if match else ""


def _strip_line_comment(line: str) -> str:
    quote = ""
    escaped = False
    for index, char in enumerate(line):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "/" and index + 1 < len(line) and line[index + 1] == "/":
            return line[:index]
    return line


def _clean_c_expr(expr: str) -> str:
    text = str(expr or "").strip()
    while text.startswith("("):
        close_index = _find_c_matching_paren(text, 0)
        if close_index <= 0:
            break
        prefix = text[1:close_index].strip()
        suffix = text[close_index + 1 :].strip()
        if not suffix:
            break
        if re.fullmatch(r"(?:const\s+)?(?:unsigned\s+|signed\s+)?[A-Za-z_][A-Za-z0-9_:\s\*]*", prefix):
            text = suffix
            continue
        break
    return text.strip()


def _literal_string_value(expr: str) -> str | None:
    text = str(expr or "").strip()
    if len(text) < 2 or text[0] != '"' or text[-1] != '"':
        return None
    try:
        value = ast.literal_eval(text)
    except Exception:
        return None
    return value if isinstance(value, str) else None


class _BinaryStringResolver:
    def __init__(self, binary_path: Path) -> None:
        self.binary_path = Path(binary_path)
        self._loaded = False
        self._sections: list[tuple[int, bytes]] = []
        self._is_little_endian = True
        self._word_size = 4
        self._cache: dict[str, str | None] = {}

    def resolve(self, expr: str) -> str | None:
        token = _clean_c_expr(expr)
        if token in self._cache:
            return self._cache[token]
        result = self._resolve_uncached(token)
        self._cache[token] = result
        return result

    def _resolve_uncached(self, token: str) -> str | None:
        match = _DAT_TOKEN_RE.search(token)
        if not match:
            return None
        address = int(match.group(1), 16)
        self._load()
        if not self._sections:
            return None
        if token.startswith("s_"):
            direct = self._read_c_string(address)
            if direct is not None:
                return direct
        pointer_bytes = self._read_bytes(address, self._word_size)
        if pointer_bytes:
            pointer = int.from_bytes(pointer_bytes, "little" if self._is_little_endian else "big")
            resolved = self._read_c_string(pointer)
            if resolved is not None:
                return resolved
        return self._read_c_string(address)

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]
        except Exception:
            return
        try:
            with self.binary_path.open("rb") as handle:
                elf = ELFFile(handle)
                self._is_little_endian = elf.little_endian
                self._word_size = 8 if elf.elfclass == 64 else 4
                sections: list[tuple[int, bytes]] = []
                for section in elf.iter_sections():
                    address = int(section["sh_addr"] or 0)
                    size = int(section["sh_size"] or 0)
                    if address <= 0 or size <= 0:
                        continue
                    try:
                        data = section.data()
                    except Exception:
                        continue
                    sections.append((address, bytes(data)))
                self._sections = sections
        except Exception:
            self._sections = []

    def _read_bytes(self, address: int, size: int) -> bytes | None:
        if size <= 0:
            return None
        for base, data in self._sections:
            offset = address - base
            if 0 <= offset <= len(data) - size:
                return data[offset : offset + size]
        return None

    def _read_c_string(self, address: int, max_bytes: int = 4096) -> str | None:
        chunks = bytearray()
        for index in range(max_bytes):
            value = self._read_bytes(address + index, 1)
            if not value:
                return None
            byte = value[0]
            if byte == 0:
                if not chunks:
                    return ""
                try:
                    return bytes(chunks).decode("utf-8", errors="replace")
                except Exception:
                    return "".join(chr(item) for item in chunks)
            if byte < 0x09 or (0x0D < byte < 0x20):
                return None
            chunks.append(byte)
        return None


def unsupported_dynamic_overflow_proof(
    candidate_id: str,
    reason: str,
    *,
    request: ConcolicRequest | GhidraDynamicProofRequest | None = None,
) -> dict[str, Any]:
    """Return a stable non-reportable dynamic proof artifact."""

    request_payload: Mapping[str, Any] = request.to_dict() if request is not None else {}
    input_model = str(request_payload.get("input_model") or "")
    proof_scope = str(request_payload.get("proof_scope") or "")
    if not proof_scope and input_model:
        proof_scope = "function_harness" if input_model == "function_harness" else "process_entrypoint"
    process_setup_reason = str(reason)
    process_setup = (
        {
            "status": "unsupported" if process_setup_reason.startswith("unsupported_process_input_setup") else "not_run",
            "reason": process_setup_reason,
            "input_model": input_model,
            "concrete_input_hex": str(request_payload.get("concrete_input_hex") or ""),
            "stdin_input_hex": str(request_payload.get("stdin_input_hex") or ""),
            "file_input_hex": str(request_payload.get("file_input_hex") or ""),
            "file_name": str(request_payload.get("file_name") or ""),
            "process_input_source": str(request_payload.get("process_input_source") or ""),
            "process_input_evidence": dict(request_payload.get("process_input_evidence") or {})
            if isinstance(request_payload.get("process_input_evidence"), Mapping)
            else {},
        }
        if proof_scope == "process_entrypoint"
        else {"status": "not_applicable", "reason": "function_harness_scope"}
    )
    return {
        "schema_version": 1,
        "proof_kind": "ghidra_dynamic_overflow",
        "candidate_id": candidate_id,
        "status": "unsupported",
        "unsupported": True,
        "reason": str(reason),
        "proof_scope": proof_scope,
        "request": dict(request_payload),
        "sink_reached": False,
        "exact_sink_reached": False,
        "sink_address": "",
        "write_size_bytes": 0,
        "read_size_bytes": 0,
        "capacity_bytes": 0,
        "overflow_bytes": 0,
        "oob_bytes": 0,
        "write_range": {},
        "read_range": {},
        "object_range": {},
        "harness_model": {},
        "process_input_setup": process_setup,
        "process_replay": {"status": "unsupported", "reason": str(reason), "reached_target": False}
        if proof_scope == "process_entrypoint"
        else {},
        "local_sink_probe": {"status": "not_run", "reason": "unsupported_proof", "reached_target": False},
        "native_replay": _native_replay_not_run(),
    }


def _annotate_dynamic_overflow_proof(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
    proof_payload: Mapping[str, Any],
) -> dict[str, Any]:
    payload = dict(proof_payload)
    candidate = _candidate(evidence_pack)
    payload.setdefault("schema_version", 1)
    payload.setdefault("proof_kind", "ghidra_dynamic_overflow")
    payload.setdefault("candidate_id", request.candidate_id)
    payload.setdefault("sink_address", _normalize_address(request.sink_address or request.target_address))
    payload.setdefault("sink_name", str(candidate.get("sink") or ""))
    payload.setdefault("target_buffer", str(candidate.get("target_buffer") or ""))
    payload.setdefault("destination_kind", str(candidate.get("destination_kind") or ""))
    payload.setdefault("capacity_bytes", _safe_int(candidate.get("capacity_bytes"), default=0))
    payload.setdefault("capacity_source", str(candidate.get("capacity_source") or ""))
    payload.setdefault("capacity_basis", str(candidate.get("capacity_basis") or ""))
    payload.setdefault("read_size_bytes", _safe_int(candidate.get("write_size_bytes"), default=0))
    payload.setdefault("oob_bytes", 0)
    payload.setdefault("read_range", {})
    payload.setdefault("native_replay", _native_replay_not_run())
    payload.setdefault("source_trace", _source_trace_metadata(evidence_pack))
    classification_trace = candidate.get("classification_trace") if isinstance(candidate.get("classification_trace"), Mapping) else {}
    enrichment = classification_trace.get("fact_enrichment") if isinstance(classification_trace.get("fact_enrichment"), Mapping) else {}
    relational = enrichment.get("relational_safety_proof") if isinstance(enrichment.get("relational_safety_proof"), Mapping) else {}
    if relational:
        payload.setdefault("relational_safety_proof", dict(relational))
    proof_scope = str(payload.get("proof_scope") or "")
    if not proof_scope:
        proof_scope = "function_harness" if request.input_model == "function_harness" else "process_entrypoint"
        payload["proof_scope"] = proof_scope
    if proof_scope == "process_entrypoint":
        process_replay = payload.get("process_replay")
        if not isinstance(process_replay, Mapping):
            process_replay = payload.get("path_replay") if isinstance(payload.get("path_replay"), Mapping) else {}
            payload["process_replay"] = dict(process_replay)
        payload.setdefault(
            "process_input_setup",
            dict(process_replay.get("process_input_setup") or {}) if isinstance(process_replay, Mapping) else {},
        )
        local_sink_probe = payload.get("local_exact_sink_replay")
        payload.setdefault("local_sink_probe", dict(local_sink_probe) if isinstance(local_sink_probe, Mapping) else {})
        if str(payload.get("status") or "") in DYNAMIC_MEMORY_PROOF_STATUSES and str(process_replay.get("status") or "") != "reached":
            payload["status"] = "sink_unreached"
            payload["reason"] = "process_replay_did_not_reach_exact_sink"
            payload["sink_reached"] = False
            payload["exact_sink_reached"] = False
            payload["overflow_bytes"] = 0
            payload["oob_bytes"] = 0
    else:
        payload.setdefault("process_input_setup", {"status": "not_applicable", "reason": "function_harness_scope"})
        payload.setdefault("process_replay", {})
        local_sink_probe = payload.get("local_exact_sink_replay")
        payload.setdefault("local_sink_probe", dict(local_sink_probe) if isinstance(local_sink_probe, Mapping) else {})
    entrypoint = _derived_process_entrypoint(evidence_pack, request)
    if entrypoint:
        payload.setdefault(
            "process_entrypoint",
            {
                "entry_function": str(entrypoint.get("entry_function") or ""),
                "entry_address": _normalize_address(entrypoint.get("entry_address")),
                "input_model": str(entrypoint.get("input_model") or ""),
                "call_path": [str(item) for item in _coerce_sequence(entrypoint.get("call_path", []))],
                "entry_surface": dict(entrypoint.get("entry_surface") or {}) if isinstance(entrypoint.get("entry_surface"), Mapping) else {},
            },
        )
    status = str(payload.get("status") or "")
    if status not in CONCOLIC_DYNAMIC_PROOF_STATUSES:
        payload["status"] = "backend_error"
        payload["reason"] = f"invalid_dynamic_proof_status:{status}"
    return payload


def _annotate_pcode_sink_trace(
    evidence_pack: Mapping[str, Any],
    request: ConcolicRequest,
    pcode_payload: Mapping[str, Any],
) -> dict[str, Any]:
    payload = dict(pcode_payload)
    resolution = payload.get("exact_sink_resolution") if isinstance(payload.get("exact_sink_resolution"), Mapping) else {}
    sink_address = _exact_sink_address_from_pack(evidence_pack) or _normalize_address(resolution.get("exact_sink_address"))
    candidate = _candidate(evidence_pack)
    requested = _normalize_address(request.target_address)
    replay = payload.get("replay") if isinstance(payload.get("replay"), Mapping) else {}
    exact_sink_replay = payload.get("exact_sink_replay") if isinstance(payload.get("exact_sink_replay"), Mapping) else {}
    function_entry_reached = str(replay.get("status") or payload.get("status") or "") == "reached"
    local_exact_reached = str(exact_sink_replay.get("status") or "") == "reached"
    pcode_target = _normalize_address(payload.get("target_address"))
    script_resolved = bool(resolution.get("resolved") and sink_address and pcode_target == sink_address)
    pack_exact = _exact_sink_address_from_pack(evidence_pack)
    function_address = _normalize_address(candidate.get("address"))
    pack_exact_is_function_entry = bool(pack_exact and function_address and pack_exact == function_address)
    exact_selected = bool(
        sink_address and (script_resolved or (pack_exact and not pack_exact_is_function_entry and requested == sink_address))
    )
    exact_reached = bool(exact_selected and function_entry_reached and pcode_target == sink_address)
    reason = ""
    if not sink_address:
        reason = "missing_exact_operation_address"
    elif pack_exact_is_function_entry and not script_resolved:
        reason = "function_entry_is_not_exact_sink"
    elif not exact_selected:
        reason = "target_address_is_not_exact_sink"
    elif not exact_reached:
        reason = "pcode_replay_did_not_reach_exact_sink"
    payload["sink_trace"] = {
        "schema_version": 1,
        "exact_sink_address": sink_address,
        "requested_target_address": requested,
        "pcode_target_address": pcode_target,
        "candidate_function_address": function_address,
        "exact_sink_selected": exact_selected,
        "exact_sink_reached": exact_reached,
        "function_entry_reached_exact_sink": bool(function_entry_reached and pcode_target == sink_address),
        "local_exact_sink_replayed": bool(local_exact_reached and pcode_target == sink_address),
        "exact_sink_replay_kind": "function_entry"
        if bool(function_entry_reached and pcode_target == sink_address)
        else "",
        "reason": reason,
        "resolution": dict(resolution),
        "source_trace": _source_trace_metadata(evidence_pack),
    }
    return payload


def _exact_sink_address_from_pack(evidence_pack: Mapping[str, Any]) -> str:
    candidate = _candidate(evidence_pack)
    address = _normalize_address(candidate.get("operation_address"))
    if address:
        return address
    facts = _facts(evidence_pack)
    for row in _coerce_sequence(facts.get("write_table", [])):
        if isinstance(row, Mapping):
            address = _normalize_address(row.get("operation_address"))
            if address:
                return address
    for key in ("exact_sink_address", "llm_exact_sink_address"):
        address = _normalize_address(facts.get(key))
        if address:
            return address
    pcode_slice = facts.get("pcode_slice") if isinstance(facts.get("pcode_slice"), Mapping) else {}
    return _normalize_address(pcode_slice.get("operation_address"))


def _source_trace_metadata(evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    facts = _facts(evidence_pack)
    reproducer = facts.get("reproducer_hypothesis")
    if not isinstance(reproducer, Mapping):
        reproducer = evidence_pack.get("reproducer_hypothesis")
    if not isinstance(reproducer, Mapping):
        reproducer = {}
    entrypoint = _semantic_entrypoint_derivation(evidence_pack)
    source_to_sink = {}
    if isinstance(entrypoint, Mapping):
        source_to_sink = dict(entrypoint.get("source_to_sink_trace") or {}) if isinstance(entrypoint.get("source_to_sink_trace"), Mapping) else {}
    if not source_to_sink and isinstance(_facts(evidence_pack).get("source_to_sink_trace"), Mapping):
        source_to_sink = dict(_facts(evidence_pack).get("source_to_sink_trace") or {})
    entry_model = str(entrypoint.get("input_model") or "") if isinstance(entrypoint, Mapping) else ""
    entry_function = str(entrypoint.get("entry_function") or "") if isinstance(entrypoint, Mapping) else ""
    entry_call_path = (
        [str(item) for item in _coerce_sequence(entrypoint.get("call_path", []))]
        if isinstance(entrypoint, Mapping)
        else []
    )
    return {
        "input_surface": entry_model or str(reproducer.get("input_surface") or ""),
        "suggested_entry": entry_function or str(reproducer.get("suggested_entry") or ""),
        "call_path": entry_call_path or [str(item) for item in _coerce_sequence(reproducer.get("call_path", []))],
        "controlled_roles": [str(item) for item in _coerce_sequence(source_to_sink.get("controlled_roles") or reproducer.get("controlled_roles", []))],
        "blocking_unknowns": [str(item) for item in _coerce_sequence(reproducer.get("blocking_unknowns", []))],
        "entrypoint_status": str(entrypoint.get("status") or "") if isinstance(entrypoint, Mapping) else "",
        "entry_surface": dict(entrypoint.get("entry_surface") or {}) if isinstance(entrypoint.get("entry_surface"), Mapping) else {},
        "source_to_sink_trace": source_to_sink,
    }


def run_concolic_tool_request(
    evidence_pack: Mapping[str, Any],
    tool_request: Mapping[str, Any],
    config: ConcolicToolConfig,
) -> dict[str, Any]:
    """Execute and persist one controller-loop concolic tool request."""

    request = concolic_request_from_tool_request(evidence_pack, tool_request, config)
    config.output_dir.mkdir(parents=True, exist_ok=True)
    output_path = config.output_dir / _concolic_filename(request.candidate_id)
    if output_path.exists() and not config.overwrite:
        payload = json.loads(output_path.read_text() or "{}")
        verdict = _concolic_verdict_from_payload(payload)
        verdict_path = _artifact_run_dir(config.output_dir, request.candidate_id) / CONCOLIC_VERDICT_FILENAME
        if not verdict_path.exists():
            verdict_path = output_path
    else:
        llm_actions = _llm_actions_for_tool_request(tool_request)
        artifact_dir = _artifact_run_dir(config.output_dir, request.candidate_id)
        verdict = run_concolic_request(
            request,
            evidence_pack,
            artifact_dir=artifact_dir,
            ghidra_dynamic_proof=config.ghidra_dynamic_proof,
            ghidra_dynamic_max_steps=config.ghidra_dynamic_max_steps,
            ghidra_dir=config.ghidra_dir,
            llm_actions=llm_actions,
        )
        verdict_path, verdict = _write_concolic_artifacts(
            config.output_dir,
            request,
            verdict,
            pcode_trace_enabled=False,
            ghidra_dynamic_proof_enabled=config.ghidra_dynamic_proof,
            compatibility_path=output_path,
        )
    return {
        "tool": CONCOLIC_TOOL_NAME,
        "status": "ok",
        "candidate_id": request.candidate_id,
        "result": verdict.to_dict(),
        "artifact_path": str(verdict_path),
        "compatibility_artifact_path": str(output_path),
    }


def run_concolic_evidence_dir(
    evidence_dir: Path,
    *,
    binary_path: Path,
    output_dir: Path,
    export_dir: Path | None = None,
    backend: str = "angr",
    input_model: str = "",
    symbolic_bytes: int = 256,
    timeout_seconds: float = 30.0,
    pcode_trace: bool = False,
    ghidra_dynamic_proof: bool = False,
    ghidra_dynamic_max_steps: int = 2048,
    ghidra_dir: Path | None = None,
    llm_controller: bool = False,
    target_candidate_id: str = "",
    target_candidate_ids: Sequence[str] | None = None,
    target_selector: str = "",
    target_limit: int = 0,
    overwrite: bool = False,
    continue_on_error: bool = False,
    jobs: int = 1,
    isolate_candidates: bool = False,
    memory_limit_mb: int = 0,
    native_replay: bool = True,
) -> ConcolicRunResult:
    """Run concolic verification over every pack in an evidence-pack directory."""

    from binary_agent.analysis.confirmation import iter_evidence_packs

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    skipped: list[str] = []
    errors: dict[str, str] = {}
    verdict_counts = {verdict: 0 for verdict in sorted(CONCOLIC_VERDICTS)}
    diagnostic_counts: dict[str, int] = {}
    tasks: list[tuple[Path, Mapping[str, Any]]] = []
    loaded_packs = iter_evidence_packs(Path(evidence_dir))
    selected_packs = _select_concolic_target_packs(
        loaded_packs,
        target_candidate_id=target_candidate_id,
        target_candidate_ids=target_candidate_ids,
        target_selector=target_selector,
        target_limit=target_limit,
        single_target=False,
    )
    for pack_path, evidence_pack in selected_packs:
        candidate_id = _candidate_id_from_pack(evidence_pack) or pack_path.stem
        output_path = output_dir / _concolic_filename(candidate_id)
        if output_path.exists() and not overwrite:
            skipped.append(candidate_id)
            continue
        tasks.append((pack_path, evidence_pack))

    worker_tasks = [
        {
            "pack_path": str(pack_path),
            "evidence_pack": dict(evidence_pack),
            "binary_path": str(binary_path),
            "output_dir": str(output_dir),
            "export_dir": str(export_dir) if export_dir is not None else "",
            "backend": backend,
            "input_model": input_model,
            "symbolic_bytes": symbolic_bytes,
            "timeout_seconds": timeout_seconds,
            "pcode_trace": pcode_trace,
            "ghidra_dynamic_proof": ghidra_dynamic_proof,
            "ghidra_dynamic_max_steps": ghidra_dynamic_max_steps,
            "ghidra_dir": str(ghidra_dir) if ghidra_dir is not None else "",
            "llm_controller": llm_controller,
            "continue_on_error": continue_on_error,
            "memory_limit_mb": int(memory_limit_mb or 0),
            "native_replay": bool(native_replay),
        }
        for pack_path, evidence_pack in tasks
    ]

    def record_worker_result(worker_result: Mapping[str, Any]) -> None:
        output_path = Path(str(worker_result["output_path"]))
        verdict = ConcolicVerdict.from_dict(worker_result["verdict"])
        error = worker_result.get("error")
        written.append(output_path)
        if error is not None:
            errors[verdict.candidate_id] = str(error)
        verdict_counts[verdict.verdict] = verdict_counts.get(verdict.verdict, 0) + 1
        diagnostic = verdict.diagnostic
        diagnostic_key = f"{diagnostic['stage']}:{diagnostic['reason']}"
        diagnostic_counts[diagnostic_key] = diagnostic_counts.get(diagnostic_key, 0) + 1

    jobs = max(1, int(jobs or 1))
    attempted_count = 0
    if isolate_candidates:
        isolated_results, attempted_count = _run_isolated_concolic_workers(
            worker_tasks,
            jobs=jobs,
            continue_on_error=continue_on_error,
        )
        for worker_result in isolated_results:
            record_worker_result(worker_result)
    else:
        attempted_count = len(tasks)
        for task in worker_tasks:
            record_worker_result(_run_concolic_worker(task))

    result = ConcolicRunResult(
        output_dir=output_dir,
        written=tuple(written),
        skipped=tuple(skipped),
        errors=errors,
        verdict_counts=verdict_counts,
        eligible_count=len(selected_packs),
        scheduled_count=len(tasks),
        attempted_count=attempted_count,
        timed_out_count=int(verdict_counts.get("timeout") or 0),
        memory_limited_count=int(diagnostic_counts.get("resource:memory_limit") or 0),
        diagnostic_counts=dict(sorted(diagnostic_counts.items())),
    )
    (output_dir / CONCOLIC_RUN_SUMMARY).write_text(json.dumps(result.to_dict(), indent=2))
    return result


def _select_concolic_target_packs(
    packs: Sequence[tuple[Path, Mapping[str, Any]]],
    *,
    target_candidate_id: str = "",
    target_candidate_ids: Sequence[str] | None = None,
    target_selector: str = "",
    target_limit: int = 0,
    single_target: bool = False,
) -> list[tuple[Path, Mapping[str, Any]]]:
    if target_selector not in TARGET_SELECTORS:
        raise ValueError(f"target_selector must be one of {sorted(TARGET_SELECTORS)}")
    selected = list(packs)
    if target_candidate_id:
        selected = [
            (path, pack)
            for path, pack in selected
            if _candidate_id_from_pack(pack) == target_candidate_id
        ]
        if not selected:
            raise ValueError(f"target_candidate_id not found: {target_candidate_id}")
        return selected[:1] if single_target else selected
    if target_candidate_ids is not None:
        ordered_ids = list(dict.fromkeys(str(item) for item in target_candidate_ids if str(item)))
        by_id = {_candidate_id_from_pack(pack): (path, pack) for path, pack in selected}
        missing = [candidate_id for candidate_id in ordered_ids if candidate_id not in by_id]
        if missing:
            raise ValueError(f"target_candidate_ids not found: {', '.join(missing)}")
        return [by_id[candidate_id] for candidate_id in ordered_ids]
    if target_selector == "direct_stack_overflow":
        selected = [
            (path, pack)
            for path, pack in selected
            if _is_direct_stack_overflow_pack(pack)
        ]
        selected.sort(key=lambda item: _direct_stack_overflow_priority(item[1]))
        return _limit_concolic_target_packs(selected, single_target=single_target, target_limit=target_limit)
    if target_selector == "direct_heap_overflow":
        selected = [
            (path, pack)
            for path, pack in selected
            if _is_direct_heap_overflow_pack(pack)
        ]
        selected.sort(key=lambda item: _direct_heap_overflow_priority(item[1]))
        return _limit_concolic_target_packs(selected, single_target=single_target, target_limit=target_limit)
    if target_selector == "direct_memory_overflow":
        selected = [
            (path, pack)
            for path, pack in selected
            if _is_direct_stack_overflow_pack(pack) or _is_direct_heap_overflow_pack(pack)
        ]
        selected.sort(key=lambda item: _direct_memory_overflow_priority(item[1]))
        return _limit_concolic_target_packs(selected, single_target=single_target, target_limit=target_limit)
    if target_selector == "proof_ready_memory":
        selected = [
            (path, pack)
            for path, pack in selected
            if _is_proof_ready_memory_pack(pack)
        ]
        selected.sort(key=lambda item: _proof_ready_memory_priority(item[1]))
        controlled_selected = [
            (path, pack)
            for path, pack in selected
            if _source_to_sink_control_rank(pack) <= 2
        ]
        if controlled_selected:
            selected = controlled_selected
        return _limit_concolic_target_packs(selected, single_target=single_target, target_limit=target_limit)
    return _limit_concolic_target_packs(selected, single_target=single_target, target_limit=target_limit)


def _limit_concolic_target_packs(
    selected: list[tuple[Path, Mapping[str, Any]]],
    *,
    single_target: bool,
    target_limit: int,
) -> list[tuple[Path, Mapping[str, Any]]]:
    if single_target:
        return selected[:1]
    limit = int(target_limit or 0)
    if limit <= 0:
        return selected
    return selected[:limit]


def _is_proof_ready_memory_pack(evidence_pack: Mapping[str, Any]) -> bool:
    candidate = _candidate_for_memory_proof(evidence_pack)
    if _is_proof_ready_oob_read_pack(evidence_pack):
        return True
    sink = _semantic_api_name(candidate.get("sink"))
    if sink not in {
        "read",
        "fread",
        "fgets",
        "gets",
        "memcpy",
        "memmove",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "sprintf",
        "snprintf",
        "vsprintf",
        "vsnprintf",
    }:
        return False
    destination = str(candidate.get("destination_kind") or "").lower()
    if not any(kind in destination for kind in ("stack", "heap", "global")):
        return False
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    if capacity <= 0:
        capacity_model = _candidate_capacity_model(evidence_pack)
        if "heap" not in destination or not str(capacity_model.get("symbolic_expr") or ""):
            return False
    write_size = _safe_int(candidate.get("write_size_bytes"), default=0)
    relation = str(candidate.get("write_relation") or "")
    verdict = str(candidate.get("verdict") or "")
    proof = evidence_pack.get("proof_obligation") if isinstance(evidence_pack.get("proof_obligation"), Mapping) else {}
    proof_relation = str(proof.get("relation") or "")
    return (
        write_size > capacity
        or relation in {"proven_overflow", "unbounded"}
        or verdict in {"overflow", "unbounded"}
        or proof_relation in {"proven_overflow", "unbounded"}
    )


def _is_proof_ready_oob_read_pack(evidence_pack: Mapping[str, Any]) -> bool:
    candidate = _candidate(evidence_pack)
    if str(candidate.get("vulnerability_type") or "") != "out_of_bounds_read":
        return False
    raw_sink = str(candidate.get("sink") or "").lower()
    sink = _semantic_api_name(raw_sink)
    if sink != "array_load" and not raw_sink.endswith("_source_read") and raw_sink != "cursor_limit_read":
        return False
    if sink == "array_load" and not _normalize_address(candidate.get("operation_address")):
        return False
    destination = str(candidate.get("destination_kind") or "").lower()
    trace = _candidate_classification_trace(evidence_pack)
    if not any(kind in destination for kind in ("stack", "heap", "global")) and not (
        "source_buffer" in destination and isinstance(trace.get("cursor_limit_read"), Mapping)
    ):
        return False
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    capacity_model = _candidate_capacity_model(evidence_pack)
    if capacity <= 0 and not str(capacity_model.get("symbolic_expr") or ""):
        return False
    write_size = _safe_int(candidate.get("write_size_bytes"), default=0)
    relation = str(candidate.get("write_relation") or "")
    verdict = str(candidate.get("verdict") or "")
    proof = evidence_pack.get("proof_obligation") if isinstance(evidence_pack.get("proof_obligation"), Mapping) else {}
    proof_relation = str(proof.get("relation") or "")
    return (
        write_size > 0
        or bool(str(candidate.get("write_size_expr") or ""))
        or bool(str(candidate.get("offset_expr") or ""))
        or relation in {"proven_oob_read", "symbolic_read_offset", "symbolic_size"}
        or verdict in {"oob_read_proven", "overflow"}
        or proof_relation in {"proven_oob_read", "symbolic_read_offset", "symbolic_size"}
    )


def _proof_ready_memory_priority(evidence_pack: Mapping[str, Any]) -> tuple[int, int, int, int, int, int, str]:
    candidate = _candidate_for_memory_proof(evidence_pack)
    destination = str(candidate.get("destination_kind") or "").lower()
    destination_rank = 0 if "stack" in destination else 1 if "heap" in destination else 2
    raw_sink = str(candidate.get("sink") or "").lower()
    sink = _semantic_api_name(raw_sink)
    oob_rank = 0 if str(candidate.get("vulnerability_type") or "") == "out_of_bounds_read" else 1
    if raw_sink.endswith("_source_read"):
        sink_rank = 0
    elif sink == "array_load":
        sink_rank = 1
    else:
        sink_rank = 0 if sink in {"memcpy", "strcpy", "sprintf", "snprintf", "fgets", "strcat"} else 2
    write_size = _safe_int(candidate.get("write_size_bytes"), default=0)
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    return (
        _source_to_sink_control_rank(evidence_pack),
        _entrypoint_path_rank(evidence_pack),
        oob_rank,
        sink_rank,
        destination_rank,
        -max(0, write_size - capacity),
        _candidate_id_from_pack(evidence_pack),
    )


def _source_to_sink_control_rank(evidence_pack: Mapping[str, Any]) -> int:
    trace = _source_to_sink_trace(evidence_pack)
    if not trace:
        return 3
    controlled = bool(trace.get("attacker_control_reaches_sink_role"))
    blockers = [str(item) for item in _coerce_sequence(trace.get("blockers")) if str(item)]
    status = str(trace.get("status") or "").lower()
    confidence = str(trace.get("confidence") or "").lower()
    if controlled and not blockers and (status in {"complete", "proven"} or confidence == "proven"):
        return 0
    if controlled and not blockers:
        return 1
    if controlled:
        return 2
    if blockers or status == "blocked" or confidence == "blocked":
        return 4
    return 3


def _source_to_sink_trace(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    top_level = evidence_pack.get("source_to_sink_trace")
    if isinstance(top_level, Mapping):
        return top_level
    derivation = evidence_pack.get("entrypoint_derivation")
    if isinstance(derivation, Mapping) and isinstance(derivation.get("source_to_sink_trace"), Mapping):
        return derivation["source_to_sink_trace"]
    facts = _facts(evidence_pack)
    derivation = facts.get("entrypoint_derivation")
    if isinstance(derivation, Mapping) and isinstance(derivation.get("source_to_sink_trace"), Mapping):
        return derivation["source_to_sink_trace"]
    trace = facts.get("source_to_sink_trace")
    if isinstance(trace, Mapping):
        return trace
    return {}


def _entrypoint_path_rank(evidence_pack: Mapping[str, Any]) -> int:
    derivation = evidence_pack.get("entrypoint_derivation")
    if not isinstance(derivation, Mapping):
        return 1_000_000
    reachability = derivation.get("entry_reachability")
    if isinstance(reachability, Mapping):
        length = _safe_int(reachability.get("path_length"), default=0)
        if length > 0:
            return length
    call_path = _coerce_sequence(derivation.get("call_path"))
    if call_path:
        return len(call_path)
    return 1_000_000


def _is_direct_stack_overflow_pack(evidence_pack: Mapping[str, Any]) -> bool:
    candidate = _candidate_for_memory_proof(evidence_pack)
    sink = str(candidate.get("sink") or "").lower()
    if sink not in {"read", "memcpy", "strcpy", "sprintf", "snprintf"}:
        return False
    if "stack" not in str(candidate.get("destination_kind") or "").lower():
        return False
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    if capacity <= 0:
        return False
    write_size = _safe_int(candidate.get("write_size_bytes"), default=0)
    relation = str(candidate.get("write_relation") or "")
    verdict = str(candidate.get("verdict") or "")
    return write_size > capacity or relation in {"proven_overflow", "unbounded"} or verdict in {"overflow", "unbounded"}


def _direct_stack_overflow_priority(evidence_pack: Mapping[str, Any]) -> tuple[int, int, str]:
    candidate = _candidate_for_memory_proof(evidence_pack)
    target_buffer = str(candidate.get("target_buffer") or "")
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    sink = str(candidate.get("sink") or "").lower()
    local_258 = 0 if ("local_258" in target_buffer and capacity == 0x200) else 1
    sink_rank = 0 if sink in {"read", "memcpy"} else 1
    return (local_258, sink_rank, _candidate_id_from_pack(evidence_pack))


def _is_direct_heap_overflow_pack(evidence_pack: Mapping[str, Any]) -> bool:
    candidate = _candidate(evidence_pack)
    sink = str(candidate.get("sink") or "").lower()
    if sink not in {"read", "memcpy", "strcpy", "sprintf", "snprintf"}:
        return False
    if "heap" not in str(candidate.get("destination_kind") or "").lower():
        return False
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    if capacity <= 0:
        return False
    write_size = _safe_int(candidate.get("write_size_bytes"), default=0)
    relation = str(candidate.get("write_relation") or "")
    verdict = str(candidate.get("verdict") or "")
    return write_size > capacity or relation in {"proven_overflow", "unbounded"} or verdict in {"overflow", "unbounded"}


def _direct_heap_overflow_priority(evidence_pack: Mapping[str, Any]) -> tuple[int, int, str]:
    candidate = _candidate(evidence_pack)
    sink = str(candidate.get("sink") or "").lower()
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    write_size = _safe_int(candidate.get("write_size_bytes"), default=0)
    source = str(candidate.get("capacity_source") or "")
    trusted_source_rank = 0 if source.startswith(("local_", "allocator_wrapper:")) else 1
    sink_rank = 0 if sink in {"memcpy", "snprintf", "sprintf"} else 1
    overflow_margin = max(0, write_size - capacity)
    return (trusted_source_rank, sink_rank, -overflow_margin, _candidate_id_from_pack(evidence_pack))


def _direct_memory_overflow_priority(evidence_pack: Mapping[str, Any]) -> tuple[int, int, int, str]:
    candidate = _candidate(evidence_pack)
    destination = str(candidate.get("destination_kind") or "").lower()
    destination_rank = 0 if "stack" in destination else 1 if "heap" in destination else 2
    if "heap" in destination:
        heap_rank = _direct_heap_overflow_priority(evidence_pack)
        return (destination_rank, heap_rank[0], heap_rank[1], heap_rank[3])
    stack_rank = _direct_stack_overflow_priority(evidence_pack)
    return (destination_rank, stack_rank[0], stack_rank[1], stack_rank[2])


def _run_concolic_worker(task: Mapping[str, Any]) -> dict[str, Any]:
    pack_path = Path(str(task["pack_path"]))
    evidence_pack = dict(task["evidence_pack"])
    output_dir = Path(str(task["output_dir"]))
    binary_path = Path(str(task["binary_path"]))
    export_dir_text = str(task.get("export_dir") or "")
    export_dir = Path(export_dir_text) if export_dir_text else None
    backend = str(task.get("backend") or "angr")
    input_model = str(task.get("input_model") or "")
    symbolic_bytes = int(task.get("symbolic_bytes") or 256)
    timeout_seconds = float(task.get("timeout_seconds") or 30.0)
    pcode_trace = bool(task.get("pcode_trace", False))
    ghidra_dynamic_proof = bool(task.get("ghidra_dynamic_proof", False))
    ghidra_dynamic_max_steps = int(task.get("ghidra_dynamic_max_steps") or 2048)
    ghidra_dir_text = str(task.get("ghidra_dir") or "")
    ghidra_dir = Path(ghidra_dir_text) if ghidra_dir_text else None
    llm_controller = bool(task.get("llm_controller", False))
    continue_on_error = bool(task.get("continue_on_error", False))
    native_replay = bool(task.get("native_replay", True))

    candidate_id = _candidate_id_from_pack(evidence_pack) or pack_path.stem
    output_path = output_dir / _concolic_filename(candidate_id)
    try:
        request, llm_actions = _request_for_evidence_pack(
            evidence_pack,
            binary_path=binary_path,
            output_dir=output_dir,
            export_dir=export_dir,
            backend=backend,
            input_model=input_model,
            symbolic_bytes=symbolic_bytes,
            timeout_seconds=timeout_seconds,
            llm_controller=llm_controller,
        )
        artifact_dir = _artifact_run_dir(output_dir, request.candidate_id)
        verdict = run_concolic_request(
            request,
            evidence_pack,
            pcode_trace=pcode_trace,
            ghidra_dynamic_proof=ghidra_dynamic_proof,
            ghidra_dynamic_max_steps=ghidra_dynamic_max_steps,
            ghidra_dir=ghidra_dir,
            artifact_dir=artifact_dir,
            llm_actions=llm_actions,
            native_replay=native_replay,
        )
        error = None
    except Exception as exc:
        if not continue_on_error:
            raise
        error = (
            f"worker_memory_limit_exceeded:{int(task.get('memory_limit_mb') or 0)}MiB"
            if isinstance(exc, MemoryError)
            else str(exc)
        )
        request_dict = {"candidate_id": candidate_id, "binary_path": str(binary_path), "backend": backend}
        verdict = ConcolicVerdict(
            candidate_id=candidate_id,
            verdict="backend_error",
            backend=backend,
            request=request_dict,
            rationale=error[:1000],
            errors=(error[:1000],),
            llm_actions=_default_llm_actions(enabled=llm_controller, rejected_reason=error[:1000]),
        )
    verdict_path, verdict = _write_concolic_artifacts(
        output_dir,
        ConcolicRequest.from_dict(verdict.request) if verdict.request else ConcolicRequest(
            candidate_id=candidate_id,
            binary_path=binary_path,
            export_dir=export_dir,
            backend=backend,
        ),
        verdict,
        pcode_trace_enabled=pcode_trace,
        ghidra_dynamic_proof_enabled=ghidra_dynamic_proof,
        compatibility_path=output_path,
    )
    return {"output_path": str(verdict_path), "verdict": verdict.to_dict(), "error": error}


def _run_isolated_concolic_workers(
    tasks: Sequence[Mapping[str, Any]],
    *,
    jobs: int,
    continue_on_error: bool,
) -> tuple[list[dict[str, Any]], int]:
    """Run each task in a fresh bounded process and never reuse its address space."""
    if not tasks:
        return [], 0
    context = multiprocessing.get_context("fork" if hasattr(os, "fork") else "spawn")
    pending = iter(tasks)
    active: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    attempted = 0
    exhausted = False
    try:
        while active or not exhausted:
            while len(active) < max(1, jobs) and not exhausted:
                try:
                    task = next(pending)
                except StopIteration:
                    exhausted = True
                    break
                receive, send = context.Pipe(duplex=False)
                worker_task = dict(task)
                worker_task["parent_pid"] = os.getpid()
                process = context.Process(target=_isolated_concolic_worker_entry, args=(worker_task, send))
                process.start()
                send.close()
                wall_timeout = _isolated_worker_timeout_seconds(task)
                active.append(
                    {
                        "process": process,
                        "receive": receive,
                        "task": task,
                        "deadline": time.monotonic() + wall_timeout,
                        "wall_timeout": wall_timeout,
                    }
                )
                attempted += 1

            progressed = False
            for item in list(active):
                process = item["process"]
                receive = item["receive"]
                task = item["task"]
                message: Mapping[str, Any] | None = None
                if receive.poll():
                    try:
                        message = receive.recv()
                    except EOFError:
                        message = {"error": f"isolated_worker_exit:{process.exitcode}"}
                elif not process.is_alive():
                    process.join(timeout=0.1)
                    if receive.poll(0.1):
                        try:
                            message = receive.recv()
                        except EOFError:
                            pass
                    if message is None:
                        message = {"error": f"isolated_worker_exit:{process.exitcode}"}
                elif time.monotonic() >= float(item["deadline"]):
                    _terminate_isolated_process(process)
                    wall_timeout = float(item["wall_timeout"])
                    results.append(
                        _isolated_worker_failure_result(
                            task,
                            verdict="timeout",
                            reason=f"isolated_worker_timeout:{wall_timeout:g}s",
                            elapsed_seconds=wall_timeout,
                        )
                    )
                    receive.close()
                    active.remove(item)
                    progressed = True
                    continue

                if message is None:
                    continue
                _finish_isolated_process(process)
                receive.close()
                active.remove(item)
                progressed = True
                worker_result = message.get("result")
                if isinstance(worker_result, Mapping):
                    results.append(dict(worker_result))
                    continue
                reason = str(message.get("error") or f"isolated_worker_exit:{process.exitcode}")
                if "MemoryError" in reason and int(task.get("memory_limit_mb") or 0) > 0:
                    reason = f"worker_memory_limit_exceeded:{int(task['memory_limit_mb'])}MiB"
                if not continue_on_error:
                    raise RuntimeError(reason)
                results.append(_isolated_worker_failure_result(task, verdict="backend_error", reason=reason))

            if not progressed and active:
                time.sleep(ISOLATED_WORKER_POLL_SECONDS)
    finally:
        for item in active:
            _terminate_isolated_process(item["process"])
            item["receive"].close()
    return results, attempted


def _ghidra_subprocess_timeout_seconds(backend_timeout: float) -> float:
    return max(
        float(backend_timeout) + GHIDRA_SUBPROCESS_STARTUP_GRACE_SECONDS,
        GHIDRA_SUBPROCESS_MIN_TIMEOUT_SECONDS,
    )


def _isolated_worker_timeout_seconds(task: Mapping[str, Any]) -> float:
    backend_timeout = max(0.01, float(task.get("timeout_seconds") or 30.0))
    wall_timeout = backend_timeout + ISOLATED_BACKEND_SETUP_GRACE_SECONDS
    ghidra_timeout = _ghidra_subprocess_timeout_seconds(backend_timeout)
    if bool(task.get("pcode_trace", False)):
        wall_timeout += ghidra_timeout
    if bool(task.get("ghidra_dynamic_proof", False)):
        wall_timeout += MAX_DYNAMIC_PROOF_ATTEMPTS * ghidra_timeout
        if bool(task.get("native_replay", True)):
            wall_timeout += min(backend_timeout, MAX_NATIVE_REPLAY_SECONDS)
    return wall_timeout + ISOLATED_WORKER_GRACE_SECONDS


def _isolated_concolic_worker_entry(task: Mapping[str, Any], connection: Any) -> None:
    try:
        if os.name == "posix":
            os.setsid()
        _set_parent_death_signal(int(task.get("parent_pid") or 0))
        _set_worker_memory_limit(int(task.get("memory_limit_mb") or 0))
        connection.send({"result": _run_concolic_worker(task)})
    except BaseException as exc:
        try:
            connection.send({"error": f"{type(exc).__name__}:{exc}"})
        except BaseException:
            pass
    finally:
        connection.close()


def _set_parent_death_signal(expected_parent_pid: int = 0) -> None:
    if not sys.platform.startswith("linux"):
        return
    def kill_worker_group(_signum: int, _frame: Any) -> None:
        os.killpg(os.getpgrp(), signal.SIGKILL)

    parent_pid = expected_parent_pid or os.getppid()
    signal.signal(signal.SIGTERM, kill_worker_group)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG) failed")
    if os.getppid() != parent_pid:
        kill_worker_group(signal.SIGTERM, None)


def _set_worker_memory_limit(memory_limit_mb: int) -> None:
    if memory_limit_mb <= 0:
        return
    try:
        import resource
    except ImportError as exc:
        raise RuntimeError("worker_memory_limit_unsupported") from exc
    if not hasattr(resource, "RLIMIT_AS"):
        raise RuntimeError("worker_memory_limit_unsupported")
    requested = memory_limit_mb * 1024 * 1024
    _soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    limit = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
    resource.setrlimit(resource.RLIMIT_AS, (limit, hard))


def _restore_subprocess_address_space_limit() -> None:
    if os.name != "posix":
        return
    import resource

    _soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (hard, hard))


def _ghidra_subprocess_limit_kwargs() -> dict[str, Any]:
    return {"preexec_fn": _restore_subprocess_address_space_limit} if os.name == "posix" else {}


def _terminate_isolated_process(process: multiprocessing.Process) -> None:
    if not process.is_alive():
        process.join(timeout=0.1)
        return
    used_group = False
    if os.name == "posix" and process.pid is not None:
        try:
            if os.getpgid(process.pid) == process.pid:
                os.killpg(process.pid, signal.SIGTERM)
                used_group = True
        except ProcessLookupError:
            pass
    if not used_group and process.is_alive():
        process.terminate()
    process.join(timeout=0.5)
    if not process.is_alive():
        return
    if used_group and process.pid is not None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif hasattr(process, "kill"):
        process.kill()
    else:
        process.terminate()
    process.join(timeout=1.0)


def _finish_isolated_process(process: multiprocessing.Process) -> None:
    process.join(timeout=1.0)
    if process.is_alive():
        _terminate_isolated_process(process)


def _isolated_worker_failure_result(
    task: Mapping[str, Any],
    *,
    verdict: str,
    reason: str,
    elapsed_seconds: float = 0.0,
) -> dict[str, Any]:
    evidence_pack = dict(task["evidence_pack"])
    candidate_id = _candidate_id_from_pack(evidence_pack) or Path(str(task["pack_path"])).stem
    output_dir = Path(str(task["output_dir"]))
    output_path = output_dir / _concolic_filename(candidate_id)
    binary_path = Path(str(task["binary_path"]))
    export_dir = Path(str(task["export_dir"])) if str(task.get("export_dir") or "") else None
    try:
        request, _llm_actions = _request_for_evidence_pack(
            evidence_pack,
            binary_path=binary_path,
            output_dir=output_dir,
            export_dir=export_dir,
            backend=str(task.get("backend") or "angr"),
            input_model=str(task.get("input_model") or ""),
            symbolic_bytes=int(task.get("symbolic_bytes") or 256),
            timeout_seconds=float(task.get("timeout_seconds") or 30.0),
            llm_controller=False,
        )
    except Exception:
        request = ConcolicRequest(
            candidate_id=candidate_id,
            binary_path=binary_path,
            export_dir=export_dir,
            backend=str(task.get("backend") or "angr"),
            symbolic_bytes=int(task.get("symbolic_bytes") or 256),
            timeout_seconds=float(task.get("timeout_seconds") or 30.0),
        )
    resolved = ConcolicVerdict(
        candidate_id=candidate_id,
        verdict=verdict,
        backend=request.backend,
        request=request.to_dict(),
        rationale=reason,
        errors=(reason,),
        elapsed_seconds=elapsed_seconds,
        llm_actions=_default_llm_actions(enabled=bool(task.get("llm_controller", False)), rejected_reason=reason),
    )
    verdict_path, resolved = _write_concolic_artifacts(
        output_dir,
        request,
        resolved,
        pcode_trace_enabled=bool(task.get("pcode_trace", False)),
        ghidra_dynamic_proof_enabled=bool(task.get("ghidra_dynamic_proof", False)),
        compatibility_path=output_path,
    )
    return {"output_path": str(verdict_path), "verdict": resolved.to_dict(), "error": reason}


def _dynamic_proof_bug_class(proof: Mapping[str, Any] | None) -> str:
    violation = (proof or {}).get("lifetime_violation")
    if isinstance(violation, Mapping) and violation.get("vulnerability"):
        return str(violation["vulnerability"])
    if str((proof or {}).get("status") or "") == "oob_read_proven":
        return "out_of_bounds_read"
    destination_kind = str((proof or {}).get("destination_kind") or "").lower()
    if "heap" in destination_kind:
        return "heap_buffer_overflow"
    if "stack" in destination_kind:
        return "stack_buffer_overflow"
    return "memory_buffer_overflow"


def concolic_confirmation_dict(verdict: ConcolicVerdict | Mapping[str, Any]) -> dict[str, Any]:
    """Convert a concolic verdict into strict ``CandidateConfirmation`` JSON."""

    resolved = verdict if isinstance(verdict, ConcolicVerdict) else ConcolicVerdict.from_dict(verdict)
    artifact_refs = [f"concolic_artifact:{path}" for path in resolved.artifact_paths]
    evidence_refs = _unique_strings(list(resolved.evidence_refs) + artifact_refs)
    if resolved.verdict in REPORTABLE_CONCOLIC_VERDICTS and resolved.reportable:
        status = "confirmed_bug"
        if _has_dynamic_lifetime_proof(resolved.ghidra_dynamic_proof):
            reason_code = "ghidra_dynamic_lifetime_violation_proven"
            rationale = resolved.rationale or "Ghidra dynamic proof reached the exact sink and tied the violating operation to a concrete released heap object."
        elif _has_dynamic_oob_read_proof(resolved.ghidra_dynamic_proof):
            reason_code = "ghidra_dynamic_oob_read_proven"
            rationale = resolved.rationale or "Ghidra dynamic proof reached the exact sink and proved the concrete read exceeds the modeled source object capacity."
        elif _has_dynamic_oob_write_proof(resolved.ghidra_dynamic_proof):
            reason_code = "ghidra_dynamic_oob_write_proven"
            rationale = resolved.rationale or "Ghidra dynamic proof reached the exact sink and proved the concrete write exceeds the modeled object capacity."
        elif _has_dynamic_heap_overflow_proof(resolved.ghidra_dynamic_proof):
            reason_code = "ghidra_dynamic_heap_overflow_proven"
            rationale = resolved.rationale or "Ghidra dynamic proof reached the exact sink and proved the concrete heap write exceeds allocation capacity."
        else:
            reason_code = "ghidra_dynamic_overflow_proven"
            rationale = resolved.rationale or "Ghidra dynamic proof reached the exact sink and proved the concrete write exceeds the modeled destination capacity."
    elif resolved.verdict in REPORTABLE_CONCOLIC_VERDICTS:
        status = "needs_dynamic_confirmation"
        proof_status = str((resolved.ghidra_dynamic_proof or {}).get("status") or "")
        if not _has_dynamic_proof_artifact(resolved.artifact_paths):
            reason_code = "ghidra_dynamic_proof_missing"
            rationale = resolved.rationale or "Concolic execution produced a witness, but Ghidra dynamic proof was not run."
        elif proof_status == "sink_unreached":
            reason_code = "ghidra_dynamic_sink_unreached"
            rationale = resolved.rationale or "Ghidra dynamic proof did not reach the exact sink with the concrete input."
        elif proof_status == "no_overflow":
            reason_code = "ghidra_dynamic_no_overflow"
            rationale = resolved.rationale or "Ghidra reached the sink but did not prove a write beyond destination capacity."
        elif proof_status == "no_oob_read":
            reason_code = "ghidra_dynamic_no_oob_read"
            rationale = resolved.rationale or "Ghidra reached the sink but did not prove a read beyond source object capacity."
        elif proof_status == "no_lifetime_violation":
            reason_code = "ghidra_dynamic_no_lifetime_violation"
            rationale = resolved.rationale or "Ghidra reached the sink but did not tie the operation to an object in the required lifetime state."
        else:
            reason_code = "ghidra_dynamic_overflow_not_proven"
            rationale = (
                resolved.rationale
                or "Concolic execution produced a witness, but Ghidra did not prove a concrete memory-safety violation."
            )
    elif resolved.verdict in SAFE_CONCOLIC_VERDICTS:
        status = "not_a_bug"
        reason_code = f"concolic_{resolved.verdict}"
        rationale = resolved.rationale or "Concolic execution refuted the candidate path."
    elif resolved.verdict == "target_reached" and str((resolved.ghidra_dynamic_proof or {}).get("status") or "").startswith("no_"):
        status = "needs_more_evidence"
        reason_code = f"ghidra_dynamic_{str(resolved.ghidra_dynamic_proof.get('status') or '')}"
        rationale = resolved.rationale or "Ghidra reached the exact sink but the concrete operation did not violate modeled memory safety."
    elif resolved.verdict == "timeout":
        status = "needs_dynamic_confirmation"
        reason_code = "concolic_timeout"
        rationale = resolved.rationale or "Concolic execution timed out before reaching a decisive verdict."
    elif resolved.verdict == "backend_error" and any("unsupported_input_model" in error for error in resolved.errors):
        status = "needs_dynamic_confirmation"
        reason_code = "concolic_unsupported_harness"
        rationale = resolved.rationale or "The current concolic backend does not support the required harness."
    else:
        status = "needs_more_evidence"
        reason_code = "concolic_backend_error"
        rationale = resolved.rationale or "The concolic backend could not analyze this candidate."

    memory_safety_argument: dict[str, Any] = {
        "concolic_verdict": resolved.verdict,
        "backend": resolved.backend,
        "reached_addresses": list(resolved.reached_addresses),
        "replay_result": dict(resolved.replay_result),
        "native_replay": _native_replay_not_run(),
    }
    if resolved.witness is not None:
        memory_safety_argument["witness"] = resolved.witness.to_dict()
    if resolved.pcode_trace:
        memory_safety_argument["pcode_sink_trace"] = dict(resolved.pcode_trace.get("sink_trace") or {})
    if resolved.ghidra_dynamic_proof:
        memory_safety_argument["ghidra_dynamic_proof"] = dict(resolved.ghidra_dynamic_proof)
        memory_safety_argument["concrete_input"] = _concrete_input_from_verdict(resolved)
        memory_safety_argument["sink_address"] = str(resolved.ghidra_dynamic_proof.get("sink_address") or "")
        memory_safety_argument["write_range"] = dict(resolved.ghidra_dynamic_proof.get("write_range") or {})
        memory_safety_argument["read_range"] = dict(resolved.ghidra_dynamic_proof.get("read_range") or {})
        memory_safety_argument["object_range"] = dict(resolved.ghidra_dynamic_proof.get("object_range") or {})
        memory_safety_argument["capacity_bytes"] = _safe_int(resolved.ghidra_dynamic_proof.get("capacity_bytes"), default=0)
        memory_safety_argument["overflow_bytes"] = _safe_int(resolved.ghidra_dynamic_proof.get("overflow_bytes"), default=0)
        memory_safety_argument["oob_bytes"] = _safe_int(resolved.ghidra_dynamic_proof.get("oob_bytes"), default=0)
        memory_safety_argument["harness_model"] = dict(resolved.ghidra_dynamic_proof.get("harness_model") or {})
    if resolved.llm_actions:
        memory_safety_argument["llm_trace"] = dict(resolved.llm_actions)
    confirmation = {
        "candidate_id": resolved.candidate_id,
        "status": status,
        "reason_codes": [reason_code],
        "rationale": rationale,
        "memory_safety_argument": memory_safety_argument,
        "evidence_refs": evidence_refs,
        "feasibility_argument": _feasibility_argument(resolved),
        "provider_metadata": {
            "provider": "concolic",
            "backend": resolved.backend,
            "concolic_verdict": resolved.verdict,
            "ghidra_dynamic_proof_status": str((resolved.ghidra_dynamic_proof or {}).get("status") or ""),
            "elapsed_seconds": resolved.elapsed_seconds,
            "artifact_paths": list(resolved.artifact_paths),
            "errors": list(resolved.errors),
        },
    }
    if status == "confirmed_bug":
        confirmation["bug_class"] = _dynamic_proof_bug_class(resolved.ghidra_dynamic_proof)
        confirmation["decision"] = resolved.verdict
    return confirmation


def is_concolic_verdict_payload(payload: Any) -> bool:
    return isinstance(payload, Mapping) and (
        "concolic_verdict" in payload
        or str(payload.get("verdict") or "") in CONCOLIC_VERDICTS
    )


def concolic_verdict_entries(payload: Any) -> list[tuple[str, Mapping[str, Any]]]:
    """Return concolic verdict entries from common JSON wrapper shapes."""

    if is_concolic_verdict_payload(payload):
        candidate_id = str(payload.get("candidate_id") or "")
        return [(candidate_id, payload)] if candidate_id else []
    if isinstance(payload, Mapping) and "concolic_verdicts" in payload:
        payload = payload["concolic_verdicts"]
    if isinstance(payload, list):
        entries: list[tuple[str, Mapping[str, Any]]] = []
        for item in payload:
            if is_concolic_verdict_payload(item):
                entries.append((str(item.get("candidate_id") or ""), item))
        return [(candidate_id, item) for candidate_id, item in entries if candidate_id]
    if isinstance(payload, Mapping):
        entries = []
        for key, value in payload.items():
            if is_concolic_verdict_payload(value):
                data = dict(value)
                data.setdefault("candidate_id", str(key))
                entries.append((str(data.get("candidate_id") or key), data))
        return entries
    return []


def load_concolic_dynamic_proofs(
    output_dir: Path,
    *,
    include_unsupported: bool = False,
) -> dict[str, dict[str, Any]]:
    """Load successful Ghidra dynamic proof payloads from concolic verdict artifacts."""

    output_dir = Path(output_dir)
    if not output_dir.exists():
        raise FileNotFoundError(f"Concolic output directory not found: {output_dir}")
    paths = [*sorted(output_dir.glob("*.json")), *sorted(output_dir.rglob(CONCOLIC_VERDICT_FILENAME))]
    proofs: dict[str, dict[str, Any]] = {}
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if path.name in CONCOLIC_ARTIFACT_FILENAMES and path.name != CONCOLIC_VERDICT_FILENAME:
            continue
        payload = json.loads(path.read_text() or "{}")
        for candidate_id, entry in concolic_verdict_entries(payload):
            verdict = ConcolicVerdict.from_dict(entry)
            proof = dict(verdict.ghidra_dynamic_proof or {})
            if not proof:
                continue
            if not include_unsupported and not _has_dynamic_memory_safety_proof(proof):
                continue
            proof.setdefault("candidate_id", candidate_id)
            proofs[candidate_id] = proof
    return proofs


def run_ghidra_pcode_trace(trace_request: PcodeTraceRequest) -> dict[str, Any]:
    """Run the headless Ghidra p-code trace script or return an unsupported artifact."""

    if trace_request.ghidra_dir is None:
        return unsupported_pcode_trace(
            trace_request.candidate_id,
            "ghidra_dir_not_configured",
            request=trace_request,
        )
    try:
        runner, runner_prefix = _resolve_ghidra_runner(trace_request.ghidra_dir)
    except Exception as exc:
        return unsupported_pcode_trace(
            trace_request.candidate_id,
            f"ghidra_runner_unavailable:{exc}",
            request=trace_request,
        )
    script_dir = _repo_root() / "ghidra_scripts"
    script_path = script_dir / "pcode_trace.py"
    if not script_path.exists():
        return unsupported_pcode_trace(
            trace_request.candidate_id,
            "pcode_trace_script_missing",
            request=trace_request,
        )
    trace_request.output_path.parent.mkdir(parents=True, exist_ok=True)
    project_root_cleanup: Path | None = None
    project_dir, project_root_cleanup = _ghidra_project_location(trace_request.output_path.parent, "pcode_trace")
    project_dir.mkdir(parents=True, exist_ok=True)
    command = [str(runner), *runner_prefix]
    command.extend([str(project_dir), "pcode_trace_project", "-import", str(trace_request.binary_path), "-overwrite"])
    command.extend(["-scriptPath", str(script_dir), "-postScript", "pcode_trace.py"])
    command.extend(
        [
            f"output_path={trace_request.output_path}",
            f"candidate_id={trace_request.candidate_id}",
            f"function_address={trace_request.function_address}",
            f"start_address={trace_request.start_address}",
            f"target_address={trace_request.target_address}",
            f"input_model={trace_request.input_model}",
            f"max_steps={trace_request.max_steps}",
            f"timeout_ms={int(trace_request.timeout_seconds * 1000)}",
            f"sink_name={trace_request.sink_name}",
            f"target_buffer={trace_request.target_buffer}",
            f"offset_expr={trace_request.offset_expr}",
            f"candidate_line_number={trace_request.line_number}",
            f"candidate_line_text={trace_request.line_text}",
        ]
    )
    try:
        env = _ghidra_subprocess_env()
        try:
            completed = subprocess.run(
                command,
                input="y\ny\n" if runner_prefix else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=_ghidra_subprocess_timeout_seconds(trace_request.timeout_seconds),
                check=False,
                env=env,
                **_ghidra_subprocess_limit_kwargs(),
            )
        finally:
            if project_root_cleanup is not None:
                shutil.rmtree(project_root_cleanup, ignore_errors=True)
    except Exception as exc:
        return unsupported_pcode_trace(
            trace_request.candidate_id,
            f"ghidra_trace_failed:{exc}",
            request=trace_request,
        )
    if completed.returncode != 0:
        return unsupported_pcode_trace(
            trace_request.candidate_id,
            f"ghidra_trace_exit_{completed.returncode}:{(completed.stdout or '')[-500:]}",
            request=trace_request,
        )
    if not trace_request.output_path.exists():
        payload = unsupported_pcode_trace(
            trace_request.candidate_id,
            "ghidra_trace_no_output",
            request=trace_request,
        )
        payload["runner_output_tail"] = (completed.stdout or "")[-2000:]
        return payload
    try:
        payload = json.loads(trace_request.output_path.read_text() or "{}")
    except json.JSONDecodeError as exc:
        return unsupported_pcode_trace(
            trace_request.candidate_id,
            f"ghidra_trace_invalid_json:{exc}",
            request=trace_request,
        )
    if not isinstance(payload, Mapping):
        return unsupported_pcode_trace(
            trace_request.candidate_id,
            "ghidra_trace_output_not_object",
            request=trace_request,
        )
    return dict(payload)


def run_ghidra_dynamic_overflow_proof(proof_request: GhidraDynamicProofRequest) -> dict[str, Any]:
    """Run the headless Ghidra dynamic memory-safety proof script."""

    input_setup_blocker = _process_input_setup_blocker(proof_request)
    if input_setup_blocker:
        return unsupported_dynamic_overflow_proof(
            proof_request.candidate_id,
            input_setup_blocker,
            request=proof_request,
        )
    if proof_request.ghidra_dir is None:
        return unsupported_dynamic_overflow_proof(
            proof_request.candidate_id,
            "ghidra_dir_not_configured",
            request=proof_request,
        )
    try:
        runner, runner_prefix = _resolve_ghidra_runner(proof_request.ghidra_dir)
    except Exception as exc:
        return unsupported_dynamic_overflow_proof(
            proof_request.candidate_id,
            f"ghidra_runner_unavailable:{exc}",
            request=proof_request,
        )
    script_dir = _repo_root() / "ghidra_scripts"
    script_path = script_dir / "dynamic_overflow_proof.py"
    if not script_path.exists():
        return unsupported_dynamic_overflow_proof(
            proof_request.candidate_id,
            "dynamic_overflow_proof_script_missing",
            request=proof_request,
        )
    proof_request.output_path.parent.mkdir(parents=True, exist_ok=True)
    project_root_cleanup: Path | None = None
    project_dir, project_root_cleanup = _ghidra_project_location(proof_request.output_path.parent, "dynamic_overflow_proof")
    project_dir.mkdir(parents=True, exist_ok=True)
    command = [str(runner), *runner_prefix]
    command.extend([str(project_dir), "dynamic_overflow_proof_project", "-import", str(proof_request.binary_path), "-overwrite"])
    command.extend(["-scriptPath", str(script_dir), "-postScript", "dynamic_overflow_proof.py"])
    command.extend(
        [
            f"output_path={proof_request.output_path}",
            f"candidate_id={proof_request.candidate_id}",
            f"function_address={proof_request.function_address}",
            f"start_address={proof_request.start_address}",
            f"sink_address={proof_request.sink_address}",
            f"proof_scope={proof_request.proof_scope}",
            f"input_model={proof_request.input_model}",
            f"env_name={proof_request.env_name}",
            f"env_values_json={json.dumps(dict(proof_request.env_values), sort_keys=True)}",
            f"concrete_input_hex={proof_request.concrete_input_hex}",
            f"argv_values_hex={','.join(value.encode('utf-8').hex() for value in proof_request.argv_values)}",
            f"stdin_input_hex={proof_request.stdin_input_hex}",
            f"file_input_hex={proof_request.file_input_hex}",
            f"file_name={proof_request.file_name}",
            f"process_input_source={proof_request.process_input_source}",
            f"process_input_evidence_json={json.dumps(dict(proof_request.process_input_evidence), sort_keys=True)}",
            f"static_path_addresses={json.dumps(list(proof_request.static_path_addresses))}",
            f"function_harness_json={json.dumps(dict(proof_request.function_harness), sort_keys=True)}",
            f"max_steps={proof_request.max_steps}",
            f"timeout_ms={int(proof_request.timeout_seconds * 1000)}",
            f"sink_name={proof_request.sink_name}",
            f"vulnerability_type={proof_request.vulnerability_type}",
            f"write_relation={proof_request.write_relation}",
            f"target_buffer={proof_request.target_buffer}",
            f"destination_kind={proof_request.destination_kind}",
            f"capacity_bytes={proof_request.capacity_bytes}",
            f"capacity_source={proof_request.capacity_source}",
            f"capacity_basis={proof_request.capacity_basis}",
            f"offset_expr={proof_request.offset_expr}",
            f"write_size_bytes={proof_request.write_size_bytes}",
            f"candidate_line_number={proof_request.line_number}",
            f"candidate_line_text={proof_request.line_text}",
        ]
    )
    try:
        try:
            completed = subprocess.run(
                command,
                input="y\ny\n" if runner_prefix else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=_ghidra_subprocess_timeout_seconds(proof_request.timeout_seconds),
                check=False,
                env=_ghidra_subprocess_env(),
                **_ghidra_subprocess_limit_kwargs(),
            )
        finally:
            if project_root_cleanup is not None:
                shutil.rmtree(project_root_cleanup, ignore_errors=True)
    except Exception as exc:
        return unsupported_dynamic_overflow_proof(
            proof_request.candidate_id,
            f"ghidra_dynamic_proof_failed:{exc}",
            request=proof_request,
        )
    if completed.returncode != 0:
        return unsupported_dynamic_overflow_proof(
            proof_request.candidate_id,
            f"ghidra_dynamic_proof_exit_{completed.returncode}:{(completed.stdout or '')[-500:]}",
            request=proof_request,
        )
    if not proof_request.output_path.exists():
        payload = unsupported_dynamic_overflow_proof(
            proof_request.candidate_id,
            "ghidra_dynamic_proof_no_output",
            request=proof_request,
        )
        payload["runner_output_tail"] = (completed.stdout or "")[-2000:]
        return payload
    try:
        payload = json.loads(proof_request.output_path.read_text() or "{}")
    except json.JSONDecodeError as exc:
        return unsupported_dynamic_overflow_proof(
            proof_request.candidate_id,
            f"ghidra_dynamic_proof_invalid_json:{exc}",
            request=proof_request,
        )
    if not isinstance(payload, Mapping):
        return unsupported_dynamic_overflow_proof(
            proof_request.candidate_id,
            "ghidra_dynamic_proof_output_not_object",
            request=proof_request,
        )
    return dict(payload)


def _process_input_setup_blocker(proof_request: GhidraDynamicProofRequest) -> str:
    if proof_request.proof_scope != "process_entrypoint":
        return ""
    if proof_request.input_model == "env_file":
        if not proof_request.env_name or proof_request.env_name not in proof_request.env_values:
            return "unsupported_process_input_setup:missing_env_file_environment"
        if not proof_request.file_name or not proof_request.file_input_hex:
            return "unsupported_process_input_setup:missing_env_file_input"
    if proof_request.input_model == "env" and proof_request.process_input_setup_reason:
        return proof_request.process_input_setup_reason
    if proof_request.input_model == "stdin" and proof_request.process_input_setup_reason:
        return proof_request.process_input_setup_reason
    if proof_request.input_model != "argv_file_stdin":
        return ""
    if proof_request.process_input_setup_reason:
        return proof_request.process_input_setup_reason
    if not str(proof_request.file_input_hex or "").strip():
        return "unsupported_process_input_setup:missing_file_input_hex"
    return ""


def _ghidra_subprocess_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("PYGHIDRA_AUTO_INSTALL", "y")
    java_home = _discover_java_home(env)
    if java_home is not None and not env.get("JAVA_HOME"):
        env["JAVA_HOME"] = str(java_home)
        java_bin = str(java_home / "bin")
        path = env.get("PATH", "")
        if java_bin not in path.split(os.pathsep):
            env["PATH"] = java_bin + (os.pathsep + path if path else "")
    venv = env.get("VIRTUAL_ENV")
    if not venv and getattr(sys, "prefix", "") and sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        venv = sys.prefix
    if venv:
        env["VIRTUAL_ENV"] = str(venv)
        venv_bin = str(Path(venv) / "bin")
        path = env.get("PATH", "")
        if venv_bin not in path.split(os.pathsep):
            env["PATH"] = venv_bin + (os.pathsep + path if path else "")
    return env


def _discover_java_home(env: Mapping[str, str]) -> Path | None:
    configured = env.get("JAVA_HOME")
    if configured and (Path(configured) / "bin" / "java").exists():
        return Path(configured)
    if shutil.which("java", path=env.get("PATH")):
        return None
    for candidate in _candidate_java_homes():
        if (candidate / "bin" / "java").exists():
            return candidate
    return None


def _candidate_java_homes() -> list[Path]:
    candidates = [
        Path("/home/linuxbrew/.linuxbrew/opt/openjdk@21/libexec"),
        Path("/home/linuxbrew/.linuxbrew/opt/openjdk/libexec"),
        Path("/usr/lib/jvm/default-java"),
    ]
    for root in (Path("/usr/lib/jvm"), Path("/opt"), Path("/usr/local")):
        if root.exists():
            candidates.extend(sorted(root.glob("*jdk*"), reverse=True))
            candidates.extend(sorted(root.glob("*jre*"), reverse=True))
    return candidates


def _request_for_evidence_pack(
    evidence_pack: Mapping[str, Any],
    *,
    binary_path: Path,
    output_dir: Path,
    export_dir: Path | None,
    backend: str,
    input_model: str,
    symbolic_bytes: int,
    timeout_seconds: float,
    llm_controller: bool,
) -> tuple[ConcolicRequest, Mapping[str, Any]]:
    llm_actions = _default_llm_actions(enabled=llm_controller)
    if llm_controller:
        tool_request = _first_llm_concolic_request(evidence_pack)
        if tool_request is not None:
            config = ConcolicToolConfig(
                binary_path=binary_path,
                output_dir=output_dir,
                export_dir=export_dir,
                backend=backend,
                timeout_seconds=timeout_seconds,
                max_symbolic_bytes=max(512, int(symbolic_bytes or 0)),
            )
            request = concolic_request_from_tool_request(evidence_pack, tool_request, config)
            return request, _llm_actions_for_tool_request(tool_request, accepted=True)
    request = build_concolic_request(
        evidence_pack,
        binary_path=binary_path,
        export_dir=export_dir,
        backend=backend,
        input_model=input_model,
        symbolic_bytes=symbolic_bytes,
        timeout_seconds=timeout_seconds,
    )
    return request, llm_actions


def _first_llm_concolic_request(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any] | None:
    candidates: list[Any] = []
    for key in ("llm_concolic_requests", "tool_requests"):
        candidates.extend(_coerce_sequence(evidence_pack.get(key, [])))
    for container_key in ("llm_actions", "controller_actions", "controller_context"):
        container = evidence_pack.get(container_key)
        if isinstance(container, Mapping):
            candidates.extend(_coerce_sequence(container.get("tool_requests", [])))
            candidates.extend(_coerce_sequence(container.get("requests", [])))
    for item in candidates:
        if isinstance(item, Mapping) and str(item.get("tool") or "") == CONCOLIC_TOOL_NAME:
            return item
    return None


def _first_tool_request_from_action(action: Mapping[str, Any]) -> Mapping[str, Any] | None:
    if str(action.get("tool") or "") == CONCOLIC_TOOL_NAME:
        return action
    candidates: list[Any] = []
    for key in ("tool_requests", "actions", "requests"):
        candidates.extend(_coerce_sequence(action.get(key, [])))
    controller = action.get("controller_action")
    if isinstance(controller, Mapping):
        candidates.append(controller)
        candidates.extend(_coerce_sequence(controller.get("tool_requests", [])))
    for item in candidates:
        if isinstance(item, Mapping) and str(item.get("tool") or "") == CONCOLIC_TOOL_NAME:
            return item
    return None


def _default_llm_actions(*, enabled: bool, rejected_reason: str = "") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "enabled": bool(enabled),
        "accepted_requests": [],
        "rejected_requests": [],
        "raw_actions": [],
    }
    if rejected_reason:
        payload["rejected_requests"].append({"reason": rejected_reason})
    return payload


def _llm_actions_for_tool_request(
    tool_request: Mapping[str, Any],
    *,
    accepted: bool = True,
    raw_action: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload = _default_llm_actions(enabled=True)
    key = "accepted_requests" if accepted else "rejected_requests"
    payload[key].append(dict(tool_request))
    if raw_action is not None:
        payload["raw_actions"].append(dict(raw_action))
    return payload


def _merge_llm_actions(target: dict[str, Any], source: Mapping[str, Any]) -> None:
    target["enabled"] = bool(target.get("enabled")) or bool(source.get("enabled"))
    for key in ("accepted_requests", "rejected_requests", "raw_actions", "command_runs"):
        existing = target.get(key)
        if not isinstance(existing, list):
            existing = []
        existing.extend(dict(item) if isinstance(item, Mapping) else item for item in _coerce_sequence(source.get(key, [])))
        target[key] = existing


def _write_concolic_artifacts(
    output_dir: Path,
    request: ConcolicRequest,
    verdict: ConcolicVerdict,
    *,
    pcode_trace_enabled: bool,
    ghidra_dynamic_proof_enabled: bool,
    compatibility_path: Path,
) -> tuple[Path, ConcolicVerdict]:
    artifact_dir = _artifact_run_dir(output_dir, verdict.candidate_id or request.candidate_id)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    request_path = artifact_dir / CONCOLIC_REQUEST_FILENAME
    angr_trace_path = artifact_dir / CONCOLIC_ANGR_TRACE_FILENAME
    llm_actions_path = artifact_dir / CONCOLIC_LLM_ACTIONS_FILENAME
    replay_path = artifact_dir / CONCOLIC_REPLAY_FILENAME
    verdict_path = artifact_dir / CONCOLIC_VERDICT_FILENAME
    request_path.write_text(json.dumps(request.to_dict(), indent=2))
    angr_trace_path.write_text(json.dumps(dict(verdict.angr_trace or {}), indent=2))
    llm_actions_path.write_text(json.dumps(dict(verdict.llm_actions or _default_llm_actions(enabled=False)), indent=2))
    initial_replay = dict(verdict.replay_result or _empty_replay_result("not_run", "No replay result."))
    initial_replay.setdefault("native_replay", _native_replay_not_run())
    replay_path.write_text(json.dumps(initial_replay, indent=2))

    pcode_payload = dict(verdict.pcode_trace or {})
    if not pcode_payload:
        reason = "pcode_trace_enabled_but_no_payload" if pcode_trace_enabled else "pcode_trace_disabled"
        pcode_payload = unsupported_pcode_trace(verdict.candidate_id or request.candidate_id, reason, request=request)
    pcode_name = (
        CONCOLIC_PCODE_UNSUPPORTED_FILENAME
        if pcode_payload.get("unsupported") or pcode_payload.get("status") == "unsupported"
        else CONCOLIC_PCODE_TRACE_FILENAME
    )
    stale_pcode_name = (
        CONCOLIC_PCODE_TRACE_FILENAME
        if pcode_name == CONCOLIC_PCODE_UNSUPPORTED_FILENAME
        else CONCOLIC_PCODE_UNSUPPORTED_FILENAME
    )
    (artifact_dir / stale_pcode_name).unlink(missing_ok=True)
    pcode_path = artifact_dir / pcode_name
    pcode_path.write_text(json.dumps(pcode_payload, indent=2))
    pcode_trace = dict(pcode_payload)
    pcode_trace["artifact_path"] = _artifact_ref(output_dir, pcode_path)

    dynamic_proof_payload = dict(verdict.ghidra_dynamic_proof or {})
    if not dynamic_proof_payload:
        reason = (
            "ghidra_dynamic_proof_enabled_but_no_payload"
            if ghidra_dynamic_proof_enabled
            else "ghidra_dynamic_proof_disabled"
        )
        dynamic_proof_payload = unsupported_dynamic_overflow_proof(
            verdict.candidate_id or request.candidate_id,
            reason,
            request=request,
        )
    dynamic_name = (
        CONCOLIC_DYNAMIC_PROOF_UNSUPPORTED_FILENAME
        if dynamic_proof_payload.get("unsupported") or dynamic_proof_payload.get("status") == "unsupported"
        else CONCOLIC_DYNAMIC_PROOF_FILENAME
    )
    stale_dynamic_name = (
        CONCOLIC_DYNAMIC_PROOF_FILENAME
        if dynamic_name == CONCOLIC_DYNAMIC_PROOF_UNSUPPORTED_FILENAME
        else CONCOLIC_DYNAMIC_PROOF_UNSUPPORTED_FILENAME
    )
    (artifact_dir / stale_dynamic_name).unlink(missing_ok=True)
    dynamic_path = artifact_dir / dynamic_name
    dynamic_path.write_text(json.dumps(dynamic_proof_payload, indent=2))
    ghidra_dynamic_proof = dict(dynamic_proof_payload)
    ghidra_dynamic_proof["artifact_path"] = _artifact_ref(output_dir, dynamic_path)
    process_witness_attempt_path = artifact_dir / CONCOLIC_PROCESS_WITNESS_ATTEMPT_FILENAME

    fixed_artifact_paths = (
        _artifact_ref(output_dir, request_path),
        _artifact_ref(output_dir, angr_trace_path),
        _artifact_ref(output_dir, pcode_path),
        _artifact_ref(output_dir, dynamic_path),
        *(
            (_artifact_ref(output_dir, process_witness_attempt_path),)
            if process_witness_attempt_path.exists()
            else ()
        ),
        _artifact_ref(output_dir, llm_actions_path),
        _artifact_ref(output_dir, replay_path),
        _artifact_ref(output_dir, verdict_path),
    )
    artifact_paths = tuple(_unique_strings(list(verdict.artifact_paths) + list(fixed_artifact_paths)))
    replay_result = dict(verdict.replay_result or _empty_replay_result("not_run", "No replay result."))
    replay_result.setdefault("native_replay", _native_replay_not_run())
    final_verdict = replace(
        verdict,
        artifact_paths=artifact_paths,
        pcode_trace=pcode_trace,
        ghidra_dynamic_proof=ghidra_dynamic_proof,
        replay_result=replay_result,
    )
    verdict_path.write_text(json.dumps(final_verdict.to_dict(), indent=2))
    compatibility_path.write_text(json.dumps({final_verdict.candidate_id: final_verdict.to_dict()}, indent=2))
    return verdict_path, final_verdict


def _artifact_ref(output_dir: Path, path: Path) -> str:
    try:
        return str(path.relative_to(output_dir))
    except ValueError:
        return str(path)


def _artifact_run_dir(output_dir: Path, candidate_id: str) -> Path:
    return Path(output_dir) / _concolic_stem(candidate_id)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _resolve_ghidra_dir(ghidra_dir: Path | str | None) -> Path | None:
    if ghidra_dir:
        return Path(ghidra_dir).expanduser().resolve()
    configured = os.getenv("GHIDRA_INSTALL_DIR")
    if configured:
        candidate = Path(configured).expanduser()
        if _is_ghidra_install(candidate):
            return candidate.resolve()
    for tool in ("analyzeHeadless", "ghidraRun"):
        resolved = shutil.which(tool)
        if not resolved:
            continue
        install = _ghidra_install_from_runner(Path(resolved))
        if install is not None:
            return install.resolve()
    for root in _default_ghidra_search_roots():
        if not root.exists() or not root.is_dir():
            continue
        for candidate in sorted(root.glob("ghidra_*"), reverse=True):
            if _is_ghidra_install(candidate):
                return candidate.resolve()
    return None


def _is_ghidra_install(path: Path) -> bool:
    support = Path(path).expanduser() / "support"
    return (support / "analyzeHeadless").exists() or any(
        (support / name).exists() for name in ("pyGhidraRun", "pyghidraRun")
    )


def _ghidra_project_location(output_parent: Path, purpose: str) -> tuple[Path, Path | None]:
    """Return a headless-safe Ghidra project location.

    Ghidra rejects project locations containing hidden path components such as
    `.ai`; the artifact output can still be written there.
    """

    base = Path(output_parent)
    if any(part.startswith(".") and part not in {".", ".."} for part in base.resolve().parts):
        cleanup_root = Path(tempfile.mkdtemp(prefix=f"binary_agent_{purpose}_"))
        return cleanup_root / "ghidra_project", cleanup_root
    return base / "_ghidra_project", None


def _ghidra_install_from_runner(runner: Path) -> Path | None:
    path = runner.expanduser().resolve()
    if path.parent.name == "support" and _is_ghidra_install(path.parent.parent):
        return path.parent.parent
    try:
        text = path.read_text(errors="ignore")[:4096]
    except OSError:
        return None
    match = re.search(
        r"([^\s\"']+/support/(?:analyzeHeadless|ghidraRun|pyGhidraRun|pyghidraRun))",
        text,
    )
    if not match:
        return None
    support_runner = Path(match.group(1)).expanduser()
    install = support_runner.parent.parent
    return install if _is_ghidra_install(install) else None


def _default_ghidra_search_roots() -> list[Path]:
    home = Path.home()
    return [
        _repo_root() / "ghidra_downloads",
        home / ".config" / "ghidra",
        home / ".local" / "share" / "ghidra",
        home / "Documents" / "projects" / "re-bench" / ".tools" / "ghidra",
        Path("/opt"),
        Path("/usr/local"),
    ]


def _resolve_ghidra_runner(ghidra_dir: Path) -> tuple[Path, list[str]]:
    support_dir = Path(ghidra_dir) / "support"
    headless = support_dir / "analyzeHeadless"
    for name in ("pyGhidraRun", "pyghidraRun"):
        runner = support_dir / name
        if runner.exists():
            return runner, ["-H"]
    if headless.exists():
        return headless, []
    raise FileNotFoundError(f"Could not locate analyzeHeadless under {ghidra_dir}")


def translate_ghidra_to_loader_address(
    address: str | int,
    *,
    image_base: int = 0,
    loader_base: int = 0,
    relative_address: int | None = None,
) -> AddressTranslation:
    """Translate a Ghidra/export address to a backend loader address."""

    parsed = _parse_address(address)
    if parsed is None:
        raise ValueError(f"Invalid address: {address!r}")
    if relative_address is None:
        relative_address = parsed - image_base if image_base and parsed >= image_base else parsed
    loader_address = loader_base + relative_address
    return AddressTranslation(
        ghidra_address=_normalize_address(address),
        relative_address=int(relative_address),
        loader_address=int(loader_address),
        image_base=int(image_base),
        loader_base=int(loader_base),
    )


def _run_angr_backend(request: ConcolicRequest, evidence_pack: Mapping[str, Any]) -> ConcolicVerdict:
    started = time.perf_counter()
    for logger_name in ("angr", "cle", "pyvex"):
        logging.getLogger(logger_name).setLevel(logging.ERROR)
    try:
        import angr  # type: ignore
        import claripy  # type: ignore
    except Exception as exc:
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="backend_error",
            backend=request.backend,
            request=request.to_dict(),
            rationale=f"angr backend is not available: {exc}",
            errors=(str(exc),),
            angr_trace=_backend_error_trace(request, str(exc)),
            elapsed_seconds=round(time.perf_counter() - started, 4),
        )

    try:
        project = angr.Project(str(request.binary_path), auto_load_libs=False)
        loader_base = int(project.loader.main_object.mapped_base or 0)
        image_base = _image_base_from_export(request.export_dir)
        target = translate_ghidra_to_loader_address(
            request.target_address,
            image_base=image_base,
            loader_base=loader_base,
        )
        symbolic = claripy.BVS("concolic_input", request.symbolic_bytes * 8)
        setup = _make_angr_state(project, angr, claripy, request, evidence_pack, symbolic=symbolic)
        if setup.get("unsupported"):
            reason = str(setup.get("reason") or f"unsupported_input_model:{request.input_model}")
            return ConcolicVerdict(
                candidate_id=request.candidate_id,
                verdict="backend_error",
                backend=request.backend,
                request=request.to_dict(),
                rationale=f"Input model {request.input_model!r} is not supported by the current angr harness.",
                errors=(reason,),
                angr_trace=_backend_error_trace(request, reason, target=target.to_dict()),
                elapsed_seconds=round(time.perf_counter() - started, 4),
            )

        state = setup["state"]
        memory_writes: list[dict[str, Any]] = []
        sink_events: list[dict[str, Any]] = []
        _install_sink_hooks(project, angr, request, evidence_pack, symbolic, sink_events)
        _install_mem_write_trace(state, angr, memory_writes)
        if _input_model_requires_printable_bytes(request.input_model):
            _constrain_printable_symbolic_bytes(state, symbolic)
        constraint_trace = _apply_concolic_request_constraints(state, symbolic, request)
        simgr = project.factory.simulation_manager(state, save_unconstrained=True)
        deadline = time.perf_counter() + request.timeout_seconds
        branch_target = None
        goals = [target.loader_address]
        waypoint_addresses = list(request.waypoint_addresses[:8])
        if not waypoint_addresses and request.extra_branch_goal:
            waypoint_addresses = [request.extra_branch_goal]
        waypoint_targets = [
            translate_ghidra_to_loader_address(address, image_base=image_base, loader_base=loader_base)
            for address in waypoint_addresses
        ]
        if waypoint_targets:
            branch_target = waypoint_targets[0]
            goals = [item.loader_address for item in waypoint_targets] + [target.loader_address]
        goal_index = 0
        block_cache: dict[int, tuple[int, ...]] = {}
        exploration_metrics = {
            "simgr_steps": 0,
            "peak_active_states": len(getattr(simgr, "active", []) or []),
            "peak_total_states": _simgr_state_total(simgr),
            "waypoint_count": len(waypoint_targets),
            "reached_waypoint_count": 0,
        }

        def record_exploration_metrics() -> None:
            exploration_metrics["peak_active_states"] = max(
                _safe_int(exploration_metrics.get("peak_active_states")),
                len(getattr(simgr, "active", []) or []),
            )
            exploration_metrics["peak_total_states"] = max(
                _safe_int(exploration_metrics.get("peak_total_states")),
                _simgr_state_total(simgr),
            )

        found = [
            active
            for active in simgr.active
            if _state_reached_loader_instruction(project, active, goals[goal_index], block_cache)
        ]
        record_exploration_metrics()
        logs = [f"target_loader_address=0x{target.loader_address:x}"]
        if branch_target is not None:
            logs.append(f"branch_goal_loader_address=0x{branch_target.loader_address:x}")
        logs.extend(f"waypoint_loader_address=0x{item.loader_address:x}" for item in waypoint_targets)
        while found and goal_index + 1 < len(goals):
            try:
                simgr.stashes["active"] = list(found)
            except Exception:
                pass
            if goal_index < len(waypoint_targets):
                exploration_metrics["reached_waypoint_count"] = goal_index + 1
            goal_index += 1
            found = [
                active
                for active in simgr.active
                if _state_reached_loader_instruction(project, active, goals[goal_index], block_cache)
            ]
            record_exploration_metrics()
        initial_target_reached = bool(
            found
            and goal_index == len(goals) - 1
            and request.input_model == "function_harness"
            and not waypoint_addresses
        )
        deadline_interrupted = False
        previous_alarm_handler: Any = None
        alarm_installed = False

        def interrupt_exploration(_signum: int, _frame: Any) -> None:
            raise _AngrExplorationDeadline()

        try:
            previous_alarm_handler = signal.getsignal(signal.SIGALRM)
            signal.signal(signal.SIGALRM, interrupt_exploration)
            signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - time.perf_counter()))
            alarm_installed = True
        except (AttributeError, OSError, ValueError):
            alarm_installed = False
        try:
            while not found and simgr.active and time.perf_counter() < deadline:
                simgr.step()
                exploration_metrics["simgr_steps"] = _safe_int(exploration_metrics.get("simgr_steps")) + 1
                record_exploration_metrics()
                found.extend(
                    state
                    for state in simgr.active
                    if _state_reached_loader_instruction(project, state, goals[goal_index], block_cache)
                )
                if found and goal_index + 1 < len(goals):
                    try:
                        simgr.stashes["active"] = list(found)
                    except Exception:
                        pass
                    if goal_index < len(waypoint_targets):
                        exploration_metrics["reached_waypoint_count"] = goal_index + 1
                    goal_index += 1
                    found = [
                        active
                        for active in simgr.active
                        if _state_reached_loader_instruction(project, active, goals[goal_index], block_cache)
                    ]
                    record_exploration_metrics()
                    continue
                if found:
                    break
        except _AngrExplorationDeadline:
            deadline_interrupted = True
        finally:
            if alarm_installed:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous_alarm_handler)
        constraint_trace = {
            **dict(constraint_trace),
            "exploration_deadline_interrupted": deadline_interrupted,
        }
        elapsed = round(time.perf_counter() - started, 4)
        trace = _build_angr_trace(
            request,
            target=target.to_dict(),
            branch_target=branch_target.to_dict() if branch_target is not None else {},
            simgr=simgr,
            state=found[0] if found else state,
            memory_writes=memory_writes,
            sink_events=sink_events,
            constraint_trace=constraint_trace,
            exploration_metrics=exploration_metrics,
            elapsed_seconds=elapsed,
            status=(
                "trivial_function_harness_entry"
                if initial_target_reached
                else (
                    "target_reached"
                    if found
                    else "unconstrained"
                    if simgr.unconstrained
                    else "execution_error"
                    if simgr.errored
                    else "timeout"
                )
            ),
        )
        if initial_target_reached:
            concrete = _eval_symbolic_bytes(state, symbolic)
            witness = _witness_for_input(
                request.input_model,
                concrete,
                evidence_pack=evidence_pack,
                function_args=dict(setup.get("function_args") or {}),
                reached_addresses=tuple(trace.get("reached_blocks", [])),
            )
            replay = _empty_replay_result(
                "trivial_function_harness_entry",
                "function_harness exploration started at the target address",
            )
            return ConcolicVerdict(
                candidate_id=request.candidate_id,
                verdict="timeout",
                backend=request.backend,
                request=request.to_dict(),
                witness=witness,
                evidence_refs=tuple(_default_evidence_refs(evidence_pack)),
                rationale="function_harness target was the harness entrypoint, not a downstream sink.",
                reached_addresses=witness.reached_addresses,
                angr_trace=trace,
                replay_result=replay,
                logs=tuple([*logs, "function_harness_target_is_entrypoint"]),
                elapsed_seconds=elapsed,
            )
        if simgr.unconstrained and not found:
            candidate = _candidate(evidence_pack)
            semantic_effect = _is_semantic_vulnerability_type(
                str(candidate.get("vulnerability_type") or "")
            )
            if semantic_effect and not found:
                replay = _empty_replay_result(
                    "not_run",
                    "angr errored before reaching the semantic sink target.",
                )
                return ConcolicVerdict(
                    candidate_id=request.candidate_id,
                    verdict="timeout",
                    backend=request.backend,
                    request=request.to_dict(),
                    rationale="angr hit an errored or unconstrained state before reaching the semantic sink target.",
                    evidence_refs=tuple(_default_evidence_refs(evidence_pack)),
                    angr_trace=trace,
                    replay_result=replay,
                    logs=tuple([*logs, "semantic_pre_target_error"]),
                    elapsed_seconds=elapsed,
                )
            crash_state = simgr.unconstrained[0]
            concrete = _eval_symbolic_bytes(crash_state, symbolic)
            witness = _witness_for_input(
                request.input_model,
                concrete,
                evidence_pack=evidence_pack,
                crash_signal="symbolic_crash_or_unconstrained",
                function_args=dict(setup.get("function_args") or {}),
                reached_addresses=tuple(trace.get("reached_blocks", [])),
            )
            replay = _replay_angr_witness(
                project,
                angr,
                request,
                evidence_pack,
                concrete=concrete,
                target_loader_address=target.loader_address,
                expect_crash=True,
            )
            if _concrete_angr_replay_status(replay) != "replayed":
                return ConcolicVerdict(
                    candidate_id=request.candidate_id,
                    verdict="timeout",
                    backend=request.backend,
                    request=request.to_dict(),
                    witness=witness,
                    evidence_refs=tuple(_default_evidence_refs(evidence_pack)),
                    rationale="angr found an errored or unconstrained state, but concrete angr replay did not reproduce it.",
                    reached_addresses=witness.reached_addresses,
                    angr_trace=trace,
                    replay_result=replay,
                    logs=tuple([*logs, "concrete_angr_replay_failed"]),
                    elapsed_seconds=elapsed,
                )
            return ConcolicVerdict(
                candidate_id=request.candidate_id,
                verdict="crash_reproduced",
                backend=request.backend,
                request=request.to_dict(),
                witness=witness,
                evidence_refs=tuple(_default_evidence_refs(evidence_pack)),
                rationale="angr reached an errored or unconstrained state while exploring the candidate.",
                reached_addresses=witness.reached_addresses,
                angr_trace=trace,
                replay_result=replay,
                logs=tuple(logs),
                elapsed_seconds=elapsed,
            )
        if simgr.errored and not found:
            error_messages = tuple(
                str(item.get("error") or "angr execution error")
                for item in _errored_state_summary(simgr)
            )
            return ConcolicVerdict(
                candidate_id=request.candidate_id,
                verdict="backend_error",
                backend=request.backend,
                request=request.to_dict(),
                evidence_refs=tuple(_default_evidence_refs(evidence_pack)),
                rationale="angr ended in execution errors before reaching the requested sink.",
                errors=error_messages,
                angr_trace=trace,
                replay_result=_empty_replay_result(
                    "not_run",
                    "Errored states are diagnostics, not concrete crash witnesses.",
                ),
                logs=tuple([*logs, "execution_error_before_target"]),
                elapsed_seconds=elapsed,
            )
        if found:
            found_state = found[0]
            concrete = _eval_symbolic_bytes(found_state, symbolic)
            witness = _witness_for_input(
                request.input_model,
                concrete,
                evidence_pack=evidence_pack,
                function_args=dict(setup.get("function_args") or {}),
                reached_addresses=tuple(trace.get("reached_blocks", [])),
            )
            candidate = _candidate(evidence_pack)
            decisive = _reached_sink_proves_memory_overflow(
                evidence_pack,
                concrete,
                export_dir=request.export_dir,
            )
            semantic_effect = _is_semantic_vulnerability_type(
                str(candidate.get("vulnerability_type") or "")
            )
            replay = _replay_angr_witness(
                project,
                angr,
                request,
                evidence_pack,
                concrete=concrete,
                target_loader_address=target.loader_address,
                expect_crash=False,
            )
            if _concrete_angr_replay_status(replay) != "replayed":
                return ConcolicVerdict(
                    candidate_id=request.candidate_id,
                    verdict="timeout",
                    backend=request.backend,
                    request=request.to_dict(),
                    witness=witness,
                    evidence_refs=tuple(_default_evidence_refs(evidence_pack)),
                    rationale="angr reached the requested sink address, but concrete angr replay did not reproduce the path.",
                    reached_addresses=witness.reached_addresses,
                    angr_trace=trace,
                    replay_result=replay,
                    logs=tuple([*logs, "concrete_angr_replay_failed"]),
                    elapsed_seconds=elapsed,
                )
            return ConcolicVerdict(
                candidate_id=request.candidate_id,
                verdict="overflow_witness" if decisive else ("target_reached" if semantic_effect else "timeout"),
                backend=request.backend,
                request=request.to_dict(),
                witness=witness,
                evidence_refs=tuple(_default_evidence_refs(evidence_pack)),
                rationale=(
                    "angr reached the requested sink address with concrete input."
                    if decisive
                    else (
                        "angr reached the requested semantic sink address with concrete input."
                        if semantic_effect
                        else "angr reached the requested sink address, but no overflow predicate was proven."
                    )
                ),
                reached_addresses=witness.reached_addresses,
                angr_trace=trace,
                replay_result=replay,
                logs=tuple(logs),
                elapsed_seconds=elapsed,
            )
        exhausted_without_path = (
            not found
            and not simgr.active
            and not simgr.errored
            and not simgr.unconstrained
        )
        guided_checkpoint_unreached = bool(waypoint_addresses and goal_index < len(goals) - 1)
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="timeout" if guided_checkpoint_unreached else ("path_unsat" if exhausted_without_path else "timeout"),
            backend=request.backend,
            request=request.to_dict(),
            rationale=(
                "guided_checkpoint_unreached"
                if guided_checkpoint_unreached
                else "angr exhausted all active states without reaching the target address."
                if exhausted_without_path
                else "angr did not reach the target address before the bounded exploration budget expired."
            ),
            angr_trace=trace,
            replay_result=_empty_replay_result("not_run", "No concrete witness was produced."),
            logs=tuple([*logs, "guided_checkpoint_unreached"] if guided_checkpoint_unreached else logs),
            elapsed_seconds=elapsed,
        )
    except Exception as exc:
        return ConcolicVerdict(
            candidate_id=request.candidate_id,
            verdict="backend_error",
            backend=request.backend,
            request=request.to_dict(),
            rationale=f"angr backend failed: {exc}",
            errors=(str(exc),),
            angr_trace=_backend_error_trace(request, str(exc)),
            replay_result=_empty_replay_result("not_run", f"angr backend failed: {exc}"),
            elapsed_seconds=round(time.perf_counter() - started, 4),
        )


def _eval_symbolic_bytes(state: Any, symbolic: Any) -> bytes:
    try:
        return state.solver.eval(symbolic, cast_to=bytes)
    except Exception:
        return b""


def _concrete_angr_replay_status(replay_result: Mapping[str, Any]) -> str:
    concrete = replay_result.get("concrete_angr_replay") if isinstance(replay_result, Mapping) else {}
    return str(concrete.get("status") or "") if isinstance(concrete, Mapping) else ""


def _witness_for_input(
    input_model: str,
    concrete: bytes,
    *,
    evidence_pack: Mapping[str, Any] | None = None,
    crash_signal: str = "",
    function_args: Mapping[str, str] | None = None,
    reached_addresses: Sequence[str] = (),
) -> CrashWitness:
    if input_model == "stdin":
        spec = _stdin_process_input_spec(evidence_pack or {})
        argv_values = tuple(str(item).encode("utf-8") for item in _coerce_sequence(spec.get("argv_values"))[1:])
        return CrashWitness(
            input_model=input_model,
            stdin=concrete,
            argv=argv_values,
            crash_signal=crash_signal,
            reached_addresses=tuple(reached_addresses),
        )
    if input_model == "file":
        return CrashWitness(
            input_model=input_model,
            file_inputs={"concolic_input": concrete},
            argv=("concolic_input".encode("utf-8"),),
            crash_signal=crash_signal,
            reached_addresses=tuple(reached_addresses),
        )
    if input_model == "argv_file_stdin":
        spec = _combined_process_input_spec(evidence_pack or {})
        file_name = str(spec.get("file_name") or "concolic_input")
        argv_values = tuple(str(item).encode("utf-8") for item in _coerce_sequence(spec.get("argv_values"))[1:])
        file_bytes = _bytes_from_hex(spec.get("file_input_hex"))
        return CrashWitness(
            input_model=input_model,
            stdin=concrete,
            argv=argv_values or (file_name.encode("utf-8"),),
            file_inputs={file_name: file_bytes} if file_bytes is not None else {},
            crash_signal=crash_signal,
            reached_addresses=tuple(reached_addresses),
        )
    if input_model == "env":
        return CrashWitness(
            input_model=input_model,
            env={_env_process_input_name(evidence_pack or {}): concrete},
            crash_signal=crash_signal,
            reached_addresses=tuple(reached_addresses),
        )
    if input_model == "env_file":
        spec = _env_selected_file_input_spec(evidence_pack or {})
        file_name = str(spec.get("file_name") or "concolic_input")
        argv_values = tuple(str(item).encode("utf-8") for item in _coerce_sequence(spec.get("argv_values"))[1:])
        env_values = {
            str(key): str(value).encode("utf-8")
            for key, value in dict(spec.get("env_values") or {}).items()
        }
        return CrashWitness(
            input_model=input_model,
            argv=argv_values,
            file_inputs={file_name: concrete},
            env=env_values,
            crash_signal=crash_signal,
            reached_addresses=tuple(reached_addresses),
        )
    if input_model == "function_harness":
        return CrashWitness(
            input_model=input_model,
            function_args=dict(function_args or {}),
            crash_signal=crash_signal,
            reached_addresses=tuple(reached_addresses),
            solver_model={"symbolic_buffer_hex": concrete.hex()},
        )
    return CrashWitness(
        input_model=input_model,
        argv=(concrete,),
        crash_signal=crash_signal,
        reached_addresses=tuple(reached_addresses),
    )


def _make_angr_state(
    project: Any,
    angr: Any,
    claripy: Any,
    request: ConcolicRequest,
    evidence_pack: Mapping[str, Any],
    *,
    symbolic: Any,
) -> dict[str, Any]:
    if request.input_model == "argv":
        return {"state": project.factory.full_init_state(args=[str(request.binary_path), symbolic])}
    if request.input_model == "stdin":
        spec = _stdin_process_input_spec(evidence_pack)
        argv_values = [str(item) for item in _coerce_sequence(spec.get("argv_values"))]
        stream = angr.SimFileStream(name="stdin", content=symbolic, has_end=True)
        return {
            "state": project.factory.full_init_state(
                args=[str(request.binary_path), *argv_values[1:]],
                stdin=stream,
            )
        }
    if request.input_model == "file":
        simfile = angr.SimFile("concolic_input", content=symbolic, size=request.symbolic_bytes)
        return {
            "state": project.factory.full_init_state(
                args=[str(request.binary_path), "concolic_input"],
                fs={"concolic_input": simfile},
            )
        }
    if request.input_model == "argv_file_stdin":
        spec = _combined_process_input_spec(evidence_pack)
        file_name = str(spec.get("file_name") or "concolic_input")
        argv_values = [str(item) for item in _coerce_sequence(spec.get("argv_values"))]
        file_bytes = _bytes_from_hex(spec.get("file_input_hex"))
        if file_bytes is None:
            return {
                "unsupported": True,
                "reason": str(spec.get("unsupported_reason") or "unsupported_process_input_setup:missing_file_input_hex"),
            }
        stream = angr.SimFileStream(name="stdin", content=symbolic, has_end=True)
        simfile = angr.SimFile(file_name, content=file_bytes, size=len(file_bytes))
        return {
            "state": project.factory.full_init_state(
                args=[str(request.binary_path), *(argv_values[1:] or [file_name])],
                stdin=stream,
                fs={file_name: simfile},
            )
        }
    if request.input_model == "env":
        return {"state": project.factory.full_init_state(env={_env_process_input_name(evidence_pack): symbolic})}
    if request.input_model == "env_file":
        spec = _env_selected_file_input_spec(evidence_pack)
        file_name = str(spec.get("file_name") or "")
        env_values = {str(key): str(value) for key, value in dict(spec.get("env_values") or {}).items()}
        argv_values = [str(item) for item in _coerce_sequence(spec.get("argv_values"))]
        if not file_name or not env_values:
            return {"unsupported": True, "reason": "unsupported_process_input_setup:missing_env_file_spec"}
        simfile = angr.SimFile(file_name, content=symbolic, size=request.symbolic_bytes)
        return {
            "state": project.factory.full_init_state(
                args=[str(request.binary_path), *argv_values[1:]],
                env=env_values,
                fs={file_name: simfile},
            )
        }
    if request.input_model == "function_harness":
        return _make_angr_function_harness_state(project, claripy, request, evidence_pack, symbolic=symbolic)
    return {"unsupported": True, "reason": f"unsupported_input_model:{request.input_model}"}


def _make_angr_concrete_state(
    project: Any,
    angr: Any,
    request: ConcolicRequest,
    evidence_pack: Mapping[str, Any],
    *,
    concrete: bytes,
) -> dict[str, Any]:
    if request.input_model == "argv":
        return {"state": project.factory.full_init_state(args=[str(request.binary_path), concrete])}
    if request.input_model == "stdin":
        spec = _stdin_process_input_spec(evidence_pack)
        argv_values = [str(item) for item in _coerce_sequence(spec.get("argv_values"))]
        stream = angr.SimFileStream(name="stdin", content=concrete, has_end=True)
        return {
            "state": project.factory.full_init_state(
                args=[str(request.binary_path), *argv_values[1:]],
                stdin=stream,
            )
        }
    if request.input_model == "file":
        simfile = angr.SimFile("concolic_input", content=concrete, size=len(concrete))
        return {
            "state": project.factory.full_init_state(
                args=[str(request.binary_path), "concolic_input"],
                fs={"concolic_input": simfile},
            )
        }
    if request.input_model == "argv_file_stdin":
        spec = _combined_process_input_spec(evidence_pack)
        file_name = str(spec.get("file_name") or "concolic_input")
        argv_values = [str(item) for item in _coerce_sequence(spec.get("argv_values"))]
        file_bytes = _bytes_from_hex(spec.get("file_input_hex"))
        if file_bytes is None:
            return {
                "unsupported": True,
                "reason": str(spec.get("unsupported_reason") or "unsupported_process_input_setup:missing_file_input_hex"),
            }
        stream = angr.SimFileStream(name="stdin", content=concrete, has_end=True)
        simfile = angr.SimFile(file_name, content=file_bytes, size=len(file_bytes))
        return {
            "state": project.factory.full_init_state(
                args=[str(request.binary_path), *(argv_values[1:] or [file_name])],
                stdin=stream,
                fs={file_name: simfile},
            )
        }
    if request.input_model == "env":
        return {"state": project.factory.full_init_state(env={_env_process_input_name(evidence_pack): concrete})}
    if request.input_model == "env_file":
        spec = _env_selected_file_input_spec(evidence_pack)
        file_name = str(spec.get("file_name") or "")
        env_values = {str(key): str(value) for key, value in dict(spec.get("env_values") or {}).items()}
        argv_values = [str(item) for item in _coerce_sequence(spec.get("argv_values"))]
        if not file_name or not env_values:
            return {"unsupported": True, "reason": "unsupported_process_input_setup:missing_env_file_spec"}
        simfile = angr.SimFile(file_name, content=concrete, size=len(concrete))
        return {
            "state": project.factory.full_init_state(
                args=[str(request.binary_path), *argv_values[1:]],
                env=env_values,
                fs={file_name: simfile},
            )
        }
    if request.input_model == "function_harness":
        return _make_angr_function_harness_state(project, None, request, evidence_pack, concrete=concrete)
    return {"unsupported": True, "reason": f"unsupported_input_model:{request.input_model}"}


def _make_angr_function_harness_state(
    project: Any,
    claripy: Any,
    request: ConcolicRequest,
    evidence_pack: Mapping[str, Any],
    *,
    symbolic: Any | None = None,
    concrete: bytes | None = None,
) -> dict[str, Any]:
    harness = _function_harness_spec(evidence_pack)
    if not harness:
        return {"unsupported": True, "reason": "unsupported_input_model:function_harness"}
    function_address = _normalize_address(harness.get("function_address") or _candidate(evidence_pack).get("address"))
    parsed = _parse_address(function_address)
    if parsed is None:
        return {"unsupported": True, "reason": "unsupported_function_harness:missing_function_address"}
    loader_base = int(project.loader.main_object.mapped_base or 0)
    image_base = _image_base_from_export(request.export_dir)
    function_target = translate_ghidra_to_loader_address(
        function_address,
        image_base=image_base,
        loader_base=loader_base,
    )
    arg_count = _safe_int(harness.get("arg_count"), default=1)
    if arg_count <= 0 or arg_count > 8:
        return {"unsupported": True, "reason": "unsupported_function_harness:invalid_arg_count"}
    input_addr = _safe_int(harness.get("input_address"), default=_FUNCTION_HARNESS_INPUT_ADDRESS)
    data = symbolic if symbolic is not None else concrete
    if data is None:
        return {"unsupported": True, "reason": "unsupported_function_harness:missing_input"}
    args: list[Any] = []
    input_arg_index = _safe_int(harness.get("input_arg_index"), default=0)
    input_arg_indices = {input_arg_index}
    raw_input_arg_indices = harness.get("input_arg_indices")
    if isinstance(raw_input_arg_indices, Sequence) and not isinstance(raw_input_arg_indices, (str, bytes, bytearray)):
        parsed_indices = {
            parsed
            for parsed in (_safe_int(raw_index, default=-1) for raw_index in raw_input_arg_indices)
            if 0 <= parsed < arg_count
        }
        if parsed_indices:
            input_arg_indices = parsed_indices
    length_arg_index = _safe_int(harness.get("length_arg_index"), default=-1)
    if length_arg_index < 0 and bool(harness.get("length_arg", False)):
        length_arg_index = 1 if input_arg_index != 1 else -1
    constant_args = harness.get("constant_args") if isinstance(harness.get("constant_args"), Mapping) else {}
    for index in range(arg_count):
        if index in input_arg_indices:
            args.append(input_addr)
        elif index == length_arg_index:
            args.append(request.symbolic_bytes if symbolic is not None else len(concrete or b""))
        else:
            args.append(_safe_int(constant_args.get(str(index)), default=0))
    try:
        state = project.factory.call_state(function_target.loader_address, *args)
        state.memory.store(input_addr, data)
        if claripy is not None:
            state.memory.store(input_addr + request.symbolic_bytes, claripy.BVV(0, 8))
        else:
            state.memory.store(input_addr + len(concrete or b""), b"\x00")
    except Exception as exc:
        return {"unsupported": True, "reason": f"unsupported_function_harness:{exc}"}
    return {
        "state": state,
        "function_args": {
            "function_address": function_address,
            "loader_address": f"0x{function_target.loader_address:x}",
            "input_arg_index": str(input_arg_index),
            f"arg{input_arg_index}": f"0x{input_addr:x}",
            "arg_count": str(arg_count),
        },
    }


def _constrain_printable_symbolic_bytes(state: Any, symbolic: Any) -> None:
    try:
        bytes_iter = symbolic.chop(8)
    except Exception:
        return
    for byte in bytes_iter:
        try:
            state.solver.add(byte != 0)
            state.solver.add(byte >= 0x20)
            state.solver.add(byte <= 0x7e)
        except Exception:
            return


def _input_model_requires_printable_bytes(input_model: str) -> bool:
    return input_model in {"argv", "env", "argv_directory"}


def _apply_concolic_request_constraints(state: Any, symbolic: Any, request: ConcolicRequest) -> dict[str, Any]:
    trace: dict[str, Any] = {
        "constraints": [],
        "seed_mutations": [],
        "rejected": [],
        "extra_branch_goal": request.extra_branch_goal,
    }
    symbolic_bytes = _symbolic_byte_list(symbolic)
    for seed_index, seed in enumerate(request.seed_mutations):
        seed_bytes = _seed_bytes(seed)
        if not seed_bytes:
            trace["rejected"].append({"kind": "seed_mutation", "value": seed, "reason": "empty_seed"})
            continue
        if seed_index > 0:
            trace["rejected"].append(
                {"kind": "seed_mutation", "value": seed[:80], "reason": "only_first_seed_applied_per_attempt"}
            )
            continue
        applied = _apply_prefix_bytes(state, symbolic_bytes, seed_bytes)
        trace["seed_mutations"].append({"value": seed[:80], "bytes_applied": applied})
    for constraint in request.constraints:
        applied = _apply_single_request_constraint(state, symbolic_bytes, constraint)
        if applied.get("applied"):
            trace["constraints"].append(applied)
        else:
            trace["rejected"].append(applied)
    return trace


def _apply_single_request_constraint(state: Any, symbolic_bytes: Sequence[Any], constraint: str) -> dict[str, Any]:
    text = str(constraint or "").strip()
    if not text:
        return {"constraint": constraint, "applied": False, "reason": "empty_constraint"}
    prefix_match = re.match(r"^(?:prefix|starts_with)\s*[:=]\s*(.+)$", text, re.IGNORECASE)
    if prefix_match:
        raw = prefix_match.group(1).strip()
        seed = _seed_bytes(raw)
        applied = _apply_prefix_bytes(state, symbolic_bytes, seed)
        return {"constraint": constraint, "applied": applied > 0, "kind": "prefix", "bytes_applied": applied}
    byte_match = re.match(
        r"^(?:byte|input)\[(\d+)\]\s*(==|!=|>=|<=|>|<)\s*('(?:[^']|\\')'|0x[0-9a-fA-F]+|\d+)$",
        text,
    )
    if not byte_match:
        return {"constraint": constraint, "applied": False, "reason": "unsupported_constraint_syntax"}
    index = int(byte_match.group(1))
    op = byte_match.group(2)
    value = _constraint_byte_value(byte_match.group(3))
    if value is None or value < 0 or value > 0xFF:
        return {"constraint": constraint, "applied": False, "reason": "invalid_byte_value"}
    if index < 0 or index >= len(symbolic_bytes):
        return {"constraint": constraint, "applied": False, "reason": "byte_index_out_of_range"}
    byte = symbolic_bytes[index]
    try:
        if op == "==":
            state.solver.add(byte == value)
        elif op == "!=":
            state.solver.add(byte != value)
        elif op == ">=":
            state.solver.add(byte >= value)
        elif op == "<=":
            state.solver.add(byte <= value)
        elif op == ">":
            state.solver.add(byte > value)
        elif op == "<":
            state.solver.add(byte < value)
    except Exception as exc:
        return {"constraint": constraint, "applied": False, "reason": f"solver_rejected:{exc}"}
    return {"constraint": constraint, "applied": True, "kind": "byte_compare", "index": index, "operator": op, "value": value}


def _apply_prefix_bytes(state: Any, symbolic_bytes: Sequence[Any], prefix: bytes) -> int:
    applied = 0
    for index, value in enumerate(prefix[: len(symbolic_bytes)]):
        try:
            state.solver.add(symbolic_bytes[index] == value)
            applied += 1
        except Exception:
            break
    return applied


def _symbolic_byte_list(symbolic: Any) -> list[Any]:
    try:
        return list(symbolic.chop(8))
    except Exception:
        return []


def _seed_bytes(seed: Any) -> bytes:
    text = str(seed or "")
    if not text:
        return b""
    if text.startswith("hex:"):
        try:
            return bytes.fromhex(text[4:])
        except ValueError:
            return b""
    stripped = text.strip()
    if stripped.startswith("0x") and len(stripped) > 2 and len(stripped[2:]) % 2 == 0:
        try:
            return bytes.fromhex(stripped[2:])
        except ValueError:
            pass
    return stripped.encode("utf-8", errors="ignore")


def _constraint_byte_value(value: str) -> int | None:
    text = str(value).strip()
    if len(text) >= 3 and text[0] == "'" and text[-1] == "'":
        body = text[1:-1]
        return ord(body.encode("utf-8").decode("unicode_escape")[:1]) if body else None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _install_sink_hooks(
    project: Any,
    angr: Any,
    request: ConcolicRequest,
    evidence_pack: Mapping[str, Any],
    symbolic: Any,
    sink_events: list[dict[str, Any]],
) -> None:
    candidate = _candidate(evidence_pack)
    sink_names = {str(candidate.get("sink") or ""), *request.allowed_stubs}
    sink_names = {name for name in sink_names if name in {"read", "memcpy", "strcpy", "sprintf", "snprintf"}}
    if not sink_names:
        return
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    modeled_write_size = _candidate_write_size_bytes(evidence_pack, None) or request.symbolic_bytes

    def record(state: Any, sink_name: str, args: Sequence[Any], write_size: int, dst: Any = None) -> None:
        if len(sink_events) >= 64:
            return
        sink_events.append(
            {
                "sink": sink_name,
                "state_address": _format_address(getattr(state, "addr", None)),
                "args": [_solver_value_summary(state, arg) for arg in args],
                "destination": _solver_value_summary(state, dst) if dst is not None else "",
                "write_size_bytes": int(write_size),
                "capacity_bytes": capacity,
                "overflow_bytes": max(0, int(write_size) - capacity) if capacity > 0 else 0,
            }
        )

    def symbolic_prefix(size: int) -> Any:
        if size <= 0:
            return b""
        try:
            if hasattr(symbolic, "get_bytes"):
                return symbolic.get_bytes(0, min(size, request.symbolic_bytes))
        except Exception:
            pass
        return symbolic

    class ReadHook(angr.SimProcedure):  # type: ignore[misc]
        def run(self, fd: Any, buf: Any, count: Any) -> Any:  # pragma: no cover - exercised only with angr
            size = _bounded_solver_int(self.state, count, default=modeled_write_size, upper=request.symbolic_bytes)
            try:
                self.state.memory.store(buf, symbolic_prefix(size))
            except Exception:
                pass
            record(self.state, "read", (fd, buf, count), size, dst=buf)
            return size

    class MemcpyHook(angr.SimProcedure):  # type: ignore[misc]
        def run(self, dst: Any, src: Any, count: Any) -> Any:  # pragma: no cover - exercised only with angr
            size = _bounded_solver_int(self.state, count, default=modeled_write_size, upper=max(request.symbolic_bytes, modeled_write_size))
            try:
                self.state.memory.store(dst, self.state.memory.load(src, size))
            except Exception:
                pass
            record(self.state, "memcpy", (dst, src, count), size, dst=dst)
            return dst

    class StringCopyHook(angr.SimProcedure):  # type: ignore[misc]
        def run(self, dst: Any, src: Any) -> Any:  # pragma: no cover - exercised only with angr
            size = max(1, min(modeled_write_size or request.symbolic_bytes, request.symbolic_bytes))
            try:
                self.state.memory.store(dst, symbolic_prefix(size))
            except Exception:
                pass
            record(self.state, "strcpy", (dst, src), size, dst=dst)
            return dst

    class SprintfHook(angr.SimProcedure):  # type: ignore[misc]
        def run(self, dst: Any, fmt: Any, *args: Any) -> Any:  # pragma: no cover - exercised only with angr
            size = max(1, min(modeled_write_size or request.symbolic_bytes, request.symbolic_bytes))
            try:
                self.state.memory.store(dst, symbolic_prefix(size))
            except Exception:
                pass
            record(self.state, "sprintf", (dst, fmt, *args[:4]), size, dst=dst)
            return size

    class SnprintfHook(angr.SimProcedure):  # type: ignore[misc]
        def run(self, dst: Any, limit: Any, fmt: Any, *args: Any) -> Any:  # pragma: no cover - exercised only with angr
            limit_size = _bounded_solver_int(self.state, limit, default=modeled_write_size, upper=max(request.symbolic_bytes, modeled_write_size))
            size = max(0, min(modeled_write_size or limit_size, limit_size))
            try:
                self.state.memory.store(dst, symbolic_prefix(size))
            except Exception:
                pass
            record(self.state, "snprintf", (dst, limit, fmt, *args[:4]), size, dst=dst)
            return size

    hooks = {
        "read": ReadHook,
        "memcpy": MemcpyHook,
        "strcpy": StringCopyHook,
        "sprintf": SprintfHook,
        "snprintf": SnprintfHook,
    }
    for name in sink_names:
        try:
            project.hook_symbol(name, hooks[name]())
        except Exception:
            continue


def _bounded_solver_int(state: Any, value: Any, *, default: int, upper: int) -> int:
    try:
        resolved = int(state.solver.eval(value))
    except Exception:
        resolved = int(default)
    if resolved < 0:
        return 0
    return min(resolved, max(1, int(upper or default or 1)))


def _install_mem_write_trace(state: Any, angr: Any, memory_writes: list[dict[str, Any]]) -> None:
    try:
        bp_after = angr.BP_AFTER
    except Exception:
        return

    def record_write(write_state: Any) -> None:
        if len(memory_writes) >= 128:
            return
        inspect = getattr(write_state, "inspect", None)
        if inspect is None:
            return
        memory_writes.append(
            {
                "address": _solver_value_summary(write_state, getattr(inspect, "mem_write_address", None)),
                "expr": _solver_value_summary(write_state, getattr(inspect, "mem_write_expr", None)),
                "length": _solver_value_summary(write_state, getattr(inspect, "mem_write_length", None)),
                "state_address": _format_address(getattr(write_state, "addr", None)),
            }
        )

    try:
        state.inspect.b("mem_write", when=bp_after, action=record_write)
    except Exception:
        return


def _build_angr_trace(
    request: ConcolicRequest,
    *,
    target: Mapping[str, Any],
    branch_target: Mapping[str, Any] | None = None,
    simgr: Any,
    state: Any,
    memory_writes: Sequence[Mapping[str, Any]],
    sink_events: Sequence[Mapping[str, Any]] = (),
    constraint_trace: Mapping[str, Any] | None = None,
    exploration_metrics: Mapping[str, Any] | None = None,
    elapsed_seconds: float,
    status: str,
) -> dict[str, Any]:
    metrics = exploration_metrics if isinstance(exploration_metrics, Mapping) else {}
    return {
        "schema_version": 2,
        "trace_kind": "angr",
        "candidate_id": request.candidate_id,
        "status": status,
        "target": dict(target),
        "branch_goal": dict(branch_target or {}),
        "reached_blocks": _state_reached_addresses(state),
        "constraints_summary": _constraints_summary(state),
        "applied_request_controls": dict(constraint_trace or {}),
        "memory_writes": [dict(item) for item in memory_writes],
        "sink_events": [dict(item) for item in sink_events],
        "errored_states": _errored_state_summary(simgr),
        "unconstrained_states": _state_list_summary(getattr(simgr, "unconstrained", [])),
        "stash_counts": _stash_counts(simgr),
        "exploration_metrics": {
            "simgr_steps": _safe_int(metrics.get("simgr_steps")),
            "peak_active_states": _safe_int(metrics.get("peak_active_states")),
            "peak_total_states": _safe_int(metrics.get("peak_total_states")),
            "waypoint_count": _safe_int(metrics.get("waypoint_count")),
            "reached_waypoint_count": _safe_int(metrics.get("reached_waypoint_count")),
        },
        "elapsed_seconds": elapsed_seconds,
    }


def _backend_error_trace(
    request: ConcolicRequest,
    reason: str,
    *,
    target: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "trace_kind": "angr",
        "candidate_id": request.candidate_id,
        "status": "backend_error",
        "target": dict(target or {}),
        "branch_goal": {},
        "reached_blocks": [],
        "constraints_summary": {"count": 0, "samples": []},
        "applied_request_controls": {"constraints": [], "seed_mutations": [], "rejected": []},
        "memory_writes": [],
        "sink_events": [],
        "errored_states": [{"error": str(reason)}],
        "unconstrained_states": [],
        "stash_counts": {},
        "exploration_metrics": {
            "simgr_steps": 0,
            "peak_active_states": 0,
            "peak_total_states": 0,
            "waypoint_count": len(request.waypoint_addresses),
            "reached_waypoint_count": 0,
        },
        "elapsed_seconds": 0.0,
    }


def _replay_angr_witness(
    project: Any,
    angr: Any,
    request: ConcolicRequest,
    evidence_pack: Mapping[str, Any],
    *,
    concrete: bytes,
    target_loader_address: int,
    expect_crash: bool,
) -> dict[str, Any]:
    started = time.perf_counter()
    setup = _make_angr_concrete_state(project, angr, request, evidence_pack, concrete=concrete)
    if setup.get("unsupported"):
        return _empty_replay_result("unsupported", str(setup.get("reason") or "unsupported replay harness"))
    state = setup["state"]
    simgr = project.factory.simulation_manager(state, save_unconstrained=True)
    deadline = time.perf_counter() + min(max(request.timeout_seconds, 0.1), 30.0)
    block_cache: dict[int, tuple[int, ...]] = {}

    def reached_target() -> bool:
        return any(
            _state_reached_loader_instruction(project, active, target_loader_address, block_cache)
            for active in simgr.active
        )

    reached = reached_target()
    status = "not_replayed"
    trivial_function_harness_entry = bool(reached and request.input_model == "function_harness")
    if reached:
        status = "trivial_function_harness_entry" if trivial_function_harness_entry else "replayed"
    while status != "replayed" and simgr.active and time.perf_counter() < deadline:
        if trivial_function_harness_entry:
            break
        if reached_target():
            reached = True
            break
        simgr.step()
        if expect_crash and (simgr.errored or simgr.unconstrained):
            status = "replayed"
            break
    if trivial_function_harness_entry:
        status = "trivial_function_harness_entry"
    elif reached or reached_target():
        status = "replayed"
    elif status != "replayed" and time.perf_counter() >= deadline:
        status = "timeout"
    return {
        "schema_version": 1,
        "concrete_angr_replay": {
            "status": status,
            "input_model": request.input_model,
            "target_loader_address": f"0x{target_loader_address:x}",
            "input_hex": concrete.hex(),
            "initial_target_reached": bool(trivial_function_harness_entry),
            "reason": "function_harness replay started at the target address" if trivial_function_harness_entry else "",
            "reached_addresses": _state_reached_addresses(simgr.active[0]) if simgr.active else [],
            "errored_states": _errored_state_summary(simgr),
            "unconstrained_states": _state_list_summary(getattr(simgr, "unconstrained", [])),
            "elapsed_seconds": round(time.perf_counter() - started, 4),
        },
        "ghidra_pcode_replay": {
            "status": "unsupported",
            "reason": "Ghidra p-code replay is emitted separately when --pcode-trace is enabled.",
        },
    }


def _empty_replay_result(status: str, reason: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "concrete_angr_replay": {"status": status, "reason": reason},
        "ghidra_pcode_replay": {"status": "unsupported", "reason": reason},
    }


def _has_concrete_replay(replay_result: Mapping[str, Any]) -> bool:
    replay = replay_result.get("concrete_angr_replay") if isinstance(replay_result, Mapping) else {}
    return isinstance(replay, Mapping) and str(replay.get("status") or "") == "replayed"


def _has_replay_artifact(artifact_paths: Sequence[str]) -> bool:
    return any(Path(str(path)).name == CONCOLIC_REPLAY_FILENAME for path in artifact_paths)


def _has_pcode_trace_artifact(artifact_paths: Sequence[str]) -> bool:
    return any(Path(str(path)).name == CONCOLIC_PCODE_TRACE_FILENAME for path in artifact_paths)


def _has_dynamic_proof_artifact(artifact_paths: Sequence[str]) -> bool:
    return any(Path(str(path)).name == CONCOLIC_DYNAMIC_PROOF_FILENAME for path in artifact_paths)


def _has_dynamic_memory_safety_proof(proof: Mapping[str, Any]) -> bool:
    if not isinstance(proof, Mapping):
        return False
    return DynamicProofView(proof).is_memory_safety_proof(
        require_setup=False,
        require_sink=True,
        allow_non_process_scope=True,
    )


def _has_decisive_dynamic_process_result(proof: Mapping[str, Any]) -> bool:
    if _has_dynamic_memory_safety_proof(proof):
        return True
    if not isinstance(proof, Mapping) or str(proof.get("status") or "") not in {
        "no_overflow",
        "no_oob_read",
        "no_lifetime_violation",
    }:
        return False
    view = DynamicProofView(proof)
    return (
        view.scope == "process_entrypoint"
        and str(view.process_input_setup.get("status") or "") == "configured"
        and str(view.process_replay.get("status") or "") == "reached"
        and proof.get("exact_sink_reached") is True
        and bool(view.sink_address)
    )


def _has_dynamic_overflow_proof(proof: Mapping[str, Any]) -> bool:
    return (
        isinstance(proof, Mapping)
        and DynamicProofView(proof).status in {"overflow_proven", "heap_overflow_proven", "oob_write_proven"}
        and _has_dynamic_memory_safety_proof(proof)
    )


def _has_dynamic_heap_overflow_proof(proof: Mapping[str, Any]) -> bool:
    return (
        isinstance(proof, Mapping)
        and DynamicProofView(proof).status == "heap_overflow_proven"
        and _has_dynamic_memory_safety_proof(proof)
    )


def _has_dynamic_oob_write_proof(proof: Mapping[str, Any]) -> bool:
    return (
        isinstance(proof, Mapping)
        and DynamicProofView(proof).status == "oob_write_proven"
        and _has_dynamic_memory_safety_proof(proof)
    )


def _has_dynamic_oob_read_proof(proof: Mapping[str, Any]) -> bool:
    return (
        isinstance(proof, Mapping)
        and DynamicProofView(proof).status == "oob_read_proven"
        and _has_dynamic_memory_safety_proof(proof)
    )


def _has_dynamic_lifetime_proof(proof: Mapping[str, Any]) -> bool:
    return (
        isinstance(proof, Mapping)
        and DynamicProofView(proof).status == "lifetime_violation_proven"
        and _has_dynamic_memory_safety_proof(proof)
    )


def _concolic_iteration_count(verdict: ConcolicVerdict) -> int:
    trace = verdict.angr_trace
    for key in ("iterations", "steps", "attempt_count"):
        value = trace.get(key) if isinstance(trace, Mapping) else None
        try:
            if value is not None:
                return int(value)
        except (TypeError, ValueError):
            pass
    attempts = trace.get("attempts") if isinstance(trace, Mapping) else None
    if isinstance(attempts, Sequence) and not isinstance(attempts, (str, bytes)):
        return len(attempts)
    return 0


def _has_exact_pcode_sink_trace(pcode_trace: Mapping[str, Any]) -> bool:
    if not isinstance(pcode_trace, Mapping):
        return False
    sink_trace = pcode_trace.get("sink_trace")
    replay = pcode_trace.get("replay")
    replay_reached = isinstance(replay, Mapping) and str(replay.get("status") or "") == "reached"
    return (
        isinstance(sink_trace, Mapping)
        and sink_trace.get("exact_sink_reached") is True
        and bool(sink_trace.get("exact_sink_address"))
        and replay_reached
    )


def _function_harness_spec(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    trace = _candidate_classification_trace(evidence_pack)
    for key in ("function_harness", "harness"):
        value = trace.get(key)
        if isinstance(value, Mapping):
            return value
    for value in (
        evidence_pack.get("function_harness"),
        _facts(evidence_pack).get("function_harness"),
        _facts(evidence_pack).get("harness"),
    ):
        if isinstance(value, Mapping):
            return value
    reproducer = _facts(evidence_pack).get("reproducer_hypothesis")
    if isinstance(reproducer, Mapping):
        for key in ("function_harness", "harness"):
            value = reproducer.get(key)
            if isinstance(value, Mapping):
                return value
    return _derive_function_harness_spec(evidence_pack)


def _candidate_classification_trace(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    candidate = _candidate(evidence_pack)
    trace = candidate.get("classification_trace")
    if isinstance(trace, Mapping):
        return trace
    static_candidate = _static_candidate(evidence_pack)
    trace = static_candidate.get("classification_trace")
    if isinstance(trace, Mapping):
        return trace
    type_facts = evidence_pack.get("type_facts")
    if isinstance(type_facts, Mapping):
        trace = type_facts.get("classification_trace")
        if isinstance(trace, Mapping):
            return trace
    facts = _facts(evidence_pack)
    trace = facts.get("classification_trace")
    return trace if isinstance(trace, Mapping) else {}


def _static_candidate(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    type_facts = evidence_pack.get("type_facts")
    if isinstance(type_facts, Mapping):
        static_candidate = type_facts.get("static_candidate")
        if isinstance(static_candidate, Mapping):
            return static_candidate
    facts = _facts(evidence_pack)
    static_candidate = facts.get("static_candidate")
    return static_candidate if isinstance(static_candidate, Mapping) else {}


def _candidate_capacity_model(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    candidate = _candidate(evidence_pack)
    model = candidate.get("capacity_model")
    if isinstance(model, Mapping):
        return model
    model = _static_candidate(evidence_pack).get("capacity_model")
    return model if isinstance(model, Mapping) else {}


def _candidate_dynamic_proof_hints(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    trace = _candidate_classification_trace(evidence_pack)
    hints = trace.get("dynamic_proof")
    return hints if isinstance(hints, Mapping) else {}


def _derive_function_harness_spec(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    candidate = _candidate(evidence_pack)
    function_address = _normalize_address(candidate.get("address"))
    if not function_address:
        return {}
    facts = _facts(evidence_pack)
    reproducer = facts.get("reproducer_hypothesis")
    if not isinstance(reproducer, Mapping):
        reproducer = evidence_pack.get("reproducer_hypothesis")
    input_surface = str(reproducer.get("input_surface") if isinstance(reproducer, Mapping) else "").lower()
    if input_surface and input_surface not in {
        "api_parameter",
        "network_input",
        "unknown",
        "stdin",
        "env",
        "environment",
        "file",
        "file_or_fd",
        "cli_argument",
        "function_harness",
    }:
        return {}
    arg_count = _estimate_harness_arg_count(evidence_pack)
    input_arg_indices = _controlled_parameter_arg_indices(evidence_pack)
    input_arg_index = input_arg_indices[0] if input_arg_indices else _controlled_parameter_arg_index(evidence_pack)
    input_arg_indices = tuple(sorted({input_arg_index, *input_arg_indices}))
    if input_arg_indices:
        arg_count = max(arg_count, max(input_arg_indices) + 1)
    constant_args = {str(index): 0 for index in range(arg_count) if index not in input_arg_indices}
    return {
        "derived": True,
        "function_address": function_address,
        "arg_count": arg_count,
        "input_address": _FUNCTION_HARNESS_INPUT_ADDRESS,
        "input_arg_index": input_arg_index,
        "input_arg_indices": list(input_arg_indices),
        "length_arg": False,
        "constant_args": constant_args,
    }


def _controlled_parameter_arg_indices(evidence_pack: Mapping[str, Any]) -> tuple[int, ...]:
    result: set[int] = set()
    facts = _facts(evidence_pack)
    role_sources: list[Any] = []
    source_to_write = facts.get("source_to_write") if isinstance(facts.get("source_to_write"), Mapping) else {}
    role_sources.append(source_to_write.get("roles") if isinstance(source_to_write.get("roles"), Mapping) else {})
    trace = _source_to_sink_trace(evidence_pack)
    role_sources.append(trace.get("argument_roles") if isinstance(trace, Mapping) else [])
    for roles in role_sources:
        if isinstance(roles, Mapping):
            iterable = roles.values()
        else:
            iterable = _coerce_sequence(roles)
        for role in iterable:
            if not isinstance(role, Mapping):
                continue
            if str(role.get("classification") or "") not in {"parameter_controlled", "source_controlled"}:
                continue
            for match in re.finditer(r"\bparam_(\d+)\b", str(role.get("expr") or "")):
                result.add(max(0, _safe_int(match.group(1), default=1) - 1))
            for item in _coerce_sequence(role.get("evidence")):
                for match in re.finditer(r"\bparameter:param_(\d+)\b", str(item)):
                    result.add(max(0, _safe_int(match.group(1), default=1) - 1))
    return tuple(sorted(index for index in result if 0 <= index < 8))


def _controlled_parameter_arg_index(evidence_pack: Mapping[str, Any]) -> int:
    facts = _facts(evidence_pack)
    source_to_write = facts.get("source_to_write") if isinstance(facts.get("source_to_write"), Mapping) else {}
    roles = source_to_write.get("roles") if isinstance(source_to_write.get("roles"), Mapping) else {}
    for role_name in ("write_source", "write_size", "write_offset", "destination_pointer"):
        role = roles.get(role_name)
        if not isinstance(role, Mapping):
            continue
        if str(role.get("classification") or "") not in {"parameter_controlled", "source_controlled"}:
            continue
        match = re.search(r"\bparam_(\d+)\b", str(role.get("expr") or ""))
        if match:
            return max(0, _safe_int(match.group(1), default=1) - 1)
    for text in _harness_text_corpus(evidence_pack):
        match = re.search(r"\bparam_(\d+)\b", text)
        if match:
            return max(0, _safe_int(match.group(1), default=1) - 1)
    return 0


def _estimate_harness_arg_count(evidence_pack: Mapping[str, Any]) -> int:
    max_param = 0
    for text in _harness_text_corpus(evidence_pack):
        for match in re.finditer(r"\bparam_(\d+)\b", text):
            max_param = max(max_param, _safe_int(match.group(1), default=0))
    if max_param <= 0:
        return 1
    return min(max_param, 8)


def _harness_text_corpus(evidence_pack: Mapping[str, Any]) -> list[str]:
    candidate = _candidate(evidence_pack)
    facts = _facts(evidence_pack)
    texts = [
        candidate.get("line_text"),
        candidate.get("overflow_condition"),
        candidate.get("source_evidence"),
    ]
    for row in _coerce_sequence(facts.get("write_table", [])):
        if isinstance(row, Mapping):
            texts.extend([row.get("line_text"), row.get("offset_expr"), row.get("write_size_expr")])
    excerpt = facts.get("decompiled_excerpt")
    if isinstance(excerpt, Mapping):
        texts.extend(str(item) for item in _coerce_sequence(excerpt.get("lines", [])))
        texts.append(excerpt.get("text"))
    elif excerpt:
        texts.append(excerpt)
    return [str(text) for text in texts if text]


def _state_reached_addresses(state: Any) -> list[str]:
    try:
        addresses = list(state.history.bbl_addrs)
    except Exception:
        addresses = []
    result: list[str] = []
    seen: set[str] = set()
    for address in addresses[-256:]:
        text = _format_address(address)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    current = _format_address(getattr(state, "addr", None))
    if current and current not in seen:
        result.append(current)
    return result


def _state_reached_loader_instruction(
    project: Any,
    state: Any,
    target_loader_address: int,
    block_cache: dict[int, tuple[int, ...]],
) -> bool:
    current = getattr(state, "addr", None)
    try:
        if current is not None and int(current) == int(target_loader_address):
            return True
    except Exception:
        pass
    try:
        block_addresses = list(state.history.bbl_addrs)[-64:]
    except Exception:
        block_addresses = []
    if current is not None:
        block_addresses.append(current)
    for block_address in block_addresses:
        try:
            block_start = int(block_address)
        except Exception:
            continue
        instruction_addresses = block_cache.get(block_start)
        if instruction_addresses is None:
            try:
                block = project.factory.block(block_start)
                instruction_addresses = tuple(int(item) for item in getattr(block, "instruction_addrs", []) or [])
            except Exception:
                instruction_addresses = ()
            block_cache[block_start] = instruction_addresses
        if int(target_loader_address) in instruction_addresses:
            return True
    return False


def _constraints_summary(state: Any) -> dict[str, Any]:
    try:
        constraints = list(state.solver.constraints)
    except Exception:
        constraints = []
    return {
        "count": len(constraints),
        "samples": [str(item)[:240] for item in constraints[:20]],
    }


def _errored_state_summary(simgr: Any) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for item in list(getattr(simgr, "errored", []) or [])[:16]:
        state = getattr(item, "state", None)
        result.append(
            {
                "address": _format_address(getattr(state, "addr", None)),
                "error": str(getattr(item, "error", item))[:500],
            }
        )
    return result


def _state_list_summary(states: Sequence[Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for state in list(states or [])[:16]:
        result.append({"address": _format_address(getattr(state, "addr", None))})
    return result


def _stash_counts(simgr: Any) -> dict[str, int]:
    stashes = getattr(simgr, "stashes", {}) or {}
    return {str(name): len(items) for name, items in stashes.items()}


def _simgr_state_total(simgr: Any) -> int:
    """Return all retained simulation states without relying on named stashes."""

    stashes = getattr(simgr, "stashes", {}) or {}
    active_count = len(getattr(simgr, "active", []) or [])
    try:
        return max(active_count, sum(len(items) for items in stashes.values()))
    except (AttributeError, TypeError):
        return active_count


def _solver_value_summary(state: Any, value: Any) -> str:
    if value is None:
        return ""
    try:
        if getattr(value, "symbolic", False):
            return str(value)[:240]
    except Exception:
        pass
    try:
        resolved = state.solver.eval(value)
        return _format_address(resolved)
    except Exception:
        return str(value)[:240]


def _format_address(value: Any) -> str:
    try:
        if value is None:
            return ""
        return f"0x{int(value):x}"
    except Exception:
        return str(value or "")


def _safe_int(value: Any, *, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return default


def _candidate_write_size_bytes(evidence_pack: Mapping[str, Any], verdict: ConcolicVerdict | None) -> int:
    candidate = _candidate(evidence_pack)
    direct = _safe_int(candidate.get("write_size_bytes"), default=0)
    if direct > 0:
        return direct
    facts = _facts(evidence_pack)
    for row in _coerce_sequence(facts.get("write_table", [])):
        if isinstance(row, Mapping):
            row_size = _safe_int(row.get("write_size_bytes"), default=0)
            if row_size > 0:
                return row_size
    if verdict is not None:
        concrete = _concrete_input_from_verdict(verdict)
        input_hex = str(concrete.get("input_hex") or "")
        if input_hex:
            return len(input_hex) // 2
    return 0


def _reached_sink_proves_memory_overflow(
    evidence_pack: Mapping[str, Any],
    concrete: bytes,
    *,
    export_dir: Path | None = None,
) -> bool:
    candidate = _candidate_for_memory_proof(evidence_pack, export_dir=export_dir)
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    write_size = _candidate_write_size_bytes(evidence_pack, None)
    if capacity > 0 and write_size > capacity:
        return True
    if capacity <= 0:
        return False
    relation = str(candidate.get("write_relation") or "")
    verdict = str(candidate.get("verdict") or "")
    proof = evidence_pack.get("proof_obligation") if isinstance(evidence_pack.get("proof_obligation"), Mapping) else {}
    proof_relation = str(proof.get("relation") or "")
    if relation == "proven_overflow" or verdict == "overflow" or proof_relation == "proven_overflow":
        return True
    if "unbounded" not in {relation, verdict, proof_relation}:
        return False
    available = max(0, capacity - max(0, _safe_int(candidate.get("offset_expr"), default=0)))
    if available <= 0:
        return True
    return _c_string_payload_length(concrete) > available


def _c_string_payload_length(concrete: bytes) -> int:
    if not concrete:
        return 0
    return len(concrete.split(b"\x00", 1)[0])


def _concrete_input_from_verdict(verdict: ConcolicVerdict) -> dict[str, Any]:
    if verdict.witness is not None:
        witness = verdict.witness
        if witness.stdin is not None:
            return {"input_model": witness.input_model, "input_hex": witness.stdin.hex(), "source": "stdin"}
        if witness.input_model == "file" and witness.file_inputs:
            name, value = next(iter(witness.file_inputs.items()))
            return {"input_model": witness.input_model, "input_hex": value.hex(), "source": f"file:{name}"}
        if witness.input_model == "env_file" and witness.file_inputs:
            name, value = next(iter(witness.file_inputs.items()))
            return {"input_model": witness.input_model, "input_hex": value.hex(), "source": f"file:{name}"}
        if witness.argv:
            return {"input_model": witness.input_model, "input_hex": witness.argv[0].hex(), "source": "argv[0]"}
        if witness.file_inputs:
            name, value = next(iter(witness.file_inputs.items()))
            return {"input_model": witness.input_model, "input_hex": value.hex(), "source": f"file:{name}"}
        if witness.env:
            name, value = next(iter(witness.env.items()))
            return {"input_model": witness.input_model, "input_hex": value.hex(), "source": f"env:{name}"}
        symbolic_hex = str(witness.solver_model.get("symbolic_buffer_hex") or "")
        if symbolic_hex:
            return {"input_model": witness.input_model, "input_hex": symbolic_hex, "source": "function_harness"}
    replay = verdict.replay_result.get("concrete_angr_replay") if isinstance(verdict.replay_result, Mapping) else {}
    if isinstance(replay, Mapping) and replay.get("input_hex"):
        return {"input_model": str(replay.get("input_model") or ""), "input_hex": str(replay.get("input_hex")), "source": "replay"}
    proof = verdict.ghidra_dynamic_proof
    if isinstance(proof, Mapping):
        harness = proof.get("harness_model") if isinstance(proof.get("harness_model"), Mapping) else {}
        if harness.get("concrete_input_hex"):
            return {
                "input_model": str(harness.get("input_model") or ""),
                "input_hex": str(harness.get("concrete_input_hex") or ""),
                "source": "ghidra_dynamic_proof",
            }
    return {"input_model": "", "input_hex": "", "source": ""}


def _native_replay_not_run() -> dict[str, str]:
    return {
        "status": "not_run",
        "reason": "Native, QEMU, and device replay are out of scope for this pipeline stage.",
    }


def _native_replay_refutes_memory_proof(replay: Mapping[str, Any]) -> bool:
    if str(replay.get("status") or "") != "replayed":
        return False
    stderr = str(replay.get("stderr_tail") or "").lower()
    return "buffer overflow detected" in stderr or "fortify" in stderr


def _promote_ghidra_process_overflow_verdict(
    request: ConcolicRequest,
    verdict: ConcolicVerdict,
    proof: Mapping[str, Any],
) -> ConcolicVerdict:
    proof_status = str(proof.get("status") or "")
    if _has_decisive_dynamic_process_result(proof) and proof_status in {
        "no_overflow",
        "no_oob_read",
        "no_lifetime_violation",
    }:
        relational = proof.get("relational_safety_proof") if isinstance(proof.get("relational_safety_proof"), Mapping) else {}
        if proof_status == "no_overflow" and relational.get("status") == "proven_safe" and relational.get("all_paths_proven"):
            return replace(
                verdict,
                verdict="guard_refuted",
                rationale=(
                    "Ghidra replay reached the exact process sink and observed no overflow; "
                    "the shared static relation proves allocation >= offset + write size on every recovered path."
                ),
                reached_addresses=tuple(
                    _unique_strings([*verdict.reached_addresses, _normalize_address(request.target_address), _normalize_address(request.sink_address)])
                ),
                logs=tuple(_unique_strings([*verdict.logs, "relational_allocation_write_guard_refuted"])),
            )
        return replace(
            verdict,
            verdict="target_reached",
            rationale=(
                f"Ghidra process replay reached the exact sink with concrete {request.input_model} input; "
                f"the modeled operation concluded {proof_status}."
            ),
            reached_addresses=tuple(
                _unique_strings(
                    [
                        *verdict.reached_addresses,
                        _normalize_address(request.target_address),
                        _normalize_address(request.sink_address),
                    ]
                )
            ),
            logs=tuple(_unique_strings([*verdict.logs, "ghidra_dynamic_exact_sink_result"])),
        )
    if not _has_dynamic_memory_safety_proof(proof):
        return verdict
    promoted_verdict = (
        "memory_violation_witness"
        if str(proof.get("status") or "") == "lifetime_violation_proven"
        else "overflow_witness"
    )
    if verdict.verdict == promoted_verdict:
        return verdict
    proof_scope = str(proof.get("proof_scope") or "")
    addresses = _unique_strings(
        [
            *verdict.reached_addresses,
            _normalize_address(request.target_address),
            _normalize_address(request.sink_address),
        ]
    )
    scope_label = "process" if proof_scope == "process_entrypoint" else proof_scope or "dynamic"
    rationale = f"Ghidra {scope_label} proof reached the exact sink with concrete {request.input_model} input and proved a memory-safety violation."
    if verdict.rationale:
        rationale = f"{rationale} Original {verdict.backend} verdict was {verdict.verdict}: {verdict.rationale}"
    return replace(
        verdict,
        verdict=promoted_verdict,
        rationale=rationale,
        reached_addresses=tuple(addresses),
        logs=tuple(_unique_strings([*verdict.logs, "ghidra_dynamic_proof_promoted_verdict"])),
    )


def _native_process_replay(
    request: ConcolicRequest,
    verdict: ConcolicVerdict,
    proof: Mapping[str, Any],
) -> dict[str, Any]:
    if str(proof.get("proof_scope") or "") != "process_entrypoint":
        return _native_replay_not_run()
    if request.input_model not in PROCESS_DYNAMIC_INPUT_MODELS:
        payload = _native_replay_not_run()
        payload["reason"] = f"unsupported_native_replay_input_model:{request.input_model}"
        return payload
    concrete = _concrete_input_from_verdict(verdict)
    input_hex = str(concrete.get("input_hex") or "")
    input_source = str(concrete.get("source") or "ghidra_dynamic_proof")
    if request.input_model in {"stdin", "argv_file_stdin"}:
        proof_request = proof.get("request") if isinstance(proof.get("request"), Mapping) else {}
        process_setup = proof.get("process_input_setup") if isinstance(proof.get("process_input_setup"), Mapping) else {}
        configured_stdin_hex = str(
            proof_request.get("stdin_input_hex")
            or process_setup.get("stdin_input_hex")
            or ""
        )
        if configured_stdin_hex:
            input_hex = configured_stdin_hex
            input_source = "ghidra_process_input_setup"
    if not input_hex:
        harness = proof.get("harness_model") if isinstance(proof.get("harness_model"), Mapping) else {}
        input_hex = str(harness.get("concrete_input_hex") or "")
    try:
        input_bytes = bytes.fromhex(input_hex)
    except ValueError:
        payload = _native_replay_not_run()
        payload["reason"] = "native_replay_invalid_concrete_input_hex"
        return payload
    binary_path = Path(request.binary_path)
    if not binary_path.exists() or not binary_path.is_file():
        payload = _native_replay_not_run()
        payload["reason"] = "native_replay_binary_missing"
        return payload
    timeout = max(1.0, min(float(request.timeout_seconds or 5.0), 10.0))
    if request.input_model in {"socket_service", "http_daemon"}:
        return _native_service_replay(request, proof, input_bytes, input_hex, timeout)
    command: list[Any]
    run_kwargs: dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "timeout": timeout,
        "check": False,
    }
    if request.input_model == "argv":
        if b"\x00" in input_bytes:
            payload = _native_replay_not_run()
            payload["reason"] = "native_replay_argv_contains_nul"
            return payload
        command = [os.fsencode(str(binary_path)), input_bytes]
        completed = _run_native_replay_command(command, run_kwargs, request.input_model, input_hex, proof, timeout)
    elif request.input_model == "stdin":
        command = [str(binary_path), *_combined_argv_args_from_proof(proof, "")]
        run_kwargs["input"] = input_bytes
        completed = _run_native_replay_command(command, run_kwargs, request.input_model, input_hex, proof, timeout)
    elif request.input_model == "file":
        with tempfile.TemporaryDirectory(prefix="binary_agent_native_file_") as replay_dir:
            replay_file = Path(replay_dir) / "concolic_input"
            replay_file.write_bytes(input_bytes)
            command = [str(binary_path), "concolic_input"]
            run_kwargs["cwd"] = replay_dir
            completed = _run_native_replay_command(command, run_kwargs, request.input_model, input_hex, proof, timeout)
    elif request.input_model == "env_file":
        proof_request = proof.get("request") if isinstance(proof.get("request"), Mapping) else {}
        file_name = _combined_file_name_from_proof(proof)
        env_name = _native_env_name_from_proof(proof)
        env_values = {
            str(key): str(value)
            for key, value in dict(proof_request.get("env_values") or {}).items()
        }
        if not file_name or not env_name:
            payload = _native_replay_not_run()
            payload["reason"] = "native_replay_env_file_setup_unavailable"
            return payload
        with tempfile.TemporaryDirectory(prefix="binary_agent_native_env_file_") as replay_dir:
            replay_file = Path(replay_dir) / file_name
            replay_file.write_bytes(input_bytes)
            env_values[env_name] = replay_dir
            command = [str(binary_path), *_combined_argv_args_from_proof(proof, file_name)]
            run_kwargs["cwd"] = replay_dir
            run_kwargs["env"] = {**os.environ, **env_values}
            completed = _run_native_replay_command(command, run_kwargs, request.input_model, input_hex, proof, timeout)
    elif request.input_model == "argv_file_stdin":
        file_name = _combined_file_name_from_proof(proof)
        file_bytes = _combined_file_bytes_from_proof(proof)
        if not file_name or not file_bytes:
            payload = _native_replay_not_run()
            payload["reason"] = "native_replay_combined_file_input_unavailable"
            return payload
        with tempfile.TemporaryDirectory(prefix="binary_agent_native_argv_file_stdin_") as replay_dir:
            replay_file = Path(replay_dir) / file_name
            replay_file.write_bytes(file_bytes)
            command = [str(binary_path), *_combined_argv_args_from_proof(proof, file_name)]
            run_kwargs["cwd"] = replay_dir
            run_kwargs["input"] = input_bytes
            completed = _run_native_replay_command(command, run_kwargs, request.input_model, input_hex, proof, timeout)
    elif request.input_model == "argv_directory":
        directory_name = _combined_file_name_from_proof(proof)
        if not directory_name:
            payload = _native_replay_not_run()
            payload["reason"] = "native_replay_directory_name_unavailable"
            return payload
        if b"\x00" in input_bytes or b"/" in input_bytes:
            payload = _native_replay_not_run()
            payload["reason"] = "native_replay_directory_entry_invalid"
            return payload
        entry_name = input_bytes[:255]
        with tempfile.TemporaryDirectory(prefix="binary_agent_native_argv_directory_") as replay_dir:
            directory_path = Path(replay_dir) / directory_name
            try:
                directory_path.mkdir(parents=True, exist_ok=True)
                (directory_path / entry_name.decode("utf-8", errors="ignore")).write_bytes(b"")
            except OSError as exc:
                payload = _native_replay_not_run()
                payload["reason"] = f"native_replay_directory_setup_failed:{exc}"
                return payload
            command = [str(binary_path), *_combined_argv_args_from_proof(proof, directory_name)]
            run_kwargs["cwd"] = replay_dir
            completed = _run_native_replay_command(command, run_kwargs, request.input_model, input_hex, proof, timeout)
    else:
        env_name = _native_env_name_from_proof(proof)
        if not env_name:
            payload = _native_replay_not_run()
            payload["reason"] = "native_replay_env_name_unavailable"
            return payload
        if b"\x00" in input_bytes:
            payload = _native_replay_not_run()
            payload["reason"] = "native_replay_env_contains_nul"
            return payload
        command = [str(binary_path)]
        run_kwargs["env"] = {**os.environ, env_name: os.fsdecode(input_bytes)}
        completed = _run_native_replay_command(command, run_kwargs, request.input_model, input_hex, proof, timeout)
    if isinstance(completed, Mapping):
        return dict(completed)
    stdout_tail = _bytes_tail(completed.stdout)
    stderr_tail = _bytes_tail(completed.stderr)
    signal_name = _native_signal_name(completed.returncode)
    violation = proof.get("lifetime_violation") if isinstance(proof.get("lifetime_violation"), Mapping) else {}
    lifetime_vulnerability = str(violation.get("vulnerability") or "")
    native_text = f"{stdout_tail}\n{stderr_tail}".lower()
    lifetime_marker = any(
        marker in native_text
        for marker in ("double free", "invalid pointer", "addresssanitizer", "use-after-free", "heap-use-after-free")
    )
    exact_operation_trace = _native_exact_operation_trace(request, proof, input_bytes, timeout)
    return {
        "status": "replayed",
        "input_model": request.input_model,
        "input_hex": input_hex,
        "input_source": input_source,
        "argv_index": 1 if request.input_model == "argv" else None,
        "file_name": _native_replay_file_name(request, proof),
        "env_name": _native_env_name_from_proof(proof) if request.input_model in {"env", "env_file"} else "",
        "returncode": int(completed.returncode),
        "nonzero_exit_observed": completed.returncode != 0,
        "signal": signal_name,
        "crash_observed": bool(signal_name or lifetime_marker),
        "lifetime_event_observed": bool(lifetime_vulnerability and (signal_name or lifetime_marker)),
        "lifetime_vulnerability": lifetime_vulnerability,
        "stdout_tail": stdout_tail,
        "stderr_tail": stderr_tail,
        "proof_correlation": _native_replay_proof_correlation(proof),
        "exact_operation_trace": exact_operation_trace,
    }


def _native_exact_operation_trace(
    request: ConcolicRequest,
    proof: Mapping[str, Any],
    stdin_bytes: bytes,
    timeout: float,
) -> dict[str, Any]:
    """Use an optional local debugger to bind concrete process execution to one PIE operation."""
    if request.input_model not in {"argv", "stdin", "argv_file_stdin"}:
        return {"status": "not_run", "reason": f"unsupported_exact_trace_input_model:{request.input_model}"}
    gdb = shutil.which("gdb")
    if not gdb:
        return {"status": "not_run", "reason": "gdb_unavailable"}
    if request.export_dir is None:
        return {"status": "not_run", "reason": "exact_trace_export_unavailable"}
    binary = Path(request.binary_path).expanduser().resolve()
    image_base = _export_image_base(Path(request.export_dir))
    sink_address = _safe_int(request.sink_address, default=0)
    if not binary.is_file() or sink_address <= image_base:
        return {"status": "not_run", "reason": "exact_trace_address_unavailable"}
    helper = Path(__file__).resolve().parents[3] / "scripts" / "gdb_exact_memory_trace.py"
    if not helper.is_file():
        return {"status": "not_run", "reason": "native_exact_trace_helper_unavailable"}
    file_name = _combined_file_name_from_proof(proof) if request.input_model == "argv_file_stdin" else ""
    file_bytes = _combined_file_bytes_from_proof(proof) if file_name else b""
    if request.input_model == "argv_file_stdin" and (
        not file_name or not file_bytes or Path(file_name).name != file_name
    ):
        return {"status": "not_run", "reason": "exact_trace_file_input_unavailable"}
    relative_address = sink_address - image_base
    with tempfile.TemporaryDirectory(prefix="binary_agent_native_exact_") as replay_dir:
        if file_name:
            (Path(replay_dir) / file_name).write_bytes(file_bytes)
        argv = _combined_argv_args_from_proof(proof, file_name)
        command = [
            gdb,
            "-q",
            "-nx",
            "-batch",
            "-ex",
            "set pagination off",
            "-ex",
            "set confirm off",
            "-ex",
            "set debuginfod enabled off",
            "-ex",
            "starti",
            "-x",
            str(helper),
            "--args",
            str(binary),
            *argv,
        ]
        environment = {
            **os.environ,
            "BINARY_AGENT_BINARY": str(binary),
            "BINARY_AGENT_RELATIVE_ADDRESS": hex(relative_address),
            "BINARY_AGENT_STATIC_ADDRESS": hex(sink_address),
            "BINARY_AGENT_SOURCE_ROOT": str(Path(__file__).resolve().parents[2]),
        }
        proof_request = proof.get("request") if isinstance(proof.get("request"), Mapping) else {}
        vulnerability_type = str(proof_request.get("vulnerability_type") or "")
        try:
            proof_backend = get_vulnerability_spec(vulnerability_type).backend
        except (KeyError, ValueError):
            proof_backend = ""
        track_allocations = proof_backend in {"memory_access", "memory_lifetime"}
        environment["BINARY_AGENT_TRACK_ALLOCATIONS"] = "1" if track_allocations else "0"
        environment["BINARY_AGENT_TRACK_RESOURCES"] = "1" if proof_backend == "memory_lifetime" else "0"
        environment["BINARY_AGENT_CONTINUE_AFTER_EXACT"] = "1" if proof_backend == "semantic_effect" else "0"
        environment["BINARY_AGENT_VULNERABILITY_TYPE"] = vulnerability_type
        environment["BINARY_AGENT_OPERATION_NAME"] = str(
            proof_request.get("sink_name") or proof.get("sink_name") or ""
        )
        environment["BINARY_AGENT_PROCESS_WIDE_DUPLICATE_CONTROL"] = "0"
        try:
            completed = subprocess.run(
                command,
                cwd=replay_dir,
                env=environment,
                input=stdin_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=max(1.0, min(timeout, 20.0)),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "status": "timeout",
                "reason": "native_exact_trace_timeout",
                "stdout_tail": _bytes_tail(exc.stdout),
                "stderr_tail": _bytes_tail(exc.stderr),
            }
        except OSError as exc:
            return {"status": "not_run", "reason": f"native_exact_trace_failed:{exc}"}
    stdout = bytes(completed.stdout or b"").decode("utf-8", errors="replace")
    stderr = bytes(completed.stderr or b"").decode("utf-8", errors="replace")
    traced = _parse_native_memory_trace(stdout, stderr)
    common = {
        "relative_address": f"0x{relative_address:X}",
        "returncode": int(completed.returncode),
        "stdout_tail": _bytes_tail(completed.stdout),
        "stderr_tail": _bytes_tail(completed.stderr),
    }
    if traced:
        return {**traced, **common}
    return {"status": "unreached", "operation_address": "", **common}


def _parse_native_memory_trace(*transcripts: str) -> dict[str, Any]:
    prefix = "BINARY_AGENT_EXACT_MEMORY="
    for transcript in transcripts:
        for line in reversed(str(transcript or "").splitlines()):
            if prefix not in line:
                continue
            raw = line.split(prefix, 1)[1].strip()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, Mapping) and payload.get("status") == "reached":
                return dict(payload)
    return {}


def _export_image_base(export_dir: Path) -> int:
    for name in ("manifest_normalized.json", "manifest.json"):
        path = Path(export_dir) / name
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text() or "{}")
        except (OSError, json.JSONDecodeError):
            continue
        value = _safe_int(payload.get("image_base"), default=0) if isinstance(payload, Mapping) else 0
        if value >= 0:
            return value
    return 0


def _native_service_replay(
    request: ConcolicRequest,
    proof: Mapping[str, Any],
    payload: bytes,
    input_hex: str,
    timeout: float,
) -> dict[str, Any]:
    proof_request = proof.get("request") if isinstance(proof.get("request"), Mapping) else {}
    evidence = proof_request.get("process_input_evidence") if isinstance(proof_request.get("process_input_evidence"), Mapping) else {}
    if not evidence:
        raw_evidence = str(proof_request.get("process_input_evidence_json") or "")
        try:
            parsed_evidence = json.loads(raw_evidence) if raw_evidence else {}
        except json.JSONDecodeError:
            parsed_evidence = {}
        evidence = parsed_evidence if isinstance(parsed_evidence, Mapping) else {}
    host = str(evidence.get("host") or "127.0.0.1")
    port = _safe_int(evidence.get("port"), default=0)
    if port <= 0:
        result = _native_replay_not_run()
        result["reason"] = "native_service_replay_missing_port"
        return result
    command = [str(request.binary_path)]
    port_arg = evidence.get("port_arg")
    if port_arg:
        command.append(str(port))
    env = dict(os.environ)
    port_env = str(evidence.get("port_env") or "")
    if port_env:
        env[port_env] = str(port)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    request_bytes = _native_service_request_bytes(request.input_model, payload)
    response = b""
    deadline = time.monotonic() + timeout
    connected = False
    last_error = ""
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                with socket.create_connection((host, port), timeout=min(0.2, max(0.05, deadline - time.monotonic()))) as client:
                    connected = True
                    client.sendall(request_bytes)
                    try:
                        client.shutdown(socket.SHUT_WR)
                        client.settimeout(0.2)
                        response = client.recv(4096)
                    except OSError:
                        pass
                break
            except OSError as exc:
                last_error = str(exc)
                time.sleep(0.02)
        remaining = max(0.05, deadline - time.monotonic())
        stdout, stderr = process.communicate(timeout=remaining)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return {
            "status": "timeout",
            "reason": "native_service_replay_timeout",
            "input_model": request.input_model,
            "host": host,
            "port": port,
            "connected": connected,
            "input_hex": input_hex,
            "stdout_tail": _bytes_tail(stdout),
            "stderr_tail": _bytes_tail(stderr),
            "proof_correlation": _native_replay_proof_correlation(proof),
        }
    returncode = int(process.returncode or 0)
    stdout_tail = _bytes_tail(stdout)
    stderr_tail = _bytes_tail(stderr)
    signal_name = _native_signal_name(returncode)
    text = f"{stdout_tail}\n{stderr_tail}".lower()
    crash_observed = bool(signal_name or "stack smashing" in text or "buffer overflow" in text)
    return {
        "status": "replayed" if connected else "blocked",
        "reason": "" if connected else f"native_service_replay_connect_failed:{last_error}",
        "input_model": request.input_model,
        "host": host,
        "port": port,
        "connected": connected,
        "input_hex": input_hex,
        "request_size_bytes": len(request_bytes),
        "response_size_bytes": len(response),
        "returncode": returncode,
        "signal": signal_name,
        "crash_observed": crash_observed,
        "stdout_tail": stdout_tail,
        "stderr_tail": stderr_tail,
        "proof_correlation": _native_replay_proof_correlation(proof),
    }


def _native_service_request_bytes(input_model: str, payload: bytes) -> bytes:
    if input_model != "http_daemon":
        return payload
    if payload.startswith((b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ")) and b"HTTP/" in payload:
        return payload
    path_payload = bytes(value for value in payload if value not in (0, 10, 13, 32))
    return b"GET /" + path_payload + b" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"


def _native_replay_file_name(request: ConcolicRequest, proof: Mapping[str, Any]) -> str:
    if request.input_model == "file":
        return "concolic_input"
    if request.input_model in {"env_file", "argv_file_stdin"}:
        return _combined_file_name_from_proof(proof)
    return ""


def _combined_file_name_from_proof(proof: Mapping[str, Any]) -> str:
    setup = proof.get("process_input_setup") if isinstance(proof.get("process_input_setup"), Mapping) else {}
    request = proof.get("request") if isinstance(proof.get("request"), Mapping) else {}
    return str(setup.get("file_name") or request.get("file_name") or "concolic_input")


def _combined_argv_args_from_proof(proof: Mapping[str, Any], file_name: str) -> list[str]:
    request = proof.get("request") if isinstance(proof.get("request"), Mapping) else {}
    values = [str(item) for item in _coerce_sequence(request.get("argv_values")) if str(item)]
    if not values:
        setup = proof.get("process_input_setup") if isinstance(proof.get("process_input_setup"), Mapping) else {}
        values = [str(item) for item in _coerce_sequence(setup.get("argv_values")) if str(item)] if isinstance(setup, Mapping) else []
    if not values:
        return [file_name] if file_name else []
    return values[1:] if values[0] in {"program", "$program", "${program}"} else values


def _combined_file_bytes_from_proof(proof: Mapping[str, Any]) -> bytes:
    request = proof.get("request") if isinstance(proof.get("request"), Mapping) else {}
    file_hex = str(request.get("file_input_hex") or "")
    if file_hex:
        try:
            return bytes.fromhex(file_hex)
        except ValueError:
            return b""
    return b""


def _native_env_name_from_proof(proof: Mapping[str, Any]) -> str:
    setup = proof.get("process_input_setup") if isinstance(proof.get("process_input_setup"), Mapping) else {}
    name = str(setup.get("env_name") or "CONCOLIC_INPUT").strip() if isinstance(setup, Mapping) else "CONCOLIC_INPUT"
    if not name or "=" in name or "\x00" in name:
        return ""
    return name


def _run_native_replay_command(
    command: Sequence[Any],
    run_kwargs: Mapping[str, Any],
    input_model: str,
    input_hex: str,
    proof: Mapping[str, Any],
    timeout: float,
) -> Any:
    try:
        return subprocess.run(list(command), **dict(run_kwargs))
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "timeout",
            "reason": "native_replay_timeout",
            "input_model": input_model,
            "input_hex": input_hex,
            "timeout_seconds": timeout,
            "stdout_tail": _bytes_tail(exc.stdout),
            "stderr_tail": _bytes_tail(exc.stderr),
            "proof_correlation": _native_replay_proof_correlation(proof),
        }
    except Exception as exc:
        payload = _native_replay_not_run()
        payload["reason"] = f"native_replay_failed:{exc}"
        return payload


def _native_replay_proof_correlation(proof: Mapping[str, Any]) -> dict[str, Any]:
    process_replay = proof.get("process_replay") if isinstance(proof.get("process_replay"), Mapping) else {}
    return {
        "ghidra_dynamic_proof_status": str(proof.get("status") or ""),
        "proof_scope": str(proof.get("proof_scope") or ""),
        "process_replay_status": str(process_replay.get("status") or ""),
        "sink_address": _normalize_address(proof.get("sink_address")),
    }


def _native_signal_name(returncode: int) -> str:
    if returncode >= 0:
        return ""
    try:
        import signal

        return signal.Signals(-returncode).name
    except Exception:
        return f"signal_{-returncode}"


def _bytes_tail(value: Any, *, limit: int = 4096) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value[-limit:]
    try:
        data = bytes(value)
    except Exception:
        return str(value)[-limit:]
    return data[-limit:].decode("utf-8", errors="replace")


def _image_base_from_export(export_dir: Path | None) -> int:
    if export_dir is None:
        return 0
    path = Path(export_dir) / "manifest_normalized.json"
    if not path.exists():
        return 0
    try:
        payload = json.loads(path.read_text() or "{}")
    except json.JSONDecodeError:
        return 0
    try:
        return int(payload.get("image_base", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _concolic_verdict_from_payload(payload: Mapping[str, Any]) -> ConcolicVerdict:
    entries = concolic_verdict_entries(payload)
    if not entries:
        raise ValueError("No concolic verdict found in payload")
    return ConcolicVerdict.from_dict(entries[0][1])


def _candidate_id_from_pack(evidence_pack: Mapping[str, Any]) -> str:
    candidate_id = str(evidence_pack.get("candidate_id") or "")
    if candidate_id:
        return candidate_id
    return str(_candidate(evidence_pack).get("candidate_id") or "")


def _candidate(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    candidate = evidence_pack.get("deterministic_candidate")
    return candidate if isinstance(candidate, Mapping) else {}


def _candidate_for_memory_proof(
    evidence_pack: Mapping[str, Any],
    *,
    export_dir: Path | None = None,
) -> Mapping[str, Any]:
    candidate = _candidate(evidence_pack)
    if not _declared_stack_array_capacity_is_stale(evidence_pack, candidate, export_dir=export_dir):
        return candidate
    updated = dict(candidate)
    target = str(updated.get("target_buffer") or updated.get("source_object") or "memory_object")
    original_capacity = _safe_int(updated.get("capacity_bytes"), default=0)
    original_source = str(updated.get("capacity_source") or "declared_local_array")
    updated["capacity_bytes"] = 0
    updated["capacity_source"] = "direct_object_extent_unknown"
    updated["capacity_basis"] = (
        f"{target}: direct object extent unknown; stale {original_capacity}-byte "
        f"{original_source} extent is not proof-grade"
    )
    model = dict(updated.get("capacity_model") or {}) if isinstance(updated.get("capacity_model"), Mapping) else {}
    model.update(
        {
            "fixed_bytes": None,
            "symbolic_expr": f"object_extent({target})",
            "source": "direct_object_extent_unknown",
            "trust": "unknown",
        }
    )
    updated["capacity_model"] = model
    if str(updated.get("write_relation") or "") == "proven_overflow":
        updated["write_relation"] = "symbolic_capacity"
    if str(updated.get("verdict") or "") == "overflow":
        updated["verdict"] = "candidate"
    sources = [str(item) for item in _coerce_sequence(updated.get("evidence_sources", [])) if str(item)]
    if "direct_object_extent_unknown" not in sources:
        sources.append("direct_object_extent_unknown")
    if sources:
        updated["evidence_sources"] = sources
    return updated


def _declared_stack_array_capacity_is_stale(
    evidence_pack: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    export_dir: Path | None = None,
) -> bool:
    static_candidate = _static_candidate(evidence_pack)
    capacity_model = _candidate_capacity_model(evidence_pack)
    destination_kind = str(
        candidate.get("destination_kind")
        or static_candidate.get("destination_kind")
        or _facts(evidence_pack).get("destination_kind")
        or ""
    ).lower()
    if "stack" not in destination_kind:
        return False
    capacity_source = str(
        candidate.get("capacity_source")
        or static_candidate.get("capacity_source")
        or capacity_model.get("source")
        or _facts(evidence_pack).get("capacity_source")
        or ""
    ).lower()
    if capacity_source != "declared_local_array":
        return False
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    if capacity <= 0:
        return False
    target = _root_identifier(str(candidate.get("target_buffer") or candidate.get("source_object") or ""))
    if not target:
        return False
    declaration = _declared_array_for_candidate_target(evidence_pack, target, export_dir=export_dir)
    if declaration is None:
        return False
    element_type, element_count = declaration
    return element_count == capacity and not _declared_array_element_is_byte_storage(element_type)


def _root_identifier(expr: str) -> str:
    match = re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\b", str(expr or ""))
    return match.group(0) if match else ""


def _declared_array_for_candidate_target(
    evidence_pack: Mapping[str, Any],
    target: str,
    *,
    export_dir: Path | None = None,
) -> tuple[str, int] | None:
    source_text = _candidate_decompiled_text_for_capacity(evidence_pack, export_dir=export_dir)
    if not source_text:
        return None
    name_pattern = re.escape(target)
    pattern = re.compile(
        rf"(?P<type>[A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*)\s+"
        rf"{name_pattern}\s*\[\s*(?P<count>0x[0-9a-fA-F]+|\d+)\s*\]"
    )
    for match in pattern.finditer(source_text):
        count = _safe_int(match.group("count"), default=0)
        if count > 0:
            return match.group("type"), count
    return None


def _candidate_decompiled_text_for_capacity(
    evidence_pack: Mapping[str, Any],
    *,
    export_dir: Path | None = None,
) -> str:
    export_dirs: list[Path] = []
    if export_dir is not None and Path(export_dir).exists():
        export_dirs.append(Path(export_dir))
    export_dirs.extend(path for path in _process_export_dirs(evidence_pack) if path not in export_dirs)
    groups = _combined_process_decompile_identifier_groups(evidence_pack)
    for candidate_export_dir in export_dirs:
        for names, address_tokens in groups:
            for path in _candidate_decompile_paths(candidate_export_dir, names, address_tokens)[:4]:
                try:
                    return path.read_text(errors="replace")[:512 * 1024]
                except OSError:
                    continue
    return ""


def _declared_array_element_is_byte_storage(type_text: str) -> bool:
    lowered = re.sub(r"\s+", " ", str(type_text or "").strip().lower())
    if not lowered or "*" in lowered:
        return False
    tokens = [
        token
        for token in lowered.split()
        if token not in {"const", "volatile", "register", "static", "extern", "signed", "unsigned"}
    ]
    canonical = " ".join(tokens)
    return canonical in {
        "byte",
        "char",
        "guint8",
        "int8_t",
        "schar",
        "uchar",
        "uint8",
        "uint8_t",
        "undefined",
        "undefined1",
    }


def _facts(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    facts = evidence_pack.get("facts_available_to_llm")
    return facts if isinstance(facts, Mapping) else {}


def _normalize_concolic_input_model(input_model: str) -> str:
    model = str(input_model or "").strip()
    return CONCOLIC_INPUT_MODEL_ALIASES.get(model, model)


def _declared_process_input_model(evidence_pack: Mapping[str, Any]) -> str:
    facts = _facts(evidence_pack)
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    for value in (
        evidence_pack.get("process_input"),
        type_facts.get("process_input"),
        facts.get("process_input"),
        type_facts.get("source_to_sink_trace"),
        facts.get("source_to_sink_trace"),
        evidence_pack.get("replay_hypothesis"),
    ):
        if not isinstance(value, Mapping):
            continue
        model = _normalize_concolic_input_model(str(value.get("input_model") or ""))
        if model in KNOWN_PROCESS_INPUT_MODELS:
            return model
    return ""


def _explicit_process_input_model(evidence_pack: Mapping[str, Any]) -> str:
    """Return only a concrete process-input fact, excluding inferred traces."""

    facts = _facts(evidence_pack)
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    for value in (
        evidence_pack.get("process_input"),
        type_facts.get("process_input"),
        facts.get("process_input"),
    ):
        if not isinstance(value, Mapping):
            continue
        model = _normalize_concolic_input_model(str(value.get("input_model") or ""))
        if model in KNOWN_PROCESS_INPUT_MODELS and value.get("inferred") is not True:
            return model
    return ""


def _default_input_model(
    evidence_pack: Mapping[str, Any],
    *,
    target_resolution: Mapping[str, Any] | None = None,
) -> str:
    trace = _candidate_classification_trace(evidence_pack)
    replay_hints = trace.get("replay_hints") if isinstance(trace.get("replay_hints"), Mapping) else {}
    if str(replay_hints.get("mode") or "").lower() == "function_harness":
        return "function_harness"
    # A schema-v2 process-input fact is an explicit concrete setup supplied by
    # the caller.  It must take precedence over observations such as getenv in
    # the entry function, which describe ambient inputs but not necessarily the
    # witness that reaches this candidate.
    explicit_model = _explicit_process_input_model(evidence_pack)
    if explicit_model:
        return _effective_process_input_model(evidence_pack, explicit_model)
    derived_semantic_model = _derived_semantic_process_input_model(evidence_pack, target_resolution=target_resolution)
    candidate_linked_model = _candidate_linked_file_input_model(
        evidence_pack,
        base_model=derived_semantic_model,
    )
    if candidate_linked_model:
        return candidate_linked_model
    if derived_semantic_model:
        return _effective_process_input_model(evidence_pack, derived_semantic_model)
    semantic_model = _semantic_process_input_model(evidence_pack, target_resolution=target_resolution)
    if _is_semantic_process_candidate(evidence_pack) and not semantic_model:
        return "function_harness"
    facts = _facts(evidence_pack)
    reproducer = facts.get("reproducer_hypothesis") if isinstance(facts.get("reproducer_hypothesis"), Mapping) else {}
    surface = str(reproducer.get("input_surface") or "").lower()
    if _memory_candidate_prefers_function_harness(evidence_pack):
        return "function_harness"
    if surface == "function_harness" and semantic_model:
        return semantic_model
    if "stdin" in surface:
        return "stdin"
    if "env" in surface or "environment" in surface or "getenv" in surface:
        return "env"
    if "cli" in surface or "argv" in surface or "argument" in surface:
        return "argv"
    if "file" in surface or "fd" in surface:
        return "file"
    if "http" in surface:
        return "http"
    if "socket" in surface or "network" in surface or "tcp" in surface or "udp" in surface:
        return "network"
    if "ipc" in surface or "message queue" in surface or "unix domain" in surface:
        return "ipc"
    if "config" in surface or "nvram" in surface or "setting" in surface:
        return "config"
    if "device" in surface or "ioctl" in surface or "/dev/" in surface:
        return "device"
    if "daemon" in surface or "service" in surface or "protocol" in surface:
        return "daemon"
    if semantic_model:
        return _effective_process_input_model(evidence_pack, semantic_model)
    return "function_harness" if surface else _effective_process_input_model(evidence_pack, "argv")


def _memory_candidate_prefers_function_harness(evidence_pack: Mapping[str, Any]) -> bool:
    if _is_semantic_process_candidate(evidence_pack):
        return False
    candidate = _candidate(evidence_pack)
    if not _normalize_address(candidate.get("address")):
        return False
    destination = str(candidate.get("destination_kind") or "").lower()
    if "heap" not in destination and "source_buffer" not in destination:
        return False
    relation = str(candidate.get("write_relation") or "")
    verdict = str(candidate.get("verdict") or "")
    proof = evidence_pack.get("proof_obligation") if isinstance(evidence_pack.get("proof_obligation"), Mapping) else {}
    proof_relation = str(proof.get("relation") or "")
    return bool(
        relation in {"proven_overflow", "proven_oob_read", "unbounded", "symbolic_size", "symbolic_offset", "symbolic_read_offset"}
        or verdict in {"overflow", "unbounded", "oob_read_proven"}
        or proof_relation in {"proven_overflow", "proven_oob_read", "unbounded", "symbolic_size", "symbolic_offset", "symbolic_read_offset"}
    )


def _default_target_address(
    evidence_pack: Mapping[str, Any],
    *,
    target_resolution: Mapping[str, Any] | None = None,
) -> str:
    resolution = target_resolution if isinstance(target_resolution, Mapping) else {}
    resolved_target = _normalize_address(resolution.get("target_address"))
    if resolved_target:
        return resolved_target
    candidate = _candidate(evidence_pack)
    for key in ("operation_address", "address"):
        address = _normalize_address(candidate.get(key))
        if address:
            return address
    facts = _facts(evidence_pack)
    for row in _coerce_sequence(facts.get("write_table", [])):
        if isinstance(row, Mapping):
            address = _normalize_address(row.get("operation_address"))
            if address:
                return address
    return ""


def _allowed_addresses(
    evidence_pack: Mapping[str, Any],
    *,
    export_dir: Path | None = None,
    target_resolution: Mapping[str, Any] | None = None,
) -> set[str]:
    addresses: set[str] = set()
    resolution = target_resolution if isinstance(target_resolution, Mapping) else {}
    if not resolution and export_dir is not None:
        resolution = _semantic_concolic_target_resolution(evidence_pack, export_dir=export_dir)
    if not resolution and export_dir is not None:
        resolution = _memory_safety_concolic_target_resolution(evidence_pack, export_dir=export_dir)
    for key in ("target_address", "sink_address", "callsite_address", "callee_address", "function_address"):
        address = _normalize_address(resolution.get(key))
        if address:
            addresses.add(address)
    candidate = _candidate(evidence_pack)
    for key in ("address", "operation_address"):
        address = _normalize_address(candidate.get(key))
        if address:
            addresses.add(address)
    facts = _facts(evidence_pack)
    for row in _coerce_sequence(facts.get("write_table", [])):
        if isinstance(row, Mapping):
            address = _normalize_address(row.get("operation_address") or row.get("address"))
            if address:
                addresses.add(address)
    pcode_slice = facts.get("pcode_slice") if isinstance(facts.get("pcode_slice"), Mapping) else {}
    address = _normalize_address(pcode_slice.get("operation_address"))
    if address:
        addresses.add(address)
    for key in ("exact_sink_address", "llm_exact_sink_address"):
        address = _normalize_address(facts.get(key))
        if address:
            addresses.add(address)
    for catalog_key in ("pcode_sink_catalog", "store_catalog", "call_catalog"):
        for row in _coerce_sequence(facts.get(catalog_key, [])):
            if isinstance(row, Mapping):
                for key in ("instruction_address", "address", "target_address"):
                    address = _normalize_address(row.get(key))
                    if address:
                        addresses.add(address)
    proof = evidence_pack.get("proof_obligation")
    if isinstance(proof, Mapping):
        for ref in _coerce_sequence(proof.get("evidence_refs", [])):
            match = re.search(r"0x[0-9a-fA-F]+", str(ref))
            if match:
                addresses.add(_normalize_address(match.group(0)))
    return addresses


def _allowed_stub_names(evidence_pack: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()
    candidate_sink = str(_candidate(evidence_pack).get("sink") or "")
    if candidate_sink:
        names.add(candidate_sink)
    for value in (
        evidence_pack.get("allowed_stubs"),
        _facts(evidence_pack).get("allowed_stubs"),
    ):
        names.update(str(item) for item in _coerce_sequence(value))
    reproducer = _facts(evidence_pack).get("reproducer_hypothesis")
    if isinstance(reproducer, Mapping):
        names.update(str(item) for item in _coerce_sequence(reproducer.get("allowed_stubs", [])))
    for row in _coerce_sequence(_facts(evidence_pack).get("write_table", [])):
        if isinstance(row, Mapping):
            stub = str(row.get("stub") or "")
            if stub:
                names.add(stub)
    return {name for name in names if name}


def _default_evidence_refs(evidence_pack: Mapping[str, Any]) -> list[str]:
    refs: list[str] = []
    proof = evidence_pack.get("proof_obligation")
    if isinstance(proof, Mapping):
        refs.extend(str(item) for item in _coerce_sequence(proof.get("evidence_refs", [])))
    refs.extend(["concolic:request", "concolic:witness"])
    return _unique_strings(refs)


def _feasibility_argument(verdict: ConcolicVerdict) -> str:
    if verdict.reportable:
        return "A bounded concolic backend produced a concrete witness and Ghidra proved the exact-sink memory-safety violation."
    if verdict.verdict in SAFE_CONCOLIC_VERDICTS:
        return "A bounded concolic backend refuted the candidate path under the supplied constraints."
    return "No decisive concolic witness was produced."


def _normalize_address(value: Any) -> str:
    parsed = _parse_address(value)
    return f"0x{parsed:x}" if parsed is not None else ""


def _parse_address(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    text = str(value).strip()
    if not text:
        return None
    if not _ADDRESS_RE.match(text):
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _is_address_string(value: Any) -> bool:
    return _parse_address(value) is not None


def _bytes_from_hex(value: Any) -> bytes | None:
    text = str(value or "")
    if not text:
        return None
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def _coerce_sequence(value: Any) -> list[Any]:
    if isinstance(value, str):
        return [value] if value else []
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        return []
    return list(value)


def _unique_strings(values: Sequence[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _concolic_filename(candidate_id: str) -> str:
    return f"{_concolic_stem(candidate_id)}.json"


def _concolic_stem(candidate_id: str) -> str:
    safe = re.sub(r"[^0-9A-Za-z_.-]+", "_", candidate_id).strip("_")
    if not safe:
        safe = "candidate"
    if len(safe) > 160:
        digest = hashlib.sha1(candidate_id.encode("utf-8")).hexdigest()[:12]
        safe = f"{safe[:147].rstrip('_')}_{digest}"
    return safe
