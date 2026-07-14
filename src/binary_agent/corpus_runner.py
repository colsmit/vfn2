"""Reproducible schema-v2 vulnerable/fixed corpus orchestration."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import socket
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.capability_sweep import run_capability_sweep
from binary_agent.data.manifest import FunctionRecord, Manifest
from binary_agent.discovery import (
    load_discovery_context,
    run_discovery,
    write_discovery_candidates,
    write_discovery_metrics,
)
from binary_agent.pipeline import (
    CandidateState,
    ProofResult,
    write_candidate_states,
    write_proof_results,
)
from binary_agent.proof import dispatch_proof, proof_metrics, render_backend_finding
from binary_agent.promotion import promote_with_proof_results
from binary_agent.replay import ReplayRequest, run_replay_request
from binary_agent.taxonomy import get_vulnerability_spec
from binary_agent.utils.time import utc_timestamp


CORPUS_SCHEMA_VERSION = 2
CORPUS_MODES = frozenset({"lightweight", "full"})
LANE_ROLES = frozenset({"vulnerable", "fixed"})


@dataclass(frozen=True)
class CorpusLane:
    lane_id: str
    role: str
    comparison_group: str
    expected_positives: tuple[str, ...]
    expected_negatives: tuple[str, ...]
    allowed_blocked: tuple[str, ...]
    vulnerability_types: tuple[str, ...]
    binary: Path | None
    source: Path | None
    process_input: Path | None
    process: Mapping[str, Any]
    requires_ghidra: bool
    compiler_flags: tuple[str, ...] = ()
    compiler: str = "cc"


@dataclass(frozen=True)
class CorpusManifest:
    corpus_id: str
    path: Path
    lanes: tuple[CorpusLane, ...]
    cache_dir: Path | None = None
    proof_timeout_seconds: float = 15.0
    proof_dynamic_max_steps: int = 30000


@dataclass(frozen=True)
class CorpusLaneResult:
    lane_id: str
    role: str
    comparison_group: str
    status: str
    run_dir: str
    binary_path: str
    binary_sha256: str
    candidate_count: int
    candidate_types: Mapping[str, int]
    proof_count: int
    proof_outcomes: Mapping[str, int]
    report_count: int
    report_types: Mapping[str, int]
    duplicate_candidate_ids: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CorpusRunSummary:
    corpus_id: str
    mode: str
    output_dir: str
    accepted: bool
    lanes: tuple[CorpusLaneResult, ...]
    errors: tuple[str, ...]
    totals: Mapping[str, Any]
    pair_differential_path: str
    capability_summary_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CORPUS_SCHEMA_VERSION,
            "artifact_kind": "schema2_corpus_summary",
            **asdict(self),
            "lanes": [lane.to_dict() for lane in self.lanes],
        }


def load_corpus_manifest(path: Path) -> CorpusManifest:
    manifest_path = Path(path).expanduser().resolve()
    payload = json.loads(manifest_path.read_text() or "{}")
    if not isinstance(payload, Mapping):
        raise ValueError(f"Corpus manifest {manifest_path} must contain an object")
    if int(payload.get("schema_version", 0) or 0) != CORPUS_SCHEMA_VERSION:
        raise ValueError(f"Corpus manifest {manifest_path} must use schema v2")
    corpus_id = str(payload.get("corpus_id") or "").strip()
    if not corpus_id:
        raise ValueError(f"Corpus manifest {manifest_path} is missing corpus_id")
    raw_lanes = payload.get("lanes")
    if not isinstance(raw_lanes, list) or not raw_lanes:
        raise ValueError(f"Corpus manifest {manifest_path} must contain a non-empty lanes list")
    lanes: list[CorpusLane] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_lanes):
        if not isinstance(raw, Mapping):
            raise ValueError(f"Corpus lane {index} must be an object")
        lane_id = str(raw.get("id") or "").strip()
        if not lane_id:
            raise ValueError(f"Corpus lane {index} is missing id")
        if lane_id in seen:
            raise ValueError(f"Duplicate corpus lane id: {lane_id}")
        seen.add(lane_id)
        role = str(raw.get("role") or "").strip()
        if role not in LANE_ROLES:
            raise ValueError(f"Corpus lane {lane_id} has invalid role {role!r}")
        group = str(raw.get("comparison_group") or "").strip()
        if not group:
            raise ValueError(f"Corpus lane {lane_id} is missing comparison_group")
        positives = _vulnerability_types(raw.get("expected_positives"), lane_id, "expected_positives")
        negatives = _vulnerability_types(raw.get("expected_negatives"), lane_id, "expected_negatives")
        blocked = _vulnerability_types(raw.get("allowed_blocked"), lane_id, "allowed_blocked")
        selected = _vulnerability_types(raw.get("vulnerability_types"), lane_id, "vulnerability_types")
        if not selected:
            selected = tuple(dict.fromkeys((*positives, *negatives, *blocked)))
        if not selected:
            raise ValueError(f"Corpus lane {lane_id} must select at least one vulnerability type")
        binary = _optional_path(raw.get("binary"), manifest_path.parent)
        source = _optional_path(raw.get("source"), manifest_path.parent)
        if binary is None and source is None:
            raise ValueError(f"Corpus lane {lane_id} requires binary or source")
        for label, value in (("binary", binary), ("source", source)):
            if value is not None and not value.is_file():
                raise FileNotFoundError(f"Corpus lane {lane_id} {label} not found: {value}")
        process_input = _optional_path(raw.get("process_input"), manifest_path.parent)
        if process_input is not None and not process_input.is_file():
            raise FileNotFoundError(f"Corpus lane {lane_id} process_input not found: {process_input}")
        process = raw.get("process") if isinstance(raw.get("process"), Mapping) else {}
        compiler_flags = raw.get("compiler_flags", [])
        if not isinstance(compiler_flags, list) or not all(isinstance(item, str) for item in compiler_flags):
            raise ValueError(f"Corpus lane {lane_id} compiler_flags must be a string list")
        compiler = str(raw.get("compiler") or "cc").strip()
        if compiler not in {"cc", "c++"}:
            raise ValueError(f"Corpus lane {lane_id} compiler must be 'cc' or 'c++'")
        lanes.append(
            CorpusLane(
                lane_id=lane_id,
                role=role,
                comparison_group=group,
                expected_positives=positives,
                expected_negatives=negatives,
                allowed_blocked=blocked,
                vulnerability_types=selected,
                binary=binary,
                source=source,
                process_input=process_input,
                process=dict(process),
                requires_ghidra=bool(raw.get("requires_ghidra", binary is not None and source is None)),
                compiler_flags=tuple(compiler_flags),
                compiler=compiler,
            )
        )
    _validate_pairs(lanes)
    proof = payload.get("proof") if isinstance(payload.get("proof"), Mapping) else {}
    proof_timeout_seconds = float(proof.get("timeout_seconds", 15.0))
    proof_dynamic_max_steps = int(proof.get("dynamic_max_steps", 30000))
    if proof_timeout_seconds <= 0:
        raise ValueError("Corpus proof timeout_seconds must be greater than zero")
    if not 1 <= proof_dynamic_max_steps <= 100000:
        raise ValueError("Corpus proof dynamic_max_steps must be between 1 and 100000")
    return CorpusManifest(
        corpus_id=corpus_id,
        path=manifest_path,
        lanes=tuple(lanes),
        cache_dir=_optional_path(payload.get("cache_dir"), manifest_path.parent),
        proof_timeout_seconds=proof_timeout_seconds,
        proof_dynamic_max_steps=proof_dynamic_max_steps,
    )


def run_corpus(
    manifest: CorpusManifest,
    output_dir: Path,
    *,
    mode: str,
    overwrite: bool = False,
) -> CorpusRunSummary:
    if mode not in CORPUS_MODES:
        raise ValueError(f"Unknown corpus mode {mode!r}; expected lightweight or full")
    root = Path(output_dir).expanduser().resolve()
    _validate_output_root(root)
    if root.exists() and any(root.iterdir()):
        if not overwrite:
            raise FileExistsError(f"Corpus output directory is not empty: {root}; pass --overwrite")
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    resolved_manifest = root / "corpus_manifest_resolved.json"
    resolved_manifest.write_text(json.dumps(_manifest_to_dict(manifest), indent=2, sort_keys=True) + "\n")

    lane_results: list[CorpusLaneResult] = []
    corpus_errors: list[str] = []
    for lane in manifest.lanes:
        lane_root = root / "lanes" / _safe_name(lane.lane_id)
        try:
            if mode == "lightweight":
                if lane.source is None:
                    lane_results.append(_skipped_lane(lane, "requires_full_mode"))
                    continue
                result = _run_lightweight_lane(lane, lane_root)
            else:
                result = _run_full_lane(lane, lane_root, root, manifest)
            lane_results.append(result)
        except Exception as exc:  # Corpus execution records target-scoped errors.
            message = f"{lane.lane_id}: {type(exc).__name__}: {exc}"
            corpus_errors.append(message)
            lane_results.append(
                CorpusLaneResult(
                    lane_id=lane.lane_id,
                    role=lane.role,
                    comparison_group=lane.comparison_group,
                    status="error",
                    run_dir=str(lane_root),
                    binary_path=str(lane.binary or ""),
                    binary_sha256="",
                    candidate_count=0,
                    candidate_types={},
                    proof_count=0,
                    proof_outcomes={},
                    report_count=0,
                    report_types={},
                    errors=(message,),
                )
            )

    pair_payload = build_pair_differential(manifest.lanes, lane_results)
    pair_path = root / "pair_differential.json"
    pair_path.write_text(json.dumps(pair_payload, indent=2, sort_keys=True) + "\n")
    expectation_errors = _expectation_errors(manifest.lanes, lane_results)
    corpus_errors.extend(expectation_errors)
    capability_path = ""
    if mode == "full" and all(item.status != "error" for item in lane_results):
        capability_path = _write_capability_summary(manifest.lanes, lane_results, root)
    totals = _totals(lane_results, pair_payload)
    summary = CorpusRunSummary(
        corpus_id=manifest.corpus_id,
        mode=mode,
        output_dir=str(root),
        accepted=not corpus_errors,
        lanes=tuple(lane_results),
        errors=tuple(corpus_errors),
        totals=totals,
        pair_differential_path=str(pair_path),
        capability_summary_path=capability_path,
    )
    (root / "corpus_summary.json").write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n")
    return summary


def build_pair_differential(
    lanes: Sequence[CorpusLane],
    results: Sequence[CorpusLaneResult],
) -> dict[str, Any]:
    by_id = {result.lane_id: result for result in results}
    groups: dict[str, list[CorpusLane]] = {}
    for lane in lanes:
        groups.setdefault(lane.comparison_group, []).append(lane)
    rows: list[dict[str, Any]] = []
    total_shared_symbolic = 0
    total_raw = 0
    total_public = 0
    for group, group_lanes in sorted(groups.items()):
        vulnerable = next((item for item in group_lanes if item.role == "vulnerable"), None)
        fixed = next((item for item in group_lanes if item.role == "fixed"), None)
        if vulnerable is None or fixed is None:
            continue
        vulnerable_result = by_id.get(vulnerable.lane_id)
        fixed_result = by_id.get(fixed.lane_id)
        vulnerable_candidates = _load_candidates(Path(vulnerable_result.run_dir)) if vulnerable_result else []
        fixed_candidates = _load_candidates(Path(fixed_result.run_dir)) if fixed_result else []
        vulnerable_proofs = _load_proof_map(Path(vulnerable_result.run_dir)) if vulnerable_result else {}
        fixed_proofs = _load_proof_map(Path(fixed_result.run_dir)) if fixed_result else {}
        v_signatures = _signature_rows(vulnerable_candidates)
        f_signatures = _signature_rows(fixed_candidates)
        shared = sorted(set(v_signatures) & set(f_signatures))
        suppressed: list[dict[str, Any]] = []
        for signature in shared:
            paired_count = min(len(v_signatures[signature]), len(f_signatures[signature]))
            paired_candidates = sorted(
                v_signatures[signature],
                key=lambda item: str(item.get("candidate_id") or ""),
            )[:paired_count]
            for candidate in paired_candidates:
                proof = vulnerable_proofs.get(str(candidate.get("candidate_id") or ""), {})
                if _paired_symbolic_suppressible(candidate, proof):
                    suppressed.append(
                        {
                            "candidate_id": candidate.get("candidate_id", ""),
                            "signature": list(signature),
                            "reason": "paired_fixed_symbolic_equivalent",
                        }
                    )
        raw_count = len(vulnerable_candidates) + len(fixed_candidates)
        suppressed_count = len(suppressed)
        suppressed_ids = {str(item["candidate_id"]) for item in suppressed}
        public_rows = [
            {
                "candidate_id": str(candidate.get("candidate_id") or ""),
                "signature": list(signature),
            }
            for signature, candidates in sorted(v_signatures.items())
            for candidate in candidates
            if str(candidate.get("candidate_id") or "") not in suppressed_ids
        ]
        public_count = len(public_rows)
        total_raw += raw_count
        total_shared_symbolic += suppressed_count
        total_public += public_count
        rows.append(
            {
                "comparison_group": group,
                "vulnerable_lane": vulnerable.lane_id,
                "fixed_lane": fixed.lane_id,
                "raw_candidate_count": raw_count,
                "vulnerable_raw_candidate_count": len(vulnerable_candidates),
                "fixed_raw_candidate_count": len(fixed_candidates),
                "vulnerable_only_signatures": [list(item) for item in sorted(set(v_signatures) - set(f_signatures))],
                "fixed_only_signatures": [list(item) for item in sorted(set(f_signatures) - set(v_signatures))],
                "shared_signature_count": len(shared),
                "shared_symbolic_suppressed": suppressed,
                "public_review": public_rows,
                "public_review_count": public_count,
            }
        )
    return {
        "schema_version": CORPUS_SCHEMA_VERSION,
        "artifact_kind": "pair_differential",
        "groups": rows,
        "totals": {
            "raw_candidate_count": total_raw,
            "shared_symbolic_suppressed_count": total_shared_symbolic,
            "public_review_count": total_public,
        },
    }


def _run_lightweight_lane(lane: CorpusLane, lane_root: Path) -> CorpusLaneResult:
    lane_root.mkdir(parents=True, exist_ok=True)
    binary_path = lane_root / "build" / lane.lane_id
    binary_path.parent.mkdir(parents=True, exist_ok=True)
    compile_command = [lane.compiler, "-O0", "-fno-inline", *lane.compiler_flags, str(lane.source), "-o", str(binary_path)]
    compile_result = subprocess.run(compile_command, capture_output=True, text=True, timeout=30)
    (lane_root / "compile.log").write_text(compile_result.stdout + compile_result.stderr)
    if compile_result.returncode != 0:
        raise RuntimeError(f"fixture compilation failed with exit {compile_result.returncode}")
    export_dir = _write_fixture_export(lane, binary_path, lane_root / "export")
    discovery = run_discovery(
        load_discovery_context(export_dir),
        vulnerability_types=list(lane.vulnerability_types),
    )
    states = list(discovery.states)
    discovery_dir = lane_root / "discovery"
    write_discovery_candidates(states, discovery_dir)
    write_discovery_metrics(discovery.metrics, discovery_dir)
    write_candidate_states(states, discovery_dir / "candidate_states.json")
    results = [_lightweight_proof(state, lane, binary_path, lane_root) for state in states]
    proof_dir = lane_root / "proof"
    write_proof_results(results, proof_dir / "proof_results.json")
    (proof_dir / "metrics.json").write_text(json.dumps(proof_metrics(results), indent=2, sort_keys=True))
    promoted, _events = promote_with_proof_results(states, results)
    report_rows = [
        render_backend_finding(state, result)
        for state, result in zip(promoted, results)
        if result.status == "proven" and state.status == "report_ready"
    ]
    report_dir = lane_root / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "vulnerabilities.json").write_text(
        json.dumps({"schema_version": 2, "vulnerabilities": report_rows}, indent=2, sort_keys=True)
    )
    write_candidate_states(promoted, lane_root / "promotion" / "candidate_states.json")
    return _summarize_lane(lane, lane_root, binary_path)


def _run_full_lane(
    lane: CorpusLane,
    lane_root: Path,
    corpus_root: Path,
    manifest: CorpusManifest,
) -> CorpusLaneResult:
    lane_root.mkdir(parents=True, exist_ok=True)
    binary_path = lane.binary
    if binary_path is None:
        binary_path = lane_root / "build" / lane.lane_id
        binary_path.parent.mkdir(parents=True, exist_ok=True)
        command = [lane.compiler, "-O0", "-fno-inline", *lane.compiler_flags, str(lane.source), "-o", str(binary_path)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=30)
        (lane_root / "compile.log").write_text(compiled.stdout + compiled.stderr)
        if compiled.returncode != 0:
            raise RuntimeError(f"fixture compilation failed with exit {compiled.returncode}")
    process_input = lane.process_input
    if process_input is None and lane.process:
        process_input = lane_root / "process_input.json"
        process_input.write_text(json.dumps({"schema_version": 2, **dict(lane.process)}, indent=2, sort_keys=True))
    command = _full_toolchain_command(
        lane,
        binary_path,
        lane_root,
        corpus_root,
        manifest,
        process_input,
    )
    completed = subprocess.run(command, capture_output=True, text=True)
    (lane_root / "toolchain.stdout.log").write_text(completed.stdout)
    (lane_root / "toolchain.stderr.log").write_text(completed.stderr)
    if completed.returncode != 0:
        raise RuntimeError(f"toolchain failed with exit {completed.returncode}")
    run_dirs = [path.parent.parent for path in (lane_root / "toolchain").rglob("report/vulnerabilities.json")]
    if len(run_dirs) != 1:
        raise RuntimeError(f"expected one toolchain run directory, found {len(run_dirs)}")
    generated_run = run_dirs[0]
    pointer = lane_root / "run_dir.json"
    pointer.write_text(json.dumps({"schema_version": 2, "run_dir": str(generated_run)}, indent=2))
    return _summarize_lane(lane, generated_run, binary_path, public_run_dir=lane_root)


def _full_toolchain_command(
    lane: CorpusLane,
    binary_path: Path,
    lane_root: Path,
    corpus_root: Path,
    manifest: CorpusManifest,
    process_input: Path | None,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "binary_agent.cli.toolchain",
        str(binary_path),
        "--output-root",
        str(lane_root / "toolchain"),
        "--cache-dir",
        str(manifest.cache_dir or corpus_root / "cache"),
        "--analysis-cache-dir",
        str(corpus_root / "analysis-cache"),
        "--stages",
        "intake,discovery,refinement,proof,replay,report",
        "--vulnerability-types",
        ",".join(lane.vulnerability_types),
        "--replay-mode",
        "auto",
        "--proof-timeout-seconds",
        str(manifest.proof_timeout_seconds),
        "--proof-dynamic-max-steps",
        str(manifest.proof_dynamic_max_steps),
        "--proof-jobs",
        "1",
        "--hypothesis-policy",
        "off",
        "--overwrite",
    ]
    if process_input is not None:
        command.extend(["--process-input-json", str(process_input)])
    return command


def _lightweight_proof(
    state: CandidateState,
    lane: CorpusLane,
    binary_path: Path,
    lane_root: Path,
) -> ProofResult:
    operation_address = str(state.operation.get("address") or state.location.get("operation_address") or "")
    if state.backend == "static_evidence":
        facts = dict(state.type_facts)
        exact = bool(
            facts.get("exact_call")
            or (facts.get("literal_fingerprint") and facts.get("consumer_address"))
        )
        evidence = {
            "scope": "static",
            "exact_operation_reached": True,
            "operation_address": operation_address,
            "static_evidence": {
                "exact": exact,
                "reachable": facts.get("reachable") is True,
                "kind": str(facts.get("exact_call") or state.mechanism),
                "literal_fingerprint": str(facts.get("literal_fingerprint") or ""),
                "consumer_address": str(facts.get("consumer_address") or ""),
            },
            "artifact_refs": [str(binary_path), str(lane.source)],
        }
        return dispatch_proof(state, evidence)
    if state.backend in {"memory_access", "memory_lifetime"}:
        replay_evidence = _lightweight_process_evidence(state, lane, binary_path, lane_root)
        observed = replay_evidence.pop("effect_observed")
        if state.backend == "memory_access":
            if state.vulnerability_type == "uninitialized_memory_use":
                replay_evidence["memory_access"] = {
                    "definedness": "undefined" if observed else "defined",
                    "read": observed,
                    "undefined_byte_ranges": state.type_facts.get("undefined_byte_ranges", []) if observed else [],
                    "defined_byte_ranges": state.type_facts.get("defined_byte_ranges", []),
                }
            elif state.vulnerability_type == "overlapping_memory_copy":
                replay_evidence["memory_access"] = {
                    "ranges_overlap": observed,
                    "operation": "memcpy",
                }
            else:
                replay_evidence["memory_access"] = {
                    "same_object": observed,
                    "object_range": [0, 1] if observed else [],
                    "access_range": [1, 2] if observed else [],
                    "out_of_bounds": observed,
                    "operation": state.operation.get("name", ""),
                }
        else:
            lifetime = {
                "same_resource": observed,
                "events": ["borrow", "invalidating_allocation", "copy_read"] if observed else [],
                "violation": observed,
                "mechanism": state.mechanism,
            }
            if state.vulnerability_type == "mismatched_deallocator":
                lifetime.update(
                    {
                        "allocator_family": state.type_facts.get("allocator_family", "") if observed else "",
                        "deallocator_family": state.type_facts.get("deallocator_family", "") if observed else "",
                    }
                )
            elif state.vulnerability_type == "memory_leak":
                lifetime.update(
                    {
                        "path_local": state.type_facts.get("path_local") is True,
                        "escaped": False,
                        "live_at_scope_exit": observed,
                        "resource_generation": 1 if observed else 0,
                        "scope_exit": "fixture_main_return" if observed else "",
                        "events": [
                            {
                                "action": "scope_exit",
                                "generation": 1,
                                "live_before": True,
                            }
                        ] if observed else [],
                    }
                )
            replay_evidence["lifetime_violation"] = lifetime
        return dispatch_proof(state, replay_evidence)
    if state.backend != "semantic_effect":
        return dispatch_proof(state, {"scope": "function_harness"})
    process = dict(lane.process)
    model = str(process.get("input_model") or "argv")
    argv = [str(item) for item in process.get("argv_values", process.get("argv", []))]
    stdin_text = str(process.get("stdin") or "")
    if isinstance(process.get("proof_oracle"), Mapping):
        spec = get_vulnerability_spec(state.vulnerability_type)
        setup = {
            "binary_path": str(binary_path),
            "timeout_seconds": float(process.get("timeout_seconds") or 10.0),
            **{
                key: process[key]
                for key in (
                    "env",
                    "cwd",
                    "workdir",
                    "proof_file",
                    "proof_files",
                    "database_path",
                    "log_path",
                    "outbound_listener",
                )
                if process.get(key) not in (None, "", [], {})
            },
        }
        oracle = dict(process["proof_oracle"])
        oracle.update(
            {
                "kind": spec.effect_kind,
                "vulnerability_type": state.vulnerability_type,
                "sink_address": operation_address,
            }
        )
        request = ReplayRequest(
            state.candidate_id,
            "native",
            setup,
            {"input_model": model, "argv": argv, "stdin": stdin_text},
            {
                "candidate_id": state.candidate_id,
                "vulnerability_type": state.vulnerability_type,
                "sink_address": operation_address,
                "proof_oracle": oracle,
            },
        )
        replay = run_replay_request(request, lane_root / "native-replay")
        observation = replay.control_result.get("proof_observation")
        if not isinstance(observation, Mapping):
            observation = {}
        return dispatch_proof(
            state,
            {
                "scope": "process_entrypoint",
                "exact_operation_reached": True,
                "operation_address": operation_address,
                "concrete_input": {"input_model": model, "argv": argv, "stdin": stdin_text},
                "process_setup": {"status": "configured", "input_model": model},
                "native_replay": {
                    "status": "observed" if replay.bug_observed else "reached",
                    "returncode": replay.control_result.get("returncode"),
                },
                "effect_observation": dict(observation),
                "artifact_refs": list(replay.artifacts),
            },
        )
    completed, argv, network_observed = _run_semantic_process(binary_path, argv, stdin_text, process)
    command = [str(binary_path), *argv]
    transcript = lane_root / "replay" / f"{state.candidate_id}.json"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    marker = str(process.get("effect_marker") or "")
    observed = bool(marker and marker in f"{completed.stdout}\n{completed.stderr}")
    if process.get("effect_observation") == "tcp_connection":
        observed = network_observed
    expected_mechanism = str(process.get("proof_mechanism") or "")
    if expected_mechanism:
        observed = observed and state.mechanism == expected_mechanism
    transcript.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "command": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "effect_marker": marker,
                "network_connection_observed": network_observed,
                "effect_observed": observed,
            },
            indent=2,
            sort_keys=True,
        )
    )
    spec = get_vulnerability_spec(state.vulnerability_type)
    return dispatch_proof(
        state,
        {
            "scope": "process_entrypoint",
            "exact_operation_reached": True,
            "operation_address": operation_address,
            "concrete_input": {"input_model": model, "argv": argv, "stdin": stdin_text},
            "process_setup": {"status": "configured", "input_model": model},
            "native_replay": {"status": "observed" if observed else "reached", "returncode": completed.returncode},
            "effect_observation": {"status": "observed" if observed else "not_observed", "kind": spec.effect_kind},
            "artifact_refs": [str(transcript)],
        },
    )


def _run_semantic_process(
    binary_path: Path,
    argv: list[str],
    stdin_text: str,
    process: Mapping[str, Any],
) -> tuple[subprocess.CompletedProcess[str], list[str], bool]:
    if process.get("effect_observation") != "tcp_connection":
        completed = subprocess.run(
            [str(binary_path), *argv],
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return completed, argv, False
    host = str(process.get("listener_host") or "127.0.0.1")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, 0))
        listener.listen(1)
        listener.settimeout(2.0)
        port = listener.getsockname()[1]
        resolved_argv = [item.replace("{listener_port}", str(port)) for item in argv]
        completed = subprocess.run(
            [str(binary_path), *resolved_argv],
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=10,
        )
        try:
            connection, _address = listener.accept()
        except socket.timeout:
            observed = False
        else:
            connection.close()
            observed = True
    return completed, resolved_argv, observed


def _lightweight_process_evidence(
    state: CandidateState,
    lane: CorpusLane,
    binary_path: Path,
    lane_root: Path,
) -> dict[str, Any]:
    process = dict(lane.process)
    argv = [str(item) for item in process.get("argv_values", process.get("argv", []))]
    stdin_text = str(process.get("stdin") or "")
    command = [str(binary_path), *argv]
    completed = subprocess.run(command, input=stdin_text, capture_output=True, text=True, timeout=10)
    marker = str(process.get("effect_marker") or "")
    observed = bool(marker and marker in f"{completed.stdout}\n{completed.stderr}")
    expected_mechanism = str(process.get("proof_mechanism") or "")
    if expected_mechanism:
        observed = observed and state.mechanism == expected_mechanism
    transcript = lane_root / "replay" / f"{state.candidate_id}.json"
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "command": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "effect_marker": marker,
                "effect_observed": observed,
            },
            indent=2,
            sort_keys=True,
        )
    )
    operation_address = str(state.operation.get("address") or state.location.get("operation_address") or "")
    return {
        "scope": "process_entrypoint",
        "exact_operation_reached": observed,
        "operation_address": operation_address if observed else "",
        "concrete_input": {
            "input_model": str(process.get("input_model") or "argv"),
            "argv": argv,
            "stdin": stdin_text,
        },
        "process_setup": {"status": "configured", "input_model": str(process.get("input_model") or "argv")},
        "native_replay": {"status": "observed" if observed else "reached", "returncode": completed.returncode},
        "artifact_refs": [str(transcript)],
        "effect_observed": observed,
    }


def _write_fixture_export(lane: CorpusLane, binary_path: Path, export_dir: Path) -> Path:
    export_dir.mkdir(parents=True, exist_ok=True)
    source_text = lane.source.read_text(errors="replace")
    relative_path = "main.c"
    (export_dir / relative_path).write_text(source_text)
    record = FunctionRecord(
        address="0x1000",
        relative_address=0x1000,
        name="main",
        relative_path=relative_path,
        source_exists=True,
        ordinal=0,
        size_addresses=max(1, len(source_text)),
        body_size_bytes=max(1, len(source_text)),
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=len(source_text.encode()),
        line_count=len(source_text.splitlines()),
        return_type="int",
        prototype="int main(int argc, char **argv)",
        parameters=[],
        emit_c=True,
    )
    manifest = Manifest(
        binary=lane.lane_id,
        generated_at=utc_timestamp(),
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=[record],
        language_id="x86:le:64:default",
        processor="x86",
        pointer_size_bytes=8,
        endianness="little",
        executable_format="ELF",
        compiler="cc fixture",
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict(), indent=2, sort_keys=True))
    (export_dir / "binary.json").write_text(
        json.dumps({"schema_version": 2, "path": str(binary_path), "sha256": _sha256(binary_path)}, indent=2)
    )
    return export_dir


def _summarize_lane(
    lane: CorpusLane,
    run_dir: Path,
    binary_path: Path,
    *,
    public_run_dir: Path | None = None,
) -> CorpusLaneResult:
    candidates_payload = _load_schema2(run_dir / "discovery" / "candidates.json", "candidate artifact")
    proof_payload = _load_schema2(run_dir / "proof" / "proof_results.json", "proof artifact")
    report_payload = _load_schema2(run_dir / "report" / "vulnerabilities.json", "report artifact")
    candidates = [item for item in candidates_payload.get("candidates", []) if isinstance(item, Mapping)]
    proofs = [item for item in proof_payload.get("proof_results", []) if isinstance(item, Mapping)]
    reports = [item for item in report_payload.get("vulnerabilities", []) if isinstance(item, Mapping)]
    ids = [str(item.get("candidate_id") or "") for item in candidates]
    duplicate_ids = tuple(sorted(key for key, count in Counter(ids).items() if key and count > 1))
    blockers = tuple(sorted({str(item.get("blocker")) for item in proofs if item.get("blocker")}))
    return CorpusLaneResult(
        lane_id=lane.lane_id,
        role=lane.role,
        comparison_group=lane.comparison_group,
        status="completed",
        run_dir=str(public_run_dir or run_dir),
        binary_path=str(binary_path),
        binary_sha256=_sha256(binary_path),
        candidate_count=len(candidates),
        candidate_types=dict(sorted(Counter(str(item.get("vulnerability_type") or "") for item in candidates).items())),
        proof_count=len(proofs),
        proof_outcomes=dict(sorted(Counter(str(item.get("status") or "") for item in proofs).items())),
        report_count=len(reports),
        report_types=dict(
            sorted(Counter(str(item.get("vulnerability_type") or item.get("vulnerability") or "") for item in reports).items())
        ),
        duplicate_candidate_ids=duplicate_ids,
        blockers=blockers,
    )


def _load_candidates(run_dir: Path) -> list[Mapping[str, Any]]:
    actual = _actual_run_dir(run_dir)
    path = actual / "discovery" / "candidates.json"
    if not path.exists():
        return []
    payload = json.loads(path.read_text() or "{}")
    return [item for item in payload.get("candidates", []) if isinstance(item, Mapping)]


def _load_proof_map(run_dir: Path) -> dict[str, Mapping[str, Any]]:
    actual = _actual_run_dir(run_dir)
    path = actual / "proof" / "proof_results.json"
    if not path.exists():
        return {}
    payload = json.loads(path.read_text() or "{}")
    return {
        str(item.get("candidate_id") or ""): item
        for item in payload.get("proof_results", [])
        if isinstance(item, Mapping)
    }


def _actual_run_dir(run_dir: Path) -> Path:
    pointer = run_dir / "run_dir.json"
    if pointer.exists():
        payload = json.loads(pointer.read_text() or "{}")
        candidate = Path(str(payload.get("run_dir") or ""))
        if candidate.is_dir():
            return candidate
    return run_dir


def _signature_rows(candidates: Sequence[Mapping[str, Any]]) -> dict[tuple[str, ...], list[Mapping[str, Any]]]:
    rows: dict[tuple[str, ...], list[Mapping[str, Any]]] = {}
    for candidate in candidates:
        operation = candidate.get("operation") if isinstance(candidate.get("operation"), Mapping) else {}
        affected = candidate.get("affected_object") if isinstance(candidate.get("affected_object"), Mapping) else {}
        location = candidate.get("location") if isinstance(candidate.get("location"), Mapping) else {}
        facts = candidate.get("type_facts") if isinstance(candidate.get("type_facts"), Mapping) else {}
        signature = (
            str(candidate.get("backend") or ""),
            str(candidate.get("vulnerability_type") or ""),
            str(candidate.get("mechanism") or ""),
            _normalized_pair_token(location.get("function_name")),
            str(location.get("line_number") or ""),
            str(operation.get("name") or ""),
            str(operation.get("kind") or ""),
            str(affected.get("kind") or ""),
            str(affected.get("label") or affected.get("identity") or ""),
            str(affected.get("capacity_bytes") or ""),
            _normalized_pair_token(facts.get("offset_expr")),
            _normalized_pair_token(facts.get("write_relation")),
            _normalized_pair_token(facts.get("capacity_basis")),
        )
        rows.setdefault(signature, []).append(candidate)
    return rows


def _normalized_pair_token(value: Any) -> str:
    token = str(value or "")
    token = re.sub(r"(?i)\bFUN_[0-9a-f]+\b", "FUN", token)
    return re.sub(r"(?i)\b0x[0-9a-f]+\b", "0xADDR", token)


def _paired_symbolic_suppressible(candidate: Mapping[str, Any], proof: Mapping[str, Any]) -> bool:
    if str(proof.get("status") or "") == "proven" or proof.get("exact_operation_reached") is True:
        return False
    blockers = {
        *[str(item) for item in candidate.get("blockers", [])],
        str(proof.get("blocker") or ""),
    }
    symbolic_tokens = (
        "symbolic",
        "exact_operation_not_reached",
        "overflow_condition_proof",
        "allocation_site_unknown",
        "same_resource_event_sequence_unproven",
        "same_resource_runtime_proof_required",
        "mutually_exclusive_event_paths",
        "object_extent",
    )
    return any(any(token in blocker for token in symbolic_tokens) for blocker in blockers if blocker)


def _expectation_errors(
    lanes: Sequence[CorpusLane],
    results: Sequence[CorpusLaneResult],
) -> list[str]:
    by_id = {item.lane_id: item for item in results}
    errors: list[str] = []
    for lane in lanes:
        result = by_id[lane.lane_id]
        if result.status == "skipped":
            continue
        if result.status == "error":
            errors.extend(result.errors)
            continue
        report_types = set(result.report_types)
        candidate_types = set(result.candidate_types)
        for vulnerability_type in lane.expected_positives:
            if vulnerability_type not in report_types:
                errors.append(f"{lane.lane_id}: missing expected report {vulnerability_type}")
        for vulnerability_type in lane.expected_negatives:
            if vulnerability_type in report_types:
                errors.append(f"{lane.lane_id}: unexpected fixed-lane report {vulnerability_type}")
        for vulnerability_type in lane.allowed_blocked:
            if vulnerability_type not in candidate_types:
                errors.append(f"{lane.lane_id}: allowed blocked type was not detected: {vulnerability_type}")
            if vulnerability_type in report_types:
                errors.append(f"{lane.lane_id}: allowed blocked type unexpectedly reported: {vulnerability_type}")
        if result.duplicate_candidate_ids:
            errors.append(f"{lane.lane_id}: duplicate candidate ids: {', '.join(result.duplicate_candidate_ids)}")
    return errors


def _write_capability_summary(
    lanes: Sequence[CorpusLane],
    results: Sequence[CorpusLaneResult],
    root: Path,
) -> str:
    by_id = {item.lane_id: item for item in results}
    targets = []
    for lane in lanes:
        result = by_id[lane.lane_id]
        actual = _actual_run_dir(Path(result.run_dir))
        targets.append(
            {
                "id": lane.lane_id,
                "artifact_dir": str(actual),
                "analysis_report_path": str(actual / "report" / "vulnerabilities.json"),
                "expected_positives": list(lane.expected_positives or lane.allowed_blocked),
                "expected_negatives": list(lane.expected_negatives),
                "lane": lane.role,
                "vulnerability_family": (lane.vulnerability_types[0] if lane.vulnerability_types else ""),
                "input_model": str(lane.process.get("input_model") or "unknown"),
                "comparison_group": lane.comparison_group,
            }
        )
    targets_path = root / "capability_sweep_targets.json"
    targets_path.write_text(json.dumps({"schema_version": 2, "targets": targets}, indent=2, sort_keys=True))
    output = root / "capability-sweep"
    run_capability_sweep(targets_path, output, overwrite=True)
    return str(output / "capability_sweep_summary.json")


def _totals(results: Sequence[CorpusLaneResult], pair_payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "lane_count": len(results),
        "completed_lanes": sum(item.status == "completed" for item in results),
        "skipped_lanes": sum(item.status == "skipped" for item in results),
        "error_lanes": sum(item.status == "error" for item in results),
        "candidates": sum(item.candidate_count for item in results),
        "proof_results": sum(item.proof_count for item in results),
        "proven": sum(item.proof_outcomes.get("proven", 0) for item in results),
        "reports": sum(item.report_count for item in results),
        "fixed_reports": sum(item.report_count for item in results if item.role == "fixed"),
        **dict(pair_payload.get("totals", {})),
    }


def _skipped_lane(lane: CorpusLane, reason: str) -> CorpusLaneResult:
    return CorpusLaneResult(
        lane_id=lane.lane_id,
        role=lane.role,
        comparison_group=lane.comparison_group,
        status="skipped",
        run_dir="",
        binary_path=str(lane.binary or ""),
        binary_sha256="",
        candidate_count=0,
        candidate_types={},
        proof_count=0,
        proof_outcomes={},
        report_count=0,
        report_types={},
        blockers=(reason,),
    )


def _manifest_to_dict(manifest: CorpusManifest) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "corpus_id": manifest.corpus_id,
        "proof": {
            "timeout_seconds": manifest.proof_timeout_seconds,
            "dynamic_max_steps": manifest.proof_dynamic_max_steps,
        },
        "cache_dir": str(manifest.cache_dir) if manifest.cache_dir else "",
        "lanes": [
            {
                "id": lane.lane_id,
                "role": lane.role,
                "comparison_group": lane.comparison_group,
                "expected_positives": list(lane.expected_positives),
                "expected_negatives": list(lane.expected_negatives),
                "allowed_blocked": list(lane.allowed_blocked),
                "vulnerability_types": list(lane.vulnerability_types),
                "binary": str(lane.binary) if lane.binary else "",
                "source": str(lane.source) if lane.source else "",
                "process_input": str(lane.process_input) if lane.process_input else "",
                "process": dict(lane.process),
                "requires_ghidra": lane.requires_ghidra,
                "compiler_flags": list(lane.compiler_flags),
                "compiler": lane.compiler,
            }
            for lane in manifest.lanes
        ],
    }


def _validate_pairs(lanes: Sequence[CorpusLane]) -> None:
    groups: dict[str, list[CorpusLane]] = {}
    for lane in lanes:
        groups.setdefault(lane.comparison_group, []).append(lane)
    for group, rows in groups.items():
        roles = Counter(item.role for item in rows)
        if roles["vulnerable"] != 1 or roles["fixed"] != 1:
            raise ValueError(
                f"Comparison group {group!r} must contain exactly one vulnerable and one fixed lane"
            )


def _vulnerability_types(value: Any, lane_id: str, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Corpus lane {lane_id} {field_name} must be a string list")
    result = tuple(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
    for vulnerability_type in result:
        get_vulnerability_spec(vulnerability_type)
    return result


def _optional_path(value: Any, base: Path) -> Path | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    path = Path(raw).expanduser()
    return (base / path).resolve() if not path.is_absolute() else path.resolve()


def _load_schema2(path: Path, label: str) -> Mapping[str, Any]:
    payload = json.loads(path.read_text() or "{}")
    if not isinstance(payload, Mapping) or int(payload.get("schema_version", 0) or 0) != 2:
        raise ValueError(f"{label} {path} must use schema v2")
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(value: str) -> str:
    result = "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in value)
    return result[:120] or "lane"


def _validate_output_root(root: Path) -> None:
    """Reject roots whose recursive replacement could destroy user data."""

    protected = {Path("/").resolve(), Path.home().resolve(), Path.cwd().resolve()}
    if root in protected:
        raise ValueError(f"Refusing unsafe corpus output directory: {root}")
