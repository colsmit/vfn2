"""Freeze and verify a proof-route contention benchmark."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import statistics
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from binary_agent.pipeline import CandidateState, load_candidate_states
from binary_agent.execution_envelope import discover_execution_envelope
from binary_agent.proof import proof_result_reportable
from binary_agent.proof_batching import summarize_executed_batches
from binary_agent.proof_routing import (
    ProofRouteRegistry,
    RouteExecutionContext,
    default_route_registry,
    execute_route_orchestration,
)
from binary_agent.research_corpus import analyzer_tree_sha256
from binary_agent.scheduling import ProofBudget, _candidate_score


ROUTE_BENCHMARK_SCHEMA_VERSION = 1
DEFAULT_CORPUS_ID = "openwrt-route-contention-v1"


@dataclass(frozen=True)
class FrozenRouteBenchmark:
    corpus_id: str
    corpus_dir: str
    analyzer_sha256: str
    cases: tuple[Mapping[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ROUTE_BENCHMARK_SCHEMA_VERSION,
            "artifact_kind": "frozen_route_contention_benchmark",
            "corpus_id": self.corpus_id,
            "corpus_dir": self.corpus_dir,
            "analyzer_sha256": self.analyzer_sha256,
            "frozen_at": datetime.now(timezone.utc).isoformat(),
            "selection_policy": {
                "higher_evidence_score_count": 3,
                "lower_evidence_score_count": 9,
                "expectation_authority": "strata_only_not_proof_outcomes",
            },
            "cases": [dict(item) for item in self.cases],
        }


def freeze_route_benchmark(
    source_run: Path,
    output_root: Path,
    *,
    repo_root: Path | None = None,
    corpus_id: str = DEFAULT_CORPUS_ID,
) -> FrozenRouteBenchmark:
    """Seal real proof-ready candidates before route/scheduler behavior changes."""

    repository = (repo_root or Path.cwd()).expanduser().resolve()
    run = Path(source_run).expanduser().resolve()
    state_path = run / "promotion" / "candidate_states.json"
    evidence_dir = run / "evidence"
    if not state_path.is_file() or not evidence_dir.is_dir():
        raise ValueError("source run must contain promotion/candidate_states.json and evidence/")
    states = [state for state in load_candidate_states(state_path) if state.status == "proof_ready"]
    scored = [(float(_candidate_score(state, "adaptive")[0]), state) for state in states]
    score_values = sorted({score for score, _ in scored}, reverse=True)
    if len(score_values) < 2:
        raise ValueError("contention source must contain at least two evidence-score strata")
    high_score, low_score = score_values[0], score_values[-1]
    high = sorted((state for score, state in scored if score == high_score), key=lambda item: item.candidate_id)[:3]
    low = sorted((state for score, state in scored if score == low_score), key=lambda item: item.candidate_id)[:9]
    if len(high) < 3 or len(low) < 9:
        raise ValueError("contention source requires three high-score and nine low-score candidates")
    root = Path(output_root).expanduser()
    if not root.is_absolute():
        root = repository / root
    corpus_dir = root.resolve() / corpus_id
    if corpus_dir.exists():
        raise FileExistsError(f"frozen route benchmark already exists: {corpus_dir}")
    corpus_dir.mkdir(parents=True)
    cases: list[Mapping[str, Any]] = []
    try:
        for stratum, selected in (("higher_evidence_score", high), ("lower_evidence_score", low)):
            for state in selected:
                cases.append(
                    _freeze_route_case(
                        state,
                        score=high_score if stratum == "higher_evidence_score" else low_score,
                        stratum=stratum,
                        source_evidence_dir=evidence_dir,
                        corpus_dir=corpus_dir,
                    )
                )
        frozen = FrozenRouteBenchmark(
            corpus_id=corpus_id,
            corpus_dir=str(corpus_dir),
            analyzer_sha256=analyzer_tree_sha256(repository),
            cases=tuple(sorted(cases, key=lambda item: str(item["candidate_id"]))),
        )
        _write_json(corpus_dir / "frozen_manifest.json", frozen.to_dict())
        _write_json(
            corpus_dir / "inventory.json",
            {
                "schema_version": 1,
                "artifact_kind": "frozen_route_contention_inventory",
                "tree_sha256": _tree_sha256(corpus_dir, ignored={"inventory.json"}),
                "files": _file_inventory(corpus_dir, ignored={"inventory.json"}),
            },
        )
        return frozen
    except Exception:
        shutil.rmtree(corpus_dir, ignore_errors=True)
        raise


def verify_route_benchmark(manifest_path: Path) -> dict[str, Any]:
    manifest_file = Path(manifest_path).expanduser().resolve()
    payload = _load_json(manifest_file)
    if int(payload.get("schema_version") or 0) != ROUTE_BENCHMARK_SCHEMA_VERSION:
        raise ValueError("unsupported route benchmark schema")
    root = manifest_file.parent
    failures: list[dict[str, str]] = []
    for raw in payload.get("cases", []):
        if not isinstance(raw, Mapping):
            failures.append({"candidate_id": "", "kind": "invalid_case"})
            continue
        candidate_id = str(raw.get("candidate_id") or "")
        for kind in ("state", "evidence", "binary"):
            path = root / str(raw.get(f"{kind}_path") or "")
            expected = str(raw.get(f"{kind}_sha256") or "")
            if not path.is_file():
                failures.append({"candidate_id": candidate_id, "kind": kind, "reason": "missing"})
            elif _sha256_file(path) != expected:
                failures.append({"candidate_id": candidate_id, "kind": kind, "reason": "hash_mismatch"})
        export = root / str(raw.get("export_path") or "")
        if not export.is_dir():
            failures.append({"candidate_id": candidate_id, "kind": "export", "reason": "missing"})
        elif _tree_sha256(export) != str(raw.get("export_sha256") or ""):
            failures.append({"candidate_id": candidate_id, "kind": "export", "reason": "hash_mismatch"})
    return {
        "schema_version": 1,
        "artifact_kind": "frozen_route_contention_verification",
        "corpus_id": str(payload.get("corpus_id") or ""),
        "verified": not failures,
        "case_count": len(payload.get("cases", [])),
        "higher_evidence_score_count": sum(
            isinstance(item, Mapping) and item.get("stratum") == "higher_evidence_score"
            for item in payload.get("cases", [])
        ),
        "lower_evidence_score_count": sum(
            isinstance(item, Mapping) and item.get("stratum") == "lower_evidence_score"
            for item in payload.get("cases", [])
        ),
        "failures": failures,
    }


def load_frozen_route_cases(manifest_path: Path) -> list[tuple[CandidateState, Mapping[str, Any]]]:
    manifest_file = Path(manifest_path).expanduser().resolve()
    verification = verify_route_benchmark(manifest_file)
    if not verification["verified"]:
        raise ValueError(f"frozen route benchmark verification failed: {verification['failures']}")
    payload = _load_json(manifest_file)
    root = manifest_file.parent
    loaded: list[tuple[CandidateState, Mapping[str, Any]]] = []
    for raw in payload.get("cases", []):
        if not isinstance(raw, Mapping):
            continue
        state_payload = _load_json(root / str(raw["state_path"]))
        loaded.append((CandidateState.from_dict(state_payload), dict(raw)))
    return loaded


def evaluate_route_benchmark(
    manifest_path: Path,
    output_root: Path,
    *,
    candidate_budget: int = 3,
    wall_budget_seconds: float = 60.0,
    cpu_budget_seconds: float = 60.0,
    timeout_seconds: float = 8.0,
    repetitions: int = 2,
    ghidra_dir: Path | None = None,
    repo_root: Path | None = None,
    registry: ProofRouteRegistry | None = None,
) -> dict[str, Any]:
    """Run equal-budget adaptive/exhaustive route allocation on frozen inputs."""

    repository = (repo_root or Path.cwd()).expanduser().resolve()
    manifest_file = Path(manifest_path).expanduser().resolve()
    verification = verify_route_benchmark(manifest_file)
    if not verification["verified"]:
        raise ValueError(f"frozen route benchmark verification failed: {verification['failures']}")
    manifest = _load_json(manifest_file)
    root = manifest_file.parent
    cases = load_frozen_route_cases(manifest_file)
    by_id = {state.candidate_id: (state, raw) for state, raw in cases}
    output = Path(output_root).expanduser()
    if not output.is_absolute():
        output = repository / output
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    run_id = _available_run_id(output)
    run_dir = output / run_id
    run_dir.mkdir()
    selected_registry = registry or default_route_registry()
    budget = ProofBudget(
        max_candidates=max(1, int(candidate_budget)),
        max_wall_seconds=max(0.0, float(wall_budget_seconds)),
        max_estimated_cpu_seconds=max(0.0, float(cpu_budget_seconds)),
    )
    policy_rows: dict[str, list[dict[str, Any]]] = {"adaptive": [], "exhaustive": []}
    for policy in ("adaptive", "exhaustive"):
        for repetition in range(1, max(1, int(repetitions)) + 1):
            repetition_dir = run_dir / policy / f"repeat-{repetition}"

            def context_for_state(state: CandidateState) -> RouteExecutionContext:
                raw = by_id[state.candidate_id][1]
                target = state.target if isinstance(state.target, Mapping) else {}
                rootfs_raw = target.get("firmware_target") or target.get("rootfs_path") or ""
                rootfs_path = Path(str(rootfs_raw)).expanduser().resolve() if rootfs_raw else None
                if rootfs_path is not None and not rootfs_path.is_dir():
                    rootfs_path = None
                binary_path = root / str(raw["binary_path"])
                envelope = discover_execution_envelope(
                    binary_path,
                    rootfs_path=rootfs_path,
                    cache_dir=run_dir / "execution_envelopes" / "cache",
                )
                return RouteExecutionContext(
                    binary_path=binary_path,
                    export_dir=root / str(raw["export_path"]),
                    evidence_dir=root / "evidence",
                    output_dir=repetition_dir / "routes",
                    timeout_seconds=max(0.1, float(timeout_seconds)),
                    ghidra_dir=Path(ghidra_dir).expanduser().resolve() if ghidra_dir else None,
                    memory_limit_mb=8192,
                    symbolic_bytes=256,
                    execution_envelope=envelope,
                    rootfs_path=Path(envelope.rootfs_path) if envelope.rootfs_path else None,
                )

            orchestration = execute_route_orchestration(
                [state for state, _raw in cases],
                context_for_state=context_for_state,
                budget=budget,
                policy=policy,
                registry=selected_registry,
            )
            row = _route_repetition_row(orchestration, by_id)
            _write_json(repetition_dir / "route_benchmark_result.json", row)
            policy_rows[policy].append(row)
    adaptive_first = policy_rows["adaptive"][0]
    exhaustive_first = policy_rows["exhaustive"][0]
    adaptive_median = _median_policy_metrics(policy_rows["adaptive"])
    exhaustive_median = _median_policy_metrics(policy_rows["exhaustive"])
    schedules_differ = adaptive_first["candidate_order"] != exhaustive_first["candidate_order"]
    adaptive_quality = (
        adaptive_median["completed_proofs"],
        adaptive_median["exact_operation_reaches"],
        adaptive_median["reports"],
    )
    exhaustive_quality = (
        exhaustive_median["completed_proofs"],
        exhaustive_median["exact_operation_reaches"],
        exhaustive_median["reports"],
    )
    cost_not_higher = (
        adaptive_median["cpu_seconds"] <= exhaustive_median["cpu_seconds"]
        and adaptive_median["wall_seconds"] <= exhaustive_median["wall_seconds"]
    )
    supports_claim = schedules_differ and adaptive_quality > exhaustive_quality and cost_not_higher
    summary = {
        "schema_version": 1,
        "artifact_kind": "route_contention_benchmark",
        "run_id": run_id,
        "run_dir": str(run_dir),
        "corpus_id": str(manifest.get("corpus_id") or ""),
        "frozen_analyzer_sha256": str(manifest.get("analyzer_sha256") or ""),
        "analyzer_sha256": analyzer_tree_sha256(repository),
        "case_count": len(cases),
        "budget": {
            "attempts": budget.max_candidates,
            "wall_seconds": budget.max_wall_seconds,
            "cpu_seconds": budget.max_estimated_cpu_seconds,
        },
        "repetitions": max(1, int(repetitions)),
        "schedules_differ": schedules_differ,
        "adaptive": {"runs": policy_rows["adaptive"], "median": adaptive_median},
        "exhaustive": {"runs": policy_rows["exhaustive"], "median": exhaustive_median},
        "supports_scheduling_efficiency_claim": supports_claim,
        "interpretation": (
            "Adaptive improved normalized proof yield or exact-operation reach without higher median cost."
            if supports_claim
            else "Schedules were evaluated honestly, but this run does not establish an adaptive proof-efficiency advantage."
        ),
        "ground_truth_scope": "allocation_and_completion_only; no firmware vulnerability ground truth",
    }
    _write_json(run_dir / "route_benchmark_summary.json", summary)
    _write_json(
        output / "latest.json",
        {
            "schema_version": 1,
            "artifact_kind": "route_contention_benchmark_latest",
            "run_id": run_id,
            "run_dir": str(run_dir),
            "summary_path": str(run_dir / "route_benchmark_summary.json"),
        },
    )
    return summary


def _route_repetition_row(orchestration: Any, by_id: Mapping[str, Any]) -> dict[str, Any]:
    outcomes = [item.proof_result for item in orchestration.attempts]
    candidate_order = [item.candidate_id for item in orchestration.attempts]
    strata = [str(by_id[item.candidate_id][1].get("stratum") or "") for item in orchestration.attempts]
    status_counts: dict[str, int] = {}
    route_counts: dict[str, int] = {}
    blocker_counts: dict[str, int] = {}
    for item in orchestration.attempts:
        status_counts[item.status] = status_counts.get(item.status, 0) + 1
        route_counts[item.route] = route_counts.get(item.route, 0) + 1
        if item.blocker:
            blocker_counts[item.blocker] = blocker_counts.get(item.blocker, 0) + 1
    return {
        "policy": orchestration.policy,
        "candidate_order": candidate_order,
        "selected_strata": strata,
        "route_order": [item.route for item in orchestration.attempts],
        "execution_families": [item.execution_family for item in orchestration.attempts],
        "attempt_count": len(orchestration.attempts),
        "completed_proofs": sum(item.status in {"proven", "refuted"} for item in outcomes),
        "exact_operation_reaches": sum(item.exact_operation_reached for item in outcomes),
        "reports": sum(
            proof_result_reportable(by_id[item.candidate_id][0], item.proof_result)
            for item in orchestration.attempts
        ),
        "status_counts": dict(sorted(status_counts.items())),
        "route_counts": dict(sorted(route_counts.items())),
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "stop_reason": orchestration.stop_reason,
        "wall_seconds": orchestration.wall_seconds,
        "cpu_seconds": orchestration.cpu_seconds,
        "unattempted_candidate_count": len(orchestration.unattempted_candidate_ids),
        "attempts": [item.to_dict() for item in orchestration.attempts],
        "executed_batches": summarize_executed_batches(orchestration.attempts),
    }


def _median_policy_metrics(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    keys = ("attempt_count", "completed_proofs", "exact_operation_reaches", "reports", "wall_seconds", "cpu_seconds")
    return {
        key: statistics.median(float(row.get(key) or 0.0) for row in rows)
        for key in keys
    }


def _available_run_id(root: Path) -> str:
    base = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    candidate = base
    index = 1
    while (root / candidate).exists():
        candidate = f"{base}-{index}"
        index += 1
    return candidate


def _freeze_route_case(
    state: CandidateState,
    *,
    score: float,
    stratum: str,
    source_evidence_dir: Path,
    corpus_dir: Path,
) -> Mapping[str, Any]:
    candidate_id = state.candidate_id
    source_binary = Path(str(state.target.get("path") or "")).resolve()
    source_export = Path(str(state.target.get("export_dir") or "")).resolve()
    source_evidence = source_evidence_dir / f"{candidate_id}.json"
    if not source_binary.is_file() or not source_export.is_dir() or not source_evidence.is_file():
        raise ValueError(f"candidate {candidate_id} lacks binary, export, or evidence input")
    binary_hash = _sha256_file(source_binary)
    frozen_binary = corpus_dir / "binaries" / binary_hash / source_binary.name
    if not frozen_binary.exists():
        frozen_binary.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_binary, frozen_binary)
    frozen_export = corpus_dir / "exports" / binary_hash / "decompiled"
    if not frozen_export.exists():
        frozen_export.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_export, frozen_export, symlinks=True)
    replacements = {
        str(source_binary): str(frozen_binary),
        str(source_export): str(frozen_export),
    }
    state_payload = _replace_paths(state.to_dict(), replacements)
    target = dict(state_payload.get("target") or {})
    target.update({"path": str(frozen_binary), "export_dir": str(frozen_export)})
    state_payload["target"] = target
    frozen_state = corpus_dir / "states" / f"{candidate_id}.json"
    _write_json(frozen_state, state_payload)
    evidence_payload = _replace_paths(json.loads(source_evidence.read_text()), replacements)
    frozen_evidence = corpus_dir / "evidence" / f"{candidate_id}.json"
    _write_json(frozen_evidence, evidence_payload)
    return {
        "candidate_id": candidate_id,
        "vulnerability_type": state.vulnerability_type,
        "stratum": stratum,
        "frozen_priority_score": score,
        "state_path": str(frozen_state.relative_to(corpus_dir)),
        "state_sha256": _sha256_file(frozen_state),
        "evidence_path": str(frozen_evidence.relative_to(corpus_dir)),
        "evidence_sha256": _sha256_file(frozen_evidence),
        "binary_path": str(frozen_binary.relative_to(corpus_dir)),
        "binary_sha256": binary_hash,
        "export_path": str(frozen_export.relative_to(corpus_dir)),
        "export_sha256": _tree_sha256(frozen_export),
    }


def _replace_paths(value: Any, replacements: Mapping[str, str]) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _replace_paths(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_paths(item, replacements) for item in value]
    if isinstance(value, str):
        updated = value
        for source, destination in replacements.items():
            updated = updated.replace(source, destination)
        return updated
    return value


def _tree_sha256(root: Path, ignored: set[str] | None = None) -> str:
    digest = hashlib.sha256()
    ignored_names = ignored or set()
    for path in sorted(Path(root).rglob("*"), key=lambda item: item.as_posix()):
        if path.name in ignored_names:
            continue
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode())
        if path.is_symlink():
            digest.update(b"L" + os.readlink(path).encode())
        elif path.is_file():
            digest.update(b"F" + oct(path.stat().st_mode & 0o7777).encode())
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        elif path.is_dir():
            digest.update(b"D")
    return digest.hexdigest()


def _file_inventory(root: Path, ignored: set[str] | None = None) -> list[Mapping[str, Any]]:
    ignored_names = ignored or set()
    return [
        {
            "path": str(path.relative_to(root)),
            "sha256": _sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
        for path in sorted(Path(root).rglob("*"))
        if path.is_file() and not path.is_symlink() and path.name not in ignored_names
    ]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _write_json(path: Path, payload: Any) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(path).with_suffix(Path(path).suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)
