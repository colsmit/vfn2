"""Frozen mixed-yield benchmark for budgeted proof-portfolio research."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import statistics
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.execution_envelope import discover_execution_envelope
from binary_agent.pipeline import CandidateState, load_candidate_states
from binary_agent.proof import proof_result_reportable
from binary_agent.proof_batching import summarize_executed_batches
from binary_agent.proof_routing import (
    ProofRouteRegistry,
    RouteExecutionContext,
    default_route_registry,
    execute_route_orchestration,
)
from binary_agent.research_corpus import analyzer_tree_sha256
from binary_agent.scheduling import ProofBudget
from binary_agent.yield_model import YieldTrainingRecord, fit_route_yield_model


PORTFOLIO_BENCHMARK_SCHEMA_VERSION = 1
DEFAULT_PORTFOLIO_CORPUS_ID = "mixed-proof-portfolio-v1"
PORTFOLIO_POLICIES = (
    "fifo",
    "static_rank",
    "fixed_route",
    "random",
    "exhaustive",
    "adaptive",
    "learned_adaptive",
)


def prepare_firmware_rootfs_fixture(juliet_manifest: Path, output_dir: Path) -> Path:
    """Materialize the frozen double-free pair inside a rootfs-shaped tree."""

    manifest_file = Path(juliet_manifest).expanduser().resolve()
    payload = _load_json(manifest_file)
    by_id = {
        str(item.get("id") or ""): item
        for item in payload.get("cases", []) or []
        if isinstance(item, Mapping)
    }
    required = ("cwe415-free-vulnerable", "cwe415-free-fixed")
    if any(case_id not in by_id for case_id in required):
        raise ValueError("Juliet manifest lacks the frozen CWE-415 vulnerable/fixed pair")
    output = Path(output_dir).expanduser().resolve()
    if output.exists():
        raise FileExistsError(f"firmware rootfs fixture already exists: {output}")
    binary_dir = output / "rootfs" / "usr" / "bin"
    binary_dir.mkdir(parents=True)
    rows = []
    try:
        for case_id in required:
            raw = by_id[case_id]
            source = manifest_file.parent / str(raw.get("binary_path") or "")
            if not source.is_file() or _sha256_file(source) != str(raw.get("binary_sha256") or ""):
                raise ValueError(f"frozen fixture binary failed integrity check: {case_id}")
            lane = "vulnerable" if case_id.endswith("-vulnerable") else "fixed"
            destination = binary_dir / f"double-free-{lane}"
            shutil.copy2(source, destination)
            rows.append(
                {
                    "id": case_id,
                    "lane": lane,
                    "path": str(destination.relative_to(output)),
                    "sha256": _sha256_file(destination),
                    "expected_reports": 1 if lane == "vulnerable" else 0,
                }
            )
        fixture_manifest = output / "fixture_manifest.json"
        _write_json(
            fixture_manifest,
            {
                "schema_version": 1,
                "artifact_kind": "compiled_firmware_rootfs_fixture",
                "source_manifest": str(manifest_file),
                "source_manifest_sha256": _sha256_file(manifest_file),
                "cases": rows,
            },
        )
        return fixture_manifest
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


@dataclass(frozen=True)
class _SourceCase:
    state: CandidateState
    evidence_path: Path
    binary_path: Path
    export_path: Path
    split: str
    expected_report: bool | None
    ground_truth_authority: str
    source_result_path: Path | None = None
    rootfs_path: Path | None = None
    stratum: str = ""


def build_portfolio_benchmark(
    output_root: Path,
    *,
    juliet_evaluation_summary: Path,
    firmware_run: Path,
    openwrt_manifest: Path,
    openwrt_rootfs: Path,
    repo_root: Path | None = None,
    corpus_id: str = DEFAULT_PORTFOLIO_CORPUS_ID,
) -> Path:
    """Freeze known-yield lifetime cases with real stripped firmware contention."""

    repository = (repo_root or Path.cwd()).expanduser().resolve()
    output = Path(output_root).expanduser()
    if not output.is_absolute():
        output = repository / output
    corpus = output.resolve() / corpus_id
    if corpus.exists():
        raise FileExistsError(f"frozen portfolio benchmark already exists: {corpus}")
    corpus.mkdir(parents=True)
    try:
        openwrt_runtime = corpus / "rootfs" / "openwrt"
        firmware_runtime = corpus / "rootfs" / "fixture"
        shutil.copytree(Path(openwrt_rootfs).expanduser().resolve(), openwrt_runtime, symlinks=True)
        fixture_source = _firmware_root_from_run(Path(firmware_run))
        shutil.copytree(fixture_source, firmware_runtime, symlinks=True)
        sources = _default_source_cases(
            Path(juliet_evaluation_summary),
            Path(firmware_run),
            Path(openwrt_manifest),
            openwrt_runtime=openwrt_runtime,
            firmware_runtime=firmware_runtime,
        )
        frozen_cases = [
            _freeze_source_case(source, corpus, index=index)
            for index, source in enumerate(sources, start=1)
        ]
        cases = [
            {**item, "sequence": index}
            for index, item in enumerate(
                sorted(frozen_cases, key=lambda row: str(row["candidate_id"])),
                start=1,
            )
        ]
        manifest = {
            "schema_version": PORTFOLIO_BENCHMARK_SCHEMA_VERSION,
            "artifact_kind": "frozen_mixed_yield_proof_portfolio",
            "corpus_id": corpus_id,
            "frozen_at": datetime.now(timezone.utc).isoformat(),
            "analyzer_sha256": analyzer_tree_sha256(repository),
            "ground_truth_scope": (
                "fixture cases have vulnerable-binary and prior schema-v2 proof authority; "
                "OpenWrt cases are unknown and measure operational contention only"
            ),
            "split_policy": "fixed_fixture_assignment_plus_sorted_openwrt_alternation",
            "cases": cases,
        }
        manifest_path = corpus / "frozen_manifest.json"
        _write_json(manifest_path, manifest)
        _write_json(
            corpus / "inventory.json",
            {
                "schema_version": 1,
                "artifact_kind": "proof_portfolio_inventory",
                "tree_sha256": _tree_sha256(corpus, ignored={"inventory.json"}),
                "file_count": sum(1 for path in corpus.rglob("*") if path.is_file()),
            },
        )
        return manifest_path
    except Exception:
        shutil.rmtree(corpus, ignore_errors=True)
        raise


def verify_portfolio_benchmark(manifest_path: Path) -> dict[str, Any]:
    manifest_file = Path(manifest_path).expanduser().resolve()
    payload = _load_json(manifest_file)
    if int(payload.get("schema_version") or 0) != PORTFOLIO_BENCHMARK_SCHEMA_VERSION:
        raise ValueError("unsupported proof portfolio schema")
    root = manifest_file.parent
    failures: list[dict[str, str]] = []
    rootfs_seen: set[str] = set()
    for raw in payload.get("cases", []) or []:
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
        if not export.is_dir() or _tree_sha256(export) != str(raw.get("export_sha256") or ""):
            failures.append({"candidate_id": candidate_id, "kind": "export", "reason": "missing_or_hash_mismatch"})
        rootfs_rel = str(raw.get("rootfs_path") or "")
        if rootfs_rel and rootfs_rel not in rootfs_seen:
            rootfs_seen.add(rootfs_rel)
            runtime = root / rootfs_rel
            if not runtime.is_dir() or _tree_sha256(runtime) != str(raw.get("rootfs_sha256") or ""):
                failures.append({"candidate_id": candidate_id, "kind": "rootfs", "reason": "missing_or_hash_mismatch"})
    split_counts = {
        split: sum(isinstance(item, Mapping) and item.get("split") == split for item in payload.get("cases", []) or [])
        for split in ("calibration", "holdout")
    }
    return {
        "schema_version": 1,
        "artifact_kind": "proof_portfolio_verification",
        "corpus_id": str(payload.get("corpus_id") or ""),
        "verified": not failures,
        "case_count": len(payload.get("cases", []) or []),
        "split_counts": split_counts,
        "known_positive_count": sum(
            isinstance(item, Mapping) and item.get("expected_report") is True
            for item in payload.get("cases", []) or []
        ),
        "unknown_count": sum(
            isinstance(item, Mapping) and item.get("expected_report") is None
            for item in payload.get("cases", []) or []
        ),
        "failures": failures,
    }


def evaluate_portfolio_benchmark(
    manifest_path: Path,
    output_root: Path,
    *,
    candidate_budget: int = 2,
    wall_budget_seconds: float = 30.0,
    cpu_budget_seconds: float = 30.0,
    timeout_seconds: float = 3.0,
    repetitions: int = 2,
    policies: Sequence[str] = PORTFOLIO_POLICIES,
    ghidra_dir: Path | None = None,
    repo_root: Path | None = None,
    registry: ProofRouteRegistry | None = None,
) -> dict[str, Any]:
    """Run equal-budget policies on calibration and untouched holdout splits."""

    repository = (repo_root or Path.cwd()).expanduser().resolve()
    manifest_file = Path(manifest_path).expanduser().resolve()
    verification = verify_portfolio_benchmark(manifest_file)
    if not verification["verified"]:
        raise ValueError(f"portfolio verification failed: {verification['failures']}")
    manifest = _load_json(manifest_file)
    root = manifest_file.parent
    seed = _sha256_file(manifest_file)
    selected_policies = tuple(dict.fromkeys(str(item) for item in policies))
    unknown = set(selected_policies) - set(PORTFOLIO_POLICIES)
    if unknown:
        raise ValueError(f"unsupported portfolio policies: {sorted(unknown)}")
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
    split_results: dict[str, Any] = {}
    yield_model = None
    for split in ("calibration", "holdout"):
        split_cases = [dict(item) for item in manifest.get("cases", []) if isinstance(item, Mapping) and item.get("split") == split]
        states = [CandidateState.from_dict(_load_json(root / str(item["state_path"]))) for item in split_cases]
        by_id = {state.candidate_id: raw for state, raw in zip(states, split_cases)}
        policy_rows: dict[str, Any] = {}
        for policy in selected_policies:
            rows = []
            for repetition in range(1, max(1, int(repetitions)) + 1):
                repetition_dir = run_dir / split / policy / f"repeat-{repetition}"

                def context_for_state(state: CandidateState) -> RouteExecutionContext:
                    raw = by_id[state.candidate_id]
                    binary = root / str(raw["binary_path"])
                    rootfs_rel = str(raw.get("rootfs_path") or "")
                    rootfs = root / rootfs_rel if rootfs_rel else None
                    envelope = discover_execution_envelope(
                        binary,
                        rootfs_path=rootfs,
                        cache_dir=run_dir / "execution_envelopes" / "cache",
                    )
                    return RouteExecutionContext(
                        binary_path=binary,
                        export_dir=root / str(raw["export_path"]),
                        evidence_dir=root / "evidence",
                        output_dir=repetition_dir / "routes",
                        timeout_seconds=max(0.1, float(timeout_seconds)),
                        ghidra_dir=Path(ghidra_dir).expanduser().resolve() if ghidra_dir else None,
                        execution_envelope=envelope,
                        rootfs_path=rootfs,
                    )

                orchestration = execute_route_orchestration(
                    states,
                    context_for_state=context_for_state,
                    budget=budget,
                    policy=policy,
                    registry=selected_registry,
                    policy_seed=seed,
                    route_yields=(
                        yield_model.predictions(states)
                        if policy == "learned_adaptive" and yield_model is not None
                        else None
                    ),
                )
                row = _evaluation_row(orchestration, by_id, {state.candidate_id: state for state in states})
                _write_json(repetition_dir / "portfolio_result.json", row)
                rows.append(row)
            policy_rows[policy] = {"runs": rows, "median": _median_rows(rows)}
        if split == "calibration":
            training_source = policy_rows.get("adaptive") or next(iter(policy_rows.values()))
            seen_training: set[tuple[str, str]] = set()
            training_records = []
            for attempt in training_source["runs"][0].get("attempts", []):
                candidate_id = str(attempt.get("candidate_id") or "")
                route = str(attempt.get("route") or "")
                if (candidate_id, route) in seen_training or candidate_id not in by_id:
                    continue
                seen_training.add((candidate_id, route))
                training_records.append(
                    YieldTrainingRecord(
                        candidate_id,
                        str(by_id[candidate_id].get("vulnerability_type") or ""),
                        route,
                        str(attempt.get("status") or "inconclusive"),
                        "calibration",
                    )
                )
            yield_model = fit_route_yield_model(training_records)
            _write_json(run_dir / "calibration_route_yield_model.json", yield_model.to_dict())
        oracle = portfolio_oracle_bound(split_cases, candidate_budget)
        adaptive = policy_rows.get("adaptive", {}).get("median", {})
        baselines = [
            row["median"]
            for name, row in policy_rows.items()
            if name != "adaptive"
        ]
        strongest_reports = max((float(item.get("reports") or 0.0) for item in baselines), default=0.0)
        strongest_exact = max((float(item.get("exact_operation_reaches") or 0.0) for item in baselines), default=0.0)
        split_results[split] = {
            "case_count": len(split_cases),
            "known_positive_count": sum(item.get("expected_report") is True for item in split_cases),
            "policies": policy_rows,
            "oracle_upper_bound": oracle,
            "adaptive_report_regret": max(0.0, oracle["max_reports"] - float(adaptive.get("reports") or 0.0)),
            "adaptive_beats_strong_baseline": bool(
                baselines
                and (
                float(adaptive.get("reports") or 0.0) > strongest_reports
                or (
                    float(adaptive.get("reports") or 0.0) == strongest_reports
                    and float(adaptive.get("exact_operation_reaches") or 0.0) > strongest_exact
                )
                )
            ),
        }
    holdout = split_results["holdout"]
    learned = holdout["policies"].get("learned_adaptive", {}).get("median", {})
    static = holdout["policies"].get("static_rank", {}).get("median", {})
    result = {
        "schema_version": 1,
        "artifact_kind": "proof_portfolio_ablation",
        "run_id": run_id,
        "run_dir": str(run_dir),
        "corpus_id": str(manifest.get("corpus_id") or ""),
        "analyzer_sha256": analyzer_tree_sha256(repository),
        "frozen_analyzer_sha256": str(manifest.get("analyzer_sha256") or ""),
        "budget": {
            "max_candidates": budget.max_candidates,
            "max_wall_seconds": budget.max_wall_seconds,
            "max_estimated_cpu_seconds": budget.max_estimated_cpu_seconds,
        },
        "repetitions": max(1, int(repetitions)),
        "splits": split_results,
        "supports_adaptive_holdout_claim": bool(holdout["adaptive_beats_strong_baseline"]),
        "supports_learned_over_static_holdout_claim": bool(
            learned
            and static
            and (
                float(learned.get("reports") or 0.0) > float(static.get("reports") or 0.0)
                or (
                    float(learned.get("reports") or 0.0) == float(static.get("reports") or 0.0)
                    and float(learned.get("exact_operation_reaches") or 0.0)
                    > float(static.get("exact_operation_reaches") or 0.0)
                )
            )
        ),
        "yield_model_path": str(run_dir / "calibration_route_yield_model.json") if yield_model else "",
        "interpretation": (
            "Adaptive improved held-out proof yield over the strongest measured non-oracle baseline."
            if holdout["adaptive_beats_strong_baseline"]
            else "The held-out run does not establish an adaptive advantage over the strongest measured baseline."
        ),
    }
    _write_json(run_dir / "portfolio_benchmark_summary.json", result)
    return result


def portfolio_oracle_bound(cases: Sequence[Mapping[str, Any]], candidate_budget: int) -> dict[str, Any]:
    positives = sorted(
        str(item.get("candidate_id") or "")
        for item in cases
        if item.get("expected_report") is True
    )
    selected = positives[: max(0, int(candidate_budget))]
    return {
        "authority": "evaluation_only_expected_outcomes_not_available_to_production_policies",
        "max_reports": len(selected),
        "selected_candidate_ids": selected,
    }


def _default_source_cases(
    juliet_summary: Path,
    firmware_run: Path,
    openwrt_manifest: Path,
    *,
    openwrt_runtime: Path,
    firmware_runtime: Path,
) -> list[_SourceCase]:
    summary = _load_json(juliet_summary.expanduser().resolve())
    juliet = {str(item.get("id") or ""): item for item in summary.get("cases", []) if isinstance(item, Mapping)}
    sources = [
        _source_from_run(
            Path(str(juliet["cwe401-malloc-vulnerable"]["run_dir"])),
            split="calibration",
            expected_report=True,
            authority="Juliet vulnerable lane plus prior schema-v2 report",
            binary_path=_toolchain_command_binary(juliet["cwe401-malloc-vulnerable"]),
        ),
        _source_from_run(
            Path(str(juliet["cwe416-free-vulnerable"]["run_dir"])),
            split="holdout",
            expected_report=True,
            authority="Juliet vulnerable lane; expected proof uses exact released generation",
            binary_path=_toolchain_command_binary(juliet["cwe416-free-vulnerable"]),
        ),
        _source_from_run(
            firmware_run.expanduser().resolve(),
            split="holdout",
            expected_report=True,
            authority="rootfs-contained stripped vulnerable fixture plus prior schema-v2 report",
            rootfs_path=firmware_runtime,
        ),
    ]
    openwrt_file = openwrt_manifest.expanduser().resolve()
    openwrt = _load_json(openwrt_file)
    openwrt_root = openwrt_file.parent
    rows = sorted(
        (dict(item) for item in openwrt.get("cases", []) if isinstance(item, Mapping)),
        key=lambda item: str(item.get("candidate_id") or ""),
    )[:8]
    for index, raw in enumerate(rows):
        state = CandidateState.from_dict(_load_json(openwrt_root / str(raw["state_path"])))
        sources.append(
            _SourceCase(
                state=state,
                evidence_path=openwrt_root / str(raw["evidence_path"]),
                binary_path=openwrt_root / str(raw["binary_path"]),
                export_path=openwrt_root / str(raw["export_path"]),
                split="calibration" if index % 2 == 0 else "holdout",
                expected_report=None,
                ground_truth_authority="unknown real-firmware candidate; no vulnerability label asserted",
                rootfs_path=openwrt_runtime,
                stratum=str(raw.get("stratum") or "openwrt_unknown"),
            )
        )
    return sources


def _source_from_run(
    run_dir: Path,
    *,
    split: str,
    expected_report: bool | None,
    authority: str,
    rootfs_path: Path | None = None,
    binary_path: Path | None = None,
) -> _SourceCase:
    states = [state for state in load_candidate_states(run_dir / "promotion" / "candidate_states.json") if state.vulnerability_type in {"memory_leak", "double_free", "use_after_free"}]
    if len(states) != 1:
        raise ValueError(f"expected exactly one lifetime candidate in {run_dir}, found {len(states)}")
    state = states[0].with_updates(status="proof_ready")
    evidence = run_dir / "evidence" / f"{state.candidate_id}.json"
    evidence_payload = _load_json(evidence)
    binary_raw = binary_path or Path(str(state.target.get("path") or ""))
    binary = Path(binary_raw).expanduser().resolve()
    export_raw = str(state.target.get("export_dir") or "")
    if not export_raw:
        context = evidence_payload.get("decompiler_context")
        export_raw = str(context.get("export_dir") or "") if isinstance(context, Mapping) else ""
    export = Path(export_raw).expanduser().resolve()
    report = run_dir / "report" / "vulnerabilities.json"
    return _SourceCase(
        state=state,
        evidence_path=evidence,
        binary_path=binary,
        export_path=export,
        split=split,
        expected_report=expected_report,
        ground_truth_authority=authority,
        source_result_path=report if report.is_file() else None,
        rootfs_path=rootfs_path,
        stratum="known_positive" if expected_report is True else "known_negative" if expected_report is False else "unknown",
    )


def _toolchain_command_binary(case: Mapping[str, Any]) -> Path:
    command = [str(item) for item in case.get("command", []) or []]
    try:
        module_index = command.index("binary_agent.cli.toolchain")
        return Path(command[module_index + 1])
    except (ValueError, IndexError) as exc:
        raise ValueError("research evaluation case lacks a toolchain binary command") from exc


def _freeze_source_case(source: _SourceCase, corpus: Path, *, index: int) -> dict[str, Any]:
    for path, kind in ((source.evidence_path, "evidence"), (source.binary_path, "binary")):
        if not path.is_file():
            raise ValueError(f"portfolio source {kind} is missing: {path}")
    if not source.export_path.is_dir():
        raise ValueError(f"portfolio source export is missing: {source.export_path}")
    binary_hash = _sha256_file(source.binary_path)
    frozen_binary = corpus / "binaries" / binary_hash / source.binary_path.name
    if not frozen_binary.exists():
        frozen_binary.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source.binary_path, frozen_binary)
    frozen_export = corpus / "exports" / binary_hash / "decompiled"
    if not frozen_export.exists():
        frozen_export.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source.export_path, frozen_export, symlinks=True)
    frozen_rootfs: Path | None = None
    rootfs_hash = ""
    if source.rootfs_path:
        frozen_rootfs = source.rootfs_path
        rootfs_hash = _tree_sha256(frozen_rootfs)
    replacements = {
        str(source.binary_path): str(frozen_binary),
        str(source.export_path): str(frozen_export),
    }
    original_rootfs = str(source.state.target.get("firmware_target") or source.state.target.get("rootfs_path") or "")
    if original_rootfs and frozen_rootfs:
        replacements[original_rootfs] = str(frozen_rootfs)
    state_payload = _replace_paths(source.state.to_dict(), replacements)
    target = dict(state_payload.get("target") or {})
    target.update({"path": str(frozen_binary), "export_dir": str(frozen_export)})
    if frozen_rootfs:
        target["firmware_target"] = str(frozen_rootfs)
    state_payload["target"] = target
    state_payload["status"] = "proof_ready"
    state_path = corpus / "states" / f"{source.state.candidate_id}.json"
    _write_json(state_path, state_payload)
    evidence_payload = _replace_paths(_load_json(source.evidence_path), replacements)
    evidence_path = corpus / "evidence" / f"{source.state.candidate_id}.json"
    _write_json(evidence_path, evidence_payload)
    source_result_hash = _sha256_file(source.source_result_path) if source.source_result_path and source.source_result_path.is_file() else ""
    return {
        "sequence": index,
        "candidate_id": source.state.candidate_id,
        "vulnerability_type": source.state.vulnerability_type,
        "split": source.split,
        "stratum": source.stratum,
        "expected_report": source.expected_report,
        "ground_truth_authority": source.ground_truth_authority,
        "source_result_sha256": source_result_hash,
        "state_path": str(state_path.relative_to(corpus)),
        "state_sha256": _sha256_file(state_path),
        "evidence_path": str(evidence_path.relative_to(corpus)),
        "evidence_sha256": _sha256_file(evidence_path),
        "binary_path": str(frozen_binary.relative_to(corpus)),
        "binary_sha256": binary_hash,
        "export_path": str(frozen_export.relative_to(corpus)),
        "export_sha256": _tree_sha256(frozen_export),
        "rootfs_path": str(frozen_rootfs.relative_to(corpus)) if frozen_rootfs else "",
        "rootfs_sha256": rootfs_hash,
    }


def _evaluation_row(
    orchestration: Any,
    by_id: Mapping[str, Mapping[str, Any]],
    states: Mapping[str, CandidateState],
) -> dict[str, Any]:
    attempts = list(orchestration.attempts)
    report_ids = [
        item.candidate_id
        for item in attempts
        if proof_result_reportable(states[item.candidate_id], item.proof_result)
    ]
    known_true = {candidate_id for candidate_id, raw in by_id.items() if raw.get("expected_report") is True}
    known_false = {candidate_id for candidate_id, raw in by_id.items() if raw.get("expected_report") is False}
    return {
        "candidate_order": [item.candidate_id for item in attempts],
        "route_order": [item.route for item in attempts],
        "attempts": [item.to_dict() for item in attempts],
        "attempt_count": len(attempts),
        "completed_proofs": sum(item.status in {"proven", "refuted"} for item in attempts),
        "exact_operation_reaches": sum(item.proof_result.exact_operation_reached for item in attempts),
        "reports": len(report_ids),
        "report_candidate_ids": report_ids,
        "known_positive_reports": len(set(report_ids) & known_true),
        "known_false_reports": len(set(report_ids) & known_false),
        "setup_reuse_count": sum(item.setup_reused for item in attempts),
        "wall_seconds": orchestration.wall_seconds,
        "cpu_seconds": orchestration.cpu_seconds,
        "stop_reason": orchestration.stop_reason,
        "blocker_counts": _counts(item.blocker for item in attempts if item.blocker),
        "executed_batches": summarize_executed_batches(attempts),
    }


def _median_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, float]:
    keys = (
        "attempt_count",
        "completed_proofs",
        "exact_operation_reaches",
        "reports",
        "known_positive_reports",
        "known_false_reports",
        "setup_reuse_count",
        "wall_seconds",
        "cpu_seconds",
    )
    return {
        key: statistics.median(float(row.get(key) or 0.0) for row in rows)
        for key in keys
    }


def _firmware_root_from_run(run_dir: Path) -> Path:
    states = load_candidate_states(run_dir.expanduser().resolve() / "promotion" / "candidate_states.json")
    root = next((Path(str(state.target.get("firmware_target") or "")) for state in states if state.target.get("firmware_target")), None)
    if root is None or not root.is_dir():
        raise ValueError("firmware run does not identify an existing rootfs")
    return root


def _replace_paths(value: Any, replacements: Mapping[str, str]) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _replace_paths(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_paths(item, replacements) for item in value]
    if isinstance(value, str):
        for source, destination in replacements.items():
            value = value.replace(source, destination)
    return value


def _counts(values: Sequence[str] | Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[str(value)] = counts.get(str(value), 0) + 1
    return counts


def _available_run_id(root: Path) -> str:
    base = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    candidate = base
    suffix = 1
    while (root / candidate).exists():
        suffix += 1
        candidate = f"{base}-{suffix}"
    return candidate


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
            digest.update(_sha256_file(path).encode())
        elif path.is_dir():
            digest.update(b"D")
    return digest.hexdigest()


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
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)
