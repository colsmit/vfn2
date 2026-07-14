"""Benchmark harness that normalizes capability sweep and known-overflow runs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.capability_sweep import (
    CAPABILITY_SWEEP_ROWS,
    CAPABILITY_SWEEP_SUMMARY,
    run_capability_sweep,
)
from binary_agent.utils.time import utc_timestamp


CAPABILITY_BENCHMARK_SUMMARY = "capability_benchmark_summary.json"
CAPABILITY_BENCHMARK_RUNS = "capability_benchmark_runs.json"
CAPABILITY_BENCHMARK_DELTA = "capability_benchmark_delta.json"
CAPABILITY_BENCHMARK_SUMMARY_ARTIFACT_KIND = "capability_benchmark_summary"
CAPABILITY_BENCHMARK_RUNS_ARTIFACT_KIND = "capability_benchmark_runs"
CAPABILITY_BENCHMARK_DELTA_ARTIFACT_KIND = "capability_benchmark_delta"

CAPABILITY_SWEEP_KIND = "capability_sweep"
KNOWN_OVERFLOW_CORPUS_KIND = "known_overflow_corpus"
KNOWN_BENCHMARK_KINDS = {CAPABILITY_SWEEP_KIND, KNOWN_OVERFLOW_CORPUS_KIND}

PASSED_STATUS = "passed"
FAILED_STATUS = "failed"
COMMAND_FAILED_STATUS = "command_failed"
FAILED_MISSING_INPUT_STATUS = "failed_missing_input"
SKIPPED_MISSING_INPUT_STATUS = "skipped_missing_input"

_LOWER_IS_BETTER_FRAGMENTS = (
    "blocked",
    "blocker",
    "error",
    "failed",
    "false_positive",
    "missing",
    "regressed",
    "runtime_seconds",
    "skipped",
    "targets_with_errors",
    "unexpected",
)


@dataclass(frozen=True)
class BenchmarkEntry:
    id: str
    kind: str
    label: str = ""
    required: bool = True
    summary_path: Path | None = None
    targets_json: Path | None = None
    manifest: Path | None = None
    lanes: tuple[str, ...] = ()
    cases: tuple[str, ...] = ()
    regression_subset: bool = False
    requires: tuple[str, ...] = ()
    thresholds: Mapping[str, float] = field(default_factory=dict)
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BenchmarkSuite:
    path: Path
    suite_id: str
    description: str
    benchmarks: tuple[BenchmarkEntry, ...]
    schema_version: int = 1


@dataclass
class BenchmarkRunRow:
    id: str
    kind: str
    label: str = ""
    required: bool = True
    status: str = PASSED_STATUS
    runtime_seconds: float = 0.0
    output_dir: str = ""
    summary_path: str = ""
    rows_path: str = ""
    passed_count: int = 0
    failed_count: int = 0
    target_count: int = 0
    case_count: int = 0
    blocker_count: int = 0
    expected_positive_misses: int = 0
    negative_total: int = 0
    negative_passed: int = 0
    negative_blocked: int = 0
    clean_negatives: int = 0
    provenance_complete: int = 0
    provenance_total: int = 0
    skipped_reason: str = ""
    exit_code: int | None = None
    command: list[str] = field(default_factory=list)
    artifact_paths: dict[str, str] = field(default_factory=dict)
    blockers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    threshold_failures: list[str] = field(default_factory=list)
    metrics: dict[str, int | float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        if self.status == SKIPPED_MISSING_INPUT_STATUS and not self.required:
            return True
        return self.status == PASSED_STATUS and not self.threshold_failures and not self.errors

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["success"] = self.success
        return payload


@dataclass(frozen=True)
class BenchmarkSummary:
    suite_id: str
    output_dir: Path
    rows: tuple[BenchmarkRunRow, ...]
    generated_at: str = field(default_factory=utc_timestamp)
    schema_version: int = 1
    delta_path: str = ""

    @property
    def totals(self) -> dict[str, Any]:
        required_rows = [row for row in self.rows if row.required]
        optional_rows = [row for row in self.rows if not row.required]
        required_failed = sum(1 for row in required_rows if not row.success)
        return {
            "benchmarks": len(self.rows),
            "required": len(required_rows),
            "optional": len(optional_rows),
            "passed": sum(row.passed_count for row in self.rows),
            "failed": sum(row.failed_count for row in self.rows),
            "required_failed": required_failed,
            "optional_failed": sum(1 for row in optional_rows if row.status not in {PASSED_STATUS, SKIPPED_MISSING_INPUT_STATUS}),
            "optional_skipped": sum(1 for row in optional_rows if row.status == SKIPPED_MISSING_INPUT_STATUS),
            "target_count": sum(row.target_count for row in self.rows),
            "case_count": sum(row.case_count for row in self.rows),
            "blockers": sum(row.blocker_count for row in self.rows),
            "errors": sum(len(row.errors) for row in self.rows),
            "threshold_failures": sum(len(row.threshold_failures) for row in self.rows),
            "expected_positive_misses": sum(row.expected_positive_misses for row in self.rows),
            "negative_total": sum(row.negative_total for row in self.rows),
            "negative_passed": sum(row.negative_passed for row in self.rows),
            "negative_blocked": sum(row.negative_blocked for row in self.rows),
            "clean_negatives": sum(row.clean_negatives for row in self.rows),
            "provenance_complete": sum(row.provenance_complete for row in self.rows),
            "provenance_total": sum(row.provenance_total for row in self.rows),
            "runtime_seconds": round(sum(row.runtime_seconds for row in self.rows), 4),
        }

    @property
    def success(self) -> bool:
        return int(self.totals["required_failed"]) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_kind": CAPABILITY_BENCHMARK_SUMMARY_ARTIFACT_KIND,
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "suite_id": self.suite_id,
            "success": self.success,
            "output_dir": str(self.output_dir),
            "delta_path": self.delta_path,
            "totals": self.totals,
            "runs": [row.to_dict() for row in self.rows],
        }

    def write(self) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        runs_path = self.output_dir / CAPABILITY_BENCHMARK_RUNS
        runs_path.write_text(
            json.dumps(
                {
                    "artifact_kind": CAPABILITY_BENCHMARK_RUNS_ARTIFACT_KIND,
                    "schema_version": self.schema_version,
                    "generated_at": self.generated_at,
                    "suite_id": self.suite_id,
                    "runs": [row.to_dict() for row in self.rows],
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        summary_path = self.output_dir / CAPABILITY_BENCHMARK_SUMMARY
        summary_path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        return summary_path


def load_benchmark_suite(path: Path) -> BenchmarkSuite:
    suite_path = Path(path).resolve()
    payload = json.loads(suite_path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError(f"{path} must contain a JSON object")
    raw_benchmarks = payload.get("benchmarks")
    if not isinstance(raw_benchmarks, Sequence) or isinstance(raw_benchmarks, (str, bytes, bytearray)):
        raise ValueError(f"{path} must contain a benchmarks list")
    suite_id = str(payload.get("suite_id") or suite_path.stem)
    benchmarks = tuple(
        _entry_from_dict(item, base_dir=suite_path.parent)
        for item in raw_benchmarks
        if isinstance(item, Mapping)
    )
    if not benchmarks:
        raise ValueError(f"{path} did not contain any benchmark entries")
    return BenchmarkSuite(
        path=suite_path,
        suite_id=_safe_name(suite_id),
        description=str(payload.get("description") or ""),
        schema_version=int(payload.get("schema_version") or 1),
        benchmarks=benchmarks,
    )


def run_capability_benchmark(
    suite_json: Path,
    output_dir: Path,
    *,
    baseline: Path | None = None,
    overwrite: bool = False,
) -> BenchmarkSummary:
    suite = load_benchmark_suite(suite_json)
    output_root = Path(output_dir).resolve()
    rows = tuple(_run_entry(suite, entry, output_root / entry.id, overwrite=overwrite) for entry in suite.benchmarks)
    summary = BenchmarkSummary(suite_id=suite.suite_id, output_dir=output_root, rows=rows, schema_version=suite.schema_version)
    summary_path = summary.write()
    if baseline is not None:
        baseline_payload = _load_json(Path(baseline))
        current_payload = _load_json(summary_path)
        delta_path = write_benchmark_delta(current_payload, baseline_payload, output_root)
        summary = BenchmarkSummary(
            suite_id=suite.suite_id,
            output_dir=output_root,
            rows=rows,
            generated_at=summary.generated_at,
            schema_version=suite.schema_version,
            delta_path=str(delta_path),
        )
        summary.write()
    return summary


def normalize_capability_sweep_summary(
    payload: Mapping[str, Any],
    *,
    entry: BenchmarkEntry,
    output_dir: Path,
    summary_path: Path,
    runtime_seconds: float = 0.0,
    exit_code: int | None = None,
) -> BenchmarkRunRow:
    totals = _mapping(payload.get("totals"))
    targets = _sequence(payload.get("targets"))
    target_count = _safe_int(payload.get("target_count"), len(targets))
    targets_with_errors = _safe_int(totals.get("targets_with_errors"))
    target_rows = [item for item in targets if isinstance(item, Mapping)]
    blockers = _collect_sweep_blockers(target_rows)
    passed_targets = sum(
        1
        for row in target_rows
        if not _sequence(row.get("blockers")) and not _sequence(row.get("errors"))
    )
    blocked_targets = sum(
        1
        for row in target_rows
        if _sequence(row.get("blockers")) and not _sequence(row.get("errors"))
    )
    expected_negative_count = sum(
        len(_sequence(_mapping(row.get("metadata")).get("expected_negatives"))) for row in target_rows
    )
    metrics = {
        **_flatten_numeric_mapping(totals),
        "target_count": target_count,
        "passed": passed_targets,
        "failed": max(0, target_count - passed_targets),
        "blocked": blocked_targets,
        "expected_negative_count": expected_negative_count,
        "negative_passed": _safe_int(totals.get("rejected_negatives")),
        "clean_negatives": _safe_int(totals.get("rejected_negatives")),
        "negative_blocked": _safe_int(totals.get("blocked_negatives")),
        "expected_positive_misses": _safe_int(totals.get("missing_expected_positives")),
        "target_provenance_complete": sum(1 for row in target_rows if _mapping(row.get("target_provenance"))),
        "provenance_total": target_count,
    }
    row = BenchmarkRunRow(
        id=entry.id,
        kind=entry.kind,
        label=entry.label,
        required=entry.required,
        status=PASSED_STATUS if passed_targets == target_count else FAILED_STATUS,
        runtime_seconds=round(runtime_seconds, 4),
        output_dir=str(output_dir),
        summary_path=str(summary_path),
        rows_path=str(summary_path.parent / CAPABILITY_SWEEP_ROWS),
        passed_count=passed_targets,
        failed_count=max(0, target_count - passed_targets),
        target_count=target_count,
        blocker_count=len(blockers),
        expected_positive_misses=_safe_int(totals.get("missing_expected_positives")),
        negative_total=expected_negative_count,
        negative_passed=_safe_int(totals.get("rejected_negatives")),
        negative_blocked=_safe_int(totals.get("blocked_negatives")),
        clean_negatives=_safe_int(totals.get("rejected_negatives")),
        provenance_complete=sum(1 for row_payload in target_rows if _mapping(row_payload.get("target_provenance"))),
        provenance_total=target_count,
        exit_code=exit_code,
        artifact_paths={
            key: str(path)
            for key, path in {
                "summary": summary_path,
                "targets": summary_path.parent / CAPABILITY_SWEEP_ROWS,
            }.items()
            if path.exists()
        },
        blockers=blockers,
        metrics=metrics,
        metadata={"artifact_kind": payload.get("artifact_kind", ""), "source": "capability_sweep"},
    )
    _apply_thresholds(row, entry.thresholds)
    return row


def normalize_known_overflow_summary(
    payload: Mapping[str, Any],
    *,
    entry: BenchmarkEntry,
    output_dir: Path,
    summary_path: Path,
    runtime_seconds: float = 0.0,
    exit_code: int | None = None,
) -> BenchmarkRunRow:
    cases = [item for item in _sequence(payload.get("cases")) if isinstance(item, Mapping)]
    passed = _safe_int(payload.get("passed"), sum(1 for item in cases if item.get("passed")))
    failed = _safe_int(payload.get("failed"), max(0, len(cases) - passed))
    case_count = len(cases) if cases else passed + failed
    expected_positive_misses = sum(
        1 for case in cases if str(case.get("expected_outcome") or "") == "caught" and not bool(case.get("passed"))
    )
    blockers = _collect_known_overflow_blockers(cases)
    provenance_complete = _safe_int(
        payload.get("provenance_complete"),
        sum(1 for case in cases if not _sequence(case.get("missing_provenance_fields"))),
    )
    provenance_total = _safe_int(payload.get("provenance_total"), case_count)
    metrics = {
        **_flatten_numeric_mapping({key: value for key, value in payload.items() if key != "cases"}),
        "case_count": case_count,
        "passed": passed,
        "failed": failed,
        "expected_positive_misses": expected_positive_misses,
        "negative_passed": _safe_int(payload.get("negative_passed")),
        "negative_total": _safe_int(payload.get("negative_total")),
        "clean_negatives": _safe_int(payload.get("clean_negatives")),
        "provenance_complete": provenance_complete,
        "provenance_total": provenance_total,
    }
    row = BenchmarkRunRow(
        id=entry.id,
        kind=entry.kind,
        label=entry.label,
        required=entry.required,
        status=PASSED_STATUS if failed == 0 and exit_code in (None, 0) else FAILED_STATUS,
        runtime_seconds=round(runtime_seconds, 4),
        output_dir=str(output_dir),
        summary_path=str(summary_path),
        passed_count=passed,
        failed_count=failed,
        case_count=case_count,
        blocker_count=len(blockers),
        expected_positive_misses=expected_positive_misses,
        negative_total=_safe_int(payload.get("negative_total")),
        negative_passed=_safe_int(payload.get("negative_passed")),
        negative_blocked=_safe_int(payload.get("negative_blocked")),
        clean_negatives=_safe_int(payload.get("clean_negatives")),
        provenance_complete=provenance_complete,
        provenance_total=provenance_total,
        exit_code=exit_code,
        artifact_paths={"summary": str(summary_path)} if summary_path.exists() else {},
        blockers=blockers,
        metrics=metrics,
        metadata={"source": "known_overflow_corpus"},
    )
    if exit_code not in (None, 0):
        row.errors.append(f"command_exit_{exit_code}")
    _apply_thresholds(row, entry.thresholds)
    return row


def write_benchmark_delta(current: Mapping[str, Any], baseline: Mapping[str, Any], output_dir: Path) -> Path:
    suite_id = str(current.get("suite_id") or baseline.get("suite_id") or "")
    current_metrics = _summary_metric_map(current)
    baseline_metrics = _summary_metric_map(baseline)
    rows = [
        _delta_row(key, baseline_metrics.get(key), current_metrics.get(key))
        for key in sorted(set(current_metrics) | set(baseline_metrics))
    ]
    payload = {
        "artifact_kind": CAPABILITY_BENCHMARK_DELTA_ARTIFACT_KIND,
        "schema_version": 1,
        "generated_at": utc_timestamp(),
        "suite_id": suite_id,
        "metrics": rows,
    }
    output_path = Path(output_dir) / CAPABILITY_BENCHMARK_DELTA
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output_path


def _run_entry(suite: BenchmarkSuite, entry: BenchmarkEntry, output_dir: Path, *, overwrite: bool) -> BenchmarkRunRow:
    output_dir.mkdir(parents=True, exist_ok=True)
    missing_inputs = _missing_inputs(entry)
    if missing_inputs:
        return _missing_input_row(entry, output_dir, missing_inputs)
    if entry.summary_path is not None:
        return _normalize_existing_summary(entry, output_dir, entry.summary_path)
    if entry.kind == CAPABILITY_SWEEP_KIND:
        return _run_capability_sweep_entry(entry, output_dir, overwrite=overwrite)
    if entry.kind == KNOWN_OVERFLOW_CORPUS_KIND:
        return _run_known_overflow_entry(suite, entry, output_dir, overwrite=overwrite)
    raise ValueError(f"unsupported benchmark kind: {entry.kind}")


def _normalize_existing_summary(entry: BenchmarkEntry, output_dir: Path, summary_path: Path) -> BenchmarkRunRow:
    payload = _load_json(summary_path)
    if entry.kind == CAPABILITY_SWEEP_KIND:
        return normalize_capability_sweep_summary(payload, entry=entry, output_dir=output_dir, summary_path=summary_path)
    return normalize_known_overflow_summary(payload, entry=entry, output_dir=output_dir, summary_path=summary_path)


def _run_capability_sweep_entry(entry: BenchmarkEntry, output_dir: Path, *, overwrite: bool) -> BenchmarkRunRow:
    assert entry.targets_json is not None
    started = time.monotonic()
    try:
        summary = run_capability_sweep(entry.targets_json, output_dir, overwrite=overwrite)
        runtime = time.monotonic() - started
        return normalize_capability_sweep_summary(
            summary.to_dict(),
            entry=entry,
            output_dir=output_dir,
            summary_path=output_dir / CAPABILITY_SWEEP_SUMMARY,
            runtime_seconds=runtime,
            exit_code=0,
        )
    except Exception as exc:
        runtime = time.monotonic() - started
        return BenchmarkRunRow(
            id=entry.id,
            kind=entry.kind,
            label=entry.label,
            required=entry.required,
            status=COMMAND_FAILED_STATUS,
            runtime_seconds=round(runtime, 4),
            output_dir=str(output_dir),
            errors=[f"{type(exc).__name__}:{str(exc)[:500]}"],
        )


def _run_known_overflow_entry(
    suite: BenchmarkSuite,
    entry: BenchmarkEntry,
    output_dir: Path,
    *,
    overwrite: bool,
) -> BenchmarkRunRow:
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "run_known_overflow_corpus.py"
    summary_path = output_dir / "summary.json"
    corpus_output = output_dir / "corpus"
    command = [sys.executable, str(script_path)]
    if entry.manifest is not None:
        command.extend(["--manifest", str(entry.manifest)])
    if entry.regression_subset:
        command.append("--regression-subset")
    for lane in entry.lanes:
        command.extend(["--lane", lane])
    for case in entry.cases:
        command.extend(["--case", case])
    command.extend(["--output-root", str(corpus_output), "--summary", str(summary_path)])
    _append_known_overflow_args(command, entry.args, suite.path.parent)
    if overwrite or bool(entry.args.get("overwrite", False)):
        command.append("--overwrite")

    env = os.environ.copy()
    src_path = str(repo_root / "src")
    env["PYTHONPATH"] = src_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    started = time.monotonic()
    completed = subprocess.run(command, cwd=repo_root, env=env, text=True, capture_output=True, check=False)
    runtime = time.monotonic() - started
    stdout_log = output_dir / "known_overflow.stdout.log"
    stderr_log = output_dir / "known_overflow.stderr.log"
    stdout_log.write_text(completed.stdout, encoding="utf-8")
    stderr_log.write_text(completed.stderr, encoding="utf-8")
    if summary_path.exists():
        row = normalize_known_overflow_summary(
            _load_json(summary_path),
            entry=entry,
            output_dir=output_dir,
            summary_path=summary_path,
            runtime_seconds=runtime,
            exit_code=completed.returncode,
        )
    else:
        row = BenchmarkRunRow(
            id=entry.id,
            kind=entry.kind,
            label=entry.label,
            required=entry.required,
            status=COMMAND_FAILED_STATUS,
            runtime_seconds=round(runtime, 4),
            output_dir=str(output_dir),
            exit_code=completed.returncode,
            command=command,
            errors=[f"command_exit_{completed.returncode}", "summary_missing"],
        )
    row.command = command
    row.artifact_paths.update({"stdout_log": str(stdout_log), "stderr_log": str(stderr_log)})
    return row


def _append_known_overflow_args(command: list[str], args: Mapping[str, Any], base_dir: Path) -> None:
    option_flags = {
        "cache_dir": "--cache-dir",
        "stages": "--stages",
        "proof_timeout_seconds": "--proof-timeout-seconds",
        "proof_dynamic_max_steps": "--proof-dynamic-max-steps",
        "ghidra_dir": "--ghidra-dir",
        "case_timeout_seconds": "--case-timeout-seconds",
        "require_passed": "--require-passed",
        "require_true_overflow_passed": "--require-true-overflow-passed",
        "require_diagnostics_passed": "--require-diagnostics-passed",
        "require_negative_passed": "--require-negative-passed",
        "require_regression_subset_passed": "--require-regression-subset-passed",
        "llm_hypothesis_provider_command": "--llm-hypothesis-provider-command",
        "llm_hypothesis_fixtures": "--llm-hypothesis-fixtures",
        "llm_hypothesis_systems": "--llm-hypothesis-systems",
        "llm_hypothesis_provider_timeout_seconds": "--llm-hypothesis-provider-timeout-seconds",
        "hypothesis_policy": "--hypothesis-policy",
        "max_hypothesis_calls_per_run": "--max-hypothesis-calls-per-run",
        "max_hypothesis_calls_per_candidate": "--max-hypothesis-calls-per-candidate",
        "llm_repair_provider_command": "--llm-repair-provider-command",
        "llm_repair_provider_timeout_seconds": "--llm-repair-provider-timeout-seconds",
        "llm_repair_max_attempts": "--llm-repair-max-attempts",
    }
    path_keys = {"cache_dir", "ghidra_dir", "llm_hypothesis_fixtures"}
    for key, flag in option_flags.items():
        value = args.get(key)
        if value in (None, ""):
            continue
        if key in path_keys:
            value = _resolve_path(value, base_dir)
        command.extend([flag, str(value)])
    for raw in _sequence(args.get("require_family_passed")):
        command.extend(["--require-family-passed", str(raw)])
    for raw in _sequence(args.get("require_known_vuln_family_passed")):
        command.extend(["--require-known-vuln-family-passed", str(raw)])
    if bool(args.get("full_llm_path", False)):
        command.append("--full-llm-path")
    if bool(args.get("require_provenance", False)):
        command.append("--require-provenance")
    if bool(args.get("require_live_llm", False)):
        command.append("--require-live-llm")


def _entry_from_dict(data: Mapping[str, Any], *, base_dir: Path) -> BenchmarkEntry:
    raw_id = str(data.get("id") or data.get("name") or data.get("label") or data.get("kind") or "benchmark")
    if "heldout" in data:
        raise ValueError(
            f"benchmark {raw_id!r} uses removed field 'heldout'; "
            "existing cases are regressions, so use 'regression_subset'"
        )
    kind = str(data.get("kind") or "")
    if kind not in KNOWN_BENCHMARK_KINDS:
        raise ValueError(f"benchmark {raw_id!r} has unsupported kind {kind!r}")
    thresholds = {
        str(key): float(value)
        for key, value in _mapping(data.get("thresholds") or data.get("requirements")).items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }
    return BenchmarkEntry(
        id=_safe_name(raw_id),
        kind=kind,
        label=str(data.get("label") or ""),
        required=bool(data.get("required", True)),
        summary_path=_optional_path(data.get("summary_path") or data.get("summary"), base_dir),
        targets_json=_optional_path(data.get("targets_json") or data.get("targets"), base_dir),
        manifest=_optional_path(data.get("manifest"), base_dir),
        lanes=tuple(str(item) for item in _sequence(data.get("lanes") or data.get("lane"))),
        cases=tuple(str(item) for item in _sequence(data.get("cases") or data.get("case"))),
        regression_subset=bool(data.get("regression_subset", False)),
        requires=tuple(_resolve_requirement(item, base_dir) for item in _sequence(data.get("requires"))),
        thresholds=thresholds,
        args={str(key): value for key, value in _mapping(data.get("args")).items()},
    )


def _missing_inputs(entry: BenchmarkEntry) -> list[str]:
    missing: list[str] = []
    if entry.summary_path is not None and not entry.summary_path.exists():
        missing.append(f"missing_summary_path:{entry.summary_path}")
    if entry.summary_path is None and entry.kind == CAPABILITY_SWEEP_KIND:
        if entry.targets_json is None:
            missing.append("missing_targets_json")
        elif not entry.targets_json.exists():
            missing.append(f"missing_targets_json:{entry.targets_json}")
    if entry.manifest is not None and not entry.manifest.exists():
        missing.append(f"missing_manifest:{entry.manifest}")
    for requirement in entry.requires:
        missing.extend(_missing_requirement(requirement, entry))
    return missing


def _missing_requirement(requirement: str, entry: BenchmarkEntry) -> list[str]:
    requirement = requirement.strip()
    if not requirement:
        return []
    if requirement == "ghidra":
        return [] if _ghidra_available() else ["missing_ghidra"]
    if requirement.startswith("env:"):
        name = requirement.partition(":")[2]
        return [] if os.environ.get(name) else [f"missing_env:{name}"]
    path = Path(requirement)
    return [] if path.exists() else [f"missing_path:{path}"]


def _missing_input_row(entry: BenchmarkEntry, output_dir: Path, missing_inputs: list[str]) -> BenchmarkRunRow:
    status = SKIPPED_MISSING_INPUT_STATUS if not entry.required else FAILED_MISSING_INPUT_STATUS
    row = BenchmarkRunRow(
        id=entry.id,
        kind=entry.kind,
        label=entry.label,
        required=entry.required,
        status=status,
        output_dir=str(output_dir),
        skipped_reason=";".join(missing_inputs) if not entry.required else "",
        errors=[] if not entry.required else missing_inputs,
        blockers=missing_inputs,
        blocker_count=len(missing_inputs),
        metrics={"missing_input_count": len(missing_inputs)},
    )
    return row


def _apply_thresholds(row: BenchmarkRunRow, thresholds: Mapping[str, float]) -> None:
    for metric_name, minimum in thresholds.items():
        value = row.metrics.get(metric_name)
        if value is None:
            row.threshold_failures.append(f"{metric_name}=missing < required {minimum:g}")
            continue
        if float(value) < float(minimum):
            row.threshold_failures.append(f"{metric_name}={value:g} < required {minimum:g}")
    if row.threshold_failures and row.status == PASSED_STATUS:
        row.status = FAILED_STATUS


def _collect_sweep_blockers(targets: Sequence[Mapping[str, Any]]) -> list[str]:
    blockers: list[str] = []
    for row in targets:
        for value in _sequence(row.get("blockers")):
            blockers.append(str(value))
        for value in _sequence(row.get("errors")):
            blockers.append(str(value))
    return blockers


def _collect_known_overflow_blockers(cases: Sequence[Mapping[str, Any]]) -> list[str]:
    blockers: list[str] = []
    for case in cases:
        if bool(case.get("passed")):
            continue
        case_id = str(case.get("id") or "case")
        reason = str(case.get("failure_reason") or case.get("error") or "failed")
        blockers.append(f"{case_id}:{reason}")
        backend = str(case.get("backend_missing_reason") or "")
        if backend:
            blockers.append(f"{case_id}:{backend}")
        missing = _sequence(case.get("missing_provenance_fields"))
        if missing:
            blockers.append(f"{case_id}:missing_provenance:{','.join(str(item) for item in missing)}")
    return blockers


def _summary_metric_map(payload: Mapping[str, Any]) -> dict[str, float]:
    suite_id = str(payload.get("suite_id") or "suite")
    metrics: dict[str, float] = {}
    for metric_name, value in _flatten_numeric_mapping(_mapping(payload.get("totals"))).items():
        metrics[f"{suite_id}:suite:{metric_name}"] = float(value)
    for row in _sequence(payload.get("runs")):
        if not isinstance(row, Mapping):
            continue
        row_id = str(row.get("id") or "run")
        row_metrics = _flatten_numeric_mapping(_mapping(row.get("metrics")))
        for metric_name, value in row_metrics.items():
            metrics[f"{suite_id}:run:{row_id}:{metric_name}"] = float(value)
    return metrics


def _delta_row(key: str, baseline: float | None, current: float | None) -> dict[str, Any]:
    metric_name = key.rsplit(":", 1)[-1]
    if baseline is None:
        return {"key": key, "metric_name": metric_name, "status": "added", "baseline": None, "current": current, "delta": None}
    if current is None:
        return {"key": key, "metric_name": metric_name, "status": "removed", "baseline": baseline, "current": None, "delta": None}
    delta = current - baseline
    if delta == 0:
        status = "unchanged"
    elif _lower_is_better(metric_name):
        status = "improved" if delta < 0 else "regressed"
    else:
        status = "improved" if delta > 0 else "regressed"
    return {
        "key": key,
        "metric_name": metric_name,
        "status": status,
        "baseline": baseline,
        "current": current,
        "delta": delta,
    }


def _lower_is_better(metric_name: str) -> bool:
    return any(fragment in metric_name for fragment in _LOWER_IS_BETTER_FRAGMENTS)


def _flatten_numeric_mapping(payload: Mapping[str, Any], prefix: str = "") -> dict[str, int | float]:
    metrics: dict[str, int | float] = {}
    for key, value in payload.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            metrics[name] = value
        elif isinstance(value, Mapping):
            metrics.update(_flatten_numeric_mapping(value, name))
    return metrics


def _ghidra_available() -> bool:
    env_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if env_dir and Path(env_dir).exists():
        return True
    root = Path(__file__).resolve().parents[2] / "ghidra_downloads"
    if not root.exists():
        return False
    for support in root.glob("ghidra_*/support"):
        if (support / "analyzeHeadless").exists() or (support / "pyGhidraRun").exists() or (support / "pyghidraRun").exists():
            return True
    return False


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return dict(payload) if isinstance(payload, Mapping) else {}


def _optional_path(value: object, base_dir: Path) -> Path | None:
    if value in (None, ""):
        return None
    return _resolve_path(value, base_dir)


def _resolve_path(value: object, base_dir: Path) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = Path(base_dir) / path
    return path.resolve()


def _resolve_requirement(value: object, base_dir: Path) -> str:
    text = str(value)
    if text == "ghidra" or text.startswith("env:"):
        return text
    return str(_resolve_path(text, base_dir))


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: object) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return [value]


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_name(value: str) -> str:
    name = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in value.strip())
    return name.strip("-._") or "benchmark"
