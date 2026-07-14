import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from binary_agent.capability_benchmark import (
    CAPABILITY_BENCHMARK_DELTA,
    CAPABILITY_BENCHMARK_RUNS,
    CAPABILITY_BENCHMARK_SUMMARY,
    BenchmarkEntry,
    load_benchmark_suite,
    normalize_capability_sweep_summary,
    normalize_known_overflow_summary,
    run_capability_benchmark,
    write_benchmark_delta,
)


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _capability_summary(target_count: int = 1, targets_with_errors: int = 0, blocked: bool = False) -> dict:
    return {
        "artifact_kind": "capability_sweep_summary",
        "schema_version": 1,
        "target_count": target_count,
        "totals": {
            "targets_with_errors": targets_with_errors,
            "rejected_negatives": 1,
            "blocked_negatives": 0,
            "missing_expected_positives": 1,
            "dynamic_proofs": 2,
        },
        "targets": [
            {
                "id": "safe",
                "blockers": ["missing_export_dir:demo"] if blocked else [],
                "errors": [],
                "target_provenance": {"target_kind": "single_binary"},
                "metadata": {"expected_negatives": ["safe_case"]},
            }
        ],
    }


def _known_summary(passed: int = 1, failed: int = 0) -> dict:
    cases = [
        {
            "id": "caught",
            "lane": "true_overflow",
            "expected_outcome": "caught",
            "passed": True,
            "failure_reason": "none",
            "missing_provenance_fields": [],
        }
    ]
    if failed:
        cases.append(
            {
                "id": "missed",
                "lane": "true_overflow",
                "expected_outcome": "caught",
                "passed": False,
                "failure_reason": "missing_report_issue",
                "missing_provenance_fields": ["source_url"],
            }
        )
    return {
        "schema_version": 1,
        "passed": passed,
        "failed": failed,
        "lanes": {"true_overflow": {"passed": passed, "failed": failed, "total": passed + failed}},
        "provenance_complete": passed,
        "provenance_total": passed + failed,
        "true_overflow_passed": passed,
        "true_overflow_total": passed + failed,
        "negative_passed": 0,
        "negative_total": 0,
        "clean_negatives": 0,
        "cases": cases,
    }


def test_load_benchmark_suite_resolves_paths_and_requirements(tmp_path: Path) -> None:
    summary_path = _write_json(tmp_path / "summaries" / "sweep.json", _capability_summary())
    manifest = _write_json(
        tmp_path / "suite.json",
        {
            "suite_id": "demo suite",
            "benchmarks": [
                {
                    "id": "sweep",
                    "kind": "capability_sweep",
                    "summary_path": "summaries/sweep.json",
                    "requires": ["inputs", "ghidra"],
                    "thresholds": {"passed": 1},
                }
            ],
        },
    )

    suite = load_benchmark_suite(manifest)

    assert suite.suite_id == "demo-suite"
    assert suite.benchmarks[0].summary_path == summary_path
    assert suite.benchmarks[0].requires[0] == str((tmp_path / "inputs").resolve())
    assert suite.benchmarks[0].requires[1] == "ghidra"
    assert suite.benchmarks[0].thresholds == {"passed": 1.0}


def test_load_benchmark_suite_rejects_false_heldout_label(tmp_path: Path) -> None:
    manifest = _write_json(
        tmp_path / "suite.json",
        {
            "benchmarks": [
                {"id": "known", "kind": "known_overflow_corpus", "heldout": True}
            ]
        },
    )

    with pytest.raises(ValueError, match="existing cases are regressions"):
        load_benchmark_suite(manifest)


def test_optional_missing_input_is_explicit_skip_and_serialized(tmp_path: Path) -> None:
    manifest = _write_json(
        tmp_path / "suite.json",
        {
            "suite_id": "skip-demo",
            "benchmarks": [
                {
                    "id": "optional-summary",
                    "kind": "known_overflow_corpus",
                    "required": False,
                    "summary_path": "missing.json",
                }
            ],
        },
    )

    summary = run_capability_benchmark(manifest, tmp_path / "out")

    assert summary.success is True
    assert summary.rows[0].status == "skipped_missing_input"
    assert "missing_summary_path" in summary.rows[0].skipped_reason
    summary_payload = json.loads((tmp_path / "out" / CAPABILITY_BENCHMARK_SUMMARY).read_text(encoding="utf-8"))
    runs_payload = json.loads((tmp_path / "out" / CAPABILITY_BENCHMARK_RUNS).read_text(encoding="utf-8"))
    assert summary_payload["artifact_kind"] == "capability_benchmark_summary"
    assert runs_payload["artifact_kind"] == "capability_benchmark_runs"
    assert summary_payload["totals"]["optional_skipped"] == 1


def test_required_missing_input_fails_summary(tmp_path: Path) -> None:
    manifest = _write_json(
        tmp_path / "suite.json",
        {
            "suite_id": "required-missing-demo",
            "benchmarks": [
                {
                    "id": "required-summary",
                    "kind": "capability_sweep",
                    "summary_path": "missing.json",
                }
            ],
        },
    )

    summary = run_capability_benchmark(manifest, tmp_path / "out")

    assert summary.success is False
    assert summary.rows[0].status == "failed_missing_input"
    assert summary.totals["required_failed"] == 1


def test_required_threshold_failure_fails_summary(tmp_path: Path) -> None:
    known_path = _write_json(tmp_path / "known.json", _known_summary(passed=1, failed=0))
    manifest = _write_json(
        tmp_path / "suite.json",
        {
            "suite_id": "threshold-demo",
            "benchmarks": [
                {
                    "id": "known",
                    "kind": "known_overflow_corpus",
                    "summary_path": "known.json",
                    "thresholds": {"passed": 2},
                }
            ],
        },
    )

    summary = run_capability_benchmark(manifest, tmp_path / "out")

    assert summary.success is False
    assert summary.rows[0].status == "failed"
    assert summary.rows[0].threshold_failures == ["passed=1 < required 2"]
    assert known_path.exists()


def test_capability_sweep_summary_normalization_uses_shared_metrics(tmp_path: Path) -> None:
    entry = BenchmarkEntry(id="sweep", kind="capability_sweep", thresholds={"passed": 1})

    row = normalize_capability_sweep_summary(
        _capability_summary(),
        entry=entry,
        output_dir=tmp_path / "out",
        summary_path=tmp_path / "capability_sweep_summary.json",
    )

    assert row.status == "passed"
    assert row.passed_count == 1
    assert row.target_count == 1
    assert row.blocker_count == 0
    assert row.negative_total == 1
    assert row.negative_passed == 1
    assert row.negative_blocked == 0
    assert row.expected_positive_misses == 1
    assert row.provenance_complete == 1
    assert row.metrics["dynamic_proofs"] == 2


def test_capability_sweep_blockers_do_not_count_as_passes_or_clean_negatives(tmp_path: Path) -> None:
    payload = _capability_summary(blocked=True)
    payload["totals"]["rejected_negatives"] = 0
    payload["totals"]["blocked_negatives"] = 1

    row = normalize_capability_sweep_summary(
        payload,
        entry=BenchmarkEntry(id="blocked", kind="capability_sweep"),
        output_dir=tmp_path / "out",
        summary_path=tmp_path / "capability_sweep_summary.json",
    )

    assert row.status == "failed"
    assert row.passed_count == 0
    assert row.failed_count == 1
    assert row.negative_passed == 0
    assert row.negative_blocked == 1
    assert row.clean_negatives == 0


def test_known_overflow_summary_normalization_tracks_misses_and_blockers(tmp_path: Path) -> None:
    entry = BenchmarkEntry(id="known", kind="known_overflow_corpus")

    row = normalize_known_overflow_summary(
        _known_summary(passed=1, failed=1),
        entry=entry,
        output_dir=tmp_path / "out",
        summary_path=tmp_path / "summary.json",
    )

    assert row.status == "failed"
    assert row.passed_count == 1
    assert row.failed_count == 1
    assert row.case_count == 2
    assert row.expected_positive_misses == 1
    assert row.provenance_complete == 1
    assert row.provenance_total == 2
    assert "missed:missing_report_issue" in row.blockers
    assert "missed:missing_provenance:source_url" in row.blockers
    assert row.metrics["lanes.true_overflow.failed"] == 1


def test_delta_generation_classifies_added_removed_improved_regressed_and_unchanged(tmp_path: Path) -> None:
    baseline = {
        "suite_id": "delta-demo",
        "totals": {"passed": 1, "failed": 2, "blockers": 1, "same": 5, "removed": 7},
        "runs": [{"id": "bench", "metrics": {"passed": 1}}],
    }
    current = {
        "suite_id": "delta-demo",
        "totals": {"passed": 2, "failed": 1, "blockers": 3, "same": 5, "added": 9},
        "runs": [{"id": "bench", "metrics": {"passed": 1}}],
    }

    delta_path = write_benchmark_delta(current, baseline, tmp_path)

    assert delta_path.name == CAPABILITY_BENCHMARK_DELTA
    payload = json.loads(delta_path.read_text(encoding="utf-8"))
    by_key = {item["key"]: item for item in payload["metrics"]}
    assert by_key["delta-demo:suite:passed"]["status"] == "improved"
    assert by_key["delta-demo:suite:failed"]["status"] == "improved"
    assert by_key["delta-demo:suite:blockers"]["status"] == "regressed"
    assert by_key["delta-demo:suite:same"]["status"] == "unchanged"
    assert by_key["delta-demo:suite:added"]["status"] == "added"
    assert by_key["delta-demo:suite:removed"]["status"] == "removed"
    assert by_key["delta-demo:run:bench:passed"]["status"] == "unchanged"


def test_capability_benchmark_cli_integrates_fixture_summaries(tmp_path: Path) -> None:
    cap_summary = _write_json(tmp_path / "capability_sweep_summary.json", _capability_summary())
    known_summary = _write_json(tmp_path / "known_summary.json", _known_summary())
    manifest = _write_json(
        tmp_path / "suite.json",
        {
            "suite_id": "cli-demo",
            "benchmarks": [
                {
                    "id": "sweep",
                    "kind": "capability_sweep",
                    "summary_path": str(cap_summary),
                    "thresholds": {"passed": 1},
                },
                {
                    "id": "known",
                    "kind": "known_overflow_corpus",
                    "summary_path": str(known_summary),
                    "thresholds": {"passed": 1},
                },
            ],
        },
    )
    env = os.environ.copy()
    src_path = str(Path.cwd() / "src")
    env["PYTHONPATH"] = src_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "binary_agent.cli.run_capability_benchmark",
            str(manifest),
            "--output-dir",
            str(tmp_path / "out"),
        ],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    summary_payload = json.loads((tmp_path / "out" / CAPABILITY_BENCHMARK_SUMMARY).read_text(encoding="utf-8"))
    assert summary_payload["success"] is True
    assert summary_payload["totals"]["benchmarks"] == 2
    assert summary_payload["totals"]["target_count"] == 1
    assert summary_payload["totals"]["case_count"] == 1
    assert (tmp_path / "out" / CAPABILITY_BENCHMARK_RUNS).exists()
