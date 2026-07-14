import importlib.util
import json
from argparse import Namespace
from pathlib import Path

import pytest


def _load_script_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "run_known_overflow_corpus.py"
    spec = importlib.util.spec_from_file_location("run_known_overflow_corpus", script_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_parse_run_dir_uses_final_toolchain_run_line() -> None:
    module = _load_script_module()
    stdout = "\n".join(
        [
            "[+] Proof-gated run directory: /tmp/old",
            "[+] Reports written",
            "[+] Proof-gated run directory: /tmp/new",
        ]
    )

    assert module.parse_run_dir(stdout) == "/tmp/new"


def test_evaluate_run_requires_exact_report_and_witness_counts(tmp_path: Path) -> None:
    module = _load_script_module()
    run_dir = tmp_path / "case" / "binary" / "20260617-000000"
    (run_dir / "proof").mkdir(parents=True)
    (run_dir / "report").mkdir()
    (run_dir / "proof" / "_concolic_run_summary.json").write_text(
        json.dumps({"verdict_counts": {"overflow_witness": 1, "timeout": 0}}),
        encoding="utf-8",
    )
    (run_dir / "report" / "vulnerabilities.json").write_text(
        json.dumps({"vulnerabilities": [{"candidate_id": "demo"}]}),
        encoding="utf-8",
    )
    case = {"id": "demo", "expected_issue_count": 1, "expected_overflow_witnesses": 1}

    result = module.evaluate_run(case, run_dir, 0)

    assert result["passed"] is True
    assert result["lane"] == "true_overflow"
    assert result["vuln_family"] == "unspecified"
    assert result["known_vuln_family"] == ""
    assert result["issue_count"] == 1
    assert result["overflow_witnesses"] == 1


def test_evaluate_run_caught_case_allows_auxiliary_timeout_count(tmp_path: Path) -> None:
    module = _load_script_module()
    run_dir = tmp_path / "case" / "binary" / "20260617-000000"
    (run_dir / "proof").mkdir(parents=True)
    (run_dir / "report").mkdir()
    (run_dir / "proof" / "_concolic_run_summary.json").write_text(
        json.dumps({"verdict_counts": {"overflow_witness": 1, "timeout": 1}}),
        encoding="utf-8",
    )
    (run_dir / "report" / "vulnerabilities.json").write_text(
        json.dumps({"vulnerabilities": [{"candidate_id": "demo"}]}),
        encoding="utf-8",
    )
    case = {"id": "demo", "expected_outcome": "caught", "expected_issue_count": 1, "expected_overflow_witnesses": 1}

    result = module.evaluate_run(case, run_dir, 0)

    assert result["passed"] is True
    assert result["failure_reason"] == "none"


def test_evaluate_run_fails_on_extra_report_issue(tmp_path: Path) -> None:
    module = _load_script_module()
    run_dir = tmp_path / "case" / "binary" / "20260617-000000"
    (run_dir / "proof").mkdir(parents=True)
    (run_dir / "report").mkdir()
    (run_dir / "proof" / "_concolic_run_summary.json").write_text(
        json.dumps({"verdict_counts": {"overflow_witness": 1}}),
        encoding="utf-8",
    )
    (run_dir / "report" / "vulnerabilities.json").write_text(
        json.dumps({"vulnerabilities": [{"candidate_id": "one"}, {"candidate_id": "two"}]}),
        encoding="utf-8",
    )
    case = {"id": "demo", "expected_issue_count": 1, "expected_overflow_witnesses": 1}

    result = module.evaluate_run(case, run_dir, 0)

    assert result["passed"] is False
    assert result["issue_count"] == 2


def test_evaluate_run_counts_lifetime_witness_as_memory_safety_detection(tmp_path: Path) -> None:
    module = _load_script_module()
    run_dir = tmp_path / "case" / "binary" / "20260617-000000"
    (run_dir / "proof").mkdir(parents=True)
    (run_dir / "report").mkdir()
    (run_dir / "proof" / "_concolic_run_summary.json").write_text(
        json.dumps({"verdict_counts": {"memory_violation_witness": 1}}),
        encoding="utf-8",
    )
    (run_dir / "report" / "vulnerabilities.json").write_text(
        json.dumps({"vulnerabilities": [{"candidate_id": "double-free"}]}),
        encoding="utf-8",
    )
    case = {
        "id": "lifetime",
        "expected_outcome": "caught",
        "expected_issue_count": 1,
        "expected_overflow_witnesses": 1,
    }

    result = module.evaluate_run(case, run_dir, 0)

    assert result["passed"] is True
    assert result["memory_safety_witnesses"] == 1


def test_evaluate_run_accepts_expected_known_miss(tmp_path: Path) -> None:
    module = _load_script_module()
    run_dir = tmp_path / "case" / "binary" / "20260617-000000"
    (run_dir / "proof").mkdir(parents=True)
    (run_dir / "report").mkdir()
    (run_dir / "proof" / "_concolic_run_summary.json").write_text(
        json.dumps({"verdict_counts": {"overflow_witness": 0, "path_unsat": 1}}),
        encoding="utf-8",
    )
    (run_dir / "report" / "vulnerabilities.json").write_text(
        json.dumps({"vulnerabilities": []}),
        encoding="utf-8",
    )
    case = {
        "id": "demo-known-miss",
        "expected_outcome": "known_miss",
        "known_issue_count": 1,
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
        "expected_failure_reason": "path_unsat",
    }

    result = module.evaluate_run(case, run_dir, 0)

    assert result["passed"] is True
    assert result["known_issue_count"] == 1
    assert result["failure_reason"] == "path_unsat"


def test_evaluate_run_accepts_diagnostic_known_miss_when_optional_backend_missing(tmp_path: Path) -> None:
    module = _load_script_module()
    run_dir = tmp_path / "case" / "binary" / "20260617-000000"
    proof_case = run_dir / "proof" / "candidate"
    proof_case.mkdir(parents=True)
    (run_dir / "report").mkdir()
    (run_dir / "proof" / "_concolic_run_summary.json").write_text(
        json.dumps({"verdict_counts": {"backend_error": 1, "overflow_witness": 0}}),
        encoding="utf-8",
    )
    (proof_case / "verdict.json").write_text(
        json.dumps({"rationale": "angr backend is not available: No module named 'angr'"}),
        encoding="utf-8",
    )
    (run_dir / "report" / "vulnerabilities.json").write_text(
        json.dumps({"vulnerabilities": []}),
        encoding="utf-8",
    )
    case = {
        "id": "demo-diagnostic",
        "lane": "diagnostic",
        "expected_outcome": "known_miss",
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
        "expected_failure_reason": "timeout",
        "allow_backend_missing_known_miss": True,
    }

    result = module.evaluate_run(case, run_dir, 0)

    assert result["passed"] is True
    assert result["failure_reason"] == "backend_error"
    assert result["backend_missing_reason"] == "optional_backend_missing:angr"


def test_evaluate_run_accepts_clean_negative_case(tmp_path: Path) -> None:
    module = _load_script_module()
    run_dir = tmp_path / "case" / "binary" / "20260617-000000"
    (run_dir / "proof").mkdir(parents=True)
    (run_dir / "report").mkdir()
    (run_dir / "proof" / "_concolic_run_summary.json").write_text(
        json.dumps({"verdict_counts": {"overflow_witness": 0, "guard_refuted": 2}}),
        encoding="utf-8",
    )
    (run_dir / "report" / "vulnerabilities.json").write_text(
        json.dumps({"vulnerabilities": []}),
        encoding="utf-8",
    )
    case = {
        "id": "demo-negative",
        "lane": "negative",
        "vuln_family": "guarded_out_of_bounds_read",
        "expected_outcome": "clean",
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
        "expected_suppression_reason": "guard_refuted",
    }

    result = module.evaluate_run(case, run_dir, 0)

    assert result["passed"] is True
    assert result["lane"] == "negative"
    assert result["vuln_family"] == "guarded_out_of_bounds_read"
    assert result["failure_reason"] == "none"
    assert result["suppression_reason"] == "guard_refuted"


def test_evaluate_run_marks_timed_out_negative_blocked_not_clean(tmp_path: Path) -> None:
    module = _load_script_module()
    run_dir = tmp_path / "case" / "binary" / "20260617-000000"
    (run_dir / "proof").mkdir(parents=True)
    (run_dir / "report").mkdir()
    (run_dir / "proof" / "_concolic_run_summary.json").write_text(
        json.dumps({"verdict_counts": {"overflow_witness": 0, "timeout": 1}}),
        encoding="utf-8",
    )
    (run_dir / "report" / "vulnerabilities.json").write_text(
        json.dumps({"vulnerabilities": []}),
        encoding="utf-8",
    )
    case = {
        "id": "timed-out-negative",
        "lane": "negative",
        "expected_outcome": "clean",
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
    }

    result = module.evaluate_run(case, run_dir, 0)

    assert result["passed"] is False
    assert result["failure_reason"] == "timeout"
    assert result["execution_status"] == "blocked"


def test_select_cases_filters_by_lane() -> None:
    module = _load_script_module()
    cases = [
        {"id": "caught", "lane": "true_overflow"},
        {"id": "diagnostic", "lane": "diagnostic"},
        {"id": "negative", "lane": "negative"},
    ]

    assert [case["id"] for case in module.select_cases(cases, None, ["diagnostic"])] == ["diagnostic"]
    assert [case["id"] for case in module.select_cases(cases, None, ["negative"])] == ["negative"]
    assert [case["id"] for case in module.select_cases(cases, ["caught"], None)] == ["caught"]


def test_select_regression_subset_includes_ambiguous_http_case() -> None:
    module = _load_script_module()
    selected = module.select_regression_subset(module.DEFAULT_CASES)
    selected_ids = {case["id"] for case in selected}

    assert "goahead-2.1-cve-2002-1951-http-get" in selected_ids
    assert "guarded-heartbleed-slice" in selected_ids
    assert all(case["id"] in module.DEFAULT_REGRESSION_SUBSET_IDS for case in selected)


def test_default_corpus_has_readiness_lane_counts() -> None:
    module = _load_script_module()

    assert sum(1 for case in module.DEFAULT_CASES if case.get("lane") == "true_overflow") == 8
    assert sum(1 for case in module.DEFAULT_CASES if case.get("lane") == "diagnostic") == 6
    assert sum(1 for case in module.DEFAULT_CASES if case.get("lane") == "negative") == 1
    assert sum(1 for case in module.DEFAULT_CASES if case.get("vuln_family") == "stack_overflow") == 2
    assert sum(1 for case in module.DEFAULT_CASES if case.get("vuln_family") == "out_of_bounds_write") == 5
    assert sum(1 for case in module.DEFAULT_CASES if module.case_known_vuln_family(case) == "heap_overflow") == 1
    assert sum(1 for case in module.DEFAULT_CASES if module.case_known_vuln_family(case) == "out_of_bounds_read") == 1
    assert sum(1 for case in module.DEFAULT_CASES if module.case_known_vuln_family(case) == "out_of_bounds_write") >= 1
    assert (
        sum(
            1
            for case in module.DEFAULT_CASES
            if module.case_known_vuln_family(case) == "integer_overflow_to_heap_overflow"
        )
        == 1
    )
    assert all(not module.missing_provenance_fields(module.case_provenance(case)) for case in module.DEFAULT_CASES)
    assert all("proof_max_candidates" not in case for case in module.DEFAULT_CASES)


def test_goahead_http_daemon_known_miss_records_process_input_metadata(tmp_path: Path) -> None:
    module = _load_script_module()
    case = next(case for case in module.DEFAULT_CASES if case["id"] == "goahead-2.1-cve-2002-1951-http-get")
    run_dir = tmp_path / "case" / "webs_stripped" / "20260618-000000"
    (run_dir / "proof").mkdir(parents=True)
    (run_dir / "report").mkdir()
    (run_dir / "proof" / "_concolic_run_summary.json").write_text(
        json.dumps({"verdict_counts": {"backend_error": 1, "overflow_witness": 0}}),
        encoding="utf-8",
    )
    (run_dir / "report" / "vulnerabilities.json").write_text(
        json.dumps({"vulnerabilities": []}),
        encoding="utf-8",
    )

    result = module.evaluate_run(case, run_dir, 0)

    assert result["passed"] is True
    assert result["process_input_model"] == "http_daemon"
    assert result["replay_hints"]["http_daemon"]["port"] == 18080
    assert result["known_vuln_family"] == "out_of_bounds_write"


def test_write_summary_records_lane_totals(tmp_path: Path) -> None:
    module = _load_script_module()
    summary_path = tmp_path / "summary.json"

    payload = module.write_summary(
        summary_path,
        [
            {
                "id": "caught",
                "lane": "true_overflow",
                "vuln_family": "stack_overflow",
                "known_vuln_family": "stack_overflow",
                "regression_subset": True,
                "passed": True,
                "expected_outcome": "caught",
                "missing_provenance_fields": [],
                "llm_metrics": {"model_calls": 1, "hypothesis_accepted_count": 1, "replay_confirmed_count": 1},
            },
            {
                "id": "unsupported",
                "lane": "diagnostic",
                "vuln_family": "diagnostic_unsupported_input_source",
                "known_vuln_family": "",
                "passed": True,
                "expected_outcome": "known_miss",
                "missing_provenance_fields": [],
            },
            {
                "id": "guarded",
                "lane": "negative",
                "vuln_family": "guarded_out_of_bounds_read",
                "known_vuln_family": "",
                "passed": True,
                "expected_outcome": "clean",
                "missing_provenance_fields": [],
            },
            {
                "id": "miss",
                "lane": "true_overflow",
                "vuln_family": "stack_overflow",
                "known_vuln_family": "stack_overflow",
                "passed": False,
                "expected_outcome": "caught",
                "missing_provenance_fields": ["source_url"],
            },
        ],
    )

    assert payload["true_overflow_passed"] == 1
    assert payload["true_overflow_total"] == 2
    assert payload["diagnostics_passed"] == 1
    assert payload["diagnostics_total"] == 1
    assert payload["negative_passed"] == 1
    assert payload["negative_total"] == 1
    assert payload["clean_negatives"] == 1
    assert payload["families"]["stack_overflow"] == {"failed": 1, "passed": 1, "total": 2}
    assert payload["families"]["guarded_out_of_bounds_read"] == {"failed": 0, "passed": 1, "total": 1}
    assert payload["known_vuln_families"]["stack_overflow"] == {"failed": 1, "passed": 1, "total": 2}
    assert payload["caught_known_vuln_families"] == {"stack_overflow": 1}
    assert payload["regression_subset_passed"] == 1
    assert payload["regression_subset_total"] == 1
    assert payload["llm_metrics"]["model_calls"] == 1
    assert payload["llm_metrics"]["hypothesis_accepted_count"] == 1
    assert payload["llm_metrics"]["replay_confirmed_count"] == 1
    assert payload["provenance_complete"] == 3
    assert payload == json.loads(summary_path.read_text(encoding="utf-8"))


def test_llm_run_metrics_reads_hypothesis_replay_repair_and_report_artifacts(tmp_path: Path) -> None:
    module = _load_script_module()
    run_dir = tmp_path / "run"
    (run_dir / "hypotheses").mkdir(parents=True)
    (run_dir / "replay" / "cand" / "repair").mkdir(parents=True)
    (run_dir / "report").mkdir()
    (run_dir / "hypotheses" / "summary.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "candidate_count": 2,
                "eligible_candidate_count": 1,
                "provider_calls": 1,
                "accepted_count": 1,
                "rejected_count": 1,
                "model_calls": 1,
                "input_tokens": 10,
                "output_tokens": 5,
                "total_tokens": 15,
                "wall_time_seconds": 0.25,
                "json_repair_count": 0,
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "hypotheses" / "accepted_index.json").write_text(
        json.dumps({"accepted": [{"candidate_id": "cand"}]}),
        encoding="utf-8",
    )
    (run_dir / "hypotheses" / "rejected_index.json").write_text(
        json.dumps({"rejected": [{"candidate_id": "bad"}]}),
        encoding="utf-8",
    )
    (run_dir / "replay" / "cand" / "result.json").write_text(
        json.dumps({"candidate_id": "cand", "result": "confirmed", "sink_reached": True, "bug_observed": True}),
        encoding="utf-8",
    )
    (run_dir / "replay" / "cand" / "repair" / "repair_attempts.json").write_text(
        json.dumps(
            {
                "attempts": [{"attempt": 1, "accepted": True}],
                "final_result": {"result": "confirmed", "sink_reached": True, "bug_observed": True},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "report" / "vulnerabilities.json").write_text(
        json.dumps({"vulnerabilities": [{"candidate_id": "cand"}]}),
        encoding="utf-8",
    )

    metrics = module.llm_run_metrics(run_dir)

    assert metrics["hypothesis_enabled"] is True
    assert metrics["hypothesis_accepted_count"] == 1
    assert metrics["hypothesis_rejected_count"] == 1
    assert metrics["replay_confirmed_count"] == 1
    assert metrics["repair_attempt_count"] == 1
    assert metrics["repair_confirmed_count"] == 1
    assert metrics["report_deduped_issue_count"] == 1


def test_llm_run_metrics_counts_partial_hypothesis_artifacts_without_summary(tmp_path: Path) -> None:
    module = _load_script_module()
    run_dir = tmp_path / "run"
    system_dir = run_dir / "hypotheses" / "L2"
    system_dir.mkdir(parents=True)
    (system_dir / "cand_replay.json").write_text(
        json.dumps(
            {
                "candidate_id": "cand",
                "cost_metadata": {
                    "model_calls": 1,
                    "input_tokens": 12,
                    "output_tokens": 3,
                    "total_tokens": 15,
                    "wall_time_seconds": 0.5,
                },
                "validator_result": {"accepted": True},
            }
        ),
        encoding="utf-8",
    )

    metrics = module.llm_run_metrics(run_dir)

    assert metrics["hypothesis_enabled"] is True
    assert metrics["hypothesis_provider_calls"] == 1
    assert metrics["hypothesis_accepted_count"] == 1
    assert metrics["hypothesis_rejected_count"] == 0
    assert metrics["model_calls"] == 1
    assert metrics["total_tokens"] == 15
    assert metrics["llm_wall_time_seconds"] == 0.5


def test_requirement_failures_enforce_gate_minimums() -> None:
    module = _load_script_module()
    payload = {"passed": 4, "true_overflow_passed": 2, "diagnostics_passed": 2, "negative_passed": 1}
    args = Namespace(
        require_passed=4,
        require_true_overflow_passed=3,
        require_diagnostics_passed=2,
        require_negative_passed=1,
        require_regression_subset_passed=None,
        require_family_passed=[],
        require_known_vuln_family_passed=[],
        require_provenance=False,
    )

    assert module.requirement_failures(payload, args) == ["true_overflow_passed=2 < required 3"]


def test_requirement_failures_enforce_family_minimums() -> None:
    module = _load_script_module()
    payload = {
        "passed": 4,
        "true_overflow_passed": 2,
        "diagnostics_passed": 1,
        "negative_passed": 1,
        "families": {
            "stack_overflow": {"passed": 2, "failed": 0, "total": 2},
            "out_of_bounds_write": {"passed": 4, "failed": 1, "total": 5},
        },
    }
    args = Namespace(
        require_passed=None,
        require_true_overflow_passed=None,
        require_diagnostics_passed=None,
        require_negative_passed=None,
        require_regression_subset_passed=None,
        require_family_passed=["stack_overflow=2", "out_of_bounds_write=5"],
        require_known_vuln_family_passed=[],
        require_provenance=False,
    )

    assert module.requirement_failures(payload, args) == ["families.out_of_bounds_write.passed=4 < required 5"]


def test_requirement_failures_enforce_known_family_and_provenance_gates() -> None:
    module = _load_script_module()
    payload = {
        "passed": 1,
        "true_overflow_passed": 1,
        "diagnostics_passed": 0,
        "negative_passed": 0,
        "families": {},
        "known_vuln_families": {"heap_overflow": {"passed": 0, "failed": 1, "total": 1}},
        "cases": [
            {
                "id": "missing-provenance",
                "missing_provenance_fields": ["source_url", "source_file"],
            }
        ],
    }
    args = Namespace(
        require_passed=None,
        require_true_overflow_passed=None,
        require_diagnostics_passed=None,
        require_negative_passed=None,
        require_regression_subset_passed=None,
        require_family_passed=[],
        require_known_vuln_family_passed=["heap_overflow=1"],
        require_provenance=True,
    )

    assert module.requirement_failures(payload, args) == [
        "known_vuln_families.heap_overflow.passed=0 < required 1",
        "cases.missing-provenance.provenance missing source_url,source_file",
    ]


def test_parse_count_requirement_rejects_malformed_family_gate() -> None:
    module = _load_script_module()

    try:
        module.parse_count_requirement("stack_overflow", "--require-family-passed")
    except ValueError as exc:
        assert "FAMILY=COUNT" in str(exc)
    else:
        raise AssertionError("malformed family gate was accepted")


def test_evaluate_run_classifies_outer_timeout() -> None:
    module = _load_script_module()
    case = {
        "id": "demo-timeout",
        "expected_outcome": "known_miss",
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
        "expected_failure_reason": "proof_timeout",
    }

    result = module.evaluate_run(case, None, 124)

    assert result["passed"] is True
    assert result["failure_reason"] == "proof_timeout"
    assert result["timeout_diagnostics"]["partial_stage"] == "startup"


def test_evaluate_run_records_bounded_timeout_diagnostics(tmp_path: Path) -> None:
    module = _load_script_module()
    run_dir = tmp_path / "case" / "binary" / "20260617-000000"
    proof_case = run_dir / "proof" / "candidate"
    proof_case.mkdir(parents=True)
    (proof_case / "request.json").write_text("{}", encoding="utf-8")
    (proof_case / "angr_trace.json").write_text("{}", encoding="utf-8")
    case = {
        "id": "demo-timeout",
        "expected_outcome": "known_miss",
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
        "expected_failure_reason": "proof_timeout",
    }

    result = module.evaluate_run(case, run_dir, 124)

    assert result["passed"] is True
    assert result["timeout_diagnostics"]["partial_stage"] == "proof"
    assert result["timeout_diagnostics"]["proof_json_count"] == 2
    assert result["timeout_diagnostics"]["last_proof_artifacts"] == [
        "proof/candidate/angr_trace.json",
        "proof/candidate/request.json",
    ]


def test_toolchain_command_never_uses_manifest_candidate_id_or_candidate_cap(tmp_path: Path) -> None:
    module = _load_script_module()
    ghidra_dir = tmp_path / "ghidra"
    command = module.toolchain_command(
        {"proof_target_candidate_id": "binary:target"},
        tmp_path / "binary",
        tmp_path / "out",
        tmp_path / "cache",
        60.0,
        20000,
        "intake,proof,report",
        True,
        ghidra_dir,
    )
    assert command[command.index("--ghidra-dir") + 1] == str(ghidra_dir)
    assert command[command.index("--stages") + 1] == "intake,proof,report"
    assert "--proof-target-candidate-id" not in command
    assert "binary:target" not in command
    assert "--proof-max-candidates" not in command
    assert command[command.index("--proof-jobs") + 1] == "1"
    assert command[command.index("--proof-memory-limit-mb") + 1] == "8192"
    assert "--overwrite" in command


def test_toolchain_command_forwards_full_llm_path_options(tmp_path: Path) -> None:
    module = _load_script_module()
    command = module.toolchain_command(
        {},
        tmp_path / "binary",
        tmp_path / "out",
        tmp_path / "cache",
        60.0,
        20000,
        module.DEFAULT_LLM_CORPUS_STAGES,
        False,
        llm_options={
            "llm_hypothesis_provider_command": "auto",
            "llm_hypothesis_systems": "L2",
            "hypothesis_policy": "blocked-only",
            "max_hypothesis_calls_per_run": 3,
            "max_hypothesis_calls_per_candidate": 1,
            "llm_repair_provider_command": "auto",
            "llm_repair_max_attempts": 2,
            "require_live_llm": True,
        },
    )

    assert command[command.index("--stages") + 1] == module.DEFAULT_LLM_CORPUS_STAGES
    assert module.DEFAULT_LLM_CORPUS_STAGES.split(",").index("hypothesis") < module.DEFAULT_LLM_CORPUS_STAGES.split(",").index("proof")
    assert command[command.index("--llm-hypothesis-provider-command") + 1] == "auto"
    assert command[command.index("--llm-repair-provider-command") + 1] == "auto"
    assert command[command.index("--max-hypothesis-calls-per-run") + 1] == "3"
    assert "--require-live-llm" in command


def test_full_llm_path_defaults_to_auto_live_providers() -> None:
    module = _load_script_module()
    args = Namespace(
        full_llm_path=True,
        llm_hypothesis_provider_command="",
        llm_hypothesis_fixtures=None,
        llm_hypothesis_systems="L2",
        llm_hypothesis_provider_timeout_seconds=120.0,
        hypothesis_policy="blocked-only",
        max_hypothesis_calls_per_run=module.DEFAULT_LLM_HYPOTHESIS_CALLS_PER_RUN,
        max_hypothesis_calls_per_candidate=1,
        llm_repair_provider_command="",
        llm_repair_provider_timeout_seconds=120.0,
        llm_repair_max_attempts=2,
        require_live_llm=False,
    )

    options = module.llm_options_from_args(args)

    assert options["llm_hypothesis_provider_command"] == "auto"
    assert options["llm_repair_provider_command"] == "auto"
    assert options["require_live_llm"] is False


def test_default_corpus_options_do_not_enable_llm_path() -> None:
    module = _load_script_module()
    args = Namespace(
        full_llm_path=False,
        llm_hypothesis_provider_command="",
        llm_hypothesis_fixtures=None,
        llm_hypothesis_systems="L2",
        llm_hypothesis_provider_timeout_seconds=120.0,
        hypothesis_policy="blocked-only",
        max_hypothesis_calls_per_run=module.DEFAULT_LLM_HYPOTHESIS_CALLS_PER_RUN,
        max_hypothesis_calls_per_candidate=1,
        llm_repair_provider_command="",
        llm_repair_provider_timeout_seconds=120.0,
        llm_repair_max_attempts=2,
        require_live_llm=False,
    )

    assert module.llm_options_from_args(args) == {}


def test_default_ghidra_dir_prefers_repo_local_download(tmp_path: Path) -> None:
    module = _load_script_module()
    ghidra_dir = tmp_path / "ghidra_downloads" / "ghidra_12.1.2_PUBLIC"
    (ghidra_dir / "support").mkdir(parents=True)
    (ghidra_dir / "support" / "pyghidraRun").write_text("#!/bin/sh\n", encoding="utf-8")

    assert module.default_ghidra_dir(tmp_path) == ghidra_dir


def _external_case(binary: str, *, case_id: str = "pair-vulnerable") -> dict:
    return {
        "id": case_id,
        "binary": binary,
        "lane": "true_overflow",
        "expected_outcome": "caught",
        "vuln_family": "stack_overflow",
        "provenance": {
            "package": "external-package",
            "version": "1.0",
            "source_url": "https://example.test/source.tar.gz",
            "advisory_urls": ["https://example.test/advisory"],
            "fix_reference_urls": ["https://example.test/fix"],
            "source_file": "src/tool.c",
            "source_function": "parse",
            "evidence_summary": "The vulnerable release copies an attacker-controlled argument into a fixed buffer.",
        },
    }


def _analyzer_root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "ghidra_scripts").mkdir()
    (root / "src" / "analyzer.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname = 'test'\n", encoding="utf-8")
    return root


def test_freeze_manifest_round_trip_binds_binary_and_analyzer(tmp_path: Path) -> None:
    module = _load_script_module()
    repo_root = _analyzer_root(tmp_path)
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    binary = corpus_root / "tool"
    binary.write_bytes(b"ELF-test-binary")
    candidate = corpus_root / "candidate.json"
    candidate.write_text(
        json.dumps({"corpus_id": "external-20260709", "cases": [_external_case("tool")]}),
        encoding="utf-8",
    )
    frozen_path = corpus_root / "frozen.json"

    frozen = module.freeze_manifest(candidate, frozen_path, repo_root)
    loaded, cases = module.validate_frozen_manifest(frozen_path, repo_root)

    assert loaded["corpus_id"] == "external-20260709"
    assert frozen["analyzer_sha256"] == module.analyzer_sha256(repo_root)
    assert frozen["cases"][0]["binary_sha256"] == module.sha256_file(binary)
    assert cases[0]["binary"] == str(binary.resolve())
    assert cases[0]["expected_issue_count"] == 1
    assert cases[0]["expected_overflow_witnesses"] == 1

    binary.write_bytes(b"changed")
    with pytest.raises(ValueError, match="binary SHA-256 mismatch"):
        module.validate_frozen_manifest(frozen_path, repo_root)


def test_frozen_manifest_rejects_analyzer_drift_and_internal_selectors(tmp_path: Path) -> None:
    module = _load_script_module()
    repo_root = _analyzer_root(tmp_path)
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    (corpus_root / "tool").write_bytes(b"ELF-test-binary")
    candidate = corpus_root / "candidate.json"
    candidate.write_text(
        json.dumps({"corpus_id": "external-20260709", "cases": [_external_case("tool")]}),
        encoding="utf-8",
    )
    frozen_path = corpus_root / "frozen.json"
    module.freeze_manifest(candidate, frozen_path, repo_root)

    (repo_root / "src" / "analyzer.py").write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="analyzer SHA-256 mismatch"):
        module.validate_frozen_manifest(frozen_path, repo_root)

    selector_case = _external_case("tool")
    selector_case["proof_target_candidate_id"] = "known:target"
    candidate.write_text(
        json.dumps({"corpus_id": "external-selectors", "cases": [selector_case]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="forbidden internal field"):
        module.freeze_manifest(candidate, frozen_path, repo_root)


def test_frozen_manifest_rejects_duplicate_ids_and_incomplete_provenance(tmp_path: Path) -> None:
    module = _load_script_module()
    duplicate = _external_case("one")
    with pytest.raises(ValueError, match="duplicate case id"):
        module._validate_external_cases([duplicate, duplicate], require_hash=False)

    incomplete = _external_case("one")
    del incomplete["provenance"]["source_url"]
    with pytest.raises(ValueError, match="provenance is missing: source_url"):
        module._validate_external_cases([incomplete], require_hash=False)


def test_evaluation_metrics_do_not_count_blocked_negative_as_clean() -> None:
    module = _load_script_module()
    metrics = module.evaluation_metrics(
        [
            {
                "id": "vulnerable",
                "expected_outcome": "caught",
                "execution_status": "completed",
                "passed": False,
                "issue_count": 0,
                "overflow_witnesses": 0,
                "pipeline_metrics": {
                    "proof_eligible_candidates": 2,
                    "proof_attempted_candidates": 2,
                    "proof_diagnostic_counts": {"exploration:wall_timeout": 2},
                },
            },
            {
                "id": "fixed",
                "expected_outcome": "clean",
                "execution_status": "blocked",
                "failure_reason": "proof_timeout",
                "passed": False,
                "issue_count": 0,
                "overflow_witnesses": 0,
                "pipeline_metrics": {
                    "proof_eligible_candidates": 1,
                    "proof_attempted_candidates": 1,
                    "proof_diagnostic_counts": {"exploration:wall_timeout": 1},
                },
            },
        ]
    )

    assert metrics["completed_positives"] == 1
    assert metrics["missed_positives"] == 1
    assert metrics["completed_negatives"] == 0
    assert metrics["clean_negatives"] == 0
    assert metrics["blocked_cases"] == 1
    assert metrics["conditional_false_positive_rate"] is None
    assert metrics["stage_totals"]["proof_eligible_candidates"] == 3
    assert metrics["stage_totals"]["proof_attempted_candidates"] == 3
    assert metrics["stage_totals"]["proof_attempt_coverage"] == 1.0
    assert metrics["stage_totals"]["proof_diagnostic_counts"] == {"exploration:wall_timeout": 3}


def test_pipeline_stage_metrics_reads_existing_stage_artifacts(tmp_path: Path) -> None:
    module = _load_script_module()
    run_dir = tmp_path / "run"
    (run_dir / "discovery").mkdir(parents=True)
    (run_dir / "promotion").mkdir()
    (run_dir / "proof").mkdir()
    (run_dir / "replay" / "one").mkdir(parents=True)
    (run_dir / "report").mkdir()
    (run_dir / "discovery" / "candidates.json").write_text(
        json.dumps({"candidates": [{"candidate_id": "one"}, {"candidate_id": "two"}]}),
        encoding="utf-8",
    )
    (run_dir / "promotion" / "promotion_events.json").write_text(
        json.dumps(
            {
                "promotion_events": [
                    {"candidate_id": "one", "to_status": "proof_ready"},
                    {"candidate_id": "one", "to_status": "replay_ready"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "proof" / "_concolic_run_summary.json").write_text(
        json.dumps(
            {
                "verdict_counts": {"overflow_witness": 1, "path_unsat": 1},
                "eligible_count": 1,
                "attempted_count": 1,
                "timed_out_count": 0,
                "memory_limited_count": 0,
                "diagnostic_counts": {"input_model:symbolic_input_not_connected": 1},
                "skipped": [],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "replay" / "one" / "result.json").write_text(
        json.dumps({"result": "confirmed", "sink_reached": True, "bug_observed": True}),
        encoding="utf-8",
    )
    (run_dir / "report" / "vulnerabilities.json").write_text(
        json.dumps({"vulnerabilities": [{"candidate_id": "one"}]}),
        encoding="utf-8",
    )

    assert module.pipeline_stage_metrics(run_dir) == {
        "discovery_candidates": 2,
        "proof_ready_candidates": 1,
        "proof_eligible_candidates": 1,
        "proof_attempted_candidates": 1,
        "proof_skipped_candidates": 0,
        "proof_timed_out_candidates": 0,
        "proof_memory_limited_candidates": 0,
        "proof_diagnostic_counts": {"input_model:symbolic_input_not_connected": 1},
        "proof_attempt_coverage": 1.0,
        "proof_verdicts": 2,
        "replay_attempts": 1,
        "replay_confirmations": 1,
        "reports": 1,
    }
