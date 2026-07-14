import io
import json
import zipfile
from pathlib import Path
from typing import Any, Mapping

from binary_agent.analysis.witness import build_witness_plan
import binary_agent.capability_sweep as sweep_module
from binary_agent.capability_sweep import CapabilitySweepTarget, run_capability_sweep, run_capability_sweep_target
from binary_agent.capability_sweep import build_proof_blocker_inventory
from binary_agent.data.manifest import FunctionRecord, Manifest
from binary_agent.pipeline import CandidateState, CandidateStatus, build_source_to_sink_trace, has_reportable_source_to_sink
from binary_agent.reporting import AnalysisReport, ReportConfig, VulnerabilityReport, save_report_json


def _record(name: str, address: str, relative_path: str, text: str) -> FunctionRecord:
    return FunctionRecord(
        address=address,
        relative_address=int(address, 16),
        name=name,
        relative_path=relative_path,
        source_exists=True,
        ordinal=0,
        size_addresses=16,
        body_size_bytes=len(text),
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=len(text.encode("utf-8")),
        line_count=len(text.splitlines()),
        return_type="void",
        prototype=f"void {name}(void)",
        parameters=[],
        emit_c=True,
        string_refs=[],
        pcode_calls=[],
        pcode_stores=[],
        ambiguous_callsites=[],
    )


def _write_export(tmp_path: Path, sources: Mapping[str, str]) -> Path:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    records = []
    for index, (relative_path, text) in enumerate(sources.items()):
        (export_dir / relative_path).write_text(text)
        records.append(_record(relative_path.removesuffix(".c"), f"0x{0x1000 + index * 0x100:x}", relative_path, text))
    manifest = Manifest(
        binary="safe-demo.bin",
        generated_at="2026-06-20T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=records,
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))
    return export_dir


def test_blocker_inventory_uses_fixed_stage_order_and_deterministic_selection() -> None:
    rows = [
        {
            "id": "alpha-vulnerable",
            "label": "heap",
            "candidates": 1,
            "proof_ready_count": 1,
            "blockers": ["timeout_during_exploration"],
            "metadata": {"lane": "vulnerable", "blocked_expected_positive_count": 1},
        },
        {
            "id": "alpha-fixed",
            "label": "heap",
            "blockers": ["timeout_during_exploration"],
            "metadata": {"lane": "fixed"},
        },
        {
            "id": "beta-vulnerable",
            "label": "heap",
            "blockers": ["missing_exact_sink", "timeout_during_exploration"],
            "metadata": {"lane": "vulnerable", "blocked_expected_positive_count": 1},
        },
    ]
    inventory = build_proof_blocker_inventory(rows)
    assert inventory["schema_version"] == 2
    assert inventory["selected_expansion_blocker"]["primary_category"] == "detection_gap"
    beta_rows = [item for item in inventory["candidate_rows"] if item["target_id"] == "beta-vulnerable"]
    assert next(item for item in beta_rows if item["expected_positive_blocks"])["primary_category"] == "detection_gap"
    assert inventory["category_totals"]["detection_gap"] == 2


def test_blocker_inventory_selects_scoped_expected_case_not_global_artifact_noise() -> None:
    rows = [
        {
            "id": "patch-vulnerable",
            "blockers": ["archive_materialization_requires_backend_support"],
            "metadata": {
                "lane": "vulnerable",
                "proof_blocker_inventory_rows": [
                    {
                        "record_kind": "expected_positive",
                        "comparison_group": "patch",
                        "vulnerability_family": "double_free",
                        "input_model": "stdin",
                        "expectation_id": "double_free",
                        "candidate_status": "not_detected",
                        "primary_category": "detection_gap",
                        "primary_reason": "expected_positive_not_detected",
                        "expected_positive_blocks": 1,
                    }
                ],
            },
        },
        {
            "id": "patch-fixed",
            "blockers": ["archive_materialization_requires_backend_support"],
            "metadata": {"lane": "fixed", "proof_blocker_inventory_rows": []},
        },
    ]

    inventory = build_proof_blocker_inventory(rows)

    selected = inventory["selected_expansion_blocker"]
    assert selected["comparison_group"] == "patch"
    assert selected["primary_category"] == "detection_gap"
    assert selected["normalized_reason"] == "expected_positive_not_detected"
    assert selected["fixed_count"] == 0
    assert inventory["target_diagnostics"][0]["reasons"] == ["archive_materialization_requires_backend_support"]
    assert not [item for item in inventory["candidate_rows"] if item["target_id"] == "patch-fixed"]


def test_target_blocker_inventory_excludes_resolved_candidates_and_matched_cases(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "run"
    promotion_dir = artifact_dir / "promotion"
    promotion_dir.mkdir(parents=True)
    (promotion_dir / "candidate_states.json").write_text(
        json.dumps(
            {
                "candidate_states": [
                    {
                        "candidate_id": "confirmed-double-free",
                        "vulnerability_type": "double_free",
                        "status": "report_ready",
                        "blockers": [],
                        "proof_obligations": [],
                    },
                    {
                        "candidate_id": "pending-overflow",
                        "vulnerability_type": "heap_overflow",
                        "status": "needs_refinement",
                        "blockers": ["overflow_condition_proof"],
                        "proof_obligations": [],
                    },
                ]
            }
        )
    )
    target = CapabilitySweepTarget(
        id="demo-vulnerable",
        artifact_dir=str(artifact_dir),
        expected_positives=("double_free",),
        metadata={"lane": "vulnerable", "comparison_group": "demo", "input_model": "stdin"},
    )

    rows = sweep_module._target_proof_blocker_inventory_rows(
        target,
        artifact_dir=artifact_dir,
        report=None,
    )

    assert [row["candidate_id"] for row in rows] == ["pending-overflow"]
    assert rows[0]["record_kind"] == "unresolved_candidate"


def test_witness_plan_materializes_trial_inputs_without_claiming_proof() -> None:
    pack: dict[str, Any] = {
        "candidate_id": "cand-optarg",
        "candidate": {"vulnerability_type": "stack_overflow"},
        "type_facts": {
            "capacity_bytes": 8,
            "process_input": {"input_model": "argv"},
            "source_to_sink_trace": {"input_model": "argv"},
        },
        "source": {"evidence": ["getopt writes optarg into the vulnerable sink"]},
        "sink": {"name": "strcpy"},
        "grounded_refs": ["object:0"],
    }

    plan = build_witness_plan(pack)

    assert plan.to_dict()["artifact_kind"] == "witness_plan"
    assert plan.to_dict()["proof_status"] == "trial_only_until_replay"
    assert {item.kind for item in plan.witnesses} >= {"argv_payload", "argv_option_argument"}
    assert all(item.proof_status == "trial_only" for item in plan.witnesses)

    http_plan = build_witness_plan(
        {
            "candidate_id": "cand-http",
            "candidate": {"vulnerability_type": "command_injection"},
            "type_facts": {
                "process_input": {"input_model": "http_daemon"},
                "replay_hints": {
                    "method": "POST",
                    "path": "/diag",
                    "body": "cmd=id",
                    "proof_oracle": {"marker": "uid="},
                },
            },
        }
    )
    assert http_plan.replay_request_inputs[0]["input_model"] == "http_daemon"
    assert http_plan.replay_request_inputs[0]["path"] == "/diag"

    cgi_plan = build_witness_plan(
        {
            "candidate_id": "cand-cgi",
            "candidate": {"vulnerability_type": "command_injection"},
            "type_facts": {"process_input": {"input_model": "http_cgi"}},
            "source": {"route": {"method": "POST", "path": "/cgi-bin/diag"}},
        }
    )
    cgi_input = cgi_plan.replay_request_inputs[0]
    assert cgi_input["input_model"] == "http_cgi"
    assert cgi_input["form"]["cmd"].startswith("BINARY_AGENT_CMD")
    assert cgi_input["body"].startswith("cmd=BINARY_AGENT_CMD")

    stdin_plan = build_witness_plan(
        {"candidate_id": "cand-stdin", "type_facts": {"process_input": {"input_model": "stdin"}}}
    )
    stdin_witness = next(item for item in stdin_plan.witnesses if item.kind == "stdin_record")
    assert stdin_witness.replay_request_input["input_model"] == "stdin"
    assert stdin_witness.replay_request_input["stdin"]

    env_plan = build_witness_plan(
        {
            "candidate_id": "cand-env",
            "type_facts": {"process_input": {"input_model": "env", "env_key": "UPLOAD_DIR"}},
        }
    )
    env_witness = next(item for item in env_plan.witnesses if item.kind == "env_var")
    assert env_witness.replay_request_input["env"]["UPLOAD_DIR"]

    line_plan = build_witness_plan(
        {
            "candidate_id": "cand-line",
            "type_facts": {"process_input": {"input_model": "line_file", "file_name": "records.txt"}},
        }
    )
    line_witness = next(item for item in line_plan.witnesses if item.kind == "line_file")
    assert line_witness.replay_request_input["input_model"] == "file"
    assert line_witness.replay_request_input["file_name"] == "records.txt"

    argv_file_stdin_plan = build_witness_plan(
        {
            "candidate_id": "cand-file-stdin",
            "type_facts": {"process_input": {"input_model": "argv_file_stdin", "file_name": "input.dat"}},
        }
    )
    argv_file_stdin_witness = next(item for item in argv_file_stdin_plan.witnesses if item.kind == "argv_file_stdin")
    assert argv_file_stdin_witness.replay_request_input["argv"] == ["input.dat"]
    assert argv_file_stdin_witness.replay_request_input["stdin"]

    directory_plan = build_witness_plan(
        {"candidate_id": "cand-dir", "type_facts": {"process_input": {"input_model": "argv_directory"}}}
    )
    directory_witness = next(item for item in directory_plan.witnesses if item.kind == "directory_file_pair")
    assert directory_witness.replay_request_input["input_model"] == "argv_directory"
    assert directory_witness.replay_request_input["directory_entries"][0]["name"]

    socket_plan = build_witness_plan(
        {"candidate_id": "cand-socket", "type_facts": {"process_input": {"input_model": "socket_service"}}}
    )
    socket_witness = next(item for item in socket_plan.witnesses if item.kind == "socket_payload")
    assert socket_witness.replay_request_input["input_model"] == "socket_service"
    assert socket_witness.replay_request_input["payload"]

    archive_plan = build_witness_plan({"candidate_id": "cand-zip", "source": {"evidence": ["zip archive record"]}})
    assert archive_plan.input_model == "archive_text_record"
    archive_witness = next(item for item in archive_plan.witnesses if item.kind == "archive_text_record")
    archive_input = archive_witness.replay_request_input
    with zipfile.ZipFile(io.BytesIO(bytes.fromhex(str(archive_input["file_input_hex"])))) as archive:
        assert archive.read("payload.txt").startswith(b"A")
    assert "archive_materialization_requires_backend_support" in archive_plan.blockers

    config_plan = build_witness_plan(
        {
            "candidate_id": "cand-config",
            "candidate": {"vulnerability_type": "command_injection"},
            "type_facts": {"process_input": {"input_model": "config", "config_key": "diagnostic_cmd"}},
            "source": {"evidence": ["configuration file key diagnostic_cmd reaches system"]},
        }
    )
    config_witness = next(item for item in config_plan.witnesses if item.kind == "config_key_value_file")
    assert config_witness.proof_status == "trial_only"
    assert config_witness.payload["key"] == "diagnostic_cmd"
    assert config_witness.replay_request_input["input_model"] == "file"
    assert config_witness.replay_request_input["config"]["diagnostic_cmd"].startswith("BINARY_AGENT_CMD")


def test_capability_sweep_writes_summary_for_tiny_negative(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "main.c": """// Function: main
// Address: 0x1000

void main(void)
{
  return;
}
""",
        },
    )
    targets = tmp_path / "targets.json"
    targets.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "id": "safe-target",
                        "label": "negative",
                        "export_dir": str(export_dir),
                        "expected_negatives": ["safe_bounded_write", "benign_parser_input"],
                    }
                ]
            }
        )
    )

    summary = run_capability_sweep(targets, tmp_path / "sweep")

    summary_path = tmp_path / "sweep" / "capability_sweep_summary.json"
    rows_path = tmp_path / "sweep" / "capability_sweep_targets.json"
    row_path = tmp_path / "sweep" / "safe-target" / "capability_sweep_row.json"
    audit_path = tmp_path / "sweep" / "safe-target" / "negative_precision_audit.json"
    assert summary_path.exists()
    assert rows_path.exists()
    assert row_path.exists()
    assert audit_path.exists()
    summary_payload = json.loads(summary_path.read_text())
    rows_payload = json.loads(rows_path.read_text())
    row_payload = json.loads(row_path.read_text())
    assert summary_payload["artifact_kind"] == "capability_sweep_summary"
    assert rows_payload["artifact_kind"] == "capability_sweep_targets"
    assert row_payload["artifact_kind"] == "capability_sweep_row"
    assert row_payload["schema_version"] == 2
    assert summary.totals["targets_with_errors"] == 0
    assert summary.rows[0].rejected_negatives == 2
    assert summary.rows[0].reports == 0
    audit = json.loads(audit_path.read_text())
    assert audit["artifact_kind"] == "negative_precision_audit"
    assert audit["outcome"] == "rejected"
    assert audit["rejected_count"] == 2
    assert audit["blocked_count"] == 0
    assert audit["observed_report_count"] == 0
    assert [case["label"] for case in audit["cases"]] == ["safe_bounded_write", "benign_parser_input"]
    assert {case["outcome"] for case in audit["cases"]} == {"rejected"}


def test_capability_sweep_negative_audit_records_false_positive_reports(tmp_path: Path, monkeypatch) -> None:
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def fake_run_pipeline(export_dir_arg: Path, **kwargs: Any) -> AnalysisReport:
        kwargs["write_evidence_packs_dir"].mkdir(parents=True, exist_ok=True)
        return AnalysisReport(
            ReportConfig(binary="demo", export_dir=str(export_dir_arg), run_label="test"),
            vulnerability_reports=[
                VulnerabilityReport(
                    report_id="r1",
                    slug="r1",
                    binary="demo",
                    function_name="safe",
                    address="0x1000",
                    relative_path="safe.c",
                    severity="high",
                    summary="False positive report",
                    reasoning="test",
                    vulnerability_type="stack_overflow",
                    candidate_id="cand-fp",
                )
            ],
        )

    monkeypatch.setattr(sweep_module, "run_pipeline", fake_run_pipeline)

    row = run_capability_sweep_target(
        CapabilitySweepTarget(
            id="negative-with-report",
            label="negative",
            export_dir=str(export_dir),
            expected_negatives=("guarded_index",),
        ),
        tmp_path / "out",
    )

    audit = json.loads(Path(row.negative_audit_path).read_text())
    assert row.rejected_negatives == 0
    assert row.false_positive_notes == ["expected negative target produced 1 report(s)"]
    assert audit["outcome"] == "reported"
    assert audit["observed_report_count"] == 1
    assert audit["observed_reports"][0]["candidate_id"] == "cand-fp"
    assert audit["cases"] == [
        {
            "label": "guarded_index",
            "outcome": "reported",
            "observed_report_count": 1,
            "blockers": [],
            "errors": [],
        }
    ]


def test_capability_sweep_summarizes_precomputed_report_and_evidence(tmp_path: Path) -> None:
    report_path = tmp_path / "analysis_report.json"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    save_report_json(
        AnalysisReport(
            ReportConfig(binary="demo", export_dir="/exports/demo", run_label="precomputed"),
            candidate_findings=[{"candidate_id": "cand-1"}],
            candidate_confirmations={"cand-1": {"candidate_id": "cand-1", "status": "confirmed_bug"}},
            vulnerability_reports=[
                VulnerabilityReport(
                    report_id="r1",
                    slug="r1",
                    binary="demo",
                    function_name="vulnerable",
                    address="0x1000",
                    relative_path="demo.c",
                    severity="high",
                    summary="Precomputed report",
                    reasoning="artifact-backed",
                    vulnerability_type="stack_overflow",
                    candidate_id="cand-1",
                )
            ],
            stage_metrics={"proof_ready_count": 1},
        ),
        report_path,
    )
    (evidence_dir / "cand-1.json").write_text(
        json.dumps(
            {
                "candidate_id": "cand-1",
                "candidate": {"vulnerability_type": "stack_overflow"},
                "type_facts": {"capacity_bytes": 8, "process_input": {"input_model": "argv"}},
                "source": {"evidence": ["argv source"]},
                "sink": {"name": "strcpy"},
            }
        )
    )
    targets = tmp_path / "targets.json"
    targets.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "id": "precomputed",
                        "analysis_report_path": str(report_path),
                        "evidence_dir": str(evidence_dir),
                        "expected_positives": ["stack_overflow", "command_injection"],
                    }
                ]
            }
        )
    )

    summary = run_capability_sweep(targets, tmp_path / "sweep")
    row = summary.rows[0]

    assert row.errors == []
    assert row.reports == 1
    assert row.candidates == 1
    assert row.confirmed_bugs == 1
    assert row.proof_ready_count == 1
    assert row.false_positive_notes == ["expected positive reports missing: command_injection"]
    assert row.report_path == str(report_path)
    assert row.evidence_dir == str(evidence_dir)
    assert row.witness_plan_dir
    assert row.positive_audit_path
    assert row.metadata["expected_positive_count"] == 2
    assert row.metadata["matched_expected_positive_count"] == 1
    assert row.metadata["missing_expected_positive_count"] == 1
    assert row.metadata["blocked_expected_positive_count"] == 0
    assert row.metadata["expected_positive_cases"] == [
        {
            "label": "stack_overflow",
            "outcome": "matched",
            "matched_report_count": 1,
            "matched_reports": [
                {
                    "report_id": "r1",
                    "candidate_id": "cand-1",
                    "vulnerability_type": "stack_overflow",
                    "function_name": "vulnerable",
                    "address": "0x1000",
                    "summary": "Precomputed report",
                }
            ],
        },
        {
            "label": "command_injection",
            "outcome": "missing",
            "matched_report_count": 0,
            "matched_reports": [],
        },
    ]
    assert row.metadata["evidence_pack_count"] == 1
    assert row.metadata["witness_plan_count"] == 1
    assert row.metadata["witness_plan_missing_count"] == 0
    assert row.metadata["witness_plan_coverage"] == "complete"
    assert summary.totals["evidence_packs"] == 1
    assert summary.totals["expected_positives"] == 2
    assert summary.totals["matched_expected_positives"] == 1
    assert summary.totals["missing_expected_positives"] == 1
    assert summary.totals["blocked_expected_positives"] == 0
    assert summary.totals["witness_plans"] == 1
    assert summary.totals["witness_plan_missing_count"] == 0
    aggregate_witness_plan = json.loads((Path(row.witness_plan_dir) / "witness_plan.json").read_text())
    assert aggregate_witness_plan["artifact_kind"] == "witness_plan"
    assert aggregate_witness_plan["plans"][0]["plan"]["artifact_kind"] == "witness_plan"
    positive_audit = json.loads(Path(row.positive_audit_path).read_text())
    assert positive_audit["artifact_kind"] == "positive_expectation_audit"
    assert positive_audit["outcome"] == "missing"
    assert positive_audit["expected_positive_count"] == 2
    assert positive_audit["matched_expected_positive_count"] == 1
    assert positive_audit["missing_expected_positive_count"] == 1
    assert positive_audit["blocked_expected_positive_count"] == 0
    assert positive_audit["observed_report_count"] == 1
    assert positive_audit["cases"] == row.metadata["expected_positive_cases"]
    assert positive_audit["false_positive_notes"] == ["expected positive reports missing: command_injection"]


def test_capability_sweep_positive_audit_records_blocked_expected_positive(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()

    row = run_capability_sweep_target(
        CapabilitySweepTarget(
            id="blocked-positive",
            label="known_positive",
            rootfs_path=str(rootfs),
            expected_positives=("stack_overflow",),
        ),
        tmp_path / "sweep",
    )

    assert row.errors == []
    assert row.reports == 0
    assert "decompiled_export_missing" in row.blockers
    assert row.positive_audit_path
    assert row.metadata["expected_positive_count"] == 1
    assert row.metadata["matched_expected_positive_count"] == 0
    assert row.metadata["missing_expected_positive_count"] == 0
    assert row.metadata["blocked_expected_positive_count"] == 1
    positive_audit = json.loads(Path(row.positive_audit_path).read_text())
    assert positive_audit["artifact_kind"] == "positive_expectation_audit"
    assert positive_audit["outcome"] == "blocked"
    assert positive_audit["cases"] == [
        {
            "label": "stack_overflow",
            "outcome": "blocked",
            "matched_report_count": 0,
            "matched_reports": [],
        }
    ]
    assert positive_audit["blockers"] == ["decompiled_export_missing"]
    assert positive_audit["observed_report_count"] == 0


def test_optional_capability_sweep_target_records_missing_inputs_as_blockers(tmp_path: Path) -> None:
    row = run_capability_sweep_target(
        CapabilitySweepTarget(
            id="optional-missing",
            label="known_positive",
            optional=True,
            artifact_dir=str(tmp_path / "missing-run"),
            analysis_report_path=str(tmp_path / "missing-report.json"),
            export_dir=str(tmp_path / "missing-export"),
            binary_path=str(tmp_path / "missing-binary"),
            expected_positives=("stack_overflow",),
        ),
        tmp_path / "sweep",
    )

    assert row.errors == []
    assert row.metadata["optional"] is True
    assert row.positive_audit_path
    assert any(blocker.startswith("optional_target_unavailable:missing_artifact_dir:") for blocker in row.blockers)
    assert any(blocker.startswith("optional_target_unavailable:missing_analysis_report:") for blocker in row.blockers)
    assert any(blocker.startswith("optional_target_unavailable:missing_export_dir:") for blocker in row.blockers)
    assert row.metadata["blocker_category_counts"] == {"missing": 4}
    positive_audit = json.loads(Path(row.positive_audit_path).read_text())
    assert positive_audit["outcome"] == "blocked"
    assert positive_audit["blocked_expected_positive_count"] == 1


def test_capability_sweep_summarizes_existing_proof_gated_run_dir(tmp_path: Path) -> None:
    run_dir = tmp_path / "proof_run"
    evidence_dir = run_dir / "evidence"
    promotion_dir = run_dir / "promotion"
    replay_dir = run_dir / "replay" / "cand-1"
    service_replay_dir = run_dir / "replay" / "cand-service"
    semantic_replay_dir = run_dir / "replay" / "cand-command"
    safe_semantic_replay_dir = run_dir / "replay" / "cand-safe-command"
    report_dir = run_dir / "report"
    source_trace_dir = report_dir / "source_to_sink"
    intake_dir = run_dir / "intake"
    for path in (
        evidence_dir,
        promotion_dir,
        replay_dir,
        service_replay_dir,
        semantic_replay_dir,
        safe_semantic_replay_dir,
        report_dir,
        source_trace_dir,
        intake_dir,
    ):
        path.mkdir(parents=True)
    (intake_dir / "target.json").write_text(
        json.dumps({"schema_version": 1, "kind": "single_binary", "path": "/bin/demo", "inventory_root": "/bin/demo"})
    )
    (intake_dir / "binaries.json").write_text(json.dumps({"binaries": [{"path": "/bin/demo", "sha256": "abc"}]}))
    (intake_dir / "services.json").write_text(json.dumps({"services": []}))
    (intake_dir / "routes.json").write_text(json.dumps({"routes": []}))
    (intake_dir / "configs.json").write_text(json.dumps({"configs": []}))
    (evidence_dir / "cand-1.json").write_text(
        json.dumps(
            {
                "candidate_id": "cand-1",
                "candidate": {"vulnerability_type": "heap_overflow"},
                "type_facts": {"capacity_bytes": 16, "process_input": {"input_model": "stdin"}},
                "source": {"evidence": ["stdin source"]},
                "sink": {"name": "memcpy"},
            }
        )
    )
    (promotion_dir / "candidate_states.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "candidate_states": [
                    {"candidate_id": "cand-1", "status": "report_ready"},
                    {
                        "candidate_id": "cand-2",
                        "status": "needs_refinement",
                        "blockers": ["guarded_index", "unsupported_function_entry_sink"],
                    },
                ],
            }
        )
    )
    (replay_dir / "result.json").write_text(
        json.dumps(
            {
                "candidate_id": "cand-1",
                "result": "confirmed",
                "sink_reached": True,
                "bug_observed": True,
                "control_result": {
                    "ghidra_dynamic_proof": {
                        "candidate_id": "cand-1",
                        "proof_kind": "ghidra_dynamic_overflow",
                        "status": "heap_overflow_proven",
                        "proof_scope": "process_entrypoint",
                        "sink_reached": True,
                        "exact_sink_reached": True,
                    }
                },
            }
        )
    )
    (replay_dir / "process_witness_attempt.json").write_text(
        json.dumps(
            {
                "artifact_kind": "process_witness_attempt",
                "schema_version": 1,
                "candidate_id": "cand-1",
                "input_model": "file",
                "proof_scope": "process_entrypoint",
                "status": "observed",
                "attempt_count": 2,
                "observed_count": 1,
                "unsupported_count": 1,
                "blocked_count": 0,
                "status_counts": {"observed": 1, "unsupported": 1},
                "input_model_counts": {"file": 1, "stdin": 1},
                "blockers": [],
                "attempts": [
                    {
                        "attempt_source": "file_seed",
                        "status": "observed",
                        "candidate_id": "cand-1",
                        "input_model": "file",
                        "dynamic_proof_status": "heap_overflow_proven",
                        "dynamic_proof_observed": True,
                    },
                    {
                        "attempt_source": "stdin_seed",
                        "status": "unsupported",
                        "candidate_id": "cand-1",
                        "input_model": "stdin",
                        "dynamic_proof_status": "unsupported",
                        "dynamic_proof_reason": "unsupported_process_input_setup:stdin",
                        "dynamic_proof_observed": False,
                    },
                ],
            }
        )
    )
    (service_replay_dir / "service_replay_result.json").write_text(
        json.dumps(
            {
                "artifact_kind": "service_replay_result",
                "candidate_id": "cand-service",
                "status": "blocked",
                "blocked_reason": "missing rootfs for service replay",
                "blockers": ["missing_rootfs"],
            }
        )
    )
    (semantic_replay_dir / "dynamic_command_effect_observation.json").write_text(
        json.dumps(
            {
                "candidate_id": "cand-command",
                "kind": "command_effect",
                "status": "command_effect_observed",
                "bug_observed": True,
                "sink_reached": True,
            }
        )
    )
    (safe_semantic_replay_dir / "dynamic_command_effect_observation.json").write_text(
        json.dumps(
            {
                "candidate_id": "cand-safe-command",
                "kind": "command_effect",
                "status": "command_effect_not_observed",
                "bug_observed": False,
                "sink_reached": False,
            }
        )
    )
    (report_dir / "vulnerabilities.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "vulnerabilities": [
                    {
                        "candidate_id": "cand-1",
                        "title": "Heap overflow in demo",
                        "vulnerability": "heap_overflow",
                        "affected_component": "demo",
                    }
                ],
            }
        )
    )
    (source_trace_dir / "cand-1_source_to_sink_trace.json").write_text(
        json.dumps(
            {
                "artifact_kind": "source_to_sink_trace",
                "schema_version": 2,
                "candidate_id": "cand-1",
                "status": "proven",
                "confidence": "proven",
                "input_model": "stdin",
                "controlled_roles": ["write_source:source_controlled"],
                "propagation_path": [{"function": "main"}, {"function": "vulnerable"}],
                "dynamic_artifacts": [str(replay_dir / "result.json")],
            }
        )
    )
    targets = tmp_path / "targets.json"
    targets.write_text(json.dumps({"targets": [{"id": "existing-proof-run", "run_dir": str(run_dir)}]}))

    summary = run_capability_sweep(targets, tmp_path / "sweep")
    row = summary.rows[0]

    assert row.errors == []
    assert row.artifact_dir == str(run_dir)
    assert row.candidates == 2
    assert row.confirmations == 1
    assert row.confirmed_bugs == 1
    assert row.proof_ready_count == 1
    assert row.dynamic_proofs == 2
    assert row.metadata["dynamic_proof_count"] == 2
    assert row.metadata["dynamic_proof_status_counts"] == {
        "command_effect_observed": 1,
        "heap_overflow_proven": 1,
    }
    assert row.metadata["dynamic_memory_proof_status_counts"] == {"heap_overflow_proven": 1}
    assert row.metadata["dynamic_semantic_observed_kind_counts"] == {"command_effect": 1}
    assert row.metadata["dynamic_semantic_observation_status_counts"] == {
        "command_effect_not_observed": 1,
        "command_effect_observed": 1,
    }
    assert row.metadata["dynamic_semantic_observation_count"] == 2
    assert row.metadata["dynamic_semantic_not_observed_count"] == 1
    assert row.metadata["process_witness_attempts"] == 2
    assert row.metadata["process_witness_observed"] == 1
    assert row.metadata["process_witness_unsupported"] == 1
    assert row.metadata["process_witness_blocked"] == 0
    assert row.metadata["process_witness_status_counts"] == {"observed": 1, "unsupported": 1}
    assert row.metadata["process_witness_input_model_counts"] == {"file": 1, "stdin": 1}
    assert row.unsupported_blockers == 3
    assert row.metadata["blocker_category_counts"] == {"missing": 2, "unsupported": 1}
    assert row.reports == 1
    assert "guarded_index" in row.blockers
    assert "unsupported_function_entry_sink" in row.blockers
    assert row.report_path == str(report_dir / "vulnerabilities.json")
    assert row.evidence_dir == str(evidence_dir)
    assert row.target_provenance["target_kind"] == "single_binary"
    assert row.metadata["artifact_candidate_status_counts"]["report_ready"] == 1
    assert row.metadata["artifact_replay_result_counts"]["confirmed"] == 1
    assert row.metadata["artifact_replay_result_counts"]["blocked"] == 1
    assert row.metadata["witness_plan_count"] == 1
    assert row.metadata["witness_plan_coverage"] == "complete"
    assert row.metadata["source_to_sink_trace_count"] == 1
    assert row.metadata["source_to_sink_trace_status_counts"]["proven"] == 1
    assert row.metadata["source_to_sink_trace_confidence_counts"]["proven"] == 1
    assert row.metadata["source_to_sink_report_ready_count"] == 1
    assert row.metadata["source_to_sink_report_ready_trace_missing_count"] == 0
    assert row.metadata["source_to_sink_report_ready_trace_incomplete_count"] == 0
    assert row.metadata["source_to_sink_report_ready_trace_coverage"] == "complete"
    assert summary.totals["dynamic_proof_status_counts"] == {
        "command_effect_observed": 1,
        "heap_overflow_proven": 1,
    }
    assert summary.totals["dynamic_memory_proof_status_counts"] == {"heap_overflow_proven": 1}
    assert summary.totals["dynamic_semantic_observed_kind_counts"] == {"command_effect": 1}
    assert summary.totals["dynamic_semantic_observation_status_counts"] == {
        "command_effect_not_observed": 1,
        "command_effect_observed": 1,
    }
    assert summary.totals["dynamic_semantic_observation_count"] == 2
    assert summary.totals["dynamic_semantic_not_observed_count"] == 1
    assert summary.totals["process_witness_attempts"] == 2
    assert summary.totals["process_witness_observed"] == 1
    assert summary.totals["process_witness_unsupported"] == 1
    assert summary.totals["process_witness_blocked"] == 0
    assert summary.totals["process_witness_status_counts"] == {"observed": 1, "unsupported": 1}
    assert summary.totals["process_witness_input_model_counts"] == {"file": 1, "stdin": 1}
    assert summary.totals["unsupported_blockers"] == 3
    assert summary.totals["blocker_category_counts"] == {"missing": 2, "unsupported": 1}
    assert summary.totals["source_to_sink_traces"] == 1
    assert summary.totals["source_to_sink_report_ready_trace_missing_count"] == 0
    assert summary.totals["source_to_sink_report_ready_trace_incomplete_count"] == 0


def test_capability_sweep_flags_report_ready_source_trace_gap(tmp_path: Path) -> None:
    run_dir = tmp_path / "trace_gap_run"
    promotion_dir = run_dir / "promotion"
    promotion_dir.mkdir(parents=True)
    (promotion_dir / "candidate_states.json").write_text(
        json.dumps({"candidate_states": [{"candidate_id": "cand-gap", "status": "report_ready"}]})
    )

    row = run_capability_sweep_target(
        CapabilitySweepTarget(id="trace-gap", artifact_dir=str(run_dir)),
        tmp_path / "sweep",
    )

    assert row.metadata["source_to_sink_report_ready_count"] == 1
    assert row.metadata["source_to_sink_report_ready_trace_missing_count"] == 1
    assert row.metadata["source_to_sink_report_ready_trace_coverage"] == "missing"
    assert row.metadata["source_to_sink_report_ready_trace_gaps"] == [
        {"candidate_id": "cand-gap", "gaps": ["missing_source_to_sink_trace_artifact"]}
    ]
    assert "source_to_sink_trace_missing_for_report_ready:1" in row.blockers


def test_capability_sweep_flags_incomplete_report_ready_source_trace(tmp_path: Path) -> None:
    run_dir = tmp_path / "trace_incomplete_run"
    promotion_dir = run_dir / "promotion"
    source_trace_dir = run_dir / "report" / "source_to_sink"
    replay_dir = run_dir / "replay" / "cand-incomplete"
    for path in (promotion_dir, source_trace_dir, replay_dir):
        path.mkdir(parents=True)
    replay_result = replay_dir / "result.json"
    replay_result.write_text(json.dumps({"candidate_id": "cand-incomplete", "result": "confirmed"}))
    (promotion_dir / "candidate_states.json").write_text(
        json.dumps({"candidate_states": [{"candidate_id": "cand-incomplete", "status": "report_ready"}]})
    )
    (source_trace_dir / "cand-incomplete_source_to_sink_trace.json").write_text(
        json.dumps(
            {
                "artifact_kind": "source_to_sink_trace",
                "candidate_id": "cand-incomplete",
                "status": "proven",
                "confidence": "proven",
                "input_model": "argv",
                "controlled_roles": ["write_source:not_controlled"],
                "propagation_path": [{"function": "main"}, {"function": "handler"}],
                "dynamic_artifacts": [str(replay_result)],
            }
        )
    )

    row = run_capability_sweep_target(
        CapabilitySweepTarget(id="trace-incomplete", artifact_dir=str(run_dir)),
        tmp_path / "sweep",
    )

    assert row.metadata["source_to_sink_report_ready_trace_missing_count"] == 0
    assert row.metadata["source_to_sink_report_ready_trace_incomplete_count"] == 1
    assert row.metadata["source_to_sink_report_ready_trace_coverage"] == "partial"
    assert row.metadata["source_to_sink_report_ready_trace_gaps"] == [
        {
            "candidate_id": "cand-incomplete",
            "path": str(source_trace_dir / "cand-incomplete_source_to_sink_trace.json"),
            "gaps": ["missing_controlled_role"],
        }
    ]
    assert "source_to_sink_trace_incomplete_for_report_ready:1" in row.blockers


def test_capability_sweep_negative_audit_observes_artifact_run_reports(tmp_path: Path) -> None:
    run_dir = tmp_path / "negative_run"
    report_dir = run_dir / "report"
    promotion_dir = run_dir / "promotion"
    for path in (report_dir, promotion_dir):
        path.mkdir(parents=True)
    (promotion_dir / "candidate_states.json").write_text(
        json.dumps({"candidate_states": [{"candidate_id": "cand-fp", "status": "report_ready"}]})
    )
    (report_dir / "vulnerabilities.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "vulnerabilities": [
                    {
                        "candidate_id": "cand-fp",
                        "title": "Unexpected negative report",
                        "vulnerability": "stack_overflow",
                        "affected_component": "safe-parser",
                    }
                ],
            }
        )
    )

    row = run_capability_sweep_target(
        CapabilitySweepTarget(
            id="negative-proof-run",
            label="negative",
            artifact_dir=str(run_dir),
            expected_negatives=("guarded_index",),
        ),
        tmp_path / "sweep",
    )

    audit = json.loads(Path(row.negative_audit_path).read_text())
    assert row.reports == 1
    assert row.rejected_negatives == 0
    assert row.false_positive_notes == ["expected negative target produced 1 report(s)"]
    assert audit["outcome"] == "reported"
    assert audit["observed_report_count"] == 1
    assert audit["observed_reports"] == [
        {
            "candidate_id": "cand-fp",
            "report_id": "cand-fp",
            "vulnerability_type": "stack_overflow",
            "summary": "Unexpected negative report",
        }
    ]
    assert audit["cases"][0]["outcome"] == "reported"


def test_capability_sweep_flags_incomplete_witness_plan_coverage(tmp_path: Path, monkeypatch) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "cand-1.json").write_text(json.dumps({"candidate_id": "cand-1"}))
    report_path = tmp_path / "analysis_report.json"
    save_report_json(
        AnalysisReport(ReportConfig(binary="demo", export_dir="/exports/demo", run_label="precomputed")),
        report_path,
    )
    targets = tmp_path / "targets.json"
    targets.write_text(
        json.dumps(
            {
                "targets": [
                    {"id": "missing-witness", "analysis_report_path": str(report_path), "evidence_dir": str(evidence_dir)}
                ]
            }
        )
    )
    monkeypatch.setattr(sweep_module, "write_witness_plans_for_evidence_dir", lambda *_args, **_kwargs: {})

    summary = run_capability_sweep(targets, tmp_path / "sweep")
    row = summary.rows[0]

    assert row.metadata["evidence_pack_count"] == 1
    assert row.metadata["witness_plan_count"] == 0
    assert row.metadata["witness_plan_missing_count"] == 1
    assert row.metadata["witness_plan_coverage"] == "missing"
    assert "witness_plan_missing:1" in row.blockers
    assert summary.totals["witness_plan_missing_count"] == 1


def test_capability_sweep_requires_proof_gated_artifacts_for_dynamic_confirmation(
    tmp_path: Path, monkeypatch
) -> None:
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    binary = tmp_path / "target.sh"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    captured: dict[str, Any] = {}

    def fake_run_pipeline(export_dir_arg: Path, **kwargs: Any) -> AnalysisReport:
        captured["export_dir"] = export_dir_arg
        captured.update(kwargs)
        evidence_dir = kwargs["write_evidence_packs_dir"]
        evidence_dir.mkdir(parents=True, exist_ok=True)
        return AnalysisReport(
            ReportConfig(binary=str(binary), export_dir=str(export_dir_arg), run_label="test"),
        )

    monkeypatch.setattr(sweep_module, "run_pipeline", fake_run_pipeline)

    row = run_capability_sweep_target(
        CapabilitySweepTarget(
            id="dynamic-target",
            export_dir=str(export_dir),
            binary_path=str(binary),
            dynamic_confirm=True,
            replay_mode="native",
        ),
        tmp_path / "out",
    )

    assert row.errors == []
    assert captured["report_policy"] == "confirmed"
    assert "dynamic_confirm_binary" not in captured
    assert "dynamic_confirmation_requires_proof_gated_artifact_dir" in row.blockers
    assert row.metadata["replay_mode"] == "native"
    assert row.metadata["dynamic_confirm_requested"] is True
    assert row.metadata["dynamic_confirm_eligible"] is True
    assert row.metadata["dynamic_confirm_output_dir"] == str(tmp_path / "out" / "dynamic_confirmations")


def test_capability_sweep_default_report_policy_is_confirmed(tmp_path: Path, monkeypatch) -> None:
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    captured: dict[str, Any] = {}

    def fake_run_pipeline(export_dir_arg: Path, **kwargs: Any) -> AnalysisReport:
        captured["export_dir"] = export_dir_arg
        captured.update(kwargs)
        kwargs["write_evidence_packs_dir"].mkdir(parents=True, exist_ok=True)
        return AnalysisReport(ReportConfig(binary="demo", export_dir=str(export_dir_arg), run_label="test"))

    monkeypatch.setattr(sweep_module, "run_pipeline", fake_run_pipeline)

    row = run_capability_sweep_target(
        CapabilitySweepTarget(id="default-policy-target", export_dir=str(export_dir)),
        tmp_path / "out",
    )

    assert row.errors == []
    assert captured["report_policy"] == "confirmed"


def test_capability_sweep_ignores_deterministic_report_policy(tmp_path: Path, monkeypatch) -> None:
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    captured: dict[str, Any] = {}

    def fake_run_pipeline(export_dir_arg: Path, **kwargs: Any) -> AnalysisReport:
        captured.update(kwargs)
        kwargs["write_evidence_packs_dir"].mkdir(parents=True, exist_ok=True)
        return AnalysisReport(ReportConfig(binary="demo", export_dir=str(export_dir_arg), run_label="test"))

    monkeypatch.setattr(sweep_module, "run_pipeline", fake_run_pipeline)

    row = run_capability_sweep_target(
        CapabilitySweepTarget(id="deterministic-policy-target", export_dir=str(export_dir), report_policy="deterministic"),
        tmp_path / "out",
    )

    assert row.errors == []
    assert captured["report_policy"] == "confirmed"
    assert "unsupported_report_policy_for_capability_sweep:deterministic" in row.blockers


def test_capability_sweep_inventories_rootfs_without_export_error(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "etc" / "init.d").mkdir(parents=True)
    (rootfs / "etc").mkdir(exist_ok=True)
    (rootfs / "usr" / "bin").mkdir(parents=True)
    (rootfs / "www").mkdir()
    daemon = rootfs / "usr" / "bin" / "demo_httpd"
    daemon.write_text("#!/bin/sh\nexit 0\n")
    daemon.chmod(0o755)
    init = rootfs / "etc" / "init.d" / "demo"
    init.write_text("#!/bin/sh\n/usr/bin/demo_httpd --port 8080\n")
    init.chmod(0o755)
    (rootfs / "etc" / "httpd.conf").write_text("POST /cgi-bin/demo\n")
    (rootfs / "www" / "routes.txt").write_text("POST /cgi-bin/demo\n")
    targets = tmp_path / "targets.json"
    targets.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "id": "firmware-rootfs",
                        "label": "firmware",
                        "rootfs_path": str(rootfs),
                        "package": "demo-web",
                        "product": "DemoRouter",
                        "version": "2.0",
                    }
                ]
            }
        )
    )

    summary = run_capability_sweep(targets, tmp_path / "sweep")
    row = summary.rows[0]

    assert row.errors == []
    assert row.reports == 0
    assert "decompiled_export_missing" in row.blockers
    assert row.unsupported_blockers == 1
    assert row.metadata["blocker_category_counts"] == {"missing": 1}
    assert row.intake_dir
    assert row.target_provenance["product"] == "DemoRouter"
    assert row.target_provenance["version"] == "2.0"
    assert row.target_provenance["package"] == "demo-web"
    assert Path(row.target_provenance["binary_path"]) == daemon
    assert row.target_provenance["binary_relative_path"] == "usr/bin/demo_httpd"
    assert len(row.target_provenance["binary_sha256"]) == 64
    assert row.target_provenance["architecture"]
    assert row.target_provenance["startup_command"] == "/usr/bin/demo_httpd --port 8080"
    assert row.target_provenance["reproduction_environment"] == {
        "rootfs_path": str(rootfs),
        "architecture": row.target_provenance["architecture"],
        "startup_command": "/usr/bin/demo_httpd --port 8080",
        "replay_mode": "off",
    }
    assert row.target_provenance["binary_count"] >= 1
    assert row.target_provenance["service_count"] == 1
    assert row.target_provenance["route_count"] >= 1
    assert any(route["route"] == "/cgi-bin/demo" for route in row.target_provenance["routes"])
    assert summary.totals["targets_with_errors"] == 0


def test_blocked_trace_with_dynamic_artifact_is_replay_observed_not_reportable(tmp_path: Path) -> None:
    proof_path = tmp_path / "ghidra_dynamic_proof.json"
    proof_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "proof_kind": "ghidra_dynamic_overflow",
                "candidate_id": "cand-trace",
                "status": "overflow_proven",
                "proof_scope": "process_entrypoint",
                "sink_reached": True,
                "exact_sink_reached": True,
                "process_input_setup": {"status": "configured", "input_model": "argv"},
                "process_replay": {"status": "reached"},
                "capacity_bytes": 8,
                "overflow_bytes": 4,
            }
        )
    )
    state = CandidateState(
        candidate_id="cand-trace",
        vulnerability_type="stack_overflow",
        status=CandidateStatus.REPLAY_CONFIRMED.value,
        target={"binary": "demo"},
        location={"function_name": "helper", "address": "0x1000"},
        source={"kind": "attacker_input"},
        sink={"name": "strcpy", "target_buffer": "buf"},
        type_facts={
            "capacity_bytes": 8,
            "destination_kind": "stack",
            "source_to_sink_trace": {
                "status": "blocked",
                "attacker_control_reaches_sink_role": False,
                "input_model": "argv",
                "call_path": ["main", "helper"],
                "controlled_roles": [],
                "blockers": ["missing_controlled_argument_role"],
            },
        },
        proof_obligations=[],
        blockers=[],
        replay_artifacts=[str(proof_path)],
    )

    trace = build_source_to_sink_trace(state)

    assert trace.confidence == "replay_observed"
    assert trace.status == "blocked"
    assert has_reportable_source_to_sink(state) is False


def test_complete_static_trace_without_replay_is_partial_not_reportable() -> None:
    state = CandidateState(
        candidate_id="cand-partial-trace",
        vulnerability_type="command_injection",
        status=CandidateStatus.PROOF_READY.value,
        target={"binary": "demo"},
        location={"function_name": "handler", "address": "0x1000"},
        source={"kind": "http_param"},
        sink={"name": "system"},
        type_facts={
            "source_to_sink_trace": {
                "status": "complete",
                "attacker_control_reaches_sink_role": True,
                "input_model": "http_cgi",
                "call_path": ["main", "handler"],
                "argument_roles": [
                    {
                        "role": "command_argument",
                        "expr": "param",
                        "classification": "source_controlled",
                        "controlled": True,
                        "complete": True,
                    }
                ],
                "propagation_path": [{"from": "http_param:cmd", "to": "system:arg0"}],
            },
        },
        proof_obligations=[],
        blockers=[],
        replay_artifacts=[],
    )

    trace = build_source_to_sink_trace(state)

    assert trace.status == "blocked"
    assert trace.confidence == "partial"
    assert trace.blockers == ["boundary_replay_missing"]
    assert has_reportable_source_to_sink(state) is False
