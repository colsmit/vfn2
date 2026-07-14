from pathlib import Path

import pytest

from binary_agent.analysis.candidates import StaticCandidate
from binary_agent.reporting import (
    AnalysisReport,
    ReportConfig,
    build_vulnerability_reports,
    serialize_report,
    write_markdown_reports,
)


def _candidate(**overrides) -> StaticCandidate:
    data = {
        "binary": "demo.bin",
        "function_name": "entry",
        "source_symbol": "entry",
        "demangled_name": "",
        "source_object": "",
        "address": "0x1100",
        "relative_path": "entry.c",
        "candidate_id": "demo.bin:0x1100:entry:4:gets:local_20",
        "kind": "call",
        "sink": "gets",
        "line_number": 4,
        "line_text": "gets(local_20);",
        "target_buffer": "local_20",
        "capacity_bytes": 16,
        "capacity_basis": "local_20: stack[-0x20..-0x10], 16 bytes",
        "write_relation": "unbounded",
        "write_size_expr": "unbounded",
        "write_size_bytes": None,
        "overflow_condition": "gets has no destination bound",
        "verdict": "unbounded",
        "severity": "high",
        "evidence": ["line 4: gets(local_20);"],
        "source_evidence": ["line 3: argv[1]"],
        "guard_evidence": [],
        "call_path": ["main", "entry"],
        "input_reaches_sink": True,
        "path_is_valid": True,
    }
    data.update(overrides)
    return StaticCandidate(**data)


def _source_to_write_trace(
    *,
    write_source: str = "constant_or_literal",
    write_size: str = "constant_or_literal",
    write_offset: str = "constant_or_literal",
    destination_pointer: str = "internal_local",
) -> dict:
    return {
        "source_to_write": {
            "roles": {
                "write_source": {"classification": write_source, "complete": True},
                "write_size": {"classification": write_size, "complete": True},
                "write_offset": {"classification": write_offset, "complete": True},
                "destination_pointer": {"classification": destination_pointer, "complete": True},
            }
        }
    }


def test_serialize_report_roundtrip() -> None:
    config = ReportConfig(binary="demo.bin", export_dir="/tmp", run_label="run123")
    candidate = _candidate()
    report = AnalysisReport(
        config=config,
        candidate_findings=[candidate],
        confirmation_findings=[candidate],
        candidate_confirmations={
            candidate.candidate_id: {
                "status": "confirmed_bug",
                "reason_codes": ["unbounded_stack_write"],
            }
        },
    )

    serialized = serialize_report(report)

    assert "demo.bin" in serialized
    assert "candidate_findings" in serialized
    assert "confirmation_findings" in serialized
    assert "candidate_confirmations" in serialized
    assert "scout_findings" not in serialized


def test_vulnerability_reports_render_candidate_evidence(tmp_path: Path) -> None:
    config = ReportConfig(binary="demo.bin", export_dir="/tmp", run_label="run456")
    candidate = _candidate()

    reports = build_vulnerability_reports([candidate])
    assert len(reports) == 1
    document_paths = write_markdown_reports(reports, tmp_path / "reports", config)

    assert len(document_paths) == 1
    rendered = document_paths[0].read_text()
    assert "Vulnerability Report" in rendered
    assert "main -> entry" in rendered
    assert "gets has no destination bound" in rendered


def test_vulnerability_reports_render_oob_read_type(tmp_path: Path) -> None:
    config = ReportConfig(binary="demo.bin", export_dir="/tmp", run_label="run-oob-read")
    candidate = _candidate(
        kind="source_read",
        sink="memcpy_source_read",
        vulnerability_type="out_of_bounds_read",
        write_relation="proven_oob_read",
        verdict="overflow",
        overflow_condition="memcpy reads byte range 12..15 outside 8-byte source object",
        classification_trace=_source_to_write_trace(write_size="source_controlled"),
    )

    reports = build_vulnerability_reports([candidate])
    assert len(reports) == 1
    assert reports[0].vulnerability_type == "out_of_bounds_read"
    assert "read outside" in reports[0].summary
    document_paths = write_markdown_reports(reports, tmp_path / "reports", config)

    rendered = document_paths[0].read_text()
    assert "Vulnerability type" in rendered
    assert "out_of_bounds_read" in rendered


def test_write_markdown_reports_placeholder(tmp_path: Path) -> None:
    config = ReportConfig(binary="demo.bin", export_dir="/tmp", run_label="run789")
    output_dir = tmp_path / "empty_reports"

    written = write_markdown_reports([], output_dir, config)

    assert written == []
    assert "No verified vulnerabilities" in (output_dir / "README.md").read_text()


def test_vulnerability_reports_skip_unreachable_candidate() -> None:
    candidate = _candidate(path_is_valid=False, call_path=[])

    assert build_vulnerability_reports([candidate]) == []


def test_vulnerability_reports_skip_exact_entry_path_without_source_influence() -> None:
    candidate = _candidate(
        input_reaches_sink=False,
        reachability_kind="entry_path",
        source_evidence=[],
    )

    reports = build_vulnerability_reports([candidate])

    assert reports == []


def test_confirmed_policy_reports_confirmed_entry_path_candidate() -> None:
    candidate = _candidate(
        verdict="candidate",
        input_reaches_sink=False,
        reachability_kind="entry_path",
        path_is_valid=True,
    )

    reports = build_vulnerability_reports(
        [candidate],
        confirmations={
            candidate.candidate_id: {
                "status": "confirmed_bug",
                "reason_codes": ["ai_confirmed"],
            }
        },
        report_policy="confirmed",
    )

    assert len(reports) == 1
    assert reports[0].candidate_id == candidate.candidate_id


def test_confirmed_report_includes_dynamic_proof_dossier(tmp_path: Path) -> None:
    candidate = _candidate(verdict="candidate", input_reaches_sink=False, path_is_valid=True)

    reports = build_vulnerability_reports(
        [candidate],
        confirmations={
            candidate.candidate_id: {
                "status": "confirmed_bug",
                "reason_codes": ["ghidra_dynamic_overflow_proven"],
                "memory_safety_argument": {
                    "ghidra_dynamic_proof": {
                        "status": "overflow_proven",
                        "sink_address": "0x1010",
                        "write_size_bytes": 32,
                        "capacity_bytes": 16,
                        "overflow_bytes": 16,
                    },
                    "concrete_input": {"input_hex": "41" * 32},
                    "write_range": {
                        "range_kind": "modeled_heap_allocation_offsets",
                        "base": "buf",
                        "start_offset": 0,
                        "end_offset_exclusive": 32,
                        "size_bytes": 32,
                    },
                    "object_range": {
                        "range_kind": "modeled_heap_allocation_offsets",
                        "base": "buf",
                        "start_offset": 0,
                        "end_offset_exclusive": 16,
                        "size_bytes": 16,
                    },
                    "harness_model": {"input_model": "stdin"},
                    "llm_trace": {"accepted_requests": [{"target_address": "0x1010"}]},
                    "native_replay": {"status": "not_run"},
                },
            }
        },
        report_policy="confirmed",
    )

    dossier = reports[0].cve_dossier["dynamic_confirmation"]
    assert dossier["ghidra_dynamic_proof"]["status"] == "overflow_proven"
    assert dossier["concrete_input"]["input_hex"] == "41" * 32
    assert dossier["native_replay"]["status"] == "not_run"

    paths = write_markdown_reports(
        reports,
        tmp_path / "reports",
        ReportConfig(binary="demo.bin", export_dir="/tmp", run_label="run-dynamic"),
    )
    rendered = paths[0].read_text()
    assert "## Dynamic Confirmation" in rendered
    assert "Concrete input hex" in rendered
    assert "modeled_heap_allocation_offsets" in rendered
    assert "Native replay: not_run" in rendered


def test_confirmed_oob_read_report_includes_read_range_dossier(tmp_path: Path) -> None:
    candidate = _candidate(
        kind="indexed_read",
        sink="array_load",
        vulnerability_type="out_of_bounds_read",
        write_relation="symbolic_read_offset",
        verdict="candidate",
        overflow_condition="index i is not proven below 16 readable elements",
        line_text="value = local_20[i];",
        classification_trace=_source_to_write_trace(write_offset="source_controlled"),
    )

    reports = build_vulnerability_reports(
        [candidate],
        confirmations={
            candidate.candidate_id: {
                "status": "confirmed_bug",
                "reason_codes": ["ghidra_dynamic_oob_read_proven"],
                "memory_safety_argument": {
                    "ghidra_dynamic_proof": {
                        "status": "oob_read_proven",
                        "sink_address": "0x1010",
                        "read_size_bytes": 4,
                        "capacity_bytes": 16,
                        "oob_bytes": 4,
                    },
                    "concrete_input": {"input_hex": "14"},
                    "read_range": {
                        "range_kind": "modeled_stack_offsets",
                        "base": "local_20",
                        "start_offset": 20,
                        "end_offset_exclusive": 24,
                        "size_bytes": 4,
                    },
                    "object_range": {
                        "range_kind": "modeled_stack_offsets",
                        "base": "local_20",
                        "start_offset": 0,
                        "end_offset_exclusive": 16,
                        "size_bytes": 16,
                    },
                    "native_replay": {"status": "not_run"},
                },
            }
        },
        report_policy="confirmed",
    )

    dossier = reports[0].cve_dossier["dynamic_confirmation"]
    assert dossier["ghidra_dynamic_proof"]["status"] == "oob_read_proven"
    assert dossier["read_range"]["start_offset"] == 20
    assert dossier["oob_bytes"] == 4

    paths = write_markdown_reports(
        reports,
        tmp_path / "reports",
        ReportConfig(binary="demo.bin", export_dir="/tmp", run_label="run-oob-dynamic"),
    )
    rendered = paths[0].read_text()
    assert "Read/capacity/overrun: 4 / 16 / 4 bytes" in rendered
    assert "Read range: modeled_stack_offsets, local_20[20..24), 4 bytes" in rendered


def test_confirmed_policy_keeps_integer_memory_risks_triage_only() -> None:
    candidate = _candidate(
        vulnerability_type="integer_overflow_to_memory_access",
        kind="integer_size_risk",
        sink="memcpy",
        write_relation="integer_overflow_risk",
        verdict="candidate",
        overflow_condition="n * 4 may overflow before feeding memcpy size",
    )

    reports = build_vulnerability_reports(
        [candidate],
        confirmations={
            candidate.candidate_id: {
                "status": "confirmed_bug",
                "reason_codes": ["manual_integer_review"],
            }
        },
        report_policy="confirmed",
    )

    assert reports == []


def test_confirmed_policy_does_not_report_likely_bug() -> None:
    candidate = _candidate(
        verdict="candidate",
        input_reaches_sink=True,
        path_is_valid=True,
    )

    reports = build_vulnerability_reports(
        [candidate],
        confirmations={
            candidate.candidate_id: {
                "status": "likely_bug",
                "reason_codes": ["needs_dynamic_confirmation"],
            }
        },
        report_policy="confirmed",
    )

    assert reports == []


def test_unknown_report_policy_is_rejected() -> None:
    candidate = _candidate(verdict="candidate")

    with pytest.raises(ValueError, match="report_policy must be"):
        build_vulnerability_reports([candidate], report_policy="unknown")
