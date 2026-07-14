import importlib.util
import json
from pathlib import Path


_SCORER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "score_romeo_cwe121.py"
_SPEC = importlib.util.spec_from_file_location("score_romeo_cwe121", _SCORER_PATH)
scorer = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(scorer)


def _candidate(function_name: str, *, reportable: bool = True, source_symbol: str = "") -> dict:
    return {
        "function_name": function_name,
        "source_symbol": source_symbol,
        "candidate_id": f"demo:0x1000:{function_name}:4:gets:local_20",
        "verdict": "overflow" if reportable else "candidate",
        "input_reaches_sink": reportable,
        "path_is_valid": reportable,
    }


def test_load_detections_reads_only_reportable_candidates() -> None:
    report = {
        "candidate_findings": [
            _candidate("badSink"),
            _candidate("helper", reportable=False),
        ]
    }

    assert scorer.load_detections(report, surface="reportable") == {"badsink"}


def test_load_detections_defaults_to_confirmation_queue() -> None:
    report = {
        "candidate_findings": [
            _candidate("badSink"),
            _candidate("helper", reportable=False),
        ],
        "confirmation_findings": [
            _candidate("badSink", reportable=False),
            _candidate("helper", reportable=False),
        ],
    }

    assert scorer.load_detections(report) == {"badsink", "helper"}


def test_confirmation_surface_falls_back_for_legacy_reports() -> None:
    report = {
        "candidate_findings": [
            _candidate("badSink"),
            _candidate("helper", reportable=False),
        ]
    }

    assert scorer.load_detections(report) == {"badsink"}


def test_score_reports_scores_reportable_stage(tmp_path: Path) -> None:
    report_path = tmp_path / "reports" / "CWE121_demo-bad.json"
    report_path.parent.mkdir()
    report_path.write_text(
        json.dumps(
            {
                "config": {"binary": "CWE121_demo-bad"},
                "candidate_findings": [_candidate("badSink"), _candidate("unknownHelper")],
            }
        )
    )
    ground_truth = {
        "cwe121_demo": {
            "positives": {"badsink"},
            "negatives": set(),
            "ignored": set(),
        }
    }

    rows, metrics = scorer.score_reports(
        [report_path],
        ground_truth=ground_truth,
        scope="strict",
        surface="reportable",
    )

    assert metrics["stage"] == "reportable"
    assert metrics["tp"] == 1
    assert metrics["fp"] == 1
    assert metrics["fn"] == 0
    assert {row["truth_label"] for row in rows} == {"tp", "fp"}


def test_score_reports_scores_confirmation_screen_by_default(tmp_path: Path) -> None:
    report_path = tmp_path / "reports" / "CWE121_demo-bad.json"
    report_path.parent.mkdir()
    report_path.write_text(
        json.dumps(
            {
                "config": {"binary": "CWE121_demo-bad"},
                "candidate_findings": [_candidate("badSink")],
                "confirmation_findings": [
                    _candidate("badSink", reportable=False),
                    _candidate("unknownHelper", reportable=False),
                ],
            }
        )
    )
    ground_truth = {
        "cwe121_demo": {
            "positives": {"badsink"},
            "negatives": set(),
            "ignored": set(),
        }
    }

    rows, metrics = scorer.score_reports([report_path], ground_truth=ground_truth, scope="strict")

    assert metrics["stage"] == "confirmation"
    assert metrics["tp"] == 1
    assert metrics["fp"] == 1
    assert metrics["fn"] == 0
    assert {row["truth_label"] for row in rows} == {"tp", "fp"}


def test_score_reports_ignores_unknown_detections_in_scoped_mode(tmp_path: Path) -> None:
    report_path = tmp_path / "reports" / "demo.json"
    report_path.parent.mkdir()
    report_path.write_text(
        json.dumps(
            {
                "config": {"binary": "demo"},
                "candidate_findings": [_candidate("unknownHelper")],
            }
        )
    )
    ground_truth = {
        "demo": {
            "positives": {"badsink"},
            "negatives": set(),
            "ignored": set(),
        }
    }

    rows, metrics = scorer.score_reports(
        [report_path],
        ground_truth=ground_truth,
        scope="scoped",
        surface="reportable",
    )

    assert metrics["tp"] == 0
    assert metrics["fp"] == 0
    assert metrics["fn"] == 1
    assert {row["truth_label"] for row in rows} == {"ignored", "fn"}


def test_score_reports_prefers_source_symbol_for_stripped_names(tmp_path: Path) -> None:
    report_path = tmp_path / "reports" / "linked-demo-bad_20260424-120000.json"
    report_path.parent.mkdir()
    report_path.write_text(
        json.dumps(
            {
                "config": {"binary": "linked-demo-bad"},
                "candidate_findings": [_candidate("FUN_00101100", source_symbol="badSink")],
            }
        )
    )
    ground_truth = {
        "demo": {
            "positives": {"badsink"},
            "negatives": set(),
            "ignored": set(),
        }
    }

    rows, metrics = scorer.score_reports(
        [report_path],
        ground_truth=ground_truth,
        scope="strict",
        surface="reportable",
    )

    assert metrics["tp"] == 1
    assert metrics["fp"] == 0
    assert rows[0]["function"] == "badsink"
