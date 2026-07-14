#!/usr/bin/env python3
"""Evaluate the v3 fact-first deterministic analyzer across export sets."""

from __future__ import annotations

import argparse
import csv
import json
import re
import resource
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from binary_agent.analysis.candidates import (
    StaticCandidate,
    run_static_pipeline,
    simulate_candidate_proof_gates,
)
from binary_agent.ingest.loader import load_manifest_record


TARGET_FUNCTIONS = {
    "suricata": "ShortenString",
    "vim-xxd": "main",
    "openplc_v3": "processEnipMessage",
    "editorconfig-core-c": "ec_glob",
    "gstreamer-opus": "gst_opus_dec_parse_header",
    "gstreamer-vorbis": "vorbis_handle_identification_packet",
    "libxml2-xmllint": "xmlShellReadline",
    "xmllint": "xmlShellReadline",
    "libtiff-tiffcrop": "loadImage",
    "tiffcrop": "loadImage",
    "trustedfirmware-m": "context_boot_go",
    "glibc-nscd": "addinnetgrX",
    "nscd": "addinnetgrX",
    "iptraf-ng": "dev_up",
    "jq": "decNumberCopy",
    "libbiosig-mfer": "sopen_extended",
    "luajit": "lj_strfmt_wfnum",
    "quickjs": "get_class_atom",
}


@dataclass(frozen=True)
class EngineMetrics:
    candidate_count: int
    confirmation_count: int
    report_count: int
    target_candidate_hit: bool
    target_confirmation_hit: bool
    target_report_hit: bool
    elapsed_seconds: float
    max_rss_kb: int
    signatures: set[tuple[str, ...]]
    base_signatures: set[tuple[str, ...]]
    candidates_by_base: dict[tuple[str, ...], list[StaticCandidate]]
    candidates_by_location: dict[tuple[str, ...], list[StaticCandidate]]
    kind_counts: dict[str, int]
    sink_counts: dict[str, int]
    relation_counts: dict[str, int]
    verdict_counts: dict[str, int]
    proof_gate_simulation: dict[str, dict[str, object]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate fact-first deterministic analysis.")
    parser.add_argument(
        "root",
        type=Path,
        nargs="?",
        default=Path("../vulnfinder-real/runs/vfn_exports"),
        help="Root containing Ghidra export directories.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for comparison CSV/JSON output. Defaults under /tmp.",
    )
    parser.add_argument(
        "--analysis-cache-dir",
        type=Path,
        default=None,
        help="Directory for fact-v3 analysis cache. Defaults to <output-dir>/cache.",
    )
    parser.add_argument("--limit", type=int, default=None, help="Limit number of exports analyzed.")
    parser.add_argument(
        "--skip-binary",
        action="append",
        default=[],
        help="Binary/export label to skip. May be repeated.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output_dir = args.output_dir or Path("/tmp") / f"vulnfinder2_fact_v3_eval_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    export_dirs = list(_discover_exports(args.root))
    if args.skip_binary:
        skipped = set(args.skip_binary)
        export_dirs = [path for path in export_dirs if skipped.isdisjoint(_export_labels(path))]
    if args.limit is not None:
        export_dirs = export_dirs[: args.limit]

    rows: list[dict[str, object]] = []
    diffs: dict[str, object] = {}
    aggregate = _empty_aggregate()

    for export_dir in export_dirs:
        manifest = load_manifest_record(export_dir)
        target_function = _target_for(export_dir, manifest.binary)
        cache_dir = args.analysis_cache_dir or (output_dir / "cache")
        metrics = _run_pipeline(export_dir, target_function, cache_dir)
        key = _export_key(export_dir, manifest.binary)
        diffs[key] = {
            "export_dir": str(export_dir),
            "target_function": target_function,
            "candidate_count": metrics.candidate_count,
            "confirmation_count": metrics.confirmation_count,
            "report_count": metrics.report_count,
            "kind_counts": metrics.kind_counts,
            "sink_counts": metrics.sink_counts,
            "relation_counts": metrics.relation_counts,
            "verdict_counts": metrics.verdict_counts,
            "proof_gate_simulation": metrics.proof_gate_simulation,
        }
        rows.append(_summary_row(export_dir, manifest.binary, target_function, metrics))
        _add_aggregate(aggregate, "fact_v3", metrics, target_function)

    _write_csv(output_dir / "per_binary_summary.csv", rows)
    (output_dir / "candidate_diffs.json").write_text(json.dumps(diffs, indent=2))
    (output_dir / "triage_summary.json").write_text(json.dumps(_triage_summary(rows, diffs), indent=2))
    (output_dir / "aggregate_metrics.json").write_text(json.dumps(aggregate, indent=2))
    print(f"[+] Wrote fact-v3 evaluation to {output_dir}")


def _discover_exports(root: Path) -> Iterable[Path]:
    for manifest_path in sorted(Path(root).rglob("manifest_normalized.json")):
        yield manifest_path.parent


def _run_pipeline(export_dir: Path, target_function: str, cache_dir: Path | None = None) -> EngineMetrics:
    start = time.perf_counter()
    report = run_static_pipeline(
        export_dir,
        persist_stage_artifacts=False,
        report_policy="deterministic",
        cache_dir=cache_dir,
    )
    elapsed = time.perf_counter() - start
    max_rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return EngineMetrics(
        candidate_count=len(report.candidate_findings),
        confirmation_count=len(report.confirmation_findings),
        report_count=len(report.vulnerability_reports),
        target_candidate_hit=_target_hit(report.candidate_findings, target_function),
        target_confirmation_hit=_target_hit(report.confirmation_findings, target_function),
        target_report_hit=any(_name_matches(report.function_name, target_function) for report in report.vulnerability_reports),
        elapsed_seconds=elapsed,
        max_rss_kb=max_rss,
        signatures={_candidate_signature(candidate) for candidate in report.candidate_findings},
        base_signatures={_candidate_base_signature(candidate) for candidate in report.candidate_findings},
        candidates_by_base=_group_candidates(report.candidate_findings, _candidate_base_signature),
        candidates_by_location=_group_candidates(report.candidate_findings, _candidate_location_signature),
        kind_counts=_count_candidates(report.candidate_findings, "kind"),
        sink_counts=_count_candidates(report.candidate_findings, "sink"),
        relation_counts=_count_candidates(report.candidate_findings, "write_relation"),
        verdict_counts=_count_candidates(report.candidate_findings, "verdict"),
        proof_gate_simulation=_proof_gate_simulation(report, target_function),
    )


def _summary_row(
    export_dir: Path,
    binary: str,
    target_function: str,
    metrics: EngineMetrics,
) -> dict[str, object]:
    return {
        "export_dir": str(export_dir),
        "binary": binary,
        "target_function": target_function,
        "candidates": metrics.candidate_count,
        "confirmations": metrics.confirmation_count,
        "reports": metrics.report_count,
        "target_candidate": metrics.target_candidate_hit,
        "target_confirmation": metrics.target_confirmation_hit,
        "target_report": metrics.target_report_hit,
        "elapsed_seconds": round(metrics.elapsed_seconds, 4),
        "max_rss_kb": metrics.max_rss_kb,
    }


def _write_csv(path: Path, rows: Sequence[dict[str, object]]) -> None:
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _empty_aggregate() -> dict[str, object]:
    return {
        "fact_v3": _engine_aggregate(),
        "code_metrics": _code_metrics(),
    }


def _engine_aggregate() -> dict[str, object]:
    return {
        "candidate_count": 0,
        "confirmation_count": 0,
        "report_count": 0,
        "target_candidate_hits": 0,
        "target_confirmation_hits": 0,
        "target_report_hits": 0,
        "target_total": 0,
        "elapsed_seconds": 0.0,
        "max_rss_kb": 0,
        "kind_counts": {},
        "sink_counts": {},
        "relation_counts": {},
        "verdict_counts": {},
        "proof_gate_simulation": {},
    }


def _code_metrics() -> dict[str, object]:
    repo_root = Path(__file__).resolve().parents[1]
    files = {
        "fact_pipeline": repo_root / "src" / "binary_agent" / "analysis" / "candidates.py",
        "memory_set_domain": repo_root / "src" / "binary_agent" / "analysis" / "memory_sets.py",
    }
    return {name: _file_metrics(path) for name, path in files.items()}


def _file_metrics(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"path": str(path), "exists": False}
    lines = path.read_text().splitlines()
    return {
        "path": str(path),
        "exists": True,
        "lines": len(lines),
        "nonblank_lines": sum(1 for line in lines if line.strip()),
        "function_defs": sum(1 for line in lines if line.startswith("def ") or line.startswith("    def ")),
        "class_defs": sum(1 for line in lines if line.startswith("class ") or line.startswith("    class ")),
    }


def _add_aggregate(
    aggregate: dict[str, object],
    engine: str,
    metrics: EngineMetrics,
    target_function: str,
) -> None:
    bucket = aggregate[engine]
    assert isinstance(bucket, dict)
    bucket["candidate_count"] = int(bucket["candidate_count"]) + metrics.candidate_count
    bucket["confirmation_count"] = int(bucket["confirmation_count"]) + metrics.confirmation_count
    bucket["report_count"] = int(bucket["report_count"]) + metrics.report_count
    bucket["elapsed_seconds"] = round(float(bucket["elapsed_seconds"]) + metrics.elapsed_seconds, 4)
    bucket["max_rss_kb"] = max(int(bucket["max_rss_kb"]), metrics.max_rss_kb)
    _merge_counts(bucket["kind_counts"], metrics.kind_counts)
    _merge_counts(bucket["sink_counts"], metrics.sink_counts)
    _merge_counts(bucket["relation_counts"], metrics.relation_counts)
    _merge_counts(bucket["verdict_counts"], metrics.verdict_counts)
    _merge_gate_simulation(bucket["proof_gate_simulation"], metrics.proof_gate_simulation)
    if target_function:
        bucket["target_total"] = int(bucket["target_total"]) + 1
        bucket["target_candidate_hits"] = int(bucket["target_candidate_hits"]) + int(metrics.target_candidate_hit)
        bucket["target_confirmation_hits"] = int(bucket["target_confirmation_hits"]) + int(metrics.target_confirmation_hit)
        bucket["target_report_hits"] = int(bucket["target_report_hits"]) + int(metrics.target_report_hit)


def _merge_counts(target: object, source: dict[str, int]) -> None:
    if not isinstance(target, dict):
        return
    for key, value in source.items():
        target[key] = int(target.get(key, 0)) + value


def _merge_gate_simulation(target: object, source: dict[str, dict[str, object]]) -> None:
    if not isinstance(target, dict):
        return
    for gate, metrics in source.items():
        bucket = target.setdefault(gate, {})
        if not isinstance(bucket, dict):
            continue
        for key, value in metrics.items():
            if isinstance(value, bool):
                bucket[key] = int(bucket.get(key, 0)) + int(value)
            elif isinstance(value, int):
                bucket[key] = int(bucket.get(key, 0)) + value


def _triage_summary(rows: Sequence[dict[str, object]], diffs: dict[str, object]) -> dict[str, object]:
    target_misses = [
        row
        for row in rows
        if row.get("target_function")
        and not (row.get("target_candidate") or row.get("target_confirmation") or row.get("target_report"))
    ]
    changed_exports = sorted(
        rows,
        key=lambda row: (
            int(row["candidates"])
            + int(row["confirmations"])
            + int(row["reports"])
        ),
        reverse=True,
    )
    del diffs
    return {
        "target_misses": target_misses,
        "top_exports_by_findings": changed_exports[:20],
    }


def _target_for(export_dir: Path, binary: str) -> str:
    for label in _export_labels(export_dir, binary):
        if label in TARGET_FUNCTIONS:
            return TARGET_FUNCTIONS[label]
    return ""


def _proof_gate_simulation(report, target_function: str) -> dict[str, dict[str, object]]:
    simulation = simulate_candidate_proof_gates(
        report.candidate_findings,
        report.confirmation_findings,
        [item.candidate_id for item in report.vulnerability_reports],
    )
    for gate, metrics in simulation.items():
        kept_candidates = [
            candidate for candidate in report.candidate_findings if not _candidate_removed_by_gate(candidate, gate)
        ]
        kept_confirmations = [
            candidate for candidate in report.confirmation_findings if not _candidate_removed_by_gate(candidate, gate)
        ]
        metrics["target_candidate_loss"] = bool(
            _target_hit(report.candidate_findings, target_function)
            and not _target_hit(kept_candidates, target_function)
        )
        metrics["target_confirmation_loss"] = bool(
            _target_hit(report.confirmation_findings, target_function)
            and not _target_hit(kept_confirmations, target_function)
        )
    return simulation


def _candidate_removed_by_gate(candidate: StaticCandidate, gate: str) -> bool:
    trace = getattr(candidate, "classification_trace", {}) or {}
    reachability_dataflow = trace.get("reachability_dataflow", {}) if isinstance(trace, dict) else {}
    graph = reachability_dataflow.get("graph", {}) if isinstance(reachability_dataflow, dict) else {}
    expr_taint = reachability_dataflow.get("expr_taint", {}) if isinstance(reachability_dataflow, dict) else {}
    if gate == "complete_unreachable_candidate":
        return bool(graph.get("complete_unreachable_candidate")) if isinstance(graph, dict) else False
    if gate == "complete_unreachable_and_no_source_taint":
        return bool(graph.get("complete_unreachable_candidate")) and not _has_source_or_parameter_taint(expr_taint)
    if gate == "non_input_expr_candidate":
        return bool(expr_taint.get("non_input_expr_candidate")) if isinstance(expr_taint, dict) else False
    return False


def _has_source_or_parameter_taint(expr_taint: object) -> bool:
    if not isinstance(expr_taint, dict):
        return False
    rows = expr_taint.get("taint_table", [])
    if not isinstance(rows, list):
        return False
    return any(
        isinstance(row, dict)
        and str(row.get("classification") or "") in {"source_controlled", "parameter_controlled"}
        for row in rows
    )


def _export_key(export_dir: Path, binary: str) -> str:
    labels = _export_labels(export_dir, binary)
    return labels[0] if labels else str(export_dir)


def _export_labels(export_dir: Path, binary: str = "") -> list[str]:
    labels = [binary] if binary else []
    labels.extend(part for part in reversed(export_dir.parts) if part and part not in {"decompiled", "runs", "vfn_exports"})
    result: list[str] = []
    for label in labels:
        if label and label not in result:
            result.append(label)
    return result


def _target_hit(candidates: Sequence[StaticCandidate], target_function: str) -> bool:
    if not target_function:
        return False
    return any(
        _name_matches(candidate.function_name, target_function)
        or _name_matches(candidate.source_symbol, target_function)
        or _name_matches(candidate.demangled_name, target_function)
        or _candidate_line_calls_target(candidate, target_function)
        for candidate in candidates
    )


def _name_matches(actual: str, expected: str) -> bool:
    if not actual or not expected:
        return False
    actual_name = str(actual).split("(", 1)[0].split("::")[-1].lstrip("_")
    expected_name = str(expected).split("(", 1)[0].split("::")[-1].lstrip("_")
    return actual_name == expected_name


def _candidate_line_calls_target(candidate: StaticCandidate, target_function: str) -> bool:
    expected_name = str(target_function).split("(", 1)[0].split("::")[-1].lstrip("_")
    if len(expected_name) <= 4 or expected_name == "main":
        return False
    pattern = re.compile(rf"\b{re.escape(expected_name)}\s*\(")
    line_text = str(getattr(candidate, "line_text", "") or "")
    if pattern.search(line_text):
        return True
    for item in getattr(candidate, "evidence", []) or []:
        if pattern.search(str(item)):
            return True
    return False


def _candidate_signature(candidate: StaticCandidate) -> tuple[str, ...]:
    return (
        candidate.function_name,
        candidate.kind,
        candidate.sink,
        candidate.target_buffer,
        str(candidate.line_number),
        candidate.verdict,
        candidate.write_relation,
        " ".join(candidate.line_text.split()),
    )


def _candidate_base_signature(candidate: StaticCandidate) -> tuple[str, ...]:
    return (
        candidate.function_name,
        candidate.kind,
        candidate.sink,
        candidate.target_buffer,
        str(candidate.line_number),
        " ".join(candidate.line_text.split()),
    )


def _candidate_location_signature(candidate: StaticCandidate) -> tuple[str, ...]:
    return (
        candidate.function_name,
        candidate.kind,
        candidate.sink,
        str(candidate.line_number),
        " ".join(candidate.line_text.split()),
    )


def _group_candidates(
    candidates: Sequence[StaticCandidate],
    key_fn,
) -> dict[tuple[str, ...], list[StaticCandidate]]:
    grouped: dict[tuple[str, ...], list[StaticCandidate]] = {}
    for candidate in candidates:
        grouped.setdefault(key_fn(candidate), []).append(candidate)
    return grouped


def _count_candidates(candidates: Sequence[StaticCandidate], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for candidate in candidates:
        value = str(getattr(candidate, field) or "")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _candidate_example(candidate: StaticCandidate) -> dict[str, object]:
    return {
        "function_name": candidate.function_name,
        "kind": candidate.kind,
        "sink": candidate.sink,
        "target_buffer": candidate.target_buffer,
        "line_number": candidate.line_number,
        "verdict": candidate.verdict,
        "write_relation": candidate.write_relation,
        "capacity_bytes": candidate.capacity_bytes,
        "capacity_source": candidate.capacity_source,
        "destination_kind": candidate.destination_kind,
        "line_text": " ".join(candidate.line_text.split()),
    }


if __name__ == "__main__":
    main()
