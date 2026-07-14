#!/usr/bin/env python3
"""Emit a focused deterministic-analysis trace for one target function."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.analysis.candidates import StaticCandidate, run_static_pipeline
from binary_agent.analysis.extractors import load_memory_operation_specs
from binary_agent.ingest.loader import FunctionNode, load_function_nodes


CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
ALLOC_RE = re.compile(r"\b(?:malloc|calloc|realloc|alloca|mempool_alloc|xmalloc|zalloc)\b", re.IGNORECASE)
FIELD_WRITE_RE = re.compile(r"(?:->|\.)\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:(?:[+*/%&|^-]?=(?!=))|\+\+|--)")
INDEX_WRITE_RE = re.compile(r"\[[^\]]+\]\s*(?:(?:[+*/%&|^-]?=(?!=))|\+\+|--)")
POINTER_WRITE_RE = re.compile(r"^\s*\*[^=]+=(?!=)")

KEYWORDS = {
    "case",
    "do",
    "for",
    "if",
    "return",
    "sizeof",
    "switch",
    "while",
}

COPY_HINTS = (
    "copy",
    "memcpy",
    "memmove",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "sprintf",
    "snprintf",
    "scanf",
    "read",
    "recv",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Trace why one function did or did not produce static findings.")
    parser.add_argument("export_dir", type=Path, help="Ghidra decompiled export directory.")
    parser.add_argument("target", help="Function name, address, source symbol, demangled name, or relative path fragment.")
    parser.add_argument("--output", type=Path, default=None, help="Write JSON trace to this path instead of stdout.")
    parser.add_argument("--analysis-cache-dir", type=Path, default=None, help="Optional analysis cache directory.")
    parser.add_argument("--max-items", type=int, default=80, help="Maximum entries per trace list.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    trace = build_trace(args.export_dir, args.target, cache_dir=args.analysis_cache_dir, max_items=args.max_items)
    text = json.dumps(trace, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
        print(f"[+] Wrote target trace to {args.output}")
    else:
        print(text)


def build_trace(
    export_dir: Path,
    target: str,
    *,
    cache_dir: Path | None = None,
    max_items: int = 80,
) -> dict[str, Any]:
    manifest, nodes = load_function_nodes(export_dir)
    matched_nodes = [node for node in nodes if _node_matches_target(node, target)]
    report = run_static_pipeline(
        export_dir,
        cache_dir=cache_dir,
        persist_stage_artifacts=False,
        report_policy="deterministic",
    )
    sink_names = set(load_memory_operation_specs().as_dict_mapping())

    target_candidates = [
        candidate.to_dict()
        for candidate in report.candidate_findings
        if _candidate_matches_target(candidate, target)
    ]
    target_confirmations = [
        candidate.to_dict()
        for candidate in report.confirmation_findings
        if _candidate_matches_target(candidate, target)
    ]
    related_candidates = [
        candidate.to_dict()
        for candidate in report.candidate_findings
        if _candidate_is_related(candidate, target) and not _candidate_matches_target(candidate, target)
    ]
    summaries = [
        summary.to_dict()
        for summary in report.function_summaries
        if _summary_is_related(summary.to_dict(), target)
    ]

    node_traces = [_trace_node(node, sink_names, max_items=max_items) for node in matched_nodes]
    trace = {
        "target": target,
        "binary": manifest.binary,
        "export_dir": str(Path(export_dir).resolve()),
        "matched_functions": node_traces,
        "analyzer_totals": {
            "candidates": len(report.candidate_findings),
            "confirmation_findings": len(report.confirmation_findings),
            "vulnerability_reports": len(report.vulnerability_reports),
            "target_candidates": len(target_candidates),
            "target_confirmation_findings": len(target_confirmations),
            "related_candidates": len(related_candidates),
            "related_function_summaries": len(summaries),
        },
        "target_candidates": target_candidates[:max_items],
        "target_confirmation_findings": target_confirmations[:max_items],
        "related_candidates": related_candidates[:max_items],
        "related_function_summaries": summaries[:max_items],
        "assessment": _assessment(node_traces, target_candidates, target_confirmations, related_candidates, summaries),
        "stage_metrics": dict(report.stage_metrics),
    }
    if not matched_nodes:
        trace["assessment"].insert(0, f"No function record matched target {target!r}.")
    return trace


def _trace_node(node: FunctionNode, sink_names: set[str], *, max_items: int) -> dict[str, Any]:
    line_traces = [_trace_line(number, line, sink_names) for number, line in enumerate(node.text.splitlines(), start=1)]
    interesting_lines = [entry for entry in line_traces if entry["categories"]]
    return {
        "name": node.record.name,
        "address": node.record.address,
        "relative_path": node.record.relative_path,
        "prototype": node.record.prototype,
        "parameters": list(node.record.parameters or []),
        "stack_regions": list(node.record.stack_regions or []),
        "callers": list(node.metadata.get("callers") or []),
        "callees": list(node.metadata.get("callees") or []),
        "pcode_calls": [_summarize_pcode_call(item) for item in (node.record.pcode_calls or [])[:max_items]],
        "pcode_stores": [dict(item) for item in (node.record.pcode_stores or [])[:max_items]],
        "ambiguous_callsites": [
            _summarize_ambiguous_callsite(item) for item in (node.record.ambiguous_callsites or [])[:max_items]
        ],
        "interesting_c_lines": interesting_lines[:max_items],
        "interesting_c_line_count": len(interesting_lines),
    }


def _trace_line(line_number: int, line: str, sink_names: set[str]) -> dict[str, Any]:
    stripped = line.strip()
    calls = [name for name in CALL_RE.findall(stripped) if name not in KEYWORDS]
    categories: list[str] = []
    if any(call in sink_names for call in calls):
        categories.append("known_sink_call")
    if any(_is_copy_like_call(call) for call in calls):
        categories.append("copy_like_call")
    if any(call.startswith("FUN_") for call in calls):
        categories.append("unresolved_call")
    if ALLOC_RE.search(stripped):
        categories.append("allocation")
    if FIELD_WRITE_RE.search(stripped):
        categories.append("field_write")
    if INDEX_WRITE_RE.search(stripped):
        categories.append("indexed_write")
    if POINTER_WRITE_RE.search(stripped):
        categories.append("pointer_write")
    categories = _unique(categories)
    return {
        "line_number": line_number,
        "line_text": stripped,
        "calls": calls,
        "categories": categories,
    }


def _summarize_pcode_call(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "call_address": entry.get("call_address") or entry.get("address") or "",
        "callee": entry.get("callee") or "",
        "callee_address": entry.get("callee_address") or "",
        "arg_count": entry.get("arg_count"),
        "args": list(entry.get("args") or []),
    }


def _summarize_ambiguous_callsite(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "call_address": entry.get("call_address") or entry.get("address") or "",
        "callee": entry.get("callee") or "",
        "callee_address": entry.get("callee_address") or "",
        "arg_count": entry.get("arg_count"),
        "args": list(entry.get("args") or []),
        "ambiguity_reasons": list(entry.get("ambiguity_reasons") or []),
    }


def _assessment(
    node_traces: Sequence[Mapping[str, Any]],
    target_candidates: Sequence[Mapping[str, Any]],
    target_confirmations: Sequence[Mapping[str, Any]],
    related_candidates: Sequence[Mapping[str, Any]],
    summaries: Sequence[Mapping[str, Any]],
) -> list[str]:
    notes: list[str] = []
    if target_candidates:
        notes.append(f"Analyzer emitted {len(target_candidates)} direct target candidate(s).")
    else:
        notes.append("Analyzer emitted no direct target candidates.")
    if target_confirmations:
        notes.append(f"Analyzer queued {len(target_confirmations)} direct target confirmation finding(s).")
    else:
        notes.append("Analyzer queued no direct target confirmation findings.")
    if related_candidates:
        notes.append(f"{len(related_candidates)} candidate(s) are related through target call paths or call-site text.")
    if summaries:
        notes.append(f"{len(summaries)} function summary record(s) mention the target.")
    for node in node_traces:
        stack_regions = node.get("stack_regions") or []
        pcode_stores = node.get("pcode_stores") or []
        interesting_lines = node.get("interesting_c_lines") or []
        categories = {
            category
            for entry in interesting_lines
            for category in (entry.get("categories") or [])
        }
        if not pcode_stores:
            notes.append(f"{node.get('name')} has no p-code store facts in the export metadata.")
        if "allocation" in categories and not target_candidates:
            notes.append(
                f"{node.get('name')} has allocation-backed memory activity, but no stack/global/static destination was resolved."
            )
        if "field_write" in categories and not target_candidates:
            notes.append(
                f"{node.get('name')} has field writes; scalar or heap-object field writes are not promoted as stack overflow candidates."
            )
        if stack_regions and not target_candidates:
            notes.append(
                f"{node.get('name')} has {len(stack_regions)} stack region(s), but none were resolved as the destination of an unsafe write."
            )
    return _unique(notes)


def _node_matches_target(node: FunctionNode, target: str) -> bool:
    values = (
        node.record.name,
        node.record.address,
        node.record.relative_path,
        node.record.source_symbol,
        node.record.demangled_name,
    )
    return any(_matches(value, target) for value in values)


def _candidate_matches_target(candidate: StaticCandidate, target: str) -> bool:
    values = (
        candidate.function_name,
        candidate.source_symbol,
        candidate.demangled_name,
        candidate.address,
        candidate.relative_path,
    )
    return any(_matches(value, target) for value in values)


def _candidate_is_related(candidate: StaticCandidate, target: str) -> bool:
    if _candidate_matches_target(candidate, target):
        return True
    if _matches(candidate.line_text, target):
        return True
    return any(_matches(item, target) for item in candidate.call_path)


def _summary_is_related(summary: Mapping[str, Any], target: str) -> bool:
    if _matches(str(summary.get("function_name") or ""), target):
        return True
    for key in summary.get("function_keys") or []:
        if _matches(str(key), target):
            return True
    for collection in ("writes", "allocations", "sources", "wrappers"):
        for item in summary.get(collection) or []:
            if _matches(json.dumps(item, sort_keys=True, default=str), target):
                return True
    return False


def _matches(value: object, target: str) -> bool:
    value_text = str(value or "")
    target_text = str(target or "")
    if not value_text or not target_text:
        return False
    if value_text == target_text:
        return True
    return _normalize(value_text) == _normalize(target_text) or _normalize(target_text) in _normalize(value_text)


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower().lstrip("_"))


def _is_copy_like_call(call: str) -> bool:
    lowered = call.lower()
    return any(hint in lowered for hint in COPY_HINTS)


def _unique(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


if __name__ == "__main__":
    main()
