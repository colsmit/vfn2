#!/usr/bin/env python3
"""Score deterministic screen findings against ROMEO/JULIET ground truth."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple


DEFAULT_RUNS_ROOT = Path("runs/romeo_cwe121/reports")
DEFAULT_SCOPE = "scoped"
SCOPES = ("scoped", "strict")
DEFAULT_SURFACE = "confirmation"
SURFACES = ("confirmation", "reportable", "candidate")
REPORT_LABEL_SUFFIX_RE = re.compile(r"_\d{8}-\d{6}$")
VARIANT_SUFFIX_RE = re.compile(r"^(?P<base>.+?)(?:-|_)(?P<variant>bad|good|goodb2g|goodg2b)$", re.IGNORECASE)


def _canonical_symbol(name: str) -> str:
    return str(name).strip().lower().lstrip("_")


def normalize_binary_key(value: str) -> str:
    stem = Path(value).name
    if stem.lower().startswith("linked-"):
        stem = stem[len("linked-") :]
    stem = Path(stem).stem
    if stem.lower().endswith(".o"):
        stem = Path(stem).stem
    stem = REPORT_LABEL_SUFFIX_RE.sub("", stem)
    return stem.lower()


def load_ground_truth(path: Path) -> Dict[str, dict]:
    payload = json.loads(path.read_text())
    binaries = payload.get("binaries", payload)
    truth: Dict[str, dict] = {}
    for key, entry in (binaries or {}).items():
        if not isinstance(entry, dict):
            continue
        truth[normalize_binary_key(str(key))] = {
            "positives": {_canonical_symbol(str(name)) for name in entry.get("positives", []) if name},
            "negatives": {_canonical_symbol(str(name)) for name in entry.get("negatives", []) if name},
            "ignored": {_canonical_symbol(str(name)) for name in entry.get("ignored", []) if name},
            "source_path": str(entry.get("source_path") or ""),
        }
    return truth


def _ground_truth_candidates(binary_key: str) -> List[str]:
    candidates: List[str] = []

    def add(value: str) -> None:
        if value and value not in candidates:
            candidates.append(value)

    normalized = normalize_binary_key(binary_key)
    match = VARIANT_SUFFIX_RE.match(normalized)
    if match:
        base = match.group("base")
        variant = match.group("variant").lower()
        add(f"{base}_{variant}")
        add(f"{base}-{variant}")
        add(base)
    add(normalized)
    return candidates


def resolve_ground_truth_entry(ground_truth: Dict[str, dict], binary_key: str) -> Tuple[Optional[dict], int]:
    for candidate in _ground_truth_candidates(binary_key):
        if candidate in ground_truth:
            return ground_truth[candidate], 1
    return None, 0


def iter_report_paths(root: Path) -> List[Path]:
    if root.is_file():
        return [root]
    return sorted(path for path in root.rglob("*.json") if path.is_file())


def _report_binary_key(path: Path, report: dict) -> str:
    config = report.get("config") if isinstance(report.get("config"), dict) else {}
    return normalize_binary_key(str(config.get("binary") or path.stem))


def _candidate_is_reportable(candidate: dict) -> bool:
    return bool(
        candidate.get("verdict") in {"overflow", "unbounded"}
        and candidate.get("input_reaches_sink")
        and candidate.get("path_is_valid")
    )


def _candidate_symbol(candidate: dict) -> str:
    return _canonical_symbol(str(candidate.get("source_symbol") or candidate.get("function_name") or ""))


def _surface_candidates(report: dict, surface: str) -> Sequence[dict]:
    if surface == "confirmation":
        if "confirmation_findings" in report:
            return report.get("confirmation_findings") or []
        return [
            candidate
            for candidate in report.get("candidate_findings") or []
            if isinstance(candidate, dict) and _candidate_is_reportable(candidate)
        ]
    return report.get("candidate_findings") or []


def load_detections(report: dict, *, surface: str = DEFAULT_SURFACE) -> Set[str]:
    if surface not in SURFACES:
        raise ValueError(f"surface must be one of: {', '.join(SURFACES)}")
    detections: Set[str] = set()
    for candidate in _surface_candidates(report, surface):
        if not isinstance(candidate, dict):
            continue
        if surface == "reportable" and not _candidate_is_reportable(candidate):
            continue
        symbol = _candidate_symbol(candidate)
        if symbol:
            detections.add(symbol)
    return detections


def _safe_divide(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _metrics(tp: int, fp: int, fn: int, *, surface: str) -> dict:
    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1 = _safe_divide(2 * precision * recall, precision + recall)
    return {
        "stage": surface,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def score_reports(
    report_paths: Sequence[Path],
    *,
    ground_truth: Dict[str, dict],
    scope: str = DEFAULT_SCOPE,
    surface: str = DEFAULT_SURFACE,
) -> Tuple[List[dict], dict]:
    if scope not in SCOPES:
        raise ValueError(f"scope must be one of: {', '.join(SCOPES)}")
    if surface not in SURFACES:
        raise ValueError(f"surface must be one of: {', '.join(SURFACES)}")

    rows: List[dict] = []
    tp = fp = fn = 0
    missing_ground_truth = 0

    for path in report_paths:
        report = json.loads(path.read_text())
        binary_key = _report_binary_key(path, report)
        truth, truth_matches = resolve_ground_truth_entry(ground_truth, binary_key)
        if not truth:
            missing_ground_truth += 1
            continue

        positives = set(truth.get("positives") or set())
        negatives = set(truth.get("negatives") or set())
        ignored = set(truth.get("ignored") or set())
        detections = load_detections(report, surface=surface)

        for detection in sorted(detections):
            if detection in positives:
                label = "tp"
                tp += 1
            elif detection in negatives or scope == "strict":
                label = "fp"
                fp += 1
            else:
                label = "ignored"
            rows.append(
                {
                    "binary": binary_key,
                    "function": detection,
                    "truth_label": label,
                    "stage": surface,
                    "report": str(path),
                    "truth_matches": truth_matches,
                }
            )

        missed = positives - detections
        for function in sorted(missed):
            if function in ignored:
                continue
            fn += 1
            rows.append(
                {
                    "binary": binary_key,
                    "function": function,
                    "truth_label": "fn",
                    "stage": surface,
                    "report": str(path),
                    "truth_matches": truth_matches,
                }
            )

    metrics = _metrics(tp, fp, fn, surface=surface)
    metrics["missing_ground_truth"] = missing_ground_truth
    metrics["rows"] = len(rows)
    return rows, metrics


def write_rows(path: Path, rows: Sequence[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["binary", "function", "truth_label", "stage", "report", "truth_matches"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-root", type=Path, default=DEFAULT_RUNS_ROOT, help="Report JSON file or directory.")
    parser.add_argument("--ground-truth", type=Path, required=True, help="Ground truth JSON from build_romeo_ground_truth.py.")
    parser.add_argument("--scope", choices=SCOPES, default=DEFAULT_SCOPE, help="How to score unknown detections.")
    parser.add_argument(
        "--surface",
        choices=SURFACES,
        default=DEFAULT_SURFACE,
        help=(
            "Detection surface to score. 'confirmation' scores the high-recall LLM handoff queue, "
            "'reportable' scores the exact deterministic overflow surface, and 'candidate' scores all candidate_findings."
        ),
    )
    parser.add_argument("--out", type=Path, default=None, help="CSV output path.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    report_paths = iter_report_paths(args.runs_root.expanduser().resolve())
    ground_truth = load_ground_truth(args.ground_truth.expanduser().resolve())
    rows, metrics = score_reports(report_paths, ground_truth=ground_truth, scope=args.scope, surface=args.surface)
    out_path = args.out or (args.runs_root.expanduser().resolve().parent / f"score_{args.surface}.csv")
    write_rows(out_path, rows)
    print(json.dumps(metrics, indent=2, sort_keys=True))
    print(f"[+] wrote {len(rows)} rows to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
