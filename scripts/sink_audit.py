#!/usr/bin/env python3
"""Inventory unknown copy/read/format-like calls in decompiled exports."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Sequence

from binary_agent.analysis.extractors import load_memory_operation_specs
from binary_agent.ingest.loader import load_function_nodes


CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(")
INTERESTING_RE = re.compile(
    r"(?:copy|cpy|cat|move|mem|read|recv|scan|print|format|fmt|gets?|put|write|append|alloc)",
    re.IGNORECASE,
)
IGNORED_CALLS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "typedef",
}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exports", nargs="+", type=Path, help="Export directories to audit.")
    parser.add_argument("--operation-specs", type=Path, default=None, help="Override operation_specs.json path.")
    parser.add_argument("--output", type=Path, default=None, help="Optional JSON output path.")
    parser.add_argument("--limit", type=int, default=200, help="Maximum unknown call names to include.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    report = audit_exports(args.exports, operation_specs_path=args.operation_specs, limit=args.limit)
    text = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text)


def audit_exports(
    exports: Iterable[Path],
    *,
    operation_specs_path: Path | None = None,
    limit: int = 200,
) -> dict[str, object]:
    specs = load_memory_operation_specs(operation_specs_path)
    counts: Counter[str] = Counter()
    examples: dict[str, list[dict[str, object]]] = defaultdict(list)
    scanned_exports = 0
    scanned_functions = 0
    for export_dir in exports:
        export_dir = Path(export_dir)
        try:
            _manifest, nodes = load_function_nodes(export_dir)
        except Exception as exc:
            examples[f"<load_error:{export_dir}>"].append({"error": str(exc)})
            continue
        scanned_exports += 1
        for node in nodes:
            scanned_functions += 1
            for line_number, line in enumerate(node.text.splitlines(), start=1):
                for raw_name in _iter_interesting_calls(line):
                    normalized = specs.normalize_name(raw_name)
                    if normalized in specs.sinks:
                        continue
                    counts[normalized] += 1
                    if len(examples[normalized]) < 5:
                        examples[normalized].append(
                            {
                                "export_dir": str(export_dir),
                                "function": node.record.name,
                                "address": node.record.address,
                                "relative_path": node.record.relative_path,
                                "line_number": line_number,
                                "line_text": line.strip(),
                                "raw_name": raw_name,
                            }
                        )
    unknown = [
        {
            "name": name,
            "count": count,
            "examples": examples.get(name, []),
        }
        for name, count in counts.most_common(max(0, limit))
    ]
    return {
        "operation_specs_version": specs.version,
        "scanned_exports": scanned_exports,
        "scanned_functions": scanned_functions,
        "unknown_interesting_calls": unknown,
        "unknown_interesting_call_count": sum(counts.values()),
        "unknown_interesting_name_count": len(counts),
    }


def _iter_interesting_calls(line: str) -> list[str]:
    stripped = _strip_comments_and_strings(line)
    names: list[str] = []
    for match in CALL_RE.finditer(stripped):
        raw = match.group(1).split("::")[-1]
        lowered = raw.lower().lstrip("_")
        if lowered in IGNORED_CALLS:
            continue
        if INTERESTING_RE.search(lowered):
            names.append(raw)
    return names


def _strip_comments_and_strings(line: str) -> str:
    out: list[str] = []
    quote = ""
    escaped = False
    idx = 0
    while idx < len(line):
        char = line[idx]
        nxt = line[idx + 1] if idx + 1 < len(line) else ""
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            out.append(" ")
            idx += 1
            continue
        if char in {"'", '"'}:
            quote = char
            out.append(" ")
            idx += 1
            continue
        if char == "/" and nxt == "/":
            break
        out.append(char)
        idx += 1
    return "".join(out)


if __name__ == "__main__":
    main()
