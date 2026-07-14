"""Run a benchmark suite over capability sweep and known-overflow summaries."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from binary_agent.capability_benchmark import CAPABILITY_BENCHMARK_SUMMARY, run_capability_benchmark


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite_json", type=Path, help="Benchmark suite JSON manifest.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory for benchmark artifacts.")
    parser.add_argument("--baseline", type=Path, help="Previous capability_benchmark_summary.json for delta output.")
    parser.add_argument("--overwrite", action="store_true", help="Forward overwrite behavior to benchmark runners.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = run_capability_benchmark(
        args.suite_json,
        args.output_dir,
        baseline=args.baseline,
        overwrite=args.overwrite,
    )
    summary_path = Path(args.output_dir).resolve() / CAPABILITY_BENCHMARK_SUMMARY
    print(f"[+] Capability benchmark summary saved to {summary_path}")
    print(json.dumps(summary.totals, indent=2, sort_keys=True))
    return 0 if summary.success else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
