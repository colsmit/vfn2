"""Freeze, verify, or evaluate a proof-route contention benchmark."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from binary_agent.route_benchmark import evaluate_route_benchmark, freeze_route_benchmark, verify_route_benchmark


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    freeze = subparsers.add_parser("freeze")
    freeze.add_argument("--source-run", type=Path, required=True)
    freeze.add_argument("--output-root", type=Path, default=Path(".ai/runs/research-corpora"))
    freeze.add_argument("--corpus-id", default="openwrt-route-contention-v1")
    verify = subparsers.add_parser("verify")
    verify.add_argument("manifest", type=Path)
    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("manifest", type=Path)
    evaluate.add_argument("--output-root", type=Path, default=Path(".ai/runs/route-benchmarks"))
    evaluate.add_argument("--candidate-budget", type=int, default=3)
    evaluate.add_argument("--wall-budget-seconds", type=float, default=60.0)
    evaluate.add_argument("--cpu-budget-seconds", type=float, default=60.0)
    evaluate.add_argument("--proof-timeout-seconds", type=float, default=8.0)
    evaluate.add_argument("--repetitions", type=int, default=2)
    evaluate.add_argument("--ghidra-dir", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "freeze":
        payload = freeze_route_benchmark(
            args.source_run,
            args.output_root,
            repo_root=Path.cwd(),
            corpus_id=args.corpus_id,
        ).to_dict()
    elif args.command == "verify":
        payload = verify_route_benchmark(args.manifest)
    else:
        payload = evaluate_route_benchmark(
            args.manifest,
            args.output_root,
            candidate_budget=args.candidate_budget,
            wall_budget_seconds=args.wall_budget_seconds,
            cpu_budget_seconds=args.cpu_budget_seconds,
            timeout_seconds=args.proof_timeout_seconds,
            repetitions=args.repetitions,
            ghidra_dir=args.ghidra_dir,
            repo_root=Path.cwd(),
        )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("verified", True) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
