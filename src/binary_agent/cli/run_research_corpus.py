"""Freeze or verify immutable research-corpus inputs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from binary_agent.scheduling import SCHEDULER_POLICIES

from binary_agent.research_corpus import (
    evaluate_frozen_corpus,
    freeze_research_corpus,
    verify_frozen_corpus,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    freeze = subparsers.add_parser("freeze")
    freeze.add_argument("manifest", type=Path)
    freeze.add_argument("--source-root", type=Path, required=True)
    freeze.add_argument("--output-root", type=Path, default=Path(".ai/runs/research-corpora"))
    verify = subparsers.add_parser("verify")
    verify.add_argument("manifest", type=Path)
    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("manifest", type=Path)
    evaluate.add_argument("--output-root", type=Path, default=Path(".ai/runs/research-evaluation"))
    evaluate.add_argument("--scheduler", choices=tuple(sorted(SCHEDULER_POLICIES)), default="adaptive")
    evaluate.add_argument("--candidate-budget", type=int, default=8)
    evaluate.add_argument("--wall-budget-seconds", type=float, default=120.0)
    evaluate.add_argument("--cpu-budget-seconds", type=float, default=120.0)
    evaluate.add_argument("--proof-timeout-seconds", type=float, default=15.0)
    evaluate.add_argument("--proof-jobs", type=int, default=1)
    evaluate.add_argument("--ghidra-dir", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "freeze":
        result = freeze_research_corpus(
            args.manifest,
            args.output_root,
            source_root=args.source_root,
            repo_root=Path.cwd(),
        )
        payload = result.to_dict()
    elif args.command == "verify":
        payload = verify_frozen_corpus(args.manifest)
    else:
        payload = evaluate_frozen_corpus(
            args.manifest,
            args.output_root,
            scheduler=args.scheduler,
            candidate_budget=args.candidate_budget,
            wall_budget_seconds=args.wall_budget_seconds,
            cpu_budget_seconds=args.cpu_budget_seconds,
            proof_timeout_seconds=args.proof_timeout_seconds,
            proof_jobs=args.proof_jobs,
            ghidra_dir=args.ghidra_dir,
            repo_root=Path.cwd(),
        ).to_dict()
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("verified", True) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
