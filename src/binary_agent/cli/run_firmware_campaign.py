"""Run a bounded, hash-pinned untouched-firmware research campaign."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from binary_agent.scheduling import SCHEDULER_POLICIES

from binary_agent.firmware_campaign import run_firmware_campaign


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output-root", type=Path, default=Path(".ai/runs/firmware-campaigns"))
    parser.add_argument("--scheduler", choices=tuple(sorted(SCHEDULER_POLICIES)), default="adaptive")
    parser.add_argument("--candidate-budget", type=int, default=64)
    parser.add_argument("--wall-budget-seconds", type=float, default=3600.0)
    parser.add_argument("--cpu-budget-seconds", type=float, default=3600.0)
    parser.add_argument("--proof-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--proof-jobs", type=int, default=1)
    parser.add_argument("--ghidra-dir", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = run_firmware_campaign(
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
    )
    payload = result.to_dict()
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if all(int(item.get("toolchain_returncode") or 0) == 0 for item in payload["images"]) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
