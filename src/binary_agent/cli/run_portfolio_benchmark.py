"""Build, verify, and evaluate the mixed-yield proof portfolio."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from binary_agent.portfolio_benchmark import (
    PORTFOLIO_POLICIES,
    build_portfolio_benchmark,
    evaluate_portfolio_benchmark,
    prepare_firmware_rootfs_fixture,
    verify_portfolio_benchmark,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare-rootfs")
    prepare.add_argument("juliet_manifest", type=Path)
    prepare.add_argument("output_dir", type=Path)
    build = subparsers.add_parser("build")
    build.add_argument("--output-root", type=Path, default=Path(".ai/runs/research-corpora"))
    build.add_argument("--juliet-evaluation-summary", type=Path, required=True)
    build.add_argument("--firmware-run", type=Path, required=True)
    build.add_argument("--openwrt-manifest", type=Path, required=True)
    build.add_argument("--openwrt-rootfs", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("manifest", type=Path)
    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("manifest", type=Path)
    evaluate.add_argument("--output-root", type=Path, default=Path(".ai/runs/portfolio-benchmarks"))
    evaluate.add_argument("--candidate-budget", type=int, default=2)
    evaluate.add_argument("--wall-budget-seconds", type=float, default=30.0)
    evaluate.add_argument("--cpu-budget-seconds", type=float, default=30.0)
    evaluate.add_argument("--proof-timeout-seconds", type=float, default=3.0)
    evaluate.add_argument("--repetitions", type=int, default=2)
    evaluate.add_argument("--policies", default=",".join(PORTFOLIO_POLICIES))
    evaluate.add_argument("--ghidra-dir", type=Path, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "prepare-rootfs":
        fixture = prepare_firmware_rootfs_fixture(args.juliet_manifest, args.output_dir)
        payload = {"fixture_manifest": str(fixture), **json.loads(fixture.read_text())}
    elif args.command == "build":
        manifest = build_portfolio_benchmark(
            args.output_root,
            juliet_evaluation_summary=args.juliet_evaluation_summary,
            firmware_run=args.firmware_run,
            openwrt_manifest=args.openwrt_manifest,
            openwrt_rootfs=args.openwrt_rootfs,
        )
        payload = {"manifest_path": str(manifest), **verify_portfolio_benchmark(manifest)}
    elif args.command == "verify":
        payload = verify_portfolio_benchmark(args.manifest)
    else:
        payload = evaluate_portfolio_benchmark(
            args.manifest,
            args.output_root,
            candidate_budget=args.candidate_budget,
            wall_budget_seconds=args.wall_budget_seconds,
            cpu_budget_seconds=args.cpu_budget_seconds,
            timeout_seconds=args.proof_timeout_seconds,
            repetitions=args.repetitions,
            policies=tuple(item.strip() for item in args.policies.split(",") if item.strip()),
            ghidra_dir=args.ghidra_dir,
        )
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
