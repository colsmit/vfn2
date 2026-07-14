"""Freeze, verify, or evaluate an OpenWrt ubus transaction benchmark."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from binary_agent.transaction_benchmark import (
    TRANSACTION_BENCHMARK_CORPUS_ID,
    evaluate_transaction_benchmark,
    freeze_transaction_benchmark,
    verify_transaction_benchmark,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("freeze")
    freeze.add_argument("campaign_root", type=Path)
    freeze.add_argument("rootfs", type=Path)
    freeze.add_argument("--netifd-export", type=Path, required=True)
    freeze.add_argument("--rpcd-export", type=Path, required=True)
    freeze.add_argument("--output-root", type=Path, default=Path(".ai/runs/research-corpora"))
    freeze.add_argument("--corpus-id", default=TRANSACTION_BENCHMARK_CORPUS_ID)
    verify = sub.add_parser("verify")
    verify.add_argument("manifest", type=Path)
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("manifest", type=Path)
    evaluate.add_argument("--output-root", type=Path, default=Path(".ai/runs/transaction-benchmarks"))
    evaluate.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    if args.command == "freeze":
        manifest = freeze_transaction_benchmark(
            args.campaign_root,
            args.rootfs,
            {"netifd": args.netifd_export, "rpcd": args.rpcd_export},
            args.output_root,
            corpus_id=args.corpus_id,
        )
        result = {"manifest_path": str(manifest), **verify_transaction_benchmark(manifest)}
    elif args.command == "verify":
        result = verify_transaction_benchmark(args.manifest)
    else:
        result = evaluate_transaction_benchmark(
            args.manifest,
            args.output_root,
            repetitions=args.repetitions,
        )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
