"""Run a capability sweep over mixed analyzer targets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from binary_agent.capability_sweep import CAPABILITY_SWEEP_SUMMARY, run_capability_sweep


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets_json", type=Path, help="JSON list or object with a targets list.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory for sweep artifacts.")
    parser.add_argument("--overwrite", action="store_true", help="Rewrite generated target artifacts where supported.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = run_capability_sweep(args.targets_json, args.output_dir, overwrite=args.overwrite)
    summary_path = Path(args.output_dir).resolve() / CAPABILITY_SWEEP_SUMMARY
    print(f"[+] Capability sweep summary saved to {summary_path}")
    print(json.dumps(summary.totals, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
