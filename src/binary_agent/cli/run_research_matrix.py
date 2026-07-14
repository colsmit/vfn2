"""Run the durable registered research corpus matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from binary_agent.research_matrix import run_registered_matrix


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path(".ai/runs/registered-matrix"),
        help="Durable research experiment root.",
    )
    parser.add_argument("--mode", choices=("lightweight", "full"), default="lightweight")
    parser.add_argument("--run-id", help="Optional stable experiment directory name.")
    parser.add_argument("--overwrite-run", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = run_registered_matrix(
        args.output_root,
        mode=args.mode,
        run_id=args.run_id,
        overwrite_run=args.overwrite_run,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    if not result.accepted:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
