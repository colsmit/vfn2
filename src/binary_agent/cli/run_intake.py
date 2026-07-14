"""Generate intake artifacts for a target binary or root filesystem."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from binary_agent.intake import run_intake
from binary_agent.utils.env import load_dotenv_if_available


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate proof-gated pipeline intake artifacts.")
    parser.add_argument("target", type=Path, help="Binary, rootfs directory, or tar archive to inventory.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory for intake JSON artifacts.")
    parser.add_argument("--export-dir", type=Path, default=None, help="Optional Ghidra export directory to reference.")
    parser.add_argument("--no-overwrite", action="store_true", help="Preserve existing intake artifact files.")
    return parser.parse_args()


def main() -> None:
    load_dotenv_if_available()
    args = parse_args()
    result = run_intake(
        args.target,
        args.output_dir,
        export_dir=args.export_dir,
        overwrite=not args.no_overwrite,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
