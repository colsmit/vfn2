"""Record research prerequisites and optionally run the available live-Ghidra tier."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from binary_agent.research_validation import run_research_validation


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path(".ai/runs/research-validation"),
    )
    parser.add_argument("--ghidra-dir", type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--build-samples", action="store_true")
    parser.add_argument("--run-live-ghidra", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    environment = dict(os.environ)
    if args.ghidra_dir is not None:
        environment["GHIDRA_INSTALL_DIR"] = str(args.ghidra_dir.expanduser().resolve())
    result = run_research_validation(
        args.output_root,
        repo_root=Path.cwd(),
        environment=environment,
        build_samples=args.build_samples,
        run_live_ghidra=args.run_live_ghidra and not args.preflight_only,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    if result.status != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
