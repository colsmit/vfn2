"""Run a schema-v2 vulnerable/fixed corpus manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from binary_agent.corpus_runner import load_corpus_manifest, run_corpus


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="Schema-v2 corpus manifest JSON.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Generated corpus run directory.")
    parser.add_argument("--mode", choices=("lightweight", "full"), default="lightweight")
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = run_corpus(
        load_corpus_manifest(args.manifest),
        args.output_dir,
        mode=args.mode,
        overwrite=args.overwrite,
    )
    print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    if not summary.accepted:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
