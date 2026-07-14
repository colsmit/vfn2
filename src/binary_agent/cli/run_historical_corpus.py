"""Freeze or verify the historical vulnerable/fixed CVE binary corpus."""

import argparse
import json
from pathlib import Path

from binary_agent.historical_corpus import (
    freeze_historical_corpus,
    prove_historical_corpus,
    summarize_historical_discovery,
    validate_historical_reproducer,
    verify_historical_corpus,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("freeze")
    freeze.add_argument("source_manifest", type=Path)
    freeze.add_argument("--output-root", type=Path, default=Path(".ai/runs/research-corpora"))
    verify = sub.add_parser("verify")
    verify.add_argument("manifest", type=Path)
    summarize = sub.add_parser("summarize")
    summarize.add_argument("manifest", type=Path)
    summarize.add_argument("discovery_root", type=Path)
    summarize.add_argument("--output", type=Path)
    validate = sub.add_parser("validate-reproducer")
    validate.add_argument("manifest", type=Path)
    validate.add_argument("--url", required=True)
    validate.add_argument("--sha256", required=True)
    validate.add_argument("--vulnerable-operation", default="0x10FCF0")
    validate.add_argument("--argv", action="append", default=[])
    validate.add_argument("--image-base", type=lambda value: int(value, 0), default=0x100000)
    validate.add_argument("--timeout", type=float, default=20.0)
    validate.add_argument(
        "--output-root",
        type=Path,
        default=Path(".ai/runs/historical-reproducer-validation"),
    )
    prove = sub.add_parser("prove")
    prove.add_argument("manifest", type=Path)
    prove.add_argument("--timeout", type=float, default=20.0)
    prove.add_argument(
        "--output-root",
        type=Path,
        default=Path(".ai/runs/historical-differential-proof"),
    )
    args = parser.parse_args()
    if args.command == "freeze":
        manifest = freeze_historical_corpus(args.source_manifest, args.output_root)
        result = {"manifest_path": str(manifest), **verify_historical_corpus(manifest)}
    elif args.command == "verify":
        result = verify_historical_corpus(args.manifest)
    elif args.command == "summarize":
        result = summarize_historical_discovery(
            args.manifest,
            args.discovery_root,
            output_path=args.output,
        )
    elif args.command == "validate-reproducer":
        result = validate_historical_reproducer(
            args.manifest,
            args.output_root,
            provenance_url=args.url,
            expected_sha256=args.sha256,
            vulnerable_operation=args.vulnerable_operation,
            argv=tuple(args.argv or ("-R", "-f")),
            image_base=args.image_base,
            timeout=args.timeout,
        )
    else:
        result = prove_historical_corpus(
            args.manifest,
            args.output_root,
            timeout=args.timeout,
        )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
