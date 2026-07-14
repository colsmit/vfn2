"""Generate or check deterministic proof certificates for a frozen campaign."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from binary_agent.adjudication import AdjudicationError
from binary_agent.adjudication_autoprove import check_all_certificates, run_autoprove
from binary_agent.adjudication_certificates import CertificateError


DEFAULT_CAMPAIGN = Path(".ai/runs/openwrt-four-binary-adjudication-v1")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    run = subparsers.add_parser("run", help="emit checked certificates and residual queue")
    run.add_argument("campaign_root", type=Path, nargs="?", default=DEFAULT_CAMPAIGN)
    run.add_argument(
        "--admit",
        action="store_true",
        help="admit complete checked review proposals through the existing review gate",
    )
    check = subparsers.add_parser("check", help="independently re-check every certificate")
    check.add_argument("campaign_root", type=Path, nargs="?", default=DEFAULT_CAMPAIGN)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.mode == "run":
            result = run_autoprove(args.campaign_root, admit=args.admit)
            payload = {"mode": "run", **result.to_dict()}
        else:
            payload = {"mode": "check", **check_all_certificates(args.campaign_root)}
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except (AdjudicationError, CertificateError, OSError, json.JSONDecodeError) as exc:
        print(f"autoprove failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
