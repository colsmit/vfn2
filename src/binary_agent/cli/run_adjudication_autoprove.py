"""Generate or check deterministic proof certificates for a frozen campaign."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from binary_agent.adjudication import AdjudicationError
from binary_agent.adjudication_autoprove import check_all_certificates, run_autoprove
from binary_agent.adjudication_certificates import CertificateError
from binary_agent.adjudication_investigation import (
    ExternalCommandInvestigationProvider,
    InvestigationError,
)


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
    run.add_argument(
        "--direct-command",
        help="OpenAI-compatible provider adapter command receiving one pack on stdin",
    )
    run.add_argument(
        "--agent-command",
        help="coding-agent exec command (for example a Pi adapter) receiving one pack on stdin",
    )
    run.add_argument("--direct-timeout", type=float, default=120.0)
    run.add_argument("--agent-timeout", type=float, default=900.0)
    run.add_argument("--direct-call-cap", type=int)
    run.add_argument("--agent-call-cap", type=int)
    check = subparsers.add_parser("check", help="independently re-check every certificate")
    check.add_argument("campaign_root", type=Path, nargs="?", default=DEFAULT_CAMPAIGN)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.mode == "run":
            direct_provider = (
                ExternalCommandInvestigationProvider.from_command_string(
                    args.direct_command,
                    timeout_seconds=args.direct_timeout,
                )
                if args.direct_command
                else None
            )
            agent_provider = (
                ExternalCommandInvestigationProvider.from_command_string(
                    args.agent_command,
                    timeout_seconds=args.agent_timeout,
                )
                if args.agent_command
                else None
            )
            result = run_autoprove(
                args.campaign_root,
                admit=args.admit,
                direct_provider=direct_provider,
                agent_provider=agent_provider,
                direct_call_cap=args.direct_call_cap,
                agent_call_cap=args.agent_call_cap,
            )
            payload = {"mode": "run", **result.to_dict()}
        else:
            payload = {"mode": "check", **check_all_certificates(args.campaign_root)}
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except (
        AdjudicationError,
        CertificateError,
        InvestigationError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        print(f"autoprove failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
