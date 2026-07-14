"""Summarize proof-gated validation corpus results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from binary_agent.pipeline import load_candidate_states
from binary_agent.utils.env import load_dotenv_if_available
from binary_agent.validation import summarize_validation_corpus, write_validation_summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize proof-gated validation cases from candidate states.")
    parser.add_argument("candidate_states", type=Path, help="candidate_states.json from promotion or report generation.")
    parser.add_argument("--output", type=Path, default=None, help="Optional path for validation_summary.json.")
    return parser.parse_args()


def main() -> None:
    load_dotenv_if_available()
    args = parse_args()
    states = load_candidate_states(args.candidate_states)
    summary = summarize_validation_corpus(states)
    if args.output:
        write_validation_summary(states, args.output)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
