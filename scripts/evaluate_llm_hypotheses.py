#!/usr/bin/env python3
"""Run offline LLM vulnerability hypothesis evaluation over evidence packs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from binary_agent.analysis.concolic import ConcolicToolConfig
from binary_agent.analysis.llm_evaluation import (
    EVALUATION_SYSTEMS,
    load_gold_labels,
    run_offline_llm_evaluation,
)
from binary_agent.replay.models import load_replay_results


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate mocked or recorded LLM replay, environment, branch-guidance, "
            "and triage hypotheses against deterministic evidence packs."
        )
    )
    parser.add_argument("evidence_dir", type=Path, help="Directory containing evidence-pack JSON and index.json.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory for summary and per-candidate artifacts.")
    parser.add_argument(
        "--fixtures-dir",
        type=Path,
        default=None,
        help=(
            "Directory containing LLM hypothesis JSON fixtures. Use fixtures_mocked for "
            "hand-written compatibility fixtures, fixtures_live_blind for blind live runs, "
            "or fixtures_live_repair for repair-loop runs."
        ),
    )
    parser.add_argument(
        "--replay-results",
        type=Path,
        default=None,
        help="Optional replay result JSON or replay artifact directory used for proof-lift scoring.",
    )
    parser.add_argument(
        "--systems",
        nargs="+",
        choices=sorted(EVALUATION_SYSTEMS),
        default=["D0", "L1", "L2", "L3"],
        help="Evaluation systems to score.",
    )
    parser.add_argument(
        "--gold-labels",
        type=Path,
        default=None,
        help="Optional curated JSON labels for environment/precondition coverage.",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=None,
        help="Optional binary path used to validate branch-guidance concolic requests.",
    )
    parser.add_argument(
        "--export-dir",
        type=Path,
        default=None,
        help="Optional decompiled export directory used in branch-guidance validation metadata.",
    )
    parser.add_argument(
        "--backend",
        choices=("angr",),
        default="angr",
        help="Concolic backend name for branch-guidance validation.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=30.0,
        help="Bounded timeout recorded in validated branch-guidance requests.",
    )
    parser.add_argument(
        "--max-symbolic-bytes",
        type=int,
        default=512,
        help="Maximum symbolic byte budget accepted from branch-guidance hypotheses.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    concolic_config = None
    if args.binary is not None:
        concolic_config = ConcolicToolConfig(
            binary_path=args.binary,
            output_dir=args.output_dir / "_concolic_validation",
            export_dir=args.export_dir,
            backend=args.backend,
            timeout_seconds=args.timeout_seconds,
            max_symbolic_bytes=args.max_symbolic_bytes,
        )
    result = run_offline_llm_evaluation(
        args.evidence_dir,
        args.output_dir,
        fixtures_dir=args.fixtures_dir,
        systems=args.systems,
        gold_labels=load_gold_labels(args.gold_labels),
        concolic_config=concolic_config,
        replay_results=load_replay_results(args.replay_results) if args.replay_results is not None else None,
    )
    print(
        json.dumps(
            {
                "summary_path": str(result.summary_path),
                "lift_summary_path": str(result.lift_summary_path),
                "summary": result.summary,
                "lift_summary": result.lift_summary,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
