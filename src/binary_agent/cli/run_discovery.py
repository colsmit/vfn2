"""Run shared deterministic discovery backends on a Ghidra export."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from binary_agent.discovery import (
    load_discovery_context,
    run_discovery,
    write_discovery_candidates,
    write_discovery_metrics,
)
from binary_agent.pipeline import write_candidate_states
from binary_agent.utils.env import load_dotenv_if_available


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run proof-gated deterministic vulnerability discovery.")
    parser.add_argument("export_dir", type=Path, help="Ghidra decompiled export directory.")
    parser.add_argument("--intake-dir", type=Path, default=None, help="Optional intake artifact directory.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory for discovery artifacts.")
    parser.add_argument(
        "--discovery-backends",
        default="",
        help="Comma-separated discovery backends; omitted selects all registered backends.",
    )
    parser.add_argument(
        "--vulnerability-types",
        default="",
        help="Comma-separated terminal vulnerability types; omitted selects every registered type.",
    )
    return parser.parse_args()


def main() -> None:
    load_dotenv_if_available()
    args = parse_args()
    context = load_discovery_context(args.export_dir, intake_dir=args.intake_dir)
    backend_names = [item.strip() for item in args.discovery_backends.split(",") if item.strip()] or None
    vulnerability_types = [item.strip() for item in args.vulnerability_types.split(",") if item.strip()] or None
    result = run_discovery(
        context,
        backend_names=backend_names,
        vulnerability_types=vulnerability_types,
    )
    states = list(result.states)
    candidates_path = write_discovery_candidates(states, args.output_dir)
    metrics_path = write_discovery_metrics(result.metrics, args.output_dir)
    states_path = write_candidate_states(states, args.output_dir / "candidate_states.json")
    print(json.dumps({"candidates": str(candidates_path), "candidate_states": str(states_path), "metrics": str(metrics_path), "count": len(states)}, indent=2))


if __name__ == "__main__":
    main()
