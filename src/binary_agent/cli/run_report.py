"""Write lean artifact-bound reports from candidate states."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from binary_agent.pipeline import load_candidate_states, write_bug_bounty_evidence_artifacts, write_source_to_sink_trace_artifacts
from binary_agent.reporting import build_lean_reports, write_lean_reports, write_vendor_evidence_bundles
from binary_agent.utils.env import load_dotenv_if_available


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write replay-gated vulnerability reports.")
    parser.add_argument("candidate_states", type=Path, help="candidate_states.json from promotion.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory for report artifacts.")
    parser.add_argument("--intake-dir", type=Path, default=None, help="Optional intake artifact directory for vendor evidence.")
    return parser.parse_args()


def main() -> None:
    load_dotenv_if_available()
    args = parse_args()
    states = load_candidate_states(args.candidate_states)
    states, _trace_artifacts = write_source_to_sink_trace_artifacts(states, args.output_dir / "source_to_sink")
    states, _bug_bounty_evidence_artifacts = write_bug_bounty_evidence_artifacts(
        states,
        args.output_dir / "bug_bounty_evidence",
    )
    reports = build_lean_reports(states)
    written = write_lean_reports(reports, args.output_dir)
    bundles = write_vendor_evidence_bundles(states, args.output_dir / "vendor_evidence", intake_dir=args.intake_dir)
    print(
        json.dumps(
            {
                "reports": len(reports),
                "vendor_evidence_bundles": len(bundles),
                "artifacts": {key: str(path) for key, path in written.items()},
                "vendor_evidence": [bundle.to_dict() for bundle in bundles],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
