"""Run replay validation for proof-ready candidate states."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from binary_agent.pipeline import load_candidate_states, write_source_to_sink_trace_artifacts
from binary_agent.promotion import apply_replay_results, promote_for_replay, write_promotion_artifacts
from binary_agent.replay import build_replay_plan, build_replay_requests, run_replay_plan, run_replay_requests
from binary_agent.utils.env import load_dotenv_if_available


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run replay validation for proof-gated candidates.")
    parser.add_argument("candidate_states", type=Path, help="candidate_states.json from refinement or promotion.")
    parser.add_argument("--binary", type=Path, default=None, help="Binary path for native replay.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory for replay artifacts.")
    parser.add_argument("--promotion-dir", type=Path, required=True, help="Directory for updated promotion artifacts.")
    parser.add_argument("--mode", choices=("auto", "native", "function_harness", "qemu_user", "qemu_system", "container_service", "off"), default="auto")
    parser.add_argument("--hypothesis-artifacts", type=Path, default=None, help="Validated hypothesis stage directory to merge into replay planning.")
    parser.add_argument("--evidence-dir", type=Path, default=None, help="Evidence-pack directory used for proof-oracle derivation and repair validation.")
    parser.add_argument("--max-replay-requests-per-candidate", type=int, default=3)
    return parser.parse_args()


def main() -> None:
    load_dotenv_if_available()
    args = parse_args()
    states = load_candidate_states(args.candidate_states)
    plan = None
    if args.hypothesis_artifacts is not None or args.evidence_dir is not None:
        plan = build_replay_plan(
            states,
            binary_path=args.binary,
            mode=args.mode,
            hypothesis_artifacts_dir=args.hypothesis_artifacts,
            evidence_dir=args.evidence_dir,
            max_requests_per_candidate=args.max_replay_requests_per_candidate,
        )
        plan.write(args.output_dir / "replay_plan.json")
        requests = plan.requests
    else:
        requests = build_replay_requests(states, binary_path=args.binary, mode=args.mode)
    request_artifacts = _write_request_index(requests, args.output_dir)
    states, replay_events = promote_for_replay(states, request_artifacts=request_artifacts)
    results = (
        run_replay_plan(plan, args.output_dir, evidence_dir=args.evidence_dir)
        if plan is not None
        else run_replay_requests(requests, args.output_dir)
    )
    states, result_events, lift = apply_replay_results(states, results)
    states, _source_trace_artifacts = write_source_to_sink_trace_artifacts(states, args.promotion_dir / "source_to_sink")
    artifacts = write_promotion_artifacts(states, [*replay_events, *result_events], lift, args.promotion_dir)
    print(json.dumps({"requests": len(requests), "results": len(results), **{key: str(value) for key, value in artifacts.items()}}, indent=2))


def _write_request_index(requests, output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    refs: dict[str, str] = {}
    rows = []
    for request in requests:
        path = output_dir / _safe_name(request.candidate_id) / "request.json"
        rows.append({"candidate_id": request.candidate_id, "path": str(path)})
        refs[request.candidate_id] = str(path)
    (output_dir / "replay_requests.json").write_text(json.dumps({"replay_requests": rows}, indent=2, sort_keys=True))
    return refs


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)[:120] or "candidate"


if __name__ == "__main__":
    main()
