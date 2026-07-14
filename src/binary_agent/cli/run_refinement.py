"""Build evidence packs and apply deterministic proof-readiness gates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from binary_agent.analysis.confirmation import build_evidence_pack_v3
from binary_agent.analysis.concolic import infer_process_input_fact
from binary_agent.pipeline import load_candidate_states
from binary_agent.promotion import promote_proof_ready, write_promotion_artifacts
from binary_agent.utils.env import load_dotenv_if_available


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run proof-gated refinement over candidate states.")
    parser.add_argument("candidate_states", type=Path, help="candidate_states.json or discovery candidates file.")
    parser.add_argument("--evidence-dir", type=Path, required=True, help="Directory for schema-v3 evidence packs.")
    parser.add_argument("--promotion-dir", type=Path, required=True, help="Directory for promotion artifacts.")
    return parser.parse_args()


def main() -> None:
    load_dotenv_if_available()
    args = parse_args()
    states = load_candidate_states(args.candidate_states)
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    enriched_states = []
    for state in states:
        pack = build_evidence_pack_v3(state.to_dict())
        state, pack = _state_and_pack_with_process_input(state, pack)
        enriched_states.append(state)
        path = args.evidence_dir / f"{_safe_name(state.candidate_id)}.json"
        path.write_text(json.dumps(pack, indent=2, sort_keys=True))
        entries.append({"candidate_id": state.candidate_id, "path": path.name})
    (args.evidence_dir / "index.json").write_text(json.dumps({"schema_version": 3, "evidence_packs": entries}, indent=2))
    states = enriched_states
    states, events, lift = promote_proof_ready(states)
    artifacts = write_promotion_artifacts(states, events, lift, args.promotion_dir)
    print(json.dumps({key: str(value) for key, value in artifacts.items()}, indent=2, sort_keys=True))


def _state_and_pack_with_process_input(state: Any, pack: Mapping[str, Any]):
    type_facts = dict(getattr(state, "type_facts", {}) or {})
    if isinstance(type_facts.get("process_input"), Mapping):
        return state, dict(pack)
    process_input = infer_process_input_fact(pack)
    if not process_input:
        return state, dict(pack)
    updated = state.with_updates(type_facts={**type_facts, "process_input": process_input})
    return updated, build_evidence_pack_v3(updated.to_dict())


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)[:120] or "candidate"


if __name__ == "__main__":
    main()
