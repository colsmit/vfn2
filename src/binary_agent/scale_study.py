"""Plan clustered, shared-setup proof work over a large candidate inventory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from binary_agent.candidate_clustering import cluster_mechanism_candidates
from binary_agent.execution_envelope import discover_execution_envelope
from binary_agent.pipeline import load_candidate_states
from binary_agent.proof_batching import plan_proof_batches
from binary_agent.scheduling import ProofBudget, schedule_proofs


def run_scale_study(
    candidate_states_path: Path,
    output_path: Path,
    *,
    rootfs_path: Path | None = None,
    candidate_budget: int = 64,
    cache_dir: Path | None = None,
) -> dict[str, Any]:
    states = [state for state in load_candidate_states(candidate_states_path) if state.status == "proof_ready"]
    representatives, suppressions = cluster_mechanism_candidates(states)
    envelopes = {}
    by_binary = {}
    for state in representatives:
        binary = Path(str(state.target.get("path") or "")).expanduser().resolve()
        if binary not in by_binary:
            by_binary[binary] = discover_execution_envelope(
                binary,
                rootfs_path=rootfs_path,
                cache_dir=cache_dir,
            )
        envelopes[state.candidate_id] = {
            item.route: item for item in by_binary[binary].capabilities
        }
    schedule = schedule_proofs(
        representatives,
        plans=None,
        budget=ProofBudget(candidate_budget, 3600.0, 3600.0),
        policy="adaptive",
        route_capabilities=envelopes,
    )
    batches = plan_proof_batches(schedule.attempts)
    result = {
        "schema_version": 1,
        "artifact_kind": "clustered_shared_setup_scale_study",
        "candidate_states_path": str(Path(candidate_states_path).resolve()),
        "raw_proof_ready_candidates": len(states),
        "cluster_representatives": len(representatives),
        "cluster_suppressed": len(suppressions),
        "unique_binaries": len(by_binary),
        "scheduled_attempts": len(schedule.attempts),
        "batch_count": len(batches),
        "multi_candidate_batch_count": sum(len(item.candidate_ids) > 1 for item in batches),
        "projected_unbatched_seconds": round(sum(item.projected_unbatched_seconds for item in batches), 6),
        "projected_batched_seconds": round(sum(item.projected_batched_seconds for item in batches), 6),
        "projected_saved_seconds": round(sum(item.projected_saved_seconds for item in batches), 6),
        "measured_wall_seconds": None,
        "measured_cpu_seconds": None,
        "measurement_status": "planning_only_no_execution_claim",
        "batches": [item.to_dict() for item in batches],
        "suppressions": [item.to_dict() for item in suppressions],
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result
