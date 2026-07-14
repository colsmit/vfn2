"""Plan and summarize proof work that shares backend setup."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Sequence

from binary_agent.scheduling import ProofAttempt


@dataclass(frozen=True)
class ProofBatch:
    batch_id: str
    setup_key: str
    route: str
    candidate_ids: tuple[str, ...]
    cold_setup_seconds: float
    marginal_seconds: float
    projected_unbatched_seconds: float
    projected_batched_seconds: float
    projected_saved_seconds: float

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["candidate_ids"] = list(self.candidate_ids)
        return payload


def plan_proof_batches(attempts: Sequence[ProofAttempt]) -> tuple[ProofBatch, ...]:
    grouped: dict[tuple[str, str], list[ProofAttempt]] = {}
    for attempt in attempts:
        setup_key = attempt.setup_key or f"unshared:{attempt.candidate_id}:{attempt.route}"
        grouped.setdefault((setup_key, attempt.route), []).append(attempt)
    batches = []
    for index, ((setup_key, route), rows) in enumerate(sorted(grouped.items()), start=1):
        ordered = sorted(rows, key=lambda item: (item.rank, item.candidate_id))
        cold = max((float(item.estimated_setup_seconds) for item in ordered), default=0.0)
        marginal = sum(float(item.estimated_marginal_seconds) for item in ordered)
        unbatched = sum(
            float(item.estimated_setup_seconds) + float(item.estimated_marginal_seconds)
            for item in ordered
        )
        batched = cold + marginal
        batches.append(
            ProofBatch(
                batch_id=f"batch-{index:04d}",
                setup_key=setup_key,
                route=route,
                candidate_ids=tuple(item.candidate_id for item in ordered),
                cold_setup_seconds=round(cold, 6),
                marginal_seconds=round(marginal, 6),
                projected_unbatched_seconds=round(unbatched, 6),
                projected_batched_seconds=round(batched, 6),
                projected_saved_seconds=round(max(0.0, unbatched - batched), 6),
            )
        )
    return tuple(batches)


def summarize_executed_batches(results: Sequence[Any]) -> dict[str, Any]:
    keys: dict[str, list[Any]] = {}
    for item in results:
        key = str(getattr(item, "setup_key", "") or f"unshared:{getattr(item, 'candidate_id', '')}")
        keys.setdefault(key, []).append(item)
    return {
        "schema_version": 1,
        "artifact_kind": "executed_proof_batch_summary",
        "batch_count": len(keys),
        "multi_candidate_batch_count": sum(len(rows) > 1 for rows in keys.values()),
        "setup_reuse_count": sum(bool(getattr(item, "setup_reused", False)) for item in results),
        "measured_wall_seconds_sum": round(sum(float(getattr(item, "duration_seconds", 0.0)) for item in results), 6),
        "measured_cpu_seconds_sum": round(sum(float(getattr(item, "cpu_seconds", 0.0)) for item in results), 6),
        "batches": [
            {
                "setup_key": key,
                "candidate_ids": [str(getattr(item, "candidate_id", "")) for item in rows],
                "attempt_count": len(rows),
            }
            for key, rows in sorted(keys.items())
        ],
    }
