"""Backend-oriented discovery orchestration and metrics."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from binary_agent.discovery.backends import (
    MemoryAccessBackend,
    MemoryLifetimeBackend,
    SemanticEffectBackend,
    StaticEvidenceBackend,
    merge_candidates,
)
from binary_agent.data.proof_specs import attach_compiled_proof_plan, load_proof_specs
from binary_agent.candidate_clustering import cluster_mechanism_candidates
from binary_agent.discovery.base import DiscoveryBackend, DiscoveryContext
from binary_agent.pipeline import CandidateState
from binary_agent.taxonomy import ACTIVE_BACKENDS, VULNERABILITY_SPECS, validate_selection
from binary_agent.utils.time import utc_timestamp


@dataclass(frozen=True)
class DiscoveryResult:
    states: tuple[CandidateState, ...]
    metrics: dict[str, object]


def registered_backends() -> tuple[DiscoveryBackend, ...]:
    """Construct one fresh instance of each active backend."""

    return (
        MemoryAccessBackend(),
        MemoryLifetimeBackend(),
        SemanticEffectBackend(),
        StaticEvidenceBackend(),
    )


def discover_candidates(
    context: DiscoveryContext,
    *,
    backend_names: Iterable[str] | None = None,
    vulnerability_types: Iterable[str] | None = None,
    backends: Sequence[DiscoveryBackend] | None = None,
) -> list[CandidateState]:
    return list(
        run_discovery(
            context,
            backend_names=backend_names,
            vulnerability_types=vulnerability_types,
            backends=backends,
        ).states
    )


def run_discovery(
    context: DiscoveryContext,
    *,
    backend_names: Iterable[str] | None = None,
    vulnerability_types: Iterable[str] | None = None,
    backends: Sequence[DiscoveryBackend] | None = None,
) -> DiscoveryResult:
    selected_backends, selected_types = validate_selection(backend_names, vulnerability_types)
    available = tuple(backends or registered_backends())
    by_name = {backend.name: backend for backend in available}
    missing = selected_backends - by_name.keys()
    if missing:
        raise ValueError(f"No implementation registered for backend(s): {', '.join(sorted(missing))}")
    states: list[CandidateState] = []
    runtimes: dict[str, float] = {}
    emitted_counts: dict[str, int] = {}
    for backend_name in sorted(selected_backends):
        enabled = frozenset(
            name
            for name in selected_types
            if VULNERABILITY_SPECS[name].backend == backend_name
        )
        if enabled:
            started = time.perf_counter()
            emitted = list(by_name[backend_name].discover(context, context.index, enabled))
            runtimes[backend_name] = round(time.perf_counter() - started, 6)
            emitted_counts[backend_name] = len(emitted)
            states.extend(emitted)
    emitted_total = len(states)
    merged, merged_count = merge_candidates(states)
    clustered, cluster_suppressions = cluster_mechanism_candidates(merged)
    proof_specs = load_proof_specs()
    planned = [attach_compiled_proof_plan(item, proof_specs) for item in clustered]
    ordered = tuple(sorted(planned, key=lambda item: item.candidate_id))
    metrics = discovery_metrics(
        context,
        ordered,
        backend_runtimes=runtimes,
        candidates_before_merge=emitted_total,
    )
    metrics["backend_candidates_emitted"] = emitted_counts
    metrics["candidates_merged"] = merged_count
    metrics["mechanism_candidates_clustered"] = len(cluster_suppressions)
    metrics["mechanism_cluster_suppressions"] = [item.to_dict() for item in cluster_suppressions]
    metrics["normalized_blocker_totals"] = _blocker_totals(ordered)
    return DiscoveryResult(states=ordered, metrics=metrics)


def discovery_metrics(
    context: DiscoveryContext,
    states: Sequence[CandidateState],
    *,
    backend_runtimes: dict[str, float] | None = None,
    candidates_before_merge: int | None = None,
) -> dict[str, object]:
    counts: dict[str, int] = {}
    for state in states:
        counts[state.backend] = counts.get(state.backend, 0) + 1
    return {
        "schema_version": 2,
        "index_build_seconds": context.index.metrics.build_seconds,
        "functions_examined": context.index.metrics.functions,
        "operations_examined": len(context.index.operations),
        "backend_runtime_seconds": dict(backend_runtimes or {}),
        "candidates_emitted": int(candidates_before_merge if candidates_before_merge is not None else len(states)),
        "candidates_merged": max(0, int(candidates_before_merge or len(states)) - len(states)),
        "candidate_counts_by_backend": counts,
    }


def write_discovery_candidates(states: Sequence[CandidateState], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "candidates.json"
    payload = {
        "schema_version": 2,
        "generated_at": utc_timestamp(),
        "candidates": [state.to_dict() for state in states],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


def write_discovery_metrics(metrics: dict[str, object], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "metrics.json"
    path.write_text(json.dumps(metrics, indent=2, sort_keys=True))
    return path


def _blocker_totals(states: Sequence[CandidateState]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for state in states:
        for blocker in state.blockers:
            normalized = str(blocker).strip().lower().replace(" ", "_") or "unknown"
            totals[normalized] = totals.get(normalized, 0) + 1
    return dict(sorted(totals.items()))
