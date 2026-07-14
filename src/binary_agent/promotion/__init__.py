"""Promotion gates for proof-gated vulnerability states."""

from .gates import (
    apply_replay_results,
    candidate_needs_exact_memory_operation,
    integrate_concolic_results,
    promote_for_replay,
    promote_for_report,
    promote_proof_ready,
    promote_with_proof_results,
    write_promotion_artifacts,
)

__all__ = [
    "candidate_needs_exact_memory_operation",
    "integrate_concolic_results",
    "apply_replay_results",
    "promote_for_replay",
    "promote_for_report",
    "promote_proof_ready",
    "promote_with_proof_results",
    "write_promotion_artifacts",
]
