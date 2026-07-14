"""Deterministic proof scheduling under a global research compute budget."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.data.proof_specs import CompiledProofPlan, compile_proof_plan
from binary_agent.execution_envelope import RouteCapability
from binary_agent.pipeline import CandidateState
from binary_agent.yield_model import RouteYieldEstimate


SCHEDULER_POLICIES = frozenset(
    {"adaptive", "learned_adaptive", "exhaustive", "fifo", "static_rank", "fixed_route", "random"}
)
TERMINAL_OUTCOMES = frozenset({"proven", "refuted"})
FAILED_ROUTE_OUTCOMES = frozenset({"unsupported", "setup_error"})
NO_BUG_OUTCOMES = frozenset({"no_bug", "sink_reached_no_bug", "not_observed"})


@dataclass(frozen=True)
class ProofBudget:
    max_candidates: int = 32
    max_wall_seconds: float = 1800.0
    max_estimated_cpu_seconds: float = 1800.0

    def __post_init__(self) -> None:
        if self.max_candidates < 0 or self.max_wall_seconds < 0 or self.max_estimated_cpu_seconds < 0:
            raise ValueError("proof budgets must be non-negative")


@dataclass(frozen=True)
class AttemptOutcome:
    candidate_id: str
    route: str
    outcome: str
    duration_seconds: float = 0.0
    cpu_seconds: float = 0.0
    blocker: str = ""
    capability_key: str = ""
    setup_key: str = ""
    setup_reused: bool = False
    variant_id: str = ""


@dataclass(frozen=True)
class ProofAttempt:
    candidate_id: str
    vulnerability_type: str
    route: str
    rank: int
    score: float
    estimated_seconds: float
    reasons: tuple[str, ...]
    capability_key: str = ""
    setup_key: str = ""
    estimated_setup_seconds: float = 0.0
    estimated_marginal_seconds: float = 0.0
    setup_reused: bool = False
    variant_id: str = ""


@dataclass(frozen=True)
class DeferredCandidate:
    candidate_id: str
    vulnerability_type: str
    score: float
    reason: str


@dataclass(frozen=True)
class ProofSchedule:
    policy: str
    budget: ProofBudget
    attempts: tuple[ProofAttempt, ...]
    deferred: tuple[DeferredCandidate, ...]
    estimated_cpu_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "artifact_kind": "proof_schedule",
            "policy": self.policy,
            "budget": asdict(self.budget),
            "attempts": [asdict(item) for item in self.attempts],
            "deferred": [asdict(item) for item in self.deferred],
            "estimated_cpu_seconds": round(self.estimated_cpu_seconds, 6),
            "selected_candidates": len(self.attempts),
            "deferred_candidates": len(self.deferred),
        }


def load_proof_schedule(path_or_payload: Path | str | Mapping[str, Any]) -> ProofSchedule:
    """Load schedule schemas v1/v2; legacy attempts use the empty variant."""

    if isinstance(path_or_payload, Mapping):
        payload = dict(path_or_payload)
    else:
        payload = json.loads(Path(path_or_payload).read_text())
    if not isinstance(payload, Mapping):
        raise ValueError("proof schedule must be a JSON object")
    schema_version = int(payload.get("schema_version") or 0)
    if schema_version not in {1, 2}:
        raise ValueError(f"unsupported proof schedule schema:{schema_version or 'missing'}")
    raw_budget = payload.get("budget") if isinstance(payload.get("budget"), Mapping) else {}
    budget = ProofBudget(
        max_candidates=int(raw_budget.get("max_candidates") or 0),
        max_wall_seconds=float(raw_budget.get("max_wall_seconds") or 0.0),
        max_estimated_cpu_seconds=float(raw_budget.get("max_estimated_cpu_seconds") or 0.0),
    )
    attempts: list[ProofAttempt] = []
    for raw in payload.get("attempts", []) or []:
        if not isinstance(raw, Mapping):
            raise ValueError("proof schedule attempt must be an object")
        attempts.append(
            ProofAttempt(
                candidate_id=str(raw.get("candidate_id") or ""),
                vulnerability_type=str(raw.get("vulnerability_type") or ""),
                route=str(raw.get("route") or ""),
                rank=int(raw.get("rank") or 0),
                score=float(raw.get("score") or 0.0),
                estimated_seconds=float(raw.get("estimated_seconds") or 0.0),
                reasons=tuple(str(item) for item in raw.get("reasons", []) or []),
                capability_key=str(raw.get("capability_key") or ""),
                setup_key=str(raw.get("setup_key") or ""),
                estimated_setup_seconds=float(raw.get("estimated_setup_seconds") or 0.0),
                estimated_marginal_seconds=float(raw.get("estimated_marginal_seconds") or 0.0),
                setup_reused=bool(raw.get("setup_reused")),
                variant_id=str(raw.get("variant_id") or "") if schema_version >= 2 else "",
            )
        )
    deferred: list[DeferredCandidate] = []
    for raw in payload.get("deferred", []) or []:
        if not isinstance(raw, Mapping):
            raise ValueError("proof schedule deferred row must be an object")
        deferred.append(
            DeferredCandidate(
                candidate_id=str(raw.get("candidate_id") or ""),
                vulnerability_type=str(raw.get("vulnerability_type") or ""),
                score=float(raw.get("score") or 0.0),
                reason=str(raw.get("reason") or ""),
            )
        )
    return ProofSchedule(
        policy=str(payload.get("policy") or "adaptive"),
        budget=budget,
        attempts=tuple(attempts),
        deferred=tuple(deferred),
        estimated_cpu_seconds=float(payload.get("estimated_cpu_seconds") or 0.0),
    )


def schedule_proofs(
    states: Sequence[CandidateState],
    plans: Mapping[str, CompiledProofPlan] | None,
    budget: ProofBudget,
    history: Sequence[AttemptOutcome] = (),
    policy: str = "adaptive",
    route_capabilities: Mapping[str, Mapping[str, RouteCapability]] | None = None,
    warm_setup_keys: frozenset[str] = frozenset(),
    policy_seed: str = "",
    route_yields: Mapping[str, Mapping[str, RouteYieldEstimate]] | None = None,
    variant_ids: Mapping[str, Sequence[str]] | None = None,
    variant_features: Mapping[str, Mapping[str, Mapping[str, Any]]] | None = None,
) -> ProofSchedule:
    """Rank eligible candidates and allocate one unfailed route to each."""

    if policy not in SCHEDULER_POLICIES:
        raise ValueError(f"unsupported scheduler policy: {policy!r}")
    compiled = dict(plans or {})
    terminal_ids = {item.candidate_id for item in history if item.outcome in TERMINAL_OUTCOMES}
    attempted_routes = {
        (item.candidate_id, item.route, item.variant_id): item.outcome for item in history
    }
    global_failures: dict[tuple[str, str], int] = {}
    for item in history:
        if item.outcome in FAILED_ROUTE_OUTCOMES:
            key = (item.route, item.capability_key or item.setup_key or "legacy_global")
            global_failures[key] = global_failures.get(key, 0) + 1
    capabilities = route_capabilities or {}
    yields = route_yields or {}
    variants = variant_ids or {}
    features = variant_features or {}
    ranked: list[tuple[int, float, int, CandidateState, tuple[str, ...]]] = []
    deferred: list[DeferredCandidate] = []
    for input_rank, state in enumerate(states):
        if state.status not in {"proof_ready", "candidate", "needs_refinement"}:
            deferred.append(DeferredCandidate(state.candidate_id, state.vulnerability_type, 0.0, f"ineligible_status:{state.status}"))
            continue
        if state.candidate_id in terminal_ids:
            deferred.append(DeferredCandidate(state.candidate_id, state.vulnerability_type, 0.0, "terminal_outcome_already_recorded"))
            continue
        score, reasons = _candidate_score(state, policy, seed=policy_seed)
        prior_attempts = sum(item.candidate_id == state.candidate_id for item in history)
        if prior_attempts:
            reasons = (*reasons, f"prior_route_attempts:{prior_attempts}")
        plan = compiled.get(state.candidate_id) or compile_proof_plan(state)
        ranking_score = _portfolio_ranking_score(
            score,
            state,
            plan,
            history,
            capabilities.get(state.candidate_id, {}),
            warm_setup_keys,
            policy,
            yields.get(state.candidate_id, {}),
            tuple(str(item) for item in variants.get(state.candidate_id, ("",))) or ("",),
        )
        ranked.append((prior_attempts, ranking_score, input_rank, state, reasons))
    ranked.sort(
        key=lambda item: (
            item[0],
            -item[1],
            item[2] if policy == "fifo" else item[3].candidate_id,
        )
    )

    attempts: list[ProofAttempt] = []
    estimated = 0.0
    for _prior_attempts, ranking_score, _input_rank, state, reasons in ranked:
        score, _unused = _candidate_score(state, policy, seed=policy_seed)
        plan = compiled.get(state.candidate_id) or compile_proof_plan(state)
        candidate_capabilities = capabilities.get(state.candidate_id, {})
        candidate_variants = tuple(str(item) for item in variants.get(state.candidate_id, ("",))) or ("",)
        candidate_variants = _rank_variants(
            candidate_variants,
            features.get(state.candidate_id, {}),
            policy=policy,
            seed=policy_seed,
        )
        variant_id = ""
        routes = []
        for candidate_variant in candidate_variants:
            candidate_routes = _available_routes(
                plan,
                state.candidate_id,
                candidate_variant,
                attempted_routes,
                global_failures,
                policy,
                candidate_capabilities,
            )
            if candidate_routes:
                variant_id = candidate_variant
                routes = candidate_routes
                break
        if policy == "learned_adaptive":
            candidate_yields = yields.get(state.candidate_id, {})
            routes = sorted(
                routes,
                key=lambda route: (
                    -float(candidate_yields[route.name].report_probability) if route.name in candidate_yields else -0.5,
                    route.estimated_seconds,
                    route.name,
                ),
            )
        if not routes:
            deferred.append(DeferredCandidate(state.candidate_id, state.vulnerability_type, score, "all_routes_exhausted_or_suppressed"))
            continue
        if budget.max_candidates and len(attempts) >= budget.max_candidates:
            deferred.append(DeferredCandidate(state.candidate_id, state.vulnerability_type, score, "candidate_budget_exhausted"))
            continue
        selected_route = None
        selected_estimate = 0.0
        selected_capability: RouteCapability | None = None
        failed_cpu_budget = False
        failed_wall_budget = False
        for route in routes:
            capability = candidate_capabilities.get(route.name)
            route_estimate, setup_estimate, marginal_estimate, setup_reused = _route_estimate(
                route.name,
                route.estimated_seconds,
                history,
                capability,
                warm_setup_keys,
            )
            if policy != "exhaustive":
                route_estimate *= _blocker_cost_multiplier(state)
            if budget.max_estimated_cpu_seconds and estimated + route_estimate > budget.max_estimated_cpu_seconds:
                failed_cpu_budget = True
                continue
            if budget.max_wall_seconds and estimated + route_estimate > budget.max_wall_seconds:
                failed_wall_budget = True
                continue
            selected_route, selected_estimate, selected_capability = route, route_estimate, capability
            break
        if selected_route is None:
            reason = "estimated_cpu_budget_exhausted" if failed_cpu_budget else "estimated_wall_budget_exhausted" if failed_wall_budget else "all_routes_exhausted_or_suppressed"
            deferred.append(DeferredCandidate(state.candidate_id, state.vulnerability_type, score, reason))
            continue
        route = selected_route
        route_estimate = selected_estimate
        setup_key = selected_capability.setup_key if selected_capability else ""
        setup_reused = bool(setup_key and setup_key in warm_setup_keys)
        setup_estimate = 0.0 if setup_reused else float(selected_capability.setup_seconds if selected_capability else 0.0)
        marginal_estimate = float(selected_capability.marginal_seconds if selected_capability else route_estimate)
        attempts.append(
            ProofAttempt(
                candidate_id=state.candidate_id,
                vulnerability_type=state.vulnerability_type,
                route=route.name,
                rank=len(attempts) + 1,
                score=round(score, 6),
                estimated_seconds=round(route_estimate, 6),
                reasons=(*reasons, f"portfolio_rank:{ranking_score:.6f}"),
                capability_key=setup_key or f"{route.name}:unscoped",
                setup_key=setup_key,
                estimated_setup_seconds=round(setup_estimate, 6),
                estimated_marginal_seconds=round(marginal_estimate, 6),
                setup_reused=setup_reused,
                variant_id=variant_id,
            )
        )
        estimated += route_estimate
    return ProofSchedule(
        policy=policy,
        budget=budget,
        attempts=tuple(attempts),
        deferred=tuple(sorted(deferred, key=lambda item: (item.reason, item.candidate_id))),
        estimated_cpu_seconds=estimated,
    )


def _candidate_score(state: CandidateState, policy: str, *, seed: str = "") -> tuple[float, tuple[str, ...]]:
    if policy in {"exhaustive", "fixed_route", "fifo"}:
        return 0.0, (f"{policy}_candidate_order",)
    if policy == "random":
        digest = hashlib.sha256(f"{seed}\0{state.candidate_id}".encode()).digest()
        return int.from_bytes(digest[:8], "big") / float(2**64), ("deterministic_seeded_random",)
    score = 0.0
    reasons: list[str] = []

    def add(value: float, reason: str) -> None:
        nonlocal score
        score += value
        reasons.append(f"{reason}:{value:+g}")

    if state.status == "proof_ready":
        add(5.0, "proof_ready")
    operation_address = str(state.operation.get("address") or state.sink.get("operation_address") or "")
    function_address = str(state.location.get("address") or "")
    if operation_address and operation_address.lower() != function_address.lower():
        add(4.0, "exact_operation")
    trace = state.type_facts.get("source_to_sink_trace")
    if isinstance(trace, Mapping) and trace.get("status") in {"complete", "proven"}:
        add(3.0, "complete_source_to_sink")
    entrypoint = state.type_facts.get("entrypoint_derivation")
    if isinstance(entrypoint, Mapping) and entrypoint.get("status") == "derived":
        add(2.0, "derived_entrypoint")
    process = state.type_facts.get("process_input")
    if isinstance(process, Mapping) and process.get("input_model"):
        add(2.0, "concrete_process_model")
    if state.affected_object.get("capacity_bytes") not in {None, "", 0, "0"}:
        add(1.5, "known_object_capacity")
    if state.type_facts.get("same_resource") is True or state.type_facts.get("resource_generation"):
        add(1.5, "resource_identity")
    severity = {"critical": 2.0, "high": 1.5, "medium": 0.5, "low": 0.0}.get(
        str(state.metadata.get("severity") or ""), 0.0
    )
    if severity:
        add(severity, "severity")
    if state.blockers:
        add(-0.75 * len(state.blockers), "blockers")
    if any(any(token in str(blocker).lower() for token in ("unsupported", "unresolved", "missing")) for blocker in state.blockers):
        add(-4.0, "hard_blocker")
    return score, tuple(reasons)


def _rank_variants(
    variant_ids: Sequence[str],
    features: Mapping[str, Mapping[str, Any]],
    *,
    policy: str,
    seed: str,
) -> tuple[str, ...]:
    """Order variants from static/online features without ground-truth labels."""

    unique = tuple(dict.fromkeys(str(item) for item in variant_ids))
    if policy in {"exhaustive", "fifo", "fixed_route"}:
        return unique
    if policy == "random":
        return tuple(
            sorted(
                unique,
                key=lambda item: hashlib.sha256(f"{seed}\0{item}".encode()).digest(),
            )
        )

    def utility(variant_id: str) -> float:
        row = features.get(variant_id, {})
        distance = row.get("callback_distance")
        proximity = 0.0
        if distance not in {None, ""}:
            try:
                numeric_distance = int(distance)
            except (TypeError, ValueError):
                numeric_distance = -1
            if numeric_distance >= 0:
                proximity = 4.0 / (1.0 + numeric_distance)
        schema_fields = max(0, int(row.get("schema_field_count") or 0))
        complexity = 2.0 / (1.0 + schema_fields)
        reuse = 2.0 if row.get("setup_reused") else 0.0
        observed = max(0, int(row.get("prior_observed_reaches") or 0)) if policy in {"adaptive", "learned_adaptive"} else 0
        cost = max(0.05, float(row.get("estimated_marginal_seconds") or 1.0))
        return (proximity + complexity + reuse + min(4.0, 1.5 * observed)) / cost

    return tuple(sorted(unique, key=lambda item: (-utility(item), item)))


def _available_routes(
    plan: CompiledProofPlan,
    candidate_id: str,
    variant_id: str,
    attempted_routes: Mapping[tuple[str, str, str], str],
    global_failures: Mapping[tuple[str, str], int],
    policy: str,
    capabilities: Mapping[str, RouteCapability],
):
    if any(
        candidate == candidate_id
        and candidate_variant == variant_id
        and outcome in NO_BUG_OUTCOMES
        for (candidate, _route, candidate_variant), outcome in attempted_routes.items()
    ):
        return []
    available = []
    for route in plan.routes:
        if (candidate_id, route.name, variant_id) in attempted_routes:
            continue
        capability = capabilities.get(route.name)
        if capability is not None and not capability.viable:
            continue
        capability_key = capability.setup_key if capability else "legacy_global"
        if policy in {"adaptive", "learned_adaptive"} and global_failures.get((route.name, capability_key), 0) >= 2:
            continue
        available.append(route)
    return available


def _blocker_cost_multiplier(state: CandidateState) -> float:
    return min(2.0, 1.0 + 0.1 * len(state.blockers))


def _measured_route_estimate(
    route: str,
    configured_seconds: float,
    history: Sequence[AttemptOutcome],
) -> float:
    observed = sorted(
        max(float(item.duration_seconds or 0.0), float(item.cpu_seconds or 0.0))
        for item in history
        if item.route == route and max(float(item.duration_seconds or 0.0), float(item.cpu_seconds or 0.0)) > 0
    )
    if not observed:
        return configured_seconds
    middle = len(observed) // 2
    median = observed[middle] if len(observed) % 2 else (observed[middle - 1] + observed[middle]) / 2.0
    return max(configured_seconds, median)


def _route_estimate(
    route: str,
    configured_seconds: float,
    history: Sequence[AttemptOutcome],
    capability: RouteCapability | None,
    warm_setup_keys: frozenset[str],
) -> tuple[float, float, float, bool]:
    if capability is None:
        measured = _measured_route_estimate(route, configured_seconds, history)
        return measured, 0.0, measured, False
    reused = bool(capability.setup_key and capability.setup_key in warm_setup_keys)
    setup = 0.0 if reused else capability.setup_seconds
    measured = _measured_route_estimate(route, capability.marginal_seconds, history)
    return setup + measured, setup, measured, reused


def _portfolio_ranking_score(
    evidence_score: float,
    state: CandidateState,
    plan: CompiledProofPlan,
    history: Sequence[AttemptOutcome],
    capabilities: Mapping[str, RouteCapability],
    warm_setup_keys: frozenset[str],
    policy: str,
    route_yields: Mapping[str, RouteYieldEstimate],
    variant_ids: Sequence[str] = ("",),
) -> float:
    if policy not in {"adaptive", "learned_adaptive"}:
        return evidence_score
    attempted = {(item.candidate_id, item.route, item.variant_id) for item in history}
    utilities = []
    for route in plan.routes:
        if all((state.candidate_id, route.name, variant_id) in attempted for variant_id in variant_ids):
            continue
        capability = capabilities.get(route.name)
        if capability is not None and not capability.viable:
            continue
        estimate, _setup, _marginal, _reused = _route_estimate(
            route.name,
            route.estimated_seconds,
            history,
            capability,
            warm_setup_keys,
        )
        probability = (
            float(route_yields[route.name].report_probability)
            if policy == "learned_adaptive" and route.name in route_yields
            else 1.0
        )
        utilities.append(evidence_score * probability / max(0.05, estimate))
    if not utilities:
        return -1_000_000.0
    return max(utilities)
