"""Execute one scheduled proof route without implicit backend fallback."""

from __future__ import annotations

import hashlib
import json
import resource
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from binary_agent.analysis.concolic import run_concolic_evidence_dir, run_native_exact_route
from binary_agent.data.proof_specs import load_proof_specs
from binary_agent.execution_envelope import (
    ExecutionEnvelope,
    route_capability,
    write_execution_envelope,
)
from binary_agent.pipeline import CandidateState, ProofResult
from binary_agent.proof import proof_results_from_replay
from binary_agent.replay import (
    ReplayPlan,
    ReplayResult,
    ReplayStatus,
    build_replay_plan,
    import_concolic_replay_results,
    run_replay_plan,
)
from binary_agent.scheduling import AttemptOutcome, ProofAttempt, ProofBudget, schedule_proofs
from binary_agent.service_reconstruction import reconstruct_process_recipes, write_process_recipes
from binary_agent.yield_model import RouteYieldEstimate


ROUTE_EXECUTION_STATUSES = frozenset(
    {"proven", "refuted", "inconclusive", "unsupported", "setup_error", "timeout"}
)


@dataclass(frozen=True)
class RouteExecutionContext:
    binary_path: Path
    export_dir: Path | None
    evidence_dir: Path
    output_dir: Path
    timeout_seconds: float = 30.0
    ghidra_dir: Path | None = None
    memory_limit_mb: int = 8192
    symbolic_bytes: int = 256
    ghidra_dynamic_max_steps: int = 20000
    execution_envelope: ExecutionEnvelope | None = None
    rootfs_path: Path | None = None


@dataclass(frozen=True)
class RouteExecutionResult:
    candidate_id: str
    route: str
    execution_family: str
    status: str
    duration_seconds: float
    cpu_seconds: float
    blocker: str
    artifact_paths: tuple[str, ...]
    proof_result: ProofResult
    profile: Mapping[str, Any]
    setup_key: str = ""
    setup_reused: bool = False
    variant_id: str = ""

    def __post_init__(self) -> None:
        if self.status not in ROUTE_EXECUTION_STATUSES:
            raise ValueError(f"invalid route execution status: {self.status}")
        if self.proof_result.candidate_id != self.candidate_id:
            raise ValueError("route result and proof result candidate ids differ")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "artifact_kind": "proof_route_execution",
            "candidate_id": self.candidate_id,
            "route": self.route,
            "execution_family": self.execution_family,
            "status": self.status,
            "duration_seconds": round(self.duration_seconds, 6),
            "cpu_seconds": round(self.cpu_seconds, 6),
            "blocker": self.blocker,
            "artifact_paths": list(self.artifact_paths),
            "artifact_hashes": [
                {"path": path, "sha256": _sha256_if_file(Path(path))}
                for path in self.artifact_paths
            ],
            "profile": dict(self.profile),
            "setup_key": self.setup_key,
            "setup_reused": self.setup_reused,
            "variant_id": self.variant_id,
            "proof_result": self.proof_result.to_dict(),
        }


class ProofRouteExecutor(Protocol):
    route: str
    execution_family: str

    def execute(
        self,
        state: CandidateState,
        attempt: ProofAttempt,
        context: RouteExecutionContext,
    ) -> RouteExecutionResult: ...


class ProofRouteRegistry:
    def __init__(self, executors: Mapping[str, ProofRouteExecutor]) -> None:
        self._executors = dict(executors)
        declared = {item.name for item in load_proof_specs().routes}
        if set(self._executors) != declared:
            raise ValueError(
                f"route executor mismatch: missing={sorted(declared - set(self._executors))}, "
                f"extra={sorted(set(self._executors) - declared)}"
            )

    @property
    def routes(self) -> tuple[str, ...]:
        return tuple(sorted(self._executors))

    def describe(self, route: str) -> Mapping[str, Any]:
        executor = self._executors[route]
        return {
            "route": route,
            "execution_family": executor.execution_family,
            "backend": getattr(executor, "backend", ""),
            "replay_mode": getattr(executor, "replay_mode", ""),
            "pcode_trace": bool(getattr(executor, "pcode_trace", False)),
            "ghidra_dynamic_proof": bool(getattr(executor, "ghidra_dynamic_proof", False)),
            "native_replay": False if isinstance(executor, _ConcolicExecutor) else None,
        }

    def execute(
        self,
        state: CandidateState,
        attempt: ProofAttempt,
        context: RouteExecutionContext,
    ) -> RouteExecutionResult:
        if attempt.candidate_id != state.candidate_id:
            raise ValueError("attempt candidate does not match route state")
        executor = self._executors.get(attempt.route)
        if executor is None:
            raise ValueError(f"no executor registered for route {attempt.route!r}")
        attempt_dir = Path(context.output_dir) / _safe_name(state.candidate_id) / f"rank-{attempt.rank}-{attempt.route}"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        scoped = replace(context, output_dir=attempt_dir)
        envelope_artifacts: tuple[str, ...] = ()
        capability = None
        if scoped.execution_envelope is not None:
            capability = route_capability(scoped.execution_envelope, attempt.route)
            envelope_path = write_execution_envelope(
                scoped.execution_envelope,
                attempt_dir / "execution_envelope.json",
            )
            envelope_artifacts = (str(envelope_path),)
            if not capability.viable:
                proof = _unsupported_proof(
                    state,
                    f"execution_envelope:{capability.reason}",
                )
                result = RouteExecutionResult(
                    candidate_id=state.candidate_id,
                    route=attempt.route,
                    execution_family=getattr(executor, "execution_family", "unknown"),
                    status="unsupported",
                    duration_seconds=0.0,
                    cpu_seconds=0.0,
                    blocker=capability.reason,
                    artifact_paths=envelope_artifacts,
                    proof_result=proof,
                    profile={
                        "execution_preflight": "rejected",
                        "capability_status": capability.status,
                        "capability_reason": capability.reason,
                    },
                    setup_key=capability.setup_key,
                    setup_reused=attempt.setup_reused,
                    variant_id=attempt.variant_id,
                )
                result_path = attempt_dir / "route_execution.json"
                _write_json(result_path, result.to_dict())
                return replace(
                    result,
                    artifact_paths=(*envelope_artifacts, str(result_path)),
                    proof_result=replace(
                        proof,
                        artifact_refs=tuple(dict.fromkeys([*proof.artifact_refs, *envelope_artifacts, str(result_path)])),
                    ),
                )
        started = time.monotonic()
        usage_started = resource.getrusage(resource.RUSAGE_CHILDREN)
        try:
            result = executor.execute(state, attempt, scoped)
        except Exception as exc:
            proof = _unsupported_proof(state, f"route_setup_error:{attempt.route}:{exc}")
            result = RouteExecutionResult(
                candidate_id=state.candidate_id,
                route=attempt.route,
                execution_family=getattr(executor, "execution_family", "unknown"),
                status="setup_error",
                duration_seconds=time.monotonic() - started,
                cpu_seconds=0.0,
                blocker=str(exc),
                artifact_paths=(),
                proof_result=proof,
                profile={"exception_type": type(exc).__name__},
                setup_key=capability.setup_key if capability else attempt.setup_key,
                setup_reused=attempt.setup_reused,
                variant_id=attempt.variant_id,
            )
        if result.route != attempt.route or result.execution_family != executor.execution_family:
            raise ValueError("route executor returned mismatched route or execution family")
        if result.duration_seconds <= 0:
            result = replace(result, duration_seconds=time.monotonic() - started)
        usage_finished = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu_seconds = max(
            0.0,
            usage_finished.ru_utime
            + usage_finished.ru_stime
            - usage_started.ru_utime
            - usage_started.ru_stime,
        )
        result = replace(
            result,
            cpu_seconds=cpu_seconds,
            setup_key=result.setup_key or (capability.setup_key if capability else attempt.setup_key),
            setup_reused=attempt.setup_reused,
            variant_id=attempt.variant_id,
        )
        result_path = attempt_dir / "route_execution.json"
        _write_json(result_path, result.to_dict())
        artifacts = tuple(dict.fromkeys([*envelope_artifacts, *result.artifact_paths, str(result_path)]))
        return replace(
            result,
            artifact_paths=artifacts,
            proof_result=replace(
                result.proof_result,
                artifact_refs=tuple(dict.fromkeys([*result.proof_result.artifact_refs, *envelope_artifacts, str(result_path)])),
            ),
        )


@dataclass(frozen=True)
class RouteOrchestrationResult:
    policy: str
    attempts: tuple[RouteExecutionResult, ...]
    history: tuple[AttemptOutcome, ...]
    stop_reason: str
    wall_seconds: float
    cpu_seconds: float
    unattempted_candidate_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "artifact_kind": "proof_route_orchestration",
            "policy": self.policy,
            "attempt_count": len(self.attempts),
            "attempts": [item.to_dict() for item in self.attempts],
            "history": [asdict(item) for item in self.history],
            "stop_reason": self.stop_reason,
            "wall_seconds": round(self.wall_seconds, 6),
            "cpu_seconds": round(self.cpu_seconds, 6),
            "unattempted_candidate_ids": list(self.unattempted_candidate_ids),
        }


def execute_route_orchestration(
    states: Sequence[CandidateState],
    *,
    context_for_state: Callable[[CandidateState], RouteExecutionContext],
    budget: ProofBudget,
    policy: str,
    registry: ProofRouteRegistry | None = None,
    policy_seed: str = "",
    route_yields: Mapping[str, Mapping[str, RouteYieldEstimate]] | None = None,
) -> RouteOrchestrationResult:
    """Schedule and execute one explicit route at a time with measured feedback."""

    selected_registry = registry or default_route_registry()
    eligible = [state for state in states if state.status == "proof_ready"]
    by_id = {state.candidate_id: state for state in eligible}
    contexts = {state.candidate_id: context_for_state(state) for state in eligible}
    route_capabilities = {
        candidate_id: {
            capability.route: capability
            for capability in context.execution_envelope.capabilities
        }
        for candidate_id, context in contexts.items()
        if context.execution_envelope is not None
    }
    max_attempts = budget.max_candidates or sum(
        len(load_proof_specs().get(state.vulnerability_type).routes) for state in eligible
    )
    history: list[AttemptOutcome] = []
    results: list[RouteExecutionResult] = []
    started = time.monotonic()
    used_cpu = 0.0
    warm_setup_keys: set[str] = set()
    stop_reason = "all_routes_exhausted_or_terminal"
    while len(results) < max_attempts:
        used_wall = time.monotonic() - started
        remaining_wall = max(0.0, budget.max_wall_seconds - used_wall) if budget.max_wall_seconds else 0.0
        remaining_cpu = max(0.0, budget.max_estimated_cpu_seconds - used_cpu) if budget.max_estimated_cpu_seconds else 0.0
        if budget.max_wall_seconds and remaining_wall <= 0:
            stop_reason = "actual_wall_budget_exhausted"
            break
        if budget.max_estimated_cpu_seconds and remaining_cpu <= 0:
            stop_reason = "actual_cpu_budget_exhausted"
            break
        schedule = schedule_proofs(
            eligible,
            plans=None,
            budget=ProofBudget(
                max_candidates=1,
                max_wall_seconds=remaining_wall,
                max_estimated_cpu_seconds=remaining_cpu,
            ),
            history=history,
            policy=policy,
            route_capabilities=route_capabilities,
            warm_setup_keys=frozenset(warm_setup_keys),
            policy_seed=policy_seed,
            route_yields=route_yields,
        )
        if not schedule.attempts:
            reasons = {item.reason for item in schedule.deferred}
            if "estimated_cpu_budget_exhausted" in reasons:
                stop_reason = "projected_cpu_budget_exhausted"
            elif "estimated_wall_budget_exhausted" in reasons:
                stop_reason = "projected_wall_budget_exhausted"
            break
        attempt = replace(schedule.attempts[0], rank=len(results) + 1)
        state = by_id[attempt.candidate_id]
        result = selected_registry.execute(state, attempt, contexts[state.candidate_id])
        results.append(result)
        used_cpu += result.cpu_seconds
        history.append(
            AttemptOutcome(
                candidate_id=result.candidate_id,
                route=result.route,
                outcome=result.status,
                duration_seconds=result.duration_seconds,
                cpu_seconds=result.cpu_seconds,
                blocker=result.blocker,
                capability_key=attempt.capability_key,
                setup_key=result.setup_key or attempt.setup_key,
                setup_reused=result.setup_reused,
                variant_id=attempt.variant_id,
            )
        )
        if result.setup_key and result.status not in {"unsupported", "setup_error"}:
            warm_setup_keys.add(result.setup_key)
    if len(results) >= max_attempts:
        stop_reason = "attempt_budget_exhausted"
    attempted_ids = {item.candidate_id for item in results}
    return RouteOrchestrationResult(
        policy=policy,
        attempts=tuple(results),
        history=tuple(history),
        stop_reason=stop_reason,
        wall_seconds=time.monotonic() - started,
        cpu_seconds=used_cpu,
        unattempted_candidate_ids=tuple(sorted(set(by_id) - attempted_ids)),
    )


@dataclass(frozen=True)
class _StaticExactExecutor:
    route: str = "static_exact"
    execution_family: str = "static"

    def execute(self, state: CandidateState, attempt: ProofAttempt, context: RouteExecutionContext) -> RouteExecutionResult:
        started = time.monotonic()
        proof = proof_results_from_replay([state], [])[0]
        return _result(state, attempt, self.execution_family, proof, started, (), {"dispatcher": "static_exact"})


@dataclass(frozen=True)
class _ReplayExecutor:
    route: str
    execution_family: str
    replay_mode: str

    def execute(self, state: CandidateState, attempt: ProofAttempt, context: RouteExecutionContext) -> RouteExecutionResult:
        started = time.monotonic()
        recipe_set = reconstruct_process_recipes(
            state,
            Path(context.binary_path),
            rootfs_path=context.rootfs_path,
        )
        recipe_path = write_process_recipes(recipe_set, Path(context.output_dir) / "process_recipes.json")
        plan = build_replay_plan(
            [state],
            binary_path=Path(context.binary_path),
            mode=self.replay_mode,
            evidence_dir=Path(context.evidence_dir),
            max_requests_per_candidate=1,
        )
        plan = ReplayPlan(
            tuple(
                replace(
                    entry,
                    request=replace(
                        entry.request,
                        setup={
                            **dict(entry.request.setup),
                            "timeout_seconds": max(0.1, float(context.timeout_seconds)),
                            **(
                                {"rootfs_path": str(context.rootfs_path)}
                                if self.replay_mode == "qemu_user" and context.rootfs_path
                                else {}
                            ),
                            **(
                                {"qemu_user_bin": context.execution_envelope.qemu_user_bin}
                                if self.replay_mode == "qemu_user"
                                and context.execution_envelope is not None
                                and context.execution_envelope.qemu_user_bin
                                else {}
                            ),
                            **(
                                {"process_recipes": [item.to_dict() for item in recipe_set.recipes]}
                                if self.replay_mode == "qemu_user"
                                else {}
                            ),
                            **({"qemu_exact_access": True} if self.replay_mode == "qemu_user" else {}),
                        },
                    ),
                )
                for entry in plan.entries
            )
        )
        plan_path = plan.write(Path(context.output_dir) / "replay_plan.json")
        selected = [entry for entry in plan.entries if entry.selected]
        if not selected:
            proof = _unsupported_proof(state, f"{self.route}_replay_plan_empty")
            return _result(
                state,
                attempt,
                self.execution_family,
                proof,
                started,
                (str(recipe_path), str(plan_path)),
                {"mode": self.replay_mode, "selected_requests": 0},
                status="unsupported",
            )
        blocked = [entry for entry in selected if entry.request.mode == "off"]
        if blocked and len(blocked) == len(selected):
            reason = next(
                (
                    str(entry.blocked_reason or entry.request.setup.get("blocked_reason") or "")
                    for entry in blocked
                    if entry.blocked_reason or entry.request.setup.get("blocked_reason")
                ),
                f"{self.route}_replay_plan_blocked",
            )
            proof = _unsupported_proof(state, reason)
            return _result(
                state,
                attempt,
                self.execution_family,
                proof,
                started,
                (str(recipe_path), str(plan_path)),
                {"mode": self.replay_mode, "selected_requests": len(selected), "preflight": "blocked"},
                status="unsupported",
                blocker=reason,
            )
        if any(entry.request.mode not in {self.replay_mode, "off"} for entry in selected):
            raise ValueError(f"route {self.route} produced a cross-family replay mode")
        if blocked:
            plan = ReplayPlan(tuple(entry for entry in plan.entries if entry.request.mode != "off"))
        replay_results = run_replay_plan(
            plan,
            Path(context.output_dir) / "replay",
            evidence_dir=Path(context.evidence_dir),
            repair_provider=None,
            repair_max_attempts=0,
        )
        proof = proof_results_from_replay([state], replay_results)[0]
        artifacts = tuple(
            dict.fromkeys([str(recipe_path), str(plan_path), *[path for item in replay_results for path in item.artifacts]])
        )
        status = _route_status_from_proof(proof)
        blocker = proof.blocker
        if status == "inconclusive":
            reasons = [
                str(item.control_result.get("blocker") or item.control_result.get("reason") or "")
                for item in replay_results
            ]
            reason = next((item for item in reasons if item), "")
            if "timeout" in reason.lower():
                status, blocker = "timeout", reason
            elif any(item.result in {"blocked", "setup_invalid"} for item in replay_results):
                status, blocker = "unsupported", reason or proof.blocker
        return _result(
            state,
            attempt,
            self.execution_family,
            proof,
            started,
            artifacts,
            {"mode": self.replay_mode, "selected_requests": len(selected)},
            status=status,
            blocker=blocker,
        )


@dataclass(frozen=True)
class _NativeExactExecutor:
    route: str
    execution_family: str = "native"
    replay_mode: str = "native"

    def execute(self, state: CandidateState, attempt: ProofAttempt, context: RouteExecutionContext) -> RouteExecutionResult:
        started = time.monotonic()
        evidence_path = Path(context.evidence_dir) / f"{state.candidate_id}.json"
        if not evidence_path.is_file():
            proof = _unsupported_proof(state, "native_route_evidence_pack_missing")
            return _result(
                state,
                attempt,
                self.execution_family,
                proof,
                started,
                (),
                {"mode": "native_exact", "gdb_trace": True},
                status="unsupported",
            )
        evidence = json.loads(evidence_path.read_text())
        if not isinstance(evidence, Mapping):
            raise ValueError("native route evidence pack must be an object")
        payload = run_native_exact_route(
            evidence,
            binary_path=Path(context.binary_path),
            export_dir=Path(context.export_dir) if context.export_dir else None,
            timeout_seconds=context.timeout_seconds,
            symbolic_bytes=context.symbolic_bytes,
        )
        payload_path = Path(context.output_dir) / "native_exact_route.json"
        _write_json(payload_path, payload)
        native = payload.get("native_replay") if isinstance(payload.get("native_replay"), Mapping) else {}
        trace = native.get("exact_operation_trace") if isinstance(native.get("exact_operation_trace"), Mapping) else {}
        exact = bool(trace.get("status") == "reached" and trace.get("operation_address"))
        memory = trace.get("memory_access") if isinstance(trace.get("memory_access"), Mapping) else {}
        lifetime = trace.get("lifetime_violation") if isinstance(trace.get("lifetime_violation"), Mapping) else {}
        bug = bool(memory.get("out_of_bounds") is True or lifetime.get("violation") is True)
        replay = ReplayResult(
            candidate_id=state.candidate_id,
            result=(
                ReplayStatus.CONFIRMED.value
                if bug
                else ReplayStatus.SINK_REACHED_NO_BUG.value
                if exact
                else ReplayStatus.BLOCKED.value
            ),
            mode="native_exact_operation",
            sink_reached=exact,
            bug_observed=bug,
            crash_observed=bool(native.get("crash_observed")),
            control_result={
                "backend": "native",
                "ghidra_dynamic_proof": dict(payload),
                "route": self.route,
            },
            artifacts=[str(payload_path)],
            artifact_refs=[{"kind": "native_exact_route", "path": str(payload_path)}],
        )
        proof = proof_results_from_replay([state], [replay])[0]
        status = _route_status_from_proof(proof)
        blocker = proof.blocker
        if not exact:
            reason = str(trace.get("reason") or native.get("reason") or payload.get("reason") or proof.blocker)
            status = "timeout" if "timeout" in reason.lower() else "unsupported" if "unsupported" in reason.lower() or "unavailable" in reason.lower() else "inconclusive"
            blocker = reason
        return _result(
            state,
            attempt,
            self.execution_family,
            proof,
            started,
            (str(payload_path),),
            {
                "mode": "native_exact",
                "gdb_trace": True,
                "resource_ledger": self.route == "native_ledger",
                "angr": False,
                "ghidra": False,
                "qemu": False,
            },
            status=status,
            blocker=blocker,
        )


@dataclass(frozen=True)
class _ConcolicExecutor:
    route: str
    execution_family: str
    backend: str
    pcode_trace: bool
    ghidra_dynamic_proof: bool

    def execute(self, state: CandidateState, attempt: ProofAttempt, context: RouteExecutionContext) -> RouteExecutionResult:
        started = time.monotonic()
        concolic_dir = Path(context.output_dir) / "concolic"
        run = run_concolic_evidence_dir(
            Path(context.evidence_dir),
            binary_path=Path(context.binary_path),
            output_dir=concolic_dir,
            export_dir=Path(context.export_dir) if context.export_dir else None,
            backend=self.backend,
            symbolic_bytes=max(1, int(context.symbolic_bytes)),
            timeout_seconds=max(0.1, float(context.timeout_seconds)),
            pcode_trace=self.pcode_trace,
            ghidra_dynamic_proof=self.ghidra_dynamic_proof,
            ghidra_dynamic_max_steps=int(context.ghidra_dynamic_max_steps),
            ghidra_dir=context.ghidra_dir,
            target_candidate_id=state.candidate_id,
            overwrite=True,
            continue_on_error=True,
            jobs=1,
            isolate_candidates=True,
            memory_limit_mb=max(0, int(context.memory_limit_mb)),
            native_replay=False,
        )
        replay_results = []
        if self.execution_family == "ghidra":
            replay_results = import_concolic_replay_results(
                concolic_dir,
                Path(context.output_dir) / "normalized_replay",
                candidate_ids={state.candidate_id},
                evidence_dir=Path(context.evidence_dir),
            )
            for replay in replay_results:
                if replay.mode not in {"ghidra_process", "ghidra_function_harness", "native_exact_operation"}:
                    raise ValueError(f"Ghidra route attempted cross-family replay mode {replay.mode!r}")
        proof = proof_results_from_replay([state], replay_results)[0]
        artifacts = tuple(str(path) for path in sorted(Path(context.output_dir).rglob("*")) if path.is_file())
        status = _route_status_from_proof(proof)
        blocker = proof.blocker
        if status == "inconclusive" and run.timed_out_count:
            status, blocker = "timeout", "concolic_route_timeout"
        elif status == "inconclusive" and run.error_count:
            status, blocker = "setup_error", next(iter(run.errors.values()), "concolic_route_error")
        return _result(
            state,
            attempt,
            self.execution_family,
            proof,
            started,
            artifacts,
            {
                "backend": self.backend,
                "pcode_trace": self.pcode_trace,
                "ghidra_dynamic_proof": self.ghidra_dynamic_proof,
                "native_replay": False,
                "qemu_replay": False,
            },
            status=status,
            blocker=blocker,
        )


def default_route_registry() -> ProofRouteRegistry:
    return ProofRouteRegistry(
        {
            "static_exact": _StaticExactExecutor(),
            "native_trace": _NativeExactExecutor("native_trace"),
            "native_ledger": _NativeExactExecutor("native_ledger"),
            "native_oracle": _ReplayExecutor("native_oracle", "native", "native"),
            "ghidra_call_trace": _ConcolicExecutor(
                "ghidra_call_trace", "ghidra", "deterministic_seed", False, True
            ),
            "ghidra_pcode": _ConcolicExecutor(
                "ghidra_pcode", "ghidra", "deterministic_seed", True, True
            ),
            "angr_concolic": _ConcolicExecutor(
                "angr_concolic", "angr", "angr", False, False
            ),
            "qemu_user": _ReplayExecutor("qemu_user", "qemu", "qemu_user"),
        }
    )


def _result(
    state: CandidateState,
    attempt: ProofAttempt,
    family: str,
    proof: ProofResult,
    started: float,
    artifacts: tuple[str, ...],
    profile: Mapping[str, Any],
    *,
    status: str | None = None,
    blocker: str | None = None,
) -> RouteExecutionResult:
    return RouteExecutionResult(
        candidate_id=state.candidate_id,
        route=attempt.route,
        execution_family=family,
        status=status or _route_status_from_proof(proof),
        duration_seconds=time.monotonic() - started,
        cpu_seconds=0.0,
        blocker=proof.blocker if blocker is None else blocker,
        artifact_paths=tuple(dict.fromkeys(artifacts)),
        proof_result=replace(proof, artifact_refs=tuple(dict.fromkeys([*proof.artifact_refs, *artifacts]))),
        profile=dict(profile),
        setup_key=attempt.setup_key,
        setup_reused=attempt.setup_reused,
        variant_id=attempt.variant_id,
    )


def _route_status_from_proof(proof: ProofResult) -> str:
    return proof.status if proof.status in {"proven", "refuted", "unsupported"} else "inconclusive"


def _unsupported_proof(state: CandidateState, blocker: str) -> ProofResult:
    base = proof_results_from_replay([state], [])[0]
    return replace(base, status="unsupported", blocker=blocker)


def _sha256_if_file(path: Path) -> str:
    if not path.is_file():
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)[:160]


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
