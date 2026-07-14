from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from binary_agent.pipeline import CandidateState
from binary_agent.execution_envelope import RouteCapability, discover_execution_envelope
from binary_agent.proof import proof_results_from_replay
from binary_agent.proof_routing import (
    ProofRouteRegistry,
    RouteExecutionContext,
    RouteExecutionResult,
    default_route_registry,
    execute_route_orchestration,
)
from binary_agent.scheduling import ProofAttempt, ProofBudget
from binary_agent.taxonomy import VULNERABILITY_SPECS


def _state(candidate_id: str, *, high: bool = False) -> CandidateState:
    spec = VULNERABILITY_SPECS["uninitialized_memory_use"]
    facts = {
        "definedness": "undefined",
        "prior_store": False,
        "undefined_byte_ranges": [[0, 1]],
    }
    if high:
        facts.update(
            {
                "entrypoint_derivation": {"status": "derived"},
                "process_input": {"input_model": "argv"},
            }
        )
    return CandidateState(
        candidate_id=candidate_id,
        backend=spec.backend,
        vulnerability_type="uninitialized_memory_use",
        mechanism=spec.mechanism,
        status="proof_ready",
        target={"path": "/tmp/fixture"},
        location={"function_name": "main", "address": "0x1000"},
        source={"kind": "definedness"},
        sink={"name": "pcode_load", "operation_address": "0x1010"},
        operation={"name": "pcode_load", "address": "0x1010"},
        affected_object={"identity": "stack:value"},
        type_facts=facts,
        proof_obligations=[],
        blockers=[],
    )


class _FakeExecutor:
    def __init__(self, route: str, log: list[tuple[str, str]]) -> None:
        self.route = route
        self.execution_family = f"family:{route}"
        self.log = log

    def execute(self, state, attempt, context):
        self.log.append((state.candidate_id, attempt.route))
        proof = proof_results_from_replay([state], [])[0]
        return RouteExecutionResult(
            candidate_id=state.candidate_id,
            route=attempt.route,
            execution_family=self.execution_family,
            status="inconclusive",
            duration_seconds=0.01,
            cpu_seconds=0.0,
            blocker=proof.blocker,
            artifact_paths=(),
            proof_result=proof,
            profile={"fake": True},
        )


def test_default_route_profiles_are_backend_isolated() -> None:
    registry = default_route_registry()
    assert registry.describe("angr_concolic") == {
        "route": "angr_concolic",
        "execution_family": "angr",
        "backend": "angr",
        "replay_mode": "",
        "pcode_trace": False,
        "ghidra_dynamic_proof": False,
        "native_replay": False,
    }
    ghidra = registry.describe("ghidra_pcode")
    assert ghidra["backend"] == "deterministic_seed"
    assert ghidra["pcode_trace"] is True
    assert ghidra["ghidra_dynamic_proof"] is True
    assert ghidra["native_replay"] is False
    assert registry.describe("native_trace")["replay_mode"] == "native"
    assert registry.describe("qemu_user")["replay_mode"] == "qemu_user"


def test_concolic_routes_pass_isolated_flags(monkeypatch, tmp_path: Path) -> None:
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(timed_out_count=0, error_count=0, errors={})

    monkeypatch.setattr("binary_agent.proof_routing.run_concolic_evidence_dir", fake_run)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    context = RouteExecutionContext(tmp_path / "binary", tmp_path / "export", evidence, tmp_path / "out")
    state = _state("candidate")
    registry = default_route_registry()
    for rank, route in enumerate(("angr_concolic", "ghidra_pcode", "ghidra_call_trace"), start=1):
        attempt = ProofAttempt(state.candidate_id, state.vulnerability_type, route, rank, 1.0, 1.0, ())
        registry.execute(state, attempt, context)
    assert calls[0]["backend"] == "angr"
    assert calls[0]["ghidra_dynamic_proof"] is False
    assert calls[0]["native_replay"] is False
    assert calls[1]["backend"] == "deterministic_seed"
    assert calls[1]["pcode_trace"] is True
    assert calls[1]["native_replay"] is False
    assert calls[2]["backend"] == "deterministic_seed"
    assert calls[2]["pcode_trace"] is False


def test_iterative_orchestrator_chooses_distinct_candidates_before_retry(tmp_path: Path) -> None:
    log: list[tuple[str, str]] = []
    declared = default_route_registry().routes
    registry = ProofRouteRegistry({route: _FakeExecutor(route, log) for route in declared})
    states = [_state("low-a"), _state("low-b"), _state("high", high=True)]
    result = execute_route_orchestration(
        states,
        context_for_state=lambda _state: RouteExecutionContext(
            tmp_path / "binary", None, tmp_path, tmp_path / "attempts"
        ),
        budget=ProofBudget(max_candidates=3, max_wall_seconds=30, max_estimated_cpu_seconds=30),
        policy="adaptive",
        registry=registry,
    )
    assert [item.candidate_id for item in result.attempts] == ["high", "low-a", "low-b"]
    assert len({item.candidate_id for item in result.attempts}) == 3
    assert result.stop_reason == "attempt_budget_exhausted"


def test_static_route_uses_schema_v2_dispatch_without_process_execution(tmp_path: Path) -> None:
    spec = VULNERABILITY_SPECS["weak_cryptography"]
    state = CandidateState(
        candidate_id="static",
        backend=spec.backend,
        vulnerability_type="weak_cryptography",
        mechanism=spec.mechanism,
        status="proof_ready",
        target={"path": "/does/not/run"},
        location={"function_name": "main", "address": "0x1000"},
        source={"kind": "literal"},
        sink={"name": "MD5", "operation_address": "0x1010"},
        operation={"name": "MD5", "address": "0x1010"},
        affected_object={},
        type_facts={"exact_call": "MD5", "reachable": True},
        proof_obligations=[],
        blockers=[],
    )
    attempt = ProofAttempt("static", "weak_cryptography", "static_exact", 1, 1.0, 0.05, ())
    result = default_route_registry().execute(
        state,
        attempt,
        RouteExecutionContext(tmp_path / "missing", None, tmp_path, tmp_path / "out"),
    )
    assert result.status == "proven"
    assert result.proof_result.status == "proven"
    assert result.execution_family == "static"


def test_execution_envelope_preflight_rejects_without_calling_executor(tmp_path: Path) -> None:
    binary = tmp_path / "binary"
    binary.write_bytes(Path("/bin/true").read_bytes())
    envelope = discover_execution_envelope(binary)
    capabilities = tuple(
        RouteCapability(
            item.route,
            "unsupported" if item.route == "native_trace" else item.status,
            "fixture_runtime_missing" if item.route == "native_trace" else item.reason,
            item.setup_key,
            item.setup_seconds,
            item.marginal_seconds,
        )
        for item in envelope.capabilities
    )
    envelope = replace(envelope, capabilities=capabilities)
    log: list[tuple[str, str]] = []
    declared = default_route_registry().routes
    registry = ProofRouteRegistry({route: _FakeExecutor(route, log) for route in declared})
    state = _state("candidate")
    attempt = ProofAttempt(state.candidate_id, state.vulnerability_type, "native_trace", 1, 1.0, 1.0, ())
    result = registry.execute(
        state,
        attempt,
        RouteExecutionContext(binary, None, tmp_path, tmp_path / "out", execution_envelope=envelope),
    )
    assert result.status == "unsupported"
    assert result.blocker == "fixture_runtime_missing"
    assert log == []
    assert any(path.endswith("execution_envelope.json") for path in result.artifact_paths)
