"""Taxonomy-driven proof dispatch and the common report gate."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.pipeline import CandidateState, ProofResult
from binary_agent.replay.models import ReplayResult, ReplayStatus
from binary_agent.taxonomy import get_vulnerability_spec


def dispatch_proof(state: CandidateState, evidence: Mapping[str, Any]) -> ProofResult:
    """Validate backend evidence according to the candidate's sole proof policy."""

    spec = get_vulnerability_spec(state.vulnerability_type)
    if state.backend != spec.backend:
        return _unsupported(state, f"candidate_backend_mismatch:{state.backend}:{spec.backend}")
    dispatcher = {
        "memory_access": _memory_access_proof,
        "memory_lifetime": _memory_lifetime_proof,
        "semantic_effect": _semantic_effect_proof,
        "static_evidence": _static_evidence_proof,
    }[spec.proof_policy]
    return dispatcher(state, evidence)


def proof_result_reportable(state: CandidateState, result: ProofResult) -> bool:
    """Apply the one fail-closed report gate shared by every renderer."""

    spec = get_vulnerability_spec(state.vulnerability_type)
    if result.candidate_id != state.candidate_id or result.backend != spec.backend:
        return False
    if result.status != "proven":
        return False
    if spec.backend == "memory_access":
        return result.exact_operation_reached and _memory_payload_proves(state, result.memory_access)
    if spec.backend == "memory_lifetime":
        return result.exact_operation_reached and _lifetime_payload_proves(state, result.lifetime_violation)
    if spec.backend == "semantic_effect":
        return bool(
            result.scope == "process_entrypoint"
            and result.exact_operation_reached
            and result.process_setup.get("status") == "configured"
            and result.native_replay.get("status") in {"reached", "observed"}
            and result.effect_observation.get("status") == "observed"
            and result.effect_observation.get("kind") == spec.effect_kind
            and result.concrete_input
        )
    return bool(
        spec.backend == "static_evidence"
        and result.scope == "static"
        and result.exact_operation_reached
        and result.static_evidence.get("exact") is True
        and result.static_evidence.get("reachable") is True
    )


def render_backend_finding(state: CandidateState, result: ProofResult) -> dict[str, Any]:
    """Render one schema-v2 report row after the common gate succeeds."""

    if not proof_result_reportable(state, result):
        raise ValueError(f"Candidate {state.candidate_id} does not satisfy its report gate")
    spec = get_vulnerability_spec(state.vulnerability_type)
    return {
        "schema_version": 2,
        "candidate_id": state.candidate_id,
        "backend": state.backend,
        "vulnerability_type": state.vulnerability_type,
        "mechanism": state.mechanism,
        "effect_kind": spec.effect_kind,
        "cwe_ids": list(spec.cwe_ids),
        "severity": spec.default_severity,
        "target": dict(state.target),
        "location": dict(state.location),
        "operation": dict(state.operation),
        "affected_object": dict(state.affected_object),
        "root_causes": list(state.root_causes),
        "proof": result.to_dict(),
    }


def proof_metrics(results: list[ProofResult] | tuple[ProofResult, ...]) -> dict[str, Any]:
    outcomes: dict[str, int] = {}
    blockers: dict[str, int] = {}
    by_backend: dict[str, int] = {}
    for result in results:
        outcomes[result.status] = outcomes.get(result.status, 0) + 1
        by_backend[result.backend] = by_backend.get(result.backend, 0) + 1
        if result.blocker:
            blockers[result.blocker] = blockers.get(result.blocker, 0) + 1
    return {
        "schema_version": 2,
        "proof_attempts": len(results),
        "proof_outcomes": dict(sorted(outcomes.items())),
        "proof_attempts_by_backend": dict(sorted(by_backend.items())),
        "normalized_blocker_totals": dict(sorted(blockers.items())),
    }


def proof_results_from_replay(
    states: Sequence[CandidateState],
    replay_results: Sequence[ReplayResult],
) -> list[ProofResult]:
    """Normalize concrete replay artifacts and dispatch one v2 result per candidate.

    The concolic and Ghidra engines have detailed internal artifacts whose
    schemas are intentionally private to those engines.  This boundary keeps
    them from becoming report policy: only normalized evidence is passed to
    the taxonomy dispatcher.
    """

    replay_by_id = {result.candidate_id: result for result in replay_results}
    results: list[ProofResult] = []
    for state in states:
        replay = replay_by_id.get(state.candidate_id)
        evidence = _normalized_replay_evidence(state, replay)
        results.append(dispatch_proof(state, evidence))
    return results


def _memory_access_proof(state: CandidateState, evidence: Mapping[str, Any]) -> ProofResult:
    exact = _exact_operation(state, evidence)
    payload = _mapping(evidence.get("memory_access"))
    if evidence.get("unsupported"):
        return _unsupported(state, str(evidence.get("blocker") or "unsupported_memory_semantics"))
    if not exact:
        return _inconclusive(state, "exact_operation_not_reached", scope=_scope(evidence))
    if not _memory_payload_proves(state, payload):
        if payload.get("safe") is True:
            return _result(state, "refuted", _scope(evidence), True, memory_access=payload)
        return _inconclusive(state, "object_range_or_pointer_state_unproven", scope=_scope(evidence), exact=True)
    return _result(state, "proven", _scope(evidence), True, memory_access=payload, evidence=evidence)


def _memory_lifetime_proof(state: CandidateState, evidence: Mapping[str, Any]) -> ProofResult:
    exact = _exact_operation(state, evidence)
    payload = _mapping(evidence.get("lifetime_violation"))
    if evidence.get("unsupported"):
        return _unsupported(state, str(evidence.get("blocker") or "unsupported_lifetime_semantics"))
    if exact and payload.get("safe") is True:
        return _result(state, "refuted", _scope(evidence), True, lifetime_violation=payload, evidence=evidence)
    if not exact or not _lifetime_payload_proves(state, payload):
        return _inconclusive(state, "same_resource_event_sequence_unproven", scope=_scope(evidence), exact=exact)
    return _result(state, "proven", _scope(evidence), True, lifetime_violation=payload, evidence=evidence)


def _semantic_effect_proof(state: CandidateState, evidence: Mapping[str, Any]) -> ProofResult:
    spec = get_vulnerability_spec(state.vulnerability_type)
    effect = _mapping(evidence.get("effect_observation"))
    process_setup = _mapping(evidence.get("process_setup"))
    native_replay = _mapping(evidence.get("native_replay"))
    concrete_input = _mapping(evidence.get("concrete_input"))
    exact = _exact_operation(state, evidence)
    if evidence.get("unsupported"):
        return _unsupported(state, str(evidence.get("blocker") or "unsupported_process_semantics"))
    proven = bool(
        _scope(evidence) == "process_entrypoint"
        and exact
        and process_setup.get("status") == "configured"
        and native_replay.get("status") in {"reached", "observed"}
        and effect.get("status") == "observed"
        and effect.get("kind") == spec.effect_kind
        and concrete_input
    )
    if not proven:
        return _result(
            state,
            "inconclusive",
            _scope(evidence),
            exact,
            effect_observation=effect,
            evidence=evidence,
            blocker="concrete_process_effect_unproven",
        )
    return _result(state, "proven", "process_entrypoint", True, effect_observation=effect, evidence=evidence)


def _static_evidence_proof(state: CandidateState, evidence: Mapping[str, Any]) -> ProofResult:
    payload = _mapping(evidence.get("static_evidence"))
    if evidence.get("unsupported"):
        return _unsupported(state, str(evidence.get("blocker") or "unsupported_static_evidence"), scope="static")
    proven = bool(payload.get("exact") is True and payload.get("reachable") is True and payload.get("kind"))
    return _result(
        state,
        "proven" if proven else "inconclusive",
        "static",
        proven,
        static_evidence=payload,
        evidence=evidence,
        blocker="" if proven else "exact_reachable_static_evidence_unproven",
    )


def _memory_payload_proves(state: CandidateState, payload: Mapping[str, Any]) -> bool:
    if not payload:
        return False
    if state.vulnerability_type == "null_pointer_dereference":
        return payload.get("pointer_value") == 0 and payload.get("accessed") is True
    if state.vulnerability_type == "uninitialized_memory_use":
        return bool(
            payload.get("definedness") == "undefined"
            and payload.get("read") is True
            and payload.get("undefined_byte_ranges")
        )
    if state.vulnerability_type == "overlapping_memory_copy":
        return payload.get("ranges_overlap") is True and payload.get("operation") == "memcpy"
    return bool(
        payload.get("same_object") is True
        and payload.get("object_range")
        and payload.get("access_range")
        and payload.get("out_of_bounds") is True
    )


def _lifetime_payload_proves(state: CandidateState, payload: Mapping[str, Any]) -> bool:
    if not payload or payload.get("same_resource") is not True:
        return False
    if state.vulnerability_type == "memory_leak":
        return bool(
            payload.get("path_local") is True
            and payload.get("escaped") is False
            and payload.get("live_at_scope_exit") is True
            and payload.get("resource_generation")
            and payload.get("scope_exit")
            and any(
                isinstance(item, Mapping) and item.get("action") == "scope_exit"
                for item in payload.get("events", [])
            )
        )
    if state.vulnerability_type == "mismatched_deallocator":
        return bool(payload.get("allocator_family") and payload.get("deallocator_family") and payload.get("allocator_family") != payload.get("deallocator_family"))
    return bool(payload.get("events") and payload.get("violation") is True)


def _exact_operation(state: CandidateState, evidence: Mapping[str, Any]) -> bool:
    expected = str(
        state.sink.get("operation_address")
        or state.operation.get("operation_address")
        or state.operation.get("address")
        or state.location.get("operation_address")
        or ""
    )
    actual = str(evidence.get("operation_address") or "")
    return bool(
        evidence.get("exact_operation_reached") is True
        and expected
        and _normalized_address(actual) == _normalized_address(expected)
    )


def _scope(evidence: Mapping[str, Any]) -> str:
    value = str(evidence.get("scope") or "function_harness")
    return value if value in {"process_entrypoint", "function_harness", "static"} else "function_harness"


def _result(
    state: CandidateState,
    status: str,
    scope: str,
    exact: bool,
    *,
    memory_access: Mapping[str, Any] | None = None,
    lifetime_violation: Mapping[str, Any] | None = None,
    effect_observation: Mapping[str, Any] | None = None,
    static_evidence: Mapping[str, Any] | None = None,
    evidence: Mapping[str, Any] | None = None,
    blocker: str = "",
) -> ProofResult:
    evidence = evidence or {}
    return ProofResult(
        backend=state.backend,
        candidate_id=state.candidate_id,
        status=status,
        scope=scope,
        exact_operation_reached=exact,
        memory_access=memory_access or {},
        lifetime_violation=lifetime_violation or {},
        effect_observation=effect_observation or {},
        static_evidence=static_evidence or {},
        concrete_input=_mapping(evidence.get("concrete_input")),
        process_setup=_mapping(evidence.get("process_setup")),
        native_replay=_mapping(evidence.get("native_replay")),
        artifact_refs=tuple(str(item) for item in evidence.get("artifact_refs", ()) if str(item)),
        blocker=blocker,
    )


def _unsupported(state: CandidateState, blocker: str, *, scope: str = "function_harness") -> ProofResult:
    return _result(state, "unsupported", scope, False, blocker=blocker)


def _inconclusive(
    state: CandidateState,
    blocker: str,
    *,
    scope: str = "function_harness",
    exact: bool = False,
) -> ProofResult:
    return _result(state, "inconclusive", scope, exact, blocker=blocker)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _normalized_replay_evidence(
    state: CandidateState,
    replay: ReplayResult | None,
) -> dict[str, Any]:
    if state.backend == "static_evidence":
        facts = dict(state.type_facts)
        kind = str(facts.get("exact_call") or state.mechanism or state.operation.get("name") or "")
        return {
            "scope": "static",
            "exact_operation_reached": bool(kind),
            "operation_address": _expected_operation_address(state),
            "static_evidence": {
                "exact": bool(
                    (facts.get("literal_fingerprint") and facts.get("consumer_address"))
                    or facts.get("exact_call")
                ),
                "reachable": facts.get("reachable") is True,
                "kind": kind,
                "literal_fingerprint": str(facts.get("literal_fingerprint") or ""),
                "literal_length": facts.get("literal_length"),
                "literal_address": str(facts.get("literal_address") or ""),
                "consumer_address": str(facts.get("consumer_address") or ""),
                "consumer_name": str(facts.get("consumer_name") or ""),
                "observed_call": str(facts.get("observed_call") or ""),
            },
        }

    if replay is None:
        return {
            "scope": "function_harness",
            "exact_operation_reached": False,
            "operation_address": "",
        }

    dynamic = _dynamic_proof_from_replay(replay)
    exact = bool(dynamic.get("exact_sink_reached") and replay.sink_reached)
    operation_address = str(dynamic.get("sink_address") or "")
    scope = str(dynamic.get("proof_scope") or "function_harness")
    process_setup = dict(_mapping(dynamic.get("process_input_setup")))
    native = dict(_mapping(dynamic.get("native_replay")))
    native_trace = _mapping(native.get("exact_operation_trace"))
    native_operation = str(native_trace.get("operation_address") or "")
    native_exact = bool(
        native_trace.get("status") == "reached"
        and _normalized_address(native_operation) == _normalized_address(_expected_operation_address(state))
    )
    if native_exact:
        exact = True
        operation_address = native_operation
        scope = "process_entrypoint"
    native_status = str(native.get("status") or "")
    if replay.sink_reached and native_status not in {"reached", "observed"}:
        native["status"] = "observed" if replay.bug_observed else "reached"
    concrete_input = _concrete_input_from_setup(process_setup)
    evidence: dict[str, Any] = {
        "scope": scope,
        "exact_operation_reached": exact,
        "operation_address": operation_address,
        "concrete_input": concrete_input,
        "process_setup": process_setup,
        "native_replay": native,
        "artifact_refs": list(replay.artifacts),
    }

    if state.backend == "memory_access":
        status = str(dynamic.get("status") or "")
        object_size = _positive_int(dynamic.get("object_size_bytes") or dynamic.get("capacity_bytes"))
        access_range = dynamic.get("write_range") or dynamic.get("read_range") or []
        native_access = _mapping(native_trace.get("memory_access")) if native_exact else {}
        native_object_range = native_access.get("object_range") if isinstance(native_access.get("object_range"), list) else []
        native_access_range = native_access.get("access_range") if isinstance(native_access.get("access_range"), list) else []
        if not access_range and object_size and _positive_int(dynamic.get("oob_bytes")):
            access_range = [0, object_size + _positive_int(dynamic.get("oob_bytes"))]
        if native_access_range:
            access_range = native_access_range
        safe = bool(
            (replay.result == ReplayStatus.SINK_REACHED_NO_BUG.value and exact)
            or (native_access and native_access.get("out_of_bounds") is False)
        )
        indexed_definedness = bool(
            state.vulnerability_type == "uninitialized_memory_use"
            and native_exact
            and state.type_facts.get("definedness") == "undefined"
            and state.type_facts.get("prior_store") is False
        )
        evidence["memory_access"] = {
            "same_object": bool(native_access.get("same_object") is True or dynamic.get("object_identity") or object_size),
            "object_identity": native_access.get("object_address") or dynamic.get("object_identity", ""),
            "object_range": native_object_range or ([0, object_size] if object_size else []),
            "access_range": access_range,
            "out_of_bounds": bool(
                native_access.get("out_of_bounds") is True
                or (
                    replay.bug_observed
                    and exact
                    and ("proven" in status or _positive_int(dynamic.get("oob_bytes")) > 0)
                )
            ),
            "safe": safe,
            "pointer_value": native_access.get("pointer_value", dynamic.get("pointer_value")),
            "effective_address": native_access.get("effective_address", dynamic.get("effective_address")),
            "accessed": bool(native_access.get("accessed") or dynamic.get("accessed")),
            "definedness": "undefined" if indexed_definedness else str(dynamic.get("definedness") or ""),
            "defined_byte_ranges": (
                list(state.type_facts.get("defined_byte_ranges") or []) if indexed_definedness else []
            ),
            "undefined_byte_ranges": (
                list(state.type_facts.get("undefined_byte_ranges") or []) if indexed_definedness else []
            ),
            "read": bool(dynamic.get("read_range") or indexed_definedness),
            "ranges_overlap": bool(native_access.get("ranges_overlap") or dynamic.get("ranges_overlap")),
            "operation": str(native_access.get("operation") or dynamic.get("operation") or state.operation.get("name") or ""),
        }
    elif state.backend == "memory_lifetime":
        violation = dict(_mapping(dynamic.get("lifetime_violation")))
        violation_status = "lifetime_violation_proven" in str(dynamic.get("status") or "")
        safe = replay.result == ReplayStatus.SINK_REACHED_NO_BUG.value and exact
        if state.mechanism == "reentrant_copy_invalidation" and native_exact:
            lineage = _mapping(state.type_facts.get("resource_lineage"))
            callee = _mapping(state.type_facts.get("callee_summary"))
            ordered = state.type_facts.get("ordered_events")
            if (
                lineage.get("same_resource") is True
                and lineage.get("path_relation") == "copy_branch_feasible"
                and callee.get("may_allocate") is True
                and isinstance(ordered, list)
                and ordered == ["borrow", "invalidating_allocation", "copy_read"]
            ):
                violation = {
                    "vulnerability": "use_after_free",
                    "same_resource": True,
                    "resource_identity": state.type_facts.get("resource_identity", ""),
                    "borrow_expression": lineage.get("borrow_expression", ""),
                    "invalidating_operation": lineage.get("invalidating_operation", ""),
                    "allocation_evidence": list(callee.get("allocation_evidence") or []),
                    "proof_basis": "native_exact_branch_plus_indexed_same_owner_invalidation",
                }
                violation_status = True
        elif state.vulnerability_type in {
            "use_after_free",
            "double_free",
            "invalid_free",
            "memory_leak",
            "mismatched_deallocator",
            "double_close",
            "use_after_close",
        } and native_exact:
            runtime_violation = _mapping(native_trace.get("lifetime_violation"))
            if (
                runtime_violation.get("vulnerability") == state.vulnerability_type
                and runtime_violation.get("same_resource") is True
                and runtime_violation.get("violation") is True
                and runtime_violation.get("resource_generation")
                and runtime_violation.get("events")
            ):
                violation = {
                    **dict(runtime_violation),
                    "proof_basis": "generation_aware_native_resource_ledger",
                }
                if state.vulnerability_type == "memory_leak":
                    violation.update(
                        {
                            "path_local": state.type_facts.get("path_local") is True,
                            "escaped": state.type_facts.get("escaped") is True,
                            "live_at_scope_exit": runtime_violation.get("live_at_scope_exit") is True,
                            "static_scope_exits": list(state.type_facts.get("scope_exits") or []),
                        }
                    )
                violation_status = True
        evidence["lifetime_violation"] = {
            **violation,
            "same_resource": bool(
                violation.get("same_resource") is True
                or violation.get("object_id") is not None
                or violation.get("object_identity")
                or violation.get("handle") is not None
            ),
            "events": (
                list(violation.get("events") or [])
                if state.vulnerability_type == "memory_leak"
                else list(state.type_facts.get("ordered_events") or [])
                if violation and state.type_facts.get("ordered_events")
                else [violation] if violation else []
            ),
            "violation": bool(
                exact
                and violation_status
                and violation
                and (
                    replay.bug_observed
                    or state.mechanism == "reentrant_copy_invalidation"
                    or state.vulnerability_type in {
                        "use_after_free",
                        "double_free",
                        "invalid_free",
                        "mismatched_deallocator",
                        "double_close",
                        "use_after_close",
                        "memory_leak",
                    }
                )
            ),
            "safe": safe,
        }
    elif state.backend == "semantic_effect":
        effect = dict(_mapping(dynamic.get("effect_observation")))
        if not effect:
            control = dict(replay.control_result)
            candidate_effect = control.get("effect_observation") or control.get("proof_observation")
            if isinstance(candidate_effect, Mapping):
                effect = dict(candidate_effect)
        evidence["effect_observation"] = _normalize_effect_observation(
            state,
            effect,
            replay,
        )
    return evidence


def _normalize_effect_observation(
    state: CandidateState,
    effect: Mapping[str, Any],
    replay: ReplayResult,
) -> dict[str, Any]:
    if not effect:
        return {}
    spec = get_vulnerability_spec(state.vulnerability_type)
    raw_status = str(effect.get("status") or "")
    if raw_status not in {"observed", "not_observed", "unsupported"}:
        raw_status = "observed" if effect.get("bug_observed") is True else "not_observed"
    sink_address = str(effect.get("sink_address") or "")
    expected = _expected_operation_address(state)
    if sink_address and _normalized_address(sink_address) != _normalized_address(expected):
        raw_status = "unsupported"
    kind = str(effect.get("kind") or "")
    if kind != spec.effect_kind:
        raw_status = "unsupported"
    return {
        "status": raw_status,
        "kind": kind,
        "sink_address": sink_address or expected,
        "concrete_input_fingerprint": str(effect.get("concrete_input_fingerprint") or ""),
        "details": dict(_mapping(effect.get("details"))),
        "artifact_refs": [
            str(item)
            for item in effect.get("artifact_refs", ())
            if str(item) and str(item) in replay.artifacts
        ],
    }


def _dynamic_proof_from_replay(replay: ReplayResult) -> Mapping[str, Any]:
    control = dict(replay.control_result)
    embedded = control.get("ghidra_dynamic_proof")
    dynamic: dict[str, Any] = {}
    if isinstance(embedded, Mapping):
        dynamic.update(embedded)
    for raw in replay.artifacts:
        path = Path(raw)
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text() or "{}")
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(payload, Mapping):
            continue
        if path.name.startswith("ghidra_dynamic_proof"):
            dynamic.update(payload)
        elif path.name == "replay.json":
            native = payload.get("native_replay")
            if not isinstance(native, Mapping):
                continue
            trace = native.get("exact_operation_trace")
            if not isinstance(trace, Mapping) or trace.get("status") != "reached":
                continue
            dynamic["native_replay"] = dict(native)
            dynamic["exact_sink_reached"] = True
            dynamic["sink_address"] = str(
                trace.get("operation_address") or dynamic.get("sink_address") or ""
            )
            dynamic["proof_scope"] = "process_entrypoint"
    return dynamic


def _concrete_input_from_setup(setup: Mapping[str, Any]) -> dict[str, Any]:
    model = str(setup.get("input_model") or "")
    if not model:
        return {}
    result: dict[str, Any] = {"input_model": model}
    if isinstance(setup.get("argv_values"), list):
        result["argv"] = [str(item) for item in setup["argv_values"]]
    input_hex = str(
        setup.get("concrete_input_hex")
        or setup.get("stdin_input_hex")
        or setup.get("file_input_hex")
        or ""
    )
    if input_hex:
        result["input_hex"] = input_hex
    if setup.get("file_name"):
        result["file_name"] = str(setup["file_name"])
    return result


def _expected_operation_address(state: CandidateState) -> str:
    return str(
        state.sink.get("operation_address")
        or state.operation.get("operation_address")
        or state.operation.get("address")
        or state.location.get("operation_address")
        or ""
    )


def _normalized_address(value: str) -> str:
    raw = str(value or "").strip()
    try:
        return hex(int(raw, 0))
    except ValueError:
        return raw.lower()


def _positive_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0
