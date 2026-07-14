"""Hard promotion gates for candidate lifecycle states."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.pipeline import (
    CandidateState,
    CandidateStatus,
    LiftRecord,
    PromotionEvent,
    ProofResult,
    has_reportable_source_to_sink,
    write_candidate_states,
)
from binary_agent.proof import proof_result_reportable
from binary_agent.taxonomy import get_vulnerability_spec
from binary_agent.replay.models import ReplayResult, ReplayStatus
from binary_agent.utils.time import utc_timestamp


def promote_proof_ready(states: Sequence[CandidateState]) -> tuple[list[CandidateState], list[PromotionEvent], list[LiftRecord]]:
    """Promote candidates whose deterministic proof obligations are satisfied."""
    promoted: list[CandidateState] = []
    events: list[PromotionEvent] = []
    lift: list[LiftRecord] = []
    for state in states:
        if state.status not in {CandidateStatus.CANDIDATE.value, CandidateStatus.NEEDS_REFINEMENT.value}:
            promoted.append(state)
            continue
        if _proof_preconditions_satisfied(state):
            updated = state.with_updates(status=CandidateStatus.PROOF_READY.value, blockers=[])
            events.append(
                PromotionEvent(
                    candidate_id=state.candidate_id,
                    from_status=state.status,
                    to_status=updated.status,
                    reason="proof_preconditions_satisfied",
                    artifact_refs=list(state.validation_artifacts),
                )
            )
            promoted.append(updated)
        else:
            promoted.append(state)
    return promoted, events, lift


def promote_with_proof_results(
    states: Sequence[CandidateState],
    proof_results: Sequence[ProofResult],
    *,
    report_artifacts: Mapping[str, str] | None = None,
) -> tuple[list[CandidateState], list[PromotionEvent]]:
    """Promote exclusively through the taxonomy-driven schema-v2 report gate."""

    by_id = {result.candidate_id: result for result in proof_results}
    report_artifacts = dict(report_artifacts or {})
    promoted: list[CandidateState] = []
    events: list[PromotionEvent] = []
    for state in states:
        result = by_id.get(state.candidate_id)
        if result is None:
            promoted.append(state)
            continue
        if result.status == "refuted":
            updated = state.with_updates(
                status=CandidateStatus.REJECTED.value,
                blockers=[],
                type_facts={**dict(state.type_facts), "proof_result": result.to_dict()},
                validation_artifacts=_dedupe([*state.validation_artifacts, *result.artifact_refs]),
            )
            reason = "backend_proof_refuted_candidate"
        elif proof_result_reportable(state, result):
            artifact = report_artifacts.get(state.candidate_id, "")
            updated = state.with_updates(
                status=CandidateStatus.REPORT_READY.value,
                blockers=[],
                type_facts={**dict(state.type_facts), "proof_result": result.to_dict()},
                validation_artifacts=_dedupe([*state.validation_artifacts, *result.artifact_refs]),
                report_artifacts=_dedupe([*state.report_artifacts, artifact] if artifact else state.report_artifacts),
            )
            reason = f"{get_vulnerability_spec(state.vulnerability_type).proof_policy}_proof_proven"
        else:
            blocker = result.blocker or f"proof_{result.status}"
            promoted.append(
                state.with_updates(
                    blockers=_dedupe([*state.blockers, blocker]),
                    type_facts={**dict(state.type_facts), "proof_result": result.to_dict()},
                    validation_artifacts=_dedupe([*state.validation_artifacts, *result.artifact_refs]),
                )
            )
            continue
        events.append(
            PromotionEvent(
                candidate_id=state.candidate_id,
                from_status=state.status,
                to_status=updated.status,
                reason=reason,
                artifact_refs=list(result.artifact_refs),
            )
        )
        promoted.append(updated)
    return promoted, events


def promote_for_replay(
    states: Sequence[CandidateState],
    *,
    request_artifacts: Mapping[str, str] | None = None,
    artifact_confirmed_candidate_ids: Sequence[str] = (),
) -> tuple[list[CandidateState], list[PromotionEvent]]:
    request_artifacts = dict(request_artifacts or {})
    artifact_confirmed_ids = {str(candidate_id) for candidate_id in artifact_confirmed_candidate_ids}
    promoted: list[CandidateState] = []
    events: list[PromotionEvent] = []
    for state in states:
        proof_ready = state.status == CandidateStatus.PROOF_READY.value
        artifact_confirmed = (
            state.candidate_id in artifact_confirmed_ids
            and state.status in {
                CandidateStatus.CANDIDATE.value,
                CandidateStatus.NEEDS_REFINEMENT.value,
                CandidateStatus.PROOF_READY.value,
            }
        )
        if not proof_ready and not artifact_confirmed:
            promoted.append(state)
            continue
        request_ref = request_artifacts.get(state.candidate_id)
        if not request_ref:
            promoted.append(state)
            continue
        proof_obligations = list(state.proof_obligations)
        blockers = list(state.blockers)
        if artifact_confirmed:
            blockers = []
            proof_obligations = [
                {
                    **dict(obligation),
                    "status": "satisfied",
                    "evidence_refs": _dedupe(
                        [
                            *[str(item) for item in obligation.get("evidence_refs", [])],
                            request_ref,
                        ]
                    ),
                }
                for obligation in state.proof_obligations
            ]
        updated = state.with_updates(
            status=CandidateStatus.REPLAY_READY.value,
            blockers=blockers,
            proof_obligations=proof_obligations,
            replay_artifacts=[*state.replay_artifacts, request_ref],
        )
        events.append(
            PromotionEvent(
                candidate_id=state.candidate_id,
                from_status=state.status,
                to_status=updated.status,
                reason=(
                    "artifact_confirmed_process_proof_available"
                    if artifact_confirmed and not proof_ready
                    else "concrete_replay_request_available"
                ),
                artifact_refs=[request_ref],
            )
        )
        promoted.append(updated)
    return promoted, events


def apply_replay_results(
    states: Sequence[CandidateState],
    replay_results: Sequence[ReplayResult],
) -> tuple[list[CandidateState], list[PromotionEvent], list[LiftRecord]]:
    by_id = {result.candidate_id: result for result in replay_results}
    promoted: list[CandidateState] = []
    events: list[PromotionEvent] = []
    lift: list[LiftRecord] = []
    for state in states:
        result = by_id.get(state.candidate_id)
        if result is None:
            promoted.append(state)
            continue
        if state.status != CandidateStatus.REPLAY_READY.value:
            promoted.append(state)
            continue
        if (
            result.result == ReplayStatus.CONFIRMED.value
            and result.sink_reached
            and result.bug_observed
        ):
            updated = state.with_updates(
                status=CandidateStatus.REPLAY_CONFIRMED.value,
                replay_artifacts=_dedupe([*state.replay_artifacts, *result.artifacts]),
            )
            events.append(
                PromotionEvent(
                    candidate_id=state.candidate_id,
                    from_status=state.status,
                    to_status=updated.status,
                    reason="replay_demonstrated_bug_condition",
                    artifact_refs=list(result.artifacts),
                )
            )
            lift.append(
                LiftRecord(
                    candidate_id=state.candidate_id,
                    role="replay",
                    outcome="replay_succeeded",
                    evidence_refs=list(result.artifacts),
                )
            )
            promoted.append(updated)
        elif result.result in {
            ReplayStatus.SINK_REACHED_NO_BUG.value,
            ReplayStatus.SINK_NOT_REACHED.value,
            ReplayStatus.SETUP_INVALID.value,
            ReplayStatus.CRASH_UNCLASSIFIED.value,
        }:
            updated = state.with_updates(replay_artifacts=_dedupe([*state.replay_artifacts, *result.artifacts]))
            if has_reportable_source_to_sink(updated):
                updated = updated.with_updates(status=CandidateStatus.REPLAY_CONFIRMED.value)
                events.append(
                    PromotionEvent(
                        candidate_id=state.candidate_id,
                        from_status=state.status,
                        to_status=updated.status,
                        reason="replay_artifact_backed_proof",
                        artifact_refs=list(result.artifacts),
                    )
                )
                lift.append(
                    LiftRecord(
                        candidate_id=state.candidate_id,
                        role="replay",
                        outcome="artifact_backed_proof",
                        evidence_refs=list(result.artifacts),
                    )
                )
                promoted.append(updated)
                continue
            if result.result == ReplayStatus.SINK_REACHED_NO_BUG.value:
                updated = updated.with_updates(status=CandidateStatus.REJECTED.value)
            if updated.status == CandidateStatus.REJECTED.value:
                events.append(
                    PromotionEvent(
                        candidate_id=state.candidate_id,
                        from_status=state.status,
                        to_status=updated.status,
                        reason="replay_reached_sink_without_bug",
                        artifact_refs=list(result.artifacts),
                    )
                )
                lift.append(
                    LiftRecord(
                        candidate_id=state.candidate_id,
                        role="replay",
                        outcome="false_positive_rejected",
                        evidence_refs=list(result.artifacts),
                    )
                )
            promoted.append(updated)
        else:
            promoted.append(state.with_updates(replay_artifacts=_dedupe([*state.replay_artifacts, *result.artifacts])))
    return promoted, events, lift


def promote_for_report(
    states: Sequence[CandidateState],
    *,
    report_artifacts: Mapping[str, str],
) -> tuple[list[CandidateState], list[PromotionEvent]]:
    promoted: list[CandidateState] = []
    events: list[PromotionEvent] = []
    for state in states:
        if state.status != CandidateStatus.REPLAY_CONFIRMED.value:
            promoted.append(state)
            continue
        artifact = report_artifacts.get(state.candidate_id)
        if not artifact:
            promoted.append(state)
            continue
        if not has_reportable_source_to_sink(state):
            promoted.append(state)
            continue
        updated = state.with_updates(
            status=CandidateStatus.REPORT_READY.value,
            report_artifacts=[*state.report_artifacts, artifact],
        )
        events.append(
            PromotionEvent(
                candidate_id=state.candidate_id,
                from_status=state.status,
                to_status=updated.status,
                reason="report_claims_artifact_backed",
                artifact_refs=[artifact],
            )
        )
        promoted.append(updated)
    return promoted, events


def integrate_concolic_results(
    states: Sequence[CandidateState],
    concolic_results: Sequence[Mapping[str, Any]],
) -> tuple[list[CandidateState], list[PromotionEvent], list[LiftRecord]]:
    """Remove proof blockers only when backend concolic artifacts reached the sink."""
    by_id = {str(item.get("candidate_id") or ""): item for item in concolic_results if isinstance(item, Mapping)}
    promoted: list[CandidateState] = []
    events: list[PromotionEvent] = []
    lift: list[LiftRecord] = []
    for state in states:
        result = by_id.get(state.candidate_id)
        if not result:
            promoted.append(state)
            continue
        if not (result.get("concolic_ran") and result.get("sink_reached") and result.get("input_generated")):
            promoted.append(state)
            continue
        artifacts = [str(item) for item in result.get("artifact_refs", []) or result.get("artifact_paths", []) or []]
        remaining_blockers = [blocker for blocker in state.blockers if blocker not in {"overflow_condition_proof", "attacker_input_reaches_sink"}]
        updated = state.with_updates(
            blockers=remaining_blockers,
            validation_artifacts=[*state.validation_artifacts, *artifacts],
        )
        if state.blockers != updated.blockers:
            events.append(
                PromotionEvent(
                    candidate_id=state.candidate_id,
                    from_status=state.status,
                    to_status=updated.status,
                    reason="concolic_backend_removed_proof_blocker",
                    artifact_refs=artifacts,
                )
            )
            lift.append(
                LiftRecord(
                    candidate_id=state.candidate_id,
                    role="branch_guide",
                    outcome="blocker_removed",
                    evidence_refs=artifacts,
                )
            )
        promoted.append(updated)
    return promoted, events, lift


def write_promotion_artifacts(
    states: Sequence[CandidateState],
    events: Sequence[PromotionEvent],
    lift_records: Sequence[LiftRecord],
    output_dir: Path,
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    candidate_path = write_candidate_states(list(states), output_dir / "candidate_states.json")
    event_path = output_dir / "promotion_events.json"
    lift_path = output_dir / "lift_summary.json"
    event_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generated_at": utc_timestamp(),
                "promotion_events": [event.to_dict() for event in events],
            },
            indent=2,
            sort_keys=True,
        )
    )
    lift_path.write_text(json.dumps(_lift_summary(lift_records), indent=2, sort_keys=True))
    return {
        "candidate_states": candidate_path,
        "promotion_events": event_path,
        "lift_summary": lift_path,
    }


def _proof_preconditions_satisfied(
    state: CandidateState,
    *,
    require_exact_memory_operation: bool = True,
) -> bool:
    facts = dict(state.type_facts)
    static_candidate = facts.get("static_candidate") if isinstance(facts.get("static_candidate"), Mapping) else {}
    write_relation = str(facts.get("write_relation") or static_candidate.get("write_relation") or "")
    verdict = str(facts.get("verdict") or static_candidate.get("verdict") or "")
    if (
        _candidate_backend(state) in {"memory_access", "memory_lifetime"}
        and require_exact_memory_operation
        and not _has_exact_memory_operation(state)
    ):
        return False
    if state.vulnerability_type in {"stack_overflow", "heap_overflow", "out_of_bounds_write"}:
        local_overflow_proven = write_relation in {"proven_overflow", "unbounded"} or verdict in {"overflow", "unbounded"}
        reachability_only = set(state.blockers) <= {"valid_reachability_path", "attacker_input_reaches_sink"}
        return local_overflow_proven and reachability_only and _has_deterministic_input_basis(state)
    if state.vulnerability_type == "out_of_bounds_read":
        if state.mechanism == "rounded_stride_miscalculation":
            return bool(
                facts.get("range_relation") == "factor_applied_after_rounded_byte_conversion"
                and set(state.blockers) <= {"concrete_object_range_replay_required"}
                and (
                    _has_deterministic_input_basis(state)
                    or _has_concrete_process_input(state)
                )
            )
        local_read_proven = (
            write_relation in {"proven_oob_read", "symbolic_read_offset", "symbolic_size"}
            or verdict in {"oob_read_proven", "overflow"}
        )
        reachability_only = set(state.blockers) <= {
            "valid_reachability_path",
            "attacker_input_reaches_sink",
            "read_extent_proof",
        }
        return local_read_proven and reachability_only and _has_deterministic_input_basis(state)
    if state.vulnerability_type in {"use_after_free", "double_free", "invalid_free"}:
        if state.vulnerability_type == "use_after_free" and state.mechanism == "reentrant_copy_invalidation":
            lineage = _mapping(facts.get("resource_lineage"))
            callee = _mapping(facts.get("callee_summary"))
            return bool(
                set(state.blockers) <= {"concrete_reentrant_invalidation_replay_required"}
                and lineage.get("same_resource") is True
                and lineage.get("path_relation") == "copy_branch_feasible"
                and callee.get("may_allocate") is True
                and (
                    _has_deterministic_input_basis(state)
                    or _has_concrete_process_input(state)
                )
            )
        if state.vulnerability_type == "double_free" and facts.get("trigger_sequence"):
            indexed_owner_blockers = {
                "dynamic_indexed_owner_identity_unproven",
                "owner_alias_range_overlap_unproven",
                "process_trigger_reaches_cleanup_unproven",
            }
            entrypoint = _mapping(facts.get("entrypoint_derivation"))
            if (
                set(state.blockers) <= indexed_owner_blockers
                and entrypoint.get("status") == "derived"
                and entrypoint.get("process_input_supported") is True
            ):
                return True
        allowed_blocker = (
            "dynamic_non_base_release_unproven"
            if state.vulnerability_type == "invalid_free"
            else "dynamic_same_object_lifetime_unproven"
        )
        lifetime_only = set(state.blockers) <= {allowed_blocker}
        derived_pointer = facts.get("derived_pointer") if isinstance(facts.get("derived_pointer"), Mapping) else {}
        exact_derivation = state.vulnerability_type != "invalid_free" or bool(
            derived_pointer.get("base_variable") and derived_pointer.get("offset_expression")
        )
        return bool(lifetime_only and facts.get("allocation_site") and exact_derivation)
    if state.vulnerability_type in {"mismatched_deallocator", "double_close", "use_after_close"}:
        control_flow = _mapping(facts.get("control_flow"))
        return bool(
            set(state.blockers) <= {"same_resource_runtime_proof_required"}
            and facts.get("same_resource") is True
            and facts.get("path_relation") in {
                "same_basic_block",
                "cfg_dominates",
                "cfg_reachable_branch",
                "text_linear_fallthrough",
            }
            and control_flow.get("feasible") is True
            and len(facts.get("ordered_events") or []) >= 2
        )
    if state.vulnerability_type == "overlapping_memory_copy":
        return bool(
            set(state.blockers) <= {"concrete_range_replay_required"}
            and state.operation.get("name") in {"memcpy", "memcpy_chk"}
            and (
                facts.get("exact_overlap") is True
                or facts.get("attacker_controlled_range_expression") is True
                or _has_deterministic_input_basis(state)
                or _has_concrete_process_input(state)
            )
        )
    if state.vulnerability_type == "null_pointer_dereference":
        return bool(
            set(state.blockers) <= {"effective_address_zero_replay_required"}
            and facts.get("exact_null") is True
            and facts.get("pointer_value") == 0
            and _has_concrete_process_input(state)
        )
    if state.vulnerability_type == "memory_leak":
        return bool(
            set(state.blockers) <= {"live_generation_at_scope_exit_replay_required"}
            and facts.get("path_local") is True
            and facts.get("escaped") is False
            and facts.get("live_at_scope_exit") is True
            and facts.get("scope_exits")
            and _has_concrete_process_input(state)
        )
    if _candidate_backend(state) == "semantic_effect" and _has_concrete_process_input(state):
        return bool(
            set(state.blockers) <= {"concrete_effect_replay_required"}
            and state.operation.get("address")
            and state.type_facts.get("effect_kind")
        )
    if state.vulnerability_type in {
        "command_injection",
        "path_traversal",
        "format_string",
        "unsafe_file_write",
        "integer_overflow",
    } and not _has_deterministic_input_basis(state):
        return False
    if state.blockers:
        return False
    obligations = state.proof_obligations or []
    return all(str(item.get("status") or "") == "satisfied" for item in obligations if isinstance(item, Mapping))


def candidate_needs_exact_memory_operation(state: CandidateState) -> bool:
    return bool(
        _candidate_backend(state) in {"memory_access", "memory_lifetime"}
        and not _has_exact_memory_operation(state)
        and _proof_preconditions_satisfied(state, require_exact_memory_operation=False)
    )


def _candidate_backend(state: CandidateState) -> str:
    if state.backend:
        return state.backend
    try:
        return get_vulnerability_spec(state.vulnerability_type).backend
    except ValueError:
        return ""


def _has_deterministic_input_basis(state: CandidateState) -> bool:
    facts = dict(state.type_facts)
    for trace in (
        facts.get("source_to_sink_trace"),
        _mapping(facts.get("entrypoint_derivation")).get("source_to_sink_trace"),
    ):
        if not isinstance(trace, Mapping):
            continue
        if (
            str(trace.get("status") or "").lower() in {"complete", "proven"}
            and trace.get("attacker_control_reaches_sink_role") is True
            and not trace.get("blockers")
            and _trace_has_causal_process_input(trace)
        ):
            return True

    static_candidate = _mapping(facts.get("static_candidate"))
    classification = _mapping(static_candidate.get("classification_trace"))
    roles = _mapping(_mapping(classification.get("source_to_write")).get("roles"))
    entrypoint = _mapping(facts.get("entrypoint_derivation"))
    executable_process_input = bool(
        str(entrypoint.get("status") or "").lower() == "derived"
        and entrypoint.get("process_input_supported") is True
        and entrypoint.get("entry_address")
    )
    explicit_harness = _mapping(classification.get("function_harness")) or _mapping(
        facts.get("function_harness")
    )
    executable_harness = bool(explicit_harness.get("function_address"))
    if not (executable_process_input or executable_harness):
        return False
    for role_name in ("write_source", "write_size", "write_offset", "read_source", "read_size", "read_offset"):
        role = _mapping(roles.get(role_name))
        classification = str(role.get("classification") or "")
        if role.get("complete") is True and (
            classification == "source_controlled"
            or (classification == "parameter_controlled" and executable_harness)
        ):
            return True
    return False


def _has_concrete_process_input(state: CandidateState) -> bool:
    """Return true only for an executable, explicitly supplied process input."""
    facts = _mapping(state.type_facts)
    process_input = _mapping(facts.get("process_input"))
    return bool(
        process_input.get("inferred") is False
        and (
            process_input.get("argv_values")
            or process_input.get("file_input_hex")
            or process_input.get("stdin_input_hex")
            or process_input.get("env_values")
        )
    )


def _trace_has_causal_process_input(trace: Mapping[str, Any]) -> bool:
    if _mapping(trace.get("evidence")).get("source_to_write_complete") is True:
        return True
    for role in trace.get("argument_roles", []) if isinstance(trace.get("argument_roles"), list) else []:
        if (
            isinstance(role, Mapping)
            and role.get("complete") is True
            and str(role.get("classification") or "") == "source_controlled"
        ):
            return True
    return str(_mapping(trace.get("sink_argument")).get("classification") or "") == "source_controlled"


def _has_exact_memory_operation(state: CandidateState) -> bool:
    facts = _mapping(state.type_facts)
    static_candidate = _mapping(facts.get("static_candidate"))
    operation_address = str(
        _mapping(state.sink).get("operation_address")
        or _mapping(state.operation).get("address")
        or _mapping(state.sink).get("address")
        or static_candidate.get("operation_address")
        or facts.get("exact_sink_address")
        or facts.get("llm_exact_sink_address")
        or _mapping(facts.get("pcode_slice")).get("operation_address")
        or ""
    ).strip()
    if not operation_address:
        for row in facts.get("write_table", []) if isinstance(facts.get("write_table"), list) else []:
            if isinstance(row, Mapping) and row.get("operation_address"):
                operation_address = str(row["operation_address"]).strip()
                break
    function_address = str(static_candidate.get("address") or _mapping(state.location).get("address") or "").strip()
    return bool(operation_address and (not function_address or operation_address.lower() != function_address.lower()))


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _lift_summary(records: Sequence[LiftRecord]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    by_role: dict[str, int] = {}
    for record in records:
        if not record.measurable:
            continue
        counts[record.outcome] = counts.get(record.outcome, 0) + 1
        by_role[record.role] = by_role.get(record.role, 0) + 1
    return {
        "schema_version": 1,
        "generated_at": utc_timestamp(),
        "counts": counts,
        "by_role": by_role,
        "records": [record.to_dict() for record in records],
    }


def _dedupe(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result
