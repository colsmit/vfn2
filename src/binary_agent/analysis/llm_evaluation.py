"""Offline evaluation helpers for LLM vulnerability hypotheses.

The evaluator treats model output as a hypothesis to validate, never as a
security verdict.  Deterministic evidence packs, concolic request bounds, and
curated labels decide whether a hypothesis is useful enough to score.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.analysis.confirmation import iter_evidence_packs
from binary_agent.analysis.concolic import (
    CONCOLIC_TOOL_NAME,
    ConcolicToolConfig,
    concolic_request_from_tool_request,
)


HYPOTHESIS_KINDS = {"replay", "environment", "branch_guidance", "triage"}
EVALUATION_SYSTEMS = {"D0", "L1", "L2", "L3"}
LLM_EVAL_SUMMARY = "summary.json"
LLM_EVAL_LIFT_SUMMARY = "lift_summary.json"
LIFT_CLASSES = {
    "no_lift",
    "schema_lift_only",
    "environment_lift",
    "replay_lift",
    "branch_lift",
    "triage_lift",
    "proof_lift",
    "report_lift",
}
_PROCESS_VULN_PROOF_ORACLES = {
    "command_injection": "command_effect",
    "path_traversal": "filesystem_read_escape",
    "unsafe_file_write": "filesystem_write_escape",
    "format_string": "format_string_effect",
    "credential_disclosure": "credential_disclosure",
    "hardcoded_credential": "credential_disclosure",
    "auth_bypass": "auth_bypass_effect",
}

_GENERIC_TEXT = {
    "*",
    "?",
    "any",
    "anything",
    "all",
    "unknown",
    "n/a",
    "na",
    "none",
    "null",
    "todo",
    "tbd",
    "large",
    "long",
    "long enough",
    "big",
    "attacker controlled",
    "attacker-controlled",
    "arbitrary",
    "some input",
    "valid input",
    "input",
    "payload",
}
_SUPPRESS_DECISIONS = {
    "not_a_bug",
    "likely_safe",
    "false_positive",
    "suppress",
    "suppressed",
    "bounded_safe",
    "harness_only",
}
_REPORTING_DECISIONS = {
    "likely_bug",
    "confirmed_bug",
    "needs_dynamic_confirmation",
    "needs_more_evidence",
    "group_root_cause",
    "duplicate",
}


@dataclass(frozen=True)
class HypothesisArtifact:
    """Schema-complete pass/fail artifact for one model hypothesis."""

    candidate_id: str
    hypothesis_kind: str
    proposed_setup: dict[str, Any] = field(default_factory=dict)
    proposed_inputs: dict[str, Any] = field(default_factory=dict)
    expected_sink: dict[str, Any] = field(default_factory=dict)
    assumptions: list[str] = field(default_factory=list)
    validator_result: dict[str, Any] = field(default_factory=dict)
    failure_reason: str = ""
    cost_metadata: dict[str, Any] = field(default_factory=dict)
    raw_hypothesis: dict[str, Any] = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return bool(self.validator_result.get("accepted", False))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OfflineEvaluationResult:
    """Summary of an offline evaluation run."""

    output_dir: Path
    summary_path: Path
    lift_summary_path: Path
    artifact_paths: tuple[Path, ...]
    summary: dict[str, Any]
    lift_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "output_dir": str(self.output_dir),
            "summary_path": str(self.summary_path),
            "lift_summary_path": str(self.lift_summary_path),
            "artifact_paths": [str(path) for path in self.artifact_paths],
            "summary": dict(self.summary),
            "lift_summary": dict(self.lift_summary),
        }


def load_gold_labels(path: Path | None) -> dict[str, Any]:
    """Load optional curated labels used by environment and triage checks."""

    if path is None:
        return {}
    payload = json.loads(Path(path).read_text() or "{}")
    if not isinstance(payload, Mapping):
        raise ValueError(f"Gold-label file must contain a JSON object: {path}")
    return dict(payload)


def extract_preconditions(
    proposed_setup: Mapping[str, Any] | None,
    proposed_inputs: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize route, environment, filesystem, config, auth, and input setup."""

    setup = _coerce_mapping(proposed_setup)
    inputs = _coerce_mapping(proposed_inputs)
    invalid: dict[str, list[str]] = {
        "routes": [],
        "services": [],
        "env": [],
        "filesystem": [],
        "config": [],
        "auth": [],
        "inputs": [],
        "validation_commands": [],
    }
    routes = _extract_routes(setup, inputs, invalid)
    services = _extract_services(setup, inputs, invalid)
    env = _extract_env(setup, inputs, invalid)
    filesystem = _extract_filesystem(setup, inputs, invalid)
    config = _extract_named_mapping(setup, inputs, ("config", "configs", "nvram", "settings"), "config", invalid)
    auth = _extract_named_mapping(setup, inputs, ("auth", "authentication", "session", "sessions"), "auth", invalid)
    input_surfaces = _extract_input_surfaces(inputs, invalid)
    validation_commands = _extract_validation_commands(setup, inputs, invalid)
    return {
        "routes": routes,
        "services": services,
        "env": env,
        "filesystem": filesystem,
        "config": config,
        "auth": auth,
        "inputs": input_surfaces,
        "validation_commands": validation_commands,
        "invalid": {key: values for key, values in invalid.items() if values},
    }


def validate_hypothesis(
    evidence_pack: Mapping[str, Any],
    payload: Mapping[str, Any] | None,
    *,
    concolic_config: ConcolicToolConfig | None = None,
    gold_labels: Mapping[str, Any] | None = None,
) -> HypothesisArtifact:
    """Validate one LLM hypothesis and return a pass/fail artifact.

    Ordinary malformed or overbroad model output is represented as a rejected
    artifact instead of an exception, making offline runs stable and auditable.
    """

    candidate_id = _candidate_id_from_pack(evidence_pack)
    if not isinstance(payload, Mapping):
        return _rejected_artifact(
            candidate_id,
            "unknown",
            {},
            "hypothesis_must_be_object",
            raw={},
        )

    raw = dict(payload)
    hypothesis_kind = _infer_hypothesis_kind(raw)
    proposed_setup = _coerce_mapping(raw.get("proposed_setup"))
    proposed_inputs = _coerce_mapping(raw.get("proposed_inputs"))
    expected_sink = _coerce_mapping(raw.get("expected_sink"))
    assumptions = _coerce_string_list(raw.get("assumptions", []))
    cost_metadata = _coerce_mapping(raw.get("cost_metadata"))

    schema_errors: list[str] = []
    if hypothesis_kind not in HYPOTHESIS_KINDS:
        schema_errors.append(f"invalid_hypothesis_kind:{hypothesis_kind or 'missing'}")
    proposed_id = str(raw.get("candidate_id") or "").strip()
    if proposed_id and candidate_id and proposed_id != candidate_id:
        schema_errors.append(f"candidate_id_mismatch:{proposed_id}!={candidate_id}")
    for key in ("proposed_setup", "proposed_inputs", "expected_sink", "cost_metadata"):
        if key in raw and raw.get(key) is not None and not isinstance(raw.get(key), Mapping):
            schema_errors.append(f"{key}_must_be_object")
    if "assumptions" in raw and raw.get("assumptions") is not None and not _is_sequence_like(raw.get("assumptions")):
        schema_errors.append("assumptions_must_be_string_or_list")

    if schema_errors:
        return _artifact(
            candidate_id,
            hypothesis_kind or "unknown",
            proposed_setup,
            proposed_inputs,
            expected_sink,
            assumptions,
            _validator(False, schema_errors, failure_reason=";".join(schema_errors)),
            cost_metadata,
            raw,
        )

    if hypothesis_kind == "replay":
        result = _validate_replay_hypothesis(evidence_pack, raw, proposed_setup, proposed_inputs, expected_sink)
    elif hypothesis_kind == "environment":
        result = _validate_environment_hypothesis(
            evidence_pack,
            raw,
            proposed_setup,
            proposed_inputs,
            gold_labels=gold_labels or {},
        )
    elif hypothesis_kind == "branch_guidance":
        result = _validate_branch_guidance_hypothesis(evidence_pack, raw, concolic_config)
    elif hypothesis_kind == "triage":
        result = _validate_triage_hypothesis(evidence_pack, raw, gold_labels=gold_labels or {})
    else:
        result = _validator(False, ["invalid_hypothesis_kind"], failure_reason="invalid_hypothesis_kind")

    return _artifact(
        candidate_id,
        hypothesis_kind,
        proposed_setup,
        proposed_inputs,
        expected_sink,
        assumptions,
        result,
        cost_metadata,
        raw,
    )


def branch_guidance_tool_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Extract or construct a bounded ``run_concolic_poc`` tool request."""

    if not isinstance(payload, Mapping):
        raise ValueError("branch-guidance payload must be a JSON object")
    direct = _first_tool_request(payload)
    if direct is not None:
        return dict(direct)

    guidance = payload.get("branch_guidance")
    if not isinstance(guidance, Mapping):
        proposed_inputs = payload.get("proposed_inputs")
        if isinstance(proposed_inputs, Mapping) and isinstance(proposed_inputs.get("branch_guidance"), Mapping):
            guidance = proposed_inputs["branch_guidance"]
        elif isinstance(proposed_inputs, Mapping):
            guidance = proposed_inputs
        else:
            guidance = payload

    request: dict[str, Any] = {"tool": CONCOLIC_TOOL_NAME}
    for key in (
        "candidate_id",
        "target_address",
        "sink_address",
        "write_address",
        "input_model",
        "backend",
        "extra_branch_goal",
        "waypoint_addresses",
        "timeout_seconds",
    ):
        if key in guidance:
            request[key] = guidance[key]
    if "symbolic_byte_budget" in guidance:
        request["symbolic_byte_budget"] = guidance["symbolic_byte_budget"]
    elif "symbolic_bytes" in guidance:
        request["symbolic_byte_budget"] = guidance["symbolic_bytes"]
    elif "byte_budget" in guidance:
        request["symbolic_byte_budget"] = guidance["byte_budget"]
    for key in ("constraints", "allowed_stubs", "seed_mutations"):
        if key in guidance:
            request[key] = guidance[key]

    branch_goals = _coerce_sequence(guidance.get("branch_goals", []))
    if branch_goals and "extra_branch_goal" not in request:
        first_goal = branch_goals[0]
        if isinstance(first_goal, Mapping):
            request["extra_branch_goal"] = first_goal.get("address") or first_goal.get("target_address") or ""
        else:
            request["extra_branch_goal"] = str(first_goal)

    expected_sink = payload.get("expected_sink")
    if isinstance(expected_sink, Mapping):
        if "sink_address" not in request:
            request["sink_address"] = (
                expected_sink.get("sink_address")
                or expected_sink.get("operation_address")
                or expected_sink.get("target_address")
                or expected_sink.get("address")
                or ""
            )
        if "target_address" not in request:
            request["target_address"] = request.get("sink_address", "")
    return request


def run_offline_llm_evaluation(
    evidence_dir: Path,
    output_dir: Path,
    *,
    fixtures_dir: Path | None = None,
    systems: Sequence[str] = ("D0", "L1", "L2", "L3"),
    gold_labels: Mapping[str, Any] | None = None,
    concolic_config: ConcolicToolConfig | None = None,
    replay_results: Sequence[Mapping[str, Any] | Any] | None = None,
) -> OfflineEvaluationResult:
    """Run an offline D0/L1/L2/L3 evaluation over frozen evidence packs."""

    normalized_systems = [str(system).upper() for system in systems]
    for system in normalized_systems:
        if system not in EVALUATION_SYSTEMS:
            raise ValueError(f"Unsupported evaluation system: {system!r}")

    packs = iter_evidence_packs(Path(evidence_dir))
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_paths: list[Path] = []
    by_system: dict[str, list[HypothesisArtifact]] = {system: [] for system in normalized_systems}

    for system in normalized_systems:
        system_dir = output_dir / system
        system_dir.mkdir(parents=True, exist_ok=True)
        for stale_path in system_dir.glob("*.json"):
            stale_path.unlink()
        for _pack_path, pack in packs:
            candidate_id = _candidate_id_from_pack(pack)
            artifacts = _evaluate_system_candidate(
                system,
                pack,
                fixtures_dir=Path(fixtures_dir) if fixtures_dir is not None else None,
                gold_labels=gold_labels or {},
                concolic_config=concolic_config,
            )
            for index, artifact in enumerate(artifacts, start=1):
                suffix = f"_{artifact.hypothesis_kind}"
                if len(artifacts) > 1:
                    suffix += f"_{index}"
                path = system_dir / f"{_safe_stem(candidate_id)}{suffix}.json"
                path.write_text(json.dumps(artifact.to_dict(), indent=2))
                artifact_paths.append(path)
                by_system[system].append(artifact)

    summary = {
        "schema_version": 1,
        "candidate_count": len(packs),
        "systems_requested": normalized_systems,
        "systems": {
            system: _system_metrics(artifacts)
            for system, artifacts in by_system.items()
        },
    }
    summary_path = output_dir / LLM_EVAL_SUMMARY
    summary_path.write_text(json.dumps(summary, indent=2))
    lift_summary = build_lift_summary(by_system, replay_results=replay_results)
    lift_summary_path = output_dir / LLM_EVAL_LIFT_SUMMARY
    lift_summary_path.write_text(json.dumps(lift_summary, indent=2, sort_keys=True))
    return OfflineEvaluationResult(
        output_dir=output_dir,
        summary_path=summary_path,
        lift_summary_path=lift_summary_path,
        artifact_paths=tuple(artifact_paths),
        summary=summary,
        lift_summary=lift_summary,
    )


def build_lift_summary(
    artifacts_by_system: Mapping[str, Sequence[HypothesisArtifact | Mapping[str, Any]]],
    *,
    replay_results: Sequence[Mapping[str, Any] | Any] | None = None,
) -> dict[str, Any]:
    """Classify measurable lift over D0 for each evaluated hypothesis artifact."""

    normalized: dict[str, list[HypothesisArtifact]] = {
        str(system).upper(): [_coerce_artifact(item) for item in artifacts]
        for system, artifacts in artifacts_by_system.items()
    }
    baseline_by_candidate: dict[str, str] = {}
    for artifact in normalized.get("D0", []):
        baseline_by_candidate[artifact.candidate_id] = _baseline_status(artifact)
    replay_by_candidate = {
        str(_result_value(result, "candidate_id") or ""): result
        for result in replay_results or []
        if str(_result_value(result, "candidate_id") or "")
    }
    records: list[dict[str, Any]] = []
    for system, artifacts in sorted(normalized.items()):
        for artifact in artifacts:
            replay_result = replay_by_candidate.get(artifact.candidate_id)
            record = _lift_record(
                system,
                artifact,
                baseline_by_candidate.get(artifact.candidate_id, "unknown"),
                replay_result,
            )
            records.append(record)
    counts = {lift: 0 for lift in sorted(LIFT_CLASSES)}
    by_system: dict[str, dict[str, int]] = {}
    by_role: dict[str, dict[str, int]] = {}
    for record in records:
        lift = str(record["lift"])
        counts[lift] = counts.get(lift, 0) + 1
        system_counts = by_system.setdefault(str(record["system"]), {})
        system_counts[lift] = system_counts.get(lift, 0) + 1
        role_counts = by_role.setdefault(str(record["llm_role"]), {})
        role_counts[lift] = role_counts.get(lift, 0) + 1
    return {
        "schema_version": 1,
        "lift_classes": sorted(LIFT_CLASSES),
        "counts": counts,
        "by_system": by_system,
        "by_role": by_role,
        "records": records,
    }


def _evaluate_system_candidate(
    system: str,
    evidence_pack: Mapping[str, Any],
    *,
    fixtures_dir: Path | None,
    gold_labels: Mapping[str, Any],
    concolic_config: ConcolicToolConfig | None,
) -> list[HypothesisArtifact]:
    if system == "D0":
        return [_deterministic_baseline_artifact(evidence_pack)]

    candidate_id = _candidate_id_from_pack(evidence_pack)
    payload = _load_fixture_payload(fixtures_dir, system, candidate_id) if fixtures_dir is not None else None
    if payload is None:
        if system == "L1":
            pack_request = _first_tool_request(evidence_pack)
            if pack_request is not None:
                payload = {
                    "candidate_id": candidate_id,
                    "hypothesis_kind": "branch_guidance",
                    "branch_guidance": dict(pack_request),
                    "proposed_setup": {},
                    "proposed_inputs": {"branch_guidance": dict(pack_request)},
                    "expected_sink": _expected_sink_from_pack(evidence_pack),
                    "assumptions": [],
                }
        if payload is None:
            return [_missing_fixture_artifact(candidate_id, "branch_guidance" if system == "L1" else "replay", system)]

    if system == "L3":
        return [_validate_iterative_hypothesis(evidence_pack, payload, concolic_config, gold_labels)]

    hypotheses = _hypotheses_from_payload(payload)
    return [
        validate_hypothesis(
            evidence_pack,
            hypothesis,
            concolic_config=concolic_config,
            gold_labels=gold_labels,
        )
        for hypothesis in hypotheses
    ]


def _validate_iterative_hypothesis(
    evidence_pack: Mapping[str, Any],
    payload: Mapping[str, Any],
    concolic_config: ConcolicToolConfig | None,
    gold_labels: Mapping[str, Any],
) -> HypothesisArtifact:
    attempts = _coerce_sequence(payload.get("attempts", payload.get("iterations", [])))
    if not attempts:
        single = validate_hypothesis(
            evidence_pack,
            payload,
            concolic_config=concolic_config,
            gold_labels=gold_labels,
        )
        return _artifact_with_validator(
            single,
            {
                **single.validator_result,
                "system": "L3",
                "attempt_count": 1,
                "accepted_iteration": 1 if single.accepted else 0,
                "iteration_results": [single.validator_result],
            },
        )

    candidate_id = _candidate_id_from_pack(evidence_pack)
    attempt_artifacts: list[HypothesisArtifact] = []
    accepted_iteration = 0
    selected: HypothesisArtifact | None = None
    for index, attempt in enumerate(attempts, start=1):
        artifact = validate_hypothesis(
            evidence_pack,
            attempt if isinstance(attempt, Mapping) else {},
            concolic_config=concolic_config,
            gold_labels=gold_labels,
        )
        attempt_artifacts.append(artifact)
        if artifact.accepted and selected is None:
            accepted_iteration = index
            selected = artifact
    if selected is None:
        selected = attempt_artifacts[-1] if attempt_artifacts else _missing_fixture_artifact(candidate_id, "replay", "L3")
    result = {
        **selected.validator_result,
        "system": "L3",
        "accepted": bool(selected.accepted),
        "attempt_count": len(attempt_artifacts),
        "accepted_iteration": accepted_iteration,
        "iteration_results": [artifact.validator_result for artifact in attempt_artifacts],
    }
    failure_reason = "" if selected.accepted else selected.failure_reason
    if not selected.accepted and not failure_reason:
        failure_reason = "all_iterations_rejected"
    return HypothesisArtifact(
        candidate_id=candidate_id,
        hypothesis_kind=selected.hypothesis_kind,
        proposed_setup=selected.proposed_setup,
        proposed_inputs=selected.proposed_inputs,
        expected_sink=selected.expected_sink,
        assumptions=selected.assumptions,
        validator_result=result,
        failure_reason=failure_reason,
        cost_metadata=_merge_attempt_costs(attempt_artifacts),
        raw_hypothesis={"attempts": [artifact.raw_hypothesis for artifact in attempt_artifacts]},
    )


def _validate_replay_hypothesis(
    evidence_pack: Mapping[str, Any],
    payload: Mapping[str, Any],
    proposed_setup: Mapping[str, Any],
    proposed_inputs: Mapping[str, Any],
    expected_sink: Mapping[str, Any],
) -> dict[str, Any]:
    preconditions = extract_preconditions(proposed_setup, proposed_inputs)
    reason_codes: list[str] = []
    details: dict[str, Any] = {"preconditions": preconditions}

    invalid = preconditions.get("invalid") if isinstance(preconditions.get("invalid"), Mapping) else {}
    if invalid:
        reason_codes.append("overbroad_preconditions")

    sink_result = _validate_expected_sink(evidence_pack, expected_sink)
    details["expected_sink"] = sink_result
    if not sink_result.get("accepted"):
        reason_codes.append(str(sink_result.get("reason") or "invalid_expected_sink"))
    oracle_result = _validate_required_process_oracle(evidence_pack, expected_sink)
    if oracle_result:
        details["proof_oracle"] = oracle_result
        if not oracle_result.get("accepted"):
            reason_codes.append(str(oracle_result.get("reason") or "invalid_proof_oracle"))

    if not _has_concrete_replay_surface(preconditions):
        reason_codes.append("missing_concrete_replay_surface")

    if reason_codes:
        return _validator(False, reason_codes, failure_reason=";".join(reason_codes), details=details)

    return _validator(
        True,
        ["replay_ready"],
        details={
            **details,
            "replay_ready": True,
            "validation_command_shape": _validation_command_shape(payload, preconditions),
        },
    )


def _validate_environment_hypothesis(
    evidence_pack: Mapping[str, Any],
    payload: Mapping[str, Any],
    proposed_setup: Mapping[str, Any],
    proposed_inputs: Mapping[str, Any],
    *,
    gold_labels: Mapping[str, Any],
) -> dict[str, Any]:
    preconditions = extract_preconditions(proposed_setup, proposed_inputs)
    details: dict[str, Any] = {"preconditions": preconditions}
    invalid = preconditions.get("invalid") if isinstance(preconditions.get("invalid"), Mapping) else {}
    if invalid:
        return _validator(
            False,
            ["overbroad_preconditions"],
            failure_reason="overbroad_preconditions",
            details=details,
        )

    candidate_id = _candidate_id_from_pack(evidence_pack)
    requirements = _gold_requirements(gold_labels, candidate_id, "environment")
    if not requirements:
        requirements = _gold_requirements(gold_labels, candidate_id, "replay")
    if not requirements:
        if _has_any_precondition(preconditions):
            return _validator(True, ["environment_preconditions_concrete"], details=details)
        return _validator(
            False,
            ["missing_environment_preconditions"],
            failure_reason="missing_environment_preconditions",
            details=details,
        )

    missing: dict[str, list[str]] = {}
    for category in ("routes", "env", "filesystem", "config", "auth"):
        labels = _requirement_labels(requirements.get(category))
        if not labels:
            continue
        values = _precondition_match_values(preconditions, category)
        for label in labels:
            if not _label_covered(label, values):
                missing.setdefault(category, []).append(label)
    details["gold_requirements"] = dict(requirements)
    if missing:
        details["missing_gold_labels"] = missing
        return _validator(
            False,
            ["missing_gold_preconditions"],
            failure_reason="missing_gold_preconditions",
            details=details,
        )
    return _validator(True, ["gold_preconditions_covered"], details=details)


def _validate_branch_guidance_hypothesis(
    evidence_pack: Mapping[str, Any],
    payload: Mapping[str, Any],
    concolic_config: ConcolicToolConfig | None,
) -> dict[str, Any]:
    if concolic_config is None:
        return _validator(
            False,
            ["missing_concolic_config"],
            failure_reason="missing_concolic_config",
            details={"tool_request": _safe_branch_tool_request(payload)},
        )
    try:
        tool_request = branch_guidance_tool_request(payload)
        request = concolic_request_from_tool_request(evidence_pack, tool_request, concolic_config)
    except Exception as exc:
        return _validator(
            False,
            ["invalid_branch_guidance"],
            failure_reason=str(exc)[:1000],
            details={"tool_request": _safe_branch_tool_request(payload)},
        )
    return _validator(
        True,
        ["branch_guidance_bounded"],
        details={
            "tool_request": tool_request,
            "concolic_request": request.to_dict(),
        },
    )


def _validate_triage_hypothesis(
    evidence_pack: Mapping[str, Any],
    payload: Mapping[str, Any],
    *,
    gold_labels: Mapping[str, Any],
) -> dict[str, Any]:
    triage = payload.get("triage")
    if not isinstance(triage, Mapping):
        triage = payload
    decision = _normalize_decision(
        triage.get("decision")
        or triage.get("triage_decision")
        or triage.get("status")
        or payload.get("decision")
        or payload.get("triage_decision")
        or payload.get("status")
    )
    rationale = str(
        triage.get("rationale")
        or triage.get("reason")
        or payload.get("rationale")
        or payload.get("reason")
        or ""
    ).strip()
    root_cause_id = str(triage.get("root_cause_id") or triage.get("group_id") or payload.get("root_cause_id") or "")
    details = {
        "decision": decision,
        "rationale": rationale,
        "root_cause_id": root_cause_id,
        "deterministic_summary": _deterministic_summary(evidence_pack),
    }
    gold_triage = _gold_requirements(gold_labels, _candidate_id_from_pack(evidence_pack), "triage")
    if gold_triage:
        details["gold_triage"] = dict(gold_triage)
    if not decision:
        return _validator(False, ["missing_triage_decision"], failure_reason="missing_triage_decision", details=details)
    if decision in _SUPPRESS_DECISIONS and _has_deterministic_overflow_proof(evidence_pack):
        details["deterministic_override"] = True
        details["pipeline_override"] = False
        if _gold_triage_allows_suppression(gold_triage, decision):
            return _validator(
                True,
                [
                    "triage_hypothesis_accepted",
                    "gold_triage_label_matches_deterministic_false_positive",
                    "deterministic_baseline_disagrees",
                ],
                details=details,
            )
        return _validator(
            False,
            ["deterministic_proof_overrides_llm_triage"],
            failure_reason="deterministic_proof_overrides_llm_triage",
            details=details,
        )
    if decision not in _SUPPRESS_DECISIONS and decision not in _REPORTING_DECISIONS:
        return _validator(False, ["unsupported_triage_decision"], failure_reason="unsupported_triage_decision", details=details)
    if not _is_concrete_text(rationale):
        return _validator(False, ["missing_triage_rationale"], failure_reason="missing_triage_rationale", details=details)
    reason_codes = ["triage_hypothesis_accepted"]
    if decision in _SUPPRESS_DECISIONS:
        reason_codes.append("suppression_candidate")
    if root_cause_id:
        reason_codes.append("root_cause_grouped")
    return _validator(True, reason_codes, details=details)


def _gold_triage_allows_suppression(gold_triage: Mapping[str, Any], decision: str) -> bool:
    if not gold_triage:
        return False
    if bool(gold_triage.get("allow_deterministic_override")):
        return True
    if bool(gold_triage.get("expected_false_positive")) and decision in _SUPPRESS_DECISIONS:
        return True
    expected = _normalize_decision(gold_triage.get("expected_decision") or gold_triage.get("decision"))
    if expected and expected == decision:
        return True
    expected_decisions = [_normalize_decision(item) for item in _coerce_sequence(gold_triage.get("expected_decisions", []))]
    return decision in expected_decisions


def _deterministic_baseline_artifact(evidence_pack: Mapping[str, Any]) -> HypothesisArtifact:
    candidate_id = _candidate_id_from_pack(evidence_pack)
    summary = _deterministic_summary(evidence_pack)
    return HypothesisArtifact(
        candidate_id=candidate_id,
        hypothesis_kind="triage",
        proposed_setup={},
        proposed_inputs={},
        expected_sink=_expected_sink_from_pack(evidence_pack),
        assumptions=[],
        validator_result={
            "accepted": True,
            "status": "accepted",
            "system": "D0",
            "reason_codes": ["deterministic_baseline_recorded"],
            "deterministic_summary": summary,
        },
        failure_reason="",
        cost_metadata={},
        raw_hypothesis={"system": "D0"},
    )


def _missing_fixture_artifact(candidate_id: str, kind: str, system: str) -> HypothesisArtifact:
    return HypothesisArtifact(
        candidate_id=candidate_id,
        hypothesis_kind=kind,
        proposed_setup={},
        proposed_inputs={},
        expected_sink={},
        assumptions=[],
        validator_result={
            "accepted": False,
            "status": "rejected",
            "system": system,
            "reason_codes": ["missing_fixture"],
        },
        failure_reason="missing_fixture",
        cost_metadata={},
        raw_hypothesis={},
    )


def _artifact(
    candidate_id: str,
    hypothesis_kind: str,
    proposed_setup: Mapping[str, Any],
    proposed_inputs: Mapping[str, Any],
    expected_sink: Mapping[str, Any],
    assumptions: Sequence[str],
    validator_result: Mapping[str, Any],
    cost_metadata: Mapping[str, Any],
    raw: Mapping[str, Any],
) -> HypothesisArtifact:
    failure_reason = "" if bool(validator_result.get("accepted")) else str(validator_result.get("failure_reason") or "")
    return HypothesisArtifact(
        candidate_id=candidate_id,
        hypothesis_kind=hypothesis_kind,
        proposed_setup=dict(proposed_setup),
        proposed_inputs=dict(proposed_inputs),
        expected_sink=dict(expected_sink),
        assumptions=[str(item) for item in assumptions],
        validator_result=dict(validator_result),
        failure_reason=failure_reason,
        cost_metadata=dict(cost_metadata),
        raw_hypothesis=dict(raw),
    )


def _artifact_with_validator(artifact: HypothesisArtifact, validator_result: Mapping[str, Any]) -> HypothesisArtifact:
    return HypothesisArtifact(
        candidate_id=artifact.candidate_id,
        hypothesis_kind=artifact.hypothesis_kind,
        proposed_setup=artifact.proposed_setup,
        proposed_inputs=artifact.proposed_inputs,
        expected_sink=artifact.expected_sink,
        assumptions=artifact.assumptions,
        validator_result=dict(validator_result),
        failure_reason="" if bool(validator_result.get("accepted")) else str(validator_result.get("failure_reason") or artifact.failure_reason),
        cost_metadata=artifact.cost_metadata,
        raw_hypothesis=artifact.raw_hypothesis,
    )


def _rejected_artifact(
    candidate_id: str,
    hypothesis_kind: str,
    validator_details: Mapping[str, Any],
    failure_reason: str,
    *,
    raw: Mapping[str, Any],
) -> HypothesisArtifact:
    return HypothesisArtifact(
        candidate_id=candidate_id,
        hypothesis_kind=hypothesis_kind,
        proposed_setup={},
        proposed_inputs={},
        expected_sink={},
        assumptions=[],
        validator_result=_validator(False, [failure_reason], failure_reason=failure_reason, details=dict(validator_details)),
        failure_reason=failure_reason,
        cost_metadata={},
        raw_hypothesis=dict(raw),
    )


def _validator(
    accepted: bool,
    reason_codes: Sequence[str],
    *,
    failure_reason: str = "",
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "accepted": bool(accepted),
        "status": "accepted" if accepted else "rejected",
        "reason_codes": [str(item) for item in reason_codes],
        "failure_reason": "" if accepted else str(failure_reason or (reason_codes[0] if reason_codes else "")),
        "details": dict(details or {}),
    }


def _infer_hypothesis_kind(payload: Mapping[str, Any]) -> str:
    explicit = str(payload.get("hypothesis_kind") or payload.get("kind") or "").strip()
    if explicit:
        return explicit
    if "branch_guidance" in payload or _first_tool_request(payload) is not None:
        return "branch_guidance"
    if "triage" in payload or "triage_decision" in payload or "root_cause_id" in payload:
        return "triage"
    if "proposed_setup" in payload or "proposed_inputs" in payload:
        return "replay"
    return ""


def _validate_expected_sink(evidence_pack: Mapping[str, Any], expected_sink: Mapping[str, Any]) -> dict[str, Any]:
    sink = _coerce_mapping(expected_sink)
    if not sink:
        return {"accepted": False, "reason": "missing_expected_sink"}
    candidate = _candidate(evidence_pack)
    sink_name = str(sink.get("sink") or sink.get("sink_name") or "").strip()
    candidate_sink = str(candidate.get("sink") or "").strip()
    if sink_name and candidate_sink and sink_name.lower() != candidate_sink.lower():
        return {"accepted": False, "reason": "sink_mismatch", "expected": candidate_sink, "actual": sink_name}
    function_name = str(sink.get("function_name") or sink.get("function") or "").strip()
    candidate_function = str(candidate.get("function_name") or "").strip()
    if function_name and candidate_function and function_name != candidate_function:
        return {
            "accepted": False,
            "reason": "function_mismatch",
            "expected": candidate_function,
            "actual": function_name,
        }
    address = _normalize_address(
        sink.get("operation_address")
        or sink.get("sink_address")
        or sink.get("target_address")
        or sink.get("address")
    )
    allowed = _allowed_addresses(evidence_pack)
    if address and allowed and address not in allowed:
        return {
            "accepted": False,
            "reason": "sink_address_not_in_evidence_pack",
            "address": address,
            "allowed_addresses": sorted(allowed),
        }
    proof_address_result = _validate_proof_oracle_addresses(evidence_pack, sink)
    if not proof_address_result.get("accepted", True):
        return proof_address_result
    if not (sink_name or function_name or address):
        return {"accepted": False, "reason": "expected_sink_not_concrete"}
    return {"accepted": True, "sink": sink_name, "function_name": function_name, "address": address}


def _validate_required_process_oracle(evidence_pack: Mapping[str, Any], expected_sink: Mapping[str, Any]) -> dict[str, Any]:
    expected_kind = _required_process_oracle_kind(evidence_pack)
    if not expected_kind:
        return {}
    oracle = _proof_oracle_from_expected_sink(expected_sink)
    if not oracle:
        return {
            "accepted": False,
            "reason": "missing_class_proof_oracle",
            "expected_kind": expected_kind,
        }
    actual_kind = str(oracle.get("kind") or oracle.get("type") or "").strip()
    if actual_kind != expected_kind:
        return {
            "accepted": False,
            "reason": "proof_oracle_kind_mismatch",
            "expected_kind": expected_kind,
            "actual_kind": actual_kind,
        }
    return {"accepted": True, "kind": actual_kind}


def _required_process_oracle_kind(evidence_pack: Mapping[str, Any]) -> str:
    return _PROCESS_VULN_PROOF_ORACLES.get(_vulnerability_type_from_pack(evidence_pack), "")


def _vulnerability_type_from_pack(evidence_pack: Mapping[str, Any]) -> str:
    candidate = _candidate(evidence_pack)
    if candidate.get("vulnerability_type"):
        return str(candidate.get("vulnerability_type") or "").strip()
    for source in (
        evidence_pack,
        _facts(evidence_pack),
        evidence_pack.get("candidate"),
        evidence_pack.get("type_facts"),
        _facts(evidence_pack).get("semantic_seed"),
    ):
        if isinstance(source, Mapping) and source.get("vulnerability_type"):
            return str(source.get("vulnerability_type") or "").strip()
    return ""


def _proof_oracle_from_expected_sink(expected_sink: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("proof_oracle", "overflow_oracle", "dynamic_overflow_oracle"):
        oracle = expected_sink.get(key)
        if isinstance(oracle, Mapping):
            return oracle
    return {}


def _validate_proof_oracle_addresses(evidence_pack: Mapping[str, Any], expected_sink: Mapping[str, Any]) -> dict[str, Any]:
    """Reject proof-oracle addresses that are not explicitly exposed as facts.

    Older evaluation fixtures did not include a proof-address allowlist.  In
    that compatibility case this check is intentionally inert.  Automated
    replay evidence packs expose ``allowed_proof_addresses``/``proof_oracle_facts``
    and therefore get strict address validation.
    """

    oracle = {}
    for key in ("proof_oracle", "overflow_oracle", "dynamic_overflow_oracle"):
        value = expected_sink.get(key)
        if isinstance(value, Mapping):
            oracle = value
            break
    if not oracle:
        return {"accepted": True}
    allowed = _proof_allowed_addresses(evidence_pack)
    if not allowed:
        return {"accepted": True}
    rejected: dict[str, str] = {}
    for key in (
        "function_address",
        "allocation_call_address",
        "allocation_return_address",
        "sink_call_address",
        "sink_return_address",
        "call_address",
    ):
        address = _normalize_address(oracle.get(key))
        if address and address not in allowed:
            rejected[key] = address
    if rejected:
        return {
            "accepted": False,
            "reason": "proof_address_not_in_evidence_pack",
            "rejected_addresses": rejected,
            "allowed_addresses": sorted(allowed),
        }
    return {"accepted": True}


def _extract_routes(
    setup: Mapping[str, Any],
    inputs: Mapping[str, Any],
    invalid: dict[str, list[str]],
) -> list[dict[str, str]]:
    values: list[Any] = []
    for source in (setup, inputs):
        for key in ("route", "routes", "request_route", "url", "uri", "endpoint", "handler"):
            values.extend(_coerce_sequence(source.get(key, [])))
        http = source.get("http") or source.get("request")
        if isinstance(http, Mapping):
            route_value = http.get("route") or http.get("path") or http.get("url") or http.get("uri")
            if route_value:
                values.append({"path": route_value, "method": http.get("method", "")})
    routes: list[dict[str, str]] = []
    for item in values:
        if isinstance(item, Mapping):
            route = {
                str(key): str(value)
                for key, value in item.items()
                if key in {"method", "path", "route", "url", "handler", "factory", "name"} and str(value).strip()
            }
        else:
            route = {"path": str(item)}
        if any(_is_concrete_text(value) for value in route.values()):
            routes.append(route)
        elif route:
            invalid["routes"].append(json.dumps(route, sort_keys=True))
    return routes


def _extract_services(
    setup: Mapping[str, Any],
    inputs: Mapping[str, Any],
    invalid: dict[str, list[str]],
) -> list[dict[str, str]]:
    values: list[Any] = []
    for source in (setup, inputs):
        for key in ("service", "services", "socket", "sockets", "listener", "listeners", "daemon"):
            values.extend(_coerce_sequence(source.get(key, [])))
        if any(key in source for key in ("host", "port", "protocol")):
            values.append(source)
    services: list[dict[str, str]] = []
    for item in values:
        if isinstance(item, Mapping):
            service = {
                str(key): str(value)
                for key, value in item.items()
                if key in {"host", "port", "protocol", "scheme", "path", "name", "unix_socket", "port_env"} and str(value).strip()
            }
        else:
            service = {"name": str(item)}
        concrete_values = [service.get(key, "") for key in ("host", "port", "unix_socket", "port_env", "name")]
        if any(_is_concrete_text(value, allow_glob=True) for value in concrete_values):
            services.append(service)
        elif service:
            invalid["services"].append(json.dumps(service, sort_keys=True))
    return services


def _extract_env(
    setup: Mapping[str, Any],
    inputs: Mapping[str, Any],
    invalid: dict[str, list[str]],
) -> dict[str, str]:
    env: dict[str, str] = {}
    for source in (setup, inputs):
        for key in ("env", "environment", "environment_variables", "cgi_env"):
            value = source.get(key)
            if isinstance(value, Mapping):
                for env_key, env_value in value.items():
                    text_key = str(env_key).strip()
                    if _is_concrete_text(text_key, allow_glob=True):
                        env[text_key] = str(env_value)
                    else:
                        invalid["env"].append(text_key)
            else:
                for item in _coerce_sequence(value):
                    text = str(item).strip()
                    if "=" in text:
                        env_key, env_value = text.split("=", 1)
                    else:
                        env_key, env_value = text, ""
                    if _is_concrete_text(env_key, allow_glob=True):
                        env[env_key.strip()] = env_value.strip()
                    elif env_key:
                        invalid["env"].append(env_key)
    return env


def _extract_filesystem(
    setup: Mapping[str, Any],
    inputs: Mapping[str, Any],
    invalid: dict[str, list[str]],
) -> list[dict[str, str]]:
    values: list[Any] = []
    for source in (setup, inputs):
        for key in ("filesystem", "file_system", "files", "required_files", "file_setup", "paths", "file_inputs"):
            values.extend(_coerce_sequence(source.get(key, [])))
    files: list[dict[str, str]] = []
    for item in values:
        if isinstance(item, Mapping):
            entry = {
                str(key): str(value)
                for key, value in item.items()
                if key in {"path", "pattern", "name", "content", "mode", "min_length", "directory"} and str(value).strip()
            }
        else:
            entry = {"path": str(item)}
        concrete_values = [entry.get(key, "") for key in ("path", "pattern", "name", "directory")]
        if any(_is_concrete_text(value, allow_glob=True) for value in concrete_values):
            files.append(entry)
        elif entry:
            invalid["filesystem"].append(json.dumps(entry, sort_keys=True))
    return files


def _extract_named_mapping(
    setup: Mapping[str, Any],
    inputs: Mapping[str, Any],
    keys: Sequence[str],
    category: str,
    invalid: dict[str, list[str]],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for source in (setup, inputs):
        for key in keys:
            value = source.get(key)
            if isinstance(value, Mapping):
                for item_key, item_value in value.items():
                    text_key = str(item_key).strip()
                    if _is_concrete_text(text_key, allow_glob=True):
                        result[text_key] = str(item_value)
                    else:
                        invalid[category].append(text_key)
            else:
                for item in _coerce_sequence(value):
                    text = str(item).strip()
                    if "=" in text:
                        item_key, item_value = text.split("=", 1)
                    else:
                        item_key, item_value = text, ""
                    if _is_concrete_text(item_key, allow_glob=True):
                        result[item_key.strip()] = item_value.strip()
                    elif item_key:
                        invalid[category].append(item_key)
    return result


def _extract_input_surfaces(inputs: Mapping[str, Any], invalid: dict[str, list[str]]) -> list[dict[str, Any]]:
    surfaces: list[dict[str, Any]] = []
    for key in (
        "argv",
        "stdin",
        "body",
        "query",
        "params",
        "form",
        "cookies",
        "headers",
        "request",
        "payload",
        "message",
        "data",
        "line",
        "command",
        "script",
        "file_inputs",
        "file_path",
        "filename",
        "config_path",
        "config_value",
    ):
        if key not in inputs:
            continue
        value = inputs.get(key)
        concrete = _value_has_concrete_text(value)
        if concrete:
            surfaces.append({"kind": key, "value": value})
        else:
            invalid["inputs"].append(key)
    return surfaces


def _extract_validation_commands(
    setup: Mapping[str, Any],
    inputs: Mapping[str, Any],
    invalid: dict[str, list[str]],
) -> list[str]:
    commands: list[str] = []
    for source in (setup, inputs):
        for key in ("validation_command", "validation_commands", "command", "commands"):
            for value in _coerce_sequence(source.get(key, [])):
                text = str(value).strip()
                if _is_concrete_text(text):
                    commands.append(text)
                elif text:
                    invalid["validation_commands"].append(text)
    return commands


def _validation_command_shape(payload: Mapping[str, Any], preconditions: Mapping[str, Any]) -> str:
    command = str(payload.get("validation_command") or "").strip()
    if command:
        return command
    commands = _coerce_sequence(preconditions.get("validation_commands", []))
    return str(commands[0]) if commands else ""


def _has_concrete_replay_surface(preconditions: Mapping[str, Any]) -> bool:
    return any(
        bool(preconditions.get(key))
        for key in ("routes", "env", "filesystem", "config", "auth", "inputs", "validation_commands")
    )


def _has_any_precondition(preconditions: Mapping[str, Any]) -> bool:
    return any(bool(preconditions.get(key)) for key in ("routes", "services", "env", "filesystem", "config", "auth"))


def _gold_requirements(gold_labels: Mapping[str, Any], candidate_id: str, kind: str) -> Mapping[str, Any]:
    candidates = gold_labels.get("candidates") if isinstance(gold_labels.get("candidates"), Mapping) else gold_labels
    entry = candidates.get(candidate_id) if isinstance(candidates, Mapping) else None
    if not isinstance(entry, Mapping):
        return {}
    direct = entry.get(kind)
    if isinstance(direct, Mapping):
        return direct
    labels = entry.get("gold_labels")
    if isinstance(labels, Mapping) and isinstance(labels.get(kind), Mapping):
        return labels[kind]
    if kind == "environment":
        return {
            key: entry.get(key)
            for key in ("routes", "env", "filesystem", "config", "auth")
            if key in entry
        }
    return {}


def _requirement_labels(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        return [str(key) for key in value.keys()]
    return [str(item) for item in _coerce_sequence(value)]


def _precondition_match_values(preconditions: Mapping[str, Any], category: str) -> list[str]:
    values: list[str] = []
    if category == "routes":
        for route in _coerce_sequence(preconditions.get("routes", [])):
            if isinstance(route, Mapping):
                values.extend(str(value) for value in route.values())
            else:
                values.append(str(route))
        return values
    if category in {"env", "config", "auth"}:
        mapping = preconditions.get(category)
        if isinstance(mapping, Mapping):
            for key, value in mapping.items():
                values.append(str(key))
                if value not in (None, ""):
                    values.append(f"{key}={value}")
        return values
    if category == "filesystem":
        for entry in _coerce_sequence(preconditions.get("filesystem", [])):
            if isinstance(entry, Mapping):
                values.extend(str(value) for value in entry.values())
            else:
                values.append(str(entry))
        return values
    return values


def _label_covered(label: str, values: Sequence[str]) -> bool:
    wanted = str(label).strip()
    if not wanted:
        return True
    for value in values:
        observed = str(value).strip()
        if not observed:
            continue
        if observed == wanted:
            return True
        if wanted in observed or observed in wanted:
            return True
        if "*" in wanted and fnmatch.fnmatchcase(observed, wanted):
            return True
        if "*" in observed and fnmatch.fnmatchcase(wanted, observed):
            return True
    return False


def _safe_branch_tool_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return branch_guidance_tool_request(payload)
    except Exception as exc:
        return {"error": str(exc)[:500]}


def _first_tool_request(payload: Mapping[str, Any]) -> Mapping[str, Any] | None:
    if str(payload.get("tool") or "") == CONCOLIC_TOOL_NAME:
        return payload
    candidates: list[Any] = []
    for key in ("tool_requests", "actions", "requests", "llm_concolic_requests"):
        candidates.extend(_coerce_sequence(payload.get(key, [])))
    for key in ("branch_guidance", "llm_actions", "controller_actions", "controller_context"):
        container = payload.get(key)
        if isinstance(container, Mapping):
            candidates.extend(_coerce_sequence(container.get("tool_requests", [])))
            candidates.extend(_coerce_sequence(container.get("requests", [])))
            if str(container.get("tool") or "") == CONCOLIC_TOOL_NAME:
                candidates.append(container)
    for item in candidates:
        if isinstance(item, Mapping) and str(item.get("tool") or "") == CONCOLIC_TOOL_NAME:
            return item
    return None


def _normalize_decision(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "safe": "likely_safe",
        "bounded": "bounded_safe",
        "bounded_format": "bounded_safe",
        "false_positive_suppression": "false_positive",
        "not_bug": "not_a_bug",
        "bug": "likely_bug",
        "root_cause": "group_root_cause",
    }
    return aliases.get(text, text)


def _has_deterministic_overflow_proof(evidence_pack: Mapping[str, Any]) -> bool:
    candidate = _candidate(evidence_pack)
    verdict = str(candidate.get("verdict") or "").lower()
    relation = str(candidate.get("write_relation") or candidate.get("relation") or "").lower()
    if verdict in {"overflow", "proven_overflow", "confirmed_bug"}:
        return True
    if relation in {"proven_overflow", "overflow_proven"}:
        return True
    proof = evidence_pack.get("proof_obligation")
    if isinstance(proof, Mapping):
        proof_relation = str(proof.get("relation") or "").lower()
        if proof_relation in {"proven_overflow", "overflow_proven"}:
            return True
    for result in _coerce_sequence(evidence_pack.get("tool_results", [])):
        if not isinstance(result, Mapping):
            continue
        nested = result.get("result")
        if isinstance(nested, Mapping):
            proof_payload = nested.get("ghidra_dynamic_proof")
            if isinstance(proof_payload, Mapping) and proof_payload.get("status") == "overflow_proven":
                return True
        proof_payload = result.get("ghidra_dynamic_proof")
        if isinstance(proof_payload, Mapping) and proof_payload.get("status") == "overflow_proven":
            return True
    return False


def _deterministic_summary(evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    candidate = _candidate(evidence_pack)
    capacity = _safe_int(candidate.get("capacity_bytes"), default=0)
    write_size = _safe_int(candidate.get("write_size_bytes"), default=0)
    return {
        "candidate_id": _candidate_id_from_pack(evidence_pack),
        "function_name": str(candidate.get("function_name") or ""),
        "operation_address": _normalize_address(candidate.get("operation_address")),
        "sink": str(candidate.get("sink") or ""),
        "capacity_bytes": capacity,
        "write_size_bytes": write_size,
        "write_relation": str(candidate.get("write_relation") or ""),
        "verdict": str(candidate.get("verdict") or ""),
        "overflow_proven": _has_deterministic_overflow_proof(evidence_pack),
        "bounded_by_capacity": bool(capacity > 0 and write_size > 0 and write_size <= capacity),
    }


def _expected_sink_from_pack(evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    candidate = _candidate(evidence_pack)
    return {
        "function_name": str(candidate.get("function_name") or ""),
        "sink": str(candidate.get("sink") or ""),
        "operation_address": _normalize_address(candidate.get("operation_address")),
    }


def _load_fixture_payload(fixtures_dir: Path | None, system: str, candidate_id: str) -> Mapping[str, Any] | None:
    if fixtures_dir is None:
        return None
    safe = _safe_stem(candidate_id)
    candidates = [
        fixtures_dir / system / f"{safe}.json",
        fixtures_dir / system.lower() / f"{safe}.json",
        fixtures_dir / f"{system}_{safe}.json",
        fixtures_dir / f"{system.lower()}_{safe}.json",
        fixtures_dir / f"{safe}_{system}.json",
        fixtures_dir / f"{safe}_{system.lower()}.json",
        fixtures_dir / f"{safe}.json",
    ]
    for path in candidates:
        if not path.exists():
            continue
        payload = json.loads(path.read_text() or "{}")
        if not isinstance(payload, Mapping):
            raise ValueError(f"Fixture must contain a JSON object: {path}")
        return dict(payload)
    return None


def _hypotheses_from_payload(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    hypotheses = payload.get("hypotheses")
    if hypotheses is None:
        return [payload]
    result = [item for item in _coerce_sequence(hypotheses) if isinstance(item, Mapping)]
    return result or [payload]


def _system_metrics(artifacts: Sequence[HypothesisArtifact]) -> dict[str, Any]:
    by_kind: dict[str, dict[str, int]] = {}
    for artifact in artifacts:
        kind_counts = by_kind.setdefault(artifact.hypothesis_kind, {"accepted": 0, "rejected": 0})
        if artifact.accepted:
            kind_counts["accepted"] += 1
        else:
            kind_counts["rejected"] += 1
    cost = _aggregate_costs(artifacts)
    return {
        "artifact_count": len(artifacts),
        "accepted": sum(1 for artifact in artifacts if artifact.accepted),
        "rejected": sum(1 for artifact in artifacts if not artifact.accepted),
        "missing_fixture": sum(1 for artifact in artifacts if artifact.failure_reason == "missing_fixture"),
        "deterministic_overrides": sum(
            1
            for artifact in artifacts
            if bool(_nested_details(artifact).get("deterministic_override", False))
        ),
        "replay_ready": sum(
            1
            for artifact in artifacts
            if artifact.hypothesis_kind == "replay" and artifact.accepted
        ),
        "environment_covered": sum(
            1
            for artifact in artifacts
            if artifact.hypothesis_kind == "environment" and artifact.accepted
        ),
        "branch_guidance_valid": sum(
            1
            for artifact in artifacts
            if artifact.hypothesis_kind == "branch_guidance" and artifact.accepted
        ),
        "triage_accepted": sum(
            1
            for artifact in artifacts
            if artifact.hypothesis_kind == "triage" and artifact.accepted
        ),
        "by_kind": by_kind,
        "cost": cost,
    }


def _lift_record(
    system: str,
    artifact: HypothesisArtifact,
    baseline_status: str,
    replay_result: Mapping[str, Any] | Any | None,
) -> dict[str, Any]:
    validator_accepted = artifact.accepted
    replay_attempted = _replay_attempted(replay_result)
    sink_reached = bool(_result_value(replay_result, "sink_reached", False)) if replay_result is not None else False
    bug_observed = bool(_result_value(replay_result, "bug_observed", False)) if replay_result is not None else False
    blocker_removed = _blocker_removed(artifact, replay_attempted, sink_reached, bug_observed)
    lift = _classify_lift(artifact, replay_result, replay_attempted, sink_reached, bug_observed, blocker_removed)
    return {
        "candidate_id": artifact.candidate_id,
        "system": system,
        "baseline_status": baseline_status,
        "llm_role": _llm_role_for_kind(artifact.hypothesis_kind),
        "hypothesis_kind": artifact.hypothesis_kind,
        "validator_accepted": validator_accepted,
        "blocker_removed": blocker_removed,
        "replay_attempted": replay_attempted,
        "sink_reached": sink_reached,
        "bug_observed": bug_observed,
        "lift": lift,
    }


def _classify_lift(
    artifact: HypothesisArtifact,
    replay_result: Mapping[str, Any] | Any | None,
    replay_attempted: bool,
    sink_reached: bool,
    bug_observed: bool,
    blocker_removed: bool,
) -> str:
    if artifact.validator_result.get("system") == "D0":
        return "no_lift"
    if not artifact.accepted:
        return "no_lift"
    if replay_attempted and sink_reached and bug_observed:
        return "proof_lift"
    if artifact.hypothesis_kind == "branch_guidance":
        if replay_attempted and sink_reached:
            return "branch_lift"
        return "schema_lift_only"
    if artifact.hypothesis_kind == "replay":
        if replay_attempted:
            return "replay_lift"
        return "schema_lift_only"
    if artifact.hypothesis_kind == "environment":
        reason_codes = _reason_codes(artifact)
        details = _nested_details(artifact)
        if "gold_preconditions_covered" in reason_codes or (
            "gold_requirements" in details and "missing_gold_labels" not in details
        ):
            return "environment_lift"
        return "schema_lift_only"
    if artifact.hypothesis_kind == "triage":
        details = _nested_details(artifact)
        decision = str(details.get("decision") or "")
        reason_codes = _reason_codes(artifact)
        if "root_cause_grouped" in reason_codes or "suppression_candidate" in reason_codes or "gold_triage" in details:
            return "triage_lift"
        if decision in _REPORTING_DECISIONS and decision not in {"needs_more_evidence", "needs_dynamic_confirmation"}:
            return "report_lift" if blocker_removed else "schema_lift_only"
        return "schema_lift_only"
    return "schema_lift_only"


def _blocker_removed(
    artifact: HypothesisArtifact,
    replay_attempted: bool,
    sink_reached: bool,
    bug_observed: bool,
) -> bool:
    if not artifact.accepted:
        return False
    if replay_attempted and (sink_reached or bug_observed):
        return True
    reason_codes = set(_reason_codes(artifact))
    if artifact.hypothesis_kind == "environment":
        return "gold_preconditions_covered" in reason_codes
    if artifact.hypothesis_kind == "triage":
        details = _nested_details(artifact)
        return bool(
            "root_cause_grouped" in reason_codes
            or "suppression_candidate" in reason_codes
            or "gold_triage" in details
        )
    return False


def _baseline_status(artifact: HypothesisArtifact) -> str:
    summary = artifact.validator_result.get("deterministic_summary")
    if not isinstance(summary, Mapping):
        details = _nested_details(artifact)
        summary = details.get("deterministic_summary") if isinstance(details.get("deterministic_summary"), Mapping) else {}
    if bool(summary.get("overflow_proven")):
        return "overflow_proven"
    if bool(summary.get("bounded_by_capacity")) or str(summary.get("verdict") or "").lower() == "bounded":
        return "bounded"
    relation = str(summary.get("write_relation") or "").strip()
    verdict = str(summary.get("verdict") or "").strip()
    if verdict or relation:
        return verdict or relation
    return "recorded"


def _llm_role_for_kind(kind: str) -> str:
    return {
        "environment": "environment_infer",
        "replay": "replay_plan",
        "branch_guidance": "branch_guide",
        "triage": "triage",
        "report_draft": "report_draft",
    }.get(str(kind or ""), "unknown")


def _reason_codes(artifact: HypothesisArtifact) -> list[str]:
    return [str(item) for item in artifact.validator_result.get("reason_codes", []) or []]


def _replay_attempted(result: Mapping[str, Any] | Any | None) -> bool:
    if result is None:
        return False
    status = str(_result_value(result, "result") or "")
    return status not in {"", "not_attempted", "setup_invalid", "blocked"}


def _result_value(result: Mapping[str, Any] | Any | None, name: str, default: Any = "") -> Any:
    if result is None:
        return default
    if isinstance(result, Mapping):
        return result.get(name, default)
    return getattr(result, name, default)


def _coerce_artifact(value: HypothesisArtifact | Mapping[str, Any]) -> HypothesisArtifact:
    if isinstance(value, HypothesisArtifact):
        return value
    return HypothesisArtifact(
        candidate_id=str(value.get("candidate_id") or ""),
        hypothesis_kind=str(value.get("hypothesis_kind") or ""),
        proposed_setup=dict(value.get("proposed_setup") or {}) if isinstance(value.get("proposed_setup"), Mapping) else {},
        proposed_inputs=dict(value.get("proposed_inputs") or {}) if isinstance(value.get("proposed_inputs"), Mapping) else {},
        expected_sink=dict(value.get("expected_sink") or {}) if isinstance(value.get("expected_sink"), Mapping) else {},
        assumptions=[str(item) for item in _coerce_sequence(value.get("assumptions", []))],
        validator_result=dict(value.get("validator_result") or {}) if isinstance(value.get("validator_result"), Mapping) else {},
        failure_reason=str(value.get("failure_reason") or ""),
        cost_metadata=dict(value.get("cost_metadata") or {}) if isinstance(value.get("cost_metadata"), Mapping) else {},
        raw_hypothesis=dict(value.get("raw_hypothesis") or {}) if isinstance(value.get("raw_hypothesis"), Mapping) else {},
    )


def _nested_details(artifact: HypothesisArtifact) -> Mapping[str, Any]:
    details = artifact.validator_result.get("details")
    return details if isinstance(details, Mapping) else {}


def _aggregate_costs(artifacts: Sequence[HypothesisArtifact]) -> dict[str, Any]:
    totals = {
        "model_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "wall_time_seconds": 0.0,
    }
    for artifact in artifacts:
        cost = artifact.cost_metadata
        totals["model_calls"] += _safe_int(cost.get("model_calls"), default=0)
        totals["input_tokens"] += _safe_int(cost.get("input_tokens"), default=0)
        totals["output_tokens"] += _safe_int(cost.get("output_tokens"), default=0)
        total_tokens = _safe_int(cost.get("total_tokens"), default=0)
        if total_tokens <= 0:
            total_tokens = _safe_int(cost.get("input_tokens"), default=0) + _safe_int(cost.get("output_tokens"), default=0)
        totals["total_tokens"] += total_tokens
        try:
            totals["wall_time_seconds"] += float(cost.get("wall_time_seconds") or 0.0)
        except (TypeError, ValueError):
            pass
    return totals


def _merge_attempt_costs(artifacts: Sequence[HypothesisArtifact]) -> dict[str, Any]:
    return _aggregate_costs(artifacts)


def _is_concrete_text(value: Any, *, allow_glob: bool = False) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    lowered = re.sub(r"\s+", " ", text.lower())
    if lowered in _GENERIC_TEXT:
        return False
    if not allow_glob and any(char in text for char in "*?") and text.strip("*? /") == "":
        return False
    if allow_glob and text.strip("*? /") == "":
        return False
    if lowered.startswith(("any ", "some ", "whatever")):
        return False
    return True


def _value_has_concrete_text(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(_is_concrete_text(key, allow_glob=True) or _value_has_concrete_text(item) for key, item in value.items())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_value_has_concrete_text(item) for item in value)
    return _is_concrete_text(value, allow_glob=True)


def _candidate_id_from_pack(evidence_pack: Mapping[str, Any]) -> str:
    candidate_id = str(evidence_pack.get("candidate_id") or "").strip()
    if candidate_id:
        return candidate_id
    candidate = _candidate(evidence_pack)
    return str(candidate.get("candidate_id") or "").strip()


def _candidate(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    candidate = evidence_pack.get("deterministic_candidate")
    if isinstance(candidate, Mapping):
        return candidate
    # Evidence-pack v3 is state-shaped rather than legacy StaticCandidate-shaped.
    v3_candidate = evidence_pack.get("candidate")
    location = evidence_pack.get("location")
    sink = evidence_pack.get("sink")
    type_facts = evidence_pack.get("type_facts")
    if not any(isinstance(item, Mapping) for item in (v3_candidate, location, sink, type_facts)):
        return {}
    candidate_map = dict(v3_candidate) if isinstance(v3_candidate, Mapping) else {}
    location_map = dict(location) if isinstance(location, Mapping) else {}
    sink_map = dict(sink) if isinstance(sink, Mapping) else {}
    facts_map = dict(type_facts) if isinstance(type_facts, Mapping) else {}
    static_candidate = facts_map.get("static_candidate")
    if isinstance(static_candidate, Mapping):
        merged = dict(static_candidate)
    else:
        merged = {}
    merged.update(
        {
            "candidate_id": candidate_map.get("candidate_id") or merged.get("candidate_id", ""),
            "vulnerability_type": candidate_map.get("vulnerability_type") or facts_map.get("vulnerability_type") or merged.get("vulnerability_type", ""),
            "function_name": location_map.get("function_name") or candidate_map.get("function_name") or merged.get("function_name", ""),
            "address": location_map.get("address") or candidate_map.get("address") or merged.get("address", ""),
            "operation_address": sink_map.get("operation_address")
            or candidate_map.get("operation_address")
            or facts_map.get("operation_address")
            or merged.get("operation_address", ""),
            "sink": sink_map.get("name") or candidate_map.get("sink") or merged.get("sink", ""),
            "target_buffer": sink_map.get("target_buffer") or candidate_map.get("target_buffer") or merged.get("target_buffer", ""),
            "capacity_bytes": facts_map.get("capacity_bytes", merged.get("capacity_bytes", 0)),
            "write_size_bytes": facts_map.get("write_size_bytes", merged.get("write_size_bytes")),
            "write_relation": facts_map.get("write_relation", merged.get("write_relation", "")),
            "verdict": facts_map.get("verdict", merged.get("verdict", "")),
        }
    )
    return merged


def _facts(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    facts = evidence_pack.get("facts_available_to_llm")
    return facts if isinstance(facts, Mapping) else {}


def _allowed_addresses(evidence_pack: Mapping[str, Any]) -> set[str]:
    addresses: set[str] = set()
    candidate = _candidate(evidence_pack)
    for key in ("address", "operation_address"):
        address = _normalize_address(candidate.get(key))
        if address:
            addresses.add(address)
    facts = _facts(evidence_pack)
    for row in _coerce_sequence(facts.get("write_table", [])):
        if isinstance(row, Mapping):
            for key in ("operation_address", "address", "target_address"):
                address = _normalize_address(row.get(key))
                if address:
                    addresses.add(address)
    for key in ("exact_sink_address", "llm_exact_sink_address"):
        address = _normalize_address(facts.get(key))
        if address:
            addresses.add(address)
    pcode_slice = facts.get("pcode_slice")
    if isinstance(pcode_slice, Mapping):
        address = _normalize_address(pcode_slice.get("operation_address"))
        if address:
            addresses.add(address)
    return addresses


def _proof_allowed_addresses(evidence_pack: Mapping[str, Any]) -> set[str]:
    addresses: set[str] = set()
    for source in (evidence_pack, _facts(evidence_pack)):
        for key in ("allowed_proof_addresses", "proof_allowed_addresses"):
            for item in _coerce_sequence(source.get(key, [])):
                address = _normalize_address(item)
                if address:
                    addresses.add(address)
        facts = source.get("proof_oracle_facts")
        if isinstance(facts, Mapping):
            addresses.update(_address_values_from_known_fact_container(facts))
    type_facts = evidence_pack.get("type_facts")
    if isinstance(type_facts, Mapping):
        for key in (
            "allocation_call_address",
            "allocation_return_address",
            "sink_call_address",
            "sink_return_address",
        ):
            address = _normalize_address(type_facts.get(key))
            if address:
                addresses.add(address)
    return addresses


def _address_values_from_known_fact_container(value: Any) -> set[str]:
    addresses: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            if key_text.endswith("_address") or key_text in {"address", "call_address", "return_address"}:
                address = _normalize_address(item)
                if address:
                    addresses.add(address)
            elif isinstance(item, (Mapping, list, tuple)):
                addresses.update(_address_values_from_known_fact_container(item))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            addresses.update(_address_values_from_known_fact_container(item))
    return addresses


def _normalize_address(value: Any) -> str:
    parsed = _parse_address(value)
    return f"0x{parsed:x}" if parsed is not None else ""


def _parse_address(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    text = str(value).strip()
    if not text or not re.match(r"^0x[0-9a-fA-F]+$|^[0-9]+$", text):
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _coerce_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _coerce_sequence(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return list(value)
    return [value]


def _coerce_string_list(value: Any) -> list[str]:
    return [str(item) for item in _coerce_sequence(value) if str(item).strip()]


def _is_sequence_like(value: Any) -> bool:
    return isinstance(value, str) or (
        isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray))
    )


def _safe_int(value: Any, *, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return default


def _safe_stem(candidate_id: str) -> str:
    safe = re.sub(r"[^0-9A-Za-z_.-]+", "_", str(candidate_id)).strip("_")
    if not safe:
        safe = "candidate"
    if len(safe) > 140:
        digest = hashlib.sha1(str(candidate_id).encode("utf-8")).hexdigest()[:12]
        safe = f"{safe[:127].rstrip('_')}_{digest}"
    return safe
