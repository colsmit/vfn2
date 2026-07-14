"""Lean artifact-bound vulnerability reports for the end-to-end pipeline."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.analysis.provenance import source_read_wrapper_chain_from_candidate, source_read_wrapper_chain_text
from binary_agent.pipeline import (
    CandidateState,
    CandidateStatus,
    build_bug_bounty_evidence,
    build_source_to_sink_trace,
    has_reportable_bug_bounty_evidence,
    has_reportable_source_to_sink,
)
from binary_agent.taxonomy import get_vulnerability_spec


@dataclass(frozen=True)
class ClaimCheckResult:
    accepted: bool
    unsupported_claims: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LeanVulnerabilityReport:
    title: str
    target: Mapping[str, Any]
    vulnerability: str
    confidence_level: str
    confidence_evidence: list[str]
    affected_component: str
    root_cause: str
    attacker_controlled_input: str
    proof_path: list[str]
    replay_steps: list[str]
    impact: str
    artifacts: list[str]
    evidence_scope: list[str]
    suggested_fix: str
    candidate_id: str
    backend: str = ""
    mechanism: str = ""
    effect_kind: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    severity: str = ""
    proof_result: Mapping[str, Any] = field(default_factory=dict)
    proof_details: Mapping[str, Any] = field(default_factory=dict)
    claim_check: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def check_report_claims(report: Mapping[str, Any], state: CandidateState) -> ClaimCheckResult:
    """Reject claims that are not backed by explicit candidate artifacts."""
    text = json.dumps(report, sort_keys=True).lower()
    unsupported: list[str] = []
    facts = dict(state.type_facts)
    target = dict(state.target)
    source = dict(state.source)
    has_replay = bool(state.replay_artifacts)
    crash_backed = bool(facts.get("crash_observed")) or any("native_transcript" in item for item in state.replay_artifacts)

    if re.search(r"\b(network reachable|remote|over the network)\b", text):
        if not (target.get("network_reachable") or source.get("route") or facts.get("route")):
            unsupported.append("network_reachability")
    if "unauthenticated" in text:
        if not (facts.get("unauthenticated") or source.get("auth") == "unauthenticated"):
            unsupported.append("unauthenticated_access")
    if re.search(r"\b(rce|remote code execution)\b", text):
        if not (state.vulnerability_type == "command_injection" and has_replay and facts.get("command_execution_observed")):
            unsupported.append("remote_code_execution")
    if re.search(r"\b(denial of service|dos)\b", text):
        if not crash_backed:
            unsupported.append("denial_of_service")
    if "affected version" in text or "affected versions" in text:
        if not target.get("version"):
            unsupported.append("affected_versions")
    if "exploitable" in text or "exploitability" in text:
        if not has_replay:
            unsupported.append("exploitability")
    if re.search(r"\b(privilege escalation|root shell|full compromise|data exfiltration)\b", text):
        if not (facts.get("impact_observed") or facts.get("privilege_escalation_observed") or facts.get("data_exfiltration_observed")):
            unsupported.append("impact")
    return ClaimCheckResult(accepted=not unsupported, unsupported_claims=unsupported)


def build_lean_reports(states: Sequence[CandidateState]) -> list[LeanVulnerabilityReport]:
    reports: list[LeanVulnerabilityReport] = []
    for state in select_report_states(states):
        report = _report_for_state(state)
        claim_check = check_report_claims(report.to_dict(), state)
        if not claim_check.accepted:
            continue
        reports.append(_replace_claim_check(report, claim_check))
    return reports


def select_report_states(states: Sequence[CandidateState]) -> list[CandidateState]:
    """Return one representative state for each vendor-facing proof obligation."""
    selected: dict[tuple[str, ...], tuple[int, CandidateState]] = {}
    for index, state in enumerate(states):
        if state.status not in {CandidateStatus.REPLAY_CONFIRMED.value, CandidateStatus.REPORT_READY.value}:
            continue
        if not has_reportable_source_to_sink(state):
            continue
        if not has_reportable_bug_bounty_evidence(state):
            continue
        key = _report_group_key(state)
        previous = selected.get(key)
        if previous is None or _report_state_rank(state) < _report_state_rank(previous[1]):
            selected[key] = (previous[0] if previous is not None else index, state)
    return [state for _, state in sorted(selected.values(), key=lambda item: item[0])]


def write_lean_reports(reports: Sequence[LeanVulnerabilityReport], output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "vulnerabilities.json"
    json_path.write_text(
        json.dumps(
            {"schema_version": 2, "vulnerabilities": [report.to_dict() for report in reports]},
            indent=2,
            sort_keys=True,
        )
    )
    written: dict[str, Path] = {"json": json_path}
    if not reports:
        readme = output_dir / "README.md"
        readme.write_text("No verified vulnerabilities met the replay-backed reporting gate.\n")
        written["readme"] = readme
        return written
    for index, report in enumerate(reports, start=1):
        slug = _slugify(report.title)
        path = output_dir / f"{index:03d}_{slug}.md"
        path.write_text(_render_markdown(report))
        written[report.candidate_id] = path
    return written


def _report_for_state(state: CandidateState) -> LeanVulnerabilityReport:
    facts = dict(state.type_facts)
    location = dict(state.location)
    sink = dict(state.sink)
    metadata = dict(state.metadata)
    static_candidate = facts.get("static_candidate") if isinstance(facts.get("static_candidate"), Mapping) else {}
    semantic_seed = facts.get("semantic_seed") if isinstance(facts.get("semantic_seed"), Mapping) else {}
    function_name = str(location.get("function_name") or static_candidate.get("function_name") or "unknown")
    sink_name = str(sink.get("name") or static_candidate.get("sink") or "sink")
    target_buffer = str(sink.get("target_buffer") or static_candidate.get("target_buffer") or "target object")
    root_cause = str(
        facts.get("overflow_condition")
        or static_candidate.get("overflow_condition")
        or semantic_seed.get("rationale")
        or f"{sink_name} reaches {target_buffer}"
    )
    proof_path = [str(item.get("condition") or item.get("description") or item) for item in state.proof_obligations]
    if metadata.get("semantic_seed_id"):
        proof_path.append(f"Semantic seed `{metadata['semantic_seed_id']}` was grounded before replay.")
    vulnerability = report_vulnerability_type(state)
    confidence_level, confidence_evidence = report_confidence(state)
    bug_bounty_evidence = build_bug_bounty_evidence(state)
    spec = get_vulnerability_spec(state.vulnerability_type)
    proof_result = facts.get("proof_result") if isinstance(facts.get("proof_result"), Mapping) else {}
    return LeanVulnerabilityReport(
        title=f"{vulnerability.replace('_', ' ').title()} in {function_name}",
        target=dict(state.target),
        vulnerability=vulnerability,
        confidence_level=confidence_level,
        confidence_evidence=confidence_evidence,
        affected_component=function_name,
        root_cause=root_cause,
        attacker_controlled_input=_attacker_input_summary(state),
        proof_path=proof_path,
        replay_steps=[f"Replay mode produced artifact: {path}" for path in _dedupe(state.replay_artifacts)],
        impact=_impact_summary(vulnerability),
        artifacts=_dedupe([*state.validation_artifacts, *state.replay_artifacts, *state.report_artifacts]),
        evidence_scope=[_evidence_scope_summary(state)],
        suggested_fix=_suggested_fix(vulnerability),
        candidate_id=state.candidate_id,
        backend=state.backend,
        mechanism=state.mechanism,
        effect_kind=spec.effect_kind,
        cwe_ids=list(spec.cwe_ids),
        severity=spec.default_severity,
        proof_result=dict(proof_result),
        proof_details={
            **_proof_details(state),
            "bug_bounty_evidence_status": bug_bounty_evidence.status,
            "bug_bounty_evidence_id": bug_bounty_evidence.evidence_id,
            "bug_bounty_evidence": bug_bounty_evidence.to_dict(),
        },
    )


def _replace_claim_check(report: LeanVulnerabilityReport, claim_check: ClaimCheckResult) -> LeanVulnerabilityReport:
    return LeanVulnerabilityReport(
        title=report.title,
        target=report.target,
        vulnerability=report.vulnerability,
        confidence_level=report.confidence_level,
        confidence_evidence=report.confidence_evidence,
        affected_component=report.affected_component,
        root_cause=report.root_cause,
        attacker_controlled_input=report.attacker_controlled_input,
        proof_path=report.proof_path,
        replay_steps=report.replay_steps,
        impact=report.impact,
        artifacts=report.artifacts,
        evidence_scope=report.evidence_scope,
        suggested_fix=report.suggested_fix,
        candidate_id=report.candidate_id,
        backend=report.backend,
        mechanism=report.mechanism,
        effect_kind=report.effect_kind,
        cwe_ids=report.cwe_ids,
        severity=report.severity,
        proof_result=report.proof_result,
        proof_details=report.proof_details,
        claim_check=claim_check.to_dict(),
    )


def _attacker_input_summary(state: CandidateState) -> str:
    trace = build_source_to_sink_trace(state)
    if trace.input_model:
        role = trace.sink_argument.get("role") if isinstance(trace.sink_argument, Mapping) else ""
        entry = trace.entry_function or "derived entrypoint"
        path = " -> ".join(trace.call_path)
        suffix = f" through {path}" if path else ""
        role_text = f" controlling `{role}`" if role else ""
        return f"`{trace.input_model}` input at `{entry}`{suffix}{role_text}."
    source = dict(state.source)
    if source.get("expression"):
        return str(source["expression"])
    if source.get("call_path"):
        return " -> ".join(str(item) for item in source.get("call_path", []) or [])
    return str(source.get("kind") or "Replay input recorded in artifacts.")


def _proof_details(state: CandidateState) -> dict[str, Any]:
    trace = build_source_to_sink_trace(state)
    replay_result = _first_replay_result(state)
    concolic_verdict = _first_concolic_verdict(state)
    concolic_replay = (
        concolic_verdict.get("replay_result")
        if isinstance(concolic_verdict.get("replay_result"), Mapping)
        else {}
    )
    concolic_request = (
        concolic_verdict.get("request")
        if isinstance(concolic_verdict.get("request"), Mapping)
        else {}
    )
    concrete_angr_replay = (
        concolic_replay.get("concrete_angr_replay")
        if isinstance(concolic_replay.get("concrete_angr_replay"), Mapping)
        else {}
    )
    control = replay_result.get("control_result") if isinstance(replay_result.get("control_result"), Mapping) else {}
    ghidra_proof = control.get("ghidra_dynamic_proof") if isinstance(control.get("ghidra_dynamic_proof"), Mapping) else {}
    if not ghidra_proof:
        ghidra_proof = _first_json_artifact(state, "ghidra_dynamic_proof.json")
    process_replay = ghidra_proof.get("process_replay") if isinstance(ghidra_proof.get("process_replay"), Mapping) else {}
    process_setup = ghidra_proof.get("process_input_setup") if isinstance(ghidra_proof.get("process_input_setup"), Mapping) else {}
    proof_observation = control.get("proof_observation") if isinstance(control.get("proof_observation"), Mapping) else {}
    if not proof_observation:
        proof_observation = _first_dynamic_observation(state)
    details = {
        "input_model": trace.input_model,
        "entry_function": trace.entry_function,
        "entry_surface_kind": trace.entry_surface_kind,
        "call_path": list(trace.call_path),
        "sink_name": trace.sink.get("name") if isinstance(trace.sink, Mapping) else "",
        "sink_address": str(
            ghidra_proof.get("sink_address")
            or concolic_request.get("sink_address")
            or concolic_request.get("target_address")
            or (trace.sink.get("address") if isinstance(trace.sink, Mapping) else "")
        ),
        "sink_role": trace.sink_argument.get("role") if isinstance(trace.sink_argument, Mapping) else "",
        "trace_status": trace.status,
        "trace_confidence": trace.confidence,
        "dynamic_artifacts": list(trace.dynamic_artifacts),
        "replay_mode": str(replay_result.get("mode") or ""),
        "replay_result": str(replay_result.get("result") or ""),
        "proof_scope": str(ghidra_proof.get("proof_scope") or ""),
        "process_input_setup_status": str(process_setup.get("status") or ""),
        "process_input_model": str(process_setup.get("input_model") or ""),
        "process_replay_status": str(process_replay.get("status") or ""),
        "exact_sink_reached": bool(ghidra_proof.get("exact_sink_reached", False)),
        "ghidra_dynamic_proof_status": str(ghidra_proof.get("status") or ""),
        "concolic_verdict": str(concolic_verdict.get("concolic_verdict") or ""),
        "concolic_backend": str(concolic_verdict.get("backend") or ""),
        "concrete_angr_replay_status": str(concrete_angr_replay.get("status") or ""),
        "dynamic_overflow_bytes": ghidra_proof.get("overflow_bytes", ""),
        "dynamic_oob_bytes": ghidra_proof.get("oob_bytes", ""),
        "dynamic_observation_kind": str(proof_observation.get("kind") or ""),
        "dynamic_observation_status": str(proof_observation.get("status") or ""),
        "effect_channels_observed": _effect_channels_observed(control),
        **_process_input_provenance(state, process_setup),
    }
    wrapper_chain = source_read_wrapper_chain_from_candidate(state.to_dict())
    if wrapper_chain:
        details["source_read_wrapper_chain"] = wrapper_chain
        details["source_read_wrapper_chain_text"] = source_read_wrapper_chain_text(wrapper_chain)
    return details


def _effect_channels_observed(control: Mapping[str, Any]) -> list[str]:
    return [
        key
        for key in ("stdout", "stderr", "socket_response", "http_response", "syslog")
        if str(control.get(key) or "")
    ]


def _process_input_provenance(state: CandidateState, process_setup: Mapping[str, Any]) -> dict[str, Any]:
    facts = dict(state.type_facts)
    process_input = facts.get("process_input") if isinstance(facts.get("process_input"), Mapping) else {}
    evidence = process_setup.get("process_input_evidence") if isinstance(process_setup.get("process_input_evidence"), Mapping) else {}
    if not evidence and isinstance(process_input.get("process_input_evidence"), Mapping):
        evidence = process_input["process_input_evidence"]
    source = str(process_setup.get("process_input_source") or process_input.get("process_input_source") or "")
    inferred = bool(process_input.get("inferred")) or source.startswith("inferred_")
    return {
        "process_input_source": source,
        "process_input_inferred": inferred,
        "process_input_file_seed_reason": str(evidence.get("file_seed_reason") or ""),
        "process_input_decompile_source_file": str(evidence.get("decompile_source_file") or evidence.get("source_path") or ""),
    }


def report_confidence(state: CandidateState) -> tuple[str, list[str]]:
    metadata = dict(state.metadata)
    explicit = str(metadata.get("report_confidence_level") or "").strip()
    if explicit:
        evidence = [str(item) for item in _sequence(metadata.get("report_confidence_evidence")) if str(item)]
        return explicit, evidence or ["confidence level supplied by candidate metadata"]
    artifacts = [str(item) for item in [*state.validation_artifacts, *state.replay_artifacts, *state.report_artifacts]]
    target_text = json.dumps(dict(state.target), sort_keys=True)
    joined = "\n".join([target_text, *artifacts])
    if "known_overflow_corpus" in joined or "known_overflow_sources" in joined:
        return "known_corpus_confirmed", ["report artifact path belongs to the known-overflow corpus"]
    if metadata.get("source_reviewed"):
        return "source_reviewed", ["source review marker present in candidate metadata"]
    if _native_crash_observed(state):
        return "native_reproducer_confirmed", ["native replay artifact records crash_observed=true"]
    if state.status in {CandidateStatus.REPLAY_CONFIRMED.value, CandidateStatus.REPORT_READY.value}:
        return "real_binary_replay_confirmed", ["replay-confirmed candidate passed the source-to-sink report gate"]
    return "artifact_backed", ["candidate passed the report gate with artifact-backed evidence"]


def _native_crash_observed(state: CandidateState) -> bool:
    for artifact in state.replay_artifacts:
        path = Path(artifact)
        if path.name != "result.json" or not path.exists():
            continue
        try:
            payload = json.loads(path.read_text() or "{}")
        except (OSError, json.JSONDecodeError):
            continue
        mode = str(payload.get("mode") or "")
        if bool(payload.get("crash_observed")) and mode in {"native", "qemu_user", "ghidra_process"}:
            return True
    return False


def _first_replay_result(state: CandidateState) -> dict[str, Any]:
    for raw in state.replay_artifacts:
        path = Path(raw)
        candidates = [path]
        if path.name != "result.json":
            candidates.append(path.with_name("result.json"))
        for candidate in candidates:
            if not candidate.exists() or candidate.suffix.lower() != ".json":
                continue
            try:
                payload = json.loads(candidate.read_text() or "{}")
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, Mapping) and payload.get("result"):
                return dict(payload)
    return {}


def _first_concolic_verdict(state: CandidateState) -> dict[str, Any]:
    for raw in state.replay_artifacts:
        path = Path(raw)
        if path.name != "verdict.json" or not path.exists():
            continue
        try:
            payload = json.loads(path.read_text() or "{}")
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, Mapping) and str(payload.get("candidate_id") or "") == state.candidate_id:
            return dict(payload)
    return {}


def _first_json_artifact(state: CandidateState, name: str) -> dict[str, Any]:
    for raw in [*state.validation_artifacts, *state.replay_artifacts, *state.report_artifacts]:
        path = Path(raw)
        if path.name != name or not path.exists():
            continue
        try:
            payload = json.loads(path.read_text() or "{}")
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, Mapping):
            return dict(payload)
    return {}


def _first_dynamic_observation(state: CandidateState) -> dict[str, Any]:
    for raw in state.replay_artifacts:
        path = Path(raw)
        if not path.name.endswith("_observation.json") and path.name not in {
            "dynamic_overflow_observation.json",
            "target_overflow_observation.json",
        }:
            continue
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text() or "{}")
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, Mapping):
            return dict(payload)
    return {}


def report_vulnerability_type(state: CandidateState) -> str:
    """Return the report-facing vulnerability class for a candidate state."""
    vulnerability_type = str(state.vulnerability_type or "")
    destination_kind = _destination_kind(state)
    if vulnerability_type in {"stack_overflow", "heap_overflow", "out_of_bounds_write"}:
        if destination_kind == "heap":
            return "heap_overflow"
        if destination_kind in {"global", "static_local", "tls", "parameter", "caller_buffer", "struct_field"}:
            return "out_of_bounds_write"
        if destination_kind == "stack":
            return "stack_overflow"
    return vulnerability_type


def _impact_summary(vulnerability_type: str) -> str:
    if vulnerability_type in {"stack_overflow", "heap_overflow", "out_of_bounds_write"}:
        return "Replay demonstrated the expected memory corruption condition."
    if vulnerability_type == "out_of_bounds_read":
        return "Replay demonstrated a concrete read beyond the modeled source object capacity."
    if vulnerability_type == "command_injection":
        return "Replay demonstrated the configured command-effect oracle."
    if vulnerability_type == "path_traversal":
        return "Replay demonstrated the configured filesystem read-escape oracle."
    if vulnerability_type == "unsafe_file_write":
        return "Replay demonstrated the configured filesystem write-escape oracle."
    if vulnerability_type == "format_string":
        return "Replay demonstrated the configured format-string oracle."
    if vulnerability_type in {"credential_disclosure", "hardcoded_credential"}:
        return "Replay demonstrated the configured credential-disclosure oracle."
    if vulnerability_type == "auth_bypass":
        return "Replay demonstrated the configured authorization-bypass oracle."
    if vulnerability_type == "fs_config_memory_corruption":
        return "Replay demonstrated the configured filesystem/config memory-corruption oracle."
    return "Replay demonstrated the candidate condition described in the proof path."


def _evidence_scope_summary(state: CandidateState) -> str:
    if dict(state.metadata).get("semantic_seed_id"):
        return "Semantic seed, replay result, dynamic observation, and report artifacts listed above back this finding."
    return "Replay, static proof, and report artifacts listed above back this finding."


def _suggested_fix(vulnerability_type: str) -> str:
    if vulnerability_type in {"stack_overflow", "heap_overflow", "out_of_bounds_write"}:
        return "Bound the write by the destination capacity and reject oversized input before the sink."
    if vulnerability_type == "out_of_bounds_read":
        return "Bound the read offset and length by the source object capacity before dereference or copy."
    if vulnerability_type == "command_injection":
        return "Avoid shell invocation with attacker-controlled strings; use fixed argv arrays and strict allowlists."
    if vulnerability_type == "path_traversal":
        return "Canonicalize paths and enforce an allowlisted base directory before filesystem access."
    if vulnerability_type == "format_string":
        return "Keep format strings constant and pass attacker-controlled data only as arguments to bounded formatting APIs."
    if vulnerability_type in {"credential_disclosure", "hardcoded_credential"}:
        return "Remove embedded secrets from the binary or response path and use revocable credentials from a protected store."
    if vulnerability_type == "auth_bypass":
        return "Require the authorization check before the protected action and add negative tests for unauthenticated requests."
    return "Add input validation and make the failing proof obligation impossible by construction."


def _render_markdown(report: LeanVulnerabilityReport) -> str:
    lines = [
        f"# {report.title}",
        "",
        f"- Candidate: `{report.candidate_id}`",
        f"- Vulnerability: `{report.vulnerability}`",
        f"- Confidence level: `{report.confidence_level}`",
        f"- Affected component: `{report.affected_component}`",
        "",
        "## Root Cause",
        report.root_cause,
        "",
        "## Attacker-Controlled Input",
        report.attacker_controlled_input,
        "",
        "## Proof Path",
        *[f"- {item}" for item in report.proof_path],
        "",
        "## Replay Steps",
        *[f"- {item}" for item in report.replay_steps],
        "",
        "## Proof Details",
        *[f"- {key}: `{value}`" for key, value in report.proof_details.items() if value not in ("", [], False)],
        "",
        "## Impact",
        report.impact,
        "",
        "## Artifacts",
        *[f"- `{item}`" for item in report.artifacts],
        "",
        "## Evidence Scope",
        *[f"- {item}" for item in report.evidence_scope],
        "",
        "## Confidence Evidence",
        *[f"- {item}" for item in report.confidence_evidence],
        "",
        "## Suggested Fix",
        report.suggested_fix,
        "",
    ]
    return "\n".join(lines)


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "vulnerability"


def _dedupe(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _report_group_key(state: CandidateState) -> tuple[str, ...]:
    target = dict(state.target)
    location = dict(state.location)
    source = dict(state.source)
    sink = dict(state.sink)
    facts = dict(state.type_facts)
    static_candidate = facts.get("static_candidate") if isinstance(facts.get("static_candidate"), Mapping) else {}
    return (
        str(target.get("relative_path") or target.get("path") or target.get("binary") or ""),
        str(location.get("address") or ""),
        report_vulnerability_type(state),
        str(sink.get("name") or static_candidate.get("sink") or ""),
        str(sink.get("target_buffer") or static_candidate.get("target_buffer") or ""),
        _source_group_key(source),
        _proof_oracle_key(state),
    )


def _source_group_key(source: Mapping[str, Any]) -> str:
    expression = str(source.get("expression") or "").strip()
    if expression:
        return f"expr:{expression}"
    kind = str(source.get("kind") or "").strip()
    if kind and kind != "unknown":
        return f"kind:{kind}"
    call_path = source.get("call_path")
    if isinstance(call_path, Sequence) and not isinstance(call_path, (str, bytes)) and call_path:
        return "path:" + "->".join(str(item) for item in call_path)
    return ""


def _proof_oracle_key(state: CandidateState) -> str:
    for artifact in state.replay_artifacts:
        path = Path(artifact)
        if path.name != "result.json" or not path.exists():
            continue
        try:
            result = json.loads(path.read_text() or "{}")
        except (OSError, json.JSONDecodeError):
            continue
        control = result.get("control_result") if isinstance(result.get("control_result"), Mapping) else {}
        observation = control.get("proof_observation") if isinstance(control.get("proof_observation"), Mapping) else {}
        kind = str(observation.get("kind") or "")
        status = str(observation.get("status") or "")
        if kind or status:
            return f"{kind}:{status}"
        expected = result.get("expected_result") if isinstance(result.get("expected_result"), Mapping) else {}
        kind = str(expected.get("kind") or "")
        if kind:
            return kind
    return ""


def _report_state_rank(state: CandidateState) -> tuple[int, int, int, int, str]:
    metadata = dict(state.metadata)
    source = dict(state.source)
    location = dict(state.location)
    return (
        0 if metadata.get("semantic_seed_id") else 1,
        0 if _source_group_key(source) else 1,
        -len(state.replay_artifacts),
        int(location.get("line_number") or 0),
        state.candidate_id,
    )


def _destination_kind(state: CandidateState) -> str:
    facts = dict(state.type_facts)
    static_candidate = facts.get("static_candidate") if isinstance(facts.get("static_candidate"), Mapping) else {}
    return str(facts.get("destination_kind") or static_candidate.get("destination_kind") or "").lower()
