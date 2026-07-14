"""Evidence-pack and confirmation helpers for deterministic candidates."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.analysis.proof_obligations import (
    ALLOWED_FACT_TOOLS,
    build_proof_obligation,
)
from binary_agent.analysis.provenance import source_read_wrapper_chain_from_candidate, source_read_wrapper_chain_text
from binary_agent.analysis.concolic import (
    CONCOLIC_ARTIFACT_FILENAMES,
    CONCOLIC_RUN_SUMMARY,
    CONCOLIC_VERDICT_FILENAME,
    concolic_confirmation_dict,
    concolic_verdict_entries,
)
from binary_agent.analysis.entrypoints import EntryPointDeriver
from binary_agent.ingest.loader import FunctionNode


CONFIRMATION_STATUSES = {
    "confirmed_bug",
    "likely_bug",
    "likely_safe",
    "not_a_bug",
    "needs_more_static_facts",
    "needs_dynamic_confirmation",
    "insufficient_evidence",
    "rejected",
    "needs_more_evidence",
}
EVIDENCE_PACK_INDEX = "index.json"
CONFIRMATION_RUN_SUMMARY = "_run_summary.json"
EVIDENCE_PACK_V3_SCHEMA_VERSION = 3
HELPER_ROLES = {"environment_infer", "replay_plan", "branch_guide", "triage", "report_draft"}


@dataclass(frozen=True)
class CandidateConfirmation:
    candidate_id: str
    status: str
    reason_codes: list[str] = field(default_factory=list)
    rationale: str = ""
    memory_safety_argument: dict[str, Any] = field(default_factory=dict)
    tool_requests: list[dict[str, Any]] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    missing_constraints: list[str] = field(default_factory=list)
    overflow_condition: str = ""
    feasibility_argument: str = ""
    decision: str = ""
    bug_class: str = ""
    must_conditions: list[str] = field(default_factory=list)
    notes_for_human: str = ""
    agent_tool_trace: list[dict[str, Any]] = field(default_factory=list)
    provider_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def confirmed_bug(self) -> bool:
        return self.status == "confirmed_bug"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, candidate_id: str, data: Mapping[str, Any]) -> "CandidateConfirmation":
        status = str(data.get("status") or data.get("verdict") or "").strip()
        if status not in CONFIRMATION_STATUSES:
            raise ValueError(
                f"Invalid confirmation status for {candidate_id}: {status!r}; "
                f"expected one of {sorted(CONFIRMATION_STATUSES)}"
            )
        return cls(
            candidate_id=str(data.get("candidate_id") or candidate_id),
            status=status,
            reason_codes=_coerce_reason_codes(data.get("reason_codes", [])),
            rationale=str(data.get("rationale") or data.get("reason") or ""),
            memory_safety_argument=_coerce_mapping(data.get("memory_safety_argument")),
            tool_requests=_coerce_mapping_list(data.get("tool_requests", [])),
            evidence_refs=_coerce_string_list(data.get("evidence_refs", [])),
            missing_constraints=_coerce_string_list(data.get("missing_constraints", [])),
            overflow_condition=str(data.get("overflow_condition") or ""),
            feasibility_argument=str(data.get("feasibility_argument") or ""),
            decision=str(data.get("decision") or ""),
            bug_class=str(data.get("bug_class") or ""),
            must_conditions=_coerce_string_list(data.get("must_conditions", [])),
            notes_for_human=str(data.get("notes_for_human") or ""),
            agent_tool_trace=_coerce_mapping_list(data.get("agent_tool_trace", [])),
            provider_metadata=_coerce_mapping(data.get("provider_metadata")),
        )


@dataclass(frozen=True)
class GroundingValidationResult:
    """Result of checking whether helper output is grounded in an evidence pack."""

    accepted: bool
    reasons: list[str] = field(default_factory=list)
    grounded_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_evidence_pack_v3(
    candidate: Mapping[str, Any],
    *,
    decompiler_context: Mapping[str, Any] | None = None,
    intake_facts: Mapping[str, Any] | None = None,
    deterministic_tools: Sequence[str] | None = None,
    entrypoint_derivation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the bounded schema-v3 evidence pack used by helper roles.

    The pack is intentionally redundant: validators can inspect it without
    knowing whether the candidate came from the legacy stack analyzer or a new
    discovery module.
    """
    data = candidate.to_dict() if hasattr(candidate, "to_dict") else dict(candidate)
    static_candidate = _coerce_mapping(data.get("type_facts", {})).get("static_candidate")
    if isinstance(static_candidate, Mapping):
        legacy = dict(static_candidate)
    else:
        legacy = data
    candidate_id = str(data.get("candidate_id") or legacy.get("candidate_id") or "")
    vulnerability_type = str(data.get("vulnerability_type") or legacy.get("vulnerability_type") or "stack_overflow")
    location = _coerce_mapping(data.get("location")) or {
        "function_name": legacy.get("function_name", ""),
        "address": legacy.get("address", ""),
        "relative_path": legacy.get("relative_path", ""),
        "line_number": legacy.get("line_number", 0),
        "line_text": legacy.get("line_text", ""),
    }
    source = _coerce_mapping(data.get("source")) or {
        "kind": "attacker_input" if legacy.get("input_reaches_sink") else "unknown",
        "evidence": legacy.get("source_evidence", []),
    }
    sink = _coerce_mapping(data.get("sink")) or {
        "name": legacy.get("sink", ""),
        "target_buffer": legacy.get("target_buffer", ""),
    }
    proof_obligations = list(data.get("proof_obligations", []) or [])
    if not proof_obligations and legacy:
        proof_obligations = [build_proof_obligation(legacy)]
    type_facts = _coerce_mapping(data.get("type_facts")) or legacy
    if entrypoint_derivation:
        type_facts = dict(type_facts)
        type_facts["entrypoint_derivation"] = dict(entrypoint_derivation)
    pack = {
        "schema_version": EVIDENCE_PACK_V3_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "candidate": {
            "candidate_id": candidate_id,
            "vulnerability_type": vulnerability_type,
            "status": str(data.get("status") or "candidate"),
        },
        "target": _coerce_mapping(data.get("target")) or {"binary": legacy.get("binary", "")},
        "location": location,
        "source": source,
        "sink": sink,
        "type_facts": type_facts,
        "decompiler_context": dict(decompiler_context or {}),
        "reachability": _pack_reachability(data, legacy),
        "proof_obligations": proof_obligations,
        "known_blockers": list(data.get("blockers", []) or []),
        "replay_hypothesis": _default_replay_hypothesis(data, legacy),
        "intake_facts": dict(intake_facts or {}),
        "available_deterministic_tools": list(deterministic_tools or sorted(ALLOWED_FACT_TOOLS)),
        "helper_roles": sorted(HELPER_ROLES),
    }
    if entrypoint_derivation:
        pack["entrypoint_derivation"] = dict(entrypoint_derivation)
    process_input = _coerce_mapping(type_facts.get("process_input") or type_facts.get("process_inputs"))
    if process_input:
        pack["process_input"] = dict(process_input)
    concolic_candidate = _concolic_candidate_from_v3(data, legacy, pack)
    if concolic_candidate:
        pack["deterministic_candidate"] = concolic_candidate
        pack["facts_available_to_llm"] = _concolic_facts_from_v3(data, legacy, pack, concolic_candidate)
        pack["proof_obligation"] = proof_obligations[0] if proof_obligations else build_proof_obligation(concolic_candidate)
    proof_oracle_facts = _proof_oracle_facts(data, legacy)
    if proof_oracle_facts:
        pack["proof_oracle_facts"] = proof_oracle_facts
        pack["allowed_proof_addresses"] = sorted(_proof_oracle_addresses(proof_oracle_facts))
    pack["grounded_refs"] = sorted(_collect_grounded_refs(pack))
    return pack


def validate_helper_output_grounding(
    evidence_pack: Mapping[str, Any],
    helper_output: Mapping[str, Any],
) -> GroundingValidationResult:
    """Reject helper facts not grounded in schema-v3 evidence-pack facts."""
    if not isinstance(helper_output, Mapping):
        return GroundingValidationResult(False, ["helper_output_not_object"])
    role = str(helper_output.get("role") or "")
    reasons: list[str] = []
    if role and role not in HELPER_ROLES:
        reasons.append(f"unsupported_helper_role:{role}")

    grounded_values = _collect_grounded_refs(evidence_pack)
    known_paths = {value for value in grounded_values if "/" in value or value.endswith(".c")}
    known_routes = _known_routes(evidence_pack)
    known_env = _known_env_keys(evidence_pack)
    known_sinks = _known_sinks(evidence_pack)

    for path in _coerce_string_list(helper_output.get("files", [])) + _coerce_string_list(helper_output.get("paths", [])):
        if path not in known_paths and path not in grounded_values:
            reasons.append(f"ungrounded_file:{path}")
    for route in _coerce_string_list(helper_output.get("routes", [])):
        if route not in known_routes:
            reasons.append(f"ungrounded_route:{route}")
    env_output = helper_output.get("env") or helper_output.get("env_vars") or {}
    if isinstance(env_output, Mapping):
        env_names = [str(key) for key in env_output]
    else:
        env_names = _coerce_string_list(env_output)
    for env_name in env_names:
        if env_name not in known_env:
            reasons.append(f"ungrounded_env:{env_name}")
    for sink in _coerce_string_list(helper_output.get("sinks", [])):
        if sink not in known_sinks:
            reasons.append(f"ungrounded_sink:{sink}")
    reachability = helper_output.get("reachability")
    if isinstance(reachability, Mapping):
        for claim in ("network_reachable", "unauthenticated", "remote"):
            if reachability.get(claim) and claim not in grounded_values:
                reasons.append(f"unsupported_reachability:{claim}")
    impact = str(helper_output.get("impact") or "")
    if impact and impact.lower() not in {str(value).lower() for value in grounded_values}:
        reasons.append("unsupported_impact")
    return GroundingValidationResult(accepted=not reasons, reasons=reasons, grounded_refs=sorted(grounded_values))


def load_candidate_confirmations(confirmation_dir: Path) -> dict[str, CandidateConfirmation]:
    """Load strict legacy LLM confirmation artifacts from every JSON file in a directory."""
    confirmation_dir = Path(confirmation_dir)
    if not confirmation_dir.exists():
        raise FileNotFoundError(f"Confirmation directory not found: {confirmation_dir}")
    confirmations: dict[str, CandidateConfirmation] = {}
    for path in sorted(confirmation_dir.glob("*.json")):
        if path.name in {CONFIRMATION_RUN_SUMMARY, CONCOLIC_RUN_SUMMARY}:
            continue
        if path.name in CONCOLIC_ARTIFACT_FILENAMES and path.name != CONCOLIC_VERDICT_FILENAME:
            continue
        payload = json.loads(path.read_text() or "{}")
        concolic_entries = concolic_verdict_entries(payload)
        if concolic_entries:
            for candidate_id, entry in concolic_entries:
                data = concolic_confirmation_dict(entry)
                confirmation = CandidateConfirmation.from_dict(candidate_id, data)
                confirmations[confirmation.candidate_id] = confirmation
            continue
        for candidate_id, entry in _iter_confirmation_entries(payload):
            confirmation = CandidateConfirmation.from_dict(candidate_id, entry)
            confirmations[confirmation.candidate_id] = confirmation
    return confirmations


def iter_evidence_packs(evidence_dir: Path) -> list[tuple[Path, Mapping[str, Any]]]:
    """Read evidence packs from an evidence-pack directory in stable order."""
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.exists():
        raise FileNotFoundError(f"Evidence-pack directory not found: {evidence_dir}")
    index_path = evidence_dir / EVIDENCE_PACK_INDEX
    pack_paths: list[Path] = []
    if index_path.exists():
        payload = json.loads(index_path.read_text() or "{}")
        for entry in payload.get("evidence_packs", []):
            if not isinstance(entry, Mapping):
                continue
            relative = str(entry.get("path") or "")
            if not relative:
                continue
            pack_paths.append(evidence_dir / relative)
    else:
        pack_paths = sorted(
            path
            for path in evidence_dir.glob("*.json")
            if path.name not in {EVIDENCE_PACK_INDEX, CONFIRMATION_RUN_SUMMARY}
        )

    packs: list[tuple[Path, Mapping[str, Any]]] = []
    seen: set[Path] = set()
    for path in pack_paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if not path.exists():
            raise FileNotFoundError(f"Evidence pack listed in index does not exist: {path}")
        payload = json.loads(path.read_text() or "{}")
        if not isinstance(payload, Mapping):
            raise ValueError(f"Evidence pack must be a JSON object: {path}")
        packs.append((path, payload))
    return packs


def write_evidence_packs(
    candidates: Sequence[Any],
    nodes: Sequence[FunctionNode],
    output_dir: Path,
    *,
    excerpt_radius: int = 4,
) -> list[Path]:
    """Write one bounded evidence-pack JSON document per candidate plus an index."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    node_by_name = {node.record.name: node for node in nodes}
    deriver = _entrypoint_deriver_for_nodes(nodes)
    written: list[Path] = []
    index_entries: list[dict[str, str]] = []

    for candidate in candidates:
        candidate_id = _candidate_value(candidate, "candidate_id")
        node = node_by_name.get(_candidate_value(candidate, "function_name"))
        entrypoint_derivation = _derive_entrypoint_for_pack(deriver, candidate)
        candidate_dict = candidate.to_dict() if hasattr(candidate, "to_dict") else dict(candidate)
        record = node.record if node else None
        decompiler_context = {
            "decompile_completed": bool(getattr(record, "decompile_completed", False)) if record else False,
            "emit_c": bool(getattr(record, "emit_c", False)) if record else False,
            "source_exists": bool(getattr(record, "source_exists", False)) if record else False,
            "line_count": int(getattr(record, "line_count", 0) or 0) if record else 0,
            "stub_kind": getattr(record, "stub_kind", None) if record else None,
            "c_excerpt": _bounded_excerpt(
                node.text if node else "",
                int(candidate_dict.get("line_number", 0) or 0),
                excerpt_radius,
            ),
        }
        pack = build_evidence_pack_v3(
            candidate_dict,
            decompiler_context=decompiler_context,
            entrypoint_derivation=entrypoint_derivation,
        )
        filename = _pack_filename(candidate_id)
        path = output_dir / filename
        path.write_text(json.dumps(pack, indent=2))
        written.append(path)
        index_entries.append({"candidate_id": candidate_id, "path": filename})

    index_path = output_dir / EVIDENCE_PACK_INDEX
    index_path.write_text(json.dumps({"evidence_packs": index_entries}, indent=2))
    written.append(index_path)
    return written


def _entrypoint_deriver_for_nodes(nodes: Sequence[FunctionNode]) -> EntryPointDeriver | None:
    for node in nodes:
        if node.path is None:
            continue
        try:
            return EntryPointDeriver.from_export_dir(node.path.parent)
        except Exception:
            continue
    return None


def _derive_entrypoint_for_pack(deriver: EntryPointDeriver | None, candidate: Any) -> dict[str, Any]:
    if deriver is None:
        return {}
    candidate_dict = candidate.to_dict() if hasattr(candidate, "to_dict") else dict(candidate)
    try:
        return deriver.derive_for_candidate(candidate_dict).to_dict()
    except Exception:
        return {}


def _iter_confirmation_entries(payload: Any) -> list[tuple[str, Mapping[str, Any]]]:
    if isinstance(payload, Mapping) and "candidate_confirmations" in payload:
        payload = payload["candidate_confirmations"]
    if isinstance(payload, Mapping) and "confirmations" in payload:
        payload = payload["confirmations"]
    if isinstance(payload, list):
        entries = []
        for item in payload:
            if not isinstance(item, Mapping):
                continue
            candidate_id = str(item.get("candidate_id") or "")
            if candidate_id:
                entries.append((candidate_id, item))
        return entries
    if isinstance(payload, Mapping):
        entries = []
        for key, value in payload.items():
            if isinstance(value, Mapping):
                entries.append((str(key), value))
        return entries
    return []


def _pack_reachability(data: Mapping[str, Any], legacy: Mapping[str, Any]) -> dict[str, Any]:
    reachability = data.get("reachability")
    if isinstance(reachability, Mapping):
        return dict(reachability)
    trace = legacy.get("classification_trace")
    if isinstance(trace, Mapping):
        maybe = trace.get("reachability_dataflow")
        if isinstance(maybe, Mapping):
            return dict(maybe)
    return {
        "reachability_kind": legacy.get("reachability_kind", "unknown"),
        "call_path": legacy.get("call_path", []),
        "input_reaches_sink": bool(legacy.get("input_reaches_sink", False)),
        "path_is_valid": bool(legacy.get("path_is_valid", False)),
    }


def _default_replay_hypothesis(data: Mapping[str, Any], legacy: Mapping[str, Any]) -> dict[str, Any]:
    location = _coerce_mapping(data.get("location"))
    sink = _coerce_mapping(data.get("sink"))
    type_facts = _coerce_mapping(data.get("type_facts"))
    static_candidate = _coerce_mapping(type_facts.get("static_candidate"))
    capacity = type_facts.get("capacity_bytes") or static_candidate.get("capacity_bytes") or legacy.get("capacity_bytes") or 0
    try:
        capacity_int = int(capacity)
    except (TypeError, ValueError):
        capacity_int = 0
    return {
        "mode": "auto",
        "function_name": location.get("function_name") or legacy.get("function_name", ""),
        "sink": sink.get("name") or legacy.get("sink", ""),
        "input_model": "argv",
        "payload_length": max(capacity_int + 64, 128) if capacity_int else 256,
        "expected_condition": type_facts.get("overflow_condition")
        or static_candidate.get("overflow_condition")
        or legacy.get("overflow_condition", ""),
    }


def _concolic_candidate_from_v3(
    data: Mapping[str, Any],
    legacy: Mapping[str, Any],
    pack: Mapping[str, Any],
) -> dict[str, Any]:
    candidate = _coerce_mapping(pack.get("candidate"))
    location = _coerce_mapping(pack.get("location"))
    sink = _coerce_mapping(pack.get("sink"))
    target = _coerce_mapping(pack.get("target"))
    type_facts = _coerce_mapping(pack.get("type_facts"))
    static_candidate = _coerce_mapping(type_facts.get("static_candidate"))
    candidate_id = str(candidate.get("candidate_id") or legacy.get("candidate_id") or "")
    if not candidate_id:
        return {}
    operation_address = _normalize_address(
        sink.get("operation_address")
        or sink.get("address")
        or location.get("operation_address")
        or static_candidate.get("operation_address")
        or legacy.get("operation_address")
    )
    address = _normalize_address(
        location.get("address")
        or static_candidate.get("address")
        or operation_address
        or legacy.get("address")
    )
    sink_name = str(sink.get("name") or sink.get("sink") or static_candidate.get("sink") or legacy.get("sink") or "")
    result: dict[str, Any] = {
        "candidate_id": candidate_id,
        "vulnerability_type": str(candidate.get("vulnerability_type") or data.get("vulnerability_type") or legacy.get("vulnerability_type") or ""),
        "binary": str(target.get("binary") or legacy.get("binary") or ""),
        "target_path": str(target.get("path") or legacy.get("path") or ""),
        "function_name": str(location.get("function_name") or static_candidate.get("function_name") or legacy.get("function_name") or ""),
        "address": address,
        "operation_address": operation_address,
        "kind": str(static_candidate.get("kind") or legacy.get("kind") or "call"),
        "sink": sink_name,
        "source_kind": str(_coerce_mapping(pack.get("source")).get("kind") or ""),
        "source_expression": str(_coerce_mapping(pack.get("source")).get("expression") or ""),
        "verdict": str(static_candidate.get("verdict") or legacy.get("verdict") or "candidate"),
        "write_relation": str(static_candidate.get("write_relation") or legacy.get("write_relation") or ""),
        "mechanism": str(data.get("mechanism") or type_facts.get("mechanism") or ""),
    }
    for key in (
        "destination_kind",
        "target_buffer",
        "capacity_bytes",
        "write_size_bytes",
        "write_size_expr",
        "overflow_condition",
        "allocation_call_address",
        "allocation_return_address",
        "sink_call_address",
        "sink_return_address",
    ):
        value = type_facts.get(key)
        if value in (None, ""):
            value = static_candidate.get(key)
        if value in (None, ""):
            value = legacy.get(key)
        if value not in (None, ""):
            result[key] = value
    return result


def _concolic_facts_from_v3(
    data: Mapping[str, Any],
    legacy: Mapping[str, Any],
    pack: Mapping[str, Any],
    concolic_candidate: Mapping[str, Any],
) -> dict[str, Any]:
    type_facts = _coerce_mapping(pack.get("type_facts"))
    static_candidate = _coerce_mapping(type_facts.get("static_candidate"))
    sink_name = str(concolic_candidate.get("sink") or "")
    operation_address = _normalize_address(concolic_candidate.get("operation_address") or concolic_candidate.get("address"))
    input_model = _concolic_input_model_from_v3(data, pack)
    reproducer = {
        "input_surface": input_model,
        "allowed_stubs": [sink_name] if sink_name else [],
    }
    entrypoint = _coerce_mapping(type_facts.get("entrypoint_derivation") or pack.get("entrypoint_derivation"))
    if entrypoint:
        if entrypoint.get("entry_function"):
            reproducer["suggested_entry"] = str(entrypoint.get("entry_function") or "")
        if isinstance(entrypoint.get("call_path"), Sequence) and not isinstance(entrypoint.get("call_path"), (str, bytes, bytearray)):
            reproducer["call_path"] = [str(item) for item in entrypoint.get("call_path") or []]
        reproducer["entrypoint_status"] = str(entrypoint.get("status") or "")
        reproducer["entry_surface"] = dict(_coerce_mapping(entrypoint.get("entry_surface")))
        reproducer["source_to_sink_trace"] = dict(_coerce_mapping(entrypoint.get("source_to_sink_trace")))
    semantic_seed = _coerce_mapping(type_facts.get("semantic_seed"))
    replay_hints = _coerce_mapping(type_facts.get("replay_hints") or semantic_seed.get("replay_hints"))
    if replay_hints:
        reproducer["semantic_replay_hints"] = dict(replay_hints)
    facts: dict[str, Any] = {
        "reproducer_hypothesis": reproducer,
        "allowed_stubs": [sink_name] if sink_name else [],
        "review_priority": {"source": "proof_gated_v3", "rank": "semantic" if semantic_seed else "deterministic"},
        "reachability": dict(_coerce_mapping(pack.get("reachability"))),
    }
    if entrypoint:
        facts["entrypoint_derivation"] = dict(entrypoint)
        facts["entry_reachability"] = dict(_coerce_mapping(entrypoint.get("entry_reachability")))
        facts["source_to_sink_trace"] = dict(_coerce_mapping(entrypoint.get("source_to_sink_trace")))
    process_input = _coerce_mapping(type_facts.get("process_input") or type_facts.get("process_inputs"))
    if process_input:
        facts["process_input"] = dict(process_input)
    wrapper_chain = source_read_wrapper_chain_from_candidate(data)
    if not wrapper_chain:
        wrapper_chain = source_read_wrapper_chain_from_candidate(legacy)
    if wrapper_chain:
        facts["source_read_wrapper_chain"] = wrapper_chain
        facts["source_read_wrapper_chain_text"] = source_read_wrapper_chain_text(wrapper_chain)
    if operation_address:
        facts["write_table"] = [
            {
                "operation_address": operation_address,
                "address": _normalize_address(concolic_candidate.get("address")) or operation_address,
                "sink": sink_name,
                "stub": sink_name,
                "write_relation": str(concolic_candidate.get("write_relation") or ""),
            }
        ]
        facts["pcode_slice"] = {"operation_address": operation_address}
        facts["exact_sink_address"] = operation_address
    proof_oracle = _proof_oracle_facts(data, legacy)
    if proof_oracle:
        facts["dynamic_proof_oracle"] = proof_oracle
    for key in ("object_table", "allocation_table", "source_to_write", "safety_result"):
        value = type_facts.get(key)
        if value in (None, ""):
            value = static_candidate.get(key)
        if value not in (None, ""):
            facts[key] = value
    return facts


def _concolic_input_model_from_v3(data: Mapping[str, Any], pack: Mapping[str, Any]) -> str:
    type_facts = _coerce_mapping(pack.get("type_facts"))
    entrypoint = _coerce_mapping(type_facts.get("entrypoint_derivation") or pack.get("entrypoint_derivation"))
    entrypoint_model = str(entrypoint.get("input_model") or "").strip()
    if entrypoint.get("status") == "derived" and entrypoint_model in {"argv", "stdin", "file"}:
        return entrypoint_model
    if _coerce_mapping(type_facts.get("semantic_seed")):
        return "unknown"
    replay_hints = _coerce_mapping(type_facts.get("replay_hints"))
    hint_mode = str(replay_hints.get("mode") or _coerce_mapping(replay_hints.get("setup")).get("mode") or "").strip()
    if hint_mode == "function_harness":
        return "function_harness"
    hint_input = _coerce_mapping(replay_hints.get("input") or replay_hints.get("inputs") or replay_hints.get("proposed_inputs"))
    for key in ("stdin", "body"):
        if key in hint_input:
            return "stdin"
    if "argv" in hint_input:
        return "argv"
    if "file" in hint_input or "path" in hint_input or "param" in hint_input:
        return "file"
    source = _coerce_mapping(pack.get("source"))
    source_text = " ".join(
        [
            str(source.get("kind") or ""),
            str(source.get("expression") or ""),
            str(data.get("source") or ""),
        ]
    ).lower()
    if "stdin" in source_text or "form" in source_text or "body" in source_text or "query" in source_text:
        return "stdin"
    if "file" in source_text or "path" in source_text or "config" in source_text:
        return "file"
    if "argv" in source_text or "cli" in source_text or "argument" in source_text:
        return "argv"
    return "unknown"


def _proof_oracle_facts(data: Mapping[str, Any], legacy: Mapping[str, Any]) -> dict[str, Any]:
    type_facts = _coerce_mapping(data.get("type_facts"))
    static_candidate = _coerce_mapping(type_facts.get("static_candidate"))
    sink = _coerce_mapping(data.get("sink"))
    semantic_seed = _coerce_mapping(type_facts.get("semantic_seed"))
    replay_hints = _coerce_mapping(type_facts.get("replay_hints") or semantic_seed.get("replay_hints"))
    replay_expected = _coerce_mapping(replay_hints.get("expected_result") or replay_hints.get("expected_sink"))
    for source in (replay_hints, replay_expected):
        oracle = source.get("proof_oracle") if isinstance(source.get("proof_oracle"), Mapping) else None
        if not isinstance(oracle, Mapping):
            continue
        kind = str(oracle.get("kind") or oracle.get("type") or "")
        if kind not in {"command_effect", "filesystem_read_escape", "filesystem_write_escape"}:
            continue
        source_info = _coerce_mapping(data.get("source"))
        intent = _coerce_mapping(type_facts.get("deterministic_replay_intent") or semantic_seed.get("deterministic_replay_intent"))
        facts = dict(oracle)
        facts.setdefault("syscall_observation", True)
        facts.setdefault("vulnerability_type", str(data.get("vulnerability_type") or semantic_seed.get("vulnerability_type") or intent.get("vulnerability_type") or ""))
        facts.setdefault("sink", str(sink.get("name") or intent.get("sink") or ""))
        facts.setdefault("source_kind", str(source_info.get("kind") or ""))
        facts.setdefault("source_expression", str(source_info.get("expression") or intent.get("source_expression") or ""))
        return facts
    facts: dict[str, Any] = {}
    for key in (
        "allocation_call_address",
        "allocation_return_address",
        "sink_call_address",
        "sink_return_address",
        "capacity_bytes",
        "write_bound_bytes",
        "write_size_bytes",
        "allocation_size_register",
        "allocation_pointer_register",
        "sink_pointer_register",
        "sink_bound_register",
    ):
        value = type_facts.get(key)
        if value in (None, ""):
            value = static_candidate.get(key)
        if value in (None, "") and key == "sink_call_address":
            value = sink.get("operation_address") or legacy.get("operation_address")
        if value not in (None, ""):
            facts[key] = value
    if "kind" not in facts and any(str(key).endswith("_address") for key in facts):
        facts["kind"] = "bounded_write_overflow"
        facts["observe_memory_write"] = True
    return facts


def _proof_oracle_addresses(value: Any) -> set[str]:
    addresses: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            if key_text.endswith("_address") or key_text in {"address", "call_address", "return_address"}:
                normalized = _normalize_address(item)
                if normalized:
                    addresses.add(normalized)
            elif isinstance(item, (Mapping, list, tuple)):
                addresses.update(_proof_oracle_addresses(item))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            addresses.update(_proof_oracle_addresses(item))
    return addresses


def _normalize_address(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, int):
        return f"0x{value:x}" if value >= 0 else ""
    text = str(value).strip().lower()
    if not text:
        return ""
    try:
        parsed = int(text, 16 if text.startswith("0x") else 10)
    except ValueError:
        return ""
    return f"0x{parsed:x}" if parsed >= 0 else ""


def _collect_grounded_refs(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key).lower()
            if key_text in {"path", "relative_path", "route", "name", "sink", "function_name", "binary"}:
                if isinstance(item, (str, int, float, bool)):
                    refs.add(str(item))
            if key_text in {"env_keys", "ports"} and isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
                refs.update(str(entry) for entry in item)
            refs.update(_collect_grounded_refs(item))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            refs.update(_collect_grounded_refs(item))
    elif isinstance(value, str):
        if value.startswith("/") or value.endswith(".c") or value.endswith(".conf") or value in {
            "network_reachable",
            "unauthenticated",
            "remote",
        }:
            refs.add(value)
    return refs


def _known_routes(evidence_pack: Mapping[str, Any]) -> set[str]:
    routes: set[str] = set()
    intake = evidence_pack.get("intake_facts")
    if isinstance(intake, Mapping):
        route_payload = intake.get("routes")
        if isinstance(route_payload, Mapping):
            rows = route_payload.get("routes", [])
            for row in rows if isinstance(rows, Sequence) else []:
                if isinstance(row, Mapping) and row.get("route"):
                    routes.add(str(row["route"]))
    refs = evidence_pack.get("grounded_refs", [])
    if isinstance(refs, Sequence) and not isinstance(refs, (str, bytes)):
        routes.update(str(item) for item in refs if str(item).startswith("/"))
    return routes


def _known_env_keys(evidence_pack: Mapping[str, Any]) -> set[str]:
    keys: set[str] = set()
    intake = evidence_pack.get("intake_facts")
    if isinstance(intake, Mapping):
        config_payload = intake.get("configs")
        if isinstance(config_payload, Mapping):
            rows = config_payload.get("configs", [])
            for row in rows if isinstance(rows, Sequence) else []:
                if isinstance(row, Mapping):
                    keys.update(str(item) for item in row.get("env_keys", []) or [])
    return keys


def _known_sinks(evidence_pack: Mapping[str, Any]) -> set[str]:
    sinks: set[str] = set()
    sink = evidence_pack.get("sink")
    if isinstance(sink, Mapping):
        if sink.get("name"):
            sinks.add(str(sink["name"]))
        if sink.get("kind"):
            sinks.add(str(sink["kind"]))
    type_facts = evidence_pack.get("type_facts")
    if isinstance(type_facts, Mapping):
        if type_facts.get("sink"):
            sinks.add(str(type_facts["sink"]))
        static_candidate = type_facts.get("static_candidate")
        if isinstance(static_candidate, Mapping) and static_candidate.get("sink"):
            sinks.add(str(static_candidate["sink"]))
    return sinks


def _coerce_reason_codes(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if not hasattr(value, "__iter__"):
        return []
    return [str(item) for item in value]


def _coerce_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        return []
    return [str(item) for item in value if str(item).strip()]


def _coerce_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _coerce_mapping_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _candidate_value(candidate: Any, name: str, default: str = "") -> str:
    if isinstance(candidate, Mapping):
        return str(candidate.get(name, default))
    return str(getattr(candidate, name, default))


def _pack_filename(candidate_id: str) -> str:
    safe = re.sub(r"[^0-9A-Za-z_.-]+", "_", candidate_id).strip("_")
    if not safe:
        safe = "candidate"
    if len(safe) > 160:
        digest = hashlib.sha1(candidate_id.encode("utf-8")).hexdigest()[:12]
        safe = f"{safe[:147].rstrip('_')}_{digest}"
    return f"{safe}.json"


def _bounded_excerpt(text: str, line_number: int, radius: int) -> Mapping[str, Any]:
    lines = (text or "").splitlines()
    if not lines:
        return {"start_line": 0, "end_line": 0, "text": ""}
    if line_number <= 0:
        line_number = 1
    start = max(1, line_number - radius)
    end = min(len(lines), line_number + radius)
    excerpt_lines = lines[start - 1 : end]
    return {
        "start_line": start,
        "end_line": end,
        "text": "\n".join(excerpt_lines)[:4000],
    }
