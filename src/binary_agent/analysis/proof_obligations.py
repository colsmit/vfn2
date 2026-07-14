"""Proof-obligation facts for confirmation evidence packs."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from binary_agent.analysis.fact_enrichment import build_enriched_facts
from binary_agent.analysis.extractors import load_memory_operation_specs
from binary_agent.analysis.provenance import source_read_wrapper_chain_from_candidate, source_read_wrapper_chain_text
from binary_agent.ingest.loader import FunctionNode


ALLOWED_FACT_TOOLS = {
    "trace_expr",
    "get_dominating_guards",
    "get_postdominating_rejects",
    "get_loop_summary",
    "get_range_summary",
    "get_object_provenance",
    "get_candidate_context",
    "get_sink_spec",
    "get_caller_substitutions",
    "get_pcode_slice",
    "get_field_layout",
    "get_alias_history",
    "get_taint_path",
    "get_reachability_path",
}

_OPERATION_SPEC_SET = load_memory_operation_specs()
_OPERATION_SPECS = _OPERATION_SPEC_SET.as_dict_mapping()
_SINK_ALIASES = {
    "isoc99_scanf": "scanf",
    "isoc99_fscanf": "fscanf",
    "isoc99_sscanf": "sscanf",
    "builtin___memcpy_chk": "memcpy",
    "builtin___memmove_chk": "memmove",
    "builtin___memset_chk": "memset",
    "builtin___sprintf_chk": "sprintf",
    "builtin___snprintf_chk": "snprintf",
    "builtin___strcpy_chk": "strcpy",
    "builtin___strcat_chk": "strcat",
    "memcpy_chk": "memcpy",
    "memmove_chk": "memmove",
    "memset_chk": "memset",
    "sprintf_chk": "sprintf",
    "snprintf_chk": "snprintf",
    "strcpy_chk": "strcpy",
    "strcat_chk": "strcat",
    **dict(getattr(_OPERATION_SPEC_SET, "aliases", {}) or {}),
}
_FORTIFY_OBJECT_SIZE_ARG = {
    "memcpy": 3,
    "memmove": 3,
    "memset": 3,
    "strncpy": 3,
    "sprintf": 2,
    "vsprintf": 2,
    "snprintf": 3,
    "vsnprintf": 3,
    "strcpy": 2,
    "strcat": 2,
}
_DIRECT_WRITE_SINKS = {"array_store", "array_write", "field_array_store", "pointer_store", "pcode_store"}
_DECLARED_CAPACITY_SOURCES = {"declared_local_array", "declared_address_taken_object"}
_HEAP_CAPACITY_PREFIXES = ("local_malloc", "local_calloc", "local_realloc", "allocator_wrapper:")
_GHIDRA_METADATA_CAPACITY_SOURCES = {
    "ghidra_data_reference",
    "ghidra_global_ref",
    "ghidra_stack_object",
    "ghidra_static_ref",
    "ghidra_tls_ref",
    "inferred_stack_aggregate_extent",
    "stack metadata",
    "stack_region",
}
_RAW_STACK_NAME_RE = re.compile(r"(?:[acdfipsu]Stack|local|param|auStack|uStack|cStack)_[0-9a-fA-F]+")


def build_proof_obligation(
    candidate: Mapping[str, Any],
    *,
    excerpt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    relation = str(candidate.get("write_relation") or "")
    vulnerability_type = str(candidate.get("vulnerability_type") or "memory_overflow")
    capacity = _safe_int(candidate.get("capacity_bytes"))
    offset_expr = _expr(candidate.get("offset_expr") or "0")
    size_expr = _expr(candidate.get("write_size_expr") or "unknown")
    width = _safe_int(candidate.get("write_size_bytes"))
    if width <= 0 and relation in {"symbolic_offset", "symbolic_read_offset", "iterated_alias_unproven"}:
        width = 1

    if relation == "symbolic_read_offset":
        safe_condition = f"0 <= ({offset_expr}) && ({offset_expr}) + {width} <= {capacity}"
        overflow_condition = f"({offset_expr}) < 0 || ({offset_expr}) + {width} > {capacity}"
        unknowns = _unknowns_for_expr(offset_expr, prefixes=("bound", "signedness"))
        attempt_kind = "local_read_offset_guard_check"
    elif relation == "symbolic_offset":
        safe_condition = f"0 <= ({offset_expr}) && ({offset_expr}) + {width} <= {capacity}"
        overflow_condition = f"({offset_expr}) < 0 || ({offset_expr}) + {width} > {capacity}"
        unknowns = _unknowns_for_expr(offset_expr, prefixes=("bound", "signedness"))
        attempt_kind = "local_offset_guard_check"
    elif relation == "symbolic_size":
        safe_condition = f"({size_expr}) <= {max(capacity, 0)} - ({offset_expr})"
        overflow_condition = f"({size_expr}) > {max(capacity, 0)} - ({offset_expr})"
        unknowns = _unknowns_for_expr(size_expr, prefixes=("upper_bound", "source_control"))
        attempt_kind = "local_size_relation_check"
    elif relation == "iterated_alias_unproven":
        safe_condition = f"start_offset + trip_count * {width} <= {capacity}"
        overflow_condition = f"start_offset + trip_count * {width} > {capacity}"
        unknowns = ["trip_count", "alias_delta", "loop_exit_condition"]
        attempt_kind = "loop_alias_summary"
    elif relation == "append_length_unknown":
        safe_condition = f"current_len + appended_len + terminator <= {capacity}"
        overflow_condition = f"current_len + appended_len + terminator > {capacity}"
        unknowns = ["current_destination_length", "appended_length"]
        attempt_kind = "append_length_model"
    elif relation in {"proven_overflow", "proven_oob_read", "unbounded"}:
        safe_condition = "already disproven by deterministic analyzer"
        overflow_condition = str(candidate.get("overflow_condition") or relation)
        unknowns = []
        attempt_kind = "deterministic_reportability_check"
    else:
        safe_condition = str(candidate.get("overflow_condition") or "unknown")
        overflow_condition = str(candidate.get("overflow_condition") or "unknown")
        unknowns = ["relation_specific_model"]
        attempt_kind = "generic_relation_check"

    if not candidate.get("path_is_valid"):
        unknowns.append("valid_reachability_path")
    if not candidate.get("input_reaches_sink") and candidate.get("reachability_kind") != "entry_path":
        unknowns.append("input_or_entry_reachability")

    return {
        "relation": relation,
        "safe_condition": safe_condition,
        "overflow_condition": overflow_condition,
        "unknowns": _unique(unknowns),
        "analyzer_attempts": [
            {
                "attempt": attempt_kind,
                "result": "failed" if relation not in {"proven_overflow", "unbounded"} else "proved_unsafe",
                "reason": _attempt_reason(candidate, relation),
            }
        ],
        "normalized_terms": {
            "vulnerability_type": vulnerability_type,
            "capacity_bytes": capacity,
            "offset_expr": offset_expr,
            "write_size_expr": size_expr,
            "write_width": width,
            "line_text": str(candidate.get("line_text") or ""),
        },
        "evidence_refs": _default_evidence_refs(candidate, excerpt),
    }


def build_facts_available_to_llm(
    candidate: Mapping[str, Any],
    *,
    stack_object: Mapping[str, Any] | None = None,
    excerpt: Mapping[str, Any] | None = None,
    node: FunctionNode | None = None,
) -> dict[str, Any]:
    excerpt = excerpt or {}
    stack_object = stack_object or {}
    text = str(excerpt.get("text") or "")
    offset_expr = _expr(candidate.get("offset_expr") or "")
    size_expr = _expr(candidate.get("write_size_expr") or "")
    identifiers = _unique(_identifiers(offset_expr) + _identifiers(size_expr))
    enriched = build_enriched_facts(
        candidate,
        source_text=node.text if node else "",
        excerpt=excerpt,
    )
    guard_table = _merge_fact_rows(enriched.get("guard_table", []), _guard_facts(candidate, text))
    def_use_table = _merge_fact_rows(enriched.get("def_use_table", []), _def_use_facts(identifiers, text))
    loop_table = _merge_fact_rows(enriched.get("loop_summary", []), _loop_facts(text))
    pcode_slice = dict(enriched.get("pcode_slice", {}) if isinstance(enriched.get("pcode_slice"), Mapping) else {})
    pcode_slice.setdefault("operation_address", candidate.get("operation_address", ""))
    pcode_slice.setdefault("evidence_sources", candidate.get("evidence_sources", []))
    pcode_slice.setdefault("available", bool(candidate.get("operation_address")))
    reachability = candidate_reachability_summary(candidate)
    taint_table = _candidate_taint_table(candidate)
    source_to_write = _candidate_source_to_write(candidate)
    review_priority = _candidate_trace_dict(candidate, "review_priority")
    stack_coalescing = _candidate_trace_dict(candidate, "stack_coalescing")
    sink_semantics_validation = [
        _sink_semantics_validation(candidate),
    ]
    capacity_validation = [
        _capacity_validation(
            candidate,
            stack_object=stack_object,
            stack_coalescing=stack_coalescing,
            allocation_table=enriched.get("allocation_table", []),
            sink_semantics=sink_semantics_validation[0],
        )
    ]
    reproducer_hypothesis = _reproducer_hypothesis(
        candidate,
        reachability=reachability,
        source_to_write=source_to_write,
        review_priority=review_priority,
        stack_coalescing=stack_coalescing,
    )
    facts = {
        "object_table": [
            {
                "name": candidate.get("target_buffer", ""),
                "kind": candidate.get("destination_kind", ""),
                "capacity_bytes": candidate.get("capacity_bytes", 0),
                "capacity_source": candidate.get("capacity_source", ""),
                "capacity_basis": candidate.get("capacity_basis", ""),
                "stack_object": dict(stack_object),
            }
        ],
        "write_table": [
            {
                "vulnerability_type": candidate.get("vulnerability_type", "memory_overflow"),
                "kind": candidate.get("kind", ""),
                "sink": candidate.get("sink", ""),
                "operation_address": candidate.get("operation_address", ""),
                "line_number": candidate.get("line_number", 0),
                "line_text": candidate.get("line_text", ""),
                "offset_expr": offset_expr,
                "write_size_expr": size_expr,
                "write_size_bytes": candidate.get("write_size_bytes"),
                "write_relation": candidate.get("write_relation", ""),
            }
        ],
        "guard_table": guard_table,
        "def_use_table": def_use_table,
        "loop_table": loop_table,
        "taint_table": taint_table,
        "source_to_write": source_to_write,
        "review_priority": review_priority,
        "stack_coalescing": stack_coalescing,
        "capacity_validation": capacity_validation,
        "sink_semantics_validation": sink_semantics_validation,
        "reproducer_hypothesis": reproducer_hypothesis,
        "pcode_slice": pcode_slice,
        "decompiled_excerpt": excerpt,
        "reachability": reachability,
        "function": {
            "name": candidate.get("function_name", ""),
            "address": candidate.get("address", ""),
            "relative_path": candidate.get("relative_path", ""),
            "line_count": int(getattr(node.record, "line_count", 0) or 0) if node else 0,
        },
    }
    wrapper_chain = source_read_wrapper_chain_from_candidate(candidate)
    if wrapper_chain:
        facts["source_read_wrapper_chain"] = wrapper_chain
        facts["source_read_wrapper_chain_text"] = source_read_wrapper_chain_text(wrapper_chain)
    for key in (
        "range_table",
        "reject_guard_table",
        "loop_summary",
        "append_length_table",
        "allocation_table",
        "safety_result",
        "alias_history",
        "range_summary",
        "expression_summary",
    ):
        facts[key] = enriched.get(key, [] if key.endswith("_table") or key in {"loop_summary", "alias_history"} else {})
    return facts


def candidate_reachability_summary(candidate: Mapping[str, Any]) -> dict[str, Any]:
    trace = _reachability_dataflow(candidate)
    graph = trace.get("graph") if isinstance(trace.get("graph"), Mapping) else {}
    source_link = trace.get("source_link") if isinstance(trace.get("source_link"), Mapping) else {}
    summary = {
        "reachability_kind": candidate.get("reachability_kind", "unknown"),
        "call_path": candidate.get("call_path", []),
        "input_reaches_sink": candidate.get("input_reaches_sink", False),
        "path_is_valid": candidate.get("path_is_valid", False),
        "source_evidence": candidate.get("source_evidence", []),
        "source_link": dict(source_link),
    }
    if isinstance(graph, Mapping):
        for key in (
            "caller_count",
            "callers",
            "root_kind",
            "function_root_kind",
            "path_root",
            "path_root_kind",
            "source_reaches_function",
            "has_real_path",
            "is_exported",
            "is_public",
            "is_root_like",
            "is_entry",
            "is_thread_start",
            "is_graph_root",
            "has_public_symbol",
            "has_source_object",
            "has_callback_evidence",
            "complete_unreachable_candidate",
        ):
            if key in graph:
                summary[key] = graph.get(key)
    return summary


def run_fact_tool_request(
    evidence_pack: Mapping[str, Any],
    request: Mapping[str, Any],
) -> dict[str, Any]:
    tool = str(request.get("tool") or "")
    if tool not in ALLOWED_FACT_TOOLS:
        raise ValueError(f"Unsupported fact tool: {tool!r}")
    candidate = _candidate_from_pack(evidence_pack)
    facts = evidence_pack.get("facts_available_to_llm")
    if not isinstance(facts, Mapping):
        facts = {}
    proof = evidence_pack.get("proof_obligation")
    if not isinstance(proof, Mapping):
        proof = {}
    excerpt = facts.get("decompiled_excerpt") if isinstance(facts.get("decompiled_excerpt"), Mapping) else {}
    text = str(excerpt.get("text") or "")
    result: Any
    if tool == "trace_expr":
        expr = str(request.get("expr") or request.get("symbol") or "")
        if not expr:
            expr = _first_symbolic_term(proof, candidate)
        symbols = set(_identifiers(expr))
        defs = facts.get("def_use_table", [])
        if isinstance(defs, list) and symbols:
            defs = [item for item in defs if isinstance(item, Mapping) and str(item.get("symbol") or "") in symbols]
        ranges = facts.get("range_table", [])
        if isinstance(ranges, list) and symbols:
            ranges = [item for item in ranges if isinstance(item, Mapping) and str(item.get("symbol") or "") in symbols]
        result = {"expr": expr, "defs": defs, "ranges": ranges, "safety_result": facts.get("safety_result", {})}
    elif tool == "get_dominating_guards":
        result = {
            "operation_address": request.get("operation_address") or candidate.get("operation_address", ""),
            "guards": facts.get("guard_table", []),
            "range_table": facts.get("range_table", []),
        }
    elif tool == "get_postdominating_rejects":
        rejects = facts.get("reject_guard_table", [])
        if not rejects:
            rejects = [item for item in facts.get("guard_table", []) if "return" in str(item.get("text", "")) or "goto" in str(item.get("text", ""))]
        result = {
            "operation_address": request.get("operation_address") or candidate.get("operation_address", ""),
            "rejects": rejects,
        }
    elif tool == "get_loop_summary":
        result = {
            "operation_address": request.get("operation_address") or candidate.get("operation_address", ""),
            "loops": facts.get("loop_summary", facts.get("loop_table", [])),
            "loop_table": facts.get("loop_table", []),
            "alias_history": facts.get("alias_history", []),
        }
    elif tool == "get_range_summary":
        result = {
            "operation_address": request.get("operation_address") or candidate.get("operation_address", ""),
            "range_summary": facts.get("range_summary", {}),
            "range_table": facts.get("range_table", []),
            "guard_table": facts.get("guard_table", []),
            "reject_guard_table": facts.get("reject_guard_table", []),
            "expression_summary": facts.get("expression_summary", {}),
            "safety_result": facts.get("safety_result", {}),
        }
    elif tool == "get_caller_substitutions":
        result = {"call_path": candidate.get("call_path", []), "line_text": candidate.get("line_text", ""), "evidence_sources": candidate.get("evidence_sources", [])}
    elif tool == "get_pcode_slice":
        result = {
            **dict(facts.get("pcode_slice", {}) if isinstance(facts.get("pcode_slice"), Mapping) else {}),
            "safety_result": facts.get("safety_result", {}),
            "capacity_validation": facts.get("capacity_validation", []),
            "sink_semantics_validation": facts.get("sink_semantics_validation", []),
        }
    elif tool == "get_field_layout":
        result = {
            "object_table": facts.get("object_table", []),
            "capacity_model": candidate.get("capacity_model", {}),
            "allocation_table": facts.get("allocation_table", []),
            "stack_coalescing": facts.get("stack_coalescing", {}),
            "capacity_validation": facts.get("capacity_validation", []),
            "sink_semantics_validation": facts.get("sink_semantics_validation", []),
        }
    elif tool == "get_object_provenance":
        result = {
            "object_table": facts.get("object_table", []),
            "allocation_table": facts.get("allocation_table", []),
            "capacity_validation": facts.get("capacity_validation", []),
            "stack_object": evidence_pack.get("stack_object", {}),
            "capacity_model": candidate.get("capacity_model", {}),
            "classification_trace": {
                key: value
                for key, value in (candidate.get("classification_trace", {}) or {}).items()
                if key in {"object_resolution", "capacity_resolution", "stack_coalescing", "allocation_table"}
            }
            if isinstance(candidate.get("classification_trace"), Mapping)
            else {},
        }
    elif tool == "get_candidate_context":
        result = {
            "candidate_id": evidence_pack.get("candidate_id", ""),
            "deterministic_candidate": candidate,
            "proof_obligation": proof,
            "write_bound": evidence_pack.get("write_bound", {}),
            "sink_spec_result": evidence_pack.get("sink_spec_result", {}),
            "reachability": facts.get("reachability", evidence_pack.get("reachability", {})),
            "review_priority": facts.get("review_priority", {}),
            "decompiled_excerpt": facts.get("decompiled_excerpt", evidence_pack.get("c_excerpt", {})),
        }
    elif tool == "get_sink_spec":
        requested = str(request.get("sink") or candidate.get("sink") or "")
        normalized = _normalize_sink_name(requested)
        result = {
            "requested_sink": requested,
            "normalized_sink": normalized,
            "spec": dict(_OPERATION_SPECS.get(normalized, {})),
            "sink_semantics_validation": facts.get("sink_semantics_validation", []),
        }
    elif tool == "get_alias_history":
        result = {
            "alias_history": facts.get("alias_history", []),
            "alias_evidence": [source for source in candidate.get("evidence_sources", []) if "alias" in str(source)],
            "line_text": candidate.get("line_text", ""),
        }
    elif tool == "get_taint_path":
        reachability = facts.get("reachability", {})
        result = {
            "source_evidence": reachability.get("source_evidence", []) if isinstance(reachability, Mapping) else [],
            "call_path": reachability.get("call_path", []) if isinstance(reachability, Mapping) else [],
            "taint_table": facts.get("taint_table", []),
            "source_to_write": facts.get("source_to_write", {}),
            "review_priority": facts.get("review_priority", {}),
            "reproducer_hypothesis": facts.get("reproducer_hypothesis", {}),
            "source_link": reachability.get("source_link", {}) if isinstance(reachability, Mapping) else {},
            "reachability": reachability,
        }
    else:
        result = facts.get("reachability", {})
    return {
        "tool": tool,
        "request": dict(request),
        "status": "ok",
        "result": result,
    }


def _candidate_from_pack(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    candidate = evidence_pack.get("deterministic_candidate")
    return candidate if isinstance(candidate, Mapping) else {}


def _reachability_dataflow(candidate: Mapping[str, Any]) -> Mapping[str, Any]:
    trace = candidate.get("classification_trace")
    if not isinstance(trace, Mapping):
        return {}
    value = trace.get("reachability_dataflow")
    return value if isinstance(value, Mapping) else {}


def _candidate_taint_table(candidate: Mapping[str, Any]) -> list[dict[str, Any]]:
    trace = _reachability_dataflow(candidate)
    expr_taint = trace.get("expr_taint") if isinstance(trace.get("expr_taint"), Mapping) else {}
    rows = expr_taint.get("taint_table", []) if isinstance(expr_taint, Mapping) else []
    if not isinstance(rows, list):
        return []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _candidate_source_to_write(candidate: Mapping[str, Any]) -> dict[str, Any]:
    trace = candidate.get("classification_trace")
    if not isinstance(trace, Mapping):
        return {}
    source_to_write = trace.get("source_to_write")
    return dict(source_to_write) if isinstance(source_to_write, Mapping) else {}


def _candidate_trace_dict(candidate: Mapping[str, Any], key: str) -> dict[str, Any]:
    trace = candidate.get("classification_trace")
    if not isinstance(trace, Mapping):
        return {}
    value = trace.get(key)
    return dict(value) if isinstance(value, Mapping) else {}


def _capacity_validation(
    candidate: Mapping[str, Any],
    *,
    stack_object: Mapping[str, Any],
    stack_coalescing: Mapping[str, Any],
    allocation_table: Any,
    sink_semantics: Mapping[str, Any],
) -> dict[str, Any]:
    capacity = _safe_int(candidate.get("capacity_bytes"))
    if capacity <= 0:
        capacity = _safe_int(stack_object.get("size_bytes"))
    target = str(candidate.get("target_buffer") or "")
    destination_kind = str(candidate.get("destination_kind") or stack_object.get("destination_kind") or "")
    source = str(
        candidate.get("capacity_source")
        or stack_object.get("capacity_source")
        or stack_object.get("capacity_basis_kind")
        or ""
    )
    basis = str(candidate.get("capacity_basis") or stack_object.get("annotation") or stack_object.get("offset_range") or "")
    capacity_model = candidate.get("capacity_model") if isinstance(candidate.get("capacity_model"), Mapping) else {}
    reasons: list[str] = []
    conflicts: list[dict[str, Any]] = []
    supporting_refs = ["object:0"]

    allocation_match = _exact_allocation_match(allocation_table)
    if allocation_match:
        reasons.append("exact_allocator_match")
        supporting_refs.append("allocation:0")

    object_size_bytes = sink_semantics.get("object_size_bytes")
    if isinstance(object_size_bytes, int) and object_size_bytes > 0 and capacity > 0:
        supporting_refs.append("sink_semantics:0")
        if object_size_bytes > capacity:
            conflicts.append(
                {
                    "kind": "chk_object_size_conflict",
                    "object_size_bytes": object_size_bytes,
                    "capacity_bytes": capacity,
                    "relation": "object_size_exceeds_selected_capacity",
                }
            )
            reasons.append("object_size_conflict")
        elif object_size_bytes == capacity:
            reasons.append("chk_object_size_matches_capacity")

    merged_names = _stack_object_var_names(stack_object)
    if len(merged_names) > 1:
        reasons.append("merged_stack_region")
    if str(stack_coalescing.get("classification") or "") == "likely_decompiler_split":
        reasons.append("likely_decompiler_split")
    if capacity > 0 and destination_kind == "stack" and capacity <= 8 and _looks_like_raw_stack_capacity(target, basis, source):
        reasons.append("small_raw_stack_slot")

    if capacity <= 0 and not allocation_match:
        status = "unknown"
        reasons.append("missing_fixed_capacity")
    elif conflicts:
        status = "invalid"
    elif allocation_match:
        status = "strong"
    elif source in _DECLARED_CAPACITY_SOURCES:
        status = "strong"
        reasons.append(source)
    elif source in _GHIDRA_METADATA_CAPACITY_SOURCES:
        status = "weak"
        reasons.append(source)
    elif destination_kind in {"global", "static_local", "tls"} and capacity > 0:
        status = "strong"
        reasons.append(f"{destination_kind}_object")
    elif destination_kind == "heap" and capacity > 0 and source.startswith(_HEAP_CAPACITY_PREFIXES):
        status = "strong"
        reasons.append("exact_heap_allocation")
    elif destination_kind == "struct_field" and capacity > 0:
        status = "strong"
        reasons.append("struct_field_object")
    elif source in {"sink_size_arg", "caller_size_argument", "parameter_contract"}:
        status = "weak"
        reasons.append(source)
    elif "merged_stack_region" in reasons or "likely_decompiler_split" in reasons or "small_raw_stack_slot" in reasons:
        status = "weak"
    elif destination_kind == "stack" and capacity > 0 and source in {"", "stack metadata"}:
        status = "weak"
        reasons.append("single_stack_region_metadata")
    elif capacity > 0 and capacity_model.get("trust") == "high":
        status = "strong"
        reasons.append("high_trust_capacity_model")
    else:
        status = "weak" if capacity > 0 else "unknown"
        if capacity > 0:
            reasons.append("unclassified_capacity_source")

    return {
        "status": status,
        "target": target,
        "destination_kind": destination_kind,
        "capacity_bytes": capacity,
        "capacity_source": source,
        "capacity_basis": basis,
        "capacity_model": dict(capacity_model),
        "reasons": _unique(reasons),
        "conflicts": conflicts,
        "supporting_refs": _unique(supporting_refs),
    }


def _sink_semantics_validation(candidate: Mapping[str, Any]) -> dict[str, Any]:
    candidate_sink = str(candidate.get("sink") or "")
    line_text = str(candidate.get("line_text") or "")
    raw_sink, args = _raw_sink_call_for_candidate(line_text, candidate_sink)
    normalized_sink = _normalize_sink_name(raw_sink or candidate_sink)
    spec = _OPERATION_SPECS.get(normalized_sink, {})
    is_direct_write = candidate_sink in _DIRECT_WRITE_SINKS or str(candidate.get("kind") or "") in {
        "indexed_store",
        "field_indexed_write",
        "pointer_store",
        "pcode_store",
    }
    is_chk = _is_fortify_chk(raw_sink)
    reasons: list[str] = []
    object_size_arg_index: int | None = None
    object_size_expr = ""
    object_size_bytes: int | None = None
    if is_chk:
        object_size_arg_index = _FORTIFY_OBJECT_SIZE_ARG.get(normalized_sink)
        if object_size_arg_index is None:
            reasons.append("unknown_chk_object_size_position")
        elif object_size_arg_index < len(args):
            object_size_expr = args[object_size_arg_index]
            object_size_bytes = _parse_int_literal(object_size_expr)
            reasons.append("fortify_chk_object_size_argument")
        else:
            reasons.append("missing_chk_object_size_argument")

    capacity = _safe_int(candidate.get("capacity_bytes"))
    object_size_relation = "not_applicable"
    object_size_conflict = False
    if object_size_expr:
        if object_size_bytes is None:
            object_size_relation = "symbolic_object_size"
        elif capacity <= 0:
            object_size_relation = "object_size_without_selected_capacity"
        elif object_size_bytes > capacity:
            object_size_relation = "exceeds_selected_capacity"
            object_size_conflict = True
        elif object_size_bytes == capacity:
            object_size_relation = "matches_selected_capacity"
        else:
            object_size_relation = "below_selected_capacity"

    if spec:
        status = "known"
        reasons.append("sink_spec_known")
    elif is_direct_write:
        status = "known"
        normalized_sink = candidate_sink
        reasons.append("deterministic_store_semantics")
    else:
        status = "unknown"
        reasons.append("missing_sink_spec")
    if is_chk and not object_size_expr:
        status = "unknown"

    return {
        "status": status,
        "raw_sink": raw_sink or candidate_sink,
        "normalized_sink": normalized_sink or candidate_sink,
        "semantics": str(spec.get("semantics") or ("direct_write" if is_direct_write and not spec else "")),
        "is_fortify_chk": is_chk,
        "dest_arg_index": _optional_int(spec.get("dest_arg")) if spec else 0 if is_direct_write else None,
        "size_arg_index": _optional_int(spec.get("size_arg")) if spec else None,
        "object_size_arg_index": object_size_arg_index,
        "object_size_expr": object_size_expr,
        "object_size_bytes": object_size_bytes,
        "object_size_relation": object_size_relation,
        "object_size_conflict": object_size_conflict,
        "arg_count": len(args),
        "reasons": _unique(reasons),
    }


def _exact_allocation_match(allocation_table: Any) -> bool:
    rows = allocation_table if isinstance(allocation_table, Sequence) and not isinstance(allocation_table, (str, bytes, bytearray)) else []
    return any(isinstance(row, Mapping) and row.get("matched") and row.get("exact") for row in rows)


def _stack_object_var_names(stack_object: Mapping[str, Any]) -> list[str]:
    names = stack_object.get("var_names") if isinstance(stack_object, Mapping) else []
    if not isinstance(names, Sequence) or isinstance(names, (str, bytes, bytearray)):
        return []
    return [str(name) for name in names if str(name)]


def _looks_like_raw_stack_capacity(target: str, basis: str, source: str) -> bool:
    text = " ".join([target, basis, source])
    if source in {"declared_local_array", "declared_address_taken_object"}:
        return False
    return bool(_RAW_STACK_NAME_RE.search(text)) or source in {"ghidra_stack_object", "stack_region", "stack metadata", ""}


def _raw_sink_call_for_candidate(line_text: str, candidate_sink: str) -> tuple[str, list[str]]:
    normalized_candidate = _normalize_sink_name(candidate_sink)
    for raw_name, args in _iter_raw_calls(line_text):
        normalized = _normalize_sink_name(raw_name)
        if normalized == normalized_candidate or raw_name == candidate_sink:
            return raw_name, args
    return candidate_sink, []


def _iter_raw_calls(line_text: str) -> list[tuple[str, list[str]]]:
    calls: list[tuple[str, list[str]]] = []
    idx = 0
    quote = ""
    escaped = False
    while idx < len(line_text):
        ch = line_text[idx]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            idx += 1
            continue
        if ch in {"'", '"'}:
            quote = ch
            idx += 1
            continue
        if not (ch.isalpha() or ch == "_"):
            idx += 1
            continue
        start = idx
        idx += 1
        while idx < len(line_text) and (line_text[idx].isalnum() or line_text[idx] == "_"):
            idx += 1
        raw_name = line_text[start:idx]
        open_index = idx
        while open_index < len(line_text) and line_text[open_index].isspace():
            open_index += 1
        if open_index >= len(line_text) or line_text[open_index] != "(":
            continue
        close_index = _find_matching_paren(line_text, open_index)
        if close_index < 0:
            continue
        normalized = _normalize_sink_name(raw_name)
        if normalized in _OPERATION_SPECS or _is_fortify_chk(raw_name):
            calls.append((raw_name, _split_arguments(line_text[open_index + 1 : close_index])))
        idx = close_index + 1
    return calls


def _find_matching_paren(text: str, open_index: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for idx in range(open_index, len(text)):
        ch = text[idx]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _split_arguments(text: str) -> list[str]:
    args: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for idx, ch in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
            continue
        if ch in "([{":
            depth += 1
            continue
        if ch in ")]}":
            depth = max(0, depth - 1)
            continue
        if ch == "," and depth == 0:
            args.append(text[start:idx].strip())
            start = idx + 1
    tail = text[start:].strip()
    if tail:
        args.append(tail)
    return args


def _normalize_sink_name(name: str) -> str:
    lowered = str(name or "").strip().split("::")[-1].lower()
    lowered = lowered.split("@", 1)[0]
    lowered = lowered.lstrip("_")
    if lowered in _SINK_ALIASES:
        return _SINK_ALIASES[lowered]
    if lowered in _OPERATION_SPECS:
        return lowered
    if lowered.endswith("_chk"):
        base = lowered[:-4].lstrip("_")
        if base in _OPERATION_SPECS:
            return base
    for sink in sorted(_OPERATION_SPECS, key=len, reverse=True):
        if lowered == sink or lowered.endswith(f"_{sink}") or lowered.endswith(sink):
            return sink
    return lowered


def _is_fortify_chk(raw_sink: str) -> bool:
    lowered = str(raw_sink or "").strip().split("::")[-1].lower()
    lowered = lowered.split("@", 1)[0].lstrip("_")
    return lowered.endswith("_chk") or lowered in _SINK_ALIASES and lowered.endswith("_chk")


def _parse_int_literal(expr: str) -> int | None:
    text = str(expr or "").strip()
    text = re.sub(r"^\((?:size_t|ulong|long|uint|unsigned int|int)\)", "", text).strip()
    if not re.fullmatch(r"[-+]?(?:0x[0-9a-fA-F]+|\d+)", text):
        return None
    try:
        value = int(text, 0)
    except ValueError:
        return None
    if value in {-1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF}:
        return None
    return value


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _reproducer_hypothesis(
    candidate: Mapping[str, Any],
    *,
    reachability: Mapping[str, Any],
    source_to_write: Mapping[str, Any],
    review_priority: Mapping[str, Any],
    stack_coalescing: Mapping[str, Any],
) -> dict[str, Any]:
    roles = source_to_write.get("roles") if isinstance(source_to_write.get("roles"), Mapping) else {}
    controlled_roles: list[str] = []
    role_items = roles.items() if isinstance(roles, Mapping) else []
    for role, fact in role_items:
        if not isinstance(fact, Mapping):
            continue
        classification = str(fact.get("classification") or "")
        if classification in {"source_controlled", "parameter_controlled"}:
            controlled_roles.append(f"{role}:{classification}")
    call_path = reachability.get("call_path", []) if isinstance(reachability, Mapping) else []
    entry = call_path[0] if isinstance(call_path, list) and call_path else candidate.get("function_name", "")
    source_evidence = reachability.get("source_evidence", []) if isinstance(reachability, Mapping) else []
    evidence_text = " ".join(str(item) for item in source_evidence)
    evidence_text = " ".join([evidence_text, str(candidate.get("function_name") or ""), str(candidate.get("line_text") or "")]).lower()
    input_surface = _input_surface_from_evidence(evidence_text, roles)
    blocking_unknowns: list[str] = []
    if not isinstance(source_to_write, Mapping) or not source_to_write.get("complete"):
        blocking_unknowns.append("source_to_write_roles_incomplete")
    if _safe_int(candidate.get("capacity_bytes")) <= 0:
        blocking_unknowns.append("exact_destination_capacity")
    if isinstance(reachability, Mapping) and not reachability.get("path_is_valid"):
        blocking_unknowns.append("valid_reachability_path")
    if isinstance(stack_coalescing, Mapping) and stack_coalescing.get("classification") == "likely_decompiler_split":
        blocking_unknowns.append("decompiler_split_stack_object")
    steps = [
        f"Reach {entry or candidate.get('function_name', 'candidate function')} through {input_surface}.",
        f"Control {', '.join(controlled_roles) if controlled_roles else 'the write role that remains unknown'}.",
        f"Exercise {candidate.get('sink', 'write')} at line {candidate.get('line_number', 0)} with relation {candidate.get('write_relation', '')}.",
        "Validate with sanitizer, debugger, or crash triage at the reported operation address.",
    ]
    return {
        "input_surface": input_surface,
        "suggested_entry": entry,
        "call_path": call_path if isinstance(call_path, list) else [],
        "controlled_roles": controlled_roles,
        "priority": review_priority.get("priority", "") if isinstance(review_priority, Mapping) else "",
        "steps": steps,
        "blocking_unknowns": _unique(blocking_unknowns),
    }


def _input_surface_from_evidence(evidence_text: str, roles: Mapping[str, Any]) -> str:
    if "argv" in evidence_text or "argc" in evidence_text:
        return "cli_argument"
    if any(token in evidence_text for token in ("recv", "recvfrom", "socket", "packet", "message", "enip", "modbus")):
        return "network_input"
    if any(token in evidence_text for token in ("fgets", "gets", "scanf", "stdin")):
        return "stdin"
    if any(token in evidence_text for token in ("read(", "file", "fd", "fread")):
        return "file_or_fd"
    if any(
        isinstance(fact, Mapping) and fact.get("classification") == "parameter_controlled"
        for fact in roles.values()
    ):
        return "api_parameter"
    return "unknown"


def _first_symbolic_term(proof: Mapping[str, Any], candidate: Mapping[str, Any]) -> str:
    terms = proof.get("normalized_terms")
    if isinstance(terms, Mapping):
        for key in ("offset_expr", "write_size_expr"):
            identifiers = _identifiers(str(terms.get(key) or ""))
            if identifiers:
                return identifiers[0]
    for key in ("offset_expr", "write_size_expr"):
        identifiers = _identifiers(str(candidate.get(key) or ""))
        if identifiers:
            return identifiers[0]
    return ""


def _guard_facts(candidate: Mapping[str, Any], text: str) -> list[dict[str, Any]]:
    facts = [
        {"source": "candidate_guard_evidence", "text": str(item), "accepted": True}
        for item in candidate.get("guard_evidence", []) or []
    ]
    for line_number, line in _excerpt_lines(text):
        stripped = line.strip()
        if re.search(r"\b(?:if|while|for)\s*\(", stripped):
            facts.append({"source": "excerpt", "line_number": line_number, "text": stripped, "accepted": "unknown"})
    return facts[:20]


def _def_use_facts(identifiers: list[str], text: str) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for identifier in identifiers:
        pattern = re.compile(rf"\b{re.escape(identifier)}\b\s*(?:=|\+=|-=|\+\+|--)")
        for line_number, line in _excerpt_lines(text):
            if pattern.search(line):
                facts.append({"symbol": identifier, "line_number": line_number, "text": line.strip()})
    return facts[:30]


def _loop_facts(text: str) -> list[dict[str, Any]]:
    loops: list[dict[str, Any]] = []
    for line_number, line in _excerpt_lines(text):
        stripped = line.strip()
        match = re.search(r"\b(?P<kind>for|while)\s*\((?P<condition>[^)]*)\)", stripped)
        if match:
            loops.append({"line_number": line_number, "kind": match.group("kind"), "condition": match.group("condition"), "text": stripped})
    return loops[:12]


def _excerpt_lines(text: str) -> list[tuple[int, str]]:
    return [(index, line) for index, line in enumerate((text or "").splitlines(), start=1)]


def _attempt_reason(candidate: Mapping[str, Any], relation: str) -> str:
    if relation in {"proven_overflow", "unbounded"}:
        return str(candidate.get("overflow_condition") or "deterministic analyzer classified this write as unsafe")
    if relation == "symbolic_offset":
        return "available guards do not prove the symbolic offset stays within capacity"
    if relation == "symbolic_size":
        return "available guards do not prove the symbolic write size fits the remaining capacity"
    if relation == "iterated_alias_unproven":
        return "loop trip count or alias progression is not bounded tightly enough"
    if relation == "append_length_unknown":
        return "current destination string length is not known"
    return "relation-specific proof is not implemented"


def _default_evidence_refs(candidate: Mapping[str, Any], excerpt: Mapping[str, Any] | None) -> list[str]:
    refs = ["candidate:0", "write:0", "object:0", "capacity_validation:0", "sink_semantics:0"]
    if candidate.get("guard_evidence"):
        refs.append("guard:0")
    if candidate.get("source_evidence"):
        refs.append("source:0")
    if excerpt and excerpt.get("text"):
        refs.append("excerpt:0")
    return refs


def _unknowns_for_expr(expr: str, *, prefixes: tuple[str, ...]) -> list[str]:
    identifiers = _identifiers(expr)
    if not identifiers:
        return ["constant_relation_review"]
    unknowns: list[str] = []
    for identifier in identifiers:
        for prefix in prefixes:
            unknowns.append(f"{prefix}({identifier})")
    return unknowns


def _identifiers(expr: str) -> list[str]:
    ignored = {
        "char",
        "int",
        "long",
        "short",
        "size_t",
        "uint",
        "ulong",
        "undefined",
        "undefined1",
        "undefined2",
        "undefined4",
        "undefined8",
    }
    return _unique([item for item in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expr or "") if item not in ignored])


def _expr(value: Any) -> str:
    text = str(value or "").strip()
    return text or "unknown"


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _unique(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _merge_fact_rows(*tables: Any) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for table in tables:
        if not isinstance(table, list):
            continue
        for item in table:
            if not isinstance(item, Mapping):
                continue
            row = dict(item)
            key = repr(sorted(row.items()))
            if key in seen:
                continue
            seen.add(key)
            merged.append(row)
    return merged
