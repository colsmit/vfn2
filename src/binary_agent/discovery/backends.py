"""Four shared deterministic discovery backends."""

from __future__ import annotations

import base64
import binascii
import re
import time
from dataclasses import replace
from typing import Any, Iterable, Mapping, Sequence

from binary_agent.analysis.candidates import extract_static_candidates
from binary_agent.analysis.program_index import IndexedOperation, ProgramIndex
from binary_agent.discovery.base import DiscoveryContext
from binary_agent.pipeline import (
    CandidateState,
    CandidateStatus,
    ProofObligation,
    candidate_state_from_static_candidate,
    semantic_candidate_id,
)
from binary_agent.taxonomy import get_vulnerability_spec


ROOT_CAUSE_TYPES = {
    "integer_overflow_to_memory_access": "integer_overflow",
    "integer_underflow_to_memory_access": "integer_underflow",
    "signed_conversion_to_memory_access": "signed_conversion",
    "integer_truncation_to_memory_access": "truncation",
}
ROOT_CAUSE_RELATIONS = {
    "integer_overflow_risk": "integer_overflow",
    "integer_underflow_risk": "integer_underflow",
    "signed_conversion_risk": "signed_conversion",
    "integer_truncation_risk": "truncation",
    "off_by_one": "off_by_one",
    "negative_offset": "negative_offset",
    "allocation_size_mismatch": "allocation_size_mismatch",
}
PLACEHOLDER_RE = re.compile(
    r"^(?:changeme|password|secret|example|sample|dummy|test|todo|xxx+|0+|a+)$",
    re.IGNORECASE,
)


class MemoryAccessBackend:
    name = "memory_access"

    def __init__(self) -> None:
        self.extraction_count = 0
        self.last_metrics: Mapping[str, Any] = {}

    def discover(
        self,
        context: DiscoveryContext,
        index: ProgramIndex,
        enabled_types: frozenset[str],
    ) -> Iterable[CandidateState]:
        started = time.perf_counter()
        self.extraction_count += 1
        raw_candidates = extract_static_candidates(index.manifest, index.nodes)
        groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
        for candidate in raw_candidates:
            data = _with_index_operation_address(candidate.to_dict(), index)
            key = (
                str(data.get("address") or ""),
                str(data.get("operation_address") or data.get("address") or ""),
                f"{data.get('destination_kind') or 'memory'}:{data.get('target_buffer') or 'unknown'}",
            )
            groups.setdefault(key, []).append(data)

        emitted: list[CandidateState] = []
        for rows in groups.values():
            final_rows = [row for row in rows if str(row.get("vulnerability_type") or "") not in ROOT_CAUSE_TYPES]
            if not final_rows:
                continue
            selected = _richest_static_row(final_rows)
            vulnerability_type = _memory_type(selected)
            if vulnerability_type not in enabled_types:
                continue
            if not _grounded_static_memory_candidate(selected, vulnerability_type):
                continue
            selected = {**selected, "vulnerability_type": vulnerability_type}
            state = candidate_state_from_static_candidate(selected)
            state = _attach_indexed_memory_object(state, selected, index)
            roots = {
                ROOT_CAUSE_TYPES[str(row.get("vulnerability_type"))]
                for row in rows
                if str(row.get("vulnerability_type")) in ROOT_CAUSE_TYPES
            }
            for row in rows:
                relation = str(row.get("write_relation") or "")
                if relation in ROOT_CAUSE_RELATIONS:
                    roots.add(ROOT_CAUSE_RELATIONS[relation])
                offset = str(row.get("offset_expr") or "")
                if re.search(r"(?:^|[^A-Za-z0-9_])-\s*(?:0x[0-9a-f]+|\d+)", offset, re.IGNORECASE):
                    roots.add("negative_offset")
            state = replace(
                state,
                root_causes=tuple(sorted(roots)),
                metadata={**dict(state.metadata), "index_build_seconds": index.metrics.build_seconds},
            )
            emitted.append(state)

        if "null_pointer_dereference" in enabled_types:
            emitted.extend(_null_dereference_candidates(context, index))
        if "overlapping_memory_copy" in enabled_types:
            emitted.extend(_overlap_candidates(context, index))
        if "uninitialized_memory_use" in enabled_types:
            emitted.extend(_uninitialized_candidates(context, index))
        if "out_of_bounds_read" in enabled_types:
            emitted.extend(_rounded_stride_read_candidates(context, index))
        self.last_metrics = {
            "runtime_seconds": round(time.perf_counter() - started, 6),
            "functions_examined": len(index.functions),
            "operations_examined": len(index.operations_for_backend(self.name)),
            "spatial_extractions": self.extraction_count,
            "candidates_emitted": len(emitted),
        }
        return emitted


class MemoryLifetimeBackend:
    name = "memory_lifetime"

    def discover(
        self,
        context: DiscoveryContext,
        index: ProgramIndex,
        enabled_types: frozenset[str],
    ) -> Iterable[CandidateState]:
        # Mature ownership-table, callback, refcount, and cross-function logic is
        # retained behind this one backend while all resources share the index.
        from binary_agent.discovery.patterns import DoubleFreePattern, InvalidFreePattern, UseAfterFreePattern

        states: list[CandidateState] = []
        legacy = {
            "use_after_free": UseAfterFreePattern(),
            "double_free": DoubleFreePattern(),
            "invalid_free": InvalidFreePattern(),
        }
        for vulnerability_type, detector in legacy.items():
            if vulnerability_type in enabled_types:
                for item in detector.discover(context):
                    state = _enrich_lifetime_state(_normalize_state(item, context, self.name), index)
                    operation_name = str(state.operation.get("name") or "")
                    local_callee = next(
                        (
                            function
                            for function in index.functions
                            if function.name.lower() == operation_name.lower()
                        ),
                        None,
                    )
                    if local_callee is not None and operation_name.lower() not in {
                        "free",
                        "operator_delete",
                        "operator_delete_array",
                        "fclose",
                        "close",
                        "closedir",
                        "closesocket",
                    }:
                        # A generic pattern may call any repeated local function
                        # a release.  Only the indexed parameter instantiation
                        # may establish the inner release and caller identity.
                        continue
                    if "mutually_exclusive_event_paths" not in state.blockers:
                        states.append(state)
        states.extend(_indexed_lifetime_candidates(context, index, enabled_types))
        if "use_after_free" in enabled_types:
            states.extend(_reentrant_copy_uaf_candidates(context, index))
        return states


class SemanticEffectBackend:
    name = "semantic_effect"

    def discover(
        self,
        context: DiscoveryContext,
        index: ProgramIndex,
        enabled_types: frozenset[str],
    ) -> Iterable[CandidateState]:
        states: list[CandidateState] = []
        effect_to_type = {
            "command_effect": "command_injection",
            "filesystem_read_escape": "path_traversal",
            "format_string_effect": "format_string",
            "query_execution": "sql_injection",
            "process_argv": "argument_injection",
            "code_evaluation": "code_injection",
            "outbound_connection": "server_side_request_forgery",
            "http_header_emission": "http_header_injection",
            "log_emission": "log_injection",
            "redirect_emission": "open_redirect",
        }
        for operation in index.operations_for_backend(self.name):
            if "unsafe_file_write" in enabled_types and operation.name in {"open", "fopen", "write_file"}:
                write_mode = any(
                    re.search(r'(?:["\'](?:w|a|r\+)|O_(?:WRONLY|CREAT|TRUNC|APPEND))', argument)
                    for argument in operation.arguments[1:]
                ) or operation.effect_kind == "filesystem_write_escape"
                path_value = operation.role("path")
                if write_mode and _is_untrusted(path_value):
                    states.append(
                        _indexed_state(
                            context,
                            operation,
                            vulnerability_type="unsafe_file_write",
                            backend=self.name,
                            affected_identity=f"effect:filesystem_write_escape:{operation.operation_address}",
                            affected_kind="process_effect",
                            source={"kind": "path_expression", "expression": path_value},
                            facts={"effect_kind": "filesystem_write_escape", "argument_roles": dict(operation.argument_roles)},
                            blockers=["concrete_effect_replay_required"],
                            mechanism="unrestricted_upload" if any(token in path_value.lower() for token in ("upload", "filename", "multipart")) else "",
                        )
                    )
            if (
                "credential_disclosure" in enabled_types
                and operation.effect_kind in {"format_string_effect", "log_emission", "http_header_emission"}
                and any(
                    not _quoted_literal(value)
                    and re.search(
                        r"pass(?:word|wd)?|secret|token|credential",
                        value,
                        re.IGNORECASE,
                    )
                    for value in operation.arguments
                )
            ):
                states.append(
                    _indexed_state(
                        context,
                        operation,
                        vulnerability_type="credential_disclosure",
                        backend=self.name,
                        affected_identity=f"effect:credential_disclosure:{operation.operation_address}",
                        affected_kind="process_effect",
                        source={"kind": "credential_value", "expression": operation.arguments[-1] if operation.arguments else ""},
                        facts={"effect_kind": "credential_disclosure", "argument_roles": dict(operation.argument_roles)},
                        blockers=["concrete_effect_replay_required"],
                    )
                )
            vulnerability_type = effect_to_type.get(operation.effect_kind)
            if vulnerability_type not in enabled_types:
                continue
            controlled = _controlled_semantic_argument(
                operation,
                vulnerability_type,
                index,
            )
            if not controlled:
                continue
            states.append(
                _indexed_state(
                    context,
                    operation,
                    vulnerability_type=vulnerability_type,
                    backend=self.name,
                    affected_identity=f"effect:{operation.effect_kind}:{operation.operation_address}",
                    affected_kind="process_effect",
                    source={"kind": "attacker_input", "expression": controlled},
                    facts={"effect_kind": operation.effect_kind, "argument_roles": dict(operation.argument_roles)},
                    blockers=["concrete_effect_replay_required"],
                )
            )
        if "auth_bypass" in enabled_types:
            for function in index.functions:
                if not any(token in function.name.lower() for token in ("auth", "login", "permission", "access")):
                    continue
                match = re.search(r"\breturn\s+(?:1|true|0x1)\s*;", function.text, re.IGNORECASE)
                if not match or re.search(r"\b(strcmp|memcmp|crypt|hash|verify|token)\b", function.text, re.IGNORECASE):
                    continue
                operation = IndexedOperation(
                    kind="decision",
                    name="authorization_decision",
                    backend=self.name,
                    semantics="unconditional_allow",
                    effect_kind="auth_bypass_effect",
                    function_name=function.name,
                    function_address=function.address,
                    operation_address=f"{function.address}:auth_allow",
                    line_number=function.text[: match.start()].count("\n") + 1,
                    evidence_source="program_index_function",
                )
                states.append(
                    _indexed_state(
                        context,
                        operation,
                        vulnerability_type="auth_bypass",
                        backend=self.name,
                        affected_identity=f"effect:auth_bypass:{function.address}",
                        affected_kind="process_effect",
                        source={"kind": "request_context", "expression": function.name},
                        facts={"effect_kind": "auth_bypass_effect", "decision": "unconditional_allow"},
                        blockers=["concrete_effect_replay_required"],
                    )
                )
        return states


def _controlled_semantic_argument(
    operation: IndexedOperation,
    vulnerability_type: str,
    index: ProgramIndex,
) -> str:
    preferred_roles = {
        "argument_injection": {"argv", "first_argument"},
        "format_string": {"format"},
        "sql_injection": {"query"},
        "code_injection": {"code"},
        "server_side_request_forgery": {"target"},
        "http_header_injection": {"header"},
        "log_injection": {"message"},
        "open_redirect": {"location"},
    }.get(vulnerability_type)
    return next(
        (
            value
            for role, value in operation.argument_roles
            if (preferred_roles is None or role in preferred_roles)
            and _semantic_expression_controlled(value, operation, index)
        ),
        "",
    )


def _semantic_expression_controlled(
    expression: str,
    operation: IndexedOperation,
    index: ProgramIndex,
) -> bool:
    if _quoted_literal(expression):
        return False
    if _is_untrusted(expression):
        return True
    function = index.function(operation.function_name)
    if function is None:
        return False
    tainted: set[str] = set()
    assignments = re.findall(
        r"\b(?P<left>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*)\s*=\s*(?P<right>[^;]+);",
        function.text,
    )
    changed = True
    while changed:
        changed = False
        for left, right in assignments:
            right_is_process_input = bool(
                re.search(r"\b(?:argv|input|request|user)[A-Za-z0-9_]*\b", right, re.IGNORECASE)
                or re.search(r"\bparam_\d+\s*\[\s*[1-9]\d*\s*\]", right)
                or re.search(r"\bparam_\d+\s*\+\s*(?:0x)?[1-9][0-9a-f]*", right, re.IGNORECASE)
            )
            right_is_tainted = right_is_process_input or any(
                re.search(rf"\b{re.escape(name)}\b", right) for name in tainted
            )
            base = left.split(".", 1)[0]
            if right_is_tainted and base not in tainted:
                tainted.add(base)
                changed = True
    if any(re.search(rf"\b{re.escape(name)}\b", expression) for name in tainted):
        return True
    base_match = re.search(r"&?local_(?P<offset>[0-9a-f]+)", expression, re.IGNORECASE)
    if base_match:
        base_offset = int(base_match.group("offset"), 16)
        for name in tainted:
            item = re.fullmatch(r"local_([0-9a-f]+)", name, re.IGNORECASE)
            if item and 0 <= base_offset - int(item.group(1), 16) <= 0x80:
                return True
    return False


class StaticEvidenceBackend:
    name = "static_evidence"

    def discover(
        self,
        context: DiscoveryContext,
        index: ProgramIndex,
        enabled_types: frozenset[str],
    ) -> Iterable[CandidateState]:
        states: list[CandidateState] = []
        for literal in index.strings:
            if (
                not literal.reachable
                or _placeholder(literal.value)
                or re.search(r"(?:^|_)(?:test|example|fixture|selftest)(?:_|$)", literal.function_name, re.IGNORECASE)
            ):
                continue
            function = index.function(literal.function_name)
            if function is None:
                continue
            if (
                "hardcoded_credential" in enabled_types
                and any(
                    vulnerability_type == "hardcoded_credential"
                    for vulnerability_type, _mechanism in _classify_static_literal(
                        literal.value,
                        literal.context,
                    )
                )
            ):
                fingerprint = _literal_fingerprint(literal.value)
                operation = IndexedOperation(
                    kind="literal",
                    name="embedded_credential",
                    backend=self.name,
                    semantics="embedded_credential",
                    effect_kind="embedded_secret",
                    function_name=function.name,
                    function_address=function.address,
                    operation_address=literal.address,
                    line_number=0,
                    evidence_source=literal.source,
                    observed_name="embedded_credential",
                )
                states.append(
                    _indexed_state(
                        context,
                        operation,
                        vulnerability_type="hardcoded_credential",
                        backend=self.name,
                        affected_identity=f"literal:{literal.address}:{fingerprint}",
                        affected_kind="embedded_configuration",
                        source={
                            "kind": "binary_literal_fingerprint",
                            "length": len(literal.value),
                            "fingerprint": fingerprint,
                        },
                        facts={
                            "literal_fingerprint": fingerprint,
                            "literal_length": len(literal.value),
                            "literal_verified": True,
                            "literal_address": literal.address,
                            "consumer_address": literal.address,
                            "consumer_name": "declaration_context",
                            "reachable": True,
                        },
                        blockers=[],
                    )
                )
            consumers = tuple(
                item
                for item in index.literal_consumers
                if item.function_name == literal.function_name
                and item.literal_fingerprint.startswith(_literal_fingerprint(literal.value))
                and item.reachable
            )
            for vulnerability_type, mechanism, consumer in _classify_consumed_literal(
                literal.value,
                literal.context,
                consumers,
                index,
            ):
                if vulnerability_type not in enabled_types:
                    continue
                operation = IndexedOperation(
                    kind="literal_consumer",
                    name=consumer.consumer_name,
                    backend=self.name,
                    semantics=mechanism,
                    effect_kind=get_vulnerability_spec(vulnerability_type).effect_kind,
                    function_name=function.name,
                    function_address=function.address,
                    operation_address=consumer.consumer_address,
                    line_number=0,
                    arguments=(),
                    argument_roles=(("literal_role", consumer.argument_role),),
                    evidence_source=literal.source,
                    observed_name=consumer.consumer_name,
                )
                fingerprint = _literal_fingerprint(literal.value)
                states.append(
                    _indexed_state(
                        context,
                        operation,
                        vulnerability_type=vulnerability_type,
                        backend=self.name,
                        affected_identity=f"literal:{literal.address}:{fingerprint}",
                        affected_kind="embedded_configuration",
                        source={
                            "kind": "binary_literal_fingerprint",
                            "length": len(literal.value),
                            "fingerprint": fingerprint,
                        },
                        facts={
                            "literal_fingerprint": fingerprint,
                            "literal_length": len(literal.value),
                            "literal_verified": True,
                            "literal_address": literal.address,
                            "consumer_address": consumer.consumer_address,
                            "consumer_name": consumer.consumer_name,
                            "consumer_role": consumer.argument_role,
                            "reachable": True,
                            "evidence_source": literal.source,
                        },
                        blockers=[],
                    )
                )
        for operation in index.operations_for_backend(self.name):
            indexed_function = index.function(operation.function_name)
            if indexed_function is not None and not indexed_function.reachable_from_entry:
                continue
            vulnerability_type = ""
            extra_facts: dict[str, Any] = {}
            if operation.effect_kind == "weak_crypto_configuration" and _exact_weak_crypto_call(operation):
                vulnerability_type = "weak_cryptography"
                extra_facts["algorithm_alias"] = operation.observed_name or operation.name
            elif operation.effect_kind == "insecure_random_api":
                consumer = _security_random_consumer(operation, index)
                if consumer is not None:
                    vulnerability_type = "insecure_randomness"
                    extra_facts.update(
                        {
                            "random_result": operation.role("result"),
                            "consumer_name": consumer.name,
                            "consumer_address": consumer.operation_address,
                        }
                    )
            elif operation.effect_kind == "tls_validation_configuration" and _tls_validation_disabled(operation):
                vulnerability_type = "disabled_certificate_validation"
                extra_facts.update(
                    {
                        "configuration_roles": dict(operation.argument_roles),
                        "observed_alias": operation.observed_name or operation.name,
                    }
                )
            if vulnerability_type not in enabled_types:
                continue
            states.append(
                _indexed_state(
                    context,
                    operation,
                    vulnerability_type=vulnerability_type,
                    backend=self.name,
                    affected_identity=f"configuration:{operation.operation_address}",
                    affected_kind="security_configuration",
                    source={"kind": "security_api", "operation": operation.name},
                    facts={
                        "exact_call": operation.name,
                        "observed_call": operation.observed_name or operation.name,
                        "reachable": True,
                        **extra_facts,
                    },
                    blockers=[],
                )
            )
        return states


def merge_candidates(states: Sequence[CandidateState]) -> tuple[list[CandidateState], int]:
    """Merge semantic duplicates while retaining all evidence and root causes."""

    merged: dict[str, CandidateState] = {}
    merged_count = 0
    for state in states:
        previous = merged.get(state.candidate_id)
        if previous is None:
            merged[state.candidate_id] = state
            continue
        merged_count += 1
        preferred, other = _preferred_state(previous, state)
        facts = dict(preferred.type_facts)
        evidence = _dedupe(
            [
                *[str(item) for item in facts.get("evidence", [])],
                *[str(item) for item in other.type_facts.get("evidence", [])],
            ]
        )
        if evidence:
            facts["evidence"] = evidence
        merged[preferred.candidate_id] = replace(
            preferred,
            root_causes=tuple(sorted(set(preferred.root_causes) | set(other.root_causes))),
            blockers=_dedupe([*preferred.blockers, *other.blockers]),
            proof_obligations=_merge_mappings(preferred.proof_obligations, other.proof_obligations, "obligation_id"),
            validation_artifacts=_dedupe([*preferred.validation_artifacts, *other.validation_artifacts]),
            replay_artifacts=_dedupe([*preferred.replay_artifacts, *other.replay_artifacts]),
            report_artifacts=_dedupe([*preferred.report_artifacts, *other.report_artifacts]),
            type_facts=facts,
            metadata={**dict(other.metadata), **dict(preferred.metadata), "merged_evidence_count": len(evidence)},
        )
    return list(merged.values()), merged_count


def _memory_type(data: Mapping[str, Any]) -> str:
    raw = str(data.get("vulnerability_type") or "")
    kind = str(data.get("kind") or "").lower()
    if raw == "out_of_bounds_read" or "load" in kind or kind.startswith("read"):
        return "out_of_bounds_read"
    destination = str(data.get("destination_kind") or "").lower()
    if "heap" in destination:
        return "heap_overflow"
    if "stack" in destination:
        return "stack_overflow"
    return "out_of_bounds_write"


def _grounded_static_memory_candidate(data: Mapping[str, Any], vulnerability_type: str) -> bool:
    """Reject generic read suspicions that have neither an exact nor a proven range relation."""

    if vulnerability_type != "out_of_bounds_read":
        return True
    relation = str(data.get("write_relation") or "")
    if relation == "proven_oob_read" or str(data.get("verdict") or "") == "overflow":
        return True
    return bool(
        data.get("operation_address")
        and data.get("path_is_valid") is True
        and data.get("input_reaches_sink") is True
    )


def _richest_static_row(rows: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    return max(
        rows,
        key=lambda row: (
            str(row.get("operation_address") or "").startswith("0x"),
            any(str(item).startswith("pcode") for item in row.get("evidence_sources", [])),
            bool(row.get("capacity_bytes")),
            len(str(row.get("target_buffer") or "")),
        ),
    )


def _with_index_operation_address(data: Mapping[str, Any], index: ProgramIndex) -> Mapping[str, Any]:
    """Prefer one exact indexed call/load/store over a function entry address."""

    function_name = str(data.get("function_name") or "")
    function_address = str(data.get("address") or "")
    operation_name = str(data.get("sink") or data.get("kind") or "")
    current = str(data.get("operation_address") or "")
    if current and current.lower() != function_address.lower():
        return data
    candidate_kind = str(data.get("kind") or "")
    call_matches = [
        operation
        for operation in index.operations
        if operation.function_name == function_name
        and operation.kind == "call"
        and operation.name == operation_name
        and operation.operation_address
    ]
    if candidate_kind == "call" or call_matches:
        matches = call_matches
    else:
        access_kind = str(data.get("access_kind") or "write")
        index_kind = "load" if access_kind == "read" else "store"
        matches = [
            operation
            for operation in index.operations
            if operation.function_name == function_name
            and operation.kind == index_kind
            and operation.operation_address
        ]
    line_number = int(data.get("line_number") or 0)
    line_matches = [operation for operation in matches if line_number and operation.line_number == line_number]
    target = str(data.get("target_buffer") or "").lower()
    target_matches = [
        operation
        for operation in line_matches or matches
        if target and any(target in str(argument).lower() for argument in operation.arguments)
    ]
    selected = (
        target_matches[0]
        if len(target_matches) == 1
        else line_matches[0]
        if len(line_matches) == 1
        else matches[0]
        if len(matches) == 1
        else None
    )
    if selected is None:
        return data
    evidence_sources = _dedupe(
        [*[str(item) for item in data.get("evidence_sources", [])], selected.evidence_source]
    )
    return {
        **dict(data),
        "operation_address": selected.operation_address,
        "evidence_sources": evidence_sources,
    }


def _attach_indexed_memory_object(
    state: CandidateState,
    data: Mapping[str, Any],
    index: ProgramIndex,
) -> CandidateState:
    if str(data.get("destination_kind") or "") != "heap":
        return state
    target = str(data.get("target_buffer") or "")
    function_name = str(data.get("function_name") or "")
    matches = [
        item
        for item in index.memory_objects
        if item.kind == "heap"
        and item.function_name == function_name
        and re.sub(r"\s+", "", item.label).lower() == re.sub(r"\s+", "", target).lower()
    ]
    if len(matches) != 1:
        return state
    memory_object = matches[0]
    affected = {
        **dict(state.affected_object),
        "identity": memory_object.identity,
        "kind": "heap",
        "label": memory_object.label,
        "allocation_operation_address": memory_object.address,
        "extent_source": memory_object.source,
    }
    if memory_object.size_bytes is not None:
        affected["capacity_bytes"] = memory_object.size_bytes
    operation_address = str(state.operation.get("address") or "")
    candidate_id = semantic_candidate_id(
        binary_identity=index.binary_identity,
        backend=state.backend,
        vulnerability_type=state.vulnerability_type,
        function_address=str(state.location.get("address") or ""),
        operation_address=operation_address,
        affected_object_identity=memory_object.identity,
        mechanism=state.mechanism,
    )
    facts = {
        **dict(state.type_facts),
        "indexed_memory_object": {
            "identity": memory_object.identity,
            "allocation_operation_address": memory_object.address,
            "extent_source": memory_object.source,
            "size_bytes": memory_object.size_bytes,
        },
    }
    return replace(
        state,
        candidate_id=candidate_id,
        affected_object=affected,
        type_facts=facts,
        proof_obligations=[
            {**dict(item), "obligation_id": f"{candidate_id}:{position}"}
            for position, item in enumerate(state.proof_obligations)
        ],
    )


def _enrich_lifetime_state(state: CandidateState, index: ProgramIndex) -> CandidateState:
    """Attach one normalized release/use lineage without claiming path feasibility."""

    if state.vulnerability_type != "use_after_free":
        return state
    token = str(
        state.sink.get("stale_alias")
        or state.type_facts.get("stale_alias")
        or state.affected_object.get("label")
        or ""
    )
    function_name = str(state.location.get("function_name") or "")
    function_address = str(state.location.get("address") or "")
    if not token or not function_name:
        return state
    resource_identity = f"{function_address}:{re.sub(r'\s+', '', token).lower()}"
    events = [
        event
        for event in index.lifecycle_events
        if event.function_name == function_name and event.resource_identity == resource_identity
    ]
    releases = [event for event in events if event.event_kind == "release"]
    uses = [event for event in events if event.event_kind == "use"]
    if not releases or not uses:
        return state
    function = index.function(function_name)
    text = function.text if function else ""
    mutually_exclusive = bool(
        re.search(
            rf"if\s*\([^)]*\)\s*\{{[^{{}}]*\bfree\s*\(\s*{re.escape(token)}\s*\)\s*;[^{{}}]*\}}\s*else\s*\{{[^{{}}]*\brealloc\s*\(\s*{re.escape(token)}\s*,",
            text,
            re.IGNORECASE | re.DOTALL,
        )
    )
    lineage_origin = "caller_owned_parameter" if re.fullmatch(r"param_\d+", token, re.IGNORECASE) else "local_alias"
    facts = {
        **dict(state.type_facts),
        "resource_identity": resource_identity,
        "resource_lineage": {
            "origin": lineage_origin,
            "release_operation": releases[0].operation_address,
            "use_operation": uses[0].operation_address,
            "same_expression": True,
            "path_relation": "mutually_exclusive" if mutually_exclusive else "unproven",
        },
    }
    blockers = [item for item in state.blockers if item != "allocation_site_unknown"]
    blockers.append(
        "mutually_exclusive_event_paths"
        if mutually_exclusive
        else "same_resource_runtime_proof_required"
    )
    operation_address = str(state.operation.get("address") or state.location.get("operation_address") or "")
    candidate_id = semantic_candidate_id(
        binary_identity=index.binary_identity,
        backend=state.backend,
        vulnerability_type=state.vulnerability_type,
        function_address=function_address,
        operation_address=operation_address,
        affected_object_identity=resource_identity,
        mechanism=state.mechanism,
    )
    return replace(
        state,
        candidate_id=candidate_id,
        affected_object={"identity": resource_identity, "kind": "heap", "label": token},
        type_facts=facts,
        blockers=_dedupe(blockers),
        proof_obligations=[
            {**dict(item), "obligation_id": f"{candidate_id}:{position}"}
            for position, item in enumerate(state.proof_obligations)
        ],
    )


def _normalize_state(state: CandidateState, context: DiscoveryContext, backend: str) -> CandidateState:
    spec = get_vulnerability_spec(state.vulnerability_type)
    mechanism = spec.mechanism
    semantic_text = " ".join(
        str(item)
        for item in (
            state.source.get("expression"),
            state.sink.get("name"),
            state.sink.get("kind"),
            state.location.get("line_text"),
        )
    ).lower()
    if state.vulnerability_type == "path_traversal" and any(token in semantic_text for token in ("archive", "tar", "entry_name", "zip")):
        mechanism = "archive_entry_escape"
    elif state.vulnerability_type == "unsafe_file_write" and any(token in semantic_text for token in ("upload", "multipart", "filename")):
        mechanism = "unrestricted_upload"
    operation = dict(state.operation or state.sink)
    operation_address = str(
        operation.get("address")
        or operation.get("operation_address")
        or state.sink.get("operation_address")
        or state.location.get("address")
        or ""
    )
    operation = {
        "name": operation.get("name") or state.sink.get("name") or "",
        "kind": operation.get("kind") or state.sink.get("kind") or "",
        "address": operation_address,
        **operation,
    }
    identity = str(
        state.affected_object.get("identity")
        or state.sink.get("released_object")
        or state.sink.get("stale_alias")
        or state.sink.get("target_buffer")
        or state.type_facts.get("resource_identity")
        or operation_address
    )
    candidate_id = semantic_candidate_id(
        binary_identity=context.manifest.binary,
        backend=backend,
        vulnerability_type=state.vulnerability_type,
        function_address=str(state.location.get("address") or ""),
        operation_address=operation_address,
        affected_object_identity=identity,
        mechanism=mechanism,
    )
    return replace(
        state,
        candidate_id=candidate_id,
        backend=backend,
        mechanism=mechanism,
        operation=operation,
        affected_object={
            "identity": identity,
            "kind": (
                "resource"
                if backend == "memory_lifetime"
                else "embedded_configuration"
                if backend == "static_evidence"
                else "process_effect"
            ),
            "label": identity,
        },
        proof_obligations=[
            {**dict(item), "obligation_id": f"{candidate_id}:{index}"}
            for index, item in enumerate(state.proof_obligations)
        ],
        metadata={"proof_policy": spec.proof_policy, "effect_kind": spec.effect_kind},
    )


def _indexed_state(
    context: DiscoveryContext,
    operation: IndexedOperation,
    *,
    vulnerability_type: str,
    backend: str,
    affected_identity: str,
    affected_kind: str,
    source: Mapping[str, Any],
    facts: Mapping[str, Any],
    blockers: list[str],
    mechanism: str = "",
) -> CandidateState:
    spec = get_vulnerability_spec(vulnerability_type)
    actual_mechanism = mechanism or spec.mechanism
    candidate_id = semantic_candidate_id(
        binary_identity=context.manifest.binary,
        backend=backend,
        vulnerability_type=vulnerability_type,
        function_address=operation.function_address,
        operation_address=operation.operation_address,
        affected_object_identity=affected_identity,
        mechanism=actual_mechanism,
    )
    proof = ProofObligation(
        obligation_id=f"{candidate_id}:{spec.proof_policy}",
        description=f"Satisfy the {spec.proof_policy} proof policy for {vulnerability_type}.",
        condition=actual_mechanism,
        required_evidence=[spec.proof_policy, "exact_operation"],
        status="open" if blockers else "satisfied",
        evidence_refs=[operation.evidence_source] if operation.evidence_source else [],
    )
    normalized_operation = {
        "name": operation.name,
        "kind": operation.kind,
        "address": operation.operation_address,
        "semantics": operation.semantics,
        "effect_kind": operation.effect_kind,
        "argument_roles": dict(operation.argument_roles),
        "evidence_source": operation.evidence_source,
    }
    indexed_function = context.index.function(operation.function_name)
    return CandidateState(
        candidate_id=candidate_id,
        backend=backend,
        vulnerability_type=vulnerability_type,
        mechanism=actual_mechanism,
        status=CandidateStatus.NEEDS_REFINEMENT.value if blockers else CandidateStatus.CANDIDATE.value,
        target={"binary": context.manifest.binary, "component": context.manifest.binary},
        location={
            "function_name": operation.function_name,
            "address": operation.function_address,
            "operation_address": operation.operation_address,
            "line_number": operation.line_number,
            "relative_path": indexed_function.relative_path if indexed_function else "",
        },
        source=dict(source),
        sink=normalized_operation,
        operation=normalized_operation,
        affected_object={"identity": affected_identity, "kind": affected_kind, "label": affected_identity},
        root_causes=(),
        type_facts={"path_is_valid": True, "evidence": [operation.evidence_source], **dict(facts)},
        proof_obligations=[proof.to_dict()],
        blockers=blockers,
        metadata={"proof_policy": spec.proof_policy, "effect_kind": spec.effect_kind},
    )


def _null_dereference_candidates(context: DiscoveryContext, index: ProgramIndex) -> list[CandidateState]:
    states: list[CandidateState] = []
    for operation in index.operations_for_backend("memory_access"):
        if operation.kind not in {"load", "store"}:
            continue
        address = operation.role("address") or operation.role("destination") or operation.role("source")
        normalized = re.sub(r"[()\s]", "", address).lower()
        if 0 not in operation.address_constants and normalized not in {"0", "0x0", "null", "void*0"}:
            continue
        states.append(
            _indexed_state(
                context,
                operation,
                vulnerability_type="null_pointer_dereference",
                backend="memory_access",
                affected_identity="null:0",
                affected_kind="null_pointer",
                source={"kind": "pointer_state", "expression": address},
                facts={
                    "pointer_value": 0,
                    "exact_null": True,
                    "access_kind": operation.kind,
                    "access_width_bytes": operation.width_bytes,
                },
                blockers=["effective_address_zero_replay_required"],
            )
        )
    return states


def _overlap_candidates(context: DiscoveryContext, index: ProgramIndex) -> list[CandidateState]:
    states: list[CandidateState] = []
    for operation in index.operations_for_backend("memory_access"):
        if operation.name not in {"memcpy", "memcpy_chk"}:
            continue
        destination = operation.role("destination")
        source = operation.role("source")
        size = operation.role("size")
        if not destination or not source or not size:
            continue
        dest_base, dest_offset = _base_offset(destination)
        source_base, source_offset = _base_offset(source)
        width = _int_literal(size)
        exact_ranges = bool(dest_base == source_base and width is not None)
        overlap = bool(
            exact_ranges
            and max(dest_offset, source_offset) < min(dest_offset + width, source_offset + width)
        )
        if exact_ranges and not overlap:
            continue
        if not exact_ranges and not (
            _is_untrusted(destination)
            or _is_untrusted(source)
            or dest_base == source_base
        ):
            continue
        states.append(
            _indexed_state(
                context,
                operation,
                vulnerability_type="overlapping_memory_copy",
                backend="memory_access",
                affected_identity=f"range:{dest_base}:{source_base}",
                affected_kind="memory_range",
                source={"kind": "copy_ranges", "destination": destination, "source": source},
                facts={
                    "destination_range": [dest_offset, dest_offset + width] if exact_ranges else [],
                    "source_range": [source_offset, source_offset + width] if exact_ranges else [],
                    "exact_overlap": overlap,
                    "range_proof": "static_literal_ranges" if exact_ranges else "native_concrete_ranges_required",
                    "attacker_controlled_range_expression": bool(
                        _is_untrusted(destination) or _is_untrusted(source) or _is_untrusted(size)
                    ),
                },
                blockers=[] if overlap else ["concrete_range_replay_required"],
            )
        )
    return states


def _uninitialized_candidates(context: DiscoveryContext, index: ProgramIndex) -> list[CandidateState]:
    states: list[CandidateState] = []
    stores_by_function: dict[str, set[str]] = {}
    for operation in index.operations:
        if operation.kind == "store":
            stores_by_function.setdefault(operation.function_name, set()).update(operation.arguments)
        if operation.kind != "load":
            continue
        if operation.definedness != "undefined":
            continue
        address = operation.role("address")
        if not address or not re.search(r"(?:local_|stack)", address, re.IGNORECASE):
            continue
        if address in stores_by_function.get(operation.function_name, set()):
            continue
        states.append(
            _indexed_state(
                context,
                operation,
                vulnerability_type="uninitialized_memory_use",
                backend="memory_access",
                affected_identity=f"undefined:{operation.function_address}:{address}",
                affected_kind="stack",
                source={"kind": "definedness", "expression": address},
                facts={
                    "definedness": "undefined",
                    "prior_store": False,
                    "defined_byte_ranges": [list(item) for item in operation.defined_byte_ranges],
                    "undefined_byte_ranges": (
                        [list(item) for item in operation.undefined_byte_ranges]
                        or [[operation.stack_offset or 0, (operation.stack_offset or 0) + (operation.width_bytes or 1)]]
                    ),
                    "read_width_bytes": operation.width_bytes or 1,
                },
                blockers=[],
            )
        )
    pcode_functions = {
        operation.function_name
        for operation in index.operations
        if operation.kind == "load" and operation.definedness
    }
    for function in index.functions:
        if function.name in pcode_functions:
            continue
        lines = function.text.splitlines()
        for declaration_line, name, width in _uninitialized_local_declarations(lines):
            function_operations = tuple(
                operation
                for operation in index.operations
                if operation.function_name == function.name
            )
            use_line = _first_uninitialized_source_use(
                lines,
                declaration_line,
                name,
                function_operations,
            )
            if use_line is None:
                continue
            indexed_use = next(
                iter(
                    sorted(
                        (
                            operation
                            for operation in index.operations
                            if operation.function_name == function.name
                            and _operation_reads_local(operation, name)
                        ),
                        key=lambda item: abs(item.line_number - use_line),
                    )
                ), None
            )
            operation = indexed_use or IndexedOperation(
                    kind="load",
                    name="local_read",
                    backend="memory_access",
                    semantics="direct_memory_load",
                    effect_kind="memory_load",
                    function_name=function.name,
                    function_address=function.address,
                    operation_address=f"{function.address}:line:{use_line}",
                    line_number=use_line,
                    arguments=(name,),
                    argument_roles=(("address", name),),
                    definedness="undefined",
                    evidence_source="c_text_definedness",
                )
            exact_machine_operation = _address_sort_key(operation.operation_address)[0] < 2**64 - 1
            states.append(
                _indexed_state(
                    context,
                    operation,
                    vulnerability_type="uninitialized_memory_use",
                    backend="memory_access",
                    affected_identity=f"undefined:{function.address}:{name}",
                    affected_kind="stack",
                    source={"kind": "definedness", "expression": name},
                    facts={
                        "definedness": "undefined",
                        "prior_store": False,
                        "defined_byte_ranges": [],
                        "undefined_byte_ranges": [[0, width]],
                        "read_width_bytes": width,
                    },
                blockers=(
                    ["machine_definedness_unresolved"]
                    if exact_machine_operation
                    else [
                        "machine_definedness_unresolved",
                        "exact_machine_operation_unresolved",
                    ]
                ),
            )
            )
    return states


def _uninitialized_local_declarations(lines: Sequence[str]) -> list[tuple[int, str, int]]:
    rows: list[tuple[int, str, int]] = []
    pattern = re.compile(
        r"^\s*(?:(?:unsigned|signed|const|volatile)\s+)*(?P<type>char|short|int|uint|long|ulong|float|double|size_t|undefined\d*|u?int(?:8|16|32|64)_t)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;\s*$"
    )
    for line_number, line in enumerate(lines, start=1):
        match = pattern.match(line)
        if match:
            name = match.group("name")
            if re.match(
                r"^(?:in_|unaff_|extraout_|register0x)",
                name,
                re.IGNORECASE,
            ):
                # Ghidra uses these spellings for values entering in machine
                # registers, including the TLS base.  They are not stack-local
                # storage declarations and this fallback cannot prove them
                # undefined at function entry.
                continue
            type_name = match.group("type").lower()
            digits = re.search(r"(?:undefined|int)(8|16|32|64)", type_name)
            width = int(digits.group(1)) // 8 if digits else {
                "char": 1,
                "short": 2,
                "long": 8,
                "ulong": 8,
                "double": 8,
            }.get(type_name, 4)
            rows.append((line_number, name, width))
    return rows


def _first_uninitialized_source_use(
    lines: Sequence[str],
    declaration_line: int,
    name: str,
    operations: Sequence[IndexedOperation] = (),
) -> int | None:
    token = re.compile(rf"\b{re.escape(name)}\b")
    assignment = re.compile(rf"\b{re.escape(name)}\s*=(?!=)")
    address_of = re.compile(rf"&\s*\b{re.escape(name)}\b")
    for line_number in range(declaration_line + 1, len(lines) + 1):
        line = lines[line_number - 1]
        match = token.search(line)
        if not match:
            continue
        value_text = address_of.sub("", line)
        direct_assignment = assignment.search(value_text)
        if direct_assignment:
            if _assignment_rhs_reads_prior_value(
                value_text,
                direct_assignment.end(),
                token,
            ):
                return line_number
            return None
        if not token.search(value_text):
            if _unconditional_output_write(operations, line_number, name):
                return None
            # Taking an address does not itself read or define the pointee.  An
            # unknown or conditional call leaves the scan live for later uses.
            continue
        if re.search(
            rf"(?:\breturn\s+{re.escape(name)}\b|\([^;]*\b{re.escape(name)}\b[^;]*\)|"
            rf"=\s*[^;]*\b{re.escape(name)}\b|(?:\+\+|--)\s*\b{re.escape(name)}\b|"
            rf"\b{re.escape(name)}\b\s*(?:\+\+|--))",
            value_text,
        ):
            return line_number
    return None


def _unconditional_output_write(
    operations: Sequence[IndexedOperation],
    line_number: int,
    name: str,
) -> bool:
    for operation in operations:
        if operation.output_write_guarantee != "always":
            continue
        if operation.line_number and abs(operation.line_number - line_number) > 4:
            continue
        for index in operation.output_pointer_args:
            if index < len(operation.arguments) and _is_address_of_local(
                operation.arguments[index], name
            ):
                return True
    return False


def _assignment_rhs_reads_prior_value(
    line: str,
    rhs_start: int,
    token: re.Pattern[str],
) -> bool:
    """Inspect only the assignment expression, not later sequenced clauses."""

    depth = 0
    quote = ""
    escaped = False
    for character in line[:rhs_start]:
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
        elif character in {'"', "'"}:
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}" and depth:
            depth -= 1
    base_depth = depth
    end = len(line)
    quote = ""
    escaped = False
    current_depth = depth
    for index in range(rhs_start, len(line)):
        character = line[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {'"', "'"}:
            quote = character
        elif character in "([{":
            current_depth += 1
        elif character in ")]}":
            if current_depth <= base_depth:
                end = index
                break
            current_depth -= 1
        elif character in {",", ";"} and current_depth == base_depth:
            end = index
            break
    return bool(token.search(line[rhs_start:end]))


def _operation_reads_local(operation: IndexedOperation, name: str) -> bool:
    for index, argument in enumerate(operation.arguments):
        if not re.search(rf"\b{re.escape(name)}\b", argument):
            continue
        if index in operation.output_pointer_args and _is_address_of_local(argument, name):
            continue
        return True
    return False


def _is_address_of_local(expression: str, name: str) -> bool:
    return bool(
        re.search(rf"(?:^|[^A-Za-z0-9_])&\s*{re.escape(name)}\b", str(expression))
    )


def _rounded_stride_read_candidates(
    context: DiscoveryContext,
    index: ProgramIndex,
) -> list[CandidateState]:
    states: list[CandidateState] = []
    for function in index.functions:
        assignments = _line_assignments(function.text)
        for stride, stride_expression, stride_line in assignments:
            relation = _outer_rounded_multiplier(stride_expression)
            if relation is None:
                continue
            factor, rounded_expression = relation
            dependent = {stride}
            changed = True
            while changed:
                changed = False
                for name, expression, _line in assignments:
                    if name in dependent:
                        continue
                    if any(re.search(rf"\b{re.escape(item)}\b", expression) for item in dependent):
                        dependent.add(name)
                        changed = True
            load_rows: list[tuple[int, str, IndexedOperation]] = []
            dependent_read_lines: list[tuple[int, str, str]] = []
            for line_number, line in enumerate(function.text.splitlines(), start=1):
                if line_number <= stride_line or ("*" not in line and "[" not in line):
                    continue
                if not any(re.search(rf"\b{re.escape(item)}\b", line) for item in dependent):
                    continue
                dependent_read_lines.append(
                    (line_number, line.strip(), _read_base_expression(line, ""))
                )
                operations = [
                    operation
                    for operation in index.operations
                    if operation.function_name == function.name
                    and operation.kind == "load"
                    and operation.line_number == line_number
                ]
                if not operations and ("[" in line or re.search(r"\*\s*\([^)]*\*\)", line)):
                    base = _read_base_expression(line, "memory")
                    operations = [
                        IndexedOperation(
                            kind="load",
                            name="text_load",
                            backend="memory_access",
                            semantics="direct_memory_load",
                            effect_kind="memory_load",
                            function_name=function.name,
                            function_address=function.address,
                            operation_address=f"{function.address}:line:{line_number}:load",
                            line_number=line_number,
                            arguments=(base,),
                            argument_roles=(("address", base),),
                            width_bytes=1,
                            evidence_source="c_text_load",
                        )
                    ]
                for operation in operations:
                    load_rows.append((line_number, line.strip(), operation))
            if not load_rows:
                if not dependent_read_lines:
                    continue
            # Prefer the first exact load whose address depends on the rounded
            # stride.  Later lookahead loads can be on a mutually exclusive
            # bit-shifting branch; choosing them made concrete replay miss the
            # actual trailing-byte access even though the function was entered.
            pcode_rows = [row for row in load_rows if row[2].evidence_source == "pcode_load"]
            bases = {base for _line_number, _line, base in dependent_read_lines if base}
            correlated_pcode = [
                operation
                for operation in index.operations
                if operation.function_name == function.name
                and operation.kind == "load"
                and operation.evidence_source == "pcode_load"
                and any(argument in bases for argument in operation.arguments)
            ]
            if correlated_pcode:
                operation = min(
                    correlated_pcode,
                    key=lambda item: _address_sort_key(item.operation_address),
                )
                line_number, line, _base = min(
                    dependent_read_lines,
                    key=lambda row: abs(row[0] - operation.line_number),
                )
            else:
                line_number, line, operation = (pcode_rows or load_rows)[0]
            address_expression = operation.role("address") or (operation.arguments[0] if operation.arguments else "")
            base = _read_base_expression(line, address_expression)
            state = _indexed_state(
                context,
                operation,
                vulnerability_type="out_of_bounds_read",
                backend="memory_access",
                affected_identity=f"heap_parameter:{function.address}:{base or address_expression}",
                affected_kind="heap",
                source={
                    "kind": "heap_buffer_parameter",
                    "expression": base or address_expression,
                },
                facts={
                    "access_expression": line,
                    "stride_variable": stride,
                    "stride_expression": stride_expression,
                    "rounded_expression": rounded_expression,
                    "outer_factor": factor,
                    "dependent_offsets": sorted(dependent),
                    "range_relation": "factor_applied_after_rounded_byte_conversion",
                    "exact_access_width_bytes": operation.width_bytes or 1,
                    "destination_kind": "heap",
                    "target_buffer": base or address_expression,
                    "write_size_bytes": operation.width_bytes or 1,
                    "write_relation": "symbolic_read_offset",
                    "path_is_valid": True,
                },
                blockers=["concrete_object_range_replay_required"],
                mechanism="rounded_stride_miscalculation",
            )
            states.append(
                replace(
                    state,
                    root_causes=("integer_truncation", "allocation_size_mismatch"),
                    location={**dict(state.location), "line_number": line_number, "line_text": line},
                )
            )
    return states


def _address_sort_key(value: str) -> tuple[int, str]:
    try:
        return int(str(value), 0), str(value)
    except ValueError:
        return 2**64 - 1, str(value)


def _reentrant_copy_uaf_candidates(
    context: DiscoveryContext,
    index: ProgramIndex,
) -> list[CandidateState]:
    states: list[CandidateState] = []
    for relation in index.path_relations:
        if not relation.inverted_boolean:
            continue
        function = index.function(relation.function_name)
        if function is None:
            continue
        lines = function.text.splitlines()
        for line_number in range(relation.end_line + 1, min(len(lines), relation.end_line + 80) + 1):
            line = lines[line_number - 1].strip()
            call = re.search(
                r"(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:\([^;=]+\)\s*)?)?"
                r"(?P<callee>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>[^;{}]+)\)\s*;",
                line,
            )
            if call is None:
                continue
            callee = call.group("callee")
            summary = index.summary(callee) or index.summary(callee.upper())
            inline_allocation = _inline_callee_may_allocate(function.text, callee)
            if (summary is None or not summary.may_allocate) and not inline_allocation:
                continue
            arguments = _split_call_arguments(call.group("args"))
            source_expression = next(
                (
                    value
                    for value in reversed(arguments)
                    if "+" in value or re.search(r"\b(?:stack|argv|source|src|buffer)\b", value, re.IGNORECASE)
                ),
                "",
            )
            if not source_expression:
                continue
            guard_window = "\n".join(lines[relation.end_line : line_number])
            if not re.search(rf"if\s*\(\s*{re.escape(relation.guard_variable)}\s*\)", guard_window):
                continue
            if not re.search(rf"\*[^;=]+\s*=\s*[^;]*{re.escape(source_expression.split('+')[0].strip())}[^;]*;", guard_window):
                continue
            operations = [
                operation
                for operation in index.operations
                if operation.function_name == function.name
                and operation.kind == "call"
                and operation.name.lower() == callee.lower()
            ]
            if not operations:
                operations = [
                    IndexedOperation(
                        kind="call",
                        name=callee,
                        backend="memory_lifetime",
                        semantics="allocation_capable_copy",
                        effect_kind="resource_reallocate",
                        function_name=function.name,
                        function_address=function.address,
                        operation_address=f"{function.address}:line:{line_number}:call:{callee}",
                        line_number=line_number,
                        arguments=tuple(arguments),
                        argument_roles=(("source", source_expression),),
                        evidence_source="c_text_call",
                    )
                ]
            if len(operations) != 1:
                continue
            operation = operations[0]
            owner_base = source_expression.split("+")[0].strip()
            states.append(
                _indexed_state(
                    context,
                    operation,
                    vulnerability_type="use_after_free",
                    backend="memory_lifetime",
                    affected_identity=f"reallocatable_owner:{function.address}:{owner_base}",
                    affected_kind="heap",
                    source={"kind": "owner_backed_alias", "expression": source_expression},
                    facts={
                        "resource_identity": f"reallocatable_owner:{function.address}:{owner_base}",
                        "resource_lineage": {
                            "origin": "owner_backed_storage",
                            "borrow_expression": source_expression,
                            "invalidating_operation": operation.operation_address,
                            "same_resource": True,
                            "path_relation": "copy_branch_feasible",
                        },
                        "guard_relation": {
                            "variable": relation.guard_variable,
                            "condition": relation.condition,
                            "true_value": relation.true_value,
                            "false_value": relation.false_value,
                            "inverted": True,
                        },
                        "callee_summary": {
                            "function": summary.function_name if summary else callee,
                            "may_allocate": True,
                            "allocation_evidence": (
                                list(summary.allocation_evidence)
                                if summary
                                else ["inline_allocator_call"]
                            ),
                        },
                        "same_resource": True,
                        "ordered_events": ["borrow", "invalidating_allocation", "copy_read"],
                        "path_is_valid": True,
                    },
                    blockers=["concrete_reentrant_invalidation_replay_required"],
                    mechanism="reentrant_copy_invalidation",
                )
            )
    return states


def _line_assignments(text: str) -> list[tuple[str, str, int]]:
    rows: list[tuple[str, str, int]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = re.search(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expression>[^;]+);", line)
        if match:
            rows.append((match.group("name"), match.group("expression").strip(), line_number))
    return rows


def _outer_rounded_multiplier(expression: str) -> tuple[str, str] | None:
    terms = _split_top_level_operator(expression.strip(), "*")
    if len(terms) != 2:
        return None
    factor, rounded = (item.strip() for item in terms)
    inner = _strip_balanced_parentheses(rounded)
    if inner == rounded or not re.search(r"\+\s*7\s*(?:>>\s*3|\)\s*/\s*8|/\s*8)", inner):
        return None
    factor_name = re.sub(r"\([^()]*\)", "", factor).strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", factor_name):
        return None
    return factor_name, inner


def _split_top_level_operator(expression: str, operator: str) -> list[str]:
    rows: list[str] = []
    depth = 0
    start = 0
    for index, character in enumerate(expression):
        if character in "([{":
            depth += 1
        elif character in ")]}":
            depth = max(0, depth - 1)
        elif character == operator and depth == 0:
            rows.append(expression[start:index])
            start = index + 1
    rows.append(expression[start:])
    return rows


def _strip_balanced_parentheses(expression: str) -> str:
    result = expression.strip()
    stripped = False
    while result.startswith("(") and result.endswith(")"):
        depth = 0
        balanced = True
        for index, character in enumerate(result):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0 and index != len(result) - 1:
                    balanced = False
                    break
        if not balanced or depth != 0:
            break
        result = result[1:-1].strip()
        stripped = True
    return result if stripped else expression.strip()


def _read_base_expression(line: str, fallback: str) -> str:
    match = re.search(r"\*\s*\([^)]*\*\)\s*\(?(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+", line)
    if match:
        return match.group("base")
    match = re.search(r"\b(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\[", line)
    if match:
        return match.group("base")
    return fallback


def _inline_callee_may_allocate(text: str, callee: str) -> bool:
    definition = re.search(
        rf"\b{re.escape(callee)}\s*\([^)]*\)\s*\{{(?P<body>.*?)\n\}}",
        text,
        re.DOTALL,
    )
    return bool(
        definition
        and re.search(
            r"\b(?:malloc|calloc|realloc|operator_new)\s*\(",
            definition.group("body"),
            re.IGNORECASE,
        )
    )


def _split_call_arguments(raw: str) -> list[str]:
    rows: list[str] = []
    depth = 0
    start = 0
    quote = ""
    escaped = False
    for index, character in enumerate(raw):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {'"', "'"}:
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            rows.append(raw[start:index].strip())
            start = index + 1
    tail = raw[start:].strip()
    if tail:
        rows.append(tail)
    return rows


def _indexed_lifetime_candidates(
    context: DiscoveryContext,
    index: ProgramIndex,
    enabled_types: frozenset[str],
) -> list[CandidateState]:
    states: list[CandidateState] = []
    events_by_resource: dict[tuple[str, str], list[Any]] = {}
    for event in index.lifecycle_events:
        events_by_resource.setdefault((event.resource_kind, event.resource_identity), []).append(event)
    for (resource_kind, identity), events in events_by_resource.items():
        ordered = sorted(
            events,
            key=lambda item: (
                item.context_function_address or item.function_address,
                item.context_line_number or item.line_number,
                _address_sort_key(item.context_operation_address or item.operation_address),
                _address_sort_key(item.operation_address),
            ),
        )
        releases = [item for item in ordered if item.event_kind == "release"]
        allocations = [item for item in ordered if item.event_kind == "allocate"]
        uses = [item for item in ordered if item.event_kind == "use"]
        if (
            len(releases) > 1
            and resource_kind == "heap"
            and "double_free" in enabled_types
            and any(item.context_function_name for item in releases)
        ):
            release_pair = next(
                (
                    (before, after, index.event_relation(before, after))
                    for before in releases
                    for after in releases
                    if before is not after
                    and index.event_relation(before, after).feasible
                    and index.event_path_avoiding(before, after, allocations)
                ),
                None,
            )
            if release_pair:
                first_release, event, relation = release_pair
                states.append(
                    _indexed_state(
                        context,
                        _event_operation(event),
                        vulnerability_type="double_free",
                        backend="memory_lifetime",
                        affected_identity=identity,
                        affected_kind=resource_kind,
                        source={
                            "kind": "first_release",
                            "operation_address": first_release.operation_address,
                            "context_operation_address": first_release.context_operation_address,
                        },
                        facts={
                            "events": [_event_dict(item) for item in ordered],
                            "same_resource": True,
                            "ordered_events": ["release", "release"],
                            **_control_flow_facts(relation),
                        },
                        blockers=["same_resource_runtime_proof_required"],
                    )
                )
        if (
            releases
            and uses
            and resource_kind == "heap"
            and "use_after_free" in enabled_types
            and any(item.context_function_name for item in (*releases, *uses))
        ):
            violating_pair = next(
                (
                    (release, use, index.event_relation(release, use))
                    for release in releases
                    for use in uses
                    if index.event_relation(release, use).feasible
                    and index.event_path_avoiding(release, use, allocations)
                ),
                None,
            )
            if violating_pair:
                first_release, event, relation = violating_pair
                states.append(
                    _indexed_state(
                        context,
                        _event_operation(event),
                        vulnerability_type="use_after_free",
                        backend="memory_lifetime",
                        affected_identity=identity,
                        affected_kind=resource_kind,
                        source={
                            "kind": "heap_release",
                            "operation_address": first_release.operation_address,
                            "context_operation_address": first_release.context_operation_address,
                        },
                        facts={
                            "events": [_event_dict(item) for item in ordered],
                            "same_resource": True,
                            "ordered_events": ["release", "use"],
                            **_control_flow_facts(relation),
                        },
                        blockers=["same_resource_runtime_proof_required"],
                    )
                )
        if len(releases) > 1 and resource_kind in {"handle", "descriptor", "stream", "directory", "socket"}:
            vulnerability_type = "double_close"
            release_pair = next(
                (
                    (before, after, index.event_relation(before, after))
                    for before in releases
                    for after in releases
                    if before is not after
                    and index.event_relation(before, after).feasible
                    and index.event_path_avoiding(before, after, allocations)
                ),
                None,
            )
            if vulnerability_type in enabled_types and release_pair:
                first_release, event, relation = release_pair
                operation = _event_operation(event)
                states.append(
                    _indexed_state(
                        context,
                        operation,
                        vulnerability_type=vulnerability_type,
                        backend="memory_lifetime",
                        affected_identity=identity,
                        affected_kind=resource_kind,
                        source={"kind": "first_release", "operation_address": first_release.operation_address},
                        facts={
                            "events": [_event_dict(item) for item in ordered],
                            "same_resource": True,
                            "ordered_events": ["release", "release"],
                            **_control_flow_facts(relation),
                        },
                        blockers=["same_resource_runtime_proof_required"],
                    )
                )
        if releases and uses and "use_after_close" in enabled_types and resource_kind in {"handle", "descriptor", "stream", "directory", "socket"}:
            violating_pair = next(
                (
                    (release, use, index.event_relation(release, use))
                    for release in releases
                    for use in uses
                    if index.event_relation(release, use).feasible
                    and index.event_path_avoiding(release, use, allocations)
                ),
                None,
            )
            if violating_pair:
                first_release, event, relation = violating_pair
                states.append(
                    _indexed_state(
                        context,
                        _event_operation(event),
                        vulnerability_type="use_after_close",
                        backend="memory_lifetime",
                        affected_identity=identity,
                        affected_kind=resource_kind,
                        source={"kind": "handle_close", "operation_address": first_release.operation_address},
                        facts={
                            "events": [_event_dict(item) for item in ordered],
                            "same_resource": True,
                            "ordered_events": ["release", "use"],
                            **_control_flow_facts(relation),
                        },
                        blockers=["same_resource_runtime_proof_required"],
                    )
                )
        if allocations and releases:
            allocation_pair = next(
                (
                    (allocation, release, index.event_relation(allocation, release))
                    for allocation in allocations
                    for release in releases
                    if index.event_relation(allocation, release).feasible
                ),
                None,
            )
            if allocation_pair:
                allocation, event, relation = allocation_pair
                alloc_family = allocation.allocator_family
                release_family = event.allocator_family
            else:
                alloc_family = release_family = ""
            if allocation_pair and not _resource_families_compatible(alloc_family, release_family, resource_kind) and "mismatched_deallocator" in enabled_types:
                states.append(
                    _indexed_state(
                        context,
                        _event_operation(event),
                        vulnerability_type="mismatched_deallocator",
                        backend="memory_lifetime",
                        affected_identity=identity,
                        affected_kind=resource_kind,
                        source={"kind": "allocation", "allocator_family": alloc_family},
                        facts={
                            "allocator_family": alloc_family,
                            "deallocator_family": release_family,
                            "same_resource": True,
                            "ordered_events": ["allocate", "release"],
                            **_control_flow_facts(relation),
                        },
                        blockers=["same_resource_runtime_proof_required"],
                    )
                )
        if allocations and "memory_leak" in enabled_types and resource_kind == "heap":
            for event in allocations:
                node = next((item for item in index.nodes if item.record.name == event.function_name), None)
                if node is not None and node.record.is_thunk:
                    continue
                identity_token = identity.rsplit(":", 1)[-1]
                if not releases and any(
                    item.event_kind == "release"
                    and item.function_name == event.function_name
                    and identity_token
                    and re.search(rf"\b{re.escape(identity_token)}\b", item.argument, re.IGNORECASE)
                    for item in index.lifecycle_events
                ):
                    continue
                paths = [
                    item
                    for item in index.resource_paths
                    if item.resource_identity == identity
                    and item.allocation_address == event.operation_address
                    and item.feasible
                ]
                live_paths = [item for item in paths if item.live_at_exit and not item.escaped]
                if not live_paths:
                    continue
                states.append(
                    _indexed_state(
                        context,
                        _event_operation(event),
                        vulnerability_type="memory_leak",
                        backend="memory_lifetime",
                        affected_identity=identity,
                        affected_kind=resource_kind,
                        source={"kind": "allocation", "operation_address": event.operation_address},
                        facts={
                            "path_local": True,
                            "escaped": False,
                            "live_at_scope_exit": True,
                            "scope_exits": [item.exit_address for item in live_paths],
                            "resource_paths": [
                                {
                                    "exit_address": item.exit_address,
                                    "release_addresses": list(item.release_addresses),
                                    "live_at_exit": item.live_at_exit,
                                    "escape_kind": item.escape_kind,
                                }
                                for item in paths
                            ],
                        },
                        blockers=["live_generation_at_scope_exit_replay_required"],
                    )
                )
    return states


def _address_sort_key(value: str) -> tuple[int, str]:
    try:
        return int(str(value), 0), ""
    except (TypeError, ValueError):
        return 2**63 - 1, str(value)


def _control_flow_facts(relation: Any) -> dict[str, Any]:
    return {
        "path_relation": relation.relation,
        "control_flow": {
            "feasible": relation.feasible,
            "before_dominates_after": relation.before_dominates_after,
            "same_block": relation.same_block,
            "evidence": relation.evidence,
        },
    }


def _resource_families_compatible(allocator: str, deallocator: str, resource_kind: str) -> bool:
    if allocator == deallocator:
        return True
    return (allocator, deallocator, resource_kind) in {
        ("socket", "descriptor", "socket"),
    }


def _event_operation(event: Any) -> IndexedOperation:
    return IndexedOperation(
        kind="call",
        name=event.operation_name,
        backend="memory_lifetime",
        semantics=event.event_kind,
        effect_kind="resource_lifetime",
        function_name=event.function_name,
        function_address=event.function_address,
        operation_address=event.operation_address,
        line_number=event.line_number,
        arguments=(event.argument,),
        argument_roles=(("resource", event.argument),),
        evidence_source="program_index_lifecycle",
    )


def _event_dict(event: Any) -> dict[str, Any]:
    return {
        "event": event.event_kind,
        "resource_kind": event.resource_kind,
        "resource_identity": event.resource_identity,
        "allocator_family": event.allocator_family,
        "operation_address": event.operation_address,
        "context_function_name": event.context_function_name,
        "context_function_address": event.context_function_address,
        "context_operation_address": event.context_operation_address,
        "context_line_number": event.context_line_number,
        "call_path": list(event.call_path),
        "instantiation_source": event.instantiation_source,
    }


def _classify_static_literal(value: str, context: str = "") -> list[tuple[str, str]]:
    lowered = value.lower()
    combined = f"{context} {value}"
    rows: list[tuple[str, str]] = []
    if "-----begin " in lowered and "private key-----" in lowered:
        rows.append(("embedded_private_key", "embedded_private_key"))
    if re.search(r"(?:api[_-]?key|token|bearer)\s*[:=]\s*[A-Za-z0-9_\-]{12,}", combined, re.IGNORECASE):
        rows.append(("embedded_api_token", "embedded_api_token"))
    if re.search(r"(?:pass(?:word|wd)?|secret|credential)[A-Za-z0-9_]*\s*(?:[:=]\s*)?(?:\"[^\"]{4,}|\S{4,})", combined, re.IGNORECASE):
        rows.append(("hardcoded_credential", "embedded_credential"))
    if re.search(r"(?:default|admin).*(?:pass|credential)|(?:user|login)\s*[:=]\s*admin", combined, re.IGNORECASE):
        rows.append(("default_credential", "shipped_default_credential"))
    return rows


def _classify_consumed_literal(
    value: str,
    context: str,
    consumers: Sequence[Any],
    index: ProgramIndex,
) -> list[tuple[str, str, Any]]:
    rows: list[tuple[str, str, Any]] = []
    if not consumers or _static_example_or_template(value, context):
        return rows
    operation_by_address = {
        item.operation_address: item for item in index.operations if item.kind == "call"
    }
    for consumer in consumers:
        operation = operation_by_address.get(consumer.consumer_address)
        if operation is None:
            continue
        if operation.semantics == "credential_consumer":
            if not (
                re.fullmatch(r'"(?:\\.|[^"\\])+"', operation.role("username").strip())
                and re.fullmatch(r'"(?:\\.|[^"\\])+"', operation.role("password").strip())
            ):
                continue
            peer_roles = {
                item.argument_role
                for item in index.literal_consumers
                if item.consumer_address == consumer.consumer_address and item.reachable
            }
            if {"username", "password"}.issubset(peer_roles) and consumer.argument_role == "password":
                username = operation.role("username").strip('"\'')
                password = operation.role("password").strip('"\'')
                if not _known_example_credential(username, password) and _secret_diversity(password):
                    rows.append(("default_credential", "shipped_default_credential", consumer))
            if consumer.argument_role == "password" and _secret_diversity(value):
                rows.append(("hardcoded_credential", "embedded_credential", consumer))
        elif operation.semantics == "private_key_consumer" and _valid_private_key_literal(value):
            rows.append(("embedded_private_key", "embedded_private_key", consumer))
        elif operation.semantics == "api_token_consumer" and _token_shaped(value):
            rows.append(("embedded_api_token", "embedded_api_token", consumer))
    return rows


def _valid_private_key_literal(value: str) -> bool:
    text = str(value).replace("\\n", "\n").strip()
    match = re.fullmatch(
        r"-----BEGIN (?P<label>(?:RSA |EC |OPENSSH )?PRIVATE KEY)-----\s*"
        r"(?P<body>[A-Za-z0-9+/=\s]+?)\s*"
        r"-----END (?P=label)-----",
        text,
        re.DOTALL,
    )
    if match is None:
        return False
    compact = re.sub(r"\s+", "", match.group("body"))
    try:
        der = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(der) >= 16 and der[0] == 0x30 and len(set(der)) >= 8


def _token_shaped(value: str) -> bool:
    token = str(value).strip().strip('"\'')
    if re.search(r"(?:\$\{|\{\{|<%|example|sample|dummy)", token, re.IGNORECASE):
        return False
    if len(token) < 20 or not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
        return False
    categories = sum(
        bool(pattern.search(token))
        for pattern in (re.compile(r"[a-z]"), re.compile(r"[A-Z]"), re.compile(r"\d"), re.compile(r"[_.-]"))
    )
    return categories >= 3 and len(set(token)) >= 10 and len(set(token)) > len(token) // 4


def _secret_diversity(value: str) -> bool:
    secret = str(value).strip().strip('"\'')
    if len(secret) < 8 or _placeholder(secret):
        return False
    return len(set(secret)) >= 5 and not re.fullmatch(r"(.)\1+", secret)


def _known_example_credential(username: str, password: str) -> bool:
    pair = (username.lower(), password.lower())
    return pair in {
        ("admin", "admin"),
        ("root", "root"),
        ("user", "password"),
        ("test", "test"),
        ("guest", "guest"),
        ("example", "example"),
    }


def _static_example_or_template(value: str, context: str) -> bool:
    combined = f"{context} {value}"
    return bool(
        re.search(
            r"(?:rfc\s*\d+|nist|test[_ -]?vector|self[_ -]?test|placeholder|"
            r"\$\{|\{\{|<%|example\.com|example[_ -]|dummy)",
            combined,
            re.IGNORECASE,
        )
    )


def _exact_weak_crypto_call(operation: IndexedOperation) -> bool:
    observed = (operation.observed_name or operation.name).lower().lstrip("_")
    return observed in {
        "md5",
        "sha1",
        "des_set_key",
        "evp_md5",
        "evp_sha1",
        "weak_crypto",
    }


def _security_random_consumer(
    operation: IndexedOperation,
    index: ProgramIndex,
) -> IndexedOperation | None:
    observed = (operation.observed_name or operation.name).lower()
    if observed == "srand":
        return None
    result = operation.role("result")
    if not result:
        return None
    return next(
        (
            item
            for item in index.operations
            if item.function_name == operation.function_name
            and item.semantics == "security_random_consumer"
            and any(re.search(rf"\b{re.escape(result)}\b", argument) for argument in item.arguments)
            and _address_sort_key(item.operation_address) > _address_sort_key(operation.operation_address)
        ),
        None,
    )


def _tls_validation_disabled(operation: IndexedOperation) -> bool:
    if operation.name == "disable_tls_verify":
        return True
    if operation.name == "ssl_ctx_set_verify":
        mode = re.sub(r"[()\s]", "", operation.role("verify_mode")).lower()
        return mode in {"0", "0x0", "ssl_verify_none"}
    if operation.name == "curl_easy_setopt":
        option = re.sub(r"[()\s]", "", operation.role("option")).upper()
        value = re.sub(r"[()\sULul]", "", operation.role("value")).lower()
        return option in {"CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST"} and value in {"0", "0x0"}
    return False


def _placeholder(value: str) -> bool:
    stripped = re.sub(r"[^A-Za-z0-9]", "", value)
    return (
        len(stripped) < 4
        or bool(PLACEHOLDER_RE.fullmatch(stripped))
        or bool(re.fullmatch(r"(.)\1{3,}", stripped, re.IGNORECASE))
    )


def _is_untrusted(value: str) -> bool:
    if _quoted_literal(value):
        return False
    lowered = str(value or "").lower()
    if any(token in lowered for token in ("fixed", "safe", "allowlisted", "constant")):
        return False
    return any(token in lowered for token in ("argv", "input", "buf", "query", "param", "recv", "read", "getenv", "cgi", "request", "url", "header", "message", "user"))


def _quoted_literal(value: str) -> bool:
    return bool(re.match(r'^\s*(?:u8|[LuU])?["\']', str(value or "")))


def _literal_fingerprint(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _base_offset(expression: str) -> tuple[str, int]:
    normalized = str(expression or "")
    cast = re.compile(
        r"\((?:(?:const|volatile|signed|unsigned)\s+)*(?:void|char|short|int|long|size_t|u?int(?:8|16|32|64)_t)(?:\s*\*)*\)"
    )
    previous = ""
    while normalized != previous:
        previous = normalized
        normalized = cast.sub("", normalized)
    normalized = re.sub(r"[()\s&]", "", normalized)
    match = re.fullmatch(r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)(?:(?P<sign>[+-])(?P<offset>0x[0-9a-fA-F]+|\d+))?", normalized)
    if not match:
        return normalized, 0
    offset = int(match.group("offset"), 0) if match.group("offset") else 0
    if match.group("sign") == "-":
        offset = -offset
    return match.group("base"), offset


def _int_literal(value: str) -> int | None:
    try:
        return int(re.sub(r"[uUlL]+$", "", value.strip()), 0)
    except ValueError:
        return None


def _preferred_state(left: CandidateState, right: CandidateState) -> tuple[CandidateState, CandidateState]:
    def score(state: CandidateState) -> tuple[int, int, int, int]:
        operation = state.operation
        source = str(operation.get("evidence_source") or "")
        address = str(operation.get("address") or "")
        identity = str(state.affected_object.get("identity") or "")
        return (
            int(source.startswith("pcode")),
            int(address.startswith("0x")),
            len(identity),
            -len(state.blockers),
        )

    return (left, right) if score(left) >= score(right) else (right, left)


def _dedupe(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(str(item) for item in values if str(item)))


def _merge_mappings(
    left: Sequence[Mapping[str, Any]],
    right: Sequence[Mapping[str, Any]],
    key: str,
) -> list[Mapping[str, Any]]:
    rows: dict[str, Mapping[str, Any]] = {}
    for item in (*left, *right):
        rows.setdefault(str(item.get(key) or len(rows)), item)
    return list(rows.values())
