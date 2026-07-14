"""Fact extraction boundary for the v3 deterministic analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from binary_agent.analysis.facts import CapacityModel, FunctionSummary, MemObject, ResolvedWrite, SuppressedFinding, WriteFact
from binary_agent.analysis.policy import triage_tier_for_candidate
from binary_agent.data.operation_specs import (
    DEFAULT_OPERATION_SPECS_PATH,
    load_operation_specs,
    normalize_operation_name,
)


DEFAULT_OPERATION_MEMORY_SPECS_PATH = DEFAULT_OPERATION_SPECS_PATH


@dataclass(frozen=True)
class MemoryOperationSpec:
    name: str
    semantics: str
    dest_arg: Optional[int] = None
    size_arg: Optional[int] = None
    object_size_arg: Optional[int] = None
    format_arg: Optional[int] = None
    first_dest_arg: Optional[int] = None
    source_arg: Optional[int] = None
    source_args: tuple[int, ...] = ()
    aliases: tuple[str, ...] = ()
    units: str = "bytes"
    terminator: bool = False
    append: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {key: value for key, value in self.raw.items()}
        payload["semantics"] = self.semantics
        if self.dest_arg is not None:
            payload["dest_arg"] = self.dest_arg
        if self.size_arg is not None:
            payload["size_arg"] = self.size_arg
        if self.object_size_arg is not None:
            payload["object_size_arg"] = self.object_size_arg
        if self.format_arg is not None:
            payload["format_arg"] = self.format_arg
        if self.first_dest_arg is not None:
            payload["first_dest_arg"] = self.first_dest_arg
        if self.source_arg is not None:
            payload["source_arg"] = self.source_arg
        if self.source_args:
            payload["source_args"] = list(self.source_args)
        if self.aliases:
            payload["aliases"] = list(self.aliases)
        if self.units:
            payload["units"] = self.units
        if self.terminator:
            payload["terminator"] = self.terminator
        if self.append:
            payload["append"] = self.append
        return payload


@dataclass(frozen=True)
class MemoryOperationSpecSet:
    version: int
    sinks: dict[str, MemoryOperationSpec]
    aliases: dict[str, str] = field(default_factory=dict)
    path: str = ""

    def get(self, name: str, default: object = None) -> MemoryOperationSpec | object:
        normalized = self.normalize_name(name)
        return self.sinks.get(normalized, default)

    def __contains__(self, name: object) -> bool:
        return self.normalize_name(str(name)) in self.sinks

    def names(self) -> set[str]:
        return set(self.sinks)

    def as_dict_mapping(self) -> dict[str, dict[str, object]]:
        return {name: spec.to_dict() for name, spec in self.sinks.items()}

    def normalize_name(self, name: object) -> str:
        lowered = _canonical_sink_name(str(name or ""))
        return self.aliases.get(lowered, lowered)


@dataclass(frozen=True)
class FactExtractionResult:
    write_facts: list[WriteFact] = field(default_factory=list)
    resolved_writes: list[ResolvedWrite] = field(default_factory=list)
    function_summaries: list[FunctionSummary] = field(default_factory=list)
    suppressed_findings: list[SuppressedFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "write_facts": [fact.to_dict() for fact in self.write_facts],
            "resolved_writes": [write.to_dict() for write in self.resolved_writes],
            "function_summaries": [summary.to_dict() for summary in self.function_summaries],
            "suppressed_findings": [finding.to_dict() for finding in self.suppressed_findings],
        }


def load_memory_operation_specs(path: Path | str | None = None) -> MemoryOperationSpecSet:
    spec_path = Path(path) if path is not None else DEFAULT_OPERATION_MEMORY_SPECS_PATH
    operation_specs = load_operation_specs(spec_path)
    sinks: dict[str, MemoryOperationSpec] = {}
    aliases: dict[str, str] = {}
    for operation in operation_specs.operations:
        if operation.backend != "memory_access" or operation.effect_kind != "memory_write":
            continue
        canonical_name = operation.name
        roles = dict(operation.argument_roles)
        metadata = dict(operation.metadata)
        semantics = _spatial_semantics(operation.semantics)
        raw_aliases = operation.aliases
        source_arg = roles.get("source")
        source_args = (source_arg,) if source_arg is not None else ()
        append = "append" in operation.semantics
        raw = {
            "backend": operation.backend,
            "effect_kind": operation.effect_kind,
            "operation_semantics": operation.semantics,
            **metadata,
        }
        sinks[canonical_name] = MemoryOperationSpec(
            name=canonical_name,
            semantics=semantics,
            dest_arg=roles.get("destination"),
            size_arg=roles.get("size"),
            object_size_arg=_optional_int(metadata.get("object_size_arg")),
            format_arg=roles.get("format"),
            first_dest_arg=_optional_int(metadata.get("first_dest_arg")),
            source_arg=source_arg,
            source_args=source_args,
            aliases=raw_aliases,
            units=str(metadata.get("units") or "bytes"),
            terminator=bool(metadata.get("terminator", False)),
            append=append,
            raw=dict(raw),
        )
    aliases = {
        alias: canonical
        for alias, canonical in operation_specs.alias_items
        if canonical in sinks and alias != canonical
    }
    return MemoryOperationSpecSet(version=operation_specs.version, sinks=sinks, aliases=aliases, path=str(spec_path))


def _spatial_semantics(value: str) -> str:
    if value == "format_input":
        return "format_string"
    if "unbounded" in value:
        return "unbounded"
    if "append" in value:
        return "append_bounded"
    return "bounded"


def _canonical_sink_name(name: str) -> str:
    return normalize_operation_name(name)


def _coerce_string_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if not isinstance(value, Sequence):
        return ()
    return tuple(str(item) for item in value if str(item).strip())


def _coerce_int_tuple(value: Any) -> tuple[int, ...]:
    if isinstance(value, (str, bytes, bytearray)):
        parsed = _optional_int(value)
        return (parsed,) if parsed is not None else ()
    if not isinstance(value, Sequence):
        return ()
    parsed_items: list[int] = []
    for item in value:
        parsed = _optional_int(item)
        if parsed is not None and parsed not in parsed_items:
            parsed_items.append(parsed)
    return tuple(parsed_items)


def candidate_to_write_fact(candidate: object) -> WriteFact:
    data = candidate.to_dict() if hasattr(candidate, "to_dict") else dict(candidate)
    capacity_model = _capacity_from_candidate(data)
    evidence_sources = [str(item) for item in data.get("evidence_sources", []) or []]
    producer = "reconciled"
    if evidence_sources:
        if any(source.startswith("pcode") for source in evidence_sources):
            producer = "pcode"
        elif "interprocedural_summary" in evidence_sources:
            producer = "summary"
        elif "c_text" in evidence_sources:
            producer = "c_text"
    fact_id = str(data.get("candidate_id") or "")
    return WriteFact(
        fact_id=fact_id,
        binary=str(data.get("binary") or ""),
        function_name=str(data.get("function_name") or ""),
        address=str(data.get("address") or ""),
        relative_path=str(data.get("relative_path") or ""),
        producer=producer,
        kind=str(data.get("kind") or ""),
        sink=str(data.get("sink") or ""),
        semantics=str(data.get("sink_semantics") or ""),
        operation_address=str(data.get("operation_address") or ""),
        line_number=int(data.get("line_number", 0) or 0),
        line_text=str(data.get("line_text") or ""),
        destination_expr=str(data.get("target_buffer") or ""),
        destination_object_id=f"{data.get('destination_kind') or 'memory'}:{data.get('target_buffer') or ''}",
        target_buffer=str(data.get("target_buffer") or ""),
        offset_expr=_offset_expr_from_candidate(data),
        write_size_expr=str(data.get("write_size_expr") or ""),
        write_size_bytes=_optional_int(data.get("write_size_bytes")),
        capacity=capacity_model,
        evidence_sources=evidence_sources,
        source_evidence=[str(item) for item in data.get("source_evidence", []) or []],
        guard_evidence=[str(item) for item in data.get("guard_evidence", []) or []],
        attacker_control=_attacker_control_from_candidate(
            data,
            {
                "destination_pointer": "unknown",
                "source_bytes": "attacker_controlled" if data.get("source_evidence") else "unknown",
                "write_size": "symbolic" if data.get("write_size_bytes") in {None, ""} else "constant",
                "offset": (
                    "symbolic"
                    if str(data.get("write_relation") or "") in {"symbolic_offset", "symbolic_offset_size_guarded"}
                    else "classified"
                ),
                "format_string": "unknown",
            },
        ),
        raw={**data, "vulnerability_type": str(data.get("vulnerability_type") or "memory_overflow")},
    )


def candidate_to_resolved_write(candidate: object) -> ResolvedWrite:
    data = candidate.to_dict() if hasattr(candidate, "to_dict") else dict(candidate)
    fact = candidate_to_write_fact(data)
    capacity = _capacity_from_candidate(data)
    destination_kind = str(data.get("destination_kind") or "memory")
    target = str(data.get("target_buffer") or "memory_object")
    memory = MemObject(
        object_id=f"{destination_kind}:{target}",
        label=target,
        kind=destination_kind,
        capacity=capacity,
        object_trust=str(data.get("object_trust") or capacity.trust or "unknown"),
        var_names=[target] if target else [],
        field_path=str(data.get("field_path") or ""),
        metadata={
            "capacity_basis": data.get("capacity_basis", ""),
            "capacity_source": data.get("capacity_source", ""),
            "candidate_id": data.get("candidate_id", ""),
            "vulnerability_type": data.get("vulnerability_type", "memory_overflow"),
        },
    )
    trace = classified_trace_for_candidate(data)
    return ResolvedWrite(
        resolved_id=str(data.get("candidate_id") or fact.fact_id),
        write_fact=fact,
        memory_object=memory,
        offset_expr=fact.offset_expr,
        width_expr=str(data.get("write_size_expr") or ""),
        width_bytes=_optional_int(data.get("write_size_bytes")),
        resolution_trace={
            "object_resolution": trace.get("object_resolution", {}),
            "capacity_resolution": trace.get("capacity_resolution", {}),
            "evidence_sources": data.get("evidence_sources", []),
        },
    )


def extract_write_facts(manifest: object, nodes: Sequence[object], operation_specs: MemoryOperationSpecSet | None = None) -> FactExtractionResult:
    """Run the analyzer and expose its fact artifacts.

    The implementation intentionally imports `candidates` lazily to avoid a
    module cycle. The candidate module owns the mature C/p-code parsing helpers;
    this boundary converts its v3 extraction result to typed facts for callers.
    """

    from binary_agent.analysis import candidates as candidate_module

    if hasattr(candidate_module, "_extract_fact_pipeline"):
        previous_specs = getattr(candidate_module, "OPERATION_SPEC_SET", None)
        if operation_specs is not None and hasattr(candidate_module, "_refresh_sink_spec_views"):
            candidate_module._refresh_sink_spec_views(operation_specs)
        try:
            result = candidate_module._extract_fact_pipeline(manifest, nodes)
        finally:
            if operation_specs is not None and previous_specs is not None and hasattr(candidate_module, "_refresh_sink_spec_views"):
                candidate_module._refresh_sink_spec_views(previous_specs)
        return FactExtractionResult(
            write_facts=list(result.write_facts),
            resolved_writes=list(getattr(result, "resolved_writes", [])),
            function_summaries=list(result.function_summaries),
            suppressed_findings=list(result.suppressed_findings),
        )
    found = candidate_module.extract_static_candidates(manifest, nodes)
    return FactExtractionResult(
        write_facts=[candidate_to_write_fact(candidate) for candidate in found],
        resolved_writes=[candidate_to_resolved_write(candidate) for candidate in found],
    )


def classified_trace_for_candidate(candidate: object) -> dict[str, object]:
    data = candidate.to_dict() if hasattr(candidate, "to_dict") else dict(candidate)
    existing = data.get("classification_trace")
    if isinstance(existing, Mapping) and existing:
        return dict(existing)
    return {
        "object_resolution": {
            "target_buffer": data.get("target_buffer", ""),
            "destination_kind": data.get("destination_kind", ""),
            "capacity_source": data.get("capacity_source", ""),
            "vulnerability_type": data.get("vulnerability_type", "memory_overflow"),
        },
        "capacity_resolution": data.get("capacity_model") or _capacity_from_candidate(data).to_dict(),
        "guards": {
            "accepted": data.get("guard_evidence", []),
            "rejected": [],
        },
        "aliases": [source for source in data.get("evidence_sources", []) or [] if "alias" in str(source)],
        "summaries": [source for source in data.get("evidence_sources", []) or [] if "summary" in str(source)],
        "source_flow": data.get("source_evidence", []),
        "suppression_reason": "",
        "triage_tier": triage_tier_for_candidate(data),
    }


def _capacity_from_candidate(data: Mapping[str, Any]) -> CapacityModel:
    model = data.get("capacity_model")
    if isinstance(model, Mapping):
        return CapacityModel.from_dict(model)
    capacity = _optional_int(data.get("capacity_bytes"))
    capacity_expr = str(data.get("capacity_expr") or "")
    if not capacity_expr and capacity in {None, 0}:
        basis = str(data.get("capacity_basis") or "")
        if "modeled by" in basis:
            capacity_expr = basis.rsplit("modeled by", 1)[-1].strip()
    return CapacityModel(
        fixed_bytes=capacity if capacity and capacity > 0 else None,
        symbolic_expr="" if capacity and capacity > 0 else capacity_expr,
        source=str(data.get("capacity_source") or ""),
        trust="high" if capacity and capacity > 0 else "symbolic",
    )


def _attacker_control_from_candidate(
    data: Mapping[str, Any],
    fallback: Mapping[str, str],
) -> dict[str, str]:
    trace = data.get("classification_trace")
    source_to_write = trace.get("source_to_write") if isinstance(trace, Mapping) else None
    roles = source_to_write.get("roles") if isinstance(source_to_write, Mapping) else None
    if not isinstance(roles, Mapping):
        return {str(key): str(value) for key, value in fallback.items()}

    def role_classification(role: str, default: str) -> str:
        fact = roles.get(role)
        if isinstance(fact, Mapping):
            classification = str(fact.get("classification") or "")
            if classification:
                return classification
        return default

    return {
        **{str(key): str(value) for key, value in fallback.items()},
        "destination_pointer": role_classification(
            "destination_pointer",
            fallback.get("destination_pointer", "unknown"),
        ),
        "source_bytes": role_classification("write_source", fallback.get("source_bytes", "unknown")),
        "write_size": role_classification("write_size", fallback.get("write_size", "unknown")),
        "offset": role_classification("write_offset", fallback.get("offset", "unknown")),
    }


def _offset_expr_from_candidate(data: Mapping[str, Any]) -> str:
    offset_expr = str(data.get("offset_expr") or "")
    if offset_expr:
        return offset_expr
    relation = str(data.get("write_relation") or "")
    if relation in {"symbolic_offset", "symbolic_offset_size_guarded", "iterated_alias_unproven", "unproven_offset_relation"}:
        return str(data.get("write_size_expr") or "")
    return "0"


def _optional_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None
