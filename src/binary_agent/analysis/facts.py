"""Fact-first schema for deterministic memory-write analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Optional, Sequence


def _clean_mapping(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return dict(value or {})


def _clean_list(value: Sequence[Any] | None) -> list[Any]:
    return list(value or [])


@dataclass(frozen=True)
class CapacityModel:
    """Capacity for a memory object.

    ``fixed_bytes`` is set when the analyzer knows an exact byte count.
    ``symbolic_expr`` preserves expressions such as ``sizeof(struct foo)`` or
    caller-provided size parameters instead of collapsing them to zero.
    """

    fixed_bytes: Optional[int] = None
    symbolic_expr: str = ""
    lower_bound: Optional[int] = None
    upper_bound: Optional[int] = None
    source: str = ""
    trust: str = "unknown"

    @property
    def has_fixed_capacity(self) -> bool:
        return self.fixed_bytes is not None and self.fixed_bytes > 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "CapacityModel":
        if not data:
            return cls()
        return cls(
            fixed_bytes=_optional_int(data.get("fixed_bytes")),
            symbolic_expr=str(data.get("symbolic_expr") or ""),
            lower_bound=_optional_int(data.get("lower_bound")),
            upper_bound=_optional_int(data.get("upper_bound")),
            source=str(data.get("source") or ""),
            trust=str(data.get("trust") or "unknown"),
        )


@dataclass(frozen=True)
class MemObject:
    """Resolved memory object used by the v3 fact pipeline."""

    object_id: str
    label: str
    kind: str
    capacity: CapacityModel = field(default_factory=CapacityModel)
    object_trust: str = "unknown"
    var_names: list[str] = field(default_factory=list)
    base_object_id: str = ""
    field_path: str = ""
    field_offset: Optional[int] = None
    element_stride: Optional[int] = None
    field_capacity: Optional[int] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["capacity"] = self.capacity.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MemObject":
        return cls(
            object_id=str(data.get("object_id") or ""),
            label=str(data.get("label") or ""),
            kind=str(data.get("kind") or "unknown"),
            capacity=CapacityModel.from_dict(data.get("capacity") if isinstance(data.get("capacity"), Mapping) else None),
            object_trust=str(data.get("object_trust") or "unknown"),
            var_names=[str(item) for item in data.get("var_names", []) or []],
            base_object_id=str(data.get("base_object_id") or ""),
            field_path=str(data.get("field_path") or ""),
            field_offset=_optional_int(data.get("field_offset")),
            element_stride=_optional_int(data.get("element_stride")),
            field_capacity=_optional_int(data.get("field_capacity")),
            metadata=_clean_mapping(data.get("metadata") if isinstance(data.get("metadata"), Mapping) else None),
        )


@dataclass(frozen=True)
class WriteFact:
    """Neutral observation of a memory write before policy filtering."""

    fact_id: str
    binary: str
    function_name: str
    address: str
    relative_path: str
    producer: str
    kind: str
    sink: str
    semantics: str = ""
    operation_address: str = ""
    pcode_sequence: str = ""
    line_number: int = 0
    line_text: str = ""
    destination_expr: str = ""
    destination_object_id: str = ""
    target_buffer: str = ""
    offset_expr: str = ""
    write_size_expr: str = ""
    write_size_bytes: Optional[int] = None
    capacity: CapacityModel = field(default_factory=CapacityModel)
    evidence_sources: list[str] = field(default_factory=list)
    source_evidence: list[str] = field(default_factory=list)
    guard_evidence: list[str] = field(default_factory=list)
    attacker_control: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["capacity"] = self.capacity.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WriteFact":
        return cls(
            fact_id=str(data.get("fact_id") or ""),
            binary=str(data.get("binary") or ""),
            function_name=str(data.get("function_name") or ""),
            address=str(data.get("address") or ""),
            relative_path=str(data.get("relative_path") or ""),
            producer=str(data.get("producer") or ""),
            kind=str(data.get("kind") or ""),
            sink=str(data.get("sink") or ""),
            semantics=str(data.get("semantics") or ""),
            operation_address=str(data.get("operation_address") or ""),
            pcode_sequence=str(data.get("pcode_sequence") or ""),
            line_number=int(data.get("line_number", 0) or 0),
            line_text=str(data.get("line_text") or ""),
            destination_expr=str(data.get("destination_expr") or ""),
            destination_object_id=str(data.get("destination_object_id") or ""),
            target_buffer=str(data.get("target_buffer") or ""),
            offset_expr=str(data.get("offset_expr") or ""),
            write_size_expr=str(data.get("write_size_expr") or ""),
            write_size_bytes=_optional_int(data.get("write_size_bytes")),
            capacity=CapacityModel.from_dict(data.get("capacity") if isinstance(data.get("capacity"), Mapping) else None),
            evidence_sources=[str(item) for item in data.get("evidence_sources", []) or []],
            source_evidence=[str(item) for item in data.get("source_evidence", []) or []],
            guard_evidence=[str(item) for item in data.get("guard_evidence", []) or []],
            attacker_control={str(key): str(value) for key, value in _clean_mapping(data.get("attacker_control") if isinstance(data.get("attacker_control"), Mapping) else None).items()},
            raw=_clean_mapping(data.get("raw") if isinstance(data.get("raw"), Mapping) else None),
        )


@dataclass(frozen=True)
class ResolvedWrite:
    """A write fact resolved to one memory object and byte-range model."""

    resolved_id: str
    write_fact: WriteFact
    memory_object: MemObject
    offset_expr: str = ""
    width_expr: str = ""
    width_bytes: Optional[int] = None
    resolution_trace: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolved_id": self.resolved_id,
            "write_fact": self.write_fact.to_dict(),
            "memory_object": self.memory_object.to_dict(),
            "offset_expr": self.offset_expr,
            "width_expr": self.width_expr,
            "width_bytes": self.width_bytes,
            "resolution_trace": dict(self.resolution_trace),
        }


@dataclass(frozen=True)
class AliasFact:
    function_name: str
    alias: str
    target_object_id: str = ""
    target_param_index: Optional[int] = None
    offset_expr: str = ""
    source: str = ""
    line_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BoundFact:
    function_name: str
    variable: str
    relation: str
    bound_expr: str
    accepted: bool
    source: str
    line_number: int = 0
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SourceFact:
    function_name: str
    source_kind: str
    line_number: int = 0
    evidence: str = ""
    operation_address: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FunctionSummary:
    """Interprocedural summary retained even when no public finding is emitted."""

    function_name: str
    function_keys: list[str] = field(default_factory=list)
    writes: list[dict[str, Any]] = field(default_factory=list)
    allocations: list[dict[str, Any]] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    wrappers: list[dict[str, Any]] = field(default_factory=list)
    max_depth: int = 0
    complete: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FunctionSummary":
        return cls(
            function_name=str(data.get("function_name") or ""),
            function_keys=[str(item) for item in data.get("function_keys", []) or []],
            writes=[dict(item) for item in data.get("writes", []) or [] if isinstance(item, Mapping)],
            allocations=[dict(item) for item in data.get("allocations", []) or [] if isinstance(item, Mapping)],
            sources=[dict(item) for item in data.get("sources", []) or [] if isinstance(item, Mapping)],
            wrappers=[dict(item) for item in data.get("wrappers", []) or [] if isinstance(item, Mapping)],
            max_depth=int(data.get("max_depth", 0) or 0),
            complete=bool(data.get("complete", True)),
        )


@dataclass(frozen=True)
class ClassifiedFinding:
    """A write fact after memory-set classification and trace assembly."""

    finding_id: str
    write_fact: WriteFact
    status: str
    relation: str
    condition: str
    triage_tier: str
    reportable: bool = False
    confirmation_queue: bool = False
    classification_trace: dict[str, Any] = field(default_factory=dict)
    candidate: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "write_fact": self.write_fact.to_dict(),
            "status": self.status,
            "relation": self.relation,
            "condition": self.condition,
            "triage_tier": self.triage_tier,
            "reportable": self.reportable,
            "confirmation_queue": self.confirmation_queue,
            "classification_trace": dict(self.classification_trace),
            "candidate": dict(self.candidate),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ClassifiedFinding":
        raw_fact = data.get("write_fact")
        return cls(
            finding_id=str(data.get("finding_id") or ""),
            write_fact=WriteFact.from_dict(raw_fact if isinstance(raw_fact, Mapping) else {}),
            status=str(data.get("status") or ""),
            relation=str(data.get("relation") or ""),
            condition=str(data.get("condition") or ""),
            triage_tier=str(data.get("triage_tier") or ""),
            reportable=bool(data.get("reportable", False)),
            confirmation_queue=bool(data.get("confirmation_queue", False)),
            classification_trace=_clean_mapping(data.get("classification_trace") if isinstance(data.get("classification_trace"), Mapping) else None),
            candidate=_clean_mapping(data.get("candidate") if isinstance(data.get("candidate"), Mapping) else None),
        )


@dataclass(frozen=True)
class SuppressedFinding:
    """Debug-only record for a fact that policy suppressed."""

    fact_id: str
    reason: str
    function_name: str = ""
    sink: str = ""
    target_buffer: str = ""
    trace: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _optional_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None
