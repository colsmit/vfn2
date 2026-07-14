"""Canonical schemas for the proof-gated vulnerability pipeline."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from binary_agent.dynamic_proof import (
    DYNAMIC_MEMORY_ACCESS,
    DynamicProofView,
    first_ghidra_dynamic_proof,
)
from binary_agent.utils.time import utc_timestamp
from binary_agent.taxonomy import VULNERABILITY_SPECS, get_vulnerability_spec, vulnerability_types_for_backend


class CandidateStatus(str, Enum):
    """Allowed lifecycle states for one vulnerability candidate."""

    CANDIDATE = "candidate"
    NEEDS_REFINEMENT = "needs_refinement"
    PROOF_READY = "proof_ready"
    REPLAY_READY = "replay_ready"
    REPLAY_CONFIRMED = "replay_confirmed"
    REJECTED = "rejected"
    REPORT_READY = "report_ready"

    @classmethod
    def normalize(cls, value: str | "CandidateStatus") -> str:
        raw = value.value if isinstance(value, CandidateStatus) else str(value or "")
        if raw not in {item.value for item in cls}:
            raise ValueError(f"Invalid candidate status: {raw!r}")
        return raw


@dataclass(frozen=True)
class ProofObligation:
    """A deterministic condition that must be proven before reporting."""

    obligation_id: str
    description: str
    condition: str
    required_evidence: list[str] = field(default_factory=list)
    status: str = "open"
    evidence_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProofObligation":
        return cls(
            obligation_id=str(data.get("obligation_id") or data.get("id") or ""),
            description=str(data.get("description") or ""),
            condition=str(data.get("condition") or ""),
            required_evidence=[str(item) for item in _coerce_sequence(data.get("required_evidence", []))],
            status=str(data.get("status") or "open"),
            evidence_refs=[str(item) for item in _coerce_sequence(data.get("evidence_refs", []))],
        )


@dataclass(frozen=True)
class ValidationArtifact:
    """A bounded helper result plus its grounding decision."""

    artifact_id: str
    role: str
    status: str
    path: str = ""
    grounded: bool = False
    blocker_removed: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SourceToSinkTrace:
    """Report gate artifact tying an input boundary to a sink and replay proof."""

    trace_id: str
    candidate_id: str
    status: str
    source_kind: str = ""
    input_model: str = ""
    entry_function: str = ""
    entry_surface_kind: str = ""
    call_path: list[str] = field(default_factory=list)
    source_artifacts: list[Mapping[str, Any]] = field(default_factory=list)
    propagation_path: list[Mapping[str, Any]] = field(default_factory=list)
    argument_roles: list[Mapping[str, Any]] = field(default_factory=list)
    controlled_roles: list[str] = field(default_factory=list)
    sink: Mapping[str, Any] = field(default_factory=dict)
    sink_argument: Mapping[str, Any] = field(default_factory=dict)
    destination_object: Mapping[str, Any] = field(default_factory=dict)
    transformations: list[Mapping[str, Any]] = field(default_factory=list)
    sanitizer_checks: list[Mapping[str, Any]] = field(default_factory=list)
    bounds_checks: list[Mapping[str, Any]] = field(default_factory=list)
    execution_limitations: list[Mapping[str, Any]] = field(default_factory=list)
    dynamic_artifacts: list[str] = field(default_factory=list)
    confidence: str = ""
    blockers: list[str] = field(default_factory=list)
    override_artifact: str = ""
    notes: str = ""
    evidence: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = 2

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["artifact_kind"] = SOURCE_TO_SINK_TRACE_KIND
        return payload


@dataclass(frozen=True)
class BugBountyEvidence:
    """Vendor-facing evidence contract for one replay-backed finding."""

    evidence_id: str
    candidate_id: str
    status: str
    vulnerability_class: str
    target_identity: Mapping[str, Any]
    attacker_input_surface: Mapping[str, Any]
    concrete_poc: Mapping[str, Any]
    source_to_sink_trace: Mapping[str, Any]
    sink_effect_proof: Mapping[str, Any]
    replay: Mapping[str, Any]
    observed_result: Mapping[str, Any]
    limitations: list[str] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["artifact_kind"] = BUG_BOUNTY_EVIDENCE_KIND
        return payload


@dataclass(frozen=True)
class ReplayArtifactRef:
    """Reference to a replay artifact generated for one candidate."""

    artifact_id: str
    path: str
    result: str
    mode: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PromotionEvent:
    """One lifecycle transition for a candidate."""

    candidate_id: str
    from_status: str
    to_status: str
    reason: str
    artifact_refs: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utc_timestamp)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LiftRecord:
    """A measured useful helper contribution."""

    candidate_id: str
    role: str
    outcome: str
    evidence_refs: list[str] = field(default_factory=list)
    measurable: bool = True
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CandidateState:
    """Pipeline source of truth for one possible vulnerability."""

    candidate_id: str
    vulnerability_type: str
    status: str
    target: Mapping[str, Any]
    location: Mapping[str, Any]
    source: Mapping[str, Any]
    sink: Mapping[str, Any]
    type_facts: Mapping[str, Any]
    proof_obligations: list[Mapping[str, Any]]
    blockers: list[str]
    backend: str = ""
    mechanism: str = ""
    operation: Mapping[str, Any] = field(default_factory=dict)
    affected_object: Mapping[str, Any] = field(default_factory=dict)
    root_causes: tuple[str, ...] = ()
    validation_artifacts: list[str] = field(default_factory=list)
    replay_artifacts: list[str] = field(default_factory=list)
    report_artifacts: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_timestamp)
    updated_at: str = field(default_factory=utc_timestamp)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        CandidateStatus.normalize(self.status)
        if self.backend and self.backend not in {
            "memory_access",
            "memory_lifetime",
            "semantic_effect",
            "static_evidence",
        }:
            raise ValueError(f"Invalid candidate backend: {self.backend!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "backend": self.backend,
            "vulnerability_type": self.vulnerability_type,
            "mechanism": self.mechanism,
            "status": self.status,
            "target": dict(self.target),
            "location": dict(self.location),
            "source": dict(self.source),
            "sink": dict(self.sink),
            "operation": _json_safe_mapping(self.operation),
            "affected_object": _json_safe_mapping(self.affected_object),
            "root_causes": list(self.root_causes),
            "type_facts": _json_safe_mapping(self.type_facts),
            "proof_obligations": [_json_safe_mapping(item) for item in self.proof_obligations],
            "blockers": list(self.blockers),
            "validation_artifacts": list(self.validation_artifacts),
            "replay_artifacts": list(self.replay_artifacts),
            "report_artifacts": list(self.report_artifacts),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": _json_safe_mapping(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CandidateState":
        return cls(
            candidate_id=str(data.get("candidate_id") or ""),
            backend=str(data.get("backend") or ""),
            vulnerability_type=str(data.get("vulnerability_type") or data.get("type") or ""),
            mechanism=str(data.get("mechanism") or ""),
            status=CandidateStatus.normalize(str(data.get("status") or CandidateStatus.CANDIDATE.value)),
            target=_coerce_mapping(data.get("target")),
            location=_coerce_mapping(data.get("location")),
            source=_coerce_mapping(data.get("source")),
            sink=_coerce_mapping(data.get("sink")),
            operation=_coerce_mapping(data.get("operation") or data.get("sink")),
            affected_object=_coerce_mapping(data.get("affected_object")),
            root_causes=tuple(str(item) for item in _coerce_sequence(data.get("root_causes", []))),
            type_facts=_coerce_mapping(data.get("type_facts")),
            proof_obligations=[_coerce_mapping(item) for item in _coerce_sequence(data.get("proof_obligations", []))],
            blockers=[str(item) for item in _coerce_sequence(data.get("blockers", []))],
            validation_artifacts=[str(item) for item in _coerce_sequence(data.get("validation_artifacts", []))],
            replay_artifacts=[str(item) for item in _coerce_sequence(data.get("replay_artifacts", []))],
            report_artifacts=[str(item) for item in _coerce_sequence(data.get("report_artifacts", []))],
            created_at=str(data.get("created_at") or utc_timestamp()),
            updated_at=str(data.get("updated_at") or utc_timestamp()),
            metadata=_coerce_mapping(data.get("metadata")),
        )

    def with_updates(self, **updates: Any) -> "CandidateState":
        updates.setdefault("updated_at", utc_timestamp())
        if "status" in updates:
            updates["status"] = CandidateStatus.normalize(updates["status"])
        return replace(self, **updates)


@dataclass
class ArtifactIndex:
    """Append-only index of generated pipeline artifacts."""

    entries: list[dict[str, Any]] = field(default_factory=list)

    def add(
        self,
        path: Path | str,
        *,
        kind: str,
        stage: str = "",
        candidate_id: str = "",
        description: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        raw_path = str(path)
        artifact_id = _stable_id(kind, stage, candidate_id, raw_path)
        entry = {
            "artifact_id": artifact_id,
            "path": raw_path,
            "kind": kind,
            "stage": stage,
            "candidate_id": candidate_id,
            "description": description,
            "metadata": dict(metadata or {}),
            "created_at": utc_timestamp(),
        }
        self.entries = [item for item in self.entries if item.get("artifact_id") != artifact_id]
        self.entries.append(entry)
        return artifact_id

    def to_dict(self) -> dict[str, Any]:
        return {"artifacts": list(self.entries)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ArtifactIndex":
        entries = data.get("artifacts", []) if isinstance(data, Mapping) else []
        return cls(entries=[dict(item) for item in entries if isinstance(item, Mapping)])

    @classmethod
    def load(cls, path: Path) -> "ArtifactIndex":
        if not Path(path).exists():
            return cls()
        payload = json.loads(Path(path).read_text() or "{}")
        return cls.from_dict(payload)

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))
        return path


SOURCE_TO_SINK_TRACE_KIND = "source_to_sink_trace"
SOURCE_TO_SINK_OVERRIDE_KIND = "source_to_sink_override"
BUG_BOUNTY_EVIDENCE_KIND = "bug_bounty_evidence"
PROCESS_REPLAY_MODES = {"native", "qemu_user", "container_service"}
PROCESS_INPUT_MODELS = {
    "argv",
    "stdin",
    "file",
    "env",
    "argv_file_stdin",
    "argv_directory",
    "line_file",
    "text_record",
    "config",
    "archive",
    "archive_text_record",
    "http_cgi",
    "http_daemon",
    "socket_service",
}
CONTROLLED_ROLE_CLASSIFICATIONS = {"source_controlled", "parameter_controlled"}
MEMORY_CORRUPTION_TYPES = (
    vulnerability_types_for_backend("memory_access")
    | vulnerability_types_for_backend("memory_lifetime")
)
FUNCTION_HARNESS_WRITE_DESTINATIONS = {"stack", "heap", "global", "static", "static_local", "tls"}
FUNCTION_HARNESS_READ_DESTINATIONS = FUNCTION_HARNESS_WRITE_DESTINATIONS | {"source_buffer"}
FUNCTION_HARNESS_PROOF_REPORT_POLICY = {
    "overflow_proven": {
        "vulnerability_types": DYNAMIC_MEMORY_ACCESS["write"]["vulnerability_types"],
        "destinations": FUNCTION_HARNESS_WRITE_DESTINATIONS,
        "byte_field": DYNAMIC_MEMORY_ACCESS["write"]["byte_field"],
    },
    "heap_overflow_proven": {
        "vulnerability_types": DYNAMIC_MEMORY_ACCESS["write"]["vulnerability_types"],
        "destinations": FUNCTION_HARNESS_WRITE_DESTINATIONS,
        "byte_field": DYNAMIC_MEMORY_ACCESS["write"]["byte_field"],
    },
    "oob_write_proven": {
        "vulnerability_types": DYNAMIC_MEMORY_ACCESS["write"]["vulnerability_types"],
        "destinations": FUNCTION_HARNESS_WRITE_DESTINATIONS,
        "byte_field": DYNAMIC_MEMORY_ACCESS["write"]["byte_field"],
    },
    "oob_read_proven": {
        "vulnerability_types": DYNAMIC_MEMORY_ACCESS["read"]["vulnerability_types"],
        "destinations": FUNCTION_HARNESS_READ_DESTINATIONS,
        "byte_field": DYNAMIC_MEMORY_ACCESS["read"]["byte_field"],
    },
}
STATIC_MEMORY_VULN_TYPES = vulnerability_types_for_backend("memory_access")
INTEGER_MEMORY_RISK_TYPES = {
    "integer_overflow_to_memory_access",
    "integer_underflow_to_memory_access",
    "signed_conversion_to_memory_access",
    "integer_truncation_to_memory_access",
}
CONTROLLED_SINK_ROLES = {
    "write_source",
    "write_size",
    "write_offset",
    "read_source",
    "read_size",
    "read_offset",
    "memory_write_source",
    "memory_write_size",
    "memory_write_offset",
    "memory_read_source",
    "memory_read_size",
    "memory_read_offset",
    "destination_pointer",
    "command_argument",
    "path_argument",
    "format_argument",
    "file_path",
    "credential_source",
    "auth_decision",
    "sink_argument",
}
SEMANTIC_PROCESS_TYPES = vulnerability_types_for_backend("semantic_effect")
SEMANTIC_PROCESS_ORACLE_KINDS = {
    spec.effect_kind
    for spec in VULNERABILITY_SPECS.values()
    if spec.backend == "semantic_effect" and spec.effect_kind
}


def candidate_state_from_static_candidate(candidate: Any) -> CandidateState:
    """Convert a deterministic static candidate into the pipeline state model."""
    data = candidate.to_dict() if hasattr(candidate, "to_dict") else dict(candidate)
    raw_vulnerability_type = str(data.get("vulnerability_type") or "")
    vulnerability_type = (
        raw_vulnerability_type
        if raw_vulnerability_type in STATIC_MEMORY_VULN_TYPES or raw_vulnerability_type in INTEGER_MEMORY_RISK_TYPES
        else _memory_vulnerability_type_from_destination(data.get("destination_kind"))
    )
    backend = "memory_access"
    mechanism = "out_of_bounds_read" if vulnerability_type == "out_of_bounds_read" else "out_of_bounds_write"
    function_address = str(data.get("address") or "")
    operation_address = str(data.get("operation_address") or function_address)
    affected_identity = f"{data.get('destination_kind') or 'memory'}:{data.get('target_buffer') or 'unknown'}"
    candidate_id = semantic_candidate_id(
        binary_identity=str(data.get("binary") or ""),
        backend=backend,
        vulnerability_type=vulnerability_type,
        function_address=function_address,
        operation_address=operation_address,
        affected_object_identity=affected_identity,
        mechanism=mechanism,
    )
    write_relation = str(data.get("write_relation") or "")
    verdict = str(data.get("verdict") or "")
    blockers: list[str] = []
    if not data.get("path_is_valid"):
        blockers.append("valid_reachability_path")
    if not data.get("input_reaches_sink"):
        blockers.append("attacker_input_reaches_sink")
    if vulnerability_type == "out_of_bounds_read":
        if write_relation not in {"proven_oob_read"} and verdict not in {"oob_read_proven", "overflow"}:
            blockers.append("read_extent_proof")
    elif write_relation not in {"proven_overflow", "unbounded"} and verdict not in {"overflow", "unbounded"}:
        blockers.append("overflow_condition_proof")
    if blockers:
        status = CandidateStatus.NEEDS_REFINEMENT.value
    else:
        status = CandidateStatus.CANDIDATE.value
    obligation = ProofObligation(
        obligation_id=f"{candidate_id}:{vulnerability_type}_bounds",
        description=_static_candidate_proof_description(vulnerability_type),
        condition=str(data.get("overflow_condition") or write_relation or _static_candidate_default_condition(vulnerability_type)),
        required_evidence=_static_candidate_required_evidence(vulnerability_type),
        status="satisfied" if not blockers else "open",
        evidence_refs=[str(item) for item in data.get("evidence_sources", []) or data.get("evidence", []) or []],
    )
    return CandidateState(
        candidate_id=candidate_id,
        backend=backend,
        vulnerability_type=vulnerability_type,
        mechanism=mechanism,
        status=status,
        target={
            "binary": data.get("binary", ""),
            "component": data.get("binary", ""),
        },
        location={
            "function_name": data.get("function_name", ""),
            "address": data.get("address", ""),
            "relative_path": data.get("relative_path", ""),
            "line_number": data.get("line_number", 0),
            "line_text": data.get("line_text", ""),
        },
        source={
            "kind": "attacker_input" if data.get("input_reaches_sink") else "unknown",
            "call_path": data.get("call_path", []),
            "evidence": data.get("source_evidence", []),
        },
        sink={
            "name": data.get("sink", ""),
            "kind": data.get("kind", ""),
            "target_buffer": data.get("target_buffer", ""),
            "operation_address": data.get("operation_address", ""),
        },
        operation={
            "name": data.get("sink", ""),
            "kind": data.get("kind", ""),
            "address": operation_address,
            "access_kind": "read" if vulnerability_type == "out_of_bounds_read" else "write",
        },
        affected_object={
            "identity": affected_identity,
            "kind": data.get("destination_kind", "memory"),
            "label": data.get("target_buffer", ""),
            "capacity_bytes": data.get("capacity_bytes", 0),
        },
        type_facts={
            "static_candidate": data,
            "capacity_bytes": data.get("capacity_bytes", 0),
            "capacity_basis": data.get("capacity_basis", ""),
            "capacity_source": data.get("capacity_source", ""),
            "destination_kind": data.get("destination_kind", "stack"),
            "vulnerability_type": vulnerability_type,
            "write_relation": write_relation,
            "write_size_expr": data.get("write_size_expr", ""),
            "write_size_bytes": data.get("write_size_bytes"),
            "offset_expr": data.get("offset_expr", "0"),
            "overflow_condition": data.get("overflow_condition", ""),
            "verdict": verdict,
            "input_reaches_sink": bool(data.get("input_reaches_sink")),
            "path_is_valid": bool(data.get("path_is_valid")),
            "evidence": data.get("evidence", []),
        },
        proof_obligations=[obligation.to_dict()],
        blockers=blockers,
        metadata={"source_model": "StaticCandidate"},
    )


def _static_candidate_proof_description(vulnerability_type: str) -> str:
    if vulnerability_type == "out_of_bounds_read":
        return "Prove attacker-controlled input can exceed the source object readable capacity."
    return "Prove attacker-controlled input can exceed the destination object capacity."


def _memory_vulnerability_type_from_destination(destination_kind: Any) -> str:
    destination = str(destination_kind or "").lower()
    if "heap" in destination:
        return "heap_overflow"
    if "global" in destination:
        return "out_of_bounds_write"
    return "stack_overflow"


def _static_candidate_default_condition(vulnerability_type: str) -> str:
    if vulnerability_type == "out_of_bounds_read":
        return "source read exceeds source object capacity"
    if vulnerability_type == "heap_overflow":
        return "heap write exceeds destination"
    if vulnerability_type == "out_of_bounds_write":
        return "write exceeds destination"
    return "stack write exceeds destination"


def _static_candidate_required_evidence(vulnerability_type: str) -> list[str]:
    if vulnerability_type == "out_of_bounds_read":
        return ["capacity_bytes", "read_size_or_offset", "attacker_controlled_input"]
    return ["capacity_bytes", "write_size_or_unbounded_sink", "attacker_controlled_input"]


def load_candidate_states(path: Path) -> list[CandidateState]:
    payload = json.loads(Path(path).read_text() or "{}")
    if not isinstance(payload, Mapping):
        raise ValueError(f"Candidate artifact {path} must be a schema-v2 object")
    schema_version = int(payload.get("schema_version", 0) or 0)
    if schema_version != 2:
        raise ValueError(
            f"Candidate artifact {path} uses schema {schema_version or 'missing'}; schema v2 is required"
        )
    rows = payload.get("candidate_states")
    if not isinstance(rows, list):
        raise ValueError(f"Candidate artifact {path} must contain a 'candidate_states' list")
    return [CandidateState.from_dict(item) for item in rows if isinstance(item, Mapping)]


def write_candidate_states(states: Sequence[CandidateState], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 2,
        "generated_at": utc_timestamp(),
        "candidate_states": [state.to_dict() for state in states],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


PROOF_RESULT_STATUSES = frozenset({"proven", "refuted", "inconclusive", "unsupported"})
PROOF_RESULT_SCOPES = frozenset({"process_entrypoint", "function_harness", "static"})


@dataclass(frozen=True)
class ProofResult:
    """Backend-neutral schema-v2 proof result."""

    backend: str
    candidate_id: str
    status: str
    scope: str
    exact_operation_reached: bool
    memory_access: Mapping[str, Any] = field(default_factory=dict)
    lifetime_violation: Mapping[str, Any] = field(default_factory=dict)
    effect_observation: Mapping[str, Any] = field(default_factory=dict)
    static_evidence: Mapping[str, Any] = field(default_factory=dict)
    concrete_input: Mapping[str, Any] = field(default_factory=dict)
    process_setup: Mapping[str, Any] = field(default_factory=dict)
    native_replay: Mapping[str, Any] = field(default_factory=dict)
    artifact_refs: tuple[str, ...] = ()
    blocker: str = ""

    def __post_init__(self) -> None:
        if self.status not in PROOF_RESULT_STATUSES:
            raise ValueError(f"Invalid proof result status: {self.status!r}")
        if self.scope not in PROOF_RESULT_SCOPES:
            raise ValueError(f"Invalid proof result scope: {self.scope!r}")
        if self.backend not in {"memory_access", "memory_lifetime", "semantic_effect", "static_evidence"}:
            raise ValueError(f"Invalid proof result backend: {self.backend!r}")
        populated = sum(
            bool(item)
            for item in (
                self.memory_access,
                self.lifetime_violation,
                self.effect_observation,
                self.static_evidence,
            )
        )
        if self.status == "proven" and populated != 1:
            raise ValueError("A proven result must contain exactly one backend-specific evidence payload")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "backend": self.backend,
            "candidate_id": self.candidate_id,
            "status": self.status,
            "scope": self.scope,
            "exact_operation_reached": self.exact_operation_reached,
            "memory_access": _json_safe_mapping(self.memory_access),
            "lifetime_violation": _json_safe_mapping(self.lifetime_violation),
            "effect_observation": _json_safe_mapping(self.effect_observation),
            "static_evidence": _json_safe_mapping(self.static_evidence),
            "concrete_input": _json_safe_mapping(self.concrete_input),
            "process_setup": _json_safe_mapping(self.process_setup),
            "native_replay": _json_safe_mapping(self.native_replay),
            "artifact_refs": list(self.artifact_refs),
            "blocker": self.blocker,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProofResult":
        schema_version = int(data.get("schema_version", 0) or 0)
        if schema_version != 2:
            raise ValueError(f"Proof result uses schema {schema_version or 'missing'}; schema v2 is required")
        return cls(
            backend=str(data.get("backend") or ""),
            candidate_id=str(data.get("candidate_id") or ""),
            status=str(data.get("status") or ""),
            scope=str(data.get("scope") or ""),
            exact_operation_reached=bool(data.get("exact_operation_reached")),
            memory_access=_coerce_mapping(data.get("memory_access")),
            lifetime_violation=_coerce_mapping(data.get("lifetime_violation")),
            effect_observation=_coerce_mapping(data.get("effect_observation")),
            static_evidence=_coerce_mapping(data.get("static_evidence")),
            concrete_input=_coerce_mapping(data.get("concrete_input")),
            process_setup=_coerce_mapping(data.get("process_setup")),
            native_replay=_coerce_mapping(data.get("native_replay")),
            artifact_refs=tuple(str(item) for item in _coerce_sequence(data.get("artifact_refs", []))),
            blocker=str(data.get("blocker") or ""),
        )


def load_proof_results(path: Path) -> list[ProofResult]:
    payload = json.loads(Path(path).read_text() or "{}")
    if not isinstance(payload, Mapping) or int(payload.get("schema_version", 0) or 0) != 2:
        raise ValueError(f"Proof artifact {path} must use schema v2")
    rows = payload.get("proof_results")
    if not isinstance(rows, list):
        raise ValueError(f"Proof artifact {path} must contain a 'proof_results' list")
    return [ProofResult.from_dict({**item, "schema_version": 2}) for item in rows if isinstance(item, Mapping)]


def write_proof_results(results: Sequence[ProofResult], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "generated_at": utc_timestamp(),
                "proof_results": [result.to_dict() for result in results],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return path


def semantic_candidate_id(
    *,
    binary_identity: str,
    backend: str,
    vulnerability_type: str,
    function_address: str,
    operation_address: str,
    affected_object_identity: str,
    mechanism: str,
) -> str:
    """Return a stable v2 id without decompiler line text."""

    return _stable_id(
        binary_identity,
        backend,
        vulnerability_type,
        function_address,
        operation_address,
        affected_object_identity,
        mechanism,
    )


def build_source_to_sink_trace(state: CandidateState) -> SourceToSinkTrace:
    trace = _state_source_to_sink_trace(state)
    override = _source_to_sink_override_artifact(state)
    dynamic_artifacts = _boundary_replay_artifacts(state)
    dynamic_process_input_support = _dynamic_process_input_role_support(state)
    backend_process_proof = (
        _reportable_lifetime_process_proof(state)
        or _reportable_memory_access_process_proof(state)
        or _reportable_semantic_v2_proof(state)
    )
    static_backend_proof = _reportable_static_v2_proof(state)
    if static_backend_proof:
        blockers = []
    elif backend_process_proof:
        process_setup = _coerce_mapping(
            backend_process_proof.get("process_input_setup")
            or backend_process_proof.get("process_setup")
        )
        proven_input_model = str(process_setup.get("input_model") or "")
        if proven_input_model in PROCESS_INPUT_MODELS:
            trace = {**trace, "input_model": proven_input_model}
    argument_roles = _source_to_sink_argument_roles(state, trace, dynamic_process_input_support=dynamic_process_input_support)
    controlled_roles = _controlled_role_labels(trace, argument_roles)
    propagation_path = _source_to_sink_propagation_path(trace)
    if static_backend_proof:
        blockers = []
    elif backend_process_proof:
        blockers = []
        if not propagation_path and state.vulnerability_type != "null_pointer_dereference":
            blockers.append("missing_source_to_sink_propagation_path")
        if str(trace.get("input_model") or "") not in PROCESS_INPUT_MODELS:
            blockers.append("unsupported_or_missing_process_input_model")
        if not dynamic_artifacts:
            blockers.append("boundary_replay_missing")
    else:
        blockers = _source_to_sink_blockers(
            trace,
            dynamic_artifacts,
            argument_roles=argument_roles,
            propagation_path=propagation_path,
            dynamic_process_input_support=dynamic_process_input_support,
        )
    status = "proven" if not blockers else "blocked"
    if override:
        status = "override"
        blockers = []
    sink = dict(state.sink)
    destination = {
        "name": sink.get("target_buffer") or _coerce_mapping(state.type_facts).get("target_buffer") or "",
        "kind": _coerce_mapping(state.type_facts).get("destination_kind") or "",
        "capacity_bytes": _coerce_mapping(state.type_facts).get("capacity_bytes") or "",
    }
    return SourceToSinkTrace(
        trace_id=_stable_id(SOURCE_TO_SINK_TRACE_KIND, state.candidate_id),
        candidate_id=state.candidate_id,
        status=status,
        source_kind=str(_coerce_mapping(state.source).get("kind") or "attacker_input"),
        input_model=str(trace.get("input_model") or ""),
        entry_function=str(trace.get("entry_function") or ""),
        entry_surface_kind=str(trace.get("entry_surface_kind") or ""),
        call_path=[str(item) for item in _coerce_sequence(trace.get("call_path", []))],
        source_artifacts=_source_to_sink_source_artifacts(state, trace),
        propagation_path=propagation_path,
        argument_roles=argument_roles,
        controlled_roles=controlled_roles,
        sink={
            "name": sink.get("name") or trace.get("sink_name") or "",
            "address": (
                sink.get("operation_address")
                or _coerce_mapping(state.operation).get("address")
                or _coerce_mapping(state.location).get("address")
                or ""
            ),
            "role": _primary_sink_role(argument_roles),
        },
        sink_argument=_primary_sink_argument(argument_roles),
        destination_object=destination,
        transformations=_source_to_sink_transformations(state, trace),
        sanitizer_checks=_source_to_sink_sanitizer_checks(state, trace),
        bounds_checks=_source_to_sink_bounds_checks(state, trace),
        execution_limitations=_normalize_mapping_sequence(trace.get("execution_limitations")),
        dynamic_artifacts=dynamic_artifacts,
        confidence=_source_to_sink_confidence(status, blockers, dynamic_artifacts),
        blockers=blockers,
        override_artifact=override,
        notes="human override accepted" if override else "",
        evidence=_coerce_mapping(trace.get("evidence")),
    )


def has_reportable_source_to_sink(state: CandidateState) -> bool:
    if (
        _reportable_lifetime_process_proof(state)
        or _reportable_memory_access_process_proof(state)
        or _reportable_semantic_v2_proof(state)
        or _reportable_static_v2_proof(state)
    ):
        return True
    if _source_to_sink_override_artifact(state):
        return True
    for payload, _path in _json_artifact_payloads(_all_state_artifact_paths(state)):
        if str(payload.get("artifact_kind") or payload.get("kind") or "") != SOURCE_TO_SINK_TRACE_KIND:
            continue
        if str(payload.get("status") or "") == "override":
            return True
        if _source_to_sink_artifact_reportable(payload, state, trace_artifact_path=_path):
            return True
    return build_source_to_sink_trace(state).status == "proven"


def write_source_to_sink_trace_artifacts(
    states: Sequence[CandidateState],
    output_dir: Path,
) -> tuple[list[CandidateState], dict[str, str]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    updated: list[CandidateState] = []
    artifacts: dict[str, str] = {}
    for state in states:
        trace = build_source_to_sink_trace(state)
        path = output_dir / f"{_safe_artifact_name(state.candidate_id)}_source_to_sink_trace.json"
        payload = trace.to_dict()
        payload["artifact_kind"] = SOURCE_TO_SINK_TRACE_KIND
        path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        artifacts[state.candidate_id] = str(path)
        updated.append(
            state.with_updates(
                validation_artifacts=_dedupe_strings([*state.validation_artifacts, str(path)])
            )
        )
    return updated, artifacts


def build_bug_bounty_evidence(state: CandidateState) -> BugBountyEvidence:
    """Normalize report evidence from candidate, trace, replay, and proof artifacts."""

    trace = build_source_to_sink_trace(state)
    payloads = _json_artifact_payloads(_all_state_artifact_paths(state))
    request_payload, request_path = _first_named_payload(payloads, "request.json")
    result_payload, result_path = _first_replay_result_payload(payloads, state.candidate_id)
    memory_proof, memory_proof_path = _first_process_memory_proof(payloads, state)
    semantic_observation, semantic_observation_path = _first_semantic_observation(payloads, state)
    semantic_proof = _reportable_semantic_v2_proof(state)
    static_proof = _reportable_static_v2_proof(state)
    limitations = _bug_bounty_limitations(
        state,
        trace=trace,
        request_payload=request_payload,
        result_payload=result_payload,
        memory_proof=memory_proof,
        semantic_observation=semantic_observation,
    )
    status = "report_ready" if not limitations else "blocked"
    artifact_refs = _dedupe_strings(
        [
            *trace.dynamic_artifacts,
            request_path,
            result_path,
            memory_proof_path,
            semantic_observation_path,
        ]
    )
    return BugBountyEvidence(
        evidence_id=_stable_id(BUG_BOUNTY_EVIDENCE_KIND, state.candidate_id),
        candidate_id=state.candidate_id,
        status=status,
        vulnerability_class=state.vulnerability_type,
        target_identity=_bug_bounty_target_identity(state),
        attacker_input_surface=_bug_bounty_input_surface(trace),
        concrete_poc=_bug_bounty_concrete_poc(
            request_payload,
            result_payload,
            memory_proof,
            semantic_proof,
        ),
        source_to_sink_trace=trace.to_dict(),
        sink_effect_proof=_bug_bounty_sink_effect_proof(
            state,
            memory_proof,
            semantic_observation,
            static_proof,
        ),
        replay=_bug_bounty_replay(request_payload, request_path, result_payload, result_path),
        observed_result=_bug_bounty_observed_result(result_payload, memory_proof, semantic_observation),
        limitations=limitations,
        artifact_refs=artifact_refs,
    )


def has_reportable_bug_bounty_evidence(state: CandidateState) -> bool:
    return build_bug_bounty_evidence(state).status == "report_ready"


def write_bug_bounty_evidence_artifacts(
    states: Sequence[CandidateState],
    output_dir: Path,
) -> tuple[list[CandidateState], dict[str, str]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    updated: list[CandidateState] = []
    artifacts: dict[str, str] = {}
    for state in states:
        evidence = build_bug_bounty_evidence(state)
        path = output_dir / f"{_safe_artifact_name(state.candidate_id)}_bug_bounty_evidence.json"
        path.write_text(json.dumps(evidence.to_dict(), indent=2, sort_keys=True))
        artifacts[state.candidate_id] = str(path)
        updated.append(
            state.with_updates(
                validation_artifacts=_dedupe_strings([*state.validation_artifacts, str(path)])
            )
        )
    return updated, artifacts


def _state_source_to_sink_trace(state: CandidateState) -> dict[str, Any]:
    facts = _coerce_mapping(state.type_facts)
    for value in (
        facts.get("source_to_sink_trace"),
        _coerce_mapping(facts.get("entrypoint_derivation")).get("source_to_sink_trace"),
        _coerce_mapping(_coerce_mapping(facts.get("static_candidate")).get("entrypoint_derivation")).get("source_to_sink_trace"),
    ):
        if isinstance(value, Mapping):
            return dict(value)
    static_candidate = _coerce_mapping(facts.get("static_candidate"))
    return {
        "status": "blocked",
        "attacker_control_reaches_sink_role": False,
        "entry_function": "",
        "call_path": [],
        "input_model": "",
        "sink_name": static_candidate.get("sink") or _coerce_mapping(state.sink).get("name") or "",
        "controlled_roles": [],
        "blockers": ["missing_explicit_source_to_sink_trace"],
    }


def _source_to_sink_argument_roles(
    state: CandidateState,
    trace: Mapping[str, Any],
    *,
    dynamic_process_input_support: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    explicit = _normalize_argument_roles(_coerce_sequence(trace.get("argument_roles")))
    if explicit:
        return _apply_dynamic_process_input_role_support(explicit, dynamic_process_input_support)
    evidence = _coerce_mapping(trace.get("evidence"))
    roles = _coerce_mapping(evidence.get("source_to_write_roles"))
    if not roles:
        roles = _coerce_mapping(_coerce_mapping(trace.get("source_to_write")).get("roles"))
    if not roles:
        classification = _classification_trace(state)
        roles = _coerce_mapping(_coerce_mapping(classification.get("source_to_write")).get("roles"))
    normalized = _normalize_role_mapping(roles)
    if normalized:
        return _apply_dynamic_process_input_role_support(normalized, dynamic_process_input_support)
    fallback: list[dict[str, Any]] = []
    for item in _coerce_sequence(trace.get("controlled_roles")):
        role, _sep, classification = str(item).partition(":")
        role = role.strip()
        classification = classification.strip() or "source_controlled"
        if role:
            fallback.append(
                _normalize_role_fact(
                    role,
                    {
                        "role": role,
                        "classification": classification,
                        "controlled": classification in CONTROLLED_ROLE_CLASSIFICATIONS,
                        "complete": True,
                    },
                )
            )
    return _apply_dynamic_process_input_role_support(fallback, dynamic_process_input_support)


def _apply_dynamic_process_input_role_support(
    argument_roles: Sequence[Mapping[str, Any]],
    support: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    normalized = [dict(role) for role in argument_roles]
    if not support or str(support.get("source_expr") or "") != "optarg":
        return normalized
    updated: list[dict[str, Any]] = []
    for role in normalized:
        if str(role.get("role") or "") == "write_source" and str(role.get("expr") or "") == "optarg":
            evidence = _dedupe_strings(
                [
                    *[str(item) for item in _coerce_sequence(role.get("evidence")) if str(item)],
                    "Ghidra process proof modeled getopt option `%s` and wrote optarg"
                    % str(support.get("mode_flag") or ""),
                    str(support.get("artifact") or ""),
                ]
            )
            role = {
                **role,
                "classification": "source_controlled",
                "controlled": True,
                "complete": True,
                "evidence": evidence[:8],
            }
        updated.append(role)
    return updated


def _normalize_role_mapping(roles: Mapping[str, Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for role, fact in roles.items():
        if isinstance(fact, Mapping):
            normalized.append(_normalize_role_fact(str(role), fact))
    return normalized


def _normalize_argument_roles(values: Sequence[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, Mapping):
            continue
        role = str(value.get("role") or "")
        if role:
            normalized.append(_normalize_role_fact(role, value))
    return normalized


def _normalize_role_fact(role: str, fact: Mapping[str, Any]) -> dict[str, Any]:
    classification = str(fact.get("classification") or "unknown")
    evidence = [str(item) for item in _coerce_sequence(fact.get("evidence")) if str(item)]
    controlled = classification in CONTROLLED_ROLE_CLASSIFICATIONS
    return {
        "role": role,
        "expr": str(fact.get("expr") or ""),
        "classification": classification,
        "controlled": bool(fact.get("controlled", controlled)),
        "complete": bool(fact.get("complete", classification != "unknown")),
        "evidence": evidence[:8],
    }


def _controlled_role_labels(trace: Mapping[str, Any], argument_roles: Sequence[Mapping[str, Any]]) -> list[str]:
    labels = [
        f"{role.get('role')}:{role.get('classification')}"
        for role in argument_roles
        if bool(role.get("controlled")) and role.get("role") and role.get("classification")
    ]
    if labels:
        return _dedupe_strings([str(item) for item in labels])
    return _dedupe_strings([str(item) for item in _coerce_sequence(trace.get("controlled_roles")) if str(item)])


def _has_controlled_argument_role(argument_roles: Sequence[Mapping[str, Any]]) -> bool:
    return any(
        bool(role.get("controlled"))
        and str(role.get("classification") or "") in CONTROLLED_ROLE_CLASSIFICATIONS
        and str(role.get("role") or "") in CONTROLLED_SINK_ROLES
        for role in argument_roles
    )


def _primary_sink_role(argument_roles: Sequence[Mapping[str, Any]]) -> str:
    primary = _primary_sink_argument(argument_roles)
    return str(primary.get("role") or "write_source")


def _primary_sink_argument(argument_roles: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    for wanted in (
        "write_source",
        "read_source",
        "memory_write_source",
        "memory_read_source",
        "command_argument",
        "path_argument",
        "format_argument",
        "file_path",
        "credential_source",
        "auth_decision",
        "sink_argument",
        "write_size",
        "read_size",
        "memory_write_size",
        "memory_read_size",
        "write_offset",
        "read_offset",
        "memory_write_offset",
        "memory_read_offset",
        "destination_pointer",
    ):
        for role in argument_roles:
            if str(role.get("role") or "") == wanted and bool(role.get("controlled")):
                return dict(role)
    return dict(argument_roles[0]) if argument_roles else {}


def _source_to_sink_propagation_path(trace: Mapping[str, Any]) -> list[dict[str, Any]]:
    explicit = _normalize_mapping_sequence(trace.get("propagation_path"))
    if explicit:
        return explicit
    call_path = [str(item) for item in _coerce_sequence(trace.get("call_path")) if str(item)]
    result: list[dict[str, Any]] = []
    for index, function in enumerate(call_path):
        if index == 0:
            role = "entry"
        elif index == len(call_path) - 1:
            role = "sink_function"
        else:
            role = "intermediate"
        result.append({"kind": "function", "function": function, "index": index, "role": role})
    return result


def _source_to_sink_source_artifacts(
    state: CandidateState,
    trace: Mapping[str, Any],
) -> list[dict[str, Any]]:
    explicit = _normalize_mapping_sequence(trace.get("source_artifacts"))
    if explicit:
        return explicit
    artifacts: list[dict[str, Any]] = []
    evidence = _coerce_mapping(trace.get("evidence"))
    for observation in _coerce_sequence(evidence.get("input_observations")):
        if isinstance(observation, Mapping):
            artifacts.append({"kind": "input_observation", **dict(observation)})
    for item in _coerce_sequence(_coerce_mapping(state.source).get("evidence")):
        text = str(item or "")
        if text:
            artifacts.append({"kind": "state_source_evidence", "evidence": text})
    return artifacts[:12]


def _source_to_sink_transformations(
    state: CandidateState,
    trace: Mapping[str, Any],
) -> list[dict[str, Any]]:
    explicit = _normalize_mapping_sequence(trace.get("transformations"))
    if explicit:
        return explicit
    classification = _classification_trace(state)
    result: list[dict[str, Any]] = []
    for key, kind in (("aliases", "alias"), ("summaries", "summary"), ("source_flow", "source_flow")):
        for item in _coerce_sequence(classification.get(key)):
            text = str(item or "")
            if text:
                result.append({"kind": kind, "evidence": text})
    return result[:12]


def _source_to_sink_sanitizer_checks(
    state: CandidateState,
    trace: Mapping[str, Any],
) -> list[dict[str, Any]]:
    explicit = _normalize_mapping_sequence(trace.get("sanitizer_checks"))
    if explicit:
        return explicit
    classification = _classification_trace(state)
    facts = _coerce_mapping(state.type_facts)
    result: list[dict[str, Any]] = []
    for safety in (
        _coerce_mapping(trace.get("safety_result")),
        _coerce_mapping(classification.get("safety_result")),
        _coerce_mapping(facts.get("safety_result")),
    ):
        if safety:
            result.append({"kind": "safety_result", **safety})
            break
    guards = _coerce_mapping(classification.get("guards"))
    for status in ("accepted", "rejected"):
        for guard in _coerce_sequence(guards.get(status)):
            text = str(guard or "")
            if text:
                result.append({"kind": "guard", "status": status, "condition": text})
    return result[:12]


def _source_to_sink_bounds_checks(
    state: CandidateState,
    trace: Mapping[str, Any],
) -> list[dict[str, Any]]:
    explicit = _normalize_mapping_sequence(trace.get("bounds_checks"))
    if explicit:
        return explicit
    classification = _classification_trace(state)
    result: list[dict[str, Any]] = []
    bounds = _coerce_mapping(classification.get("bounds"))
    for status in ("accepted", "rejected"):
        for item in _coerce_sequence(bounds.get(status)):
            if isinstance(item, Mapping):
                result.append({"kind": "bound", "status": status, **dict(item)})
            elif str(item or ""):
                result.append({"kind": "bound", "status": status, "relation": str(item)})
    facts = _coerce_mapping(state.type_facts)
    for row in _coerce_sequence(facts.get("range_table")):
        if isinstance(row, Mapping):
            result.append({"kind": "range", **dict(row)})
    return result[:12]


def _source_to_sink_confidence(
    status: str,
    blockers: Sequence[str],
    dynamic_artifacts: Sequence[str] = (),
) -> str:
    if status == "override":
        return "human_override"
    if status == "proven":
        return "proven"
    if dynamic_artifacts:
        return "replay_observed"
    if set(str(item) for item in blockers) == {"boundary_replay_missing"}:
        return "partial"
    if blockers:
        return "blocked"
    return "partial"


def _source_to_sink_artifact_reportable(
    payload: Mapping[str, Any],
    state: CandidateState,
    *,
    trace_artifact_path: str = "",
) -> bool:
    if str(payload.get("status") or "") != "proven":
        return False
    roles = _normalize_argument_roles(_coerce_sequence(payload.get("argument_roles")))
    if not roles:
        roles = [
            _normalize_role_fact(
                str(item).partition(":")[0],
                {
                    "classification": str(item).partition(":")[2] or "source_controlled",
                    "complete": True,
                },
            )
            for item in _coerce_sequence(payload.get("controlled_roles"))
            if str(item).partition(":")[0]
        ]
    if _reportable_lifetime_process_proof(state) or _reportable_memory_access_process_proof(state):
        return (
            bool(_source_to_sink_propagation_path(payload))
            and str(payload.get("input_model") or "") in PROCESS_INPUT_MODELS
            and _dynamic_artifacts_are_currently_reportable(payload, state, trace_artifact_path=trace_artifact_path)
        )
    return (
        _has_controlled_argument_role(roles)
        and bool(_source_to_sink_propagation_path(payload))
        and str(payload.get("input_model") or "") in PROCESS_INPUT_MODELS
        and _dynamic_artifacts_are_currently_reportable(payload, state, trace_artifact_path=trace_artifact_path)
    )


def _dynamic_artifacts_are_currently_reportable(
    payload: Mapping[str, Any],
    state: CandidateState,
    *,
    trace_artifact_path: str = "",
) -> bool:
    raw_dynamic = [str(item) for item in _coerce_sequence(payload.get("dynamic_artifacts")) if str(item)]
    if not raw_dynamic:
        return False
    valid = {_canonical_artifact_path(path) for path in _boundary_replay_artifacts(state)}
    if not valid:
        return False
    trace_dir = Path(trace_artifact_path).parent if trace_artifact_path else None
    for raw in raw_dynamic:
        for candidate in _artifact_path_candidates(raw, trace_dir):
            if _canonical_artifact_path(candidate) in valid:
                return True
    return False


def _artifact_path_candidates(raw: str, base_dir: Path | None) -> list[Path]:
    path = Path(raw)
    candidates = [path]
    if not path.is_absolute():
        if base_dir is not None:
            candidates.append(base_dir / path)
        candidates.append(Path.cwd() / path)
    return candidates


def _canonical_artifact_path(path: Path | str) -> str:
    candidate = Path(path)
    try:
        return str(candidate.resolve())
    except OSError:
        return str(candidate.absolute())


def _classification_trace(state: CandidateState) -> dict[str, Any]:
    facts = _coerce_mapping(state.type_facts)
    trace = facts.get("classification_trace")
    if isinstance(trace, Mapping):
        return dict(trace)
    static_candidate = _coerce_mapping(facts.get("static_candidate"))
    trace = static_candidate.get("classification_trace")
    return dict(trace) if isinstance(trace, Mapping) else {}


def _normalize_mapping_sequence(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in _coerce_sequence(value) if isinstance(item, Mapping)]


def _source_to_sink_blockers(
    trace: Mapping[str, Any],
    dynamic_artifacts: Sequence[str],
    *,
    argument_roles: Sequence[Mapping[str, Any]],
    propagation_path: Sequence[Mapping[str, Any]],
    dynamic_process_input_support: Mapping[str, Any] | None = None,
) -> list[str]:
    blockers: list[str] = []
    dynamic_role_supported = bool(dynamic_process_input_support) and _has_controlled_argument_role(argument_roles)
    if not trace:
        blockers.append("missing_source_to_sink_trace")
    if str(trace.get("status") or "") != "complete" and not dynamic_role_supported:
        blockers.append("source_to_sink_trace_incomplete")
    if not bool(trace.get("attacker_control_reaches_sink_role", False)) and not dynamic_role_supported:
        blockers.append("attacker_control_not_linked_to_sink_role")
    if not _has_controlled_argument_role(argument_roles):
        blockers.append("missing_controlled_argument_role")
    if not propagation_path:
        blockers.append("missing_source_to_sink_propagation_path")
    input_model = str(trace.get("input_model") or "")
    if input_model not in PROCESS_INPUT_MODELS:
        blockers.append("unsupported_or_missing_process_input_model")
    for item in _coerce_sequence(trace.get("blockers", [])):
        blocker = str(item)
        if dynamic_role_supported and blocker in {"source_to_write_roles_incomplete", "no_controlled_sink_role"}:
            continue
        if blocker:
            blockers.append(blocker)
    if not dynamic_artifacts:
        blockers.append("boundary_replay_missing")
    return _dedupe_strings(blockers)


def _dynamic_process_input_role_support(state: CandidateState) -> dict[str, Any]:
    for payload, path in _json_artifact_payloads(_all_state_artifact_paths(state)):
        if str(payload.get("candidate_id") or "") != state.candidate_id:
            continue
        view = DynamicProofView(payload)
        if not view.is_memory_safety_proof(
            scope="process_entrypoint",
            require_setup=True,
            require_sink=False,
        ):
            continue
        process_replay = view.process_replay
        process_setup = view.process_input_setup
        if str(process_setup.get("process_input_source") or "") != "inferred_from_optarg_sink":
            continue
        evidence = _coerce_mapping(process_setup.get("process_input_evidence"))
        if str(evidence.get("argv_seed_reason") or "") != "optarg_option_argument":
            continue
        mode_flag = str(evidence.get("mode_flag") or "")
        for call in _coerce_sequence(process_replay.get("modeled_runtime_calls")):
            if not isinstance(call, Mapping):
                continue
            if str(call.get("function_model") or "") not in {"getopt", "getopt_long", "getopt_long_only"}:
                continue
            if mode_flag and str(call.get("option") or "") != mode_flag:
                continue
            if str(call.get("optarg_write_status") or "") != "written":
                continue
            return {
                "source_expr": "optarg",
                "mode_flag": mode_flag,
                "artifact": path,
            }
    return {}


def _boundary_replay_artifacts(state: CandidateState) -> list[str]:
    artifacts: list[str] = []
    backend_v2 = _reportable_lifetime_v2_proof(state) or _reportable_memory_access_v2_proof(state)
    if backend_v2:
        artifacts.extend(
            str(item)
            for item in _coerce_sequence(backend_v2.get("artifact_refs"))
            if str(item) and Path(str(item)).is_file()
        )
    requires_dynamic_memory_proof = state.vulnerability_type in MEMORY_CORRUPTION_TYPES
    for payload, path in _json_artifact_payloads(_all_state_artifact_paths(state)):
        ghidra_proof = _ghidra_dynamic_proof_payload(payload)
        if ghidra_proof:
            if _ghidra_dynamic_proof_reportable(ghidra_proof, state):
                artifacts.append(path)
            continue
        if _concolic_overflow_witness_reportable(payload, state):
            artifacts.append(path)
            continue
        if requires_dynamic_memory_proof:
            continue
        if "candidate_id" in payload and "result" in payload:
            mode = str(payload.get("mode") or "")
            if (
                str(payload.get("result") or "") == "confirmed"
                and mode in PROCESS_REPLAY_MODES
                and bool(payload.get("sink_reached"))
                and bool(payload.get("bug_observed"))
            ):
                artifacts.append(path)
                artifacts.extend(_observed_semantic_dynamic_artifacts(payload, base_path=path))
    return _dedupe_strings(artifacts)


def _observed_semantic_dynamic_artifacts(payload: Mapping[str, Any], *, base_path: str) -> list[str]:
    artifacts: list[str] = []
    base_dir = Path(base_path).parent
    for raw in _coerce_sequence(payload.get("artifacts")):
        path = Path(str(raw))
        if not path.is_absolute():
            path = base_dir / path
        if not path.name.startswith("dynamic_") or not path.name.endswith("_observation.json"):
            continue
        if not path.exists():
            continue
        try:
            observation = json.loads(path.read_text() or "{}")
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(observation, Mapping):
            continue
        if not bool(observation.get("bug_observed", False)):
            continue
        status = str(observation.get("status") or "")
        if status.endswith("_observed"):
            artifacts.append(str(path))
    return artifacts


def _concolic_overflow_witness_reportable(payload: Mapping[str, Any], state: CandidateState) -> bool:
    # Concolic reachability alone is useful proof-stage evidence, but the
    # bug-bounty report gate requires process-scope Ghidra memory proof.
    if state.vulnerability_type in MEMORY_CORRUPTION_TYPES:
        return False
    if state.vulnerability_type not in {"stack_overflow", "heap_overflow", "out_of_bounds_write"}:
        return False
    if str(payload.get("candidate_id") or "") != state.candidate_id:
        return False
    if str(payload.get("concolic_verdict") or "") != "overflow_witness":
        return False
    request = _coerce_mapping(payload.get("request"))
    if str(request.get("input_model") or "") not in PROCESS_INPUT_MODELS:
        return False
    if _state_uses_unmodeled_optarg_source(state):
        return False
    replay = _coerce_mapping(payload.get("replay_result"))
    concrete = _coerce_mapping(replay.get("concrete_angr_replay"))
    return str(concrete.get("status") or "") == "replayed" and bool(payload.get("sink_reached", False))


def _state_uses_unmodeled_optarg_source(state: CandidateState) -> bool:
    trace = _state_source_to_sink_trace(state)
    for role in _normalize_argument_roles(_coerce_sequence(trace.get("argument_roles"))):
        if str(role.get("role") or "") == "write_source" and str(role.get("expr") or "").strip() == "optarg":
            return True
    static_candidate = _coerce_mapping(_coerce_mapping(state.type_facts).get("static_candidate"))
    return "optarg" in str(static_candidate.get("line_text") or "")


def _ghidra_dynamic_proof_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    return first_ghidra_dynamic_proof(payload)


def _ghidra_dynamic_proof_reportable(payload: Mapping[str, Any], state: CandidateState) -> bool:
    view = DynamicProofView(payload)
    if view.access_kind == "lifetime":
        violation = _coerce_mapping(payload.get("lifetime_violation"))
        native = _coerce_mapping(payload.get("native_replay"))
        exact_invalid_release = state.vulnerability_type != "invalid_free" or (
            str(violation.get("reason") or "") == "release_address_is_not_object_base"
            and bool(violation.get("object_id"))
            and str(violation.get("address") or "") != str(violation.get("object_base_address") or "")
        )
        return bool(
            str(violation.get("vulnerability") or "") == state.vulnerability_type
            and exact_invalid_release
            and native.get("lifetime_event_observed") is True
            and view.is_memory_safety_proof(scope="process_entrypoint", require_setup=True, require_sink=True)
        )
    if state.vulnerability_type in MEMORY_CORRUPTION_TYPES:
        return view.is_memory_safety_proof(scope="process_entrypoint", require_setup=True, require_sink=True)
    if not view.is_memory_safety_proof(require_setup=True, require_sink=True):
        return False
    if view.scope == "process_entrypoint":
        return True
    if view.scope != "function_harness":
        return False
    return _ghidra_function_harness_proof_reportable(
        payload,
        state,
        view.process_input_setup,
        view.status,
    )


def _reportable_lifetime_process_proof(state: CandidateState) -> dict[str, Any]:
    if state.vulnerability_type not in vulnerability_types_for_backend("memory_lifetime"):
        return {}
    v2 = _reportable_lifetime_v2_proof(state)
    if v2:
        return _dynamic_lifetime_proof_from_v2(state, v2)
    for payload, _path in _json_artifact_payloads(_all_state_artifact_paths(state)):
        proof = _ghidra_dynamic_proof_payload(payload)
        if proof and _ghidra_dynamic_proof_reportable(proof, state):
            return proof
    return {}


def _reportable_lifetime_v2_proof(state: CandidateState) -> dict[str, Any]:
    proof = _coerce_mapping(_coerce_mapping(state.type_facts).get("proof_result"))
    lifetime = _coerce_mapping(proof.get("lifetime_violation"))
    process_setup = _coerce_mapping(proof.get("process_setup"))
    native = _coerce_mapping(proof.get("native_replay"))
    native_trace = _coerce_mapping(native.get("exact_operation_trace"))
    if not (
        int(proof.get("schema_version") or 0) == 2
        and proof.get("backend") == "memory_lifetime"
        and proof.get("candidate_id") == state.candidate_id
        and proof.get("status") == "proven"
        and proof.get("scope") == "process_entrypoint"
        and proof.get("exact_operation_reached") is True
        and lifetime.get("same_resource") is True
        and lifetime.get("violation") is True
        and lifetime.get("events")
        and process_setup.get("status") == "configured"
        and native_trace.get("status") == "reached"
    ):
        return {}
    return dict(proof)


def _dynamic_lifetime_proof_from_v2(state: CandidateState, proof: Mapping[str, Any]) -> dict[str, Any]:
    operation_address = str(
        _coerce_mapping(state.operation).get("address")
        or _coerce_mapping(state.sink).get("operation_address")
        or ""
    )
    return {
        "schema_version": 2,
        "status": "lifetime_violation_proven",
        "proof_scope": "process_entrypoint",
        "sink_reached": True,
        "exact_sink_reached": True,
        "sink_address": operation_address,
        "process_input_setup": dict(_coerce_mapping(proof.get("process_setup"))),
        "process_replay": {"status": "reached", "reached_target": True},
        "native_replay": dict(_coerce_mapping(proof.get("native_replay"))),
        "lifetime_violation": dict(_coerce_mapping(proof.get("lifetime_violation"))),
        "artifact_refs": [str(item) for item in _coerce_sequence(proof.get("artifact_refs")) if str(item)],
    }


def _reportable_memory_access_process_proof(state: CandidateState) -> dict[str, Any]:
    proof = _reportable_memory_access_v2_proof(state)
    return _dynamic_memory_access_proof_from_v2(state, proof) if proof else {}


def _reportable_memory_access_v2_proof(state: CandidateState) -> dict[str, Any]:
    proof = _coerce_mapping(_coerce_mapping(state.type_facts).get("proof_result"))
    memory = _coerce_mapping(proof.get("memory_access"))
    process_setup = _coerce_mapping(proof.get("process_setup"))
    native = _coerce_mapping(proof.get("native_replay"))
    native_trace = _coerce_mapping(native.get("exact_operation_trace"))
    if state.vulnerability_type == "null_pointer_dereference":
        violation = memory.get("pointer_value") == 0 and memory.get("accessed") is True
    elif state.vulnerability_type == "uninitialized_memory_use":
        violation = bool(
            memory.get("definedness") == "undefined"
            and memory.get("read") is True
            and memory.get("undefined_byte_ranges")
        )
    elif state.vulnerability_type == "overlapping_memory_copy":
        violation = memory.get("ranges_overlap") is True and memory.get("operation") == "memcpy"
    else:
        violation = bool(
            memory.get("same_object") is True
            and memory.get("object_range")
            and memory.get("access_range")
            and memory.get("out_of_bounds") is True
        )
    if not (
        int(proof.get("schema_version") or 0) == 2
        and proof.get("backend") == "memory_access"
        and proof.get("candidate_id") == state.candidate_id
        and proof.get("status") == "proven"
        and proof.get("scope") == "process_entrypoint"
        and proof.get("exact_operation_reached") is True
        and violation
        and process_setup.get("status") == "configured"
        and native_trace.get("status") == "reached"
    ):
        return {}
    return dict(proof)


def _reportable_semantic_v2_proof(state: CandidateState) -> dict[str, Any]:
    if state.vulnerability_type not in SEMANTIC_PROCESS_TYPES:
        return {}
    proof = _coerce_mapping(_coerce_mapping(state.type_facts).get("proof_result"))
    observation = _coerce_mapping(proof.get("effect_observation"))
    process_setup = _coerce_mapping(proof.get("process_setup"))
    native = _coerce_mapping(proof.get("native_replay"))
    spec = VULNERABILITY_SPECS.get(state.vulnerability_type)
    if not (
        spec
        and int(proof.get("schema_version") or 0) == 2
        and proof.get("backend") == "semantic_effect"
        and proof.get("candidate_id") == state.candidate_id
        and proof.get("status") == "proven"
        and proof.get("scope") == "process_entrypoint"
        and proof.get("exact_operation_reached") is True
        and process_setup.get("status") == "configured"
        and native.get("status") in {"reached", "observed"}
        and observation.get("status") == "observed"
        and observation.get("kind") == spec.effect_kind
        and observation.get("sink_address")
        and observation.get("concrete_input_fingerprint")
        and proof.get("concrete_input")
    ):
        return {}
    return dict(proof)


def _reportable_static_v2_proof(state: CandidateState) -> dict[str, Any]:
    if state.vulnerability_type not in vulnerability_types_for_backend("static_evidence"):
        return {}
    proof = _coerce_mapping(_coerce_mapping(state.type_facts).get("proof_result"))
    evidence = _coerce_mapping(proof.get("static_evidence"))
    if not (
        int(proof.get("schema_version") or 0) == 2
        and proof.get("backend") == "static_evidence"
        and proof.get("candidate_id") == state.candidate_id
        and proof.get("status") == "proven"
        and proof.get("scope") == "static"
        and proof.get("exact_operation_reached") is True
        and evidence.get("exact") is True
        and evidence.get("reachable") is True
        and (evidence.get("consumer_address") or evidence.get("observed_call"))
    ):
        return {}
    return dict(proof)


def _dynamic_memory_access_proof_from_v2(state: CandidateState, proof: Mapping[str, Any]) -> dict[str, Any]:
    operation_address = str(
        _coerce_mapping(state.operation).get("address")
        or _coerce_mapping(state.sink).get("operation_address")
        or ""
    )
    memory = _coerce_mapping(proof.get("memory_access"))
    object_range = list(_coerce_sequence(memory.get("object_range")))
    access_range = list(_coerce_sequence(memory.get("access_range")))
    capacity = (
        max(0, int(object_range[1]) - int(object_range[0]))
        if len(object_range) == 2
        else 0
    )
    oob_bytes = (
        max(0, int(access_range[1]) - int(object_range[1]))
        if len(object_range) == 2 and len(access_range) == 2
        else 0
    )
    access_kind = "read" if (
        state.vulnerability_type in {"out_of_bounds_read", "uninitialized_memory_use"}
        or (
            state.vulnerability_type == "null_pointer_dereference"
            and (
                memory.get("read") is True
                or "load" in str(memory.get("operation") or "").lower()
            )
        )
    ) else "write"
    proof_status = (
        "null_dereference_proven"
        if state.vulnerability_type == "null_pointer_dereference"
        else ("oob_read_proven" if access_kind == "read" else "oob_write_proven")
    )
    return {
        "schema_version": 2,
        "proof_kind": "schema2_native_memory_access",
        "status": proof_status,
        "proof_scope": "process_entrypoint",
        "sink_reached": True,
        "exact_sink_reached": True,
        "sink_address": operation_address,
        "process_input_setup": dict(_coerce_mapping(proof.get("process_setup"))),
        "process_replay": {"status": "reached", "reached_target": True},
        "native_replay": dict(_coerce_mapping(proof.get("native_replay"))),
        "object_identity": memory.get("object_identity", ""),
        "object_size_bytes": capacity,
        "capacity_bytes": capacity,
        "read_range" if access_kind == "read" else "write_range": access_range,
        "read_size_bytes" if access_kind == "read" else "write_size_bytes": (
            max(0, int(access_range[1]) - int(access_range[0])) if len(access_range) == 2 else 0
        ),
        "oob_bytes" if access_kind == "read" else "overflow_bytes": oob_bytes,
        "artifact_refs": [str(item) for item in _coerce_sequence(proof.get("artifact_refs")) if str(item)],
    }


def _first_named_payload(
    payloads: Sequence[tuple[dict[str, Any], str]],
    filename: str,
) -> tuple[dict[str, Any], str]:
    for payload, path in payloads:
        if Path(path).name == filename:
            return dict(payload), path
    return {}, ""


def _first_replay_result_payload(
    payloads: Sequence[tuple[dict[str, Any], str]],
    candidate_id: str,
) -> tuple[dict[str, Any], str]:
    for payload, path in payloads:
        if str(payload.get("candidate_id") or "") != candidate_id:
            continue
        if "result" in payload and "control_result" in payload:
            return dict(payload), path
    return {}, ""


def _first_process_memory_proof(
    payloads: Sequence[tuple[dict[str, Any], str]],
    state: CandidateState,
) -> tuple[dict[str, Any], str]:
    if state.vulnerability_type not in MEMORY_CORRUPTION_TYPES:
        return {}, ""
    memory_v2 = _reportable_memory_access_v2_proof(state)
    if memory_v2:
        paths = [str(item) for item in _coerce_sequence(memory_v2.get("artifact_refs")) if str(item)]
        return _dynamic_memory_access_proof_from_v2(state, memory_v2), (paths[0] if paths else "")
    lifetime_v2 = _reportable_lifetime_v2_proof(state)
    if lifetime_v2:
        paths = [str(item) for item in _coerce_sequence(lifetime_v2.get("artifact_refs")) if str(item)]
        return _dynamic_lifetime_proof_from_v2(state, lifetime_v2), (paths[0] if paths else "")
    for payload, path in payloads:
        proof = _ghidra_dynamic_proof_payload(payload)
        if not proof:
            nested = payload.get("ghidra_dynamic_proof")
            proof = dict(nested) if isinstance(nested, Mapping) else {}
        if not proof:
            continue
        view = DynamicProofView(proof)
        if view.is_memory_safety_proof(scope="process_entrypoint", require_setup=True, require_sink=True):
            return dict(proof), path
    return {}, ""


def _first_semantic_observation(
    payloads: Sequence[tuple[dict[str, Any], str]],
    state: CandidateState,
) -> tuple[dict[str, Any], str]:
    if state.vulnerability_type not in SEMANTIC_PROCESS_TYPES:
        return {}, ""
    semantic_proof = _reportable_semantic_v2_proof(state)
    if semantic_proof:
        observation = dict(_coerce_mapping(semantic_proof.get("effect_observation")))
        paths = [
            str(item)
            for item in _coerce_sequence(observation.get("artifact_refs"))
            if str(item)
        ]
        return observation, (paths[0] if paths else "")
    for payload, path in payloads:
        observation = _semantic_observation_from_payload(payload)
        if _semantic_observation_reportable(observation):
            return observation, path
    return {}, ""


def _semantic_observation_from_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(payload.get("kind") or "") in SEMANTIC_PROCESS_ORACLE_KINDS:
        return dict(payload)
    control = payload.get("control_result") if isinstance(payload.get("control_result"), Mapping) else {}
    observation = control.get("proof_observation") if isinstance(control.get("proof_observation"), Mapping) else {}
    return dict(observation) if observation else {}


def _semantic_observation_reportable(observation: Mapping[str, Any]) -> bool:
    if str(observation.get("kind") or "") not in SEMANTIC_PROCESS_ORACLE_KINDS:
        return False
    status = str(observation.get("status") or "")
    if status == "observed":
        return bool(
            observation.get("sink_address")
            and observation.get("concrete_input_fingerprint")
            and isinstance(observation.get("details"), Mapping)
        )
    return bool(observation.get("bug_observed", False)) and status.endswith("_observed")


def _bug_bounty_limitations(
    state: CandidateState,
    *,
    trace: SourceToSinkTrace,
    request_payload: Mapping[str, Any],
    result_payload: Mapping[str, Any],
    memory_proof: Mapping[str, Any],
    semantic_observation: Mapping[str, Any],
) -> list[str]:
    limitations: list[str] = []
    if trace.status not in {"proven", "override"}:
        limitations.extend(trace.blockers or ["source_to_sink_trace_not_proven"])
    if state.status not in {CandidateStatus.REPLAY_CONFIRMED.value, CandidateStatus.REPORT_READY.value}:
        limitations.append(f"candidate_status_not_replay_confirmed:{state.status}")
    if not has_reportable_source_to_sink(state):
        limitations.append("source_to_sink_replay_gate_not_satisfied")
    if state.vulnerability_type in MEMORY_CORRUPTION_TYPES:
        if not memory_proof:
            limitations.append("process_scope_ghidra_memory_proof_missing")
    elif state.vulnerability_type in SEMANTIC_PROCESS_TYPES:
        if not result_payload:
            limitations.append("process_replay_result_missing")
        if not semantic_observation:
            limitations.append("class_specific_dynamic_observation_missing")
    elif state.vulnerability_type in vulnerability_types_for_backend("static_evidence"):
        if not _reportable_static_v2_proof(state):
            limitations.append("exact_reachable_static_evidence_missing")
    else:
        limitations.append(f"unsupported_vulnerability_class:{state.vulnerability_type}")
    if (
        state.vulnerability_type not in vulnerability_types_for_backend("static_evidence")
        and not _bug_bounty_concrete_poc(
        request_payload,
        result_payload,
        memory_proof,
        _reportable_semantic_v2_proof(state),
        )
    ):
        limitations.append("concrete_poc_missing")
    return _dedupe_strings(limitations)


def _bug_bounty_target_identity(state: CandidateState) -> dict[str, Any]:
    target = dict(state.target)
    location = dict(state.location)
    return {
        key: value
        for key, value in {
            **target,
            "function_name": location.get("function_name"),
            "address": location.get("address"),
            "relative_path": location.get("relative_path"),
            "line_number": location.get("line_number"),
        }.items()
        if value not in (None, "", [], {})
    }


def _bug_bounty_input_surface(trace: SourceToSinkTrace) -> dict[str, Any]:
    return {
        key: value
        for key, value in {
            "source_kind": trace.source_kind,
            "input_model": trace.input_model,
            "entry_function": trace.entry_function,
            "entry_surface_kind": trace.entry_surface_kind,
            "call_path": list(trace.call_path),
            "controlled_roles": list(trace.controlled_roles),
            "source_artifacts": [dict(item) for item in trace.source_artifacts],
            "sink_argument": dict(trace.sink_argument),
        }.items()
        if value not in (None, "", [], {})
    }


def _bug_bounty_concrete_poc(
    request_payload: Mapping[str, Any],
    result_payload: Mapping[str, Any],
    memory_proof: Mapping[str, Any],
    semantic_proof: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    semantic_proof = semantic_proof or {}
    semantic_input = semantic_proof.get("concrete_input")
    if isinstance(semantic_input, Mapping) and semantic_input:
        return {
            "source": "schema2_semantic_proof.concrete_input",
            **_bounded_mapping(semantic_input),
        }
    process_setup = memory_proof.get("process_input_setup")
    if isinstance(process_setup, Mapping) and process_setup.get("input_model"):
        concrete_process_input = _concrete_process_input_from_setup(process_setup)
        if concrete_process_input:
            return {
                "source": "ghidra_dynamic_proof.process_input_setup",
                **concrete_process_input,
            }
    request_input = request_payload.get("input") if isinstance(request_payload.get("input"), Mapping) else {}
    if request_input:
        return {"source": "replay_request", **_bounded_mapping(request_input)}
    control = result_payload.get("control_result") if isinstance(result_payload.get("control_result"), Mapping) else {}
    for key in ("concrete_input", "witness", "input"):
        value = control.get(key) if isinstance(control, Mapping) else None
        if isinstance(value, Mapping):
            return {"source": f"replay_result.{key}", **_bounded_mapping(value)}
    for key in ("concrete_input", "witness", "input"):
        value = memory_proof.get(key)
        if isinstance(value, Mapping):
            return {"source": f"ghidra_dynamic_proof.{key}", **_bounded_mapping(value)}
    if isinstance(process_setup, Mapping) and process_setup.get("input_model"):
        return {
            "source": "ghidra_dynamic_proof.process_input_setup",
            **_bounded_mapping(process_setup),
        }
    return {}


def _concrete_process_input_from_setup(process_setup: Mapping[str, Any]) -> dict[str, Any]:
    input_model = str(process_setup.get("input_model") or "")
    if input_model not in PROCESS_INPUT_MODELS:
        return {}
    payload = {
        key: process_setup.get(key)
        for key in (
            "input_model",
            "stdin_input_hex",
            "file_input_hex",
            "file_name",
            "env_name",
            "env_values",
            "argv_values",
            "process_input_source",
            "process_input_evidence",
        )
        if process_setup.get(key) not in (None, "", [], {})
    }
    if not any(key in payload for key in ("stdin_input_hex", "file_input_hex", "env_values", "argv_values")):
        concrete_input_hex = str(process_setup.get("concrete_input_hex") or "")
        if concrete_input_hex:
            payload["concrete_input_hex"] = concrete_input_hex
    return _bounded_mapping(payload) if len(payload) > 1 else {}


def _bug_bounty_sink_effect_proof(
    state: CandidateState,
    memory_proof: Mapping[str, Any],
    semantic_observation: Mapping[str, Any],
    static_proof: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    static_proof = static_proof or {}
    if memory_proof:
        access = DYNAMIC_MEMORY_ACCESS[DynamicProofView(memory_proof).access_kind or "write"]
        return {
            "proof_kind": "ghidra_dynamic_memory",
            "status": str(memory_proof.get("status") or ""),
            "proof_scope": str(memory_proof.get("proof_scope") or ""),
            "sink_address": str(memory_proof.get("sink_address") or ""),
            "exact_sink_reached": bool(memory_proof.get("exact_sink_reached", False)),
            "capacity_bytes": memory_proof.get("capacity_bytes", ""),
            str(access["size_field"]): memory_proof.get(str(access["size_field"]), ""),
            str(access["byte_field"]): memory_proof.get(str(access["byte_field"]), ""),
        }
    if semantic_observation:
        return {
            "proof_kind": "semantic_process_observation",
            "kind": str(semantic_observation.get("kind") or ""),
            "status": str(semantic_observation.get("status") or ""),
            "bug_observed": bool(semantic_observation.get("bug_observed", False)),
            "vulnerability_class": state.vulnerability_type,
        }
    if static_proof:
        evidence = _coerce_mapping(static_proof.get("static_evidence"))
        return {
            "proof_kind": "schema2_static_evidence",
            "status": "proven",
            "proof_scope": "static",
            "exact": True,
            "reachable": True,
            "consumer_address": str(evidence.get("consumer_address") or ""),
            "observed_call": str(evidence.get("observed_call") or ""),
            "literal_fingerprint": str(evidence.get("literal_fingerprint") or ""),
        }
    return {}


def _bug_bounty_replay(
    request_payload: Mapping[str, Any],
    request_path: str,
    result_payload: Mapping[str, Any],
    result_path: str,
) -> dict[str, Any]:
    setup = request_payload.get("setup") if isinstance(request_payload.get("setup"), Mapping) else {}
    replay: dict[str, Any] = {
        "mode": result_payload.get("mode") or request_payload.get("mode") or "",
        "request_artifact": request_path,
        "result_artifact": result_path,
    }
    binary_path = setup.get("binary_path")
    if binary_path:
        replay["binary_path"] = binary_path
    if request_payload:
        replay["request"] = _bounded_mapping(request_payload)
    return {key: value for key, value in replay.items() if value not in (None, "", [], {})}


def _bug_bounty_observed_result(
    result_payload: Mapping[str, Any],
    memory_proof: Mapping[str, Any],
    semantic_observation: Mapping[str, Any],
) -> dict[str, Any]:
    observed = {
        "replay_result": result_payload.get("result", ""),
        "sink_reached": result_payload.get("sink_reached", ""),
        "bug_observed": result_payload.get("bug_observed", ""),
        "crash_observed": result_payload.get("crash_observed", ""),
    }
    control = result_payload.get("control_result") if isinstance(result_payload.get("control_result"), Mapping) else {}
    for key in ("stdout", "stderr", "socket_response", "http_response", "syslog", "reason"):
        value = control.get(key) if isinstance(control, Mapping) else None
        if value not in (None, ""):
            observed[key] = str(value)[-1000:]
    if memory_proof:
        observed["ghidra_dynamic_proof_status"] = str(memory_proof.get("status") or "")
        observed["proof_scope"] = str(memory_proof.get("proof_scope") or "")
    if semantic_observation:
        observed["dynamic_observation_kind"] = str(semantic_observation.get("kind") or "")
        observed["dynamic_observation_status"] = str(semantic_observation.get("status") or "")
    return {key: value for key, value in observed.items() if value not in (None, "", [], {})}


def _bounded_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = _json_safe_mapping(value)
    text = json.dumps(payload, sort_keys=True, default=str)
    if len(text) <= 4000:
        return payload
    return {"truncated": True, "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()}


def _ghidra_function_harness_proof_reportable(
    payload: Mapping[str, Any],
    state: CandidateState,
    setup: Mapping[str, Any],
    status: str,
) -> bool:
    if str(setup.get("status") or "") != "configured":
        return False
    if str(setup.get("input_model") or "") != "function_harness":
        return False
    trace = _classification_trace(state)
    static_candidate = _coerce_mapping(_coerce_mapping(state.type_facts).get("static_candidate"))
    sink_name = str(_coerce_mapping(state.sink).get("name") or static_candidate.get("sink") or "")
    destination_kind = str(
        _coerce_mapping(state.type_facts).get("destination_kind")
        or static_candidate.get("destination_kind")
        or _coerce_mapping(trace.get("object_resolution")).get("destination_kind")
        or ""
    )
    if not sink_name:
        return False
    policy = FUNCTION_HARNESS_PROOF_REPORT_POLICY.get(status)
    if not policy:
        return False
    if state.vulnerability_type not in policy["vulnerability_types"]:
        return False
    if destination_kind not in policy["destinations"]:
        return False
    if _coerce_int(payload.get(str(policy["byte_field"]))) <= 0:
        return False
    if status == "oob_read_proven":
        if destination_kind == "source_buffer":
            return sink_name == "cursor_limit_read" and bool(_coerce_mapping(trace.get("cursor_limit_read")))
        return True
    return True


def _source_to_sink_override_artifact(state: CandidateState) -> str:
    for payload, path in _json_artifact_payloads(_all_state_artifact_paths(state)):
        kind = str(payload.get("artifact_kind") or payload.get("kind") or "")
        if kind == SOURCE_TO_SINK_OVERRIDE_KIND and str(payload.get("status") or "") == "approved":
            return path
    return ""


def _json_artifact_payloads(paths: Sequence[str]) -> list[tuple[dict[str, Any], str]]:
    payloads: list[tuple[dict[str, Any], str]] = []
    for raw in paths:
        path = Path(raw)
        if not path.exists() or not path.is_file() or path.suffix.lower() != ".json":
            continue
        try:
            payload = json.loads(path.read_text() or "{}")
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, Mapping):
            payloads.append((dict(payload), str(path)))
    return payloads


def _all_state_artifact_paths(state: CandidateState) -> list[str]:
    paths = [*state.validation_artifacts, *state.replay_artifacts, *state.report_artifacts]
    for raw in list(paths):
        parent = Path(raw).parent
        for sibling_name in ("result.json", "request.json"):
            sibling = parent / sibling_name
            if sibling.exists():
                paths.append(str(sibling))
        path = Path(raw)
        if path.exists() and path.is_file() and path.suffix.lower() == ".json":
            try:
                payload = json.loads(path.read_text() or "{}")
            except (OSError, json.JSONDecodeError):
                payload = {}
            if isinstance(payload, Mapping):
                for item in _coerce_sequence(payload.get("artifacts")):
                    artifact_path = Path(str(item))
                    if not artifact_path.is_absolute():
                        artifact_path = parent / artifact_path
                    paths.append(str(artifact_path))
    return _dedupe_strings(paths)


def _safe_artifact_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in str(value))[:120] or "candidate"


def _dedupe_strings(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _stable_id(*parts: Any) -> str:
    raw = "|".join(str(part) for part in parts if part is not None)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def _coerce_sequence(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _coerce_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _coerce_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _json_safe_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(dict(value), default=str))
