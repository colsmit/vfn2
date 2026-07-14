"""Static candidate extraction for stack buffer overflow analysis."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from typing import AbstractSet, Any, Iterable, Mapping, MutableMapping, Optional, Sequence

from binary_agent.analysis.callgraph import CallGraph, build_call_graph, load_cached_call_graph
from binary_agent.analysis.stack import _format_offset, normalize_stack_regions
from binary_agent.analysis.memory_sets import (
    MemObject,
    OffsetSet,
    WriteSet,
    classify_write,
    offset_set_from_expr,
)
from binary_agent.analysis.extractors import (
    MemoryOperationSpecSet,
    candidate_to_resolved_write,
    candidate_to_write_fact,
    classified_trace_for_candidate,
    load_memory_operation_specs,
)
from binary_agent.analysis.fact_enrichment import build_enriched_facts
from binary_agent.analysis.facts import (
    CapacityModel,
    ClassifiedFinding,
    FunctionSummary,
    MemObject as FactMemObject,
    ResolvedWrite,
    SuppressedFinding,
    WriteFact,
)
from binary_agent.analysis.policy import build_policy_views, triage_tier_for_candidate
from binary_agent.analysis.source_taint import (
    IdentifierTaint,
    SourceTaintRules,
    identifier_taint_before_line,
    trace_expression_taint,
)
from binary_agent.analysis.confirmation import (
    CandidateConfirmation,
    load_candidate_confirmations,
    write_evidence_packs,
)
from binary_agent.analysis.concolic import load_concolic_dynamic_proofs
from binary_agent.data.manifest import Manifest
from binary_agent.ingest.loader import FunctionNode, load_function_nodes
from binary_agent.reporting import AnalysisReport, ReportConfig, build_vulnerability_reports
from binary_agent.utils.time import utc_timestamp
from binary_agent.utils.thread_scan import find_thread_start_functions


CANDIDATE_ARTIFACT = "candidate_findings.json"
WRITE_FACT_ARTIFACT = "write_facts.json"
RESOLVED_WRITE_ARTIFACT = "resolved_writes.json"
FUNCTION_SUMMARY_ARTIFACT = "function_summaries.json"
CONFIRMATION_CANDIDATE_ARTIFACT = "confirmation_findings.json"
SUPPRESSED_FINDING_ARTIFACT = "suppressed_findings.json"
ANALYSIS_CACHE_VERSION = "program_index_v11_literal_taint_output_signatures_partial_stack_terminal_cfg_operation_specs_v12"
STALE_STAGE_ARTIFACTS = (
    "scout_findings.json",
    "triage_findings.json",
    "verify_findings.json",
    "llm_cache.json",
)

ENTRY_NAMES = ("main", "_start", "entry", "WinMain", "wmain")
SOURCE_CALLS = {
    "flash_area_read",
    "fgetc",
    "fread",
    "fgets",
    "getc",
    "getchar",
    "gets",
    "recv",
    "recvfrom",
    "read",
    "scanf",
    "fscanf",
    "sscanf",
    "getenv",
}
SOURCE_TOKENS = ("argv", "argc")
SOURCE_TO_WRITE_ROLES = (
    "write_source",
    "write_size",
    "write_offset",
    "destination_pointer",
)
TAINT_CLASSIFICATIONS = {
    "source_controlled",
    "parameter_controlled",
    "internal_local",
    "constant_or_literal",
    "unknown",
}
TAINT_CLASSIFICATION_PRIORITY = (
    "source_controlled",
    "parameter_controlled",
    "unknown",
    "internal_local",
    "constant_or_literal",
)
CONTROLLED_TAINT_CLASSES = {"source_controlled", "parameter_controlled"}
GHIDRA_METADATA_CAPACITY_SOURCES = {
    "ghidra_data_reference",
    "ghidra_global_ref",
    "ghidra_stack_object",
    "ghidra_static_ref",
    "ghidra_tls_ref",
    "inferred_stack_aggregate_extent",
    "stack metadata",
    "stack_region",
}
CONFIRMATION_REVIEW_RULES = (
    "exact_overflow",
    "unbounded_sink",
    "controlled_offset",
    "controlled_extent",
    "loop_alias_frontier",
    "exact_oob_read",
    "controlled_read_offset",
)
WRITE_SOURCE_ARG_BY_SINK = {
    "memcpy": 1,
    "memmove": 1,
    "strncpy": 1,
    "strncat": 1,
    "strcpy": 1,
    "strcat": 1,
    "memset": 1,
}
MEMORY_SOURCE_READ_SINKS = {"memcpy", "memmove", "strncpy", "strncat"}
PACKET_CURSOR_ADVANCE_MACROS = {
    "n2s": 2,
    "n2l": 4,
    "n2l3": 3,
}
INTEGER_MEMORY_RISK_RELATIONS = {
    "integer_overflow_risk",
    "integer_underflow_risk",
    "signed_conversion_risk",
    "integer_truncation_risk",
}
INTEGER_MEMORY_RISK_TYPES = {
    "integer_overflow_to_memory_access",
    "integer_underflow_to_memory_access",
    "signed_conversion_to_memory_access",
    "integer_truncation_to_memory_access",
}

OPERATION_SPEC_SET = load_memory_operation_specs()
OPERATION_SPECS: dict[str, dict[str, object]] = OPERATION_SPEC_SET.as_dict_mapping()
UNBOUNDED_DEST_ARG: dict[str, int] = {}
LENGTH_DEST_AND_SIZE_ARGS: dict[str, tuple[int, int]] = {}
SCANF_FAMILY: set[str] = set()
ALL_SINKS: set[str] = set()
SORTED_ALL_SINKS: list[str] = []
_BUILTIN_SINK_ALIASES = {
    "isoc99_scanf": "scanf",
    "isoc99_fscanf": "fscanf",
    "isoc99_sscanf": "sscanf",
    "builtin___strcpy_chk": "strcpy_chk",
    "builtin___memcpy_chk": "memcpy_chk",
    "builtin___sprintf_chk": "sprintf_chk",
    "builtin___snprintf_chk": "snprintf_chk",
}
SINK_ALIASES = dict(_BUILTIN_SINK_ALIASES)


def _refresh_sink_spec_views(specs: MemoryOperationSpecSet) -> None:
    global OPERATION_SPEC_SET, OPERATION_SPECS, UNBOUNDED_DEST_ARG, LENGTH_DEST_AND_SIZE_ARGS, SCANF_FAMILY, ALL_SINKS, SORTED_ALL_SINKS, SINK_ALIASES
    OPERATION_SPEC_SET = specs
    OPERATION_SPECS = specs.as_dict_mapping()
    SINK_ALIASES = {**_BUILTIN_SINK_ALIASES, **dict(getattr(specs, "aliases", {}) or {})}
    UNBOUNDED_DEST_ARG = {
        name: int(spec["dest_arg"])
        for name, spec in OPERATION_SPECS.items()
        if spec.get("semantics") == "unbounded" and "dest_arg" in spec
    }
    LENGTH_DEST_AND_SIZE_ARGS = {
        name: (int(spec["dest_arg"]), int(spec["size_arg"]))
        for name, spec in OPERATION_SPECS.items()
        if spec.get("semantics") in {"bounded", "append_bounded"}
        and "dest_arg" in spec
        and "size_arg" in spec
    }
    SCANF_FAMILY = {
        name for name, spec in OPERATION_SPECS.items() if spec.get("semantics") == "format_string"
    }
    ALL_SINKS = set(OPERATION_SPECS)
    SORTED_ALL_SINKS = sorted(ALL_SINKS, key=len, reverse=True)
    normalizer = globals().get("_normalize_sink_name")
    if normalizer is not None and hasattr(normalizer, "cache_clear"):
        normalizer.cache_clear()


_refresh_sink_spec_views(OPERATION_SPEC_SET)
TYPE_SIZES = {
    "byte": 1,
    "char": 1,
    "uchar": 1,
    "uint8_t": 1,
    "guint8": 1,
    "undefined": 1,
    "undefined1": 1,
    "short": 2,
    "ushort": 2,
    "uint16_t": 2,
    "undefined2": 2,
    "int": 4,
    "uint": 4,
    "guint": 4,
    "int32_t": 4,
    "__int32_t": 4,
    "undefined4": 4,
    "long": 8,
    "ulong": 8,
    "size_t": 8,
    "undefined8": 8,
    "streamid": 16,
    "ifreq": 40,
    "gst audio channel position": 4,
    "gstaudiochannelposition": 4,
}

INDEX_WRITE_RE = re.compile(
    r"\b(?P<array>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<index>[^\]]+)\s*\]\s*"
    r"(?:(?:[+*/%&|^-]?=(?!=))|\+\+|--)"
)
POINTER_STORE_RE = re.compile(
    r"\*\s*\([^)]*\)\s*\([^;]*?\b(?P<base>local_[0-9a-fA-F]+)\b\s*\+\s*"
    r"(?:\([^)]+\)\s*)?(?P<index>[A-Za-z_][A-Za-z0-9_]*|[-+]?0x[0-9a-fA-F]+|[-+]?\d+)"
    r"(?:\s*\*\s*(?P<scale>0x[0-9a-fA-F]+|\d+))?[^;]*?\)\s*="
)
DECLARED_ARRAY_RE = re.compile(
    r"(?:^|(?<=[;{]))\s*(?P<type>(?:unsigned\s+)?(?:struct\s+)?[A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<count>\d+)\s*\]\s*;",
    re.MULTILINE,
)
DECLARED_OBJECT_RE = re.compile(
    r"(?:^|(?<=[;{]))\s*(?P<type>(?:struct\s+)?[A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;",
    re.MULTILINE,
)
CAST_PREFIX_RE = re.compile(r"^\([A-Za-z_][A-Za-z0-9_\s\*]*\)\s*")
C_CAST_RE = re.compile(
    r"\(\s*"
    r"(?:unsigned\s+|signed\s+)?"
    r"(?:char|short|int|long|ulong|uint|size_t|byte|undefined\d*|[A-Za-z_][A-Za-z0-9_]*\s+\*)"
    r"\s*\*?\s*\)"
)
ARRAY_EXPR_RE = re.compile(
    r"\b(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<index>[^\]]+)\s*\]"
)
WHITESPACE_RE = re.compile(r"\s+")
IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
INLINEABLE_EXPR_RE = re.compile(r"[A-Za-z0-9_xXa-fA-F+\-*/%() <>&|]+")
SIMPLE_REPLACEMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|\d+")
CALL_LIKE_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(")
GENERATED_TEMP_RE = re.compile(r"[a-z]{1,3}Var[0-9a-fA-F]+")
RAW_STACK_SLOT_RE = re.compile(
    r"(?:local|uStack|auStack|puStack|pcStack|pbStack|piStack)_[0-9a-fA-F]+|"
    r"[a-z]{1,3}Stack[0-9a-fA-F]+"
)
LINEAR_EXPR_KEYWORDS = {
    "sizeof",
    "char",
    "short",
    "int",
    "long",
    "void",
    "unsigned",
    "signed",
    "const",
    "volatile",
    "static",
    "struct",
    "enum",
    "union",
    "undefined",
    "undefined1",
    "undefined2",
    "undefined4",
    "undefined8",
    "size_t",
}
REVERSED_COMPARISON_OP = {">": "<", ">=": "<=", "<": ">", "<=": ">="}
REJECTED_COMPARISON_OP = {">=": "<", ">": "<=", "<=": ">", "<": ">="}
STACK_PROBE_ALIAS_RE = re.compile(
    r"\b(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*(?:[+\-]\s*[-+]?(?:0x[0-9a-fA-F]+|\d+))?\s*!=\s*"
    r"(?P<stack>[A-Za-z_][A-Za-z0-9_]*)\b"
)


@dataclass(frozen=True)
class _AliasTarget:
    stack_obj: Optional[dict] = None
    param_index: Optional[int] = None
    offset_expr: str = ""
    evidence_source: str = "alias"
    iterated: bool = False


@dataclass(frozen=True)
class _HeapTarget:
    heap_obj: dict
    offset_expr: str = ""
    evidence_source: str = "c_heap_alloc"
    iterated: bool = False


@dataclass(frozen=True)
class _FallbackAliasState:
    assign_line: int
    assign_text: str
    saw_null_check: bool = False
    null_check_line: int = 0


@dataclass(frozen=True)
class _CallSite:
    line_number: int
    line: str
    original_line: str
    callee: str
    args: tuple[str, ...]
    aliases: Mapping[str, _AliasTarget]


@dataclass(frozen=True)
class _WriteSummary:
    function_name: str
    function_keys: tuple[str, ...]
    dest_arg_index: int
    kind: str
    sink: str
    line_number: int
    line_text: str
    dest_arg_type: str = ""
    write_size_expr: str = ""
    write_size_bytes: Optional[int] = None
    offset_bound_expr: str = ""
    offset_bound_complete: bool = False
    offset_bound_evidence: tuple[str, ...] = ()
    semantics: str = ""
    source_evidence: tuple[str, ...] = ()
    evidence_sources: tuple[str, ...] = ("c_text", "interprocedural_summary")


@dataclass(frozen=True)
class _ParameterSourceReadSummary:
    function_name: str
    function_keys: tuple[str, ...]
    param_index: int
    sink: str
    line_number: int
    line_text: str
    source_offset_expr: str
    read_size_expr: str
    source_evidence: tuple[str, ...] = ()
    evidence_sources: tuple[str, ...] = ("c_text", "interprocedural_field_source")


@dataclass(frozen=True)
class _AllocationSummary:
    function_name: str
    function_keys: tuple[str, ...]
    capacity_expr: str
    source: str


@dataclass(frozen=True)
class _FunctionContext:
    node: FunctionNode
    stack_index: "_StackIndex"
    lines: tuple[str, ...]
    code_lines: tuple[str, ...]
    source_evidence: tuple[str, ...]
    aliases: Mapping[str, _AliasTarget]
    aliases_by_line: tuple[Mapping[str, _AliasTarget], ...]
    heap_aliases: Mapping[str, _HeapTarget]
    heap_aliases_by_line: tuple[Mapping[str, _HeapTarget], ...]
    param_names: tuple[str, ...]
    summaries: tuple[_WriteSummary, ...]
    source_read_summaries: tuple[_ParameterSourceReadSummary, ...] = ()


@dataclass(frozen=True)
class _FactPipelineResult:
    candidate_findings: list["StaticCandidate"]
    write_facts: list[WriteFact]
    resolved_writes: list[ResolvedWrite]
    function_summaries: list[FunctionSummary]
    classified_findings: list[ClassifiedFinding]
    suppressed_findings: list[SuppressedFinding]


@dataclass(frozen=True)
class _ReachabilityContext:
    graph: CallGraph
    source_nodes: tuple[str, ...]
    entry_nodes: tuple[str, ...]
    thread_start_nodes: frozenset[str]
    callback_nodes: frozenset[str]
    roots: tuple[str, ...]
    source_paths: Mapping[str, list[str]]
    entry_paths: Mapping[str, list[str]]
    node_by_name: Mapping[str, FunctionNode]


@dataclass(frozen=True)
class StaticCandidate:
    """One deterministic memory-write candidate emitted by the v2 extractor."""

    binary: str
    function_name: str
    source_symbol: str
    demangled_name: str
    source_object: str
    address: str
    relative_path: str
    candidate_id: str
    kind: str
    sink: str
    line_number: int
    line_text: str
    target_buffer: str
    capacity_bytes: int
    capacity_basis: str
    destination_kind: str = "stack"
    capacity_source: str = ""
    write_relation: str = ""
    write_size_expr: str = ""
    write_size_bytes: Optional[int] = None
    offset_expr: str = "0"
    overflow_condition: str = ""
    verdict: str = "candidate"
    severity: str = "medium"
    vulnerability_type: str = "memory_overflow"
    evidence: list[str] = field(default_factory=list)
    source_evidence: list[str] = field(default_factory=list)
    guard_evidence: list[str] = field(default_factory=list)
    evidence_sources: list[str] = field(default_factory=list)
    operation_address: str = ""
    call_path: list[str] = field(default_factory=list)
    reachability_kind: str = "unknown"
    input_reaches_sink: bool = False
    path_is_valid: bool = False
    capacity_model: dict[str, object] = field(default_factory=dict)
    classification_trace: dict[str, object] = field(default_factory=dict)
    triage_tier: str = ""
    cluster_id: str = ""
    cluster_size: int = 1
    sibling_ids: list[str] = field(default_factory=list)
    cluster_key: str = ""
    cluster_summary: dict[str, object] = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return self.verdict in {"overflow", "unbounded"}

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "StaticCandidate":
        write_size = data.get("write_size_bytes")
        return cls(
            binary=str(data.get("binary", "")),
            function_name=str(data.get("function_name", "")),
            source_symbol=str(data.get("source_symbol", "")),
            demangled_name=str(data.get("demangled_name", "")),
            source_object=str(data.get("source_object", "")),
            address=str(data.get("address", "")),
            relative_path=str(data.get("relative_path", "")),
            candidate_id=str(data.get("candidate_id", "")),
            kind=str(data.get("kind", "")),
            sink=str(data.get("sink", "")),
            line_number=int(data.get("line_number", 0)),
            line_text=str(data.get("line_text", "")),
            target_buffer=str(data.get("target_buffer", "")),
            capacity_bytes=int(data.get("capacity_bytes", 0)),
            capacity_basis=str(data.get("capacity_basis", "")),
            destination_kind=str(data.get("destination_kind", "stack")),
            capacity_source=str(data.get("capacity_source", "")),
            write_relation=str(data.get("write_relation", "")),
            write_size_expr=str(data.get("write_size_expr", "")),
            write_size_bytes=None if write_size in {None, ""} else int(write_size),
            offset_expr=str(data.get("offset_expr", "0") or "0"),
            overflow_condition=str(data.get("overflow_condition", "")),
            verdict=str(data.get("verdict", "candidate")),
            severity=str(data.get("severity", "medium")),
            vulnerability_type=str(data.get("vulnerability_type", "memory_overflow") or "memory_overflow"),
            evidence=[str(item) for item in data.get("evidence", [])],
            source_evidence=[str(item) for item in data.get("source_evidence", [])],
            guard_evidence=[str(item) for item in data.get("guard_evidence", [])],
            evidence_sources=[str(item) for item in data.get("evidence_sources", [])],
            operation_address=str(data.get("operation_address", "")),
            call_path=[str(item) for item in data.get("call_path", [])],
            reachability_kind=str(data.get("reachability_kind", "unknown")),
            input_reaches_sink=bool(data.get("input_reaches_sink", False)),
            path_is_valid=bool(data.get("path_is_valid", False)),
            capacity_model=dict(data.get("capacity_model", {}) or {}),
            classification_trace=dict(data.get("classification_trace", {}) or {}),
            triage_tier=str(data.get("triage_tier", "")),
            cluster_id=str(data.get("cluster_id", "")),
            cluster_size=int(data.get("cluster_size", 1) or 1),
            sibling_ids=[str(item) for item in data.get("sibling_ids", []) or []],
            cluster_key=str(data.get("cluster_key", "")),
            cluster_summary=dict(data.get("cluster_summary", {}) or {}),
        )


def write_candidate_artifact(export_dir: Path, candidates: Sequence[StaticCandidate]) -> Path:
    path = Path(export_dir) / CANDIDATE_ARTIFACT
    path.write_text(json.dumps([candidate.to_dict() for candidate in candidates], indent=2))
    return path


def write_write_fact_artifact(export_dir: Path, facts: Sequence[WriteFact]) -> Path:
    path = Path(export_dir) / WRITE_FACT_ARTIFACT
    path.write_text(json.dumps([fact.to_dict() for fact in facts], indent=2))
    return path


def write_resolved_write_artifact(export_dir: Path, writes: Sequence[ResolvedWrite]) -> Path:
    path = Path(export_dir) / RESOLVED_WRITE_ARTIFACT
    path.write_text(json.dumps([write.to_dict() for write in writes], indent=2))
    return path


def write_function_summary_artifact(export_dir: Path, summaries: Sequence[FunctionSummary]) -> Path:
    path = Path(export_dir) / FUNCTION_SUMMARY_ARTIFACT
    path.write_text(json.dumps([summary.to_dict() for summary in summaries], indent=2))
    return path


def write_confirmation_artifact(export_dir: Path, candidates: Sequence[StaticCandidate]) -> Path:
    path = Path(export_dir) / CONFIRMATION_CANDIDATE_ARTIFACT
    path.write_text(json.dumps([candidate.to_dict() for candidate in candidates], indent=2))
    return path


def write_suppressed_artifact(export_dir: Path, suppressed: Sequence[SuppressedFinding]) -> Path:
    path = Path(export_dir) / SUPPRESSED_FINDING_ARTIFACT
    path.write_text(json.dumps([finding.to_dict() for finding in suppressed], indent=2))
    return path


def load_candidate_artifact(export_dir: Path) -> list[StaticCandidate]:
    path = Path(export_dir) / CANDIDATE_ARTIFACT
    payload = json.loads(path.read_text() or "[]")
    return [StaticCandidate.from_dict(item) for item in payload]


def select_confirmation_candidates(candidates: Sequence[StaticCandidate]) -> list[StaticCandidate]:
    """Select candidates that should be handed to external LLM reasoning.

    This queue is intentionally unranked. A candidate enters only through one
    of the explicit confirmation frontier rules recorded in its debug trace.
    """
    selected: list[StaticCandidate] = []
    for candidate in candidates:
        rule = _confirmation_queue_rule(candidate)
        if rule is None:
            continue
        trace = dict(candidate.classification_trace or {})
        trace["confirmation_rule"] = rule
        selected.append(replace(candidate, classification_trace=trace))
    return _dedupe_confirmation_candidates(selected)


def _confirmation_status(confirmation: CandidateConfirmation | Mapping[str, object] | None) -> str:
    if confirmation is None:
        return ""
    if isinstance(confirmation, Mapping):
        return str(confirmation.get("status") or "")
    return str(confirmation.status or "")


def _confirmation_reason_codes(confirmation: CandidateConfirmation | Mapping[str, object] | None) -> list[str]:
    if confirmation is None:
        return []
    if isinstance(confirmation, Mapping):
        raw_codes = confirmation.get("reason_codes") or []
    else:
        raw_codes = confirmation.reason_codes
    if isinstance(raw_codes, str):
        return [raw_codes]
    if isinstance(raw_codes, Sequence):
        return [str(code) for code in raw_codes]
    return []


def _confirmation_memory_safety_argument(
    confirmation: CandidateConfirmation | Mapping[str, object] | None,
) -> Mapping[str, object]:
    if confirmation is None:
        return {}
    if isinstance(confirmation, Mapping):
        argument = confirmation.get("memory_safety_argument")
    else:
        argument = confirmation.memory_safety_argument
    return argument if isinstance(argument, Mapping) else {}


def _has_authoritative_dynamic_overflow_confirmation(
    confirmation: CandidateConfirmation | Mapping[str, object] | None,
) -> bool:
    if _confirmation_status(confirmation) != "confirmed_bug":
        return False
    if set(_confirmation_reason_codes(confirmation)) & {
        "ghidra_dynamic_overflow_proven",
        "ghidra_dynamic_heap_overflow_proven",
        "ghidra_dynamic_oob_write_proven",
        "ghidra_dynamic_oob_read_proven",
    }:
        return True
    argument = _confirmation_memory_safety_argument(confirmation)
    proof = argument.get("ghidra_dynamic_proof")
    return isinstance(proof, Mapping) and str(proof.get("status") or "") in {
        "overflow_proven",
        "heap_overflow_proven",
        "oob_write_proven",
        "oob_read_proven",
    }


def _select_report_candidates(
    candidates: Sequence[StaticCandidate],
    confirmation_findings: Sequence[StaticCandidate],
    confirmations: Mapping[str, CandidateConfirmation],
    selected_policy: str,
) -> list[StaticCandidate]:
    if selected_policy != "confirmed":
        return list(candidates)

    report_candidates: list[StaticCandidate] = list(confirmation_findings)
    seen_ids = {candidate.candidate_id for candidate in report_candidates}
    for candidate in candidates:
        if candidate.candidate_id in seen_ids:
            continue
        if not _has_authoritative_dynamic_overflow_confirmation(confirmations.get(candidate.candidate_id)):
            continue
        report_candidates.append(candidate)
        seen_ids.add(candidate.candidate_id)
    return report_candidates


def simulate_candidate_proof_gates(
    candidates: Sequence[StaticCandidate],
    confirmation_candidates: Sequence[StaticCandidate] | None = None,
    report_candidate_ids: Sequence[str] | None = None,
) -> dict[str, dict[str, int]]:
    """Report disabled proof-gate removal counts without applying them."""
    confirmation_candidates = confirmation_candidates or ()
    report_ids = set(report_candidate_ids or ())
    gates = {
        "complete_unreachable_candidate": _trace_is_complete_unreachable,
        "complete_unreachable_and_no_source_taint": (
            lambda candidate: _trace_is_complete_unreachable(candidate)
            and not _trace_has_source_or_parameter_taint(candidate)
        ),
        "non_input_expr_candidate": _trace_is_non_input_expr_candidate,
    }
    simulation: dict[str, dict[str, int]] = {}
    for name, predicate in gates.items():
        candidate_ids = {candidate.candidate_id for candidate in candidates if predicate(candidate)}
        confirmation_ids = {
            candidate.candidate_id for candidate in confirmation_candidates if predicate(candidate)
        }
        simulation[name] = {
            "candidate_removals": len(candidate_ids),
            "confirmation_removals": len(confirmation_ids),
            "report_removals": len(candidate_ids & report_ids),
        }
    return simulation


def confirmation_rule_counts(candidates: Sequence[StaticCandidate]) -> dict[str, int]:
    counts = {rule: 0 for rule in CONFIRMATION_REVIEW_RULES}
    for candidate in candidates:
        trace = candidate.classification_trace if isinstance(candidate.classification_trace, Mapping) else {}
        rule = str(trace.get("confirmation_rule") or "")
        if rule in counts:
            counts[rule] += 1
    return {rule: count for rule, count in counts.items() if count}


def remove_stale_stage_artifacts(export_dir: Path) -> None:
    """Delete obsolete model-stage artifacts from a deterministic export."""
    for name in STALE_STAGE_ARTIFACTS:
        path = Path(export_dir) / name
        if path.exists() and path.is_file():
            path.unlink()


def extract_static_candidates(
    manifest: Manifest,
    nodes: Sequence[FunctionNode],
) -> list[StaticCandidate]:
    """Extract deterministic sink/write candidates with the v3 fact pipeline."""
    return _extract_fact_pipeline(manifest, nodes).candidate_findings


def _extract_fact_pipeline(
    manifest: Manifest,
    nodes: Sequence[FunctionNode],
) -> _FactPipelineResult:
    """Extract actionable candidates and unresolved parameter summaries separately."""
    use_memory_sets = True
    candidates: list[StaticCandidate] = []
    allocation_summaries = _extract_allocation_summaries(nodes)
    global_extent_index = _build_global_extent_index(nodes)
    stage_results = _extract_function_stages(
        manifest,
        nodes,
        allocation_summaries,
        global_extent_index,
        use_memory_sets=use_memory_sets,
    )
    contexts = [context for context, _ in stage_results]
    for _, node_candidates in stage_results:
        candidates.extend(node_candidates)
    call_sites_by_context = _build_context_call_sites(contexts)
    fixed_point_summaries = _fixed_point_write_summaries(
        contexts,
        call_sites_by_context=call_sites_by_context,
    )
    fixed_point_source_read_summaries = _fixed_point_source_read_summaries(
        contexts,
        call_sites_by_context=call_sites_by_context,
    )
    candidates.extend(
        _instantiate_write_summaries(
            manifest,
            contexts,
            fixed_point_summaries,
            call_sites_by_context=call_sites_by_context,
        )
    )
    candidates.extend(
        _instantiate_parameter_source_read_summaries(
            manifest,
            contexts,
            source_read_summaries=fixed_point_source_read_summaries,
            call_sites_by_context=call_sites_by_context,
        )
    )
    candidates.extend(_uninstantiated_parameter_summary_candidates(manifest, contexts, fixed_point_summaries))
    safe_write_facts, safe_classified_findings, safe_suppressions = _safe_write_facts_from_contexts(
        manifest,
        contexts,
    )
    (
        wrapper_safe_facts,
        wrapper_safe_classified,
        wrapper_safe_suppressions,
    ) = _safe_summary_write_facts_from_contexts(
        manifest,
        contexts,
        fixed_point_summaries,
        call_sites_by_context=call_sites_by_context,
    )
    safe_write_facts.extend(wrapper_safe_facts)
    safe_classified_findings.extend(wrapper_safe_classified)
    safe_suppressions.extend(wrapper_safe_suppressions)
    filtered, suppressed_findings = _reconcile_candidate_duplicates(candidates)
    source_nodes = [context.node.record.name for context in contexts if context.source_evidence]
    reachability_context = _build_reachability_context(
        manifest,
        nodes,
        filtered,
        source_nodes=source_nodes,
    )
    enriched = _attach_reachability(
        manifest,
        nodes,
        filtered,
        source_nodes=source_nodes,
        reachability_context=reachability_context,
    )
    (
        enriched,
        enrichment_safe_facts,
        enrichment_safe_classified,
        enrichment_suppressions,
    ) = _suppress_proven_safe_by_fact_enrichment(enriched, nodes)
    safe_write_facts.extend(enrichment_safe_facts)
    safe_classified_findings.extend(enrichment_safe_classified)
    suppressed_findings.extend(enrichment_suppressions)
    enriched = _attach_reachability_dataflow(
        manifest,
        nodes,
        enriched,
        contexts=contexts,
        source_nodes=source_nodes,
        reachability_context=reachability_context,
    )
    enriched = _attach_source_to_write_dataflow(
        nodes,
        enriched,
        contexts=contexts,
        write_summaries=fixed_point_summaries,
        call_sites_by_context=call_sites_by_context,
    )
    enriched = _attach_cve_verification_guidance(nodes, enriched)
    enriched = [_with_v3_trace(candidate) for candidate in enriched]
    enriched, cluster_rule_suppressions = _suppress_cluster_rule_candidates(enriched)
    suppressed_findings.extend(cluster_rule_suppressions)
    enriched = _cluster_candidate_representatives(enriched)
    enriched = sorted(enriched, key=_stable_candidate_sort_key)
    write_facts = _unique_write_fact_ids(
        [candidate_to_write_fact(candidate) for candidate in enriched] + safe_write_facts
    )
    resolved_writes = [_resolved_write_from_fact(fact) for fact in write_facts]
    function_summaries = _function_summaries_from_contexts(contexts, allocation_summaries, fixed_point_summaries)
    classified_findings = safe_classified_findings + [
        _classified_finding_from_candidate(candidate) for candidate in enriched
    ]
    return _FactPipelineResult(
        candidate_findings=enriched,
        write_facts=write_facts,
        resolved_writes=resolved_writes,
        function_summaries=function_summaries,
        classified_findings=classified_findings,
        suppressed_findings=suppressed_findings + safe_suppressions,
    )


def _extract_function_stages(
    manifest: Manifest,
    nodes: Sequence[FunctionNode],
    allocation_summaries: Sequence[_AllocationSummary],
    global_extent_index: Mapping[str, Mapping[str, object]],
    *,
    use_memory_sets: bool,
) -> list[tuple[_FunctionContext, list[StaticCandidate]]]:
    node_list = list(nodes)
    worker_count = _fact_extraction_workers(len(node_list))
    if worker_count <= 1:
        return [
            _extract_function_stage(
                manifest,
                node,
                allocation_summaries,
                global_extent_index,
                use_memory_sets=use_memory_sets,
            )
            for node in node_list
        ]

    results: list[tuple[_FunctionContext, list[StaticCandidate]] | None] = [None] * len(node_list)
    indexed_nodes = list(enumerate(node_list))
    batch_size = _stage_batch_size(len(indexed_nodes), worker_count)
    batches = [
        indexed_nodes[index : index + batch_size]
        for index in range(0, len(indexed_nodes), batch_size)
    ]
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                _extract_function_stage_batch,
                manifest,
                batch,
                allocation_summaries,
                global_extent_index,
                use_memory_sets=use_memory_sets,
            ): batch
            for batch in batches
        }
        for future in as_completed(futures):
            for index, result in future.result():
                results[index] = result
    return [result for result in results if result is not None]


def _fact_extraction_workers(function_count: int) -> int:
    if function_count < 2:
        return 1
    cpu_count = os.cpu_count() or 1
    return max(1, min(function_count, cpu_count, 8))


def _stage_batch_size(function_count: int, worker_count: int) -> int:
    if function_count <= worker_count:
        return 1
    return max(32, function_count // max(1, worker_count * 16))


def _extract_function_stage_batch(
    manifest: Manifest,
    indexed_nodes: Sequence[tuple[int, FunctionNode]],
    allocation_summaries: Sequence[_AllocationSummary],
    global_extent_index: Mapping[str, Mapping[str, object]],
    *,
    use_memory_sets: bool,
) -> list[tuple[int, tuple[_FunctionContext, list[StaticCandidate]]]]:
    return [
        (
            index,
            _extract_function_stage(
                manifest,
                node,
                allocation_summaries,
                global_extent_index,
                use_memory_sets=use_memory_sets,
            ),
        )
        for index, node in indexed_nodes
    ]


def _extract_function_stage(
    manifest: Manifest,
    node: FunctionNode,
    allocation_summaries: Sequence[_AllocationSummary],
    global_extent_index: Mapping[str, Mapping[str, object]],
    *,
    use_memory_sets: bool,
) -> tuple[_FunctionContext, list[StaticCandidate]]:
    if str(node.record.name or "").startswith("__pfx_"):
        return _empty_function_context(node), []
    exact_regions = normalize_stack_regions(node.record)
    source_text = node.text or ""
    lines = source_text.splitlines()
    code_lines = _strip_c_comments(lines)
    skip_public_candidates = _should_skip_node(node, code_lines)
    stack_objects = _stack_objects_for_node(node, exact_regions)
    stack_objects = stack_objects + _non_stack_objects_for_node(
        node,
        stack_objects,
        code_lines,
        global_extent_index=global_extent_index,
    )
    stack_index = _StackIndex(stack_objects, exact_regions)
    source_evidence = tuple(_source_evidence_for_node(node, code_lines))
    param_names = tuple(_parameter_names(node))
    param_types = tuple(_parameter_types(node, param_names))
    alias_snapshots = (
        tuple(_build_stack_alias_snapshots(code_lines, stack_index, param_names))
        if _text_may_have_stack_aliases(source_text, stack_index, param_names)
        else ()
    )
    aliases = alias_snapshots[-1] if alias_snapshots else {}
    heap_alias_snapshots = (
        tuple(_build_heap_alias_snapshots(code_lines, stack_index, allocation_summaries))
        if use_memory_sets and _text_may_have_heap_aliases(source_text, allocation_summaries)
        else ()
    )
    heap_aliases = heap_alias_snapshots[-1] if heap_alias_snapshots else {}
    fallback_alias_snapshots = (
        tuple(_build_allocation_fallback_alias_snapshots(code_lines, stack_index))
        if _text_may_have_allocation_fallback_aliases(source_text, stack_index)
        else ()
    )
    summaries = tuple(
        _extract_write_summaries(
            node,
            stack_index,
            source_evidence,
            code_lines,
            alias_snapshots,
            param_names,
            param_types,
        )
    )
    source_read_summaries = tuple(
        _extract_parameter_source_read_summaries(
            node,
            stack_index,
            source_evidence,
            code_lines,
            lines,
            alias_snapshots,
            param_names,
        )
    )
    context = _FunctionContext(
        node=node,
        stack_index=stack_index,
        lines=tuple(lines),
        code_lines=tuple(code_lines),
        source_evidence=source_evidence,
        aliases=aliases,
        aliases_by_line=alias_snapshots,
        heap_aliases=heap_aliases,
        heap_aliases_by_line=heap_alias_snapshots,
        param_names=param_names,
        summaries=summaries,
        source_read_summaries=source_read_summaries,
    )

    candidates: list[StaticCandidate] = []
    if skip_public_candidates or (not stack_index.objects and not heap_aliases):
        return context, candidates

    if node.record.pcode_calls:
        candidates.extend(
            _extract_pcode_call_candidates(
                manifest,
                node,
                stack_index,
                source_evidence,
                use_memory_sets=use_memory_sets,
            )
        )
    for line_number, line in enumerate(code_lines, start=1):
        if _line_may_contain_sink_call(line):
            candidates.extend(
                _extract_sink_candidates(
                    manifest,
                    node,
                    stack_index,
                    source_evidence,
                    code_lines,
                    line_number,
                    line,
                    lines[line_number - 1] if line_number - 1 < len(lines) else line,
                    alias_snapshots[line_number - 1] if line_number - 1 < len(alias_snapshots) else aliases,
                    param_names,
                    heap_alias_snapshots[line_number - 1] if line_number - 1 < len(heap_alias_snapshots) else heap_aliases,
                    use_memory_sets=use_memory_sets,
                )
            )
        if use_memory_sets and _line_may_contain_allocation(line):
            candidates.extend(
                _extract_integer_allocation_candidates(
                    manifest,
                    node,
                    stack_index,
                    source_evidence,
                    code_lines,
                    line_number,
                    line,
                    lines[line_number - 1] if line_number - 1 < len(lines) else line,
                    param_names,
                    allocation_summaries,
                )
            )
        if fallback_alias_snapshots and "(" in line:
            candidates.extend(
                _extract_allocation_fallback_copy_candidates(
                    manifest,
                    node,
                    stack_index,
                    source_evidence,
                    line_number,
                    line,
                    lines[line_number - 1] if line_number - 1 < len(lines) else line,
                    fallback_alias_snapshots[line_number - 1]
                    if line_number - 1 < len(fallback_alias_snapshots)
                    else fallback_alias_snapshots[-1],
                )
            )
    if node.record.pcode_stores:
        candidates.extend(
            _extract_pcode_store_candidates(
                manifest,
                node,
                stack_index,
                source_evidence,
                use_memory_sets=use_memory_sets,
            )
        )
    for line_number, line in enumerate(code_lines, start=1):
        original_line = lines[line_number - 1] if line_number - 1 < len(lines) else line
        if _line_may_contain_index_write(line):
            candidates.extend(
                _extract_index_candidates(
                    manifest,
                    node,
                    stack_index,
                    source_evidence,
                    code_lines,
                    line_number,
                    line,
                    original_line,
                    alias_snapshots[line_number - 1] if line_number - 1 < len(alias_snapshots) else aliases,
                    heap_alias_snapshots[line_number - 1] if line_number - 1 < len(heap_alias_snapshots) else heap_aliases,
                    param_names,
                    use_memory_sets=use_memory_sets,
                )
            )
        if _line_may_contain_pointer_store(line):
            candidates.extend(
                _extract_pointer_store_candidates(
                    manifest,
                    node,
                    stack_index,
                    source_evidence,
                    code_lines,
                    line_number,
                    line,
                    original_line,
                    alias_snapshots[line_number - 1] if line_number - 1 < len(alias_snapshots) else aliases,
                    heap_alias_snapshots[line_number - 1] if line_number - 1 < len(heap_alias_snapshots) else heap_aliases,
                    param_names,
                    use_memory_sets=use_memory_sets,
                )
            )
        if _line_may_contain_index_read(line):
            candidates.extend(
                _extract_index_read_candidates(
                    manifest,
                    node,
                    stack_index,
                    source_evidence,
                    code_lines,
                    line_number,
                    line,
                    original_line,
                    alias_snapshots[line_number - 1] if line_number - 1 < len(alias_snapshots) else aliases,
                    heap_alias_snapshots[line_number - 1] if line_number - 1 < len(heap_alias_snapshots) else heap_aliases,
                    param_names,
                    use_memory_sets=use_memory_sets,
                )
            )
        if use_memory_sets and _line_may_contain_pointer_read(line):
            candidates.extend(
                _extract_pointer_read_candidates(
                    manifest,
                    node,
                    stack_index,
                    source_evidence,
                    code_lines,
                    line_number,
                    line,
                    original_line,
                    heap_alias_snapshots[line_number - 1]
                    if line_number - 1 < len(heap_alias_snapshots)
                    else heap_aliases,
                )
            )
    candidates.extend(
        _extract_cursor_limit_read_candidates(
            manifest,
            node,
            source_evidence,
            code_lines,
            lines,
        )
    )
    return context, candidates


def _build_context_call_sites(contexts: Sequence[_FunctionContext]) -> dict[int, tuple[_CallSite, ...]]:
    result: dict[int, tuple[_CallSite, ...]] = {}
    for context in contexts:
        if not context.code_lines or (not context.param_names and not context.stack_index.objects):
            continue
        result[id(context)] = tuple(_context_call_sites(context))
    return result


def _context_call_sites(context: _FunctionContext) -> Iterable[_CallSite]:
    for line_number, line, original_line in _iter_logical_statements(context.code_lines, context.lines):
        if "(" not in line:
            continue
        aliases = (
            context.aliases_by_line[line_number - 1]
            if line_number - 1 < len(context.aliases_by_line)
            else context.aliases
        )
        for callee, args in _iter_calls(line):
            yield _CallSite(
                line_number=line_number,
                line=line,
                original_line=original_line,
                callee=callee,
                args=tuple(args),
                aliases=aliases,
            )


def _empty_function_context(node: FunctionNode) -> _FunctionContext:
    return _FunctionContext(
        node=node,
        stack_index=_StackIndex(()),
        lines=tuple((node.text or "").splitlines()),
        code_lines=(),
        source_evidence=(),
        aliases={},
        aliases_by_line=(),
        heap_aliases={},
        heap_aliases_by_line=(),
        param_names=(),
        summaries=(),
    )


def _safe_write_facts_from_contexts(
    manifest: Manifest,
    contexts: Sequence[_FunctionContext],
) -> tuple[list[WriteFact], list[ClassifiedFinding], list[SuppressedFinding]]:
    facts: list[WriteFact] = []
    classified: list[ClassifiedFinding] = []
    suppressed: list[SuppressedFinding] = []
    for context in contexts:
        facts.extend(_safe_pcode_write_facts(manifest, context))
        for line_number, line, original_line in _iter_logical_statements(context.code_lines, context.lines):
            aliases = (
                context.aliases_by_line[line_number - 1]
                if line_number - 1 < len(context.aliases_by_line)
                else context.aliases
            )
            heap_aliases = (
                context.heap_aliases_by_line[line_number - 1]
                if line_number - 1 < len(context.heap_aliases_by_line)
                else context.heap_aliases
            )
            if _line_may_contain_sink_call(line):
                facts.extend(
                    _safe_sink_write_facts(
                        manifest,
                        context,
                        line_number,
                        line,
                        original_line,
                        aliases,
                        heap_aliases,
                    )
                )
    facts = _unique_write_fact_ids(facts)
    for fact in facts:
        classified.append(_classified_finding_from_write_fact(fact, status="safe"))
        suppressed.append(_suppressed_finding_from_write_fact(fact, reason="proven_safe"))
        plan_reason = _plan_suppression_reason_for_safe_write_fact(fact)
        if plan_reason:
            suppressed.append(_suppressed_finding_from_write_fact(fact, reason=plan_reason))
    return facts, classified, suppressed


def _plan_suppression_reason_for_safe_write_fact(fact: WriteFact) -> str:
    if str(fact.kind) == "pcode_store":
        return "range_loop_proven_safe"
    semantics = str(fact.semantics or "")
    if semantics == "bounded" or _normalize_sink_name(fact.sink) in LENGTH_DEST_AND_SIZE_ARGS:
        return "bounded_capacity_proven_safe"
    if semantics == "unbounded" and "literal_source_bound" in set(fact.evidence_sources):
        return "bounded_capacity_proven_safe"
    return ""


def _safe_summary_write_facts_from_contexts(
    manifest: Manifest,
    contexts: Sequence[_FunctionContext],
    summaries: Sequence[_WriteSummary],
    *,
    call_sites_by_context: Mapping[int, Sequence[_CallSite]],
) -> tuple[list[WriteFact], list[ClassifiedFinding], list[SuppressedFinding]]:
    if not summaries:
        return [], [], []
    summaries_by_key: dict[str, list[_WriteSummary]] = {}
    for summary in summaries:
        for key in summary.function_keys:
            summaries_by_key.setdefault(key, []).append(summary)
    facts: list[WriteFact] = []
    for context in contexts:
        if not context.stack_index.objects:
            continue
        for site in call_sites_by_context.get(id(context), ()):
            for summary in _summaries_for_call(site.callee, summaries_by_key):
                fact = _safe_summary_write_fact_for_callsite(manifest, context, summary, site)
                if fact is not None:
                    facts.append(fact)
    facts = _unique_write_fact_ids(facts)
    classified = [_classified_finding_from_write_fact(fact, status="safe") for fact in facts]
    suppressed = [
        _suppressed_finding_from_write_fact(fact, reason="bounded_wrapper_proven_safe")
        for fact in facts
    ]
    return facts, classified, suppressed


def _safe_summary_write_fact_for_callsite(
    manifest: Manifest,
    context: _FunctionContext,
    summary: _WriteSummary,
    site: _CallSite,
) -> Optional[WriteFact]:
    if summary.dest_arg_index >= len(site.args):
        return None
    target = _resolve_stack_destination(site.args[summary.dest_arg_index], context.stack_index, site.aliases)
    if not target or not target.stack_obj:
        return None
    stack_obj = target.stack_obj
    evidence_sources = list(summary.evidence_sources)
    for source in _candidate_sources("interprocedural", target):
        if source not in evidence_sources:
            evidence_sources.append(source)
    source_evidence = _unique_nonempty(list(context.source_evidence) + list(summary.source_evidence))
    summary_write_expr = _instantiate_summary_expr(summary.write_size_expr, site.args)
    capacity = _safe_int(stack_obj.get("size_bytes"))
    if summary.semantics == "bounded":
        if _summary_target_has_unknown_object_extent(summary, target, site.args, stack_obj, call_text=site.line):
            return None
        write_size = summary.write_size_bytes
        if write_size is None:
            write_size = _eval_int_expr(summary_write_expr, context.stack_index)
        if write_size is None:
            return None
        if not _bounded_write_is_proven_safe(stack_obj, target, write_size, context.stack_index):
            return None
        condition = (
            f"{summary.function_name} bounded wrapper write of {write_size} bytes "
            f"fits {capacity}-byte caller destination"
        )
        return _write_fact_from_components(
            manifest,
            context.node,
            stack_obj,
            producer="summary",
            kind=f"interprocedural_{summary.kind}",
            sink=summary.sink,
            semantics=summary.semantics,
            line_number=site.line_number,
            line_text=site.original_line,
            offset_expr=target.offset_expr or "0",
            write_size_expr=summary_write_expr,
            write_size_bytes=write_size,
            relation="proven_safe",
            condition=condition,
            evidence_sources=evidence_sources,
            source_evidence=source_evidence,
        )
    if summary.semantics == "unbounded" and summary.write_size_bytes is not None:
        write_size = summary.write_size_bytes
        status, _relation, _condition = _classify_memory_write(
            stack_obj,
            target.offset_expr or "0",
            write_size,
            summary_write_expr or str(write_size),
            context.stack_index,
        )
        if status != "safe":
            return None
        condition = (
            f"{summary.function_name} literal-source write of {write_size} bytes "
            f"fits {capacity}-byte caller destination"
        )
        return _write_fact_from_components(
            manifest,
            context.node,
            stack_obj,
            producer="summary",
            kind=f"interprocedural_{summary.kind}",
            sink=summary.sink,
            semantics=summary.semantics,
            line_number=site.line_number,
            line_text=site.original_line,
            offset_expr=target.offset_expr or "0",
            write_size_expr=summary_write_expr or str(write_size),
            write_size_bytes=write_size,
            relation="proven_safe",
            condition=condition,
            evidence_sources=_unique_nonempty([*evidence_sources, "literal_source_bound"]),
            source_evidence=source_evidence,
        )
    if summary.semantics not in {"indexed_write", "pointer_store"}:
        return None
    element_size = _element_size(stack_obj)
    offset_scale = _pointer_summary_offset_scale(summary, element_size) if summary.semantics == "pointer_store" else element_size
    write_width = summary.write_size_bytes or element_size
    offset_expr = _combine_scaled_offset(target.offset_expr, summary_write_expr, offset_scale)
    constant_offset = _eval_optional_offset(offset_expr, context.stack_index)
    if constant_offset is not None:
        if constant_offset < 0 or constant_offset + write_width > capacity:
            return None
        condition = (
            f"{summary.function_name} wrapper store byte range {constant_offset}.."
            f"{constant_offset + write_width - 1} fits {capacity}-byte caller destination"
        )
    else:
        bound_status = _summary_offset_bound_status(
            summary,
            target,
            site.args,
            context.stack_index,
            capacity,
            write_width,
        )
        if not bound_status or bound_status[0] != "safe":
            return None
        _status, upper_expr, upper = bound_status
        condition = (
            f"{summary.function_name} wrapper store is bounded by {upper_expr} ({upper}) "
            f"within {capacity}-byte caller destination"
        )
    return _write_fact_from_components(
        manifest,
        context.node,
        stack_obj,
        producer="summary",
        kind=f"interprocedural_{summary.kind}",
        sink=summary.sink,
        semantics=summary.semantics,
        line_number=site.line_number,
        line_text=site.original_line,
        offset_expr=offset_expr or summary_write_expr or "0",
        write_size_expr=summary_write_expr or offset_expr or "0",
        write_size_bytes=write_width,
        relation="proven_safe",
        condition=condition,
        evidence_sources=evidence_sources,
        source_evidence=source_evidence,
    )


def _safe_pcode_write_facts(manifest: Manifest, context: _FunctionContext) -> list[WriteFact]:
    facts: list[WriteFact] = []
    node = context.node
    for entry in node.record.pcode_calls or []:
        sink = _normalize_sink_name(str(entry.get("callee") or entry.get("function") or ""))
        spec = OPERATION_SPECS.get(sink)
        if not spec or str(spec.get("semantics") or "") != "bounded":
            continue
        args = _pcode_args(entry)
        dest_index = int(spec["dest_arg"])
        size_index = int(spec["size_arg"])
        target_obj, offset_expr = _pcode_stack_target(args, dest_index, context.stack_index)
        if not target_obj:
            continue
        size_expr = _pcode_arg_expr(args, size_index) or "unknown"
        write_size = _pcode_constant_arg(args, size_index)
        status, relation, condition = _classify_memory_write(
            target_obj,
            offset_expr,
            write_size,
            size_expr,
            context.stack_index,
        )
        if status != "safe":
            continue
        facts.append(
            _write_fact_from_components(
                manifest,
                node,
                target_obj,
                producer="pcode",
                kind="call",
                sink=sink,
                semantics="bounded",
                line_number=0,
                line_text=f"{sink}(...)",
                offset_expr=offset_expr,
                write_size_expr=size_expr,
                write_size_bytes=write_size,
                relation=relation,
                condition=condition,
                evidence_sources=["pcode_calls"],
                source_evidence=context.source_evidence,
                operation_address=str(entry.get("call_address") or entry.get("address") or ""),
            )
        )
    for entry in node.record.pcode_stores or []:
        target_obj, relative_offset = _pcode_store_target(entry, context.stack_index)
        if not target_obj:
            continue
        write_width = _first_int(entry, ("write_width", "width", "write_size", "write_size_bytes")) or 1
        constant_index = _first_int(entry, ("constant_index", "index", "constant_subscript"))
        scale = _first_int(entry, ("scale", "constant_scale")) or _element_size(target_obj)
        constant_offset = _first_int(entry, ("constant_offset", "offset"))
        if constant_index is not None:
            offset_expr = str((constant_offset or 0) + constant_index * scale)
        elif relative_offset is not None:
            offset_expr = str(relative_offset + (constant_offset or 0))
        elif constant_offset is not None:
            offset_expr = str(constant_offset)
        else:
            offset_expr = "unknown"
        status, relation, condition = _classify_memory_write(
            target_obj,
            offset_expr,
            write_width,
            str(write_width),
            context.stack_index,
        )
        if status != "safe":
            continue
        facts.append(
            _write_fact_from_components(
                manifest,
                node,
                target_obj,
                producer="pcode",
                kind="pcode_store",
                sink="pcode_store",
                semantics="store",
                line_number=0,
                line_text="p-code stack store",
                offset_expr=offset_expr,
                write_size_expr=str(write_width),
                write_size_bytes=write_width,
                relation=relation,
                condition=condition,
                evidence_sources=["pcode_stores"],
                source_evidence=context.source_evidence,
                operation_address=str(entry.get("operation_address") or entry.get("address") or ""),
            )
        )
    return facts


def _safe_sink_write_facts(
    manifest: Manifest,
    context: _FunctionContext,
    line_number: int,
    line: str,
    original_line: str,
    aliases: Mapping[str, _AliasTarget],
    heap_aliases: Mapping[str, _HeapTarget],
) -> list[WriteFact]:
    facts: list[WriteFact] = []
    for sink, args in _iter_sink_calls(line):
        spec = OPERATION_SPECS.get(sink)
        if not spec:
            continue
        semantics = str(spec.get("semantics") or "")
        if semantics == "unbounded":
            fact = _safe_unbounded_literal_write_fact(
                manifest,
                context,
                line_number,
                original_line,
                aliases,
                sink,
                spec,
                args,
            )
            if fact is not None:
                facts.append(fact)
            continue
        if semantics != "bounded":
            continue
        dest_index = int(spec["dest_arg"])
        size_index = int(spec["size_arg"])
        if dest_index >= len(args) or size_index >= len(args):
            continue
        dest_expr = args[dest_index]
        size_expr = args[size_index]
        target = _resolve_stack_destination(dest_expr, context.stack_index, aliases)
        target_obj: Mapping[str, object] | None = None
        offset_expr = "0"
        evidence_sources: Sequence[str] = ()
        destination_kind = ""
        if target and target.stack_obj:
            target_obj = target.stack_obj
            offset_expr = target.offset_expr
            evidence_sources = _candidate_sources("c_text", target)
        else:
            heap_target = _resolve_heap_destination_expr(dest_expr, heap_aliases)
            if heap_target is not None:
                target_obj = heap_target.heap_obj
                offset_expr = heap_target.offset_expr
                evidence_sources = ["c_text", heap_target.evidence_source]
                destination_kind = "heap"
        if target_obj is None:
            continue
        write_size = _eval_int_expr(size_expr, context.stack_index)
        status, relation, condition = _classify_memory_write(
            target_obj,
            offset_expr,
            write_size,
            size_expr,
            context.stack_index,
        )
        if status != "safe":
            continue
        facts.append(
            _write_fact_from_components(
                manifest,
                context.node,
                target_obj,
                producer="c_text",
                kind="call",
                sink=sink,
                semantics="bounded",
                line_number=line_number,
                line_text=original_line,
                offset_expr=offset_expr,
                write_size_expr=size_expr,
                write_size_bytes=write_size,
                relation=relation,
                condition=condition,
                evidence_sources=evidence_sources,
                source_evidence=context.source_evidence,
                destination_kind=destination_kind,
            )
        )
    return facts


def _safe_unbounded_literal_write_fact(
    manifest: Manifest,
    context: _FunctionContext,
    line_number: int,
    original_line: str,
    aliases: Mapping[str, _AliasTarget],
    sink: str,
    spec: Mapping[str, object],
    args: Sequence[str],
) -> WriteFact | None:
    write_size = _literal_unbounded_write_size(sink, spec, args)
    if write_size is None:
        return None
    dest_index = int(spec.get("dest_arg", -1))
    if dest_index < 0 or dest_index >= len(args):
        return None
    target = _resolve_stack_destination(args[dest_index], context.stack_index, aliases)
    if not target or not target.stack_obj:
        return None
    status, relation, condition = _classify_memory_write(
        target.stack_obj,
        target.offset_expr,
        write_size,
        str(write_size),
        context.stack_index,
    )
    if status != "safe":
        return None
    return _write_fact_from_components(
        manifest,
        context.node,
        target.stack_obj,
        producer="c_text",
        kind="call",
        sink=sink,
        semantics="unbounded",
        line_number=line_number,
        line_text=original_line,
        offset_expr=target.offset_expr,
        write_size_expr=str(write_size),
        write_size_bytes=write_size,
        relation=relation,
        condition=condition,
        evidence_sources=[*_candidate_sources("c_text", target), "literal_source_bound"],
        source_evidence=context.source_evidence,
        guard_evidence=("literal source length is fixed",),
    )


def _write_fact_from_components(
    manifest: Manifest,
    node: FunctionNode,
    target_obj: Mapping[str, object],
    *,
    producer: str,
    kind: str,
    sink: str,
    semantics: str,
    line_number: int,
    line_text: str,
    offset_expr: str,
    write_size_expr: str,
    write_size_bytes: Optional[int],
    relation: str,
    condition: str,
    evidence_sources: Sequence[str],
    source_evidence: Sequence[str],
    guard_evidence: Sequence[str] = (),
    destination_kind: str = "",
    operation_address: str = "",
) -> WriteFact:
    target = str(target_obj.get("var_display") or target_obj.get("label") or "memory_object")
    resolved_destination_kind = str(destination_kind or target_obj.get("destination_kind") or "stack")
    capacity = CapacityModel.from_dict(
        _capacity_model_for_mapping(
            {
                **dict(target_obj),
                "capacity_source": target_obj.get("capacity_source") or target_obj.get("capacity_basis_kind") or "stack metadata",
            }
        )
    )
    normalized_offset = _normalize_offset_expr(offset_expr or "0") or "0"
    fact_id = _candidate_id(
        manifest.binary,
        node.record.address,
        node.record.name,
        line_number,
        sink,
        target,
        operation_address=operation_address,
        offset_expr=normalized_offset,
        write_size_expr=write_size_expr,
    )
    return WriteFact(
        fact_id=fact_id,
        binary=manifest.binary,
        function_name=node.record.name,
        address=node.record.address,
        relative_path=node.record.relative_path,
        producer=producer,
        kind=kind,
        sink=sink,
        semantics=semantics,
        operation_address=operation_address,
        line_number=line_number,
        line_text=line_text.strip(),
        destination_expr=target,
        destination_object_id=f"{resolved_destination_kind}:{target}",
        target_buffer=target,
        offset_expr=normalized_offset,
        write_size_expr=write_size_expr,
        write_size_bytes=write_size_bytes,
        capacity=capacity,
        evidence_sources=list(evidence_sources),
        source_evidence=list(source_evidence),
        guard_evidence=list(guard_evidence),
        attacker_control={
            "destination_pointer": "classified",
            "source_bytes": "attacker_controlled" if source_evidence else "unknown",
            "write_size": "symbolic" if _expr_is_symbolic(write_size_expr) else "constant",
            "offset": "symbolic" if _expr_is_symbolic(normalized_offset) else "constant",
            "format_string": "not_applicable",
        },
        raw={
            "relation": relation,
            "condition": condition,
            "destination_kind": resolved_destination_kind,
        },
    )


def _unique_write_fact_ids(facts: Sequence[WriteFact]) -> list[WriteFact]:
    seen: dict[str, int] = {}
    unique: list[WriteFact] = []
    for fact in facts:
        count = seen.get(fact.fact_id, 0)
        seen[fact.fact_id] = count + 1
        if count:
            unique.append(replace(fact, fact_id=f"{fact.fact_id}#raw{count + 1}"))
        else:
            unique.append(fact)
    return unique


def _resolved_write_from_fact(fact: WriteFact) -> ResolvedWrite:
    memory = FactMemObject(
        object_id=fact.destination_object_id,
        label=fact.target_buffer,
        kind=fact.destination_object_id.split(":", 1)[0] if ":" in fact.destination_object_id else "memory",
        capacity=fact.capacity,
        object_trust=fact.capacity.trust or "unknown",
        var_names=[fact.target_buffer] if fact.target_buffer else [],
        metadata={
            "producer": fact.producer,
            "vulnerability_type": fact.raw.get("vulnerability_type", "memory_overflow"),
            "relation": fact.raw.get("relation", ""),
            "condition": fact.raw.get("condition", ""),
        },
    )
    return ResolvedWrite(
        resolved_id=fact.fact_id,
        write_fact=fact,
        memory_object=memory,
        offset_expr=fact.offset_expr,
        width_expr=fact.write_size_expr,
        width_bytes=fact.write_size_bytes,
        resolution_trace={
            "object_resolution": {
                "target_buffer": fact.target_buffer,
                "destination_object_id": fact.destination_object_id,
                "evidence_sources": list(fact.evidence_sources),
            },
            "capacity_resolution": fact.capacity.to_dict(),
            "write_resolution": {
                "vulnerability_type": fact.raw.get("vulnerability_type", "memory_overflow"),
                "offset_expr": fact.offset_expr,
                "write_size_expr": fact.write_size_expr,
                "write_size_bytes": fact.write_size_bytes,
            },
        },
    )


def _classified_finding_from_write_fact(fact: WriteFact, *, status: str) -> ClassifiedFinding:
    relation = str(fact.raw.get("relation") or status)
    condition = str(fact.raw.get("condition") or "")
    return ClassifiedFinding(
        finding_id=fact.fact_id,
        write_fact=fact,
        status=status,
        relation=relation,
        condition=condition,
        triage_tier="safe" if status == "safe" else "triage",
        reportable=False,
        confirmation_queue=False,
        classification_trace={
            "object_resolution": {
                "target_buffer": fact.target_buffer,
                "destination_object_id": fact.destination_object_id,
                "evidence_sources": list(fact.evidence_sources),
            },
            "capacity_resolution": fact.capacity.to_dict(),
            "write_resolution": {
                "offset_expr": fact.offset_expr,
                "write_size_expr": fact.write_size_expr,
                "write_size_bytes": fact.write_size_bytes,
                "relation": relation,
                "condition": condition,
            },
            "bounds": {
                "accepted": [
                    {
                        "relation": relation,
                        "reason": condition,
                        "source": "memory_sets",
                    }
                ] if status == "safe" else [],
                "rejected": [],
            },
            "sources": list(fact.source_evidence),
            "aliases": [source for source in fact.evidence_sources if "alias" in source],
        },
        candidate={},
    )


def _suppressed_finding_from_write_fact(fact: WriteFact, *, reason: str) -> SuppressedFinding:
    relation = str(fact.raw.get("relation") or "")
    condition = str(fact.raw.get("condition") or "")
    return SuppressedFinding(
        fact_id=fact.fact_id,
        reason=reason,
        function_name=fact.function_name,
        sink=fact.sink,
        target_buffer=fact.target_buffer,
        trace={
            "relation": relation,
            "condition": condition,
            "offset_expr": fact.offset_expr,
            "write_size_expr": fact.write_size_expr,
            "bounds": {
                "accepted": [
                    {
                        "relation": relation,
                        "reason": condition,
                        "source": "memory_sets",
                    }
                ],
                "rejected": [],
            },
            "evidence_sources": list(fact.evidence_sources),
        },
    )


def _raw_candidate_count_from_clusters(candidates: Sequence[StaticCandidate]) -> int:
    total = 0
    for candidate in candidates:
        total += max(1, int(candidate.cluster_size or 1))
    return total


def _cluster_rule_suppression_counts(
    suppressed: Sequence[SuppressedFinding],
) -> dict[str, int]:
    counts = {reason: 0 for reason in sorted(CLUSTER_RULE_SUPPRESSION_REASONS)}
    for finding in suppressed:
        if finding.reason in counts:
            counts[finding.reason] += 1
    return counts


def run_static_pipeline(
    export_dir: Path,
    *,
    operation_specs_path: Optional[Path] = None,
    persist_debug_facts: bool = False,
    cache_dir: Optional[Path] = None,
    skip: int = 0,
    sample: Optional[int] = None,
    persist_stage_artifacts: bool = True,
    write_evidence_packs_dir: Optional[Path] = None,
    confirmation_dir: Optional[Path] = None,
    report_policy: Optional[str] = None,
) -> AnalysisReport:
    """Run the static v3 fact-first pipeline and return the report model."""
    if report_policy not in {None, "deterministic", "confirmed"}:
        raise ValueError("report_policy must be 'deterministic' or 'confirmed'")
    started_at = time.perf_counter()
    export_dir = Path(export_dir).resolve()
    previous_specs = OPERATION_SPEC_SET
    if operation_specs_path is not None:
        _refresh_sink_spec_views(load_memory_operation_specs(operation_specs_path))
    cache_hit = False
    try:
        manifest, all_nodes = load_function_nodes(export_dir)
        cache_key = _analysis_cache_key(manifest, all_nodes, export_dir)
        extraction = _load_analysis_cache(cache_dir, cache_key)
        if extraction is None:
            extraction = _extract_fact_pipeline(manifest, all_nodes)
            _write_analysis_cache(cache_dir, cache_key, extraction)
        else:
            cache_hit = True
    finally:
        if operation_specs_path is not None:
            _refresh_sink_spec_views(previous_specs)
    selected_nodes = _select_nodes(all_nodes, skip=skip, sample=sample)
    selected_signatures = {
        _finding_signature(node.record.address, node.record.relative_path) for node in selected_nodes
    }

    candidates = list(extraction.candidate_findings)
    write_facts = list(extraction.write_facts)
    resolved_writes = list(extraction.resolved_writes)
    function_summaries = list(extraction.function_summaries)
    classified_findings = list(extraction.classified_findings)
    suppressed_findings = list(extraction.suppressed_findings)
    if selected_signatures:
        candidates = [
            candidate
            for candidate in candidates
            if _finding_signature(candidate.address, candidate.relative_path) in selected_signatures
        ]
        write_facts = [
            fact
            for fact in write_facts
            if _finding_signature(fact.address, fact.relative_path) in selected_signatures
        ]
        resolved_writes = [
            write
            for write in resolved_writes
            if _finding_signature(write.write_fact.address, write.write_fact.relative_path) in selected_signatures
        ]
        function_names = {node.record.name for node in selected_nodes}
        function_summaries = [
            summary for summary in function_summaries if summary.function_name in function_names
        ]
        classified_findings = [
            finding
            for finding in classified_findings
            if _finding_signature(finding.write_fact.address, finding.write_fact.relative_path) in selected_signatures
        ]
    else:
        candidates = []
        write_facts = []
        resolved_writes = []
        function_summaries = []
        classified_findings = []

    confirmation_findings = select_confirmation_candidates(candidates)
    policy_views = build_policy_views(classified_findings, suppressed_findings)
    debug_artifact_paths: dict[str, str] = {}

    if persist_stage_artifacts and skip == 0 and sample is None:
        remove_stale_stage_artifacts(export_dir)
        debug_artifact_paths["write_facts"] = str(write_write_fact_artifact(export_dir, write_facts))
        debug_artifact_paths["resolved_writes"] = str(write_resolved_write_artifact(export_dir, resolved_writes))
        debug_artifact_paths["function_summaries"] = str(
            write_function_summary_artifact(export_dir, function_summaries)
        )
        debug_artifact_paths["candidate_findings"] = str(write_candidate_artifact(export_dir, candidates))
        debug_artifact_paths["confirmation_findings"] = str(
            write_confirmation_artifact(export_dir, confirmation_findings)
        )
        if persist_debug_facts:
            debug_artifact_paths["suppressed_findings"] = str(
                write_suppressed_artifact(export_dir, suppressed_findings)
            )

    confirmations: dict[str, CandidateConfirmation] = {}
    if confirmation_dir is not None:
        confirmations = load_candidate_confirmations(Path(confirmation_dir))
    proofs: dict[str, Any] = {}
    if confirmation_dir is not None:
        proofs = load_concolic_dynamic_proofs(Path(confirmation_dir))
    proof_counts: dict[str, int] = {}
    for proof in proofs.values():
        status = str(proof.get("status") or "unknown") if isinstance(proof, Mapping) else "unknown"
        proof_counts[status] = proof_counts.get(status, 0) + 1
    selected_policy = report_policy or ("confirmed" if confirmations else "deterministic")
    if selected_policy not in {"deterministic", "confirmed"}:
        raise ValueError("report_policy must be 'deterministic' or 'confirmed'")
    if write_evidence_packs_dir is not None:
        write_evidence_packs(confirmation_findings, all_nodes, Path(write_evidence_packs_dir))

    config = ReportConfig(binary=manifest.binary, export_dir=str(export_dir), run_label=utc_timestamp())
    report_candidates = _select_report_candidates(candidates, confirmation_findings, confirmations, selected_policy)
    vulnerability_reports = build_vulnerability_reports(
        report_candidates,
        confirmations=confirmations,
        proofs=proofs,
        report_policy=selected_policy,
    )
    proof_gate_simulation = simulate_candidate_proof_gates(
        candidates,
        confirmation_findings,
        [report.candidate_id for report in vulnerability_reports],
    )
    cluster_rule_counts = _cluster_rule_suppression_counts(suppressed_findings)
    frontier_rule_counts = confirmation_rule_counts(confirmation_findings)
    policy_metrics = policy_views.to_metrics()
    policy_metrics["classified_llm_queue"] = policy_metrics.pop("llm_queue", 0)
    stage_metrics = {
        "raw_facts": len(write_facts),
        "resolved_writes": len(resolved_writes),
        "classified_findings": len(classified_findings),
        "raw_candidates": _raw_candidate_count_from_clusters(candidates),
        "candidates": len(candidates),
        "candidate_clusters": len(candidates),
        "llm_queue": len(confirmation_findings),
        "clustered_llm_queue": len(confirmation_findings),
        "reports": len(vulnerability_reports),
        "proof_verdicts": len(proofs),
        "proof_counts": proof_counts,
        "suppressions": len(suppressed_findings),
        "suppressed_by_cluster_rules": sum(cluster_rule_counts.values()),
        "cluster_rule_suppressions": cluster_rule_counts,
        "confirmation_rule_counts": frontier_rule_counts,
        "runtime_seconds": round(time.perf_counter() - started_at, 4),
        "cache_hit": cache_hit,
        "parallel_workers": 0 if cache_hit else _fact_extraction_workers(len(all_nodes)),
        "candidate_proof_gate_simulation": proof_gate_simulation,
        **policy_metrics,
    }
    return AnalysisReport(
        config=config,
        candidate_findings=list(candidates),
        function_summaries=list(function_summaries),
        confirmation_findings=list(confirmation_findings),
        vulnerability_reports=vulnerability_reports,
        candidate_confirmations=confirmations,
        candidate_proofs=proofs,
        debug_artifact_paths=debug_artifact_paths,
        stage_metrics=stage_metrics,
    )


class _StackIndex:
    def __init__(self, objects: Sequence[dict], stack_regions: Sequence[dict] = ()):
        self.objects = [dict(item) for item in objects]
        self.stack_regions = sorted(
            [dict(item) for item in stack_regions],
            key=lambda entry: (_safe_int(entry.get("start_offset")), _safe_int(entry.get("end_offset"))),
        )
        self.buffer_objects = [obj for obj in self.objects if _is_buffer_like_stack_obj(obj)]
        self.by_var: dict[str, dict] = {}
        for obj in self.objects:
            for name in obj.get("var_names") or []:
                existing = self.by_var.get(str(name))
                if existing is None or _safe_int(obj.get("size_bytes")) < _safe_int(existing.get("size_bytes")):
                    self.by_var[str(name)] = obj
        self.buffer_by_var = {
            name: obj
            for name, obj in self.by_var.items()
            if _is_buffer_like_stack_obj(obj)
        }

    def find_for_expr(self, expr: str) -> Optional[dict]:
        expr = _clean_expr(expr)
        for name, obj in self.by_var.items():
            if _identifier_span(expr, name) is not None:
                return obj
        return None

    def find_for_var(self, name: str) -> Optional[dict]:
        return self.by_var.get(str(name or ""))

    def find_buffer_for_var(self, name: str) -> Optional[dict]:
        return self.buffer_by_var.get(str(name or ""))

    def find_for_stack_offset(self, offset: int) -> Optional[dict]:
        matches = []
        for obj in self.objects:
            start = _safe_int(obj.get("start_offset"))
            end = _safe_int(obj.get("end_offset"))
            if start <= offset < end:
                matches.append(obj)
        if not matches:
            return None
        return min(matches, key=lambda item: _safe_int(item.get("size_bytes")))

    def capacity_for_var(self, name: str) -> Optional[int]:
        obj = self.by_var.get(name)
        if not obj:
            return None
        member_sizes = obj.get("member_sizes")
        if isinstance(member_sizes, Mapping) and name in member_sizes:
            member_size = _safe_int(member_sizes.get(name))
            if member_size > 0:
                return member_size
        return _safe_int(obj.get("size_bytes")) or None


def _parameter_names(node: FunctionNode) -> list[str]:
    names: list[str] = []
    for param in node.record.parameters or []:
        for key in ("name", "param_name", "variable", "symbol", "var_name"):
            value = param.get(key) if isinstance(param, Mapping) else None
            if value:
                names.append(str(value))
                break
    for prototype in (node.record.prototype, _first_function_signature(node.text or "", node.record.name)):
        if not prototype:
            continue
        open_index = prototype.find("(")
        close_index = _find_matching_paren(prototype, open_index) if open_index >= 0 else -1
        if open_index < 0 or close_index < 0:
            continue
        for raw_param in _split_arguments(prototype[open_index + 1 : close_index]):
            name = _parameter_name_from_decl(raw_param)
            if name:
                names.append(name)
    deduped: list[str] = []
    for name in names:
        if name and name not in deduped:
            deduped.append(name)
    return deduped


def _parameter_types(node: FunctionNode, param_names: Sequence[str]) -> list[str]:
    types = [""] * len(param_names)
    by_name = {name: index for index, name in enumerate(param_names)}
    for param in node.record.parameters or []:
        if not isinstance(param, Mapping):
            continue
        name = ""
        for key in ("name", "param_name", "variable", "symbol", "var_name"):
            if param.get(key):
                name = str(param.get(key))
                break
        if name not in by_name:
            continue
        for key in ("data_type", "type", "type_name", "datatype"):
            if param.get(key):
                types[by_name[name]] = str(param.get(key))
                break
    for prototype in (node.record.prototype, _first_function_signature(node.text or "", node.record.name)):
        if not prototype:
            continue
        open_index = prototype.find("(")
        close_index = _find_matching_paren(prototype, open_index) if open_index >= 0 else -1
        if open_index < 0 or close_index < 0:
            continue
        for raw_param in _split_arguments(prototype[open_index + 1 : close_index]):
            name = _parameter_name_from_decl(raw_param)
            if name not in by_name:
                continue
            parsed_type = _parameter_type_from_decl(raw_param, name)
            if parsed_type and not types[by_name[name]]:
                types[by_name[name]] = parsed_type
    return types


def _parameter_type_from_decl(raw_param: str, name: str) -> str:
    cleaned = raw_param.split("=", 1)[0].strip()
    cleaned = re.sub(r"\[[^\]]*\]", "", cleaned)
    match = re.search(rf"\b{re.escape(name)}\b\s*$", cleaned)
    if not match:
        return ""
    return cleaned[: match.start()].strip()


def _param_type_at(index: Optional[int], param_types: Sequence[str]) -> str:
    if index is None or index < 0 or index >= len(param_types):
        return ""
    return str(param_types[index] or "")


def _first_function_signature(source_text: str, function_name: str = "") -> str:
    prefix = (source_text or "").split("{", 1)[0]
    if function_name and function_name in prefix:
        signature = prefix[prefix.rfind(function_name) :]
        return " ".join(signature.split())
    for line in (source_text or "").splitlines():
        stripped = line.strip()
        if "(" in stripped and not stripped.startswith(("if ", "for ", "while ", "switch ")):
            return stripped.split("{", 1)[0].strip()
    return ""


def _parameter_name_from_decl(raw_param: str) -> str:
    cleaned = raw_param.strip()
    if not cleaned or cleaned == "void" or cleaned == "...":
        return ""
    cleaned = cleaned.split("=", 1)[0].strip()
    cleaned = re.sub(r"\[[^\]]*\]", "", cleaned)
    identifiers = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", cleaned)
    if not identifiers:
        return ""
    keywords = {"const", "volatile", "restrict", "struct", "enum", "union", "unsigned", "signed"}
    identifiers = [item for item in identifiers if item not in keywords]
    return identifiers[-1] if identifiers else ""


def _build_stack_aliases(
    lines: Sequence[str],
    stack_index: _StackIndex,
    param_names: Sequence[str],
) -> dict[str, _AliasTarget]:
    snapshots = _build_stack_alias_snapshots(lines, stack_index, param_names)
    return dict(snapshots[-1]) if snapshots else {}


def _build_stack_alias_snapshots(
    lines: Sequence[str],
    stack_index: _StackIndex,
    param_names: Sequence[str],
) -> list[dict[str, _AliasTarget]]:
    aliases: dict[str, _AliasTarget] = {}
    snapshots: list[dict[str, _AliasTarget]] = []
    iterated_names: set[str] = set()
    for line in lines:
        probe_alias = _stack_probe_alias(line, stack_index)
        if probe_alias is not None:
            name, target = probe_alias
            aliases[name] = target
        lhs, rhs = _split_simple_assignment(line)
        if not lhs:
            _advance_packet_cursor_aliases(line, aliases, stack_index)
            snapshots.append(dict(aliases))
            continue
        name = _lhs_name(lhs)
        if not name:
            _advance_packet_cursor_aliases(line, aliases, stack_index)
            snapshots.append(dict(aliases))
            continue
        target = _resolve_destination_expr(rhs, stack_index, aliases, param_names)
        if target and (target.stack_obj is not None or target.param_index is not None):
            source = "c_stack_probe_alias" if target.evidence_source.startswith("c_stack_probe") else "c_alias"
            iterated = target.iterated or _rhs_advances_alias(rhs, aliases) or _for_step_advances_alias(line, name)
            if iterated:
                iterated_names.add(name)
            aliases[name] = replace(
                target,
                evidence_source=source,
                iterated=iterated,
            )
        else:
            aliases.pop(name, None)
        _advance_packet_cursor_aliases(line, aliases, stack_index)
        snapshots.append(dict(aliases))
    if not iterated_names:
        return snapshots
    return [
        {
            name: replace(target, iterated=True) if name in iterated_names and not target.iterated else target
            for name, target in snapshot.items()
        }
        for snapshot in snapshots
    ]


def _advance_packet_cursor_aliases(
    line: str,
    aliases: MutableMapping[str, _AliasTarget],
    stack_index: _StackIndex,
) -> None:
    if not aliases:
        return
    for name, delta in _packet_cursor_advance_deltas(line, aliases):
        target = aliases.get(name)
        if target is not None:
            aliases[name] = _advanced_packet_cursor_alias(target, delta, stack_index)


def _packet_cursor_advance_deltas(
    line: str,
    aliases: Mapping[str, _AliasTarget],
) -> list[tuple[str, int]]:
    masked = _mask_string_literals(str(line or ""))
    if re.match(r"\s*for\s*\(", masked):
        return []
    deltas: list[tuple[str, int]] = []
    for match in re.finditer(
        r"\b(?P<macro>n2s|n2l|n2l3)\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*,",
        masked,
    ):
        name = match.group("name")
        if name in aliases:
            deltas.append((name, PACKET_CURSOR_ADVANCE_MACROS[match.group("macro")]))
    for match in re.finditer(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>\+\+|--)", masked):
        name = match.group("name")
        if name in aliases:
            deltas.append((name, 1 if match.group("op") == "++" else -1))
    for match in re.finditer(r"(?P<op>\+\+|--)\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b", masked):
        name = match.group("name")
        if name in aliases:
            deltas.append((name, 1 if match.group("op") == "++" else -1))
    for match in re.finditer(
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>\+=|-=)\s*(?P<delta>0x[0-9a-fA-F]+|\d+)\b",
        masked,
    ):
        name = match.group("name")
        if name not in aliases:
            continue
        delta = int(match.group("delta"), 0)
        deltas.append((name, delta if match.group("op") == "+=" else -delta))
    return deltas


def _advanced_packet_cursor_alias(
    target: _AliasTarget,
    delta: int,
    stack_index: _StackIndex,
) -> _AliasTarget:
    if delta == 0:
        return target
    next_offset_expr = _combine_offsets(target.offset_expr, str(delta))
    stack_obj = target.stack_obj
    if stack_obj is None:
        return replace(target, offset_expr=next_offset_expr)
    next_offset = _eval_optional_offset(next_offset_expr, stack_index)
    capacity = _safe_int(stack_obj.get("size_bytes"))
    if next_offset is None or next_offset <= 0 or next_offset >= capacity:
        return replace(target, offset_expr=next_offset_expr)
    return replace(
        target,
        stack_obj=_remaining_packet_slice_object(stack_obj, next_offset),
        offset_expr="",
    )


def _packet_slice_alias_from_concrete_offset(
    target: _AliasTarget,
    stack_index: _StackIndex,
) -> _AliasTarget:
    stack_obj = target.stack_obj
    if stack_obj is None:
        return target
    offset = _eval_optional_offset(target.offset_expr, stack_index)
    capacity = _safe_int(stack_obj.get("size_bytes"))
    if offset is None or offset <= 0 or offset >= capacity:
        return target
    return replace(
        target,
        stack_obj=_remaining_packet_slice_object(stack_obj, offset),
        offset_expr="",
    )


def _remaining_packet_slice_object(stack_obj: Mapping[str, object], consumed_bytes: int) -> dict:
    capacity = _safe_int(stack_obj.get("size_bytes"))
    remaining = max(0, capacity - consumed_bytes)
    base = str(stack_obj.get("slice_base") or stack_obj.get("var_display") or stack_obj.get("label") or "packet")
    base_offset = _safe_int(stack_obj.get("slice_offset"))
    absolute_offset = base_offset + consumed_bytes
    label = f"{base}[{absolute_offset}:]"
    obj = dict(stack_obj)
    start_offset = _safe_int(obj.get("start_offset")) + consumed_bytes
    end_offset = _safe_int(obj.get("end_offset"))
    obj.update(
        {
            "label": label,
            "var_display": label,
            "var_names": [label],
            "start_offset": start_offset,
            "end_offset": end_offset,
            "offset_range": f"[{_format_offset(start_offset)}..{_format_offset(end_offset)}]",
            "size_bytes": remaining,
            "size_hex": f"0x{remaining:x}",
            "annotation": (
                f"{base}: inferred packet slice after {absolute_offset} byte cursor advance, "
                f"{remaining} bytes remain"
            ),
            "capacity_source": "inferred_packet_slice_remaining",
            "capacity_basis_kind": "inferred_packet_slice_remaining",
            "slice_base": base,
            "slice_offset": absolute_offset,
        }
    )
    return obj


def _text_may_have_stack_aliases(
    source_text: str,
    stack_index: _StackIndex,
    param_names: Sequence[str],
) -> bool:
    if "=" not in source_text:
        return False
    names: set[str] = set(param_names)
    for obj in stack_index.buffer_objects:
        names.update(str(name) for name in obj.get("var_names") or [] if name)
        label = str(obj.get("label") or obj.get("var_display") or "")
        if label:
            names.add(label)
    if not names:
        return False
    tokens = set(IDENTIFIER_RE.findall(source_text))
    return bool(names.intersection(tokens))


def _text_may_have_allocation_fallback_aliases(source_text: str, stack_index: _StackIndex) -> bool:
    if "=" not in source_text or "(" not in source_text:
        return False
    lowered = source_text.lower()
    if "null" not in lowered and "0x0" not in lowered and "== 0" not in lowered:
        return False
    if "alloc" not in lowered:
        return False
    names: set[str] = set()
    for obj in stack_index.buffer_objects:
        names.update(str(name) for name in obj.get("var_names") or [] if name)
    if not names:
        return False
    tokens = set(IDENTIFIER_RE.findall(source_text))
    return bool(names.intersection(tokens))


def _build_allocation_fallback_alias_snapshots(
    lines: Sequence[str],
    stack_index: _StackIndex,
) -> list[dict[str, _AliasTarget]]:
    aliases: dict[str, _AliasTarget] = {}
    states: dict[str, _FallbackAliasState] = {}
    null_flag_targets: dict[str, str] = {}
    snapshots: list[dict[str, _AliasTarget]] = []

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        for name in list(states):
            state = states[name]
            if index - state.assign_line > 24:
                states.pop(name, None)

        _mark_direct_null_checks(states, stripped, index)
        lhs, rhs = _split_simple_assignment(stripped)
        name = _lhs_name(lhs)
        if name:
            checked_name = _null_checked_pointer_name(rhs)
            if checked_name and checked_name in states:
                null_flag_targets[name] = checked_name
                states[checked_name] = replace(
                    states[checked_name],
                    saw_null_check=True,
                    null_check_line=index,
                )

            if _rhs_is_call_assignment(rhs):
                states[name] = _FallbackAliasState(assign_line=index, assign_text=stripped)
                aliases.pop(name, None)
            else:
                target = _resolve_destination_expr(rhs, stack_index, {}, ())
                if (
                    target
                    and target.stack_obj is not None
                    and name in states
                    and _recent_null_checked_fallback(states[name], index)
                ):
                    aliases[name] = replace(target, evidence_source="allocation_fallback_alias")
                elif name in aliases:
                    aliases.pop(name, None)

        for checked_name in _null_checked_names_from_if(stripped, null_flag_targets):
            if checked_name in states:
                states[checked_name] = replace(
                    states[checked_name],
                    saw_null_check=True,
                    null_check_line=index,
                )
        snapshots.append(dict(aliases))
    return snapshots


def _rhs_is_call_assignment(rhs: str) -> bool:
    if not rhs:
        return False
    for callee, _args in _iter_calls(rhs) or ():
        if _normalize_function_key(callee) in {"sizeof"}:
            continue
        return True
    return False


def _mark_direct_null_checks(
    states: MutableMapping[str, _FallbackAliasState],
    line: str,
    line_number: int,
) -> None:
    for name, state in list(states.items()):
        if _line_null_checks_name(line, name):
            states[name] = replace(state, saw_null_check=True, null_check_line=line_number)


def _null_checked_pointer_name(expr: str) -> str:
    cleaned = _normalize_offset_expr(expr)
    if not cleaned:
        return ""
    match = re.fullmatch(
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:==|!=)\s*(?:NULL|\(?\s*[A-Za-z_][A-Za-z0-9_]*\s*\*\s*\)?\s*)?0x?0",
        cleaned,
        flags=re.IGNORECASE,
    )
    if match:
        return match.group("name")
    match = re.fullmatch(
        r"(?:NULL|\(?\s*[A-Za-z_][A-Za-z0-9_]*\s*\*\s*\)?\s*)?0x?0\s*(?:==|!=)\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
        cleaned,
        flags=re.IGNORECASE,
    )
    return match.group("name") if match else ""


def _null_checked_names_from_if(line: str, null_flag_targets: Mapping[str, str]) -> list[str]:
    match = re.search(r"\bif\s*\((?P<cond>[^)]*)\)", line)
    if not match:
        return []
    condition = _normalize_offset_expr(match.group("cond"))
    names: list[str] = []
    for flag, target in null_flag_targets.items():
        if re.fullmatch(rf"!?\s*{re.escape(flag)}", condition):
            names.append(target)
    for name in IDENTIFIER_RE.findall(condition):
        if _line_null_checks_name(f"if ({condition})", name):
            names.append(name)
    return _unique_nonempty(names)


def _line_null_checks_name(line: str, name: str) -> bool:
    if not name:
        return False
    escaped = re.escape(name)
    null_atom = r"(?:NULL|\(?\s*[A-Za-z_][A-Za-z0-9_]*\s*\*\s*\)?\s*)?0x?0"
    return bool(
        re.search(rf"\b{escaped}\b\s*(?:==|!=)\s*{null_atom}", line, flags=re.IGNORECASE)
        or re.search(rf"{null_atom}\s*(?:==|!=)\s*\b{escaped}\b", line, flags=re.IGNORECASE)
        or re.search(rf"\bif\s*\(\s*!\s*\b{escaped}\b\s*\)", line)
    )


def _recent_null_checked_fallback(state: _FallbackAliasState, line_number: int) -> bool:
    return bool(
        state.saw_null_check
        and state.null_check_line >= state.assign_line
        and line_number - state.assign_line <= 24
        and line_number - state.null_check_line <= 8
    )


def _build_heap_alias_snapshots(
    lines: Sequence[str],
    stack_index: _StackIndex,
    allocation_summaries: Sequence[_AllocationSummary] = (),
) -> list[dict[str, _HeapTarget]]:
    aliases: dict[str, _HeapTarget] = {}
    snapshots: list[dict[str, _HeapTarget]] = []
    iterated_names: set[str] = set()
    for line in lines:
        lhs, rhs = _split_simple_assignment(line)
        if not lhs:
            snapshots.append(dict(aliases))
            continue
        name = _lhs_name(lhs)
        if not name:
            snapshots.append(dict(aliases))
            continue
        heap_obj = _heap_object_from_allocation(name, rhs, stack_index, allocation_summaries)
        if heap_obj is not None:
            aliases[name] = _HeapTarget(heap_obj=heap_obj)
            snapshots.append(dict(aliases))
            continue
        target = _resolve_heap_destination_expr(rhs, aliases)
        if target is not None:
            iterated = target.iterated or _rhs_advances_heap_alias(rhs, aliases) or _for_step_advances_alias(line, name)
            if iterated:
                iterated_names.add(name)
            aliases[name] = replace(target, evidence_source="c_heap_alias", iterated=iterated)
        else:
            aliases.pop(name, None)
        snapshots.append(dict(aliases))
    if not iterated_names:
        return snapshots
    return [
        {
            name: replace(target, iterated=True) if name in iterated_names and not target.iterated else target
            for name, target in snapshot.items()
        }
        for snapshot in snapshots
    ]


def _text_may_have_heap_aliases(
    source_text: str,
    allocation_summaries: Sequence[_AllocationSummary],
) -> bool:
    if "=" not in source_text:
        return False
    if any(token in source_text for token in ("malloc", "calloc", "realloc", "alloca", "xmalloc", "g_malloc", "operator_new")):
        return True
    if not allocation_summaries:
        return False
    return any(
        f"{key}(" in source_text
        for summary in allocation_summaries
        for key in summary.function_keys
        if key
    )


def _heap_object_from_allocation(
    name: str,
    rhs: str,
    stack_index: _StackIndex,
    allocation_summaries: Sequence[_AllocationSummary] = (),
) -> Optional[dict]:
    cleaned = _clean_expr(str(rhs or "").rstrip(";"))
    wrapper = _allocation_summary_for_call(cleaned, allocation_summaries)
    if wrapper is not None:
        capacity_expr, source = wrapper
        capacity_bytes = _eval_heap_capacity_expr(capacity_expr, stack_index) or 0
        capacity_display = f"{capacity_bytes} bytes" if capacity_bytes > 0 else capacity_expr
        return {
            "label": name,
            "var_display": name,
            "size_bytes": capacity_bytes,
            "capacity_expr": capacity_expr,
            "offset_range": "[heap allocation]",
            "annotation": f"{name}: {source} capacity {capacity_display}",
            "capacity_source": source,
            "capacity_basis_kind": source,
            "destination_kind": "heap",
            "var_names": [name],
        }
    match = re.match(
        r"^(?P<func>malloc|calloc|realloc|alloca|xmalloc|g_malloc0?|g_try_malloc0?|g_realloc|operator_new)\s*\((?P<args>.*)\)$",
        cleaned,
    )
    source = ""
    if match:
        func = match.group("func")
        args = _split_arguments(match.group("args"))
        if func in {"malloc", "alloca", "xmalloc", "g_malloc", "g_malloc0", "g_try_malloc", "g_try_malloc0", "operator_new"}:
            if not args:
                return None
            capacity_expr = args[0]
        elif func == "calloc":
            if len(args) < 2:
                return None
            capacity_expr = f"({args[0]}) * ({args[1]})"
        else:
            if len(args) < 2:
                return None
            capacity_expr = args[1]
        source = f"local_{func}"
    else:
        return None
    capacity_bytes = _eval_heap_capacity_expr(capacity_expr, stack_index) or 0
    capacity_display = f"{capacity_bytes} bytes" if capacity_bytes > 0 else capacity_expr
    return {
        "label": name,
        "var_display": name,
        "size_bytes": capacity_bytes,
        "capacity_expr": capacity_expr,
        "offset_range": "[heap allocation]",
        "annotation": f"{name}: {source} capacity {capacity_display}",
        "capacity_source": source,
        "capacity_basis_kind": source,
        "destination_kind": "heap",
        "var_names": [name],
    }


def _extract_allocation_summaries(nodes: Sequence[FunctionNode]) -> list[_AllocationSummary]:
    summaries: list[_AllocationSummary] = []
    for node in nodes:
        text = node.text or ""
        if not text.strip() or not any(
            token in text
            for token in ("malloc", "calloc", "realloc", "alloca", "xmalloc", "g_malloc", "operator_new")
        ):
            continue
        lines = _strip_c_comments(text.splitlines())
        param_names = tuple(_parameter_names(node))
        summary = _extract_allocation_summary(node, lines, param_names)
        if summary is not None:
            summaries.append(summary)
    return summaries


def _extract_allocation_summary(
    node: FunctionNode,
    lines: Sequence[str],
    param_names: Sequence[str],
) -> Optional[_AllocationSummary]:
    if not param_names:
        return None
    body = "\n".join(lines)
    returned = re.search(r"\breturn\s+(?P<expr>[^;]+);", body)
    if returned:
        capacity_expr = _allocation_capacity_expr(returned.group("expr"), param_names)
        if capacity_expr:
            return _AllocationSummary(
                function_name=node.record.name,
                function_keys=tuple(_function_keys(node)),
                capacity_expr=capacity_expr,
                source=f"allocator_wrapper:{node.record.name}",
            )
    allocations: dict[str, str] = {}
    for line in lines:
        lhs, rhs = _split_simple_assignment(line)
        name = _lhs_name(lhs)
        if not name:
            continue
        capacity_expr = _allocation_capacity_expr(rhs, param_names)
        if capacity_expr:
            allocations[name] = capacity_expr
    returned_name = returned.group("expr").strip() if returned else ""
    if returned_name in allocations:
        return _AllocationSummary(
            function_name=node.record.name,
            function_keys=tuple(_function_keys(node)),
            capacity_expr=allocations[returned_name],
            source=f"allocator_wrapper:{node.record.name}",
        )
    return None


def _allocation_capacity_expr(expr: str, param_names: Sequence[str]) -> str:
    cleaned = _clean_expr(str(expr or "").rstrip(";"))
    match = re.match(
        r"^(?P<func>malloc|calloc|realloc|alloca|xmalloc|g_malloc0?|g_try_malloc0?|g_realloc|operator_new)\s*\((?P<args>.*)\)$",
        cleaned,
    )
    if not match:
        return ""
    func = match.group("func")
    args = _split_arguments(match.group("args"))
    if func in {"malloc", "alloca", "xmalloc", "g_malloc", "g_malloc0", "g_try_malloc", "g_try_malloc0", "operator_new"} and args:
        return _param_template_expr(args[0], param_names)
    if func == "calloc" and len(args) >= 2:
        left = _param_template_expr(args[0], param_names)
        right = _param_template_expr(args[1], param_names)
        if left and right:
            return f"({left}) * ({right})"
    if func == "realloc" and len(args) >= 2:
        return _param_template_expr(args[1], param_names)
    return ""


def _eval_heap_capacity_expr(expr: str, stack_index: _StackIndex) -> Optional[int]:
    if _contains_unknown_sizeof(expr, stack_index):
        return None
    return _eval_int_expr(expr, stack_index)


def _contains_unknown_sizeof(expr: str, stack_index: _StackIndex) -> bool:
    for match in re.finditer(r"\bsizeof\s*(?:\(\s*(?P<paren>[^)]+)\s*\)|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))", expr or ""):
        item = _normalize_c_type(match.group("paren") or match.group("bare") or "")
        if not item:
            continue
        if stack_index.capacity_for_var(item) is not None:
            continue
        if _known_type_size(item) is not None:
            continue
        return True
    return False


def _param_template_expr(expr: str, param_names: Sequence[str]) -> str:
    cleaned = _normalize_offset_expr(expr)
    if not cleaned:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9_xXa-fA-F+\-*/%() <>&|]+", cleaned):
        return ""
    result = cleaned
    for index, name in enumerate(param_names):
        result = re.sub(rf"\b{re.escape(name)}\b", f"${index}", result)
    if re.search(r"[A-Za-z_][A-Za-z0-9_]*", result):
        return ""
    return result


def _allocation_summary_for_call(
    expr: str,
    allocation_summaries: Sequence[_AllocationSummary],
) -> Optional[tuple[str, str]]:
    for callee, args in _iter_calls(expr):
        for summary in allocation_summaries:
            if callee not in summary.function_keys and _normalize_function_key(callee) not in summary.function_keys:
                continue
            capacity_expr = summary.capacity_expr
            for index, arg in enumerate(args):
                capacity_expr = capacity_expr.replace(f"${index}", f"({arg})")
            if "$" in capacity_expr:
                continue
            return capacity_expr, summary.source
    return None


def _resolve_heap_destination_expr(
    expr: str,
    aliases: Mapping[str, _HeapTarget],
) -> Optional[_HeapTarget]:
    cleaned = _normalize_pointer_expr(expr)
    if not cleaned:
        return None
    matches: list[tuple[int, int, str, _HeapTarget]] = []
    for name, target in aliases.items():
        position = _rooted_name_position(cleaned, name)
        if position is None:
            continue
        matches.append((position, -len(name), name, target))
    if not matches:
        return None
    _pos, _length, name, target = min(matches, key=lambda item: (item[0], item[1]))
    return replace(
        target,
        offset_expr=_combine_offsets(target.offset_expr, _offset_from_base(cleaned, name)),
    )


def _rhs_advances_heap_alias(rhs: str, aliases: Mapping[str, _HeapTarget]) -> bool:
    cleaned = _normalize_pointer_expr(rhs)
    for name in aliases:
        span = _identifier_span(cleaned, name)
        if span is None:
            continue
        without_name = f"{cleaned[:span[0]]}0{cleaned[span[1]:]}"
        if "+" in without_name or "-" in without_name or "*" in without_name:
            return True
    return False


def _stack_probe_alias(line: str, stack_index: _StackIndex) -> Optional[tuple[str, _AliasTarget]]:
    match = STACK_PROBE_ALIAS_RE.search(line)
    if not match:
        return None
    stack_obj = stack_index.find_buffer_for_var(match.group("stack"))
    if not stack_obj:
        return None
    return (
        match.group("alias"),
        _AliasTarget(stack_obj=dict(stack_obj), evidence_source="c_stack_probe"),
    )


def _rhs_advances_alias(rhs: str, aliases: Mapping[str, _AliasTarget]) -> bool:
    cleaned = _normalize_pointer_expr(rhs)
    for name in aliases:
        span = _identifier_span(cleaned, name)
        if span is None:
            continue
        without_name = f"{cleaned[:span[0]]}0{cleaned[span[1]:]}"
        if "+" in without_name or "-" in without_name or "*" in without_name:
            return True
    return False


def _for_step_advances_alias(line: str, name: str) -> bool:
    if "for" not in line or name not in line:
        return False
    match = re.search(r"\bfor\s*\((?P<init>[^;]*);(?P<cond>[^;]*);(?P<step>[^)]*)\)", line)
    if not match:
        return False
    step = match.group("step")
    escaped = re.escape(name)
    return bool(
        re.search(rf"\b{escaped}\b\s*\+\+", step)
        or re.search(rf"\+\+\s*\b{escaped}\b", step)
        or re.search(rf"\b{escaped}\b\s*\+=\s*[^;]+", step)
        or re.search(rf"\b{escaped}\b\s*=\s*\b{escaped}\b\s*[+\-]\s*[^;]+", step)
    )


def _resolve_stack_destination(
    expr: str,
    stack_index: _StackIndex,
    aliases: Mapping[str, _AliasTarget],
) -> Optional[_AliasTarget]:
    target = _resolve_destination_expr(expr, stack_index, aliases, ())
    if target and target.stack_obj is not None:
        return target
    return None


def _resolve_param_destination(
    expr: str,
    param_names: Sequence[str],
    aliases: Mapping[str, _AliasTarget],
) -> Optional[int]:
    target = _resolve_destination_expr(expr, _StackIndex(()), aliases, param_names)
    if target and target.param_index is not None:
        return target.param_index
    return None


def _resolve_destination_expr(
    expr: str,
    stack_index: _StackIndex,
    aliases: Mapping[str, _AliasTarget],
    param_names: Sequence[str],
) -> Optional[_AliasTarget]:
    cleaned = _normalize_pointer_expr(expr)
    if not cleaned:
        return None
    stack_matches: list[tuple[int, int, dict, str]] = []
    for obj in stack_index.buffer_objects:
        for name in obj.get("var_names") or []:
            var_name = str(name)
            position = _rooted_name_position(cleaned, var_name)
            if position is None:
                continue
            stack_matches.append((position, _safe_int(obj.get("size_bytes")), dict(obj), var_name))
    if stack_matches:
        _pos, _size, obj, var_name = min(stack_matches, key=lambda item: (item[0], item[1]))
        return _AliasTarget(
            stack_obj=obj,
            offset_expr=_combine_offsets(
                _member_offset_expr(obj, var_name),
                _offset_from_base(cleaned, var_name),
            ),
            evidence_source="c_text",
        )
    alias_matches: list[tuple[int, int, str, _AliasTarget]] = []
    for name, alias in aliases.items():
        position = _rooted_name_position(cleaned, name)
        if position is None:
            continue
        alias_matches.append((position, -len(name), name, alias))
    if alias_matches:
        _pos, _len, name, alias = min(alias_matches, key=lambda item: (item[0], item[1]))
        return replace(
            alias,
            offset_expr=_combine_offsets(alias.offset_expr, _offset_from_base(cleaned, name)),
        )
    param_matches: list[tuple[int, int, str]] = []
    for index, name in enumerate(param_names):
        position = _rooted_name_position(cleaned, name)
        if position is None:
            continue
        param_matches.append((position, index, name))
    if param_matches:
        _pos, index, name = min(param_matches, key=lambda item: (item[0], item[1]))
        return _AliasTarget(
            param_index=index,
            offset_expr=_offset_from_base(cleaned, name),
            evidence_source="param_alias",
        )
    return None


def _expr_is_rooted_at_name(expr: str, name: str) -> bool:
    return _rooted_name_position(_normalize_offset_expr(expr), name) is not None


def _rooted_name_position(expr: str, name: str) -> Optional[int]:
    if not expr or not name:
        return None
    name = str(name)
    if _starts_identifier_at(expr, name, 0):
        return 0
    if not expr.startswith("("):
        return None
    index = 1
    while index < len(expr) and expr[index].isspace():
        index += 1
    if not _starts_identifier_at(expr, name, index):
        return None
    after = index + len(name)
    while after < len(expr) and expr[after].isspace():
        after += 1
    return index if after < len(expr) and expr[after] == ")" else None


def _identifier_span(text: str, name: str) -> Optional[tuple[int, int]]:
    if not text or not name:
        return None
    start = 0
    while True:
        index = text.find(name, start)
        if index < 0:
            return None
        if _starts_identifier_at(text, name, index):
            return index, index + len(name)
        start = index + 1


def _starts_identifier_at(text: str, name: str, index: int) -> bool:
    end = index + len(name)
    if index < 0 or end > len(text) or text[index:end] != name:
        return False
    before = text[index - 1] if index > 0 else ""
    after = text[end] if end < len(text) else ""
    return not _is_identifier_char(before) and not _is_identifier_char(after)


def _is_identifier_char(char: str) -> bool:
    return bool(char) and (char.isalnum() or char == "_")


@lru_cache(maxsize=65536)
def _normalize_pointer_expr(expr: str) -> str:
    cleaned = _clean_expr(str(expr or "").rstrip(";"))
    cleaned = cleaned.rstrip(";").strip()
    while cleaned.startswith("&"):
        cleaned = cleaned[1:].strip()
    cleaned = ARRAY_EXPR_RE.sub(r"\g<base> + (\g<index>)", cleaned)
    cleaned = _strip_c_casts(cleaned).strip()
    while cleaned.startswith("&"):
        cleaned = cleaned[1:].strip()
    return cleaned


def _offset_from_base(expr: str, base_name: str) -> str:
    cleaned = _normalize_offset_expr(expr)
    span = _identifier_span(cleaned, base_name)
    replaced = f"{cleaned[:span[0]]}0{cleaned[span[1]:]}" if span is not None else cleaned
    replaced = _normalize_offset_expr(replaced)
    for prefix in ("0 +", "(0) +"):
        if replaced.startswith(prefix):
            replaced = replaced[len(prefix) :].strip()
    if replaced in {"", "0", "(0)"}:
        return ""
    return replaced


@lru_cache(maxsize=65536)
def _normalize_offset_expr(expr: str) -> str:
    cleaned = _strip_c_casts(_clean_expr(str(expr or "")))
    cleaned = cleaned.replace("(ulong)", "").replace("(long)", "")
    cleaned = WHITESPACE_RE.sub(" ", cleaned).strip()
    if cleaned.startswith("+"):
        cleaned = cleaned[1:].strip()
    return cleaned


def _strip_outer_parens(expr: str) -> str:
    text = str(expr or "").strip()
    while text.startswith("(") and text.endswith(")") and _outer_parens_are_balanced(text):
        text = text[1:-1].strip()
    return text


def _outer_parens_are_balanced(text: str) -> bool:
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(text) - 1:
                return False
    return depth == 0


def _combine_offsets(first: str, second: str) -> str:
    first = _normalize_offset_expr(first)
    second = _normalize_offset_expr(second)
    if not first or first == "0":
        return "" if second == "0" else second
    if not second or second == "0":
        return first
    return f"({first}) + ({second})"


def _combine_scaled_offset(base_offset: str, index_expr: str, scale: int) -> str:
    index_expr = _normalize_offset_expr(index_expr)
    if not index_expr:
        scaled = "0"
    elif scale == 1:
        scaled = index_expr
    else:
        scaled = f"({index_expr}) * {scale}"
    return _combine_offsets(base_offset, scaled)


def _pointer_summary_offset_scale(summary: _WriteSummary, default_scale: int) -> int:
    """Return the unit scale for a callee pointer-store offset expression."""
    dest_type = str(summary.dest_arg_type or "")
    if "*" not in dest_type:
        return 1
    return max(1, default_scale)


def _eval_optional_offset(expr: str, stack_index: _StackIndex) -> Optional[int]:
    expr = _normalize_offset_expr(expr)
    if not expr:
        return 0
    return _eval_int_expr(expr, stack_index)


def _mem_object_from_mapping(obj: Mapping[str, object]) -> MemObject:
    label = str(obj.get("var_display") or obj.get("label") or "memory_object")
    source = str(obj.get("capacity_source") or obj.get("capacity_basis_kind") or "")
    capacity_bytes = _safe_int(obj.get("size_bytes"))
    basis = str(obj.get("capacity_basis_kind") or "").lower()
    type_text = " ".join(str(item).lower() for item in obj.get("data_types") or [obj.get("type_display") or ""])
    if basis == "declared_address_taken_object" and capacity_bytes <= 1:
        if not re.search(r"\b(?:char|uchar|byte|uint8_t|undefined1?)\b", type_text):
            capacity_bytes = 0
    return MemObject(
        object_id=f"{obj.get('destination_kind') or 'stack'}:{label}",
        label=label,
        capacity_bytes=capacity_bytes,
        kind=str(obj.get("destination_kind") or "stack"),
        capacity_expr=str(obj.get("capacity_expr") or ""),
        capacity_source=source,
    )


def _offset_set_from_expr(expr: str, stack_index: _StackIndex) -> OffsetSet:
    return offset_set_from_expr(
        expr or "0",
        resolve_int=lambda value: _eval_optional_offset(value, stack_index),
    )


def _classify_memory_write(
    obj: Mapping[str, object],
    offset_expr: str,
    width_bytes: Optional[int],
    width_expr: str,
    stack_index: _StackIndex,
) -> tuple[str, str, str]:
    classification = classify_write(
        WriteSet(
            memory=_mem_object_from_mapping(obj),
            offsets=_offset_set_from_expr(offset_expr, stack_index),
            width_bytes=width_bytes,
            width_expr=width_expr,
        )
    )
    return classification.status, classification.relation, classification.condition


def _is_allocator_wrapper_heap(obj: Mapping[str, object]) -> bool:
    return str(obj.get("capacity_source") or "").startswith("allocator_wrapper:")


def _is_heap_object(obj: Mapping[str, object]) -> bool:
    return str(obj.get("destination_kind") or "") == "heap"


def _root_names_object(expr: str, obj: Mapping[str, object]) -> bool:
    root = _root_identifier(expr)
    if not root:
        return False
    return root in {str(name) for name in obj.get("var_names") or [] if name}


def _bounded_write_is_proven_safe(
    stack_obj: Mapping[str, object],
    target: _AliasTarget,
    write_size: int,
    stack_index: _StackIndex,
) -> bool:
    offset = _eval_optional_offset(target.offset_expr, stack_index)
    if offset is None or write_size < 0:
        return False
    capacity = _safe_int(stack_obj.get("size_bytes"))
    return 0 <= offset and offset + write_size <= capacity


def _bounded_write_is_proven_overflow(
    stack_obj: Mapping[str, object],
    target: _AliasTarget,
    write_size: int,
    stack_index: _StackIndex,
) -> bool:
    offset = _eval_optional_offset(target.offset_expr, stack_index)
    if offset is None or write_size < 0:
        return False
    capacity = _safe_int(stack_obj.get("size_bytes"))
    return offset < 0 or offset + write_size > capacity


def _capacity_is_proof_grade(obj: Mapping[str, object]) -> bool:
    source = str(obj.get("capacity_source") or obj.get("capacity_basis_kind") or "").lower()
    if source == "declared_local_array":
        return _bounded_byte_sink_stack_capacity_is_proof_grade(obj) or _stack_object_has_typed_array_extent(obj)
    if source == "ghidra_adjacent_global_extent":
        return True
    if _stack_object_has_typed_array_extent(obj):
        return True
    if source in GHIDRA_METADATA_CAPACITY_SOURCES:
        return False
    if str(obj.get("object_trust") or "").lower() == "metadata" and source.startswith("ghidra_"):
        return False
    return True


def _stack_object_has_typed_array_extent(obj: Mapping[str, object]) -> bool:
    if str(obj.get("destination_kind") or "stack") != "stack":
        return False
    capacity = _safe_int(obj.get("size_bytes"))
    if capacity <= 0:
        return False
    if _stack_object_has_declared_typed_array_extent(obj):
        return True
    type_texts = [str(item) for item in obj.get("data_types") or [] if item]
    if not type_texts and obj.get("type_display"):
        type_texts = [str(obj.get("type_display"))]
    for type_text in type_texts:
        known_size = _known_type_size(type_text)
        if known_size is not None and known_size > 1 and capacity > known_size and capacity % known_size == 0:
            return True
    return False


def _stack_object_has_declared_typed_array_extent(obj: Mapping[str, object]) -> bool:
    capacity = _safe_int(obj.get("size_bytes"))
    element_size = _safe_int(obj.get("declared_element_size_bytes"))
    element_count = _safe_int(obj.get("declared_element_count"))
    if capacity <= 0 or element_size <= 1 or element_count <= 0:
        return False
    return capacity == element_size * element_count


def _direct_object_extent_unknown_obj(obj: Mapping[str, object]) -> dict:
    if str(obj.get("destination_kind") or "stack") == "stack":
        return _direct_object_extent_unknown_stack_obj(obj)
    updated = dict(obj)
    label = str(updated.get("var_display") or updated.get("label") or "memory_object")
    original_capacity = _safe_int(updated.get("size_bytes"))
    original_source = str(updated.get("capacity_source") or updated.get("capacity_basis_kind") or "metadata")
    updated["size_bytes"] = 0
    updated["capacity_expr"] = f"object_extent({label})"
    updated["capacity_source"] = "direct_object_extent_unknown"
    updated["capacity_basis_kind"] = "direct_object_extent_unknown"
    updated["annotation"] = (
        f"{label}: direct object extent unknown; "
        f"Ghidra metadata modeled object as {original_capacity} bytes from {original_source}"
    )
    return updated


def _summary_unknown_extent_obj(
    obj: Mapping[str, object],
    evidence_sources: Sequence[str],
) -> tuple[Mapping[str, object], str, list[str]]:
    if str(obj.get("destination_kind") or "stack") == "stack":
        capacity_source = "interprocedural_object_extent_unknown"
        updated_obj = _object_extent_unknown_stack_obj(obj)
    else:
        capacity_source = "direct_object_extent_unknown"
        updated_obj = _direct_object_extent_unknown_obj(obj)
    updated_sources = list(evidence_sources)
    if capacity_source not in updated_sources:
        updated_sources.append(capacity_source)
    return updated_obj, capacity_source, updated_sources


def _demote_nonproof_capacity_overflow(
    obj: Mapping[str, object],
    evidence_sources: Sequence[str],
    condition: str,
) -> tuple[Mapping[str, object], Sequence[str], str] | None:
    if _capacity_is_proof_grade(obj):
        return None
    raw_capacity = _safe_int(obj.get("size_bytes"))
    source = str(obj.get("capacity_source") or obj.get("capacity_basis_kind") or "metadata")
    label = str(obj.get("var_display") or obj.get("label") or "memory object")
    updated_sources = list(evidence_sources)
    if "direct_object_extent_unknown" not in updated_sources:
        updated_sources.append("direct_object_extent_unknown")
    updated_condition = (
        f"{condition}; the {raw_capacity}-byte {source} extent for {label} "
        "is not treated as the full object capacity"
    )
    return _direct_object_extent_unknown_obj(obj), tuple(updated_sources), updated_condition


def _candidate_sources(base: str, target: _AliasTarget) -> list[str]:
    sources = [base]
    if target.evidence_source and target.evidence_source not in sources:
        sources.append(target.evidence_source)
    return sources


def _is_buffer_like_stack_obj(obj: Mapping[str, object]) -> bool:
    size = _safe_int(obj.get("size_bytes"))
    if size <= 0:
        return False
    kind = str(obj.get("capacity_basis_kind") or "").lower()
    if kind in {"contiguous_stack_region", "merged_stack_region"}:
        return False
    names = [str(item) for item in obj.get("var_names") or [] if item]
    if len(names) > 1 and not _looks_like_declared_array(obj) and kind != "inferred_stack_aggregate_extent":
        return False
    if names and all(_looks_like_generated_temp(name) for name in names) and not kind.startswith("declared_"):
        return False
    return True


def _summary_target_has_unknown_object_extent(
    summary: _WriteSummary,
    target: _AliasTarget,
    args: Sequence[str],
    stack_obj: Mapping[str, object],
    *,
    peer_summaries: Sequence[_WriteSummary] = (),
    call_text: str = "",
) -> bool:
    if summary.dest_arg_index >= len(args):
        return False
    if str(stack_obj.get("destination_kind") or "stack") != "stack":
        return False
    if _summary_writes_cxx_receiver_object(summary, call_text):
        return True
    if (
        summary.semantics in {"bounded", "append_bounded", "indexed_write", "pointer_store"}
        and _stack_obj_is_weak_declared_address_taken_object(stack_obj)
    ):
        return True
    arg_expr = args[summary.dest_arg_index]
    if summary.semantics in {"bounded", "append_bounded"}:
        if _caller_arg_has_object_pointer_cast(arg_expr):
            return True
        return _caller_arg_address_takes_weak_object(arg_expr, stack_obj)
    if summary.semantics not in {"indexed_write", "pointer_store"}:
        return False
    if _summary_writes_address_taken_word_object(summary, stack_obj):
        return True
    if (
        _caller_arg_has_decompiler_field_component(arg_expr)
        or _caller_arg_has_decompiler_field_component(target.offset_expr)
    ):
        return True
    strong_capacity = _interprocedural_capacity_is_strong(stack_obj)
    layout_object_head = _interprocedural_layout_is_probable_object_head(
        summary, args, stack_obj, peer_summaries
    )
    if strong_capacity and not layout_object_head:
        return False
    if target.evidence_source.startswith("c_stack_probe"):
        return True
    if _caller_arg_has_object_pointer_cast(arg_expr):
        return True
    if layout_object_head:
        return True
    return _caller_arg_address_takes_weak_object(arg_expr, stack_obj)


def _summary_writes_cxx_receiver_object(summary: _WriteSummary, call_text: str) -> bool:
    if summary.dest_arg_index != 0:
        return False
    function_name = str(summary.function_name or "")
    return "::" in function_name or _call_text_has_cxx_call(call_text)


def _caller_arg_has_decompiler_field_component(expr: str) -> bool:
    text = _normalize_offset_expr(expr)
    return bool(
        re.search(r"(?:^|[^A-Za-z0-9_])(?:[A-Za-z_][A-Za-z0-9_]*|0)\._\d+_\d+_", text)
    )


def _call_text_has_cxx_call(call_text: str) -> bool:
    text = str(call_text or "")
    if "::" not in text or "(" not in text:
        return False
    return bool(re.search(r"\b[A-Za-z_][A-Za-z0-9_:~<>]*::[A-Za-z_~][A-Za-z0-9_:~<>]*\s*\(", text))


def _interprocedural_capacity_is_strong(stack_obj: Mapping[str, object]) -> bool:
    kind = str(stack_obj.get("capacity_basis_kind") or stack_obj.get("capacity_source") or "").lower()
    if kind == "declared_local_array" or _looks_like_declared_array(stack_obj):
        return True
    if kind == "declared_address_taken_object":
        type_text = str(stack_obj.get("type_display") or " ".join(str(item) for item in stack_obj.get("data_types") or []))
        known_size = _known_type_size(type_text)
        return known_size is not None and known_size > 1 and _safe_int(stack_obj.get("size_bytes")) >= known_size
    return False


def _interprocedural_layout_is_probable_object_head(
    summary: _WriteSummary,
    args: Sequence[str],
    stack_obj: Mapping[str, object],
    peer_summaries: Sequence[_WriteSummary],
) -> bool:
    if summary.dest_arg_index >= len(args):
        return False
    kind = str(stack_obj.get("capacity_basis_kind") or stack_obj.get("capacity_source") or "").lower()
    if kind not in {"declared_local_array", "ghidra_stack_object"} and not _looks_like_declared_array(stack_obj):
        return False
    if _summary_dest_type_is_byte_pointer(summary):
        return False
    capacity = _safe_int(stack_obj.get("size_bytes"))
    if capacity <= 0:
        return False
    if not _caller_arg_is_stack_object_root_like(args[summary.dest_arg_index], stack_obj):
        return False
    offsets = _same_dest_fixed_summary_byte_offsets(summary, peer_summaries, stack_obj)
    return len(offsets) >= 3 and max(offsets) >= capacity + 16


def _summary_dest_type_is_byte_pointer(summary: _WriteSummary) -> bool:
    raw_type = str(summary.dest_arg_type or "")
    if "*" not in raw_type:
        return False
    return _pointer_cast_type_is_byte_pointer(raw_type.replace("*", ""))


def _pointer_cast_type_is_byte_pointer(raw_type: str) -> bool:
    canonical = _canonical_pointer_cast_type(raw_type)
    return canonical in {
        "byte",
        "char",
        "guint8",
        "int8_t",
        "schar",
        "uchar",
        "uint8",
        "uint8_t",
        "void",
        "undefined",
        "undefined1",
    }


def _caller_arg_is_bare_stack_root(expr: str, stack_obj: Mapping[str, object]) -> bool:
    if "&" in str(expr or "") or _pointer_cast_types(expr):
        return False
    return _caller_arg_is_stack_object_root_like(expr, stack_obj)


def _caller_arg_is_stack_object_root_like(expr: str, stack_obj: Mapping[str, object]) -> bool:
    if _pointer_cast_types(expr):
        return False
    cleaned = _normalize_pointer_expr(expr)
    root = _root_identifier(cleaned)
    if not root:
        return False
    names = {str(name) for name in stack_obj.get("var_names") or [] if name}
    if root not in names:
        return False
    return not _offset_from_base(cleaned, root)


def _same_dest_fixed_summary_offsets(
    summary: _WriteSummary,
    peer_summaries: Sequence[_WriteSummary],
) -> set[int]:
    offsets: set[int] = set()
    for peer in peer_summaries:
        if peer.dest_arg_index != summary.dest_arg_index:
            continue
        if peer.semantics not in {"indexed_write", "pointer_store"}:
            continue
        offset = _parse_int_literal(_normalize_offset_expr(peer.write_size_expr))
        if offset is not None:
            offsets.add(offset)
    return offsets


def _same_dest_fixed_summary_byte_offsets(
    summary: _WriteSummary,
    peer_summaries: Sequence[_WriteSummary],
    stack_obj: Mapping[str, object],
) -> set[int]:
    offsets: set[int] = set()
    element_size = _element_size(stack_obj)
    for peer in peer_summaries:
        if peer.dest_arg_index != summary.dest_arg_index:
            continue
        if peer.semantics not in {"indexed_write", "pointer_store"}:
            continue
        offset = _parse_int_literal(_normalize_offset_expr(peer.write_size_expr))
        if offset is None:
            continue
        if peer.semantics == "indexed_write":
            offset *= element_size
        offsets.add(offset)
    return offsets


def _caller_arg_has_object_pointer_cast(expr: str) -> bool:
    saw_pointer_cast = False
    for raw_type in _pointer_cast_types(expr):
        saw_pointer_cast = True
        if not _pointer_cast_type_is_scalar_or_byte(raw_type):
            return True
    return False if saw_pointer_cast else False


def _pointer_cast_types(expr: str) -> list[str]:
    pattern = re.compile(
        r"\(\s*"
        r"(?P<type>"
        r"(?:(?:const|volatile|restrict|struct|class|union|enum|unsigned|signed)\s+)*"
        r"[A-Za-z_][A-Za-z0-9_:<>]*"
        r"(?:\s+[A-Za-z_][A-Za-z0-9_:<>]*)*"
        r")\s*\*\s*\)"
    )
    return [match.group("type") for match in pattern.finditer(str(expr or ""))]


def _pointer_cast_type_is_scalar_or_byte(raw_type: str) -> bool:
    canonical = _canonical_pointer_cast_type(raw_type)
    if not canonical:
        return True
    scalar_types = {
        "bool",
        "byte",
        "char",
        "double",
        "float",
        "guint",
        "guint8",
        "int",
        "int8_t",
        "int16_t",
        "int32_t",
        "long",
        "schar",
        "short",
        "size_t",
        "uchar",
        "uint",
        "uint8",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "ulong",
        "ushort",
        "void",
        "undefined",
        "undefined1",
        "undefined2",
        "undefined4",
        "undefined8",
    }
    return canonical in scalar_types


def _canonical_pointer_cast_type(raw_type: str) -> str:
    text = str(raw_type or "").strip().lower()
    text = text.replace("::", " ")
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)
    qualifiers = {
        "class",
        "const",
        "enum",
        "restrict",
        "signed",
        "struct",
        "union",
        "unsigned",
        "volatile",
    }
    tokens = [token.lstrip("_") for token in tokens if token not in qualifiers]
    if not tokens:
        return ""
    return _normalize_c_type(" ".join(tokens)).replace(" ", "")


def _caller_arg_address_takes_weak_object(expr: str, stack_obj: Mapping[str, object]) -> bool:
    if "&" not in str(expr or ""):
        return False
    root = _root_identifier(_normalize_pointer_expr(expr))
    names = {str(name) for name in stack_obj.get("var_names") or [] if name}
    if root and names and root not in names:
        return False
    kind = str(stack_obj.get("capacity_basis_kind") or "").lower()
    if kind == "declared_address_taken_object":
        return not _interprocedural_capacity_is_strong(stack_obj)
    capacity = _safe_int(stack_obj.get("size_bytes"))
    if capacity <= 0:
        return True
    if capacity > 8 and _stack_object_has_byte_element_type(stack_obj):
        return False
    if names and all(_looks_like_raw_stack_slot_name(name) for name in names):
        return False
    return capacity <= 8 or not _stack_object_has_byte_element_type(stack_obj)


def _stack_obj_is_weak_declared_address_taken_object(stack_obj: Mapping[str, object]) -> bool:
    kind = str(stack_obj.get("capacity_basis_kind") or stack_obj.get("capacity_source") or "").lower()
    if kind != "declared_address_taken_object":
        return False
    return not _interprocedural_capacity_is_strong(stack_obj)


def _summary_writes_address_taken_word_object(
    summary: _WriteSummary,
    stack_obj: Mapping[str, object],
) -> bool:
    if summary.semantics not in {"indexed_write", "pointer_store"}:
        return False
    kind = str(stack_obj.get("capacity_basis_kind") or stack_obj.get("capacity_source") or "").lower()
    if kind != "declared_address_taken_object":
        return False
    if _safe_int(stack_obj.get("size_bytes")) != 8:
        return False
    if _looks_like_declared_array(stack_obj) or _stack_object_has_byte_element_type(stack_obj):
        return False
    return True


def _stack_object_has_byte_element_type(obj: Mapping[str, object]) -> bool:
    type_texts = [str(item) for item in obj.get("data_types") or []]
    if not type_texts and obj.get("type_display"):
        type_texts = [str(obj.get("type_display"))]
    for type_text in type_texts:
        lowered = type_text.lower()
        if "[" in lowered and "]" in lowered:
            continue
        canonical = _canonical_pointer_cast_type(lowered)
        if canonical in {"byte", "char", "guint8", "int8_t", "schar", "uchar", "uint8", "uint8_t", "undefined", "undefined1"}:
            return True
    return False


def _looks_like_raw_stack_slot_name(name: str) -> bool:
    return bool(RAW_STACK_SLOT_RE.fullmatch(str(name or "")))


def _member_offset_expr(obj: Mapping[str, object], name: str) -> str:
    member_offsets = obj.get("member_offsets")
    if not isinstance(member_offsets, Mapping):
        return ""
    offset = _safe_int(member_offsets.get(str(name)))
    return "" if offset == 0 else str(offset)


def _object_extent_unknown_stack_obj(stack_obj: Mapping[str, object]) -> dict:
    obj = dict(stack_obj)
    label = str(obj.get("var_display") or obj.get("label") or "stack_object")
    original_capacity = _safe_int(obj.get("size_bytes"))
    obj["size_bytes"] = 0
    obj["capacity_expr"] = f"caller_object_extent({label})"
    obj["capacity_source"] = "interprocedural_object_extent_unknown"
    obj["capacity_basis_kind"] = "interprocedural_object_extent_unknown"
    obj["annotation"] = (
        f"{label}: interprocedural object extent unknown; "
        f"decompiler modeled local fragment as {original_capacity} bytes"
    )
    return obj


def _direct_object_extent_unknown_stack_obj(stack_obj: Mapping[str, object]) -> dict:
    obj = dict(stack_obj)
    label = str(obj.get("var_display") or obj.get("label") or "stack_object")
    original_capacity = _safe_int(obj.get("size_bytes"))
    obj["size_bytes"] = 0
    obj["capacity_expr"] = f"object_extent({label})"
    obj["capacity_source"] = "direct_object_extent_unknown"
    obj["capacity_basis_kind"] = "direct_object_extent_unknown"
    obj["annotation"] = (
        f"{label}: direct object extent unknown; "
        f"decompiler modeled local fragment as {original_capacity} bytes"
    )
    return obj


def _bounded_byte_sink_has_unknown_direct_extent(
    sink: str,
    semantics: str,
    stack_obj: Mapping[str, object],
    write_size: Optional[int],
) -> bool:
    if not _bounded_byte_sink_uses_stack_capacity(sink, semantics, stack_obj):
        return False
    if write_size is None:
        return False
    capacity = _safe_int(stack_obj.get("size_bytes"))
    if capacity <= 0 or write_size <= capacity:
        return False
    if not _bounded_byte_sink_stack_capacity_is_proof_grade(stack_obj):
        return True
    kind = str(stack_obj.get("capacity_basis_kind") or stack_obj.get("capacity_source") or "").lower()
    if kind != "declared_local_array":
        return False
    names = [str(name) for name in stack_obj.get("var_names") or [] if name]
    if not any(_looks_like_raw_stack_slot_name(name) for name in names):
        return False
    if _stack_object_has_byte_element_type(stack_obj):
        return False
    if _stack_object_has_declared_typed_array_extent(stack_obj):
        return False
    type_texts = [str(item) for item in stack_obj.get("data_types") or [] if item]
    if not type_texts and stack_obj.get("type_display"):
        type_texts = [str(stack_obj.get("type_display"))]
    return bool(type_texts) and all(_known_type_size(type_text) is None for type_text in type_texts)


def _bounded_byte_sink_uses_nonproof_stack_capacity(
    sink: str,
    semantics: str,
    stack_obj: Mapping[str, object],
) -> bool:
    return (
        _bounded_byte_sink_uses_stack_capacity(sink, semantics, stack_obj)
        and not _bounded_byte_sink_stack_capacity_is_proof_grade(stack_obj)
    )


def _bounded_byte_sink_uses_stack_capacity(
    sink: str,
    semantics: str,
    stack_obj: Mapping[str, object],
) -> bool:
    if semantics != "bounded":
        return False
    spec = OPERATION_SPECS.get(_normalize_sink_name(sink), {})
    if str(spec.get("units") or "") != "bytes":
        return False
    return str(stack_obj.get("destination_kind") or "stack") == "stack"


def _bounded_byte_sink_stack_capacity_is_proof_grade(stack_obj: Mapping[str, object]) -> bool:
    kind = str(stack_obj.get("capacity_basis_kind") or stack_obj.get("capacity_source") or "").lower()
    if kind in {"ghidra_stack_object", "inferred_stack_aggregate_extent"}:
        return False
    if kind == "declared_local_array":
        names = [str(name) for name in stack_obj.get("var_names") or [] if name]
        if any(_looks_like_raw_stack_slot_name(name) for name in names):
            return _stack_object_has_byte_element_type(stack_obj) or _stack_object_has_declared_typed_array_extent(stack_obj)
    return True


def _looks_like_generated_temp(name: str) -> bool:
    return bool(GENERATED_TEMP_RE.fullmatch(str(name or "")))


def _stack_region_identity(region: Mapping[str, object]) -> tuple[int, int, int, tuple[str, ...]]:
    return (
        _safe_int(region.get("index")),
        _safe_int(region.get("start_offset")),
        _safe_int(region.get("end_offset")),
        tuple(str(name) for name in region.get("var_names") or [] if name),
    )


def _raw_byte_stack_aggregates(exact_regions: Sequence[dict]) -> tuple[list[dict], set[tuple[int, int, int, tuple[str, ...]]]]:
    aggregates: list[dict] = []
    consumed: set[tuple[int, int, int, tuple[str, ...]]] = set()
    current: list[dict] = []

    def flush() -> None:
        nonlocal current
        if _raw_byte_stack_group_is_aggregate(current):
            obj = _raw_byte_stack_group_object(current, len(aggregates) + 1)
            aggregates.append(obj)
            consumed.update(_stack_region_identity(region) for region in current)
        current = []

    for region in sorted(
        (dict(item) for item in exact_regions),
        key=lambda item: (_safe_int(item.get("start_offset")), _safe_int(item.get("end_offset"))),
    ):
        if not _is_raw_byte_stack_fragment(region):
            flush()
            continue
        current_end = max((_safe_int(item.get("end_offset")) for item in current), default=None)
        if current_end is not None and _safe_int(region.get("start_offset")) > current_end:
            flush()
        current.append(region)
    flush()
    return aggregates, consumed


def _raw_byte_stack_group_is_aggregate(regions: Sequence[Mapping[str, object]]) -> bool:
    if len(regions) < 2:
        return False
    if not any(_safe_int(region.get("size_bytes")) == 1 for region in regions):
        return False
    if not any(_stack_region_type_has_array(region) or _safe_int(region.get("size_bytes")) > 1 for region in regions):
        return False
    start = min(_safe_int(region.get("start_offset")) for region in regions)
    end = max(_safe_int(region.get("end_offset")) for region in regions)
    total_size = max(0, end - start)
    return total_size > max(_safe_int(region.get("size_bytes")) for region in regions)


def _raw_byte_stack_group_object(regions: Sequence[Mapping[str, object]], index: int) -> dict:
    start = min(_safe_int(region.get("start_offset")) for region in regions)
    end = max(_safe_int(region.get("end_offset")) for region in regions)
    size = max(0, end - start)
    var_names: list[str] = []
    data_types: list[str] = []
    member_offsets: dict[str, int] = {}
    member_sizes: dict[str, int] = {}
    for region in regions:
        region_start = _safe_int(region.get("start_offset"))
        region_size = _safe_int(region.get("size_bytes"))
        for name in [str(item) for item in region.get("var_names") or [] if item]:
            if name not in var_names:
                var_names.append(name)
            member_offsets[name] = max(0, region_start - start)
            member_sizes[name] = region_size
        for data_type in [str(item) for item in region.get("data_types") or [] if item]:
            if data_type not in data_types:
                data_types.append(data_type)
    label = f"{var_names[0]}..{var_names[-1]}" if var_names else f"raw_stack_aggregate_{index}"
    offset_range = f"[{_format_offset(start)}..{_format_offset(end)}]"
    return {
        "index": index,
        "label": label,
        "start_offset": start,
        "end_offset": end,
        "offset_range": offset_range,
        "size_bytes": size,
        "size_hex": f"0x{size:x}",
        "var_names": var_names,
        "var_display": "/".join(var_names) if var_names else label,
        "data_types": data_types,
        "type_display": "/".join(data_types) if data_types else "(unknown)",
        "member_offsets": member_offsets,
        "member_sizes": member_sizes,
        "member_count": len(regions),
        "members": [dict(region) for region in regions],
        "annotation": f"{label}: inferred contiguous raw byte stack object, stack{offset_range}, {size} bytes",
        "capacity_source": "inferred_stack_aggregate_extent",
        "capacity_basis_kind": "inferred_stack_aggregate_extent",
        "stack_offset_known": True,
    }


def _is_raw_byte_stack_fragment(region: Mapping[str, object]) -> bool:
    names = [str(name) for name in region.get("var_names") or [] if name]
    if len(names) != 1 or not _looks_like_raw_stack_slot_name(names[0]):
        return False
    if _safe_int(region.get("size_bytes")) <= 0:
        return False
    return _stack_region_type_is_byte_storage(region)


def _stack_region_type_is_byte_storage(region: Mapping[str, object]) -> bool:
    data_types = [str(item) for item in region.get("data_types") or [] if item]
    if not data_types and region.get("type_display"):
        data_types = [str(region.get("type_display"))]
    if not data_types:
        return False
    return all(_type_text_is_byte_storage(data_type) for data_type in data_types)


def _stack_region_type_has_array(region: Mapping[str, object]) -> bool:
    return any("[" in str(data_type) and "]" in str(data_type) for data_type in region.get("data_types") or [])


def _type_text_is_byte_storage(type_text: str) -> bool:
    lowered = str(type_text or "").lower()
    if "*" in lowered:
        return False
    element_type = lowered.split("[", 1)[0].strip()
    canonical = _canonical_pointer_cast_type(element_type)
    return canonical in {"byte", "char", "guint8", "int8_t", "schar", "uchar", "uint8", "uint8_t", "undefined", "undefined1"}


def _stack_objects_for_node(node: FunctionNode, exact_regions: Sequence[dict]) -> list[dict]:
    objects: list[dict] = []
    seen_vars: set[str] = set()
    ambiguous_vars: set[str] = set()
    aggregate_objects, aggregate_members = _raw_byte_stack_aggregates(exact_regions)
    for obj in aggregate_objects:
        objects.append(obj)
        seen_vars.update(str(name) for name in obj.get("var_names") or [] if name)
    for region in exact_regions:
        if _stack_region_identity(region) in aggregate_members:
            continue
        obj = dict(region)
        var_names = [str(name) for name in obj.get("var_names") or [] if name]
        if len(var_names) > 1 and not _looks_like_declared_array(obj):
            ambiguous_vars.update(var_names)
            continue
        obj["stack_offset_known"] = True
        obj.setdefault("capacity_source", "ghidra_stack_object")
        obj.setdefault("capacity_basis_kind", obj.get("capacity_source") or "ghidra_stack_object")
        objects.append(obj)
        seen_vars.update(var_names)

    for declared in _declared_stack_objects(node.text or ""):
        name = str(declared["name"])
        existing_for_name = [
            obj
            for obj in objects
            if name in {str(item) for item in obj.get("var_names") or []}
        ]
        if name in seen_vars:
            if declared.get("kind") != "declared_local_array":
                continue
            size = int(declared["size_bytes"])
            if not existing_for_name or any(len(obj.get("var_names") or []) > 1 for obj in existing_for_name):
                continue
            if all(_safe_int(obj.get("size_bytes")) >= size for obj in existing_for_name):
                for obj in existing_for_name:
                    if _safe_int(obj.get("size_bytes")) != size:
                        continue
                    start_offset = _safe_int(obj.get("start_offset"))
                    offset_range = f"[{_format_offset(start_offset)}..{_format_offset(start_offset + size)}]"
                    obj["offset_range"] = offset_range
                    obj["annotation"] = f"{name}: declared local stack object, stack{offset_range}, {size} bytes"
                    obj["data_types"] = [str(declared["data_type"])]
                    obj["type_display"] = str(declared["data_type"])
                    obj["capacity_source"] = str(declared["kind"])
                    obj["capacity_basis_kind"] = str(declared["kind"])
                continue
            objects = [
                obj
                for obj in objects
                if name not in {str(item) for item in obj.get("var_names") or []}
            ]
            seen_vars.discard(name)
        if name in ambiguous_vars and declared.get("kind") != "declared_local_array":
            continue
        size = int(declared["size_bytes"])
        existing_with_offset = next(
            (obj for obj in existing_for_name if obj.get("stack_offset_known")),
            None,
        )
        start_offset = _safe_int(existing_with_offset.get("start_offset")) if existing_with_offset else 0
        offset_known = existing_with_offset is not None
        offset_range = (
            f"[{_format_offset(start_offset)}..{_format_offset(start_offset + size)}]"
            if offset_known
            else "[?.. ?]"
        )
        annotation = (
            f"{name}: declared local stack object, stack{offset_range}, {size} bytes"
            if offset_known
            else f"{name}: declared local stack object, {size} bytes"
        )
        objects.append(
            {
                "index": len(objects) + 1,
                "label": name,
                "start_offset": start_offset,
                "end_offset": start_offset + size,
                "offset_range": offset_range,
                "size_bytes": size,
                "size_hex": f"0x{size:x}",
                "var_names": [name],
                "var_display": name,
                "data_types": [str(declared["data_type"])],
                "type_display": str(declared["data_type"]),
                "annotation": annotation,
                "capacity_source": str(declared["kind"]),
                "capacity_basis_kind": str(declared["kind"]),
                "stack_offset_known": offset_known,
            }
        )
        seen_vars.add(name)
    return objects


def _non_stack_objects_for_node(
    node: FunctionNode,
    stack_objects: Sequence[Mapping[str, object]] = (),
    code_lines: Sequence[str] = (),
    *,
    global_extent_index: Mapping[str, Mapping[str, object]] | None = None,
) -> list[dict]:
    objects: list[dict] = []
    record = node.record
    global_extent_index = global_extent_index or {}
    for attr, kind, source in (
        ("global_refs", "global", "ghidra_global_ref"),
        ("static_refs", "static_local", "ghidra_static_ref"),
        ("tls_refs", "tls", "ghidra_tls_ref"),
    ):
        for entry in getattr(record, attr, []) or []:
            obj = dict(entry)
            label = str(obj.get("var_display") or obj.get("label") or obj.get("name") or obj.get("address") or kind)
            obj.setdefault("label", label)
            obj.setdefault("var_display", label)
            obj.setdefault("var_names", [label])
            obj.setdefault("destination_kind", kind)
            obj.setdefault("capacity_source", source)
            obj.setdefault("capacity_basis_kind", source)
            obj.setdefault("annotation", f"{label}: {kind} object from {source}")
            _apply_global_extent(obj, global_extent_index)
            objects.append(obj)

    base_objects = {str(obj.get("label") or obj.get("var_display") or ""): obj for obj in objects}
    base_objects.update(
        {
            str(obj.get("label") or obj.get("var_display") or ""): obj
            for obj in stack_objects
        }
    )
    for field in getattr(record, "composite_fields", []) or []:
        base = str(field.get("base") or field.get("base_label") or "")
        field_path = str(field.get("field_path") or field.get("name") or "")
        if not field_path:
            continue
        label = f"{base}.{field_path}" if base else field_path
        size = _safe_int(field.get("field_capacity") or field.get("size_bytes") or field.get("length"))
        base_obj = base_objects.get(base, {})
        objects.append(
            {
                "label": label,
                "var_display": label,
                "var_names": [label],
                "size_bytes": size,
                "capacity_expr": str(field.get("capacity_expr") or ""),
                "destination_kind": "struct_field",
                "capacity_source": str(field.get("source") or "ghidra_composite_field"),
                "capacity_basis_kind": "composite_field",
                "annotation": f"{label}: struct field, {size or 'symbolic'} bytes",
                "field_path": field_path,
                "field_offset": field.get("field_offset") or field.get("offset"),
                "element_stride": field.get("element_stride") or field.get("stride"),
                "field_capacity": size,
                "base_object_id": str(base_obj.get("object_id") or base),
            }
        )
    existing_names = {
        str(name)
        for obj in objects
        for name in ([obj.get("label"), obj.get("var_display")] + list(obj.get("var_names") or []))
        if name
    }
    objects.extend(_inferred_static_objects_for_node(node, existing_names, code_lines))
    return objects


def _build_global_extent_index(nodes: Sequence[FunctionNode]) -> dict[str, dict[str, object]]:
    refs: dict[tuple[str, str, int], dict[str, object]] = {}
    for node in nodes:
        record = node.record
        for attr, kind in (
            ("global_refs", "global"),
            ("static_refs", "static_local"),
            ("tls_refs", "tls"),
        ):
            for entry in getattr(record, attr, []) or []:
                address = _parse_address_int(entry.get("address"))
                if address is None:
                    continue
                block = str(entry.get("block") or "")
                if block not in {".bss", ".data", ".sbss", ".sdata"}:
                    continue
                refs.setdefault((kind, block, address), dict(entry))

    extents: dict[str, dict[str, object]] = {}
    groups: dict[tuple[str, str], list[tuple[int, dict[str, object]]]] = {}
    for (kind, block, address), entry in refs.items():
        groups.setdefault((kind, block), []).append((address, entry))

    for (kind, block), entries in groups.items():
        entries.sort(key=lambda item: item[0])
        for index, (address, entry) in enumerate(entries[:-1]):
            next_address = _next_global_boundary(entries, index)
            if next_address is None:
                continue
            extent = next_address - address
            declared = _safe_int(entry.get("size_bytes"))
            if extent <= max(declared, 0):
                continue
            payload = {
                "size_bytes": extent,
                "capacity_source": "ghidra_adjacent_global_extent",
                "capacity_basis_kind": "ghidra_adjacent_global_extent",
                "annotation": (
                    f"{entry.get('var_display') or entry.get('label') or hex(address)}: "
                    f"{kind} object extent from adjacent {block} references, {extent} bytes"
                ),
            }
            for key in _global_extent_keys(entry):
                extents[key] = payload
    return extents


def _next_global_boundary(entries: Sequence[tuple[int, Mapping[str, object]]], index: int) -> int | None:
    address, entry = entries[index]
    declared = _safe_int(entry.get("size_bytes"))
    for next_address, next_entry in entries[index + 1 :]:
        gap = next_address - address
        if gap <= 0:
            continue
        if declared <= 1 and _safe_int(next_entry.get("size_bytes")) <= 1 and gap < 8:
            continue
        return next_address
    return None


def _apply_global_extent(obj: MutableMapping[str, object], extent_index: Mapping[str, Mapping[str, object]]) -> None:
    current = _safe_int(obj.get("size_bytes"))
    if current > 1:
        return
    for key in _global_extent_keys(obj):
        extent = extent_index.get(key)
        if not extent:
            continue
        size = _safe_int(extent.get("size_bytes"))
        if size <= current:
            continue
        obj["size_bytes"] = size
        obj["capacity_expr"] = str(size)
        obj["capacity_source"] = str(extent.get("capacity_source") or "ghidra_adjacent_global_extent")
        obj["capacity_basis_kind"] = str(extent.get("capacity_basis_kind") or "ghidra_adjacent_global_extent")
        obj["annotation"] = str(extent.get("annotation") or obj.get("annotation") or "")
        obj["data_types"] = [f"undefined1[{size}]"]
        obj["type_display"] = f"undefined1[{size}]"
        return


def _global_extent_keys(entry: Mapping[str, object]) -> list[str]:
    keys = []
    for raw in (
        entry.get("label"),
        entry.get("var_display"),
        entry.get("name"),
        entry.get("address"),
    ):
        value = str(raw or "").strip()
        if value and value not in keys:
            keys.append(value)
    address = _parse_address_int(entry.get("address"))
    if address is not None:
        for value in (f"0x{address:x}", f"0x{address:X}"):
            if value not in keys:
                keys.append(value)
    return keys


def _parse_address_int(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _inferred_static_objects_for_node(
    node: FunctionNode,
    existing_names: set[str],
    code_lines: Sequence[str] = (),
) -> list[dict]:
    capacities: dict[str, int] = {}
    source_text = node.text or ""
    if not any(token in source_text for token in ("memcpy", "memmove", "memset")):
        return []
    lines = list(code_lines) if code_lines else _strip_c_comments(source_text.splitlines())
    for line in lines:
        for sink, args in _iter_sink_calls(line):
            if sink not in {"memcpy", "memmove", "memset"} or len(args) < 3:
                continue
            hint = _remaining_capacity_static_hint(args[0], args[2])
            if hint is None:
                continue
            name, capacity = hint
            if name in existing_names or not _looks_like_unmodeled_static_buffer_name(name):
                continue
            capacities[name] = max(capacity, capacities.get(name, 0))
    return [
        {
            "label": name,
            "var_display": name,
            "var_names": [name],
            "size_bytes": capacity,
            "capacity_expr": str(capacity),
            "destination_kind": "static_local",
            "capacity_source": "inferred_static_remaining_size",
            "capacity_basis_kind": "inferred_static_remaining_size",
            "annotation": f"{name}: inferred static buffer, {capacity} bytes",
            "data_types": [f"undefined1[{capacity}]"],
            "type_display": f"undefined1[{capacity}]",
        }
        for name, capacity in sorted(capacities.items())
        if capacity > 0
    ]


def _remaining_capacity_static_hint(dest_expr: str, size_expr: str) -> tuple[str, int] | None:
    root = _root_identifier(dest_expr)
    if not root:
        return None
    offset_expr = _offset_from_base(_normalize_pointer_expr(dest_expr), root)
    if not offset_expr:
        return None
    size_text = _strip_outer_parens(_normalize_offset_expr(size_expr))
    match = re.match(r"^(?P<capacity>0x[0-9a-fA-F]+|\d+)\s*-\s*(?P<offset>.+)$", size_text)
    if not match:
        return None
    if _strip_outer_parens(_normalize_offset_expr(match.group("offset"))) != _strip_outer_parens(_normalize_offset_expr(offset_expr)):
        return None
    capacity = _parse_int_literal(match.group("capacity"))
    if capacity is None or capacity <= 0:
        return None
    return root, capacity


def _looks_like_unmodeled_static_buffer_name(name: str) -> bool:
    if not re.search(r"_[0-9]+$", name):
        return False
    if name.startswith(("local_", "uStack_", "auStack_", "puVar", "pcVar", "pbVar", "piVar", "iVar", "uVar", "lVar")):
        return False
    return not _looks_like_generated_temp(name)


def _looks_like_declared_array(obj: Mapping[str, object]) -> bool:
    for data_type in obj.get("data_types") or []:
        if "[" in str(data_type) and "]" in str(data_type):
            return True
    return False


def _declared_stack_objects(source_text: str) -> list[dict[str, object]]:
    objects: list[dict[str, object]] = []
    address_taken = set(re.findall(r"&\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b", source_text or ""))
    for match in DECLARED_ARRAY_RE.finditer(source_text or ""):
        raw_type = _normalize_c_type(match.group("type"))
        count = int(match.group("count"))
        objects.append(
            {
                "name": match.group("name"),
                "data_type": raw_type,
                "count": count,
                "size_bytes": count * _type_size(raw_type),
                "kind": "declared_local_array",
            }
        )
    existing = {str(item["name"]) for item in objects}
    for match in DECLARED_OBJECT_RE.finditer(source_text or ""):
        name = match.group("name")
        if name in existing or name not in address_taken:
            continue
        raw_type = _normalize_c_type(match.group("type"))
        if "*" in raw_type:
            continue
        objects.append(
            {
                "name": name,
                "data_type": raw_type,
                "count": 1,
                "size_bytes": _type_size(raw_type),
                "kind": "declared_address_taken_object",
            }
        )
    return objects


def _normalize_c_type(raw_type: str) -> str:
    return " ".join(str(raw_type or "").lower().replace("unsigned", "").split())


def _type_size(raw_type: str) -> int:
    return TYPE_SIZES.get(raw_type, 1)


def _known_type_size(raw_type: str) -> Optional[int]:
    return TYPE_SIZES.get(_normalize_c_type(raw_type))


def _should_skip_node(node: FunctionNode, code_lines: Sequence[str] | None = None) -> bool:
    record = node.record
    if str(getattr(record, "name", "") or "").startswith("__pfx_"):
        return True
    if getattr(record, "is_thunk", False):
        return True
    if getattr(record, "wrapper_type", None) in {"plt_thunk", "single_call_wrapper", "indirect_forward"}:
        return True
    if getattr(record, "stub_kind", None) in {"wrapper", "single_call_wrapper", "tiny_body"}:
        return True
    if _looks_like_unlabeled_transparent_wrapper(node, code_lines):
        return True
    if not (node.text or "").strip() and not (record.pcode_calls or record.pcode_stores):
        return True
    return False


def _looks_like_unlabeled_transparent_wrapper(node: FunctionNode, code_lines: Sequence[str] | None = None) -> bool:
    if node.record.pcode_stores:
        return False
    for entry in node.record.pcode_calls or []:
        callee = _normalize_sink_name(str(entry.get("callee") or entry.get("function") or ""))
        if callee in ALL_SINKS:
            return False
    lines = list(code_lines) if code_lines is not None else _strip_c_comments((node.text or "").splitlines())
    masked = "\n".join(_mask_string_literals(line) for line in lines)
    if not masked.strip():
        return False
    if _text_may_contain_sink_call(masked) and any(True for _sink, _args in _iter_sink_calls(masked)):
        return False
    if (_line_may_contain_index_write(masked) and INDEX_WRITE_RE.search(masked)) or (
        _line_may_contain_pointer_store(masked) and re.search(r"\*\s*[^=;]+=", masked)
    ):
        return False
    if re.search(r"\b(?:if|for|while|switch)\b", masked):
        return False
    body = _function_body(masked)
    if "[" in body:
        return False
    calls = [
        name
        for name, _args in _iter_calls(masked)
        if _normalize_function_key(name) != _normalize_function_key(node.record.name)
    ]
    if len(calls) != 1 or len(_unique_nonempty(calls)) != 1:
        return False
    if re.search(r"(?<![=!<>])=(?!=)", body):
        return False
    return True


def _function_body(text: str) -> str:
    open_index = text.find("{")
    close_index = text.rfind("}")
    if open_index < 0 or close_index <= open_index:
        return text
    return text[open_index + 1 : close_index]


def _extract_pcode_call_candidates(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    *,
    use_memory_sets: bool = False,
) -> list[StaticCandidate]:
    candidates: list[StaticCandidate] = []
    for entry in node.record.pcode_calls or []:
        sink = _normalize_sink_name(str(entry.get("callee") or entry.get("function") or ""))
        spec = OPERATION_SPECS.get(sink)
        if not spec:
            continue
        args = _pcode_args(entry)
        operation_address = str(entry.get("call_address") or entry.get("address") or "")
        semantics = str(spec.get("semantics") or "")
        if semantics == "unbounded":
            dest_index = int(spec["dest_arg"])
            stack_obj = _pcode_stack_arg(args, dest_index, stack_index)
            if not stack_obj:
                continue
            if _fortified_pcode_call_cannot_overflow(spec, args, stack_obj):
                continue
            evidence_sources: Sequence[str] = ["pcode_calls"]
            verdict = "unbounded"
            write_relation = "unbounded"
            condition = f"{sink} has no destination bound"
            demoted = _demote_nonproof_capacity_overflow(stack_obj, evidence_sources, condition)
            if demoted is not None:
                stack_obj, evidence_sources, condition = demoted
                verdict = "candidate"
                write_relation = "symbolic_capacity"
            candidates.append(
                _build_candidate(
                    manifest,
                    node,
                    stack_obj,
                    kind="call",
                    sink=sink,
                    line_number=0,
                    line=f"{sink}(...)",
                    write_size_expr="unbounded",
                    write_size_bytes=None,
                    verdict=verdict,
                    overflow_condition=condition,
                    source_evidence=source_evidence,
                    evidence_sources=evidence_sources,
                    operation_address=operation_address,
                    write_relation=write_relation,
                    offset_expr="0",
                )
            )
            continue
        if semantics in {"bounded", "append_bounded"}:
            dest_index = int(spec["dest_arg"])
            size_index = int(spec["size_arg"])
            stack_obj, dest_offset_expr = _pcode_stack_target(args, dest_index, stack_index)
            if not stack_obj:
                continue
            write_size = _pcode_constant_arg(args, size_index)
            write_expr = _pcode_arg_expr(args, size_index) or "unknown"
            if _fortified_pcode_call_cannot_overflow(
                spec,
                args,
                stack_obj,
                write_size=write_size,
            ):
                continue
            if use_memory_sets and semantics == "bounded":
                candidate = _bounded_memory_set_candidate(
                    manifest,
                    node,
                    stack_index,
                    stack_obj,
                    dest_offset_expr,
                    ["pcode_calls"],
                    source_evidence,
                    0,
                    f"{sink}(...)",
                    sink,
                    semantics,
                    write_expr,
                    operation_address=operation_address,
                )
                if candidate is not None:
                    candidates.append(candidate)
                continue
            capacity = _safe_int(stack_obj.get("size_bytes"))
            if (
                semantics == "bounded"
                and write_size is not None
                and write_size <= capacity
            ):
                continue
            if semantics == "append_bounded" and write_size is not None and write_size <= capacity:
                verdict = "candidate"
                condition = (
                    f"{sink} appends up to {write_size} bytes, but the current destination "
                    f"length is unknown for {capacity}-byte storage"
                )
                write_relation = "append_length_unknown"
            else:
                verdict = "overflow" if write_size is not None and write_size > capacity else "candidate"
                if write_size is not None and write_size > capacity:
                    condition = f"{sink} size {write_size} exceeds {capacity}-byte destination"
                    write_relation = "proven_overflow"
                elif write_size is not None:
                    condition = (
                        f"{sink} size {write_size} is within {capacity}-byte capacity "
                        "but the write relation is not fully proven safe"
                    )
                    write_relation = "unproven_size_relation"
                else:
                    condition = f"{sink} size is not statically bounded in p-code facts"
                    write_relation = "symbolic_size"
            candidates.append(
                _build_candidate(
                    manifest,
                    node,
                    stack_obj,
                    kind="call",
                    sink=sink,
                    line_number=0,
                    line=f"{sink}(...)",
                    write_size_expr=write_expr,
                    write_size_bytes=write_size,
                    verdict=verdict,
                    overflow_condition=condition,
                    source_evidence=source_evidence,
                    evidence_sources=["pcode_calls"],
                    operation_address=operation_address,
                    write_relation=write_relation,
                    offset_expr=dest_offset_expr,
                )
            )
    return candidates


def _extract_pcode_store_candidates(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    *,
    use_memory_sets: bool = False,
) -> list[StaticCandidate]:
    candidates: list[StaticCandidate] = []
    for entry in node.record.pcode_stores or []:
        stack_obj, relative_offset = _pcode_store_target(entry, stack_index)
        if not stack_obj:
            continue
        capacity = _safe_int(stack_obj.get("size_bytes"))
        write_width = _first_int(entry, ("write_width", "width", "write_size", "write_size_bytes")) or 1
        operation_address = str(entry.get("operation_address") or entry.get("address") or "")
        constant_index = _first_int(entry, ("constant_index", "index", "constant_subscript"))
        scale = _first_int(entry, ("scale", "constant_scale")) or _element_size(stack_obj)
        constant_offset = _first_int(entry, ("constant_offset", "offset"))
        write_start: Optional[int] = None
        write_expr = "unknown"
        memory_offset_expr = "unknown"
        if constant_index is not None:
            write_start = (constant_offset or 0) + constant_index * scale
            write_expr = str(constant_index)
            memory_offset_expr = str(write_start)
        elif relative_offset is not None:
            write_start = relative_offset + (constant_offset or 0)
            write_expr = str(write_start)
            memory_offset_expr = write_expr
        elif constant_offset is not None:
            write_start = constant_offset
            write_expr = str(constant_offset)
            memory_offset_expr = write_expr

        if use_memory_sets:
            status, write_relation, condition = _classify_memory_write(
                stack_obj,
                memory_offset_expr,
                write_width,
                str(write_width),
                stack_index,
            )
            if status == "safe":
                continue
            if status == "overflow":
                demoted = _demote_nonproof_capacity_overflow(stack_obj, ["pcode_stores"], condition)
                if demoted is not None:
                    stack_obj, evidence_sources, condition = demoted
                    status = "candidate"
                    write_relation = "symbolic_capacity"
                else:
                    evidence_sources = ["pcode_stores"]
            else:
                evidence_sources = ["pcode_stores"]
            candidates.append(
                _build_candidate(
                    manifest,
                    node,
                    stack_obj,
                    kind="pcode_store",
                    sink="pcode_store",
                    line_number=0,
                    line="p-code stack store",
                    write_size_expr=write_expr,
                    write_size_bytes=write_width,
                    verdict="overflow" if status == "overflow" else "candidate",
                    overflow_condition=condition,
                    source_evidence=source_evidence,
                    evidence_sources=evidence_sources,
                    operation_address=operation_address,
                    write_relation=write_relation,
                    offset_expr=memory_offset_expr,
                )
            )
            continue

        if write_start is not None:
            write_end = write_start + write_width
            if 0 <= write_start and write_end <= capacity:
                continue
            condition = (
                f"p-code store writes byte range {write_start}..{write_end - 1} "
                f"outside {capacity}-byte destination"
            )
            verdict = "overflow"
            write_relation = "proven_overflow"
        else:
            condition = "p-code store address is not proven within stack object bounds"
            verdict = "candidate"
            write_relation = "symbolic_offset"
        candidates.append(
            _build_candidate(
                manifest,
                node,
                stack_obj,
                kind="pcode_store",
                sink="pcode_store",
                line_number=0,
                line="p-code stack store",
                write_size_expr=write_expr,
                write_size_bytes=write_width,
                verdict=verdict,
                overflow_condition=condition,
                source_evidence=source_evidence,
                evidence_sources=["pcode_stores"],
                operation_address=operation_address,
                write_relation=write_relation,
                offset_expr=memory_offset_expr,
            )
        )
    return candidates


def _extract_sink_candidates(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    lines: Sequence[str],
    line_number: int,
    line: str,
    original_line: Optional[str] = None,
    aliases: Mapping[str, _AliasTarget] | None = None,
    param_names: Sequence[str] = (),
    heap_aliases: Mapping[str, _HeapTarget] | None = None,
    *,
    use_memory_sets: bool = False,
) -> list[StaticCandidate]:
    candidates: list[StaticCandidate] = []
    alias_map = aliases or {}
    heap_alias_map = heap_aliases or {}
    for sink, args in _iter_sink_calls(line):
        spec = OPERATION_SPECS.get(sink)
        if not spec:
            continue
        semantics = str(spec.get("semantics") or "")
        display_line = original_line if original_line is not None else line
        if semantics == "unbounded":
            dest_index = int(spec["dest_arg"])
            if dest_index >= len(args):
                continue
            dest_expr = args[dest_index]
            if use_memory_sets:
                heap_target = _resolve_heap_destination_expr(dest_expr, heap_alias_map)
                if heap_target is not None:
                    if _fortified_call_has_active_bound(spec, args, stack_index):
                        continue
                    candidates.append(
                        _unbounded_heap_call_candidate(
                            manifest,
                            node,
                            heap_target,
                            source_evidence,
                            line_number,
                            display_line,
                            sink,
                        )
                    )
                    continue
            target = _resolve_stack_destination(dest_expr, stack_index, alias_map)
            if not target or not target.stack_obj:
                continue
            stack_obj = target.stack_obj
            if _fortified_call_cannot_overflow(spec, args, stack_obj, stack_index):
                continue
            literal_write_size = _literal_unbounded_write_size(sink, spec, args)
            if literal_write_size is not None:
                status, relation, condition = _classify_memory_write(
                    stack_obj,
                    target.offset_expr,
                    literal_write_size,
                    str(literal_write_size),
                    stack_index,
                )
                if status == "safe":
                    continue
                evidence_sources = [*_candidate_sources("c_text", target), "literal_source_bound"]
                if status == "overflow":
                    demoted = _demote_nonproof_capacity_overflow(stack_obj, evidence_sources, condition)
                    if demoted is not None:
                        stack_obj, evidence_sources, condition = demoted
                        status = "candidate"
                        relation = "symbolic_capacity"
                candidates.append(
                    _build_candidate(
                        manifest,
                        node,
                        stack_obj,
                        kind="call",
                        sink=sink,
                        line_number=line_number,
                        line=display_line,
                        write_size_expr=str(literal_write_size),
                        write_size_bytes=literal_write_size,
                        verdict="overflow" if status == "overflow" else "candidate",
                        overflow_condition=condition,
                        source_evidence=source_evidence,
                        evidence_sources=evidence_sources,
                        write_relation=relation,
                        offset_expr=target.offset_expr,
                    )
                )
                continue
            evidence_sources = _candidate_sources("c_text", target)
            candidate_stack_obj = stack_obj
            verdict = "unbounded"
            write_relation = "unbounded"
            condition = f"{sink} has no destination bound"
            demoted = _demote_nonproof_capacity_overflow(stack_obj, evidence_sources, condition)
            if demoted is not None:
                candidate_stack_obj, evidence_sources, condition = demoted
                verdict = "candidate"
                write_relation = "symbolic_capacity"
            candidates.append(
                _build_candidate(
                    manifest,
                    node,
                    candidate_stack_obj,
                    kind="call",
                    sink=sink,
                    line_number=line_number,
                    line=display_line,
                    write_size_expr="unbounded",
                    write_size_bytes=None,
                    verdict=verdict,
                    overflow_condition=condition,
                    source_evidence=source_evidence,
                    evidence_sources=evidence_sources,
                    write_relation=write_relation,
                    offset_expr=target.offset_expr,
                )
            )
            continue

        if semantics in {"bounded", "append_bounded"}:
            dest_index = int(spec["dest_arg"])
            size_index = int(spec["size_arg"])
            if dest_index >= len(args) or size_index >= len(args):
                continue
            dest_expr = args[dest_index]
            size_expr = args[size_index]
            integer_candidates: list[StaticCandidate] = []
            source_read_candidates = _source_read_candidates_for_call(
                manifest,
                node,
                stack_index,
                source_evidence,
                lines,
                line_number,
                display_line,
                sink,
                spec,
                args,
                alias_map,
                heap_alias_map,
                param_names,
                use_memory_sets=use_memory_sets,
            )
            target = _resolve_stack_destination(dest_expr, stack_index, alias_map)
            if not target or not target.stack_obj:
                if use_memory_sets:
                    heap_target = _resolve_heap_destination_expr(dest_expr, heap_alias_map)
                    if heap_target is not None:
                        integer_candidates.extend(
                            _integer_memory_risk_candidates(
                                manifest,
                                node,
                                stack_index,
                                heap_target.heap_obj,
                                source_evidence,
                                lines,
                                line_number,
                                display_line,
                                param_names,
                                size_expr,
                                role="write_size",
                                source_sink=sink,
                                offset_expr=heap_target.offset_expr,
                                destination_kind="heap",
                            )
                        )
                        candidate = _bounded_memory_set_candidate(
                            manifest,
                            node,
                            stack_index,
                            heap_target.heap_obj,
                            heap_target.offset_expr,
                            ["c_text", heap_target.evidence_source],
                            source_evidence,
                            line_number,
                            display_line,
                            sink,
                            semantics,
                            size_expr,
                            destination_kind="heap",
                        )
                        if candidate is not None:
                            candidates.extend(integer_candidates)
                            candidates.extend(source_read_candidates)
                            candidates.append(candidate)
                        else:
                            candidates.extend(source_read_candidates)
                        continue
                caller_candidate = _caller_buffer_bounded_candidate(
                    manifest,
                    node,
                    stack_index,
                    source_evidence,
                    line_number,
                    display_line,
                    sink,
                    semantics,
                    dest_expr,
                    size_expr,
                    alias_map,
                    param_names,
                )
                if caller_candidate is not None:
                    candidates.append(caller_candidate)
                candidates.extend(source_read_candidates)
                continue
            stack_obj = target.stack_obj
            write_size = _eval_int_expr(size_expr, stack_index)
            if _fortified_call_cannot_overflow(
                spec,
                args,
                stack_obj,
                stack_index,
                write_size=write_size,
            ):
                candidates.extend(source_read_candidates)
                continue
            integer_candidates.extend(
                _integer_memory_risk_candidates(
                    manifest,
                    node,
                    stack_index,
                    stack_obj,
                    source_evidence,
                    lines,
                    line_number,
                    display_line,
                    param_names,
                    size_expr,
                    role="write_size",
                    source_sink=sink,
                    offset_expr=target.offset_expr,
                )
            )
            if use_memory_sets and semantics == "bounded":
                candidate = _bounded_memory_set_candidate(
                    manifest,
                    node,
                    stack_index,
                    stack_obj,
                    target.offset_expr,
                    _candidate_sources("c_text", target),
                    source_evidence,
                    line_number,
                    display_line,
                    sink,
                    semantics,
                    size_expr,
                )
                if candidate is not None:
                    candidates.extend(integer_candidates)
                    candidates.extend(source_read_candidates)
                    candidates.append(candidate)
                else:
                    candidates.extend(source_read_candidates)
                continue
            capacity = _safe_int(stack_obj.get("size_bytes"))
            unknown_direct_extent = _bounded_byte_sink_has_unknown_direct_extent(
                sink,
                semantics,
                stack_obj,
                write_size,
            )
            candidate_stack_obj = stack_obj
            evidence_sources = list(_candidate_sources("c_text", target))
            if unknown_direct_extent:
                candidate_stack_obj = _direct_object_extent_unknown_stack_obj(stack_obj)
                if "direct_object_extent_unknown" not in evidence_sources:
                    evidence_sources.append("direct_object_extent_unknown")
            if (
                semantics == "bounded"
                and not unknown_direct_extent
                and write_size is not None
                and _bounded_write_is_proven_safe(stack_obj, target, write_size, stack_index)
            ):
                candidates.extend(source_read_candidates)
                continue
            bounded_overflow = (
                write_size is not None
                and _bounded_write_is_proven_overflow(stack_obj, target, write_size, stack_index)
            )
            if semantics == "append_bounded" and write_size is not None and write_size <= capacity:
                verdict = "candidate"
                condition = (
                    f"{sink} appends up to {write_size} bytes, but the current destination "
                    f"length is unknown for {capacity}-byte storage"
                )
                write_relation = "append_length_unknown"
            else:
                verdict = "overflow" if bounded_overflow or (write_size is not None and write_size > capacity) else "candidate"
                if unknown_direct_extent and (bounded_overflow or (write_size is not None and write_size > capacity)):
                    verdict = "candidate"
                    condition = (
                        f"{sink} writes {write_size} bytes through {stack_obj.get('var_display') or target.offset_expr}; "
                        f"the {capacity}-byte decompiler local fragment is not treated as the full object capacity"
                    )
                    write_relation = "symbolic_capacity"
                elif bounded_overflow:
                    offset = _eval_optional_offset(target.offset_expr, stack_index) or 0
                    condition = (
                        f"{sink} writes byte range {offset}..{offset + write_size - 1} "
                        f"outside {capacity}-byte destination"
                    )
                    write_relation = "proven_overflow"
                elif write_size is not None and write_size > capacity:
                    condition = f"{sink} size {write_size} exceeds {capacity}-byte destination"
                    write_relation = "proven_overflow"
                elif write_size is not None:
                    condition = (
                        f"{sink} size {write_size} is within {capacity}-byte capacity "
                        "but the write relation is not fully proven safe"
                    )
                    write_relation = (
                        "symbolic_offset"
                        if target.offset_expr and _eval_optional_offset(target.offset_expr, stack_index) is None
                        else "unproven_size_relation"
                    )
                else:
                    condition = f"{sink} size expression is not statically bounded"
                    write_relation = "symbolic_size"
            candidates.append(
                _build_candidate(
                    manifest,
                    node,
                    candidate_stack_obj,
                    kind="call",
                    sink=sink,
                    line_number=line_number,
                    line=display_line,
                    write_size_expr=size_expr,
                    write_size_bytes=write_size,
                    verdict=verdict,
                    overflow_condition=condition,
                    source_evidence=source_evidence,
                    evidence_sources=evidence_sources,
                    write_relation=write_relation,
                    offset_expr=target.offset_expr,
                )
            )
            candidates.extend(integer_candidates)
            candidates.extend(source_read_candidates)
            continue

        if semantics == "format_string":
            candidate = _extract_scanf_candidate(
                manifest,
                node,
                stack_index,
                source_evidence,
                sink,
                args,
                line_number,
                display_line,
                alias_map,
            )
            if candidate is not None:
                candidates.append(candidate)
    return candidates


def _extract_allocation_fallback_copy_candidates(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    line_number: int,
    line: str,
    original_line: str,
    fallback_aliases: Mapping[str, _AliasTarget],
) -> list[StaticCandidate]:
    if not fallback_aliases:
        return []
    candidates: list[StaticCandidate] = []
    for callee, args in _iter_calls(line) or ():
        if len(args) < 3:
            continue
        normalized = _normalize_sink_name(callee)
        if normalized in ALL_SINKS:
            continue
        if not _looks_like_unresolved_copy_call(callee):
            continue
        dest_expr = args[0]
        target = _resolve_fallback_alias_destination_expr(dest_expr, fallback_aliases)
        if target is None or target.stack_obj is None:
            continue
        size_expr = args[2]
        evidence_sources = _candidate_sources("c_text", target)
        evidence_sources.append(f"unresolved_copy_call:{callee}")
        candidate = _bounded_memory_set_candidate(
            manifest,
            node,
            stack_index,
            target.stack_obj,
            target.offset_expr,
            evidence_sources,
            source_evidence,
            line_number,
            original_line,
            "memcpy",
            "bounded",
            size_expr,
        )
        if candidate is not None:
            condition = (
                f"unresolved call {callee} writes through allocation fallback alias "
                f"{dest_expr} with size expression {size_expr!r}"
            )
            candidates.append(replace(candidate, overflow_condition=condition))
    return candidates


def _looks_like_unresolved_copy_call(callee: str) -> bool:
    key = _normalize_function_key(callee).lower()
    if key in {"if", "for", "while", "switch", "return", "sizeof"}:
        return False
    return bool(key.startswith(("fun_", "sub_")) or key.startswith("unnamed_") or re.fullmatch(r"fn_[0-9a-f]+", key))


def _resolve_fallback_alias_destination_expr(
    expr: str,
    aliases: Mapping[str, _AliasTarget],
) -> Optional[_AliasTarget]:
    cleaned = _normalize_pointer_expr(expr)
    if not cleaned:
        return None
    matches: list[tuple[int, int, str, _AliasTarget]] = []
    for name, target in aliases.items():
        position = _rooted_name_position(cleaned, name)
        if position is None:
            continue
        matches.append((position, -len(name), name, target))
    if not matches:
        return None
    _pos, _length, name, target = min(matches, key=lambda item: (item[0], item[1]))
    return replace(
        target,
        offset_expr=_combine_offsets(target.offset_expr, _offset_from_base(cleaned, name)),
    )


def _unbounded_heap_call_candidate(
    manifest: Manifest,
    node: FunctionNode,
    heap_target: _HeapTarget,
    source_evidence: Sequence[str],
    line_number: int,
    line: str,
    sink: str,
) -> StaticCandidate:
    return _build_candidate(
        manifest,
        node,
        heap_target.heap_obj,
        kind="call",
        sink=sink,
        line_number=line_number,
        line=line,
        write_size_expr="unbounded",
        write_size_bytes=None,
        verdict="unbounded",
        overflow_condition=f"{sink} has no destination bound",
        source_evidence=source_evidence,
        evidence_sources=["c_text", heap_target.evidence_source],
        destination_kind="heap",
        write_relation="unbounded",
        offset_expr=heap_target.offset_expr,
    )


def _bounded_memory_set_candidate(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    target_obj: Mapping[str, object],
    offset_expr: str,
    evidence_sources: Sequence[str],
    source_evidence: Sequence[str],
    line_number: int,
    line: str,
    sink: str,
    semantics: str,
    size_expr: str,
    *,
    destination_kind: str = "",
    operation_address: str = "",
) -> Optional[StaticCandidate]:
    write_size = _eval_int_expr(size_expr, stack_index)
    if _bounded_byte_sink_has_unknown_direct_extent(sink, semantics, target_obj, write_size):
        target_obj = _direct_object_extent_unknown_stack_obj(target_obj)
        if "direct_object_extent_unknown" not in evidence_sources:
            evidence_sources = tuple(list(evidence_sources) + ["direct_object_extent_unknown"])
    capacity = _safe_int(target_obj.get("size_bytes"))
    if semantics == "append_bounded" and write_size is not None and write_size <= capacity:
        return _build_candidate(
            manifest,
            node,
            target_obj,
            kind="call",
            sink=sink,
            line_number=line_number,
            line=line,
            write_size_expr=size_expr,
            write_size_bytes=write_size,
            verdict="candidate",
            overflow_condition=(
                f"{sink} appends up to {write_size} bytes, but the current destination "
                f"length is unknown for {capacity}-byte storage"
            ),
            source_evidence=source_evidence,
            evidence_sources=evidence_sources,
            destination_kind=destination_kind,
            operation_address=operation_address,
            write_relation="append_length_unknown",
            offset_expr=offset_expr,
        )
    status, relation, condition = _classify_memory_write(
        target_obj,
        offset_expr,
        write_size,
        size_expr,
        stack_index,
    )
    if status == "safe":
        return None
    if status == "overflow" and _bounded_byte_sink_uses_nonproof_stack_capacity(sink, semantics, target_obj):
        raw_capacity = _safe_int(target_obj.get("size_bytes"))
        target_obj = _direct_object_extent_unknown_stack_obj(target_obj)
        if "direct_object_extent_unknown" not in evidence_sources:
            evidence_sources = tuple(list(evidence_sources) + ["direct_object_extent_unknown"])
        status = "candidate"
        relation = "symbolic_capacity"
        condition = (
            f"{sink} writes through {target_obj.get('var_display') or target_obj.get('label') or 'stack object'}; "
            f"the {raw_capacity}-byte Ghidra stack fragment is not treated as the full object capacity"
        )
    elif status == "overflow":
        demoted = _demote_nonproof_capacity_overflow(target_obj, evidence_sources, condition)
        if demoted is not None:
            target_obj, evidence_sources, condition = demoted
            status = "candidate"
            relation = "symbolic_capacity"
    return _build_candidate(
        manifest,
        node,
        target_obj,
        kind="call",
        sink=sink,
        line_number=line_number,
        line=line,
        write_size_expr=size_expr,
        write_size_bytes=write_size,
        verdict="overflow" if status == "overflow" else "candidate",
        overflow_condition=condition,
        source_evidence=source_evidence,
        evidence_sources=evidence_sources,
        destination_kind=destination_kind,
        operation_address=operation_address,
        write_relation=relation,
        offset_expr=offset_expr,
    )


def _source_read_candidates_for_call(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    lines: Sequence[str],
    line_number: int,
    line: str,
    sink: str,
    spec: Mapping[str, object],
    args: Sequence[str],
    aliases: Mapping[str, _AliasTarget],
    heap_aliases: Mapping[str, _HeapTarget],
    param_names: Sequence[str],
    *,
    use_memory_sets: bool,
) -> list[StaticCandidate]:
    if sink not in MEMORY_SOURCE_READ_SINKS:
        return []
    size_index = spec.get("size_arg")
    if size_index is None or int(size_index) >= len(args):
        return []
    size_expr = args[int(size_index)]
    candidates: list[StaticCandidate] = []
    for source_index in _source_arg_indices(spec):
        if source_index < 0 or source_index >= len(args):
            continue
        source_expr = args[source_index]
        target = _resolve_stack_destination(source_expr, stack_index, aliases)
        if target and target.stack_obj:
            target = _packet_slice_alias_from_concrete_offset(target, stack_index)
            candidates.extend(
                _source_read_candidates_for_object(
                    manifest,
                    node,
                    stack_index,
                    source_evidence,
                    lines,
                    line_number,
                    line,
                    sink,
                    target.stack_obj,
                    target.offset_expr,
                    _candidate_sources("c_text", target),
                    size_expr,
                    param_names,
                )
            )
            continue
        if not use_memory_sets:
            continue
        heap_target = _resolve_heap_destination_expr(source_expr, heap_aliases)
        if heap_target is None:
            continue
        candidates.extend(
            _source_read_candidates_for_object(
                manifest,
                node,
                stack_index,
                source_evidence,
                lines,
                line_number,
                line,
                sink,
                heap_target.heap_obj,
                heap_target.offset_expr,
                ["c_text", heap_target.evidence_source],
                size_expr,
                param_names,
                destination_kind="heap",
            )
        )
    return candidates


def _source_read_candidates_for_object(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    lines: Sequence[str],
    line_number: int,
    line: str,
    sink: str,
    source_obj: Mapping[str, object],
    offset_expr: str,
    evidence_sources: Sequence[str],
    size_expr: str,
    param_names: Sequence[str],
    *,
    destination_kind: str = "",
) -> list[StaticCandidate]:
    candidates: list[StaticCandidate] = []
    read_size = _eval_int_expr(size_expr, stack_index)
    status, relation, condition = _classify_memory_write(
        source_obj,
        offset_expr,
        read_size,
        size_expr,
        stack_index,
    )
    if status == "safe":
        return candidates
    if status == "overflow":
        demoted = _demote_nonproof_capacity_overflow(source_obj, evidence_sources, condition)
        if demoted is not None:
            return candidates
        relation = "proven_oob_read"
        condition = _read_range_condition(sink, source_obj, offset_expr, read_size, stack_index)
        verdict = "overflow"
    elif relation in {"symbolic_size", "symbolic_offset"}:
        if relation == "symbolic_size" and str(source_obj.get("capacity_source") or "") != "inferred_packet_slice_remaining":
            return candidates
        relation = "symbolic_read_offset" if relation == "symbolic_offset" else relation
        verdict = "candidate"
    else:
        return candidates
    candidates.append(
        _build_candidate(
            manifest,
            node,
            source_obj,
            kind="source_read",
            sink=f"{sink}_source_read",
            line_number=line_number,
            line=line,
            write_size_expr=size_expr,
            write_size_bytes=read_size,
            verdict=verdict,
            overflow_condition=condition,
            source_evidence=source_evidence,
            evidence_sources=evidence_sources,
            destination_kind=destination_kind,
            write_relation=relation,
            offset_expr=offset_expr,
            vulnerability_type="out_of_bounds_read",
        )
    )
    candidates.extend(
        _integer_memory_risk_candidates(
            manifest,
            node,
            stack_index,
            source_obj,
            source_evidence,
            lines,
            line_number,
            line,
            param_names,
            size_expr,
            role="read_size",
            source_sink=sink,
            offset_expr=offset_expr,
            destination_kind=destination_kind,
        )
    )
    return candidates


def _read_range_condition(
    sink: str,
    source_obj: Mapping[str, object],
    offset_expr: str,
    read_size: Optional[int],
    stack_index: _StackIndex,
) -> str:
    capacity = _safe_int(source_obj.get("size_bytes"))
    offset = _eval_optional_offset(offset_expr, stack_index)
    if offset is not None and read_size is not None:
        return (
            f"{sink} reads byte range {offset}..{offset + read_size - 1} "
            f"outside {capacity}-byte source object"
        )
    if read_size is not None:
        return f"{sink} reads {read_size} bytes from a source offset not proven within {capacity}-byte object"
    return f"{sink} source read is not proven within {capacity}-byte object"


def _integer_memory_risk_candidates(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    target_obj: Mapping[str, object],
    source_evidence: Sequence[str],
    lines: Sequence[str],
    line_number: int,
    line: str,
    param_names: Sequence[str],
    expr: str,
    *,
    role: str,
    source_sink: str,
    offset_expr: str = "0",
    destination_kind: str = "",
) -> list[StaticCandidate]:
    if not expr or not _expr_is_externally_controlled(expr, lines, line_number, param_names):
        return []
    candidates: list[StaticCandidate] = []
    for risk in _integer_memory_risks(expr):
        relation = str(risk["relation"])
        vulnerability_type = str(risk["vulnerability_type"])
        condition = (
            f"{role} expression {expr!r} feeding {source_sink} can {risk['action']} "
            "before the memory access"
        )
        candidate = _build_candidate(
            manifest,
            node,
            target_obj,
            kind=f"integer_{role}",
            sink=f"{source_sink}_{vulnerability_type}",
            line_number=line_number,
            line=line,
            write_size_expr=expr if "size" in role else "1",
            write_size_bytes=_eval_int_expr(expr, stack_index) if "size" in role else 1,
            verdict="candidate",
            overflow_condition=condition,
            source_evidence=source_evidence,
            evidence_sources=["c_text", "integer_expression"],
            destination_kind=destination_kind,
            write_relation=relation,
            offset_expr=expr if "offset" in role else offset_expr,
            vulnerability_type=vulnerability_type,
        )
        trace = dict(candidate.classification_trace or {})
        trace["integer_risk"] = {
            "role": role,
            "expr": expr,
            "source_sink": source_sink,
            "relation": relation,
            "cwe": risk["cwe"],
        }
        candidates.append(replace(candidate, classification_trace=trace))
    return candidates


def _integer_memory_risks(expr: str) -> list[dict[str, str]]:
    text = str(expr or "")
    masked = _mask_string_literals(text)
    if not re.search(r"[A-Za-z_][A-Za-z0-9_]*", masked):
        return []
    risks: list[dict[str, str]] = []
    if _has_narrowing_integer_cast(masked):
        risks.append(
            {
                "vulnerability_type": "integer_truncation_to_memory_access",
                "relation": "integer_truncation_risk",
                "cwe": "CWE-681",
                "action": "truncate",
            }
        )
    if _has_unsigned_or_size_cast(masked):
        risks.append(
            {
                "vulnerability_type": "signed_conversion_to_memory_access",
                "relation": "signed_conversion_risk",
                "cwe": "CWE-195",
                "action": "reinterpret a signed value as an unsigned size",
            }
        )
    if _has_binary_underflow_operator(masked):
        risks.append(
            {
                "vulnerability_type": "integer_underflow_to_memory_access",
                "relation": "integer_underflow_risk",
                "cwe": "CWE-191",
                "action": "underflow",
            }
        )
    if _has_binary_overflow_operator(masked):
        risks.append(
            {
                "vulnerability_type": "integer_overflow_to_memory_access",
                "relation": "integer_overflow_risk",
                "cwe": "CWE-190",
                "action": "overflow",
            }
        )
    return risks


def _has_narrowing_integer_cast(expr: str) -> bool:
    return bool(
        re.search(
            r"\(\s*(?:unsigned\s+|signed\s+)?"
            r"(?:char|short|int8_t|uint8_t|int16_t|uint16_t|byte|undefined1|undefined2)\s*\)",
            expr,
        )
    )


def _has_unsigned_or_size_cast(expr: str) -> bool:
    return bool(
        re.search(
            r"\(\s*(?:size_t|ssize_t|unsigned|unsigned\s+int|unsigned\s+long|uint|ulong|uint32_t|uint64_t)\s*\)",
            expr,
        )
    )


def _has_binary_underflow_operator(expr: str) -> bool:
    return bool(re.search(r"(?:\b[A-Za-z_][A-Za-z0-9_]*|\)|\])\s*-\s*(?:\b[A-Za-z_][A-Za-z0-9_]*|\d|\()", expr))


def _has_binary_overflow_operator(expr: str) -> bool:
    if re.search(r"(?:\b[A-Za-z_][A-Za-z0-9_]*|\)|\])\s*(?:\*|<<)\s*(?:\b[A-Za-z_][A-Za-z0-9_]*|\d|\()", expr):
        return True
    return bool(
        re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\b\s*\+\s*\b[A-Za-z_][A-Za-z0-9_]*\b", expr)
    )


def _expr_is_externally_controlled(
    expr: str,
    lines: Sequence[str],
    line_number: int,
    param_names: Sequence[str],
) -> bool:
    rules = _source_taint_rules()
    state = identifier_taint_before_line(lines, line_number, param_names, rules)
    trace = trace_expression_taint("integer_risk", expr, state, param_names, rules)
    return bool(trace.get("source_controlled") or trace.get("parameter_controlled"))


def _line_may_contain_allocation(line: str) -> bool:
    text = str(line or "")
    return "=" in text and "(" in text and any(
        token in text
        for token in ("malloc", "calloc", "realloc", "alloca", "xmalloc", "g_malloc", "operator_new")
    )


def _extract_integer_allocation_candidates(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    lines: Sequence[str],
    line_number: int,
    line: str,
    original_line: str,
    param_names: Sequence[str],
    allocation_summaries: Sequence[_AllocationSummary],
) -> list[StaticCandidate]:
    lhs, rhs = _split_simple_assignment(line)
    name = _lhs_name(lhs)
    if not name:
        return []
    heap_obj = _heap_object_from_allocation(name, rhs, stack_index, allocation_summaries)
    if heap_obj is None:
        return []
    capacity_expr = str(heap_obj.get("capacity_expr") or "")
    return _integer_memory_risk_candidates(
        manifest,
        node,
        stack_index,
        heap_obj,
        source_evidence,
        lines,
        line_number,
        original_line,
        param_names,
        capacity_expr,
        role="allocation_size",
        source_sink="allocation",
        destination_kind="heap",
    )


def _caller_buffer_bounded_candidate(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    line_number: int,
    line: str,
    sink: str,
    semantics: str,
    dest_expr: str,
    size_expr: str,
    aliases: Mapping[str, _AliasTarget],
    param_names: Sequence[str],
) -> Optional[StaticCandidate]:
    if semantics != "bounded" or sink not in {"snprintf", "vsnprintf"} or not param_names:
        return None
    target = _resolve_destination_expr(dest_expr, stack_index, aliases, param_names)
    if not target or target.param_index is None or target.stack_obj is not None:
        return None
    if not target.offset_expr:
        return None
    if _caller_size_expr_accounts_for_offset(size_expr, target.offset_expr):
        return None
    if target.param_index >= len(param_names):
        return None
    target_name = param_names[target.param_index]
    capacity_obj = {
        "label": target_name,
        "var_display": target_name,
        "size_bytes": 0,
        "capacity_expr": size_expr,
        "annotation": (
            f"{target_name}: caller-provided buffer; {sink} size argument {size_expr} "
            f"is applied after destination offset {target.offset_expr}"
        ),
        "capacity_source": "sink_size_arg",
        "capacity_basis_kind": "caller_size_argument",
        "destination_kind": "caller_buffer",
    }
    condition = (
        f"{sink} writes to caller buffer {target_name} at offset {target.offset_expr}; "
        f"size argument {size_expr} is not proven to be remaining capacity"
    )
    return _build_candidate(
        manifest,
        node,
        capacity_obj,
        kind="call",
        sink=sink,
        line_number=line_number,
        line=line,
        write_size_expr=size_expr,
        write_size_bytes=_eval_int_expr(size_expr, stack_index),
        verdict="candidate",
        overflow_condition=condition,
        source_evidence=source_evidence,
        evidence_sources=_candidate_sources("c_text", target),
        destination_kind="caller_buffer",
        capacity_source="sink_size_arg",
        write_relation="symbolic_offset",
        offset_expr=target.offset_expr,
    )


def _caller_size_expr_accounts_for_offset(size_expr: str, offset_expr: str) -> bool:
    size_text = _normalize_offset_expr(size_expr)
    offset_text = _normalize_offset_expr(offset_expr)
    if not size_text or not offset_text:
        return False
    escaped = re.escape(offset_text)
    compact_size = re.sub(r"\s+", "", size_text)
    compact_offset = re.sub(r"\s+", "", offset_text)
    return bool(
        re.search(rf"-\s*\(?\s*{escaped}\s*\)?", size_text)
        or compact_size.endswith(f"-{compact_offset}")
        or f"-({compact_offset})" in compact_size
    )


def _literal_unbounded_write_size(
    sink: str,
    spec: Mapping[str, object],
    args: Sequence[str],
) -> int | None:
    if str(spec.get("semantics") or "") != "unbounded" or bool(spec.get("append")):
        return None
    source_index = spec.get("source_arg")
    if source_index is None:
        source_index = spec.get("format_arg")
    if source_index is None:
        return None
    index = int(source_index)
    if index < 0 or index >= len(args):
        return None
    literal_expr = args[index]
    if sink in {"sprintf", "vsprintf"} and _format_literal_has_conversion(literal_expr):
        return None
    literal_length = _c_string_literal_length(literal_expr)
    if literal_length is None:
        return None
    return literal_length + (1 if bool(spec.get("terminator")) else 0)


def _format_literal_has_conversion(expr: str) -> bool:
    text = str(expr or "").strip()
    if _c_string_literal_length(text) is None:
        return True
    idx = 0
    while idx < len(text):
        char = text[idx]
        if char != "%":
            idx += 1
            continue
        if idx + 1 < len(text) and text[idx + 1] == "%":
            idx += 2
            continue
        return True
    return False


def _c_string_literal_length(expr: str) -> int | None:
    text = str(expr or "").strip()
    if not text:
        return None
    parts: list[str] = []
    position = 0
    literal_re = re.compile(r'(?:u8)?(?P<body>"(?:\\.|[^"\\])*")')
    while position < len(text):
        whitespace = re.match(r"\s+", text[position:])
        if whitespace:
            position += whitespace.end()
            continue
        match = literal_re.match(text, position)
        if not match:
            return None
        parts.append(match.group("body"))
        position = match.end()
    total = 0
    for part in parts:
        try:
            value = ast.literal_eval(part)
        except (SyntaxError, ValueError):
            return None
        if not isinstance(value, str):
            return None
        total += len(value.encode("utf-8"))
    return total


def _extract_scanf_candidate(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    sink: str,
    args: Sequence[str],
    line_number: int,
    line: str,
    aliases: Mapping[str, _AliasTarget] | None = None,
) -> Optional[StaticCandidate]:
    alias_map = aliases or {}
    spec = OPERATION_SPECS.get(sink, {})
    format_index = int(spec.get("format_arg", 0))
    first_dest_index = int(spec.get("first_dest_arg", format_index + 1))
    if len(args) <= first_dest_index:
        return None
    format_arg = args[format_index]
    conversions = _scanf_conversions(format_arg)
    if conversions is None:
        for dest_expr in args[first_dest_index:]:
            target = _resolve_stack_destination(dest_expr, stack_index, alias_map)
            if not target or not target.stack_obj:
                continue
            stack_obj = target.stack_obj
            return _build_candidate(
                manifest,
                node,
                stack_obj,
                kind="call",
                sink=sink,
                line_number=line_number,
                line=line,
                write_size_expr="unknown scanf format",
                write_size_bytes=None,
                verdict="candidate",
                overflow_condition=f"{sink} format string is not statically known",
                source_evidence=source_evidence,
                evidence_sources=_candidate_sources("c_text", target),
                write_relation="symbolic_size",
                offset_expr=target.offset_expr,
            )
        return None

    dest_index = first_dest_index
    for conversion in conversions:
        if not conversion["consumes_dest"]:
            continue
        if dest_index >= len(args):
            break
        dest_expr = args[dest_index]
        dest_index += 1
        if not conversion["string_like"] or not conversion["unbounded"]:
            continue
        target = _resolve_stack_destination(dest_expr, stack_index, alias_map)
        if not target or not target.stack_obj:
            continue
        stack_obj = target.stack_obj
        return _build_candidate(
            manifest,
            node,
            stack_obj,
            kind="call",
            sink=sink,
            line_number=line_number,
            line=line,
            write_size_expr="unbounded %s",
            write_size_bytes=None,
            verdict="unbounded",
            overflow_condition=f"{sink} uses an unbounded string conversion into stack storage",
            source_evidence=source_evidence,
            evidence_sources=_candidate_sources("c_text", target),
            write_relation="unbounded",
            offset_expr=target.offset_expr,
        )
    return None


def _extract_index_candidates(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    lines: Sequence[str],
    line_number: int,
    line: str,
    original_line: Optional[str] = None,
    aliases: Mapping[str, _AliasTarget] | None = None,
    heap_aliases: Mapping[str, _HeapTarget] | None = None,
    param_names: Sequence[str] = (),
    *,
    use_memory_sets: bool = False,
) -> list[StaticCandidate]:
    candidates: list[StaticCandidate] = []
    alias_map = aliases or {}
    heap_alias_map = heap_aliases or {}
    for match in INDEX_WRITE_RE.finditer(line):
        array_name = match.group("array")
        target = _resolve_stack_destination(array_name, stack_index, alias_map)
        if not target or not target.stack_obj:
            if not use_memory_sets:
                continue
            heap_target = _resolve_heap_destination_expr(array_name, heap_alias_map)
            if heap_target is None:
                continue
            candidate = _index_memory_set_candidate(
                manifest,
                node,
                stack_index,
                source_evidence,
                lines,
                line_number,
                original_line if original_line is not None else line,
                array_name,
                match.group("index").strip(),
                heap_target.heap_obj,
                heap_target.offset_expr,
                heap_target.iterated,
                ["c_text", heap_target.evidence_source],
                destination_kind="heap",
            )
            if candidate is not None:
                candidates.extend(
                    _integer_memory_risk_candidates(
                        manifest,
                        node,
                        stack_index,
                        heap_target.heap_obj,
                        source_evidence,
                        lines,
                        line_number,
                        original_line if original_line is not None else line,
                        param_names,
                        expr=match.group("index").strip(),
                        role="write_offset",
                        source_sink="array_store",
                        offset_expr=candidate.offset_expr,
                        destination_kind="heap",
                    )
                )
                candidates.append(candidate)
            continue
        stack_obj = target.stack_obj
        index_expr = match.group("index").strip()
        if use_memory_sets:
            candidate = _index_memory_set_candidate(
                manifest,
                node,
                stack_index,
                source_evidence,
                lines,
                line_number,
                original_line if original_line is not None else line,
                array_name,
                index_expr,
                stack_obj,
                target.offset_expr,
                target.iterated,
                _candidate_sources("c_text", target),
            )
            if candidate is not None:
                candidates.extend(
                    _integer_memory_risk_candidates(
                        manifest,
                        node,
                        stack_index,
                        stack_obj,
                        source_evidence,
                        lines,
                        line_number,
                        original_line if original_line is not None else line,
                        param_names,
                        expr=index_expr,
                        role="write_offset",
                        source_sink="array_store",
                        offset_expr=candidate.offset_expr,
                    )
                )
                candidates.append(candidate)
            continue
        capacity = _safe_int(stack_obj.get("size_bytes"))
        element_size = _element_size(stack_obj)
        element_count = capacity // max(1, element_size) if capacity else 0
        byte_offset_expr = _combine_scaled_offset(target.offset_expr, index_expr, element_size)
        constant_offset = _eval_optional_offset(byte_offset_expr, stack_index)
        constant_index = _eval_int_expr(index_expr, stack_index)
        del constant_index
        if constant_offset is not None:
            highest_byte = constant_offset + element_size
            if constant_offset < 0 and target.evidence_source.startswith("c_stack_probe"):
                continue
            if 0 <= constant_offset and highest_byte <= capacity:
                if not target.iterated:
                    continue
                if _iterated_alias_loop_bound_proves_safe(
                    lines,
                    line_number,
                    array_name,
                    target,
                    stack_index,
                    constant_offset,
                    element_size,
                ):
                    continue
                if not _iterated_alias_has_symbolic_bound(lines, line_number, array_name, target, stack_index):
                    continue
                condition = (
                    f"iterated pointer alias writes index {index_expr}; "
                    f"loop bounds are not proven within {capacity}-byte destination"
                )
                verdict = "candidate"
                write_relation = "iterated_alias_unproven"
            else:
                condition = (
                    f"index {index_expr} writes outside byte range 0..{capacity - 1}"
                    if constant_offset < 0
                    else f"index {index_expr} writes through byte {highest_byte}, "
                    f"past {capacity}-byte destination"
                )
                verdict = "overflow"
                write_relation = "proven_overflow"
            guards: list[str] = []
        else:
            guard_expr = _single_identifier_in_expr(index_expr) or index_expr
            guards = _nearby_guard_evidence(lines, line_number, guard_expr, stack_index, element_count)
            if _indexed_write_bounds_prove_safe(
                lines,
                line_number,
                index_expr,
                target.offset_expr,
                stack_obj,
                stack_index,
            ):
                continue
            if _loop_bound_proves_index_safe(lines, line_number, guard_expr, stack_index, element_count) or _guards_prove_index_safe(
                guards,
                guard_expr,
                stack_index,
                element_count,
            ):
                continue
            condition = f"index {index_expr} is not proven below {element_count} elements"
            verdict = "candidate"
            write_relation = "symbolic_offset"
        evidence_sources = _candidate_sources("c_text", target)
        if verdict == "overflow":
            demoted = _demote_nonproof_capacity_overflow(stack_obj, evidence_sources, condition)
            if demoted is not None:
                stack_obj, evidence_sources, condition = demoted
                verdict = "candidate"
                write_relation = "symbolic_capacity"
        candidates.append(
            _build_candidate(
                manifest,
                node,
                stack_obj,
                kind="indexed_write",
                sink="array_store",
                line_number=line_number,
                line=original_line if original_line is not None else line,
                write_size_expr=byte_offset_expr or index_expr,
                write_size_bytes=element_size,
                verdict=verdict,
                overflow_condition=condition,
                source_evidence=source_evidence,
                guard_evidence=guards,
                evidence_sources=evidence_sources,
                write_relation=write_relation,
                offset_expr=byte_offset_expr or index_expr,
            )
        )
        candidates.extend(
            _integer_memory_risk_candidates(
                manifest,
                node,
                stack_index,
                stack_obj,
                source_evidence,
                lines,
                line_number,
                original_line if original_line is not None else line,
                param_names,
                expr=index_expr,
                role="write_offset",
                source_sink="array_store",
                offset_expr=byte_offset_expr or index_expr,
            )
        )
    return candidates


def _index_memory_set_candidate(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    lines: Sequence[str],
    line_number: int,
    line: str,
    array_name: str,
    index_expr: str,
    target_obj: Mapping[str, object],
    base_offset_expr: str,
    iterated: bool,
    evidence_sources: Sequence[str],
    *,
    destination_kind: str = "",
) -> Optional[StaticCandidate]:
    capacity = _safe_int(target_obj.get("size_bytes"))
    element_size = _element_size(target_obj)
    element_count = capacity // max(1, element_size) if capacity else 0
    byte_offset_expr = _combine_scaled_offset(base_offset_expr, index_expr, element_size)
    status, relation, condition = _classify_memory_write(
        target_obj,
        byte_offset_expr,
        element_size,
        str(element_size),
        stack_index,
    )
    guards: list[str] = []
    if status == "safe":
        if not iterated:
            return None
        constant_offset = _eval_optional_offset(byte_offset_expr, stack_index)
        if constant_offset is not None and _iterated_alias_loop_bound_proves_safe(
            lines,
            line_number,
            array_name,
            _AliasTarget(stack_obj=dict(target_obj), offset_expr=base_offset_expr, iterated=True),
            stack_index,
            constant_offset,
            element_size,
        ):
            return None
        if not _iterated_alias_has_symbolic_bound(
            lines,
            line_number,
            array_name,
            _AliasTarget(stack_obj=dict(target_obj), offset_expr=base_offset_expr, iterated=True),
            stack_index,
        ):
            return None
        condition = (
            f"iterated pointer alias writes index {index_expr}; "
            f"loop bounds are not proven within {capacity}-byte destination"
        )
        relation = "iterated_alias_unproven"
        verdict = "candidate"
    elif status == "overflow":
        demoted = _demote_nonproof_capacity_overflow(target_obj, evidence_sources, condition)
        if demoted is not None:
            target_obj, evidence_sources, condition = demoted
            relation = "symbolic_capacity"
            verdict = "candidate"
            return _build_candidate(
                manifest,
                node,
                target_obj,
                kind="indexed_write",
                sink="array_store",
                line_number=line_number,
                line=line,
                write_size_expr=byte_offset_expr or index_expr,
                write_size_bytes=element_size,
                verdict=verdict,
                overflow_condition=condition,
                source_evidence=source_evidence,
                guard_evidence=guards,
                evidence_sources=evidence_sources,
                destination_kind=destination_kind,
                write_relation=relation,
                offset_expr=byte_offset_expr or index_expr,
            )
        constant_offset = _eval_optional_offset(byte_offset_expr, stack_index)
        if constant_offset is None:
            if _indexed_write_bounds_prove_safe(
                lines,
                line_number,
                index_expr,
                base_offset_expr,
                target_obj,
                stack_index,
            ):
                return None
            if _direct_target_has_decompiler_field_component(base_offset_expr, byte_offset_expr, target_obj):
                target_obj = _object_extent_unknown_stack_obj(target_obj)
                if "direct_object_extent_unknown" not in evidence_sources:
                    evidence_sources = tuple(list(evidence_sources) + ["direct_object_extent_unknown"])
                condition = (
                    f"index {index_expr} writes through a decompiler field component; "
                    "the enclosing local object extent is not treated as an exact byte-buffer capacity"
                )
                relation = "symbolic_capacity"
                verdict = "candidate"
            else:
                condition = f"index {index_expr} is not proven below {element_count} elements"
                relation = "symbolic_offset"
                verdict = "candidate"
        else:
            if constant_offset < 0 and not _root_names_object(array_name, target_obj):
                return None
            if element_size > capacity and not _root_names_object(array_name, target_obj):
                return None
            verdict = "overflow"
    else:
        guard_expr = _single_identifier_in_expr(index_expr) or index_expr
        if _indexed_write_bounds_prove_safe(
            lines,
            line_number,
            index_expr,
            base_offset_expr,
            target_obj,
            stack_index,
        ):
            return None
        if _direct_target_has_decompiler_field_component(base_offset_expr, byte_offset_expr, target_obj):
            target_obj = _object_extent_unknown_stack_obj(target_obj)
            if "direct_object_extent_unknown" not in evidence_sources:
                evidence_sources = tuple(list(evidence_sources) + ["direct_object_extent_unknown"])
            condition = (
                f"index {index_expr} writes through a decompiler field component; "
                "the enclosing local object extent is not treated as an exact byte-buffer capacity"
            )
            relation = "symbolic_capacity"
            verdict = "candidate"
            guards = _nearby_guard_evidence(lines, line_number, guard_expr, stack_index, element_count) if element_count else []
            return _build_candidate(
                manifest,
                node,
                target_obj,
                kind="indexed_write",
                sink="array_store",
                line_number=line_number,
                line=line,
                write_size_expr=byte_offset_expr or index_expr,
                write_size_bytes=element_size,
                verdict=verdict,
                overflow_condition=condition,
                source_evidence=source_evidence,
                guard_evidence=guards,
                evidence_sources=evidence_sources,
                destination_kind=destination_kind,
                write_relation=relation,
                offset_expr=byte_offset_expr or index_expr,
            )
        if element_count and (
            _loop_bound_proves_index_safe(lines, line_number, guard_expr, stack_index, element_count)
            or _guards_prove_index_safe(
                _nearby_guard_evidence(lines, line_number, guard_expr, stack_index, element_count),
                guard_expr,
                stack_index,
                element_count,
            )
        ):
            return None
        guards = _nearby_guard_evidence(lines, line_number, guard_expr, stack_index, element_count) if element_count else []
        verdict = "candidate"
    return _build_candidate(
        manifest,
        node,
        target_obj,
        kind="indexed_write",
        sink="array_store",
        line_number=line_number,
        line=line,
        write_size_expr=byte_offset_expr or index_expr,
        write_size_bytes=element_size,
        verdict=verdict,
        overflow_condition=condition,
        source_evidence=source_evidence,
        guard_evidence=guards,
        evidence_sources=evidence_sources,
        destination_kind=destination_kind,
        write_relation=relation,
        offset_expr=byte_offset_expr or index_expr,
    )


def _extract_index_read_candidates(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    lines: Sequence[str],
    line_number: int,
    line: str,
    original_line: Optional[str] = None,
    aliases: Mapping[str, _AliasTarget] | None = None,
    heap_aliases: Mapping[str, _HeapTarget] | None = None,
    param_names: Sequence[str] = (),
    *,
    use_memory_sets: bool = False,
) -> list[StaticCandidate]:
    if _line_may_contain_sink_call(line):
        return []
    candidates: list[StaticCandidate] = []
    alias_map = aliases or {}
    heap_alias_map = heap_aliases or {}
    display_line = original_line if original_line is not None else line
    for match in ARRAY_EXPR_RE.finditer(line):
        if _array_expr_is_declaration(line, match) or _array_expr_is_assignment_lhs(line, match):
            continue
        array_name = match.group("base")
        index_expr = match.group("index").strip()
        target = _resolve_stack_destination(array_name, stack_index, alias_map)
        if target and target.stack_obj:
            candidate = _index_read_candidate_for_object(
                manifest,
                node,
                stack_index,
                source_evidence,
                lines,
                line_number,
                display_line,
                array_name,
                index_expr,
                target.stack_obj,
                target.offset_expr,
                _candidate_sources("c_text", target),
            )
            if candidate is not None:
                candidates.append(candidate)
                candidates.extend(
                    _integer_memory_risk_candidates(
                        manifest,
                        node,
                        stack_index,
                        target.stack_obj,
                        source_evidence,
                        lines,
                        line_number,
                        display_line,
                        param_names,
                        index_expr,
                        role="read_offset",
                        source_sink="array_load",
                        offset_expr=candidate.offset_expr,
                    )
                )
            continue
        if not use_memory_sets:
            continue
        heap_target = _resolve_heap_destination_expr(array_name, heap_alias_map)
        if heap_target is None:
            continue
        candidate = _index_read_candidate_for_object(
            manifest,
            node,
            stack_index,
            source_evidence,
            lines,
            line_number,
            display_line,
            array_name,
            index_expr,
            heap_target.heap_obj,
            heap_target.offset_expr,
            ["c_text", heap_target.evidence_source],
            destination_kind="heap",
        )
        if candidate is not None:
            candidates.append(candidate)
            candidates.extend(
                _integer_memory_risk_candidates(
                    manifest,
                    node,
                    stack_index,
                    heap_target.heap_obj,
                    source_evidence,
                    lines,
                    line_number,
                    display_line,
                    param_names,
                    index_expr,
                    role="read_offset",
                    source_sink="array_load",
                    offset_expr=candidate.offset_expr,
                    destination_kind="heap",
                )
            )
    return candidates


def _extract_pointer_read_candidates(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    lines: Sequence[str],
    line_number: int,
    line: str,
    original_line: str,
    heap_aliases: Mapping[str, _HeapTarget],
) -> list[StaticCandidate]:
    """Find scaled reads through symbolic heap allocations such as calloc(n, 4)."""

    candidates: list[StaticCandidate] = []
    assignment = _assignment_index(line)
    for start, cast_type, target_expr in _pointer_read_expressions(line):
        if assignment >= 0 and start < assignment:
            continue
        target = _resolve_heap_destination_expr(target_expr, heap_aliases)
        if target is None:
            continue
        capacity_term = _scaled_identifier(str(target.heap_obj.get("capacity_expr") or ""))
        offset_term = _scaled_identifier(target.offset_expr)
        if capacity_term is None or offset_term is None:
            continue
        count_name, allocation_scale = capacity_term
        index_name, offset_scale = offset_term
        read_width = max(1, _type_size(_normalize_c_type(cast_type)))
        if allocation_scale != offset_scale or read_width > allocation_scale:
            continue
        guards = _symbolic_allocation_read_guards(lines, line_number, line, start, index_name, count_name)
        if guards:
            continue
        condition = (
            f"heap read index {index_name} is not proven below allocation count {count_name}; "
            f"both allocation and read use {allocation_scale}-byte elements"
        )
        candidate = _build_candidate(
                manifest,
                node,
                target.heap_obj,
                kind="pointer_read",
                sink="pointer_load",
                line_number=line_number,
                line=original_line,
                write_size_expr=str(read_width),
                write_size_bytes=read_width,
                verdict="candidate",
                overflow_condition=condition,
                source_evidence=source_evidence,
                evidence_sources=("c_text", target.evidence_source, "symbolic_allocation_read"),
                destination_kind="heap",
                write_relation="symbolic_read_offset",
                offset_expr=target.offset_expr,
                vulnerability_type="out_of_bounds_read",
            )
        operation_address = _pointer_load_operation_address(
            node,
            line_number=line_number,
            target_name=str(target.heap_obj.get("var_display") or target.heap_obj.get("label") or ""),
            index_name=index_name,
            read_width=read_width,
        )
        if operation_address:
            candidate = replace(
                candidate,
                operation_address=operation_address,
                evidence_sources=[*candidate.evidence_sources, "pcode_loads"],
            )
        candidates.append(candidate)
    return candidates


def _pointer_load_operation_address(
    node: FunctionNode,
    *,
    line_number: int,
    target_name: str,
    index_name: str,
    read_width: int,
) -> str:
    token_loads = {
        str(address)
        for row in node.record.c_line_addresses or []
        if int(row.get("line_number") or 0) == line_number
        for address in row.get("load_addresses", [])
    }
    token_loads.discard("")
    if len(token_loads) == 1:
        return next(iter(token_loads))
    load_widths = {
        str(entry.get("operation_address") or ""): int(entry.get("read_width") or 0)
        for entry in node.record.pcode_loads or []
    }
    for preceding_line in range(line_number - 1, max(0, line_number - 4), -1):
        preceding_loads = {
            str(address)
            for row in node.record.c_line_addresses or []
            if int(row.get("line_number") or 0) == preceding_line
            for address in row.get("load_addresses", [])
            if load_widths.get(str(address)) == read_width
        }
        preceding_loads.discard("")
        if len(preceding_loads) == 1:
            return next(iter(preceding_loads))
        if preceding_loads:
            break
    line_addresses = {
        str(address)
        for row in node.record.c_line_addresses or []
        if int(row.get("line_number") or 0) == line_number
        for address in row.get("addresses", [])
    }
    line_matches = {
        str(entry.get("operation_address") or "")
        for entry in node.record.pcode_loads or []
        if int(entry.get("read_width") or 0) == read_width
        and str(entry.get("operation_address") or "") in line_addresses
    }
    line_matches.discard("")
    if len(line_matches) == 1:
        return next(iter(line_matches))
    matches: list[str] = []
    for entry in node.record.pcode_loads or []:
        if int(entry.get("read_width") or 0) != read_width:
            continue
        names = {
            str(item.get("var_name") or "")
            for item in entry.get("address_inputs", [])
            if isinstance(item, Mapping)
        }
        names.update(str(item) for item in entry.get("address_vars", []) if str(item))
        if target_name in names and index_name in names:
            address = str(entry.get("operation_address") or "")
            if address and address not in matches:
                matches.append(address)
    return matches[0] if len(matches) == 1 else ""


def _pointer_read_expressions(line: str) -> list[tuple[int, str, str]]:
    result: list[tuple[int, str, str]] = []
    pattern = re.compile(
        r"\*\s*\(\s*(?P<type>(?:unsigned\s+|signed\s+)?[A-Za-z_][A-Za-z0-9_\s]*)\s*\*\s*\)\s*\("
    )
    for match in pattern.finditer(line):
        open_index = match.end() - 1
        close_index = _find_matching_paren(line, open_index)
        if close_index < 0:
            continue
        result.append((match.start(), match.group("type").strip(), line[open_index + 1 : close_index]))
    return result


def _scaled_identifier(expr: str) -> tuple[str, int] | None:
    cleaned = str(expr or "").strip().rstrip(";")
    cleaned = re.sub(
        r"\(\s*(?:unsigned\s+|signed\s+)?(?:char|short|int|long|ulong|uint|size_t|byte|undefined\d*)\s*\)",
        "",
        cleaned,
    )
    compact = re.sub(r"[()\s]", "", cleaned)
    for pattern in (
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\*(?P<scale>0x[0-9a-fA-F]+|\d+)",
        r"(?P<scale>0x[0-9a-fA-F]+|\d+)\*(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    ):
        match = re.fullmatch(pattern, compact)
        if match:
            return match.group("name"), int(match.group("scale"), 0)
    return None


def _symbolic_allocation_read_guards(
    lines: Sequence[str],
    line_number: int,
    current_line: str,
    access_start: int,
    index_name: str,
    count_name: str,
) -> list[str]:
    index = re.escape(index_name)
    count = re.escape(count_name)
    safe_bound = rf"(?:\b{index}\b\s*<\s*\b{count}\b|\b{count}\b\s*>\s*\b{index}\b)"
    current_prefix = current_line[:access_start]
    if re.search(safe_bound, current_prefix):
        return [current_line.strip()]
    previous = list(lines[max(0, line_number - 4) : max(0, line_number - 1)])
    for raw in reversed(previous):
        if not raw.strip():
            continue
        if re.match(r"\s*[A-Za-z_][A-Za-z0-9_]*:\s*$", raw):
            continue
        if re.search(safe_bound, raw) and "if" in raw and ("{" in raw or "&&" in raw):
            return [raw.strip()]
        break
    rejecting_bound = rf"(?:\b{index}\b\s*>=\s*\b{count}\b|\b{count}\b\s*<=\s*\b{index}\b)"
    start = max(0, line_number - 7)
    for raw in lines[start : max(0, line_number - 1)]:
        if re.search(rejecting_bound, raw) and re.search(r"\b(?:goto|return|continue|break)\b", raw):
            return [raw.strip()]
    return []


def _extract_cursor_limit_read_candidates(
    manifest: Manifest,
    node: FunctionNode,
    source_evidence: Sequence[str],
    code_lines: Sequence[str],
    original_lines: Sequence[str],
) -> list[StaticCandidate]:
    """Detect base-256 cursor reads checked against the source limit too late."""

    limit_models: dict[str, tuple[str, str]] = {}
    for line in code_lines:
        match = re.search(
            r"\b(?P<limit>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"(?P<base>param_\d+)\s*\+\s*(?:\([^)]*\)\s*)?(?P<length>param_\d+)\b",
            line,
        )
        if match:
            limit_models[match.group("limit")] = (match.group("base"), match.group("length"))
    if not limit_models:
        return []

    candidates: list[StaticCandidate] = []
    seen: set[tuple[str, int]] = set()
    for marker_index, line in enumerate(code_lines):
        marker = re.search(r"\*\s*(?P<cursor>[A-Za-z_][A-Za-z0-9_]*)\s*==\s*0x80\b", line)
        if marker is None:
            continue
        cursor = marker.group("cursor")
        if not re.search(rf"\*\s*{re.escape(cursor)}\s*==\s*0xff\b", line):
            continue
        for limit, (base_param, length_param) in limit_models.items():
            match = _cursor_limit_late_check_match(code_lines, marker_index, cursor, limit)
            if match is None:
                continue
            deref_index, successor = match
            key = (cursor, deref_index)
            if key in seen:
                continue
            seen.add(key)
            line_number = deref_index + 1
            display_line = (
                original_lines[deref_index]
                if deref_index < len(original_lines)
                else code_lines[deref_index]
            )
            target = f"{base_param}[0:{length_param}]"
            source_obj = {
                "var_display": target,
                "label": target,
                "size_bytes": 0,
                "capacity_expr": length_param,
                "capacity_source": "function_length_argument",
                "capacity_basis_kind": "function_length_argument",
                "destination_kind": "source_buffer",
            }
            capacity_basis = f"cursor limit {limit} = {base_param} + {length_param}"
            overflow_condition = (
                f"base-256 marker branch advances {cursor} before reading *{cursor}; "
                f"the {successor or cursor} == {limit} limit check occurs after that byte read"
            )
            candidate = _build_candidate(
                manifest,
                node,
                source_obj,
                kind="source_read",
                sink="cursor_limit_read",
                line_number=line_number,
                line=display_line,
                write_size_expr="1",
                write_size_bytes=1,
                verdict="candidate",
                overflow_condition=overflow_condition,
                source_evidence=source_evidence,
                evidence_sources=("c_text", "cursor_limit_read"),
                destination_kind="source_buffer",
                capacity_source="function_length_argument",
                write_relation="symbolic_read_offset",
                offset_expr=length_param,
                vulnerability_type="out_of_bounds_read",
            )
            input_arg_index = max(0, _safe_int(base_param.removeprefix("param_")) - 1)
            length_arg_index = max(0, _safe_int(length_param.removeprefix("param_")) - 1)
            arg_count = max(_highest_param_index(code_lines), input_arg_index + 1, length_arg_index + 1)
            constant_args = {str(index): 0 for index in range(arg_count) if index not in {input_arg_index, length_arg_index}}
            capacity_model = _capacity_model_for_mapping(source_obj)
            trace = {
                "cursor_limit_read": {
                    "cursor": cursor,
                    "successor": successor,
                    "limit": limit,
                    "base_param": base_param,
                    "length_param": length_param,
                    "marker_values": ["0x80", "0xff"],
                    "sink_operation_pattern": "base256_loop_load_after_marker_advance",
                },
                "replay_hints": {"mode": "function_harness"},
                "function_harness": {
                    "function_address": str(node.record.address or ""),
                    "arg_count": arg_count,
                    "input_address": 0x70000000,
                    "input_arg_index": input_arg_index,
                    "length_arg": True,
                    "length_arg_index": length_arg_index,
                    "constant_args": constant_args,
                },
                "dynamic_proof": {
                    "capacity_from_concrete_input": True,
                    "offset_from_concrete_input": True,
                },
                "source_to_write": {
                    "roles": {
                        "write_source": {"expr": base_param, "classification": "source_controlled", "complete": True},
                        "write_size": {"expr": "1", "classification": "constant_or_literal", "complete": True},
                        "write_offset": {
                            "expr": length_param,
                            "classification": "source_controlled",
                            "complete": True,
                        },
                        "destination_pointer": {
                            "expr": base_param,
                            "classification": "source_controlled",
                            "complete": True,
                        },
                    }
                },
            }
            candidates.append(
                replace(
                    candidate,
                    capacity_basis=capacity_basis,
                    capacity_model=capacity_model,
                    classification_trace=trace,
                )
            )
    return candidates


def _cursor_limit_late_check_match(
    code_lines: Sequence[str],
    marker_index: int,
    cursor: str,
    limit: str,
) -> tuple[int, str] | None:
    window = list(enumerate(code_lines[marker_index + 1 : marker_index + 16], start=marker_index + 1))
    advanced = False
    successor = ""
    for idx, line in window:
        if not advanced:
            if re.search(rf"\b{re.escape(cursor)}\s*=\s*{re.escape(cursor)}\s*\+\s*1\b", line):
                advanced = True
            continue
        successor_match = re.search(
            rf"\b(?P<successor>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*{re.escape(cursor)}\s*\+\s*1\b",
            line,
        )
        if successor_match:
            successor = successor_match.group("successor")
            continue
        if _line_checks_cursor_limit_before_read(line, cursor, successor, limit):
            return None
        if re.search(rf"\*\s*{re.escape(cursor)}\b", line):
            if _cursor_limit_check_after_read(code_lines, idx, cursor, successor, limit):
                return idx, successor
            return None
    return None


def _line_checks_cursor_limit_before_read(line: str, cursor: str, successor: str, limit: str) -> bool:
    names = [cursor]
    if successor:
        names.append(successor)
    return any(
        re.search(rf"\b{re.escape(name)}\s*==\s*{re.escape(limit)}\b", line)
        or re.search(rf"\b{re.escape(limit)}\s*==\s*{re.escape(name)}\b", line)
        for name in names
    )


def _cursor_limit_check_after_read(
    code_lines: Sequence[str],
    deref_index: int,
    cursor: str,
    successor: str,
    limit: str,
) -> bool:
    for line in code_lines[deref_index + 1 : deref_index + 6]:
        if _line_checks_cursor_limit_before_read(line, cursor, successor, limit):
            return True
    return False


def _highest_param_index(lines: Sequence[str]) -> int:
    highest = 0
    for line in lines:
        for match in re.finditer(r"\bparam_(\d+)\b", line):
            highest = max(highest, _safe_int(match.group(1)))
    return max(1, min(highest, 8))


def _index_read_candidate_for_object(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    lines: Sequence[str],
    line_number: int,
    line: str,
    array_name: str,
    index_expr: str,
    target_obj: Mapping[str, object],
    base_offset_expr: str,
    evidence_sources: Sequence[str],
    *,
    destination_kind: str = "",
) -> Optional[StaticCandidate]:
    capacity = _safe_int(target_obj.get("size_bytes"))
    element_size = _element_size(target_obj)
    element_count = capacity // max(1, element_size) if capacity else 0
    byte_offset_expr = _combine_scaled_offset(base_offset_expr, index_expr, element_size)
    status, relation, condition = _classify_memory_write(
        target_obj,
        byte_offset_expr,
        element_size,
        str(element_size),
        stack_index,
    )
    guards: list[str] = []
    if status == "safe":
        return None
    if status == "overflow":
        demoted = _demote_nonproof_capacity_overflow(target_obj, evidence_sources, condition)
        if demoted is not None:
            target_obj, evidence_sources, condition = demoted
            relation = "symbolic_capacity"
            verdict = "candidate"
        else:
            constant_offset = _eval_optional_offset(byte_offset_expr, stack_index)
            if constant_offset is not None:
                highest_byte = constant_offset + element_size
                condition = (
                    f"index {index_expr} reads outside byte range 0..{capacity - 1}"
                    if constant_offset < 0
                    else f"index {index_expr} reads through byte {highest_byte}, "
                    f"past {capacity}-byte source object"
                )
            else:
                condition = f"index {index_expr} is not proven below {element_count} readable elements"
            relation = "proven_oob_read"
            verdict = "overflow"
    else:
        guard_expr = _single_identifier_in_expr(index_expr) or index_expr
        guards = _nearby_guard_evidence(lines, line_number, guard_expr, stack_index, element_count) if element_count else []
        if element_count and (
            _loop_bound_proves_index_safe(lines, line_number, guard_expr, stack_index, element_count)
            or _guards_prove_index_safe(guards, guard_expr, stack_index, element_count)
        ):
            return None
        condition = f"index {index_expr} is not proven below {element_count} readable elements"
        relation = "symbolic_read_offset"
        verdict = "candidate"
    return _build_candidate(
        manifest,
        node,
        target_obj,
        kind="indexed_read",
        sink="array_load",
        line_number=line_number,
        line=line,
        write_size_expr=byte_offset_expr or index_expr,
        write_size_bytes=element_size,
        verdict=verdict,
        overflow_condition=condition,
        source_evidence=source_evidence,
        guard_evidence=guards,
        evidence_sources=evidence_sources,
        destination_kind=destination_kind,
        write_relation=relation,
        offset_expr=byte_offset_expr or index_expr,
        vulnerability_type="out_of_bounds_read",
    )


def _array_expr_is_declaration(line: str, match: re.Match[str]) -> bool:
    prefix = line[: match.start()]
    segment = prefix.rsplit(";", 1)[-1]
    return bool(
        re.search(
            r"(?:^|\s)(?:unsigned\s+|signed\s+|struct\s+|const\s+|volatile\s+|static\s+)*"
            r"(?:char|short|int|long|size_t|uint|ulong|byte|undefined\d*|[A-Za-z_][A-Za-z0-9_]*)\s+$",
            segment,
        )
    )


def _array_expr_is_assignment_lhs(line: str, match: re.Match[str]) -> bool:
    assignment_index = _assignment_index(line)
    return bool(assignment_index >= 0 and match.start() < assignment_index and match.end() <= assignment_index)


def _extract_pointer_store_candidates(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    lines: Sequence[str],
    line_number: int,
    line: str,
    original_line: Optional[str] = None,
    aliases: Mapping[str, _AliasTarget] | None = None,
    heap_aliases: Mapping[str, _HeapTarget] | None = None,
    param_names: Sequence[str] = (),
    *,
    use_memory_sets: bool = False,
) -> list[StaticCandidate]:
    candidates: list[StaticCandidate] = []
    alias_map = aliases or {}
    heap_alias_map = heap_aliases or {}
    lhs = _assignment_lhs(line)
    if not lhs or not lhs.strip().startswith("*"):
        return candidates
    _lhs, rhs = _split_simple_assignment(line)
    rhs_target = _deref_target_expr(rhs) if rhs.strip().startswith("*") else rhs
    if rhs and _normalize_pointer_expr(_deref_target_expr(lhs)) == _normalize_pointer_expr(rhs_target):
        return candidates
    target_expr = _deref_target_expr(lhs)
    target = _resolve_stack_destination(target_expr, stack_index, alias_map)
    if not target or not target.stack_obj:
        if use_memory_sets:
            heap_target = _resolve_heap_destination_expr(target_expr, heap_alias_map)
            if heap_target is not None:
                candidate = _pointer_memory_set_candidate(
                    manifest,
                    node,
                    stack_index,
                    source_evidence,
                    lines,
                    line_number,
                    original_line if original_line is not None else line,
                    lhs,
                    target_expr,
                    heap_target.heap_obj,
                    heap_target.offset_expr,
                    heap_target.iterated,
                    ["c_text", heap_target.evidence_source],
                    destination_kind="heap",
                )
                if candidate is not None:
                    candidates.extend(
                        _integer_memory_risk_candidates(
                            manifest,
                            node,
                            stack_index,
                            heap_target.heap_obj,
                            source_evidence,
                            lines,
                            line_number,
                            original_line if original_line is not None else line,
                            param_names,
                            heap_target.offset_expr,
                            role="write_offset",
                            source_sink="pointer_store",
                            offset_expr=candidate.offset_expr,
                            destination_kind="heap",
                        )
                    )
                    candidates.append(candidate)
        return candidates
    stack_obj = target.stack_obj
    if use_memory_sets:
        candidate = _pointer_memory_set_candidate(
            manifest,
            node,
            stack_index,
            source_evidence,
            lines,
            line_number,
            original_line if original_line is not None else line,
            lhs,
            target_expr,
            stack_obj,
            target.offset_expr,
            target.iterated,
            _candidate_sources("c_text", target),
        )
        if candidate is not None:
            candidates.extend(
                _integer_memory_risk_candidates(
                    manifest,
                    node,
                    stack_index,
                    stack_obj,
                    source_evidence,
                    lines,
                    line_number,
                    original_line if original_line is not None else line,
                    param_names,
                    target.offset_expr,
                    role="write_offset",
                    source_sink="pointer_store",
                    offset_expr=candidate.offset_expr,
                )
            )
            candidates.append(candidate)
        return candidates
    write_width = _deref_write_width(lhs, stack_obj)
    capacity = _safe_int(stack_obj.get("size_bytes"))
    offset_expr = target.offset_expr or "0"
    constant_offset = _eval_optional_offset(offset_expr, stack_index)
    guard_expr = _single_identifier_in_expr(offset_expr) or offset_expr
    element_count = capacity // max(1, write_width) if capacity else 0
    guards = _nearby_guard_evidence(lines, line_number, guard_expr, stack_index, element_count)
    if constant_offset is not None:
        highest_byte = constant_offset + write_width
        if constant_offset < 0 and target.evidence_source.startswith("c_stack_probe"):
            return candidates
        if 0 <= constant_offset and highest_byte <= capacity:
            if not target.iterated:
                return candidates
            alias_name = _root_identifier(target_expr)
            if alias_name and _iterated_alias_loop_bound_proves_safe(
                lines,
                line_number,
                alias_name,
                target,
                stack_index,
                constant_offset,
                write_width,
            ):
                return candidates
            if not _iterated_alias_has_symbolic_bound(lines, line_number, alias_name, target, stack_index):
                return candidates
            condition = (
                f"iterated pointer alias writes byte range {constant_offset}..{highest_byte - 1}; "
                f"loop bounds are not proven within {capacity}-byte destination"
            )
            verdict = "candidate"
            write_relation = "iterated_alias_unproven"
        else:
            condition = f"pointer store writes byte range {constant_offset}..{highest_byte - 1} outside {capacity}-byte destination"
            verdict = "overflow"
            write_relation = "proven_overflow"
    else:
        if _loop_bound_proves_index_safe(lines, line_number, guard_expr, stack_index, element_count) or _guards_prove_index_safe(
            guards,
            guard_expr,
            stack_index,
            element_count,
        ):
            return candidates
        dangerous_guard = _dangerous_index_guard(guards, guard_expr, element_count)
        condition = dangerous_guard or f"pointer offset {offset_expr} is not proven within {capacity}-byte destination"
        verdict = "overflow" if dangerous_guard else "candidate"
        write_relation = "proven_overflow" if dangerous_guard else "symbolic_offset"
    evidence_sources = _candidate_sources("c_text", target)
    if verdict == "overflow":
        demoted = _demote_nonproof_capacity_overflow(stack_obj, evidence_sources, condition)
        if demoted is not None:
            stack_obj, evidence_sources, condition = demoted
            verdict = "candidate"
            write_relation = "symbolic_capacity"
    candidates.append(
        _build_candidate(
            manifest,
            node,
            stack_obj,
            kind="pointer_store",
            sink="pointer_store",
            line_number=line_number,
            line=original_line if original_line is not None else line,
            write_size_expr=offset_expr,
            write_size_bytes=write_width,
            verdict=verdict,
            overflow_condition=condition,
            source_evidence=source_evidence,
            guard_evidence=guards,
            evidence_sources=evidence_sources,
            write_relation=write_relation,
            offset_expr=offset_expr,
        )
    )
    candidates.extend(
        _integer_memory_risk_candidates(
            manifest,
            node,
            stack_index,
            stack_obj,
            source_evidence,
            lines,
            line_number,
            original_line if original_line is not None else line,
            param_names,
            offset_expr,
            role="write_offset",
            source_sink="pointer_store",
            offset_expr=offset_expr,
        )
    )
    return candidates


def _pointer_memory_set_candidate(
    manifest: Manifest,
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    lines: Sequence[str],
    line_number: int,
    line: str,
    lhs: str,
    target_expr: str,
    target_obj: Mapping[str, object],
    offset_expr: str,
    iterated: bool,
    evidence_sources: Sequence[str],
    *,
    destination_kind: str = "",
) -> Optional[StaticCandidate]:
    write_width = _deref_write_width(lhs, target_obj)
    capacity = _safe_int(target_obj.get("size_bytes"))
    element_count = capacity // max(1, write_width) if capacity else 0
    status, relation, condition = _classify_memory_write(
        target_obj,
        offset_expr or "0",
        write_width,
        str(write_width),
        stack_index,
    )
    guards: list[str] = []
    if status == "safe":
        if not iterated:
            return None
        constant_offset = _eval_optional_offset(offset_expr, stack_index)
        alias_name = _root_identifier(target_expr)
        alias_target = _AliasTarget(stack_obj=dict(target_obj), offset_expr=offset_expr, iterated=True)
        if constant_offset is not None and alias_name and _iterated_alias_loop_bound_proves_safe(
            lines,
            line_number,
            alias_name,
            alias_target,
            stack_index,
            constant_offset,
            write_width,
        ):
            return None
        if not _iterated_alias_has_symbolic_bound(lines, line_number, alias_name, alias_target, stack_index):
            return None
        highest_byte = (constant_offset or 0) + write_width
        condition = (
            f"iterated pointer alias writes byte range {constant_offset or 0}..{highest_byte - 1}; "
            f"loop bounds are not proven within {capacity}-byte destination"
        )
        relation = "iterated_alias_unproven"
        verdict = "candidate"
    elif status == "overflow":
        demoted = _demote_nonproof_capacity_overflow(target_obj, evidence_sources, condition)
        if demoted is not None:
            target_obj, evidence_sources, condition = demoted
            relation = "symbolic_capacity"
            verdict = "candidate"
            return _build_candidate(
                manifest,
                node,
                target_obj,
                kind="pointer_store",
                sink="pointer_store",
                line_number=line_number,
                line=line,
                write_size_expr=offset_expr or "0",
                write_size_bytes=write_width,
                verdict=verdict,
                overflow_condition=condition,
                source_evidence=source_evidence,
                guard_evidence=guards,
                evidence_sources=evidence_sources,
                destination_kind=destination_kind,
                write_relation=relation,
                offset_expr=offset_expr or "0",
            )
        constant_offset = _eval_optional_offset(offset_expr, stack_index)
        if constant_offset is None:
            guard_expr = _single_identifier_in_expr(offset_expr) or offset_expr
            condition = f"pointer offset {offset_expr or 'unknown'} is not proven within {capacity}-byte destination"
            relation = "symbolic_offset"
            verdict = "candidate"
        else:
            if constant_offset < 0 and not _root_names_object(target_expr, target_obj):
                return None
            if write_width > capacity and not _root_names_object(target_expr, target_obj):
                return None
            verdict = "overflow"
    else:
        guard_expr = _single_identifier_in_expr(offset_expr) or offset_expr
        guards = _nearby_guard_evidence(lines, line_number, guard_expr, stack_index, element_count) if element_count else []
        if element_count and (
            _loop_bound_proves_index_safe(lines, line_number, guard_expr, stack_index, element_count)
            or _guards_prove_index_safe(guards, guard_expr, stack_index, element_count)
        ):
            return None
        dangerous_guard = _dangerous_index_guard(guards, guard_expr, element_count) if element_count else ""
        if dangerous_guard:
            condition = dangerous_guard
            relation = "proven_overflow"
            verdict = "overflow"
        else:
            verdict = "candidate"
    return _build_candidate(
        manifest,
        node,
        target_obj,
        kind="pointer_store",
        sink="pointer_store",
        line_number=line_number,
        line=line,
        write_size_expr=offset_expr or "0",
        write_size_bytes=write_width,
        verdict=verdict,
        overflow_condition=condition,
        source_evidence=source_evidence,
        guard_evidence=guards,
        evidence_sources=evidence_sources,
        destination_kind=destination_kind,
        write_relation=relation,
        offset_expr=offset_expr or "0",
    )


def _extract_write_summaries(
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    lines: Sequence[str],
    aliases_by_line: Sequence[Mapping[str, _AliasTarget]],
    param_names: Sequence[str],
    param_types: Sequence[str] = (),
) -> list[_WriteSummary]:
    if not param_names:
        return []
    summaries: list[_WriteSummary] = []
    keys = tuple(_function_keys(node))
    for line_number, line in enumerate(lines, start=1):
        aliases = aliases_by_line[line_number - 1] if line_number - 1 < len(aliases_by_line) else {}
        if not (
            _line_may_contain_sink_call(line)
            or _line_may_contain_index_write(line)
            or _line_may_contain_pointer_store(line)
            or (("->" in line or "." in line) and ("=" in line or "++" in line or "--" in line))
        ):
            continue
        sink_items = _iter_sink_calls(line) if _line_may_contain_sink_call(line) else ()
        for sink, args in sink_items:
            spec = OPERATION_SPECS.get(sink)
            if not spec:
                continue
            semantics = str(spec.get("semantics") or "")
            if semantics == "format_string":
                summaries.extend(
                    _scanf_write_summaries(
                        node,
                        keys,
                        stack_index,
                        source_evidence,
                        aliases,
                        param_names,
                        param_types,
                        sink,
                        args,
                        line_number,
                        line,
                    )
                )
                continue
            dest_index = int(spec.get("dest_arg", 0))
            if dest_index >= len(args):
                continue
            param_index = _resolve_param_destination(args[dest_index], param_names, aliases)
            if param_index is None:
                continue
            write_expr = "unbounded"
            write_bytes: Optional[int] = None
            if semantics in {"bounded", "append_bounded"}:
                size_index = int(spec.get("size_arg", -1))
                if size_index >= len(args) or size_index < 0:
                    continue
                write_expr = _param_template_expr(args[size_index], param_names) or args[size_index]
                write_bytes = _eval_int_expr(write_expr, stack_index)
            elif semantics == "unbounded":
                literal_write_size = _literal_unbounded_write_size(sink, spec, args)
                if literal_write_size is not None:
                    write_expr = str(literal_write_size)
                    write_bytes = literal_write_size
            summaries.append(
                _WriteSummary(
                    function_name=node.record.name,
                    function_keys=keys,
                    dest_arg_index=param_index,
                    kind="call",
                    sink=sink,
                    line_number=line_number,
                    line_text=line.strip(),
                    dest_arg_type=_param_type_at(param_index, param_types),
                    write_size_expr=write_expr,
                    write_size_bytes=write_bytes,
                    semantics=semantics,
                    source_evidence=tuple(source_evidence),
                )
            )

        index_matches = INDEX_WRITE_RE.finditer(line) if _line_may_contain_index_write(line) else ()
        for match in index_matches:
            array_name = match.group("array")
            param_index = _resolve_param_destination(array_name, param_names, aliases)
            if param_index is None:
                continue
            index_expr = match.group("index").strip()
            templated_index = _param_template_expr(index_expr, param_names) or index_expr
            bound = _summary_offset_bound_for_param_write(
                index_expr,
                line_number,
                lines,
                param_names,
                param_types,
                param_index,
            )
            summaries.append(
                _WriteSummary(
                    function_name=node.record.name,
                    function_keys=keys,
                    dest_arg_index=param_index,
                    kind="indexed_write",
                    sink="array_store",
                    line_number=line_number,
                    line_text=line.strip(),
                    dest_arg_type=_param_type_at(param_index, param_types),
                    write_size_expr=templated_index,
                    offset_bound_expr=bound[0] if bound else "",
                    offset_bound_complete=bool(bound and bound[1]),
                    offset_bound_evidence=bound[2] if bound else (),
                    semantics="indexed_write",
                    source_evidence=tuple(source_evidence),
                )
            )

        field_match = (
            re.search(
                r"\b(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*(?:->|\.)\s*"
                r"[A-Za-z_][A-Za-z0-9_]*\s*\[\s*(?P<index>[^\]]+)\s*\]\s*(?:[+*/%&|^-]?=|\+\+|--)",
                line,
            )
            if _line_may_contain_index_write(line) and ("->" in line or "." in line)
            else None
        )
        if field_match:
            param_index = _resolve_param_destination(field_match.group("base"), param_names, aliases)
            index_expr = field_match.group("index").strip()
            if param_index is not None and _eval_int_expr(index_expr, stack_index) is None:
                templated_index = _param_template_expr(index_expr, param_names) or index_expr
                summaries.append(
                    _WriteSummary(
                        function_name=node.record.name,
                        function_keys=keys,
                        dest_arg_index=param_index,
                        kind="field_indexed_write",
                        sink="field_array_store",
                        line_number=line_number,
                        line_text=line.strip(),
                        dest_arg_type=_param_type_at(param_index, param_types),
                        write_size_expr=templated_index,
                        semantics="indexed_write",
                        source_evidence=tuple(source_evidence),
                    )
                )

        field_store_match = (
            re.search(
                r"\b(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*(?:->|\.)\s*"
                r"[A-Za-z_][A-Za-z0-9_]*\s*(?:[+*/%&|^-]?=|\+\+|--)",
                line,
            )
            if ("->" in line or "." in line) and ("=" in line or "++" in line or "--" in line)
            else None
        )
        if field_store_match and _resolve_param_destination(field_store_match.group("base"), param_names, aliases) is not None:
            pass

        lhs = _assignment_lhs(line) if _line_may_contain_pointer_store(line) else ""
        if lhs and lhs.strip().startswith("*"):
            target_expr = _deref_target_expr(lhs)
            target = _resolve_destination_expr(target_expr, stack_index, aliases, param_names)
            param_index = target.param_index if target else None
            if param_index is None:
                continue
            offset_expr = target.offset_expr if target else "unknown"
            templated_offset = _param_template_expr(offset_expr, param_names) or offset_expr
            summaries.append(
                _WriteSummary(
                    function_name=node.record.name,
                    function_keys=keys,
                    dest_arg_index=param_index,
                    kind="pointer_store",
                    sink="pointer_store",
                    line_number=line_number,
                    line_text=line.strip(),
                    dest_arg_type=_param_type_at(param_index, param_types),
                    write_size_expr=templated_offset or "0",
                    semantics="pointer_store",
                    source_evidence=tuple(source_evidence),
                )
            )
    return summaries


def _summary_offset_bound_for_param_write(
    index_expr: str,
    line_number: int,
    lines: Sequence[str],
    param_names: Sequence[str],
    param_types: Sequence[str],
    dest_arg_index: int,
) -> Optional[tuple[str, bool, tuple[str, ...]]]:
    """Return an inclusive byte-offset bound for byte-destination indexed writes."""

    if not _param_type_is_byte_pointer(_param_type_at(dest_arg_index, param_types)):
        return None
    assignments = _simple_assignments_before(lines, line_number)
    resolved_index = _inline_simple_expr(index_expr, assignments)
    linear = _linear_identifier_offset(resolved_index)
    if linear is None:
        return None
    root, delta = linear
    guarded = _reject_guard_for_upper_bound(
        root,
        lines,
        line_number,
        param_names,
        param_types,
        dest_arg_index,
    )
    if guarded is None:
        return None
    size_index, guard_line = guarded
    bound_expr = _offset_bound_with_delta(f"${size_index} - 1", delta)
    complete = _index_offset_has_nonnegative_lower_bound(
        root,
        delta,
        lines,
        line_number,
        param_names,
        param_types,
    )
    evidence = [
        f"size_guard:{guard_line.strip()}",
        f"index_bound:{_normalize_offset_expr(index_expr)} <= {bound_expr}",
    ]
    if complete:
        evidence.append("lower_bound:nonnegative_index")
    return bound_expr, complete, tuple(evidence)


def _param_type_is_byte_pointer(raw_type: str) -> bool:
    text = str(raw_type or "").strip()
    if "*" not in text:
        return False
    return _pointer_cast_type_is_byte_pointer(text.replace("*", " "))


def _simple_assignments_before(lines: Sequence[str], line_number: int) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for line in lines[: max(0, line_number - 1)]:
        lhs, rhs = _split_simple_assignment(line)
        name = _lhs_name(lhs)
        if not name:
            continue
        rhs = _normalize_offset_expr(rhs)
        if _assignment_rhs_is_inlineable(rhs):
            inlined_rhs = _inline_simple_expr(rhs, assignments)
            if _expr_node_count(inlined_rhs) > 24:
                assignments.pop(name, None)
                continue
            self_update = _linear_identifier_offset(inlined_rhs)
            if self_update is not None and self_update[0] == name:
                if self_update[1] <= 0 and name in assignments:
                    continue
                assignments.pop(name, None)
                continue
            existing = _linear_identifier_offset(assignments.get(name, ""))
            updated = _linear_identifier_offset(inlined_rhs)
            if existing is not None and updated is not None and existing[0] == updated[0] and updated[1] <= existing[1]:
                continue
            assignments[name] = inlined_rhs
        elif name in assignments:
            del assignments[name]
    return assignments


def _assignment_rhs_is_inlineable(expr: str) -> bool:
    text = _normalize_offset_expr(expr)
    if not text or "(" in text and CALL_LIKE_RE.search(text):
        return False
    return bool(INLINEABLE_EXPR_RE.fullmatch(text))


def _inline_simple_expr(expr: str, assignments: Mapping[str, str], *, max_depth: int = 8) -> str:
    result = _normalize_offset_expr(expr)
    for _ in range(max_depth):
        changed = False

        def repl(match: re.Match[str]) -> str:
            nonlocal changed
            name = match.group(0)
            replacement = assignments.get(name)
            if replacement is None:
                return name
            changed = True
            if SIMPLE_REPLACEMENT_RE.fullmatch(replacement):
                return replacement
            return f"({replacement})"

        result = IDENTIFIER_RE.sub(repl, result)
        result = _normalize_offset_expr(result)
        if not changed:
            break
    return result


def _linear_identifier_offset(expr: str) -> Optional[tuple[str, int]]:
    return _linear_identifier_offset_cached(_normalize_offset_expr(expr))


@lru_cache(maxsize=65536)
def _linear_identifier_offset_cached(cleaned: str) -> Optional[tuple[str, int]]:
    fast = _fast_linear_identifier_offset(cleaned)
    if fast is not None:
        return fast
    if not cleaned:
        return None
    identifiers = _expr_identifier_names(cleaned)
    if len(identifiers) != 1:
        return None
    name = identifiers[0]
    zero_expr = _replace_identifier_with_literal(cleaned, name, "0")
    one_expr = _replace_identifier_with_literal(cleaned, name, "1")
    zero = _eval_int_expr(zero_expr, _StackIndex(()))
    one = _eval_int_expr(one_expr, _StackIndex(()))
    if zero is None or one is None or one - zero != 1:
        return None
    return name, zero


def _fast_linear_identifier_offset(expr: str) -> Optional[tuple[str, int]]:
    cleaned = _normalize_offset_expr(expr)
    name = _simple_nonkeyword_identifier(cleaned)
    if name:
        return name, 0
    split = _split_top_level_add_sub(cleaned)
    if split is None:
        return None
    left, op, right = split
    left_name = _simple_nonkeyword_identifier(left)
    if left_name:
        right_value = _parse_int_literal(_strip_outer_parens(right))
        if right_value is not None:
            return left_name, right_value if op == "+" else -right_value
    if op == "+":
        right_name = _simple_nonkeyword_identifier(right)
        left_value = _parse_int_literal(_strip_outer_parens(left))
        if right_name and left_value is not None:
            return right_name, left_value
    return None


def _simple_nonkeyword_identifier(expr: str) -> str:
    text = _strip_outer_parens(_normalize_offset_expr(expr))
    if IDENTIFIER_RE.fullmatch(text) and text not in LINEAR_EXPR_KEYWORDS:
        return text
    return ""


def _split_top_level_add_sub(expr: str) -> Optional[tuple[str, str, str]]:
    text = _strip_outer_parens(_normalize_offset_expr(expr))
    depth = 0
    quote = ""
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "(":
            depth += 1
            continue
        if char == ")":
            depth = max(0, depth - 1)
            continue
        if depth == 0 and index > 0 and char in {"+", "-"}:
            return text[:index].strip(), char, text[index + 1 :].strip()
    return None


def _expr_identifier_names(expr: str) -> list[str]:
    text = re.sub(r"0x[0-9a-fA-F]+", "0", _normalize_offset_expr(expr))
    names: list[str] = []
    for name in IDENTIFIER_RE.findall(text):
        if name in LINEAR_EXPR_KEYWORDS or name in names:
            continue
        names.append(name)
    return names


def _replace_identifier_with_literal(expr: str, name: str, value: str) -> str:
    return re.sub(rf"\b{re.escape(name)}\b", value, _normalize_offset_expr(expr))


def _reject_guard_for_upper_bound(
    root: str,
    lines: Sequence[str],
    line_number: int,
    param_names: Sequence[str],
    param_types: Sequence[str],
    dest_arg_index: int,
) -> Optional[tuple[int, str]]:
    for guard_index, line in enumerate(lines[: max(0, line_number - 1)]):
        condition = _if_condition(line)
        if not condition or root not in condition:
            continue
        if not _guard_branch_returns(lines, guard_index):
            continue
        normalized = _normalize_offset_expr(condition)
        for size_index in _size_param_indices_for_dest(param_names, param_types, dest_arg_index):
            size_name = param_names[size_index]
            if _condition_rejects_root_at_or_above_size(normalized, root, size_name):
                return size_index, line
    return None


def _size_param_indices_for_dest(
    param_names: Sequence[str],
    param_types: Sequence[str],
    dest_arg_index: int,
) -> list[int]:
    result: list[int] = []
    for index, name in enumerate(param_names):
        if index == dest_arg_index:
            continue
        lowered = str(name or "").lower()
        raw_type = _param_type_at(index, param_types).lower()
        if re.search(r"(?:len|length|size|sz|cap|capacity|bytes|nbyte|bufsiz)", lowered):
            result.append(index)
            continue
        if raw_type in {"size_t", "ssize_t"} or "size_t" in raw_type:
            result.append(index)
    return result


def _condition_rejects_root_at_or_above_size(condition: str, root: str, size_name: str) -> bool:
    root_re = re.escape(root)
    size_re = re.escape(size_name)
    return bool(
        re.search(rf"\b{size_re}\b\s*<=\s*\b{root_re}\b", condition)
        or re.search(rf"\b{root_re}\b\s*>=\s*\b{size_re}\b", condition)
    )


def _if_condition(line: str) -> str:
    match = re.search(r"\bif\s*\(", line)
    if not match:
        return ""
    open_index = line.find("(", match.start())
    close_index = _find_matching_paren(line, open_index)
    if open_index < 0 or close_index < 0:
        return ""
    return line[open_index + 1 : close_index].strip()


def _guard_branch_returns(lines: Sequence[str], guard_index: int) -> bool:
    guard_line = lines[guard_index] if 0 <= guard_index < len(lines) else ""
    condition = _if_condition(guard_line)
    condition_end = guard_line.find(condition) + len(condition) if condition else -1
    if condition_end >= 0 and "return" in guard_line[condition_end:]:
        return True
    if "{" not in guard_line:
        for line in lines[guard_index + 1 : guard_index + 3]:
            stripped = line.strip()
            if not stripped:
                continue
            return stripped.startswith("return") or stripped.startswith("goto")
        return False
    depth = 0
    opened = False
    for index, line in enumerate(lines[guard_index : min(len(lines), guard_index + 20)]):
        if "{" in line:
            opened = True
        if opened and ("return" in line or re.search(r"\bgoto\b", line)):
            return True
        depth += line.count("{") - line.count("}")
        if opened and depth <= 0 and index > 0:
            break
    return False


def _offset_bound_with_delta(base_expr: str, delta: int) -> str:
    base = _normalize_offset_expr(base_expr)
    if delta == 0:
        return base
    if delta > 0:
        return f"({base}) + {delta}"
    return f"({base}) - {abs(delta)}"


def _index_offset_has_nonnegative_lower_bound(
    root: str,
    delta: int,
    lines: Sequence[str],
    line_number: int,
    param_names: Sequence[str],
    param_types: Sequence[str],
) -> bool:
    root_min = _known_root_minimum(root, lines, line_number, param_names, param_types)
    if root_min is not None and root_min + delta >= 0:
        return True
    guarded_min = _reject_guard_lower_bound(root, lines, line_number)
    return guarded_min is not None and guarded_min + delta >= 0


def _known_root_minimum(
    root: str,
    lines: Sequence[str],
    line_number: int,
    param_names: Sequence[str],
    param_types: Sequence[str],
) -> Optional[int]:
    declared_type = _identifier_decl_type(root, lines, line_number, param_names, param_types)
    minimum = 0 if _type_is_unsigned_integer(declared_type) else None
    for line in lines[: max(0, line_number - 1)]:
        lhs, rhs = _split_simple_assignment(line)
        if _lhs_name(lhs) != root:
            continue
        if re.search(r"\bdigits(?:10|_base10)?\s*\(", rhs):
            minimum = max(minimum or 0, 1)
    return minimum


def _identifier_decl_type(
    root: str,
    lines: Sequence[str],
    line_number: int,
    param_names: Sequence[str],
    param_types: Sequence[str],
) -> str:
    if root in param_names:
        return _param_type_at(param_names.index(root), param_types)
    root_re = re.escape(root)
    for line in lines[: max(0, line_number - 1)]:
        stripped = line.strip().rstrip(";")
        if root not in stripped or "(" in stripped:
            continue
        match = re.search(rf"^(?P<type>[A-Za-z_][A-Za-z0-9_\s\*]*?)\s+\**\b{root_re}\b(?:\s|$|=|,)", stripped)
        if match:
            return match.group("type").strip()
    return ""


def _type_is_unsigned_integer(raw_type: str) -> bool:
    normalized = _normalize_c_type(raw_type)
    return bool(
        normalized == "size_t"
        or normalized.startswith(("uint", "ulong", "ushort", "uchar"))
        or "unsigned" in normalized
    )


def _reject_guard_lower_bound(root: str, lines: Sequence[str], line_number: int) -> Optional[int]:
    best: Optional[int] = None
    for guard_index, line in enumerate(lines[: max(0, line_number - 1)]):
        condition = _if_condition(line)
        if not condition or root not in condition:
            continue
        if not _guard_branch_returns(lines, guard_index):
            continue
        lower = _reject_condition_lower_bound(root, condition)
        if lower is not None:
            best = lower if best is None else max(best, lower)
    return best


def _reject_condition_lower_bound(root: str, condition: str) -> Optional[int]:
    root_re = re.escape(root)
    normalized = _normalize_offset_expr(condition)
    best: Optional[int] = None
    literal = r"0x[0-9a-fA-F]+|\d+"
    for pattern, inclusive_delta in (
        (rf"\b{root_re}\b\s*<\s*(?P<limit>{literal})", 0),
        (rf"\b{root_re}\b\s*<=\s*(?P<limit>{literal})", 1),
        (rf"(?P<limit>{literal})\s*>\s*\b{root_re}\b", 0),
        (rf"(?P<limit>{literal})\s*>=\s*\b{root_re}\b", 1),
    ):
        match = re.search(pattern, normalized)
        if not match:
            continue
        limit = _parse_int_literal(match.group("limit"))
        if limit is None:
            continue
        lower = limit + inclusive_delta
        best = lower if best is None else max(best, lower)
    return best


def _scanf_write_summaries(
    node: FunctionNode,
    keys: Sequence[str],
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    aliases: Mapping[str, _AliasTarget],
    param_names: Sequence[str],
    param_types: Sequence[str],
    sink: str,
    args: Sequence[str],
    line_number: int,
    line: str,
) -> list[_WriteSummary]:
    spec = OPERATION_SPECS.get(sink, {})
    format_index = int(spec.get("format_arg", 0))
    first_dest_index = int(spec.get("first_dest_arg", format_index + 1))
    if len(args) <= first_dest_index:
        return []
    conversions = _scanf_conversions(args[format_index])
    summaries: list[_WriteSummary] = []
    if conversions is None:
        for arg_index, dest_expr in enumerate(args[first_dest_index:], start=first_dest_index):
            param_index = _resolve_param_destination(dest_expr, param_names, aliases)
            if param_index is None:
                continue
            summaries.append(
                _WriteSummary(
                    function_name=node.record.name,
                    function_keys=tuple(keys),
                    dest_arg_index=param_index,
                    kind="call",
                    sink=sink,
                    line_number=line_number,
                    line_text=line.strip(),
                    dest_arg_type=_param_type_at(param_index, param_types),
                    write_size_expr=f"unknown scanf destination {arg_index}",
                    semantics="format_string",
                    source_evidence=tuple(source_evidence),
                )
            )
        return summaries
    dest_index = first_dest_index
    for conversion in conversions:
        if not conversion["consumes_dest"]:
            continue
        if dest_index >= len(args):
            break
        dest_expr = args[dest_index]
        dest_index += 1
        if not conversion["string_like"] or not conversion["unbounded"]:
            continue
        param_index = _resolve_param_destination(dest_expr, param_names, aliases)
        if param_index is None:
            continue
        summaries.append(
            _WriteSummary(
                function_name=node.record.name,
                function_keys=tuple(keys),
                dest_arg_index=param_index,
                kind="call",
                sink=sink,
                line_number=line_number,
                line_text=line.strip(),
                dest_arg_type=_param_type_at(param_index, param_types),
                write_size_expr="unbounded %s",
                semantics="format_string",
                source_evidence=tuple(source_evidence),
            )
        )
    return summaries


def _instantiate_write_summaries(
    manifest: Manifest,
    contexts: Sequence[_FunctionContext],
    summaries: Sequence[_WriteSummary] | None = None,
    *,
    call_sites_by_context: Mapping[int, Sequence[_CallSite]] | None = None,
) -> list[StaticCandidate]:
    summaries_by_key: dict[str, list[_WriteSummary]] = {}
    source_summaries = list(summaries) if summaries is not None else [
        summary for context in contexts for summary in context.summaries
    ]
    for summary in source_summaries:
        for key in summary.function_keys:
            summaries_by_key.setdefault(key, []).append(summary)

    candidates: list[StaticCandidate] = []
    call_sites_by_context = call_sites_by_context or {}
    for context in contexts:
        if not context.stack_index.objects:
            continue
        for site in call_sites_by_context.get(id(context), ()):
            callee_summaries = _summaries_for_call(site.callee, summaries_by_key)
            for summary in callee_summaries:
                if summary.dest_arg_index >= len(site.args):
                    continue
                target = _resolve_stack_destination(site.args[summary.dest_arg_index], context.stack_index, site.aliases)
                if not target or not target.stack_obj:
                    continue
                candidate = _candidate_from_summary(
                    manifest,
                    context,
                    summary,
                    target,
                    site.args,
                    site.line_number,
                    site.original_line,
                    peer_summaries=callee_summaries,
                )
                if candidate is not None:
                    candidates.append(candidate)
    return candidates


def _extract_parameter_source_read_summaries(
    node: FunctionNode,
    stack_index: _StackIndex,
    source_evidence: Sequence[str],
    code_lines: Sequence[str],
    lines: Sequence[str],
    alias_snapshots: Sequence[Mapping[str, _AliasTarget]],
    param_names: Sequence[str],
) -> list[_ParameterSourceReadSummary]:
    if not param_names:
        return []
    keys = tuple(_function_keys(node))
    summaries: list[_ParameterSourceReadSummary] = []
    for line_number, line, original_line in _iter_logical_statements(code_lines, lines):
        if not _line_may_contain_sink_call(line):
            continue
        aliases = (
            alias_snapshots[line_number - 1]
            if line_number - 1 < len(alias_snapshots)
            else {}
        )
        for sink, args in _iter_sink_calls(line):
            if sink not in MEMORY_SOURCE_READ_SINKS:
                continue
            spec = OPERATION_SPECS.get(sink) or {}
            size_index = spec.get("size_arg")
            if size_index is None or int(size_index) >= len(args):
                continue
            read_size_expr = args[int(size_index)]
            for source_index in _source_arg_indices(spec):
                if source_index < 0 or source_index >= len(args):
                    continue
                source_target = _resolve_destination_expr(args[source_index], stack_index, aliases, param_names)
                if (
                    source_target is None
                    or source_target.param_index is None
                    or source_target.stack_obj is not None
                    or not _split_param_field_offset(source_target.offset_expr)[0]
                ):
                    continue
                summaries.append(
                    _ParameterSourceReadSummary(
                        function_name=node.record.name,
                        function_keys=keys,
                        param_index=source_target.param_index,
                        sink=sink,
                        line_number=line_number,
                        line_text=(original_line or line).strip(),
                        source_offset_expr=source_target.offset_expr,
                        read_size_expr=_param_template_expr(read_size_expr, param_names) or read_size_expr,
                        source_evidence=tuple(source_evidence),
                    )
                )
    return summaries


def _instantiate_parameter_source_read_summaries(
    manifest: Manifest,
    contexts: Sequence[_FunctionContext],
    *,
    source_read_summaries: Sequence[_ParameterSourceReadSummary] | None = None,
    call_sites_by_context: Mapping[int, Sequence[_CallSite]] | None = None,
) -> list[StaticCandidate]:
    summaries_by_key: dict[str, list[_ParameterSourceReadSummary]] = {}
    summaries = source_read_summaries
    if summaries is None:
        summaries = tuple(summary for context in contexts for summary in context.source_read_summaries)
    for summary in summaries:
        for key in summary.function_keys:
            summaries_by_key.setdefault(key, []).append(summary)

    candidates: list[StaticCandidate] = []
    context_by_name = {context.node.record.name: context for context in contexts}
    call_sites_by_context = call_sites_by_context or {}
    for caller in contexts:
        if not caller.stack_index.objects:
            continue
        for site in call_sites_by_context.get(id(caller), ()):
            callee_summaries = _source_read_summaries_for_call(site.callee, summaries_by_key)
            if not callee_summaries:
                continue
            field_targets = _caller_field_targets_before_site(caller, site)
            if not field_targets:
                continue
            for summary in callee_summaries:
                callee_context = context_by_name.get(summary.function_name)
                if callee_context is None:
                    continue
                if summary.param_index >= len(site.args):
                    continue
                root_target = _resolve_object_destination_expr(
                    site.args[summary.param_index],
                    caller.stack_index,
                    site.aliases,
                    caller.heap_aliases,
                    caller.param_names,
                )
                if root_target is None or root_target.stack_obj is None:
                    continue
                field_tokens, byte_offset = _split_param_field_offset(summary.source_offset_expr)
                if not field_tokens:
                    continue
                source_target = _resolve_caller_field_source(root_target, field_tokens, field_targets)
                if source_target is None or source_target.stack_obj is None:
                    continue
                source_target = replace(
                    source_target,
                    offset_expr=_combine_offsets(source_target.offset_expr, str(byte_offset)),
                    evidence_source="interprocedural_field_source",
                )
                source_target = _packet_slice_alias_from_concrete_offset(source_target, caller.stack_index)
                candidates.extend(
                    _source_read_candidates_for_object(
                        manifest,
                        callee_context.node,
                        caller.stack_index,
                        _unique_nonempty(
                            [
                                *caller.source_evidence,
                                *callee_context.source_evidence,
                                *summary.source_evidence,
                            ]
                        ),
                        callee_context.code_lines,
                        summary.line_number,
                        summary.line_text,
                        summary.sink,
                        source_target.stack_obj,
                        source_target.offset_expr,
                        _unique_nonempty([*summary.evidence_sources, *_candidate_sources("c_text", source_target)]),
                        _instantiate_summary_expr(summary.read_size_expr, site.args),
                        callee_context.param_names,
                    )
                )
    return candidates


def _source_arg_indices(spec: Mapping[str, object]) -> list[int]:
    raw_indices = spec.get("source_args")
    if isinstance(raw_indices, Sequence) and not isinstance(raw_indices, (str, bytes, bytearray)):
        return [int(index) for index in raw_indices]
    if spec.get("source_arg") is not None:
        return [int(spec["source_arg"])]
    return []


def _source_read_summaries_for_call(
    callee: str,
    summaries_by_key: Mapping[str, list[_ParameterSourceReadSummary]],
) -> list[_ParameterSourceReadSummary]:
    summaries: list[_ParameterSourceReadSummary] = []
    seen: set[tuple[object, ...]] = set()
    for key in _summary_lookup_keys(callee):
        for summary in summaries_by_key.get(key, []):
            identity = (
                summary.function_name,
                summary.param_index,
                summary.sink,
                summary.line_number,
                _normalize_offset_expr(summary.source_offset_expr),
                _normalize_offset_expr(summary.read_size_expr),
            )
            if identity in seen:
                continue
            seen.add(identity)
            summaries.append(summary)
    return summaries


def _caller_field_targets_before_site(
    context: _FunctionContext,
    site: _CallSite,
) -> dict[tuple[str, tuple[str, ...]], _AliasTarget]:
    targets: dict[tuple[str, tuple[str, ...]], _AliasTarget] = {}
    for line_number, line, _original_line in _iter_logical_statements(context.code_lines, context.lines):
        if line_number >= site.line_number:
            break
        lhs, rhs = _split_simple_assignment(line)
        if not lhs:
            continue
        heap_aliases = (
            context.heap_aliases_by_line[line_number - 1]
            if line_number - 1 < len(context.heap_aliases_by_line)
            else context.heap_aliases
        )
        base_key, fields = _object_field_lhs(lhs, context.stack_index, heap_aliases)
        if not base_key or not fields:
            continue
        aliases = (
            context.aliases_by_line[line_number - 1]
            if line_number - 1 < len(context.aliases_by_line)
            else context.aliases
        )
        target = _resolve_object_destination_expr(
            rhs,
            context.stack_index,
            aliases,
            heap_aliases,
            context.param_names,
        )
        if target is None or (target.stack_obj is None and target.param_index is None):
            continue
        targets[(base_key, fields)] = target
    return targets


def _stack_field_lhs(lhs: str, stack_index: _StackIndex) -> tuple[str, tuple[str, ...]]:
    return _object_field_lhs(lhs, stack_index, {})


def _object_field_lhs(
    lhs: str,
    stack_index: _StackIndex,
    heap_aliases: Mapping[str, _HeapTarget],
) -> tuple[str, tuple[str, ...]]:
    cleaned = _normalize_pointer_expr(lhs)
    if not cleaned:
        return "", ()
    matches: list[tuple[int, int, dict, str]] = []
    for obj in stack_index.objects:
        for name in obj.get("var_names") or []:
            var_name = str(name)
            position = _rooted_name_position(cleaned, var_name)
            if position is None:
                continue
            matches.append((position, -len(var_name), obj, var_name))
    if not matches:
        heap_matches: list[tuple[int, int, str, _HeapTarget]] = []
        for name, target in heap_aliases.items():
            position = _rooted_name_position(cleaned, name)
            if position is None:
                continue
            heap_matches.append((position, -len(name), name, target))
        if not heap_matches:
            return "", ()
        position, _length, name, target = min(heap_matches, key=lambda item: (item[0], item[1]))
        if position != 0:
            return "", ()
        fields = _field_tokens_after_base(cleaned, name)
        if not fields:
            return "", ()
        return _stack_obj_key(target.heap_obj), fields
    position, _length, obj, var_name = min(matches, key=lambda item: (item[0], item[1]))
    if position != 0:
        return "", ()
    fields = _field_tokens_after_base(cleaned, var_name)
    if not fields:
        return "", ()
    return _stack_obj_key(obj), fields


def _field_tokens_after_base(expr: str, base_name: str) -> tuple[str, ...]:
    cleaned = _normalize_pointer_expr(expr)
    span = _identifier_span(cleaned, base_name)
    if span is None:
        return ()
    suffix = cleaned[span[1] :]
    if not re.fullmatch(r"(?:(?:->|\.)\s*[A-Za-z_][A-Za-z0-9_]*)+", suffix):
        return ()
    return tuple(re.findall(r"(?:->|\.)\s*([A-Za-z_][A-Za-z0-9_]*)", suffix))


def _split_param_field_offset(expr: str) -> tuple[tuple[str, ...], int]:
    cleaned = _normalize_offset_expr(expr)
    offset = 0
    while True:
        split = _split_top_level_add_sub(cleaned)
        if split is None:
            break
        left, op, right = split
        right_literal = _parse_int_literal(_strip_outer_parens(right))
        if right_literal is not None:
            offset += right_literal if op == "+" else -right_literal
            cleaned = left
            continue
        left_literal = _parse_int_literal(_strip_outer_parens(left))
        if op == "+" and left_literal is not None:
            offset += left_literal
            cleaned = right
            continue
        break
    return _param_field_offset_tokens(cleaned), offset


def _param_field_offset_tokens(expr: str) -> tuple[str, ...]:
    cleaned = _strip_outer_parens(_normalize_offset_expr(expr))
    if not re.fullmatch(r"0(?:(?:->|\.)\s*[A-Za-z_][A-Za-z0-9_]*)+", cleaned):
        return ()
    return tuple(re.findall(r"(?:->|\.)\s*([A-Za-z_][A-Za-z0-9_]*)", cleaned))


def _resolve_caller_field_source(
    root_target: _AliasTarget,
    fields: Sequence[str],
    field_targets: Mapping[tuple[str, tuple[str, ...]], _AliasTarget],
) -> Optional[_AliasTarget]:
    current = root_target
    remaining = tuple(fields)
    while remaining:
        if current.stack_obj is None:
            return None
        key_base = _stack_obj_key(current.stack_obj)
        matched = False
        for width in range(len(remaining), 0, -1):
            target = field_targets.get((key_base, remaining[:width]))
            if target is None:
                continue
            current = target
            remaining = remaining[width:]
            matched = True
            break
        if not matched:
            return None
    return current


def _resolve_object_destination_expr(
    expr: str,
    stack_index: _StackIndex,
    aliases: Mapping[str, _AliasTarget],
    heap_aliases: Mapping[str, _HeapTarget],
    param_names: Sequence[str],
) -> Optional[_AliasTarget]:
    target = _resolve_destination_expr(expr, stack_index, aliases, param_names)
    if target is not None:
        return target
    target = _resolve_manifest_object_destination_expr(expr, stack_index)
    if target is not None:
        return target
    heap_target = _resolve_heap_destination_expr(expr, heap_aliases)
    if heap_target is None:
        return None
    return _AliasTarget(
        stack_obj=dict(heap_target.heap_obj),
        offset_expr=heap_target.offset_expr,
        evidence_source=heap_target.evidence_source,
        iterated=heap_target.iterated,
    )


def _resolve_manifest_object_destination_expr(
    expr: str,
    stack_index: _StackIndex,
) -> Optional[_AliasTarget]:
    cleaned = _normalize_pointer_expr(expr)
    if not cleaned:
        return None
    matches: list[tuple[int, int, dict, str]] = []
    for obj in stack_index.objects:
        for name in obj.get("var_names") or []:
            var_name = str(name)
            position = _rooted_name_position(cleaned, var_name)
            if position is None:
                continue
            matches.append((position, _safe_int(obj.get("size_bytes")), dict(obj), var_name))
    if not matches:
        return None
    _pos, _size, obj, var_name = min(matches, key=lambda item: (item[0], item[1]))
    return _AliasTarget(
        stack_obj=obj,
        offset_expr=_combine_offsets(
            _member_offset_expr(obj, var_name),
            _offset_from_base(cleaned, var_name),
        ),
        evidence_source="c_text",
    )


def _stack_obj_key(obj: Mapping[str, object]) -> str:
    names = [str(name) for name in obj.get("var_names") or [] if name]
    if names:
        return names[0]
    label = str(obj.get("var_display") or obj.get("label") or "")
    if label:
        return label
    return f"stack:{_safe_int(obj.get('start_offset'))}:{_safe_int(obj.get('size_bytes'))}"


def _fixed_point_write_summaries(
    contexts: Sequence[_FunctionContext],
    *,
    call_sites_by_context: Mapping[int, Sequence[_CallSite]] | None = None,
    max_summary_depth: int = 4,
    max_expr_nodes: int = 32,
    max_summaries_per_function: int = 20,
) -> list[_WriteSummary]:
    """Propagate parameter-write summaries through simple wrappers."""

    summaries: list[_WriteSummary] = []
    seen: set[tuple[object, ...]] = set()
    summary_counts: dict[str, int] = {}

    def add(summary: _WriteSummary) -> bool:
        if _expr_node_count(summary.write_size_expr) > max_expr_nodes:
            return False
        if summary.offset_bound_expr and _expr_node_count(summary.offset_bound_expr) > max_expr_nodes:
            return False
        key = _summary_identity(summary)
        if key in seen:
            return False
        current_count = summary_counts.get(summary.function_name, 0)
        if current_count >= max_summaries_per_function:
            return False
        seen.add(key)
        summaries.append(summary)
        summary_counts[summary.function_name] = current_count + 1
        return True

    for context in contexts:
        for summary in context.summaries:
            add(summary)

    call_sites_by_context = call_sites_by_context or {}
    for depth in range(1, max_summary_depth + 1):
        summaries_by_key: dict[str, list[_WriteSummary]] = {}
        for summary in summaries:
            for key in summary.function_keys:
                summaries_by_key.setdefault(key, []).append(summary)
        changed = False
        for context in contexts:
            if not context.param_names:
                continue
            for site in call_sites_by_context.get(id(context), ()):
                for callee_summary in _summaries_for_call(site.callee, summaries_by_key):
                    if callee_summary.dest_arg_index >= len(site.args):
                        continue
                    target = _resolve_destination_expr(
                        site.args[callee_summary.dest_arg_index],
                        context.stack_index,
                        site.aliases,
                        context.param_names,
                    )
                    if not target or target.param_index is None or target.stack_obj is not None:
                        continue
                    instantiated_expr = _instantiate_summary_expr(callee_summary.write_size_expr, site.args)
                    templated_expr = _param_template_expr(instantiated_expr, context.param_names) or instantiated_expr
                    templated_bound = ""
                    if callee_summary.offset_bound_expr:
                        instantiated_bound = _instantiate_summary_expr(callee_summary.offset_bound_expr, site.args)
                        if target.offset_expr and _param_type_is_byte_pointer(callee_summary.dest_arg_type):
                            instantiated_bound = _combine_offsets(target.offset_expr, instantiated_bound)
                        templated_bound = _param_template_expr(instantiated_bound, context.param_names) or instantiated_bound
                    propagated = _WriteSummary(
                        function_name=context.node.record.name,
                        function_keys=tuple(_function_keys(context.node)),
                        dest_arg_index=target.param_index,
                        kind=callee_summary.kind,
                        sink=callee_summary.sink,
                        line_number=site.line_number,
                        line_text=site.original_line.strip() or site.line.strip(),
                        dest_arg_type=callee_summary.dest_arg_type,
                        write_size_expr=templated_expr,
                        write_size_bytes=callee_summary.write_size_bytes,
                        offset_bound_expr=templated_bound,
                        offset_bound_complete=callee_summary.offset_bound_complete,
                        offset_bound_evidence=tuple(callee_summary.offset_bound_evidence),
                        semantics=callee_summary.semantics,
                        source_evidence=tuple(_unique_nonempty(list(context.source_evidence) + list(callee_summary.source_evidence))),
                        evidence_sources=tuple(
                            _unique_nonempty(
                                list(callee_summary.evidence_sources)
                                + ["fixed_point_summary", f"summary_depth_{depth}"]
                            )
                        ),
                    )
                    changed = add(propagated) or changed
        if not changed:
            break
    return summaries


def _summary_identity(summary: _WriteSummary) -> tuple[object, ...]:
    return (
        summary.function_name,
        tuple(summary.function_keys),
        summary.dest_arg_index,
        summary.dest_arg_type,
        summary.kind,
        summary.sink,
        summary.semantics,
        _normalize_offset_expr(summary.write_size_expr),
        summary.write_size_bytes,
        _normalize_offset_expr(summary.offset_bound_expr),
        summary.offset_bound_complete,
    )


def _fixed_point_source_read_summaries(
    contexts: Sequence[_FunctionContext],
    *,
    call_sites_by_context: Mapping[int, Sequence[_CallSite]] | None = None,
    max_summary_depth: int = 4,
    max_expr_nodes: int = 32,
    max_summaries_per_function: int = 20,
) -> list[_ParameterSourceReadSummary]:
    """Propagate source-read summaries through exact parameter pass-through wrappers."""

    summaries: list[_ParameterSourceReadSummary] = []
    seen: set[tuple[object, ...]] = set()
    summary_counts: dict[str, int] = {}

    def add(summary: _ParameterSourceReadSummary) -> bool:
        if _expr_node_count(summary.source_offset_expr) > max_expr_nodes:
            return False
        if _expr_node_count(summary.read_size_expr) > max_expr_nodes:
            return False
        key = _source_read_summary_identity(summary)
        if key in seen:
            return False
        current_count = summary_counts.get(summary.function_name, 0)
        if current_count >= max_summaries_per_function:
            return False
        seen.add(key)
        summaries.append(summary)
        summary_counts[summary.function_name] = current_count + 1
        return True

    for context in contexts:
        for summary in context.source_read_summaries:
            add(summary)

    call_sites_by_context = call_sites_by_context or {}
    for depth in range(1, max_summary_depth + 1):
        summaries_by_key: dict[str, list[_ParameterSourceReadSummary]] = {}
        for summary in summaries:
            for key in summary.function_keys:
                summaries_by_key.setdefault(key, []).append(summary)
        changed = False
        for context in contexts:
            if not context.param_names:
                continue
            for site in call_sites_by_context.get(id(context), ()):
                for callee_summary in _source_read_summaries_for_call(site.callee, summaries_by_key):
                    if callee_summary.param_index >= len(site.args):
                        continue
                    target = _resolve_exact_source_read_wrapper_argument(
                        site.args[callee_summary.param_index],
                        context,
                        site,
                    )
                    if not target or target.param_index is None or target.stack_obj is not None:
                        continue
                    source_offset_expr = _source_read_wrapper_offset(
                        target.offset_expr,
                        callee_summary.source_offset_expr,
                    )
                    if source_offset_expr is None:
                        continue
                    read_size_expr = _instantiate_summary_expr(callee_summary.read_size_expr, site.args)
                    read_size_expr = _param_template_expr(read_size_expr, context.param_names) or read_size_expr
                    propagated = _ParameterSourceReadSummary(
                        function_name=callee_summary.function_name,
                        function_keys=tuple(_function_keys(context.node)),
                        param_index=target.param_index,
                        sink=callee_summary.sink,
                        line_number=callee_summary.line_number,
                        line_text=callee_summary.line_text,
                        source_offset_expr=source_offset_expr,
                        read_size_expr=read_size_expr,
                        source_evidence=tuple(
                            _unique_nonempty(list(context.source_evidence) + list(callee_summary.source_evidence))
                        ),
                        evidence_sources=tuple(
                            _unique_nonempty(
                                list(callee_summary.evidence_sources)
                                + [
                                    "fixed_point_source_read_summary",
                                    f"source_summary_depth_{depth}",
                                    f"source_read_wrapper_call:{context.node.record.name}->{site.callee}",
                                ]
                            )
                        ),
                    )
                    changed = add(propagated) or changed
        if not changed:
            break
    return summaries


def _source_read_summary_identity(summary: _ParameterSourceReadSummary) -> tuple[object, ...]:
    return (
        summary.function_name,
        tuple(summary.function_keys),
        summary.param_index,
        summary.sink,
        summary.line_number,
        _normalize_offset_expr(summary.source_offset_expr),
        _normalize_offset_expr(summary.read_size_expr),
    )


def _source_read_wrapper_offset(wrapper_offset_expr: str, callee_offset_expr: str) -> str | None:
    wrapper_fields, wrapper_byte_offset = _split_param_field_offset(wrapper_offset_expr or "0")
    callee_fields, callee_byte_offset = _split_param_field_offset(callee_offset_expr or "0")
    if wrapper_fields or callee_fields:
        fields = (*wrapper_fields, *callee_fields)
        if not fields:
            return str(wrapper_byte_offset + callee_byte_offset)
        field_expr = "0" + "".join(f"->{field}" for field in fields)
        byte_offset = wrapper_byte_offset + callee_byte_offset
        return _combine_offsets(field_expr, str(byte_offset)) if byte_offset else field_expr
    if _normalize_offset_expr(wrapper_offset_expr or "0") in {"", "0"}:
        return _normalize_offset_expr(callee_offset_expr or "0")
    if _normalize_offset_expr(callee_offset_expr or "0") in {"", "0"}:
        return _normalize_offset_expr(wrapper_offset_expr or "0")
    return None


def _resolve_exact_source_read_wrapper_argument(
    expr: str,
    context: _FunctionContext,
    site: _CallSite,
) -> _AliasTarget | None:
    direct = _resolve_destination_expr(expr, context.stack_index, {}, context.param_names)
    if direct and direct.param_index is not None and direct.stack_obj is None:
        return direct
    target = _resolve_destination_expr(expr, context.stack_index, site.aliases, context.param_names)
    if not target or target.param_index is None or target.stack_obj is not None:
        return None
    if target.evidence_source != "c_alias":
        return None
    alias_name = _root_identifier(expr)
    if not alias_name or alias_name in context.param_names:
        return None
    return target if _local_alias_is_exact_param_projection(context, alias_name, site.line_number) else None


def _local_alias_is_exact_param_projection(
    context: _FunctionContext,
    alias_name: str,
    site_line_number: int,
) -> bool:
    assignments = 0
    for line_number, line, _original_line in _iter_logical_statements(context.code_lines, context.lines):
        if line_number >= site_line_number:
            break
        lhs, rhs = _split_simple_assignment(line)
        if _lhs_name(lhs) != alias_name:
            continue
        assignments += 1
        if assignments > 1 or _line_has_control_prefix(line):
            return False
        target = _resolve_destination_expr(rhs, context.stack_index, {}, context.param_names)
        if not target or target.param_index is None or target.stack_obj is not None:
            return False
    return assignments == 1


def _line_has_control_prefix(line: str) -> bool:
    return bool(re.search(r"\b(?:if|else|for|while|switch)\b", str(line or "")))


def _expr_node_count(expr: str) -> int:
    return len(re.findall(r"[A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|\d+|[()+*/%&|<>-]", expr or ""))


def _instantiate_summary_expr(expr: str, args: Sequence[str]) -> str:
    result = str(expr or "")
    for index, arg in enumerate(args):
        cleaned_arg = _normalize_offset_expr(arg)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|\d+", cleaned_arg):
            replacement = cleaned_arg
        else:
            replacement = f"({arg})"
        result = result.replace(f"${index}", replacement)
    return result


def _passes_symbolic_confirmation_filter(candidate: StaticCandidate) -> bool:
    return _confirmation_queue_rule(candidate) is not None


def _confirmation_queue_rule(candidate: StaticCandidate) -> str | None:
    if candidate.vulnerability_type == "memory_overflow":
        return confirmation_review_rule(candidate)
    if candidate.vulnerability_type == "out_of_bounds_read":
        return oob_read_confirmation_rule(candidate)
    return None


def confirmation_review_rule(candidate: StaticCandidate) -> str | None:
    """Return the single confirmation frontier rule that admits a candidate."""

    if not _candidate_has_confirmation_destination(candidate):
        return None
    if not _candidate_has_source_sink_alignment(candidate):
        return None
    if _pointer_store_uses_modeled_object_as_pointee_source(candidate):
        return None
    if _is_api_contract_confirmation_candidate(candidate):
        return None
    if _candidate_has_weak_confirmation_destination(candidate):
        return None
    if _candidate_fact_proven_safe(candidate):
        return None
    if _constant_initializer_summary_candidate(candidate):
        return None
    if candidate.verdict in {"overflow", "unbounded"}:
        if not (
            _candidate_has_reportable_confirmation_path(candidate)
            or _entry_static_format_overflow_confirmation_candidate(candidate)
            or _interprocedural_callsite_overflow_confirmation_candidate(candidate)
        ):
            return None
        if candidate.verdict == "unbounded" or candidate.write_relation == "unbounded":
            return "unbounded_sink"
        return "exact_overflow"
    if _trace_is_complete_unreachable(candidate) and _complete_unreachable_is_low_signal(candidate):
        return None
    if not _candidate_has_unresolved_confirmation_signal(candidate):
        return None
    if not _candidate_has_unresolved_write_relation(candidate):
        return None
    relation = str(candidate.write_relation or "")
    if relation == "symbolic_offset":
        return _controlled_offset_confirmation_rule(candidate)
    if relation in {"symbolic_size", "append_length_unknown"}:
        return _controlled_extent_confirmation_rule(candidate)
    if relation == "iterated_alias_unproven":
        return _loop_alias_frontier_confirmation_rule(candidate)
    return None


def oob_read_confirmation_rule(candidate: StaticCandidate) -> str | None:
    """Return the confirmation rule for read-side memory safety candidates."""

    if candidate.vulnerability_type != "out_of_bounds_read":
        return None
    if not _candidate_has_confirmation_destination(candidate):
        return None
    if not _candidate_has_source_sink_alignment(candidate):
        return None
    if _candidate_has_weak_confirmation_destination(candidate):
        return None
    if _candidate_fact_proven_safe(candidate):
        return None
    relation = str(candidate.write_relation or "")
    if relation == "proven_oob_read":
        if _candidate_has_reportable_confirmation_path(candidate):
            return "exact_oob_read"
        return None
    if _trace_is_complete_unreachable(candidate) and _complete_unreachable_is_low_signal(candidate):
        return None
    if relation not in {"symbolic_read_offset", "symbolic_size"}:
        return None
    if not _candidate_has_unresolved_confirmation_signal(candidate):
        return None
    if not _is_actionable_unresolved_confirmation_candidate(candidate):
        return None
    return "controlled_extent" if relation == "symbolic_size" else "controlled_read_offset"


def _candidate_fact_proven_safe(candidate: StaticCandidate) -> bool:
    if _candidate_is_safe_review_shadow(candidate):
        return False
    trace = candidate.classification_trace if isinstance(candidate.classification_trace, Mapping) else {}
    safety = trace.get("safety_result") if isinstance(trace.get("safety_result"), Mapping) else {}
    if safety and str(safety.get("status") or "") == "proven_safe":
        return True
    enrichment = trace.get("fact_enrichment") if isinstance(trace.get("fact_enrichment"), Mapping) else {}
    enrichment_safety = (
        enrichment.get("safety_result")
        if isinstance(enrichment.get("safety_result"), Mapping)
        else {}
    )
    return bool(enrichment_safety and str(enrichment_safety.get("status") or "") == "proven_safe")


def _candidate_has_weak_confirmation_destination(candidate: StaticCandidate) -> bool:
    trace = candidate.classification_trace if isinstance(candidate.classification_trace, Mapping) else {}
    stack = trace.get("stack_coalescing") if isinstance(trace.get("stack_coalescing"), Mapping) else {}
    if stack and str(stack.get("classification") or "") == "likely_decompiler_split":
        return True
    basis = f"{candidate.capacity_basis} {candidate.capacity_source}".lower()
    return any(token in basis for token in ("merged_stack_region", "contiguous_stack_region", "decompiler local fragment"))


def _constant_initializer_summary_candidate(candidate: StaticCandidate) -> bool:
    if candidate.verdict != "overflow" or candidate.write_relation != "proven_overflow":
        return False
    roles = _source_to_write_roles(candidate)
    if not roles:
        return False
    if not (
        candidate.kind.startswith("interprocedural_")
        or any("summary" in str(source) for source in candidate.evidence_sources)
    ):
        return False
    if not _candidate_has_initializer_summary_shape(candidate):
        return False
    for role in SOURCE_TO_WRITE_ROLES:
        fact = roles.get(role)
        if not isinstance(fact, Mapping):
            continue
        classification = str(fact.get("classification") or "")
        if classification not in {"", "constant_or_literal", "internal_local"}:
            return False
    return True


def _candidate_has_initializer_summary_shape(candidate: StaticCandidate) -> bool:
    names = [candidate.function_name]
    names.extend(callee for callee, _args in _iter_calls(candidate.line_text))
    condition = str(candidate.overflow_condition or "")
    if " writes " in condition:
        names.append(condition.split(" writes ", 1)[0].strip())
    for name in names:
        normalized = _normalize_function_name_for_match(name)
        if re.search(r"(?:^|_)(?:init|initialize|clear|reset|zero|default|setup)(?:_|$)", normalized):
            return True
        if re.search(r"^(?:init|initialize|clear|reset|zero|default|setup)[a-z0-9_]*$", normalized):
            return True
    return False


def _normalize_function_name_for_match(name: str) -> str:
    text = str(name or "").split("(", 1)[0].split("::")[-1]
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_")
    return text.lower()


def _complete_unreachable_is_low_signal(candidate: StaticCandidate) -> bool:
    if _candidate_is_safe_review_shadow(candidate):
        return False
    roles = _source_to_write_roles(candidate)
    return not _roles_have_classification(
        roles,
        SOURCE_TO_WRITE_ROLES,
        CONTROLLED_TAINT_CLASSES | {"unknown"},
    )


def _controlled_offset_confirmation_rule(candidate: StaticCandidate) -> str | None:
    offset_classification = _role_classification(
        _source_to_write_roles(candidate),
        "write_offset",
        "",
    )
    if offset_classification not in CONTROLLED_TAINT_CLASSES | {"unknown"}:
        return None
    if not _is_actionable_unresolved_confirmation_candidate(candidate):
        return None
    return "controlled_offset"


def _controlled_extent_confirmation_rule(candidate: StaticCandidate) -> str | None:
    roles = _source_to_write_roles(candidate)
    if _roles_have_controlled_dimension(
        roles,
        ("write_source", "write_size", "destination_pointer"),
    ):
        if _is_actionable_unresolved_confirmation_candidate(candidate):
            return "controlled_extent"
    if _candidate_is_safe_review_shadow(candidate) and _roles_have_classification(
        roles,
        ("write_source", "write_size", "destination_pointer"),
        {"source_controlled"},
    ):
        return "controlled_extent"
    return None


def _loop_alias_frontier_confirmation_rule(candidate: StaticCandidate) -> str | None:
    roles = _source_to_write_roles(candidate)
    if candidate.input_reaches_sink or candidate.reachability_kind in {"source_path", "local_source"}:
        return "loop_alias_frontier"
    graph = _reachability_graph_trace(candidate)
    public_boundary = bool(graph.get("is_public") or graph.get("is_exported") or graph.get("is_root_like"))
    if public_boundary and _roles_have_controlled_dimension(roles, SOURCE_TO_WRITE_ROLES):
        return "loop_alias_frontier"
    write_source = _role_classification(roles, "write_source", "")
    if candidate.path_is_valid and write_source == "unknown":
        return "loop_alias_frontier"
    if not candidate.line_text and not candidate.evidence:
        return "loop_alias_frontier"
    return None


def _reachability_graph_trace(candidate: StaticCandidate) -> Mapping[str, object]:
    trace = candidate.classification_trace if isinstance(candidate.classification_trace, Mapping) else {}
    reachability = trace.get("reachability_dataflow") if isinstance(trace.get("reachability_dataflow"), Mapping) else {}
    graph = reachability.get("graph") if isinstance(reachability.get("graph"), Mapping) else {}
    return graph


def _is_api_contract_confirmation_candidate(candidate: StaticCandidate) -> bool:
    return (
        candidate.write_relation == "missing_size_contract"
        and (
            candidate.kind.startswith("parameter_summary_")
            or candidate.destination_kind == "parameter"
            or candidate.capacity_source == "parameter_contract"
        )
    )


def _api_contract_has_confirmation_signal(candidate: StaticCandidate) -> bool:
    if candidate.write_relation != "missing_size_contract":
        return False
    if candidate.kind == "parameter_summary_call":
        return False
    if not (candidate.path_is_valid or candidate.input_reaches_sink):
        return False
    roles = _source_to_write_roles(candidate)
    return _roles_have_controlled_dimension(
        roles,
        ("write_source", "write_size", "destination_pointer"),
    )


def _candidate_has_reportable_confirmation_path(candidate: StaticCandidate) -> bool:
    return bool(
        candidate.path_is_valid
        and _candidate_has_reportable_memory_influence(candidate)
        and not _weak_object_candidate_is_not_reportable(candidate)
    )


def _entry_static_format_overflow_confirmation_candidate(candidate: StaticCandidate) -> bool:
    return bool(
        candidate.function_name in ENTRY_NAMES
        and
        candidate.path_is_valid
        and not _trace_is_complete_unreachable(candidate)
        and not _weak_object_candidate_is_not_reportable(candidate)
        and candidate.write_relation == "unbounded"
        and _normalize_sink_name(candidate.sink) in {"sprintf", "vsprintf"}
        and candidate.destination_kind in {"global", "static_local", "tls"}
    )


def _interprocedural_callsite_overflow_confirmation_candidate(candidate: StaticCandidate) -> bool:
    if not (
        candidate.path_is_valid
        and candidate.write_relation == "proven_overflow"
        and candidate.kind.startswith("interprocedural_")
        and candidate.reachability_kind == "entry_path"
        and not _trace_is_complete_unreachable(candidate)
        and not _weak_object_candidate_is_not_reportable(candidate)
    ):
        return False
    if candidate.capacity_source not in {"declared_local_array", "static_data", "global_object"}:
        return False
    for callee, _args in _iter_calls(candidate.line_text):
        if _normalize_sink_name(callee) not in ALL_SINKS:
            return True
    return False


def _candidate_has_reportable_memory_influence(candidate: StaticCandidate) -> bool:
    roles = _source_to_write_roles(candidate)
    if roles:
        return _roles_have_controlled_dimension(
            roles,
            ("write_source", "write_size", "write_offset", "destination_pointer"),
        )
    return bool(candidate.input_reaches_sink)


def _candidate_has_unresolved_dimension_taint(candidate: StaticCandidate) -> bool:
    roles = _source_to_write_roles(candidate)
    if not roles:
        return _candidate_has_attacker_taint(candidate)
    relation = str(candidate.write_relation or "")
    if relation in {"symbolic_offset", "symbolic_read_offset"}:
        return _roles_have_controlled_dimension(roles, ("write_offset", "destination_pointer"))
    if relation == "symbolic_size":
        if _candidate_has_allocation_fallback_alias(candidate):
            return _roles_have_controlled_dimension(roles, ("write_size", "write_source", "destination_pointer"))
        return bool(
            _roles_have_classification(roles, ("write_size",), {"source_controlled"})
            or _roles_have_classification(roles, ("destination_pointer",), {"source_controlled"})
        )
    if relation == "append_length_unknown":
        return _roles_have_controlled_dimension(roles, ("write_size", "write_source", "destination_pointer"))
    if relation == "iterated_alias_unproven":
        return _roles_have_controlled_dimension(roles, ("write_offset", "destination_pointer"))
    return _roles_have_controlled_dimension(
        roles,
        ("write_source", "write_size", "write_offset", "destination_pointer"),
    )


def _candidate_has_unresolved_confirmation_signal(candidate: StaticCandidate) -> bool:
    if _caller_buffer_offset_lacks_reachable_taint(candidate):
        return False
    if _candidate_has_unresolved_dimension_taint(candidate):
        return True
    if _candidate_is_safe_review_shadow(candidate):
        return True
    roles = _source_to_write_roles(candidate)
    any_controlled_role = _roles_have_controlled_dimension(
        roles,
        ("write_source", "write_size", "write_offset", "destination_pointer"),
    )
    relation = str(candidate.write_relation or "")
    if relation == "iterated_alias_unproven":
        return bool(
            any_controlled_role
            or (
                candidate.path_is_valid
                and candidate.capacity_bytes > 0
                and (
                    not _trace_is_non_input_expr_candidate(candidate)
                    or candidate.function_name not in ENTRY_NAMES
                )
            )
        )
    if relation == "symbolic_size":
        if candidate.vulnerability_type == "out_of_bounds_read":
            return bool(any_controlled_role or candidate.source_evidence or candidate.input_reaches_sink)
        if _candidate_has_allocation_fallback_alias(candidate) and any_controlled_role:
            return True
        return False
    if relation in {"symbolic_offset", "symbolic_read_offset", "append_length_unknown"}:
        if any_controlled_role:
            return True
    return False


def _caller_buffer_offset_lacks_reachable_taint(candidate: StaticCandidate) -> bool:
    roles = _source_to_write_roles(candidate)
    if _roles_have_controlled_dimension(roles, ("write_offset",)):
        return False
    return bool(
        candidate.destination_kind == "caller_buffer"
        and candidate.write_relation == "symbolic_offset"
        and not candidate.input_reaches_sink
        and (not candidate.path_is_valid or _trace_is_complete_unreachable(candidate))
    )


def _complete_unreachable_has_confirmation_signal(candidate: StaticCandidate) -> bool:
    roles = _source_to_write_roles(candidate)
    return bool(
        _candidate_has_unresolved_dimension_taint(candidate)
        or _roles_have_controlled_dimension(
            roles,
            ("write_source", "write_size", "write_offset", "destination_pointer"),
        )
        or _candidate_is_safe_review_shadow(candidate)
    )


def _roles_have_controlled_dimension(
    roles: Mapping[str, object],
    dimensions: Sequence[str],
) -> bool:
    return _roles_have_classification(roles, dimensions, CONTROLLED_TAINT_CLASSES)


def _candidate_has_allocation_fallback_alias(candidate: StaticCandidate) -> bool:
    return any(str(source) == "allocation_fallback_alias" for source in candidate.evidence_sources)


def _roles_have_classification(
    roles: Mapping[str, object],
    dimensions: Sequence[str],
    classifications: AbstractSet[str],
) -> bool:
    for dimension in dimensions:
        fact = roles.get(dimension)
        if not isinstance(fact, Mapping):
            continue
        if str(fact.get("classification") or "") in classifications:
            return True
    return False


def _is_actionable_unresolved_confirmation_candidate(candidate: StaticCandidate) -> bool:
    relation = str(candidate.write_relation or "")
    kind = candidate.kind.removeprefix("parameter_summary_")
    if relation in {"append_length_unknown", "iterated_alias_unproven"}:
        return True
    if relation == "symbolic_size":
        if candidate.vulnerability_type == "out_of_bounds_read":
            return kind in {"source_read", "call"} and bool(candidate.path_is_valid)
        if _candidate_has_allocation_fallback_alias(candidate):
            return kind == "call"
        return kind == "call" and bool(candidate.path_is_valid)
    if relation not in {"symbolic_offset", "symbolic_read_offset"}:
        return False
    if kind == "pointer_read" and candidate.destination_kind == "heap":
        return _role_classification(_source_to_write_roles(candidate), "write_offset", "") == "source_controlled"
    if candidate.destination_kind in {"heap", "global", "static_local", "tls"}:
        return bool(candidate.path_is_valid)
    if kind == "source_read":
        return bool(candidate.path_is_valid)
    if kind in {"call", "interprocedural_call"}:
        return bool(candidate.path_is_valid)
    if kind in {"indexed_write", "interprocedural_indexed_write", "indexed_read"}:
        return bool(candidate.path_is_valid)
    if _is_unknown_interprocedural_pointer_store_summary(candidate):
        return True
    return False


def _is_unknown_interprocedural_pointer_store_summary(candidate: StaticCandidate) -> bool:
    return (
        candidate.kind == "interprocedural_pointer_store"
        and candidate.write_relation == "symbolic_offset"
        and not candidate.path_is_valid
    )


def _candidate_is_safe_review_shadow(candidate: StaticCandidate) -> bool:
    trace = candidate.classification_trace if isinstance(candidate.classification_trace, Mapping) else {}
    return bool(trace.get("safe_review_shadow"))


def _candidate_has_confirmation_destination(candidate: StaticCandidate) -> bool:
    if candidate.kind.startswith("parameter_summary_"):
        return candidate.destination_kind == "parameter" and candidate.capacity_source == "parameter_contract"
    if candidate.destination_kind == "caller_buffer":
        return candidate.capacity_source in {"sink_size_arg", "caller_size_argument"}
    if candidate.capacity_bytes <= 0:
        model = candidate.capacity_model or {}
        symbolic_expr = str(model.get("symbolic_expr") or "")
        if not symbolic_expr and candidate.destination_kind not in {"heap", "parameter", "global", "static_local", "tls"}:
            return False
    basis = str(candidate.capacity_basis or "").lower()
    if "caller-provided pointer" in basis or "contiguous_stack_region" in basis or "merged_stack_region" in basis:
        return False
    return True


def _candidate_has_unresolved_write_relation(candidate: StaticCandidate) -> bool:
    relation = str(candidate.write_relation or "")
    if relation in {
        "append_length_unknown",
        "iterated_alias_unproven",
        "proven_overflow",
        "symbolic_offset",
        "symbolic_size",
        "missing_size_contract",
        "symbolic_read_offset",
        "unbounded",
    }:
        return True
    if relation in {
        "iterated_alias_local",
        "proven_safe",
        "symbolic_offset_size_guarded",
        "unproven_offset_relation",
        "unproven_size_relation",
    }:
        return False
    kind = candidate.kind.removeprefix("parameter_summary_").removeprefix("interprocedural_")
    if kind == "field_write":
        return False
    sink = _normalize_sink_name(candidate.sink)
    semantics = str(OPERATION_SPECS.get(sink, {}).get("semantics") or "")
    if semantics in {"unbounded", "format_string"}:
        return True
    if semantics == "append_bounded":
        return True
    if semantics == "bounded":
        return candidate.write_size_bytes is None or _expr_is_symbolic(candidate.write_size_expr)
    if kind in {"indexed_write", "field_indexed_write", "pointer_store", "pcode_store"}:
        return (
            candidate.write_size_bytes is None
            or _expr_is_symbolic(candidate.write_size_expr)
            or _summary_expr_has_negative_offset(candidate.write_size_expr)
        )
    return False


def _expr_is_symbolic(expr: str) -> bool:
    text = _normalize_offset_expr(str(expr or ""))
    if not text:
        return True
    if text.lower() in {"unknown", "unbounded", "unbounded %s", "unknown scanf format"}:
        return True
    if _parse_int_literal(text) is not None:
        return False
    return bool(re.search(r"[A-Za-z_][A-Za-z0-9_]*", text))


def _summary_expr_has_negative_offset(expr: str) -> bool:
    text = _normalize_offset_expr(expr)
    if not text:
        return False
    literal = _parse_int_literal(text)
    if literal is not None:
        return literal < 0
    return bool(re.search(r"(^|[+(*/%&|^]\s*)-\s*(?:0x[0-9a-fA-F]+|\d+|[A-Za-z_])", text))


def _iter_logical_statements(
    code_lines: Sequence[str],
    original_lines: Sequence[str],
) -> Iterable[tuple[int, str, str]]:
    buffer: list[str] = []
    original_buffer: list[str] = []
    start_line = 0
    depth = 0
    for line_number, line in enumerate(code_lines, start=1):
        stripped = line.strip()
        if not stripped and not buffer:
            continue
        if not buffer:
            start_line = line_number
        buffer.append(stripped)
        original_buffer.append(
            original_lines[line_number - 1].strip() if line_number - 1 < len(original_lines) else stripped
        )
        depth += _paren_delta(stripped)
        if depth <= 0 and (";" in stripped or stripped.endswith("{") or stripped.endswith("}")):
            yield start_line, " ".join(buffer), " ".join(original_buffer)
            buffer = []
            original_buffer = []
            start_line = 0
            depth = 0
    if buffer:
        yield start_line or 1, " ".join(buffer), " ".join(original_buffer)


def _paren_delta(line: str) -> int:
    quote: Optional[str] = None
    escaped = False
    delta = 0
    for ch in line:
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in {"'", '"'}:
            quote = ch
            continue
        if ch == "(":
            delta += 1
        elif ch == ")":
            delta -= 1
    return delta


def _summary_offset_bound_status(
    summary: _WriteSummary,
    target: _AliasTarget,
    args: Sequence[str],
    stack_index: _StackIndex,
    capacity: int,
    write_width: int,
) -> Optional[tuple[str, str, int]]:
    if not summary.offset_bound_expr or capacity <= 0:
        return None
    caller_offset = _eval_optional_offset(target.offset_expr, stack_index)
    if caller_offset is None or caller_offset < 0:
        return None
    instantiated_bound = _instantiate_summary_expr(summary.offset_bound_expr, args)
    upper_expr = _combine_offsets(target.offset_expr, instantiated_bound)
    upper = _eval_optional_offset(upper_expr, stack_index)
    if upper is None or upper < caller_offset:
        return None
    highest_byte = upper + max(1, write_width)
    if highest_byte > capacity:
        return None
    status = "safe" if summary.offset_bound_complete else "upper_guarded"
    return status, upper_expr or "0", upper


def _candidate_from_summary(
    manifest: Manifest,
    context: _FunctionContext,
    summary: _WriteSummary,
    target: _AliasTarget,
    args: Sequence[str],
    line_number: int,
    line: str,
    *,
    peer_summaries: Sequence[_WriteSummary] = (),
) -> Optional[StaticCandidate]:
    stack_obj = target.stack_obj
    if not stack_obj:
        return None
    summary_write_expr = _instantiate_summary_expr(summary.write_size_expr, args)
    capacity = _safe_int(stack_obj.get("size_bytes"))
    evidence_sources = list(summary.evidence_sources)
    for source in _candidate_sources("interprocedural", target):
        if source not in evidence_sources:
            evidence_sources.append(source)
    source_evidence = list(context.source_evidence)
    for item in summary.source_evidence:
        if item not in source_evidence:
            source_evidence.append(item)

    if summary.semantics in {"bounded", "append_bounded"}:
        write_size = summary.write_size_bytes
        if write_size is None:
            write_size = _eval_int_expr(summary_write_expr, context.stack_index)
        unknown_object_extent = _summary_target_has_unknown_object_extent(
            summary,
            target,
            args,
            stack_obj,
            peer_summaries=peer_summaries,
            call_text=line,
        )
        metadata_extent_unknown = not _capacity_is_proof_grade(stack_obj)
        if metadata_extent_unknown:
            unknown_object_extent = True
        unknown_direct_extent = _bounded_byte_sink_has_unknown_direct_extent(
            summary.sink,
            summary.semantics,
            stack_obj,
            write_size,
        )
        candidate_stack_obj = stack_obj
        capacity_source = ""
        if unknown_direct_extent:
            unknown_object_extent = True
            candidate_stack_obj = _direct_object_extent_unknown_stack_obj(stack_obj)
            capacity_source = "direct_object_extent_unknown"
            if "direct_object_extent_unknown" not in evidence_sources:
                evidence_sources.append("direct_object_extent_unknown")
        elif unknown_object_extent:
            candidate_stack_obj, capacity_source, evidence_sources = _summary_unknown_extent_obj(
                stack_obj,
                evidence_sources,
            )
        if (
            summary.semantics == "bounded"
            and not unknown_object_extent
            and write_size is not None
            and _bounded_write_is_proven_safe(stack_obj, target, write_size, context.stack_index)
        ):
            return None
        bounded_overflow = (
            write_size is not None
            and _bounded_write_is_proven_overflow(stack_obj, target, write_size, context.stack_index)
        )
        if summary.semantics == "append_bounded" and write_size is not None and write_size <= capacity:
            verdict = "candidate"
            condition = (
                f"{summary.function_name} calls {summary.sink} on argument {summary.dest_arg_index}; "
                f"caller passes stack storage and current destination length is unknown"
            )
            write_relation = "append_length_unknown"
        else:
            verdict = "overflow" if bounded_overflow or (write_size is not None and write_size > capacity) else "candidate"
            if unknown_object_extent and (bounded_overflow or (write_size is not None and write_size > capacity)):
                verdict = "candidate"
                write_relation = "symbolic_capacity"
                if unknown_direct_extent:
                    condition = (
                        f"{summary.function_name} writes argument {summary.dest_arg_index} with {summary.sink}; "
                        f"the {capacity}-byte decompiler local fragment is not treated as the full object capacity"
                    )
                else:
                    condition = (
                        f"{summary.function_name} writes argument {summary.dest_arg_index} with {summary.sink}; "
                        f"caller object extent is unknown, so the {capacity}-byte decompiler local fragment "
                        "is not treated as the full capacity"
                    )
            elif bounded_overflow:
                offset = _eval_optional_offset(target.offset_expr, context.stack_index) or 0
                condition = (
                    f"{summary.function_name} writes byte range {offset}..{offset + write_size - 1} "
                    f"of caller argument {summary.dest_arg_index}, outside {capacity} bytes"
                )
                write_relation = "proven_overflow"
            elif write_size is not None and write_size > capacity:
                condition = (
                    f"{summary.function_name} writes {write_size} bytes to argument {summary.dest_arg_index}; "
                    f"caller passes {capacity}-byte storage"
                )
                write_relation = "proven_overflow"
            else:
                if write_size is not None and target.offset_expr and _eval_optional_offset(target.offset_expr, context.stack_index) is None:
                    condition = (
                        f"{summary.function_name} writes argument {summary.dest_arg_index} with "
                        f"{summary.sink}; caller destination offset is not statically bounded"
                    )
                    write_relation = "symbolic_offset"
                else:
                    condition = (
                        f"{summary.function_name} writes argument {summary.dest_arg_index} with "
                        f"{summary.sink}; size is not statically bounded at the caller"
                    )
                    write_relation = "symbolic_size"
        return _build_candidate(
            manifest,
            context.node,
            candidate_stack_obj,
            kind="interprocedural_call",
            sink=summary.sink,
            line_number=line_number,
            line=line,
            write_size_expr=summary_write_expr,
            write_size_bytes=write_size,
            verdict=verdict,
            overflow_condition=condition,
            source_evidence=source_evidence,
            evidence_sources=evidence_sources,
            capacity_source=capacity_source,
            write_relation=write_relation,
            offset_expr=target.offset_expr or "0",
        )

    if summary.semantics == "field_write":
        return None

    if summary.semantics in {"indexed_write", "pointer_store"}:
        element_size = _element_size(stack_obj)
        if summary.semantics == "pointer_store":
            offset_scale = _pointer_summary_offset_scale(summary, element_size)
            write_width = summary.write_size_bytes or element_size
        else:
            offset_scale = element_size
            write_width = element_size
        offset_expr = _combine_scaled_offset(target.offset_expr, summary_write_expr, offset_scale)
        constant_offset = _eval_optional_offset(offset_expr, context.stack_index)
        unknown_object_extent = _summary_target_has_unknown_object_extent(
            summary,
            target,
            args,
            stack_obj,
            peer_summaries=peer_summaries,
            call_text=line,
        )
        metadata_extent_unknown = not _capacity_is_proof_grade(stack_obj)
        if metadata_extent_unknown:
            unknown_object_extent = True
        candidate_stack_obj = stack_obj
        capacity_source = ""
        if unknown_object_extent:
            candidate_stack_obj, capacity_source, evidence_sources = _summary_unknown_extent_obj(
                stack_obj,
                evidence_sources,
            )
        if constant_offset is not None:
            highest_byte = constant_offset + write_width
            if 0 <= constant_offset and highest_byte <= capacity:
                return None
            if unknown_object_extent:
                verdict = "candidate"
                write_relation = "symbolic_capacity"
                condition = (
                    f"{summary.function_name} writes byte range {constant_offset}..{highest_byte - 1} "
                    f"through caller stack argument {summary.dest_arg_index}; caller object extent is unknown, "
                    f"so the {capacity}-byte decompiler local fragment is not treated as the full capacity"
                )
            else:
                verdict = "overflow"
                write_relation = "proven_overflow"
                condition = (
                    f"{summary.function_name} writes byte range {constant_offset}..{highest_byte - 1} "
                    f"of caller argument {summary.dest_arg_index}, outside {capacity} bytes"
                )
        else:
            bound_status = (
                None
                if unknown_object_extent
                else _summary_offset_bound_status(
                    summary,
                    target,
                    args,
                    context.stack_index,
                    capacity,
                    write_width,
                )
            )
            if bound_status and bound_status[0] == "safe":
                return None
            verdict = "candidate"
            if unknown_object_extent:
                write_relation = "symbolic_capacity"
                condition = (
                    f"{summary.function_name} writes through caller stack argument {summary.dest_arg_index}; "
                    f"offset {offset_expr or summary_write_expr or 'unknown'} and caller object extent are not "
                    f"statically known"
                )
            elif bound_status:
                _status, upper_expr, upper = bound_status
                if "summary_offset_bound" not in evidence_sources:
                    evidence_sources.append("summary_offset_bound")
                for item in summary.offset_bound_evidence:
                    if item not in source_evidence:
                        source_evidence.append(item)
                write_relation = "symbolic_offset_size_guarded"
                condition = (
                    f"{summary.function_name} writes through caller stack argument {summary.dest_arg_index}; "
                    f"callee size guard bounds the highest byte at {upper_expr} ({upper}) within {capacity} bytes, "
                    "but the lower offset is not fully proven"
                )
            else:
                write_relation = "symbolic_offset"
                condition = (
                    f"{summary.function_name} writes through caller stack argument {summary.dest_arg_index}; "
                    f"offset {offset_expr or summary_write_expr or 'unknown'} is not proven within {capacity} bytes"
                )
        return _build_candidate(
            manifest,
            context.node,
            candidate_stack_obj,
            kind=f"interprocedural_{summary.kind}",
            sink=summary.sink,
            line_number=line_number,
            line=line,
            write_size_expr=offset_expr or summary_write_expr or "unknown",
            write_size_bytes=write_width,
            verdict=verdict,
            overflow_condition=condition,
            source_evidence=source_evidence,
            evidence_sources=evidence_sources,
            capacity_source=capacity_source,
            write_relation=write_relation,
            offset_expr=offset_expr or summary_write_expr or "unknown",
        )

    if summary.semantics == "unbounded" and summary.write_size_bytes is not None:
        write_size = summary.write_size_bytes
        status, relation, condition = _classify_memory_write(
            stack_obj,
            target.offset_expr or "0",
            write_size,
            summary_write_expr or str(write_size),
            context.stack_index,
        )
        if status == "safe":
            return None
        candidate_stack_obj = stack_obj
        capacity_source = ""
        if status == "overflow" and not _capacity_is_proof_grade(stack_obj):
            candidate_stack_obj, capacity_source, evidence_sources = _summary_unknown_extent_obj(
                stack_obj,
                evidence_sources,
            )
            status = "candidate"
            relation = "symbolic_capacity"
            condition = (
                f"{summary.function_name} writes argument {summary.dest_arg_index} with {summary.sink}; "
                f"the {capacity}-byte recovered metadata extent is not treated as the full capacity"
            )
        return _build_candidate(
            manifest,
            context.node,
            candidate_stack_obj,
            kind="interprocedural_call",
            sink=summary.sink,
            line_number=line_number,
            line=line,
            write_size_expr=summary_write_expr or str(write_size),
            write_size_bytes=write_size,
            verdict="overflow" if status == "overflow" else "candidate",
            overflow_condition=condition,
            source_evidence=source_evidence,
            evidence_sources=_unique_nonempty([*evidence_sources, "literal_source_bound"]),
            capacity_source=capacity_source,
            write_relation=relation,
            offset_expr=target.offset_expr or "0",
        )

    verdict = "unbounded" if summary.semantics in {"unbounded", "format_string"} else "candidate"
    write_relation = "unbounded" if verdict == "unbounded" else "symbolic_size"
    candidate_stack_obj = stack_obj
    capacity_source = ""
    condition = (
        f"{summary.function_name} writes argument {summary.dest_arg_index} with {summary.sink}; "
        f"caller passes {capacity}-byte storage"
    )
    if verdict == "unbounded" and not _capacity_is_proof_grade(stack_obj):
        candidate_stack_obj, capacity_source, evidence_sources = _summary_unknown_extent_obj(
            stack_obj,
            evidence_sources,
        )
        verdict = "candidate"
        write_relation = "symbolic_capacity"
        condition = (
            f"{summary.function_name} writes argument {summary.dest_arg_index} with {summary.sink}; "
            f"the {capacity}-byte recovered metadata extent is not treated as the full capacity"
        )
    return _build_candidate(
        manifest,
        context.node,
        candidate_stack_obj,
        kind="interprocedural_call",
        sink=summary.sink,
        line_number=line_number,
        line=line,
        write_size_expr=summary_write_expr or "unknown",
        write_size_bytes=summary.write_size_bytes,
        verdict=verdict,
        overflow_condition=condition,
        source_evidence=source_evidence,
        evidence_sources=evidence_sources,
        capacity_source=capacity_source,
        write_relation=write_relation,
        offset_expr=target.offset_expr or "0",
    )


def _uninstantiated_parameter_summary_candidates(
    manifest: Manifest,
    contexts: Sequence[_FunctionContext],
    summaries: Sequence[_WriteSummary],
) -> list[StaticCandidate]:
    context_by_name = {context.node.record.name: context for context in contexts}
    candidates: list[StaticCandidate] = []
    for summary in summaries:
        context = context_by_name.get(summary.function_name)
        if context is None or not _is_api_like_context(context):
            continue
        if summary.dest_arg_index >= len(context.param_names):
            continue
        param_name = context.param_names[summary.dest_arg_index]
        if not param_name:
            continue
        parameter_obj = {
            "label": param_name,
            "var_display": param_name,
            "size_bytes": 0,
            "capacity_expr": f"caller_capacity({param_name})",
            "annotation": f"{param_name}: exported/API parameter buffer with no local size contract",
            "capacity_source": "parameter_contract",
            "capacity_basis_kind": "parameter_contract",
            "destination_kind": "parameter",
            "var_names": [param_name],
        }
        condition = (
            f"{summary.function_name} writes to parameter {param_name} with {summary.sink}; "
            "no local destination capacity contract is available"
        )
        candidate = _build_candidate(
            manifest,
            context.node,
            parameter_obj,
            kind=f"parameter_summary_{summary.kind}",
            sink=summary.sink,
            line_number=summary.line_number,
            line=summary.line_text,
            write_size_expr=summary.write_size_expr or "unknown",
            write_size_bytes=summary.write_size_bytes,
            verdict="candidate",
            overflow_condition=condition,
            source_evidence=summary.source_evidence,
            evidence_sources=tuple(
                _unique_nonempty(list(summary.evidence_sources) + ["uninstantiated_parameter_summary"])
            ),
            destination_kind="parameter",
            capacity_source="parameter_contract",
            write_relation="missing_size_contract",
            offset_expr="0",
        )
        candidates.append(candidate)
    return candidates


def _is_api_like_context(context: _FunctionContext) -> bool:
    record = context.node.record
    return bool(record.source_symbol or record.demangled_name or record.source_object)


def _function_summaries_from_contexts(
    contexts: Sequence[_FunctionContext],
    allocation_summaries: Sequence[_AllocationSummary],
    write_summaries: Sequence[_WriteSummary] | None = None,
) -> list[FunctionSummary]:
    allocations_by_function: dict[str, list[dict[str, object]]] = {}
    for summary in allocation_summaries:
        allocations_by_function.setdefault(summary.function_name, []).append(
            {
                "function_keys": list(summary.function_keys),
                "capacity_expr": summary.capacity_expr,
                "source": summary.source,
            }
        )
    summaries: list[FunctionSummary] = []
    summaries_by_function: dict[str, list[_WriteSummary]] = {}
    for summary in write_summaries or [summary for context in contexts for summary in context.summaries]:
        summaries_by_function.setdefault(summary.function_name, []).append(summary)
    for context in contexts:
        write_entries = [
            {
                "function_name": summary.function_name,
                "function_keys": list(summary.function_keys),
                "dest_arg_index": summary.dest_arg_index,
                "kind": summary.kind,
                "sink": summary.sink,
                "line_number": summary.line_number,
                "line_text": summary.line_text,
                "dest_arg_type": summary.dest_arg_type,
                "write_size_expr": summary.write_size_expr,
                "write_size_bytes": summary.write_size_bytes,
                "offset_bound_expr": summary.offset_bound_expr,
                "offset_bound_complete": summary.offset_bound_complete,
                "offset_bound_evidence": list(summary.offset_bound_evidence),
                "semantics": summary.semantics,
                "source_evidence": list(summary.source_evidence),
                "evidence_sources": list(summary.evidence_sources),
            }
            for summary in summaries_by_function.get(context.node.record.name, [])
        ]
        source_entries = [
            {"evidence": evidence, "function_name": context.node.record.name}
            for evidence in context.source_evidence
        ]
        wrappers: list[dict[str, object]] = []
        if context.node.record.wrapper_type:
            wrappers.append({"wrapper_type": context.node.record.wrapper_type})
        if context.node.record.stub_kind:
            wrappers.append({"stub_kind": context.node.record.stub_kind})
        if write_entries or source_entries or wrappers or allocations_by_function.get(context.node.record.name):
            summaries.append(
                FunctionSummary(
                    function_name=context.node.record.name,
                    function_keys=_function_keys(context.node),
                    writes=write_entries[:20],
                    allocations=allocations_by_function.get(context.node.record.name, [])[:20],
                    sources=source_entries[:20],
                    wrappers=wrappers,
                    max_depth=0,
                    complete=len(summaries_by_function.get(context.node.record.name, [])) <= 20,
                )
            )
    return summaries


def _with_v3_trace(candidate: StaticCandidate) -> StaticCandidate:
    capacity_model = candidate.capacity_model or _capacity_model_for_candidate(candidate)
    base_candidate = replace(candidate, capacity_model=capacity_model)
    trace = {
        **_classification_trace_for_candidate(base_candidate),
        **dict(candidate.classification_trace or {}),
    }
    tier = candidate.triage_tier or triage_tier_for_candidate(candidate)
    return replace(
        candidate,
        capacity_model=capacity_model,
        classification_trace=trace,
        triage_tier=tier,
    )


def _classification_trace_for_candidate(candidate: StaticCandidate) -> dict[str, object]:
    base = classified_trace_for_candidate(candidate)
    accepted_guards, rejected_guards = _guard_trace_for_candidate(candidate)
    evidence_sources = list(candidate.evidence_sources)
    return {
        **base,
        "object_resolution": {
            "target_buffer": candidate.target_buffer,
            "destination_kind": candidate.destination_kind,
            "object_identity": f"{candidate.destination_kind}:{candidate.target_buffer}",
            "object_trust": _object_trust_for_candidate(candidate),
            "evidence_sources": evidence_sources,
        },
        "capacity_resolution": candidate.capacity_model or _capacity_model_for_candidate(candidate),
        "write_resolution": {
            "vulnerability_type": candidate.vulnerability_type,
            "sink": candidate.sink,
            "kind": candidate.kind,
            "operation_address": candidate.operation_address,
            "offset_expr": candidate.offset_expr,
            "write_size_expr": candidate.write_size_expr,
            "write_size_bytes": candidate.write_size_bytes,
            "relation": candidate.write_relation,
            "condition": candidate.overflow_condition,
        },
        "guards": {
            "accepted": accepted_guards,
            "rejected": rejected_guards,
        },
        "bounds": {
            "accepted": [
                {"source": "guard", "relation": guard, "reason": "accepted nearby bound"}
                for guard in accepted_guards
            ],
            "rejected": [
                {"source": "guard", "relation": guard, "reason": candidate.overflow_condition}
                for guard in rejected_guards
            ],
        },
        "aliases": [source for source in evidence_sources if "alias" in source],
        "summaries": [source for source in evidence_sources if "summary" in source],
        "sources": [
            {"source_kind": "input", "evidence": evidence}
            for evidence in candidate.source_evidence
        ],
        "source_flow": list(candidate.source_evidence),
        "attacker_control": _attacker_control_trace(candidate),
        "integer_relations": _integer_relation_trace(candidate),
        "loop_shape": _loop_shape_trace(candidate),
        "suppression_reason": "",
        "triage_tier": candidate.triage_tier or triage_tier_for_candidate(candidate),
    }


def _suppress_proven_safe_by_fact_enrichment(
    candidates: Sequence[StaticCandidate],
    nodes: Sequence[FunctionNode],
) -> tuple[list[StaticCandidate], list[WriteFact], list[ClassifiedFinding], list[SuppressedFinding]]:
    node_by_name = {node.record.name: node for node in nodes}
    kept: list[StaticCandidate] = []
    safe_facts: list[WriteFact] = []
    safe_classified: list[ClassifiedFinding] = []
    suppressed: list[SuppressedFinding] = []
    for candidate in candidates:
        if candidate.write_relation not in {
            "append_length_unknown",
            "iterated_alias_unproven",
            "symbolic_offset",
            "symbolic_read_offset",
            "symbolic_size",
            "unbounded",
        }:
            kept.append(candidate)
            continue
        if candidate.line_number <= 0:
            kept.append(candidate)
            continue
        node = node_by_name.get(candidate.function_name)
        facts = build_enriched_facts(
            candidate.to_dict(),
            source_text=node.text if node else "",
            excerpt=_candidate_source_excerpt(node.text if node else "", candidate.line_number, radius=40),
        )
        safety = facts.get("safety_result") if isinstance(facts.get("safety_result"), Mapping) else {}
        if safety.get("status") != "proven_safe":
            kept.append(candidate)
            continue
        keep_review_shadow = _should_keep_safe_review_shadow(candidate, facts)
        if keep_review_shadow:
            kept.append(
                replace(
                    candidate,
                    classification_trace={
                        **dict(candidate.classification_trace or {}),
                        "fact_enrichment": facts,
                        "safe_review_shadow": True,
                    },
                )
            )
        relational = facts.get("relational_safety_proof") if isinstance(facts.get("relational_safety_proof"), Mapping) else {}
        relational_safe = bool(relational.get("status") == "proven_safe" and relational.get("all_paths_proven"))
        reason = str(safety.get("reason") or "fact enrichment proved this write safe")
        suppression_reason = (
            "relational_allocation_write_proven_safe" if relational_safe else "fact_enrichment_proven_safe"
        )
        safe_candidate = replace(
            candidate,
            write_relation="proven_safe",
            overflow_condition=reason,
            classification_trace={
                **dict(candidate.classification_trace or {}),
                "fact_enrichment": facts,
                "suppression_reason": suppression_reason,
            },
        )
        fact = candidate_to_write_fact(safe_candidate)
        fact = replace(
            fact,
            raw={
                **dict(fact.raw),
                "relation": "proven_safe",
                "condition": reason,
                "safety_result": safety,
            },
        )
        safe_facts.append(fact)
        safe_classified.append(_classified_finding_from_write_fact(fact, status="safe"))
        suppressed.append(
            SuppressedFinding(
                fact_id=candidate.candidate_id,
                reason=suppression_reason,
                function_name=candidate.function_name,
                sink=candidate.sink,
                target_buffer=candidate.target_buffer,
                trace={
                    "relation": candidate.write_relation,
                    "condition": reason,
                    "safety_result": dict(safety),
                    "range_table": facts.get("range_table", []),
                    "reject_guard_table": facts.get("reject_guard_table", []),
                    "loop_summary": facts.get("loop_summary", []),
                    "append_length_table": facts.get("append_length_table", []),
                    "allocation_table": facts.get("allocation_table", []),
                    "relational_safety_proof": dict(relational),
                },
            )
        )
        plan_reason = _plan_suppression_reason_for_fact_enrichment(candidate, facts)
        if plan_reason:
            suppressed.append(
                SuppressedFinding(
                    fact_id=candidate.candidate_id,
                    reason=plan_reason,
                    function_name=candidate.function_name,
                    sink=candidate.sink,
                    target_buffer=candidate.target_buffer,
                    trace={
                        "relation": candidate.write_relation,
                        "condition": reason,
                        "cluster_rule": plan_reason,
                        "safety_result": dict(safety),
                        "range_table": facts.get("range_table", []),
                        "append_length_table": facts.get("append_length_table", []),
                        "allocation_table": facts.get("allocation_table", []),
                    },
                )
            )
    return kept, safe_facts, safe_classified, suppressed


def _should_keep_safe_review_shadow(
    candidate: StaticCandidate,
    facts: Mapping[str, object],
) -> bool:
    if candidate.write_relation != "symbolic_size":
        return False
    if _plan_suppression_reason_for_fact_enrichment(candidate, facts) != "allocation_write_proven_safe":
        return False
    if candidate.function_name in ENTRY_NAMES:
        return False
    if not any(
        isinstance(item, Mapping) and item.get("matched") and item.get("exact")
        for item in facts.get("allocation_table", []) or []
    ):
        return False
    return bool(candidate.source_evidence or candidate.input_reaches_sink or candidate.path_is_valid)


def _plan_suppression_reason_for_fact_enrichment(
    candidate: StaticCandidate,
    facts: Mapping[str, object],
) -> str:
    if candidate.write_relation == "append_length_unknown":
        return "bounded_capacity_proven_safe"
    allocation_table = facts.get("allocation_table", [])
    if isinstance(allocation_table, Sequence) and not isinstance(allocation_table, (str, bytes, bytearray)):
        if any(isinstance(item, Mapping) and item.get("matched") and item.get("exact") for item in allocation_table):
            return "allocation_write_proven_safe"
    if candidate.write_relation in {"symbolic_offset", "iterated_alias_unproven"}:
        return "range_loop_proven_safe"
    if candidate.write_relation == "symbolic_size":
        sink = _normalize_sink_name(candidate.sink)
        if sink in LENGTH_DEST_AND_SIZE_ARGS or candidate.kind in {"call", "interprocedural_call"}:
            return "bounded_capacity_proven_safe"
    return ""


def _attach_cve_verification_guidance(
    nodes: Sequence[FunctionNode],
    candidates: Sequence[StaticCandidate],
) -> list[StaticCandidate]:
    node_by_name = {node.record.name: node for node in nodes}
    enriched: list[StaticCandidate] = []
    for candidate in candidates:
        node = node_by_name.get(candidate.function_name)
        trace = dict(candidate.classification_trace or {})
        trace["stack_coalescing"] = _stack_coalescing_trace(candidate, node)
        interim = replace(candidate, classification_trace=trace)
        trace["review_priority"] = _review_priority_trace(interim)
        enriched.append(replace(candidate, classification_trace=trace))
    return enriched


def _stack_coalescing_trace(
    candidate: StaticCandidate,
    node: FunctionNode | None,
) -> dict[str, object]:
    evidence: list[str] = []
    if candidate.destination_kind != "stack":
        return {"classification": "not_indicated", "evidence": [], "complete": True}
    capacity = _candidate_fragment_capacity_for_coalescing(candidate)
    if capacity <= 0 or capacity > 8:
        return {"classification": "not_indicated", "evidence": [], "complete": True}
    target_names = _raw_stack_names_for_candidate(candidate)
    if not target_names:
        return {"classification": "not_indicated", "evidence": [], "complete": True}
    evidence.append(f"destination {candidate.target_buffer} is a small {capacity}-byte raw stack slot")
    source_text = node.text if node else ""
    nearby = _nearby_raw_stack_slot_names(source_text, target_names)
    if len(nearby) < 2:
        return {"classification": "not_indicated", "evidence": evidence[:8], "complete": True}
    evidence.append("nearby raw stack slots: " + ", ".join(nearby[:6]))
    if candidate.write_size_bytes and candidate.write_size_bytes > capacity:
        evidence.append(f"write size {candidate.write_size_bytes} exceeds the selected slot capacity")
    elif _expr_is_symbolic(candidate.write_size_expr):
        evidence.append(f"write size expression {candidate.write_size_expr} is symbolic against the selected slot")
    return {
        "classification": "likely_decompiler_split",
        "evidence": _unique_nonempty(evidence)[:8],
        "complete": True,
    }


def _candidate_fragment_capacity_for_coalescing(candidate: StaticCandidate) -> int:
    if candidate.capacity_bytes > 0:
        return candidate.capacity_bytes
    match = re.search(r"fragment as (?P<size>\d+) bytes", candidate.capacity_basis or "")
    if not match:
        return 0
    return _safe_int(match.group("size"))


def _raw_stack_names_for_candidate(candidate: StaticCandidate) -> list[str]:
    names = [
        candidate.target_buffer,
        *re.findall(RAW_STACK_SLOT_RE, candidate.capacity_basis or ""),
        *re.findall(RAW_STACK_SLOT_RE, candidate.line_text or ""),
    ]
    return _unique_nonempty([name for name in names if _looks_like_raw_stack_slot_name(name)])


def _nearby_raw_stack_slot_names(source_text: str, target_names: Sequence[str]) -> list[str]:
    if not source_text:
        return []
    target_set = set(target_names)
    names: list[str] = []
    for line in source_text.splitlines()[:220]:
        for match in RAW_STACK_SLOT_RE.finditer(line):
            name = match.group(0)
            if name in target_set or any(target in line for target in target_set):
                names.append(name)
                continue
            if re.search(r"\b(?:undefined\d*|char|byte|int|long|uint|ulong|short)\b", line):
                names.append(name)
    return _unique_nonempty(names)


def _review_priority_trace(candidate: StaticCandidate) -> dict[str, object]:
    score = 35
    reasons: list[str] = []
    relation = candidate.write_relation
    if relation in {"proven_overflow", "unbounded"}:
        score += 35
        reasons.append(f"{relation} relation")
    elif relation in {"symbolic_offset", "symbolic_size"}:
        score += 22
        reasons.append(f"unresolved {relation} relation")
    elif relation in {"iterated_alias_unproven", "append_length_unknown"}:
        score += 16
        reasons.append(f"unresolved {relation} relation")

    roles = _source_to_write_roles(candidate)
    controlled_roles: list[str] = []
    parameter_roles: list[str] = []
    for role in ("write_source", "write_size", "write_offset", "destination_pointer"):
        classification = _role_classification(roles, role, "")
        if classification == "source_controlled":
            controlled_roles.append(role)
        elif classification == "parameter_controlled":
            parameter_roles.append(role)
    if controlled_roles:
        score += 16
        reasons.append("source-controlled roles: " + ", ".join(controlled_roles))
    elif parameter_roles:
        score += 10
        reasons.append("API-parameter-controlled roles: " + ", ".join(parameter_roles))
    else:
        score -= 8
        reasons.append("no source-to-write controlled role proven")

    if candidate.input_reaches_sink and candidate.path_is_valid:
        score += 12
        reasons.append("valid input path reaches sink")
    elif candidate.path_is_valid:
        score += 4
        reasons.append("valid entry path reaches sink")
    else:
        score -= 12
        reasons.append("reachability path is not proven")

    if candidate.capacity_bytes > 0:
        score += 8
        reasons.append(f"fixed destination capacity {candidate.capacity_bytes} bytes")
    else:
        score -= 10
        reasons.append("destination capacity is symbolic or unknown")

    stack_trace = candidate.classification_trace.get("stack_coalescing") if isinstance(candidate.classification_trace, Mapping) else {}
    if isinstance(stack_trace, Mapping) and stack_trace.get("classification") == "likely_decompiler_split":
        score -= 35
        reasons.append("likely decompiler-split stack object")
        score = min(score, 40)

    score = max(0, min(100, score))
    if score >= 75:
        priority = "high"
    elif score >= 45:
        priority = "medium"
    else:
        priority = "low"
    return {
        "priority": priority,
        "score": score,
        "reasons": _unique_nonempty(reasons)[:8],
        "complete": True,
    }


def _candidate_source_excerpt(text: str, line_number: int, *, radius: int) -> Mapping[str, object]:
    lines = (text or "").splitlines()
    if not lines:
        return {"start_line": 0, "end_line": 0, "text": ""}
    line_number = max(1, min(line_number, len(lines)))
    start = max(1, line_number - radius)
    end = min(len(lines), line_number + radius)
    return {
        "start_line": start,
        "end_line": end,
        "text": "\n".join(lines[start - 1 : end]),
    }


def _object_trust_for_candidate(candidate: StaticCandidate) -> str:
    model = candidate.capacity_model or {}
    trust = str(model.get("trust") or "")
    if trust:
        return trust
    if candidate.capacity_bytes > 0:
        return "high"
    if candidate.destination_kind in {"heap", "parameter"}:
        return "symbolic"
    return "unknown"


def _guard_trace_for_candidate(candidate: StaticCandidate) -> tuple[list[str], list[str]]:
    accepted: list[str] = []
    rejected: list[str] = []
    for guard in candidate.guard_evidence:
        lowered = guard.lower()
        if candidate.write_relation == "proven_overflow" and (
            "< 0" in lowered or ">=" in lowered or "outside" in candidate.overflow_condition
        ):
            rejected.append(guard)
        else:
            accepted.append(guard)
    return accepted, rejected


def _control_label(candidate: StaticCandidate, dimension: str) -> str:
    if dimension == "destination" and candidate.destination_kind in {"parameter", "caller_buffer"}:
        return "caller_controlled"
    if candidate.source_evidence:
        return "data_dependent"
    return "unknown"


def _attacker_control_trace(candidate: StaticCandidate) -> dict[str, str]:
    roles = _source_to_write_roles(candidate)
    if roles:
        return {
            "destination_pointer": _role_classification(roles, "destination_pointer", "unknown"),
            "source_bytes": _role_classification(
                roles,
                "write_source",
                "source_controlled" if candidate.source_evidence else "unknown",
            ),
            "write_size": _role_classification(
                roles,
                "write_size",
                "unknown" if _expr_is_symbolic(candidate.write_size_expr) else "constant_or_literal",
            ),
            "offset": _role_classification(roles, "write_offset", "unknown"),
            "format_string": "unknown" if candidate.sink in SCANF_FAMILY else "not_applicable",
        }
    return {
        "destination_pointer": _control_label(candidate, "destination"),
        "source_bytes": "attacker_controlled" if candidate.source_evidence else "unknown",
        "write_size": "attacker_controlled_or_symbolic" if _expr_is_symbolic(candidate.write_size_expr) else "constant",
        "offset": (
            "attacker_controlled_or_symbolic"
            if candidate.write_relation in {"symbolic_offset", "symbolic_offset_size_guarded", "iterated_alias_unproven"}
            else "classified"
        ),
        "format_string": "unknown" if candidate.sink in SCANF_FAMILY else "not_applicable",
    }


def _source_to_write_roles(candidate: StaticCandidate) -> Mapping[str, object]:
    trace = candidate.classification_trace if isinstance(candidate.classification_trace, Mapping) else {}
    source_to_write = trace.get("source_to_write") if isinstance(trace, Mapping) else None
    if not isinstance(source_to_write, Mapping):
        return {}
    roles = source_to_write.get("roles")
    return roles if isinstance(roles, Mapping) else {}


def _role_classification(
    roles: Mapping[str, object],
    role: str,
    fallback: str,
) -> str:
    fact = roles.get(role)
    if isinstance(fact, Mapping):
        classification = str(fact.get("classification") or "")
        if classification:
            return classification
    return fallback


def _integer_relation_trace(candidate: StaticCandidate) -> list[dict[str, str]]:
    relations: list[dict[str, str]] = []
    text = " ".join([candidate.write_size_expr, candidate.overflow_condition, *candidate.guard_evidence])
    if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*<\s*0\b", text):
        relations.append({"kind": "signed_lower_bound", "relation": "value < 0"})
    if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*>=\s*(?:0x[0-9a-fA-F]+|\d+)", text):
        relations.append({"kind": "upper_reject_or_wrap_guard", "relation": ">="})
    if any(token in text for token in ("UINT_MAX", "SIZE_MAX", "wrap", "overflow")):
        relations.append({"kind": "wrap_sensitive", "relation": "integer wrap mentioned"})
    return relations


def _loop_shape_trace(candidate: StaticCandidate) -> dict[str, object]:
    if candidate.write_relation == "iterated_alias_unproven":
        return {"kind": "iterated_alias", "bounded": False, "reason": candidate.overflow_condition}
    if any("for " in guard or "while " in guard for guard in candidate.guard_evidence):
        return {"kind": "loop_guard", "bounded": candidate.write_relation != "symbolic_offset"}
    return {}


def _classified_finding_from_candidate(candidate: StaticCandidate) -> ClassifiedFinding:
    traced = _with_v3_trace(candidate)
    fact = candidate_to_write_fact(traced)
    reportable = _candidate_is_deterministic_reportable(traced)
    return ClassifiedFinding(
        finding_id=traced.candidate_id,
        write_fact=fact,
        status="overflow" if traced.verdict in {"overflow", "unbounded"} else "candidate",
        relation=traced.write_relation,
        condition=traced.overflow_condition,
        triage_tier=traced.triage_tier or triage_tier_for_candidate(traced),
        reportable=reportable,
        confirmation_queue=_passes_symbolic_confirmation_filter(traced),
        classification_trace=dict(traced.classification_trace),
        candidate=traced.to_dict(),
    )


def _candidate_is_deterministic_reportable(candidate: StaticCandidate) -> bool:
    relation = str(candidate.write_relation or "")
    if candidate.vulnerability_type == "out_of_bounds_read":
        return bool(
            candidate.verdict == "overflow"
            and relation == "proven_oob_read"
            and candidate.path_is_valid
            and not _trace_is_complete_unreachable(candidate)
            and not _weak_object_candidate_is_not_reportable(candidate)
            and _candidate_has_reportable_memory_influence(candidate)
        )
    if candidate.vulnerability_type != "memory_overflow":
        return False
    return bool(
        candidate.verdict in {"overflow", "unbounded"}
        and candidate.path_is_valid
        and (
            relation == "proven_overflow"
            or (relation == "unbounded" and _is_direct_unbounded_input_source(candidate))
        )
        and not _trace_is_complete_unreachable(candidate)
        and not _weak_object_candidate_is_not_reportable(candidate)
        and _candidate_has_reportable_memory_influence(candidate)
    )


def _is_direct_unbounded_input_source(candidate: StaticCandidate) -> bool:
    sink = _normalize_sink_name(candidate.sink)
    return sink in SOURCE_CALLS


def _capacity_model_for_candidate(candidate: StaticCandidate) -> dict[str, object]:
    fixed = candidate.capacity_bytes if candidate.capacity_bytes > 0 else None
    symbolic_expr = ""
    if fixed is None:
        symbolic_expr = _capacity_expr_from_basis(candidate.capacity_basis)
    return {
        "fixed_bytes": fixed,
        "symbolic_expr": symbolic_expr,
        "lower_bound": None,
        "upper_bound": None,
        "source": candidate.capacity_source,
        "trust": "high" if fixed is not None else "symbolic" if symbolic_expr else "unknown",
    }


def _capacity_model_for_mapping(mapping: Mapping[str, object]) -> dict[str, object]:
    capacity = _safe_int(mapping.get("size_bytes"))
    capacity_expr = str(mapping.get("capacity_expr") or "")
    source = str(mapping.get("capacity_source") or mapping.get("capacity_basis_kind") or "")
    fixed = capacity if capacity > 0 else None
    return {
        "fixed_bytes": fixed,
        "symbolic_expr": "" if fixed is not None else capacity_expr,
        "lower_bound": None,
        "upper_bound": None,
        "source": source,
        "trust": "high" if fixed is not None else "symbolic" if capacity_expr else "unknown",
    }


def _capacity_expr_from_basis(basis: str) -> str:
    text = str(basis or "")
    marker = "modeled by "
    if marker in text:
        return text.split(marker, 1)[-1].split(" from ", 1)[0].strip()
    return ""


def _default_write_relation(
    kind: str,
    sink: str,
    verdict: str,
    write_size_expr: str,
    write_size_bytes: Optional[int],
) -> str:
    if verdict == "overflow":
        return "proven_overflow"
    if verdict == "unbounded":
        return "unbounded"
    normalized_kind = kind.removeprefix("parameter_summary_").removeprefix("interprocedural_")
    semantics = str(OPERATION_SPECS.get(_normalize_sink_name(sink), {}).get("semantics") or "")
    if semantics == "append_bounded":
        return "append_length_unknown"
    if semantics == "bounded":
        return "symbolic_size" if write_size_bytes is None or _expr_is_symbolic(write_size_expr) else "unproven_size_relation"
    if semantics == "format_string":
        return "unbounded"
    if normalized_kind in {"indexed_write", "field_indexed_write", "pointer_store", "pcode_store"}:
        return "symbolic_offset" if _expr_is_symbolic(write_size_expr) else "unproven_offset_relation"
    return "unresolved"


def _build_candidate(
    manifest: Manifest,
    node: FunctionNode,
    stack_obj: Mapping[str, object],
    *,
    kind: str,
    sink: str,
    line_number: int,
    line: str,
    write_size_expr: str,
    write_size_bytes: Optional[int],
    verdict: str,
    overflow_condition: str,
    source_evidence: Sequence[str],
    guard_evidence: Sequence[str] = (),
    evidence_sources: Sequence[str] = (),
    operation_address: str = "",
    destination_kind: str = "",
    capacity_source: str = "",
    write_relation: str = "",
    offset_expr: str = "0",
    vulnerability_type: str = "memory_overflow",
) -> StaticCandidate:
    capacity = _safe_int(stack_obj.get("size_bytes"))
    target = str(stack_obj.get("var_display") or stack_obj.get("label") or "stack_object")
    severity = "high" if verdict in {"overflow", "unbounded"} else "medium"
    clean_line = line.strip()
    resolved_capacity_source = str(
        capacity_source or stack_obj.get("capacity_source") or stack_obj.get("capacity_basis_kind") or "stack metadata"
    )
    resolved_destination_kind = str(destination_kind or stack_obj.get("destination_kind") or "stack")
    capacity_expr = str(stack_obj.get("capacity_expr") or "").strip()
    capacity_model = _capacity_model_for_mapping(
        {
            **dict(stack_obj),
            "capacity_source": resolved_capacity_source,
        }
    )
    resolved_write_relation = write_relation or _default_write_relation(kind, sink, verdict, write_size_expr, write_size_bytes)
    resolved_offset_expr = _normalize_offset_expr(offset_expr or "0") or "0"
    if resolved_write_relation == "symbolic_capacity":
        capacity = 0
    evidence = [
        f"line {line_number}: {clean_line}",
        overflow_condition,
    ]
    if capacity > 0:
        evidence.insert(1, f"target {target} has capacity {capacity} bytes from {resolved_capacity_source}")
    elif capacity_expr:
        evidence.insert(1, f"target {target} capacity is modeled by {capacity_expr} from {resolved_capacity_source}")
    else:
        evidence.insert(1, f"target {target} capacity source is {resolved_capacity_source}")
    if operation_address:
        evidence.append(f"operation address: {operation_address}")
    if guard_evidence:
        evidence.append("nearby guards: " + "; ".join(guard_evidence))
    candidate_id = _candidate_id(
        manifest.binary,
        node.record.address,
        node.record.name,
        line_number,
        sink,
        target,
        operation_address=operation_address,
        offset_expr=resolved_offset_expr,
        write_size_expr=write_size_expr,
    )
    triage_tier = triage_tier_for_candidate(
        {
            "verdict": verdict,
            "write_relation": resolved_write_relation,
            "destination_kind": resolved_destination_kind,
            "capacity_bytes": capacity,
            "vulnerability_type": vulnerability_type,
        }
    )
    return StaticCandidate(
        binary=manifest.binary,
        function_name=node.record.name,
        source_symbol=node.record.source_symbol,
        demangled_name=node.record.demangled_name,
        source_object=node.record.source_object,
        address=node.record.address,
        relative_path=node.record.relative_path,
        candidate_id=candidate_id,
        kind=kind,
        sink=sink,
        line_number=line_number,
        line_text=clean_line,
        target_buffer=target,
        capacity_bytes=capacity,
        capacity_basis=str(stack_obj.get("annotation") or stack_obj.get("offset_range") or "stack metadata"),
        destination_kind=resolved_destination_kind,
        capacity_source=resolved_capacity_source,
        write_relation=resolved_write_relation,
        write_size_expr=write_size_expr,
        write_size_bytes=write_size_bytes,
        offset_expr=resolved_offset_expr,
        overflow_condition=overflow_condition,
        verdict=verdict,
        severity=severity,
        vulnerability_type=vulnerability_type,
        evidence=evidence,
        source_evidence=list(source_evidence),
        guard_evidence=list(guard_evidence),
        evidence_sources=list(evidence_sources),
        operation_address=operation_address,
        capacity_model=capacity_model,
        classification_trace={},
        triage_tier=triage_tier,
    )


def _attach_reachability(
    manifest: Manifest,
    nodes: Sequence[FunctionNode],
    candidates: Sequence[StaticCandidate],
    *,
    source_nodes: Sequence[str] | None = None,
    reachability_context: _ReachabilityContext | None = None,
) -> list[StaticCandidate]:
    if not candidates:
        return []
    context = reachability_context or _build_reachability_context(
        manifest,
        nodes,
        candidates,
        source_nodes=source_nodes,
    )
    source_node_set = set(context.source_nodes)
    entry_node_set = set(context.entry_nodes)
    source_paths = context.source_paths
    entry_paths = context.entry_paths

    enriched: list[StaticCandidate] = []
    for candidate in candidates:
        if candidate.function_name in source_node_set:
            kind = "local_source"
            path = [candidate.function_name]
        elif candidate.function_name in source_paths:
            kind = "source_path"
            path = source_paths[candidate.function_name]
        elif candidate.function_name in entry_paths or candidate.function_name in entry_node_set:
            kind = "entry_path"
            path = entry_paths.get(candidate.function_name, [candidate.function_name])
        else:
            kind = "unknown"
            path = []
        input_reaches_sink = kind in {"local_source", "source_path"} or bool(candidate.source_evidence)
        enriched.append(
            replace(
                candidate,
                call_path=path,
                reachability_kind=kind,
                input_reaches_sink=input_reaches_sink,
                path_is_valid=bool(path),
            )
        )
    return enriched


def _build_reachability_context(
    manifest: Manifest,
    nodes: Sequence[FunctionNode],
    candidates: Sequence[StaticCandidate],
    *,
    source_nodes: Sequence[str] | None = None,
) -> _ReachabilityContext:
    graph = load_cached_call_graph(
        manifest,
        nodes,
        include_pcode_edges=True,
        include_text_edges=False,
    ) or build_call_graph(
        nodes,
        include_pcode_edges=True,
    )
    source_nodes = list(source_nodes) if source_nodes is not None else _source_function_names(nodes)
    entry_nodes = _entry_function_names(graph.order)
    roots = sorted(graph.roots(), key=lambda name: graph.order.get(name, 1_000_000))

    target_names = {candidate.function_name for candidate in candidates}
    source_paths = graph.find_paths_to_targets(source_nodes, target_names, max_depth=16)
    entry_paths = graph.find_paths_to_targets(entry_nodes, target_names, max_depth=16)
    names = set(graph.order)
    return _ReachabilityContext(
        graph=graph,
        source_nodes=tuple(source_nodes),
        entry_nodes=tuple(entry_nodes),
        thread_start_nodes=frozenset(_thread_start_function_names(nodes, names)),
        callback_nodes=frozenset(_callback_function_names(nodes, names)),
        roots=tuple(roots),
        source_paths=source_paths,
        entry_paths=entry_paths,
        node_by_name={node.record.name: node for node in nodes},
    )


def _attach_reachability_dataflow(
    manifest: Manifest,
    nodes: Sequence[FunctionNode],
    candidates: Sequence[StaticCandidate],
    *,
    contexts: Sequence[_FunctionContext] = (),
    source_nodes: Sequence[str] | None = None,
    reachability_context: _ReachabilityContext | None = None,
) -> list[StaticCandidate]:
    if not candidates:
        return []
    context = reachability_context or _build_reachability_context(
        manifest,
        nodes,
        candidates,
        source_nodes=source_nodes,
    )
    context_by_name = {item.node.record.name: item for item in contexts}
    taint_state_cache: dict[
        tuple[str, int],
        tuple[dict[str, IdentifierTaint], tuple[str, ...]],
    ] = {}
    enriched: list[StaticCandidate] = []
    for candidate in candidates:
        node = context.node_by_name.get(candidate.function_name)
        expr_taint = _candidate_expr_taint_trace(
            candidate,
            node,
            context=context_by_name.get(candidate.function_name),
            state_cache=taint_state_cache,
        )
        source_link = _source_link_trace(candidate, expr_taint)
        graph_trace = _candidate_reachability_graph_trace(candidate, node, context, source_link)
        trace = dict(candidate.classification_trace or {})
        trace["reachability_dataflow"] = {
            "graph": graph_trace,
            "expr_taint": expr_taint,
            "source_link": source_link,
        }
        enriched.append(
            replace(
                candidate,
                classification_trace=trace,
            )
        )
    return enriched


def _attach_source_to_write_dataflow(
    nodes: Sequence[FunctionNode],
    candidates: Sequence[StaticCandidate],
    *,
    contexts: Sequence[_FunctionContext] = (),
    write_summaries: Sequence[_WriteSummary] = (),
    call_sites_by_context: Mapping[int, Sequence[_CallSite]] | None = None,
) -> list[StaticCandidate]:
    if not candidates:
        return []
    node_by_name = {node.record.name: node for node in nodes}
    context_by_name = {context.node.record.name: context for context in contexts}
    summaries_by_key: dict[str, list[_WriteSummary]] = {}
    for summary in write_summaries:
        for key in summary.function_keys:
            summaries_by_key.setdefault(key, []).append(summary)
    call_sites_by_context = call_sites_by_context or {}

    enriched: list[StaticCandidate] = []
    for candidate in candidates:
        node = node_by_name.get(candidate.function_name)
        context = context_by_name.get(candidate.function_name)
        trace = None
        if candidate.kind.startswith("interprocedural_") and context is not None:
            trace = _interprocedural_source_to_write_trace(
                candidate,
                context,
                context_by_name,
                summaries_by_key,
                call_sites_by_context.get(id(context), ()),
            )
        if trace is None:
            trace = _local_source_to_write_trace(candidate, node, context)
        classification_trace = dict(candidate.classification_trace or {})
        classification_trace["source_to_write"] = trace
        enriched.append(replace(candidate, classification_trace=classification_trace))
    return enriched


def _local_source_to_write_trace(
    candidate: StaticCandidate,
    node: FunctionNode | None,
    context: _FunctionContext | None = None,
) -> dict[str, object]:
    state, param_names = _source_to_write_state(node, context, candidate.line_number)
    line = candidate.line_text or ""
    kind = candidate.kind.removeprefix("parameter_summary_").removeprefix("interprocedural_")
    exprs: dict[str, str] = {}
    direct_roles: dict[str, dict[str, object]] = {}
    evidence_sources = list(candidate.evidence_sources)

    if kind == "call":
        exprs, direct_roles = _call_source_to_write_exprs(candidate, line)
    elif kind in {"indexed_write", "field_indexed_write"}:
        exprs = _indexed_store_source_to_write_exprs(candidate, line)
    elif kind in {"indexed_read", "pointer_read"}:
        exprs = {
            "write_size": _write_width_expr(candidate),
            "write_offset": candidate.offset_expr or "unknown",
            "destination_pointer": candidate.target_buffer,
        }
    elif kind == "pointer_store":
        exprs = _pointer_store_source_to_write_exprs(candidate, line)
    elif kind == "source_read":
        exprs = {
            "write_size": candidate.write_size_expr or _write_width_expr(candidate),
            "write_offset": candidate.offset_expr or "0",
            "destination_pointer": candidate.target_buffer,
        }
    elif kind.startswith("integer_"):
        risk = candidate.classification_trace.get("integer_risk") if isinstance(candidate.classification_trace, Mapping) else {}
        risk_expr = str(risk.get("expr") or candidate.write_size_expr or candidate.offset_expr) if isinstance(risk, Mapping) else ""
        risk_role = str(risk.get("role") or "") if isinstance(risk, Mapping) else ""
        exprs = {
            "write_size": risk_expr if "size" in risk_role else candidate.write_size_expr or _write_width_expr(candidate),
            "write_offset": risk_expr if "offset" in risk_role else candidate.offset_expr or "0",
            "destination_pointer": candidate.target_buffer,
        }
    elif kind == "pcode_store":
        exprs = {
            "write_size": _write_width_expr(candidate),
            "write_offset": candidate.offset_expr or "unknown",
            "destination_pointer": candidate.target_buffer,
        }
    else:
        exprs = {
            "write_size": candidate.write_size_expr or _write_width_expr(candidate),
            "write_offset": candidate.offset_expr or "0",
            "destination_pointer": candidate.target_buffer,
        }
        if candidate.sink in SOURCE_CALLS:
            direct_roles["write_source"] = _source_to_write_direct_role_fact(
                "write_source",
                candidate.sink,
                "source_controlled",
                [f"{candidate.sink} is modeled as an input source"],
            )

    if candidate.sink in SOURCE_CALLS and "write_source" not in direct_roles and kind == "call":
        direct_roles["write_source"] = _source_to_write_direct_role_fact(
            "write_source",
            candidate.sink,
            "source_controlled",
            [f"{candidate.sink} is modeled as an input source"],
        )
    return _source_to_write_trace_from_exprs(
        candidate,
        state,
        param_names,
        exprs,
        direct_roles=direct_roles,
        evidence_sources=evidence_sources,
        default_reason="role expression was not recovered from the write statement",
    )


def _interprocedural_source_to_write_trace(
    candidate: StaticCandidate,
    context: _FunctionContext,
    context_by_name: Mapping[str, _FunctionContext],
    summaries_by_key: Mapping[str, Sequence[_WriteSummary]],
    call_sites: Sequence[_CallSite],
) -> dict[str, object] | None:
    match = _matching_summary_callsite(candidate, context, summaries_by_key, call_sites)
    if match is None:
        return None
    summary, site = match
    state, param_names = _source_to_write_state(context.node, context, site.line_number)
    callee_context = context_by_name.get(summary.function_name)
    source_template, direct_source, source_complete = _summary_write_source_template(summary, callee_context)
    exprs: dict[str, str] = {
        "write_size": _summary_role_size_expr(candidate, summary, site.args),
        "write_offset": candidate.offset_expr or "0",
        "destination_pointer": site.args[summary.dest_arg_index] if summary.dest_arg_index < len(site.args) else "",
    }
    direct_roles: dict[str, dict[str, object]] = {}
    if direct_source:
        direct_roles["write_source"] = _source_to_write_direct_role_fact(
            "write_source",
            summary.sink,
            "source_controlled",
            [f"{summary.function_name} calls input source {summary.sink}"],
        )
    elif source_template:
        exprs["write_source"] = _instantiate_summary_expr(source_template, site.args)
    elif not source_complete:
        direct_roles["write_source"] = _source_to_write_direct_role_fact(
            "write_source",
            "",
            "unknown",
            [f"{summary.function_name} summary does not expose a direct source argument"],
            complete=False,
        )
    return _source_to_write_trace_from_exprs(
        candidate,
        state,
        param_names,
        exprs,
        direct_roles=direct_roles,
        evidence_sources=_unique_nonempty(
            [*candidate.evidence_sources, *summary.evidence_sources, "interprocedural_summary"]
        ),
        default_reason="interprocedural role expression was not recovered",
    )


def _matching_summary_callsite(
    candidate: StaticCandidate,
    context: _FunctionContext,
    summaries_by_key: Mapping[str, Sequence[_WriteSummary]],
    call_sites: Sequence[_CallSite],
) -> tuple[_WriteSummary, _CallSite] | None:
    wanted_kind = candidate.kind.removeprefix("interprocedural_")
    for site in call_sites:
        if site.line_number != candidate.line_number:
            continue
        for summary in _summaries_for_call(site.callee, summaries_by_key):
            if summary.sink != candidate.sink or summary.kind != wanted_kind:
                continue
            if summary.dest_arg_index >= len(site.args):
                continue
            target = _resolve_stack_destination(site.args[summary.dest_arg_index], context.stack_index, site.aliases)
            if not target or not target.stack_obj:
                continue
            target_name = str(target.stack_obj.get("var_display") or target.stack_obj.get("label") or "")
            if target_name != candidate.target_buffer:
                continue
            return summary, site
    return None


def _source_to_write_state(
    node: FunctionNode | None,
    context: _FunctionContext | None,
    line_number: int,
) -> tuple[dict[str, IdentifierTaint], list[str]]:
    if context is not None:
        param_names = list(context.param_names)
        lines = list(context.code_lines)
    elif node is not None:
        param_names = _parameter_names(node)
        lines = _strip_c_comments((node.text or "").splitlines())
    else:
        param_names = []
        lines = []
    return (
        identifier_taint_before_line(
            lines,
            line_number,
            param_names,
            _source_taint_rules(),
        ),
        param_names,
    )


def _call_source_to_write_exprs(
    candidate: StaticCandidate,
    line: str,
) -> tuple[dict[str, str], dict[str, dict[str, object]]]:
    sink_name = _normalize_sink_name(candidate.sink)
    for sink, args in _iter_sink_calls(line):
        if sink != sink_name:
            continue
        spec = OPERATION_SPECS.get(sink, {})
        exprs: dict[str, str] = {
            "write_offset": candidate.offset_expr or "0",
            "destination_pointer": _call_destination_expr(sink, args, spec) or candidate.target_buffer,
        }
        direct_roles: dict[str, dict[str, object]] = {}
        size_expr = _call_size_expr(args, spec)
        if size_expr:
            exprs["write_size"] = size_expr
        elif candidate.write_size_expr:
            exprs["write_size"] = candidate.write_size_expr
        source_expr, direct_source = _call_write_source_expr(sink, args, spec)
        if direct_source:
            direct_roles["write_source"] = _source_to_write_direct_role_fact(
                "write_source",
                sink,
                "source_controlled",
                [f"{sink} is modeled as an input source"],
            )
        elif source_expr:
            exprs["write_source"] = source_expr
        return exprs, direct_roles
    return (
        {
            "write_size": candidate.write_size_expr or _write_width_expr(candidate),
            "write_offset": candidate.offset_expr or "0",
            "destination_pointer": candidate.target_buffer,
        },
        {},
    )


def _indexed_store_source_to_write_exprs(candidate: StaticCandidate, line: str) -> dict[str, str]:
    exprs = {
        "write_size": _write_width_expr(candidate),
        "write_offset": candidate.offset_expr or "unknown",
        "destination_pointer": candidate.target_buffer,
    }
    match = next(iter(INDEX_WRITE_RE.finditer(line)), None)
    if match is not None:
        exprs["write_offset"] = candidate.offset_expr or match.group("index").strip()
        exprs["destination_pointer"] = match.group("array")
    lhs, rhs = _split_simple_assignment(line)
    if lhs and rhs:
        exprs["write_source"] = rhs
    return exprs


def _pointer_store_source_to_write_exprs(candidate: StaticCandidate, line: str) -> dict[str, str]:
    lhs, rhs = _split_simple_assignment(line)
    exprs = {
        "write_size": _write_width_expr(candidate),
        "write_offset": candidate.offset_expr or "unknown",
        "destination_pointer": candidate.target_buffer,
    }
    if lhs:
        exprs["destination_pointer"] = _deref_target_expr(lhs) or candidate.target_buffer
    if rhs:
        exprs["write_source"] = rhs
    return exprs


def _source_to_write_trace_from_exprs(
    candidate: StaticCandidate,
    state: Mapping[str, IdentifierTaint],
    param_names: Sequence[str],
    exprs: Mapping[str, str],
    *,
    direct_roles: Mapping[str, Mapping[str, object]] | None = None,
    evidence_sources: Sequence[str] = (),
    default_reason: str,
) -> dict[str, object]:
    direct_roles = direct_roles or {}
    roles: dict[str, dict[str, object]] = {}
    for role in SOURCE_TO_WRITE_ROLES:
        if role in direct_roles:
            roles[role] = dict(direct_roles[role])
            continue
        expr = str(exprs.get(role) or "")
        if not expr:
            roles[role] = _source_to_write_direct_role_fact(
                role,
                "",
                "unknown",
                [default_reason],
                complete=False,
            )
            continue
        if role == "destination_pointer":
            roles[role] = _destination_pointer_role_fact(candidate, expr, state, param_names)
        else:
            roles[role] = _source_to_write_role_fact_from_expr(role, expr, state, param_names)
    return {
        "roles": roles,
        "complete": all(bool(role.get("complete")) for role in roles.values()),
        "evidence_sources": _unique_nonempty([str(item) for item in evidence_sources]),
    }


def _source_to_write_role_fact_from_expr(
    role: str,
    expr: str,
    state: Mapping[str, IdentifierTaint],
    param_names: Sequence[str],
) -> dict[str, object]:
    trace = trace_expression_taint(
        role,
        expr,
        state,
        param_names,
        _source_taint_rules(),
    )
    rows = [row for row in trace.get("taint_rows", []) if isinstance(row, Mapping)]
    classification = _source_to_write_rows_classification(rows)
    evidence: list[str] = []
    for row in rows:
        symbol = str(row.get("symbol") or "")
        row_class = str(row.get("classification") or "unknown")
        if symbol:
            evidence.append(f"{symbol}: {row_class}")
        else:
            evidence.append(f"{role}: {row_class}")
        evidence.extend(str(source) for source in row.get("sources", []) or [])
        evidence.extend(str(item) for item in row.get("trace", []) or [])
    evidence = _unique_nonempty(evidence)[:8]
    return {
        "role": role,
        "expr": str(trace.get("expr") or _normalize_offset_expr(expr)),
        "classification": classification,
        "evidence": evidence,
        "complete": bool(rows) and classification != "unknown",
    }


def _destination_pointer_role_fact(
    candidate: StaticCandidate,
    expr: str,
    state: Mapping[str, IdentifierTaint],
    param_names: Sequence[str],
) -> dict[str, object]:
    fact = _source_to_write_role_fact_from_expr("destination_pointer", expr, state, param_names)
    classification = str(fact.get("classification") or "unknown")
    if classification in {"source_controlled", "parameter_controlled"}:
        return fact
    if candidate.destination_kind in {"parameter", "caller_buffer"}:
        return _source_to_write_direct_role_fact(
            "destination_pointer",
            expr,
            "parameter_controlled",
            [f"destination {candidate.target_buffer} is caller-provided"],
        )
    if candidate.destination_kind in {"stack", "heap", "global", "static_local", "tls"}:
        return _source_to_write_direct_role_fact(
            "destination_pointer",
            expr,
            "internal_local",
            [f"destination resolves to {candidate.destination_kind} object {candidate.target_buffer}"],
        )
    return fact


def _source_to_write_direct_role_fact(
    role: str,
    expr: str,
    classification: str,
    evidence: Sequence[str],
    *,
    complete: bool = True,
) -> dict[str, object]:
    if classification not in TAINT_CLASSIFICATIONS:
        classification = "unknown"
    return {
        "role": role,
        "expr": _normalize_offset_expr(expr) if expr else "",
        "classification": classification,
        "evidence": _unique_nonempty([str(item) for item in evidence])[:8],
        "complete": bool(complete and classification != "unknown"),
    }


def _source_to_write_rows_classification(rows: Sequence[Mapping[str, object]]) -> str:
    labels = {str(row.get("classification") or "unknown") for row in rows}
    if not labels:
        return "unknown"
    for classification in TAINT_CLASSIFICATION_PRIORITY:
        if classification in labels:
            return classification
    return "unknown"


def _call_destination_expr(sink: str, args: Sequence[str], spec: Mapping[str, object]) -> str:
    dest_index = _call_destination_arg_index(sink, spec)
    if dest_index is None or dest_index >= len(args):
        return ""
    return args[dest_index]


def _call_destination_arg_index(sink: str, spec: Mapping[str, object]) -> Optional[int]:
    if "dest_arg" in spec:
        return int(spec["dest_arg"])
    if "first_dest_arg" in spec:
        return int(spec["first_dest_arg"])
    if sink in SOURCE_CALLS and sink in OPERATION_SPECS and "dest_arg" in OPERATION_SPECS[sink]:
        return int(OPERATION_SPECS[sink]["dest_arg"])
    return None


def _call_size_expr(args: Sequence[str], spec: Mapping[str, object]) -> str:
    if "size_arg" not in spec:
        return ""
    size_index = int(spec["size_arg"])
    return args[size_index] if size_index < len(args) else ""


def _fortified_call_has_active_bound(
    spec: Mapping[str, object],
    args: Sequence[str],
    stack_index: _StackIndex,
) -> bool:
    if not bool(spec.get("fortified")):
        return False
    object_size_index = spec.get("object_size_arg")
    if object_size_index is None or int(object_size_index) >= len(args):
        return False
    object_size = _eval_int_expr(args[int(object_size_index)], stack_index)
    return object_size is not None and 0 < object_size < (1 << 63)


def _fortified_call_cannot_overflow(
    spec: Mapping[str, object],
    args: Sequence[str],
    destination: Mapping[str, object],
    stack_index: _StackIndex,
    *,
    write_size: Optional[int] = None,
) -> bool:
    if not _fortified_call_has_active_bound(spec, args, stack_index):
        return False
    object_size_index = int(spec["object_size_arg"])
    object_size = _eval_int_expr(args[object_size_index], stack_index)
    if object_size is None:
        return False
    capacity = _safe_int(destination.get("size_bytes"))
    return object_size <= capacity or (write_size is not None and write_size > object_size)


def _call_write_source_expr(
    sink: str,
    args: Sequence[str],
    spec: Mapping[str, object],
) -> tuple[str, bool]:
    if sink in SOURCE_CALLS:
        return "", True
    source_index = WRITE_SOURCE_ARG_BY_SINK.get(sink)
    if source_index is not None and source_index < len(args):
        return args[source_index], False
    if sink in {"sprintf", "vsprintf"}:
        return ", ".join(args[1:]), False
    if sink in {"snprintf", "vsnprintf"}:
        format_index = int(spec.get("format_arg", 2) or 2)
        return ", ".join(args[format_index + 1 :]), False
    return "", False


def _summary_write_source_template(
    summary: _WriteSummary,
    callee_context: _FunctionContext | None,
) -> tuple[str, bool, bool]:
    if callee_context is None:
        return "", False, False
    line = summary.line_text or ""
    if summary.kind == "call":
        for sink, args in _iter_sink_calls(line):
            if sink != summary.sink:
                continue
            source_expr, direct_source = _call_write_source_expr(sink, args, OPERATION_SPECS.get(sink, {}))
            if direct_source:
                return "", True, True
            if source_expr:
                return _param_template_expr(source_expr, callee_context.param_names) or source_expr, False, True
            return "", False, False
    if summary.kind in {"indexed_write", "field_indexed_write"}:
        lhs, rhs = _split_simple_assignment(line)
        if lhs and rhs:
            return _param_template_expr(rhs, callee_context.param_names) or rhs, False, True
        return "", False, False
    if summary.kind == "pointer_store":
        _lhs, rhs = _split_simple_assignment(line)
        if rhs:
            return _param_template_expr(rhs, callee_context.param_names) or rhs, False, True
        return "", False, False
    return "", False, False


def _summary_role_size_expr(
    candidate: StaticCandidate,
    summary: _WriteSummary,
    args: Sequence[str],
) -> str:
    if summary.semantics in {"indexed_write", "pointer_store"}:
        return _write_width_expr(candidate)
    if summary.write_size_expr:
        return _instantiate_summary_expr(summary.write_size_expr, args)
    return candidate.write_size_expr or _write_width_expr(candidate)


def _write_width_expr(candidate: StaticCandidate) -> str:
    if candidate.write_size_bytes is not None:
        return str(candidate.write_size_bytes)
    return candidate.write_size_expr or "unknown"


def _candidate_reachability_graph_trace(
    candidate: StaticCandidate,
    node: FunctionNode | None,
    context: _ReachabilityContext,
    source_link: Mapping[str, object],
) -> dict[str, object]:
    name = candidate.function_name
    callers = sorted(context.graph.callers(name), key=lambda item: context.graph.order.get(item, 1_000_000))
    root_name = candidate.call_path[0] if candidate.call_path else ""
    path_root_node = context.node_by_name.get(root_name) if root_name else None
    function_root_kind = _reachability_root_kind(name, node, context)
    path_root_kind = _reachability_root_kind(root_name, path_root_node, context) if root_name else "unknown"
    public_flags = _public_reachability_flags(candidate, node, context)
    has_thread_or_callback = bool(public_flags["is_thread_start"] or public_flags["has_callback_evidence"])
    has_real_path = bool(
        candidate.reachability_kind in {"local_source", "source_path"}
        or candidate.reachability_kind == "entry_path"
    )
    complete_unreachable = bool(
        not has_real_path
        and not callers
        and not public_flags["is_root_like"]
        and not public_flags["is_public"]
        and not public_flags["is_exported"]
        and not has_thread_or_callback
        and not candidate.source_evidence
        and not source_link.get("source_function_reaches_candidate")
    )
    return {
        "reachability_kind": candidate.reachability_kind,
        "call_path": list(candidate.call_path),
        "caller_count": len(callers),
        "callers": callers[:12],
        "root_kind": path_root_kind if path_root_kind != "unknown" else function_root_kind,
        "function_root_kind": function_root_kind,
        "path_root": root_name,
        "path_root_kind": path_root_kind,
        "source_reaches_function": bool(source_link.get("source_function_reaches_candidate")),
        "has_real_path": has_real_path,
        "input_reaches_sink": candidate.input_reaches_sink,
        "path_is_valid": candidate.path_is_valid,
        "is_exported": public_flags["is_exported"],
        "is_public": public_flags["is_public"],
        "is_root_like": public_flags["is_root_like"],
        "is_entry": public_flags["is_entry"],
        "is_thread_start": public_flags["is_thread_start"],
        "is_graph_root": public_flags["is_graph_root"],
        "has_public_symbol": public_flags["has_public_symbol"],
        "has_source_object": public_flags["has_source_object"],
        "has_callback_evidence": public_flags["has_callback_evidence"],
        "complete_unreachable_candidate": complete_unreachable,
    }


def _public_reachability_flags(
    candidate: StaticCandidate,
    node: FunctionNode | None,
    context: _ReachabilityContext,
) -> dict[str, bool]:
    record = node.record if node else None
    source_symbol = candidate.source_symbol or (record.source_symbol if record else "")
    demangled_name = candidate.demangled_name or (record.demangled_name if record else "")
    source_object = candidate.source_object or (record.source_object if record else "")
    name = candidate.function_name
    has_public_symbol = bool(source_symbol or demangled_name)
    has_source_object = bool(source_object)
    is_entry = name in context.entry_nodes
    is_thread_start = name in context.thread_start_nodes
    is_graph_root = name in context.roots
    has_callback_evidence = name in context.callback_nodes
    is_public = bool(has_public_symbol or has_source_object)
    is_exported = bool(source_symbol)
    is_root_like = bool(is_entry or is_thread_start or is_public or has_callback_evidence)
    return {
        "is_exported": is_exported,
        "is_public": is_public,
        "is_root_like": is_root_like,
        "is_entry": is_entry,
        "is_thread_start": is_thread_start,
        "is_graph_root": is_graph_root,
        "has_public_symbol": has_public_symbol,
        "has_source_object": has_source_object,
        "has_callback_evidence": has_callback_evidence,
    }


def _reachability_root_kind(
    name: str,
    node: FunctionNode | None,
    context: _ReachabilityContext,
) -> str:
    if not name:
        return "unknown"
    record = node.record if node else None
    if name in context.entry_nodes:
        return "entry"
    if name in context.thread_start_nodes:
        return "thread_start"
    if record and (record.source_symbol or record.demangled_name):
        return "public_symbol"
    if record and record.source_object:
        return "source_object"
    if name in context.roots:
        return "graph_root"
    return "unknown"


def _thread_start_function_names(nodes: Sequence[FunctionNode], names: set[str]) -> list[str]:
    starts: list[str] = []
    for node in nodes:
        for target in sorted(find_thread_start_functions(node.text or "")):
            if target in names and target not in starts:
                starts.append(target)
    return starts


def _callback_function_names(nodes: Sequence[FunctionNode], names: set[str]) -> list[str]:
    callbacks: list[str] = []
    address_of_re = re.compile(r"&\s*([A-Za-z_][A-Za-z0-9_]*)")
    for node in nodes:
        for match in address_of_re.finditer(node.text or ""):
            target = match.group(1)
            if target in names and target not in callbacks:
                callbacks.append(target)
    return callbacks


def _candidate_expr_taint_trace(
    candidate: StaticCandidate,
    node: FunctionNode | None,
    *,
    context: _FunctionContext | None = None,
    state_cache: MutableMapping[
        tuple[str, int],
        tuple[dict[str, IdentifierTaint], tuple[str, ...]],
    ] | None = None,
) -> dict[str, object]:
    cache_key = (candidate.function_name, candidate.line_number)
    cached = state_cache.get(cache_key) if state_cache is not None else None
    if cached is None:
        if context is not None:
            param_names = tuple(context.param_names)
            lines = context.code_lines
        elif node is not None:
            param_names = tuple(_parameter_names(node))
            lines = _strip_c_comments((node.text or "").splitlines())
        else:
            param_names = ()
            lines = ()
        state = identifier_taint_before_line(
            lines,
            candidate.line_number,
            param_names,
            _source_taint_rules(),
        )
        if state_cache is not None:
            state_cache[cache_key] = (state, param_names)
    else:
        state, param_names = cached
    rules = _source_taint_rules()
    offset_summary = trace_expression_taint(
        "offset_expr",
        candidate.offset_expr or "0",
        state,
        param_names,
        rules,
    )
    size_summary = trace_expression_taint(
        "write_size_expr",
        candidate.write_size_expr or "",
        state,
        param_names,
        rules,
    )
    table = list(offset_summary.get("taint_rows", [])) + list(size_summary.get("taint_rows", []))
    offset_summary = {key: value for key, value in offset_summary.items() if key != "taint_rows"}
    size_summary = {key: value for key, value in size_summary.items() if key != "taint_rows"}
    expr_trace = {
        "offset_expr": offset_summary,
        "write_size_expr": size_summary,
        "taint_table": table,
    }
    expr_trace["non_input_expr_candidate"] = _non_input_expr_candidate(candidate, expr_trace)
    return expr_trace


def _source_taint_rules() -> SourceTaintRules:
    return SourceTaintRules(
        source_calls=frozenset(SOURCE_CALLS),
        source_tokens=tuple(SOURCE_TOKENS),
        operation_specs=OPERATION_SPECS,
        iter_calls=_iter_calls,
        normalize_call=_normalize_sink_name,
        expression_identifiers=_expr_identifier_names,
        split_assignment=_split_simple_assignment,
        lhs_name=_lhs_name,
        mask_string_literals=_mask_string_literals,
        normalize_expression=_normalize_offset_expr,
        constant_expression=lambda expression: (
            _eval_int_expr(expression, _StackIndex(())) is not None
        ),
    )


























def _non_input_expr_candidate(
    candidate: StaticCandidate,
    expr_trace: Mapping[str, object],
) -> bool:
    dimensions = _symbolic_taint_dimensions(candidate)
    if not dimensions:
        return False
    for dimension in dimensions:
        summary = expr_trace.get(dimension)
        if not isinstance(summary, Mapping):
            return False
        rows = [
            row
            for row in expr_trace.get("taint_table", [])
            if isinstance(row, Mapping) and row.get("dimension") == dimension
        ]
        if not rows:
            return False
        labels = {str(row.get("classification") or "unknown") for row in rows}
        if labels & {"source_controlled", "parameter_controlled", "unknown"}:
            return False
        if not labels.issubset({"constant_or_literal", "internal_local"}):
            return False
    return True


def _symbolic_taint_dimensions(candidate: StaticCandidate) -> list[str]:
    dimensions: list[str] = []
    relation = str(candidate.write_relation or "")
    if relation in {"symbolic_offset", "symbolic_offset_size_guarded", "iterated_alias_unproven", "symbolic_read_offset"}:
        dimensions.append("offset_expr")
    if relation in {"symbolic_size", "append_length_unknown"}:
        dimensions.append("write_size_expr")
    if relation in INTEGER_MEMORY_RISK_RELATIONS:
        risk = candidate.classification_trace.get("integer_risk") if isinstance(candidate.classification_trace, Mapping) else {}
        role = str(risk.get("role") or "") if isinstance(risk, Mapping) else ""
        if "offset" in role:
            dimensions.append("offset_expr")
        elif "size" in role:
            dimensions.append("write_size_expr")
    if not dimensions:
        if _expr_is_symbolic(candidate.offset_expr):
            dimensions.append("offset_expr")
        if _expr_is_symbolic(candidate.write_size_expr):
            dimensions.append("write_size_expr")
    return _unique_nonempty(dimensions)


def _source_link_trace(
    candidate: StaticCandidate,
    expr_taint: Mapping[str, object],
) -> dict[str, object]:
    rows = [
        row for row in expr_taint.get("taint_table", []) if isinstance(row, Mapping)
    ]
    source_rows = [row for row in rows if row.get("classification") == "source_controlled"]
    parameter_rows = [row for row in rows if row.get("classification") == "parameter_controlled"]
    source_symbols = _unique_nonempty([str(row.get("symbol") or "") for row in source_rows])
    parameter_symbols = _unique_nonempty([str(row.get("symbol") or "") for row in parameter_rows])
    sources = [str(source) for row in source_rows for source in row.get("sources", [])]
    source_call_symbols = _unique_nonempty(
        [str(row.get("symbol") or "") for row in source_rows if any("source_call:" in source for source in row.get("sources", []))]
    )
    argv_symbols = _unique_nonempty(
        [str(row.get("symbol") or "") for row in source_rows if any("argv" in source for source in row.get("sources", []))]
    )
    argc_symbols = _unique_nonempty(
        [str(row.get("symbol") or "") for row in source_rows if any("argc" in source for source in row.get("sources", []))]
    )
    return {
        "source_function_reaches_candidate": bool(
            candidate.input_reaches_sink
            or candidate.reachability_kind in {"local_source", "source_path"}
            or candidate.source_evidence
        ),
        "expr_source_linked": bool(source_rows or parameter_rows),
        "source_controlled_identifiers": source_symbols,
        "parameter_controlled_identifiers": parameter_symbols,
        "source_call_identifiers": source_call_symbols,
        "argv_identifiers": argv_symbols,
        "argc_identifiers": argc_symbols,
        "parameter_identifiers": parameter_symbols,
        "local_source_sources": _unique_nonempty(sources),
    }


def _reachability_dataflow_trace(candidate: StaticCandidate) -> Mapping[str, object]:
    trace = candidate.classification_trace if isinstance(candidate.classification_trace, Mapping) else {}
    value = trace.get("reachability_dataflow") if isinstance(trace, Mapping) else None
    return value if isinstance(value, Mapping) else {}


def _trace_is_complete_unreachable(candidate: StaticCandidate) -> bool:
    trace = _reachability_dataflow_trace(candidate)
    graph = trace.get("graph") if isinstance(trace.get("graph"), Mapping) else {}
    return bool(graph.get("complete_unreachable_candidate")) if isinstance(graph, Mapping) else False


def _trace_is_non_input_expr_candidate(candidate: StaticCandidate) -> bool:
    trace = _reachability_dataflow_trace(candidate)
    expr_taint = trace.get("expr_taint") if isinstance(trace.get("expr_taint"), Mapping) else {}
    return bool(expr_taint.get("non_input_expr_candidate")) if isinstance(expr_taint, Mapping) else False


def _trace_has_source_or_parameter_taint(candidate: StaticCandidate) -> bool:
    trace = _reachability_dataflow_trace(candidate)
    expr_taint = trace.get("expr_taint") if isinstance(trace.get("expr_taint"), Mapping) else {}
    rows = expr_taint.get("taint_table", []) if isinstance(expr_taint, Mapping) else []
    if not isinstance(rows, list):
        return False
    return any(
        isinstance(row, Mapping)
        and str(row.get("classification") or "") in {"source_controlled", "parameter_controlled"}
        for row in rows
    )


def _source_function_names(nodes: Sequence[FunctionNode]) -> list[str]:
    names: list[str] = []
    for node in nodes:
        evidence = _source_evidence_for_node(node, _strip_c_comments((node.text or "").splitlines()))
        if evidence:
            names.append(node.record.name)
    return names


def _entry_function_names(order: Mapping[str, int]) -> list[str]:
    exact = [name for name in ENTRY_NAMES if name in order]
    if exact:
        return exact
    lowered = {name.lower(): name for name in order}
    return [original for lowered_name, original in lowered.items() if lowered_name in {item.lower() for item in ENTRY_NAMES}]


def _select_nodes(nodes: Sequence[FunctionNode], *, skip: int, sample: Optional[int]) -> list[FunctionNode]:
    if skip < 0:
        raise ValueError("--skip must be non-negative")
    if sample is not None and sample < 0:
        raise ValueError("--sample must be non-negative when provided")
    selected = list(nodes[skip:] if skip < len(nodes) else [])
    if sample is not None:
        selected = selected[:sample]
    return selected


def _analysis_cache_key(
    manifest: Manifest,
    nodes: Sequence[FunctionNode],
    export_dir: Path,
) -> str:
    export_dir = Path(export_dir)
    callgraph_path = export_dir / str(manifest.callgraph_path or "callgraph.json")
    source_symbols_path = export_dir / "source_symbols.json"
    payload = {
        "analysis_version": ANALYSIS_CACHE_VERSION,
        "operation_specs_version": OPERATION_SPEC_SET.version,
        "operation_specs": OPERATION_SPECS,
        "manifest": {
            "binary": manifest.binary,
            "generated_at": manifest.generated_at,
            "image_base": manifest.image_base,
            "function_count": len(manifest.functions),
            "manifest_sha256": _file_sha256(export_dir / "manifest_normalized.json"),
        },
        "function_text_hashes": [
            {
                "address": node.record.address,
                "relative_path": node.record.relative_path,
                "text_sha256": hashlib.sha256((node.text or "").encode("utf-8")).hexdigest(),
            }
            for node in nodes
        ],
        "sidecar_hashes": {
            "callgraph": _file_sha256(callgraph_path),
            "source_symbols": _file_sha256(source_symbols_path),
        },
    }
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    try:
        if not path.exists() or not path.is_file():
            return ""
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _analysis_cache_path(cache_dir: Optional[Path], cache_key: str) -> Optional[Path]:
    if cache_dir is None:
        return None
    return Path(cache_dir).resolve() / f"{cache_key}.json"


def _load_analysis_cache(cache_dir: Optional[Path], cache_key: str) -> Optional[_FactPipelineResult]:
    path = _analysis_cache_path(cache_dir, cache_key)
    if path is None or not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    candidates = [StaticCandidate.from_dict(item) for item in payload.get("candidate_findings", [])]
    write_facts = [
        WriteFact.from_dict(item)
        for item in payload.get("write_facts", [])
        if isinstance(item, Mapping)
    ]
    summaries = [
        FunctionSummary.from_dict(item)
        for item in payload.get("function_summaries", [])
        if isinstance(item, Mapping)
    ]
    classified = [
        ClassifiedFinding.from_dict(item)
        for item in payload.get("classified_findings", [])
        if isinstance(item, Mapping)
    ]
    suppressed = [
        SuppressedFinding(
            fact_id=str(item.get("fact_id") or ""),
            reason=str(item.get("reason") or ""),
            function_name=str(item.get("function_name") or ""),
            sink=str(item.get("sink") or ""),
            target_buffer=str(item.get("target_buffer") or ""),
            trace=dict(item.get("trace", {}) or {}),
        )
        for item in payload.get("suppressed_findings", [])
        if isinstance(item, Mapping)
    ]
    candidates = [_with_v3_trace(candidate) for candidate in candidates]
    if not write_facts:
        write_facts = [candidate_to_write_fact(candidate) for candidate in candidates]
    if not classified:
        classified = [_classified_finding_from_candidate(candidate) for candidate in candidates]
    return _FactPipelineResult(
        candidate_findings=candidates,
        write_facts=write_facts,
        resolved_writes=[_resolved_write_from_fact(fact) for fact in write_facts],
        function_summaries=summaries,
        classified_findings=classified,
        suppressed_findings=suppressed,
    )


def _write_analysis_cache(
    cache_dir: Optional[Path],
    cache_key: str,
    extraction: _FactPipelineResult,
) -> None:
    path = _analysis_cache_path(cache_dir, cache_key)
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "analysis_version": ANALYSIS_CACHE_VERSION,
            "cache_key": cache_key,
            "candidate_findings": [candidate.to_dict() for candidate in extraction.candidate_findings],
            "write_facts": [fact.to_dict() for fact in extraction.write_facts],
            "classified_findings": [finding.to_dict() for finding in extraction.classified_findings],
            "function_summaries": [summary.to_dict() for summary in extraction.function_summaries],
            "suppressed_findings": [finding.to_dict() for finding in extraction.suppressed_findings],
        }
        path.write_text(json.dumps(payload, indent=2))
    except OSError:
        return


def _finding_signature(address: str, relative_path: str) -> str:
    return f"{address}:{relative_path}"


CLUSTER_RULE_SUPPRESSION_REASONS = {
    "non_sink_callsite",
    "bounded_capacity_proven_safe",
    "bounded_wrapper_proven_safe",
    "range_loop_proven_safe",
    "allocation_write_proven_safe",
    "weak_object_not_reportable",
    "constant_initializer_summary",
}


def _suppress_cluster_rule_candidates(
    candidates: Sequence[StaticCandidate],
) -> tuple[list[StaticCandidate], list[SuppressedFinding]]:
    kept: list[StaticCandidate] = []
    suppressed: list[SuppressedFinding] = []
    for candidate in candidates:
        reason = _cluster_rule_suppression_reason(candidate)
        if not reason:
            kept.append(candidate)
            continue
        suppressed.append(
            SuppressedFinding(
                fact_id=candidate.candidate_id,
                reason=reason,
                function_name=candidate.function_name,
                sink=candidate.sink,
                target_buffer=candidate.target_buffer,
                trace={
                    "candidate_id": candidate.candidate_id,
                    "kind": candidate.kind,
                    "line_text": candidate.line_text,
                    "write_relation": candidate.write_relation,
                    "verdict": candidate.verdict,
                    "cluster_rule": reason,
                    "evidence_sources": list(candidate.evidence_sources),
                },
            )
        )
    return kept, suppressed


def _cluster_rule_suppression_reason(candidate: StaticCandidate) -> str:
    if not _candidate_has_source_sink_alignment(candidate):
        return "non_sink_callsite"
    if _pointer_store_uses_modeled_object_as_pointee_source(candidate):
        return "non_sink_callsite"
    if _constant_initializer_summary_candidate(candidate):
        return "constant_initializer_summary"
    return ""


def _candidate_has_source_sink_alignment(candidate: StaticCandidate) -> bool:
    """Return whether the modeled write is backed by sink or write semantics."""

    kind = candidate.kind.removeprefix("parameter_summary_").removeprefix("interprocedural_")
    sink = _normalize_sink_name(candidate.sink)
    if sink in ALL_SINKS:
        return True
    if candidate.vulnerability_type in {"out_of_bounds_read", *INTEGER_MEMORY_RISK_TYPES}:
        return True
    if kind in {"indexed_write", "field_indexed_write", "pointer_store", "pcode_store"}:
        return candidate.sink in {
            "array_store",
            "field_array_store",
            "pointer_store",
            "pcode_store",
        }
    if any(str(source).startswith("pcode") for source in candidate.evidence_sources):
        return True
    if any("summary" in str(source) for source in candidate.evidence_sources):
        return True
    for callee, _args in _iter_calls(candidate.line_text):
        normalized = _normalize_sink_name(callee)
        if normalized in ALL_SINKS:
            return True
    return False


def _pointer_store_uses_modeled_object_as_pointee_source(candidate: StaticCandidate) -> bool:
    kind = candidate.kind.removeprefix("parameter_summary_").removeprefix("interprocedural_")
    if kind not in {"pointer_store", "pcode_store"}:
        return False
    target = str(candidate.target_buffer or "")
    line = str(candidate.line_text or "")
    if not target or "*(" not in line:
        return False
    escaped = re.escape(target)
    return bool(re.search(rf"\*\s*\([^)]*\)\s*\([^;]*\b{escaped}\s*\[[^\]]+\]\s*\+", line))


def _weak_object_candidate_is_not_reportable(candidate: StaticCandidate) -> bool:
    if candidate.verdict not in {"overflow", "unbounded"}:
        return False
    trace = candidate.classification_trace if isinstance(candidate.classification_trace, Mapping) else {}
    stack = trace.get("stack_coalescing") if isinstance(trace.get("stack_coalescing"), Mapping) else {}
    if stack and str(stack.get("classification") or "") == "likely_decompiler_split":
        return True
    basis = f"{candidate.capacity_basis} {candidate.capacity_source}".lower()
    return any(token in basis for token in ("merged_stack_region", "contiguous_stack_region", "decompiler local fragment"))


def _cluster_candidate_representatives(candidates: Sequence[StaticCandidate]) -> list[StaticCandidate]:
    clusters: dict[tuple[str, ...], list[StaticCandidate]] = {}
    for candidate in candidates:
        clusters.setdefault(_candidate_cluster_key(candidate), []).append(candidate)
    representatives: list[StaticCandidate] = []
    for key, siblings in clusters.items():
        representatives.append(_candidate_cluster_representative(key, siblings))
    return representatives


def _candidate_cluster_key(candidate: StaticCandidate) -> tuple[str, ...]:
    normalized_kind = candidate.kind.removeprefix("parameter_summary_").removeprefix("interprocedural_")
    if normalized_kind in {"indexed_write", "field_indexed_write"}:
        semantics = "indexed_store"
    elif normalized_kind in {"pointer_store", "pcode_store"}:
        semantics = "direct_store"
    else:
        sink = _normalize_sink_name(candidate.sink)
        semantics = str(OPERATION_SPECS.get(sink, {}).get("semantics") or sink or normalized_kind)
    capacity_class = (
        f"fixed:{candidate.capacity_bytes}"
        if candidate.capacity_bytes > 0
        else f"symbolic:{candidate.capacity_source}:{_normalize_offset_expr(str((candidate.capacity_model or {}).get('symbolic_expr') or ''))}"
    )
    source = _candidate_cluster_source_fingerprint(candidate, normalized_kind)
    exact_range = ""
    if candidate.verdict in {"overflow", "unbounded"}:
        exact_range = ":".join(
            [
                _normalize_offset_expr(candidate.offset_expr),
                _normalize_offset_expr(candidate.write_size_expr),
                "" if candidate.write_size_bytes is None else str(candidate.write_size_bytes),
                candidate.overflow_condition,
            ]
        )
    return (
        candidate.source_object or candidate.binary,
        candidate.function_name,
        candidate.vulnerability_type,
        source,
        semantics,
        candidate.destination_kind,
        _canonical_cluster_destination(candidate.target_buffer),
        capacity_class,
        _normalize_offset_expr(candidate.write_relation),
        exact_range,
    )


def _candidate_cluster_source_fingerprint(candidate: StaticCandidate, normalized_kind: str) -> str:
    if candidate.operation_address:
        return f"op:{candidate.operation_address}"
    if normalized_kind in {"indexed_write", "field_indexed_write", "pointer_store", "pcode_store"}:
        return ":".join(
            [
                "store",
                normalized_kind,
                _normalize_offset_expr(candidate.offset_expr),
                "" if candidate.write_size_bytes is None else str(candidate.write_size_bytes),
            ]
        )
    if normalized_kind in {"indexed_read", "pointer_read", "source_read"} or candidate.vulnerability_type in INTEGER_MEMORY_RISK_TYPES:
        return ":".join(
            [
                "read_or_integer",
                candidate.vulnerability_type,
                normalized_kind,
                _normalize_offset_expr(candidate.offset_expr),
                _normalize_offset_expr(candidate.write_size_expr),
            ]
        )
    line_text = " ".join(candidate.line_text.split())
    return f"line:{candidate.line_number}:{line_text}"


def _canonical_cluster_destination(target: str) -> str:
    text = _normalize_offset_expr(target)
    text = re.sub(r"\[[^\]]+\]", "[]", text)
    return text


def _candidate_cluster_representative(
    key: tuple[str, ...],
    siblings: Sequence[StaticCandidate],
) -> StaticCandidate:
    ordered = sorted(siblings, key=_stable_candidate_sort_key)
    representative = max(ordered, key=_candidate_cluster_rank)
    sibling_ids = [candidate.candidate_id for candidate in ordered if candidate.candidate_id != representative.candidate_id]
    cluster_key = "|".join(key)
    cluster_id = "cluster:" + hashlib.sha256(cluster_key.encode("utf-8")).hexdigest()[:16]
    traces = [_candidate_cluster_member_trace(candidate) for candidate in ordered]
    summary = {
        "cluster_id": cluster_id,
        "cluster_key": list(key),
        "representative_id": representative.candidate_id,
        "candidate_ids": [candidate.candidate_id for candidate in ordered],
        "size": len(ordered),
        "verdicts": sorted({candidate.verdict for candidate in ordered if candidate.verdict}),
        "write_relations": sorted({candidate.write_relation for candidate in ordered if candidate.write_relation}),
        "sinks": sorted({candidate.sink for candidate in ordered if candidate.sink}),
        "members": traces,
    }
    evidence = _unique_nonempty([item for candidate in ordered for item in candidate.evidence])
    source_evidence = _unique_nonempty([item for candidate in ordered for item in candidate.source_evidence])
    guard_evidence = _unique_nonempty([item for candidate in ordered for item in candidate.guard_evidence])
    evidence_sources = _unique_nonempty([item for candidate in ordered for item in candidate.evidence_sources])
    trace = {
        **dict(representative.classification_trace or {}),
        "cluster": summary,
    }
    return replace(
        representative,
        evidence=evidence,
        source_evidence=source_evidence,
        guard_evidence=guard_evidence,
        evidence_sources=evidence_sources,
        classification_trace=trace,
        cluster_id=cluster_id,
        cluster_size=len(ordered),
        sibling_ids=sibling_ids,
        cluster_key=cluster_key,
        cluster_summary=summary,
    )


def _candidate_cluster_rank(candidate: StaticCandidate) -> tuple[int, int, int, int, int, str]:
    verdict_rank = {"overflow": 4, "unbounded": 4, "candidate": 1}.get(candidate.verdict, 0)
    taint_rank = 3 if _candidate_has_attacker_taint(candidate) else 0
    reachability_rank = 2 if candidate.path_is_valid or candidate.reachability_kind in {"entry_path", "source_path", "local_source"} else 0
    object_rank = 0 if _weak_object_candidate_is_not_reportable(candidate) else 1
    evidence_rank = len(set(candidate.evidence_sources))
    return (
        verdict_rank,
        taint_rank,
        reachability_rank,
        object_rank,
        evidence_rank,
        candidate.candidate_id,
    )


def _candidate_has_attacker_taint(candidate: StaticCandidate) -> bool:
    if candidate.input_reaches_sink:
        return True
    if candidate.path_is_valid and candidate.source_evidence:
        return True
    has_reachable_context = bool(
        candidate.path_is_valid
        or candidate.reachability_kind in {"entry_path", "source_path", "local_source"}
    )
    if has_reachable_context and _trace_has_source_or_parameter_taint(candidate):
        return True
    trace = candidate.classification_trace if isinstance(candidate.classification_trace, Mapping) else {}
    attacker = trace.get("attacker_control") if isinstance(trace.get("attacker_control"), Mapping) else {}
    return bool(
        has_reachable_context
        and any(
            str(value) in {"source_controlled", "parameter_controlled", "attacker_controlled"}
            for value in attacker.values()
        )
    )


def _candidate_cluster_member_trace(candidate: StaticCandidate) -> dict[str, object]:
    return {
        "candidate_id": candidate.candidate_id,
        "function_name": candidate.function_name,
        "vulnerability_type": candidate.vulnerability_type,
        "kind": candidate.kind,
        "sink": candidate.sink,
        "line_number": candidate.line_number,
        "operation_address": candidate.operation_address,
        "target_buffer": candidate.target_buffer,
        "offset_expr": candidate.offset_expr,
        "write_size_expr": candidate.write_size_expr,
        "write_size_bytes": candidate.write_size_bytes,
        "write_relation": candidate.write_relation,
        "verdict": candidate.verdict,
        "evidence_sources": list(candidate.evidence_sources),
    }


def _candidate_id(
    binary: str,
    address: str,
    name: str,
    line: int,
    sink: str,
    target: str,
    *,
    operation_address: str = "",
    offset_expr: str = "",
    write_size_expr: str = "",
) -> str:
    safe_target = re.sub(r"[^0-9A-Za-z_.-]+", "_", target).strip("_")
    safe_offset = re.sub(r"[^0-9A-Za-z_.-]+", "_", _normalize_offset_expr(offset_expr or "0")).strip("_") or "0"
    safe_size = re.sub(r"[^0-9A-Za-z_.-]+", "_", _normalize_offset_expr(write_size_expr or "unknown")).strip("_") or "unknown"
    location = operation_address or str(line)
    return f"{binary}:{address}:{name}:{location}:{sink}:{safe_target}:{safe_offset}:{safe_size}"


def _reconcile_candidate_duplicates(
    candidates: Sequence[StaticCandidate],
) -> tuple[list[StaticCandidate], list[SuppressedFinding]]:
    """Collapse true duplicate write observations while preserving debug trace.

    P-code and C producers are both allowed to run. This step removes only
    findings that describe the same semantic write: same function, sink family,
    destination, normalized write range, and either the same operation address
    or the same decompiled source line when no operation address is available.
    """

    best_by_key: dict[tuple[str, ...], StaticCandidate] = {}
    suppressed: list[SuppressedFinding] = []
    for candidate in candidates:
        key = _candidate_reconcile_key(candidate)
        existing = best_by_key.get(key)
        if existing is None:
            best_by_key[key] = candidate
            continue
        keep, drop = _preferred_duplicate_candidate(existing, candidate)
        best_by_key[key] = keep
        suppressed.append(
            SuppressedFinding(
                fact_id=drop.candidate_id,
                reason="duplicate_write_fact",
                function_name=drop.function_name,
                sink=drop.sink,
                target_buffer=drop.target_buffer,
                trace={
                    "kept_candidate_id": keep.candidate_id,
                    "dropped_candidate_id": drop.candidate_id,
                    "reconcile_key": list(key),
                    "kept_sources": list(keep.evidence_sources),
                    "dropped_sources": list(drop.evidence_sources),
                },
            )
        )
    return list(best_by_key.values()), suppressed


def _candidate_reconcile_key(candidate: StaticCandidate) -> tuple[str, ...]:
    location = (
        f"op:{candidate.operation_address}"
        if candidate.operation_address
        else f"line:{candidate.line_number}:{' '.join(candidate.line_text.split())}"
    )
    normalized_kind = candidate.kind.removeprefix("interprocedural_")
    if normalized_kind in {"indexed_write", "field_indexed_write"}:
        normalized_sink = "indexed_store"
    elif normalized_kind in {"pointer_store", "pcode_store"}:
        normalized_sink = "direct_store"
    else:
        normalized_sink = _normalize_sink_name(candidate.sink)
    return (
        candidate.binary,
        candidate.address,
        candidate.function_name,
        location,
        candidate.vulnerability_type,
        normalized_sink,
        candidate.destination_kind,
        candidate.target_buffer,
        _normalize_offset_expr(candidate.offset_expr),
        _normalize_offset_expr(candidate.write_size_expr),
        "" if candidate.write_size_bytes is None else str(candidate.write_size_bytes),
        _normalize_offset_expr(candidate.write_relation),
    )


def _preferred_duplicate_candidate(
    left: StaticCandidate,
    right: StaticCandidate,
) -> tuple[StaticCandidate, StaticCandidate]:
    def score(candidate: StaticCandidate) -> tuple[int, int, int, int]:
        has_pcode = int(any(str(source).startswith("pcode") for source in candidate.evidence_sources))
        has_operation = int(bool(candidate.operation_address))
        verdict_rank = {"overflow": 3, "unbounded": 2, "candidate": 1}.get(candidate.verdict, 0)
        source_count = len(set(candidate.evidence_sources))
        return has_pcode, has_operation, verdict_rank, source_count

    if score(right) > score(left):
        return right, left
    return left, right


def _stable_candidate_sort_key(candidate: StaticCandidate) -> tuple[str, ...]:
    return (
        candidate.binary,
        candidate.address,
        candidate.function_name,
        candidate.operation_address or f"{candidate.line_number:08d}",
        candidate.sink,
        candidate.destination_kind,
        candidate.target_buffer,
        _normalize_offset_expr(candidate.offset_expr),
        _normalize_offset_expr(candidate.write_size_expr),
        "" if candidate.write_size_bytes is None else str(candidate.write_size_bytes),
        candidate.candidate_id,
    )


def _dedupe_candidates(candidates: Sequence[StaticCandidate]) -> list[StaticCandidate]:
    deduped: dict[str, StaticCandidate] = {}
    for candidate in candidates:
        if candidate.candidate_id not in deduped:
            deduped[candidate.candidate_id] = candidate
    return list(deduped.values())


def _dedupe_candidates_stable(candidates: Sequence[StaticCandidate]) -> list[StaticCandidate]:
    deduped: dict[str, StaticCandidate] = {}
    for candidate in candidates:
        if candidate.candidate_id not in deduped:
            deduped[candidate.candidate_id] = candidate
    return list(deduped.values())


def _dedupe_confirmation_candidates(candidates: Sequence[StaticCandidate]) -> list[StaticCandidate]:
    deduped: dict[tuple[str, ...], StaticCandidate] = {}
    for candidate in candidates:
        signature = _confirmation_dedupe_signature(candidate)
        existing = deduped.get(signature)
        if existing is None:
            deduped[signature] = candidate
        elif _is_interprocedural_callsite_confirmation_candidate(candidate):
            deduped[signature] = _merge_confirmation_equivalent_candidate(existing, candidate)
    return list(deduped.values())


def _confirmation_dedupe_signature(candidate: StaticCandidate) -> tuple[str, ...]:
    if _is_unknown_interprocedural_pointer_store_summary(candidate):
        return (
            candidate.binary,
            "unknown_interprocedural_pointer_store",
            _interprocedural_summary_callee(candidate),
            candidate.sink,
            candidate.destination_kind,
            candidate.write_relation,
        )
    callsite_signature = _interprocedural_callsite_confirmation_signature(candidate)
    if callsite_signature:
        return callsite_signature
    common = (
        candidate.binary,
        candidate.function_name,
        candidate.kind,
        candidate.sink,
        candidate.vulnerability_type,
        candidate.target_buffer,
        candidate.destination_kind,
        candidate.capacity_source,
        candidate.capacity_basis,
        candidate.write_relation,
        _confirmation_source_locator(candidate),
    )
    if candidate.verdict == "candidate":
        return common
    return common + (
        _normalize_offset_expr(candidate.offset_expr),
        _normalize_offset_expr(candidate.write_size_expr),
        candidate.overflow_condition,
    )


def _interprocedural_callsite_confirmation_signature(candidate: StaticCandidate) -> tuple[str, ...]:
    if not _is_interprocedural_callsite_confirmation_candidate(candidate):
        return ()
    return (
        candidate.binary,
        candidate.address,
        candidate.relative_path,
        candidate.function_name,
        "interprocedural_callsite",
        candidate.kind,
        candidate.sink,
        candidate.target_buffer,
        candidate.destination_kind,
        candidate.capacity_source,
        candidate.capacity_basis,
        candidate.write_relation,
        _confirmation_source_locator(candidate),
    )


def _is_interprocedural_callsite_confirmation_candidate(candidate: StaticCandidate) -> bool:
    return bool(
        candidate.kind.startswith("interprocedural_")
        and "interprocedural_summary" in candidate.evidence_sources
    )


_CONFIRMATION_AGGREGATION_EVIDENCE_PREFIX = "confirmation aggregation:"


def _merge_confirmation_equivalent_candidate(
    kept: StaticCandidate,
    duplicate: StaticCandidate,
) -> StaticCandidate:
    trace = dict(kept.classification_trace or {})
    writes = list(trace.get("confirmation_equivalent_writes") or [])
    if not writes:
        writes.append(_confirmation_equivalent_write_trace(kept))
    writes.append(_confirmation_equivalent_write_trace(duplicate))
    trace["confirmation_equivalent_writes"] = writes
    trace["confirmation_equivalent_write_count"] = len(writes)
    evidence = [
        item
        for item in kept.evidence
        if not str(item).startswith(_CONFIRMATION_AGGREGATION_EVIDENCE_PREFIX)
    ]
    evidence.append(_confirmation_aggregation_evidence(writes))
    return replace(
        kept,
        evidence=evidence,
        source_evidence=_unique_nonempty([*kept.source_evidence, *duplicate.source_evidence]),
        guard_evidence=_unique_nonempty([*kept.guard_evidence, *duplicate.guard_evidence]),
        evidence_sources=_unique_nonempty([*kept.evidence_sources, *duplicate.evidence_sources]),
        classification_trace=trace,
    )


def _confirmation_equivalent_write_trace(candidate: StaticCandidate) -> dict[str, object]:
    return {
        "candidate_id": candidate.candidate_id,
        "kind": candidate.kind,
        "sink": candidate.sink,
        "offset_expr": candidate.offset_expr,
        "write_size_expr": candidate.write_size_expr,
        "write_size_bytes": candidate.write_size_bytes,
        "overflow_condition": candidate.overflow_condition,
    }


def _confirmation_aggregation_evidence(writes: Sequence[Mapping[str, object]]) -> str:
    offsets = _unique_nonempty(
        [
            _normalize_offset_expr(str(write.get("offset_expr") or ""))
            or str(write.get("offset_expr") or "")
            for write in writes
        ]
    )
    sample = ", ".join(offsets[:8])
    if len(offsets) > 8:
        sample = f"{sample}, ..."
    suffix = f"; offsets: {sample}" if sample else ""
    return (
        f"{_CONFIRMATION_AGGREGATION_EVIDENCE_PREFIX} "
        f"{len(writes)} equivalent writes at this callsite{suffix}"
    )


def _confirmation_source_locator(candidate: StaticCandidate) -> str:
    line_text = " ".join(candidate.line_text.split())
    if candidate.line_number > 0 or line_text:
        return f"line:{candidate.line_number}:{line_text}"
    return f"op:{candidate.operation_address or candidate.address}"


def _interprocedural_summary_callee(candidate: StaticCandidate) -> str:
    condition = str(candidate.overflow_condition or "")
    if " writes " in condition:
        callee = condition.split(" writes ", 1)[0].strip()
        if callee:
            return callee
    for callee, _args in _iter_calls(candidate.line_text):
        if callee:
            return callee
    return candidate.function_name


def _function_keys(node: FunctionNode) -> list[str]:
    keys = [node.record.name, node.record.source_symbol, _demangled_base_name(node.record.demangled_name)]
    return _unique_nonempty(keys + [_normalize_function_key(key) for key in keys])


@lru_cache(maxsize=8192)
def _demangled_base_name(name: str) -> str:
    base = str(name or "").split("(", 1)[0].strip()
    if "::" in base:
        base = base.split("::")[-1]
    return base.strip()


@lru_cache(maxsize=8192)
def _normalize_function_key(name: str) -> str:
    cleaned = str(name or "").strip().split("::")[-1]
    cleaned = cleaned.split("@", 1)[0].lstrip("_")
    return cleaned


def _unique_nonempty(values: Sequence[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in result:
            result.append(text)
    return result


def _summaries_for_call(callee: str, summaries_by_key: Mapping[str, list[_WriteSummary]]) -> list[_WriteSummary]:
    summaries: list[_WriteSummary] = []
    seen: set[tuple[object, ...]] = set()
    for key in _summary_lookup_keys(callee):
        for summary in summaries_by_key.get(key, []):
            identity = _summary_identity(summary)
            if identity not in seen:
                seen.add(identity)
                summaries.append(summary)
    return summaries


@lru_cache(maxsize=8192)
def _summary_lookup_keys(callee: str) -> tuple[str, ...]:
    return tuple(_unique_nonempty([callee, _normalize_function_key(callee), _normalize_sink_name(callee)]))


def _iter_calls(line: str) -> Iterable[tuple[str, list[str]]]:
    if "(" not in line:
        return
    ignored = {"if", "for", "while", "switch", "return", "sizeof"}
    idx = 0
    quote: Optional[str] = None
    escaped = False
    while idx < len(line):
        ch = line[idx]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
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
        while idx < len(line) and (line[idx].isalnum() or line[idx] == "_"):
            idx += 1
        raw_name = line[start:idx]
        if raw_name in ignored:
            continue
        open_index = idx
        while open_index < len(line) and line[open_index].isspace():
            open_index += 1
        if open_index >= len(line) or line[open_index] != "(":
            continue
        close_index = _find_matching_paren(line, open_index)
        if close_index < 0:
            continue
        yield raw_name, _split_arguments(line[open_index + 1 : close_index])
        idx = close_index + 1


def _iter_sink_calls(line: str) -> Iterable[tuple[str, list[str]]]:
    idx = 0
    quote: Optional[str] = None
    escaped = False
    while idx < len(line):
        ch = line[idx]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
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
        while idx < len(line) and (line[idx].isalnum() or line[idx] == "_"):
            idx += 1
        raw_name = line[start:idx]
        open_index = idx
        while open_index < len(line) and line[open_index].isspace():
            open_index += 1
        if open_index >= len(line) or line[open_index] != "(":
            continue
        sink = _normalize_sink_name(raw_name)
        if sink not in ALL_SINKS:
            continue
        close_index = _find_matching_paren(line, open_index)
        if close_index < 0:
            continue
        raw_args = line[open_index + 1 : close_index]
        yield sink, _split_arguments(raw_args)
        idx = close_index + 1


def _find_matching_paren(text: str, open_index: int) -> int:
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for idx in range(open_index, len(text)):
        ch = text[idx]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
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


def _split_arguments(raw: str) -> list[str]:
    args: list[str] = []
    start = 0
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for idx, ch in enumerate(raw):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
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
            args.append(raw[start:idx].strip())
            start = idx + 1
    tail = raw[start:].strip()
    if tail:
        args.append(tail)
    return args


def _text_may_contain_sink_call(text: str) -> bool:
    lowered = str(text or "").lower()
    if "(" not in lowered:
        return False
    return any(sink in lowered for sink in ALL_SINKS)


def _line_may_contain_sink_call(line: str) -> bool:
    return _text_may_contain_sink_call(line)


def _line_may_contain_index_write(line: str) -> bool:
    text = str(line or "")
    if "[" not in text or "]" not in text:
        return False
    return "=" in text or "++" in text or "--" in text


def _line_may_contain_index_read(line: str) -> bool:
    text = str(line or "")
    return "[" in text and "]" in text


def _line_may_contain_pointer_read(line: str) -> bool:
    return bool(re.search(r"\*\s*\([^)]*\*\s*\)\s*\(", str(line or "")))


def _line_may_contain_pointer_store(line: str) -> bool:
    text = str(line or "")
    return "*" in text and "=" in text


def _split_simple_assignment(line: str) -> tuple[str, str]:
    idx = _assignment_index(line)
    if idx < 0:
        return "", ""
    lhs = line[:idx].strip()
    rhs = line[idx + 1 :].strip()
    rhs = rhs.split(";", 1)[0].strip()
    return lhs, rhs


def _assignment_lhs(line: str) -> str:
    idx = _assignment_index(line)
    return "" if idx < 0 else line[:idx].strip()


def _assignment_index(line: str) -> int:
    if "=" not in line:
        return -1
    quote: Optional[str] = None
    escaped = False
    for idx, ch in enumerate(line):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in {"'", '"'}:
            quote = ch
            continue
        if ch != "=":
            continue
        prev_ch = line[idx - 1] if idx else ""
        next_ch = line[idx + 1] if idx + 1 < len(line) else ""
        if prev_ch in {"=", "!", "<", ">", "+", "-", "*", "/", "%", "&", "|", "^"}:
            continue
        if next_ch == "=":
            continue
        return idx
    return -1


def _lhs_name(lhs: str) -> str:
    if not lhs or lhs.strip().startswith("*"):
        return ""
    if "[" in lhs or "->" in lhs or "." in lhs:
        return ""
    identifiers = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", lhs)
    if not identifiers:
        return ""
    keywords = {
        "char",
        "short",
        "int",
        "long",
        "void",
        "unsigned",
        "signed",
        "const",
        "volatile",
        "static",
        "struct",
        "enum",
        "union",
        "undefined",
        "undefined1",
        "undefined2",
        "undefined4",
        "undefined8",
        "size_t",
    }
    identifiers = [item for item in identifiers if item not in keywords]
    return identifiers[-1] if identifiers else ""


def _deref_target_expr(lhs: str) -> str:
    stripped = lhs.strip()
    while stripped.startswith("*"):
        stripped = stripped[1:].strip()
    return _clean_expr(stripped)


def _deref_cast_type(lhs: str) -> str:
    match = re.search(
        r"\(\s*(?P<type>(?:unsigned\s+)?[A-Za-z_][A-Za-z0-9_\s]*)\s*\*\s*\)",
        lhs,
    )
    return match.group("type") if match else ""


def _deref_write_width(lhs: str, stack_obj: Mapping[str, object]) -> int:
    cast_type = _deref_cast_type(lhs)
    if cast_type:
        return max(1, _type_size(_normalize_c_type(cast_type)))
    return max(1, _element_size(stack_obj))


@lru_cache(maxsize=8192)
def _normalize_sink_name(name: str) -> str:
    lowered = str(name or "").strip().split("::")[-1].lower()
    lowered = lowered.split("@", 1)[0]
    lowered = lowered.lstrip("_")
    if lowered in SINK_ALIASES:
        return SINK_ALIASES[lowered]
    if lowered in ALL_SINKS:
        return lowered
    for sink in SORTED_ALL_SINKS:
        if lowered == sink or lowered.endswith(f"_{sink}") or lowered.endswith(sink):
            return sink
    return lowered


def _pcode_args(entry: Mapping[str, object]) -> list[Mapping[str, object]]:
    args = entry.get("argument_facts") or entry.get("arguments") or entry.get("args") or []
    if isinstance(args, (str, bytes)) or not hasattr(args, "__iter__"):
        return []
    normalized: list[Mapping[str, object]] = []
    for arg in args:
        if isinstance(arg, Mapping):
            normalized.append(arg)
        else:
            normalized.append({"expr": str(arg)})
    return normalized


def _fortified_pcode_call_cannot_overflow(
    spec: Mapping[str, object],
    args: Sequence[Mapping[str, object]],
    destination: Mapping[str, object],
    *,
    write_size: Optional[int] = None,
) -> bool:
    if not bool(spec.get("fortified")):
        return False
    object_size_index = spec.get("object_size_arg")
    if object_size_index is None:
        return False
    object_size = _pcode_constant_arg(args, int(object_size_index))
    if object_size is None or object_size <= 0 or object_size >= (1 << 63):
        return False
    capacity = _safe_int(destination.get("size_bytes"))
    return object_size <= capacity or (write_size is not None and write_size > object_size)


def _pcode_stack_arg(args: Sequence[Mapping[str, object]], index: int, stack_index: _StackIndex) -> Optional[dict]:
    obj, _offset_expr = _pcode_stack_target(args, index, stack_index)
    return obj


def _pcode_stack_target(
    args: Sequence[Mapping[str, object]],
    index: int,
    stack_index: _StackIndex,
) -> tuple[Optional[dict], str]:
    if index >= len(args):
        return None, "unknown"
    arg = args[index]
    stack_ref = arg.get("stack_ref") if isinstance(arg.get("stack_ref"), Mapping) else {}
    for key in ("var_name", "base_var", "base_variable", "base", "stack_var", "stack_base"):
        value = arg.get(key) or stack_ref.get(key)
        if value:
            obj = stack_index.find_for_var(str(value))
            if obj:
                relative_offset = _first_int(arg, ("relative_offset", "object_offset"))
                if relative_offset is None and stack_ref:
                    relative_offset = _first_int(stack_ref, ("relative_offset", "object_offset"))
                return obj, (
                    _combine_offsets(
                        _member_offset_expr(obj, str(value)),
                        "0" if relative_offset is None else str(relative_offset),
                    )
                    or "0"
                )
    stack_offset = _first_int(arg, ("stack_offset", "base_offset", "offset"))
    if stack_offset is None and stack_ref:
        stack_offset = _first_int(stack_ref, ("stack_offset", "base_offset", "offset"))
    if stack_offset is not None:
        obj = stack_index.find_for_stack_offset(stack_offset)
        if obj:
            return obj, str(stack_offset - _safe_int(obj.get("start_offset")))
    expr = _pcode_arg_expr(args, index)
    obj = stack_index.find_for_expr(expr)
    return obj, "0" if obj else "unknown"


def _pcode_constant_arg(args: Sequence[Mapping[str, object]], index: int) -> Optional[int]:
    if index >= len(args):
        return None
    return _first_int(args[index], ("constant", "constant_value", "value", "int_value"))


def _pcode_arg_expr(args: Sequence[Mapping[str, object]], index: int) -> str:
    if index >= len(args):
        return ""
    arg = args[index]
    for key in ("expr", "expression", "repr", "storage"):
        value = arg.get(key)
        if value not in {None, ""}:
            return str(value)
    constant = _pcode_constant_arg(args, index)
    return "" if constant is None else str(constant)


def _pcode_store_target(entry: Mapping[str, object], stack_index: _StackIndex) -> tuple[Optional[dict], Optional[int]]:
    stack_ref = entry.get("stack_ref") if isinstance(entry.get("stack_ref"), Mapping) else {}
    for key in ("base_var", "base_variable", "var_name", "stack_var", "stack_base", "base"):
        value = entry.get(key) or stack_ref.get(key)
        if not value:
            continue
        obj = stack_index.find_for_var(str(value))
        if not obj:
            continue
        relative_offset = _first_int(entry, ("relative_offset", "object_offset"))
        if relative_offset is None:
            relative_offset = _first_int(stack_ref, ("relative_offset", "object_offset"))
        return obj, relative_offset
    stack_offset = _first_int(entry, ("stack_offset", "dest_stack_offset", "base_offset"))
    if stack_offset is None:
        stack_offset = _first_int(stack_ref, ("stack_offset", "dest_stack_offset", "base_offset"))
    if stack_offset is None:
        return None, None
    obj = stack_index.find_for_stack_offset(stack_offset)
    if not obj:
        return None, None
    relative_offset = stack_offset - _safe_int(obj.get("start_offset"))
    return obj, relative_offset


def _first_int(mapping: Mapping[str, object], keys: Sequence[str]) -> Optional[int]:
    for key in keys:
        if key not in mapping:
            continue
        value = mapping.get(key)
        if value is None or value == "":
            continue
        try:
            return int(str(value), 0)
        except (TypeError, ValueError):
            continue
    return None


@lru_cache(maxsize=65536)
def _clean_expr(expr: str) -> str:
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")") and _find_matching_paren(expr, 0) == len(expr) - 1:
        expr = expr[1:-1].strip()
    expr = CAST_PREFIX_RE.sub("", expr).strip()
    expr = _flatten_parenthesized_member_expr(expr)
    return expr


def _flatten_parenthesized_member_expr(expr: str) -> str:
    pattern = re.compile(
        r"\((?P<inner>[A-Za-z_][A-Za-z0-9_]*(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)+)\)"
        r"\s*(?P<op>->|\.)\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)"
    )
    previous = None
    text = str(expr or "")
    while previous != text:
        previous = text
        text = pattern.sub(r"\g<inner>\g<op>\g<field>", text)
    return text


@lru_cache(maxsize=65536)
def _strip_c_casts(expr: str) -> str:
    previous = None
    cleaned = str(expr or "")
    while previous != cleaned:
        previous = cleaned
        cleaned = C_CAST_RE.sub("", cleaned)
        cleaned = _clean_expr(cleaned)
    return cleaned.strip()


def _eval_int_expr(expr: str, stack_index: _StackIndex) -> Optional[int]:
    expr = _normalize_offset_expr(expr)
    if not expr:
        return None
    expr = _replace_sizeof_and_array_size(expr, stack_index)
    literal = _parse_int_literal(expr)
    if literal is not None:
        return literal
    if not re.fullmatch(r"[0-9xXa-fA-F+\-*/%() <>&|]+", expr):
        return None
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        return None
    try:
        return int(_eval_ast_int(tree.body))
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _replace_sizeof_and_array_size(expr: str, stack_index: _StackIndex) -> str:
    def sizeof_replacement(match: re.Match[str]) -> str:
        name = match.group("name")
        size = stack_index.capacity_for_var(name)
        if size is None:
            size = _type_size(_normalize_c_type(name))
        return str(size) if size else match.group(0)

    def array_size_replacement(match: re.Match[str]) -> str:
        name = match.group("name")
        obj = stack_index.find_for_var(name)
        if not obj:
            return match.group(0)
        capacity = _safe_int(obj.get("size_bytes"))
        element_size = max(1, _element_size(obj))
        return str(capacity // element_size) if capacity else match.group(0)

    cleaned = re.sub(
        r"\bsizeof\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
        sizeof_replacement,
        expr,
    )
    cleaned = re.sub(
        r"\bsizeof\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
        sizeof_replacement,
        cleaned,
    )
    cleaned = re.sub(
        r"\b(?:ARRAY_SIZE|array_size)\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
        array_size_replacement,
        cleaned,
    )
    return cleaned


def _parse_int_literal(value: str) -> Optional[int]:
    try:
        return int(value, 0)
    except ValueError:
        return None


def _eval_ast_int(node: ast.AST) -> int:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return int(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_eval_ast_int(node.operand)
    if isinstance(node, ast.BinOp):
        left = _eval_ast_int(node.left)
        right = _eval_ast_int(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.FloorDiv):
            return left // right
        if isinstance(node.op, ast.Div):
            return left // right
        if isinstance(node.op, ast.Mod):
            return left % right
        if isinstance(node.op, ast.LShift):
            return left << right
        if isinstance(node.op, ast.RShift):
            return left >> right
        if isinstance(node.op, ast.BitOr):
            return left | right
        if isinstance(node.op, ast.BitAnd):
            return left & right
    raise TypeError(f"Unsupported integer expression: {ast.dump(node)}")


def _scanf_conversions(format_arg: str) -> Optional[list[dict[str, object]]]:
    match = re.search(r'"(?P<fmt>(?:\\.|[^"\\])*)"', format_arg)
    if not match:
        return None
    fmt = match.group("fmt")
    conversions: list[dict[str, object]] = []
    idx = 0
    while idx < len(fmt):
        if fmt[idx] != "%":
            idx += 1
            continue
        idx += 1
        if idx < len(fmt) and fmt[idx] == "%":
            idx += 1
            continue
        suppress = idx < len(fmt) and fmt[idx] == "*"
        if suppress:
            idx += 1
        width_start = idx
        while idx < len(fmt) and fmt[idx].isdigit():
            idx += 1
        width = fmt[width_start:idx]
        for modifier in ("hh", "ll", "h", "l", "j", "z", "t", "L"):
            if fmt.startswith(modifier, idx):
                idx += len(modifier)
                break
        if idx >= len(fmt):
            break
        kind = fmt[idx]
        if kind == "[":
            idx += 1
            if idx < len(fmt) and fmt[idx] == "^":
                idx += 1
            if idx < len(fmt) and fmt[idx] == "]":
                idx += 1
            while idx < len(fmt) and fmt[idx] != "]":
                idx += 1
            if idx < len(fmt) and fmt[idx] == "]":
                idx += 1
            kind = "["
        else:
            idx += 1
        consumes_dest = not suppress and kind not in {"%", "m"}
        string_like = kind in {"s", "["}
        conversions.append(
            {
                "kind": kind,
                "width": width,
                "consumes_dest": consumes_dest,
                "string_like": string_like,
                "unbounded": string_like and not width,
            }
        )
    return conversions


def _nearby_guard_evidence(
    lines: Sequence[str],
    line_number: int,
    index_expr: str,
    stack_index: _StackIndex,
    element_count: int,
) -> list[str]:
    del stack_index, element_count
    token = _simple_identifier(index_expr)
    if not token:
        return []
    start = max(0, line_number - 6)
    end = min(len(lines), line_number + 1)
    guards: list[str] = []
    for raw in lines[start:end]:
        line = raw.strip()
        if token not in line:
            continue
        if any(op in line for op in ("<", ">", "<=", ">=", "==")):
            guards.append(line)
    return guards


def _loop_bound_proves_index_safe(
    lines: Sequence[str],
    line_number: int,
    index_expr: str,
    stack_index: _StackIndex,
    element_count: int,
) -> bool:
    token = _simple_identifier(index_expr)
    if not token or element_count <= 0:
        return False
    start = max(0, line_number - 8)
    prefix = [raw.strip() for raw in lines[start : max(0, line_number - 1)]]
    initialized_zero = any(re.search(rf"\b{re.escape(token)}\b\s*=\s*0\s*;", line) for line in prefix)
    for line in prefix:
        if "for" not in line or token not in line:
            continue
        match = re.search(r"\bfor\s*\((?P<init>[^;]*);(?P<cond>[^;]*);(?P<step>[^)]*)\)", line)
        if not match:
            continue
        init = match.group("init")
        cond = match.group("cond")
        step = match.group("step")
        has_zero_init = initialized_zero or bool(re.search(rf"\b{re.escape(token)}\b\s*=\s*0\b", init))
        if not has_zero_init or not _loop_step_is_forward_by_one(step, token):
            continue
        upper = _loop_upper_bound(cond, token, stack_index)
        if upper is None:
            continue
        operator, limit = upper
        if operator == "<" and limit <= element_count:
            return True
        if operator == "<=" and limit < element_count:
            return True
    return False


def _indexed_write_bounds_prove_safe(
    lines: Sequence[str],
    line_number: int,
    index_expr: str,
    base_offset_expr: str,
    target_obj: Mapping[str, object],
    stack_index: _StackIndex,
) -> bool:
    capacity = _safe_int(target_obj.get("size_bytes"))
    if capacity <= 0:
        return False
    linear = _linear_identifier_offset(index_expr)
    if linear is None:
        return False
    symbol, delta = linear
    base_offset = _eval_optional_offset(base_offset_expr, stack_index)
    if base_offset is None:
        return False
    lower, upper = _index_symbol_bounds(symbol, lines, line_number, stack_index)
    if lower is None or upper is None:
        return False
    element_size = _element_size(target_obj)
    min_index = lower + delta
    max_index = upper + delta
    min_byte = base_offset + min_index * element_size
    highest_byte = base_offset + max_index * element_size + element_size
    return 0 <= min_byte and highest_byte <= capacity


def _index_symbol_bounds(
    symbol: str,
    lines: Sequence[str],
    line_number: int,
    stack_index: _StackIndex,
) -> tuple[Optional[int], Optional[int]]:
    lower: Optional[int] = None
    upper: Optional[int] = None
    root_re = re.escape(symbol)
    decl_re = re.compile(rf"^(?P<type>[A-Za-z_][A-Za-z0-9_\s\*]*?)\s+\**\b{root_re}\b(?:\s|$|=|,)")
    upper_start = max(0, line_number - 12)
    prefix_end = max(0, line_number - 1)
    for guard_index, line in enumerate(lines[:prefix_end]):
        if lower is None and _local_decl_is_unsigned(symbol, line, decl_re):
            lower = 0
        lhs, rhs = _split_simple_assignment(line)
        if _lhs_name(lhs) == symbol and re.search(r"\bdigits(?:10|_base10)?\s*\(", rhs):
            lower = max(lower or 0, 1)
        if symbol not in line:
            continue
        condition = _if_condition(line)
        if not condition or symbol not in condition:
            continue
        reject = _guard_branch_returns(lines, guard_index)
        if reject:
            reject_lower = _reject_condition_lower_bound(symbol, condition)
            if reject_lower is not None:
                lower = reject_lower if lower is None else max(lower, reject_lower)
        if guard_index < upper_start:
            continue
        line_upper = _condition_upper_bound_for_symbol(
            condition,
            symbol,
            stack_index,
            reject=reject,
        )
        if line_upper is None:
            continue
        upper = line_upper if upper is None else min(upper, line_upper)
    return lower, upper


def _local_decl_is_unsigned(symbol: str, line: str, decl_re: re.Pattern[str]) -> bool:
    stripped = line.strip().rstrip(";")
    if symbol not in stripped or "(" in stripped:
        return False
    match = decl_re.search(stripped)
    return bool(match and _type_is_unsigned_integer(match.group("type").strip()))


def _condition_upper_bound_for_symbol(
    condition: str,
    symbol: str,
    stack_index: _StackIndex,
    *,
    reject: bool,
) -> Optional[int]:
    upper: Optional[int] = None
    for atom in _iter_condition_comparison_terms(condition, reject=reject):
        comparison = _comparison_atom(atom)
        if comparison is None:
            continue
        left, op, right = comparison
        bound = _comparison_upper_bound_for_symbol(left, op, right, symbol, stack_index, reject=reject)
        if bound is not None:
            upper = bound if upper is None else min(upper, bound)
    return upper


def _iter_condition_comparison_terms(condition: str, *, reject: bool) -> Iterable[str]:
    text = _strip_outer_parens(_normalize_offset_expr(condition))
    split_op = "||" if reject else "&&"
    blocker_op = "&&" if reject else "||"
    for term in _iter_top_level_boolean_split(text, split_op):
        stripped = _strip_outer_parens(term)
        if _has_top_level_boolean_operator(stripped, blocker_op):
            continue
        yield stripped


def _iter_top_level_boolean_split(text: str, operator: str) -> Iterable[str]:
    start = 0
    for index in _iter_top_level_boolean_operator_indexes(text, operator):
        yield text[start:index].strip()
        start = index + len(operator)
    yield text[start:].strip()


def _has_top_level_boolean_operator(text: str, operator: str) -> bool:
    return any(True for _ in _iter_top_level_boolean_operator_indexes(_strip_outer_parens(text), operator))


def _iter_top_level_boolean_operator_indexes(text: str, operator: str) -> Iterable[int]:
    depth = 0
    quote = ""
    index = 0
    while index <= len(text) - len(operator):
        char = text[index]
        if quote:
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "(":
            depth += 1
            index += 1
            continue
        if char == ")":
            depth = max(0, depth - 1)
            index += 1
            continue
        if depth == 0 and text.startswith(operator, index):
            yield index
            index += len(operator)
            continue
        index += 1


def _comparison_atom(condition: str) -> Optional[tuple[str, str, str]]:
    text = _strip_outer_parens(_normalize_offset_expr(condition))
    for op in ("<=", ">=", "<", ">"):
        index = _comparison_operator_index(text, op)
        if index >= 0:
            return text[:index].strip(), op, text[index + len(op) :].strip()
    return None


def _comparison_operator_index(text: str, op: str) -> int:
    depth = 0
    quote = ""
    index = 0
    while index <= len(text) - len(op):
        char = text[index]
        if quote:
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and text.startswith(op, index):
            return index
        index += 1
    return -1


def _comparison_upper_bound_for_symbol(
    left: str,
    op: str,
    right: str,
    symbol: str,
    stack_index: _StackIndex,
    *,
    reject: bool,
) -> Optional[int]:
    left_linear = _linear_identifier_offset(left)
    if left_linear is not None and left_linear[0] == symbol:
        right_value = _eval_int_expr(right, stack_index)
        if right_value is not None:
            return _upper_bound_from_linear_comparison(op, right_value, left_linear[1], reject=reject)
    right_linear = _linear_identifier_offset(right)
    if right_linear is not None and right_linear[0] == symbol:
        left_value = _eval_int_expr(left, stack_index)
        if left_value is not None:
            reversed_op = REVERSED_COMPARISON_OP.get(op, op)
            return _upper_bound_from_linear_comparison(reversed_op, left_value, right_linear[1], reject=reject)
    return None


def _upper_bound_from_linear_comparison(op: str, value: int, delta: int, *, reject: bool) -> Optional[int]:
    positive_op = op
    if reject:
        positive_op = REJECTED_COMPARISON_OP.get(op, op)
    if positive_op == "<":
        return value - delta - 1
    if positive_op == "<=":
        return value - delta
    return None


def _direct_target_has_decompiler_field_component(
    base_offset_expr: str,
    byte_offset_expr: str,
    target_obj: Mapping[str, object],
) -> bool:
    if str(target_obj.get("destination_kind") or "stack") != "stack":
        return False
    return (
        _caller_arg_has_decompiler_field_component(base_offset_expr)
        or _caller_arg_has_decompiler_field_component(byte_offset_expr)
    )


def _loop_step_is_forward_by_one(step: str, token: str) -> bool:
    escaped = re.escape(token)
    return bool(
        re.search(rf"\b{escaped}\b\s*\+\+", step)
        or re.search(rf"\+\+\s*\b{escaped}\b", step)
        or re.search(rf"\b{escaped}\b\s*\+=\s*1\b", step)
        or re.search(rf"\b{escaped}\b\s*=\s*\b{escaped}\b\s*\+\s*1\b", step)
    )


def _loop_upper_bound(cond: str, token: str, stack_index: _StackIndex) -> Optional[tuple[str, int]]:
    escaped = re.escape(token)
    patterns = [
        (rf"\b{escaped}\b\s*<\s*(?P<limit>[^&|]+)", "<"),
        (rf"\b{escaped}\b\s*<=\s*(?P<limit>[^&|]+)", "<="),
        (rf"(?P<limit>[^&|]+)\s*>\s*\b{escaped}\b", "<"),
        (rf"(?P<limit>[^&|]+)\s*>=\s*\b{escaped}\b", "<="),
    ]
    for pattern, operator in patterns:
        match = re.search(pattern, cond)
        if not match:
            continue
        raw_limit = match.group("limit").strip()
        raw_limit = re.split(r"\s*(?:&&|\|\|)\s*", raw_limit, maxsplit=1)[0].strip()
        limit = _eval_int_expr(raw_limit, stack_index)
        if limit is not None:
            return operator, limit
    return None


def _iterated_alias_loop_bound_proves_safe(
    lines: Sequence[str],
    line_number: int,
    alias_name: str,
    target: _AliasTarget,
    stack_index: _StackIndex,
    write_offset: int,
    write_width: int,
) -> bool:
    if not alias_name or not target.stack_obj or write_width <= 0:
        return False
    start_offset = _eval_optional_offset(target.offset_expr, stack_index)
    if start_offset is None:
        return False
    relative_write_offset = write_offset - start_offset
    if relative_write_offset < 0:
        return False
    capacity = _safe_int(target.stack_obj.get("size_bytes"))
    for loop in _nearby_for_loops(lines, line_number, alias_name):
        bounds = _alias_loop_bounds(loop, alias_name, target.stack_obj, stack_index)
        if bounds is None:
            continue
        _start, max_alias_offset = bounds
        if max_alias_offset < 0:
            continue
        if max_alias_offset + relative_write_offset + write_width <= capacity:
            return True
    return False


def _nearby_for_loops(lines: Sequence[str], line_number: int, alias_name: str) -> list[str]:
    start = max(0, line_number - 10)
    prefix = [line.strip() for line in lines[start : max(0, line_number - 1)]]
    return [line for line in prefix if "for" in line and alias_name in line]


def _iterated_alias_has_symbolic_bound(
    lines: Sequence[str],
    line_number: int,
    alias_name: str,
    target: _AliasTarget,
    stack_index: _StackIndex,
) -> bool:
    if not alias_name or not target.stack_obj:
        return False
    start = max(0, line_number - 8)
    end = min(len(lines), line_number + 8)
    known_names = {alias_name}
    known_names.update(str(name) for obj in stack_index.objects for name in obj.get("var_names") or [])
    known_names.update(
        {
            "char",
            "short",
            "int",
            "long",
            "ulong",
            "uint",
            "size_t",
            "undefined",
            "undefined1",
            "undefined2",
            "undefined4",
            "undefined8",
        }
    )
    for raw in lines[start:end]:
        if alias_name not in raw:
            continue
        condition = _loop_or_branch_condition(raw)
        if not condition or alias_name not in condition:
            continue
        identifiers = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", condition))
        if any(identifier not in known_names for identifier in identifiers):
            return True
    return False


def _loop_or_branch_condition(line: str) -> str:
    for keyword in ("for", "while", "if"):
        match = re.search(rf"\b{keyword}\s*\((?P<body>.*)\)", line)
        if match:
            return match.group("body")
    return ""


def _alias_loop_bounds(
    loop_line: str,
    alias_name: str,
    stack_obj: Mapping[str, object],
    stack_index: _StackIndex,
) -> Optional[tuple[int, int]]:
    match = re.search(r"\bfor\s*\((?P<init>[^;]*);(?P<cond>[^;]*);(?P<step>[^)]*)\)", loop_line)
    if not match:
        return None
    init_lhs, init_rhs = _split_simple_assignment(match.group("init") + ";")
    if _lhs_name(init_lhs) != alias_name:
        return None
    base_name = _stack_base_name_for_expr(init_rhs, stack_obj)
    if not base_name:
        return None
    start_offset = _eval_optional_offset(_offset_from_base(_normalize_pointer_expr(init_rhs), base_name), stack_index)
    if start_offset is None:
        return None
    cond_bound = _alias_loop_condition_bound(match.group("cond"), alias_name, base_name, stack_index)
    if cond_bound is None:
        return None
    operator, limit_offset = cond_bound
    step = _alias_loop_step(match.group("step"), alias_name, stack_index)
    if step is None or step <= 0:
        return None
    if operator == "<":
        max_alias_offset = limit_offset - step
    elif operator == "<=":
        max_alias_offset = limit_offset
    elif operator == "!=":
        distance = limit_offset - start_offset
        if distance <= 0 or distance % step != 0:
            return None
        max_alias_offset = limit_offset - step
    else:
        return None
    return start_offset, max_alias_offset


def _stack_base_name_for_expr(expr: str, stack_obj: Mapping[str, object]) -> str:
    cleaned = _normalize_pointer_expr(expr)
    for name in stack_obj.get("var_names") or []:
        text = str(name)
        if _expr_is_rooted_at_name(cleaned, text):
            return text
    return ""


def _alias_loop_condition_bound(
    cond: str,
    alias_name: str,
    base_name: str,
    stack_index: _StackIndex,
) -> Optional[tuple[str, int]]:
    alias = re.escape(alias_name)
    base = re.escape(base_name)
    patterns = (
        (rf"\b{alias}\b\s*<\s*(?P<limit>{base}\b[^&|)]*)", "<"),
        (rf"\b{alias}\b\s*<=\s*(?P<limit>{base}\b[^&|)]*)", "<="),
        (rf"\b{alias}\b\s*!=\s*(?P<limit>{base}\b[^&|)]*)", "!="),
        (rf"(?P<limit>{base}\b[^&|)]*)\s*>\s*\b{alias}\b", "<"),
        (rf"(?P<limit>{base}\b[^&|)]*)\s*>=\s*\b{alias}\b", "<="),
        (rf"(?P<limit>{base}\b[^&|)]*)\s*!=\s*\b{alias}\b", "!="),
    )
    for pattern, operator in patterns:
        match = re.search(pattern, cond)
        if not match:
            continue
        limit_expr = _normalize_pointer_expr(match.group("limit"))
        offset = _eval_optional_offset(_offset_from_base(limit_expr, base_name), stack_index)
        if offset is not None:
            return operator, offset
    return None


def _alias_loop_step(step: str, alias_name: str, stack_index: _StackIndex) -> Optional[int]:
    escaped = re.escape(alias_name)
    if re.search(rf"\b{escaped}\b\s*\+\+", step) or re.search(rf"\+\+\s*\b{escaped}\b", step):
        return 1
    for pattern in (
        rf"\b{escaped}\b\s*\+=\s*(?P<delta>[^;]+)",
        rf"\b{escaped}\b\s*=\s*\b{escaped}\b\s*\+\s*(?P<delta>[^;]+)",
    ):
        match = re.search(pattern, step)
        if not match:
            continue
        delta = _eval_int_expr(match.group("delta"), stack_index)
        if delta is not None:
            return delta
    return None


def _guards_prove_index_safe(
    guards: Sequence[str],
    index_expr: str,
    stack_index: _StackIndex,
    element_count: int,
) -> bool:
    del stack_index
    token = _simple_identifier(index_expr)
    if not token or element_count <= 0:
        return False
    if _guards_reject_out_of_range(guards, token, element_count):
        return True
    if not _guards_have_lower_bound(guards, token):
        return False
    for guard in guards:
        upper = _extract_upper_bound(guard, token)
        if upper is None:
            continue
        operator, limit = upper
        if operator == "<" and 0 < limit <= element_count:
            return True
        if operator == "<=" and 0 <= limit < element_count:
            return True
    return False


def _guards_reject_out_of_range(guards: Sequence[str], token: str, element_count: int) -> bool:
    escaped = re.escape(token)
    for guard in guards:
        has_low_reject = bool(
            re.search(rf"\b{escaped}\b\s*<\s*0\b", guard)
            or re.search(rf"\b0\b\s*>\s*\b{escaped}\b", guard)
        )
        if not has_low_reject:
            continue
        upper_limits: list[int] = []
        for pattern in (
            rf"(?P<limit>0x[0-9a-fA-F]+|\d+)\s*<\s*\b{escaped}\b",
            rf"\b{escaped}\b\s*>\s*(?P<limit>0x[0-9a-fA-F]+|\d+)",
            rf"\b{escaped}\b\s*>=\s*(?P<limit>0x[0-9a-fA-F]+|\d+)",
        ):
            for match in re.finditer(pattern, guard):
                limit = _parse_int_literal(match.group("limit"))
                if limit is not None:
                    upper_limits.append(limit)
        if any(limit >= element_count - 1 for limit in upper_limits):
            return True
    return False


def _guards_have_lower_bound(guards: Sequence[str], token: str) -> bool:
    for guard in guards:
        escaped = re.escape(token)
        if re.search(rf"\b{escaped}\b\s*>=\s*0\b", guard):
            return True
        if re.search(rf"\b0\b\s*<=\s*\b{escaped}\b", guard):
            return True
    return False


def _extract_upper_bound(guard: str, token: str) -> Optional[tuple[str, int]]:
    escaped = re.escape(token)
    patterns = [
        (rf"\b{escaped}\b\s*<\s*(?P<limit>0x[0-9a-fA-F]+|\d+)", "<"),
        (rf"\b{escaped}\b\s*<=\s*(?P<limit>0x[0-9a-fA-F]+|\d+)", "<="),
    ]
    for pattern, operator in patterns:
        match = re.search(pattern, guard)
        if not match:
            continue
        limit = _parse_int_literal(match.group("limit"))
        if limit is not None:
            return operator, limit
    return None


def _dangerous_index_guard(guards: Sequence[str], index_expr: str, element_count: int) -> str:
    token = _simple_identifier(index_expr)
    if not token:
        return ""
    escaped = re.escape(token)
    for guard in guards:
        if re.search(rf"\b{escaped}\b\s*<\s*0\b", guard):
            return f"guard allows only negative {token}, which writes before the stack object"
        match = re.search(rf"\b{escaped}\b\s*>=\s*(?P<limit>0x[0-9a-fA-F]+|\d+)", guard)
        if match:
            limit = _parse_int_literal(match.group("limit"))
            if limit is not None and element_count and limit >= element_count:
                return f"guard allows {token} >= {limit}, outside {element_count} elements"
    return ""


def _simple_identifier(expr: str) -> str:
    expr = _clean_expr(expr)
    return expr if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr) else ""


def _root_identifier(expr: str) -> str:
    cleaned = _normalize_pointer_expr(expr)
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\b", cleaned)
    return match.group(1) if match else ""


def _single_identifier_in_expr(expr: str) -> str:
    cleaned = _normalize_offset_expr(expr)
    identifiers = [
        token
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", cleaned)
        if token
        not in {
            "long",
            "ulong",
            "int",
            "uint",
            "size_t",
            "char",
            "undefined",
            "undefined1",
            "undefined2",
            "undefined4",
            "undefined8",
        }
    ]
    unique = _unique_nonempty(identifiers)
    return unique[0] if len(unique) == 1 else ""


def _element_size(stack_obj: Mapping[str, object]) -> int:
    declared_size = _safe_int(stack_obj.get("declared_element_size_bytes"))
    if declared_size > 0:
        return declared_size
    for data_type in stack_obj.get("data_types") or []:
        lowered = str(data_type).lower()
        if "long long" in lowered:
            return 8
        if re.search(r"\blong\b", lowered):
            return 8
        if re.search(r"\bint\b|undefined4", lowered):
            return 4
        if re.search(r"\bshort\b|undefined2", lowered):
            return 2
        if re.search(r"\bchar\b|\bbyte\b|undefined1|undefined", lowered):
            return 1
    return 1


def _source_evidence_for_node(node: FunctionNode, lines: Sequence[str]) -> list[str]:
    evidence: list[str] = []
    source_text = node.text or ""
    if not any(token in source_text for token in (*SOURCE_CALLS, *SOURCE_TOKENS)) and not node.record.pcode_calls:
        return []
    original_lines = source_text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        masked = _mask_string_literals(line).lower()
        if "(" in masked and any(source in masked for source in SOURCE_CALLS):
            if any(sink in SOURCE_CALLS for sink, _args in _iter_sink_calls(masked)):
                display = original_lines[line_number - 1].strip() if line_number - 1 < len(original_lines) else line.strip()
                evidence.append(f"line {line_number}: {display}")
                continue
        if any(re.search(rf"\b{re.escape(token)}\b", masked) for token in SOURCE_TOKENS):
            display = original_lines[line_number - 1].strip() if line_number - 1 < len(original_lines) else line.strip()
            evidence.append(f"line {line_number}: {display}")
    for entry in node.record.pcode_calls or []:
        callee = _normalize_sink_name(str(entry.get("callee") or entry.get("function") or ""))
        if callee in SOURCE_CALLS:
            address = str(entry.get("call_address") or entry.get("address") or "")
            suffix = f" at {address}" if address else ""
            evidence.append(f"p-code call: {callee}{suffix}")
    return evidence[:4]


def _strip_c_comments(lines: Sequence[str]) -> list[str]:
    cleaned: list[str] = []
    in_block = False
    for raw in lines:
        idx = 0
        quote: Optional[str] = None
        escaped = False
        out: list[str] = []
        while idx < len(raw):
            ch = raw[idx]
            nxt = raw[idx + 1] if idx + 1 < len(raw) else ""
            if in_block:
                if ch == "*" and nxt == "/":
                    in_block = False
                    idx += 2
                else:
                    idx += 1
                continue
            if quote:
                out.append(ch)
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                idx += 1
                continue
            if ch in {"'", '"'}:
                quote = ch
                out.append(ch)
                idx += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block = True
                idx += 2
                continue
            out.append(ch)
            idx += 1
        cleaned.append("".join(out))
    return cleaned


def _mask_string_literals(line: str) -> str:
    out: list[str] = []
    quote: Optional[str] = None
    escaped = False
    for ch in line:
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
                out.append(ch)
                continue
            out.append(" ")
            continue
        if ch in {"'", '"'}:
            quote = ch
            out.append(ch)
            continue
        out.append(ch)
    return "".join(out)


def _safe_int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
