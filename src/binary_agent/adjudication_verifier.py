"""Deterministic semantic verification for untrusted adjudication proposals.

Provider prose is never evidence.  This module reloads an immutable
investigation pack, derives facts from the bound source and binary operation,
and either emits a checked result or a structured rejection.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.adjudication import sha256_file
from binary_agent.adjudication_investigation import (
    InvestigationError,
    check_investigation_pack,
    validate_proposal_shape,
)


SCHEMA_VERSION = 1
VERIFIED_KIND = "binary_adjudication_verified_investigation"
NULLABLE_ALLOCATORS = frozenset(
    {
        "calloc",
        "calloc_a",
        "malloc",
        "realloc",
        "strdup",
        "strndup",
    }
)


class VerificationError(ValueError):
    """Raised when a proposal cannot be deterministically verified."""


@dataclass(frozen=True)
class SourceStatement:
    text: str
    normalized: str
    start_line: int
    end_line: int
    byte_start: int
    byte_end: int
    brace_depth: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SourceFunction:
    name: str
    path: str
    text: str
    start_line: int


@dataclass(frozen=True)
class VerifiedInvestigation:
    candidate_id: str
    verified: bool
    decision: str = ""
    basis: str = ""
    claim_kind: str = ""
    exact_operation: Mapping[str, Any] = field(default_factory=dict)
    proof: Mapping[str, Any] = field(default_factory=dict)
    root_cause: Mapping[str, Any] = field(default_factory=dict)
    nearby_defects: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    evidence_refs: Sequence[Mapping[str, str]] = field(default_factory=tuple)
    rejection_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": VERIFIED_KIND,
            **asdict(self),
        }


def group_verified_investigations(
    investigations: Sequence[VerifiedInvestigation],
) -> Mapping[str, Any]:
    """Build a deterministic group index without using candidate IDs as identity."""

    candidate_ids = [item.candidate_id for item in investigations]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise VerificationError("verified investigation set contains duplicate candidates")
    grouped: dict[str, dict[str, Any]] = {}
    nearby: list[Mapping[str, Any]] = []
    for investigation in investigations:
        if not investigation.verified:
            raise VerificationError("unverified investigation cannot enter root grouping")
        for defect in investigation.nearby_defects:
            nearby.append({"observed_while_checking": investigation.candidate_id, **dict(defect)})
        if investigation.decision != "bug":
            continue
        cause = dict(investigation.root_cause)
        root_id = str(cause.get("root_cause_id") or "")
        if not root_id:
            raise VerificationError("bug investigation has no root-cause identity")
        payload = {key: value for key, value in cause.items() if key != "root_cause_id"}
        existing = grouped.get(root_id)
        if existing is not None and existing["root_cause"] != payload:
            raise VerificationError("root-cause hash collision has incompatible causal facts")
        if existing is None:
            grouped[root_id] = {
                "root_cause_id": root_id,
                "root_cause": payload,
                "candidate_ids": [],
            }
        grouped[root_id]["candidate_ids"].append(investigation.candidate_id)
    groups = []
    for root_id in sorted(grouped):
        row = grouped[root_id]
        row["candidate_ids"] = sorted(row["candidate_ids"])
        groups.append(row)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": "binary_adjudication_root_cause_groups",
        "groups": groups,
        "nearby_defects": sorted(
            nearby,
            key=lambda item: (
                str(item.get("nearby_defect_id") or ""),
                str(item.get("observed_while_checking") or ""),
            ),
        ),
    }


def verify_investigation_proposal(
    campaign_root: Path,
    pack_path: Path,
    proposal_path: Path,
) -> VerifiedInvestigation:
    """Verify one proposal from frozen evidence, never from provider authority."""

    root = Path(campaign_root).resolve()
    pack = check_investigation_pack(root, pack_path)
    proposal_file = Path(proposal_path).resolve()
    try:
        raw = json.loads(proposal_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot load investigation proposal: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise VerificationError("investigation proposal must be an object")
    candidate_id = str(pack.get("candidate_id") or "")
    try:
        proposal = validate_proposal_shape(raw, candidate_id=candidate_id)
    except InvestigationError as exc:
        raise VerificationError(str(exc)) from exc
    if str(proposal.get("proposed_decision") or "") == "escalate":
        return _rejected(pack, "proposal requests additional investigation")
    _verify_exact_operation(pack, _object(proposal.get("exact_operation")))
    claim_kind = str(proposal.get("claim_kind") or "")
    if claim_kind == "null_path":
        result = verify_null_path(root, pack, proposal)
    elif claim_kind == "spatial_path":
        result = verify_spatial_path(root, pack, proposal)
    else:
        return _rejected(pack, f"claim kind {claim_kind!r} has no semantic verifier")
    if result.decision != str(proposal.get("proposed_decision") or ""):
        return _rejected(
            pack,
            "proposed decision disagrees with deterministic semantic result",
            proof={"derived_decision": result.decision, "derived_proof": result.proof},
        )
    evidence_refs = [
        {
            "path": _relative(root, Path(pack_path)),
            "sha256": sha256_file(Path(pack_path)),
            "kind": "investigation_pack",
        },
        {
            "path": _relative(root, proposal_file),
            "sha256": sha256_file(proposal_file),
            "kind": "untrusted_investigation_proposal",
        },
        {
            "path": str(_object(pack.get("source_context")).get("path") or ""),
            "sha256": str(_object(pack.get("source_context")).get("sha256") or ""),
            "kind": "exact_source",
        },
    ]
    for reference in result.proof.get("supporting_evidence_refs") or []:
        if isinstance(reference, Mapping) and reference not in evidence_refs:
            evidence_refs.append(dict(reference))
    return VerifiedInvestigation(
        candidate_id=result.candidate_id,
        verified=True,
        decision=result.decision,
        basis=result.basis,
        claim_kind=result.claim_kind,
        exact_operation=result.exact_operation,
        proof=result.proof,
        root_cause=result.root_cause,
        nearby_defects=result.nearby_defects,
        evidence_refs=tuple(evidence_refs),
    )


def verify_null_path(
    campaign_root: Path,
    pack: Mapping[str, Any],
    proposal: Mapping[str, Any],
) -> VerifiedInvestigation:
    """Derive null reachability and the earliest mandatory dereference."""

    candidate_id = str(pack.get("candidate_id") or "")
    source = _object(pack.get("source_context"))
    function_text = str(source.get("function_text") or "")
    operation_line = int(source.get("operation_line_in_function") or 0)
    statements = split_c_statements(function_text)
    candidate_statement = _statement_for_line(statements, operation_line)
    pointer = _candidate_pointer(candidate_statement.normalized)
    if not pointer:
        return _rejected(pack, "exact source operation is not a pointer dereference")
    proposed_pointer = str(_object(proposal.get("claims")).get("pointer") or "")
    if proposed_pointer and proposed_pointer != pointer:
        return _rejected(pack, "proposal pointer disagrees with exact source operation")

    candidate_index = statements.index(candidate_statement)
    origins = [
        (index, statement, allocator)
        for index, statement in enumerate(statements[:candidate_index])
        if (allocator := _nullable_assignment(statement.normalized, pointer)) is not None
    ]
    if not origins:
        return _rejected(pack, "no nullable allocation origin reaches the exact operation")
    origin_index, origin_statement, allocator = origins[-1]
    between = statements[origin_index + 1 : candidate_index]
    guard = next(
        (statement for statement in between if _terminating_null_guard(statement.normalized, pointer)),
        None,
    )
    earlier = [
        statement
        for statement in between
        if _dereferences_pointer(statement.normalized, pointer)
        and not _is_null_test(statement.normalized, pointer)
    ]
    candidate_dereferences = _dereferences_pointer(candidate_statement.normalized, pointer)
    if not candidate_dereferences:
        return _rejected(pack, "exact source statement does not dereference its pointer")

    common = {
        "pointer": pointer,
        "allocator": allocator,
        "origin_statement": origin_statement.to_dict(),
        "candidate_statement": candidate_statement.to_dict(),
        "source_function_sha256": str(source.get("function_sha256") or ""),
    }
    exact_operation = _operation_identity(pack)
    if guard is not None and not earlier:
        proof = {
            **common,
            "rule_claim": "a terminating null guard dominates the exact dereference",
            "guard_statement": guard.to_dict(),
            "earliest_fault": exact_operation,
            "null_path_reaches_candidate": False,
            "claims": {
                "exact_operation": True,
                "source_or_binary_binding": True,
                "pointer_origin": True,
                "null_path": True,
                "earliest_fault": True,
                "dominating_nonnull_guard": True,
                "dominating_non_null": True,
                "exact_zero_capable_access": True,
            },
        }
        return VerifiedInvestigation(
            candidate_id=candidate_id,
            verified=True,
            decision="not_bug",
            basis="source_proves_safety",
            claim_kind="null_path",
            exact_operation=exact_operation,
            proof=proof,
            root_cause={},
        )
    if earlier:
        earliest = earlier[0]
        defect = _nearby_null_defect(pack, pointer, allocator, origin_statement, earliest)
        proof = {
            **common,
            "rule_claim": "the proposed null path must fault at an earlier dereference",
            "earlier_dereferences": [statement.to_dict() for statement in earlier],
            "earliest_fault": earliest.to_dict(),
            "null_path_reaches_candidate": False,
            "claims": {
                "exact_operation": True,
                "source_or_binary_binding": True,
                "pointer_origin": True,
                "null_path": True,
                "earliest_fault": True,
                "complete_cfg_path_infeasible": True,
                "violating_path_infeasible": True,
                "exact_zero_capable_access": True,
            },
        }
        return VerifiedInvestigation(
            candidate_id=candidate_id,
            verified=True,
            decision="not_bug",
            basis="cfg_smt_path_infeasible",
            claim_kind="null_path",
            exact_operation=exact_operation,
            proof=proof,
            root_cause={},
            nearby_defects=(defect,),
        )

    entry = verify_source_entry_reachability(campaign_root, pack)
    if not entry.get("reachable"):
        return _rejected(pack, "no enumerated process or callback entry reaches the exact source function")
    relation = "nullable allocation result is dereferenced without a dominating guard"
    root_cause = _root_cause(
        pack,
        causal_operation={
            "source_function_sha256": str(source.get("function_sha256") or ""),
            "origin_normalized": origin_statement.normalized,
        },
        object_identity=f"pointer:{pointer}",
        defect_relation=relation,
    )
    proof = {
        **common,
        "rule_claim": relation,
        "earlier_dereferences": [],
        "earliest_fault": candidate_statement.to_dict(),
        "null_path_reaches_candidate": True,
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "pointer_origin": True,
            "null_path": True,
            "earliest_fault": True,
            "exact_zero_capable_access": True,
            "real_entry_reachability": True,
            "zero_address_feasible": True,
            "attacker_or_boundary_control": True,
        },
        "entry_reachability": entry,
        "supporting_evidence_refs": entry.get("evidence_refs") or [],
    }
    return VerifiedInvestigation(
        candidate_id=candidate_id,
        verified=True,
        decision="bug",
        basis="exact_source_feasible_violation",
        claim_kind="null_path",
        exact_operation=exact_operation,
        proof=proof,
        root_cause=root_cause,
    )


def verify_spatial_path(
    campaign_root: Path,
    pack: Mapping[str, Any],
    proposal: Mapping[str, Any],
) -> VerifiedInvestigation:
    """Prove a length-derived STORE against an exact array capacity."""

    candidate_id = str(pack.get("candidate_id") or "")
    source = _object(pack.get("source_context"))
    function_text = str(source.get("function_text") or "")
    statements = split_c_statements(function_text)
    candidate = _statement_for_line(
        statements, int(source.get("operation_line_in_function") or 0)
    )
    pointer = _candidate_pointer(candidate.normalized)
    if not pointer:
        return _rejected(pack, "exact source operation has no verifiable pointer base")
    proposed_pointer = str(_object(proposal.get("claims")).get("pointer") or "")
    if proposed_pointer and proposed_pointer != pointer:
        return _rejected(pack, "proposal pointer disagrees with exact source operation")

    candidate_index = statements.index(candidate)
    origin = _last_length_pointer_origin(statements[:candidate_index], pointer)
    if origin is None:
        return _rejected(pack, "no length-derived pointer origin reaches the exact STORE")
    origin_index, origin_statement, object_name = origin
    try:
        capacity = _resolve_object_capacity(campaign_root, pack, object_name)
    except VerificationError as exc:
        return _rejected(pack, str(exc))
    width = int(_object(pack.get("exact_operation")).get("width_bytes") or 0)
    if width <= 0:
        return _rejected(pack, "exact STORE has no positive binary width")

    guard = _find_capacity_guard(
        statements[origin_index + 1 : candidate_index],
        pointer=pointer,
        object_name=object_name,
        required_width=width,
    )
    exact_operation = _operation_identity(pack)
    common = {
        "pointer": pointer,
        "object": object_name,
        "capacity_bytes": capacity["capacity_bytes"],
        "capacity_basis": capacity,
        "pointer_origin": origin_statement.to_dict(),
        "candidate_statement": candidate.to_dict(),
        "source_function_sha256": str(source.get("function_sha256") or ""),
    }
    if guard is not None:
        proof = {
            **common,
            "rule_claim": "a terminating capacity guard dominates the exact STORE",
            "guard": guard,
            "claims": {
                "exact_operation": True,
                "source_or_binary_binding": True,
                "exact_store": True,
                "object_identity": True,
                "capacity": True,
                "offset_relation": True,
                "dominating_bounds_guard": True,
                "bounds_proven": True,
            },
            "supporting_evidence_refs": capacity.get("evidence_refs") or [],
        }
        return VerifiedInvestigation(
            candidate_id=candidate_id,
            verified=True,
            decision="not_bug",
            basis="source_proves_safety",
            claim_kind="spatial_path",
            exact_operation=exact_operation,
            proof=proof,
            root_cause={},
        )

    producer = _capacity_length_producer(
        campaign_root,
        pack,
        statements[: origin_index + 1],
        object_name=object_name,
    )
    if not producer.get("maximum_length_reachable"):
        return _rejected(pack, "no verified producer can fill the object to capacity minus one")
    entry = verify_source_entry_reachability(campaign_root, pack)
    if not entry.get("reachable"):
        return _rejected(pack, "no enumerated process or callback entry reaches the exact source function")

    between = statements[origin_index + 1 : candidate_index]
    increments = sum(_pointer_increment(statement.normalized, pointer) for statement in between)
    source_index = _source_write_index(candidate.normalized, pointer)
    if source_index is None:
        return _rejected(pack, "exact source STORE offset is not statically recoverable")
    pointer_offset = int(capacity["capacity_bytes"]) - 1 + increments
    start_offset = pointer_offset + source_index
    end_offset_exclusive = start_offset + width
    if end_offset_exclusive <= int(capacity["capacity_bytes"]):
        return _rejected(pack, "derived exact STORE remains within the recovered object capacity")

    downstream: Mapping[str, Any] = {}
    if increments:
        downstream = _verify_downstream_store(
            campaign_root,
            pack,
            statements,
            candidate_index=candidate_index,
            origin_index=origin_index,
            pointer=pointer,
            object_name=object_name,
            capacity=capacity,
        )
        if not downstream.get("reachable_after_prior_write"):
            return _rejected(pack, "downstream STORE reachability is not proven")

    append_cause = _append_causal_operation(
        statements,
        origin_index=origin_index,
        pointer=pointer,
    )
    relation = "capacity-minus-one pathname receives slash and terminator without two-byte room"
    root_cause = _root_cause(
        pack,
        causal_operation=append_cause,
        object_identity=f"array:{object_name}:capacity:{capacity['capacity_bytes']}",
        defect_relation=relation,
    )
    evidence_refs = _unique_refs(
        [
            *(capacity.get("evidence_refs") or []),
            *(producer.get("evidence_refs") or []),
            *(entry.get("evidence_refs") or []),
            *(downstream.get("evidence_refs") or []),
        ]
    )
    proof = {
        **common,
        "rule_claim": relation,
        "producer": producer,
        "entry_reachability": entry,
        "pointer_increments": increments,
        "pointer_offset_bytes": pointer_offset,
        "source_store_index": source_index,
        "write_interval": {
            "start_offset": start_offset,
            "end_offset_exclusive": end_offset_exclusive,
            "capacity_bytes": capacity["capacity_bytes"],
            "overflow_bytes": end_offset_exclusive - int(capacity["capacity_bytes"]),
        },
        "downstream_reachability": downstream,
        "earliest_causal_operation": append_cause,
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "real_entry_reachability": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "maximum_length_feasible": True,
            "downstream_path": not increments or bool(downstream),
            "feasible_out_of_bounds": True,
            "attacker_or_boundary_control": True,
        },
        "supporting_evidence_refs": evidence_refs,
    }
    return VerifiedInvestigation(
        candidate_id=candidate_id,
        verified=True,
        decision="bug",
        basis="exact_source_feasible_violation",
        claim_kind="spatial_path",
        exact_operation=exact_operation,
        proof=proof,
        root_cause=root_cause,
    )


def split_c_statements(function_text: str) -> list[SourceStatement]:
    """Split a C function into semicolon and control-header statements.

    The splitter preserves source lines and braces while ignoring comment and
    quoted literal contents.  It is intentionally conservative: it keeps
    multi-line calls intact and emits control headers at their opening brace.
    """

    masked = _c_lexical_mask(function_text)
    statements: list[SourceStatement] = []
    start = 0
    depth = 0
    paren_depth = 0
    for index, char in enumerate(masked):
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        elif char == "{":
            segment = function_text[start:index].strip()
            if segment:
                statements.append(_source_statement(function_text, start, index, depth))
            depth += 1
            start = index + 1
        elif char == "}":
            segment = function_text[start:index].strip()
            if segment:
                statements.append(_source_statement(function_text, start, index, depth))
            depth = max(0, depth - 1)
            start = index + 1
        elif char == ";" and paren_depth == 0:
            statements.append(_source_statement(function_text, start, index + 1, depth))
            start = index + 1
    return [statement for statement in statements if statement.normalized]


def verify_source_entry_reachability(
    campaign_root: Path,
    pack: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Find a source call path from main or an explicitly registered callback."""

    operation = _object(pack.get("exact_operation"))
    operation_function = str(operation.get("function_address") or "").lower()
    exact_surfaces = [
        dict(surface)
        for surface in pack.get("entry_surfaces") or []
        if isinstance(surface, Mapping)
        and str(surface.get("function_address") or surface.get("address") or "").lower()
        == operation_function
    ]
    if exact_surfaces:
        return {
            "reachable": True,
            "basis": "frozen_entry_surface",
            "path": [str(_object(pack.get("source_context")).get("function") or "")],
            "surfaces": exact_surfaces,
            "evidence_refs": [],
        }

    functions, file_texts = _load_source_functions(campaign_root, pack)
    target = str(_object(pack.get("source_context")).get("function") or "")
    if target not in functions:
        return {"reachable": False, "reason": "target function absent from source tree"}
    graph, roots = _source_call_graph(functions, file_texts)
    queue: deque[tuple[str, list[str]]] = deque((root, [root]) for root in sorted(roots))
    visited: set[str] = set()
    found: list[str] = []
    while queue:
        node, path = queue.popleft()
        if node in visited:
            continue
        visited.add(node)
        if node == target:
            found = path
            break
        for successor in sorted(graph.get(node, set())):
            queue.append((successor, [*path, successor]))
    if not found:
        return {
            "reachable": False,
            "basis": "source_callback_call_graph",
            "target": target,
            "enumerated_roots": sorted(roots),
        }
    refs = _unique_refs(
        [
            _source_file_ref(campaign_root, functions[name][0].path)
            for name in found
            if name in functions
        ]
    )
    return {
        "reachable": True,
        "basis": "source_callback_call_graph",
        "path": found,
        "entry_kind": "main" if found[0] == "main" else "registered_callback",
        "enumerated_roots": sorted(roots),
        "evidence_refs": refs,
    }


def _load_source_functions(
    campaign_root: Path,
    pack: Mapping[str, Any],
) -> tuple[dict[str, list[SourceFunction]], dict[str, str]]:
    root = Path(campaign_root).resolve()
    tree = _object(pack.get("source_tree"))
    functions: dict[str, list[SourceFunction]] = {}
    texts: dict[str, str] = {}
    for row in tree.get("files") or []:
        if not isinstance(row, Mapping):
            continue
        relative = str(row.get("path") or "")
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise VerificationError("source-tree file escapes campaign root") from exc
        if not path.is_file() or sha256_file(path) != str(row.get("sha256") or ""):
            raise VerificationError(f"source-tree evidence changed: {relative}")
        text = path.read_text(encoding="utf-8")
        texts[relative] = text
        for function in _source_functions_in_file(text, relative):
            functions.setdefault(function.name, []).append(function)
    return functions, texts


def _source_functions_in_file(text: str, path: str) -> list[SourceFunction]:
    masked = _c_lexical_mask(text)
    result: list[SourceFunction] = []
    depth = 0
    index = 0
    controls = {"if", "for", "while", "switch", "sizeof"}
    while index < len(masked):
        char = masked[index]
        if char == "{" and depth == 0:
            boundary = max(masked.rfind(";", 0, index), masked.rfind("}", 0, index)) + 1
            header = masked[boundary:index]
            names = list(re.finditer(r"\b([A-Za-z_]\w*)\s*\(", header))
            name = names[-1].group(1) if names else ""
            close = _matching_c_brace(masked, index)
            if name and name not in controls and close is not None:
                header_start = boundary + len(header) - len(header.lstrip())
                raw = text[header_start : close + 1].strip() + "\n"
                result.append(
                    SourceFunction(
                        name=name,
                        path=path,
                        text=raw,
                        start_line=text.count("\n", 0, header_start) + 1,
                    )
                )
                index = close + 1
                continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        index += 1
    return result


def _matching_c_brace(masked: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _source_call_graph(
    functions: Mapping[str, Sequence[SourceFunction]],
    file_texts: Mapping[str, str],
) -> tuple[dict[str, set[str]], set[str]]:
    known = set(functions)
    graph: dict[str, set[str]] = {name: set() for name in known}
    roots: set[str] = {"main"} if "main" in known else set()
    tables: dict[str, set[str]] = {}
    for text in file_texts.values():
        masked = _c_lexical_mask(text)
        for match in re.finditer(
            r"\b([A-Za-z_]\w*)\s*\[\s*\]\s*=\s*\{(?P<body>.*?)\}\s*;",
            masked,
            re.DOTALL,
        ):
            members = {
                item.group(1)
                for item in re.finditer(r"=\s*&?\s*([A-Za-z_]\w*)", match.group("body"))
                if item.group(1) in known
            }
            if members:
                tables[match.group(1)] = members
        for match in re.finditer(
            r"(?:->|\.)\s*[A-Za-z_]\w*\s*=\s*&?\s*([A-Za-z_]\w*)",
            masked,
        ):
            if match.group(1) in known:
                roots.add(match.group(1))
        for match in re.finditer(
            r"\.\s*[A-Za-z_]\w*\s*=\s*&?\s*([A-Za-z_]\w*)",
            masked,
        ):
            if match.group(1) in known:
                roots.add(match.group(1))

    ignored = {"if", "for", "while", "switch", "return", "sizeof"}
    for name, variants in functions.items():
        for function in variants:
            masked = _c_lexical_mask(function.text)
            for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", masked):
                called = match.group(1)
                if called in known and called not in ignored and called != name:
                    graph[name].add(called)
            for table, members in tables.items():
                if re.search(rf"\b{re.escape(table)}\s*\[[^\]]+\]\s*\(", masked):
                    graph[name].update(members)
    return graph, roots


def _last_length_pointer_origin(
    statements: Sequence[SourceStatement],
    pointer: str,
) -> tuple[int, SourceStatement, str] | None:
    result = None
    pattern = re.compile(
        rf"\b{re.escape(pointer)}\s*=\s*&?\s*(?P<object>[A-Za-z_]\w*)\s*"
        rf"\+\s*strlen\s*\(\s*(?P=object)\s*\)"
    )
    for index, statement in enumerate(statements):
        match = pattern.search(statement.normalized)
        if match:
            result = (index, statement, match.group("object"))
    return result


def _resolve_object_capacity(
    campaign_root: Path,
    pack: Mapping[str, Any],
    object_name: str,
) -> Mapping[str, Any]:
    root = Path(campaign_root).resolve()
    source_path = root / str(_object(pack.get("source_context")).get("path") or "")
    text = source_path.read_text(encoding="utf-8")
    declaration = re.search(
        rf"\b(?:unsigned\s+)?char\s+{re.escape(object_name)}\s*\[\s*(?P<size>[^\]]+)\s*\]",
        _c_lexical_mask(text),
    )
    if declaration is None:
        raise VerificationError(f"cannot recover a byte-array declaration for {object_name}")
    expression = declaration.group("size").strip()
    value = _integer_constant(expression)
    if value is None and re.fullmatch(r"[A-Za-z_]\w*", expression):
        value = _source_macro_integer(pack, root, expression)
    refs: list[Mapping[str, str]] = [_source_file_ref(root, str(source_path.relative_to(root)))]
    symbol_fact: Mapping[str, Any] = {}
    if value is None:
        symbol_fact = _reference_object_symbol(root, pack, object_name)
        value = int(symbol_fact.get("size_bytes") or 0)
        refs.extend(symbol_fact.get("evidence_refs") or [])
    if value <= 0:
        raise VerificationError(f"cannot resolve a positive capacity for {object_name}")
    return {
        "object": object_name,
        "capacity_bytes": value,
        "declaration_expression": expression,
        "basis": "source_integer_extent" if not symbol_fact else "reference_binary_symbol_size",
        "symbol": symbol_fact,
        "evidence_refs": _unique_refs(refs),
    }


def _integer_constant(expression: str) -> int | None:
    try:
        return int(expression, 0)
    except ValueError:
        return None


def _source_macro_integer(pack: Mapping[str, Any], root: Path, name: str) -> int | None:
    for row in _object(pack.get("source_tree")).get("files") or []:
        if not isinstance(row, Mapping):
            continue
        text = (root / str(row.get("path") or "")).read_text(encoding="utf-8")
        match = re.search(
            rf"^\s*#\s*define\s+{re.escape(name)}\s+(0[xX][0-9A-Fa-f]+|\d+)\b",
            text,
            re.MULTILINE,
        )
        if match:
            return int(match.group(1), 0)
    return None


def _reference_object_symbol(
    root: Path,
    pack: Mapping[str, Any],
    object_name: str,
) -> Mapping[str, Any]:
    mapping_ref = next(
        (
            row
            for row in pack.get("input_refs") or []
            if isinstance(row, Mapping) and row.get("kind") == "reference_build_mapping"
        ),
        None,
    )
    if not isinstance(mapping_ref, Mapping):
        raise VerificationError("pack has no reference-build mapping")
    mapping_path = root / str(mapping_ref.get("path") or "")
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    reference = _object(mapping.get("reference_binary"))
    binary_path = root / str(reference.get("path") or "")
    if not binary_path.is_file() or sha256_file(binary_path) != str(reference.get("sha256") or ""):
        raise VerificationError("symbol-rich reference binary hash changed")
    if not mapping.get("code_bytes_match") or not mapping.get("direct_source_mapping_allowed"):
        raise VerificationError("reference binary is not exact-code bound to the frozen binary")
    try:
        completed = subprocess.run(
            ["nm", "-S", "--defined-only", str(binary_path)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VerificationError(f"cannot inspect reference symbols: {exc}") from exc
    symbols: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        match = re.match(
            r"^\s*([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([A-Za-z])\s+(.+?)\s*$",
            line,
        )
        if match:
            symbols.append(
                {
                    "address": int(match.group(1), 16),
                    "size_bytes": int(match.group(2), 16),
                    "type": match.group(3),
                    "name": match.group(4),
                }
            )
    matches = [
        item
        for item in symbols
        if item["name"] == object_name or re.fullmatch(rf"{re.escape(object_name)}\.\d+", item["name"])
    ]
    if len(matches) != 1:
        raise VerificationError(
            f"reference binary has {len(matches)} unambiguous symbols for {object_name}"
        )
    selected = matches[0]
    later = sorted(
        (item for item in symbols if item["address"] >= selected["address"] + selected["size_bytes"]),
        key=lambda item: item["address"],
    )
    next_symbol = later[0] if later else {}
    refs = [
        {
            "path": str(mapping_path.relative_to(root)),
            "sha256": sha256_file(mapping_path),
            "kind": "reference_build_mapping",
        },
        {
            "path": str(binary_path.relative_to(root)),
            "sha256": sha256_file(binary_path),
            "kind": "symbol_rich_reference_binary",
        },
    ]
    return {
        "name": selected["name"],
        "address": hex(selected["address"]),
        "size_bytes": selected["size_bytes"],
        "next_symbol": {
            **next_symbol,
            "address": hex(next_symbol["address"]) if next_symbol else "",
        },
        "nm_stdout_sha256": hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
        "evidence_refs": refs,
    }


def _find_capacity_guard(
    statements: Sequence[SourceStatement],
    *,
    pointer: str,
    object_name: str,
    required_width: int,
) -> Mapping[str, Any] | None:
    for index, statement in enumerate(statements):
        normalized = statement.normalized
        if not normalized.startswith("if"):
            continue
        if not re.search(
            rf"\b{re.escape(pointer)}\s*-\s*{re.escape(object_name)}\b", normalized
        ):
            continue
        if not re.search(rf"sizeof\s*\(\s*{re.escape(object_name)}\s*\)", normalized):
            continue
        addition = re.search(r"\+\s*(\d+)\s*(?:>=|>)", normalized)
        if addition is None or int(addition.group(1)) < required_width:
            continue
        terminating = bool(re.search(r"\b(return|goto|break|continue)\b", normalized))
        if not terminating and index + 1 < len(statements):
            following = statements[index + 1]
            terminating = (
                following.brace_depth > statement.brace_depth
                and bool(re.search(r"\b(return|goto|break|continue)\b", following.normalized))
            )
        if terminating:
            return {
                "condition_statement": statement.to_dict(),
                "required_width": required_width,
                "termination_proven": True,
            }
    return None


def _capacity_length_producer(
    campaign_root: Path,
    pack: Mapping[str, Any],
    statements: Sequence[SourceStatement],
    *,
    object_name: str,
) -> Mapping[str, Any]:
    functions, _texts = _load_source_functions(campaign_root, pack)
    target_name = str(_object(pack.get("source_context")).get("function") or "")
    target_function = functions.get(target_name, [])
    target_parameters = set(_function_parameters(target_function[0])) if target_function else set()
    for statement_index, statement in enumerate(statements):
        for call_name, arguments in _calls_in_text(statement.text):
            object_positions = [
                index
                for index, argument in enumerate(arguments)
                if re.search(rf"\b{re.escape(object_name)}\b", argument)
            ]
            if not object_positions:
                continue
            contract: Mapping[str, Any] = {}
            input_expression = arguments[0] if arguments else ""
            refs: list[Mapping[str, str]] = []
            if call_name == "realpath" and object_positions == [1]:
                contract = {"api": "realpath", "output_argument_index": 1, "wrapper": ""}
            else:
                for wrapper in functions.get(call_name, []):
                    parameters = _function_parameters(wrapper)
                    position = object_positions[0]
                    if position >= len(parameters):
                        continue
                    output_parameter = parameters[position]
                    realpath_calls = [
                        args
                        for name, args in _calls_in_text(wrapper.text)
                        if name == "realpath" and len(args) > 1
                    ]
                    if any(
                        re.search(rf"\b{re.escape(output_parameter)}\b", args[1])
                        for args in realpath_calls
                    ):
                        contract = {
                            "api": "realpath",
                            "output_argument_index": position,
                            "wrapper": call_name,
                            "wrapper_output_parameter": output_parameter,
                            "wrapper_branch_feasible": True,
                        }
                        refs.append(_source_file_ref(campaign_root, wrapper.path))
                        break
            if not contract:
                continue
            attacker_influence = any(
                re.search(rf"\b{re.escape(parameter)}\b", input_expression)
                for parameter in target_parameters
            )
            dataflow_statement: Mapping[str, Any] = {}
            if not attacker_influence:
                for prior in statements[:statement_index]:
                    if not re.search(rf"\b{re.escape(input_expression.strip('& '))}\b", prior.normalized):
                        continue
                    if any(
                        re.search(rf"\b{re.escape(parameter)}\b", prior.normalized)
                        for parameter in target_parameters
                    ):
                        attacker_influence = True
                        dataflow_statement = prior.to_dict()
                        break
            source_path = str(_object(pack.get("source_context")).get("path") or "")
            refs.append(_source_file_ref(campaign_root, source_path))
            return {
                "maximum_length_reachable": attacker_influence,
                "call_statement": statement.to_dict(),
                "call": call_name,
                "input_expression": input_expression,
                "attacker_controlled_input": attacker_influence,
                "input_dataflow_statement": dataflow_statement,
                "contract": {
                    **contract,
                    "contract_id": "posix_realpath_c_string_v1",
                    "maximum_string_length": "capacity_bytes - 1",
                    "maximum_length_path_feasible": True,
                    "input_trailing_slash_independent_of_canonical_output": True,
                },
                "evidence_refs": _unique_refs(refs),
            }
    return {"maximum_length_reachable": False}


def _function_parameters(function: SourceFunction) -> list[str]:
    header = function.text.split("{", 1)[0]
    start = header.find("(")
    end = header.rfind(")")
    if start < 0 or end <= start:
        return []
    result = []
    for parameter in _split_c_arguments(header[start + 1 : end]):
        names = re.findall(r"\b([A-Za-z_]\w*)\b", parameter)
        if names and names[-1] != "void":
            result.append(names[-1])
    return result


def _calls_in_text(text: str) -> list[tuple[str, list[str]]]:
    masked = _c_lexical_mask(text)
    calls: list[tuple[str, list[str]]] = []
    ignored = {"if", "for", "while", "switch", "sizeof", "return"}
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", masked):
        name = match.group(1)
        if name in ignored:
            continue
        opening = masked.find("(", match.start())
        closing = _matching_paren(masked, opening)
        if closing is None:
            continue
        calls.append((name, _split_c_arguments(text[opening + 1 : closing])))
    return calls


def _matching_paren(masked: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "(":
            depth += 1
        elif masked[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_c_arguments(text: str) -> list[str]:
    masked = _c_lexical_mask(text)
    result: list[str] = []
    start = 0
    parens = brackets = braces = 0
    for index, char in enumerate(masked):
        if char == "(":
            parens += 1
        elif char == ")":
            parens = max(0, parens - 1)
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets = max(0, brackets - 1)
        elif char == "{":
            braces += 1
        elif char == "}":
            braces = max(0, braces - 1)
        elif char == "," and not (parens or brackets or braces):
            result.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        result.append(tail)
    return result


def _pointer_increment(statement: str, pointer: str) -> int:
    if re.search(rf"(?:\+\+\s*{re.escape(pointer)}\b|\b{re.escape(pointer)}\s*\+\+)", statement):
        return 1
    match = re.search(rf"\b{re.escape(pointer)}\s*\+=\s*(\d+)\b", statement)
    return int(match.group(1)) if match else 0


def _source_write_index(statement: str, pointer: str) -> int | None:
    indexed = re.search(rf"\b{re.escape(pointer)}\s*\[\s*(\d+)\s*\]\s*=", statement)
    if indexed:
        return int(indexed.group(1))
    if re.search(rf"\*\s*{re.escape(pointer)}\s*=", statement):
        return 0
    return None


def _verify_downstream_store(
    campaign_root: Path,
    pack: Mapping[str, Any],
    statements: Sequence[SourceStatement],
    *,
    candidate_index: int,
    origin_index: int,
    pointer: str,
    object_name: str,
    capacity: Mapping[str, Any],
) -> Mapping[str, Any]:
    before = statements[origin_index + 1 : candidate_index]
    loop_match = None
    loop_statement = None
    for statement in before:
        match = re.search(
            r"\blist_for_each_entry\s*\(\s*(?P<item>[A-Za-z_]\w*)\s*,\s*&\s*(?P<list>[A-Za-z_]\w*)",
            statement.normalized,
        )
        if match:
            loop_match = match
            loop_statement = statement
    if loop_match is None or loop_statement is None:
        return {"reachable_after_prior_write": False, "reason": "no finite list loop dominates STORE"}
    item = loop_match.group("item")
    collection = loop_match.group("list")
    length_statement = next(
        (
            statement
            for statement in before
            if re.search(
                rf"\b(?P<len>[A-Za-z_]\w*)\s*=\s*{re.escape(object_name)}\s*\+\s*sizeof\s*\(\s*{re.escape(object_name)}\s*\)\s*-\s*{re.escape(pointer)}\s*-\s*1",
                statement.normalized,
            )
        ),
        None,
    )
    if length_statement is None:
        return {"reachable_after_prior_write": False, "reason": "remaining-length relation absent"}
    length_name = re.search(r"\b([A-Za-z_]\w*)\s*=", length_statement.normalized).group(1)  # type: ignore[union-attr]
    comparison = next(
        (
            statement
            for statement in before
            if re.search(
                rf"strlen\s*\(\s*{re.escape(item)}\s*->\s*[A-Za-z_]\w*\s*\)\s*>\s*{re.escape(length_name)}\b",
                statement.normalized,
            )
        ),
        None,
    )
    copy = next(
        (
            statement
            for statement in before
            if re.search(
                rf"\bstrcpy\s*\(\s*{re.escape(pointer)}\s*,\s*{re.escape(item)}\s*->",
                statement.normalized,
            )
        ),
        None,
    )
    failing_call = next(
        (
            statement
            for statement in before
            if re.search(rf"\bstat\s*\(\s*{re.escape(object_name)}\b", statement.normalized)
        ),
        None,
    )
    if comparison is None or copy is None or failing_call is None:
        return {"reachable_after_prior_write": False, "reason": "loop copy/failure path is incomplete"}
    initializer = _nonempty_collection_initializer(campaign_root, pack, collection)
    if not initializer.get("nonempty"):
        return {"reachable_after_prior_write": False, "reason": "collection non-emptiness is unproven"}
    symbol = _object(capacity.get("symbol"))
    next_symbol = _object(symbol.get("next_symbol"))
    try:
        object_end = int(str(symbol.get("address") or "0"), 16) + int(symbol.get("size_bytes") or 0)
        next_address = int(str(next_symbol.get("address") or "0"), 16)
    except ValueError:
        object_end = next_address = 0
    adjacent_writable = object_end > 0 and object_end == next_address and int(next_symbol.get("size_bytes") or 0) > 1
    if not adjacent_writable:
        return {"reachable_after_prior_write": False, "reason": "prior one-past write may stop before STORE"}
    refs = _unique_refs(
        [
            *(capacity.get("evidence_refs") or []),
            *(initializer.get("evidence_refs") or []),
        ]
    )
    return {
        "reachable_after_prior_write": True,
        "loop_statement": loop_statement.to_dict(),
        "collection": collection,
        "collection_initializer": initializer,
        "remaining_length_statement": length_statement.to_dict(),
        "remaining_length_at_capacity_pointer": -1,
        "comparison_statement": comparison.to_dict(),
        "signed_to_unsigned_promotion": "strlen size_t comparison converts -1 to SIZE_MAX",
        "copy_statement": copy.to_dict(),
        "failure_statement": failing_call.to_dict(),
        "failure_contract": "pathname longer than PATH_MAX makes stat fail before cleanup STORE",
        "adjacent_writable_symbol": next_symbol,
        "evidence_refs": refs,
    }


def _nonempty_collection_initializer(
    campaign_root: Path,
    pack: Mapping[str, Any],
    collection: str,
) -> Mapping[str, Any]:
    functions, texts = _load_source_functions(campaign_root, pack)
    graph, _roots = _source_call_graph(functions, texts)
    add_functions = [
        function
        for variants in functions.values()
        for function in variants
        if re.search(
            rf"\blist_add(?:_tail)?\s*\([^;]*&\s*{re.escape(collection)}\b",
            _c_lexical_mask(function.text),
        )
    ]
    for add_function in add_functions:
        call_pattern = re.compile(
            rf"\b{re.escape(add_function.name)}\s*\(\s*\"(?P<value>[^\"]+)\""
        )
        for caller_name, variants in functions.items():
            for caller in variants:
                literal = call_pattern.search(caller.text)
                if literal is None:
                    continue
                main_path = _graph_path(graph, "main", caller_name)
                if caller_name != "main" and not main_path:
                    continue
                refs = _unique_refs(
                    [
                        _source_file_ref(campaign_root, add_function.path),
                        _source_file_ref(campaign_root, caller.path),
                    ]
                )
                return {
                    "nonempty": True,
                    "collection_add_function": add_function.name,
                    "literal_value": literal.group("value"),
                    "initializer_function": caller_name,
                    "main_call_path": main_path or ["main"],
                    "evidence_refs": refs,
                }
    return {"nonempty": False}


def _graph_path(
    graph: Mapping[str, set[str]],
    start: str,
    target: str,
) -> list[str]:
    if start not in graph:
        return []
    queue: deque[tuple[str, list[str]]] = deque([(start, [start])])
    visited: set[str] = set()
    while queue:
        node, path = queue.popleft()
        if node in visited:
            continue
        visited.add(node)
        if node == target:
            return path
        for successor in sorted(graph.get(node, set())):
            queue.append((successor, [*path, successor]))
    return []


def _append_causal_operation(
    statements: Sequence[SourceStatement],
    *,
    origin_index: int,
    pointer: str,
) -> Mapping[str, Any]:
    writes: list[str] = []
    increment = ""
    guard = ""
    for statement in statements[origin_index + 1 :]:
        if not guard and re.search(rf"\b{re.escape(pointer)}\s*\[\s*-\s*1\s*\]", statement.normalized):
            guard = statement.normalized
        if _source_write_index(statement.normalized, pointer) is not None:
            writes.append(statement.normalized)
        if _pointer_increment(statement.normalized, pointer):
            increment = statement.normalized
            break
    return {
        "kind": "length_derived_two_byte_append",
        "pointer_origin_normalized": statements[origin_index].normalized,
        "append_guard_normalized": guard,
        "append_writes_normalized": writes[:2],
        "pointer_increment_normalized": increment,
    }


def _source_file_ref(campaign_root: Path, relative_path: str) -> Mapping[str, str]:
    root = Path(campaign_root).resolve()
    path = (root / relative_path).resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise VerificationError("supporting source file escapes campaign root") from exc
    if not path.is_file():
        raise VerificationError(f"supporting source file is absent: {relative_path}")
    return {
        "path": str(relative),
        "sha256": sha256_file(path),
        "kind": "source_tree_file",
    }


def _unique_refs(references: Sequence[Mapping[str, Any]]) -> list[Mapping[str, str]]:
    result: list[Mapping[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for reference in references:
        row = {
            "path": str(reference.get("path") or ""),
            "sha256": str(reference.get("sha256") or ""),
            "kind": str(reference.get("kind") or ""),
        }
        key = (row["path"], row["sha256"], row["kind"])
        if not row["path"] or not row["sha256"] or key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result


def _source_statement(text: str, start: int, end: int, depth: int) -> SourceStatement:
    segment_mask = _c_lexical_mask(text[start:end])
    first_code = next(
        (index for index, char in enumerate(segment_mask) if not char.isspace()),
        len(segment_mask),
    )
    start += first_code
    raw = text[start:end].strip()
    normalized = " ".join(_c_lexical_mask(raw).split())
    return SourceStatement(
        text=raw,
        normalized=normalized,
        start_line=text.count("\n", 0, start) + 1,
        end_line=text.count("\n", 0, end) + 1,
        byte_start=start,
        byte_end=end,
        brace_depth=depth,
    )


def _statement_for_line(
    statements: Sequence[SourceStatement],
    line_number: int,
) -> SourceStatement:
    matches = [
        statement
        for statement in statements
        if statement.start_line <= line_number <= statement.end_line
    ]
    if len(matches) != 1:
        raise VerificationError(
            f"exact source line maps to {len(matches)} statements instead of one"
        )
    return matches[0]


def _candidate_pointer(statement: str) -> str:
    arrow = re.search(r"\b([A-Za-z_]\w*)\s*->", statement)
    if arrow:
        return arrow.group(1)
    indexed = re.search(r"\b([A-Za-z_]\w*)\s*\[", statement)
    if indexed:
        return indexed.group(1)
    unary = re.search(r"(?:^|[=(,])\s*\*\s*([A-Za-z_]\w*)\b", statement)
    return unary.group(1) if unary else ""


def _nullable_assignment(statement: str, pointer: str) -> str | None:
    match = re.search(
        rf"\b{re.escape(pointer)}\s*=\s*(?P<allocator>[A-Za-z_]\w*)\s*\(",
        statement,
    )
    if match is None:
        return None
    allocator = match.group("allocator")
    return allocator if allocator in NULLABLE_ALLOCATORS else None


def _dereferences_pointer(statement: str, pointer: str) -> bool:
    escaped = re.escape(pointer)
    return bool(
        re.search(rf"\b{escaped}\s*->", statement)
        or re.search(rf"\b{escaped}\s*\[", statement)
        or re.search(rf"(?:^|[=(,&])\s*\*\s*{escaped}\b", statement)
    )


def _is_null_test(statement: str, pointer: str) -> bool:
    escaped = re.escape(pointer)
    return bool(
        re.search(rf"!\s*{escaped}\b", statement)
        or re.search(rf"\b{escaped}\s*==\s*(?:NULL|0)\b", statement)
        or re.search(rf"(?:NULL|0)\s*==\s*{escaped}\b", statement)
    )


def _terminating_null_guard(statement: str, pointer: str) -> bool:
    if not _is_null_test(statement, pointer):
        return False
    return bool(re.search(r"\b(return|goto|break|continue|exit|_exit|abort)\b", statement))


def _nearby_null_defect(
    pack: Mapping[str, Any],
    pointer: str,
    allocator: str,
    origin: SourceStatement,
    earliest: SourceStatement,
) -> Mapping[str, Any]:
    source = _object(pack.get("source_context"))
    relation = "unchecked nullable allocation reaches an earlier mandatory dereference"
    identity = _root_cause(
        pack,
        causal_operation={
            "source_function_sha256": str(source.get("function_sha256") or ""),
            "origin_normalized": origin.normalized,
        },
        object_identity=f"pointer:{pointer}",
        defect_relation=relation,
    )
    return {
        "nearby_defect_id": identity["root_cause_id"],
        "kind": "unchecked_allocation",
        "status": "source_proven_nearby_defect",
        "candidate_replacement_forbidden": True,
        "pointer": pointer,
        "allocator": allocator,
        "origin_statement": origin.to_dict(),
        "earliest_fault_statement": earliest.to_dict(),
        "root_cause": identity,
    }


def _root_cause(
    pack: Mapping[str, Any],
    *,
    causal_operation: Mapping[str, Any],
    object_identity: str,
    defect_relation: str,
) -> Mapping[str, Any]:
    payload = {
        "binary_sha256": _frozen_binary_hash(pack),
        "source_function_sha256": str(
            _object(pack.get("source_context")).get("function_sha256") or ""
        ),
        "causal_operation": causal_operation,
        "object_identity": object_identity,
        "defect_relation": defect_relation,
    }
    digest = hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {"root_cause_id": digest[:24], **payload}


def _frozen_binary_hash(pack: Mapping[str, Any]) -> str:
    for reference in pack.get("input_refs") or []:
        if isinstance(reference, Mapping) and reference.get("kind") == "frozen_binary":
            return str(reference.get("sha256") or "")
    return ""


def _verify_exact_operation(pack: Mapping[str, Any], proposed: Mapping[str, Any]) -> None:
    actual = _object(pack.get("exact_operation"))
    proposed_address = str(proposed.get("address") or "").lower()
    actual_address = str(actual.get("address") or "").lower()
    if proposed_address != actual_address:
        raise VerificationError("proposal exact operation address changed")
    proposed_pcode = str(proposed.get("pcode") or "").upper()
    actual_pcode = str(actual.get("pcode") or "").upper()
    if proposed_pcode != actual_pcode:
        raise VerificationError("proposal exact operation p-code changed")


def _operation_identity(pack: Mapping[str, Any]) -> Mapping[str, Any]:
    operation = _object(pack.get("exact_operation"))
    return {
        "address": str(operation.get("address") or ""),
        "pcode": str(operation.get("pcode") or ""),
        "width_bytes": int(operation.get("width_bytes") or 0),
        "function_address": str(operation.get("function_address") or ""),
    }


def _rejected(
    pack: Mapping[str, Any],
    reason: str,
    *,
    proof: Mapping[str, Any] | None = None,
) -> VerifiedInvestigation:
    return VerifiedInvestigation(
        candidate_id=str(pack.get("candidate_id") or ""),
        verified=False,
        claim_kind="",
        exact_operation=_operation_identity(pack),
        proof=dict(proof or {}),
        rejection_reason=reason,
    )


def _c_lexical_mask(text: str) -> str:
    result = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                result[index] = result[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == "/" and nxt == "*":
                result[index] = result[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char in {'"', "'"}:
                quote = char
                result[index] = " "
                state = "quoted"
                index += 1
                continue
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                result[index] = " "
            index += 1
            continue
        elif state == "block_comment":
            if char == "*" and nxt == "/":
                result[index] = result[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                result[index] = " "
            index += 1
            continue
        elif state == "quoted":
            if char == "\\" and nxt:
                result[index] = result[index + 1] = " "
                index += 2
                continue
            if char == quote:
                result[index] = " "
                state = "code"
            elif char != "\n":
                result[index] = " "
            index += 1
            continue
        index += 1
    return "".join(result)


def _object(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _relative(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path.resolve())
