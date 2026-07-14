"""Deterministic fact enrichment for unresolved memory-write candidates.

This module is intentionally conservative.  It extracts small, JSON-friendly
facts from nearby decompiled C text and proves safety only for exact local
relations that can be checked with integer arithmetic.
"""

from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_INT_RE = re.compile(r"[-+]?(?:0x[0-9a-fA-F]+|\d+)")
_REJECT_ACTION_RE = re.compile(r"\b(?:return|goto|break|continue|exit\s*\()\b")


@dataclass(frozen=True)
class LinearExpr:
    symbol: str = ""
    scale: int = 0
    constant: int = 0

    @property
    def is_constant(self) -> bool:
        return not self.symbol


@dataclass(frozen=True)
class AffineExpr:
    """A deterministic integer constant plus coefficients for named symbols."""

    constant: int = 0
    coefficients: tuple[tuple[str, int], ...] = ()

    @classmethod
    def symbol(cls, name: str) -> "AffineExpr":
        return cls(0, ((name, 1),))

    def _mapping(self) -> dict[str, int]:
        return {name: value for name, value in self.coefficients if value}

    @classmethod
    def _from_parts(cls, constant: int, coefficients: Mapping[str, int]) -> "AffineExpr":
        return cls(int(constant), tuple(sorted((name, int(value)) for name, value in coefficients.items() if value)))

    def add(self, other: "AffineExpr") -> "AffineExpr":
        values = self._mapping()
        for name, value in other.coefficients:
            values[name] = values.get(name, 0) + value
        return self._from_parts(self.constant + other.constant, values)

    def subtract(self, other: "AffineExpr") -> "AffineExpr":
        return self.add(other.multiply(-1))

    def multiply(self, value: int) -> "AffineExpr":
        return self._from_parts(self.constant * value, {name: coefficient * value for name, coefficient in self.coefficients})

    def to_dict(self) -> dict[str, Any]:
        return {
            "constant": self.constant,
            "coefficients": {name: value for name, value in self.coefficients},
            "expression": str(self),
        }

    def __str__(self) -> str:
        terms: list[str] = []
        for name, coefficient in self.coefficients:
            if coefficient == 1:
                term = name
            elif coefficient == -1:
                term = f"-{name}"
            else:
                term = f"{coefficient}*{name}"
            terms.append(term)
        if self.constant or not terms:
            terms.append(str(self.constant))
        return " + ".join(terms).replace("+ -", "- ")


def parse_affine_expr(expr: str, values: Mapping[str, AffineExpr] | None = None) -> Optional[AffineExpr]:
    """Parse constants, symbols, signs, +/- and multiplication by constants."""

    cleaned = _normalize_expr(expr)
    if not cleaned or cleaned.lower() in {"unknown", "unbounded"}:
        return None
    try:
        tree = ast.parse(cleaned, mode="eval")
    except (SyntaxError, ValueError):
        return None
    bindings = values or {}

    def visit(node: ast.AST) -> AffineExpr:
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            return AffineExpr(constant=int(node.value))
        if isinstance(node, ast.Name):
            return bindings.get(node.id, AffineExpr.symbol(node.id))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            value = visit(node.operand)
            return value if isinstance(node.op, ast.UAdd) else value.multiply(-1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
            left, right = visit(node.left), visit(node.right)
            return left.add(right) if isinstance(node.op, ast.Add) else left.subtract(right)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            left, right = visit(node.left), visit(node.right)
            if not left.coefficients:
                return right.multiply(left.constant)
            if not right.coefficients:
                return left.multiply(right.constant)
            raise ValueError("nonlinear expression")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "strlen" and len(node.args) == 1:
            argument = ast.unparse(node.args[0]).strip()
            return AffineExpr.symbol(f"strlen({argument})")
        raise ValueError("unsupported affine expression")

    try:
        return visit(tree.body)
    except (TypeError, ValueError):
        return None


@dataclass
class _RelationalState:
    values: dict[str, AffineExpr] = field(default_factory=dict)
    allocations: dict[str, tuple[AffineExpr, int, str]] = field(default_factory=dict)
    nonnegative_symbols: set[str] = field(default_factory=set)
    supporting_source_lines: list[str] = field(default_factory=list)
    terminated: bool = False
    unknown_reason: str = ""
    write: tuple[AffineExpr, AffineExpr, AffineExpr, int, str] | None = None
    relevant_names: set[str] = field(default_factory=set)

    def clone(self) -> "_RelationalState":
        return _RelationalState(
            values=dict(self.values),
            allocations=dict(self.allocations),
            nonnegative_symbols=set(self.nonnegative_symbols),
            supporting_source_lines=list(self.supporting_source_lines),
            terminated=self.terminated,
            unknown_reason=self.unknown_reason,
            write=self.write,
            relevant_names=set(self.relevant_names),
        )


def build_enriched_facts(
    candidate: Mapping[str, Any],
    *,
    source_text: str = "",
    excerpt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build optional deterministic facts for evidence packs and filtering."""
    line_records = _line_records(source_text, excerpt)
    candidate_line = _safe_int(candidate.get("line_number"))
    if candidate_line <= 0 and line_records:
        candidate_line = line_records[-1][0]
    target = str(candidate.get("target_buffer") or "")
    capacity = _safe_int(candidate.get("capacity_bytes"))
    width = _write_width(candidate)
    offset_expr = _expr(candidate.get("offset_expr") or "0")
    size_expr = _expr(candidate.get("write_size_expr") or "")
    identifiers = _unique(_identifiers(offset_expr) + _identifiers(size_expr))

    guard_table: list[dict[str, Any]] = []
    reject_guard_table: list[dict[str, Any]] = []
    range_table: list[dict[str, Any]] = []
    loop_summary: list[dict[str, Any]] = []

    for line_number, line in line_records:
        if candidate_line and line_number > candidate_line:
            continue
        if candidate_line and line_number < max(1, candidate_line - 20):
            continue
        stripped = line.strip()
        if not stripped:
            continue
        loop = _parse_for_loop(stripped, candidate)
        if loop:
            loop_summary.append(loop)
            guard_table.append(
                {
                    "source": "counted_loop" if loop.get("kind") == "counted_loop" else "pointer_loop",
                    "line_number": line_number,
                    "text": stripped,
                    "accepted": bool(loop.get("exact")),
                }
            )
            range_table.extend(_ranges_from_loop(loop, line_number, stripped))
        condition = _control_condition(stripped)
        if not condition:
            continue
        is_reject = _is_reject_guard(line_records, line_number)
        guard_entry = {
            "source": "reject_guard" if is_reject else "dominating_guard",
            "line_number": line_number,
            "text": stripped,
            "condition": condition,
            "accepted": "unknown" if is_reject else True,
        }
        if is_reject:
            reject_guard_table.append(guard_entry)
            range_table.extend(_ranges_from_reject_condition(condition, line_number, stripped, candidate))
        else:
            guard_table.append(guard_entry)
            range_table.extend(_ranges_from_positive_condition(condition, line_number, stripped, candidate))

    for item in candidate.get("guard_evidence", []) or []:
        text = str(item)
        guard_table.append(
            {
                "source": "candidate_guard_evidence",
                "line_number": 0,
                "text": text,
                "condition": _control_condition(text) or text,
                "accepted": True,
            }
        )
        range_table.extend(_ranges_from_positive_condition(text, 0, text, candidate))

    append_length_table = _append_length_facts(candidate, line_records, candidate_line)
    allocation_table = _allocation_relation_facts(candidate, line_records, candidate_line)
    def_use_table = _def_use_facts(identifiers, line_records, candidate_line)
    alias_history = _alias_history_facts(candidate, line_records, candidate_line, loop_summary)
    pcode_slice = {
        "operation_address": candidate.get("operation_address", ""),
        "evidence_sources": list(candidate.get("evidence_sources", []) or []),
        "available": bool(candidate.get("operation_address")),
        "line_text": candidate.get("line_text", ""),
    }

    facts: dict[str, Any] = {
        "guard_table": _dedupe_dicts(guard_table)[:40],
        "range_table": _dedupe_dicts(range_table)[:40],
        "reject_guard_table": _dedupe_dicts(reject_guard_table)[:20],
        "loop_summary": _dedupe_dicts(loop_summary)[:20],
        "append_length_table": _dedupe_dicts(append_length_table)[:20],
        "allocation_table": _dedupe_dicts(allocation_table)[:20],
        "def_use_table": _dedupe_dicts(def_use_table)[:40],
        "alias_history": _dedupe_dicts(alias_history)[:30],
        "pcode_slice": pcode_slice,
    }
    facts["relational_safety_proof"] = prove_relational_allocation_write(
        candidate,
        source_text=source_text,
        excerpt=excerpt,
    )
    facts["safety_result"] = safety_result_for_candidate(candidate, facts)
    facts["range_summary"] = _range_summary(facts["range_table"])
    facts["expression_summary"] = {
        "offset": _linear_expr_to_dict(parse_linear_expr(offset_expr)),
        "write_size": _linear_expr_to_dict(parse_linear_expr(size_expr)),
        "capacity_bytes": capacity,
        "write_width": width,
        "target_buffer": target,
    }
    return facts


def safety_result_for_candidate(
    candidate: Mapping[str, Any],
    facts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a conservative safety verdict for one unresolved candidate."""
    facts = facts or {}
    relational = facts.get("relational_safety_proof")
    if isinstance(relational, Mapping) and relational.get("status") == "proven_safe":
        return _safety(
            "proven_safe",
            str(relational.get("reason") or "allocation/write relation is safe on every recovered path"),
            evidence=[str(item) for item in relational.get("supporting_source_lines", []) or []],
        )
    relation = str(candidate.get("write_relation") or "")
    if relation not in {
        "symbolic_offset",
        "symbolic_read_offset",
        "symbolic_size",
        "iterated_alias_unproven",
        "append_length_unknown",
        "unbounded",
    }:
        return _safety("unknown", "relation is not handled by targeted enrichment")
    if relation == "symbolic_size":
        allocation_safety = _allocation_relation_safety(candidate, facts)
        if allocation_safety.get("status") == "proven_safe":
            return allocation_safety
    capacity = _safe_int(candidate.get("capacity_bytes"))
    if capacity <= 0:
        return _safety("unknown", "destination capacity is not fixed")
    if relation in {"symbolic_offset", "symbolic_read_offset"}:
        return _symbolic_offset_safety(candidate, facts, capacity)
    if relation == "symbolic_size":
        return _symbolic_size_safety(candidate, facts, capacity)
    if relation == "iterated_alias_unproven":
        return _iterated_alias_safety(candidate, facts, capacity)
    return _append_length_safety(candidate, facts, capacity)


def prove_relational_allocation_write(
    candidate: Mapping[str, Any],
    *,
    source_text: str = "",
    excerpt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Prove a heap string write safe on every bounded recovered source path."""

    records = _line_records(source_text, excerpt)
    if not records:
        return _relational_unknown("candidate source excerpt is unavailable")
    candidate_line = _safe_int(candidate.get("line_number"))
    # Parse the complete function/excerpt so braces and labels after the
    # candidate remain structurally visible.  The interpreter stops changing
    # a state after it reaches the exact candidate write.
    selected = list(records)
    if not selected:
        return _relational_unknown("candidate source excerpt does not include the write")
    matching_writes = sum(
        len(re.findall(r"\b(?:strcpy|__strcpy_chk)\s*\(", text))
        for line_number, text in selected
        if line_number == candidate_line
    )
    if matching_writes != 1:
        return _relational_unknown(
            "candidate source line does not identify exactly one strcpy write"
        )
    evaluated = _evaluate_relational_path(candidate, selected, path_index=0)
    proofs = list(evaluated.pop("_structured_path_proofs", [evaluated]))
    if not proofs or any(proof.get("status") != "proven_safe" for proof in proofs):
        reason = next(
            (str(proof.get("reason")) for proof in proofs if proof.get("status") != "proven_safe"),
            "no feasible allocation/write path was recovered",
        )
        return {
            "schema_version": 1,
            "status": "unknown",
            "reason": reason,
            "all_paths_proven": False,
            "path_count": len(proofs),
            "paths": proofs,
            "supporting_source_lines": _unique(
                [line for proof in proofs for line in proof.get("supporting_source_lines", []) or []]
            ),
        }
    first = proofs[0]
    return {
        "schema_version": 1,
        "status": "proven_safe",
        "reason": f"all {len(proofs)} recovered path(s) establish a non-negative destination offset and write_end <= allocation_size",
        "all_paths_proven": True,
        "path_count": len(proofs),
        "allocation": first.get("allocation", {}),
        "offset": first.get("offset", {}),
        "write_size": first.get("write_size", {}),
        "write_end": first.get("write_end", {}),
        "residual_inequalities": [item for proof in proofs for item in proof.get("residual_inequalities", [])],
        "assumptions": _unique([item for proof in proofs for item in proof.get("assumptions", [])]),
        "supporting_source_lines": _unique(
            [line for proof in proofs for line in proof.get("supporting_source_lines", [])]
        ),
        "paths": proofs,
    }


def _relational_unknown(reason: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "unknown",
        "reason": reason,
        "all_paths_proven": False,
        "path_count": 0,
        "paths": [],
        "residual_inequalities": [],
        "assumptions": [],
        "supporting_source_lines": [],
    }


@dataclass(frozen=True)
class _RelationalToken:
    line_number: int
    text: str


@dataclass(frozen=True)
class _RelationalNode:
    kind: str
    line_number: int
    text: str = ""
    body: tuple["_RelationalNode", ...] = ()
    otherwise: tuple["_RelationalNode", ...] = ()
    end_line: int = 0


def _relational_program(records: Sequence[tuple[int, str]]) -> tuple[tuple[_RelationalNode, ...], dict[str, int]] | None:
    tokens = _relational_tokens(records)
    if tokens is None:
        return None
    labels = {
        match.group("label"): token.line_number
        for token in tokens
        if (match := re.match(r"^(?P<label>[A-Za-z_][A-Za-z0-9_]*):$", token.text))
    }
    try:
        nodes, position = _parse_relational_nodes(tokens, 0)
    except ValueError:
        return None
    if position != len(tokens):
        return None
    return tuple(nodes), labels


def _relational_tokens(records: Sequence[tuple[int, str]]) -> list[_RelationalToken] | None:
    """Tokenize the small C subset used by the fail-closed relation prover."""

    tokens: list[_RelationalToken] = []
    for line_number, raw in records:
        text = raw.strip()
        if not text or text.startswith(("//", "/*", "*")):
            continue
        current: list[str] = []
        quote = ""
        escaped = False
        paren_depth = 0
        for char in text:
            if quote:
                current.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
                continue
            if char in {"'", '"'}:
                quote = char
                current.append(char)
                continue
            if char == "(":
                paren_depth += 1
                current.append(char)
                continue
            if char == ")":
                paren_depth = max(0, paren_depth - 1)
                current.append(char)
                continue
            if paren_depth == 0 and char in "{}":
                statement = "".join(current).strip()
                if statement:
                    _append_relational_statement_tokens(tokens, line_number, statement)
                tokens.append(_RelationalToken(line_number, char))
                current = []
                continue
            if paren_depth == 0 and char == ";":
                statement = "".join(current).strip()
                if statement:
                    _append_relational_statement_tokens(tokens, line_number, statement + ";")
                current = []
                continue
            current.append(char)
        if quote or paren_depth:
            return None
        statement = "".join(current).strip()
        if statement:
            _append_relational_statement_tokens(tokens, line_number, statement)
    return tokens


def _append_relational_statement_tokens(
    tokens: list[_RelationalToken],
    line_number: int,
    statement: str,
) -> None:
    # Keep compound ``else if`` as one token.  The structural parser rejects
    # it rather than guessing at unbraced nesting semantics.
    tokens.append(_RelationalToken(line_number, statement.strip()))


def _parse_relational_nodes(
    tokens: Sequence[_RelationalToken],
    position: int,
    *,
    stop_at_close: bool = False,
) -> tuple[list[_RelationalNode], int]:
    nodes: list[_RelationalNode] = []
    while position < len(tokens):
        token = tokens[position]
        if token.text == "}":
            if not stop_at_close:
                raise ValueError("unexpected close brace")
            return nodes, position + 1
        if token.text in {"{", "else"}:
            raise ValueError("unexpected structural token")
        lower = token.text.lower()
        if lower.startswith("else"):
            raise ValueError("unsupported else-if control flow")
        inline_if = _split_inline_relational_if(token)
        if re.match(r"^if\s*\(", token.text):
            if inline_if is not None:
                condition, inline_body = inline_if
                body = [_RelationalNode("statement", token.line_number, inline_body, (), (), token.line_number)]
                position += 1
                other: list[_RelationalNode] = []
                nodes.append(_RelationalNode("if", token.line_number, condition, tuple(body), tuple(other), token.line_number))
                continue
            body, position = _parse_relational_control_body(tokens, position + 1)
            other: list[_RelationalNode] = []
            if position < len(tokens) and tokens[position].text == "else":
                other, position = _parse_relational_control_body(tokens, position + 1)
            end_line = (other[-1].end_line if other else body[-1].end_line) if (body or other) else token.line_number
            nodes.append(_RelationalNode("if", token.line_number, token.text, tuple(body), tuple(other), end_line))
            continue
        if re.match(r"^(?:while|for)\s*\(", token.text):
            body, position = _parse_relational_control_body(tokens, position + 1)
            end_line = body[-1].end_line if body else token.line_number
            nodes.append(_RelationalNode("loop", token.line_number, token.text, tuple(body), (), end_line))
            continue
        if lower == "do":
            body, position = _parse_relational_control_body(tokens, position + 1)
            if position >= len(tokens) or not re.match(r"^while\s*\(", tokens[position].text):
                raise ValueError("unsupported do loop")
            end_line = tokens[position].line_number
            position += 1
            nodes.append(_RelationalNode("loop", token.line_number, token.text, tuple(body), (), end_line))
            continue
        if position + 1 < len(tokens) and tokens[position + 1].text == "{":
            # A function or compiler-generated lexical block.  It has no
            # branch semantics of its own.
            body, position = _parse_relational_control_body(tokens, position + 1)
            end_line = body[-1].end_line if body else token.line_number
            nodes.append(_RelationalNode("block", token.line_number, token.text, tuple(body), (), end_line))
            continue
        nodes.append(_RelationalNode("statement", token.line_number, token.text, (), (), token.line_number))
        position += 1
    if stop_at_close:
        raise ValueError("unclosed brace")
    return nodes, position


def _split_inline_relational_if(token: _RelationalToken) -> tuple[str, str] | None:
    text = token.text.strip()
    if not text.startswith("if"):
        return None
    opening = text.find("(")
    if opening < 0:
        return None
    depth = 0
    quote = ""
    for index, char in enumerate(text[opening:], start=opening):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                tail = text[index + 1 :].strip()
                if tail:
                    return text[: index + 1], tail
                return None
    return None


def _parse_relational_control_body(
    tokens: Sequence[_RelationalToken],
    position: int,
) -> tuple[list[_RelationalNode], int]:
    if position >= len(tokens):
        raise ValueError("missing control body")
    if tokens[position].text == "{":
        return _parse_relational_nodes(tokens, position + 1, stop_at_close=True)
    nodes, next_position = _parse_relational_nodes(tokens, position)
    if not nodes:
        raise ValueError("missing unbraced control statement")
    return [nodes[0]], position + 1


def _evaluate_relational_path(
    candidate: Mapping[str, Any],
    records: Sequence[tuple[int, str]],
    *,
    path_index: int,
) -> dict[str, Any]:
    program = _relational_program(records)
    if program is None:
        return _relational_path_unknown(path_index, "unsupported control flow syntax", [])
    nodes, labels = program
    candidate_line = _safe_int(candidate.get("line_number"))
    if candidate_line <= 0:
        return _relational_path_unknown(path_index, "candidate write line is unavailable", [])
    states = _execute_relational_nodes(
        nodes,
        [_RelationalState(relevant_names=_relational_relevant_names(candidate, records))],
        candidate=candidate,
        candidate_line=candidate_line,
        labels=labels,
        in_loop=False,
    )
    target_states = [state for state in states if state.write is not None and not state.terminated]
    unknown_states = [state for state in states if state.unknown_reason and not state.terminated]
    if unknown_states:
        state = unknown_states[0]
        return _relational_path_unknown(path_index, state.unknown_reason, state.supporting_source_lines)
    if not target_states:
        return _relational_path_unknown(path_index, "no matching allocated strcpy write was recovered", [])
    # This helper now evaluates all feasible paths itself.  Retain a single
    # path_index only for the historical JSON interface.
    proofs = [_relational_state_proof(state, path_index=index) for index, state in enumerate(target_states)]
    if any(proof["status"] != "proven_safe" for proof in proofs):
        return next(proof for proof in proofs if proof["status"] != "proven_safe")
    if len(proofs) == 1:
        return proofs[0]
    first = proofs[0]
    return {
        **first,
        "path_index": path_index,
        "reason": f"all {len(proofs)} feasible structured paths are safe",
        "supporting_source_lines": _unique(
            [line for proof in proofs for line in proof["supporting_source_lines"]]
        ),
        "_structured_path_proofs": proofs,
    }


def _execute_relational_nodes(
    nodes: Sequence[_RelationalNode],
    states: Sequence[_RelationalState],
    *,
    candidate: Mapping[str, Any],
    candidate_line: int,
    labels: Mapping[str, int],
    in_loop: bool,
) -> list[_RelationalState]:
    active = list(states)
    for node in nodes:
        next_states: list[_RelationalState] = []
        for state in active:
            if state.terminated or state.unknown_reason or state.write is not None:
                next_states.append(state)
                continue
            if node.kind == "statement":
                next_states.append(
                    _execute_relational_statement(
                        node,
                        state,
                        candidate=candidate,
                        candidate_line=candidate_line,
                        labels=labels,
                        in_loop=in_loop,
                    )
                )
            elif node.kind == "block":
                next_states.extend(
                    _execute_relational_nodes(
                        node.body,
                        [state],
                        candidate=candidate,
                        candidate_line=candidate_line,
                        labels=labels,
                        in_loop=in_loop,
                    )
                )
            elif node.kind == "if":
                body_contains = _relational_nodes_contain_line(node.body, candidate_line)
                otherwise_contains = _relational_nodes_contain_line(node.otherwise, candidate_line)
                if body_contains:
                    next_states.extend(
                        _execute_relational_nodes(
                            node.body,
                            [_apply_relational_condition(state.clone(), node.text, truth=True)],
                            candidate=candidate,
                            candidate_line=candidate_line,
                            labels=labels,
                            in_loop=in_loop,
                        )
                    )
                if otherwise_contains:
                    next_states.extend(
                        _execute_relational_nodes(
                            node.otherwise,
                            [_apply_relational_condition(state.clone(), node.text, truth=False)],
                            candidate=candidate,
                            candidate_line=candidate_line,
                            labels=labels,
                            in_loop=in_loop,
                        )
                    )
                if not body_contains and not otherwise_contains:
                    next_states.extend(
                        _execute_relational_nodes(
                            node.body,
                            [_apply_relational_condition(state.clone(), node.text, truth=True)],
                            candidate=candidate,
                            candidate_line=candidate_line,
                            labels=labels,
                            in_loop=in_loop,
                        )
                    )
                    next_states.extend(
                        _execute_relational_nodes(
                            node.otherwise,
                            [_apply_relational_condition(state.clone(), node.text, truth=False)],
                            candidate=candidate,
                            candidate_line=candidate_line,
                            labels=labels,
                            in_loop=in_loop,
                        )
                    )
            elif node.kind == "loop":
                next_states.extend(
                    _execute_relational_loop(
                        node,
                        state,
                        candidate=candidate,
                        candidate_line=candidate_line,
                        labels=labels,
                    )
                )
            else:
                unknown = state.clone()
                unknown.unknown_reason = "unsupported structured statement"
                next_states.append(unknown)
        active = _limit_relational_states(next_states)
        if len(active) > 8:
            return [_relational_unknown_state("allocation/write excerpt exceeds the eight-path limit")]
    return active


def _relational_nodes_contain_line(nodes: Sequence[_RelationalNode], line_number: int) -> bool:
    for node in nodes:
        if node.kind == "statement" and node.line_number == line_number:
            return True
        if _relational_nodes_contain_line(node.body, line_number) or _relational_nodes_contain_line(node.otherwise, line_number):
            return True
    return False


def _execute_relational_loop(
    node: _RelationalNode,
    state: _RelationalState,
    *,
    candidate: Mapping[str, Any],
    candidate_line: int,
    labels: Mapping[str, int],
) -> list[_RelationalState]:
    if not (node.line_number <= candidate_line <= node.end_line):
        if not _relational_loop_mutates_relevant(node.body, state.relevant_names):
            return [state]
        return [_relational_unknown_state("unsupported loop before allocation/write candidate", state)]
    roots = _relational_loop_accumulator_roots(node.body, state)
    if not roots:
        return [_relational_unknown_state("unsupported loop-carried allocation/write state", state)]
    first = _execute_relational_nodes(
        node.body,
        [state.clone()],
        candidate=candidate,
        candidate_line=candidate_line,
        labels=labels,
        in_loop=True,
    )
    invariant = state.clone()
    for root in roots:
        symbol = f"loop_accumulator({root})"
        invariant.values[root] = AffineExpr.symbol(symbol)
        invariant.nonnegative_symbols.add(symbol)
    repeated = _execute_relational_nodes(
        node.body,
        [invariant],
        candidate=candidate,
        candidate_line=candidate_line,
        labels=labels,
        in_loop=True,
    )
    return _limit_relational_states([*first, *repeated])


def _relational_loop_mutates_relevant(nodes: Sequence[_RelationalNode], relevant_names: set[str]) -> bool:
    for _line_number, text in _iter_relational_statements(nodes):
        lhs = _assignment_lhs(text)
        if lhs and lhs in relevant_names:
            return True
        compound = re.match(r"^(?P<name>[A-Za-z_]\w*)\s*(?:\+=|-=)", text.strip())
        if compound and compound.group("name") in relevant_names:
            return True
    return False


def _relational_loop_accumulator_roots(
    nodes: Sequence[_RelationalNode],
    state: _RelationalState,
) -> set[str]:
    statements = list(_iter_relational_statements(nodes))
    strlen_names = {
        lhs
        for _number, text in statements
        if (lhs := _assignment_lhs(text))
        and re.search(r"=\s*strlen\s*\(", text)
    }
    roots: set[str] = set()
    for _number, text in statements:
        match = re.match(r"^(?P<name>[A-Za-z_]\w*)\s*\+=\s*(?P<rhs>.+);$", text.strip())
        if match and _loop_rhs_is_nonnegative(match.group("rhs"), strlen_names | {match.group("name")}):
            roots.add(match.group("name"))
            continue
        match = re.match(
            r"^(?P<name>[A-Za-z_]\w*)\s*=\s*(?P=name)\s*\+\s*(?P<rhs>.+);$",
            text.strip(),
        )
        if match and _loop_rhs_is_nonnegative(match.group("rhs"), strlen_names | {match.group("name")}):
            roots.add(match.group("name"))
    return {
        root
        for root in roots
        if _affine_non_negative(state.values.get(root, AffineExpr()), state.nonnegative_symbols)[0]
    }


def _iter_relational_statements(nodes: Sequence[_RelationalNode]) -> Sequence[tuple[int, str]]:
    statements: list[tuple[int, str]] = []
    for node in nodes:
        if node.kind == "statement":
            statements.append((node.line_number, node.text))
        statements.extend(_iter_relational_statements(node.body))
        statements.extend(_iter_relational_statements(node.otherwise))
    return statements


def _assignment_lhs(text: str) -> str:
    lhs, _rhs = _split_simple_assignment(text)
    return lhs


def _loop_rhs_is_nonnegative(text: str, allowed_names: set[str]) -> bool:
    cleaned = re.sub(r"\([^()]*\)", "", text).replace("+", " ").strip().rstrip(";")
    if "-" in cleaned or "*" in cleaned or "/" in cleaned:
        return False
    names = set(_IDENT_RE.findall(cleaned))
    if names - allowed_names:
        return False
    return all((value := _parse_int(token)) is None or value >= 0 for token in _INT_RE.findall(cleaned))


def _execute_relational_statement(
    node: _RelationalNode,
    state: _RelationalState,
    *,
    candidate: Mapping[str, Any],
    candidate_line: int,
    labels: Mapping[str, int],
    in_loop: bool,
) -> _RelationalState:
    result = state.clone()
    text = node.text.strip()
    if not text or re.match(r"^[A-Za-z_][A-Za-z0-9_]*:$", text):
        return result
    if re.match(r"^(?:switch|case|default|try|catch)\b", text):
        return _relational_unknown_state("unsupported control flow near allocation/write candidate", result)
    if text.startswith("return"):
        result.terminated = True
        return result
    goto = re.match(r"^goto\s+(?P<label>[A-Za-z_][A-Za-z0-9_]*);$", text)
    if goto:
        target_line = labels.get(goto.group("label"))
        if target_line is not None and target_line > candidate_line:
            result.terminated = True
        else:
            result.unknown_reason = "goto may reach the allocation/write candidate"
        return result
    if re.match(r"^(?:break|continue);$", text):
        if in_loop:
            result.terminated = True
        else:
            result.unknown_reason = "unsupported loop control flow"
        return result
    compound = re.match(r"^(?P<name>[A-Za-z_]\w*)\s*(?P<op>\+=|-=)\s*(?P<rhs>.+?)\s*;$", text)
    if compound:
        old = result.values.get(compound.group("name"), AffineExpr.symbol(compound.group("name")))
        rhs = _parse_c_affine(compound.group("rhs"), result.values)
        if rhs is None:
            return _relational_unknown_state("unsupported compound assignment", result)
        value = old.add(rhs if compound.group("op") == "+=" else rhs.multiply(-1))
        result.values[compound.group("name")] = value
        _record_relational_nonnegative(result, value)
        _record_relational_support(result, node)
        return result
    lhs, rhs = _split_simple_assignment(text)
    if lhs and rhs:
        call = _parse_simple_call(rhs)
        if call and call[0].lower() in {"malloc", "realloc", "calloc"}:
            size_text = _allocator_size_expr(call[0], call[1])
            size = _parse_c_affine(size_text, result.values)
            if size is None:
                return _relational_unknown_state("allocation size is not affine", result)
            if lhs in result.relevant_names or _canonical_pointer_expr(lhs) in result.relevant_names:
                result.allocations[_canonical_pointer_expr(lhs)] = (size, node.line_number, node.text)
            result.values[lhs] = AffineExpr.symbol(lhs)
            _record_relational_support(result, node)
            return result
        value = _parse_c_affine(rhs, result.values)
        if value is not None:
            result.values[lhs] = value
            _record_relational_nonnegative(result, value)
            source_pointer = _canonical_pointer_expr(rhs)
            if source_pointer in result.allocations and lhs in result.relevant_names:
                result.allocations[_canonical_pointer_expr(lhs)] = result.allocations[source_pointer]
            elif lhs in result.allocations:
                result.allocations.pop(_canonical_pointer_expr(lhs), None)
            _record_relational_support(result, node)
            return result
        # Unsupported assignments are tolerated only if they replace an
        # irrelevant scalar.  Replacing a tracked allocation loses the proof.
        if _canonical_pointer_expr(lhs) in result.allocations:
            return _relational_unknown_state("tracked allocation is reassigned by unsupported expression", result)
        result.values.pop(lhs, None)
        _record_relational_support(result, node)
        return result
    free_call = re.match(r"^free\s*\(\s*(?P<ptr>[^)]+)\s*\);$", text)
    if free_call:
        result.allocations.pop(_canonical_pointer_expr(free_call.group("ptr")), None)
        _record_relational_support(result, node)
        return result
    strcpy = re.search(r"\b(?:strcpy|__strcpy_chk)\s*\(\s*(?P<dest>[^,]+)\s*,\s*(?P<src>[^,)]+)", text)
    if strcpy and node.line_number == candidate_line:
        base, offset = _pointer_base_and_offset(strcpy.group("dest"), result.values, result.allocations)
        source = strcpy.group("src").strip()
        write_size = _parse_c_affine(f"strlen({source}) + 1", result.values)
        if not base or offset is None or write_size is None or base not in result.allocations:
            return _relational_unknown_state("no matching allocated strcpy write was recovered", result)
        allocation, _allocation_line, _allocation_text = result.allocations[base]
        result.write = (allocation, offset, write_size, node.line_number, node.text)
        _record_relational_support(result, node)
    return result


def _apply_relational_condition(state: _RelationalState, text: str, *, truth: bool) -> _RelationalState:
    condition = text[text.find("(") + 1 : text.rfind(")")].strip() if "(" in text and ")" in text else ""
    match = re.fullmatch(r"(?P<name>[A-Za-z_]\w*)\s*(?P<op>==|!=|>=|>|<=|<)\s*(?P<value>-?\d+)", condition)
    if not match:
        return state
    name, op, value = match.group("name"), match.group("op"), int(match.group("value"))
    if (truth and op == "==" and value == 0) or (not truth and op == "!=" and value == 0):
        state.values[name] = AffineExpr()
        return state
    nonnegative = (truth and ((op == ">=" and value >= 0) or (op == ">" and value >= -1))) or (
        not truth and ((op == "<" and value <= 0) or (op == "<=" and value < 0))
    )
    if nonnegative:
        expression = state.values.get(name, AffineExpr.symbol(name))
        if expression.constant == 0 and len(expression.coefficients) == 1 and expression.coefficients[0][1] == 1:
            state.nonnegative_symbols.add(expression.coefficients[0][0])
    return state


def _record_relational_nonnegative(state: _RelationalState, expression: AffineExpr) -> None:
    if expression.constant == 0 and len(expression.coefficients) == 1 and expression.coefficients[0][1] == 1:
        name = expression.coefficients[0][0]
        if name.startswith("strlen("):
            state.nonnegative_symbols.add(name)


def _record_relational_support(state: _RelationalState, node: _RelationalNode) -> None:
    state.supporting_source_lines.append(f"{node.line_number}: {node.text}")


def _relational_unknown_state(reason: str, source: _RelationalState | None = None) -> _RelationalState:
    state = source.clone() if source is not None else _RelationalState()
    state.unknown_reason = reason
    return state


def _limit_relational_states(states: Sequence[_RelationalState]) -> list[_RelationalState]:
    # Terminated paths do not need to spend the bounded proof-state budget.
    live = [state for state in states if not state.terminated]
    deduplicated: list[_RelationalState] = []
    seen: set[tuple[object, ...]] = set()
    for state in live:
        key = _relational_state_key(state)
        if key not in seen:
            seen.add(key)
            deduplicated.append(state)
    live = deduplicated
    if len(live) > 8:
        return [_relational_unknown_state("allocation/write excerpt exceeds the eight-path limit")]
    # A terminating path cannot execute this candidate; it is intentionally
    # omitted from the universal relation rather than consuming path budget.
    return live


def _relational_state_key(state: _RelationalState) -> tuple[object, ...]:
    relevant = state.relevant_names
    values = tuple(sorted((name, value) for name, value in state.values.items() if name in relevant))
    allocations = tuple(sorted((name, value) for name, value in state.allocations.items() if name in relevant))
    return values, allocations, tuple(sorted(state.nonnegative_symbols)), state.unknown_reason, state.write


def _relational_relevant_names(
    candidate: Mapping[str, Any],
    records: Sequence[tuple[int, str]],
) -> set[str]:
    candidate_line = _safe_int(candidate.get("line_number"))
    seeds = " ".join(
        str(candidate.get(key) or "")
        for key in ("target_buffer", "offset_expr", "write_size_expr", "line_text")
    )
    relevant = set(_IDENT_RE.findall(seeds))
    changed = True
    while changed:
        changed = False
        for line_number, text in reversed(records):
            if candidate_line and line_number > candidate_line:
                continue
            lhs, rhs = _split_simple_assignment(text.strip())
            if not lhs or lhs not in relevant:
                continue
            for name in _IDENT_RE.findall(rhs):
                if name not in relevant:
                    relevant.add(name)
                    changed = True
    return relevant


def _relational_state_proof(state: _RelationalState, *, path_index: int) -> dict[str, Any]:
    if state.write is None:
        return _relational_path_unknown(path_index, "no matching allocated strcpy write was recovered", state.supporting_source_lines)
    allocation, offset, write_size, _number, _text = state.write
    write_end = offset.add(write_size)
    offset_ok, offset_residual = _affine_non_negative(offset, state.nonnegative_symbols)
    capacity_residual = allocation.subtract(write_end)
    capacity_ok, capacity_reason = _affine_non_negative(capacity_residual, state.nonnegative_symbols)
    assumptions = sorted(
        f"{name} >= 0"
        for expression in (allocation, offset, write_size, write_end)
        for name, _coefficient in expression.coefficients
        if name.startswith("strlen(") or name in state.nonnegative_symbols
    )
    status = "proven_safe" if offset_ok and capacity_ok else "unknown"
    reason = (
        "non-negative offset and allocation minus write_end are non-negative after coefficient cancellation"
        if status == "proven_safe"
        else f"relation is not universally non-negative: offset={offset_residual}; allocation-write_end={capacity_reason}"
    )
    return {
        "path_index": path_index,
        "status": status,
        "reason": reason,
        "allocation": allocation.to_dict(),
        "offset": offset.to_dict(),
        "write_size": write_size.to_dict(),
        "write_end": write_end.to_dict(),
        "residual_inequalities": [
            {"expression": str(offset), "relation": ">= 0", "proven": offset_ok},
            {"expression": str(capacity_residual), "relation": "allocation - write_end >= 0", "proven": capacity_ok},
        ],
        "assumptions": _unique(assumptions),
        "supporting_source_lines": _unique(state.supporting_source_lines),
    }


def _relational_path_unknown(path_index: int, reason: str, support: Sequence[str]) -> dict[str, Any]:
    return {
        "path_index": path_index,
        "status": "unknown",
        "reason": reason,
        "residual_inequalities": [],
        "assumptions": [],
        "supporting_source_lines": list(support),
    }


def _parse_c_affine(expr: str, values: Mapping[str, AffineExpr]) -> Optional[AffineExpr]:
    text = str(expr or "").strip().rstrip(";")
    text = re.sub(r"\(\s*(?:size_t|ssize_t|long|int|unsigned(?:\s+long)?|char\s*\*)\s*\)", "", text)
    return parse_affine_expr(text, values)


def _pointer_base_and_offset(
    expression: str,
    values: Mapping[str, AffineExpr],
    allocations: Mapping[str, tuple[AffineExpr, int, str]],
) -> tuple[str, AffineExpr | None]:
    text = re.sub(r"^\s*\([^()]*\)\s*", "", expression).strip()
    canonical = _canonical_pointer_expr(text)
    if canonical in allocations:
        return canonical, AffineExpr()
    for base in sorted(allocations, key=len, reverse=True):
        match = re.match(rf"^{re.escape(base)}\s*\+\s*(.+)$", text)
        if match:
            return base, _parse_c_affine(match.group(1), values)
        match = re.match(rf"^&\s*{re.escape(base)}\s*\[\s*(.+)\s*\]$", text)
        if match:
            return base, _parse_c_affine(match.group(1), values)
    return "", None


def _affine_non_negative(
    expression: AffineExpr,
    nonnegative_symbols: Sequence[str] = (),
) -> tuple[bool, str]:
    if expression.constant < 0:
        return False, f"negative constant {expression.constant}"
    for name, coefficient in expression.coefficients:
        if coefficient < 0 or (not name.startswith("strlen(") and name not in set(nonnegative_symbols)):
            return False, f"unbounded coefficient {coefficient} for {name}"
    return True, str(expression)


def parse_linear_expr(expr: str) -> Optional[LinearExpr]:
    """Parse a simple one-variable linear integer expression."""
    cleaned = _normalize_expr(expr)
    if not cleaned or cleaned.lower() in {"unknown", "unbounded"}:
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(cleaned, mode="eval")
    except SyntaxError:
        return None
    try:
        return _linear_from_ast(tree.body)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _symbolic_offset_safety(
    candidate: Mapping[str, Any],
    facts: Mapping[str, Any],
    capacity: int,
) -> dict[str, Any]:
    offset_expr = _expr(candidate.get("offset_expr") or "0")
    width = _write_width(candidate)
    direct_bounds = _direct_expr_bounds(offset_expr, facts, candidate)
    access = _memory_access_noun(candidate)
    if direct_bounds is not None:
        lower, upper, evidence = direct_bounds
        if 0 <= lower and upper + width <= capacity:
            return _safety(
                "proven_safe",
                f"expression {offset_expr!r} is bounded to [{lower}, {upper}], keeping {access} byte range {lower}..{upper + width - 1} within {capacity} bytes",
                evidence=evidence,
            )
        return _safety(
            "candidate",
            f"expression {offset_expr!r} may {access} byte range {lower}..{upper + width - 1} against {capacity} bytes",
            evidence=evidence,
        )
    linear = parse_linear_expr(offset_expr)
    if linear is None:
        return _safety("candidate", f"offset expression {offset_expr!r} is not a supported linear expression")
    if linear.is_constant:
        start = linear.constant
        if 0 <= start and start + width <= capacity:
            return _safety("proven_safe", f"constant {access} range {start}..{start + width - 1} fits in {capacity} bytes")
        return _safety("candidate", f"constant {access} range starts at {start}, not proven safe")
    bounds = _aggregate_range(facts.get("range_table", []), linear.symbol)
    if bounds["lower"] is None or bounds["upper"] is None:
        return _safety("candidate", f"missing exact lower/upper bounds for {linear.symbol}", evidence=bounds["evidence"])
    if linear.scale < 0:
        min_offset = int(bounds["upper"]) * linear.scale + linear.constant
        max_offset = int(bounds["lower"]) * linear.scale + linear.constant
    else:
        min_offset = int(bounds["lower"]) * linear.scale + linear.constant
        max_offset = int(bounds["upper"]) * linear.scale + linear.constant
    if 0 <= min_offset and max_offset + width <= capacity:
        return _safety(
            "proven_safe",
            f"{linear.symbol} in [{bounds['lower']}, {bounds['upper']}] keeps {access} range {min_offset}..{max_offset + width - 1} within {capacity} bytes",
            evidence=bounds["evidence"],
        )
    return _safety(
        "candidate",
        f"{linear.symbol} bounds allow {access} range {min_offset}..{max_offset + width - 1} against {capacity} bytes",
        evidence=bounds["evidence"],
    )


def _symbolic_size_safety(
    candidate: Mapping[str, Any],
    facts: Mapping[str, Any],
    capacity: int,
) -> dict[str, Any]:
    size_expr = _expr(candidate.get("write_size_expr") or "")
    offset_expr = _expr(candidate.get("offset_expr") or "0")
    access = _memory_access_noun(candidate)
    object_role = _memory_object_role(candidate)
    if _size_expr_is_remaining_capacity(size_expr, offset_expr, candidate, capacity):
        offset_bounds = _expr_bounds(offset_expr, facts, candidate)
        if offset_bounds is None:
            return _safety(
                "candidate",
                f"size expression {size_expr!r} accounts for offset {offset_expr!r}, but offset bounds are not exact",
            )
        lower, upper, evidence = offset_bounds
        if 0 <= lower and upper <= capacity:
            return _safety(
                "proven_safe",
                f"{access} size expression {size_expr!r} is the remaining {capacity}-byte {object_role} capacity after offset {offset_expr!r}",
                evidence=evidence,
            )
        return _safety(
            "candidate",
            f"remaining-capacity expression is present, but offset {offset_expr!r} may be outside [0, {capacity}]",
            evidence=evidence,
        )
    offset = _eval_int_expr(offset_expr, candidate)
    if offset is None or offset < 0:
        return _safety("candidate", f"offset {offset_expr!r} is not a non-negative constant")
    linear = parse_linear_expr(size_expr)
    if linear is None:
        direct_bounds = _direct_expr_bounds(size_expr, facts, candidate)
        if direct_bounds is None:
            return _safety("candidate", f"size expression {size_expr!r} is not a supported linear expression")
        _lower, upper_size, evidence = direct_bounds
    elif linear.is_constant:
        upper_size = linear.constant
        evidence: list[str] = []
    else:
        bounds = _aggregate_range(facts.get("range_table", []), linear.symbol)
        if bounds["upper"] is None:
            return _safety("candidate", f"missing exact upper bound for {linear.symbol}", evidence=bounds["evidence"])
        if linear.scale < 0:
            if bounds["lower"] is None:
                return _safety("candidate", f"missing exact lower bound for {linear.symbol}", evidence=bounds["evidence"])
            upper_size = int(bounds["lower"]) * linear.scale + linear.constant
        else:
            upper_size = int(bounds["upper"]) * linear.scale + linear.constant
        evidence = bounds["evidence"]
    if upper_size < 0:
        return _safety("candidate", f"{access} size upper bound {upper_size} is invalid", evidence=evidence)
    remaining = capacity - offset
    if upper_size <= remaining:
        return _safety(
            "proven_safe",
            f"{access} size is bounded by {upper_size}, remaining {object_role} capacity is {remaining}",
            evidence=evidence,
        )
    return _safety(
        "candidate",
        f"{access} size may reach {upper_size}, exceeding remaining {object_role} capacity {remaining}",
        evidence=evidence,
    )


def _size_expr_is_remaining_capacity(
    size_expr: str,
    offset_expr: str,
    candidate: Mapping[str, Any],
    capacity: int,
) -> bool:
    size_linear = parse_linear_expr(_capacity_substituted_expr(size_expr, candidate, capacity))
    offset_linear = parse_linear_expr(_capacity_substituted_expr(offset_expr or "0", candidate, capacity))
    if size_linear is None or offset_linear is None:
        return False
    if size_linear.symbol != offset_linear.symbol:
        return False
    return bool(
        size_linear.scale + offset_linear.scale == 0
        and size_linear.constant + offset_linear.constant == capacity
    )


def _capacity_substituted_expr(expr: str, candidate: Mapping[str, Any], capacity: int) -> str:
    text = _normalize_expr(expr)
    target = str(candidate.get("target_buffer") or "")
    if target:
        escaped = re.escape(target)
        text = re.sub(rf"\bsizeof\s*\(\s*{escaped}\s*\)", str(capacity), text)
        text = re.sub(rf"\bsizeof\s+{escaped}\b", str(capacity), text)
    return text


def _expr_bounds(
    expr: str,
    facts: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[int, int, list[str]] | None:
    direct = _direct_expr_bounds(expr, facts, candidate)
    if direct is not None:
        return direct
    linear = parse_linear_expr(expr)
    if linear is None:
        return None
    if linear.is_constant:
        return linear.constant, linear.constant, []
    bounds = _aggregate_range(facts.get("range_table", []), linear.symbol)
    lower = _optional_int(bounds.get("lower"))
    upper = _optional_int(bounds.get("upper"))
    if lower is None or upper is None:
        return None
    if linear.scale < 0:
        min_value = upper * linear.scale + linear.constant
        max_value = lower * linear.scale + linear.constant
    else:
        min_value = lower * linear.scale + linear.constant
        max_value = upper * linear.scale + linear.constant
    return min_value, max_value, list(bounds.get("evidence", []))


def _iterated_alias_safety(
    candidate: Mapping[str, Any],
    facts: Mapping[str, Any],
    capacity: int,
) -> dict[str, Any]:
    width = _write_width(candidate)
    offset = _eval_int_expr(_expr(candidate.get("offset_expr") or "0"), candidate)
    if offset is None:
        return _safety("candidate", "iterated alias write offset is not constant")
    for loop in facts.get("loop_summary", []) or []:
        if not isinstance(loop, Mapping) or loop.get("kind") != "pointer_loop" or not loop.get("exact"):
            continue
        max_offset = _optional_int(loop.get("max_offset"))
        if max_offset is None:
            continue
        end = max_offset + offset + width
        if 0 <= offset and end <= capacity:
            return _safety(
                "proven_safe",
                f"exact pointer loop max offset {max_offset} plus write offset {offset} and width {width} fits in {capacity} bytes",
                evidence=[str(loop.get("text") or loop.get("line_number") or "pointer_loop")],
            )
    return _safety("candidate", "no exact pointer-loop capacity summary proves this iterated alias safe")


def _append_length_safety(
    candidate: Mapping[str, Any],
    facts: Mapping[str, Any],
    capacity: int,
) -> dict[str, Any]:
    append_bound = _optional_int(candidate.get("write_size_bytes"))
    if append_bound is None:
        size_expr = _expr(candidate.get("write_size_expr") or "")
        linear = parse_linear_expr(size_expr)
        if linear is None:
            return _safety("candidate", "append bound is symbolic")
        if linear.is_constant:
            append_bound = linear.constant
        else:
            bounds = _aggregate_range(facts.get("range_table", []), linear.symbol)
            if bounds["upper"] is None:
                return _safety("candidate", f"missing upper bound for append length {linear.symbol}", evidence=bounds["evidence"])
            append_bound = int(bounds["upper"]) * linear.scale + linear.constant
    if append_bound < 0:
        return _safety("candidate", "append bound is negative or invalid")
    best: Mapping[str, Any] | None = None
    for fact in facts.get("append_length_table", []) or []:
        if not isinstance(fact, Mapping) or not fact.get("exact"):
            continue
        current_len = _optional_int(fact.get("length"))
        if current_len is None:
            continue
        if best is None or _safe_int(fact.get("line_number")) > _safe_int(best.get("line_number")):
            best = fact
    if best is None:
        return _safety("candidate", "current destination string length is not exact")
    current_len = int(best.get("length") or 0)
    total = current_len + append_bound + 1
    if total <= capacity:
        return _safety(
            "proven_safe",
            f"current length {current_len} plus append bound {append_bound} and terminator fits in {capacity} bytes",
            evidence=[str(best.get("text") or best.get("source") or "append_length")],
        )
    return _safety(
        "candidate",
        f"current length {current_len} plus append bound {append_bound} and terminator may require {total} bytes",
        evidence=[str(best.get("text") or best.get("source") or "append_length")],
    )


def _ranges_from_loop(loop: Mapping[str, Any], line_number: int, text: str) -> list[dict[str, Any]]:
    if loop.get("kind") != "counted_loop" or not loop.get("index") or not loop.get("exact"):
        return []
    lower = _optional_int(loop.get("init"))
    upper = _optional_int(loop.get("max_value"))
    min_value = _optional_int(loop.get("min_value"))
    if min_value is not None:
        lower = min_value if lower is None else min(lower, min_value)
    if lower is None or upper is None:
        return []
    return [
        {
            "symbol": loop["index"],
            "lower": lower,
            "upper": upper,
            "source": "counted_loop",
            "line_number": line_number,
            "text": text,
            "exact": True,
        }
    ]


def _ranges_from_positive_condition(
    condition: str,
    line_number: int,
    text: str,
    candidate: Mapping[str, Any],
) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    for atom in _condition_atoms(condition, "&&"):
        bound = _bound_from_positive_atom(atom, candidate)
        if bound:
            bound.update({"source": "guard", "line_number": line_number, "text": text, "exact": True})
            ranges.append(bound)
    return ranges


def _ranges_from_reject_condition(
    condition: str,
    line_number: int,
    text: str,
    candidate: Mapping[str, Any],
) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    for atom in _condition_atoms(condition, "||"):
        bound = _bound_from_reject_atom(atom, candidate)
        if bound:
            bound.update({"source": "reject_guard", "line_number": line_number, "text": text, "exact": True})
            ranges.append(bound)
    if not ranges:
        inverted = _bound_from_reject_atom(condition, candidate)
        if inverted:
            inverted.update({"source": "reject_guard", "line_number": line_number, "text": text, "exact": True})
            ranges.append(inverted)
    return ranges


def _bound_from_positive_atom(atom: str, candidate: Mapping[str, Any]) -> dict[str, Any] | None:
    parsed = _parse_comparison(atom, candidate)
    if parsed is None:
        return None
    left, op, right = parsed
    return _range_from_comparison(left, op, right, candidate, reject=False)


def _bound_from_reject_atom(atom: str, candidate: Mapping[str, Any]) -> dict[str, Any] | None:
    parsed = _parse_comparison(atom, candidate)
    if parsed is None:
        return None
    left, op, right = parsed
    return _range_from_comparison(left, op, right, candidate, reject=True)


def _range_from_comparison(
    left: str,
    op: str,
    right: str,
    candidate: Mapping[str, Any],
    *,
    reject: bool,
) -> dict[str, Any] | None:
    left_linear = parse_linear_expr(left)
    right_value = _eval_int_expr(right, candidate)
    if left_linear is not None and left_linear.symbol and right_value is not None:
        bound = _bound_for_linear(left_linear, op, right_value, reject=reject)
        if bound:
            return bound
    right_linear = parse_linear_expr(right)
    left_value = _eval_int_expr(left, candidate)
    if right_linear is not None and right_linear.symbol and left_value is not None:
        reversed_op = {">": "<", ">=": "<=", "<": ">", "<=": ">="}.get(op, op)
        bound = _bound_for_linear(right_linear, reversed_op, left_value, reject=reject)
        if bound:
            return bound
    return None


def _direct_expr_bounds(
    expr: str,
    facts: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[int, int, list[str]] | None:
    raw = str(expr or "").strip()
    text = _normalize_expr(raw)
    byte_cast = re.search(
        r"\(\s*(?:unsigned\s+char|uchar|uint8_t|byte|undefined1)\s*\)\s*"
        r"(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)\b",
        raw,
    )
    if byte_cast:
        symbol = byte_cast.group("symbol")
        return 0, 255, [f"byte_cast:{symbol}"]
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
        line_text = str(candidate.get("line_text") or "")
        if re.search(
            rf"\(\s*(?:unsigned\s+char|uchar|uint8_t|byte|undefined1)\s*\)\s*{re.escape(text)}\b",
            line_text,
        ):
            return 0, 255, [f"byte_cast:{text}"]
    mask_match = re.fullmatch(r"\(?\s*(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)\s*&\s*0x[fF]{2}\s*\)?", text)
    if mask_match:
        return 0, 255, [f"byte_mask:{mask_match.group('symbol')}"]
    call = re.match(r"(?P<name>MIN|MAX|min|max|CLAMP|clamp)\s*\((?P<args>.*)\)$", text)
    if call:
        args = _split_call_args(call.group("args"))
        name = call.group("name").lower()
        if name == "clamp" and len(args) >= 3:
            lower = _eval_int_expr(args[1], candidate)
            upper = _eval_int_expr(args[2], candidate)
            if lower is not None and upper is not None:
                return min(lower, upper), max(lower, upper), [f"clamp:{text}"]
        if name in {"min", "max"} and len(args) >= 2:
            left_bounds = _expr_arg_bounds(args[0], facts, candidate)
            right_bounds = _expr_arg_bounds(args[1], facts, candidate)
            if left_bounds is None or right_bounds is None:
                return None
            if name == "min":
                return min(left_bounds[0], right_bounds[0]), min(left_bounds[1], right_bounds[1]), [f"min:{text}"]
            if name == "max":
                return max(left_bounds[0], right_bounds[0]), max(left_bounds[1], right_bounds[1]), [f"max:{text}"]
    return None


def _expr_arg_bounds(
    expr: str,
    facts: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[int, int] | None:
    value = _eval_int_expr(expr, candidate)
    if value is not None:
        return value, value
    direct = _direct_expr_bounds(expr, facts, candidate)
    if direct is not None:
        return direct[0], direct[1]
    linear = parse_linear_expr(expr)
    if linear is None or not linear.symbol or linear.scale != 1 or linear.constant != 0:
        return None
    bounds = _aggregate_range(facts.get("range_table", []), linear.symbol)
    lower = _optional_int(bounds.get("lower"))
    upper = _optional_int(bounds.get("upper"))
    if lower is None or upper is None:
        return None
    return lower, upper


def _bound_for_linear(linear: LinearExpr, op: str, value: int, *, reject: bool) -> dict[str, Any] | None:
    if linear.scale == 0:
        return None
    if linear.scale < 0:
        return None
    adjusted = value - linear.constant
    if adjusted % linear.scale == 0:
        exact = adjusted // linear.scale
    else:
        exact = adjusted / linear.scale
    positive_op = op
    if reject:
        positive_op = {">=": "<", ">": "<=", "<=": ">", "<": ">="}.get(op, op)
    if positive_op == ">=":
        return {"symbol": linear.symbol, "lower": _ceil_number(exact), "upper": None, "relation": f"{linear.symbol} >= {_ceil_number(exact)}"}
    if positive_op == ">":
        return {"symbol": linear.symbol, "lower": _floor_number(exact) + 1, "upper": None, "relation": f"{linear.symbol} > {exact}"}
    if positive_op == "<=":
        return {"symbol": linear.symbol, "lower": None, "upper": _floor_number(exact), "relation": f"{linear.symbol} <= {_floor_number(exact)}"}
    if positive_op == "<":
        return {"symbol": linear.symbol, "lower": None, "upper": _ceil_number(exact) - 1, "relation": f"{linear.symbol} < {exact}"}
    return None


def _parse_for_loop(line: str, candidate: Mapping[str, Any]) -> dict[str, Any] | None:
    match = re.search(r"\bfor\s*\((?P<init>[^;]*);(?P<cond>[^;]*);(?P<step>[^)]*)\)", line)
    if not match:
        return None
    counted = _parse_counted_loop(match.group("init"), match.group("cond"), match.group("step"), line, candidate)
    if counted:
        return counted
    return _parse_pointer_loop(match.group("init"), match.group("cond"), match.group("step"), line, candidate)


def _parse_counted_loop(init: str, cond: str, step: str, text: str, candidate: Mapping[str, Any]) -> dict[str, Any] | None:
    init_match = re.search(r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\b\s*=\s*(?P<value>[-+]?0x[0-9a-fA-F]+|[-+]?\d+)", init)
    if not init_match:
        return None
    var = init_match.group("var")
    start = _parse_int(init_match.group("value"))
    if start is None:
        return None
    step_value = _loop_step_value(step, var)
    if step_value is None or step_value == 0:
        return None
    if step_value < 0:
        lower = _loop_condition_lower(cond, var, candidate)
        if lower is None:
            return {
                "kind": "counted_loop",
                "index": var,
                "init": start,
                "step": step_value,
                "condition": cond.strip(),
                "text": text,
                "exact": False,
            }
        op, limit = lower
        min_value = limit - step_value if op == ">" else limit
        trip_count = ((start - min_value) // abs(step_value) + 1) if start >= min_value else 0
        return {
            "kind": "counted_loop",
            "index": var,
            "init": start,
            "step": step_value,
            "limit": limit,
            "operator": op,
            "min_value": min_value,
            "max_value": start,
            "trip_count": trip_count,
            "condition": cond.strip(),
            "text": text,
            "exact": True,
        }
    upper = _loop_condition_upper(cond, var, candidate)
    if upper is None:
        return {
            "kind": "counted_loop",
            "index": var,
            "init": start,
            "step": step_value,
            "condition": cond.strip(),
            "text": text,
            "exact": False,
        }
    op, limit = upper
    max_value = limit - step_value if op == "<" else limit
    trip_count = ((max_value - start) // step_value + 1) if max_value >= start else 0
    return {
        "kind": "counted_loop",
        "index": var,
        "init": start,
        "step": step_value,
        "limit": limit,
        "operator": op,
        "max_value": max_value,
        "trip_count": trip_count,
        "condition": cond.strip(),
        "text": text,
        "exact": True,
    }


def _parse_pointer_loop(init: str, cond: str, step: str, text: str, candidate: Mapping[str, Any]) -> dict[str, Any] | None:
    target = str(candidate.get("target_buffer") or "")
    if not target:
        return None
    init_match = re.search(r"\b(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\b\s*=\s*(?P<expr>.+)", init.strip())
    if not init_match:
        return None
    alias = init_match.group("alias")
    start_offset = _offset_from_target_expr(init_match.group("expr"), target, candidate)
    if start_offset is None:
        return None
    step_value = _pointer_step_value(step, alias)
    if step_value is None or step_value <= 0:
        return None
    bound = _pointer_condition_bound(cond, alias, target, candidate)
    if bound is None:
        return {
            "kind": "pointer_loop",
            "alias": alias,
            "base": target,
            "start_offset": start_offset,
            "step": step_value,
            "condition": cond.strip(),
            "text": text,
            "exact": False,
        }
    op, limit_offset = bound
    if op == "<":
        max_offset = limit_offset - step_value
    elif op == "<=":
        max_offset = limit_offset
    elif op == "!=":
        distance = limit_offset - start_offset
        if distance <= 0 or distance % step_value != 0:
            max_offset = None
        else:
            max_offset = limit_offset - step_value
    else:
        max_offset = None
    return {
        "kind": "pointer_loop",
        "alias": alias,
        "base": target,
        "start_offset": start_offset,
        "step": step_value,
        "limit_offset": limit_offset,
        "operator": op,
        "max_offset": max_offset,
        "condition": cond.strip(),
        "text": text,
        "exact": max_offset is not None,
    }


def _append_length_facts(
    candidate: Mapping[str, Any],
    line_records: Sequence[tuple[int, str]],
    candidate_line: int,
) -> list[dict[str, Any]]:
    target = str(candidate.get("target_buffer") or "")
    if not target:
        return []
    facts: list[dict[str, Any]] = []
    for line_number, line in line_records:
        if candidate_line and line_number >= candidate_line:
            continue
        if candidate_line and line_number < max(1, candidate_line - 40):
            continue
        stripped = line.strip()
        escaped = re.escape(target)
        if re.search(rf"\b{escaped}\s*\[\s*0\s*\]\s*=\s*(?:'\\0'|0)\s*;", stripped):
            facts.append({"target": target, "length": 0, "exact": True, "source": "nul_initialization", "line_number": line_number, "text": stripped})
            continue
        if re.search(rf"\*\s*{escaped}\s*=\s*(?:'\\0'|0)\s*;", stripped):
            facts.append({"target": target, "length": 0, "exact": True, "source": "nul_initialization", "line_number": line_number, "text": stripped})
            continue
        memset = re.search(rf"\bmemset\s*\(\s*{escaped}\s*,\s*0\s*,\s*(?P<size>[^)]+)\)", stripped)
        if memset and _eval_int_expr(memset.group("size"), candidate) == _safe_int(candidate.get("capacity_bytes")):
            facts.append({"target": target, "length": 0, "exact": True, "source": "zeroed_buffer", "line_number": line_number, "text": stripped})
            continue
        strcpy = re.search(rf"\bstrcpy\s*\(\s*{escaped}\s*,\s*(?P<literal>\"(?:\\.|[^\"\\])*\")\s*\)", stripped)
        if strcpy:
            length = _string_literal_length(strcpy.group("literal"))
            if length is not None:
                facts.append({"target": target, "length": length, "exact": True, "source": "constant_strcpy", "line_number": line_number, "text": stripped})
            continue
        snprintf = re.search(
            rf"\bsnprintf\s*\(\s*{escaped}\s*,\s*(?P<size>[^,]+)\s*,\s*(?P<literal>\"(?:\\.|[^\"\\])*\")",
            stripped,
        )
        if snprintf:
            length = _string_literal_length(snprintf.group("literal"))
            size_bound = _eval_int_expr(snprintf.group("size"), candidate)
            if length is not None and size_bound is not None:
                facts.append(
                    {
                        "target": target,
                        "length": min(length, max(size_bound - 1, 0)),
                        "exact": length < size_bound,
                        "source": "bounded_constant_snprintf",
                        "line_number": line_number,
                        "text": stripped,
                    }
                )
    return facts


def _allocation_relation_facts(
    candidate: Mapping[str, Any],
    line_records: Sequence[tuple[int, str]],
    candidate_line: int,
) -> list[dict[str, Any]]:
    target = _canonical_pointer_expr(str(candidate.get("target_buffer") or ""))
    write_size_expr = _candidate_write_size_expr(candidate)
    write_size_key = _canonical_size_expr(write_size_expr)
    if not target or not write_size_key:
        return []
    facts: list[dict[str, Any]] = []
    for line_number, line in line_records:
        if candidate_line and line_number >= candidate_line:
            continue
        if candidate_line and line_number < max(1, candidate_line - 80):
            continue
        stripped = line.strip()
        lhs, rhs = _split_simple_assignment(stripped)
        if not lhs or not rhs:
            continue
        lhs_key = _canonical_pointer_expr(lhs)
        if lhs_key != target:
            continue
        call = _parse_simple_call(rhs)
        if not call:
            continue
        allocator, args = call
        allocation_size_expr = _allocator_size_expr(allocator, args)
        if not allocation_size_expr:
            continue
        allocation_size_key = _canonical_size_expr(allocation_size_expr)
        matched = _size_exprs_equivalent(allocation_size_expr, write_size_expr)
        facts.append(
            {
                "source": "local_allocator_assignment",
                "line_number": line_number,
                "target": lhs_key,
                "allocator": allocator,
                "allocation_size_expr": allocation_size_expr,
                "write_size_expr": write_size_expr,
                "normalized_allocation_size": allocation_size_key,
                "normalized_write_size": write_size_key,
                "matched": matched,
                "exact": matched,
                "text": stripped,
            }
        )
    return facts


def _allocation_relation_safety(
    candidate: Mapping[str, Any],
    facts: Mapping[str, Any],
) -> dict[str, Any]:
    offset_expr = _expr(candidate.get("offset_expr") or "0")
    offset = _eval_int_expr(offset_expr, candidate)
    if offset not in {0, None}:
        return _safety("candidate", f"allocation relation does not prove non-zero offset {offset_expr!r} safe")
    if offset is None and _canonical_size_expr(offset_expr) not in {"0", ""}:
        return _safety("candidate", f"allocation relation does not prove symbolic offset {offset_expr!r} safe")
    for fact in facts.get("allocation_table", []) or []:
        if not isinstance(fact, Mapping) or not fact.get("matched") or not fact.get("exact"):
            continue
        target = str(fact.get("target") or candidate.get("target_buffer") or "destination")
        allocator = str(fact.get("allocator") or "allocator")
        allocation_size = str(fact.get("allocation_size_expr") or "")
        write_size = str(fact.get("write_size_expr") or "")
        return _safety(
            "proven_safe",
            f"{target} is allocated by {allocator} with size expression {allocation_size!r}, matching write size {write_size!r}",
            evidence=[str(fact.get("text") or ""), f"write size: {write_size}"],
        )
    return _safety("unknown", "no exact local allocation size relation matches this symbolic write")


def _candidate_write_size_expr(candidate: Mapping[str, Any]) -> str:
    expr = _expr(candidate.get("write_size_expr") or "")
    if expr:
        return expr
    width = _optional_int(candidate.get("write_size_bytes"))
    return str(width) if width is not None and width > 0 else ""


def _split_simple_assignment(line: str) -> tuple[str, str]:
    depth = 0
    quote = ""
    for idx, char in enumerate(line):
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
        if char == "=" and depth == 0:
            if idx + 1 < len(line) and line[idx + 1] == "=":
                continue
            if idx > 0 and line[idx - 1] in {"!", "<", ">", "="}:
                continue
            lhs = line[:idx].strip()
            rhs = line[idx + 1 :].strip().rstrip(";")
            if " " in lhs or "*" in lhs:
                name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?$", lhs)
                if name_match:
                    lhs = name_match.group(1)
            return lhs, rhs
    return "", ""


def _parse_simple_call(expr: str) -> tuple[str, list[str]] | None:
    text = _normalize_expr(expr)
    text = re.sub(r"^\s*\([^()]*\)\s*", "", text).strip()
    match = re.search(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
    if not match:
        return None
    open_index = text.find("(", match.start("name"))
    close_index = _find_matching_paren(text, open_index)
    if close_index < 0:
        return None
    name = match.group("name")
    args = _split_call_args(text[open_index + 1 : close_index])
    return name, args


def _split_call_args(args_text: str) -> list[str]:
    args: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for idx, char in enumerate(args_text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
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
        if char == "," and depth == 0:
            args.append(args_text[start:idx].strip())
            start = idx + 1
    tail = args_text[start:].strip()
    if tail:
        args.append(tail)
    return args


def _allocator_size_expr(allocator: str, args: Sequence[str]) -> str:
    lowered = allocator.lower()
    if "calloc" in lowered and len(args) >= 2:
        return f"({args[0]}) * ({args[1]})"
    if "realloc" in lowered and len(args) >= 2:
        return args[1]
    if lowered == "heapalloc" and len(args) >= 3:
        return args[2]
    if ("alloc" in lowered or lowered in {"malloc", "xmalloc"}) and args:
        return args[0]
    return ""


def _size_exprs_equivalent(left: str, right: str) -> bool:
    left_key = _canonical_size_expr(left)
    right_key = _canonical_size_expr(right)
    if left_key and left_key == right_key:
        return True
    left_linear = parse_linear_expr(left)
    right_linear = parse_linear_expr(right)
    return left_linear is not None and right_linear is not None and left_linear == right_linear


def _canonical_size_expr(expr: str) -> str:
    text = _normalize_expr(expr)
    previous = ""
    while text != previous:
        previous = text
        text = _normalize_expr(text)
    text = re.sub(r"\s+", "", text)
    return text


def _canonical_pointer_expr(expr: str) -> str:
    text = _normalize_expr(expr)
    text = re.sub(r"^\s*&\s*", "", text)
    text = re.sub(r"\s+", "", text)
    return text


def _def_use_facts(
    identifiers: Sequence[str],
    line_records: Sequence[tuple[int, str]],
    candidate_line: int,
) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for symbol in identifiers:
        escaped = re.escape(symbol)
        for line_number, line in line_records:
            if candidate_line and abs(line_number - candidate_line) > 25:
                continue
            stripped = line.strip()
            role = ""
            if re.search(rf"\b{escaped}\b\s*(?:=|\+=|-=|\*=|/=|%=|\+\+|--)", stripped) or re.search(rf"(?:\+\+|--)\s*\b{escaped}\b", stripped):
                role = "definition"
            elif re.search(rf"\b(?:if|while|for)\s*\([^)]*\b{escaped}\b", stripped):
                role = "condition_use"
            elif re.search(rf"\b{escaped}\b", stripped):
                role = "use"
            if role:
                facts.append({"symbol": symbol, "line_number": line_number, "text": stripped, "role": role})
    return facts


def _alias_history_facts(
    candidate: Mapping[str, Any],
    line_records: Sequence[tuple[int, str]],
    candidate_line: int,
    loop_summary: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    target = str(candidate.get("target_buffer") or "")
    facts: list[dict[str, Any]] = []
    for loop in loop_summary:
        if isinstance(loop, Mapping) and loop.get("kind") == "pointer_loop":
            facts.append({"source": "loop_summary", **dict(loop)})
    if not target:
        return facts
    escaped = re.escape(target)
    for line_number, line in line_records:
        if candidate_line and line_number > candidate_line:
            continue
        if candidate_line and line_number < max(1, candidate_line - 25):
            continue
        stripped = line.strip()
        if re.search(rf"\b[A-Za-z_][A-Za-z0-9_]*\b\s*=\s*&?\s*{escaped}\b", stripped):
            facts.append({"source": "alias_assignment", "line_number": line_number, "text": stripped})
    return facts


def _parse_comparison(atom: str, candidate: Mapping[str, Any]) -> tuple[str, str, str] | None:
    del candidate
    text = _strip_outer_parens(_normalize_condition_atom(atom))
    for op in ("<=", ">=", "<", ">"):
        index = _find_top_level_operator(text, op)
        if index >= 0:
            return text[:index].strip(), op, text[index + len(op) :].strip()
    return None


def _find_top_level_operator(text: str, op: str) -> int:
    depth = 0
    quote = ""
    idx = 0
    while idx <= len(text) - len(op):
        char = text[idx]
        if quote:
            if char == quote:
                quote = ""
            idx += 1
            continue
        if char in {"'", '"'}:
            quote = char
            idx += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and text.startswith(op, idx):
            return idx
        idx += 1
    return -1


def _condition_atoms(condition: str, separator: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    idx = 0
    while idx < len(condition):
        char = condition[idx]
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        if depth == 0 and condition.startswith(separator, idx):
            parts.append(condition[start:idx].strip())
            start = idx + len(separator)
            idx = start
            continue
        idx += 1
    tail = condition[start:].strip()
    if tail:
        parts.append(tail)
    return parts or [condition.strip()]


def _line_records(source_text: str, excerpt: Mapping[str, Any] | None) -> list[tuple[int, str]]:
    if source_text:
        return [(idx, line) for idx, line in enumerate(source_text.splitlines(), start=1)]
    excerpt = excerpt or {}
    text = str(excerpt.get("text") or "")
    start = _safe_int(excerpt.get("start_line")) or 1
    return [(start + idx, line) for idx, line in enumerate(text.splitlines())]


def _control_condition(line: str) -> str:
    for keyword in ("if", "while", "for"):
        match = re.search(rf"\b{keyword}\s*\(", line)
        if not match:
            continue
        open_index = line.find("(", match.start())
        close_index = _find_matching_paren(line, open_index)
        if close_index >= 0:
            if keyword == "for":
                parts = _split_for_header(line[open_index + 1 : close_index])
                return parts[1] if len(parts) == 3 else ""
            return line[open_index + 1 : close_index].strip()
    return ""


def _split_for_header(header: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for idx, char in enumerate(header):
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == ";" and depth == 0:
            parts.append(header[start:idx].strip())
            start = idx + 1
    parts.append(header[start:].strip())
    return parts


def _find_matching_paren(text: str, open_index: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for idx in range(open_index, len(text)):
        char = text[idx]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _is_reject_guard(line_records: Sequence[tuple[int, str]], line_number: int) -> bool:
    by_line = {number: text for number, text in line_records}
    current = by_line.get(line_number, "")
    if _REJECT_ACTION_RE.search(current):
        return True
    for next_line in range(line_number + 1, line_number + 4):
        text = by_line.get(next_line, "").strip()
        if _REJECT_ACTION_RE.search(text):
            return True
        if text and not text.startswith(("{", "}")):
            break
    return False


def _loop_step_value(step: str, var: str) -> int | None:
    escaped = re.escape(var)
    if re.search(rf"\b{escaped}\b\s*\+\+", step) or re.search(rf"\+\+\s*\b{escaped}\b", step):
        return 1
    if re.search(rf"\b{escaped}\b\s*--", step) or re.search(rf"--\s*\b{escaped}\b", step):
        return -1
    match = re.search(rf"\b{escaped}\b\s*\+=\s*(?P<value>{_INT_RE.pattern})", step)
    if match:
        return _parse_int(match.group("value"))
    match = re.search(rf"\b{escaped}\b\s*-=\s*(?P<value>{_INT_RE.pattern})", step)
    if match:
        value = _parse_int(match.group("value"))
        return -value if value is not None else None
    match = re.search(rf"\b{escaped}\b\s*=\s*\b{escaped}\b\s*\+\s*(?P<value>{_INT_RE.pattern})", step)
    if match:
        return _parse_int(match.group("value"))
    match = re.search(rf"\b{escaped}\b\s*=\s*\b{escaped}\b\s*-\s*(?P<value>{_INT_RE.pattern})", step)
    if match:
        value = _parse_int(match.group("value"))
        return -value if value is not None else None
    return None


def _loop_condition_upper(cond: str, var: str, candidate: Mapping[str, Any]) -> tuple[str, int] | None:
    escaped = re.escape(var)
    patterns = (
        (rf"\b{escaped}\b\s*<\s*(?P<limit>.+)", "<"),
        (rf"\b{escaped}\b\s*<=\s*(?P<limit>.+)", "<="),
        (rf"(?P<limit>.+)\s*>\s*\b{escaped}\b", "<"),
        (rf"(?P<limit>.+)\s*>=\s*\b{escaped}\b", "<="),
    )
    for pattern, op in patterns:
        match = re.search(pattern, cond)
        if not match:
            continue
        raw = re.split(r"\s*(?:&&|\|\|)\s*", match.group("limit").strip(), maxsplit=1)[0]
        value = _eval_int_expr(raw, candidate)
        if value is not None:
            return op, value
    return None


def _loop_condition_lower(cond: str, var: str, candidate: Mapping[str, Any]) -> tuple[str, int] | None:
    escaped = re.escape(var)
    patterns = (
        (rf"\b{escaped}\b\s*>\s*(?P<limit>.+)", ">"),
        (rf"\b{escaped}\b\s*>=\s*(?P<limit>.+)", ">="),
        (rf"(?P<limit>.+)\s*<\s*\b{escaped}\b", ">"),
        (rf"(?P<limit>.+)\s*<=\s*\b{escaped}\b", ">="),
    )
    for pattern, op in patterns:
        match = re.search(pattern, cond)
        if not match:
            continue
        raw = re.split(r"\s*(?:&&|\|\|)\s*", match.group("limit").strip(), maxsplit=1)[0]
        value = _eval_int_expr(raw, candidate)
        if value is not None:
            return op, value
    return None


def _pointer_step_value(step: str, alias: str) -> int | None:
    escaped = re.escape(alias)
    if re.search(rf"\b{escaped}\b\s*\+\+", step) or re.search(rf"\+\+\s*\b{escaped}\b", step):
        return 1
    match = re.search(rf"\b{escaped}\b\s*\+=\s*(?P<value>{_INT_RE.pattern})", step)
    if match:
        return _parse_int(match.group("value"))
    match = re.search(rf"\b{escaped}\b\s*=\s*\b{escaped}\b\s*\+\s*(?P<value>{_INT_RE.pattern})", step)
    if match:
        return _parse_int(match.group("value"))
    return None


def _pointer_condition_bound(
    cond: str,
    alias: str,
    target: str,
    candidate: Mapping[str, Any],
) -> tuple[str, int] | None:
    escaped = re.escape(alias)
    patterns = (
        (rf"\b{escaped}\b\s*<\s*(?P<limit>.+)", "<"),
        (rf"\b{escaped}\b\s*<=\s*(?P<limit>.+)", "<="),
        (rf"\b{escaped}\b\s*!=\s*(?P<limit>.+)", "!="),
        (rf"(?P<limit>.+)\s*>\s*\b{escaped}\b", "<"),
        (rf"(?P<limit>.+)\s*>=\s*\b{escaped}\b", "<="),
        (rf"(?P<limit>.+)\s*!=\s*\b{escaped}\b", "!="),
    )
    for pattern, op in patterns:
        match = re.search(pattern, cond)
        if not match:
            continue
        raw = re.split(r"\s*(?:&&|\|\|)\s*", match.group("limit").strip(), maxsplit=1)[0]
        offset = _offset_from_target_expr(raw, target, candidate)
        if offset is not None:
            return op, offset
    return None


def _offset_from_target_expr(expr: str, target: str, candidate: Mapping[str, Any]) -> int | None:
    cleaned = _normalize_expr(expr)
    cleaned = re.sub(r"^&\s*", "", cleaned)
    escaped = re.escape(target)
    if not re.search(rf"\b{escaped}\b", cleaned):
        return None
    replaced = re.sub(rf"\b{escaped}\b", "0", cleaned, count=1)
    replaced = re.sub(r"^\s*0\s*\+\s*", "", replaced)
    replaced = replaced.strip()
    if not replaced:
        return 0
    return _eval_int_expr(replaced, candidate)


def _aggregate_range(entries: Any, symbol: str) -> dict[str, Any]:
    lower: int | None = None
    upper: int | None = None
    evidence: list[str] = []
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes, bytearray)):
        return {"lower": None, "upper": None, "evidence": []}
    for entry in entries:
        if not isinstance(entry, Mapping) or str(entry.get("symbol") or "") != symbol:
            continue
        entry_lower = _optional_int(entry.get("lower"))
        entry_upper = _optional_int(entry.get("upper"))
        if entry_lower is not None:
            lower = entry_lower if lower is None else max(lower, entry_lower)
        if entry_upper is not None:
            upper = entry_upper if upper is None else min(upper, entry_upper)
        evidence_text = str(entry.get("text") or entry.get("relation") or "")
        if evidence_text and evidence_text not in evidence:
            evidence.append(evidence_text)
    return {"lower": lower, "upper": upper, "evidence": evidence}


def _range_summary(entries: Any) -> dict[str, Any]:
    symbols = _unique([str(entry.get("symbol") or "") for entry in entries or [] if isinstance(entry, Mapping)])
    return {symbol: _aggregate_range(entries, symbol) for symbol in symbols if symbol}


def _linear_from_ast(node: ast.AST) -> LinearExpr:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return LinearExpr(constant=int(node.value))
    if isinstance(node, ast.Name):
        return LinearExpr(symbol=node.id, scale=1, constant=0)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _linear_from_ast(node.operand)
        return LinearExpr(symbol=inner.symbol, scale=-inner.scale, constant=-inner.constant)
    if isinstance(node, ast.BinOp):
        left = _linear_from_ast(node.left)
        right = _linear_from_ast(node.right)
        if isinstance(node.op, ast.Add):
            return _combine_linear(left, right, 1)
        if isinstance(node.op, ast.Sub):
            return _combine_linear(left, right, -1)
        if isinstance(node.op, ast.Mult):
            if left.is_constant and not right.is_constant:
                return LinearExpr(symbol=right.symbol, scale=right.scale * left.constant, constant=right.constant * left.constant)
            if right.is_constant and not left.is_constant:
                return LinearExpr(symbol=left.symbol, scale=left.scale * right.constant, constant=left.constant * right.constant)
            if left.is_constant and right.is_constant:
                return LinearExpr(constant=left.constant * right.constant)
    raise TypeError(f"unsupported expression: {ast.dump(node)}")


def _combine_linear(left: LinearExpr, right: LinearExpr, right_sign: int) -> LinearExpr:
    if left.symbol and right.symbol and left.symbol != right.symbol:
        raise TypeError("multiple symbols are not linear in this domain")
    symbol = left.symbol or right.symbol
    return LinearExpr(
        symbol=symbol,
        scale=left.scale + right_sign * right.scale,
        constant=left.constant + right_sign * right.constant,
    )


def _eval_int_expr(expr: str, candidate: Mapping[str, Any]) -> int | None:
    text = _normalize_expr(expr)
    if not text:
        return None
    target = str(candidate.get("target_buffer") or "")
    capacity = _safe_int(candidate.get("capacity_bytes"))
    width = max(1, _write_width(candidate))
    if target and capacity > 0:
        escaped = re.escape(target)
        text = re.sub(rf"\bsizeof\s*\(\s*{escaped}\s*\)", str(capacity), text)
        text = re.sub(rf"\bsizeof\s+{escaped}\b", str(capacity), text)
        text = re.sub(rf"\b(?:ARRAY_SIZE|array_size)\s*\(\s*{escaped}\s*\)", str(capacity // width), text)
    try:
        parsed = parse_linear_expr(text)
    except RecursionError:
        parsed = None
    if parsed is not None and parsed.is_constant:
        return parsed.constant
    if re.fullmatch(r"[0-9xXa-fA-F+\-*/%() <>&|]+", text):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(text, mode="eval")
            return int(_eval_ast_int(tree.body))
        except (SyntaxError, TypeError, ValueError, ZeroDivisionError):
            return None
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
        if isinstance(node.op, (ast.Div, ast.FloorDiv)):
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
    raise TypeError(ast.dump(node))


def _normalize_expr(expr: str) -> str:
    text = str(expr or "").strip().rstrip(";")
    text = re.sub(
        r"\(\s*(?:unsigned\s+|signed\s+)?(?:char|short|int|long|ulong|uint|size_t|byte|undefined\d*|[A-Za-z_][A-Za-z0-9_]*\s+\*)\s*\*?\s*\)",
        "",
        text,
    )
    text = re.sub(r"\s+", " ", text).strip()
    while text.startswith("(") and text.endswith(")") and _outer_parens_are_balanced(text):
        text = text[1:-1].strip()
    if text.startswith("+"):
        text = text[1:].strip()
    return text


def _normalize_condition_atom(atom: str) -> str:
    text = _normalize_expr(atom)
    if text.startswith("!"):
        text = text[1:].strip()
    return text


def _strip_outer_parens(expr: str) -> str:
    text = str(expr or "").strip()
    while text.startswith("(") and text.endswith(")") and _outer_parens_are_balanced(text):
        text = text[1:-1].strip()
    return text


def _outer_parens_are_balanced(text: str) -> bool:
    depth = 0
    quote = ""
    for idx, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and idx != len(text) - 1:
                return False
    return depth == 0


def _string_literal_length(literal: str) -> int | None:
    try:
        value = ast.literal_eval(literal)
    except (SyntaxError, ValueError):
        return None
    return len(value) if isinstance(value, str) else None


def _write_width(candidate: Mapping[str, Any]) -> int:
    width = _optional_int(candidate.get("write_size_bytes"))
    if width is not None and width > 0:
        return width
    if str(candidate.get("write_relation") or "") in {"symbolic_offset", "symbolic_read_offset", "iterated_alias_unproven"}:
        return 1
    return 0


def _memory_access_noun(candidate: Mapping[str, Any]) -> str:
    if str(candidate.get("vulnerability_type") or "") == "out_of_bounds_read" or str(candidate.get("kind") or "") in {
        "indexed_read",
        "source_read",
    }:
        return "read"
    return "write"


def _memory_object_role(candidate: Mapping[str, Any]) -> str:
    return "source" if _memory_access_noun(candidate) == "read" else "destination"


def _expr(value: Any) -> str:
    return str(value or "").strip()


def _identifiers(expr: str) -> list[str]:
    ignored = {
        "sizeof",
        "ARRAY_SIZE",
        "array_size",
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
    return [item for item in _IDENT_RE.findall(expr or "") if item not in ignored]


def _parse_int(text: str) -> int | None:
    try:
        return int(str(text).strip(), 0)
    except ValueError:
        return None


def _optional_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value: Any) -> int:
    return _optional_int(value) or 0


def _ceil_number(value: float | int) -> int:
    number = float(value)
    integer = int(number)
    return integer if number == integer else integer + 1


def _floor_number(value: float | int) -> int:
    number = float(value)
    integer = int(number)
    return integer if number >= 0 or number == integer else integer - 1


def _safety(status: str, reason: str, *, evidence: Sequence[str] = ()) -> dict[str, Any]:
    return {
        "status": status,
        "reason": reason,
        "evidence": _unique([str(item) for item in evidence if str(item).strip()]),
    }


def _linear_expr_to_dict(expr: Optional[LinearExpr]) -> dict[str, Any]:
    if expr is None:
        return {"supported": False}
    return {
        "supported": True,
        "symbol": expr.symbol,
        "scale": expr.scale,
        "constant": expr.constant,
    }


def _dedupe_dicts(items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for item in items:
        payload = dict(item)
        key = repr(sorted(payload.items()))
        if key in seen:
            continue
        seen.add(key)
        result.append(payload)
    return result


def _unique(values: Sequence[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result
