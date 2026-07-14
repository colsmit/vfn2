"""Local expression-taint state used by deterministic candidate analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence


@dataclass(frozen=True)
class IdentifierTaint:
    classification: str
    sources: tuple[str, ...] = ()
    trace: tuple[str, ...] = ()
    line_number: int = 0


@dataclass(frozen=True)
class SourceTaintRules:
    source_calls: frozenset[str]
    source_tokens: tuple[str, ...]
    operation_specs: Mapping[str, Mapping[str, object]]
    iter_calls: Callable[[str], Iterable[tuple[str, list[str]]]]
    normalize_call: Callable[[str], str]
    expression_identifiers: Callable[[str], list[str]]
    split_assignment: Callable[[str], tuple[str, str]]
    lhs_name: Callable[[str], str]
    mask_string_literals: Callable[[str], str]
    normalize_expression: Callable[[str], str]
    constant_expression: Callable[[str], bool]


def identifier_taint_before_line(
    lines: Sequence[str],
    line_number: int,
    param_names: Sequence[str],
    rules: SourceTaintRules,
) -> dict[str, IdentifierTaint]:
    state: dict[str, IdentifierTaint] = {
        name: IdentifierTaint(
            classification="parameter_controlled",
            sources=(f"parameter:{name}",),
            trace=(f"{name} is a function parameter",),
        )
        for name in param_names
        if name
    }
    if not lines:
        return state
    end = max(0, min(len(lines), line_number - 1 if line_number > 0 else len(lines)))
    start = max(0, end - 160)
    for index in range(start, end):
        current_line = index + 1
        stripped = lines[index].strip()
        if not stripped:
            continue
        _apply_source_call_taint(state, stripped, current_line, rules)
        _apply_assignment_taint(state, stripped, current_line, param_names, rules)
        _apply_update_taint(state, stripped, current_line)
    return state


def trace_expression_taint(
    dimension: str,
    expression: str,
    state: Mapping[str, IdentifierTaint],
    param_names: Sequence[str],
    rules: SourceTaintRules,
) -> dict[str, object]:
    cleaned = rules.normalize_expression(expression or "")
    identifiers = rules.expression_identifiers(cleaned)
    rows: list[dict[str, object]] = []
    classifications: dict[str, str] = {}
    if not identifiers:
        classification = (
            "constant_or_literal"
            if _rhs_is_constant_or_literal(cleaned or "0", rules)
            else "unknown"
        )
        rows.append(
            {
                "dimension": dimension,
                "expr": cleaned,
                "symbol": "",
                "classification": classification,
                "sources": [],
                "trace": [],
                "line_number": 0,
            }
        )
        return {
            "expr": cleaned,
            "identifiers": [],
            "classifications": {},
            "source_controlled": False,
            "parameter_controlled": False,
            "constant_or_literal": classification == "constant_or_literal",
            "internal_local": False,
            "unknown": classification == "unknown",
            "taint_rows": rows,
        }
    for identifier in identifiers:
        taint = _classify_identifier_taint(identifier, state, param_names, rules)
        classifications[identifier] = taint.classification
        rows.append(
            {
                "dimension": dimension,
                "expr": cleaned,
                "symbol": identifier,
                "classification": taint.classification,
                "sources": list(taint.sources),
                "trace": list(taint.trace),
                "line_number": taint.line_number,
            }
        )
    labels = set(classifications.values())
    return {
        "expr": cleaned,
        "identifiers": identifiers,
        "classifications": classifications,
        "source_controlled": "source_controlled" in labels,
        "parameter_controlled": "parameter_controlled" in labels,
        "constant_or_literal": labels == {"constant_or_literal"},
        "internal_local": bool(labels)
        and labels.issubset({"constant_or_literal", "internal_local"})
        and "internal_local" in labels,
        "unknown": "unknown" in labels,
        "taint_rows": rows,
    }


def _apply_source_call_taint(
    state: dict[str, IdentifierTaint],
    line: str,
    line_number: int,
    rules: SourceTaintRules,
) -> None:
    for callee, args in rules.iter_calls(line) or ():
        source_name = rules.normalize_call(callee)
        if source_name not in rules.source_calls:
            continue
        for name in _source_output_identifiers(source_name, args, rules):
            state[name] = IdentifierTaint(
                classification="source_controlled",
                sources=(f"source_call:{source_name}:line {line_number}",),
                trace=(f"{name} receives data from {source_name} at line {line_number}",),
                line_number=line_number,
            )


def _source_output_identifiers(
    source_name: str,
    args: Sequence[str],
    rules: SourceTaintRules,
) -> list[str]:
    if not args:
        return []
    names: list[str] = []
    if source_name in {"scanf", "fscanf", "sscanf"}:
        start = 2 if source_name in {"fscanf", "sscanf"} else 1
        for argument in args[start:]:
            names.extend(_addressed_identifiers(argument, rules))
    elif source_name in {
        "read",
        "recv",
        "recvfrom",
        "fread",
        "fgets",
        "gets",
        "flash_area_read",
    }:
        spec = rules.operation_specs.get(source_name, {})
        destination_index = int(spec.get("dest_arg", 0) or 0)
        if destination_index < len(args):
            names.extend(_addressed_identifiers(args[destination_index], rules))
    else:
        for argument in args:
            names.extend(_addressed_identifiers(argument, rules))
    return _unique_nonempty(names)


def _addressed_identifiers(expression: str, rules: SourceTaintRules) -> list[str]:
    cleaned = str(expression or "").replace("&", " ").replace("*", " ")
    return rules.expression_identifiers(cleaned)


def _apply_assignment_taint(
    state: dict[str, IdentifierTaint],
    line: str,
    line_number: int,
    param_names: Sequence[str],
    rules: SourceTaintRules,
) -> None:
    lhs, rhs = rules.split_assignment(line)
    name = rules.lhs_name(lhs)
    if not name:
        for declared in _declared_local_names(line):
            state.setdefault(
                declared,
                IdentifierTaint(
                    classification="internal_local",
                    sources=(f"local_declaration:line {line_number}",),
                    trace=(f"{declared} is a local variable declared at line {line_number}",),
                    line_number=line_number,
                ),
            )
        return
    rhs_taint = _classify_rhs_taint(rhs, state, param_names, line_number, rules)
    state[name] = IdentifierTaint(
        classification=rhs_taint.classification,
        sources=rhs_taint.sources,
        trace=(f"{name} assigned at line {line_number}", *rhs_taint.trace[:6]),
        line_number=line_number,
    )


def _declared_local_names(line: str) -> list[str]:
    stripped = line.strip()
    if "=" in stripped or "(" in stripped or not stripped.endswith(";"):
        return []
    match = re.match(
        r"(?:const\s+|volatile\s+|static\s+|unsigned\s+|signed\s+|struct\s+)*"
        r"(?:char|short|int|long|size_t|uint|ulong|byte|undefined\d*)\s+(.+);$",
        stripped,
    )
    if not match:
        return []
    names: list[str] = []
    for raw in match.group(1).split(","):
        token = raw.strip().lstrip("*").split("[", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
            names.append(token)
    return names


def _classify_rhs_taint(
    rhs: str,
    state: Mapping[str, IdentifierTaint],
    param_names: Sequence[str],
    line_number: int,
    rules: SourceTaintRules,
) -> IdentifierTaint:
    rhs = rhs.strip()
    source_links = _rhs_source_links(rhs, line_number, rules)
    if source_links:
        return IdentifierTaint(
            classification="source_controlled",
            sources=tuple(source_links),
            trace=tuple(source_links),
            line_number=line_number,
        )
    identifiers = rules.expression_identifiers(rhs)
    if not identifiers:
        if _rhs_is_constant_or_literal(rhs, rules):
            return IdentifierTaint(
                classification="constant_or_literal",
                sources=(f"literal:line {line_number}",),
                trace=(f"literal expression at line {line_number}",),
                line_number=line_number,
            )
        return IdentifierTaint(
            classification="unknown",
            sources=(f"unknown_rhs:line {line_number}",),
            trace=(f"rhs at line {line_number} is not a simple literal or expression",),
            line_number=line_number,
        )
    children = [
        _classify_identifier_taint(name, state, param_names, rules)
        for name in identifiers
    ]
    classifications = [item.classification for item in children]
    sources = _unique_nonempty([source for item in children for source in item.sources])
    traces = _unique_nonempty([trace for item in children for trace in item.trace])
    if "source_controlled" in classifications:
        classification = "source_controlled"
    elif "parameter_controlled" in classifications:
        classification = "parameter_controlled"
    elif "unknown" in classifications:
        classification = "unknown"
    elif "internal_local" in classifications:
        classification = "internal_local"
    else:
        classification = "constant_or_literal"
    return IdentifierTaint(
        classification=classification,
        sources=tuple(sources),
        trace=tuple(traces),
        line_number=max((item.line_number for item in children), default=0),
    )


def _rhs_source_links(
    rhs: str,
    line_number: int,
    rules: SourceTaintRules,
) -> list[str]:
    links: list[str] = []
    masked = rules.mask_string_literals(rhs)
    for token in rules.source_tokens:
        if re.search(rf"\b{re.escape(token)}\b", masked):
            links.append(f"{token}:line {line_number}")
    for callee, _args in rules.iter_calls(masked) or ():
        source_name = rules.normalize_call(callee)
        if source_name in rules.source_calls:
            links.append(f"source_call:{source_name}:line {line_number}")
    return _unique_nonempty(links)


def _rhs_is_constant_or_literal(rhs: str, rules: SourceTaintRules) -> bool:
    text = rules.normalize_expression(rhs)
    if not text:
        return False
    if rules.constant_expression(text):
        return True
    stripped = rhs.strip()
    return bool(
        re.fullmatch(r'"[^"]*"', stripped)
        or re.fullmatch(r"'(?:\\.|[^'])'", stripped)
        or stripped in {"NULL", "null", "true", "false"}
    )


def _apply_update_taint(
    state: dict[str, IdentifierTaint],
    line: str,
    line_number: int,
) -> None:
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\b\s*(?:\+\+|--|\+=|-=)", line):
        name = match.group(1)
        existing = state.get(name)
        if existing is None:
            state[name] = IdentifierTaint(
                classification="internal_local",
                sources=(f"local_update:line {line_number}",),
                trace=(f"{name} updated locally at line {line_number}",),
                line_number=line_number,
            )
        elif existing.classification in {"constant_or_literal", "internal_local"}:
            state[name] = IdentifierTaint(
                classification="internal_local",
                sources=existing.sources or (f"local_update:line {line_number}",),
                trace=(*existing.trace[:5], f"{name} updated locally at line {line_number}"),
                line_number=line_number,
            )


def _classify_identifier_taint(
    identifier: str,
    state: Mapping[str, IdentifierTaint],
    param_names: Sequence[str],
    rules: SourceTaintRules,
) -> IdentifierTaint:
    if identifier in rules.source_tokens:
        return IdentifierTaint(
            classification="source_controlled",
            sources=(f"{identifier}:direct",),
            trace=(f"{identifier} is a process input token",),
        )
    if identifier in param_names:
        return IdentifierTaint(
            classification="parameter_controlled",
            sources=(f"parameter:{identifier}",),
            trace=(f"{identifier} is a function parameter",),
        )
    taint = state.get(identifier)
    if taint is not None:
        return taint
    return IdentifierTaint(
        classification="unknown",
        sources=(f"unresolved_identifier:{identifier}",),
        trace=(f"{identifier} has no recovered local definition before the write",),
    )


def _unique_nonempty(values: Sequence[str]) -> list[str]:
    rows: list[str] = []
    for value in values:
        text = str(value)
        if text and text not in rows:
            rows.append(text)
    return rows


__all__ = (
    "IdentifierTaint",
    "SourceTaintRules",
    "identifier_taint_before_line",
    "trace_expression_taint",
)
