"""Pattern helpers consumed only by the four shared discovery backends."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from binary_agent.discovery.base import DiscoveryContext
from binary_agent.ingest.loader import FunctionNode
from binary_agent.pipeline import CandidateState, CandidateStatus, ProofObligation
from binary_agent.taxonomy import get_vulnerability_spec
from binary_agent.utils.time import utc_timestamp


UNTRUSTED_TOKENS = ("argv", "input", "buf", "buffer", "query", "param", "recv", "read", "getenv", "cgi", "request")

_ALLOCATION_RE = re.compile(
    r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]*\)\s*)?"
    r"(?P<allocator>malloc|calloc|realloc|new)\s*\((?P<args>[^;]*)\)"
)
_RELEASE_RE = re.compile(
    r"\b(?P<release>free|kfree|delete|put_[A-Za-z0-9_]+|release_[A-Za-z0-9_]+|"
    r"kref_put|refcount_dec_and_test|atomic_dec_and_test)\s*\(\s*(?:&\s*)?"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
)
_FREE_CALL_START_RE = re.compile(r"\bfree\s*\(")
_ASSIGNMENT_OPERATOR = r"(?:<<|>>|[+\-*/%&|^])?=(?!=)"


@dataclass(frozen=True)
class CommandInjectionPattern:
    vulnerability_type: str = "command_injection"

    def discover(self, context: DiscoveryContext) -> list[CandidateState]:
        return _call_expr_module(
            context,
            vulnerability_type=self.vulnerability_type,
            call_names=("system", "popen"),
            sink_kind="command_execution",
            obligation="Prove attacker-controlled input reaches a shell command sink.",
            condition_builder=lambda sink, expr: f"{sink} receives command expression {expr}",
            predicate=lambda expr: _has_untrusted_token(expr) or not _first_arg(expr).startswith('"'),
        )


@dataclass(frozen=True)
class PathTraversalPattern:
    vulnerability_type: str = "path_traversal"

    def discover(self, context: DiscoveryContext) -> list[CandidateState]:
        return _call_expr_module(
            context,
            vulnerability_type=self.vulnerability_type,
            call_names=("fopen", "open", "unlink", "rename", "stat", "lstat"),
            sink_kind="filesystem_path",
            obligation="Prove attacker-controlled path input can escape the intended directory.",
            condition_builder=lambda sink, expr: f"{sink} uses path expression {expr}",
            predicate=lambda expr: ".." in expr or _has_untrusted_token(expr),
        )


@dataclass(frozen=True)
class FormatStringPattern:
    vulnerability_type: str = "format_string"

    def discover(self, context: DiscoveryContext) -> list[CandidateState]:
        states: list[CandidateState] = []
        for node in context.nodes:
            text = node.text or ""
            for match in re.finditer(r"\b(?P<sink>printf|fprintf|sprintf|snprintf|syslog)\s*\((?P<args>[^;]+)\);?", text):
                sink = match.group("sink")
                args = _split_args(match.group("args"))
                if not args:
                    continue
                format_arg_index = {
                    "printf": 0,
                    "fprintf": 1,
                    "sprintf": 1,
                    "snprintf": 2,
                    "syslog": 1,
                }.get(sink, 0)
                fmt = args[format_arg_index] if format_arg_index < len(args) else ""
                if fmt.strip().startswith('"'):
                    continue
                line = _line_number(text, match.start())
                line_text = _line_text(text, line)
                controlled = _has_untrusted_token(fmt)
                type_facts: dict[str, Any] = {"format_arg": fmt, "call_args": args}
                if controlled:
                    type_facts["classification_trace"] = _controlled_format_classification_trace(fmt, line_text)
                states.append(
                    _state(
                        context,
                        node,
                        vulnerability_type=self.vulnerability_type,
                        line_number=line,
                        line_text=line_text,
                        source={"kind": "format_expression", "expression": fmt},
                        sink={"name": sink, "kind": "format_parser"},
                        type_facts=type_facts,
                        obligation="Prove attacker-controlled data is used as a format string.",
                        condition=f"{sink} format argument is non-literal expression {fmt}",
                        blockers=[] if controlled else ["attacker_controlled_format"],
                    )
                )
        return states


@dataclass(frozen=True)
class UnsafeFileWritePattern:
    vulnerability_type: str = "unsafe_file_write"

    def discover(self, context: DiscoveryContext) -> list[CandidateState]:
        states: list[CandidateState] = []
        for node in context.nodes:
            text = node.text or ""
            for match in re.finditer(r"\bfopen\s*\((?P<args>[^;]+)\);?", text):
                args = _split_args(match.group("args"))
                if len(args) < 2:
                    continue
                mode = args[1].strip().strip('"')
                if not any(ch in mode for ch in ("w", "a", "+")):
                    continue
                path_expr = args[0].strip()
                line = _line_number(text, match.start())
                states.append(
                    _state(
                        context,
                        node,
                        vulnerability_type=self.vulnerability_type,
                        line_number=line,
                        line_text=_line_text(text, line),
                        source={"kind": "path_expression", "expression": path_expr},
                        sink={"name": "fopen", "kind": "file_write", "mode": mode},
                        type_facts={"path_expr": path_expr, "mode": mode},
                        obligation="Prove attacker-controlled path or content reaches a file write sink.",
                        condition=f"fopen writes to {path_expr} with mode {mode}",
                        blockers=[] if _has_untrusted_token(path_expr) else ["attacker_controlled_path_or_content"],
                    )
                )
            for match in re.finditer(r"\bopen\s*\((?P<args>[^;]+O_(?:WRONLY|CREAT|TRUNC|APPEND)[^;]+)\);?", text):
                args = _split_args(match.group("args"))
                path_expr = args[0].strip() if args else ""
                line = _line_number(text, match.start())
                states.append(
                    _state(
                        context,
                        node,
                        vulnerability_type=self.vulnerability_type,
                        line_number=line,
                        line_text=_line_text(text, line),
                        source={"kind": "path_expression", "expression": path_expr},
                        sink={"name": "open", "kind": "file_write"},
                        type_facts={"path_expr": path_expr, "flags": match.group("args")},
                        obligation="Prove attacker-controlled path or content reaches a file write sink.",
                        condition=f"open writes to {path_expr}",
                        blockers=[] if _has_untrusted_token(path_expr) else ["attacker_controlled_path_or_content"],
                    )
                )
        return states


@dataclass(frozen=True)
class HardcodedCredentialPattern:
    vulnerability_type: str = "hardcoded_credential"

    def discover(self, context: DiscoveryContext) -> list[CandidateState]:
        states: list[CandidateState] = []
        pattern = re.compile(
            r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*(?:pass|passwd|password|secret|token|api_key|apikey)[A-Za-z0-9_]*)\b\s*(?:=|:)\s*\"(?P<value>[^\"]{4,})\"",
            re.IGNORECASE,
        )
        for node in context.nodes:
            text = node.text or ""
            for match in pattern.finditer(text):
                line = _line_number(text, match.start())
                states.append(
                    _state(
                        context,
                        node,
                        vulnerability_type=self.vulnerability_type,
                        line_number=line,
                        line_text=_line_text(text, line),
                        source={"kind": "literal", "name": match.group("name")},
                        sink={"name": "credential_literal", "kind": "secret_storage"},
                        type_facts={"credential_name": match.group("name"), "literal_length": len(match.group("value"))},
                        obligation="Prove the secret is embedded in the binary or configuration.",
                        condition=f"{match.group('name')} is assigned a non-empty literal",
                        blockers=[],
                    )
                )
        return states


@dataclass(frozen=True)
class AuthBypassPattern:
    vulnerability_type: str = "auth_bypass"

    def discover(self, context: DiscoveryContext) -> list[CandidateState]:
        states: list[CandidateState] = []
        for node in context.nodes:
            name = node.record.name.lower()
            text = node.text or ""
            if not any(token in name for token in ("auth", "login", "permission", "access")):
                continue
            if not re.search(r"\breturn\s+(?:1|true|0x1)\s*;", text, re.IGNORECASE):
                continue
            if re.search(r"\b(strcmp|memcmp|crypt|hash|verify|token)\b", text):
                continue
            line = _line_number(text, re.search(r"\breturn\s+(?:1|true|0x1)\s*;", text, re.IGNORECASE).start())
            states.append(
                _state(
                    context,
                    node,
                    vulnerability_type=self.vulnerability_type,
                    line_number=line,
                    line_text=_line_text(text, line),
                    source={"kind": "request_context", "expression": node.record.name},
                    sink={"name": "authorization_decision", "kind": "auth_gate"},
                    type_facts={"function_name": node.record.name, "decision": "unconditional_allow"},
                    obligation="Prove an authorization decision can be reached without credential verification.",
                    condition=f"{node.record.name} returns allow without a verifier call",
                    blockers=[],
                )
            )
        return states


@dataclass(frozen=True)
class UseAfterFreePattern:
    vulnerability_type: str = "use_after_free"

    def discover(self, context: DiscoveryContext) -> list[CandidateState]:
        states: list[CandidateState] = []
        for node in context.nodes:
            text = node.text or ""
            allocations = _allocation_sites(text, _ALLOCATION_RE)
            for release in _RELEASE_RE.finditer(text):
                var = release.group("var")
                if _is_release_guarded_by_return(text, release.end()):
                    continue
                use = _first_stale_use(text, var, release.end())
                if use is None:
                    continue
                use_start, use_kind, use_expr, sink_name = use
                release_line = _line_number(text, release.start())
                use_line = _line_number(text, use_start)
                allocation = allocations.get(var, {})
                blockers = [] if allocation else ["allocation_site_unknown"]
                operation_address = (
                    _call_operation_address(node, use_line, sink_name)
                    if sink_name != "direct_memory_access"
                    else _memory_operation_address(node, use_line)
                )
                if not operation_address:
                    blockers.append("exact_lifetime_sink_unresolved")
                states.append(
                    _state(
                        context,
                        node,
                        vulnerability_type=self.vulnerability_type,
                        line_number=use_line,
                        line_text=_line_text(text, use_line),
                        source={
                            "kind": "lifetime_end",
                            "expression": f"{release.group('release')}({var})",
                            "line_number": release_line,
                        },
                        sink={
                            "name": sink_name,
                            "kind": use_kind,
                            "stale_alias": var,
                            **({"operation_address": operation_address} if operation_address else {}),
                        },
                        type_facts={
                            "allocation_site": allocation,
                            "free_site": {
                                "line_number": release_line,
                                "line_text": _line_text(text, release_line),
                                "release": release.group("release"),
                                "variable": var,
                            },
                            "use_site": {
                                "line_number": use_line,
                                "line_text": _line_text(text, use_line),
                                "use_kind": use_kind,
                                "expression": use_expr,
                            },
                            "stale_alias": var,
                            "trigger_sequence": [
                                {"event": "release", "line_number": release_line},
                                {"event": "use", "line_number": use_line},
                            ],
                            "llm_may_not_prove": [
                                "same_object_identity",
                                "exploitability",
                                "remote_code_execution",
                                "attacker_controlled_reallocation",
                            ],
                        },
                        obligation="Prove the same allocated object is released and then used through a stale alias.",
                        condition=f"{var} is released at line {release_line} and used again at line {use_line}",
                        blockers=blockers,
                        required_evidence=[
                            "allocation_site",
                            "free_or_release_site",
                            "same_object_identity",
                            "post_free_use_site",
                            "trigger_sequence_reaches_use",
                        ],
                    )
                )
        states.extend(_cross_function_lifetime_candidates(context))
        return states


@dataclass(frozen=True)
class DoubleFreePattern:
    vulnerability_type: str = "double_free"

    def discover(self, context: DiscoveryContext) -> list[CandidateState]:
        states: list[CandidateState] = []
        for node in context.nodes:
            text = node.text or ""
            releases_by_var: dict[str, list[re.Match[str]]] = {}
            for release in _RELEASE_RE.finditer(text):
                releases_by_var.setdefault(release.group("var"), []).append(release)
            for var, releases in releases_by_var.items():
                for first, second in zip(releases, releases[1:]):
                    allocation = _allocation_site_before(text, var, first.start())
                    if not allocation:
                        continue
                    between = text[first.end() : second.start()]
                    if _intervening_lifetime_change(between, var) or _obvious_path_break(between):
                        continue
                    first_line = _line_number(text, first.start())
                    second_line = _line_number(text, second.start())
                    first_address = _call_operation_address(node, first_line, first.group("release"))
                    second_address = _call_operation_address(node, second_line, second.group("release"))
                    states.append(
                        _state(
                            context,
                            node,
                            vulnerability_type=self.vulnerability_type,
                            line_number=second_line,
                            line_text=_line_text(text, second_line),
                            source={
                                "kind": "first_release",
                                "expression": f"{first.group('release')}({var})",
                                "line_number": first_line,
                            },
                            sink={
                                "name": second.group("release"),
                                "kind": "second_release",
                                "released_object": var,
                                **({"operation_address": second_address} if second_address else {}),
                            },
                            type_facts={
                                "path_is_valid": False,
                                "allocation_site": allocation,
                                "same_local_object_identity": {
                                    "variable": var,
                                    "basis": "same local value with no intervening assignment",
                                    "static": True,
                                },
                                "first_release_site": {
                                    "line_number": first_line,
                                    "line_text": _line_text(text, first_line),
                                    "release": first.group("release"),
                                    **({"operation_address": first_address} if first_address else {}),
                                },
                                "second_release_site": {
                                    "line_number": second_line,
                                    "line_text": _line_text(text, second_line),
                                    "release": second.group("release"),
                                    **({"operation_address": second_address} if second_address else {}),
                                },
                                "trigger_sequence": [
                                    {"event": "allocation", "line_number": allocation["line_number"]},
                                    {"event": "release", "line_number": first_line},
                                    {"event": "release", "line_number": second_line},
                                ],
                                "llm_may_not_prove": [
                                    "dynamic_same_object_lifetime",
                                    "exploitability",
                                    "remote_code_execution",
                                ],
                            },
                            obligation="Dynamically confirm that one allocated object reaches both release operations.",
                            condition=(
                                f"{var} is released at lines {first_line} and {second_line} "
                                "without an intervening assignment"
                            ),
                            blockers=[
                                "dynamic_same_object_lifetime_unproven",
                                *([] if second_address else ["exact_lifetime_sink_unresolved"]),
                            ],
                            required_evidence=[
                                "allocation_site",
                                "same_local_object_identity",
                                "first_release_site",
                                "second_release_site",
                                "no_intervening_assignment_or_reallocation",
                                "trigger_sequence_reaches_both_releases",
                                "dynamic_lifetime_confirmation",
                            ],
                        )
                    )
                    break
            states.extend(_indexed_slot_double_free_candidates(context, node, text))
            states.extend(_indexed_owner_alias_underflow_candidates(context, node, text))
        return states


def _indexed_slot_double_free_candidates(
    context: DiscoveryContext,
    node: FunctionNode,
    text: str,
) -> list[CandidateState]:
    """Find repeated releases of the same array-backed ownership slot.

    Decompilers commonly render a heap-owner table as ``table[index]`` or as a
    casted version of that expression.  It is not a local allocation variable,
    so the ordinary double-free detector cannot represent it.  This detector
    records the exact slot identity and deliberately leaves dynamic object and
    control-flow identity as proof obligations.
    """

    calls: dict[str, list[tuple[int, str]]] = {}
    for start, argument in _free_calls(text):
        identity = _indexed_slot_identity(argument)
        if identity:
            calls.setdefault(identity, []).append((start, argument))
    states: list[CandidateState] = []
    for identity, releases in sorted(calls.items()):
        for first, second in zip(releases, releases[1:]):
            first_start, first_argument = first
            second_start, second_argument = second
            between = text[first_start : second_start]
            if _indexed_slot_is_reinitialized(between, identity) or _indexed_slot_has_complex_control_flow(between):
                continue
            first_line = _line_number(text, first_start)
            second_line = _line_number(text, second_start)
            first_address = _call_operation_address(node, first_line, "free")
            second_address = _call_operation_address(node, second_line, "free")
            blockers = [
                "dynamic_indexed_slot_object_identity_unproven",
                "indexed_slot_path_feasibility_unproven",
            ]
            if not second_address:
                blockers.append("exact_lifetime_sink_unresolved")
            states.append(
                _state(
                    context,
                    node,
                    vulnerability_type="double_free",
                    line_number=second_line,
                    line_text=_line_text(text, second_line),
                    source={
                        "kind": "first_release",
                        "expression": f"free({first_argument})",
                        "line_number": first_line,
                    },
                    sink={
                        "name": "free",
                        "kind": "second_release",
                        "released_object": identity,
                        **({"operation_address": second_address} if second_address else {}),
                    },
                    type_facts={
                        "path_is_valid": False,
                        "same_indexed_slot_identity": {
                            "slot": identity,
                            "first_argument": first_argument,
                            "second_argument": second_argument,
                            "basis": "same canonical array-slot expression with no direct slot reinitialization",
                            "static": True,
                        },
                        "allocation_site": {},
                        "first_release_site": {
                            "line_number": first_line,
                            "line_text": _line_text(text, first_line),
                            "release": "free",
                            "argument": first_argument,
                            **({"operation_address": first_address} if first_address else {}),
                        },
                        "second_release_site": {
                            "line_number": second_line,
                            "line_text": _line_text(text, second_line),
                            "release": "free",
                            "argument": second_argument,
                            **({"operation_address": second_address} if second_address else {}),
                        },
                        "trigger_sequence": [
                            {"event": "slot_release", "line_number": first_line},
                            {"event": "slot_release", "line_number": second_line},
                        ],
                        "llm_may_not_prove": [
                            "dynamic_indexed_slot_object_identity",
                            "path_feasibility",
                            "exploitability",
                            "remote_code_execution",
                        ],
                    },
                    obligation="Dynamically confirm that one indexed ownership slot reaches both free operations without reinitialization.",
                    condition=(
                        f"ownership slot {identity} is released at lines {first_line} and {second_line} "
                        "without a direct slot reinitialization"
                    ),
                    blockers=blockers,
                    required_evidence=[
                        "same_indexed_slot_identity",
                        "first_release_site",
                        "second_release_site",
                        "no_slot_reinitialization",
                        "trigger_sequence_reaches_both_releases",
                        "dynamic_lifetime_confirmation",
                    ],
                )
            )
            # Adjacent pairs are enough to surface the ownership lifecycle;
            # further pairs are diagnostic duplicates of the same mechanism.
            break
    return states


def _indexed_slot_identity(argument: str) -> str:
    expression = _strip_pointer_casts(argument)
    expression = _strip_balanced_outer_parentheses(expression)
    match = re.fullmatch(
        r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<index>.+)\s*\]",
        expression,
    )
    if not match or not _balanced_parentheses(match.group("index")):
        return ""
    base = match.group("base")
    index = re.sub(r"\s+", "", match.group("index"))
    return f"{base}[{index}]"


def _strip_pointer_casts(expression: str) -> str:
    value = str(expression or "").strip()
    while True:
        stripped = re.sub(
            r"^\(\s*(?:(?:unsigned|signed)\s+)?(?:void|char|short|int|long|size_t|u?int\d+_t|undefined\d*)\s*\*?\s*\)\s*",
            "",
            value,
        )
        if stripped == value:
            return value
        value = stripped


def _strip_balanced_outer_parentheses(expression: str) -> str:
    value = expression.strip()
    while value.startswith("(") and value.endswith(")") and _balanced_parentheses(value[1:-1]):
        value = value[1:-1].strip()
    return value


def _indexed_slot_is_reinitialized(text: str, identity: str) -> bool:
    base, _separator, index = identity.partition("[")
    index = index.rstrip("]")
    direct_store = re.compile(
        rf"\b{re.escape(base)}\s*\[\s*{re.escape(index)}\s*\]\s*{_ASSIGNMENT_OPERATOR}"
    )
    return bool(direct_store.search(text))


def _indexed_slot_has_complex_control_flow(text: str) -> bool:
    """Keep the simple repeated-slot rule to straight-line ownership code."""

    return bool(
        re.search(r"[{}]", text)
        or re.search(r"\b(?:if|else|for|while|do|switch|case|goto|return|break|continue)\b", text)
        or re.search(r"^\s*[A-Za-z_][A-Za-z0-9_]*:\s*$", text, re.MULTILINE)
    )


def _indexed_owner_alias_underflow_candidates(
    context: DiscoveryContext,
    node: FunctionNode,
    text: str,
) -> list[CandidateState]:
    """Recover an owner-table alias hazard rooted in an unguarded index-1 read.

    A repeated textual free is neither necessary nor sufficient for this
    lifetime pattern.  Some parsers copy entries between indexed ownership
    tables and later use an index-minus-one metadata lookup to decide which
    aliases a cleanup loop excludes.  If the lower bound is absent, that
    bookkeeping can select an overlapping cleanup range.  The candidate is
    intentionally a double-free *proof obligation*: runtime object identity,
    range overlap, and process reachability remain required.
    """

    aliases = _indexed_owner_aliases(text)
    if not aliases:
        return []
    free_calls: list[tuple[int, str, str]] = []
    for start, argument in _free_calls(text):
        identity = _indexed_slot_identity(argument)
        if not identity:
            continue
        table, _separator, index = identity.partition("[")
        free_calls.append((start, table, index.rstrip("]")))
    if not free_calls:
        return []
    states: list[CandidateState] = []
    emitted_tables: set[str] = set()
    for alias in aliases:
        table = str(alias["table"])
        if table in emitted_tables:
            continue
        releases = [item for item in free_calls if item[1] == table]
        if not releases:
            continue
        unsafe_lookback = _unguarded_index_minus_one_lookback(text, table, alias)
        if unsafe_lookback is None:
            continue
        release_start, _release_table, release_index = releases[0]
        release_line = _line_number(text, release_start)
        operation_address = _call_operation_address(node, release_line, "free")
        if not operation_address:
            # Exact-sink resolution is part of the vertical slice.  Preserve
            # the candidate for another resolver rather than claiming a call.
            continue
        lookback_line, metadata_table, lookback_index, lookback_text = unsafe_lookback
        states.append(
            _state(
                context,
                node,
                vulnerability_type="double_free",
                line_number=release_line,
                line_text=_line_text(text, release_line),
                source={
                    "kind": "indexed_owner_alias",
                    "expression": f"{table}[{alias['destination_index']}] = {table}[{alias['source_index']}]",
                    "line_number": int(alias["line_number"]),
                },
                sink={
                    "name": "free",
                    "kind": "indexed_owner_cleanup_release",
                    "released_object": f"{table}[{release_index}]",
                    "operation_address": operation_address,
                },
                type_facts={
                    "path_is_valid": False,
                    "indexed_owner_alias": {
                        "table": table,
                        "destination_index": alias["destination_index"],
                        "source_index": alias["source_index"],
                        "line_number": alias["line_number"],
                        "line_text": alias["line_text"],
                    },
                    "unguarded_index_minus_one_lookup": {
                        "metadata_table": metadata_table,
                        "index": lookback_index,
                        "line_number": lookback_line,
                        "line_text": lookback_text,
                        "lower_bound_guard": "absent",
                    },
                    "cleanup_release_site": {
                        "table": table,
                        "index": release_index,
                        "line_number": release_line,
                        "line_text": _line_text(text, release_line),
                        "operation_address": operation_address,
                    },
                    "trigger_sequence": [
                        {"event": "owner_alias_copy", "line_number": alias["line_number"]},
                        {"event": "unguarded_index_minus_one_lookup", "line_number": lookback_line},
                        {"event": "owner_cleanup_release", "line_number": release_line},
                    ],
                    "llm_may_not_prove": [
                        "dynamic_indexed_owner_identity",
                        "alias_range_overlap",
                        "process_trigger_reaches_cleanup",
                        "exploitability",
                    ],
                },
                obligation=(
                    "Dynamically confirm that an unguarded index-minus-one metadata lookup permits an aliased "
                    "owner-table entry to reach the exact cleanup free twice."
                ),
                condition=(
                    f"{table} aliases entries while {metadata_table}[{lookback_index} - 1] is consulted without "
                    "a lower-bound guard before cleanup"
                ),
                blockers=[
                    "dynamic_indexed_owner_identity_unproven",
                    "owner_alias_range_overlap_unproven",
                    "process_trigger_reaches_cleanup_unproven",
                ],
                required_evidence=[
                    "indexed_owner_alias",
                    "unguarded_index_minus_one_lookup",
                    "cleanup_release_site",
                    "dynamic_same_object_lifetime",
                    "trigger_sequence_reaches_cleanup",
                    "exact_cleanup_free_reached",
                ],
            )
        )
        emitted_tables.add(table)
    return states


def _indexed_owner_aliases(text: str) -> list[dict[str, Any]]:
    aliases: list[dict[str, Any]] = []
    pattern = re.compile(
        r"\b(?P<table>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<destination>[^\]\n]+)\s*\]"
        r"\s*=\s*(?:\([^;=]*?\)\s*)?"
        r"(?P=table)\s*\[\s*(?P<source>[^\]\n]+)\s*\]\s*;"
    )
    for match in pattern.finditer(text):
        destination = re.sub(r"\s+", "", match.group("destination"))
        source = re.sub(r"\s+", "", match.group("source"))
        if not destination or not source or destination == source:
            continue
        line_number = _line_number(text, match.start())
        aliases.append(
            {
                "table": match.group("table"),
                "destination_index": destination,
                "source_index": source,
                "line_number": line_number,
                "line_text": _line_text(text, line_number),
            }
        )
    return aliases


def _unguarded_index_minus_one_lookback(
    text: str,
    owner_table: str,
    alias: Mapping[str, Any],
) -> tuple[int, str, str, str] | None:
    """Return one lookback only when its enclosing condition lacks ``index > 0``."""

    # The metadata table need not be the owner table.  Keep the parser small:
    # it recognizes only a direct ``table[index - 1]`` subscript and refuses
    # to infer a guard across unrelated blocks.
    pattern = re.compile(
        r"\b(?P<table>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*"
        r"(?P<index>[A-Za-z_][A-Za-z0-9_]*)\s*-\s*1\s*\]"
    )
    for match in pattern.finditer(text):
        index = match.group("index")
        # Alias/range bookkeeping must share at least the relevant owner
        # index vocabulary; otherwise this is an unrelated array lookback.
        if index not in {str(alias["destination_index"]), str(alias["source_index"])}:
            # A cleanup release can use a third cursor, but require it to be
            # the same table's release index below before accepting it.
            release_indices = {
                identity.partition("[")[2].rstrip("]")
                for _start, argument in _free_calls(text)
                if (identity := _indexed_slot_identity(argument)) and identity.startswith(owner_table + "[")
            }
            if index not in release_indices:
                continue
        line_number = _line_number(text, match.start())
        line_text = _line_text(text, line_number)
        condition_window = text[max(0, text.rfind("if", max(0, match.start() - 320), match.start())) : match.end()]
        if _index_has_lower_bound_guard(condition_window, index):
            continue
        return line_number, match.group("table"), index, line_text
    return None


def _index_has_lower_bound_guard(condition: str, index: str) -> bool:
    escaped = re.escape(index)
    return bool(
        re.search(rf"(?:\(\s*long\s*\)\s*)?{escaped}\s*<\s*1\b", condition)
        or re.search(rf"(?:\(\s*long\s*\)\s*)?{escaped}\s*<=\s*0\b", condition)
        or re.search(rf"\b0\s*>=\s*(?:\(\s*long\s*\)\s*)?{escaped}\b", condition)
    )


@dataclass(frozen=True)
class InvalidFreePattern:
    vulnerability_type: str = "invalid_free"

    def discover(self, context: DiscoveryContext) -> list[CandidateState]:
        states: list[CandidateState] = []
        for node in context.nodes:
            text = node.text or ""
            for release_start, argument in _free_calls(text):
                derivation = _non_base_allocation_derivation(text, argument, release_start)
                if not derivation:
                    continue
                release_line = _line_number(text, release_start)
                operation_address = _call_operation_address(node, release_line, "free")
                blockers = ["dynamic_non_base_release_unproven"]
                if not operation_address:
                    blockers.append("exact_lifetime_sink_unresolved")
                allocation = derivation["allocation_site"]
                derived_pointer = derivation["derived_pointer"]
                states.append(
                    _state(
                        context,
                        node,
                        vulnerability_type=self.vulnerability_type,
                        line_number=release_line,
                        line_text=_line_text(text, release_line),
                        source={
                            "kind": "allocation_derived_pointer",
                            "expression": derivation["base_variable"],
                            "line_number": allocation["line_number"],
                        },
                        sink={
                            "name": "free",
                            "kind": "non_base_release",
                            "released_pointer": argument,
                            **({"operation_address": operation_address} if operation_address else {}),
                        },
                        type_facts={
                            "path_is_valid": False,
                            "allocation_site": allocation,
                            "derived_pointer": derived_pointer,
                            "invalid_release_site": {
                                "line_number": release_line,
                                "line_text": _line_text(text, release_line),
                                "release": "free",
                                "argument": argument,
                                **({"operation_address": operation_address} if operation_address else {}),
                            },
                            "trigger_sequence": [
                                {"event": "allocation", "line_number": allocation["line_number"]},
                                {
                                    "event": "derive_non_base_pointer",
                                    "line_number": derived_pointer["line_number"],
                                },
                                {"event": "release", "line_number": release_line},
                            ],
                            "llm_may_not_prove": [
                                "runtime_object_identity",
                                "release_address_is_not_object_base",
                                "exploitability",
                            ],
                        },
                        obligation=(
                            "Dynamically confirm that free receives a non-base address "
                            "within the same allocated object."
                        ),
                        condition=(
                            f"free receives {argument}, derived from allocation base "
                            f"{derivation['base_variable']} with offset {derived_pointer['offset_expression']}"
                        ),
                        blockers=blockers,
                        required_evidence=[
                            "allocation_site",
                            "allocation_derived_pointer",
                            "exact_release_site",
                            "runtime_object_identity",
                            "release_address_is_not_object_base",
                            "native_invalid_release_observed",
                        ],
                    )
                )
        return states


def _call_expr_module(
    context: DiscoveryContext,
    *,
    vulnerability_type: str,
    call_names: tuple[str, ...],
    sink_kind: str,
    obligation: str,
    condition_builder: Callable[[str, str], str],
    predicate: Callable[[str], bool],
) -> list[CandidateState]:
    call_pattern = "|".join(re.escape(name) for name in call_names)
    call_re = re.compile(rf"\b(?P<sink>{call_pattern})\s*\((?P<args>[^;]+)\);?")
    states: list[CandidateState] = []
    for node in context.nodes:
        text = node.text or ""
        for match in call_re.finditer(text):
            args = match.group("args").strip()
            first_arg = _first_arg(args)
            if not predicate(args):
                continue
            line = _line_number(text, match.start())
            states.append(
                _state(
                    context,
                    node,
                    vulnerability_type=vulnerability_type,
                    line_number=line,
                    line_text=_line_text(text, line),
                    source={"kind": "expression", "expression": first_arg},
                    sink={"name": match.group("sink"), "kind": sink_kind},
                    type_facts={"call_args": args, "primary_arg": first_arg},
                    obligation=obligation,
                    condition=condition_builder(match.group("sink"), first_arg),
                    blockers=[] if _has_untrusted_token(args) else ["attacker_controlled_input"],
                )
            )
    return states


def _state(
    context: DiscoveryContext,
    node: FunctionNode,
    *,
    vulnerability_type: str,
    line_number: int,
    line_text: str,
    source: Mapping[str, Any],
    sink: Mapping[str, Any],
    type_facts: Mapping[str, Any],
    obligation: str,
    condition: str,
    blockers: list[str],
    required_evidence: list[str] | None = None,
) -> CandidateState:
    sink_name = str(sink.get("name") or sink.get("kind") or "sink")
    candidate_id = _candidate_id(context.manifest.binary, node.record.name, line_number, vulnerability_type, sink_name, line_text)
    proof = ProofObligation(
        obligation_id=f"{candidate_id}:{vulnerability_type}",
        description=obligation,
        condition=condition,
        required_evidence=list(required_evidence or ["grounded_source", "sink_semantics", "reachability"]),
        status="open" if blockers else "satisfied",
        evidence_refs=[node.record.relative_path],
    )
    class_spec = get_vulnerability_spec(vulnerability_type)
    return CandidateState(
        candidate_id=candidate_id,
        vulnerability_type=vulnerability_type,
        status=CandidateStatus.NEEDS_REFINEMENT.value if blockers else CandidateStatus.CANDIDATE.value,
        target={"binary": context.manifest.binary, "component": context.manifest.binary},
        location={
            "function_name": node.record.name,
            "address": node.record.address,
            "relative_path": node.record.relative_path,
            "line_number": line_number,
            "line_text": line_text,
        },
        source=dict(source),
        sink=dict(sink),
        type_facts={"evidence": [line_text], "path_is_valid": True, **dict(type_facts)},
        proof_obligations=[proof.to_dict()],
        blockers=list(blockers),
        metadata={
            "backend": class_spec.backend,
            "proof_policy": class_spec.proof_policy,
            "effect_kind": class_spec.effect_kind,
        },
    )


def _dedupe_states(states: list[CandidateState]) -> list[CandidateState]:
    deduped: dict[str, CandidateState] = {}
    for state in states:
        deduped.setdefault(state.candidate_id, state)
    return list(deduped.values())


def _candidate_id(*parts: Any) -> str:
    raw = "|".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:20]


def _has_untrusted_token(expr: str) -> bool:
    lowered = (expr or "").lower()
    return any(token in lowered for token in UNTRUSTED_TOKENS)


def _controlled_format_classification_trace(fmt: str, line_text: str) -> dict[str, Any]:
    return {
        "source_to_write": {
            "complete": True,
            "roles": {
                "format_argument": {
                    "role": "format_argument",
                    "expr": fmt.strip(),
                    "classification": "source_controlled",
                    "controlled": True,
                    "complete": True,
                    "evidence": [line_text],
                }
            },
        },
        "reachability_dataflow": {
            "graph": {
                "path_is_valid": True,
                "has_real_path": True,
            }
        },
    }


def _first_arg(args: str) -> str:
    split = _split_args(args)
    return split[0].strip() if split else ""


def _split_args(args: str) -> list[str]:
    result: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    escaped = False
    for ch in args or "":
        if quote:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
            current.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth:
            depth -= 1
        if ch == "," and depth == 0:
            result.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        result.append("".join(current).strip())
    return result


def _line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _line_text(text: str, line_number: int) -> str:
    lines = text.splitlines()
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()
    return ""


def _allocation_sites(text: str, allocation_re: re.Pattern[str]) -> dict[str, dict[str, Any]]:
    sites: dict[str, dict[str, Any]] = {}
    for match in allocation_re.finditer(text):
        line = _line_number(text, match.start())
        sites[match.group("var")] = {
            "line_number": line,
            "line_text": _line_text(text, line),
            "allocator": match.group("allocator"),
            "variable": match.group("var"),
            "arguments": match.group("args").strip(),
        }
    return sites


def _allocation_site_before(text: str, var: str, position: int) -> dict[str, Any]:
    allocations = [
        match
        for match in _ALLOCATION_RE.finditer(text, 0, position)
        if match.group("var") == var
    ]
    if not allocations:
        return {}
    allocation = allocations[-1]
    assignment_re = re.compile(rf"\b{re.escape(var)}\s*{_ASSIGNMENT_OPERATOR}")
    assignments = list(assignment_re.finditer(text, 0, position))
    if assignments and assignments[-1].start() != allocation.start():
        return {}
    line = _line_number(text, allocation.start())
    return {
        "line_number": line,
        "line_text": _line_text(text, line),
        "allocator": allocation.group("allocator"),
        "variable": var,
        "arguments": allocation.group("args").strip(),
    }


def _non_base_allocation_derivation(text: str, argument: str, position: int) -> dict[str, Any]:
    expression = argument.strip()
    derived_variable = ""
    derivation_position = position
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expression):
        derived_variable = expression
        assignments = list(
            re.finditer(
                rf"\b{re.escape(derived_variable)}\s*=\s*(?P<expression>[^;]+);",
                text[:position],
            )
        )
        if not assignments:
            return {}
        assignment = assignments[-1]
        expression = assignment.group("expression").strip()
        derivation_position = assignment.start()

    allocation_vars = {
        match.group("var")
        for match in _ALLOCATION_RE.finditer(text, 0, derivation_position)
    }
    for base_variable in sorted(allocation_vars):
        offset_expression = _nonzero_pointer_offset(expression, base_variable)
        if not offset_expression:
            continue
        allocation = _allocation_site_before(text, base_variable, position)
        if not allocation:
            continue
        derivation_line = _line_number(text, derivation_position)
        return {
            "base_variable": base_variable,
            "allocation_site": allocation,
            "derived_pointer": {
                "base_variable": base_variable,
                "derived_variable": derived_variable,
                "released_expression": argument.strip(),
                "derivation_expression": expression,
                "offset_expression": offset_expression,
                "line_number": derivation_line,
                "line_text": _line_text(text, derivation_line),
                "basis": "explicit pointer arithmetic from allocation base",
            },
        }
    return {}


def _nonzero_pointer_offset(expression: str, base_variable: str) -> str:
    expression = re.sub(
        r"\(\s*(?:(?:unsigned|signed)\s+)?(?:void|char|short|int|long|size_t|u?int\d+_t|undefined\d*)\s*\*?\s*\)",
        "",
        expression,
    ).strip()
    while expression.startswith("(") and expression.endswith(")"):
        inner = expression[1:-1].strip()
        if not inner or not _balanced_parentheses(inner):
            break
        expression = inner
    base = re.escape(base_variable)
    patterns = (
        rf"^\s*{base}\s*\+\s*(?P<offset>.+?)\s*$",
        rf"^\s*(?P<offset>.+?)\s*\+\s*{base}\s*$",
        rf"^\s*&\s*{base}\s*\[\s*(?P<offset>.+?)\s*\]\s*$",
    )
    for pattern in patterns:
        match = re.match(pattern, expression)
        if match is None:
            continue
        offset = match.group("offset").strip()
        try:
            if int(offset.rstrip("uUlL"), 0) == 0:
                return ""
        except ValueError:
            pass
        return offset
    return ""


def _free_calls(text: str) -> list[tuple[int, str]]:
    calls: list[tuple[int, str]] = []
    for match in _FREE_CALL_START_RE.finditer(text):
        open_index = text.find("(", match.start())
        depth = 1
        index = open_index + 1
        while index < len(text) and depth:
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                depth -= 1
            index += 1
        if depth == 0:
            calls.append((match.start(), text[open_index + 1 : index - 1].strip()))
    return calls


def _balanced_parentheses(text: str) -> bool:
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _intervening_lifetime_change(text: str, var: str) -> bool:
    return bool(re.search(rf"\b{re.escape(var)}\s*{_ASSIGNMENT_OPERATOR}", text))


def _obvious_path_break(text: str) -> bool:
    return bool(
        re.search(r"\b(?:return|goto|break|continue|else|case|default)\b", text)
        or re.search(r"\b(?:exit|_exit|quick_exit|abort|longjmp)\s*\(", text)
    )


def _first_stale_use(text: str, var: str, start: int) -> tuple[int, str, str, str] | None:
    window = text[start : start + 1200]
    reassignment_re = re.compile(rf"\b{re.escape(var)}\s*=\s*(?:malloc|calloc|realloc|new|\w+)")
    reassignment = reassignment_re.search(window)
    search_end = reassignment.start() if reassignment else len(window)
    search = window[:search_end]
    patterns: list[tuple[str, re.Pattern[str], str]] = [
        (
            "stale_pointer_dereference",
            re.compile(
                rf"(?:\*\s*{re.escape(var)}\b|\b{re.escape(var)}\s*\[[^\]]+\]|"
                rf"\b{re.escape(var)}\s*(?:->|\.)\s*[A-Za-z_][A-Za-z0-9_]*)"
            ),
            "direct_memory_access",
        ),
        (
            "callback_stale_pointer",
            re.compile(rf"\b(?P<func>add_timer|mod_timer|register_[A-Za-z0-9_]+|schedule_[A-Za-z0-9_]+)\s*\([^;]*\b{re.escape(var)}\b[^;]*\)"),
            "",
        ),
        (
            "stale_pointer_call_argument",
            re.compile(
                rf"\b(?!(?:free|kfree|delete|put_|release_|kref_put|refcount_dec_and_test|atomic_dec_and_test)\b)"
                rf"(?P<func>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\b{re.escape(var)}\b[^;]*\)"
            ),
            "",
        ),
    ]
    best: tuple[int, str, str, str] | None = None
    for kind, pattern, fixed_sink in patterns:
        match = pattern.search(search)
        if match is None:
            continue
        absolute = start + match.start()
        expr = match.group(0).strip()
        sink_name = fixed_sink or str(match.groupdict().get("func") or kind)
        if best is None or absolute < best[0]:
            best = (absolute, kind, expr, sink_name)
    return best


def _call_operation_address(node: FunctionNode, line_number: int, callee: str) -> str:
    line_rows = _operation_line_rows(node, line_number)
    line_addresses = {
        str(address)
        for row in line_rows
        for address in row.get("addresses", [])
    }
    calls = [
        call
        for call in node.record.pcode_calls or []
        if str(call.get("call_address") or "") in line_addresses
    ]
    # Decompiled source-to-address rows can be offset by compiler-generated
    # labels.  Never turn an unrelated nearby call into a lifetime sink: only
    # accept one p-code call whose resolved callee is the requested release.
    named = [call for call in calls if str(call.get("callee") or "").lstrip("_") == callee.lstrip("_")]
    addresses = {str(call.get("call_address") or "") for call in named}
    addresses.discard("")
    return next(iter(addresses)) if len(addresses) == 1 else ""


def _memory_operation_address(node: FunctionNode, line_number: int) -> str:
    line_rows = _operation_line_rows(node, line_number)
    addresses = {
        str(address)
        for row in line_rows
        for address in row.get("load_addresses", [])
    }
    if not addresses:
        line_addresses = {str(address) for row in line_rows for address in row.get("addresses", [])}
        addresses = {
            str(load.get("operation_address") or "")
            for load in node.record.pcode_loads or []
            if str(load.get("operation_address") or "") in line_addresses
        }
    addresses.discard("")
    return next(iter(addresses)) if len(addresses) == 1 else ""


def _operation_line_rows(node: FunctionNode, file_line_number: int) -> list[Mapping[str, Any]]:
    rows = list(node.record.c_line_addresses or [])
    return [
        row
        for line_number in (file_line_number, file_line_number - 3)
        for row in rows
        if int(row.get("line_number") or 0) == line_number
    ]


def _cross_function_lifetime_candidates(context: DiscoveryContext) -> list[CandidateState]:
    if not any(
        str(call.get("callee") or "").lstrip("_") == "free"
        for node in context.nodes
        for call in node.record.pcode_calls or []
    ):
        return []
    assigned_from_call = {
        match.group("global")
        for node in context.nodes
        for match in re.finditer(
            r"\b(?P<global>(?:DAT|PTR)_[A-Za-z0-9_]+)\s*=\s*"
            r"(?:\([^;=]+\)\s*)?(?:FUN_[A-Za-z0-9_]+|malloc|calloc|realloc)\s*\(",
            node.text or "",
        )
    }
    states: list[CandidateState] = []
    for node in context.nodes:
        globals_by_name = {
            str(ref.get("var_display") or ref.get("label") or ""): ref
            for ref in node.record.global_refs or []
            if int(ref.get("size_bytes") or 0) > 0
        }
        for load in node.record.pcode_loads or []:
            global_names = [
                str(name)
                for name in load.get("address_vars", [])
                if str(name) in globals_by_name
            ]
            operation_address = str(load.get("operation_address") or "")
            if not global_names or not operation_address:
                continue
            line_number = _file_line_for_operation(node, operation_address)
            line_text = _line_text(node.text or "", line_number)
            for global_name in global_names:
                constant_field = re.search(rf"\b{re.escape(global_name)}\s*\+\s*0x[0-9a-fA-F]+", line_text)
                if global_name not in assigned_from_call or "*(" not in line_text or constant_field is None:
                    continue
                states.append(
                    _state(
                        context,
                        node,
                        vulnerability_type="use_after_free",
                        line_number=line_number,
                        line_text=line_text,
                        source={
                            "kind": "cross_function_heap_lifetime",
                            "expression": global_name,
                        },
                        sink={
                            "name": "direct_memory_access",
                            "kind": "stale_pointer_dereference",
                            "stale_alias": global_name,
                            "operation_address": operation_address,
                        },
                        type_facts={
                            "allocation_site": {
                                "kind": "runtime_heap_object",
                                "status": "dynamic_identity_required",
                            },
                            "global_pointer": dict(globals_by_name[global_name]),
                            "use_site": {
                                "line_number": line_number,
                                "line_text": line_text,
                                "use_kind": "cross_function_global_pointer_load",
                                "operation_address": operation_address,
                                "read_width": int(load.get("read_width") or 0),
                            },
                            "stale_alias": global_name,
                            "llm_may_not_prove": [
                                "same_object_identity",
                                "release_precedes_use",
                                "exploitability",
                            ],
                        },
                        obligation="Dynamically prove that this global-derived address resolves into a released heap object.",
                        condition=f"{global_name} participates in the memory read at {operation_address}",
                        blockers=["dynamic_same_object_lifetime_unproven"],
                        required_evidence=[
                            "runtime_allocation_event",
                            "runtime_release_event",
                            "same_object_identity",
                            "exact_post_release_access",
                        ],
                    )
                )
    return states


def _file_line_for_operation(node: FunctionNode, operation_address: str) -> int:
    for row in node.record.c_line_addresses or []:
        addresses = [*row.get("addresses", []), *row.get("load_addresses", [])]
        if operation_address in {str(address) for address in addresses}:
            line_number = int(row.get("line_number") or 0)
            return line_number + 3 if (node.text or "").startswith("// Function:") else line_number
    return 0


def _is_release_guarded_by_return(text: str, start: int) -> bool:
    following = text[start : start + 120]
    return bool(re.match(r"\s*\)\s*;\s*(?:return|goto|break|continue)\b", following))
