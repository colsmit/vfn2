#!/usr/bin/env python3
"""Build ground-truth maps for ROMEO runs using Juliet manifest + source files."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple


CWE_RE = re.compile(r"CWE(\d+)")
FUNC_NAME_RE = re.compile(r"~?[A-Za-z_][A-Za-z0-9_]*$")
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
FUNC_PTR_DECL_ASSIGN_RE = re.compile(
    r"\(\s*\*\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\([^;]*\)\s*=\s*(?P<target>[A-Za-z_][A-Za-z0-9_]*)\b"
)
FUNC_PTR_ASSIGN_RE = re.compile(
    r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*;"
)
ARGV_TOKEN_RE = re.compile(r"\b(?:argc|argv|wargc|wargv)\b")
ARG_VOID_RE = re.compile(r"\(void\)\s*(?:argc|argv|wargc|wargv)\b")
ARG_UNREF_RE = re.compile(
    r"\bUNREFERENCED_PARAMETER\s*\(\s*(?:argc|argv|wargc|wargv)\s*\)"
)
ARG_INDEX_RE = re.compile(r"\b(?:argv|wargv)\s*\[")
ARG_DEREF_RE = re.compile(r"\*\s*(?:argv|wargv)\b")
ARG_OP_RE = re.compile(r"\b(?:argc|wargc)\b\s*[+\-*/%<>=!]")
CIN_TOKEN_RE = re.compile(r"\bcin\b")
GROUP_SUFFIX_RE = re.compile(r"^(?P<prefix>.+?_(?:\d+))(?P<suffix>[a-z])$")
ENTRY_SUFFIX_RE = re.compile(
    r"^(?P<prefix>.+?_(?:\d+))_(?P<suffix>bad|good|goodb2g|goodg2b)$",
    re.IGNORECASE,
)
MAIN_ENTRY_SUFFIXES = ("_good", "_bad", "_goodb2g", "_goodg2b")
GOOD_ENTRY_SUFFIXES = ("_good", "_goodb2g", "_goodg2b")
GOOD_ENTRY_NAMES = {"good", "goodb2g", "goodg2b"}
DEFAULT_INPUT_APIS = (
    "recv",
    "recvfrom",
    "recvmsg",
    "read",
    "readv",
    "pread",
    "pread64",
    "fgets",
    "fgets_s",
    "gets",
    "gets_s",
    "fread",
    "fscanf",
    "fscanf_s",
    "scanf",
    "scanf_s",
    "sscanf",
    "sscanf_s",
    "vscanf",
    "vfscanf",
    "vsscanf",
    "getc",
    "fgetc",
    "getchar",
    "getc_unlocked",
    "fgetc_unlocked",
    "getchar_unlocked",
    "getdelim",
    "getline",
    "fgetws",
    "getws",
    "getwc",
    "fgetwc",
    "getwchar",
    "fwscanf",
    "wscanf",
    "swscanf",
    "getenv",
    "getenv_s",
    "readfile",
    "wsarecv",
    "wsarecvfrom",
    "internetreadfile",
    "getenvironmentvariable",
    "getenvironmentvariablea",
    "getenvironmentvariablew",
)

@dataclass
class Flaw:
    line: int
    cwe: str


@dataclass
class FunctionRange:
    name: str
    start_line: int
    end_line: int


@dataclass
class FileTruth:
    source_path: str
    binary_key: str
    positives: List[str]
    negatives: List[str]
    ignored: List[str]
    flaws: List[Dict[str, object]]
    unmapped_flaws: List[Dict[str, object]]
    parse_errors: List[str]
    attacker_controlled: Dict[str, object] = field(default_factory=dict)


@dataclass
class SourceEntry:
    manifest_rel: str
    source_path: Path
    flaws: List[Flaw]
    binary_key: str
    group_key: str
    ranges: List[FunctionRange] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)
    source_lines: List[str] = field(default_factory=list)


def normalize_binary_key(value: str) -> str:
    stem = Path(value).name
    if stem.lower().startswith("linked-"):
        stem = stem[len("linked-") :]
    return Path(stem).stem.lower()


def _read_allowlist(path: Path) -> List[str]:
    lines: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def load_allowlist_keys(path: Path) -> Set[str]:
    keys: Set[str] = set()
    for entry in _read_allowlist(path):
        entry_path = Path(entry)
        ext = entry_path.suffix.lower()
        if ext in {".h", ".hpp"}:
            continue
        if ext in {".c", ".cc", ".cpp", ".cxx", ".o"}:
            entry_path = entry_path.with_suffix("")
        key = normalize_binary_key(entry_path.name)
        if key:
            keys.add(key)
    return keys


def _group_key_from_name(name: str) -> str:
    stem = Path(name).stem
    match = GROUP_SUFFIX_RE.match(stem)
    if match:
        return match.group("prefix")
    match = ENTRY_SUFFIX_RE.match(stem)
    if match:
        return match.group("prefix")
    return stem


def _is_c_identifier(name: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name))


def _demangle_symbols(symbols: Sequence[str]) -> List[str]:
    if not symbols:
        return []
    cxxfilt = shutil.which("c++filt")
    if not cxxfilt:
        return list(symbols)
    joined = "\n".join(symbols) + "\n"
    result = subprocess.run(
        [cxxfilt],
        input=joined,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return list(symbols)
    lines = result.stdout.splitlines()
    if len(lines) != len(symbols):
        return list(symbols)
    return [line.strip() for line in lines]


def _demangled_base(name: str) -> str:
    base = name.split("(", 1)[0].strip()
    if "::" in base:
        base = base.split("::")[-1].strip()
    return base


def _is_entry_base(base: str, demangled_full: str) -> bool:
    lowered = base.lower()
    if lowered.endswith(MAIN_ENTRY_SUFFIXES):
        return True
    if lowered in {"bad", "good", "goodb2g", "goodg2b"}:
        return "cwe" in demangled_full.lower()
    return False


def _classify_entry_symbol(base: str, demangled_full: str) -> Optional[str]:
    if not _is_entry_base(base, demangled_full):
        return None
    if not _is_c_identifier(base):
        return None
    lowered = base.lower()
    if lowered == "bad" or lowered.endswith("_bad"):
        return "bad"
    if lowered in GOOD_ENTRY_NAMES or lowered.endswith(GOOD_ENTRY_SUFFIXES):
        return "good"
    return None


def _collect_entry_functions(objects: Sequence[Path], nm_path: str) -> List[str]:
    good_syms: Set[str] = set()
    bad_syms: Set[str] = set()
    for obj in objects:
        result = subprocess.run(
            [nm_path, "--defined-only", str(obj)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            continue
        symbols: List[Tuple[str, str]] = []
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            if len(parts) == 2:
                sym_type, sym_name = parts
            else:
                sym_type, sym_name = parts[-2], parts[-1]
            if sym_type not in {"T", "t"}:
                continue
            symbols.append((sym_type, sym_name))
        if not symbols:
            continue
        mangled_names = [sym_name for _, sym_name in symbols]
        demangled = _demangle_symbols(mangled_names)
        for (_, sym_name), demangled_name in zip(symbols, demangled):
            base = _demangled_base(demangled_name)
            entry_type = _classify_entry_symbol(base, demangled_name)
            if entry_type == "bad":
                bad_syms.add(base)
            elif entry_type == "good":
                good_syms.add(base)
    return sorted(good_syms) + sorted(bad_syms)


def _load_source_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return path.read_text(errors="ignore").splitlines()


def _propagate_reachability(edges: Dict[str, Set[str]], sources: Set[str]) -> Set[str]:
    if not sources:
        return set()
    reachable = set(sources)
    queue = deque(sorted(sources))
    while queue:
        node = queue.popleft()
        for callee in sorted(edges.get(node, set())):
            if callee in reachable:
                continue
            reachable.add(callee)
            queue.append(callee)
    return reachable


def _expand_destructor_reachability(
    entries: Sequence[SourceEntry], reachable: Set[str]
) -> Set[str]:
    if not reachable:
        return reachable
    destructor_names = {
        item.name
        for entry in entries
        for item in entry.ranges
        if item.name.startswith("~")
    }
    if not destructor_names:
        return reachable
    bodies: Dict[str, str] = {}
    for entry in entries:
        if not entry.source_lines:
            continue
        for item in entry.ranges:
            body = "\n".join(entry.source_lines[item.start_line - 1 : item.end_line])
            bodies[item.name] = body
    reachable_bodies = [bodies[name] for name in reachable if name in bodies]
    if not reachable_bodies:
        return reachable
    expanded = set(reachable)
    for dtor in sorted(destructor_names):
        class_name = dtor[1:]
        if not class_name:
            continue
        pattern = re.compile(rf"\b{re.escape(class_name)}\b")
        if any(pattern.search(body) for body in reachable_bodies):
            expanded.add(dtor)
    return expanded


def _expand_destructor_taint(
    entries: Sequence[SourceEntry], tainted: Set[str]
) -> Set[str]:
    return _expand_destructor_reachability(entries, tainted)


def _propagate_taint(
    edges: Dict[str, Set[str]],
    reverse_edges: Dict[str, Set[str]],
    sources: Set[str],
) -> Set[str]:
    if not sources:
        return set()
    tainted = set(sources)
    queue = deque(sorted(sources))
    while queue:
        node = queue.popleft()
        for neighbor in sorted(edges.get(node, set())) + sorted(reverse_edges.get(node, set())):
            if neighbor in tainted:
                continue
            tainted.add(neighbor)
            queue.append(neighbor)
    return tainted


def _analyze_group(
    entries: Sequence[SourceEntry],
    input_apis: Set[str],
) -> Tuple[Dict[str, Set[str]], Set[str], Set[str], Set[str]]:
    func_names: Set[str] = set()
    for entry in entries:
        for item in entry.ranges:
            func_names.add(item.name)

    edges: Dict[str, Set[str]] = {name: set() for name in func_names}
    reverse_edges: Dict[str, Set[str]] = {name: set() for name in func_names}
    input_functions: Set[str] = set()

    for entry in entries:
        if not entry.source_lines:
            continue
        file_has_iostream = False
        file_has_std_cin = False
        file_has_std_using = False
        in_block_comment = False
        for raw_line in entry.source_lines:
            stripped, in_block_comment = _strip_comments_and_strings(
                raw_line, in_block_comment
            )
            if not stripped:
                continue
            if "#include" in stripped and "<iostream>" in stripped:
                file_has_iostream = True
            if "using namespace std" in stripped or "using std::cin" in stripped:
                file_has_std_using = True
            if "std::cin" in stripped:
                file_has_std_cin = True
        cin_allowed = file_has_iostream or file_has_std_using or file_has_std_cin
        for item in entry.ranges:
            in_block_comment = False
            in_signature = True
            function_pointer_targets: Dict[str, str] = {}
            body = entry.source_lines[item.start_line - 1 : item.end_line]
            for raw_line in body:
                stripped, in_block_comment = _strip_comments_and_strings(
                    raw_line, in_block_comment
                )
                if in_signature:
                    if "{" in stripped:
                        in_signature = False
                    continue
                if ARGV_TOKEN_RE.search(stripped):
                    if ARG_VOID_RE.search(stripped) or ARG_UNREF_RE.search(stripped):
                        pass
                    elif (
                        ARG_INDEX_RE.search(stripped)
                        or ARG_DEREF_RE.search(stripped)
                        or ARG_OP_RE.search(stripped)
                    ):
                        input_functions.add(item.name)
                if "std::cin" in stripped:
                    input_functions.add(item.name)
                elif cin_allowed and CIN_TOKEN_RE.search(stripped):
                    if ">>" in stripped or "getline" in stripped or ".get" in stripped:
                        input_functions.add(item.name)
                for pattern in (FUNC_PTR_DECL_ASSIGN_RE, FUNC_PTR_ASSIGN_RE):
                    for match in pattern.finditer(stripped):
                        var_name = match.group("var")
                        target_name = match.group("target")
                        if target_name in func_names:
                            function_pointer_targets[var_name] = target_name
                for match in CALL_RE.finditer(stripped):
                    callee = match.group(1)
                    if callee.lower() in input_apis:
                        input_functions.add(item.name)
                    if callee in func_names:
                        edges[item.name].add(callee)
                        reverse_edges[callee].add(item.name)
                        continue
                    target = function_pointer_targets.get(callee)
                    if target and target in func_names:
                        edges[item.name].add(target)
                        reverse_edges[target].add(item.name)

    tainted = _propagate_taint(edges, reverse_edges, input_functions)
    if input_functions and tainted:
        tainted = _expand_destructor_taint(entries, tainted)
    return edges, input_functions, tainted, func_names


def _build_entry_function_map(object_root: Path) -> Tuple[Dict[str, List[str]], Dict[str, object]]:
    nm_path = shutil.which("nm")
    summary = {
        "object_root": str(object_root),
        "nm_available": bool(nm_path),
        "groups": 0,
        "entry_functions": 0,
    }
    if not nm_path:
        return {}, summary
    groups: Dict[str, List[Path]] = {}
    for path in object_root.rglob("*.o"):
        if path.name.startswith("linked-"):
            continue
        group_key = _group_key_from_name(path.stem).lower()
        groups.setdefault(group_key, []).append(path)
    entry_map: Dict[str, List[str]] = {}
    for group_key, group in sorted(groups.items()):
        entries = _collect_entry_functions(group, nm_path)
        entry_map[group_key] = entries
        summary["entry_functions"] += len(entries)
    summary["groups"] = len(entry_map)
    return entry_map, summary


def _infer_entry_functions(entries: Sequence[SourceEntry]) -> List[str]:
    good_syms: Set[str] = set()
    bad_syms: Set[str] = set()
    for entry in entries:
        source_context = "::".join(
            part
            for part in (
                entry.source_path.stem,
                entry.binary_key,
                entry.group_key,
            )
            if part
        )
        for item in entry.ranges:
            context = f"{source_context}::{item.name}" if source_context else item.name
            entry_type = _classify_entry_symbol(item.name, context)
            if entry_type == "bad":
                bad_syms.add(item.name)
            elif entry_type == "good":
                good_syms.add(item.name)
    return sorted(good_syms) + sorted(bad_syms)

def extract_cwe_id(value: str) -> Optional[int]:
    match = CWE_RE.search(value or "")
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def build_source_index(source_root: Path) -> Dict[str, List[Path]]:
    index: Dict[str, List[Path]] = {}
    for ext in (".c", ".cpp"):
        for path in source_root.rglob(f"*{ext}"):
            index.setdefault(path.name, []).append(path)
    for name in list(index.keys()):
        index[name] = sorted(index[name])
    return index


def resolve_source_path(
    source_root: Path,
    manifest_path: str,
    source_index: Optional[Dict[str, List[Path]]] = None,
) -> Path:
    rel = Path(manifest_path)
    parts = list(rel.parts)
    if parts and parts[0].lower() in {"c", "cpp"}:
        parts = parts[1:]
    if parts and parts[0].lower() == "testcases":
        parts = parts[1:]
    candidate = source_root / Path(*parts)
    if candidate.exists():
        return candidate
    if source_index:
        matches = source_index.get(rel.name)
        if matches:
            return matches[0]
    return candidate


def _strip_comments_and_strings(line: str, in_block_comment: bool) -> Tuple[str, bool]:
    out = []
    i = 0
    while i < len(line):
        if in_block_comment:
            end = line.find("*/", i)
            if end == -1:
                return "", True
            i = end + 2
            in_block_comment = False
            continue
        if line.startswith("/*", i):
            in_block_comment = True
            i += 2
            continue
        if line.startswith("//", i):
            break
        ch = line[i]
        if ch in {'"', "'"}:
            quote = ch
            i += 1
            while i < len(line):
                if line[i] == "\\":
                    i += 2
                    continue
                if line[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), in_block_comment


def _extract_function_name(signature: str) -> Optional[str]:
    if not signature:
        return None
    if "{" not in signature:
        return None
    before_brace = signature.split("{", 1)[0]
    if ";" in before_brace:
        return None
    if "(" not in before_brace:
        return None
    head = before_brace.rsplit("(", 1)[0].strip()
    if not head or head.endswith(")"):
        return None
    if "::" in head:
        candidate = head.split("::")[-1]
    else:
        candidate = head.split()[-1]
    candidate = candidate.strip().lstrip("*&")
    if "<" in candidate:
        candidate = candidate.split("<", 1)[0]
    match = FUNC_NAME_RE.search(candidate)
    if not match:
        return None
    return match.group(0)


def parse_function_ranges(path: Path) -> Tuple[List[FunctionRange], List[str]]:
    errors: List[str] = []
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except FileNotFoundError:
        return [], [f"missing source: {path}"]

    results: List[FunctionRange] = []
    in_block_comment = False
    in_function = False
    brace_depth = 0
    sig_lines: List[str] = []
    sig_start: Optional[int] = None
    current_name: Optional[str] = None
    start_line = 0

    def flush_signature(combined: str, line_index: int) -> None:
        nonlocal in_function, brace_depth, current_name, start_line
        name = _extract_function_name(combined)
        if not name:
            return
        current_name = name
        in_function = True
        start_line = (sig_start or 0) + 1
        brace_depth = combined.count("{") - combined.count("}")
        if brace_depth <= 0:
            results.append(FunctionRange(name=current_name, start_line=start_line, end_line=line_index + 1))
            in_function = False
            current_name = None

    for idx, raw_line in enumerate(lines):
        line, in_block_comment = _strip_comments_and_strings(raw_line, in_block_comment)
        if not in_function:
            if sig_start is None:
                if "(" not in line or line.lstrip().startswith("#"):
                    continue
                sig_start = idx
                sig_lines = [line]
                if "{" in line or ";" in line:
                    combined = " ".join(sig_lines)
                    flush_signature(combined, idx)
                    sig_start = None
                    sig_lines = []
            else:
                sig_lines.append(line)
                if "{" in line or ";" in line:
                    combined = " ".join(sig_lines)
                    flush_signature(combined, idx)
                    sig_start = None
                    sig_lines = []
            continue

        brace_depth += line.count("{") - line.count("}")
        if brace_depth <= 0 and current_name:
            results.append(FunctionRange(name=current_name, start_line=start_line, end_line=idx + 1))
            in_function = False
            current_name = None

    if in_function and current_name:
        errors.append(f"unterminated function {current_name} in {path}")
        results.append(FunctionRange(name=current_name, start_line=start_line, end_line=len(lines)))

    return results, errors


def parse_support_functions(support_root: Optional[Path]) -> Set[str]:
    if not support_root or not support_root.exists():
        return set()
    functions: Set[str] = set()
    for path in sorted(support_root.rglob("*.c")):
        ranges, _ = parse_function_ranges(path)
        for entry in ranges:
            functions.add(entry.name)
    return functions


def load_manifest_entries(
    manifest_path: Path,
    source_root: Path,
    cwe_filter: Optional[Set[int]],
    source_index: Optional[Dict[str, List[Path]]] = None,
) -> List[Tuple[str, Path, List[Flaw]]]:
    root = ET.parse(manifest_path).getroot()
    entries: List[Tuple[str, Path, List[Flaw]]] = []

    for file_tag in root.findall(".//file"):
        file_path = file_tag.get("path") or file_tag.get("name")
        if not file_path:
            continue
        file_cwe = extract_cwe_id(file_path) or 0
        flaws: List[Flaw] = []
        for flaw_tag in file_tag.findall("flaw"):
            line_attr = flaw_tag.get("line")
            if line_attr and line_attr.isdigit():
                cwe_name = flaw_tag.get("name") or flaw_tag.get("cwe") or ""
                flaws.append(Flaw(line=int(line_attr), cwe=cwe_name))
                if not file_cwe:
                    file_cwe = extract_cwe_id(cwe_name or "") or file_cwe
        if cwe_filter and file_cwe not in cwe_filter:
            continue
        resolved = resolve_source_path(source_root, file_path, source_index)
        entries.append((file_path, resolved, flaws))

    return entries


def build_ground_truth(
    manifest_path: Path,
    source_root: Path,
    support_root: Optional[Path],
    cwe_filter: Optional[Set[int]],
    *,
    attacker_controlled: bool = False,
    allowlist_keys: Optional[Set[str]] = None,
    input_apis: Optional[Set[str]] = None,
    entry_functions_by_group: Optional[Dict[str, List[str]]] = None,
) -> Tuple[Dict[str, FileTruth], Dict[str, object]]:
    source_index = build_source_index(source_root)
    support_functions = parse_support_functions(support_root)
    file_truth: Dict[str, FileTruth] = {}
    summary = {
        "files": 0,
        "files_missing": 0,
        "flaws": 0,
        "unmapped_flaws": 0,
        "functions": 0,
        "support_functions": len(support_functions),
    }
    if attacker_controlled:
        summary["attacker_controlled_files"] = 0
        summary["attacker_controlled_positives"] = 0
        summary["attacker_controlled_unknown"] = 0
        summary["attacker_controlled_reachable"] = 0
        summary["allowlist_skipped"] = 0

    grouped: Dict[str, List[SourceEntry]] = {}
    for manifest_rel, source_path, flaws in load_manifest_entries(
        manifest_path, source_root, cwe_filter, source_index
    ):
        binary_key = normalize_binary_key(Path(manifest_rel).stem)
        if allowlist_keys is not None and binary_key not in allowlist_keys:
            if attacker_controlled:
                summary["allowlist_skipped"] += 1
            continue
        group_key = _group_key_from_name(binary_key).lower()
        grouped.setdefault(group_key, []).append(
            SourceEntry(
                manifest_rel=manifest_rel,
                source_path=source_path,
                flaws=flaws,
                binary_key=binary_key,
                group_key=group_key,
            )
        )

    for group_key, entries in grouped.items():
        for entry in entries:
            summary["files"] += 1
            ranges, errors = parse_function_ranges(entry.source_path)
            if not ranges:
                summary["files_missing"] += 1
            summary["functions"] += len(ranges)
            summary["flaws"] += len(entry.flaws)
            entry.ranges = ranges
            entry.parse_errors = errors
            entry.source_lines = _load_source_lines(entry.source_path)

        edges: Dict[str, Set[str]] = {}
        input_functions: Set[str] = set()
        tainted: Set[str] = set()
        if attacker_controlled and input_apis is not None:
            edges, input_functions, tainted, _ = _analyze_group(entries, input_apis)

        entry_functions = (
            entry_functions_by_group.get(group_key, [])
            if entry_functions_by_group
            else []
        )
        if not entry_functions:
            entry_functions = _infer_entry_functions(entries)
        reachable = (
            _propagate_reachability(edges, set(entry_functions))
            if entry_functions
            else set()
        )
        if attacker_controlled and entry_functions and reachable:
            reachable = _expand_destructor_reachability(entries, reachable)

        for entry in entries:
            positives: Set[str] = set()
            unmapped_flaws: List[Dict[str, object]] = []
            for flaw in entry.flaws:
                match = next(
                    (r for r in entry.ranges if r.start_line <= flaw.line <= r.end_line),
                    None,
                )
                if match:
                    positives.add(match.name)
                else:
                    summary["unmapped_flaws"] += 1
                    unmapped_flaws.append({"line": flaw.line, "cwe": flaw.cwe})

            all_functions = {r.name for r in entry.ranges}
            negatives = sorted(all_functions - positives)
            ignored = sorted(support_functions - all_functions)

            attacker_payload: Dict[str, object] = {}
            if attacker_controlled:
                attacker_positives = sorted(positives & tainted)
                attacker_unknown = sorted(positives - tainted)
                attacker_payload = {
                    "input_functions": sorted(input_functions),
                    "tainted_functions": sorted(tainted),
                    "positives": attacker_positives,
                    "unknown_positives": attacker_unknown,
                }
                if entry_functions:
                    attacker_payload["entry_functions"] = entry_functions
                    attacker_payload["reachable_positives"] = sorted(
                        set(attacker_positives) & reachable
                    )
                summary["attacker_controlled_files"] += 1
                summary["attacker_controlled_positives"] += len(attacker_positives)
                summary["attacker_controlled_unknown"] += len(attacker_unknown)
                if entry_functions:
                    summary["attacker_controlled_reachable"] += len(
                        attacker_payload.get("reachable_positives", [])
                    )

            file_truth[entry.binary_key] = FileTruth(
                source_path=str(entry.source_path),
                binary_key=entry.binary_key,
                positives=sorted(positives),
                negatives=negatives,
                ignored=ignored,
                flaws=[{"line": flaw.line, "cwe": flaw.cwe} for flaw in entry.flaws],
                unmapped_flaws=unmapped_flaws,
                parse_errors=entry.parse_errors,
                attacker_controlled=attacker_payload,
            )

    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "manifest": str(manifest_path),
        "source_root": str(source_root),
        "support_root": str(support_root) if support_root else "",
        "summary": summary,
        "support_functions": sorted(support_functions),
        "source_index_entries": len(source_index),
    }
    return file_truth, metadata


def validate_attacker_controlled_truth(
    metadata: Dict[str, object],
    *,
    allow_unresolved: bool = False,
) -> None:
    if allow_unresolved:
        return
    summary = metadata.get("summary") or {}
    unresolved = int(summary.get("attacker_controlled_unknown", 0) or 0)
    if unresolved <= 0:
        return
    raise ValueError(
        "Attacker-controlled ground truth contains unresolved positives "
        f"({unresolved}). Refine the truth generation inputs or rerun with "
        "--allow-unresolved-truth if this ambiguity is intentional."
    )


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build ground-truth maps for ROMEO runs using Juliet manifest + sources."
    )
    parser.add_argument(
        "--juliet-root",
        type=Path,
        default=None,
        help="Path to Juliet C root (contains manifest.xml + testcases/).",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Path to Juliet manifest.xml (overrides --juliet-root).",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=None,
        help="Path to Juliet testcases directory (overrides --juliet-root).",
    )
    parser.add_argument(
        "--support-root",
        type=Path,
        default=None,
        help="Path to Juliet testcasesupport directory (overrides --juliet-root).",
    )
    parser.add_argument(
        "--cwe",
        action="append",
        type=int,
        default=[],
        help="Filter by CWE id (repeatable).",
    )
    parser.add_argument(
        "--attacker-controlled",
        action="store_true",
        help="Compute attacker-controlled subsets by scanning for input APIs and propagating through calls.",
    )
    parser.add_argument(
        "--attacker-controlled-list",
        type=Path,
        default=None,
        help="Optional allowlist of Juliet sources/binaries to include when attacker-controlled mode is enabled.",
    )
    parser.add_argument(
        "--no-default-attacker-controlled-list",
        action="store_true",
        help="Disable the implicit CWE121_attacker_controlled.txt allowlist.",
    )
    parser.add_argument(
        "--allow-unresolved-truth",
        action="store_true",
        help="Allow attacker-controlled truth to contain unresolved positives.",
    )
    parser.add_argument(
        "--input-api",
        action="append",
        default=[],
        help="Function name treated as attacker-controlled input (case-insensitive). Repeatable.",
    )
    parser.add_argument(
        "--no-default-input-apis",
        action="store_true",
        help="Disable the built-in input API list when computing attacker-controlled subsets.",
    )
    parser.add_argument(
        "--object-root",
        type=Path,
        default=None,
        help="Root directory containing ROMEO object files (used for entry functions and optional linking).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("artifacts/romeo/ground_truth.json"),
        help="Output JSON path.",
    )
    return parser.parse_args(argv)


def resolve_inputs(args: argparse.Namespace) -> Tuple[Path, Path, Optional[Path]]:
    if args.juliet_root:
        juliet_root = args.juliet_root.expanduser().resolve()
        manifest = args.manifest or (juliet_root / "manifest.xml")
        source_root = args.source_root or (juliet_root / "testcases")
        support_root = args.support_root or (juliet_root / "testcasesupport")
    else:
        if not args.manifest or not args.source_root:
            raise SystemExit(
                "Provide --juliet-root or both --manifest and --source-root."
            )
        manifest = args.manifest.expanduser().resolve()
        source_root = args.source_root.expanduser().resolve()
        support_root = args.support_root.expanduser().resolve() if args.support_root else None
    if not manifest.exists():
        raise SystemExit(f"manifest not found: {manifest}")
    if not source_root.exists():
        raise SystemExit(f"source-root not found: {source_root}")
    return manifest, source_root, support_root


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    manifest, source_root, support_root = resolve_inputs(args)
    cwe_filter = set(args.cwe or []) or None
    input_apis: Optional[Set[str]] = None
    allowlist_keys: Optional[Set[str]] = None
    allowlist_path: Optional[Path] = None
    if args.attacker_controlled:
        input_apis = set()
        if not args.no_default_input_apis:
            input_apis.update(DEFAULT_INPUT_APIS)
        input_apis.update(name.lower() for name in args.input_api if name)
        if args.attacker_controlled_list:
            allowlist_path = args.attacker_controlled_list.expanduser().resolve()
        elif not args.no_default_attacker_controlled_list:
            default_list = Path("CWE121_attacker_controlled.txt")
            if default_list.exists():
                allowlist_path = default_list.resolve()
        if allowlist_path and allowlist_path.exists():
            allowlist_keys = load_allowlist_keys(allowlist_path)

    object_root = (
        args.object_root.expanduser().resolve()
        if args.object_root
        else None
    )
    if object_root is None:
        fallback = Path("romeo/object_files/C/testcases/CWE121_Stack_Based_Buffer_Overflow")
        if fallback.exists():
            object_root = fallback.resolve()

    entry_functions_by_group: Optional[Dict[str, List[str]]] = None
    entry_summary: Dict[str, object] = {}
    if object_root and object_root.exists():
        entry_functions_by_group, entry_summary = _build_entry_function_map(object_root)

    truth, metadata = build_ground_truth(
        manifest_path=manifest,
        source_root=source_root,
        support_root=support_root,
        cwe_filter=cwe_filter,
        attacker_controlled=args.attacker_controlled,
        allowlist_keys=allowlist_keys,
        input_apis=input_apis,
        entry_functions_by_group=entry_functions_by_group,
    )
    if args.attacker_controlled:
        try:
            validate_attacker_controlled_truth(
                metadata,
                allow_unresolved=args.allow_unresolved_truth,
            )
        except ValueError as exc:
            raise SystemExit(str(exc))
    if args.attacker_controlled:
        metadata["attacker_controlled"] = {
            "enabled": True,
            "allowlist_path": str(allowlist_path) if allowlist_path else "",
            "allowlist_entries": len(allowlist_keys or []),
            "input_apis": sorted(input_apis or []),
            "allow_unresolved_truth": args.allow_unresolved_truth,
        }
    if entry_summary:
        metadata["entry_functions"] = entry_summary
    payload = {
        "metadata": metadata,
        "binaries": {key: vars(value) for key, value in truth.items()},
    }

    out_path = args.out.expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True))

    print(json.dumps(metadata["summary"], indent=2))
    print(f"[+] Wrote ground truth for {len(truth)} binaries to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
