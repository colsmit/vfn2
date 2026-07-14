"""Utilities to convert normalized manifests into function nodes."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from binary_agent.data.manifest import (
    FunctionRecord,
    Manifest,
    ManifestError,
    read_normalized_manifest,
    write_normalized_manifest,
)
from binary_agent.utils.thread_scan import find_thread_start_functions

CALL_REGEX = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


@dataclass(frozen=True)
class FunctionNode:
    """Encapsulates a function's source, metadata, and text representation."""

    record: FunctionRecord
    text: str
    metadata: dict
    path: Optional[Path]
    record_index: int


def load_manifest_record(export_dir: Path) -> Manifest:
    """Load the normalized manifest for a headless export directory."""
    try:
        return read_normalized_manifest(export_dir)
    except ManifestError:
        # Fall back to generating on the fly if the normalized manifest is missing
        write_normalized_manifest(export_dir)
        return read_normalized_manifest(export_dir)


def load_manifest_records(export_dir: Path) -> Iterable[FunctionRecord]:
    """Iterate over manifest function records."""
    manifest = load_manifest_record(export_dir)
    return manifest.functions


def _build_metadata(
    manifest: Manifest,
    record: FunctionRecord,
    callees: Optional[List[str]] = None,
    callers: Optional[List[str]] = None,
    extra_metadata: Optional[dict] = None,
) -> dict:
    payload = {
        "binary": manifest.binary,
        "function_name": record.name,
        "address": record.address,
        "relative_address": record.relative_address,
        "relative_path": record.relative_path,
        "source_symbol": record.source_symbol,
        "demangled_name": record.demangled_name,
        "source_object": record.source_object,
        "ordinal": record.ordinal,
        "is_thunk": record.is_thunk,
        "stack_purge": record.stack_purge,
        "call_fixup": record.call_fixup,
        "prototype": record.prototype,
        "return_type": record.return_type,
        "parameters": record.parameters,
        "byte_length": record.byte_length,
        "line_count": record.line_count,
        "stack_regions": record.stack_regions,
        "string_refs": record.string_refs,
        "pcode_calls": record.pcode_calls,
        "pcode_stores": record.pcode_stores,
        "pcode_loads": record.pcode_loads,
        "pcode_operations": record.pcode_operations,
        "c_line_addresses": record.c_line_addresses,
        "basic_blocks": record.basic_blocks,
        "ambiguous_callsites": record.ambiguous_callsites,
        "wrapper_type": record.wrapper_type,
        "stub_kind": record.stub_kind,
        "emit_c": record.emit_c,
        "image_base": manifest.image_base,
        "language_id": manifest.language_id,
        "processor": manifest.processor,
        "pointer_size_bytes": manifest.pointer_size_bytes,
        "endianness": manifest.endianness,
        "executable_format": manifest.executable_format,
        "compiler": manifest.compiler,
        "callees": callees or [],
        "callers": callers or [],
    }
    if extra_metadata:
        payload.update(extra_metadata)
    return payload


def _append_edge(mapping: Dict[str, Set[str]], caller: str, callee: str) -> None:
    if not caller or not callee or caller == callee:
        return
    mapping.setdefault(caller, set()).add(callee)


def _reverse_edges(callee_map: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    callers: Dict[str, Set[str]] = {}
    for caller, callees in callee_map.items():
        for callee in callees:
            callers.setdefault(callee, set()).add(caller)
    return callers


def _load_cached_callgraph_edges(
    manifest: Manifest,
    base_path: Path,
    function_names: Set[str],
) -> Dict[str, Set[str]]:
    edges: Dict[str, Set[str]] = {}
    if not manifest.callgraph_path:
        return edges
    callgraph_file = base_path / manifest.callgraph_path
    if not callgraph_file.exists():
        return edges
    try:
        payload = json.loads(callgraph_file.read_text())
        raw_edges = payload.get("edges", {}) or {}
    except Exception:
        return {}
    for caller, callees in raw_edges.items():
        if caller not in function_names:
            continue
        for callee in callees or []:
            if callee in function_names:
                _append_edge(edges, caller, callee)
    return edges


def _derive_text_call_edges(
    manifest: Manifest,
    base_path: Path,
    function_names: Set[str],
) -> Dict[str, Set[str]]:
    edges: Dict[str, Set[str]] = {}
    for record in manifest.functions:
        if not record.relative_path:
            continue
        file_path = base_path / record.relative_path
        if not file_path.exists():
            continue
        text = _sanitize_c_for_calls(file_path.read_text())
        if not text.strip():
            continue
        for match in CALL_REGEX.finditer(text):
            callee = match.group(1)
            if callee in function_names:
                _append_edge(edges, record.name, callee)
    return edges


def _sanitize_c_for_calls(text: str) -> str:
    lines: List[str] = []
    in_block = False
    for raw in (text or "").splitlines():
        idx = 0
        quote: Optional[str] = None
        escaped = False
        out: List[str] = []
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
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                    out.append(ch)
                    idx += 1
                    continue
                out.append(" ")
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
        lines.append("".join(out))
    return "\n".join(lines)


def _derive_thread_start_edges(
    manifest: Manifest,
    base_path: Path,
    function_names: Set[str],
) -> Dict[str, Set[str]]:
    edges: Dict[str, Set[str]] = {}
    for record in manifest.functions:
        if not record.relative_path:
            continue
        file_path = base_path / record.relative_path
        if not file_path.exists():
            continue
        text = file_path.read_text()
        if not text.strip():
            continue
        for cleaned in find_thread_start_functions(text):
            if cleaned in function_names:
                _append_edge(edges, record.name, cleaned)
    return edges


def _derive_pcode_edges(
    manifest: Manifest,
    function_names: Set[str],
) -> Dict[str, Set[str]]:
    edges: Dict[str, Set[str]] = {}
    for record in manifest.functions:
        for entry in record.pcode_calls or []:
            callee = str(entry.get("callee") or "").strip()
            if callee in function_names:
                _append_edge(edges, record.name, callee)
    return edges


def _sorted_edges(callee_map: Dict[str, Set[str]], name: str) -> List[str]:
    return sorted(callee_map.get(name, set()))


def load_function_nodes(export_dir: Path) -> tuple[Manifest, List[FunctionNode]]:
    """
    Construct LlamaIndex TextNodes for each function in an export directory.

    Returns
    -------
    manifest:
        The parsed manifest object for reference.
    nodes:
        A list of FunctionNode instances with populated TextNodes and metadata.
    """
    manifest = load_manifest_record(export_dir)
    base_path = Path(manifest.export_dir)
    function_names = {record.name for record in manifest.functions}
    direct_callee_map = _load_cached_callgraph_edges(manifest, base_path, function_names)
    if direct_callee_map:
        text_callee_map: Dict[str, Set[str]] = {}
        thread_callee_map: Dict[str, Set[str]] = {}
    else:
        text_callee_map = _derive_text_call_edges(manifest, base_path, function_names)
        thread_callee_map = _derive_thread_start_edges(manifest, base_path, function_names)
    pcode_callee_map = _derive_pcode_edges(manifest, function_names)
    for caller, callees in text_callee_map.items():
        direct_callee_map.setdefault(caller, set()).update(callees)
    direct_callers_map = _reverse_edges(direct_callee_map)
    thread_callers_map = _reverse_edges(thread_callee_map)
    pcode_callers_map = _reverse_edges(pcode_callee_map)

    nodes: List[FunctionNode] = []
    for index, record in enumerate(manifest.functions):
        file_path: Optional[Path] = base_path / record.relative_path if record.relative_path else None
        text = ""
        if file_path and not str(record.name or "").startswith("__pfx_"):
            try:
                text = file_path.read_text()
            except FileNotFoundError:
                file_path = None
        elif record.relative_path:
            file_path = None
        callers = _sorted_edges(direct_callers_map, record.name)
        callees = _sorted_edges(direct_callee_map, record.name)
        metadata = _build_metadata(
            manifest,
            record,
            callees=callees,
            callers=callers,
            extra_metadata={
                "callers_direct": callers,
                "callees_direct": callees,
                "callers_thread_start": _sorted_edges(thread_callers_map, record.name),
                "callees_thread_start": _sorted_edges(thread_callee_map, record.name),
                "callers_pcode": _sorted_edges(pcode_callers_map, record.name),
                "callees_pcode": _sorted_edges(pcode_callee_map, record.name),
            },
        )
        nodes.append(
            FunctionNode(
                record=record,
                text=text,
                metadata=metadata,
                path=file_path,
                record_index=index,
            )
        )
    return manifest, nodes
