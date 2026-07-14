"""Simple call graph utilities for decompiled function text or cached adjacency lists."""

from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set

from binary_agent.data.manifest import Manifest
from binary_agent.ingest.loader import FunctionNode
from binary_agent.utils.thread_scan import find_thread_start_functions


CALL_REGEX = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


@dataclass(frozen=True)
class CallGraph:
    edges: Dict[str, Set[str]]
    reverse_edges: Dict[str, Set[str]]
    order: Dict[str, int]
    transparent_nodes: Set[str] = field(default_factory=set)

    def neighbors(self, name: str) -> Set[str]:
        return self.edges.get(name, set())

    def callers(self, name: str) -> Set[str]:
        return self.reverse_edges.get(name, set())

    def find_path(self, sources: Sequence[str], target: str, max_depth: int) -> Optional[List[str]]:
        if not sources:
            return None
        target = target.strip()
        queue = deque((source, [source]) for source in sources)
        seen = set(sources)
        while queue:
            node, path = queue.popleft()
            if node == target:
                return path
            if len(path) > max_depth:
                continue
            for neighbor in sorted(self.neighbors(node), key=self._order_key):
                if neighbor in seen:
                    continue
                seen.add(neighbor)
                queue.append((neighbor, path + [neighbor]))
        return None

    def find_paths(
        self,
        sources: Sequence[str],
        target: str,
        max_depth: int,
        limit: int,
    ) -> List[List[str]]:
        """Return up to `limit` simple paths from any source to target."""
        if not sources or limit <= 0:
            return []
        target = target.strip()
        paths: List[List[str]] = []
        queue = deque((source, [source], {source}) for source in sources)
        visits: Dict[str, int] = defaultdict(int)
        for source in sources:
            visits[source] += 1

        while queue and len(paths) < limit:
            current, path, visited = queue.popleft()
            if len(path) > max_depth:
                continue
            if current == target:
                paths.append(path)
                continue
            if len(path) == max_depth:
                continue
            for neighbor in sorted(self.neighbors(current), key=self._order_key):
                if neighbor in visited or visits[neighbor] >= limit:
                    continue
                visits[neighbor] += 1
                queue.append((neighbor, path + [neighbor], visited | {neighbor}))

        return paths

    def find_paths_to_targets(
        self,
        sources: Sequence[str],
        targets: Set[str],
        max_depth: int,
    ) -> Dict[str, List[str]]:
        """
        Multi-target BFS from the given sources.

        Returns a mapping of target name to the first (shortest) path discovered
        within the depth bound. Stops early once all targets are reached.
        """
        if not sources or not targets:
            return {}

        queue = deque((source, 0) for source in sources)
        parents: Dict[str, Optional[str]] = {source: None for source in sources}
        seen: Set[str] = set(sources)
        remaining = set(targets)
        results: Dict[str, List[str]] = {}

        while queue and remaining:
            node, depth = queue.popleft()
            if node in remaining:
                results[node] = _reconstruct_path(parents, node)
                remaining.remove(node)
                if not remaining:
                    break
            if depth >= max_depth:
                continue
            for neighbor in sorted(self.neighbors(node), key=self._order_key):
                if neighbor in seen:
                    continue
                seen.add(neighbor)
                parents[neighbor] = node
                queue.append((neighbor, depth + 1))

        return results

    def find_reverse_path(
        self,
        target: str,
        sources: Sequence[str],
        max_depth: int,
    ) -> Optional[List[str]]:
        """
        Search backwards from `target` toward any source using caller edges.

        Returns the first path discovered, oriented from source to target.
        """
        if not sources:
            return None
        target = target.strip()
        queue = deque([(target, 0)])
        parents: Dict[str, Optional[str]] = {target: None}
        seen: Set[str] = {target}
        source_set = set(sources)

        while queue:
            node, depth = queue.popleft()
            if node in source_set:
                return _reconstruct_path(parents, node, reverse=False)
            if depth >= max_depth:
                continue
            for caller in sorted(self.callers(node), key=self._order_key):
                if caller in seen:
                    continue
                seen.add(caller)
                parents[caller] = node
                queue.append((caller, depth + 1))

        return None

    def roots(self) -> Set[str]:
        return {name for name, callers in self.reverse_edges.items() if not callers}

    def _order_key(self, name: str) -> int:
        return self.order.get(name, 1_000_000)


def _merge_edge_maps(
    edges: Dict[str, Set[str]],
    reverse: Dict[str, Set[str]],
    additions: tuple[Dict[str, Set[str]], Dict[str, Set[str]]],
) -> None:
    add_edges, add_reverse = additions
    for caller, callees in add_edges.items():
        if caller not in edges:
            continue
        for callee in callees:
            if callee not in edges:
                continue
            if callee in edges[caller]:
                continue
            edges[caller].add(callee)
            reverse[callee].add(caller)
    for callee, callers in add_reverse.items():
        if callee not in edges:
            continue
        reverse[callee].update(caller for caller in callers if caller in edges)


def build_call_graph(
    nodes: Iterable[FunctionNode],
    *,
    include_thread_start_edges: bool = True,
    include_pcode_edges: bool = False,
) -> CallGraph:
    nodes = list(nodes)
    names = {node.record.name for node in nodes}
    edges: Dict[str, Set[str]] = {name: set() for name in names}
    reverse: Dict[str, Set[str]] = defaultdict(set)
    order = {node.record.name: node.record.ordinal for node in nodes}

    _merge_edge_maps(
        edges,
        reverse,
        _derive_text_edges(
            nodes,
            names,
            include_thread_start_edges=include_thread_start_edges,
        ),
    )
    if include_pcode_edges:
        _merge_edge_maps(edges, reverse, _derive_pcode_edges(nodes, names))

    transparent_nodes = _detect_transparent_nodes(nodes, edges)
    _contract_transparent_nodes(edges, reverse, transparent_nodes)

    # Ensure all nodes appear in reverse mapping
    for name in names:
        reverse.setdefault(name, set())

    return CallGraph(
        edges=edges,
        reverse_edges=dict(reverse),
        order=order,
        transparent_nodes=transparent_nodes,
    )


def _derive_text_edges(
    nodes: Sequence[FunctionNode],
    names: Set[str],
    *,
    include_thread_start_edges: bool = True,
) -> tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    edges: Dict[str, Set[str]] = {name: set() for name in names}
    reverse: Dict[str, Set[str]] = defaultdict(set)
    for node in nodes:
        caller = node.record.name
        text = _sanitize_c_for_calls(node.text or "")
        if not text.strip():
            continue
        for match in CALL_REGEX.finditer(text):
            callee = match.group(1)
            if callee == caller:
                continue
            if callee in names:
                edges[caller].add(callee)
                reverse[callee].add(caller)
        if include_thread_start_edges:
            for target in find_thread_start_functions(text):
                if target == caller:
                    continue
                if target in names:
                    edges[caller].add(target)
                    reverse[target].add(caller)
    return edges, reverse


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


def _derive_pcode_edges(
    nodes: Sequence[FunctionNode],
    names: Set[str],
) -> tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    edges: Dict[str, Set[str]] = {name: set() for name in names}
    reverse: Dict[str, Set[str]] = defaultdict(set)
    for node in nodes:
        caller = node.record.name
        for entry in node.record.pcode_calls or []:
            callee = str(entry.get("callee") or "").strip()
            if not callee or callee == caller or callee not in names:
                continue
            edges[caller].add(callee)
            reverse[callee].add(caller)
    return edges, reverse


def load_cached_call_graph(
    manifest: Manifest,
    nodes: Sequence[FunctionNode],
    *,
    include_thread_start_edges: bool = True,
    include_pcode_edges: bool = False,
    include_text_edges: bool = True,
) -> Optional[CallGraph]:
    """
    Load a cached call graph if present alongside the manifest.
    Falls back to None if the cache is missing or malformed. When present, this
    serves as the canonical call graph; no additional heuristic edges are added.
    """
    if not manifest.callgraph_path:
        return None
    path = Path(manifest.export_dir) / manifest.callgraph_path
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
    except Exception:
        return None

    raw_edges = payload.get("edges", {})
    order = {node.record.name: node.record.ordinal for node in nodes}
    edges: Dict[str, Set[str]] = {name: set() for name in order}
    reverse: Dict[str, Set[str]] = defaultdict(set)

    for caller, callees in raw_edges.items():
        if caller not in edges:
            continue
        for callee in callees or []:
            if callee not in edges:
                continue
            edges[caller].add(callee)
            reverse[callee].add(caller)

    if include_text_edges:
        _merge_edge_maps(
            edges,
            reverse,
            _derive_text_edges(
                nodes,
                set(order),
                include_thread_start_edges=include_thread_start_edges,
            ),
        )
    if include_pcode_edges:
        _merge_edge_maps(edges, reverse, _derive_pcode_edges(nodes, set(order)))

    transparent_nodes = _detect_transparent_nodes(nodes, edges)
    _contract_transparent_nodes(edges, reverse, transparent_nodes)

    for name in edges:
        reverse.setdefault(name, set())

    return CallGraph(
        edges=edges,
        reverse_edges=dict(reverse),
        order=order,
        transparent_nodes=transparent_nodes,
    )


def _reconstruct_path(
    parents: Dict[str, Optional[str]],
    node: str,
    *,
    reverse: bool = True,
) -> List[str]:
    path: List[str] = []
    cursor: Optional[str] = node
    while cursor is not None:
        path.append(cursor)
        cursor = parents.get(cursor)
    if reverse:
        path.reverse()
    return path


def _detect_transparent_nodes(nodes: Sequence[FunctionNode], edges: Dict[str, Set[str]]) -> Set[str]:
    transparent: Set[str] = set()
    for node in nodes:
        record = node.record
        name = record.name
        callees = edges.get(name, set())
        if _is_transparent(node, callees):
            transparent.add(name)
    return transparent


def _is_transparent(node: FunctionNode, callees: Set[str]) -> bool:
    record = node.record
    if getattr(record, "is_thunk", False):
        return True
    wrapper_type = getattr(record, "wrapper_type", None)
    stub_kind = getattr(record, "stub_kind", None)

    if wrapper_type in {"single_call_wrapper", "plt_thunk", "indirect_forward"}:
        return True
    if stub_kind in {"wrapper", "single_call_wrapper"}:
        return True
    if stub_kind == "tiny_body" and len(callees) == 1:
        return True
    if _looks_like_unlabeled_forwarder(node, callees):
        return True
    return False


def _looks_like_unlabeled_forwarder(node: FunctionNode, callees: Set[str]) -> bool:
    if len(callees) != 1 or node.record.pcode_stores:
        return False
    text = _sanitize_c_for_calls(node.text or "")
    if not text.strip():
        return False
    body = _function_body(text)
    if re.search(r"\b(?:if|for|while|switch)\b", body):
        return False
    if re.search(r"\[[^\]]+\]\s*(?:[+*/%&|^-]?=|\+\+|--)", body):
        return False
    if re.search(r"\*\s*[^=;]+=", body):
        return False
    if re.search(r"(?<![=!<>])=(?!=)", body):
        return False
    calls = [
        match.group(1)
        for match in CALL_REGEX.finditer(text)
        if match.group(1) not in {"if", "for", "while", "switch", "return", "sizeof"}
        and _normalize_function_key(match.group(1)) != _normalize_function_key(node.record.name)
    ]
    return len(calls) == 1 and set(calls) == set(callees)


def _function_body(text: str) -> str:
    open_index = text.find("{")
    close_index = text.rfind("}")
    if open_index < 0 or close_index <= open_index:
        return text
    return text[open_index + 1 : close_index]


def _normalize_function_key(name: str) -> str:
    return str(name or "").strip().split("::")[-1].split("@", 1)[0].lstrip("_")


def _contract_transparent_nodes(
    edges: Dict[str, Set[str]],
    reverse: Dict[str, Set[str]],
    transparent_nodes: Set[str],
) -> None:
    if not transparent_nodes:
        return
    for node in transparent_nodes:
        callers = list(reverse.get(node, ()))
        callees = list(edges.get(node, ()))
        for caller in callers:
            for callee in callees:
                if caller == callee:
                    continue
                edges[caller].add(callee)
                reverse[callee].add(caller)
