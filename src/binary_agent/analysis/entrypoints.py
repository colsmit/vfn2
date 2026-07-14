"""Deterministic process entrypoint derivation from structured Ghidra facts."""

from __future__ import annotations

import json
import re
import shlex
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.analysis.callgraph import CallGraph, load_cached_call_graph
from binary_agent.data.manifest import Manifest
from binary_agent.ingest.loader import FunctionNode, load_function_nodes
from binary_agent.utils.thread_scan import find_thread_start_functions


ENTRY_SURFACE_NAMES = {"main", "_start", "entry", "winmain", "wmain"}
STDIN_SOURCE_CALLEES = {
    "fgetc",
    "fgets",
    "fread",
    "getc",
    "getchar",
    "gets",
    "getline",
    "read",
    "scanf",
}
ARGV_SOURCE_CALLEES = {"getopt", "getopt_long", "getopt_long_only"}
FILE_SOURCE_CALLEES = {"fopen", "fopen64", "open", "open64"}
ENV_SOURCE_CALLEES = {"getenv", "secure_getenv"}
NETWORK_SOURCE_CALLEES = {"recv", "recvfrom", "recvmsg", "readv"}
SOCKET_SOURCE_CALLEES = {"accept", "accept4"}
HTTP_SOURCE_CALLEES = {
    "cgiFormString",
    "http_parser_execute",
    "httpd_parse_request",
    "mg_get_http_var",
    "mg_http_get_var",
    "mg_http_parse",
    "websGetVar",
}
IPC_SOURCE_CALLEES = {"dbus_message_get_args", "mq_receive", "msgrcv", "ubus_invoke"}
DEVICE_SOURCE_CALLEES = {"ioctl"}
CONFIG_SOURCE_CALLEES = {
    "config_get",
    "g_key_file_get_string",
    "ini_get",
    "nvram_get",
    "uci_get",
    "uci_lookup_option_string",
}
ASYNC_EVENT_LOOP_CALLEES = {
    "event_base_dispatch",
    "event_base_loop",
    "epoll_pwait",
    "epoll_wait",
    "libwebsocket_service",
    "libwebsockets_service",
    "poll",
    "select",
    "uloop_run",
}
SUPPORTED_PROCESS_INPUT_MODELS = {
    "argv",
    "stdin",
    "file",
    "env",
    "http_cgi",
    "http_daemon",
    "socket_service",
    "ubus_call",
}
STRUCTURED_CALLBACK_FAMILIES = {
    "uloop": {"kind": "uloop_callback", "protocol": "uloop", "input_model": ""},
    "runqueue": {"kind": "runqueue_callback", "protocol": "runqueue", "input_model": ""},
    "http": {"kind": "http_handler", "protocol": "http", "input_model": "http_daemon"},
    "cgi": {"kind": "cgi_handler", "protocol": "cgi", "input_model": "http_cgi"},
}


@dataclass(frozen=True)
class EntrySurface:
    """A concrete boundary where attacker-controlled process data can enter."""

    function: str
    address: str
    kind: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EntryPointDerivation:
    """A deterministic entrypoint candidate for a target function."""

    status: str
    target_function: str = ""
    target_address: str = ""
    entry_function: str = ""
    entry_address: str = ""
    call_path: list[str] = field(default_factory=list)
    input_model: str = ""
    process_input_supported: bool = False
    entry_surface: dict[str, Any] = field(default_factory=dict)
    entry_reachability: dict[str, Any] = field(default_factory=dict)
    source_to_sink_trace: dict[str, Any] = field(default_factory=dict)
    derivation_method: str = ""
    blockers: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    schema_version: int = 2
    no_text_matching: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EntryPointDeriver:
    """Derive process entrypoints from cached Ghidra callgraph and p-code metadata."""

    def __init__(self, manifest: Manifest, nodes: Sequence[FunctionNode], graph: CallGraph | None, method: str):
        self.manifest = manifest
        self.nodes = list(nodes)
        self.graph = graph
        self.method = method
        self.node_by_name = {node.record.name: node for node in self.nodes}
        self.node_by_address = {_normalize_address(node.record.address): node for node in self.nodes}
        self._entry_surface_cache: dict[str, tuple[EntrySurface, ...]] = {}
        self._path_cache: dict[tuple[tuple[str, ...], str, int], tuple[tuple[str, ...], ...]] = {}
        self._execution_limitations_cache: dict[str, tuple[dict[str, Any], ...]] = {}

    @classmethod
    def from_export_dir(cls, export_dir: Path) -> "EntryPointDeriver":
        manifest, nodes = load_function_nodes(Path(export_dir))
        graph = load_cached_call_graph(
            manifest,
            nodes,
            include_text_edges=False,
            include_pcode_edges=True,
        )
        method = "ghidra_cached_callgraph+pcode_calls"
        if graph is None:
            graph = _pcode_only_call_graph(nodes)
            method = "ghidra_pcode_calls"
        return cls(manifest, nodes, graph, method)

    def derive_for_candidate(
        self,
        candidate: Mapping[str, Any],
        *,
        max_depth: int = 16,
        intake_facts: Mapping[str, Any] | None = None,
    ) -> EntryPointDerivation:
        target = _candidate_target_node(candidate, self.node_by_name, self.node_by_address)
        if target is None:
            return EntryPointDerivation(
                status="blocked",
                derivation_method=self.method,
                blockers=["target_function_not_in_export"],
                evidence={"export_dir": self.manifest.export_dir},
            )
        if self.graph is None:
            return EntryPointDerivation(
                status="blocked",
                target_function=target.record.name,
                target_address=_normalize_address(target.record.address),
                derivation_method=self.method,
                blockers=["structured_callgraph_unavailable"],
                evidence={"export_dir": self.manifest.export_dir},
            )

        surfaces = self._entry_surfaces(candidate, intake_facts=intake_facts)
        if not surfaces:
            return EntryPointDerivation(
                status="blocked",
                target_function=target.record.name,
                target_address=_normalize_address(target.record.address),
                derivation_method=self.method,
                blockers=["no_explicit_entry_surfaces"],
                evidence={
                    "graph_root_count": len(self.graph.roots()),
                    "export_dir": self.manifest.export_dir,
                },
            )
        roots = [surface.function for surface in surfaces]
        surface_by_function = {surface.function: surface for surface in surfaces}
        path_key = (tuple(roots), target.record.name, max_depth)
        if path_key not in self._path_cache:
            self._path_cache[path_key] = tuple(
                tuple(path)
                for path in self.graph.find_paths(roots, target.record.name, max_depth=max_depth, limit=32)
            )
        paths = [list(path) for path in self._path_cache[path_key]]
        if not paths:
            return EntryPointDerivation(
                status="blocked",
                target_function=target.record.name,
                target_address=_normalize_address(target.record.address),
                derivation_method=self.method,
                blockers=["target_not_reachable_from_explicit_entry_surface"],
                evidence={
                    "entry_surface_count": len(surfaces),
                    "entry_surfaces": [surface.to_dict() for surface in surfaces[:16]],
                    "graph_root_count": len(self.graph.roots()),
                    "export_dir": self.manifest.export_dir,
                },
            )

        path_evaluations: list[dict[str, Any]] = []
        for path in paths:
            input_model, observations = self._input_model_for_path(path, target_function=target.record.name)
            surface = surface_by_function.get(path[0])
            if _is_cross_function_lifetime_candidate(candidate):
                lifetime_model, lifetime_observations = self._lifetime_process_input(path[0])
                if lifetime_model:
                    input_model = lifetime_model
                    observations = lifetime_observations
            if (
                not input_model
                and surface is not None
                and _candidate_source_evidence_applies_to_entry(
                    candidate,
                    entry_function=surface.function,
                    entry_surface_kind=surface.kind,
                    target_function=target.record.name,
                )
            ):
                local_model, local_observations = _candidate_local_stdin_source_input_model(
                    candidate,
                    function_name=surface.function,
                )
                if local_model:
                    input_model = local_model
                    observations = [*observations, *local_observations]
            if surface is not None and surface.kind == "cgi_handler" and input_model in {"", "env", "stdin", "http"}:
                input_model = "http_cgi"
                observations = [
                    *observations,
                    {
                        "function": path[0],
                        "source": "intake_cgi_route",
                        "input_model": input_model,
                    },
                ]
            if not input_model and surface is not None:
                surface_model = str(surface.evidence.get("input_model") or "")
                if surface_model in SUPPORTED_PROCESS_INPUT_MODELS:
                    input_model = surface_model
                    observations = [
                        *observations,
                        {
                            "function": path[0],
                            "source": str(surface.evidence.get("source") or "entry_surface"),
                            "input_model": input_model,
                        },
                    ]
            supported = input_model in SUPPORTED_PROCESS_INPUT_MODELS
            execution_limitations = self._execution_limitations_for_path(path)
            path_evaluations.append(
                {
                    "call_path": list(path),
                    "entry_surface": surface.to_dict() if surface else {},
                    "input_model": input_model,
                    "process_input_supported": supported,
                    "input_observations": observations,
                    "execution_limitations": execution_limitations,
                }
            )
        selected = min(
            path_evaluations,
            key=lambda item: (
                not bool(item.get("process_input_supported")),
                len(item.get("call_path") or []),
                tuple(self.graph._order_key(str(name)) for name in item.get("call_path") or []),
            ),
        )
        path = list(selected["call_path"])
        surface = surface_by_function.get(path[0])
        input_model = str(selected.get("input_model") or "")
        observations = list(selected.get("input_observations") or [])
        source_trace = _source_to_sink_trace(
            candidate,
            entry_surface=surface,
            target_function=target.record.name,
            target_address=_normalize_address(target.record.address),
            call_path=path,
            input_model=input_model,
            observations=observations,
            execution_limitations=list(selected.get("execution_limitations") or []),
        )
        blockers: list[str] = []
        if not input_model:
            blockers.append("no_structured_process_input_source")
        elif input_model not in SUPPORTED_PROCESS_INPUT_MODELS:
            blockers.append(f"unsupported_process_input_model:{input_model}")
        entry = self.node_by_name.get(path[0])
        status = "derived" if input_model in SUPPORTED_PROCESS_INPUT_MODELS else "blocked"
        return EntryPointDerivation(
            status=status,
            target_function=target.record.name,
            target_address=_normalize_address(target.record.address),
            entry_function=entry.record.name if entry else path[0],
            entry_address=_normalize_address(entry.record.address) if entry else "",
            call_path=path,
            input_model=input_model if input_model in SUPPORTED_PROCESS_INPUT_MODELS else "",
            process_input_supported=input_model in SUPPORTED_PROCESS_INPUT_MODELS,
            entry_surface=surface.to_dict() if surface else {},
            entry_reachability={
                "schema_version": 1,
                "status": "complete",
                "entry_function": path[0],
                "target_function": target.record.name,
                "call_path": path,
                "path_length": len(path),
                "entry_surface_kind": surface.kind if surface else "",
            },
            source_to_sink_trace=source_trace,
            derivation_method=self.method,
            blockers=blockers,
            evidence={
                "entry_surface_count": len(surfaces),
                "entry_surfaces": [surface.to_dict() for surface in surfaces[:16]],
                "graph_root_count": len(self.graph.roots()),
                "input_observations": observations,
                "export_dir": self.manifest.export_dir,
                "callgraph_source": self.method,
                "candidate_path_count": len(paths),
                "candidate_paths": path_evaluations[:8],
                "execution_limitations": list(selected.get("execution_limitations") or []),
            },
        )

    def _entry_surfaces(
        self,
        candidate: Mapping[str, Any] | None = None,
        *,
        intake_facts: Mapping[str, Any] | None = None,
    ) -> list[EntrySurface]:
        surfaces: list[EntrySurface] = []
        seen: set[str] = set()
        external_kind, external_evidence = _external_entry_surface(candidate or {}, intake_facts or {})
        cache_key = json.dumps([external_kind, external_evidence], sort_keys=True, default=str)
        cached = self._entry_surface_cache.get(cache_key)
        if cached is not None:
            return list(cached)

        def add(function: str, kind: str, evidence: Mapping[str, Any] | None = None) -> None:
            if function in seen:
                return
            node = self.node_by_name.get(function)
            if node is None or _is_import_or_wrapper(node):
                return
            seen.add(function)
            surfaces.append(
                EntrySurface(
                    function=node.record.name,
                    address=_normalize_address(node.record.address),
                    kind=kind,
                    evidence=dict(evidence or {}),
                )
            )

        for node in sorted(self.nodes, key=lambda item: item.record.ordinal):
            api = _api_name(node.record.name)
            if api in ENTRY_SURFACE_NAMES:
                evidence = {"symbol": node.record.name}
                if external_evidence:
                    evidence.update(external_evidence)
                add(node.record.name, external_kind or "program_entry", evidence)
                for main_function in _libc_start_main_entry_targets(node, self.node_by_address, self.graph):
                    add(
                        main_function,
                        external_kind or "program_entry",
                        {
                            **evidence,
                            "source": "__libc_start_main_handoff",
                            "registered_by": node.record.name,
                            "input_model": "argv",
                        },
                    )

        for node in sorted(self.nodes, key=lambda item: item.record.ordinal):
            record = node.record
            if record.source_symbol:
                add(record.name, "exported_function", {"source_symbol": record.source_symbol})
            elif record.demangled_name:
                add(record.name, "public_function", {"demangled_name": record.demangled_name})
            elif record.source_object:
                add(record.name, "public_function", {"source_object": record.source_object})

        names = set(self.node_by_name)
        for node in sorted(self.nodes, key=lambda item: item.record.ordinal):
            for target in sorted(find_thread_start_functions(node.text or "")):
                if target in names:
                    add(target, "thread_start", {"registered_by": node.record.name})
            for target in _callback_targets(node.text or ""):
                if target in names:
                    add(target, "callback", {"registered_by": node.record.name})

        for registration in _ubus_callback_registrations(self.nodes):
            add(
                str(registration["callback"]),
                "ubus_call",
                {
                    "source": "structured_ubus_registration",
                    "input_model": "ubus_call",
                    "protocol": "ubus",
                    "object": str(registration["object"]),
                    "method": str(registration["method"]),
                    "registered_by": str(registration.get("registered_by") or ""),
                    "registration_address": _normalize_address(registration.get("address")),
                },
            )

        for registration in _structured_callback_registrations(self.nodes):
            family = str(registration["family"])
            spec = STRUCTURED_CALLBACK_FAMILIES[family]
            add(
                str(registration["callback"]),
                str(spec["kind"]),
                {
                    "source": "structured_callback_registration",
                    "input_model": str(spec["input_model"]),
                    "protocol": str(spec["protocol"]),
                    "family": family,
                    "event": str(registration.get("event") or ""),
                    "registered_by": str(registration.get("registered_by") or ""),
                    "registration_address": _normalize_address(registration.get("address")),
                },
            )

        surfaces.sort(key=lambda surface: self.graph._order_key(surface.function) if self.graph else 1_000_000)
        self._entry_surface_cache[cache_key] = tuple(surfaces)
        return surfaces

    def _input_model_for_path(
        self,
        path: Sequence[str],
        *,
        target_function: str = "",
    ) -> tuple[str, list[dict[str, Any]]]:
        observations: list[dict[str, Any]] = []
        fallback_model = ""
        http_protocol = _path_contains_http_protocol(path, self.node_by_name)
        for name in path:
            node = self.node_by_name.get(name)
            if node is None:
                continue
            for call in node.record.pcode_calls or []:
                callee = _api_name(call.get("callee"))
                input_model = _input_model_for_api(callee)
                if not input_model:
                    continue
                if input_model == "socket_service" and http_protocol:
                    input_model = "http_daemon"
                if _is_target_local_ambiguous_process_api(name, target_function, input_model):
                    continue
                observations.append(
                    {
                        "function": name,
                        "callee": callee,
                        "address": _normalize_address(call.get("address") or call.get("operation_address")),
                        "input_model": input_model,
                    }
                )
                if input_model in SUPPORTED_PROCESS_INPUT_MODELS:
                    return input_model, observations
                if not fallback_model:
                    fallback_model = input_model
            if _main_accepts_argv(node):
                observations.append({"function": name, "source": "main_parameter_shape", "input_model": "argv"})
                if not fallback_model:
                    fallback_model = "argv"
                continue
            if self.graph is None:
                continue
            for callee_name in sorted(self.graph.neighbors(name), key=self.graph._order_key):
                callee = _api_name(callee_name)
                input_model = _input_model_for_api(callee)
                if not input_model:
                    continue
                if input_model == "socket_service" and http_protocol:
                    input_model = "http_daemon"
                if _is_target_local_ambiguous_process_api(name, target_function, input_model):
                    continue
                callee_node = self.node_by_name.get(callee_name)
                observations.append(
                    {
                        "function": name,
                        "callee": callee,
                        "callee_function": callee_name,
                        "callee_address": _normalize_address(callee_node.record.address) if callee_node else "",
                        "source": "structured_callgraph_edge",
                        "input_model": input_model,
                    }
                )
                if input_model in SUPPORTED_PROCESS_INPUT_MODELS:
                    return input_model, observations
                if not fallback_model:
                    fallback_model = input_model
        return fallback_model, observations

    def _execution_limitations_for_path(self, path: Sequence[str]) -> list[dict[str, Any]]:
        limitations: list[dict[str, Any]] = []
        for name in path:
            node = self.node_by_name.get(name)
            if node is None:
                continue
            if name not in self._execution_limitations_cache:
                self._execution_limitations_cache[name] = tuple(
                    [*_async_event_loop_limitations(node), *_indirect_resolution_limitations(node)]
                )
            limitations.extend(self._execution_limitations_cache[name])
        return _dedupe_limitations(limitations)[:16]

    def _lifetime_process_input(self, entry_function: str) -> tuple[str, list[dict[str, Any]]]:
        if self.graph is None:
            return "", []
        queue: list[tuple[str, int]] = [(entry_function, 0)]
        seen: set[str] = set()
        while queue:
            function, depth = queue.pop(0)
            if function in seen or depth > 3:
                continue
            seen.add(function)
            if depth:
                model = _input_model_for_api(_api_name(function))
                if model == "file":
                    return "file", [
                        {
                            "function": entry_function,
                            "callee_function": function,
                            "callee": _api_name(function),
                            "source": "lifetime_process_file_path",
                            "input_model": "file",
                        }
                    ]
            for callee in sorted(self.graph.neighbors(function), key=self.graph._order_key):
                queue.append((callee, depth + 1))
        return "", []


def derive_entrypoint_for_candidate(
    candidate: Mapping[str, Any],
    *,
    export_dir: Path,
    max_depth: int = 16,
) -> EntryPointDerivation:
    """Derive one conservative process entrypoint for a candidate."""

    return EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(candidate, max_depth=max_depth)


def _pcode_only_call_graph(nodes: Sequence[FunctionNode]) -> CallGraph:
    names = {node.record.name for node in nodes}
    edges: dict[str, set[str]] = {name: set() for name in names}
    reverse: dict[str, set[str]] = defaultdict(set)
    order = {node.record.name: node.record.ordinal for node in nodes}
    for node in nodes:
        caller = node.record.name
        for call in node.record.pcode_calls or []:
            callee = str(call.get("callee") or "").strip()
            if callee and callee != caller and callee in names:
                edges[caller].add(callee)
                reverse[callee].add(caller)
    for name in names:
        reverse.setdefault(name, set())
    return CallGraph(edges=edges, reverse_edges=dict(reverse), order=order)


def _candidate_target_node(
    candidate: Mapping[str, Any],
    by_name: Mapping[str, FunctionNode],
    by_address: Mapping[str, FunctionNode],
) -> FunctionNode | None:
    location = _coerce_mapping(candidate.get("location"))
    type_facts = _coerce_mapping(candidate.get("type_facts"))
    semantic_target = _coerce_mapping(type_facts.get("semantic_target"))
    static_candidate = _coerce_mapping(type_facts.get("static_candidate"))
    names = [
        location.get("function_name"),
        semantic_target.get("function_name"),
        static_candidate.get("function_name"),
        candidate.get("function_name"),
    ]
    for name in names:
        text = str(name or "")
        if text and text in by_name:
            return by_name[text]
    addresses = [
        location.get("address"),
        semantic_target.get("function_address"),
        static_candidate.get("address"),
        candidate.get("address"),
    ]
    for address in addresses:
        normalized = _normalize_address(address)
        if normalized and normalized in by_address:
            return by_address[normalized]
    return None


def _is_import_or_wrapper(node: FunctionNode) -> bool:
    record = node.record
    if record.is_thunk:
        return True
    if record.wrapper_type in {"plt_thunk", "single_call_wrapper", "indirect_forward"}:
        return True
    if record.stub_kind in {"wrapper", "single_call_wrapper", "tiny_body"}:
        return True
    return False


def _main_accepts_argv(node: FunctionNode) -> bool:
    record = node.record
    if _api_name(record.name) != "main":
        return False
    params = list(record.parameters or [])
    if len(params) < 2:
        return False
    second = params[1] if isinstance(params[1], Mapping) else {}
    datatype = str(second.get("data_type") or second.get("type") or "")
    return datatype.count("*") >= 2 or "char" in datatype.lower() and "*" in datatype


def _input_model_for_api(callee: str) -> str:
    if callee in ARGV_SOURCE_CALLEES:
        return "argv"
    if callee in STDIN_SOURCE_CALLEES:
        return "stdin"
    if callee in FILE_SOURCE_CALLEES:
        return "file"
    if callee in ENV_SOURCE_CALLEES:
        return "env"
    if callee in NETWORK_SOURCE_CALLEES or callee in SOCKET_SOURCE_CALLEES:
        return "socket_service"
    if callee in HTTP_SOURCE_CALLEES:
        return "http_daemon"
    if callee in IPC_SOURCE_CALLEES:
        return "ubus_call" if callee == "ubus_invoke" else "ipc"
    if callee in DEVICE_SOURCE_CALLEES:
        return "device"
    if callee in CONFIG_SOURCE_CALLEES:
        return "config"
    return ""


def _ubus_callback_registrations(nodes: Sequence[FunctionNode]) -> list[dict[str, Any]]:
    """Return only complete structured object/method/callback registrations."""

    names = {node.record.name for node in nodes}
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for node in nodes:
        candidates: list[Mapping[str, Any]] = []
        metadata_rows = node.metadata.get("ubus_registrations", [])
        if isinstance(metadata_rows, Sequence) and not isinstance(metadata_rows, (str, bytes, bytearray)):
            candidates.extend(item for item in metadata_rows if isinstance(item, Mapping))
        for call in node.record.pcode_calls or []:
            registrations = call.get("ubus_registrations")
            if isinstance(registrations, Sequence) and not isinstance(registrations, (str, bytes, bytearray)):
                candidates.extend(item for item in registrations if isinstance(item, Mapping))
            registration = call.get("ubus_registration")
            if isinstance(registration, Mapping):
                candidates.append(registration)
        for raw in candidates:
            object_name = str(raw.get("object") or raw.get("object_name") or "").strip()
            method_name = str(raw.get("method") or raw.get("method_name") or "").strip()
            callback = str(raw.get("callback") or raw.get("callback_function") or "").strip()
            if not object_name or not method_name or callback not in names:
                continue
            key = (object_name, method_name, callback)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "object": object_name,
                    "method": method_name,
                    "callback": callback,
                    "registered_by": str(raw.get("registered_by") or node.record.name),
                    "address": raw.get("address") or raw.get("registration_address") or "",
                }
            )
    return sorted(rows, key=lambda item: (item["object"], item["method"], item["callback"]))


def _structured_callback_registrations(nodes: Sequence[FunctionNode]) -> list[dict[str, Any]]:
    """Return complete structured uloop, runqueue, HTTP, and CGI registrations."""

    names = {node.record.name for node in nodes}
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for node in nodes:
        candidates: list[Mapping[str, Any]] = []
        metadata_rows = node.metadata.get("callback_registrations", [])
        if isinstance(metadata_rows, Sequence) and not isinstance(metadata_rows, (str, bytes, bytearray)):
            candidates.extend(item for item in metadata_rows if isinstance(item, Mapping))
        for call in node.record.pcode_calls or []:
            nested = call.get("callback_registrations")
            if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes, bytearray)):
                candidates.extend(item for item in nested if isinstance(item, Mapping))
            single = call.get("callback_registration")
            if isinstance(single, Mapping):
                candidates.append(single)
        for raw in candidates:
            family = str(raw.get("family") or raw.get("registration_family") or "").strip().lower()
            callback = str(raw.get("callback") or raw.get("callback_function") or "").strip()
            event = str(raw.get("event") or raw.get("event_name") or raw.get("route") or "").strip()
            if family not in STRUCTURED_CALLBACK_FAMILIES or callback not in names:
                continue
            key = (family, event, callback)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "family": family,
                    "callback": callback,
                    "event": event,
                    "registered_by": str(raw.get("registered_by") or node.record.name),
                    "address": raw.get("address") or raw.get("registration_address") or "",
                }
            )
    return sorted(rows, key=lambda item: (item["family"], item["event"], item["callback"]))


def _path_contains_http_protocol(
    path: Sequence[str],
    node_by_name: Mapping[str, FunctionNode],
) -> bool:
    text = "\n".join(str(node_by_name[name].text or "") for name in path if name in node_by_name)
    upper = text.upper()
    return "HTTP/1." in upper and any(marker in upper for marker in ('"GET ', '"POST ', 'CONTENT-LENGTH:', 'HOST:'))


def _libc_start_main_entry_targets(
    node: FunctionNode,
    by_address: Mapping[str, FunctionNode],
    graph: CallGraph | None,
) -> list[str]:
    if _api_name(node.record.name) not in ENTRY_SURFACE_NAMES:
        return []
    has_libc_start_main = False
    if graph is not None:
        has_libc_start_main = any(_api_name(name) == "libc_start_main" for name in graph.neighbors(node.record.name))
    if not has_libc_start_main:
        for ref in node.record.global_refs or []:
            label = _api_name(ref.get("label") or ref.get("var_display"))
            if "__libc_start_main" in label:
                has_libc_start_main = True
                break
    if not has_libc_start_main:
        has_libc_start_main = any(
            _api_name(call.get("callee")) == "libc_start_main"
            for call in node.record.pcode_calls or []
        )
    if not has_libc_start_main:
        return []
    targets: list[str] = []
    for ref in node.record.global_refs or []:
        if str(ref.get("block") or "") != ".text":
            continue
        target = by_address.get(_normalize_address(ref.get("address")))
        if target is None or target.record.name == node.record.name or _is_import_or_wrapper(target):
            continue
        targets.append(target.record.name)
    for call in node.record.pcode_calls or []:
        if _api_name(call.get("callee")) != "libc_start_main":
            continue
        args = call.get("args")
        if not isinstance(args, Sequence) or isinstance(args, (str, bytes, bytearray)) or not args:
            continue
        first = args[0] if isinstance(args[0], Mapping) else {}
        target = by_address.get(_normalize_address(first.get("address") or first.get("constant")))
        if target is None or target.record.name == node.record.name or _is_import_or_wrapper(target):
            continue
        targets.append(target.record.name)
    return _unique_nonempty(targets)


def _is_target_local_ambiguous_process_api(function_name: str, target_function: str, input_model: str) -> bool:
    if function_name != target_function:
        return False
    return input_model in {"stdin", "file"}


def _async_event_loop_limitations(node: FunctionNode) -> list[dict[str, Any]]:
    limitations: list[dict[str, Any]] = []
    for call in node.record.pcode_calls or []:
        callee = _api_name(call.get("callee"))
        if callee in ASYNC_EVENT_LOOP_CALLEES:
            limitations.append(
                {
                    "kind": "async_event_loop",
                    "function": node.record.name,
                    "callee": callee,
                    "address": _normalize_address(call.get("address") or call.get("operation_address")),
                    "reason": "event loop scheduling is not modeled as process input replay",
                }
            )
    text = node.text or ""
    for callee in sorted(ASYNC_EVENT_LOOP_CALLEES):
        if re.search(rf"\b{re.escape(callee)}\s*\(", text):
            limitations.append(
                {
                    "kind": "async_event_loop",
                    "function": node.record.name,
                    "callee": callee,
                    "reason": "event loop scheduling is not modeled as process input replay",
                }
            )
    return limitations


def _indirect_resolution_limitations(node: FunctionNode) -> list[dict[str, Any]]:
    limitations: list[dict[str, Any]] = []
    for call in node.record.pcode_calls or []:
        target_kind = str(call.get("target_kind") or "").lower()
        callee = str(call.get("callee") or "")
        if target_kind == "indirect" and not callee:
            limitations.append(
                {
                    "kind": "unresolved_indirect_target",
                    "function": node.record.name,
                    "address": _normalize_address(call.get("address") or call.get("operation_address")),
                    "reason": "indirect call target is not resolved in structured export facts",
                }
            )
    for row in node.record.ambiguous_callsites or []:
        reasons = [str(item) for item in row.get("ambiguity_reasons", []) or []]
        reason_text = " ".join(reasons).lower()
        kind = (
            "arbitrary_devirtualization_required"
            if any(token in reason_text for token in ("virtual", "vtable", "devirtual"))
            else "unresolved_indirect_target"
        )
        limitations.append(
            {
                "kind": kind,
                "function": node.record.name,
                "address": _normalize_address(row.get("call_address") or row.get("address")),
                "reasons": reasons,
                "reason": "ambiguous callsite needs concrete target evidence before process replay can treat it as resolved",
            }
        )
    return limitations


def _dedupe_limitations(limitations: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for limitation in limitations:
        key = (
            str(limitation.get("kind") or ""),
            str(limitation.get("function") or ""),
            str(limitation.get("callee") or ""),
            str(limitation.get("address") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(dict(limitation))
    return result


def _external_entry_surface(candidate: Mapping[str, Any], intake_facts: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    refs = _candidate_binary_refs(candidate, intake_facts)
    services = _matching_services(refs, candidate, intake_facts)
    routes = _matching_cgi_routes(refs, candidate, intake_facts)
    if routes:
        return "cgi_handler", {
            "source": "intake_routes",
            "input_model": "http_cgi",
            "routes": routes,
            "services": services,
            "binary_refs": refs,
        }
    if not services:
        return "", {}
    busybox = _busybox_applet(services, refs)
    if busybox:
        return "busybox_applet", {
            "source": "intake_services",
            "busybox_applet": busybox,
            "services": services,
            "binary_refs": refs,
        }
    if any(item.get("ports") for item in services) or any(_looks_daemon_service(item) for item in services):
        return "daemon_launch", {
            "source": "intake_services",
            "services": services,
            "binary_refs": refs,
        }
    return "service_launch", {
        "source": "intake_services",
        "services": services,
        "binary_refs": refs,
    }


def _candidate_binary_refs(candidate: Mapping[str, Any], intake_facts: Mapping[str, Any]) -> dict[str, list[str]]:
    values: list[str] = []
    target = _coerce_mapping(candidate.get("target"))
    metadata = _coerce_mapping(candidate.get("metadata"))
    for key in ("path", "relative_path", "binary", "component"):
        raw = str(target.get(key) or "")
        if raw:
            values.append(raw)
    raw = str(metadata.get("firmware_binary") or "")
    if raw:
        values.append(raw)
    binaries = _coerce_mapping(intake_facts.get("binaries")).get("binaries", [])
    binary_rows = binaries if isinstance(binaries, Sequence) and not isinstance(binaries, (str, bytes)) else []
    for row in binary_rows:
        if not isinstance(row, Mapping):
            continue
        for key in ("path", "relative_path"):
            raw = str(row.get(key) or "")
            if raw:
                values.append(raw)
    paths = _unique_nonempty(values)
    basenames = _unique_nonempty(Path(value.replace("\\", "/")).name for value in paths)
    return {"paths": paths, "basenames": basenames}


def _matching_services(
    refs: Mapping[str, Sequence[str]],
    candidate: Mapping[str, Any],
    intake_facts: Mapping[str, Any],
) -> list[dict[str, Any]]:
    rows: list[Mapping[str, Any]] = []
    metadata = _coerce_mapping(candidate.get("metadata"))
    firmware_services = metadata.get("firmware_services")
    if isinstance(firmware_services, Sequence) and not isinstance(firmware_services, (str, bytes)):
        rows.extend(item for item in firmware_services if isinstance(item, Mapping))
    services = _coerce_mapping(intake_facts.get("services")).get("services", [])
    if isinstance(services, Sequence) and not isinstance(services, (str, bytes)):
        rows.extend(item for item in services if isinstance(item, Mapping))
    matched: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not _service_matches_binary(row, refs):
            continue
        key = str(row.get("service_id") or row.get("path") or row.get("relative_path") or row.get("exec") or len(seen))
        if key in seen:
            continue
        seen.add(key)
        matched.append(_bounded_service_evidence(row))
    return matched[:8]


def _matching_cgi_routes(
    refs: Mapping[str, Sequence[str]],
    candidate: Mapping[str, Any],
    intake_facts: Mapping[str, Any],
) -> list[dict[str, Any]]:
    route_rows: list[Mapping[str, Any]] = []
    routes = _coerce_mapping(intake_facts.get("routes")).get("routes", [])
    if isinstance(routes, Sequence) and not isinstance(routes, (str, bytes)):
        route_rows.extend(item for item in routes if isinstance(item, Mapping))
    source = _coerce_mapping(candidate.get("source"))
    source_route = str(source.get("expression") or source.get("route") or "")
    if str(source.get("kind") or "").lower() in {"route", "cgi_route", "http_route"} and source_route:
        route_rows.append({"route": source_route, "method": str(source.get("method") or ""), "evidence": source.get("evidence", [])})
    matched: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in route_rows:
        route = str(row.get("route") or row.get("path") or "")
        if not _route_matches_binary(route, refs, source_route=source_route):
            continue
        key = f"{row.get('method') or ''}:{route}"
        if key in seen:
            continue
        seen.add(key)
        matched.append(_bounded_route_evidence(row))
    return matched[:8]


def _service_matches_binary(service: Mapping[str, Any], refs: Mapping[str, Sequence[str]]) -> bool:
    exec_text = str(service.get("exec") or "")
    if not exec_text:
        return False
    lowered_exec = exec_text.replace("\\", "/").lower()
    for path in refs.get("paths", []):
        normalized = str(path).replace("\\", "/").strip().lower()
        if normalized and normalized in lowered_exec:
            return True
    tokens = _command_tokens(exec_text)
    basenames = {str(item).lower() for item in refs.get("basenames", []) if str(item)}
    for token in tokens:
        base = Path(str(token).replace("\\", "/")).name.lower()
        if base in basenames:
            return True
    return False


def _route_matches_binary(route: str, refs: Mapping[str, Sequence[str]], *, source_route: str = "") -> bool:
    route_text = str(route or source_route or "").strip()
    if not route_text:
        return False
    route_base = Path(route_text.rstrip("/").replace("\\", "/")).name.lower()
    route_lower = route_text.lower()
    basenames = {str(item).lower() for item in refs.get("basenames", []) if str(item)}
    if route_base in basenames:
        return True
    if "cgi-bin" not in route_lower:
        return False
    return any(base and re.search(rf"(?:^|[/_.-]){re.escape(base)}(?:$|[/_.-])", route_lower) for base in basenames)


def _bounded_service_evidence(service: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "service_id": str(service.get("service_id") or ""),
        "name": str(service.get("name") or ""),
        "relative_path": str(service.get("relative_path") or ""),
        "path": str(service.get("path") or ""),
        "exec": str(service.get("exec") or ""),
        "ports": [int(item) for item in service.get("ports", []) or [] if _looks_int(item)],
        "evidence": [dict(item) for item in service.get("evidence", []) or [] if isinstance(item, Mapping)][:4],
    }


def _bounded_route_evidence(route: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "route_id": str(route.get("route_id") or ""),
        "route": str(route.get("route") or route.get("path") or ""),
        "method": str(route.get("method") or ""),
        "relative_path": str(route.get("relative_path") or ""),
        "path": str(route.get("path") or ""),
        "evidence": [dict(item) for item in route.get("evidence", []) or [] if isinstance(item, Mapping)][:4],
    }


def _busybox_applet(services: Sequence[Mapping[str, Any]], refs: Mapping[str, Sequence[str]]) -> str:
    basenames = {str(item).lower() for item in refs.get("basenames", []) if str(item)}
    if "busybox" not in basenames:
        return ""
    for service in services:
        tokens = _command_tokens(str(service.get("exec") or ""))
        for index, token in enumerate(tokens):
            if Path(str(token).replace("\\", "/")).name.lower() != "busybox":
                continue
            for applet in tokens[index + 1 :]:
                text = str(applet).strip()
                if text and not text.startswith("-"):
                    return Path(text.replace("\\", "/")).name
    return ""


def _looks_daemon_service(service: Mapping[str, Any]) -> bool:
    text = " ".join(
        [
            str(service.get("name") or ""),
            str(service.get("relative_path") or ""),
            str(service.get("exec") or ""),
        ]
    ).lower()
    return any(token in text for token in ("daemon", "httpd", "inetd", "server", "service", "procd", "supervisord"))


def _command_tokens(command: str) -> list[str]:
    try:
        return [str(item) for item in shlex.split(str(command or ""))]
    except ValueError:
        return [item for item in re.split(r"\s+", str(command or "")) if item]


def _unique_nonempty(values: Sequence[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _looks_int(value: Any) -> bool:
    try:
        int(value)
        return True
    except Exception:
        return False


def _source_to_sink_trace(
    candidate: Mapping[str, Any],
    *,
    entry_surface: EntrySurface | None,
    target_function: str,
    target_address: str,
    call_path: Sequence[str],
    input_model: str,
    observations: Sequence[Mapping[str, Any]],
    execution_limitations: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    classification_trace = _coerce_mapping(candidate.get("classification_trace"))
    type_facts = _coerce_mapping(candidate.get("type_facts"))
    static_candidate = _coerce_mapping(type_facts.get("static_candidate"))
    if not classification_trace:
        classification_trace = _coerce_mapping(static_candidate.get("classification_trace"))
    source_to_write = _coerce_mapping(classification_trace.get("source_to_write"))
    roles = _coerce_mapping(source_to_write.get("roles"))
    controlled_roles = _controlled_roles(roles)
    reachability = _coerce_mapping(classification_trace.get("reachability_dataflow"))
    graph_trace = _coerce_mapping(reachability.get("graph"))
    source_link = _coerce_mapping(reachability.get("source_link"))
    sink_name = str(
        _coerce_mapping(candidate.get("sink")).get("name")
        or static_candidate.get("sink")
        or candidate.get("sink")
        or ""
    )
    blockers: list[str] = []
    if not input_model:
        blockers.append("no_entry_input_source")
    elif input_model not in SUPPORTED_PROCESS_INPUT_MODELS:
        blockers.append(f"unsupported_process_input_model:{input_model}")
    unbounded_controlled = _has_unbounded_controlled_write_source(candidate, roles)
    controlled_oob_read_extent = _has_controlled_oob_read_extent(candidate, roles)
    if not source_to_write:
        blockers.append("missing_source_to_write_trace")
    elif not source_to_write.get("complete") and not unbounded_controlled and not controlled_oob_read_extent:
        blockers.append("source_to_write_roles_incomplete")
    if not controlled_roles:
        blockers.append("no_controlled_sink_role")
    if graph_trace and not call_path and not graph_trace.get("has_real_path", graph_trace.get("path_is_valid", False)):
        blockers.append("static_reachability_path_not_proven")
    status = "complete" if not blockers else "blocked"
    argument_roles = _source_to_sink_argument_roles(roles)
    propagation_path = _source_to_sink_propagation_path(call_path)
    return {
        "schema_version": 2,
        "status": status,
        "attacker_control_reaches_sink_role": status == "complete",
        "entry_function": entry_surface.function if entry_surface else "",
        "entry_surface_kind": entry_surface.kind if entry_surface else "",
        "target_function": target_function,
        "target_address": target_address,
        "sink_name": sink_name,
        "call_path": [str(item) for item in call_path],
        "input_model": input_model if input_model in SUPPORTED_PROCESS_INPUT_MODELS else "",
        "source_artifacts": _source_to_sink_source_artifacts(entry_surface, observations, source_link),
        "propagation_path": propagation_path,
        "argument_roles": argument_roles,
        "controlled_roles": controlled_roles,
        "sink_argument": _primary_sink_argument(argument_roles),
        "transformations": _source_to_sink_transformations(classification_trace),
        "sanitizer_checks": _source_to_sink_sanitizer_checks(classification_trace),
        "bounds_checks": _source_to_sink_bounds_checks(classification_trace),
        "execution_limitations": [dict(item) for item in execution_limitations],
        "confidence": "proven" if status == "complete" else "blocked",
        "blockers": blockers,
        "evidence": {
            "input_observations": [dict(item) for item in observations],
            "observed_input_model": input_model,
            "source_to_write_complete": bool(source_to_write.get("complete")),
            "source_to_write_roles": roles,
            "reachability_graph": graph_trace,
            "source_link": source_link,
            "execution_limitations": [dict(item) for item in execution_limitations],
        },
    }


def _source_to_sink_argument_roles(roles: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for role, fact in roles.items():
        if not isinstance(fact, Mapping):
            continue
        classification = str(fact.get("classification") or "unknown")
        result.append(
            {
                "role": str(role),
                "expr": str(fact.get("expr") or ""),
                "classification": classification,
                "controlled": classification in {"source_controlled", "parameter_controlled"},
                "complete": bool(fact.get("complete", classification != "unknown")),
                "evidence": [str(item) for item in _coerce_sequence(fact.get("evidence")) if str(item)][:8],
            }
        )
    return result


def _candidate_local_stdin_source_input_model(
    candidate: Mapping[str, Any],
    *,
    function_name: str,
) -> tuple[str, list[dict[str, Any]]]:
    for evidence in _candidate_source_evidence(candidate):
        callee = _source_evidence_stdin_callee(evidence)
        if not callee:
            continue
        return (
            "stdin",
            [
                {
                    "function": function_name,
                    "callee": callee,
                    "source": "candidate_source_evidence",
                    "input_model": "stdin",
                    "evidence": evidence,
                }
            ],
        )
    return "", []


def _candidate_source_evidence(candidate: Mapping[str, Any]) -> list[str]:
    evidence: list[str] = []
    for key in ("source_evidence", "evidence", "line_text"):
        value = candidate.get(key)
        if isinstance(value, str):
            evidence.append(value)
        else:
            evidence.extend(str(item) for item in _coerce_sequence(value) if str(item))
    type_facts = _coerce_mapping(candidate.get("type_facts"))
    static_candidate = _coerce_mapping(type_facts.get("static_candidate"))
    for key in ("source_evidence", "evidence", "line_text"):
        value = static_candidate.get(key)
        if isinstance(value, str):
            evidence.append(value)
        else:
            evidence.extend(str(item) for item in _coerce_sequence(value) if str(item))
    return _unique_nonempty(evidence)[:16]


def _is_cross_function_lifetime_candidate(candidate: Mapping[str, Any]) -> bool:
    return bool(
        str(candidate.get("vulnerability_type") or "") == "use_after_free"
        and str(_coerce_mapping(candidate.get("source")).get("kind") or "")
        == "cross_function_heap_lifetime"
    )


def _candidate_source_evidence_applies_to_entry(
    candidate: Mapping[str, Any],
    *,
    entry_function: str,
    entry_surface_kind: str,
    target_function: str,
) -> bool:
    if entry_function == target_function:
        return entry_surface_kind == "program_entry"
    trace = _coerce_mapping(candidate.get("classification_trace"))
    reachability = _coerce_mapping(trace.get("reachability_dataflow"))
    graph = _coerce_mapping(reachability.get("graph"))
    call_path = [str(item) for item in _coerce_sequence(graph.get("call_path")) if str(item)]
    return bool(
        call_path
        and call_path[0] == entry_function
        and call_path[-1] == target_function
        and (graph.get("input_reaches_sink") is True or graph.get("path_is_valid") is True)
    )


def _source_evidence_stdin_callee(evidence: str) -> str:
    for callee in sorted(STDIN_SOURCE_CALLEES, key=len, reverse=True):
        if re.search(rf"\b{re.escape(callee)}\s*\(", evidence):
            return callee
    return ""


def _has_controlled_oob_read_extent(candidate: Mapping[str, Any], roles: Mapping[str, Any]) -> bool:
    type_facts = _coerce_mapping(candidate.get("type_facts"))
    static_candidate = _coerce_mapping(type_facts.get("static_candidate"))
    vulnerability_type = str(candidate.get("vulnerability_type") or type_facts.get("vulnerability_type") or static_candidate.get("vulnerability_type") or "")
    if vulnerability_type != "out_of_bounds_read":
        return False
    relation = str(candidate.get("write_relation") or type_facts.get("write_relation") or static_candidate.get("write_relation") or "")
    if relation in {"symbolic_size", "proven_oob_read"}:
        return _role_is_controlled(roles.get("write_size"))
    if relation == "symbolic_read_offset":
        return _role_is_controlled(roles.get("write_offset"))
    return False


def _role_is_controlled(role: Any) -> bool:
    if not isinstance(role, Mapping):
        return False
    return str(role.get("classification") or "") in {"source_controlled", "parameter_controlled"}


def _has_unbounded_controlled_write_source(candidate: Mapping[str, Any], roles: Mapping[str, Any]) -> bool:
    write_source = _coerce_mapping(roles.get("write_source"))
    classification = str(write_source.get("classification") or "")
    if classification not in {"source_controlled", "parameter_controlled"}:
        return False
    type_facts = _coerce_mapping(candidate.get("type_facts"))
    static_candidate = _coerce_mapping(type_facts.get("static_candidate"))
    write_relation = str(type_facts.get("write_relation") or static_candidate.get("write_relation") or "")
    verdict = str(type_facts.get("verdict") or static_candidate.get("verdict") or "")
    if write_relation not in {"unbounded", "proven_overflow"} and verdict not in {"unbounded", "overflow"}:
        return False
    sink_name = _api_name(_coerce_mapping(candidate.get("sink")).get("name") or static_candidate.get("sink"))
    return sink_name in {"gets", "memcpy", "memmove", "snprintf", "sprintf", "strcat", "strcpy", "strncat", "strncpy"}


def _source_to_sink_propagation_path(call_path: Sequence[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, function in enumerate(call_path):
        if index == 0:
            role = "entry"
        elif index == len(call_path) - 1:
            role = "sink_function"
        else:
            role = "intermediate"
        result.append({"kind": "function", "function": str(function), "index": index, "role": role})
    return result


def _source_to_sink_source_artifacts(
    entry_surface: EntrySurface | None,
    observations: Sequence[Mapping[str, Any]],
    source_link: Mapping[str, Any],
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    if entry_surface is not None:
        artifacts.append(
            {
                "kind": "entry_surface",
                "surface_kind": entry_surface.kind,
                "function": entry_surface.function,
                "address": entry_surface.address,
                "evidence": dict(entry_surface.evidence),
            }
        )
    for observation in observations:
        artifacts.append({"kind": "input_observation", **dict(observation)})
    for source in _coerce_sequence(source_link.get("local_source_sources")):
        text = str(source or "")
        if text:
            artifacts.append({"kind": "source_link", "evidence": text})
    return artifacts[:12]


def _primary_sink_argument(argument_roles: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    for wanted in (
        "write_source",
        "command_argument",
        "path_argument",
        "format_argument",
        "file_path",
        "sink_argument",
        "write_size",
        "write_offset",
        "destination_pointer",
    ):
        for role in argument_roles:
            if str(role.get("role") or "") == wanted and bool(role.get("controlled")):
                return dict(role)
    return dict(argument_roles[0]) if argument_roles else {}


def _source_to_sink_transformations(classification_trace: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for key, kind in (("aliases", "alias"), ("summaries", "summary"), ("source_flow", "source_flow")):
        for item in _coerce_sequence(classification_trace.get(key)):
            text = str(item or "")
            if text:
                result.append({"kind": kind, "evidence": text})
    return result[:12]


def _source_to_sink_sanitizer_checks(classification_trace: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    safety = _coerce_mapping(classification_trace.get("safety_result"))
    if safety:
        result.append({"kind": "safety_result", **safety})
    guards = _coerce_mapping(classification_trace.get("guards"))
    for status in ("accepted", "rejected"):
        for guard in _coerce_sequence(guards.get(status)):
            text = str(guard or "")
            if text:
                result.append({"kind": "guard", "status": status, "condition": text})
    return result[:12]


def _source_to_sink_bounds_checks(classification_trace: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    bounds = _coerce_mapping(classification_trace.get("bounds"))
    for status in ("accepted", "rejected"):
        for item in _coerce_sequence(bounds.get(status)):
            if isinstance(item, Mapping):
                result.append({"kind": "bound", "status": status, **dict(item)})
            elif str(item or ""):
                result.append({"kind": "bound", "status": status, "relation": str(item)})
    return result[:12]


def _controlled_roles(roles: Mapping[str, Any]) -> list[str]:
    controlled: list[str] = []
    for role, fact in roles.items():
        if not isinstance(fact, Mapping):
            continue
        classification = str(fact.get("classification") or "")
        if classification in {"source_controlled", "parameter_controlled"}:
            controlled.append(f"{role}:{classification}")
    return controlled


def _callback_targets(text: str) -> list[str]:
    targets: list[str] = []
    for match in re.finditer(r"&\s*([A-Za-z_][A-Za-z0-9_]*)", text or ""):
        target = match.group(1)
        if target not in targets:
            targets.append(target)
    return targets


def _api_name(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.split("@", 1)[0]
    if "::" in text:
        text = text.rsplit("::", 1)[-1]
    if text.startswith("thunk_"):
        text = text.removeprefix("thunk_")
    return text.strip("_").lower()


def _normalize_address(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, int):
        return f"0x{value:x}" if value >= 0 else ""
    text = str(value).strip().lower()
    if not text:
        return ""
    try:
        return f"0x{int(text, 0):x}"
    except ValueError:
        return text


def _coerce_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _coerce_sequence(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def entrypoint_derivation_json(derivation: EntryPointDerivation | Mapping[str, Any]) -> str:
    payload = derivation.to_dict() if isinstance(derivation, EntryPointDerivation) else dict(derivation)
    return json.dumps(payload, indent=2, sort_keys=True)
