"""Immutable, single-build normalized view of one Ghidra export."""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Mapping, Sequence

from binary_agent.data.manifest import Manifest
from binary_agent.data.operation_specs import OperationSpecSet, load_operation_specs
from binary_agent.ingest.loader import FunctionNode


ENTRY_NAMES = frozenset({"main", "_start", "entry", "winmain", "wmain"})
SOURCE_OPERATIONS = frozenset(
    {"read", "recv", "recvfrom", "fread", "fgets", "gets", "scanf", "getenv", "getchar"}
)
CALL_RE = re.compile(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>[^;{}]*)\)")
INDIRECT_IMPORT_CALL_RE = re.compile(
    r"\bPTR_(?P<name>[A-Za-z_][A-Za-z0-9_]*?)_(?:0x)?[0-9A-Fa-f]{6,16}"
    r"\s*\)\s*\((?P<args>.*?)\)\s*;",
    re.DOTALL,
)


def normalize_observed_name(name: object) -> str:
    """Keep the binary spelling while removing import/decompiler decoration."""

    return str(name or "").strip().split("@", 1)[0].lstrip("_")


@dataclass(frozen=True)
class IndexedFunction:
    name: str
    address: str
    relative_address: int
    relative_path: str
    text: str
    callees: tuple[str, ...]
    callers: tuple[str, ...]
    reachable_from_entry: bool


@dataclass(frozen=True)
class IndexedOperation:
    kind: str
    name: str
    backend: str
    semantics: str
    effect_kind: str
    function_name: str
    function_address: str
    operation_address: str
    line_number: int
    arguments: tuple[str, ...] = ()
    argument_roles: tuple[tuple[str, str], ...] = ()
    width_bytes: int | None = None
    definedness: str = ""
    definedness_basis: str = ""
    defined_byte_ranges: tuple[tuple[int, int], ...] = ()
    undefined_byte_ranges: tuple[tuple[int, int], ...] = ()
    stack_offset: int | None = None
    evidence_source: str = ""
    observed_name: str = ""
    address_constants: tuple[int, ...] = ()
    output_pointer_args: tuple[int, ...] = ()
    output_write_guarantee: str = ""

    def role(self, name: str) -> str:
        return dict(self.argument_roles).get(name, "")


@dataclass(frozen=True)
class IndexedMemoryObject:
    identity: str
    kind: str
    function_name: str
    label: str
    size_bytes: int | None
    address: str = ""
    source: str = ""


@dataclass(frozen=True)
class LifecycleEvent:
    event_kind: str
    resource_kind: str
    resource_identity: str
    allocator_family: str
    function_name: str
    function_address: str
    operation_address: str
    line_number: int
    operation_name: str
    argument: str = ""
    context_function_name: str = ""
    context_function_address: str = ""
    context_operation_address: str = ""
    context_line_number: int = 0
    call_path: tuple[str, ...] = ()
    instantiation_source: str = ""


@dataclass(frozen=True)
class IndexedString:
    value: str
    function_name: str
    address: str
    reachable: bool
    source: str
    context: str = ""


@dataclass(frozen=True)
class IndexedLiteralConsumer:
    literal_address: str
    literal_value: str
    literal_fingerprint: str
    function_name: str
    consumer_name: str
    consumer_address: str
    argument_role: str
    reachable: bool


@dataclass(frozen=True)
class IndexedScopeExit:
    function_name: str
    function_address: str
    operation_address: str
    line_number: int
    kind: str


@dataclass(frozen=True)
class IndexedResourcePath:
    resource_identity: str
    allocation_address: str
    function_name: str
    exit_address: str
    release_addresses: tuple[str, ...]
    feasible: bool
    live_at_exit: bool
    escaped: bool
    escape_kind: str = ""


@dataclass(frozen=True)
class EntrySurface:
    function_name: str
    function_address: str
    kind: str
    protocol: str = ""
    object_name: str = ""
    method_name: str = ""
    event_name: str = ""
    registration_address: str = ""


@dataclass(frozen=True)
class SourceObservation:
    kind: str
    function_name: str
    operation_address: str
    expression: str


@dataclass(frozen=True)
class IndexedFunctionSummary:
    function_name: str
    function_address: str
    may_allocate: bool
    allocation_evidence: tuple[str, ...] = ()
    copy_source_arguments: tuple[int, ...] = ()


@dataclass(frozen=True)
class IndexedPathRelation:
    function_name: str
    guard_variable: str
    condition: str
    true_value: str
    false_value: str
    start_line: int
    end_line: int

    @property
    def inverted_boolean(self) -> bool:
        return self.true_value == "false" and self.false_value == "true"


@dataclass(frozen=True)
class IndexedBasicBlock:
    function_name: str
    start_address: str
    end_address: str
    successors: tuple[str, ...]


@dataclass(frozen=True)
class IndexedEventRelation:
    relation: str
    feasible: bool
    before_dominates_after: bool
    same_block: bool
    evidence: str


@dataclass(frozen=True)
class ProgramIndexMetrics:
    build_seconds: float
    functions: int
    call_operations: int
    load_operations: int
    store_operations: int
    memory_objects: int
    lifecycle_events: int


@dataclass(frozen=True)
class ProgramIndex:
    """Read-only normalized program facts shared by every discovery backend."""

    binary_identity: str
    functions: tuple[IndexedFunction, ...]
    operations: tuple[IndexedOperation, ...]
    memory_objects: tuple[IndexedMemoryObject, ...]
    lifecycle_events: tuple[LifecycleEvent, ...]
    strings: tuple[IndexedString, ...]
    literal_consumers: tuple[IndexedLiteralConsumer, ...]
    entry_surfaces: tuple[EntrySurface, ...]
    source_observations: tuple[SourceObservation, ...]
    function_summaries: tuple[IndexedFunctionSummary, ...]
    path_relations: tuple[IndexedPathRelation, ...]
    basic_blocks: tuple[IndexedBasicBlock, ...]
    scope_exits: tuple[IndexedScopeExit, ...]
    resource_paths: tuple[IndexedResourcePath, ...]
    reachability: tuple[tuple[str, tuple[str, ...]], ...]
    metrics: ProgramIndexMetrics
    # The mature spatial extractor still consumes these already-loaded values.
    # They are shared once and excluded from comparison/repr.
    manifest: Manifest = field(compare=False, repr=False)
    nodes: tuple[FunctionNode, ...] = field(compare=False, repr=False)

    def function(self, name: str) -> IndexedFunction | None:
        return next((item for item in self.functions if item.name == name), None)

    def reachable_from(self, name: str) -> tuple[str, ...]:
        return dict(self.reachability).get(name, ())

    def operations_for_backend(self, backend: str) -> tuple[IndexedOperation, ...]:
        return tuple(item for item in self.operations if item.backend == backend)

    def summary(self, function_name: str) -> IndexedFunctionSummary | None:
        return next((item for item in self.function_summaries if item.function_name == function_name), None)

    def path_relation(self, function_name: str, guard_variable: str) -> IndexedPathRelation | None:
        return next(
            (
                item
                for item in self.path_relations
                if item.function_name == function_name and item.guard_variable == guard_variable
            ),
            None,
        )

    def event_relation(self, before: LifecycleEvent, after: LifecycleEvent) -> IndexedEventRelation:
        """Describe whether two indexed events can execute in the required order."""
        before_function = before.context_function_name or before.function_name
        after_function = after.context_function_name or after.function_name
        if before_function != after_function:
            return IndexedEventRelation("interprocedural_unresolved", False, False, False, "function_boundary")
        before_address = before.context_operation_address or before.operation_address
        after_address = after.context_operation_address or after.operation_address
        before_line = before.context_line_number or before.line_number
        after_line = after.context_line_number or after.line_number
        blocks = tuple(item for item in self.basic_blocks if item.function_name == before_function)
        terminal_operations = tuple(
            item
            for item in self.operations
            if item.function_name == before_function
            and item.semantics == "process_terminate"
        )
        if blocks:
            relation = _cfg_event_relation(blocks, before_address, after_address)
            if (
                relation.feasible
                and terminal_operations
                and not _cfg_path_avoiding(
                    blocks,
                    before_address,
                    after_address,
                    tuple(item.operation_address for item in terminal_operations),
                )
            ):
                relation = IndexedEventRelation(
                    "cfg_process_terminated_before_after",
                    False,
                    False,
                    False,
                    "ghidra_basic_block+process_terminate",
                )
            if relation.relation not in {"cfg_address_unresolved", "cfg_block_unresolved"}:
                return replace(
                    relation,
                    evidence=(
                        "interprocedural_callsite:" + relation.evidence
                        if before.context_function_name or after.context_function_name
                        else relation.evidence
                    ),
                )
        function = self.function(before_function)
        relation = _text_event_relation(
            function.text if function else "",
            before_line,
            after_line,
            before_address,
            after_address,
        )
        if relation.feasible and any(
            before_line < item.line_number < after_line
            for item in terminal_operations
            if item.line_number > 0
        ):
            relation = IndexedEventRelation(
                "text_process_terminated_before_after",
                False,
                False,
                False,
                "decompiled_text+process_terminate",
            )
        if before.context_function_name or after.context_function_name:
            return replace(relation, evidence="interprocedural_callsite:" + relation.evidence)
        return relation

    def event_path_avoiding(
        self,
        before: LifecycleEvent,
        after: LifecycleEvent,
        barriers: Sequence[LifecycleEvent],
    ) -> bool:
        """Return whether one ordered CFG path avoids every barrier event.

        This is used for generation-sensitive lifetime pairs.  Reassigning a
        resource variable through a fresh acquire separates generations; a
        release-to-use path that must cross that acquire is not a same-resource
        use-after-release path.
        """

        before_function = before.context_function_name or before.function_name
        after_function = after.context_function_name or after.function_name
        if before_function != after_function:
            return True
        applicable = [
            item
            for item in barriers
            if (item.context_function_name or item.function_name) == before_function
        ]
        if not applicable:
            return True
        blocks = tuple(item for item in self.basic_blocks if item.function_name == before_function)
        if not blocks:
            return True
        return _cfg_path_avoiding(
            blocks,
            before.context_operation_address or before.operation_address,
            after.context_operation_address or after.operation_address,
            tuple(item.context_operation_address or item.operation_address for item in applicable),
        )


def _indexed_ubus_entry_surfaces(nodes: Sequence[FunctionNode]) -> list[EntrySurface]:
    """Index complete structured ubus callback registrations only."""

    by_name = {node.record.name: node for node in nodes}
    result: list[EntrySurface] = []
    seen: set[tuple[str, str, str]] = set()
    for registration_node in nodes:
        candidates: list[Mapping[str, Any]] = []
        metadata_rows = registration_node.metadata.get("ubus_registrations", [])
        if isinstance(metadata_rows, Sequence) and not isinstance(metadata_rows, (str, bytes, bytearray)):
            candidates.extend(item for item in metadata_rows if isinstance(item, Mapping))
        for call in registration_node.record.pcode_calls or []:
            nested = call.get("ubus_registrations")
            if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes, bytearray)):
                candidates.extend(item for item in nested if isinstance(item, Mapping))
            single = call.get("ubus_registration")
            if isinstance(single, Mapping):
                candidates.append(single)
        for raw in candidates:
            object_name = str(raw.get("object") or raw.get("object_name") or "").strip()
            method_name = str(raw.get("method") or raw.get("method_name") or "").strip()
            callback_name = str(raw.get("callback") or raw.get("callback_function") or "").strip()
            callback = by_name.get(callback_name)
            if callback is None or not object_name or not method_name:
                continue
            key = (object_name, method_name, callback_name)
            if key in seen:
                continue
            seen.add(key)
            result.append(
                EntrySurface(
                    function_name=callback_name,
                    function_address=callback.record.address,
                    kind="ubus_call",
                    protocol="ubus",
                    object_name=object_name,
                    method_name=method_name,
                )
            )
    return result


INDEXED_CALLBACK_FAMILIES = {
    "uloop": ("uloop_callback", "uloop"),
    "runqueue": ("runqueue_callback", "runqueue"),
    "http": ("http_handler", "http"),
    "cgi": ("cgi_handler", "cgi"),
}


def _indexed_callback_entry_surfaces(nodes: Sequence[FunctionNode]) -> list[EntrySurface]:
    """Index complete structured callback registrations without text guessing."""

    by_name = {node.record.name: node for node in nodes}
    result: list[EntrySurface] = []
    seen: set[tuple[str, str, str]] = set()
    for registration_node in nodes:
        candidates: list[Mapping[str, Any]] = []
        metadata_rows = registration_node.metadata.get("callback_registrations", [])
        if isinstance(metadata_rows, Sequence) and not isinstance(metadata_rows, (str, bytes, bytearray)):
            candidates.extend(item for item in metadata_rows if isinstance(item, Mapping))
        for call in registration_node.record.pcode_calls or []:
            nested = call.get("callback_registrations")
            if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes, bytearray)):
                candidates.extend(item for item in nested if isinstance(item, Mapping))
            single = call.get("callback_registration")
            if isinstance(single, Mapping):
                candidates.append(single)
        for raw in candidates:
            family = str(raw.get("family") or raw.get("registration_family") or "").strip().lower()
            callback_name = str(raw.get("callback") or raw.get("callback_function") or "").strip()
            event_name = str(raw.get("event") or raw.get("event_name") or raw.get("route") or "").strip()
            callback = by_name.get(callback_name)
            if callback is None or family not in INDEXED_CALLBACK_FAMILIES:
                continue
            key = (family, event_name, callback_name)
            if key in seen:
                continue
            seen.add(key)
            kind, protocol = INDEXED_CALLBACK_FAMILIES[family]
            result.append(
                EntrySurface(
                    function_name=callback_name,
                    function_address=callback.record.address,
                    kind=kind,
                    protocol=protocol,
                    event_name=event_name,
                    registration_address=str(
                        raw.get("address") or raw.get("registration_address") or ""
                    ),
                )
            )
    return result


def _indexed_main_entry_surfaces(nodes: Sequence[FunctionNode]) -> list[EntrySurface]:
    """Recover the libc main handoff from structured ELF-entry facts."""

    by_address = {
        _index_address(node.record.address): node
        for node in nodes
        if _index_address(node.record.address)
    }
    result: list[EntrySurface] = []
    seen: set[str] = set()
    for node in nodes:
        raw_entry_name = node.record.name.lower()
        normalized_entry_name = normalize_observed_name(node.record.name).lower()
        if raw_entry_name not in ENTRY_NAMES and normalized_entry_name not in {
            normalize_observed_name(name).lower() for name in ENTRY_NAMES
        }:
            continue
        has_handoff = any(
            normalize_observed_name(name).lower() == "libc_start_main"
            for name in node.metadata.get("callees", ())
        ) or any(
            "__libc_start_main" in str(ref.get("label") or ref.get("var_display") or "").lower()
            for ref in node.record.global_refs or []
        ) or any(
            normalize_observed_name(call.get("callee")).lower() == "libc_start_main"
            for call in node.record.pcode_calls or []
        )
        if not has_handoff:
            continue
        target_addresses: list[str] = []
        target_addresses.extend(
            _index_address(ref.get("address"))
            for ref in node.record.global_refs or []
            if str(ref.get("block") or "") == ".text"
        )
        for call in node.record.pcode_calls or []:
            if normalize_observed_name(call.get("callee")).lower() != "libc_start_main":
                continue
            args = call.get("args")
            if isinstance(args, Sequence) and not isinstance(args, (str, bytes, bytearray)) and args:
                first = args[0] if isinstance(args[0], Mapping) else {}
                target_addresses.append(_index_address(first.get("address") or first.get("constant")))
        for address in target_addresses:
            target = by_address.get(address)
            if target is None or target.record.name == node.record.name or target.record.is_thunk:
                continue
            if target.record.name in seen:
                continue
            seen.add(target.record.name)
            result.append(
                EntrySurface(
                    function_name=target.record.name,
                    function_address=target.record.address,
                    kind="process_main",
                    protocol="elf_libc_start_main",
                    registration_address=node.record.address,
                )
            )
    return result


def _index_address(value: object) -> str:
    try:
        return f"0x{int(str(value), 0):x}"
    except (TypeError, ValueError):
        return ""


def build_program_index(
    manifest: Manifest,
    nodes: Sequence[FunctionNode],
    *,
    operation_specs: OperationSpecSet | None = None,
) -> ProgramIndex:
    started = time.perf_counter()
    specs = operation_specs or load_operation_specs()
    node_rows = tuple(nodes)
    names = {node.record.name for node in node_rows}
    callee_map = {
        node.record.name: tuple(sorted(set(str(item) for item in node.metadata.get("callees", ()) if str(item) in names)))
        for node in node_rows
    }
    caller_map = {
        node.record.name: tuple(sorted(set(str(item) for item in node.metadata.get("callers", ()) if str(item) in names)))
        for node in node_rows
    }
    explicit_entries = tuple(node for node in node_rows if node.record.name.lower() in ENTRY_NAMES)
    entry_nodes = explicit_entries or tuple(node for node in node_rows if not caller_map.get(node.record.name))
    process_entries = tuple(
        EntrySurface(
            function_name=node.record.name,
            function_address=node.record.address,
            kind="process_entrypoint" if node.record.name.lower() in ENTRY_NAMES else "exported_entry",
        )
        for node in entry_nodes
    )
    ubus_entries = tuple(_indexed_ubus_entry_surfaces(node_rows))
    callback_entries = tuple(_indexed_callback_entry_surfaces(node_rows))
    recovered_main_entries = tuple(_indexed_main_entry_surfaces(node_rows))
    entries = tuple(
        sorted(
            {*process_entries, *recovered_main_entries, *ubus_entries, *callback_entries},
            key=lambda item: (
                item.function_address,
                item.kind,
                item.object_name,
                item.method_name,
                item.event_name,
                item.registration_address,
            ),
        )
    )
    entry_names = tuple(item.function_name for item in entries)
    reachable_from_entry = _reachable_union(entry_names, callee_map)
    functions = tuple(
        IndexedFunction(
            name=node.record.name,
            address=node.record.address,
            relative_address=node.record.relative_address,
            relative_path=node.record.relative_path,
            text=node.text or "",
            callees=callee_map.get(node.record.name, ()),
            callers=caller_map.get(node.record.name, ()),
            reachable_from_entry=node.record.name in reachable_from_entry,
        )
        for node in node_rows
    )

    operations: list[IndexedOperation] = []
    objects: list[IndexedMemoryObject] = []
    strings: list[IndexedString] = []
    sources: list[SourceObservation] = []
    for node in node_rows:
        node_pcode = _pcode_operations(node, specs)
        operations.extend(node_pcode)
        # A PLT/import thunk decompiles with the imported function's prototype.
        # Treating that declaration as a call makes the thunk look like an
        # allocation, release, or semantic sink in its own right.  Real call
        # sites remain available through their p-code and C operations.
        if not node.record.is_thunk:
            operations.extend(_text_operations(node, specs, node_pcode))
        objects.extend(_memory_objects(node))
        strings.extend(_strings(node, reachable=node.record.name in reachable_from_entry))
    local_function_names = {
        specs.normalize_name(function.name): function.name for function in functions
    }
    operations_by_node = {
        node.record.name: tuple(
            item for item in operations if item.function_name == node.record.name
        )
        for node in node_rows
    }
    for node in node_rows:
        if not node.record.is_thunk:
            operations.extend(
                _local_call_operations(
                    node,
                    specs,
                    local_function_names,
                    operations_by_node.get(node.record.name, ()),
                )
            )
    allocator_wrappers = _allocator_wrapper_names(functions)
    if allocator_wrappers:
        operations_by_function: dict[str, list[IndexedOperation]] = {}
        for operation in operations:
            operations_by_function.setdefault(operation.function_name, []).append(operation)
        for node in node_rows:
            if not node.record.is_thunk:
                operations.extend(
                    _wrapper_allocation_operations(
                        node,
                        allocator_wrappers,
                        operations_by_function.get(node.record.name, ()),
                    )
                )
    operations = _merge_operations(operations)
    operations = _apply_local_output_contracts(operations, functions, specs)
    objects.extend(_heap_memory_objects(operations))
    for operation in operations:
        if operation.name in SOURCE_OPERATIONS:
            sources.append(
                SourceObservation(
                    kind=operation.name,
                    function_name=operation.function_name,
                    operation_address=operation.operation_address,
                    expression=operation.role("source") or operation.role("destination"),
                )
            )
    for function in functions:
        for token in ("argv", "stdin", "environ"):
            if re.search(rf"\b{token}\b", function.text):
                sources.append(SourceObservation(token, function.name, function.address, token))
    local_lifecycle = tuple(_lifecycle_events(operations, functions))
    lifecycle = tuple(
        [
            *local_lifecycle,
            *_interprocedural_lifecycle_events(
                functions,
                operations,
                local_lifecycle,
                specs,
            ),
        ]
    )
    summaries = _function_summaries(functions, operations, callee_map)
    path_relations = tuple(
        relation
        for function in functions
        for relation in _structured_path_relations(function)
    )
    basic_blocks = tuple(
        IndexedBasicBlock(
            function_name=node.record.name,
            start_address=str(raw.get("start") or ""),
            end_address=str(raw.get("end") or raw.get("start") or ""),
            successors=tuple(str(item) for item in raw.get("successors", ()) if str(item)),
        )
        for node in node_rows
        for raw in node.record.basic_blocks
        if raw.get("start")
    )
    literal_consumers = tuple(_literal_consumers(strings, operations, functions))
    scope_exits = tuple(_scope_exits(functions, basic_blocks, node_rows))
    resource_paths = tuple(
        _resource_paths(functions, operations, lifecycle, basic_blocks, scope_exits)
    )
    reachability = tuple(
        (name, tuple(sorted(_reachable_union((name,), callee_map)))) for name in sorted(callee_map)
    )
    load_count = sum(item.kind == "load" for item in operations)
    store_count = sum(item.kind == "store" for item in operations)
    call_count = sum(item.kind == "call" for item in operations)
    metrics = ProgramIndexMetrics(
        build_seconds=round(time.perf_counter() - started, 6),
        functions=len(functions),
        call_operations=call_count,
        load_operations=load_count,
        store_operations=store_count,
        memory_objects=len(objects),
        lifecycle_events=len(lifecycle),
    )
    return ProgramIndex(
        binary_identity=manifest.binary,
        functions=functions,
        operations=tuple(operations),
        memory_objects=tuple(_unique(objects, key=lambda item: item.identity)),
        lifecycle_events=lifecycle,
        strings=tuple(_unique(strings, key=lambda item: (item.function_name, item.address, item.value))),
        literal_consumers=literal_consumers,
        entry_surfaces=entries,
        source_observations=tuple(_unique(sources, key=lambda item: (item.kind, item.function_name, item.operation_address))),
        function_summaries=summaries,
        path_relations=path_relations,
        basic_blocks=basic_blocks,
        scope_exits=scope_exits,
        resource_paths=resource_paths,
        reachability=reachability,
        metrics=metrics,
        manifest=manifest,
        nodes=node_rows,
    )


def _pcode_operations(node: FunctionNode, specs: OperationSpecSet) -> list[IndexedOperation]:
    rows: list[IndexedOperation] = []
    line_by_address = _line_address_map(node)
    for raw in node.record.pcode_calls:
        operation_address = str(raw.get("call_address") or raw.get("operation_address") or node.record.address)
        line_number = line_by_address.get(str(raw.get("call_address") or ""), 0)
        recovered_import = (
            _indirect_import_call_near_line(node, line_number)
            if not str(raw.get("callee") or "").strip()
            else None
        )
        observed_name = normalize_observed_name(
            raw.get("callee") or (recovered_import[0] if recovered_import else "indirect_call")
        )
        name = specs.normalize_name(observed_name)
        spec = specs.get(name)
        pcode_args = tuple(_pcode_argument(item) for item in raw.get("args", ()) if item is not None)
        args = recovered_import[1] if recovered_import else pcode_args
        rows.append(
            IndexedOperation(
                kind="call",
                name=spec.name if spec else name,
                backend=spec.backend if spec else "",
                semantics=spec.semantics if spec else "unknown_call",
                effect_kind=spec.effect_kind if spec else "",
                function_name=node.record.name,
                function_address=node.record.address,
                operation_address=operation_address,
                line_number=line_number,
                arguments=args,
                argument_roles=_role_values(spec.argument_roles if spec else (), args),
                evidence_source="pcode_call",
                observed_name=observed_name,
                output_pointer_args=spec.output_pointer_args if spec else (),
                output_write_guarantee=spec.output_write_guarantee if spec else "",
            )
        )
    for kind, raw_rows in (("load", node.record.pcode_loads), ("store", node.record.pcode_stores)):
        for raw in raw_rows:
            address_vars = tuple(str(item) for item in raw.get("address_vars", ()) if str(item))
            if not address_vars and raw.get("base_var"):
                address_vars = (str(raw.get("base_var")),)
            constants = tuple(
                parsed
                for item in raw.get("address_constants", ())
                if (parsed := _optional_int(item)) is not None
            )
            direct_constant = _optional_int(raw.get("address_constant"))
            if direct_constant is not None:
                constants = (*constants, direct_constant)
            definedness_basis = str(raw.get("definedness_basis") or "")
            # Older exporters inferred that a LOAD through a pointer named
            # ``local_*`` read uninitialized stack storage merely because no
            # STORE through that pointer had appeared earlier.  A local
            # pointer is not the pointee it addresses.  Retain exact stack
            # byte-range evidence and legacy basis-free fixtures, but reject
            # the ambiguous variable-name heuristic.
            defined_ranges = _byte_ranges(raw.get("defined_byte_ranges"))
            trustworthy_definedness = (
                definedness_basis != "prior_pcode_store_variable_byte_ranges"
                and not (
                    definedness_basis == "prior_pcode_store_byte_ranges"
                    and str(raw.get("definedness") or "") == "undefined"
                    and not defined_ranges
                )
            )
            rows.append(
                IndexedOperation(
                    kind=kind,
                    name=f"pcode_{kind}",
                    backend="memory_access",
                    semantics=f"direct_memory_{kind}",
                    effect_kind=f"memory_{kind}",
                    function_name=node.record.name,
                    function_address=node.record.address,
                    operation_address=str(raw.get("operation_address") or node.record.address),
                    line_number=line_by_address.get(str(raw.get("operation_address") or ""), 0),
                    arguments=address_vars,
                    argument_roles=(("address", address_vars[0]),) if address_vars else (),
                    width_bytes=_optional_int(raw.get("read_width") if kind == "load" else raw.get("write_width")),
                    definedness=(
                        str(raw.get("definedness") or "")
                        if trustworthy_definedness
                        else ""
                    ),
                    definedness_basis=definedness_basis,
                    defined_byte_ranges=(
                        defined_ranges
                        if trustworthy_definedness
                        else ()
                    ),
                    undefined_byte_ranges=(
                        _byte_ranges(raw.get("undefined_byte_ranges"))
                        if trustworthy_definedness
                        else ()
                    ),
                    stack_offset=(
                        _optional_int(raw.get("stack_offset"))
                        if trustworthy_definedness
                        else None
                    ),
                    evidence_source=f"pcode_{kind}",
                    observed_name=f"pcode_{kind}",
                    address_constants=tuple(dict.fromkeys(constants)),
                )
            )
    # High p-code can fold an absolute access into a decompiler RAM symbol.
    # Preserve that exact Ghidra address and its mapped machine instruction so
    # null accesses are not reduced to an uncorrelated crash observation.
    for line_number, line in enumerate((node.text or "").splitlines(), start=1):
        for match in re.finditer(r"\buRam(?P<address>[0-9A-Fa-f]{8,16})\b", line):
            constant = int(match.group("address"), 16)
            suffix = line[match.end() :]
            kind = "store" if re.match(r"\s*=\s*(?!=)", suffix) else "load"
            rows.append(
                IndexedOperation(
                    kind=kind,
                    name=f"ghidra_absolute_{kind}",
                    backend="memory_access",
                    semantics=f"direct_memory_{kind}",
                    effect_kind=f"memory_{kind}",
                    function_name=node.record.name,
                    function_address=node.record.address,
                    operation_address=_operation_address_for_line(node, line_number),
                    line_number=line_number,
                    arguments=(hex(constant),),
                    argument_roles=(("address", hex(constant)),),
                    evidence_source="ghidra_absolute_memory",
                    observed_name=f"uRam{match.group('address')}",
                    address_constants=(constant,),
                )
            )
    return rows


def _text_operations(
    node: FunctionNode,
    specs: OperationSpecSet,
    existing: Sequence[IndexedOperation],
) -> list[IndexedOperation]:
    rows: list[IndexedOperation] = []
    for line_number, line in enumerate((node.text or "").splitlines(), start=1):
        for match, argument_text in _nested_call_matches(line):
            if re.match(
                rf"^\s*[^;{{}}=]*\b{re.escape(match.group('name'))}\s*\([^;{{}}]*\)\s*\{{",
                line,
            ):
                continue
            if match.group("name").lower() == node.record.name.lower():
                continue
            spec = specs.get(match.group("name"))
            if spec is None:
                continue
            args = tuple(_split_arguments(argument_text))
            role_values = list(_role_values(spec.argument_roles, args))
            assignment_result = _assignment_result(line[: match.start()])
            if assignment_result and spec.semantics in {
                "heap_allocate",
                "heap_reallocate",
                "filesystem_access",
                "outbound_connect",
                "socket_acquire",
                "stream_acquire",
                "insecure_random_api",
            }:
                role_values.append(("result", assignment_result))
            rows.append(
                IndexedOperation(
                    kind="call",
                    name=spec.name,
                    backend=spec.backend,
                    semantics=spec.semantics,
                    effect_kind=spec.effect_kind,
                    function_name=node.record.name,
                    function_address=node.record.address,
                    operation_address=(
                        _exact_text_call_address(node, line_number, spec.name, existing)
                        or f"{node.record.address}:line:{line_number}:col:{match.start()}"
                    ),
                    line_number=line_number,
                    arguments=args,
                    argument_roles=tuple(role_values),
                    evidence_source="c_text",
                    observed_name=normalize_observed_name(match.group("name")),
                    output_pointer_args=spec.output_pointer_args,
                    output_write_guarantee=spec.output_write_guarantee,
                )
            )
    for line_number, observed_name, args, assignment_result in _indirect_import_calls_in_text(
        node.text or ""
    ):
        spec = specs.get(observed_name)
        if spec is None:
            continue
        role_values = list(_role_values(spec.argument_roles, args))
        if assignment_result and spec.semantics in {
            "heap_allocate",
            "heap_reallocate",
            "filesystem_access",
            "outbound_connect",
            "socket_acquire",
            "stream_acquire",
            "insecure_random_api",
        }:
            role_values.append(("result", assignment_result))
        rows.append(
            IndexedOperation(
                kind="call",
                name=spec.name,
                backend=spec.backend,
                semantics=spec.semantics,
                effect_kind=spec.effect_kind,
                function_name=node.record.name,
                function_address=node.record.address,
                operation_address=(
                    _exact_text_call_address(node, line_number, spec.name, existing)
                    or f"{node.record.address}:line:{line_number}:indirect:{spec.name}"
                ),
                line_number=line_number,
                arguments=args,
                argument_roles=tuple(role_values),
                evidence_source="c_text_indirect_import",
                observed_name=normalize_observed_name(observed_name),
                output_pointer_args=spec.output_pointer_args,
                output_write_guarantee=spec.output_write_guarantee,
            )
        )
    return rows


def _local_call_operations(
    node: FunctionNode,
    specs: OperationSpecSet,
    local_function_names: Mapping[str, str],
    existing: Sequence[IndexedOperation],
) -> list[IndexedOperation]:
    """Index direct local calls without assigning them ownership semantics."""

    pcode_by_name: dict[str, list[str]] = {}
    for operation in existing:
        if operation.kind == "call":
            pcode_by_name.setdefault(operation.name, []).append(operation.operation_address)
    seen_by_name: dict[str, int] = {}
    rows: list[IndexedOperation] = []
    for line_number, line in enumerate((node.text or "").splitlines(), start=1):
        for match, argument_text in _nested_call_matches(line):
            observed = normalize_observed_name(match.group("name"))
            normalized = specs.normalize_name(observed)
            callee_name = local_function_names.get(normalized)
            if not callee_name or callee_name == node.record.name:
                continue
            if re.match(
                rf"^\s*[^;{{}}=]*\b{re.escape(match.group('name'))}\s*\([^;{{}}]*\)\s*\{{",
                line,
            ):
                continue
            ordinal = seen_by_name.get(normalized, 0)
            seen_by_name[normalized] = ordinal + 1
            addresses = pcode_by_name.get(normalized, ())
            address = (
                addresses[ordinal]
                if ordinal < len(addresses)
                else f"{node.record.address}:line:{line_number}:col:{match.start()}"
            )
            rows.append(
                IndexedOperation(
                    kind="call",
                    name=normalized,
                    backend="",
                    semantics="unknown_call",
                    effect_kind="local_direct_call",
                    function_name=node.record.name,
                    function_address=node.record.address,
                    operation_address=address,
                    line_number=line_number,
                    arguments=tuple(_split_arguments(argument_text)),
                    evidence_source="local_call_c_text",
                    observed_name=observed,
                )
            )
    return rows


def _nested_call_matches(line: str) -> Iterable[tuple[Any, str]]:
    start_pattern = re.compile(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for match in start_pattern.finditer(line):
        opening = line.find("(", match.start())
        depth = 0
        quote = ""
        escaped = False
        for index in range(opening, len(line)):
            character = line[index]
            if quote:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = ""
                continue
            if character in {'"', "'"}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    yield match, line[opening + 1 : index]
                    break


def _indirect_import_calls(line: str) -> Iterable[tuple[str, tuple[str, ...]]]:
    """Recover Ghidra's ``(*(code *)PTR_name_address)(args)`` spelling."""

    for match in INDIRECT_IMPORT_CALL_RE.finditer(line):
        yield match.group("name"), tuple(_split_arguments(match.group("args")))


def _indirect_import_calls_in_text(
    text: str,
) -> Iterable[tuple[int, str, tuple[str, ...], str]]:
    for match in INDIRECT_IMPORT_CALL_RE.finditer(text):
        line_number = text[: match.start()].count("\n") + 1
        line_start = text.rfind("\n", 0, match.start()) + 1
        prefix = text[line_start : match.start()]
        assignment = re.search(
            r"(?P<result>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"\(\s*\*\s*\(\s*code\s*\*\s*\)\s*$",
            prefix,
        )
        yield (
            line_number,
            match.group("name"),
            tuple(_split_arguments(match.group("args"))),
            assignment.group("result") if assignment else "",
        )


def _indirect_import_call_near_line(
    node: FunctionNode,
    exported_line_number: int,
) -> tuple[str, tuple[str, ...]] | None:
    """Map an indirect p-code call to its exact decompiler import statement.

    Normalized exports prepend a three-line function/address header while
    Ghidra line facts retain decompiler-native line numbers.  Applying that
    known offset is intentionally stricter than nearest-line matching: adjacent
    imported calls commonly occur only two lines apart, and guessing would
    assign the wrong API contract to an exact machine callsite.
    """

    text = node.text or ""
    if not text or exported_line_number <= 0:
        return None
    lines = text.splitlines()
    header_offset = 3 if lines and lines[0].startswith("// Function:") else 0
    expected_physical_line = exported_line_number + header_offset
    candidates: list[tuple[str, tuple[str, ...]]] = []
    for physical_line, name, args, _assignment in _indirect_import_calls_in_text(text):
        if physical_line == expected_physical_line:
            candidates.append((name, args))
    if not candidates:
        return None
    return candidates[0] if len(candidates) == 1 else None


def _apply_local_output_contracts(
    operations: Sequence[IndexedOperation],
    functions: Sequence[IndexedFunction],
    specs: OperationSpecSet,
) -> list[IndexedOperation]:
    contracts = {
        specs.normalize_name(function.name): indexes
        for function in functions
        if (indexes := _guaranteed_local_output_pointer_args(function))
    }
    if not contracts:
        return list(operations)
    rows: list[IndexedOperation] = []
    for operation in operations:
        indexes = contracts.get(specs.normalize_name(operation.name), ())
        if not indexes or operation.kind != "call":
            rows.append(operation)
            continue
        rows.append(
            replace(
                operation,
                output_pointer_args=tuple(indexes),
                output_write_guarantee="always",
            )
        )
    return rows


def _guaranteed_local_output_pointer_args(function: IndexedFunction) -> tuple[int, ...]:
    """Infer only unconditional top-level writes through pointer parameters."""

    parameters = _function_parameters(function)
    if not parameters or "goto" in function.text:
        return ()
    body_start = function.text.find("{")
    if body_start < 0:
        return ()
    returns = [match.start() for match in re.finditer(r"\breturn\b", function.text)]
    result: list[int] = []
    for index, parameter in enumerate(parameters):
        writes = list(
            re.finditer(
                rf"\*\s*(?:\(\s*)?{re.escape(parameter)}\s*\)?\s*=(?!=)",
                function.text,
                re.IGNORECASE,
            )
        )
        top_level = [
            match
            for match in writes
            if _brace_depth(function.text, body_start, match.start()) == 1
        ]
        if not top_level:
            continue
        first = top_level[0].start()
        if any(position < first for position in returns):
            continue
        result.append(index)
    return tuple(result)


def _brace_depth(text: str, start: int, end: int) -> int:
    segment = text[start:end]
    return segment.count("{") - segment.count("}")


def _allocator_wrapper_names(functions: Sequence[IndexedFunction]) -> frozenset[str]:
    names: set[str] = set()
    for function in functions:
        text = function.text
        if not re.search(r"\b(?:malloc|calloc|operator_new)\s*\(", text, re.IGNORECASE):
            continue
        if not re.search(r"\breturn\s+[A-Za-z_][A-Za-z0-9_]*\s*;", text):
            continue
        names.add(function.name.lower())
    return frozenset(names)


def _function_summaries(
    functions: Sequence[IndexedFunction],
    operations: Sequence[IndexedOperation],
    callee_map: Mapping[str, Sequence[str]],
) -> tuple[IndexedFunctionSummary, ...]:
    evidence: dict[str, set[str]] = {function.name: set() for function in functions}
    copy_sources: dict[str, set[int]] = {function.name: set() for function in functions}
    for operation in operations:
        if operation.semantics in {"heap_allocate", "heap_reallocate"}:
            evidence.setdefault(operation.function_name, set()).add(
                f"{operation.name}@{operation.operation_address}"
            )
    for function in functions:
        text = function.text
        if re.search(r"\b(?:malloc|calloc|realloc|operator_new)\s*\(", text, re.IGNORECASE):
            evidence[function.name].add("direct_allocator_call")
        if _allocation_construction_shape(text):
            evidence[function.name].add("allocation_construction_shape")
        if re.search(
            r"for\s*\([^)]*\)\s*\{[^{}]*\*[^;=]+\s*=\s*\*[^;]+;",
            text,
            re.DOTALL,
        ):
            copy_sources[function.name].add(2)

    changed = True
    while changed:
        changed = False
        for caller, callees in callee_map.items():
            inherited = {
                f"callee:{callee}"
                for callee in callees
                if evidence.get(callee)
            }
            if not inherited.issubset(evidence.setdefault(caller, set())):
                evidence[caller].update(inherited)
                changed = True
    return tuple(
        IndexedFunctionSummary(
            function_name=function.name,
            function_address=function.address,
            may_allocate=bool(evidence.get(function.name)),
            allocation_evidence=tuple(sorted(evidence.get(function.name, set()))),
            copy_source_arguments=tuple(sorted(copy_sources.get(function.name, set()))),
        )
        for function in functions
    )


def _allocation_construction_shape(text: str) -> bool:
    assignments = re.findall(
        r"\b(?P<left>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<call>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>[^;{}]*)\)\s*;",
        text,
    )
    if len(assignments) < 2 or not re.search(r"\breturn\s+[A-Za-z_][A-Za-z0-9_]*\s*;", text):
        return False
    assigned_names = {left for left, _call, _args in assignments}
    return any(
        re.search(rf"\*[^;=]+\s*=\s*{re.escape(name)}\s*;", text)
        for name in assigned_names
    )


def _structured_path_relations(function: IndexedFunction) -> list[IndexedPathRelation]:
    pattern = re.compile(
        r"if\s*\((?P<condition>[^{}]+)\)\s*\{\s*"
        r"(?P<guard>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<true>true|false)\s*;\s*\}"
        r"\s*else\s*\{\s*(?P=guard)\s*=\s*(?P<false>true|false)\s*;\s*\}",
        re.IGNORECASE,
    )
    rows: list[IndexedPathRelation] = []
    for match in pattern.finditer(function.text):
        rows.append(
            IndexedPathRelation(
                function_name=function.name,
                guard_variable=match.group("guard"),
                condition=" ".join(match.group("condition").split()),
                true_value=match.group("true").lower(),
                false_value=match.group("false").lower(),
                start_line=function.text[: match.start()].count("\n") + 1,
                end_line=function.text[: match.end()].count("\n") + 1,
            )
        )
    return rows


def _wrapper_allocation_operations(
    node: FunctionNode,
    wrapper_names: frozenset[str],
    existing: Sequence[IndexedOperation],
) -> list[IndexedOperation]:
    rows: list[IndexedOperation] = []
    pcode_by_name: dict[str, list[str]] = {}
    for operation in existing:
        if operation.function_name == node.record.name and operation.kind == "call":
            pcode_by_name.setdefault(operation.name.lower(), []).append(operation.operation_address)
    seen_by_name: dict[str, int] = {}
    for line_number, line in enumerate((node.text or "").splitlines(), start=1):
        for match in CALL_RE.finditer(line):
            name = match.group("name")
            normalized_name = name.lower()
            if normalized_name not in wrapper_names:
                continue
            args = tuple(_split_arguments(match.group("args")))
            assignment_result = _assignment_result(line[: match.start()])
            if not args or not assignment_result:
                continue
            ordinal = seen_by_name.get(normalized_name, 0)
            seen_by_name[normalized_name] = ordinal + 1
            addresses = pcode_by_name.get(normalized_name, [])
            operation_address = (
                addresses[ordinal]
                if ordinal < len(addresses)
                else f"{node.record.address}:line:{line_number}:col:{match.start()}"
            )
            rows.append(
                IndexedOperation(
                    kind="call",
                    name=normalized_name,
                    backend="memory_lifetime",
                    semantics="heap_allocate",
                    effect_kind="resource_acquire",
                    function_name=node.record.name,
                    function_address=node.record.address,
                    operation_address=operation_address,
                    line_number=line_number,
                    arguments=args,
                    argument_roles=(("size", args[0]), ("result", assignment_result)),
                    evidence_source="allocator_wrapper_call",
                )
            )
    return rows


def _assignment_result(prefix: str) -> str:
    match = re.search(
        r"(?P<result>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:(?:\([^()]*\))\s*)*$",
        prefix,
    )
    return match.group("result") if match else ""


def _memory_objects(node: FunctionNode) -> list[IndexedMemoryObject]:
    rows: list[IndexedMemoryObject] = []
    for raw in node.record.stack_regions:
        labels = tuple(str(item) for item in raw.get("var_names", ()) if str(item)) or ("stack_region",)
        start = str(raw.get("start_offset", ""))
        for label in labels:
            rows.append(
                IndexedMemoryObject(
                    identity=f"{node.record.address}:stack:{start}:{label}",
                    kind="stack",
                    function_name=node.record.name,
                    label=label,
                    size_bytes=_optional_int(raw.get("size_bytes")),
                    source="ghidra_stack_region",
                )
            )
    for kind, raw_rows in (
        ("global", node.record.global_refs),
        ("static", node.record.static_refs),
        ("tls", node.record.tls_refs),
    ):
        for raw in raw_rows:
            label = str(raw.get("label") or raw.get("var_display") or raw.get("address") or kind)
            address = str(raw.get("address") or "")
            rows.append(
                IndexedMemoryObject(
                    identity=f"{kind}:{address}:{label}",
                    kind=kind,
                    function_name=node.record.name,
                    label=label,
                    size_bytes=_optional_int(raw.get("size_bytes")),
                    address=address,
                    source=str(raw.get("capacity_source") or "ghidra_reference"),
                )
            )
    return rows


def _heap_memory_objects(operations: Sequence[IndexedOperation]) -> list[IndexedMemoryObject]:
    rows: list[IndexedMemoryObject] = []
    for operation in operations:
        if operation.semantics not in {"heap_allocate", "heap_reallocate"}:
            continue
        result = operation.role("result")
        if not result:
            continue
        size_expression = operation.role("size")
        rows.append(
            IndexedMemoryObject(
                identity=f"{operation.function_address}:{_normalize_resource(result)}",
                kind="heap",
                function_name=operation.function_name,
                label=result,
                size_bytes=_optional_int(size_expression),
                address=operation.operation_address,
                source=(
                    f"{operation.name}:{size_expression}"
                    if size_expression
                    else operation.name
                ),
            )
        )
    return rows


def _strings(node: FunctionNode, *, reachable: bool) -> list[IndexedString]:
    rows: list[IndexedString] = []
    for raw in node.record.string_refs:
        value = str(raw.get("value") or raw.get("string") or raw.get("text") or "")
        if value:
            rows.append(
                IndexedString(
                    value=value,
                    function_name=node.record.name,
                    address=str(raw.get("address") or raw.get("reference_address") or node.record.address),
                    reachable=reachable,
                    source="ghidra_string_reference",
                )
            )
    for match in re.finditer(r'"(?P<value>(?:\\.|[^"\\]){4,})"', node.text or ""):
            line_start = (node.text or "").rfind("\n", 0, match.start()) + 1
            line_end = (node.text or "").find("\n", match.end())
            if line_end < 0:
                line_end = len(node.text or "")
            global_refs = list(node.record.global_refs)
            literal_address = (
                str(global_refs[0].get("address") or node.record.address)
                if len(global_refs) == 1
                else node.record.address
            )
            rows.append(
                IndexedString(
                    match.group("value"),
                    node.record.name,
                    literal_address,
                    reachable,
                    "c_text_literal",
                    (node.text or "")[line_start:line_end].strip(),
                )
            )
    return rows


def _lifecycle_events(
    operations: Sequence[IndexedOperation],
    functions: Sequence[IndexedFunction],
) -> Iterable[LifecycleEvent]:
    alias_maps = _resource_alias_maps(functions)
    rows: list[LifecycleEvent] = []
    for operation in operations:
        semantics = operation.semantics
        if semantics == "heap_allocate":
            event_kind, resource_kind = "allocate", "heap"
        elif semantics == "heap_reallocate":
            old_argument = operation.role("resource")
            old_identity = _resource_identity(operation, old_argument, alias_maps)
            rows.append(LifecycleEvent(
                event_kind="use",
                resource_kind="heap",
                resource_identity=old_identity,
                allocator_family="c_heap",
                function_name=operation.function_name,
                function_address=operation.function_address,
                operation_address=operation.operation_address,
                line_number=operation.line_number,
                operation_name=operation.name,
                argument=old_argument,
            ))
            result = operation.role("result")
            if result:
                rows.append(LifecycleEvent(
                    event_kind="allocate",
                    resource_kind="heap",
                    resource_identity=_resource_identity(operation, result, alias_maps),
                    allocator_family="c_heap",
                    function_name=operation.function_name,
                    function_address=operation.function_address,
                    operation_address=operation.operation_address,
                    line_number=operation.line_number,
                    operation_name=operation.name,
                    argument=result,
                ))
            continue
        elif semantics == "heap_release":
            event_kind, resource_kind = "release", "heap"
        elif semantics in {"handle_release", "descriptor_release", "stream_release", "directory_release", "socket_release"}:
            event_kind = "release"
            resource_kind = {
                "descriptor_release": "descriptor",
                "stream_release": "stream",
                "directory_release": "directory",
                "socket_release": "socket",
            }.get(semantics, "handle")
        elif operation.name in {"open", "fopen", "opendir", "socket"} and operation.role("result"):
            event_kind = "allocate"
            resource_kind = {
                "fopen": "stream",
                "opendir": "directory",
                "socket": "socket",
            }.get(operation.name, "descriptor")
        elif semantics == "stream_acquire" and operation.role("result"):
            event_kind, resource_kind = "allocate", "stream"
        elif operation.name in {"read", "recv"}:
            event_kind = "use"
            resource_kind = "socket" if operation.name == "recv" else "descriptor"
        elif operation.name in {"fgets", "fread"}:
            event_kind, resource_kind = "use", "stream"
        elif semantics == "directory_use" or operation.name == "readdir":
            event_kind, resource_kind = "use", "directory"
        elif operation.kind in {"load", "store"} and operation.role("address"):
            event_kind, resource_kind = "use", "memory"
        else:
            continue
        argument = (
            operation.role("result")
            if event_kind == "allocate"
            else operation.role("resource")
            or operation.role("source")
            or operation.role("destination")
            or operation.role("address")
        )
        family = _allocator_family(operation.name)
        normalized_identity = _resource_identity(operation, argument, alias_maps)
        rows.append(LifecycleEvent(
            event_kind=event_kind,
            resource_kind=resource_kind,
            resource_identity=normalized_identity,
            allocator_family=family,
            function_name=operation.function_name,
            function_address=operation.function_address,
            operation_address=operation.operation_address,
            line_number=operation.line_number,
            operation_name=operation.name,
            argument=argument,
        ))

    acquired_kinds = {
        event.resource_identity: event.resource_kind
        for event in rows
        if event.event_kind == "allocate"
    }
    for event in rows:
        acquired_kind = acquired_kinds.get(event.resource_identity)
        if acquired_kind and event.event_kind != "allocate":
            yield replace(event, resource_kind=acquired_kind)
        else:
            yield event


def _interprocedural_lifecycle_events(
    functions: Sequence[IndexedFunction],
    operations: Sequence[IndexedOperation],
    local_events: Sequence[LifecycleEvent],
    specs: OperationSpecSet,
) -> Iterable[LifecycleEvent]:
    """Instantiate one-level, parameter-exact lifetime effects at callsites."""

    function_by_normalized = {
        specs.normalize_name(function.name): function for function in functions
    }
    parameters = {
        function.name: _function_parameters(function) for function in functions
    }
    events_by_function: dict[str, list[LifecycleEvent]] = {}
    acquired_kinds = {
        event.resource_identity: event.resource_kind
        for event in local_events
        if event.event_kind == "allocate"
    }
    for event in local_events:
        if event.event_kind in {"release", "use"}:
            events_by_function.setdefault(event.function_name, []).append(event)
    alias_maps = _resource_alias_maps(functions)
    for call in operations:
        if call.kind != "call" or call.effect_kind != "local_direct_call":
            continue
        caller = next(
            (item for item in functions if item.name == call.function_name),
            None,
        )
        callee = function_by_normalized.get(call.name)
        if caller is None or callee is None or caller.name == callee.name:
            continue
        if not caller.reachable_from_entry:
            continue
        callee_parameters = parameters.get(callee.name, ())
        if not callee_parameters or len(call.arguments) < len(callee_parameters):
            continue
        parameter_index = {name: index for index, name in enumerate(callee_parameters)}
        for event in events_by_function.get(callee.name, ()):
            parameter = _simple_parameter_reference(event.argument)
            index = parameter_index.get(parameter)
            if index is None:
                continue
            actual = _simple_parameter_reference(call.arguments[index])
            if not actual:
                continue
            resource_identity = _resource_identity(call, actual, alias_maps)
            yield replace(
                event,
                resource_kind=acquired_kinds.get(resource_identity, event.resource_kind),
                resource_identity=resource_identity,
                argument=actual,
                context_function_name=caller.name,
                context_function_address=caller.address,
                context_operation_address=call.operation_address,
                context_line_number=call.line_number,
                call_path=(caller.name, callee.name),
                instantiation_source="direct_parameter_call",
            )


def _function_parameters(function: IndexedFunction) -> tuple[str, ...]:
    match = re.search(
        rf"\b{re.escape(function.name)}\s*\((?P<parameters>.*?)\)\s*\{{",
        function.text,
        re.DOTALL,
    )
    if match is None:
        return ()
    raw_parameters = _split_arguments(match.group("parameters"))
    if len(raw_parameters) == 1 and raw_parameters[0].strip().lower() == "void":
        return ()
    names: list[str] = []
    for raw in raw_parameters:
        if "..." in raw or "(" in raw or ")" in raw:
            return ()
        identifiers = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", raw)
        if not identifiers:
            return ()
        names.append(identifiers[-1].lower())
    if len(set(names)) != len(names):
        return ()
    return tuple(names)


def _simple_parameter_reference(value: str) -> str:
    text = str(value or "").strip()
    while re.match(r"^\([^()]+\)\s*", text):
        text = re.sub(r"^\([^()]+\)\s*", "", text, count=1).strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
        return ""
    return text.lower()


def _resource_alias_maps(functions: Sequence[IndexedFunction]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    assignment_re = re.compile(
        r"(?<![A-Za-z0-9_*>.\]])(?P<left>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^;=]+\)\s*)?"
        r"(?P<right>[A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|\d+)\s*;"
    )
    for function in functions:
        parent: dict[str, str] = {}

        def find(value: str) -> str:
            parent.setdefault(value, value)
            while parent[value] != value:
                parent[value] = parent[parent[value]]
                value = parent[value]
            return value

        for match in assignment_re.finditer(function.text):
            left = _normalize_resource(match.group("left"))
            right = _normalize_resource(match.group("right"))
            left_root, right_root = find(left), find(right)
            # Prefer the right-hand origin so q = p resolves to p.
            if left_root != right_root:
                parent[left_root] = right_root
        result[function.name] = {value: find(value) for value in tuple(parent)}
    return result


def _resource_identity(
    operation: IndexedOperation,
    argument: str,
    alias_maps: Mapping[str, Mapping[str, str]],
) -> str:
    normalized = _normalize_resource(argument or f"return:{operation.operation_address}")
    normalized = str(alias_maps.get(operation.function_name, {}).get(normalized, normalized))
    if not re.search(r"(?:^|:)(?:dat_|global_|ptr_dat_)", normalized):
        normalized = f"{operation.function_address}:{normalized}"
    return normalized


def _literal_consumers(
    strings: Sequence[IndexedString],
    operations: Sequence[IndexedOperation],
    functions: Sequence[IndexedFunction],
) -> Iterable[IndexedLiteralConsumer]:
    """Connect an exact literal reference to the reachable call that consumes it."""

    reachable = {item.name: item.reachable_from_entry for item in functions}
    function_text = {item.name: item.text for item in functions}
    operations_by_function: dict[str, list[IndexedOperation]] = {}
    for operation in operations:
        if operation.kind == "call":
            operations_by_function.setdefault(operation.function_name, []).append(operation)
    for literal in strings:
        literal_address = _address_int(literal.address)
        for operation in operations_by_function.get(literal.function_name, ()):
            role = ""
            for role_name, value in operation.argument_roles:
                value_address = _address_int(value)
                if (
                    literal.value in value
                    or (literal_address is not None and value_address == literal_address)
                ):
                    role = role_name
                    break
            if not role and literal.context:
                observed = operation.observed_name or operation.name
                if re.search(rf"\b{re.escape(observed)}\s*\(", literal.context):
                    role = "literal_argument"
                else:
                    call_contains_literal = _call_contains_literal(
                        function_text.get(literal.function_name, ""),
                        observed,
                        literal.context,
                    )
                    if call_contains_literal:
                        role = (
                            operation.argument_roles[0][0]
                            if len(operation.argument_roles) == 1
                            else "literal_argument"
                        )
            if not role:
                continue
            yield IndexedLiteralConsumer(
                literal_address=literal.address,
                literal_value=literal.value,
                literal_fingerprint=hashlib.sha256(
                    literal.value.encode("utf-8", errors="replace")
                ).hexdigest(),
                function_name=literal.function_name,
                consumer_name=operation.name,
                consumer_address=operation.operation_address,
                argument_role=role,
                reachable=bool(reachable.get(literal.function_name, False)),
            )


def _call_contains_literal(text: str, observed_name: str, literal_context: str) -> bool:
    literal_position = text.find(literal_context)
    if literal_position < 0:
        return False
    needle = observed_name + "("
    search_from = 0
    while True:
        call_position = text.find(needle, search_from)
        if call_position < 0 or call_position > literal_position:
            return False
        if literal_position - call_position <= 4096:
            closing = text.find(")", literal_position, literal_position + 4097)
            if closing >= 0:
                return True
        search_from = call_position + len(needle)


def _scope_exits(
    functions: Sequence[IndexedFunction],
    basic_blocks: Sequence[IndexedBasicBlock],
    nodes: Sequence[FunctionNode],
) -> Iterable[IndexedScopeExit]:
    """Enumerate exact CFG terminals, with text returns as a fixture fallback."""

    nodes_by_name = {item.record.name: item for item in nodes}
    blocks_by_function: dict[str, list[IndexedBasicBlock]] = {}
    for block in basic_blocks:
        blocks_by_function.setdefault(block.function_name, []).append(block)
    for function in functions:
        blocks = blocks_by_function.get(function.name, ())
        terminal_blocks = [item for item in blocks if not item.successors]
        if terminal_blocks:
            node = nodes_by_name.get(function.name)
            for block in terminal_blocks:
                yield IndexedScopeExit(
                    function_name=function.name,
                    function_address=function.address,
                    operation_address=block.end_address,
                    line_number=_line_for_address(node, block.end_address) if node else 0,
                    kind="cfg_terminal",
                )
            continue
        text_exit_count = 0
        for line_number, line in enumerate(function.text.splitlines(), start=1):
            if not re.search(r"\breturn\b", line):
                continue
            text_exit_count += 1
            yield IndexedScopeExit(
                function_name=function.name,
                function_address=function.address,
                operation_address=f"{function.address}:line:{line_number}:scope_exit",
                line_number=line_number,
                kind="return",
            )
        lines = function.text.splitlines()
        final_line = next((line for line in reversed(lines) if line.strip()), "")
        if text_exit_count == 0 or not re.search(r"\breturn\b", final_line):
            line_number = max(1, len(lines))
            yield IndexedScopeExit(
                function_name=function.name,
                function_address=function.address,
                operation_address=f"{function.address}:line:{line_number}:scope_exit",
                line_number=line_number,
                kind="function_end",
            )


def _resource_paths(
    functions: Sequence[IndexedFunction],
    operations: Sequence[IndexedOperation],
    lifecycle: Sequence[LifecycleEvent],
    basic_blocks: Sequence[IndexedBasicBlock],
    exits: Sequence[IndexedScopeExit],
) -> Iterable[IndexedResourcePath]:
    """Summarize allocation-to-exit paths without converting absence into proof."""

    function_by_name = {item.name: item for item in functions}
    operations_by_function: dict[str, list[IndexedOperation]] = {}
    releases_by_resource: dict[tuple[str, str], list[LifecycleEvent]] = {}
    blocks_by_function: dict[str, list[IndexedBasicBlock]] = {}
    exits_by_function: dict[str, list[IndexedScopeExit]] = {}
    for operation in operations:
        operations_by_function.setdefault(operation.function_name, []).append(operation)
    for event in lifecycle:
        if event.event_kind == "release":
            releases_by_resource.setdefault(
                (
                    event.context_function_name or event.function_name,
                    event.resource_identity,
                ),
                [],
            ).append(event)
    for block in basic_blocks:
        blocks_by_function.setdefault(block.function_name, []).append(block)
    for scope_exit in exits:
        exits_by_function.setdefault(scope_exit.function_name, []).append(scope_exit)
    for allocation in (item for item in lifecycle if item.event_kind == "allocate" and item.resource_kind == "heap"):
        function = function_by_name.get(allocation.function_name)
        if function is None:
            continue
        token = allocation.argument or allocation.resource_identity.rsplit(":", 1)[-1]
        escaped, escape_kind = _resource_escape(
            function,
            operations_by_function.get(allocation.function_name, ()),
            allocation,
            token,
        )
        releases = tuple(
            releases_by_resource.get(
                (allocation.function_name, allocation.resource_identity),
                (),
            )
        )
        function_blocks = tuple(blocks_by_function.get(allocation.function_name, ()))
        release_covers_owned_paths = bool(releases) and _release_covers_owned_paths(
            function.text,
            token,
        )
        for scope_exit in exits_by_function.get(allocation.function_name, ()):
            live = False if release_covers_owned_paths else _allocation_path_avoids_releases(
                allocation.operation_address,
                scope_exit.operation_address,
                tuple(item.context_operation_address or item.operation_address for item in releases),
                function_blocks,
                allocation.line_number,
                scope_exit.line_number,
                tuple(item.context_line_number or item.line_number for item in releases),
            )
            yield IndexedResourcePath(
                resource_identity=allocation.resource_identity,
                allocation_address=allocation.operation_address,
                function_name=allocation.function_name,
                exit_address=scope_exit.operation_address,
                release_addresses=tuple(item.operation_address for item in releases),
                feasible=live is not None,
                live_at_exit=live is True and not escaped,
                escaped=escaped,
                escape_kind=escape_kind,
            )


def _resource_escape(
    function: IndexedFunction,
    operations: Sequence[IndexedOperation],
    allocation: LifecycleEvent,
    token: str,
) -> tuple[bool, str]:
    if not token or token.startswith("return:"):
        return True, "unresolved_allocation_result"
    escaped_token = re.escape(token)
    if re.search(rf"\breturn\s+{escaped_token}\b", function.text):
        return True, "returned_ownership"
    if re.search(rf"\b(?:DAT_|PTR_DAT_|global_|g_)[A-Za-z0-9_]*\s*=\s*{escaped_token}\b", function.text):
        return True, "global_transfer"
    if re.search(rf"\*\s*param_[A-Za-z0-9_]+\s*=\s*{escaped_token}\b", function.text):
        return True, "output_parameter_transfer"
    allocation_value = _address_int(allocation.operation_address)
    for operation in operations:
        if operation.function_name != function.name or operation.kind != "call":
            continue
        operation_value = _address_int(operation.operation_address)
        if allocation_value is not None and operation_value is not None and operation_value <= allocation_value:
            continue
        if operation.semantics != "unknown_call":
            continue
        if any(re.search(rf"\b{escaped_token}\b", argument) for argument in operation.arguments):
            return True, "unresolved_ownership_call"
    allocation_column = _text_operation_column(allocation.operation_address)
    for line_number, line in enumerate(function.text.splitlines(), start=1):
        if line_number < allocation.line_number:
            continue
        for match, arguments in _nested_call_matches(line):
            if match.group("name") in {"if", "while", "for", "switch", "sizeof", "return"}:
                continue
            if line_number == allocation.line_number and match.start() <= allocation_column:
                continue
            if not re.search(rf"\b{escaped_token}\b", arguments):
                continue
            known = next(
                (
                    item
                    for item in operations
                    if item.function_name == function.name
                    and (item.observed_name or item.name).lower() == match.group("name").lower()
                    and item.semantics != "unknown_call"
                ),
                None,
            )
            if known is None:
                return True, "unresolved_ownership_call"
    return False, ""


def _release_covers_owned_paths(text: str, token: str) -> bool:
    """Recognize the canonical allocation-failure split without treating null as owned."""
    escaped = re.escape(token)
    null_check = re.search(
        rf"\bif\s*\([^\n]*\b{escaped}\b[^\n]*(?:0x0|NULL|nullptr)[^\n]*\)",
        text,
        re.IGNORECASE,
    )
    if null_check is None:
        return False
    else_match = re.search(r"\}\s*else\s*\{", text[null_check.end() :])
    if else_match is None:
        return False
    success_start = null_check.end() + else_match.end()
    release = re.search(rf"\bfree\s*\(\s*{escaped}\s*\)", text[success_start:])
    if release is None:
        return False
    before_release = text[success_start : success_start + release.start()]
    return re.search(r"\breturn\b", before_release) is None


def _allocation_path_avoids_releases(
    allocation_address: str,
    exit_address: str,
    release_addresses: Sequence[str],
    blocks: Sequence[IndexedBasicBlock],
    allocation_line: int,
    exit_line: int,
    release_lines: Sequence[int],
) -> bool | None:
    if not blocks:
        if allocation_line <= 0 or exit_line <= 0 or exit_line < allocation_line:
            return None
        allocation_column = _text_operation_column(allocation_address)
        released = any(
            (
                allocation_line < line <= exit_line
                or (
                    line == allocation_line == exit_line
                    and _text_operation_column(address) > allocation_column
                )
            )
            for address, line in zip(release_addresses, release_lines)
            if line > 0
        )
        return not released

    def containing(address: str) -> IndexedBasicBlock | None:
        value = _address_int(address)
        if value is None:
            return None
        return next(
            (
                block
                for block in blocks
                if (_address_int(block.start_address) or -1)
                <= value
                <= (_address_int(block.end_address) or -1)
            ),
            None,
        )

    start = containing(allocation_address)
    target = containing(exit_address)
    if start is None or target is None:
        return None
    release_blocks = {
        block.start_address
        for address in release_addresses
        if (block := containing(address)) is not None
    }
    by_start = {item.start_address: item for item in blocks}

    def successor_start(address: str) -> str:
        block = containing(address)
        return block.start_address if block else address

    pending = [start.start_address]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current in seen or (current in release_blocks and current != start.start_address):
            continue
        seen.add(current)
        if current == target.start_address:
            if current == start.start_address:
                allocation_value = _address_int(allocation_address) or -1
                exit_value = _address_int(exit_address) or -1
                released_between = any(
                    allocation_value < (_address_int(address) or -1) <= exit_value
                    for address in release_addresses
                )
                return not released_between
            return True
        block = by_start.get(current)
        if block:
            pending.extend(successor_start(item) for item in block.successors)
    return False


def _text_operation_column(address: str) -> int:
    match = re.search(r":col:(\d+)", str(address or ""))
    return int(match.group(1)) if match else 2**31 - 1


def _merge_operations(rows: Sequence[IndexedOperation]) -> list[IndexedOperation]:
    merged: dict[tuple[str, str, str, str], IndexedOperation] = {}
    for row in rows:
        key = (row.function_address, row.operation_address, row.kind, row.name)
        previous = merged.get(key)
        if previous is None:
            merged[key] = row
            continue
        if previous.evidence_source != "pcode_call" and row.evidence_source.startswith("pcode"):
            primary, secondary = row, previous
        else:
            primary, secondary = previous, row
        # Exact p-code roles own the callsite.  Source recovery may fill a
        # missing role, but must never replace an exact argument with a
        # same-name call from another source line.
        roles = dict(secondary.argument_roles)
        roles.update(dict(primary.argument_roles))
        # Decompiled assignment recovery adds a result role that p-code CALL
        # rows do not currently export; retain it while preferring exact p-code.
        if secondary.role("result"):
            roles["result"] = secondary.role("result")
        merged[key] = replace(
            primary,
            backend=primary.backend or secondary.backend,
            semantics=(
                secondary.semantics
                if primary.semantics == "unknown_call" and secondary.semantics != "unknown_call"
                else primary.semantics
            ),
            effect_kind=primary.effect_kind or secondary.effect_kind,
            line_number=primary.line_number or secondary.line_number,
            arguments=(
                secondary.arguments
                if secondary.evidence_source
                in {"c_text", "c_text_indirect_import", "local_call_c_text"}
                else primary.arguments or secondary.arguments
            ),
            argument_roles=tuple(sorted(roles.items())),
            observed_name=primary.observed_name or secondary.observed_name,
            address_constants=tuple(
                dict.fromkeys((*primary.address_constants, *secondary.address_constants))
            ),
            output_pointer_args=primary.output_pointer_args or secondary.output_pointer_args,
            output_write_guarantee=(
                primary.output_write_guarantee or secondary.output_write_guarantee
            ),
            definedness_basis=primary.definedness_basis or secondary.definedness_basis,
        )
    return sorted(merged.values(), key=lambda item: (item.function_address, item.operation_address, item.kind, item.name))


def _reachable_union(roots: Iterable[str], edges: Mapping[str, Sequence[str]]) -> set[str]:
    seen: set[str] = set()
    pending = list(roots)
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pending.extend(item for item in edges.get(current, ()) if item not in seen)
    return seen


def _line_for_address(node: FunctionNode, address: str) -> int:
    return _line_address_map(node).get(address, 0)


def _line_address_map(node: FunctionNode) -> dict[str, int]:
    rows: dict[str, int] = {}
    for raw in node.record.c_line_addresses:
        line_number = _optional_int(raw.get("line_number") or raw.get("line")) or 0
        addresses = {str(raw.get(key) or "") for key in ("address", "start", "operation_address")}
        for key in ("addresses", "call_addresses", "load_addresses", "store_addresses"):
            values = raw.get(key, ())
            if isinstance(values, (list, tuple)):
                addresses.update(str(item) for item in values if item)
        for address in addresses:
            if address:
                rows.setdefault(address, line_number)
    return rows


def _operation_address_for_line(node: FunctionNode, line_number: int) -> str:
    candidate_lines = {line_number}
    text_lines = (node.text or "").splitlines()
    if len(text_lines) >= 3 and text_lines[0].startswith("// Function:"):
        candidate_lines.add(max(1, line_number - 3))
    for raw in node.record.c_line_addresses:
        current = _optional_int(raw.get("line_number") or raw.get("line")) or 0
        if current not in candidate_lines:
            continue
        values: list[str] = []
        for key in ("load_addresses", "store_addresses", "addresses"):
            raw_values = raw.get(key, ())
            if isinstance(raw_values, Sequence) and not isinstance(raw_values, (str, bytes, bytearray)):
                values.extend(str(item) for item in raw_values if item)
        if values:
            return min(values, key=lambda value: _address_int(value) or 2**64 - 1)
    return node.record.address


def _exact_text_call_address(
    node: FunctionNode,
    physical_line_number: int,
    operation_name: str,
    existing: Sequence[IndexedOperation],
) -> str:
    """Resolve one source call using its exported line, never name ordinal."""

    lines = (node.text or "").splitlines()
    header_offset = 3 if lines and lines[0].startswith("// Function:") else 0
    exported_line_number = physical_line_number - header_offset
    line_addresses: set[str] = set()
    for raw in node.record.c_line_addresses:
        current = _optional_int(raw.get("line_number") or raw.get("line")) or 0
        if current != exported_line_number:
            continue
        for key in ("call_addresses", "addresses"):
            values = raw.get(key, ())
            if isinstance(values, Sequence) and not isinstance(values, (str, bytes, bytearray)):
                line_addresses.update(str(item) for item in values if item)
    matches = [
        item.operation_address
        for item in existing
        if item.function_name == node.record.name
        and item.kind == "call"
        and item.name == operation_name
        and item.operation_address in line_addresses
    ]
    if len(set(matches)) == 1:
        return matches[0]
    if not line_addresses:
        name_matches = [
            item.operation_address
            for item in existing
            if item.function_name == node.record.name
            and item.kind == "call"
            and item.name == operation_name
        ]
        if len(set(name_matches)) == 1:
            return name_matches[0]
    return ""


def _role_values(role_items: Sequence[tuple[str, int]], arguments: Sequence[str]) -> tuple[tuple[str, str], ...]:
    return tuple((role, arguments[index]) for role, index in role_items if index < len(arguments))


def _pcode_argument(value: Any) -> str:
    if not isinstance(value, Mapping):
        return str(value)
    variable = str(value.get("var_name") or "").strip()
    if variable and variable.upper() != "UNNAMED":
        return variable
    constant = value.get("constant")
    if constant is not None:
        try:
            return hex(int(constant))
        except (TypeError, ValueError):
            pass
    return str(value.get("repr") or value.get("expr") or value)


def _split_arguments(raw: str) -> list[str]:
    values: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(raw):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            values.append(raw[start:index].strip())
            start = index + 1
    tail = raw[start:].strip()
    if tail:
        values.append(tail)
    return values


def _allocator_family(name: str) -> str:
    if name in {"operator_new", "operator_delete"}:
        return "cpp_scalar"
    if name in {"operator_new_array", "operator_delete_array"}:
        return "cpp_array"
    if name in {"fopen", "fdopen", "fclose"}:
        return "stdio_stream"
    if name in {"opendir", "closedir", "readdir"}:
        return "directory"
    if name in {"socket", "closesocket", "recv"}:
        return "socket"
    if name in {"open", "close", "read"}:
        return "descriptor"
    return "c_heap"


def _normalize_resource(value: str) -> str:
    return re.sub(r"\s+", "", str(value or "unknown")).lower()


def _address_int(value: str) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _cfg_event_relation(
    blocks: Sequence[IndexedBasicBlock],
    before_address: str,
    after_address: str,
) -> IndexedEventRelation:
    before_value = _address_int(before_address)
    after_value = _address_int(after_address)
    if before_value is None or after_value is None:
        return IndexedEventRelation("cfg_address_unresolved", False, False, False, "basic_blocks")

    def containing(value: int) -> IndexedBasicBlock | None:
        return next(
            (
                block
                for block in blocks
                if (_address_int(block.start_address) or -1) <= value <= (_address_int(block.end_address) or -1)
            ),
            None,
        )

    before_block, after_block = containing(before_value), containing(after_value)
    if before_block is None or after_block is None:
        return IndexedEventRelation("cfg_block_unresolved", False, False, False, "basic_blocks")
    if before_block.start_address == after_block.start_address:
        ordered = before_value < after_value
        return IndexedEventRelation(
            "same_basic_block" if ordered else "same_basic_block_reversed",
            ordered,
            ordered,
            True,
            "ghidra_basic_block",
        )

    by_start = {block.start_address: block for block in blocks}

    def canonical_successor(address: str) -> str:
        value = _address_int(address)
        block = containing(value) if value is not None else None
        return block.start_address if block else address

    edges = {
        block.start_address: tuple(
            target
            for target in (canonical_successor(item) for item in block.successors)
            if target in by_start
        )
        for block in blocks
    }
    reachable = _reachable_union((before_block.start_address,), edges)
    if after_block.start_address not in reachable:
        return IndexedEventRelation("cfg_no_ordered_path", False, False, False, "ghidra_basic_block")

    starts = set(by_start)
    predecessors: dict[str, set[str]] = {start: set() for start in starts}
    for source, targets in edges.items():
        for target in targets:
            predecessors[target].add(source)
    entry = min(starts, key=lambda item: _address_int(item) or 0)
    dominators: dict[str, set[str]] = {
        start: ({start} if start == entry else set(starts)) for start in starts
    }
    changed = True
    while changed:
        changed = False
        for start in sorted(starts):
            if start == entry:
                continue
            incoming = predecessors[start]
            updated = {start} | (set.intersection(*(dominators[item] for item in incoming)) if incoming else set())
            if updated != dominators[start]:
                dominators[start] = updated
                changed = True
    dominates = before_block.start_address in dominators[after_block.start_address]
    return IndexedEventRelation(
        "cfg_dominates" if dominates else "cfg_reachable_branch",
        True,
        dominates,
        False,
        "ghidra_basic_block",
    )


def _cfg_path_avoiding(
    blocks: Sequence[IndexedBasicBlock],
    before_address: str,
    after_address: str,
    barrier_addresses: Sequence[str],
) -> bool:
    def containing(value: int) -> IndexedBasicBlock | None:
        return next(
            (
                block
                for block in blocks
                if (_address_int(block.start_address) or -1)
                <= value
                <= (_address_int(block.end_address) or -1)
            ),
            None,
        )

    before_value = _address_int(before_address)
    after_value = _address_int(after_address)
    if before_value is None or after_value is None:
        return True
    before_block = containing(before_value)
    after_block = containing(after_value)
    if before_block is None or after_block is None:
        return True
    if before_block.start_address == after_block.start_address:
        if before_value >= after_value:
            return True
        return not any(
            before_value < barrier < after_value
            for raw in barrier_addresses
            if (barrier := _address_int(raw)) is not None
        )

    by_start = {block.start_address: block for block in blocks}

    def canonical(address: str) -> str:
        value = _address_int(address)
        block = containing(value) if value is not None else None
        return block.start_address if block else address

    blocked: set[str] = set()
    for raw in barrier_addresses:
        value = _address_int(raw)
        block = containing(value) if value is not None else None
        if block is None:
            continue
        if block.start_address == before_block.start_address and value <= before_value:
            continue
        if block.start_address == after_block.start_address and value >= after_value:
            continue
        blocked.add(block.start_address)
    if before_block.start_address in blocked:
        return False
    pending = [before_block.start_address]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current in seen or (current in blocked and current != before_block.start_address):
            continue
        seen.add(current)
        if current == after_block.start_address:
            return True
        block = by_start.get(current)
        if block:
            pending.extend(
                target
                for target in (canonical(item) for item in block.successors)
                if target in by_start and target not in seen
            )
    return False


def _text_event_relation(
    text: str,
    before_line: int,
    after_line: int,
    before_address: str,
    after_address: str,
) -> IndexedEventRelation:
    if before_line <= 0:
        return IndexedEventRelation("text_order_unresolved", False, False, False, "decompiled_text")
    if after_line == before_line:
        before_column = re.search(r":col:(\d+)$", before_address)
        after_column = re.search(r":col:(\d+)$", after_address)
        ordered = bool(before_column and after_column and int(before_column.group(1)) < int(after_column.group(1)))
        return IndexedEventRelation(
            "text_linear_fallthrough" if ordered else "text_order_unresolved",
            ordered,
            ordered,
            False,
            "decompiled_text",
        )
    if after_line < before_line:
        return IndexedEventRelation("text_order_unresolved", False, False, False, "decompiled_text")
    between = "\n".join(str(text or "").splitlines()[before_line: max(before_line, after_line - 1)])
    if any(
        re.match(r"^\s*(?:else\b|return\b|goto\b)", line)
        for line in between.splitlines()
    ):
        return IndexedEventRelation("text_control_transfer_unresolved", False, False, False, "decompiled_text")
    return IndexedEventRelation("text_linear_fallthrough", True, True, False, "decompiled_text")


def _optional_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _byte_ranges(value: Any) -> tuple[tuple[int, int], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    rows: list[tuple[int, int]] = []
    for item in value:
        if not isinstance(item, Sequence) or isinstance(item, (str, bytes, bytearray)) or len(item) != 2:
            continue
        start, end = _optional_int(item[0]), _optional_int(item[1])
        if start is not None and end is not None and end > start:
            rows.append((start, end))
    return tuple(rows)


def _unique(items: Iterable[Any], *, key: Any) -> list[Any]:
    values: dict[Any, Any] = {}
    for item in items:
        values.setdefault(key(item), item)
    return list(values.values())
