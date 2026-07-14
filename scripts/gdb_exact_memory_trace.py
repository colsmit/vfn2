"""GDB-side exact-operation and live-allocation tracer.

This file is loaded by ``analysis.concolic`` inside GDB.  It intentionally
uses only GDB's bundled Python and emits one machine-readable stdout marker.
Unsupported instructions are recorded without claiming a memory violation.
"""

from __future__ import annotations

import json
import os
import sys

import gdb

sys.path.insert(0, os.environ["BINARY_AGENT_SOURCE_ROOT"])
from binary_agent.analysis.native_memory import (  # noqa: E402
    abi_argument_registers,
    abi_return_register,
    decode_memory_operand,
)
from binary_agent.analysis.native_resources import RuntimeResourceLedger  # noqa: E402


MARKER = "BINARY_AGENT_EXACT_MEMORY="
LIVE_ALLOCATIONS = {}
LAST_EXACT_PAYLOAD = None
EMITTED = False
ARCHITECTURE = ""
RESOURCE_LEDGER = RuntimeResourceLedger()
EXACT_HITS = []


def _register(name):
    try:
        return int(gdb.parse_and_eval("$" + name))
    except gdb.error:
        return 0


def _argument(index):
    registers = abi_argument_registers(ARCHITECTURE)
    return _register(registers[index]) if index < len(registers) else 0


class _AllocationReturn(gdb.FinishBreakpoint):
    def __init__(self, kind, first, second=0):
        super().__init__(internal=True)
        self.silent = True
        self.kind = kind
        self.first = first
        self.second = second

    def stop(self):
        result_register = abi_return_register(ARCHITECTURE)
        result = _register(result_register) if result_register else 0
        if self.kind == "realloc" and result:
            LIVE_ALLOCATIONS.pop(self.first, None)
            RESOURCE_LEDGER.release(self.first, ("heap",), "c_heap")
        if result:
            size = self.first
            if self.kind == "calloc":
                size = self.first * self.second
            elif self.kind == "realloc":
                size = self.second
            LIVE_ALLOCATIONS[result] = max(0, size)
            RESOURCE_LEDGER.acquire("heap", result, _allocation_family(self.kind))
        return False


class _AllocatorBreakpoint(gdb.Breakpoint):
    def __init__(self, symbol, kind):
        super().__init__(symbol, internal=True)
        self.silent = True
        self.kind = kind

    def stop(self):
        global EMITTED
        try:
            if self.kind in {"free", "operator_delete", "operator_delete_array"}:
                identity = _argument(0)
                existing = RESOURCE_LEDGER.lookup(identity, ("heap",))
                LIVE_ALLOCATIONS.pop(identity, None)
                RESOURCE_LEDGER.release(
                    identity,
                    ("heap",),
                    _release_family(self.kind),
                    details={"process_wide_control": True},
                )
                if (
                    os.environ.get("BINARY_AGENT_PROCESS_WIDE_DUPLICATE_CONTROL") == "1"
                    and existing is not None
                    and not existing.live
                ):
                    violation = RESOURCE_LEDGER.violation(
                        "double_free",
                        identity,
                        kinds=("heap",),
                        release_family=_release_family(self.kind),
                    )
                    payload = {
                        "schema_version": 2,
                        "status": "reached",
                        "operation_address": "",
                        "process_wide_duplicate_release": True,
                        "lifetime_violation": violation,
                        "resource_events": list(RESOURCE_LEDGER.events),
                    }
                    print(MARKER + json.dumps(payload, sort_keys=True))
                    EMITTED = True
                    return True
            elif self.kind == "calloc":
                _AllocationReturn(self.kind, _argument(0), _argument(1))
            elif self.kind == "realloc":
                _AllocationReturn(self.kind, _argument(0), _argument(1))
            else:
                _AllocationReturn(self.kind, _argument(0))
        except gdb.error:
            pass
        return False


class _ResourceAcquireReturn(gdb.FinishBreakpoint):
    def __init__(self, kind, family):
        super().__init__(internal=True)
        self.silent = True
        self.kind = kind
        self.family = family

    def stop(self):
        result_register = abi_return_register(ARCHITECTURE)
        result = _register(result_register) if result_register else -1
        RESOURCE_LEDGER.acquire(self.kind, result, self.family)
        return False


class _ResourceAcquireBreakpoint(gdb.Breakpoint):
    def __init__(self, symbol, kind, family):
        super().__init__(symbol, internal=True)
        self.silent = True
        self.kind = kind
        self.family = family

    def stop(self):
        try:
            _ResourceAcquireReturn(self.kind, self.family)
        except gdb.error:
            pass
        return False


class _ResourceEventBreakpoint(gdb.Breakpoint):
    def __init__(self, symbol, action, kinds, family=""):
        super().__init__(symbol, internal=True)
        self.silent = True
        self.action = action
        self.kinds = kinds
        self.family = family

    def stop(self):
        identity = _argument(0)
        if self.action == "release":
            RESOURCE_LEDGER.release(identity, self.kinds, self.family)
        else:
            RESOURCE_LEDGER.use(identity, self.kinds)
        return False


class _ScopeExitBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, runtime_address, static_address, instruction, first_event):
        super().__init__(internal=True)
        self.silent = True
        self.runtime_address = runtime_address
        self.static_address = static_address
        self.instruction = instruction
        self.first_event = first_event

    def stop(self):
        global EMITTED
        acquired = [
            event
            for event in RESOURCE_LEDGER.events[self.first_event :]
            if event.get("action") == "acquire" and event.get("resource_kind") == "heap"
        ]
        RESOURCE_LEDGER.scope_exit("containing_function_return")
        violation = {"violation": False, "same_resource": False, "events": []}
        if acquired:
            latest = acquired[-1]
            violation = RESOURCE_LEDGER.violation(
                "memory_leak",
                int(latest["identity"]),
                kinds=("heap",),
            )
            violation["path_local"] = True
            violation["escaped"] = False
            violation["live_at_scope_exit"] = bool(violation.get("violation"))
            violation["scope_exit"] = "containing_function_return"
        payload = {
            "schema_version": 2,
            "status": "reached",
            "operation_address": "0x%X" % self.static_address,
            "runtime_address": "0x%X" % self.runtime_address,
            "instruction": self.instruction,
            "lifetime_violation": violation,
            "resource_events": list(RESOURCE_LEDGER.events),
        }
        print(MARKER + json.dumps(payload, sort_keys=True))
        EMITTED = True
        return True


def _allocation_family(name):
    if name in {"operator_new", "_Znwm", "_Znwj"}:
        return "cpp_scalar"
    if name in {"operator_new_array", "_Znam", "_Znaj"}:
        return "cpp_array"
    return "c_heap"


def _release_family(name):
    return {
        "operator_delete": "cpp_scalar",
        "_ZdlPv": "cpp_scalar",
        "operator_delete_array": "cpp_array",
        "_ZdaPv": "cpp_array",
        "fclose": "stdio_stream",
        "closedir": "directory",
        "closesocket": "socket",
        "close": "descriptor",
    }.get(name, "c_heap")


def _instruction():
    text = gdb.execute("x/i $pc", to_string=True).strip()
    return text.split(":", 1)[-1].strip()


def _nearest_allocation(address, width):
    if address is None:
        return None
    rows = []
    for base, size in LIVE_ALLOCATIONS.items():
        end = base + size
        if base <= address < end:
            distance = 0
        elif address >= end:
            distance = address - end
        else:
            distance = base - (address + max(width, 1))
        rows.append((max(0, distance), base, size))
    if not rows:
        return None
    distance, base, size = min(rows)
    if distance > max(4096, size):
        return None
    return base, size


class _ExactOperationBreakpoint(gdb.Breakpoint):
    def __init__(self, runtime_address, static_address):
        super().__init__("*0x%x" % runtime_address, internal=True)
        self.silent = True
        self.runtime_address = runtime_address
        self.static_address = static_address

    def stop(self):
        global EMITTED, LAST_EXACT_PAYLOAD
        instruction = _instruction()
        vulnerability_type = os.environ.get("BINARY_AGENT_VULNERABILITY_TYPE", "")
        hit = {
            "sequence": len(EXACT_HITS) + 1,
            "operation_address": "0x%X" % self.static_address,
            "runtime_address": "0x%X" % self.runtime_address,
            "instruction": instruction,
        }
        EXACT_HITS.append(hit)
        if vulnerability_type == "memory_leak":
            try:
                _ScopeExitBreakpoint(
                    self.runtime_address,
                    self.static_address,
                    instruction,
                    len(RESOURCE_LEDGER.events),
                )
            except gdb.error:
                return True
            return False
        if os.environ.get("BINARY_AGENT_CONTINUE_AFTER_EXACT") == "1":
            payload = {
                "schema_version": 2,
                "status": "reached",
                "operation_address": "0x%X" % self.static_address,
                "runtime_address": "0x%X" % self.runtime_address,
                "instruction": instruction,
                "semantic_callsite": True,
                "continued_after_exact_operation": True,
            }
            print(MARKER + json.dumps(payload, sort_keys=True))
            EMITTED = True
            self.enabled = False
            return False
        if vulnerability_type in {"double_free", "double_close"}:
            operation_name = os.environ.get("BINARY_AGENT_OPERATION_NAME", "")
            identity = _argument(0)
            violation = RESOURCE_LEDGER.violation(
                vulnerability_type,
                identity,
                kinds=("heap", "descriptor", "stream", "directory", "socket"),
                release_family=_release_family(operation_name),
            )
            if not violation.get("violation"):
                return False
            RESOURCE_LEDGER.release(
                identity,
                kinds=("heap", "descriptor", "stream", "directory", "socket"),
                family=_release_family(operation_name),
                details={
                    "exact_second_release": True,
                    "operation_address": "0x%X" % self.static_address,
                    "runtime_address": "0x%X" % self.runtime_address,
                },
            )
            violation = RESOURCE_LEDGER.violation(
                vulnerability_type,
                identity,
                kinds=("heap", "descriptor", "stream", "directory", "socket"),
                release_family=_release_family(operation_name),
            )
            violation["exact_second_release"] = True
            payload = {
                "schema_version": 2,
                "status": "reached",
                "operation_address": "0x%X" % self.static_address,
                "runtime_address": "0x%X" % self.runtime_address,
                "instruction": instruction,
                "lifetime_violation": violation,
                "resource_events": list(RESOURCE_LEDGER.events),
                "exact_hits": list(EXACT_HITS),
            }
            print(MARKER + json.dumps(payload, sort_keys=True))
            EMITTED = True
            return True
        if vulnerability_type in {
            "invalid_free",
            "mismatched_deallocator",
            "use_after_close",
        }:
            operation_name = os.environ.get("BINARY_AGENT_OPERATION_NAME", "")
            identity = _argument(0)
            violation = RESOURCE_LEDGER.violation(
                vulnerability_type,
                identity,
                kinds=("heap", "descriptor", "stream", "directory", "socket"),
                release_family=_release_family(operation_name),
            )
            payload = {
                "schema_version": 2,
                "status": "reached",
                "operation_address": "0x%X" % self.static_address,
                "runtime_address": "0x%X" % self.runtime_address,
                "instruction": instruction,
                "lifetime_violation": violation,
                "resource_events": list(RESOURCE_LEDGER.events),
                "exact_hits": list(EXACT_HITS),
            }
            print(MARKER + json.dumps(payload, sort_keys=True))
            EMITTED = True
            return True
        operand = decode_memory_operand(instruction, ARCHITECTURE)
        width = operand.width_bytes if operand else 0
        address = operand.effective_address(_register) if operand else None
        if vulnerability_type == "use_after_free":
            identity_source = "memory_effective_address"
            identity = address
            if identity is None and instruction.lstrip().startswith(("call", "bl ", "blx ")):
                identity = _argument(0)
                identity_source = "call_argument_0"
            violation = RESOURCE_LEDGER.violation(
                vulnerability_type,
                identity or 0,
                kinds=("heap",),
            )
            violation["identity_source"] = identity_source
            violation["observed_identity"] = identity
            payload = {
                "schema_version": 2,
                "status": "reached",
                "operation_address": "0x%X" % self.static_address,
                "runtime_address": "0x%X" % self.runtime_address,
                "instruction": instruction,
                "effective_address": "0x%X" % address if address is not None else "",
                "lifetime_violation": violation,
                "resource_events": list(RESOURCE_LEDGER.events),
            }
            print(MARKER + json.dumps(payload, sort_keys=True))
            EMITTED = True
            return True
        allocation = _nearest_allocation(address, width)
        payload = {
            "schema_version": 1,
            "status": "reached",
            "operation_address": "0x%X" % self.static_address,
            "runtime_address": "0x%X" % self.runtime_address,
            "instruction": instruction,
            "access_width_bytes": width,
            "effective_address": "0x%X" % address if address is not None else "",
            "live_allocation_count": len(LIVE_ALLOCATIONS),
            "memory_access": {},
        }
        if vulnerability_type == "overlapping_memory_copy":
            destination = _argument(0)
            source = _argument(1)
            size = max(0, _argument(2))
            payload["memory_access"] = {
                "destination_range": [destination, destination + size],
                "source_range": [source, source + size],
                "ranges_overlap": bool(
                    size > 0
                    and max(destination, source) < min(destination + size, source + size)
                ),
                "operation": "memcpy",
            }
            print(MARKER + json.dumps(payload, sort_keys=True))
            EMITTED = True
            return True
        if vulnerability_type == "null_pointer_dereference":
            payload["memory_access"] = {
                "pointer_value": address,
                "effective_address": address,
                "accessed": address == 0,
                "access_range": [address, address + width] if address is not None and width else [],
            }
            print(MARKER + json.dumps(payload, sort_keys=True))
            EMITTED = True
            return True
        if allocation is not None and address is not None and width:
            base, size = allocation
            access_end = address + width
            payload["memory_access"] = {
                "same_object": True,
                "object_address": "0x%X" % base,
                "object_range": [base, base + size],
                "access_range": [address, access_end],
                "out_of_bounds": address < base or access_end > base + size,
            }
            if payload["memory_access"]["out_of_bounds"] is False:
                expression = operand.gdb_expression() if operand else ""
                if expression:
                    self.condition = "(%s < %d) || (%s + %d > %d)" % (
                        expression,
                        base,
                        expression,
                        width,
                        base + size,
                    )
                    LAST_EXACT_PAYLOAD = payload
                    return False
        print(MARKER + json.dumps(payload, sort_keys=True))
        EMITTED = True
        return True


def _emit_last_exact_on_exit(_event):
    global EMITTED
    if (
        not EMITTED
        and os.environ.get("BINARY_AGENT_PROCESS_WIDE_DUPLICATE_CONTROL") == "1"
    ):
        payload = {
            "schema_version": 2,
            "status": "process_exited",
            "operation_address": "",
            "process_wide_duplicate_release": False,
            "lifetime_violation": {
                "vulnerability": "double_free",
                "violation": False,
                "same_resource": False,
                "events": [],
            },
            "resource_events": list(RESOURCE_LEDGER.events),
        }
        print(MARKER + json.dumps(payload, sort_keys=True))
        EMITTED = True
        return
    if not EMITTED and EXACT_HITS:
        vulnerability_type = os.environ.get("BINARY_AGENT_VULNERABILITY_TYPE", "")
        payload = {
            "schema_version": 2,
            "status": "reached",
            "operation_address": EXACT_HITS[-1]["operation_address"],
            "runtime_address": EXACT_HITS[-1]["runtime_address"],
            "instruction": EXACT_HITS[-1]["instruction"],
            "exact_hits": list(EXACT_HITS),
            "lifetime_violation": {
                "vulnerability": vulnerability_type,
                "violation": False,
                "same_resource": False,
                "events": [],
            },
            "resource_events": list(RESOURCE_LEDGER.events),
        }
        print(MARKER + json.dumps(payload, sort_keys=True))
        EMITTED = True
        return
    if not EMITTED and LAST_EXACT_PAYLOAD is not None:
        print(MARKER + json.dumps(LAST_EXACT_PAYLOAD, sort_keys=True))
        EMITTED = True


def _main():
    global ARCHITECTURE
    target = os.path.realpath(os.environ["BINARY_AGENT_BINARY"])
    relative = int(os.environ["BINARY_AGENT_RELATIVE_ADDRESS"], 0)
    static_address = int(os.environ["BINARY_AGENT_STATIC_ADDRESS"], 0)
    pid = gdb.selected_inferior().pid
    rows = open("/proc/%d/maps" % pid).read().splitlines()
    row = next(
        item
        for item in rows
        if item.split()[-1] == target and item.split()[2] == "00000000"
    )
    base = int(row.split("-", 1)[0], 16)
    ARCHITECTURE = gdb.selected_frame().architecture().name()
    gdb.execute("set breakpoint pending on", to_string=True)
    if os.environ.get("BINARY_AGENT_TRACK_ALLOCATIONS") == "1":
        for symbol, kind in (
            ("malloc", "malloc"),
            ("calloc", "calloc"),
            ("realloc", "realloc"),
            ("free", "free"),
            ("_Znwm", "operator_new"),
            ("_Znwj", "operator_new"),
            ("_Znam", "operator_new_array"),
            ("_Znaj", "operator_new_array"),
            ("_ZdlPv", "operator_delete"),
            ("_ZdaPv", "operator_delete_array"),
        ):
            try:
                _AllocatorBreakpoint(symbol + "@plt", kind)
            except gdb.error:
                try:
                    _AllocatorBreakpoint(symbol, kind)
                except gdb.error:
                    pass
    if os.environ.get("BINARY_AGENT_TRACK_RESOURCES") == "1":
        for symbol, kind, family in (
            ("open", "descriptor", "descriptor"),
            ("socket", "socket", "socket"),
            ("fopen", "stream", "stdio_stream"),
            ("fdopen", "stream", "stdio_stream"),
            ("opendir", "directory", "directory"),
        ):
            try:
                _ResourceAcquireBreakpoint(symbol + "@plt", kind, family)
            except gdb.error:
                try:
                    _ResourceAcquireBreakpoint(symbol, kind, family)
                except gdb.error:
                    pass
        for symbol, action, kinds, family in (
            ("close", "release", ("descriptor", "socket"), "descriptor"),
            ("closesocket", "release", ("socket",), "socket"),
            ("fclose", "release", ("stream",), "stdio_stream"),
            ("closedir", "release", ("directory",), "directory"),
            ("read", "use", ("descriptor", "socket"), ""),
            ("recv", "use", ("socket", "descriptor"), ""),
            ("readdir", "use", ("directory",), ""),
        ):
            try:
                _ResourceEventBreakpoint(symbol + "@plt", action, kinds, family)
            except gdb.error:
                try:
                    _ResourceEventBreakpoint(symbol, action, kinds, family)
                except gdb.error:
                    pass
    if os.environ.get("BINARY_AGENT_PROCESS_WIDE_DUPLICATE_CONTROL") != "1":
        _ExactOperationBreakpoint(base + relative, static_address)
    gdb.events.exited.connect(_emit_last_exact_on_exit)
    gdb.execute("continue")


_main()
