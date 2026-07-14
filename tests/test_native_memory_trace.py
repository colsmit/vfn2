import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from binary_agent.analysis.concolic import _parse_native_memory_trace
from binary_agent.analysis.native_memory import (
    abi_argument_registers,
    abi_return_register,
    architecture_family,
    decode_memory_operand,
)
from binary_agent.analysis.native_resources import RuntimeResourceLedger


def test_native_memory_trace_parser_accepts_only_reached_json_marker() -> None:
    payload = {
        "status": "reached",
        "operation_address": "0x1010",
        "memory_access": {
            "same_object": True,
            "object_range": [4096, 4104],
            "access_range": [4104, 4105],
            "out_of_bounds": True,
        },
    }
    transcript = "noise\nBINARY_AGENT_EXACT_MEMORY=" + json.dumps(payload)
    assert _parse_native_memory_trace(transcript) == payload
    assert _parse_native_memory_trace("BINARY_AGENT_EXACT_MEMORY={bad") == {}
    assert _parse_native_memory_trace('BINARY_AGENT_EXACT_MEMORY={"status":"unreached"}') == {}


@pytest.mark.parametrize(
    ("architecture", "instruction", "registers", "width", "address"),
    [
        ("i386:x86-64", "movzbl 0x8(%rax,%rcx,4),%edx", {"rax": 0x1000, "rcx": 2}, 1, 0x1010),
        ("aarch64", "ldrb w0, [x1, #8]", {"x1": 0x2000}, 1, 0x2008),
        ("aarch64", "ldr x0, [x1, x2, lsl #3]", {"x1": 0x2000, "x2": 3}, 8, 0x2018),
        ("armv7", "ldr r0, [r1, r2, lsl #2]", {"r1": 0x3000, "r2": 3}, 4, 0x300C),
        ("armv7", "strh r0, [r1, #-2]", {"r1": 0x3000}, 2, 0x2FFE),
    ],
)
def test_architecture_memory_operands_are_exact_and_scalar(
    architecture: str,
    instruction: str,
    registers: dict[str, int],
    width: int,
    address: int,
) -> None:
    operand = decode_memory_operand(instruction, architecture)
    assert operand is not None
    assert operand.width_bytes == width
    assert operand.effective_address(lambda name: registers[name]) == address
    assert operand.gdb_expression().startswith("$")


def test_architecture_abi_and_unsupported_operands_fail_closed() -> None:
    assert architecture_family("aarch64:little") == "aarch64"
    assert abi_argument_registers("aarch64")[:2] == ("x0", "x1")
    assert abi_return_register("armv7") == "r0"
    assert decode_memory_operand("ldp x0, x1, [x2]", "aarch64") is None
    assert decode_memory_operand("ldr x0, [x1, #8]!", "aarch64") is None
    assert decode_memory_operand("vldr d0, [r1]", "armv7") is None
    assert decode_memory_operand("mov (%rax),%eax", "mips") is None


def test_x86_unsuffixed_gdb_instruction_infers_scalar_width() -> None:
    operand = decode_memory_operand("mov    (%rax),%eax", "i386:x86-64")

    assert operand is not None
    assert operand.width_bytes == 4
    assert operand.base_register == "rax"


def test_runtime_resource_ledger_uses_generations_for_reused_descriptors() -> None:
    ledger = RuntimeResourceLedger()
    first = ledger.acquire("descriptor", 7, "descriptor")
    assert first is not None and first.generation == 1
    ledger.release(7, ("descriptor",), "descriptor")
    assert ledger.violation("double_close", 7, kinds=("descriptor",))["violation"] is True

    second = ledger.acquire("descriptor", 7, "descriptor")
    assert second is not None and second.generation == 2
    assert ledger.violation("double_close", 7, kinds=("descriptor",))["violation"] is False
    ledger.release(7, ("descriptor",), "descriptor")
    violation = ledger.violation("use_after_close", 7, kinds=("descriptor",))
    assert violation["violation"] is True
    assert violation["resource_generation"] == 2
    assert {event["generation"] for event in violation["events"]} == {2}


def test_runtime_resource_ledger_proves_allocator_family_mismatch() -> None:
    ledger = RuntimeResourceLedger()
    ledger.acquire("heap", 0x4000, "cpp_array")
    mismatch = ledger.violation(
        "mismatched_deallocator",
        0x4000,
        kinds=("heap",),
        release_family="c_heap",
    )
    assert mismatch["violation"] is True
    assert mismatch["allocator_family"] == "cpp_array"
    assert mismatch["deallocator_family"] == "c_heap"


def test_runtime_resource_ledger_proves_double_free_generation() -> None:
    ledger = RuntimeResourceLedger()
    acquired = ledger.acquire("heap", 0x5000, "c_heap")
    assert acquired is not None
    ledger.release(0x5000, ("heap",), "c_heap")
    violation = ledger.violation("double_free", 0x5000, kinds=("heap",), release_family="c_heap")
    assert violation["violation"] is True
    assert violation["same_resource"] is True
    assert violation["resource_generation"] == 1


@pytest.mark.skipif(not shutil.which("gdb") or not shutil.which("cc"), reason="GDB and a C compiler are required")
def test_gdb_helper_binds_exact_pie_load_to_live_allocation(tmp_path: Path) -> None:
    source = tmp_path / "range.c"
    binary = tmp_path / "range"
    source.write_text(
        """
#include <stdlib.h>
int main(void) {
    unsigned char *pointer = malloc(8);
    unsigned int value;
    if (!pointer) return 2;
    __asm__ volatile (
        ".global exact_memory_operation\\n"
        "exact_memory_operation:\\n"
        "movzbl 8(%1), %0\\n"
        : "=r" (value) : "r" (pointer) : "memory");
    free(pointer);
    return value == 256;
}
"""
    )
    subprocess.run(["cc", "-O0", "-fPIE", "-pie", str(source), "-o", str(binary)], check=True)
    symbols = subprocess.check_output(["nm", str(binary)], text=True)
    address = next(int(line.split()[0], 16) for line in symbols.splitlines() if line.endswith(" exact_memory_operation"))
    helper = Path(__file__).resolve().parents[1] / "scripts" / "gdb_exact_memory_trace.py"
    environment = {
        **os.environ,
        "BINARY_AGENT_BINARY": str(binary),
        "BINARY_AGENT_RELATIVE_ADDRESS": hex(address),
        "BINARY_AGENT_STATIC_ADDRESS": hex(address),
        "BINARY_AGENT_TRACK_ALLOCATIONS": "1",
        "BINARY_AGENT_SOURCE_ROOT": str(Path(__file__).resolve().parents[1] / "src"),
    }
    completed = subprocess.run(
        [
            shutil.which("gdb"),
            "-q",
            "-nx",
            "-batch",
            "-ex",
            "set debuginfod enabled off",
            "-ex",
            "starti",
            "-x",
            str(helper),
            "--args",
            str(binary),
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    payload = _parse_native_memory_trace(completed.stdout, completed.stderr)
    assert payload["operation_address"] == f"0x{address:X}"
    assert payload["access_width_bytes"] == 1
    assert payload["memory_access"]["same_object"] is True
    assert payload["memory_access"]["out_of_bounds"] is True


@pytest.mark.skipif(not shutil.which("gdb") or not shutil.which("cc"), reason="GDB and a C compiler are required")
def test_gdb_helper_proves_same_generation_double_close(tmp_path: Path) -> None:
    source = tmp_path / "double_close.c"
    binary = tmp_path / "double_close"
    source.write_text(
        r'''
#include <fcntl.h>
#include <unistd.h>
int main(void) {
    int descriptor = open("/dev/null", O_RDONLY);
    if (descriptor < 0) return 2;
    close(descriptor);
    __asm__ volatile (
        ".global exact_resource_operation\n"
        "exact_resource_operation:\n"
        "call close@PLT\n"
        : : "D" (descriptor) : "rax", "rcx", "r11", "memory");
    return 0;
}
'''
    )
    subprocess.run(["cc", "-O0", "-fPIE", "-pie", str(source), "-o", str(binary)], check=True)
    symbols = subprocess.check_output(["nm", str(binary)], text=True)
    address = next(int(line.split()[0], 16) for line in symbols.splitlines() if line.endswith(" exact_resource_operation"))
    helper = Path(__file__).resolve().parents[1] / "scripts" / "gdb_exact_memory_trace.py"
    environment = {
        **os.environ,
        "BINARY_AGENT_BINARY": str(binary),
        "BINARY_AGENT_RELATIVE_ADDRESS": hex(address),
        "BINARY_AGENT_STATIC_ADDRESS": hex(address),
        "BINARY_AGENT_TRACK_ALLOCATIONS": "1",
        "BINARY_AGENT_TRACK_RESOURCES": "1",
        "BINARY_AGENT_VULNERABILITY_TYPE": "double_close",
        "BINARY_AGENT_OPERATION_NAME": "close",
        "BINARY_AGENT_SOURCE_ROOT": str(Path(__file__).resolve().parents[1] / "src"),
    }
    completed = subprocess.run(
        [
            shutil.which("gdb"),
            "-q",
            "-nx",
            "-batch",
            "-ex",
            "set debuginfod enabled off",
            "-ex",
            "starti",
            "-x",
            str(helper),
            "--args",
            str(binary),
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    payload = _parse_native_memory_trace(completed.stdout, completed.stderr)
    assert payload["status"] == "reached", completed.stderr
    violation = payload["lifetime_violation"]
    assert violation["vulnerability"] == "double_close"
    assert violation["violation"] is True
    assert violation["resource_generation"] == 1
    assert [event["action"] for event in violation["events"]] == ["acquire", "release", "release"]
    assert violation["events"][1]["live_before"] is True
    assert violation["events"][2]["live_before"] is False
    assert violation["events"][2]["exact_second_release"] is True


@pytest.mark.skipif(not shutil.which("gdb") or not shutil.which("cc"), reason="GDB and a C compiler are required")
def test_gdb_helper_correlates_use_after_free_call_argument(tmp_path: Path) -> None:
    source = tmp_path / "use_after_free.c"
    binary = tmp_path / "use_after_free"
    source.write_text(
        r'''
#include <stdlib.h>
__attribute__((noinline)) static void consume(const char *value) {
    __asm__ volatile ("" : : "r" (value) : "memory");
}
int main(void) {
    char *value = malloc(32);
    if (!value) return 2;
    free(value);
    __asm__ volatile (
        ".global exact_use_operation\n"
        "exact_use_operation:\n"
        "call consume\n"
        : : "D" (value) : "rax", "rcx", "r11", "memory");
    return 0;
}
'''
    )
    subprocess.run(["cc", "-O0", "-fPIE", "-pie", str(source), "-o", str(binary)], check=True)
    symbols = subprocess.check_output(["nm", str(binary)], text=True)
    address = next(int(line.split()[0], 16) for line in symbols.splitlines() if line.endswith(" exact_use_operation"))
    helper = Path(__file__).resolve().parents[1] / "scripts" / "gdb_exact_memory_trace.py"
    environment = {
        **os.environ,
        "BINARY_AGENT_BINARY": str(binary),
        "BINARY_AGENT_RELATIVE_ADDRESS": hex(address),
        "BINARY_AGENT_STATIC_ADDRESS": hex(address),
        "BINARY_AGENT_TRACK_ALLOCATIONS": "1",
        "BINARY_AGENT_VULNERABILITY_TYPE": "use_after_free",
        "BINARY_AGENT_SOURCE_ROOT": str(Path(__file__).resolve().parents[1] / "src"),
    }
    completed = subprocess.run(
        [
            shutil.which("gdb"),
            "-q",
            "-nx",
            "-batch",
            "-ex",
            "set debuginfod enabled off",
            "-ex",
            "starti",
            "-x",
            str(helper),
            "--args",
            str(binary),
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    payload = _parse_native_memory_trace(completed.stdout, completed.stderr)
    assert payload["status"] == "reached", completed.stderr
    violation = payload["lifetime_violation"]
    assert violation["violation"] is True
    assert violation["same_resource"] is True
    assert violation["resource_generation"] == 1
    assert violation["identity_source"] == "call_argument_0"
