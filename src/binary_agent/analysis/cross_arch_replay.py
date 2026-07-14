"""Deterministic QEMU replay for freestanding ARM scalar memory fixtures."""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

from binary_agent.analysis.native_memory import decode_memory_operand


def build_freestanding_fixture(source: Path, output: Path, architecture: str) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    if architecture == "arm":
        compiler = shutil.which("arm-none-eabi-gcc")
        if not compiler:
            return {"status": "unsupported", "reason": "arm_none_eabi_gcc_unavailable"}
        completed = subprocess.run(
            [compiler, "-nostdlib", "-static", "-Wl,-e,_start", str(source), "-o", str(output)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode:
            return {"status": "unsupported", "reason": "arm_fixture_link_failed", "stderr": completed.stderr}
        symbols = _symbols(output, "arm-none-eabi-nm")
    elif architecture == "aarch64":
        compiler = shutil.which("clang")
        if not compiler:
            return {"status": "unsupported", "reason": "clang_unavailable"}
        object_path = output.with_suffix(".o")
        completed = subprocess.run(
            [compiler, "--target=aarch64-none-elf", "-c", str(source), "-o", str(object_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode:
            return {"status": "unsupported", "reason": "aarch64_fixture_assemble_failed", "stderr": completed.stderr}
        text = _elf64_section(object_path.read_bytes(), ".text")
        if not text:
            return {"status": "unsupported", "reason": "aarch64_text_section_unavailable"}
        entry = 0x401000
        output.write_bytes(_aarch64_executable(text, entry))
        output.chmod(0o755)
        symbols = {
            "_start": entry,
            "exact_memory_operation": entry + 4,
            "tracked_object": entry + 16,
        }
    else:
        return {"status": "unsupported", "reason": f"unsupported_architecture:{architecture}"}
    required = {"_start", "exact_memory_operation", "tracked_object"}
    if not required <= symbols.keys():
        return {"status": "unsupported", "reason": "fixture_symbols_unavailable", "symbols": symbols}
    return {"status": "built", "binary": str(output), "symbols": symbols}


def replay_qemu_exact_memory(
    binary: Path,
    architecture: str,
    *,
    exact_address: int,
    object_address: int,
    object_size: int,
) -> dict[str, Any]:
    emulator = shutil.which("qemu-aarch64" if architecture == "aarch64" else "qemu-arm")
    if not emulator:
        return {"status": "unsupported", "reason": f"qemu_{architecture}_unavailable"}
    log_path = binary.with_suffix(".qemu.log")
    completed = subprocess.run(
        [
            emulator,
            "-one-insn-per-tb",
            "-d",
            "in_asm,cpu",
            "-D",
            str(log_path),
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    trace = _qemu_operation(log_path.read_text(errors="replace") if log_path.exists() else "", exact_address)
    if not trace:
        return {
            "status": "unreached",
            "reason": "qemu_exact_operation_unreached",
            "returncode": completed.returncode,
            "stderr": completed.stderr[-1000:],
        }
    instruction, registers = trace
    operand = decode_memory_operand(instruction, architecture)
    if operand is None:
        return {"status": "unsupported", "reason": "unsupported_qemu_memory_operand", "instruction": instruction}
    try:
        address = operand.effective_address(lambda name: registers[name.lower()])
    except KeyError as exc:
        return {"status": "unsupported", "reason": f"qemu_register_unavailable:{exc.args[0]}"}
    access_range = [address, address + operand.width_bytes]
    object_range = [object_address, object_address + object_size]
    return {
        "schema_version": 2,
        "status": "reached",
        "architecture": architecture,
        "operation_address": f"0x{exact_address:X}",
        "instruction": instruction,
        "registers": {key: f"0x{value:X}" for key, value in sorted(registers.items())},
        "memory_access": {
            "same_object": True,
            "object_range": object_range,
            "access_range": access_range,
            "out_of_bounds": access_range[0] < object_range[0] or access_range[1] > object_range[1],
        },
        "returncode": completed.returncode,
        "artifact_refs": [str(log_path)],
    }


def _symbols(binary: Path, command_name: str) -> dict[str, int]:
    command = shutil.which(command_name) or shutil.which("nm")
    if not command:
        return {}
    completed = subprocess.run([command, "-n", str(binary)], capture_output=True, text=True, check=False)
    rows: dict[str, int] = {}
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                rows[parts[-1]] = int(parts[0], 16)
            except ValueError:
                continue
    return rows


def _qemu_operation(log: str, exact_address: int) -> tuple[str, dict[str, int]] | None:
    address_pattern = re.compile(rf"0x0*{exact_address:x}:\s+[0-9a-f]+\s+(?P<instruction>[^\n]+)", re.IGNORECASE)
    for section in str(log or "").split("----------------"):
        match = address_pattern.search(section)
        if not match:
            continue
        registers: dict[str, int] = {}
        for name, value in re.findall(r"\b(?:R|X)(\d{2})=([0-9a-fA-F]+)", section):
            prefix = "x" if re.search(r"\bX\d{2}=", section) else "r"
            registers[f"{prefix}{int(name)}"] = int(value, 16)
        return match.group("instruction").strip(), registers
    return None


def _elf64_section(payload: bytes, wanted: str) -> bytes:
    if payload[:5] != b"\x7fELF\x02" or len(payload) < 64:
        return b""
    section_offset = struct.unpack_from("<Q", payload, 0x28)[0]
    entry_size, count, names_index = struct.unpack_from("<HHH", payload, 0x3A)
    sections = [
        struct.unpack_from("<IIQQQQIIQQ", payload, section_offset + index * entry_size)
        for index in range(count)
    ]
    names = sections[names_index]
    names_payload = payload[names[4] : names[4] + names[5]]
    for section in sections:
        name_start = section[0]
        name_end = names_payload.find(b"\x00", name_start)
        name = names_payload[name_start:name_end].decode(errors="replace")
        if name == wanted:
            return payload[section[4] : section[4] + section[5]]
    return b""


def _aarch64_executable(text: bytes, entry: int) -> bytes:
    file_offset = 0x1000
    virtual_base = entry - file_offset
    size = file_offset + len(text)
    ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        2,
        183,
        1,
        entry,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    program = struct.pack("<IIQQQQQQ", 1, 7, 0, virtual_base, virtual_base, size, size, 0x1000)
    return header + program + b"\x00" * (file_offset - len(header) - len(program)) + text
