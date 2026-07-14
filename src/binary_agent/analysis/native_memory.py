"""Pure architecture decoding for one native scalar memory operand."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class NativeMemoryOperand:
    width_bytes: int
    base_register: str
    index_register: str = ""
    scale: int = 1
    displacement: int = 0

    def effective_address(self, register: Callable[[str], int]) -> int:
        return (
            register(self.base_register)
            + self.displacement
            + (register(self.index_register) * self.scale if self.index_register else 0)
        )

    def gdb_expression(self) -> str:
        expression = f"${self.base_register}"
        if self.displacement:
            expression += f"+({self.displacement})"
        if self.index_register:
            expression += f"+${self.index_register}*{self.scale}"
        return expression


def architecture_family(name: str) -> str:
    lowered = str(name or "").lower()
    if any(token in lowered for token in ("i386:x86-64", "x86-64", "amd64")):
        return "x86_64"
    if "aarch64" in lowered or "arm64" in lowered:
        return "aarch64"
    if "arm" in lowered:
        return "arm"
    return "unsupported"


def abi_argument_registers(architecture: str) -> tuple[str, ...]:
    family = architecture_family(architecture)
    if family == "x86_64":
        return ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
    if family == "aarch64":
        return tuple(f"x{index}" for index in range(8))
    if family == "arm":
        return ("r0", "r1", "r2", "r3")
    return ()


def abi_return_register(architecture: str) -> str:
    return {"x86_64": "rax", "aarch64": "x0", "arm": "r0"}.get(
        architecture_family(architecture),
        "",
    )


def decode_memory_operand(instruction: str, architecture: str) -> NativeMemoryOperand | None:
    family = architecture_family(architecture)
    if family == "x86_64":
        return _decode_x86(instruction)
    if family in {"arm", "aarch64"}:
        return _decode_arm(instruction, family)
    return None


def _decode_x86(instruction: str) -> NativeMemoryOperand | None:
    mnemonic = _mnemonic(instruction)
    if not mnemonic.startswith(("mov", "cmp", "test", "and", "or", "xor", "add", "sub")):
        return None
    explicit = re.search(r"(?:movz|movs)([bwlq])", mnemonic)
    suffix = explicit.group(1) if explicit else mnemonic[-1:]
    width = {"b": 1, "w": 2, "l": 4, "q": 8}.get(suffix, 0)
    if not width:
        width = _x86_register_width(instruction)
    match = re.search(
        r"(?P<disp>-?(?:0x[0-9a-f]+|\d+))?\(%(?P<base>[a-z0-9]+)"
        r"(?:,%(?P<index>[a-z0-9]+)(?:,(?P<scale>[1248]))?)?\)",
        instruction,
        re.IGNORECASE,
    )
    if not match or not width:
        return None
    return NativeMemoryOperand(
        width_bytes=width,
        base_register=match.group("base").lower(),
        index_register=(match.group("index") or "").lower(),
        scale=int(match.group("scale") or "1"),
        displacement=int(match.group("disp") or "0", 0),
    )


def _x86_register_width(instruction: str) -> int:
    registers = re.findall(r"%([a-z][a-z0-9]*)", instruction, re.IGNORECASE)
    for register in reversed(registers):
        lowered = register.lower()
        if lowered in {"al", "bl", "cl", "dl", "sil", "dil", "spl", "bpl"} or re.fullmatch(r"r\d+b", lowered):
            return 1
        if lowered in {"ax", "bx", "cx", "dx", "si", "di", "sp", "bp"} or re.fullmatch(r"r\d+w", lowered):
            return 2
        if lowered.startswith("e") and lowered[1:] in {"ax", "bx", "cx", "dx", "si", "di", "sp", "bp"}:
            return 4
        if re.fullmatch(r"r\d+d", lowered):
            return 4
        if lowered in {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"} or re.fullmatch(r"r\d+", lowered):
            return 8
    return 0


def _decode_arm(instruction: str, family: str) -> NativeMemoryOperand | None:
    mnemonic = _mnemonic(instruction).split(".", 1)[0]
    if not mnemonic.startswith(("ldr", "str")) or mnemonic.startswith(("ldp", "stp")):
        return None
    if "!" in instruction or re.search(r"\]\s*,", instruction):
        return None
    operands = instruction.split(None, 1)[1] if " " in instruction else ""
    first_register = re.match(r"\s*(?P<register>[wxr][0-9]+)\b", operands, re.IGNORECASE)
    if not first_register:
        return None
    width = _arm_width(mnemonic, first_register.group("register"), family)
    match = re.search(
        r"\[\s*(?P<base>[xr][0-9]+|sp)\s*"
        r"(?:,\s*(?:(?P<immediate>#?-?(?:0x[0-9a-f]+|\d+))|(?P<index>[xr][0-9]+)"
        r"(?:\s*,\s*lsl\s*#(?P<shift>\d+))?))?\s*\]",
        instruction,
        re.IGNORECASE,
    )
    if not match or not width:
        return None
    immediate = str(match.group("immediate") or "0").lstrip("#")
    shift = int(match.group("shift") or "0")
    if shift > 4:
        return None
    return NativeMemoryOperand(
        width_bytes=width,
        base_register=match.group("base").lower(),
        index_register=(match.group("index") or "").lower(),
        scale=1 << shift,
        displacement=int(immediate, 0),
    )


def _arm_width(mnemonic: str, register: str, family: str) -> int:
    if mnemonic.endswith(("b", "sb")):
        return 1
    if mnemonic.endswith(("h", "sh")):
        return 2
    if mnemonic.endswith("sw"):
        return 4
    if mnemonic not in {"ldr", "str"}:
        return 0
    if family == "aarch64":
        return 8 if register.lower().startswith("x") else 4
    return 4


def _mnemonic(instruction: str) -> str:
    text = str(instruction or "").strip()
    if ":" in text:
        text = text.split(":", 1)[1].strip()
    return text.split(None, 1)[0].lower() if text else ""
