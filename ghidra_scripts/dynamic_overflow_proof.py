#@category AgentToolchain
#
# Headless Ghidra script that writes a bounded concrete exact-sink memory-safety
# proof artifact.  The script keeps the proof conservative: it only emits
# overflow_proven or oob_read_proven when the requested sink address is reached
# and the concrete access exceeds the modeled object capacity supplied by the
# deterministic candidate pack.

import json
import os
import re
import struct
import time

try:
    from ghidra.app.emulator import EmulatorHelper
except ImportError:  # pragma: no cover - lets local tooling parse this file
    EmulatorHelper = None


MAX_RECORDED_INSTRUCTIONS = 512


def parse_kv_args(raw_args):
    result = {}
    for arg in raw_args:
        if "=" in arg:
            key, value = arg.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def parse_int(raw_value, default=0):
    if raw_value is None:
        return default
    text = str(raw_value).strip()
    if not text:
        return default
    try:
        return int(text, 0)
    except Exception:
        return default


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)


def write_json(path, payload):
    ensure_parent(path)
    with open(path, "w") as handle:
        handle.write(json.dumps(payload, indent=2))


def address_from(program, raw_value):
    parsed = parse_int(raw_value, None)
    if parsed is None:
        return None
    try:
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(parsed)
    except Exception:
        return None


def address_hex(address):
    try:
        return "0x%X" % int(address.getOffset())
    except Exception:
        return str(address or "")


def instruction_fact(instruction):
    address = instruction.getAddress()
    return {
        "address": address_hex(address),
        "text": str(instruction),
    }


def unsupported(candidate_id, reason, args):
    proof_scope = proof_scope_from_args(args)
    return {
        "schema_version": 1,
        "proof_kind": "ghidra_dynamic_overflow",
        "candidate_id": candidate_id,
        "status": "unsupported",
        "unsupported": True,
        "reason": str(reason),
        "proof_scope": proof_scope,
        "request": dict(args),
        "sink_reached": False,
        "exact_sink_reached": False,
        "sink_address": str(args.get("sink_address") or ""),
        "write_size_bytes": 0,
        "capacity_bytes": parse_int(args.get("capacity_bytes"), 0),
        "capacity_source": str(args.get("capacity_source") or ""),
        "capacity_basis": str(args.get("capacity_basis") or ""),
        "overflow_bytes": 0,
        "read_size_bytes": 0,
        "oob_bytes": 0,
        "write_range": {},
        "read_range": {},
        "object_range": {},
        "harness_model": {},
        "process_input_setup": process_input_setup_payload(args, "unsupported", str(reason))
        if proof_scope == "process_entrypoint"
        else {"status": "not_applicable", "reason": "function_harness_scope"},
        "process_replay": {"status": "unsupported", "reason": str(reason), "reached_target": False}
        if proof_scope == "process_entrypoint"
        else {},
        "local_sink_probe": {"status": "not_run", "reason": "unsupported_proof", "reached_target": False},
        "native_replay": {
            "status": "not_run",
            "reason": "Native, QEMU, and device replay are out of scope for this pipeline stage.",
        },
    }


def proof_scope_from_args(args):
    requested = str(args.get("proof_scope") or "").strip()
    if requested:
        return requested
    if str(args.get("input_model") or "") == "function_harness":
        return "function_harness"
    return "process_entrypoint"


def json_arg(args, key):
    value = args.get(key)
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def process_input_setup_payload(args, status, reason):
    return {
        "status": str(status),
        "reason": str(reason),
        "input_model": str(args.get("input_model") or ""),
        "concrete_input_hex": str(args.get("concrete_input_hex") or ""),
        "stdin_input_hex": str(args.get("stdin_input_hex") or ""),
        "file_input_hex": str(args.get("file_input_hex") or ""),
        "file_name": str(args.get("file_name") or ""),
        "process_input_source": str(args.get("process_input_source") or ""),
        "process_input_evidence": json_arg(args, "process_input_evidence_json"),
    }


def program_abi(program):
    try:
        language = program.getLanguage()
        language_id = str(language.getLanguageID()).lower()
        processor = str(language.getProcessor()).lower()
        big_endian = bool(language.isBigEndian())
    except Exception:
        language_id = ""
        processor = ""
        big_endian = False
    pointer_size = 0
    try:
        pointer_size = int(program.getDefaultPointerSize())
    except Exception:
        pass
    if pointer_size <= 0:
        try:
            pointer_size = int(program.getLanguage().getDefaultSpace().getPointerSize())
        except Exception:
            pointer_size = 0
    if ("aarch64" in language_id or "aarch64" in processor) and pointer_size == 8:
        abi = "aarch64"
    elif "arm" in processor and pointer_size == 4:
        abi = "arm32"
    elif "x86" in processor and pointer_size == 8:
        abi = "x86_64_sysv"
    elif "x86" in processor and pointer_size == 4:
        abi = "i386"
    else:
        abi = ""
    return {
        "abi": abi,
        "processor": processor,
        "language_id": language_id,
        "pointer_size_bytes": pointer_size,
        "endianness": "big" if big_endian else "little",
    }


def bytes_from_hex(text):
    cleaned = re.sub(r"\s+", "", str(text or ""))
    if not cleaned:
        return []
    if len(cleaned) % 2:
        return None
    values = []
    for index in range(0, len(cleaned), 2):
        try:
            values.append(int(cleaned[index : index + 2], 16) & 0xFF)
        except Exception:
            return None
    return values


def hex_values_arg(text):
    values = []
    for item in str(text or "").split(","):
        item = item.strip()
        if not item:
            continue
        decoded = bytes_from_hex(item)
        if decoded is None:
            return None
        values.append(decoded)
    return values


def ascii_bytes(text):
    return [ord(char) & 0xFF for char in str(text or "")]


def pointer_bytes(value, pointer_size, big_endian):
    shifts = range(pointer_size - 1, -1, -1) if big_endian else range(pointer_size)
    return [int(value >> (shift * 8)) & 0xFF for shift in shifts]


def default_space_address(program, offset):
    try:
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(int(offset))
    except Exception:
        return None


def write_memory_bytes(program, helper, address, values):
    current = default_space_address(program, address)
    if current is None:
        return False
    try:
        for value in values:
            helper.writeMemoryValue(current, 1, int(value) & 0xFF)
            current = current.add(1)
        return True
    except Exception:
        try:
            for value in values:
                helper.writeMemory(current, chr(int(value) & 0xFF))
                current = current.add(1)
            return True
        except Exception:
            return False


def write_memory_integer(program, helper, address, value, size, big_endian):
    size = max(1, int(size or 0))
    shifts = range(size - 1, -1, -1) if big_endian else range(size)
    values = [(int(value) >> (shift * 8)) & 0xFF for shift in shifts]
    return write_memory_bytes(program, helper, address, values)


def global_symbol_address(program, names):
    try:
        table = program.getSymbolTable()
    except Exception:
        return None
    for name in names:
        try:
            symbols = table.getGlobalSymbols(name)
            for symbol in symbols:
                address = symbol.getAddress()
                if address is not None:
                    return address
        except Exception:
            pass
        try:
            symbol = table.getSymbol(name)
            if symbol is not None:
                address = symbol.getAddress()
                if address is not None:
                    return address
        except Exception:
            pass
    return None


def write_register(program, helper, names, value):
    for name in names:
        try:
            register = program.getRegister(name)
        except Exception:
            register = None
        if register is not None:
            try:
                helper.writeRegister(register, int(value))
                return name
            except Exception:
                pass
        try:
            helper.writeRegister(name, int(value))
            return name
        except Exception:
            pass
    return ""


def write_stack_pointer(program, helper, value):
    try:
        register = program.getCompilerSpec().getStackPointer()
    except Exception:
        register = None
    if register is not None:
        try:
            helper.writeRegister(register, int(value))
            return str(register.getName())
        except Exception:
            pass
    return write_register(program, helper, ("RSP", "ESP", "SP", "sp"), value)


def to_int(value):
    try:
        return int(value)
    except Exception:
        pass
    for method_name in ("longValue", "intValue"):
        try:
            return int(getattr(value, method_name)())
        except Exception:
            pass
    try:
        unsigned = value.getUnsignedValue()
        return to_int(unsigned)
    except Exception:
        return None


def read_register(program, helper, names):
    for name in names:
        try:
            register = program.getRegister(name)
        except Exception:
            register = None
        if register is not None:
            try:
                value = to_int(helper.readRegister(register))
                if value is not None:
                    return value
            except Exception:
                pass
        try:
            value = to_int(helper.readRegister(name))
            if value is not None:
                return value
        except Exception:
            pass
    return None


def read_memory_integer(program, helper, address, size, big_endian):
    current = default_space_address(program, address)
    if current is None or size <= 0:
        return None
    values = []
    try:
        for _index in range(size):
            try:
                value = to_int(helper.readMemoryByte(current))
            except Exception:
                value = to_int(helper.readMemoryValue(current, 1))
            if value is None:
                return None
            values.append(value & 0xFF)
            current = current.add(1)
    except Exception:
        return None
    if big_endian:
        result = 0
        for value in values:
            result = (result << 8) | value
        return result
    result = 0
    for index, value in enumerate(values):
        result |= int(value) << (index * 8)
    return result


def bytes_to_int(values, big_endian=False):
    result = 0
    ordered = list(values) if big_endian else list(reversed(values))
    for value in ordered:
        result = (result << 8) | (int(value) & 0xFF)
    return result


def read_memory_c_string(program, helper, address, max_bytes=4096):
    values = read_memory_c_bytes(program, helper, address, max_bytes)
    if values is None:
        return None
    try:
        return bytes(values).decode("utf-8", errors="replace")
    except Exception:
        return None


def read_memory_byte_at(program, helper, address):
    current = default_space_address(program, address)
    if current is None:
        return None
    try:
        try:
            value = to_int(helper.readMemoryByte(current))
        except Exception:
            value = to_int(helper.readMemoryValue(current, 1))
        if value is None:
            return None
        return value & 0xFF
    except Exception:
        return None


def read_memory_bytes(program, helper, address, size):
    size = max(0, int(size or 0))
    values = []
    for index in range(size):
        value = read_memory_byte_at(program, helper, int(address) + index)
        if value is None:
            return None
        values.append(value)
    return values


def read_memory_c_bytes(program, helper, address, max_bytes=65536, allow_prefix=False):
    values = []
    for index in range(max_bytes):
        value = read_memory_byte_at(program, helper, int(address) + index)
        if value is None:
            return None
        if value == 0:
            return values
        values.append(value)
    return values if allow_prefix else None


def process_input_path_candidates(process_setup):
    candidates = []
    input_model = str(process_setup.get("input_model") or "")
    concrete = bytes_from_hex(process_setup.get("concrete_input_hex"))
    if input_model == "argv" and concrete:
        candidates.append(("argv", concrete))
    file_name = str(process_setup.get("file_name") or "")
    if file_name:
        candidates.append(("file_name", ascii_bytes(file_name)))
        if input_model == "argv_directory":
            candidates.append(("directory_name", ascii_bytes(file_name.rstrip("/") + "/")))
    return candidates


def process_input_path_match(program, helper, address, process_setup):
    if address is None:
        return {}
    actual = read_memory_c_bytes(program, helper, int(address))
    if actual is None:
        return {}
    for source, candidate in process_input_path_candidates(process_setup):
        if actual == list(candidate):
            return {
                "source": source,
                "path_address": "0x%X" % int(address),
                "path_size_bytes": len(actual),
            }
    return {}


def next_runtime_fd(runtime_state, path_match):
    fd = max(3, int(runtime_state.get("next_fd") or 3))
    runtime_state["next_fd"] = fd + 1
    runtime_state.setdefault("descriptors", {})[fd] = dict(path_match)
    return fd


def dirent_name_offset(process_setup):
    explicit = parse_int(process_setup.get("dirent_d_name_offset_bytes"), 0)
    if explicit > 0:
        return explicit
    abi = dict(process_setup or {})
    if not abi.get("abi"):
        return 0
    if abi.get("abi") == "x86_64_sysv":
        return 19
    if abi.get("abi") == "i386":
        return 11
    return 0


def directory_entry_bytes(process_setup):
    values = bytes_from_hex(process_setup.get("concrete_input_hex"))
    if values is None:
        return None, "invalid_directory_entry_hex"
    values = list(values)[:255]
    if not values:
        return None, "missing_directory_entry"
    if 0 in values or ord("/") in values:
        return None, "invalid_directory_entry_name"
    return values, ""


def write_modeled_stat_buffer(program, helper, address, process_setup):
    abi = dict(process_setup or {})
    if not abi.get("abi"):
        abi.update(program_abi(program))
    if abi.get("abi") != "x86_64_sysv":
        return False, "stat_layout_unsupported_abi"
    size = max(0, parse_int(process_setup.get("input_size_bytes"), 0))
    if not write_memory_bytes(program, helper, int(address), [0] * 144):
        return False, "stat_buffer_write_failed"
    big_endian = abi.get("endianness") == "big"
    if not write_memory_integer(program, helper, int(address) + 24, 0o100644, 4, big_endian):
        return False, "stat_mode_write_failed"
    if not write_memory_integer(program, helper, int(address) + 48, size, 8, big_endian):
        return False, "stat_size_write_failed"
    return True, ""


def abi_argument_values(program, helper, abi, count):
    abi_name = str(abi.get("abi") or "")
    pointer_size = int(abi.get("pointer_size_bytes") or 0)
    if abi_name == "x86_64_sysv":
        registers = [("RDI", "rdi"), ("RSI", "rsi"), ("RDX", "rdx"), ("RCX", "rcx"), ("R8", "r8"), ("R9", "r9")]
        return [read_register(program, helper, registers[index]) for index in range(min(count, len(registers)))]
    if abi_name == "aarch64":
        registers = [("x%d" % index, "X%d" % index) for index in range(8)]
        return [read_register(program, helper, registers[index]) for index in range(min(count, len(registers)))]
    if abi_name == "arm32":
        registers = [("r0", "R0"), ("r1", "R1"), ("r2", "R2"), ("r3", "R3")]
        return [read_register(program, helper, registers[index]) for index in range(min(count, len(registers)))]
    if abi_name == "i386" and pointer_size in (4, 8):
        stack_pointer = read_register(program, helper, ("ESP", "esp", "SP", "sp"))
        if stack_pointer is None:
            return []
        big_endian = abi.get("endianness") == "big"
        return [
            read_memory_integer(program, helper, stack_pointer + pointer_size * (index + 1), pointer_size, big_endian)
            for index in range(count)
        ]
    return []


def write_return_value(program, helper, abi, value):
    abi_name = str(abi.get("abi") or "")
    if abi_name == "x86_64_sysv":
        return write_register(program, helper, ("RAX", "rax"), value)
    if abi_name == "i386":
        return write_register(program, helper, ("EAX", "eax"), value)
    if abi_name == "aarch64":
        return write_register(program, helper, ("x0", "X0"), value)
    if abi_name == "arm32":
        return write_register(program, helper, ("r0", "R0"), value)
    return ""


def write_abi_argument(program, helper, abi, index, value):
    abi_name = str(abi.get("abi") or "")
    pointer_size = int(abi.get("pointer_size_bytes") or 0)
    if abi_name == "x86_64_sysv":
        registers = [("RDI", "rdi"), ("RSI", "rsi"), ("RDX", "rdx"), ("RCX", "rcx"), ("R8", "r8"), ("R9", "r9")]
        if 0 <= index < len(registers):
            return write_register(program, helper, registers[index], value)
        if index >= len(registers) and pointer_size in (4, 8):
            stack_pointer = read_register(program, helper, ("RSP", "rsp", "SP", "sp"))
            if stack_pointer is None:
                return ""
            big_endian = abi.get("endianness") == "big"
            address = stack_pointer + pointer_size * (index - len(registers) + 1)
            if write_memory_bytes(program, helper, address, pointer_bytes(value, pointer_size, big_endian)):
                return "stack:0x%X" % address
    if abi_name == "aarch64":
        registers = [("x0", "X0"), ("x1", "X1"), ("x2", "X2"), ("x3", "X3"), ("x4", "X4"), ("x5", "X5")]
        if 0 <= index < len(registers):
            return write_register(program, helper, registers[index], value)
    if abi_name == "arm32":
        registers = [("r0", "R0"), ("r1", "R1"), ("r2", "R2"), ("r3", "R3")]
        if 0 <= index < len(registers):
            return write_register(program, helper, registers[index], value)
    if abi_name == "i386" and pointer_size in (4, 8):
        stack_pointer = read_register(program, helper, ("ESP", "esp", "SP", "sp"))
        if stack_pointer is None:
            return ""
        big_endian = abi.get("endianness") == "big"
        address = stack_pointer + pointer_size * (index + 1)
        if write_memory_bytes(program, helper, address, pointer_bytes(value, pointer_size, big_endian)):
            return "stack:0x%X" % address
    return ""


def address_offset(address):
    try:
        return int(address.getOffset())
    except Exception:
        return None


def addresses_equal(left, right):
    left_offset = address_offset(left)
    right_offset = address_offset(right)
    return left_offset is not None and right_offset is not None and left_offset == right_offset


def instruction_is_call(instruction):
    try:
        flow_type = instruction.getFlowType()
        if flow_type is not None and flow_type.isCall():
            return True
    except Exception:
        pass
    try:
        return str(instruction.getMnemonicString()).upper().startswith("CALL")
    except Exception:
        return str(instruction).upper().startswith("CALL")


def instruction_mnemonic(instruction):
    try:
        return str(instruction.getMnemonicString()).upper()
    except Exception:
        return str(instruction or "").split(" ", 1)[0].upper()


def instruction_fallthrough(instruction):
    try:
        return instruction.getFallThrough()
    except Exception:
        return None


def instruction_operand_count(instruction):
    try:
        return max(0, int(instruction.getNumOperands()))
    except Exception:
        return 0


def instruction_operand_objects(instruction, index):
    try:
        return list(instruction.getOpObjects(index))
    except Exception:
        return []


def instruction_operand_representation(instruction, index):
    try:
        return str(instruction.getDefaultOperandRepresentation(index) or "")
    except Exception:
        return ""


def function_name(function):
    try:
        return str(function.getName())
    except Exception:
        return ""


def normalized_api_name(name):
    text = str(name or "").strip().split("@", 1)[0]
    text = text.split("(", 1)[0].strip()
    if "::" in text:
        text = text.rsplit("::", 1)[-1]
    lowered = text.lower()
    for prefix in ("__imp_", "_imp_", "imp_"):
        if lowered.startswith(prefix):
            text = text[len(prefix) :]
            lowered = text.lower()
            break
    if text.startswith("thunk_"):
        text = text[len("thunk_") :]
    text = text.strip("_").lower()
    if text.endswith("_alias"):
        text = text[: -len("_alias")]
    return text


def function_is_external_or_thunk(function):
    if function is None:
        return False
    try:
        if function.isExternal():
            return True
    except Exception:
        pass
    try:
        if function.isThunk():
            return True
    except Exception:
        pass
    return False


def function_at(program, address):
    try:
        function = program.getFunctionManager().getFunctionAt(address)
        if function is not None:
            return function
    except Exception:
        pass
    try:
        return program.getFunctionManager().getFunctionContaining(address)
    except Exception:
        return None


def operand_integer(value):
    try:
        return int(value.getOffset())
    except Exception:
        pass
    try:
        return int(value.getUnsignedValue())
    except Exception:
        pass
    return to_int(value)


def operand_register_name(program, value):
    try:
        name = str(value.getName())
    except Exception:
        return ""
    if not name:
        return ""
    try:
        if program.getRegister(name) is None:
            return ""
    except Exception:
        pass
    return name


COMMON_REGISTER_NAMES = (
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rsp",
    "rbp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "esp",
    "ebp",
    "x0",
    "x1",
    "x2",
    "x3",
    "x4",
    "x5",
    "x6",
    "x7",
    "x8",
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
)


def representation_register_names(text):
    lowered = str(text or "").lower()
    names = []
    for name in COMMON_REGISTER_NAMES:
        if re.search(r"(?<![a-z0-9_])%s(?![a-z0-9_])" % re.escape(name), lowered):
            names.append(name)
    return names


def representation_is_memory_reference(text):
    lowered = str(text or "").lower()
    return "[" in lowered or "]" in lowered or "(" in lowered or ")" in lowered or lowered.startswith("*")


def memory_reference_value(text, register_values):
    match = re.search(r"\[([^\]]+)\]", str(text or ""))
    if not match:
        return None
    total = 0
    for raw_term in re.sub(r"(?<!^)-", "+-", match.group(1)).split("+"):
        term = raw_term.strip().lower()
        if not term:
            continue
        scale_match = re.match(r"^([a-z][a-z0-9]*)\s*\*\s*(0x[0-9a-f]+|\d+)$", term)
        if scale_match:
            register = scale_match.group(1)
            if register not in register_values:
                return None
            total += int(register_values[register]) * int(scale_match.group(2), 0)
            continue
        if re.match(r"^[a-z][a-z0-9]*$", term):
            if term not in register_values:
                return None
            total += int(register_values[term])
            continue
        try:
            total += int(term, 0)
        except Exception:
            return None
    return total


def memory_reference_base_value(text, register_values):
    match = re.search(r"\[([^\]]+)\]", str(text or ""))
    if not match:
        return None
    for raw_term in re.sub(r"(?<!^)-", "+-", match.group(1)).split("+"):
        term = raw_term.strip().lower()
        if re.match(r"^[a-z][a-z0-9]*$", term) and term in register_values:
            return int(register_values[term])
    return None


def modeled_direct_memory_read(program, helper, instruction, args):
    if instruction is None or not is_oob_read_candidate(args):
        return {}
    for index in range(instruction_operand_count(instruction)):
        representation = instruction_operand_representation(instruction, index)
        if not representation_is_memory_reference(representation):
            continue
        registers = {}
        for name in representation_register_names(representation):
            value = read_register(program, helper, (name, name.upper()))
            if value is None:
                registers = {}
                break
            registers[name] = value
        address = memory_reference_value(representation, registers)
        if address is None:
            continue
        effect = {
            "status": "modeled",
            "function_model": "direct_memory_read",
            "source_address": "0x%X" % int(address),
            "read_bytes": max(1, parse_int(args.get("write_size_bytes"), 1)),
            "operand": representation,
        }
        base_address = memory_reference_base_value(representation, registers)
        if base_address is not None:
            effect["object_base_address"] = "0x%X" % int(base_address)
        return effect
    return {}


def modeled_direct_lifetime_access(program, helper, instruction, args, runtime_state):
    if instruction is None or str(args.get("vulnerability_type") or "") != "use_after_free":
        return {}
    mnemonic = str(instruction.getMnemonicString() or "").lower()
    for index in range(instruction_operand_count(instruction)):
        representation = instruction_operand_representation(instruction, index)
        if not representation_is_memory_reference(representation):
            continue
        registers = {}
        for name in representation_register_names(representation):
            value = read_register(program, helper, (name, name.upper()))
            if value is None:
                registers = {}
                break
            registers[name] = value
        address = memory_reference_value(representation, registers)
        if address is None:
            continue
        access_kind = "write" if index == 0 and mnemonic not in {"cmp", "test", "push"} else "read"
        event = {
            "status": "lifetime_violation",
            "function_model": "direct_memory_%s" % access_kind,
            "address": "0x%X" % int(address),
            "operand": representation,
            "access_kind": access_kind,
        }
        violation = released_object_access(runtime_state, int(address), access_kind, event)
        if violation:
            event["lifetime_violation"] = violation
            return event
    return {}


def indirect_call_target(program, helper, instruction):
    if helper is None or instruction is None or not instruction_is_call(instruction):
        return None
    try:
        if list(instruction.getFlows()):
            return None
    except Exception:
        pass
    abi = program_abi(program)
    pointer_size = int(abi.get("pointer_size_bytes") or 0)
    if pointer_size not in (4, 8):
        return None
    big_endian = abi.get("endianness") == "big"
    count = instruction_operand_count(instruction) or 1
    for index in range(count):
        representation = instruction_operand_representation(instruction, index)
        memory_reference = representation_is_memory_reference(representation)
        for obj in instruction_operand_objects(instruction, index):
            register_name = operand_register_name(program, obj)
            if register_name:
                register_value = read_register(program, helper, (register_name, register_name.upper()))
                if register_value is None:
                    continue
                if memory_reference:
                    pointer = read_memory_integer(program, helper, register_value, pointer_size, big_endian)
                    if pointer is not None:
                        return default_space_address(program, pointer)
                return default_space_address(program, register_value)
            value = operand_integer(obj)
            if value is not None and function_at(program, default_space_address(program, value)):
                return default_space_address(program, value)
        for register_name in representation_register_names(representation):
            register_value = read_register(program, helper, (register_name, register_name.upper()))
            if register_value is None:
                continue
            if memory_reference:
                pointer = read_memory_integer(program, helper, register_value, pointer_size, big_endian)
                if pointer is not None:
                    return default_space_address(program, pointer)
            return default_space_address(program, register_value)
    return None


def external_call_skip(program, helper, instruction, sink_address):
    target = external_call_target(program, instruction, sink_address, helper)
    if not target:
        return {}
    target = dict(target)
    target["reason"] = "non_sink_external_call"
    return target


def resolved_call_target(program, helper, instruction, sink_address, external_only=True):
    if instruction is None or not instruction_is_call(instruction):
        return {}
    try:
        targets = list(instruction.getFlows())
    except Exception:
        targets = []
    if not targets:
        indirect = indirect_call_target(program, helper, instruction)
        targets = [indirect] if indirect is not None else []
        target_kind = "indirect"
    else:
        target_kind = "direct"
    fallthrough = instruction_fallthrough(instruction)
    if fallthrough is None:
        return {}
    for target in targets:
        if target is None:
            continue
        if external_only and addresses_equal(target, sink_address):
            return {}
        target_function = function_at(program, target)
        if external_only and not function_is_external_or_thunk(target_function):
            continue
        return {
            "call_address": address_hex(instruction.getAddress()),
            "target_address": address_hex(target),
            "target_function": function_name(target_function),
            "fallthrough_address": address_hex(fallthrough),
            "target_kind": target_kind,
        }
    return {}


def external_call_target(program, instruction, sink_address, helper=None):
    return resolved_call_target(program, helper, instruction, sink_address, external_only=True)


def modeled_stdin_input_call(program, helper, instruction, sink_address, args, process_setup, input_state):
    if str(args.get("input_model") or "") not in {"stdin", "argv_file_stdin"}:
        return {}
    target = external_call_target(program, instruction, sink_address, helper)
    if not target:
        return {}
    api = normalized_api_name(target.get("target_function"))
    if api not in {"read", "fgets", "gets", "fread", "getc", "fgetc", "getc_unlocked", "ungetc", "feof", "feof_unlocked", "ferror", "clearerr", "fseek", "fseeko", "fseeko64", "ftell", "ftello", "ftello64"}:
        return {}
    input_bytes = input_state.get("bytes")
    if input_bytes is None:
        input_bytes = bytes_from_hex(args.get("stdin_input_hex") or args.get("concrete_input_hex"))
        if input_bytes is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:invalid_concrete_input_hex"}
        input_state["bytes"] = list(input_bytes)
    offset = int(input_state.get("offset") or 0)
    remaining = list(input_state.get("bytes") or [])[offset:]
    abi = dict(process_setup or {})
    if not abi.get("abi"):
        abi.update(program_abi(program))
    values = abi_argument_values(program, helper, abi, 4)
    stream_index = 3 if api == "fread" else 2 if api == "fgets" else 1 if api == "ungetc" else 0
    if api not in {"read", "gets"} and len(values) > stream_index and values[stream_index] is not None:
        stream_address = int(values[stream_index])
        known_stream = process_setup.get("stdin_stream_address")
        if known_stream is None:
            process_setup["stdin_stream_address"] = stream_address
        elif int(known_stream) != stream_address:
            return {}
    if api in {"ftell", "ftello", "ftello64"}:
        if not write_return_value(program, helper, abi, offset):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:stdin_return_register_unavailable"}
        event = {
            "status": "modeled",
            "input_model": "stdin",
            "function_model": api,
            "call_address": target.get("call_address"),
            "target_address": target.get("target_address"),
            "target_function": target.get("target_function"),
            "fallthrough_address": target.get("fallthrough_address"),
            "return_value": offset,
            "input_offset_before": offset,
            "input_offset_after": offset,
        }
        process_setup.setdefault("modeled_stdin_calls", []).append(event)
        return event
    if api in {"fseek", "fseeko", "fseeko64"}:
        if len(values) < 3 or values[1] is None or values[2] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:stdin_fseek_args_unavailable"}
        requested_offset = int(values[1])
        whence = int(values[2])
        if whence == 0:
            next_offset = requested_offset
        elif whence == 1:
            next_offset = offset + requested_offset
        elif whence == 2:
            next_offset = len(list(input_state.get("bytes") or [])) + requested_offset
        else:
            next_offset = -1
        return_value = 0 if 0 <= next_offset <= len(list(input_state.get("bytes") or [])) else -1
        if return_value == 0:
            input_state["offset"] = next_offset
            process_setup["stdin_consumed_bytes"] = next_offset
        if not write_return_value(program, helper, abi, return_value):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:stdin_return_register_unavailable"}
        event = {
            "status": "modeled",
            "input_model": "stdin",
            "function_model": api,
            "call_address": target.get("call_address"),
            "target_address": target.get("target_address"),
            "target_function": target.get("target_function"),
            "fallthrough_address": target.get("fallthrough_address"),
            "return_value": return_value,
            "requested_offset": requested_offset,
            "whence": whence,
            "input_offset_before": offset,
            "input_offset_after": int(input_state.get("offset") or 0),
        }
        process_setup.setdefault("modeled_stdin_calls", []).append(event)
        return event
    if api in {"feof", "feof_unlocked", "ferror", "clearerr"}:
        return_value = 1 if api in {"feof", "feof_unlocked"} and not remaining else 0
        if not write_return_value(program, helper, abi, return_value):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:stdin_return_register_unavailable"}
        event = {
            "status": "modeled",
            "input_model": "stdin",
            "function_model": api,
            "call_address": target.get("call_address"),
            "target_address": target.get("target_address"),
            "target_function": target.get("target_function"),
            "fallthrough_address": target.get("fallthrough_address"),
            "return_value": return_value,
            "input_offset_before": offset,
            "input_offset_after": offset,
        }
        process_setup.setdefault("modeled_stdin_calls", []).append(event)
        return event
    if api == "ungetc":
        if len(values) < 1 or values[0] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:stdin_ungetc_args_unavailable"}
        return_value = -1
        if offset > 0 and int(values[0]) >= 0:
            input_state["offset"] = offset - 1
            return_value = int(values[0]) & 0xFF
        if not write_return_value(program, helper, abi, return_value):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:stdin_return_register_unavailable"}
        process_setup["stdin_consumed_bytes"] = int(input_state.get("offset") or 0)
        event = {
            "status": "modeled",
            "input_model": "stdin",
            "function_model": api,
            "call_address": target.get("call_address"),
            "target_address": target.get("target_address"),
            "target_function": target.get("target_function"),
            "fallthrough_address": target.get("fallthrough_address"),
            "return_value": return_value,
            "input_offset_before": offset,
            "input_offset_after": int(input_state.get("offset") or 0),
        }
        process_setup.setdefault("modeled_stdin_calls", []).append(event)
        return event
    if api == "read":
        if len(values) < 3 or values[0] is None or values[1] is None or values[2] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:stdin_read_args_unavailable"}
        if int(values[0]) != 0:
            return {}
        buffer_address = int(values[1])
        requested = max(0, int(values[2]))
        chunk = remaining[:requested]
        written_values = chunk
        return_value = len(chunk)
    elif api == "fgets":
        if len(values) < 2 or values[0] is None or values[1] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:stdin_fgets_args_unavailable"}
        buffer_address = int(values[0])
        requested = max(0, int(values[1]) - 1)
        chunk = remaining[:requested]
        newline_index = -1
        try:
            newline_index = chunk.index(10)
        except Exception:
            pass
        if newline_index >= 0:
            chunk = chunk[: newline_index + 1]
        written_values = chunk + [0]
        return_value = buffer_address if chunk else 0
    elif api == "gets":
        if len(values) < 1 or values[0] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:stdin_gets_args_unavailable"}
        buffer_address = int(values[0])
        requested = len(remaining)
        chunk = remaining
        written_values = chunk + [0]
        return_value = buffer_address if chunk else 0
    elif api == "fread":
        if len(values) < 3 or values[0] is None or values[1] is None or values[2] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:stdin_fread_args_unavailable"}
        buffer_address = int(values[0])
        item_size = max(0, int(values[1]))
        item_count = max(0, int(values[2]))
        requested = item_size * item_count
        chunk = remaining[:requested]
        written_values = chunk
        return_value = len(chunk) // item_size if item_size else 0
    else:
        buffer_address = 0
        requested = 1
        chunk = remaining[:1]
        written_values = []
        return_value = chunk[0] if chunk else -1
    if written_values and not write_memory_bytes(program, helper, buffer_address, written_values):
        return {"status": "unsupported", "reason": "unsupported_process_input_setup:stdin_memory_write_failed"}
    if not write_return_value(program, helper, abi, return_value):
        return {"status": "unsupported", "reason": "unsupported_process_input_setup:stdin_return_register_unavailable"}
    input_state["offset"] = offset + len(chunk)
    process_setup["stdin_consumed_bytes"] = input_state["offset"]
    event = {
        "status": "modeled",
        "input_model": "stdin",
        "function_model": api,
        "call_address": target.get("call_address"),
        "target_address": target.get("target_address"),
        "target_function": target.get("target_function"),
        "fallthrough_address": target.get("fallthrough_address"),
        "buffer_address": "0x%X" % buffer_address,
        "requested_bytes": requested,
        "written_bytes": len(chunk),
        "return_value": return_value,
        "nul_terminated": api in {"fgets", "gets"},
        "input_offset_before": offset,
        "input_offset_after": input_state["offset"],
    }
    process_setup.setdefault("modeled_stdin_calls", []).append(event)
    return event


def path_basename(path):
    text = str(path or "").replace("\\", "/")
    return text.rsplit("/", 1)[-1]


def file_path_matches(path, expected):
    return path_basename(path) == str(expected or "")


def ensure_file_state(args, file_state):
    input_bytes = file_state.get("bytes")
    if input_bytes is None:
        input_bytes = bytes_from_hex(args.get("file_input_hex") or args.get("concrete_input_hex"))
        if input_bytes is None:
            return None
        file_state["bytes"] = list(input_bytes)
    file_state.setdefault("file_name", str(args.get("file_name") or "concolic_input"))
    file_state.setdefault("descriptors", {})
    file_state.setdefault("streams", {})
    file_state.setdefault("next_fd", 3)
    file_state.setdefault("next_stream", 0x7FFEE000)
    return file_state


def read_file_chunk(file_state, handle_table, handle, requested):
    entry = handle_table.get(handle)
    if entry is None:
        return None
    offset = int(entry.get("offset") or 0)
    requested = max(0, int(requested or 0))
    data = list(file_state.get("bytes") or [])
    chunk = []
    pushback = entry.setdefault("pushback", [])
    while len(chunk) < requested and pushback:
        chunk.append(int(pushback.pop()) & 0xFF)
    remaining = requested - len(chunk)
    file_chunk = data[offset : offset + remaining]
    chunk.extend(file_chunk)
    entry["offset"] = offset + len(file_chunk)
    if remaining > 0 and len(file_chunk) < remaining:
        entry["eof"] = True
    elif chunk:
        entry["eof"] = False
    return offset, chunk


def seek_file_stream(file_state, streams, handle, offset, whence):
    entry = streams.get(handle)
    if entry is None:
        return None
    data_size = len(list(file_state.get("bytes") or []))
    current = int(entry.get("offset") or 0)
    whence = int(whence)
    if whence == 0:
        target = int(offset)
    elif whence == 1:
        target = current + int(offset)
    elif whence == 2:
        target = data_size + int(offset)
    else:
        return None
    if target < 0:
        return None
    entry["offset"] = target
    entry["pushback"] = []
    entry["eof"] = False
    return current, target


def tell_file_stream(streams, handle):
    entry = streams.get(handle)
    if entry is None:
        return None
    return max(0, int(entry.get("offset") or 0) - len(list(entry.get("pushback") or [])))


def bounded_string_scan_widths(format_text):
    text = str(format_text or "")
    widths = []
    index = 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        if text[index] != "%":
            return None
        index += 1
        start = index
        while index < len(text) and text[index].isdigit():
            index += 1
        if start == index or index >= len(text) or text[index] != "s":
            return None
        width = int(text[start:index])
        if width <= 0 or width > 4096:
            return None
        widths.append(width)
        index += 1
    return widths or None


def scan_file_string(file_state, streams, handle, width):
    entry = streams.get(handle)
    if entry is None:
        return None
    while True:
        result = read_file_chunk(file_state, streams, handle, 1)
        if result is None:
            return None
        _offset, chunk = result
        if not chunk:
            return None
        if chr(int(chunk[0]) & 0xFF).isspace():
            continue
        entry.setdefault("pushback", []).append(int(chunk[0]) & 0xFF)
        break
    token = []
    while len(token) < int(width):
        result = read_file_chunk(file_state, streams, handle, 1)
        if result is None:
            return None
        _offset, chunk = result
        if not chunk:
            break
        value = int(chunk[0]) & 0xFF
        if chr(value).isspace():
            entry.setdefault("pushback", []).append(value)
            break
        token.append(value)
    return token or None


def modeled_file_input_call(program, helper, instruction, sink_address, args, process_setup, file_state):
    if str(args.get("input_model") or "") not in {"file", "env_file", "argv_file_stdin"}:
        return {}
    target = external_call_target(program, instruction, sink_address, helper)
    if not target:
        return {}
    api = normalized_api_name(target.get("target_function"))
    if api not in {
        "open",
        "open64",
        "fopen",
        "fopen64",
        "fdopen",
        "fstat",
        "fstat64",
        "lseek",
        "lseek64",
        "mmap",
        "mmap64",
        "munmap",
        "read",
        "fread",
        "fgets",
        "fseek",
        "fseeko",
        "fseeko64",
        "ftell",
        "ftello",
        "ftello64",
        "rewind",
        "getc",
        "fgetc",
        "getc_unlocked",
        "ungetc",
        "feof",
        "feof_unlocked",
        "ferror",
        "clearerr",
        "close",
        "fclose",
    }:
        if api != "fscanf" and not api.endswith("_fscanf"):
            return {}
    file_state = ensure_file_state(args, file_state)
    if file_state is None:
        return {"status": "unsupported", "reason": "unsupported_process_input_setup:invalid_concrete_input_hex"}
    abi = dict(process_setup or {})
    if not abi.get("abi"):
        abi.update(program_abi(program))
    values = abi_argument_values(program, helper, abi, 6)
    descriptors = file_state.setdefault("descriptors", {})
    streams = file_state.setdefault("streams", {})
    file_name = str(file_state.get("file_name") or "concolic_input")
    if api in {"open", "open64"}:
        if len(values) < 1 or values[0] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_open_args_unavailable"}
        path = read_memory_c_string(program, helper, int(values[0]))
        if path is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_open_path_unavailable"}
        if not file_path_matches(path, file_name):
            return {}
        handle = int(file_state.get("next_fd") or 3)
        file_state["next_fd"] = handle + 1
        descriptors[handle] = {"offset": 0, "path": path}
        if not write_return_value(program, helper, abi, handle):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {"status": "modeled", "input_model": "file", "function_model": api, "file_name": file_name, "path": path, "handle": handle, "handle_kind": "fd"}
    elif api in {"fopen", "fopen64"}:
        if len(values) < 1 or values[0] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_fopen_args_unavailable"}
        path = read_memory_c_string(program, helper, int(values[0]))
        if path is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_fopen_path_unavailable"}
        if not file_path_matches(path, file_name):
            return {}
        handle = int(file_state.get("next_stream") or 0x7FFEE000)
        file_state["next_stream"] = handle + 0x100
        streams[handle] = {"offset": 0, "path": path}
        if not write_return_value(program, helper, abi, handle):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {"status": "modeled", "input_model": "file", "function_model": api, "file_name": file_name, "path": path, "handle": handle, "handle_kind": "FILE"}
    elif api == "fdopen":
        if len(values) < 1 or values[0] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_fdopen_args_unavailable"}
        descriptor = int(values[0])
        descriptor_state = descriptors.get(descriptor)
        if descriptor_state is None:
            return {}
        handle = int(file_state.get("next_stream") or 0x7FFEE000)
        file_state["next_stream"] = handle + 0x100
        streams[handle] = descriptor_state
        if not write_return_value(program, helper, abi, handle):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {
            "status": "modeled",
            "input_model": "file",
            "function_model": api,
            "descriptor": descriptor,
            "handle": handle,
            "handle_kind": "FILE",
            "input_offset_after": tell_file_stream(streams, handle),
        }
    elif api in {"fstat", "fstat64"}:
        if len(values) < 2 or values[0] is None or values[1] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_fstat_args_unavailable"}
        handle = int(values[0])
        if handle not in descriptors:
            return {}
        ok, reason = write_modeled_stat_buffer(program, helper, int(values[1]), process_setup)
        if not ok:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_fstat_%s" % reason}
        if not write_return_value(program, helper, abi, 0):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {
            "status": "modeled",
            "input_model": "file",
            "function_model": api,
            "handle": handle,
            "handle_kind": "fd",
            "return_value": 0,
            "stat_buffer_address": "0x%X" % int(values[1]),
        }
    elif api in {"lseek", "lseek64"}:
        if len(values) < 3 or values[0] is None or values[1] is None or values[2] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_lseek_args_unavailable"}
        handle = int(values[0])
        entry = descriptors.get(handle)
        if entry is None:
            return {}
        offset_before = int(entry.get("offset") or 0)
        requested = int(values[1])
        whence = int(values[2])
        if whence == 0:
            offset_after = requested
        elif whence == 1:
            offset_after = offset_before + requested
        elif whence == 2:
            offset_after = len(list(file_state.get("bytes") or [])) + requested
        else:
            offset_after = -1
        if offset_after < 0:
            return_value = -1
            offset_after = offset_before
        else:
            entry["offset"] = offset_after
            entry["eof"] = False
            return_value = offset_after
        if not write_return_value(program, helper, abi, return_value):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {
            "status": "modeled",
            "input_model": "file",
            "function_model": api,
            "handle": handle,
            "handle_kind": "fd",
            "return_value": return_value,
            "requested_offset": requested,
            "whence": whence,
            "input_offset_before": offset_before,
            "input_offset_after": offset_after,
        }
    elif api in {"mmap", "mmap64"}:
        if len(values) < 6 or values[1] is None or values[4] is None or values[5] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_mmap_args_unavailable"}
        handle = int(values[4])
        if handle not in descriptors:
            return {}
        length = max(0, int(values[1]))
        offset = max(0, int(values[5]))
        address = allocate_runtime_memory(program, helper, file_state, max(1, length), zero_fill=True)
        if not address:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_mmap_allocation_failed"}
        contents = list(file_state.get("bytes") or [])[offset : offset + length]
        if contents and not write_memory_bytes(program, helper, address, contents):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_mmap_write_failed"}
        if not write_return_value(program, helper, abi, address):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {
            "status": "modeled",
            "input_model": "file",
            "function_model": api,
            "handle": handle,
            "handle_kind": "fd",
            "mapping_address": "0x%X" % address,
            "mapping_size_bytes": length,
            "file_offset": offset,
            "mapped_bytes": len(contents),
            "return_value": "0x%X" % address,
        }
    elif api == "munmap":
        if len(values) < 2 or values[0] is None or values[1] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_munmap_args_unavailable"}
        address = int(values[0])
        file_state.setdefault("allocations", {}).pop(address, None)
        if not write_return_value(program, helper, abi, 0):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {
            "status": "modeled",
            "input_model": "file",
            "function_model": api,
            "mapping_address": "0x%X" % address,
            "mapping_size_bytes": max(0, int(values[1])),
            "return_value": 0,
        }
    elif api == "fscanf" or api.endswith("_fscanf"):
        if len(values) < 2 or values[0] is None or values[1] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_fscanf_args_unavailable"}
        handle = int(values[0])
        format_text = read_memory_c_string(program, helper, int(values[1]))
        widths = bounded_string_scan_widths(format_text)
        if widths is None or len(values) < 2 + len(widths):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_fscanf_format_unsupported"}
        assignments = 0
        field_sizes = []
        for index, width in enumerate(widths):
            destination = values[index + 2]
            if destination is None:
                return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_fscanf_destination_unavailable"}
            token = scan_file_string(file_state, streams, handle, width)
            if token is None:
                break
            if not write_memory_bytes(program, helper, int(destination), token + [0]):
                return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_memory_write_failed"}
            assignments += 1
            field_sizes.append(len(token))
        return_value = assignments if assignments else -1
        if not write_return_value(program, helper, abi, return_value):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {
            "status": "modeled",
            "input_model": "file",
            "function_model": api,
            "handle": handle,
            "handle_kind": "FILE",
            "scan_format": format_text,
            "field_widths": widths,
            "field_sizes": field_sizes,
            "return_value": return_value,
            "input_offset_after": tell_file_stream(streams, handle),
        }
    elif api in {"fseek", "fseeko", "fseeko64"}:
        if len(values) < 3 or values[0] is None or values[1] is None or values[2] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_fseek_args_unavailable"}
        handle = int(values[0])
        result = seek_file_stream(file_state, streams, handle, int(values[1]), int(values[2]))
        if result is None:
            return_value = -1
            offset_before = tell_file_stream(streams, handle)
            offset_after = offset_before
        else:
            offset_before, offset_after = result
            return_value = 0
        if not write_return_value(program, helper, abi, return_value):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {
            "status": "modeled",
            "input_model": "file",
            "function_model": api,
            "handle": handle,
            "handle_kind": "FILE",
            "requested_offset": int(values[1]),
            "whence": int(values[2]),
            "return_value": return_value,
            "input_offset_before": offset_before,
            "input_offset_after": offset_after,
        }
    elif api in {"ftell", "ftello", "ftello64"}:
        if len(values) < 1 or values[0] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_ftell_args_unavailable"}
        handle = int(values[0])
        offset = tell_file_stream(streams, handle)
        return_value = -1 if offset is None else int(offset)
        if not write_return_value(program, helper, abi, return_value):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {"status": "modeled", "input_model": "file", "function_model": api, "handle": handle, "handle_kind": "FILE", "return_value": return_value, "input_offset_after": offset}
    elif api == "rewind":
        if len(values) < 1 or values[0] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_rewind_args_unavailable"}
        handle = int(values[0])
        result = seek_file_stream(file_state, streams, handle, 0, 0)
        if result is None:
            return {}
        offset_before, offset_after = result
        if not write_return_value(program, helper, abi, 0):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {"status": "modeled", "input_model": "file", "function_model": api, "handle": handle, "handle_kind": "FILE", "input_offset_before": offset_before, "input_offset_after": offset_after}
    elif api in {"feof", "feof_unlocked", "ferror", "clearerr"}:
        if len(values) < 1 or values[0] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_status_args_unavailable"}
        handle = int(values[0])
        entry = streams.get(handle)
        if entry is None:
            return {}
        if api in {"feof", "feof_unlocked"}:
            value = 1 if bool(entry.get("eof")) else 0
        else:
            value = 0
            if api == "clearerr":
                entry["eof"] = False
        if not write_return_value(program, helper, abi, value):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {"status": "modeled", "input_model": "file", "function_model": api, "handle": handle, "handle_kind": "FILE", "return_value": value, "input_offset_after": tell_file_stream(streams, handle)}
    elif api in {"getc", "fgetc", "getc_unlocked"}:
        if len(values) < 1 or values[0] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_getc_args_unavailable"}
        handle = int(values[0])
        result = read_file_chunk(file_state, streams, handle, 1)
        if result is None:
            return {}
        offset, chunk = result
        return_value = chunk[0] if chunk else -1
        if not write_return_value(program, helper, abi, return_value):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {"status": "modeled", "input_model": "file", "function_model": api, "handle": handle, "handle_kind": "FILE", "return_value": return_value, "input_offset_before": offset, "input_offset_after": tell_file_stream(streams, handle)}
    elif api == "ungetc":
        if len(values) < 2 or values[0] is None or values[1] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_ungetc_args_unavailable"}
        handle = int(values[1])
        entry = streams.get(handle)
        if entry is None:
            return {}
        value = int(values[0])
        if value < 0:
            return_value = -1
        else:
            entry.setdefault("pushback", []).append(value & 0xFF)
            entry["eof"] = False
            return_value = value & 0xFF
        if not write_return_value(program, helper, abi, return_value):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {"status": "modeled", "input_model": "file", "function_model": api, "handle": handle, "handle_kind": "FILE", "return_value": return_value, "input_offset_after": tell_file_stream(streams, handle)}
    elif api == "read":
        if len(values) < 3 or values[0] is None or values[1] is None or values[2] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_read_args_unavailable"}
        handle = int(values[0])
        result = read_file_chunk(file_state, descriptors, handle, int(values[2]))
        if result is None:
            return {}
        offset, chunk = result
        if not write_memory_bytes(program, helper, int(values[1]), chunk):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_memory_write_failed"}
        if not write_return_value(program, helper, abi, len(chunk)):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {"status": "modeled", "input_model": "file", "function_model": api, "handle": handle, "handle_kind": "fd", "buffer_address": "0x%X" % int(values[1]), "requested_bytes": int(values[2]), "written_bytes": len(chunk), "input_offset_before": offset, "input_offset_after": offset + len(chunk)}
    elif api == "fread":
        raw_api = str(target.get("target_function") or "").lower()
        if "_chk" in raw_api and len(values) >= 5 and values[4] is not None:
            buffer_value = values[0]
            size_value = values[2]
            count_value = values[3]
            handle_value = values[4]
        elif len(values) >= 4:
            buffer_value = values[0]
            size_value = values[1]
            count_value = values[2]
            handle_value = values[3]
        else:
            buffer_value = size_value = count_value = handle_value = None
        if buffer_value is None or size_value is None or count_value is None or handle_value is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_fread_args_unavailable"}
        size = max(0, int(size_value))
        count = max(0, int(count_value))
        requested = size * count
        handle = int(handle_value)
        result = read_file_chunk(file_state, streams, handle, requested)
        if result is None:
            return {}
        offset, chunk = result
        if not write_memory_bytes(program, helper, int(buffer_value), chunk):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_memory_write_failed"}
        items = (len(chunk) // size) if size > 0 else 0
        if not write_return_value(program, helper, abi, items):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {"status": "modeled", "input_model": "file", "function_model": api, "handle": handle, "handle_kind": "FILE", "buffer_address": "0x%X" % int(buffer_value), "requested_bytes": requested, "written_bytes": len(chunk), "items_returned": items, "input_offset_before": offset, "input_offset_after": tell_file_stream(streams, handle)}
    elif api == "fgets":
        if len(values) < 3 or values[0] is None or values[1] is None or values[2] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_fgets_args_unavailable"}
        handle = int(values[2])
        result = read_file_chunk(file_state, streams, handle, max(0, int(values[1]) - 1))
        if result is None:
            return {}
        offset, chunk = result
        newline_index = -1
        try:
            newline_index = chunk.index(10)
        except Exception:
            pass
        if newline_index >= 0:
            chunk = chunk[: newline_index + 1]
            streams[handle]["offset"] = offset + len(chunk)
        if not write_memory_bytes(program, helper, int(values[0]), chunk + [0]):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_memory_write_failed"}
        if not write_return_value(program, helper, abi, int(values[0]) if chunk else 0):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {"status": "modeled", "input_model": "file", "function_model": api, "handle": handle, "handle_kind": "FILE", "buffer_address": "0x%X" % int(values[0]), "requested_bytes": max(0, int(values[1]) - 1), "written_bytes": len(chunk), "nul_terminated": True, "input_offset_before": offset, "input_offset_after": offset + len(chunk)}
    elif api in {"close", "fclose"}:
        if len(values) < 1 or values[0] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_close_args_unavailable"}
        handle = int(values[0])
        descriptors.pop(handle, None)
        streams.pop(handle, None)
        if not write_return_value(program, helper, abi, 0):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:file_return_register_unavailable"}
        event = {"status": "modeled", "input_model": "file", "function_model": api, "handle": handle}
    else:
        return {}
    event.update({"call_address": target.get("call_address"), "target_address": target.get("target_address"), "target_function": target.get("target_function"), "fallthrough_address": target.get("fallthrough_address")})
    process_setup.setdefault("modeled_file_calls", []).append(event)
    prior_consumed = parse_int(process_setup.get("file_consumed_bytes"), 0)
    process_setup["file_consumed_bytes"] = max(
        [int(entry.get("offset") or 0) for entry in list(descriptors.values()) + list(streams.values())]
        + [prior_consumed]
    )
    return event


def ensure_env_state(args, env_state):
    variables = env_state.get("variables")
    if variables is None:
        variables = {}
        if str(args.get("input_model") or "") == "env_file":
            for name, value in json_arg(args, "env_values_json").items():
                name = str(name)
                value_bytes = ascii_bytes(str(value))
                if not name or "=" in name or "\x00" in name or 0 in value_bytes:
                    return None
                variables[name] = value_bytes
        else:
            input_bytes = env_state.get("bytes")
            if input_bytes is None:
                input_bytes = bytes_from_hex(args.get("concrete_input_hex"))
            if input_bytes is None or 0 in input_bytes:
                return None
            name = str(args.get("env_name") or "CONCOLIC_INPUT")
            variables[name] = list(input_bytes)
        env_state["variables"] = variables
    if not variables:
        return None
    env_state.setdefault("values", {})
    env_state.setdefault("next_value_address", 0x7FFDB000)
    return env_state


def env_value_address(program, helper, env_state, variable_name):
    values = env_state.setdefault("values", {})
    entry = values.get(variable_name)
    if entry is not None:
        return int(entry.get("address") or 0)
    address = int(env_state.get("next_value_address") or 0x7FFDB000)
    value_bytes = list(dict(env_state.get("variables") or {}).get(variable_name) or [])
    if not value_bytes:
        return 0
    if not write_memory_bytes(program, helper, address, value_bytes + [0]):
        return 0
    env_state["next_value_address"] = address + max(0x100, len(value_bytes) + 1)
    values[variable_name] = {"address": address, "size_bytes": len(value_bytes)}
    return address


def modeled_env_input_call(program, helper, instruction, sink_address, args, process_setup, env_state):
    input_model = str(args.get("input_model") or "")
    if input_model not in {"env", "env_file"}:
        return {}
    target = external_call_target(program, instruction, sink_address, helper)
    if not target:
        return {}
    api = normalized_api_name(target.get("target_function"))
    if api not in {"getenv", "secure_getenv"}:
        return {}
    abi = dict(process_setup or {})
    if not abi.get("abi"):
        abi.update(program_abi(program))
    values = abi_argument_values(program, helper, abi, 1)
    if len(values) < 1 or values[0] is None:
        return {"status": "unsupported", "reason": "unsupported_process_input_setup:env_getenv_args_unavailable"}
    variable_name = read_memory_c_string(program, helper, int(values[0]))
    if not variable_name:
        return {"status": "unsupported", "reason": "unsupported_process_input_setup:env_name_unavailable"}
    env_state = ensure_env_state(args, env_state)
    if env_state is None:
        return {"status": "unsupported", "reason": "unsupported_process_input_setup:invalid_env_value"}
    variables = dict(env_state.get("variables") or {})
    if variable_name not in variables:
        if not write_return_value(program, helper, abi, 0):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:env_return_register_unavailable"}
        event = {
            "status": "modeled",
            "input_model": input_model,
            "function_model": api,
            "variable_name": variable_name,
            "value_address": "0x0",
            "value_size_bytes": 0,
            "environment_model": "absent",
            "input_controlled": False,
            "call_address": target.get("call_address"),
            "target_address": target.get("target_address"),
            "target_function": target.get("target_function"),
            "fallthrough_address": target.get("fallthrough_address"),
        }
        process_setup.setdefault("modeled_env_calls", []).append(event)
        return event
    value_address = env_value_address(program, helper, env_state, variable_name)
    if not value_address:
        return {"status": "unsupported", "reason": "unsupported_process_input_setup:env_memory_write_failed"}
    if not write_return_value(program, helper, abi, value_address):
        return {"status": "unsupported", "reason": "unsupported_process_input_setup:env_return_register_unavailable"}
    event = {
        "status": "modeled",
        "input_model": input_model,
        "function_model": api,
        "variable_name": variable_name,
        "value_address": "0x%X" % value_address,
        "value_size_bytes": len(list(variables.get(variable_name) or [])),
        "environment_model": "configured",
        "input_controlled": input_model == "env",
        "call_address": target.get("call_address"),
        "target_address": target.get("target_address"),
        "target_function": target.get("target_function"),
        "fallthrough_address": target.get("fallthrough_address"),
    }
    process_setup.setdefault("modeled_env_calls", []).append(event)
    names = process_setup.setdefault("env_variable_names", [])
    if variable_name not in names:
        names.append(variable_name)
    return event


def align_down(value, alignment):
    alignment = max(1, int(alignment or 1))
    return int(value) - (int(value) % alignment)


def runtime_api_name(name):
    api = normalized_api_name(name).replace(" ", "_").replace(".", "_")
    for prefix in ("libc_", "gi_", "isoc99_"):
        if api.startswith(prefix):
            api = api[len(prefix) :]
    aliases = {
        "bcopy": "memmove",
        "bzero": "memzero",
        "stpcpy": "strcpy_end",
        "printf_chk": "printf",
        "fprintf_chk": "fprintf",
        "operator_new": "malloc",
        "operator_new[]": "malloc",
        "operator_delete": "free",
        "operator_delete[]": "free",
    }
    return aliases.get(api, api)


def runtime_event(target, api, status="modeled"):
    event = {
        "status": status,
        "function_model": api,
        "call_address": target.get("call_address"),
        "target_address": target.get("target_address"),
        "target_function": target.get("target_function"),
        "fallthrough_address": target.get("fallthrough_address"),
    }
    if target.get("target_kind"):
        event["target_kind"] = target.get("target_kind")
    return event


def compare_c_byte_lists(left, right):
    left = list(left or [])
    right = list(right or [])
    limit = max(len(left), len(right)) + 1
    for index in range(limit):
        left_value = left[index] if index < len(left) else 0
        right_value = right[index] if index < len(right) else 0
        if left_value != right_value:
            return -1 if left_value < right_value else 1
    return 0


def render_printf_bytes(program, helper, format_address, arguments):
    format_bytes = read_memory_c_bytes(program, helper, int(format_address))
    if format_bytes is None:
        return None
    rendered = []
    argument_index = 0
    index = 0
    while index < len(format_bytes):
        value = int(format_bytes[index])
        if value != ord("%"):
            rendered.append(value)
            index += 1
            continue
        index += 1
        if index < len(format_bytes) and int(format_bytes[index]) == ord("%"):
            rendered.append(ord("%"))
            index += 1
            continue
        while index < len(format_bytes) and chr(int(format_bytes[index])) in "-+ #0'123456789.*hljztL":
            index += 1
        if index >= len(format_bytes) or argument_index >= len(arguments):
            return None
        spec = chr(int(format_bytes[index]))
        argument = arguments[argument_index]
        argument_index += 1
        index += 1
        if argument is None:
            return None
        if spec == "s":
            string_bytes = read_memory_c_bytes(program, helper, int(argument))
            if string_bytes is None:
                return None
            rendered.extend(string_bytes)
        elif spec == "c":
            rendered.append(int(argument) & 0xFF)
        elif spec in "di":
            rendered.extend(ascii_bytes(str(int(argument))))
        elif spec == "u":
            rendered.extend(ascii_bytes(str(int(argument) & 0xFFFFFFFFFFFFFFFF)))
        elif spec in "xX":
            text = format(int(argument) & 0xFFFFFFFFFFFFFFFF, "x")
            rendered.extend(ascii_bytes(text.upper() if spec == "X" else text))
        elif spec == "o":
            rendered.extend(ascii_bytes(format(int(argument) & 0xFFFFFFFFFFFFFFFF, "o")))
        elif spec == "p":
            rendered.extend(ascii_bytes("0x%x" % (int(argument) & 0xFFFFFFFFFFFFFFFF)))
        else:
            return None
    return rendered


def allocate_runtime_memory(program, helper, runtime_state, size, zero_fill=False):
    size = max(1, int(size or 0))
    heap_next = int(runtime_state.get("next_heap") or 0x70000000)
    address = align_down(heap_next + 15, 16)
    runtime_state["next_heap"] = address + max(size, 16)
    object_id = int(runtime_state.get("next_object_id") or 1)
    runtime_state["next_object_id"] = object_id + 1
    runtime_state.setdefault("allocations", {})[address] = {
        "object_id": object_id,
        "base_address": address,
        "size_bytes": size,
        "state": "live",
    }
    if zero_fill and not write_memory_bytes(program, helper, address, [0] * size):
        return 0
    return address


def runtime_errno_address(program, helper, runtime_state):
    address = int(runtime_state.get("errno_address") or 0)
    if address:
        return address
    address = allocate_runtime_memory(program, helper, runtime_state, 4, zero_fill=True)
    if address:
        runtime_state["errno_address"] = address
    return address


def set_runtime_errno(program, helper, runtime_state, value, big_endian=False):
    address = runtime_errno_address(program, helper, runtime_state)
    if not address:
        return False
    return write_memory_integer(program, helper, address, int(value), 4, big_endian)


def runtime_object_for_address(runtime_state, address):
    address = int(address or 0)
    if address <= 0:
        return None, None
    matches = []
    for base, obj in runtime_state.setdefault("allocations", {}).items():
        size = max(1, int(obj.get("size_bytes") or 0))
        if int(base) <= address < int(base) + size:
            matches.append((int(base), obj))
    if not matches:
        return None, None
    return max(matches, key=lambda item: item[0])


def record_runtime_allocation_event(runtime_state, address, event):
    obj = runtime_state.setdefault("allocations", {}).get(int(address or 0))
    if obj is not None:
        obj["allocation_event"] = dict(event)
        event["object_id"] = int(obj.get("object_id") or 0)
        event["object_state"] = str(obj.get("state") or "")


def release_runtime_object(runtime_state, address, event, release_kind="free"):
    address = int(address or 0)
    event["release_address"] = "0x%X" % address
    if address == 0:
        event["lifetime_result"] = "null_release"
        return {}
    base, obj = runtime_object_for_address(runtime_state, address)
    if obj is None:
        event["lifetime_result"] = "unknown_pointer"
        return {
            "vulnerability": "invalid_free",
            "access_kind": "release",
            "reason": "pointer_is_not_a_modeled_allocation",
            "address": "0x%X" % address,
        }
    object_id = int(obj.get("object_id") or 0)
    event.update(
        {
            "object_id": object_id,
            "object_base_address": "0x%X" % int(base),
            "object_size_bytes": int(obj.get("size_bytes") or 0),
            "object_state_before": str(obj.get("state") or ""),
        }
    )
    if address != int(base):
        event["lifetime_result"] = "interior_pointer_release"
        return {
            "vulnerability": "invalid_free",
            "access_kind": "release",
            "reason": "release_address_is_not_object_base",
            "object_id": object_id,
            "address": "0x%X" % address,
            "object_base_address": "0x%X" % int(base),
            "object_size_bytes": int(obj.get("size_bytes") or 0),
        }
    if str(obj.get("state") or "") == "released":
        event["lifetime_result"] = "double_release"
        return {
            "vulnerability": "double_free",
            "access_kind": "release",
            "reason": "object_already_released",
            "object_id": object_id,
            "address": "0x%X" % address,
            "object_base_address": "0x%X" % int(base),
            "object_size_bytes": int(obj.get("size_bytes") or 0),
            "allocation_event": dict(obj.get("allocation_event") or {}),
            "first_release_event": dict(obj.get("release_event") or {}),
        }
    obj["state"] = "released"
    obj["release_event"] = dict(event)
    obj["release_event"]["release_kind"] = release_kind
    event["lifetime_result"] = "released"
    event["object_state_after"] = "released"
    return {}


def released_runtime_object_for_address(runtime_state, address):
    base, obj = runtime_object_for_address(runtime_state, address)
    if obj is None or str(obj.get("state") or "") != "released":
        return None, None
    return base, obj


def released_object_access(runtime_state, address, access_kind, event=None):
    base, obj = released_runtime_object_for_address(runtime_state, address)
    if obj is None:
        return {}
    violation = {
        "vulnerability": "use_after_free",
        "access_kind": str(access_kind or "access"),
        "reason": "address_resolves_to_released_object",
        "object_id": int(obj.get("object_id") or 0),
        "address": "0x%X" % int(address),
        "object_base_address": "0x%X" % int(base),
        "object_size_bytes": int(obj.get("size_bytes") or 0),
        "allocation_event": dict(obj.get("allocation_event") or {}),
        "release_event": dict(obj.get("release_event") or {}),
    }
    if event:
        violation["access_event"] = dict(event)
    return violation


def transfer_event(target, api, transfer_address, reason):
    event = runtime_event(target, api, "transfer")
    event.update(
        {
            "transfer_address": address_hex(transfer_address),
            "transfer_reason": reason,
            "target_function": target.get("target_function") or function_name(target.get("function")),
        }
    )
    return event


def prepare_callback_return(program, helper, abi, fallthrough_address):
    """Materialize the return link normally created by the skipped call instruction."""
    return_address = parse_int(fallthrough_address, 0)
    if not return_address:
        return False
    abi_name = str(abi.get("abi") or "")
    pointer_size = int(abi.get("pointer_size_bytes") or 0)
    if abi_name in {"x86_64_sysv", "i386"} and pointer_size in (4, 8):
        names = ("RSP", "rsp", "SP", "sp") if abi_name == "x86_64_sysv" else ("ESP", "esp", "SP", "sp")
        stack_pointer = read_register(program, helper, names)
        if stack_pointer is None:
            return False
        next_stack = int(stack_pointer) - pointer_size
        if not write_memory_integer(
            program,
            helper,
            next_stack,
            return_address,
            pointer_size,
            abi.get("endianness") == "big",
        ):
            return False
        return bool(write_register(program, helper, names, next_stack))
    if abi_name == "aarch64":
        return bool(write_register(program, helper, ("x30", "X30", "lr", "LR"), return_address))
    if abi_name == "arm32":
        return bool(write_register(program, helper, ("lr", "LR", "r14", "R14"), return_address))
    return False


def modeled_control_transfer_call(program, helper, instruction, sink_address, process_setup):
    target = external_call_target(program, instruction, sink_address, helper)
    if not target:
        return {}
    api = runtime_api_name(target.get("target_function"))
    abi = dict(process_setup or {})
    if not abi.get("abi"):
        abi.update(program_abi(program))
    values = abi_argument_values(program, helper, abi, 6)

    if api == "start_main":
        if len(values) < 3 or values[0] is None or values[1] is None or values[2] is None:
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_initializer:libc_start_main_args_unavailable"
            return event
        main_address = default_space_address(program, int(values[0]))
        if main_address is None or function_at(program, main_address) is None:
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_initializer:main_address_unavailable"
            return event
        if not write_abi_argument(program, helper, abi, 0, int(values[1])):
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_initializer:argc_register_unavailable"
            return event
        if not write_abi_argument(program, helper, abi, 1, int(values[2])):
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_initializer:argv_register_unavailable"
            return event
        envp_address = parse_int(process_setup.get("envp_address"), 0)
        if envp_address:
            write_abi_argument(program, helper, abi, 2, envp_address)
        event = transfer_event(target, api, main_address, "libc_start_main")
        event.update({"argc": int(values[1]), "argv_address": "0x%X" % int(values[2])})
        return event

    if api == "pthread_create":
        if len(values) < 4 or values[2] is None:
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_callback:pthread_create_args_unavailable"
            return event
        callback_address = default_space_address(program, int(values[2]))
        if callback_address is None or function_at(program, callback_address) is None:
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_callback:start_routine_unavailable"
            return event
        write_abi_argument(program, helper, abi, 0, int(values[3] or 0))
        event = transfer_event(target, api, callback_address, "pthread_start_routine")
        event["callback_arg"] = "0x%X" % int(values[3] or 0)
        return event

    if api == "pthread_once":
        if len(values) < 2 or values[1] is None:
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_callback:pthread_once_args_unavailable"
            return event
        callback_address = default_space_address(program, int(values[1]))
        if callback_address is None or function_at(program, callback_address) is None:
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_callback:init_routine_unavailable"
            return event
        return transfer_event(target, api, callback_address, "pthread_once_init_routine")

    if api == "qsort":
        if len(values) < 4 or values[0] is None or values[1] is None or values[2] is None or values[3] is None:
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_callback:qsort_args_unavailable"
            return event
        base = int(values[0])
        count = max(0, int(values[1]))
        size = max(0, int(values[2]))
        if count > 4096 or size <= 0 or size > 4096:
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_callback:qsort_extent_unbounded"
            return event
        rows = []
        for index in range(count):
            chunk = read_memory_bytes(program, helper, base + index * size, size)
            if chunk is None:
                event = runtime_event(target, api, "unsupported")
                event["reason"] = "unsupported_callback:qsort_table_unavailable"
                return event
            key_width = min(4, size)
            key = bytes_to_int(chunk[:key_width], abi.get("endianness") == "big")
            rows.append((key, index, chunk))
        rows.sort(key=lambda item: (item[0], item[1]))
        for index, (_key, _original, chunk) in enumerate(rows):
            if not write_memory_bytes(program, helper, base + index * size, chunk):
                event = runtime_event(target, api, "unsupported")
                event["reason"] = "unsupported_callback:qsort_table_write_failed"
                return event
        event = runtime_event(target, api)
        event.update({"callback_invoked": False, "concrete_sort": True, "element_count": count, "element_size": size})
        return event

    if api == "bsearch":
        if len(values) < 5 or values[0] is None or values[1] is None or values[2] is None or values[4] is None:
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_callback:bsearch_args_unavailable"
            return event
        count = max(0, int(values[2]))
        size = max(0, int(values[3] or 0))
        if count > 4096 or size <= 0 or size > 4096:
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_callback:bsearch_extent_unbounded"
            return event
        key_width = min(4, size)
        key_bytes = read_memory_bytes(program, helper, int(values[0]), key_width)
        if key_bytes is None:
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_callback:bsearch_key_unavailable"
            return event
        key = bytes_to_int(key_bytes, abi.get("endianness") == "big")
        result = 0
        for index in range(count):
            address = int(values[1]) + index * size
            item = read_memory_bytes(program, helper, address, key_width)
            if item is None:
                event = runtime_event(target, api, "unsupported")
                event["reason"] = "unsupported_callback:bsearch_table_unavailable"
                return event
            if bytes_to_int(item, abi.get("endianness") == "big") == key:
                result = address
                break
        if not write_return_value(program, helper, abi, result):
            event = runtime_event(target, api, "unsupported")
            event["reason"] = "unsupported_callback:bsearch_return_register_unavailable"
            return event
        event = runtime_event(target, api)
        event.update({"callback_invoked": False, "concrete_search": True, "result": "0x%X" % result if result else "0x0"})
        return event

    return {}


def modeled_indirect_call_transfer(program, helper, instruction, sink_address):
    target = resolved_call_target(program, helper, instruction, sink_address, external_only=False)
    if not target or target.get("target_kind") != "indirect":
        return {}
    target_address = address_from(program, target.get("target_address"))
    target_function = function_at(program, target_address) if target_address is not None else None
    if target_address is None or function_is_external_or_thunk(target_function):
        return {}
    target["target_function"] = function_name(target_function)
    target["function"] = target_function
    return transfer_event(target, "indirect_call", target_address, "resolved_indirect_call")


SYSCALL_NAMES = {
    "x86_64_sysv": {
        0: "read",
        1: "write",
        2: "open",
        3: "close",
        9: "mmap",
        12: "brk",
        60: "exit",
        231: "exit_group",
        257: "openat",
    },
    "i386": {
        1: "exit",
        3: "read",
        4: "write",
        5: "open",
        6: "close",
        45: "brk",
        90: "mmap",
        192: "mmap",
        252: "exit_group",
        295: "openat",
    },
    "aarch64": {
        56: "openat",
        57: "close",
        63: "read",
        64: "write",
        93: "exit",
        94: "exit_group",
        214: "brk",
        222: "mmap",
    },
    "arm32": {
        1: "exit",
        3: "read",
        4: "write",
        5: "open",
        6: "close",
        45: "brk",
        90: "mmap",
        192: "mmap",
        248: "exit_group",
        322: "openat",
    },
}


def instruction_is_syscall(instruction):
    mnemonic = instruction_mnemonic(instruction)
    if mnemonic in {"SYSCALL", "SVC", "SWI"}:
        return True
    return mnemonic == "INT" and "0x80" in str(instruction).lower()


def syscall_register_values(program, helper, abi):
    abi_name = str(abi.get("abi") or "")
    if abi_name == "x86_64_sysv":
        number = read_register(program, helper, ("RAX", "rax"))
        args = [
            read_register(program, helper, ("RDI", "rdi")),
            read_register(program, helper, ("RSI", "rsi")),
            read_register(program, helper, ("RDX", "rdx")),
            read_register(program, helper, ("R10", "r10")),
            read_register(program, helper, ("R8", "r8")),
            read_register(program, helper, ("R9", "r9")),
        ]
        return number, args
    if abi_name == "i386":
        number = read_register(program, helper, ("EAX", "eax"))
        args = [
            read_register(program, helper, ("EBX", "ebx")),
            read_register(program, helper, ("ECX", "ecx")),
            read_register(program, helper, ("EDX", "edx")),
            read_register(program, helper, ("ESI", "esi")),
            read_register(program, helper, ("EDI", "edi")),
            read_register(program, helper, ("EBP", "ebp")),
        ]
        return number, args
    if abi_name == "aarch64":
        number = read_register(program, helper, ("x8", "X8"))
        args = [read_register(program, helper, ("x%d" % index, "X%d" % index)) for index in range(6)]
        return number, args
    if abi_name == "arm32":
        number = read_register(program, helper, ("r7", "R7"))
        args = [read_register(program, helper, ("r%d" % index, "R%d" % index)) for index in range(6)]
        return number, args
    return None, []


def syscall_name(abi, number):
    abi_name = str(abi.get("abi") or "")
    table = SYSCALL_NAMES.get(abi_name, {})
    return table.get(int(number), "syscall_%d" % int(number))


def syscall_event_base(instruction, target, name, number, status="modeled"):
    if target:
        event = runtime_event(target, "syscall:%s" % name, status)
    else:
        fallthrough = instruction_fallthrough(instruction)
        event = {
            "status": status,
            "function_model": "syscall:%s" % name,
            "call_address": address_hex(instruction.getAddress()) if instruction is not None else "",
            "target_address": "",
            "target_function": "",
            "fallthrough_address": address_hex(fallthrough) if fallthrough is not None else "",
        }
    event["syscall_number"] = int(number)
    event["syscall_name"] = name
    return event


def modeled_syscall(
    program,
    helper,
    instruction,
    target,
    number,
    syscall_args,
    args,
    process_setup,
    stdin_state,
    file_state,
    runtime_state,
):
    abi = dict(process_setup or {})
    if not abi.get("abi"):
        abi.update(program_abi(program))
    if number is None:
        return {}
    name = syscall_name(abi, number)
    values = list(syscall_args or [])

    def unsupported(reason):
        event = syscall_event_base(instruction, target, name, number, "unsupported")
        event["reason"] = "unsupported_syscall:%s" % reason
        return event

    def ret(value, event):
        if not write_return_value(program, helper, abi, int(value or 0)):
            return unsupported("%s_return_register_unavailable" % name)
        event["return_value"] = int(value or 0)
        return event

    if name in {"exit", "exit_group"}:
        event = syscall_event_base(instruction, target, name, number, "terminated")
        event["reason"] = "process_terminated:%s" % name
        return event

    if name == "write":
        if len(values) < 3 or values[2] is None:
            return unsupported("write_args_unavailable")
        event = syscall_event_base(instruction, target, name, number)
        event.update({"fd": int(values[0] or 0), "written_bytes": max(0, int(values[2]))})
        return ret(max(0, int(values[2])), event)

    if name == "close":
        if len(values) < 1 or values[0] is None:
            return unsupported("close_args_unavailable")
        handle = int(values[0])
        file_state.setdefault("descriptors", {}).pop(handle, None)
        event = syscall_event_base(instruction, target, name, number)
        event["fd"] = handle
        return ret(0, event)

    if name in {"brk", "mmap"}:
        event = syscall_event_base(instruction, target, name, number)
        if name == "brk":
            requested = int(values[0] or 0) if values else 0
            current = int(runtime_state.get("program_break") or 0x71000000)
            if requested:
                runtime_state["program_break"] = requested
                current = requested
            event["program_break"] = "0x%X" % current
            return ret(current, event)
        if len(values) < 2 or values[1] is None:
            return unsupported("mmap_args_unavailable")
        size = max(1, int(values[1]))
        address = allocate_runtime_memory(program, helper, runtime_state, size, zero_fill=True)
        if not address:
            return unsupported("mmap_allocation_failed")
        event.update({"allocation_address": "0x%X" % address, "allocation_size_bytes": size})
        record_runtime_allocation_event(runtime_state, address, event)
        return ret(address, event)

    if name in {"open", "openat"}:
        path_index = 1 if name == "openat" else 0
        if len(values) <= path_index or values[path_index] is None:
            return unsupported("%s_path_arg_unavailable" % name)
        file_state = ensure_file_state(args, file_state)
        if file_state is None:
            return unsupported("invalid_concrete_input_hex")
        path = read_memory_c_string(program, helper, int(values[path_index]))
        if path is None:
            return unsupported("%s_path_unavailable" % name)
        event = syscall_event_base(instruction, target, name, number)
        event["path"] = path
        if not file_path_matches(path, str(file_state.get("file_name") or "concolic_input")):
            return ret(-2, event)
        handle = int(file_state.get("next_fd") or 3)
        file_state["next_fd"] = handle + 1
        file_state.setdefault("descriptors", {})[handle] = {"offset": 0, "path": path}
        event.update({"fd": handle, "file_name": str(file_state.get("file_name") or "concolic_input")})
        return ret(handle, event)

    if name == "read":
        if len(values) < 3 or values[0] is None or values[1] is None or values[2] is None:
            return unsupported("read_args_unavailable")
        fd = int(values[0])
        buffer_address = int(values[1])
        requested = max(0, int(values[2]))
        event = syscall_event_base(instruction, target, name, number)
        event.update({"fd": fd, "buffer_address": "0x%X" % buffer_address, "requested_bytes": requested})
        if fd == 0 and str(args.get("input_model") or "") in {"stdin", "argv_file_stdin"}:
            input_bytes = stdin_state.get("bytes")
            if input_bytes is None:
                input_bytes = bytes_from_hex(args.get("stdin_input_hex") or args.get("concrete_input_hex"))
                if input_bytes is None:
                    return unsupported("invalid_concrete_input_hex")
                stdin_state["bytes"] = list(input_bytes)
            offset = int(stdin_state.get("offset") or 0)
            chunk = list(stdin_state.get("bytes") or [])[offset : offset + requested]
            if not write_memory_bytes(program, helper, buffer_address, chunk):
                return unsupported("stdin_memory_write_failed")
            stdin_state["offset"] = offset + len(chunk)
            process_setup["stdin_consumed_bytes"] = stdin_state["offset"]
            event.update({"input_model": "stdin", "written_bytes": len(chunk), "input_offset_before": offset, "input_offset_after": stdin_state["offset"]})
            return ret(len(chunk), event)
        if str(args.get("input_model") or "") in {"file", "argv_file_stdin"}:
            file_state = ensure_file_state(args, file_state)
            if file_state is None:
                return unsupported("invalid_concrete_input_hex")
            result = read_file_chunk(file_state, file_state.setdefault("descriptors", {}), fd, requested)
            if result is None:
                return unsupported("read_fd_unmodeled")
            offset, chunk = result
            if not write_memory_bytes(program, helper, buffer_address, chunk):
                return unsupported("file_memory_write_failed")
            event.update({"input_model": "file", "written_bytes": len(chunk), "input_offset_before": offset, "input_offset_after": offset + len(chunk)})
            process_setup["file_consumed_bytes"] = max(parse_int(process_setup.get("file_consumed_bytes"), 0), offset + len(chunk))
            return ret(len(chunk), event)
        return unsupported("read_fd_unmodeled")

    return unsupported("number_%d" % int(number))


def modeled_syscall_instruction(program, helper, instruction, args, process_setup, stdin_state, file_state, runtime_state):
    if not instruction_is_syscall(instruction):
        return {}
    abi = dict(process_setup or {})
    if not abi.get("abi"):
        abi.update(program_abi(program))
    number, syscall_args = syscall_register_values(program, helper, abi)
    return modeled_syscall(
        program,
        helper,
        instruction,
        {},
        number,
        syscall_args,
        args,
        process_setup,
        stdin_state,
        file_state,
        runtime_state,
    )


def modeled_syscall_wrapper_call(program, helper, instruction, sink_address, args, process_setup, stdin_state, file_state, runtime_state):
    target = external_call_target(program, instruction, sink_address, helper)
    if not target or runtime_api_name(target.get("target_function")) != "syscall":
        return {}
    abi = dict(process_setup or {})
    if not abi.get("abi"):
        abi.update(program_abi(program))
    values = abi_argument_values(program, helper, abi, 7)
    if not values or values[0] is None:
        event = runtime_event(target, "syscall:unknown", "unsupported")
        event["reason"] = "unsupported_syscall:wrapper_number_unavailable"
        return event
    return modeled_syscall(
        program,
        helper,
        instruction,
        target,
        int(values[0]),
        values[1:],
        args,
        process_setup,
        stdin_state,
        file_state,
        runtime_state,
    )


def modeled_runtime_call(program, helper, instruction, sink_address, process_setup, runtime_state, proof_args=None):
    target = external_call_target(program, instruction, sink_address, helper)
    if not target:
        return {}
    api = runtime_api_name(target.get("target_function"))
    abi = dict(process_setup or {})
    if not abi.get("abi"):
        abi.update(program_abi(program))
    values = abi_argument_values(program, helper, abi, 6)

    if str((proof_args or {}).get("vulnerability_type") or "") == "use_after_free" and api != "free":
        for index, value in enumerate(values):
            if value is None:
                continue
            violation = released_object_access(runtime_state, int(value), "call_argument")
            if not violation:
                continue
            event = runtime_event(target, api, "lifetime_violation")
            event.update({"argument_index": index, "argument_address": "0x%X" % int(value)})
            violation["access_event"] = dict(event)
            event["lifetime_violation"] = violation
            return event

    def missing(reason):
        event = runtime_event(target, api, "unsupported")
        event["reason"] = "unsupported_runtime_call:%s" % reason
        return event

    def ret(value):
        if not write_return_value(program, helper, abi, int(value or 0)):
            return missing("%s_return_register_unavailable" % api)
        return None

    if api == "errno_location":
        address = runtime_errno_address(program, helper, runtime_state)
        if not address:
            return missing("errno_location_allocation_failed")
        error = ret(address)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": "0x%X" % address, "errno_address": "0x%X" % address})
        return event

    checked_memory_apis = {
        "memcpy_chk": "memcpy",
        "memmove_chk": "memmove",
        "memset_chk": "memset",
    }
    checked_base = checked_memory_apis.get(api)
    checked_api = api if checked_base else ""
    if checked_base:
        if len(values) < 4 or any(values[index] is None for index in range(4)):
            return missing("%s_args_unavailable" % api)
        attempted_size = max(0, int(values[2]))
        object_size = max(0, int(values[3]))
        if attempted_size > object_size:
            event = runtime_event(target, api, "terminated")
            event.update(
                {
                    "reason": "fortified_bound_exceeded",
                    "attempted_write_bytes": attempted_size,
                    "object_size_bytes": object_size,
                    "written_bytes": 0,
                }
            )
            return event
        api = checked_base

    if api in {"getenv", "secure_getenv"}:
        error = ret(0)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": "0x0", "environment_model": "absent"})
        return event

    if api in {"strchr", "strrchr"}:
        if len(values) < 2 or values[0] is None or values[1] is None:
            return missing("%s_args_unavailable" % api)
        source_address = int(values[0])
        source = read_memory_c_bytes(program, helper, source_address)
        if source is None:
            return missing("%s_source_unavailable" % api)
        needle = int(values[1]) & 0xFF
        result = 0
        if needle == 0:
            result = source_address + len(source)
        elif api == "strchr":
            for index, value in enumerate(source):
                if int(value) == needle:
                    result = source_address + index
                    break
        else:
            for index in range(len(source) - 1, -1, -1):
                if int(source[index]) == needle:
                    result = source_address + index
                    break
        error = ret(result)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update(
            {
                "result": "0x%X" % result if result else "0x0",
                "source_address": "0x%X" % source_address,
                "needle": needle,
                "source_size_bytes": len(source),
            }
        )
        return event

    if api == "strpbrk":
        if len(values) < 2 or values[0] is None or values[1] is None:
            return missing("strpbrk_args_unavailable")
        source_address = int(values[0])
        source = read_memory_c_bytes(program, helper, source_address)
        accepted = read_memory_c_bytes(program, helper, int(values[1]))
        if source is None or accepted is None:
            return missing("strpbrk_source_unavailable")
        accepted_set = set(int(value) for value in accepted)
        result = 0
        for index, value in enumerate(source):
            if int(value) in accepted_set:
                result = source_address + index
                break
        error = ret(result)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": "0x%X" % result if result else "0x0", "source_address": "0x%X" % source_address})
        return event

    if api in {"tolower", "toupper"}:
        if not values or values[0] is None:
            return missing("%s_arg_unavailable" % api)
        value = int(values[0]) & 0xFF
        if api == "tolower" and ord("A") <= value <= ord("Z"):
            value += ord("a") - ord("A")
        elif api == "toupper" and ord("a") <= value <= ord("z"):
            value -= ord("a") - ord("A")
        error = ret(value)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event["result"] = value
        return event

    if api in {"getopt", "getopt_long", "getopt_long_only"}:
        if len(values) < 2 or values[0] is None or values[1] is None:
            return missing("%s_args_unavailable" % api)
        argc = max(0, int(values[0]))
        argv = int(values[1])
        pointer_size = int(abi.get("pointer_size_bytes") or 0)
        if pointer_size not in (4, 8):
            return missing("%s_pointer_size_unavailable" % api)
        big_endian = abi.get("endianness") == "big"
        optind = 1
        optind_address = global_symbol_address(program, ("optind", "__optind"))
        if optind_address is not None:
            current_optind = read_memory_integer(program, helper, address_offset(optind_address), 4, big_endian)
            if current_optind is not None and current_optind > 0:
                optind = int(current_optind)
        pending_key = "%X:%d" % (argv, optind)
        pending_options = runtime_state.setdefault("getopt_pending", {})
        pending = pending_options.get(pending_key)
        option_bytes = None
        option_pointer = None
        option_position = 1
        if isinstance(pending, dict):
            option_bytes = pending.get("option_bytes")
            option_pointer = pending.get("option_pointer")
            option_position = int(pending.get("next_position") or 1)
        else:
            while optind < argc:
                arg_pointer = read_memory_integer(program, helper, argv + optind * pointer_size, pointer_size, big_endian)
                if arg_pointer is None:
                    return missing("%s_argv_unavailable" % api)
                arg_bytes = read_memory_c_bytes(program, helper, arg_pointer)
                if arg_bytes is None:
                    return missing("%s_argv_string_unavailable" % api)
                if len(arg_bytes) == 2 and arg_bytes[0] == ord("-") and arg_bytes[1] == ord("-"):
                    optind += 1
                    break
                if len(arg_bytes) < 2 or arg_bytes[0] != ord("-"):
                    break
                option_bytes = arg_bytes
                option_pointer = arg_pointer
                break
        if option_bytes is not None:
            if option_position >= len(option_bytes) or option_bytes[1] == ord("-") or len(values) < 3 or values[2] is None:
                return missing("%s_option_parsing_unsupported" % api)
            optstring_bytes = read_memory_c_bytes(program, helper, int(values[2]), 4096)
            if optstring_bytes is None:
                return missing("%s_option_parsing_unsupported" % api)
            flag = int(option_bytes[option_position])
            option_index = -1
            for index, value in enumerate(optstring_bytes):
                if int(value) == flag:
                    option_index = index
                    break
            requires_argument = (
                option_index >= 0
                and option_index + 1 < len(optstring_bytes)
                and int(optstring_bytes[option_index + 1]) == ord(":")
                and not (option_index + 2 < len(optstring_bytes) and int(optstring_bytes[option_index + 2]) == ord(":"))
            )
            optarg_address = global_symbol_address(program, ("optarg", "__optarg"))
            optarg_status = "not_written"
            optarg_pointer = 0
            optarg_bytes = []
            if requires_argument:
                if option_position != len(option_bytes) - 1 or optind + 1 >= argc:
                    return missing("%s_option_parsing_unsupported" % api)
                optarg_pointer = read_memory_integer(program, helper, argv + (optind + 1) * pointer_size, pointer_size, big_endian)
                if optarg_pointer is None:
                    return missing("%s_argv_unavailable" % api)
                optarg_bytes = read_memory_c_bytes(program, helper, optarg_pointer)
                if optarg_bytes is None:
                    return missing("%s_argv_string_unavailable" % api)
                if optarg_address is None:
                    return missing("%s_optarg_symbol_unavailable" % api)
                optarg_offset = address_offset(optarg_address)
                if optarg_offset is not None and write_memory_integer(program, helper, optarg_offset, optarg_pointer, pointer_size, big_endian):
                    optarg_status = "written"
                else:
                    optarg_status = "write_failed"
                pending_options.pop(pending_key, None)
                optind += 2
            else:
                if optarg_address is not None:
                    optarg_offset = address_offset(optarg_address)
                    if optarg_offset is not None and write_memory_integer(program, helper, optarg_offset, 0, pointer_size, big_endian):
                        optarg_status = "cleared"
                next_position = option_position + 1
                if next_position < len(option_bytes):
                    pending_options[pending_key] = {
                        "option_bytes": list(option_bytes),
                        "option_pointer": option_pointer,
                        "next_position": next_position,
                    }
                else:
                    pending_options.pop(pending_key, None)
                    optind += 1
            optind_status = "not_written"
            if optind_address is not None:
                optind_offset = address_offset(optind_address)
                if optind_offset is not None and write_memory_integer(program, helper, optind_offset, optind, 4, big_endian):
                    optind_status = "written"
                else:
                    optind_status = "write_failed"
            error = ret(flag)
            if error is not None:
                return error
            event = runtime_event(target, api)
            event.update(
                {
                    "result": flag,
                    "option": chr(flag),
                    "option_address": "0x%X" % int(option_pointer),
                    "optarg_address": "0x%X" % int(optarg_pointer) if optarg_pointer else "0x0",
                    "optarg_size_bytes": len(optarg_bytes),
                    "optarg_write_status": optarg_status,
                    "short_option_group_pending": bool(pending_options.get(pending_key)),
                    "optind": optind,
                    "optind_write_status": optind_status,
                }
            )
            return event
        optind_status = "not_written"
        if optind_address is not None:
            optind_offset = address_offset(optind_address)
            if optind_offset is not None and write_memory_integer(program, helper, optind_offset, optind, 4, big_endian):
                optind_status = "written"
            else:
                optind_status = "write_failed"
        error = ret(-1)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": -1, "optind": optind, "optind_write_status": optind_status})
        return event

    if api in {"access", "euidaccess", "eaccess"}:
        if len(values) < 1 or values[0] is None:
            return missing("%s_args_unavailable" % api)
        path_match = process_input_path_match(program, helper, int(values[0]), process_setup)
        if not path_match:
            return missing("%s_path_not_modeled_process_input" % api)
        error = ret(0)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update(path_match)
        event.update({"result": 0})
        return event

    if api in {"opendir", "fdopendir"}:
        if api == "opendir":
            if len(values) < 1 or values[0] is None:
                return missing("opendir_args_unavailable")
            path_match = process_input_path_match(program, helper, int(values[0]), process_setup)
            if not path_match:
                return missing("opendir_path_not_modeled_process_input")
        else:
            if len(values) < 1 or values[0] is None:
                return missing("fdopendir_args_unavailable")
            path_match = runtime_state.setdefault("descriptors", {}).get(int(values[0]))
            if not path_match:
                return missing("fdopendir_fd_not_modeled_process_input")
        entry, reason = directory_entry_bytes(process_setup)
        if entry is None:
            return missing("opendir_%s" % reason)
        handle = allocate_runtime_memory(program, helper, runtime_state, 32, zero_fill=True)
        if not handle:
            return missing("opendir_handle_allocation_failed")
        d_name_offset = dirent_name_offset(process_setup)
        if d_name_offset <= 0:
            return missing("opendir_dirent_layout_unsupported_abi")
        dirent_address = allocate_runtime_memory(program, helper, runtime_state, d_name_offset + len(entry) + 1, zero_fill=True)
        if not dirent_address:
            return missing("opendir_dirent_allocation_failed")
        runtime_state.setdefault("directories", {})[handle] = {
            "entries": [entry],
            "index": 0,
            "dirent_address": dirent_address,
            "d_name_offset": d_name_offset,
            "path": dict(path_match),
        }
        error = ret(handle)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update(path_match)
        event.update(
            {
                "result": "0x%X" % handle,
                "directory_handle": "0x%X" % handle,
                "dirent_address": "0x%X" % dirent_address,
                "directory_entry_size_bytes": len(entry),
                "dirent_d_name_offset_bytes": d_name_offset,
            }
        )
        return event

    if api in {"readdir", "readdir64"}:
        if len(values) < 1 or values[0] is None:
            return missing("%s_args_unavailable" % api)
        handle = int(values[0])
        directory = runtime_state.setdefault("directories", {}).get(handle)
        if not directory:
            return missing("%s_directory_not_modeled" % api)
        index = int(directory.get("index") or 0)
        entries = list(directory.get("entries") or [])
        if index >= len(entries):
            error = ret(0)
            if error is not None:
                return error
            event = runtime_event(target, api)
            event.update({"result": "0x0", "directory_handle": "0x%X" % handle, "end_of_directory": True})
            return event
        entry = list(entries[index])
        directory["index"] = index + 1
        dirent_address = int(directory.get("dirent_address") or 0)
        d_name_offset = int(directory.get("d_name_offset") or 0)
        if not dirent_address or d_name_offset <= 0:
            return missing("%s_dirent_state_unavailable" % api)
        if not write_memory_bytes(program, helper, dirent_address, [0] * (d_name_offset + len(entry) + 1)):
            return missing("%s_dirent_clear_failed" % api)
        if not write_memory_bytes(program, helper, dirent_address + d_name_offset, entry + [0]):
            return missing("%s_d_name_write_failed" % api)
        error = ret(dirent_address)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update(
            {
                "result": "0x%X" % dirent_address,
                "directory_handle": "0x%X" % handle,
                "dirent_address": "0x%X" % dirent_address,
                "d_name_address": "0x%X" % (dirent_address + d_name_offset),
                "directory_entry_size_bytes": len(entry),
                "entry_index": index,
            }
        )
        return event

    if api == "closedir":
        if len(values) >= 1 and values[0] is not None:
            runtime_state.setdefault("directories", {}).pop(int(values[0]), None)
        error = ret(0)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": 0})
        return event

    if api in {"fstatat", "fstatat64", "newfstatat"} and str(process_setup.get("input_model") or "") == "stdin":
        if len(values) < 3 or values[1] is None:
            return missing("%s_args_unavailable" % api)
        path = read_memory_c_string(program, helper, int(values[1]))
        if path is None:
            return missing("%s_path_unavailable" % api)
        if not set_runtime_errno(program, helper, runtime_state, 2, abi.get("endianness") == "big"):
            return missing("%s_errno_write_failed" % api)
        error = ret(-1)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": -1, "path": path, "filesystem_model": "unconfigured_path_absent", "errno": 2})
        return event

    if api in {"stat", "stat64", "lstat", "lstat64", "__xstat", "__xstat64", "__lxstat", "__lxstat64"}:
        versioned = api.startswith("__")
        path_index = 1 if versioned else 0
        buffer_index = 2 if versioned else 1
        if len(values) <= buffer_index or values[path_index] is None or values[buffer_index] is None:
            return missing("%s_args_unavailable" % api)
        path_match = process_input_path_match(program, helper, int(values[path_index]), process_setup)
        if not path_match:
            if str(process_setup.get("input_model") or "") == "stdin":
                path = read_memory_c_string(program, helper, int(values[path_index]))
                if path is None:
                    return missing("%s_path_unavailable" % api)
                if not set_runtime_errno(program, helper, runtime_state, 2, abi.get("endianness") == "big"):
                    return missing("%s_errno_write_failed" % api)
                error = ret(-1)
                if error is not None:
                    return error
                event = runtime_event(target, api)
                event.update({"result": -1, "path": path, "filesystem_model": "unconfigured_path_absent", "errno": 2})
                return event
            return missing("%s_path_not_modeled_process_input" % api)
        ok, reason = write_modeled_stat_buffer(program, helper, int(values[buffer_index]), process_setup)
        if not ok:
            return missing("%s_%s" % (api, reason))
        error = ret(0)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update(path_match)
        event.update({"result": 0, "stat_buffer_address": "0x%X" % int(values[buffer_index])})
        return event

    if str(process_setup.get("input_model") or "") == "stdin" and api == "fileno":
        error = ret(0)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": 0, "fd": 0, "stream_role": "stdin"})
        return event

    if str(process_setup.get("input_model") or "") == "stdin" and api in {"fstat", "fstat64"}:
        if len(values) < 2 or values[0] is None or values[1] is None:
            return missing("%s_args_unavailable" % api)
        if int(values[0]) != 0:
            return missing("%s_fd_not_modeled_stdin" % api)
        ok, reason = write_modeled_stat_buffer(program, helper, int(values[1]), process_setup)
        if not ok:
            return missing("%s_%s" % (api, reason))
        error = ret(0)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": 0, "fd": 0, "stat_buffer_address": "0x%X" % int(values[1])})
        return event

    if str(process_setup.get("input_model") or "") == "stdin" and api in {"ftell", "ftello", "ftello64"}:
        result = max(0, parse_int(process_setup.get("stdin_consumed_bytes"), 0))
        error = ret(result)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": result, "stream_role": "stdin"})
        return event

    if api in {"openat", "openat64"} and str(process_setup.get("input_model") or "") == "stdin":
        if len(values) < 3 or values[1] is None or values[2] is None:
            return missing("%s_args_unavailable" % api)
        path = read_memory_c_string(program, helper, int(values[1]))
        if path is None:
            return missing("%s_path_unavailable" % api)
        flags = int(values[2])
        if flags & 0x40:
            fd = next_runtime_fd(runtime_state, {"path": path, "filesystem_model": "created_sandbox_file"})
            result = fd
            file_model = "created_sandbox_file"
        else:
            if not set_runtime_errno(program, helper, runtime_state, 2, abi.get("endianness") == "big"):
                return missing("%s_errno_write_failed" % api)
            result = -1
            file_model = "unconfigured_path_absent"
        error = ret(result)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": result, "path": path, "flags": flags, "filesystem_model": file_model})
        return event

    if api in {"open", "open64", "creat"}:
        if len(values) < 1 or values[0] is None:
            return missing("%s_args_unavailable" % api)
        path_match = process_input_path_match(program, helper, int(values[0]), process_setup)
        if not path_match:
            if str(process_setup.get("input_model") or "") == "stdin":
                path = read_memory_c_string(program, helper, int(values[0]))
                if path is None:
                    return missing("%s_path_unavailable" % api)
                if not set_runtime_errno(program, helper, runtime_state, 2, abi.get("endianness") == "big"):
                    return missing("%s_errno_write_failed" % api)
                error = ret(-1)
                if error is not None:
                    return error
                event = runtime_event(target, api)
                event.update({"result": -1, "path": path, "filesystem_model": "unconfigured_path_absent", "errno": 2})
                return event
            if str(process_setup.get("input_model") or "") == "env_file":
                error = ret(-1)
                if error is not None:
                    return error
                event = runtime_event(target, api)
                event.update({"result": -1, "filesystem_model": "absent"})
                return event
            if str(process_setup.get("input_model") or "") not in {"file", "argv_file_stdin"}:
                return missing("%s_path_not_modeled_process_input" % api)
            path = read_memory_c_string(program, helper, int(values[0]))
            if path is None:
                return missing("%s_path_unavailable" % api)
            path_match = {"path": path, "input_model": "runtime_file"}
        fd = next_runtime_fd(runtime_state, path_match)
        error = ret(fd)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update(path_match)
        event.update({"result": fd, "fd": fd})
        return event

    if api in {"fopen", "fopen64"}:
        if len(values) < 1 or values[0] is None:
            return missing("%s_args_unavailable" % api)
        path_match = process_input_path_match(program, helper, int(values[0]), process_setup)
        if not path_match:
            if str(process_setup.get("input_model") or "") == "env_file":
                error = ret(0)
                if error is not None:
                    return error
                event = runtime_event(target, api)
                event.update({"result": "0x0", "filesystem_model": "absent"})
                return event
            if str(process_setup.get("input_model") or "") not in {"file", "argv_file_stdin"}:
                return missing("%s_path_not_modeled_process_input" % api)
            path = read_memory_c_string(program, helper, int(values[0]))
            if path is None:
                return missing("%s_path_unavailable" % api)
            path_match = {"path": path, "input_model": "runtime_file"}
        stream = allocate_runtime_memory(program, helper, runtime_state, 32, zero_fill=True)
        if not stream:
            return missing("%s_stream_allocation_failed" % api)
        runtime_state.setdefault("streams", {})[stream] = dict(path_match)
        error = ret(stream)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update(path_match)
        event.update({"result": "0x%X" % stream, "stream": "0x%X" % stream})
        return event

    if api == "fdopen" and len(values) >= 1 and values[0] is not None:
        fd = int(values[0])
        descriptor = runtime_state.setdefault("descriptors", {}).get(fd)
        if descriptor is None:
            return missing("fdopen_fd_unavailable")
        stream = allocate_runtime_memory(program, helper, runtime_state, 32, zero_fill=True)
        if not stream:
            return missing("fdopen_stream_allocation_failed")
        runtime_state.setdefault("streams", {})[stream] = {**dict(descriptor), "fd": fd, "offset": 0}
        error = ret(stream)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": "0x%X" % stream, "stream": "0x%X" % stream, "fd": fd})
        return event

    if api == "fwrite" and len(values) >= 3 and values[1] is not None and values[2] is not None:
        item_size = max(0, int(values[1]))
        item_count = max(0, int(values[2]))
        error = ret(item_count)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": item_count, "written_bytes": item_size * item_count})
        return event

    if api == "fclose" and len(values) >= 1 and values[0] is not None:
        stream = int(values[0])
        runtime_state.setdefault("streams", {}).pop(stream, None)
        error = ret(0)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": 0, "stream": "0x%X" % stream})
        return event

    if api in {"ferror", "feof", "feof_unlocked", "clearerr"} and len(values) >= 1 and values[0] is not None:
        stream = int(values[0])
        if stream not in runtime_state.setdefault("streams", {}):
            return {}
        error = ret(0)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": 0, "stream": "0x%X" % stream})
        return event

    if api == "unlinkat":
        error = ret(0)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event["result"] = 0
        return event

    if api == "realpath":
        if len(values) < 2 or values[0] is None:
            return missing("realpath_args_unavailable")
        path_match = process_input_path_match(program, helper, int(values[0]), process_setup)
        if not path_match:
            return missing("realpath_path_not_modeled_process_input")
        source_bytes = read_memory_c_bytes(program, helper, int(values[0]))
        if source_bytes is None:
            return missing("realpath_source_unavailable")
        dest = int(values[1] or 0)
        if dest == 0:
            dest = allocate_runtime_memory(program, helper, runtime_state, len(source_bytes) + 1)
        if not dest or not write_memory_bytes(program, helper, dest, source_bytes + [0]):
            return missing("realpath_destination_write_failed")
        error = ret(dest)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update(path_match)
        event.update({"result": "0x%X" % dest, "resolved_path_address": "0x%X" % dest})
        return event

    if api == "basename":
        if len(values) < 1 or values[0] is None:
            return missing("basename_args_unavailable")
        path_match = process_input_path_match(program, helper, int(values[0]), process_setup)
        if not path_match:
            return missing("basename_path_not_modeled_process_input")
        source_bytes = read_memory_c_bytes(program, helper, int(values[0]))
        if source_bytes is None:
            return missing("basename_source_unavailable")
        basename_offset = 0
        for index, value in enumerate(source_bytes):
            if value == ord("/"):
                basename_offset = index + 1
        result_address = int(values[0]) + basename_offset
        error = ret(result_address)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update(path_match)
        event.update({"result": "0x%X" % result_address, "basename_offset": basename_offset})
        return event

    if api in {"exit", "abort", "stack_chk_fail", "fortify_fail"}:
        event = runtime_event(target, api, "terminated")
        event["reason"] = "process_terminated:%s" % api
        return event

    if api in {"malloc", "calloc", "realloc"}:
        old_address = 0
        if api == "malloc":
            if len(values) < 1 or values[0] is None:
                return missing("malloc_args_unavailable")
            size = int(values[0])
            address = allocate_runtime_memory(program, helper, runtime_state, size)
        elif api == "calloc":
            if len(values) < 2 or values[0] is None or values[1] is None:
                return missing("calloc_args_unavailable")
            size = max(0, int(values[0])) * max(0, int(values[1]))
            address = allocate_runtime_memory(program, helper, runtime_state, size, zero_fill=True)
        else:
            if len(values) < 2 or values[0] is None or values[1] is None:
                return missing("realloc_args_unavailable")
            old_address = int(values[0])
            size = int(values[1])
            address = allocate_runtime_memory(program, helper, runtime_state, size)
            old = runtime_state.setdefault("allocations", {}).get(old_address)
            if old is not None and address:
                copied = min(int(old.get("size_bytes") or 0), max(0, size))
                chunk = read_memory_bytes(program, helper, old_address, copied)
                if chunk is not None:
                    write_memory_bytes(program, helper, address, chunk)
        if not address:
            return missing("%s_allocation_failed" % api)
        error = ret(address)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"allocation_address": "0x%X" % address, "allocation_size_bytes": max(1, int(size or 0))})
        record_runtime_allocation_event(runtime_state, address, event)
        if api == "realloc" and old_address:
            release_event = runtime_event(target, "realloc_release")
            violation = release_runtime_object(runtime_state, old_address, release_event, "realloc")
            event["reallocated_from"] = release_event
            if violation:
                event["status"] = "lifetime_violation"
                event["lifetime_violation"] = violation
        return event

    if api == "free":
        event = runtime_event(target, api)
        if len(values) < 1 or values[0] is None:
            return missing("free_arg_unavailable")
        violation = release_runtime_object(runtime_state, int(values[0]), event)
        if violation:
            event["status"] = "lifetime_violation"
            event["lifetime_violation"] = violation
        return event

    if api in {"strlen", "strnlen"}:
        needed = 2 if api == "strnlen" else 1
        if len(values) < needed or values[0] is None or (needed == 2 and values[1] is None):
            return missing("%s_args_unavailable" % api)
        max_len = int(values[1]) if api == "strnlen" else 65536
        data = read_memory_c_bytes(program, helper, int(values[0]), max_len, allow_prefix=(api == "strnlen"))
        if data is None:
            return missing("%s_source_unavailable" % api)
        length = min(len(data), max_len)
        error = ret(length)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"source_address": "0x%X" % int(values[0]), "result": length})
        return event

    if api in {"strcmp", "strncmp", "memcmp"}:
        needed = 3 if api in {"strncmp", "memcmp"} else 2
        if len(values) < needed or values[0] is None or values[1] is None or (needed == 3 and values[2] is None):
            return missing("%s_args_unavailable" % api)
        if api == "memcmp":
            size = max(0, int(values[2]))
            left = read_memory_bytes(program, helper, int(values[0]), size)
            right = read_memory_bytes(program, helper, int(values[1]), size)
            if left is None or right is None:
                return missing("memcmp_source_unavailable")
            result = 0
            for index in range(size):
                if left[index] != right[index]:
                    result = -1 if left[index] < right[index] else 1
                    break
        else:
            max_len = int(values[2]) if api == "strncmp" else 65536
            left = read_memory_c_bytes(program, helper, int(values[0]), max_len, allow_prefix=(api == "strncmp"))
            right = read_memory_c_bytes(program, helper, int(values[1]), max_len, allow_prefix=(api == "strncmp"))
            if left is None or right is None:
                return missing("%s_source_unavailable" % api)
            result = compare_c_byte_lists(left[:max_len], right[:max_len])
        error = ret(result)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event["result"] = result
        return event

    if api in {"memcpy", "memmove", "memzero", "memset"}:
        if api == "memzero":
            if len(values) < 2 or values[0] is None or values[1] is None:
                return missing("memzero_args_unavailable")
            dest = int(values[0])
            size = max(0, int(values[1]))
            chunk = [0] * size
        elif api == "memset":
            if len(values) < 3 or values[0] is None or values[1] is None or values[2] is None:
                return missing("memset_args_unavailable")
            dest = int(values[0])
            size = max(0, int(values[2]))
            chunk = [int(values[1]) & 0xFF] * size
        else:
            if len(values) < 3 or values[0] is None or values[1] is None or values[2] is None:
                return missing("%s_args_unavailable" % api)
            dest = int(values[0])
            source = int(values[1])
            size = max(0, int(values[2]))
            chunk = read_memory_bytes(program, helper, source, size)
            if chunk is None:
                return missing("%s_source_unavailable" % api)
        if not write_memory_bytes(program, helper, dest, chunk):
            return missing("%s_memory_write_failed" % api)
        error = ret(dest)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"destination_address": "0x%X" % dest, "written_bytes": len(chunk)})
        if checked_api:
            event["checked_function_model"] = checked_api
            event["object_size_bytes"] = max(0, int(values[3]))
        if api in {"memcpy", "memmove"}:
            event.update({"source_address": "0x%X" % source, "read_bytes": len(chunk)})
        return event

    if api in {"strcpy_chk", "strcat_chk"}:
        if len(values) < 3 or values[0] is None or values[1] is None or values[2] is None:
            return missing("%s_args_unavailable" % api)
        dest = int(values[0])
        source = int(values[1])
        object_size = max(0, int(values[2]))
        source_bytes = read_memory_c_bytes(program, helper, source)
        if source_bytes is None:
            return missing("%s_source_unavailable" % api)
        write_address = dest
        existing_size = 0
        if api == "strcat_chk":
            existing = read_memory_c_bytes(program, helper, dest)
            if existing is None:
                return missing("%s_destination_unavailable" % api)
            existing_size = len(existing)
            write_address = dest + existing_size
        attempted_size = existing_size + len(source_bytes) + 1
        if attempted_size > object_size:
            event = runtime_event(target, api, "terminated")
            event.update(
                {
                    "reason": "fortified_bound_exceeded",
                    "destination_address": "0x%X" % dest,
                    "source_address": "0x%X" % source,
                    "attempted_write_bytes": attempted_size,
                    "object_size_bytes": object_size,
                    "written_bytes": 0,
                }
            )
            return event
        chunk = source_bytes + [0]
        if not write_memory_bytes(program, helper, write_address, chunk):
            return missing("%s_memory_write_failed" % api)
        error = ret(dest)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update(
            {
                "destination_address": "0x%X" % dest,
                "write_address": "0x%X" % write_address,
                "source_address": "0x%X" % source,
                "written_bytes": len(chunk),
                "read_bytes": len(source_bytes),
                "object_size_bytes": object_size,
                "nul_terminated": True,
            }
        )
        return event

    if api in {"strcpy", "strcpy_end", "strncpy", "strcat", "strncat"}:
        needed = 3 if api in {"strncpy", "strncat"} else 2
        if len(values) < needed or values[0] is None or values[1] is None or (needed == 3 and values[2] is None):
            return missing("%s_args_unavailable" % api)
        dest = int(values[0])
        source = int(values[1])
        source_bytes = read_memory_c_bytes(
            program,
            helper,
            source,
            max(0, int(values[2])) if api in {"strncpy", "strncat"} else 65536,
            allow_prefix=api in {"strncpy", "strncat"},
        )
        if source_bytes is None:
            return missing("%s_source_unavailable" % api)
        write_address = dest
        if api in {"strcat", "strncat"}:
            existing = read_memory_c_bytes(program, helper, dest)
            if existing is None:
                return missing("%s_destination_unavailable" % api)
            write_address = dest + len(existing)
        if api == "strncpy":
            limit = max(0, int(values[2]))
            chunk = source_bytes[:limit]
            if len(source_bytes) < limit:
                chunk = chunk + [0] * (limit - len(chunk))
            nul_terminated = len(source_bytes) < limit
        elif api == "strncat":
            limit = max(0, int(values[2]))
            chunk = source_bytes[:limit] + [0]
            nul_terminated = True
        else:
            chunk = source_bytes + [0]
            nul_terminated = True
        if not write_memory_bytes(program, helper, write_address, chunk):
            return missing("%s_memory_write_failed" % api)
        return_value = write_address + max(0, len(source_bytes)) if api == "strcpy_end" else dest
        error = ret(return_value)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update(
            {
                "destination_address": "0x%X" % dest,
                "write_address": "0x%X" % write_address,
                "source_address": "0x%X" % source,
                "written_bytes": len(chunk),
                "read_bytes": len(source_bytes),
                "nul_terminated": nul_terminated,
            }
        )
        return event

    if api in {"strdup", "strndup"}:
        needed = 2 if api == "strndup" else 1
        if len(values) < needed or values[0] is None or (needed == 2 and values[1] is None):
            return missing("%s_args_unavailable" % api)
        limit = int(values[1]) if api == "strndup" else 65536
        source_bytes = read_memory_c_bytes(program, helper, int(values[0]), limit, allow_prefix=(api == "strndup"))
        if source_bytes is None:
            return missing("%s_source_unavailable" % api)
        chunk = source_bytes[:limit]
        address = allocate_runtime_memory(program, helper, runtime_state, len(chunk) + 1)
        if not address or not write_memory_bytes(program, helper, address, chunk + [0]):
            return missing("%s_memory_write_failed" % api)
        error = ret(address)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"allocation_address": "0x%X" % address, "written_bytes": len(chunk) + 1})
        return event

    if api in {"atoi", "atol", "atoll"}:
        if len(values) < 1 or values[0] is None:
            return missing("%s_args_unavailable" % api)
        text = read_memory_c_string(program, helper, int(values[0]))
        if text is None:
            return missing("%s_source_unavailable" % api)
        match = re.match(r"^[\t\n\r ]*([+-]?\d+)", text)
        result = int(match.group(1)) if match else 0
        error = ret(result)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event["result"] = result
        return event

    if api in {"strtol", "strtoul", "strtoll", "strtoull"}:
        if len(values) < 3 or values[0] is None or values[2] is None:
            return missing("%s_args_unavailable" % api)
        source_address = int(values[0])
        text = read_memory_c_string(program, helper, source_address)
        if text is None:
            return missing("%s_source_unavailable" % api)
        base = int(values[2])
        pattern = r"^[\t\n\r ]*([+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+))"
        match = re.match(pattern, text)
        token = match.group(1) if match else ""
        try:
            result = int(token, base or 0) if token else 0
        except Exception:
            result = 0
        if api in {"strtoul", "strtoull"} and result < 0:
            bits = 64 if int(abi.get("pointer_size_bytes") or 8) == 8 else 32
            result %= 1 << bits
        if values[1]:
            consumed = match.end(1) if match else 0
            big_endian = abi.get("endianness") == "big"
            pointer_size = int(abi.get("pointer_size_bytes") or 0)
            if pointer_size not in (4, 8) or not write_memory_integer(
                program, helper, int(values[1]), source_address + consumed, pointer_size, big_endian
            ):
                return missing("%s_endptr_write_failed" % api)
        error = ret(result)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": result, "base": base, "consumed_bytes": match.end(1) if match else 0})
        return event

    if api in {"atof", "strtod"}:
        if not values or values[0] is None:
            return missing("%s_args_unavailable" % api)
        text = read_memory_c_string(program, helper, int(values[0]))
        if text is None:
            return missing("%s_source_unavailable" % api)
        match = re.match(r"^[\t\n\r ]*([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)", text)
        result = float(match.group(1)) if match else 0.0
        bits = struct.unpack(">Q", struct.pack(">d", result))[0]
        register = write_register(program, helper, ("XMM0", "xmm0"), bits)
        if not register:
            return missing("%s_return_register_unavailable" % api)
        if api == "strtod" and len(values) > 1 and values[1]:
            pointer_size = int(abi.get("pointer_size_bytes") or 0)
            big_endian = abi.get("endianness") == "big"
            consumed = match.end(1) if match else 0
            if pointer_size not in (4, 8) or not write_memory_integer(
                program, helper, int(values[1]), int(values[0]) + consumed, pointer_size, big_endian
            ):
                return missing("strtod_endptr_write_failed")
        event = runtime_event(target, api)
        event.update({"result": result, "return_register": register})
        return event

    if api in {"ctype_get_mb_cur_max", "mbsinit"}:
        error = ret(1)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event["result"] = 1
        event["locale_model"] = "single_byte"
        return event

    if api == "iswprint":
        if len(values) < 1 or values[0] is None:
            return missing("iswprint_args_unavailable")
        codepoint = int(values[0])
        result = 1 if 0x20 <= codepoint <= 0x7E else 0
        error = ret(result)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": result, "codepoint": codepoint, "locale_model": "single_byte"})
        return event

    if api == "mbrtowc":
        if len(values) < 3 or values[1] is None or values[2] is None:
            return missing("mbrtowc_args_unavailable")
        source = int(values[1])
        available = max(0, int(values[2]))
        if available == 0:
            result = -2
            byte_value = None
        else:
            byte_value = read_memory_byte_at(program, helper, source)
            if byte_value is None:
                return missing("mbrtowc_source_unavailable")
            if byte_value == 0:
                result = 0
            elif byte_value < 0x80:
                result = 1
            else:
                result = -1
            if values[0] is not None and result >= 0:
                big_endian = abi.get("endianness") == "big"
                if not write_memory_integer(program, helper, int(values[0]), int(byte_value), 4, big_endian):
                    return missing("mbrtowc_destination_write_failed")
        error = ret(result)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": result, "source_byte": byte_value, "locale_model": "single_byte"})
        return event

    if api == "sprintf":
        if len(values) < 2 or values[0] is None or values[1] is None:
            return missing("sprintf_args_unavailable")
        rendered = render_printf_bytes(program, helper, int(values[1]), values[2:])
        if rendered is None:
            return missing("sprintf_format_unsupported")
        if not write_memory_bytes(program, helper, int(values[0]), list(rendered) + [0]):
            return missing("sprintf_destination_write_failed")
        error = ret(len(rendered))
        if error is not None:
            return error
        event = runtime_event(target, api)
        event.update({"result": len(rendered), "destination_address": "0x%X" % int(values[0]), "written_bytes": len(rendered) + 1})
        return event

    if api in {
        "printf",
        "fprintf",
        "puts",
        "putchar",
        "perror",
        "fflush",
        "write",
        "close",
        "atexit",
        "cxa_atexit",
        "setvbuf",
        "gmon_start",
        "libc_csu_init",
        "init",
        "frame_dummy",
        "register_tm_clones",
        "deregister_tm_clones",
        "do_global_dtors_aux",
    }:
        result = 0
        if api == "write" and len(values) >= 3 and values[2] is not None:
            result = max(0, int(values[2]))
        elif api == "puts":
            result = 1
        error = ret(result)
        if error is not None:
            return error
        event = runtime_event(target, api)
        event["result"] = result
        return event

    return {}


def setup_process_arguments(program, helper, args, stack_top, argv_values, metadata=None, env_values=None):
    abi = program_abi(program)
    abi_name = abi.get("abi", "")
    pointer_size = int(abi.get("pointer_size_bytes") or 0)
    if not abi_name or pointer_size not in (4, 8):
        payload = process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:unsupported_abi")
        payload.update(abi)
        return payload
    big_endian = abi.get("endianness") == "big"
    env_requested = env_values is not None
    env_values = list(env_values or [])
    stack_top = align_down(stack_top, 16)
    # Process argument vectors and strings live above the initial stack
    # pointer.  Keeping them below it lets ordinary callee frames overwrite
    # argv before option parsing in functions with large local frames.
    argv_address = stack_top + 0x400
    envp_address = argv_address + pointer_size * (len(argv_values) + 1)
    string_size = sum(len(value) + 1 for value in list(argv_values) + env_values)
    string_base = stack_top + max(0x2000, pointer_size * (len(argv_values) + len(env_values) + 4))
    arg_addresses = []
    cursor = string_base
    for index, value in enumerate(argv_values):
        value_bytes = list(value) + [0]
        if not write_memory_bytes(program, helper, cursor, value_bytes):
            payload = process_input_setup_payload(
                args,
                "unsupported",
                "unsupported_process_input_setup:argv%d_memory_write_failed" % index,
            )
            payload.update(abi)
            return payload
        arg_addresses.append(cursor)
        cursor += len(value_bytes)
    env_addresses = []
    for index, value in enumerate(env_values):
        value_bytes = list(value) + [0]
        if not write_memory_bytes(program, helper, cursor, value_bytes):
            payload = process_input_setup_payload(
                args,
                "unsupported",
                "unsupported_process_input_setup:env%d_memory_write_failed" % index,
            )
            payload.update(abi)
            return payload
        env_addresses.append(cursor)
        cursor += len(value_bytes)
    argv_bytes = []
    for address in arg_addresses:
        argv_bytes.extend(pointer_bytes(address, pointer_size, big_endian))
    argv_bytes.extend(pointer_bytes(0, pointer_size, big_endian))
    if not write_memory_bytes(program, helper, argv_address, argv_bytes):
        payload = process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:argv_array_memory_write_failed")
        payload.update(abi)
        return payload
    if env_requested:
        envp_bytes = []
        for address in env_addresses:
            envp_bytes.extend(pointer_bytes(address, pointer_size, big_endian))
        envp_bytes.extend(pointer_bytes(0, pointer_size, big_endian))
        if not write_memory_bytes(program, helper, envp_address, envp_bytes):
            payload = process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:envp_array_memory_write_failed")
            payload.update(abi)
            return payload
    stack_pointer = stack_top - 0x80
    register_arguments = {}
    stack_arguments = {}
    argc = len(argv_values)
    if abi_name == "x86_64_sysv":
        argc_register = write_register(program, helper, ("RDI", "rdi"), argc)
        argv_register = write_register(program, helper, ("RSI", "rsi"), argv_address)
        if not argc_register or not argv_register:
            payload = process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:x86_64_arg_register_unavailable")
            payload.update(abi)
            return payload
        register_arguments = {"argc": argc_register, "argv": argv_register}
        if env_requested:
            envp_register = write_register(program, helper, ("RDX", "rdx"), envp_address)
            if not envp_register:
                payload = process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:x86_64_envp_register_unavailable")
                payload.update(abi)
                return payload
            register_arguments["envp"] = envp_register
    elif abi_name == "aarch64":
        argc_register = write_register(program, helper, ("x0", "X0"), argc)
        argv_register = write_register(program, helper, ("x1", "X1"), argv_address)
        if not argc_register or not argv_register:
            payload = process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:aarch64_arg_register_unavailable")
            payload.update(abi)
            return payload
        register_arguments = {"argc": argc_register, "argv": argv_register}
        if env_requested:
            envp_register = write_register(program, helper, ("x2", "X2"), envp_address)
            if not envp_register:
                payload = process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:aarch64_envp_register_unavailable")
                payload.update(abi)
                return payload
            register_arguments["envp"] = envp_register
    elif abi_name == "arm32":
        argc_register = write_register(program, helper, ("r0", "R0"), argc)
        argv_register = write_register(program, helper, ("r1", "R1"), argv_address)
        if not argc_register or not argv_register:
            payload = process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:arm32_arg_register_unavailable")
            payload.update(abi)
            return payload
        register_arguments = {"argc": argc_register, "argv": argv_register}
        if env_requested:
            envp_register = write_register(program, helper, ("r2", "R2"), envp_address)
            if not envp_register:
                payload = process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:arm32_envp_register_unavailable")
                payload.update(abi)
                return payload
            register_arguments["envp"] = envp_register
    elif abi_name == "i386":
        stack_pointer = stack_top - 0x100
        stack_bytes = (
            pointer_bytes(0, pointer_size, big_endian)
            + pointer_bytes(argc, pointer_size, big_endian)
            + pointer_bytes(argv_address, pointer_size, big_endian)
        )
        if env_requested:
            stack_bytes += pointer_bytes(envp_address, pointer_size, big_endian)
        if not write_memory_bytes(program, helper, stack_pointer, stack_bytes):
            payload = process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:i386_stack_arg_write_failed")
            payload.update(abi)
            return payload
        stack_arguments = {
            "return_address": "0x%X" % stack_pointer,
            "argc": "0x%X" % (stack_pointer + pointer_size),
            "argv": "0x%X" % (stack_pointer + (pointer_size * 2)),
        }
        if env_requested:
            stack_arguments["envp"] = "0x%X" % (stack_pointer + (pointer_size * 3))
    stack_register = write_stack_pointer(program, helper, stack_pointer)
    if not stack_register:
        payload = process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:stack_pointer_register_unavailable")
        payload.update(abi)
        return payload
    payload = process_input_setup_payload(args, "configured", "")
    payload.update(abi)
    payload.update(
        {
            "argc": argc,
            "argv_address": "0x%X" % argv_address,
            "argv_entries": ["0x%X" % address for address in arg_addresses] + ["0x0"],
            "stack_pointer": "0x%X" % stack_pointer,
            "stack_pointer_register": stack_register,
            "register_arguments": register_arguments,
            "stack_arguments": stack_arguments,
        }
    )
    if env_requested:
        payload.update(
            {
                "envp_address": "0x%X" % envp_address,
                "envp_entries": ["0x%X" % address for address in env_addresses] + ["0x0"],
            }
        )
    if metadata:
        payload.update(metadata)
    return payload


def setup_argv_process_input(program, helper, args, stack_top):
    input_bytes = bytes_from_hex(args.get("concrete_input_hex"))
    if input_bytes is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_concrete_input_hex")
    argv_values = hex_values_arg(args.get("argv_values_hex"))
    if argv_values is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_argv_values_hex")
    if not argv_values:
        argv_values = [ascii_bytes("program"), list(input_bytes)]
        input_arg_index = 1
    else:
        input_arg_index = len(argv_values) - 1
    return setup_process_arguments(
        program,
        helper,
        args,
        stack_top,
        argv_values,
        {
            "argv_values": [bytes(value).decode("utf-8", errors="replace") for value in argv_values],
            "input_arg_index": input_arg_index,
            "input_size_bytes": len(argv_values[input_arg_index]) if argv_values else len(input_bytes),
        },
    )


def setup_stdin_process_input(program, helper, args, stack_top):
    input_bytes = bytes_from_hex(args.get("stdin_input_hex") or args.get("concrete_input_hex"))
    if input_bytes is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_concrete_input_hex")
    argv_values = hex_values_arg(args.get("argv_values_hex"))
    if argv_values is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_argv_values_hex")
    if not argv_values:
        argv_values = [ascii_bytes("program")]
    return setup_process_arguments(
        program,
        helper,
        args,
        stack_top,
        argv_values,
        {
            "argv_values": [bytes(value).decode("utf-8", errors="replace") for value in argv_values],
            "input_size_bytes": len(input_bytes),
            "stdin_size_bytes": len(input_bytes),
            "stdin_consumed_bytes": 0,
            "modeled_stdin_calls": [],
        },
    )


def setup_file_process_input(program, helper, args, stack_top):
    input_bytes = bytes_from_hex(args.get("concrete_input_hex"))
    if input_bytes is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_concrete_input_hex")
    file_name = str(args.get("file_name") or "concolic_input")
    argv_values = hex_values_arg(args.get("argv_values_hex"))
    if argv_values is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_argv_values_hex")
    if not argv_values:
        argv_values = [ascii_bytes("program"), ascii_bytes(file_name)]
    input_arg_index = len(argv_values) - 1
    return setup_process_arguments(
        program,
        helper,
        args,
        stack_top,
        argv_values,
        {
            "argv_values": [bytes(value).decode("utf-8", errors="replace") for value in argv_values],
            "input_arg_index": input_arg_index,
            "input_size_bytes": len(input_bytes),
            "file_name": file_name,
            "file_size_bytes": len(input_bytes),
            "file_consumed_bytes": 0,
            "modeled_file_calls": [],
        },
    )


def service_request_bytes(args):
    payload = bytes_from_hex(args.get("concrete_input_hex"))
    if payload is None:
        return None
    if str(args.get("input_model") or "") != "http_daemon":
        return list(payload)
    text = bytes(payload).decode("latin-1", errors="replace")
    if any(text.startswith(prefix) for prefix in ("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ")) and "HTTP/" in text:
        return list(payload)
    path_payload = [value for value in payload if value not in (0, 10, 13, 32)]
    return ascii_bytes("GET /") + path_payload + ascii_bytes(" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")


def setup_service_process_input(program, helper, args, stack_top):
    request = service_request_bytes(args)
    if request is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_concrete_input_hex")
    return setup_process_arguments(
        program,
        helper,
        args,
        stack_top,
        [ascii_bytes("program")],
        {
            "input_size_bytes": len(request),
            "network_request_size_bytes": len(request),
            "network_consumed_bytes": 0,
            "synthetic_listener_fd": 3,
            "synthetic_client_fd": 4,
            "modeled_network_calls": [],
            "http_request_valid": str(args.get("input_model") or "") == "http_daemon",
        },
    )


def modeled_network_input_call(program, helper, instruction, sink_address, args, process_setup, network_state):
    input_model = str(args.get("input_model") or "")
    if input_model not in {"socket_service", "http_daemon"}:
        return {}
    target = external_call_target(program, instruction, sink_address, helper)
    if not target:
        return {}
    api = normalized_api_name(target.get("target_function"))
    if api not in {"socket", "bind", "listen", "accept", "accept4", "recv", "recvfrom", "read", "close", "shutdown", "setsockopt"}:
        return {}
    abi = dict(process_setup or {})
    if not abi.get("abi"):
        abi.update(program_abi(program))
    values = abi_argument_values(program, helper, abi, 6)
    listener_fd = int(network_state.get("listener_fd") or 3)
    client_fd = int(network_state.get("client_fd") or 4)
    descriptors = network_state.setdefault("descriptors", {})

    if api == "socket":
        descriptors[listener_fd] = {"role": "listener", "state": "created"}
        result = listener_fd
    elif api in {"bind", "listen", "setsockopt"}:
        if not values or values[0] is None or int(values[0]) != listener_fd:
            return {}
        descriptors.setdefault(listener_fd, {"role": "listener"})["state"] = api
        result = 0
    elif api in {"accept", "accept4"}:
        if not values or values[0] is None or int(values[0]) != listener_fd:
            return {}
        descriptors[client_fd] = {"role": "client", "state": "accepted"}
        result = client_fd
    elif api in {"recv", "recvfrom", "read"}:
        if len(values) < 3 or values[0] is None or values[1] is None or values[2] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:%s_args_unavailable" % api}
        handle = int(values[0])
        if handle != client_fd or handle not in descriptors:
            return {}
        offset = int(network_state.get("offset") or 0)
        requested = max(0, int(values[2]))
        chunk = list(network_state.get("bytes") or [])[offset : offset + requested]
        if not write_memory_bytes(program, helper, int(values[1]), chunk):
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:network_memory_write_failed"}
        network_state["offset"] = offset + len(chunk)
        result = len(chunk)
    else:
        if not values or values[0] is None:
            return {"status": "unsupported", "reason": "unsupported_process_input_setup:%s_args_unavailable" % api}
        handle = int(values[0])
        if handle not in descriptors:
            return {}
        descriptors[handle]["state"] = "closed"
        result = 0

    if not write_return_value(program, helper, abi, result):
        return {"status": "unsupported", "reason": "unsupported_process_input_setup:%s_return_register_unavailable" % api}
    event = {
        "status": "modeled",
        "input_model": input_model,
        "function_model": api,
        "return_value": result,
        "call_address": target.get("call_address"),
        "target_address": target.get("target_address"),
        "target_function": target.get("target_function"),
        "fallthrough_address": target.get("fallthrough_address"),
    }
    if api in {"recv", "recvfrom", "read"}:
        event.update({
            "handle": int(values[0]),
            "buffer_address": "0x%X" % int(values[1]),
            "requested_bytes": max(0, int(values[2])),
            "written_bytes": result,
            "input_offset_before": offset,
            "input_offset_after": offset + result,
        })
        process_setup["network_consumed_bytes"] = offset + result
    process_setup.setdefault("modeled_network_calls", []).append(event)
    return event


def setup_argv_file_stdin_process_input(program, helper, args, stack_top):
    stdin_bytes = bytes_from_hex(args.get("stdin_input_hex") or args.get("concrete_input_hex"))
    if stdin_bytes is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_stdin_input_hex")
    file_hex = str(args.get("file_input_hex") or "").strip()
    if not file_hex:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:missing_file_input_hex")
    file_bytes = bytes_from_hex(file_hex)
    if file_bytes is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_file_input_hex")
    file_name = str(args.get("file_name") or "concolic_input")
    argv_values = hex_values_arg(args.get("argv_values_hex"))
    if argv_values is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_argv_values_hex")
    if not argv_values:
        argv_values = [ascii_bytes("program"), ascii_bytes(file_name)]
    return setup_process_arguments(
        program,
        helper,
        args,
        stack_top,
        argv_values,
        {
            "input_size_bytes": len(stdin_bytes),
            "stdin_size_bytes": len(stdin_bytes),
            "stdin_consumed_bytes": 0,
            "argv_values": [bytes(value).decode("utf-8", errors="replace") for value in argv_values],
            "file_name": file_name,
            "file_size_bytes": len(file_bytes),
            "file_consumed_bytes": 0,
            "modeled_stdin_calls": [],
            "modeled_file_calls": [],
        },
    )


def setup_argv_directory_process_input(program, helper, args, stack_top):
    entry = bytes_from_hex(args.get("concrete_input_hex"))
    if entry is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_directory_entry_hex")
    entry = list(entry)[:255]
    if not entry:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:missing_directory_entry")
    if 0 in entry or ord("/") in entry:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_directory_entry_name")
    directory_name = str(args.get("file_name") or "concolic_dir")
    argv_values = hex_values_arg(args.get("argv_values_hex"))
    if argv_values is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_argv_values_hex")
    if not argv_values:
        argv_values = [ascii_bytes("program"), ascii_bytes(directory_name.rstrip("/") + "/*")]
    return setup_process_arguments(
        program,
        helper,
        args,
        stack_top,
        argv_values,
        {
            "input_size_bytes": len(entry),
            "argv_values": [bytes(value).decode("utf-8", errors="replace") for value in argv_values],
            "input_arg_index": len(argv_values) - 1,
            "file_name": directory_name,
            "directory_name": directory_name,
            "directory_entry_size_bytes": len(entry),
            "dirent_d_name_offset_bytes": dirent_name_offset(program_abi(program)),
            "modeled_directory_calls": [],
        },
    )


def setup_env_process_input(program, helper, args, stack_top):
    input_bytes = bytes_from_hex(args.get("concrete_input_hex"))
    if input_bytes is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_concrete_input_hex")
    if 0 in input_bytes:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:env_value_contains_nul")
    env_name = str(args.get("env_name") or "CONCOLIC_INPUT")
    if not env_name or "=" in env_name or "\x00" in env_name:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_env_name")
    env_value = ascii_bytes(env_name + "=") + list(input_bytes)
    return setup_process_arguments(
        program,
        helper,
        args,
        stack_top,
        [ascii_bytes("program")],
        {
            "input_size_bytes": len(input_bytes),
            "env_name": env_name,
            "env_value_size_bytes": len(input_bytes),
            "env_value_contains_nul": False,
            "modeled_env_calls": [],
            "env_variable_names": [env_name],
        },
        env_values=[env_value],
    )


def setup_env_file_process_input(program, helper, args, stack_top):
    file_bytes = bytes_from_hex(args.get("file_input_hex") or args.get("concrete_input_hex"))
    if file_bytes is None or not file_bytes:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_env_file_input_hex")
    file_name = str(args.get("file_name") or "")
    env_name = str(args.get("env_name") or "")
    env_values = json_arg(args, "env_values_json")
    if not file_name:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:missing_env_file_name")
    if not env_name or env_name not in env_values:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:missing_env_file_environment")
    encoded_env = []
    for name, value in sorted(env_values.items()):
        name = str(name)
        value_bytes = ascii_bytes(str(value))
        if not name or "=" in name or "\x00" in name or 0 in value_bytes:
            return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_env_file_environment")
        encoded_env.append(ascii_bytes(name + "=") + value_bytes)
    argv_values = hex_values_arg(args.get("argv_values_hex"))
    if argv_values is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_process_input_setup:invalid_argv_values_hex")
    if not argv_values:
        argv_values = [ascii_bytes("program")]
    return setup_process_arguments(
        program,
        helper,
        args,
        stack_top,
        argv_values,
        {
            "input_size_bytes": len(file_bytes),
            "file_name": file_name,
            "file_size_bytes": len(file_bytes),
            "file_consumed_bytes": 0,
            "env_name": env_name,
            "env_values": {str(key): str(value) for key, value in env_values.items()},
            "env_variable_names": sorted(str(key) for key in env_values),
            "argv_values": [bytes(value).decode("utf-8", errors="replace") for value in argv_values],
            "modeled_env_calls": [],
            "modeled_file_calls": [],
        },
        env_values=encoded_env,
    )


def compact_instruction_trace(replay, limit=MAX_RECORDED_INSTRUCTIONS):
    if not isinstance(replay, dict):
        return replay
    instructions = replay.get("instructions")
    if not isinstance(instructions, list):
        return replay
    count = len(instructions)
    replay["instruction_count"] = count
    replay["instructions_truncated"] = max(0, count - max(0, int(limit or 0)))
    if replay["instructions_truncated"]:
        prefix_count = max(0, int(limit or 0)) // 2
        suffix_count = max(0, int(limit or 0)) - prefix_count
        replay["instructions"] = instructions[:prefix_count]
        if suffix_count:
            replay["instructions"] += instructions[-suffix_count:]
    return replay


def record_static_path_hits(replay, args):
    """Preserve ordered checkpoint hits before the general trace is compacted."""
    if not isinstance(replay, dict):
        return replay
    raw_addresses = (args or {}).get("static_path_addresses") or []
    if isinstance(raw_addresses, str):
        try:
            raw_addresses = json.loads(raw_addresses)
        except Exception:
            raw_addresses = []
    if not isinstance(raw_addresses, (list, tuple)):
        raw_addresses = []
    wanted = []
    for item in raw_addresses:
        address = str(item).lower()
        if address and address not in wanted:
            wanted.append(address)
    if not wanted:
        return replay
    hits = []
    wanted_index = 0
    for instruction in replay.get("instructions", []) or []:
        if not isinstance(instruction, dict):
            continue
        address = str(instruction.get("address") or "").lower()
        if wanted_index < len(wanted) and address == wanted[wanted_index]:
            hits.append(address)
            wanted_index += 1
    replay["static_path_hits"] = hits[:8]
    replay["static_path_address_count"] = len(wanted)
    return replay


def setup_function_harness_input(program, helper, args, stack_top):
    input_bytes = bytes_from_hex(args.get("concrete_input_hex"))
    if input_bytes is None:
        return process_input_setup_payload(args, "unsupported", "unsupported_function_harness:invalid_concrete_input_hex")
    harness = json_arg(args, "function_harness_json")
    abi = program_abi(program)
    pointer_size = int(abi.get("pointer_size_bytes") or 0)
    if not abi.get("abi") or pointer_size not in (4, 8):
        payload = process_input_setup_payload(args, "unsupported", "unsupported_function_harness:unsupported_abi")
        payload.update(abi)
        return payload
    input_address = parse_int(harness.get("input_address"), 0x71000000)
    if input_address <= 0:
        return process_input_setup_payload(args, "unsupported", "unsupported_function_harness:invalid_input_address")
    if not write_memory_bytes(program, helper, input_address, list(input_bytes) + [0]):
        return process_input_setup_payload(args, "unsupported", "unsupported_function_harness:input_memory_write_failed")
    arg_count = parse_int(harness.get("arg_count"), 1)
    if arg_count <= 0 or arg_count > 8:
        return process_input_setup_payload(args, "unsupported", "unsupported_function_harness:invalid_arg_count")
    input_arg_index = parse_int(harness.get("input_arg_index"), 0)
    input_arg_indices = set([input_arg_index])
    raw_input_arg_indices = harness.get("input_arg_indices")
    if isinstance(raw_input_arg_indices, list):
        input_arg_indices = set()
        for raw_index in raw_input_arg_indices:
            parsed_index = parse_int(raw_index, -1)
            if 0 <= parsed_index < arg_count:
                input_arg_indices.add(parsed_index)
        if not input_arg_indices:
            input_arg_indices.add(input_arg_index)
    length_arg_index = parse_int(harness.get("length_arg_index"), -1)
    if length_arg_index < 0 and bool(harness.get("length_arg")):
        length_arg_index = 1 if input_arg_index != 1 else -1
    constant_args = harness.get("constant_args") if isinstance(harness.get("constant_args"), dict) else {}
    stack_pointer = align_down(stack_top, 16) - 0x80
    try:
        stack_register = program.getCompilerSpec().getStackPointer()
        if stack_register is not None:
            helper.writeRegister(stack_register, stack_pointer)
    except Exception:
        pass
    big_endian = abi.get("endianness") == "big"
    write_memory_bytes(program, helper, stack_pointer, pointer_bytes(0, pointer_size, big_endian))
    register_arguments = {}
    for index in range(arg_count):
        if index in input_arg_indices:
            value = input_address
        elif index == length_arg_index:
            value = len(input_bytes)
        else:
            value = parse_int(constant_args.get(str(index)), 0)
        location = write_abi_argument(program, helper, abi, index, value)
        if not location:
            return process_input_setup_payload(
                args,
                "unsupported",
                "unsupported_function_harness:arg%d_unavailable" % index,
            )
        register_arguments["arg%d" % index] = {"location": location, "value": value}
    payload = process_input_setup_payload(args, "configured", "")
    payload.update(
        {
            "proof_scope": "function_harness",
            "input_size_bytes": len(input_bytes),
            "input_address": "0x%X" % input_address,
            "input_arg_index": input_arg_index,
            "input_arg_indices": sorted(input_arg_indices),
            "length_arg_index": length_arg_index,
            "arg_count": arg_count,
            "register_arguments": register_arguments,
            "stack_pointer": "0x%X" % stack_pointer,
        }
    )
    payload.update(abi)
    return payload


def concrete_emulator_replay(program, start_address, sink_address, max_steps, timeout_ms, args=None):
    if EmulatorHelper is None:
        return {"status": "unsupported", "reason": "EmulatorHelper unavailable", "instructions": []}
    helper = EmulatorHelper(program)
    instructions = []
    skipped_calls = []
    modeled_input_calls = []
    modeled_runtime_calls = []
    modeled_syscalls = []
    modeled_control_transfers = []
    stdin_state = {}
    file_state = {}
    env_state = {}
    network_state = {}
    runtime_state = {"next_heap": 0x70000000, "allocations": {}}
    exact_sink_effects = []
    started = time.time()
    try:
        pc = helper.getPCRegister()
        helper.writeRegister(pc, start_address.getOffset())
        try:
            stack_pointer = program.getCompilerSpec().getStackPointer()
            if stack_pointer is not None:
                helper.writeRegister(stack_pointer, 0x7FFFF000)
        except Exception:
            pass
        process_setup = {}
        if args is not None and proof_scope_from_args(args) == "function_harness":
            process_setup = setup_function_harness_input(program, helper, args, 0x7FFFF000)
            if process_setup.get("status") == "unsupported":
                return {
                    "status": "unsupported",
                    "reason": process_setup["reason"],
                    "instructions": instructions,
                    "skipped_calls": skipped_calls,
                    "modeled_input_calls": modeled_input_calls,
                    "modeled_runtime_calls": modeled_runtime_calls,
                    "modeled_syscalls": modeled_syscalls,
                    "modeled_control_transfers": modeled_control_transfers,
                    "reached_target": False,
                    "process_input_setup": process_setup,
                }
        elif args is not None and proof_scope_from_args(args) == "process_entrypoint":
            input_model = str(args.get("input_model") or "")
            if input_model not in {"argv", "stdin", "file", "env", "env_file", "argv_file_stdin", "argv_directory", "socket_service", "http_daemon"}:
                process_setup = process_input_setup_payload(
                    args,
                    "unsupported",
                    "unsupported_process_input_setup:input_model_%s" % input_model,
                )
                return {
                    "status": "unsupported",
                    "reason": process_setup["reason"],
                    "instructions": instructions,
                    "skipped_calls": skipped_calls,
                    "modeled_input_calls": modeled_input_calls,
                    "modeled_runtime_calls": modeled_runtime_calls,
                    "modeled_syscalls": modeled_syscalls,
                    "modeled_control_transfers": modeled_control_transfers,
                    "reached_target": False,
                    "process_input_setup": process_setup,
                }
            if input_model == "argv":
                process_setup = setup_argv_process_input(program, helper, args, 0x7FFFF000)
            elif input_model == "stdin":
                process_setup = setup_stdin_process_input(program, helper, args, 0x7FFFF000)
                stdin_state = {
                    "bytes": bytes_from_hex(args.get("stdin_input_hex") or args.get("concrete_input_hex")) or [],
                    "offset": 0,
                }
            elif input_model == "file":
                process_setup = setup_file_process_input(program, helper, args, 0x7FFFF000)
                file_state = {
                    "bytes": bytes_from_hex(args.get("concrete_input_hex")) or [],
                    "file_name": str(process_setup.get("file_name") or "concolic_input"),
                    "descriptors": {},
                    "streams": {},
                    "next_fd": 3,
                    "next_stream": 0x7FFEE000,
                }
            elif input_model == "argv_file_stdin":
                process_setup = setup_argv_file_stdin_process_input(program, helper, args, 0x7FFFF000)
                stdin_state = {"bytes": bytes_from_hex(args.get("stdin_input_hex") or args.get("concrete_input_hex")) or [], "offset": 0}
                file_state = {
                    "bytes": bytes_from_hex(args.get("file_input_hex")) or [],
                    "file_name": str(process_setup.get("file_name") or "concolic_input"),
                    "descriptors": {},
                    "streams": {},
                    "next_fd": 3,
                    "next_stream": 0x7FFEE000,
                }
            elif input_model == "argv_directory":
                process_setup = setup_argv_directory_process_input(program, helper, args, 0x7FFFF000)
            elif input_model == "env":
                process_setup = setup_env_process_input(program, helper, args, 0x7FFFF000)
                env_state = {
                    "bytes": bytes_from_hex(args.get("concrete_input_hex")) or [],
                    "values": {},
                    "next_value_address": 0x7FFDB000,
                }
            elif input_model == "env_file":
                process_setup = setup_env_file_process_input(program, helper, args, 0x7FFFF000)
                file_state = {
                    "bytes": bytes_from_hex(args.get("file_input_hex") or args.get("concrete_input_hex")) or [],
                    "file_name": str(process_setup.get("file_name") or "concolic_input"),
                    "descriptors": {},
                    "streams": {},
                    "next_fd": 3,
                    "next_stream": 0x7FFEE000,
                }
                env_state = {
                    "variables": {
                        str(name): ascii_bytes(str(value))
                        for name, value in json_arg(args, "env_values_json").items()
                    },
                    "values": {},
                    "next_value_address": 0x7FFDB000,
                }
            else:
                process_setup = setup_service_process_input(program, helper, args, 0x7FFFF000)
                network_state = {
                    "bytes": service_request_bytes(args) or [],
                    "offset": 0,
                    "listener_fd": 3,
                    "client_fd": 4,
                    "descriptors": {},
                }
            if process_setup.get("status") != "configured":
                return {
                    "status": "unsupported",
                    "reason": str(process_setup.get("reason") or "unsupported_process_input_setup"),
                    "instructions": instructions,
                    "skipped_calls": skipped_calls,
                    "modeled_input_calls": modeled_input_calls,
                    "modeled_runtime_calls": modeled_runtime_calls,
                    "modeled_syscalls": modeled_syscalls,
                    "modeled_control_transfers": modeled_control_transfers,
                    "reached_target": False,
                    "process_input_setup": process_setup,
                }
        for _index in range(max_steps):
            if int((time.time() - started) * 1000) > timeout_ms:
                return {
                    "status": "timeout",
                    "instructions": instructions,
                    "skipped_calls": skipped_calls,
                    "modeled_input_calls": modeled_input_calls,
                    "modeled_runtime_calls": modeled_runtime_calls,
                    "modeled_syscalls": modeled_syscalls,
                    "modeled_control_transfers": modeled_control_transfers,
                    "reached_target": False,
                    "process_input_setup": process_setup,
                }
            current = helper.getExecutionAddress()
            if current is None:
                return {
                    "status": "unsupported",
                    "reason": "execution address unavailable",
                    "instructions": instructions,
                    "skipped_calls": skipped_calls,
                    "modeled_input_calls": modeled_input_calls,
                    "modeled_runtime_calls": modeled_runtime_calls,
                    "modeled_syscalls": modeled_syscalls,
                    "modeled_control_transfers": modeled_control_transfers,
                    "process_input_setup": process_setup,
                }
            instruction = program.getListing().getInstructionAt(current)
            if instruction is not None:
                instructions.append(instruction_fact(instruction))
            if current == sink_address:
                sink_effect = {}
                if instruction is not None:
                    sink_effect = modeled_network_input_call(
                        program, helper, instruction, sink_address, args or {}, process_setup, network_state
                    )
                    if not sink_effect:
                        sink_effect = modeled_runtime_call(
                            program,
                            helper,
                            instruction,
                            sink_address,
                            process_setup,
                            runtime_state,
                            args or {},
                        )
                    if not sink_effect:
                        sink_effect = modeled_direct_lifetime_access(
                            program,
                            helper,
                            instruction,
                            args or {},
                            runtime_state,
                        )
                    if not sink_effect:
                        sink_effect = modeled_direct_memory_read(program, helper, instruction, args or {})
                    if sink_effect and sink_effect.get("status") != "unsupported":
                        modeled_runtime_calls.append(sink_effect)
                exact_sink_effects.append(dict(sink_effect or {}))
                sink_status = str(sink_effect.get("status") or "")
                expected_vulnerability = str((args or {}).get("vulnerability_type") or "")
                lifetime_violation = (
                    sink_effect.get("lifetime_violation")
                    if isinstance(sink_effect.get("lifetime_violation"), dict)
                    else {}
                )
                if (
                    expected_vulnerability == "double_free"
                    and sink_status == "modeled"
                    and str(lifetime_violation.get("vulnerability") or "") != "double_free"
                ):
                    fallthrough = parse_int(sink_effect.get("fallthrough_address"), 0)
                    if fallthrough:
                        helper.writeRegister(pc, fallthrough)
                        continue
                if sink_status == "terminated":
                    replay_status = "terminated"
                elif sink_status == "unsupported":
                    replay_status = "unsupported"
                else:
                    replay_status = "reached"
                return {
                    "status": replay_status,
                    "reason": str(sink_effect.get("reason") or "") if replay_status != "reached" else "",
                    "instructions": instructions,
                    "skipped_calls": skipped_calls,
                    "modeled_input_calls": modeled_input_calls,
                    "modeled_runtime_calls": modeled_runtime_calls,
                    "modeled_syscalls": modeled_syscalls,
                    "modeled_control_transfers": modeled_control_transfers,
                    "sink_effect": sink_effect,
                    "sink_effects": exact_sink_effects,
                    "exact_sink_hit_count": len(exact_sink_effects),
                    "reached_target": replay_status == "reached",
                    "process_input_setup": process_setup,
                }
            modeled_syscall = modeled_syscall_instruction(
                program,
                helper,
                instruction,
                args or {},
                process_setup,
                stdin_state,
                file_state,
                runtime_state,
            )
            if modeled_syscall:
                if modeled_syscall.get("status") == "unsupported":
                    return {
                        "status": "unsupported",
                        "reason": str(modeled_syscall.get("reason") or "unsupported_syscall"),
                        "instructions": instructions,
                        "skipped_calls": skipped_calls,
                        "modeled_input_calls": modeled_input_calls,
                        "modeled_runtime_calls": modeled_runtime_calls,
                        "modeled_syscalls": modeled_syscalls,
                        "modeled_control_transfers": modeled_control_transfers,
                        "reached_target": False,
                        "process_input_setup": process_setup,
                    }
                modeled_syscalls.append(modeled_syscall)
                if modeled_syscall.get("status") == "terminated":
                    return {
                        "status": "terminated",
                        "reason": str(modeled_syscall.get("reason") or "process_terminated"),
                        "instructions": instructions,
                        "skipped_calls": skipped_calls,
                        "modeled_input_calls": modeled_input_calls,
                        "modeled_runtime_calls": modeled_runtime_calls,
                        "modeled_syscalls": modeled_syscalls,
                        "modeled_control_transfers": modeled_control_transfers,
                        "reached_target": False,
                        "process_input_setup": process_setup,
                    }
                helper.writeRegister(pc, parse_int(modeled_syscall.get("fallthrough_address"), 0))
                continue
            modeled_network = modeled_network_input_call(
                program,
                helper,
                instruction,
                sink_address,
                args or {},
                process_setup,
                network_state,
            )
            if modeled_network:
                if modeled_network.get("status") == "unsupported":
                    return {
                        "status": "unsupported",
                        "reason": str(modeled_network.get("reason") or "unsupported_process_input_setup"),
                        "instructions": instructions,
                        "skipped_calls": skipped_calls,
                        "modeled_input_calls": modeled_input_calls,
                        "modeled_runtime_calls": modeled_runtime_calls,
                        "modeled_syscalls": modeled_syscalls,
                        "modeled_control_transfers": modeled_control_transfers,
                        "reached_target": False,
                        "process_input_setup": process_setup,
                    }
                modeled_input_calls.append(modeled_network)
                helper.writeRegister(pc, parse_int(modeled_network.get("fallthrough_address"), 0))
                continue
            modeled_file = modeled_file_input_call(
                program,
                helper,
                instruction,
                sink_address,
                args or {},
                process_setup,
                file_state,
            )
            if modeled_file:
                if modeled_file.get("status") == "unsupported":
                    return {
                        "status": "unsupported",
                        "reason": str(modeled_file.get("reason") or "unsupported_process_input_setup"),
                        "instructions": instructions,
                        "skipped_calls": skipped_calls,
                        "modeled_input_calls": modeled_input_calls,
                        "modeled_runtime_calls": modeled_runtime_calls,
                        "modeled_syscalls": modeled_syscalls,
                        "modeled_control_transfers": modeled_control_transfers,
                        "reached_target": False,
                        "process_input_setup": process_setup,
                    }
                modeled_input_calls.append(modeled_file)
                helper.writeRegister(pc, parse_int(modeled_file.get("fallthrough_address"), 0))
                continue
            modeled_env = modeled_env_input_call(
                program,
                helper,
                instruction,
                sink_address,
                args or {},
                process_setup,
                env_state,
            )
            if modeled_env:
                if modeled_env.get("status") == "unsupported":
                    return {
                        "status": "unsupported",
                        "reason": str(modeled_env.get("reason") or "unsupported_process_input_setup"),
                        "instructions": instructions,
                        "skipped_calls": skipped_calls,
                        "modeled_input_calls": modeled_input_calls,
                        "modeled_runtime_calls": modeled_runtime_calls,
                        "modeled_syscalls": modeled_syscalls,
                        "modeled_control_transfers": modeled_control_transfers,
                        "reached_target": False,
                        "process_input_setup": process_setup,
                    }
                modeled_input_calls.append(modeled_env)
                helper.writeRegister(pc, parse_int(modeled_env.get("fallthrough_address"), 0))
                continue
            modeled_input = modeled_stdin_input_call(
                program,
                helper,
                instruction,
                sink_address,
                args or {},
                process_setup,
                stdin_state,
            )
            if modeled_input:
                if modeled_input.get("status") == "unsupported":
                    return {
                        "status": "unsupported",
                        "reason": str(modeled_input.get("reason") or "unsupported_process_input_setup"),
                        "instructions": instructions,
                        "skipped_calls": skipped_calls,
                        "modeled_input_calls": modeled_input_calls,
                        "modeled_runtime_calls": modeled_runtime_calls,
                        "modeled_syscalls": modeled_syscalls,
                        "modeled_control_transfers": modeled_control_transfers,
                        "reached_target": False,
                        "process_input_setup": process_setup,
                    }
                modeled_input_calls.append(modeled_input)
                helper.writeRegister(pc, parse_int(modeled_input.get("fallthrough_address"), 0))
                continue
            modeled_syscall = modeled_syscall_wrapper_call(
                program,
                helper,
                instruction,
                sink_address,
                args or {},
                process_setup,
                stdin_state,
                file_state,
                runtime_state,
            )
            if modeled_syscall:
                if modeled_syscall.get("status") == "unsupported":
                    return {
                        "status": "unsupported",
                        "reason": str(modeled_syscall.get("reason") or "unsupported_syscall"),
                        "instructions": instructions,
                        "skipped_calls": skipped_calls,
                        "modeled_input_calls": modeled_input_calls,
                        "modeled_runtime_calls": modeled_runtime_calls,
                        "modeled_syscalls": modeled_syscalls,
                        "modeled_control_transfers": modeled_control_transfers,
                        "reached_target": False,
                        "process_input_setup": process_setup,
                    }
                modeled_syscalls.append(modeled_syscall)
                if modeled_syscall.get("status") == "terminated":
                    return {
                        "status": "terminated",
                        "reason": str(modeled_syscall.get("reason") or "process_terminated"),
                        "instructions": instructions,
                        "skipped_calls": skipped_calls,
                        "modeled_input_calls": modeled_input_calls,
                        "modeled_runtime_calls": modeled_runtime_calls,
                        "modeled_syscalls": modeled_syscalls,
                        "modeled_control_transfers": modeled_control_transfers,
                        "reached_target": False,
                        "process_input_setup": process_setup,
                    }
                helper.writeRegister(pc, parse_int(modeled_syscall.get("fallthrough_address"), 0))
                continue
            control_transfer = modeled_control_transfer_call(program, helper, instruction, sink_address, process_setup)
            if control_transfer:
                if control_transfer.get("status") == "unsupported":
                    return {
                        "status": "unsupported",
                        "reason": str(control_transfer.get("reason") or "unsupported_control_transfer"),
                        "instructions": instructions,
                        "skipped_calls": skipped_calls,
                        "modeled_input_calls": modeled_input_calls,
                        "modeled_runtime_calls": modeled_runtime_calls,
                        "modeled_syscalls": modeled_syscalls,
                        "modeled_control_transfers": modeled_control_transfers,
                        "reached_target": False,
                        "process_input_setup": process_setup,
                    }
                modeled_control_transfers.append(control_transfer)
                if control_transfer.get("status") == "transfer":
                    helper.writeRegister(pc, parse_int(control_transfer.get("transfer_address"), 0))
                else:
                    helper.writeRegister(pc, parse_int(control_transfer.get("fallthrough_address"), 0))
                continue
            modeled_runtime = modeled_runtime_call(
                program,
                helper,
                instruction,
                sink_address,
                process_setup,
                runtime_state,
            )
            if modeled_runtime:
                if modeled_runtime.get("status") == "unsupported":
                    return {
                        "status": "unsupported",
                        "reason": str(modeled_runtime.get("reason") or "unsupported_runtime_call"),
                        "instructions": instructions,
                        "skipped_calls": skipped_calls,
                        "modeled_input_calls": modeled_input_calls,
                        "modeled_runtime_calls": modeled_runtime_calls,
                        "modeled_syscalls": modeled_syscalls,
                        "modeled_control_transfers": modeled_control_transfers,
                        "reached_target": False,
                        "process_input_setup": process_setup,
                    }
                modeled_runtime_calls.append(modeled_runtime)
                if modeled_runtime.get("status") == "terminated":
                    return {
                        "status": "terminated",
                        "reason": str(modeled_runtime.get("reason") or "process_terminated"),
                        "instructions": instructions,
                        "skipped_calls": skipped_calls,
                        "modeled_input_calls": modeled_input_calls,
                        "modeled_runtime_calls": modeled_runtime_calls,
                        "modeled_syscalls": modeled_syscalls,
                        "modeled_control_transfers": modeled_control_transfers,
                        "reached_target": False,
                        "process_input_setup": process_setup,
                    }
                helper.writeRegister(pc, parse_int(modeled_runtime.get("fallthrough_address"), 0))
                continue
            indirect_transfer = modeled_indirect_call_transfer(program, helper, instruction, sink_address)
            if indirect_transfer:
                modeled_control_transfers.append(indirect_transfer)
            skip = external_call_skip(program, helper, instruction, sink_address)
            if skip:
                skipped_calls.append(skip)
                helper.writeRegister(pc, parse_int(skip.get("fallthrough_address"), 0))
                continue
            try:
                step_monitor = getMonitor()
            except Exception:
                step_monitor = monitor
            if not helper.step(step_monitor):
                return {
                    "status": "stopped",
                    "instructions": instructions,
                    "skipped_calls": skipped_calls,
                    "modeled_input_calls": modeled_input_calls,
                    "modeled_runtime_calls": modeled_runtime_calls,
                    "modeled_syscalls": modeled_syscalls,
                    "modeled_control_transfers": modeled_control_transfers,
                    "reached_target": False,
                    "process_input_setup": process_setup,
                }
        return {
            "status": "step_cap",
            "instructions": instructions,
            "skipped_calls": skipped_calls,
            "modeled_input_calls": modeled_input_calls,
            "modeled_runtime_calls": modeled_runtime_calls,
            "modeled_syscalls": modeled_syscalls,
            "modeled_control_transfers": modeled_control_transfers,
            "reached_target": False,
            "process_input_setup": process_setup,
        }
    except Exception as exc:
        return {
            "status": "unsupported",
            "reason": str(exc),
            "instructions": instructions,
            "skipped_calls": skipped_calls,
            "modeled_input_calls": modeled_input_calls,
            "modeled_runtime_calls": modeled_runtime_calls,
            "modeled_syscalls": modeled_syscalls,
            "modeled_control_transfers": modeled_control_transfers,
        }
    finally:
        try:
            helper.dispose()
        except Exception:
            pass


def concrete_sink_write_size(replay):
    if not isinstance(replay, dict):
        return 0
    sink_effect = replay.get("sink_effect")
    if not isinstance(sink_effect, dict):
        return 0
    return parse_int(sink_effect.get("written_bytes"), 0)


def sink_requires_concrete_write_size(args):
    return normalized_api_name(args.get("sink_name")) in {
        "strcpy",
        "strcpy_chk",
        "strcpy_end",
        "strncpy",
        "strcat",
        "strcat_chk",
        "strncat",
    }


def modeled_write_size(args, replay=None):
    concrete_size = concrete_sink_write_size(replay)
    if concrete_size > 0:
        return concrete_size
    formatted_bound = parse_int(args.get("formatted_write_bound_bytes"), 0)
    explicit = parse_int(args.get("write_size_bytes"), 0)
    if formatted_bound > 0:
        if explicit > 0:
            return min(explicit, formatted_bound)
        return formatted_bound
    if explicit > 0:
        return explicit
    input_hex = str(args.get("concrete_input_hex") or "")
    if input_hex:
        return len(input_hex) // 2
    return 0


def modeled_write_size_source(args, replay=None):
    if concrete_sink_write_size(replay) > 0:
        return "concrete_sink_effect"
    if parse_int(args.get("formatted_write_bound_bytes"), 0) > 0:
        return "constant_snprintf_format_bound"
    return "candidate_or_input_model"


def split_call_args(text):
    call_start = text.find("(")
    call_end = text.rfind(")")
    if call_start < 0 or call_end <= call_start:
        return []
    raw = text[call_start + 1 : call_end]
    args = []
    current = []
    depth = 0
    in_string = False
    in_char = False
    escape = False
    for char in raw:
        if escape:
            current.append(char)
            escape = False
            continue
        if char == "\\" and (in_string or in_char):
            current.append(char)
            escape = True
            continue
        if char == '"' and not in_char:
            current.append(char)
            in_string = not in_string
            continue
        if char == "'" and not in_string:
            current.append(char)
            in_char = not in_char
            continue
        if in_string or in_char:
            current.append(char)
            continue
        if char in "([{":
            depth += 1
            current.append(char)
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            current.append(char)
            continue
        if char == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        args.append("".join(current).strip())
    return args


def decode_c_string_literal(text):
    value = str(text or "").strip()
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        return None
    result = []
    index = 1
    end = len(value) - 1
    while index < end:
        char = value[index]
        if char != "\\":
            result.append(char)
            index += 1
            continue
        index += 1
        if index >= end:
            break
        esc = value[index]
        mapping = {
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "0": "\0",
            "\\": "\\",
            '"': '"',
        }
        if esc in mapping:
            result.append(mapping[esc])
            index += 1
            continue
        if esc == "x":
            index += 1
            digits = []
            while index < end and len(digits) < 2 and value[index] in "0123456789abcdefABCDEF":
                digits.append(value[index])
                index += 1
            if digits:
                result.append(chr(int("".join(digits), 16)))
            continue
        if esc in "01234567":
            digits = [esc]
            index += 1
            while index < end and len(digits) < 3 and value[index] in "01234567":
                digits.append(value[index])
                index += 1
            result.append(chr(int("".join(digits), 8)))
            continue
        result.append(esc)
        index += 1
    return "".join(result)


def program_byte(program, address):
    try:
        raw = program.getMemory().getByte(address)
        return int(raw) & 0xFF
    except Exception:
        return None


def program_word(program, address):
    try:
        big_endian = bool(program.getLanguage().isBigEndian())
    except Exception:
        big_endian = False
    values = []
    current = address
    for _index in range(4):
        byte = program_byte(program, current)
        if byte is None:
            return None
        values.append(byte)
        try:
            current = current.add(1)
        except Exception:
            return None
    if big_endian:
        result = 0
        for byte in values:
            result = (result << 8) | byte
        return result
    result = 0
    for shift, byte in enumerate(values):
        result |= byte << (shift * 8)
    return result


def program_c_string(program, address, max_bytes=4096):
    values = []
    current = address
    for _index in range(max_bytes):
        byte = program_byte(program, current)
        if byte is None:
            return None
        if byte == 0:
            try:
                return bytes(bytearray(values)).decode("utf-8", "replace")
            except Exception:
                return "".join(chr(item) for item in values)
        values.append(byte)
        try:
            current = current.add(1)
        except Exception:
            return None
    return None


DAT_TOKEN_RE = re.compile(r"^(?:DAT|s|u|PTR|PTR_s|PTR_DAT)_0*([0-9a-fA-F]+)$")


def resolve_format_string(program, token):
    literal = decode_c_string_literal(token)
    if literal is not None:
        return literal, {"source": "source_literal"}
    match = DAT_TOKEN_RE.match(str(token or "").strip())
    if not match or program is None:
        return None, {}
    literal_address = address_from(program, "0x" + match.group(1))
    if literal_address is None:
        return None, {}
    pointer = program_word(program, literal_address)
    if pointer is None:
        return None, {}
    pointee = address_from(program, pointer)
    if pointee is None:
        return None, {}
    resolved = program_c_string(program, pointee)
    if resolved is None:
        return None, {}
    return resolved, {
        "source": "literal_pool_pointer",
        "literal_pool_address": address_hex(literal_address),
        "format_address": address_hex(pointee),
    }


def _digits_for_integer_format(length_modifier, spec):
    signed = spec in "di"
    if length_modifier in ("ll", "j", "z", "t", "L"):
        bits = 64
    elif length_modifier in ("l",):
        bits = 64
    else:
        bits = 32
    if spec in "xX":
        digits = bits // 4
    elif spec == "o":
        digits = (bits + 2) // 3
    else:
        digits = 20 if bits > 32 else 10
    if signed:
        digits += 1
    return digits


def printf_format_upper_bound_bytes(format_text):
    text = str(format_text or "")
    total = 0
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char != "%":
            total += 1
            index += 1
            continue
        index += 1
        if index < length and text[index] == "%":
            total += 1
            index += 1
            continue
        while index < length and text[index] in "-+ #0'":
            index += 1
        width = 0
        if index < length and text[index] == "*":
            return None
        while index < length and text[index].isdigit():
            width = width * 10 + int(text[index])
            index += 1
        precision = None
        if index < length and text[index] == ".":
            index += 1
            if index < length and text[index] == "*":
                return None
            precision = 0
            while index < length and text[index].isdigit():
                precision = precision * 10 + int(text[index])
                index += 1
        length_modifier = ""
        if index + 1 < length and text[index : index + 2] in ("hh", "ll"):
            length_modifier = text[index : index + 2]
            index += 2
        elif index < length and text[index] in "hljztL":
            length_modifier = text[index]
            index += 1
        if index >= length:
            return None
        spec = text[index]
        index += 1
        if spec in "diuoxX":
            item_width = _digits_for_integer_format(length_modifier, spec)
            if precision is not None:
                item_width = max(item_width, precision)
            total += max(width, item_width)
            continue
        if spec == "c":
            total += max(width, 1)
            continue
        if spec == "p":
            total += max(width, 18)
            continue
        if spec == "s":
            if precision is None:
                return None
            total += max(width, precision)
            continue
        return None
    return total + 1


def snprintf_format_model(program, args):
    if str(args.get("sink_name") or "").lower() != "snprintf":
        return {}
    line_text = str(args.get("candidate_line_text") or args.get("line_text") or "")
    call_args = split_call_args(line_text)
    if len(call_args) < 3:
        return {}
    format_text, format_source = resolve_format_string(program, call_args[2])
    if format_text is None:
        return {}
    bound = printf_format_upper_bound_bytes(format_text)
    model = dict(format_source)
    model["kind"] = "constant_snprintf_format"
    model["format"] = format_text
    model["bounded"] = bound is not None
    if bound is not None:
        model["formatted_write_bound_bytes"] = bound
        args["formatted_write_bound_bytes"] = str(bound)
    return model


RAW_STACK_SLOT_RE = re.compile(
    r"(?:local|uStack|auStack|puStack|pcStack|pbStack|piStack)_[0-9a-fA-F]+|"
    r"[a-z]{1,3}Stack[0-9a-fA-F]+"
)


def stack_regions_from_program(program, function_address):
    function = None
    if function_address is not None:
        try:
            function = program.getFunctionManager().getFunctionAt(function_address)
        except Exception:
            function = None
        if function is None:
            try:
                function = program.getFunctionManager().getFunctionContaining(function_address)
            except Exception:
                function = None
    if function is None:
        return []
    try:
        stack_frame = function.getStackFrame()
        stack_vars = list(stack_frame.getStackVariables())
    except Exception:
        return []
    regions = []
    for var in stack_vars:
        try:
            start = int(var.getStackOffset())
            length = int(var.getLength())
        except Exception:
            continue
        if length <= 0:
            continue
        try:
            name = str(var.getName())
        except Exception:
            name = ""
        regions.append(
            {
                "start_offset": start,
                "end_offset": start + length,
                "size_bytes": length,
                "var_names": [name] if name else [],
            }
        )
    regions.sort(key=lambda item: (parse_int(item.get("start_offset")), parse_int(item.get("end_offset"))))
    return regions


def stack_regions_from_args(args):
    raw = args.get("stack_regions_json")
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
    except Exception:
        return []
    if not isinstance(decoded, list):
        return []
    regions = []
    for item in decoded:
        if isinstance(item, dict):
            regions.append(dict(item))
    regions.sort(key=lambda item: (parse_int(item.get("start_offset")), parse_int(item.get("end_offset"))))
    return regions


def _var_names(region):
    return [str(item) for item in region.get("var_names") or [] if item]


def _looks_like_raw_stack_slot(name):
    text = str(name or "")
    match = RAW_STACK_SLOT_RE.match(text)
    return bool(match and match.end() == len(text))


def infer_stack_aggregate_capacity(args, stack_regions, write_size):
    target_buffer = str(args.get("target_buffer") or "")
    if not target_buffer or write_size < 64 or len(stack_regions) < 3:
        return 0, {}
    target_region = None
    for region in stack_regions:
        if target_buffer in _var_names(region):
            target_region = region
            break
    if target_region is None or not _looks_like_raw_stack_slot(target_buffer):
        return 0, {}
    start = parse_int(target_region.get("start_offset"), 0)
    end = start + write_size
    span_regions = []
    for region in stack_regions:
        region_start = parse_int(region.get("start_offset"), 0)
        region_end = parse_int(region.get("end_offset"), 0)
        if start <= region_start < end and region_end <= end:
            span_regions.append(region)
    if not span_regions:
        return 0, {}
    if min(parse_int(region.get("start_offset"), 0) for region in span_regions) != start:
        return 0, {}
    if not any(parse_int(region.get("start_offset"), 0) == end for region in stack_regions):
        return 0, {}
    if not any(start < parse_int(region.get("start_offset"), 0) < end for region in span_regions):
        return 0, {}
    last_end = start
    max_gap = 0
    for region in sorted(span_regions, key=lambda item: (parse_int(item.get("start_offset"), 0), parse_int(item.get("end_offset"), 0))):
        region_start = parse_int(region.get("start_offset"), 0)
        region_end = parse_int(region.get("end_offset"), 0)
        if region_start > last_end:
            max_gap = max(max_gap, region_start - last_end)
        last_end = max(last_end, region_end)
    if end > last_end:
        max_gap = max(max_gap, end - last_end)
    if max_gap < max(32, write_size // 4):
        return 0, {}
    return write_size, {
        "kind": "decompiler_split_stack_aggregate",
        "source": "ghidra_stack_frame_layout",
        "target_start_offset": start,
        "aggregate_end_offset": end,
        "max_anonymous_gap_bytes": max_gap,
        "original_capacity_bytes": parse_int(args.get("capacity_bytes"), 0),
        "inferred_capacity_bytes": write_size,
    }


def sink_write_address(replay):
    sink_effect = replay.get("sink_effect") if isinstance(replay, dict) else {}
    if not isinstance(sink_effect, dict):
        return 0
    return parse_int(sink_effect.get("write_address"), 0) or parse_int(sink_effect.get("destination_address"), 0)


def modeled_runtime_allocation_for_address(replay, address):
    if address <= 0 or not isinstance(replay, dict):
        return {}
    matches = []
    for event in replay.get("modeled_runtime_calls") or []:
        if not isinstance(event, dict):
            continue
        base = parse_int(event.get("allocation_address"), 0)
        size = parse_int(event.get("allocation_size_bytes"), 0)
        if base <= 0 or size <= 0:
            continue
        if base <= address < base + size:
            matches.append((base, size, event))
    if not matches:
        return {}
    base, size, event = max(matches, key=lambda item: item[0])
    return {
        "kind": "modeled_runtime_allocation",
        "source": "modeled_runtime_allocation",
        "base_address": "0x%X" % base,
        "size_bytes": size,
        "allocation_event": event,
    }


def sink_runtime_allocation(replay):
    address = sink_write_address(replay)
    if address <= 0:
        sink_effect = replay.get("sink_effect") if isinstance(replay, dict) else {}
        if isinstance(sink_effect, dict):
            address = parse_int(sink_effect.get("object_base_address"), 0)
            if address <= 0:
                address = parse_int(sink_effect.get("source_address"), 0)
    return modeled_runtime_allocation_for_address(replay, address)


def resolved_capacity(args, stack_regions, write_size, replay=None):
    capacity = parse_int(args.get("capacity_bytes"), 0)
    source = str(args.get("capacity_source") or "")
    inference = {}
    destination_kind = str(args.get("destination_kind") or "").lower()
    if "stack" in destination_kind:
        inferred, inference = infer_stack_aggregate_capacity(args, stack_regions, write_size)
        if inferred > capacity:
            capacity = inferred
            source = "inferred_stack_aggregate_extent"
    elif "heap" in destination_kind and capacity <= 0:
        allocation = sink_runtime_allocation(replay or {})
        allocation_size = parse_int(allocation.get("size_bytes"), 0)
        if allocation_size > 0:
            capacity = allocation_size
            source = "modeled_runtime_allocation"
            inference = allocation
    return capacity, source, inference


def destination_model(destination_kind):
    lowered = str(destination_kind or "").lower()
    if "stack" in lowered:
        return {
            "supported": True,
            "kind": "stack",
            "write_range_kind": "modeled_stack_object_offsets",
            "read_range_kind": "modeled_stack_object_offsets",
            "object_range_kind": "modeled_stack_object_offsets",
        }
    if "heap" in lowered:
        return {
            "supported": True,
            "kind": "heap",
            "write_range_kind": "modeled_heap_allocation_offsets",
            "read_range_kind": "modeled_heap_allocation_offsets",
            "object_range_kind": "modeled_heap_allocation_offsets",
        }
    if "global" in lowered:
        return {
            "supported": True,
            "kind": "global",
            "write_range_kind": "modeled_memory_offsets",
            "read_range_kind": "modeled_memory_offsets",
            "object_range_kind": "modeled_memory_offsets",
        }
    if "source_buffer" in lowered:
        return {
            "supported": True,
            "kind": "source_buffer",
            "write_range_kind": "modeled_source_buffer_offsets",
            "read_range_kind": "modeled_source_buffer_offsets",
            "object_range_kind": "modeled_source_buffer_offsets",
        }
    return {
        "supported": False,
        "kind": lowered,
        "write_range_kind": "modeled_memory_offsets",
        "read_range_kind": "modeled_memory_offsets",
        "object_range_kind": "modeled_memory_offsets",
    }


def modeled_write_start_offset(args, replay):
    write_address = sink_write_address(replay)
    if write_address <= 0:
        return 0
    destination_kind = str(args.get("destination_kind") or "").lower()
    if "heap" in destination_kind:
        allocation = modeled_runtime_allocation_for_address(replay, write_address)
        base = parse_int(allocation.get("base_address"), 0)
        if base > 0 and write_address >= base:
            return write_address - base
    if "global" not in destination_kind:
        return 0
    target_buffer = str(args.get("target_buffer") or "")
    match = DAT_TOKEN_RE.match(target_buffer)
    if not match:
        return 0
    base = parse_int("0x" + match.group(1), 0)
    if base <= 0 or write_address < base:
        return 0
    return write_address - base


def is_oob_read_candidate(args):
    vulnerability_type = str(args.get("vulnerability_type") or "").lower()
    relation = str(args.get("write_relation") or "").lower()
    sink_name = normalized_api_name(args.get("sink_name"))
    return bool(
        vulnerability_type == "out_of_bounds_read"
        or relation in {"proven_oob_read", "symbolic_read_offset"}
        or sink_name == "array_load"
        or sink_name.endswith("_source_read")
    )


def concrete_sink_read_size(replay):
    if not isinstance(replay, dict):
        return 0
    sink_effect = replay.get("sink_effect")
    if not isinstance(sink_effect, dict):
        return 0
    return parse_int(sink_effect.get("read_bytes"), 0)


def modeled_read_size(args, replay=None):
    concrete_size = concrete_sink_read_size(replay)
    if concrete_size > 0:
        return concrete_size
    explicit = parse_int(args.get("write_size_bytes"), 0)
    if explicit > 0:
        return explicit
    return 0


def modeled_read_size_source(args, replay=None):
    if concrete_sink_read_size(replay) > 0:
        return "concrete_sink_effect"
    return "candidate"


def parsed_offset_expr(args):
    return parse_int(args.get("offset_expr"), None)


def modeled_read_start_offset(args, replay):
    sink_effect = replay.get("sink_effect") if isinstance(replay, dict) else {}
    if isinstance(sink_effect, dict):
        read_address = parse_int(sink_effect.get("source_address"), 0)
        if read_address > 0:
            destination_kind = str(args.get("destination_kind") or "").lower()
            target_buffer = str(args.get("target_buffer") or "")
            if "global" in destination_kind:
                match = DAT_TOKEN_RE.match(target_buffer)
                if match:
                    base = parse_int("0x" + match.group(1), 0)
                    if base > 0 and read_address >= base:
                        return read_address - base
            if "heap" in destination_kind:
                object_base = parse_int(sink_effect.get("object_base_address"), 0)
                allocation = modeled_runtime_allocation_for_address(replay, object_base or read_address)
                base = parse_int(allocation.get("base_address"), 0)
                if base > 0 and read_address >= base:
                    return read_address - base
    return parsed_offset_expr(args)


def range_overrun_bytes(start, size, capacity):
    if capacity <= 0 or size <= 0:
        return 0
    end = start + size
    if end <= capacity:
        return 0
    if start >= capacity:
        return size
    return end - capacity


def lifetime_proof_payload(args, replay, local_replay):
    candidate_id = args.get("candidate_id", "")
    sink_address = str(args.get("sink_address") or "")
    proof_scope = proof_scope_from_args(args)
    process_setup = replay.get("process_input_setup") if isinstance(replay.get("process_input_setup"), dict) else {}
    sink_effect = replay.get("sink_effect") if isinstance(replay.get("sink_effect"), dict) else {}
    violation = sink_effect.get("lifetime_violation") if isinstance(sink_effect.get("lifetime_violation"), dict) else {}
    expected = str(args.get("vulnerability_type") or "")
    observed = str(violation.get("vulnerability") or "")
    sink_reached = replay.get("status") == "reached"
    object_id = parse_int(violation.get("object_id"), 0)
    exact_invalid_release = (
        expected != "invalid_free"
        or (
            str(violation.get("reason") or "") == "release_address_is_not_object_base"
            and parse_int(violation.get("address"), 0) != parse_int(violation.get("object_base_address"), 0)
        )
    )
    status = "sink_unreached"
    reason = "exact_sink_not_reached"
    if proof_scope == "process_entrypoint" and process_setup.get("status") == "unsupported":
        status = "unsupported"
        reason = str(process_setup.get("reason") or "unsupported_process_input_setup")
    elif sink_reached and observed == expected and object_id > 0 and exact_invalid_release:
        status = "lifetime_violation_proven"
        reason = ""
    elif sink_reached and observed == expected and expected == "invalid_free":
        status = "unsupported"
        reason = "invalid_free_requires_allocation_derived_non_base_address"
    elif sink_reached and observed == expected:
        status = "unsupported"
        reason = "lifetime_violation_missing_object_identity"
    elif sink_reached:
        status = "no_lifetime_violation"
        reason = "expected_%s_observed_%s" % (expected, observed or "none")
    return {
        "schema_version": 1,
        "proof_kind": "ghidra_dynamic_memory_safety",
        "candidate_id": candidate_id,
        "status": status,
        "unsupported": status == "unsupported",
        "reason": reason,
        "proof_scope": proof_scope,
        "sink_reached": bool(sink_reached),
        "exact_sink_reached": bool(sink_reached),
        "sink_address": sink_address,
        "sink_name": str(args.get("sink_name") or ""),
        "vulnerability": expected,
        "observed_vulnerability": observed,
        "lifetime_violation": violation,
        "object_size_bytes": parse_int(violation.get("object_size_bytes"), 0),
        "object_identity": {
            "object_id": object_id,
            "base_address": str(violation.get("object_base_address") or ""),
            "size_bytes": parse_int(violation.get("object_size_bytes"), 0),
        },
        "harness_model": {
            "input_model": str(args.get("input_model") or ""),
            "concrete_input_hex": str(args.get("concrete_input_hex") or ""),
            "proof_scope": proof_scope,
            "path_replay_status": str(replay.get("status") or ""),
            "local_exact_sink_replay_status": str(local_replay.get("status") or ""),
            "process_input_setup_status": str(process_setup.get("status") or ""),
        },
        "process_input_setup": process_setup
        if proof_scope == "process_entrypoint"
        else process_setup
        if process_setup
        else {"status": "not_applicable", "reason": "function_harness_scope"},
        "process_replay": replay if proof_scope == "process_entrypoint" else {},
        "local_sink_probe": local_replay,
        "path_replay": replay,
        "local_exact_sink_replay": local_replay,
        "native_replay": {
            "status": "not_run",
            "reason": "Native, QEMU, and device replay are out of scope for this pipeline stage.",
        },
        "request": dict(args),
    }


def proof_payload(args, replay, local_replay, stack_regions=None):
    if str(args.get("vulnerability_type") or "") in {
        "use_after_free",
        "double_free",
        "invalid_free",
        "memory_leak",
        "mismatched_deallocator",
        "double_close",
        "use_after_close",
    }:
        return lifetime_proof_payload(args, replay, local_replay)
    candidate_id = args.get("candidate_id", "")
    sink_address = str(args.get("sink_address") or "")
    oob_read_candidate = is_oob_read_candidate(args)
    write_size = modeled_write_size(args, replay)
    write_size_source = modeled_write_size_source(args, replay)
    read_size = modeled_read_size(args, replay)
    read_size_source = modeled_read_size_source(args, replay)
    stack_regions = list(stack_regions or stack_regions_from_args(args))
    capacity, capacity_source, capacity_inference = resolved_capacity(
        args,
        stack_regions,
        read_size if oob_read_candidate else write_size,
        replay,
    )
    proof_scope = proof_scope_from_args(args)
    sink_reached = replay.get("status") == "reached"
    destination_kind = str(args.get("destination_kind") or "").lower()
    model = destination_model(destination_kind)
    write_start_offset = modeled_write_start_offset(args, replay)
    write_end_offset = write_start_offset + write_size
    read_start_offset = modeled_read_start_offset(args, replay)
    read_start_for_range = read_start_offset if read_start_offset is not None else 0
    read_end_offset = read_start_for_range + read_size
    overflow_bytes = max(0, write_end_offset - capacity) if capacity > 0 else 0
    oob_bytes = (
        range_overrun_bytes(read_start_for_range, read_size, capacity)
        if read_start_offset is not None
        else 0
    )
    status = "sink_unreached"
    reason = "exact_sink_not_reached"
    process_setup = replay.get("process_input_setup") if isinstance(replay.get("process_input_setup"), dict) else {}
    if proof_scope == "process_entrypoint" and process_setup.get("status") == "unsupported":
        status = "unsupported"
        reason = str(process_setup.get("reason") or "unsupported_process_input_setup")
    if sink_reached:
        if not model["supported"]:
            status = "unsupported"
            reason = "unsupported_destination_kind"
        elif oob_read_candidate and capacity <= 0:
            status = "unsupported"
            reason = "missing_source_capacity"
        elif oob_read_candidate and read_size <= 0:
            status = "unsupported"
            reason = "concrete_sink_read_size_unavailable"
        elif oob_read_candidate and read_start_offset is None:
            status = "unsupported"
            reason = "concrete_read_offset_unavailable"
        elif oob_read_candidate and oob_bytes > 0:
            status = "oob_read_proven"
            reason = ""
        elif oob_read_candidate:
            status = "no_oob_read"
            reason = "concrete_read_does_not_exceed_capacity"
        elif sink_requires_concrete_write_size(args) and write_size_source != "concrete_sink_effect":
            status = "unsupported"
            reason = "concrete_sink_write_size_unavailable"
        elif capacity <= 0:
            status = "unsupported"
            reason = "missing_destination_capacity"
        elif overflow_bytes > 0:
            status = "overflow_proven"
            reason = ""
        else:
            status = "no_overflow"
            reason = "concrete_write_does_not_exceed_capacity"
    reported_overflow_bytes = overflow_bytes if status == "overflow_proven" else 0
    reported_oob_bytes = oob_bytes if status == "oob_read_proven" else 0
    target_buffer = str(args.get("target_buffer") or "")
    sink_effect_model = args.get("sink_effect_model") or {}
    if isinstance(sink_effect_model, str):
        try:
            sink_effect_model = json.loads(sink_effect_model)
        except Exception:
            sink_effect_model = {}
    write_range = {
        "range_kind": model["write_range_kind"],
        "base": target_buffer,
        "start_offset": write_start_offset,
        "end_offset_exclusive": write_end_offset,
        "size_bytes": write_size,
    }
    read_range = {
        "range_kind": model["read_range_kind"],
        "base": target_buffer,
        "start_offset": read_start_for_range,
        "end_offset_exclusive": read_end_offset,
        "size_bytes": read_size,
    }
    object_range = {
        "range_kind": model["object_range_kind"],
        "base": target_buffer,
        "start_offset": 0,
        "end_offset_exclusive": capacity,
        "size_bytes": capacity,
    }
    payload = {
        "schema_version": 1,
        "proof_kind": "ghidra_dynamic_overflow",
        "candidate_id": candidate_id,
        "status": status,
        "unsupported": status == "unsupported",
        "reason": reason,
        "proof_scope": proof_scope,
        "sink_reached": bool(sink_reached),
        "exact_sink_reached": bool(sink_reached),
        "sink_address": sink_address,
        "sink_name": str(args.get("sink_name") or ""),
        "target_buffer": target_buffer,
        "destination_kind": str(args.get("destination_kind") or ""),
        "write_size_bytes": write_size,
        "write_size_source": write_size_source,
        "read_size_bytes": read_size,
        "read_size_source": read_size_source,
        "capacity_bytes": capacity,
        "capacity_source": capacity_source,
        "capacity_basis": str(args.get("capacity_basis") or ""),
        "capacity_inference": capacity_inference,
        "overflow_bytes": reported_overflow_bytes,
        "oob_bytes": reported_oob_bytes,
        "write_range": write_range,
        "read_range": read_range,
        "object_range": object_range,
        "harness_model": {
            "input_model": str(args.get("input_model") or ""),
            "concrete_input_hex": str(args.get("concrete_input_hex") or ""),
            "proof_scope": proof_scope,
            "path_replay_status": str(replay.get("status") or ""),
            "local_exact_sink_replay_status": str(local_replay.get("status") or ""),
            "process_input_setup_status": str(process_setup.get("status") or ""),
            "process_replay_status": str(replay.get("status") or "") if proof_scope == "process_entrypoint" else "",
            "local_sink_probe_status": str(local_replay.get("status") or ""),
        },
        "sink_effect_model": sink_effect_model if isinstance(sink_effect_model, dict) else {},
        "process_input_setup": process_setup
        if proof_scope == "process_entrypoint"
        else process_setup
        if process_setup
        else {"status": "not_applicable", "reason": "function_harness_scope"},
        "process_replay": replay if proof_scope == "process_entrypoint" else {},
        "local_sink_probe": local_replay,
        "path_replay": replay,
        "local_exact_sink_replay": local_replay,
        "native_replay": {
            "status": "not_run",
            "reason": "Native, QEMU, and device replay are out of scope for this pipeline stage.",
        },
        "request": dict(args),
    }
    return payload


def main():
    args = parse_kv_args(getScriptArgs())
    output_path = args.get("output_path")
    candidate_id = args.get("candidate_id", "")
    if not output_path:
        println("dynamic_overflow_proof.py: missing output_path")
        return
    program = currentProgram
    args = dict(args)
    sink_effect_model = snprintf_format_model(program, args)
    if sink_effect_model:
        args["sink_effect_model"] = sink_effect_model
    sink_address = address_from(program, args.get("sink_address"))
    if sink_address is None:
        write_json(output_path, unsupported(candidate_id, "invalid_sink_address", args))
        return
    start_address = address_from(program, args.get("start_address")) or sink_address
    max_steps = parse_int(args.get("max_steps"), 2048)
    timeout_ms = parse_int(args.get("timeout_ms"), 30000)
    if max_steps <= 0:
        max_steps = 2048
    if timeout_ms <= 0:
        timeout_ms = 30000
    proof_scope = proof_scope_from_args(args)
    if proof_scope == "process_entrypoint" and str(args.get("input_model") or "") not in {
        "argv",
        "stdin",
        "file",
        "env",
        "env_file",
        "argv_file_stdin",
        "argv_directory",
        "socket_service",
        "http_daemon",
    }:
        write_json(
            output_path,
            unsupported(
                candidate_id,
                "unsupported_process_input_setup:input_model_%s" % str(args.get("input_model") or ""),
                args,
            ),
        )
        return
    stack_regions = stack_regions_from_program(program, address_from(program, args.get("function_address")))
    replay = concrete_emulator_replay(
        program,
        start_address,
        sink_address,
        max_steps,
        timeout_ms,
        args,
    )
    local_replay = concrete_emulator_replay(program, sink_address, sink_address, 1, timeout_ms)
    record_static_path_hits(replay, args)
    record_static_path_hits(local_replay, args)
    compact_instruction_trace(replay)
    compact_instruction_trace(local_replay)
    payload = proof_payload(args, replay, local_replay, stack_regions)
    write_json(output_path, payload)


if __name__ == "__main__":
    main()
