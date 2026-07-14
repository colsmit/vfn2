import importlib.util
from pathlib import Path
from typing import Any

import pytest


def _load_script_module():
    script_path = Path(__file__).resolve().parents[1] / "ghidra_scripts" / "dynamic_overflow_proof.py"
    spec = importlib.util.spec_from_file_location("dynamic_overflow_proof", script_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _FakeAddress:
    def __init__(self, offset: int) -> None:
        self._offset = offset

    def add(self, amount: int) -> "_FakeAddress":
        return _FakeAddress(self._offset + amount)

    def getOffset(self) -> int:
        return self._offset

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _FakeAddress) and self._offset == other._offset


class _FakeAddressSpace:
    def getAddress(self, offset: int) -> _FakeAddress:
        return _FakeAddress(offset)


class _FakeAddressFactory:
    def getDefaultAddressSpace(self) -> _FakeAddressSpace:
        return _FakeAddressSpace()


class _FakeLanguage:
    def __init__(self, processor: str, pointer_size: int) -> None:
        self._processor = processor
        self._pointer_size = pointer_size

    def getLanguageID(self) -> str:
        return f"{self._processor}:LE:{self._pointer_size * 8}:default"

    def getProcessor(self) -> str:
        return self._processor

    def isBigEndian(self) -> bool:
        return False


class _FakeRegister:
    def __init__(self, name: str) -> None:
        self._name = name

    def getName(self) -> str:
        return self._name


class _FakeCompilerSpec:
    def __init__(self, stack_register: str) -> None:
        self._stack_register = _FakeRegister(stack_register)

    def getStackPointer(self) -> _FakeRegister:
        return self._stack_register


class _FakeProgram:
    def __init__(self, processor: str, pointer_size: int, stack_register: str) -> None:
        self._language = _FakeLanguage(processor, pointer_size)
        self._pointer_size = pointer_size
        self._compiler_spec = _FakeCompilerSpec(stack_register)
        self.functions: dict[int, object] = {}
        self.symbols: dict[str, _FakeAddress] = {}

    def getLanguage(self) -> _FakeLanguage:
        return self._language

    def getDefaultPointerSize(self) -> int:
        return self._pointer_size

    def getAddressFactory(self) -> _FakeAddressFactory:
        return _FakeAddressFactory()

    def getCompilerSpec(self) -> _FakeCompilerSpec:
        return self._compiler_spec

    def getRegister(self, name: str) -> _FakeRegister:
        return _FakeRegister(name)

    def getFunctionManager(self):
        return self

    def getFunctionAt(self, address: _FakeAddress):
        return self.functions.get(address.getOffset())

    def getFunctionContaining(self, address: _FakeAddress):
        return self.functions.get(address.getOffset())

    def getSymbolTable(self):
        return _FakeSymbolTable(self.symbols)


class _FakeSymbol:
    def __init__(self, address: _FakeAddress) -> None:
        self._address = address

    def getAddress(self) -> _FakeAddress:
        return self._address


class _FakeSymbolTable:
    def __init__(self, symbols: dict[str, _FakeAddress]) -> None:
        self._symbols = symbols

    def getGlobalSymbols(self, name: str) -> list[_FakeSymbol]:
        address = self._symbols.get(name)
        return [_FakeSymbol(address)] if address is not None else []

    def getSymbol(self, name: str) -> _FakeSymbol | None:
        address = self._symbols.get(name)
        return _FakeSymbol(address) if address is not None else None


class _FakeFunction:
    def __init__(self, name: str, *, external: bool = False, thunk: bool = False) -> None:
        self._name = name
        self._external = external
        self._thunk = thunk

    def getName(self) -> str:
        return self._name

    def isExternal(self) -> bool:
        return self._external

    def isThunk(self) -> bool:
        return self._thunk


class _FakeFlowType:
    def __init__(self, is_call: bool = True) -> None:
        self._is_call = is_call

    def isCall(self) -> bool:
        return self._is_call


class _FakeInstruction:
    def __init__(
        self,
        address: int,
        target: int | None,
        fallthrough: int,
        *,
        mnemonic: str = "CALL",
        operands: list[list[object]] | None = None,
        operand_representations: list[str] | None = None,
        is_call: bool = True,
    ) -> None:
        self._address = _FakeAddress(address)
        self._target = _FakeAddress(target) if target is not None else None
        self._fallthrough = _FakeAddress(fallthrough)
        self._mnemonic = mnemonic
        self._operands = operands or []
        self._operand_representations = operand_representations or []
        self._is_call = is_call

    def getAddress(self) -> _FakeAddress:
        return self._address

    def getFlowType(self) -> _FakeFlowType:
        return _FakeFlowType(self._is_call)

    def getFlows(self) -> list[_FakeAddress]:
        return [self._target] if self._target is not None else []

    def getFallThrough(self) -> _FakeAddress:
        return self._fallthrough

    def getMnemonicString(self) -> str:
        return self._mnemonic

    def getNumOperands(self) -> int:
        return len(self._operands)

    def getOpObjects(self, index: int) -> list[object]:
        return self._operands[index]

    def getDefaultOperandRepresentation(self, index: int) -> str:
        if index < len(self._operand_representations):
            return self._operand_representations[index]
        return ""

    def __str__(self) -> str:
        return self._mnemonic


class _FakeHelper:
    def __init__(self) -> None:
        self.registers: dict[str, int] = {}
        self.memory: dict[int, int] = {}

    def writeRegister(self, register, value: int) -> None:
        name = register.getName() if hasattr(register, "getName") else str(register)
        self.registers[name] = int(value)

    def readRegister(self, register) -> int:
        name = register.getName() if hasattr(register, "getName") else str(register)
        return self.registers[name]

    def writeMemoryValue(self, address: _FakeAddress, _size: int, value: int) -> None:
        self.memory[address.getOffset()] = int(value) & 0xFF

    def readMemoryValue(self, address: _FakeAddress, _size: int) -> int:
        return self.memory.get(address.getOffset(), 0)


def test_getopt_long_model_returns_eof_for_non_option_argv_and_sets_optind() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("getopt_long", external=True)
    program.symbols["optind"] = _FakeAddress(0x7000)
    argv = 0x5000
    program_name = 0x6000
    input_name = 0x6100
    module.write_memory_bytes(program, helper, argv, module.pointer_bytes(program_name, 8, False))
    module.write_memory_bytes(program, helper, argv + 8, module.pointer_bytes(input_name, 8, False))
    module.write_memory_bytes(program, helper, argv + 16, module.pointer_bytes(0, 8, False))
    module.write_memory_bytes(program, helper, program_name, [ord(c) for c in "program"] + [0])
    module.write_memory_bytes(program, helper, input_name, [ord(c) for c in "input.txt"] + [0])
    helper.writeRegister("RDI", 2)
    helper.writeRegister("RSI", argv)
    instruction = _FakeInstruction(0x400100, 0x401000, 0x400105)

    event = module.modeled_runtime_call(program, helper, instruction, _FakeAddress(0x402000), {}, {})

    assert event["status"] == "modeled"
    assert event["function_model"] == "getopt_long"
    assert event["result"] == -1
    assert event["optind"] == 1
    assert event["optind_write_status"] == "written"
    assert helper.registers["RAX"] == -1
    assert helper.memory[0x7000] == 1
    assert helper.memory[0x7001] == 0


def test_getopt_long_model_keeps_option_parsing_explicitly_unsupported() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("getopt_long", external=True)
    argv = 0x5000
    program_name = 0x6000
    option = 0x6100
    module.write_memory_bytes(program, helper, argv, module.pointer_bytes(program_name, 8, False))
    module.write_memory_bytes(program, helper, argv + 8, module.pointer_bytes(option, 8, False))
    module.write_memory_bytes(program, helper, argv + 16, module.pointer_bytes(0, 8, False))
    module.write_memory_bytes(program, helper, program_name, [ord(c) for c in "program"] + [0])
    module.write_memory_bytes(program, helper, option, [ord("-"), ord("x"), 0])
    helper.writeRegister("RDI", 2)
    helper.writeRegister("RSI", argv)
    instruction = _FakeInstruction(0x400100, 0x401000, 0x400105)

    event = module.modeled_runtime_call(program, helper, instruction, _FakeAddress(0x402000), {}, {})

    assert event["status"] == "unsupported"
    assert event["reason"] == "unsupported_runtime_call:getopt_long_option_parsing_unsupported"


def test_getopt_long_model_parses_short_option_with_required_argument() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("getopt_long", external=True)
    program.symbols["optind"] = _FakeAddress(0x7000)
    program.symbols["optarg"] = _FakeAddress(0x7010)
    argv = 0x5000
    program_name = 0x6000
    option = 0x6100
    option_argument = 0x6200
    optstring = 0x6300
    module.write_memory_bytes(program, helper, argv, module.pointer_bytes(program_name, 8, False))
    module.write_memory_bytes(program, helper, argv + 8, module.pointer_bytes(option, 8, False))
    module.write_memory_bytes(program, helper, argv + 16, module.pointer_bytes(option_argument, 8, False))
    module.write_memory_bytes(program, helper, argv + 24, module.pointer_bytes(0, 8, False))
    module.write_memory_bytes(program, helper, program_name, [ord(c) for c in "program"] + [0])
    module.write_memory_bytes(program, helper, option, [ord("-"), ord("o"), 0])
    module.write_memory_bytes(program, helper, option_argument, [ord("A")] * 8 + [0])
    module.write_memory_bytes(program, helper, optstring, [ord("o"), ord(":"), 0])
    helper.writeRegister("RDI", 3)
    helper.writeRegister("RSI", argv)
    helper.writeRegister("RDX", optstring)
    helper.writeRegister("RCX", 0)
    helper.writeRegister("R8", 0)
    instruction = _FakeInstruction(0x400100, 0x401000, 0x400105)

    event = module.modeled_runtime_call(program, helper, instruction, _FakeAddress(0x402000), {}, {})

    assert event["status"] == "modeled"
    assert event["function_model"] == "getopt_long"
    assert event["result"] == ord("o")
    assert event["option"] == "o"
    assert event["optarg_address"] == "0x6200"
    assert event["optarg_write_status"] == "written"
    assert event["optind"] == 3
    assert event["optind_write_status"] == "written"
    assert helper.registers["RAX"] == ord("o")
    assert module.read_memory_integer(program, helper, 0x7000, 4, False) == 3
    assert module.read_memory_integer(program, helper, 0x7010, 8, False) == option_argument


def test_getopt_long_model_parses_grouped_no_argument_short_options() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("getopt_long", external=True)
    program.symbols["optind"] = _FakeAddress(0x7000)
    program.symbols["optarg"] = _FakeAddress(0x7010)
    argv = 0x5000
    program_name = 0x6000
    option_group = 0x6100
    optstring = 0x6200
    module.write_memory_bytes(program, helper, argv, module.pointer_bytes(program_name, 8, False))
    module.write_memory_bytes(program, helper, argv + 8, module.pointer_bytes(option_group, 8, False))
    module.write_memory_bytes(program, helper, argv + 16, module.pointer_bytes(0, 8, False))
    module.write_memory_bytes(program, helper, program_name, [ord(c) for c in "program"] + [0])
    module.write_memory_bytes(program, helper, option_group, [ord("-"), ord("R"), ord("f"), 0])
    module.write_memory_bytes(program, helper, optstring, [ord("R"), ord("f"), 0])
    helper.writeRegister("RDI", 2)
    helper.writeRegister("RSI", argv)
    helper.writeRegister("RDX", optstring)
    helper.writeRegister("RCX", 0)
    helper.writeRegister("R8", 0)
    instruction = _FakeInstruction(0x400100, 0x401000, 0x400105)
    runtime_state: dict[str, Any] = {}

    first = module.modeled_runtime_call(program, helper, instruction, _FakeAddress(0x402000), {}, runtime_state)
    second = module.modeled_runtime_call(program, helper, instruction, _FakeAddress(0x402000), {}, runtime_state)
    final = module.modeled_runtime_call(program, helper, instruction, _FakeAddress(0x402000), {}, runtime_state)

    assert first["status"] == "modeled"
    assert first["option"] == "R"
    assert first["short_option_group_pending"] is True
    assert first["optind"] == 1
    assert second["status"] == "modeled"
    assert second["option"] == "f"
    assert second["short_option_group_pending"] is False
    assert second["optind"] == 2
    assert final["result"] == -1
    assert final["optind"] == 2
    assert module.read_memory_integer(program, helper, 0x7000, 4, False) == 2


def test_runtime_getenv_is_absent_for_non_env_process_inputs() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("getenv", external=True)
    variable = 0x6000
    module.write_memory_bytes(program, helper, variable, [ord(c) for c in "UNZIP"] + [0])
    helper.writeRegister("RDI", variable)
    instruction = _FakeInstruction(0x400100, 0x401000, 0x400105)

    event = module.modeled_runtime_call(
        program,
        helper,
        instruction,
        _FakeAddress(0x402000),
        {"input_model": "argv_directory"},
        {},
    )

    assert event["status"] == "modeled"
    assert event["function_model"] == "getenv"
    assert event["environment_model"] == "absent"
    assert helper.registers["RAX"] == 0


def test_stdin_runtime_models_errno_and_unconfigured_paths_as_absent() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("__errno_location", external=True)
    program.functions[0x401010] = _FakeFunction("fstatat", external=True)
    path = 0x6000
    stat_buffer = 0x6100
    module.write_memory_bytes(program, helper, path, module.ascii_bytes("missing-target") + [0])
    setup = {"input_model": "stdin", **module.program_abi(program)}
    runtime_state: dict[str, Any] = {}

    errno_event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x400000, 0x401000, 0x400005),
        _FakeAddress(0x402000),
        setup,
        runtime_state,
    )
    helper.registers.update({"RDI": -100, "RSI": path, "RDX": stat_buffer, "RCX": 0})
    stat_event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x400005, 0x401010, 0x40000A),
        _FakeAddress(0x402000),
        setup,
        runtime_state,
    )

    errno_address = int(errno_event["errno_address"], 16)
    assert stat_event["result"] == -1
    assert stat_event["filesystem_model"] == "unconfigured_path_absent"
    assert module.read_memory_integer(program, helper, errno_address, 4, False) == 2
    assert helper.registers["RAX"] == -1


def test_runtime_strrchr_returns_last_matching_character() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("strrchr", external=True)
    source = 0x6000
    module.write_memory_bytes(program, helper, source, [ord(c) for c in "aa/bb/cc"] + [0])
    helper.writeRegister("RDI", source)
    helper.writeRegister("RSI", ord("/"))
    instruction = _FakeInstruction(0x400100, 0x401000, 0x400105)

    event = module.modeled_runtime_call(program, helper, instruction, _FakeAddress(0x402000), {}, {})

    assert event["status"] == "modeled"
    assert event["function_model"] == "strrchr"
    assert event["result"] == "0x6005"
    assert helper.registers["RAX"] == 0x6005


def test_runtime_string_search_and_numeric_models_preserve_library_control_flow() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    source = 0x6000
    accepted = 0x6100
    endptr = 0x6200
    module.write_memory_bytes(program, helper, source, module.ascii_bytes("270:tail") + [0])
    module.write_memory_bytes(program, helper, accepted, module.ascii_bytes(":/") + [0])

    def call(name: str, arguments: tuple[int, ...]):
        program.functions[0x401000] = _FakeFunction(name, external=True)
        for register, value in zip(("RDI", "RSI", "RDX"), arguments):
            helper.writeRegister(register, value)
        return module.modeled_runtime_call(
            program,
            helper,
            _FakeInstruction(0x400100, 0x401000, 0x400105),
            _FakeAddress(0x402000),
            {},
            {},
        )

    assert call("strchr", (source, ord(":")))["result"] == "0x6003"
    assert call("strpbrk", (source, accepted))["result"] == "0x6003"
    assert call("tolower", (ord("R"),))["result"] == ord("r")
    number = call("strtoul", (source, endptr, 10))
    assert number["result"] == 270
    assert module.read_memory_integer(program, helper, endptr, 8, False) == source + 3


def test_runtime_atof_writes_xmm0_double_bits() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("atof", external=True)
    source = 0x6000
    module.write_memory_bytes(program, helper, source, module.ascii_bytes("10.5") + [0])
    helper.writeRegister("RDI", source)

    event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x400100, 0x401000, 0x400105),
        _FakeAddress(0x402000),
        {},
        {},
    )

    assert event["result"] == 10.5
    assert helper.registers["XMM0"] == 0x4025000000000000


def test_runtime_sprintf_materializes_simple_variadic_format() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("sprintf", external=True)
    destination = 0x6000
    format_address = 0x6100
    string_address = 0x6200
    module.write_memory_bytes(program, helper, format_address, module.ascii_bytes("%s/p%cXXXXXX") + [0])
    module.write_memory_bytes(program, helper, string_address, module.ascii_bytes("/tmp") + [0])
    helper.registers.update({"RDI": destination, "RSI": format_address, "RDX": string_address, "RCX": ord("o")})

    event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x400000, 0x401000, 0x400005),
        _FakeAddress(0x402000),
        {},
        {},
    )

    assert event["status"] == "modeled"
    assert module.read_memory_c_string(program, helper, destination) == "/tmp/poXXXXXX"
    assert helper.registers["RAX"] == len("/tmp/poXXXXXX")


def test_runtime_model_access_accepts_concrete_process_input_path() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("access", external=True)
    path = b"/tmp/input"
    path_address = 0x6000
    module.write_memory_bytes(program, helper, path_address, list(path) + [0])
    helper.writeRegister("RDI", path_address)
    helper.writeRegister("RSI", 0)
    process_setup = {
        "input_model": "argv",
        "concrete_input_hex": path.hex(),
        "input_size_bytes": str(len(path)),
    }
    instruction = _FakeInstruction(0x400100, 0x401000, 0x400105)

    event = module.modeled_runtime_call(program, helper, instruction, _FakeAddress(0x402000), process_setup, {})

    assert event["status"] == "modeled"
    assert event["function_model"] == "access"
    assert event["source"] == "argv"
    assert event["path_address"] == "0x6000"
    assert event["path_size_bytes"] == len(path)
    assert event["result"] == 0
    assert helper.registers["RAX"] == 0


def test_runtime_model_stat_writes_deterministic_file_metadata() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("stat", external=True)
    path = b"/tmp/input"
    path_address = 0x6000
    stat_address = 0x7000
    module.write_memory_bytes(program, helper, path_address, list(path) + [0])
    helper.writeRegister("RDI", path_address)
    helper.writeRegister("RSI", stat_address)
    process_setup = {
        "input_model": "argv",
        "concrete_input_hex": path.hex(),
        "input_size_bytes": str(len(path)),
    }
    instruction = _FakeInstruction(0x400100, 0x401000, 0x400105)

    event = module.modeled_runtime_call(program, helper, instruction, _FakeAddress(0x402000), process_setup, {})

    assert event["status"] == "modeled"
    assert event["function_model"] == "stat"
    assert event["source"] == "argv"
    assert event["result"] == 0
    assert event["stat_buffer_address"] == "0x7000"
    assert helper.registers["RAX"] == 0
    assert module.read_memory_integer(program, helper, stat_address + 24, 4, False) == 0o100644
    assert module.read_memory_integer(program, helper, stat_address + 48, 8, False) == len(path)


def test_runtime_model_open_allocates_fd_for_process_input_file_name() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("open", external=True)
    path = b"input.txt"
    path_address = 0x6000
    runtime_state: dict[str, object] = {}
    module.write_memory_bytes(program, helper, path_address, list(path) + [0])
    helper.writeRegister("RDI", path_address)
    helper.writeRegister("RSI", 0)
    process_setup = {"input_model": "argv_file", "file_name": path.decode("ascii"), "input_size_bytes": "9"}
    instruction = _FakeInstruction(0x400100, 0x401000, 0x400105)

    event = module.modeled_runtime_call(
        program,
        helper,
        instruction,
        _FakeAddress(0x402000),
        process_setup,
        runtime_state,
    )

    assert event["status"] == "modeled"
    assert event["function_model"] == "open"
    assert event["source"] == "file_name"
    assert event["fd"] == 3
    assert event["result"] == 3
    assert helper.registers["RAX"] == 3
    assert runtime_state["descriptors"][3]["source"] == "file_name"


def test_runtime_model_opendir_readdir_returns_modeled_directory_entry() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("opendir", external=True)
    program.functions[0x401100] = _FakeFunction("readdir", external=True)
    directory = b"input_dir/"
    entry = b"A" * 32
    path_address = 0x6000
    runtime_state: dict[str, object] = {}
    process_setup = {
        "input_model": "argv_directory",
        "file_name": "input_dir",
        "concrete_input_hex": entry.hex(),
        "abi": "x86_64_sysv",
        "pointer_size_bytes": 8,
        "endianness": "little",
    }
    module.write_memory_bytes(program, helper, path_address, list(directory) + [0])
    helper.writeRegister("RDI", path_address)

    open_event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x400100, 0x401000, 0x400105),
        _FakeAddress(0x402000),
        process_setup,
        runtime_state,
    )

    handle = int(open_event["directory_handle"], 16)
    helper.writeRegister("RDI", handle)
    read_event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x400105, 0x401100, 0x40010A),
        _FakeAddress(0x402000),
        process_setup,
        runtime_state,
    )

    assert open_event["status"] == "modeled"
    assert open_event["source"] == "directory_name"
    assert read_event["status"] == "modeled"
    assert read_event["function_model"] == "readdir"
    assert read_event["directory_entry_size_bytes"] == len(entry)
    assert module.read_memory_c_bytes(program, helper, int(read_event["d_name_address"], 16)) == list(entry)
    assert helper.registers["RAX"] == int(read_event["dirent_address"], 16)


def test_runtime_model_rejects_ambiguous_unmatched_path() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    program.functions[0x401000] = _FakeFunction("open", external=True)
    path_address = 0x6000
    module.write_memory_bytes(program, helper, path_address, list(b"/etc/passwd") + [0])
    helper.writeRegister("RDI", path_address)
    helper.writeRegister("RSI", 0)
    process_setup = {
        "input_model": "argv",
        "concrete_input_hex": b"/tmp/input".hex(),
        "input_size_bytes": "10",
    }
    instruction = _FakeInstruction(0x400100, 0x401000, 0x400105)

    event = module.modeled_runtime_call(program, helper, instruction, _FakeAddress(0x402000), process_setup, {})

    assert event["status"] == "unsupported"
    assert event["reason"] == "unsupported_runtime_call:open_path_not_modeled_process_input"
    assert "RAX" not in helper.registers


def test_argv_process_setup_honors_explicit_argv_values() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    helper = _FakeHelper()
    argv_values = [b"program", b"-o", b"A" * 80]
    args = {
        "input_model": "argv",
        "concrete_input_hex": (b"A" * 80).hex(),
        "argv_values_hex": ",".join(value.hex() for value in argv_values),
    }

    setup = module.setup_argv_process_input(program, helper, args, 0x7FFFF000)

    assert setup["status"] == "configured"
    assert setup["argc"] == 3
    assert setup["argv_values"] == ["program", "-o", "A" * 80]
    assert setup["input_arg_index"] == 2
    argv_address = int(setup["argv_address"], 16)
    third_arg = module.read_memory_integer(program, helper, argv_address + 16, 8, False)
    assert module.read_memory_c_bytes(program, helper, third_arg) == [ord("A")] * 80


def test_dynamic_proof_uses_decompiler_split_stack_aggregate_extent() -> None:
    module = _load_script_module()
    args = {
        "candidate_id": "demo",
        "sink_address": "0x12028",
        "sink_name": "memcpy",
        "target_buffer": "local_258",
        "destination_kind": "stack",
        "capacity_bytes": "12",
        "write_size_bytes": "0x200",
        "input_model": "function_harness",
    }
    stack_regions = [
        {"start_offset": -0x258, "end_offset": -0x254, "size_bytes": 4, "var_names": ["local_258"]},
        {"start_offset": -0x24C, "end_offset": -0x248, "size_bytes": 4, "var_names": ["local_24c"]},
        {"start_offset": -0x58, "end_offset": -0x54, "size_bytes": 4, "var_names": ["local_58"]},
    ]

    payload = module.proof_payload(args, {"status": "reached"}, {"status": "stopped"}, stack_regions)

    assert payload["status"] == "no_overflow"
    assert payload["capacity_bytes"] == 0x200
    assert payload["capacity_source"] == "inferred_stack_aggregate_extent"
    assert payload["capacity_inference"]["kind"] == "decompiler_split_stack_aggregate"
    assert payload["overflow_bytes"] == 0


def test_dynamic_proof_supports_global_destination_overflow() -> None:
    module = _load_script_module()
    args = {
        "candidate_id": "demo",
        "sink_address": "0x403c31",
        "sink_name": "strcpy",
        "target_buffer": "DAT_0045ed00",
        "destination_kind": "global",
        "capacity_bytes": "1024",
        "write_size_bytes": "1025",
        "input_model": "argv",
        "proof_scope": "process_entrypoint",
    }

    replay = {"status": "reached", "sink_effect": {"status": "modeled", "written_bytes": 1025}}
    payload = module.proof_payload(args, replay, {"status": "reached"})

    assert payload["status"] == "overflow_proven"
    assert payload["overflow_bytes"] == 1
    assert payload["write_size_source"] == "concrete_sink_effect"
    assert payload["write_range"]["range_kind"] == "modeled_memory_offsets"
    assert payload["object_range"]["range_kind"] == "modeled_memory_offsets"


def test_dynamic_proof_rejects_string_overflow_without_concrete_sink_effect() -> None:
    module = _load_script_module()
    args = {
        "candidate_id": "demo",
        "sink_address": "0x403c31",
        "sink_name": "strcpy",
        "target_buffer": "DAT_0045ed00",
        "destination_kind": "global",
        "capacity_bytes": "1024",
        "write_size_bytes": "1025",
        "input_model": "argv",
        "proof_scope": "process_entrypoint",
    }

    payload = module.proof_payload(args, {"status": "reached"}, {"status": "reached"})

    assert payload["status"] == "unsupported"
    assert payload["reason"] == "concrete_sink_write_size_unavailable"
    assert payload["write_size_source"] == "candidate_or_input_model"


def test_dynamic_proof_proves_heap_allocation_overflow() -> None:
    module = _load_script_module()
    args = {
        "candidate_id": "demo",
        "sink_address": "0x155f0",
        "sink_name": "snprintf",
        "target_buffer": "__s",
        "destination_kind": "heap",
        "capacity_bytes": "1",
        "capacity_source": "local_operator_new",
        "capacity_basis": "__s: local_operator_new capacity 1 bytes",
        "write_size_bytes": "0x80",
        "input_model": "function_harness",
    }

    payload = module.proof_payload(args, {"status": "reached"}, {"status": "stopped"}, [])

    assert payload["status"] == "overflow_proven"
    assert payload["capacity_bytes"] == 1
    assert payload["capacity_source"] == "local_operator_new"
    assert payload["write_size_bytes"] == 0x80
    assert payload["overflow_bytes"] == 0x7F
    assert payload["write_range"]["range_kind"] == "modeled_heap_allocation_offsets"
    assert payload["object_range"]["range_kind"] == "modeled_heap_allocation_offsets"


def test_dynamic_proof_uses_modeled_heap_allocation_for_symbolic_capacity() -> None:
    module = _load_script_module()
    args = {
        "candidate_id": "demo",
        "sink_address": "0x155f0",
        "sink_name": "strcpy",
        "target_buffer": "buf",
        "destination_kind": "heap",
        "capacity_bytes": "0",
        "capacity_source": "local_malloc",
        "capacity_basis": "buf: local_malloc capacity left_len + right_len + 2",
        "write_size_bytes": "0",
        "input_model": "function_harness",
    }
    replay = {
        "status": "reached",
        "modeled_runtime_calls": [
            {
                "status": "modeled",
                "function_model": "malloc",
                "allocation_address": "0x70000000",
                "allocation_size_bytes": 16,
            }
        ],
        "sink_effect": {
            "status": "modeled",
            "function_model": "strcpy",
            "destination_address": "0x70000000",
            "write_address": "0x70000008",
            "written_bytes": 24,
        },
    }

    payload = module.proof_payload(args, replay, {"status": "stopped"}, [])

    assert payload["status"] == "overflow_proven"
    assert payload["capacity_bytes"] == 16
    assert payload["capacity_source"] == "modeled_runtime_allocation"
    assert payload["capacity_inference"]["base_address"] == "0x70000000"
    assert payload["write_range"]["start_offset"] == 8
    assert payload["write_range"]["end_offset_exclusive"] == 32
    assert payload["overflow_bytes"] == 16


def test_dynamic_proof_uses_direct_heap_read_address_for_symbolic_capacity() -> None:
    module = _load_script_module()
    args = {
        "candidate_id": "demo",
        "sink_address": "0x10618c",
        "sink_name": "pointer_load",
        "vulnerability_type": "out_of_bounds_read",
        "write_relation": "symbolic_read_offset",
        "target_buffer": "table",
        "destination_kind": "heap",
        "capacity_bytes": "0",
        "write_size_bytes": "4",
        "input_model": "file",
    }
    replay = {
        "status": "reached",
        "modeled_runtime_calls": [
            {
                "status": "modeled",
                "function_model": "calloc",
                "allocation_address": "0x70000090",
                "allocation_size_bytes": 4,
            }
        ],
        "sink_effect": {
            "status": "modeled",
            "function_model": "direct_memory_read",
            "source_address": "0x7000048c",
            "object_base_address": "0x70000090",
            "read_bytes": 4,
        },
    }

    payload = module.proof_payload(args, replay, {"status": "stopped"}, [])

    assert payload["status"] == "oob_read_proven"
    assert payload["capacity_bytes"] == 4
    assert payload["read_range"]["start_offset"] == 0x3FC
    assert payload["oob_bytes"] == 4


def test_memory_reference_value_handles_scaled_register_address() -> None:
    module = _load_script_module()

    address = module.memory_reference_value("dword ptr [R11 + RDI*0x4]", {"r11": 0x70000090, "rdi": 0xFF})

    assert address == 0x7000048C


def test_dynamic_proof_proves_memcpy_source_oob_read() -> None:
    module = _load_script_module()
    args = {
        "candidate_id": "demo",
        "sink_address": "0x155f0",
        "sink_name": "memcpy_source_read",
        "vulnerability_type": "out_of_bounds_read",
        "write_relation": "proven_oob_read",
        "target_buffer": "src",
        "destination_kind": "stack",
        "capacity_bytes": "8",
        "capacity_source": "declared_local_array",
        "write_size_bytes": "4",
        "offset_expr": "12",
        "input_model": "function_harness",
    }
    replay = {
        "status": "reached",
        "sink_effect": {
            "status": "modeled",
            "source_address": "0x70000C",
            "read_bytes": 4,
            "written_bytes": 4,
        },
    }

    payload = module.proof_payload(args, replay, {"status": "stopped"}, [])

    assert payload["status"] == "oob_read_proven"
    assert payload["read_size_bytes"] == 4
    assert payload["read_range"]["start_offset"] == 12
    assert payload["read_range"]["end_offset_exclusive"] == 16
    assert payload["oob_bytes"] == 4
    assert payload["overflow_bytes"] == 0


def test_dynamic_proof_downgrades_bounded_source_read() -> None:
    module = _load_script_module()
    args = {
        "candidate_id": "demo",
        "sink_address": "0x155f0",
        "sink_name": "memcpy_source_read",
        "vulnerability_type": "out_of_bounds_read",
        "write_relation": "symbolic_read_offset",
        "target_buffer": "src",
        "destination_kind": "stack",
        "capacity_bytes": "8",
        "write_size_bytes": "4",
        "offset_expr": "4",
        "input_model": "function_harness",
    }

    payload = module.proof_payload(args, {"status": "reached"}, {"status": "stopped"}, [])

    assert payload["status"] == "no_oob_read"
    assert payload["reason"] == "concrete_read_does_not_exceed_capacity"
    assert payload["oob_bytes"] == 0


def test_global_string_proof_uses_concrete_write_offset() -> None:
    module = _load_script_module()
    base = 0x435458
    replay = {
        "status": "reached",
        "sink_effect": {
            "status": "modeled",
            "write_address": "0x%X" % (base + 4080),
            "written_bytes": 32,
        },
        "process_input_setup": {"status": "configured"},
    }
    payload = module.proof_payload(
        {
            "candidate_id": "demo",
            "sink_address": "0x4184A4",
            "sink_name": "strcpy",
            "target_buffer": "DAT_00435458",
            "destination_kind": "global",
            "capacity_bytes": "4096",
        },
        replay,
        {"status": "not_run"},
    )

    assert payload["status"] == "overflow_proven"
    assert payload["overflow_bytes"] == 16
    assert payload["write_range"]["start_offset"] == 4080
    assert payload["write_range"]["end_offset_exclusive"] == 4112


def test_process_dynamic_proof_requires_process_replay_not_local_sink_probe() -> None:
    module = _load_script_module()
    args = {
        "candidate_id": "demo",
        "sink_address": "0x155f0",
        "sink_name": "memcpy",
        "target_buffer": "local_20",
        "destination_kind": "stack",
        "capacity_bytes": "16",
        "write_size_bytes": "32",
        "input_model": "argv",
        "proof_scope": "process_entrypoint",
        "concrete_input_hex": "41" * 32,
    }
    replay = {"status": "stopped", "reached_target": False, "process_input_setup": {"status": "configured"}}
    local_probe = {"status": "reached", "reached_target": True}

    payload = module.proof_payload(args, replay, local_probe, [])

    assert payload["status"] == "sink_unreached"
    assert payload["proof_scope"] == "process_entrypoint"
    assert payload["sink_reached"] is False
    assert payload["process_replay"]["status"] == "stopped"
    assert payload["local_sink_probe"]["status"] == "reached"
    assert payload["overflow_bytes"] == 0


def test_external_call_skip_only_skips_non_sink_external_calls() -> None:
    module = _load_script_module()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x1090] = _FakeFunction("__printf_chk", thunk=True)
    program.functions[0x11E0] = _FakeFunction("vulnerable_copy")

    external_skip = module.external_call_skip(program, None, _FakeInstruction(0x10CD, 0x1090, 0x10D2), _FakeAddress(0x11F6))
    internal_skip = module.external_call_skip(program, None, _FakeInstruction(0x10D5, 0x11E0, 0x10DA), _FakeAddress(0x11F6))
    sink_skip = module.external_call_skip(program, None, _FakeInstruction(0x11F6, 0x1080, 0x11FB), _FakeAddress(0x1080))

    assert external_skip["fallthrough_address"] == "0x10D2"
    assert external_skip["target_function"] == "__printf_chk"
    assert internal_skip == {}
    assert sink_skip == {}


@pytest.mark.parametrize(
    ("processor", "pointer_size", "stack_register", "expected_abi", "expected_argument_kind"),
    [
        ("x86", 8, "RSP", "x86_64_sysv", "register_arguments"),
        ("x86", 4, "ESP", "i386", "stack_arguments"),
        ("AARCH64", 8, "SP", "aarch64", "register_arguments"),
        ("ARM", 4, "SP", "arm32", "register_arguments"),
    ],
)
def test_argv_process_input_setup_records_abi_metadata(
    processor: str,
    pointer_size: int,
    stack_register: str,
    expected_abi: str,
    expected_argument_kind: str,
) -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram(processor, pointer_size, stack_register)

    setup = module.setup_argv_process_input(
        program,
        helper,
        {"input_model": "argv", "concrete_input_hex": "4142", "proof_scope": "process_entrypoint"},
        0x7FFFF000,
    )

    assert setup["status"] == "configured"
    assert setup["abi"] == expected_abi
    assert setup["argc"] == 2
    assert setup["pointer_size_bytes"] == pointer_size
    assert setup["input_size_bytes"] == 2
    assert setup[expected_argument_kind]
    assert helper.registers[stack_register] == int(setup["stack_pointer"], 16)
    assert int(setup["argv_address"], 16) > int(setup["stack_pointer"], 16)
    assert all(
        int(address, 16) > int(setup["stack_pointer"], 16)
        for address in setup["argv_entries"]
        if address != "0x0"
    )


def test_function_harness_input_setup_can_bind_multiple_input_args() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    setup = module.setup_function_harness_input(
        program,
        helper,
        {
            "input_model": "function_harness",
            "concrete_input_hex": "414243",
            "function_harness_json": '{"arg_count": 2, "input_arg_index": 0, "input_arg_indices": [0, 1]}',
        },
        0x7FFFF000,
    )

    assert setup["status"] == "configured"
    assert setup["arg_count"] == 2
    assert setup["input_arg_indices"] == [0, 1]
    assert helper.registers["RDI"] == int(setup["input_address"], 16)
    assert helper.registers["RSI"] == int(setup["input_address"], 16)
    assert setup["input_address"] == "0x71000000"
    assert helper.memory[int(setup["input_address"], 16) + 3] == 0


def test_stdin_process_input_setup_records_abi_metadata() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")

    setup = module.setup_stdin_process_input(
        program,
        helper,
        {"input_model": "stdin", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"},
        0x7FFFF000,
    )

    assert setup["status"] == "configured"
    assert setup["abi"] == "x86_64_sysv"
    assert setup["argc"] == 1
    assert setup["stdin_size_bytes"] == 4
    assert setup["stdin_consumed_bytes"] == 0
    assert setup["register_arguments"] == {"argc": "RDI", "argv": "RSI"}


def test_stdin_process_input_setup_prefers_explicit_stdin_bytes() -> None:
    module = _load_script_module()
    setup = module.setup_stdin_process_input(
        _FakeProgram("x86", 8, "RSP"),
        _FakeHelper(),
        {
            "input_model": "stdin",
            "concrete_input_hex": "4141",
            "stdin_input_hex": "4243440a",
            "proof_scope": "process_entrypoint",
        },
        0x7FFFF000,
    )

    assert setup["status"] == "configured"
    assert setup["input_size_bytes"] == 4
    assert setup["stdin_size_bytes"] == 4


def test_stdin_process_input_setup_preserves_optional_argv_topology() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")

    setup = module.setup_stdin_process_input(
        program,
        helper,
        {
            "input_model": "stdin",
            "concrete_input_hex": "4142",
            "argv_values_hex": "70726f6772616d,2d52,2d66",
            "proof_scope": "process_entrypoint",
        },
        0x7FFFF000,
    )

    assert setup["status"] == "configured"
    assert setup["argc"] == 3
    assert setup["argv_values"] == ["program", "-R", "-f"]
    assert setup["stdin_size_bytes"] == 2


def test_static_path_hits_are_preserved_before_instruction_trace_compaction() -> None:
    module = _load_script_module()
    replay = {
        "instructions": [
            {"address": "0x1000"},
            {"address": "0x1010"},
            {"address": "0x1020"},
            {"address": "0x1010"},
            {"address": "0x1030"},
        ]
    }

    recorded = module.record_static_path_hits(
        replay,
        {"static_path_addresses": '["0x1010", "0x1020", "0x2000"]'},
    )
    module.compact_instruction_trace(recorded, limit=2)

    assert recorded["static_path_hits"] == ["0x1010", "0x1020"]
    assert recorded["static_path_address_count"] == 3
    assert recorded["instructions_truncated"] == 3


def test_static_path_hits_ignore_early_out_of_order_repeated_callee() -> None:
    module = _load_script_module()
    replay = {
        "instructions": [
            {"address": "0x1000"},
            {"address": "0x1200"},
            {"address": "0x1100"},
            {"address": "0x1200"},
            {"address": "0x1300"},
        ]
    }

    recorded = module.record_static_path_hits(
        replay,
        {"static_path_addresses": '["0x1000", "0x1100", "0x1200", "0x1300"]'},
    )

    assert recorded["static_path_hits"] == ["0x1000", "0x1100", "0x1200", "0x1300"]


def test_http_service_setup_materializes_valid_request() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    args = {
        "input_model": "http_daemon",
        "concrete_input_hex": (b"A" * 8).hex(),
        "proof_scope": "process_entrypoint",
    }

    setup = module.setup_service_process_input(program, helper, args, 0x7FFFF000)
    request = bytes(module.service_request_bytes(args))

    assert setup["status"] == "configured"
    assert setup["synthetic_listener_fd"] == 3
    assert setup["synthetic_client_fd"] == 4
    assert setup["http_request_valid"] is True
    assert request.startswith(b"GET /AAAAAAAA HTTP/1.1\r\n")
    assert request.endswith(b"\r\n\r\n")


def test_socket_service_models_listener_accept_recv_and_close() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    for address, name in (
        (0x2000, "socket"),
        (0x2010, "bind"),
        (0x2020, "listen"),
        (0x2030, "accept"),
        (0x2040, "recv"),
        (0x2050, "close"),
    ):
        program.functions[address] = _FakeFunction(name, thunk=True)
    args = {"input_model": "socket_service", "concrete_input_hex": "41424344"}
    setup = module.setup_service_process_input(program, helper, args, 0x7FFFF000)
    state = {"bytes": [0x41, 0x42, 0x43, 0x44], "offset": 0, "listener_fd": 3, "client_fd": 4, "descriptors": {}}

    helper.registers.update({"RDI": 2, "RSI": 1, "RDX": 0})
    socket_event = module.modeled_network_input_call(program, helper, _FakeInstruction(0x1000, 0x2000, 0x1005), _FakeAddress(0x3000), args, setup, state)
    helper.registers.update({"RDI": 3, "RSI": 0x5000, "RDX": 16})
    bind_event = module.modeled_network_input_call(program, helper, _FakeInstruction(0x1005, 0x2010, 0x100A), _FakeAddress(0x3000), args, setup, state)
    helper.registers.update({"RDI": 3, "RSI": 1})
    listen_event = module.modeled_network_input_call(program, helper, _FakeInstruction(0x100A, 0x2020, 0x100F), _FakeAddress(0x3000), args, setup, state)
    helper.registers.update({"RDI": 3, "RSI": 0, "RDX": 0})
    accept_event = module.modeled_network_input_call(program, helper, _FakeInstruction(0x100F, 0x2030, 0x1014), _FakeAddress(0x3000), args, setup, state)
    helper.registers.update({"RDI": 4, "RSI": 0x6000, "RDX": 3})
    recv_event = module.modeled_network_input_call(program, helper, _FakeInstruction(0x1014, 0x2040, 0x1019), _FakeAddress(0x3000), args, setup, state)
    helper.registers.update({"RDI": 4})
    close_event = module.modeled_network_input_call(program, helper, _FakeInstruction(0x1019, 0x2050, 0x101E), _FakeAddress(0x3000), args, setup, state)

    assert socket_event["return_value"] == 3
    assert bind_event["return_value"] == 0
    assert listen_event["return_value"] == 0
    assert accept_event["return_value"] == 4
    assert recv_event["written_bytes"] == 3
    assert setup["network_consumed_bytes"] == 3
    assert [helper.memory[0x6000 + index] for index in range(3)] == [0x41, 0x42, 0x43]
    assert close_event["return_value"] == 0
    assert state["descriptors"][4]["state"] == "closed"


def test_stdin_read_call_model_writes_concrete_input_and_return_value() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2000] = _FakeFunction("read", thunk=True)
    setup = module.setup_stdin_process_input(
        program,
        helper,
        {"input_model": "stdin", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"},
        0x7FFFF000,
    )
    helper.registers.update({"RDI": 0, "RSI": 0x6000, "RDX": 3})

    event = module.modeled_stdin_input_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2000, 0x1005),
        _FakeAddress(0x3000),
        {"input_model": "stdin", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"},
        setup,
        {"bytes": [0x41, 0x42, 0x43, 0x44], "offset": 0},
    )

    assert event["status"] == "modeled"
    assert event["function_model"] == "read"
    assert event["written_bytes"] == 3
    assert setup["stdin_consumed_bytes"] == 3
    assert helper.registers["RAX"] == 3
    assert [helper.memory[0x6000 + index] for index in range(3)] == [0x41, 0x42, 0x43]


def test_stdin_stdio_models_fileno_fstat_ftell_and_fread() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    for address, name in (
        (0x2000, "fileno"),
        (0x2010, "fstat"),
        (0x2020, "ftell"),
        (0x2030, "fread"),
        (0x2040, "fseek"),
    ):
        program.functions[address] = _FakeFunction(name, thunk=True)
    args = {
        "input_model": "stdin",
        "concrete_input_hex": "4141",
        "stdin_input_hex": "4243440a",
        "proof_scope": "process_entrypoint",
    }
    setup = module.setup_stdin_process_input(program, helper, args, 0x7FFFF000)
    runtime_state: dict[str, Any] = {}

    helper.registers.update({"RDI": 0xDEAD})
    fileno = module.modeled_runtime_call(
        program, helper, _FakeInstruction(0x1000, 0x2000, 0x1005), _FakeAddress(0x3000), setup, runtime_state
    )
    helper.registers.update({"RDI": 0, "RSI": 0x6000})
    fstat = module.modeled_runtime_call(
        program, helper, _FakeInstruction(0x1005, 0x2010, 0x100A), _FakeAddress(0x3000), setup, runtime_state
    )
    helper.registers.update({"RDI": 0xDEAD})
    ftell = module.modeled_runtime_call(
        program, helper, _FakeInstruction(0x100A, 0x2020, 0x100F), _FakeAddress(0x3000), setup, runtime_state
    )
    helper.registers.update({"RDI": 0x7000, "RSI": 1, "RDX": 3, "RCX": 0xDEAD})
    stdin_state = {"bytes": [0x42, 0x43, 0x44, 0x0A], "offset": 0}
    fread = module.modeled_stdin_input_call(
        program,
        helper,
        _FakeInstruction(0x100F, 0x2030, 0x1014),
        _FakeAddress(0x3000),
        args,
        setup,
        stdin_state,
    )
    helper.registers.update({"RDI": 0xDEAD, "RSI": 1, "RDX": 0})
    fseek = module.modeled_stdin_input_call(
        program,
        helper,
        _FakeInstruction(0x1014, 0x2040, 0x1019),
        _FakeAddress(0x3000),
        args,
        setup,
        stdin_state,
    )

    assert fileno["result"] == 0
    assert fstat["result"] == 0
    assert module.read_memory_integer(program, helper, 0x6000 + 48, 8, False) == 4
    assert ftell["result"] == 0
    assert fread["return_value"] == 3
    assert [helper.memory[0x7000 + index] for index in range(3)] == [0x42, 0x43, 0x44]
    assert fseek["return_value"] == 0
    assert fseek["input_offset_after"] == 1
    assert setup["stdin_consumed_bytes"] == 1


def test_file_process_input_setup_records_path_metadata() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")

    setup = module.setup_file_process_input(
        program,
        helper,
        {"input_model": "file", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"},
        0x7FFFF000,
    )

    assert setup["status"] == "configured"
    assert setup["abi"] == "x86_64_sysv"
    assert setup["argc"] == 2
    assert setup["file_name"] == "concolic_input"
    assert setup["file_size_bytes"] == 4
    assert setup["file_consumed_bytes"] == 0


def test_file_fopen_fread_model_writes_concrete_input_and_return_value() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2100] = _FakeFunction("fopen", thunk=True)
    program.functions[0x2200] = _FakeFunction("fread", thunk=True)
    args = {"input_model": "file", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"}
    setup = module.setup_file_process_input(program, helper, args, 0x7FFFF000)
    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes("concolic_input") + [0])
    helper.registers.update({"RDI": 0x5000, "RSI": 0x5100})
    state = {"bytes": [0x41, 0x42, 0x43, 0x44], "file_name": "concolic_input", "descriptors": {}, "streams": {}}

    fopen_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2100, 0x1005),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )
    stream = helper.registers["RAX"]
    helper.registers.update({"RDI": 0x6000, "RSI": 1, "RDX": 3, "RCX": stream})
    fread_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x1005, 0x2200, 0x100A),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )

    assert fopen_event["function_model"] == "fopen"
    assert fread_event["function_model"] == "fread"
    assert fread_event["written_bytes"] == 3
    assert setup["file_consumed_bytes"] == 3
    assert helper.registers["RAX"] == 3
    assert [helper.memory[0x6000 + index] for index in range(3)] == [0x41, 0x42, 0x43]


def test_file_descriptor_fstat_and_lseek_preserve_binary_loader_input() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    for address, name in ((0x2100, "open64"), (0x2200, "fstat64"), (0x2300, "lseek64")):
        program.functions[address] = _FakeFunction(name, thunk=True)
    args = {"input_model": "file", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"}
    setup = module.setup_file_process_input(program, helper, args, 0x7FFFF000)
    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes("concolic_input") + [0])
    state = {"bytes": [0x41, 0x42, 0x43, 0x44], "file_name": "concolic_input", "descriptors": {}, "streams": {}}

    helper.registers.update({"RDI": 0x5000, "RSI": 0})
    module.modeled_file_input_call(program, helper, _FakeInstruction(0x1000, 0x2100, 0x1005), _FakeAddress(0x3000), args, setup, state)
    descriptor = helper.registers["RAX"]
    helper.registers.update({"RDI": descriptor, "RSI": 0x6000})
    stat_event = module.modeled_file_input_call(program, helper, _FakeInstruction(0x1005, 0x2200, 0x100A), _FakeAddress(0x3000), args, setup, state)
    helper.registers.update({"RDI": descriptor, "RSI": -1, "RDX": 2})
    seek_event = module.modeled_file_input_call(program, helper, _FakeInstruction(0x100A, 0x2300, 0x100F), _FakeAddress(0x3000), args, setup, state)

    assert stat_event["return_value"] == 0
    assert module.read_memory_integer(program, helper, 0x6000 + 48, 8, False) == 4
    assert seek_event["return_value"] == 3
    assert state["descriptors"][descriptor]["offset"] == 3


def test_file_descriptor_mmap_materializes_concrete_file_bytes() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    for address, name in ((0x2100, "open64"), (0x2200, "mmap64"), (0x2300, "munmap")):
        program.functions[address] = _FakeFunction(name, thunk=True)
    args = {"input_model": "file", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"}
    setup = module.setup_file_process_input(program, helper, args, 0x7FFFF000)
    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes("concolic_input") + [0])
    state = {"bytes": [0x41, 0x42, 0x43, 0x44], "file_name": "concolic_input", "descriptors": {}, "streams": {}}
    helper.registers.update({"RDI": 0x5000, "RSI": 0})
    module.modeled_file_input_call(program, helper, _FakeInstruction(0x1000, 0x2100, 0x1005), _FakeAddress(0x3000), args, setup, state)
    descriptor = helper.registers["RAX"]
    helper.registers.update({"RDI": 0, "RSI": 4, "RDX": 1, "RCX": 2, "R8": descriptor, "R9": 0})
    mapping = module.modeled_file_input_call(program, helper, _FakeInstruction(0x1005, 0x2200, 0x100A), _FakeAddress(0x3000), args, setup, state)
    mapped_address = int(mapping["mapping_address"], 16)
    helper.registers.update({"RDI": mapped_address, "RSI": 4})
    unmap = module.modeled_file_input_call(program, helper, _FakeInstruction(0x100A, 0x2300, 0x100F), _FakeAddress(0x3000), args, setup, state)

    assert module.read_memory_bytes(program, helper, mapped_address, 4) == [0x41, 0x42, 0x43, 0x44]
    assert mapping["mapped_bytes"] == 4
    assert unmap["return_value"] == 0


def test_file_stream_model_tracks_seek_tell_getc_ungetc_and_eof() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2100] = _FakeFunction("fopen", thunk=True)
    program.functions[0x2200] = _FakeFunction("fseeko64", thunk=True)
    program.functions[0x2300] = _FakeFunction("ftello64", thunk=True)
    program.functions[0x2400] = _FakeFunction("getc", thunk=True)
    program.functions[0x2500] = _FakeFunction("ungetc", thunk=True)
    program.functions[0x2600] = _FakeFunction("fread", thunk=True)
    program.functions[0x2700] = _FakeFunction("feof", thunk=True)
    program.functions[0x2800] = _FakeFunction("ferror", thunk=True)
    args = {"input_model": "file", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"}
    setup = module.setup_file_process_input(program, helper, args, 0x7FFFF000)
    state = {"bytes": [0x41, 0x42, 0x43, 0x44], "file_name": "concolic_input", "descriptors": {}, "streams": {}}

    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes("concolic_input") + [0])
    helper.registers.update({"RDI": 0x5000, "RSI": 0x5100})
    module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2100, 0x1005),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )
    stream = helper.registers["RAX"]

    helper.registers.update({"RDI": stream, "RSI": 2, "RDX": 0})
    seek_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x1005, 0x2200, 0x100A),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )
    helper.registers.update({"RDI": stream})
    tell_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x100A, 0x2300, 0x100F),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )
    helper.registers.update({"RDI": stream})
    getc_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x100F, 0x2400, 0x1014),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )
    helper.registers.update({"RDI": 0x43, "RSI": stream})
    ungetc_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x1014, 0x2500, 0x1019),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )
    helper.registers.update({"RDI": stream})
    getc_again_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x1019, 0x2400, 0x101E),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )
    helper.registers.update({"RDI": 0x6000, "RSI": 1, "RDX": 2, "RCX": stream})
    fread_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x101E, 0x2600, 0x1023),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )
    helper.registers.update({"RDI": stream})
    feof_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x1023, 0x2700, 0x1028),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )
    helper.registers.update({"RDI": stream})
    ferror_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x1028, 0x2800, 0x102D),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )

    assert seek_event["return_value"] == 0
    assert seek_event["input_offset_after"] == 2
    assert tell_event["return_value"] == 2
    assert getc_event["return_value"] == 0x43
    assert ungetc_event["return_value"] == 0x43
    assert getc_again_event["return_value"] == 0x43
    assert fread_event["written_bytes"] == 1
    assert helper.registers["RAX"] == 0
    assert helper.memory[0x6000] == 0x44
    assert feof_event["return_value"] == 1
    assert ferror_event["return_value"] == 0


def test_argv_file_stdin_setup_models_file_and_stdin_calls() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2100] = _FakeFunction("fopen", thunk=True)
    program.functions[0x2200] = _FakeFunction("fread", thunk=True)
    program.functions[0x2300] = _FakeFunction("fgets", thunk=True)
    file_name = "script.dat"
    args = {
        "input_model": "argv_file_stdin",
        "concrete_input_hex": "4142430a",
        "stdin_input_hex": "4142430a",
        "file_input_hex": "46494c45",
        "file_name": file_name,
        "argv_values_hex": ",".join(item.encode().hex() for item in ["program", "-f", file_name]),
        "proof_scope": "process_entrypoint",
        "process_input_source": "inferred_from_entry_decompile",
        "process_input_evidence_json": '{"mode_flag":"f","file_seed_reason":"script_format_text"}',
    }
    setup = module.setup_argv_file_stdin_process_input(program, helper, args, 0x7FFFF000)

    assert setup["status"] == "configured"
    assert setup["argc"] == 3
    assert setup["stdin_size_bytes"] == 4
    assert setup["file_name"] == file_name
    assert setup["file_size_bytes"] == 4
    assert setup["process_input_source"] == "inferred_from_entry_decompile"
    assert setup["process_input_evidence"] == {"mode_flag": "f", "file_seed_reason": "script_format_text"}

    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes(file_name) + [0])
    helper.registers.update({"RDI": 0x5000, "RSI": 0x5100})
    file_state = {"bytes": [0x46, 0x49, 0x4C, 0x45], "file_name": file_name, "descriptors": {}, "streams": {}}
    fopen_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2100, 0x1005),
        _FakeAddress(0x3000),
        args,
        setup,
        file_state,
    )
    stream = helper.registers["RAX"]
    helper.registers.update({"RDI": 0x6000, "RSI": 1, "RDX": 3, "RCX": stream})
    fread_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x1005, 0x2200, 0x100A),
        _FakeAddress(0x3000),
        args,
        setup,
        file_state,
    )

    helper.registers.update({"RDI": 0x7000, "RSI": 5, "RDX": 0xDEAD})
    stdin_state = {"bytes": [0x41, 0x42, 0x43, 0x0A], "offset": 0}
    fgets_event = module.modeled_stdin_input_call(
        program,
        helper,
        _FakeInstruction(0x100A, 0x2300, 0x100F),
        _FakeAddress(0x3000),
        args,
        setup,
        stdin_state,
    )

    assert fopen_event["function_model"] == "fopen"
    assert fread_event["function_model"] == "fread"
    assert fread_event["written_bytes"] == 3
    assert fgets_event["function_model"] == "fgets"
    assert fgets_event["written_bytes"] == 4
    assert setup["stdin_consumed_bytes"] == 4
    assert [helper.memory[0x6000 + index] for index in range(3)] == [0x46, 0x49, 0x4C]
    assert [helper.memory[0x7000 + index] for index in range(5)] == [0x41, 0x42, 0x43, 0x0A, 0]


def test_argv_file_stdin_setup_blocks_missing_file_input_hex() -> None:
    module = _load_script_module()
    setup = module.setup_argv_file_stdin_process_input(
        _FakeProgram("x86", 8, "RSP"),
        _FakeHelper(),
        {
            "input_model": "argv_file_stdin",
            "stdin_input_hex": "4142430a",
            "file_name": "script.dat",
            "argv_values_hex": ",".join(item.encode().hex() for item in ["program", "script.dat"]),
            "proof_scope": "process_entrypoint",
            "process_input_source": "missing_process_input_fact",
        },
        0x7FFFF000,
    )

    assert setup["status"] == "unsupported"
    assert setup["reason"] == "unsupported_process_input_setup:missing_file_input_hex"
    assert setup["process_input_source"] == "missing_process_input_fact"


def test_env_process_input_setup_records_envp_metadata() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")

    setup = module.setup_env_process_input(
        program,
        helper,
        {"input_model": "env", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"},
        0x7FFFF000,
    )

    assert setup["status"] == "configured"
    assert setup["abi"] == "x86_64_sysv"
    assert setup["argc"] == 1
    assert setup["env_name"] == "CONCOLIC_INPUT"
    assert setup["env_value_size_bytes"] == 4
    assert setup["envp_address"]
    assert setup["register_arguments"] == {"argc": "RDI", "argv": "RSI", "envp": "RDX"}


def test_env_getenv_model_returns_concrete_value_pointer() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2300] = _FakeFunction("getenv", thunk=True)
    args = {"input_model": "env", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"}
    setup = module.setup_env_process_input(program, helper, args, 0x7FFFF000)
    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes("CONCOLIC_INPUT") + [0])
    helper.registers.update({"RDI": 0x5000})

    event = module.modeled_env_input_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2300, 0x1005),
        _FakeAddress(0x3000),
        args,
        setup,
        {"bytes": [0x41, 0x42, 0x43, 0x44], "values": {}},
    )

    value_address = helper.registers["RAX"]
    assert event["status"] == "modeled"
    assert event["function_model"] == "getenv"
    assert event["variable_name"] == "CONCOLIC_INPUT"
    assert event["environment_model"] == "configured"
    assert event["input_controlled"] is True
    assert setup["modeled_env_calls"][0]["variable_name"] == "CONCOLIC_INPUT"
    assert [helper.memory[value_address + index] for index in range(5)] == [0x41, 0x42, 0x43, 0x44, 0]


def test_env_getenv_model_returns_null_for_unconfigured_name() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2300] = _FakeFunction("getenv", thunk=True)
    args = {"input_model": "env", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"}
    setup = module.setup_env_process_input(program, helper, args, 0x7FFFF000)
    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes("PAYLOAD") + [0])
    helper.registers.update({"RDI": 0x5000})

    event = module.modeled_env_input_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2300, 0x1005),
        _FakeAddress(0x3000),
        args,
        setup,
        {"bytes": [0x41, 0x42, 0x43, 0x44], "values": {}},
    )

    assert event["environment_model"] == "absent"
    assert event["input_controlled"] is False
    assert helper.registers["RAX"] == 0


def test_env_file_setup_and_stream_scan_share_descriptor_state() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2100] = _FakeFunction("open", thunk=True)
    program.functions[0x2200] = _FakeFunction("fdopen", thunk=True)
    program.functions[0x2300] = _FakeFunction("__isoc23_fscanf", thunk=True)
    program.functions[0x2400] = _FakeFunction("getenv", thunk=True)
    file_bytes = b"  ALPHA BETA\n"
    args = {
        "input_model": "env_file",
        "concrete_input_hex": file_bytes.hex(),
        "file_input_hex": file_bytes.hex(),
        "file_name": "charset.alias",
        "env_name": "CHARSETALIASDIR",
        "env_values_json": '{"CHARSETALIASDIR":".","QUOTING_STYLE":"locale"}',
        "argv_values_hex": ",".join(item.encode().hex() for item in ["program", "-i", "/missing"]),
        "proof_scope": "process_entrypoint",
    }
    setup = module.setup_env_file_process_input(program, helper, args, 0x7FFFF000)

    assert setup["status"] == "configured"
    assert setup["argc"] == 3
    assert setup["file_name"] == "charset.alias"
    assert setup["env_values"] == {"CHARSETALIASDIR": ".", "QUOTING_STYLE": "locale"}

    env_state = {
        "variables": {"CHARSETALIASDIR": module.ascii_bytes("."), "QUOTING_STYLE": module.ascii_bytes("locale")},
        "values": {},
    }
    module.write_memory_bytes(program, helper, 0x4800, module.ascii_bytes("QUOTING_STYLE") + [0])
    helper.registers.update({"RDI": 0x4800})
    env_event = module.modeled_env_input_call(
        program,
        helper,
        _FakeInstruction(0x0FF0, 0x2400, 0x0FF5),
        _FakeAddress(0x3000),
        args,
        setup,
        env_state,
    )
    env_value = helper.registers["RAX"]
    assert env_event["environment_model"] == "configured"
    assert env_event["input_controlled"] is False
    assert bytes(helper.memory[env_value + index] for index in range(6)) == b"locale"

    state = {
        "bytes": list(file_bytes),
        "file_name": "charset.alias",
        "descriptors": {},
        "streams": {},
        "next_fd": 3,
        "next_stream": 0x7FFEE000,
    }
    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes("./charset.alias") + [0])
    helper.registers.update({"RDI": 0x5000, "RSI": 0})
    open_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2100, 0x1005),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )
    descriptor = helper.registers["RAX"]

    helper.registers.update({"RDI": descriptor, "RSI": 0x5100})
    fdopen_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x1005, 0x2200, 0x100A),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )
    stream = helper.registers["RAX"]
    assert state["streams"][stream] is state["descriptors"][descriptor]

    module.write_memory_bytes(program, helper, 0x5200, module.ascii_bytes("%5s %4s") + [0])
    helper.registers.update({"RDI": stream, "RSI": 0x5200, "RDX": 0x6000, "RCX": 0x6100})
    scan_event = module.modeled_file_input_call(
        program,
        helper,
        _FakeInstruction(0x100A, 0x2300, 0x100F),
        _FakeAddress(0x3000),
        args,
        setup,
        state,
    )

    assert open_event["function_model"] == "open"
    assert fdopen_event["function_model"] == "fdopen"
    assert scan_event["function_model"] == "isoc23_fscanf"
    assert scan_event["return_value"] == 2
    assert scan_event["field_sizes"] == [5, 4]
    assert bytes(helper.memory[0x6000 + index] for index in range(6)) == b"ALPHA\0"
    assert bytes(helper.memory[0x6100 + index] for index in range(5)) == b"BETA\0"
    assert helper.registers["RAX"] == 2
    assert module.bounded_string_scan_widths("%s") is None
    assert module.bounded_string_scan_widths("%10d") is None


def test_compact_instruction_trace_preserves_bounded_context() -> None:
    module = _load_script_module()
    replay = {"instructions": [{"address": "0x%X" % index} for index in range(1000)]}

    module.compact_instruction_trace(replay, limit=10)

    assert replay["instruction_count"] == 1000
    assert replay["instructions_truncated"] == 990
    assert [item["address"] for item in replay["instructions"]] == [
        "0x0", "0x1", "0x2", "0x3", "0x4", "0x3E3", "0x3E4", "0x3E5", "0x3E6", "0x3E7"
    ]

    zero_replay = {"instructions": [{"address": "0x1"}]}
    module.compact_instruction_trace(zero_replay, limit=0)

    assert zero_replay["instruction_count"] == 1
    assert zero_replay["instructions_truncated"] == 1
    assert zero_replay["instructions"] == []


def test_runtime_strlen_model_returns_concrete_length() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2400] = _FakeFunction("strlen", thunk=True)
    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes("ABCD") + [0])
    helper.registers.update({"RDI": 0x5000})

    event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2400, 0x1005),
        _FakeAddress(0x3000),
        {},
        {"next_heap": 0x70000000, "allocations": {}},
    )

    assert event["status"] == "modeled"
    assert event["function_model"] == "strlen"
    assert event["result"] == 4
    assert helper.registers["RAX"] == 4


def test_runtime_strcpy_model_copies_source_and_return_value() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2500] = _FakeFunction("__strcpy_chk", thunk=True)
    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes("PAYLOAD") + [0])
    helper.registers.update({"RDI": 0x6000, "RSI": 0x5000, "RDX": 8})

    event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2500, 0x1005),
        _FakeAddress(0x3000),
        {},
        {"next_heap": 0x70000000, "allocations": {}},
    )

    assert event["status"] == "modeled"
    assert event["function_model"] == "strcpy_chk"
    assert event["written_bytes"] == 8
    assert helper.registers["RAX"] == 0x6000
    assert [helper.memory[0x6000 + index] for index in range(8)] == module.ascii_bytes("PAYLOAD") + [0]


def test_runtime_strcpy_chk_model_terminates_before_oversized_write() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2500] = _FakeFunction("__strcpy_chk", thunk=True)
    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes("TOO-LONG") + [0])
    helper.registers.update({"RDI": 0x6000, "RSI": 0x5000, "RDX": 4})

    event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2500, 0x1005),
        _FakeAddress(0x3000),
        {},
        {"next_heap": 0x70000000, "allocations": {}},
    )

    assert event["status"] == "terminated"
    assert event["function_model"] == "strcpy_chk"
    assert event["reason"] == "fortified_bound_exceeded"
    assert event["written_bytes"] == 0
    assert 0x6000 not in helper.memory


def test_runtime_allocator_models_heap_memory_and_zero_fill() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2600] = _FakeFunction("malloc", thunk=True)
    program.functions[0x2700] = _FakeFunction("calloc", thunk=True)
    runtime_state = {"next_heap": 0x70000000, "allocations": {}}

    helper.registers.update({"RDI": 8})
    malloc_event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2600, 0x1005),
        _FakeAddress(0x3000),
        {},
        runtime_state,
    )
    malloc_address = helper.registers["RAX"]
    helper.registers.update({"RDI": 2, "RSI": 3})
    calloc_event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1005, 0x2700, 0x100A),
        _FakeAddress(0x3000),
        {},
        runtime_state,
    )
    calloc_address = helper.registers["RAX"]

    assert malloc_event["allocation_size_bytes"] == 8
    assert int(malloc_event["allocation_address"], 16) == malloc_address
    assert calloc_event["allocation_size_bytes"] == 6
    assert runtime_state["allocations"][malloc_address]["size_bytes"] == 8
    assert runtime_state["allocations"][calloc_address]["size_bytes"] == 6
    assert runtime_state["allocations"][malloc_address]["object_id"] == 1
    assert runtime_state["allocations"][calloc_address]["object_id"] == 2
    assert [helper.memory[calloc_address + index] for index in range(6)] == [0] * 6


def test_runtime_double_free_keeps_object_identity_and_release_history() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2600] = _FakeFunction("malloc", thunk=True)
    program.functions[0x2700] = _FakeFunction("free", thunk=True)
    runtime_state = {"next_heap": 0x70000000, "allocations": {}}

    helper.registers["RDI"] = 24
    module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2600, 0x1005),
        _FakeAddress(0x3000),
        {},
        runtime_state,
    )
    address = helper.registers["RAX"]
    helper.registers["RDI"] = address
    first = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1005, 0x2700, 0x100A),
        _FakeAddress(0x3000),
        {},
        runtime_state,
    )
    second = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x100A, 0x2700, 0x100F),
        _FakeAddress(0x3000),
        {},
        runtime_state,
    )

    assert first["lifetime_result"] == "released"
    assert runtime_state["allocations"][address]["state"] == "released"
    assert second["status"] == "lifetime_violation"
    assert second["lifetime_violation"]["vulnerability"] == "double_free"
    assert second["lifetime_violation"]["object_id"] == 1
    assert second["lifetime_violation"]["first_release_event"]["call_address"] == "0x1005"


def test_runtime_invalid_free_requires_non_base_address_in_modeled_allocation() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2600] = _FakeFunction("malloc", thunk=True)
    program.functions[0x2700] = _FakeFunction("free", thunk=True)
    runtime_state = {"next_heap": 0x70000000, "allocations": {}}

    helper.registers["RDI"] = 24
    module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2600, 0x1005),
        _FakeAddress(0x3000),
        {},
        runtime_state,
    )
    base = helper.registers["RAX"]
    helper.registers["RDI"] = base + 4
    interior = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1005, 0x2700, 0x100A),
        _FakeAddress(0x1005),
        {},
        runtime_state,
    )
    helper.registers["RDI"] = 0x1234
    unknown = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x100A, 0x2700, 0x100F),
        _FakeAddress(0x100A),
        {},
        runtime_state,
    )

    assert interior["status"] == "lifetime_violation"
    assert interior["lifetime_violation"] == {
        "vulnerability": "invalid_free",
        "access_kind": "release",
        "reason": "release_address_is_not_object_base",
        "object_id": 1,
        "address": f"0x{base + 4:X}",
        "object_base_address": f"0x{base:X}",
        "object_size_bytes": 24,
    }
    assert runtime_state["allocations"][base]["state"] == "live"
    assert unknown["lifetime_violation"]["reason"] == "pointer_is_not_a_modeled_allocation"
    assert "object_id" not in unknown["lifetime_violation"]


def test_runtime_use_after_free_requires_same_released_object() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2600] = _FakeFunction("malloc", thunk=True)
    program.functions[0x2700] = _FakeFunction("free", thunk=True)
    program.functions[0x2800] = _FakeFunction("puts", thunk=True)
    runtime_state = {"next_heap": 0x70000000, "allocations": {}}

    helper.registers["RDI"] = 12
    module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2600, 0x1005),
        _FakeAddress(0x3000),
        {},
        runtime_state,
    )
    released_address = helper.registers["RAX"]
    helper.registers["RDI"] = released_address
    module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1005, 0x2700, 0x100A),
        _FakeAddress(0x3000),
        {},
        runtime_state,
    )
    event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x100A, 0x2800, 0x100F),
        _FakeAddress(0x100A),
        {},
        runtime_state,
        {"vulnerability_type": "use_after_free"},
    )

    assert event["status"] == "lifetime_violation"
    assert event["argument_index"] == 0
    assert event["lifetime_violation"]["vulnerability"] == "use_after_free"
    assert event["lifetime_violation"]["object_id"] == 1
    assert event["lifetime_violation"]["release_event"]["call_address"] == "0x1005"


def test_dynamic_lifetime_payload_requires_expected_violation_and_object_identity() -> None:
    module = _load_script_module()
    args = {
        "candidate_id": "demo",
        "sink_address": "0x100a",
        "sink_name": "free",
        "vulnerability_type": "double_free",
        "input_model": "argv",
        "proof_scope": "process_entrypoint",
    }
    violation = {
        "vulnerability": "double_free",
        "object_id": 7,
        "object_base_address": "0x70000000",
        "object_size_bytes": 24,
        "allocation_event": {"call_address": "0x1000"},
        "first_release_event": {"call_address": "0x1005"},
    }
    replay = {
        "status": "reached",
        "process_input_setup": {"status": "configured", "input_model": "argv"},
        "sink_effect": {"status": "lifetime_violation", "lifetime_violation": violation},
    }

    payload = module.proof_payload(args, replay, {"status": "stopped"})

    assert payload["proof_kind"] == "ghidra_dynamic_memory_safety"
    assert payload["status"] == "lifetime_violation_proven"
    assert payload["exact_sink_reached"] is True
    assert payload["object_identity"] == {
        "object_id": 7,
        "base_address": "0x70000000",
        "size_bytes": 24,
    }

    replay["sink_effect"]["lifetime_violation"] = {**violation, "vulnerability": "use_after_free"}
    mismatch = module.proof_payload(args, replay, {"status": "stopped"})
    assert mismatch["status"] == "no_lifetime_violation"


def test_dynamic_invalid_free_payload_rejects_unknown_pointer_without_object_derivation() -> None:
    module = _load_script_module()
    args = {
        "candidate_id": "demo",
        "sink_address": "0x100a",
        "sink_name": "free",
        "vulnerability_type": "invalid_free",
        "input_model": "argv",
        "proof_scope": "process_entrypoint",
    }
    replay = {
        "status": "reached",
        "process_input_setup": {"status": "configured", "input_model": "argv"},
        "sink_effect": {
            "status": "lifetime_violation",
            "lifetime_violation": {
                "vulnerability": "invalid_free",
                "reason": "pointer_is_not_a_modeled_allocation",
                "address": "0x1234",
            },
        },
    }

    unknown = module.proof_payload(args, replay, {"status": "stopped"})
    replay["sink_effect"]["lifetime_violation"] = {
        "vulnerability": "invalid_free",
        "reason": "release_address_is_not_object_base",
        "object_id": 9,
        "address": "0x70000004",
        "object_base_address": "0x70000000",
        "object_size_bytes": 24,
    }
    interior = module.proof_payload(args, replay, {"status": "stopped"})

    assert unknown["status"] == "unsupported"
    assert unknown["reason"] == "invalid_free_requires_allocation_derived_non_base_address"
    assert interior["status"] == "lifetime_violation_proven"
    assert interior["object_identity"]["object_id"] == 9


def test_runtime_output_call_is_modeled_instead_of_broad_skip() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2800] = _FakeFunction("__printf_chk", thunk=True)

    event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2800, 0x1005),
        _FakeAddress(0x3000),
        {},
        {"next_heap": 0x70000000, "allocations": {}},
    )

    assert event["status"] == "modeled"
    assert event["function_model"] == "printf"
    assert event["fallthrough_address"] == "0x1005"
    assert helper.registers["RAX"] == 0


def test_runtime_exit_model_terminates_process_replay() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2900] = _FakeFunction("exit", thunk=True)

    event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x2900, 0x1005),
        _FakeAddress(0x3000),
        {},
        {"next_heap": 0x70000000, "allocations": {}},
    )

    assert event["status"] == "terminated"
    assert event["reason"] == "process_terminated:exit"


def test_indirect_runtime_call_model_resolves_register_target() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x2400] = _FakeFunction("strlen", thunk=True)
    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes("ABCDE") + [0])
    helper.registers.update({"RAX": 0x2400, "RDI": 0x5000})

    event = module.modeled_runtime_call(
        program,
        helper,
        _FakeInstruction(
            0x1000,
            None,
            0x1005,
            operands=[[_FakeRegister("RAX")]],
            operand_representations=["RAX"],
        ),
        _FakeAddress(0x3000),
        {},
        {"next_heap": 0x70000000, "allocations": {}},
    )

    assert event["status"] == "modeled"
    assert event["function_model"] == "strlen"
    assert event["target_kind"] == "indirect"
    assert helper.registers["RAX"] == 5


def test_indirect_internal_call_transfers_to_resolved_target() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x4400] = _FakeFunction("callback_target")
    helper.registers.update({"RAX": 0x4400})

    event = module.modeled_indirect_call_transfer(
        program,
        helper,
        _FakeInstruction(
            0x1000,
            None,
            0x1005,
            operands=[[_FakeRegister("RAX")]],
            operand_representations=["RAX"],
        ),
        _FakeAddress(0x3000),
    )

    assert event["status"] == "transfer"
    assert event["function_model"] == "indirect_call"
    assert event["transfer_address"] == "0x4400"
    assert event["transfer_reason"] == "resolved_indirect_call"


def test_libc_start_main_model_transfers_to_main_with_process_args() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x3000] = _FakeFunction("__libc_start_main", thunk=True)
    program.functions[0x1100] = _FakeFunction("main")
    helper.registers.update({"RDI": 0x1100, "RSI": 2, "RDX": 0x7000})

    event = module.modeled_control_transfer_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x3000, 0x1005),
        _FakeAddress(0x5000),
        {"abi": "x86_64_sysv", "pointer_size_bytes": 8, "envp_address": "0x7100"},
    )

    assert event["status"] == "transfer"
    assert event["function_model"] == "start_main"
    assert event["transfer_address"] == "0x1100"
    assert helper.registers["RDI"] == 2
    assert helper.registers["RSI"] == 0x7000
    assert helper.registers["RDX"] == 0x7100


def test_qsort_and_bsearch_models_concrete_fixed_width_records() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    program.functions[0x3100] = _FakeFunction("qsort", thunk=True)
    program.functions[0x3200] = _FakeFunction("bsearch", thunk=True)
    program.functions[0x4500] = _FakeFunction("compare")
    module.write_memory_integer(program, helper, 0x8000, 9, 4, False)
    module.write_memory_integer(program, helper, 0x8008, 3, 4, False)
    helper.registers.update({"RDI": 0x8000, "RSI": 2, "RDX": 8, "RCX": 0x4500, "RSP": 0x9000})

    event = module.modeled_control_transfer_call(
        program,
        helper,
        _FakeInstruction(0x1000, 0x3100, 0x1005),
        _FakeAddress(0x5000),
        {"abi": "x86_64_sysv", "pointer_size_bytes": 8},
    )

    assert event["status"] == "modeled"
    assert event["function_model"] == "qsort"
    assert event["concrete_sort"] is True
    assert module.read_memory_integer(program, helper, 0x8000, 4, False) == 3
    assert module.read_memory_integer(program, helper, 0x8008, 4, False) == 9

    module.write_memory_integer(program, helper, 0x8100, 9, 4, False)
    helper.registers.update({"RDI": 0x8100, "RSI": 0x8000, "RDX": 2, "RCX": 8, "R8": 0x4500})
    search = module.modeled_control_transfer_call(
        program,
        helper,
        _FakeInstruction(0x1005, 0x3200, 0x100A),
        _FakeAddress(0x5000),
        {"abi": "x86_64_sysv", "pointer_size_bytes": 8},
    )
    assert search["concrete_search"] is True
    assert helper.registers["RAX"] == 0x8008


def test_syscall_read_model_feeds_stdin_bytes() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    setup = module.setup_stdin_process_input(
        program,
        helper,
        {"input_model": "stdin", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"},
        0x7FFFF000,
    )
    helper.registers.update({"RAX": 0, "RDI": 0, "RSI": 0x6000, "RDX": 3})

    event = module.modeled_syscall_instruction(
        program,
        helper,
        _FakeInstruction(0x1000, None, 0x1002, mnemonic="SYSCALL", is_call=False),
        {"input_model": "stdin", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"},
        setup,
        {"bytes": [0x41, 0x42, 0x43, 0x44], "offset": 0},
        {},
        {"next_heap": 0x70000000, "allocations": {}},
    )

    assert event["status"] == "modeled"
    assert event["syscall_name"] == "read"
    assert event["written_bytes"] == 3
    assert setup["stdin_consumed_bytes"] == 3
    assert helper.registers["RAX"] == 3
    assert [helper.memory[0x6000 + index] for index in range(3)] == [0x41, 0x42, 0x43]


def test_syscall_open_read_model_feeds_file_bytes() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    args = {"input_model": "file", "concrete_input_hex": "41424344", "proof_scope": "process_entrypoint"}
    setup = module.setup_file_process_input(program, helper, args, 0x7FFFF000)
    state = {
        "bytes": [0x41, 0x42, 0x43, 0x44],
        "file_name": "concolic_input",
        "descriptors": {},
        "streams": {},
        "next_fd": 3,
    }
    module.write_memory_bytes(program, helper, 0x5000, module.ascii_bytes("concolic_input") + [0])
    helper.registers.update({"RAX": 2, "RDI": 0x5000, "RSI": 0})

    open_event = module.modeled_syscall_instruction(
        program,
        helper,
        _FakeInstruction(0x1000, None, 0x1002, mnemonic="SYSCALL", is_call=False),
        args,
        setup,
        {},
        state,
        {"next_heap": 0x70000000, "allocations": {}},
    )
    fd = helper.registers["RAX"]
    helper.registers.update({"RAX": 0, "RDI": fd, "RSI": 0x6000, "RDX": 4})
    read_event = module.modeled_syscall_instruction(
        program,
        helper,
        _FakeInstruction(0x1002, None, 0x1004, mnemonic="SYSCALL", is_call=False),
        args,
        setup,
        {},
        state,
        {"next_heap": 0x70000000, "allocations": {}},
    )

    assert open_event["syscall_name"] == "open"
    assert open_event["fd"] == 3
    assert read_event["syscall_name"] == "read"
    assert read_event["written_bytes"] == 4
    assert setup["file_consumed_bytes"] == 4
    assert [helper.memory[0x6000 + index] for index in range(4)] == [0x41, 0x42, 0x43, 0x44]


def test_syscall_exit_model_terminates_process_replay() -> None:
    module = _load_script_module()
    helper = _FakeHelper()
    program = _FakeProgram("x86", 8, "RSP")
    helper.registers.update({"RAX": 60, "RDI": 0})

    event = module.modeled_syscall_instruction(
        program,
        helper,
        _FakeInstruction(0x1000, None, 0x1002, mnemonic="SYSCALL", is_call=False),
        {},
        {"abi": "x86_64_sysv", "pointer_size_bytes": 8},
        {},
        {},
        {"next_heap": 0x70000000, "allocations": {}},
    )

    assert event["status"] == "terminated"
    assert event["syscall_name"] == "exit"
    assert event["reason"] == "process_terminated:exit"


def test_dynamic_proof_downgrades_bounded_numeric_snprintf() -> None:
    module = _load_script_module()
    args = {
        "candidate_id": "demo",
        "sink_address": "0xe2fc",
        "sink_name": "snprintf",
        "target_buffer": "acStack_50",
        "destination_kind": "stack",
        "capacity_bytes": "48",
        "capacity_source": "stack_object",
        "write_size_bytes": "0x40",
        "formatted_write_bound_bytes": "44",
        "input_model": "function_harness",
    }

    payload = module.proof_payload(args, {"status": "reached"}, {"status": "stopped"}, [])

    assert payload["status"] == "no_overflow"
    assert payload["write_size_bytes"] == 44
    assert payload["write_size_source"] == "constant_snprintf_format_bound"
    assert payload["overflow_bytes"] == 0


def test_constant_snprintf_numeric_format_bound_includes_nul() -> None:
    module = _load_script_module()

    assert module.printf_format_upper_bound_bytes("%lde%ld") == 44
    assert module.printf_format_upper_bound_bytes("%s%d:%d:%d") is None
