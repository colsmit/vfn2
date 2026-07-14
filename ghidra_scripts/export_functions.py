#@category AgentToolchain
#
# Headless Ghidra script that exports per-function decompiler listings for a
# stripped binary. Produces C-like source files and a companion manifest.

import hashlib
import json
import os
import re

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.app.decompiler.component import DecompilerUtils
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.exception import CancelledException
except ImportError:  # pragma: no cover - lets pytest import helper functions locally
    DecompInterface = None
    DecompilerUtils = None
    PcodeOp = None
    BasicBlockModel = None

    class CancelledException(Exception):
        pass


DEFAULT_DECOMPILE_TIMEOUT_SEC = 180
DEFAULT_RETRY_TIMEOUT_SEC = 600
DEFAULT_MAX_PAYLOAD_MBYTES = 50
MAX_OUTPUT_FILENAME_CHARS = 180


def parse_kv_args(raw_args):
    result = {}
    for arg in raw_args:
        if "=" in arg:
            key, value = arg.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def sanitize_name(name):
    name = name or "UNKNOWN"
    name = name.strip()
    sanitized = re.sub(r"[^0-9A-Za-z_]+", "_", name)
    sanitized = sanitized.strip("_")
    return sanitized or "f"


def parse_positive_int(raw_value, default):
    try:
        value = int(str(raw_value).strip())
    except Exception:
        return default
    return value if value > 0 else default


def parse_bool_flag(raw_value, default=False):
    if raw_value is None:
        return default
    return str(raw_value).strip().lower() in {"1", "true", "yes", "on"}


def parse_int_like(raw_value):
    if raw_value is None:
        return None
    text = str(raw_value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except Exception:
        return None


def program_metadata(program):
    metadata = {
        "language_id": "",
        "processor": "",
        "pointer_size_bytes": 0,
        "endianness": "",
        "executable_format": "",
        "compiler": "",
    }
    try:
        language = program.getLanguage()
    except Exception:
        language = None
    if language is not None:
        try:
            metadata["language_id"] = str(language.getLanguageID())
        except Exception:
            pass
        try:
            metadata["processor"] = str(language.getProcessor())
        except Exception:
            pass
        try:
            metadata["endianness"] = "big" if language.isBigEndian() else "little"
        except Exception:
            pass
    try:
        metadata["pointer_size_bytes"] = int(program.getDefaultPointerSize())
    except Exception:
        try:
            metadata["pointer_size_bytes"] = int(language.getDefaultSpace().getPointerSize()) if language is not None else 0
        except Exception:
            pass
    try:
        metadata["executable_format"] = str(program.getExecutableFormat())
    except Exception:
        pass
    try:
        metadata["compiler"] = str(program.getCompilerSpec().getCompilerSpecID())
    except Exception:
        pass
    return metadata


def build_output_filename(address, func_name, used_filenames, max_chars=MAX_OUTPUT_FILENAME_CHARS):
    prefix = "%08X_" % address
    suffix = ".c"
    sanitized = sanitize_name(func_name)
    max_name_chars = max_chars - len(prefix) - len(suffix)
    if max_name_chars < 16:
        max_name_chars = 16

    if len(sanitized) > max_name_chars:
        digest = hashlib.sha1(sanitized.encode("utf-8")).hexdigest()[:12]
        head_length = max_name_chars - len(digest) - 1
        sanitized = "%s_%s" % (sanitized[:head_length].rstrip("_"), digest)

    candidate = "%s%s%s" % (prefix, sanitized, suffix)
    dedupe_index = 1
    while candidate in used_filenames:
        dedupe_suffix = "_%d" % dedupe_index
        base_limit = max_name_chars - len(dedupe_suffix)
        if len(sanitized) > base_limit:
            candidate_name = sanitized[:base_limit].rstrip("_")
        else:
            candidate_name = sanitized
        candidate = "%s%s%s%s" % (prefix, candidate_name, dedupe_suffix, suffix)
        dedupe_index += 1

    used_filenames.add(candidate)
    return candidate


def build_placeholder_source(func_name, address, prototype, error_message):
    signature = (prototype or "").strip()
    if not signature:
        signature = "undefined %s(void)" % (func_name or "f")
    reason = (error_message or "Decompiler did not return source.").strip()
    return (
        "// Function: %s\n"
        "// Address: 0x%X\n"
        "// Placeholder emitted after incomplete Ghidra decompilation.\n\n"
        "%s\n"
        "{\n"
        "  /* %s */\n"
        "}\n"
    ) % (func_name, address, signature, reason)


def collect_stack_regions(function):
    regions = []
    try:
        stack_frame = function.getStackFrame()
    except Exception:
        stack_frame = None
    if stack_frame is None:
        return regions

    try:
        stack_vars = list(stack_frame.getStackVariables())
    except Exception:
        stack_vars = []

    if not stack_vars:
        return regions

    stack_vars.sort(key=lambda var: (var.getStackOffset(), var.getName()))

    for var in stack_vars:
        try:
            data_type = var.getDataType()
            data_type_name = data_type.getName() if data_type else ""
        except Exception:
            data_type_name = ""
        try:
            offset = var.getStackOffset()
        except Exception:
            continue
        try:
            length = var.getLength()
        except Exception:
            length = 0
        if length <= 0:
            continue
        regions.append(
            {
                "start_offset": offset,
                "end_offset": offset + length,
                "size_bytes": length,
                "var_names": [var.getName()],
                "data_types": [data_type_name],
            }
        )
    return regions


def collect_composite_fields(function):
    fields = []
    try:
        stack_frame = function.getStackFrame()
    except Exception:
        stack_frame = None
    if stack_frame is None:
        return fields
    try:
        stack_vars = list(stack_frame.getStackVariables())
    except Exception:
        stack_vars = []
    for var in stack_vars:
        try:
            base_name = var.getName()
            data_type = var.getDataType()
        except Exception:
            continue
        if data_type is None or not hasattr(data_type, "getComponents"):
            continue
        try:
            components = list(data_type.getComponents())
        except Exception:
            components = []
        for component in components:
            try:
                field_name = component.getFieldName() or component.getDefaultFieldName()
            except Exception:
                field_name = ""
            try:
                offset = int(component.getOffset())
            except Exception:
                offset = None
            try:
                length = int(component.getLength())
            except Exception:
                length = None
            try:
                field_type = component.getDataType().getName()
            except Exception:
                field_type = ""
            if not field_name and offset is None:
                continue
            entry = {
                "base": base_name,
                "field_path": field_name or ("field_%s" % offset),
                "source": "ghidra_composite_field",
                "object_trust": "field_metadata",
            }
            if offset is not None:
                entry["field_offset"] = offset
            if length is not None:
                entry["field_capacity"] = length
                entry["size_bytes"] = length
            if field_type:
                entry["data_type"] = field_type
            fields.append(entry)
    return fields


def collect_global_static_tls_refs(program, function, limit=64):
    refs = {"global_refs": [], "static_refs": [], "tls_refs": []}
    try:
        listing = program.getListing()
        memory = program.getMemory()
        symbol_table = program.getSymbolTable()
        instructions = listing.getInstructions(function.getBody(), True)
    except Exception:
        return refs
    seen = set()
    while instructions.hasNext():
        instruction = instructions.next()
        try:
            raw_refs = instruction.getReferencesFrom()
        except Exception:
            raw_refs = []
        for ref in raw_refs:
            try:
                if not ref.getReferenceType().isData():
                    continue
                address = ref.getToAddress()
                if address is None or address in seen:
                    continue
                block = memory.getBlock(address)
                if block is None:
                    continue
            except Exception:
                continue
            seen.add(address)
            try:
                block_name = block.getName()
            except Exception:
                block_name = ""
            try:
                symbol = symbol_table.getPrimarySymbol(address)
                label = symbol.getName() if symbol is not None else str(address)
            except Exception:
                label = str(address)
            try:
                data = listing.getDataAt(address)
                length = int(data.getLength()) if data is not None else 0
            except Exception:
                length = 0
            entry = {
                "address": _address_hex(address),
                "label": label,
                "var_display": label,
                "block": block_name,
                "capacity_source": "ghidra_data_reference",
                "object_trust": "metadata",
            }
            if length > 0:
                entry["size_bytes"] = length
            bucket = "global_refs"
            lowered_block = str(block_name).lower()
            lowered_label = str(label).lower()
            if "tls" in lowered_block or "thread" in lowered_block:
                bucket = "tls_refs"
                entry["destination_kind"] = "tls"
            elif lowered_label.startswith("static_") or ".bss" in lowered_block or ".data" in lowered_block:
                bucket = "static_refs" if lowered_label.startswith("static_") else "global_refs"
                entry["destination_kind"] = "static_local" if bucket == "static_refs" else "global"
            else:
                entry["destination_kind"] = "global"
            refs[bucket].append(entry)
            if sum(len(value) for value in refs.values()) >= limit:
                return refs
    return refs


def _signed_stack_offset(offset):
    try:
        value = int(offset)
    except Exception:
        return None
    if value >= 0x80000000:
        value -= 0x100000000
    return value


def _address_hex(address):
    try:
        return "0x%X" % address.getOffset()
    except Exception:
        return ""


def _varnode_fact(varnode):
    fact = {
        "repr": str(varnode),
    }
    try:
        fact["size_bytes"] = int(varnode.getSize())
    except Exception:
        pass
    try:
        if varnode.isConstant():
            fact["constant"] = int(varnode.getOffset())
    except Exception:
        pass
    try:
        address = varnode.getAddress()
        if address is not None:
            fact["address"] = _address_hex(address)
            try:
                space = address.getAddressSpace()
                fact["address_space"] = space.getName()
                if space.isStackSpace():
                    fact["stack_offset"] = _signed_stack_offset(address.getOffset())
            except Exception:
                pass
    except Exception:
        pass
    try:
        high = varnode.getHigh()
        if high is not None:
            name = high.getName()
            if name:
                fact["var_name"] = name
            data_type = high.getDataType()
            if data_type:
                fact["data_type"] = data_type.getName()
    except Exception:
        pass
    # A HighVariable named ``local_*`` can still be a pointer held in a
    # register or unique varnode.  It is a direct stack reference only when
    # the varnode itself belongs to the stack address space; otherwise a LOAD
    # reads the pointee, not the local pointer's stack slot.
    if fact.get("address_space") == "stack":
        stack_ref = {}
        if "var_name" in fact:
            stack_ref["var_name"] = fact["var_name"]
        if "stack_offset" in fact:
            stack_ref["stack_offset"] = fact["stack_offset"]
        if stack_ref:
            fact["stack_ref"] = stack_ref
    return fact


def _varnode_dependency_names(varnode, depth=8, seen=None):
    if depth < 0 or varnode is None:
        return []
    seen = seen or set()
    key = str(varnode)
    if key in seen:
        return []
    seen.add(key)
    fact = _varnode_fact(varnode)
    names = []
    name = str(fact.get("var_name") or "")
    if name and name != "UNNAMED":
        names.append(name)
    try:
        definition = varnode.getDef()
    except Exception:
        definition = None
    if definition is None:
        return names
    try:
        inputs = [definition.getInput(index) for index in range(definition.getNumInputs())]
    except Exception:
        inputs = []
    for item in inputs:
        names.extend(_varnode_dependency_names(item, depth - 1, seen))
    return sorted(set(names))


def _varnode_dependency_constants(varnode, depth=8, seen=None):
    if depth < 0 or varnode is None:
        return []
    seen = seen or set()
    key = str(varnode)
    if key in seen:
        return []
    seen.add(key)
    fact = _varnode_fact(varnode)
    constants = []
    if "constant" in fact:
        constants.append(int(fact["constant"]))
    try:
        definition = varnode.getDef()
    except Exception:
        definition = None
    if definition is None:
        return constants
    try:
        inputs = [definition.getInput(index) for index in range(definition.getNumInputs())]
    except Exception:
        inputs = []
    for item in inputs:
        constants.extend(_varnode_dependency_constants(item, depth - 1, seen))
    return sorted(set(constants))


def _resolve_call_target(program, function_manager, target_varnode):
    address = None
    try:
        address = target_varnode.getAddress()
    except Exception:
        address = None
    try:
        if address is None and target_varnode.isConstant():
            address = program.getAddressFactory().getDefaultAddressSpace().getAddress(target_varnode.getOffset())
    except Exception:
        address = None
    if address is None:
        return "", ""
    callee_address = _address_hex(address)
    callee_name = ""
    try:
        callee = function_manager.getFunctionAt(address)
        if callee is not None:
            callee_name = callee.getName()
    except Exception:
        pass
    return callee_name, callee_address


def _collect_pcode_facts(program, function, results):
    pcode_calls = []
    pcode_stores = []
    pcode_loads = []
    pcode_operations = []
    try:
        high_function = results.getHighFunction()
    except Exception:
        high_function = None
    if high_function is None:
        return pcode_calls, pcode_stores, pcode_loads, pcode_operations

    function_manager = program.getFunctionManager()
    try:
        ops = high_function.getPcodeOps()
    except Exception:
        return pcode_calls, pcode_stores, pcode_loads, pcode_operations

    defined_stack_bytes = set()
    defined_stack_variables = {}
    while ops.hasNext():
        op = ops.next()
        try:
            opcode = op.getOpcode()
        except Exception:
            continue
        try:
            op_address = _address_hex(op.getSeqnum().getTarget())
        except Exception:
            op_address = ""
        try:
            mnemonic = op.getMnemonic()
        except Exception:
            mnemonic = str(op)

        inputs = []
        try:
            input_count = op.getNumInputs()
        except Exception:
            input_count = 0
        for idx in range(input_count):
            try:
                inputs.append(_varnode_fact(op.getInput(idx)))
            except Exception:
                pass
        try:
            output = op.getOutput()
        except Exception:
            output = None
        pcode_operations.append(
            {
                "operation_address": op_address,
                "pcode": mnemonic,
                "inputs": inputs,
                "output": _varnode_fact(output) if output is not None else {},
            }
        )

        if PcodeOp is not None and opcode in (PcodeOp.CALL, PcodeOp.CALLIND):
            try:
                target = op.getInput(0)
            except Exception:
                target = None
            callee_name, callee_address = _resolve_call_target(program, function_manager, target) if target is not None else ("", "")
            args = []
            try:
                count = op.getNumInputs()
            except Exception:
                count = 0
            for idx in range(1, count):
                try:
                    args.append(_varnode_fact(op.getInput(idx)))
                except Exception:
                    pass
            pcode_calls.append(
                {
                    "call_address": op_address,
                    "callee": callee_name,
                    "callee_address": callee_address,
                    "arg_count": len(args),
                    "args": args,
                    "pcode": mnemonic,
                    "target_kind": "indirect" if opcode == PcodeOp.CALLIND else "direct",
                }
            )
            continue

        if PcodeOp is not None and opcode == PcodeOp.STORE:
            try:
                dest = op.getInput(1)
                value = op.getInput(2)
            except Exception:
                continue
            dest_fact = _varnode_fact(dest)
            value_fact = _varnode_fact(value)
            stack_ref = dest_fact.get("stack_ref")
            store = {
                "operation_address": op_address,
                "write_width": value_fact.get("size_bytes", 0),
                "address_vars": _varnode_dependency_names(dest),
                "address_constants": _varnode_dependency_constants(dest),
                "pcode": mnemonic,
            }
            if "constant" in dest_fact:
                store["address_constant"] = int(dest_fact["constant"])
            if stack_ref:
                store["stack_ref"] = stack_ref
                if "var_name" in stack_ref:
                    store["base_var"] = stack_ref["var_name"]
                if "stack_offset" in stack_ref:
                    stack_offset = int(stack_ref["stack_offset"])
                    width = max(0, int(store.get("write_width") or 0))
                    store["stack_offset"] = stack_offset
                    store["defined_byte_range"] = [stack_offset, stack_offset + width]
                    defined_stack_bytes.update(range(stack_offset, stack_offset + width))
                elif "var_name" in stack_ref:
                    width = max(0, int(store.get("write_width") or 0))
                    defined_stack_variables.setdefault(str(stack_ref["var_name"]), set()).update(range(width))
            else:
                store["unknown_address"] = True
            pcode_stores.append(store)
            continue

        if PcodeOp is not None and opcode == PcodeOp.LOAD:
            try:
                address_varnode = op.getInput(1)
                output = op.getOutput()
            except Exception:
                continue
            output_fact = _varnode_fact(output)
            address_fact = _varnode_fact(address_varnode)
            load = {
                "operation_address": op_address,
                "read_width": output_fact.get("size_bytes", 0),
                "address_vars": _varnode_dependency_names(address_varnode),
                "address_constants": _varnode_dependency_constants(address_varnode),
                "pcode": mnemonic,
            }
            if "constant" in address_fact:
                load["address_constant"] = int(address_fact["constant"])
            stack_ref = address_fact.get("stack_ref")
            if stack_ref:
                stack_offset = stack_ref.get("stack_offset")
                var_name = str(stack_ref.get("var_name") or "")
                width = max(0, int(load.get("read_width") or 0))
                if stack_offset is not None:
                    stack_offset = int(stack_offset)
                    offsets = list(range(stack_offset, stack_offset + width))
                    load["stack_offset"] = stack_offset
                    known = [item for item in offsets if item in defined_stack_bytes]
                    if known:
                        undefined = [item for item in offsets if item not in defined_stack_bytes]
                        load["defined_byte_ranges"] = _integer_ranges(known)
                        load["undefined_byte_ranges"] = _integer_ranges(undefined)
                        load["definedness"] = "undefined" if undefined else "defined"
                        load["definedness_basis"] = "prior_pcode_store_byte_ranges"
                    else:
                        # High p-code represents many scalar assignments as
                        # COPY/SSA definitions rather than STORE operations.
                        # Absence of a STORE is therefore not proof that a
                        # directly addressed stack slot is uninitialized.
                        load["definedness"] = "unknown"
                        load["definedness_basis"] = "no_overlapping_pcode_store_not_proof"
            pcode_loads.append(load)
    return pcode_calls, pcode_stores, pcode_loads, pcode_operations


def _integer_ranges(values):
    ordered = sorted(set(int(item) for item in values))
    if not ordered:
        return []
    rows = []
    start = previous = ordered[0]
    for value in ordered[1:]:
        if value != previous + 1:
            rows.append([start, previous + 1])
            start = value
        previous = value
    rows.append([start, previous + 1])
    return rows


def _collect_c_line_addresses(results):
    if DecompilerUtils is None:
        return []
    try:
        lines = DecompilerUtils.toLines(results.getCCodeMarkup())
    except Exception:
        return []
    collected = []
    for line in lines:
        addresses = []
        load_addresses = []
        token_operations = []
        try:
            tokens = line.getAllTokens()
        except Exception:
            tokens = []
        for token in tokens:
            try:
                address = _address_hex(token.getMinAddress())
            except Exception:
                address = ""
            if address and address not in addresses:
                addresses.append(address)
            try:
                token_op = token.getPcodeOp()
                if token_op is not None:
                    token_address = _address_hex(token_op.getSeqnum().getTarget())
                    try:
                        token_text = token.getText()
                    except Exception:
                        token_text = str(token)
                    try:
                        token_mnemonic = token_op.getMnemonic()
                    except Exception:
                        token_mnemonic = str(token_op)
                    token_fact = {
                        "token": str(token_text),
                        "operation_address": token_address,
                        "pcode": token_mnemonic,
                    }
                    if token_address and token_fact not in token_operations:
                        token_operations.append(token_fact)
                    if token_op.getOpcode() == PcodeOp.LOAD:
                        if token_address and token_address not in load_addresses:
                            load_addresses.append(token_address)
            except Exception:
                pass
        if addresses:
            row = {"line_number": int(line.getLineNumber()), "addresses": addresses}
            if load_addresses:
                row["load_addresses"] = load_addresses
            if token_operations:
                row["token_operations"] = token_operations
            collected.append(row)
    return collected


def _collect_basic_blocks(program, function):
    """Export the intra-function control-flow graph as address ranges."""
    if BasicBlockModel is None:
        return []
    rows = []
    try:
        model = BasicBlockModel(program)
        blocks = model.getCodeBlocksContaining(function.getBody(), monitor)
    except Exception:
        return []
    while blocks.hasNext():
        try:
            block = blocks.next()
            destinations = block.getDestinations(monitor)
            successors = []
            while destinations.hasNext():
                destination = destinations.next().getDestinationAddress()
                if destination is not None and function.getBody().contains(destination):
                    successors.append(_address_hex(destination))
            rows.append({
                "start": _address_hex(block.getMinAddress()),
                "end": _address_hex(block.getMaxAddress()),
                "successors": sorted(set(successors)),
            })
        except Exception:
            continue
    return sorted(rows, key=lambda row: row.get("start") or "")


def collect_string_refs(program, function, limit=8):
    listing = program.getListing()
    body = function.getBody()
    if body is None:
        return []
    strings = []
    seen = set()
    try:
        instructions = listing.getInstructions(body, True)
    except Exception:
        return strings

    while instructions.hasNext():
        instruction = instructions.next()
        try:
            references = instruction.getReferencesFrom()
        except Exception:
            references = []
        for ref in references:
            try:
                if not ref.getReferenceType().isData():
                    continue
                to_address = ref.getToAddress()
                if to_address is None or to_address in seen:
                    continue
                data = listing.getDataAt(to_address)
                if data is None or not data.hasStringValue():
                    continue
                value = data.getDefaultValue()
                if value is None:
                    continue
                text = str(value)
            except Exception:
                continue
            if not text:
                continue
            seen.add(to_address)
            strings.append(
                {
                    "address": "0x%X" % to_address.getOffset(),
                    "value": text[:256],
                }
            )
            if len(strings) >= limit:
                return strings
    return strings


def classify_wrapper(function, decompiled_source):
    if function.isThunk():
        return "plt_thunk"

    body_lines = []
    for line in decompiled_source.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("//"):
            continue
        if stripped.startswith("/*") and stripped.endswith("*/"):
            continue
        if stripped in ("{", "}"):
            continue
        body_lines.append(stripped)

    if not body_lines:
        return None

    joined = " ".join(body_lines)
    if "(*(code *)" in joined and len(body_lines) <= 3:
        return "indirect_forward"

    call_tokens = []
    for match in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\(", joined):
        token = match.group(1)
        if token not in {"if", "while", "for", "switch", "return", "sizeof"}:
            call_tokens.append(token)

    if call_tokens:
        unique_calls = set(call_tokens)
        if len(unique_calls) == 1 and len(body_lines) <= 4:
            return "single_call_wrapper"

    return None


def main():
    args = parse_kv_args(getScriptArgs())
    output_dir = args.get("output_dir")
    if not output_dir:
        println("export_functions.py requires output_dir=<path>")
        return
    if DecompInterface is None:
        raise RuntimeError("export_functions.py must run inside Ghidra")
    mode = args.get("mode", "paramid").lower()
    emit_c = parse_bool_flag(args.get("emit_c"), True)
    decompile_timeout_sec = parse_positive_int(args.get("decompile_timeout_sec"), DEFAULT_DECOMPILE_TIMEOUT_SEC)
    retry_timeout_sec = parse_positive_int(args.get("retry_timeout_sec"), DEFAULT_RETRY_TIMEOUT_SEC)
    max_payload_mbytes = parse_positive_int(
        args.get("max_payload_mbytes"),
        DEFAULT_MAX_PAYLOAD_MBYTES,
    )
    target_name = args.get("function_name")
    target_relative_address = parse_int_like(args.get("function_relative_address"))
    fallback_incomplete = parse_bool_flag(args.get("fallback_incomplete"), True)

    program = currentProgram
    if program is None:
        println("No current program; aborting.")
        return

    ensure_dir(output_dir)
    manifest_path = os.path.join(output_dir, "manifest.jsonl")
    image_base = int(program.getImageBase().getOffset())
    abi_metadata = program_metadata(program)

    decompiler = DecompInterface()
    options = decompiler.getOptions()
    try:
        options.setMaxPayloadMBytes(max_payload_mbytes)
    except Exception:
        pass
    try:
        decompiler.setOptions(options)
    except Exception:
        pass
    if mode == "paramid":
        try:
            decompiler.setSimplificationStyle("paramid")
        except Exception:
            pass
    decompiler.toggleCCode(True)
    decompiler.toggleSyntaxTree(True)
    decompiler.openProgram(program)

    function_manager = program.getFunctionManager()
    functions = []
    memory = program.getMemory()
    for function in function_manager.getFunctions(True):
        try:
            if function.getName().startswith("__pfx_"):
                continue
        except Exception:
            pass
        try:
            if function.isExternal():
                continue
        except Exception:
            pass
        try:
            entry_point = function.getEntryPoint()
            block = memory.getBlock(entry_point) if entry_point is not None else None
            if block is not None and block.getName() == "EXTERNAL":
                continue
        except Exception:
            pass
        try:
            relative_address = int(function.getEntryPoint().getOffset()) - image_base
        except Exception:
            relative_address = None
        if target_name and function.getName() != target_name:
            continue
        if target_relative_address is not None and relative_address != target_relative_address:
            continue
        functions.append(function)
    total = len(functions)
    println("Exporting %d functions to %s" % (total, output_dir))

    call_edges = {}
    used_filenames = set()

    with open(manifest_path, "w") as manifest_file:
        for idx, function in enumerate(functions, start=1):
            monitor.checkCanceled()

            entry_point = function.getEntryPoint()
            address = entry_point.getOffset()
            func_name = function.getName()
            relative_address = int(address) - image_base
            signature = function.getSignature()
            try:
                prototype = signature.getPrototypeString(True)
            except Exception:
                prototype = function.getPrototypeString()
            try:
                return_type = signature.getReturnType().getName()
            except Exception:
                return_type = ""
            parameters = []
            try:
                for param in function.getParameters():
                    try:
                        data_type = param.getDataType()
                        data_type_name = data_type.getName() if data_type else ""
                    except Exception:
                        data_type_name = ""
                    parameters.append(
                        {
                            "name": param.getName(),
                            "data_type": data_type_name,
                            "storage": str(param.getVariableStorage()),
                        }
                    )
            except Exception:
                pass

            try:
                results = decompiler.decompileFunction(function, decompile_timeout_sec, monitor)
            except CancelledException:
                raise
            except Exception as exc:  # pragma: no cover - defensive logging
                println("Failed to decompile %s: %s" % (func_name, exc))
                continue

            if not results.decompileCompleted():
                try:
                    error_message = results.getErrorMessage() or ""
                except Exception:
                    error_message = ""
                if (
                    retry_timeout_sec > decompile_timeout_sec
                    and error_message
                    and "timeout" in error_message.lower()
                ):
                    try:
                        println(
                            "Retrying %s after timeout with %d second budget"
                            % (func_name, retry_timeout_sec)
                        )
                        results = decompiler.decompileFunction(function, retry_timeout_sec, monitor)
                    except CancelledException:
                        raise
                    except Exception as exc:  # pragma: no cover - defensive logging
                        println("Retry failed for %s: %s" % (func_name, exc))
                    if not results.decompileCompleted():
                        try:
                            error_message = results.getErrorMessage() or error_message
                        except Exception:
                            pass
                if not fallback_incomplete:
                    if error_message:
                        println("Decompilation incomplete for %s: %s" % (func_name, error_message))
                    else:
                        println("Decompilation incomplete for %s" % func_name)
                    continue

            filename = ""
            c_body = ""
            placeholder_kind = None
            if emit_c:
                try:
                    decompiled = results.getDecompiledFunction()
                except Exception:
                    decompiled = None

                if decompiled is not None:
                    try:
                        c_body = decompiled.getC() or ""
                    except Exception as exc:
                        println("Failed to fetch C from decompiled function %s: %s" % (func_name, exc))
                        c_body = ""
                if not c_body and hasattr(results, "getC"):
                    try:
                        c_body = results.getC() or ""
                    except Exception as exc:
                        println("Failed to fetch C output for %s: %s" % (func_name, exc))
                        c_body = ""

                if not c_body and not results.decompileCompleted() and fallback_incomplete:
                    c_body = build_placeholder_source(func_name, address, prototype, error_message)
                    placeholder_kind = "decompile_timeout" if "timeout" in (error_message or "").lower() else "decompile_incomplete"
                    println("Incomplete fallback emitted for %s: %s" % (func_name, error_message or "no error message"))

                if c_body:
                    filename = build_output_filename(address, func_name, used_filenames)
                    file_path = os.path.join(output_dir, filename)
                    with open(file_path, "w") as fout:
                        fout.write("// Function: %s\n" % func_name)
                        fout.write("// Address: 0x%X\n\n" % address)
                        fout.write(c_body)
                        fout.write("\n")
                else:
                    println("Decompiled C output empty for %s" % func_name)
            relative_path = filename

            try:
                callees = [callee.getName() for callee in function.getCalledFunctions(monitor)]
            except Exception:
                callees = []
            call_edges[func_name] = sorted(set(callees))

            body = function.getBody()
            body_size_addresses = body.getNumAddresses() if body else 0
            body_size_bytes = body_size_addresses

            byte_length = len(c_body.encode("utf-8")) if c_body else 0
            line_count = len(c_body.splitlines()) if c_body else 0

            manifest_entry = {
                "address": "0x%X" % address,
                "relative_address": relative_address,
                "name": func_name,
                "filename": filename,
                "relative_path": relative_path,
                "is_thunk": function.isThunk(),
                "stack_purge": function.getStackPurgeSize(),
                "call_fixup": function.getCallFixup(),
                "decompile_completed": results.decompileCompleted(),
                "size": body_size_addresses,
                "ordinal": idx,
                "return_type": return_type,
                "prototype": prototype,
                "parameters": parameters,
                "emit_c": emit_c,
                "c_line_number_offset": 3 if emit_c else 0,
                "byte_length": byte_length,
                "line_count": line_count,
                "body_size_bytes": body_size_bytes,
            }
            wrapper_type = classify_wrapper(function, c_body)
            if wrapper_type:
                manifest_entry["wrapper_type"] = wrapper_type
            if placeholder_kind:
                manifest_entry["stub_kind"] = placeholder_kind
            elif body_size_addresses <= 32:
                manifest_entry["stub_kind"] = "tiny_body"
            elif wrapper_type in {"plt_thunk", "single_call_wrapper"}:
                manifest_entry["stub_kind"] = "wrapper"
            stack_regions = collect_stack_regions(function)
            if stack_regions:
                manifest_entry["stack_regions"] = stack_regions
            composite_fields = collect_composite_fields(function)
            if composite_fields:
                manifest_entry["composite_fields"] = composite_fields
            object_refs = collect_global_static_tls_refs(program, function)
            for key in ("global_refs", "static_refs", "tls_refs"):
                if object_refs.get(key):
                    manifest_entry[key] = object_refs[key]
            string_refs = collect_string_refs(program, function)
            if string_refs:
                manifest_entry["string_refs"] = string_refs
            pcode_calls, pcode_stores, pcode_loads, pcode_operations = _collect_pcode_facts(
                program, function, results
            )
            c_line_addresses = _collect_c_line_addresses(results)
            basic_blocks = _collect_basic_blocks(program, function)
            if pcode_calls:
                manifest_entry["pcode_calls"] = pcode_calls
            if pcode_stores:
                manifest_entry["pcode_stores"] = pcode_stores
            if pcode_loads:
                manifest_entry["pcode_loads"] = pcode_loads
            if pcode_operations:
                manifest_entry["pcode_operations"] = pcode_operations
            if c_line_addresses:
                manifest_entry["c_line_addresses"] = c_line_addresses
            if basic_blocks:
                manifest_entry["basic_blocks"] = basic_blocks
            manifest_file.write(json.dumps(manifest_entry))
            manifest_file.write("\n")

    callgraph_path = os.path.join(output_dir, "callgraph.json")
    with open(callgraph_path, "w") as callgraph_file:
        payload = {
            "image_base": image_base,
            "edges": call_edges,
        }
        payload.update(abi_metadata)
        callgraph_file.write(json.dumps(payload, indent=2))

    println("Export complete.")


if __name__ == "__main__":
    main()
