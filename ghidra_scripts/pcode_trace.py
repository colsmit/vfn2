#@category AgentToolchain
#
# Headless Ghidra script that writes a bounded concrete p-code trace artifact.
# The script is deliberately conservative: if a concrete emulator setup cannot
# be established, it writes an explicit unsupported artifact instead of guessing.

import json
import os
import re
import time

try:
    from ghidra.app.emulator import EmulatorHelper
except ImportError:  # pragma: no cover - lets local tooling parse this file
    EmulatorHelper = None

try:
    from ghidra.app.decompiler import DecompInterface
except ImportError:  # pragma: no cover - lets local tooling parse this file
    DecompInterface = None


def parse_kv_args(raw_args):
    result = {}
    for arg in raw_args:
        if "=" in arg:
            key, value = arg.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def parse_int(raw_value, default=None):
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


def unsupported(candidate_id, reason, args):
    return {
        "schema_version": 1,
        "trace_kind": "ghidra_pcode",
        "candidate_id": candidate_id,
        "status": "unsupported",
        "unsupported": True,
        "reason": str(reason),
        "request": dict(args),
        "instructions": [],
        "pcode_ops": [],
        "memory_writes": [],
        "store_catalog": [],
        "call_catalog": [],
        "replay": {"status": "unsupported", "reason": str(reason)},
    }


def address_from(program, raw_value):
    parsed = parse_int(raw_value)
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
        return str(address)


def normalize_line_text(text):
    text = re.sub(r"^\s*\d+\s*:\s*", "", str(text or ""))
    return re.sub(r"\s+", " ", text).strip().rstrip(";")


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
    normalized = text.strip("_").lower()
    for suffix in ("_chk", "_alias"):
        if normalized.endswith(suffix):
            return normalized[: -len(suffix)]
    return normalized


def pcode_fact(op, instruction_address):
    try:
        mnemonic = op.getMnemonic()
    except Exception:
        mnemonic = str(op)
    fact = {
        "instruction_address": address_hex(instruction_address),
        "mnemonic": mnemonic,
        "text": str(op),
    }
    try:
        fact["opcode"] = int(op.getOpcode())
    except Exception:
        pass
    try:
        output = op.getOutput()
        if output is not None:
            fact["output"] = str(output)
    except Exception:
        pass
    inputs = []
    try:
        count = op.getNumInputs()
    except Exception:
        count = 0
    for index in range(count):
        try:
            inputs.append(str(op.getInput(index)))
        except Exception:
            pass
    if inputs:
        fact["inputs"] = inputs
    return fact


def pcode_op_address(op):
    try:
        return op.getSeqnum().getTarget()
    except Exception:
        return None


def pcode_op_mnemonic(op):
    try:
        return str(op.getMnemonic()).upper()
    except Exception:
        return str(op).split(" ", 1)[0].upper()


def instruction_fact(instruction):
    address = instruction.getAddress()
    return {
        "address": address_hex(address),
        "text": str(instruction),
    }


def static_pcode_window(program, function, target_address, limit):
    listing = program.getListing()
    instructions = []
    pcode_ops = []
    try:
        iterator = listing.getInstructions(function.getBody(), True)
    except Exception:
        return instructions, pcode_ops
    before = []
    after_remaining = 0
    found = False
    while iterator.hasNext() and len(instructions) < limit:
        instruction = iterator.next()
        address = instruction.getAddress()
        if not found and address != target_address:
            before.append(instruction)
            if len(before) > 16:
                before.pop(0)
            continue
        if address == target_address and not found:
            found = True
            selected = before + [instruction]
            after_remaining = 16
        elif found and after_remaining > 0:
            selected = [instruction]
            after_remaining -= 1
        else:
            continue
        for item in selected:
            instructions.append(instruction_fact(item))
            try:
                for op in item.getPcode():
                    pcode_ops.append(pcode_fact(op, item.getAddress()))
            except Exception:
                pass
        if found and after_remaining <= 0:
            break
    return instructions[:limit], pcode_ops[:limit * 8]


def pcode_memory_writes(pcode_ops):
    writes = []
    for op in pcode_ops:
        mnemonic = str(op.get("mnemonic") or "").upper()
        if mnemonic == "STORE":
            writes.append(op)
    return writes


def pcode_operation_catalog(program, function, limit):
    listing = program.getListing()
    stores = []
    calls = []
    try:
        iterator = listing.getInstructions(function.getBody(), True)
    except Exception:
        return stores, calls
    while iterator.hasNext() and (len(stores) < limit or len(calls) < limit):
        instruction = iterator.next()
        try:
            ops = instruction.getPcode()
        except Exception:
            continue
        for op in ops:
            fact = pcode_fact(op, instruction.getAddress())
            mnemonic = str(fact.get("mnemonic") or "").upper()
            if mnemonic == "STORE" and len(stores) < limit:
                stores.append(fact)
            elif mnemonic in ("CALL", "CALLIND") and len(calls) < limit:
                calls.append(fact)
    return stores, calls


def line_matches_candidate(line_text, args):
    normalized = normalize_line_text(line_text)
    candidate_line_text = args.get("candidate_line_text", "")
    wanted = normalize_line_text(candidate_line_text)
    if wanted and normalized == wanted:
        return "exact_line_text"
    sink_name = str(args.get("sink_name") or "")
    target_buffer = str(args.get("target_buffer") or "")
    offset_expr = str(args.get("offset_expr") or "")
    if sink_name in ("pointer_store", "array_store"):
        if target_buffer and target_buffer not in normalized:
            return ""
        if offset_expr and offset_expr not in {"0", "unbounded"} and offset_expr not in normalized:
            return ""
        return "store_target_match" if target_buffer else ""
    normalized_sink = normalized_api_name(sink_name)
    if sink_name and sink_name not in normalized and (not normalized_sink or normalized_sink not in normalized):
        return ""
    if target_buffer and target_buffer not in normalized:
        return ""
    return "call_target_match" if sink_name else ""


def node_children(node):
    try:
        child_count = node.numChildren()
    except Exception:
        child_count = 0
    for index in range(child_count):
        try:
            child = node.Child(index)
        except Exception:
            child = None
        if child is not None:
            yield child


def node_class_name(node):
    try:
        return str(node.getClass().getName())
    except Exception:
        return ""


def node_line_parent(node):
    try:
        line_parent = node.getLineParent()
    except Exception:
        line_parent = None
    if line_parent is not None:
        return line_parent
    if "ClangStatement" in node_class_name(node):
        return node
    return None


def node_line_number(node):
    for method_name in ("getLineNumber", "getLine"):
        try:
            value = getattr(node, method_name)()
            parsed = parse_int(value, 0)
            if parsed > 0:
                return parsed
        except Exception:
            pass
    return 0


def pcode_token_key(node):
    try:
        op = node.getPcodeOp()
    except Exception:
        op = None
    if op is not None:
        address = pcode_op_address(op)
        address_text = address_hex(address) if address is not None else ""
        return (address_text, str(op))
    try:
        return ("min", address_hex(node.getMinAddress()), str(node))
    except Exception:
        return ("id", str(id(node)))


def collect_descendant_pcode_tokens(node, tokens, seen):
    try:
        op = node.getPcodeOp()
    except Exception:
        op = None
    if op is not None:
        key = pcode_token_key(node)
        if key not in seen:
            seen.add(key)
            tokens.append(node)
    for child in node_children(node):
        collect_descendant_pcode_tokens(child, tokens, seen)


def collect_line_tokens(markup, args):
    candidate_line_text = args.get("candidate_line_text", "")
    wanted = normalize_line_text(candidate_line_text)
    wanted_line_number = parse_int(args.get("candidate_line_number"), 0)
    tokens = []
    seen_tokens = set()
    seen_lines = set()
    matched_lines = {}
    match_methods = {}
    tokens_by_line = {}
    candidate_samples = {}

    def visit(node):
        line_parent = node_line_parent(node)
        if line_parent is None:
            for child in node_children(node):
                visit(child)
            return
        line_key = str(line_parent)
        if line_key not in seen_lines:
            seen_lines.add(line_key)
            line_text = normalize_line_text(line_key)
            sink_name = str(args.get("sink_name") or "")
            target_buffer = str(args.get("target_buffer") or "")
            if len(candidate_samples) < 20 and (
                (sink_name and sink_name in line_text) or (target_buffer and target_buffer in line_text)
            ):
                candidate_samples[line_text] = line_key
            method = line_matches_candidate(line_text, args)
            line_number = node_line_number(line_parent)
            if wanted_line_number > 0:
                method = "line_number_match" if line_number == wanted_line_number and method else ""
            if method:
                line_tokens = []
                matched_lines[line_text] = line_key
                match_methods[line_text] = method
                collect_descendant_pcode_tokens(line_parent, line_tokens, seen_tokens)
                tokens_by_line[line_text] = line_tokens
                tokens.extend(line_tokens)
        for child in node_children(node):
            visit(child)

    visit(markup)
    exact_lines = [
        line_text for line_text, method in match_methods.items() if method in {"exact_line_text", "line_number_match"}
    ]
    if exact_lines:
        matched_lines = {line_text: matched_lines[line_text] for line_text in exact_lines}
        match_methods = {line_text: match_methods[line_text] for line_text in exact_lines}
        tokens = []
        for line_text in exact_lines:
            tokens.extend(tokens_by_line.get(line_text, []))
    if not tokens:
        return [], {
            "resolved": False,
            "reason": "candidate_line_not_found",
            "candidate_line_text": wanted,
            "candidate_line_samples": list(candidate_samples.values()),
        }
    if len(matched_lines) != 1:
        return [], {
            "resolved": False,
            "reason": "ambiguous_candidate_line",
            "candidate_line_text": wanted,
            "matched_lines": list(matched_lines.values()),
            "match_methods": match_methods,
        }
    return tokens, {
        "resolved": False,
        "reason": "candidate_line_matched",
        "candidate_line_text": wanted,
        "matched_lines": list(matched_lines.values()),
        "match_methods": match_methods,
    }


def exact_sink_from_decompiler(program, function, args):
    if DecompInterface is None:
        return None, {"resolved": False, "reason": "decompiler_unavailable"}
    sink_name = str(args.get("sink_name") or "")
    target_buffer = str(args.get("target_buffer") or "")
    decompiler = DecompInterface()
    try:
        decompiler.openProgram(program)
        try:
            timeout_sec = max(5, int(parse_int(args.get("timeout_ms"), 30000) / 1000))
        except Exception:
            timeout_sec = 30
        results = decompiler.decompileFunction(function, timeout_sec, monitor)
    except Exception as exc:
        return None, {"resolved": False, "reason": "decompile_failed:%s" % exc}
    if not results.decompileCompleted():
        return None, {"resolved": False, "reason": "decompile_incomplete:%s" % results.getErrorMessage()}
    markup = results.getCCodeMarkup()
    tokens, base = collect_line_tokens(markup, args)
    if not tokens:
        return None, base
    desired = "CALL" if sink_name not in ("pointer_store", "array_store") else "STORE"
    candidates = {}
    for token in tokens:
        try:
            op = token.getPcodeOp()
        except Exception:
            op = None
        if op is None:
            continue
        mnemonic = pcode_op_mnemonic(op)
        if desired == "CALL" and mnemonic not in ("CALL", "CALLIND"):
            continue
        if desired == "STORE" and mnemonic != "STORE":
            continue
        address = pcode_op_address(op)
        if address is None:
            try:
                address = token.getMinAddress()
            except Exception:
                address = None
        if address is None:
            continue
        key = address_hex(address)
        candidates[key] = {
            "instruction_address": key,
            "mnemonic": mnemonic,
            "text": str(op),
        }
    if len(candidates) != 1:
        result = dict(base)
        result.update(
            {
                "resolved": False,
                "reason": "ambiguous_exact_sink" if candidates else "no_matching_pcode_op_on_candidate_line",
                "sink_name": sink_name,
                "target_buffer": target_buffer,
                "desired_mnemonic": desired,
                "candidate_ops": list(candidates.values()),
            }
        )
        return None, result
    address_text, op_fact = list(candidates.items())[0]
    resolved = dict(base)
    resolved.update(
        {
            "resolved": True,
            "reason": "",
            "sink_name": sink_name,
            "target_buffer": target_buffer,
            "desired_mnemonic": desired,
            "exact_sink_address": address_text,
            "pcode_op": op_fact,
        }
    )
    return address_from(program, address_text), resolved


def concrete_emulator_trace(program, start_address, target_address, max_steps, timeout_ms):
    if EmulatorHelper is None:
        return {"status": "unsupported", "reason": "EmulatorHelper unavailable", "instructions": []}
    helper = EmulatorHelper(program)
    instructions = []
    reached = False
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
        for _index in range(max_steps):
            if int((time.time() - started) * 1000) > timeout_ms:
                return {"status": "timeout", "instructions": instructions, "reached_target": reached}
            current = helper.getExecutionAddress()
            if current is None:
                return {"status": "unsupported", "reason": "execution address unavailable", "instructions": instructions}
            instruction = program.getListing().getInstructionAt(current)
            if instruction is not None:
                instructions.append(instruction_fact(instruction))
            if current == target_address:
                reached = True
                return {"status": "reached", "instructions": instructions, "reached_target": True}
            try:
                step_monitor = getMonitor()
            except Exception:
                step_monitor = monitor
            if not helper.step(step_monitor):
                return {"status": "stopped", "instructions": instructions, "reached_target": reached}
        return {"status": "step_cap", "instructions": instructions, "reached_target": reached}
    except Exception as exc:
        return {"status": "unsupported", "reason": str(exc), "instructions": instructions}
    finally:
        try:
            helper.dispose()
        except Exception:
            pass


def main():
    args = parse_kv_args(getScriptArgs())
    output_path = args.get("output_path")
    candidate_id = args.get("candidate_id", "")
    if not output_path:
        println("pcode_trace.py: missing output_path")
        return
    program = currentProgram
    target_address = address_from(program, args.get("target_address"))
    start_address = address_from(program, args.get("start_address")) or target_address
    if target_address is None:
        write_json(output_path, unsupported(candidate_id, "invalid_target_address", args))
        return
    function_manager = program.getFunctionManager()
    function_address = address_from(program, args.get("function_address"))
    function = None
    if function_address is not None:
        function = function_manager.getFunctionContaining(function_address)
    if function is None:
        function = function_manager.getFunctionContaining(target_address)
    if function is None:
        write_json(output_path, unsupported(candidate_id, "function_not_found", args))
        return
    if start_address is None:
        start_address = function.getEntryPoint()
    max_steps = parse_int(args.get("max_steps"), 2048)
    timeout_ms = parse_int(args.get("timeout_ms"), 30000)
    if max_steps <= 0:
        max_steps = 2048
    if timeout_ms <= 0:
        timeout_ms = 30000
    requested_target_address = target_address
    exact_target_address, exact_sink_resolution = exact_sink_from_decompiler(program, function, args)
    if exact_target_address is not None:
        target_address = exact_target_address
    static_instructions, pcode_ops = static_pcode_window(program, function, target_address, min(max_steps, 256))
    store_catalog, call_catalog = pcode_operation_catalog(program, function, min(max_steps, 256))
    replay = concrete_emulator_trace(program, start_address, target_address, max_steps, timeout_ms)
    if exact_target_address is not None:
        exact_sink_replay = concrete_emulator_trace(program, target_address, target_address, 1, timeout_ms)
    else:
        exact_sink_replay = {
            "status": "unsupported",
            "reason": "exact_sink_not_resolved",
            "instructions": [],
            "reached_target": False,
        }
    payload = {
        "schema_version": 1,
        "trace_kind": "ghidra_pcode",
        "candidate_id": candidate_id,
        "status": replay.get("status", "unknown"),
        "unsupported": replay.get("status") == "unsupported",
        "function": {
            "name": function.getName(),
            "entry_address": address_hex(function.getEntryPoint()),
        },
        "start_address": address_hex(start_address),
        "requested_target_address": address_hex(requested_target_address),
        "target_address": address_hex(target_address),
        "exact_sink_resolution": exact_sink_resolution,
        "instructions": static_instructions,
        "pcode_ops": pcode_ops,
        "memory_writes": pcode_memory_writes(pcode_ops),
        "store_catalog": store_catalog,
        "call_catalog": call_catalog,
        "replay": replay,
        "exact_sink_replay": exact_sink_replay,
        "request": dict(args),
    }
    if payload["unsupported"]:
        payload["reason"] = replay.get("reason", "unsupported")
    write_json(output_path, payload)


if __name__ == "__main__":
    main()
