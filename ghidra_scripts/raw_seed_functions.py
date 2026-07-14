# Headless helper for raw firmware sections that have no loader metadata.
# It seeds a small set of likely function starts so export_functions.py has
# something to decompile after a BinaryLoader import.

from ghidra.program.model.symbol import SourceType


def _parse_args(argv):
    parsed = {}
    for item in argv:
        if "=" in item:
            key, value = item.split("=", 1)
            parsed[key.strip()] = value.strip()
    return parsed


def _parse_int(value, default):
    if value is None or value == "":
        return default
    try:
        return int(value, 0)
    except Exception:
        return default


def _read_bytes(memory, addr, size):
    out = []
    for offset in range(size):
        try:
            out.append(memory.getByte(addr.add(offset)) & 0xFF)
        except Exception:
            return None
    return out


def _matches_arch_prologue(memory, addr, language_id):
    data = _read_bytes(memory, addr, 4)
    if not data:
        return False
    lang = (language_id or "").upper()
    if lang.startswith("MIPS:BE"):
        return data[0] == 0x27 and data[1] == 0xBD and data[2] in (0xFF, 0xFE, 0xFD, 0xFC)
    if lang.startswith("MIPS:LE"):
        return data[3] == 0x27 and data[2] == 0xBD and data[1] in (0xFF, 0xFE, 0xFD, 0xFC)
    if lang.startswith("ARM:LE"):
        return data in ([0x00, 0x48, 0x2D, 0xE9], [0x10, 0x40, 0x2D, 0xE9], [0xF0, 0x40, 0x2D, 0xE9])
    if lang.startswith("ARM:BE"):
        return data in ([0xE9, 0x2D, 0x48, 0x00], [0xE9, 0x2D, 0x40, 0x10], [0xE9, 0x2D, 0x40, 0xF0])
    return False


def _make_function(listing, addr, name):
    try:
        if listing.getFunctionContaining(addr) is not None:
            return False
    except Exception:
        pass
    try:
        disassemble(addr)
    except Exception:
        return False
    try:
        if listing.getInstructionAt(addr) is None:
            return False
    except Exception:
        return False
    try:
        createFunction(addr, name)
        return True
    except Exception:
        return False


def main():
    args = _parse_args(getScriptArgs())
    program = currentProgram
    memory = program.getMemory()
    listing = program.getListing()
    lang = str(program.getLanguageID())

    start_offset = _parse_int(args.get("start"), 0)
    scan_len = _parse_int(args.get("scan_len"), 0x200000)
    stride = _parse_int(args.get("stride"), 4)
    max_funcs = _parse_int(args.get("max_funcs"), 256)
    if stride <= 0:
        stride = 4
    if max_funcs <= 0:
        max_funcs = 1

    blocks = list(memory.getBlocks())
    if not blocks:
        println("raw_seed_functions: no memory blocks")
        return
    block = blocks[0]
    block_start = block.getStart()
    block_size = int(block.getSize())
    scan_start = start_offset if start_offset >= 0 else 0
    if scan_start >= block_size:
        scan_start = 0
    scan_end = min(block_size, scan_start + max(0, scan_len))

    created = 0
    entry = block_start.add(scan_start)
    if _make_function(listing, entry, "raw_entry_%X" % int(entry.getOffset())):
        created += 1

    offset = scan_start
    while offset + 4 <= scan_end and created < max_funcs:
        addr = block_start.add(offset)
        if _matches_arch_prologue(memory, addr, lang):
            if _make_function(listing, addr, "raw_func_%X" % int(addr.getOffset())):
                created += 1
        offset += stride

    try:
        analyzeChanges(program)
    except Exception:
        pass
    println(
        "raw_seed_functions: language=%s start=0x%X scan_len=0x%X created=%d"
        % (lang, scan_start, scan_len, created)
    )


if __name__ == "__main__":
    main()
