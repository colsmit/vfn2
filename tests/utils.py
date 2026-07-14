from pathlib import Path

from typing import List, Optional

from binary_agent.data.manifest import FunctionRecord
from binary_agent.ingest.loader import FunctionNode


def make_function_node(
    name: str = "vulnerable_copy",
    text: Optional[str] = None,
    relative_path: Optional[str] = None,
    callers: Optional[List[str]] = None,
    callees: Optional[List[str]] = None,
    wrapper_type: Optional[str] = None,
    stack_regions: Optional[List[dict]] = None,
) -> FunctionNode:
    relative_path = relative_path or "1000_vulnerable_copy.c"
    node_text = text or "void vulnerable_copy(char *buf) { strcpy(buf, input); }"
    stack_regions = stack_regions or []
    record = FunctionRecord(
        address="0x1000",
        relative_address=0x1000,
        name=name,
        relative_path=relative_path,
        source_exists=True,
        ordinal=0,
        size_addresses=16,
        body_size_bytes=16,
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=10,
        line_count=3,
        stack_regions=stack_regions,
        return_type="void",
        prototype="void vulnerable_copy(char *buf)",
        parameters=[{"name": "buf", "data_type": "char *", "storage": "stack"}],
        emit_c=True,
        string_refs=[{"address": "0x2000", "value": "%s"}],
        pcode_calls=[],
        pcode_stores=[],
        wrapper_type=wrapper_type,
    )
    callers = callers or ["main"]
    callees = callees or ["strcpy"]
    return FunctionNode(
        record=record,
        text=node_text,
        metadata={
            "binary": "demo.bin",
            "function_name": name,
            "address": "0x1000",
            "relative_address": 0x1000,
            "relative_path": relative_path,
            "source_symbol": name,
            "demangled_name": name,
            "source_object": "",
            "ordinal": 0,
            "is_thunk": False,
            "stack_purge": None,
            "call_fixup": None,
            "prototype": "void vulnerable_copy(char *buf)",
            "return_type": "void",
            "parameters": record.parameters,
            "byte_length": record.byte_length,
            "line_count": record.line_count,
            "stack_regions": record.stack_regions,
            "string_refs": record.string_refs,
            "pcode_calls": record.pcode_calls,
            "pcode_stores": record.pcode_stores,
            "wrapper_type": wrapper_type,
            "stub_kind": None,
            "emit_c": True,
            "image_base": 0,
            "callees": callees,
            "callers": callers,
            "callees_direct": callees,
            "callers_direct": callers,
            "callees_thread_start": [],
            "callers_thread_start": [],
            "callees_pcode": [],
            "callers_pcode": [],
        },
        path=Path("dummy"),
        record_index=0,
    )
