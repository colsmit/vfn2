import json
from dataclasses import replace
from pathlib import Path

from binary_agent.analysis.callgraph import CallGraph
from binary_agent.analysis.confirmation import write_evidence_packs
from binary_agent.analysis.candidates import (
    StaticCandidate,
    confirmation_review_rule,
    confirmation_rule_counts,
    extract_static_candidates,
    run_static_pipeline,
    select_confirmation_candidates,
)
from binary_agent.analysis.extractors import load_memory_operation_specs
from binary_agent.data.manifest import FunctionRecord, Manifest, write_normalized_manifest
from binary_agent.ingest.loader import load_function_nodes


def _record(
    *,
    name: str,
    address: str,
    ordinal: int,
    relative_path: str,
    text: str,
    stack_regions: list[dict] | None = None,
    source_symbol: str = "",
    demangled_name: str = "",
    source_object: str = "",
    pcode_calls: list[dict] | None = None,
    pcode_stores: list[dict] | None = None,
    pcode_loads: list[dict] | None = None,
    c_line_addresses: list[dict] | None = None,
    global_refs: list[dict] | None = None,
    static_refs: list[dict] | None = None,
    tls_refs: list[dict] | None = None,
    composite_fields: list[dict] | None = None,
) -> FunctionRecord:
    return FunctionRecord(
        address=address,
        relative_address=int(address, 16),
        name=name,
        relative_path=relative_path,
        source_exists=True,
        ordinal=ordinal,
        size_addresses=16,
        body_size_bytes=16,
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=len(text.encode("utf-8")),
        line_count=len(text.splitlines()),
        return_type="void",
        prototype=f"void {name}(void)",
        parameters=[],
        emit_c=True,
        source_symbol=source_symbol,
        demangled_name=demangled_name,
        source_object=source_object,
        stack_regions=stack_regions or [],
        string_refs=[],
        pcode_calls=pcode_calls or [],
        pcode_stores=pcode_stores or [],
        pcode_loads=pcode_loads or [],
        c_line_addresses=c_line_addresses or [],
        ambiguous_callsites=[],
        global_refs=global_refs or [],
        static_refs=static_refs or [],
        tls_refs=tls_refs or [],
        composite_fields=composite_fields or [],
    )


def _stack_region(name: str = "local_20", size: int = 16, start: int = -0x20) -> dict:
    return {
        "start_offset": start,
        "end_offset": start + size,
        "size_bytes": size,
        "var_names": [name],
        "data_types": ["char"],
    }


def _source_to_write_trace(
    *,
    write_source: str = "constant_or_literal",
    write_size: str = "constant_or_literal",
    write_offset: str = "constant_or_literal",
    destination_pointer: str = "internal_local",
) -> dict:
    return {
        "source_to_write": {
            "roles": {
                "write_source": {"classification": write_source, "complete": True},
                "write_size": {"classification": write_size, "complete": True},
                "write_offset": {"classification": write_offset, "complete": True},
                "destination_pointer": {"classification": destination_pointer, "complete": True},
            }
        }
    }


def _write_export(tmp_path: Path, records: list[FunctionRecord], sources: dict[str, str]) -> Path:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    for relative_path, text in sources.items():
        (export_dir / relative_path).write_text(text)
    manifest = Manifest(
        binary="demo.bin",
        generated_at="2026-04-24T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=records,
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))
    return export_dir


def _write_raw_export(
    tmp_path: Path,
    entries: list[dict],
    sources: dict[str, str],
    callgraph: dict | None = None,
) -> Path:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    for relative_path, text in sources.items():
        (export_dir / relative_path).write_text(text)
    with (export_dir / "manifest.jsonl").open("w") as fout:
        for entry in entries:
            fout.write(json.dumps(entry))
            fout.write("\n")
    if callgraph is not None:
        (export_dir / "callgraph.json").write_text(json.dumps(callgraph))
    write_normalized_manifest(export_dir)
    return export_dir


def test_static_candidates_detect_oversized_fgets(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  fgets(local_20, 64, stdin);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.sink == "fgets"
    assert candidate.verdict == "overflow"
    assert candidate.write_size_bytes == 64
    assert candidate.input_reaches_sink is True


def test_static_candidates_detect_constant_oob_indexed_read(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int value = local_20[20];
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    reads = [item for item in report.candidate_findings if item.vulnerability_type == "out_of_bounds_read"]
    assert len(reads) == 1
    candidate = reads[0]
    assert candidate.kind == "indexed_read"
    assert candidate.sink == "array_load"
    assert candidate.write_relation == "proven_oob_read"
    assert candidate.verdict == "overflow"
    assert report.vulnerability_reports == []


def test_static_candidates_skip_guarded_symbolic_oob_read(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int i;
  scanf("%d", &i);
  if (0 <= i && i < 16) {
    int value = local_20[i];
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert [item for item in report.candidate_findings if item.kind == "indexed_read"] == []


def test_symbolic_oob_read_enters_confirmation_queue(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int i;
  scanf("%d", &i);
  int value = local_20[i];
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    reads = [item for item in report.candidate_findings if item.kind == "indexed_read"]
    assert len(reads) == 1
    assert reads[0].vulnerability_type == "out_of_bounds_read"
    assert reads[0].write_relation == "symbolic_read_offset"
    assert [item.candidate_id for item in report.confirmation_findings] == [reads[0].candidate_id]
    assert report.confirmation_findings[0].classification_trace["confirmation_rule"] == "controlled_read_offset"
    assert report.vulnerability_reports == []


def test_symbolic_heap_pointer_read_distinguishes_missing_and_present_count_guard(tmp_path: Path) -> None:
    vulnerable = """
void main(FILE *param_1) {
  uint count;
  uint index;
  int *table;
  count = (uint)fgetc(param_1);
  table = calloc(count, 4);
  index = (uint)fgetc(param_1);
  if (*(int *)((long)table + (ulong)index * 4) == 0) {
    puts("selected");
  }
}
"""
    fixed = vulnerable.replace(
        "if (*(int *)((long)table + (ulong)index * 4) == 0)",
        "if ((index < count) && (*(int *)((long)table + (ulong)index * 4) == 0))",
    )
    vulnerable_root = tmp_path / "vulnerable"
    fixed_root = tmp_path / "fixed"
    vulnerable_root.mkdir()
    fixed_root.mkdir()
    vulnerable_export = _write_export(
        vulnerable_root,
        [
            _record(
                name="main",
                address="0x1000",
                ordinal=0,
                relative_path="main.c",
                text=vulnerable,
                pcode_loads=[
                    {
                        "operation_address": "0x1010",
                        "read_width": 4,
                        "address_inputs": [{"var_name": "table"}, {"var_name": "index"}],
                    }
                ],
                c_line_addresses=[
                    {"line_number": 9, "addresses": ["0x100f"], "load_addresses": ["0x1010"]}
                ],
            )
        ],
        {"main.c": vulnerable},
    )
    fixed_export = _write_export(
        fixed_root,
        [_record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=fixed)],
        {"main.c": fixed},
    )

    vulnerable_report = run_static_pipeline(vulnerable_export)
    fixed_report = run_static_pipeline(fixed_export)

    reads = [item for item in vulnerable_report.candidate_findings if item.kind == "pointer_read"]
    assert len(reads) == 1
    assert reads[0].vulnerability_type == "out_of_bounds_read"
    assert reads[0].destination_kind == "heap"
    assert reads[0].capacity_model["symbolic_expr"] == "(count) * (4)"
    assert reads[0].offset_expr == "index * 4"
    assert reads[0].write_relation == "symbolic_read_offset"
    assert reads[0].operation_address == "0x1010"
    assert "pcode_loads" in reads[0].evidence_sources
    assert reads[0].classification_trace["source_to_write"]["roles"]["write_offset"]["classification"] == "source_controlled"
    assert [item.kind for item in vulnerable_report.confirmation_findings] == ["pointer_read"]
    assert [item for item in fixed_report.candidate_findings if item.kind == "pointer_read"] == []


def test_static_candidates_detect_cursor_limit_oob_read(tmp_path: Path) -> None:
    text = """
ulong from_header(byte *param_1, ulong param_2, long param_3, long param_4, long param_5, char param_6, char param_7) {
  byte *local_20;
  byte *local_18;
  byte *pbVar2;
  ulong local_10;
  local_20 = param_1 + param_2;
  local_18 = param_1;
  if ((*local_18 == 0x80) || (*local_18 == 0xff)) {
    local_18 = local_18 + 1;
    while (true) {
      pbVar2 = local_18 + 1;
      local_10 = (ulong)*local_18 + local_10 * 0x100;
      local_18 = pbVar2;
      if (pbVar2 == local_20) break;
    }
  }
  return local_10;
}
"""
    record = _record(
        name="from_header",
        address="0x1000",
        ordinal=0,
        relative_path="from_header.c",
        text=text,
        stack_regions=[_stack_region("local_20", size=8, start=-0x20)],
    )
    export_dir = _write_export(tmp_path, [record], {"from_header.c": text})

    report = run_static_pipeline(export_dir)

    reads = [item for item in report.candidate_findings if item.sink == "cursor_limit_read"]
    assert len(reads) == 1
    candidate = reads[0]
    assert candidate.vulnerability_type == "out_of_bounds_read"
    assert candidate.write_relation == "symbolic_read_offset"
    assert candidate.destination_kind == "source_buffer"
    assert candidate.capacity_source == "function_length_argument"
    assert candidate.capacity_model["symbolic_expr"] == "param_2"
    assert candidate.offset_expr == "param_2"
    assert candidate.classification_trace["function_harness"]["length_arg_index"] == 1
    assert candidate.classification_trace["dynamic_proof"]["offset_from_concrete_input"] is True


def test_static_candidates_detect_memcpy_source_oob_read(tmp_path: Path) -> None:
    text = """
void main(void) {
  char src[8];
  char dst[32];
  memcpy(dst, src + 12, 4);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[
            _stack_region("src", 8, -0x30),
            _stack_region("dst", 32, -0x28),
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    reads = [item for item in report.candidate_findings if item.kind == "source_read"]
    assert len(reads) == 1
    assert reads[0].vulnerability_type == "out_of_bounds_read"
    assert reads[0].write_relation == "proven_oob_read"
    assert reads[0].target_buffer == "src"


def test_static_candidates_infer_packet_slice_source_capacity(tmp_path: Path) -> None:
    text = """
void main(void) {
  unsigned char heartbeat_record[8];
  unsigned char dst[64];
  unsigned char *p = heartbeat_record;
  unsigned char *pl;
  unsigned short hbtype;
  unsigned int payload;
  read(0, heartbeat_record, sizeof(heartbeat_record));
  hbtype = *p++;
  n2s(p, payload);
  pl = p;
  memcpy(dst, pl, payload);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    reads = [item for item in report.candidate_findings if item.kind == "source_read"]
    assert len(reads) == 1
    candidate = reads[0]
    assert candidate.vulnerability_type == "out_of_bounds_read"
    assert candidate.write_relation == "symbolic_size"
    assert candidate.write_size_expr == "payload"
    assert candidate.capacity_bytes == 5
    assert candidate.capacity_source == "inferred_packet_slice_remaining"
    assert candidate.target_buffer == "heartbeat_record[3:]"
    assert [item.candidate_id for item in report.confirmation_findings] == [candidate.candidate_id]


def test_static_candidates_infer_direct_packet_slice_source_capacity(tmp_path: Path) -> None:
    text = """
void main(void) {
  unsigned char heartbeat_record[8];
  unsigned char dst[64];
  unsigned int payload;
  read(0, heartbeat_record, sizeof(heartbeat_record));
  payload = CONCAT11(heartbeat_record[1], heartbeat_record[2]);
  memcpy(dst, heartbeat_record + 3, payload);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    reads = [item for item in report.candidate_findings if item.kind == "source_read"]
    assert len(reads) == 1
    candidate = reads[0]
    assert candidate.vulnerability_type == "out_of_bounds_read"
    assert candidate.write_relation == "symbolic_size"
    assert candidate.capacity_bytes == 5
    assert candidate.capacity_source == "inferred_packet_slice_remaining"
    assert candidate.target_buffer == "heartbeat_record[3:]"


def test_static_candidates_infer_interprocedural_record_source_capacity(tmp_path: Path) -> None:
    main_text = """
int main(void) {
  unsigned char heartbeat_record[8];
  SSL3_STATE ssl3_state;
  SSL ssl;
  read(0, heartbeat_record, 8);
  ssl.s3 = &ssl3_state;
  ssl3_state.rrec.data = heartbeat_record;
  ssl3_state.rrec.length = 8;
  tls1_process_heartbeat(&ssl);
}
"""
    heartbeat_text = """
int tls1_process_heartbeat(SSL *s) {
  unsigned char *puVar3;
  unsigned int uVar6;
  puVar3 = (s->s3->rrec).data;
  uVar6 = CONCAT11(puVar3[1], puVar3[2]);
  memcpy(buf_ + 3, puVar3 + 3, (ulong)uVar6);
}
"""
    main_record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=main_text,
        stack_regions=[
            _stack_region("heartbeat_record", 8, -0x20),
            _stack_region("ssl3_state", 1200, -0x550),
            _stack_region("ssl", 808, -0x900),
        ],
    )
    heartbeat_record = _record(
        name="tls1_process_heartbeat",
        address="0x2000",
        ordinal=1,
        relative_path="tls.c",
        text=heartbeat_text,
    )
    export_dir = _write_export(
        tmp_path,
        [main_record, heartbeat_record],
        {"main.c": main_text, "tls.c": heartbeat_text},
    )

    report = run_static_pipeline(export_dir)

    reads = [
        item
        for item in report.candidate_findings
        if item.kind == "source_read" and item.function_name == "tls1_process_heartbeat"
    ]
    assert len(reads) == 1
    candidate = reads[0]
    assert candidate.vulnerability_type == "out_of_bounds_read"
    assert candidate.write_relation == "symbolic_size"
    assert candidate.write_size_expr == "(ulong)uVar6"
    assert candidate.capacity_bytes == 5
    assert candidate.capacity_source == "inferred_packet_slice_remaining"
    assert candidate.target_buffer == "heartbeat_record[3:]"
    assert "interprocedural_field_source" in candidate.evidence_sources
    assert candidate.source_evidence == ["line 6: read(0, heartbeat_record, 8);"]
    assert [item.candidate_id for item in report.confirmation_findings] == [candidate.candidate_id]


def test_static_candidates_infer_wrapped_interprocedural_record_source_capacity(tmp_path: Path) -> None:
    main_text = """
int main(void) {
  unsigned char heartbeat_record[8];
  SSL3_STATE ssl3_state;
  SSL ssl;
  read(0, heartbeat_record, 8);
  ssl.s3 = &ssl3_state;
  ssl3_state.rrec.data = heartbeat_record;
  ssl3_state.rrec.length = 8;
  heartbeat_outer(&ssl);
}
"""
    outer_text = """
int heartbeat_outer(SSL *s) {
  return heartbeat_wrapper(s);
}
"""
    wrapper_text = """
int heartbeat_wrapper(SSL *s) {
  return tls1_process_heartbeat(s);
}
"""
    heartbeat_text = """
int tls1_process_heartbeat(SSL *s) {
  unsigned char *puVar3;
  unsigned int uVar6;
  puVar3 = (s->s3->rrec).data;
  uVar6 = CONCAT11(puVar3[1], puVar3[2]);
  memcpy(buf_ + 3, puVar3 + 3, (ulong)uVar6);
}
"""
    main_record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=main_text,
        stack_regions=[
            _stack_region("heartbeat_record", 8, -0x20),
            _stack_region("ssl3_state", 1200, -0x550),
            _stack_region("ssl", 808, -0x900),
        ],
    )
    wrapper_record = _record(
        name="heartbeat_outer",
        address="0x1800",
        ordinal=1,
        relative_path="outer.c",
        text=outer_text,
    )
    inner_record = _record(
        name="heartbeat_wrapper",
        address="0x1900",
        ordinal=2,
        relative_path="wrapper.c",
        text=wrapper_text,
    )
    heartbeat_record = _record(
        name="tls1_process_heartbeat",
        address="0x2000",
        ordinal=3,
        relative_path="tls.c",
        text=heartbeat_text,
    )
    export_dir = _write_export(
        tmp_path,
        [main_record, wrapper_record, inner_record, heartbeat_record],
        {"main.c": main_text, "outer.c": outer_text, "wrapper.c": wrapper_text, "tls.c": heartbeat_text},
    )

    report = run_static_pipeline(export_dir)

    reads = [
        item
        for item in report.candidate_findings
        if item.kind == "source_read" and item.function_name == "tls1_process_heartbeat"
    ]
    assert len(reads) == 1
    candidate = reads[0]
    assert candidate.target_buffer == "heartbeat_record[3:]"
    assert candidate.capacity_bytes == 5
    assert candidate.capacity_source == "inferred_packet_slice_remaining"
    assert "fixed_point_source_read_summary" in candidate.evidence_sources
    assert "source_summary_depth_2" in candidate.evidence_sources
    assert "source_read_wrapper_call:heartbeat_wrapper->tls1_process_heartbeat" in candidate.evidence_sources
    assert "source_read_wrapper_call:heartbeat_outer->heartbeat_wrapper" in candidate.evidence_sources
    assert candidate.path_is_valid is True
    assert candidate.call_path == ["main", "tls1_process_heartbeat"]
    assert [item.candidate_id for item in report.confirmation_findings] == [candidate.candidate_id]


def test_static_candidates_infer_wrapper_field_projection_source_capacity(tmp_path: Path) -> None:
    main_text = """
int main(void) {
  unsigned char heartbeat_record[8];
  SSL3_STATE ssl3_state;
  SSL ssl;
  HeartbeatCtx ctx;
  read(0, heartbeat_record, 8);
  ssl.s3 = &ssl3_state;
  ssl3_state.rrec.data = heartbeat_record;
  ctx.ssl = &ssl;
  heartbeat_ctx_wrapper(&ctx);
}
"""
    wrapper_text = """
int heartbeat_ctx_wrapper(HeartbeatCtx *ctx) {
  return tls1_process_heartbeat(ctx->ssl);
}
"""
    heartbeat_text = """
int tls1_process_heartbeat(SSL *s) {
  unsigned char *p;
  unsigned int payload;
  p = (s->s3->rrec).data;
  payload = CONCAT11(p[1], p[2]);
  memcpy(buf_ + 3, p + 3, payload);
}
"""
    main_record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=main_text,
        stack_regions=[
            _stack_region("heartbeat_record", 8, -0x20),
            _stack_region("ssl3_state", 1200, -0x550),
            _stack_region("ssl", 808, -0x900),
            _stack_region("ctx", 64, -0x950),
        ],
    )
    wrapper_record = _record(
        name="heartbeat_ctx_wrapper",
        address="0x1800",
        ordinal=1,
        relative_path="wrapper.c",
        text=wrapper_text,
    )
    heartbeat_record = _record(
        name="tls1_process_heartbeat",
        address="0x2000",
        ordinal=2,
        relative_path="tls.c",
        text=heartbeat_text,
    )
    export_dir = _write_export(
        tmp_path,
        [main_record, wrapper_record, heartbeat_record],
        {"main.c": main_text, "wrapper.c": wrapper_text, "tls.c": heartbeat_text},
    )

    report = run_static_pipeline(export_dir)

    reads = [
        item
        for item in report.candidate_findings
        if item.kind == "source_read" and item.function_name == "tls1_process_heartbeat"
    ]
    assert len(reads) == 1
    candidate = reads[0]
    assert candidate.target_buffer == "heartbeat_record[3:]"
    assert candidate.capacity_bytes == 5
    assert candidate.capacity_source == "inferred_packet_slice_remaining"
    assert "source_read_wrapper_call:heartbeat_ctx_wrapper->tls1_process_heartbeat" in candidate.evidence_sources
    assert [item.candidate_id for item in report.confirmation_findings] == [candidate.candidate_id]


def test_static_candidates_infer_wrapper_local_alias_source_capacity(tmp_path: Path) -> None:
    main_text = """
int main(void) {
  unsigned char heartbeat_record[8];
  SSL3_STATE ssl3_state;
  SSL ssl;
  read(0, heartbeat_record, 8);
  ssl.s3 = &ssl3_state;
  ssl3_state.rrec.data = heartbeat_record;
  heartbeat_alias_wrapper(&ssl);
}
"""
    wrapper_text = """
int heartbeat_alias_wrapper(SSL *s) {
  SSL *next;
  next = s;
  return tls1_process_heartbeat(next);
}
"""
    heartbeat_text = """
int tls1_process_heartbeat(SSL *s) {
  unsigned char *p;
  unsigned int payload;
  p = (s->s3->rrec).data;
  payload = CONCAT11(p[1], p[2]);
  memcpy(buf_ + 3, p + 3, payload);
}
"""
    main_record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=main_text,
        stack_regions=[
            _stack_region("heartbeat_record", 8, -0x20),
            _stack_region("ssl3_state", 1200, -0x550),
            _stack_region("ssl", 808, -0x900),
        ],
    )
    wrapper_record = _record(
        name="heartbeat_alias_wrapper",
        address="0x1800",
        ordinal=1,
        relative_path="wrapper.c",
        text=wrapper_text,
    )
    heartbeat_record = _record(
        name="tls1_process_heartbeat",
        address="0x2000",
        ordinal=2,
        relative_path="tls.c",
        text=heartbeat_text,
    )
    export_dir = _write_export(
        tmp_path,
        [main_record, wrapper_record, heartbeat_record],
        {"main.c": main_text, "wrapper.c": wrapper_text, "tls.c": heartbeat_text},
    )

    report = run_static_pipeline(export_dir)

    reads = [
        item
        for item in report.candidate_findings
        if item.kind == "source_read" and item.function_name == "tls1_process_heartbeat"
    ]
    assert len(reads) == 1
    candidate = reads[0]
    assert candidate.target_buffer == "heartbeat_record[3:]"
    assert "source_read_wrapper_call:heartbeat_alias_wrapper->tls1_process_heartbeat" in candidate.evidence_sources


def test_static_candidates_reject_ambiguous_wrapper_local_alias(tmp_path: Path) -> None:
    main_text = """
int main(void) {
  unsigned char heartbeat_record[8];
  SSL3_STATE ssl3_state;
  SSL ssl_a;
  SSL ssl_b;
  read(0, heartbeat_record, 8);
  ssl_a.s3 = &ssl3_state;
  ssl3_state.rrec.data = heartbeat_record;
  heartbeat_ambiguous_wrapper(&ssl_b, &ssl_a, flag);
}
"""
    wrapper_text = """
int heartbeat_ambiguous_wrapper(SSL *a, SSL *b, int flag) {
  SSL *next;
  if (flag) next = a;
  else next = b;
  return tls1_process_heartbeat(next);
}
"""
    heartbeat_text = """
int tls1_process_heartbeat(SSL *s) {
  unsigned char *p;
  unsigned int payload;
  p = (s->s3->rrec).data;
  payload = CONCAT11(p[1], p[2]);
  memcpy(buf_ + 3, p + 3, payload);
}
"""
    main_record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=main_text,
        stack_regions=[
            _stack_region("heartbeat_record", 8, -0x20),
            _stack_region("ssl3_state", 1200, -0x550),
            _stack_region("ssl_a", 808, -0x900),
            _stack_region("ssl_b", 808, -0xd00),
        ],
    )
    wrapper_record = _record(
        name="heartbeat_ambiguous_wrapper",
        address="0x1800",
        ordinal=1,
        relative_path="wrapper.c",
        text=wrapper_text,
    )
    heartbeat_record = _record(
        name="tls1_process_heartbeat",
        address="0x2000",
        ordinal=2,
        relative_path="tls.c",
        text=heartbeat_text,
    )
    export_dir = _write_export(
        tmp_path,
        [main_record, wrapper_record, heartbeat_record],
        {"main.c": main_text, "wrapper.c": wrapper_text, "tls.c": heartbeat_text},
    )

    report = run_static_pipeline(export_dir)

    assert [
        item
        for item in report.candidate_findings
        if item.kind == "source_read" and item.function_name == "tls1_process_heartbeat"
    ] == []


def test_static_candidates_suppress_guarded_packet_source_read(tmp_path: Path) -> None:
    text = """
void main(void) {
  unsigned char heartbeat_record[8];
  unsigned char dst[64];
  unsigned int payload;
  read(0, heartbeat_record, sizeof(heartbeat_record));
  payload = CONCAT11(heartbeat_record[1], heartbeat_record[2]);
  if (payload <= 5) {
    memcpy(dst, heartbeat_record + 3, payload);
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)

    assert [item for item in report.candidate_findings if item.kind == "source_read"] == []
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())
    source_read = [
        item
        for item in suppressed
        if item["sink"] == "memcpy_source_read" and item["target_buffer"] == "heartbeat_record[3:]"
    ]
    assert len(source_read) == 2
    assert source_read[0]["reason"] == "fact_enrichment_proven_safe"
    assert "read size is bounded by 5, remaining source capacity is 5" in source_read[0]["trace"]["condition"]


def test_static_candidates_infer_global_field_record_source_capacity(tmp_path: Path) -> None:
    main_text = """
int main(void) {
  read(0, g_record, 8);
  g_ssl.s3 = &g_state;
  g_state.rrec.data = g_record;
  tls1_process_heartbeat(&g_ssl);
}
"""
    heartbeat_text = """
int tls1_process_heartbeat(SSL *s) {
  unsigned char *p;
  unsigned int payload;
  p = (s->s3->rrec).data;
  payload = CONCAT11(p[1], p[2]);
  memcpy(buf_ + 3, p + 3, payload);
}
"""
    main_record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=main_text,
        global_refs=[
            {"label": "g_ssl", "var_names": ["g_ssl"], "size_bytes": 808, "address": "0x5000"},
            {"label": "g_state", "var_names": ["g_state"], "size_bytes": 1200, "address": "0x6000"},
            {"label": "g_record", "var_names": ["g_record"], "size_bytes": 8, "address": "0x7000"},
        ],
    )
    heartbeat_record = _record(
        name="tls1_process_heartbeat",
        address="0x2000",
        ordinal=1,
        relative_path="tls.c",
        text=heartbeat_text,
    )
    export_dir = _write_export(
        tmp_path,
        [main_record, heartbeat_record],
        {"main.c": main_text, "tls.c": heartbeat_text},
    )

    report = run_static_pipeline(export_dir)

    reads = [
        item
        for item in report.candidate_findings
        if item.kind == "source_read" and item.function_name == "tls1_process_heartbeat"
    ]
    assert len(reads) == 1
    candidate = reads[0]
    assert candidate.target_buffer == "g_record[3:]"
    assert candidate.destination_kind == "global"
    assert candidate.capacity_bytes == 5
    assert candidate.capacity_source == "inferred_packet_slice_remaining"
    assert candidate.write_relation == "symbolic_size"


def test_static_candidates_infer_heap_field_record_source_capacity(tmp_path: Path) -> None:
    main_text = """
int main(void) {
  unsigned char heartbeat_record[8];
  SSL *ssl;
  SSL3_STATE *ssl3_state;
  read(0, heartbeat_record, 8);
  ssl = malloc(808);
  ssl3_state = malloc(1200);
  ssl->s3 = ssl3_state;
  ssl3_state->rrec.data = heartbeat_record;
  tls1_process_heartbeat(ssl);
}
"""
    heartbeat_text = """
int tls1_process_heartbeat(SSL *s) {
  unsigned char *p;
  unsigned int payload;
  p = (s->s3->rrec).data;
  payload = CONCAT11(p[1], p[2]);
  memcpy(buf_ + 3, p + 3, payload);
}
"""
    main_record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=main_text,
        stack_regions=[_stack_region("heartbeat_record", 8, -0x20)],
    )
    heartbeat_record = _record(
        name="tls1_process_heartbeat",
        address="0x2000",
        ordinal=1,
        relative_path="tls.c",
        text=heartbeat_text,
    )
    export_dir = _write_export(
        tmp_path,
        [main_record, heartbeat_record],
        {"main.c": main_text, "tls.c": heartbeat_text},
    )

    report = run_static_pipeline(export_dir)

    reads = [
        item
        for item in report.candidate_findings
        if item.kind == "source_read" and item.function_name == "tls1_process_heartbeat"
    ]
    assert len(reads) == 1
    candidate = reads[0]
    assert candidate.target_buffer == "heartbeat_record[3:]"
    assert candidate.capacity_bytes == 5
    assert candidate.capacity_source == "inferred_packet_slice_remaining"
    assert candidate.write_relation == "symbolic_size"


def test_integer_overflow_size_feeding_memcpy_is_candidate(tmp_path: Path) -> None:
    text = """
void main(void) {
  char src[64];
  char dst[64];
  int n;
  scanf("%d", &n);
  memcpy(dst, src, n * 4);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[
            _stack_region("src", 64, -0x80),
            _stack_region("dst", 64, -0x40),
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    risks = [
        item for item in report.candidate_findings
        if item.vulnerability_type == "integer_overflow_to_memory_access"
    ]
    assert risks
    assert {item.write_relation for item in risks} == {"integer_overflow_risk"}
    assert {item.triage_tier for item in risks} == {"integer_memory_risk"}
    assert [item for item in report.confirmation_findings if item.vulnerability_type != "memory_overflow"] == []


def test_integer_underflow_offset_feeding_indexed_read_is_candidate(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int n;
  scanf("%d", &n);
  int value = local_20[n - 1];
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    risks = [
        item for item in report.candidate_findings
        if item.vulnerability_type == "integer_underflow_to_memory_access"
    ]
    assert len(risks) == 1
    assert risks[0].write_relation == "integer_underflow_risk"


def test_signed_conversion_size_feeding_read_is_candidate(tmp_path: Path) -> None:
    text = """
void main(void) {
  char dst[64];
  int n;
  scanf("%d", &n);
  read(0, dst, (size_t)n);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region("dst", 64, -0x40)],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    risks = [
        item for item in report.candidate_findings
        if item.vulnerability_type == "signed_conversion_to_memory_access"
    ]
    assert len(risks) == 1
    assert risks[0].write_relation == "signed_conversion_risk"


def test_integer_truncation_index_feeding_read_is_candidate(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int n;
  scanf("%d", &n);
  int value = local_20[(unsigned char)n];
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    risks = [
        item for item in report.candidate_findings
        if item.vulnerability_type == "integer_truncation_to_memory_access"
    ]
    assert len(risks) == 1
    assert risks[0].write_relation == "integer_truncation_risk"


def test_bounded_byte_sink_does_not_trust_unknown_decompiler_array_extent(tmp_path: Path) -> None:
    text = """
void main(void) {
  stat64 local_848[14];
  fgets(local_848, 0x800, stdin);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[
            {
                "start_offset": -0x848,
                "end_offset": -0x847,
                "size_bytes": 1,
                "var_names": ["local_848"],
                "data_types": ["undefined"],
            }
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    candidate = report.candidate_findings[0]
    assert candidate.sink == "fgets"
    assert candidate.target_buffer == "local_848"
    assert candidate.verdict == "candidate"
    assert candidate.write_relation == "symbolic_capacity"
    assert candidate.capacity_bytes == 0
    assert candidate.capacity_source == "direct_object_extent_unknown"
    assert "direct_object_extent_unknown" in candidate.evidence_sources
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_bounded_byte_sink_does_not_trust_ghidra_stack_fragment_extent(tmp_path: Path) -> None:
    text = """
void main(void) {
  undefined8 local_1458;
  ulong uStack_1450;
  undefined4 local_1448;
  fgets((char *)&local_1458, 0x13aa, stdin);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[
            {
                "start_offset": -0x1458,
                "end_offset": -0x1448,
                "size_bytes": 16,
                "var_names": ["local_1458"],
                "data_types": ["undefined1[16]"],
            },
            {
                "start_offset": -0x1448,
                "end_offset": -0x1444,
                "size_bytes": 4,
                "var_names": ["local_1448"],
                "data_types": ["undefined4"],
            },
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    candidate = report.candidate_findings[0]
    assert candidate.sink == "fgets"
    assert candidate.target_buffer == "local_1458"
    assert candidate.verdict == "candidate"
    assert candidate.write_relation == "symbolic_capacity"
    assert candidate.capacity_bytes == 0
    assert candidate.capacity_source == "direct_object_extent_unknown"
    assert "direct_object_extent_unknown" in candidate.evidence_sources
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_split_raw_byte_stack_fragments_recover_safe_bounded_extent(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_4038;
  char local_4037[31];
  undefined1 local_4018[16352];
  fgets(&local_4038, 0x4000, stdin);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[
            {
                "start_offset": -0x4038,
                "end_offset": -0x4037,
                "size_bytes": 1,
                "var_names": ["local_4038"],
                "data_types": ["char"],
            },
            {
                "start_offset": -0x4037,
                "end_offset": -0x4018,
                "size_bytes": 31,
                "var_names": ["local_4037"],
                "data_types": ["char[31]"],
            },
            {
                "start_offset": -0x4018,
                "end_offset": -0x38,
                "size_bytes": 16352,
                "var_names": ["local_4018"],
                "data_types": ["undefined1[16352]"],
            },
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_split_raw_byte_stack_fragments_keep_unbounded_sink_at_aggregate_capacity(tmp_path: Path) -> None:
    text = """
void main(void) {
  int mode;
  char local_4038;
  char local_4037[31];
  undefined1 local_4018[16352];
  sscanf(&local_4038, "begin %o %s", &mode, &local_4038);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[
            {
                "start_offset": -0x4038,
                "end_offset": -0x4037,
                "size_bytes": 1,
                "var_names": ["local_4038"],
                "data_types": ["char"],
            },
            {
                "start_offset": -0x4037,
                "end_offset": -0x4018,
                "size_bytes": 31,
                "var_names": ["local_4037"],
                "data_types": ["char[31]"],
            },
            {
                "start_offset": -0x4018,
                "end_offset": -0x38,
                "size_bytes": 16352,
                "var_names": ["local_4018"],
                "data_types": ["undefined1[16352]"],
            },
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.sink == "sscanf"
    assert candidate.target_buffer == "local_4038/local_4037/local_4018"
    assert candidate.capacity_bytes == 0x4000
    assert candidate.capacity_source == "inferred_stack_aggregate_extent"


def test_adjacent_raw_byte_arrays_are_not_merged_as_split_stack_object(tmp_path: Path) -> None:
    text = """
void main(void) {
  undefined1 local_828[1024];
  undefined1 local_428[1024];
  strcpy(local_428, input);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[
            {
                "start_offset": -0x828,
                "end_offset": -0x428,
                "size_bytes": 1024,
                "var_names": ["local_828"],
                "data_types": ["undefined1"],
            },
            {
                "start_offset": -0x428,
                "end_offset": -0x28,
                "size_bytes": 1024,
                "var_names": ["local_428"],
                "data_types": ["undefined1"],
            },
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.target_buffer == "local_428"
    assert candidate.capacity_bytes == 1024
    assert candidate.capacity_source == "declared_local_array"


def test_bounded_wrapper_does_not_trust_unknown_decompiler_array_extent(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  stat64 local_848[14];
  wrapper(local_848);
}
"""
    wrapper_text = """
char *wrapper(char *param_1) {
  char *__s;
  __s = fgets(param_1,0x800,stdin);
  return __s;
}
"""
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=main_text,
            stack_regions=[
                {
                    "start_offset": -0x848,
                    "end_offset": -0x847,
                    "size_bytes": 1,
                    "var_names": ["local_848"],
                    "data_types": ["undefined"],
                }
            ],
        ),
        _record(name="wrapper", address="0x1100", ordinal=1, relative_path="wrapper.c", text=wrapper_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "wrapper.c": wrapper_text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.kind == "interprocedural_call"
    assert candidate.sink == "fgets"
    assert candidate.verdict == "candidate"
    assert candidate.write_relation == "symbolic_capacity"
    assert candidate.capacity_bytes == 0
    assert candidate.capacity_source == "direct_object_extent_unknown"
    assert "direct_object_extent_unknown" in candidate.evidence_sources
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_bounded_wrapper_trusts_abi_scoped_stat64_array_extent(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  stat64 local_848[14];
  wrapper(local_848);
}
"""
    wrapper_text = """
char *wrapper(char *param_1) {
  char *__s;
  __s = fgets(param_1,0x800,stdin);
  return __s;
}
"""
    export_dir = _write_raw_export(
        tmp_path,
        [
            {
                "name": "main",
                "address": "0x1000",
                "relative_address": 0x1000,
                "filename": "main.c",
                "relative_path": "main.c",
                "is_thunk": False,
                "stack_purge": None,
                "call_fixup": None,
                "decompile_completed": True,
                "size": 16,
                "ordinal": 0,
                "return_type": "void",
                "prototype": "void main(void)",
                "parameters": [],
                "emit_c": True,
                "stack_regions": [
                    {
                        "start_offset": -0x848,
                        "end_offset": -0x847,
                        "size_bytes": 1,
                        "var_names": ["local_848"],
                        "data_types": ["undefined"],
                    }
                ],
            },
            {
                "name": "wrapper",
                "address": "0x1100",
                "relative_address": 0x1100,
                "filename": "wrapper.c",
                "relative_path": "wrapper.c",
                "is_thunk": False,
                "stack_purge": None,
                "call_fixup": None,
                "decompile_completed": True,
                "size": 16,
                "ordinal": 1,
                "return_type": "char *",
                "prototype": "char * wrapper(char * param_1)",
                "parameters": [{"name": "param_1", "data_type": "char *", "storage": "stack"}],
                "emit_c": True,
            },
        ],
        {"main.c": main_text, "wrapper.c": wrapper_text},
        {
            "image_base": 0,
            "language_id": "x86:LE:64:default",
            "processor": "x86",
            "pointer_size_bytes": 8,
            "endianness": "little",
            "executable_format": "Executable and Linking Format (ELF)",
            "compiler": "gcc",
            "edges": {"main": ["wrapper"], "wrapper": ["fgets"]},
        },
    )

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.kind == "interprocedural_call"
    assert candidate.sink == "fgets"
    assert candidate.verdict == "overflow"
    assert candidate.write_relation == "proven_overflow"
    assert candidate.capacity_bytes == 2016
    assert candidate.capacity_source == "declared_local_array"
    assert "direct_object_extent_unknown" not in candidate.evidence_sources


def test_static_candidates_skip_bounded_snprintf(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  snprintf(local_20, 16, "%s", input);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    assert extract_static_candidates(manifest, nodes) == []


def test_static_pipeline_keeps_unbounded_indexed_write_as_candidate(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  int index;
  scanf("%d", &index);
  badSink(index);
}
"""
    sink_text = """
void badSink(int index) {
  char local_20[16];
  local_20[index] = 0;
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text),
        _record(
            name="badSink",
            address="0x1100",
            ordinal=1,
            relative_path="badSink.c",
            text=sink_text,
            stack_regions=[_stack_region()],
        ),
    ]
    export_dir = _write_export(
        tmp_path,
        records,
        {
            "main.c": main_text,
            "badSink.c": sink_text,
        },
    )

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.vulnerability_reports == []
    candidate = report.candidate_findings[0]
    assert candidate.call_path == ["main", "badSink"]
    assert candidate.verdict == "candidate"
    assert candidate.input_reaches_sink is True
    assert [item.candidate_id for item in report.confirmation_findings] == [candidate.candidate_id]
    trace = candidate.classification_trace["reachability_dataflow"]
    assert trace["graph"]["reachability_kind"] == "source_path"
    assert trace["graph"]["caller_count"] == 1
    assert trace["source_link"]["source_function_reaches_candidate"] is True
    assert trace["expr_taint"]["offset_expr"]["classifications"]["index"] == "parameter_controlled"
    assert (export_dir / "candidate_findings.json").exists()
    assert (export_dir / "confirmation_findings.json").exists()


def test_reachability_dataflow_taints_local_scanf_index(tmp_path: Path) -> None:
    text = """
void main(void) {
  int index;
  char local_20[16];
  scanf("%d", &index);
  local_20[index] = 0;
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    candidate = report.candidate_findings[0]
    taint = candidate.classification_trace["reachability_dataflow"]["expr_taint"]
    assert taint["offset_expr"]["classifications"]["index"] == "source_controlled"
    assert any(
        row["symbol"] == "index" and row["classification"] == "source_controlled"
        for row in taint["taint_table"]
    )
    source_to_write = candidate.classification_trace["source_to_write"]["roles"]
    assert source_to_write["write_offset"]["classification"] == "source_controlled"
    assert source_to_write["write_source"]["classification"] == "constant_or_literal"
    assert source_to_write["destination_pointer"]["classification"] == "internal_local"


def test_source_to_write_proves_read_memcpy_source_and_size(tmp_path: Path) -> None:
    text = """
void main(void) {
  int n;
  char src[64];
  char local_20[16];
  scanf("%d", &n);
  read(0, src, n);
  memcpy(local_20, src, n);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    candidate = next(item for item in report.candidate_findings if item.sink == "memcpy")
    roles = candidate.classification_trace["source_to_write"]["roles"]
    assert roles["write_source"]["classification"] == "source_controlled"
    assert roles["write_size"]["classification"] == "source_controlled"
    assert roles["write_offset"]["classification"] == "constant_or_literal"
    assert candidate.classification_trace["attacker_control"]["source_bytes"] == "source_controlled"
    assert candidate.classification_trace["attacker_control"]["write_size"] == "source_controlled"

    write_facts = json.loads((export_dir / "write_facts.json").read_text())
    fact = next(item for item in write_facts if item["fact_id"] == candidate.candidate_id)
    assert fact["attacker_control"]["source_bytes"] == "source_controlled"
    assert fact["attacker_control"]["write_size"] == "source_controlled"


def test_reachability_dataflow_taints_argv_assignment(tmp_path: Path) -> None:
    text = """
void main(int argc, char **argv) {
  int index;
  char local_20[16];
  index = atoi(argv[1]);
  local_20[index] = 0;
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    trace = report.candidate_findings[0].classification_trace["reachability_dataflow"]
    assert trace["expr_taint"]["offset_expr"]["classifications"]["index"] == "source_controlled"
    assert trace["source_link"]["argv_identifiers"] == ["index"]


def test_reachability_dataflow_marks_internal_expr_without_suppressing(tmp_path: Path) -> None:
    text = """
void main(void) {
  int local_count;
  int index = local_count;
  char local_20[16];
  local_20[index] = 0;
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    candidate = report.candidate_findings[0]
    trace = candidate.classification_trace["reachability_dataflow"]
    assert trace["expr_taint"]["offset_expr"]["classifications"]["index"] == "internal_local"
    assert trace["expr_taint"]["non_input_expr_candidate"] is True
    source_to_write = candidate.classification_trace["source_to_write"]["roles"]
    assert source_to_write["write_offset"]["classification"] == "internal_local"
    assert source_to_write["write_source"]["classification"] == "constant_or_literal"
    assert report.confirmation_findings == []


def test_source_to_write_instantiates_direct_helper_call(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  int n;
  char src[64];
  char local_20[16];
  scanf("%d", &n);
  read(0, src, n);
  helper(local_20, src, n);
}
"""
    helper_text = """
void helper(char *dst, char *src, int n) {
  memcpy(dst, src, n);
}
"""
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=main_text,
            stack_regions=[_stack_region()],
        ),
        _record(
            name="helper",
            address="0x1100",
            ordinal=1,
            relative_path="helper.c",
            text=helper_text,
        ),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "helper.c": helper_text})

    report = run_static_pipeline(export_dir)

    candidate = next(
        item
        for item in report.candidate_findings
        if item.kind == "interprocedural_call" and item.sink == "memcpy"
    )
    roles = candidate.classification_trace["source_to_write"]["roles"]
    assert roles["write_source"]["classification"] == "source_controlled"
    assert roles["write_size"]["classification"] == "source_controlled"
    assert roles["destination_pointer"]["classification"] == "internal_local"


def test_source_to_write_unknown_wrapper_keeps_candidate_and_confirmation(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  int index;
  char local_20[16];
  scanf("%d", &index);
  wrapper(local_20, index);
}
"""
    wrapper_text = """
void wrapper(char *dst, int index) {
  helper(dst, index);
}
"""
    helper_text = """
void helper(char *dst, int index) {
  dst[index] = 0;
}
"""
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=main_text,
            stack_regions=[_stack_region()],
        ),
        _record(name="wrapper", address="0x1100", ordinal=1, relative_path="wrapper.c", text=wrapper_text),
        _record(name="helper", address="0x1200", ordinal=2, relative_path="helper.c", text=helper_text),
    ]
    export_dir = _write_export(
        tmp_path,
        records,
        {"main.c": main_text, "wrapper.c": wrapper_text, "helper.c": helper_text},
    )

    report = run_static_pipeline(export_dir)

    candidate = next(
        item
        for item in report.candidate_findings
        if item.kind == "interprocedural_indexed_write" and item.sink == "array_store"
    )
    roles = candidate.classification_trace["source_to_write"]["roles"]
    assert roles["write_source"]["classification"] == "unknown"
    assert candidate.candidate_id in {item.candidate_id for item in report.confirmation_findings}


def test_exact_heap_allocation_size_relation_is_suppressed_as_safe(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_208[512];
  int sVar2;
  fgets(local_208, 500, stdin);
  sVar2 = strlen(local_208);
  char *__dest = malloc((long)((int)sVar2 + 1));
  memcpy(__dest, local_208, (long)((int)sVar2 + 1));
}
"""
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())

    assert report.candidate_findings == []
    match = next(item for item in suppressed if item["reason"] == "fact_enrichment_proven_safe")
    allocation_table = match["trace"]["allocation_table"]
    assert allocation_table
    assert allocation_table[0]["matched"] is True
    assert allocation_table[0]["target"] == "__dest"


def test_nonmatching_heap_allocation_relation_stays_queued(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_208[512];
  char *__dest;
  int sVar2;
  fgets(local_208, 500, stdin);
  sVar2 = strlen(local_208);
  __dest = malloc((long)((int)sVar2 + 2));
  memcpy(__dest, local_208, (long)((int)sVar2 + 1));
}
"""
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    candidate = report.candidate_findings[0]
    assert candidate.destination_kind == "heap"
    assert candidate.write_relation == "symbolic_size"
    assert candidate.candidate_id in {item.candidate_id for item in report.confirmation_findings}


def test_allocation_fallback_alias_unresolved_copy_is_confirmed(tmp_path: Path) -> None:
    text = """
void addinnetgrX(void *db, request_header *req, char *key) {
  indataset dataset_mem;
  indataset *packet;
  int local_95;
  int iVar3;
  packet = mempool_alloc(db,(long)req->key_len + 0x28,1);
  local_95 = packet == (indataset *)0x0;
  if (local_95) {
    packet = &dataset_mem;
  }
  iVar3 = req->key_len;
  FUN_00105010(packet + 1,key,(long)iVar3);
}
"""
    record = _record(
        name="addinnetgrX",
        address="0x116410",
        ordinal=0,
        relative_path="addinnetgrX.c",
        text=text,
        stack_regions=[_stack_region("dataset_mem", 40, -0x68)],
    )
    export_dir = _write_export(tmp_path, [record], {"addinnetgrX.c": text})

    report = run_static_pipeline(export_dir)

    candidate = next(
        item
        for item in report.candidate_findings
        if "allocation_fallback_alias" in item.evidence_sources
    )
    assert candidate.target_buffer == "dataset_mem"
    assert candidate.sink == "memcpy"
    assert candidate.write_relation == "symbolic_size"
    assert candidate.write_size_expr == "(long)iVar3"
    confirmation = next(
        item
        for item in report.confirmation_findings
        if item.candidate_id == candidate.candidate_id
    )
    assert confirmation.classification_trace["confirmation_rule"] == "controlled_extent"


def test_allocation_result_stack_alias_without_null_fallback_does_not_create_unresolved_copy_candidate(
    tmp_path: Path,
) -> None:
    text = """
void addinnetgrX(void *db, request_header *req, char *key) {
  indataset dataset_mem;
  indataset *packet;
  int iVar3;
  packet = mempool_alloc(db,(long)req->key_len + 0x28,1);
  packet = &dataset_mem;
  iVar3 = req->key_len;
  FUN_00105010(packet + 1,key,(long)iVar3);
}
"""
    record = _record(
        name="addinnetgrX",
        address="0x116410",
        ordinal=0,
        relative_path="addinnetgrX.c",
        text=text,
        stack_regions=[_stack_region("dataset_mem", 40, -0x68)],
    )
    export_dir = _write_export(tmp_path, [record], {"addinnetgrX.c": text})

    report = run_static_pipeline(export_dir)

    assert all("allocation_fallback_alias" not in item.evidence_sources for item in report.candidate_findings)


def test_stack_coalescing_annotation_lowers_review_priority_and_stays_out_of_confirmation(tmp_path: Path) -> None:
    text = """
void main(void) {
  undefined8 uStack_148;
  undefined8 uStack_140;
  undefined1 auStack_138[256];
  snprintf((char *)&uStack_148, 0x28, "%s", input);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region(name="uStack_148", size=8, start=-0x148)],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    trace = report.candidate_findings[0].classification_trace
    assert trace["stack_coalescing"]["classification"] == "likely_decompiler_split"
    assert trace["review_priority"]["priority"] == "low"
    assert report.confirmation_findings == []


def test_symbolic_offset_guard_relation_is_suppressed_as_safe(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int i;
  if ((0 <= i) && (i + 1 <= sizeof(local_20))) {
    local_20[i] = 0;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())

    assert report.candidate_findings == []
    assert any(item["reason"] == "fact_enrichment_proven_safe" for item in suppressed)
    assert report.stage_metrics["raw_facts"] == 1


def test_symbolic_offset_unbounded_count_guard_stays_queued(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int i;
  int count;
  if (i < count) {
    local_20[i] = 0;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].write_relation == "symbolic_offset"
    assert report.confirmation_findings == []


def test_unsigned_local_index_upper_guard_is_suppressed_as_safe(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  uint i;
  if (i < 16) {
    local_20[i] = 0;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []
    assert report.confirmation_findings == []


def test_unsigned_local_index_or_upper_guard_stays_queued(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  uint i;
  int flag;
  if ((flag != 0) || (i < 16)) {
    local_20[i] = 0;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].write_relation == "symbolic_offset"


def test_unsigned_local_index_reject_and_guard_stays_queued(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  uint i;
  int flag;
  if ((flag != 0) && (i >= 16)) {
    return;
  }
  local_20[i] = 0;
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].write_relation == "symbolic_offset"


def test_signed_local_index_upper_guard_stays_queued(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int i;
  if (i < 16) {
    local_20[i] = 0;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].write_relation == "symbolic_offset"


def test_unsigned_local_index_negative_delta_is_not_suppressed(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  uint i;
  if (i < 16) {
    local_20[i - 1] = 0;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].write_relation == "symbolic_offset"


def test_reverse_counted_loop_bounds_suppress_indexed_write(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int i;
  for (i = 15; i >= 0; i--) {
    local_20[i] = 0;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())

    assert report.candidate_findings == []
    assert any(item["reason"] == "range_loop_proven_safe" for item in suppressed)


def test_unsigned_byte_cast_index_suppresses_256_entry_table_write(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_100[256];
  int i;
  local_100[(unsigned char)i] = 0;
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region("local_100", size=256, start=-0x100)],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())

    assert report.candidate_findings == []
    assert any(item["reason"] == "range_loop_proven_safe" for item in suppressed)


def test_symbolic_size_guarded_by_capacity_is_suppressed_as_safe(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int n;
  if (n <= sizeof(local_20)) {
    memcpy(local_20, src, n);
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())

    assert report.candidate_findings == []
    assert any(item["reason"] == "fact_enrichment_proven_safe" for item in suppressed)


def test_remaining_capacity_size_with_offset_bounds_is_suppressed_as_safe(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int used;
  scanf("%d", &used);
  if (used >= 0 && used <= 16) {
    snprintf(local_20 + used, 16 - used, "%s", input);
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())

    assert report.candidate_findings == []
    assert report.confirmation_findings == []
    assert any(item["reason"] == "bounded_capacity_proven_safe" for item in suppressed)


def test_symbolic_size_guarded_above_capacity_stays_actionable(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_80[128];
  int n;
  scanf("%d", &n);
  if (n <= 256) {
    memcpy(local_80, src, n);
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region("local_80", size=128, start=-0x80)],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].write_relation == "symbolic_size"
    assert len(report.confirmation_findings) == 1


def test_append_length_unknown_uses_empty_buffer_initialization(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  local_20[0] = 0;
  strncat(local_20, input, 15);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())

    assert report.candidate_findings == []
    assert any(
        item["reason"] == "fact_enrichment_proven_safe"
        and item["trace"]["append_length_table"][0]["source"] == "nul_initialization"
        for item in suppressed
    )


def test_evidence_packs_are_written_for_symbolic_confirmation_queue_only(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  char local_20[16];
  int index;
  scanf("%d", &index);
  local_20[index] = 0;
  helper();
}
"""
    helper_text = """
void helper(void) {
  char local_40[16];
  memcpy(local_40, input, size);
}
"""
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=main_text,
            stack_regions=[_stack_region()],
        ),
        _record(
            name="helper",
            address="0x1100",
            ordinal=1,
            relative_path="helper.c",
            text=helper_text,
            stack_regions=[_stack_region("local_40", start=-0x40)],
        ),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "helper.c": helper_text})
    evidence_dir = tmp_path / "evidence"

    report = run_static_pipeline(export_dir, write_evidence_packs_dir=evidence_dir)

    assert len(report.candidate_findings) == 2
    assert len(report.confirmation_findings) == 1
    index = json.loads((evidence_dir / "index.json").read_text())
    assert {item["candidate_id"] for item in index["evidence_packs"]} == {
        item.candidate_id for item in report.confirmation_findings
    }


def test_ambiguous_merged_stack_region_is_not_a_candidate(tmp_path: Path) -> None:
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text="",
        stack_regions=[
            {
                "start_offset": -0x20,
                "end_offset": -0x10,
                "size_bytes": 16,
                "var_names": ["local_20", "local_24"],
                "data_types": ["char", "char"],
            }
        ],
        pcode_calls=[
            {
                "call_address": "0x1010",
                "callee": "memcpy",
                "args": [
                    {"expr": "local_20", "stack_ref": {"var_name": "local_20"}},
                    {"expr": "input"},
                    {"expr": "size"},
                ],
            }
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": ""})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []
    assert report.confirmation_findings == []


def test_confirmed_policy_uses_tainted_confirmation_queue(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  char local_20[16];
  int index;
  scanf("%d", &index);
  local_20[index] = 0;
  helper();
}
"""
    helper_text = """
void helper(void) {
  char local_40[16];
  memcpy(local_40, input, size);
}
"""
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=main_text,
            stack_regions=[_stack_region()],
        ),
        _record(
            name="helper",
            address="0x1100",
            ordinal=1,
            relative_path="helper.c",
            text=helper_text,
            stack_regions=[_stack_region("local_40", start=-0x40)],
        ),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "helper.c": helper_text})
    first_report = run_static_pipeline(export_dir)
    confirmations_dir = tmp_path / "confirmations"
    confirmations_dir.mkdir()
    confirmations = {
        candidate.candidate_id: {
            "status": "confirmed_bug",
            "reason_codes": ["test_confirmation"],
        }
        for candidate in first_report.candidate_findings
    }
    (confirmations_dir / "confirmations.json").write_text(json.dumps(confirmations))

    confirmed_report = run_static_pipeline(export_dir, confirmation_dir=confirmations_dir)

    assert len(confirmed_report.confirmation_findings) == 1
    assert len(confirmed_report.vulnerability_reports) == 1
    assert {report.candidate_id for report in confirmed_report.vulnerability_reports} == {
        item.candidate_id for item in confirmed_report.confirmation_findings
    }


def test_static_pipeline_removes_stale_stage_artifacts(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  gets(local_20);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    for name in ("scout_findings.json", "triage_findings.json", "verify_findings.json", "llm_cache.json"):
        (export_dir / name).write_text("[]")

    run_static_pipeline(export_dir)

    assert (export_dir / "candidate_findings.json").exists()
    assert (export_dir / "write_facts.json").exists()
    assert (export_dir / "resolved_writes.json").exists()
    assert (export_dir / "function_summaries.json").exists()
    assert (export_dir / "confirmation_findings.json").exists()
    for name in ("scout_findings.json", "triage_findings.json", "verify_findings.json", "llm_cache.json"):
        assert not (export_dir / name).exists()


def test_operation_specs_load_from_json() -> None:
    specs = load_memory_operation_specs()

    assert specs.version == 12
    assert specs.sinks["memcpy"].semantics == "bounded"
    assert specs.sinks["scanf"].first_dest_arg == 1
    assert specs.normalize_name("__builtin___memcpy_chk") == "memcpy_chk"
    assert specs.sinks["memcpy_chk"].object_size_arg == 3
    assert specs.sinks["memcpy_chk"].raw["fortified"] is True


def test_fortified_strcpy_bound_suppresses_memory_corruption_candidate(tmp_path: Path) -> None:
    text = """
void main(char *input) {
  char local_20[16];
  __strcpy_chk(local_20, input, 0x10);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []


def test_unchecked_strcpy_remains_memory_corruption_candidate(tmp_path: Path) -> None:
    text = """
void main(char *input) {
  char local_20[16];
  strcpy(local_20, input);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].sink == "strcpy"
    assert report.candidate_findings[0].write_relation == "unbounded"


def test_persist_debug_facts_writes_suppressed_artifact(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  gets(local_20);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)

    assert (export_dir / "suppressed_findings.json").exists()
    assert "suppressed_findings" in report.debug_artifact_paths
    assert report.stage_metrics["raw_facts"] == 1


def test_analysis_cache_reports_hit_on_second_run(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  gets(local_20);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    cache_dir = tmp_path / "cache"

    first = run_static_pipeline(export_dir, persist_stage_artifacts=False, cache_dir=cache_dir)
    second = run_static_pipeline(export_dir, persist_stage_artifacts=False, cache_dir=cache_dir)

    assert first.stage_metrics["cache_hit"] is False
    assert second.stage_metrics["cache_hit"] is True
    assert [item.candidate_id for item in first.candidate_findings] == [
        item.candidate_id for item in second.candidate_findings
    ]


def test_analysis_cache_invalidates_when_c_text_changes(tmp_path: Path) -> None:
    vulnerable_text = """
void main(void) {
  char local_20[16];
  memcpy(local_20, input, 64);
}
"""
    safe_text = """
void main(void) {
  char local_20[16];
  memset(local_20, 0, 1);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=vulnerable_text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": vulnerable_text})
    cache_dir = tmp_path / "cache"

    first = run_static_pipeline(export_dir, persist_stage_artifacts=False, cache_dir=cache_dir)
    (export_dir / "main.c").write_text(safe_text)
    second = run_static_pipeline(export_dir, persist_stage_artifacts=False, cache_dir=cache_dir)

    assert first.stage_metrics["cache_hit"] is False
    assert len(first.candidate_findings) == 1
    assert second.stage_metrics["cache_hit"] is False
    assert second.candidate_findings == []
    assert second.stage_metrics["raw_facts"] == 1


def test_same_line_bounded_writes_keep_distinct_offsets(tmp_path: Path) -> None:
    text = "void main(void) { char local_40[64]; memcpy(local_40 + 16, input, 64); memcpy(local_40 + 32, input, 64); }\n"
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region("local_40", size=64, start=-0x40)],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)
    write_facts = json.loads((export_dir / "write_facts.json").read_text())
    resolved_writes = json.loads((export_dir / "resolved_writes.json").read_text())

    assert len(report.candidate_findings) == 2
    assert {candidate.offset_expr for candidate in report.candidate_findings} == {"16", "32"}
    assert len({candidate.candidate_id for candidate in report.candidate_findings}) == 2
    assert {fact["offset_expr"] for fact in write_facts} == {"16", "32"}
    assert {write["offset_expr"] for write in resolved_writes} == {"16", "32"}


def test_equivalent_symbolic_index_writes_cluster_to_representative(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int i;
  local_20[i] = 0;
  local_20[i] = 1;
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    candidate = report.candidate_findings[0]
    assert candidate.cluster_size == 2
    assert len(candidate.sibling_ids) == 1
    assert candidate.cluster_id
    assert candidate.classification_trace["cluster"]["size"] == 2
    assert report.stage_metrics["raw_candidates"] == 2
    assert report.stage_metrics["candidate_clusters"] == 1


def test_safe_bounded_writes_are_raw_facts_and_debug_suppressions(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  memset(local_20, 0, 1);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)
    write_facts = json.loads((export_dir / "write_facts.json").read_text())
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())

    assert report.candidate_findings == []
    assert report.stage_metrics["raw_facts"] == 1
    assert report.stage_metrics["classified_findings"] == 1
    assert write_facts[0]["sink"] == "memset"
    assert write_facts[0]["offset_expr"] == "0"
    assert write_facts[0]["raw"]["relation"] == "proven_safe"
    assert suppressed[0]["reason"] == "proven_safe"
    assert suppressed[0]["trace"]["bounds"]["accepted"]
    assert any(item["reason"] == "bounded_capacity_proven_safe" for item in suppressed)


def test_static_candidates_detect_pointer_arithmetic_stack_store(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int index;
  scanf("%d", &index);
  if (index < 0) {
    *(undefined4 *)(local_20 + (long)index * 4) = 1;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    memory_candidates = [candidate for candidate in candidates if candidate.vulnerability_type == "memory_overflow"]
    assert len(memory_candidates) == 1
    assert memory_candidates[0].sink == "pointer_store"
    assert memory_candidates[0].verdict == "overflow"
    assert "negative index" in memory_candidates[0].overflow_condition
    assert any(candidate.vulnerability_type == "integer_overflow_to_memory_access" for candidate in candidates)


def test_pointer_alias_indexed_stack_write_is_candidate(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  char *p;
  int index;
  p = local_20;
  p[index] = 0;
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].target_buffer == "local_20"
    assert candidates[0].sink == "array_store"
    assert "c_alias" in candidates[0].evidence_sources


def test_pointer_alias_deref_stack_write_is_candidate(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  char *p;
  int index;
  p = local_20 + index;
  *p = 0;
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].sink == "pointer_store"
    assert candidates[0].target_buffer == "local_20"


def test_no_taint_iterated_alias_constant_index_stays_out_of_confirmation_queue(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  char *p;
  for (p = local_20 + 1; p != local_20 + count; p = p + 2) {
    p[1] = 0;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.confirmation_findings == []


def test_iterated_alias_exact_pointer_loop_is_not_queued(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  char *p;
  for (p = local_20; p != local_20 + sizeof(local_20); p++) {
    *p = 0;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []
    assert report.confirmation_findings == []


def test_caller_buffer_offset_with_full_size_stays_out_without_reachable_taint(tmp_path: Path) -> None:
    text = """
void shorten(char *input, char *output, size_t output_size) {
  char s[2];
  size_t used;
  snprintf(s, 2, "%c", input[0]);
  snprintf(output + used, output_size, "%s", input);
}
"""
    record = _record(
        name="shorten",
        address="0x1000",
        ordinal=0,
        relative_path="shorten.c",
        text=text,
        stack_regions=[_stack_region("s", size=2)],
    )
    export_dir = _write_export(tmp_path, [record], {"shorten.c": text})

    report = run_static_pipeline(export_dir)

    caller_candidates = [
        candidate for candidate in report.candidate_findings if candidate.destination_kind == "caller_buffer"
    ]
    assert len(caller_candidates) == 1
    assert caller_candidates[0].target_buffer == "output"
    assert caller_candidates[0].capacity_source == "sink_size_arg"
    assert caller_candidates[0].write_relation == "symbolic_offset"
    assert report.confirmation_findings == []


def test_caller_buffer_offset_with_remaining_size_is_proven_safe(tmp_path: Path) -> None:
    text = """
void shorten(char *input, char *output, size_t output_size) {
  char s[2];
  size_t used;
  snprintf(s, 2, "%c", input[0]);
  snprintf(output + used, output_size - used, "%s", input);
}
"""
    record = _record(
        name="shorten",
        address="0x1000",
        ordinal=0,
        relative_path="shorten.c",
        text=text,
        stack_regions=[_stack_region("s", size=2)],
    )
    export_dir = _write_export(tmp_path, [record], {"shorten.c": text})

    report = run_static_pipeline(export_dir)

    assert [candidate for candidate in report.candidate_findings if candidate.destination_kind == "caller_buffer"] == []


def test_callee_parameter_sink_is_instantiated_at_stack_callsite(tmp_path: Path) -> None:
    main_text = """
void main(int argc, char **argv) {
  char local_20[16];
  fill(local_20, argv[1]);
}
"""
    fill_text = """
void fill(char *out, char *input) {
  strcpy(out, input);
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text),
        _record(name="fill", address="0x1100", ordinal=1, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "fill.c": fill_text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    instantiated = [candidate for candidate in candidates if candidate.function_name == "main"]
    assert len(instantiated) == 1
    assert instantiated[0].sink == "strcpy"
    assert instantiated[0].verdict == "unbounded"
    assert "interprocedural_summary" in instantiated[0].evidence_sources

    summaries = [candidate for candidate in candidates if candidate.kind.startswith("parameter_summary")]
    assert summaries == []


def test_unbounded_literal_copy_that_fits_is_suppressed_as_safe(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  strcpy(local_20, "ok");
}
"""
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())

    assert report.candidate_findings == []
    assert report.confirmation_findings == []
    assert any(item["reason"] == "bounded_capacity_proven_safe" for item in suppressed)


def test_unbounded_literal_copy_over_capacity_is_exact_overflow(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[4];
  strcpy(local_20, "0123456789");
}
"""
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].write_relation == "proven_overflow"
    assert report.candidate_findings[0].verdict == "overflow"


def test_unbounded_literal_wrapper_copy_that_fits_is_suppressed_as_safe(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  char local_20[16];
  fill(local_20);
}
"""
    fill_text = """
void fill(char *out) {
  strcpy(out, "ok");
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text),
        _record(name="fill", address="0x1100", ordinal=1, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "fill.c": fill_text})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())

    assert report.candidate_findings == []
    assert any(item["reason"] == "bounded_wrapper_proven_safe" for item in suppressed)


def test_fixed_point_wrapper_summary_instantiates_at_stack_callsite(tmp_path: Path) -> None:
    main_text = """
void main(int argc, char **argv) {
  char local_20[16];
  wrap(local_20, argv[1]);
}
"""
    wrap_text = """
void wrap(char *out, char *input) {
  fill(out, input);
}
"""
    fill_text = """
void fill(char *out, char *input) {
  strcpy(out, input);
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text),
        _record(name="wrap", address="0x1100", ordinal=1, relative_path="wrap.c", text=wrap_text),
        _record(name="fill", address="0x1200", ordinal=2, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(
        tmp_path,
        records,
        {"main.c": main_text, "wrap.c": wrap_text, "fill.c": fill_text},
    )
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    instantiated = [candidate for candidate in candidates if candidate.function_name == "main"]
    assert len(instantiated) == 1
    assert instantiated[0].sink == "strcpy"
    assert "fixed_point_summary" in instantiated[0].evidence_sources


def test_interprocedural_integer_address_pointer_offsets_are_byte_offsets(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  long local_28[5];
  helper((long)local_28);
}
"""
    helper_text = """
void helper(long param_1) {
  *(undefined8 *)(param_1 + 0x18) = 0;
  *(uint *)(param_1 + 0x20) = 0;
}
"""
    stack_region = {
        "start_offset": -0x28,
        "end_offset": 0,
        "size_bytes": 40,
        "var_names": ["local_28"],
        "data_types": ["long"],
    }
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=main_text,
            stack_regions=[stack_region],
        ),
        _record(name="helper", address="0x1100", ordinal=1, relative_path="helper.c", text=helper_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "helper.c": helper_text})

    report = run_static_pipeline(export_dir)

    assert [candidate for candidate in report.candidate_findings if candidate.function_name == "main"] == []


def test_interprocedural_typed_pointer_store_offsets_remain_element_scaled(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  long local_28[5];
  helper(local_28);
}
"""
    helper_text = """
void helper(long *param_1) {
  *(param_1 + 5) = 0;
}
"""
    stack_region = {
        "start_offset": -0x28,
        "end_offset": 0,
        "size_bytes": 40,
        "var_names": ["local_28"],
        "data_types": ["long"],
    }
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=main_text,
            stack_regions=[stack_region],
        ),
        _record(name="helper", address="0x1100", ordinal=1, relative_path="helper.c", text=helper_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "helper.c": helper_text})

    report = run_static_pipeline(export_dir)

    instantiated = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(instantiated) == 1
    assert instantiated[0].write_relation == "proven_overflow"
    assert instantiated[0].write_size_bytes == 8
    assert instantiated[0].offset_expr == "(5) * 8"


def test_interprocedural_size_guarded_index_helper_is_suppressed(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  int n;
  char local_20[16];
  scanf("%d", &n);
  bounded_digits(local_20, 16, n);
}
"""
    helper_text = """
void bounded_digits(char *dst, size_t dstlen, int n) {
  if (n < 0) {
    return;
  }
  if (dstlen <= n) {
    return;
  }
  dst[n] = 0;
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text, stack_regions=[_stack_region()]),
        _record(name="bounded_digits", address="0x1100", ordinal=1, relative_path="bounded.c", text=helper_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "bounded.c": helper_text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []
    assert report.confirmation_findings == []
    summaries = json.loads((export_dir / "function_summaries.json").read_text())
    writes = [write for summary in summaries for write in summary.get("writes", [])]
    assert any(write.get("offset_bound_complete") is True for write in writes)


def test_interprocedural_size_guarded_upper_only_index_leaves_queue(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  int n;
  char local_20[16];
  scanf("%d", &n);
  bounded_digits(local_20, 16, n);
}
"""
    helper_text = """
void bounded_digits(char *dst, size_t dstlen, int n) {
  if (dstlen <= n) {
    return;
  }
  dst[n] = 0;
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text, stack_regions=[_stack_region()]),
        _record(name="bounded_digits", address="0x1100", ordinal=1, relative_path="bounded.c", text=helper_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "bounded.c": helper_text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].write_relation == "symbolic_offset_size_guarded"
    assert "summary_offset_bound" in report.candidate_findings[0].evidence_sources
    assert report.confirmation_findings == []


def test_interprocedural_size_guarded_decremented_index_leaves_queue(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  uint n;
  char local_20[16];
  scanf("%u", &n);
  bounded_digits(local_20, 16, n);
}
"""
    helper_text = """
void bounded_digits(char *dst, size_t dstlen, uint n) {
  int i;
  if (dstlen <= n) {
    return;
  }
  i = n;
  n = i - 2;
  dst[i - 1] = 0;
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text, stack_regions=[_stack_region()]),
        _record(name="bounded_digits", address="0x1100", ordinal=1, relative_path="bounded.c", text=helper_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "bounded.c": helper_text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].offset_expr == "i - 1"
    assert report.candidate_findings[0].write_relation == "symbolic_offset_size_guarded"
    assert report.confirmation_findings == []


def test_interprocedural_size_guarded_index_helper_oversized_bound_stays_queued(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  int n;
  char local_20[16];
  scanf("%d", &n);
  bounded_digits(local_20, 64, n);
}
"""
    helper_text = """
void bounded_digits(char *dst, size_t dstlen, int n) {
  if (dstlen <= n) {
    return;
  }
  dst[n] = 0;
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text, stack_regions=[_stack_region()]),
        _record(name="bounded_digits", address="0x1100", ordinal=1, relative_path="bounded.c", text=helper_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "bounded.c": helper_text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].kind == "interprocedural_indexed_write"
    assert report.candidate_findings[0].write_relation == "symbolic_offset"
    assert len(report.confirmation_findings) == 1


def test_interprocedural_size_guarded_wrapper_propagates_bound(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  int n;
  char local_20[16];
  scanf("%d", &n);
  wrap_digits(local_20, 16, n);
}
"""
    wrap_text = """
void wrap_digits(char *dst, size_t dstlen, int n) {
  bounded_digits(dst + 1, dstlen - 1, n);
}
"""
    helper_text = """
void bounded_digits(char *dst, size_t dstlen, int n) {
  if (n < 0) {
    return;
  }
  if (dstlen <= n) {
    return;
  }
  dst[n] = 0;
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text, stack_regions=[_stack_region()]),
        _record(name="wrap_digits", address="0x1100", ordinal=1, relative_path="wrap.c", text=wrap_text),
        _record(name="bounded_digits", address="0x1200", ordinal=2, relative_path="bounded.c", text=helper_text),
    ]
    export_dir = _write_export(
        tmp_path,
        records,
        {"main.c": main_text, "wrap.c": wrap_text, "bounded.c": helper_text},
    )

    report = run_static_pipeline(export_dir, persist_debug_facts=True)
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())

    assert report.candidate_findings == []
    assert report.confirmation_findings == []
    assert any(item["reason"] == "bounded_wrapper_proven_safe" for item in suppressed)


def test_exported_parameter_summary_stays_out_of_confirmation_queue(tmp_path: Path) -> None:
    text = """
void exported_fill(char *out, char *input) {
  strcpy(out, input);
}
"""
    record = _record(
        name="exported_fill",
        address="0x1100",
        ordinal=0,
        relative_path="fill.c",
        text=text,
        source_symbol="exported_fill",
    )
    export_dir = _write_export(tmp_path, [record], {"fill.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].kind == "parameter_summary_call"
    assert report.candidate_findings[0].destination_kind == "parameter"
    assert report.candidate_findings[0].write_relation == "missing_size_contract"
    assert report.candidate_findings[0].triage_tier == "api_contract"
    assert report.confirmation_findings == []


def test_confirmation_queue_collapses_unresolved_offsets_by_line() -> None:
    base = StaticCandidate(
        binary="demo.bin",
        function_name="main",
        source_symbol="main",
        demangled_name="",
        source_object="",
        address="0x1000",
        relative_path="main.c",
        candidate_id="demo:0x1000:main:4:array_store:buf:i:8",
        kind="interprocedural_indexed_write",
        sink="pointer_store",
        line_number=4,
        line_text="buf[i] = value;",
        target_buffer="buf",
        capacity_bytes=16,
        capacity_basis="buf: stack[-0x20..-0x10], 16 bytes",
        destination_kind="stack",
        capacity_source="stack_region",
        write_relation="symbolic_offset",
        write_size_expr="8",
        write_size_bytes=8,
        offset_expr="i",
        overflow_condition="offset i is not proven within 16 bytes",
        verdict="candidate",
        path_is_valid=True,
        input_reaches_sink=True,
        reachability_kind="local_source",
        classification_trace=_source_to_write_trace(
            write_offset="parameter_controlled",
            write_source="parameter_controlled",
        ),
    )
    same_line = replace(
        base,
        candidate_id="demo:0x1000:main:4:array_store:buf:j:8",
        offset_expr="j",
        overflow_condition="offset j is not proven within 16 bytes",
    )
    next_line = replace(
        base,
        candidate_id="demo:0x1000:main:5:array_store:buf:k:8",
        line_number=5,
        line_text="buf[k] = value;",
        offset_expr="k",
        overflow_condition="offset k is not proven within 16 bytes",
    )
    exact_overflow = replace(
        base,
        candidate_id="demo:0x1000:main:6:array_store:buf:0x20:8",
        line_number=6,
        line_text="buf[0x20] = value;",
        offset_expr="0x20",
        overflow_condition="offset 32 is outside 16 bytes",
        verdict="overflow",
        write_relation="proven_overflow",
    )
    same_exact_line = replace(
        exact_overflow,
        candidate_id="demo:0x1000:main:6:array_store:buf:0x28:8",
        offset_expr="0x28",
        overflow_condition="offset 40 is outside 16 bytes",
    )

    selected = select_confirmation_candidates(
        [base, same_line, next_line, exact_overflow, same_exact_line]
    )

    assert [candidate.candidate_id for candidate in selected] == [
        base.candidate_id,
        next_line.candidate_id,
        exact_overflow.candidate_id,
        same_exact_line.candidate_id,
    ]
    assert selected[0].classification_trace["confirmation_rule"] == "controlled_offset"
    assert selected[2].classification_trace["confirmation_rule"] == "exact_overflow"


def test_confirmation_queue_collapses_interprocedural_callsite_equivalent_writes() -> None:
    base = StaticCandidate(
        binary="demo.bin",
        function_name="main",
        source_symbol="main",
        demangled_name="",
        source_object="",
        address="0x1000",
        relative_path="main.c",
        candidate_id="demo:0x1000:main:4:pointer_store:buf:0x20:8",
        kind="interprocedural_pointer_store",
        sink="pointer_store",
        line_number=4,
        line_text="helper(buf);",
        target_buffer="buf",
        capacity_bytes=16,
        capacity_basis="buf: declared local stack object, 16 bytes",
        destination_kind="stack",
        capacity_source="declared_local_array",
        write_relation="proven_overflow",
        write_size_expr="0x20",
        write_size_bytes=8,
        offset_expr="0x20",
        overflow_condition="helper writes byte range 32..39 outside 16 bytes",
        verdict="overflow",
        path_is_valid=True,
        input_reaches_sink=True,
        reachability_kind="local_source",
        evidence=["line 4: helper(buf);"],
        evidence_sources=["c_text", "interprocedural_summary", "fixed_point_summary"],
    )
    same_callsite = replace(
        base,
        candidate_id="demo:0x1000:main:4:pointer_store:buf:0x28:8",
        offset_expr="0x28",
        write_size_expr="0x28",
        overflow_condition="helper writes byte range 40..47 outside 16 bytes",
    )
    next_callsite = replace(
        base,
        candidate_id="demo:0x1000:main:5:pointer_store:buf:0x20:8",
        line_number=5,
        line_text="helper_again(buf);",
    )
    direct_same_line = replace(
        base,
        candidate_id="demo:0x1000:main:4:direct:buf:0x30:8",
        kind="pointer_store",
        offset_expr="0x30",
        write_size_expr="0x30",
        overflow_condition="direct write byte range 48..55 outside 16 bytes",
        evidence_sources=["c_text"],
    )

    selected = select_confirmation_candidates([base, same_callsite, next_callsite, direct_same_line])

    assert [candidate.candidate_id for candidate in selected] == [
        base.candidate_id,
        next_callsite.candidate_id,
        direct_same_line.candidate_id,
    ]
    merged = selected[0]
    assert merged.classification_trace["confirmation_equivalent_write_count"] == 2
    assert [item["candidate_id"] for item in merged.classification_trace["confirmation_equivalent_writes"]] == [
        base.candidate_id,
        same_callsite.candidate_id,
    ]
    assert any("2 equivalent writes at this callsite" in item for item in merged.evidence)
    assert any("0x28" in item for item in merged.evidence)


def test_confirmation_queue_uses_tight_structural_policy() -> None:
    base = StaticCandidate(
        binary="demo.bin",
        function_name="main",
        source_symbol="main",
        demangled_name="",
        source_object="",
        address="0x1000",
        relative_path="main.c",
        candidate_id="demo:base",
        kind="pointer_store",
        sink="pointer_store",
        line_number=4,
        line_text="buf[i] = value;",
        target_buffer="buf",
        capacity_bytes=16,
        capacity_basis="buf: stack[-0x20..-0x10], 16 bytes",
        destination_kind="stack",
        capacity_source="stack_region",
        write_relation="symbolic_offset",
        write_size_expr="8",
        write_size_bytes=8,
        offset_expr="i",
        overflow_condition="offset i is not proven within 16 bytes",
        verdict="candidate",
        path_is_valid=True,
        input_reaches_sink=True,
        reachability_kind="local_source",
        classification_trace=_source_to_write_trace(
            write_offset="parameter_controlled",
            write_source="parameter_controlled",
        ),
    )
    reportable_exact = replace(
        base,
        candidate_id="demo:exact",
        verdict="overflow",
        write_relation="proven_overflow",
        offset_expr="0x20",
        overflow_condition="offset 32 is outside 16 bytes",
    )
    unknown_exact = replace(
        reportable_exact,
        candidate_id="demo:unknown-exact",
        path_is_valid=False,
        input_reaches_sink=False,
        reachability_kind="unknown",
    )
    direct_stack_symbolic = replace(base, candidate_id="demo:direct-stack")
    direct_static_symbolic = replace(
        base,
        candidate_id="demo:direct-static",
        destination_kind="static_local",
        capacity_source="inferred_static_remaining_size",
    )
    interprocedural_size = replace(
        base,
        candidate_id="demo:inter-size",
        kind="interprocedural_call",
        sink="memcpy",
        write_relation="symbolic_size",
        write_size_expr="n",
        write_size_bytes=None,
    )
    direct_size = replace(
        interprocedural_size,
        candidate_id="demo:direct-size",
        kind="call",
        classification_trace=_source_to_write_trace(
            write_size="source_controlled",
            write_source="source_controlled",
        ),
    )
    loop_alias = replace(
        base,
        candidate_id="demo:loop-alias",
        write_relation="iterated_alias_unproven",
        path_is_valid=False,
        input_reaches_sink=False,
        reachability_kind="unknown",
    )
    unknown_helper = replace(
        direct_size,
        candidate_id="demo:unknown-helper",
        sink="unknown_helper",
        line_text="unknown_helper(buf, n);",
        evidence_sources=["c_text"],
    )

    selected = select_confirmation_candidates(
        [
            reportable_exact,
            unknown_exact,
            direct_stack_symbolic,
            direct_static_symbolic,
            interprocedural_size,
            direct_size,
            loop_alias,
            unknown_helper,
        ]
    )

    assert [candidate.candidate_id for candidate in selected] == [
        reportable_exact.candidate_id,
        direct_static_symbolic.candidate_id,
        direct_size.candidate_id,
    ]
    assert confirmation_rule_counts(selected) == {
        "exact_overflow": 1,
        "controlled_offset": 1,
        "controlled_extent": 1,
    }


def test_confirmation_review_rule_names_five_frontier_shapes() -> None:
    base = StaticCandidate(
        binary="demo.bin",
        function_name="main",
        source_symbol="main",
        demangled_name="",
        source_object="",
        address="0x1000",
        relative_path="main.c",
        candidate_id="demo:base",
        kind="call",
        sink="memcpy",
        line_number=4,
        line_text="memcpy(buf, input, n);",
        target_buffer="buf",
        capacity_bytes=16,
        capacity_basis="buf: stack[-0x20..-0x10], 16 bytes",
        destination_kind="stack",
        capacity_source="stack_region",
        write_relation="proven_overflow",
        write_size_expr="32",
        write_size_bytes=32,
        offset_expr="0",
        overflow_condition="write size 32 exceeds 16-byte destination",
        verdict="overflow",
        path_is_valid=True,
        input_reaches_sink=True,
        reachability_kind="local_source",
        classification_trace=_source_to_write_trace(write_source="source_controlled"),
    )
    assert confirmation_review_rule(base) == "exact_overflow"
    assert confirmation_review_rule(
        replace(
            base,
            candidate_id="demo:unbounded",
            sink="strcpy",
            write_relation="unbounded",
            write_size_expr="unbounded",
            write_size_bytes=None,
            overflow_condition="strcpy has no destination bound",
            verdict="unbounded",
            classification_trace=_source_to_write_trace(write_source="parameter_controlled"),
        )
    ) == "unbounded_sink"
    assert confirmation_review_rule(
        replace(
            base,
            candidate_id="demo:offset",
            kind="indexed_write",
            sink="array_store",
            write_relation="symbolic_offset",
            write_size_expr="1",
            write_size_bytes=1,
            offset_expr="i",
            overflow_condition="offset i is not proven within 16 bytes",
            verdict="candidate",
            classification_trace=_source_to_write_trace(write_offset="source_controlled"),
        )
    ) == "controlled_offset"
    assert confirmation_review_rule(
        replace(
            base,
            candidate_id="demo:extent",
            write_relation="symbolic_size",
            write_size_expr="n",
            write_size_bytes=None,
            overflow_condition="write size n is not statically bounded",
            verdict="candidate",
            classification_trace=_source_to_write_trace(
                write_source="source_controlled",
                write_size="source_controlled",
            ),
        )
    ) == "controlled_extent"
    assert confirmation_review_rule(
        replace(
            base,
            candidate_id="demo:loop",
            kind="pointer_store",
            sink="pointer_store",
            write_relation="iterated_alias_unproven",
            write_size_expr="1",
            write_size_bytes=1,
            overflow_condition="loop bounds are not proven within 16-byte destination",
            verdict="candidate",
            classification_trace=_source_to_write_trace(write_source="unknown"),
        )
    ) == "loop_alias_frontier"


def test_confirmation_review_rule_suppresses_destination_only_and_constant_initializers() -> None:
    destination_only = StaticCandidate(
        binary="demo.bin",
        function_name="main",
        source_symbol="main",
        demangled_name="",
        source_object="",
        address="0x1000",
        relative_path="main.c",
        candidate_id="demo:destination-only",
        kind="indexed_write",
        sink="array_store",
        line_number=4,
        line_text="buf[4] = value;",
        target_buffer="buf",
        capacity_bytes=16,
        capacity_basis="buf: stack[-0x20..-0x10], 16 bytes",
        destination_kind="stack",
        capacity_source="stack_region",
        write_relation="symbolic_offset",
        write_size_expr="1",
        write_size_bytes=1,
        offset_expr="4",
        overflow_condition="offset is not proven within 16 bytes",
        verdict="candidate",
        path_is_valid=True,
        input_reaches_sink=True,
        reachability_kind="local_source",
        classification_trace=_source_to_write_trace(destination_pointer="parameter_controlled"),
    )
    initializer = replace(
        destination_only,
        candidate_id="demo:initializer",
        kind="interprocedural_pointer_store",
        sink="pointer_store",
        line_text="init_buffer(buf);",
        write_relation="proven_overflow",
        offset_expr="0x20",
        overflow_condition="init_buffer writes byte range 32..35 outside 16 bytes",
        verdict="overflow",
        evidence_sources=["c_text", "interprocedural_summary"],
        classification_trace=_source_to_write_trace(),
    )

    assert confirmation_review_rule(destination_only) is None
    assert confirmation_review_rule(initializer) is None


def test_callee_parameter_sink_without_stack_callsite_is_not_public(tmp_path: Path) -> None:
    fill_text = """
void fill(char *out, char *input) {
  strcpy(out, input);
}
"""
    records = [
        _record(name="fill", address="0x1100", ordinal=0, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"fill.c": fill_text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []
    assert report.vulnerability_reports == []


def test_uninstantiated_summaries_are_not_public_even_when_artifacts_are_written(tmp_path: Path) -> None:
    fill_text = """
void fill(char *out, char *input) {
  strcpy(out, input);
}
"""
    records = [
        _record(name="fill", address="0x1100", ordinal=0, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"fill.c": fill_text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []
    assert not (export_dir / "summary_findings.json").exists()


def test_uninstantiated_sink_wrapper_is_not_public_candidate(tmp_path: Path) -> None:
    wrap_text = """
void wrap(char *out, char *input) {
  return strcpy(out, input);
}
"""
    records = [
        _record(name="wrap", address="0x1100", ordinal=0, relative_path="wrap.c", text=wrap_text),
    ]
    export_dir = _write_export(tmp_path, records, {"wrap.c": wrap_text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []


def test_unlabeled_nonsink_forwarder_is_skipped(tmp_path: Path) -> None:
    wrap_text = """
void wrap(char *out, char *input) {
  return fill(out, input);
}
"""
    records = [
        _record(name="wrap", address="0x1100", ordinal=0, relative_path="wrap.c", text=wrap_text),
    ]
    export_dir = _write_export(tmp_path, records, {"wrap.c": wrap_text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []


def test_uninstantiated_parameter_summaries_are_not_exported(tmp_path: Path) -> None:
    source_text = """
void source_wrap(int argc, char **argv, char *out) {
  strcpy(out, argv[1]);
}
"""
    unknown_text = """
void unknown_wrap(char *out, char *input) {
  *out = *input;
}
"""
    records = [
        _record(name="source_wrap", address="0x1100", ordinal=0, relative_path="source_wrap.c", text=source_text),
        _record(name="unknown_wrap", address="0x1200", ordinal=1, relative_path="unknown_wrap.c", text=unknown_text),
    ]
    export_dir = _write_export(
        tmp_path,
        records,
        {"source_wrap.c": source_text, "unknown_wrap.c": unknown_text},
    )

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []


def test_uninstantiated_summary_artifact_is_empty(tmp_path: Path) -> None:
    fill_text = """
void fill(char *out, char *input) {
  strcpy(out, input);
}
"""
    records = [
        _record(name="fill", address="0x1100", ordinal=0, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"fill.c": fill_text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []


def test_scalar_parameter_store_does_not_create_summary(tmp_path: Path) -> None:
    fill_text = """
void fill(char *out, char *input) {
  *out = *input;
  out[0] = 0;
}
"""
    records = [
        _record(name="fill", address="0x1100", ordinal=0, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"fill.c": fill_text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []


def test_variable_parameter_index_write_without_stack_callsite_is_not_public(tmp_path: Path) -> None:
    fill_text = """
void fill(char *out, int index) {
  scanf("%d", &index);
  out[index] = 0;
}
"""
    records = [
        _record(name="fill", address="0x1100", ordinal=0, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"fill.c": fill_text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []


def test_variable_parameter_index_without_source_stays_internal(tmp_path: Path) -> None:
    fill_text = """
void fill(char *out, int index) {
  out[index] = 0;
}
"""
    records = [
        _record(name="fill", address="0x1100", ordinal=0, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"fill.c": fill_text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []


def test_parameter_field_store_does_not_create_summary(tmp_path: Path) -> None:
    fill_text = """
void fill(struct item *out, int value) {
  out->count = value;
}
"""
    records = [
        _record(name="fill", address="0x1100", ordinal=0, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"fill.c": fill_text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []


def test_parameter_mentioned_inside_helper_call_is_not_destination_summary(tmp_path: Path) -> None:
    fill_text = """
void fill(char *out, char *input) {
  *(undefined1 *)(helper(out) + input[0]) = 0;
}
"""
    records = [
        _record(name="fill", address="0x1100", ordinal=0, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"fill.c": fill_text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []


def test_stack_object_mentioned_inside_helper_call_is_not_destination(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  memcpy(helper(local_20), input, 64);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    assert extract_static_candidates(manifest, nodes) == []


def test_casted_address_of_stack_object_is_destination(tmp_path: Path) -> None:
    fill_text = """
void fill(char *out) {
  out[8] = 0;
}
"""
    main_text = """
void main(void) {
  char local_20[4];
  fill((char *)&local_20);
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text, stack_regions=[_stack_region(size=4)]),
        _record(name="fill", address="0x1100", ordinal=1, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "fill.c": fill_text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].kind == "interprocedural_indexed_write"
    assert candidates[0].verdict == "overflow"


def test_interprocedural_object_pointer_cast_uses_symbolic_capacity(tmp_path: Path) -> None:
    init_text = """
void init(Ctx *ctx) {
  *(int *)(ctx + 0x10) = 0;
}
"""
    main_text = """
void main(void) {
  init((Ctx *)local_8);
}
"""
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=main_text,
            stack_regions=[_stack_region("local_8", size=8, start=-8)],
        ),
        _record(name="init", address="0x1100", ordinal=1, relative_path="init.c", text=init_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "init.c": init_text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.kind == "interprocedural_pointer_store"
    assert candidate.verdict == "candidate"
    assert candidate.write_relation == "symbolic_capacity"
    assert candidate.capacity_bytes == 0
    assert candidate.capacity_source == "interprocedural_object_extent_unknown"
    assert "interprocedural_object_extent_unknown" in candidate.evidence_sources
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_interprocedural_address_taken_object_uses_symbolic_capacity(tmp_path: Path) -> None:
    init_text = """
void init(Ctx *ctx) {
  *(int *)(ctx + 0x10) = 0;
}
"""
    main_text = """
void main(void) {
  Ctx ctx;
  init(&ctx);
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text),
        _record(name="init", address="0x1100", ordinal=1, relative_path="init.c", text=init_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "init.c": init_text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 1
    assert candidates[0].kind == "interprocedural_pointer_store"
    assert candidates[0].write_relation == "symbolic_capacity"
    assert candidates[0].capacity_source == "interprocedural_object_extent_unknown"
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_interprocedural_address_taken_alias_uses_symbolic_capacity(tmp_path: Path) -> None:
    init_text = """
void init(Ctx *ctx) {
  *(int *)(ctx + 0x10) = 0;
}
"""
    main_text = """
void main(void) {
  Ctx ctx;
  Ctx *alias;
  alias = &ctx;
  init(alias);
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text),
        _record(name="init", address="0x1100", ordinal=1, relative_path="init.c", text=init_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "init.c": init_text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 1
    assert candidates[0].kind == "interprocedural_pointer_store"
    assert candidates[0].write_relation == "symbolic_capacity"
    assert candidates[0].capacity_source == "interprocedural_object_extent_unknown"
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_interprocedural_address_taken_word_pointer_store_uses_symbolic_capacity(tmp_path: Path) -> None:
    init_text = """
void init(undefined8 *out) {
  *(undefined8 *)(out + 8) = 0;
}
"""
    main_text = """
void main(void) {
  undefined8 slot;
  init(&slot);
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text),
        _record(name="init", address="0x1100", ordinal=1, relative_path="init.c", text=init_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "init.c": init_text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 1
    assert candidates[0].kind == "interprocedural_pointer_store"
    assert candidates[0].write_relation == "symbolic_capacity"
    assert candidates[0].capacity_source == "interprocedural_object_extent_unknown"
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_interprocedural_address_taken_word_unbounded_call_without_taint_stays_out_of_queue(tmp_path: Path) -> None:
    init_text = """
void init(char *out) {
  strcpy(out, src);
}
"""
    main_text = """
void main(void) {
  undefined8 slot;
  init(&slot);
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text),
        _record(name="init", address="0x1100", ordinal=1, relative_path="init.c", text=init_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "init.c": init_text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 1
    assert candidates[0].kind == "interprocedural_call"
    assert candidates[0].write_relation == "unbounded"
    assert candidates[0].capacity_source == "declared_address_taken_object"
    assert report.confirmation_findings == []


def test_interprocedural_small_array_object_head_uses_symbolic_capacity(tmp_path: Path) -> None:
    init_text = """
void init(long ctx) {
  *(undefined1 *)(ctx + 0x10) = 0;
  *(undefined1 *)(ctx + 0x18) = 0;
  *(undefined1 *)(ctx + 0x20) = 0;
}
"""
    main_text = """
void main(void) {
  undefined1 local_8[8];
  init(local_8);
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text),
        _record(name="init", address="0x1100", ordinal=1, relative_path="init.c", text=init_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "init.c": init_text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 3
    assert {candidate.write_relation for candidate in candidates} == {"symbolic_capacity"}
    assert {candidate.capacity_source for candidate in candidates} == {"interprocedural_object_extent_unknown"}
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_interprocedural_ghidra_stack_object_layout_uses_symbolic_capacity(tmp_path: Path) -> None:
    init_text = """
void init(long ctx) {
  *(undefined1 *)(ctx + 0x40) = 0;
  *(undefined1 *)(ctx + 0x48) = 0;
  *(undefined1 *)(ctx + 0x50) = 0;
}
"""
    main_text = """
void main(void) {
  init(local_40);
}
"""
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=main_text,
            stack_regions=[_stack_region("local_40", size=32, start=-0x40)],
        ),
        _record(name="init", address="0x1100", ordinal=1, relative_path="init.c", text=init_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "init.c": init_text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 3
    assert {candidate.write_relation for candidate in candidates} == {"symbolic_capacity"}
    assert {candidate.capacity_source for candidate in candidates} == {"interprocedural_object_extent_unknown"}
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_interprocedural_decompiler_field_component_uses_symbolic_capacity(tmp_path: Path) -> None:
    init_text = """
void init(long ctx) {
  *(undefined8 *)(ctx + 0x30) = 0;
}
"""
    main_text = """
void main(void) {
  undefined8 auVar1[2];
  init(auVar1._0_8_);
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text),
        _record(name="init", address="0x1100", ordinal=1, relative_path="init.c", text=init_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "init.c": init_text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 1
    assert candidates[0].kind == "interprocedural_pointer_store"
    assert candidates[0].write_relation == "symbolic_capacity"
    assert candidates[0].capacity_source == "interprocedural_object_extent_unknown"
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_local_decompiler_field_component_uses_symbolic_capacity(tmp_path: Path) -> None:
    text = """
void main(void) {
  undefined8 auVar1[2];
  undefined8 *p;
  int i;
  p = auVar1._0_8_;
  p[i] = 0;
}
"""
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 1
    assert candidates[0].kind == "indexed_write"
    assert candidates[0].write_relation == "symbolic_capacity"
    assert candidates[0].capacity_source == "interprocedural_object_extent_unknown"
    assert "direct_object_extent_unknown" in candidates[0].evidence_sources
    assert report.confirmation_findings == []


def test_interprocedural_byte_pointer_multi_write_remains_overflow(tmp_path: Path) -> None:
    fill_text = """
void fill(char *out) {
  out[8] = 0;
  out[9] = 0;
  out[10] = 0;
}
"""
    main_text = """
void main(void) {
  char local_20[4];
  fill(local_20);
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text),
        _record(name="fill", address="0x1100", ordinal=1, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "fill.c": fill_text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 3
    assert {candidate.write_relation for candidate in candidates} == {"proven_overflow"}
    assert {candidate.verdict for candidate in candidates} == {"overflow"}
    assert report.vulnerability_reports == []


def test_interprocedural_byte_pointer_layout_span_remains_overflow(tmp_path: Path) -> None:
    fill_text = """
void fill(char *out) {
  out[0x40] = 0;
  out[0x48] = 0;
  out[0x50] = 0;
}
"""
    main_text = """
void main(void) {
  char local_40[32];
  fill(local_40);
}
"""
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=main_text,
            stack_regions=[_stack_region("local_40", size=32, start=-0x40)],
        ),
        _record(name="fill", address="0x1100", ordinal=1, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "fill.c": fill_text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 3
    assert {candidate.write_relation for candidate in candidates} == {"proven_overflow"}
    assert {candidate.verdict for candidate in candidates} == {"overflow"}
    assert len(report.confirmation_findings) == 1
    assert report.vulnerability_reports == []


def test_exported_parameter_index_summary_enters_confirmation_queue(tmp_path: Path) -> None:
    helper_text = """
void helper(char *out, int index) {
  out[index] = 0;
}
"""
    wrapper_text = """
void wrapper(char *buf, int index) {
  scanf("%d", &index);
  helper(buf + index, index);
}
"""
    records = [
        _record(
            name="wrapper",
            address="0x1000",
            ordinal=0,
            relative_path="wrapper.c",
            text=wrapper_text,
            source_symbol="wrapper",
        ),
        _record(name="helper", address="0x1100", ordinal=1, relative_path="helper.c", text=helper_text),
    ]
    export_dir = _write_export(tmp_path, records, {"wrapper.c": wrapper_text, "helper.c": helper_text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].kind == "parameter_summary_indexed_write"
    assert report.candidate_findings[0].destination_kind == "parameter"
    assert report.candidate_findings[0].write_relation == "missing_size_contract"
    assert report.candidate_findings[0].triage_tier == "api_contract"
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_flash_area_read_parameter_destination_without_stack_callsite_is_not_public(tmp_path: Path) -> None:
    text = """
void boot_read_image_header(image_header *out_hdr) {
  flash_area_read(fap, 0, out_hdr, 0x20);
}
"""
    record = _record(
        name="boot_read_image_header",
        address="0x1000",
        ordinal=0,
        relative_path="boot.c",
        text=text,
    )
    export_dir = _write_export(tmp_path, [record], {"boot.c": text})

    report = run_static_pipeline(export_dir)

    assert report.candidate_findings == []


def test_adjacent_stack_locals_do_not_inflate_capacity(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_30[16];
  char local_20[16];
  memcpy(local_20, input, 24);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[
            _stack_region("local_30", size=16, start=-0x30),
            _stack_region("local_20", size=16, start=-0x20),
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].target_buffer == "local_20"
    assert candidates[0].capacity_bytes == 16
    assert "capacity_confidence" not in candidates[0].to_dict()
    assert candidates[0].verdict == "overflow"


def test_decompiler_split_stack_header_extent_uses_symbolic_capacity(tmp_path: Path) -> None:
    text = """
void main(short *param_2) {
  int local_258[3];
  unsigned int local_24c;
  unsigned int local_58;
  memcpy(local_258, param_2, 0x200);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[
            _stack_region("local_258", size=4, start=-0x258),
            _stack_region("local_24c", size=4, start=-0x24c),
            _stack_region("local_58", size=4, start=-0x58),
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    candidate = report.candidate_findings[0]
    assert candidate.target_buffer == "local_258"
    assert candidate.verdict == "candidate"
    assert candidate.write_relation == "symbolic_capacity"
    assert candidate.capacity_bytes == 0
    assert candidate.capacity_source == "direct_object_extent_unknown"
    assert report.confirmation_findings == []
    assert report.vulnerability_reports == []


def test_named_declared_stack_array_is_visible_to_c_fallback(tmp_path: Path) -> None:
    text = """
void main(int argc, char **argv) {
  char temp_filepath[16];
  memcpy(temp_filepath, argv[1], 64);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].target_buffer == "temp_filepath"
    assert candidates[0].capacity_bytes == 16


def test_global_object_metadata_is_visible_to_c_fallback(tmp_path: Path) -> None:
    text = """
void main(void) {
  memcpy(global_buf, input, 32);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        global_refs=[
            {
                "label": "global_buf",
                "var_names": ["global_buf"],
                "size_bytes": 16,
                "destination_kind": "global",
                "capacity_source": "test_global_ref",
            }
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].destination_kind == "global"
    assert candidates[0].target_buffer == "global_buf"
    assert candidates[0].verdict == "overflow"


def test_ghidra_data_reference_extent_is_not_proof_grade(tmp_path: Path) -> None:
    text = """
void main(void) {
  memcpy(DAT_0018e000, input, 0x8000);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        global_refs=[
            {
                "label": "DAT_0018e000",
                "var_display": "DAT_0018e000",
                "var_names": ["DAT_0018e000"],
                "size_bytes": 1,
                "destination_kind": "global",
                "capacity_source": "ghidra_data_reference",
                "object_trust": "metadata",
            }
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    candidate = report.candidate_findings[0]
    assert candidate.target_buffer == "DAT_0018e000"
    assert candidate.destination_kind == "global"
    assert candidate.verdict == "candidate"
    assert candidate.write_relation == "symbolic_capacity"
    assert candidate.capacity_bytes == 0
    assert candidate.capacity_source == "direct_object_extent_unknown"
    assert "direct_object_extent_unknown" in candidate.evidence_sources
    assert report.vulnerability_reports == []


def test_unbounded_ghidra_data_reference_extent_is_not_proof_grade(tmp_path: Path) -> None:
    text = """
void main(void) {
  strcpy(DAT_0016d9a0, input);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        global_refs=[
            {
                "label": "DAT_0016d9a0",
                "var_display": "DAT_0016d9a0",
                "var_names": ["DAT_0016d9a0"],
                "size_bytes": 1,
                "destination_kind": "global",
                "capacity_source": "ghidra_data_reference",
                "object_trust": "metadata",
            }
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    candidate = report.candidate_findings[0]
    assert candidate.target_buffer == "DAT_0016d9a0"
    assert candidate.verdict == "candidate"
    assert candidate.write_relation == "symbolic_capacity"
    assert candidate.capacity_bytes == 0
    assert candidate.capacity_source == "direct_object_extent_unknown"
    assert report.vulnerability_reports == []


def test_interprocedural_ghidra_data_reference_extent_is_not_proof_grade(tmp_path: Path) -> None:
    fill_text = """
void fill(char *dst) {
  dst[1] = 0;
}
"""
    main_text = """
void main(void) {
  fill(&DAT_001197c0);
}
"""
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=main_text,
            global_refs=[
                {
                    "label": "DAT_001197c0",
                    "var_display": "DAT_001197c0",
                    "var_names": ["DAT_001197c0"],
                    "size_bytes": 1,
                    "destination_kind": "global",
                    "capacity_source": "ghidra_data_reference",
                    "object_trust": "metadata",
                }
            ],
        ),
        _record(name="fill", address="0x1100", ordinal=1, relative_path="fill.c", text=fill_text),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "fill.c": fill_text})

    report = run_static_pipeline(export_dir)

    candidates = [candidate for candidate in report.candidate_findings if candidate.function_name == "main"]
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.target_buffer == "DAT_001197c0"
    assert candidate.kind == "interprocedural_indexed_write"
    assert candidate.verdict == "candidate"
    assert candidate.write_relation == "symbolic_capacity"
    assert candidate.capacity_bytes == 0
    assert candidate.capacity_source == "direct_object_extent_unknown"
    assert report.vulnerability_reports == []


def test_direct_ghidra_stack_slot_extent_is_not_proof_grade(tmp_path: Path) -> None:
    text = """
void main(void) {
  local_418[10] = 0x41;
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region("local_418", size=8, start=-0x418)],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    candidate = report.candidate_findings[0]
    assert candidate.target_buffer == "local_418"
    assert candidate.destination_kind == "stack"
    assert candidate.verdict == "candidate"
    assert candidate.write_relation == "symbolic_capacity"
    assert candidate.capacity_bytes == 0
    assert candidate.capacity_source == "direct_object_extent_unknown"
    assert "direct_object_extent_unknown" in candidate.evidence_sources
    assert report.vulnerability_reports == []


def test_inferred_static_remaining_capacity_buffer_enters_confirmation_queue(tmp_path: Path) -> None:
    text = """
void main(int argc) {
  int used;
  int idx;
  if ((used = sprintf(scratch_1, "%d", argc), used < 0x20)) {
    memset(scratch_1 + used, 0x20, (ulong)(0x20 - used));
  }
  scratch_1[idx] = 0x41;
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        source_symbol="main",
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    static_candidates = [
        candidate
        for candidate in report.candidate_findings
        if candidate.target_buffer == "scratch_1" and candidate.destination_kind == "static_local"
    ]
    assert static_candidates
    assert {candidate.capacity_bytes for candidate in static_candidates} == {32}
    assert any(candidate.write_relation == "symbolic_offset" for candidate in static_candidates)
    assert any(candidate.target_buffer == "scratch_1" for candidate in report.confirmation_findings)


def test_declared_array_survives_ambiguous_merged_stack_region(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_208[500];
  undefined1 local_14;
  memcpy(local_208, input, 501);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[
            {
                "start_offset": -0x208,
                "end_offset": -0x10,
                "size_bytes": 504,
                "var_names": ["local_208", "local_14"],
                "data_types": ["char", "undefined1"],
            }
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].target_buffer == "local_208"
    assert candidates[0].capacity_bytes == 500
    assert candidates[0].verdict == "overflow"


def test_declared_array_replaces_undersized_exact_stack_region(tmp_path: Path) -> None:
    text = """
void main(void) {
  uint local_148[64];
  uint *p;
  p = local_148;
  p[63] = 0;
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[
            {
                "start_offset": -0x148,
                "end_offset": -0x147,
                "size_bytes": 1,
                "var_names": ["local_148"],
                "data_types": ["undefined"],
            }
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    assert extract_static_candidates(manifest, nodes) == []


def test_address_taken_declared_stack_object_is_visible_to_c_fallback(tmp_path: Path) -> None:
    text = """
int dev_up(char *iface) {
  ifreq ifr;
  strcpy((char *)&ifr, iface);
}
"""
    record = _record(
        name="dev_up",
        address="0x1000",
        ordinal=0,
        relative_path="dev_up.c",
        text=text,
        stack_regions=[],
    )
    export_dir = _write_export(tmp_path, [record], {"dev_up.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].target_buffer == "ifr"
    assert candidates[0].capacity_bytes == 40


def test_negative_constant_index_is_reported(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  local_20[-1] = 0;
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].sink == "array_store"
    assert candidates[0].write_relation == "proven_overflow"
    assert "outside 16-byte destination" in candidates[0].overflow_condition


def test_indexed_comparisons_are_not_writes(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  if (local_20[1] == 'A') {
    return;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    assert extract_static_candidates(manifest, nodes) == []


def test_scanf_conversions_align_to_destination_arguments(tmp_path: Path) -> None:
    text = """
void main(void) {
  int n;
  char local_20[16];
  scanf("%d %s", &n, local_20);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].sink == "scanf"
    assert candidates[0].target_buffer == "local_20"


def test_comments_and_string_literals_do_not_create_fake_sink_calls(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  // strcpy(local_20, input);
  puts("memcpy(local_20, input, 64)");
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    assert extract_static_candidates(manifest, nodes) == []


def test_strncat_unknown_destination_length_remains_candidate(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  strncat(local_20, input, 8);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].sink == "strncat"
    assert candidates[0].verdict == "candidate"


def test_bounded_call_through_alias_uses_remaining_capacity(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  char *p;
  p = local_20 + 4;
  memcpy(p, input, 12);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    assert extract_static_candidates(manifest, nodes) == []


def test_bounded_call_through_alias_reports_past_remaining_capacity(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  char *p;
  p = local_20 + 4;
  memcpy(p, input, 13);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].verdict == "overflow"
    assert "byte range 4..16" in candidates[0].overflow_condition


def test_sizeof_arithmetic_can_prove_bounded_call_safe(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  memcpy(local_20, input, sizeof(local_20) - 1);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    assert extract_static_candidates(manifest, nodes) == []


def test_simple_for_loop_bound_prunes_safe_indexed_write(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int i;
  for (i = 0; i < 16; i++) {
    local_20[i] = 0;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    assert extract_static_candidates(manifest, nodes) == []


def test_pcode_call_finds_oversized_bounded_sink_without_c_text(tmp_path: Path) -> None:
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text="",
        stack_regions=[_stack_region()],
        pcode_calls=[
            {
                "call_address": "0x1010",
                "callee": "memcpy",
                "args": [
                    {"expr": "local_20", "stack_ref": {"var_name": "local_20"}},
                    {"expr": "input"},
                    {"constant": 64, "expr": "64"},
                ],
            }
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": ""})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].sink == "memcpy"
    assert candidates[0].operation_address == "0x1010"
    assert candidates[0].evidence_sources == ["pcode_calls", "direct_object_extent_unknown"]


def test_duplicate_pcode_writes_are_reconciled_with_suppression_trace(tmp_path: Path) -> None:
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text="",
        stack_regions=[_stack_region()],
        pcode_calls=[
            {
                "call_address": "0x1010",
                "callee": "memcpy",
                "args": [
                    {"expr": "local_20", "stack_ref": {"var_name": "local_20"}},
                    {"expr": "input"},
                    {"constant": 64, "expr": "64"},
                ],
            },
            {
                "call_address": "0x1010",
                "callee": "memcpy",
                "args": [
                    {"expr": "local_20", "stack_ref": {"var_name": "local_20"}},
                    {"expr": "input"},
                    {"constant": 64, "expr": "64"},
                ],
            },
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": ""})

    report = run_static_pipeline(export_dir, persist_debug_facts=True)

    assert len(report.candidate_findings) == 1
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())
    assert len(suppressed) == 1
    assert suppressed[0]["reason"] == "duplicate_write_fact"


def test_unactionable_pcode_calls_fall_back_to_c_text(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  memcpy(local_20, input, 64);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
        pcode_calls=[{"callee": "memcpy", "args": [{"expr": "unique"}, {"expr": "input"}]}],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].sink == "memcpy"
    assert candidates[0].evidence_sources == ["c_text"]


def test_pcode_store_finds_out_of_bounds_stack_write(tmp_path: Path) -> None:
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text="",
        stack_regions=[_stack_region()],
        pcode_stores=[
            {
                "operation_address": "0x1018",
                "base_var": "local_20",
                "constant_index": 20,
                "scale": 1,
                "write_width": 1,
            }
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": ""})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].sink == "pcode_store"
    assert candidates[0].operation_address == "0x1018"
    assert candidates[0].verdict == "candidate"
    assert candidates[0].write_relation == "symbolic_capacity"
    assert candidates[0].capacity_source == "direct_object_extent_unknown"


def test_static_candidates_drop_proven_safe_guarded_pointer_store(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int index;
  if ((0 <= index) && (index < 16)) {
    *(undefined1 *)(local_20 + index) = 1;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    assert extract_static_candidates(manifest, nodes) == []


def test_static_candidates_drop_proven_safe_reject_guard_pointer_store(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  int index;
  if ((index < 0) || (15 < index)) {
    printLine("bad index");
  }
  else {
    *(undefined1 *)(local_20 + index) = 1;
  }
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    assert extract_static_candidates(manifest, nodes) == []


def test_static_pipeline_keeps_multiple_candidates_in_one_function(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  char local_40[16];
  gets(local_20);
  gets(local_40);
}
"""
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=text,
            stack_regions=[_stack_region("local_20"), _stack_region("local_40")],
        )
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 2
    assert len({finding.candidate_id for finding in report.candidate_findings}) == 2
    assert len(report.vulnerability_reports) == 2


def test_reachability_does_not_use_per_candidate_path_search(tmp_path: Path, monkeypatch) -> None:
    def fail_find_path(*_args, **_kwargs):
        raise AssertionError("per-candidate find_path should not be used")

    monkeypatch.setattr(CallGraph, "find_path", fail_find_path)
    text = """
void main(void) {
  char local_20[16];
  char local_40[16];
  gets(local_20);
  gets(local_40);
}
"""
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=text,
            stack_regions=[_stack_region("local_20", start=-0x20), _stack_region("local_40", start=-0x40)],
        )
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 2


def test_static_candidates_preserve_source_symbol_metadata(tmp_path: Path) -> None:
    text = """
void FUN_00101100(void) {
  char local_20[16];
  gets(local_20);
}
"""
    record = _record(
        name="FUN_00101100",
        address="0x101100",
        ordinal=0,
        relative_path="sink.c",
        text=text,
        stack_regions=[_stack_region()],
        source_symbol="badSink",
        demangled_name="Case::badSink()",
        source_object="case.cpp.o",
    )
    export_dir = _write_export(tmp_path, [record], {"sink.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].source_symbol == "badSink"
    assert candidates[0].demangled_name == "Case::badSink()"
    assert candidates[0].source_object == "case.cpp.o"


def test_exported_public_root_not_simulated_unreachable(tmp_path: Path) -> None:
    text = """
void exported_entry(void) {
  char local_20[16];
  gets(local_20);
}
"""
    record = _record(
        name="exported_entry",
        address="0x1000",
        ordinal=0,
        relative_path="exported.c",
        text=text,
        stack_regions=[_stack_region()],
        source_symbol="exported_entry",
    )
    export_dir = _write_export(tmp_path, [record], {"exported.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    graph = report.candidate_findings[0].classification_trace["reachability_dataflow"]["graph"]
    assert graph["is_public"] is True
    assert graph["complete_unreachable_candidate"] is False


def test_private_helper_without_real_root_is_simulated_unreachable(tmp_path: Path) -> None:
    text = """
void helper(void) {
  int local_count;
  int index = local_count;
  char local_20[16];
  local_20[index] = 0;
}
"""
    record = _record(
        name="helper",
        address="0x1000",
        ordinal=0,
        relative_path="helper.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"helper.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    candidate = report.candidate_findings[0]
    graph = candidate.classification_trace["reachability_dataflow"]["graph"]
    assert graph["function_root_kind"] == "graph_root"
    assert graph["complete_unreachable_candidate"] is True
    assert report.stage_metrics["candidate_proof_gate_simulation"]["complete_unreachable_candidate"]["candidate_removals"] == 1


def test_evidence_packs_use_bounded_excerpts(tmp_path: Path) -> None:
    lines = ["void main(void) {", "  char local_20[16];"]
    lines.extend(f"  int filler_{idx} = {idx};" for idx in range(40))
    lines.append("  gets(local_20);")
    lines.extend(f"  int tail_{idx} = {idx};" for idx in range(40))
    lines.append("}")
    text = "\n".join(lines)
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)
    candidates = extract_static_candidates(manifest, nodes)

    output_dir = tmp_path / "packs"
    written = write_evidence_packs(candidates, nodes, output_dir)

    pack_paths = [path for path in written if path.name != "index.json"]
    assert len(pack_paths) == 1
    pack = json.loads(pack_paths[0].read_text())
    excerpt = pack["decompiler_context"]["c_excerpt"]
    excerpt_lines = excerpt["text"].splitlines()
    assert len(excerpt_lines) <= 9
    assert "gets(local_20);" in excerpt["text"]
    assert "filler_0" not in excerpt["text"]
    assert pack["schema_version"] == 3


def test_evidence_pack_filename_is_bounded(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  gets(local_20);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)
    candidate = extract_static_candidates(manifest, nodes)[0]
    long_candidate = type(candidate)(
        **{
            **candidate.to_dict(),
            "candidate_id": candidate.candidate_id + ":" + ("local_20_" * 80),
        }
    )

    output_dir = tmp_path / "packs"
    written = write_evidence_packs([long_candidate], nodes, output_dir)

    pack_paths = [path for path in written if path.name != "index.json"]
    assert len(pack_paths) == 1
    assert len(pack_paths[0].name) < 180


def test_confirmed_policy_reports_only_confirmed_candidates(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  char local_40[16];
  char local_60[16];
  gets(local_20);
  gets(local_40);
  gets(local_60);
}
"""
    records = [
        _record(
            name="main",
            address="0x1000",
            ordinal=0,
            relative_path="main.c",
            text=text,
            stack_regions=[
                _stack_region("local_20", start=-0x20),
                _stack_region("local_40", start=-0x40),
                _stack_region("local_60", start=-0x60),
            ],
        )
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": text})
    first_report = run_static_pipeline(export_dir)
    confirmations_dir = tmp_path / "confirmations"
    confirmations_dir.mkdir()
    candidate_ids = [candidate.candidate_id for candidate in first_report.candidate_findings]
    (confirmations_dir / "confirmations.json").write_text(
        json.dumps(
            {
                candidate_ids[0]: {
                    "status": "confirmed_bug",
                    "reason_codes": ["unbounded_stack_write"],
                },
                candidate_ids[1]: {"status": "rejected", "reason_codes": ["benign_wrapper"]},
                candidate_ids[2]: {
                    "status": "needs_more_evidence",
                    "reason_codes": ["missing_pcode"],
                },
            }
        )
    )

    confirmed_report = run_static_pipeline(export_dir, confirmation_dir=confirmations_dir)

    assert len(confirmed_report.candidate_findings) == 3
    assert set(confirmed_report.candidate_confirmations) == set(candidate_ids)
    assert len(confirmed_report.vulnerability_reports) == 1
    assert confirmed_report.vulnerability_reports[0].candidate_id == candidate_ids[0]


def test_memory_set_engine_preserves_stack_safe_bounded_write(tmp_path: Path) -> None:
    text = """
void main(void) {
  char local_20[16];
  snprintf(local_20, 16, "%s", input);
}
"""
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text=text,
        stack_regions=[_stack_region()],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    assert extract_static_candidates(manifest, nodes) == []


def test_memory_set_engine_detects_local_heap_constant_overflow(tmp_path: Path) -> None:
    text = """
void main(void) {
  char *buf;
  buf = malloc(16);
  memcpy(buf, input, 32);
}
"""
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].destination_kind == "heap"
    assert candidates[0].capacity_source == "local_malloc"
    assert candidates[0].verdict == "overflow"
    assert candidates[0].write_relation == "proven_overflow"


def test_confirmed_policy_reports_authoritative_heap_proof_outside_frontier(tmp_path: Path) -> None:
    text = """
void main(void) {
  char *buf;
  buf = malloc(16);
  memcpy(buf, input, 32);
}
"""
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    first_report = run_static_pipeline(export_dir)
    candidate = first_report.candidate_findings[0]
    assert first_report.confirmation_findings == []

    confirmations_dir = tmp_path / "confirmations"
    confirmations_dir.mkdir()
    (confirmations_dir / "confirmations.json").write_text(
        json.dumps(
            {
                candidate.candidate_id: {
                    "status": "confirmed_bug",
                    "reason_codes": ["ghidra_dynamic_overflow_proven"],
                    "bug_class": "heap_buffer_overflow",
                    "memory_safety_argument": {
                        "ghidra_dynamic_proof": {
                            "status": "overflow_proven",
                            "destination_kind": "heap",
                            "sink_address": "0x1010",
                            "write_size_bytes": 32,
                            "capacity_bytes": 16,
                            "overflow_bytes": 16,
                        },
                        "native_replay": {"status": "not_run"},
                    },
                }
            }
        )
    )

    confirmed_report = run_static_pipeline(
        export_dir,
        confirmation_dir=confirmations_dir,
        report_policy="confirmed",
    )

    assert confirmed_report.confirmation_findings == []
    assert len(confirmed_report.vulnerability_reports) == 1
    assert confirmed_report.vulnerability_reports[0].candidate_id == candidate.candidate_id
    assert (
        confirmed_report.vulnerability_reports[0]
        .cve_dossier["dynamic_confirmation"]["ghidra_dynamic_proof"]["status"]
        == "overflow_proven"
    )


def test_memory_set_engine_detects_casted_heap_initializer_overflow(tmp_path: Path) -> None:
    text = """
void main(void) {
  char *buf = (char *)malloc(16);
  memcpy(buf, input, 32);
}
"""
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].destination_kind == "heap"
    assert candidates[0].verdict == "overflow"


def test_memory_set_engine_instantiates_simple_allocator_wrapper(tmp_path: Path) -> None:
    main_text = """
void main(void) {
  char *buf;
  buf = xmalloc(16);
  memcpy(buf, input, 32);
}
"""
    wrapper_text = """
void *xmalloc(size_t n) {
  return malloc(n);
}
"""
    records = [
        _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=main_text),
        _record(
            name="xmalloc",
            address="0x1100",
            ordinal=1,
            relative_path="xmalloc.c",
            text=wrapper_text,
        ),
    ]
    export_dir = _write_export(tmp_path, records, {"main.c": main_text, "xmalloc.c": wrapper_text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].destination_kind == "heap"
    assert candidates[0].capacity_source == "allocator_wrapper:xmalloc"
    assert candidates[0].verdict == "overflow"


def test_fact_pipeline_preserves_unknown_sizeof_heap_capacity(tmp_path: Path) -> None:
    text = """
void main(void) {
  void *buf;
  buf = malloc(sizeof(unknown_struct));
  memcpy(buf, input, 32);
}
"""
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].destination_kind == "heap"
    assert candidates[0].write_relation == "symbolic_capacity"
    assert candidates[0].capacity_model["symbolic_expr"] == "sizeof(unknown_struct)"
    assert candidates[0].triage_tier == "symbolic_heap"


def test_memory_set_engine_suppresses_relationally_safe_symbolic_heap_writes(tmp_path: Path) -> None:
    text = """
char *join(char *left, char *right) {
  size_t left_len;
  size_t right_len;
  char *buf;
  right_len = strlen(right);
  left_len = strlen(left);
  buf = malloc(left_len + right_len + 2);
  strcpy(buf, right);
  strcpy(buf + right_len, left);
  return buf;
}
"""
    record = _record(
        name="join",
        address="0x1000",
        ordinal=0,
        relative_path="join.c",
        text=text,
        stack_regions=[_stack_region("buf", size=8, start=-0x20)],
    )
    export_dir = _write_export(tmp_path, [record], {"join.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = [candidate for candidate in extract_static_candidates(manifest, nodes) if candidate.sink == "strcpy"]

    assert candidates == []
    run_static_pipeline(export_dir, persist_debug_facts=True)
    suppressed = json.loads((export_dir / "suppressed_findings.json").read_text())
    relational = [
        item for item in suppressed
        if item["reason"] == "relational_allocation_write_proven_safe"
    ]
    assert len(relational) == 2
    assert all(item["trace"]["relational_safety_proof"]["all_paths_proven"] for item in relational)


def test_memory_set_engine_drops_local_heap_safe_index_write(tmp_path: Path) -> None:
    text = """
void main(void) {
  char *buf;
  buf = malloc(16);
  buf[15] = 0;
}
"""
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    assert extract_static_candidates(manifest, nodes) == []


def test_memory_set_engine_detects_local_heap_index_overflow(tmp_path: Path) -> None:
    text = """
void main(void) {
  char *buf;
  buf = malloc(16);
  buf[16] = 0;
}
"""
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    export_dir = _write_export(tmp_path, [record], {"main.c": text})
    manifest, nodes = load_function_nodes(export_dir)

    candidates = extract_static_candidates(manifest, nodes)

    assert len(candidates) == 1
    assert candidates[0].destination_kind == "heap"
    assert candidates[0].sink == "array_store"
    assert candidates[0].verdict == "overflow"


def test_fact_pipeline_queues_local_heap_symbolic_offset_candidate(tmp_path: Path) -> None:
    text = """
void main(void) {
  char *buf;
  size_t used;
  scanf("%zu", &used);
  buf = malloc(16);
  memcpy(buf + used, input, 8);
}
"""
    record = _record(name="main", address="0x1000", ordinal=0, relative_path="main.c", text=text)
    export_dir = _write_export(tmp_path, [record], {"main.c": text})

    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert len(report.confirmation_findings) == 1
    assert report.candidate_findings[0].destination_kind == "heap"
    assert report.candidate_findings[0].write_relation == "symbolic_offset"


def test_memory_set_engine_routes_pcode_bounded_call_through_classifier(tmp_path: Path) -> None:
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text="",
        stack_regions=[_stack_region()],
        pcode_calls=[
            {
                "call_address": "0x1010",
                "callee": "memcpy",
                "args": [
                    {"expr": "local_20 + 8", "stack_ref": {"var_name": "local_20"}, "relative_offset": 8},
                    {"expr": "input"},
                    {"constant": 12, "expr": "12"},
                ],
            }
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": ""})
    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].sink == "memcpy"
    assert report.candidate_findings[0].verdict == "candidate"
    assert report.candidate_findings[0].write_relation == "symbolic_capacity"
    assert report.candidate_findings[0].capacity_source == "direct_object_extent_unknown"


def test_memory_set_engine_routes_pcode_store_through_classifier(tmp_path: Path) -> None:
    record = _record(
        name="main",
        address="0x1000",
        ordinal=0,
        relative_path="main.c",
        text="",
        stack_regions=[_stack_region()],
        pcode_stores=[
            {
                "operation_address": "0x1018",
                "base_var": "local_20",
                "constant_index": 2,
                "scale": 8,
                "write_width": 1,
            }
        ],
    )
    export_dir = _write_export(tmp_path, [record], {"main.c": ""})
    report = run_static_pipeline(export_dir)

    assert len(report.candidate_findings) == 1
    assert report.candidate_findings[0].sink == "pcode_store"
    assert report.candidate_findings[0].verdict == "candidate"
    assert report.candidate_findings[0].write_relation == "symbolic_capacity"
    assert report.candidate_findings[0].capacity_source == "direct_object_extent_unknown"
