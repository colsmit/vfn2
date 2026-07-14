import json
import struct
from pathlib import Path

import pytest

from binary_agent.adjudication import (
    executable_segment_fingerprint,
    finalize_campaign,
    prepare_campaign,
    sha256_file,
)
from binary_agent.adjudication_autoprove import check_all_certificates, run_autoprove
from binary_agent.adjudication_certificates import CertificateError, check_certificate
from binary_agent import adjudication_certificates as checker_module
from binary_agent import adjudication as adjudication_module


IMAGE_BASE = 0x100000


def _elf_with_calls(*offsets: int) -> bytes:
    data = bytearray(0x400)
    data[:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        3,
        62,
        1,
        0x80,
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
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, len(data), len(data), 0x1000)
    for offset in offsets:
        data[offset : offset + 5] = b"\xe8\x00\x00\x00\x00"
    return bytes(data)


def _elf_with_indirect_call(offset: int) -> bytes:
    data = bytearray(_elf_with_calls())
    data[offset : offset + 6] = b"\xff\x15\x00\x00\x00\x00"
    return bytes(data)


def _state(
    candidate_id: str,
    *,
    operation_offset: int = 0x100,
    successor_literal: bool = True,
    vulnerability_type: str = "stack_overflow",
) -> dict:
    operation_address = IMAGE_BASE + operation_offset
    spatial = vulnerability_type in {"stack_overflow", "out_of_bounds_write"}
    line_text = (
        f"*(undefined8 *)(local_20 + offset) = {hex(operation_address + 5)};"
        if successor_literal
        else "value = local_20;"
    )
    return {
        "candidate_id": candidate_id,
        "backend": "memory_access",
        "vulnerability_type": vulnerability_type,
        "mechanism": "out_of_bounds_write" if spatial else "",
        "status": "needs_refinement",
        "target": {"binary": "demo", "component": "demo"},
        "location": {
            "address": hex(IMAGE_BASE + 0x80),
            "function_name": "target",
            "line_number": 10 + operation_offset,
            "line_text": line_text,
            "relative_path": "target.c",
        },
        "source": {
            "kind": "unknown" if spatial else "definedness",
            "expression": "" if spatial else "local_20",
        },
        "sink": {
            "kind": "pointer_store" if spatial else "load",
            "name": "pointer_store" if spatial else "local_read",
            "operation_address": "" if successor_literal else hex(operation_address),
            "target_buffer": "local_20" if spatial else "",
        },
        "operation": {},
        "affected_object": {
            "identity": "stack:local_20",
            "kind": "stack",
            "label": "local_20",
            "capacity_bytes": 8,
        },
        "type_facts": {},
        "proof_obligations": [],
        "blockers": ["proof_required"],
        "validation_artifacts": [],
        "replay_artifacts": [],
        "report_artifacts": [],
        "metadata": {},
    }


def _manifest(states: list[dict]) -> dict:
    stores = []
    loads = []
    for state in states:
        operation_text = str(state["sink"].get("operation_address") or "")
        offset = int(operation_text, 16) - IMAGE_BASE if operation_text else 0
        if not operation_text:
            literal = int(state["location"]["line_text"].split("=")[-1].strip(" ;"), 16)
            offset = literal - IMAGE_BASE - 5
        row = {
            "operation_address": hex(IMAGE_BASE + offset),
            "pcode": "STORE" if state["vulnerability_type"] != "uninitialized_memory_use" else "LOAD",
        }
        if row["pcode"] == "STORE":
            row.update({"write_width": 8, "address_vars": ["local_20"]})
            stores.append(row)
        else:
            row.update({"read_width": 8, "address_vars": ["local_20"]})
            loads.append(row)
    return {
        "binary": "demo",
        "image_base": IMAGE_BASE,
        "processor": "x86",
        "pointer_size_bytes": 8,
        "functions": [
            {
                "name": "target",
                "address": hex(IMAGE_BASE + 0x80),
                "pcode_stores": stores,
                "pcode_loads": loads,
                "pcode_calls": [],
                "pcode_operations": [],
                "c_line_addresses": [],
                "basic_blocks": [],
            }
        ],
    }


def _prepare(
    tmp_path: Path,
    states: list[dict],
    binary: bytes,
    *,
    manifest_payload: dict | None = None,
) -> Path:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    states_path = inputs / "candidate_states.json"
    states_path.write_text(json.dumps({"schema_version": 2, "candidate_states": states}))
    binary_path = inputs / "demo"
    binary_path.write_bytes(binary)
    manifest_path = inputs / "manifest_normalized.json"
    manifest_path.write_text(json.dumps(manifest_payload or _manifest(states)))
    audit_path = inputs / "audit_summary.json"
    audit_path.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "name": "demo",
                        "binary_sha256": sha256_file(binary_path),
                        "source_repository": "https://example.invalid/demo.git",
                        "source_commit": "a" * 40,
                        "final": {
                            "candidate_count": len(states),
                            "candidate_states_sha256": sha256_file(states_path),
                        },
                    }
                ]
            }
        )
    )
    root = tmp_path / "campaign"
    prepare_campaign(
        root,
        audit_summary_path=audit_path,
        candidate_state_paths={"demo": states_path},
        binary_paths={"demo": binary_path},
        export_manifest_paths={"demo": manifest_path},
    )
    return root


def test_autoprove_checks_admits_and_finalizes_x86_certificate(tmp_path: Path) -> None:
    root = _prepare(tmp_path, [_state("candidate-1")], _elf_with_calls(0x100))

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert result.residual_candidates == 0
    assert result.complete_units == 1
    assert result.admitted_units == 1
    assert check_all_certificates(root) == {
        "checked_certificate_count": 1,
        "residual_candidate_count": 0,
        "partition_candidate_count": 1,
        "counts_by_rule": {"x86_call_return_slot_v1": 1},
    }
    finalized = finalize_campaign(root)
    ledger = json.loads(finalized.ledger_path.read_text())
    assert ledger["decisions"][0]["candidate_id"] == "candidate-1"
    assert ledger["decisions"][0]["decision"] == "not_bug"
    assert ledger["decisions"][0]["basis"] == "verified_modeling_error"


def test_certificate_checker_rejects_tampered_proof(tmp_path: Path) -> None:
    root = _prepare(tmp_path, [_state("candidate-1")], _elf_with_calls(0x100))
    run_autoprove(root)
    summary = json.loads((root / "autoprove" / "summary.json").read_text())
    path = root / summary["certificates"][0]["path"]
    certificate = json.loads(path.read_text())
    certificate["proof"]["instruction"]["successor_address"] = "0xDEADBEEF"
    path.write_text(json.dumps(certificate))

    with pytest.raises(CertificateError, match="proof payload"):
        check_certificate(root, path)


def test_check_all_rejects_candidate_omitted_from_partition(tmp_path: Path) -> None:
    root = _prepare(tmp_path, [_state("candidate-1")], _elf_with_calls(0x100))
    run_autoprove(root)
    summary_path = root / "autoprove" / "summary.json"
    summary = json.loads(summary_path.read_text())
    summary["certificates"] = []
    summary["proven_candidate_count"] = 0
    summary["counts_by_rule"] = {}
    summary_path.write_text(json.dumps(summary))

    with pytest.raises(CertificateError, match="partition mismatch"):
        check_all_certificates(root)


def test_check_all_rejects_summary_certificate_hash_tampering(tmp_path: Path) -> None:
    root = _prepare(tmp_path, [_state("candidate-1")], _elf_with_calls(0x100))
    run_autoprove(root)
    summary_path = root / "autoprove" / "summary.json"
    summary = json.loads(summary_path.read_text())
    summary["certificates"][0]["sha256"] = "0" * 64
    summary_path.write_text(json.dumps(summary))

    with pytest.raises(CertificateError, match="certificate hash changed"):
        check_all_certificates(root)


def test_unsupported_candidate_remains_residual(tmp_path: Path) -> None:
    state = _state(
        "candidate-1",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 0
    assert result.residual_candidates == 1
    assert result.complete_units == 0
    assert result.admitted_units == 0
    residual = json.loads(result.residual_queue_path.read_text())
    assert residual["residual_candidates"][0]["candidate_id"] == "candidate-1"
    assert not (root / "reviews").exists()


def test_generic_x86_call_store_does_not_require_decompiler_literal(tmp_path: Path) -> None:
    state = _state("candidate-1", operation_offset=0x120, successor_literal=False)
    root = _prepare(tmp_path, [state], _elf_with_calls(0x120))

    result = run_autoprove(root)

    assert result.proven_candidates == 1
    summary = json.loads(result.summary_path.read_text())
    assert summary["counts_by_rule"] == {"x86_call_pcode_store_v1": 1}


def test_ghidra_indirect_call_effect_is_not_a_runtime_read(tmp_path: Path) -> None:
    state = _state(
        "candidate-1",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    manifest = _manifest([state])
    function = manifest["functions"][0]
    function["pcode_loads"] = []
    function["pcode_operations"] = [
        {
            "operation_address": hex(IMAGE_BASE + 0x120),
            "pcode": "CALL",
            "inputs": [
                {
                    "repr": "(ram, 0x80, 8)",
                    "size_bytes": 8,
                    "address": "0x80",
                    "address_space": "ram",
                }
            ],
            "output": {},
        },
        {
            "operation_address": hex(IMAGE_BASE + 0x120),
            "pcode": "INDIRECT",
            "inputs": [
                {
                    "repr": "(stack, 0xffffffffffffffe0, 8)",
                    "size_bytes": 8,
                    "address": "0x-20",
                    "address_space": "stack",
                    "stack_offset": -32,
                    "var_name": "local_20",
                },
                {
                    "repr": "(const, 0x1, 4)",
                    "size_bytes": 4,
                    "address": "0x1",
                    "address_space": "const",
                    "constant": 1,
                },
            ],
            "output": {
                "repr": "(stack, 0xffffffffffffffe0, 8)",
                "size_bytes": 8,
                "address": "0x-20",
                "address_space": "stack",
                "stack_offset": -32,
                "var_name": "local_20",
            },
        },
    ]
    root = _prepare(
        tmp_path,
        [state],
        _elf_with_calls(0x120),
        manifest_payload=manifest,
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert result.admitted_units == 1
    summary = json.loads(result.summary_path.read_text())
    assert summary["counts_by_rule"] == {"ghidra_indirect_call_effect_v1": 1}
    assert finalize_campaign(root).ledger_path.is_file()


def test_import_pointer_cast_feeding_callind_is_not_a_local_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "candidate-import-cast",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    manifest = _manifest([state])
    function = manifest["functions"][0]
    function["pcode_loads"] = []
    cast_output = {
        "repr": "(unique, 0x9000, 8)",
        "size_bytes": 8,
        "address": "0x9000",
        "address_space": "unique",
        "var_name": "UNNAMED",
    }
    function["pcode_operations"] = [
        {
            "operation_address": hex(IMAGE_BASE + 0x120),
            "pcode": "CALLIND",
            "inputs": [
                cast_output,
                {
                    "repr": "(register, 0x7, 8)",
                    "size_bytes": 8,
                    "address": "0x7",
                    "address_space": "register",
                },
            ],
            "output": {},
        },
        {
            "operation_address": hex(IMAGE_BASE + 0x120),
            "pcode": "CAST",
            "inputs": [
                {
                    "repr": "(ram, 0x100180, 8)",
                    "size_bytes": 8,
                    "address": "0x100180",
                    "address_space": "ram",
                    "var_name": "PTR_demo_00100180",
                }
            ],
            "output": cast_output,
        },
    ]
    root = _prepare(
        tmp_path,
        [state],
        _elf_with_indirect_call(0x120),
        manifest_payload=manifest,
    )
    monkeypatch.setattr(
        checker_module,
        "_dynamic_function_relocation",
        lambda _context, _address: {
            "offset": "0x180",
            "type": "R_X86_64_GLOB_DAT",
            "symbol": "demo",
            "addend": 0,
        },
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    summary = json.loads(result.summary_path.read_text())
    assert summary["counts_by_rule"] == {"ghidra_import_pointer_cast_v1": 1}
    assert finalize_campaign(root).ledger_path.is_file()


def test_partial_unit_is_not_proposed_or_admitted(tmp_path: Path) -> None:
    states = [
        _state("candidate-proven", operation_offset=0x100),
        _state("candidate-residual", operation_offset=0x120, successor_literal=False),
    ]
    root = _prepare(tmp_path, states, _elf_with_calls(0x100))

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert result.residual_candidates == 1
    assert result.complete_units == 0
    assert result.admitted_units == 0
    summary = json.loads(result.summary_path.read_text())
    assert summary["partial_unit_count"] == 1
    assert summary["review_proposals"] == []
    assert not (root / "reviews").exists()


def test_typed_libubox_list_store_is_certified_from_exact_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state("candidate-list", operation_offset=0x120, successor_literal=False)
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_path = _add_fake_reference_mapping(root, monkeypatch)
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "_list_add", "path": str(source_path), "line": 107},
            {"function": "caller", "path": "package/caller.c", "line": 20},
        ],
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 1
    assert result.residual_candidates == 0
    summary = json.loads(result.summary_path.read_text())
    assert summary["counts_by_rule"] == {"libubox_typed_list_store_v1": 1}
    assert check_all_certificates(root)["checked_certificate_count"] == 1


def test_vla_capacity_source_proof_is_admitted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _state("candidate-vla", operation_offset=0x120, successor_literal=False)
    manifest = _manifest([state])
    manifest["functions"][0]["pcode_stores"][0]["write_width"] = 1
    root = _prepare(
        tmp_path,
        [state],
        _elf_with_calls(),
        manifest_payload=manifest,
    )
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    source_path = source_root / "progress.c"
    lines = [""] * 180
    lines[173] = "    barlength = get_tty2_width() - 49;"
    lines[174] = "    if (barlength > 0) {"
    lines[176] = "        char buf[barlength + 1];"
    lines[178] = "        memset(buf, ' ', barlength);"
    lines[179] = "        buf[barlength] = '\\0';"
    source_path.write_text("\n".join(lines) + "\n")
    sdk_hash = _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        adjudication_module,
        "OPENWRT_24_10_4_X86_64_SDK_SHA256",
        sdk_hash,
    )
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "progress_update", "path": "demo/progress.c", "line": 180}
        ],
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert result.admitted_units == 1
    summary = json.loads(result.summary_path.read_text())
    assert summary["counts_by_rule"] == {"c_vla_index_capacity_v1": 1}
    review = next((root / "reviews").glob("*.json"))
    decision = json.loads(review.read_text())["decisions"][0]
    assert decision["basis"] == "source_proves_safety"
    assert decision["source_binding"]["source_sha256"] == sha256_file(source_path)
    assert finalize_campaign(root).ledger_path.is_file()


def test_blobmsg_table_initialization_contract_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "candidate-table",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    source_path = source_root / "target.c"
    source_path.write_text(
        "static void\n"
        "target(void)\n"
        "{\n"
        "    struct blob_attr *tb[MAX_ATTR];\n"
        "    blobmsg_parse(policy, MAX_ATTR, tb, data, len);\n"
        "    if (tb[ATTR_NAME])\n"
        "        use(tb[ATTR_NAME]);\n"
        "}\n"
    )
    sdk_hash = _add_source_reference_mapping(root, source_root)
    package_file = root / "sdk" / "libubox.Makefile"
    source_archive = root / "sdk" / "libubox.tar.zst"
    package_file.write_text("pinned libubox package\n")
    source_archive.write_bytes(b"pinned libubox source")
    dependency = {
        "package_commit": "b" * 40,
        "package_makefile": {
            "path": str(package_file.relative_to(root)),
            "sha256": sha256_file(package_file),
            "kind": "source_review",
        },
        "source_archive": {
            "path": str(source_archive.relative_to(root)),
            "sha256": sha256_file(source_archive),
            "kind": "source_review",
        },
        "archive_member": "libubox/blobmsg.c",
        "member_sha256": "c" * 64,
        "function": "blobmsg_parse",
        "initialization_statement": "memset(tb, 0, policy_len * sizeof(*tb));",
        "sdk_sha256": sdk_hash,
    }
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        adjudication_module,
        "OPENWRT_24_10_4_X86_64_SDK_SHA256",
        sdk_hash,
    )
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/target.c", "line": 6}
        ],
    )
    monkeypatch.setattr(
        checker_module,
        "_libubox_blobmsg_contract",
        lambda _context, _mapping, **_kwargs: dependency,
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert result.admitted_units == 1
    summary = json.loads(result.summary_path.read_text())
    assert summary["counts_by_rule"] == {
        "libubox_blobmsg_parse_initializes_table_v1": 1
    }
    decision = json.loads(next((root / "reviews").glob("*.json")).read_text())["decisions"][0]
    assert decision["obligations"]["all_path_initialization"]["status"] == "satisfied"
    assert finalize_campaign(root).ledger_path.is_file()


def test_immediate_unconditional_assignment_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "candidate-assignment",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    source_path = source_root / "target.c"
    source_path.write_text(
        "static void\n"
        "target(void)\n"
        "{\n"
        "    void *value;\n"
        "    value = lookup();\n"
        "    if (!value)\n"
        "        return;\n"
        "}\n"
    )
    sdk_hash = _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        adjudication_module,
        "OPENWRT_24_10_4_X86_64_SDK_SHA256",
        sdk_hash,
    )
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/target.c", "line": 6}
        ],
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    summary = json.loads(result.summary_path.read_text())
    assert summary["counts_by_rule"] == {
        "c_immediate_unconditional_assignment_v1": 1
    }
    assert finalize_campaign(root).ledger_path.is_file()


def test_immediate_assignment_rejects_unbraced_conditional_definition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "candidate-conditional",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    source_path = source_root / "target.c"
    source_path.write_text(
        "static void\n"
        "target(void)\n"
        "{\n"
        "    void *value;\n"
        "    if (enabled)\n"
        "    value = lookup();\n"
        "    if (!value)\n"
        "        return;\n"
        "}\n"
    )
    sdk_hash = _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        adjudication_module,
        "OPENWRT_24_10_4_X86_64_SDK_SHA256",
        sdk_hash,
    )
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/target.c", "line": 7}
        ],
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 0
    assert result.residual_candidates == 1


def test_checked_calloc_a_outputs_are_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "candidate-calloc-output",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    source_path = source_root / "target.c"
    source_path.write_text(
        "static void\n"
        "target(const char *input)\n"
        "{\n"
        "    struct item *item;\n"
        "    char *output;\n"
        "    item = calloc_a(sizeof(*item),\n"
        "                    &output, strlen(input) + 1);\n"
        "    if (!item)\n"
        "        return;\n"
        "    item->value = strcpy(output, input);\n"
        "}\n"
    )
    sdk_hash = _add_source_reference_mapping(root, source_root)
    package_file = root / "sdk" / "libubox.Makefile"
    source_archive = root / "sdk" / "libubox.tar.zst"
    package_file.write_text("pinned libubox package\n")
    source_archive.write_bytes(b"pinned libubox source")
    dependency = {
        "package_commit": "b" * 40,
        "package_makefile": {
            "path": str(package_file.relative_to(root)),
            "sha256": sha256_file(package_file),
            "kind": "source_review",
        },
        "source_archive": {
            "path": str(source_archive.relative_to(root)),
            "sha256": sha256_file(source_archive),
            "kind": "source_review",
        },
        "archive_member": "libubox/utils.c",
        "member_sha256": "c" * 64,
        "function": "__calloc_a",
        "allocation_statement": "ptr = calloc(1, alloc_len);",
        "failure_result": "NULL before auxiliary output assignment",
        "output_statement": "*cur_addr = &ptr[alloc_len];",
        "success_result": "ret after every non-null vararg output",
        "enumeration_macro": "foreach_arg enumerates non-null outputs",
        "sdk_sha256": sdk_hash,
    }
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        adjudication_module,
        "OPENWRT_24_10_4_X86_64_SDK_SHA256",
        sdk_hash,
    )
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/target.c", "line": 10}
        ],
    )
    monkeypatch.setattr(
        checker_module,
        "_libubox_calloc_contract",
        lambda _context, _mapping: dependency,
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    summary = json.loads(result.summary_path.read_text())
    assert summary["counts_by_rule"] == {"libubox_checked_calloc_a_outputs_v1": 1}
    decision = json.loads(next((root / "reviews").glob("*.json")).read_text())["decisions"][0]
    assert decision["obligations"]["all_path_initialization"]["status"] == "satisfied"
    assert finalize_campaign(root).ledger_path.is_file()


def test_libubox_foreach_macro_initializes_loop_locals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "candidate-foreach",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    manifest = _manifest([state])
    function = manifest["functions"][0]
    function["pcode_loads"] = []
    function["pcode_operations"] = [
        {
            "operation_address": hex(IMAGE_BASE + 0x120),
            "pcode": "INT_SUB",
            "inputs": [],
            "output": {},
        }
    ]
    root = _prepare(tmp_path, [state], _elf_with_calls(), manifest_payload=manifest)
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    source_path = source_root / "target.c"
    source_path.write_text(
        "static void\n"
        "target(struct blob_attr *data)\n"
        "{\n"
        "    struct blob_attr *cur;\n"
        "    int rem;\n"
        "    blobmsg_for_each_attr(cur, data, rem) {\n"
        "        use(cur);\n"
        "    }\n"
        "}\n"
    )
    sdk_hash = _add_source_reference_mapping(root, source_root)
    package_file = root / "sdk" / "libubox.Makefile"
    source_archive = root / "sdk" / "libubox.tar.zst"
    package_file.write_text("pinned libubox package\n")
    source_archive.write_bytes(b"pinned libubox source")
    dependency = {
        "package_commit": "b" * 40,
        "package_makefile": {
            "path": str(package_file.relative_to(root)),
            "sha256": sha256_file(package_file),
            "kind": "source_review",
        },
        "source_archive": {
            "path": str(source_archive.relative_to(root)),
            "sha256": sha256_file(source_archive),
            "kind": "source_review",
        },
        "archive_member": "libubox/blobmsg.h",
        "member_sha256": "c" * 64,
        "macro": "blobmsg_for_each_attr",
        "macro_definition": "for (rem = attr ? blobmsg_data_len(attr) : 0, pos = attr; ...)",
        "sdk_sha256": sdk_hash,
    }
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        adjudication_module,
        "OPENWRT_24_10_4_X86_64_SDK_SHA256",
        sdk_hash,
    )
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/target.c", "line": 6}
        ],
    )
    monkeypatch.setattr(
        checker_module,
        "_libubox_foreach_contract",
        lambda _context, _mapping, **_kwargs: dependency,
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "libubox_foreach_macro_initializes_v1": 1
    }
    assert finalize_campaign(root).ledger_path.is_file()


def test_checked_stat_output_initialization_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "candidate-stat",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    source_path = source_root / "target.c"
    source_path.write_text(
        "static void\n"
        "target(const char *path)\n"
        "{\n"
        "    struct stat st;\n"
        "    int result = stat(path, &st);\n"
        "    if (result)\n"
        "        return;\n"
        "    use(st.st_size);\n"
        "}\n"
    )
    sdk_hash = _add_source_reference_mapping(root, source_root)
    sdk_archive = root / "sdk" / "fake-sdk.tar.zst"
    api_header = root / "sdk" / "stat.h"
    api_header.write_text("int stat(const char *, struct stat *);\n")
    dependency = {
        "sdk_archive": {
            "path": str(sdk_archive.relative_to(root)),
            "sha256": sha256_file(sdk_archive),
            "kind": "source_review",
        },
        "api_header": {
            "path": str(api_header.relative_to(root)),
            "sha256": sha256_file(api_header),
            "kind": "source_review",
        },
        "api": "stat",
        "declaration": "int stat(const char *, struct stat *);",
        "success_contract": "return value 0 initializes the caller-provided output object",
        "sdk_sha256": sdk_hash,
    }
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        adjudication_module,
        "OPENWRT_24_10_4_X86_64_SDK_SHA256",
        sdk_hash,
    )
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/target.c", "line": 8}
        ],
    )
    monkeypatch.setattr(
        checker_module,
        "_sdk_api_contract",
        lambda _context, _mapping, **_kwargs: dependency,
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "c_checked_api_output_initialization_v1": 1
    }
    assert finalize_campaign(root).ledger_path.is_file()


def test_dominating_nonnull_guard_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "candidate-null",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="null_pointer_dereference",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    source_path = source_root / "target.c"
    source_path.write_text(
        "static void\n"
        "target(char *data)\n"
        "{\n"
        "    char *newline = strchr(data, '\\n');\n"
        "    if (!newline)\n"
        "        return;\n"
        "    *newline = 0;\n"
        "}\n"
    )
    sdk_hash = _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        adjudication_module,
        "OPENWRT_24_10_4_X86_64_SDK_SHA256",
        sdk_hash,
    )
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/target.c", "line": 7}
        ],
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "c_dominating_nonnull_guard_v1": 1
    }
    decision = json.loads(next((root / "reviews").glob("*.json")).read_text())["decisions"][0]
    assert decision["obligations"]["dominating_non_null"]["status"] == "satisfied"
    assert finalize_campaign(root).ledger_path.is_file()


def test_fixed_path_effect_uses_intentional_boundary_basis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "candidate-fixed-path",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="path_traversal",
    )
    manifest = _manifest([state])
    manifest["functions"][0]["pcode_stores"][0]["pcode"] = "CALLIND"
    root = _prepare(tmp_path, [state], _elf_with_calls(), manifest_payload=manifest)
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    source_path = source_root / "target.c"
    source_path.write_text(
        "static void\n"
        "target(void)\n"
        "{\n"
        "    int fd = open(\"/dev/null\", O_RDONLY);\n"
        "}\n"
    )
    sdk_hash = _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        adjudication_module,
        "OPENWRT_24_10_4_X86_64_SDK_SHA256",
        sdk_hash,
    )
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/target.c", "line": 4}
        ],
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    review = json.loads(next((root / "reviews").glob("*.json")).read_text())
    assert review["decisions"][0]["basis"] == "intentional_no_boundary"
    assert review["decisions"][0]["obligations"]["no_security_boundary"]["status"] == "satisfied"
    assert finalize_campaign(root).ledger_path.is_file()


def test_source_proven_bug_stays_separate_from_report_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "renamed-boundary-store",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="out_of_bounds_write",
    )
    manifest = _manifest([state])
    manifest["functions"][0]["pcode_stores"][0]["write_width"] = 2
    manifest["entry_surfaces"] = [
        {
            "kind": "registered_callback",
            "function_address": state["location"]["address"],
            "name": "shifted_worker",
        }
    ]
    root = _prepare(
        tmp_path,
        [state],
        _elf_with_calls(),
        manifest_payload=manifest,
    )
    source_root = root / "sources" / "shifted"
    source_root.mkdir(parents=True)
    source_path = source_root / "worker.c"
    source_path.write_text(
        "#include <stdlib.h>\n"
        "static void shifted_worker(const char *request)\n"
        "{\n"
        "    static char storage[16];\n"
        "    char *cursor;\n"
        "    if (!realpath(request, storage))\n"
        "        return;\n"
        "    cursor = storage + strlen(storage);\n"
        "    if (cursor[-1] != '/') {\n"
        "        cursor[0] = '/';\n"
        "        cursor[1] = 0;\n"
        "        cursor++;\n"
        "    }\n"
        "}\n"
    )
    sdk_hash = _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        adjudication_module,
        "OPENWRT_24_10_4_X86_64_SDK_SHA256",
        sdk_hash,
    )
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "shifted_worker", "path": "shifted/worker.c", "line": 10}
        ],
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    review = json.loads(next((root / "reviews").glob("*.json")).read_text())
    assert review["decisions"][0]["decision"] == "bug"
    assert review["decisions"][0]["basis"] == "exact_source_feasible_violation"
    finalized = finalize_campaign(root)
    assert json.loads(finalized.reports_path.read_text())["vulnerabilities"] == []

    summary = json.loads(result.summary_path.read_text())
    certificate_path = root / summary["certificates"][0]["path"]
    certificate = json.loads(certificate_path.read_text())
    certificate["proof"]["rule_claim"] = "provider prose replaced the checked proof"
    certificate_path.write_text(json.dumps(certificate))
    with pytest.raises(CertificateError, match="proof differs"):
        check_certificate(root, certificate_path)


def _add_fake_reference_mapping(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    sdk_archive = root / "sdk" / "fake-sdk.tar.zst"
    sdk_archive.parent.mkdir(parents=True)
    sdk_archive.write_bytes(b"pinned test SDK")
    sdk_hash = sha256_file(sdk_archive)
    monkeypatch.setattr(checker_module, "OPENWRT_24_10_4_X86_64_SDK_SHA256", sdk_hash)

    source_path = root / "sdk" / "include" / "libubox" / "list.h"
    source_path.parent.mkdir(parents=True)
    lines = [""] * 110
    lines[0:4] = [
        "struct list_head {",
        "    struct list_head *next;",
        "    struct list_head *prev;",
        "};",
    ]
    lines[106] = "next->prev = _new;"
    source_path.write_text("\n".join(lines) + "\n")

    binary_path = root / "frozen" / "binaries" / "demo"
    reference_path = root / "reference-builds" / "demo" / "symbol-rich" / "demo"
    reference_path.parent.mkdir(parents=True)
    reference_path.write_bytes(binary_path.read_bytes())
    fingerprint = executable_segment_fingerprint(binary_path)
    mapping = {
        "schema_version": 1,
        "binary": "demo",
        "sdk": {"path": str(sdk_archive.relative_to(root)), "sha256": sdk_hash},
        "source": {"path": "sdk/include", "commit": "a" * 40},
        "frozen_binary": {
            "path": str(binary_path.relative_to(root)),
            "sha256": sha256_file(binary_path),
            "executable_segments": fingerprint,
        },
        "reference_binary": {
            "path": str(reference_path.relative_to(root)),
            "sha256": sha256_file(reference_path),
            "executable_segments": fingerprint,
        },
        "code_bytes_match": True,
        "direct_source_mapping_allowed": True,
    }
    mapping_path = root / "frozen" / "reference_build_mappings" / "demo.json"
    mapping_path.parent.mkdir(parents=True)
    mapping_path.write_text(json.dumps(mapping))
    manifest_path = root / "frozen_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["reference_build_mappings"] = [
        {
            "binary": "demo",
            "path": str(mapping_path.relative_to(root)),
            "sha256": sha256_file(mapping_path),
        }
    ]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return source_path


def _add_source_reference_mapping(root: Path, source_root: Path) -> str:
    sdk_path = root / "sdk" / "fake-sdk.tar.zst"
    sdk_path.parent.mkdir(parents=True, exist_ok=True)
    sdk_path.write_bytes(b"source proof test SDK")
    sdk_hash = sha256_file(sdk_path)
    binary_path = root / "frozen" / "binaries" / "demo"
    reference_path = root / "reference-builds" / "demo" / "symbol-rich" / "demo"
    reference_path.parent.mkdir(parents=True, exist_ok=True)
    reference_path.write_bytes(binary_path.read_bytes())
    fingerprint = executable_segment_fingerprint(binary_path)
    mapping = {
        "schema_version": 1,
        "binary": "demo",
        "sdk": {"path": str(sdk_path.relative_to(root)), "sha256": sdk_hash},
        "source": {"path": str(source_root.relative_to(root)), "commit": "a" * 40},
        "frozen_binary": {
            "path": str(binary_path.relative_to(root)),
            "sha256": sha256_file(binary_path),
            "executable_segments": fingerprint,
        },
        "reference_binary": {
            "path": str(reference_path.relative_to(root)),
            "sha256": sha256_file(reference_path),
            "executable_segments": fingerprint,
        },
        "code_bytes_match": True,
        "direct_source_mapping_allowed": True,
    }
    mapping_path = root / "frozen" / "reference_build_mappings" / "demo.json"
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    mapping_path.write_text(json.dumps(mapping))
    manifest_path = root / "frozen_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["reference_build_mappings"] = [
        {
            "binary": "demo",
            "path": str(mapping_path.relative_to(root)),
            "sha256": sha256_file(mapping_path),
        }
    ]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return sdk_hash
