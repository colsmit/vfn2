import json
import subprocess
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
from binary_agent.adjudication_certificates import (
    CampaignContext,
    CampaignContextIndex,
    CertificateError,
    check_certificate,
)
from binary_agent import adjudication_certificates as checker_module
from binary_agent import adjudication as adjudication_module


IMAGE_BASE = 0x100000


def test_normalized_function_fingerprint_masks_addresses_but_keeps_constants(
    tmp_path: Path,
) -> None:
    first = bytearray(_elf_with_calls())
    second = bytearray(_elf_with_calls())
    # mov rax,[rip+disp32]; cmp eax,7; ret.  Only the relocatable data
    # displacement differs between the two otherwise identical functions.
    first[0x100:0x10B] = b"\x48\x8b\x05\x20\x00\x00\x00\x83\xf8\x07\xc3"
    second[0x180:0x18B] = b"\x48\x8b\x05\x40\x00\x00\x00\x83\xf8\x07\xc3"
    first_path = tmp_path / "first"
    second_path = tmp_path / "second"
    first_path.write_bytes(first)
    second_path.write_bytes(second)

    first_fingerprint = checker_module._normalized_function_fingerprint(
        first_path, 0x100, 11
    )
    second_fingerprint = checker_module._normalized_function_fingerprint(
        second_path, 0x180, 11
    )

    assert first_fingerprint == second_fingerprint

    changed = bytearray(second)
    changed[0x189] = 8
    changed_path = tmp_path / "changed"
    changed_path.write_bytes(changed)
    changed_fingerprint = checker_module._normalized_function_fingerprint(
        changed_path, 0x180, 11
    )
    assert changed_fingerprint["normalized_function_sha256"] != first_fingerprint[
        "normalized_function_sha256"
    ]
    assert changed_fingerprint["constant_signature_sha256"] != first_fingerprint[
        "constant_signature_sha256"
    ]


def test_reference_operation_mapping_uses_unique_function_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen = bytearray(_elf_with_calls())
    reference = bytearray(_elf_with_calls())
    frozen[0x100:0x10B] = b"\x48\x8b\x05\x20\x00\x00\x00\x83\xf8\x07\xc3"
    reference[0x180:0x18B] = b"\x48\x8b\x05\x40\x00\x00\x00\x83\xf8\x07\xc3"
    frozen_path = tmp_path / "frozen"
    reference_path = tmp_path / "reference"
    frozen_path.write_bytes(frozen)
    reference_path.write_bytes(reference)
    reference_fingerprint = checker_module._normalized_function_fingerprint(
        reference_path, 0x180, 11
    )
    monkeypatch.setattr(
        checker_module,
        "_reference_function_index",
        lambda _context, _path: {
            11: [
                {
                    "address": 0x180,
                    "names": ["mapped_function"],
                    **reference_fingerprint,
                }
            ]
        },
    )
    operation = IMAGE_BASE + 0x107
    context = CampaignContext(
        root=tmp_path,
        manifest={},
        candidate={"candidate_id": "candidate", "binary": "demo"},
        state={},
        binding={"address": hex(operation)},
        input_row={"binary_sha256": sha256_file(frozen_path)},
        binary_path=frozen_path,
        export_manifest={
            "image_base": IMAGE_BASE,
            "functions": [
                {
                    "address": hex(IMAGE_BASE + 0x100),
                    "body_size_bytes": 11,
                    "basic_blocks": [
                        {
                            "start": hex(IMAGE_BASE + 0x100),
                            "end": hex(IMAGE_BASE + 0x10A),
                        }
                    ],
                }
            ],
        },
    )
    mapping = {
        "code_bytes_match": False,
        "frozen_binary": {
            "path": frozen_path.name,
            "sha256": sha256_file(frozen_path),
        },
        "reference_binary": {
            "path": reference_path.name,
            "sha256": sha256_file(reference_path),
        },
    }

    result = checker_module._reference_operation_mapping(context, mapping, operation)

    assert result["mapping_basis"] == "function_fingerprint"
    assert result["reference_vma"] == 0x187
    assert result["frozen_function_sha256"] == result["reference_function_sha256"]
    assert result["constants_match"] is True
    assert result["call_topology_match"] is True


def test_process_split_classifier_accepts_direct_fork_switch() -> None:
    lines = """int run(int fd) {
switch (fork()) {
case 0:
    close(fd);
    if (execv(path, argv))
        return 1;
default:
    close(fd);
    return 0;
}
}""".splitlines()

    result = checker_module._classify_process_split(lines, first_line=4, sink_line=8)

    assert result is not None
    assert result["kind"] == "fork_switch_child"
    assert result["exec_function"] == "execv"


def test_process_split_classifier_accepts_noreturn_child() -> None:
    lines = """static NORETURN void child_exit(void) {
    abort();
}
static int forkshell(void) {
    int pid = fork();
    if (pid == 0) {
        child_setup();
    }
    return pid;
}
void run(int fd) {
    if (forkshell() == 0) {
        close(fd);
        child_exit();
    }
    close(fd);
}""".splitlines()

    result = checker_module._classify_process_split(lines, first_line=13, sink_line=16)

    assert result is not None
    assert result["kind"] == "fork_if_child"
    assert result["terminal"]["noreturn_function"] == "child_exit"
    assert result["fork_wrapper"]["fork_line"] == 5


def test_process_split_classifier_accepts_noreturn_error_macro() -> None:
    lines = """static void die(const char *, ...) NORETURN;
#define fail(...) die(__VA_ARGS__)
void run(int fd, int error) {
    if (error) {
        close(fd);
        fail("error");
    }
    close(fd);
}""".splitlines()

    result = checker_module._classify_process_split(lines, first_line=5, sink_line=8)

    assert result is not None
    assert result["kind"] == "terminating_error_block"
    assert result["terminal"]["macro_line"] == 2


def test_process_split_classifier_rejects_returning_optional_block() -> None:
    lines = """void run(int fd, int child) {
    if (child) {
        close(fd);
        log_error();
    }
    close(fd);
}""".splitlines()

    assert checker_module._classify_process_split(
        lines, first_line=3, sink_line=6
    ) is None


def test_addr2line_falls_back_when_gnu_cannot_decode_lto_ranges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = tmp_path / "reference"
    reference.write_bytes(b"reference")
    calls: list[str] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command[0])
        if command[0] == "addr2line":
            return subprocess.CompletedProcess(command, 0, "inlined_function\n?:?\n", "")
        if command[0] == "llvm-addr2line":
            return subprocess.CompletedProcess(
                command,
                0,
                "inlined_function\npackage/source.c:42\ncaller\npackage/source.c:90\n",
                "",
            )
        raise AssertionError("elfutils fallback should not run after LLVM succeeds")

    monkeypatch.setattr(checker_module.subprocess, "run", fake_run)

    assert checker_module._addr2line_frames(reference, 0x401000) == [
        {"function": "inlined_function", "path": "package/source.c", "line": 42},
        {"function": "caller", "path": "package/source.c", "line": 90},
    ]
    assert calls == ["addr2line", "llvm-addr2line"]


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


def test_campaign_context_index_parses_shared_export_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    states = [
        _state("candidate-1", operation_offset=0x100),
        _state("candidate-2", operation_offset=0x120),
    ]
    root = _prepare(tmp_path, states, _elf_with_calls(0x100, 0x120))
    manifest = json.loads((root / "frozen_manifest.json").read_text())
    export_path = (root / manifest["inputs"][0]["export_manifest_path"]).resolve()
    original_load = checker_module._load_json
    export_loads = 0

    def counting_load(path: Path) -> dict:
        nonlocal export_loads
        if Path(path).resolve() == export_path:
            export_loads += 1
        return original_load(path)

    monkeypatch.setattr(checker_module, "_load_json", counting_load)
    index = CampaignContextIndex.build(root)
    first = index.load("candidate-1")
    second = index.load("candidate-2")

    assert export_loads == 1
    assert first.state["candidate_id"] == "candidate-1"
    assert second.state["candidate_id"] == "candidate-2"
    assert first.binding["candidate_id"] == "candidate-1"
    assert second.binding["candidate_id"] == "candidate-2"


def test_campaign_context_index_rejects_tampered_export_at_construction(
    tmp_path: Path,
) -> None:
    root = _prepare(tmp_path, [_state("candidate-1")], _elf_with_calls(0x100))
    manifest = json.loads((root / "frozen_manifest.json").read_text())
    export_path = root / manifest["inputs"][0]["export_manifest_path"]
    export_path.write_text(export_path.read_text() + "\n")

    with pytest.raises(CertificateError, match="frozen export manifest changed"):
        CampaignContextIndex.build(root)


def test_independent_certificate_check_revalidates_export_after_batch(
    tmp_path: Path,
) -> None:
    root = _prepare(tmp_path, [_state("candidate-1")], _elf_with_calls(0x100))
    result = run_autoprove(root)
    summary = json.loads(result.summary_path.read_text())
    certificate_path = root / summary["certificates"][0]["path"]
    manifest = json.loads((root / "frozen_manifest.json").read_text())
    export_path = root / manifest["inputs"][0]["export_manifest_path"]
    export_path.write_text(export_path.read_text() + "\n")

    with pytest.raises(CertificateError, match="frozen export manifest changed"):
        check_certificate(root, certificate_path)


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
    certificate = json.loads(
        next((root / "autoprove" / "runs").glob("*/certificates/*.json")).read_text()
    )
    assert certificate["proof"]["operation_mapping"] == {
        "mapping_basis": "exact_code_bytes",
        "frozen_vma": 0x120,
        "reference_vma": 0x120,
    }
    assert check_all_certificates(root)["checked_certificate_count"] == 1


def test_candidate_context_reuses_validated_mapping_and_source_frame(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state("candidate-source-cache", operation_offset=0x120, successor_literal=False)
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_path = _add_fake_reference_mapping(root, monkeypatch)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    addr2line_calls = 0

    def counted_frames(_reference: Path, _address: int) -> list[dict]:
        nonlocal addr2line_calls
        addr2line_calls += 1
        return [{"function": "_list_add", "path": str(source_path), "line": 107}]

    monkeypatch.setattr(checker_module, "_addr2line_frames", counted_frames)
    context = CampaignContextIndex.build(root).load(state["candidate_id"])

    first = checker_module._exact_source_context(context)
    second = checker_module._exact_source_context(context)

    assert first["source_path"] == source_path.resolve()
    assert second["source_path"] == source_path.resolve()
    assert addr2line_calls == 1
    assert context.cache["reference_mapping"]["binary"] == "demo"


def test_source_rules_leave_unresolved_exact_operation_residual(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "candidate-unresolved-source",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())
    _add_fake_reference_mapping(root, monkeypatch)
    binding_path = root / "bindings" / f"{state['candidate_id']}.json"
    binding = json.loads(binding_path.read_text())
    binding.update(
        {
            "status": "unresolved",
            "address": "",
            "pcode": "",
            "reason": "ambiguous_pcode_operations_at_candidate_line",
        }
    )
    binding_path.write_text(json.dumps(binding))

    result = run_autoprove(root)

    assert result.proven_candidates == 0
    assert result.residual_candidates == 1
    residual = json.loads(result.residual_queue_path.read_text())
    attempts = residual["residual_candidates"][0]["attempts"]
    assert any(
        item["reason"] == "candidate has no resolved exact binary operation"
        for item in attempts
    )


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


def test_blobmsg_parameter_table_is_proven_from_sole_caller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "candidate-parameter-table",
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
        "target(struct object *obj, struct blob_attr **tb)\n"
        "{\n"
        "    struct blob_attr *cur;\n"
        "#define cfg_item(_attr) \\\n"
        "    do { \\\n"
        "        if ((cur = tb[_attr]) != NULL) use(cur); \\\n"
        "    } while (0)\n"
        "    cfg_item(ATTR_NAME);\n"
        "}\n"
        "static void caller(struct object *obj, void *data, int len)\n"
        "{\n"
        "    struct blob_attr *parsed[MAX_ATTR];\n"
        "    blobmsg_parse(policy, MAX_ATTR, parsed, data, len);\n"
        "    target(obj, parsed);\n"
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
            {"function": "target", "path": "demo/target.c", "line": 9}
        ],
    )
    monkeypatch.setattr(
        checker_module,
        "_libubox_blobmsg_contract",
        lambda _context, _mapping, **_kwargs: dependency,
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    certificate = json.loads(
        next((root / "autoprove" / "runs").glob("*/certificates/*.json")).read_text()
    )
    assert certificate["proof"]["caller_contract"] == {
        "caller_count": 1,
        "table": "parsed",
        "element_count": "MAX_ATTR",
        "declaration_line": 13,
        "parser_line": 14,
        "call_line": 15,
        "parser_count_expression": "MAX_ATTR",
    }
    assert certificate["proof"]["source_excerpt"]["macro_definition_line"] == 5


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


def test_absolute_dwarf_path_relocates_inside_copied_campaign(tmp_path: Path) -> None:
    root = tmp_path / "copied-campaign"
    relocated = root / "sdk" / "tree" / "include" / "list.h"
    relocated.parent.mkdir(parents=True)
    relocated.write_text("struct list_head { void *next; void *prev; };\n")

    resolved = checker_module._resolve_campaign_frame_file(
        root,
        "/old/research/campaign/sdk/tree/include/list.h",
        "test DWARF source",
    )

    assert resolved == relocated.resolve()


def test_absolute_dwarf_source_relocates_by_suffix_inside_pinned_checkout(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "sources" / "component"
    relocated = source_root / "src" / "worker.c"
    relocated.parent.mkdir(parents=True)
    relocated.write_text("int worker(void) { return 0; }\n")

    resolved = checker_module._resolve_frame_source(
        source_root,
        "/old/sdk/build/component/src/worker.c",
    )

    assert resolved == relocated.resolve()


def test_cross_file_source_scan_accepts_non_utf8_c_file(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "legacy.c").write_bytes(b"/* author: \xf6 */\nint legacy(void);\n")
    definition = source_root / "table.c"
    definition.write_text("static int values[4];\n")

    result = checker_module._unique_source_array_definition(
        {"source_root": source_root},
        "values",
    )

    assert result["path"] == str(definition.relative_to(source_root.parents[1]))
    assert result["capacity"] == "4"


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
        "mismatch_policy": "exact_code_bytes",
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
        "mismatch_policy": "exact_code_bytes",
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
