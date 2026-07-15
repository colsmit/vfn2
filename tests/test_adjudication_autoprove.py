import json
import shutil
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


def test_source_function_prefix_resolves_compiler_clone_suffix() -> None:
    lines = (
        "static int system_add_vxlan(int value)\n"
        "{\n"
        "    value++;\n"
        "    return value;\n"
        "}\n"
    ).splitlines()

    prefix = checker_module._source_function_prefix(
        lines, "system_add_vxlan.lto_priv.0", 3
    )

    assert "static int system_add_vxlan(int value)" in prefix
    assert prefix.endswith("    value++;")


@pytest.mark.parametrize(
    ("declaration", "expected_proven"),
    [
        ("static char *matches[4];", 1),
        ("char **matches;\n    // matches[4] = legacy;", 0),
        ("", 0),
    ],
)
def test_array_object_rule_ignores_commented_declarations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    declaration: str,
    expected_proven: int,
) -> None:
    state = _state(
        "candidate-array-object",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="null_pointer_dereference",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    (source_root / "target.c").write_text(
        "static void target(int i)\n"
        "{\n"
        f"    {declaration}\n"
        "    use(matches[i]);\n"
        "}\n"
    )
    _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {
                "function": "target",
                "path": "demo/target.c",
                "line": 5 if "legacy" in declaration else 4,
            }
        ],
    )

    result = run_autoprove(root)

    assert result.proven_candidates == expected_proven
    assert result.residual_candidates == 1 - expected_proven


def test_array_declaration_prefix_rejects_expression_keywords() -> None:
    assert checker_module._c_declaration_prefix_is_type("char *const")
    assert checker_module._c_declaration_prefix_is_type("struct message *")
    assert not checker_module._c_declaration_prefix_is_type("")
    assert not checker_module._c_declaration_prefix_is_type("return")


def test_array_object_rule_does_not_treat_struct_field_as_standalone_array(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state(
        "candidate-member-array",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="null_pointer_dereference",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    (source_root / "target.c").write_text(
        "struct holder {\n"
        "    char *items[4];\n"
        "};\n"
        "static void target(struct holder *holder, int i)\n"
        "{\n"
        "    use(holder->items[i]);\n"
        "}\n"
    )
    _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/target.c", "line": 6}
        ],
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 0
    assert result.residual_candidates == 1


@pytest.mark.parametrize(
    ("second_definition", "expected_proven"),
    [
        ("static char *matches[8] ALIGN_PTR = { 0 };", 1),
        ("static char **matches;", 0),
    ],
)
def test_array_object_rule_checks_every_preprocessor_alternative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    second_definition: str,
    expected_proven: int,
) -> None:
    state = _state(
        "candidate-array-alternatives",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="null_pointer_dereference",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    (source_root / "target.c").write_text(
        "#if FIRST_LAYOUT\n"
        "static char *matches[4] ALIGN_PTR = { 0 };\n"
        "#else\n"
        f"{second_definition}\n"
        "#endif\n"
        "static void target(int i)\n"
        "{\n"
        "    use(matches[i]);\n"
        "}\n"
    )
    _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/target.c", "line": 8}
        ],
    )

    result = run_autoprove(root)

    assert result.proven_candidates == expected_proven
    assert result.residual_candidates == 1 - expected_proven


def test_reference_struct_layout_resolves_anonymous_typedef(
    tmp_path: Path,
) -> None:
    compiler = shutil.which("gcc") or shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for the DWARF layout regression")
    source = tmp_path / "layout.c"
    source.write_text(
        "typedef struct { unsigned char first; unsigned int second; } msg_t;\n"
        "volatile msg_t packet;\n"
        "int main(void) { return packet.first; }\n"
    )
    reference = tmp_path / "reference"
    subprocess.run(
        [compiler, "-O0", "-g", "-o", str(reference), str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
    context = CampaignContext(
        root=tmp_path,
        manifest={},
        candidate={},
        state={},
        binding={},
        input_row={},
        binary_path=reference,
        export_manifest={},
    )

    layout = checker_module._reference_struct_layout(
        context,
        {
            "reference_binary": {
                "path": reference.name,
                "sha256": sha256_file(reference),
            }
        },
        "msg_t",
    )

    assert layout["type_binding"] == "typedef_to_structure"
    assert layout["size_bytes"] == 8
    assert layout["members"] == [
        {"name": "first", "offset_bytes": 0, "size_bytes": 1},
        {"name": "second", "offset_bytes": 4, "size_bytes": 4},
    ]


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
    first_summary = result.summary_path.read_bytes()
    first_review = next((root / "reviews").glob("*.json")).read_bytes()
    repeated = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert result.residual_candidates == 0
    assert result.complete_units == 1
    assert result.admitted_units == 1
    assert repeated.admitted_units == 1
    assert repeated.summary_path.read_bytes() == first_summary
    assert next((root / "reviews").glob("*.json")).read_bytes() == first_review
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


def test_repeated_autoprove_preserves_separately_authored_valid_review(tmp_path: Path) -> None:
    root = _prepare(tmp_path, [_state("candidate-1")], _elf_with_calls(0x100))
    run_autoprove(root, admit=True)
    review_path = next((root / "reviews").glob("*.json"))
    review = json.loads(review_path.read_text())
    review["decisions"][0]["rationale"] += " Independently reviewed."
    review_path.write_text(json.dumps(review))

    repeated = run_autoprove(root, admit=True)
    preserved = json.loads(review_path.read_text())

    assert repeated.admitted_units == 1
    assert preserved["decisions"][0]["rationale"].endswith("Independently reviewed.")


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


def test_typed_link_cursor_store_is_certified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_text = (
        "typedef struct CronFile {\n"
        "    struct CronLine *cf_lines;\n"
        "} CronFile;\n"
        "typedef struct CronLine {\n"
        "    struct CronLine *cl_next;\n"
        "} CronLine;\n"
        "static void delete_cronfile(CronFile *file)\n"
        "{\n"
        "    CronLine **pline = &file->cf_lines;\n"
        "    CronLine *line;\n"
        "    while ((line = *pline) != NULL) {\n"
        "        if (line->keep)\n"
        "            pline = &line->cl_next;\n"
        "        else\n"
        "            *pline = line->cl_next;\n"
        "    }\n"
        "}\n"
    )
    root = _prepare_source_rule_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-typed-link",
        source_relative="miscutils/crond.c",
        source_text=source_text,
        function="delete_cronfile",
        source_line=15,
        write_width=8,
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "c_typed_link_pointer_store_v1": 1
    }
    assert check_all_certificates(root)["checked_certificate_count"] == 1


def test_bounded_wrapper_read_terminator_is_certified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_text = (
        "#define filedata bb_common_bufsiz1\n"
        "static int read_file(const char *name)\n"
        "{\n"
        "    int n = open_read_close(name, filedata, COMMON_BUFSIZE - 1);\n"
        "    if (n < 0) {\n"
        "        filedata[0] = '\\0';\n"
        "    } else {\n"
        "        filedata[n] = '\\0';\n"
        "    }\n"
        "    return n;\n"
        "}\n"
    )
    root = _prepare_source_rule_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-bounded-wrapper-read",
        source_relative="networking/brctl.c",
        source_text=source_text,
        function="read_file",
        source_line=8,
        write_width=1,
    )
    source_root = root / "sources" / "demo"
    read_source = source_root / "libbb" / "read.c"
    read_source.parent.mkdir(parents=True)
    read_source.write_text(
        "ssize_t FAST_FUNC safe_read(int fd, void *buf, size_t count) {\n"
        "    ssize_t n; n = read(fd, buf, count); return n;\n"
        "}\n"
        "ssize_t FAST_FUNC full_read(int fd, void *buf, size_t len) {\n"
        "    ssize_t cc, total = 0;\n"
        "    while (len) { cc = safe_read(fd, buf, len);\n"
        "        if (cc <= 0) break; total += cc; len -= cc; }\n"
        "    return total;\n"
        "}\n"
        "ssize_t FAST_FUNC read_close(int fd, void *buf, size_t size) {\n"
        "    size = full_read(fd, buf, size); return size;\n"
        "}\n"
        "ssize_t FAST_FUNC open_read_close(const char *name, void *buf, size_t size) {\n"
        "    int fd = open(name, 0); return read_close(fd, buf, size);\n"
        "}\n"
    )
    (source_root / "libbb" / "common_bufsiz.c").write_text(
        "char bb_common_bufsiz1[COMMON_BUFSIZE];\n"
    )
    sdk_path = root / "sdk" / "fake-sdk.tar.zst"
    sdk_ref = {
        "path": str(sdk_path.relative_to(root)),
        "sha256": sha256_file(sdk_path),
        "kind": "source_review",
    }
    api_header = root / "sdk" / "unistd.h"
    api_header.write_text("ssize_t read(int, void *, size_t);\n")
    api_ref = {
        "path": str(api_header.relative_to(root)),
        "sha256": sha256_file(api_header),
        "kind": "source_review",
    }
    monkeypatch.setattr(
        checker_module,
        "_reference_defined_data_symbol",
        lambda _context, _source, name: {
            "name": name,
            "address": "0x4000",
            "size_bytes": 1024,
            "symbol_type": "B",
            "reference_binary_path": "reference-builds/demo/symbol-rich/demo",
            "reference_binary_sha256": sha256_file(
                root / "reference-builds" / "demo" / "symbol-rich" / "demo"
            ),
        },
    )
    monkeypatch.setattr(
        checker_module,
        "_sdk_api_contract",
        lambda _context, _mapping, api: {
            "sdk_archive": sdk_ref,
            "api_header": api_ref,
            "api": api,
            "declaration": "ssize_t read(int, void *, size_t);",
            "success_contract": "a positive return is no greater than the requested byte count",
            "sdk_sha256": sdk_ref["sha256"],
        },
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "c_bounded_wrapper_read_terminator_v1": 1
    }
    assert check_all_certificates(root)["checked_certificate_count"] == 1


def test_masked_static_ring_store_is_certified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_text = (
        "char *auto_string(char *str)\n"
        "{\n"
        "    static char *saved[4];\n"
        "    static uint8_t cur_saved; /* = 0 */\n"
        "    free(saved[cur_saved]);\n"
        "    saved[cur_saved] = str;\n"
        "    cur_saved = (cur_saved + 1) & (ARRAY_SIZE(saved)-1);\n"
        "    return str;\n"
        "}\n"
    )
    root = _prepare_source_rule_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-masked-ring",
        source_relative="libbb/auto_string.c",
        source_text=source_text,
        function="auto_string",
        source_line=6,
        write_width=8,
    )
    header = root / "sources" / "demo" / "include" / "libbb.h"
    header.parent.mkdir(parents=True)
    header.write_text(
        "#define ARRAY_SIZE(x) ((unsigned)(sizeof(x) / sizeof((x)[0])))\n"
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "c_masked_static_ring_index_v1": 1
    }
    assert check_all_certificates(root)["checked_certificate_count"] == 1


def test_trailing_escape_terminator_is_certified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_text = (
        "static void add_cmd(const char *cmdstr)\n"
        "{\n"
        "    unsigned len, n;\n"
        "    if (G.add_cmd_line) {\n"
        "        char *tp = xasprintf(\"%s\\n%s\", G.add_cmd_line, cmdstr);\n"
        "        free(G.add_cmd_line);\n"
        "        cmdstr = G.add_cmd_line = tp;\n"
        "    }\n"
        "    n = len = strlen(cmdstr);\n"
        "    while (n && cmdstr[n-1] == '\\\\')\n"
        "        n--;\n"
        "    if ((len - n) & 1) {\n"
        "        if (!G.add_cmd_line)\n"
        "            G.add_cmd_line = xstrdup(cmdstr);\n"
        "        G.add_cmd_line[len-1] = '\\0';\n"
        "    }\n"
        "}\n"
    )
    root = _prepare_source_rule_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-trailing-escape",
        source_relative="editors/sed.c",
        source_text=source_text,
        function="add_cmd",
        source_line=15,
        write_width=1,
    )
    allocator = root / "sources" / "demo" / "libbb" / "xfuncs_printf.c"
    allocator.parent.mkdir(parents=True)
    allocator.write_text(
        "char* FAST_FUNC xstrdup(const char *s) {\n"
        "    char *t; t = strdup(s); if (t == NULL) die(); return t;\n"
        "}\n"
        "char* FAST_FUNC xasprintf(const char *format, ...) {\n"
        "    int r; char *string_ptr; va_list p;\n"
        "    r = vasprintf(&string_ptr, format, p);\n"
        "    if (r < 0) die(); return string_ptr;\n"
        "}\n"
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "c_trailing_escape_terminator_v1": 1
    }
    assert check_all_certificates(root)["checked_certificate_count"] == 1


@pytest.mark.parametrize(
    ("candidate_id", "source_relative", "source_text", "function", "source_line", "write_width"),
    [
        (
            "candidate-macro-scalar",
            "shell/ash.c",
            "struct globals_misc { volatile smallint pending_int; };\n"
            "#define pending_int (G_misc.pending_int)\n"
            "static void raise_interrupt(void)\n"
            "{\n"
            "    pending_int = 0;\n"
            "}\n",
            "raise_interrupt",
            5,
            1,
        ),
        (
            "candidate-macro-array",
            "editors/vi.c",
            "struct globals { char *mark[28]; };\n"
            "#define mark (G.mark)\n"
            "static char *swap_context(char *p)\n"
            "{\n"
            "    char *tmp = p;\n"
            "    mark[26] = p = tmp;\n"
            "    return p;\n"
            "}\n",
            "swap_context",
            6,
            8,
        ),
    ],
)
def test_macro_typed_member_store_is_certified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    candidate_id: str,
    source_relative: str,
    source_text: str,
    function: str,
    source_line: int,
    write_width: int,
) -> None:
    root = _prepare_source_rule_campaign(
        tmp_path,
        monkeypatch,
        candidate_id=candidate_id,
        source_relative=source_relative,
        source_text=source_text,
        function=function,
        source_line=source_line,
        write_width=write_width,
    )
    platform = root / "sources" / "demo" / "include" / "platform.h"
    platform.parent.mkdir(parents=True, exist_ok=True)
    platform.write_text(
        "#if defined(i386) || defined(__x86_64__)\n"
        "typedef signed char smallint;\n"
        "#else\n"
        "typedef int smallint;\n"
        "#endif\n"
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "c_macro_typed_member_store_v1": 1
    }
    assert check_all_certificates(root)["checked_certificate_count"] == 1


@pytest.mark.parametrize(("bound", "proven"), [(3, True), (16, False)])
def test_bounded_typed_byte_array_store_requires_in_capacity_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bound: int,
    proven: bool,
) -> None:
    source_text = (
        '#include "utils.h"\n'
        "int FAST_FUNC get_addr_1(inet_prefix *addr, char *name, int family)\n"
        "{\n"
        "    unsigned i = 0;\n"
        "    unsigned n = 0;\n"
        "    const char *cp = name - 1;\n"
        "    while (*++cp) {\n"
        "        if ((unsigned char)(*cp - '0') <= 9) {\n"
        "            n = 10 * n + (unsigned char)(*cp - '0');\n"
        "            if (n >= 256)\n"
        "                return -1;\n"
        "            ((uint8_t*)addr->data)[i] = n;\n"
        "            continue;\n"
        "        }\n"
        f"        if (*cp == '.' && ++i <= {bound}) {{\n"
        "            n = 0;\n"
        "            continue;\n"
        "        }\n"
        "        return -1;\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )
    root = _prepare_source_rule_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-bounded-typed-byte-store",
        source_relative="networking/libiproute/utils.c",
        source_text=source_text,
        function="get_addr_1",
        source_line=12,
        write_width=1,
    )
    header = root / "sources" / "demo" / "networking" / "libiproute" / "utils.h"
    header.write_text(
        "typedef struct {\n"
        "    uint8_t family;\n"
        "    uint8_t bytelen;\n"
        "    int16_t bitlen;\n"
        "    uint32_t data[4];\n"
        "} inet_prefix;\n"
    )

    result = run_autoprove(root)

    assert result.proven_candidates == int(proven)
    expected_counts = {"c_bounded_typed_byte_array_store_v1": 1} if proven else {}
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == expected_counts
    assert check_all_certificates(root)["checked_certificate_count"] == int(proven)


def test_blobmsg_table_initialization_contract_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _prepare_blobmsg_table_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-table",
        source_text=(
            "static void\n"
            "target(void)\n"
            "{\n"
            "    struct blob_attr *tb[MAX_ATTR], *cur;\n"
            "    blobmsg_parse(policy, MAX_ATTR, tb, data, len);\n"
            "    log_debug(\"target(\");\n"
            "    if ((cur = tb[ATTR_NAME]) != NULL) {\n"
            "        use(cur);\n"
            "    }\n"
            "}\n"
        ),
        source_line=8,
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert result.admitted_units == 1
    summary = json.loads(result.summary_path.read_text())
    assert summary["counts_by_rule"] == {
        "libubox_blobmsg_parse_initializes_table_v1": 1
    }
    certificate = json.loads(next((root / "autoprove" / "runs").glob("*/certificates/*.json")).read_text())
    assert certificate["proof"]["source_excerpt"]["table_access"]["kind"] == (
        "enclosing_table_alias_assignment"
    )
    decision = json.loads(next((root / "reviews").glob("*.json")).read_text())["decisions"][0]
    assert decision["obligations"]["all_path_initialization"]["status"] == "satisfied"
    assert finalize_campaign(root).ledger_path.is_file()


@pytest.mark.parametrize(
    ("parse_count", "guard", "expected_reason"),
    [
        (
            "MAX_ATTR - 1",
            "if ((cur = tb[ATTR_NAME]) != NULL) {",
            "blobmsg parser count is not proven equal to table capacity",
        ),
        (
            "MAX_ATTR",
            "if (enabled || (cur = tb[ATTR_NAME]) != NULL) {",
            "exact source operation does not read a parsed attribute table",
        ),
    ],
)
def test_blobmsg_table_proof_rejects_unsafe_counterexamples(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    parse_count: str,
    guard: str,
    expected_reason: str,
) -> None:
    root = _prepare_blobmsg_table_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-unsafe-table",
        source_text=(
            "static void target(void)\n"
            "{\n"
            "    struct blob_attr *tb[MAX_ATTR], *cur;\n"
            f"    blobmsg_parse(policy, {parse_count}, tb, data, len);\n"
            f"    {guard}\n"
            "        use(cur);\n"
            "    }\n"
            "}\n"
        ),
        source_line=6,
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 0
    assert check_all_certificates(root)["checked_certificate_count"] == 0
    residual = json.loads(result.residual_queue_path.read_text())
    attempt = next(
        item
        for item in residual["residual_candidates"][0]["attempts"]
        if item["rule_id"] == "libubox_blobmsg_parse_initializes_table_v1"
    )
    assert attempt["reason"] == expected_reason


def test_blobmsg_table_alias_accepts_immediate_unbraced_guard() -> None:
    lines = (
        "static void target(struct blob_attr **tb)\n"
        "{\n"
        "    struct blob_attr *cur;\n"
        "    if ((cur = tb[ATTR_NAME]))\n"
        "        use(cur);\n"
        "}\n"
    ).splitlines()

    result = checker_module._enclosing_blobmsg_table_alias(lines, 5, lines[4])

    assert result is not None
    assert result["kind"] == "unbraced_table_alias_assignment"
    assert result["table_index"] == "ATTR_NAME"


def test_named_blobmsg_table_initialization_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _prepare_blobmsg_table_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-named-table",
        source_text=(
            "static void target(void)\n"
            "{\n"
            "    struct blob_attr *tb_data[MAX_ATTR], *cur;\n"
            "    blobmsg_parse(policy, MAX_ATTR, tb_data, data, len);\n"
            "    if ((cur = tb_data[ATTR_NAME]) != NULL) {\n"
            "        use(cur);\n"
            "    }\n"
            "}\n"
        ),
        source_line=5,
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "libubox_named_blobmsg_parse_initializes_table_v1": 1
    }


def test_named_blobmsg_table_rejects_short_parse_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _prepare_blobmsg_table_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-unsafe-named-table",
        source_text=(
            "static void target(void)\n"
            "{\n"
            "    struct blob_attr *tb_data[MAX_ATTR], *cur;\n"
            "    blobmsg_parse(policy, MAX_ATTR - 1, tb_data, data, len);\n"
            "    if ((cur = tb_data[ATTR_NAME]) != NULL) {\n"
            "        use(cur);\n"
            "    }\n"
            "}\n"
        ),
        source_line=5,
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 0
    assert result.residual_candidates == 1


def test_formatted_input_output_address_is_not_a_value_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _prepare_formatted_input_campaign(
        tmp_path,
        monkeypatch,
        output_argument="&value",
        runtime_local=False,
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "c_formatted_input_output_not_read_v1": 1
    }


@pytest.mark.parametrize(
    ("output_argument", "runtime_local"),
    [("value", False), ("&value", True)],
)
def test_formatted_input_output_proof_rejects_runtime_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_argument: str,
    runtime_local: bool,
) -> None:
    root = _prepare_formatted_input_campaign(
        tmp_path,
        monkeypatch,
        output_argument=output_argument,
        runtime_local=runtime_local,
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 0
    assert result.residual_candidates == 1


def test_stat_output_call_effect_is_not_a_value_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _prepare_stat_call_effect_campaign(
        tmp_path,
        monkeypatch,
        output_expression="&first",
        runtime_local=False,
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "c_stat_output_call_effect_not_read_v1": 1
    }


@pytest.mark.parametrize(
    ("output_expression", "runtime_local"),
    [("first", False), ("&first", True)],
)
def test_stat_output_call_effect_rejects_runtime_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_expression: str,
    runtime_local: bool,
) -> None:
    root = _prepare_stat_call_effect_campaign(
        tmp_path,
        monkeypatch,
        output_expression=output_expression,
        runtime_local=runtime_local,
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 0
    assert result.residual_candidates == 1


def _prepare_stat_call_effect_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    output_expression: str,
    runtime_local: bool,
) -> Path:
    root = _prepare_formatted_input_campaign(
        tmp_path,
        monkeypatch,
        output_argument="&value",
        runtime_local=runtime_local,
    )
    (root / "sources" / "demo" / "target.c").write_text(
        "static void target(const char *path)\n"
        "{\n"
        "    struct stat first, second;\n"
        "    prepare();\n"
        f"    if (stat(path, {output_expression}) || stat(path, &second))\n"
        "        return;\n"
        "}\n"
    )
    return root


def _prepare_formatted_input_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    output_argument: str,
    runtime_local: bool,
) -> Path:
    state = _state(
        "candidate-formatted-input",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    operation_address = hex(IMAGE_BASE + 0x120)
    state["sink"] = {
        "address": operation_address,
        "operation_address": operation_address,
        "kind": "call",
        "name": "fscanf",
        "semantics": "format_input",
        "evidence_source": "pcode_call",
    }
    state["operation"] = dict(state["sink"])
    manifest = _manifest([state])
    function = manifest["functions"][0]
    function["pcode_loads"] = []
    target = {
        "address": "0x9000",
        "address_space": "unique",
        "size_bytes": 8,
        "var_name": "UNNAMED",
    }
    local = {
        "address": "0x-20",
        "address_space": "stack",
        "size_bytes": 4,
        "stack_offset": -32,
        "var_name": "local_20",
    }
    pointer = {
        "address": "0x9100",
        "address_space": "unique",
        "size_bytes": 8,
        "var_name": "UNNAMED",
    }
    call_args = [
        {
            "address": "0x0",
            "address_space": "register",
            "size_bytes": 8,
            "var_name": "fp",
        },
        {
            "address": "0x9200",
            "address_space": "unique",
            "size_bytes": 8,
            "var_name": "UNNAMED",
        },
        local if runtime_local else pointer,
    ]
    function["pcode_calls"] = [
        {
            "call_address": operation_address,
            "pcode": "CALLIND",
            "callee": "",
            "callee_address": "0x9000",
            "target_kind": "indirect",
            "arg_count": len(call_args),
            "args": call_args,
        }
    ]
    function["pcode_operations"] = [
        {
            "operation_address": operation_address,
            "pcode": "CALLIND",
            "inputs": [target, *call_args],
            "output": {},
        },
        {
            "operation_address": operation_address,
            "pcode": "INDIRECT",
            "inputs": [
                local,
                {
                    "address": "0x1",
                    "address_space": "const",
                    "constant": 1,
                    "size_bytes": 4,
                },
            ],
            "output": local,
        },
    ]
    root = _prepare(
        tmp_path,
        [state],
        _elf_with_calls(0x120),
        manifest_payload=manifest,
    )
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    (source_root / "target.c").write_text(
        "static void target(FILE *fp)\n"
        "{\n"
        "    int value;\n"
        "    int result;\n"
        f"    result = fscanf(fp, \"%d\", {output_argument});\n"
        "    use(result);\n"
        "}\n"
    )
    _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/target.c", "line": 5}
        ],
    )
    monkeypatch.setattr(
        checker_module,
        "_sdk_api_contract",
        lambda *_args, **_kwargs: {
            "api": "fscanf",
            "declaration": "int fscanf(FILE *, const char *, ...);",
            "success_contract": "conversions store through output pointers",
        },
    )
    return root


def test_busybox_rtattr_table_initialization_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _prepare_busybox_source_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-rtattr",
        source_text=(
            "static void target(void)\n"
            "{\n"
            "    struct rtattr *tb[MAX + 1];\n"
            "    parse_rtattr(tb, MAX, rta, len);\n"
            "    if (tb[NAME]) {\n"
            "        use(RTA_DATA(tb[NAME]));\n"
            "    }\n"
            "}\n"
        ),
        source_line=6,
        dependency_name="_busybox_parse_rtattr_contract",
        dependency={
            "source_commit": "a" * 40,
            "implementation": {
                "path": "sources/demo/networking/libiproute/libnetlink.c",
                "sha256": "b" * 64,
                "kind": "source_review",
            },
            "function": "parse_rtattr",
            "initialization_statement": (
                "memset(tb, 0, (max + 1) * sizeof(tb[0]));"
            ),
            "bounded_store_statement": (
                "if (rta->rta_type <= max) { tb[rta->rta_type] = rta;"
            ),
            "path_coverage": "zeroing precedes the parser loop",
        },
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "busybox_parse_rtattr_initializes_table_v1": 1
    }
    assert check_all_certificates(root)["checked_certificate_count"] == 1


@pytest.mark.parametrize(
    ("source_text", "source_line"),
    [
        ((
            "static void target(void)\n"
            "{\n"
            "    struct rtattr *tb[MAX];\n"
            "    parse_rtattr(tb, MAX, rta, len);\n"
            "    if (tb[NAME]) {\n"
            "        use(RTA_DATA(tb[NAME]));\n"
            "    }\n"
            "}\n"
        ), 6),
        ((
            "static void target(void)\n"
            "{\n"
            "    struct rtattr *tb[MAX + 1];\n"
            "    parse_rtattr(tb, MAX, rta, len);\n"
            "    use(RTA_DATA(tb[NAME]));\n"
            "}\n"
        ), 5),
        ((
            "static void target(void)\n"
            "{\n"
            "    struct rtattr *tb[MAX + 1];\n"
            "    parse_rtattr(tb, MAX, rta, len);\n"
            "    if (enabled) use(RTA_DATA(tb[NAME]));\n"
            "}\n"
        ), 5),
    ],
)
def test_busybox_rtattr_proof_rejects_unsafe_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_text: str,
    source_line: int,
) -> None:
    root = _prepare_busybox_source_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-unsafe-rtattr",
        source_text=source_text,
        source_line=source_line,
        dependency_name="_busybox_parse_rtattr_contract",
        dependency={},
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 0
    assert result.residual_candidates == 1


def test_busybox_getopt32_guarded_output_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _prepare_busybox_source_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-getopt32",
        source_text=_getopt32_source("0", '"m:"'),
        source_line=9,
        dependency_name="_busybox_getopt32_contract",
        dependency={
            "source_commit": "a" * 40,
            "implementation": {
                "path": "sources/demo/libbb/getopt32.c",
                "sha256": "b" * 64,
                "kind": "source_review",
            },
            "noreturn_header": {
                "path": "sources/demo/include/libbb.h",
                "sha256": "c" * 64,
                "kind": "source_review",
            },
            "function": "vgetopt32",
            "option_bit_statement": "on_off->switch_on = (1U << c);",
            "argument_store_statement": "*(char **)(on_off->optarg) = optarg;",
            "success_contract": "the output store precedes return",
            "source_error_path": "bb_show_usage();",
        },
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "busybox_getopt32_guarded_output_v1": 1
    }
    certificate = json.loads(
        next((root / "autoprove" / "runs").glob("*/certificates/*.json")).read_text()
    )
    assert certificate["proof"]["initialization"]["inherited_mask_proof"][
        "incoming_values"
    ] == [0]


@pytest.mark.parametrize(
    ("caller_mask", "option_spec"),
    [("OPT_m", '"m:"'), ("0", '"m:\\0m"')],
)
def test_busybox_getopt32_proof_rejects_unsafe_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caller_mask: str,
    option_spec: str,
) -> None:
    root = _prepare_busybox_source_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-unsafe-getopt32",
        source_text=_getopt32_source(caller_mask, option_spec),
        source_line=10,
        dependency_name="_busybox_getopt32_contract",
        dependency={},
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 0
    assert result.residual_candidates == 1


def test_fixed_recv_struct_member_initialization_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dependency = {
        "sdk_archive": {
            "path": "sdk/fake-sdk.tar.zst",
            "sha256": "a" * 64,
            "kind": "source_review",
        },
        "api_header": {
            "path": "sdk/socket.h",
            "sha256": "b" * 64,
            "kind": "source_review",
        },
        "api": "recv",
        "declaration": "ssize_t recv(int, void *, size_t, int);",
        "success_contract": "the return value is the initialized byte count",
        "sdk_sha256": "c" * 64,
    }
    root = _prepare_busybox_source_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-recv",
        source_text=_fixed_recv_source("8", terminates=True),
        source_line=10,
        dependency_name="_sdk_api_contract",
        dependency=dependency,
    )
    monkeypatch.setattr(
        checker_module,
        "_reference_struct_layout",
        lambda _context, _mapping, _name: {
            "name": "msg_t",
            "type_binding": "typedef_to_structure",
            "size_bytes": 8,
            "members": [
                {"name": "first", "offset_bytes": 0, "size_bytes": 4},
                {"name": "second", "offset_bytes": 4, "size_bytes": 4},
            ],
            "reference_binary_path": "reference-builds/demo/symbol-rich/demo",
            "reference_binary_sha256": "d" * 64,
        },
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "c_fixed_size_recv_initialization_v1": 1
    }
    certificate = json.loads(
        next((root / "autoprove" / "runs").glob("*/certificates/*.json")).read_text()
    )
    assert certificate["proof"]["initialization"]["selected_member_end_bytes"] == 8
    assert certificate["proof"]["initialization"]["minimum_accepted_size_bytes"] == 8


@pytest.mark.parametrize(
    ("accepted_size", "terminates"),
    [("4", True), ("8", False)],
)
def test_fixed_recv_proof_rejects_short_or_fallthrough_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    accepted_size: str,
    terminates: bool,
) -> None:
    root = _prepare_busybox_source_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-unsafe-recv",
        source_text=_fixed_recv_source(accepted_size, terminates=terminates),
        source_line=10,
        dependency_name="_sdk_api_contract",
        dependency={},
    )
    monkeypatch.setattr(
        checker_module,
        "_reference_struct_layout",
        lambda _context, _mapping, _name: {
            "name": "msg_t",
            "size_bytes": 8,
            "members": [
                {"name": "first", "offset_bytes": 0, "size_bytes": 4},
                {"name": "second", "offset_bytes": 4, "size_bytes": 4},
            ],
        },
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 0
    assert result.residual_candidates == 1


def test_checked_network_parse_output_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dependency = {
        "sdk_archive": {
            "path": "sdk/fake-sdk.tar.zst",
            "sha256": "a" * 64,
            "kind": "source_review",
        },
        "api_header": {
            "path": "sdk/inet.h",
            "sha256": "b" * 64,
            "kind": "source_review",
        },
        "api": "inet_aton",
        "declaration": "int inet_aton(const char *, struct in_addr *);",
        "success_contract": "a nonzero return initializes the output",
        "sdk_sha256": "c" * 64,
    }
    root = _prepare_busybox_source_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-network-output",
        source_text=_network_parse_source("!= 0"),
        source_line=5,
        dependency_name="_sdk_api_contract",
        dependency=dependency,
    )

    result = run_autoprove(root, admit=True)

    assert result.proven_candidates == 1
    assert json.loads(result.summary_path.read_text())["counts_by_rule"] == {
        "c_checked_network_parse_output_v1": 1
    }


def test_checked_network_parse_output_rejects_failure_branch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _prepare_busybox_source_campaign(
        tmp_path,
        monkeypatch,
        candidate_id="candidate-unsafe-network-output",
        source_text=_network_parse_source("== 0"),
        source_line=5,
        dependency_name="_sdk_api_contract",
        dependency={},
    )

    result = run_autoprove(root)

    assert result.proven_candidates == 0
    assert result.residual_candidates == 1


def _network_parse_source(comparison: str) -> str:
    return (
        "static void target(const char *host)\n"
        "{\n"
        "    struct in_addr parsed;\n"
        f"    if (inet_aton(host, &parsed) {comparison}) {{\n"
        "        destination = parsed;\n"
        "    }\n"
        "}\n"
    )


def _fixed_recv_source(accepted_size: str, *, terminates: bool) -> str:
    failure = "return;" if terminates else "warn();"
    return (
        "typedef struct { unsigned first; unsigned second; } msg_t;\n"
        "static void target(int fd)\n"
        "{\n"
        "    msg_t msg;\n"
        "    int size;\n"
        "    size = recv(fd, &msg, sizeof(msg), 0);\n"
        f"    if (size != {accepted_size}) {{\n"
        f"        {failure}\n"
        "    }\n"
        "    use(msg.second);\n"
        "}\n"
    )


def _getopt32_source(caller_mask: str, option_spec: str) -> str:
    return (
        "enum { OPT_m = (1 << 0) };\n"
        "static void target(unsigned op, char **argv)\n"
        "{\n"
        "    char *value;\n"
        f"    op |= getopt32(argv, {option_spec}, &value);\n"
        "    unrelated();\n"
        "    if (op & OPT_m) {\n"
        "        consume_guard();\n"
        "        use(value);\n"
        "    }\n"
        "}\n"
        "static void caller(char **argv)\n"
        "{\n"
        f"    target({caller_mask}, argv);\n"
        "}\n"
    )


def _prepare_busybox_source_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    candidate_id: str,
    source_text: str,
    source_line: int,
    dependency_name: str,
    dependency: dict,
) -> Path:
    state = _state(
        candidate_id,
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    source_path = source_root / "target.c"
    source_path.write_text(source_text)
    _add_source_reference_mapping(root, source_root)
    for reference_name in (
        "implementation",
        "noreturn_header",
        "sdk_archive",
        "api_header",
    ):
        reference = dependency.get(reference_name)
        if not isinstance(reference, dict) or not reference.get("path"):
            continue
        dependency_path = root / str(reference["path"])
        if not dependency_path.exists():
            dependency_path.parent.mkdir(parents=True, exist_ok=True)
            dependency_path.write_text(f"pinned {reference_name}\n")
        reference["sha256"] = sha256_file(dependency_path)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/target.c", "line": source_line}
        ],
    )
    monkeypatch.setattr(checker_module, dependency_name, lambda *_args, **_kwargs: dependency)
    return root


def _prepare_blobmsg_table_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    candidate_id: str,
    source_text: str,
    source_line: int,
) -> Path:
    state = _state(
        candidate_id,
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    root = _prepare(tmp_path, [state], _elf_with_calls())
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    source_path = source_root / "target.c"
    source_path.write_text(source_text)
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
            {"function": "target", "path": "demo/target.c", "line": source_line}
        ],
    )
    monkeypatch.setattr(
        checker_module,
        "_libubox_blobmsg_contract",
        lambda _context, _mapping, **_kwargs: dependency,
    )
    return root


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


def test_unchecked_calloc_a_pattern_requires_immediate_unguarded_use() -> None:
    unsafe = (
        "static void target(const char *input)\n"
        "{\n"
        "    struct item *item;\n"
        "    char *output;\n"
        "    item = calloc_a(sizeof(*item), &output, strlen(input) + 1);\n"
        "    item->value = strcpy(output, input);\n"
        "}\n"
    ).splitlines()

    result = checker_module._unchecked_calloc_a_source_pattern(
        unsafe,
        function="target",
        use_line=6,
    )

    assert result["primary"] == "item"
    assert result["output"] == "output"
    assert result["allocation_line"] == 5

    guarded = unsafe[:5] + ["    if (!item)", "        return;"] + unsafe[5:]
    with pytest.raises(
        checker_module.RuleNotApplicable,
        match="not the immediate next statement",
    ):
        checker_module._unchecked_calloc_a_source_pattern(
            guarded,
            function="target",
            use_line=8,
        )


def test_registered_ubus_string_entry_requires_registered_object(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source_path = source_root / "ubus.c"
    source_path.write_text(
        "static int add_dynamic(struct blob_attr *msg)\n"
        "{\n"
        "    struct blob_attr *tb[MAX];\n"
        "    const char *name;\n"
        "    blobmsg_parse(policy, MAX, tb, blob_data(msg), blob_len(msg));\n"
        "    if (!tb[NAME])\n"
        "        return 1;\n"
        "    name = blobmsg_get_string(tb[NAME]);\n"
        "    target(name, msg);\n"
        "    return 0;\n"
        "}\n"
        "static struct ubus_method methods[] = {\n"
        "    UBUS_METHOD(\"add_dynamic\", add_dynamic, policy),\n"
        "};\n"
        "static struct ubus_object object = {\n"
        "    .methods = methods,\n"
        "};\n"
    )
    dummy_binary = tmp_path / "dummy"
    dummy_binary.write_bytes(b"dummy")
    context = CampaignContext(
        root=tmp_path,
        manifest={},
        candidate={},
        state={},
        binding={},
        input_row={},
        binary_path=dummy_binary,
        export_manifest={},
    )

    with pytest.raises(
        checker_module.RuleNotApplicable,
        match="no unique registered ubus callback",
    ):
        checker_module._registered_ubus_string_entry_contract(
            context,
            source_root,
            callee="target",
        )

    source_path.write_text(source_path.read_text() + "void init(void) { ubus_add_object(&object); }\n")
    context.shared_cache.clear()
    result = checker_module._registered_ubus_string_entry_contract(
        context,
        source_root,
        callee="target",
    )

    assert result["callback"] == "add_dynamic"
    assert result["method"] == "add_dynamic"
    assert result["request_string"] == "name"
    assert result["call_line"] == 9


def test_registered_ubus_callback_is_recovered_from_frozen_method_table(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen = bytearray(_elf_with_calls())
    struct.pack_into("<H", frozen, 16, 2)  # ET_EXEC
    struct.pack_into("<I", frozen, 68, 7)  # one readable/writable/executable test segment
    frozen[0x300 : 0x30C] = b"add_dynamic\0"
    struct.pack_into("<QQ", frozen, 0x380, 0x300, 0x100)
    frozen_path = tmp_path / "frozen"
    frozen_path.write_bytes(frozen)
    reference_path = tmp_path / "reference"
    reference_path.write_bytes(bytes(frozen))
    fingerprint = {
        "normalized_function_sha256": "1" * 64,
        "constant_signature_sha256": "2" * 64,
        "call_topology_sha256": "3" * 64,
        "control_flow_sha256": "4" * 64,
        "relocation_shape_sha256": "5" * 64,
        "instruction_offsets": [0],
    }
    context = CampaignContext(
        root=tmp_path,
        manifest={},
        candidate={},
        state={},
        binding={},
        input_row={},
        binary_path=frozen_path,
        export_manifest={},
    )
    monkeypatch.setattr(
        checker_module,
        "_reference_function_index",
        lambda _context, _path: {
            5: [{"address": 0x180, "names": ["add_dynamic.lto_priv.0"], **fingerprint}]
        },
    )
    monkeypatch.setattr(
        checker_module,
        "_reference_struct_layout",
        lambda _context, _mapping, _name: {
            "name": "ubus_method",
            "size_bytes": 48,
            "members": [
                {"name": "name", "offset_bytes": 0, "size_bytes": 8},
                {"name": "handler", "offset_bytes": 8, "size_bytes": 8},
            ],
        },
    )
    monkeypatch.setattr(
        checker_module,
        "_normalized_function_fingerprint",
        lambda _path, _address, _size: dict(fingerprint),
    )

    result = checker_module._registered_ubus_callback_binary_binding(
        context,
        {"mapping": {"reference_binary": {"path": reference_path.name}}},
        callback="add_dynamic",
        method="add_dynamic",
    )

    assert result["surface_kind"] == "registered_ubus_callback"
    assert result["method_record_address"] == "0x380"
    assert result["handler_address"] == "0x100"
    assert result["mapping_basis"] == "ubus_method_record_plus_function_fingerprint"


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


@pytest.mark.parametrize(
    ("conditional_memset", "expected_proven"),
    [(False, 1), (True, 0)],
)
def test_struct_output_memset_requires_unconditional_dominating_initialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    conditional_memset: bool,
    expected_proven: int,
) -> None:
    state = _state(
        "candidate-struct-output",
        operation_offset=0x140,
        successor_literal=False,
        vulnerability_type="uninitialized_memory_use",
    )
    operation_address = hex(IMAGE_BASE + 0x140)
    state["source"]["expression"] = "local_58"
    state["operation"] = {
        "address": operation_address,
        "operation_address": operation_address,
        "pcode": "CALL",
        "kind": "call",
        "name": "use",
        "evidence_source": "pcode_call",
    }
    state["sink"] = dict(state["operation"])
    manifest = _manifest([state])
    function = manifest["functions"][0]
    function["body_size_bytes"] = 0x101
    function["pcode_loads"] = []
    function["basic_blocks"] = [
        {
            "start": hex(IMAGE_BASE + 0x80),
            "end": hex(IMAGE_BASE + 0x180),
            "successors": [],
        }
    ]
    function["pcode_calls"] = [
        {
            "call_address": hex(IMAGE_BASE + 0x100),
            "callee": "initialize",
            "callee_address": hex(IMAGE_BASE + 0x200),
            "arg_count": 1,
            "args": [
                {
                    "address_space": "unique",
                    "address": "0x9000",
                    "size_bytes": 8,
                    "var_name": "UNNAMED",
                }
            ],
            "pcode": "CALL",
            "target_kind": "direct",
        },
        {
            "call_address": operation_address,
            "callee": "use",
            "callee_address": hex(IMAGE_BASE + 0x240),
            "arg_count": 1,
            "args": [
                {
                    "address_space": "stack",
                    "address": "0x-58",
                    "stack_offset": -88,
                    "size_bytes": 4,
                    "var_name": "local_58",
                    "stack_ref": {"var_name": "local_58", "stack_offset": -88},
                }
            ],
            "pcode": "CALL",
            "target_kind": "direct",
        },
    ]
    function["pcode_operations"] = [
        {
            "operation_address": hex(IMAGE_BASE + 0xF8),
            "pcode": "PTRSUB",
            "inputs": [
                {"address_space": "register", "address": "0x20", "size_bytes": 8},
                {"address_space": "const", "constant": -88, "size_bytes": 8},
            ],
            "output": {
                "address_space": "unique",
                "address": "0x9000",
                "size_bytes": 8,
            },
        },
        {
            "operation_address": hex(IMAGE_BASE + 0x100),
            "pcode": "CALL",
            "inputs": [
                {"address_space": "ram", "address": hex(IMAGE_BASE + 0x200), "size_bytes": 8},
                {"address_space": "unique", "address": "0x9000", "size_bytes": 8},
            ],
            "output": {},
        },
        {
            "operation_address": operation_address,
            "pcode": "CALL",
            "inputs": [
                {"address_space": "ram", "address": hex(IMAGE_BASE + 0x240), "size_bytes": 8},
                {
                    "address_space": "stack",
                    "address": "0x-58",
                    "stack_offset": -88,
                    "size_bytes": 4,
                    "var_name": "local_58",
                    "stack_ref": {"var_name": "local_58", "stack_offset": -88},
                },
            ],
            "output": {},
        },
    ]
    root = _prepare(tmp_path, [state], _elf_with_calls(), manifest_payload=manifest)
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    (source_root / "demo.h").write_text(
        "struct settings {\n"
        "    unsigned int value;\n"
        "};\n"
    )
    memset_source = (
        "    if (ready) {\n"
        "        memset(out, 0, sizeof(*out));\n"
        "    }\n"
        if conditional_memset
        else "    memset(out, 0, sizeof(*out));\n"
    )
    (source_root / "demo.c").write_text(
        "void initialize(struct settings *out)\n"
        "{\n"
        + memset_source
        + "}\n"
        "void target(void)\n"
        "{\n"
        "    struct settings st;\n"
        "    initialize(&st);\n"
        "    use(st.value);\n"
        "}\n"
    )
    _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(checker_module, "_addr2line_frames", lambda *_args: [])

    def operation_mapping(_context: object, _mapping: object, address: int) -> dict:
        names = ["initialize"] if address == IMAGE_BASE + 0x200 else ["target.constprop.0"]
        return {
            "mapping_basis": "exact_code_bytes",
            "frozen_vma": address,
            "reference_vma": address,
            "reference_function_names": names,
        }

    monkeypatch.setattr(checker_module, "_reference_operation_mapping", operation_mapping)
    reference = root / "reference-builds" / "demo" / "symbol-rich" / "demo"
    monkeypatch.setattr(
        checker_module,
        "_reference_struct_layout",
        lambda _context, _mapping, _name: {
            "name": "settings",
            "size_bytes": 4,
            "members": [{"name": "value", "offset_bytes": 0, "size_bytes": 4}],
            "reference_binary_path": str(reference.relative_to(root)),
            "reference_binary_sha256": sha256_file(reference),
        },
    )

    result = run_autoprove(root)

    assert result.proven_candidates == expected_proven
    assert result.residual_candidates == 1 - expected_proven
    summary = json.loads(result.summary_path.read_text())
    assert summary["counts_by_rule"] == (
        {"c_struct_output_memset_initialization_v1": 1} if expected_proven else {}
    )


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


def test_stat_family_path_proof_accepts_terminating_goto_route() -> None:
    lines = (
        "static void target(const char *path)\n"
        "{\n"
        "    struct stat st;\n"
        "    if (lstat(path, &st) < 0) {\n"
        "        if (skip)\n"
        "            goto finished;\n"
        "        return;\n"
        "    }\n"
        "    use(st.st_mode);\n"
        "finished:\n"
        "    return;\n"
        "}\n"
    ).splitlines()
    initialization = checker_module._stat_family_failure_blocks(lines, "st", 9)[0]

    proof = checker_module._stat_output_path_proof(
        lines,
        output="st",
        use_line=9,
        initialization=initialization,
    )

    assert proof is not None
    assert proof["kind"] == "failure_routes_terminate_or_skip_use"


def test_stat_family_path_proof_rejects_fallthrough_failure() -> None:
    lines = (
        "static void target(const char *path)\n"
        "{\n"
        "    struct stat st;\n"
        "    if (lstat(path, &st) < 0) {\n"
        "        warn();\n"
        "    }\n"
        "    use(st.st_mode);\n"
        "}\n"
    ).splitlines()
    initialization = checker_module._stat_family_failure_blocks(lines, "st", 7)[0]

    proof = checker_module._stat_output_path_proof(
        lines,
        output="st",
        use_line=7,
        initialization=initialization,
    )

    assert proof is None


def test_stat_family_success_flag_rejects_true_assignment_outside_success_branch() -> None:
    lines = (
        "static void target(const char *path)\n"
        "{\n"
        "    struct stat st;\n"
        "    int exists = 0;\n"
        "    if (lstat(path, &st) < 0) {\n"
        "        exists = 1;\n"
        "    } else {\n"
        "        consume_path(path);\n"
        "    }\n"
        "    if (exists) {\n"
        "        use(st.st_mode);\n"
        "    }\n"
        "}\n"
    ).splitlines()
    initialization = checker_module._stat_family_failure_blocks(lines, "st", 11)[0]

    proof = checker_module._stat_output_path_proof(
        lines,
        output="st",
        use_line=11,
        initialization=initialization,
    )

    assert proof is None


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


def _prepare_source_rule_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    candidate_id: str,
    source_relative: str,
    source_text: str,
    function: str,
    source_line: int,
    write_width: int,
) -> Path:
    state = _state(
        candidate_id,
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="out_of_bounds_write",
    )
    manifest = _manifest([state])
    manifest["functions"][0]["pcode_stores"][0]["write_width"] = write_width
    root = _prepare(
        tmp_path,
        [state],
        _elf_with_calls(),
        manifest_payload=manifest,
    )
    source_root = root / "sources" / "demo"
    source_path = source_root / source_relative
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(source_text)
    _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {
                "function": function,
                "path": f"demo/{source_relative}",
                "line": source_line,
            }
        ],
    )
    return root
