import os
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from binary_agent.analysis.candidates import run_static_pipeline
from binary_agent.analysis.concolic import (
    CrashWitness,
    ConcolicVerdict,
    GhidraDynamicProofRequest,
    build_concolic_request,
    build_dynamic_overflow_proof_request,
    run_ghidra_dynamic_overflow_proof,
)
from binary_agent.analysis.confirmation import build_evidence_pack_v3
from binary_agent.analysis.entrypoints import EntryPointDeriver
from binary_agent.pipeline import CandidateStatus, candidate_state_from_static_candidate
from binary_agent.promotion import apply_replay_results, promote_for_replay
from binary_agent.replay import import_concolic_replay_results
from binary_agent.reporting import build_lean_reports


pytestmark = pytest.mark.skipif(
    os.environ.get("BINARY_AGENT_RUN_GHIDRA_VALIDATION") != "1",
    reason="set BINARY_AGENT_RUN_GHIDRA_VALIDATION=1 and GHIDRA_INSTALL_DIR to run real Ghidra validation",
)


def test_vuln_demo_argv_process_reaches_exact_sink_with_ghidra(tmp_path: Path) -> None:
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_dir or not Path(ghidra_dir).exists():
        pytest.skip("GHIDRA_INSTALL_DIR does not point to a Ghidra install")
    binary = Path("samples/vuln_demo/build/vuln_demo")
    if not binary.exists():
        pytest.skip("sample binary is not built")
    start_address, function_address, sink_address = _sample_addresses(binary, "strcpy")

    proof = run_ghidra_dynamic_overflow_proof(
        GhidraDynamicProofRequest(
            candidate_id="vuln_demo:argv_process_validation",
            binary_path=binary,
            output_path=tmp_path / "ghidra_dynamic_proof.json",
            ghidra_dir=Path(ghidra_dir),
            function_address=function_address,
            start_address=start_address,
            sink_address=sink_address,
            proof_scope="process_entrypoint",
            input_model="argv",
            concrete_input_hex="41" * 64,
            max_steps=256,
            timeout_seconds=30.0,
            sink_name="strcpy",
            target_buffer="auStack_18",
            destination_kind="stack",
            capacity_bytes=24,
            capacity_source="declared_local_array",
            capacity_basis="auStack_18: declared local stack object, 24 bytes",
            write_size_bytes=64,
            line_text="pcVar1 = strcpy(acStack_18,param_1);",
            line_number=11,
        )
    )

    assert proof["status"] == "overflow_proven", json.dumps(proof, indent=2)
    assert proof["proof_scope"] == "process_entrypoint"
    assert proof["process_input_setup"]["status"] == "configured"
    assert proof["process_input_setup"]["abi"] == "x86_64_sysv"
    assert proof["process_replay"]["status"] == "reached"
    assert proof["process_replay"]["reached_target"] is True
    assert proof["local_sink_probe"]["status"] == "reached"
    assert proof["overflow_bytes"] == 41


def test_fortified_vuln_demo_terminates_before_sink_write_with_ghidra(tmp_path: Path) -> None:
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_dir or not Path(ghidra_dir).exists():
        pytest.skip("GHIDRA_INSTALL_DIR does not point to a Ghidra install")
    binary = Path("samples/vuln_demo/build/vuln_demo_fortified")
    if not binary.exists():
        pytest.skip("fortified sample binary is not built")
    start_address, function_address, sink_address = _sample_addresses(binary, "__strcpy_chk")

    proof = run_ghidra_dynamic_overflow_proof(
        GhidraDynamicProofRequest(
            candidate_id="vuln_demo:fortified_argv_validation",
            binary_path=binary,
            output_path=tmp_path / "ghidra_fortified_proof.json",
            ghidra_dir=Path(ghidra_dir),
            function_address=function_address,
            start_address=start_address,
            sink_address=sink_address,
            proof_scope="process_entrypoint",
            input_model="argv",
            concrete_input_hex="41" * 64,
            max_steps=256,
            timeout_seconds=30.0,
            sink_name="strcpy_chk",
            target_buffer="auStack_18",
            destination_kind="stack",
            capacity_bytes=24,
            capacity_source="fortified_object_size",
            capacity_basis="__strcpy_chk object size argument",
            write_size_bytes=64,
            line_text="uVar1 = __strcpy_chk(auStack_18,param_1,0x18);",
            line_number=11,
        )
    )

    assert proof["status"] == "sink_unreached", json.dumps(proof, indent=2)
    assert proof["process_replay"]["status"] == "terminated"
    assert proof["process_replay"]["reason"] == "fortified_bound_exceeded"
    assert proof["process_replay"]["sink_effect"]["written_bytes"] == 0


def test_heartbleed_shaped_stdin_oob_read_reaches_report_with_ghidra(tmp_path: Path) -> None:
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_dir or not Path(ghidra_dir).exists():
        pytest.skip("GHIDRA_INSTALL_DIR does not point to a Ghidra install")
    if shutil.which("gcc") is None:
        pytest.skip("gcc is required to build the validation binary")
    if not _direct_disassembly_available():
        pytest.skip("objdump or capstone+pyelftools is required to resolve exact sink addresses")

    source = tmp_path / "heartbleed_slice.c"
    binary = tmp_path / "heartbleed_slice"
    source.write_text(
        """
#include <stdint.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    unsigned char heartbeat_record[8] = {0};
    unsigned char dst[64] = {0};
    unsigned char *p = heartbeat_record;
    unsigned char *pl;
    unsigned int payload;

    if (read(0, heartbeat_record, sizeof(heartbeat_record)) != sizeof(heartbeat_record)) {
        return 1;
    }
    if (*p++ != 1) {
        return 0;
    }
    payload = ((unsigned int)p[0] << 8) | p[1];
    p += 2;
    pl = p;
    memcpy(dst, pl, payload);
    return dst[0];
}
"""
    )
    subprocess.run(
        [
            "gcc",
            "-O0",
            "-g",
            "-fno-stack-protector",
            "-fno-builtin-memcpy",
            "-no-pie",
            "-o",
            str(binary),
            str(source),
        ],
        check=True,
    )

    decompile_root = tmp_path / "decompile"
    env = dict(os.environ)
    env["PYTHONPATH"] = "src" if not env.get("PYTHONPATH") else f"src{os.pathsep}{env['PYTHONPATH']}"
    subprocess.run(
        [
            sys.executable,
            "scripts/decompile.py",
            str(binary),
            "--output-dir",
            str(decompile_root),
            "--ghidra-dir",
            ghidra_dir,
        ],
        check=True,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    export_dir = next(decompile_root.glob("**/decompiled"))

    static_report = run_static_pipeline(export_dir)
    source_reads = [
        item
        for item in static_report.candidate_findings
        if item.kind == "source_read" and item.vulnerability_type == "out_of_bounds_read"
    ]
    assert len(source_reads) == 1
    candidate = source_reads[0]
    assert candidate.capacity_bytes == 5
    assert candidate.capacity_source == "inferred_packet_slice_remaining"
    assert candidate.write_relation == "symbolic_size"

    entrypoint = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(candidate.to_dict()).to_dict()
    assert entrypoint["status"] == "derived"
    assert entrypoint["input_model"] == "stdin"
    assert entrypoint["source_to_sink_trace"]["status"] == "complete"

    state = candidate_state_from_static_candidate(candidate)
    state = state.with_updates(
        status=CandidateStatus.PROOF_READY.value,
        blockers=[],
        type_facts={
            **dict(state.type_facts),
            "entrypoint_derivation": entrypoint,
            "source_to_sink_trace": entrypoint["source_to_sink_trace"],
        },
    )
    pack = build_evidence_pack_v3(state, entrypoint_derivation=entrypoint)
    request = build_concolic_request(
        pack,
        binary_path=binary,
        export_dir=export_dir,
        symbolic_bytes=32,
        timeout_seconds=60.0,
    )
    assert request.input_model == "stdin"
    assert request.sink_address != candidate.address
    assert request.target_resolution["target_kind"] in {
        "exact_pcode_callsite",
        "disassembly_unique_source_read_callsite",
    }
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model="stdin", stdin=bytes.fromhex("0100204845415254")),
    )
    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "proof" / "ghidra_dynamic_proof.json",
        ghidra_dir=Path(ghidra_dir),
        max_steps=512,
    )
    proof = run_ghidra_dynamic_overflow_proof(proof_request)
    assert proof["status"] == "oob_read_proven"
    assert proof["read_size_bytes"] == 32
    assert proof["capacity_bytes"] == 5
    assert proof["oob_bytes"] == 27

    verdict_dir = tmp_path / "verdicts" / "heartbleed_slice"
    verdict_dir.mkdir(parents=True)
    request_payload = request.to_dict()
    (verdict_dir / "request.json").write_text(json.dumps(request_payload))
    (verdict_dir / "ghidra_dynamic_proof.json").write_text(json.dumps(proof))
    (verdict_dir / "verdict.json").write_text(
        json.dumps(
            {
                "candidate_id": state.candidate_id,
                "concolic_verdict": "overflow_witness",
                "backend": "ghidra",
                "request": request_payload,
                "witness": {"input_model": "stdin", "stdin_hex": "0100204845415254"},
                "ghidra_dynamic_proof": proof,
                "artifact_paths": ["request.json", "ghidra_dynamic_proof.json", "verdict.json"],
            }
        )
    )

    results = import_concolic_replay_results(tmp_path / "verdicts", tmp_path / "replay")
    replay_ready, _ = promote_for_replay(
        [state],
        request_artifacts={state.candidate_id: str(verdict_dir / "request.json")},
    )
    replay_confirmed, _, _ = apply_replay_results(replay_ready, results)
    reports = build_lean_reports(replay_confirmed)

    assert len(results) == 1
    assert replay_confirmed[0].status == "replay_confirmed"
    assert len(reports) == 1
    assert reports[0].vulnerability == "out_of_bounds_read"
    assert reports[0].proof_details["ghidra_dynamic_proof_status"] == "oob_read_proven"
    assert reports[0].proof_details["dynamic_oob_bytes"] == 27


def test_linked_openssl_heartbleed_oob_read_reaches_report_with_auto_sink_resolution(tmp_path: Path) -> None:
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_dir or not Path(ghidra_dir).exists():
        pytest.skip("GHIDRA_INSTALL_DIR does not point to a Ghidra install")
    harness = os.environ.get("BINARY_AGENT_OPENSSL_HEARTBLEED_HARNESS")
    if not harness or not Path(harness).exists():
        pytest.skip("set BINARY_AGENT_OPENSSL_HEARTBLEED_HARNESS to a linked OpenSSL Heartbleed harness")
    if not _direct_disassembly_available():
        pytest.skip("objdump or capstone+pyelftools is required to resolve exact sink addresses")
    binary = Path(harness)
    export_env = os.environ.get("BINARY_AGENT_OPENSSL_HEARTBLEED_EXPORT")
    if export_env and Path(export_env).exists():
        export_dir = Path(export_env)
    else:
        decompile_root = tmp_path / "openssl_decompile"
        env = dict(os.environ)
        env["PYTHONPATH"] = "src" if not env.get("PYTHONPATH") else f"src{os.pathsep}{env['PYTHONPATH']}"
        subprocess.run(
            [
                sys.executable,
                "scripts/decompile.py",
                str(binary),
                "--output-dir",
                str(decompile_root),
                "--ghidra-dir",
                ghidra_dir,
            ],
            check=True,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        export_dir = next(decompile_root.glob("**/decompiled"))

    static_report = run_static_pipeline(export_dir)
    source_reads = [
        item
        for item in static_report.candidate_findings
        if item.kind == "source_read"
        and item.vulnerability_type == "out_of_bounds_read"
        and item.function_name == "tls1_process_heartbeat"
        and item.target_buffer == "heartbeat_record[3:]"
    ]
    assert len(source_reads) == 1
    candidate = source_reads[0]
    assert candidate.capacity_bytes == 5
    assert candidate.capacity_source == "inferred_packet_slice_remaining"
    assert candidate.write_relation == "symbolic_size"

    entrypoint = EntryPointDeriver.from_export_dir(export_dir).derive_for_candidate(candidate.to_dict()).to_dict()
    assert entrypoint["status"] == "derived"
    assert entrypoint["entry_function"] == "main"
    assert entrypoint["call_path"] == ["main", "tls1_process_heartbeat"]
    assert entrypoint["input_model"] == "stdin"

    state = candidate_state_from_static_candidate(candidate)
    state = state.with_updates(
        status=CandidateStatus.PROOF_READY.value,
        blockers=[],
        type_facts={
            **dict(state.type_facts),
            "entrypoint_derivation": entrypoint,
            "source_to_sink_trace": entrypoint["source_to_sink_trace"],
        },
    )
    pack = build_evidence_pack_v3(state, entrypoint_derivation=entrypoint)
    request = build_concolic_request(
        pack,
        binary_path=binary,
        export_dir=export_dir,
        symbolic_bytes=32,
        timeout_seconds=120.0,
    )
    assert request.input_model == "stdin"
    assert request.sink_address != candidate.address
    assert request.target_resolution["target_kind"] in {
        "exact_pcode_callsite",
        "disassembly_unique_source_read_callsite",
    }
    verdict = ConcolicVerdict(
        candidate_id=request.candidate_id,
        verdict="overflow_witness",
        backend=request.backend,
        request=request.to_dict(),
        witness=CrashWitness(input_model="stdin", stdin=bytes.fromhex("0100204845415254")),
    )
    proof_request = build_dynamic_overflow_proof_request(
        pack,
        request,
        verdict,
        output_path=tmp_path / "openssl_proof" / "ghidra_dynamic_proof.json",
        ghidra_dir=Path(ghidra_dir),
        max_steps=20000,
    )
    proof = run_ghidra_dynamic_overflow_proof(proof_request)
    assert proof["status"] == "oob_read_proven"
    assert proof["read_size_bytes"] == 32
    assert proof["capacity_bytes"] == 5
    assert proof["oob_bytes"] == 27

    verdict_dir = tmp_path / "openssl_verdicts" / "openssl_heartbleed"
    verdict_dir.mkdir(parents=True)
    (verdict_dir / "request.json").write_text(json.dumps(request.to_dict()))
    (verdict_dir / "ghidra_dynamic_proof.json").write_text(json.dumps(proof))
    (verdict_dir / "verdict.json").write_text(
        json.dumps(
            {
                "candidate_id": state.candidate_id,
                "concolic_verdict": "overflow_witness",
                "backend": "ghidra",
                "request": request.to_dict(),
                "witness": {"input_model": "stdin", "stdin_hex": "0100204845415254"},
                "ghidra_dynamic_proof": proof,
                "artifact_paths": ["request.json", "ghidra_dynamic_proof.json", "verdict.json"],
            }
        )
    )

    results = import_concolic_replay_results(tmp_path / "openssl_verdicts", tmp_path / "openssl_replay")
    replay_ready, _ = promote_for_replay(
        [state],
        request_artifacts={state.candidate_id: str(verdict_dir / "request.json")},
    )
    replay_confirmed, _, _ = apply_replay_results(replay_ready, results)
    reports = build_lean_reports(replay_confirmed)

    assert len(results) == 1
    assert replay_confirmed[0].status == "replay_confirmed"
    assert len(reports) == 1
    assert reports[0].vulnerability == "out_of_bounds_read"
    assert reports[0].proof_details["ghidra_dynamic_proof_status"] == "oob_read_proven"
    assert reports[0].proof_details["dynamic_oob_bytes"] == 27


def _direct_disassembly_available() -> bool:
    if shutil.which("objdump") is not None:
        return True
    try:
        import capstone  # noqa: F401
        import elftools  # noqa: F401
    except Exception:
        return False
    return True


def _sample_addresses(binary: Path, callee: str) -> tuple[str, str, str]:
    if shutil.which("nm") is None or shutil.which("objdump") is None:
        pytest.skip("nm and objdump are required for sample address resolution")
    symbols: dict[str, int] = {}
    for line in subprocess.check_output(["nm", "-n", str(binary)], text=True).splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in {"main", "vulnerable_copy"}:
            symbols[parts[2]] = int(parts[0], 16)
    disassembly = subprocess.check_output(["objdump", "-d", str(binary)], text=True)
    match = next(
        (
            line
            for line in disassembly.splitlines()
            if "call" in line and f"<{callee}@plt>" in line
        ),
        "",
    )
    if set(symbols) != {"main", "vulnerable_copy"} or not match:
        raise AssertionError(f"unable to resolve {callee} sample addresses")
    sink = int(match.split(":", 1)[0].strip(), 16)
    ghidra_image_base = 0x100000
    return tuple(
        hex(ghidra_image_base + address)
        for address in (symbols["main"], symbols["vulnerable_copy"], sink)
    )
