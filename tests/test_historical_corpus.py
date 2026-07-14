import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from binary_agent.historical_corpus import (
    GNU_PATCH_FIX,
    GNU_PATCH_VULNERABLE_PARENT,
    _run_native_duplicate_trace,
    _same_generation_exact_second_release,
    freeze_historical_corpus,
    prove_historical_corpus,
    summarize_historical_discovery,
    validate_historical_reproducer,
    verify_historical_corpus,
)


def test_historical_corpus_freezes_pairs_and_detects_tampering(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "binaries").mkdir(parents=True)
    pocs = {
        "GNU patch": source / "pocs/patch/PoC_df",
        "libtiff tiffcrop": source / "pocs/libtiff/poc.tif",
        "mruby": source / "pocs/mruby/cve-2020-6838.rb",
    }
    for path in pocs.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("reproducer")
    cases = []
    for package, stem, vuln in (
        ("GNU patch", "patch", "double_free"),
        ("libtiff tiffcrop", "libtiff", "heap_overflow"),
        ("mruby", "mruby", "use_after_free"),
    ):
        for lane in ("vulnerable", "fixed"):
            binary = source / "binaries" / f"{stem}-{lane}"
            binary.write_text(f"{package}-{lane}")
            cases.append(
                {
                    "id": f"{stem}-{lane}",
                    "binary": str(binary.relative_to(source)),
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "expected_outcome": "caught" if lane == "vulnerable" else "clean",
                    "known_vuln_family": vuln,
                    "process_input_model": "argv",
                    "provenance": {"package": package, "version": lane},
                }
            )
    manifest = source / "frozen-manifest.json"
    manifest.write_text(json.dumps({"cases": cases}))
    frozen = freeze_historical_corpus(manifest, tmp_path / "output")
    assert verify_historical_corpus(frozen)["verified"] is True
    payload = json.loads(frozen.read_text())
    binary = frozen.parent / payload["cases"][0]["binary_path"]
    binary.write_bytes(binary.read_bytes() + b"tamper")
    assert verify_historical_corpus(frozen)["verified"] is False


def test_historical_discovery_summary_keeps_candidate_separation_distinct_from_proof(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "binaries").mkdir(parents=True)
    poc = source / "pocs/patch/PoC_df"
    poc.parent.mkdir(parents=True)
    poc.write_text("reproducer")
    cases = []
    for lane in ("vulnerable", "fixed"):
        binary = source / "binaries" / f"patch-{lane}"
        binary.write_text(lane)
        cases.append(
            {
                "id": f"patch-{lane}",
                "binary": str(binary.relative_to(source)),
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "expected_outcome": "caught" if lane == "vulnerable" else "clean",
                "known_vuln_family": "double_free",
                "process_input_model": "argv",
                "provenance": {"package": "GNU patch", "version": lane},
            }
        )
    # The freezer deliberately requires all three adjacent-revision groups.
    for package, stem, vuln in (
        ("libtiff tiffcrop", "libtiff", "heap_overflow"),
        ("mruby", "mruby", "use_after_free"),
    ):
        package_poc = source / {
            "libtiff tiffcrop": "pocs/libtiff/poc.tif",
            "mruby": "pocs/mruby/cve-2020-6838.rb",
        }[package]
        package_poc.parent.mkdir(parents=True, exist_ok=True)
        package_poc.write_text("reproducer")
        for lane in ("vulnerable", "fixed"):
            binary = source / "binaries" / f"{stem}-{lane}"
            binary.write_text(f"{stem}-{lane}")
            cases.append(
                {
                    "id": f"{stem}-{lane}",
                    "binary": str(binary.relative_to(source)),
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "expected_outcome": "caught" if lane == "vulnerable" else "clean",
                    "known_vuln_family": vuln,
                    "process_input_model": "argv",
                    "provenance": {"package": package, "version": lane},
                }
            )
    source_manifest = source / "manifest.json"
    source_manifest.write_text(json.dumps({"cases": cases}))
    frozen = freeze_historical_corpus(source_manifest, tmp_path / "corpus")
    discovery = tmp_path / "discovery"
    for case in json.loads(frozen.read_text())["cases"]:
        lane_dir = discovery / Path(case["binary_path"]).name
        lane_dir.mkdir(parents=True)
        candidate = []
        if case["lane"] == "vulnerable":
            candidate = [
                {
                    "candidate_id": f"candidate-{case['id']}",
                    "vulnerability_type": case["vulnerability_type"],
                    "status": "needs_refinement",
                }
            ]
        (lane_dir / "candidates.json").write_text(json.dumps({"candidates": candidate}))
    output = tmp_path / "summary.json"
    summary = summarize_historical_discovery(frozen, discovery, output_path=output)
    assert summary["complete"] is True
    assert summary["vulnerable_only_separation_count"] == 3
    assert summary["proven_report_count"] == 0
    assert summary["candidate_separation_is_not_proof"] is True
    assert output.is_file()


def _patch_v1_manifest(tmp_path: Path, reproducer: bytes) -> Path:
    root = tmp_path / "v1"
    (root / "binaries").mkdir(parents=True)
    (root / "reproducer").mkdir()
    poc = root / "reproducer" / "PoC_df"
    poc.write_bytes(reproducer)
    cases = []
    for lane, version in (
        ("vulnerable", GNU_PATCH_VULNERABLE_PARENT),
        ("fixed", GNU_PATCH_FIX),
    ):
        binary = root / "binaries" / f"patch-{lane}"
        binary.write_bytes(lane.encode())
        cases.append(
            {
                "id": f"gnu-patch-{lane}",
                "comparison_group": "gnu-patch",
                "lane": lane,
                "vulnerability_type": "double_free",
                "binary_path": str(binary.relative_to(root)),
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "reproducer_path": str(poc.relative_to(root)),
                "reproducer_sha256": hashlib.sha256(reproducer).hexdigest(),
                "process_input_model": "stdin",
                "provenance": {"package": "GNU patch", "version": version},
            }
        )
    manifest = root / "frozen_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_kind": "frozen_historical_cve_binary_corpus",
                "corpus_id": "historical-cve-memory-v1",
                "cases": cases,
            }
        )
    )
    return manifest


def _exact_duplicate_trace() -> dict:
    events = [
        {"sequence": 1, "action": "acquire", "identity": 55, "generation": 2},
        {"sequence": 2, "action": "release", "identity": 55, "generation": 2, "live_before": True},
        {
            "sequence": 3,
            "action": "release",
            "identity": 55,
            "generation": 2,
            "live_before": False,
            "exact_second_release": True,
            "operation_address": "0x10FCF0",
        },
    ]
    return {
        "status": "reached",
        "operation_address": "0x10FCF0",
        "artifact_refs": ["trace.json"],
        "lifetime_violation": {
            "vulnerability": "double_free",
            "violation": True,
            "same_resource": True,
            "resource_identity": 55,
            "resource_generation": 2,
            "exact_second_release": True,
            "events": events,
        },
    }


def _clean_control() -> dict:
    return {
        "status": "process_exited",
        "process_wide_control": True,
        "process_wide_duplicate_release": False,
        "lifetime_violation": {"violation": False, "events": []},
        "artifact_refs": ["control.json"],
    }


def test_reproducer_validation_freezes_only_after_differential_gate(tmp_path: Path, monkeypatch) -> None:
    reproducer = b"public-poc"
    manifest = _patch_v1_manifest(tmp_path, reproducer)

    def fake_trace(binary, _reproducer, *, process_wide_control, **_kwargs):
        if binary.name.endswith("vulnerable") and not process_wide_control:
            return _exact_duplicate_trace()
        return _clean_control()

    monkeypatch.setattr("binary_agent.historical_corpus._run_native_duplicate_trace", fake_trace)
    digest = hashlib.sha256(reproducer).hexdigest()
    result = validate_historical_reproducer(
        manifest,
        tmp_path / "runs",
        provenance_url=f"https://example.test/reproducers/{digest}",
        expected_sha256=digest,
        fetcher=lambda _url: reproducer,
    )
    assert result["status"] == "validated"
    frozen = Path(result["frozen_manifest_path"])
    assert frozen.is_file()
    assert verify_historical_corpus(frozen)["verified"] is True
    payload = json.loads(frozen.read_text())
    assert payload["schema_version"] == 2
    assert payload["process_prerequisites"]["argv"] == ["-R", "-f"]
    evidence = frozen.parent / payload["validation_evidence_path"]
    assert hashlib.sha256(evidence.read_bytes()).hexdigest() == payload["validation_evidence_sha256"]

    proof = prove_historical_corpus(frozen, tmp_path / "proof")
    assert proof["status"] == "proven"
    assert proof["report_count"] == 1
    assert proof["fixed_process_wide_duplicate_release"] is False


def test_reproducer_validation_fails_closed_on_provenance_or_fixed_duplicate(tmp_path: Path, monkeypatch) -> None:
    reproducer = b"public-poc"
    digest = hashlib.sha256(reproducer).hexdigest()
    manifest = _patch_v1_manifest(tmp_path, reproducer)
    mutable = validate_historical_reproducer(
        manifest,
        tmp_path / "mutable",
        provenance_url="https://savannah.gnu.org/bugs/?56683",
        expected_sha256=digest,
        fetcher=lambda _url: reproducer,
    )
    assert mutable["status"] == "blocked"
    assert mutable["blocker"] == "reproducer_provenance_url_is_not_immutable"

    def duplicate_fixed(binary, _reproducer, *, process_wide_control, **_kwargs):
        if binary.name.endswith("vulnerable") and not process_wide_control:
            return _exact_duplicate_trace()
        if binary.name.endswith("fixed") and process_wide_control:
            return {
                **_clean_control(),
                "status": "reached",
                "process_wide_duplicate_release": True,
                "lifetime_violation": {"violation": True, "events": [{"action": "release"}]},
            }
        return _clean_control()

    monkeypatch.setattr("binary_agent.historical_corpus._run_native_duplicate_trace", duplicate_fixed)
    result = validate_historical_reproducer(
        manifest,
        tmp_path / "duplicate",
        provenance_url=f"https://example.test/reproducers/{digest}",
        expected_sha256=digest,
        fetcher=lambda _url: reproducer,
    )
    assert result["status"] == "blocked"
    assert result["blocker"] == "public_reproducer_does_not_distinguish_adjacent_revisions"
    assert not result["frozen_manifest_path"]


@pytest.mark.skipif(
    not shutil.which("gdb") or not shutil.which("cc"),
    reason="GDB and a C compiler are required",
)
def test_historical_exact_trace_replays_stdin_and_retains_repeated_breakpoint(tmp_path: Path) -> None:
    source = tmp_path / "stdin_double_free.c"
    binary = tmp_path / "stdin_double_free"
    source.write_text(
        r'''
#include <stdio.h>
#include <stdlib.h>
__attribute__((noinline)) static void exact_release(void *value) {
    __asm__ volatile (
        ".global exact_release_call\n"
        "exact_release_call:\n"
        "call free@PLT\n"
        : : "D" (value) : "rax", "rcx", "r11", "memory");
}
int main(void) {
    if (getchar() != 'X') return 3;
    void *value = malloc(16);
    if (!value) return 2;
    exact_release(value);
    exact_release(value);
    return 0;
}
'''
    )
    subprocess.run(["cc", "-O0", "-fPIE", "-pie", str(source), "-o", str(binary)], check=True)
    symbols = subprocess.check_output(["nm", str(binary)], text=True)
    address = next(
        int(line.split()[0], 16)
        for line in symbols.splitlines()
        if line.endswith(" exact_release_call")
    )

    trace = _run_native_duplicate_trace(
        binary,
        b"X\n",
        argv=(),
        operation_address=hex(address),
        image_base=0,
        process_wide_control=False,
        timeout=20.0,
        artifact_root=tmp_path / "trace",
    )

    assert trace["status"] == "reached"
    assert len(trace["exact_hits"]) == 2
    assert _same_generation_exact_second_release(trace) is True
