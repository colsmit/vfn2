"""Freeze and verify adjacent vulnerable/fixed historical CVE binaries."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from binary_agent.pipeline import CandidateState, write_proof_results
from binary_agent.proof import dispatch_proof, proof_result_reportable, render_backend_finding
from binary_agent.taxonomy import get_vulnerability_spec


HISTORICAL_CORPUS_SCHEMA_VERSION = 1
DEFAULT_HISTORICAL_CORPUS_ID = "historical-cve-memory-v1"
HISTORICAL_V2_CORPUS_ID = "historical-cve-memory-v2"
HISTORICAL_V2_SCHEMA_VERSION = 2
GNU_PATCH_FIX = "15b158db3ae11cb835f2eb8d2eb48e09d1a4af48"
GNU_PATCH_VULNERABLE_PARENT = "dce4683cbbe107a95f1f0d45fabc304acfb5d71a"
_POCS = {
    "GNU patch": "pocs/patch/PoC_df",
    "libtiff tiffcrop": "pocs/libtiff/poc.tif",
    "mruby": "pocs/mruby/cve-2020-6838.rb",
}


def freeze_historical_corpus(
    source_manifest: Path,
    output_root: Path,
    *,
    corpus_id: str = DEFAULT_HISTORICAL_CORPUS_ID,
) -> Path:
    source_file = Path(source_manifest).expanduser().resolve()
    source = _load_json(source_file)
    source_root = source_file.parent
    output = Path(output_root).expanduser().resolve() / corpus_id
    if output.exists():
        raise FileExistsError(f"historical corpus already exists: {output}")
    cases = source.get("cases", [])
    if len(cases) != 6:
        raise ValueError("historical source manifest must contain six cases")
    output.mkdir(parents=True)
    frozen_cases = []
    try:
        for raw in cases:
            if not isinstance(raw, Mapping):
                raise ValueError("historical source case must be an object")
            source_binary = source_root / str(raw.get("binary") or "")
            expected_hash = str(raw.get("binary_sha256") or "")
            if not source_binary.is_file() or _sha256_file(source_binary) != expected_hash:
                raise ValueError(f"historical binary failed source verification: {raw.get('id')}")
            destination = output / "binaries" / source_binary.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_binary, destination)
            provenance = dict(raw.get("provenance") or {})
            package = str(provenance.get("package") or "")
            poc_relative = _POCS.get(package, "")
            frozen_poc = ""
            poc_hash = ""
            if poc_relative:
                poc_source = source_root / poc_relative
                if not poc_source.is_file():
                    raise ValueError(f"historical reproducer is missing for {package}")
                poc_destination = output / "reproducers" / package.lower().replace(" ", "-") / poc_source.name
                poc_destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(poc_source, poc_destination)
                frozen_poc = str(poc_destination.relative_to(output))
                poc_hash = _sha256_file(poc_destination)
            lane = "vulnerable" if str(raw.get("expected_outcome")) == "caught" else "fixed"
            frozen_cases.append(
                {
                    "id": str(raw.get("id") or ""),
                    "comparison_group": package.lower().replace(" ", "-"),
                    "lane": lane,
                    "vulnerability_type": str(raw.get("known_vuln_family") or ""),
                    "binary_path": str(destination.relative_to(output)),
                    "binary_sha256": _sha256_file(destination),
                    "reproducer_path": frozen_poc,
                    "reproducer_sha256": poc_hash,
                    "process_input_model": str(raw.get("process_input_model") or ""),
                    "provenance": provenance,
                    "ground_truth_authority": "adjacent_public_upstream_revision_and_reproducer",
                }
            )
        manifest = output / "frozen_manifest.json"
        _write_json(
            manifest,
            {
                "schema_version": HISTORICAL_CORPUS_SCHEMA_VERSION,
                "artifact_kind": "frozen_historical_cve_binary_corpus",
                "corpus_id": corpus_id,
                "frozen_at": datetime.now(timezone.utc).isoformat(),
                "source_manifest_sha256": _sha256_file(source_file),
                "expected_labels_are_evaluation_only": True,
                "cases": frozen_cases,
            },
        )
        _write_json(
            output / "inventory.json",
            {
                "schema_version": 1,
                "artifact_kind": "historical_corpus_inventory",
                "tree_sha256": _tree_sha256(output, ignored={"inventory.json"}),
            },
        )
        return manifest
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def verify_historical_corpus(manifest_path: Path) -> dict[str, Any]:
    manifest_file = Path(manifest_path).expanduser().resolve()
    payload = _load_json(manifest_file)
    schema_version = int(payload.get("schema_version") or 0)
    if schema_version not in {HISTORICAL_CORPUS_SCHEMA_VERSION, HISTORICAL_V2_SCHEMA_VERSION}:
        raise ValueError("unsupported historical corpus schema")
    root = manifest_file.parent
    failures = []
    groups: dict[str, set[str]] = {}
    for raw in payload.get("cases", []) or []:
        if not isinstance(raw, Mapping):
            failures.append({"id": "", "kind": "invalid_case"})
            continue
        case_id = str(raw.get("id") or "")
        groups.setdefault(str(raw.get("comparison_group") or ""), set()).add(str(raw.get("lane") or ""))
        for kind in ("binary", "reproducer"):
            relative = str(raw.get(f"{kind}_path") or "")
            expected = str(raw.get(f"{kind}_sha256") or "")
            if not relative:
                failures.append({"id": case_id, "kind": kind, "reason": "missing_manifest_path"})
                continue
            path = root / relative
            if not path.is_file():
                failures.append({"id": case_id, "kind": kind, "reason": "missing"})
            elif _sha256_file(path) != expected:
                failures.append({"id": case_id, "kind": kind, "reason": "hash_mismatch"})
    for group, lanes in groups.items():
        if lanes != {"vulnerable", "fixed"}:
            failures.append({"id": group, "kind": "comparison_group", "reason": "unpaired_lanes"})
    if schema_version == HISTORICAL_V2_SCHEMA_VERSION:
        evidence_relative = str(payload.get("validation_evidence_path") or "")
        evidence_hash = str(payload.get("validation_evidence_sha256") or "")
        evidence_path = root / evidence_relative
        if (
            not evidence_relative
            or not evidence_path.is_file()
            or _sha256_file(evidence_path) != evidence_hash
        ):
            failures.append({"kind": "validation_evidence", "reason": "missing_or_hash_mismatch"})
        else:
            evidence = _load_json(evidence_path)
            if not (
                evidence.get("status") == "validated"
                and evidence.get("distinguished_adjacent_revisions") is True
                and evidence.get("vulnerable_exact_duplicate_release") is True
                and evidence.get("fixed_process_wide_duplicate_release") is False
            ):
                failures.append({"kind": "validation_evidence", "reason": "differential_gate_not_satisfied"})
    return {
        "schema_version": schema_version,
        "artifact_kind": "historical_corpus_verification",
        "corpus_id": str(payload.get("corpus_id") or ""),
        "verified": not failures,
        "case_count": len(payload.get("cases", []) or []),
        "comparison_group_count": len(groups),
        "vulnerable_count": sum(isinstance(item, Mapping) and item.get("lane") == "vulnerable" for item in payload.get("cases", []) or []),
        "fixed_count": sum(isinstance(item, Mapping) and item.get("lane") == "fixed" for item in payload.get("cases", []) or []),
        "failures": failures,
    }


def validate_historical_reproducer(
    manifest_path: Path,
    output_root: Path,
    *,
    provenance_url: str,
    expected_sha256: str,
    vulnerable_operation: str = "0x10FCF0",
    argv: Sequence[str] = ("-R", "-f"),
    image_base: int = 0x100000,
    timeout: float = 20.0,
    fetcher: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    """Reacquire and dynamically validate the GNU patch reproducer.

    A v2 pair is written only when the reacquired bytes match the declared
    digest, the vulnerable parent has an exact same-generation second release,
    and a process-wide control observes no duplicate release in the fixed
    revision.  All binaries receive identical traces before manifest labels
    are joined for evaluation.
    """

    manifest_file = Path(manifest_path).expanduser().resolve()
    verification = verify_historical_corpus(manifest_file)
    if not verification["verified"]:
        raise ValueError("historical corpus failed verification")
    source = _load_json(manifest_file)
    if int(source.get("schema_version") or 0) != HISTORICAL_CORPUS_SCHEMA_VERSION:
        raise ValueError("reproducer validation requires immutable historical schema v1")
    run_root = _new_validation_run(Path(output_root).expanduser().resolve())
    validation_path = run_root / "validation.json"
    common = {
        "schema_version": 2,
        "artifact_kind": "historical_reproducer_validation",
        "corpus_id": HISTORICAL_V2_CORPUS_ID,
        "source_manifest": str(manifest_file),
        "source_manifest_sha256": _sha256_file(manifest_file),
        "provenance_url": str(provenance_url),
        "expected_reproducer_sha256": str(expected_sha256).lower(),
        "argv": [str(item) for item in argv],
        "stdin": "reacquired_public_reproducer",
        "cwd": "fresh_empty_directory",
        "vulnerable_operation": _numeric_address(vulnerable_operation),
        "image_base": f"0x{int(image_base):X}",
        "labels_attached_after_tracing": True,
    }
    if not _immutable_provenance_url(provenance_url):
        return _write_blocked_validation(
            validation_path,
            common,
            "reproducer_provenance_url_is_not_immutable",
        )
    try:
        reproducer = (
            fetcher(str(provenance_url))
            if fetcher is not None
            else _download_bytes(str(provenance_url), timeout)
        )
    except Exception as exc:
        return _write_blocked_validation(
            validation_path,
            common,
            f"reproducer_reacquisition_failed:{type(exc).__name__}",
        )
    if not isinstance(reproducer, bytes):
        raise TypeError("historical reproducer fetcher must return bytes")
    acquired_hash = hashlib.sha256(reproducer).hexdigest()
    acquired_path = run_root / "reacquired" / "PoC_df"
    acquired_path.parent.mkdir(parents=True, exist_ok=True)
    acquired_path.write_bytes(reproducer)
    common.update(
        {
            "reacquired_reproducer": str(acquired_path),
            "reacquired_reproducer_sha256": acquired_hash,
        }
    )
    if acquired_hash != str(expected_sha256).lower():
        return _write_blocked_validation(
            validation_path,
            common,
            "reacquired_reproducer_hash_mismatch",
        )

    cases = _gnu_patch_cases(source)
    raw_traces: dict[str, dict[str, Any]] = {}
    # Deliberately do not branch on lane here.  Expected labels are joined only
    # after both trace modes have run on every adjacent revision.
    for raw in sorted(cases, key=lambda item: str(item.get("binary_sha256") or "")):
        case_id = str(raw.get("id") or "")
        binary = manifest_file.parent / str(raw.get("binary_path") or "")
        lane_root = run_root / "traces" / hashlib.sha256(case_id.encode()).hexdigest()[:12]
        raw_traces[case_id] = {
            "exact": _run_native_duplicate_trace(
                binary,
                reproducer,
                argv=argv,
                operation_address=vulnerable_operation,
                image_base=image_base,
                process_wide_control=False,
                timeout=timeout,
                artifact_root=lane_root / "exact",
            ),
            "process_wide": _run_native_duplicate_trace(
                binary,
                reproducer,
                argv=argv,
                operation_address=vulnerable_operation,
                image_base=image_base,
                process_wide_control=True,
                timeout=timeout,
                artifact_root=lane_root / "process-wide",
            ),
        }
    by_lane = {str(item.get("lane") or ""): item for item in cases}
    vulnerable = by_lane["vulnerable"]
    fixed = by_lane["fixed"]
    vulnerable_trace = raw_traces[str(vulnerable.get("id") or "")]["exact"]
    fixed_trace = raw_traces[str(fixed.get("id") or "")]["process_wide"]
    vulnerable_proven = _same_generation_exact_second_release(vulnerable_trace)
    fixed_control_clean = _clean_process_wide_control(fixed_trace)
    distinguished = vulnerable_proven and fixed_control_clean
    result = {
        **common,
        "status": "validated" if distinguished else "blocked",
        "distinguished_adjacent_revisions": distinguished,
        "vulnerable_exact_duplicate_release": vulnerable_proven,
        "fixed_process_wide_duplicate_release": not fixed_control_clean,
        "traces_by_unlabelled_case": raw_traces,
        "evaluated_lanes": {
            "vulnerable_case_id": str(vulnerable.get("id") or ""),
            "fixed_case_id": str(fixed.get("id") or ""),
        },
        "blocker": (
            ""
            if distinguished
            else "public_reproducer_does_not_distinguish_adjacent_revisions"
        ),
    }
    if not distinguished:
        _write_json(validation_path, result)
        return {**result, "validation_path": str(validation_path), "frozen_manifest_path": ""}
    frozen_manifest = _freeze_validated_gnu_patch_pair(
        run_root,
        manifest_file,
        cases,
        reproducer,
        result,
    )
    result["frozen_manifest_path"] = str(frozen_manifest)
    _write_json(validation_path, result)
    return {**result, "validation_path": str(validation_path)}


def prove_historical_corpus(
    manifest_path: Path,
    output_root: Path,
    *,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Produce the schema-v2 report for an already validated v2 pair."""

    manifest_file = Path(manifest_path).expanduser().resolve()
    manifest = _load_json(manifest_file)
    if int(manifest.get("schema_version") or 0) != HISTORICAL_V2_SCHEMA_VERSION:
        raise ValueError("historical proof requires a validated schema-v2 corpus")
    verification = verify_historical_corpus(manifest_file)
    if not verification["verified"]:
        raise ValueError("historical v2 corpus failed verification")
    prerequisite = dict(manifest.get("process_prerequisites") or {})
    argv = tuple(str(item) for item in prerequisite.get("argv", []) or [])
    image_base = int(str(prerequisite.get("image_base") or "0x100000"), 0)
    operation = _numeric_address(str(prerequisite.get("vulnerable_operation") or ""))
    cases = [dict(item) for item in manifest.get("cases", []) if isinstance(item, Mapping)]
    by_lane = {str(item.get("lane") or ""): item for item in cases}
    vulnerable = by_lane["vulnerable"]
    fixed = by_lane["fixed"]
    root = manifest_file.parent
    reproducer = (root / str(vulnerable.get("reproducer_path") or "")).read_bytes()
    run_root = _new_validation_run(Path(output_root).expanduser().resolve(), prefix="proof")
    vulnerable_trace = _run_native_duplicate_trace(
        root / str(vulnerable.get("binary_path") or ""),
        reproducer,
        argv=argv,
        operation_address=operation,
        image_base=image_base,
        process_wide_control=False,
        timeout=timeout,
        artifact_root=run_root / "vulnerable",
    )
    fixed_trace = _run_native_duplicate_trace(
        root / str(fixed.get("binary_path") or ""),
        reproducer,
        argv=argv,
        operation_address=operation,
        image_base=image_base,
        process_wide_control=True,
        timeout=timeout,
        artifact_root=run_root / "fixed-control",
    )
    state = _historical_double_free_candidate(vulnerable, operation, manifest_file)
    lifetime = dict(vulnerable_trace.get("lifetime_violation") or {})
    evidence = {
        "scope": "process_entrypoint",
        "exact_operation_reached": _same_generation_exact_second_release(vulnerable_trace),
        "operation_address": operation,
        "lifetime_violation": lifetime,
        "concrete_input": {
            "stdin_sha256": hashlib.sha256(reproducer).hexdigest(),
            "argv": list(argv),
        },
        "process_setup": {"status": "configured", "cwd": "fresh_empty_directory"},
        "native_replay": {"status": "reached"},
        "artifact_refs": list(vulnerable_trace.get("artifact_refs") or []),
    }
    proof_result = dispatch_proof(state, evidence)
    fixed_clean = _clean_process_wide_control(fixed_trace)
    reports = []
    if proof_result_reportable(state, proof_result) and fixed_clean:
        reports.append(render_backend_finding(state, proof_result))
    write_proof_results([proof_result], run_root / "proof_results.json")
    _write_json(
        run_root / "reports.json",
        {"schema_version": 2, "vulnerabilities": reports},
    )
    result = {
        "schema_version": 2,
        "artifact_kind": "historical_differential_proof",
        "status": "proven" if len(reports) == 1 else "blocked",
        "report_count": len(reports),
        "vulnerable_exact_duplicate_release": _same_generation_exact_second_release(vulnerable_trace),
        "fixed_process_wide_duplicate_release": not fixed_clean,
        "vulnerable_trace": vulnerable_trace,
        "fixed_control_trace": fixed_trace,
        "proof_result": proof_result.to_dict(),
        "report_artifact": str(run_root / "reports.json"),
        "proof_results_artifact": str(run_root / "proof_results.json"),
        "blocker": "" if len(reports) == 1 else "differential_proof_gate_failed",
    }
    _write_json(run_root / "result.json", result)
    return {**result, "result_path": str(run_root / "result.json")}


def summarize_historical_discovery(
    manifest_path: Path,
    discovery_root: Path,
    *,
    output_path: Path | None = None,
) -> dict[str, Any]:
    """Compare discovery candidates across frozen adjacent revisions.

    This is an evaluation-only join.  Ground-truth labels from the frozen
    manifest are read after discovery and never become detector input.  A
    vulnerable-only candidate is still a candidate, not a proven report.
    """

    manifest_file = Path(manifest_path).expanduser().resolve()
    corpus_check = verify_historical_corpus(manifest_file)
    if not corpus_check["verified"]:
        raise ValueError("historical corpus failed verification")
    manifest = _load_json(manifest_file)
    root = Path(discovery_root).expanduser().resolve()
    lanes: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for raw in manifest.get("cases", []) or []:
        if not isinstance(raw, Mapping):
            continue
        case_id = str(raw.get("id") or "")
        binary_name = Path(str(raw.get("binary_path") or "")).name
        candidate_file = root / binary_name / "candidates.json"
        if not candidate_file.is_file():
            failures.append(
                {
                    "id": case_id,
                    "reason": "missing_candidate_artifact",
                    "path": str(candidate_file),
                }
            )
            continue
        payload = _load_json(candidate_file)
        expected_type = str(raw.get("vulnerability_type") or "")
        candidates = [
            item
            for item in payload.get("candidates", []) or []
            if isinstance(item, Mapping)
        ]
        matching = [
            item
            for item in candidates
            if str(item.get("vulnerability_type") or "") == expected_type
        ]
        lanes.append(
            {
                "id": case_id,
                "comparison_group": str(raw.get("comparison_group") or ""),
                "lane": str(raw.get("lane") or ""),
                "expected_vulnerability_type": expected_type,
                "candidate_artifact": str(candidate_file),
                "all_candidate_count": len(candidates),
                "matching_candidate_count": len(matching),
                "matching_candidate_ids": sorted(
                    str(item.get("candidate_id") or "") for item in matching
                ),
                "matching_statuses": sorted({str(item.get("status") or "") for item in matching}),
                "proven_candidate_count": sum(
                    str(item.get("status") or "") == "proven" for item in matching
                ),
            }
        )
    comparisons = []
    group_names = sorted({str(item["comparison_group"]) for item in lanes})
    for group in group_names:
        members = {
            str(item["lane"]): item
            for item in lanes
            if item["comparison_group"] == group
        }
        vulnerable = members.get("vulnerable")
        fixed = members.get("fixed")
        complete = vulnerable is not None and fixed is not None
        if not complete:
            failures.append({"id": group, "reason": "missing_discovery_lane", "path": str(root)})
        vulnerable_count = int(vulnerable["matching_candidate_count"]) if vulnerable else 0
        fixed_count = int(fixed["matching_candidate_count"]) if fixed else 0
        comparisons.append(
            {
                "comparison_group": group,
                "vulnerability_type": str(
                    (vulnerable or fixed or {}).get("expected_vulnerability_type") or ""
                ),
                "complete": complete,
                "vulnerable_matching_candidate_count": vulnerable_count,
                "fixed_matching_candidate_count": fixed_count,
                "vulnerable_only_candidate_separation": complete and vulnerable_count > 0 and fixed_count == 0,
                "proven_report_claimed": False,
            }
        )
    result = {
        "schema_version": 1,
        "artifact_kind": "historical_discovery_differential",
        "corpus_id": str(manifest.get("corpus_id") or ""),
        "evaluation_only": True,
        "ground_truth_labels_used_by_discovery": False,
        "candidate_separation_is_not_proof": True,
        "report_artifacts_evaluated": False,
        "complete": not failures,
        "comparison_count": len(comparisons),
        "vulnerable_only_separation_count": sum(
            bool(item["vulnerable_only_candidate_separation"]) for item in comparisons
        ),
        "proven_candidate_count": sum(
            int(item["proven_candidate_count"]) for item in lanes
        ),
        "proven_report_count": 0,
        "lanes": lanes,
        "comparisons": comparisons,
        "failures": failures,
    }
    if output_path is not None:
        _write_json(Path(output_path).expanduser().resolve(), result)
    return result


def _new_validation_run(output_root: Path, *, prefix: str = "validation") -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    run = output_root / f"{prefix}-{stamp}"
    run.mkdir(parents=True, exist_ok=False)
    return run


def _immutable_provenance_url(value: str) -> bool:
    parsed = urllib.parse.urlparse(str(value))
    if parsed.scheme != "https" or not parsed.netloc:
        return False
    query = urllib.parse.parse_qs(parsed.query)
    if any(query.get(name) for name in ("file_id", "attachment_id")):
        return True
    components = "/".join((parsed.path, parsed.query, parsed.fragment)).lower()
    return any(
        len(token) in {40, 64} and all(character in "0123456789abcdef" for character in token)
        for token in components.replace("=", "/").replace("?", "/").replace("&", "/").split("/")
    )


def _download_bytes(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "binary-agent-historical-reproducer-validator/2"},
    )
    with urllib.request.urlopen(request, timeout=max(1.0, float(timeout))) as response:
        return response.read()


def _write_blocked_validation(
    path: Path,
    common: Mapping[str, Any],
    blocker: str,
) -> dict[str, Any]:
    payload = {
        **dict(common),
        "status": "blocked",
        "distinguished_adjacent_revisions": False,
        "blocker": str(blocker),
        "frozen_manifest_path": "",
    }
    _write_json(path, payload)
    return {**payload, "validation_path": str(path)}


def _gnu_patch_cases(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = [
        dict(item)
        for item in manifest.get("cases", []) or []
        if isinstance(item, Mapping) and str(item.get("comparison_group") or "") == "gnu-patch"
    ]
    by_lane = {str(item.get("lane") or ""): item for item in rows}
    if set(by_lane) != {"vulnerable", "fixed"}:
        raise ValueError("historical corpus must contain one paired GNU patch case")
    versions = {
        lane: str(dict(row.get("provenance") or {}).get("version") or "")
        for lane, row in by_lane.items()
    }
    if versions != {
        "vulnerable": GNU_PATCH_VULNERABLE_PARENT,
        "fixed": GNU_PATCH_FIX,
    }:
        raise ValueError("GNU patch pair is not the required adjacent upstream revisions")
    return rows


def _run_native_duplicate_trace(
    binary: Path,
    reproducer: bytes,
    *,
    argv: Sequence[str],
    operation_address: str,
    image_base: int,
    process_wide_control: bool,
    timeout: float,
    artifact_root: Path,
) -> dict[str, Any]:
    binary = Path(binary).resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)
    stdout_path = artifact_root / "gdb.stdout"
    stderr_path = artifact_root / "gdb.stderr"
    trace_path = artifact_root / "trace.json"
    gdb = shutil.which("gdb")
    source_root = Path(__file__).resolve().parents[2]
    script = source_root / "scripts" / "gdb_exact_memory_trace.py"
    address = int(_numeric_address(operation_address), 16)
    result: dict[str, Any] = {
        "schema_version": 2,
        "status": "unsupported",
        "backend": "gdb_generation_ledger_v2",
        "operation_address": _numeric_address(operation_address),
        "process_wide_control": bool(process_wide_control),
        "artifact_refs": [str(stdout_path), str(stderr_path), str(trace_path)],
    }
    if not gdb or not script.is_file() or not binary.is_file():
        result["blocker"] = "native_trace_prerequisite_missing"
        _write_json(trace_path, result)
        return result
    environment = os.environ.copy()
    environment.update(
        {
            "BINARY_AGENT_BINARY": str(binary),
            "BINARY_AGENT_RELATIVE_ADDRESS": hex(max(0, address - int(image_base))),
            "BINARY_AGENT_STATIC_ADDRESS": _numeric_address(operation_address),
            "BINARY_AGENT_SOURCE_ROOT": str(source_root / "src"),
            "BINARY_AGENT_TRACK_ALLOCATIONS": "1",
            "BINARY_AGENT_TRACK_RESOURCES": "0",
            "BINARY_AGENT_CONTINUE_AFTER_EXACT": "0",
            "BINARY_AGENT_PROCESS_WIDE_DUPLICATE_CONTROL": "1" if process_wide_control else "0",
            "BINARY_AGENT_VULNERABILITY_TYPE": "double_free",
            "BINARY_AGENT_OPERATION_NAME": "free",
        }
    )
    command = [
        gdb,
        "-q",
        "-nx",
        "-batch",
        "-ex",
        "set pagination off",
        "-ex",
        "set confirm off",
        "-ex",
        "set debuginfod enabled off",
        "-ex",
        "starti",
        "-x",
        str(script),
        "--args",
        str(binary),
        *[str(item) for item in argv],
    ]
    try:
        with tempfile.TemporaryDirectory(prefix="binary-agent-patch-") as working:
            completed = subprocess.run(
                command,
                cwd=working,
                env=environment,
                input=reproducer,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=max(1.0, float(timeout)),
                check=False,
            )
        stdout = completed.stdout
        stderr = completed.stderr
        returncode: int | None = completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = bytes(exc.stdout or b"")
        stderr = bytes(exc.stderr or b"")
        returncode = None
        result.update({"status": "unsupported", "blocker": "native_trace_timeout"})
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    marker = _last_trace_marker(stdout)
    if marker:
        result.update(marker)
        result["backend"] = "gdb_generation_ledger_v2"
        result["process_wide_control"] = bool(process_wide_control)
        result["artifact_refs"] = [str(stdout_path), str(stderr_path), str(trace_path)]
    elif "blocker" not in result:
        result.update({"status": "unsupported", "blocker": "native_trace_marker_missing"})
    result["gdb_returncode"] = returncode
    _write_json(trace_path, result)
    return result


def _last_trace_marker(stdout: bytes) -> dict[str, Any]:
    marker = b"BINARY_AGENT_EXACT_MEMORY="
    matches = []
    for row in stdout.splitlines():
        index = row.find(marker)
        if index < 0:
            continue
        try:
            decoded = json.loads(row[index + len(marker) :].decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(decoded, dict):
            matches.append(decoded)
    return matches[-1] if matches else {}


def _same_generation_exact_second_release(trace: Mapping[str, Any]) -> bool:
    violation = dict(trace.get("lifetime_violation") or {})
    identity = violation.get("resource_identity")
    generation = violation.get("resource_generation")
    events = [
        item
        for item in violation.get("events", []) or []
        if isinstance(item, Mapping)
        and item.get("identity") == identity
        and item.get("generation") == generation
    ]
    if not identity or not generation or violation.get("same_resource") is not True:
        return False
    acquire = next((item for item in events if item.get("action") == "acquire"), None)
    first_release = next(
        (
            item
            for item in events
            if item.get("action") == "release" and item.get("live_before") is True
        ),
        None,
    )
    second_release = next(
        (
            item
            for item in events
            if item.get("action") == "release"
            and item.get("live_before") is False
            and item.get("exact_second_release") is True
        ),
        None,
    )
    return bool(
        trace.get("status") == "reached"
        and violation.get("vulnerability") == "double_free"
        and violation.get("violation") is True
        and violation.get("exact_second_release") is True
        and acquire
        and first_release
        and second_release
        and int(acquire.get("sequence") or 0) < int(first_release.get("sequence") or 0)
        < int(second_release.get("sequence") or 0)
        and _numeric_address(str(second_release.get("operation_address") or ""))
        == _numeric_address(str(trace.get("operation_address") or ""))
    )


def _clean_process_wide_control(trace: Mapping[str, Any]) -> bool:
    return bool(
        trace.get("process_wide_control") is True
        and trace.get("status") == "process_exited"
        and trace.get("process_wide_duplicate_release") is False
        and not (dict(trace.get("lifetime_violation") or {}).get("violation") is True)
    )


def _freeze_validated_gnu_patch_pair(
    run_root: Path,
    source_manifest: Path,
    cases: Sequence[Mapping[str, Any]],
    reproducer: bytes,
    validation: Mapping[str, Any],
) -> Path:
    output = run_root / HISTORICAL_V2_CORPUS_ID
    output.mkdir(parents=True, exist_ok=False)
    frozen_cases = []
    for raw in cases:
        binary_source = source_manifest.parent / str(raw.get("binary_path") or "")
        binary_destination = output / "binaries" / binary_source.name
        binary_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary_source, binary_destination)
        reproducer_destination = output / "reproducer" / "PoC_df"
        reproducer_destination.parent.mkdir(parents=True, exist_ok=True)
        if not reproducer_destination.exists():
            reproducer_destination.write_bytes(reproducer)
        frozen_cases.append(
            {
                "id": str(raw.get("id") or ""),
                "comparison_group": "gnu-patch",
                "lane": str(raw.get("lane") or ""),
                "vulnerability_type": "double_free",
                "binary_path": str(binary_destination.relative_to(output)),
                "binary_sha256": _sha256_file(binary_destination),
                "reproducer_path": str(reproducer_destination.relative_to(output)),
                "reproducer_sha256": _sha256_file(reproducer_destination),
                "process_input_model": "stdin",
                "provenance": dict(raw.get("provenance") or {}),
            }
        )
    evidence_path = output / "validation_evidence.json"
    _write_json(
        evidence_path,
        {
            "schema_version": 2,
            "artifact_kind": "gnu_patch_reproducer_validation_evidence",
            "status": str(validation.get("status") or ""),
            "distinguished_adjacent_revisions": validation.get("distinguished_adjacent_revisions") is True,
            "vulnerable_exact_duplicate_release": validation.get("vulnerable_exact_duplicate_release") is True,
            "fixed_process_wide_duplicate_release": validation.get("fixed_process_wide_duplicate_release") is True,
            "labels_attached_after_tracing": validation.get("labels_attached_after_tracing") is True,
            "traces_by_unlabelled_case": dict(validation.get("traces_by_unlabelled_case") or {}),
        },
    )
    manifest_path = output / "frozen_manifest.json"
    _write_json(
        manifest_path,
        {
            "schema_version": 2,
            "artifact_kind": "frozen_historical_cve_differential_corpus",
            "corpus_id": HISTORICAL_V2_CORPUS_ID,
            "frozen_at": datetime.now(timezone.utc).isoformat(),
            "source_manifest_sha256": _sha256_file(source_manifest),
            "expected_labels_are_evaluation_only": True,
            "labels_attached_after_tracing": True,
            "process_prerequisites": {
                "argv": list(validation.get("argv") or []),
                "stdin_sha256": str(validation.get("reacquired_reproducer_sha256") or ""),
                "cwd": "fresh_empty_directory",
                "image_base": str(validation.get("image_base") or ""),
                "vulnerable_operation": str(validation.get("vulnerable_operation") or ""),
            },
            "reproducer_provenance": {
                "immutable_url": str(validation.get("provenance_url") or ""),
                "sha256": str(validation.get("reacquired_reproducer_sha256") or ""),
            },
            "validation_artifact": str(run_root / "validation.json"),
            "validation_evidence_path": str(evidence_path.relative_to(output)),
            "validation_evidence_sha256": _sha256_file(evidence_path),
            "cases": frozen_cases,
        },
    )
    return manifest_path


def _historical_double_free_candidate(
    raw: Mapping[str, Any],
    operation: str,
    manifest_path: Path,
) -> CandidateState:
    spec = get_vulnerability_spec("double_free")
    binary_hash = str(raw.get("binary_sha256") or "")
    return CandidateState(
        candidate_id=f"gnu-patch-cve-2019-20633-{binary_hash[:16]}",
        vulnerability_type="double_free",
        status="proof_ready",
        backend=spec.backend,
        mechanism=spec.mechanism,
        target={
            "binary": Path(str(raw.get("binary_path") or "")).name,
            "sha256": binary_hash,
            "corpus_manifest": str(manifest_path),
        },
        location={"function_name": "another_hunk", "operation_address": operation},
        source={"kind": "stdin", "protocol": "process_stdin"},
        sink={"name": "free", "operation_address": operation},
        operation={"name": "free", "address": operation},
        affected_object={"identity": "runtime_heap_generation"},
        type_facts={"resource_identity": "runtime_heap_generation"},
        proof_obligations=[],
        blockers=[],
        replay_artifacts=[],
    )


def _numeric_address(value: str) -> str:
    text = str(value).strip()
    try:
        number = int(text, 0)
    except ValueError as exc:
        raise ValueError(f"exact operation address must be numeric: {value!r}") from exc
    if number <= 0:
        raise ValueError(f"exact operation address must be positive: {value!r}")
    return f"0x{number:X}"


def _tree_sha256(root: Path, ignored: set[str] | None = None) -> str:
    digest = hashlib.sha256()
    ignored_names = ignored or set()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.name in ignored_names:
            continue
        digest.update(path.relative_to(root).as_posix().encode())
        if path.is_symlink():
            digest.update(b"L" + os.readlink(path).encode())
        elif path.is_file():
            digest.update(b"F" + _sha256_file(path).encode())
        elif path.is_dir():
            digest.update(b"D")
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)
