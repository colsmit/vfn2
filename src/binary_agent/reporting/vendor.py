"""Vendor-submittable evidence bundles for replay-confirmed findings."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.analysis.provenance import source_read_wrapper_chain_from_candidate, source_read_wrapper_chain_text
from binary_agent.dynamic_proof import dynamic_access_metadata
from binary_agent.pipeline import CandidateState, build_source_to_sink_trace
from binary_agent.utils.time import utc_timestamp

from .lean import report_confidence, report_vulnerability_type, select_report_states


VENDOR_BUNDLE_MANIFEST_ARTIFACT_KIND = "vendor_evidence_bundle_manifest"
VENDOR_BUNDLE_INDEX_ARTIFACT_KIND = "vendor_evidence_bundle_index"


@dataclass(frozen=True)
class VendorEvidenceBundle:
    candidate_id: str
    title: str
    directory: Path
    report_path: Path
    manifest_path: Path
    reproducer_path: Path
    artifact_paths: list[Path] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return {
            key: [str(item) for item in value] if isinstance(value, list) else str(value)
            for key, value in payload.items()
        }


def write_vendor_evidence_bundles(
    states: Sequence[CandidateState],
    output_dir: Path,
    *,
    intake_dir: Path | None = None,
) -> list[VendorEvidenceBundle]:
    """Write one self-contained vendor evidence bundle per replay-confirmed report."""
    output_dir.mkdir(parents=True, exist_ok=True)
    intake_facts = _load_intake_facts(intake_dir) if intake_dir else {}
    bundles: list[VendorEvidenceBundle] = []
    for state in select_report_states(states):
        bundle_dir = output_dir / _safe_name(state.candidate_id)
        artifacts_dir = bundle_dir / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        copied_artifacts = _copy_artifacts(state, artifacts_dir)
        request = _load_first_json(state.replay_artifacts, "request.json")
        transcript = _load_first_json(state.replay_artifacts, "native_transcript.json") or _load_first_json(
            state.replay_artifacts,
            "qemu_user_transcript.json",
        )
        replay_result = _replay_result(state)
        binary_row = _binary_row_for_state(state, intake_facts)
        poc_paths = _write_poc_inputs(bundle_dir, replay_result, request)
        reproducer_path = bundle_dir / "reproduce.sh"
        reproducer_path.write_text(_render_reproducer(request, binary_row, replay_result))
        reproducer_path.chmod(0o755)
        expected_path = bundle_dir / "expected_observation.txt"
        expected_path.write_text(_render_expected_observation(transcript, replay_result))
        report_path = bundle_dir / "vendor_report.md"
        report_path.write_text(
            _render_vendor_report(
                state,
                request,
                transcript,
                binary_row,
                [*poc_paths, *copied_artifacts],
                intake_facts=intake_facts,
            )
        )
        manifest_path = bundle_dir / "manifest.json"
        manifest_path.write_text(
            json.dumps(
                _bundle_manifest(
                    state,
                    bundle_dir,
                    binary_row,
                    [report_path, reproducer_path, expected_path, *poc_paths, *copied_artifacts],
                    request=request,
                    intake_facts=intake_facts,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        bundles.append(
            VendorEvidenceBundle(
                candidate_id=state.candidate_id,
                title=_title(state),
                directory=bundle_dir,
                report_path=report_path,
                manifest_path=manifest_path,
                reproducer_path=reproducer_path,
                artifact_paths=[expected_path, *poc_paths, *copied_artifacts],
            )
        )
    index_path = output_dir / "index.json"
    index_path.write_text(
        json.dumps(
            {
                "artifact_kind": VENDOR_BUNDLE_INDEX_ARTIFACT_KIND,
                "schema_version": 1,
                "generated_at": utc_timestamp(),
                "bundles": [bundle.to_dict() for bundle in bundles],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return bundles


def _render_vendor_report(
    state: CandidateState,
    request: Mapping[str, Any],
    transcript: Mapping[str, Any],
    binary_row: Mapping[str, Any],
    copied_artifacts: Sequence[Path],
    *,
    intake_facts: Mapping[str, Any] | None = None,
) -> str:
    facts = dict(state.type_facts)
    static_candidate = facts.get("static_candidate") if isinstance(facts.get("static_candidate"), Mapping) else {}
    location = dict(state.location)
    sink = dict(state.sink)
    replay_result = _replay_result(state)
    replay_mode = str(replay_result.get("mode") or "")
    is_concolic = replay_mode in {"concolic_angr", "ghidra_process", "ghidra_function_harness"}
    is_ghidra_process = replay_mode == "ghidra_process"
    is_ghidra_function_harness = replay_mode == "ghidra_function_harness"
    crash_observed = bool(replay_result.get("crash_observed", False))
    proof_observation = _first_proof_observation(state)
    vulnerability = report_vulnerability_type(state)
    argv = transcript.get("argv", []) if isinstance(transcript.get("argv"), list) else []
    payload = str(argv[1]) if len(argv) > 1 else ""
    stdout = str(transcript.get("stdout") or "")
    stderr = str(transcript.get("stderr") or "")
    socket_response = str(transcript.get("socket_response") or "")
    http_response = str(transcript.get("http_response") or "")
    syslog = str(transcript.get("syslog") or "")
    returncode = transcript.get("returncode", "")
    input_hex = _replay_input_hex(replay_result, request)
    concolic = replay_result.get("control_result") if isinstance(replay_result.get("control_result"), Mapping) else {}
    concolic_replay = concolic.get("concrete_angr_replay") if isinstance(concolic.get("concrete_angr_replay"), Mapping) else {}
    pcode_replay = concolic.get("ghidra_pcode_replay") if isinstance(concolic.get("ghidra_pcode_replay"), Mapping) else {}
    ghidra_proof = _ghidra_dynamic_proof(state, replay_result)
    process_setup = ghidra_proof.get("process_input_setup") if isinstance(ghidra_proof.get("process_input_setup"), Mapping) else {}
    process_replay = ghidra_proof.get("process_replay") if isinstance(ghidra_proof.get("process_replay"), Mapping) else {}
    process_input_provenance = _process_input_provenance(state, process_setup)
    target_provenance = _target_environment_provenance(state, binary_row, request, intake_facts or {})
    wrapper_chain = source_read_wrapper_chain_from_candidate(state.to_dict())
    wrapper_chain_text = source_read_wrapper_chain_text(wrapper_chain)
    confidence_level, confidence_evidence = report_confidence(state)
    proof_status = str(ghidra_proof.get("status") or "")
    proven_condition = str(
        dynamic_access_metadata(proof_status=proof_status, vulnerability=vulnerability)["condition"]
    )
    poc_length = _hex_length(input_hex) if input_hex else len(payload)
    source_summary = _source_summary(state)
    if is_ghidra_process:
        summary = (
            f"An artifact-backed `{vulnerability}` was confirmed in `{binary_row.get('relative_path') or state.target.get('binary')}`. "
            f"Ghidra process replay started at the derived entrypoint with the attached witness input, reached the exact sink, and proved the {proven_condition}."
        )
        reproduction_steps = [
            "1. Use the same binary identified by the SHA-256 above.",
            "2. Use `poc_input.bin` from this bundle as the concrete witness input.",
            "3. Run `./reproduce.sh /path/to/vendor/binary` in a compatible environment and compare with the copied Ghidra process-proof artifact.",
        ]
    elif is_ghidra_function_harness:
        summary = (
            f"An artifact-backed `{vulnerability}` was confirmed in `{binary_row.get('relative_path') or state.target.get('binary')}`. "
            f"Ghidra function-harness replay invoked the target function with the attached witness input, reached the exact sink, and proved the {proven_condition}."
        )
        reproduction_steps = [
            "1. Use the same binary identified by the SHA-256 above.",
            "2. Review `artifacts/ghidra_dynamic_proof.json` for the concrete function-harness input and ABI argument setup.",
            "3. Re-run the Ghidra dynamic proof with that setup and confirm the same proof status and exact sink address recorded below.",
        ]
    elif is_concolic:
        summary = (
            f"An artifact-backed `{vulnerability}` was confirmed in `{binary_row.get('relative_path') or state.target.get('binary')}`. "
            "The concrete angr replay reached the candidate target with the attached witness input, and the Ghidra p-code replay reached the same target instruction."
        )
        reproduction_steps = [
            "1. Use the same binary identified by the SHA-256 above.",
            "2. Use `poc_input.bin` from this bundle as the concrete witness input.",
            "3. Run `./reproduce.sh /path/to/vendor/binary` in a compatible firmware or emulator environment and confirm execution reaches the target address recorded below.",
        ]
    elif crash_observed:
        summary = (
            f"A replay-confirmed `{vulnerability}` was observed in `{binary_row.get('relative_path') or state.target.get('binary')}`. "
            "The binary aborts with the supplied proof-of-concept input, and the replay classifier tied the observed crash to the expected condition."
        )
        reproduction_steps = [
            "1. Use the same binary identified by the SHA-256 above.",
            "2. From this bundle directory, run `./reproduce.sh /path/to/vendor/binary`.",
            "3. Confirm the process exits abnormally and emits the observed stderr shown below.",
        ]
    else:
        summary = (
            f"A replay-confirmed `{vulnerability}` was observed in `{binary_row.get('relative_path') or state.target.get('binary')}`. "
            "The replay produced a dynamic proof observation artifact for the class-specific oracle without requiring a process crash."
        )
        reproduction_steps = [
            "1. Use the same binary identified by the SHA-256 above.",
            "2. Review the replay request and dynamic observation artifacts copied in this bundle.",
            "3. In a compatible firmware or emulator environment, rerun the request and confirm the same dynamic observation status recorded below.",
        ]
    lines = [
        f"# {_title(state)}",
        "",
        "## Summary",
        summary,
        "",
        "## Target Identity",
        f"- Binary path analyzed: `{binary_row.get('path') or state.target.get('path') or state.target.get('binary')}`",
        f"- SHA-256: `{binary_row.get('sha256', '')}`",
        f"- Size: `{binary_row.get('size_bytes', '')}` bytes",
        f"- Architecture: `{binary_row.get('architecture', '')}`",
        *_target_identity_provenance_lines(target_provenance),
        "",
        "## Finding",
        f"- Candidate ID: `{state.candidate_id}`",
        f"- Vulnerability type: `{vulnerability}`",
        f"- Confidence level: `{confidence_level}`",
        *[f"- Confidence evidence: {item}" for item in confidence_evidence],
        f"- Function/address: `{location.get('function_name', '')}` at `{location.get('address', '')}`",
        f"- Decompiled location: `{location.get('relative_path', '')}:{location.get('line_number', '')}`",
        f"- Sink: `{sink.get('name') or static_candidate.get('sink', '')}`",
        f"- Destination object: `{sink.get('target_buffer') or static_candidate.get('target_buffer', '')}`",
        f"- Destination capacity: `{facts.get('capacity_bytes') or static_candidate.get('capacity_bytes', '')}` bytes",
        f"- Root cause: {facts.get('overflow_condition') or static_candidate.get('overflow_condition', '')}",
        "",
        "## Static Evidence",
        f"- Decompiled sink line: `{location.get('line_text', '')}`",
        f"- Capacity basis: `{facts.get('capacity_basis') or static_candidate.get('capacity_basis', '')}`",
        f"- Source/control evidence: {source_summary}",
        *([f"- Source-read wrapper chain: `{wrapper_chain_text}`"] if wrapper_chain_text else []),
        "",
        "## Source-to-Sink Trace",
        *_source_to_sink_trace_lines(state, request, transcript),
        "",
        "## Replay Evidence",
        f"- Replay result: `{replay_result.get('result', '')}`",
        f"- Replay mode: `{replay_result.get('mode', '')}`",
        f"- Concolic verdict: `{concolic.get('concolic_verdict', '')}`",
        f"- Sink reached: `{replay_result.get('sink_reached', '')}`",
        f"- Bug observed: `{replay_result.get('bug_observed', '')}`",
        f"- Crash observed: `{replay_result.get('crash_observed', '')}`",
        f"- Dynamic observation status: `{proof_observation.get('status', '')}`",
        f"- Dynamic observation kind: `{proof_observation.get('kind', '')}`",
        f"- Process return code: `{returncode}`",
        f"- Target address reached: `{concolic_replay.get('target_loader_address') or (request.get('setup') or {}).get('target_address') if isinstance(request.get('setup'), Mapping) else ''}`",
        f"- P-code replay status: `{pcode_replay.get('status', '')}`",
        f"- Process proof scope: `{ghidra_proof.get('proof_scope', '')}`",
        f"- Process input model: `{process_setup.get('input_model', '')}`",
        f"- Process input setup: `{process_setup.get('status', '')}`",
        f"- Process input source: `{process_input_provenance.get('source', '')}`",
        f"- Process input inferred: `{process_input_provenance.get('inferred', '')}`",
        f"- File seed reason: `{process_input_provenance.get('file_seed_reason', '')}`",
        f"- Decompile source file: `{process_input_provenance.get('decompile_source_file', '')}`",
        f"- Process replay status: `{process_replay.get('status', '')}`",
        f"- Ghidra proof status: `{proof_status}`",
        f"- Dynamic overflow bytes: `{ghidra_proof.get('overflow_bytes', '')}`",
        f"- Dynamic OOB-read bytes: `{ghidra_proof.get('oob_bytes', '')}`",
        f"- Exact sink reached: `{ghidra_proof.get('exact_sink_reached', '')}`",
        f"- PoC payload length: `{poc_length}` bytes",
        "",
        "## Reproduction Steps",
        *reproduction_steps,
        "",
        "Observed stderr:",
        "",
        "    " + (stderr.strip() or "(empty)").replace("\n", "\n    "),
        "",
        "Observed stdout:",
        "",
        "    " + (stdout.strip() or "(empty)").replace("\n", "\n    "),
        "",
        "Observed socket response:",
        "",
        "    " + (socket_response.strip() or "(empty)").replace("\n", "\n    "),
        "",
        "Observed HTTP response:",
        "",
        "    " + (http_response.strip() or "(empty)").replace("\n", "\n    "),
        "",
        "Observed syslog:",
        "",
        "    " + (syslog.strip() or "(empty)").replace("\n", "\n    "),
        "",
        "## Artifact Manifest",
        *[f"- `{path.relative_to(path.parents[1]) if len(path.parents) > 1 else path.name}`" for path in copied_artifacts],
        "- `reproduce.sh`",
        "- `expected_observation.txt`",
        "- `manifest.json`",
        "",
        "## Impact",
        _impact_summary(
            vulnerability=vulnerability,
            is_concolic=is_concolic,
            crash_observed=crash_observed,
            proof_observation=proof_observation,
            replay_mode=replay_mode,
            proof_status=proof_status,
        ),
        "",
        "## Suggested Fix",
        _suggested_fix(state),
        "",
        "## Evidence Scope",
        "- Function names such as `FUN_...` are decompiler labels recovered from the stripped binary.",
        "- The bundle includes the semantic seed when present, concrete replay result, dynamic observation, static evidence, and copied replay artifacts listed above.",
        "",
    ]
    return "\n".join(lines)


def _impact_summary(
    *,
    vulnerability: str = "",
    is_concolic: bool,
    crash_observed: bool,
    proof_observation: Mapping[str, Any],
    replay_mode: str = "",
    proof_status: str = "",
) -> str:
    if replay_mode == "ghidra_process":
        impact = dynamic_access_metadata(proof_status=proof_status, vulnerability=vulnerability)["impact"]
        return (
            "The attached witness demonstrates exact-sink reachability from the derived process entrypoint "
            f"and a proven {impact} in Ghidra process replay."
        )
    if replay_mode == "ghidra_function_harness":
        impact = dynamic_access_metadata(proof_status=proof_status, vulnerability=vulnerability)["impact"]
        return f"The attached witness demonstrates exact-sink reachability in a Ghidra function harness and a proven {impact}."
    if is_concolic:
        return "The attached witness demonstrates the candidate memory-corruption condition under concrete angr replay and Ghidra p-code target replay."
    if crash_observed:
        return "The provided PoC demonstrates a process abort from memory-corruption defenses for the supplied binary/input pair."
    status = str(proof_observation.get("status") or "the class-specific oracle condition")
    return f"The provided replay demonstrates `{status}` through a dynamic proof observation without requiring a process crash."


def _render_reproducer(request: Mapping[str, Any], binary_row: Mapping[str, Any], replay_result: Mapping[str, Any] | None = None) -> str:
    replay_result = replay_result or {}
    if replay_result.get("mode") == "ghidra_function_harness":
        return "\n".join(
            [
                "#!/bin/sh",
                "set -eu",
                'echo "This finding is backed by Ghidra function-harness replay."',
                'echo "Review artifacts/ghidra_dynamic_proof.json for the concrete input and ABI argument setup."',
                "",
            ]
        )
    if replay_result.get("mode") in {"concolic_angr", "ghidra_process"}:
        default_binary = str(binary_row.get("path") or "")
        input_model = _replay_input_model(replay_result, request) or "stdin"
        input_arg = '< "$INPUT_PATH"' if input_model == "stdin" else '"$INPUT_PATH"'
        return "\n".join(
            [
                "#!/bin/sh",
                "set -eu",
                f'BINARY_PATH="${{1:-{default_binary}}}"',
                'INPUT_PATH="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/poc_input.bin"',
                "if [ ! -f \"$INPUT_PATH\" ]; then",
                "  echo \"missing poc_input.bin\" >&2",
                "  exit 2",
                "fi",
                "if [ ! -x \"$BINARY_PATH\" ]; then",
                "  echo \"usage: $0 /path/to/vendor/binary\" >&2",
                "  exit 2",
                "fi",
                'RUNNER="${QEMU_USER_BIN:-}"',
                "if [ -n \"$RUNNER\" ]; then",
                f'  exec "$RUNNER" "$BINARY_PATH" {input_arg}',
                "fi",
                f'exec "$BINARY_PATH" {input_arg}',
                "",
            ]
        )
    argv = []
    input_payload = request.get("input") if isinstance(request.get("input"), Mapping) else {}
    if isinstance(input_payload, Mapping):
        argv = input_payload.get("argv", []) if isinstance(input_payload.get("argv"), list) else []
    payload = str(argv[0]) if argv else "A" * 128
    default_binary = str(binary_row.get("path") or "")
    return "\n".join(
        [
            "#!/bin/sh",
            "set -eu",
            f'BINARY_PATH="${{1:-{default_binary}}}"',
            "if [ ! -x \"$BINARY_PATH\" ]; then",
            "  echo \"usage: $0 /path/to/binary\" >&2",
            "  exit 2",
            "fi",
            "PAYLOAD=$(python3 - <<'PY'",
            f"print({payload!r})",
            "PY",
            ")",
            "exec \"$BINARY_PATH\" \"$PAYLOAD\"",
            "",
        ]
    )


def _render_expected_observation(transcript: Mapping[str, Any], replay_result: Mapping[str, Any] | None = None) -> str:
    replay_result = replay_result or {}
    control = replay_result.get("control_result") if isinstance(replay_result.get("control_result"), Mapping) else {}
    if replay_result.get("mode") in {"concolic_angr", "ghidra_process", "ghidra_function_harness"}:
        concrete = control.get("concrete_angr_replay") if isinstance(control.get("concrete_angr_replay"), Mapping) else {}
        pcode = control.get("ghidra_pcode_replay") if isinstance(control.get("ghidra_pcode_replay"), Mapping) else {}
        proof = control.get("ghidra_dynamic_proof") if isinstance(control.get("ghidra_dynamic_proof"), Mapping) else {}
        return "\n".join(
            [
                f"replay_result: {replay_result.get('result', '')}",
                f"replay_mode: {replay_result.get('mode', '')}",
                f"concolic_verdict: {control.get('concolic_verdict', '')}",
                f"angr_status: {concrete.get('status', '')}",
                f"target_loader_address: {concrete.get('target_loader_address', '')}",
                f"pcode_status: {pcode.get('status', '')}",
                f"pcode_reached_target: {pcode.get('reached_target', '')}",
                f"ghidra_proof_scope: {proof.get('proof_scope', '')}",
                f"ghidra_proof_status: {proof.get('status', '')}",
                f"ghidra_sink_address: {proof.get('sink_address', '')}",
            "",
        ]
    )
    socket_response = transcript.get("socket_response") or control.get("socket_response") or ""
    http_response = transcript.get("http_response") or control.get("http_response") or ""
    syslog = transcript.get("syslog") or control.get("syslog") or ""
    return "\n".join(
        [
            f"returncode: {transcript.get('returncode', '')}",
            "stderr:",
            str(transcript.get("stderr") or "").rstrip(),
            "stdout:",
            str(transcript.get("stdout") or "").rstrip(),
            "socket_response:",
            str(socket_response).rstrip(),
            "http_response:",
            str(http_response).rstrip(),
            "syslog:",
            str(syslog).rstrip(),
            "",
        ]
    )


def _bundle_manifest(
    state: CandidateState,
    bundle_dir: Path,
    binary_row: Mapping[str, Any],
    paths: Sequence[Path],
    *,
    request: Mapping[str, Any] | None = None,
    intake_facts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    request = request or {}
    intake_facts = intake_facts or {}
    files = _bundle_file_rows(bundle_dir, paths)
    target_provenance = _target_environment_provenance(state, binary_row, request, intake_facts)
    return {
        "artifact_kind": VENDOR_BUNDLE_MANIFEST_ARTIFACT_KIND,
        "schema_version": 1,
        "generated_at": utc_timestamp(),
        "candidate_id": state.candidate_id,
        "vulnerability_type": state.vulnerability_type,
        "target": dict(state.target),
        "binary": dict(binary_row),
        "target_provenance": target_provenance,
        "reproduction_environment": dict(target_provenance.get("reproduction_environment") or {})
        if isinstance(target_provenance.get("reproduction_environment"), Mapping)
        else {},
        "environment_artifacts": _environment_artifact_refs(files),
        "files": files,
    }


def _bundle_file_rows(bundle_dir: Path, paths: Sequence[Path]) -> list[dict[str, Any]]:
    return [
        {
            "path": str(path.relative_to(bundle_dir)),
            "sha256": _sha256(path),
            "size_bytes": path.stat().st_size,
        }
        for path in paths
        if path.exists()
    ]


def _environment_artifact_refs(files: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for row in files:
        path = str(row.get("path") or "")
        for role in _environment_artifact_roles(path):
            refs.append({"role": role, **dict(row)})
    return refs


def _environment_artifact_roles(relative_path: str) -> list[str]:
    name = Path(relative_path).name
    roles: list[str] = []
    if name == "vendor_report.md":
        roles.append("vendor_report")
    if name == "reproduce.sh":
        roles.append("reproducer")
    if name == "expected_observation.txt":
        roles.append("expected_observation")
    if name == "poc_input.bin":
        roles.append("proof_of_concept_input")
    if name == "request.json":
        roles.append("replay_request")
    if name == "result.json":
        roles.append("replay_result")
    if name in {"native_transcript.json", "qemu_user_transcript.json"}:
        roles.append("replay_transcript")
    if name == "ghidra_dynamic_proof.json":
        roles.append("dynamic_proof")
    if name == "service_replay_result.json":
        roles.append("service_replay_result")
    if name.endswith("_source_to_sink_trace.json") or name == "source_to_sink_trace.json":
        roles.append("source_to_sink_trace")
    if name.endswith("_bug_bounty_evidence.json") or name == "bug_bounty_evidence.json":
        roles.append("bug_bounty_evidence")
    if name.startswith("dynamic_") and name.endswith("_observation.json"):
        roles.append("dynamic_observation")
    if name == "verdict.json":
        roles.append("concolic_verdict")
    if name == "replay.json":
        roles.append("concolic_replay")
    return roles


def _target_environment_provenance(
    state: CandidateState,
    binary_row: Mapping[str, Any],
    request: Mapping[str, Any],
    intake_facts: Mapping[str, Any],
) -> dict[str, Any]:
    target = dict(state.target)
    setup = request.get("setup") if isinstance(request.get("setup"), Mapping) else {}
    input_payload = request.get("input") if isinstance(request.get("input"), Mapping) else {}
    matched_services = _service_rows_for_binary(binary_row, intake_facts)
    startup_command = str(setup.get("startup_command") or setup.get("command") or "")
    if not startup_command and matched_services:
        startup_command = str(matched_services[0].get("exec") or "")
    rootfs_path = str(
        setup.get("rootfs_path")
        or setup.get("qemu_rootfs")
        or target.get("rootfs_path")
        or target.get("firmware_target")
        or binary_row.get("source_target")
        or ""
    )
    product = str(target.get("product") or target.get("product_name") or _nested(intake_facts, "target", "product") or "")
    version = str(
        target.get("version")
        or target.get("firmware_version")
        or _nested(intake_facts, "target", "version")
        or _nested(intake_facts, "target", "firmware_version")
        or ""
    )
    return {
        key: value
        for key, value in {
            "binary_path": binary_row.get("path") or target.get("path") or target.get("binary"),
            "binary_relative_path": binary_row.get("relative_path") or target.get("relative_path"),
            "binary_sha256": binary_row.get("sha256") or target.get("sha256"),
            "package": target.get("package") or target.get("package_name"),
            "product": product,
            "version": version,
            "rootfs_path": rootfs_path,
            "architecture": binary_row.get("architecture") or target.get("architecture"),
            "startup_command": startup_command,
            "replay_mode": request.get("mode"),
            "input_model": input_payload.get("input_model"),
            "services": matched_services,
            "routes": _route_rows_for_state(state, intake_facts),
            "configs": _config_rows_for_state(state, intake_facts),
            "reproduction_environment": {
                "rootfs_path": rootfs_path,
                "architecture": binary_row.get("architecture") or target.get("architecture") or "",
                "startup_command": startup_command,
                "replay_mode": request.get("mode") or "",
                "input_model": input_payload.get("input_model") or "",
            },
        }.items()
        if value not in (None, "", [], {})
    }


def _target_identity_provenance_lines(provenance: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    for label, key in (
        ("Package", "package"),
        ("Product", "product"),
        ("Version", "version"),
        ("Rootfs path", "rootfs_path"),
        ("Startup command", "startup_command"),
    ):
        value = provenance.get(key)
        if value:
            lines.append(f"- {label}: `{value}`")
    services = provenance.get("services")
    if isinstance(services, list) and services:
        rendered = []
        for row in services[:3]:
            if not isinstance(row, Mapping):
                continue
            name = str(row.get("name") or row.get("service_id") or "")
            exec_value = str(row.get("exec") or row.get("relative_path") or "")
            rendered.append(f"{name} ({exec_value})" if name and exec_value else name or exec_value)
        rendered = [item for item in rendered if item]
        if rendered:
            lines.append(f"- Matched service: `{'; '.join(rendered)}`")
    return lines


def _nested(value: Mapping[str, Any], *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _service_rows_for_binary(binary_row: Mapping[str, Any], intake_facts: Mapping[str, Any]) -> list[dict[str, Any]]:
    services = intake_facts.get("services")
    rows = services.get("services", []) if isinstance(services, Mapping) else []
    if not isinstance(rows, list):
        return []
    binary_terms = _identity_terms(
        binary_row.get("path"),
        binary_row.get("relative_path"),
        Path(str(binary_row.get("path") or binary_row.get("relative_path") or "")).name,
    )
    matched: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        haystack = " ".join(_flatten_strings(row)).lower()
        if binary_terms and not any(term.lower() in haystack for term in binary_terms):
            continue
        matched.append(_compact_row(row, ("service_id", "name", "path", "relative_path", "exec", "ports", "evidence")))
    return matched[:8]


def _route_rows_for_state(state: CandidateState, intake_facts: Mapping[str, Any]) -> list[dict[str, Any]]:
    routes = intake_facts.get("routes")
    rows = routes.get("routes", []) if isinstance(routes, Mapping) else []
    if not isinstance(rows, list):
        return []
    terms = _identity_terms(*_candidate_route_terms(state))
    if not terms:
        return [_compact_row(row, ("route_id", "route", "method", "path", "relative_path", "evidence")) for row in rows[:4] if isinstance(row, Mapping)]
    matched: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        haystack = " ".join(_flatten_strings(row)).lower()
        if any(term.lower() in haystack for term in terms):
            matched.append(_compact_row(row, ("route_id", "route", "method", "path", "relative_path", "evidence")))
    return matched[:8]


def _config_rows_for_state(state: CandidateState, intake_facts: Mapping[str, Any]) -> list[dict[str, Any]]:
    configs = intake_facts.get("configs")
    rows = configs.get("configs", []) if isinstance(configs, Mapping) else []
    if not isinstance(rows, list):
        return []
    terms = _identity_terms(*_candidate_config_terms(state))
    matched: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        haystack = " ".join(_flatten_strings(row)).lower()
        if terms and not any(term.lower() in haystack for term in terms):
            continue
        matched.append(_compact_row(row, ("config_id", "path", "relative_path", "kind", "env_keys", "evidence")))
    return matched[:8]


def _candidate_route_terms(state: CandidateState) -> list[str]:
    facts = dict(state.type_facts)
    process_input = facts.get("process_input") if isinstance(facts.get("process_input"), Mapping) else {}
    terms = [
        state.source.get("route") if isinstance(state.source, Mapping) else "",
        state.source.get("expression") if isinstance(state.source, Mapping) else "",
        process_input.get("route") if isinstance(process_input, Mapping) else "",
        process_input.get("path") if isinstance(process_input, Mapping) else "",
        process_input.get("endpoint") if isinstance(process_input, Mapping) else "",
    ]
    semantic_seed = facts.get("semantic_seed") if isinstance(facts.get("semantic_seed"), Mapping) else {}
    replay_hints = semantic_seed.get("replay_hints") if isinstance(semantic_seed.get("replay_hints"), Mapping) else {}
    hint_input = replay_hints.get("input") if isinstance(replay_hints.get("input"), Mapping) else {}
    if isinstance(hint_input, Mapping):
        terms.extend([hint_input.get("path"), hint_input.get("route"), hint_input.get("endpoint")])
    return [str(term) for term in terms if str(term or "").startswith("/")]


def _candidate_config_terms(state: CandidateState) -> list[str]:
    terms: list[str] = []
    for value in _flatten_strings(state.to_dict()):
        if "/" in value or value.isupper() or value.endswith((".conf", ".cfg", ".ini", ".env", ".json", ".xml")):
            terms.append(value)
    return terms


def _identity_terms(*values: Any) -> list[str]:
    terms: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        terms.append(text)
        basename = Path(text).name
        if basename and basename != text:
            terms.append(basename)
    seen: set[str] = set()
    result: list[str] = []
    for term in terms:
        lowered = term.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        result.append(term)
    return result


def _compact_row(row: Mapping[str, Any], keys: Sequence[str]) -> dict[str, Any]:
    return {key: row[key] for key in keys if row.get(key) not in (None, "", [], {})}


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        strings: list[str] = []
        for item in value.values():
            strings.extend(_flatten_strings(item))
        return strings
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        strings = []
        for item in value:
            strings.extend(_flatten_strings(item))
        return strings
    return []


def _copy_artifacts(state: CandidateState, artifacts_dir: Path) -> list[Path]:
    copied: list[Path] = []
    seen: set[Path] = set()
    for path in _bundle_artifact_paths(state):
        if not path.exists() or path in seen:
            continue
        seen.add(path)
        target = artifacts_dir / path.name
        if target.exists():
            target = artifacts_dir / f"{_sha256(path)[:8]}_{path.name}"
        shutil.copy2(path, target)
        copied.append(target)
    return copied


def _bundle_artifact_paths(state: CandidateState) -> list[Path]:
    paths: list[Path] = []
    for raw in [*state.validation_artifacts, *state.replay_artifacts, *state.report_artifacts]:
        path = Path(raw)
        paths.append(path)
        if raw in state.replay_artifacts:
            sibling_result = path.with_name("result.json")
            if sibling_result.exists():
                paths.append(sibling_result)
    return paths


def _load_first_json(paths: Sequence[str], name: str) -> dict[str, Any]:
    for raw in paths:
        path = Path(raw)
        if path.name != name or not path.exists():
            continue
        try:
            payload = json.loads(path.read_text() or "{}")
        except json.JSONDecodeError:
            continue
        if isinstance(payload, Mapping):
            return dict(payload)
    return {}


def _replay_result(state: CandidateState) -> dict[str, Any]:
    for raw in state.replay_artifacts:
        path = Path(raw)
        result_path = path.with_name("result.json")
        if result_path.exists():
            try:
                payload = json.loads(result_path.read_text() or "{}")
            except json.JSONDecodeError:
                continue
            if isinstance(payload, Mapping):
                return dict(payload)
    return {}


def _first_proof_observation(state: CandidateState) -> dict[str, Any]:
    for raw in state.replay_artifacts:
        path = Path(raw)
        if not path.name.endswith("_observation.json") and path.name not in {
            "dynamic_overflow_observation.json",
            "target_overflow_observation.json",
        }:
            continue
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text() or "{}")
        except json.JSONDecodeError:
            continue
        if isinstance(payload, Mapping):
            return dict(payload)
    replay_result = _replay_result(state)
    control = replay_result.get("control_result") if isinstance(replay_result.get("control_result"), Mapping) else {}
    observation = control.get("proof_observation") if isinstance(control.get("proof_observation"), Mapping) else {}
    return dict(observation)


def _ghidra_dynamic_proof(state: CandidateState, replay_result: Mapping[str, Any]) -> dict[str, Any]:
    control = replay_result.get("control_result") if isinstance(replay_result.get("control_result"), Mapping) else {}
    proof = control.get("ghidra_dynamic_proof") if isinstance(control.get("ghidra_dynamic_proof"), Mapping) else {}
    if proof:
        return dict(proof)
    for raw in state.replay_artifacts:
        path = Path(raw)
        if path.name != "ghidra_dynamic_proof.json" or not path.exists():
            continue
        try:
            payload = json.loads(path.read_text() or "{}")
        except json.JSONDecodeError:
            continue
        if isinstance(payload, Mapping):
            return dict(payload)
    return {}


def _process_input_provenance(state: CandidateState, process_setup: Mapping[str, Any]) -> dict[str, Any]:
    facts = dict(state.type_facts)
    process_input = facts.get("process_input") if isinstance(facts.get("process_input"), Mapping) else {}
    evidence = process_setup.get("process_input_evidence") if isinstance(process_setup.get("process_input_evidence"), Mapping) else {}
    if not evidence and isinstance(process_input.get("process_input_evidence"), Mapping):
        evidence = process_input["process_input_evidence"]
    source = str(process_setup.get("process_input_source") or process_input.get("process_input_source") or "")
    return {
        "source": source,
        "inferred": bool(process_input.get("inferred")) or source.startswith("inferred_"),
        "file_seed_reason": str(evidence.get("file_seed_reason") or ""),
        "decompile_source_file": str(evidence.get("decompile_source_file") or evidence.get("source_path") or ""),
    }


def _write_poc_inputs(bundle_dir: Path, replay_result: Mapping[str, Any], request: Mapping[str, Any]) -> list[Path]:
    input_hex = _replay_input_hex(replay_result, request)
    if not input_hex:
        return []
    try:
        data = bytes.fromhex(input_hex)
    except ValueError:
        return []
    path = bundle_dir / "poc_input.bin"
    path.write_bytes(data)
    return [path]


def _replay_input_hex(replay_result: Mapping[str, Any], request: Mapping[str, Any]) -> str:
    request_input = request.get("input") if isinstance(request.get("input"), Mapping) else {}
    if isinstance(request_input, Mapping) and request_input.get("input_hex"):
        return str(request_input["input_hex"])
    control = replay_result.get("control_result") if isinstance(replay_result.get("control_result"), Mapping) else {}
    witness = control.get("witness") if isinstance(control.get("witness"), Mapping) else {}
    concrete = control.get("concrete_angr_replay") if isinstance(control.get("concrete_angr_replay"), Mapping) else {}
    proof = control.get("ghidra_dynamic_proof") if isinstance(control.get("ghidra_dynamic_proof"), Mapping) else {}
    setup = proof.get("process_input_setup") if isinstance(proof.get("process_input_setup"), Mapping) else {}
    if setup.get("concrete_input_hex"):
        return str(setup["concrete_input_hex"])
    for source in (witness, concrete):
        if isinstance(source, Mapping):
            for key in ("stdin_hex", "input_hex"):
                if source.get(key):
                    return str(source[key])
            argv_hex = source.get("argv_hex")
            if isinstance(argv_hex, list) and argv_hex:
                return str(argv_hex[0])
    return ""


def _replay_input_model(replay_result: Mapping[str, Any], request: Mapping[str, Any]) -> str:
    request_input = request.get("input") if isinstance(request.get("input"), Mapping) else {}
    if isinstance(request_input, Mapping) and request_input.get("input_model"):
        return str(request_input["input_model"])
    control = replay_result.get("control_result") if isinstance(replay_result.get("control_result"), Mapping) else {}
    witness = control.get("witness") if isinstance(control.get("witness"), Mapping) else {}
    if isinstance(witness, Mapping) and witness.get("input_model"):
        return str(witness["input_model"])
    return ""


def _hex_length(input_hex: str) -> int:
    try:
        return len(bytes.fromhex(input_hex))
    except ValueError:
        return 0


def _load_intake_facts(intake_dir: Path | None) -> dict[str, Any]:
    if not intake_dir:
        return {}
    facts: dict[str, Any] = {}
    for name in ("target", "binaries", "services", "routes", "configs", "analysis_manifest"):
        path = Path(intake_dir) / f"{name}.json"
        if not path.exists():
            continue
        try:
            facts[name] = json.loads(path.read_text() or "{}")
        except json.JSONDecodeError:
            facts[name] = {}
    return facts


def _binary_row_for_state(state: CandidateState, intake_facts: Mapping[str, Any]) -> dict[str, Any]:
    binaries = intake_facts.get("binaries")
    if isinstance(binaries, Mapping):
        rows = binaries.get("binaries", [])
        if isinstance(rows, list) and rows:
            target = dict(state.target)
            desired_path = str(target.get("path") or "")
            desired_relative = str(target.get("relative_path") or target.get("component") or target.get("binary") or "")
            desired_sha = str(target.get("sha256") or "")
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                if desired_sha and str(row.get("sha256") or "") == desired_sha:
                    return dict(row)
                if desired_path and str(row.get("path") or "") == desired_path:
                    return dict(row)
                if desired_relative and str(row.get("relative_path") or "") == desired_relative:
                    return dict(row)
            basename = Path(desired_relative).name
            if basename:
                for row in rows:
                    if isinstance(row, Mapping) and Path(str(row.get("relative_path") or row.get("path") or "")).name == basename:
                        return dict(row)
            return dict(rows[0]) if isinstance(rows[0], Mapping) else {}
    return {"path": state.target.get("path", ""), "relative_path": state.target.get("binary", ""), "sha256": ""}


def _source_summary(state: CandidateState) -> str:
    facts = dict(state.type_facts)
    static_candidate = facts.get("static_candidate") if isinstance(facts.get("static_candidate"), Mapping) else {}
    trace = static_candidate.get("classification_trace") if isinstance(static_candidate, Mapping) else {}
    source_to_write = trace.get("source_to_write") if isinstance(trace, Mapping) else {}
    roles = source_to_write.get("roles") if isinstance(source_to_write, Mapping) else {}
    if isinstance(roles, Mapping):
        source = roles.get("write_source")
        if isinstance(source, Mapping):
            classification = source.get("classification", "")
            evidence = "; ".join(str(item) for item in source.get("evidence", []) or [])
            return f"`write_source` is `{classification}`. {evidence}".strip()
    if state.source.get("kind"):
        return str(state.source["kind"])
    return "No source proof beyond replay is claimed."


def _source_to_sink_trace_lines(
    state: CandidateState,
    request: Mapping[str, Any],
    transcript: Mapping[str, Any],
) -> list[str]:
    normalized = build_source_to_sink_trace(state).to_dict()
    if normalized.get("argument_roles") or normalized.get("propagation_path"):
        return _normalized_source_to_sink_trace_lines(normalized, request, transcript)

    facts = dict(state.type_facts)
    static_candidate = facts.get("static_candidate") if isinstance(facts.get("static_candidate"), Mapping) else {}
    trace = static_candidate.get("classification_trace") if isinstance(static_candidate, Mapping) else {}
    source_to_write = trace.get("source_to_write") if isinstance(trace, Mapping) else {}
    roles = source_to_write.get("roles") if isinstance(source_to_write, Mapping) else {}
    reachability = trace.get("reachability_dataflow") if isinstance(trace, Mapping) else {}
    graph = reachability.get("graph") if isinstance(reachability, Mapping) else {}
    source_link = reachability.get("source_link") if isinstance(reachability, Mapping) else {}
    request_input = request.get("input") if isinstance(request.get("input"), Mapping) else {}
    replay_argv = request_input.get("argv", []) if isinstance(request_input, Mapping) else []
    transcript_argv = transcript.get("argv", []) if isinstance(transcript.get("argv"), list) else []

    lines: list[str] = []
    write_source = roles.get("write_source") if isinstance(roles, Mapping) else {}
    if isinstance(write_source, Mapping):
        lines.append(
            "- Local static dataflow: sink source expression "
            f"`{write_source.get('expr', '')}` is classified as `{write_source.get('classification', '')}`."
        )
        evidence = [str(item) for item in write_source.get("evidence", []) or []]
        if evidence:
            lines.append(f"- Local source evidence: {'; '.join(evidence)}")
    else:
        lines.append("- Local static dataflow: no recovered source expression for the sink argument.")

    if isinstance(graph, Mapping):
        path = graph.get("call_path") or []
        input_reaches_sink = bool(graph.get("input_reaches_sink", False))
        path_is_valid = bool(graph.get("path_is_valid", False))
        callers = graph.get("callers") or []
        if path_is_valid and path:
            lines.append(f"- Static interprocedural path: {' -> '.join(str(item) for item in path)}")
        else:
            caller_text = f" Recovered caller(s): {', '.join(str(item) for item in callers)}." if callers else ""
            lines.append(
                "- Static interprocedural context: recovered path metadata "
                f"(`input_reaches_sink={input_reaches_sink}`, `path_is_valid={path_is_valid}`).{caller_text}"
            )
    if isinstance(source_link, Mapping):
        linked = bool(source_link.get("expr_source_linked", False))
        if linked:
            lines.append("- Static source link: expression is linked to a recognized input source.")
        else:
            lines.append("- Static source link: recovered dataflow evidence is recorded in the static evidence pack.")

    _append_dynamic_source_line(lines, request_input, replay_argv, transcript_argv)
    lines.append(
        "- Interpretation: this bundle combines recovered local flow, static object capacity, and concrete replay evidence for the attached witness input."
    )
    return lines


def _normalized_source_to_sink_trace_lines(
    trace: Mapping[str, Any],
    request: Mapping[str, Any],
    transcript: Mapping[str, Any],
) -> list[str]:
    request_input = request.get("input") if isinstance(request.get("input"), Mapping) else {}
    replay_argv = request_input.get("argv", []) if isinstance(request_input, Mapping) else []
    transcript_argv = transcript.get("argv", []) if isinstance(transcript.get("argv"), list) else []
    path = [
        str(item.get("function") or item.get("name") or "")
        for item in trace.get("propagation_path", [])
        if isinstance(item, Mapping) and str(item.get("function") or item.get("name") or "")
    ]
    roles = [item for item in trace.get("argument_roles", []) if isinstance(item, Mapping)]
    controlled = [item for item in roles if item.get("controlled")]
    lines = [
        f"- Trace confidence: `{trace.get('confidence') or trace.get('status') or ''}`.",
        f"- Source boundary: `{trace.get('source_kind', '')}` via `{trace.get('input_model', '')}` at `{trace.get('entry_function', '')}`.",
    ]
    if path:
        lines.append(f"- Propagation path: {' -> '.join(path)}")
    if controlled:
        for role in controlled[:4]:
            evidence = [str(item) for item in role.get("evidence", []) if str(item)]
            suffix = f" Evidence: {'; '.join(evidence[:3])}" if evidence else ""
            lines.append(
                f"- Sink role `{role.get('role', '')}`: `{role.get('expr', '')}` is `{role.get('classification', '')}`.{suffix}"
            )
    else:
        lines.append("- Sink role evidence: no controlled sink argument role was recovered.")
    bounds = [item for item in trace.get("bounds_checks", []) if isinstance(item, Mapping)]
    if bounds:
        rendered = [
            str(item.get("relation") or item.get("condition") or item.get("reason") or item.get("text") or "")
            for item in bounds[:3]
        ]
        rendered = [item for item in rendered if item]
        if rendered:
            lines.append(f"- Bounds evidence: {'; '.join(rendered)}")
    checks = [item for item in trace.get("sanitizer_checks", []) if isinstance(item, Mapping)]
    if checks:
        rendered = [
            str(item.get("condition") or item.get("reason") or item.get("status") or "")
            for item in checks[:3]
        ]
        rendered = [item for item in rendered if item]
        if rendered:
            lines.append(f"- Sanitizer/check evidence: {'; '.join(rendered)}")
    limitations = [item for item in trace.get("execution_limitations", []) if isinstance(item, Mapping)]
    if limitations:
        rendered = [
            str(item.get("kind") or "") + (f" in `{item.get('function')}`" if item.get("function") else "")
            for item in limitations[:4]
            if item.get("kind")
        ]
        if rendered:
            lines.append(f"- Execution limitations: {'; '.join(rendered)}")
    _append_dynamic_source_line(lines, request_input, replay_argv, transcript_argv)
    lines.append(
        "- Interpretation: reportability depends on this source-to-sink trace plus concrete boundary replay artifacts, not on local sink reachability alone."
    )
    return lines


def _append_dynamic_source_line(
    lines: list[str],
    request_input: Mapping[str, Any],
    replay_argv: Sequence[Any],
    transcript_argv: Sequence[Any],
) -> None:
    if isinstance(request_input, Mapping) and request_input.get("input_hex"):
        length = _hex_length(str(request_input.get("input_hex") or ""))
        model = str(request_input.get("input_model") or "concrete")
        lines.append(f"- Dynamic witness input: `{model}` payload of {length} bytes is included as `poc_input.bin`.")
    elif replay_argv:
        payload = str(replay_argv[0])
        lines.append(f"- Dynamic replay source: argv payload of {len(payload)} bytes was supplied by the replay runner.")
    elif len(transcript_argv) > 1:
        payload = str(transcript_argv[1])
        lines.append(f"- Dynamic replay source: argv payload of {len(payload)} bytes was supplied to the process.")
    else:
        lines.append("- Dynamic replay source: concrete replay artifacts are listed in the artifact manifest.")


def _title(state: CandidateState) -> str:
    location = dict(state.location)
    function = str(location.get("function_name") or "unknown")
    return f"{report_vulnerability_type(state).replace('_', ' ').title()} in {function}"


def _suggested_fix(state: CandidateState) -> str:
    vulnerability = report_vulnerability_type(state)
    if vulnerability in {"stack_overflow", "heap_overflow", "out_of_bounds_write"}:
        return "Replace unbounded copy/format operations with bounded APIs and reject input longer than the destination object capacity."
    if vulnerability == "out_of_bounds_read":
        return "Validate the read offset and length against the source object capacity before dereference or copy."
    if vulnerability == "command_injection":
        return "Avoid shell interpretation for attacker-controlled strings; use fixed argv arrays and allowlists."
    if vulnerability == "path_traversal":
        return "Canonicalize paths and enforce an allowlisted base directory before filesystem access."
    if vulnerability == "unsafe_file_write":
        return "Validate and canonicalize output paths before opening files for write."
    if vulnerability == "format_string":
        return "Keep format strings constant and pass attacker-controlled data only as arguments to bounded formatting APIs."
    if vulnerability in {"credential_disclosure", "hardcoded_credential"}:
        return "Remove the exposed credential from the reachable response path and rotate any affected secret."
    if vulnerability == "auth_bypass":
        return "Enforce authentication and authorization checks before the protected action and replay-test unauthenticated requests."
    return "Add validation at the trust boundary and enforce the proof obligation described above."


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)[:120] or "candidate"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
