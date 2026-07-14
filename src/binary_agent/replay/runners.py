"""Replay execution and deterministic classification."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import posixpath
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import time
import urllib.parse
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from binary_agent.dynamic_proof import DynamicProofView
from binary_agent.firmware_services import (
    FirmwareServiceSession,
    prepare_firmware_service_sandbox,
)
from binary_agent.pipeline import CandidateState, CandidateStatus
from binary_agent.replay.models import ReplayRequest, ReplayResult, ReplayStatus, write_replay_result
from binary_agent.replay.semantic_oracles import (
    observe_effect,
    supports_semantic_oracle,
)
from binary_agent.replay.shim_sources import (
    _NATIVE_SYSLOG_INTERPOSER_SOURCE,
    _QEMU_MEMORY_WRITE_PLUGIN_SOURCE,
    _QEMU_EXACT_ACCESS_PLUGIN_SOURCE,
    _QEMU_EXACT_INSTRUCTION_PLUGIN_SOURCE,
    _QEMU_NVRAM_SHIM_SOURCE,
    _QEMU_OVERFLOW_ORACLE_PRELOAD_SOURCE,
    _QEMU_REPLAYFS_SHIM_SOURCE,
)
from binary_agent.taxonomy import (
    VULNERABILITY_SPECS,
    get_vulnerability_spec,
    vulnerability_types_for_backend,
)


DEFAULT_TIMEOUT_SECONDS = 10.0
SEMANTIC_PROCESS_TYPES = vulnerability_types_for_backend("semantic_effect")
SEMANTIC_PROCESS_ORACLE_KINDS = {
    spec.effect_kind
    for spec in VULNERABILITY_SPECS.values()
    if spec.backend == "semantic_effect" and spec.effect_kind
}
UNIX_ROOTFS_DIRS = {"bin", "sbin", "lib", "usr", "etc", "www", "var"}


def build_replay_requests(
    states: Sequence[CandidateState],
    *,
    binary_path: Path | None = None,
    mode: str = "auto",
) -> list[ReplayRequest]:
    """Create concrete replay requests for proof-ready candidates."""
    requests: list[ReplayRequest] = []
    for state in states:
        if state.status not in {CandidateStatus.PROOF_READY.value, CandidateStatus.REPLAY_READY.value}:
            continue
        if _is_pure_semantic_seed_state(state):
            continue
        if mode == "off":
            requests.append(_blocked_request(state, "not_attempted"))
            continue
        facts = dict(state.type_facts)
        static_candidate = facts.get("static_candidate") if isinstance(facts.get("static_candidate"), Mapping) else {}
        request_mode = "native" if mode == "auto" else mode
        function_name = str(state.location.get("function_name") or "")
        sink_marker = "" if function_name.startswith("FUN_") else function_name
        setup: dict[str, Any] = {
            "binary_path": str(binary_path or state.target.get("path") or ""),
            "function_name": function_name,
            "sink": state.sink.get("name", ""),
            "timeout_seconds": float(os.getenv("REPLAY_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)),
        }
        if supports_semantic_oracle(state.vulnerability_type):
            requests.append(
                _semantic_effect_replay_request(
                    state,
                    setup=setup,
                    request_mode=request_mode,
                )
            )
            continue
        if state.vulnerability_type == "format_string":
            requests.append(_format_string_replay_request(state, setup=setup, request_mode=request_mode))
            continue
        capacity = _int(facts.get("capacity_bytes") or static_candidate.get("capacity_bytes"), 0)
        payload = "A" * max(capacity + 64, 128)
        request_input: dict[str, Any] = {"argv": [payload], "payload_length": len(payload)}
        input_model = _state_process_input_model(state)
        if input_model in {"socket_service", "http_daemon"}:
            request_input = {"input_model": input_model, "payload": payload, "payload_length": len(payload)}
            _apply_service_endpoint(state, request_input, setup, input_model=input_model)
            if input_model == "http_daemon" and not _http_daemon_payload_placement_is_explicit(request_input):
                requests.append(_blocked_request(state, "ambiguous_http_replay_requires_llm:missing_explicit_input_surface"))
                continue
        if request_mode == "native" and _state_uses_argv_input(state):
            request_input["argv_materialization"] = "existing_long_path"
        if request_mode == "qemu_user":
            literal_strings = _state_literal_strings(state, binary_path or state.target.get("path"))
            form_inputs = _deterministic_qemu_form_inputs(state, binary_path or state.target.get("path"), literal_strings=literal_strings)
            if form_inputs:
                request_input["form"] = form_inputs
            filesystem_setup = _deterministic_qemu_filesystem_setup(literal_strings)
            if filesystem_setup:
                setup["filesystem"] = filesystem_setup
            route = _deterministic_qemu_route(state, binary_path or state.target.get("path"), literal_strings)
            if route:
                method, route_path = route
                setup["routes"] = [{"method": method, "path": route_path}]
                setup["env"] = {"REQUEST_METHOD": method}
                setup["auth"] = {"role": "admin", "session_id": "replay-session"}
        requests.append(
            ReplayRequest(
                candidate_id=state.candidate_id,
                mode=request_mode,
                setup=setup,
                input=request_input,
                expected_result={
                    "candidate_id": state.candidate_id,
                    "vulnerability_type": state.vulnerability_type,
                    "sink_output_contains": sink_marker,
                    "expect_crash": state.vulnerability_type in {"stack_overflow", "heap_overflow"},
                    "condition": facts.get("overflow_condition") or static_candidate.get("overflow_condition", ""),
                },
            )
        )
    return requests


def _semantic_effect_replay_request(
    state: CandidateState,
    *,
    setup: Mapping[str, Any],
    request_mode: str,
) -> ReplayRequest:
    process = _state_process_input_facts(state)
    configured_setup = dict(setup)
    for key in (
        "env",
        "cwd",
        "workdir",
        "proof_file",
        "proof_files",
        "database_path",
        "log_path",
        "outbound_listener",
        "oracle_setup",
        "timeout_seconds",
    ):
        value = process.get(key)
        if value not in (None, "", [], {}):
            configured_setup[key] = value
    input_model = str(process.get("input_model") or "argv")
    replay_input: dict[str, Any] = {"input_model": input_model}
    argv = process.get("argv_values") or process.get("argv") or []
    if isinstance(argv, Sequence) and not isinstance(argv, (str, bytes, bytearray)):
        replay_input["argv"] = [str(item) for item in argv]
    if process.get("stdin") not in (None, ""):
        replay_input["stdin"] = str(process["stdin"])
    if process.get("stdin_input_hex"):
        replay_input["stdin_input_hex"] = str(process["stdin_input_hex"])
    if isinstance(process.get("env_values"), Mapping):
        replay_input["env"] = {
            str(key): str(value) for key, value in process["env_values"].items()
        }
    spec = get_vulnerability_spec(state.vulnerability_type)
    configured_oracle = process.get("proof_oracle")
    oracle = dict(configured_oracle) if isinstance(configured_oracle, Mapping) else {}
    oracle["kind"] = spec.effect_kind
    oracle["vulnerability_type"] = state.vulnerability_type
    oracle["sink_address"] = str(
        state.operation.get("address") or state.location.get("operation_address") or ""
    )
    for key in ("proof_file", "database_path", "log_path"):
        if key not in oracle and process.get(key):
            oracle[key] = process[key]
    configured_setup["process_input_setup"] = {
        "status": "configured",
        "input_model": input_model,
    }
    return ReplayRequest(
        candidate_id=state.candidate_id,
        mode=request_mode,
        setup=configured_setup,
        input=replay_input,
        expected_result={
            "candidate_id": state.candidate_id,
            "vulnerability_type": state.vulnerability_type,
            "sink": str(state.sink.get("name") or ""),
            "sink_address": oracle["sink_address"],
            "expect_crash": False,
            "proof_oracle": oracle,
        },
    )


def _format_string_replay_request(
    state: CandidateState,
    *,
    setup: Mapping[str, Any],
    request_mode: str,
) -> ReplayRequest:
    probe = _default_format_string_probe(state)
    input_model = _state_process_input_model(state)
    request_input: dict[str, Any] = {
        "input_model": input_model if input_model in {"argv", "stdin"} else "argv",
        "payload_length": len(probe),
    }
    if input_model in {"socket_service", "http_daemon"}:
        request_input = {"input_model": input_model, "payload": probe, "payload_length": len(probe)}
        _apply_service_endpoint(state, request_input, setup, input_model=input_model)
        if input_model == "http_daemon" and not _http_daemon_payload_placement_is_explicit(request_input):
            return _blocked_request(state, "ambiguous_http_replay_requires_llm:missing_explicit_input_surface")
    elif request_input["input_model"] == "stdin":
        request_input["stdin"] = probe
    else:
        request_input["argv"] = [probe]
    return ReplayRequest(
        candidate_id=state.candidate_id,
        mode=request_mode,
        setup=dict(setup),
        input=request_input,
        expected_result={
            "candidate_id": state.candidate_id,
            "vulnerability_type": state.vulnerability_type,
            "marker": probe,
            "expect_crash": False,
            "condition": "attacker-controlled input is interpreted as a printf-family format string",
            "proof_oracle": {
                "kind": "format_string_effect",
                "marker": probe,
                "format_directive": "%x",
                "syscall_observation": False,
                "vulnerability_type": state.vulnerability_type,
                "sink": str(state.sink.get("name") or ""),
                "source_expression": str(state.source.get("expression") or ""),
                "source_kind": str(state.source.get("kind") or ""),
            },
        },
    )


def _default_format_string_probe(state: CandidateState) -> str:
    digest = hashlib.sha256(state.candidate_id.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"BINARY_AGENT_FMT_{digest}_%x_END"


def _state_process_input_model(state: CandidateState) -> str:
    process_input = _state_process_input_facts(state)
    process_model = str(process_input.get("input_model") or process_input.get("model") or "")
    if process_model:
        return process_model
    facts = dict(state.type_facts)
    trace = facts.get("source_to_sink_trace") if isinstance(facts.get("source_to_sink_trace"), Mapping) else {}
    return str(trace.get("input_model") or "")


def _state_process_input_facts(state: CandidateState) -> dict[str, Any]:
    facts = dict(state.type_facts)
    process_input = facts.get("process_input") if isinstance(facts.get("process_input"), Mapping) else {}
    return dict(process_input)


def _apply_service_endpoint(
    state: CandidateState,
    request_input: dict[str, Any],
    setup: dict[str, Any],
    *,
    input_model: str,
) -> None:
    process_input = _state_process_input_facts(state)
    hints = dict(state.type_facts.get("replay_hints") or {}) if isinstance(state.type_facts.get("replay_hints"), Mapping) else {}
    service_key = input_model if input_model in {"http_daemon", "socket_service"} else "socket_service"
    service = process_input.get(service_key) if isinstance(process_input.get(service_key), Mapping) else {}
    if not service and isinstance(hints.get(service_key), Mapping):
        service = hints[service_key]
    for key in (
        "host",
        "port",
        "read_timeout_seconds",
        "port_arg",
        "port_arg_index",
        "port_env",
        "port_env_key",
        "protocol",
        "request_terminator",
        "line_terminated",
        "method",
        "path",
        "route",
        "query",
        "params",
        "body",
        "content_type",
    ):
        value = process_input.get(key) or service.get(key) or hints.get(key)
        if value not in (None, ""):
            request_input[key] = value
    for key in ("argv", "argv_template", "steps", "socket_transcript", "headers", "form"):
        value = service.get(key) or hints.get(key)
        if value not in (None, "") and key not in request_input:
            request_input[key] = value
    if service:
        setup[service_key] = dict(service)


def _http_daemon_payload_placement_is_explicit(input_payload: Mapping[str, Any]) -> bool:
    if any(key in input_payload for key in ("body", "body_bytes_hex", "form", "input_hex", "params", "query", "request", "stdin")):
        return True
    path = str(input_payload.get("path") or input_payload.get("route") or "")
    return "{payload}" in path


def _is_pure_semantic_seed_state(state: CandidateState) -> bool:
    metadata = dict(state.metadata)
    facts = dict(state.type_facts)
    if metadata.get("semantic_enrichment_only"):
        return False
    if facts.get("static_candidate"):
        return False
    if metadata.get("source_model") and metadata.get("source_model") != "llm_semantic_seed":
        return False
    return metadata.get("provenance") == "llm_semantic_seed" or (
        "semantic_seed" in facts and not metadata.get("source_model")
    )


def _state_uses_argv_input(state: CandidateState) -> bool:
    facts = dict(state.type_facts)
    process_input = facts.get("process_input") if isinstance(facts.get("process_input"), Mapping) else {}
    process_model = str(process_input.get("input_model") or process_input.get("model") or "")
    if process_model in {"argv", "argv_file_stdin", "file"}:
        return True
    trace = facts.get("source_to_sink_trace") if isinstance(facts.get("source_to_sink_trace"), Mapping) else {}
    return str(trace.get("input_model") or "") == "argv"


def _state_literal_strings(state: CandidateState, binary_path: Path | str | None) -> list[str]:
    path = Path(str(binary_path or ""))
    if not path.exists():
        return []
    function_address = _normalize_address(state.location.get("address"))
    if not function_address:
        return []
    return _function_literal_strings(path, function_address)


def _deterministic_qemu_form_inputs(
    state: CandidateState,
    binary_path: Path | str | None,
    *,
    literal_strings: Sequence[str] | None = None,
) -> dict[str, str]:
    strings = list(literal_strings) if literal_strings is not None else _state_literal_strings(state, binary_path)
    form: dict[str, str] = {}
    for value in strings:
        text = value.strip()
        lowered = text.lower()
        if not text or len(text) > 80:
            continue
        if text.isdigit() and 1 <= len(text) <= 6:
            form.setdefault(f"P{text}", "1")
        elif ("time" in lowered or "zone" in lowered) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:-]{1,79}", text):
            form.setdefault(f"P{text}", "3600")
    return form


def _deterministic_qemu_route(
    state: CandidateState,
    binary_path: Path | str | None,
    literal_strings: Sequence[str],
) -> tuple[str, str] | None:
    path = Path(str(binary_path or ""))
    if not path.exists():
        return None
    routes = [value for value in _binary_ascii_strings(path) if value.startswith("/cgi-bin/")]
    if not routes:
        return None
    literal_tokens = _route_tokens(" ".join(literal_strings))
    location = state.location if isinstance(state.location, Mapping) else {}
    literal_tokens.update(_route_tokens(str(location.get("line_text") or "")))
    literal_tokens.update(_route_alias_tokens(literal_tokens))
    if {"time", "timezone", "zone", "override"} & literal_tokens:
        fallback = _qemu_config_post_route(path)
        if fallback:
            return ("POST", fallback)
    best_route = ""
    best_score = 0
    for route in routes:
        route_tokens = _route_tokens(route)
        score = len(route_tokens & literal_tokens)
        if {"get", "list"} <= route_tokens and {"result", "name", "url", "size"} & literal_tokens:
            score += 2
        if "post" in route_tokens and {"form", "config", "value", "time", "zone"} & literal_tokens:
            score += 2
        if score > best_score:
            best_route = route
            best_score = score
    if best_route and best_score > 0:
        return (_route_method(best_route), best_route)
    fallback = _qemu_config_post_route(path)
    if fallback:
        return ("POST", fallback)
    return None


def _deterministic_qemu_filesystem_setup(literal_strings: Sequence[str]) -> list[dict[str, str]]:
    prefixes = []
    for value in literal_strings:
        text = value.strip()
        if re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,31}\.", text):
            prefixes.append(text)
    if not prefixes:
        return []
    paths = [value.strip() for value in literal_strings if value.strip().startswith("/") and len(value.strip()) <= 160]
    bases = [value.rstrip("/") for value in paths if not value.endswith("/") and value.count("/") >= 2]
    suffix_dirs = [value for value in paths if value.endswith("/")]
    directories: set[str] = set()
    if bases:
        for base in bases:
            for suffix in suffix_dirs:
                if suffix.startswith(base + "/"):
                    directories.add(suffix)
                elif not suffix.startswith("/usr/"):
                    directories.add(base + suffix)
    else:
        for path in suffix_dirs:
            directories.add(path)
    entries: list[dict[str, str]] = []
    for directory in sorted(directories):
        if not directory.startswith("/") or len(directory) > 220:
            continue
        if not any(prefix.strip(".").lower() in directory.lower() for prefix in prefixes):
            continue
        for prefix in prefixes[:2]:
            entries.append(
                {
                    "directory": directory,
                    "pattern": f"{prefix}*",
                    "min_length": "176",
                    "content": "replay\n",
                }
            )
    return entries[:4]


def _route_tokens(value: str) -> set[str]:
    return {token.lower() for token in re.split(r"[^A-Za-z0-9]+", value) if len(token) >= 2}


def _route_alias_tokens(tokens: set[str]) -> set[str]:
    aliases: set[str] = set()
    if "core" in tokens:
        aliases.update({"dump", "crash"})
    if {"name", "url", "lastmodified", "size"} & tokens:
        aliases.update({"get", "list"})
    if {"time", "zone"} & tokens:
        aliases.update({"value", "post", "config"})
    return aliases


def _route_method(route: str) -> str:
    tokens = _route_tokens(route)
    if tokens & {"post", "save", "change", "add", "delete", "capture", "operation", "gen"}:
        return "POST"
    return "GET"


def _function_literal_strings(binary_path: Path, function_address: str) -> list[str]:
    disassembly = _objdump_window(binary_path, function_address)
    if not disassembly:
        return []
    data = binary_path.read_bytes()
    sections = _elf_sections(binary_path)
    result: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(r"@\s*([0-9a-fA-F]+)\s+<", disassembly):
        literal_va = int(match.group(1), 16)
        literal_off = _elf_va_to_offset(literal_va, sections)
        if literal_off is None or literal_off + 4 > len(data):
            continue
        pointer_va = int.from_bytes(data[literal_off : literal_off + 4], "little")
        pointer_off = _elf_va_to_offset(pointer_va, sections)
        if pointer_off is None or pointer_off >= len(data):
            continue
        text = _read_c_string(data, pointer_off)
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _qemu_config_post_route(binary_path: Path | str | None) -> str:
    path = Path(str(binary_path or ""))
    if not path.exists():
        return ""
    routes = [value for value in _binary_ascii_strings(path) if value.startswith("/cgi-bin/")]
    for route in routes:
        lowered = route.lower()
        if "post" in lowered and ("value" in lowered or "config" in lowered or "save" in lowered):
            return route
    for route in routes:
        if "post" in route.lower():
            return route
    return ""


def _objdump_window(binary_path: Path, function_address: str) -> str:
    tool = shutil.which(os.getenv("OBJDUMP") or "") or shutil.which("arm-none-eabi-objdump") or shutil.which("objdump")
    if not tool:
        return ""
    start = _address_int(function_address)
    if start is None:
        return ""
    try:
        completed = subprocess.run(
            [
                tool,
                "-d",
                f"--start-address=0x{start:x}",
                f"--stop-address=0x{start + 0x1000:x}",
                str(binary_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _elf_sections(binary_path: Path) -> list[tuple[int, int, int]]:
    try:
        completed = subprocess.run(
            ["readelf", "-S", str(binary_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    sections: list[tuple[int, int, int]] = []
    pattern = re.compile(r"\[\s*\d+\]\s+\S+\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)")
    for line in completed.stdout.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        address, offset, size = (int(item, 16) for item in match.groups())
        if size:
            sections.append((address, offset, size))
    return sections


def _elf_va_to_offset(address: int, sections: Sequence[tuple[int, int, int]]) -> int | None:
    for section_address, section_offset, section_size in sections:
        if section_address <= address < section_address + section_size:
            return section_offset + (address - section_address)
    return None


def _read_c_string(data: bytes, offset: int) -> str:
    end = offset
    while end < len(data) and data[end] != 0 and end - offset <= 256:
        byte = data[end]
        if byte < 0x20 or byte > 0x7e:
            return ""
        end += 1
    if end == offset:
        return ""
    return data[offset:end].decode("ascii", errors="ignore")


def _binary_ascii_strings(path: Path) -> list[str]:
    data = path.read_bytes()
    return [match.group(0).decode("ascii", errors="ignore") for match in re.finditer(rb"[\x20-\x7e]{4,}", data)]


def run_replay_requests(requests: Sequence[ReplayRequest], output_dir: Path) -> list[ReplayResult]:
    results: list[ReplayResult] = []
    for request in requests:
        results.append(run_replay_request(request, output_dir))
    return results


def run_replay_request(request: ReplayRequest, output_dir: Path) -> ReplayResult:
    candidate_dir = output_dir / _safe_name(request.candidate_id)
    candidate_dir.mkdir(parents=True, exist_ok=True)
    (candidate_dir / "request.json").write_text(json.dumps(request.to_dict(), indent=2, sort_keys=True))
    if request.mode in {"native", "auto"}:
        result = _run_native(request, candidate_dir)
    elif request.mode == "function_harness":
        result = _run_function_harness(request, candidate_dir)
    elif request.mode == "qemu_user":
        result = _run_qemu_user(request, candidate_dir)
    elif request.mode == "qemu_system":
        result = _run_external_tool(request, candidate_dir, os.getenv("QEMU_SYSTEM_BIN"), "qemu_system")
    elif request.mode == "container_service":
        result = _run_container_service(request, candidate_dir)
    elif request.mode == "off":
        result = _blocked_result(
            request,
            candidate_dir,
            ReplayStatus.BLOCKED.value,
            str(request.setup.get("blocked_reason") or request.setup.get("reason") or "replay disabled"),
        )
    else:
        result = ReplayResult(
            candidate_id=request.candidate_id,
            result=ReplayStatus.BLOCKED.value,
            mode=request.mode,
            sink_reached=False,
            bug_observed=False,
            crash_observed=False,
            control_result={"reason": f"unsupported replay mode {request.mode!r}"},
            artifacts=[str(candidate_dir / "request.json")],
            artifact_refs=_artifact_refs([str(candidate_dir / "request.json")], kind="request"),
        )
    write_replay_result(result, candidate_dir / "result.json")
    return result


def import_concolic_replay_results(
    verdict_dir: Path,
    output_dir: Path,
    *,
    candidate_ids: Iterable[str] | None = None,
    evidence_dir: Path | None = None,
) -> list[ReplayResult]:
    """Convert artifact-backed concolic verdicts into replay results.

    Decisive concolic verdicts are not replay confirmations by themselves.
    Process-scope Ghidra overflow proofs are imported directly as replay
    confirmations; other concrete witnesses are lowered into QEMU user-mode
    replay and returned through the same ReplayResult gate used by process replay.
    """
    verdict_dir = Path(verdict_dir)
    output_dir = Path(output_dir)
    eligible_ids = {str(candidate_id) for candidate_id in candidate_ids} if candidate_ids is not None else None
    evidence_by_id = _load_replay_evidence_by_id(evidence_dir)
    results: list[ReplayResult] = []
    for verdict_path in sorted(verdict_dir.rglob("verdict.json")):
        verdict = _load_json(verdict_path)
        if not verdict:
            continue
        candidate_id = str(verdict.get("candidate_id") or "")
        if eligible_ids is not None and candidate_id not in eligible_ids:
            continue
        concolic_verdict = str(verdict.get("concolic_verdict") or "")
        ghidra_proof = verdict.get("ghidra_dynamic_proof") if isinstance(verdict.get("ghidra_dynamic_proof"), Mapping) else {}
        native_replay = ghidra_proof.get("native_replay") if isinstance(ghidra_proof.get("native_replay"), Mapping) else {}
        native_trace = native_replay.get("exact_operation_trace") if isinstance(native_replay.get("exact_operation_trace"), Mapping) else {}
        native_exact_reached = bool(
            native_trace.get("status") == "reached" and native_trace.get("operation_address")
        )
        if not candidate_id or (concolic_verdict not in {
            "overflow_witness",
            "memory_violation_witness",
            "crash_reproduced",
            "target_reached",
        } and not native_exact_reached):
            continue
        if native_exact_reached and not _has_process_ghidra_memory_safety_proof(ghidra_proof):
            results.append(
                _import_native_exact_trace_result(
                    verdict_dir,
                    verdict_path,
                    verdict,
                    output_dir,
                    candidate_id=candidate_id,
                    concolic_verdict=concolic_verdict,
                    ghidra_proof=ghidra_proof,
                )
            )
            continue
        if _has_process_ghidra_memory_safety_proof(ghidra_proof):
            result = _import_ghidra_dynamic_proof_result(
                verdict_dir,
                verdict_path,
                verdict,
                output_dir,
                candidate_id=candidate_id,
                concolic_verdict=concolic_verdict,
                ghidra_proof=ghidra_proof,
                mode="ghidra_process",
                artifact_kind="concolic_ghidra_process_proof",
            )
            results.append(result)
            continue
        if _has_function_harness_ghidra_memory_safety_proof(ghidra_proof):
            result = _import_ghidra_dynamic_proof_result(
                verdict_dir,
                verdict_path,
                verdict,
                output_dir,
                candidate_id=candidate_id,
                concolic_verdict=concolic_verdict,
                ghidra_proof=ghidra_proof,
                mode="ghidra_function_harness",
                artifact_kind="concolic_ghidra_function_harness_proof",
            )
            results.append(result)
            continue
        replay_payload = _load_json(verdict_path.with_name("replay.json"))
        concrete_replay = replay_payload.get("concrete_angr_replay") if isinstance(replay_payload, Mapping) else {}
        pcode_replay = replay_payload.get("ghidra_pcode_replay") if isinstance(replay_payload, Mapping) else {}
        sink_reached = (
            isinstance(concrete_replay, Mapping)
            and concrete_replay.get("status") == "replayed"
        ) or (
            isinstance(pcode_replay, Mapping)
            and bool(pcode_replay.get("reached_target"))
        )
        if not sink_reached:
            continue

        request_payload = verdict.get("request") if isinstance(verdict.get("request"), Mapping) else {}
        witness = verdict.get("witness") if isinstance(verdict.get("witness"), Mapping) else {}
        evidence_pack = evidence_by_id.get(candidate_id, {})
        concolic_blocker = _concolic_qemu_replay_blocker(evidence_pack, request_payload)
        if concolic_blocker:
            original_artifacts = _resolve_concolic_artifacts(verdict_dir, verdict_path, verdict)
            candidate_dir = output_dir / _safe_name(candidate_id)
            candidate_dir.mkdir(parents=True, exist_ok=True)
            blocked_path = candidate_dir / "blocked.json"
            blocked_payload = {
                "reason": concolic_blocker,
                "candidate_id": candidate_id,
                "concolic_verdict": concolic_verdict,
                "concolic_request": dict(request_payload),
                "original_verdict_path": str(verdict_path),
            }
            blocked_path.write_text(json.dumps(blocked_payload, indent=2, sort_keys=True))
            artifacts = _dedupe([str(blocked_path), *original_artifacts])
            result = ReplayResult(
                candidate_id=candidate_id,
                result=ReplayStatus.BLOCKED.value,
                mode="qemu_user",
                sink_reached=False,
                bug_observed=False,
                crash_observed=False,
                control_result=blocked_payload,
                artifacts=artifacts,
                artifact_refs=_artifact_refs(artifacts, kind="invalid_concolic_qemu_replay"),
            )
            write_replay_result(result, candidate_dir / "result.json")
            results.append(result)
            continue
        request = _qemu_request_from_concolic_verdict(
            candidate_id,
            concolic_verdict=concolic_verdict,
            request_payload=request_payload,
            witness=witness,
            concrete_replay=concrete_replay,
            evidence_pack=evidence_pack,
        )
        result = run_replay_request(request, output_dir)
        original_artifacts = _resolve_concolic_artifacts(verdict_dir, verdict_path, verdict)
        artifacts = _dedupe([*result.artifacts, *original_artifacts])
        control_result = {
            **dict(result.control_result),
            "concolic_verdict": concolic_verdict,
            "backend": verdict.get("backend") or request_payload.get("backend") or "angr",
            "concolic_request": dict(request_payload),
            "witness": dict(witness),
            "concrete_angr_replay": dict(concrete_replay) if isinstance(concrete_replay, Mapping) else {},
            "ghidra_pcode_replay": dict(pcode_replay) if isinstance(pcode_replay, Mapping) else {},
            "original_verdict_path": str(verdict_path),
        }
        result = ReplayResult(
            candidate_id=candidate_id,
            result=result.result,
            mode=result.mode,
            sink_reached=result.sink_reached,
            bug_observed=result.bug_observed,
            crash_observed=result.crash_observed,
            control_result=control_result,
            artifacts=artifacts,
            negative_control_passed=result.negative_control_passed,
            artifact_refs=_artifact_refs(artifacts, kind="concolic_qemu_replay"),
        )
        write_replay_result(result, output_dir / _safe_name(candidate_id) / "result.json")
        results.append(result)
    return results


def _import_native_exact_trace_result(
    verdict_dir: Path,
    verdict_path: Path,
    verdict: Mapping[str, Any],
    output_dir: Path,
    *,
    candidate_id: str,
    concolic_verdict: str,
    ghidra_proof: Mapping[str, Any],
) -> ReplayResult:
    """Import exact native reach as non-confirming evidence for backend dispatch."""
    original_artifacts = _resolve_concolic_artifacts(verdict_dir, verdict_path, verdict)
    candidate_dir = output_dir / _safe_name(candidate_id)
    candidate_dir.mkdir(parents=True, exist_ok=True)
    result_path = candidate_dir / "result.json"
    artifacts = _dedupe([str(result_path), *original_artifacts])
    control_result = {
        "concolic_verdict": concolic_verdict,
        "backend": verdict.get("backend") or "angr",
        "concolic_request": dict(verdict.get("request") or {}) if isinstance(verdict.get("request"), Mapping) else {},
        "ghidra_dynamic_proof": dict(ghidra_proof),
        "original_verdict_path": str(verdict_path),
        "replay_blocker": "native exact operation reach requires backend-specific violation proof",
    }
    result = ReplayResult(
        candidate_id=candidate_id,
        result=ReplayStatus.BLOCKED.value,
        mode="native_exact_operation",
        sink_reached=True,
        bug_observed=False,
        crash_observed=False,
        control_result=control_result,
        artifacts=artifacts,
        negative_control_passed=None,
        artifact_refs=_artifact_refs(artifacts, kind="native_exact_operation_trace"),
    )
    write_replay_result(result, result_path)
    return result


def _import_ghidra_dynamic_proof_result(
    verdict_dir: Path,
    verdict_path: Path,
    verdict: Mapping[str, Any],
    output_dir: Path,
    *,
    candidate_id: str,
    concolic_verdict: str,
    ghidra_proof: Mapping[str, Any],
    mode: str,
    artifact_kind: str,
) -> ReplayResult:
    replay_payload = _load_json(verdict_path.with_name("replay.json"))
    concrete_replay = replay_payload.get("concrete_angr_replay") if isinstance(replay_payload, Mapping) else {}
    pcode_replay = replay_payload.get("ghidra_pcode_replay") if isinstance(replay_payload, Mapping) else {}
    original_artifacts = _resolve_concolic_artifacts(verdict_dir, verdict_path, verdict)
    candidate_dir = output_dir / _safe_name(candidate_id)
    candidate_dir.mkdir(parents=True, exist_ok=True)
    result_path = candidate_dir / "result.json"
    artifacts = _dedupe([str(result_path), *original_artifacts])
    control_result = {
        "concolic_verdict": concolic_verdict,
        "backend": verdict.get("backend") or "angr",
        "concolic_request": dict(verdict.get("request") or {}) if isinstance(verdict.get("request"), Mapping) else {},
        "witness": dict(verdict.get("witness") or {}) if isinstance(verdict.get("witness"), Mapping) else {},
        "concrete_angr_replay": dict(concrete_replay) if isinstance(concrete_replay, Mapping) else {},
        "ghidra_pcode_replay": dict(pcode_replay) if isinstance(pcode_replay, Mapping) else {},
        "ghidra_dynamic_proof": dict(ghidra_proof),
        "original_verdict_path": str(verdict_path),
    }
    native_replay = ghidra_proof.get("native_replay") if isinstance(ghidra_proof.get("native_replay"), Mapping) else {}
    request_payload = verdict.get("request") if isinstance(verdict.get("request"), Mapping) else {}
    input_model = str(request_payload.get("input_model") or "")
    service_proof = input_model in {"socket_service", "http_daemon"}
    service_confirmed = bool(
        native_replay.get("status") == "replayed"
        and native_replay.get("connected") is True
        and native_replay.get("crash_observed") is True
    )
    confirmed = not service_proof or service_confirmed
    if service_proof and not confirmed:
        control_result["replay_blocker"] = "service proof requires a native connected replay with an observed memory-safety crash"
    result = ReplayResult(
        candidate_id=candidate_id,
        result=ReplayStatus.CONFIRMED.value if confirmed else ReplayStatus.BLOCKED.value,
        mode=mode,
        sink_reached=True,
        bug_observed=confirmed,
        crash_observed=bool(native_replay.get("crash_observed", False)),
        control_result=control_result,
        artifacts=artifacts,
        negative_control_passed=None,
        artifact_refs=_artifact_refs(artifacts, kind=artifact_kind),
    )
    write_replay_result(result, result_path)
    return result


def _has_process_ghidra_memory_safety_proof(proof: Mapping[str, Any]) -> bool:
    return _has_ghidra_memory_safety_proof(proof, "process_entrypoint")


def _has_function_harness_ghidra_memory_safety_proof(proof: Mapping[str, Any]) -> bool:
    return _has_ghidra_memory_safety_proof(proof, "function_harness")


def _has_ghidra_memory_safety_proof(proof: Mapping[str, Any], scope: str) -> bool:
    return DynamicProofView(proof).is_memory_safety_proof(
        scope=scope,
        require_setup=True,
        require_sink=True,
        require_function_harness_input=scope == "function_harness",
    )


def _load_replay_evidence_by_id(evidence_dir: Path | None) -> dict[str, Mapping[str, Any]]:
    if evidence_dir is None:
        return {}
    try:
        from binary_agent.analysis.confirmation import iter_evidence_packs

        return {
            _candidate_id_from_evidence_pack(pack) or path.stem: pack
            for path, pack in iter_evidence_packs(Path(evidence_dir))
        }
    except Exception:
        return {}


def _concolic_qemu_replay_blocker(evidence_pack: Mapping[str, Any], request_payload: Mapping[str, Any]) -> str:
    if not evidence_pack or not _is_semantic_process_evidence(evidence_pack):
        return ""
    if str(request_payload.get("input_model") or "") == "function_harness":
        entrypoint = _semantic_entrypoint_derivation(evidence_pack)
        if not (
            entrypoint.get("status") == "derived"
            and str(entrypoint.get("input_model") or "") in {"argv", "stdin", "file"}
        ):
            blockers = ",".join(str(item) for item in (entrypoint.get("blockers") or []) if str(item)) or "entrypoint_missing"
            return f"semantic function_harness concolic requires a derived process entrypoint; blockers: {blockers}"
    exact_sink = _semantic_exact_sink_callsite(evidence_pack)
    resolution = request_payload.get("target_resolution")
    resolution = resolution if isinstance(resolution, Mapping) else {}
    resolution_target = _normalize_address(resolution.get("target_address"))
    resolution_sink = _normalize_address(resolution.get("sink_address") or resolution.get("target_address"))
    target_address = _normalize_address(request_payload.get("target_address"))
    sink_address = _normalize_address(request_payload.get("sink_address") or request_payload.get("target_address"))
    if not exact_sink:
        if (
            resolution.get("status") == "derived"
            and str(resolution.get("target_kind") or "") in {
                "exact_sink_callsite",
                "exact_pcode_callsite",
                "pcode_sink_callee",
                "disassembly_callsite",
                "structured_sink_callee",
            }
            and resolution_target
            and target_address == resolution_target
            and (not sink_address or not resolution_sink or sink_address == resolution_sink)
        ):
            return ""
        return "semantic concolic requires a concrete sink callsite; only a function anchor is available"
    if target_address != exact_sink:
        return f"semantic concolic target_address {target_address!r} must be the concrete sink callsite {exact_sink!r}"
    if sink_address and sink_address != exact_sink:
        return f"semantic concolic sink_address {sink_address!r} must be the concrete sink callsite {exact_sink!r}"
    return ""


def _is_semantic_process_evidence(evidence_pack: Mapping[str, Any]) -> bool:
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    semantic_seed = type_facts.get("semantic_seed") if isinstance(type_facts.get("semantic_seed"), Mapping) else {}
    if not semantic_seed:
        return False
    candidate = evidence_pack.get("deterministic_candidate") if isinstance(evidence_pack.get("deterministic_candidate"), Mapping) else {}
    vulnerability_type = str(candidate.get("vulnerability_type") or semantic_seed.get("vulnerability_type") or evidence_pack.get("vulnerability_type") or "")
    return vulnerability_type in SEMANTIC_PROCESS_TYPES


def _semantic_entrypoint_derivation(evidence_pack: Mapping[str, Any]) -> Mapping[str, Any]:
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    entrypoint = type_facts.get("entrypoint_derivation")
    if isinstance(entrypoint, Mapping):
        return entrypoint
    entrypoint = evidence_pack.get("entrypoint_derivation")
    return entrypoint if isinstance(entrypoint, Mapping) else {}


def _semantic_exact_sink_callsite(evidence_pack: Mapping[str, Any]) -> str:
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    semantic_seed = type_facts.get("semantic_seed") if isinstance(type_facts.get("semantic_seed"), Mapping) else {}
    semantic_target = semantic_seed.get("semantic_target") if isinstance(semantic_seed.get("semantic_target"), Mapping) else {}
    intent = type_facts.get("deterministic_replay_intent")
    if not isinstance(intent, Mapping):
        intent = semantic_seed.get("deterministic_replay_intent") if isinstance(semantic_seed.get("deterministic_replay_intent"), Mapping) else {}
    candidate = evidence_pack.get("deterministic_candidate") if isinstance(evidence_pack.get("deterministic_candidate"), Mapping) else {}
    location = evidence_pack.get("location") if isinstance(evidence_pack.get("location"), Mapping) else {}
    function_anchor = _normalize_address(location.get("address") or candidate.get("address") or semantic_target.get("function_address"))
    sink = evidence_pack.get("sink") if isinstance(evidence_pack.get("sink"), Mapping) else {}
    for value in (
        sink.get("operation_address"),
        sink.get("callsite"),
        sink.get("address"),
        semantic_target.get("sink_address"),
        semantic_target.get("sink_callsite"),
        intent.get("sink_callsite"),
    ):
        address = _normalize_address(value)
        if address and address != function_anchor:
            return address
    return ""


def _candidate_id_from_evidence_pack(evidence_pack: Mapping[str, Any]) -> str:
    candidate_id = str(evidence_pack.get("candidate_id") or "")
    if candidate_id:
        return candidate_id
    for key in ("candidate", "deterministic_candidate"):
        candidate = evidence_pack.get(key)
        if isinstance(candidate, Mapping) and candidate.get("candidate_id"):
            return str(candidate["candidate_id"])
    return ""


def _qemu_request_from_concolic_verdict(
    candidate_id: str,
    *,
    concolic_verdict: str,
    request_payload: Mapping[str, Any],
    witness: Mapping[str, Any],
    concrete_replay: Mapping[str, Any],
    evidence_pack: Mapping[str, Any],
) -> ReplayRequest:
    setup = _semantic_replay_setup_from_evidence(evidence_pack)
    setup.update(
        {
            "binary_path": str(request_payload.get("binary_path") or setup.get("binary_path") or ""),
            "export_dir": str(request_payload.get("export_dir") or setup.get("export_dir") or ""),
            "target_address": str(request_payload.get("target_address") or setup.get("target_address") or ""),
            "sink_address": str(request_payload.get("sink_address") or request_payload.get("target_address") or setup.get("sink_address") or ""),
            "concolic_backend": str(request_payload.get("backend") or "angr"),
            "concolic_verdict": concolic_verdict,
            "provenance": "concolic_witness",
        }
    )
    setup.setdefault("timeout_seconds", 30.0)
    expected = _semantic_expected_result_from_evidence(evidence_pack)
    expected.update(
        {
            "candidate_id": candidate_id,
            "concolic_verdict": concolic_verdict,
            "target_reached": True,
            "target_address": str(request_payload.get("target_address") or expected.get("target_address") or ""),
            "sink_address": str(request_payload.get("sink_address") or request_payload.get("target_address") or expected.get("sink_address") or ""),
            "expect_crash": concolic_verdict == "crash_reproduced" or bool(expected.get("expect_crash", False)),
            "provenance": "concolic_witness",
        }
    )
    return ReplayRequest(
        candidate_id=candidate_id,
        mode=_concolic_process_replay_mode(request_payload),
        setup=setup,
        input=_concolic_witness_replay_input(witness, concrete_replay, request_payload),
        expected_result=expected,
    )


def _concolic_process_replay_mode(request_payload: Mapping[str, Any]) -> str:
    binary_path = Path(str(request_payload.get("binary_path") or ""))
    machine = _elf_machine(binary_path)
    return "native" if _elf_machine_is_host_native(machine) else "qemu_user"


def _semantic_replay_setup_from_evidence(evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    hints = _semantic_replay_hints_from_evidence(evidence_pack)
    setup = hints.get("setup") or hints.get("proposed_setup")
    return dict(setup) if isinstance(setup, Mapping) else {}


def _semantic_expected_result_from_evidence(evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    hints = _semantic_replay_hints_from_evidence(evidence_pack)
    expected = hints.get("expected_result") or hints.get("expected_sink")
    result = dict(expected) if isinstance(expected, Mapping) else {}
    if not isinstance(result.get("proof_oracle"), Mapping):
        proof_oracle_facts = evidence_pack.get("proof_oracle_facts")
        if isinstance(proof_oracle_facts, Mapping):
            result["proof_oracle"] = dict(proof_oracle_facts)
    if isinstance(result.get("proof_oracle"), Mapping):
        result["proof_oracle"] = _enrich_semantic_process_oracle(dict(result["proof_oracle"]), evidence_pack)
    candidate = evidence_pack.get("candidate") if isinstance(evidence_pack.get("candidate"), Mapping) else {}
    location = evidence_pack.get("location") if isinstance(evidence_pack.get("location"), Mapping) else {}
    sink = evidence_pack.get("sink") if isinstance(evidence_pack.get("sink"), Mapping) else {}
    result.setdefault("vulnerability_type", str(candidate.get("vulnerability_type") or ""))
    result.setdefault("function_name", str(location.get("function_name") or ""))
    result.setdefault("target_address", str(location.get("address") or ""))
    result.setdefault("sink", str(sink.get("name") or ""))
    result.setdefault("sink_address", str(sink.get("operation_address") or location.get("address") or ""))
    return result


def _enrich_semantic_process_oracle(oracle: Mapping[str, Any], evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(oracle)
    kind = str(result.get("kind") or result.get("type") or "")
    if kind not in SEMANTIC_PROCESS_ORACLE_KINDS:
        return result
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    semantic_seed = type_facts.get("semantic_seed") if isinstance(type_facts.get("semantic_seed"), Mapping) else {}
    intent = type_facts.get("deterministic_replay_intent") if isinstance(type_facts.get("deterministic_replay_intent"), Mapping) else {}
    if not intent and isinstance(semantic_seed.get("deterministic_replay_intent"), Mapping):
        intent = semantic_seed["deterministic_replay_intent"]
    sink = evidence_pack.get("sink") if isinstance(evidence_pack.get("sink"), Mapping) else {}
    source = evidence_pack.get("source") if isinstance(evidence_pack.get("source"), Mapping) else {}
    location = evidence_pack.get("location") if isinstance(evidence_pack.get("location"), Mapping) else {}
    candidate = evidence_pack.get("candidate") if isinstance(evidence_pack.get("candidate"), Mapping) else {}
    hints = _semantic_replay_hints_from_evidence(evidence_pack)
    hint_input = hints.get("input") or hints.get("inputs") or hints.get("proposed_inputs")
    expected = hints.get("expected_result") or hints.get("expected_sink")
    result.setdefault("syscall_observation", True)
    result.setdefault("vulnerability_type", str(candidate.get("vulnerability_type") or semantic_seed.get("vulnerability_type") or intent.get("vulnerability_type") or ""))
    result.setdefault("sink", str(sink.get("name") or intent.get("sink") or ""))
    result.setdefault("source_expression", str(source.get("expression") or intent.get("source_expression") or ""))
    result.setdefault("source_kind", str(source.get("kind") or ""))
    result.setdefault("target_address", _normalize_address(location.get("address") or sink.get("operation_address") or ""))
    result.setdefault("sink_address", _normalize_address(sink.get("operation_address") or location.get("address") or ""))
    if isinstance(expected, Mapping):
        marker = str(expected.get("marker") or expected.get("sink_output_contains") or "")
        if marker and not result.get("marker"):
            result["marker"] = marker
    tokens = _semantic_hint_tokens(hint_input)
    if kind == "command_effect" and tokens:
        result.setdefault("command_tokens", tokens)
    if kind in {"filesystem_read_escape", "filesystem_write_escape"} and tokens:
        result.setdefault("path_tokens", tokens)
    if kind == "format_string_effect" and not result.get("marker"):
        for token in tokens:
            if "%" in token:
                result["marker"] = token
                break
    if kind == "format_string_effect":
        result["syscall_observation"] = False
        result.setdefault("format_directive", "%x")
    return result


def _semantic_hint_tokens(value: Any) -> list[str]:
    tokens: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            for child in item.values():
                visit(child)
            return
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for child in item:
                visit(child)
            return
        if isinstance(item, bytes):
            text = item.decode("latin-1", errors="ignore")
        else:
            text = str(item or "")
        token = text.strip()
        if token and token not in tokens:
            tokens.append(token)

    visit(value)
    return tokens[:12]


def _semantic_replay_hints_from_evidence(evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    type_facts = evidence_pack.get("type_facts") if isinstance(evidence_pack.get("type_facts"), Mapping) else {}
    hints = type_facts.get("replay_hints") if isinstance(type_facts, Mapping) else {}
    if isinstance(hints, Mapping):
        return dict(hints)
    semantic_seed = type_facts.get("semantic_seed") if isinstance(type_facts, Mapping) and isinstance(type_facts.get("semantic_seed"), Mapping) else {}
    hints = semantic_seed.get("replay_hints") if isinstance(semantic_seed, Mapping) else {}
    return dict(hints) if isinstance(hints, Mapping) else {}


def _concolic_witness_replay_input(
    witness: Mapping[str, Any],
    concrete_replay: Mapping[str, Any],
    request_payload: Mapping[str, Any],
) -> dict[str, Any]:
    input_model = str(
        witness.get("input_model")
        or concrete_replay.get("input_model")
        or request_payload.get("input_model")
        or ""
    )
    if input_model == "argv" and isinstance(witness.get("argv_hex"), list) and witness["argv_hex"]:
        return {
            "input_model": input_model,
            "argv": [_decode_witness_hex_text(str(item)) for item in witness["argv_hex"]],
            "input_hex": str(witness["argv_hex"][0]),
        }
    input_hex = _witness_input_hex(witness, concrete_replay)
    decoded = _decode_witness_hex_text(input_hex)
    if input_model == "stdin":
        return {"input_model": input_model, "stdin": decoded, "input_hex": input_hex}
    if input_model == "file":
        file_inputs = witness.get("file_inputs_hex")
        if isinstance(file_inputs, Mapping) and file_inputs:
            name, value = next(iter(file_inputs.items()))
            name_text = _clean_target_filename(str(name or "concolic_input")) or "concolic_input"
            return {
                "input_model": input_model,
                "argv": [name_text],
                "file_inputs": [{"name": name_text, "content_hex": str(value)}],
                "input_hex": str(value),
            }
        return {"input_model": input_model, "argv": ["concolic_input"], "file_inputs": [{"name": "concolic_input", "content_hex": input_hex}], "input_hex": input_hex}
    if input_model == "function_harness":
        return {"input_model": input_model, "argv": [decoded], "input_hex": input_hex}
    return {"input_model": input_model or "argv", "argv": [decoded], "input_hex": input_hex}


def _decode_witness_hex_text(value: str) -> str:
    if not value:
        return ""
    try:
        return bytes.fromhex(value).decode("latin-1")
    except ValueError:
        return value


def _run_native(request: ReplayRequest, candidate_dir: Path) -> ReplayResult:
    binary_path = Path(str(request.setup.get("binary_path") or ""))
    if not binary_path.exists():
        return _blocked_result(request, candidate_dir, ReplayStatus.SETUP_INVALID.value, f"binary not found: {binary_path}")
    if not os.access(binary_path, os.X_OK):
        return _blocked_result(request, candidate_dir, ReplayStatus.SETUP_INVALID.value, f"binary is not executable: {binary_path}")
    runtime_input, input_artifacts = _materialize_native_runtime_input(request, candidate_dir)
    runtime_input = _replace_runtime_placeholders(runtime_input, candidate_dir=candidate_dir)
    listener_socket, listener_details = _prepare_outbound_listener(request, candidate_dir)
    if listener_details:
        runtime_input = _replace_runtime_placeholders(
            runtime_input,
            candidate_dir=candidate_dir,
            listener_host=str(listener_details["host"]),
            listener_port=int(listener_details["port"]),
        )
    if _service_input_model(runtime_input):
        try:
            runtime_input = _materialize_socket_service_runtime_input(request, runtime_input)
        except ValueError as exc:
            _write_service_replay_result(request, candidate_dir, runtime_input=runtime_input, blocker=str(exc))
            return _blocked_result(request, candidate_dir, ReplayStatus.BLOCKED.value, str(exc))
    argv = [str(binary_path), *[str(item) for item in runtime_input.get("argv", []) or []]]
    stdin_text = _process_stdin_for_input(runtime_input)
    target_env = {
        key: str(
            _replace_runtime_placeholders(
                value,
                candidate_dir=candidate_dir,
                listener_host=str(listener_details.get("host") or ""),
                listener_port=int(listener_details.get("port") or 0),
            )
        )
        for key, value in _process_target_env(request).items()
    }
    target_env.update(_socket_service_runtime_env(runtime_input))
    observation_setup = _prepare_native_observation_setup(request, candidate_dir)
    if not observation_setup.get("ok", True):
        if listener_socket is not None:
            listener_socket.close()
        return _blocked_result(
            request,
            candidate_dir,
            ReplayStatus.SETUP_INVALID.value,
            str(observation_setup.get("reason") or "native observation setup failed"),
        )
    target_env.update({str(key): str(value) for key, value in dict(observation_setup.get("env") or {}).items()})
    timeout = float(request.setup.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
    process_env = None
    if target_env:
        process_env = os.environ.copy()
        process_env.update(target_env)
    working_directory = str(request.setup.get("cwd") or request.setup.get("workdir") or "")
    if working_directory:
        working_directory = str(
            _replace_runtime_placeholders(
                working_directory,
                candidate_dir=candidate_dir,
                listener_host=str(listener_details.get("host") or ""),
                listener_port=int(listener_details.get("port") or 0),
            )
        )
        if not Path(working_directory).is_dir():
            if listener_socket is not None:
                listener_socket.close()
            return _blocked_result(
                request,
                candidate_dir,
                ReplayStatus.SETUP_INVALID.value,
                f"native replay working directory not found: {working_directory}",
            )
    if _service_input_model(runtime_input):
        try:
            transcript = _run_native_socket_service(
                request,
                runtime_input,
                argv,
                stdin_text=stdin_text,
                process_env=process_env,
                timeout=timeout,
            )
        except TimeoutError as exc:
            if listener_socket is not None:
                listener_socket.close()
            _write_service_replay_result(request, candidate_dir, runtime_input=runtime_input, blocker=str(exc))
            return _blocked_result(request, candidate_dir, ReplayStatus.BLOCKED.value, str(exc))
        except OSError as exc:
            if listener_socket is not None:
                listener_socket.close()
            _write_service_replay_result(
                request,
                candidate_dir,
                runtime_input=runtime_input,
                blocker=f"native socket replay failed: {exc}",
            )
            return _blocked_result(request, candidate_dir, ReplayStatus.SETUP_INVALID.value, f"native socket replay failed: {exc}")
    else:
        try:
            completed = subprocess.run(
                argv,
                input=str(stdin_text) if stdin_text is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
                env=process_env,
                cwd=working_directory or None,
            )
        except subprocess.TimeoutExpired as exc:
            if listener_socket is not None:
                listener_socket.close()
            return _blocked_result(request, candidate_dir, ReplayStatus.BLOCKED.value, f"native replay timed out after {timeout}s: {exc}")
        except OSError as exc:
            if listener_socket is not None:
                listener_socket.close()
            return _blocked_result(request, candidate_dir, ReplayStatus.SETUP_INVALID.value, f"native replay could not execute binary: {exc}")
        transcript = {
            "argv": argv,
            "returncode": completed.returncode,
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
        }
    if listener_socket is not None:
        transcript["outbound_listener"] = _observe_outbound_listener(
            listener_socket,
            listener_details,
            timeout=min(timeout, 2.0),
        )
    materialized = runtime_input.get("materialized_argv")
    if materialized:
        transcript["materialized_argv"] = materialized
    if target_env:
        transcript["target_env"] = _bounded_env_for_transcript(target_env)
    syslog_text = _read_native_syslog_observation(observation_setup)
    if syslog_text:
        transcript["syslog"] = syslog_text
    proof_observation, proof_path = _evaluate_process_proof_observation(request, transcript, candidate_dir)
    if proof_observation:
        transcript["proof_observation"] = proof_observation
        transcript["proof_observation_path"] = str(proof_path)
    transcript_path = candidate_dir / "native_transcript.json"
    transcript_path.write_text(json.dumps(transcript, indent=2, sort_keys=True))
    artifacts = [str(candidate_dir / "request.json"), str(transcript_path), *input_artifacts]
    artifacts.extend(str(item) for item in observation_setup.get("artifacts", []) or [])
    if proof_path:
        artifacts.append(str(proof_path))
    if isinstance(proof_observation.get("artifact_refs"), Sequence):
        artifacts.extend(
            str(item)
            for item in proof_observation.get("artifact_refs", [])
            if str(item)
        )
    artifacts = _dedupe(artifacts)
    result = _classify_process_result(request, transcript, artifacts=artifacts)
    if _service_input_model(runtime_input):
        service_path = _write_service_replay_result(
            request,
            candidate_dir,
            runtime_input=runtime_input,
            transcript=transcript,
            result=result,
        )
        artifacts = [*result.artifacts, str(service_path)]
        result = replace(
            result,
            artifacts=artifacts,
            artifact_refs=_artifact_refs(artifacts, kind=f"{request.mode}_replay"),
        )
    return result


def _replace_runtime_placeholders(
    value: Any,
    *,
    candidate_dir: Path,
    listener_host: str = "",
    listener_port: int = 0,
) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _replace_runtime_placeholders(
                item,
                candidate_dir=candidate_dir,
                listener_host=listener_host,
                listener_port=listener_port,
            )
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            _replace_runtime_placeholders(
                item,
                candidate_dir=candidate_dir,
                listener_host=listener_host,
                listener_port=listener_port,
            )
            for item in value
        ]
    if not isinstance(value, str):
        return value
    return (
        value.replace("{candidate_dir}", str(candidate_dir))
        .replace("{listener_host}", listener_host)
        .replace("{listener_port}", str(listener_port) if listener_port else "{listener_port}")
    )


def _prepare_outbound_listener(
    request: ReplayRequest,
    candidate_dir: Path,
) -> tuple[socket.socket | None, dict[str, Any]]:
    raw = request.setup.get("outbound_listener")
    if not isinstance(raw, Mapping):
        raw = _proof_oracle(request).get("outbound_listener")
    if not isinstance(raw, Mapping):
        return None, {}
    host = str(raw.get("host") or "127.0.0.1")
    port = _int(raw.get("port"), 0)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
    except OSError:
        listener.close()
        return None, {
            "host": host,
            "port": port,
            "accepted": False,
            "setup_error": "listener_bind_failed",
            "artifact_dir": str(candidate_dir),
        }
    actual_host, actual_port = listener.getsockname()[:2]
    return listener, {
        "host": str(actual_host),
        "port": int(actual_port),
        "accepted": False,
        "artifact_dir": str(candidate_dir),
    }


def _observe_outbound_listener(
    listener: socket.socket,
    details: Mapping[str, Any],
    *,
    timeout: float,
) -> dict[str, Any]:
    result = dict(details)
    try:
        listener.settimeout(max(0.05, timeout))
        connection, peer = listener.accept()
    except (OSError, socket.timeout):
        result["accepted"] = False
    else:
        result["accepted"] = True
        result["peer"] = [str(peer[0]), int(peer[1])]
        connection.close()
    finally:
        listener.close()
    return result


def _materialize_socket_service_runtime_input(
    request: ReplayRequest,
    runtime_input: Mapping[str, Any],
) -> dict[str, Any]:
    result = dict(runtime_input)
    input_model = _service_input_model(result)
    service = request.setup.get(input_model) if isinstance(request.setup.get(input_model), Mapping) else {}
    if not service and isinstance(request.setup.get("socket_service"), Mapping):
        service = request.setup["socket_service"]
    host = str(result.get("host") or request.setup.get("host") or service.get("host") or "127.0.0.1")
    port = _int(result.get("port") or request.setup.get("port") or service.get("port"), 0)
    argv_items = _socket_service_argv_items(result, service)
    env_updates = _socket_service_env_items(result, service)
    port_env = _socket_service_port_env(result, service)
    port_arg_index = _socket_service_port_arg_index(result, service)
    has_port_placeholder = _contains_port_placeholder(argv_items) or _contains_port_placeholder(env_updates.values())
    if port <= 0:
        if not has_port_placeholder and port_arg_index is None and not port_env:
            raise ValueError(
                "socket_service replay requires a concrete TCP port or deterministic port materialization "
                "(argv placeholder, port_arg_index, or port_env)"
            )
        port = _allocate_local_tcp_port(host)
        result["port_materialized"] = True
    result["host"] = host
    result["port"] = port
    if argv_items:
        argv_items = [_substitute_socket_endpoint(item, host=host, port=port) for item in argv_items]
        if port_arg_index is not None:
            while len(argv_items) <= port_arg_index:
                argv_items.append("")
            argv_items[port_arg_index] = str(port)
        result["argv"] = argv_items
    elif port_arg_index is not None:
        raise ValueError("socket_service port_arg_index requires argv or argv_template facts")
    if env_updates or port_env:
        env_updates = {
            str(key): _substitute_socket_endpoint(value, host=host, port=port)
            for key, value in env_updates.items()
        }
        if port_env:
            env_updates[str(port_env)] = str(port)
        result["env"] = env_updates
    return result


def _service_input_model(input_payload: Mapping[str, Any]) -> str:
    input_model = str(input_payload.get("input_model") or "")
    return input_model if input_model in {"http_daemon", "socket_service"} else ""


def _socket_service_argv_items(input_payload: Mapping[str, Any], service: Mapping[str, Any]) -> list[str]:
    raw = input_payload.get("argv")
    if raw in (None, ""):
        raw = input_payload.get("argv_template") or service.get("argv") or service.get("argv_template")
    if isinstance(raw, str):
        return shlex.split(raw)
    if isinstance(raw, Sequence) and not isinstance(raw, (bytes, bytearray)):
        return [str(item) for item in raw]
    return []


def _socket_service_env_items(input_payload: Mapping[str, Any], service: Mapping[str, Any]) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw in (service.get("env"), input_payload.get("env")):
        if isinstance(raw, Mapping):
            env.update({str(key): str(value) for key, value in raw.items()})
    return env


def _socket_service_port_env(input_payload: Mapping[str, Any], service: Mapping[str, Any]) -> str:
    return str(input_payload.get("port_env") or input_payload.get("port_env_key") or service.get("port_env") or service.get("port_env_key") or "")


def _socket_service_port_arg_index(input_payload: Mapping[str, Any], service: Mapping[str, Any]) -> int | None:
    value = input_payload.get("port_arg_index")
    if value is None:
        value = input_payload.get("port_arg")
    if value is None:
        value = service.get("port_arg_index")
    if value is None:
        value = service.get("port_arg")
    if value is True:
        return 0
    if value in (None, "", False):
        return None
    index = _int(value, -1)
    return index if index >= 0 else None


def _contains_port_placeholder(values: Iterable[Any]) -> bool:
    return any(_has_socket_port_placeholder(str(value)) for value in values)


def _has_socket_port_placeholder(value: str) -> bool:
    return any(token in value for token in ("{port}", "$PORT", "${PORT}"))


def _substitute_socket_endpoint(value: Any, *, host: str, port: int) -> str:
    text = str(value)
    return (
        text.replace("{host}", host)
        .replace("${HOST}", host)
        .replace("$HOST", host)
        .replace("{port}", str(port))
        .replace("${PORT}", str(port))
        .replace("$PORT", str(port))
    )


def _socket_service_runtime_env(runtime_input: Mapping[str, Any]) -> dict[str, str]:
    env = runtime_input.get("env")
    if not isinstance(env, Mapping):
        return {}
    return {str(key): str(value) for key, value in env.items()}


def _allocate_local_tcp_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host or "127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run_native_socket_service(
    request: ReplayRequest,
    runtime_input: Mapping[str, Any],
    argv: Sequence[str],
    *,
    stdin_text: str | None,
    process_env: Mapping[str, str] | None,
    timeout: float,
) -> dict[str, Any]:
    host = str(runtime_input.get("host") or request.setup.get("host") or "127.0.0.1")
    port = _int(runtime_input.get("port") or request.setup.get("port"), 0)
    if port <= 0:
        input_model = _service_input_model(runtime_input)
        service = request.setup.get(input_model) if isinstance(request.setup.get(input_model), Mapping) else {}
        if not service and isinstance(request.setup.get("socket_service"), Mapping):
            service = request.setup["socket_service"]
        port = _int(service.get("port"), 0)
        host = str(service.get("host") or host)
    if port <= 0:
        raise OSError("socket_service replay requires a concrete TCP port")
    start = time.monotonic()
    process = subprocess.Popen(
        list(argv),
        stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        env=dict(process_env) if process_env else None,
    )
    replay_terminated_process = False
    replay_killed_process = False
    try:
        if stdin_text is not None and process.stdin is not None:
            process.stdin.write(str(stdin_text).encode("utf-8", errors="replace"))
            process.stdin.close()
            process.stdin = None
        response = _socket_service_transcript(request, runtime_input, host, port, deadline=start + timeout)
        remaining = max(0.1, min(1.0, start + timeout - time.monotonic()))
        try:
            stdout, stderr = process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired:
            replay_terminated_process = True
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                replay_killed_process = True
                process.kill()
                stdout, stderr = process.communicate(timeout=1.0)
    finally:
        if process.poll() is None:
            replay_terminated_process = True
            process.terminate()
            try:
                process.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                replay_killed_process = True
                process.kill()
                process.communicate(timeout=1.0)
    return {
        "argv": list(argv),
        "returncode": process.returncode if process.returncode is not None else -signal.SIGTERM,
        "stdout": _process_output_text(stdout)[-4000:],
        "stderr": _process_output_text(stderr)[-4000:],
        "socket_service": {"host": host, "port": port, "input_model": _service_input_model(runtime_input)},
        "socket_response": response[-4000:],
        "http_response": response[-4000:] if _service_input_model(runtime_input) == "http_daemon" else "",
        "replay_terminated_process": replay_terminated_process,
        "replay_killed_process": replay_killed_process,
    }


def _socket_service_transcript(
    request: ReplayRequest,
    runtime_input: Mapping[str, Any],
    host: str,
    port: int,
    *,
    deadline: float,
) -> str:
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        timeout = max(0.05, min(0.5, deadline - time.monotonic()))
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(float(runtime_input.get("read_timeout_seconds") or request.setup.get("read_timeout_seconds") or 0.5))
                for payload in _socket_service_payloads(runtime_input):
                    if payload:
                        sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                chunks: list[bytes] = []
                while True:
                    try:
                        chunk = sock.recv(4096)
                    except TimeoutError:
                        break
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b"".join(chunks).decode("utf-8", errors="replace")
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    raise TimeoutError(f"socket_service replay could not connect to {host}:{port}: {last_error}")


def _socket_service_payloads(input_payload: Mapping[str, Any]) -> list[bytes]:
    if _service_input_model(input_payload) == "http_daemon":
        return [_http_daemon_request_bytes(input_payload)]
    raw_steps = input_payload.get("socket_transcript") or input_payload.get("steps")
    payloads: list[tuple[Any, bool]] = []
    if isinstance(raw_steps, Sequence) and not isinstance(raw_steps, (str, bytes, bytearray)):
        for step in raw_steps:
            if isinstance(step, Mapping):
                if step.get("send_hex"):
                    payloads.append((step.get("send_hex"), True))
                else:
                    payloads.append((step.get("send"), False))
            else:
                payloads.append((step, False))
    else:
        if input_payload.get("send_hex"):
            payloads.append((input_payload.get("send_hex"), True))
        else:
            payloads.append((input_payload.get("payload"), False))
    result: list[bytes] = []
    for payload, is_hex in payloads:
        if payload is None:
            continue
        if isinstance(payload, bytes):
            result.append(payload)
        elif isinstance(payload, bytearray):
            result.append(bytes(payload))
        elif is_hex:
            result.append(bytes.fromhex(str(payload)))
        else:
            text = _socket_service_text_payload(str(payload), input_payload)
            result.append(text.encode("utf-8", errors="replace"))
    return result


def _http_daemon_request_bytes(input_payload: Mapping[str, Any]) -> bytes:
    method = str(input_payload.get("method") or "GET").strip().upper() or "GET"
    body = _http_daemon_body(input_payload)
    path = _http_daemon_path(input_payload)
    headers = _http_daemon_headers(input_payload, body=body)
    lines = [f"{method} {path} HTTP/1.0", *[f"{key}: {value}" for key, value in headers.items()], "", ""]
    return ("\r\n".join(lines).encode("utf-8", errors="replace") + body)


def _http_daemon_path(input_payload: Mapping[str, Any]) -> str:
    raw = input_payload.get("path") or input_payload.get("route") or "/"
    if isinstance(raw, Mapping):
        raw = raw.get("path") or raw.get("route") or raw.get("uri") or "/"
    path = str(raw or "/")
    if not path.startswith("/"):
        path = "/" + path
    payload = str(input_payload.get("payload") or "")
    if payload and "{payload}" in path:
        path = path.replace("{payload}", urllib.parse.quote(payload, safe=""))
    query = _http_query_string(input_payload)
    if query:
        separator = "&" if "?" in path else "?"
        path = f"{path}{separator}{query}"
    return path


def _http_daemon_body(input_payload: Mapping[str, Any]) -> bytes:
    if "body_bytes_hex" in input_payload:
        try:
            return bytes.fromhex(str(input_payload.get("body_bytes_hex") or ""))
        except ValueError:
            return str(input_payload.get("body_bytes_hex") or "").encode("latin-1", errors="replace")
    body = _process_stdin_for_input(input_payload)
    if body is None:
        return b""
    return str(body).encode("utf-8", errors="replace")


def _http_daemon_headers(input_payload: Mapping[str, Any], *, body: bytes) -> dict[str, str]:
    headers: dict[str, str] = {"Host": str(input_payload.get("host_header") or input_payload.get("host") or "127.0.0.1")}
    raw = input_payload.get("headers")
    if isinstance(raw, Mapping):
        headers.update({str(key): str(value) for key, value in raw.items()})
    if body:
        headers.setdefault("Content-Type", str(input_payload.get("content_type") or "application/x-www-form-urlencoded"))
        headers["Content-Length"] = str(len(body))
    cookies = input_payload.get("cookies") or input_payload.get("cookie")
    cookie_header = _http_cookie_header(cookies)
    if cookie_header:
        headers.setdefault("Cookie", cookie_header)
    return headers


def _socket_service_text_payload(payload: str, input_payload: Mapping[str, Any]) -> str:
    terminator = _socket_service_payload_terminator(input_payload)
    if terminator and not payload.endswith(terminator):
        return payload + terminator
    return payload


def _socket_service_payload_terminator(input_payload: Mapping[str, Any]) -> str:
    if "request_terminator" in input_payload:
        return str(input_payload.get("request_terminator") or "")
    if "terminator" in input_payload:
        return str(input_payload.get("terminator") or "")
    protocol = str(input_payload.get("protocol") or "").strip().lower()
    if protocol in {"line", "line_oriented", "line-oriented", "text_line", "command_line", "script_line"}:
        return "\n"
    if _bool_flag(input_payload.get("line_terminated")):
        return "\n"
    return ""


def _prepare_native_observation_setup(request: ReplayRequest, candidate_dir: Path) -> dict[str, Any]:
    if not _needs_native_syslog_interposer(request):
        return {"ok": True}
    binary_path = Path(str(request.setup.get("binary_path") or ""))
    if not _binary_accepts_ld_preload(binary_path):
        return {
            "ok": False,
            "reason": "native syslog observation requires a dynamically linked target or script; static ELF cannot be observed with LD_PRELOAD",
            "artifacts": [],
        }
    compiler = _resolve_host_c_compiler(request)
    source_path = candidate_dir / "native_syslog_interposer.c"
    so_path = candidate_dir / "libnative_syslog_interposer.so"
    syslog_path = candidate_dir / "native_syslog.log"
    source_path.write_text(_NATIVE_SYSLOG_INTERPOSER_SOURCE)
    if not compiler:
        return {"ok": False, "reason": "host C compiler not found for native syslog interposer", "artifacts": [str(source_path)]}
    command = [compiler, "-fPIC", "-shared", "-o", str(so_path), str(source_path)]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=float(request.setup.get("shim_compile_timeout_seconds") or 10.0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "reason": f"failed to compile native syslog interposer: {exc}", "artifacts": [str(source_path)]}
    build_log_path = candidate_dir / "native_syslog_interposer_build.json"
    build_log_path.write_text(
        json.dumps(
            {
                "argv": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
            },
            indent=2,
            sort_keys=True,
        )
    )
    if completed.returncode != 0 or not so_path.exists():
        return {"ok": False, "reason": "native syslog interposer compilation failed", "artifacts": [str(source_path), str(build_log_path)]}
    return {
        "ok": True,
        "env": {
            "LD_PRELOAD": str(so_path.resolve()),
            "REPLAY_SYSLOG_PATH": str(syslog_path.resolve()),
        },
        "syslog_path": str(syslog_path),
        "artifacts": [str(source_path), str(build_log_path), str(so_path), str(syslog_path)],
    }


def _needs_native_syslog_interposer(request: ReplayRequest) -> bool:
    return _needs_syslog_observation(request)


def _needs_syslog_observation(request: ReplayRequest) -> bool:
    oracle = _proof_oracle(request)
    kind = str(oracle.get("kind") or oracle.get("type") or "")
    sink = str(oracle.get("sink") or request.setup.get("sink") or request.expected_result.get("sink") or "")
    return kind == "format_string_effect" and (
        _bool_flag(oracle.get("syslog_observation"))
        or sink == "syslog"
        or _bool_flag(request.setup.get("syslog_observation"))
    )


def _binary_accepts_ld_preload(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except OSError:
        return True
    if not data.startswith(b"\x7fELF"):
        return True
    try:
        elf_class = data[4]
        endian = "<" if data[5] == 1 else ">"
        if elf_class == 1:
            e_phoff = struct.unpack_from(f"{endian}I", data, 28)[0]
            e_phentsize = struct.unpack_from(f"{endian}H", data, 42)[0]
            e_phnum = struct.unpack_from(f"{endian}H", data, 44)[0]
        elif elf_class == 2:
            e_phoff = struct.unpack_from(f"{endian}Q", data, 32)[0]
            e_phentsize = struct.unpack_from(f"{endian}H", data, 54)[0]
            e_phnum = struct.unpack_from(f"{endian}H", data, 56)[0]
        else:
            return True
        for index in range(e_phnum):
            offset = e_phoff + index * e_phentsize
            if offset + 4 > len(data):
                return True
            p_type = struct.unpack_from(f"{endian}I", data, offset)[0]
            if p_type == 3:
                return True
    except (struct.error, IndexError):
        return True
    return False


def _read_native_syslog_observation(setup: Mapping[str, Any]) -> str:
    path = Path(str(setup.get("syslog_path") or ""))
    if not path.exists():
        return ""
    try:
        return path.read_text(errors="replace")[-4000:]
    except OSError:
        return ""


def _materialize_native_runtime_input(request: ReplayRequest, candidate_dir: Path) -> tuple[dict[str, Any], list[str]]:
    runtime_input = dict(request.input)
    if runtime_input.get("argv_materialization") != "existing_long_path":
        return runtime_input, []
    argv_items = list(runtime_input.get("argv") or [])
    if not argv_items:
        return runtime_input, []
    target_length = _int(runtime_input.get("payload_length"), len(str(argv_items[0])))
    path = _materialize_existing_long_path(candidate_dir, target_length)
    runtime_input["argv"] = [str(path), *[str(item) for item in argv_items[1:]]]
    runtime_input["materialized_argv"] = [
        {
            "index": 0,
            "kind": "existing_long_path",
            "path": str(path),
            "requested_length": target_length,
            "actual_length": len(str(path)),
        }
    ]
    return runtime_input, [str(path)]


def _materialize_existing_long_path(candidate_dir: Path, target_length: int) -> Path:
    base = (candidate_dir / "native_input_paths").resolve()
    max_path_length = 3500
    target_length = max(1, min(int(target_length or 1), max_path_length))
    directory = base
    path = directory / "payload"
    while len(str(path)) < target_length:
        segment_length = min(80, max(1, target_length - len(str(path))))
        directory = directory / ("d" * segment_length)
        path = directory / "payload"
    directory.mkdir(parents=True, exist_ok=True)
    path.write_text("replay input\n")
    return path


def _run_function_harness(request: ReplayRequest, candidate_dir: Path) -> ReplayResult:
    simulated = request.setup.get("simulate_result") or request.input.get("simulate_result")
    if isinstance(simulated, Mapping):
        result = str(simulated.get("result") or ReplayStatus.NOT_ATTEMPTED.value)
        return ReplayResult(
            candidate_id=request.candidate_id,
            result=ReplayStatus.normalize(result),
            mode=request.mode,
            sink_reached=bool(simulated.get("sink_reached", False)),
            bug_observed=bool(simulated.get("bug_observed", False)),
            crash_observed=bool(simulated.get("crash_observed", False)),
            control_result=dict(simulated),
            artifacts=[str(candidate_dir / "request.json")],
            negative_control_passed=(
                bool(simulated["negative_control_passed"])
                if "negative_control_passed" in simulated and simulated.get("negative_control_passed") is not None
                else None
            ),
            artifact_refs=_artifact_refs([str(candidate_dir / "request.json")], kind="request"),
        )
    return _blocked_result(request, candidate_dir, ReplayStatus.BLOCKED.value, "function harness is not configured")


def _run_qemu_user_function_harness_witness(request: ReplayRequest, candidate_dir: Path) -> ReplayResult:
    """Search deterministic process launch recipes for a function-harness witness."""

    attempts_dir = candidate_dir / "function_harness_process_attempts"
    attempts_dir.mkdir(parents=True, exist_ok=True)
    attempt_summaries: list[dict[str, Any]] = []
    artifacts: list[str] = [str(candidate_dir / "request.json")]
    setup_invalid: ReplayResult | None = None
    for index, (recipe_name, recipe_input) in enumerate(_function_harness_process_recipes(request, candidate_dir), start=1):
        attempt_dir = attempts_dir / f"{index:02d}_{_safe_name(recipe_name)}"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        attempt_setup = dict(request.setup)
        attempt_timeout = float(attempt_setup.get("function_harness_recipe_timeout_seconds") or min(float(attempt_setup.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS), 5.0))
        attempt_setup["timeout_seconds"] = attempt_timeout
        attempt_request = ReplayRequest(
            candidate_id=request.candidate_id,
            mode="qemu_user",
            setup=attempt_setup,
            input=recipe_input,
            expected_result=dict(request.expected_result),
        )
        (attempt_dir / "request.json").write_text(json.dumps(attempt_request.to_dict(), indent=2, sort_keys=True))
        result = _run_qemu_user(attempt_request, attempt_dir)
        write_replay_result(result, attempt_dir / "result.json")
        artifacts.extend(result.artifacts)
        control = dict(result.control_result)
        attempt_summaries.append(
            {
                "recipe": recipe_name,
                "result": result.result,
                "sink_reached": result.sink_reached,
                "bug_observed": result.bug_observed,
                "crash_observed": result.crash_observed,
                "trace_reached_expected_address": bool(control.get("trace_reached_expected_address")),
                "timed_out": bool(control.get("timed_out")),
                "result_path": str(attempt_dir / "result.json"),
            }
        )
        if result.result == ReplayStatus.SETUP_INVALID.value:
            setup_invalid = result
            break
        if result.bug_observed or result.sink_reached:
            return _with_function_harness_attempts(result, request, candidate_dir, attempt_summaries, artifacts)
    attempts_path = candidate_dir / "function_harness_process_attempts.json"
    attempts_path.write_text(json.dumps({"attempts": attempt_summaries}, indent=2, sort_keys=True))
    artifacts.append(str(attempts_path))
    if setup_invalid is not None:
        return _with_function_harness_attempts(setup_invalid, request, candidate_dir, attempt_summaries, artifacts)
    transcript = {
        "returncode": 0,
        "stdout": "",
        "stderr": "",
        "trace_reached_expected_address": False,
        "original_input_model": "function_harness",
        "function_harness_process_attempts": attempt_summaries,
        "process_recipe_source": "deterministic_generic_launch_search",
    }
    return _classify_process_result(request, transcript, artifacts=_dedupe(artifacts))


def _with_function_harness_attempts(
    result: ReplayResult,
    request: ReplayRequest,
    candidate_dir: Path,
    attempts: Sequence[Mapping[str, Any]],
    artifacts: Sequence[str],
) -> ReplayResult:
    attempts_path = candidate_dir / "function_harness_process_attempts.json"
    attempts_path.write_text(json.dumps({"attempts": [dict(item) for item in attempts]}, indent=2, sort_keys=True))
    merged_artifacts = _dedupe([*artifacts, str(attempts_path)])
    control = {
        **dict(result.control_result),
        "original_input_model": "function_harness",
        "process_recipe_source": "deterministic_generic_launch_search",
        "function_harness_process_attempts": [dict(item) for item in attempts],
    }
    return ReplayResult(
        candidate_id=request.candidate_id,
        result=result.result,
        mode=result.mode,
        sink_reached=result.sink_reached,
        bug_observed=result.bug_observed,
        crash_observed=result.crash_observed,
        control_result=control,
        artifacts=merged_artifacts,
        negative_control_passed=result.negative_control_passed,
        artifact_refs=_artifact_refs(merged_artifacts, kind="qemu_user_replay"),
    )


def _function_harness_process_recipes(request: ReplayRequest, candidate_dir: Path) -> list[tuple[str, dict[str, Any]]]:
    input_hex = str(request.input.get("input_hex") or "")
    payload_bytes = _decode_witness_bytes(input_hex)
    if not payload_bytes:
        argv_items = request.input.get("argv") if isinstance(request.input.get("argv"), list) else []
        payload_text = str(argv_items[0]) if argv_items else "payload"
        payload_bytes = payload_text.encode("latin-1", errors="replace")
    payload_text = payload_bytes.decode("latin-1", errors="replace")
    seed_path = candidate_dir / "function_harness_seed_input.bin"
    seed_path.write_bytes(payload_bytes)
    template_path = candidate_dir / "function_harness_seed_template"
    template_path.write_bytes(payload_bytes if payload_bytes.strip() else b"payload\n")
    recipes: list[tuple[str, dict[str, Any]]] = [
        ("argv_witness", {"input_model": "argv", "argv": [payload_text], "input_hex": input_hex}),
        ("stdin_witness", {"input_model": "stdin", "stdin": payload_text, "input_hex": input_hex}),
        ("argv_existing_file", {"input_model": "argv", "argv": [str(seed_path)], "input_hex": input_hex}),
        ("argv_existing_template", {"input_model": "argv", "argv": [str(template_path)], "input_hex": input_hex}),
        ("argv_file_plus_witness", {"input_model": "argv", "argv": [str(seed_path), payload_text], "input_hex": input_hex}),
        ("argv_file_stdin_witness", {"input_model": "stdin", "argv": [str(seed_path)], "stdin": payload_text, "input_hex": input_hex}),
    ]
    return recipes


def _decode_witness_bytes(value: str) -> bytes:
    if not value:
        return b""
    try:
        return bytes.fromhex(value)
    except ValueError:
        return value.encode("latin-1", errors="replace")


def _run_qemu_user_process_recipes(
    request: ReplayRequest,
    candidate_dir: Path,
    recipes: Sequence[Any],
) -> ReplayResult:
    """Attempt every recorded firmware recipe without inventing hidden setup."""

    attempts_dir = candidate_dir / "process_recipe_attempts"
    attempts_dir.mkdir(parents=True, exist_ok=True)
    summaries: list[dict[str, Any]] = []
    results: list[ReplayResult] = []
    artifacts: list[str] = [str(candidate_dir / "request.json")]
    limit = max(1, min(int(request.setup.get("process_recipe_limit") or 6), 12))
    sessions: dict[tuple[str, ...], FirmwareServiceSession] = {}
    for index, raw in enumerate(recipes[:limit], start=1):
        if not isinstance(raw, Mapping):
            continue
        recipe_id = str(raw.get("recipe_id") or f"recipe-{index}")
        attempt_dir = attempts_dir / f"{index:02d}_{_safe_name(recipe_id)}"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        runtime_input = dict(request.input)
        input_model = str(raw.get("input_model") or runtime_input.get("input_model") or "argv")
        runtime_input["input_model"] = input_model
        if isinstance(raw.get("argv"), Sequence) and not isinstance(raw.get("argv"), (str, bytes, bytearray)):
            runtime_input["argv"] = [str(item) for item in raw.get("argv", [])]
        if raw.get("stdin") not in {None, ""}:
            runtime_input["stdin"] = str(raw.get("stdin"))
        materialized: list[str] = []
        file_replacements: dict[str, str] = {}
        for file_index, item in enumerate(raw.get("files", []) or [], start=1):
            if not isinstance(item, Mapping):
                continue
            original = str(item.get("path") or f"recipe-file-{file_index}")
            destination = attempt_dir / "files" / Path(original).name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(str(item.get("content") or ""))
            materialized.append(str(destination))
            file_replacements[original] = str(destination)
        runtime_input["argv"] = [
            file_replacements.get(str(item), str(item))
            for item in runtime_input.get("argv", []) or []
        ]
        setup = dict(request.setup)
        setup.pop("process_recipes", None)
        setup["process_recipe_active"] = True
        setup["process_recipe_id"] = recipe_id
        setup["timeout_seconds"] = min(
            float(setup.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS),
            float(setup.get("process_recipe_timeout_seconds") or 3.0),
        )
        env = dict(setup.get("env") or {}) if isinstance(setup.get("env"), Mapping) else {}
        if isinstance(raw.get("env"), Mapping):
            env.update({str(key): str(value) for key, value in raw["env"].items()})
        if env:
            setup["env"] = env
        dependencies = [str(item) for item in raw.get("required_daemons", []) or []]
        dependency_key = tuple(sorted(set(dependencies)))
        service_session: FirmwareServiceSession | None = None
        dependency_status = "not_required"
        dependency_states: dict[str, dict[str, Any]] = {}
        if dependency_key:
            service_session = sessions.get(dependency_key)
            if service_session is None:
                binary_path = Path(str(setup.get("binary_path") or ""))
                rootfs_request = ReplayRequest(
                    candidate_id=request.candidate_id,
                    mode="qemu_user",
                    setup=setup,
                    input=runtime_input,
                    expected_result=dict(request.expected_result),
                )
                base_rootfs = _prepare_qemu_user_rootfs(
                    rootfs_request,
                    candidate_dir / "dependency_rootfs_resolution",
                    binary_path,
                )
                tool = _resolve_qemu_user_tool(rootfs_request)
                if base_rootfs is not None and tool:
                    dependency_id = hashlib.sha256("\0".join(dependency_key).encode()).hexdigest()[:12]
                    service_session = prepare_firmware_service_sandbox(
                        base_rootfs,
                        candidate_dir / "dependency_sandboxes" / dependency_id,
                        tool,
                        dependency_key,
                        startup_timeout_seconds=float(
                            setup.get("firmware_service_startup_timeout_seconds") or 2.0
                        ),
                    )
                    sessions[dependency_key] = service_session
                else:
                    dependency_status = "blocked"
                    dependency_states = {
                        name: {
                            "name": name,
                            "status": "unsupported",
                            "evidence": [],
                            "blocker": (
                                "qemu_user rootfs could not be inferred"
                                if base_rootfs is None
                                else "qemu_user tool not configured or not found"
                            ),
                        }
                        for name in dependency_key
                    }
            if service_session is not None:
                setup["rootfs_path"] = str(service_session.rootfs_path)
        attempt_request = ReplayRequest(
            candidate_id=request.candidate_id,
            mode="qemu_user",
            setup=setup,
            input=runtime_input,
            expected_result=dict(request.expected_result),
        )
        request_path = attempt_dir / "request.json"
        request_path.write_text(json.dumps(attempt_request.to_dict(), indent=2, sort_keys=True))
        if dependency_key and service_session is None:
            result = _blocked_result(
                attempt_request,
                attempt_dir,
                ReplayStatus.BLOCKED.value,
                next(
                    (
                        str(item.get("blocker") or "")
                        for item in dependency_states.values()
                        if item.get("blocker")
                    ),
                    "firmware_dependencies_unavailable",
                ),
            )
        elif service_session is not None:
            try:
                if service_session.start():
                    dependency_status = "observed_ready"
                    result = _run_qemu_user(attempt_request, attempt_dir)
                else:
                    dependency_status = "blocked"
                    result = _blocked_result(
                        attempt_request,
                        attempt_dir,
                        ReplayStatus.BLOCKED.value,
                        service_session.blocker or "firmware_dependency_health_check_failed",
                    )
            finally:
                service_session.stop()
            dependency_states = service_session.states_dict()
            result = _with_firmware_service_artifacts(
                result,
                service_session,
                dependency_status=dependency_status,
            )
        else:
            result = _run_qemu_user(attempt_request, attempt_dir)
        write_replay_result(result, attempt_dir / "result.json")
        results.append(result)
        artifacts.extend([str(request_path), *materialized, *result.artifacts])
        summaries.append(
            {
                "recipe_id": recipe_id,
                "source": str(raw.get("source") or ""),
                "confidence": float(raw.get("confidence") or 0.0),
                "required_daemons": dependencies,
                "dependency_status": dependency_status,
                "dependency_states": dependency_states,
                "result": result.result,
                "sink_reached": result.sink_reached,
                "bug_observed": result.bug_observed,
                "trace_reached_expected_address": bool(result.control_result.get("trace_reached_expected_address")),
                "result_path": str(attempt_dir / "result.json"),
            }
        )
        if result.bug_observed or bool(result.control_result.get("trace_reached_expected_address")):
            break
    summary_path = candidate_dir / "process_recipe_attempts.json"
    summary_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_kind": "firmware_process_recipe_attempts",
                "attempts": summaries,
                "authority": "observed_recipe_results_only",
            },
            indent=2,
            sort_keys=True,
        )
    )
    artifacts.append(str(summary_path))
    if not results:
        return _blocked_result(request, candidate_dir, ReplayStatus.BLOCKED.value, "no_valid_process_recipes")
    best = max(
        results,
        key=lambda item: (
            int(item.bug_observed),
            int(item.sink_reached),
            int(item.result == ReplayStatus.CONFIRMED.value),
            int(item.result != ReplayStatus.SETUP_INVALID.value),
        ),
    )
    control = {
        **dict(best.control_result),
        "process_recipe_source": "deterministic_firmware_reconstruction",
        "process_recipe_attempts": summaries,
    }
    merged = _dedupe(artifacts)
    return ReplayResult(
        candidate_id=best.candidate_id,
        result=best.result,
        mode=best.mode,
        sink_reached=best.sink_reached,
        bug_observed=best.bug_observed,
        crash_observed=best.crash_observed,
        control_result=control,
        artifacts=merged,
        negative_control_passed=best.negative_control_passed,
        artifact_refs=_artifact_refs(merged, kind="qemu_process_recipe_replay"),
    )


def _with_firmware_service_artifacts(
    result: ReplayResult,
    session: FirmwareServiceSession,
    *,
    dependency_status: str,
) -> ReplayResult:
    """Attach setup evidence without changing reach or bug observations."""

    artifacts = _dedupe([*result.artifacts, *session.artifacts])
    control = {
        **dict(result.control_result),
        "firmware_service_setup": {
            "status": dependency_status,
            "rootfs_path": str(session.rootfs_path),
            "dependencies": session.states_dict(),
            "authority": "process_setup_observation_not_vulnerability_evidence",
        },
    }
    return ReplayResult(
        candidate_id=result.candidate_id,
        result=result.result,
        mode=result.mode,
        sink_reached=result.sink_reached,
        bug_observed=result.bug_observed,
        crash_observed=result.crash_observed,
        control_result=control,
        artifacts=artifacts,
        negative_control_passed=result.negative_control_passed,
        artifact_refs=_artifact_refs(artifacts, kind="qemu_firmware_service_replay"),
    )


def _run_qemu_user(request: ReplayRequest, candidate_dir: Path) -> ReplayResult:
    recipes = request.setup.get("process_recipes")
    if (
        isinstance(recipes, Sequence)
        and not isinstance(recipes, (str, bytes, bytearray))
        and recipes
        and not bool(request.setup.get("process_recipe_active"))
    ):
        return _run_qemu_user_process_recipes(request, candidate_dir, recipes)
    if str(request.input.get("input_model") or "") == "function_harness":
        return _run_qemu_user_function_harness_witness(request, candidate_dir)
    binary_path = Path(str(request.setup.get("binary_path") or ""))
    if not binary_path.exists():
        return _blocked_result(request, candidate_dir, ReplayStatus.SETUP_INVALID.value, f"binary not found: {binary_path}")
    if not os.access(binary_path, os.X_OK):
        return _blocked_result(request, candidate_dir, ReplayStatus.SETUP_INVALID.value, f"binary is not executable: {binary_path}")
    if _needs_syslog_observation(request):
        return _blocked_result(
            request,
            candidate_dir,
            ReplayStatus.BLOCKED.value,
            "qemu_user syslog observation is unsupported; use native replay on a dynamically linked target or a non-syslog proof oracle",
        )
    tool = _resolve_qemu_user_tool(request)
    if not tool:
        return _blocked_result(request, candidate_dir, ReplayStatus.BLOCKED.value, "qemu_user tool not configured or not found")
    rootfs = _prepare_qemu_user_rootfs(request, candidate_dir, binary_path)
    if rootfs is None:
        return _blocked_result(request, candidate_dir, ReplayStatus.SETUP_INVALID.value, "qemu_user rootfs could not be inferred")

    proof_oracle = _proof_oracle(request)
    expected_address = _normalize_address(
        request.expected_result.get("sink_address")
        or request.expected_result.get("target_address")
        or request.setup.get("sink_address")
        or request.setup.get("target_address")
    )
    trace_path = candidate_dir / ("qemu_proof_trace.log" if proof_oracle else "qemu_in_asm.log")
    transcript_path = candidate_dir / "qemu_user_transcript.json"
    target_env = _qemu_target_env(request)
    filesystem_entries = _qemu_filesystem_entries(request)
    shim_artifacts: list[str] = []
    filesystem_artifacts: list[str] = []
    filesystem_wrapper: list[str] = []
    oracle_artifacts: list[str] = []
    oracle_plugin_args: list[str] = []
    target_proof_path: Path | None = None
    if filesystem_entries:
        filesystem_result = _prepare_qemu_filesystem_bindings(request, candidate_dir, filesystem_entries)
        filesystem_artifacts = list(filesystem_result.get("artifacts") or [])
        if not filesystem_result.get("ok"):
            return _blocked_result(
                request,
                candidate_dir,
                ReplayStatus.BLOCKED.value,
                str(filesystem_result.get("reason") or "qemu_user replay filesystem shim could not be prepared"),
            )
        filesystem_wrapper = [str(item) for item in filesystem_result.get("wrapper") or []]
    if _needs_qemu_nvram_shim(request, target_env):
        if not _is_relative_to(rootfs, candidate_dir):
            rootfs = _build_qemu_sysroot_overlay(rootfs, candidate_dir / "qemu_rootfs_overlay")
        shim_result = _prepare_qemu_nvram_shim(request, rootfs, candidate_dir)
        shim_artifacts = list(shim_result.get("artifacts") or [])
        if not shim_result.get("ok"):
            return _blocked_result(
                request,
                candidate_dir,
                ReplayStatus.BLOCKED.value,
                str(shim_result.get("reason") or "qemu_user nvram shim could not be prepared"),
            )
    if _needs_qemu_overflow_oracle(proof_oracle):
        if not _is_relative_to(rootfs, candidate_dir):
            rootfs = _build_qemu_sysroot_overlay(rootfs, candidate_dir / "qemu_rootfs_overlay")
        oracle_result = _prepare_qemu_overflow_oracle(request, rootfs, candidate_dir)
        oracle_artifacts = list(oracle_result.get("artifacts") or [])
        if not oracle_result.get("ok"):
            return _blocked_result(
                request,
                candidate_dir,
                ReplayStatus.BLOCKED.value,
                str(oracle_result.get("reason") or "qemu_user overflow oracle could not be prepared"),
            )
        target_proof_path = Path(str(oracle_result.get("observation_path") or ""))
        oracle_plugin_args = [str(item) for item in oracle_result.get("plugin_args", []) or []]
    elif expected_address and bool(request.setup.get("qemu_exact_instruction_trace", False)):
        raw_addresses = request.setup.get("operation_addresses") or [expected_address]
        if not isinstance(raw_addresses, Sequence) or isinstance(raw_addresses, (str, bytes, bytearray)):
            raw_addresses = [expected_address]
        trace_result = _prepare_qemu_exact_instruction_trace(
            request,
            candidate_dir,
            [str(item) for item in raw_addresses],
        )
        oracle_artifacts = list(trace_result.get("artifacts") or [])
        if trace_result.get("ok"):
            oracle_plugin_args = [str(item) for item in trace_result.get("plugin_args", []) or []]
    elif expected_address and bool(request.setup.get("qemu_exact_access", False)):
        access_result = _prepare_qemu_exact_access(request, candidate_dir, expected_address)
        oracle_artifacts = list(access_result.get("artifacts") or [])
        if access_result.get("ok"):
            target_proof_path = Path(str(access_result.get("observation_path") or ""))
            oracle_plugin_args = [str(item) for item in access_result.get("plugin_args", []) or []]
    runtime_input = dict(request.input)
    input_file_artifacts = _materialize_qemu_input_files(runtime_input, candidate_dir)
    argv = [str(tool), "-L", str(rootfs)]
    if oracle_plugin_args:
        argv.extend(oracle_plugin_args)
    syscall_oracle_enabled = _needs_qemu_syscall_oracle(proof_oracle)
    if syscall_oracle_enabled:
        argv.append("-strace")
    register_oracle_enabled = _needs_qemu_register_oracle(proof_oracle)
    trace_enabled = bool((expected_address or proof_oracle) and request.setup.get("trace_instructions", True))
    if trace_enabled:
        if register_oracle_enabled:
            argv.extend(["-one-insn-per-tb", "-d", "in_asm,cpu"])
            trace_filter = _qemu_proof_trace_filter(proof_oracle, expected_address)
            if trace_filter:
                argv.extend(["-dfilter", trace_filter])
        else:
            argv.extend(["-d", "in_asm"])
            if expected_address:
                trace_window = _qemu_trace_window(expected_address)
                if trace_window:
                    argv.extend(["-dfilter", trace_window])
        argv.extend(["-D", str(trace_path)])
    inherited_target_env: dict[str, str] = {}
    for key, value in target_env.items():
        if _qemu_env_requires_inheritance(str(key), str(value)):
            inherited_target_env[str(key)] = str(value)
            continue
        argv.extend(["-E", f"{key}={value}"])
    argv.append(str(binary_path))
    argv.extend(str(item) for item in runtime_input.get("argv", []) or [])
    if filesystem_wrapper:
        argv = [*filesystem_wrapper, *argv]
    stdin_text = _process_stdin_for_input(runtime_input)
    timeout = float(request.setup.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
    try:
        process_env = None
        if inherited_target_env:
            process_env = os.environ.copy()
            process_env.update(inherited_target_env)
        completed = subprocess.run(
            argv,
            input=stdin_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            env=process_env,
        )
    except subprocess.TimeoutExpired as exc:
        return _finalize_qemu_user_result(
            request,
            candidate_dir,
            rootfs=rootfs,
            argv=argv,
            returncode=124,
            stdout=_process_output_text(exc.stdout),
            stderr=_process_output_text(exc.stderr),
            trace_enabled=trace_enabled,
            expected_address=expected_address,
            trace_path=trace_path,
            transcript_path=transcript_path,
            proof_oracle=proof_oracle,
            register_oracle_enabled=register_oracle_enabled,
            syscall_oracle_enabled=syscall_oracle_enabled,
            target_proof_path=target_proof_path,
            shim_artifacts=shim_artifacts,
            filesystem_artifacts=filesystem_artifacts,
            oracle_artifacts=oracle_artifacts,
            input_file_artifacts=input_file_artifacts,
            inherited_target_env=inherited_target_env,
            timed_out=True,
            timeout_reason=f"qemu_user replay timed out after {timeout}s: {exc}",
        )

    return _finalize_qemu_user_result(
        request,
        candidate_dir,
        rootfs=rootfs,
        argv=argv,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        trace_enabled=trace_enabled,
        expected_address=expected_address,
        trace_path=trace_path,
        transcript_path=transcript_path,
        proof_oracle=proof_oracle,
        register_oracle_enabled=register_oracle_enabled,
        syscall_oracle_enabled=syscall_oracle_enabled,
        target_proof_path=target_proof_path,
        shim_artifacts=shim_artifacts,
        filesystem_artifacts=filesystem_artifacts,
        oracle_artifacts=oracle_artifacts,
        input_file_artifacts=input_file_artifacts,
        inherited_target_env=inherited_target_env,
    )


def _finalize_qemu_user_result(
    request: ReplayRequest,
    candidate_dir: Path,
    *,
    rootfs: Path,
    argv: Sequence[str],
    returncode: int,
    stdout: Any,
    stderr: Any,
    trace_enabled: bool,
    expected_address: str,
    trace_path: Path,
    transcript_path: Path,
    proof_oracle: Mapping[str, Any],
    register_oracle_enabled: bool,
    syscall_oracle_enabled: bool,
    target_proof_path: Path | None,
    shim_artifacts: Sequence[str],
    filesystem_artifacts: Sequence[str],
    oracle_artifacts: Sequence[str],
    input_file_artifacts: Sequence[str],
    inherited_target_env: Mapping[str, str],
    timed_out: bool = False,
    timeout_reason: str = "",
) -> ReplayResult:
    stdout_text = _process_output_text(stdout)
    stderr_text = _process_output_text(stderr)
    qemu_log_text = ""
    if syscall_oracle_enabled and trace_path.exists():
        try:
            qemu_log_text = trace_path.read_text(errors="ignore")
        except OSError:
            qemu_log_text = ""
    trace_reached = _trace_contains_address(trace_path, expected_address) if trace_enabled and expected_address else False
    register_observation = (
        _evaluate_qemu_proof_oracle(proof_oracle, trace_path)
        if register_oracle_enabled and trace_path.exists()
        else {}
    )
    memory_observation = _load_json(target_proof_path) if target_proof_path is not None and target_proof_path.exists() else {}
    proof_observation = _merge_qemu_proof_observations(memory_observation, register_observation)
    transcript = {
        "argv": argv,
        "returncode": returncode,
        "stdout": stdout_text[-4000:],
        "stderr": stderr_text[-4000:],
        "rootfs": str(rootfs),
        "trace_path": str(trace_path) if trace_path.exists() else "",
        "expected_address": expected_address,
        "trace_reached_expected_address": trace_reached,
        "qemu_strace_enabled": syscall_oracle_enabled,
        "nvram_shim_artifacts": shim_artifacts,
        "filesystem_artifacts": filesystem_artifacts,
        "input_file_artifacts": input_file_artifacts,
        "overflow_oracle_artifacts": oracle_artifacts,
    }
    if timed_out:
        transcript["timed_out"] = True
        transcript["timeout_reason"] = timeout_reason
    if inherited_target_env:
        transcript["inherited_target_env"] = dict(sorted(inherited_target_env.items()))
    if target_proof_path is not None:
        transcript["target_overflow_observation_path"] = str(target_proof_path)
    process_observation, process_observation_path = _evaluate_process_proof_observation(
        request,
        {**transcript, "stdout": stdout_text, "stderr": "\n".join(item for item in (stderr_text, qemu_log_text) if item)},
        candidate_dir,
    )
    if process_observation and (not proof_observation or proof_observation.get("status") == "unsupported_oracle"):
        proof_observation = process_observation
    if proof_observation:
        proof_path = candidate_dir / "dynamic_overflow_observation.json"
        if process_observation_path:
            proof_path = process_observation_path
        proof_path.write_text(json.dumps(proof_observation, indent=2, sort_keys=True))
        transcript["proof_observation"] = proof_observation
        transcript["proof_observation_path"] = str(proof_path)
    transcript_path.write_text(json.dumps(transcript, indent=2, sort_keys=True))
    artifacts = [
        str(candidate_dir / "request.json"),
        str(transcript_path),
        *[str(item) for item in shim_artifacts],
        *[str(item) for item in filesystem_artifacts],
        *[str(item) for item in input_file_artifacts],
        *[str(item) for item in oracle_artifacts],
    ]
    if target_proof_path is not None and target_proof_path.exists():
        artifacts.append(str(target_proof_path))
    if transcript.get("proof_observation_path"):
        artifacts.append(str(transcript["proof_observation_path"]))
    if trace_path.exists():
        artifacts.append(str(trace_path))
    result = _classify_process_result(request, transcript, artifacts=artifacts)
    if timed_out and result.result == ReplayStatus.SINK_NOT_REACHED.value:
        blocked_path = candidate_dir / "blocked.json"
        blocked_path.write_text(json.dumps({"reason": timeout_reason}, indent=2, sort_keys=True))
        artifacts = _dedupe([*artifacts, str(blocked_path)])
        return ReplayResult(
            candidate_id=result.candidate_id,
            result=ReplayStatus.BLOCKED.value,
            mode=result.mode,
            sink_reached=result.sink_reached,
            bug_observed=result.bug_observed,
            crash_observed=result.crash_observed,
            control_result={**dict(result.control_result), "reason": timeout_reason},
            artifacts=artifacts,
            negative_control_passed=result.negative_control_passed,
            artifact_refs=_artifact_refs(artifacts, kind="blocked_replay"),
        )
    return result


def _run_external_tool(request: ReplayRequest, candidate_dir: Path, tool: str | None, mode_name: str) -> ReplayResult:
    if not tool or not shutil.which(tool):
        return _blocked_result(request, candidate_dir, ReplayStatus.BLOCKED.value, f"{mode_name} tool not configured or not found")
    return _blocked_result(request, candidate_dir, ReplayStatus.BLOCKED.value, f"{mode_name} execution template is not configured")


def _run_container_service(request: ReplayRequest, candidate_dir: Path) -> ReplayResult:
    command = request.setup.get("command")
    if not isinstance(command, list) or not command:
        return _blocked_result(request, candidate_dir, ReplayStatus.BLOCKED.value, "container service command is not configured")
    return _blocked_result(request, candidate_dir, ReplayStatus.BLOCKED.value, "container service runner requires an explicit harness implementation")


def _evaluate_process_proof_observation(
    request: ReplayRequest,
    transcript: Mapping[str, Any],
    candidate_dir: Path,
) -> tuple[dict[str, Any], Path | None]:
    oracle = _proof_oracle(request)
    kind = str(oracle.get("kind") or oracle.get("type") or "")
    if kind not in SEMANTIC_PROCESS_ORACLE_KINDS:
        return {}, None
    vulnerability_type = str(request.expected_result.get("vulnerability_type") or "")
    if supports_semantic_oracle(vulnerability_type):
        normalized = observe_effect(
            vulnerability_type,
            request,
            transcript,
            candidate_dir,
        )
        observation = normalized.to_dict()
        path = candidate_dir / f"dynamic_{kind}_observation.json"
        path.write_text(json.dumps(observation, indent=2, sort_keys=True))
        return observation, path
    combined = _combined_process_observation_text(transcript)
    marker = str(
        oracle.get("marker")
        or oracle.get("marker_text")
        or oracle.get("marker_content")
        or request.expected_result.get("marker")
        or request.expected_result.get("sink_output_contains")
        or ""
    )
    proof_file = str(
        oracle.get("proof_file")
        or oracle.get("proof_file_path")
        or oracle.get("marker_file")
        or oracle.get("escaped_path")
        or oracle.get("target_path")
        or ""
    )
    stdout_marker_observed = bool(marker and marker in combined)
    file_marker_observed = _proof_file_contains(proof_file, marker)
    file_exists = bool(proof_file and Path(proof_file).exists())
    syscall_observation = _evaluate_semantic_syscall_observation(kind, oracle, request, combined)
    syscall_bug_observed = bool(syscall_observation.get("bug_observed", False))
    if kind == "command_effect":
        bug_observed = stdout_marker_observed or file_marker_observed or bool(file_exists and not marker) or syscall_bug_observed
        status = "command_effect_observed" if bug_observed else "command_effect_not_observed"
    elif kind == "filesystem_read_escape":
        bug_observed = stdout_marker_observed or file_marker_observed or syscall_bug_observed
        status = "filesystem_read_escape_observed" if bug_observed else "filesystem_read_escape_not_observed"
    elif kind == "filesystem_write_escape":
        bug_observed = file_marker_observed or bool(file_exists and not marker) or syscall_bug_observed
        status = "filesystem_write_escape_observed" if bug_observed else "filesystem_write_escape_not_observed"
    elif kind == "credential_disclosure":
        credential_observation = _evaluate_marker_or_tokens(
            oracle,
            request,
            combined,
            default_status="credential_disclosure_not_observed",
            observed_status="credential_disclosure_observed",
            token_keys=("credential", "credential_token", "secret", "secret_token", "username", "password"),
        )
        bug_observed = bool(credential_observation.get("bug_observed", False)) or file_marker_observed
        status = "credential_disclosure_observed" if bug_observed else "credential_disclosure_not_observed"
    elif kind == "auth_bypass_effect":
        auth_observation = _evaluate_marker_or_tokens(
            oracle,
            request,
            combined,
            default_status="auth_bypass_not_observed",
            observed_status="auth_bypass_observed",
            token_keys=("authenticated_marker", "admin_marker", "success_marker", "role", "session_marker"),
        )
        bug_observed = bool(auth_observation.get("bug_observed", False)) or file_marker_observed
        status = "auth_bypass_observed" if bug_observed else "auth_bypass_not_observed"
    else:
        format_observation = _evaluate_format_string_effect(oracle, marker, combined)
        bug_observed = bool(format_observation.get("bug_observed", False))
        status = "format_string_effect_observed" if bug_observed else "format_string_effect_not_observed"
    observation = {
        "status": status,
        "kind": kind,
        "bug_observed": bug_observed,
        "sink_reached": bug_observed or stdout_marker_observed or file_exists or bool(syscall_observation.get("sink_reached", False)),
        "marker": marker,
        "stdout_marker_observed": stdout_marker_observed,
        "file_marker_observed": file_marker_observed,
        "proof_file": proof_file,
        "proof_file_exists": file_exists,
        "oracle": dict(oracle),
    }
    if syscall_observation:
        observation["syscall_observation"] = syscall_observation
    if kind == "format_string_effect":
        observation["format_string_observation"] = format_observation
    if kind == "credential_disclosure":
        observation["credential_observation"] = credential_observation
    if kind == "auth_bypass_effect":
        observation["auth_observation"] = auth_observation
    path = candidate_dir / f"dynamic_{kind}_observation.json"
    path.write_text(json.dumps(observation, indent=2, sort_keys=True))
    return observation, path


def _evaluate_marker_or_tokens(
    oracle: Mapping[str, Any],
    request: ReplayRequest,
    output: str,
    *,
    default_status: str,
    observed_status: str,
    token_keys: Sequence[str],
) -> dict[str, Any]:
    marker = _oracle_marker(oracle, request)
    tokens: list[str] = []
    for key in token_keys:
        value = oracle.get(key)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            tokens.extend(str(item) for item in value if str(item))
        elif value not in (None, ""):
            tokens.append(str(value))
    tokens.extend(_meaningful_tokens(_request_input_values(request.input), command=False))
    tokens = _dedupe([token for token in tokens if len(str(token)) >= 3])[:16]
    marker_observed = bool(marker and marker in output)
    token_hits = [token for token in tokens if token and token in output]
    bug_observed = marker_observed or bool(token_hits)
    return {
        "status": observed_status if bug_observed else default_status,
        "bug_observed": bug_observed,
        "marker": marker,
        "marker_observed": marker_observed,
        "token_hits": token_hits[:8],
    }


def _evaluate_format_string_effect(oracle: Mapping[str, Any], marker: str, output: str) -> dict[str, Any]:
    directive = str(oracle.get("format_directive") or "%x")
    if not marker or not directive or directive not in marker:
        return {
            "status": "format_probe_missing_directive",
            "bug_observed": False,
            "literal_marker_observed": bool(marker and marker in output),
            "expanded_marker_observed": False,
            "format_directive": directive,
        }
    prefix, _sep, suffix = marker.partition(directive)
    if not prefix and not suffix:
        return {
            "status": "format_probe_missing_stable_context",
            "bug_observed": False,
            "literal_marker_observed": marker in output,
            "expanded_marker_observed": False,
            "format_directive": directive,
        }
    expanded_pattern = re.compile(re.escape(prefix) + r"[0-9a-fA-F]+" + re.escape(suffix))
    literal_observed = marker in output
    expanded_observed = bool(expanded_pattern.search(output))
    bug_observed = expanded_observed and not literal_observed
    return {
        "status": "format_string_effect_observed" if bug_observed else "format_string_effect_not_observed",
        "bug_observed": bug_observed,
        "literal_marker_observed": literal_observed,
        "expanded_marker_observed": expanded_observed,
        "format_directive": directive,
        "prefix": prefix,
        "suffix": suffix,
    }


def _evaluate_semantic_syscall_observation(
    kind: str,
    oracle: Mapping[str, Any],
    request: ReplayRequest,
    output: str,
) -> dict[str, Any]:
    if kind not in {"command_effect", "filesystem_read_escape", "filesystem_write_escape"}:
        return {}
    if not bool(oracle.get("syscall_observation", True)):
        return {}
    calls = _parse_qemu_strace(output)
    if not calls:
        return {
            "status": "no_qemu_syscalls_observed",
            "kind": kind,
            "bug_observed": False,
            "sink_reached": False,
            "syscall_count": 0,
        }
    if kind == "command_effect":
        return _evaluate_command_syscall_observation(oracle, request, calls)
    return _evaluate_filesystem_syscall_observation(kind, oracle, request, calls)


def _parse_qemu_strace(output: str) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = re.match(r"^(?:\d+\s+)?([A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s+=\s+(.+)$", line)
        if not match:
            continue
        syscall = match.group(1)
        args = match.group(2)
        result = match.group(3).strip()
        strings = [_decode_strace_string(item) for item in re.findall(r'"((?:\\.|[^"\\])*)"', args)]
        calls.append(
            {
                "syscall": syscall,
                "args": args[:1000],
                "strings": strings[:16],
                "result": result[:120],
                "successful": not result.startswith("-"),
                "line": line[:1200],
            }
        )
    return calls


def _decode_strace_string(value: str) -> str:
    if not value:
        return ""
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return value.replace(r"\"", '"').replace(r"\\", "\\")


def _evaluate_command_syscall_observation(
    oracle: Mapping[str, Any],
    request: ReplayRequest,
    calls: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    exec_calls = [call for call in calls if str(call.get("syscall") or "") in {"execve", "execveat"}]
    marker = _oracle_marker(oracle, request)
    tokens = _command_oracle_tokens(oracle, request)
    observations: list[dict[str, Any]] = []
    bug_observed = False
    for call in exec_calls:
        strings = [str(item) for item in call.get("strings", []) or []]
        text = "\n".join(strings)
        marker_observed = bool(marker and marker in text)
        token_hits = [token for token in tokens if token and token in text]
        shell_command = any(posixpath.basename(item) in {"sh", "bash", "ash", "busybox"} for item in strings[:1]) and "-c" in strings
        attributed = marker_observed or bool(token_hits)
        bug_observed = bug_observed or attributed
        observations.append(
            {
                "syscall": str(call.get("syscall") or ""),
                "result": str(call.get("result") or ""),
                "strings": strings[:8],
                "marker_observed": marker_observed,
                "token_hits": token_hits[:4],
                "shell_command": shell_command,
                "attributed_to_replay_input": attributed,
            }
        )
    if bug_observed:
        status = "command_exec_observed_with_replay_input"
    elif exec_calls:
        status = "command_exec_observed_without_replay_input"
    else:
        status = "command_exec_not_observed"
    return {
        "status": status,
        "kind": "command_effect",
        "bug_observed": bug_observed,
        "sink_reached": bool(exec_calls),
        "syscall_count": len(calls),
        "exec_count": len(exec_calls),
        "marker": marker,
        "tokens": tokens[:8],
        "exec_observations": observations[:8],
    }


def _evaluate_filesystem_syscall_observation(
    kind: str,
    oracle: Mapping[str, Any],
    request: ReplayRequest,
    calls: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    bug_observed = False
    for call in calls:
        syscall = str(call.get("syscall") or "")
        paths = _syscall_path_arguments(syscall, call)
        if not paths:
            continue
        if kind == "filesystem_read_escape" and not _syscall_can_read_path(syscall, call):
            continue
        if kind == "filesystem_write_escape" and not _syscall_can_write_path(syscall, call):
            continue
        for path in paths:
            reason = _path_escape_reason(path, oracle, request)
            escaped = bool(reason)
            bug_observed = bug_observed or escaped
            events.append(
                {
                    "syscall": syscall,
                    "path": path,
                    "result": str(call.get("result") or ""),
                    "escaped": escaped,
                    "escape_reason": reason,
                    "write_like": _syscall_can_write_path(syscall, call),
                    "read_like": _syscall_can_read_path(syscall, call),
                }
            )
    if kind == "filesystem_read_escape":
        status = "filesystem_read_escape_observed" if bug_observed else "filesystem_read_path_observed_without_escape"
    else:
        status = "filesystem_write_escape_observed" if bug_observed else "filesystem_write_path_observed_without_escape"
    if not events:
        status = f"{kind}_syscall_not_observed"
    return {
        "status": status,
        "kind": kind,
        "bug_observed": bug_observed,
        "sink_reached": bool(events),
        "syscall_count": len(calls),
        "path_event_count": len(events),
        "path_events": events[:16],
        "allowed_bases": _oracle_allowed_bases(oracle, request),
        "path_tokens": _path_oracle_tokens(oracle, request)[:12],
    }


def _syscall_path_arguments(syscall: str, call: Mapping[str, Any]) -> list[str]:
    strings = [str(item) for item in call.get("strings", []) or []]
    if syscall in {"open", "creat", "unlink", "rmdir", "mkdir", "chmod", "chown", "truncate", "stat", "lstat", "access", "readlink"}:
        return strings[:1]
    if syscall in {"openat", "unlinkat", "mkdirat", "fchmodat", "fchownat", "faccessat", "readlinkat", "newfstatat"}:
        return strings[:1]
    if syscall in {"rename", "symlink", "link"}:
        return strings[:2]
    if syscall in {"renameat", "renameat2", "symlinkat", "linkat"}:
        return strings[:2]
    return []


def _syscall_can_read_path(syscall: str, call: Mapping[str, Any]) -> bool:
    if syscall in {"stat", "lstat", "access", "readlink", "newfstatat", "faccessat", "readlinkat"}:
        return True
    if syscall in {"open", "openat"}:
        flags = str(call.get("args") or "").upper()
        return not any(flag in flags for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"))
    return False


def _syscall_can_write_path(syscall: str, call: Mapping[str, Any]) -> bool:
    if syscall in {
        "creat",
        "unlink",
        "unlinkat",
        "rename",
        "renameat",
        "renameat2",
        "rmdir",
        "mkdir",
        "mkdirat",
        "symlink",
        "symlinkat",
        "link",
        "linkat",
        "chmod",
        "fchmodat",
        "chown",
        "fchownat",
        "truncate",
    }:
        return True
    if syscall in {"open", "openat"}:
        flags = str(call.get("args") or "").upper()
        return any(flag in flags for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"))
    return False


def _path_escape_reason(path: str, oracle: Mapping[str, Any], request: ReplayRequest) -> str:
    marker = _oracle_marker(oracle, request)
    if marker and marker in path:
        return "marker_in_path"
    normalized = _normalize_observed_path(path)
    for explicit in _oracle_explicit_paths(oracle):
        if normalized == _normalize_observed_path(explicit):
            return "explicit_oracle_path"
    if _path_has_parent_traversal(path):
        return "parent_traversal"
    path_tokens = _path_oracle_tokens(oracle, request)
    for token in path_tokens:
        if token and token in path and _path_token_is_escape_attempt(token, oracle, request):
            return "attacker_escape_path_token"
    bases = _oracle_allowed_bases(oracle, request)
    if bases and _path_escapes_allowed_bases(path, bases):
        return "outside_allowed_base"
    return ""


def _oracle_marker(oracle: Mapping[str, Any], request: ReplayRequest) -> str:
    return str(
        oracle.get("marker")
        or oracle.get("marker_text")
        or oracle.get("marker_content")
        or request.expected_result.get("marker")
        or request.expected_result.get("sink_output_contains")
        or ""
    )


def _command_oracle_tokens(oracle: Mapping[str, Any], request: ReplayRequest) -> list[str]:
    values: list[Any] = [
        oracle.get("command_token"),
        oracle.get("command"),
        oracle.get("expected_command"),
        oracle.get("payload"),
        oracle.get("command_tokens"),
    ]
    values.extend(_request_input_values(request.input))
    return _meaningful_tokens(values, command=True)


def _path_oracle_tokens(oracle: Mapping[str, Any], request: ReplayRequest) -> list[str]:
    values: list[Any] = [
        oracle.get("path_token"),
        oracle.get("path_tokens"),
        oracle.get("escaped_path"),
        oracle.get("target_path"),
        oracle.get("proof_file"),
        oracle.get("proof_file_path"),
    ]
    values.extend(_request_input_values(request.input))
    return _meaningful_tokens(values, command=False)


def _request_input_values(value: Any) -> list[Any]:
    values: list[Any] = []

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            for child in item.values():
                visit(child)
            return
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for child in item:
                visit(child)
            return
        values.append(item)

    visit(value)
    return values


def _meaningful_tokens(values: Sequence[Any], *, command: bool) -> list[str]:
    tokens: list[str] = []
    flattened: list[Any] = []

    def flatten(value: Any) -> None:
        if isinstance(value, Mapping):
            for child in value.values():
                flatten(child)
            return
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for child in value:
                flatten(child)
            return
        flattened.append(value)

    for value in values:
        flatten(value)
    for value in flattened:
        if value in (None, ""):
            continue
        candidates: list[str]
        if isinstance(value, bytes):
            candidates = [value.decode("latin-1", errors="ignore")]
        elif isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{6,}", value or "") and len(value) % 2 == 0:
            candidates = [value, _decode_witness_hex_text(value)]
        else:
            candidates = [str(value)]
        for candidate in candidates:
            token = candidate.strip("\x00\r\n\t ")
            if not _meaningful_token(token, command=command):
                continue
            if token not in tokens:
                tokens.append(token)
    return tokens[:16]


def _meaningful_token(token: str, *, command: bool) -> bool:
    if len(token) < 3:
        return False
    compact = "".join(ch for ch in token if not ch.isspace())
    if len(compact) < 3:
        return False
    if set(compact) <= {"?", "@"}:
        return False
    if command:
        return any(ch.isalnum() for ch in compact) or any(ch in compact for ch in "$;|&`<>")
    return "/" in token or ".." in token or any(ch.isalnum() for ch in compact)


def _oracle_explicit_paths(oracle: Mapping[str, Any]) -> list[str]:
    values = [
        oracle.get("escaped_path"),
        oracle.get("target_path"),
        oracle.get("proof_file"),
        oracle.get("proof_file_path"),
        oracle.get("marker_file"),
    ]
    return [str(item) for item in values if item not in (None, "")]


def _oracle_allowed_bases(oracle: Mapping[str, Any], request: ReplayRequest) -> list[str]:
    values: list[Any] = [
        oracle.get("allowed_base"),
        oracle.get("allowed_base_path"),
        oracle.get("allowed_prefix"),
        oracle.get("allowed_prefixes"),
        oracle.get("base_path"),
        oracle.get("base_dir"),
        oracle.get("document_root"),
        request.setup.get("allowed_base"),
        request.setup.get("base_path"),
        request.setup.get("base_dir"),
        request.setup.get("document_root"),
        request.setup.get("web_root"),
        request.setup.get("upload_dir"),
    ]
    tokens = _meaningful_tokens(values, command=False)
    return [_normalize_observed_path(token) for token in tokens]


def _path_token_is_escape_attempt(token: str, oracle: Mapping[str, Any], request: ReplayRequest) -> bool:
    if _path_has_parent_traversal(token):
        return True
    bases = _oracle_allowed_bases(oracle, request)
    if bases:
        return _path_escapes_allowed_bases(token, bases)
    return token.startswith("/")


def _path_has_parent_traversal(path: str) -> bool:
    return ".." in [part for part in path.replace("\\", "/").split("/") if part]


def _normalize_observed_path(path: str) -> str:
    text = urllib.parse.unquote(str(path or "").replace("\\", "/"))
    if not text:
        return ""
    return posixpath.normpath(text)


def _path_escapes_allowed_bases(path: str, bases: Sequence[str]) -> bool:
    normalized = _normalize_observed_path(path)
    if not normalized:
        return False
    for base in bases:
        base_norm = _normalize_observed_path(base)
        if not base_norm:
            continue
        candidate = normalized if normalized.startswith("/") else posixpath.normpath(posixpath.join(base_norm, normalized))
        if candidate == base_norm or candidate.startswith(base_norm.rstrip("/") + "/"):
            return False
    return True


def _proof_file_contains(path: str, marker: str) -> bool:
    if not path or not marker:
        return False
    proof_path = Path(path)
    if not proof_path.exists() or not proof_path.is_file():
        return False
    try:
        data = proof_path.read_bytes()[:1024 * 1024]
    except OSError:
        return False
    return marker.encode("utf-8", errors="replace") in data


def _classify_process_result(
    request: ReplayRequest,
    transcript: Mapping[str, Any],
    *,
    artifacts: list[str],
) -> ReplayResult:
    combined = _combined_process_observation_text(transcript)
    returncode = int(transcript.get("returncode") or 0)
    marker = str(request.expected_result.get("sink_output_contains") or "")
    sink_reached = bool(marker and marker in combined)
    if not sink_reached and bool(transcript.get("trace_reached_expected_address", False)):
        sink_reached = True
    proof_oracle = _proof_oracle(request)
    if not sink_reached and not marker and request.setup.get("sink") and not proof_oracle:
        sink_reached = str(request.setup["sink"]) in combined or returncode != 0
    crash_observed = _crash_observed(returncode, combined)
    if crash_observed and _service_exit_was_harness_cleanup(transcript, returncode):
        crash_observed = _crash_observed(0, combined)
    proof_observation = transcript.get("proof_observation") if isinstance(transcript.get("proof_observation"), Mapping) else {}
    proof_bug_observed = bool(proof_observation.get("bug_observed", False))
    if proof_bug_observed or bool(proof_observation.get("sink_reached", False)):
        sink_reached = True
    oracle_kind = str(proof_oracle.get("kind") or proof_oracle.get("type") or "")
    semantic_oracle = oracle_kind in SEMANTIC_PROCESS_ORACLE_KINDS
    pre_target_crash = (
        crash_observed
        and semantic_oracle
        and not bool(transcript.get("trace_reached_expected_address", False))
        and not bool(proof_observation.get("sink_reached", False))
        and not proof_bug_observed
    )
    effective_crash_observed = crash_observed and not pre_target_crash
    crash_bug_observed = (
        effective_crash_observed
        and bool(request.expected_result.get("expect_crash", False))
        and not bool(proof_oracle)
    )
    bug_observed = sink_reached and (crash_bug_observed or proof_bug_observed)
    if bug_observed and sink_reached:
        status = ReplayStatus.CONFIRMED.value
    elif effective_crash_observed:
        status = ReplayStatus.CRASH_UNCLASSIFIED.value
    elif sink_reached:
        status = ReplayStatus.SINK_REACHED_NO_BUG.value
    else:
        status = ReplayStatus.SINK_NOT_REACHED.value
    control_result = dict(transcript)
    if pre_target_crash:
        control_result["pre_target_crash_observed"] = True
        control_result["pre_target_crash_classification"] = "unrelated_to_semantic_oracle"
    return ReplayResult(
        candidate_id=request.candidate_id,
        result=status,
        mode=request.mode,
        sink_reached=sink_reached,
        bug_observed=bug_observed,
        crash_observed=effective_crash_observed,
        control_result=control_result,
        artifacts=artifacts,
        artifact_refs=_artifact_refs(artifacts, kind=f"{request.mode}_replay"),
    )


def _combined_process_observation_text(transcript: Mapping[str, Any]) -> str:
    values = [
        transcript.get("stdout"),
        transcript.get("stderr"),
        transcript.get("socket_response"),
        transcript.get("http_response"),
        transcript.get("syslog"),
    ]
    return "\n".join(str(value or "") for value in values)


def _crash_observed(returncode: int, output: str) -> bool:
    crash_tokens = ("segmentation fault", "buffer overflow detected", "aborted", "core dumped", "invalid write")
    if returncode < 0:
        return True
    lowered = output.lower()
    if any(token in lowered for token in crash_tokens):
        return True
    return returncode in {132, 134, 136, 139}


def _service_exit_was_harness_cleanup(transcript: Mapping[str, Any], returncode: int) -> bool:
    if returncode not in {-signal.SIGTERM, -signal.SIGKILL}:
        return False
    if not bool(transcript.get("replay_terminated_process")):
        return False
    if not isinstance(transcript.get("socket_service"), Mapping):
        return False
    return bool(str(transcript.get("socket_response") or transcript.get("http_response") or ""))


def _process_output_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _blocked_request(state: CandidateState, reason: str) -> ReplayRequest:
    return ReplayRequest(
        candidate_id=state.candidate_id,
        mode="off",
        setup={"reason": reason, "blocked_reason": reason},
        input={},
        expected_result={"candidate_id": state.candidate_id},
    )


def _write_service_replay_result(
    request: ReplayRequest,
    candidate_dir: Path,
    *,
    runtime_input: Mapping[str, Any] | None = None,
    transcript: Mapping[str, Any] | None = None,
    result: ReplayResult | None = None,
    blocker: str = "",
) -> Path:
    runtime_input = dict(runtime_input or request.input)
    transcript = dict(transcript or {})
    input_model = _service_input_model(runtime_input) or _service_input_model(request.input)
    service = request.setup.get(input_model) if isinstance(request.setup.get(input_model), Mapping) else {}
    if not service and isinstance(request.setup.get("socket_service"), Mapping):
        service = request.setup["socket_service"]
    endpoint = {
        "host": str(runtime_input.get("host") or request.setup.get("host") or service.get("host") or "127.0.0.1"),
        "port": _int(runtime_input.get("port") or request.setup.get("port") or service.get("port"), 0),
        "port_materialized": bool(runtime_input.get("port_materialized", False)),
        "port_env": str(runtime_input.get("port_env") or service.get("port_env") or ""),
        "port_arg_index": runtime_input.get("port_arg_index", service.get("port_arg_index") if isinstance(service, Mapping) else None),
    }
    reason = str(blocker or "")
    blockers = [_service_replay_blocker_code(reason)] if reason else []
    artifacts = [str(item) for item in result.artifacts] if result is not None else [str(candidate_dir / "request.json")]
    service_result = {
        "schema_version": 1,
        "artifact_kind": "service_replay_result",
        "candidate_id": request.candidate_id,
        "input_model": input_model,
        "mode": request.mode,
        "status": result.result if result is not None else "blocked",
        "sink_reached": bool(result.sink_reached) if result is not None else False,
        "bug_observed": bool(result.bug_observed) if result is not None else False,
        "crash_observed": bool(result.crash_observed) if result is not None else False,
        "endpoint": endpoint,
        "request": _service_request_summary(runtime_input),
        "environment": _service_environment_summary(request, runtime_input, transcript),
        "process": {
            "returncode": transcript.get("returncode", ""),
            "terminated_by_replay": bool(transcript.get("replay_terminated_process", False)),
            "killed_by_replay": bool(transcript.get("replay_killed_process", False)),
        },
        "response": {
            "socket_response": str(transcript.get("socket_response") or "")[-4000:],
            "http_response": str(transcript.get("http_response") or "")[-4000:],
            "stdout": str(transcript.get("stdout") or "")[-1000:],
            "stderr": str(transcript.get("stderr") or "")[-1000:],
        },
        "artifacts": artifacts,
        "blockers": blockers,
        "blocked_reason": reason,
    }
    path = candidate_dir / "service_replay_result.json"
    path.write_text(json.dumps(service_result, indent=2, sort_keys=True))
    return path


def _service_environment_summary(
    request: ReplayRequest,
    runtime_input: Mapping[str, Any],
    transcript: Mapping[str, Any],
) -> dict[str, Any]:
    setup = request.setup
    target_env: dict[str, str] = {}
    for source in (setup.get("env"), runtime_input.get("env"), transcript.get("target_env")):
        if isinstance(source, Mapping):
            target_env.update({str(key): str(value) for key, value in source.items()})
    raw_argv = transcript.get("argv")
    argv = (
        raw_argv
        if isinstance(raw_argv, Sequence) and not isinstance(raw_argv, (str, bytes, bytearray))
        else []
    )
    startup_command = str(setup.get("startup_command") or setup.get("command") or "")
    if not startup_command and argv:
        startup_command = " ".join(shlex.quote(str(item)) for item in argv)
    routes = setup.get("routes")
    route_count = len(routes) if isinstance(routes, Sequence) and not isinstance(routes, (str, bytes, bytearray)) else 0
    return {
        key: value
        for key, value in {
            "binary_path": str(setup.get("binary_path") or ""),
            "rootfs_path": str(setup.get("rootfs_path") or setup.get("qemu_rootfs") or ""),
            "startup_command": startup_command,
            "cwd": str(setup.get("cwd") or setup.get("workdir") or ""),
            "env_keys": sorted(target_env),
            "config_keys": _service_config_keys(setup),
            "route_count": route_count,
        }.items()
        if value not in (None, "", [], {})
    }


def _service_config_keys(setup: Mapping[str, Any]) -> list[str]:
    keys: list[str] = []
    for name in ("config", "configs", "nvram", "settings"):
        value = setup.get(name)
        if isinstance(value, Mapping):
            keys.extend(str(key) for key in value if str(key))
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for item in value:
                if isinstance(item, Mapping):
                    keys.extend(
                        str(item.get(key))
                        for key in ("key", "name", "config_key", "nvram_key")
                        if item.get(key) not in (None, "")
                    )
    return sorted(_dedupe(keys))


def _service_request_summary(runtime_input: Mapping[str, Any]) -> dict[str, Any]:
    summary = {
        "method": str(runtime_input.get("method") or ""),
        "path": str(runtime_input.get("path") or runtime_input.get("route") or ""),
        "protocol": str(runtime_input.get("protocol") or ""),
        "payload_length": len(str(runtime_input.get("payload") or "")),
        "has_body": any(key in runtime_input for key in ("body", "body_bytes_hex", "form", "stdin")),
        "has_query": any(key in runtime_input for key in ("query", "params")),
    }
    if isinstance(runtime_input.get("headers"), Mapping):
        summary["header_names"] = sorted(str(key) for key in runtime_input["headers"])
    return summary


def _service_replay_blocker_code(reason: str) -> str:
    lowered = str(reason or "").lower()
    if "rootfs" in lowered:
        return "missing_rootfs"
    if "config" in lowered:
        return "missing_config"
    if "event loop" in lowered:
        return "unsupported_event_loop"
    if "route" in lowered:
        return "unresolved_route_handler"
    if "timed out" in lowered or "timeout" in lowered or "could not connect" in lowered:
        return "timeout"
    if "exec format" in lowered or "architecture" in lowered or "qemu" in lowered:
        return "unsupported_architecture"
    if "port" in lowered or "endpoint" in lowered:
        return "missing_service_endpoint"
    return "service_replay_blocked"


def _blocked_result(request: ReplayRequest, candidate_dir: Path, status: str, reason: str) -> ReplayResult:
    block_path = candidate_dir / "blocked.json"
    block_path.write_text(json.dumps({"reason": reason}, indent=2, sort_keys=True))
    artifacts = [str(candidate_dir / "request.json"), str(block_path)]
    service_path = candidate_dir / "service_replay_result.json"
    if service_path.exists():
        artifacts.append(str(service_path))
    return ReplayResult(
        candidate_id=request.candidate_id,
        result=ReplayStatus.normalize(status),
        mode=request.mode,
        sink_reached=False,
        bug_observed=False,
        crash_observed=False,
        control_result={"reason": reason},
        artifacts=artifacts,
        artifact_refs=_artifact_refs(artifacts, kind="blocked_replay"),
    )


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)[:120] or "candidate"


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text() or "{}")
    except json.JSONDecodeError:
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}


def _resolve_qemu_user_tool(request: ReplayRequest) -> str:
    configured = str(request.setup.get("qemu_user_bin") or os.getenv("QEMU_USER_BIN") or "").strip()
    if configured and shutil.which(configured):
        return configured
    binary_path = Path(str(request.setup.get("binary_path") or ""))
    machine = _elf_machine(binary_path)
    candidates: list[str]
    if "ARM" in machine:
        candidates = ["qemu-arm", "qemu-arm-static"]
    elif "X86-64" in machine or "x86-64" in machine or "x86_64" in machine:
        candidates = ["qemu-x86_64", "qemu-x86_64-static"]
    elif "MIPS" in machine and "little" in machine.lower():
        candidates = ["qemu-mipsel", "qemu-mipsel-static"]
    elif "MIPS" in machine:
        candidates = ["qemu-mips", "qemu-mips-static"]
    elif "AArch64" in machine:
        candidates = ["qemu-aarch64", "qemu-aarch64-static"]
    else:
        candidates = []
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return ""


def _elf_machine_is_host_native(machine: str) -> bool:
    normalized = str(machine or "").lower()
    host = platform.machine().lower()
    if not normalized:
        return False
    if "x86-64" in normalized or "x86_64" in normalized or "amd64" in normalized:
        return host in {"x86_64", "amd64"}
    if "aarch64" in normalized:
        return host in {"aarch64", "arm64"}
    return False


def _elf_machine(binary_path: Path) -> str:
    try:
        completed = subprocess.run(
            ["readelf", "-h", str(binary_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    for line in completed.stdout.splitlines():
        if "Machine:" in line:
            return line.split("Machine:", 1)[1].strip()
    return ""


def _prepare_qemu_user_rootfs(request: ReplayRequest, candidate_dir: Path, binary_path: Path) -> Path | None:
    configured = request.setup.get("rootfs_path") or request.setup.get("qemu_rootfs")
    if configured:
        rootfs = Path(str(configured))
        if not rootfs.exists():
            return None
        if _is_unix_rootfs(rootfs):
            return rootfs
        overlay = _build_multi_rootfs_overlay_if_needed(rootfs, candidate_dir / "qemu_rootfs_overlay")
        return overlay or rootfs
    firmware_root = _infer_firmware_root(binary_path)
    if firmware_root is None:
        return _nearest_sysroot(binary_path)
    if _is_unix_rootfs(firmware_root):
        return firmware_root
    overlay = _build_multi_rootfs_overlay_if_needed(firmware_root, candidate_dir / "qemu_rootfs_overlay")
    if overlay is not None:
        return overlay
    return _nearest_sysroot(binary_path)


def _infer_firmware_root(binary_path: Path) -> Path | None:
    parents = [binary_path.parent, *binary_path.parents]
    for parent in parents:
        if parent.name == "rootfs":
            return parent
        if len(_child_rootfs_candidates(parent)) >= 2:
            return parent
    for parent in parents:
        if _is_unix_rootfs(parent):
            return parent
    return None


def _nearest_sysroot(binary_path: Path) -> Path | None:
    for parent in [binary_path.parent, *binary_path.parents]:
        if _is_unix_rootfs(parent):
            return parent
        overlay_root = _first_child_rootfs(parent)
        if overlay_root is not None:
            return overlay_root
    return None


def _is_unix_rootfs(path: Path) -> bool:
    try:
        if not path.is_dir():
            return False
        present = {name for name in UNIX_ROOTFS_DIRS if (path / name).exists()}
        if "usr" in present and ((path / "usr" / "lib").exists() or (path / "usr" / "bin").exists()):
            return True
    except OSError:
        return False
    return bool({"bin", "sbin", "lib", "etc"} & present and len(present) >= 2)


def _child_rootfs_candidates(root: Path) -> list[Path]:
    try:
        if not root.is_dir():
            return []
        children = list(root.iterdir())
    except OSError:
        return []
    return sorted(
        [child for child in children if _safe_is_dir(child) and _is_unix_rootfs(child)],
        key=lambda item: item.name,
    )


def _safe_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _first_child_rootfs(root: Path) -> Path | None:
    children = _child_rootfs_candidates(root)
    return children[0] if children else None


def _build_multi_rootfs_overlay_if_needed(firmware_root: Path, overlay: Path) -> Path | None:
    roots = _child_rootfs_candidates(firmware_root)
    if len(roots) < 2:
        return roots[0] if roots else None
    return _build_multi_rootfs_overlay(roots, overlay, firmware_root=firmware_root)


def _build_multi_rootfs_overlay(roots: Sequence[Path], overlay: Path, *, firmware_root: Path | None = None) -> Path:
    if overlay.exists():
        shutil.rmtree(overlay)
    overlay.mkdir(parents=True, exist_ok=True)
    merged: list[dict[str, str]] = []
    for root in roots:
        for entry in sorted(root.iterdir(), key=lambda item: item.name):
            if entry.name not in UNIX_ROOTFS_DIRS and entry.name not in {"dev", "proc", "sys", "tmp"}:
                continue
            _merge_overlay_entry(entry, overlay / entry.name)
        merged.append({"root": str(root), "layout_dirs": sorted(name for name in UNIX_ROOTFS_DIRS if (root / name).exists())})
    (overlay / "usr" / "lib").mkdir(parents=True, exist_ok=True)
    metadata = {
        "firmware_root": str(firmware_root or ""),
        "merged_roots": merged,
    }
    (overlay / "_overlay_manifest.json").write_text(json.dumps(metadata, indent=2, sort_keys=True))
    return overlay


def _merge_overlay_entry(source: Path, target: Path) -> None:
    if source.is_dir() and not source.is_symlink():
        target.mkdir(parents=True, exist_ok=True)
        for child in sorted(source.iterdir(), key=lambda item: item.name):
            _merge_overlay_entry(child, target / child.name)
        return
    _symlink(source, target)


def _build_qemu_sysroot_overlay(rootfs: Path, overlay: Path) -> Path:
    if overlay.exists():
        shutil.rmtree(overlay)
    for entry in rootfs.iterdir():
        if entry.name == "usr":
            continue
        _symlink(entry, overlay / entry.name)
    usr = rootfs / "usr"
    if usr.exists():
        for entry in usr.iterdir():
            if entry.name == "lib":
                continue
            _symlink(entry, overlay / "usr" / entry.name)
    source_lib = rootfs / "usr" / "lib"
    target_lib = overlay / "usr" / "lib"
    target_lib.mkdir(parents=True, exist_ok=True)
    if source_lib.exists():
        for entry in source_lib.iterdir():
            if entry.name == "libnvram.so":
                continue
            _symlink(entry, target_lib / entry.name)
    metadata = {"source_rootfs": str(rootfs)}
    (overlay / "_overlay_manifest.json").write_text(json.dumps(metadata, indent=2, sort_keys=True))
    return overlay


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _needs_qemu_nvram_shim(request: ReplayRequest, target_env: Mapping[str, str]) -> bool:
    if bool(request.setup.get("qemu_nvram") or request.setup.get("qemu_nvram_shim")):
        return True
    return any(str(key).startswith("NVRAM_") for key in target_env)


def _needs_qemu_overflow_oracle(oracle: Mapping[str, Any]) -> bool:
    return bool(
        oracle
        and (
            oracle.get("observe_memory_write")
            or oracle.get("memory_write_observation")
            or oracle.get("target_preload")
        )
    )


def _needs_qemu_syscall_oracle(oracle: Mapping[str, Any]) -> bool:
    kind = str(oracle.get("kind") or oracle.get("type") or "")
    if kind not in {"command_effect", "filesystem_read_escape", "filesystem_write_escape"}:
        return False
    return bool(oracle.get("syscall_observation", True))


def _needs_qemu_register_oracle(oracle: Mapping[str, Any]) -> bool:
    kind = str(oracle.get("kind") or oracle.get("type") or "")
    return bool(
        oracle
        and (
            _needs_qemu_overflow_oracle(oracle)
            or kind in {"bounded_write_overflow", "heap_overflow_bound", "snprintf_heap_overflow", "stack_bounded_write_overflow"}
            or any(str(key).endswith("_register") for key in oracle)
        )
    )


def _prepare_qemu_nvram_shim(request: ReplayRequest, rootfs: Path, candidate_dir: Path) -> dict[str, Any]:
    lib_dir = rootfs / "usr" / "lib"
    if not lib_dir.exists():
        return {"ok": False, "reason": f"qemu_user rootfs lacks usr/lib for nvram shim: {rootfs}"}
    compiler = _resolve_arm_compiler(request)
    if not compiler:
        return {"ok": False, "reason": "ARM compiler not found for qemu_user nvram shim"}
    source_path = candidate_dir / "nvram_env_shim.c"
    so_path = candidate_dir / "libnvram.so"
    source_path.write_text(_QEMU_NVRAM_SHIM_SOURCE)
    command = [
        compiler,
        "-fPIC",
        "-shared",
        "-nostdlib",
        "-Wl,-soname,libnvram.so",
        "-o",
        str(so_path),
        str(source_path),
    ]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=float(request.setup.get("shim_compile_timeout_seconds") or 10.0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "reason": f"failed to compile qemu_user nvram shim: {exc}", "artifacts": [str(source_path)]}
    build_log_path = candidate_dir / "nvram_env_shim_build.json"
    build_log_path.write_text(
        json.dumps(
            {
                "argv": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
            },
            indent=2,
            sort_keys=True,
        )
    )
    if completed.returncode != 0 or not so_path.exists():
        return {
            "ok": False,
            "reason": "qemu_user nvram shim compilation failed",
            "artifacts": [str(source_path), str(build_log_path)],
        }
    target_path = lib_dir / "libnvram.so"
    if target_path.exists() or target_path.is_symlink():
        target_path.unlink()
    shutil.copy2(so_path, target_path)
    return {
        "ok": True,
        "artifacts": [str(source_path), str(build_log_path), str(so_path), str(target_path)],
    }


def _prepare_qemu_filesystem_bindings(
    request: ReplayRequest,
    candidate_dir: Path,
    entries: Sequence[Mapping[str, str]],
) -> dict[str, Any]:
    proot = _resolve_proot_tool(request)
    if not proot:
        return {"ok": False, "reason": "proot not found for qemu_user absolute filesystem setup"}
    absfs_root = candidate_dir / "qemu_absfs"
    if absfs_root.exists():
        shutil.rmtree(absfs_root)
    artifacts: list[str] = []
    bind_roots: dict[str, Path] = {}
    normalized = list(entries)[:16]
    for entry in normalized:
        directory = _clean_target_directory(str(entry.get("directory") or ""))
        name = _clean_target_filename(str(entry.get("name") or ""))
        if not directory or not name:
            continue
        top = directory.strip("/").split("/", 1)[0]
        if not top:
            continue
        host_top = absfs_root / top
        bind_roots[f"/{top}"] = host_top
        host_dir = absfs_root / directory.strip("/")
        host_dir.mkdir(parents=True, exist_ok=True)
        host_file = host_dir / name
        host_file.write_text(str(entry.get("content") or "replay\n"))
        artifacts.append(str(host_file))
    if not bind_roots:
        return {"ok": False, "reason": "filesystem setup did not contain concrete absolute target paths"}
    manifest_path = candidate_dir / "filesystem_bindings.json"
    manifest_path.write_text(
        json.dumps(
            {
                "entries": normalized,
                "binds": {target: str(host) for target, host in sorted(bind_roots.items())},
            },
            indent=2,
            sort_keys=True,
        )
    )
    wrapper = [proot]
    for target, host in sorted(bind_roots.items()):
        wrapper.extend(["-b", f"{host.resolve()}:{target}"])
    return {"ok": True, "wrapper": wrapper, "artifacts": [*artifacts, str(manifest_path)]}


def _resolve_proot_tool(request: ReplayRequest) -> str:
    configured = str(request.setup.get("proot_bin") or os.getenv("PROOT_BIN") or "").strip()
    candidates = [configured] if configured else []
    candidates.extend([str(Path("tools/proot")), "proot"])
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.exists() and os.access(path, os.X_OK):
            return str(path.resolve())
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return ""


def _prepare_qemu_replayfs_shim(
    request: ReplayRequest,
    rootfs: Path,
    candidate_dir: Path,
    entries: Sequence[Mapping[str, str]],
) -> dict[str, Any]:
    lib_dir = rootfs / "usr" / "lib"
    if not lib_dir.exists():
        return {"ok": False, "reason": f"qemu_user rootfs lacks usr/lib for replayfs shim: {rootfs}"}
    compiler = _resolve_arm_compiler(request)
    if not compiler:
        return {"ok": False, "reason": "ARM compiler not found for qemu_user replayfs shim"}
    normalized = list(entries)[:16]
    source_path = candidate_dir / "replayfs_shim.c"
    so_path = candidate_dir / "libreplayfs.so"
    source_path.write_text(_QEMU_REPLAYFS_SHIM_SOURCE)
    command = [
        compiler,
        "-fPIC",
        "-shared",
        "-nostdlib",
        "-Wl,-soname,libreplayfs.so",
        "-o",
        str(so_path),
        str(source_path),
    ]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=float(request.setup.get("shim_compile_timeout_seconds") or 10.0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "reason": f"failed to compile qemu_user replayfs shim: {exc}", "artifacts": [str(source_path)]}
    build_log_path = candidate_dir / "replayfs_shim_build.json"
    build_log_path.write_text(
        json.dumps(
            {
                "argv": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
            },
            indent=2,
            sort_keys=True,
        )
    )
    if completed.returncode != 0 or not so_path.exists():
        return {
            "ok": False,
            "reason": "qemu_user replayfs shim compilation failed",
            "artifacts": [str(source_path), str(build_log_path)],
        }
    target_path = lib_dir / "libreplayfs.so"
    if target_path.exists() or target_path.is_symlink():
        target_path.unlink()
    shutil.copy2(so_path, target_path)
    manifest_path = candidate_dir / "replayfs_manifest.json"
    manifest_path.write_text(json.dumps({"entries": normalized}, indent=2, sort_keys=True))
    env: dict[str, str] = {
        # qemu-user does not chroot target syscalls into -L. A host-visible
        # preload path keeps the shim loadable while preserving target ABI.
        "LD_PRELOAD": str(so_path.resolve()),
        "REPLAYFS_COUNT": str(len(normalized)),
    }
    for index, entry in enumerate(normalized):
        env[f"REPLAYFS_DIR_{index}"] = str(entry.get("directory") or "")
        env[f"REPLAYFS_NAME_{index}"] = str(entry.get("name") or "")
        env[f"REPLAYFS_SIZE_{index}"] = str(entry.get("size") or entry.get("content_length") or "1")
    return {
        "ok": True,
        "env": env,
        "artifacts": [str(source_path), str(build_log_path), str(so_path), str(target_path), str(manifest_path)],
    }


def _qemu_filesystem_entries(request: ReplayRequest) -> list[dict[str, str]]:
    values: list[Any] = []
    for source in (request.setup, request.input):
        for key in ("filesystem", "file_system", "files", "required_files", "file_setup", "paths", "file_inputs"):
            raw = source.get(key) if isinstance(source, Mapping) else None
            if isinstance(raw, list):
                values.extend(raw)
            elif raw:
                values.append(raw)
    validated = request.setup.get("validated_preconditions")
    if isinstance(validated, Mapping):
        raw = validated.get("filesystem")
        if isinstance(raw, list):
            values.extend(raw)
        elif raw:
            values.append(raw)

    entries: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in values:
        entry = _normalize_qemu_filesystem_entry(item)
        if not entry:
            continue
        key = (entry["directory"], entry["name"])
        if key in seen:
            continue
        seen.add(key)
        entries.append(entry)
    return entries


def _normalize_qemu_filesystem_entry(item: Any) -> dict[str, str]:
    if isinstance(item, Mapping):
        raw = {str(key): str(value) for key, value in item.items() if value is not None}
    else:
        raw = {"path": str(item)}
    directory = str(raw.get("directory") or "").strip()
    name = str(raw.get("name") or "").strip()
    pattern = str(raw.get("pattern") or "").strip()
    path = str(raw.get("path") or "").strip()
    mode = str(raw.get("mode") or raw.get("kind") or "").strip().lower()
    min_length = _int(raw.get("min_length") or raw.get("minimum_length"), 0)
    content = str(raw.get("content") or "replay\n")

    if path and not directory:
        if path.endswith("/") or mode == "directory":
            directory = path
        else:
            split = Path(path)
            directory = str(split.parent)
            name = name or split.name
    if pattern and not name:
        name = _filesystem_name_from_pattern(pattern, min_length=min_length)
    if directory and not name and mode != "directory":
        name = _filesystem_name_from_pattern(pattern or "replay-entry", min_length=min_length)
    directory = _clean_target_directory(directory)
    name = _clean_target_filename(name)
    if not directory or not name:
        return {}
    size = str(max(len(content.encode("utf-8", errors="replace")), _int(raw.get("size"), 1)))
    return {"directory": directory, "name": name, "size": size, "content_length": size, "content": content}


def _filesystem_name_from_pattern(pattern: str, *, min_length: int = 0) -> str:
    text = pattern.strip() or "replay-entry"
    target_length = min(max(min_length, 160 if "*" in text else len(text)), 240)
    if "*" in text:
        filler_length = max(target_length - len(text.replace("*", "")), 1)
        text = text.replace("*", "A" * filler_length, 1).replace("*", "")
    if len(text) < target_length:
        text += "A" * (target_length - len(text))
    return text


def _clean_target_directory(path: str) -> str:
    text = path.strip()
    if not text.startswith("/") or "\x00" in text:
        return ""
    parts = [part for part in text.split("/") if part and part != "."]
    if any(part == ".." for part in parts):
        return ""
    result = "/" + "/".join(parts)
    if text.endswith("/"):
        result += "/"
    return result


def _clean_target_filename(name: str) -> str:
    text = name.strip().replace("/", "_")
    text = text.replace("\x00", "")
    if text in {"", ".", ".."}:
        return ""
    return text[:240]


def _merge_ld_preload(existing: str, added: str) -> str:
    parts = [item for item in [added, *existing.split()] if item]
    seen: set[str] = set()
    result: list[str] = []
    for item in parts:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return " ".join(result)


def _prepare_qemu_overflow_oracle(request: ReplayRequest, rootfs: Path, candidate_dir: Path) -> dict[str, Any]:
    oracle = _proof_oracle(request)
    compiler = _resolve_host_c_compiler(request)
    if not compiler:
        return {"ok": False, "reason": "host C compiler not found for qemu_user memory write plugin"}
    include_dir = _resolve_qemu_plugin_include(request)
    if not include_dir:
        return {"ok": False, "reason": "qemu-plugin.h include directory not found"}
    glib_flags = _pkg_config_flags("glib-2.0")
    if not glib_flags:
        return {"ok": False, "reason": "glib-2.0 pkg-config flags not available for qemu plugin build"}
    source_path = candidate_dir / "qemu_memory_write_plugin.c"
    so_path = candidate_dir / "qemu_memory_write_plugin.so"
    source_path.write_text(_QEMU_MEMORY_WRITE_PLUGIN_SOURCE)
    command = [
        compiler,
        "-fPIC",
        "-shared",
        "-O2",
        "-Wall",
        "-I",
        str(include_dir),
        "-o",
        str(so_path),
        str(source_path),
        *glib_flags,
    ]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=float(request.setup.get("qemu_plugin_compile_timeout_seconds") or 10.0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "reason": f"failed to compile qemu_user memory write plugin: {exc}", "artifacts": [str(source_path)]}
    build_log_path = candidate_dir / "qemu_memory_write_plugin_build.json"
    build_log_path.write_text(
        json.dumps(
            {
                "argv": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
            },
            indent=2,
            sort_keys=True,
        )
    )
    if completed.returncode != 0 or not so_path.exists():
        return {
            "ok": False,
            "reason": "qemu_user memory write plugin compilation failed",
            "artifacts": [str(source_path), str(build_log_path)],
        }
    observation_path = candidate_dir / "target_overflow_observation.json"
    plugin_options = ",".join(
        [
            f"file={so_path}",
            f"out={observation_path}",
            f"kind={str(oracle.get('kind') or oracle.get('type') or 'bounded_write_overflow')}",
            f"destination_kind={str(oracle.get('destination_kind') or '')}",
            f"alloc_call={_normalize_address(oracle.get('allocation_call_address'))}",
            f"alloc_ret={_normalize_address(oracle.get('allocation_return_address'))}",
            f"sink_call={_normalize_address(oracle.get('sink_call_address') or oracle.get('call_address'))}",
            f"sink_ret={_normalize_address(oracle.get('sink_return_address'))}",
            f"capacity={_int(oracle.get('capacity_bytes'), 0)}",
            f"bound={_int(oracle.get('write_size_bytes') or oracle.get('write_bound_bytes'), 0)}",
        ]
    )
    return {
        "ok": True,
        "plugin_args": ["-plugin", plugin_options],
        "observation_path": str(observation_path),
        "artifacts": [str(source_path), str(build_log_path), str(so_path)],
    }


def _prepare_qemu_exact_access(
    request: ReplayRequest,
    candidate_dir: Path,
    target_address: str,
) -> dict[str, Any]:
    compiler = _resolve_host_c_compiler(request)
    include_dir = _resolve_qemu_plugin_include(request)
    glib_flags = _pkg_config_flags("glib-2.0")
    if not compiler or not include_dir or not glib_flags:
        return {
            "ok": False,
            "reason": "qemu exact-access plugin toolchain unavailable",
            "artifacts": [],
        }
    source_path = candidate_dir / "qemu_exact_access_plugin.c"
    so_path = candidate_dir / "qemu_exact_access_plugin.so"
    source_path.write_text(_QEMU_EXACT_ACCESS_PLUGIN_SOURCE)
    command = [
        compiler,
        "-fPIC",
        "-shared",
        "-O2",
        "-Wall",
        "-I",
        str(include_dir),
        "-o",
        str(so_path),
        str(source_path),
        *glib_flags,
    ]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=float(request.setup.get("qemu_plugin_compile_timeout_seconds") or 10.0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "reason": str(exc), "artifacts": [str(source_path)]}
    build_path = candidate_dir / "qemu_exact_access_plugin_build.json"
    build_path.write_text(
        json.dumps(
            {
                "argv": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
            },
            indent=2,
            sort_keys=True,
        )
    )
    if completed.returncode != 0 or not so_path.is_file():
        return {
            "ok": False,
            "reason": "qemu exact-access plugin compilation failed",
            "artifacts": [str(source_path), str(build_path)],
        }
    observation = candidate_dir / "qemu_exact_access_observation.json"
    options = ",".join(
        [f"file={so_path}", f"target={target_address}", f"out={observation}"]
    )
    return {
        "ok": True,
        "plugin_args": ["-plugin", options],
        "observation_path": str(observation),
        "artifacts": [str(source_path), str(build_path), str(so_path)],
    }


def _prepare_qemu_exact_instruction_trace(
    request: ReplayRequest,
    candidate_dir: Path,
    target_addresses: Sequence[str],
) -> dict[str, Any]:
    """Compile the append-only multi-address route tracer."""

    compiler = _resolve_host_c_compiler(request)
    include_dir = _resolve_qemu_plugin_include(request)
    glib_flags = _pkg_config_flags("glib-2.0")
    normalized: list[str] = []
    for value in target_addresses:
        address = _normalize_address(value)
        if address and address not in normalized:
            normalized.append(address)
    if not compiler or not include_dir or not glib_flags or not normalized:
        return {
            "ok": False,
            "reason": "qemu exact-instruction plugin toolchain or numeric targets unavailable",
            "artifacts": [],
        }
    source_path = candidate_dir / "qemu_exact_instruction_plugin.c"
    so_path = candidate_dir / "qemu_exact_instruction_plugin.so"
    source_path.write_text(_QEMU_EXACT_INSTRUCTION_PLUGIN_SOURCE)
    command = [
        compiler,
        "-fPIC",
        "-shared",
        "-O2",
        "-Wall",
        "-I",
        str(include_dir),
        "-o",
        str(so_path),
        str(source_path),
        *glib_flags,
    ]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=float(request.setup.get("qemu_plugin_compile_timeout_seconds") or 10.0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "reason": str(exc), "artifacts": [str(source_path)]}
    build_path = candidate_dir / "qemu_exact_instruction_plugin_build.json"
    build_path.write_text(
        json.dumps(
            {
                "argv": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
                "targets": normalized,
            },
            indent=2,
            sort_keys=True,
        )
    )
    if completed.returncode != 0 or not so_path.is_file():
        return {
            "ok": False,
            "reason": "qemu exact-instruction plugin compilation failed",
            "artifacts": [str(source_path), str(build_path)],
        }
    observation = candidate_dir / "qemu_exact_instruction_hits.jsonl"
    options = ",".join(
        [
            f"file={so_path}",
            f"targets={';'.join(normalized)}",
            f"image_base={str(request.setup.get('qemu_image_base') or '0x100000')}",
            f"binary_name={Path(str(request.setup.get('binary_path') or '')).name}",
            f"out={observation}",
        ]
    )
    return {
        "ok": True,
        "plugin_args": ["-plugin", options],
        "observation_path": str(observation),
        "artifacts": [str(source_path), str(build_path), str(so_path), str(observation)],
    }


def _resolve_arm_compiler(request: ReplayRequest) -> str:
    configured = str(
        request.setup.get("arm_compiler")
        or request.setup.get("shim_compiler")
        or os.getenv("REPLAY_ARM_CC")
        or os.getenv("ARM_CC")
        or ""
    ).strip()
    if configured and shutil.which(configured):
        return configured
    for candidate in ("arm-linux-gnueabi-gcc", "arm-linux-gnueabihf-gcc", "arm-none-eabi-gcc"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return ""


def _resolve_host_c_compiler(request: ReplayRequest) -> str:
    configured = str(
        request.setup.get("host_c_compiler")
        or request.setup.get("qemu_plugin_compiler")
        or os.getenv("REPLAY_HOST_CC")
        or os.getenv("CC")
        or ""
    ).strip()
    if configured and shutil.which(configured):
        return configured
    return shutil.which("gcc") or shutil.which("cc") or ""


def _resolve_qemu_plugin_include(request: ReplayRequest) -> Path | None:
    configured = str(request.setup.get("qemu_plugin_include") or os.getenv("QEMU_PLUGIN_INCLUDE") or "").strip()
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured))
    qemu_tool = _resolve_qemu_user_tool(request)
    if qemu_tool:
        candidates.append(Path(qemu_tool).resolve().parents[1] / "include")
    candidates.extend([Path("/usr/include"), Path("/usr/local/include"), Path("/home/linuxbrew/.linuxbrew/include")])
    for candidate in candidates:
        if (candidate / "qemu-plugin.h").exists():
            return candidate
    return None


def _pkg_config_flags(package: str) -> list[str]:
    pkg_config = shutil.which("pkg-config")
    if not pkg_config:
        return []
    try:
        completed = subprocess.run(
            [pkg_config, "--cflags", "--libs", package],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0:
        return []
    return shlex.split(completed.stdout)


def _symlink(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        target.unlink()
    target.symlink_to(source.resolve(), target_is_directory=source.is_dir())


def _qemu_target_env(request: ReplayRequest) -> dict[str, str]:
    return _process_target_env(request)


def _process_target_env(request: ReplayRequest) -> dict[str, str]:
    env: dict[str, str] = {}
    setup_env = request.setup.get("env")
    if isinstance(setup_env, Mapping):
        env.update({str(key): str(value) for key, value in setup_env.items()})
    _apply_qemu_config_env(request, env)
    _apply_qemu_auth_env(request, env)
    route = _first_route(request)
    input_model = str(request.input.get("input_model") or "")
    if route:
        method = str(route.get("method") or "").strip().upper()
        path = str(route.get("path") or "").strip()
        if method:
            env.setdefault("REQUEST_METHOD", method)
        if path:
            env.setdefault("SCRIPT_NAME", path)
            env.setdefault("REQUEST_URI", path)
            env.setdefault("PATH_INFO", path)
            env.setdefault("QUERY_STRING", "")
    if input_model == "http_cgi":
        _apply_http_cgi_env(request, env)
    for key in ("REQUEST_METHOD", "QUERY_STRING", "CONTENT_TYPE", "CONTENT_LENGTH"):
        if key in request.input:
            env[key] = str(request.input[key])
    stdin_text = _qemu_stdin(request)
    if stdin_text:
        env.setdefault("CONTENT_TYPE", "application/x-www-form-urlencoded")
    if stdin_text and "CONTENT_LENGTH" not in env:
        env["CONTENT_LENGTH"] = str(len(stdin_text.encode("utf-8", errors="replace")))
    if isinstance(request.input.get("form"), Mapping):
        for key, value in request.input["form"].items():
            env.setdefault(f"FORM_{str(key)}", str(value))
    return env


def _apply_http_cgi_env(request: ReplayRequest, env: dict[str, str]) -> None:
    stdin_text = _process_stdin_for_input(request.input)
    method = str(request.input.get("method") or request.setup.get("method") or "").strip().upper()
    if not method:
        method = "POST" if stdin_text is not None else "GET"
    env.setdefault("REQUEST_METHOD", method)
    query = _http_query_string(request.input)
    if query:
        env["QUERY_STRING"] = query
    else:
        env.setdefault("QUERY_STRING", "")
    cookies = request.input.get("cookies") or request.input.get("cookie")
    cookie_header = _http_cookie_header(cookies)
    if cookie_header:
        env.setdefault("HTTP_COOKIE", cookie_header)
    if request.input.get("content_type"):
        env.setdefault("CONTENT_TYPE", str(request.input["content_type"]))
    elif stdin_text is not None:
        env.setdefault("CONTENT_TYPE", "application/x-www-form-urlencoded")
    if stdin_text is not None:
        env.setdefault("CONTENT_LENGTH", str(len(stdin_text.encode("utf-8", errors="replace"))))


def _http_query_string(input_payload: Mapping[str, Any]) -> str:
    for key in ("query_string", "query"):
        value = input_payload.get(key)
        if isinstance(value, Mapping):
            return urllib.parse.urlencode({str(k): str(v) for k, v in value.items()})
        if value is not None:
            return str(value)
    params = input_payload.get("params")
    if isinstance(params, Mapping):
        return urllib.parse.urlencode({str(k): str(v) for k, v in params.items()})
    return ""


def _http_cookie_header(value: Any) -> str:
    if isinstance(value, Mapping):
        return "; ".join(f"{key}={val}" for key, val in value.items())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return "; ".join(str(item) for item in value if str(item))
    return str(value or "")


def _bounded_env_for_transcript(env: Mapping[str, str]) -> dict[str, str]:
    keys = [
        "REQUEST_METHOD",
        "SCRIPT_NAME",
        "REQUEST_URI",
        "PATH_INFO",
        "QUERY_STRING",
        "CONTENT_TYPE",
        "CONTENT_LENGTH",
        "REMOTE_ADDR",
        "HTTP_COOKIE",
    ]
    result = {key: str(env[key])[:500] for key in keys if key in env}
    for key, value in sorted(env.items()):
        if key.startswith("FORM_") or key.startswith("COOKIE_"):
            result[key] = str(value)[:500]
    return result


def _qemu_env_requires_inheritance(key: str, value: str) -> bool:
    # qemu-user parses -E values with getsubopt(3), so commas in values are
    # treated as separators. Inherited process env preserves those values.
    return "," in key or "," in value


def _apply_qemu_config_env(request: ReplayRequest, env: dict[str, str]) -> None:
    for name in ("config", "configs", "nvram", "settings"):
        config = request.setup.get(name)
        if not isinstance(config, Mapping):
            continue
        for key, value in config.items():
            storage_key = _storage_key_from_config_key(str(key))
            if not storage_key:
                continue
            env.setdefault(_qemu_nvram_env_name(storage_key), str(value))


def _apply_qemu_auth_env(request: ReplayRequest, env: dict[str, str]) -> None:
    auth = request.setup.get("auth") or request.setup.get("authentication") or request.setup.get("session")
    if isinstance(auth, str):
        auth = {"role": auth}
    if not isinstance(auth, Mapping):
        return
    role = str(auth.get("role") or auth.get("session_role") or "admin").strip() or "admin"
    remote_addr = str(auth.get("remote_addr") or auth.get("logged_in_addr") or "127.0.0.1")
    session_id = str(auth.get("session_id") or auth.get("identity") or "replay-session")
    expires_at = str(auth.get("expires_at") or auth.get("timestamp") or "2147483647")
    token_id = str(auth.get("admin_token_id") or auth.get("token_id") or "replay-token")
    env.setdefault("REMOTE_ADDR", remote_addr)
    env.setdefault("COOKIE_session-identity", session_id)
    env.setdefault("COOKIE_session-role", role)
    env.setdefault("HTTP_COOKIE", f"session-identity={session_id}; session-role={role}")
    env.setdefault(_qemu_nvram_env_name(":session_id"), session_id)
    env.setdefault(_qemu_nvram_env_name(":logged_in_addr"), remote_addr)
    env.setdefault(_qemu_nvram_env_name(":timestamp"), expires_at)
    env.setdefault(_qemu_nvram_env_name(":session_user"), role)
    env.setdefault(_qemu_nvram_env_name(":session_admin_token_id"), token_id)


def _storage_key_from_config_key(key: str) -> str:
    text = key.strip()
    if not text:
        return ""
    for prefix in ("DataStorage:", "datastorage:", "NVRAM:", "nvram:"):
        if text.startswith(prefix):
            return text.split(":", 1)[1].strip()
    if text.startswith("NVRAM_"):
        return text.removeprefix("NVRAM_")
    return text


def _qemu_nvram_env_name(key: str) -> str:
    suffix = "".join(ch if ch.isalnum() else "_" for ch in key)
    return f"NVRAM_{suffix}"


def _first_route(request: ReplayRequest) -> Mapping[str, Any]:
    routes = request.setup.get("routes")
    if isinstance(routes, list):
        for route in routes:
            if isinstance(route, Mapping):
                return route
    route = request.setup.get("route")
    return route if isinstance(route, Mapping) else {}


def _materialize_qemu_input_files(runtime_input: dict[str, Any], candidate_dir: Path) -> list[str]:
    if str(runtime_input.get("input_model") or "") != "file":
        return []
    raw_entries = runtime_input.get("file_inputs")
    if isinstance(raw_entries, Mapping):
        raw_entries = [
            {"name": key, "content_hex": value}
            for key, value in raw_entries.items()
        ]
    elif raw_entries:
        raw_entries = list(raw_entries) if isinstance(raw_entries, Sequence) and not isinstance(raw_entries, (str, bytes, bytearray)) else [raw_entries]
    else:
        return []
    input_dir = candidate_dir / "qemu_input_files"
    input_dir.mkdir(parents=True, exist_ok=True)
    artifacts: list[str] = []
    replacements: dict[str, str] = {}
    for index, entry in enumerate(raw_entries):
        if isinstance(entry, Mapping):
            raw_name = str(entry.get("name") or entry.get("path") or f"concolic_input_{index}")
            content_hex = str(entry.get("content_hex") or "")
            content_text = entry.get("content")
        else:
            raw_name = f"concolic_input_{index}"
            content_hex = ""
            content_text = entry
        name = _clean_target_filename(Path(raw_name).name) or f"concolic_input_{index}"
        path = input_dir / name
        if content_hex:
            try:
                data = bytes.fromhex(content_hex)
            except ValueError:
                data = content_hex.encode("latin-1", errors="replace")
        elif isinstance(content_text, bytes):
            data = content_text
        else:
            data = str(content_text if content_text is not None else "").encode("latin-1", errors="replace")
        path.write_bytes(data)
        artifacts.append(str(path))
        replacements[raw_name] = str(path.resolve())
        replacements[name] = str(path.resolve())
    argv_items = [str(item) for item in runtime_input.get("argv", []) or []]
    if argv_items:
        runtime_input["argv"] = [replacements.get(item, item) for item in argv_items]
    elif artifacts:
        runtime_input["argv"] = [str(Path(artifacts[0]).resolve())]
    return artifacts


def _process_stdin_for_input(input_payload: Mapping[str, Any]) -> str | None:
    if "stdin" in input_payload:
        return str(input_payload.get("stdin") or "")
    if "body" in input_payload:
        return str(input_payload.get("body") or "")
    form = input_payload.get("form")
    if isinstance(form, Mapping):
        return urllib.parse.urlencode({str(key): str(value) for key, value in form.items()})
    return None


def _qemu_stdin(request: ReplayRequest) -> str | None:
    return _process_stdin_for_input(request.input)


def _proof_oracle(request: ReplayRequest) -> Mapping[str, Any]:
    for source in (request.expected_result, request.setup):
        for key in ("proof_oracle", "overflow_oracle", "dynamic_overflow_oracle"):
            oracle = source.get(key)
            if isinstance(oracle, Mapping):
                return oracle
    return {}


def _qemu_proof_trace_filter(oracle: Mapping[str, Any], expected_address: str) -> str:
    addresses = [
        expected_address,
        oracle.get("function_address"),
        oracle.get("allocation_call_address"),
        oracle.get("allocation_return_address"),
        oracle.get("sink_call_address"),
        oracle.get("sink_return_address"),
    ]
    parsed = [_address_int(address) for address in addresses]
    parsed = [address for address in parsed if address is not None]
    if not parsed:
        return ""
    start = max(min(parsed) - 4, 0)
    end = max(parsed) + 4
    return f"0x{start:x}..0x{end:x}"


def _qemu_trace_window(address: str) -> str:
    parsed = _address_int(address)
    if parsed is None:
        return ""
    return f"0x{max(parsed - 4, 0):x}..0x{parsed + 4:x}"


def _evaluate_qemu_proof_oracle(oracle: Mapping[str, Any], trace_path: Path) -> dict[str, Any]:
    kind = str(oracle.get("kind") or oracle.get("type") or "")
    destination_kind = str(oracle.get("destination_kind") or "").lower()
    stack_oracle = kind == "stack_bounded_write_overflow" or destination_kind == "stack"
    if kind not in {"bounded_write_overflow", "heap_overflow_bound", "snprintf_heap_overflow", "stack_bounded_write_overflow"}:
        return {"status": "unsupported_oracle", "kind": kind}

    allocation_call_address = _normalize_address(oracle.get("allocation_call_address"))
    allocation_return_address = _normalize_address(oracle.get("allocation_return_address"))
    sink_call_address = _normalize_address(oracle.get("sink_call_address") or oracle.get("call_address"))
    if not sink_call_address:
        return {"status": "missing_oracle_addresses", "kind": kind}
    if not stack_oracle and (not allocation_call_address or not allocation_return_address):
        return {"status": "missing_oracle_addresses", "kind": kind}

    allocation_call_regs = _qemu_registers_at(trace_path, allocation_call_address)
    allocation_return_regs = _qemu_registers_at(trace_path, allocation_return_address)
    sink_call_regs = _qemu_registers_at(trace_path, sink_call_address)

    capacity_register = _register_name(oracle.get("allocation_size_register") or "r0")
    allocation_pointer_register = _register_name(oracle.get("allocation_pointer_register") or "r0")
    sink_pointer_register = _register_name(oracle.get("sink_pointer_register") or "r0")
    sink_bound_register = _register_name(oracle.get("sink_bound_register") or oracle.get("write_size_register") or "r1")

    capacity_bytes = None if stack_oracle else _register_value(allocation_call_regs, capacity_register)
    if capacity_bytes is None:
        capacity_bytes = _int(oracle.get("capacity_bytes"), -1)
    sink_pointer = _register_value(sink_call_regs, sink_pointer_register)
    allocation_pointer = sink_pointer if stack_oracle else _register_value(allocation_return_regs, allocation_pointer_register)
    write_bound_bytes = _register_value(sink_call_regs, sink_bound_register)
    if write_bound_bytes is None:
        write_bound_bytes = _int(oracle.get("write_size_bytes") or oracle.get("write_bound_bytes"), -1)

    same_object = allocation_pointer is not None and allocation_pointer != 0 and allocation_pointer == sink_pointer
    overflow_bytes = max(0, int(write_bound_bytes) - int(capacity_bytes)) if capacity_bytes is not None and write_bound_bytes is not None else 0
    overflow_condition = bool(same_object and int(capacity_bytes) >= 0 and int(write_bound_bytes) > int(capacity_bytes))
    bug_observed = False if stack_oracle else overflow_condition
    if bug_observed:
        status = "overflow_proven"
    elif stack_oracle and overflow_condition:
        status = "overflow_condition_reached"
    else:
        status = "overflow_not_observed"
    return {
        "status": status,
        "kind": kind,
        "destination_kind": destination_kind,
        "bug_observed": bug_observed,
        "overflow_condition_reached": overflow_condition,
        "capacity_bytes": capacity_bytes,
        "write_bound_bytes": write_bound_bytes,
        "overflow_bytes": overflow_bytes,
        "allocation_pointer": _hex_or_none(allocation_pointer),
        "sink_pointer": _hex_or_none(sink_pointer),
        "same_object": same_object,
        "allocation_call_address": allocation_call_address,
        "allocation_return_address": allocation_return_address,
        "sink_call_address": sink_call_address,
        "allocation_size_register": capacity_register,
        "allocation_pointer_register": allocation_pointer_register,
        "sink_pointer_register": sink_pointer_register,
        "sink_bound_register": sink_bound_register,
        "allocation_call_registers": _format_registers(allocation_call_regs),
        "allocation_return_registers": _format_registers(allocation_return_regs),
        "sink_call_registers": _format_registers(sink_call_regs),
        "trace_path": str(trace_path),
    }


def _merge_qemu_proof_observations(memory_observation: Mapping[str, Any], register_observation: Mapping[str, Any]) -> dict[str, Any]:
    memory = dict(memory_observation)
    registers = dict(register_observation)
    if memory:
        if registers:
            memory["register_observation"] = registers
            memory["same_object"] = bool(memory.get("same_object", registers.get("same_object", False)))
            if "allocation_pointer" not in memory and registers.get("allocation_pointer"):
                memory["allocation_pointer"] = registers["allocation_pointer"]
            if "sink_pointer" not in memory and registers.get("sink_pointer"):
                memory["sink_pointer"] = registers["sink_pointer"]
        memory["bug_observed"] = bool(memory.get("bug_observed", False))
        return memory
    return registers


def _qemu_registers_at(trace_path: Path, address: str) -> dict[str, int]:
    normalized = _normalize_address(address)
    wanted = _address_int(normalized)
    if wanted is None:
        return {}
    try:
        lines = trace_path.read_text(errors="ignore").splitlines()
    except OSError:
        return {}
    for index, line in enumerate(lines):
        line_address = _trace_line_address(line)
        if line_address != wanted:
            continue
        registers: dict[str, int] = {}
        for following in lines[index + 1 : index + 8]:
            for key, value in _parse_qemu_register_line(following).items():
                registers[key] = value
            pc_value = registers.get("r15") or registers.get("pc")
            if pc_value == wanted:
                return registers
        if registers:
            return registers
    return {}


def _trace_line_address(line: str) -> int | None:
    stripped = line.strip().lower()
    if not stripped.startswith("0x") or ":" not in stripped:
        return None
    raw = stripped.split(":", 1)[0]
    return _address_int(raw)


def _parse_qemu_register_line(line: str) -> dict[str, int]:
    registers: dict[str, int] = {}
    for token in line.strip().split():
        if "=" not in token:
            continue
        name, raw_value = token.split("=", 1)
        register = _register_name(name)
        if not register.startswith("r") and register != "pc":
            continue
        try:
            registers[register] = int(raw_value, 16)
        except ValueError:
            continue
    return registers


def _register_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    aliases = {"r00": "r0", "r01": "r1", "r02": "r2", "r03": "r3", "r04": "r4", "r05": "r5", "r06": "r6", "r07": "r7", "r08": "r8", "r09": "r9", "r10": "r10", "r11": "r11", "r12": "r12", "r13": "r13", "sp": "r13", "r14": "r14", "lr": "r14", "r15": "r15", "pc": "pc"}
    return aliases.get(text, text)


def _register_value(registers: Mapping[str, int], register: str) -> int | None:
    if register in registers:
        return registers[register]
    if register == "pc":
        return registers.get("r15")
    if register == "r15":
        return registers.get("pc")
    return None


def _format_registers(registers: Mapping[str, int]) -> dict[str, str]:
    return {key: f"0x{value:x}" for key, value in sorted(registers.items())}


def _hex_or_none(value: int | None) -> str | None:
    return f"0x{value:x}" if value is not None else None


def _trace_contains_address(trace_path: Path, expected_address: str) -> bool:
    if not expected_address or not trace_path.exists():
        return False
    needle = expected_address.lower().removeprefix("0x").lstrip("0") or "0"
    patterns = {
        f"0x{needle}",
        f"0x{needle.zfill(8)}",
        needle,
        needle.zfill(8),
    }
    try:
        for line in trace_path.read_text(errors="ignore").splitlines():
            lowered = line.lower()
            if any(pattern in lowered for pattern in patterns):
                return True
    except OSError:
        return False
    return False


def _witness_input_hex(witness: Any, concrete_replay: Any) -> str:
    if isinstance(witness, Mapping):
        for key in ("stdin_hex", "input_hex"):
            value = witness.get(key)
            if value:
                return str(value)
        argv_hex = witness.get("argv_hex")
        if isinstance(argv_hex, list) and argv_hex:
            return str(argv_hex[0])
        file_inputs = witness.get("file_inputs_hex")
        if isinstance(file_inputs, Mapping) and file_inputs:
            return str(next(iter(file_inputs.values())))
    if isinstance(concrete_replay, Mapping) and concrete_replay.get("input_hex"):
        return str(concrete_replay["input_hex"])
    return ""


def _normalize_address(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, int):
        return f"0x{value:x}" if value >= 0 else ""
    text = str(value).strip().lower()
    if not text:
        return ""
    try:
        return f"0x{int(text, 0):x}"
    except ValueError:
        return ""


def _address_int(value: Any) -> int | None:
    normalized = _normalize_address(value)
    if not normalized:
        return None
    try:
        return int(normalized, 0)
    except ValueError:
        return None


def _resolve_concolic_artifacts(verdict_dir: Path, verdict_path: Path, verdict: Mapping[str, Any]) -> list[str]:
    paths: list[Path] = [verdict_path]
    for name in (
        "request.json",
        "angr_trace.json",
        "pcode_trace.json",
        "pcode_trace_unsupported.json",
        "ghidra_dynamic_proof.json",
        "ghidra_dynamic_proof_unsupported.json",
        "llm_actions.json",
        "replay.json",
    ):
        candidate = verdict_path.with_name(name)
        if candidate.exists():
            paths.append(candidate)
    for raw in verdict.get("artifact_paths", []) or []:
        rel = Path(str(raw))
        candidates = [rel]
        if not rel.is_absolute():
            candidates.extend([verdict_path.parent / rel, verdict_path.parent.parent / rel, verdict_dir / rel])
        for candidate in candidates:
            if candidate.exists():
                paths.append(candidate)
                break
    return _dedupe([str(path) for path in paths])


def _dedupe(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _artifact_refs(paths: Sequence[str], *, kind: str) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for path in paths:
        refs.append({"path": str(path), "kind": kind})
    return refs


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bool_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
