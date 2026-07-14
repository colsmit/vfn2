"""Deterministic trial-input witness plans for evidence packs.

Witness plans are deliberately not proof.  They are concrete input candidates
that may help a replay or dynamic proof backend exercise the real boundary.
Only replay artifacts can promote a finding.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import urllib.parse
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence


WITNESS_PLAN_SCHEMA_VERSION = 1
WITNESS_PLAN_ARTIFACT_KIND = "witness_plan"
SUPPORTED_REPLAY_INPUT_MODELS = {
    "argv",
    "stdin",
    "file",
    "env",
    "argv_file_stdin",
    "argv_directory",
    "http_cgi",
    "http_daemon",
    "socket_service",
    "line_file",
    "text_record",
    "config",
    "archive",
    "archive_text_record",
}


@dataclass(frozen=True)
class WitnessCandidate:
    witness_id: str
    kind: str
    input_model: str
    description: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    replay_request_input: Mapping[str, Any] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    proof_status: str = "trial_only"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class WitnessPlan:
    candidate_id: str
    input_model: str
    witnesses: tuple[WitnessCandidate, ...] = ()
    blockers: tuple[str, ...] = ()
    source_summary: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = WITNESS_PLAN_SCHEMA_VERSION

    @property
    def replay_request_inputs(self) -> list[dict[str, Any]]:
        return [dict(item.replay_request_input) for item in self.witnesses if item.replay_request_input]

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_kind": WITNESS_PLAN_ARTIFACT_KIND,
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "input_model": self.input_model,
            "proof_status": "trial_only_until_replay",
            "witnesses": [item.to_dict() for item in self.witnesses],
            "replay_request_inputs": self.replay_request_inputs,
            "blockers": list(self.blockers),
            "source_summary": dict(self.source_summary),
        }

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))
        return path


def build_witness_plan(evidence_pack: Mapping[str, Any]) -> WitnessPlan:
    """Build deterministic concrete trial inputs from a schema-v3 evidence pack."""

    candidate_id = _candidate_id(evidence_pack)
    input_model = _input_model(evidence_pack)
    payload_text = _payload_text(evidence_pack)
    marker = _oracle_marker(evidence_pack)
    blockers: list[str] = []
    witnesses: list[WitnessCandidate] = []

    def add(kind: str, description: str, payload: Mapping[str, Any], replay_input: Mapping[str, Any]) -> None:
        witness_id = _stable_id(candidate_id, kind, json.dumps(replay_input, sort_keys=True, default=str))
        if any(item.witness_id == witness_id for item in witnesses):
            return
        witnesses.append(
            WitnessCandidate(
                witness_id=witness_id,
                kind=kind,
                input_model=str(replay_input.get("input_model") or input_model or kind),
                description=description,
                payload=dict(payload),
                replay_request_input=dict(replay_input),
                evidence_refs=_evidence_refs(evidence_pack)[:8],
            )
        )

    if input_model in {"", "argv"}:
        add(
            "argv_payload",
            "Pass a bounded payload as the first non-program argv item.",
            {"argv": [payload_text], "payload_length": len(payload_text)},
            {"input_model": "argv", "argv": [payload_text], "payload_length": len(payload_text)},
        )
        if _mentions_optarg(evidence_pack):
            add(
                "argv_option_argument",
                "Pass the payload as a short option argument for optarg-style parsers.",
                {"option": "-o", "argument": payload_text},
                {"input_model": "argv", "argv": ["-o", payload_text], "payload_length": len(payload_text)},
            )

    if input_model in {"stdin", "line_file", "text_record"}:
        add(
            "stdin_record",
            "Send one concrete record on standard input.",
            {"stdin": payload_text},
            {"input_model": "stdin", "stdin": payload_text, "payload_length": len(payload_text)},
        )

    if input_model == "config" or _mentions_config_input(evidence_pack):
        file_name = _config_file_name(evidence_pack)
        key = _config_key(evidence_pack)
        content = f"{key}={payload_text}\n"
        add(
            "config_key_value_file",
            "Create a key/value config file containing the payload and pass the config path.",
            {"file_name": file_name, "key": key, "value": payload_text, "content": content},
            {
                "input_model": "file",
                "file_name": file_name,
                "file_content": content,
                "argv": [file_name],
                "config": {key: payload_text},
            },
        )

    if input_model == "env":
        key = _env_key(evidence_pack)
        add(
            "env_var",
            "Set one environment variable to the payload.",
            {"env": {key: payload_text}},
            {"input_model": "env", "env": {key: payload_text}, "payload_length": len(payload_text)},
        )

    if input_model == "argv_file_stdin":
        file_name = _file_name(evidence_pack)
        add(
            "argv_file_stdin",
            "Pass a file path and send the same payload on stdin.",
            {"file_name": file_name, "content": payload_text, "stdin": payload_text},
            {
                "input_model": "argv_file_stdin",
                "argv": [file_name],
                "file_name": file_name,
                "file_content": payload_text,
                "stdin": payload_text,
            },
        )

    if input_model == "argv_directory" or _mentions_directory_iteration(evidence_pack):
        add(
            "directory_file_pair",
            "Create a directory with one attacker-controlled entry name and file content.",
            {"directory": "replay_dir", "entries": [{"name": payload_text[:64], "content": payload_text}]},
            {
                "input_model": "argv_directory",
                "argv": ["replay_dir"],
                "directory_entries": [{"name": payload_text[:64], "content": payload_text}],
            },
        )

    if input_model in {"http_cgi", "http_daemon"}:
        request = _http_request_input(evidence_pack, input_model=input_model, payload_text=payload_text, marker=marker)
        add(
            input_model,
            "Send a concrete HTTP request over the modeled route or CGI boundary.",
            {"request": request},
            request,
        )

    if input_model == "socket_service":
        add(
            "socket_payload",
            "Send a concrete payload over the modeled socket service.",
            {"payload": payload_text},
            {"input_model": "socket_service", "payload": payload_text, "protocol": "line", "payload_length": len(payload_text)},
        )

    if input_model in {"archive", "archive_text_record"} or _mentions_archive_input(evidence_pack):
        archive_name = _archive_file_name(evidence_pack)
        member_name = _archive_member_name(evidence_pack)
        archive_hex = _zip_archive_bytes(member_name, payload_text).hex()
        add(
            "archive_text_record",
            "Create an archive-shaped text record for a replay backend that supports archive materialization.",
            {
                "archive_format": "zip",
                "archive_name": archive_name,
                "member_name": member_name,
                "content": payload_text,
                "file_input_hex": archive_hex,
            },
            {
                "input_model": "file",
                "file_name": archive_name,
                "archive_format": "zip",
                "archive_member": member_name,
                "file_content": payload_text,
                "file_input_hex": archive_hex,
            },
        )
        blockers.append("archive_materialization_requires_backend_support")

    if input_model in {"file", "line_file", "text_record", "config"} or _mentions_file_input(evidence_pack):
        file_name = _file_name(evidence_pack)
        add(
            "line_file",
            "Create a text file containing the payload and pass the file path.",
            {"file_name": file_name, "content": payload_text + "\n"},
            {"input_model": "file", "file_name": file_name, "file_content": payload_text + "\n", "argv": [file_name]},
        )

    if input_model and input_model not in SUPPORTED_REPLAY_INPUT_MODELS:
        blockers.append(f"unsupported_replay_input_model:{input_model}")
    if not witnesses:
        blockers.append("witness_plan_no_supported_input_model")

    return WitnessPlan(
        candidate_id=candidate_id,
        input_model=input_model or "argv",
        witnesses=tuple(witnesses),
        blockers=tuple(_dedupe(blockers)),
        source_summary=_source_summary(evidence_pack, input_model=input_model or "argv", marker=marker),
    )


def write_witness_plans_for_evidence_dir(evidence_dir: Path, output_dir: Path) -> dict[str, Path]:
    """Write one plan per evidence pack plus an aggregate witness_plan.json."""

    from binary_agent.analysis.confirmation import iter_evidence_packs

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    aggregate: list[dict[str, Any]] = []
    for pack_path, evidence_pack in iter_evidence_packs(Path(evidence_dir)):
        plan = build_witness_plan(evidence_pack)
        candidate_id = plan.candidate_id or pack_path.stem
        path = output_dir / _safe_name(candidate_id) / "witness_plan.json"
        plan.write(path)
        paths[candidate_id] = path
        aggregate.append({"candidate_id": candidate_id, "path": str(path), "plan": plan.to_dict()})
    aggregate_path = output_dir / "witness_plan.json"
    aggregate_path.write_text(
        json.dumps(
            {
                "artifact_kind": WITNESS_PLAN_ARTIFACT_KIND,
                "schema_version": WITNESS_PLAN_SCHEMA_VERSION,
                "plans": aggregate,
                "plan_count": len(aggregate),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return paths


def _candidate_id(pack: Mapping[str, Any]) -> str:
    candidate = pack.get("candidate") if isinstance(pack.get("candidate"), Mapping) else {}
    return str(pack.get("candidate_id") or candidate.get("candidate_id") or "")


def _input_model(pack: Mapping[str, Any]) -> str:
    for value in (
        _nested(pack, "process_input", "input_model"),
        _nested(pack, "type_facts", "process_input", "input_model"),
        _nested(pack, "type_facts", "source_to_sink_trace", "input_model"),
        _nested(pack, "entrypoint_derivation", "input_model"),
        _nested(pack, "entrypoint_derivation", "source_to_sink_trace", "input_model"),
        _nested(pack, "candidate", "type_facts", "process_input", "input_model"),
        _nested(pack, "candidate", "type_facts", "source_to_sink_trace", "input_model"),
        _nested(pack, "replay_hypothesis", "input_model"),
    ):
        text = str(value or "").strip()
        if text:
            return text
    strings = " ".join(_nested_strings(pack)).lower()
    if "getenv" in strings:
        return "env"
    if "fgets" in strings or "stdin" in strings:
        return "stdin"
    if "readdir" in strings or "opendir" in strings:
        return "argv_directory"
    if "http_daemon" in strings:
        return "http_daemon"
    if "http_cgi" in strings or "cgi" in strings:
        return "http_cgi"
    if "socket_service" in strings:
        return "socket_service"
    if any(token in strings for token in ("zip", "tar", "archive", "gzip", "7z")):
        return "archive_text_record"
    if "text record" in strings or "line record" in strings or "record parser" in strings:
        return "text_record"
    if "file" in strings or "fopen" in strings:
        return "file"
    return "argv"


def _payload_text(pack: Mapping[str, Any]) -> str:
    capacity = _int_first(
        _nested(pack, "type_facts", "capacity_bytes"),
        _nested(pack, "type_facts", "static_candidate", "capacity_bytes"),
        _nested(pack, "deterministic_candidate", "capacity_bytes"),
        64,
    )
    write_size = _int_first(
        _nested(pack, "type_facts", "write_size_bytes"),
        _nested(pack, "type_facts", "static_candidate", "write_size_bytes"),
        _nested(pack, "deterministic_candidate", "write_size_bytes"),
        0,
    )
    wanted = max(16, min(4096, capacity + 64, write_size if write_size > 0 else capacity + 64))
    marker = _oracle_marker(pack)
    if marker:
        return (marker + "_" + ("A" * wanted))[:wanted]
    vulnerability_type = str(_nested(pack, "candidate", "vulnerability_type") or _nested(pack, "type_facts", "vulnerability_type") or "")
    if vulnerability_type == "format_string":
        return "BINARY_AGENT_FMT_%x_END"
    if vulnerability_type == "path_traversal":
        return "../../etc/passwd"
    if vulnerability_type == "command_injection":
        return "BINARY_AGENT_CMD;id"
    return "A" * wanted


def _oracle_marker(pack: Mapping[str, Any]) -> str:
    for source in (
        pack.get("proof_oracle_facts"),
        _nested(pack, "type_facts", "proof_oracle"),
        _nested(pack, "type_facts", "replay_hints", "proof_oracle"),
        _nested(pack, "replay_hypothesis", "proof_oracle"),
        _nested(pack, "facts_available_to_llm", "proof_oracle_facts"),
    ):
        if isinstance(source, Mapping):
            for key in ("marker", "marker_text", "marker_content", "sink_output_contains"):
                value = str(source.get(key) or "").strip()
                if value:
                    return value
    return ""


def _http_request_input(
    pack: Mapping[str, Any],
    *,
    input_model: str,
    payload_text: str,
    marker: str,
) -> dict[str, Any]:
    hints = _first_mapping(
        _nested(pack, "type_facts", "replay_hints"),
        _nested(pack, "process_input", input_model),
        _nested(pack, "type_facts", "process_input", input_model),
        _nested(pack, "facts_available_to_llm", "process_input", input_model),
    )
    route = _first_mapping(hints.get("route"), _nested(pack, "source", "route"))
    path = str(route.get("path") or route.get("route") or hints.get("path") or "/")
    method = str(route.get("method") or hints.get("method") or "POST").upper()
    body = str(hints.get("body") or hints.get("payload") or payload_text)
    form = hints.get("form")
    if input_model == "http_cgi" and not isinstance(form, Mapping) and "body" not in hints and "payload" not in hints:
        form = {_http_form_key(pack): payload_text}
        body = urllib.parse.urlencode(form)
    request: dict[str, Any] = {
        "input_model": input_model,
        "method": method,
        "path": path,
        "body": body,
        "payload": payload_text,
        "headers": dict(hints.get("headers") or {}) if isinstance(hints.get("headers"), Mapping) else {},
    }
    if isinstance(form, Mapping):
        request["form"] = dict(form)
    query = hints.get("query") or hints.get("params")
    if isinstance(query, Mapping):
        request["query"] = dict(query)
    if marker:
        request["marker"] = marker
    for key in ("host", "port", "port_env", "port_env_key", "port_arg", "port_arg_index", "argv", "argv_template"):
        if hints.get(key) not in (None, ""):
            request[key] = hints[key]
    return request


def _http_form_key(pack: Mapping[str, Any]) -> str:
    for value in (
        _nested(pack, "process_input", "form_key"),
        _nested(pack, "process_input", "parameter"),
        _nested(pack, "type_facts", "process_input", "form_key"),
        _nested(pack, "type_facts", "process_input", "parameter"),
        _nested(pack, "source", "parameter"),
    ):
        text = str(value or "").strip()
        if text:
            return text
    vulnerability_type = str(_nested(pack, "candidate", "vulnerability_type") or _nested(pack, "type_facts", "vulnerability_type") or "")
    if vulnerability_type == "command_injection":
        return "cmd"
    if vulnerability_type == "path_traversal":
        return "file"
    if vulnerability_type == "unsafe_file_write":
        return "path"
    if vulnerability_type == "auth_bypass":
        return "user"
    return "input"


def _env_key(pack: Mapping[str, Any]) -> str:
    for value in (
        _nested(pack, "process_input", "env_key"),
        _nested(pack, "process_input", "env_name"),
        _nested(pack, "type_facts", "process_input", "env_key"),
        _nested(pack, "type_facts", "process_input", "env_name"),
    ):
        text = str(value or "").strip()
        if text:
            return text
    strings = " ".join(_nested_strings(pack))
    match = re.search(r"getenv\s*\(\s*[\"'](?P<key>[A-Za-z_][A-Za-z0-9_]*)", strings)
    return match.group("key") if match else "BINARY_AGENT_INPUT"


def _file_name(pack: Mapping[str, Any]) -> str:
    for value in (
        _nested(pack, "process_input", "file_name"),
        _nested(pack, "process_input", "path"),
        _nested(pack, "type_facts", "process_input", "file_name"),
        _nested(pack, "type_facts", "process_input", "path"),
    ):
        text = str(value or "").strip()
        if text:
            return Path(text).name or "input.txt"
    return "input.txt"


def _config_file_name(pack: Mapping[str, Any]) -> str:
    name = _file_name(pack)
    if name == "input.txt":
        return "input.conf"
    return name


def _config_key(pack: Mapping[str, Any]) -> str:
    for value in (
        _nested(pack, "process_input", "config_key"),
        _nested(pack, "process_input", "key"),
        _nested(pack, "type_facts", "process_input", "config_key"),
        _nested(pack, "type_facts", "process_input", "key"),
        _nested(pack, "source", "config_key"),
    ):
        text = str(value or "").strip()
        if text:
            return text
    strings = " ".join(_nested_strings(pack))
    for pattern in (
        r"config(?:uration)?\s+(?:key|name)\s*[\"':= ]+\s*(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)",
        r"get(?:_)?config\s*\(\s*[\"'](?P<key>[A-Za-z_][A-Za-z0-9_.-]*)",
    ):
        match = re.search(pattern, strings, flags=re.IGNORECASE)
        if match:
            return match.group("key")
    return "BINARY_AGENT_INPUT"


def _archive_file_name(pack: Mapping[str, Any]) -> str:
    name = _file_name(pack)
    path = Path(name)
    if name == "input.txt" or not path.suffix:
        return "witness.zip"
    if path.suffix.lower() != ".zip":
        return path.with_suffix(".zip").name
    return path.name


def _archive_member_name(pack: Mapping[str, Any]) -> str:
    for value in (
        _nested(pack, "process_input", "archive_member"),
        _nested(pack, "process_input", "member_name"),
        _nested(pack, "type_facts", "process_input", "archive_member"),
        _nested(pack, "type_facts", "process_input", "member_name"),
    ):
        text = str(value or "").strip()
        if text:
            return Path(text).name or "payload.txt"
    return "payload.txt"


def _zip_archive_bytes(member_name: str, content: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(member_name, content.encode("utf-8", errors="replace"))
    return buffer.getvalue()


def _source_summary(pack: Mapping[str, Any], *, input_model: str, marker: str) -> dict[str, Any]:
    return {
        "input_model": input_model,
        "marker": marker,
        "source_kind": str(_nested(pack, "source", "kind") or ""),
        "sink": str(_nested(pack, "sink", "name") or _nested(pack, "type_facts", "static_candidate", "sink") or ""),
        "vulnerability_type": str(_nested(pack, "candidate", "vulnerability_type") or _nested(pack, "type_facts", "vulnerability_type") or ""),
    }


def _evidence_refs(pack: Mapping[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ("grounded_refs", "evidence_refs"):
        for item in _sequence(pack.get(key)):
            text = str(item)
            if text:
                refs.append(text)
    for item in _sequence(_nested(pack, "source", "evidence")):
        text = str(item)
        if text:
            refs.append(text)
    return _dedupe(refs)


def _mentions_optarg(pack: Mapping[str, Any]) -> bool:
    return "optarg" in " ".join(_nested_strings(pack)).lower()


def _mentions_file_input(pack: Mapping[str, Any]) -> bool:
    text = " ".join(_nested_strings(pack)).lower()
    return any(token in text for token in ("fopen", "open(", "file_name", "file input", "config"))


def _mentions_config_input(pack: Mapping[str, Any]) -> bool:
    text = " ".join(_nested_strings(pack)).lower()
    return any(token in text for token in ("config", "configuration", ".conf", "key=value", "nvram"))


def _mentions_directory_iteration(pack: Mapping[str, Any]) -> bool:
    text = " ".join(_nested_strings(pack)).lower()
    return any(token in text for token in ("readdir", "opendir", "dirent", "d_name"))


def _mentions_archive_input(pack: Mapping[str, Any]) -> bool:
    text = " ".join(_nested_strings(pack)).lower()
    return any(token in text for token in ("zip", "tar", "archive", "gzip", "7z"))


def _nested(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _first_mapping(*values: Any) -> dict[str, Any]:
    for value in values:
        if isinstance(value, Mapping):
            return dict(value)
    return {}


def _nested_strings(value: Any) -> list[str]:
    strings: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            for child in item.values():
                visit(child)
            return
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for child in item:
                visit(child)
            return
        if item not in (None, ""):
            strings.append(str(item))

    visit(value)
    return strings


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _int_first(*values: Any) -> int:
    for value in values:
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def _dedupe(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)[:120] or "candidate"


def _stable_id(*parts: str) -> str:
    data = "\0".join(str(part) for part in parts)
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()[:16]
