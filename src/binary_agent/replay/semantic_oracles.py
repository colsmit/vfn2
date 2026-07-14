"""Taxonomy-keyed structural observations for process-visible effects."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from binary_agent.replay.models import ReplayRequest


OBSERVATION_STATUSES = frozenset({"observed", "not_observed", "unsupported"})


@dataclass(frozen=True)
class EffectObservation:
    status: str
    kind: str
    sink_address: str
    concrete_input_fingerprint: str
    details: Mapping[str, Any]
    artifact_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in OBSERVATION_STATUSES:
            raise ValueError(f"invalid effect observation status: {self.status!r}")

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["bug_observed"] = self.status == "observed"
        payload["sink_reached"] = self.status == "observed"
        payload["artifact_refs"] = list(self.artifact_refs)
        return payload


Oracle = Callable[[ReplayRequest, Mapping[str, Any], Path, str, str], EffectObservation]


def supports_semantic_oracle(vulnerability_type: str) -> bool:
    return vulnerability_type in SEMANTIC_ORACLE_REGISTRY


def observe_effect(
    vulnerability_type: str,
    request: ReplayRequest,
    transcript: Mapping[str, Any],
    candidate_dir: Path,
) -> EffectObservation:
    kind = str(_oracle(request).get("kind") or "")
    sink_address = str(
        _oracle(request).get("sink_address")
        or request.expected_result.get("sink_address")
        or ""
    )
    fingerprint = hashlib.sha256(
        json.dumps(request.input, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    oracle = SEMANTIC_ORACLE_REGISTRY.get(vulnerability_type)
    if oracle is None:
        return EffectObservation(
            "unsupported", kind, sink_address, fingerprint,
            {"reason": "semantic_oracle_not_registered"},
        )
    return oracle(request, transcript, candidate_dir, sink_address, fingerprint)


def _argument_oracle(
    request: ReplayRequest,
    transcript: Mapping[str, Any],
    candidate_dir: Path,
    sink: str,
    fingerprint: str,
) -> EffectObservation:
    artifact = _proof_file(request, candidate_dir)
    payload = _read_json(artifact)
    argv = (
        payload.get("argv")
        if isinstance(payload, Mapping) and isinstance(payload.get("argv"), list)
        else payload
        if isinstance(payload, list)
        else []
    )
    attacker = _input_tokens(request)
    hits = [str(item) for item in argv if str(item) in attacker]
    return _result(
        request, sink, fingerprint, bool(hits),
        {"child_argv": [str(item) for item in argv], "attacker_argument_hits": hits},
        artifact, unsupported=not artifact or not isinstance(argv, list),
    )


def _code_oracle(request: ReplayRequest, transcript: Mapping[str, Any], candidate_dir: Path, sink: str, fingerprint: str) -> EffectObservation:
    artifact = _proof_file(request, candidate_dir)
    payload = _read_json(artifact)
    action = str(payload.get("action") or "")
    observed = action in {"write", "create", "set"} and bool(payload.get("value") or payload.get("target"))
    return _result(
        request, sink, fingerprint, observed,
        {"interpreter_action": action, "target": str(payload.get("target") or ""), "value": str(payload.get("value") or "")},
        artifact, unsupported=not artifact or not payload,
    )


def _ssrf_oracle(request: ReplayRequest, transcript: Mapping[str, Any], candidate_dir: Path, sink: str, fingerprint: str) -> EffectObservation:
    listener = transcript.get("outbound_listener")
    if not isinstance(listener, Mapping):
        return _unsupported(request, sink, fingerprint, "outbound_listener_not_configured")
    observed = listener.get("accepted") is True
    return _result(
        request, sink, fingerprint, observed,
        {"listener": dict(listener)}, None,
    )


def _sql_oracle(request: ReplayRequest, transcript: Mapping[str, Any], candidate_dir: Path, sink: str, fingerprint: str) -> EffectObservation:
    oracle = _oracle(request)
    path = _configured_path(oracle.get("database_path") or oracle.get("proof_file"), candidate_dir)
    table = str(oracle.get("created_table") or oracle.get("table") or "")
    if not path or not table or not path.is_file():
        return _unsupported(request, sink, fingerprint, "replay_database_or_table_missing")
    try:
        with sqlite3.connect(str(path)) as database:
            tables = [str(row[0]) for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            row_count = int(database.execute(f'SELECT COUNT(*) FROM "{table.replace(chr(34), chr(34) * 2)}"').fetchone()[0]) if table in tables else 0
    except (sqlite3.Error, OSError) as exc:
        return _unsupported(request, sink, fingerprint, f"unparseable_replay_database:{exc}")
    return _result(
        request, sink, fingerprint, table in tables and row_count > 0,
        {"tables": tables, "attacker_table": table, "attacker_table_rows": row_count}, path,
    )


def _header_oracle(request: ReplayRequest, transcript: Mapping[str, Any], candidate_dir: Path, sink: str, fingerprint: str) -> EffectObservation:
    block = _output_text(transcript)
    headers = _parse_http_headers(block)
    injected_name = str(_oracle(request).get("injected_header") or "X-Injected").lower()
    matches = [item for item in headers if item[0].lower() == injected_name]
    details = {"headers": [{"name": key, "value": value} for key, value in headers], "injected_header": injected_name}
    return _result(request, sink, fingerprint, bool(matches), details, None, unsupported=not headers)


def _log_oracle(request: ReplayRequest, transcript: Mapping[str, Any], candidate_dir: Path, sink: str, fingerprint: str) -> EffectObservation:
    oracle = _oracle(request)
    path = _configured_path(oracle.get("log_path") or oracle.get("proof_file"), candidate_dir)
    forged = str(oracle.get("forged_record") or "FORGED_RECORD")
    if not path or not path.is_file():
        return _unsupported(request, sink, fingerprint, "replay_log_missing")
    try:
        records = path.read_text(errors="replace").splitlines()
    except OSError as exc:
        return _unsupported(request, sink, fingerprint, f"replay_log_unreadable:{exc}")
    forged_rows = [row for row in records if forged in row]
    return _result(
        request, sink, fingerprint, len(records) >= 2 and bool(forged_rows),
        {"record_count": len(records), "forged_record_count": len(forged_rows)}, path,
    )


def _redirect_oracle(request: ReplayRequest, transcript: Mapping[str, Any], candidate_dir: Path, sink: str, fingerprint: str) -> EffectObservation:
    headers = _parse_http_headers(_output_text(transcript))
    locations = [value for name, value in headers if name.lower() == "location"]
    external = str(_oracle(request).get("external_url") or "") or next(
        (token for token in _input_tokens(request) if _external_url(token)), ""
    )
    observed = bool(external and locations and locations[-1] == external and _external_url(external))
    return _result(
        request, sink, fingerprint, observed,
        {"locations": locations, "attacker_external_url": external}, None,
        unsupported=not headers,
    )


def _result(
    request: ReplayRequest,
    sink: str,
    fingerprint: str,
    observed: bool,
    details: Mapping[str, Any],
    artifact: Path | None,
    *,
    unsupported: bool = False,
) -> EffectObservation:
    kind = str(_oracle(request).get("kind") or "")
    status = "unsupported" if unsupported else "observed" if observed else "not_observed"
    return EffectObservation(status, kind, sink, fingerprint, details, (str(artifact),) if artifact else ())


def _unsupported(request: ReplayRequest, sink: str, fingerprint: str, reason: str) -> EffectObservation:
    return EffectObservation("unsupported", str(_oracle(request).get("kind") or ""), sink, fingerprint, {"reason": reason})


def _oracle(request: ReplayRequest) -> Mapping[str, Any]:
    value = request.expected_result.get("proof_oracle")
    return value if isinstance(value, Mapping) else {}


def _proof_file(request: ReplayRequest, candidate_dir: Path) -> Path | None:
    oracle = _oracle(request)
    return _configured_path(
        oracle.get("proof_file") or oracle.get("proof_file_path") or request.setup.get("proof_file"),
        candidate_dir,
    )


def _configured_path(value: Any, candidate_dir: Path) -> Path | None:
    if value in (None, ""):
        return None
    text = str(value).replace("{candidate_dir}", str(candidate_dir))
    path = Path(text)
    return path if path.is_absolute() else candidate_dir / path


def _read_json(path: Path | None) -> Any:
    if path is None or not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(errors="replace") or "{}")
    except (OSError, json.JSONDecodeError):
        return {}


def _input_tokens(request: ReplayRequest) -> list[str]:
    values: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            for item in value.values():
                visit(item)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for item in value:
                visit(item)
        elif value not in (None, ""):
            values.append(str(value))

    visit(request.input)
    return list(dict.fromkeys(values))


def _output_text(transcript: Mapping[str, Any]) -> str:
    return "\n".join(
        str(transcript.get(key) or "")
        for key in ("http_response", "socket_response", "stdout", "stderr")
    )


def _parse_http_headers(value: str) -> list[tuple[str, str]]:
    text = str(value or "").replace("\r\n", "\n").lstrip("\n")
    header_text = text.split("\n\n", 1)[0]
    rows: list[tuple[str, str]] = []
    for line in header_text.splitlines():
        if line.upper().startswith("HTTP/") or ":" not in line:
            continue
        name, raw_value = line.split(":", 1)
        if re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name.strip()):
            rows.append((name.strip(), raw_value.strip()))
    return rows


def _external_url(value: str) -> bool:
    parsed = urllib.parse.urlsplit(str(value or ""))
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)


SEMANTIC_ORACLE_REGISTRY: Mapping[str, Oracle] = {
    "argument_injection": _argument_oracle,
    "code_injection": _code_oracle,
    "server_side_request_forgery": _ssrf_oracle,
    "sql_injection": _sql_oracle,
    "http_header_injection": _header_oracle,
    "log_injection": _log_oracle,
    "open_redirect": _redirect_oracle,
}
