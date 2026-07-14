#!/usr/bin/env python3
"""Live OpenRouter replay-hypothesis provider for one evidence pack."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from llm_provider_common import (
        DEFAULT_MODEL,
        DEFAULT_URL,
        attach_cost,
        build_chat_request,
        chat_completions_url,
        cost_metadata,
        env_first,
        extract_json_object_with_repair_count,
        message_text,
        post_chat_completion,
        resolve_api_key,
    )
except ModuleNotFoundError:  # pragma: no cover - used when imported as scripts.* in tests
    from scripts.llm_provider_common import (
        DEFAULT_MODEL,
        DEFAULT_URL,
        attach_cost,
        build_chat_request,
        chat_completions_url,
        cost_metadata,
        env_first,
        extract_json_object_with_repair_count,
        message_text,
        post_chat_completion,
        resolve_api_key,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read one evidence pack from stdin and emit replay hypothesis JSON.")
    parser.add_argument("--yes-live", action="store_true", help="Acknowledge that this command will call a live model.")
    parser.add_argument("--model", default=env_first("BINARY_AGENT_HYPOTHESIS_MODEL", "OPENROUTER_MODEL", default=DEFAULT_MODEL))
    parser.add_argument("--url", default="", help="Full OpenAI-compatible /chat/completions URL.")
    parser.add_argument(
        "--base-url",
        default=env_first(
            "BINARY_AGENT_HYPOTHESIS_BASE_URL",
            "OPENAI_BASE_URL",
            "OPENAI_COMPAT_BASE_URL",
            "OPENROUTER_CHAT_COMPLETIONS_URL",
            default=DEFAULT_URL,
        ),
        help="OpenAI-compatible base URL; /chat/completions is appended when needed.",
    )
    parser.add_argument("--api-key-env", default=env_first("BINARY_AGENT_HYPOTHESIS_API_KEY_ENV", default=""))
    parser.add_argument("--api-key-file", type=Path, default=None)
    parser.add_argument("--temperature", type=float, default=float(os.environ.get("BINARY_AGENT_HYPOTHESIS_TEMPERATURE", "0")))
    parser.add_argument("--max-tokens", type=int, default=int(os.environ.get("BINARY_AGENT_HYPOTHESIS_MAX_TOKENS", "1400")))
    parser.add_argument("--timeout-seconds", type=float, default=float(os.environ.get("BINARY_AGENT_HYPOTHESIS_TIMEOUT_S", "90")))
    args = parser.parse_args(argv)
    args.url = chat_completions_url(args.url or args.base_url)
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.yes_live:
        raise SystemExit("Refusing live model calls without --yes-live.")
    evidence_pack = _read_json_stdin()
    request = build_chat_request(
        model=args.model,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        system=(
            "You propose concrete replay or environment hypotheses for binary vulnerability candidates. "
            "Return only JSON. You do not decide whether the bug exists; validators and replay decide."
        ),
        user_payload=_user_payload(evidence_pack),
    )
    response, elapsed = post_chat_completion(
        args.url,
        resolve_api_key(args.api_key_file, api_key_env=args.api_key_env),
        request,
        args.timeout_seconds,
    )
    parsed, repair_count = extract_json_object_with_repair_count(message_text(response))
    normalized = _normalize(parsed, evidence_pack)
    print(
        json.dumps(
            attach_cost(
                normalized,
                cost_metadata(response, elapsed, model=args.model, url=args.url, json_repair_count=repair_count),
            ),
            separators=(",", ":"),
        )
    )
    return 0


def _read_json_stdin() -> Mapping[str, Any]:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"stdin did not contain valid JSON: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise SystemExit("stdin JSON must be an evidence-pack object")
    return dict(payload)


def _user_payload(evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    candidate_id = _candidate_id(evidence_pack)
    return {
        "task": (
            "Emit one accepted replay hypothesis if concrete setup is recoverable; otherwise emit an environment hypothesis. "
            "For side-effect vulnerability classes, include expected_sink.proof_oracle.kind with the class-appropriate observable effect. "
            "For socket_service replay, include a concrete payload/message/request; host and port alone are only setup."
        ),
        "candidate_id": candidate_id,
        "response_schema": {
            "candidate_id": candidate_id,
            "hypothesis_kind": "replay or environment",
            "proposed_setup": {
                "mode": "qemu_user|native|function_harness",
                "routes": [{"method": "GET|POST", "path": "/concrete"}],
                "services": [{"protocol": "tcp|udp|unix", "host": "127.0.0.1", "port": "concrete port or env", "path": "optional unix socket"}],
                "env": {},
                "filesystem": [{"path": "/concrete/path", "content": "optional concrete content"}],
                "config": {},
                "auth": {},
                "daemon_args": [],
            },
            "proposed_inputs": {
                "input_model": "argv|stdin|file|http_cgi|http_daemon|socket_service",
                "method": "GET|POST",
                "path": "/concrete",
                "query": {},
                "form": {},
                "body": "",
                "payload": "",
                "message": "",
                "file_path": "",
                "config_path": "",
                "config_value": "",
                "argv": [],
                "stdin": "",
            },
            "expected_sink": {
                "function_name": "grounded",
                "sink": "grounded",
                "operation_address": "known address",
                "proof_oracle": {
                    "kind": "command_effect|filesystem_read_escape|filesystem_write_escape|format_string_effect|bounded_write_overflow",
                    "marker": "concrete marker when applicable",
                },
            },
            "assumptions": ["short bounded assumptions"],
        },
        "evidence_pack": evidence_pack,
    }


def _normalize(parsed: Mapping[str, Any], evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    candidate_id = _candidate_id(evidence_pack)
    result = dict(parsed)
    if "hypotheses" in result:
        rows = result.get("hypotheses")
        if isinstance(rows, list):
            result["hypotheses"] = [_normalize_one(item, candidate_id, evidence_pack) for item in rows if isinstance(item, Mapping)]
            return result
    return _normalize_one(result, candidate_id, evidence_pack)


def _normalize_one(payload: Mapping[str, Any], candidate_id: str, evidence_pack: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result.setdefault("candidate_id", candidate_id)
    result.setdefault("hypothesis_kind", "replay")
    result.setdefault("proposed_setup", {})
    result.setdefault("proposed_inputs", {})
    result.setdefault("expected_sink", {})
    result.setdefault("assumptions", [])
    _normalize_expected_sink(result, evidence_pack)
    _normalize_process_input_model(result, evidence_pack)
    _normalize_http_daemon_inputs(result, evidence_pack)
    _prune_empty_proposed_inputs(result)
    return result


def _normalize_expected_sink(result: dict[str, Any], evidence_pack: Mapping[str, Any]) -> None:
    sink = result.get("expected_sink")
    if not isinstance(sink, dict):
        return
    for key in ("proof_oracle", "overflow_oracle", "dynamic_overflow_oracle"):
        if key not in sink and isinstance(result.get(key), Mapping):
            sink[key] = dict(result[key])
    candidate_function = _candidate_field(evidence_pack, "function_name")
    candidate_sink = _candidate_field(evidence_pack, "sink")
    candidate_address = _candidate_field(evidence_pack, "operation_address")
    sink_name = str(sink.get("sink") or sink.get("sink_name") or "").strip()
    function_name = str(sink.get("function_name") or sink.get("function") or "").strip()
    if candidate_sink and (not sink_name or _is_placeholder_sink_value(sink_name)):
        sink["sink"] = candidate_sink
        sink_name = candidate_sink
    if candidate_function and (
        not function_name
        or _is_placeholder_sink_value(function_name)
        or function_name == sink_name
        or function_name == candidate_sink
    ):
        sink["function_name"] = candidate_function
    if candidate_address and not str(sink.get("operation_address") or sink.get("sink_address") or "").strip():
        sink["operation_address"] = candidate_address


def _is_placeholder_sink_value(value: str) -> bool:
    return str(value or "").strip().lower() in {"grounded", "known address", "known_address", "candidate", "sink"}


def _normalize_http_daemon_inputs(result: dict[str, Any], evidence_pack: Mapping[str, Any]) -> None:
    if _process_input_model(evidence_pack) != "http_daemon":
        return
    setup = result.get("proposed_setup")
    inputs = result.get("proposed_inputs")
    if not isinstance(setup, dict) or not isinstance(inputs, dict):
        return
    route = _first_route(setup)
    if not route:
        return
    method = str(route.get("method") or inputs.get("method") or "GET").upper()
    path = str(inputs.get("path") or route.get("path") or route.get("route") or "")
    path_only, query = _split_http_path_query(path)
    if path_only:
        inputs["path"] = path_only
        route["path"] = path_only
    inputs.setdefault("method", method)
    inputs.setdefault("input_model", "http_daemon")
    if query:
        merged = dict(inputs.get("query") or {}) if isinstance(inputs.get("query"), Mapping) else {}
        for key, value in query.items():
            merged.setdefault(key, value)
        inputs["query"] = merged


def _normalize_process_input_model(result: dict[str, Any], evidence_pack: Mapping[str, Any]) -> None:
    model = _process_input_model(evidence_pack)
    if not model:
        return
    inputs = result.get("proposed_inputs")
    if isinstance(inputs, dict):
        inputs.setdefault("input_model", model)


def _prune_empty_proposed_inputs(result: dict[str, Any]) -> None:
    inputs = result.get("proposed_inputs")
    if not isinstance(inputs, dict):
        return
    for key in (
        "argv",
        "stdin",
        "body",
        "query",
        "params",
        "form",
        "cookies",
        "headers",
        "request",
        "payload",
        "message",
        "data",
        "line",
        "command",
        "script",
        "file_inputs",
        "file_path",
        "filename",
        "config_path",
        "config_value",
    ):
        if key in inputs and _is_empty_input_value(inputs.get(key)):
            inputs.pop(key, None)


def _is_empty_input_value(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, Mapping):
        return not any(str(key).strip() or not _is_empty_input_value(item) for key, item in value.items())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return not any(not _is_empty_input_value(item) for item in value)
    return False


def _first_route(setup: Mapping[str, Any]) -> dict[str, Any]:
    routes = setup.get("routes")
    if isinstance(routes, list):
        for item in routes:
            if isinstance(item, dict):
                return item
    route = setup.get("route")
    if isinstance(route, dict):
        return route
    path = setup.get("path") or setup.get("url") or setup.get("uri")
    if path:
        return {"method": str(setup.get("method") or "GET"), "path": str(path)}
    return {}


def _split_http_path_query(path: str) -> tuple[str, dict[str, str]]:
    if not path:
        return "", {}
    parsed = urllib.parse.urlsplit(path)
    path_only = parsed.path or path.split("?", 1)[0] or "/"
    query = {str(key): str(value) for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)}
    return path_only, query


def _process_input_model(evidence_pack: Mapping[str, Any]) -> str:
    for source in (
        evidence_pack.get("process_input"),
        _nested(evidence_pack, "candidate", "type_facts", "process_input"),
        _nested(evidence_pack, "facts_available_to_llm", "process_input"),
        _nested(evidence_pack, "facts_available_to_llm", "source_to_sink_trace"),
    ):
        if isinstance(source, Mapping):
            model = str(source.get("input_model") or source.get("model") or "")
            if model:
                return model
    return ""


def _candidate_field(evidence_pack: Mapping[str, Any], key: str) -> str:
    if key == "function_name":
        value = _nested(evidence_pack, "location", "function_name")
        if value:
            return str(value)
    if key == "sink":
        value = _nested(evidence_pack, "sink", "name")
        if value:
            return str(value)
    if key == "operation_address":
        for value in (
            _nested(evidence_pack, "sink", "operation_address"),
            _nested(evidence_pack, "location", "address"),
            _nested(evidence_pack, "type_facts", "operation_address"),
        ):
            if value:
                return str(value)
    for source in (
        evidence_pack.get("candidate"),
        evidence_pack.get("deterministic_candidate"),
        evidence_pack,
    ):
        if isinstance(source, Mapping) and source.get(key):
            return str(source.get(key) or "")
    return ""


def _nested(source: Mapping[str, Any], *keys: str) -> Any:
    current: Any = source
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _candidate_id(pack: Mapping[str, Any]) -> str:
    candidate = pack.get("candidate")
    if isinstance(candidate, Mapping) and candidate.get("candidate_id"):
        return str(candidate["candidate_id"])
    legacy = pack.get("deterministic_candidate")
    if isinstance(legacy, Mapping) and legacy.get("candidate_id"):
        return str(legacy["candidate_id"])
    return str(pack.get("candidate_id") or "")


if __name__ == "__main__":
    raise SystemExit(main())
