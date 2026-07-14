#!/usr/bin/env python3
"""Live OpenRouter provider for repairing failed replay setup."""

from __future__ import annotations

import argparse
import json
import os
import sys
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
    parser = argparse.ArgumentParser(description="Read a failed replay summary from stdin and emit a repair hypothesis.")
    parser.add_argument("--yes-live", action="store_true", help="Acknowledge that this command will call a live model.")
    parser.add_argument("--model", default=env_first("BINARY_AGENT_REPLAY_REPAIR_MODEL", "OPENROUTER_MODEL", default=DEFAULT_MODEL))
    parser.add_argument("--url", default="", help="Full OpenAI-compatible /chat/completions URL.")
    parser.add_argument(
        "--base-url",
        default=env_first(
            "BINARY_AGENT_REPLAY_REPAIR_BASE_URL",
            "OPENAI_BASE_URL",
            "OPENAI_COMPAT_BASE_URL",
            "OPENROUTER_CHAT_COMPLETIONS_URL",
            default=DEFAULT_URL,
        ),
        help="OpenAI-compatible base URL; /chat/completions is appended when needed.",
    )
    parser.add_argument("--api-key-env", default=env_first("BINARY_AGENT_REPLAY_REPAIR_API_KEY_ENV", default=""))
    parser.add_argument("--api-key-file", type=Path, default=None)
    parser.add_argument("--temperature", type=float, default=float(os.environ.get("BINARY_AGENT_REPLAY_REPAIR_TEMPERATURE", "0")))
    parser.add_argument("--max-tokens", type=int, default=int(os.environ.get("BINARY_AGENT_REPLAY_REPAIR_MAX_TOKENS", "1000")))
    parser.add_argument("--timeout-seconds", type=float, default=float(os.environ.get("BINARY_AGENT_REPLAY_REPAIR_TIMEOUT_S", "90")))
    args = parser.parse_args(argv)
    args.url = chat_completions_url(args.url or args.base_url)
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.yes_live:
        raise SystemExit("Refusing live model calls without --yes-live.")
    failure_summary = _read_json_stdin()
    request = build_chat_request(
        model=args.model,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        system=(
            "You repair concrete replay setup for a binary vulnerability candidate. "
            "Return only one replay or environment hypothesis JSON object. "
            "Do not claim the vulnerability is confirmed."
        ),
        user_payload=_user_payload(failure_summary),
    )
    response, elapsed = post_chat_completion(
        args.url,
        resolve_api_key(args.api_key_file, api_key_env=args.api_key_env),
        request,
        args.timeout_seconds,
    )
    parsed, repair_count = extract_json_object_with_repair_count(message_text(response))
    normalized = _normalize(parsed, failure_summary)
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
        raise SystemExit("stdin JSON must be a failed replay summary object")
    return dict(payload)


def _user_payload(summary: Mapping[str, Any]) -> dict[str, Any]:
    candidate_id = str(summary.get("candidate_id") or "")
    return {
        "task": (
            "Repair the replay setup or inputs so the validator can retry replay. "
            "Use concrete route, service, file, config, env, auth, and input facts; do not leave schema placeholders. "
            "For socket_service replay, include a concrete payload/message/request; host and port alone are only setup."
        ),
        "candidate_id": candidate_id,
        "response_schema": {
            "candidate_id": candidate_id,
            "hypothesis_kind": "replay or environment",
            "proposed_setup": {
                "mode": "qemu_user|native|function_harness",
                "routes": [{"method": "GET|POST", "path": "/concrete"}],
                "services": [{"protocol": "tcp|udp|unix", "host": "127.0.0.1", "port": "concrete port or env"}],
                "env": {},
                "filesystem": [{"path": "/concrete/path", "content": "optional concrete content"}],
                "config": {},
                "auth": {},
                "daemon_args": [],
            },
            "proposed_inputs": {
                "input_model": "argv|stdin|file|http_cgi|http_daemon|socket_service",
                "payload": "",
                "message": "",
                "file_path": "",
                "config_path": "",
                "config_value": "",
                "argv": [],
                "stdin": "",
            },
            "expected_sink": {"function_name": "grounded", "sink": "grounded", "operation_address": "known address"},
            "assumptions": ["short bounded assumptions"],
        },
        "failed_replay": summary,
    }


def _normalize(parsed: Mapping[str, Any], summary: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(parsed)
    result.setdefault("candidate_id", str(summary.get("candidate_id") or ""))
    result.setdefault("hypothesis_kind", "replay")
    result.setdefault("proposed_setup", {})
    result.setdefault("proposed_inputs", {})
    result.setdefault("expected_sink", {})
    result.setdefault("assumptions", [])
    _normalize_expected_sink(result, summary)
    _prune_empty_proposed_inputs(result)
    return result


def _normalize_expected_sink(result: dict[str, Any], summary: Mapping[str, Any]) -> None:
    sink = result.get("expected_sink")
    if not isinstance(sink, dict):
        return
    expected = _nested(summary, "request", "expected_result")
    if not isinstance(expected, Mapping):
        return
    sink_name = str(sink.get("sink") or sink.get("sink_name") or "").strip()
    function_name = str(sink.get("function_name") or sink.get("function") or "").strip()
    candidate_sink = str(expected.get("sink") or "").strip()
    candidate_function = str(expected.get("function_name") or "").strip()
    candidate_address = str(expected.get("sink_address") or expected.get("operation_address") or "").strip()
    if candidate_sink and (not sink_name or _is_placeholder_sink_value(sink_name)):
        sink["sink"] = candidate_sink
    if candidate_function and (
        not function_name
        or _is_placeholder_sink_value(function_name)
        or function_name == candidate_sink
    ):
        sink["function_name"] = candidate_function
    if candidate_address and not str(sink.get("operation_address") or sink.get("sink_address") or "").strip():
        sink["operation_address"] = candidate_address
    for key in ("proof_oracle", "overflow_oracle", "dynamic_overflow_oracle"):
        oracle = sink.get(key) or result.get(key) or expected.get(key)
        if isinstance(oracle, Mapping):
            sink[key] = dict(oracle)


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


def _is_placeholder_sink_value(value: str) -> bool:
    return str(value or "").strip().lower() in {"grounded", "known address", "known_address", "candidate", "sink"}


def _nested(source: Mapping[str, Any], *keys: str) -> Any:
    current: Any = source
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


if __name__ == "__main__":
    raise SystemExit(main())
