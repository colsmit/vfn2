"""Shared helpers for live OpenAI-compatible stdin/stdout provider scripts."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping


DEFAULT_MODEL = "gpt-oss-120b"
DEFAULT_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_APP_TITLE = "vulnfinder2"


def env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return default


def default_key_file() -> Path | None:
    raw = env_first("OPENROUTER_API_KEY_FILE")
    if raw:
        return Path(raw)
    for path in (
        Path("secrets/OPENROUTER_API_KEY.txt"),
        Path("secrets/OPENROUTER_SECRET.txt"),
    ):
        if path.exists():
            return path
    return None


def resolve_api_key(path: Path | None = None, *, api_key_env: str = "") -> str:
    names = [
        name
        for name in (
            api_key_env,
            "OPENAI_API_KEY",
            "OPENROUTER_API_KEY",
            "BINARY_AGENT_HYPOTHESIS_API_KEY",
            "BINARY_AGENT_CONFIRM_API_KEY",
        )
        if name
    ]
    key = env_first(*names)
    if key:
        return key
    key_path = path or default_key_file()
    if key_path is not None:
        try:
            key = key_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            key = ""
    if not key:
        raise SystemExit("Missing OpenRouter API key. Set OPENROUTER_API_KEY or OPENROUTER_API_KEY_FILE.")
    return key


def chat_completions_url(value: str) -> str:
    """Accept either a chat-completions URL or an OpenAI-compatible base URL."""

    raw = str(value or DEFAULT_URL).strip().rstrip("/")
    if raw.endswith("/chat/completions"):
        return raw
    return f"{raw}/chat/completions"


def endpoint_profile(url: str) -> str:
    lowered = str(url or "").lower()
    if "openrouter.ai" in lowered:
        return "openrouter"
    if "deepinfra.com" in lowered:
        return "deepinfra"
    if lowered:
        return "openai_compatible"
    return ""


def post_chat_completion(
    url: str,
    api_key: str,
    payload: Mapping[str, Any],
    timeout_seconds: float,
) -> tuple[Mapping[str, Any], float]:
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    referer = env_first("OPENROUTER_HTTP_REFERER", "OPENROUTER_SITE_URL", "OPENROUTER_APP_URL")
    title = os.environ.get("OPENROUTER_APP_TITLE", DEFAULT_APP_TITLE)
    if endpoint_profile(url) == "openrouter":
        if referer:
            headers["HTTP-Referer"] = referer
        if title:
            headers["X-OpenRouter-Title"] = title
            headers["X-Title"] = title
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise SystemExit(f"OpenAI-compatible provider request failed with HTTP {exc.code}: {detail}") from exc
    return response_payload, time.monotonic() - started


def build_chat_request(
    *,
    model: str,
    temperature: float,
    max_tokens: int,
    system: str,
    user_payload: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user_payload, separators=(",", ":"), sort_keys=True)},
        ],
    }


def message_text(response: Mapping[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message") if isinstance(choices[0], Mapping) else {}
    content = message.get("content") if isinstance(message, Mapping) else ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, Mapping):
                if item.get("type") == "text":
                    parts.append(str(item.get("text") or ""))
                elif isinstance(item.get("content"), str):
                    parts.append(str(item["content"]))
        return "".join(parts)
    return ""


def extract_json_object(text: str) -> Mapping[str, Any]:
    payload, _repair_count = extract_json_object_with_repair_count(text)
    return payload


def extract_json_object_with_repair_count(text: str) -> tuple[Mapping[str, Any], int]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        payload = json.loads(stripped)
        repair_count = 0
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, re.DOTALL)
        if not match:
            raise SystemExit("model output did not contain a JSON object")
        payload = json.loads(match.group(0))
        repair_count = 1
    if not isinstance(payload, Mapping):
        raise SystemExit("model output must be a JSON object")
    return dict(payload), repair_count


def cost_metadata(
    response: Mapping[str, Any],
    wall_time_seconds: float,
    *,
    model: str = "",
    url: str = "",
    json_repair_count: int = 0,
) -> dict[str, Any]:
    usage = response.get("usage") if isinstance(response.get("usage"), Mapping) else {}
    input_tokens = safe_int(usage.get("prompt_tokens") or usage.get("input_tokens"), 0)
    output_tokens = safe_int(usage.get("completion_tokens") or usage.get("output_tokens"), 0)
    total_tokens = safe_int(usage.get("total_tokens"), input_tokens + output_tokens)
    response_model = str(response.get("model") or model or "")
    return {
        "model_calls": 1,
        "model": response_model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "wall_time_seconds": wall_time_seconds,
        "endpoint_profile": endpoint_profile(url),
        "json_repair_count": max(0, safe_int(json_repair_count, 0)),
    }


def attach_cost(payload: Mapping[str, Any], cost: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["cost_metadata"] = {**dict(result.get("cost_metadata") or {}), **dict(cost)}
    for key in ("seeds", "semantic_seeds", "hypotheses", "attempts", "iterations"):
        rows = result.get(key)
        if isinstance(rows, list):
            result[key] = [
                {**dict(item), "cost_metadata": {**dict(item.get("cost_metadata") or {}), **dict(cost)}}
                if isinstance(item, Mapping)
                else item
                for item in rows
            ]
    return result


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
