#!/usr/bin/env python3
"""Live OpenRouter provider for semantic seed cluster triage and zoom packs."""

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
    parser = argparse.ArgumentParser(description="Read a semantic seed pack from stdin and emit seed JSON.")
    parser.add_argument("--yes-live", action="store_true", help="Acknowledge that this command will call a live model.")
    parser.add_argument("--model", default=env_first("BINARY_AGENT_SEMANTIC_SEED_MODEL", "OPENROUTER_MODEL", default=DEFAULT_MODEL))
    parser.add_argument("--url", default="", help="Full OpenAI-compatible /chat/completions URL.")
    parser.add_argument(
        "--base-url",
        default=env_first(
            "BINARY_AGENT_SEMANTIC_SEED_BASE_URL",
            "OPENAI_BASE_URL",
            "OPENAI_COMPAT_BASE_URL",
            "OPENROUTER_CHAT_COMPLETIONS_URL",
            default=DEFAULT_URL,
        ),
        help="OpenAI-compatible base URL; /chat/completions is appended when needed.",
    )
    parser.add_argument("--api-key-env", default=env_first("BINARY_AGENT_SEMANTIC_SEED_API_KEY_ENV", default=""))
    parser.add_argument("--api-key-file", type=Path, default=None)
    parser.add_argument("--temperature", type=float, default=float(os.environ.get("BINARY_AGENT_SEMANTIC_SEED_TEMPERATURE", "0")))
    parser.add_argument("--max-tokens", type=int, default=int(os.environ.get("BINARY_AGENT_SEMANTIC_SEED_MAX_TOKENS", "1200")))
    parser.add_argument("--timeout-seconds", type=float, default=float(os.environ.get("BINARY_AGENT_SEMANTIC_SEED_TIMEOUT_S", "90")))
    args = parser.parse_args(argv)
    args.url = chat_completions_url(args.url or args.base_url)
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.yes_live:
        raise SystemExit("Refusing live model calls without --yes-live.")
    pack = _read_json_stdin()
    phase = str(pack.get("phase") or os.environ.get("BINARY_AGENT_SEMANTIC_SEED_PHASE") or "")
    vuln_class = str(pack.get("vuln_class") or os.environ.get("BINARY_AGENT_SEMANTIC_SEED_CLASS") or "")
    request = build_chat_request(
        model=args.model,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        system=_system_prompt(phase),
        user_payload=_user_payload(pack, phase, vuln_class),
    )
    response, elapsed = post_chat_completion(
        args.url,
        resolve_api_key(args.api_key_file, api_key_env=args.api_key_env),
        request,
        args.timeout_seconds,
    )
    parsed, repair_count = extract_json_object_with_repair_count(message_text(response))
    print(
        json.dumps(
            attach_cost(
                _normalize(parsed, pack, phase, vuln_class),
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
        raise SystemExit("stdin JSON must be an object")
    return dict(payload)


def _system_prompt(phase: str) -> str:
    if phase in {"cluster_triage", "string_signal_index"}:
        return (
            "You inspect deterministic string-signal indexes. "
            "Return only JSON. Do not claim proof, exploitability, confirmation, or reportability. "
            "Memory-corruption classes are deterministic-only and must not be proposed here."
        )
    return (
        "You confirm grounded non-memory vulnerability targets from a compact string-led source zoom pack. "
        "Return only JSON. Every seed must keep the pack string_signal_id/string_anchor, name a concrete source expression, exact sink, class oracle, and replay intent. "
        "The replay and proof gates decide whether a bug exists; do not claim confirmation."
    )


def _user_payload(pack: Mapping[str, Any], phase: str, vuln_class: str) -> dict[str, Any]:
    if phase in {"cluster_triage", "string_signal_index"}:
        return {
            "task": "No model triage is needed for string-signal indexes. Return an empty accepted_clusters list.",
            "vuln_class": vuln_class,
            "response_schema": {"accepted_clusters": [{"cluster_id": "existing id", "reason": "short"}]},
            "pack": pack,
        }
    return {
        "task": "Return concrete semantic seeds for this zoom pack.",
        "vuln_class": vuln_class,
        "allowed_oracles": {
            "command_injection": "command_effect",
            "path_traversal": "filesystem_read_escape",
            "unsafe_file_write": "filesystem_write_escape",
        },
        "response_schema": {
            "seeds": [
                {
                    "vulnerability_type": vuln_class,
                    "cluster_id": "existing cluster_id",
                    "string_signal_id": "existing pack cluster.string_signal.signal_id",
                    "string_anchor": "existing pack cluster.string_signal.anchor",
                    "anchors": [{"kind": "function", "function_name": "existing name", "address": "known address"}],
                    "source": {"kind": "route|env|file|config|argv", "expression": "concrete source"},
                    "sink": {"name": "sink", "kind": "sink kind"},
                    "proof_oracle": {"kind": "class-specific oracle"},
                    "proof_obligations": ["Replay observes the class-specific oracle."],
                    "replay_hints": {
                        "mode": "qemu_user",
                        "setup": {},
                        "input": {},
                        "expected_result": {"proof_oracle": {"kind": "class-specific oracle"}},
                    },
                }
            ]
        },
        "pack": pack,
    }


def _normalize(parsed: Mapping[str, Any], pack: Mapping[str, Any], phase: str, vuln_class: str) -> dict[str, Any]:
    result = dict(parsed)
    if phase == "cluster_triage":
        result.setdefault("accepted_clusters", [])
    else:
        rows = result.get("seeds") or result.get("semantic_seeds") or []
        if isinstance(rows, Mapping):
            rows = [rows]
        normalized = []
        cluster_id = ""
        cluster = pack.get("cluster") if isinstance(pack.get("cluster"), Mapping) else {}
        if isinstance(cluster, Mapping):
            cluster_id = str(cluster.get("cluster_id") or "")
        for item in rows if isinstance(rows, list) else []:
            if not isinstance(item, Mapping):
                continue
            seed = dict(item)
            seed.setdefault("vulnerability_type", vuln_class)
            seed.setdefault("cluster_id", cluster_id)
            normalized.append(seed)
        result["seeds"] = normalized
    return result


if __name__ == "__main__":
    raise SystemExit(main())
