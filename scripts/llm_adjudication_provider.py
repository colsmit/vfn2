#!/usr/bin/env python3
"""Direct OpenAI-compatible provider for bounded adjudication packs.

The script reads exactly one investigation pack from standard input and emits
one untrusted proposal as JSON.  It never reads repository files; the pack is
the complete model context.  Core code validates shape and a separate semantic
verifier decides whether any claim can become evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping

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
except ImportError:  # pragma: no cover - package import path
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


SYSTEM_PROMPT = """You investigate one frozen binary-analysis candidate.
You are not the decision authority. Return only one JSON proposal; deterministic
code will independently verify every statement against the supplied pack.

Never infer safety from a timeout, failed replay, missing harness, lack of crash,
or absence of evidence. Distinguish the exact candidate operation from nearby
defects. For null claims, enumerate every earlier dereference on the proposed
null path and identify the earliest mandatory fault. For spatial claims, name
the object, capacity source, pointer origin, exact STORE width and offset
relation, branch conditions, API contracts, and real entry path. If the pack is
insufficient or syntax is ambiguous, propose "escalate" and request concrete
tool actions for the coding-agent tier.

Required JSON fields:
- schema_version: 1
- artifact_kind: "binary_adjudication_investigation_proposal"
- candidate_id: copied exactly from the pack
- proposed_decision: "bug", "not_bug", or "escalate"
- claim_kind: one of the pack's allowed claim kinds
- exact_operation: address, pcode, and the source expression being adjudicated
- path_steps: ordered objects describing control/data-flow steps
- claims: structured class-specific facts, not prose alone
- root_cause: causal operation, object identity, and normalized defect relation
- nearby_defects: separate defects encountered while checking the exact candidate
- requested_actions: optional bounded commands/experiments for the agent tier
- rationale: concise explanation

Do not include markdown. Do not use an expected label: none is supplied.
"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model",
        default=env_first(
            "BINARY_AGENT_ADJUDICATION_MODEL",
            "OPENROUTER_MODEL",
            default=DEFAULT_MODEL,
        ),
    )
    parser.add_argument(
        "--base-url",
        "--url",
        dest="url",
        default=env_first(
            "BINARY_AGENT_ADJUDICATION_BASE_URL",
            "OPENROUTER_CHAT_COMPLETIONS_URL",
            default=DEFAULT_URL,
        ),
    )
    parser.add_argument(
        "--api-key-env",
        default=env_first("BINARY_AGENT_ADJUDICATION_API_KEY_ENV"),
    )
    parser.add_argument("--api-key-file", type=Path, default=None)
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=float(os.environ.get("BINARY_AGENT_ADJUDICATION_TIMEOUT_SECONDS", "120")),
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=int(os.environ.get("BINARY_AGENT_ADJUDICATION_MAX_TOKENS", "6000")),
    )
    parser.add_argument("--temperature", type=float, default=0.0)
    return parser.parse_args(argv)


def build_request(pack: Mapping[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    return build_chat_request(
        model=str(args.model),
        temperature=float(args.temperature),
        max_tokens=max(256, int(args.max_tokens)),
        system=SYSTEM_PROMPT,
        user_payload={"investigation_pack": pack},
    )


def run(pack: Mapping[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    url = chat_completions_url(str(args.url))
    api_key = resolve_api_key(args.api_key_file, api_key_env=str(args.api_key_env))
    response, duration = post_chat_completion(
        url,
        api_key,
        build_request(pack, args),
        max(1.0, float(args.timeout_seconds)),
    )
    proposal, repair_count = extract_json_object_with_repair_count(message_text(response))
    return attach_cost(
        proposal,
        cost_metadata(
            response,
            duration,
            model=str(args.model),
            url=url,
            json_repair_count=repair_count,
        ),
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        pack = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"invalid investigation pack JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(pack, Mapping):
        print("investigation pack must be a JSON object", file=sys.stderr)
        return 2
    proposal = run(pack, args)
    json.dump(proposal, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

