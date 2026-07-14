"""Prepare, admit reviews, and finalize a strict two-bucket candidate ledger."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Mapping

from binary_agent.adjudication import (
    AdjudicationError,
    admit_review,
    finalize_campaign,
    prepare_campaign,
)


DEFAULT_AUDIT = Path(".ai/runs/random-binary-audit/20260714-openwrt-batch-v5/audit_summary.json")
DEFAULT_OUTPUT = Path(".ai/runs/openwrt-four-binary-adjudication-v1")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    prepare = subparsers.add_parser("prepare", help="freeze exact inputs and create review templates")
    prepare.add_argument("campaign_root", type=Path, nargs="?", default=DEFAULT_OUTPUT)
    prepare.add_argument("--audit-summary", type=Path, default=DEFAULT_AUDIT)
    prepare.add_argument(
        "--candidate-state",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="schema-v2 state file; defaults to final paths in the audit summary",
    )
    prepare.add_argument(
        "--binary",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="frozen shipped binary; defaults to the audit rootfs plus target path",
    )
    prepare.add_argument(
        "--export-manifest",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="normalized Ghidra manifest; defaults to the hash-keyed firmware cache",
    )
    prepare.add_argument(
        "--tool",
        action="append",
        default=[],
        type=Path,
        help="additional deterministic tool/schema file to hash into the freeze",
    )
    prepare.add_argument(
        "--reference-mapping",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="pinned SDK/source/reference-build mapping; when used, all targets are required",
    )

    review = subparsers.add_parser("review", help="validate and admit one complete review unit")
    review.add_argument("campaign_root", type=Path)
    review.add_argument("review", type=Path)

    finalize = subparsers.add_parser("finalize", help="require all IDs and emit final artifacts")
    finalize.add_argument("campaign_root", type=Path, nargs="?", default=DEFAULT_OUTPUT)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.mode == "prepare":
            audit = _load_object(args.audit_summary)
            states = _parse_named(args.candidate_state) or _audit_state_paths(audit)
            binaries = _parse_named(args.binary) or _audit_binary_paths(audit)
            exports = _parse_named(args.export_manifest) or _audit_export_paths(audit)
            reference_mappings = _parse_named(args.reference_mapping)
            default_tools = [
                Path(__file__).resolve(),
                Path(__file__).resolve().parents[1] / "adjudication.py",
                Path(__file__).resolve().parents[1] / "analysis" / "entrypoints.py",
                Path(__file__).resolve().parents[1] / "analysis" / "program_index.py",
                Path(__file__).resolve().parents[1] / "data" / "manifest.py",
                Path(__file__).resolve().parents[1] / "data" / "operation_specs.json",
                Path(__file__).resolve().parents[1] / "data" / "proof_specs.json",
                Path(__file__).resolve().parents[3] / "ghidra_scripts" / "export_functions.py",
            ]
            path = prepare_campaign(
                args.campaign_root,
                audit_summary_path=args.audit_summary,
                candidate_state_paths=states,
                binary_paths=binaries,
                export_manifest_paths=exports,
                tool_paths=[*default_tools, *args.tool],
                reference_mapping_paths=reference_mappings,
            )
            print(json.dumps({"mode": "prepare", "frozen_manifest": str(path)}, indent=2, sort_keys=True))
            return 0
        if args.mode == "review":
            path = admit_review(args.campaign_root, args.review)
            print(json.dumps({"mode": "review", "review": str(path)}, indent=2, sort_keys=True))
            return 0
        result = finalize_campaign(args.campaign_root)
        print(json.dumps({"mode": "finalize", **result.to_dict()}, indent=2, sort_keys=True))
        return 0
    except (AdjudicationError, OSError, json.JSONDecodeError) as exc:
        print(f"adjudication failed: {exc}", file=sys.stderr)
        return 2


def _parse_named(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for raw in values:
        name, separator, path = raw.partition("=")
        if not separator or not name.strip() or not path.strip():
            raise AdjudicationError(f"expected NAME=PATH, got {raw!r}")
        if name in result:
            raise AdjudicationError(f"duplicate named path: {name}")
        result[name] = Path(path)
    return result


def _audit_state_paths(audit: Mapping[str, object]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for target in _targets(audit):
        final = target.get("final") if isinstance(target.get("final"), Mapping) else {}
        result[str(target["name"])] = Path(str(final.get("candidate_states_path") or ""))
    return result


def _audit_binary_paths(audit: Mapping[str, object]) -> dict[str, Path]:
    frozen = audit.get("frozen_input") if isinstance(audit.get("frozen_input"), Mapping) else {}
    rootfs = Path(str(frozen.get("rootfs_path") or ""))
    return {
        str(target["name"]): rootfs / str(target.get("binary_path") or "")
        for target in _targets(audit)
    }


def _audit_export_paths(audit: Mapping[str, object]) -> dict[str, Path]:
    cache = Path(".ai/runs/firmware-campaigns/cache/decomp")
    return {
        str(target["name"]): cache
        / str(target["name"])
        / str(target.get("binary_sha256") or "")
        / "decompiled"
        / "manifest_normalized.json"
        for target in _targets(audit)
    }


def _targets(audit: Mapping[str, object]) -> list[Mapping[str, object]]:
    rows = audit.get("targets")
    if not isinstance(rows, list):
        raise AdjudicationError("audit summary has no targets list")
    return [item for item in rows if isinstance(item, Mapping) and item.get("name")]


def _load_object(path: Path) -> dict[str, object]:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict):
        raise AdjudicationError(f"JSON artifact must be an object: {path}")
    return payload


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
