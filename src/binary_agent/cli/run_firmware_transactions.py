"""Run safe real OpenWrt ubus transactions with exact instruction tracing."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from binary_agent.firmware_transactions import (
    recover_ubus_method_callbacks,
    run_openwrt_ubus_transactions,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("target_binary", type=Path)
    parser.add_argument("--operation", action="append", default=[])
    parser.add_argument("--candidate-states", type=Path)
    parser.add_argument("--pair", action="append", default=[])
    parser.add_argument("--image-base", type=lambda value: int(value, 0))
    parser.add_argument("--qemu-user-bin", default="qemu-x86_64")
    parser.add_argument("--proot-bin", type=Path, default=Path("tools/proot"))
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    target = args.target_binary.expanduser().resolve()
    image_base = args.image_base
    if image_base is None:
        image_base = 0x400000 if target.name == "netifd" else 0x100000
    output = args.output
    if output is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        output = Path(".ai/runs/firmware-transactions") / stamp / target.name
    output = output.expanduser().resolve()
    catalog: dict[str, dict[str, Any]] = {}
    callbacks = recover_ubus_method_callbacks(
        target,
        ("status", "dump", "list", "info"),
        image_base=image_base,
    )
    for method_name, addresses in callbacks.items():
        for address in addresses:
            catalog.setdefault(address.upper(), {"address": address, "roles": []})["roles"].append(
                {"kind": "callback_probe", "method": method_name}
            )
    for address in args.operation:
        normalized = f"0x{int(str(address), 0):X}"
        catalog.setdefault(normalized.upper(), {"address": normalized, "roles": []})["roles"].append(
            {"kind": "explicit_operation"}
        )
    if args.candidate_states:
        payload = json.loads(args.candidate_states.read_text())
        for raw in payload.get("candidate_states", []) or []:
            if not isinstance(raw, Mapping):
                continue
            raw_target = dict(raw.get("target") or {})
            if Path(str(raw_target.get("path") or raw_target.get("binary") or "")).name != target.name:
                continue
            if str(raw.get("status") or "") not in {"proof_ready", "replay_ready"}:
                continue
            operation = dict(raw.get("operation") or {})
            sink = dict(raw.get("sink") or {})
            value = str(operation.get("address") or sink.get("operation_address") or "")
            try:
                normalized = f"0x{int(value, 0):X}"
            except ValueError:
                continue
            catalog.setdefault(normalized.upper(), {"address": normalized, "roles": []})["roles"].append(
                {
                    "kind": "candidate_operation",
                    "candidate_id": str(raw.get("candidate_id") or ""),
                    "vulnerability_type": str(raw.get("vulnerability_type") or ""),
                    "candidate_status": str(raw.get("status") or ""),
                }
            )
    if not catalog:
        raise SystemExit("no exact numeric operations were provided or recovered")
    pairs = []
    for value in args.pair:
        if ":" not in value:
            raise SystemExit(f"invalid object:method pair: {value}")
        pairs.append(tuple(value.rsplit(":", 1)))
    output.mkdir(parents=True, exist_ok=True)
    catalog_path = output / "operation_catalog.json"
    catalog_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_kind": "firmware_exact_operation_catalog",
                "target": target.name,
                "operations": sorted(catalog.values(), key=lambda item: int(item["address"], 16)),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    result = run_openwrt_ubus_transactions(
        args.rootfs,
        target,
        output,
        operation_addresses=[item["address"] for item in catalog.values()],
        image_base=image_base,
        selected_pairs=tuple(pairs),
        qemu_user_bin=args.qemu_user_bin,
        proot_bin=args.proot_bin,
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps({**result.to_dict(), "operation_catalog": str(catalog_path)}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
