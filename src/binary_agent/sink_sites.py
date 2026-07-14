"""Canonical sink-site identity helpers."""

from __future__ import annotations

from typing import Any, Mapping


def sink_site_identity(*sources: Mapping[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for source in sources:
        if isinstance(source, Mapping):
            merged.update(
                {str(key): value for key, value in source.items() if value not in (None, "", [], {})}
            )

    address = _first_address(
        merged.get("sink_address"),
        merged.get("callsite_address"),
        merged.get("operation_address"),
        merged.get("target_address"),
        merged.get("instruction_address"),
    )
    function_address = _normalize_address(merged.get("function_address"))
    if address and function_address and address == function_address and merged.get("sink_name"):
        address = ""

    identity = {
        "schema_version": 1,
        "key": "",
        "address": address,
        "function_address": function_address,
        "kind": str(merged.get("target_kind") or merged.get("kind") or ""),
        "sink_name": str(merged.get("sink_name") or merged.get("sink") or merged.get("callee_name") or ""),
        "callee_name": str(merged.get("callee_name") or ""),
        "callee_address": _normalize_address(merged.get("callee_address")),
        "line_number": _string_or_empty(merged.get("line_number") or merged.get("decompiled_line_number")),
        "source_order_index": _string_or_empty(
            merged.get("source_order_index")
            or merged.get("decompiled_sink_source_order_index")
            or merged.get("decompiled_sink_occurrence_index")
        ),
        "target_buffer": str(merged.get("target_buffer") or ""),
        "offset_expr": str(merged.get("offset_expr") or ""),
    }
    identity["key"] = _sink_site_key(identity)
    return {key: value for key, value in identity.items() if value not in ("", [], {})}


def sink_site_key(*sources: Mapping[str, Any]) -> str:
    return str(sink_site_identity(*sources).get("key") or "")


def _sink_site_key(identity: Mapping[str, Any]) -> str:
    address = str(identity.get("address") or "")
    if address:
        return f"addr:{address}"
    parts = [
        str(identity.get("function_address") or ""),
        str(identity.get("sink_name") or ""),
        str(identity.get("target_buffer") or ""),
        str(identity.get("offset_expr") or ""),
        str(identity.get("line_number") or ""),
        str(identity.get("source_order_index") or ""),
    ]
    key = ":".join(part for part in parts if part)
    return f"site:{key}" if key else ""


def _first_address(*values: Any) -> str:
    for value in values:
        address = _normalize_address(value)
        if address:
            return address
    return ""


def _normalize_address(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, int):
        return f"0x{value:x}" if value >= 0 else ""
    text = str(value).strip().lower()
    if not text:
        return ""
    try:
        parsed = int(text, 16 if text.startswith("0x") else 10)
    except ValueError:
        return ""
    return f"0x{parsed:x}" if parsed >= 0 else ""


def _string_or_empty(value: Any) -> str:
    return "" if value in (None, "") else str(value)
