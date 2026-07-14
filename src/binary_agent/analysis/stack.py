"""Stack object helpers used by the deterministic analyzer."""

from __future__ import annotations

import re
from typing import Any, Optional, Sequence

from binary_agent.data.manifest import FunctionRecord


def _format_offset(value: Optional[int]) -> str:
    if value is None:
        return "?"
    try:
        number = int(value)
    except (TypeError, ValueError):
        return "?"
    prefix = "-" if number < 0 else ""
    return f"{prefix}0x{abs(number):x}"


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _make_region_label(index: int, var_names: list[str]) -> str:
    if var_names:
        if len(var_names) == 1:
            return var_names[0]
        return f"{var_names[0]}..{var_names[-1]}"
    return f"stack_region_{index}"


def normalize_stack_regions(record: FunctionRecord) -> list[dict]:
    """Return every stack region with stable labels and range strings."""
    raw_regions = list(getattr(record, "stack_regions", []) or [])
    if not raw_regions:
        return []

    sorted_regions = sorted(
        raw_regions,
        key=lambda entry: (_safe_int(entry.get("start_offset")), _safe_int(entry.get("end_offset"))),
    )
    normalized: list[dict] = []
    for idx, entry in enumerate(sorted_regions, start=1):
        start = _safe_int(entry.get("start_offset"))
        end = _safe_int(entry.get("end_offset"))
        try:
            size = int(entry.get("size_bytes", 0))
        except (TypeError, ValueError):
            size = max(0, abs(end - start))
        var_names = [str(name) for name in entry.get("var_names", []) if name]
        data_types = [str(dt) for dt in entry.get("data_types", []) if dt]
        label = _make_region_label(idx, var_names)
        start_hex = _format_offset(start)
        end_hex = _format_offset(end)
        offset_range = f"[{start_hex}..{end_hex}]"
        normalized_entry = dict(entry)
        normalized_entry.update(
            {
                "index": idx,
                "label": label,
                "start_offset": start,
                "end_offset": end,
                "offset_range": offset_range,
                "size_bytes": size,
                "size_hex": f"0x{size:x}",
                "var_names": var_names,
                "var_display": "/".join(var_names) if var_names else label,
                "data_types": data_types,
                "type_display": "/".join(data_types) if data_types else "(unknown)",
                "annotation": str(entry.get("annotation") or f"{label}: stack{offset_range}, {size} bytes"),
            }
        )
        normalized.append(normalized_entry)
    return normalized


def build_stack_objects(stack_regions: Sequence[dict]) -> list[dict]:
    """Merge contiguous stack regions into larger stack objects when possible."""
    if not stack_regions:
        return []

    sorted_regions = sorted(
        stack_regions,
        key=lambda entry: (_safe_int(entry.get("start_offset")), _safe_int(entry.get("end_offset"))),
    )
    objects: list[dict] = []
    current: Optional[dict] = None

    def _finalize(obj: dict, index: int) -> dict:
        start = _safe_int(obj.get("start_offset"))
        end = _safe_int(obj.get("end_offset"))
        var_names = list(obj.get("var_names") or [])
        data_types = list(obj.get("data_types") or [])
        size = max(0, end - start)
        label = _make_region_label(index, var_names)
        offset_range = f"[{_format_offset(start)}..{_format_offset(end)}]"
        return {
            "index": index,
            "label": label,
            "start_offset": start,
            "end_offset": end,
            "offset_range": offset_range,
            "size_bytes": size,
            "size_hex": f"0x{size:x}",
            "var_names": var_names,
            "var_display": "/".join(var_names) if var_names else label,
            "data_types": data_types,
            "type_display": "/".join(data_types) if data_types else "(unknown)",
            "member_count": int(obj.get("member_count") or 0),
            "members": list(obj.get("members") or []),
            "annotation": f"{label}: stack{offset_range}, {size} bytes",
        }

    for region in sorted_regions:
        start = _safe_int(region.get("start_offset"))
        end = _safe_int(region.get("end_offset"))
        var_names = [str(name) for name in (region.get("var_names") or []) if name]
        data_types = [str(dt) for dt in (region.get("data_types") or []) if dt]
        if current is None or start > _safe_int(current.get("end_offset")):
            if current is not None:
                objects.append(_finalize(current, len(objects) + 1))
            current = {
                "start_offset": start,
                "end_offset": end,
                "var_names": list(var_names),
                "data_types": list(data_types),
                "member_count": 1,
                "members": [dict(region)],
            }
            continue

        current["end_offset"] = max(_safe_int(current.get("end_offset")), end)
        for name in var_names:
            if name not in current["var_names"]:
                current["var_names"].append(name)
        for data_type in data_types:
            if data_type not in current["data_types"]:
                current["data_types"].append(data_type)
        current["member_count"] = int(current.get("member_count") or 0) + 1
        current.setdefault("members", []).append(dict(region))

    if current is not None:
        objects.append(_finalize(current, len(objects) + 1))
    return objects


def annotate_stack_locals(code: str, stack_regions: Sequence[dict]) -> str:
    """Append inline comments with stack offsets next to local variable names."""
    if not code.strip() or not stack_regions:
        return code

    lines = code.splitlines(keepends=True)
    seen: set[str] = set()
    for region in stack_regions:
        annotation = region.get("annotation")
        var_names = region.get("var_names") or []
        if not annotation or not var_names:
            continue
        for var_name in var_names:
            if not var_name or var_name in seen:
                continue
            pattern = re.compile(rf"\b({re.escape(var_name)})\b")
            replaced = False
            for idx, line in enumerate(lines):
                comment_start = line.find("/*")
                code_segment = line if comment_start == -1 else line[:comment_start]
                match = pattern.search(code_segment)
                if match is None:
                    continue
                if re.match(r"\s*/\*", line[match.end(1):]):
                    replaced = True
                    break
                start, end = match.span(1)
                token = match.group(1)
                lines[idx] = f"{line[:start]}{token} /* {annotation} */{line[end:]}"
                seen.add(var_name)
                replaced = True
                break
            if not replaced:
                seen.discard(var_name)
    return "".join(lines)
