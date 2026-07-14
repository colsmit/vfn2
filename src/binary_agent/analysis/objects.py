"""Memory-object modeling helpers for the fact-first analyzer."""

from __future__ import annotations

from typing import Mapping, Sequence

from binary_agent.analysis.facts import CapacityModel, MemObject


OBJECT_KINDS = {
    "stack",
    "heap",
    "global",
    "static_local",
    "tls",
    "parameter",
    "inferred_frame_slice",
    "merged_frame_region",
    "struct_field",
}


def capacity_from_mapping(mapping: Mapping[str, object], *, default_source: str = "") -> CapacityModel:
    fixed = _positive_int(mapping.get("size_bytes") or mapping.get("capacity_bytes"))
    expr = str(mapping.get("capacity_expr") or mapping.get("symbolic_expr") or "")
    source = str(mapping.get("capacity_source") or mapping.get("capacity_basis_kind") or default_source)
    trust = str(mapping.get("capacity_trust") or mapping.get("object_trust") or _trust_for_source(source, fixed, expr))
    return CapacityModel(
        fixed_bytes=fixed,
        symbolic_expr="" if fixed is not None else expr,
        lower_bound=_optional_int(mapping.get("lower_bound")),
        upper_bound=_optional_int(mapping.get("upper_bound")),
        source=source,
        trust=trust,
    )


def mem_object_from_mapping(
    mapping: Mapping[str, object],
    *,
    default_kind: str = "stack",
    namespace: str = "",
) -> MemObject:
    kind = str(mapping.get("destination_kind") or mapping.get("kind") or default_kind)
    if kind not in OBJECT_KINDS:
        kind = default_kind
    label = str(mapping.get("var_display") or mapping.get("label") or mapping.get("name") or "memory_object")
    object_id = str(mapping.get("object_id") or "")
    if not object_id:
        prefix = namespace or kind
        object_id = f"{prefix}:{label}"
    return MemObject(
        object_id=object_id,
        label=label,
        kind=kind,
        capacity=capacity_from_mapping(mapping, default_source=kind),
        object_trust=str(mapping.get("object_trust") or _object_trust(mapping, kind)),
        var_names=[str(item) for item in mapping.get("var_names", []) or [] if item],
        base_object_id=str(mapping.get("base_object_id") or ""),
        field_path=str(mapping.get("field_path") or ""),
        field_offset=_optional_int(mapping.get("field_offset")),
        element_stride=_optional_int(mapping.get("element_stride")),
        field_capacity=_optional_int(mapping.get("field_capacity")),
        metadata={str(key): value for key, value in dict(mapping).items()},
    )


def memory_objects_from_record(record: object) -> list[MemObject]:
    """Build v3 memory objects from optional normalized manifest metadata."""

    objects: list[MemObject] = []
    for region in getattr(record, "stack_regions", []) or []:
        objects.append(mem_object_from_mapping(region, default_kind="stack", namespace=f"{getattr(record, 'address', '')}:stack"))
    for entry in getattr(record, "global_refs", []) or []:
        objects.append(mem_object_from_mapping(entry, default_kind="global", namespace="global"))
    for entry in getattr(record, "static_refs", []) or []:
        objects.append(mem_object_from_mapping(entry, default_kind="static_local", namespace=f"{getattr(record, 'address', '')}:static"))
    for entry in getattr(record, "tls_refs", []) or []:
        objects.append(mem_object_from_mapping(entry, default_kind="tls", namespace="tls"))
    objects.extend(_field_objects(getattr(record, "composite_fields", []) or [], objects))
    return objects


def _field_objects(fields: Sequence[Mapping[str, object]], bases: Sequence[MemObject]) -> list[MemObject]:
    by_label = {obj.label: obj for obj in bases}
    result: list[MemObject] = []
    for field in fields:
        base_label = str(field.get("base") or field.get("base_label") or "")
        base = by_label.get(base_label)
        field_path = str(field.get("field_path") or field.get("name") or "")
        if not field_path:
            continue
        capacity = capacity_from_mapping(
            {
                "size_bytes": field.get("field_capacity") or field.get("size_bytes") or field.get("length"),
                "capacity_source": field.get("source") or "composite_field",
                "capacity_trust": field.get("trust") or "field_metadata",
            },
            default_source="composite_field",
        )
        label = f"{base_label}.{field_path}" if base_label else field_path
        result.append(
            MemObject(
                object_id=str(field.get("object_id") or f"struct_field:{label}"),
                label=label,
                kind="struct_field",
                capacity=capacity,
                object_trust=str(field.get("object_trust") or "field_metadata"),
                var_names=[label],
                base_object_id=base.object_id if base else str(field.get("base_object_id") or ""),
                field_path=field_path,
                field_offset=_optional_int(field.get("field_offset") or field.get("offset")),
                element_stride=_optional_int(field.get("element_stride") or field.get("stride")),
                field_capacity=_optional_int(field.get("field_capacity") or field.get("size_bytes") or field.get("length")),
                metadata=dict(field),
            )
        )
    return result


def _object_trust(mapping: Mapping[str, object], kind: str) -> str:
    basis = str(mapping.get("capacity_basis_kind") or mapping.get("capacity_source") or "").lower()
    if "declared" in basis or "ghidra" in basis:
        return "high"
    if kind in {"global", "static_local", "tls", "struct_field"}:
        return "metadata"
    if kind in {"inferred_frame_slice", "merged_frame_region"}:
        return "low"
    return "medium"


def _trust_for_source(source: str, fixed: int | None, expr: str) -> str:
    lowered = str(source or "").lower()
    if fixed is not None and ("ghidra" in lowered or "declared" in lowered):
        return "high"
    if fixed is not None:
        return "medium"
    if expr:
        return "symbolic"
    return "unknown"


def _positive_int(value: object) -> int | None:
    parsed = _optional_int(value)
    return parsed if parsed is not None and parsed > 0 else None


def _optional_int(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None
