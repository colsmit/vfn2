"""Validated normalized call-operation specifications."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from binary_agent.taxonomy import ACTIVE_BACKENDS


DEFAULT_OPERATION_SPECS_PATH = Path(__file__).with_name("operation_specs.json")
OPERATION_SPEC_VERSION = 12
OUTPUT_WRITE_GUARANTEES = frozenset({"always", "on_success", "conditional"})


def normalize_operation_name(name: object) -> str:
    value = str(name or "").strip().split("::")[-1].split("@", 1)[0].lower()
    operator_names = {
        "operator.new": "operator_new",
        "operator.new[]": "operator_new_array",
        "operator.delete": "operator_delete",
        "operator.delete[]": "operator_delete_array",
        "operator_new__": "operator_new_array",
        "operator_delete__": "operator_delete_array",
    }
    if value in operator_names:
        return operator_names[value]
    value = re.sub(r"^(?:__builtin_|builtin_)", "", value)
    return value.lstrip("_")


@dataclass(frozen=True)
class OperationSpec:
    name: str
    backend: str
    aliases: tuple[str, ...]
    semantics: str
    effect_kind: str
    argument_roles: tuple[tuple[str, int], ...]
    metadata: tuple[tuple[str, Any], ...] = ()

    def role_index(self, role: str) -> int | None:
        return dict(self.argument_roles).get(role)

    @property
    def output_pointer_args(self) -> tuple[int, ...]:
        raw = dict(self.metadata).get("output_pointer_args", ())
        return tuple(int(item) for item in raw) if isinstance(raw, (list, tuple)) else ()

    @property
    def output_write_guarantee(self) -> str:
        return str(dict(self.metadata).get("output_write_guarantee") or "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "backend": self.backend,
            "aliases": list(self.aliases),
            "semantics": self.semantics,
            "effect_kind": self.effect_kind,
            "argument_roles": dict(self.argument_roles),
            **dict(self.metadata),
        }


@dataclass(frozen=True)
class OperationSpecSet:
    version: int
    operations: tuple[OperationSpec, ...]
    alias_items: tuple[tuple[str, str], ...]
    path: str = ""

    @property
    def aliases(self) -> Mapping[str, str]:
        return dict(self.alias_items)

    def normalize_name(self, name: object) -> str:
        normalized = normalize_operation_name(name)
        return dict(self.alias_items).get(normalized, normalized)

    def get(self, name: object) -> OperationSpec | None:
        canonical = self.normalize_name(name)
        return next((item for item in self.operations if item.name == canonical), None)

    def names(self) -> frozenset[str]:
        return frozenset(item.name for item in self.operations)


def load_operation_specs(path: Path | str | None = None) -> OperationSpecSet:
    spec_path = Path(path) if path is not None else DEFAULT_OPERATION_SPECS_PATH
    payload = json.loads(spec_path.read_text())
    if not isinstance(payload, Mapping):
        raise ValueError(f"Operation spec file {spec_path} must contain an object")
    version = int(payload.get("version", 0) or 0)
    if version != OPERATION_SPEC_VERSION:
        raise ValueError(
            f"Operation spec file {spec_path} has version {version}; expected {OPERATION_SPEC_VERSION}"
        )
    raw_operations = payload.get("operations")
    if not isinstance(raw_operations, Mapping) or not raw_operations:
        raise ValueError(f"Operation spec file {spec_path} must contain a non-empty 'operations' object")

    operations: list[OperationSpec] = []
    aliases: dict[str, str] = {}
    for raw_name, raw in raw_operations.items():
        if not isinstance(raw, Mapping):
            raise ValueError(f"Operation spec for {raw_name!r} must be an object")
        name = normalize_operation_name(raw_name)
        if not name or name != str(raw_name):
            raise ValueError(f"Operation name {raw_name!r} is not canonical")
        backend = str(raw.get("backend") or "")
        if backend not in ACTIVE_BACKENDS:
            raise ValueError(f"Operation {name!r} has unknown backend {backend!r}")
        semantics = str(raw.get("semantics") or "")
        if not semantics:
            raise ValueError(f"Operation {name!r} must declare semantics")
        effect_kind = str(raw.get("effect_kind") or "")
        output_pointer_args: list[int] = []
        raw_output_pointer_args = raw.get("output_pointer_args", ())
        if not isinstance(raw_output_pointer_args, (list, tuple)):
            raise ValueError(f"Operation {name!r} output_pointer_args must be a list")
        for index in raw_output_pointer_args:
            try:
                parsed_index = int(index)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Operation {name!r} has a non-integer output pointer index"
                ) from exc
            if parsed_index < 0:
                raise ValueError(f"Operation {name!r} has a negative output pointer index")
            output_pointer_args.append(parsed_index)
        if len(set(output_pointer_args)) != len(output_pointer_args):
            raise ValueError(f"Operation {name!r} has duplicate output pointer indexes")
        output_write_guarantee = str(raw.get("output_write_guarantee") or "")
        if output_pointer_args and output_write_guarantee not in OUTPUT_WRITE_GUARANTEES:
            raise ValueError(
                f"Operation {name!r} output pointers require one of "
                f"{sorted(OUTPUT_WRITE_GUARANTEES)}"
            )
        if output_write_guarantee and not output_pointer_args:
            raise ValueError(f"Operation {name!r} write guarantee requires output_pointer_args")
        roles = raw.get("argument_roles", {})
        if not isinstance(roles, Mapping):
            raise ValueError(f"Operation {name!r} argument_roles must be an object")
        role_items: list[tuple[str, int]] = []
        for role, index in roles.items():
            if not str(role):
                raise ValueError(f"Operation {name!r} contains an empty argument role")
            try:
                parsed_index = int(index)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Operation {name!r} role {role!r} has a non-integer index") from exc
            if parsed_index < 0:
                raise ValueError(f"Operation {name!r} role {role!r} has a negative index")
            role_items.append((str(role), parsed_index))
        raw_aliases = tuple(normalize_operation_name(item) for item in _sequence(raw.get("aliases")))
        for alias in (name, *raw_aliases):
            previous = aliases.get(alias)
            if previous is not None and previous != name:
                raise ValueError(
                    f"Operation alias {alias!r} resolves to both {previous!r} and {name!r}"
                )
            aliases[alias] = name
        metadata = tuple(
            sorted(
                (str(key), value)
                for key, value in raw.items()
                if key not in {"backend", "aliases", "semantics", "effect_kind", "argument_roles"}
            )
        )
        operations.append(
            OperationSpec(
                name=name,
                backend=backend,
                aliases=tuple(dict.fromkeys(raw_aliases)),
                semantics=semantics,
                effect_kind=effect_kind,
                argument_roles=tuple(sorted(role_items)),
                metadata=metadata,
            )
        )
    return OperationSpecSet(
        version=version,
        operations=tuple(sorted(operations, key=lambda item: item.name)),
        alias_items=tuple(sorted(aliases.items())),
        path=str(spec_path),
    )


def _sequence(value: Any) -> Iterable[Any]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return value
    raise ValueError("Operation aliases must be a string or list")
