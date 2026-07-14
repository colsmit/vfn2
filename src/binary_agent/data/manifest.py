"""Utilities for working with Ghidra export manifests."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Mapping, Optional


RAW_MANIFEST_FILENAME = "manifest.jsonl"
NORMALIZED_MANIFEST_FILENAME = "manifest_normalized.json"
SYMBOL_SIDECAR_FILENAME = "source_symbols.json"
LOCAL_ARRAY_DECL_RE = re.compile(
    r"\b(?P<type>(?:(?:const|volatile|restrict|signed|unsigned|struct|union|enum)\s+)*"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*)\s+"
    r"(?P<name>local_[0-9a-fA-F]+)\s*\[\s*(?P<count>\d+)\s*\]",
    re.IGNORECASE,
)
TYPE_SIZE_BYTES = {
    "byte": 1,
    "char": 1,
    "short": 2,
    "int": 4,
    "long": 8,
    "long long": 8,
    "undefined": 1,
    "undefined1": 1,
    "undefined2": 2,
    "undefined4": 4,
    "undefined8": 8,
    "undefined16": 16,
}


@dataclass(frozen=True)
class FunctionRecord:
    """Represents a single decompiled function and associated metadata."""

    address: str
    relative_address: int
    name: str
    relative_path: str
    source_exists: bool
    ordinal: int
    size_addresses: int
    body_size_bytes: int
    is_thunk: bool
    stack_purge: Optional[int]
    call_fixup: Optional[str]
    decompile_completed: bool
    byte_length: int
    line_count: int
    return_type: str
    prototype: str
    parameters: List[Mapping[str, object]]
    emit_c: bool
    c_line_number_offset: int = 0
    source_symbol: str = ""
    demangled_name: str = ""
    source_object: str = ""
    stack_regions: List[Mapping[str, object]] = field(default_factory=list)
    string_refs: List[Mapping[str, object]] = field(default_factory=list)
    pcode_calls: List[Mapping[str, object]] = field(default_factory=list)
    pcode_stores: List[Mapping[str, object]] = field(default_factory=list)
    pcode_loads: List[Mapping[str, object]] = field(default_factory=list)
    pcode_operations: List[Mapping[str, object]] = field(default_factory=list)
    c_line_addresses: List[Mapping[str, object]] = field(default_factory=list)
    ambiguous_callsites: List[Mapping[str, object]] = field(default_factory=list)
    global_refs: List[Mapping[str, object]] = field(default_factory=list)
    static_refs: List[Mapping[str, object]] = field(default_factory=list)
    tls_refs: List[Mapping[str, object]] = field(default_factory=list)
    composite_fields: List[Mapping[str, object]] = field(default_factory=list)
    basic_blocks: List[Mapping[str, object]] = field(default_factory=list)
    wrapper_type: Optional[str] = None
    stub_kind: Optional[str] = None

    def to_dict(self) -> Mapping[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "FunctionRecord":
        return cls(
            address=str(data.get("address")),
            relative_address=int(data.get("relative_address", 0)),
            name=str(data.get("name")),
            relative_path=str(data.get("relative_path", data.get("filename", ""))),
            source_exists=bool(data.get("source_exists", True)),
            ordinal=int(data.get("ordinal", -1)),
            size_addresses=int(data.get("size_addresses", data.get("size", 0))),
            body_size_bytes=int(data.get("body_size_bytes", data.get("body_size", 0))),
            is_thunk=bool(data.get("is_thunk", False)),
            stack_purge=data.get("stack_purge"),
            call_fixup=data.get("call_fixup"),
            decompile_completed=bool(data.get("decompile_completed", False)),
            byte_length=int(data.get("byte_length", 0)),
            line_count=int(data.get("line_count", 0)),
            return_type=str(data.get("return_type", "")),
            prototype=str(data.get("prototype", "")),
            parameters=list(data.get("parameters", [])),
            emit_c=bool(data.get("emit_c", True)),
            c_line_number_offset=int(data.get("c_line_number_offset", 0)),
            source_symbol=str(data.get("source_symbol", "")),
            demangled_name=str(data.get("demangled_name", "")),
            source_object=str(data.get("source_object", "")),
            stack_regions=list(data.get("stack_regions", [])),
            string_refs=list(data.get("string_refs", [])),
            pcode_calls=list(data.get("pcode_calls", [])),
            pcode_stores=list(data.get("pcode_stores", [])),
            pcode_loads=list(data.get("pcode_loads", [])),
            pcode_operations=list(data.get("pcode_operations", [])),
            c_line_addresses=list(data.get("c_line_addresses", [])),
            ambiguous_callsites=list(data.get("ambiguous_callsites", [])),
            global_refs=list(data.get("global_refs", [])),
            static_refs=list(data.get("static_refs", [])),
            tls_refs=list(data.get("tls_refs", [])),
            composite_fields=list(data.get("composite_fields", [])),
            basic_blocks=list(data.get("basic_blocks", [])),
            wrapper_type=data.get("wrapper_type"),
            stub_kind=data.get("stub_kind"),
        )


@dataclass(frozen=True)
class Manifest:
    """Canonical manifest for downstream ingestion."""

    binary: str
    generated_at: str
    export_dir: str
    image_base: int
    ghidra_manifest: str
    callgraph_path: Optional[str]
    functions: List[FunctionRecord]
    language_id: str = ""
    processor: str = ""
    pointer_size_bytes: int = 0
    endianness: str = ""
    executable_format: str = ""
    compiler: str = ""

    def to_dict(self) -> Mapping[str, object]:
        payload = {
            "binary": self.binary,
            "generated_at": self.generated_at,
            "export_dir": self.export_dir,
            "image_base": self.image_base,
            "ghidra_manifest": self.ghidra_manifest,
            "callgraph_path": self.callgraph_path,
            "language_id": self.language_id,
            "processor": self.processor,
            "pointer_size_bytes": self.pointer_size_bytes,
            "endianness": self.endianness,
            "executable_format": self.executable_format,
            "compiler": self.compiler,
            "functions": [record.to_dict() for record in self.functions],
        }
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Manifest":
        functions_data = data.get("functions", []) or []
        functions = [FunctionRecord.from_dict(entry) for entry in functions_data]
        return cls(
            binary=str(data.get("binary")),
            generated_at=str(data.get("generated_at")),
            export_dir=str(data.get("export_dir")),
            image_base=int(data.get("image_base", 0)),
            ghidra_manifest=str(data.get("ghidra_manifest")),
            callgraph_path=data.get("callgraph_path"),
            functions=functions,
            language_id=str(data.get("language_id", "")),
            processor=str(data.get("processor", "")),
            pointer_size_bytes=int(data.get("pointer_size_bytes", 0) or 0),
            endianness=str(data.get("endianness", "")),
            executable_format=str(data.get("executable_format", "")),
            compiler=str(data.get("compiler", "")),
        )


class ManifestError(RuntimeError):
    """Raised when manifest generation fails."""


def _normalize_c_type(raw_type: str) -> str:
    tokens = [
        token.lower()
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", str(raw_type or ""))
    ]
    qualifiers = {"const", "volatile", "restrict", "signed", "unsigned", "struct", "union", "enum"}
    tokens = [token for token in tokens if token not in qualifiers]
    return " ".join(tokens)


def _abi_scoped_type_size(raw_type: str, abi_metadata: Mapping[str, object]) -> tuple[int, str]:
    canonical = _normalize_c_type(raw_type)
    processor = str(abi_metadata.get("processor") or "").lower()
    language_id = str(abi_metadata.get("language_id") or "").lower()
    executable_format = str(abi_metadata.get("executable_format") or "").lower()
    pointer_size = _coerce_int(abi_metadata.get("pointer_size_bytes"), 0)
    is_x86_64 = pointer_size == 8 and ("x86" in processor or "x86" in language_id)
    is_elf = "elf" in executable_format or "executable and linking format" in executable_format
    if canonical == "stat64" and is_x86_64 and is_elf:
        return 144, "x86_64_elf_stat64"
    return 0, ""


def _declared_type_size(raw_type: str, abi_metadata: Mapping[str, object]) -> tuple[int, str]:
    canonical = _normalize_c_type(raw_type)
    primitive_size = TYPE_SIZE_BYTES.get(canonical)
    if primitive_size:
        return primitive_size, "primitive"
    return _abi_scoped_type_size(canonical, abi_metadata)


def _declared_local_arrays(source_text: str, abi_metadata: Mapping[str, object] | None = None) -> dict[str, dict[str, object]]:
    arrays: dict[str, dict[str, object]] = {}
    abi_metadata = abi_metadata or {}
    for match in LOCAL_ARRAY_DECL_RE.finditer(source_text or ""):
        raw_type = _normalize_c_type(match.group("type"))
        element_size, size_source = _declared_type_size(raw_type, abi_metadata)
        if not element_size:
            continue
        count = int(match.group("count"))
        arrays[match.group("name")] = {
            "name": match.group("name"),
            "data_type": raw_type,
            "count": count,
            "element_size_bytes": element_size,
            "size_bytes": count * element_size,
            "size_source": size_source,
        }
    return arrays


def _declared_local_array_sizes(source_text: str, abi_metadata: Mapping[str, object] | None = None) -> dict[str, int]:
    return {
        name: int(info["size_bytes"])
        for name, info in _declared_local_arrays(source_text, abi_metadata).items()
    }


def _coerce_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_address(value: object, default: int = -1) -> int:
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return default


def _demangled_base(name: str) -> str:
    base = str(name or "").split("(", 1)[0].strip()
    if "::" in base:
        base = base.split("::")[-1].strip()
    return base


def _load_symbol_sidecar(export_dir: Path, image_base: int) -> dict[int, dict[str, str]]:
    path = export_dir / SYMBOL_SIDECAR_FILENAME
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    raw_symbols = payload.get("symbols") if isinstance(payload, dict) else None
    entries: list[Mapping[str, object]] = []
    if isinstance(raw_symbols, dict):
        for key, entry in raw_symbols.items():
            item = dict(entry or {})
            item.setdefault("address", key)
            entries.append(item)
    elif isinstance(raw_symbols, list):
        entries = [entry for entry in raw_symbols if isinstance(entry, Mapping)]
    else:
        return {}

    symbol_map: dict[int, dict[str, str]] = {}
    for entry in entries:
        address = _coerce_address(entry.get("address"), -1)
        relative_address = _coerce_address(entry.get("relative_address"), -1)
        if relative_address < 0 and address >= 0:
            relative_address = address - image_base if image_base and address >= image_base else address
        if relative_address < 0:
            continue
        demangled_name = str(entry.get("demangled_name") or "")
        symbol_name = str(entry.get("symbol_name") or entry.get("name") or "")
        source_symbol = str(entry.get("source_symbol") or "") or _demangled_base(demangled_name or symbol_name)
        symbol_map[relative_address] = {
            "source_symbol": source_symbol,
            "demangled_name": demangled_name,
            "source_object": str(entry.get("source_object") or ""),
        }
    return symbol_map


def _repair_stack_regions(
    stack_regions: Iterable[Mapping[str, object]],
    source_text: str,
    abi_metadata: Mapping[str, object] | None = None,
) -> List[Mapping[str, object]]:
    regions = [dict(entry) for entry in (stack_regions or [])]
    if not regions or not source_text.strip():
        return regions

    declared_arrays = _declared_local_arrays(source_text, abi_metadata)
    if not declared_arrays:
        return regions

    repaired: List[Mapping[str, object]] = []
    for region in regions:
        var_names = [str(name) for name in (region.get("var_names") or []) if name]
        data_types = [str(dt).lower() for dt in (region.get("data_types") or []) if dt]
        size_bytes = _coerce_int(region.get("size_bytes"), 0)
        should_repair = (
            len(var_names) == 1
            and size_bytes > 0
            and all(data_type.startswith("undefined") for data_type in (data_types or ["undefined"]))
        )
        if should_repair:
            declared = declared_arrays.get(var_names[0]) or {}
            declared_size = _coerce_int(declared.get("size_bytes"), 0)
            if declared_size > size_bytes:
                start_offset = _coerce_int(region.get("start_offset"), 0)
                region["size_bytes"] = declared_size
                region["end_offset"] = start_offset + declared_size
                data_type = str(declared.get("data_type") or "").strip()
                count = _coerce_int(declared.get("count"), 0)
                element_size = _coerce_int(declared.get("element_size_bytes"), 0)
                if data_type and count:
                    type_display = f"{data_type}[{count}]"
                    region["data_types"] = [type_display]
                    region["type_display"] = type_display
                    region["declared_element_type"] = data_type
                    region["declared_element_count"] = count
                    region["declared_element_size_bytes"] = element_size
                    region["declared_array_size_source"] = str(declared.get("size_source") or "")
                region["capacity_source"] = "declared_local_array"
                region["capacity_basis_kind"] = "declared_local_array"
        repaired.append(region)
    return repaired


def _abi_metadata_from_mapping(data: Mapping[str, object]) -> dict[str, object]:
    return {
        "language_id": str(data.get("language_id", "")),
        "processor": str(data.get("processor", "")),
        "pointer_size_bytes": _coerce_int(data.get("pointer_size_bytes"), 0),
        "endianness": str(data.get("endianness", "")),
        "executable_format": str(data.get("executable_format", "")),
        "compiler": str(data.get("compiler", "")),
    }


def _load_raw_manifest(manifest_path: Path) -> Iterable[dict]:
    if not manifest_path.exists():
        raise ManifestError(f"Ghidra manifest not found: {manifest_path}")

    for line in manifest_path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise ManifestError(f"Malformed JSON in manifest: {exc}") from exc


def _infer_binary_name(export_dir: Path) -> str:
    run_dir = export_dir.parent
    binary_dir = run_dir.parent if run_dir else None
    if binary_dir and binary_dir.name:
        return binary_dir.name
    return export_dir.name


def _build_function_record(
    export_dir: Path,
    entry: Mapping[str, object],
    symbol_map: Mapping[int, Mapping[str, str]],
    abi_metadata: Mapping[str, object],
) -> FunctionRecord:
    relative_path = entry.get("relative_path") or entry.get("filename") or ""
    source_path = export_dir / relative_path if relative_path else None

    text = ""
    byte_length = 0
    line_count = 0
    source_exists = bool(relative_path)
    if source_path and source_path.exists():
        text = source_path.read_text()
        byte_length = len(text.encode("utf-8"))
        line_count = len(text.splitlines())
    elif relative_path:
        source_exists = False

    stack_regions = _repair_stack_regions(entry.get("stack_regions") or [], text, abi_metadata)
    wrapper_type = entry.get("wrapper_type")
    relative_address = int(entry.get("relative_address", 0))
    symbol_info = symbol_map.get(relative_address, {})

    return FunctionRecord(
        address=str(entry.get("address")),
        relative_address=relative_address,
        name=str(entry.get("name")),
        relative_path=relative_path,
        source_exists=source_exists,
        ordinal=int(entry.get("ordinal", -1)),
        size_addresses=int(entry.get("size", 0)),
        body_size_bytes=int(entry.get("body_size_bytes", entry.get("body_size", 0))),
        is_thunk=bool(entry.get("is_thunk", False)),
        stack_purge=entry.get("stack_purge"),
        call_fixup=entry.get("call_fixup"),
        decompile_completed=bool(entry.get("decompile_completed", False)),
        byte_length=byte_length,
        line_count=line_count,
        return_type=str(entry.get("return_type", "")),
        prototype=str(entry.get("prototype", "")),
        parameters=list(entry.get("parameters", [])),
        emit_c=bool(entry.get("emit_c", True)),
        c_line_number_offset=int(entry.get("c_line_number_offset", 0)),
        source_symbol=str(symbol_info.get("source_symbol", "")),
        demangled_name=str(symbol_info.get("demangled_name", "")),
        source_object=str(symbol_info.get("source_object", "")),
        stack_regions=list(stack_regions),
        string_refs=list(entry.get("string_refs", [])),
        pcode_calls=list(entry.get("pcode_calls", [])),
        pcode_stores=list(entry.get("pcode_stores", [])),
        pcode_loads=list(entry.get("pcode_loads", [])),
        pcode_operations=list(entry.get("pcode_operations", [])),
        c_line_addresses=list(entry.get("c_line_addresses", [])),
        ambiguous_callsites=list(entry.get("ambiguous_callsites", [])),
        global_refs=list(entry.get("global_refs", [])),
        static_refs=list(entry.get("static_refs", [])),
        tls_refs=list(entry.get("tls_refs", [])),
        composite_fields=list(entry.get("composite_fields", [])),
        basic_blocks=list(entry.get("basic_blocks", [])),
        wrapper_type=wrapper_type,
        stub_kind=entry.get("stub_kind"),
    )


def normalize_manifest(export_dir: Path) -> Manifest:
    """
    Build a normalized manifest for a Ghidra export directory.

    Parameters
    ----------
    export_dir:
        Path to the `decompiled` folder produced by the headless pipeline.
    """

    export_dir = export_dir.resolve()
    manifest_path = export_dir / RAW_MANIFEST_FILENAME
    callgraph_path = export_dir / "callgraph.json"
    image_base = 0
    abi_metadata: dict[str, object] = {}
    if callgraph_path.exists():
        try:
            callgraph_data = json.loads(callgraph_path.read_text())
            image_base = int(callgraph_data.get("image_base", 0))
            abi_metadata = _abi_metadata_from_mapping(callgraph_data)
        except Exception as exc:
            raise ManifestError(f"Failed to parse call graph: {exc}") from exc

    symbol_map = _load_symbol_sidecar(export_dir, image_base)
    records = [
        _build_function_record(export_dir, entry, symbol_map, abi_metadata)
        for entry in _load_raw_manifest(manifest_path)
    ]
    records.sort(key=lambda rec: (rec.ordinal, rec.address))

    generated_at = datetime.now(timezone.utc).isoformat()
    binary_name = _infer_binary_name(export_dir)

    return Manifest(
        binary=binary_name,
        generated_at=generated_at,
        export_dir=str(export_dir),
        image_base=image_base,
        ghidra_manifest=str(manifest_path),
        callgraph_path=callgraph_path.name if callgraph_path.exists() else None,
        functions=records,
        **abi_metadata,
    )


def write_normalized_manifest(export_dir: Path, filename: str = NORMALIZED_MANIFEST_FILENAME) -> Path:
    manifest = normalize_manifest(export_dir)
    output_path = export_dir / filename
    output_path.write_text(json.dumps(manifest.to_dict(), indent=2))
    return output_path


def read_normalized_manifest(export_dir: Path, filename: str = NORMALIZED_MANIFEST_FILENAME) -> Manifest:
    export_dir = export_dir.resolve()
    path = export_dir / filename
    if not path.exists():
        raise ManifestError(f"Normalized manifest not found: {path}")
    data = json.loads(path.read_text())
    return replace(Manifest.from_dict(data), export_dir=str(export_dir))
