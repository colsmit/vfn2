"""Hash-keyed observations describing how one compiled binary can execute.

An execution envelope is capability evidence, not vulnerability evidence.  It
may prevent an impossible proof route from launching, but it can never satisfy
the exact-operation or effect-observation report gates.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping


EXECUTION_ENVELOPE_SCHEMA_VERSION = 1
ROUTE_NAMES = (
    "static_exact",
    "native_trace",
    "native_ledger",
    "native_oracle",
    "ghidra_call_trace",
    "ghidra_pcode",
    "angr_concolic",
    "qemu_user",
)


@dataclass(frozen=True)
class RouteCapability:
    route: str
    status: str
    reason: str
    setup_key: str
    setup_seconds: float
    marginal_seconds: float

    def __post_init__(self) -> None:
        if self.status not in {"available", "setup_required", "unsupported"}:
            raise ValueError(f"invalid route capability status: {self.status!r}")

    @property
    def viable(self) -> bool:
        return self.status in {"available", "setup_required"}


@dataclass(frozen=True)
class ExecutionEnvelope:
    binary_path: str
    binary_sha256: str
    binary_size: int
    elf_machine: str
    elf_class: str
    endianness: str
    interpreter: str
    needed_libraries: tuple[str, ...]
    rootfs_path: str
    rootfs_identity: str
    rootfs_interpreter_path: str
    resolved_libraries: tuple[str, ...]
    missing_libraries: tuple[str, ...]
    host_machine: str
    host_native_architecture: bool
    host_interpreter_available: bool
    qemu_user_bin: str
    tool_signature: str
    cache_key: str
    capabilities: tuple[RouteCapability, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": EXECUTION_ENVELOPE_SCHEMA_VERSION,
            "artifact_kind": "binary_execution_envelope",
            **{
                key: value
                for key, value in asdict(self).items()
                if key != "capabilities"
            },
            "needed_libraries": list(self.needed_libraries),
            "resolved_libraries": list(self.resolved_libraries),
            "missing_libraries": list(self.missing_libraries),
            "capabilities": [asdict(item) for item in self.capabilities],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ExecutionEnvelope":
        if int(payload.get("schema_version") or 0) != EXECUTION_ENVELOPE_SCHEMA_VERSION:
            raise ValueError("unsupported execution envelope schema")
        return cls(
            binary_path=str(payload.get("binary_path") or ""),
            binary_sha256=str(payload.get("binary_sha256") or ""),
            binary_size=int(payload.get("binary_size") or 0),
            elf_machine=str(payload.get("elf_machine") or ""),
            elf_class=str(payload.get("elf_class") or ""),
            endianness=str(payload.get("endianness") or ""),
            interpreter=str(payload.get("interpreter") or ""),
            needed_libraries=tuple(str(item) for item in payload.get("needed_libraries", []) or []),
            rootfs_path=str(payload.get("rootfs_path") or ""),
            rootfs_identity=str(payload.get("rootfs_identity") or ""),
            rootfs_interpreter_path=str(payload.get("rootfs_interpreter_path") or ""),
            resolved_libraries=tuple(str(item) for item in payload.get("resolved_libraries", []) or []),
            missing_libraries=tuple(str(item) for item in payload.get("missing_libraries", []) or []),
            host_machine=str(payload.get("host_machine") or ""),
            host_native_architecture=bool(payload.get("host_native_architecture")),
            host_interpreter_available=bool(payload.get("host_interpreter_available")),
            qemu_user_bin=str(payload.get("qemu_user_bin") or ""),
            tool_signature=str(payload.get("tool_signature") or ""),
            cache_key=str(payload.get("cache_key") or ""),
            capabilities=tuple(
                RouteCapability(
                    route=str(item.get("route") or ""),
                    status=str(item.get("status") or "unsupported"),
                    reason=str(item.get("reason") or ""),
                    setup_key=str(item.get("setup_key") or ""),
                    setup_seconds=float(item.get("setup_seconds") or 0.0),
                    marginal_seconds=float(item.get("marginal_seconds") or 0.0),
                )
                for item in payload.get("capabilities", []) or []
                if isinstance(item, Mapping)
            ),
        )


def discover_execution_envelope(
    binary_path: Path,
    *,
    rootfs_path: Path | None = None,
    cache_dir: Path | None = None,
) -> ExecutionEnvelope:
    """Observe ELF/runtime capabilities and optionally reuse a verified cache."""

    binary = Path(binary_path).expanduser().resolve()
    if not binary.is_file():
        raise ValueError(f"execution-envelope binary does not exist: {binary}")
    binary_sha256 = _sha256_file(binary)
    header = _readelf(binary, "-h")
    program_headers = _readelf(binary, "-l")
    dynamic = _readelf(binary, "-d")
    machine = _field(header, "Machine")
    elf_class = _field(header, "Class")
    endianness = _field(header, "Data")
    interpreter = _interpreter(program_headers)
    needed = tuple(sorted(set(re.findall(r"Shared library: \[([^\]]+)\]", dynamic))))
    rootfs = _resolve_rootfs(binary, rootfs_path)
    rootfs_interpreter = _rootfs_file(rootfs, interpreter) if interpreter else None
    resolved, missing = _resolve_needed_libraries(rootfs, needed)
    rootfs_identity = _runtime_identity(rootfs, rootfs_interpreter, resolved)
    qemu = _resolve_qemu(machine)
    tools = _tool_signature(qemu)
    cache_key = hashlib.sha256(
        "\0".join((binary_sha256, rootfs_identity, tools)).encode()
    ).hexdigest()
    cache_path = Path(cache_dir).expanduser().resolve() / f"{cache_key}.json" if cache_dir else None
    if cache_path and cache_path.is_file():
        try:
            cached = ExecutionEnvelope.from_dict(json.loads(cache_path.read_text()))
        except (OSError, ValueError, json.JSONDecodeError, TypeError):
            cached = None
        if cached and cached.cache_key == cache_key and cached.binary_sha256 == binary_sha256:
            return cached
    host_machine = platform.machine()
    host_native = _machine_is_host_native(machine, host_machine)
    host_interpreter = bool(not interpreter or Path(interpreter).is_file())
    envelope = ExecutionEnvelope(
        binary_path=str(binary),
        binary_sha256=binary_sha256,
        binary_size=binary.stat().st_size,
        elf_machine=machine,
        elf_class=elf_class,
        endianness=endianness,
        interpreter=interpreter,
        needed_libraries=needed,
        rootfs_path=str(rootfs) if rootfs else "",
        rootfs_identity=rootfs_identity,
        rootfs_interpreter_path=str(rootfs_interpreter) if rootfs_interpreter else "",
        resolved_libraries=tuple(str(path) for path in resolved),
        missing_libraries=missing,
        host_machine=host_machine,
        host_native_architecture=host_native,
        host_interpreter_available=host_interpreter,
        qemu_user_bin=qemu,
        tool_signature=tools,
        cache_key=cache_key,
        capabilities=_capabilities(
            binary_sha256=binary_sha256,
            machine=machine,
            interpreter=interpreter,
            host_native=host_native,
            host_interpreter=host_interpreter,
            rootfs=rootfs,
            rootfs_identity=rootfs_identity,
            rootfs_interpreter=rootfs_interpreter,
            missing_libraries=missing,
            qemu=qemu,
        ),
    )
    if cache_path:
        _atomic_write_json(cache_path, envelope.to_dict())
    return envelope


def route_capability(envelope: ExecutionEnvelope, route: str) -> RouteCapability:
    for item in envelope.capabilities:
        if item.route == route:
            return item
    return RouteCapability(route, "unsupported", "route_not_described_by_envelope", "", 0.0, 0.0)


def write_execution_envelope(envelope: ExecutionEnvelope, path: Path) -> Path:
    _atomic_write_json(Path(path), envelope.to_dict())
    return Path(path)


def _capabilities(
    *,
    binary_sha256: str,
    machine: str,
    interpreter: str,
    host_native: bool,
    host_interpreter: bool,
    rootfs: Path | None,
    rootfs_identity: str,
    rootfs_interpreter: Path | None,
    missing_libraries: tuple[str, ...],
    qemu: str,
) -> tuple[RouteCapability, ...]:
    short = binary_sha256[:16]
    native_reason = "host_native_runtime_available"
    native_status = "available"
    if not machine:
        native_status, native_reason = "unsupported", "elf_header_unavailable"
    elif not host_native:
        native_status, native_reason = "unsupported", "foreign_architecture"
    elif interpreter and not host_interpreter:
        native_status, native_reason = "unsupported", f"host_program_interpreter_missing:{interpreter}"
    qemu_status, qemu_reason = "available", "qemu_user_runtime_available"
    if not machine:
        qemu_status, qemu_reason = "unsupported", "elf_header_unavailable"
    elif not qemu:
        qemu_status, qemu_reason = "unsupported", "qemu_user_tool_unavailable"
    elif not rootfs:
        qemu_status, qemu_reason = "unsupported", "rootfs_unavailable"
    elif interpreter and not rootfs_interpreter:
        qemu_status, qemu_reason = "unsupported", f"rootfs_program_interpreter_missing:{interpreter}"
    elif missing_libraries:
        qemu_status, qemu_reason = "unsupported", "rootfs_libraries_missing:" + ",".join(missing_libraries)
    rows = [
        RouteCapability("static_exact", "available", "no_process_execution", "", 0.0, 0.05),
        RouteCapability("native_trace", native_status, native_reason, f"native:{short}", 0.15, 1.85),
        RouteCapability("native_ledger", native_status, native_reason, f"native:{short}", 0.15, 2.85),
        RouteCapability("native_oracle", native_status, native_reason, f"native:{short}", 0.15, 1.85),
        RouteCapability("ghidra_call_trace", "available", "static_export_or_import_required", f"ghidra:{short}", 45.0, 15.0),
        RouteCapability("ghidra_pcode", "available", "static_export_or_import_required", f"ghidra:{short}", 60.0, 30.0),
        RouteCapability("angr_concolic", "available", "elf_symbolic_execution_available", f"angr:{short}", 3.0, 17.0),
        RouteCapability(
            "qemu_user",
            qemu_status,
            qemu_reason,
            f"qemu:{_machine_slug(machine)}:{rootfs_identity[:16]}",
            1.0,
            9.0,
        ),
    ]
    return tuple(rows)


def _readelf(binary: Path, option: str) -> str:
    tool = shutil.which("readelf")
    if not tool:
        return ""
    try:
        completed = subprocess.run(
            [tool, option, str(binary)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _field(header: str, name: str) -> str:
    match = re.search(rf"^\s*{re.escape(name)}:\s*(.+?)\s*$", header, re.MULTILINE)
    return match.group(1).strip() if match else ""


def _interpreter(program_headers: str) -> str:
    match = re.search(r"Requesting program interpreter:\s*([^\]]+)\]", program_headers)
    return match.group(1).strip() if match else ""


def _resolve_rootfs(binary: Path, configured: Path | None) -> Path | None:
    if configured:
        candidate = Path(configured).expanduser().resolve()
        return candidate if candidate.is_dir() else None
    for parent in (binary.parent, *binary.parents):
        if parent.name == "rootfs" and parent.is_dir():
            return parent
        if _looks_like_rootfs(parent):
            return parent
    return None


def _looks_like_rootfs(path: Path) -> bool:
    try:
        return path != Path(path.anchor) and path.is_dir() and (path / "lib").is_dir() and any(
            (path / item).exists() for item in ("bin", "usr", "etc")
        )
    except OSError:
        return False


def _rootfs_file(rootfs: Path | None, absolute_path: str) -> Path | None:
    if not rootfs or not absolute_path:
        return None
    candidate = rootfs / absolute_path.lstrip("/")
    return candidate if candidate.is_file() else None


def _resolve_needed_libraries(rootfs: Path | None, needed: tuple[str, ...]) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    if not needed:
        return (), ()
    if rootfs is None:
        return (), needed
    search = [rootfs / item for item in ("lib", "usr/lib", "lib64", "usr/lib64")]
    found: list[Path] = []
    missing: list[str] = []
    for name in needed:
        match = next((directory / name for directory in search if (directory / name).is_file()), None)
        if match is None:
            try:
                match = next((item for item in rootfs.rglob(name) if item.is_file()), None)
            except OSError:
                match = None
        if match is None:
            missing.append(name)
        else:
            found.append(match)
    return tuple(found), tuple(missing)


def _runtime_identity(rootfs: Path | None, interpreter: Path | None, libraries: tuple[Path, ...]) -> str:
    if rootfs is None:
        return ""
    digest = hashlib.sha256()
    for path in sorted(rootfs.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(rootfs).as_posix()
        digest.update(relative.encode())
        if path.is_symlink():
            digest.update(b"L" + os.readlink(path).encode())
        elif path.is_file():
            digest.update(b"F" + _sha256_file(path).encode())
        elif path.is_dir():
            digest.update(b"D")
    return digest.hexdigest()


def _resolve_qemu(machine: str) -> str:
    normalized = machine.lower()
    names: tuple[str, ...] = ()
    if "x86-64" in normalized or "x86_64" in normalized or "amd64" in normalized:
        names = ("qemu-x86_64", "qemu-x86_64-static")
    elif "aarch64" in normalized:
        names = ("qemu-aarch64", "qemu-aarch64-static")
    elif "arm" in normalized:
        names = ("qemu-arm", "qemu-arm-static")
    elif "mips" in normalized and "little" in normalized:
        names = ("qemu-mipsel", "qemu-mipsel-static")
    elif "mips" in normalized:
        names = ("qemu-mips", "qemu-mips-static")
    return next((resolved for name in names if (resolved := shutil.which(name))), "")


def _machine_is_host_native(machine: str, host: str) -> bool:
    machine_normalized = machine.lower()
    host_normalized = host.lower()
    if any(item in machine_normalized for item in ("x86-64", "x86_64", "amd64")):
        return host_normalized in {"x86_64", "amd64"}
    if "aarch64" in machine_normalized:
        return host_normalized in {"aarch64", "arm64"}
    if "arm" in machine_normalized:
        return host_normalized.startswith("arm")
    return False


def _machine_slug(machine: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", machine.lower()).strip("-") or "unknown"


def _tool_signature(qemu: str) -> str:
    rows = [f"host={platform.machine()}", f"qemu={qemu}"]
    for name in ("readelf", "gdb"):
        rows.append(f"{name}={shutil.which(name) or ''}")
    return hashlib.sha256("\0".join(rows).encode()).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        Path(temporary).replace(path)
    except Exception:
        try:
            Path(temporary).unlink()
        except OSError:
            pass
        raise
