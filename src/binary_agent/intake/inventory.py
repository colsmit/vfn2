"""Filesystem and binary intake for the proof-gated pipeline."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from binary_agent.utils.time import utc_timestamp


ROUTE_RE = re.compile(
    r"(?:\b(?:GET|POST|PUT|DELETE|PATCH)\s+|location\s+|uri\s*[:=]\s*|href\s*=\s*[\"'])"
    r"(?P<route>/[A-Za-z0-9_./{}:@?&=%+-]+)",
    re.IGNORECASE,
)
PORT_RE = re.compile(r"(?:listen|port|--port|-p)\s*[=: ]\s*(?P<port>\d{2,5})", re.IGNORECASE)
ENV_RE = re.compile(r"^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=", re.MULTILINE)
TEXT_SUFFIXES = {
    ".cfg",
    ".conf",
    ".config",
    ".env",
    ".html",
    ".ini",
    ".json",
    ".service",
    ".sh",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class IntakeResult:
    output_dir: Path
    target_path: Path
    binaries_path: Path
    services_path: Path
    routes_path: Path
    configs_path: Path
    analysis_manifest_path: Path

    def to_dict(self) -> dict[str, str]:
        return {key: str(value) for key, value in asdict(self).items()}


def run_intake(
    target_path: Path,
    output_dir: Path,
    *,
    export_dir: Path | None = None,
    overwrite: bool = True,
) -> IntakeResult:
    """Inventory a single binary, root filesystem, or tar archive into JSON artifacts."""
    target_path = Path(target_path).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if not target_path.exists():
        raise FileNotFoundError(f"Intake target not found: {target_path}")

    extracted_tmp: tempfile.TemporaryDirectory[str] | None = None
    inventory_root = target_path
    target_kind = "rootfs" if target_path.is_dir() else "single_binary"
    if target_path.is_file() and tarfile.is_tarfile(target_path):
        extracted_tmp = tempfile.TemporaryDirectory(prefix="binary-agent-intake-")
        with tarfile.open(target_path) as archive:
            _safe_extract_tar(archive, Path(extracted_tmp.name))
        inventory_root = Path(extracted_tmp.name)
        target_kind = "archive_rootfs"

    try:
        binary_rows = _inventory_binaries(inventory_root, target_path=target_path)
        service_rows = _inventory_services(inventory_root)
        route_rows = _inventory_routes(inventory_root)
        config_rows = _inventory_configs(inventory_root)
        target_payload = {
            "schema_version": 1,
            "generated_at": utc_timestamp(),
            "kind": target_kind,
            "path": str(target_path),
            "inventory_root": str(inventory_root),
            "sha256": _sha256(target_path) if target_path.is_file() else "",
            "size_bytes": target_path.stat().st_size if target_path.is_file() else 0,
        }
        analysis_payload = {
            "schema_version": 1,
            "generated_at": utc_timestamp(),
            "target": "target.json",
            "binaries": "binaries.json",
            "services": "services.json",
            "routes": "routes.json",
            "configs": "configs.json",
            "export_dir": str(Path(export_dir).resolve()) if export_dir else "",
            "analysis_inputs": [
                {"kind": "binary", "path": row["path"], "architecture": row.get("architecture", "")}
                for row in binary_rows
            ],
        }

        paths = {
            "target": output_dir / "target.json",
            "binaries": output_dir / "binaries.json",
            "services": output_dir / "services.json",
            "routes": output_dir / "routes.json",
            "configs": output_dir / "configs.json",
            "analysis_manifest": output_dir / "analysis_manifest.json",
        }
        _write_json(paths["target"], target_payload, overwrite=overwrite)
        _write_json(paths["binaries"], {"schema_version": 1, "binaries": binary_rows}, overwrite=overwrite)
        _write_json(paths["services"], {"schema_version": 1, "services": service_rows}, overwrite=overwrite)
        _write_json(paths["routes"], {"schema_version": 1, "routes": route_rows}, overwrite=overwrite)
        _write_json(paths["configs"], {"schema_version": 1, "configs": config_rows}, overwrite=overwrite)
        _write_json(paths["analysis_manifest"], analysis_payload, overwrite=overwrite)
        return IntakeResult(
            output_dir=output_dir,
            target_path=paths["target"],
            binaries_path=paths["binaries"],
            services_path=paths["services"],
            routes_path=paths["routes"],
            configs_path=paths["configs"],
            analysis_manifest_path=paths["analysis_manifest"],
        )
    finally:
        if extracted_tmp is not None:
            extracted_tmp.cleanup()


def _inventory_binaries(root: Path, *, target_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    paths = [root] if root.is_file() else _walk_files(root)
    for path in paths:
        if not path.is_file():
            continue
        if not _is_executable_candidate(path):
            continue
        rel = _relative_or_absolute(path, root if root.is_dir() else path.parent)
        rows.append(
            {
                "path": str(path),
                "relative_path": rel,
                "size_bytes": path.stat().st_size,
                "sha256": _sha256(path),
                "mode": oct(stat.S_IMODE(path.stat().st_mode)),
                "executable": os.access(path, os.X_OK),
                "architecture": _detect_architecture(path),
                "evidence": [{"kind": "filesystem_path", "path": str(path)}],
                "source_target": str(target_path),
            }
        )
    return sorted(rows, key=lambda row: row["relative_path"])


def _inventory_services(root: Path) -> list[dict[str, Any]]:
    if root.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for path in _walk_files(root):
        rel = _relative_or_absolute(path, root)
        lower = rel.lower()
        is_service = (
            "/etc/init.d/" in f"/{lower}"
            or lower.endswith(".service")
            or "/systemd/" in f"/{lower}"
            or lower.endswith("/inetd.conf")
            or lower.endswith("/rc.local")
        )
        if not is_service:
            continue
        text = _read_small_text(path)
        command, command_source = _extract_service_command(text)
        rows.append(
            {
                "service_id": _stable_id("service", rel),
                "name": path.stem,
                "path": str(path),
                "relative_path": rel,
                "exec": " ".join(command) if command else _extract_exec(text),
                "command": list(command),
                "command_source": command_source,
                "scope": {
                    "kind": "init_script" if "/etc/init.d/" in f"/{lower}" else "service_file",
                    "relative_path": rel,
                },
                "ports": _extract_ports(text),
                "evidence": [{"kind": "service_file", "path": str(path)}],
            }
        )
    return sorted(rows, key=lambda row: row["relative_path"])


def _inventory_routes(root: Path) -> list[dict[str, Any]]:
    if root.is_file():
        return []
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for path in _walk_files(root):
        if not _looks_textual(path):
            continue
        text = _read_small_text(path)
        if not text:
            continue
        for match in ROUTE_RE.finditer(text):
            route = match.group("route").rstrip("',\";)")
            key = (str(path), route)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "route_id": _stable_id("route", path, route),
                    "route": route,
                    "method": _route_method(text, match.start()),
                    "path": str(path),
                    "relative_path": _relative_or_absolute(path, root),
                    "evidence": [{"kind": "route_table_row", "path": str(path), "snippet": _snippet(text, match.start())}],
                }
            )
    return sorted(rows, key=lambda row: (row["relative_path"], row["route"]))


def _inventory_configs(root: Path) -> list[dict[str, Any]]:
    if root.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for path in _walk_files(root):
        rel = _relative_or_absolute(path, root)
        lower = rel.lower()
        if not _looks_config_path(path, lower):
            continue
        text = _read_small_text(path)
        rows.append(
            {
                "config_id": _stable_id("config", rel),
                "path": str(path),
                "relative_path": rel,
                "kind": _config_kind(path, lower),
                "env_keys": sorted(set(ENV_RE.findall(text))),
                "evidence": [{"kind": "config_file", "path": str(path)}],
            }
        )
    return sorted(rows, key=lambda row: row["relative_path"])


def _detect_architecture(path: Path) -> str:
    file_tool = shutil.which("file")
    if file_tool:
        result = subprocess.run([file_tool, "-b", str(path)], capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    try:
        data = path.read_bytes()[:20]
    except OSError:
        return "unknown"
    if data.startswith(b"\x7fELF"):
        machine = int.from_bytes(data[18:20], "little")
        return {
            3: "ELF x86",
            8: "ELF MIPS",
            40: "ELF ARM",
            62: "ELF x86-64",
            183: "ELF AArch64",
        }.get(machine, f"ELF machine {machine}")
    if data.startswith(b"#!"):
        return "script"
    return "unknown"


def _is_executable_candidate(path: Path) -> bool:
    if os.access(path, os.X_OK):
        return True
    try:
        data = path.read_bytes()[:4]
    except OSError:
        return False
    return data.startswith(b"\x7fELF")


def _walk_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            yield path


def _looks_textual(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES or path.name.lower() in {"routes", "httpd.conf", "nginx.conf"}


def _looks_config_path(path: Path, lower_relative: str) -> bool:
    return (
        path.suffix.lower() in TEXT_SUFFIXES
        or lower_relative.startswith("etc/")
        or "/etc/" in f"/{lower_relative}"
        or lower_relative.endswith(".properties")
    )


def _config_kind(path: Path, lower_relative: str) -> str:
    if path.name.endswith(".service"):
        return "service_unit"
    if ".env" in lower_relative or path.name == "environment":
        return "env"
    if "passwd" in path.name or "shadow" in path.name:
        return "account_database"
    return path.suffix.lower().lstrip(".") or "config"


def _extract_exec(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("ExecStart="):
            return stripped.split("=", 1)[1].strip()
        if stripped.startswith(("./", "/", "start-stop-daemon")):
            return stripped
    return ""


def _extract_service_command(text: str) -> tuple[tuple[str, ...], str]:
    """Recover one scoped service command without evaluating shell code."""

    lines = str(text or "").splitlines()
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("procd_set_param command"):
            command_text = stripped[len("procd_set_param command") :].strip()
            while command_text.endswith("\\") and index + 1 < len(lines):
                index += 1
                command_text = command_text[:-1].rstrip() + " " + lines[index].strip()
            tokens = _safe_shell_tokens(command_text)
            return tuple(tokens[:32]), "procd_set_param command"
        if stripped.startswith("ExecStart="):
            return tuple(_safe_shell_tokens(stripped.split("=", 1)[1])[:32]), "ExecStart"
    fallback = _extract_exec(text)
    return tuple(_safe_shell_tokens(fallback)[:32]), "shell_command" if fallback else ""


def _safe_shell_tokens(command: str) -> list[str]:
    try:
        return [str(item) for item in shlex.split(str(command or ""), comments=True, posix=True)]
    except ValueError:
        return [item for item in re.split(r"\s+", str(command or "")) if item]


def _extract_ports(text: str) -> list[int]:
    ports: set[int] = set()
    for match in PORT_RE.finditer(text or ""):
        port = int(match.group("port"))
        if 0 < port < 65536:
            ports.add(port)
    return sorted(ports)


def _route_method(text: str, position: int) -> str:
    prefix = text[max(0, position - 12) : position].upper()
    for method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
        if method in prefix:
            return method
    return ""


def _snippet(text: str, position: int, width: int = 120) -> str:
    return " ".join(text[max(0, position - width // 2) : position + width // 2].split())


def _read_small_text(path: Path, limit: int = 256 * 1024) -> str:
    try:
        data = path.read_bytes()[:limit]
    except OSError:
        return ""
    if b"\x00" in data[:4096]:
        return ""
    return data.decode("utf-8", errors="replace")


def _relative_or_absolute(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stable_id(*parts: object) -> str:
    raw = "|".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def _write_json(path: Path, payload: Mapping[str, Any], *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def _safe_extract_tar(archive: tarfile.TarFile, destination: Path) -> None:
    destination = destination.resolve()
    for member in archive.getmembers():
        target = (destination / member.name).resolve()
        if destination != target and destination not in target.parents:
            raise ValueError(f"Refusing to extract archive member outside destination: {member.name}")
    archive.extractall(destination)
