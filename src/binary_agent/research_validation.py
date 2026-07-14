"""Auditable prerequisite and live-tool validation for research workstations."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class ResearchPrerequisite:
    name: str
    status: str
    detail: str
    path: str = ""
    required_for: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ResearchValidationResult:
    run_id: str
    run_dir: str
    status: str
    prerequisites: tuple[ResearchPrerequisite, ...]
    commands: tuple[Mapping[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "artifact_kind": "research_validation_summary",
            "run_id": self.run_id,
            "run_dir": self.run_dir,
            "status": self.status,
            "prerequisites": [item.to_dict() for item in self.prerequisites],
            "commands": [dict(item) for item in self.commands],
        }


def collect_research_preflight(
    repo_root: Path,
    environment: Mapping[str, str],
) -> tuple[ResearchPrerequisite, ...]:
    """Describe local research prerequisites without changing the environment."""

    repository = repo_root.expanduser().resolve()
    search_path = str(environment["PATH"]) if "PATH" in environment else os.defpath
    rows: list[ResearchPrerequisite] = []
    for tool in ("cc", "gdb", "objdump", "nm", "strip"):
        path = shutil.which(tool, path=search_path) or ""
        rows.append(
            ResearchPrerequisite(
                name=f"tool:{tool}",
                status="available" if path else "missing",
                detail="native validation tool found" if path else "not found on PATH",
                path=path,
                required_for=("native",),
            )
        )
    for package, module in (("angr", "angr"), ("capstone", "capstone"), ("pyelftools", "elftools")):
        available = importlib.util.find_spec(module) is not None
        rows.append(
            ResearchPrerequisite(
                name=f"python:{package}",
                status="available" if available else "missing",
                detail="optional concolic dependency importable" if available else "install .[concolic]",
                required_for=("concolic",),
            )
        )
    ghidra = Path(str(environment.get("GHIDRA_INSTALL_DIR") or "")).expanduser()
    ghidra_launcher = ghidra / "support" / "analyzeHeadless" if str(ghidra) else Path()
    ghidra_available = bool(str(environment.get("GHIDRA_INSTALL_DIR") or "")) and ghidra_launcher.is_file()
    rows.append(
        ResearchPrerequisite(
            name="ghidra",
            status="available" if ghidra_available else "missing",
            detail="headless Ghidra launcher found" if ghidra_available else "set GHIDRA_INSTALL_DIR",
            path=str(ghidra) if ghidra_available else "",
            required_for=("live_ghidra", "full_matrix"),
        )
    )
    sample = repository / "samples" / "vuln_demo" / "build" / "vuln_demo_stripped"
    fortified = repository / "samples" / "vuln_demo" / "build" / "vuln_demo_fortified_stripped"
    samples_available = sample.is_file() and fortified.is_file()
    rows.append(
        ResearchPrerequisite(
            name="sample:vuln_demo",
            status="available" if samples_available else "missing",
            detail="stripped vulnerable and fortified samples built" if samples_available else "run make -C samples/vuln_demo all",
            path=str(sample.parent) if samples_available else "",
            required_for=("live_ghidra",),
        )
    )
    harness = Path(str(environment.get("BINARY_AGENT_OPENSSL_HEARTBLEED_HARNESS") or "")).expanduser()
    harness_available = bool(str(environment.get("BINARY_AGENT_OPENSSL_HEARTBLEED_HARNESS") or "")) and harness.is_file()
    rows.append(
        ResearchPrerequisite(
            name="external:linked_openssl_heartbleed",
            status="available" if harness_available else "external_blocked",
            detail="linked historical harness available" if harness_available else "external corpus input not configured",
            path=str(harness) if harness_available else "",
            required_for=("external_openssl",),
        )
    )
    return tuple(rows)


def run_research_validation(
    output_root: Path,
    *,
    repo_root: Path,
    environment: Mapping[str, str],
    build_samples: bool = False,
    run_live_ghidra: bool = False,
) -> ResearchValidationResult:
    repository = repo_root.expanduser().resolve()
    root = output_root.expanduser()
    if not root.is_absolute():
        root = repository / root
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    run_id = _available_run_id(root)
    run_dir = root / run_id
    run_dir.mkdir()
    command_rows: list[dict[str, Any]] = []
    process_environment = {**os.environ, **{str(key): str(value) for key, value in environment.items()}}

    if build_samples:
        command_rows.append(
            _run_command(
                ["make", "-C", "samples/vuln_demo", "clean", "all"],
                repository,
                process_environment,
                run_dir,
                "build_samples",
            )
        )

    prerequisites = collect_research_preflight(repository, process_environment)
    if run_live_ghidra:
        missing = [
            item.name
            for item in prerequisites
            if item.status == "missing" and "live_ghidra" in item.required_for
        ]
        if missing:
            command_rows.append(
                {
                    "name": "live_ghidra",
                    "status": "blocked",
                    "reason": "missing prerequisites: " + ", ".join(missing),
                }
            )
        else:
            live_environment = {
                **process_environment,
                "BINARY_AGENT_RUN_GHIDRA_VALIDATION": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            command_rows.append(
                _run_command(
                    [
                        str(repository / ".venv" / "bin" / "python"),
                        "-m",
                        "pytest",
                        "-q",
                        "-p",
                        "no:cacheprovider",
                        "tests/test_ghidra_process_validation.py",
                        "-k",
                        "not linked_openssl",
                    ],
                    repository,
                    live_environment,
                    run_dir,
                    "live_ghidra_process",
                )
            )
            command_rows.append(
                _run_command(
                    [
                        str(repository / ".venv" / "bin" / "python"),
                        "-m",
                        "pytest",
                        "-q",
                        "-p",
                        "no:cacheprovider",
                        "tests/test_ghidra_existing_class_corpus.py",
                    ],
                    repository,
                    live_environment,
                    run_dir,
                    "live_ghidra_existing_class_matrix",
                )
            )

    status = "passed"
    if any(row.get("status") in {"failed", "blocked"} for row in command_rows):
        status = "failed"
    result = ResearchValidationResult(
        run_id=run_id,
        run_dir=str(run_dir),
        status=status,
        prerequisites=prerequisites,
        commands=tuple(command_rows),
    )
    summary_path = run_dir / "research_validation_summary.json"
    _write_json_atomic(summary_path, result.to_dict())
    _write_json_atomic(
        root / "latest.json",
        {
            "schema_version": 1,
            "artifact_kind": "research_validation_latest",
            "run_id": run_id,
            "run_dir": str(run_dir),
            "status": status,
            "summary_path": str(summary_path),
        },
    )
    return result


def _run_command(
    command: Sequence[str],
    cwd: Path,
    environment: Mapping[str, str],
    run_dir: Path,
    name: str,
) -> dict[str, Any]:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=dict(environment),
        capture_output=True,
        text=True,
        check=False,
    )
    stdout_path = run_dir / f"{name}.stdout.log"
    stderr_path = run_dir / f"{name}.stderr.log"
    stdout_path.write_text(completed.stdout)
    stderr_path.write_text(completed.stderr)
    return {
        "name": name,
        "status": "passed" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "command": list(command),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _available_run_id(root: Path) -> str:
    base = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if not (root / base).exists():
        return base
    index = 1
    while (root / f"{base}-{index:03d}").exists():
        index += 1
    return f"{base}-{index:03d}"


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)
