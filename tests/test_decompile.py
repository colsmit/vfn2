from __future__ import annotations

from pathlib import Path
import stat

import pytest

from scripts import decompile


def _make_ghidra_install(tmp_path: Path, min_java: str = "21") -> tuple[Path, Path]:
    ghidra_dir = tmp_path / "ghidra_12.0.4_PUBLIC"
    (ghidra_dir / "Ghidra").mkdir(parents=True)
    (ghidra_dir / "support").mkdir(parents=True)
    (ghidra_dir / "Ghidra" / "application.properties").write_text(
        f"application.java.min={min_java}\n",
        encoding="utf-8",
    )
    runner = ghidra_dir / "support" / "analyzeHeadless"
    runner.write_text("", encoding="utf-8")
    return ghidra_dir, runner


def test_read_required_java_major_reads_application_properties(tmp_path: Path) -> None:
    ghidra_dir, _runner = _make_ghidra_install(tmp_path, min_java="21")

    assert decompile.read_required_java_major(ghidra_dir) == 21


def test_parse_java_major_handles_modern_and_legacy_versions() -> None:
    assert decompile.parse_java_major("21.0.2") == 21
    assert decompile.parse_java_major("17") == 17
    assert decompile.parse_java_major("1.8.0_402") == 8


def test_ensure_java_runtime_raises_when_java_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _ghidra_dir, runner = _make_ghidra_install(tmp_path, min_java="21")
    monkeypatch.setattr(decompile.shutil, "which", lambda *args, **kwargs: None)

    with pytest.raises(RuntimeError, match="requires JDK 21 or newer"):
        decompile.ensure_java_runtime(runner, {"PATH": ""})


def test_ensure_java_runtime_rejects_old_java(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _ghidra_dir, runner = _make_ghidra_install(tmp_path, min_java="21")
    monkeypatch.setattr(decompile.shutil, "which", lambda *args, **kwargs: "/usr/bin/java")
    monkeypatch.setattr(decompile, "detect_java_major", lambda _java_path: 17)

    with pytest.raises(RuntimeError, match="requires JDK 21 or newer"):
        decompile.ensure_java_runtime(runner, {"PATH": "/usr/bin"})


def test_detect_java_home_discovers_candidate_jdk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    java_home = tmp_path / "jdk-21"
    java_bin = java_home / "bin"
    java_bin.mkdir(parents=True)
    java = java_bin / "java"
    java.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    java.chmod(0o755)

    def missing_command(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setattr(decompile.subprocess, "run", missing_command)
    monkeypatch.setattr(decompile, "candidate_java_homes", lambda: [java_home])

    assert decompile.detect_java_home() == java_home


def test_locate_ghidra_accepts_lowercase_pyghidra_runner(tmp_path: Path) -> None:
    ghidra_dir = tmp_path / "ghidra_12.0.4_PUBLIC"
    support_dir = ghidra_dir / "support"
    support_dir.mkdir(parents=True)
    (support_dir / "analyzeHeadless").write_text("", encoding="utf-8")
    lower_runner = support_dir / "pyghidraRun"
    lower_runner.write_text("", encoding="utf-8")

    headless, pyghidra_runner = decompile._locate_ghidra(ghidra_dir)

    assert headless == support_dir / "analyzeHeadless"
    assert pyghidra_runner == lower_runner


def test_mark_ghidra_executables_sets_native_binary_bits(tmp_path: Path) -> None:
    native_tool = tmp_path / "Ghidra" / "Features" / "Decompiler" / "os" / "linux_x86_64" / "decompile"
    native_tool.parent.mkdir(parents=True)
    native_tool.write_text("", encoding="utf-8")
    native_tool.chmod(0o644)

    decompile._mark_ghidra_executables(tmp_path)

    assert native_tool.stat().st_mode & stat.S_IXUSR


def test_export_script_is_repo_local() -> None:
    script_path = Path(__file__).resolve().parents[1] / "ghidra_scripts" / "export_functions.py"

    assert script_path.exists()
    assert not script_path.is_symlink()
