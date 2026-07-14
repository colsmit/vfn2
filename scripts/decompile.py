"""
Helper CLI that wraps Ghidra's analyzeHeadless to export per-function
decompilations using our `export_functions.py` script.
"""

import argparse
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from binary_agent.data.manifest import (
    ManifestError,
    SYMBOL_SIDECAR_FILENAME,
    write_normalized_manifest,
)
from binary_agent.utils.env import load_dotenv_if_available
from binary_agent.utils.time import utc_timestamp


ROOT_DIR = Path(__file__).resolve().parent.parent
# Default to the locally installed Ghidra; override with GHIDRA_INSTALL_DIR or --ghidra-dir.
DEFAULT_GHIDRA_DIR = "/Applications/ghidra_12.0_PUBLIC"
GHIDRA_DOWNLOAD_ROOT = ROOT_DIR / "ghidra_downloads"
GHIDRA_RELEASES_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
GHIDRA_AUTO_DOWNLOAD_ENV = "GHIDRA_SKIP_AUTO_DOWNLOAD"
GHIDRA_FORCE_ANALYZE_ENV = "GHIDRA_FORCE_ANALYZE_HEADLESS"
GHIDRA_AUTOINSTALL_PYGHIDRA_ENV = "GHIDRA_AUTOINSTALL_PYGHIDRA"
GHIDRA_SHARED_HOME_ENV = "BINARY_AGENT_GHIDRA_HOME"
JAVA_VERSION_PATTERN = re.compile(r'version "(?P<version>[^"]+)"')
TEXT_SYMBOL_TYPES = {"T", "t", "W", "w"}


def resolve_ghidra_headless(override: str | None) -> tuple[Path, Path | None]:
    """
    Locate analyzeHeadless (or pyGhidraRun) from an explicit path, GHIDRA_INSTALL_DIR,
    or the default macOS install. If nothing is present and auto-download is allowed,
    fetch the latest Ghidra release from GitHub into ghidra_downloads/.
    """

    configured = override or os.getenv("GHIDRA_INSTALL_DIR")
    if configured:
        return _locate_ghidra(Path(configured).expanduser())

    # Try default path first.
    default_path = Path(DEFAULT_GHIDRA_DIR).expanduser()
    try:
        return _locate_ghidra(default_path)
    except FileNotFoundError:
        pass

    # Try any previously downloaded release.
    cached = _find_cached_ghidra()
    if cached:
        return _locate_ghidra(cached)

    # Auto-download unless explicitly skipped.
    if os.getenv(GHIDRA_AUTO_DOWNLOAD_ENV) == "1":
        raise FileNotFoundError(
            f"Could not locate Ghidra under '{default_path}'. Auto-download disabled by {GHIDRA_AUTO_DOWNLOAD_ENV}=1."
        )

    downloaded = _download_latest_ghidra()
    return _locate_ghidra(downloaded)


def _locate_ghidra(base_path: Path) -> tuple[Path, Path | None]:
    base = base_path.resolve()
    headless = base / "support" / "analyzeHeadless"
    pyghidra_runner = _find_pyghidra_runner(base / "support")
    _mark_ghidra_executables(base)
    if not headless.exists() and not pyghidra_runner.exists():
        raise FileNotFoundError(
            f"Could not locate analyzeHeadless or pyGhidraRun under '{base_path}'. "
            "Set GHIDRA_INSTALL_DIR or pass --ghidra-dir."
        )
    if os.getenv(GHIDRA_FORCE_ANALYZE_ENV) == "1":
        return headless, None
    return headless, (pyghidra_runner if pyghidra_runner.exists() else None)


def _find_cached_ghidra() -> Path | None:
    if not GHIDRA_DOWNLOAD_ROOT.exists():
        return None
    for entry in sorted(GHIDRA_DOWNLOAD_ROOT.iterdir(), reverse=True):
        if entry.is_dir() and entry.name.startswith("ghidra_"):
            headless = entry / "support" / "analyzeHeadless"
            pyghidra_runner = _find_pyghidra_runner(entry / "support")
            if headless.exists() or pyghidra_runner.exists():
                return entry
    return None


def _download_latest_ghidra() -> Path:
    GHIDRA_DOWNLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    release = _fetch_latest_release()
    asset = _select_release_asset(release)
    asset_name = asset["name"]
    dest_zip = GHIDRA_DOWNLOAD_ROOT / asset_name

    if not dest_zip.exists():
        _download_file(asset["browser_download_url"], dest_zip)

    extracted_dir = _extract_ghidra_zip(dest_zip)
    return extracted_dir


def _fetch_latest_release() -> dict:
    request = Request(GHIDRA_RELEASES_API, headers={"Accept": "application/vnd.github+json"})
    try:
        with urlopen(request, timeout=20) as response:
            payload = response.read().decode("utf-8")
    except URLError as exc:
        raise FileNotFoundError(f"Unable to reach GitHub for Ghidra download: {exc}") from exc
    return json.loads(payload)


def _select_release_asset(release_payload: dict) -> dict:
    assets = release_payload.get("assets") or []
    for asset in assets:
        name = asset.get("name", "")
        if name.endswith(".zip") and name.startswith("ghidra_"):
            return asset
    raise FileNotFoundError("Latest Ghidra release does not include a zip asset.")


def _download_file(url: str, dest: Path) -> None:
    request = Request(url)
    with urlopen(request, timeout=60) as response, open(dest, "wb") as handle:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            handle.write(chunk)


def _extract_ghidra_zip(zip_path: Path) -> Path:
    with zipfile.ZipFile(zip_path, "r") as archive:
        archive.extractall(GHIDRA_DOWNLOAD_ROOT)
        members = archive.namelist()
    dirs = {Path(member).parts[0] for member in members if "/" in member}
    candidates = [GHIDRA_DOWNLOAD_ROOT / entry for entry in dirs if entry.startswith("ghidra_")]
    for candidate in sorted(candidates, reverse=True):
        headless = candidate / "support" / "analyzeHeadless"
        pyghidra_runner = _find_pyghidra_runner(candidate / "support")
        if headless.exists() or pyghidra_runner.exists():
            _mark_ghidra_executables(candidate)
            return candidate
    raise FileNotFoundError("Downloaded Ghidra archive did not contain an expected layout.")


def _mark_executable(path: Path) -> None:
    if not path or not path.exists():
        return
    try:
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass


def _mark_support_executables(support_dir: Path) -> None:
    if not support_dir.exists():
        return
    targets = [
        "analyzeHeadless",
        "pyGhidraRun",
        "pyghidraRun",
        "launch.sh",
    ]
    for target in targets:
        _mark_executable(support_dir / target)
    for script in support_dir.glob("*.sh"):
        _mark_executable(script)


def _find_pyghidra_runner(support_dir: Path) -> Path:
    for name in ("pyGhidraRun", "pyghidraRun"):
        candidate = support_dir / name
        if candidate.exists():
            return candidate
    return support_dir / "pyGhidraRun"


def _mark_native_executables(root_dir: Path) -> None:
    for candidate in root_dir.glob("**/os/*/*"):
        if candidate.is_file():
            _mark_executable(candidate)


def _mark_ghidra_executables(base_dir: Path) -> None:
    _mark_support_executables(base_dir / "support")
    _mark_native_executables(base_dir / "Ghidra")
    _mark_native_executables(base_dir / "GPL")


def build_output_dirs(binary_path: Path, output_override: str | None) -> tuple[Path, Path, Path]:
    output_root = Path(output_override).expanduser().resolve() if output_override else (ROOT_DIR / "artifacts")
    timestamp = utc_timestamp()
    binary_stem = binary_path.name
    run_dir = output_root / binary_stem / timestamp
    export_dir = run_dir / "decompiled"
    user_dir = run_dir / "ghidra_user"
    export_dir.mkdir(parents=True, exist_ok=True)
    user_dir.mkdir(parents=True, exist_ok=True)
    return run_dir, export_dir, user_dir


def headless_project_location(run_dir: Path) -> tuple[Path, Path | None]:
    """Keep Ghidra project paths free of hidden components such as `.ai`."""

    resolved = Path(run_dir).resolve()
    if any(part.startswith(".") and part not in {".", ".."} for part in resolved.parts):
        cleanup_root = Path(tempfile.mkdtemp(prefix="binary_agent_decompile_"))
        project_dir = cleanup_root / "ghidra_project"
        project_dir.mkdir()
        return project_dir, cleanup_root
    project_dir = resolved / "ghidra_project"
    project_dir.mkdir(parents=True, exist_ok=True)
    return project_dir, None


def ensure_script_path() -> Path:
    script_dir = ROOT_DIR / "ghidra_scripts"
    if not script_dir.exists():
        raise FileNotFoundError("Expected ghidra_scripts directory missing.")
    return script_dir


def _demangle_symbols(symbols: list[str]) -> list[str]:
    if not symbols:
        return []
    cxxfilt = shutil.which("c++filt")
    if not cxxfilt:
        return list(symbols)
    result = subprocess.run(
        [cxxfilt],
        input="\n".join(symbols) + "\n",
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return list(symbols)
    lines = [line.strip() for line in result.stdout.splitlines()]
    return lines if len(lines) == len(symbols) else list(symbols)


def _demangled_base(name: str) -> str:
    base = str(name or "").split("(", 1)[0].strip()
    if "::" in base:
        base = base.split("::")[-1].strip()
    return base


def _build_fallback_symbol_sidecar(binary_path: Path) -> dict | None:
    nm_path = shutil.which("nm")
    if not nm_path:
        return None
    result = subprocess.run(
        [nm_path, "--defined-only", str(binary_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    raw_symbols: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        address, sym_type, symbol_name = parts[0], parts[-2], parts[-1]
        if sym_type not in TEXT_SYMBOL_TYPES:
            continue
        try:
            int(address, 16)
        except ValueError:
            continue
        raw_symbols.append((address, symbol_name))
    if not raw_symbols:
        return None
    demangled = _demangle_symbols([symbol_name for _, symbol_name in raw_symbols])
    symbols = []
    for (address, symbol_name), demangled_name in zip(raw_symbols, demangled):
        symbols.append(
            {
                "address": f"0x{int(address, 16):x}",
                "symbol_name": symbol_name,
                "demangled_name": demangled_name,
                "source_symbol": _demangled_base(demangled_name),
                "source_object": "",
            }
        )
    return {
        "binary": str(binary_path),
        "generated_at": utc_timestamp(),
        "symbols": symbols,
    }


def _stage_symbol_sidecar(binary_path: Path, export_dir: Path) -> Path | None:
    sidecar_path = binary_path.with_name(f"{binary_path.name}.symbols.json")
    target_path = export_dir / SYMBOL_SIDECAR_FILENAME
    if sidecar_path.exists():
        shutil.copy2(sidecar_path, target_path)
        return target_path
    payload = _build_fallback_symbol_sidecar(binary_path)
    if payload is None:
        return None
    target_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target_path


def detect_java_home() -> Path | None:
    env_java = os.getenv("JAVA_HOME")
    if env_java:
        expanded = Path(env_java).expanduser()
        if (expanded / "bin" / "java").exists():
            return expanded

    # Try macOS helper
    try:
        result = subprocess.run(
            ["/usr/libexec/java_home"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True,
        )
        candidate = Path(result.stdout.strip())
        if (candidate / "bin" / "java").exists():
            return candidate
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Fallback to Homebrew-installed OpenJDK (prefer 21, then 17)
    try:
        for candidate_formula in ("openjdk@21", "openjdk@17"):
            result = subprocess.run(
                ["brew", "--prefix", candidate_formula],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=True,
            )
            prefix = Path(result.stdout.strip()).expanduser()
            candidates = [
                prefix / "libexec" / "openjdk.jdk" / "Contents" / "Home",
                prefix,
            ]
            for candidate in candidates:
                if (candidate / "bin" / "java").exists():
                    return candidate
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    for candidate in candidate_java_homes():
        if (candidate / "bin" / "java").exists():
            return candidate

    return None


def candidate_java_homes() -> list[Path]:
    candidates = [
        Path("/home/linuxbrew/.linuxbrew/opt/openjdk@21/libexec"),
        Path("/home/linuxbrew/.linuxbrew/opt/openjdk@21"),
        Path("/home/linuxbrew/.linuxbrew/opt/openjdk/libexec"),
        Path("/home/linuxbrew/.linuxbrew/opt/openjdk"),
        Path("/usr/lib/jvm/default-java"),
    ]
    for root in (Path("/usr/lib/jvm"), Path("/opt"), Path("/usr/local")):
        if root.exists():
            candidates.extend(sorted(root.glob("*jdk*"), reverse=True))
            candidates.extend(sorted(root.glob("*jre*"), reverse=True))
    return candidates


def read_required_java_major(ghidra_install_dir: Path) -> int | None:
    properties_path = ghidra_install_dir / "Ghidra" / "application.properties"
    if not properties_path.exists():
        return None

    for line in properties_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("application.java.min="):
            _, _, raw_value = line.partition("=")
            raw_value = raw_value.strip()
            if raw_value.isdigit():
                return int(raw_value)
            return None
    return None


def parse_java_major(version: str) -> int | None:
    token = (version or "").strip()
    if not token:
        return None
    if token.startswith("1."):
        _, _, legacy = token.partition(".")
        legacy_major = legacy.split(".", 1)[0]
        return int(legacy_major) if legacy_major.isdigit() else None
    major = token.split(".", 1)[0]
    return int(major) if major.isdigit() else None


def detect_java_major(java_path: str) -> int | None:
    try:
        result = subprocess.run(
            [java_path, "-version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    except OSError:
        return None

    match = JAVA_VERSION_PATTERN.search(result.stdout)
    if not match:
        return None
    return parse_java_major(match.group("version"))


def ensure_java_runtime(runner_path: Path, env: dict[str, str]) -> None:
    java_path = shutil.which("java", path=env.get("PATH"))
    ghidra_install_dir = runner_path.resolve().parent.parent
    required_major = read_required_java_major(ghidra_install_dir)
    requirement = f"JDK {required_major} or newer" if required_major else "a supported JDK"

    if not java_path:
        message = (
            "Java runtime not found for Ghidra. "
            f"{ghidra_install_dir.name} requires {requirement}. "
            "Install Java and expose it via PATH or JAVA_HOME."
        )
        if platform.system() == "Darwin":
            brew_formula = f"openjdk@{required_major}" if required_major else "openjdk"
            java_home_hint = f" -v {required_major}" if required_major else ""
            message += (
                f" On macOS, try `brew install {brew_formula}` and "
                f"`export JAVA_HOME=$(/usr/libexec/java_home{java_home_hint})`."
            )
        raise RuntimeError(message)

    detected_major = detect_java_major(java_path)
    if required_major and detected_major is not None and detected_major < required_major:
        raise RuntimeError(
            f"Java {detected_major} found at {java_path}, but {ghidra_install_dir.name} requires JDK {required_major} or newer."
        )


def _parse_script_entry(entry: str) -> tuple[str, list[str]]:
    """
    Parse a script entry in the form "script.py" or "script.py:key=value,key2=value2".
    Returns the script name and a list of key=value arguments.
    """
    parts = entry.split(":", 1)
    script = parts[0].strip()
    args: list[str] = []
    if len(parts) == 2 and parts[1].strip():
        for token in parts[1].split(","):
            token = token.strip()
            if token:
                args.append(token)
    return script, args


DEFAULT_ANALYZERS = [
    "Disassemble",
    "Function ID",
    "Decompiler Parameter ID",
    "Data Reference",
]


def run_headless(
    headless_paths: tuple[Path, Path | None],
    binary_path: Path,
    export_dir: Path,
    script_dir: Path,
    project_dir: Path,
    project_name: str,
    user_dir: Path,
    home_override: Path,
    analyzers: list[str],
    pre_scripts: list[str],
    post_scripts: list[str],
    decompiler_mode: str,
    fid_path: Path | None,
) -> None:
    headless_path, explicit_pyghidra_runner = headless_paths
    is_macos_arm = platform.system() == "Darwin" and platform.machine() == "arm64"
    force_rosetta = is_macos_arm and "10.4" in str(headless_path)
    # Prefer pyGhidraRun when available (Ghidra 12+) so Python scripts run correctly.
    runner = headless_path
    runner_prefix: list[str] = []
    if explicit_pyghidra_runner:
        runner = explicit_pyghidra_runner
        force_rosetta = False  # pyGhidraRun handles arch selection internally for 12.x
        runner_prefix.append("-H")  # pyGhidraRun needs -H to invoke AnalyzeHeadless

    command = (
        ["arch", "-x86_64", str(runner)]
        if force_rosetta
        else [str(runner)]
    )
    command.extend(runner_prefix)
    command.extend([str(project_dir), project_name, "-import", str(binary_path), "-overwrite"])

    if fid_path:
        command.extend(["-fid", str(fid_path)])

    script_args: list[tuple[str, list[str], str]] = []

    if pre_scripts:
        for entry in pre_scripts:
            name, args = _parse_script_entry(entry)
            script_args.append((name, args, "-preScript"))

    export_args = [f"output_dir={export_dir}", f"mode={decompiler_mode}", "emit_c=true"]

    post_entries = list(post_scripts or [])
    if not any(entry.split(":", 1)[0].strip() == "export_functions.py" for entry in post_entries):
        post_entries.append("export_functions.py")
    for entry in post_entries:
        name, args = _parse_script_entry(entry)
        if name == "export_functions.py":
            args = export_args + args
        script_args.append((name, args, "-postScript"))

    command.extend(["-scriptPath", str(script_dir)])

    if analyzers:
        requested = ", ".join(analyzers)
        print(
            f"[!] Analyzer subset requested ({requested}) but explicit selection is not supported "
            "on this Ghidra release; running with default analysis set instead."
        )

    for script_name, args, flag in script_args:
        command.extend([flag, script_name])
        command.extend(args)

    env = os.environ.copy()

    java_home = detect_java_home()
    if java_home:
        env["JAVA_HOME"] = str(java_home)
        java_bin = Path(java_home) / "bin"
        if java_bin.exists():
            env["PATH"] = f"{java_bin}:{env['PATH']}"
    env["GHIDRA_USER_DIR"] = str(user_dir)
    auto_install_pyghidra = os.getenv(GHIDRA_AUTOINSTALL_PYGHIDRA_ENV, "1") != "0"
    if auto_install_pyghidra and "-H" in runner_prefix:
        # pyGhidraRun prompts to install PyGhidra; force a "yes" by default (opt-out with GHIDRA_AUTOINSTALL_PYGHIDRA=0).
        env.setdefault("PYGHIDRA_AUTO_INSTALL", "y")
    env["HOME"] = str(home_override)
    env["JAVA_TOOL_OPTIONS"] = f"-Duser.home={home_override}"
    ensure_java_runtime(runner, env)

    print(f"[+] Running Ghidra headless: {' '.join(command)}")
    input_data: str | None = None
    if auto_install_pyghidra and explicit_pyghidra_runner:
        # Simulate affirmative responses to pyGhidraRun's install prompts.
        input_data = "y\ny\n"
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        env=env,
        input=input_data,
    )

    if completed.returncode != 0:
        print(completed.stdout)
        raise RuntimeError(f"Ghidra analyzeHeadless failed with exit code {completed.returncode}")

    log_path = export_dir.parent / "ghidra_headless.log"
    log_path.write_text(completed.stdout)
    print(f"[+] Headless execution complete. Log saved to {log_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export per-function Ghidra decompilation for a stripped binary.")
    parser.add_argument("binary", type=Path, help="Path to the stripped binary to analyze.")
    parser.add_argument("--output-dir", type=str, default=None, help="Root output directory for artifacts (defaults to ./artifacts).")
    parser.add_argument("--ghidra-dir", type=str, default=None, help="Override path to Ghidra installation (supports ~).")
    parser.add_argument("--project-name", type=str, default=None, help="Optional explicit Ghidra project name.")
    parser.add_argument("--skip-normalize", action="store_true", help="Disable normalized manifest generation.")
    parser.add_argument(
        "--analyzers",
        type=str,
        default=",".join(DEFAULT_ANALYZERS),
        help="Comma-separated list of analyzers to enable (defaults to curated minimal set).",
    )
    parser.add_argument(
        "--pre-script",
        action="append",
        default=["enable_paramid.py"],
        help="Script to run before analysis (can be provided multiple times, supports script.py:key=value args).",
    )
    parser.add_argument(
        "--post-script",
        action="append",
        default=[],
        help="Script to run after analysis (can be provided multiple times, supports script.py:key=value args).",
    )
    parser.add_argument(
        "--decompiler-mode",
        choices=["c", "paramid"],
        default="c",
        help="Use 'paramid' when you only need prototypes (skips C output); default is 'c'.",
    )
    parser.add_argument(
        "--enable-fid",
        type=str,
        default=None,
        help="Path to a Function ID database directory to enable during analysis.",
    )
    return parser.parse_args()


def main() -> None:
    load_dotenv_if_available()
    args = parse_args()

    binary_path = args.binary.expanduser().resolve()
    if not binary_path.exists():
        raise FileNotFoundError(f"Binary does not exist: {binary_path}")
    if not binary_path.is_file():
        raise ValueError(f"Binary path is not a file: {binary_path}")

    headless_paths = resolve_ghidra_headless(args.ghidra_dir)
    run_dir, export_dir, user_dir = build_output_dirs(binary_path, args.output_dir)
    project_dir, cleanup_root = headless_project_location(run_dir)
    project_name = args.project_name or binary_path.stem

    script_dir = ensure_script_path()

    analyzers = [item.strip() for item in (args.analyzers or "").split(",") if item.strip()]
    fid_path = Path(args.enable_fid).expanduser().resolve() if args.enable_fid else None
    if fid_path and not fid_path.exists():
        raise FileNotFoundError(f"Function ID database not found: {fid_path}")

    configured_home = os.getenv(GHIDRA_SHARED_HOME_ENV, "").strip()
    home_override = Path(configured_home).expanduser().resolve() if configured_home else run_dir
    home_override.mkdir(parents=True, exist_ok=True)
    try:
        run_headless(
            headless_paths=headless_paths,
            binary_path=binary_path,
            export_dir=export_dir,
            script_dir=script_dir,
            project_dir=project_dir,
            project_name=project_name,
            user_dir=user_dir,
            home_override=home_override,
            analyzers=analyzers,
            pre_scripts=args.pre_script or [],
            post_scripts=args.post_script or [],
            decompiler_mode=args.decompiler_mode,
            fid_path=fid_path,
        )
    finally:
        if cleanup_root is not None:
            shutil.rmtree(cleanup_root, ignore_errors=True)

    manifest_path = export_dir / "manifest.jsonl"
    if manifest_path.exists():
        print(f"[+] Manifest generated: {manifest_path}")
        if not args.skip_normalize:
            try:
                symbol_path = _stage_symbol_sidecar(binary_path, export_dir)
                if symbol_path is not None:
                    print(f"[+] Symbol sidecar: {symbol_path}")
                normalized_path = write_normalized_manifest(export_dir)
                print(f"[+] Normalized manifest: {normalized_path}")
            except ManifestError as exc:
                print(f"[!] Failed to normalize manifest: {exc}", file=sys.stderr)
    else:
        print("[!] Manifest was not generated; check Ghidra logs for details.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        sys.exit(1)
