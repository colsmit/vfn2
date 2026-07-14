"""Candidate-owned firmware service sandboxes for QEMU user replay.

Service readiness is process-setup evidence only.  Nothing in this module can
set a replay sink or vulnerability observation.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


DEFAULT_UBUS_SOCKET = b"/var/run/ubus/ubus.sock\0"
SUPPORTED_DEPENDENCIES = frozenset({"ubusd", "uci-config"})


@dataclass(frozen=True)
class DependencyState:
    name: str
    status: str
    evidence: tuple[str, ...] = ()
    blocker: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence"] = list(self.evidence)
        return payload


class FirmwareServiceSession:
    """Prepared rootfs and bounded dependency process lifecycle."""

    def __init__(
        self,
        *,
        source_rootfs: Path,
        rootfs_path: Path,
        candidate_dir: Path,
        qemu_user_bin: str,
        dependencies: Sequence[str],
        socket_path: Path,
        states: Mapping[str, DependencyState],
        artifacts: Sequence[str],
        startup_timeout_seconds: float,
    ) -> None:
        self.source_rootfs = source_rootfs
        self.rootfs_path = rootfs_path
        self.candidate_dir = candidate_dir
        self.qemu_user_bin = qemu_user_bin
        self.dependencies = tuple(dict.fromkeys(str(item) for item in dependencies))
        self.socket_path = socket_path
        self.dependency_states: dict[str, DependencyState] = dict(states)
        self.artifacts: list[str] = list(artifacts)
        self.startup_timeout_seconds = max(0.1, float(startup_timeout_seconds))
        self._processes: list[subprocess.Popen[str]] = []
        self._streams: list[Any] = []
        self._lifecycle: list[dict[str, Any]] = []
        self._stopped = False

    @property
    def blocker(self) -> str:
        return next(
            (
                state.blocker
                for state in self.dependency_states.values()
                if state.status == "unsupported" and state.blocker
            ),
            "",
        )

    @property
    def ready(self) -> bool:
        return bool(self.dependencies) and all(
            self.dependency_states.get(name, DependencyState(name, "unsupported")).status
            == "observed_ready"
            for name in self.dependencies
        )

    def start(self) -> bool:
        """Start every managed dependency and require protocol health."""

        self._stopped = False
        if self.blocker:
            self._record("start_blocked", blocker=self.blocker)
            self._write_lifecycle()
            return False
        if "ubusd" in self.dependencies and not self._start_ubusd():
            self._write_lifecycle()
            return False
        self._record("dependencies_ready", dependencies=list(self.dependencies))
        self._write_lifecycle()
        return self.ready

    def stop(self) -> None:
        """Reap all dependency processes; safe to call repeatedly."""

        if self._stopped:
            return
        self._stopped = True
        for process in reversed(self._processes):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (OSError, ProcessLookupError):
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                    process.wait(timeout=1.0)
            self._record("process_stopped", pid=process.pid, returncode=process.returncode)
        for stream in self._streams:
            try:
                stream.close()
            except OSError:
                pass
        self._streams.clear()
        self._processes.clear()
        try:
            self.socket_path.unlink(missing_ok=True)
        except OSError as exc:
            self._record("socket_cleanup_failed", path=str(self.socket_path), error=str(exc))
        else:
            self._record("socket_removed", path=str(self.socket_path))
        self._write_lifecycle()

    def states_dict(self) -> dict[str, dict[str, Any]]:
        return {
            name: state.to_dict()
            for name, state in sorted(self.dependency_states.items())
        }

    def _start_ubusd(self) -> bool:
        daemon = self.rootfs_path / "sbin" / "ubusd"
        client = self.rootfs_path / "bin" / "ubus"
        stdout_path = self.candidate_dir / "ubusd.stdout.log"
        stderr_path = self.candidate_dir / "ubusd.stderr.log"
        self.socket_path.unlink(missing_ok=True)
        stdout_handle = stdout_path.open("w")
        stderr_handle = stderr_path.open("w")
        self._streams.extend((stdout_handle, stderr_handle))
        argv = [
            self.qemu_user_bin,
            "-L",
            str(self.rootfs_path),
            str(daemon),
            "-s",
            str(self.socket_path),
        ]
        try:
            process = subprocess.Popen(
                argv,
                stdout=stdout_handle,
                stderr=stderr_handle,
                text=True,
                start_new_session=True,
            )
        except OSError as exc:
            self.dependency_states["ubusd"] = DependencyState(
                "ubusd", "unsupported", (str(stderr_path),), f"ubusd_start_failed:{exc}"
            )
            self._record("process_start_failed", dependency="ubusd", error=str(exc), argv=argv)
            self.artifacts.extend((str(stdout_path), str(stderr_path)))
            return False
        self._processes.append(process)
        self.artifacts.extend((str(stdout_path), str(stderr_path)))
        self._record("process_started", dependency="ubusd", pid=process.pid, argv=argv)
        deadline = time.monotonic() + self.startup_timeout_seconds
        while time.monotonic() < deadline:
            if self.socket_path.is_socket():
                break
            if process.poll() is not None:
                break
            time.sleep(0.02)
        socket_ready = self.socket_path.is_socket()
        health_argv = [
            self.qemu_user_bin,
            "-L",
            str(self.rootfs_path),
            str(client),
            "-s",
            str(self.socket_path),
            "list",
        ]
        health: dict[str, Any] = {
            "schema_version": 1,
            "artifact_kind": "firmware_dependency_health",
            "dependency": "ubusd",
            "socket_path": str(self.socket_path),
            "socket_ready": socket_ready,
            "argv": health_argv,
            "authority": "process_setup_observation_not_vulnerability_evidence",
        }
        if socket_ready and process.poll() is None:
            try:
                completed = subprocess.run(
                    health_argv,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=self.startup_timeout_seconds,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                health.update({"status": "not_ready", "error": str(exc)})
            else:
                health.update(
                    {
                        "status": "observed_ready" if completed.returncode == 0 else "not_ready",
                        "returncode": completed.returncode,
                        "stdout": completed.stdout[-4000:],
                        "stderr": completed.stderr[-4000:],
                    }
                )
        else:
            health.update(
                {
                    "status": "not_ready",
                    "daemon_returncode": process.poll(),
                    "reason": "socket_not_ready" if not socket_ready else "daemon_exited",
                }
            )
        health_path = self.candidate_dir / "ubusd_health.json"
        _write_json(health_path, health)
        self.artifacts.append(str(health_path))
        if health.get("status") != "observed_ready":
            self.dependency_states["ubusd"] = DependencyState(
                "ubusd",
                "unsupported",
                (str(stdout_path), str(stderr_path), str(health_path)),
                "ubusd_protocol_health_check_failed",
            )
            self._record("health_failed", dependency="ubusd", health_path=str(health_path))
            return False
        self.dependency_states["ubusd"] = DependencyState(
            "ubusd",
            "observed_ready",
            (str(stdout_path), str(stderr_path), str(health_path)),
        )
        self._record("health_observed", dependency="ubusd", health_path=str(health_path))
        return True

    def _record(self, event: str, **details: Any) -> None:
        self._lifecycle.append(
            {
                "event": event,
                "monotonic_seconds": round(time.monotonic(), 6),
                **details,
            }
        )

    def _write_lifecycle(self) -> None:
        path = self.candidate_dir / "firmware_service_lifecycle.json"
        _write_json(
            path,
            {
                "schema_version": 1,
                "artifact_kind": "firmware_service_lifecycle",
                "dependencies": self.states_dict(),
                "events": self._lifecycle,
                "authority": "process_setup_observation_not_vulnerability_evidence",
            },
        )
        if str(path) not in self.artifacts:
            self.artifacts.append(str(path))


def prepare_firmware_service_sandbox(
    rootfs: Path,
    candidate_dir: Path,
    qemu_user_bin: str,
    dependencies: Sequence[str],
    *,
    startup_timeout_seconds: float = 2.0,
) -> FirmwareServiceSession:
    """Copy and prepare only explicitly declared firmware dependencies."""

    source = Path(rootfs).expanduser().resolve()
    output = Path(candidate_dir).expanduser().resolve() / "firmware_service_sandbox"
    copied_rootfs = output / "rootfs"
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, copied_rootfs, symlinks=True)
    normalized = tuple(dict.fromkeys(str(item) for item in dependencies if str(item)))
    socket_path = Path("/tmp") / f"vf{hashlib.sha256(str(output).encode()).hexdigest()[:12]}.s"
    states: dict[str, DependencyState] = {}
    preparation: dict[str, Any] = {
        "schema_version": 1,
        "artifact_kind": "firmware_service_sandbox",
        "source_rootfs": str(source),
        "rootfs_path": str(copied_rootfs),
        "dependencies": list(normalized),
        "socket_path": str(socket_path),
        "config_files": _config_inventory(copied_rootfs / "etc" / "config"),
        "patched_consumers": [],
        "account_setup": {},
        "authority": "process_setup_configuration_not_reach_or_vulnerability_evidence",
    }
    if "uci-config" in normalized:
        config_files = preparation["config_files"]
        if config_files:
            states["uci-config"] = DependencyState(
                "uci-config", "observed_ready", tuple(item["path"] for item in config_files)
            )
        else:
            states["uci-config"] = DependencyState(
                "uci-config", "unsupported", (), "uci_config_files_missing"
            )
    if "ubusd" in normalized:
        states["ubusd"] = _prepare_ubusd(
            copied_rootfs,
            socket_path,
            preparation,
        )
    for dependency in normalized:
        if dependency not in SUPPORTED_DEPENDENCIES:
            states[dependency] = DependencyState(
                dependency,
                "unsupported",
                (),
                f"unsupported_firmware_dependency:{dependency}",
            )
    manifest_path = output / "sandbox_manifest.json"
    preparation["dependency_states"] = {
        name: state.to_dict() for name, state in sorted(states.items())
    }
    _write_json(manifest_path, preparation)
    return FirmwareServiceSession(
        source_rootfs=source,
        rootfs_path=copied_rootfs,
        candidate_dir=output,
        qemu_user_bin=str(qemu_user_bin),
        dependencies=normalized,
        socket_path=socket_path,
        states=states,
        artifacts=(str(manifest_path),),
        startup_timeout_seconds=startup_timeout_seconds,
    )


def _prepare_ubusd(
    rootfs: Path,
    socket_path: Path,
    preparation: dict[str, Any],
) -> DependencyState:
    daemon = rootfs / "sbin" / "ubusd"
    client = rootfs / "bin" / "ubus"
    if not daemon.is_file() or not client.is_file():
        return DependencyState("ubusd", "unsupported", (), "ubusd_or_ubus_client_missing")
    replacement = str(socket_path).encode() + b"\0"
    if len(replacement) > len(DEFAULT_UBUS_SOCKET):
        return DependencyState("ubusd", "unsupported", (), "candidate_ubus_socket_path_too_long")
    patched: list[dict[str, Any]] = []
    for path in sorted(rootfs.rglob("libubus.so*")):
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        count = data.count(DEFAULT_UBUS_SOCKET)
        if not count:
            continue
        padded = replacement + (b"\0" * (len(DEFAULT_UBUS_SOCKET) - len(replacement)))
        updated = data.replace(DEFAULT_UBUS_SOCKET, padded)
        path.write_bytes(updated)
        patched.append(
            {
                "path": str(path),
                "replacement_count": count,
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "patched_sha256": hashlib.sha256(updated).hexdigest(),
            }
        )
    preparation["patched_consumers"] = patched
    if not patched:
        return DependencyState("ubusd", "unsupported", (), "libubus_default_socket_literal_missing")
    account_setup = _ensure_replay_accounts(rootfs / "etc" / "passwd", rootfs / "etc" / "group")
    preparation["account_setup"] = account_setup
    if account_setup.get("status") != "configured":
        return DependencyState(
            "ubusd", "unsupported", (), str(account_setup.get("blocker") or "replay_account_setup_failed")
        )
    return DependencyState(
        "ubusd",
        "prepared",
        tuple([str(daemon), str(client), *[item["path"] for item in patched]]),
    )


def _ensure_replay_accounts(passwd_path: Path, group_path: Path) -> dict[str, Any]:
    try:
        passwd = passwd_path.read_text(errors="ignore")
        group = group_path.read_text(errors="ignore")
    except OSError as exc:
        return {"status": "unsupported", "blocker": f"firmware_account_files_unreadable:{exc}"}
    uid = os.getuid()
    gid = os.getgid()
    passwd_added = not any(
        len(parts) > 2 and parts[2].isdigit() and int(parts[2]) == uid
        for line in passwd.splitlines()
        if (parts := line.split(":"))
    )
    group_added = not any(
        len(parts) > 2 and parts[2].isdigit() and int(parts[2]) == gid
        for line in group.splitlines()
        if (parts := line.split(":"))
    )
    if passwd_added:
        passwd_path.write_text(passwd.rstrip("\n") + f"\nreplay:x:{uid}:{gid}:replay:/tmp:/bin/false\n")
    if group_added:
        group_path.write_text(group.rstrip("\n") + f"\nreplay:x:{gid}:replay\n")
    return {
        "status": "configured",
        "uid": uid,
        "gid": gid,
        "passwd_entry_added": passwd_added,
        "group_entry_added": group_added,
    }


def _config_inventory(config_dir: Path) -> list[dict[str, Any]]:
    if not config_dir.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(config_dir.rglob("*")):
        if not path.is_file():
            continue
        rows.append(
            {
                "path": str(path),
                "relative_path": str(path.relative_to(config_dir)),
                "size": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    return rows


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n")
