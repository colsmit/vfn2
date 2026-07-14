from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from binary_agent.firmware_services import (
    DEFAULT_UBUS_SOCKET,
    prepare_firmware_service_sandbox,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fake_qemu(path: Path, *, health_ok: bool = True) -> Path:
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import os, signal, socket, sys, time\n"
        "args = sys.argv[1:]\n"
        "binary = args[2] if len(args) > 2 and args[0] == '-L' else args[0]\n"
        "rest = args[3:] if len(args) > 2 and args[0] == '-L' else args[1:]\n"
        "name = os.path.basename(binary)\n"
        "if name == 'ubusd':\n"
        "    endpoint = rest[rest.index('-s') + 1]\n"
        "    try: os.unlink(endpoint)\n"
        "    except FileNotFoundError: pass\n"
        "    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
        "    server.bind(endpoint); server.listen(4); server.settimeout(0.1)\n"
        "    running = [True]\n"
        "    signal.signal(signal.SIGTERM, lambda *_: running.__setitem__(0, False))\n"
        "    while running[0]:\n"
        "        try:\n"
        "            client, _ = server.accept(); client.close()\n"
        "        except socket.timeout: pass\n"
        "    server.close(); sys.exit(0)\n"
        "if name == 'ubus':\n"
        "    endpoint = rest[rest.index('-s') + 1]\n"
        "    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
        "    try: client.connect(endpoint)\n"
        "    except OSError: sys.exit(2)\n"
        "    finally: client.close()\n"
        f"    sys.exit({0 if health_ok else 3})\n"
        "print('target-ran')\n"
    )
    path.chmod(0o755)
    return path


def _rootfs(path: Path) -> Path:
    for directory in ("bin", "sbin", "lib", "etc/config", "usr/share"):
        (path / directory).mkdir(parents=True, exist_ok=True)
    for executable in (path / "sbin/ubusd", path / "bin/ubus"):
        executable.write_text("fixture\n")
        executable.chmod(0o755)
    (path / "lib/libubus.so.fixture").write_bytes(
        b"prefix\0" + DEFAULT_UBUS_SOCKET + b"suffix\0"
    )
    (path / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/false\n")
    (path / "etc/group").write_text("root:x:0:\n")
    (path / "etc/config/network").write_text("config interface 'loopback'\n")
    return path


def test_firmware_service_sandbox_observes_health_and_preserves_source(tmp_path: Path) -> None:
    rootfs = _rootfs(tmp_path / "source-rootfs")
    qemu = _fake_qemu(tmp_path / "fake-qemu")
    source_library = rootfs / "lib/libubus.so.fixture"
    before = _sha256(source_library)
    session = prepare_firmware_service_sandbox(
        rootfs,
        tmp_path / "candidate",
        str(qemu),
        ("ubusd", "uci-config"),
        startup_timeout_seconds=1.0,
    )

    assert _sha256(source_library) == before
    copied_library = session.rootfs_path / "lib/libubus.so.fixture"
    assert _sha256(copied_library) != before
    assert DEFAULT_UBUS_SOCKET not in copied_library.read_bytes()
    assert str(session.socket_path).encode() in copied_library.read_bytes()
    assert session.start() is True
    assert session.ready is True
    assert session.states_dict()["ubusd"]["status"] == "observed_ready"
    assert session.states_dict()["uci-config"]["status"] == "observed_ready"
    assert session.socket_path.is_socket()

    session.stop()
    session.stop()
    assert not session.socket_path.exists()
    lifecycle = json.loads(
        (session.candidate_dir / "firmware_service_lifecycle.json").read_text()
    )
    assert any(item["event"] == "health_observed" for item in lifecycle["events"])
    assert any(item["event"] == "process_stopped" for item in lifecycle["events"])
    manifest = json.loads((session.candidate_dir / "sandbox_manifest.json").read_text())
    assert manifest["authority"].endswith("not_reach_or_vulnerability_evidence")
    assert manifest["account_setup"]["uid"] == os.getuid()
    assert manifest["config_files"][0]["relative_path"] == "network"


def test_firmware_service_sandbox_rejects_socket_without_healthy_protocol(tmp_path: Path) -> None:
    rootfs = _rootfs(tmp_path / "source-rootfs")
    qemu = _fake_qemu(tmp_path / "fake-qemu", health_ok=False)
    session = prepare_firmware_service_sandbox(
        rootfs,
        tmp_path / "candidate",
        str(qemu),
        ("ubusd",),
        startup_timeout_seconds=1.0,
    )
    try:
        assert session.start() is False
        assert session.states_dict()["ubusd"]["status"] == "unsupported"
        health = json.loads((session.candidate_dir / "ubusd_health.json").read_text())
        assert health["socket_ready"] is True
        assert health["status"] == "not_ready"
    finally:
        session.stop()
    assert not session.socket_path.exists()


def test_firmware_service_sandbox_fails_closed_for_unknown_dependency(tmp_path: Path) -> None:
    session = prepare_firmware_service_sandbox(
        _rootfs(tmp_path / "source-rootfs"),
        tmp_path / "candidate",
        str(_fake_qemu(tmp_path / "fake-qemu")),
        ("mystery-daemon",),
    )
    assert session.start() is False
    assert session.blocker == "unsupported_firmware_dependency:mystery-daemon"
    assert session.states_dict()["mystery-daemon"]["status"] == "unsupported"
    session.stop()


def test_real_openwrt_ubus_health_and_target_connection(tmp_path: Path) -> None:
    rootfs = Path(
        ".ai/runs/firmware-campaigns/20260712-232226/images/"
        "openwrt-24.10.4-x86-64-rootfs/rootfs"
    ).resolve()
    qemu = shutil.which("qemu-x86_64")
    if not rootfs.is_dir() or not qemu:
        return
    session = prepare_firmware_service_sandbox(
        rootfs,
        tmp_path / "real-openwrt",
        qemu,
        ("ubusd", "uci-config"),
        startup_timeout_seconds=2.0,
    )
    try:
        assert session.start() is True
        argv = [
            qemu,
            "-L",
            str(session.rootfs_path),
            str(session.rootfs_path / "sbin/netifd"),
            "-d",
            "15",
        ]
        try:
            completed = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=0.5,
                check=False,
            )
            stderr = completed.stderr
        except subprocess.TimeoutExpired as exc:
            stderr = str(exc.stderr or "")
        assert "Failed to connect to ubus" not in stderr
    finally:
        session.stop()
