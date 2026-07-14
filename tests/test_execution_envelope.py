from __future__ import annotations

import subprocess
from pathlib import Path

from binary_agent.execution_envelope import (
    discover_execution_envelope,
    route_capability,
)


def _compile(source: Path, binary: Path) -> None:
    source.write_text("int main(void) { return 0; }\n")
    subprocess.run(["gcc", "-o", str(binary), str(source)], check=True)


def test_execution_envelope_observes_elf_and_reuses_cache(tmp_path: Path) -> None:
    binary = tmp_path / "demo"
    _compile(tmp_path / "demo.c", binary)
    cache = tmp_path / "cache"
    first = discover_execution_envelope(binary, cache_dir=cache)
    second = discover_execution_envelope(binary, cache_dir=cache)
    assert first == second
    assert first.binary_sha256
    assert "X86-64" in first.elf_machine
    assert first.interpreter.startswith("/")
    assert route_capability(first, "native_trace").status == "available"
    assert len(list(cache.glob("*.json"))) == 1


def test_execution_envelope_cache_invalidates_after_binary_mutation(tmp_path: Path) -> None:
    binary = tmp_path / "demo"
    source = tmp_path / "demo.c"
    _compile(source, binary)
    cache = tmp_path / "cache"
    first = discover_execution_envelope(binary, cache_dir=cache)
    source.write_text("int main(void) { return 1; }\n")
    subprocess.run(["gcc", "-o", str(binary), str(source)], check=True)
    second = discover_execution_envelope(binary, cache_dir=cache)
    assert first.binary_sha256 != second.binary_sha256
    assert first.cache_key != second.cache_key
    assert len(list(cache.glob("*.json"))) == 2


def test_openwrt_envelope_rejects_native_and_selects_x86_qemu() -> None:
    binary = Path(
        ".ai/runs/research-corpora/openwrt-route-contention-v1/"
        "binaries/09b00dbd7d68e77057ccb114caa10b6f8b63ff6efa935acd2f0a7b67aee73648/rpcd"
    )
    rootfs = Path(
        ".ai/runs/firmware-campaigns/20260712-232226/images/"
        "openwrt-24.10.4-x86-64-rootfs/rootfs"
    )
    if not binary.is_file() or not rootfs.is_dir():
        return
    envelope = discover_execution_envelope(binary, rootfs_path=rootfs)
    native = route_capability(envelope, "native_trace")
    qemu = route_capability(envelope, "qemu_user")
    assert native.status == "unsupported"
    assert "program_interpreter_missing" in native.reason
    assert qemu.status == "available"
    assert envelope.qemu_user_bin.endswith("qemu-x86_64")
    assert envelope.rootfs_interpreter_path.endswith("lib/ld-musl-x86_64.so.1")
    second_binary = Path(
        ".ai/runs/research-corpora/openwrt-route-contention-v1/"
        "binaries/35fa1da246502c24ebcd5c39b1f41d6e183523497dc7c8291e1079eb689ccac4/netifd"
    )
    if second_binary.is_file():
        second = discover_execution_envelope(second_binary, rootfs_path=rootfs)
        assert second.rootfs_identity == envelope.rootfs_identity
        assert route_capability(second, "qemu_user").setup_key == qemu.setup_key
