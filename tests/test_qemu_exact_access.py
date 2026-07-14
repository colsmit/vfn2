import json
import shutil
import subprocess
from pathlib import Path

import pytest

from binary_agent.replay import ReplayRequest, run_replay_request


@pytest.mark.skipif(
    not shutil.which("qemu-x86_64") or not shutil.which("cc"),
    reason="qemu-x86_64 and a C compiler are required",
)
def test_qemu_plugin_observes_exact_memory_read_without_claiming_bug(tmp_path: Path) -> None:
    source = tmp_path / "exact.c"
    binary = tmp_path / "exact"
    source.write_text(
        r'''
volatile int value = 7;
int main(void) {
    int result;
    __asm__ volatile (
        ".global exact_access_operation\n"
        "exact_access_operation:\n"
        "movl value(%%rip), %0\n"
        : "=r" (result) : : "memory");
    return result == 7 ? 0 : 1;
}
'''
    )
    subprocess.run(["cc", "-O0", "-no-pie", str(source), "-o", str(binary)], check=True)
    symbols = subprocess.check_output(["nm", str(binary)], text=True)
    address = next(int(line.split()[0], 16) for line in symbols.splitlines() if line.endswith(" exact_access_operation"))
    request = ReplayRequest(
        candidate_id="exact-access",
        mode="qemu_user",
        setup={
            "binary_path": str(binary),
            "rootfs_path": "/",
            "qemu_user_bin": shutil.which("qemu-x86_64"),
            "timeout_seconds": 5,
            "qemu_exact_access": True,
        },
        input={"input_model": "argv", "argv": []},
        expected_result={"target_address": hex(address), "vulnerability_type": "uninitialized_memory_use"},
    )
    result = run_replay_request(request, tmp_path / "replay")
    observation_path = next(Path(path) for path in result.artifacts if path.endswith("qemu_exact_access_observation.json"))
    observation = json.loads(observation_path.read_text())
    assert observation["status"] == "observed"
    assert observation["instruction_address"] == hex(address)
    assert observation["access_kind"] == "read"
    assert observation["bug_observed"] is False
    assert result.bug_observed is False
