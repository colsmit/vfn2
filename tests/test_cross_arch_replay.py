import json
import shutil
from pathlib import Path

import pytest

from binary_agent.analysis.cross_arch_replay import (
    build_freestanding_fixture,
    replay_qemu_exact_memory,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "cross_arch_memory"
CASES = json.loads((FIXTURE_ROOT / "manifest.json").read_text())["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_arm_qemu_exact_operation_vulnerable_fixed_pairs(tmp_path: Path, case: dict) -> None:
    architecture = case["architecture"]
    required = ["qemu-aarch64", "clang"] if architecture == "aarch64" else ["qemu-arm", "arm-none-eabi-gcc"]
    if not all(shutil.which(item) for item in required):
        pytest.skip("cross-architecture assembler and QEMU are required")

    build = build_freestanding_fixture(
        FIXTURE_ROOT / case["source"],
        tmp_path / case["id"],
        architecture,
    )
    assert build["status"] == "built", build
    symbols = build["symbols"]
    replay = replay_qemu_exact_memory(
        Path(build["binary"]),
        architecture,
        exact_address=symbols["exact_memory_operation"],
        object_address=symbols["tracked_object"],
        object_size=case["object_size"],
    )
    assert replay["status"] == "reached", replay
    assert replay["architecture"] == architecture
    assert replay["memory_access"]["out_of_bounds"] is case["expected_out_of_bounds"]
    assert replay["memory_access"]["access_range"][0] == (
        replay["memory_access"]["object_range"][1]
        if case["expected_out_of_bounds"]
        else replay["memory_access"]["object_range"][1] - 1
    )
