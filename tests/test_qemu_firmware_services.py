from __future__ import annotations

import json
from pathlib import Path

from binary_agent.firmware_services import DEFAULT_UBUS_SOCKET
from binary_agent.replay.models import ReplayRequest
from binary_agent.replay.runners import run_replay_request

from tests.test_firmware_services import _fake_qemu, _rootfs


def test_qemu_recipe_starts_declared_service_and_keeps_setup_non_reporting(
    tmp_path: Path,
) -> None:
    rootfs = _rootfs(tmp_path / "source-rootfs")
    assert DEFAULT_UBUS_SOCKET in (rootfs / "lib/libubus.so.fixture").read_bytes()
    target = tmp_path / "target"
    target.write_text("fixture\n")
    target.chmod(0o755)
    request = ReplayRequest(
        candidate_id="firmware-service",
        mode="qemu_user",
        setup={
            "binary_path": str(target),
            "rootfs_path": str(rootfs),
            "qemu_user_bin": str(_fake_qemu(tmp_path / "fake-qemu")),
            "timeout_seconds": 1.0,
            "process_recipes": [
                {
                    "recipe_id": "dependency-recipe",
                    "source": "test",
                    "confidence": 1.0,
                    "input_model": "argv",
                    "argv": [],
                    "required_daemons": ["ubusd", "uci-config"],
                }
            ],
        },
        input={"input_model": "argv", "argv": []},
        expected_result={"candidate_id": "firmware-service"},
    )
    result = run_replay_request(request, tmp_path / "replay")

    attempts = result.control_result["process_recipe_attempts"]
    assert attempts[0]["dependency_status"] == "observed_ready"
    assert attempts[0]["dependency_states"]["ubusd"]["status"] == "observed_ready"
    setup = result.control_result["firmware_service_setup"]
    assert setup["authority"] == "process_setup_observation_not_vulnerability_evidence"
    assert setup["status"] == "observed_ready"
    assert result.bug_observed is False
    assert result.sink_reached is False
    assert any(path.endswith("ubusd_health.json") for path in result.artifacts)
    summary = json.loads(
        next(Path(path) for path in result.artifacts if path.endswith("process_recipe_attempts.json")).read_text()
    )
    assert summary["attempts"][0]["dependency_status"] == "observed_ready"
