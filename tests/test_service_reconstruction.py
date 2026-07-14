from pathlib import Path

from binary_agent.pipeline import CandidateState
from binary_agent.service_reconstruction import reconstruct_process_recipes
from binary_agent.taxonomy import VULNERABILITY_SPECS


def _state(binary: Path, rootfs: Path) -> CandidateState:
    spec = VULNERABILITY_SPECS["uninitialized_memory_use"]
    return CandidateState(
        candidate_id="recipe",
        backend=spec.backend,
        vulnerability_type="uninitialized_memory_use",
        mechanism=spec.mechanism,
        status="proof_ready",
        target={"path": str(binary), "component": "sbin/netifd", "firmware_target": str(rootfs)},
        location={"function_name": "main", "address": "0x1000"},
        source={"kind": "argv"},
        sink={"name": "read", "operation_address": "0x1010"},
        operation={"name": "read", "address": "0x1010"},
        affected_object={"identity": "stack:value"},
        type_facts={"process_input": {"input_model": "argv", "argv_values": ["program", "seed.json"]}},
        proof_obligations=[],
        blockers=[],
    )


def test_service_reconstruction_combines_candidate_and_init_evidence(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "etc/init.d").mkdir(parents=True)
    (rootfs / "etc/init.d/network").write_text("procd_set_param command /sbin/netifd -d 15\n")
    binary = tmp_path / "netifd"
    binary.write_bytes(b"ELF fake ubus_connect /var/run/ubus.sock")
    recipes = reconstruct_process_recipes(_state(binary, rootfs), binary, rootfs_path=rootfs)
    assert recipes.recipes[0].source == "candidate-process-facts"
    assert any(item.source == "firmware-init-script" and item.argv == ("-d", "15") for item in recipes.recipes)
    assert any("ubusd" in item.required_daemons for item in recipes.recipes)
    assert all(
        "required_daemons_are_not_automatically_started" not in item.limitations
        for item in recipes.recipes
    )
    assert all(item.recipe_id for item in recipes.recipes)
