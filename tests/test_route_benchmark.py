from __future__ import annotations

import json
from pathlib import Path

from binary_agent.pipeline import CandidateState, write_candidate_states
from binary_agent.route_benchmark import freeze_route_benchmark, verify_route_benchmark
from binary_agent.taxonomy import VULNERABILITY_SPECS


def _state(candidate_id: str, binary: Path, export: Path, *, high: bool) -> CandidateState:
    spec = VULNERABILITY_SPECS["uninitialized_memory_use"]
    facts = {"definedness": "undefined", "prior_store": False, "undefined_byte_ranges": [[0, 1]]}
    if high:
        facts.update({"entrypoint_derivation": {"status": "derived"}, "process_input": {"input_model": "argv"}})
    return CandidateState(
        candidate_id=candidate_id,
        backend=spec.backend,
        vulnerability_type="uninitialized_memory_use",
        mechanism=spec.mechanism,
        status="proof_ready",
        target={"path": str(binary), "export_dir": str(export)},
        location={"function_name": "main", "address": "0x1000"},
        source={"kind": "definedness"},
        sink={"name": "pcode_load", "operation_address": "0x1010"},
        operation={"name": "pcode_load", "address": "0x1010"},
        affected_object={"identity": f"stack:{candidate_id}"},
        type_facts=facts,
        proof_obligations=[],
        blockers=[],
    )


def test_route_benchmark_freezes_strata_and_detects_tampering(tmp_path: Path) -> None:
    source = tmp_path / "source-run"
    binary = source / "rootfs" / "bin" / "fixture"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"\x7fELFfixture")
    export = source / "export"
    export.mkdir()
    (export / "manifest.jsonl").write_text("{}\n")
    states = []
    evidence = source / "evidence"
    evidence.mkdir()
    for index in range(3):
        state = _state(f"z-high-{index}", binary, export, high=True)
        states.append(state)
        (evidence / f"{state.candidate_id}.json").write_text(json.dumps(state.to_dict()))
    for index in range(9):
        state = _state(f"a-low-{index}", binary, export, high=False)
        states.append(state)
        (evidence / f"{state.candidate_id}.json").write_text(json.dumps(state.to_dict()))
    write_candidate_states(states, source / "promotion" / "candidate_states.json")
    frozen = freeze_route_benchmark(source, tmp_path / "corpora", repo_root=Path.cwd())
    manifest = Path(frozen.corpus_dir) / "frozen_manifest.json"
    verified = verify_route_benchmark(manifest)
    assert verified["verified"] is True
    assert verified["higher_evidence_score_count"] == 3
    assert verified["lower_evidence_score_count"] == 9
    first_state = Path(frozen.corpus_dir) / frozen.cases[0]["state_path"]
    first_state.write_text(first_state.read_text() + "tamper")
    assert verify_route_benchmark(manifest)["verified"] is False
