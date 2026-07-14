import json
from dataclasses import replace
from pathlib import Path

import pytest

from binary_agent.corpus_runner import (
    CorpusLane,
    CorpusLaneResult,
    _full_toolchain_command,
    build_pair_differential,
    load_corpus_manifest,
    run_corpus,
)
from binary_agent.discovery import write_discovery_candidates
from binary_agent.pipeline import CandidateState, CandidateStatus, ProofResult, write_proof_results


FIXTURE_MANIFEST = Path(__file__).parent / "fixtures" / "schema2_corpus" / "manifest.json"


def test_lightweight_compiled_corpus_reaches_semantic_and_static_report_gates(tmp_path: Path) -> None:
    summary = run_corpus(load_corpus_manifest(FIXTURE_MANIFEST), tmp_path / "run", mode="lightweight")

    assert summary.accepted is True
    assert summary.totals["reports"] == 2
    assert summary.totals["proven"] == 2
    assert summary.totals["fixed_reports"] == 0
    by_id = {lane.lane_id: lane for lane in summary.lanes}
    semantic = by_id["semantic-command-vulnerable"]
    static = by_id["static-token-vulnerable"]
    semantic_proof = _json(Path(semantic.run_dir) / "proof" / "proof_results.json")["proof_results"][0]
    static_proof = _json(Path(static.run_dir) / "proof" / "proof_results.json")["proof_results"][0]
    assert semantic_proof["scope"] == "process_entrypoint"
    assert semantic_proof["effect_observation"] == {"kind": "command_effect", "status": "observed"}
    assert semantic_proof["concrete_input"]["argv"] == ["printf SCHEMA2_SEMANTIC_EFFECT"]
    assert static_proof["scope"] == "static"
    assert static_proof["static_evidence"]["exact"] is True
    assert static_proof["static_evidence"]["literal_fingerprint"]
    assert "AbCDef_1234567890-ghIJ" not in json.dumps(static_proof)
    assert static_proof["native_replay"] == {}


def test_manifest_validation_rejects_v1_unknown_types_and_broken_pairs(tmp_path: Path) -> None:
    source = tmp_path / "main.c"
    source.write_text("int main(void) { return 0; }\n")
    base = {
        "schema_version": 2,
        "corpus_id": "bad",
        "lanes": [
            {
                "id": "v",
                "role": "vulnerable",
                "comparison_group": "pair",
                "source": "main.c",
                "vulnerability_types": ["command_injection"],
            },
            {
                "id": "f",
                "role": "fixed",
                "comparison_group": "pair",
                "source": "main.c",
                "vulnerability_types": ["command_injection"],
            },
        ],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({**base, "schema_version": 1}))
    with pytest.raises(ValueError, match="schema v2"):
        load_corpus_manifest(path)

    unknown = json.loads(json.dumps(base))
    unknown["lanes"][0]["vulnerability_types"] = ["not_a_vulnerability"]
    path.write_text(json.dumps(unknown))
    with pytest.raises(ValueError, match="Unknown vulnerability type"):
        load_corpus_manifest(path)

    broken = json.loads(json.dumps(base))
    broken["lanes"][1]["role"] = "vulnerable"
    path.write_text(json.dumps(broken))
    with pytest.raises(ValueError, match="exactly one vulnerable and one fixed"):
        load_corpus_manifest(path)

    excessive_steps = json.loads(json.dumps(base))
    excessive_steps["proof"] = {"dynamic_max_steps": 100001}
    path.write_text(json.dumps(excessive_steps))
    with pytest.raises(ValueError, match="between 1 and 100000"):
        load_corpus_manifest(path)


def test_runner_rejects_unsafe_output_reuse(tmp_path: Path) -> None:
    manifest = load_corpus_manifest(FIXTURE_MANIFEST)
    output = tmp_path / "occupied"
    output.mkdir()
    (output / "owned.txt").write_text("do not replace")
    with pytest.raises(FileExistsError, match="not empty"):
        run_corpus(manifest, output, mode="lightweight")


def test_full_command_uses_shared_cache_selected_types_and_process_input(tmp_path: Path) -> None:
    loaded = load_corpus_manifest(FIXTURE_MANIFEST)
    lane = _lane("v", "vulnerable")
    manifest = replace(loaded, cache_dir=tmp_path / "persistent-cache")
    process_input = tmp_path / "process.json"

    command = _full_toolchain_command(
        lane,
        tmp_path / "binary",
        tmp_path / "lane",
        tmp_path / "corpus",
        manifest,
        process_input,
    )

    assert command[1:3] == ["-m", "binary_agent.cli.toolchain"]
    assert command[command.index("--cache-dir") + 1] == str(tmp_path / "persistent-cache")
    assert command[command.index("--vulnerability-types") + 1] == "use_after_free"
    assert command[command.index("--process-input-json") + 1] == str(process_input)


def test_manifest_selects_cpp_compiler_for_real_allocator_family_pair() -> None:
    manifest = load_corpus_manifest(
        Path(__file__).parent / "fixtures" / "schema2_ghidra_completeness" / "manifest.json"
    )
    vulnerable = next(item for item in manifest.lanes if item.lane_id == "mismatched-deallocator-vulnerable")
    assert vulnerable.compiler == "c++"


def test_pair_differential_suppresses_only_nonexact_shared_symbolic_candidates(tmp_path: Path) -> None:
    vulnerable = _lane("v", "vulnerable")
    fixed = _lane("f", "fixed")
    v_dir = tmp_path / "v"
    f_dir = tmp_path / "f"
    symbolic_v = _candidate("v-symbolic", blockers=["allocation_site_unknown"])
    symbolic_f = _candidate("f-symbolic", blockers=["allocation_site_unknown"])
    exact_v = _candidate("v-exact", operation_address="0x1010")
    exact_f = _candidate("f-exact", operation_address="0x2020")
    for directory, rows in ((v_dir, [symbolic_v, exact_v]), (f_dir, [symbolic_f, exact_f])):
        write_discovery_candidates(rows, directory / "discovery")
    write_proof_results(
        [
            _proof("v-symbolic", exact=False, status="inconclusive", blocker="allocation_site_unknown"),
            _proof("v-exact", exact=True, status="proven"),
        ],
        v_dir / "proof" / "proof_results.json",
    )
    write_proof_results(
        [
            _proof("f-symbolic", exact=False, status="inconclusive", blocker="allocation_site_unknown"),
            _proof("f-exact", exact=True, status="proven"),
        ],
        f_dir / "proof" / "proof_results.json",
    )
    results = [_lane_result(vulnerable, v_dir, 2), _lane_result(fixed, f_dir, 2)]

    payload = build_pair_differential([vulnerable, fixed], results)

    assert payload["totals"]["raw_candidate_count"] == 4
    assert payload["totals"]["shared_symbolic_suppressed_count"] == 1
    assert payload["totals"]["public_review_count"] == 1
    suppressed = payload["groups"][0]["shared_symbolic_suppressed"]
    assert [row["candidate_id"] for row in suppressed] == ["v-symbolic"]
    assert [row["candidate_id"] for row in payload["groups"][0]["public_review"]] == ["v-exact"]


def _lane(lane_id: str, role: str) -> CorpusLane:
    return CorpusLane(
        lane_id=lane_id,
        role=role,
        comparison_group="pair",
        expected_positives=(),
        expected_negatives=(),
        allowed_blocked=(),
        vulnerability_types=("use_after_free",),
        binary=None,
        source=Path(__file__),
        process_input=None,
        process={},
        requires_ghidra=False,
    )


def _candidate(candidate_id: str, *, blockers: list[str] | None = None, operation_address: str = "") -> CandidateState:
    return CandidateState(
        candidate_id=candidate_id,
        backend="memory_lifetime",
        vulnerability_type="use_after_free",
        mechanism="stale_resource_use",
        status=CandidateStatus.CANDIDATE.value,
        target={"binary": candidate_id},
        location={"function_name": "same_function"},
        source={},
        sink={},
        operation={"name": "pcode_load", "kind": "load", "address": operation_address},
        affected_object={"kind": "heap", "label": "ptr"},
        type_facts={},
        proof_obligations=[],
        blockers=list(blockers or []),
    )


def _proof(candidate_id: str, *, exact: bool, status: str, blocker: str = "") -> ProofResult:
    return ProofResult(
        backend="memory_lifetime",
        candidate_id=candidate_id,
        status=status,
        scope="function_harness",
        exact_operation_reached=exact,
        lifetime_violation={"same_resource": True, "ordered_events": True} if status == "proven" else {},
        blocker=blocker,
    )


def _lane_result(lane: CorpusLane, run_dir: Path, count: int) -> CorpusLaneResult:
    return CorpusLaneResult(
        lane_id=lane.lane_id,
        role=lane.role,
        comparison_group=lane.comparison_group,
        status="completed",
        run_dir=str(run_dir),
        binary_path="",
        binary_sha256="",
        candidate_count=count,
        candidate_types={"use_after_free": count},
        proof_count=count,
        proof_outcomes={},
        report_count=0,
        report_types={},
    )


def _json(path: Path) -> dict:
    return json.loads(path.read_text())
