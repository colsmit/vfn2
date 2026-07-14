import json
from pathlib import Path

from binary_agent.corpus_runner import load_corpus_manifest, run_corpus


MANIFEST = Path(__file__).parent / "fixtures" / "schema2_completeness" / "manifest.json"


def test_compiled_memory_completeness_pairs_are_vulnerable_only_and_exact(tmp_path: Path) -> None:
    summary = run_corpus(load_corpus_manifest(MANIFEST), tmp_path / "run", mode="lightweight")

    assert summary.accepted is True
    assert summary.totals["reports"] == 10
    assert summary.totals["fixed_reports"] == 0
    by_id = {lane.lane_id: lane for lane in summary.lanes}

    stride_vulnerable = _artifacts(by_id["rounded-stride-vulnerable"])
    stride_fixed = _artifacts(by_id["rounded-stride-fixed"])
    lifetime_vulnerable = _artifacts(by_id["reentrant-copy-vulnerable"])
    lifetime_fixed = _artifacts(by_id["reentrant-copy-fixed"])

    stride = next(
        row
        for row in stride_vulnerable["candidates"]
        if row["mechanism"] == "rounded_stride_miscalculation"
    )
    assert stride["vulnerability_type"] == "out_of_bounds_read"
    assert stride["operation"]["address"] != stride["location"]["address"]
    assert stride["type_facts"]["range_relation"] == "factor_applied_after_rounded_byte_conversion"
    assert set(stride["root_causes"]) == {"allocation_size_mismatch", "integer_truncation"}
    assert not [row for row in stride_fixed["candidates"] if row["mechanism"] == stride["mechanism"]]

    lifetime = next(
        row
        for row in lifetime_vulnerable["candidates"]
        if row["mechanism"] == "reentrant_copy_invalidation"
    )
    assert lifetime["vulnerability_type"] == "use_after_free"
    assert lifetime["type_facts"]["guard_relation"]["inverted"] is True
    assert lifetime["type_facts"]["callee_summary"]["may_allocate"] is True
    assert lifetime["type_facts"]["resource_lineage"]["same_resource"] is True
    assert not [row for row in lifetime_fixed["candidates"] if row["mechanism"] == lifetime["mechanism"]]

    report_mechanisms = {
        row["mechanism"]
        for artifacts in (stride_vulnerable, lifetime_vulnerable)
        for row in artifacts["reports"]
    }
    assert report_mechanisms == {"rounded_stride_miscalculation", "reentrant_copy_invalidation"}
    assert stride_fixed["reports"] == []
    assert lifetime_fixed["reports"] == []

    for vulnerability_type, lane_id in {
        "uninitialized_memory_use": "uninitialized-use-vulnerable",
        "overlapping_memory_copy": "overlapping-copy-vulnerable",
        "mismatched_deallocator": "mismatched-deallocator-vulnerable",
        "double_close": "double-close-vulnerable",
        "use_after_close": "use-after-close-vulnerable",
    }.items():
        artifacts = _artifacts(by_id[lane_id])
        candidate = next(row for row in artifacts["candidates"] if row["vulnerability_type"] == vulnerability_type)
        proof = next(row for row in artifacts["proofs"] if row["candidate_id"] == candidate["candidate_id"])
        assert proof["status"] == "proven"
        assert proof["scope"] == "process_entrypoint"
        assert proof["exact_operation_reached"] is True
        assert any(row["candidate_id"] == candidate["candidate_id"] for row in artifacts["reports"])
        fixed = _artifacts(by_id[lane_id.replace("vulnerable", "fixed")])
        assert fixed["reports"] == []

    for vulnerability_type, lane_id, effect_kind in (
        ("argument_injection", "argument-injection-vulnerable", "process_argv"),
        ("code_injection", "code-injection-vulnerable", "code_evaluation"),
        ("server_side_request_forgery", "ssrf-vulnerable", "outbound_connection"),
    ):
        artifacts = _artifacts(by_id[lane_id])
        candidate = next(row for row in artifacts["candidates"] if row["vulnerability_type"] == vulnerability_type)
        proof = next(row for row in artifacts["proofs"] if row["candidate_id"] == candidate["candidate_id"])
        assert proof["status"] == "proven"
        assert proof["scope"] == "process_entrypoint"
        assert proof["effect_observation"] == {"kind": effect_kind, "status": "observed"}
        assert any(row["candidate_id"] == candidate["candidate_id"] for row in artifacts["reports"])
        fixed = _artifacts(by_id[lane_id.replace("vulnerable", "fixed")])
        assert fixed["reports"] == []

    proof_by_id = {
        row["candidate_id"]: row
        for artifacts in (stride_vulnerable, lifetime_vulnerable)
        for row in artifacts["proofs"]
    }
    for report in (*stride_vulnerable["reports"], *lifetime_vulnerable["reports"]):
        proof = proof_by_id[report["candidate_id"]]
        assert proof["status"] == "proven"
        assert proof["scope"] == "process_entrypoint"
        assert proof["exact_operation_reached"] is True


def test_ungrounded_generic_read_candidates_are_removed_before_fixture_proof(tmp_path: Path) -> None:
    summary = run_corpus(load_corpus_manifest(MANIFEST), tmp_path / "run", mode="lightweight")
    lane = next(item for item in summary.lanes if item.lane_id == "rounded-stride-vulnerable")
    artifacts = _artifacts(lane)
    assert artifacts["candidates"]
    assert all(row["mechanism"] == "rounded_stride_miscalculation" for row in artifacts["candidates"])


def _artifacts(lane) -> dict:
    root = Path(lane.run_dir)
    return {
        "candidates": json.loads((root / "discovery" / "candidates.json").read_text())["candidates"],
        "proofs": json.loads((root / "proof" / "proof_results.json").read_text())["proof_results"],
        "reports": json.loads((root / "report" / "vulnerabilities.json").read_text())["vulnerabilities"],
    }
