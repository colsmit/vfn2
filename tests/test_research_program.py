import json
import shutil
import tarfile
from pathlib import Path

import pytest

from binary_agent.data.proof_specs import (
    attach_compiled_proof_plan,
    compile_proof_plan,
    load_proof_specs,
)
from binary_agent.firmware_campaign import _extract_archive, _redact_sensitive, _tree_sha256
from binary_agent.execution_envelope import RouteCapability
from binary_agent.pipeline import CandidateState
from binary_agent.research_corpus import freeze_research_corpus, verify_frozen_corpus
from binary_agent.research_baselines import run_research_baselines
from binary_agent.research_metrics import CaseOutcome, compute_research_metrics
from binary_agent.scheduling import AttemptOutcome, ProofBudget, load_proof_schedule, schedule_proofs
from binary_agent.taxonomy import VULNERABILITY_SPECS
from scripts.decompile import headless_project_location


def _state(candidate_id: str, vulnerability_type: str = "stack_overflow", **overrides) -> CandidateState:
    spec = VULNERABILITY_SPECS[vulnerability_type]
    values = {
        "candidate_id": candidate_id,
        "backend": spec.backend,
        "vulnerability_type": vulnerability_type,
        "mechanism": spec.mechanism,
        "status": "proof_ready",
        "target": {"binary": "fixture"},
        "location": {"function_name": "main", "address": "0x1000"},
        "source": {"kind": "argv"},
        "sink": {"name": "memcpy", "operation_address": "0x1010"},
        "operation": {"name": "memcpy", "address": "0x1010"},
        "affected_object": {"identity": "stack:buf", "capacity_bytes": 8},
        "type_facts": {
            "source_to_sink_trace": {"status": "complete"},
            "entrypoint_derivation": {"status": "derived"},
            "process_input": {"input_model": "argv"},
        },
        "proof_obligations": [],
        "blockers": [],
    }
    values.update(overrides)
    return CandidateState(**values)


def test_proof_specs_cover_taxonomy_and_cannot_declare_observations(tmp_path: Path) -> None:
    specs = load_proof_specs()
    assert {item.name for item in specs.classes} == set(VULNERABILITY_SPECS)
    plan = compile_proof_plan(_state("one"), specs)
    assert plan.routes
    assert "exact_operation" in plan.requirements

    payload = json.loads(Path(specs.path).read_text())
    payload["classes"]["stack_overflow"]["status"] = "proven"
    malicious = tmp_path / "proof_specs.json"
    malicious.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="requirements, not observations"):
        load_proof_specs(malicious)


def test_compiled_plan_preserves_candidate_authority_fields() -> None:
    state = _state("stable", blockers=["concrete_replay_required"])
    updated = attach_compiled_proof_plan(state)
    assert updated.candidate_id == state.candidate_id
    assert updated.status == state.status
    assert updated.blockers == state.blockers
    assert updated.proof_obligations == state.proof_obligations
    assert updated.metadata["compiled_proof_plan"]["authority"] == "requirements_only"


def test_adaptive_scheduler_is_deterministic_bounded_and_uses_feedback() -> None:
    states = [_state("b"), _state("a"), _state("blocked", blockers=["unsupported_abi"])]
    plans = {item.candidate_id: compile_proof_plan(item) for item in states}
    budget = ProofBudget(max_candidates=2, max_wall_seconds=30, max_estimated_cpu_seconds=30)
    first = schedule_proofs(states, plans, budget)
    second = schedule_proofs(list(reversed(states)), plans, budget)
    assert first.to_dict() == second.to_dict()
    assert [item.candidate_id for item in first.attempts] == ["a", "b"]
    assert first.estimated_cpu_seconds <= 30

    history = [
        AttemptOutcome("old-1", "native_trace", "unsupported"),
        AttemptOutcome("old-2", "native_trace", "setup_error"),
    ]
    feedback = schedule_proofs([_state("a")], {"a": plans["a"]}, budget, history)
    assert feedback.attempts[0].route == "angr_concolic"


def test_scheduler_filters_capabilities_and_scopes_route_failures() -> None:
    state = _state("candidate")
    plan = compile_proof_plan(state)
    budget = ProofBudget(max_candidates=1, max_wall_seconds=30, max_estimated_cpu_seconds=30)
    capabilities = {
        "candidate": {
            "native_trace": RouteCapability("native_trace", "available", "ok", "native:binary-b", 0.1, 1.0),
            "ghidra_pcode": RouteCapability("ghidra_pcode", "unsupported", "no ghidra", "ghidra:b", 60, 30),
            "angr_concolic": RouteCapability("angr_concolic", "unsupported", "no angr", "angr:b", 3, 17),
            "qemu_user": RouteCapability("qemu_user", "available", "ok", "qemu:rootfs", 1, 9),
        }
    }
    history = [
        AttemptOutcome("old-a", "native_trace", "unsupported", capability_key="native:binary-a"),
        AttemptOutcome("old-b", "native_trace", "setup_error", capability_key="native:binary-a"),
    ]
    schedule = schedule_proofs(
        [state],
        {state.candidate_id: plan},
        budget,
        history,
        route_capabilities=capabilities,
    )
    assert schedule.attempts[0].route == "native_trace"
    assert schedule.attempts[0].capability_key == "native:binary-b"


def test_scheduler_charges_shared_setup_once_and_random_is_seeded() -> None:
    first = _state("first")
    second = _state("second")
    plans = {item.candidate_id: compile_proof_plan(item) for item in (first, second)}
    shared = RouteCapability("native_trace", "available", "ok", "native:shared", 4.0, 1.0)
    capabilities = {
        item.candidate_id: {"native_trace": shared}
        for item in (first, second)
    }
    budget = ProofBudget(max_candidates=1, max_wall_seconds=30, max_estimated_cpu_seconds=30)
    cold = schedule_proofs([first], plans, budget, route_capabilities=capabilities)
    warm = schedule_proofs(
        [second],
        plans,
        budget,
        route_capabilities=capabilities,
        warm_setup_keys=frozenset({"native:shared"}),
    )
    assert cold.attempts[0].estimated_setup_seconds == 4.0
    assert cold.attempts[0].estimated_seconds == 5.0
    assert warm.attempts[0].estimated_setup_seconds == 0.0
    assert warm.attempts[0].estimated_seconds == 1.0
    assert warm.attempts[0].setup_reused is True
    random_a = schedule_proofs([first, second], plans, ProofBudget(2, 30, 30), policy="random", policy_seed="sealed")
    random_b = schedule_proofs([second, first], plans, ProofBudget(2, 30, 30), policy="random", policy_seed="sealed")
    assert [item.candidate_id for item in random_a.attempts] == [item.candidate_id for item in random_b.attempts]


def test_legacy_schedule_loads_empty_variant_and_v2_serializes_variant() -> None:
    legacy = load_proof_schedule(
        {
            "schema_version": 1,
            "policy": "adaptive",
            "budget": {
                "max_candidates": 1,
                "max_wall_seconds": 10,
                "max_estimated_cpu_seconds": 10,
            },
            "attempts": [
                {
                    "candidate_id": "legacy",
                    "vulnerability_type": "stack_overflow",
                    "route": "native_trace",
                    "rank": 1,
                    "score": 1,
                    "estimated_seconds": 1,
                    "reasons": [],
                }
            ],
            "deferred": [],
        }
    )
    assert legacy.attempts[0].variant_id == ""
    state = _state("variant")
    plan = compile_proof_plan(state)
    schedule = schedule_proofs(
        [state],
        {state.candidate_id: plan},
        ProofBudget(1, 30, 30),
        variant_ids={state.candidate_id: ("one", "two")},
    )
    assert schedule.to_dict()["schema_version"] == 2
    assert schedule.attempts[0].variant_id == "one"


def test_no_bug_exhausts_only_one_variant_but_terminal_is_candidate_wide() -> None:
    state = _state("variant-scope")
    plan = compile_proof_plan(state)
    route = plan.routes[0].name
    budget = ProofBudget(1, 30, 30)
    no_bug = schedule_proofs(
        [state],
        {state.candidate_id: plan},
        budget,
        history=[AttemptOutcome(state.candidate_id, route, "sink_reached_no_bug", variant_id="one")],
        variant_ids={state.candidate_id: ("one", "two")},
    )
    assert no_bug.attempts[0].variant_id == "two"
    terminal = schedule_proofs(
        [state],
        {state.candidate_id: plan},
        budget,
        history=[AttemptOutcome(state.candidate_id, route, "proven", variant_id="one")],
        variant_ids={state.candidate_id: ("one", "two")},
    )
    assert not terminal.attempts
    assert terminal.deferred[0].reason == "terminal_outcome_already_recorded"


def test_freezer_hashes_inputs_and_detects_tampering(tmp_path: Path) -> None:
    if shutil.which("cc") is None:
        pytest.skip("C compiler is required")
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "case.c").write_text("int main(void) { return 0; }\n")
    candidate = tmp_path / "candidate.json"
    candidate.write_text(
        json.dumps(
            {
                "corpus_id": "freeze-test",
                "upstream": {"kind": "test"},
                "cases": [
                    {
                        "id": "demo-vulnerable",
                        "lane": "vulnerable",
                        "comparison_group": "demo",
                        "vulnerability_type": "stack_overflow",
                        "source": "case.c",
                        "compile": {"flags": ["-O0"]},
                    },
                    {
                        "id": "demo-fixed",
                        "lane": "fixed",
                        "comparison_group": "demo",
                        "vulnerability_type": "stack_overflow",
                        "source": "case.c",
                        "compile": {"flags": ["-O0"]},
                    },
                ],
            }
        )
    )
    frozen = freeze_research_corpus(
        candidate,
        tmp_path / "output",
        source_root=source_root,
        repo_root=Path(__file__).resolve().parents[1],
    )
    manifest = Path(frozen.corpus_dir) / "frozen_manifest.json"
    assert verify_frozen_corpus(manifest)["verified"] is True
    binary = Path(frozen.corpus_dir) / frozen.cases[0].binary_path
    binary.write_bytes(binary.read_bytes() + b"tampered")
    result = verify_frozen_corpus(manifest)
    assert result["verified"] is False
    assert result["failures"][0]["reason"] == "hash_mismatch"


def test_research_metrics_do_not_treat_blocked_as_clean() -> None:
    metrics = compute_research_metrics(
        [
            CaseOutcome("vuln", "vulnerable", "blocked", candidate_count=10, attempted_proofs=2, blockers=("timeout",)),
            CaseOutcome("fixed", "fixed", "blocked", candidate_count=9, attempted_proofs=2, blockers=("timeout",)),
        ]
    )
    assert metrics.coverage == 0.0
    assert metrics.conditional_recall is None
    assert metrics.conditional_false_positive_rate is None
    assert metrics.blocker_counts == {"timeout": 2}


def test_research_metrics_report_yield_uses_recorded_cpu_time() -> None:
    metrics = compute_research_metrics(
        [
            CaseOutcome(
                "vuln",
                "vulnerable",
                "reported",
                candidate_count=4,
                attempted_proofs=2,
                completed_proofs=1,
                report_count=1,
                wall_seconds=8,
                cpu_seconds=4,
                time_to_first_proof_seconds=8,
            ),
            CaseOutcome("fixed", "fixed", "clean", candidate_count=0, wall_seconds=1, cpu_seconds=1),
        ]
    )
    assert metrics.coverage == 1.0
    assert metrics.conditional_recall == 1.0
    assert metrics.conditional_false_positive_rate == 0.0
    assert metrics.proven_reports_per_cpu_hour == 720.0
    assert metrics.time_to_first_proof_seconds == 8


def test_firmware_extraction_hashes_tree_and_rejects_traversal(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "firmware.txt").write_text("untouched")
    archive = tmp_path / "firmware.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(source / "firmware.txt", arcname="etc/firmware.txt")
    rootfs = tmp_path / "rootfs"
    _extract_archive(archive, rootfs, "tar.gz")
    first_hash = _tree_sha256(rootfs)
    assert len(first_hash) == 64
    assert first_hash == _tree_sha256(rootfs)

    unsafe = tmp_path / "unsafe.tar"
    with tarfile.open(unsafe, "w") as bundle:
        info = tarfile.TarInfo("../escape")
        info.size = 0
        bundle.addfile(info)
    with pytest.raises(ValueError, match="unsafe archive member"):
        _extract_archive(unsafe, tmp_path / "unsafe-root", "tar")

    absolute_link = tmp_path / "absolute-link.tar"
    with tarfile.open(absolute_link, "w") as bundle:
        info = tarfile.TarInfo("etc/TZ")
        info.type = tarfile.SYMTYPE
        info.linkname = "/tmp/TZ"
        bundle.addfile(info)
    normalizations = _extract_archive(absolute_link, tmp_path / "link-root", "tar")
    assert normalizations[0]["kind"] == "absolute_link_rebased_within_rootfs"
    assert not Path((tmp_path / "link-root" / "etc" / "TZ").readlink()).is_absolute()


def test_disclosure_redaction_fingerprints_sensitive_values() -> None:
    redacted = _redact_sensitive({"api_token": "fixture-public-token", "address": "0x1000"})
    assert redacted["api_token"]["redacted"] is True
    assert "fixture-public-token" not in json.dumps(redacted)
    assert redacted["address"] == "0x1000"


def test_decompile_project_avoids_hidden_artifact_components(tmp_path: Path) -> None:
    hidden_run = tmp_path / ".ai" / "runs" / "case"
    hidden_run.mkdir(parents=True)
    project, cleanup = headless_project_location(hidden_run)
    try:
        assert cleanup is not None
        assert all(not part.startswith(".") for part in project.resolve().parts if part not in {".", ".."})
    finally:
        if cleanup is not None:
            shutil.rmtree(cleanup)


def test_baselines_preserve_incomplete_evaluation_as_blocked(tmp_path: Path) -> None:
    evaluation = tmp_path / "evaluation.json"
    evaluation.write_text(
        json.dumps(
            {
                "corpus_id": "test",
                "cases": [
                    {
                        "id": "vulnerable",
                        "lane": "vulnerable",
                        "returncode": 1,
                        "candidate_count": 0,
                        "blockers": ["toolchain_exit_1"],
                    }
                ],
            }
        )
    )
    result = run_research_baselines(evaluation, tmp_path / "baselines")
    candidate = next(item for item in result["baselines"] if item["policy"] == "candidate_only")
    assert candidate["cases"][0]["decision"] == "blocked"
    assert candidate["metrics"]["conditional_recall"] is None
