import json
from pathlib import Path

import pytest

from binary_agent.adjudication import (
    AdjudicationError,
    _required_obligations,
    admit_review,
    finalize_campaign,
    prepare_campaign,
    resolve_exact_operation,
    sha256_file,
    validate_decision,
    validate_source_binding,
)
from binary_agent.pipeline import CandidateState


def _state(candidate_id: str = "candidate-1", vulnerability_type: str = "stack_overflow") -> dict:
    pcode = "STORE" if vulnerability_type in {"stack_overflow", "out_of_bounds_write"} else "LOAD"
    return {
        "candidate_id": candidate_id,
        "backend": "memory_access" if vulnerability_type != "path_traversal" else "semantic_effect",
        "vulnerability_type": vulnerability_type,
        "mechanism": "out_of_bounds_write" if pcode == "STORE" else "",
        "status": "needs_refinement",
        "target": {"binary": "demo", "component": "demo"},
        "location": {
            "address": "0x1000",
            "function_name": "target",
            "line_number": 10,
            "line_text": "local_20[1] = value;" if pcode == "STORE" else "value = local_20[1];",
            "relative_path": "target.c",
        },
        "source": {"kind": "unknown"},
        "sink": {"name": "pointer_store" if pcode == "STORE" else "local_read"},
        "operation": {"name": "pointer_store" if pcode == "STORE" else "local_read"},
        "affected_object": {"identity": "stack:local_20", "kind": "stack", "label": "local_20"},
        "type_facts": {},
        "proof_obligations": [],
        "blockers": ["proof_required"],
        "validation_artifacts": [],
        "replay_artifacts": [],
        "report_artifacts": [],
        "metadata": {},
    }


def _manifest(vulnerability_type: str = "stack_overflow") -> dict:
    spatial = vulnerability_type in {"stack_overflow", "out_of_bounds_write"}
    return {
        "binary": "demo",
        "functions": [
            {
                "name": "target",
                "address": "0x1000",
                "pcode_stores": (
                    [
                        {
                            "operation_address": "0x1010",
                            "write_width": 8,
                            "address_vars": ["local_20"],
                            "pcode": "STORE",
                        }
                    ]
                    if spatial
                    else []
                ),
                "pcode_loads": (
                    [
                        {
                            "operation_address": "0x1010",
                            "read_width": 8,
                            "address_vars": ["local_20"],
                            "pcode": "LOAD",
                        }
                    ]
                    if not spatial
                    else []
                ),
                "pcode_calls": [],
                "c_line_addresses": [
                    {
                        "line_number": 10,
                        "addresses": ["0x1010"],
                        **({"store_addresses": ["0x1010"]} if spatial else {"load_addresses": ["0x1010"]}),
                    }
                ],
            }
        ],
    }


def _write_campaign_inputs(tmp_path: Path, states: list[dict]) -> tuple[Path, Path, Path, Path]:
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    states_path = input_root / "candidate_states.json"
    states_path.write_text(json.dumps({"schema_version": 2, "candidate_states": states}, indent=2))
    binary_path = input_root / "demo"
    binary_path.write_bytes(b"exact frozen binary bytes")
    manifest_path = input_root / "manifest_normalized.json"
    manifest_path.write_text(json.dumps(_manifest(states[0]["vulnerability_type"]), indent=2))
    audit_path = input_root / "audit_summary.json"
    audit_path.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "name": "demo",
                        "binary_sha256": sha256_file(binary_path),
                        "source_repository": "https://example.invalid/demo.git",
                        "source_commit": "a" * 40,
                        "final": {
                            "candidate_count": len(states),
                            "candidate_states_sha256": sha256_file(states_path),
                        },
                    }
                ]
            },
            indent=2,
        )
    )
    return audit_path, states_path, binary_path, manifest_path


def _prepare(tmp_path: Path, states: list[dict]) -> Path:
    audit, state_path, binary, manifest = _write_campaign_inputs(tmp_path, states)
    root = tmp_path / "campaign"
    prepare_campaign(
        root,
        audit_summary_path=audit,
        candidate_state_paths={"demo": state_path},
        binary_paths={"demo": binary},
        export_manifest_paths={"demo": manifest},
    )
    return root


def _evidence_ref(root: Path, relative: str, kind: str, text: str) -> dict:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return {"path": relative, "sha256": sha256_file(path), "kind": kind}


def _obligations(vulnerability_type: str, outcome: str, basis: str, evidence_hash: str) -> dict:
    required, alternatives = _required_obligations(
        vulnerability_type=vulnerability_type,
        decision=outcome,
        basis=basis,
    )
    names = set(required)
    names.update(next(iter(choices)) for choices in alternatives)
    return {
        name: {"status": "satisfied", "evidence_refs": [evidence_hash]}
        for name in sorted(names)
    }


def _source_binding(source_ref: dict, frozen_binary_sha256: str) -> dict:
    code_hash = "b" * 64
    return {
        "source_path": source_ref["path"],
        "source_sha256": source_ref["sha256"],
        "source_commit": "a" * 40,
        "source_function": "target",
        "source_lines": [10],
        "mapping_basis": "exact_code_bytes",
        "frozen_binary_sha256": frozen_binary_sha256,
        "frozen_code_sha256": code_hash,
        "reference_code_sha256": code_hash,
        "code_bytes_match": True,
    }


def _decision(
    root: Path,
    candidate_id: str,
    vulnerability_type: str,
    *,
    outcome: str = "not_bug",
    basis: str = "verified_modeling_error",
) -> dict:
    binding_path = root / "bindings" / f"{candidate_id}.json"
    binding = json.loads(binding_path.read_text())
    operation_ref = {
        "path": str(binding_path.relative_to(root)),
        "sha256": sha256_file(binding_path),
        "kind": "exact_binary_operation",
    }
    kind = {
        "dynamic_invariant_violation": "schema_v2_dynamic_proof",
        "exact_source_feasible_violation": "source_review",
        "source_proves_safety": "source_review",
        "cfg_smt_path_infeasible": "cfg_smt_proof",
        "verified_modeling_error": "analyzer_model_refutation",
        "intentional_no_boundary": "trust_boundary_review",
        "unreachable_all_entries": "reachability_proof",
        "exhaustive_finite_dynamic": "finite_enumeration",
    }[basis]
    basis_ref = _evidence_ref(
        root,
        f"evidence/{candidate_id}-{basis}.txt",
        kind,
        "affirmative deterministic review evidence for the selected decision basis",
    )
    refs = [operation_ref, basis_ref]
    decision = {
        "candidate_id": candidate_id,
        "decision": outcome,
        "basis": basis,
        "rationale": "Affirmative analysis proves the class-specific violating condition is absent or present.",
        "binary_operation": binding,
        "evidence_refs": refs,
        "obligations": _obligations(vulnerability_type, outcome, basis, basis_ref["sha256"]),
    }
    if basis in {"source_proves_safety", "exact_source_feasible_violation", "intentional_no_boundary"}:
        source_ref = _evidence_ref(root, f"source/{candidate_id}.c", "source_file", "int target(void) { return 0; }\n")
        refs.append(source_ref)
        decision["source_binding"] = _source_binding(source_ref, binding["frozen_binary_sha256"])
    if basis == "dynamic_invariant_violation":
        decision["dynamic_proof"] = {
            "schema_version": 2,
            "candidate_id": candidate_id,
            "invariant_violation": "exact zero-address access",
            "evidence_sha256": basis_ref["sha256"],
        }
    if basis == "exhaustive_finite_dynamic":
        decision["finite_enumeration"] = {
            "domain_size": 256,
            "tested_inputs": 256,
            "complete": True,
            "evidence_sha256": basis_ref["sha256"],
        }
    return decision


def test_prepare_freezes_complete_inventory_and_exact_store(tmp_path: Path) -> None:
    root = _prepare(tmp_path, [_state()])

    manifest = json.loads((root / "frozen_manifest.json").read_text())
    binding = json.loads((root / "bindings" / "candidate-1.json").read_text())

    assert manifest["candidate_count"] == 1
    assert len(manifest["review_units"]) == 1
    assert binding["status"] == "resolved"
    assert binding["address"] == "0x1010"
    assert binding["pcode"] == "STORE"


def test_resolve_exact_store_from_x86_call_return_address() -> None:
    state = _state()
    state["location"]["line_text"] = "*(undefined8 *)((long)&local_20 + offset) = 0x1016;"
    state["sink"]["operation_address"] = ""
    manifest = _manifest()
    manifest["functions"][0]["c_line_addresses"] = []

    binding = resolve_exact_operation(state, manifest)

    assert binding["status"] == "resolved"
    assert binding["address"] == "0x1010"
    assert binding["pcode"] == "STORE"
    assert binding["mapping_basis"] == "x86_call_return_address_store"


def test_resolve_interprocedural_store_in_exact_callee() -> None:
    state = _state(vulnerability_type="out_of_bounds_write")
    state["location"]["line_text"] = "FUN_002000(&global_object);"
    state["type_facts"] = {
        "static_candidate": {
            "kind": "interprocedural_indexed_write",
            "offset_expr": "1",
            "write_size_bytes": 1,
            "classification_trace": {},
        }
    }
    manifest = _manifest(vulnerability_type="out_of_bounds_write")
    manifest["functions"].append(
        {
            "name": "FUN_002000",
            "address": "0x2000",
            "pcode_stores": [
                {
                    "operation_address": "0x2010",
                    "write_width": 4,
                    "address_vars": ["param_1"],
                    "address_constants": [1, 4],
                    "pcode": "STORE",
                }
            ],
            "pcode_loads": [],
            "pcode_calls": [],
            "c_line_addresses": [],
            "stack_regions": [],
        }
    )
    manifest["functions"][0]["pcode_stores"] = []
    manifest["functions"][0]["c_line_addresses"] = []

    binding = resolve_exact_operation(state, manifest)

    assert binding["status"] == "resolved"
    assert binding["address"] == "0x2010"
    assert binding["function_name"] == "FUN_002000"
    assert binding["mapping_basis"] == "interprocedural_exact_store"


def test_resolve_ssa_use_from_decompiler_token_pcode() -> None:
    state = _state(vulnerability_type="uninitialized_memory_use")
    state["source"] = {"kind": "definedness", "expression": "local_20"}
    manifest = _manifest(vulnerability_type="uninitialized_memory_use")
    function = manifest["functions"][0]
    function["c_line_number_offset"] = 0
    function["pcode_operations"] = [
        {
            "operation_address": "0x1012",
            "pcode": "INT_SUB",
            "inputs": [{"var_name": "local_20", "size_bytes": 8}],
            "output": {"var_name": "result", "size_bytes": 8},
        }
    ]
    function["c_line_addresses"] = [
        {
            "line_number": 10,
            "addresses": ["0x1010"],
            "token_operations": [
                {"token": "local_20", "operation_address": "0x1012", "pcode": "INT_SUB"}
            ],
        }
    ]

    binding = resolve_exact_operation(state, manifest)

    assert binding["status"] == "resolved"
    assert binding["address"] == "0x1012"
    assert binding["pcode"] == "INT_SUB"
    assert binding["mapping_basis"] == "normalized_token_pcode_mapping"


def test_spatial_token_mapping_selects_store_over_address_calculation() -> None:
    state = _state(vulnerability_type="out_of_bounds_write")
    state["sink"]["operation_address"] = ""
    manifest = _manifest(vulnerability_type="out_of_bounds_write")
    function = manifest["functions"][0]
    function["c_line_number_offset"] = 0
    function["pcode_operations"] = [
        {
            "operation_address": "0x1010",
            "pcode": "PTRADD",
            "inputs": [{"var_name": "local_20", "size_bytes": 8}],
        },
        {
            "operation_address": "0x1010",
            "pcode": "STORE",
            "inputs": [{"var_name": "local_20", "size_bytes": 8}],
        },
    ]
    function["c_line_addresses"] = [
        {
            "line_number": 10,
            "addresses": ["0x1010"],
            "token_operations": [
                {"token": "local_20", "operation_address": "0x1010", "pcode": "PTRADD"},
                {"token": "=", "operation_address": "0x1010", "pcode": "STORE"},
            ],
        }
    ]

    binding = resolve_exact_operation(state, manifest)

    assert binding["status"] == "resolved"
    assert binding["address"] == "0x1010"
    assert binding["pcode"] == "STORE"
    assert binding["mapping_basis"] == "normalized_token_pcode_mapping"


def test_resolve_indirect_effect_call_from_named_token() -> None:
    state = _state(vulnerability_type="path_traversal")
    state["operation"] = {"kind": "call", "name": "open"}
    state["sink"] = {"kind": "call", "name": "open"}
    manifest = _manifest(vulnerability_type="path_traversal")
    function = manifest["functions"][0]
    function["pcode_calls"] = [
        {"call_address": "0x1012", "pcode": "CALLIND", "args": []}
    ]
    function["c_line_addresses"] = [
        {
            "line_number": 10,
            "addresses": ["0x1010", "0x1012"],
            "load_addresses": ["0x1010"],
            "token_operations": [
                {"token": "PTR_open_004000", "operation_address": "0x1012", "pcode": "CAST"}
            ],
        }
    ]

    binding = resolve_exact_operation(state, manifest)

    assert binding["status"] == "resolved"
    assert binding["address"] == "0x1012"
    assert binding["pcode"] == "CALLIND"
    assert binding["mapping_basis"] == "normalized_named_call_mapping"


def test_prepare_rejects_frozen_state_hash_mismatch(tmp_path: Path) -> None:
    audit, state_path, binary, manifest = _write_campaign_inputs(tmp_path, [_state()])
    payload = json.loads(audit.read_text())
    payload["targets"][0]["final"]["candidate_states_sha256"] = "0" * 64
    audit.write_text(json.dumps(payload))

    with pytest.raises(AdjudicationError, match="candidate-state hash mismatch"):
        prepare_campaign(
            tmp_path / "campaign",
            audit_summary_path=audit,
            candidate_state_paths={"demo": state_path},
            binary_paths={"demo": binary},
            export_manifest_paths={"demo": manifest},
        )


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unknown"])
def test_review_rejects_incomplete_duplicate_and_unknown_ids(tmp_path: Path, mutation: str) -> None:
    root = _prepare(tmp_path, [_state("candidate-1"), _state("candidate-2")])
    unit = json.loads((root / "frozen_manifest.json").read_text())["review_units"][0]
    rows = [_decision(root, candidate_id, "stack_overflow") for candidate_id in unit["candidate_ids"]]
    if mutation == "missing":
        rows.pop()
    elif mutation == "duplicate":
        rows[1] = rows[0]
    else:
        rows[1] = {**rows[1], "candidate_id": "not-frozen"}
    review = tmp_path / "review.json"
    review.write_text(json.dumps({"unit_id": unit["unit_id"], "decisions": rows}))

    with pytest.raises(AdjudicationError, match="candidate"):
        admit_review(root, review)


def test_review_rejects_weak_negative_even_with_hashed_artifact(tmp_path: Path) -> None:
    root = _prepare(tmp_path, [_state()])
    unit = json.loads((root / "frozen_manifest.json").read_text())["review_units"][0]
    decision = _decision(root, "candidate-1", "stack_overflow")
    decision["rationale"] = "The test did not crash and therefore the operation appears safe."
    review = tmp_path / "review.json"
    review.write_text(json.dumps({"unit_id": unit["unit_id"], "decisions": [decision]}))

    with pytest.raises(AdjudicationError, match="weak negative"):
        admit_review(root, review)


def test_review_rejects_unhashed_or_changed_evidence(tmp_path: Path) -> None:
    root = _prepare(tmp_path, [_state()])
    candidate = json.loads((root / "frozen_manifest.json").read_text())["candidates"][0]
    binding = json.loads((root / "bindings" / "candidate-1.json").read_text())
    decision = _decision(root, "candidate-1", "stack_overflow")
    decision["evidence_refs"][1]["sha256"] = "0" * 64

    with pytest.raises(AdjudicationError, match="evidence hash mismatch"):
        validate_decision(
            decision,
            candidate=candidate,
            prepared_binding=binding,
            campaign_root=root,
        )


def test_source_binding_rejects_direct_mapping_on_build_mismatch() -> None:
    binding = {
        "source_path": "source.c",
        "source_sha256": "a" * 64,
        "source_commit": "b" * 40,
        "source_function": "target",
        "source_lines": [4],
        "mapping_basis": "exact_code_bytes",
        "frozen_binary_sha256": "c" * 64,
        "frozen_code_sha256": "d" * 64,
        "reference_code_sha256": "e" * 64,
        "code_bytes_match": False,
    }

    with pytest.raises(AdjudicationError, match="matching frozen/reference code bytes"):
        validate_source_binding(binding)


def test_source_binding_accepts_verified_function_fingerprint() -> None:
    fingerprint = "d" * 64
    validate_source_binding(
        {
            "source_path": "source.c",
            "source_sha256": "a" * 64,
            "source_commit": "b" * 40,
            "source_function": "target",
            "source_lines": [4],
            "mapping_basis": "function_fingerprint",
            "frozen_binary_sha256": "c" * 64,
            "frozen_function_sha256": fingerprint,
            "reference_function_sha256": fingerprint,
            "constants_match": True,
            "call_topology_match": True,
        }
    )


def test_spatial_candidate_cannot_use_non_store_operation(tmp_path: Path) -> None:
    root = _prepare(tmp_path, [_state()])
    candidate = json.loads((root / "frozen_manifest.json").read_text())["candidates"][0]
    binding = json.loads((root / "bindings" / "candidate-1.json").read_text())
    decision = _decision(root, "candidate-1", "stack_overflow")
    decision["binary_operation"] = {**binding, "pcode": "LOAD"}

    with pytest.raises(AdjudicationError, match="frozen binding field pcode"):
        validate_decision(
            decision,
            candidate=candidate,
            prepared_binding=binding,
            campaign_root=root,
        )


@pytest.mark.parametrize(
    ("outcome", "basis", "vulnerability_type"),
    [
        ("bug", "dynamic_invariant_violation", "uninitialized_memory_use"),
        ("bug", "exact_source_feasible_violation", "uninitialized_memory_use"),
        ("not_bug", "source_proves_safety", "uninitialized_memory_use"),
        ("not_bug", "cfg_smt_path_infeasible", "uninitialized_memory_use"),
        ("not_bug", "verified_modeling_error", "uninitialized_memory_use"),
        ("not_bug", "intentional_no_boundary", "path_traversal"),
        ("not_bug", "unreachable_all_entries", "uninitialized_memory_use"),
        ("not_bug", "exhaustive_finite_dynamic", "uninitialized_memory_use"),
    ],
)
def test_each_allowed_decision_basis(
    tmp_path: Path,
    outcome: str,
    basis: str,
    vulnerability_type: str,
) -> None:
    root = _prepare(tmp_path, [_state(vulnerability_type=vulnerability_type)])
    candidate = json.loads((root / "frozen_manifest.json").read_text())["candidates"][0]
    binding = json.loads((root / "bindings" / "candidate-1.json").read_text())
    decision = _decision(
        root,
        "candidate-1",
        vulnerability_type,
        outcome=outcome,
        basis=basis,
    )

    validate_decision(
        decision,
        candidate=candidate,
        prepared_binding=binding,
        campaign_root=root,
    )


@pytest.mark.parametrize(
    ("vulnerability_type", "basis", "missing_obligations"),
    [
        ("uninitialized_memory_use", "source_proves_safety", {"all_path_initialization"}),
        ("stack_overflow", "source_proves_safety", {"bounds_proven"}),
        (
            "null_pointer_dereference",
            "source_proves_safety",
            {"dominating_non_null", "allocation_contract"},
        ),
        ("path_traversal", "intentional_no_boundary", {"no_security_boundary"}),
        (
            "memory_leak",
            "source_proves_safety",
            {"ownership_transfer", "bounded_lifetime", "later_cleanup"},
        ),
    ],
)
def test_each_class_rejects_missing_affirmative_obligation(
    tmp_path: Path,
    vulnerability_type: str,
    basis: str,
    missing_obligations: set[str],
) -> None:
    root = _prepare(tmp_path, [_state(vulnerability_type=vulnerability_type)])
    candidate = json.loads((root / "frozen_manifest.json").read_text())["candidates"][0]
    binding = json.loads((root / "bindings" / "candidate-1.json").read_text())
    decision = _decision(root, "candidate-1", vulnerability_type, basis=basis)
    for obligation in missing_obligations:
        decision["obligations"].pop(obligation, None)

    with pytest.raises(AdjudicationError, match="obligation|affirmatively satisfied"):
        validate_decision(
            decision,
            candidate=candidate,
            prepared_binding=binding,
            campaign_root=root,
        )


def test_finalize_requires_every_unit_and_supports_hashed_evidence_fanout(tmp_path: Path) -> None:
    root = _prepare(tmp_path, [_state("candidate-1"), _state("candidate-2")])
    unit = json.loads((root / "frozen_manifest.json").read_text())["review_units"][0]
    shared = _evidence_ref(
        root,
        "evidence/shared-model-refutation.txt",
        "analyzer_model_refutation",
        "one function-level model refutation with candidate-specific operation checks",
    )
    decisions = []
    for candidate_id in unit["candidate_ids"]:
        decision = _decision(root, candidate_id, "stack_overflow")
        decision["evidence_refs"] = [
            item for item in decision["evidence_refs"] if item["kind"] == "exact_binary_operation"
        ]
        decision["obligations"] = _obligations(
            "stack_overflow", "not_bug", "verified_modeling_error", shared["sha256"]
        )
        decisions.append(decision)
    review = tmp_path / "review.json"
    review.write_text(
        json.dumps(
            {"unit_id": unit["unit_id"], "shared_evidence_refs": [shared], "decisions": decisions}
        )
    )
    admit_review(root, review)

    result = finalize_campaign(root)
    ledger = json.loads(result.ledger_path.read_text())
    derived = json.loads(result.derived_states_path.read_text())

    assert ledger["candidate_count"] == 2
    assert len({item["candidate_id"] for item in ledger["decisions"]}) == 2
    assert {item["status"] for item in derived["candidate_states"]} == {"rejected"}


def test_source_proven_bug_does_not_bypass_schema_v2_report_gate(tmp_path: Path) -> None:
    vulnerability_type = "uninitialized_memory_use"
    root = _prepare(tmp_path, [_state(vulnerability_type=vulnerability_type)])
    unit = json.loads((root / "frozen_manifest.json").read_text())["review_units"][0]
    decision = _decision(
        root,
        "candidate-1",
        vulnerability_type,
        outcome="bug",
        basis="exact_source_feasible_violation",
    )
    review = tmp_path / "review.json"
    review.write_text(json.dumps({"unit_id": unit["unit_id"], "decisions": [decision]}))
    admit_review(root, review)

    first = finalize_campaign(root)
    first_ledger = first.ledger_path.read_bytes()
    second = finalize_campaign(root)
    derived = json.loads(second.derived_states_path.read_text())
    reports = json.loads(second.reports_path.read_text())

    assert first_ledger == second.ledger_path.read_bytes()
    assert derived["candidate_states"][0]["status"] == "needs_refinement"
    assert derived["candidate_states"][0]["metadata"]["adjudication"]["decision"] == "bug"
    assert reports["vulnerabilities"] == []


def test_resolve_exact_operation_refuses_synthetic_line_address() -> None:
    state = CandidateState.from_dict(
        {
            **_state(vulnerability_type="uninitialized_memory_use"),
            "operation": {"address": "0x1000:line:10", "name": "local_read"},
        }
    )

    binding = resolve_exact_operation(state, {"functions": []})

    assert binding["status"] == "unresolved"
    assert binding["address"] == ""
