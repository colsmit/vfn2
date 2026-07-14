from dataclasses import replace

from binary_agent.candidate_clustering import cluster_mechanism_candidates
from binary_agent.pipeline import CandidateState
from binary_agent.taxonomy import VULNERABILITY_SPECS


def _state(
    candidate_id: str,
    *,
    operation: str,
    affected: str = "stack:value",
    function: str = "0x1000",
    evidence_source: str = "",
) -> CandidateState:
    spec = VULNERABILITY_SPECS["uninitialized_memory_use"]
    return CandidateState(
        candidate_id=candidate_id,
        backend=spec.backend,
        vulnerability_type="uninitialized_memory_use",
        mechanism=spec.mechanism,
        status="proof_ready",
        target={"sha256": "binary"},
        location={"function_name": "main", "address": function},
        source={"kind": "definedness"},
        sink={"name": "local_read", "operation_address": operation},
        operation={
            "name": "local_read",
            "kind": "load",
            "address": operation,
            "evidence_source": evidence_source,
        },
        affected_object={"identity": affected},
        type_facts={"definedness": "undefined"},
        proof_obligations=[],
        blockers=[],
    )


def test_mechanism_clustering_collapses_repeated_operations_and_preserves_members() -> None:
    representatives, suppressed = cluster_mechanism_candidates(
        [_state("a", operation="0x1010"), _state("b", operation="0x1020")]
    )
    assert len(representatives) == 1
    assert len(suppressed) == 1
    cluster = representatives[0].type_facts["mechanism_cluster"]
    assert cluster["member_count"] == 2
    assert {item["candidate_id"] for item in cluster["members"]} == {"a", "b"}


def test_mechanism_clustering_preserves_exact_token_pcode_uses() -> None:
    representatives, suppressed = cluster_mechanism_candidates(
        [
            _state("a", operation="0x1010", evidence_source="pcode_token_use"),
            _state("b", operation="0x1020", evidence_source="pcode_token_use"),
        ]
    )

    assert [item.candidate_id for item in representatives] == ["a", "b"]
    assert suppressed == []


def test_mechanism_clustering_preserves_distinct_objects_functions_and_taxonomies() -> None:
    first = _state("a", operation="0x1010")
    rows = [
        first,
        _state("object", operation="0x1020", affected="stack:other"),
        _state("function", operation="0x1030", function="0x2000"),
        replace(first, candidate_id="taxonomy", vulnerability_type="out_of_bounds_read"),
    ]
    representatives, suppressed = cluster_mechanism_candidates(rows)
    assert len(representatives) == 4
    assert suppressed == []
