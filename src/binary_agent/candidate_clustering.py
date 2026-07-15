"""Conservative mechanism-level clustering for redundant proof hypotheses."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Any, Mapping, Sequence

from binary_agent.pipeline import CandidateState


@dataclass(frozen=True)
class ClusterSuppression:
    representative_id: str
    suppressed_id: str
    cluster_key: tuple[str, ...]
    reason: str = "same_binary_function_object_mechanism_and_flow"

    def to_dict(self) -> dict[str, Any]:
        return {
            "representative_id": self.representative_id,
            "suppressed_id": self.suppressed_id,
            "cluster_key": list(self.cluster_key),
            "reason": self.reason,
        }


def cluster_mechanism_candidates(
    states: Sequence[CandidateState],
) -> tuple[list[CandidateState], list[ClusterSuppression]]:
    """Collapse only candidates that ask the same proof question."""

    grouped: dict[tuple[str, ...], list[CandidateState]] = {}
    for state in states:
        grouped.setdefault(_cluster_key(state), []).append(state)
    representatives: list[CandidateState] = []
    suppressions: list[ClusterSuppression] = []
    for key, members in sorted(grouped.items(), key=lambda item: item[0]):
        ordered = sorted(members, key=lambda item: (_representative_score(item), item.candidate_id), reverse=True)
        representative = ordered[0]
        if len(ordered) > 1:
            member_rows = [
                {
                    "candidate_id": item.candidate_id,
                    "operation_address": str(item.operation.get("address") or item.sink.get("operation_address") or ""),
                    "evidence_refs": list(item.validation_artifacts),
                }
                for item in sorted(ordered, key=lambda item: item.candidate_id)
            ]
            facts = dict(representative.type_facts)
            facts["mechanism_cluster"] = {
                "schema_version": 1,
                "member_count": len(member_rows),
                "members": member_rows,
                "cluster_key": list(key),
                "authority": "proof_work_deduplication_not_vulnerability_observation",
            }
            metadata = dict(representative.metadata)
            metadata["mechanism_cluster_member_ids"] = [item["candidate_id"] for item in member_rows]
            representative = replace(representative, type_facts=facts, metadata=metadata)
            for item in ordered[1:]:
                suppressions.append(ClusterSuppression(representative.candidate_id, item.candidate_id, key))
        representatives.append(representative)
    return sorted(representatives, key=lambda item: item.candidate_id), sorted(
        suppressions,
        key=lambda item: (item.representative_id, item.suppressed_id),
    )


def _cluster_key(state: CandidateState) -> tuple[str, ...]:
    target = str(state.target.get("sha256") or state.target.get("path") or state.target.get("binary") or "")
    function = str(state.location.get("address") or state.location.get("function_name") or "")
    affected = str(
        state.affected_object.get("identity")
        or state.affected_object.get("name")
        or state.sink.get("target_buffer")
        or ""
    )
    source = _flow_token(state.source)
    sink = _normalized_sink(state)
    trace = state.type_facts.get("source_to_sink_trace")
    trace_token = _normalized_trace(trace) if isinstance(trace, Mapping) else ""
    # Normalized token-to-p-code mappings identify distinct machine uses even
    # when the decompiler renders them on one source line.  Collapsing those
    # uses would discard an exact operation from the frozen inventory.
    exact_token_use = ""
    if str(state.operation.get("evidence_source") or "") == "pcode_token_use":
        exact_token_use = str(
            state.operation.get("address")
            or state.sink.get("operation_address")
            or ""
        )
    return (
        target,
        state.vulnerability_type,
        state.mechanism,
        function,
        affected,
        source,
        sink,
        trace_token,
        exact_token_use,
    )


def _normalized_sink(state: CandidateState) -> str:
    name = str(state.operation.get("name") or state.sink.get("name") or "").lower()
    kind = str(state.operation.get("kind") or state.operation.get("effect_kind") or "").lower()
    if any(token in name or token in kind for token in ("load", "read")):
        return "memory_read"
    if any(token in name or token in kind for token in ("store", "write")):
        return "memory_write"
    return re.sub(r"[^a-z0-9]+", "_", name or kind).strip("_")


def _flow_token(value: Mapping[str, Any]) -> str:
    return ":".join(
        str(value.get(key) or "").lower()
        for key in ("kind", "name", "role")
    )


def _normalized_trace(trace: Mapping[str, Any]) -> str:
    rows = trace.get("nodes") or trace.get("steps") or trace.get("path") or []
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
        return str(trace.get("status") or "")
    tokens = []
    for item in rows:
        if isinstance(item, Mapping):
            tokens.append(str(item.get("kind") or item.get("role") or item.get("name") or ""))
        else:
            tokens.append(str(item))
    return json.dumps(tokens, separators=(",", ":"))


def _representative_score(state: CandidateState) -> tuple[int, int, int, int]:
    operation = str(state.operation.get("address") or state.sink.get("operation_address") or "")
    exact = int(bool(operation and ":line:" not in operation))
    proof_ready = int(state.status == "proof_ready")
    trace = state.type_facts.get("source_to_sink_trace")
    complete = int(isinstance(trace, Mapping) and trace.get("status") in {"complete", "proven"})
    return exact, proof_ready, complete, -len(state.blockers)
