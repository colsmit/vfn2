"""Shared dynamic memory-proof payload helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from binary_agent.taxonomy import vulnerability_types_for_backend


GHIDRA_DYNAMIC_PROOF_KIND = "ghidra_dynamic_overflow"
GHIDRA_DYNAMIC_MEMORY_SAFETY_PROOF_KIND = "ghidra_dynamic_memory_safety"
GHIDRA_DYNAMIC_PROOF_KINDS = {
    GHIDRA_DYNAMIC_PROOF_KIND,
    GHIDRA_DYNAMIC_MEMORY_SAFETY_PROOF_KIND,
}
PROCESS_PROOF_SCOPE = "process_entrypoint"
FUNCTION_HARNESS_PROOF_SCOPE = "function_harness"
DYNAMIC_PROOF_STATUS_TO_ACCESS_KIND = {
    "overflow_proven": "write",
    "heap_overflow_proven": "write",
    "oob_write_proven": "write",
    "oob_read_proven": "read",
    "lifetime_violation_proven": "lifetime",
}
DYNAMIC_MEMORY_PROOF_STATUSES = frozenset(DYNAMIC_PROOF_STATUS_TO_ACCESS_KIND)
DYNAMIC_MEMORY_ACCESS = {
    "write": {
        "label": "Write",
        "condition": "memory-overflow condition",
        "impact": "memory-overflow condition",
        "byte_field": "overflow_bytes",
        "range_field": "write_range",
        "size_field": "write_size_bytes",
        "evidence_verb": "overflowed by",
        "vulnerability_types": vulnerability_types_for_backend("memory_access") - {
            "out_of_bounds_read",
            "null_pointer_dereference",
            "uninitialized_memory_use",
            "overlapping_memory_copy",
        },
    },
    "read": {
        "label": "Read",
        "condition": "out-of-bounds read condition",
        "impact": "out-of-bounds read",
        "byte_field": "oob_bytes",
        "range_field": "read_range",
        "size_field": "read_size_bytes",
        "evidence_verb": "read out of bounds by",
        "vulnerability_types": {"out_of_bounds_read"},
    },
    "lifetime": {
        "label": "Heap object",
        "condition": "heap-object lifetime violation",
        "impact": "heap-object lifetime violation",
        "byte_field": "object_size_bytes",
        "range_field": "object_identity",
        "size_field": "object_size_bytes",
        "evidence_verb": "violated the lifetime of object",
        "vulnerability_types": vulnerability_types_for_backend("memory_lifetime"),
    },
}


def dynamic_access_kind(*, proof_status: str = "", vulnerability: str = "") -> str:
    status_kind = DYNAMIC_PROOF_STATUS_TO_ACCESS_KIND.get(str(proof_status or ""))
    if status_kind:
        return status_kind
    if str(vulnerability or "") in DYNAMIC_MEMORY_ACCESS["lifetime"]["vulnerability_types"]:
        return "lifetime"
    return "read" if str(vulnerability or "") == "out_of_bounds_read" else "write"


def dynamic_access_metadata(*, proof_status: str = "", vulnerability: str = "") -> Mapping[str, Any]:
    return DYNAMIC_MEMORY_ACCESS[dynamic_access_kind(proof_status=proof_status, vulnerability=vulnerability)]


def iter_ghidra_dynamic_proofs(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if str(payload.get("proof_kind") or "") in GHIDRA_DYNAMIC_PROOF_KINDS:
        return [payload]
    proof = payload.get("ghidra_dynamic_proof") if isinstance(payload.get("ghidra_dynamic_proof"), Mapping) else {}
    if proof:
        return [proof]
    control = payload.get("control_result") if isinstance(payload.get("control_result"), Mapping) else {}
    proof = control.get("ghidra_dynamic_proof") if isinstance(control.get("ghidra_dynamic_proof"), Mapping) else {}
    return [proof] if proof else []


def first_ghidra_dynamic_proof(payload: Mapping[str, Any]) -> dict[str, Any]:
    proofs = iter_ghidra_dynamic_proofs(payload)
    return dict(proofs[0]) if proofs else {}


@dataclass(frozen=True)
class DynamicProofView:
    payload: Mapping[str, Any]

    @property
    def status(self) -> str:
        return str(self.payload.get("status") or "")

    @property
    def access_kind(self) -> str:
        return DYNAMIC_PROOF_STATUS_TO_ACCESS_KIND.get(self.status, "")

    @property
    def scope(self) -> str:
        scope = str(self.payload.get("proof_scope") or "")
        if not scope and isinstance(self.payload.get("process_replay"), Mapping):
            return PROCESS_PROOF_SCOPE
        return scope

    @property
    def process_input_setup(self) -> Mapping[str, Any]:
        setup = self.payload.get("process_input_setup")
        return setup if isinstance(setup, Mapping) else {}

    @property
    def process_replay(self) -> Mapping[str, Any]:
        replay = self.payload.get("process_replay")
        if isinstance(replay, Mapping):
            return replay
        path_replay = self.payload.get("path_replay")
        return path_replay if isinstance(path_replay, Mapping) else {}

    @property
    def sink_address(self) -> str:
        return str(self.payload.get("sink_address") or "")

    def is_memory_safety_proof(
        self,
        *,
        scope: str = "",
        require_setup: bool = True,
        require_sink: bool = True,
        require_function_harness_input: bool = False,
        allow_non_process_scope: bool = False,
    ) -> bool:
        if self.status not in DYNAMIC_MEMORY_PROOF_STATUSES:
            return False
        actual_scope = self.scope
        if scope and actual_scope != scope:
            return False
        if require_sink and (
            self.payload.get("sink_reached") is False
            or self.payload.get("exact_sink_reached") is False
        ):
            return False
        if require_setup and str(self.process_input_setup.get("status") or "") != "configured":
            return False
        if actual_scope == PROCESS_PROOF_SCOPE:
            return str(self.process_replay.get("status") or "") == "reached"
        if actual_scope == FUNCTION_HARNESS_PROOF_SCOPE:
            if require_function_harness_input:
                return str(self.process_input_setup.get("input_model") or "") == "function_harness"
            return True
        return bool(allow_non_process_scope)
