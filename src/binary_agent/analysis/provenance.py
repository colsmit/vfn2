"""Small provenance helpers shared by proof packs and reports."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


SOURCE_READ_WRAPPER_PREFIX = "source_read_wrapper_call:"


def source_read_wrapper_chain_from_candidate(candidate: Mapping[str, Any]) -> list[dict[str, str]]:
    evidence: list[Any] = []
    _extend_candidate_evidence(evidence, candidate)
    type_facts = _mapping(candidate.get("type_facts"))
    _extend_candidate_evidence(evidence, type_facts)
    static_candidate = _mapping(type_facts.get("static_candidate"))
    _extend_candidate_evidence(evidence, static_candidate)
    for obligation in _sequence(candidate.get("proof_obligations")):
        _extend_candidate_evidence(evidence, _mapping(obligation))
    return source_read_wrapper_chain_from_evidence(evidence)


def source_read_wrapper_chain_from_evidence(evidence_sources: Sequence[Any]) -> list[dict[str, str]]:
    chain: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw in evidence_sources:
        text = str(raw).strip()
        if not text.startswith(SOURCE_READ_WRAPPER_PREFIX):
            continue
        caller, separator, callee = text.removeprefix(SOURCE_READ_WRAPPER_PREFIX).partition("->")
        caller = caller.strip()
        callee = callee.strip()
        if separator != "->" or not caller or not callee:
            continue
        key = (caller, callee)
        if key in seen:
            continue
        seen.add(key)
        chain.append({"caller": caller, "callee": callee})
    return chain


def source_read_wrapper_chain_text(chain: Sequence[Mapping[str, str]]) -> str:
    if not chain:
        return ""
    connected = _connected_chain_text(chain)
    if connected:
        return connected
    connected = _connected_chain_text(list(reversed(chain)))
    if connected:
        return connected
    return "; ".join(f"{hop.get('caller', '')} -> {hop.get('callee', '')}" for hop in chain)


def _extend_candidate_evidence(result: list[Any], candidate: Mapping[str, Any]) -> None:
    for key in ("evidence_sources", "evidence_refs", "evidence"):
        result.extend(_sequence(candidate.get(key)))


def _connected_chain_text(chain: Sequence[Mapping[str, str]]) -> str:
    if not chain:
        return ""
    first = chain[0]
    caller = str(first.get("caller") or "")
    callee = str(first.get("callee") or "")
    if not caller or not callee:
        return ""
    names = [caller, callee]
    for hop in chain[1:]:
        hop_caller = str(hop.get("caller") or "")
        hop_callee = str(hop.get("callee") or "")
        if hop_caller != names[-1] or not hop_callee:
            return ""
        names.append(hop_callee)
    return " -> ".join(names)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []
