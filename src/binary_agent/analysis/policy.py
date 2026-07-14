"""Policy views over classified fact-first findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from binary_agent.analysis.facts import ClassifiedFinding, SuppressedFinding


@dataclass(frozen=True)
class PolicyViews:
    deterministic_reports: list[ClassifiedFinding] = field(default_factory=list)
    llm_queue: list[ClassifiedFinding] = field(default_factory=list)
    debug_suppressed: list[SuppressedFinding] = field(default_factory=list)
    triage_tiers: dict[str, int] = field(default_factory=dict)

    def to_metrics(self) -> dict[str, int]:
        return {
            "deterministic_reports": len(self.deterministic_reports),
            "llm_queue": len(self.llm_queue),
            "suppressed": len(self.debug_suppressed),
            **{f"tier_{key}": value for key, value in self.triage_tiers.items()},
        }


def triage_tier_for_candidate(candidate: object) -> str:
    verdict = _value(candidate, "verdict")
    relation = _value(candidate, "write_relation")
    vulnerability_type = _value(candidate, "vulnerability_type")
    destination = _value(candidate, "destination_kind")
    capacity_bytes = int(_value(candidate, "capacity_bytes", 0) or 0)
    if vulnerability_type == "out_of_bounds_read" and verdict == "overflow" and relation == "proven_oob_read":
        return "deterministic_high"
    if relation in {
        "integer_overflow_risk",
        "integer_underflow_risk",
        "signed_conversion_risk",
        "integer_truncation_risk",
    }:
        return "integer_memory_risk"
    if verdict in {"overflow", "unbounded"} and relation in {"proven_overflow", "unbounded"}:
        return "deterministic_high"
    if destination == "caller_buffer":
        return "api_contract"
    if relation == "missing_size_contract" or destination == "parameter":
        return "api_contract"
    if destination == "heap" and capacity_bytes <= 0:
        return "symbolic_heap"
    if relation in {"symbolic_offset", "symbolic_offset_size_guarded", "symbolic_size", "symbolic_capacity", "symbolic_read_offset"}:
        return "symbolic"
    if relation == "append_length_unknown":
        return "append_length"
    if relation == "iterated_alias_unproven":
        return "loop_alias"
    return "triage"


def build_policy_views(
    findings: Sequence[ClassifiedFinding],
    suppressed: Sequence[SuppressedFinding] = (),
) -> PolicyViews:
    reports: list[ClassifiedFinding] = []
    queue: list[ClassifiedFinding] = []
    tiers: dict[str, int] = {}
    for finding in findings:
        tiers[finding.triage_tier] = tiers.get(finding.triage_tier, 0) + 1
        if finding.reportable:
            reports.append(finding)
        if finding.confirmation_queue:
            queue.append(finding)
    return PolicyViews(
        deterministic_reports=reports,
        llm_queue=queue,
        debug_suppressed=list(suppressed),
        triage_tiers=dict(sorted(tiers.items())),
    )


def _value(candidate: object, key: str, default: object = "") -> object:
    if isinstance(candidate, dict):
        return candidate.get(key, default)
    return getattr(candidate, key, default)
