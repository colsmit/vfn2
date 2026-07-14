"""Coverage-conditioned metrics for bounded binary vulnerability experiments."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence


COMPLETED_DECISIONS = frozenset({"reported", "clean", "missed", "false_positive"})


@dataclass(frozen=True)
class CaseOutcome:
    case_id: str
    lane: str
    decision: str
    candidate_count: int = 0
    attempted_proofs: int = 0
    completed_proofs: int = 0
    report_count: int = 0
    wall_seconds: float = 0.0
    cpu_seconds: float = 0.0
    blockers: tuple[str, ...] = ()
    time_to_first_proof_seconds: float | None = None


@dataclass(frozen=True)
class ResearchMetrics:
    selected_cases: int
    completed_cases: int
    blocked_cases: int
    unattempted_cases: int
    positive_cases: int
    negative_cases: int
    completed_positives: int
    completed_negatives: int
    detected_positives: int
    false_positive_negatives: int
    coverage: float
    positive_coverage: float
    negative_coverage: float
    conditional_recall: float | None
    conditional_false_positive_rate: float | None
    candidates: int
    attempted_proofs: int
    completed_proofs: int
    reports: int
    wall_seconds: float
    cpu_seconds: float
    proven_reports_per_cpu_hour: float | None
    candidates_per_completed_proof: float | None
    proofs_per_report: float | None
    time_to_first_proof_seconds: float | None
    blocker_counts: Mapping[str, int]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["schema_version"] = 1
        payload["artifact_kind"] = "research_scale_metrics"
        payload["blocker_counts"] = dict(self.blocker_counts)
        return payload


def compute_research_metrics(outcomes: Sequence[CaseOutcome]) -> ResearchMetrics:
    rows = tuple(outcomes)
    positives = [item for item in rows if item.lane == "vulnerable"]
    negatives = [item for item in rows if item.lane == "fixed"]
    completed = [item for item in rows if item.decision in COMPLETED_DECISIONS]
    completed_positives = [item for item in positives if item.decision in COMPLETED_DECISIONS]
    completed_negatives = [item for item in negatives if item.decision in COMPLETED_DECISIONS]
    detected = sum(item.decision == "reported" for item in completed_positives)
    false_positives = sum(item.decision == "false_positive" for item in completed_negatives)
    reports = sum(item.report_count for item in rows)
    cpu_seconds = sum(max(0.0, item.cpu_seconds) for item in rows)
    completed_proofs = sum(max(0, item.completed_proofs) for item in rows)
    attempted = sum(max(0, item.attempted_proofs) for item in rows)
    candidates = sum(max(0, item.candidate_count) for item in rows)
    proof_times = [
        float(item.time_to_first_proof_seconds)
        for item in rows
        if item.time_to_first_proof_seconds is not None
    ]
    blockers = Counter(blocker for item in rows for blocker in item.blockers if blocker)
    return ResearchMetrics(
        selected_cases=len(rows),
        completed_cases=len(completed),
        blocked_cases=sum(item.decision == "blocked" for item in rows),
        unattempted_cases=sum(item.decision == "unattempted" for item in rows),
        positive_cases=len(positives),
        negative_cases=len(negatives),
        completed_positives=len(completed_positives),
        completed_negatives=len(completed_negatives),
        detected_positives=detected,
        false_positive_negatives=false_positives,
        coverage=_ratio(len(completed), len(rows)),
        positive_coverage=_ratio(len(completed_positives), len(positives)),
        negative_coverage=_ratio(len(completed_negatives), len(negatives)),
        conditional_recall=_optional_ratio(detected, len(completed_positives)),
        conditional_false_positive_rate=_optional_ratio(false_positives, len(completed_negatives)),
        candidates=candidates,
        attempted_proofs=attempted,
        completed_proofs=completed_proofs,
        reports=reports,
        wall_seconds=round(sum(max(0.0, item.wall_seconds) for item in rows), 6),
        cpu_seconds=round(cpu_seconds, 6),
        proven_reports_per_cpu_hour=(round(reports * 3600.0 / cpu_seconds, 6) if cpu_seconds > 0 else None),
        candidates_per_completed_proof=(round(candidates / completed_proofs, 6) if completed_proofs else None),
        proofs_per_report=(round(attempted / reports, 6) if reports else None),
        time_to_first_proof_seconds=min(proof_times) if proof_times else None,
        blocker_counts=dict(sorted(blockers.items())),
    )


def case_outcome_from_mapping(value: Mapping[str, Any]) -> CaseOutcome:
    return CaseOutcome(
        case_id=str(value.get("id") or value.get("case_id") or ""),
        lane=str(value.get("lane") or ""),
        decision=str(value.get("decision") or "blocked"),
        candidate_count=int(value.get("candidate_count") or 0),
        attempted_proofs=int(value.get("attempted_proofs") or 0),
        completed_proofs=int(value.get("completed_proofs") or 0),
        report_count=int(value.get("report_count") or 0),
        wall_seconds=float(value.get("wall_seconds") or 0.0),
        cpu_seconds=float(value.get("cpu_seconds") or 0.0),
        blockers=tuple(str(item) for item in value.get("blockers", []) if str(item)),
        time_to_first_proof_seconds=(
            float(value["time_to_first_proof_seconds"])
            if value.get("time_to_first_proof_seconds") is not None
            else None
        ),
    )


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _optional_ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None
