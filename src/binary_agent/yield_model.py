"""Transparent calibration-only empirical proof-yield model."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Sequence

from binary_agent.data.proof_specs import compile_proof_plan
from binary_agent.pipeline import CandidateState


@dataclass(frozen=True)
class YieldTrainingRecord:
    candidate_id: str
    vulnerability_type: str
    route: str
    outcome: str
    split: str = "calibration"


@dataclass(frozen=True)
class RouteYieldEstimate:
    vulnerability_type: str
    route: str
    report_probability: float
    completion_probability: float
    exact_samples: int
    route_samples: int
    source: str


@dataclass(frozen=True)
class RouteYieldModel:
    exact_counts: tuple[tuple[str, str, int, int, int], ...]
    route_counts: tuple[tuple[str, int, int, int], ...]
    training_record_sha256: str
    training_record_count: int
    training_split: str = "calibration"

    def estimate(self, vulnerability_type: str, route: str) -> RouteYieldEstimate:
        exact = next(
            ((reports, completions, total) for vuln, name, reports, completions, total in self.exact_counts if vuln == vulnerability_type and name == route),
            (0, 0, 0),
        )
        route_row = next(
            ((reports, completions, total) for name, reports, completions, total in self.route_counts if name == route),
            (0, 0, 0),
        )
        if exact[2] >= 2:
            reports, completions, total = exact
            source = "taxonomy_route"
        else:
            reports, completions, total = route_row
            source = "route_backoff" if total else "uniform_prior"
        return RouteYieldEstimate(
            vulnerability_type=vulnerability_type,
            route=route,
            report_probability=round((1.0 + reports) / (2.0 + total), 8),
            completion_probability=round((1.0 + completions) / (2.0 + total), 8),
            exact_samples=exact[2],
            route_samples=route_row[2],
            source=source,
        )

    def predictions(self, states: Sequence[CandidateState]) -> dict[str, dict[str, RouteYieldEstimate]]:
        return {
            state.candidate_id: {
                route.name: self.estimate(state.vulnerability_type, route.name)
                for route in compile_proof_plan(state).routes
            }
            for state in states
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "artifact_kind": "calibration_route_yield_model",
            "training_split": self.training_split,
            "training_record_count": self.training_record_count,
            "training_record_sha256": self.training_record_sha256,
            "prior": {"alpha": 1, "beta": 1},
            "exact_counts": [
                {"vulnerability_type": vuln, "route": route, "reports": reports, "completions": completions, "total": total}
                for vuln, route, reports, completions, total in self.exact_counts
            ],
            "route_counts": [
                {"route": route, "reports": reports, "completions": completions, "total": total}
                for route, reports, completions, total in self.route_counts
            ],
            "authority": "calibration_attempt_outcomes_only_no_expected_or_holdout_labels",
        }


def fit_route_yield_model(
    records: Sequence[YieldTrainingRecord],
    *,
    training_split: str = "calibration",
) -> RouteYieldModel:
    selected = sorted(
        (item for item in records if item.split == training_split),
        key=lambda item: (item.candidate_id, item.route, item.outcome),
    )
    exact: dict[tuple[str, str], list[int]] = {}
    routes: dict[str, list[int]] = {}
    for item in selected:
        report = int(item.outcome == "proven")
        completion = int(item.outcome in {"proven", "refuted"})
        for row in (
            exact.setdefault((item.vulnerability_type, item.route), [0, 0, 0]),
            routes.setdefault(item.route, [0, 0, 0]),
        ):
            row[0] += report
            row[1] += completion
            row[2] += 1
    serialized = json.dumps([asdict(item) for item in selected], sort_keys=True, separators=(",", ":"))
    return RouteYieldModel(
        exact_counts=tuple((vuln, route, *values) for (vuln, route), values in sorted(exact.items())),
        route_counts=tuple((route, *values) for route, values in sorted(routes.items())),
        training_record_sha256=hashlib.sha256(serialized.encode()).hexdigest(),
        training_record_count=len(selected),
        training_split=training_split,
    )
