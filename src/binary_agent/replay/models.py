"""Replay request and result schemas."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


class ReplayStatus(str, Enum):
    NOT_ATTEMPTED = "not_attempted"
    SETUP_INVALID = "setup_invalid"
    SINK_NOT_REACHED = "sink_not_reached"
    SINK_REACHED_NO_BUG = "sink_reached_no_bug"
    CRASH_UNCLASSIFIED = "crash_unclassified"
    CONFIRMED = "confirmed"
    BLOCKED = "blocked"

    @classmethod
    def normalize(cls, value: str | "ReplayStatus") -> str:
        raw = value.value if isinstance(value, ReplayStatus) else str(value or "")
        if raw not in {item.value for item in cls}:
            raise ValueError(f"Invalid replay status: {raw!r}")
        return raw


@dataclass(frozen=True)
class ReplayRequest:
    candidate_id: str
    mode: str
    setup: Mapping[str, Any]
    input: Mapping[str, Any]
    expected_result: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "mode": self.mode,
            "setup": dict(self.setup),
            "input": dict(self.input),
            "expected_result": dict(self.expected_result),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ReplayRequest":
        return cls(
            candidate_id=str(data.get("candidate_id") or ""),
            mode=str(data.get("mode") or "auto"),
            setup=dict(data.get("setup") or {}) if isinstance(data.get("setup"), Mapping) else {},
            input=dict(data.get("input") or {}) if isinstance(data.get("input"), Mapping) else {},
            expected_result=dict(data.get("expected_result") or {})
            if isinstance(data.get("expected_result"), Mapping)
            else {},
        )


@dataclass(frozen=True)
class ReplayResult:
    candidate_id: str
    result: str
    mode: str
    sink_reached: bool
    bug_observed: bool
    crash_observed: bool
    control_result: Mapping[str, Any]
    artifacts: list[str] = field(default_factory=list)
    negative_control_passed: bool | None = None
    artifact_refs: list[Mapping[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        ReplayStatus.normalize(self.result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "result": self.result,
            "mode": self.mode,
            "sink_reached": self.sink_reached,
            "bug_observed": self.bug_observed,
            "crash_observed": self.crash_observed,
            "control_result": dict(self.control_result),
            "artifacts": list(self.artifacts),
            "negative_control_passed": self.negative_control_passed,
            "artifact_refs": [dict(item) for item in self.artifact_refs],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ReplayResult":
        return cls(
            candidate_id=str(data.get("candidate_id") or ""),
            result=ReplayStatus.normalize(str(data.get("result") or ReplayStatus.NOT_ATTEMPTED.value)),
            mode=str(data.get("mode") or ""),
            sink_reached=bool(data.get("sink_reached", False)),
            bug_observed=bool(data.get("bug_observed", False)),
            crash_observed=bool(data.get("crash_observed", False)),
            control_result=dict(data.get("control_result") or {}) if isinstance(data.get("control_result"), Mapping) else {},
            artifacts=[str(item) for item in data.get("artifacts", []) or []],
            negative_control_passed=(
                bool(data["negative_control_passed"])
                if "negative_control_passed" in data and data.get("negative_control_passed") is not None
                else None
            ),
            artifact_refs=[
                dict(item)
                for item in data.get("artifact_refs", []) or []
                if isinstance(item, Mapping)
            ],
        )


def write_replay_result(result: ReplayResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return path


def load_replay_results(path: Path) -> list[ReplayResult]:
    if Path(path).is_dir():
        rows = []
        for result_path in sorted(Path(path).glob("**/result.json")):
            rows.append(ReplayResult.from_dict(json.loads(result_path.read_text() or "{}")))
        return rows
    payload = json.loads(Path(path).read_text() or "{}")
    if isinstance(payload, list):
        return [ReplayResult.from_dict(item) for item in payload if isinstance(item, Mapping)]
    rows = payload.get("replay_results", [])
    return [ReplayResult.from_dict(item) for item in rows if isinstance(item, Mapping)]
