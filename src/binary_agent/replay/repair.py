"""Provider-neutral replay repair loop."""

from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from binary_agent.analysis.llm_evaluation import HypothesisArtifact, validate_hypothesis
from binary_agent.replay.conversion import replay_request_from_llm_artifact
from binary_agent.replay.models import ReplayRequest, ReplayResult, ReplayStatus
from binary_agent.replay.runners import run_replay_request


class ReplayRepairProvider(Protocol):
    """Minimal interface for an opt-in repair provider."""

    def propose_repair(self, failure_summary: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return a replay/environment hypothesis JSON object."""


@dataclass(frozen=True)
class ExternalCommandReplayRepairProvider:
    """Run a repair provider command over one failed replay summary."""

    command: Sequence[str]
    timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        if not self.command:
            raise ValueError("Repair provider command must not be empty.")

    @classmethod
    def from_command_string(
        cls,
        command: str,
        *,
        timeout_seconds: float | None = None,
    ) -> "ExternalCommandReplayRepairProvider":
        return cls(shlex.split(command), timeout_seconds=timeout_seconds)

    def propose_repair(self, failure_summary: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            completed = subprocess.run(
                list(self.command),
                input=json.dumps(failure_summary),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Repair provider command timed out after {self.timeout_seconds} seconds") from exc
        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            detail = f": {stderr[:1000]}" if stderr else ""
            raise RuntimeError(f"Repair provider command exited with status {completed.returncode}{detail}")
        stdout = (completed.stdout or "").strip()
        if not stdout:
            raise RuntimeError("Repair provider command produced no JSON on stdout")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Repair provider command produced invalid JSON: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise RuntimeError("Repair provider command must output a JSON object")
        return payload


@dataclass(frozen=True)
class ReplayRepairAttempt:
    attempt: int
    candidate_id: str
    accepted: bool
    failure_reason: str
    hypothesis_artifact: Mapping[str, Any]
    replay_request: Mapping[str, Any] = field(default_factory=dict)
    replay_result: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReplayRepairResult:
    candidate_id: str
    attempts: list[ReplayRepairAttempt]
    final_result: Mapping[str, Any]
    attempts_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "final_result": dict(self.final_result),
            "attempts_path": self.attempts_path,
        }


def summarize_failed_replay(request: ReplayRequest, result: ReplayResult) -> dict[str, Any]:
    """Build a compact, provider-neutral summary of a failed replay."""

    return {
        "candidate_id": request.candidate_id,
        "request": request.to_dict(),
        "result": result.to_dict(),
        "failure": {
            "status": result.result,
            "sink_reached": result.sink_reached,
            "bug_observed": result.bug_observed,
            "crash_observed": result.crash_observed,
            "reason": result.control_result.get("reason", "") if isinstance(result.control_result, Mapping) else "",
        },
        "repair_contract": {
            "accepted_hypothesis_kinds": ["replay", "environment"],
            "must_be_concrete": True,
            "validator_remains_authoritative": True,
        },
    }


def repair_replay(
    evidence_pack: Mapping[str, Any],
    initial_request: ReplayRequest,
    initial_result: ReplayResult,
    provider: ReplayRepairProvider,
    output_dir: Path,
    *,
    max_attempts: int = 2,
) -> ReplayRepairResult:
    """Validate provider repairs, rerun replay, and record every attempt."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    attempts: list[ReplayRepairAttempt] = []
    previous_request = initial_request
    previous_result = initial_result
    final_result: ReplayResult = initial_result
    for attempt_number in range(1, max(0, max_attempts) + 1):
        summary = summarize_failed_replay(previous_request, previous_result)
        proposal = provider.propose_repair(summary)
        artifact = validate_hypothesis(evidence_pack, proposal)
        if not artifact.accepted:
            attempts.append(_repair_attempt(attempt_number, artifact, None, None))
            continue
        try:
            request = replay_request_from_llm_artifact(
                artifact,
                binary_path=previous_request.setup.get("binary_path") if isinstance(previous_request.setup, Mapping) else None,
                default_mode=previous_request.mode or "native",
            )
        except ValueError as exc:
            rejected = _artifact_with_failure(artifact, str(exc))
            attempts.append(_repair_attempt(attempt_number, rejected, None, None))
            continue
        result = run_replay_request(request, output_dir / f"attempt_{attempt_number}")
        attempts.append(_repair_attempt(attempt_number, artifact, request, result))
        previous_request = request
        previous_result = result
        final_result = result
        if result.result == ReplayStatus.CONFIRMED.value and result.sink_reached and result.bug_observed:
            break

    attempts_path = output_dir / "repair_attempts.json"
    repair_result = ReplayRepairResult(
        candidate_id=initial_request.candidate_id,
        attempts=attempts,
        final_result=final_result.to_dict(),
        attempts_path=str(attempts_path),
    )
    attempts_path.write_text(json.dumps(repair_result.to_dict(), indent=2, sort_keys=True))
    return repair_result


def _repair_attempt(
    attempt_number: int,
    artifact: HypothesisArtifact,
    request: ReplayRequest | None,
    result: ReplayResult | None,
) -> ReplayRepairAttempt:
    return ReplayRepairAttempt(
        attempt=attempt_number,
        candidate_id=artifact.candidate_id,
        accepted=artifact.accepted,
        failure_reason=artifact.failure_reason,
        hypothesis_artifact=artifact.to_dict(),
        replay_request=request.to_dict() if request is not None else {},
        replay_result=result.to_dict() if result is not None else {},
    )


def _artifact_with_failure(artifact: HypothesisArtifact, failure_reason: str) -> HypothesisArtifact:
    validator = dict(artifact.validator_result)
    validator.update({"accepted": False, "status": "rejected", "failure_reason": failure_reason})
    return HypothesisArtifact(
        candidate_id=artifact.candidate_id,
        hypothesis_kind=artifact.hypothesis_kind,
        proposed_setup=artifact.proposed_setup,
        proposed_inputs=artifact.proposed_inputs,
        expected_sink=artifact.expected_sink,
        assumptions=artifact.assumptions,
        validator_result=validator,
        failure_reason=failure_reason,
        cost_metadata=artifact.cost_metadata,
        raw_hypothesis=artifact.raw_hypothesis,
    )
