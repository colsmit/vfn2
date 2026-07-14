"""Provider-neutral LLM hypothesis generation stage.

This module is pipeline plumbing, not a vulnerability judge.  Providers emit
candidate hypotheses; deterministic validators decide whether those hypotheses
are concrete and grounded enough to feed replay planning.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from binary_agent.analysis.confirmation import iter_evidence_packs
from binary_agent.analysis.concolic import ConcolicToolConfig
from binary_agent.analysis.llm_evaluation import (
    EVALUATION_SYSTEMS,
    HypothesisArtifact,
    build_lift_summary,
    validate_hypothesis,
)


DEFAULT_HYPOTHESIS_SYSTEMS = ("L2", "L3")
HYPOTHESIS_PROMPT_VERSION = "hypothesis-v1"
DEFAULT_HYPOTHESIS_POLICY = "blocked-only"


class HypothesisProvider(Protocol):
    """Provider interface for opt-in hypothesis generators."""

    def generate(self, evidence_pack: Mapping[str, Any], *, system: str) -> Mapping[str, Any] | Sequence[Any]:
        """Return one hypothesis JSON object, a hypotheses wrapper, or a list."""


@dataclass(frozen=True)
class ExternalCommandHypothesisProvider:
    """Run a provider command that reads one evidence pack from stdin as JSON."""

    command: Sequence[str]
    timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        if not self.command:
            raise ValueError("Hypothesis provider command must not be empty.")

    @classmethod
    def from_command_string(cls, command: str, *, timeout_seconds: float | None = None) -> "ExternalCommandHypothesisProvider":
        return cls(shlex.split(command), timeout_seconds=timeout_seconds)

    def generate(self, evidence_pack: Mapping[str, Any], *, system: str) -> Mapping[str, Any] | Sequence[Any]:
        env = dict(os.environ)
        env["BINARY_AGENT_HYPOTHESIS_SYSTEM"] = str(system)
        try:
            completed = subprocess.run(
                list(self.command),
                input=json.dumps(evidence_pack),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Hypothesis provider command timed out after {self.timeout_seconds} seconds") from exc
        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            detail = f": {stderr[:1000]}" if stderr else ""
            raise RuntimeError(f"Hypothesis provider command exited with status {completed.returncode}{detail}")
        stdout = (completed.stdout or "").strip()
        if not stdout:
            raise RuntimeError("Hypothesis provider command produced no JSON on stdout")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Hypothesis provider command produced invalid JSON: {exc}") from exc
        if not isinstance(payload, (Mapping, list, tuple)):
            raise RuntimeError("Hypothesis provider output must be a JSON object or list")
        return payload


@dataclass(frozen=True)
class FixtureHypothesisProvider:
    """Load deterministic hypothesis JSON fixtures from a directory."""

    fixtures_dir: Path

    def generate(self, evidence_pack: Mapping[str, Any], *, system: str) -> Mapping[str, Any] | Sequence[Any]:
        candidate_id = _candidate_id_from_pack(evidence_pack)
        safe = _safe_stem(candidate_id)
        system_text = str(system)
        candidates = [
            self.fixtures_dir / system_text / f"{safe}.json",
            self.fixtures_dir / system_text.lower() / f"{safe}.json",
            self.fixtures_dir / f"{system_text}_{safe}.json",
            self.fixtures_dir / f"{system_text.lower()}_{safe}.json",
            self.fixtures_dir / f"{safe}_{system_text}.json",
            self.fixtures_dir / f"{safe}_{system_text.lower()}.json",
            self.fixtures_dir / f"{safe}.json",
        ]
        for path in candidates:
            if not path.exists():
                continue
            payload = json.loads(path.read_text() or "{}")
            if not isinstance(payload, (Mapping, list, tuple)):
                raise ValueError(f"Fixture must contain a JSON object or list: {path}")
            return payload
        raise FileNotFoundError(f"No hypothesis fixture for {candidate_id} in {self.fixtures_dir}")


@dataclass(frozen=True)
class HypothesisStageResult:
    output_dir: Path
    summary_path: Path
    lift_summary_path: Path
    accepted_index_path: Path
    rejected_index_path: Path
    artifact_paths: tuple[Path, ...] = field(default_factory=tuple)
    raw_paths: tuple[Path, ...] = field(default_factory=tuple)
    accepted_artifacts: tuple[HypothesisArtifact, ...] = field(default_factory=tuple)
    rejected_artifacts: tuple[HypothesisArtifact, ...] = field(default_factory=tuple)
    summary: Mapping[str, Any] = field(default_factory=dict)
    lift_summary: Mapping[str, Any] = field(default_factory=dict)
    errors: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["output_dir"] = str(self.output_dir)
        payload["summary_path"] = str(self.summary_path)
        payload["lift_summary_path"] = str(self.lift_summary_path)
        payload["accepted_index_path"] = str(self.accepted_index_path)
        payload["rejected_index_path"] = str(self.rejected_index_path)
        payload["artifact_paths"] = [str(path) for path in self.artifact_paths]
        payload["raw_paths"] = [str(path) for path in self.raw_paths]
        payload["accepted_artifacts"] = [artifact.to_dict() for artifact in self.accepted_artifacts]
        payload["rejected_artifacts"] = [artifact.to_dict() for artifact in self.rejected_artifacts]
        payload["summary"] = dict(self.summary)
        payload["lift_summary"] = dict(self.lift_summary)
        payload["errors"] = dict(self.errors)
        return payload


def run_hypothesis_stage(
    evidence_dir: Path,
    output_dir: Path,
    *,
    provider: HypothesisProvider | None = None,
    provider_command: str | Sequence[str] | None = None,
    fixtures_dir: Path | None = None,
    systems: Sequence[str] = DEFAULT_HYPOTHESIS_SYSTEMS,
    gold_labels: Mapping[str, Any] | None = None,
    concolic_config: ConcolicToolConfig | None = None,
    provider_timeout_seconds: float | None = None,
    candidate_states: Sequence[Any] | None = None,
    replay_plan: Any | None = None,
    hypothesis_policy: str = DEFAULT_HYPOTHESIS_POLICY,
    max_hypothesis_calls_per_run: int = 32,
    max_hypothesis_calls_per_candidate: int = 1,
) -> HypothesisStageResult:
    """Generate and validate hypotheses for all evidence packs.

    If no provider or fixtures are configured, the stage writes a disabled
    summary and returns no artifacts.  Live calls are therefore always opt-in.
    """

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    normalized_systems = _normalize_systems(systems)
    all_packs = iter_evidence_packs(Path(evidence_dir)) if Path(evidence_dir).exists() else []
    packs, skipped_policy_rows = _filter_hypothesis_packs(
        all_packs,
        policy=hypothesis_policy,
        candidate_states=candidate_states or (),
        replay_plan=replay_plan,
    )
    selected_provider = _select_provider(
        provider,
        provider_command=provider_command,
        fixtures_dir=fixtures_dir,
        timeout_seconds=provider_timeout_seconds,
    )
    if selected_provider is None:
        return _write_disabled_result(
            output_dir,
            normalized_systems,
            len(all_packs),
            eligible_candidate_count=len(packs),
            skipped_policy_rows=skipped_policy_rows,
            hypothesis_policy=hypothesis_policy,
        )

    artifact_paths: list[Path] = []
    raw_paths: list[Path] = []
    accepted_rows: list[dict[str, Any]] = []
    rejected_rows: list[dict[str, Any]] = []
    accepted_artifacts: list[HypothesisArtifact] = []
    rejected_artifacts: list[HypothesisArtifact] = []
    errors: dict[str, str] = {}
    by_system: dict[str, list[HypothesisArtifact]] = {system: [] for system in normalized_systems}
    provider_call_count = 0
    provider_calls_by_candidate: dict[str, int] = {}

    for system in normalized_systems:
        system_dir = output_dir / system
        raw_dir = output_dir / "raw" / system
        system_dir.mkdir(parents=True, exist_ok=True)
        raw_dir.mkdir(parents=True, exist_ok=True)
        for pack_path, evidence_pack in packs:
            candidate_id = _candidate_id_from_pack(evidence_pack) or pack_path.stem
            safe = _safe_stem(candidate_id)
            cap_reason = _hypothesis_call_cap_reason(
                candidate_id,
                provider_call_count,
                provider_calls_by_candidate,
                max_hypothesis_calls_per_run=max_hypothesis_calls_per_run,
                max_hypothesis_calls_per_candidate=max_hypothesis_calls_per_candidate,
            )
            if cap_reason:
                artifact = _rejected_artifact(
                    candidate_id,
                    system,
                    cap_reason,
                    {"policy": hypothesis_policy, "reason": cap_reason},
                )
                by_system[system].append(artifact)
                path = _write_artifact(system_dir, safe, artifact, 1, multiple=False)
                artifact_paths.append(path)
                rejected_artifacts.append(artifact)
                rejected_rows.append(_index_row(artifact, system, path))
                continue
            try:
                provider_call_count += 1
                provider_calls_by_candidate[candidate_id] = provider_calls_by_candidate.get(candidate_id, 0) + 1
                raw_payload = selected_provider.generate(evidence_pack, system=system)
                raw_path = raw_dir / f"{safe}.json"
                raw_path.write_text(json.dumps(raw_payload, indent=2, sort_keys=True))
                raw_paths.append(raw_path)
                hypotheses = _hypotheses_from_payload(raw_payload)
            except FileNotFoundError as exc:
                artifact = _rejected_artifact(candidate_id, system, "missing_fixture", {"error": str(exc)})
                hypotheses = []
                errors[f"{system}:{candidate_id}"] = str(exc)
                by_system[system].append(artifact)
                path = _write_artifact(system_dir, safe, artifact, 1, multiple=False)
                artifact_paths.append(path)
                rejected_artifacts.append(artifact)
                rejected_rows.append(_index_row(artifact, system, path))
            except Exception as exc:
                artifact = _rejected_artifact(candidate_id, system, "provider_error", {"error": str(exc)[:1000]})
                hypotheses = []
                errors[f"{system}:{candidate_id}"] = str(exc)[:1000]
                by_system[system].append(artifact)
                path = _write_artifact(system_dir, safe, artifact, 1, multiple=False)
                artifact_paths.append(path)
                rejected_artifacts.append(artifact)
                rejected_rows.append(_index_row(artifact, system, path))

            for index, hypothesis in enumerate(hypotheses, start=1):
                artifact = validate_hypothesis(
                    evidence_pack,
                    hypothesis if isinstance(hypothesis, Mapping) else {},
                    concolic_config=concolic_config,
                    gold_labels=gold_labels or {},
                )
                artifact = _with_system(artifact, system)
                by_system[system].append(artifact)
                path = _write_artifact(system_dir, safe, artifact, index, multiple=len(hypotheses) > 1)
                artifact_paths.append(path)
                row = _index_row(artifact, system, path)
                if artifact.accepted:
                    accepted_artifacts.append(artifact)
                    accepted_rows.append(row)
                else:
                    rejected_artifacts.append(artifact)
                    rejected_rows.append(row)

    cost_totals = _aggregate_artifact_costs([*accepted_artifacts, *rejected_artifacts])
    summary_path = output_dir / "summary.json"
    summary = {
        "schema_version": 1,
        "enabled": True,
        "provider": type(selected_provider).__name__,
        "prompt_version": HYPOTHESIS_PROMPT_VERSION,
        "model": cost_totals["models"][0] if len(cost_totals["models"]) == 1 else "",
        "models": cost_totals["models"],
        "endpoint_profile": cost_totals["endpoint_profiles"][0] if len(cost_totals["endpoint_profiles"]) == 1 else "",
        "endpoint_profiles": cost_totals["endpoint_profiles"],
        "candidate_count": len(all_packs),
        "eligible_candidate_count": len(packs),
        "skipped_candidate_count": len(skipped_policy_rows),
        "skipped_candidates": skipped_policy_rows,
        "hypothesis_policy": hypothesis_policy,
        "max_hypothesis_calls_per_run": max_hypothesis_calls_per_run,
        "max_hypothesis_calls_per_candidate": max_hypothesis_calls_per_candidate,
        "provider_calls": provider_call_count,
        "systems_requested": normalized_systems,
        "systems": {system: _system_metrics(artifacts) for system, artifacts in by_system.items()},
        "accepted_count": len(accepted_rows),
        "rejected_count": len(rejected_rows),
        "model_calls": cost_totals["model_calls"],
        "input_tokens": cost_totals["input_tokens"],
        "output_tokens": cost_totals["output_tokens"],
        "total_tokens": cost_totals["total_tokens"],
        "wall_time_seconds": cost_totals["wall_time_seconds"],
        "json_repair_count": cost_totals["json_repair_count"],
        "cache_hits": 0,
        "errors": errors,
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True))
    lift_summary = build_lift_summary(by_system)
    lift_summary_path = output_dir / "lift_summary.json"
    lift_summary_path.write_text(json.dumps(lift_summary, indent=2, sort_keys=True))
    accepted_index_path = output_dir / "accepted_index.json"
    rejected_index_path = output_dir / "rejected_index.json"
    accepted_index_path.write_text(json.dumps({"schema_version": 1, "accepted": accepted_rows}, indent=2, sort_keys=True))
    rejected_index_path.write_text(json.dumps({"schema_version": 1, "rejected": rejected_rows}, indent=2, sort_keys=True))
    return HypothesisStageResult(
        output_dir=output_dir,
        summary_path=summary_path,
        lift_summary_path=lift_summary_path,
        accepted_index_path=accepted_index_path,
        rejected_index_path=rejected_index_path,
        artifact_paths=tuple(artifact_paths),
        raw_paths=tuple(raw_paths),
        accepted_artifacts=tuple(accepted_artifacts),
        rejected_artifacts=tuple(rejected_artifacts),
        summary=summary,
        lift_summary=lift_summary,
        errors=errors,
    )


def load_hypothesis_artifacts(hypothesis_dir: Path) -> list[HypothesisArtifact]:
    """Load validated hypothesis artifacts from a stage output directory."""

    hypothesis_dir = Path(hypothesis_dir)
    paths: list[Path] = []
    index_path = hypothesis_dir / "accepted_index.json"
    if index_path.exists():
        payload = json.loads(index_path.read_text() or "{}")
        for entry in payload.get("accepted", []):
            if not isinstance(entry, Mapping):
                continue
            raw_path = str(entry.get("path") or "")
            if raw_path:
                paths.append(Path(raw_path))
    if not paths:
        paths = [
            path
            for path in sorted(hypothesis_dir.glob("*/*.json"))
            if path.relative_to(hypothesis_dir).parts[0] != "raw"
            and path.name not in {"summary.json", "lift_summary.json"}
        ]
    artifacts: list[HypothesisArtifact] = []
    for path in paths:
        if not path.exists():
            continue
        payload = json.loads(path.read_text() or "{}")
        if isinstance(payload, Mapping):
            artifacts.append(_artifact_from_mapping(payload))
    return artifacts


def _filter_hypothesis_packs(
    packs: Sequence[tuple[Path, Mapping[str, Any]]],
    *,
    policy: str,
    candidate_states: Sequence[Any],
    replay_plan: Any | None,
) -> tuple[list[tuple[Path, Mapping[str, Any]]], list[dict[str, Any]]]:
    normalized_policy = str(policy or DEFAULT_HYPOTHESIS_POLICY).strip().lower()
    if normalized_policy in {"always", "all"}:
        return list(packs), []
    if normalized_policy in {"off", "disabled", "none"}:
        return [], [
            {"candidate_id": _candidate_id_from_pack(pack) or path.stem, "reason": "hypothesis_policy_off"}
            for path, pack in packs
        ]
    if normalized_policy != "blocked-only":
        raise ValueError(f"Unsupported hypothesis policy: {policy!r}")
    if not candidate_states and replay_plan is None:
        return list(packs), []

    state_by_id = {_state_candidate_id(state): state for state in candidate_states if _state_candidate_id(state)}
    executable_replay_ids = _executable_replay_candidate_ids(replay_plan)
    blocked_replay_ids = _blocked_replay_candidate_ids(replay_plan)
    eligible: list[tuple[Path, Mapping[str, Any]]] = []
    skipped: list[dict[str, Any]] = []
    for path, pack in packs:
        candidate_id = _candidate_id_from_pack(pack) or path.stem
        if candidate_id in executable_replay_ids:
            skipped.append({"candidate_id": candidate_id, "reason": "concrete_replay_plan_exists"})
            continue
        if candidate_id in blocked_replay_ids:
            eligible.append((path, pack))
            continue
        state = state_by_id.get(candidate_id)
        if state is not None and not _state_is_blocked_for_hypothesis(state):
            skipped.append({"candidate_id": candidate_id, "reason": "candidate_not_blocked"})
            continue
        eligible.append((path, pack))
    return eligible, skipped


def _hypothesis_call_cap_reason(
    candidate_id: str,
    provider_call_count: int,
    provider_calls_by_candidate: Mapping[str, int],
    *,
    max_hypothesis_calls_per_run: int,
    max_hypothesis_calls_per_candidate: int,
) -> str:
    if max_hypothesis_calls_per_run >= 0 and provider_call_count >= max_hypothesis_calls_per_run:
        return "hypothesis_run_call_cap_exceeded"
    candidate_calls = int(provider_calls_by_candidate.get(candidate_id, 0))
    if max_hypothesis_calls_per_candidate >= 0 and candidate_calls >= max_hypothesis_calls_per_candidate:
        return "hypothesis_candidate_call_cap_exceeded"
    return ""


def _executable_replay_candidate_ids(replay_plan: Any | None) -> set[str]:
    result: set[str] = set()
    for selected, candidate_id, mode, blocked in _iter_replay_entry_statuses(replay_plan):
        if selected and candidate_id and mode != "off" and not blocked:
            result.add(candidate_id)
    return result


def _blocked_replay_candidate_ids(replay_plan: Any | None) -> set[str]:
    result: set[str] = set()
    for selected, candidate_id, mode, blocked in _iter_replay_entry_statuses(replay_plan):
        if selected and candidate_id and (blocked or mode == "off"):
            result.add(candidate_id)
    return result


def _iter_replay_entry_statuses(replay_plan: Any | None) -> list[tuple[bool, str, str, str]]:
    if replay_plan is None:
        return []
    entries = getattr(replay_plan, "entries", None)
    if entries is None and isinstance(replay_plan, Mapping):
        entries = replay_plan.get("entries", [])
    result: list[tuple[bool, str, str, str]] = []
    for entry in entries or []:
        if isinstance(entry, Mapping):
            selected = bool(entry.get("selected"))
            candidate_id = str(entry.get("candidate_id") or "")
            request = entry.get("request") if isinstance(entry.get("request"), Mapping) else {}
            setup = request.get("setup") if isinstance(request.get("setup"), Mapping) else {}
            blocked = str(entry.get("blocked_reason") or setup.get("blocked_reason") or "")
            mode = str(request.get("mode") or "")
        else:
            selected = bool(getattr(entry, "selected", False))
            candidate_id = str(getattr(entry, "candidate_id", "") or "")
            request = getattr(entry, "request", None)
            setup = getattr(request, "setup", {}) if request is not None else {}
            blocked = str(getattr(entry, "blocked_reason", "") or (setup.get("blocked_reason") if isinstance(setup, Mapping) else "") or "")
            mode = str(getattr(request, "mode", "") if request is not None else "")
        result.append((selected, candidate_id, mode, blocked))
    return result


def _state_is_blocked_for_hypothesis(state: Any) -> bool:
    blockers = getattr(state, "blockers", None)
    if blockers is None and isinstance(state, Mapping):
        blockers = state.get("blockers", [])
    status = str(getattr(state, "status", "") or (state.get("status", "") if isinstance(state, Mapping) else ""))
    return bool(blockers) or status in {"needs_refinement", "candidate"}


def _state_candidate_id(state: Any) -> str:
    if isinstance(state, Mapping):
        return str(state.get("candidate_id") or "")
    return str(getattr(state, "candidate_id", "") or "")


def _select_provider(
    provider: HypothesisProvider | None,
    *,
    provider_command: str | Sequence[str] | None,
    fixtures_dir: Path | None,
    timeout_seconds: float | None,
) -> HypothesisProvider | None:
    if provider is not None:
        return provider
    if provider_command:
        if isinstance(provider_command, str):
            return ExternalCommandHypothesisProvider.from_command_string(
                provider_command,
                timeout_seconds=timeout_seconds,
            )
        return ExternalCommandHypothesisProvider(list(provider_command), timeout_seconds=timeout_seconds)
    if fixtures_dir is not None:
        return FixtureHypothesisProvider(Path(fixtures_dir))
    return None


def _write_disabled_result(
    output_dir: Path,
    systems: list[str],
    candidate_count: int,
    *,
    eligible_candidate_count: int = 0,
    skipped_policy_rows: Sequence[Mapping[str, Any]] = (),
    hypothesis_policy: str = DEFAULT_HYPOTHESIS_POLICY,
) -> HypothesisStageResult:
    summary_path = output_dir / "summary.json"
    lift_summary_path = output_dir / "lift_summary.json"
    accepted_index_path = output_dir / "accepted_index.json"
    rejected_index_path = output_dir / "rejected_index.json"
    summary = {
        "schema_version": 1,
        "enabled": False,
        "reason": "no_hypothesis_provider_configured",
        "prompt_version": HYPOTHESIS_PROMPT_VERSION,
        "candidate_count": candidate_count,
        "eligible_candidate_count": eligible_candidate_count,
        "skipped_candidate_count": len(skipped_policy_rows),
        "skipped_candidates": [dict(item) for item in skipped_policy_rows],
        "hypothesis_policy": hypothesis_policy,
        "provider_calls": 0,
        "systems_requested": systems,
        "systems": {system: _system_metrics([]) for system in systems},
        "accepted_count": 0,
        "rejected_count": 0,
        "model_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "wall_time_seconds": 0.0,
        "json_repair_count": 0,
        "cache_hits": 0,
        "errors": {},
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True))
    lift_summary_path.write_text(json.dumps(build_lift_summary({system: [] for system in systems}), indent=2, sort_keys=True))
    accepted_index_path.write_text(json.dumps({"schema_version": 1, "accepted": []}, indent=2, sort_keys=True))
    rejected_index_path.write_text(json.dumps({"schema_version": 1, "rejected": []}, indent=2, sort_keys=True))
    return HypothesisStageResult(
        output_dir=output_dir,
        summary_path=summary_path,
        lift_summary_path=lift_summary_path,
        accepted_index_path=accepted_index_path,
        rejected_index_path=rejected_index_path,
        summary=summary,
        lift_summary=build_lift_summary({system: [] for system in systems}),
    )


def _normalize_systems(systems: Sequence[str]) -> list[str]:
    result: list[str] = []
    for system in systems or DEFAULT_HYPOTHESIS_SYSTEMS:
        normalized = str(system).strip().upper()
        if not normalized:
            continue
        if normalized not in EVALUATION_SYSTEMS:
            raise ValueError(f"Unsupported hypothesis system: {system!r}")
        if normalized == "D0":
            continue
        if normalized not in result:
            result.append(normalized)
    return result or list(DEFAULT_HYPOTHESIS_SYSTEMS)


def _hypotheses_from_payload(payload: Mapping[str, Any] | Sequence[Any]) -> list[Mapping[str, Any]]:
    if isinstance(payload, Mapping):
        for key in ("hypotheses", "attempts", "iterations"):
            if key in payload:
                rows = [item for item in _coerce_sequence(payload.get(key)) if isinstance(item, Mapping)]
                return rows or [payload]
        return [payload]
    return [item for item in _coerce_sequence(payload) if isinstance(item, Mapping)]


def _write_artifact(system_dir: Path, safe_candidate_id: str, artifact: HypothesisArtifact, index: int, *, multiple: bool) -> Path:
    suffix = f"_{artifact.hypothesis_kind or 'unknown'}"
    if multiple:
        suffix += f"_{index}"
    path = system_dir / f"{safe_candidate_id}{suffix}.json"
    path.write_text(json.dumps(artifact.to_dict(), indent=2, sort_keys=True))
    return path


def _index_row(artifact: HypothesisArtifact, system: str, path: Path) -> dict[str, Any]:
    return {
        "candidate_id": artifact.candidate_id,
        "system": system,
        "hypothesis_kind": artifact.hypothesis_kind,
        "path": str(path),
        "accepted": artifact.accepted,
        "failure_reason": artifact.failure_reason,
    }


def _with_system(artifact: HypothesisArtifact, system: str) -> HypothesisArtifact:
    validator = dict(artifact.validator_result)
    validator.setdefault("system", system)
    return HypothesisArtifact(
        candidate_id=artifact.candidate_id,
        hypothesis_kind=artifact.hypothesis_kind,
        proposed_setup=artifact.proposed_setup,
        proposed_inputs=artifact.proposed_inputs,
        expected_sink=artifact.expected_sink,
        assumptions=artifact.assumptions,
        validator_result=validator,
        failure_reason=artifact.failure_reason,
        cost_metadata=artifact.cost_metadata,
        raw_hypothesis=artifact.raw_hypothesis,
    )


def _rejected_artifact(candidate_id: str, system: str, reason: str, raw: Mapping[str, Any]) -> HypothesisArtifact:
    return HypothesisArtifact(
        candidate_id=candidate_id,
        hypothesis_kind="replay",
        proposed_setup={},
        proposed_inputs={},
        expected_sink={},
        assumptions=[],
        validator_result={
            "accepted": False,
            "status": "rejected",
            "system": system,
            "reason_codes": [reason],
            "failure_reason": reason,
            "details": dict(raw),
        },
        failure_reason=reason,
        cost_metadata={},
        raw_hypothesis=dict(raw),
    )


def _artifact_from_mapping(value: Mapping[str, Any]) -> HypothesisArtifact:
    return HypothesisArtifact(
        candidate_id=str(value.get("candidate_id") or ""),
        hypothesis_kind=str(value.get("hypothesis_kind") or ""),
        proposed_setup=dict(value.get("proposed_setup") or {}) if isinstance(value.get("proposed_setup"), Mapping) else {},
        proposed_inputs=dict(value.get("proposed_inputs") or {}) if isinstance(value.get("proposed_inputs"), Mapping) else {},
        expected_sink=dict(value.get("expected_sink") or {}) if isinstance(value.get("expected_sink"), Mapping) else {},
        assumptions=[str(item) for item in _coerce_sequence(value.get("assumptions", []))],
        validator_result=dict(value.get("validator_result") or {}) if isinstance(value.get("validator_result"), Mapping) else {},
        failure_reason=str(value.get("failure_reason") or ""),
        cost_metadata=dict(value.get("cost_metadata") or {}) if isinstance(value.get("cost_metadata"), Mapping) else {},
        raw_hypothesis=dict(value.get("raw_hypothesis") or {}) if isinstance(value.get("raw_hypothesis"), Mapping) else {},
    )


def _system_metrics(artifacts: Sequence[HypothesisArtifact]) -> dict[str, Any]:
    by_kind: dict[str, dict[str, int]] = {}
    for artifact in artifacts:
        counts = by_kind.setdefault(artifact.hypothesis_kind, {"accepted": 0, "rejected": 0})
        counts["accepted" if artifact.accepted else "rejected"] += 1
    return {
        "artifact_count": len(artifacts),
        "accepted": sum(1 for artifact in artifacts if artifact.accepted),
        "rejected": sum(1 for artifact in artifacts if not artifact.accepted),
        "replay_ready": sum(1 for artifact in artifacts if artifact.hypothesis_kind == "replay" and artifact.accepted),
        "environment_covered": sum(1 for artifact in artifacts if artifact.hypothesis_kind == "environment" and artifact.accepted),
        "branch_guidance_valid": sum(1 for artifact in artifacts if artifact.hypothesis_kind == "branch_guidance" and artifact.accepted),
        "triage_accepted": sum(1 for artifact in artifacts if artifact.hypothesis_kind == "triage" and artifact.accepted),
        "missing_fixture": sum(1 for artifact in artifacts if artifact.failure_reason == "missing_fixture"),
        "by_kind": by_kind,
    }


def _aggregate_artifact_costs(artifacts: Sequence[HypothesisArtifact]) -> dict[str, Any]:
    totals = {
        "model_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "wall_time_seconds": 0.0,
        "json_repair_count": 0,
        "models": [],
        "endpoint_profiles": [],
    }
    for artifact in artifacts:
        cost = artifact.cost_metadata
        totals["model_calls"] += _safe_int(cost.get("model_calls"), 0)
        totals["input_tokens"] += _safe_int(cost.get("input_tokens"), 0)
        totals["output_tokens"] += _safe_int(cost.get("output_tokens"), 0)
        total_tokens = _safe_int(cost.get("total_tokens"), 0)
        if total_tokens <= 0:
            total_tokens = _safe_int(cost.get("input_tokens"), 0) + _safe_int(cost.get("output_tokens"), 0)
        totals["total_tokens"] += total_tokens
        try:
            totals["wall_time_seconds"] += float(cost.get("wall_time_seconds") or 0.0)
        except (TypeError, ValueError):
            pass
        totals["json_repair_count"] += _safe_int(cost.get("json_repair_count"), 0)
        model = str(cost.get("model") or "").strip()
        if model and model not in totals["models"]:
            totals["models"].append(model)
        endpoint_profile = str(cost.get("endpoint_profile") or "").strip()
        if endpoint_profile and endpoint_profile not in totals["endpoint_profiles"]:
            totals["endpoint_profiles"].append(endpoint_profile)
    return totals


def _candidate_id_from_pack(evidence_pack: Mapping[str, Any]) -> str:
    candidate_id = str(evidence_pack.get("candidate_id") or "").strip()
    if candidate_id:
        return candidate_id
    candidate = evidence_pack.get("candidate")
    if isinstance(candidate, Mapping):
        candidate_id = str(candidate.get("candidate_id") or "").strip()
        if candidate_id:
            return candidate_id
    candidate = evidence_pack.get("deterministic_candidate")
    if isinstance(candidate, Mapping):
        return str(candidate.get("candidate_id") or "").strip()
    return ""


def _safe_stem(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in str(value))[:120] or "candidate"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return default


def _coerce_sequence(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray)):
        return [value]
    if isinstance(value, Sequence):
        return list(value)
    return [value]
