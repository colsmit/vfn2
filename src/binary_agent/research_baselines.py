"""Post-hoc baseline and ablation scoring over one frozen evaluation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.research_metrics import CaseOutcome, compute_research_metrics


BASELINE_POLICIES = (
    "candidate_only",
    "static_exact",
    "crash_only",
    "angr_only",
    "ghidra_only",
    "proof_gated",
    "llm_assisted",
)


@dataclass(frozen=True)
class BaselineResult:
    policy: str
    status: str
    cases: tuple[Mapping[str, Any], ...]
    metrics: Mapping[str, Any]
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "status": self.status,
            "reason": self.reason,
            "cases": [dict(item) for item in self.cases],
            "metrics": dict(self.metrics),
        }


def run_research_baselines(evaluation: Path, output_dir: Path) -> dict[str, Any]:
    evaluation_path = Path(evaluation).expanduser().resolve()
    if evaluation_path.is_dir():
        evaluation_path = evaluation_path / "research_evaluation_summary.json"
    payload = _load_json(evaluation_path)
    raw_cases = [dict(item) for item in payload.get("cases", []) if isinstance(item, Mapping)]
    results: list[BaselineResult] = []
    for policy in BASELINE_POLICIES:
        if policy == "llm_assisted" and not _has_live_llm_evidence(raw_cases):
            results.append(BaselineResult(policy, "skipped_missing_input", (), {}, "no_live_llm_artifacts"))
            continue
        rows: list[dict[str, Any]] = []
        outcomes: list[CaseOutcome] = []
        for case in raw_cases:
            decision, evidence_count, blockers = _baseline_decision(policy, case)
            row = {
                "id": str(case.get("id") or ""),
                "lane": str(case.get("lane") or ""),
                "decision": decision,
                "evidence_count": evidence_count,
                "blockers": list(blockers),
            }
            rows.append(row)
            outcomes.append(
                CaseOutcome(
                    case_id=row["id"],
                    lane=row["lane"],
                    decision=decision,
                    candidate_count=int(case.get("candidate_count") or 0),
                    attempted_proofs=int(case.get("attempted_proofs") or 0),
                    completed_proofs=evidence_count,
                    report_count=1 if decision in {"reported", "false_positive"} else 0,
                    wall_seconds=float(case.get("wall_seconds") or 0.0),
                    cpu_seconds=float(case.get("cpu_seconds") or 0.0),
                    blockers=blockers,
                )
            )
        results.append(
            BaselineResult(
                policy,
                "completed",
                tuple(rows),
                compute_research_metrics(outcomes).to_dict(),
            )
        )
    summary = {
        "schema_version": 1,
        "artifact_kind": "research_baseline_comparison",
        "evaluation_path": str(evaluation_path),
        "corpus_id": str(payload.get("corpus_id") or ""),
        "baselines": [item.to_dict() for item in results],
    }
    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "research_baselines.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def _baseline_decision(policy: str, case: Mapping[str, Any]) -> tuple[str, int, tuple[str, ...]]:
    lane = str(case.get("lane") or "")
    run_dir_raw = str(case.get("run_dir") or "")
    run_dir = Path(run_dir_raw) if run_dir_raw else Path("/__missing_research_run__")
    positive = False
    evidence_count = 0
    if int(case.get("returncode") or 0) != 0 or not run_dir.is_dir():
        prior = tuple(str(item) for item in case.get("blockers", []) if str(item))
        return "blocked", 0, prior or ("evaluation_incomplete",)
    if policy == "proof_gated":
        prior = tuple(str(item) for item in case.get("blockers", []) if str(item))
        return str(case.get("decision") or "blocked"), int(case.get("completed_proofs") or 0), prior
    if policy == "candidate_only":
        if not (run_dir / "discovery" / "candidates.json").is_file():
            return "blocked", 0, ("candidate_artifact_missing",)
        evidence_count = int(case.get("candidate_count") or 0)
        positive = evidence_count > 0
    elif policy == "static_exact":
        if not (run_dir / "discovery" / "candidates.json").is_file():
            return "blocked", 0, ("candidate_artifact_missing",)
        candidates = _json_rows(run_dir / "discovery" / "candidates.json", "candidates")
        exact = [item for item in candidates if _exact_candidate(item)]
        evidence_count = len(exact)
        positive = bool(exact)
    elif policy == "crash_only":
        replay_rows = [_load_json(path) for path in run_dir.glob("replay/**/result.json")]
        if not replay_rows:
            return "blocked", 0, ("replay_artifact_missing",)
        evidence_count = sum(bool(item.get("crash_observed") or item.get("bug_observed")) for item in replay_rows)
        positive = evidence_count > 0
    elif policy == "angr_only":
        verdicts = [_load_json(path) for path in run_dir.glob("proof/**/verdict.json")]
        if not verdicts:
            return "blocked", 0, ("angr_verdict_missing",)
        decisive = {
            "overflow_witness",
            "memory_violation_witness",
            "crash_reproduced",
        }
        evidence_count = sum(str(item.get("concolic_verdict") or "") in decisive for item in verdicts)
        positive = evidence_count > 0
        if not positive and all(str(item.get("concolic_verdict") or "") in {"timeout", "backend_error", ""} for item in verdicts):
            return "blocked", 0, ("angr_incomplete",)
    elif policy == "ghidra_only":
        proofs = [_load_json(path) for path in run_dir.glob("proof/**/ghidra_dynamic_proof.json")]
        if not proofs:
            return "blocked", 0, ("ghidra_proof_missing",)
        evidence_count = sum(str(item.get("status") or "").endswith("_proven") for item in proofs)
        positive = evidence_count > 0
        if not positive and all(str(item.get("status") or "") in {"", "unsupported", "timeout", "inconclusive"} for item in proofs):
            return "blocked", 0, ("ghidra_incomplete",)
    elif policy == "llm_assisted":
        actions = [_load_json(path) for path in run_dir.glob("proof/**/llm_actions.json")]
        if not actions:
            return "blocked", 0, ("llm_artifact_missing",)
        evidence_count = sum(int(item.get("accepted_count") or 0) for item in actions)
        positive = evidence_count > 0
    else:
        raise ValueError(f"unsupported baseline policy: {policy}")
    if positive:
        return ("reported" if lane == "vulnerable" else "false_positive"), evidence_count, ()
    return ("missed" if lane == "vulnerable" else "clean"), evidence_count, ()


def _exact_candidate(item: Mapping[str, Any]) -> bool:
    operation = item.get("operation") if isinstance(item.get("operation"), Mapping) else {}
    sink = item.get("sink") if isinstance(item.get("sink"), Mapping) else {}
    location = item.get("location") if isinstance(item.get("location"), Mapping) else {}
    operation_address = str(operation.get("address") or sink.get("operation_address") or "")
    function_address = str(location.get("address") or "")
    return bool(operation_address and operation_address.lower() != function_address.lower())


def _has_live_llm_evidence(cases: Sequence[Mapping[str, Any]]) -> bool:
    for case in cases:
        run_dir = Path(str(case.get("run_dir") or ""))
        for path in run_dir.glob("proof/**/llm_actions.json"):
            payload = _load_json(path)
            if int(payload.get("model_calls") or payload.get("provider_calls") or 0) > 0:
                return True
    return False


def _json_rows(path: Path, key: str) -> list[dict[str, Any]]:
    payload = _load_json(path)
    rows = payload.get(key)
    return [dict(item) for item in rows if isinstance(item, Mapping)] if isinstance(rows, list) else []


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text() or "{}")
    except (OSError, json.JSONDecodeError):
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}
