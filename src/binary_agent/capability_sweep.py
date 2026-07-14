"""Capability sweep harness for proof-gated analyzer milestones."""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from binary_agent.analysis.confirmation import iter_evidence_packs
from binary_agent.analysis.witness import write_witness_plans_for_evidence_dir
from binary_agent.cli.run_pipeline import run_pipeline
from binary_agent.dynamic_proof import DYNAMIC_MEMORY_PROOF_STATUSES, first_ghidra_dynamic_proof
from binary_agent.intake import run_intake
from binary_agent.pipeline import CandidateState, build_bug_bounty_evidence, build_source_to_sink_trace, load_candidate_states
from binary_agent.reporting import AnalysisReport, ReportConfig, VulnerabilityReport, save_report_json
from binary_agent.utils.time import utc_timestamp
from binary_agent.taxonomy import VULNERABILITY_SPECS


CAPABILITY_SWEEP_SUMMARY = "capability_sweep_summary.json"
CAPABILITY_SWEEP_ROWS = "capability_sweep_targets.json"
NEGATIVE_PRECISION_AUDIT = "negative_precision_audit.json"
POSITIVE_EXPECTATION_AUDIT = "positive_expectation_audit.json"
CAPABILITY_SWEEP_SUMMARY_ARTIFACT_KIND = "capability_sweep_summary"
CAPABILITY_SWEEP_ROWS_ARTIFACT_KIND = "capability_sweep_targets"
CAPABILITY_SWEEP_ROW_ARTIFACT_KIND = "capability_sweep_row"
NEGATIVE_PRECISION_AUDIT_ARTIFACT_KIND = "negative_precision_audit"
POSITIVE_EXPECTATION_AUDIT_ARTIFACT_KIND = "positive_expectation_audit"
CAPABILITY_MATRIX = "capability_matrix.json"
CAPABILITY_MATRIX_ARTIFACT_KIND = "capability_matrix"
PROOF_BLOCKER_INVENTORY = "proof_blocker_inventory.json"
PROOF_BLOCKER_INVENTORY_ARTIFACT_KIND = "proof_blocker_inventory"
BLOCKER_STAGE_ORDER = (
    "detection_gap",
    "exact_sink",
    "input_topology",
    "process_trigger",
    "runtime_semantics",
    "exploration",
    "proof_relation",
)
SEMANTIC_DYNAMIC_ORACLE_KINDS = frozenset(
    spec.effect_kind
    for spec in VULNERABILITY_SPECS.values()
    if spec.backend == "semantic_effect" and spec.effect_kind
)


@dataclass(frozen=True)
class CapabilitySweepTarget:
    id: str
    label: str = ""
    export_dir: str = ""
    binary_path: str = ""
    rootfs_path: str = ""
    intake_dir: str = ""
    artifact_dir: str = ""
    analysis_report_path: str = ""
    evidence_dir: str = ""
    expected_positives: tuple[str, ...] = ()
    expected_negatives: tuple[str, ...] = ()
    replay_mode: str = "off"
    dynamic_confirm: bool = False
    report_policy: str = "confirmed"
    optional: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, base_dir: Path) -> "CapabilitySweepTarget":
        raw_id = str(data.get("id") or data.get("name") or data.get("label") or data.get("binary") or data.get("export_dir") or "target")
        export_dir = _path_text(data.get("export_dir") or data.get("export_path"), base_dir=base_dir)
        binary_path = _path_text(data.get("binary_path") or data.get("binary") or data.get("path"), base_dir=base_dir)
        rootfs_path = _path_text(data.get("rootfs_path") or data.get("rootfs"), base_dir=base_dir)
        intake_dir = _path_text(data.get("intake_dir") or data.get("intake"), base_dir=base_dir)
        artifact_dir = _path_text(data.get("artifact_dir") or data.get("run_dir"), base_dir=base_dir)
        analysis_report_path = _path_text(
            data.get("analysis_report_path") or data.get("analysis_report") or data.get("report_json"),
            base_dir=base_dir,
        )
        evidence_dir = _path_text(data.get("evidence_dir") or data.get("evidence_packs"), base_dir=base_dir)
        return cls(
            id=_safe_name(raw_id),
            label=str(data.get("label") or data.get("kind") or ""),
            export_dir=export_dir,
            binary_path=binary_path,
            rootfs_path=rootfs_path,
            intake_dir=intake_dir,
            artifact_dir=artifact_dir,
            analysis_report_path=analysis_report_path,
            evidence_dir=evidence_dir,
            expected_positives=tuple(str(item) for item in _sequence(data.get("expected_positives"))),
            expected_negatives=tuple(str(item) for item in _sequence(data.get("expected_negatives"))),
            replay_mode=str(data.get("replay_mode") or "off"),
            dynamic_confirm=bool(data.get("dynamic_confirm", False)),
            report_policy=str(data.get("report_policy") or "confirmed"),
            optional=bool(data.get("optional", False)),
            metadata={str(key): value for key, value in data.items() if key not in _TARGET_FIELDS},
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["expected_positives"] = list(self.expected_positives)
        payload["expected_negatives"] = list(self.expected_negatives)
        payload["metadata"] = dict(self.metadata)
        return payload


@dataclass(frozen=True)
class CapabilitySweepRow:
    id: str
    label: str
    export_dir: str = ""
    binary_path: str = ""
    rootfs_path: str = ""
    intake_dir: str = ""
    artifact_dir: str = ""
    analysis_report_path: str = ""
    evidence_dir: str = ""
    witness_plan_dir: str = ""
    report_path: str = ""
    negative_audit_path: str = ""
    positive_audit_path: str = ""
    target_provenance: Mapping[str, Any] = field(default_factory=dict)
    candidates: int = 0
    confirmations: int = 0
    confirmed_bugs: int = 0
    proof_ready_count: int = 0
    dynamic_proofs: int = 0
    rejected_negatives: int = 0
    blocked_negatives: int = 0
    unsupported_blockers: int = 0
    reports: int = 0
    runtime_seconds: float = 0.0
    false_positive_notes: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    artifact_kind: str = CAPABILITY_SWEEP_ROW_ARTIFACT_KIND
    schema_version: int = 2

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CapabilitySweepSummary:
    output_dir: Path
    rows: tuple[CapabilitySweepRow, ...]
    generated_at: str = field(default_factory=utc_timestamp)
    schema_version: int = 2

    @property
    def totals(self) -> dict[str, Any]:
        fields = (
            "candidates",
            "confirmations",
            "confirmed_bugs",
            "proof_ready_count",
            "dynamic_proofs",
            "rejected_negatives",
            "blocked_negatives",
            "unsupported_blockers",
            "reports",
        )
        totals = {field: sum(int(getattr(row, field)) for row in self.rows) for field in fields}
        totals["runtime_seconds"] = round(sum(float(row.runtime_seconds) for row in self.rows), 4)
        totals["targets_with_errors"] = sum(1 for row in self.rows if row.errors)
        totals["false_positive_notes"] = sum(len(row.false_positive_notes) for row in self.rows)
        totals["expected_positives"] = sum(_metadata_int(row, "expected_positive_count") for row in self.rows)
        totals["matched_expected_positives"] = sum(
            _metadata_int(row, "matched_expected_positive_count") for row in self.rows
        )
        totals["missing_expected_positives"] = sum(
            _metadata_int(row, "missing_expected_positive_count") for row in self.rows
        )
        totals["blocked_expected_positives"] = sum(
            _metadata_int(row, "blocked_expected_positive_count") for row in self.rows
        )
        totals["evidence_packs"] = sum(_metadata_int(row, "evidence_pack_count") for row in self.rows)
        totals["witness_plans"] = sum(_metadata_int(row, "witness_plan_count") for row in self.rows)
        totals["witness_plan_missing_count"] = sum(_metadata_int(row, "witness_plan_missing_count") for row in self.rows)
        totals["source_to_sink_traces"] = sum(_metadata_int(row, "source_to_sink_trace_count") for row in self.rows)
        totals["source_to_sink_report_ready_trace_missing_count"] = sum(
            _metadata_int(row, "source_to_sink_report_ready_trace_missing_count") for row in self.rows
        )
        totals["source_to_sink_report_ready_trace_incomplete_count"] = sum(
            _metadata_int(row, "source_to_sink_report_ready_trace_incomplete_count") for row in self.rows
        )
        totals["dynamic_proof_status_counts"] = _aggregate_metadata_counts(self.rows, "dynamic_proof_status_counts")
        totals["dynamic_memory_proof_status_counts"] = _aggregate_metadata_counts(
            self.rows,
            "dynamic_memory_proof_status_counts",
        )
        totals["dynamic_semantic_observed_kind_counts"] = _aggregate_metadata_counts(
            self.rows,
            "dynamic_semantic_observed_kind_counts",
        )
        totals["dynamic_semantic_observation_status_counts"] = _aggregate_metadata_counts(
            self.rows,
            "dynamic_semantic_observation_status_counts",
        )
        totals["dynamic_semantic_observation_count"] = sum(
            _metadata_int(row, "dynamic_semantic_observation_count") for row in self.rows
        )
        totals["dynamic_semantic_not_observed_count"] = sum(
            _metadata_int(row, "dynamic_semantic_not_observed_count") for row in self.rows
        )
        totals["process_witness_attempts"] = sum(_metadata_int(row, "process_witness_attempts") for row in self.rows)
        totals["process_witness_observed"] = sum(_metadata_int(row, "process_witness_observed") for row in self.rows)
        totals["process_witness_unsupported"] = sum(
            _metadata_int(row, "process_witness_unsupported") for row in self.rows
        )
        totals["process_witness_blocked"] = sum(_metadata_int(row, "process_witness_blocked") for row in self.rows)
        totals["process_witness_status_counts"] = _aggregate_metadata_counts(
            self.rows,
            "process_witness_status_counts",
        )
        totals["process_witness_input_model_counts"] = _aggregate_metadata_counts(
            self.rows,
            "process_witness_input_model_counts",
        )
        totals["process_witness_blocker_counts"] = _aggregate_metadata_counts(
            self.rows,
            "process_witness_blocker_counts",
        )
        totals["blocker_category_counts"] = _aggregate_metadata_counts(self.rows, "blocker_category_counts")
        totals["capability_matrix_status_counts"] = _aggregate_metadata_counts(
            self.rows,
            "capability_matrix_status_counts",
        )
        return totals

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_kind": CAPABILITY_SWEEP_SUMMARY_ARTIFACT_KIND,
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "target_count": len(self.rows),
            "output_dir": str(self.output_dir),
            "totals": self.totals,
            "targets": [row.to_dict() for row in self.rows],
        }

    def write(self) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        rows_path = self.output_dir / CAPABILITY_SWEEP_ROWS
        rows_path.write_text(
            json.dumps(
                {
                    "artifact_kind": CAPABILITY_SWEEP_ROWS_ARTIFACT_KIND,
                    "schema_version": self.schema_version,
                    "generated_at": self.generated_at,
                    "targets": [row.to_dict() for row in self.rows],
                },
                indent=2,
                sort_keys=True,
            )
        )
        summary_path = self.output_dir / CAPABILITY_SWEEP_SUMMARY
        summary_path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))
        inventory = build_proof_blocker_inventory(self.rows)
        (self.output_dir / PROOF_BLOCKER_INVENTORY).write_text(json.dumps(inventory, indent=2, sort_keys=True))
        return summary_path


def build_proof_blocker_inventory(rows: Sequence[CapabilitySweepRow | Mapping[str, Any]]) -> dict[str, Any]:
    """Build an expectation-scoped blocker inventory without global artifact leakage.

    Target diagnostics are useful operational context but are deliberately not
    selectable.  Selection is driven only by one row for each unresolved
    expected-positive case, backed by matching candidate-state evidence when a
    candidate exists.
    """

    normalized_rows = [row.to_dict() if isinstance(row, CapabilitySweepRow) else dict(row) for row in rows]
    entries: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for manifest_index, row in enumerate(normalized_rows):
        metadata = _mapping(row.get("metadata"))
        scoped = _mapping_rows(metadata.get("proof_blocker_inventory_rows"))
        # An explicitly emitted empty list means this target has no unresolved
        # candidates.  Do not resurrect a synthetic legacy row for a clean
        # fixed control merely because its scoped inventory is empty.
        if "proof_blocker_inventory_rows" in metadata:
            for item in scoped:
                entry = dict(item)
                entry.setdefault("target_id", str(row.get("id") or ""))
                entry.setdefault("manifest_index", manifest_index)
                entry.setdefault("lane", _target_lane(row))
                entry.setdefault("vulnerability_family", str(metadata.get("vulnerability_family") or "unknown"))
                entry.setdefault("input_model", str(metadata.get("input_model") or "unknown"))
                entry.setdefault("comparison_group", _comparison_group(entry["target_id"], metadata))
                entry.setdefault("record_kind", "unresolved_candidate")
                entry.setdefault("candidate_id", "")
                entry.setdefault("candidate_status", "")
                entry.setdefault("secondary_reasons", [])
                entry.setdefault("reason_sources", [])
                entry.setdefault("expected_positive_blocks", 0)
                entry.setdefault("primary_reason", str(entry.get("reason") or ""))
                entry["normalized_reason"] = _normalize_blocker_reason(str(entry.get("primary_reason") or ""))
                entry["primary_category"] = _normalize_blocker_category(entry.get("primary_category"), entry["primary_reason"])
                entries.append(entry)
        else:
            entries.extend(_legacy_inventory_rows(row, manifest_index=manifest_index))
        for entry in entries:
            if int(entry.get("manifest_index") or -1) != manifest_index:
                continue
            entry["normalized_reason"] = _normalize_blocker_reason(str(entry.get("primary_reason") or ""))
            entry["primary_category"] = _normalize_blocker_category(entry.get("primary_category"), str(entry.get("primary_reason") or ""))
        target_diagnostics = _dedupe([*map(str, _sequence(row.get("blockers"))), *map(str, _sequence(row.get("errors")))])
        if target_diagnostics:
            diagnostics.append(
                {
                    "target_id": str(row.get("id") or ""),
                    "manifest_index": manifest_index,
                    "reasons": target_diagnostics,
                }
            )

    expected_rows = [
        entry
        for entry in entries
        if entry.get("record_kind") == "expected_positive" and _safe_int(entry.get("expected_positive_blocks")) > 0
    ]
    aggregates: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for entry in expected_rows:
        key = (
            str(entry.get("comparison_group") or ""),
            str(entry.get("vulnerability_family") or "unknown"),
            str(entry.get("input_model") or "unknown"),
            str(entry.get("primary_category") or "proof_relation"),
            str(entry.get("normalized_reason") or "unknown"),
        )
        aggregate = aggregates.setdefault(
            key,
            {
                "comparison_group": key[0],
                "vulnerability_family": key[1],
                "input_model": key[2],
                "primary_category": key[3],
                "normalized_reason": key[4],
                "expected_positive_blocks": 0,
                "vulnerable_target_ids": [],
                "fixed_target_ids": [],
                "first_manifest_index": int(entry.get("manifest_index") or 0),
                "expectation_rows": [],
            },
        )
        aggregate["expected_positive_blocks"] += _safe_int(entry.get("expected_positive_blocks"))
        aggregate["vulnerable_target_ids"].append(str(entry.get("target_id") or ""))
        aggregate["first_manifest_index"] = min(aggregate["first_manifest_index"], int(entry.get("manifest_index") or 0))
        aggregate["expectation_rows"].append(
            {key: entry.get(key) for key in ("target_id", "expectation_id", "candidate_id", "primary_reason")}
        )

    for aggregate in aggregates.values():
        # A fixed lane counts only when it actually contains the same expected
        # vulnerability family.  A clean fixed lane must not be penalized for
        # unrelated target-wide diagnostics.
        aggregate["fixed_target_ids"] = _dedupe(
            [
                str(entry.get("target_id") or "")
                for entry in entries
                if entry.get("lane") == "fixed"
                and entry.get("comparison_group") == aggregate["comparison_group"]
                and entry.get("vulnerability_family") == aggregate["vulnerability_family"]
                and bool(entry.get("matches_expected_family"))
            ]
        )
        aggregate["vulnerable_target_ids"] = _dedupe(aggregate["vulnerable_target_ids"])
        aggregate["vulnerable_count"] = len(aggregate["vulnerable_target_ids"])
        aggregate["fixed_count"] = len(aggregate["fixed_target_ids"])
        aggregate["vulnerable_minus_fixed_count"] = aggregate["vulnerable_count"] - aggregate["fixed_count"]

    aggregate_rows = sorted(
        aggregates.values(),
        key=lambda item: (
            -int(item["expected_positive_blocks"]),
            -int(item["vulnerable_minus_fixed_count"]),
            -int(item["vulnerable_count"]),
            int(item["first_manifest_index"]),
            str(item["normalized_reason"]),
        ),
    )
    return {
        "artifact_kind": PROOF_BLOCKER_INVENTORY_ARTIFACT_KIND,
        "schema_version": 2,
        "stage_order": list(BLOCKER_STAGE_ORDER),
        "candidate_rows": entries,
        "target_diagnostics": diagnostics,
        "category_totals": _count_values(str(entry.get("primary_category") or "") for entry in entries),
        "aggregates": {
            "by_target": _count_values(str(entry.get("target_id") or "") for entry in entries),
            "by_lane": _count_values(str(entry.get("lane") or "") for entry in entries),
            "by_vulnerability_family": _count_values(str(entry.get("vulnerability_family") or "") for entry in entries),
            "by_input_model": _count_values(str(entry.get("input_model") or "") for entry in entries),
            "by_normalized_reason": _count_values(str(entry.get("normalized_reason") or "") for entry in entries),
        },
        "capability_rows": aggregate_rows,
        "selected_expansion_blocker": aggregate_rows[0] if aggregate_rows else {},
    }


def _legacy_inventory_rows(row: Mapping[str, Any], *, manifest_index: int) -> list[dict[str, Any]]:
    """Compatibility adapter for callers that have not emitted scoped rows."""

    metadata = _mapping(row.get("metadata"))
    lane = _target_lane(row)
    family = str(metadata.get("vulnerability_family") or metadata.get("family") or row.get("label") or "unknown")
    input_model = str(metadata.get("input_model") or _single_count_key(metadata.get("process_witness_input_model_counts")) or "unknown")
    expected_unresolved = _safe_int(metadata.get("missing_expected_positive_count")) + _safe_int(
        metadata.get("blocked_expected_positive_count")
    )
    reasons = _dedupe([str(item) for item in _sequence(row.get("blockers")) if str(item)])
    reason = "expected_positive_not_detected" if expected_unresolved else (reasons[0] if reasons else "candidate_unresolved")
    category = "detection_gap" if expected_unresolved else _primary_proof_blocker(reason, metadata=metadata)
    return [
        {
            "record_kind": "expected_positive" if expected_unresolved else "unresolved_candidate",
            "target_id": str(row.get("id") or ""),
            "manifest_index": manifest_index,
            "lane": lane,
            "comparison_group": _comparison_group(str(row.get("id") or ""), metadata),
            "vulnerability_family": family,
            "input_model": input_model,
            "expectation_id": family if expected_unresolved else "",
            "candidate_id": "",
            "candidate_status": "not_detected" if expected_unresolved else "",
            "primary_category": category,
            "primary_reason": reason,
            "secondary_reasons": reasons[1:],
            "reason_sources": ["legacy_target_blockers"] if reasons else [],
            "expected_positive_blocks": expected_unresolved,
            "matches_expected_family": False,
        }
    ]


def _comparison_group(target_id: str, metadata: Mapping[str, Any]) -> str:
    explicit = str(metadata.get("comparison_group") or "")
    if explicit:
        return explicit
    return re.sub(r"(?:[-_](?:vulnerable|fixed|negative|positive|safe|unsafe))+$", "", str(target_id).lower())


def _normalize_blocker_category(value: Any, reason: str) -> str:
    category = str(value or "")
    return category if category in BLOCKER_STAGE_ORDER else _primary_proof_blocker(reason, metadata={})


def _target_proof_blocker_inventory_rows(
    target: CapabilitySweepTarget,
    *,
    artifact_dir: Path | None,
    report: AnalysisReport | None,
) -> list[dict[str, Any]]:
    """Emit direct expected-case and candidate rows for one sweep target."""

    candidate_rows = _load_artifact_candidate_rows(artifact_dir) if artifact_dir is not None else []
    if not candidate_rows and report is not None:
        candidate_rows = [
            item.to_dict() if hasattr(item, "to_dict") else _mapping(item)
            for item in report.candidate_findings
        ]
    metadata = dict(target.metadata)
    lane = _target_lane({"id": target.id, "label": target.label, "metadata": metadata})
    comparison_group = _comparison_group(target.id, metadata)
    fallback_input_model = str(metadata.get("input_model") or metadata.get("process_input_model") or "unknown")
    records: list[dict[str, Any]] = []
    expected_labels = [str(item) for item in target.expected_positives if str(item)]
    control_labels = [str(item) for item in target.expected_negatives if str(item)]
    resolved_statuses = {"replay_confirmed", "report_ready", "rejected"}
    confirmed_families = {
        str(candidate.get("vulnerability_type") or candidate.get("type") or "")
        for candidate in candidate_rows
        if str(candidate.get("status") or "") in {"replay_confirmed", "report_ready"}
    }
    if report is not None:
        confirmed_families.update(
            str(item.get("vulnerability_type") or "")
            for item in _observed_report_rows(report)
            if str(item.get("vulnerability_type") or "")
        )

    for candidate in candidate_rows:
        vulnerability_type = str(candidate.get("vulnerability_type") or candidate.get("type") or "")
        candidate_id = str(candidate.get("candidate_id") or "")
        status = str(candidate.get("status") or "candidate")
        if status in resolved_statuses:
            continue
        reasons = _candidate_scoped_reasons(candidate)
        primary_reason = _candidate_primary_reason(candidate, reasons)
        primary_category = _candidate_primary_category(candidate, primary_reason)
        input_model = _candidate_input_model(candidate) or fallback_input_model
        matched_family = vulnerability_type in {*expected_labels, *control_labels}
        records.append(
            {
                "record_kind": "unresolved_candidate",
                "target_id": target.id,
                "lane": lane,
                "comparison_group": comparison_group,
                "vulnerability_family": vulnerability_type or "unknown",
                "input_model": input_model,
                "candidate_id": candidate_id,
                "candidate_status": status,
                "expectation_id": vulnerability_type if matched_family else "",
                "matches_expected_family": matched_family,
                "primary_category": primary_category,
                "primary_reason": primary_reason,
                "secondary_reasons": [reason for reason in reasons if reason != primary_reason],
                "reason_sources": _candidate_reason_sources(candidate),
                "expected_positive_blocks": 0,
            }
        )

    for family in expected_labels:
        if family in confirmed_families:
            continue
        matches = [record for record in records if record["vulnerability_family"] == family]
        if not matches:
            outcome = "missing"
            primary_category = "detection_gap"
            primary_reason = "expected_positive_not_detected"
            expected_blocks = 1
        else:
            outcome = "blocked"
            primary_category, primary_reason = _case_primary_from_candidate_rows(matches)
            expected_blocks = 1
        records.append(
            {
                "record_kind": "expected_positive",
                "target_id": target.id,
                "lane": lane,
                "comparison_group": comparison_group,
                "vulnerability_family": family,
                "input_model": _case_input_model(matches, fallback_input_model),
                "expectation_id": family,
                "candidate_id": matches[0]["candidate_id"] if len(matches) == 1 else "",
                "candidate_status": "not_detected" if not matches else "unresolved",
                "outcome": outcome,
                "matches_expected_family": bool(matches),
                "primary_category": primary_category,
                "primary_reason": primary_reason,
                "secondary_reasons": _dedupe(
                    [reason for match in matches for reason in match["secondary_reasons"]]
                )[:16],
                "reason_sources": _dedupe(
                    [source for match in matches for source in match["reason_sources"]]
                )[:16],
                "expected_positive_blocks": expected_blocks,
            }
        )
    return records


def _candidate_scoped_reasons(candidate: Mapping[str, Any]) -> list[str]:
    reasons = [str(item) for item in _sequence(candidate.get("blockers")) if str(item)]
    for obligation in _mapping_rows(candidate.get("proof_obligations")):
        if str(obligation.get("status") or "open") not in {"complete", "proven", "satisfied"}:
            reasons.append(str(obligation.get("condition") or obligation.get("description") or "open_proof_obligation"))
    if not reasons:
        status = str(candidate.get("status") or "candidate")
        reasons.append(f"candidate_status_{status}")
    return _dedupe(reasons)


def _candidate_reason_sources(candidate: Mapping[str, Any]) -> list[str]:
    sources = ["candidate_state.blockers", "candidate_state.proof_obligations"]
    trace = _mapping(_mapping(candidate.get("type_facts")).get("source_to_sink_trace"))
    if trace:
        sources.append("candidate_state.type_facts.source_to_sink_trace")
    return sources


def _candidate_primary_reason(candidate: Mapping[str, Any], reasons: Sequence[str]) -> str:
    structured = _mapping(candidate.get("type_facts"))
    for key, category in (
        ("exact_sink_resolution", "exact_sink"),
        ("process_input", "input_topology"),
        ("entrypoint_derivation", "process_trigger"),
    ):
        value = _mapping(structured.get(key))
        if value and str(value.get("status") or "").lower() in {"unsupported", "missing", "unresolved", "blocked"}:
            return f"{category}:{value.get('reason') or value.get('status')}"
    return min(reasons, key=lambda reason: (BLOCKER_STAGE_ORDER.index(_primary_proof_blocker(reason, metadata={})), reason))


def _candidate_primary_category(candidate: Mapping[str, Any], reason: str) -> str:
    if reason.startswith("exact_sink:"):
        return "exact_sink"
    if reason.startswith("input_topology:"):
        return "input_topology"
    if reason.startswith("process_trigger:"):
        return "process_trigger"
    status = str(candidate.get("status") or "")
    if status in {"candidate", "needs_refinement"} and not _sequence(candidate.get("blockers")):
        return "detection_gap"
    return _primary_proof_blocker(reason, metadata={})


def _candidate_input_model(candidate: Mapping[str, Any]) -> str:
    type_facts = _mapping(candidate.get("type_facts"))
    for value in (
        _mapping(type_facts.get("process_input")).get("input_model"),
        _mapping(type_facts.get("source_to_sink_trace")).get("input_model"),
        _mapping(type_facts.get("entrypoint_derivation")).get("input_model"),
    ):
        if value:
            return str(value)
    return ""


def _case_primary_from_candidate_rows(rows: Sequence[Mapping[str, Any]]) -> tuple[str, str]:
    ordered = sorted(
        rows,
        key=lambda row: (
            BLOCKER_STAGE_ORDER.index(str(row.get("primary_category") or "proof_relation")),
            str(row.get("primary_reason") or ""),
            str(row.get("candidate_id") or ""),
        ),
    )
    selected = ordered[0]
    return str(selected["primary_category"]), str(selected["primary_reason"])


def _case_input_model(rows: Sequence[Mapping[str, Any]], fallback: str) -> str:
    models = sorted({str(row.get("input_model") or "") for row in rows if str(row.get("input_model") or "")})
    return models[0] if len(models) == 1 else fallback


def _primary_proof_blocker(reason: str, *, metadata: Mapping[str, Any]) -> str:
    structured = str(metadata.get("blocker_stage") or metadata.get("primary_blocker_category") or "")
    if structured in BLOCKER_STAGE_ORDER:
        return structured
    text = reason.lower()
    patterns = {
        "detection_gap": ("not_detect", "missing_expected", "no_candidate", "expected_positive"),
        "exact_sink": ("exact_sink", "sink_address", "target_resolution", "operation_address"),
        "input_topology": ("input_model", "input_topology", "unsupported_harness", "witness_plan"),
        "process_trigger": ("trigger", "entrypoint", "process_path", "sink_unreached"),
        "runtime_semantics": ("unsupported_call", "runtime", "syscall", "simprocedure", "external_call"),
        "exploration": ("timeout", "state", "step", "exploration", "checkpoint"),
        "proof_relation": ("relation", "no_overflow", "memory_effect", "proof"),
    }
    for category in BLOCKER_STAGE_ORDER:
        if any(token in text for token in patterns[category]):
            return category
    return "proof_relation"


def _normalize_blocker_reason(reason: str) -> str:
    text = str(reason or "").strip().lower()
    text = re.sub(r"0x[0-9a-f]+", "<address>", text)
    text = re.sub(r"\b\d+\b", "<n>", text)
    text = re.sub(r"[^a-z0-9_< >]+", "_", text)
    return re.sub(r"_+", "_", text).strip("_") or "unknown"


def _target_lane(row: Mapping[str, Any]) -> str:
    metadata = _mapping(row.get("metadata"))
    explicit = str(metadata.get("lane") or "").lower()
    if explicit in {"vulnerable", "true_overflow", "positive", "unsafe"}:
        return "vulnerable"
    if explicit in {"fixed", "negative", "safe", "clean"}:
        return "fixed"
    text = " ".join((str(row.get("id") or ""), str(row.get("label") or ""))).lower()
    return "fixed" if any(token in text for token in ("fixed", "negative", "safe")) else "vulnerable"


def _single_count_key(value: Any) -> str:
    mapping = _mapping(value)
    return str(next(iter(mapping))) if len(mapping) == 1 else ""


def _count_values(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[str(value)] = counts.get(str(value), 0) + 1
    return dict(sorted(counts.items()))


def run_capability_sweep(
    targets_json: Path,
    output_dir: Path,
    *,
    overwrite: bool = False,
) -> CapabilitySweepSummary:
    """Run a mixed target sweep and write stable summary artifacts."""

    targets_path = Path(targets_json).resolve()
    output_dir = Path(output_dir).resolve()
    targets = load_sweep_targets(targets_path)
    rows = [
        run_capability_sweep_target(target, output_dir / target.id, overwrite=overwrite)
        for target in targets
    ]
    summary = CapabilitySweepSummary(output_dir=output_dir, rows=tuple(rows))
    summary.write()
    return summary


def load_sweep_targets(path: Path) -> list[CapabilitySweepTarget]:
    payload = json.loads(Path(path).read_text() or "[]")
    raw_targets = payload.get("targets") if isinstance(payload, Mapping) else payload
    if not isinstance(raw_targets, Sequence) or isinstance(raw_targets, (str, bytes, bytearray)):
        raise ValueError(f"{path} must contain a JSON list or an object with a targets list")
    targets = [
        CapabilitySweepTarget.from_dict(item, base_dir=Path(path).parent)
        for item in raw_targets
        if isinstance(item, Mapping)
    ]
    if not targets:
        raise ValueError(f"{path} did not contain any target objects")
    return targets


def run_capability_sweep_target(
    target: CapabilitySweepTarget,
    output_dir: Path,
    *,
    overwrite: bool = False,
) -> CapabilitySweepRow:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    errors: list[str] = []
    blockers: list[str] = []
    report: AnalysisReport | None = None
    evidence_dir = Path(target.evidence_dir) if target.evidence_dir else output_dir / "evidence_packs"
    witness_dir = output_dir / "witness_plans"
    report_path = output_dir / "analysis_report.json"
    analysis_report_path = Path(target.analysis_report_path) if target.analysis_report_path else None
    artifact_dir = Path(target.artifact_dir) if target.artifact_dir else None
    export_dir = Path(target.export_dir) if target.export_dir else Path()
    binary_path = Path(target.binary_path) if target.binary_path else None
    intake_dir = Path(target.intake_dir) if target.intake_dir else output_dir / "intake"
    target_provenance: dict[str, Any] = {}
    artifact_metrics: dict[str, Any] = {}
    dynamic_confirm_eligible = bool(target.dynamic_confirm and binary_path is not None and binary_path.exists())

    if artifact_dir is not None and artifact_dir.exists():
        if not target.evidence_dir and (artifact_dir / "evidence").exists():
            evidence_dir = artifact_dir / "evidence"
        if not target.intake_dir and (artifact_dir / "intake").exists():
            intake_dir = artifact_dir / "intake"
        if analysis_report_path is None and (artifact_dir / "report" / "vulnerabilities.json").exists():
            analysis_report_path = artifact_dir / "report" / "vulnerabilities.json"
        artifact_metrics = _load_artifact_run_metrics(artifact_dir)
    elif artifact_dir is not None:
        _append_missing_target_issue(target, errors, blockers, f"missing_artifact_dir:{target.artifact_dir}")

    try:
        target_provenance = _prepare_intake_provenance(target, intake_dir, export_dir=export_dir, overwrite=overwrite)
    except Exception as exc:
        issue = f"intake_failed:{type(exc).__name__}:{str(exc)[:500]}"
        if isinstance(exc, FileNotFoundError):
            _append_missing_target_issue(target, errors, blockers, issue)
        else:
            _append_target_runtime_issue(target, errors, blockers, issue, exc)
    if not target_provenance and artifact_dir is not None and (artifact_dir / "intake").exists():
        try:
            target_provenance = _load_intake_provenance(artifact_dir / "intake", target=target)
        except Exception as exc:
            _append_target_runtime_issue(
                target,
                errors,
                blockers,
                f"intake_load_failed:{type(exc).__name__}:{str(exc)[:500]}",
                exc,
            )

    if analysis_report_path is not None:
        if analysis_report_path.exists():
            try:
                report = _load_analysis_report(analysis_report_path)
                report_path = analysis_report_path
            except Exception as exc:
                _append_target_runtime_issue(
                    target,
                    errors,
                    blockers,
                    f"analysis_report_load_failed:{type(exc).__name__}:{str(exc)[:500]}",
                    exc,
                )
        else:
            _append_missing_target_issue(target, errors, blockers, f"missing_analysis_report:{target.analysis_report_path}")

    if report is None and target.export_dir and export_dir.exists():
        try:
            if target.dynamic_confirm:
                blockers.append("dynamic_confirmation_requires_proof_gated_artifact_dir")
            if target.report_policy not in {"", "confirmed"}:
                blockers.append(f"unsupported_report_policy_for_capability_sweep:{target.report_policy}")
            report = run_pipeline(
                export_dir,
                write_evidence_packs_dir=evidence_dir,
                report_policy="confirmed",
            )
            save_report_json(report, report_path)
        except Exception as exc:
            _append_target_runtime_issue(
                target,
                errors,
                blockers,
                f"pipeline_failed:{type(exc).__name__}:{str(exc)[:500]}",
                exc,
            )
    elif report is None:
        if target.export_dir:
            _append_missing_target_issue(target, errors, blockers, f"missing_export_dir:{target.export_dir}")
        elif artifact_dir is not None and artifact_dir.exists():
            pass
        elif target_provenance:
            blockers.append("decompiled_export_missing")
        else:
            _append_missing_target_issue(target, errors, blockers, "target_has_no_export_dir")

    witness_paths: dict[str, Path] = {}
    if evidence_dir.exists():
        try:
            witness_paths = write_witness_plans_for_evidence_dir(evidence_dir, witness_dir)
        except Exception as exc:
            _append_target_runtime_issue(
                target,
                errors,
                blockers,
                f"witness_planning_failed:{type(exc).__name__}:{str(exc)[:500]}",
                exc,
            )

    blockers.extend(_collect_blockers(output_dir))
    if artifact_dir is not None and artifact_dir.exists():
        blockers.extend(_collect_blockers(artifact_dir))
    blockers.extend(_source_trace_metric_blockers(artifact_metrics))
    evidence_pack_count = _evidence_pack_count(evidence_dir)
    witness_plan_count = len(witness_paths)
    witness_plan_missing_count = max(0, evidence_pack_count - witness_plan_count)
    if witness_plan_missing_count:
        blockers.append(f"witness_plan_missing:{witness_plan_missing_count}")
    blocker_category_counts = _blocker_category_counts(blockers)
    runtime_seconds = round(time.perf_counter() - started, 4)
    reports = max(len(report.vulnerability_reports) if report is not None else 0, int(artifact_metrics.get("reports") or 0))
    dynamic_proof_metrics = _dynamic_proof_metrics(report, output_dir, artifact_dir)
    process_witness_metrics = _process_witness_metrics(output_dir, artifact_dir)
    report_observed_rows = _observed_report_rows(report)
    artifact_observed_rows = [
        dict(item)
        for item in _sequence(artifact_metrics.get("observed_reports"))
        if isinstance(item, Mapping)
    ]
    observed_reports = _dedupe_report_rows([*report_observed_rows, *artifact_observed_rows])
    positive_expectation_metrics = _positive_expectation_metrics(
        target,
        observed_reports=observed_reports,
        blockers=blockers,
        errors=errors,
    )
    matrix_path, matrix_metrics = _write_capability_matrix(
        target,
        output_dir,
        artifact_dir=artifact_dir if artifact_dir is not None and artifact_dir.exists() else None,
        target_provenance=target_provenance,
    )
    negative_expected = _is_negative_target(target)
    false_positive_notes = []
    if negative_expected and reports:
        false_positive_notes.append(f"expected negative target produced {reports} report(s)")
    missing_positive_labels = [
        str(case.get("label") or "")
        for case in _mapping_rows(positive_expectation_metrics.get("expected_positive_cases"))
        if str(case.get("outcome") or "") == "missing" and str(case.get("label") or "")
    ]
    if missing_positive_labels:
        false_positive_notes.append("expected positive reports missing: " + ",".join(missing_positive_labels))
    negative_audit_path = _write_negative_precision_audit(
        target,
        output_dir,
        observed_reports=observed_reports,
        blockers=blockers,
        errors=errors,
        false_positive_notes=false_positive_notes,
    )
    positive_audit_path = _write_positive_expectation_audit(
        target,
        output_dir,
        metrics=positive_expectation_metrics,
        observed_reports=observed_reports,
        blockers=blockers,
        errors=errors,
        false_positive_notes=false_positive_notes,
    )
    scoped_inventory_rows = _target_proof_blocker_inventory_rows(
        target,
        artifact_dir=artifact_dir if artifact_dir is not None and artifact_dir.exists() else output_dir,
        report=report,
    )

    row = CapabilitySweepRow(
        id=target.id,
        label=target.label,
        export_dir=target.export_dir,
        binary_path=target.binary_path,
        rootfs_path=target.rootfs_path,
        intake_dir=str(intake_dir) if target_provenance else "",
        artifact_dir=target.artifact_dir,
        analysis_report_path=str(analysis_report_path) if analysis_report_path is not None else "",
        evidence_dir=str(evidence_dir) if evidence_dir.exists() else "",
        witness_plan_dir=str(witness_dir) if witness_paths else "",
        report_path=str(report_path) if report_path.exists() else "",
        negative_audit_path=str(negative_audit_path) if negative_audit_path else "",
        positive_audit_path=str(positive_audit_path) if positive_audit_path else "",
        target_provenance=target_provenance,
        candidates=max(len(report.candidate_findings) if report is not None else 0, int(artifact_metrics.get("candidates") or 0)),
        confirmations=max(len(report.candidate_confirmations) if report is not None else 0, int(artifact_metrics.get("confirmations") or 0)),
        confirmed_bugs=max(_confirmed_bug_count(report), int(artifact_metrics.get("confirmed_bugs") or 0)),
        proof_ready_count=max(_proof_ready_count(report), int(artifact_metrics.get("proof_ready_count") or 0)),
        dynamic_proofs=_safe_int(dynamic_proof_metrics.get("dynamic_proof_count")),
        rejected_negatives=_rejected_negative_count(
            target,
            reports=reports,
            blockers=blockers,
            errors=errors,
        ),
        blocked_negatives=_blocked_negative_count(
            target,
            reports=reports,
            blockers=blockers,
            errors=errors,
        ),
        unsupported_blockers=sum(blocker_category_counts.values()),
        reports=reports,
        runtime_seconds=runtime_seconds,
        false_positive_notes=false_positive_notes,
        blockers=blockers,
        errors=errors,
        metadata={
            **dict(target.metadata),
            "optional": bool(target.optional),
            "expected_positives": list(target.expected_positives),
            "expected_negatives": list(target.expected_negatives),
            "evidence_pack_count": evidence_pack_count,
            "witness_plan_count": witness_plan_count,
            "witness_plan_missing_count": witness_plan_missing_count,
            "witness_plan_coverage": _witness_plan_coverage(evidence_pack_count, witness_plan_count),
            "artifact_candidate_status_counts": artifact_metrics.get("artifact_candidate_status_counts", {}),
            "artifact_replay_result_counts": artifact_metrics.get("artifact_replay_result_counts", {}),
            "blocker_category_counts": blocker_category_counts,
            "proof_blocker_inventory_rows": scoped_inventory_rows,
            **positive_expectation_metrics,
            **dynamic_proof_metrics,
            **process_witness_metrics,
            **matrix_metrics,
            **({"capability_matrix_path": str(matrix_path)} if matrix_path else {}),
            **{
                key: value
                for key, value in artifact_metrics.items()
                if key.startswith("source_to_sink_")
            },
            **_dynamic_confirmation_metadata(
                report,
                target=target,
                eligible=dynamic_confirm_eligible,
                output_dir=output_dir / "dynamic_confirmations",
            ),
        },
    )
    (output_dir / "capability_sweep_row.json").write_text(json.dumps(row.to_dict(), indent=2, sort_keys=True))
    return row


def _confirmed_bug_count(report: AnalysisReport | None) -> int:
    if report is None:
        return 0
    return sum(1 for item in report.candidate_confirmations.values() if str(_mapping(item).get("status") or "") == "confirmed_bug")


def _proof_ready_count(report: AnalysisReport | None) -> int:
    if report is None:
        return 0
    metrics = dict(report.stage_metrics)
    for key in ("proof_ready_count", "proof_ready", "llm_queue", "clustered_llm_queue"):
        if key in metrics:
            try:
                return int(metrics[key])
            except (TypeError, ValueError):
                continue
    return len(report.confirmation_findings)


def _dynamic_proof_metrics(report: AnalysisReport | None, output_dir: Path, artifact_dir: Path | None = None) -> dict[str, Any]:
    seen: set[str] = set()
    seen_memory_statuses: set[tuple[str, str]] = set()
    seen_semantic_observations: set[tuple[str, str, str]] = set()
    dynamic_status_counts: dict[str, int] = {}
    memory_status_counts: dict[str, int] = {}
    semantic_observed_kind_counts: dict[str, int] = {}
    semantic_observation_status_counts: dict[str, int] = {}
    semantic_not_observed_count = 0

    def add_status(counts: dict[str, int], status: str) -> None:
        if status:
            counts[status] = counts.get(status, 0) + 1

    def add_memory_proof(proof: Mapping[str, Any], fallback_id: object) -> None:
        payload = _mapping(proof)
        status = str(payload.get("status") or "")
        if status not in DYNAMIC_MEMORY_PROOF_STATUSES:
            return
        candidate_id = str(payload.get("candidate_id") or fallback_id)
        status_key = (candidate_id, status)
        if status_key not in seen_memory_statuses:
            seen_memory_statuses.add(status_key)
            add_status(memory_status_counts, status)
            add_status(dynamic_status_counts, status)
        seen.add(candidate_id)

    if report is not None:
        for proof in report.candidate_proofs.values():
            payload = _mapping(proof)
            add_memory_proof(payload, id(payload))
        for confirmation in report.candidate_confirmations.values():
            proof = _mapping(_mapping(confirmation).get("memory_safety_argument")).get("ghidra_dynamic_proof")
            add_memory_proof(_mapping(proof), _mapping(confirmation).get("candidate_id") or id(proof))
    for root in (Path(output_dir), Path(artifact_dir) if artifact_dir is not None else None):
        if root is None or not root.exists():
            continue
        for path in root.rglob("*.json"):
            payload = _load_json(path)
            proof = first_ghidra_dynamic_proof(payload)
            add_memory_proof(proof, path)
            semantic = _semantic_dynamic_observation(path, payload)
            if not semantic:
                continue
            candidate_id = str(payload.get("candidate_id") or path.parent)
            kind = str(semantic.get("kind") or "")
            status = str(semantic.get("status") or "")
            key = (candidate_id, kind, status)
            if key in seen_semantic_observations:
                continue
            seen_semantic_observations.add(key)
            add_status(semantic_observation_status_counts, status)
            if bool(semantic.get("observed", False)):
                seen.add(candidate_id)
                semantic_observed_kind_counts[kind] = semantic_observed_kind_counts.get(kind, 0) + 1
                add_status(dynamic_status_counts, status)
            else:
                semantic_not_observed_count += 1
    return {
        key: value
        for key, value in {
            "dynamic_proof_count": len(seen),
            "dynamic_proof_status_counts": dynamic_status_counts,
            "dynamic_memory_proof_status_counts": memory_status_counts,
            "dynamic_semantic_observed_kind_counts": semantic_observed_kind_counts,
            "dynamic_semantic_observation_status_counts": semantic_observation_status_counts,
            "dynamic_semantic_observation_count": len(seen_semantic_observations),
            "dynamic_semantic_not_observed_count": semantic_not_observed_count,
        }.items()
        if value not in (None, "", [], {})
    }


def _process_witness_metrics(output_dir: Path, artifact_dir: Path | None = None) -> dict[str, Any]:
    seen_paths: set[str] = set()
    attempt_count = 0
    observed_count = 0
    unsupported_count = 0
    blocked_count = 0
    status_counts: dict[str, int] = {}
    input_model_counts: dict[str, int] = {}
    blocker_counts: dict[str, int] = {}

    def add_count(counts: dict[str, int], key: str, amount: int = 1) -> None:
        if key and amount:
            counts[key] = counts.get(key, 0) + amount

    for root in (Path(output_dir), Path(artifact_dir) if artifact_dir is not None else None):
        if root is None or not root.exists():
            continue
        for path in root.rglob("process_witness_attempt.json"):
            try:
                path_key = str(path.resolve())
            except OSError:
                path_key = str(path)
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            payload = _load_json(path)
            if not payload:
                continue
            attempts = _mapping_rows(payload.get("attempts"))
            if not attempts:
                payload_attempt_count = max(1, _safe_int(payload.get("attempt_count")))
                attempt_count += payload_attempt_count
                payload_observed = _safe_int(payload.get("observed_count"))
                payload_unsupported = _safe_int(payload.get("unsupported_count"))
                payload_blocked = _safe_int(payload.get("blocked_count"))
                payload_status = str(payload.get("status") or "")
                if not any((payload_observed, payload_unsupported, payload_blocked)):
                    payload_observed = payload_attempt_count if payload_status == "observed" else 0
                    payload_unsupported = payload_attempt_count if payload_status == "unsupported" else 0
                    payload_blocked = payload_attempt_count if payload_status == "blocked" else 0
                observed_count += payload_observed
                unsupported_count += payload_unsupported
                blocked_count += payload_blocked
                payload_status_counts = _mapping(payload.get("status_counts"))
                for status, status_amount in payload_status_counts.items():
                    add_count(status_counts, str(status), _safe_int(status_amount))
                if not payload_status_counts:
                    add_count(status_counts, payload_status, payload_attempt_count)
                payload_input_model_counts = _mapping(payload.get("input_model_counts"))
                for model, model_amount in payload_input_model_counts.items():
                    add_count(input_model_counts, str(model), _safe_int(model_amount))
                if not payload_input_model_counts:
                    add_count(input_model_counts, str(payload.get("input_model") or ""), payload_attempt_count)
                for blocker in _sequence(payload.get("blockers")):
                    add_count(blocker_counts, str(blocker))
                continue
            for row in attempts:
                attempt_count += 1
                status = str(row.get("status") or "")
                add_count(status_counts, status)
                model = str(row.get("input_model") or payload.get("input_model") or "")
                add_count(input_model_counts, model)
                for blocker in _sequence(row.get("blockers")):
                    add_count(blocker_counts, str(blocker))
                if status == "observed" or bool(row.get("dynamic_proof_observed", False)):
                    observed_count += 1
                elif status == "unsupported":
                    unsupported_count += 1
                elif status == "blocked":
                    blocked_count += 1

    return {
        key: value
        for key, value in {
            "process_witness_attempts": attempt_count,
            "process_witness_observed": observed_count,
            "process_witness_unsupported": unsupported_count,
            "process_witness_blocked": blocked_count,
            "process_witness_status_counts": status_counts,
            "process_witness_input_model_counts": input_model_counts,
            "process_witness_blocker_counts": blocker_counts,
        }.items()
        if value not in (None, "", [], {})
    }


def _is_observed_semantic_dynamic_proof(path: Path, payload: Mapping[str, Any]) -> bool:
    semantic = _semantic_dynamic_observation(path, payload)
    return bool(semantic and semantic.get("observed"))


def _semantic_dynamic_observation(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    if not path.name.startswith("dynamic_") or not path.name.endswith("_observation.json"):
        return {}
    kind = str(payload.get("kind") or "")
    if kind not in SEMANTIC_DYNAMIC_ORACLE_KINDS:
        return {}
    if not bool(payload.get("bug_observed", False)):
        status = str(payload.get("status") or "")
        return {"kind": kind, "status": status, "observed": False}
    status = str(payload.get("status") or "")
    return {"kind": kind, "status": status, "observed": status.endswith("_observed") and not status.endswith("_not_observed")}


def _load_artifact_run_metrics(artifact_dir: Path) -> dict[str, Any]:
    candidates = _load_artifact_candidate_rows(artifact_dir)
    status_counts = _status_counts(candidates)
    vulnerabilities = _load_artifact_vulnerability_rows(artifact_dir)
    observed_reports = _observed_report_rows_from_payloads(vulnerabilities)
    replay_counts = _artifact_replay_result_counts(artifact_dir)
    trace_metrics = _source_trace_metrics(artifact_dir, candidates)
    confirmed_replays = int(replay_counts.get("confirmed") or 0)
    confirmed_states = sum(int(status_counts.get(status) or 0) for status in ("replay_confirmed", "report_ready"))
    proof_ready = sum(
        int(status_counts.get(status) or 0)
        for status in ("proof_ready", "replay_ready", "replay_confirmed", "report_ready")
    )
    return {
        key: value
        for key, value in {
            "artifact_candidate_status_counts": status_counts,
            "artifact_replay_result_counts": replay_counts,
            "candidates": len(candidates),
            "confirmations": max(confirmed_replays, confirmed_states),
            "confirmed_bugs": max(len(vulnerabilities), confirmed_states),
            "proof_ready_count": proof_ready,
            "reports": len(vulnerabilities),
            "observed_reports": observed_reports,
            **trace_metrics,
        }.items()
        if value not in (None, "", [], {})
    }


def _load_artifact_candidate_rows(artifact_dir: Path) -> list[dict[str, Any]]:
    for relative in (
        Path("promotion") / "candidate_states.json",
        Path("candidate_states.json"),
        Path("discovery") / "candidates.json",
    ):
        rows = _candidate_rows_from_path(artifact_dir / relative)
        if rows:
            return rows
    return []


def _candidate_rows_from_path(path: Path) -> list[dict[str, Any]]:
    payload = _load_json(path)
    for key in ("candidate_states", "candidates"):
        rows = payload.get(key)
        if isinstance(rows, Sequence) and not isinstance(rows, (str, bytes, bytearray)):
            return [_mapping(row) for row in rows if isinstance(row, Mapping) or hasattr(row, "to_dict")]
    return []


def _load_artifact_vulnerability_rows(artifact_dir: Path) -> list[dict[str, Any]]:
    payload = _load_json(artifact_dir / "report" / "vulnerabilities.json")
    rows = payload.get("vulnerabilities")
    if isinstance(rows, Sequence) and not isinstance(rows, (str, bytes, bytearray)):
        return [_mapping(row) for row in rows if isinstance(row, Mapping) or hasattr(row, "to_dict")]
    return []


def _artifact_replay_result_counts(artifact_dir: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    seen_candidates: set[tuple[str, str]] = set()
    for path in artifact_dir.rglob("*.json"):
        if path.name not in {"result.json", "service_replay_result.json"}:
            continue
        payload = _load_json(path)
        result = str(payload.get("result") or payload.get("status") or "")
        candidate_id = str(payload.get("candidate_id") or path)
        if not result:
            continue
        key = (candidate_id, result)
        if key in seen_candidates:
            continue
        seen_candidates.add(key)
        counts[result] = counts.get(result, 0) + 1
    return counts


def _source_trace_metrics(artifact_dir: Path, candidates: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    trace_rows = _source_trace_rows(artifact_dir)
    status_counts = _status_counts([payload for _path, payload in trace_rows])
    confidence_counts: dict[str, int] = {}
    traces_by_candidate: dict[str, tuple[Path, Mapping[str, Any]]] = {}
    for path, payload in trace_rows:
        confidence = str(payload.get("confidence") or "")
        if confidence:
            confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
        candidate_id = str(payload.get("candidate_id") or "")
        if candidate_id and candidate_id not in traces_by_candidate:
            traces_by_candidate[candidate_id] = (path, payload)

    report_ready_ids = [
        str(row.get("candidate_id") or "")
        for row in candidates
        if str(row.get("status") or "") == "report_ready" and str(row.get("candidate_id") or "")
    ]
    missing_count = 0
    incomplete_count = 0
    gaps: list[dict[str, Any]] = []
    for candidate_id in report_ready_ids:
        row = traces_by_candidate.get(candidate_id)
        if row is None:
            missing_count += 1
            gaps.append({"candidate_id": candidate_id, "gaps": ["missing_source_to_sink_trace_artifact"]})
            continue
        path, payload = row
        candidate_gaps = _source_trace_report_ready_gaps(payload, trace_path=path)
        if candidate_gaps:
            incomplete_count += 1
            gaps.append({"candidate_id": candidate_id, "path": str(path), "gaps": candidate_gaps})

    return {
        "source_to_sink_trace_count": len(trace_rows),
        "source_to_sink_trace_status_counts": status_counts,
        "source_to_sink_trace_confidence_counts": confidence_counts,
        "source_to_sink_report_ready_count": len(report_ready_ids),
        "source_to_sink_report_ready_trace_missing_count": missing_count,
        "source_to_sink_report_ready_trace_incomplete_count": incomplete_count,
        "source_to_sink_report_ready_trace_coverage": _source_trace_coverage(
            len(report_ready_ids),
            missing_count,
            incomplete_count,
        ),
        "source_to_sink_report_ready_trace_gaps": gaps[:16],
    }


def _source_trace_rows(artifact_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    rows: list[tuple[Path, dict[str, Any]]] = []
    for path in artifact_dir.rglob("*.json"):
        payload = _load_json(path)
        kind = str(payload.get("artifact_kind") or payload.get("kind") or "")
        if kind != "source_to_sink_trace" and not path.name.endswith("_source_to_sink_trace.json"):
            continue
        rows.append((path, dict(payload)))
    return rows


def _source_trace_report_ready_gaps(payload: Mapping[str, Any], *, trace_path: Path) -> list[str]:
    gaps: list[str] = []
    if str(payload.get("status") or "") != "proven":
        gaps.append("source_to_sink_trace_not_proven")
    if not _source_trace_has_controlled_role(payload):
        gaps.append("missing_controlled_role")
    if not _mapping_rows(payload.get("propagation_path")):
        gaps.append("missing_propagation_path")
    if not str(payload.get("input_model") or ""):
        gaps.append("missing_input_model")
    dynamic_artifacts = [str(item) for item in _sequence(payload.get("dynamic_artifacts")) if str(item)]
    if not dynamic_artifacts:
        gaps.append("missing_dynamic_artifact_refs")
    elif not any(_artifact_path_exists(item, base_dir=trace_path.parent) for item in dynamic_artifacts):
        gaps.append("dynamic_artifact_refs_unresolved")
    return gaps


def _source_trace_has_controlled_role(payload: Mapping[str, Any]) -> bool:
    controlled_markers = ("source_controlled", "parameter_controlled", "dynamic_process_input_controlled")
    for item in _sequence(payload.get("controlled_roles")):
        text = str(item).lower()
        if any(marker in text for marker in controlled_markers) and "not_controlled" not in text:
            return True
    for role in _mapping_rows(payload.get("argument_roles")):
        text = " ".join(
            str(role.get(key) or "")
            for key in ("classification", "control", "role", "source_control")
        ).lower()
        if any(marker in text for marker in controlled_markers) and "not_controlled" not in text:
            return True
        if role.get("controlled") is True:
            return True
    return False


def _artifact_path_exists(raw: str, *, base_dir: Path) -> bool:
    path = Path(raw)
    candidates = [path]
    if not path.is_absolute():
        candidates.append(base_dir / path)
        candidates.append(Path.cwd() / path)
    return any(candidate.exists() for candidate in candidates)


def _source_trace_coverage(report_ready_count: int, missing_count: int, incomplete_count: int) -> str:
    if report_ready_count <= 0:
        return "not_applicable"
    if missing_count == 0 and incomplete_count == 0:
        return "complete"
    if missing_count < report_ready_count:
        return "partial"
    return "missing"


def _source_trace_metric_blockers(metrics: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    missing = _safe_int(metrics.get("source_to_sink_report_ready_trace_missing_count"))
    incomplete = _safe_int(metrics.get("source_to_sink_report_ready_trace_incomplete_count"))
    if missing:
        blockers.append(f"source_to_sink_trace_missing_for_report_ready:{missing}")
    if incomplete:
        blockers.append(f"source_to_sink_trace_incomplete_for_report_ready:{incomplete}")
    return blockers


def _write_capability_matrix(
    target: CapabilitySweepTarget,
    output_dir: Path,
    *,
    artifact_dir: Path | None,
    target_provenance: Mapping[str, Any],
) -> tuple[Path | None, dict[str, Any]]:
    states = _load_candidate_states_for_matrix(artifact_dir)
    if not states:
        return None, {}
    rows: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    target_type = str(target_provenance.get("target_kind") or target.label or "artifact_run")
    for state in states:
        trace = build_source_to_sink_trace(state)
        evidence = build_bug_bounty_evidence(state)
        proof_mode = _capability_proof_mode(state)
        status = _capability_matrix_status(state, trace=trace, evidence_status=evidence.status)
        key = (
            trace.input_model or "unknown",
            state.vulnerability_type or "unknown",
            target_type,
            proof_mode,
            status,
        )
        row = rows.setdefault(
            key,
            {
                "input_model": key[0],
                "vulnerability_class": key[1],
                "target_type": key[2],
                "proof_mode": key[3],
                "state": key[4],
                "candidate_count": 0,
                "candidate_ids": [],
            },
        )
        row["candidate_count"] = int(row["candidate_count"]) + 1
        row["candidate_ids"].append(state.candidate_id)
    ordered_rows = sorted(rows.values(), key=lambda item: (item["input_model"], item["vulnerability_class"], item["proof_mode"], item["state"]))
    status_counts = _status_counts(ordered_rows)
    path = output_dir / CAPABILITY_MATRIX
    path.write_text(
        json.dumps(
            {
                "artifact_kind": CAPABILITY_MATRIX_ARTIFACT_KIND,
                "schema_version": 1,
                "target_id": target.id,
                "generated_at": utc_timestamp(),
                "rows": ordered_rows,
                "status_counts": status_counts,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return path, {
        "capability_matrix_row_count": len(ordered_rows),
        "capability_matrix_candidate_count": len(states),
        "capability_matrix_status_counts": status_counts,
    }


def _load_candidate_states_for_matrix(artifact_dir: Path | None) -> list[CandidateState]:
    if artifact_dir is None:
        return []
    for relative in (
        Path("promotion") / "candidate_states.json",
        Path("candidate_states.json"),
    ):
        path = artifact_dir / relative
        if path.exists():
            try:
                return load_candidate_states(path)
            except Exception:
                return []
    return []


def _capability_matrix_status(
    state: CandidateState,
    *,
    trace: Any,
    evidence_status: str,
) -> str:
    blockers = [*state.blockers, *getattr(trace, "blockers", [])]
    if evidence_status == "report_ready":
        return "report-ready"
    if any("unsupported" in str(blocker) for blocker in blockers):
        return "unsupported"
    if getattr(trace, "dynamic_artifacts", None):
        return "replay observed"
    if getattr(trace, "input_model", "") and (
        getattr(trace, "argument_roles", None) or getattr(trace, "propagation_path", None)
    ):
        return "source-to-sink partial"
    return "candidate-only"


def _capability_proof_mode(state: CandidateState) -> str:
    for raw in [*state.replay_artifacts, *state.validation_artifacts, *state.report_artifacts]:
        path = Path(raw)
        if not path.exists() or path.suffix.lower() != ".json":
            continue
        payload = _load_json(path)
        mode = str(payload.get("mode") or "")
        if mode:
            return mode
        proof = first_ghidra_dynamic_proof(payload)
        scope = str(proof.get("proof_scope") or "")
        if scope:
            return f"ghidra_{scope}"
    return "none"


def _status_counts(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or row.get("state") or "")
        if not status:
            continue
        counts[status] = counts.get(status, 0) + 1
    return counts


def _metadata_int(row: CapabilitySweepRow, key: str) -> int:
    try:
        return int(_mapping(row.metadata).get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _aggregate_metadata_counts(rows: Sequence[CapabilitySweepRow], key: str) -> dict[str, int]:
    totals: dict[str, int] = {}
    for row in rows:
        counts = _mapping(_mapping(row.metadata).get(key))
        for name, value in counts.items():
            amount = _safe_int(value)
            if amount:
                totals[str(name)] = totals.get(str(name), 0) + amount
    return totals


def _witness_plan_coverage(evidence_pack_count: int, witness_plan_count: int) -> str:
    if evidence_pack_count <= 0:
        return "not_applicable"
    if witness_plan_count >= evidence_pack_count:
        return "complete"
    if witness_plan_count > 0:
        return "partial"
    return "missing"


def _dynamic_confirmation_metadata(
    report: AnalysisReport | None,
    *,
    target: CapabilitySweepTarget,
    eligible: bool,
    output_dir: Path,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "replay_mode": target.replay_mode,
        "dynamic_confirm_requested": bool(target.dynamic_confirm),
        "dynamic_confirm_eligible": bool(eligible),
    }
    if target.dynamic_confirm:
        metadata["dynamic_confirm_output_dir"] = str(output_dir)
    if report is None:
        return metadata
    stage_metrics = dict(report.stage_metrics)
    confirmation = stage_metrics.get("dynamic_confirmation")
    if isinstance(confirmation, Mapping):
        status_counts = confirmation.get("status_counts")
        if isinstance(status_counts, Mapping):
            metadata["dynamic_confirmation_status_counts"] = dict(status_counts)
        errors = confirmation.get("errors")
        if isinstance(errors, Mapping):
            metadata["dynamic_confirmation_error_count"] = len(errors)
        elif "error_count" in confirmation:
            metadata["dynamic_confirmation_error_count"] = _safe_int(confirmation.get("error_count"))
    if "dynamic_confirmation_symbolic_bytes" in stage_metrics:
        metadata["dynamic_confirmation_symbolic_bytes"] = _safe_int(stage_metrics.get("dynamic_confirmation_symbolic_bytes"))
    return metadata


def _collect_blockers(output_dir: Path) -> list[str]:
    blockers: list[str] = []
    for path in Path(output_dir).rglob("*.json"):
        payload = _load_json(path)
        if not payload:
            continue
        _collect_payload_blockers(payload, blockers)
    return _dedupe(blockers)


def _collect_payload_blockers(payload: Any, blockers: list[str]) -> None:
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            if key == "blockers" and isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                for item in value:
                    text = str(item)
                    if text:
                        blockers.append(text)
                continue
            if key in {"reason", "blocked_reason", "blocker", "error"}:
                text = str(value or "")
                if text and _looks_like_blocker(text):
                    blockers.append(text)
            _collect_payload_blockers(value, blockers)
        return
    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes, bytearray)):
        for item in payload:
            _collect_payload_blockers(item, blockers)


def _append_missing_target_issue(
    target: CapabilitySweepTarget,
    errors: list[str],
    blockers: list[str],
    issue: str,
) -> None:
    if target.optional:
        blockers.append(f"optional_target_unavailable:{issue}")
    else:
        errors.append(issue)


def _append_target_runtime_issue(
    target: CapabilitySweepTarget,
    errors: list[str],
    blockers: list[str],
    issue: str,
    exc: Exception,
) -> None:
    if target.optional and _optional_target_unavailable_issue(issue, exc):
        blockers.append(f"optional_target_unavailable:{issue}")
        return
    errors.append(issue)


def _optional_target_unavailable_issue(issue: str, exc: Exception) -> bool:
    if isinstance(exc, (FileNotFoundError, PermissionError, NotADirectoryError)):
        return True
    if isinstance(exc, OSError):
        return True
    text = f"{issue} {exc}".lower()
    return any(
        token in text
        for token in (
            "missing",
            "not found",
            "no such file",
            "permission",
            "denied",
            "unwritable",
            "read-only",
            "stale",
            "owned by root",
        )
    )


def _positive_expectation_metrics(
    target: CapabilitySweepTarget,
    *,
    observed_reports: Sequence[Mapping[str, Any]],
    blockers: Sequence[str],
    errors: Sequence[str],
) -> dict[str, Any]:
    expected = [label for label in target.expected_positives if label]
    if not expected:
        return {}
    cases: list[dict[str, Any]] = []
    for label in expected:
        matches = [
            dict(report)
            for report in observed_reports
            if _report_matches_expected_positive(report, label)
        ]
        if matches:
            outcome = "matched"
        elif not observed_reports and (blockers or errors):
            outcome = "blocked"
        else:
            outcome = "missing"
        cases.append(
            {
                "label": label,
                "outcome": outcome,
                "matched_report_count": len(matches),
                "matched_reports": matches[:8],
            }
        )
    return {
        "expected_positive_count": len(expected),
        "matched_expected_positive_count": sum(1 for case in cases if case["outcome"] == "matched"),
        "missing_expected_positive_count": sum(1 for case in cases if case["outcome"] == "missing"),
        "blocked_expected_positive_count": sum(1 for case in cases if case["outcome"] == "blocked"),
        "expected_positive_cases": cases,
    }


def _write_positive_expectation_audit(
    target: CapabilitySweepTarget,
    output_dir: Path,
    *,
    metrics: Mapping[str, Any],
    observed_reports: Sequence[Mapping[str, Any]],
    blockers: Sequence[str],
    errors: Sequence[str],
    false_positive_notes: Sequence[str],
) -> Path | None:
    expected = [label for label in target.expected_positives if label]
    if not expected:
        return None
    cases = _mapping_rows(metrics.get("expected_positive_cases"))
    payload = {
        "artifact_kind": POSITIVE_EXPECTATION_AUDIT_ARTIFACT_KIND,
        "schema_version": 1,
        "target_id": target.id,
        "label": target.label,
        "expected_positives": expected,
        "outcome": _positive_expectation_outcome(cases),
        "expected_positive_count": _safe_int(metrics.get("expected_positive_count")),
        "matched_expected_positive_count": _safe_int(metrics.get("matched_expected_positive_count")),
        "missing_expected_positive_count": _safe_int(metrics.get("missing_expected_positive_count")),
        "blocked_expected_positive_count": _safe_int(metrics.get("blocked_expected_positive_count")),
        "cases": cases,
        "observed_report_count": len(observed_reports),
        "observed_reports": [dict(item) for item in observed_reports],
        "blockers": list(blockers),
        "errors": list(errors),
        "false_positive_notes": list(false_positive_notes),
    }
    path = output_dir / POSITIVE_EXPECTATION_AUDIT
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


def _positive_expectation_outcome(cases: Sequence[Mapping[str, Any]]) -> str:
    outcomes = {str(case.get("outcome") or "") for case in cases}
    if not outcomes:
        return "not_applicable"
    if outcomes == {"matched"}:
        return "matched"
    if "missing" in outcomes:
        return "missing"
    if "blocked" in outcomes:
        return "blocked"
    return "mixed"


def _report_matches_expected_positive(report: Mapping[str, Any], label: str) -> bool:
    normalized = _normalize_expectation_label(label)
    if not normalized:
        return False
    if normalized in {"*", "any", "positive", "known_positive"}:
        return True
    return normalized in {
        _normalize_expectation_label(report.get("vulnerability_type")),
        _normalize_expectation_label(report.get("candidate_id")),
        _normalize_expectation_label(report.get("report_id")),
    }


def _normalize_expectation_label(value: Any) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in str(value or "").lower()).strip("_")


def _write_negative_precision_audit(
    target: CapabilitySweepTarget,
    output_dir: Path,
    *,
    observed_reports: Sequence[Mapping[str, Any]],
    blockers: Sequence[str],
    errors: Sequence[str],
    false_positive_notes: Sequence[str],
) -> Path | None:
    if not _is_negative_target(target):
        return None
    reports = [dict(item) for item in observed_reports]
    outcome = "reported" if reports else "blocked" if blockers or errors else "rejected"
    expected = list(target.expected_negatives)
    if not expected:
        expected = [target.label or target.id]
    cases = [
        {
            "label": label,
            "outcome": outcome,
            "observed_report_count": len(reports),
            "blockers": list(blockers),
            "errors": list(errors),
        }
        for label in expected
    ]
    payload = {
        "artifact_kind": NEGATIVE_PRECISION_AUDIT_ARTIFACT_KIND,
        "schema_version": 2,
        "target_id": target.id,
        "label": target.label,
        "expected_negatives": expected,
        "cases": cases,
        "outcome": outcome,
        "rejected_count": len(expected) if outcome == "rejected" else 0,
        "blocked_count": len(expected) if outcome == "blocked" else 0,
        "observed_report_count": len(reports),
        "observed_reports": reports,
        "blockers": list(blockers),
        "errors": list(errors),
        "false_positive_notes": list(false_positive_notes),
    }
    path = output_dir / NEGATIVE_PRECISION_AUDIT
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


def _rejected_negative_count(
    target: CapabilitySweepTarget,
    *,
    reports: int,
    blockers: Sequence[str],
    errors: Sequence[str],
) -> int:
    if not _is_negative_target(target) or blockers or errors:
        return 0
    if reports:
        return 0
    return max(1, len(target.expected_negatives))


def _blocked_negative_count(
    target: CapabilitySweepTarget,
    *,
    reports: int,
    blockers: Sequence[str],
    errors: Sequence[str],
) -> int:
    if not _is_negative_target(target) or reports or not (blockers or errors):
        return 0
    return max(1, len(target.expected_negatives))


def _observed_report_rows(report: AnalysisReport | None) -> list[dict[str, Any]]:
    if report is None:
        return []
    return _observed_report_rows_from_payloads(
        item.to_dict() if hasattr(item, "to_dict") else _mapping(item)
        for item in report.vulnerability_reports
    )


def _observed_report_rows_from_payloads(payloads: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for payload in payloads:
        candidate_id = payload.get("candidate_id")
        row = {
            "report_id": payload.get("report_id") or payload.get("id") or candidate_id,
            "candidate_id": candidate_id,
            "vulnerability_type": payload.get("vulnerability_type") or payload.get("vulnerability"),
            "function_name": payload.get("function_name"),
            "address": payload.get("address"),
            "summary": payload.get("summary") or payload.get("title"),
        }
        rows.append({key: value for key, value in row.items() if value not in (None, "")})
    return rows


def _dedupe_report_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for row in rows:
        payload = dict(row)
        key = json.dumps(payload, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        result.append(payload)
    return result


def _load_analysis_report(path: Path) -> AnalysisReport:
    payload = _load_json(path)
    if not payload:
        raise ValueError(f"analysis report is empty or invalid JSON: {path}")
    config_payload = payload.get("config") if isinstance(payload.get("config"), Mapping) else {}
    config = ReportConfig(
        binary=str(config_payload.get("binary") or ""),
        export_dir=str(config_payload.get("export_dir") or ""),
        run_label=str(config_payload.get("run_label") or ""),
    )
    return AnalysisReport(
        config=config,
        candidate_findings=_mapping_rows(payload.get("candidate_findings")),
        function_summaries=_mapping_rows(payload.get("function_summaries")),
        confirmation_findings=_mapping_rows(payload.get("confirmation_findings")),
        vulnerability_reports=[
            _vulnerability_report_from_mapping(item)
            for item in _mapping_rows(payload.get("vulnerability_reports") or payload.get("vulnerabilities"))
        ],
        candidate_confirmations={
            str(key): value
            for key, value in (payload.get("candidate_confirmations") or {}).items()
        }
        if isinstance(payload.get("candidate_confirmations"), Mapping)
        else {},
        candidate_proofs={
            str(key): value
            for key, value in (payload.get("candidate_proofs") or {}).items()
        }
        if isinstance(payload.get("candidate_proofs"), Mapping)
        else {},
        debug_artifact_paths=dict(payload.get("debug_artifact_paths") or {})
        if isinstance(payload.get("debug_artifact_paths"), Mapping)
        else {},
        stage_metrics=dict(payload.get("stage_metrics") or {}) if isinstance(payload.get("stage_metrics"), Mapping) else {},
    )


def _vulnerability_report_from_mapping(data: Mapping[str, Any]) -> VulnerabilityReport:
    return VulnerabilityReport(
        report_id=str(data.get("report_id") or data.get("id") or data.get("candidate_id") or ""),
        slug=str(data.get("slug") or data.get("report_id") or data.get("candidate_id") or "report"),
        binary=str(data.get("binary") or ""),
        function_name=str(data.get("function_name") or ""),
        address=str(data.get("address") or ""),
        relative_path=str(data.get("relative_path") or ""),
        severity=str(data.get("severity") or ""),
        summary=str(data.get("summary") or data.get("title") or ""),
        reasoning=str(data.get("reasoning") or ""),
        vulnerability_type=str(data.get("vulnerability_type") or data.get("vulnerability") or "memory_overflow"),
        evidence=[str(item) for item in _sequence(data.get("evidence"))],
        recommendation=str(data.get("recommendation") or ""),
        call_path=[str(item) for item in _sequence(data.get("call_path"))],
        candidate_id=str(data.get("candidate_id") or ""),
        sink=str(data.get("sink") or ""),
        target_buffer=str(data.get("target_buffer") or ""),
        capacity_bytes=_safe_int(data.get("capacity_bytes")),
        overflow_condition=str(data.get("overflow_condition") or ""),
        cve_dossier=dict(data.get("cve_dossier") or {}) if isinstance(data.get("cve_dossier"), Mapping) else {},
        target_provenance=dict(data.get("target_provenance") or {})
        if isinstance(data.get("target_provenance"), Mapping)
        else {},
    )


def _mapping_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [_mapping(item) for item in value if isinstance(item, Mapping) or hasattr(item, "to_dict")]


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _prepare_intake_provenance(
    target: CapabilitySweepTarget,
    intake_dir: Path,
    *,
    export_dir: Path,
    overwrite: bool,
) -> dict[str, Any]:
    if target.intake_dir:
        if not intake_dir.exists():
            raise FileNotFoundError(f"intake_dir not found: {intake_dir}")
        return _load_intake_provenance(intake_dir, target=target)
    source_path = _intake_source_path(target)
    if source_path is None:
        return {}
    if not source_path.exists():
        raise FileNotFoundError(f"intake target not found: {source_path}")
    run_intake(
        source_path,
        intake_dir,
        export_dir=export_dir if str(export_dir) != "." and export_dir.exists() else None,
        overwrite=overwrite or not (intake_dir / "target.json").exists(),
    )
    return _load_intake_provenance(intake_dir, target=target)


def _intake_source_path(target: CapabilitySweepTarget) -> Path | None:
    if target.rootfs_path:
        return Path(target.rootfs_path)
    if target.binary_path:
        return Path(target.binary_path)
    return None


def _load_intake_provenance(intake_dir: Path, *, target: CapabilitySweepTarget) -> dict[str, Any]:
    target_payload = _load_json(intake_dir / "target.json")
    binaries = _json_rows(intake_dir / "binaries.json", "binaries")
    services = _json_rows(intake_dir / "services.json", "services")
    routes = _json_rows(intake_dir / "routes.json", "routes")
    configs = _json_rows(intake_dir / "configs.json", "configs")
    metadata = dict(target.metadata)
    primary_binary = _primary_intake_binary(binaries, services=services, target=target)
    architecture = str(primary_binary.get("architecture") or metadata.get("architecture") or "")
    startup_command = str(
        metadata.get("startup_command")
        or metadata.get("service_startup")
        or _intake_startup_command(services, primary_binary)
        or ""
    )
    rootfs_path = target.rootfs_path
    if not rootfs_path and str(target_payload.get("kind") or "") in {"rootfs", "archive_rootfs"}:
        rootfs_path = str(target_payload.get("path") or "")
    reproduction_environment = {
        key: value
        for key, value in {
            "rootfs_path": rootfs_path,
            "architecture": architecture,
            "startup_command": startup_command,
            "replay_mode": target.replay_mode,
        }.items()
        if value not in (None, "", [], {})
    }
    return {
        key: value
        for key, value in {
            "schema_version": 1,
            "intake_dir": str(intake_dir),
            "target_kind": target_payload.get("kind"),
            "target_path": target_payload.get("path") or target.binary_path or target.rootfs_path,
            "inventory_root": target_payload.get("inventory_root"),
            "binary_path": primary_binary.get("path") or target.binary_path,
            "binary_relative_path": primary_binary.get("relative_path"),
            "binary_sha256": primary_binary.get("sha256") or target_payload.get("sha256"),
            "package": metadata.get("package") or metadata.get("package_name"),
            "rootfs_path": rootfs_path,
            "product": metadata.get("product") or metadata.get("product_name"),
            "version": metadata.get("version") or metadata.get("firmware_version"),
            "architecture": architecture,
            "startup_command": startup_command,
            "reproduction_environment": reproduction_environment,
            "binary_count": len(binaries),
            "service_count": len(services),
            "route_count": len(routes),
            "config_count": len(configs),
            "binaries": _compact_rows(binaries, ("path", "relative_path", "sha256", "architecture", "source_target")),
            "services": _compact_rows(services, ("service_id", "name", "relative_path", "exec", "ports")),
            "routes": _compact_rows(routes, ("route_id", "route", "method", "relative_path")),
            "configs": _compact_rows(configs, ("config_id", "relative_path", "kind", "env_keys")),
        }.items()
        if value not in (None, "", [], {})
    }


def _primary_intake_binary(
    binaries: Sequence[Mapping[str, Any]],
    *,
    services: Sequence[Mapping[str, Any]] = (),
    target: CapabilitySweepTarget,
) -> Mapping[str, Any]:
    if not binaries:
        return {}
    if target.binary_path:
        target_path = Path(target.binary_path)
        target_name = target_path.name
        for row in binaries:
            row_path = Path(str(row.get("path") or ""))
            if row_path == target_path or row_path.name == target_name:
                return row
            relative_path = str(row.get("relative_path") or "")
            if relative_path == str(target_path) or Path(relative_path).name == target_name:
                return row
    service_binary_names = {
        name
        for service in services
        for name in _command_path_names(str(service.get("exec") or ""))
    }
    for row in binaries:
        binary_name = Path(str(row.get("path") or row.get("relative_path") or "")).name
        if binary_name and binary_name in service_binary_names:
            return row
    return binaries[0]


def _intake_startup_command(services: Sequence[Mapping[str, Any]], binary: Mapping[str, Any]) -> str:
    if not services:
        return ""
    binary_names = {
        Path(str(binary.get("path") or "")).name,
        Path(str(binary.get("relative_path") or "")).name,
    } - {""}
    for service in services:
        command = str(service.get("exec") or "")
        if command and binary_names.intersection(_command_path_names(command)):
            return command
    return str(services[0].get("exec") or "")


def _command_path_names(command: str) -> set[str]:
    names: set[str] = set()
    for token in command.split():
        path = token.strip("'\"")
        if "/" in path or path.startswith("."):
            name = Path(path).name
            if name:
                names.add(name)
    if not names and command.split():
        name = Path(command.split()[0].strip("'\"")).name
        if name:
            names.add(name)
    return names


def _json_rows(path: Path, key: str) -> list[dict[str, Any]]:
    payload = _load_json(path)
    rows = payload.get(key, []) if isinstance(payload, Mapping) else []
    return [dict(item) for item in rows if isinstance(item, Mapping)] if isinstance(rows, Sequence) else []


def _compact_rows(rows: Sequence[Mapping[str, Any]], keys: Sequence[str], *, limit: int = 8) -> list[dict[str, Any]]:
    return [
        {key: row[key] for key in keys if row.get(key) not in (None, "", [], {})}
        for row in rows[:limit]
    ]


def _looks_like_blocker(text: str) -> bool:
    return _blocker_category(text) != ""


def _blocker_category_counts(blockers: Sequence[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for blocker in set(str(item) for item in blockers if str(item)):
        category = _blocker_category(blocker)
        if category:
            counts[category] = counts.get(category, 0) + 1
    return counts


def _blocker_category(text: str) -> str:
    lowered = text.lower()
    if "unsupported" in lowered:
        return "unsupported"
    if "missing" in lowered or "not found" in lowered or "unavailable" in lowered:
        return "missing"
    if "timeout" in lowered or "timed out" in lowered:
        return "timeout"
    if "unresolved" in lowered:
        return "unresolved"
    if "blocked" in lowered:
        return "blocked"
    if "requires" in lowered:
        return "requires"
    return ""


def _evidence_pack_count(evidence_dir: Path) -> int:
    if not Path(evidence_dir).exists():
        return 0
    try:
        return sum(1 for _path, _pack in iter_evidence_packs(Path(evidence_dir)))
    except Exception:
        return 0


def _is_negative_target(target: CapabilitySweepTarget) -> bool:
    label = target.label.lower()
    return bool(target.expected_negatives) or label in {"negative", "known_negative", "safe", "benign"}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text() or "{}")
    except (OSError, json.JSONDecodeError):
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}


def _mapping(value: Any) -> dict[str, Any]:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    return dict(value) if isinstance(value, Mapping) else {}


def _path_text(value: Any, *, base_dir: Path) -> str:
    if value in (None, ""):
        return ""
    path = Path(str(value))
    if not path.is_absolute():
        path = base_dir / path
    return str(path)


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _dedupe(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in str(value))[:120] or "target"


_TARGET_FIELDS = {
    "id",
    "name",
    "label",
    "kind",
    "binary",
    "binary_path",
    "path",
    "export_dir",
    "export_path",
    "rootfs",
    "rootfs_path",
    "intake",
    "intake_dir",
    "artifact_dir",
    "run_dir",
    "analysis_report",
    "analysis_report_path",
    "report_json",
    "evidence_dir",
    "evidence_packs",
    "expected_positives",
    "expected_negatives",
    "replay_mode",
    "dynamic_confirm",
    "report_policy",
    "optional",
}
