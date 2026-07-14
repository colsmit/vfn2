"""Data models for deterministic analysis reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, List, Mapping


@dataclass(frozen=True)
class ReportConfig:
    binary: str
    export_dir: str
    run_label: str


@dataclass(frozen=True)
class VulnerabilityReport:
    report_id: str
    slug: str
    binary: str
    function_name: str
    address: str
    relative_path: str
    severity: str
    summary: str
    reasoning: str
    vulnerability_type: str = "memory_overflow"
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""
    call_path: List[str] = field(default_factory=list)
    candidate_id: str = ""
    sink: str = ""
    target_buffer: str = ""
    capacity_bytes: int = 0
    overflow_condition: str = ""
    cve_dossier: Mapping[str, Any] = field(default_factory=dict)
    target_provenance: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class AnalysisReport:
    config: ReportConfig
    candidate_findings: List[Any] = field(default_factory=list)
    function_summaries: List[Any] = field(default_factory=list)
    confirmation_findings: List[Any] = field(default_factory=list)
    vulnerability_reports: List[VulnerabilityReport] = field(default_factory=list)
    candidate_confirmations: Mapping[str, Any] = field(default_factory=dict)
    candidate_proofs: Mapping[str, Any] = field(default_factory=dict)
    debug_artifact_paths: Mapping[str, str] = field(default_factory=dict)
    stage_metrics: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "config": {
                "binary": self.config.binary,
                "export_dir": self.config.export_dir,
                "run_label": self.config.run_label,
            },
            "candidate_findings": [
                item.to_dict() if hasattr(item, "to_dict") else dict(item)
                for item in self.candidate_findings
            ],
            "function_summaries": [
                item.to_dict() if hasattr(item, "to_dict") else dict(item)
                for item in self.function_summaries
            ],
            "confirmation_findings": [
                item.to_dict() if hasattr(item, "to_dict") else dict(item)
                for item in self.confirmation_findings
            ],
            "candidate_confirmations": {
                key: value.to_dict() if hasattr(value, "to_dict") else dict(value)
                for key, value in self.candidate_confirmations.items()
            },
            "candidate_proofs": {
                key: value.to_dict() if hasattr(value, "to_dict") else dict(value)
                for key, value in self.candidate_proofs.items()
            },
            "vulnerability_reports": [report.to_dict() for report in self.vulnerability_reports],
            "debug_artifact_paths": dict(self.debug_artifact_paths),
            "stage_metrics": dict(self.stage_metrics),
        }
