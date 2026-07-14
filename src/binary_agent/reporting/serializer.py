"""Serialization helpers for analysis reports."""

from __future__ import annotations

import json
from pathlib import Path

from .models import AnalysisReport


def serialize_report(report: AnalysisReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def save_report_json(report: AnalysisReport, output_path: Path) -> Path:
    text = serialize_report(report)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text)
    return output_path
