"""Helpers for assembling and persisting deterministic vulnerability reports."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, List, Mapping, Sequence

from binary_agent.dynamic_proof import dynamic_access_metadata

from .models import ReportConfig, VulnerabilityReport


_SLUG_PATTERN = re.compile(r"[^a-z0-9]+")
_CONTROLLED_TAINT_CLASSES = {"source_controlled", "parameter_controlled"}
_DIRECT_UNBOUNDED_SOURCE_SINKS = {"gets", "scanf", "fscanf", "sscanf"}
_INTEGER_MEMORY_RISK_TYPES = {
    "integer_overflow_to_memory_access",
    "integer_underflow_to_memory_access",
    "signed_conversion_to_memory_access",
    "integer_truncation_to_memory_access",
}


def _slugify(*parts: str) -> str:
    text = "-".join(part for part in parts if part)
    slug = _SLUG_PATTERN.sub("-", text.lower()).strip("-")
    return slug or "vulnerability"


def _candidate_value(candidate: Any, name: str, default: Any = "") -> Any:
    if isinstance(candidate, dict):
        return candidate.get(name, default)
    return getattr(candidate, name, default)


def _format_call_path(path: Sequence[str]) -> str:
    return " -> ".join(path) if path else "(none)"


def _confirmation_value(confirmation: Any, name: str, default: Any = "") -> Any:
    if confirmation is None:
        return default
    if isinstance(confirmation, dict):
        return confirmation.get(name, default)
    return getattr(confirmation, name, default)


def _proof_value(proof: Any, name: str, default: Any = "") -> Any:
    if proof is None:
        return default
    if isinstance(proof, dict):
        return proof.get(name, default)
    return getattr(proof, name, default)


def _candidate_confirmation(candidate: Any, confirmations: Mapping[str, Any] | None) -> Any:
    if not confirmations:
        return None
    candidate_id = str(_candidate_value(candidate, "candidate_id", ""))
    return confirmations.get(candidate_id)


def _candidate_proof(candidate: Any, proofs: Mapping[str, Any] | None) -> Any:
    if not proofs:
        return None
    candidate_id = str(_candidate_value(candidate, "candidate_id", ""))
    return proofs.get(candidate_id)


def _is_reportable(
    candidate: Any,
    confirmations: Mapping[str, Any] | None = None,
    proofs: Mapping[str, Any] | None = None,
    report_policy: str = "deterministic",
) -> bool:
    vulnerability_type = str(_candidate_value(candidate, "vulnerability_type", "memory_overflow") or "memory_overflow")
    if vulnerability_type in _INTEGER_MEMORY_RISK_TYPES:
        return False
    if report_policy == "confirmed":
        confirmation = _candidate_confirmation(candidate, confirmations)
        return bool(_confirmation_value(confirmation, "status") == "confirmed_bug")
    relation = str(_candidate_value(candidate, "write_relation", ""))
    if vulnerability_type == "out_of_bounds_read":
        return bool(
            _candidate_value(candidate, "verdict", "") == "overflow"
            and relation == "proven_oob_read"
            and _has_deterministic_report_path(candidate)
        )
    if vulnerability_type != "memory_overflow":
        return False
    return bool(
        _candidate_value(candidate, "verdict", "") in {"overflow", "unbounded"}
        and (
            relation == "proven_overflow"
            or (relation == "unbounded" and _is_direct_unbounded_input_source(candidate))
        )
        and _has_deterministic_report_path(candidate)
    )


def _has_deterministic_report_path(candidate: Any) -> bool:
    if not _candidate_value(candidate, "path_is_valid", False):
        return False
    if _trace_is_complete_unreachable(candidate) or _weak_object_candidate_is_not_reportable(candidate):
        return False
    return _candidate_has_reportable_memory_influence(candidate)


def _candidate_has_reportable_memory_influence(candidate: Any) -> bool:
    roles = _source_to_write_roles(candidate)
    if roles:
        return any(
            _role_classification(roles, role) in _CONTROLLED_TAINT_CLASSES
            for role in ("write_source", "write_size", "write_offset", "destination_pointer")
        )
    return bool(_candidate_value(candidate, "input_reaches_sink", False))


def _source_to_write_roles(candidate: Any) -> Mapping[str, Any]:
    trace = _candidate_value(candidate, "classification_trace", {})
    if not isinstance(trace, Mapping):
        return {}
    source_to_write = trace.get("source_to_write")
    if not isinstance(source_to_write, Mapping):
        return {}
    roles = source_to_write.get("roles")
    return roles if isinstance(roles, Mapping) else {}


def _role_classification(roles: Mapping[str, Any], role: str) -> str:
    fact = roles.get(role)
    if not isinstance(fact, Mapping):
        return ""
    return str(fact.get("classification") or "")


def _trace_is_complete_unreachable(candidate: Any) -> bool:
    reachability = _reachability_dataflow_trace(candidate)
    graph = reachability.get("graph") if isinstance(reachability.get("graph"), Mapping) else {}
    return bool(graph.get("complete_unreachable_candidate")) if isinstance(graph, Mapping) else False


def _trace_has_source_or_parameter_taint(candidate: Any) -> bool:
    reachability = _reachability_dataflow_trace(candidate)
    expr_taint = reachability.get("expr_taint") if isinstance(reachability.get("expr_taint"), Mapping) else {}
    rows = expr_taint.get("taint_table", []) if isinstance(expr_taint, Mapping) else []
    if not isinstance(rows, list):
        return False
    return any(
        isinstance(row, Mapping)
        and str(row.get("classification") or "") in _CONTROLLED_TAINT_CLASSES
        for row in rows
    )


def _reachability_dataflow_trace(candidate: Any) -> Mapping[str, Any]:
    trace = _candidate_value(candidate, "classification_trace", {})
    if not isinstance(trace, Mapping):
        return {}
    reachability = trace.get("reachability_dataflow")
    return reachability if isinstance(reachability, Mapping) else {}


def _weak_object_candidate_is_not_reportable(candidate: Any) -> bool:
    trace = _candidate_value(candidate, "classification_trace", {})
    if isinstance(trace, Mapping):
        stack = trace.get("stack_coalescing") if isinstance(trace.get("stack_coalescing"), Mapping) else {}
        if stack and str(stack.get("classification") or "") == "likely_decompiler_split":
            return True
    basis = f"{_candidate_value(candidate, 'capacity_basis', '')} {_candidate_value(candidate, 'capacity_source', '')}".lower()
    return any(token in basis for token in ("merged_stack_region", "contiguous_stack_region", "decompiler local fragment"))


def _is_direct_unbounded_input_source(candidate: Any) -> bool:
    return str(_candidate_value(candidate, "sink", "")).lower() in _DIRECT_UNBOUNDED_SOURCE_SINKS


def build_vulnerability_reports(
    candidates: Sequence[Any],
    *,
    confirmations: Mapping[str, Any] | None = None,
    proofs: Mapping[str, Any] | None = None,
    report_policy: str = "deterministic",
) -> List[VulnerabilityReport]:
    """Convert reportable deterministic candidates into human-readable reports."""
    if report_policy not in {"deterministic", "confirmed"}:
        raise ValueError("report_policy must be 'deterministic' or 'confirmed'")
    reports: List[VulnerabilityReport] = []
    for candidate in candidates:
        if not _is_reportable(candidate, confirmations, proofs, report_policy):
            continue
        confirmation = _candidate_confirmation(candidate, confirmations)
        proof = _candidate_proof(candidate, proofs)
        binary = str(_candidate_value(candidate, "binary"))
        function_name = str(_candidate_value(candidate, "function_name"))
        address = str(_candidate_value(candidate, "address"))
        relative_path = str(_candidate_value(candidate, "relative_path"))
        sink = str(_candidate_value(candidate, "sink"))
        target_buffer = str(_candidate_value(candidate, "target_buffer"))
        capacity_bytes = int(_candidate_value(candidate, "capacity_bytes", 0) or 0)
        overflow_condition = str(_candidate_value(candidate, "overflow_condition"))
        candidate_id = str(_candidate_value(candidate, "candidate_id"))
        vulnerability_type = str(_candidate_value(candidate, "vulnerability_type", "memory_overflow") or "memory_overflow")
        evidence = [str(item) for item in (_candidate_value(candidate, "evidence", []) or [])]
        source_evidence = [str(item) for item in (_candidate_value(candidate, "source_evidence", []) or [])]
        guard_evidence = [str(item) for item in (_candidate_value(candidate, "guard_evidence", []) or [])]
        confirmation_evidence = []
        if confirmation is not None:
            reason_codes = _confirmation_value(confirmation, "reason_codes", []) or []
            reason_text = ", ".join(str(item) for item in reason_codes) or "confirmed_bug"
            confirmation_evidence.append(f"LLM hypothesis validation: {reason_text}")
        proof_evidence = []
        if proof is not None:
            proof_evidence.append("Proof verdict: proven_vulnerable")
        dynamic_confirmation = _confirmation_dynamic_proof(confirmation)
        if dynamic_confirmation:
            proof_status = str(dynamic_confirmation.get("status") or "")
            sink_address = dynamic_confirmation.get("sink_address")
            access = dynamic_access_metadata(proof_status=proof_status, vulnerability=vulnerability_type)
            overrun_bytes = dynamic_confirmation.get(str(access["byte_field"]))
            confirmation_evidence.append(
                "Ghidra dynamic proof: "
                f"{sink_address or 'exact sink'} {access['evidence_verb']} {overrun_bytes or 0} bytes"
            )
        call_path = [str(item) for item in (_candidate_value(candidate, "call_path", []) or [])]
        summary = _report_summary(vulnerability_type, sink, function_name, target_buffer, capacity_bytes)
        reports.append(
            VulnerabilityReport(
                report_id=candidate_id or f"{binary}:{address}:{function_name}",
                slug=_slugify(function_name, address, sink, target_buffer),
                binary=binary,
                function_name=function_name,
                address=address,
                relative_path=relative_path,
                severity=str(_candidate_value(candidate, "severity", "high")),
                summary=summary,
                reasoning=overflow_condition,
                vulnerability_type=vulnerability_type,
                evidence=evidence + source_evidence + guard_evidence + confirmation_evidence + proof_evidence,
                recommendation=_report_recommendation(vulnerability_type),
                call_path=call_path,
                candidate_id=candidate_id,
                sink=sink,
                target_buffer=target_buffer,
                capacity_bytes=capacity_bytes,
                overflow_condition=overflow_condition,
                cve_dossier=_build_cve_dossier(candidate, proof)
                if proof is not None
                else _build_confirmation_dossier(candidate, confirmation),
                target_provenance=_build_target_provenance(candidate, confirmation),
            )
        )
    return reports


def _build_target_provenance(candidate: Any, confirmation: Any = None) -> dict[str, Any]:
    provenance: dict[str, Any] = {
        "binary": _candidate_value(candidate, "binary", ""),
        "relative_path": _candidate_value(candidate, "relative_path", ""),
        "function_name": _candidate_value(candidate, "function_name", ""),
        "address": _candidate_value(candidate, "address", ""),
    }
    for key in (
        "binary_sha256",
        "sha256",
        "package",
        "product",
        "product_name",
        "version",
        "firmware_version",
        "service",
        "service_name",
        "rootfs_path",
        "architecture",
        "startup_command",
    ):
        value = _candidate_value(candidate, key, "")
        if value not in (None, ""):
            provenance[key] = value
    trace = _candidate_value(candidate, "classification_trace", {})
    if isinstance(trace, Mapping):
        for key in ("target_provenance", "firmware_provenance", "service_provenance"):
            value = trace.get(key)
            if isinstance(value, Mapping):
                provenance.update({str(k): v for k, v in value.items() if v not in (None, "")})
    provider = _confirmation_value(confirmation, "provider_metadata", {}) if confirmation is not None else {}
    if isinstance(provider, Mapping):
        for key in ("binary_sha256", "rootfs_path", "architecture", "service", "startup_command"):
            value = provider.get(key)
            if value not in (None, ""):
                provenance.setdefault(key, value)
    return {key: value for key, value in provenance.items() if value not in (None, "")}


def _report_summary(
    vulnerability_type: str,
    sink: str,
    function_name: str,
    target_buffer: str,
    capacity_bytes: int,
) -> str:
    if vulnerability_type == "out_of_bounds_read":
        return (
            f"{sink} in {function_name} can read outside {target_buffer} "
            f"({capacity_bytes} bytes)."
        )
    if vulnerability_type in _INTEGER_MEMORY_RISK_TYPES:
        return f"Integer expression feeding {sink} in {function_name} can corrupt a memory access."
    if vulnerability_type == "format_string":
        return f"{sink} in {function_name} can parse attacker-controlled data as a format string."
    if vulnerability_type in {"credential_disclosure", "hardcoded_credential"}:
        return f"{function_name} can disclose credential material through {sink or 'the observed sink'}."
    if vulnerability_type == "auth_bypass":
        return f"{function_name} can reach an authorization bypass effect through {sink or 'the observed sink'}."
    return f"{sink} in {function_name} can overflow {target_buffer} ({capacity_bytes} bytes)."


def _report_recommendation(vulnerability_type: str) -> str:
    if vulnerability_type == "out_of_bounds_read":
        return "Validate the read offset and length against the source object capacity before use."
    if vulnerability_type in _INTEGER_MEMORY_RISK_TYPES:
        return "Validate operands before arithmetic and use checked size calculations before memory access."
    if vulnerability_type == "format_string":
        return "Use constant format strings and pass attacker-controlled data as formatting arguments."
    if vulnerability_type in {"credential_disclosure", "hardcoded_credential"}:
        return "Remove embedded or exposed credentials and use a protected secret store with rotation."
    if vulnerability_type == "auth_bypass":
        return "Enforce authentication and authorization before the protected action and test unauthenticated requests."
    return "Bound the write by the destination capacity or replace the unsafe sink."


def _confirmation_dynamic_proof(confirmation: Any) -> Mapping[str, Any]:
    argument = _confirmation_value(confirmation, "memory_safety_argument", {}) or {}
    if not isinstance(argument, Mapping):
        return {}
    proof = argument.get("ghidra_dynamic_proof")
    return proof if isinstance(proof, Mapping) else {}


def _build_confirmation_dossier(candidate: Any, confirmation: Any) -> dict[str, Any]:
    if confirmation is None:
        return {}
    argument = _confirmation_value(confirmation, "memory_safety_argument", {}) or {}
    if not isinstance(argument, Mapping):
        argument = {}
    dynamic_proof = argument.get("ghidra_dynamic_proof")
    if not isinstance(dynamic_proof, Mapping):
        return {}
    return {
        "proof_verdict": {
            "provider": "concolic",
            "status": _confirmation_value(confirmation, "status", ""),
            "reason_codes": _confirmation_value(confirmation, "reason_codes", []) or [],
        },
        "root_cause": _candidate_value(candidate, "overflow_condition", ""),
        "affected_function": _candidate_value(candidate, "function_name", ""),
        "affected_binary": _candidate_value(candidate, "binary", ""),
        "cwe_guess": _guess_cwe(candidate),
        "dynamic_confirmation": {
            "ghidra_dynamic_proof": dict(dynamic_proof),
            "concrete_input": dict(argument.get("concrete_input") or {}),
            "sink_address": argument.get("sink_address", ""),
            "write_range": dict(argument.get("write_range") or dynamic_proof.get("write_range") or {}),
            "read_range": dict(argument.get("read_range") or dynamic_proof.get("read_range") or {}),
            "object_range": dict(argument.get("object_range") or dynamic_proof.get("object_range") or {}),
            "capacity_bytes": argument.get("capacity_bytes", dynamic_proof.get("capacity_bytes", 0)),
            "overflow_bytes": argument.get("overflow_bytes", dynamic_proof.get("overflow_bytes", 0)),
            "oob_bytes": argument.get("oob_bytes", dynamic_proof.get("oob_bytes", 0)),
            "harness_model": dict(argument.get("harness_model") or {}),
            "llm_trace": dict(argument.get("llm_trace") or {}),
            "native_replay": dict(argument.get("native_replay") or {"status": "not_run"}),
        },
    }


def _build_cve_dossier(candidate: Any, proof: Any) -> dict[str, Any]:
    trace = _candidate_value(candidate, "classification_trace", {})
    if not isinstance(trace, Mapping):
        trace = {}
    source_to_write = trace.get("source_to_write") if isinstance(trace.get("source_to_write"), Mapping) else {}
    reachability = trace.get("reachability_dataflow") if isinstance(trace.get("reachability_dataflow"), Mapping) else {}
    proof_dict = proof.to_dict() if hasattr(proof, "to_dict") else dict(proof or {})
    vulnerability_argument = _proof_value(proof, "vulnerability_argument", {}) or {}
    if not isinstance(vulnerability_argument, Mapping):
        vulnerability_argument = {}
    facts = _proof_tool_facts(proof_dict)
    return {
        "proof_verdict": proof_dict,
        "root_cause": vulnerability_argument.get("root_cause")
        or _candidate_value(candidate, "overflow_condition", "")
        or _candidate_value(candidate, "write_relation", ""),
        "affected_function": _candidate_value(candidate, "function_name", ""),
        "affected_binary": _candidate_value(candidate, "binary", ""),
        "cwe_guess": _guess_cwe(candidate),
        "source_to_write": dict(source_to_write),
        "reachability": dict(reachability) if isinstance(reachability, Mapping) else {},
        "reproducer_hypothesis": facts.get("reproducer_hypothesis", {}),
        "dynamic_logs": facts.get("dynamic_logs", []),
    }


def _proof_tool_facts(proof_dict: Mapping[str, Any]) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    for item in proof_dict.get("tool_results", []) or []:
        if not isinstance(item, Mapping):
            continue
        result = item.get("result")
        if not isinstance(result, Mapping):
            continue
        for key in ("reproducer_hypothesis", "dynamic_logs"):
            if key in result and key not in facts:
                facts[key] = result[key]
    return facts


def _guess_cwe(candidate: Any) -> str:
    vulnerability_type = str(_candidate_value(candidate, "vulnerability_type", "memory_overflow") or "memory_overflow")
    if vulnerability_type == "out_of_bounds_read":
        return "CWE-126" if str(_candidate_value(candidate, "kind", "")) == "source_read" else "CWE-125"
    if vulnerability_type == "integer_overflow_to_memory_access":
        return "CWE-190"
    if vulnerability_type == "integer_underflow_to_memory_access":
        return "CWE-191"
    if vulnerability_type == "signed_conversion_to_memory_access":
        return "CWE-195"
    if vulnerability_type == "integer_truncation_to_memory_access":
        return "CWE-681"
    if vulnerability_type == "format_string":
        return "CWE-134"
    if vulnerability_type in {"credential_disclosure", "hardcoded_credential"}:
        return "CWE-798"
    if vulnerability_type == "auth_bypass":
        return "CWE-862"
    sink = str(_candidate_value(candidate, "sink", "")).lower()
    relation = str(_candidate_value(candidate, "write_relation", "")).lower()
    if sink in {"gets", "strcpy", "strcat", "sprintf", "vsprintf"} or relation == "unbounded":
        return "CWE-120"
    if "stack" in str(_candidate_value(candidate, "destination_kind", "")).lower():
        return "CWE-121"
    return "CWE-787"


def _format_dynamic_range(value: Any) -> str:
    if not isinstance(value, Mapping):
        return "(none)"
    parts: list[str] = []
    range_kind = str(value.get("range_kind") or "")
    base = str(value.get("base") or "")
    start = value.get("start_offset")
    end = value.get("end_offset_exclusive")
    size = value.get("size_bytes")
    if range_kind:
        parts.append(range_kind)
    if base and start is not None and end is not None:
        parts.append(f"{base}[{start}..{end})")
    elif start is not None and end is not None:
        parts.append(f"[{start}..{end})")
    if size is not None:
        parts.append(f"{size} bytes")
    return ", ".join(parts) or "(none)"


def _json_summary(value: Any) -> str:
    if not isinstance(value, Mapping) or not value:
        return "{}"
    return json.dumps(dict(value), sort_keys=True)


def _dynamic_confirmation_markdown_lines(report: VulnerabilityReport) -> list[str]:
    dossier = report.cve_dossier if isinstance(report.cve_dossier, Mapping) else {}
    dynamic = dossier.get("dynamic_confirmation")
    if not isinstance(dynamic, Mapping):
        return []
    proof = dynamic.get("ghidra_dynamic_proof")
    if not isinstance(proof, Mapping):
        proof = {}
    concrete_input = dynamic.get("concrete_input")
    if not isinstance(concrete_input, Mapping):
        concrete_input = {}
    native_replay = dynamic.get("native_replay")
    if not isinstance(native_replay, Mapping):
        native_replay = {"status": "not_run"}

    input_hex = str(concrete_input.get("input_hex") or "")
    input_model = str(concrete_input.get("input_model") or "")
    input_source = str(concrete_input.get("source") or "")
    input_bytes = len(input_hex) // 2 if input_hex else 0
    sink_address = dynamic.get("sink_address") or proof.get("sink_address") or ""
    proof_status = str(proof.get("status") or "")
    access = dynamic_access_metadata(proof_status=proof_status, vulnerability=report.vulnerability_type)
    access_size = proof.get(str(access["size_field"]), "")
    capacity = dynamic.get("capacity_bytes", proof.get("capacity_bytes", ""))
    overrun = dynamic.get(str(access["byte_field"]), proof.get(str(access["byte_field"]), ""))

    lines = [
        "",
        "## Dynamic Confirmation",
        "",
        f"- Ghidra proof status: {proof.get('status') or '(unknown)'}",
        f"- Destination kind: {proof.get('destination_kind') or '(unknown)'}",
        f"- Exact sink: `{sink_address or '(unknown)'}`",
        f"- {access['label']}/capacity/overrun: {access_size} / {capacity} / {overrun} bytes",
        f"- {access['label']} range: {_format_dynamic_range(dynamic.get(str(access['range_field'])))}",
        f"- Object range: {_format_dynamic_range(dynamic.get('object_range'))}",
        f"- Concrete input: {input_model or '(unknown)'} {input_source or ''} {input_bytes} bytes".rstrip(),
    ]
    if input_hex:
        lines.append(f"- Concrete input hex: `{input_hex}`")
    lines.extend(
        [
            f"- Harness model: {_json_summary(dynamic.get('harness_model'))}",
            f"- LLM trace: {_json_summary(dynamic.get('llm_trace'))}",
            f"- Native replay: {native_replay.get('status') or 'not_run'}",
        ]
    )
    return lines


def render_markdown_report(report: VulnerabilityReport, config: ReportConfig) -> str:
    """Render a single deterministic vulnerability report as Markdown."""
    call_path = _format_call_path(report.call_path)
    evidence = "\n".join(f"- {item}" for item in report.evidence) if report.evidence else "- (none)"
    recommendation = report.recommendation or "Review the unsafe memory operation and enforce strict bounds."
    lines = [
        f"# Vulnerability Report: {report.function_name} ({report.address})",
        "",
        f"- **Binary:** `{report.binary}`",
        f"- **Run label:** {config.run_label}",
        f"- **Source file:** {report.relative_path or '(unknown)'}",
        f"- **Severity:** {report.severity or 'unassigned'}",
        f"- **Vulnerability type:** `{report.vulnerability_type or 'memory_overflow'}`",
        f"- **Candidate:** `{report.candidate_id or report.report_id}`",
        f"- **Sink:** `{report.sink or '(unknown)'}`",
        f"- **Target buffer:** `{report.target_buffer or '(unknown)'}` ({report.capacity_bytes} bytes)",
        f"- **Call path:** {call_path}",
        "",
        "## Summary",
        "",
        report.summary or "No summary provided.",
        "",
        "## Deterministic Evidence",
        "",
        f"- Reasoning: {report.reasoning or '(none)'}",
        "- Evidence:",
        evidence,
        "",
        f"- Recommendation: {recommendation}",
    ]
    if report.cve_dossier:
        lines.extend(
            [
                "",
                "## Validated Proof Artifact",
                "",
                f"- Root cause: {report.cve_dossier.get('root_cause') or '(unknown)'}",
                f"- CWE guess: {report.cve_dossier.get('cwe_guess') or '(unknown)'}",
                f"- Affected function: {report.cve_dossier.get('affected_function') or report.function_name}",
                f"- Affected binary: {report.cve_dossier.get('affected_binary') or report.binary}",
            ]
        )
        lines.extend(_dynamic_confirmation_markdown_lines(report))
    if report.target_provenance:
        lines.extend(_target_provenance_markdown_lines(report.target_provenance))
    return "\n".join(lines).rstrip() + "\n"


def _target_provenance_markdown_lines(provenance: Mapping[str, Any]) -> list[str]:
    lines = ["", "## Target Provenance", ""]
    for key in (
        "sha256",
        "binary_sha256",
        "product",
        "product_name",
        "version",
        "firmware_version",
        "service",
        "service_name",
        "rootfs_path",
        "architecture",
        "startup_command",
    ):
        value = provenance.get(key)
        if value not in (None, ""):
            label = key.replace("_", " ").title()
            lines.append(f"- {label}: `{value}`")
    return lines if len(lines) > 3 else []


def _write_empty_placeholder(output_dir: Path, config: ReportConfig) -> Path:
    placeholder = (
        "# No verified vulnerabilities\n\n"
        f"The run for `{config.binary}` (label `{config.run_label}`) produced no deterministic, "
        "reachable source-to-sink overflow candidates."
    )
    path = output_dir / "README.md"
    path.write_text(placeholder)
    return path


def _clear_previous_reports(output_dir: Path) -> None:
    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)
        return
    for entry in output_dir.iterdir():
        if entry.is_file() and (entry.name == "README.md" or (entry.suffix == ".md" and entry.name[:3].isdigit())):
            entry.unlink()


def write_markdown_reports(
    reports: Sequence[VulnerabilityReport],
    output_dir: Path,
    config: ReportConfig,
) -> List[Path]:
    """Write Markdown files for each reportable deterministic candidate."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    _clear_previous_reports(output_dir)

    written: List[Path] = []
    if not reports:
        _write_empty_placeholder(output_dir, config)
        return written

    for index, report in enumerate(reports, start=1):
        path = output_dir / f"{index:03d}_{report.slug}.md"
        path.write_text(render_markdown_report(report, config))
        written.append(path)
    return written
