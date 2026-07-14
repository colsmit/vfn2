"""LLM semantic seeding over cheap, deterministic binary features.

The semantic seed stage is deliberately a discovery helper, not a proof
authority.  It lets an external model propose concrete seed locations and
replay hints, while this module validates that every anchor exists in the
feature index before the seed can become a pipeline candidate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from binary_agent.discovery.base import DiscoveryContext, load_discovery_context
from binary_agent.ingest.loader import FunctionNode
from binary_agent.pipeline import CandidateState, CandidateStatus, ProofObligation
from binary_agent.utils.time import utc_timestamp


PROMPT_VERSION = "semantic-seed-v3-source-sink-fallback"
LLM_SEMANTIC_SEED_CLASSES = (
    "command_injection",
    "path_traversal",
    "unsafe_file_write",
)
MEMORY_SEMANTIC_ENRICHMENT_CLASSES = ("fs_config_memory_corruption",)
DEFAULT_SEMANTIC_SEED_CLASSES = LLM_SEMANTIC_SEED_CLASSES
SUPPORTED_SEMANTIC_SEED_CLASSES = LLM_SEMANTIC_SEED_CLASSES + MEMORY_SEMANTIC_ENRICHMENT_CLASSES
SHELL_SINKS = {"system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve"}
FILE_READ_SINKS = {"fopen", "open", "stat", "lstat"}
FILE_WRITE_SINKS = {"fopen", "open", "write", "fwrite", "creat"}
FS_MEMORY_SINKS = {"opendir", "readdir", "readdir_r", "closedir", "snprintf", "sprintf", "strcat", "strcpy", "memcpy"}
FS_CONFIG_SOURCE_CALLS = {
    "getstring",
    "getinteger",
    "getboolean",
    "getvalue",
    "ifstream",
    "ofstream",
    "operator.new",
    "operator_new",
    "strtol",
}
PROOF_CLAIM_VALUES = {
    "confirmed",
    "replay_confirmed",
    "report_ready",
    "proven",
    "proved",
    "verified",
}
CLASS_PROOF_ORACLES = {
    "command_injection": "command_effect",
    "path_traversal": "filesystem_read_escape",
    "unsafe_file_write": "filesystem_write_escape",
    "credential_disclosure": "credential_disclosure",
    "hardcoded_credential": "credential_disclosure",
    "auth_bypass": "auth_bypass_effect",
}
GENERIC_SINK_WRAPPER_NAMES = {
    "creat",
    "execle",
    "execl",
    "execlp",
    "execv",
    "execve",
    "execvp",
    "fopen",
    "fread",
    "fwrite",
    "lstat",
    "open",
    "popen",
    "read",
    "remove",
    "rename",
    "sendfile",
    "stat",
    "system",
    "unlink",
    "write",
}
COMMAND_SIGNAL_TOKENS = (
    "/bin/sh",
    "sh -c",
    "ping",
    "traceroute",
    "nslookup",
    "iptables",
    "ifconfig",
    "route",
    "wget",
    "curl",
    "diagnostic",
    "diag",
    "command",
    "cmd",
)
PATH_TRAVERSAL_SIGNAL_TOKENS = (
    "../",
    "..%2f",
    "%2e%2e",
    "/etc/passwd",
    "download",
    "filename",
    "filepath",
    "path",
    "file",
    "config",
    "template",
    "export",
    "backup",
)
UNSAFE_WRITE_SIGNAL_TOKENS = (
    "upload",
    "restore",
    "backup",
    "write",
    "import",
    "extract",
    "firmware",
    "upgrade",
    "tar",
    "zip",
    "filename",
    "path",
)


class SemanticSeedProvider(Protocol):
    """Provider interface for cluster triage and targeted zoom prompts."""

    def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any] | Sequence[Any]:
        """Return JSON containing accepted clusters or concrete semantic seeds."""


@dataclass(frozen=True)
class ExternalCommandSemanticSeedProvider:
    """Run a provider command that reads one seed pack from stdin as JSON."""

    command: Sequence[str]
    timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        if not self.command:
            raise ValueError("Semantic seed provider command must not be empty.")

    @classmethod
    def from_command_string(
        cls,
        command: str,
        *,
        timeout_seconds: float | None = None,
    ) -> "ExternalCommandSemanticSeedProvider":
        return cls(shlex.split(command), timeout_seconds=timeout_seconds)

    def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any] | Sequence[Any]:
        env = dict(os.environ)
        env["BINARY_AGENT_SEMANTIC_SEED_PHASE"] = str(phase)
        env["BINARY_AGENT_SEMANTIC_SEED_CLASS"] = str(vuln_class)
        try:
            completed = subprocess.run(
                list(self.command),
                input=json.dumps(pack),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Semantic seed provider command timed out after {self.timeout_seconds} seconds") from exc
        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            detail = f": {stderr[:1000]}" if stderr else ""
            raise RuntimeError(f"Semantic seed provider command exited with status {completed.returncode}{detail}")
        stdout = (completed.stdout or "").strip()
        if not stdout:
            raise RuntimeError("Semantic seed provider command produced no JSON on stdout")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Semantic seed provider command produced invalid JSON: {exc}") from exc
        if not isinstance(payload, (Mapping, list, tuple)):
            raise RuntimeError("Semantic seed provider output must be a JSON object or list")
        return payload


@dataclass(frozen=True)
class SemanticSeedStageResult:
    output_dir: Path
    summary_path: Path
    feature_index_summary_path: Path
    accepted_index_path: Path
    rejected_index_path: Path
    accepted_seed_paths: tuple[Path, ...] = field(default_factory=tuple)
    rejected_seed_paths: tuple[Path, ...] = field(default_factory=tuple)
    cluster_pack_paths: tuple[Path, ...] = field(default_factory=tuple)
    zoom_pack_paths: tuple[Path, ...] = field(default_factory=tuple)
    raw_paths: tuple[Path, ...] = field(default_factory=tuple)
    summary: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for key in (
            "output_dir",
            "summary_path",
            "feature_index_summary_path",
            "accepted_index_path",
            "rejected_index_path",
        ):
            payload[key] = str(payload[key])
        for key in (
            "accepted_seed_paths",
            "rejected_seed_paths",
            "cluster_pack_paths",
            "zoom_pack_paths",
            "raw_paths",
        ):
            payload[key] = [str(path) for path in payload[key]]
        payload["summary"] = dict(self.summary)
        return payload


@dataclass(frozen=True)
class SemanticTarget:
    """A grounded target region the model ranked for deterministic validation."""

    vulnerability_type: str
    string_signal_id: str = ""
    function_name: str = ""
    function_address: str = ""
    sink_name: str = ""
    sink_address: str = ""
    string_anchor: str = ""
    config_key: str = ""
    source_expression: str = ""
    sink_callsite: str = ""
    proof_oracle_kind: str = ""
    likely_source: Mapping[str, Any] = field(default_factory=dict)
    replay_hint: Mapping[str, Any] = field(default_factory=dict)
    proof_obligation: Mapping[str, Any] = field(default_factory=dict)
    deterministic_replay_intent: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vulnerability_type": self.vulnerability_type,
            "string_signal_id": self.string_signal_id,
            "function_name": self.function_name,
            "function_address": self.function_address,
            "sink_name": self.sink_name,
            "sink_address": self.sink_address,
            "string_anchor": self.string_anchor,
            "config_key": self.config_key,
            "source_expression": self.source_expression,
            "sink_callsite": self.sink_callsite,
            "proof_oracle_kind": self.proof_oracle_kind,
            "likely_source": dict(self.likely_source),
            "replay_hint": dict(self.replay_hint),
            "proof_obligation": dict(self.proof_obligation),
            "deterministic_replay_intent": dict(self.deterministic_replay_intent),
        }

    def canonical_key(self, *, binary: str = "") -> tuple[str, ...]:
        return (
            str(binary or ""),
            self.vulnerability_type,
            self.function_address or _name_key(self.function_name),
            self.sink_address or _name_key(self.sink_name),
            self.string_signal_id or self.string_anchor,
            self.config_key,
            self.proof_oracle_kind
            or str(self.proof_obligation.get("condition") or self.proof_obligation.get("kind") or ""),
        )


def build_semantic_feature_index(
    export_dir: Path,
    *,
    binary_path: Path | str | None = None,
    intake_dir: Path | None = None,
    context: DiscoveryContext | None = None,
) -> dict[str, Any]:
    """Build a cheap feature index without embedding full decompiled bodies."""

    context = context or load_discovery_context(export_dir, intake_dir=intake_dir)
    binary = Path(str(binary_path or ""))
    binary_strings = _binary_ascii_strings(binary) if binary.exists() else []
    functions = [_function_feature(node) for node in context.nodes]
    return {
        "schema_version": 1,
        "prompt_version": PROMPT_VERSION,
        "generated_at": utc_timestamp(),
        "binary": context.manifest.binary,
        "binary_path": str(binary) if binary.exists() else "",
        "binary_sha256": _sha256(binary) if binary.exists() and binary.is_file() else "",
        "function_count": len(functions),
        "functions": functions,
        "routes": _intake_rows(context.intake_artifacts, "routes", "routes"),
        "services": _intake_rows(context.intake_artifacts, "services", "services"),
        "configs": _intake_rows(context.intake_artifacts, "configs", "configs"),
        "binary_strings": binary_strings[:2000],
    }


def run_semantic_seed_stage(
    export_dir: Path,
    output_dir: Path,
    *,
    binary_path: Path | str | None = None,
    intake_dir: Path | None = None,
    provider: SemanticSeedProvider | None = None,
    provider_command: str | Sequence[str] | None = None,
    classes: Sequence[str] = DEFAULT_SEMANTIC_SEED_CLASSES,
    max_clusters_per_class: int = 12,
    max_zoom_seeds: int = 24,
    max_seeds_per_function_class: int = 2,
    provider_timeout_seconds: float | None = 120.0,
    cache_dir: Path | None = None,
) -> SemanticSeedStageResult:
    """Run deterministic clustering plus optional LLM semantic seed validation."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cluster_dir = output_dir / "cluster_packs"
    zoom_dir = output_dir / "zoom_packs"
    accepted_dir = output_dir / "accepted"
    rejected_dir = output_dir / "rejected"
    for path in (cluster_dir, zoom_dir, accepted_dir, rejected_dir):
        path.mkdir(parents=True, exist_ok=True)

    selected_classes = _normalize_classes(classes)
    context = load_discovery_context(export_dir, intake_dir=intake_dir)
    feature_index = build_semantic_feature_index(
        export_dir,
        binary_path=binary_path,
        intake_dir=intake_dir,
        context=context,
    )
    feature_index_summary_path = output_dir / "feature_index_summary.json"
    feature_index_summary_path.write_text(json.dumps(feature_index, indent=2, sort_keys=True))

    selected_provider = _select_provider(
        provider,
        provider_command=provider_command,
        timeout_seconds=provider_timeout_seconds,
    )

    cluster_pack_paths: list[Path] = []
    zoom_pack_paths: list[Path] = []
    raw_paths: list[Path] = []
    accepted_paths: list[Path] = []
    rejected_paths: list[Path] = []
    accepted_rows: list[dict[str, Any]] = []
    rejected_rows: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    provider_calls = 0
    cache_hits = 0
    cost_totals = _empty_costs()
    cluster_counts: dict[str, int] = {}
    accepted_cluster_counts: dict[str, int] = {}
    string_signal_counts: dict[str, int] = {}
    context_pack_counts: dict[str, int] = {}
    memory_feature_count = 0
    accepted_target_keys: set[tuple[str, ...]] = set()
    accepted_function_class_counts: dict[tuple[str, str], int] = {}

    clusters_by_class = {
        vuln_class: _cluster_features(feature_index, vuln_class, max_clusters=max_clusters_per_class)
        for vuln_class in selected_classes
    }

    for vuln_class, clusters in clusters_by_class.items():
        cluster_counts[vuln_class] = len(clusters)
        if vuln_class in LLM_SEMANTIC_SEED_CLASSES:
            string_signal_counts[vuln_class] = len(clusters)
        pack = _cluster_pack(feature_index, vuln_class, clusters)
        path = cluster_dir / f"{vuln_class}.json"
        path.write_text(json.dumps(pack, indent=2, sort_keys=True))
        cluster_pack_paths.append(path)

    for vuln_class in selected_classes:
        if vuln_class not in MEMORY_SEMANTIC_ENRICHMENT_CLASSES:
            continue
        for cluster in clusters_by_class.get(vuln_class, []):
            artifact = _memory_enrichment_artifact(vuln_class, cluster)
            path = _write_seed_artifact(artifact, accepted_dir)
            accepted_paths.append(path)
            accepted_rows.append(_accepted_row(artifact, path))
            memory_feature_count += 1

    if selected_provider is None:
        summary = _summary_payload(
            enabled=False,
            provider_name="disabled",
            provider_command=provider_command,
            classes=selected_classes,
            cluster_counts=cluster_counts,
            accepted_cluster_counts={vuln_class: 0 for vuln_class in selected_classes},
            accepted_count=len(accepted_rows),
            rejected_count=len(rejected_rows),
            provider_calls=0,
            cache_hits=0,
            cost_totals=cost_totals,
            errors={},
            reason="no_semantic_seed_provider_configured",
            string_signal_counts=string_signal_counts,
            context_pack_counts=context_pack_counts,
            memory_feature_count=memory_feature_count,
            rejected_by_reason=_rejected_reason_counts(rejected_rows),
        )
        return _write_stage_result(
            output_dir,
            feature_index_summary_path,
            summary,
            accepted_rows,
            rejected_rows,
            accepted_paths,
            rejected_paths,
            cluster_pack_paths,
            zoom_pack_paths,
            raw_paths,
        )

    known = _KnownFeatureIndex.from_feature_index(feature_index)
    provider_name = type(selected_provider).__name__
    provider_cache_key = _provider_cache_key(selected_provider)
    cache_root = Path(cache_dir) / "semantic_seed" if cache_dir is not None else None
    zoom_budget_remaining = max(0, int(max_zoom_seeds))

    llm_classes = [vuln_class for vuln_class in selected_classes if vuln_class in LLM_SEMANTIC_SEED_CLASSES]
    for vuln_class in selected_classes:
        accepted_cluster_counts[vuln_class] = len(clusters_by_class.get(vuln_class, [])) if vuln_class in LLM_SEMANTIC_SEED_CLASSES else 0
    max_cluster_count = max((len(clusters_by_class.get(vuln_class, [])) for vuln_class in llm_classes), default=0)
    for cluster_index in range(max_cluster_count):
        for vuln_class in llm_classes:
            if zoom_budget_remaining <= 0:
                break
            clusters = clusters_by_class.get(vuln_class, [])
            if cluster_index >= len(clusters):
                continue
            cluster = clusters[cluster_index]
            cluster_by_id = {str(item["cluster_id"]): item for item in clusters}
            zoom_pack = _zoom_pack(feature_index, context, vuln_class, cluster)
            cluster_id = str(cluster.get("cluster_id") or "")
            zoom_path = zoom_dir / f"{vuln_class}_{_safe_stem(cluster_id)}.json"
            zoom_path.write_text(json.dumps(zoom_pack, indent=2, sort_keys=True))
            zoom_pack_paths.append(zoom_path)
            context_pack_counts[vuln_class] = context_pack_counts.get(vuln_class, 0) + 1
            try:
                raw_payload, raw_path, cached = _provider_json(
                    selected_provider,
                    zoom_pack,
                    phase="targeted_zoom",
                    vuln_class=vuln_class,
                    output_dir=output_dir,
                    cache_dir=cache_root,
                    binary_hash=str(feature_index.get("binary_sha256") or feature_index.get("binary") or ""),
                    provider_cache_key=provider_cache_key,
                )
                raw_paths.append(raw_path)
                cache_hits += 1 if cached else 0
                provider_calls += 0 if cached else 1
                _add_costs(cost_totals, _payload_cost(raw_payload))
            except Exception as exc:
                errors[f"targeted_zoom:{vuln_class}:{cluster_id}"] = str(exc)[:1000]
                rejected_rows.append(_rejected_row(cluster_id, vuln_class, "provider_error", str(exc)[:1000], ""))
                continue
            for seed in _seed_payloads(raw_payload):
                artifact = _validate_seed_payload(
                    seed,
                    vuln_class=vuln_class,
                    allowed_classes=selected_classes,
                    known=known,
                    clusters=cluster_by_id,
                    zoom_pack=zoom_pack,
                )
                artifact = _apply_semantic_seed_acceptance_policy(
                    artifact,
                    binary=str(feature_index.get("binary") or ""),
                    accepted_target_keys=accepted_target_keys,
                    accepted_function_class_counts=accepted_function_class_counts,
                    max_seeds_per_function_class=max_seeds_per_function_class,
                )
                path = _write_seed_artifact(artifact, accepted_dir if artifact["accepted"] else rejected_dir)
                if artifact["accepted"]:
                    accepted_paths.append(path)
                    accepted_rows.append(_accepted_row(artifact, path))
                else:
                    rejected_paths.append(path)
                    rejected_rows.append(_rejected_index_row(artifact, path))
            zoom_budget_remaining -= 1
        if zoom_budget_remaining <= 0:
            break

    summary = _summary_payload(
        enabled=True,
        provider_name=provider_name,
        provider_command=provider_command,
        classes=selected_classes,
        cluster_counts=cluster_counts,
        accepted_cluster_counts={vuln_class: accepted_cluster_counts.get(vuln_class, 0) for vuln_class in selected_classes},
        accepted_count=len(accepted_rows),
        rejected_count=len(rejected_rows),
        provider_calls=provider_calls,
        cache_hits=cache_hits,
        cost_totals=cost_totals,
        errors=errors,
        string_signal_counts=string_signal_counts,
        context_pack_counts=context_pack_counts,
        memory_feature_count=memory_feature_count,
        rejected_by_reason=_rejected_reason_counts(rejected_rows),
    )
    return _write_stage_result(
        output_dir,
        feature_index_summary_path,
        summary,
        accepted_rows,
        rejected_rows,
        accepted_paths,
        rejected_paths,
        cluster_pack_paths,
        zoom_pack_paths,
        raw_paths,
    )


def _memory_enrichment_artifact(vuln_class: str, cluster: Mapping[str, Any]) -> dict[str, Any]:
    anchors = [dict(item) for item in cluster.get("anchors", []) or [] if isinstance(item, Mapping)]
    features = cluster.get("features") if isinstance(cluster.get("features"), Mapping) else {}
    calls = [str(item) for item in features.get("calls", []) or [] if str(item)]
    sink_name = _preferred_memory_sink(calls)
    cluster_id = str(cluster.get("cluster_id") or "")
    location = _location_from_cluster_anchor(anchors)
    signal = {
        "signal_id": _stable_id("memory_semantic_feature", vuln_class, cluster_id, location.get("address"), sink_name),
        "vulnerability_type": vuln_class,
        "kind": "deterministic_memory_enrichment",
        "anchor": "; ".join(str(item) for item in features.get("strings", []) or [] if str(item))[:240],
        "matched_tokens": list(cluster.get("reasons", []) or [])[:8],
    }
    seed_id = _stable_id("semantic_memory_enrichment", vuln_class, cluster_id, location.get("function_name"), location.get("address"), sink_name)
    source = {
        "kind": "config_or_filesystem",
        "expression": "; ".join(str(item) for item in list(cluster.get("reasons", []) or [])[:6]),
    }
    sink = {"kind": "memory_sink", "name": sink_name or "memory_write"}
    return {
        "schema_version": 1,
        "seed_id": seed_id,
        "accepted": True,
        "failure_reason": "",
        "vulnerability_type": vuln_class,
        "cluster_id": cluster_id,
        "string_signal_id": signal["signal_id"],
        "string_anchor": signal["anchor"],
        "anchors": anchors,
        "location": location,
        "source": source,
        "source_expression": source["expression"],
        "sink": sink,
        "sink_callsite": _sink_callsite(sink, location),
        "proof_oracle_kind": "",
        "deterministic_replay_intent": {
            "policy": "deterministic_memory_enrichment_only",
            "semantic_provider_calls": 0,
        },
        "semantic_target": SemanticTarget(
            vulnerability_type=vuln_class,
            string_signal_id=signal["signal_id"],
            function_name=str(location.get("function_name") or ""),
            function_address=_normalize_address(location.get("address")),
            sink_name=str(sink.get("name") or ""),
            string_anchor=signal["anchor"],
            source_expression=source["expression"],
            sink_callsite=_sink_callsite(sink, location),
            proof_oracle_kind="",
            likely_source=source,
            deterministic_replay_intent={
                "policy": "deterministic_memory_enrichment_only",
                "semantic_provider_calls": 0,
            },
        ).to_dict(),
        "canonical_target_key": [
            "",
            vuln_class,
            _normalize_address(location.get("address")) or _name_key(str(location.get("function_name") or "")),
            _name_key(str(sink.get("name") or "")),
            signal["signal_id"],
            "",
            "",
        ],
        "proof_obligations": [],
        "replay_hints": {},
        "rationale": "Deterministic fs/config/string feature enrichment for existing memory candidates only.",
        "validator_result": {
            "accepted": True,
            "reason_codes": ["deterministic_memory_semantic_enrichment"],
            "cluster_id": cluster_id,
        },
        "cost_metadata": _empty_costs(),
        "raw_seed": {
            "provenance": "deterministic_semantic_enrichment",
            "cluster": dict(cluster),
        },
        "deterministic_enrichment_only": True,
    }


def _location_from_cluster_anchor(anchors: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    for anchor in anchors:
        if str(anchor.get("kind") or "") == "function":
            return {
                "function_name": str(anchor.get("function_name") or ""),
                "address": _normalize_address(anchor.get("address")),
                "relative_path": str(anchor.get("relative_path") or ""),
                "line_number": 0,
                "line_text": "",
            }
    return {"function_name": "", "address": "", "relative_path": "", "line_number": 0, "line_text": ""}


def _preferred_memory_sink(calls: Sequence[str]) -> str:
    lowered = {str(call).lower(): str(call) for call in calls}
    for sink in ("snprintf", "sprintf", "strcat", "strcpy", "memcpy", "readdir", "readdir_r"):
        if sink in lowered:
            return sink
    for call in calls:
        if str(call).lower() in FS_MEMORY_SINKS:
            return str(call)
    return ""


def semantic_seed_candidates_from_artifacts(
    semantic_seed_dir: Path,
    *,
    base_states: Sequence[CandidateState] | None = None,
    binary_path: Path | str | None = None,
) -> list[CandidateState]:
    """Load accepted seed artifacts and create or enrich candidate states."""

    states = list(base_states or [])
    by_id = {state.candidate_id: state for state in states}
    accepted = _load_accepted_seed_artifacts(semantic_seed_dir)
    for seed in accepted:
        artifact_path = str(seed.get("artifact_path") or "")
        existing_ids = _matching_state_ids(states, seed)
        if existing_ids:
            for existing_id in existing_ids:
                state = by_id.get(existing_id)
                if state is None:
                    continue
                updated = _enrich_state_with_seed(state, seed, artifact_path)
                by_id[existing_id] = updated
                states = [updated if item.candidate_id == existing_id else item for item in states]
            continue
        if _is_memory_enrichment_seed(seed):
            continue
        state = _candidate_from_seed(seed, binary_path=binary_path, artifact_path=artifact_path)
        states.append(state)
        by_id[state.candidate_id] = state
    return states


def _function_feature(node: FunctionNode) -> dict[str, Any]:
    record = node.record
    string_refs = [_string_value(item) for item in record.string_refs or []]
    pcode_calls = [_call_name(item) for item in record.pcode_calls or []]
    ambiguous_calls = [_call_name(item) for item in record.ambiguous_callsites or []]
    call_sites = _call_site_features(record.pcode_calls or [], record.ambiguous_callsites or [])
    metadata = node.metadata or {}
    callees = _unique_strings(
        list(metadata.get("callees", []) or [])
        + list(metadata.get("callees_direct", []) or [])
        + list(metadata.get("callees_pcode", []) or [])
        + pcode_calls
        + ambiguous_calls
        + _source_call_names(node.text)
    )
    callers = _unique_strings(
        list(metadata.get("callers", []) or [])
        + list(metadata.get("callers_direct", []) or [])
        + list(metadata.get("callers_pcode", []) or [])
    )
    known_addresses = sorted(
        {
            _normalize_address(record.address),
            *[_normalize_address(item.get("address")) for item in record.pcode_calls or [] if isinstance(item, Mapping)],
            *[_normalize_address(item.get("operation_address")) for item in record.pcode_calls or [] if isinstance(item, Mapping)],
            *[_normalize_address(item.get("address")) for item in record.pcode_stores or [] if isinstance(item, Mapping)],
            *[_normalize_address(item.get("address")) for item in record.ambiguous_callsites or [] if isinstance(item, Mapping)],
        }
        - {""}
    )
    return {
        "function_name": record.name,
        "address": _normalize_address(record.address),
        "relative_path": record.relative_path,
        "prototype": record.prototype,
        "return_type": record.return_type,
        "source_symbol": record.source_symbol,
        "demangled_name": record.demangled_name,
        "parameters": list(record.parameters or []),
        "strings": _unique_strings(string_refs)[:80],
        "calls": callees[:120],
        "call_sites": call_sites[:120],
        "callers": callers[:80],
        "known_addresses": known_addresses,
        "source_markers": _source_markers(node.text, record.parameters or []),
        "line_count": record.line_count,
        "byte_length": record.byte_length,
    }


def _cluster_features(feature_index: Mapping[str, Any], vuln_class: str, *, max_clusters: int) -> list[dict[str, Any]]:
    functions = [item for item in feature_index.get("functions", []) or [] if isinstance(item, Mapping)]
    routes = [item for item in feature_index.get("routes", []) or [] if isinstance(item, Mapping)]
    configs = [item for item in feature_index.get("configs", []) or [] if isinstance(item, Mapping)]
    binary_strings = [str(item) for item in feature_index.get("binary_strings", []) or []]
    clusters: list[dict[str, Any]] = []
    if vuln_class in LLM_SEMANTIC_SEED_CLASSES:
        for function in functions:
            clusters.extend(_string_signal_clusters(vuln_class, function, routes))
        clusters.sort(key=lambda item: (-int(item.get("score", 0)), str(item.get("cluster_id", ""))))
        return clusters[: max(0, int(max_clusters))]
    for function in functions:
        cluster = _score_function_cluster(vuln_class, function, routes, configs, binary_strings)
        if cluster:
            clusters.append(cluster)
    clusters.sort(key=lambda item: (-int(item.get("score", 0)), str(item.get("cluster_id", ""))))
    return clusters[: max(0, int(max_clusters))]


def _string_signal_clusters(
    vuln_class: str,
    function: Mapping[str, Any],
    routes: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if not _function_has_class_sink(vuln_class, function):
        return []
    signals = _extract_string_signals(vuln_class, function, routes)
    if not signals:
        return []
    clusters: list[dict[str, Any]] = []
    for signal in signals:
        if not _function_has_class_source(vuln_class, function, signal):
            continue
        calls = list(function.get("calls", []) or [])
        source_markers = list(function.get("source_markers", []) or [])
        sink_name = _preferred_class_sink(vuln_class, calls)
        if not sink_name:
            continue
        source_expression = _source_expression_from_markers(vuln_class, source_markers, signal)
        signal_id = str(signal.get("signal_id") or "")
        cluster_id = _stable_id(
            "string_signal_cluster",
            vuln_class,
            function.get("function_name"),
            function.get("address"),
            signal_id,
            sink_name,
        )
        clusters.append(
            {
                "cluster_id": cluster_id,
                "vulnerability_type": vuln_class,
                "score": int(signal.get("score") or 0) + 8,
                "reasons": [
                    f"string_signal:{signal.get('anchor', '')}",
                    f"class_sink:{sink_name}",
                    f"controlled_source:{source_expression}",
                ],
                "anchors": [
                    {
                        "kind": "function",
                        "function_name": function.get("function_name", ""),
                        "address": function.get("address", ""),
                        "relative_path": function.get("relative_path", ""),
                    }
                ],
                "string_signal": dict(signal),
                "features": {
                    "function_name": function.get("function_name", ""),
                    "prototype": function.get("prototype", ""),
                    "calls": calls[:40],
                    "call_sites": list(function.get("call_sites", []) or [])[:40],
                    "callers": list(function.get("callers", []) or [])[:20],
                    "strings": list(function.get("strings", []) or [])[:40],
                    "source_markers": source_markers[:20],
                    "source_expression": source_expression,
                    "sink_name": sink_name,
                    "string_signal": dict(signal),
                },
            }
        )
    return clusters


def _score_function_cluster(
    vuln_class: str,
    function: Mapping[str, Any],
    routes: Sequence[Mapping[str, Any]],
    configs: Sequence[Mapping[str, Any]],
    binary_strings: Sequence[str],
) -> dict[str, Any] | None:
    hay = _haystack(function)
    calls = {str(item).lower() for item in function.get("calls", []) or []}
    strings = [str(item) for item in function.get("strings", []) or []]
    reasons: list[str] = []
    score = 0
    if vuln_class == "command_injection":
        score += _score_calls(calls, SHELL_SINKS, reasons, "shell_sink_call", weight=8)
        score += _score_tokens(hay, ("shell", "/bin/sh", "ping", "traceroute", "nslookup", "diagnostic", "cmd", "command"), reasons, "shell_fragment", weight=2)
        score += _score_routes(routes, ("diag", "ping", "traceroute", "debug", "command"), reasons, weight=1)
    elif vuln_class == "path_traversal":
        score += _score_calls(calls, FILE_READ_SINKS, reasons, "file_read_call", weight=4)
        score += _score_tokens(hay, ("../", "download", "path", "filename", "file", "config", "template"), reasons, "path_fragment", weight=2)
        score += _score_routes(routes, ("download", "file", "config", "export", "backup"), reasons, weight=1)
    elif vuln_class == "unsafe_file_write":
        score += _score_calls(calls, FILE_WRITE_SINKS, reasons, "file_write_call", weight=4)
        score += _score_tokens(hay, ("upload", "restore", "backup", "write", "extract", "tar", "zip", "import"), reasons, "write_fragment", weight=2)
        score += _score_routes(routes, ("upload", "restore", "backup", "import", "write"), reasons, weight=1)
    elif vuln_class == "fs_config_memory_corruption":
        score += _score_calls(calls, FS_MEMORY_SINKS, reasons, "fs_or_string_call", weight=3)
        score += _score_calls(calls, FS_CONFIG_SOURCE_CALLS, reasons, "config_storage_or_alloc_call", weight=2)
        if calls.intersection({"snprintf", "sprintf", "strcat", "strcpy", "memcpy"}) and calls.intersection(FS_CONFIG_SOURCE_CALLS):
            score += 6
            reasons.append("config_source_to_memory_sink")
        score += _score_tokens(hay, ("opendir", "readdir", "core.", ".cfg", ".conf", "nvram", "getenv", "filename"), reasons, "fs_config_fragment", weight=2)
        score += _score_configs(configs, reasons, weight=1)
    else:
        return None
    if score <= 0:
        return None
    matched_strings = _matched_texts(strings + list(binary_strings)[:200], hay, limit=20)
    cluster_id = _stable_id(
        "semantic_cluster",
        vuln_class,
        function.get("function_name"),
        function.get("address"),
        "|".join(reasons[:8]),
    )
    return {
        "cluster_id": cluster_id,
        "vulnerability_type": vuln_class,
        "score": score,
        "reasons": reasons[:16],
        "anchors": [
            {
                "kind": "function",
                "function_name": function.get("function_name", ""),
                "address": function.get("address", ""),
                "relative_path": function.get("relative_path", ""),
            }
        ],
        "features": {
            "function_name": function.get("function_name", ""),
            "prototype": function.get("prototype", ""),
            "calls": list(function.get("calls", []) or [])[:40],
            "callers": list(function.get("callers", []) or [])[:20],
            "strings": matched_strings,
            "routes": _matched_routes(routes, hay)[:12],
            "configs": _matched_configs(configs, hay)[:12],
        },
    }


def _extract_string_signals(
    vuln_class: str,
    function: Mapping[str, Any],
    routes: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    strings = [str(item) for item in function.get("strings", []) or [] if str(item)]
    for value in strings:
        signal = _class_string_signal(vuln_class, value, "function_string")
        if signal:
            signals.append(signal)
    hay = _haystack(function)
    for route in routes:
        route_path = str(route.get("route") or route.get("path") or "")
        if not route_path:
            continue
        route_tokens = _route_tokens(route_path)
        if route_tokens and not any(token in hay for token in route_tokens):
            continue
        signal = _class_string_signal(vuln_class, route_path, "route")
        if signal:
            payload = dict(signal)
            payload["route"] = dict(route)
            signals.append(payload)
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for signal in signals:
        anchor = str(signal.get("anchor") or "")
        if anchor in seen:
            continue
        seen.add(anchor)
        signal_id = _stable_id("string_signal", vuln_class, function.get("function_name"), function.get("address"), anchor)
        payload = dict(signal)
        payload["signal_id"] = signal_id
        payload.setdefault("vulnerability_type", vuln_class)
        payload.setdefault("function_name", str(function.get("function_name") or ""))
        payload.setdefault("function_address", str(function.get("address") or ""))
        result.append(payload)
    if not result:
        fallback = _source_sink_signal(vuln_class, function)
        if fallback:
            signal_id = _stable_id(
                "source_sink_signal",
                vuln_class,
                function.get("function_name"),
                function.get("address"),
                fallback.get("anchor"),
            )
            payload = dict(fallback)
            payload["signal_id"] = signal_id
            payload.setdefault("vulnerability_type", vuln_class)
            payload.setdefault("function_name", str(function.get("function_name") or ""))
            payload.setdefault("function_address", str(function.get("address") or ""))
            result.append(payload)
    return result


def _source_sink_signal(vuln_class: str, function: Mapping[str, Any]) -> dict[str, Any] | None:
    """Fallback for source/sink pairs that lack a useful literal string anchor."""

    calls = list(function.get("calls", []) or [])
    source_markers = list(function.get("source_markers", []) or [])
    sink_name = _preferred_class_sink(vuln_class, calls)
    if not sink_name:
        return None
    if vuln_class == "unsafe_file_write" and str(sink_name).lower() in {"fopen", "open"}:
        hay = _haystack(function)
        if not any(token in hay for token in ("upload", "restore", "backup", "write", "extract", "import", "firmware", "upgrade")):
            return None
    source_expression = _source_expression_from_markers(vuln_class, source_markers, {})
    if not _concrete_source_expression(source_expression):
        return None
    if not _source_expression_matches_class(vuln_class, source_expression, {"kind": "source_marker"}):
        return None
    if vuln_class == "command_injection":
        label = "command"
    elif vuln_class == "path_traversal":
        label = "path"
    elif vuln_class == "unsafe_file_write":
        label = "write"
    else:
        return None
    anchor = f"{label} source {source_expression} reaches {sink_name}"
    signal = _class_string_signal(vuln_class, anchor, "source_sink_signal")
    if not signal:
        return None
    signal["source_expression"] = source_expression
    signal["sink_name"] = sink_name
    signal["score"] = int(signal.get("score") or 0) + 2
    return signal


def _class_string_signal(vuln_class: str, value: str, kind: str) -> dict[str, Any] | None:
    text = str(value or "").strip()
    if not text:
        return None
    lowered = text.lower()
    if vuln_class == "command_injection":
        tokens = COMMAND_SIGNAL_TOKENS
    elif vuln_class == "path_traversal":
        tokens = PATH_TRAVERSAL_SIGNAL_TOKENS
    elif vuln_class == "unsafe_file_write":
        tokens = UNSAFE_WRITE_SIGNAL_TOKENS
    else:
        return None
    matched = [token for token in tokens if token in lowered]
    if not matched:
        return None
    return {
        "signal_id": "",
        "vulnerability_type": vuln_class,
        "kind": kind,
        "anchor": text,
        "matched_tokens": matched[:8],
        "score": 4 + len(matched),
    }


def _function_has_class_sink(vuln_class: str, function: Mapping[str, Any]) -> bool:
    calls = {str(item).lower() for item in function.get("calls", []) or []}
    if vuln_class == "command_injection":
        return bool(_matching_calls(calls, SHELL_SINKS))
    if vuln_class == "path_traversal":
        return bool(_matching_calls(calls, FILE_READ_SINKS))
    if vuln_class == "unsafe_file_write":
        return bool(_matching_calls(calls, FILE_WRITE_SINKS))
    return False


def _function_has_class_source(vuln_class: str, function: Mapping[str, Any], signal: Mapping[str, Any]) -> bool:
    markers = {str(item).lower() for item in function.get("source_markers", []) or []}
    if str(signal.get("kind") or "") == "route":
        return True
    if vuln_class == "command_injection":
        return bool(markers.intersection({"argv", "env", "request", "route", "param", "query", "form", "body", "cgi", "stdin"}))
    if vuln_class == "path_traversal":
        return bool(markers.intersection({"argv", "request", "route", "param", "query", "form", "body", "filename", "path", "file", "stdin"}))
    if vuln_class == "unsafe_file_write":
        return bool(markers.intersection({"argv", "request", "route", "param", "query", "form", "body", "filename", "path", "file", "upload", "content", "stdin"}))
    return False


def _preferred_class_sink(vuln_class: str, calls: Sequence[Any]) -> str:
    lowered = {str(call).lower(): str(call) for call in calls}
    if vuln_class == "command_injection":
        wanted = ("system", "popen", "execve", "execvp", "execv", "execlp", "execl", "execle")
    elif vuln_class == "path_traversal":
        wanted = ("fopen", "open", "stat", "lstat")
    elif vuln_class == "unsafe_file_write":
        wanted = ("fwrite", "write", "creat", "fopen", "open")
    else:
        wanted = ()
    for sink in wanted:
        for call_key, original in lowered.items():
            if sink == call_key or sink in call_key:
                return original
    return ""


def _matching_calls(calls: set[str], wanted: set[str]) -> list[str]:
    return sorted(call for call in calls if any(token == call or token in call for token in wanted))


def _source_expression_from_markers(
    vuln_class: str,
    markers: Sequence[Any],
    signal: Mapping[str, Any],
) -> str:
    if str(signal.get("kind") or "") == "route":
        return str(signal.get("anchor") or "")
    marker_set = {str(item).lower() for item in markers}
    for marker in ("argv", "query", "param", "request", "form", "body", "filename", "path", "file", "upload", "env", "stdin"):
        if marker in marker_set:
            if vuln_class == "command_injection" and marker in {"filename", "path", "file", "upload"}:
                continue
            return marker
    return str(signal.get("anchor") or "")


def _cluster_pack(feature_index: Mapping[str, Any], vuln_class: str, clusters: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "prompt_version": PROMPT_VERSION,
        "phase": "string_signal_index",
        "vuln_class": vuln_class,
        "instructions": {
            "allowed_output": "Deterministic string-signal contexts selected for targeted zoom. Do not claim proof or reportability.",
            "first_pass_body_policy": "No full decompiled function bodies are included in this pack.",
            "memory_policy": "fs_config_memory_corruption entries are deterministic enrichment only and are not sent to a semantic provider.",
        },
        "binary": feature_index.get("binary", ""),
        "binary_sha256": feature_index.get("binary_sha256", ""),
        "feature_counts": {
            "functions": feature_index.get("function_count", 0),
            "routes": len(feature_index.get("routes", []) or []),
            "services": len(feature_index.get("services", []) or []),
            "configs": len(feature_index.get("configs", []) or []),
            "binary_strings": len(feature_index.get("binary_strings", []) or []),
        },
        "clusters": [dict(item) for item in clusters],
        "response_contract": {
            "seeds": [
                {
                    "vulnerability_type": vuln_class,
                    "cluster_id": "existing cluster_id",
                    "string_signal_id": "existing string_signal.signal_id",
                    "string_anchor": "existing string_signal.anchor",
                    "anchors": [{"kind": "function", "function_name": "existing name", "address": "known address"}],
                    "source": {"kind": "attacker_input", "expression": "concrete source expression"},
                    "sink": {"name": "existing or anchored sink"},
                    "proof_oracle": {"kind": CLASS_PROOF_ORACLES.get(vuln_class, "class-specific oracle")},
                    "replay_hints": {"mode": "qemu_user|native|function_harness", "setup": {}, "input": {}, "expected_result": {"proof_oracle": {"kind": CLASS_PROOF_ORACLES.get(vuln_class, "class-specific oracle")}}},
                }
            ],
        },
    }


def _zoom_pack(
    feature_index: Mapping[str, Any],
    context: DiscoveryContext,
    vuln_class: str,
    cluster: Mapping[str, Any],
) -> dict[str, Any]:
    anchors = [item for item in cluster.get("anchors", []) or [] if isinstance(item, Mapping)]
    functions: list[dict[str, Any]] = []
    for anchor in anchors:
        node = _node_for_anchor(context.nodes, anchor)
        if node is None:
            continue
        feature = _function_feature(node)
        functions.append(
            {
                **feature,
                "calls": list(feature.get("calls", []) or [])[:60],
                "call_sites": list(feature.get("call_sites", []) or [])[:40],
                "callers": list(feature.get("callers", []) or [])[:20],
                "strings": list(feature.get("strings", []) or [])[:40],
                "known_addresses": list(feature.get("known_addresses", []) or [])[:80],
                "source_markers": list(feature.get("source_markers", []) or [])[:24],
                "source_excerpt": _source_excerpt(node.text, max_lines=45),
            }
        )
    context_hay = _haystack(cluster.get("features", {}) if isinstance(cluster.get("features"), Mapping) else cluster)
    return {
        "schema_version": 1,
        "prompt_version": PROMPT_VERSION,
        "phase": "targeted_zoom",
        "vuln_class": vuln_class,
        "binary": feature_index.get("binary", ""),
        "binary_sha256": feature_index.get("binary_sha256", ""),
        "cluster": dict(cluster),
        "functions": functions,
        "routes": _matched_routes(feature_index.get("routes", []) or [], context_hay)[:24],
        "configs": _matched_configs(feature_index.get("configs", []) or [], context_hay)[:24],
        "response_contract": {
            "seeds": [
                {
                    "vulnerability_type": vuln_class,
                    "cluster_id": cluster.get("cluster_id", ""),
                    "string_signal_id": _nested(cluster, "string_signal", "signal_id"),
                    "string_anchor": _nested(cluster, "string_signal", "anchor"),
                    "anchors": [{"kind": "function", "function_name": "existing name", "address": "known address"}],
                    "source": {"kind": "attacker_input", "expression": "concrete parameter or route"},
                    "sink": {"name": "sink", "kind": "sink kind"},
                    "proof_oracle": {"kind": CLASS_PROOF_ORACLES.get(vuln_class, "class-specific oracle")},
                    "proof_obligations": ["Replay must observe the class-specific oracle."],
                    "replay_hints": {"mode": "qemu_user|native|function_harness", "setup": {}, "input": {}, "expected_result": {"proof_oracle": {"kind": CLASS_PROOF_ORACLES.get(vuln_class, "class-specific oracle")}}},
                }
            ]
        },
    }


@dataclass(frozen=True)
class _KnownFeatureIndex:
    functions_by_name: Mapping[str, Mapping[str, Any]]
    functions_by_address: Mapping[str, Mapping[str, Any]]
    known_addresses: frozenset[str]
    strings: frozenset[str]
    routes: frozenset[str]
    configs: frozenset[str]

    @classmethod
    def from_feature_index(cls, feature_index: Mapping[str, Any]) -> "_KnownFeatureIndex":
        functions = [item for item in feature_index.get("functions", []) or [] if isinstance(item, Mapping)]
        by_name = {_name_key(str(item.get("function_name") or "")): item for item in functions if item.get("function_name")}
        by_address = {_normalize_address(item.get("address")): item for item in functions if _normalize_address(item.get("address"))}
        addresses = set(by_address)
        strings: set[str] = {str(item) for item in feature_index.get("binary_strings", []) or []}
        for function in functions:
            addresses.update(_normalize_address(item) for item in function.get("known_addresses", []) or [])
            strings.update(str(item) for item in function.get("strings", []) or [])
        addresses.discard("")
        routes = {
            str(item.get("route") or item.get("path") or "")
            for item in feature_index.get("routes", []) or []
            if isinstance(item, Mapping)
        }
        routes.discard("")
        configs: set[str] = set()
        for item in feature_index.get("configs", []) or []:
            if not isinstance(item, Mapping):
                continue
            for key in ("relative_path", "path", "name", "key"):
                value = str(item.get(key) or "")
                if value:
                    configs.add(value)
            for key in ("env_keys", "keys"):
                configs.update(str(value) for value in item.get(key, []) or [] if str(value))
        return cls(
            functions_by_name=by_name,
            functions_by_address=by_address,
            known_addresses=frozenset(addresses),
            strings=frozenset(strings),
            routes=frozenset(routes),
            configs=frozenset(configs),
        )


def _validate_seed_payload(
    seed: Mapping[str, Any],
    *,
    vuln_class: str,
    allowed_classes: Sequence[str],
    known: _KnownFeatureIndex,
    clusters: Mapping[str, Mapping[str, Any]],
    zoom_pack: Mapping[str, Any],
) -> dict[str, Any]:
    raw = dict(seed)
    errors: list[str] = []
    seed_vulnerability_type = str(raw.get("vulnerability_type") or raw.get("class") or vuln_class)
    if seed_vulnerability_type not in set(allowed_classes):
        errors.append(f"unsupported_vulnerability_type:{seed_vulnerability_type}")
    cluster_id = str(raw.get("cluster_id") or "")
    if not cluster_id and isinstance(zoom_pack.get("cluster"), Mapping):
        cluster_id = str(zoom_pack["cluster"].get("cluster_id") or "")
    cluster = clusters.get(cluster_id, {})
    if cluster_id and not cluster:
        errors.append("unknown_cluster_id")
    if _claims_proof(raw):
        errors.append("seed_claims_proof_or_reportability")
    for address in _seed_addresses(raw):
        if _normalize_address(address) not in known.known_addresses and not _address_in_zoom(address, zoom_pack):
            errors.append(f"unknown_address:{address}")
    anchors = _normalize_seed_anchors(raw, known, cluster, zoom_pack)
    string_signal = _normalize_seed_string_signal(raw, cluster, known)
    if string_signal:
        anchors = _dedupe_anchors([*anchors, *_anchors_for_string_signal(string_signal, known)])
    if not anchors:
        errors.append("missing_grounded_anchor")
    sink = _normalize_sink(raw)
    location = _location_from_anchors(anchors, known, cluster)
    source = _normalize_source(raw)
    seed_id = str(raw.get("seed_id") or "") or _stable_id(
        "semantic_seed",
        seed_vulnerability_type,
        cluster_id,
        location.get("function_name"),
        location.get("address"),
        sink.get("name"),
        json.dumps(source, sort_keys=True, default=str),
    )
    replay_hints = _normalize_replay_hints(raw)
    proof_oracle_kind = _proof_oracle_kind(raw, replay_hints)
    errors.extend(
        _semantic_class_gate_errors(
            vuln_class=seed_vulnerability_type,
            string_signal=string_signal,
            source=source,
            sink=sink,
            location=location,
            raw=raw,
            replay_hints=replay_hints,
            proof_oracle_kind=proof_oracle_kind,
            known=known,
            cluster=cluster,
            zoom_pack=zoom_pack,
        )
    )
    proof_obligations = _seed_obligations(raw, seed_id, seed_vulnerability_type)
    semantic_target = _semantic_target_from_seed(
        vulnerability_type=seed_vulnerability_type,
        anchors=anchors,
        location=location,
        source=source,
        sink=sink,
        string_signal=string_signal,
        proof_oracle_kind=proof_oracle_kind,
        proof_obligations=proof_obligations,
        replay_hints=replay_hints,
    )
    deterministic_replay_intent = _deterministic_replay_intent(
        vulnerability_type=seed_vulnerability_type,
        string_signal=string_signal,
        source=source,
        sink=sink,
        replay_hints=replay_hints,
        proof_oracle_kind=proof_oracle_kind,
    )
    artifact = {
        "schema_version": 1,
        "seed_id": seed_id,
        "accepted": not errors,
        "failure_reason": ";".join(errors),
        "vulnerability_type": seed_vulnerability_type,
        "cluster_id": cluster_id,
        "string_signal_id": str(string_signal.get("signal_id") or "") if string_signal else "",
        "string_anchor": str(string_signal.get("anchor") or "") if string_signal else "",
        "anchors": anchors,
        "location": location,
        "source": source,
        "source_expression": str(source.get("expression") or source.get("name") or source.get("path") or ""),
        "sink": sink,
        "sink_callsite": _sink_callsite(sink, location),
        "proof_oracle_kind": proof_oracle_kind,
        "deterministic_replay_intent": deterministic_replay_intent,
        "semantic_target": semantic_target.to_dict(),
        "canonical_target_key": list(semantic_target.canonical_key()),
        "proof_obligations": proof_obligations,
        "replay_hints": replay_hints,
        "rationale": str(raw.get("rationale") or raw.get("reason") or ""),
        "validator_result": {
            "accepted": not errors,
            "reason_codes": ["grounded_semantic_seed"] if not errors else errors,
            "cluster_id": cluster_id,
        },
        "cost_metadata": _payload_cost(raw),
        "raw_seed": raw,
    }
    return artifact


def _normalize_seed_anchors(
    raw: Mapping[str, Any],
    known: _KnownFeatureIndex,
    cluster: Mapping[str, Any],
    zoom_pack: Mapping[str, Any],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for anchor in _coerce_sequence(raw.get("anchors", [])):
        normalized = _normalize_anchor(anchor, known, zoom_pack)
        if normalized:
            result.append(normalized)
    direct_anchor = {
        "kind": "function",
        "function_name": raw.get("function_name") or raw.get("function"),
        "address": raw.get("function_address") or raw.get("address"),
        "relative_path": raw.get("relative_path"),
    }
    normalized = _normalize_anchor(direct_anchor, known, zoom_pack)
    if normalized:
        result.append(normalized)
    if not result and cluster:
        for anchor in cluster.get("anchors", []) or []:
            normalized = _normalize_anchor(anchor, known, zoom_pack)
            if normalized:
                result.append(normalized)
                break
    return _dedupe_anchors(result)


def _normalize_anchor(anchor: Any, known: _KnownFeatureIndex, zoom_pack: Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(anchor, Mapping):
        kind = str(anchor.get("kind") or "function")
        name = str(anchor.get("function_name") or anchor.get("name") or anchor.get("function") or "")
        address = _normalize_address(anchor.get("address") or anchor.get("function_address"))
        route = str(anchor.get("route") or anchor.get("path") or "")
        string = str(anchor.get("string") or anchor.get("value") or "")
        config_key = str(anchor.get("config_key") or anchor.get("config") or anchor.get("env_key") or "")
    else:
        text = str(anchor or "").strip()
        kind = "address" if _normalize_address(text) else "text"
        name = text
        address = _normalize_address(text)
        route = text if text.startswith("/") else ""
        string = text
        config_key = text
    if name and _name_key(name) in known.functions_by_name:
        function = known.functions_by_name[_name_key(name)]
        return {
            "kind": "function",
            "function_name": function.get("function_name", ""),
            "address": function.get("address", ""),
            "relative_path": function.get("relative_path", ""),
        }
    if address and address in known.functions_by_address:
        function = known.functions_by_address[address]
        return {
            "kind": "function",
            "function_name": function.get("function_name", ""),
            "address": function.get("address", ""),
            "relative_path": function.get("relative_path", ""),
        }
    if address and _address_in_zoom(address, zoom_pack):
        return {"kind": kind, "address": address}
    if route and route in known.routes:
        return {"kind": "route", "path": route}
    if string and string in known.strings:
        return {"kind": "string", "value": string}
    if config_key and config_key in known.configs:
        return {"kind": "config", "key": config_key}
    return {}


def _candidate_from_seed(seed: Mapping[str, Any], *, binary_path: Path | str | None, artifact_path: str) -> CandidateState:
    seed_id = str(seed.get("seed_id") or "")
    vulnerability_type = str(seed.get("vulnerability_type") or "")
    location = dict(seed.get("location") or {}) if isinstance(seed.get("location"), Mapping) else {}
    sink = dict(seed.get("sink") or {}) if isinstance(seed.get("sink"), Mapping) else {}
    target_binary = str(binary_path or "")
    candidate_id = str(seed.get("candidate_id") or "") or f"semantic:{seed_id}"
    metadata = {
        "provenance": "llm_semantic_seed",
        "semantic_seed_id": seed_id,
        "semantic_seed_cluster_id": str(seed.get("cluster_id") or ""),
        "semantic_string_signal_id": str(seed.get("string_signal_id") or ""),
        "semantic_string_anchor": str(seed.get("string_anchor") or ""),
        "semantic_proof_oracle_kind": str(seed.get("proof_oracle_kind") or ""),
        "semantic_seed_artifact": artifact_path,
        "semantic_target_key": list(seed.get("canonical_target_key") or []),
        "semantic_seed_support": [seed_id] if seed_id else [],
    }
    replay_hints = dict(seed.get("replay_hints") or {}) if isinstance(seed.get("replay_hints"), Mapping) else {}
    type_facts = {
        "semantic_seed": _public_seed(seed),
        "semantic_target": dict(seed.get("semantic_target") or {}) if isinstance(seed.get("semantic_target"), Mapping) else {},
        "deterministic_replay_intent": dict(seed.get("deterministic_replay_intent") or {})
        if isinstance(seed.get("deterministic_replay_intent"), Mapping)
        else {},
        "replay_hints": replay_hints,
        "path_is_valid": True,
        "input_reaches_sink": True,
    }
    return CandidateState(
        candidate_id=candidate_id,
        vulnerability_type=vulnerability_type,
        status=CandidateStatus.CANDIDATE.value,
        target={
            "binary": Path(target_binary).name if target_binary else "",
            "component": Path(target_binary).name if target_binary else "",
            "path": target_binary,
        },
        location=location,
        source=dict(seed.get("source") or {}) if isinstance(seed.get("source"), Mapping) else {"kind": "semantic_seed"},
        sink=sink,
        type_facts=type_facts,
        proof_obligations=[dict(item) for item in seed.get("proof_obligations", []) or [] if isinstance(item, Mapping)],
        blockers=[],
        validation_artifacts=[artifact_path] if artifact_path else [],
        metadata=metadata,
    )


def _enrich_state_with_seed(state: CandidateState, seed: Mapping[str, Any], artifact_path: str) -> CandidateState:
    metadata = dict(state.metadata)
    memory_enrichment = _is_memory_enrichment_seed(seed)
    updates = {
        "semantic_seed_id": str(seed.get("seed_id") or ""),
        "semantic_seed_cluster_id": str(seed.get("cluster_id") or ""),
        "semantic_string_signal_id": str(seed.get("string_signal_id") or ""),
        "semantic_string_anchor": str(seed.get("string_anchor") or ""),
        "semantic_proof_oracle_kind": str(seed.get("proof_oracle_kind") or ""),
        "semantic_seed_artifact": artifact_path,
        "semantic_target_key": list(seed.get("canonical_target_key") or []),
    }
    if memory_enrichment:
        updates["semantic_enrichment_only"] = True
        updates.setdefault("provenance", str(metadata.get("provenance") or metadata.get("source_model") or "deterministic"))
    else:
        updates["provenance"] = "llm_semantic_seed"
    metadata.update(updates)
    support = [str(item) for item in metadata.get("semantic_seed_support", []) or [] if str(item)]
    seed_id = str(seed.get("seed_id") or "")
    if seed_id and seed_id not in support:
        support.append(seed_id)
    metadata["semantic_seed_support"] = support
    facts = dict(state.type_facts)
    facts["semantic_seed"] = _public_seed(seed)
    if isinstance(seed.get("semantic_target"), Mapping):
        facts["semantic_target"] = dict(seed["semantic_target"])
    if isinstance(seed.get("deterministic_replay_intent"), Mapping):
        facts["deterministic_replay_intent"] = dict(seed["deterministic_replay_intent"])
    if not memory_enrichment and isinstance(seed.get("replay_hints"), Mapping):
        facts["replay_hints"] = dict(seed["replay_hints"])
    if memory_enrichment:
        facts["semantic_memory_enrichment"] = {
            "seed_id": str(seed.get("seed_id") or ""),
            "string_signal_id": str(seed.get("string_signal_id") or ""),
            "string_anchor": str(seed.get("string_anchor") or ""),
            "source_expression": str(seed.get("source_expression") or ""),
        }
    return state.with_updates(
        type_facts=facts,
        validation_artifacts=_dedupe([*state.validation_artifacts, artifact_path] if artifact_path else state.validation_artifacts),
        metadata=metadata,
    )


def _matching_state_ids(states: Sequence[CandidateState], seed: Mapping[str, Any]) -> list[str]:
    location = dict(seed.get("location") or {}) if isinstance(seed.get("location"), Mapping) else {}
    sink = dict(seed.get("sink") or {}) if isinstance(seed.get("sink"), Mapping) else {}
    seed_vulnerability_type = str(seed.get("vulnerability_type") or "")
    function_name = str(location.get("function_name") or "")
    address = _normalize_address(location.get("address"))
    sink_name = str(sink.get("name") or "")
    matches: list[str] = []
    for state in states:
        if seed_vulnerability_type and not _seed_type_matches_state(seed_vulnerability_type, state.vulnerability_type):
            continue
        same_function = function_name and function_name == str(state.location.get("function_name") or "")
        same_address = address and address == _normalize_address(state.location.get("address"))
        same_sink = _seed_sink_matches_state(seed_vulnerability_type, sink_name, state)
        if (same_function or same_address) and same_sink:
            matches.append(state.candidate_id)
    return matches


def _seed_type_matches_state(seed_vulnerability_type: str, state_vulnerability_type: str) -> bool:
    if seed_vulnerability_type == state_vulnerability_type:
        return True
    if seed_vulnerability_type == "fs_config_memory_corruption":
        return state_vulnerability_type in {"stack_overflow", "heap_overflow", "out_of_bounds_write"}
    return False


def _is_memory_enrichment_seed(seed: Mapping[str, Any]) -> bool:
    return (
        str(seed.get("vulnerability_type") or "") in MEMORY_SEMANTIC_ENRICHMENT_CLASSES
        or bool(seed.get("deterministic_enrichment_only"))
        or str(_nested(seed, "deterministic_replay_intent", "policy")) == "deterministic_memory_enrichment_only"
    )


def _seed_sink_matches_state(seed_vulnerability_type: str, seed_sink_name: str, state: CandidateState) -> bool:
    if not seed_sink_name:
        return True
    state_sink = str(state.sink.get("name") or "")
    if seed_sink_name == state_sink:
        return True
    if seed_vulnerability_type == "fs_config_memory_corruption":
        return state_sink.lower() in FS_MEMORY_SINKS
    return False


def _load_accepted_seed_artifacts(semantic_seed_dir: Path) -> list[dict[str, Any]]:
    root = Path(semantic_seed_dir)
    index_path = root / "accepted_index.json"
    paths: list[Path] = []
    if index_path.exists():
        payload = json.loads(index_path.read_text() or "{}")
        for row in payload.get("accepted", []) if isinstance(payload, Mapping) else []:
            if isinstance(row, Mapping) and row.get("path"):
                paths.append(Path(str(row["path"])))
    if not paths:
        paths = sorted((root / "accepted").glob("*.json"))
    seeds: list[dict[str, Any]] = []
    for path in paths:
        if not path.exists():
            continue
        payload = json.loads(path.read_text() or "{}")
        if isinstance(payload, Mapping) and payload.get("accepted"):
            seed = dict(payload)
            seed["artifact_path"] = str(path)
            seeds.append(seed)
    return seeds


def _provider_json(
    provider: SemanticSeedProvider,
    pack: Mapping[str, Any],
    *,
    phase: str,
    vuln_class: str,
    output_dir: Path,
    cache_dir: Path | None,
    binary_hash: str,
    provider_cache_key: str,
) -> tuple[Mapping[str, Any] | Sequence[Any], Path, bool]:
    digest = _stable_id("pack", json.dumps(pack, sort_keys=True, default=str))
    cache_path = None
    if cache_dir is not None:
        cache_path = cache_dir / _safe_stem(binary_hash or "unknown") / _safe_stem(provider_cache_key) / PROMPT_VERSION / vuln_class / f"{phase}_{digest}.json"
        if cache_path.exists():
            payload = json.loads(cache_path.read_text() or "{}")
            raw_path = _write_raw_payload(output_dir, phase, vuln_class, digest, payload, cached=True)
            return payload, raw_path, True
    payload = provider.generate(pack, phase=phase, vuln_class=vuln_class)
    if cache_path is not None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    raw_path = _write_raw_payload(output_dir, phase, vuln_class, digest, payload, cached=False)
    return payload, raw_path, False


def _provider_cache_key(provider: SemanticSeedProvider) -> str:
    if isinstance(provider, ExternalCommandSemanticSeedProvider):
        env_fingerprint = {
            key: os.environ.get(key, "")
            for key in (
                "BINARY_AGENT_SEMANTIC_SEED_MODEL",
                "OPENROUTER_MODEL",
                "OPENROUTER_CHAT_COMPLETIONS_URL",
                "OPENAI_BASE_URL",
                "OPENAI_COMPAT_BASE_URL",
                "BINARY_AGENT_SEMANTIC_SEED_BASE_URL",
                "BINARY_AGENT_SEMANTIC_SEED_MAX_TOKENS",
            )
        }
        return _stable_id(type(provider).__name__, json.dumps(list(provider.command)), json.dumps(env_fingerprint, sort_keys=True))
    return type(provider).__name__


def _write_raw_payload(
    output_dir: Path,
    phase: str,
    vuln_class: str,
    digest: str,
    payload: Mapping[str, Any] | Sequence[Any],
    *,
    cached: bool,
) -> Path:
    raw_dir = output_dir / "raw" / phase / vuln_class
    raw_dir.mkdir(parents=True, exist_ok=True)
    path = raw_dir / f"{digest}.json"
    wrapper = {
        "schema_version": 1,
        "cached": cached,
        "payload": payload,
    }
    path.write_text(json.dumps(wrapper, indent=2, sort_keys=True))
    return path


def _write_stage_result(
    output_dir: Path,
    feature_index_summary_path: Path,
    summary: Mapping[str, Any],
    accepted_rows: Sequence[Mapping[str, Any]],
    rejected_rows: Sequence[Mapping[str, Any]],
    accepted_paths: Sequence[Path],
    rejected_paths: Sequence[Path],
    cluster_pack_paths: Sequence[Path],
    zoom_pack_paths: Sequence[Path],
    raw_paths: Sequence[Path],
) -> SemanticSeedStageResult:
    summary_path = output_dir / "summary.json"
    accepted_index_path = output_dir / "accepted_index.json"
    rejected_index_path = output_dir / "rejected_index.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True))
    accepted_index_path.write_text(json.dumps({"schema_version": 1, "accepted": list(accepted_rows)}, indent=2, sort_keys=True))
    rejected_index_path.write_text(json.dumps({"schema_version": 1, "rejected": list(rejected_rows)}, indent=2, sort_keys=True))
    return SemanticSeedStageResult(
        output_dir=output_dir,
        summary_path=summary_path,
        feature_index_summary_path=feature_index_summary_path,
        accepted_index_path=accepted_index_path,
        rejected_index_path=rejected_index_path,
        accepted_seed_paths=tuple(accepted_paths),
        rejected_seed_paths=tuple(rejected_paths),
        cluster_pack_paths=tuple(cluster_pack_paths),
        zoom_pack_paths=tuple(zoom_pack_paths),
        raw_paths=tuple(raw_paths),
        summary=summary,
    )


def _apply_semantic_seed_acceptance_policy(
    artifact: Mapping[str, Any],
    *,
    binary: str,
    accepted_target_keys: set[tuple[str, ...]],
    accepted_function_class_counts: dict[tuple[str, str], int],
    max_seeds_per_function_class: int,
) -> dict[str, Any]:
    result = dict(artifact)
    if not result.get("accepted"):
        return result
    target = result.get("semantic_target")
    if not isinstance(target, Mapping):
        return _reject_seed_artifact(result, "missing_semantic_target")
    semantic_target = SemanticTarget(
        vulnerability_type=str(target.get("vulnerability_type") or result.get("vulnerability_type") or ""),
        string_signal_id=str(target.get("string_signal_id") or result.get("string_signal_id") or ""),
        function_name=str(target.get("function_name") or ""),
        function_address=_normalize_address(target.get("function_address")),
        sink_name=str(target.get("sink_name") or ""),
        sink_address=_normalize_address(target.get("sink_address")),
        string_anchor=str(target.get("string_anchor") or ""),
        config_key=str(target.get("config_key") or ""),
        source_expression=str(target.get("source_expression") or result.get("source_expression") or ""),
        sink_callsite=str(target.get("sink_callsite") or result.get("sink_callsite") or ""),
        proof_oracle_kind=str(target.get("proof_oracle_kind") or result.get("proof_oracle_kind") or ""),
        likely_source=dict(target.get("likely_source") or {}) if isinstance(target.get("likely_source"), Mapping) else {},
        replay_hint=dict(target.get("replay_hint") or {}) if isinstance(target.get("replay_hint"), Mapping) else {},
        proof_obligation=dict(target.get("proof_obligation") or {}) if isinstance(target.get("proof_obligation"), Mapping) else {},
        deterministic_replay_intent=dict(target.get("deterministic_replay_intent") or result.get("deterministic_replay_intent") or {})
        if isinstance(target.get("deterministic_replay_intent") or result.get("deterministic_replay_intent"), Mapping)
        else {},
    )
    canonical_key = semantic_target.canonical_key(binary=binary)
    if canonical_key in accepted_target_keys:
        return _reject_seed_artifact(result, "duplicate_semantic_target")
    anchor_key = semantic_target.function_address or _name_key(semantic_target.function_name)
    if not anchor_key and semantic_target.string_anchor:
        anchor_key = f"string:{semantic_target.string_anchor}"
    if not anchor_key and semantic_target.config_key:
        anchor_key = f"config:{semantic_target.config_key}"
    function_key = (semantic_target.vulnerability_type, anchor_key)
    current = accepted_function_class_counts.get(function_key, 0)
    if current >= max(0, int(max_seeds_per_function_class)):
        return _reject_seed_artifact(result, "per_function_class_seed_cap")
    accepted_target_keys.add(canonical_key)
    accepted_function_class_counts[function_key] = current + 1
    result["canonical_target_key"] = list(canonical_key)
    return result


def _reject_seed_artifact(artifact: Mapping[str, Any], reason: str) -> dict[str, Any]:
    result = dict(artifact)
    existing = str(result.get("failure_reason") or "")
    result["accepted"] = False
    result["failure_reason"] = ";".join(item for item in (existing, reason) if item)
    validator = dict(result.get("validator_result") or {}) if isinstance(result.get("validator_result"), Mapping) else {}
    validator["accepted"] = False
    reason_codes = [str(item) for item in validator.get("reason_codes", []) or [] if str(item)]
    if reason not in reason_codes:
        reason_codes.append(reason)
    validator["reason_codes"] = reason_codes
    result["validator_result"] = validator
    return result


def _write_seed_artifact(artifact: Mapping[str, Any], directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{_safe_stem(str(artifact.get('seed_id') or 'seed'))}.json"
    path.write_text(json.dumps(dict(artifact), indent=2, sort_keys=True))
    return path


def _accepted_row(artifact: Mapping[str, Any], path: Path) -> dict[str, Any]:
    return {
        "seed_id": artifact.get("seed_id", ""),
        "candidate_id": f"semantic:{artifact.get('seed_id', '')}",
        "vulnerability_type": artifact.get("vulnerability_type", ""),
        "cluster_id": artifact.get("cluster_id", ""),
        "canonical_target_key": list(artifact.get("canonical_target_key") or []),
        "path": str(path),
        "accepted": True,
    }


def _rejected_index_row(artifact: Mapping[str, Any], path: Path) -> dict[str, Any]:
    return _rejected_row(
        str(artifact.get("cluster_id") or ""),
        str(artifact.get("vulnerability_type") or ""),
        str(artifact.get("failure_reason") or "rejected"),
        str(artifact.get("failure_reason") or ""),
        str(path),
        seed_id=str(artifact.get("seed_id") or ""),
    )


def _rejected_row(cluster_id: str, vuln_class: str, reason: str, detail: str, path: str, *, seed_id: str = "") -> dict[str, Any]:
    return {
        "seed_id": seed_id,
        "vulnerability_type": vuln_class,
        "cluster_id": cluster_id,
        "path": path,
        "accepted": False,
        "failure_reason": reason,
        "detail": detail,
    }


def _summary_payload(
    *,
    enabled: bool,
    provider_name: str,
    provider_command: str | Sequence[str] | None,
    classes: Sequence[str],
    cluster_counts: Mapping[str, int],
    accepted_cluster_counts: Mapping[str, int],
    accepted_count: int,
    rejected_count: int,
    provider_calls: int,
    cache_hits: int,
    cost_totals: Mapping[str, Any],
    errors: Mapping[str, str],
    reason: str = "",
    string_signal_counts: Mapping[str, int] | None = None,
    context_pack_counts: Mapping[str, int] | None = None,
    memory_feature_count: int = 0,
    rejected_by_reason: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    model_calls = int(cost_totals.get("model_calls") or 0)
    models = [str(item) for item in cost_totals.get("models", []) or [] if str(item)]
    endpoint_profiles = [str(item) for item in cost_totals.get("endpoint_profiles", []) or [] if str(item)]
    return {
        "schema_version": 1,
        "enabled": enabled,
        "reason": reason,
        "provider": provider_name,
        "provider_command": " ".join(provider_command) if isinstance(provider_command, Sequence) and not isinstance(provider_command, str) else str(provider_command or ""),
        "prompt_version": PROMPT_VERSION,
        "classes": list(classes),
        "cluster_counts": dict(cluster_counts),
        "accepted_cluster_counts": dict(accepted_cluster_counts),
        "accepted_count": accepted_count,
        "accepted_target_count": accepted_count - int(memory_feature_count),
        "rejected_count": rejected_count,
        "rejected_by_reason": dict(rejected_by_reason or {}),
        "provider_calls": provider_calls,
        "cache_hits": cache_hits,
        "model": models[0] if len(models) == 1 else "",
        "models": models,
        "endpoint_profile": endpoint_profiles[0] if len(endpoint_profiles) == 1 else "",
        "endpoint_profiles": endpoint_profiles,
        "model_calls": model_calls,
        "input_tokens": int(cost_totals.get("input_tokens") or 0),
        "output_tokens": int(cost_totals.get("output_tokens") or 0),
        "total_tokens": int(cost_totals.get("total_tokens") or 0),
        "wall_time_seconds": float(cost_totals.get("wall_time_seconds") or 0.0),
        "json_repair_count": int(cost_totals.get("json_repair_count") or 0),
        "live_provider_enabled": bool(enabled and model_calls > 0 and not _provider_name_is_smoke(provider_name)),
        "errors": dict(errors),
        "funnel_metrics": {
            "string_signals": dict(string_signal_counts or {}),
            "context_packs": dict(context_pack_counts or {}),
            "provider_calls": provider_calls,
            "accepted_targets": accepted_count - int(memory_feature_count),
            "rejected_targets": rejected_count,
            "rejected_by_reason": dict(rejected_by_reason or {}),
            "memory_semantic_feature_count": int(memory_feature_count),
            "replay_attempts": 0,
            "confirmed_targets": 0,
        },
    }


def _select_provider(
    provider: SemanticSeedProvider | None,
    *,
    provider_command: str | Sequence[str] | None,
    timeout_seconds: float | None,
) -> SemanticSeedProvider | None:
    if provider is not None:
        return provider
    if provider_command:
        if isinstance(provider_command, str):
            return ExternalCommandSemanticSeedProvider.from_command_string(provider_command, timeout_seconds=timeout_seconds)
        return ExternalCommandSemanticSeedProvider(list(provider_command), timeout_seconds=timeout_seconds)
    return None


def _accepted_cluster_ids(payload: Mapping[str, Any] | Sequence[Any], known_ids: set[str]) -> list[str]:
    result: list[str] = []
    source = payload if isinstance(payload, Mapping) else {"accepted_clusters": payload}
    for item in _coerce_sequence(source.get("accepted_clusters", []) if isinstance(source, Mapping) else []):
        cluster_id = ""
        if isinstance(item, Mapping):
            cluster_id = str(item.get("cluster_id") or item.get("id") or "")
        else:
            cluster_id = str(item or "")
        if cluster_id in known_ids and cluster_id not in result:
            result.append(cluster_id)
    for seed in _seed_payloads(payload):
        cluster_id = str(seed.get("cluster_id") or "")
        if cluster_id in known_ids and cluster_id not in result:
            result.append(cluster_id)
    return result


def _seed_payloads(payload: Mapping[str, Any] | Sequence[Any]) -> list[Mapping[str, Any]]:
    if isinstance(payload, Mapping):
        for key in ("seeds", "semantic_seeds", "candidates"):
            if key in payload:
                return [dict(item) for item in _coerce_sequence(payload.get(key)) if isinstance(item, Mapping)]
        if "vulnerability_type" in payload or "anchors" in payload:
            return [dict(payload)]
        return []
    return [dict(item) for item in _coerce_sequence(payload) if isinstance(item, Mapping)]


def _normalize_replay_hints(raw: Mapping[str, Any]) -> dict[str, Any]:
    hints = raw.get("replay_hints")
    if isinstance(hints, Mapping):
        result = dict(hints)
    else:
        result = {}
    for key in ("mode", "setup", "input", "expected_result", "proof_oracle"):
        if key in raw and key not in result:
            result[key] = raw[key]
    proof_oracle = result.get("proof_oracle")
    if isinstance(proof_oracle, Mapping):
        expected = dict(result.get("expected_result") or {}) if isinstance(result.get("expected_result"), Mapping) else {}
        expected.setdefault("proof_oracle", dict(proof_oracle))
        result["expected_result"] = expected
    return result


def _seed_obligations(raw: Mapping[str, Any], seed_id: str, vulnerability_type: str) -> list[dict[str, Any]]:
    obligations = []
    for index, item in enumerate(_coerce_sequence(raw.get("proof_obligations", [])), start=1):
        if isinstance(item, Mapping):
            obligation = dict(item)
            obligation.setdefault("obligation_id", f"{seed_id}:semantic_seed:{index}")
            obligation.setdefault("status", "satisfied")
            obligations.append(obligation)
        elif str(item).strip():
            obligations.append(
                ProofObligation(
                    obligation_id=f"{seed_id}:semantic_seed:{index}",
                    description=str(item),
                    condition=str(item),
                    required_evidence=["grounded_anchor", "class_specific_replay_oracle"],
                    status="satisfied",
                ).to_dict()
            )
    if obligations:
        return obligations
    return [
        ProofObligation(
            obligation_id=f"{seed_id}:{vulnerability_type}:semantic_seed_grounding",
            description="Accepted semantic seed anchors are grounded in deterministic feature evidence.",
            condition="All function, route, string, and address anchors validate against the feature index.",
            required_evidence=["grounded_anchor", "concrete_replay_hint"],
            status="satisfied",
        ).to_dict()
    ]


def _semantic_target_from_seed(
    *,
    vulnerability_type: str,
    anchors: Sequence[Mapping[str, Any]],
    location: Mapping[str, Any],
    source: Mapping[str, Any],
    sink: Mapping[str, Any],
    string_signal: Mapping[str, Any],
    proof_oracle_kind: str,
    proof_obligations: Sequence[Mapping[str, Any]],
    replay_hints: Mapping[str, Any],
) -> SemanticTarget:
    string_signal_id = str(string_signal.get("signal_id") or "")
    string_anchor = str(string_signal.get("anchor") or "")
    config_key = ""
    for anchor in anchors:
        if not isinstance(anchor, Mapping):
            continue
        if not string_anchor and anchor.get("kind") == "string":
            string_anchor = str(anchor.get("value") or "")
        if not config_key and anchor.get("kind") == "config":
            config_key = str(anchor.get("key") or anchor.get("path") or "")
    proof = dict(proof_obligations[0]) if proof_obligations else {}
    replay_intent = _deterministic_replay_intent(
        vulnerability_type=vulnerability_type,
        string_signal=string_signal,
        source=source,
        sink=sink,
        replay_hints=replay_hints,
        proof_oracle_kind=proof_oracle_kind,
    )
    return SemanticTarget(
        vulnerability_type=vulnerability_type,
        string_signal_id=string_signal_id,
        function_name=str(location.get("function_name") or ""),
        function_address=_normalize_address(location.get("address")),
        sink_name=str(sink.get("name") or ""),
        sink_address=_normalize_address(sink.get("operation_address") or sink.get("address")),
        string_anchor=string_anchor,
        config_key=config_key,
        source_expression=str(source.get("expression") or source.get("name") or source.get("path") or ""),
        sink_callsite=_sink_callsite(sink, location),
        proof_oracle_kind=proof_oracle_kind,
        likely_source=dict(source),
        replay_hint=dict(replay_hints),
        proof_obligation=proof,
        deterministic_replay_intent=replay_intent,
    )


def _normalize_sink(raw: Mapping[str, Any]) -> dict[str, Any]:
    sink = raw.get("sink")
    if isinstance(sink, Mapping):
        result = dict(sink)
    else:
        result = {"name": str(sink or raw.get("sink_name") or "")}
    result.setdefault("name", str(raw.get("sink_name") or result.get("name") or "semantic_sink"))
    result.setdefault("kind", str(raw.get("sink_kind") or result.get("kind") or "semantic_sink"))
    if raw.get("sink_address") and "operation_address" not in result:
        result["operation_address"] = _normalize_address(raw.get("sink_address"))
    return result


def _normalize_source(raw: Mapping[str, Any]) -> dict[str, Any]:
    source = raw.get("source")
    if isinstance(source, Mapping):
        result = dict(source)
    else:
        result = {"kind": str(raw.get("source_kind") or "attacker_input")}
        if source:
            result["expression"] = str(source)
    expression = str(
        raw.get("source_expression")
        or raw.get("controlled_source")
        or result.get("expression")
        or result.get("name")
        or result.get("path")
        or result.get("route")
        or ""
    )
    if expression:
        result["expression"] = expression
    result.setdefault("kind", str(raw.get("source_kind") or result.get("kind") or "attacker_input"))
    return result


def _normalize_seed_string_signal(
    raw: Mapping[str, Any],
    cluster: Mapping[str, Any],
    known: _KnownFeatureIndex,
) -> dict[str, Any]:
    cluster_signal = _cluster_string_signal(cluster)
    raw_signal = raw.get("string_signal")
    signal = dict(raw_signal) if isinstance(raw_signal, Mapping) else {}
    raw_signal_id = str(raw.get("string_signal_id") or raw.get("signal_id") or signal.get("signal_id") or "")
    raw_anchor = str(raw.get("string_anchor") or raw.get("anchor") or signal.get("anchor") or "")
    for key in ("string_signal_id", "signal_id"):
        if raw.get(key) and not signal.get("signal_id"):
            signal["signal_id"] = str(raw[key])
    for key in ("string_anchor", "anchor"):
        if raw.get(key) and not signal.get("anchor"):
            signal["anchor"] = str(raw[key])
    if not signal and cluster_signal:
        signal = dict(cluster_signal)
    elif signal and cluster_signal:
        if raw_signal_id and raw_signal_id != str(cluster_signal.get("signal_id") or ""):
            signal["_mismatch"] = "string_signal_id"
        if raw_anchor and raw_anchor != str(cluster_signal.get("anchor") or ""):
            signal["_mismatch"] = "string_anchor"
        signal.setdefault("signal_id", cluster_signal.get("signal_id"))
        signal.setdefault("anchor", cluster_signal.get("anchor"))
        signal.setdefault("kind", cluster_signal.get("kind"))
        signal.setdefault("matched_tokens", cluster_signal.get("matched_tokens", []))
    anchor = str(signal.get("anchor") or "")
    if anchor and anchor not in known.strings and anchor not in known.routes:
        if cluster_signal and anchor == str(cluster_signal.get("anchor") or ""):
            return signal
        return {}
    return signal


def _cluster_string_signal(cluster: Mapping[str, Any]) -> dict[str, Any]:
    signal = cluster.get("string_signal")
    if isinstance(signal, Mapping):
        return dict(signal)
    features = cluster.get("features") if isinstance(cluster.get("features"), Mapping) else {}
    signal = features.get("string_signal") if isinstance(features, Mapping) else {}
    return dict(signal) if isinstance(signal, Mapping) else {}


def _anchors_for_string_signal(signal: Mapping[str, Any], known: _KnownFeatureIndex) -> list[dict[str, Any]]:
    anchor = str(signal.get("anchor") or "")
    if not anchor:
        return []
    if anchor in known.strings:
        return [{"kind": "string", "value": anchor}]
    if anchor in known.routes:
        return [{"kind": "route", "path": anchor}]
    return []


def _proof_oracle_kind(raw: Mapping[str, Any], replay_hints: Mapping[str, Any]) -> str:
    for source in (
        raw.get("proof_oracle"),
        replay_hints.get("proof_oracle"),
        _nested_mapping(replay_hints, "expected_result", "proof_oracle"),
        _nested_mapping(replay_hints, "expected_sink", "proof_oracle"),
    ):
        if isinstance(source, Mapping):
            kind = str(source.get("kind") or source.get("type") or "")
            if kind:
                return kind
    kind = str(raw.get("proof_oracle_kind") or replay_hints.get("proof_oracle_kind") or "")
    return kind


def _semantic_class_gate_errors(
    *,
    vuln_class: str,
    string_signal: Mapping[str, Any],
    source: Mapping[str, Any],
    sink: Mapping[str, Any],
    location: Mapping[str, Any],
    raw: Mapping[str, Any],
    replay_hints: Mapping[str, Any],
    proof_oracle_kind: str,
    known: _KnownFeatureIndex,
    cluster: Mapping[str, Any],
    zoom_pack: Mapping[str, Any],
) -> list[str]:
    if vuln_class in MEMORY_SEMANTIC_ENRICHMENT_CLASSES:
        return ["memory_semantic_targets_are_deterministic_enrichment_only"]
    if vuln_class not in LLM_SEMANTIC_SEED_CLASSES:
        return []
    errors: list[str] = []
    if not string_signal:
        errors.append("missing_string_signal")
    elif string_signal.get("_mismatch"):
        errors.append(str(string_signal["_mismatch"]) + "_mismatch")
    elif not _string_signal_matches_class(vuln_class, string_signal):
        errors.append("string_signal_wrong_class")
    if not location.get("function_name") and not location.get("address"):
        errors.append("missing_concrete_function")
    source_expression = str(source.get("expression") or source.get("name") or source.get("path") or "")
    if not _concrete_source_expression(source_expression):
        errors.append("missing_concrete_source")
    elif not _source_expression_matches_class(vuln_class, source_expression, source):
        errors.append("source_wrong_class")
    sink_name = str(sink.get("name") or "")
    if not sink_name:
        errors.append("missing_sink")
    elif not _sink_matches_class(vuln_class, sink_name):
        errors.append("sink_wrong_class")
    elif not _sink_in_grounded_function(sink_name, location, cluster, zoom_pack, known):
        errors.append("sink_not_in_grounded_function")
    if _generic_sink_only_anchor(sink_name, location, string_signal, source_expression):
        errors.append("generic_sink_only_anchor")
    if _generic_source_sink_wrapper_anchor(sink_name, location, string_signal):
        errors.append("generic_sink_wrapper_anchor")
    expected_oracle = CLASS_PROOF_ORACLES.get(vuln_class, "")
    if not proof_oracle_kind:
        errors.append("missing_class_oracle")
    elif proof_oracle_kind != expected_oracle:
        errors.append("class_oracle_mismatch")
    mode = str(replay_hints.get("mode") or _nested(replay_hints, "setup", "mode") or "")
    if "|" in mode:
        errors.append("overbroad_replay_mode")
    if raw.get("replay_hints") is None and raw.get("proof_oracle") is None:
        errors.append("missing_deterministic_replay_intent")
    return errors


def _string_signal_matches_class(vuln_class: str, signal: Mapping[str, Any]) -> bool:
    anchor = str(signal.get("anchor") or "")
    if not anchor:
        return False
    return _class_string_signal(vuln_class, anchor, str(signal.get("kind") or "function_string")) is not None


def _concrete_source_expression(expression: str) -> bool:
    normalized = str(expression or "").strip().lower()
    if not normalized:
        return False
    return normalized not in {"unknown", "attacker_input", "attacker input", "user input", "controlled", "semantic_seed"}


def _source_expression_matches_class(vuln_class: str, expression: str, source: Mapping[str, Any]) -> bool:
    text = " ".join([expression, str(source.get("kind") or "")]).lower()
    if vuln_class == "command_injection":
        return any(token in text for token in ("argv", "env", "request", "route", "cgi", "diag", "ping", "cmd", "command", "query", "param", "form", "body", "stdin", "/"))
    if vuln_class == "path_traversal":
        return any(token in text for token in ("argv", "request", "route", "query", "param", "form", "body", "filename", "path", "file", "download", "config", "stdin", "/"))
    if vuln_class == "unsafe_file_write":
        return any(token in text for token in ("argv", "request", "route", "query", "param", "form", "body", "filename", "path", "file", "upload", "content", "restore", "write", "stdin", "/"))
    return False


def _sink_matches_class(vuln_class: str, sink_name: str) -> bool:
    name = str(sink_name or "").lower()
    if vuln_class == "command_injection":
        return any(item == name or item in name for item in SHELL_SINKS)
    if vuln_class == "path_traversal":
        return any(item == name or item in name for item in FILE_READ_SINKS)
    if vuln_class == "unsafe_file_write":
        return any(item == name or item in name for item in FILE_WRITE_SINKS)
    return False


def _sink_in_grounded_function(
    sink_name: str,
    location: Mapping[str, Any],
    cluster: Mapping[str, Any],
    zoom_pack: Mapping[str, Any],
    known: _KnownFeatureIndex,
) -> bool:
    function = _function_for_location(location, zoom_pack, known)
    if not function and isinstance(cluster.get("features"), Mapping):
        function = dict(cluster["features"])
    calls = {str(item).lower() for item in (function or {}).get("calls", []) or []}
    name = str(sink_name or "").lower()
    return any(name == call or name in call or call in name for call in calls)


def _function_for_location(
    location: Mapping[str, Any],
    zoom_pack: Mapping[str, Any],
    known: _KnownFeatureIndex,
) -> Mapping[str, Any]:
    address = _normalize_address(location.get("address"))
    name = _name_key(str(location.get("function_name") or ""))
    for function in zoom_pack.get("functions", []) or []:
        if not isinstance(function, Mapping):
            continue
        if address and _normalize_address(function.get("address")) == address:
            return function
        if name and _name_key(str(function.get("function_name") or "")) == name:
            return function
    if address and address in known.functions_by_address:
        return known.functions_by_address[address]
    if name and name in known.functions_by_name:
        return known.functions_by_name[name]
    return {}


def _generic_sink_only_anchor(
    sink_name: str,
    location: Mapping[str, Any],
    string_signal: Mapping[str, Any],
    source_expression: str,
) -> bool:
    function_name = _name_key(str(location.get("function_name") or ""))
    sink_key = _name_key(sink_name)
    if function_name not in GENERIC_SINK_WRAPPER_NAMES and sink_key not in GENERIC_SINK_WRAPPER_NAMES:
        return False
    return not string_signal or not _concrete_source_expression(source_expression)


def _generic_source_sink_wrapper_anchor(
    sink_name: str,
    location: Mapping[str, Any],
    string_signal: Mapping[str, Any],
) -> bool:
    if str(string_signal.get("kind") or "") != "source_sink_signal":
        return False
    function_name = _name_key(str(location.get("function_name") or ""))
    sink_key = _name_key(sink_name)
    return bool(function_name and function_name == sink_key and function_name in GENERIC_SINK_WRAPPER_NAMES)


def _sink_callsite(sink: Mapping[str, Any], location: Mapping[str, Any]) -> str:
    return _normalize_address(
        sink.get("operation_address")
        or sink.get("address")
        or sink.get("callsite")
        or location.get("address")
    )


def _deterministic_replay_intent(
    *,
    vulnerability_type: str,
    string_signal: Mapping[str, Any],
    source: Mapping[str, Any],
    sink: Mapping[str, Any],
    replay_hints: Mapping[str, Any],
    proof_oracle_kind: str,
) -> dict[str, Any]:
    return {
        "vulnerability_type": vulnerability_type,
        "string_signal_id": str(string_signal.get("signal_id") or ""),
        "string_anchor": str(string_signal.get("anchor") or ""),
        "source_expression": str(source.get("expression") or source.get("name") or source.get("path") or ""),
        "sink": str(sink.get("name") or ""),
        "sink_callsite": str(sink.get("operation_address") or sink.get("address") or ""),
        "proof_oracle_kind": proof_oracle_kind,
        "mode": str(replay_hints.get("mode") or _nested(replay_hints, "setup", "mode") or ""),
    }


def _location_from_anchors(
    anchors: Sequence[Mapping[str, Any]],
    known: _KnownFeatureIndex,
    cluster: Mapping[str, Any],
) -> dict[str, Any]:
    for anchor in anchors:
        if str(anchor.get("kind") or "") != "function":
            continue
        return {
            "function_name": str(anchor.get("function_name") or ""),
            "address": _normalize_address(anchor.get("address")),
            "relative_path": str(anchor.get("relative_path") or ""),
            "line_number": 0,
            "line_text": "",
        }
    for anchor in cluster.get("anchors", []) or []:
        if not isinstance(anchor, Mapping):
            continue
        normalized = _normalize_anchor(anchor, known, {})
        if normalized:
            return _location_from_anchors([normalized], known, {})
    return {"function_name": "", "address": "", "relative_path": "", "line_number": 0, "line_text": ""}


def _seed_addresses(raw: Mapping[str, Any]) -> list[str]:
    addresses: list[str] = []
    for key, value in _walk_items(raw):
        if str(key).endswith("_address") or str(key) in {"address", "operation_address", "sink_address", "target_address"}:
            address = _normalize_address(value)
            if address:
                addresses.append(address)
    return addresses


def _claims_proof(raw: Mapping[str, Any]) -> bool:
    for key, value in _walk_items(raw):
        key_text = str(key).lower()
        value_text = str(value).strip().lower()
        if key_text in {"status", "result", "report_status", "proof_status", "promotion_status"} and value_text in PROOF_CLAIM_VALUES:
            return True
        if key_text in {"reportable", "confirmed", "bug_observed", "sink_reached"} and value is True:
            return True
    return False


def _walk_items(value: Any) -> list[tuple[str, Any]]:
    rows: list[tuple[str, Any]] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            rows.append((str(key), item))
            rows.extend(_walk_items(item))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            rows.extend(_walk_items(item))
    return rows


def _address_in_zoom(address: Any, zoom_pack: Mapping[str, Any]) -> bool:
    normalized = _normalize_address(address)
    if not normalized:
        return False
    for function in zoom_pack.get("functions", []) or []:
        if not isinstance(function, Mapping):
            continue
        if normalized == _normalize_address(function.get("address")):
            return True
        if normalized in {_normalize_address(item) for item in function.get("known_addresses", []) or []}:
            return True
    return False


def _node_for_anchor(nodes: Sequence[FunctionNode], anchor: Mapping[str, Any]) -> FunctionNode | None:
    name = str(anchor.get("function_name") or anchor.get("name") or "")
    address = _normalize_address(anchor.get("address"))
    for node in nodes:
        if name and node.record.name == name:
            return node
        if address and _normalize_address(node.record.address) == address:
            return node
    return None


def _source_excerpt(text: str, *, max_lines: int) -> str:
    lines = (text or "").splitlines()
    if len(lines) <= max_lines:
        return "\n".join(lines)
    head = max_lines // 2
    tail = max_lines - head
    return "\n".join([*lines[:head], "/* ... semantic seed excerpt truncated ... */", *lines[-tail:]])


def _haystack(function: Mapping[str, Any]) -> str:
    values = [
        function.get("function_name", ""),
        function.get("prototype", ""),
        function.get("source_symbol", ""),
        function.get("demangled_name", ""),
        " ".join(str(item) for item in function.get("calls", []) or []),
        " ".join(str(item) for item in function.get("callers", []) or []),
        " ".join(str(item) for item in function.get("strings", []) or []),
    ]
    return "\n".join(str(item) for item in values).lower()


def _score_calls(calls: set[str], wanted: set[str], reasons: list[str], reason: str, *, weight: int) -> int:
    matched = sorted(call for call in calls if any(token == call or token in call for token in wanted))
    if not matched:
        return 0
    reasons.extend(f"{reason}:{item}" for item in matched[:8])
    return weight * len(matched)


def _score_tokens(hay: str, tokens: Sequence[str], reasons: list[str], reason: str, *, weight: int) -> int:
    matched = [token for token in tokens if token.lower() in hay]
    reasons.extend(f"{reason}:{item}" for item in matched[:8])
    return weight * len(matched)


def _score_routes(routes: Sequence[Mapping[str, Any]], tokens: Sequence[str], reasons: list[str], *, weight: int) -> int:
    score = 0
    for route in routes:
        text = json.dumps(route, sort_keys=True).lower()
        matched = [token for token in tokens if token.lower() in text]
        if not matched:
            continue
        route_path = str(route.get("route") or route.get("path") or "")
        reasons.append(f"route_hint:{route_path}")
        score += weight * len(matched)
    return score


def _score_configs(configs: Sequence[Mapping[str, Any]], reasons: list[str], *, weight: int) -> int:
    score = 0
    for config in configs:
        text = json.dumps(config, sort_keys=True).lower()
        if any(token in text for token in ("env", "nvram", "config", "cfg", "conf")):
            reasons.append(f"config_hint:{config.get('relative_path') or config.get('path') or ''}")
            score += weight
    return score


def _matched_texts(values: Sequence[str], hay: str, *, limit: int) -> list[str]:
    result = []
    seen: set[str] = set()
    tokens = set(re.findall(r"[a-z0-9_.:/-]{3,}", hay.lower()))
    for value in values:
        text = str(value)
        lowered = text.lower()
        if text in seen:
            continue
        if any(token and token in lowered for token in tokens):
            seen.add(text)
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _matched_routes(routes: Sequence[Mapping[str, Any]], hay: str) -> list[dict[str, Any]]:
    result = []
    for route in routes:
        route_path = str(route.get("route") or route.get("path") or "")
        if route_path and any(token in hay for token in _route_tokens(route_path)):
            result.append(dict(route))
    return result


def _matched_configs(configs: Sequence[Mapping[str, Any]], hay: str) -> list[dict[str, Any]]:
    result = []
    for config in configs:
        text = json.dumps(config, sort_keys=True).lower()
        if any(token in hay for token in _route_tokens(text)):
            result.append(dict(config))
    return result


def _route_tokens(value: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", value.lower()) if len(token) >= 3}


def _source_call_names(text: str) -> list[str]:
    result = []
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", _strip_string_literals(text or "")):
        name = match.group(1)
        if name in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        result.append(name)
    return _unique_strings(result)


def _strip_string_literals(text: str) -> str:
    return re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', text)


def _string_value(item: Any) -> str:
    if isinstance(item, Mapping):
        return str(item.get("value") or item.get("string") or "")
    return str(item or "")


def _call_name(item: Any) -> str:
    if isinstance(item, Mapping):
        return str(item.get("name") or item.get("target") or item.get("callee") or item.get("function") or "")
    return str(item or "")


def _call_site_features(pcode_calls: Sequence[Any], ambiguous_callsites: Sequence[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in [*pcode_calls, *ambiguous_callsites]:
        if not isinstance(item, Mapping):
            continue
        name = _call_name(item)
        if not name:
            continue
        rows.append(
            {
                "name": name,
                "address": _normalize_address(item.get("address") or item.get("operation_address")),
                "operation_address": _normalize_address(item.get("operation_address") or item.get("address")),
            }
        )
    return rows


def _source_markers(text: str, parameters: Sequence[Any]) -> list[str]:
    source = (text or "").lower()
    markers: list[str] = []
    token_map = {
        "argv": ("argv", "argc"),
        "env": ("getenv", "environ", "nvram", "getenv"),
        "request": ("request", "http", "cgi", "webs", "boa", "uhttpd"),
        "route": ("route", "uri", "url", "path_info"),
        "query": ("query", "querystring"),
        "param": ("param", "parameter", "getvar", "get_cgi", "cgi_get"),
        "form": ("form", "post", "multipart"),
        "body": ("body", "payload"),
        "filename": ("filename", "file_name"),
        "path": ("path", "filepath", "file_path"),
        "file": ("file", "fd"),
        "upload": ("upload", "restore", "import"),
        "content": ("content", "buffer", "buf"),
        "stdin": ("stdin", "fgets", "scanf", "recv", "read("),
    }
    for marker, tokens in token_map.items():
        if any(token in source for token in tokens):
            markers.append(marker)
    for parameter in parameters:
        text_value = str(parameter).lower()
        if "argv" in text_value:
            markers.append("argv")
        if "path" in text_value:
            markers.append("path")
        if "file" in text_value or "name" in text_value:
            markers.append("filename")
        if "buf" in text_value or "data" in text_value:
            markers.append("content")
    return _unique_strings(markers)


def _intake_rows(artifacts: Mapping[str, Any], name: str, row_key: str) -> list[dict[str, Any]]:
    payload = artifacts.get(name)
    rows = payload.get(row_key, []) if isinstance(payload, Mapping) else []
    return [dict(item) for item in rows if isinstance(item, Mapping)]


def _binary_ascii_strings(path: Path) -> list[str]:
    if not path.exists() or not path.is_file():
        return []
    try:
        data = path.read_bytes()
    except OSError:
        return []
    values = [match.group(0).decode("ascii", errors="ignore") for match in re.finditer(rb"[\x20-\x7e]{4,}", data)]
    result = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _payload_cost(payload: Any) -> dict[str, Any]:
    totals = _empty_costs()
    for item in _payload_cost_sources(payload):
        cost = item.get("cost_metadata") if isinstance(item, Mapping) else None
        if isinstance(cost, Mapping):
            _add_costs(totals, cost)
    return totals


def _payload_cost_sources(payload: Any) -> list[Mapping[str, Any]]:
    if isinstance(payload, Mapping):
        if isinstance(payload.get("cost_metadata"), Mapping):
            return [payload]
        rows = [payload]
        for key in ("seeds", "semantic_seeds", "accepted_clusters", "candidates"):
            rows.extend(item for item in _coerce_sequence(payload.get(key, [])) if isinstance(item, Mapping))
        return rows
    return [item for item in _coerce_sequence(payload) if isinstance(item, Mapping)]


def _empty_costs() -> dict[str, Any]:
    return {
        "model_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "wall_time_seconds": 0.0,
        "json_repair_count": 0,
        "models": [],
        "endpoint_profiles": [],
    }


def _add_costs(totals: dict[str, Any], cost: Mapping[str, Any]) -> None:
    totals["model_calls"] += _int(cost.get("model_calls"), 0)
    totals["input_tokens"] += _int(cost.get("input_tokens"), 0)
    totals["output_tokens"] += _int(cost.get("output_tokens"), 0)
    total_tokens = _int(cost.get("total_tokens"), 0)
    if total_tokens <= 0:
        total_tokens = _int(cost.get("input_tokens"), 0) + _int(cost.get("output_tokens"), 0)
    totals["total_tokens"] += total_tokens
    try:
        totals["wall_time_seconds"] += float(cost.get("wall_time_seconds") or 0.0)
    except (TypeError, ValueError):
        pass
    totals["json_repair_count"] += _int(cost.get("json_repair_count"), 0)
    model = str(cost.get("model") or "").strip()
    if model:
        models = totals.setdefault("models", [])
        if model not in models:
            models.append(model)
    for item in cost.get("models", []) or []:
        item_text = str(item).strip()
        if not item_text:
            continue
        models = totals.setdefault("models", [])
        if item_text not in models:
            models.append(item_text)
    endpoint_profile = str(cost.get("endpoint_profile") or "").strip()
    if endpoint_profile:
        profiles = totals.setdefault("endpoint_profiles", [])
        if endpoint_profile not in profiles:
            profiles.append(endpoint_profile)
    for item in cost.get("endpoint_profiles", []) or []:
        item_text = str(item).strip()
        if not item_text:
            continue
        profiles = totals.setdefault("endpoint_profiles", [])
        if item_text not in profiles:
            profiles.append(item_text)


def _public_seed(seed: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in dict(seed).items()
        if key not in {"raw_seed"} and key != "accepted"
    }


def _normalize_classes(classes: Sequence[str]) -> list[str]:
    result: list[str] = []
    supported = set(SUPPORTED_SEMANTIC_SEED_CLASSES)
    for item in classes or DEFAULT_SEMANTIC_SEED_CLASSES:
        value = str(item).strip()
        if not value:
            continue
        if value not in supported:
            raise ValueError(f"Unsupported semantic seed class: {value}")
        if value not in result:
            result.append(value)
    return result or list(DEFAULT_SEMANTIC_SEED_CLASSES)


def _provider_name_is_smoke(name: str) -> bool:
    lowered = str(name or "").lower()
    return any(token in lowered for token in ("fixture", "disabled", "smoke", "deterministic", "fake"))


def _normalize_address(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        return f"0x{int(str(value), 0):x}"
    except (TypeError, ValueError):
        return ""


def _name_key(value: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "", str(value or "").lower())


def _safe_stem(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in str(value))[:120] or "item"


def _stable_id(*parts: Any) -> str:
    raw = "|".join(str(part) for part in parts if part is not None)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:20]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _int(value: Any, default: int = 0) -> int:
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


def _unique_strings(values: Sequence[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _dedupe(items: Sequence[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result



def _nested(value: Mapping[str, Any], *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _nested_mapping(value: Mapping[str, Any], *keys: str) -> Mapping[str, Any]:
    current = _nested(value, *keys)
    return current if isinstance(current, Mapping) else {}


def _rejected_reason_counts(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        reasons = str(row.get("failure_reason") or row.get("reason") or "").split(";")
        for reason in reasons:
            reason = reason.strip()
            if not reason:
                continue
            counts[reason] = counts.get(reason, 0) + 1
    return counts


def _dedupe_anchors(anchors: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for anchor in anchors:
        key = json.dumps(dict(anchor), sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        result.append(dict(anchor))
    return result
