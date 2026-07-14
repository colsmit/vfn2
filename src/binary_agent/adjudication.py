"""Strict two-bucket adjudication for frozen vulnerability candidates.

The adjudication ledger is deliberately separate from candidate/report schema v2.
It records an exhaustive research decision while preserving the existing dynamic
proof gate as the only route to a published vulnerability report.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from binary_agent.pipeline import CandidateState, load_candidate_states
from binary_agent.proof import proof_result_reportable
from binary_agent.pipeline.models import ProofResult


SCHEMA_VERSION = 1
CAMPAIGN_KIND = "strict_hybrid_binary_adjudication"
OPENWRT_24_10_4_X86_64_SDK_SHA256 = (
    "229e871f734a2cee5ce3ad6a3e98d3836b0899bfdeaea4d9c2c5cc7b1fce1407"
)
DECISIONS = frozenset({"bug", "not_bug"})
BUG_BASES = frozenset(
    {
        "dynamic_invariant_violation",
        "exact_source_feasible_violation",
    }
)
NOT_BUG_BASES = frozenset(
    {
        "source_proves_safety",
        "cfg_smt_path_infeasible",
        "verified_modeling_error",
        "intentional_no_boundary",
        "unreachable_all_entries",
        "exhaustive_finite_dynamic",
    }
)
ALL_BASES = BUG_BASES | NOT_BUG_BASES
SPATIAL_TYPES = frozenset({"stack_overflow", "out_of_bounds_write"})
UNINITIALIZED_TYPES = frozenset({"uninitialized_memory_use"})
NULL_TYPES = frozenset({"null_pointer_dereference"})
EFFECT_TYPES = frozenset({"argument_injection", "path_traversal"})
LEAK_TYPES = frozenset({"memory_leak"})
LIFETIME_TYPES = frozenset(
    {
        "use_after_free",
        "double_free",
        "mismatched_deallocator",
        "double_close",
        "use_after_close",
    }
)
SOURCE_BASES = frozenset(
    {
        "exact_source_feasible_violation",
        "source_proves_safety",
        "intentional_no_boundary",
    }
)
BASIS_EVIDENCE_KINDS = {
    "dynamic_invariant_violation": "schema_v2_dynamic_proof",
    "exact_source_feasible_violation": "source_review",
    "source_proves_safety": "source_review",
    "cfg_smt_path_infeasible": "cfg_smt_proof",
    "verified_modeling_error": "analyzer_model_refutation",
    "intentional_no_boundary": "trust_boundary_review",
    "unreachable_all_entries": "reachability_proof",
    "exhaustive_finite_dynamic": "finite_enumeration",
}
WEAK_NEGATIVE_TOKENS = (
    "did not crash",
    "didn't crash",
    "no crash",
    "timed out",
    "timeout",
    "sanitizer silence",
    "no sanitizer",
    "missing harness",
    "unsupported tool",
    "could not reproduce",
    "not reproduced",
    "no proof",
    "lack of proof",
)
_HEX_ADDRESS = re.compile(r"^0x[0-9a-fA-F]+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{7,64}$")


class AdjudicationError(ValueError):
    """Raised when frozen inputs or review evidence violate the contract."""


@dataclass(frozen=True)
class CampaignResult:
    ledger_path: Path
    derived_states_path: Path
    reports_path: Path
    summary_path: Path

    def to_dict(self) -> dict[str, str]:
        return {
            "ledger_path": str(self.ledger_path),
            "derived_states_path": str(self.derived_states_path),
            "reports_path": str(self.reports_path),
            "summary_path": str(self.summary_path),
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def prepare_campaign(
    campaign_root: Path,
    *,
    audit_summary_path: Path,
    candidate_state_paths: Mapping[str, Path],
    binary_paths: Mapping[str, Path],
    export_manifest_paths: Mapping[str, Path],
    tool_paths: Sequence[Path] = (),
    reference_mapping_paths: Mapping[str, Path] | None = None,
) -> Path:
    """Freeze exact inputs and create deterministic review-unit templates."""

    root = Path(campaign_root).resolve()
    audit_path = Path(audit_summary_path).resolve()
    if not audit_path.is_file():
        raise AdjudicationError(f"audit summary is missing: {audit_path}")
    audit = _load_json(audit_path)
    targets = {
        str(item.get("name") or ""): item
        for item in _mapping_rows(audit.get("targets"))
        if str(item.get("name") or "")
    }
    expected_names = set(targets)
    for label, supplied in (
        ("candidate states", candidate_state_paths),
        ("binaries", binary_paths),
        ("export manifests", export_manifest_paths),
    ):
        if set(supplied) != expected_names:
            raise AdjudicationError(
                f"{label} target set mismatch: expected {sorted(expected_names)}, got {sorted(supplied)}"
            )

    existing_manifest = root / "frozen_manifest.json"
    candidate_rows: list[dict[str, Any]] = []
    input_rows: list[dict[str, Any]] = []
    manifests: dict[str, Mapping[str, Any]] = {}
    states_by_name: dict[str, list[CandidateState]] = {}

    root.mkdir(parents=True, exist_ok=True)
    frozen = root / "frozen"
    for name in sorted(expected_names):
        target = targets[name]
        states_path = Path(candidate_state_paths[name]).resolve()
        binary_path = Path(binary_paths[name]).resolve()
        export_path = Path(export_manifest_paths[name]).resolve()
        for kind, path in (
            ("candidate states", states_path),
            ("binary", binary_path),
            ("normalized export manifest", export_path),
        ):
            if not path.is_file():
                raise AdjudicationError(f"{name} {kind} is missing: {path}")

        expected_state_hash = str(_mapping(target.get("final")).get("candidate_states_sha256") or "")
        state_hash = sha256_file(states_path)
        if state_hash != expected_state_hash:
            raise AdjudicationError(
                f"{name} candidate-state hash mismatch: expected {expected_state_hash}, got {state_hash}"
            )
        expected_binary_hash = str(target.get("binary_sha256") or "")
        binary_hash = sha256_file(binary_path)
        if binary_hash != expected_binary_hash:
            raise AdjudicationError(
                f"{name} binary hash mismatch: expected {expected_binary_hash}, got {binary_hash}"
            )

        states = load_candidate_states(states_path)
        expected_count = int(_mapping(target.get("final")).get("candidate_count") or 0)
        if len(states) != expected_count:
            raise AdjudicationError(
                f"{name} candidate count mismatch: expected {expected_count}, got {len(states)}"
            )
        states_by_name[name] = states
        manifest = _load_json(export_path)
        manifests[name] = manifest

        state_destination = frozen / "candidate_states" / f"{_safe_name(name)}.json"
        binary_destination = frozen / "binaries" / _safe_name(name)
        manifest_destination = frozen / "manifests" / f"{_safe_name(name)}.json"
        _copy_exact(states_path, state_destination)
        _copy_exact(binary_path, binary_destination)
        _copy_exact(export_path, manifest_destination)
        input_rows.append(
            {
                "binary": name,
                "source_commit": str(target.get("source_commit") or ""),
                "source_repository": str(target.get("source_repository") or ""),
                "binary_path": _relative(root, binary_destination),
                "binary_sha256": binary_hash,
                "candidate_states_path": _relative(root, state_destination),
                "candidate_states_sha256": state_hash,
                "export_manifest_path": _relative(root, manifest_destination),
                "export_manifest_sha256": sha256_file(manifest_destination),
            }
        )

        for state in states:
            candidate_rows.append(
                {
                    "candidate_id": state.candidate_id,
                    "binary": name,
                    "vulnerability_type": state.vulnerability_type,
                    "function_name": str(state.location.get("function_name") or ""),
                    "line_number": int(state.location.get("line_number") or 0),
                    "original_status": state.status,
                }
            )

    ids = [row["candidate_id"] for row in candidate_rows]
    duplicates = sorted(candidate_id for candidate_id, count in Counter(ids).items() if count > 1)
    if duplicates:
        raise AdjudicationError(f"duplicate frozen candidate IDs: {duplicates}")

    audit_destination = frozen / "audit_summary.json"
    _copy_exact(audit_path, audit_destination)
    tool_hashes = _freeze_tool_hashes(root, tool_paths)
    reference_mappings = _freeze_reference_mappings(
        root,
        reference_mapping_paths or {},
        inputs=input_rows,
    )
    unit_rows = _build_review_units(candidate_rows)
    manifest_payload = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": CAMPAIGN_KIND + "_frozen_manifest",
        "strict_hybrid": True,
        "candidate_count": len(candidate_rows),
        "candidate_ids_sha256": sha256_json(sorted(ids)),
        "audit_summary_path": _relative(root, audit_destination),
        "audit_summary_sha256": sha256_file(audit_destination),
        "inputs": input_rows,
        "tool_hashes": tool_hashes,
        "reference_build_mappings": reference_mappings,
        "candidates": sorted(candidate_rows, key=lambda item: item["candidate_id"]),
        "review_units": unit_rows,
    }
    if existing_manifest.is_file():
        existing = _load_json(existing_manifest)
        if existing != manifest_payload:
            raise AdjudicationError("campaign is already frozen with different inputs or tool hashes")
    else:
        _atomic_json(existing_manifest, manifest_payload)

    binding_dir = root / "bindings"
    template_dir = root / "review_templates"
    by_id = {
        state.candidate_id: (name, state)
        for name, states in states_by_name.items()
        for state in states
    }
    binding_refs: dict[str, dict[str, str]] = {}
    for candidate_id in sorted(by_id):
        name, state = by_id[candidate_id]
        binding = resolve_exact_operation(state, manifests[name])
        binding.update(
            {
                "candidate_id": candidate_id,
                "binary": name,
                "frozen_binary_sha256": next(
                    row["binary_sha256"] for row in input_rows if row["binary"] == name
                ),
            }
        )
        binding_path = binding_dir / f"{candidate_id}.json"
        _atomic_json(binding_path, binding)
        binding_refs[candidate_id] = _evidence_ref(root, binding_path, "exact_binary_operation")

    for unit in unit_rows:
        template = {
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": CAMPAIGN_KIND + "_review",
            "unit_id": unit["unit_id"],
            "shared_evidence_refs": [],
            "decisions": [],
            "candidate_templates": [
                {
                    **next(row for row in candidate_rows if row["candidate_id"] == candidate_id),
                    "binary_operation": _load_json(
                        root / binding_refs[candidate_id]["path"]
                    ),
                    "required_evidence_ref": binding_refs[candidate_id],
                }
                for candidate_id in unit["candidate_ids"]
            ],
        }
        _atomic_json(template_dir / f"{unit['unit_id']}.json", template)

    return existing_manifest


def record_reference_build_mapping(
    campaign_root: Path,
    *,
    binary_name: str,
    frozen_binary_path: Path,
    reference_binary_path: Path,
    sdk_archive_path: Path,
    source_root: Path,
    source_commit: str,
) -> Path:
    """Record a pinned SDK/source build and whether its executable bytes match.

    The source tree, SDK archive, and both binaries must already be contained by
    the campaign root.  A mismatch is recorded, never upgraded to a direct
    source mapping; reviewers must then provide a function fingerprint.
    """

    root = Path(campaign_root).resolve()
    frozen = _contained_existing_file(root, frozen_binary_path, "frozen binary")
    reference = _contained_existing_file(root, reference_binary_path, "reference binary")
    sdk = _contained_existing_file(root, sdk_archive_path, "OpenWrt SDK archive")
    source = _contained_existing_directory(root, source_root, "source checkout")
    commit = str(source_commit).lower()
    if not _COMMIT.fullmatch(commit):
        raise AdjudicationError(f"invalid source commit for {binary_name}: {source_commit!r}")
    actual_commit = _git_head(source)
    if actual_commit != commit:
        raise AdjudicationError(
            f"{binary_name} source checkout mismatch: expected {commit}, got {actual_commit}"
        )
    sdk_hash = sha256_file(sdk)
    if sdk_hash != OPENWRT_24_10_4_X86_64_SDK_SHA256:
        raise AdjudicationError(
            f"OpenWrt SDK hash mismatch: expected {OPENWRT_24_10_4_X86_64_SDK_SHA256}, got {sdk_hash}"
        )

    frozen_code = executable_segment_fingerprint(frozen)
    reference_code = executable_segment_fingerprint(reference)
    code_bytes_match = (
        frozen_code["sha256"] == reference_code["sha256"]
        and frozen_code["size_bytes"] == reference_code["size_bytes"]
        and frozen_code["segment_count"] == reference_code["segment_count"]
    )
    symbol_count = _text_symbol_count(reference)
    if symbol_count <= 0:
        raise AdjudicationError(f"{binary_name} reference binary has no text symbols")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": CAMPAIGN_KIND + "_reference_build_mapping",
        "binary": binary_name,
        "sdk": {
            "path": _relative(root, sdk),
            "sha256": sdk_hash,
        },
        "source": {
            "path": _relative(root, source),
            "commit": commit,
        },
        "frozen_binary": {
            "path": _relative(root, frozen),
            "sha256": sha256_file(frozen),
            "executable_segments": frozen_code,
        },
        "reference_binary": {
            "path": _relative(root, reference),
            "sha256": sha256_file(reference),
            "executable_segments": reference_code,
            "text_symbol_count": symbol_count,
        },
        "code_bytes_match": code_bytes_match,
        "direct_source_mapping_allowed": code_bytes_match,
        "mismatch_policy": (
            "exact_code_bytes" if code_bytes_match else "function_fingerprint_required"
        ),
    }
    destination = root / "reference-builds" / "mappings" / f"{_safe_name(binary_name)}.json"
    _atomic_json(destination, payload)
    return destination


def executable_segment_fingerprint(path: Path) -> dict[str, Any]:
    """Hash the ordered file bytes of every executable ELF PT_LOAD segment."""

    segments = [segment for segment in _elf_load_segments(Path(path)) if segment["flags"] & 1]
    if not segments:
        raise AdjudicationError(f"ELF has no executable load segment: {path}")
    digest = hashlib.sha256()
    size = 0
    for segment in segments:
        data = segment["data"]
        digest.update(struct.pack(">Q", len(data)))
        digest.update(data)
        size += len(data)
    return {
        "sha256": digest.hexdigest(),
        "size_bytes": size,
        "segment_count": len(segments),
    }


def resolve_exact_operation(
    candidate: CandidateState | Mapping[str, Any],
    normalized_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Resolve a candidate to one numeric p-code operation without text synthesis."""

    state = candidate if isinstance(candidate, CandidateState) else CandidateState.from_dict(candidate)
    function_name = str(state.location.get("function_name") or "")
    function_address = _normalize_address(state.location.get("address"))
    functions = [item for item in _mapping_rows(normalized_manifest.get("functions"))]
    function = next(
        (
            item
            for item in functions
            if str(item.get("name") or "") == function_name
            or _normalize_address(item.get("address")) == function_address
        ),
        None,
    )
    if function is None:
        return _unresolved_operation(state, "function_missing_from_normalized_manifest")

    stores = _normalized_pcode_rows(function, "pcode_stores", "STORE")
    loads = _normalized_pcode_rows(function, "pcode_loads", "LOAD")
    calls = _normalized_pcode_rows(function, "pcode_calls", "CALL")
    operations = _normalized_pcode_rows(function, "pcode_operations", "")
    if state.vulnerability_type in SPATIAL_TYPES:
        allowed = stores
    elif state.vulnerability_type in UNINITIALIZED_TYPES:
        allowed = operations or [*loads, *stores, *calls]
    elif state.vulnerability_type in NULL_TYPES:
        allowed = [*loads, *stores, *calls]
    else:
        allowed = [*calls, *stores, *loads]
    by_address = {row["address"]: row for row in allowed if row["address"]}

    explicit_addresses = _unique(
        _normalize_address(value)
        for value in (
            state.sink.get("operation_address"),
            state.operation.get("operation_address"),
            state.operation.get("address"),
        )
        if _is_numeric_address(value)
    )
    explicit = [by_address[address] for address in explicit_addresses if address in by_address]
    if len({row["address"] for row in explicit}) == 1:
        row = explicit[0]
        return _resolved_operation(state, function, row, "candidate_exact_operation_address")

    if state.vulnerability_type in SPATIAL_TYPES:
        return_address_store = _x86_return_address_store_match(state, stores)
        if return_address_store is not None:
            return _resolved_operation(
                state,
                function,
                return_address_store,
                "x86_call_return_address_store",
            )
        interprocedural_store = _interprocedural_store_match(state, functions)
        if interprocedural_store is not None:
            callee_function, store = interprocedural_store
            return _resolved_operation(
                state,
                callee_function,
                store,
                "interprocedural_exact_store",
            )

    line_number = int(state.location.get("line_number") or 0)
    line_offset = int(
        function.get("c_line_number_offset")
        if function.get("c_line_number_offset") is not None
        else (3 if function.get("pcode_operations") else 0)
    )
    manifest_line_number = line_number - line_offset
    line_rows = [
        item
        for item in _mapping_rows(function.get("c_line_addresses"))
        if int(item.get("line_number") or 0) == manifest_line_number
    ]
    named_call_match = _named_call_token_match(state, line_rows, calls)
    if named_call_match is not None:
        return _resolved_operation(state, function, named_call_match, "normalized_named_call_mapping")
    if state.vulnerability_type in SPATIAL_TYPES:
        token_store_match = _line_token_pcode_match(line_rows, stores, "STORE")
        if token_store_match is not None:
            return _resolved_operation(
                state,
                function,
                token_store_match,
                "normalized_token_pcode_mapping",
            )
    token_match = _token_operation_match(state, line_rows, operations)
    if token_match is not None:
        return _resolved_operation(state, function, token_match, "normalized_token_pcode_mapping")
    line_addresses: list[str] = []
    preferred_key = "store_addresses" if state.vulnerability_type in SPATIAL_TYPES else ""
    for line in line_rows:
        if preferred_key:
            line_addresses.extend(
                _normalize_address(item) for item in _sequence(line.get(preferred_key))
            )
        line_addresses.extend(_normalize_address(item) for item in _sequence(line.get("addresses")))
        if state.vulnerability_type in UNINITIALIZED_TYPES | NULL_TYPES:
            line_addresses.extend(
                _normalize_address(item) for item in _sequence(line.get("load_addresses"))
            )
    semantic_line_addresses = list(line_addresses)
    if not semantic_line_addresses:
        neighbor_rows = sorted(
            (
                item
                for item in _mapping_rows(function.get("c_line_addresses"))
                if 0 < abs(int(item.get("line_number") or 0) - manifest_line_number) <= 2
            ),
            key=lambda item: abs(int(item.get("line_number") or 0) - manifest_line_number),
        )
        for line in neighbor_rows:
            semantic_line_addresses.extend(
                _normalize_address(item) for item in _sequence(line.get("addresses"))
            )
    matches = [by_address[address] for address in _unique(line_addresses) if address in by_address]
    if len({row["address"] for row in matches}) == 1:
        return _resolved_operation(state, function, matches[0], "normalized_pcode_line_mapping")
    semantic_match = _nearest_semantic_pcode_match(state, allowed, semantic_line_addresses)
    if semantic_match is not None:
        return _resolved_operation(state, function, semantic_match, "normalized_pcode_semantic_mapping")
    if not matches:
        reason = "no_pcode_operation_at_candidate_line"
    else:
        reason = "ambiguous_pcode_operations_at_candidate_line"
    return _unresolved_operation(
        state,
        reason,
        function_address=_normalize_address(function.get("address")),
        candidate_addresses=sorted({row["address"] for row in matches}),
    )


def validate_source_binding(binding: Mapping[str, Any]) -> None:
    """Validate an exact-build or fingerprint-backed upstream source mapping."""

    source_path = str(binding.get("source_path") or "")
    source_hash = str(binding.get("source_sha256") or "").lower()
    commit = str(binding.get("source_commit") or "").lower()
    function = str(binding.get("source_function") or "")
    lines = [int(item) for item in _sequence(binding.get("source_lines")) if int(item) > 0]
    if not source_path or not _SHA256.fullmatch(source_hash) or not _COMMIT.fullmatch(commit):
        raise AdjudicationError("source binding requires path, SHA-256, and pinned commit")
    if not function or not lines:
        raise AdjudicationError("source binding requires a function and positive source lines")

    basis = str(binding.get("mapping_basis") or "")
    frozen_binary = str(binding.get("frozen_binary_sha256") or "").lower()
    if not _SHA256.fullmatch(frozen_binary):
        raise AdjudicationError("source binding requires the frozen binary SHA-256")
    if basis == "exact_code_bytes":
        frozen_code = str(binding.get("frozen_code_sha256") or "").lower()
        reference_code = str(binding.get("reference_code_sha256") or "").lower()
        if (
            not _SHA256.fullmatch(frozen_code)
            or frozen_code != reference_code
            or binding.get("code_bytes_match") is not True
        ):
            raise AdjudicationError("direct source mapping requires matching frozen/reference code bytes")
    elif basis == "function_fingerprint":
        frozen_function = str(binding.get("frozen_function_sha256") or "").lower()
        reference_function = str(binding.get("reference_function_sha256") or "").lower()
        if not _SHA256.fullmatch(frozen_function) or frozen_function != reference_function:
            raise AdjudicationError("fingerprint mapping requires equal function-byte fingerprints")
        if binding.get("constants_match") is not True or binding.get("call_topology_match") is not True:
            raise AdjudicationError("fingerprint mapping requires constants and call topology matches")
    else:
        raise AdjudicationError(f"unsupported source mapping basis: {basis!r}")


def validate_decision(
    decision: Mapping[str, Any],
    *,
    candidate: Mapping[str, Any],
    prepared_binding: Mapping[str, Any],
    campaign_root: Path,
    shared_evidence_refs: Sequence[Mapping[str, Any]] = (),
) -> None:
    """Validate one final decision against strict-hybrid and class obligations."""

    candidate_id = str(candidate.get("candidate_id") or "")
    if str(decision.get("candidate_id") or "") != candidate_id:
        raise AdjudicationError(f"decision candidate mismatch for {candidate_id}")
    outcome = str(decision.get("decision") or "")
    basis = str(decision.get("basis") or "")
    if outcome not in DECISIONS:
        raise AdjudicationError(f"{candidate_id}: decision must be bug or not_bug")
    allowed = BUG_BASES if outcome == "bug" else NOT_BUG_BASES
    if basis not in allowed:
        raise AdjudicationError(f"{candidate_id}: basis {basis!r} is not allowed for {outcome}")
    rationale = " ".join(str(decision.get("rationale") or "").split())
    if len(rationale) < 24:
        raise AdjudicationError(f"{candidate_id}: rationale is too short to be affirmative evidence")
    if outcome == "not_bug" and any(token in rationale.lower() for token in WEAK_NEGATIVE_TOKENS):
        raise AdjudicationError(f"{candidate_id}: weak negative language cannot authorize not_bug")

    evidence = [*_mapping_rows(shared_evidence_refs), *_mapping_rows(decision.get("evidence_refs"))]
    verified_hashes = _validate_evidence_refs(Path(campaign_root), evidence)
    if not verified_hashes:
        raise AdjudicationError(f"{candidate_id}: at least one hashed evidence artifact is required")
    evidence_kinds = {str(item.get("kind") or "") for item in evidence}
    if "exact_binary_operation" not in evidence_kinds:
        raise AdjudicationError(f"{candidate_id}: exact binary operation evidence is not referenced")
    required_basis_kind = BASIS_EVIDENCE_KINDS[basis]
    if required_basis_kind not in evidence_kinds:
        raise AdjudicationError(
            f"{candidate_id}: basis {basis!r} requires {required_basis_kind!r} evidence"
        )

    operation = _mapping(decision.get("binary_operation"))
    _validate_operation(candidate_id, operation, prepared_binding, str(candidate.get("vulnerability_type") or ""))
    if str(prepared_binding.get("status") or "") != "resolved":
        raise AdjudicationError(f"{candidate_id}: prepared exact operation remains unresolved")

    if basis in SOURCE_BASES:
        source_binding = _mapping(decision.get("source_binding"))
        validate_source_binding(source_binding)
        if str(source_binding.get("source_sha256") or "").lower() not in verified_hashes:
            raise AdjudicationError(f"{candidate_id}: bound source file is not present in hashed evidence")
        if str(source_binding.get("frozen_binary_sha256") or "") != str(
            prepared_binding.get("frozen_binary_sha256") or ""
        ):
            raise AdjudicationError(f"{candidate_id}: source binding targets a different frozen binary")

    obligations = _mapping(decision.get("obligations"))
    required, alternatives = _required_obligations(
        vulnerability_type=str(candidate.get("vulnerability_type") or ""),
        decision=outcome,
        basis=basis,
    )
    for obligation in required:
        _validate_satisfied_obligation(candidate_id, obligation, obligations, verified_hashes)
    for choices in alternatives:
        satisfied = [
            choice
            for choice in choices
            if _obligation_is_satisfied(obligations.get(choice), verified_hashes)
        ]
        if not satisfied:
            raise AdjudicationError(
                f"{candidate_id}: one of {sorted(choices)} must be affirmatively satisfied"
            )

    if basis == "dynamic_invariant_violation":
        proof = _mapping(decision.get("dynamic_proof"))
        if int(proof.get("schema_version") or 0) != 2:
            raise AdjudicationError(f"{candidate_id}: dynamic bug proof must be schema v2")
        if str(proof.get("candidate_id") or "") != candidate_id:
            raise AdjudicationError(f"{candidate_id}: dynamic proof candidate mismatch")
        if not str(proof.get("invariant_violation") or ""):
            raise AdjudicationError(f"{candidate_id}: dynamic proof lacks a concrete invariant violation")
        if str(proof.get("evidence_sha256") or "").lower() not in verified_hashes:
            raise AdjudicationError(f"{candidate_id}: dynamic proof does not identify its hashed artifact")
    if basis == "exhaustive_finite_dynamic":
        enumeration = _mapping(decision.get("finite_enumeration"))
        domain_size = int(enumeration.get("domain_size") or 0)
        tested = int(enumeration.get("tested_inputs") or 0)
        if domain_size <= 0 or tested != domain_size or enumeration.get("complete") is not True:
            raise AdjudicationError(f"{candidate_id}: finite dynamic domain was not exhausted")
        if str(enumeration.get("evidence_sha256") or "").lower() not in verified_hashes:
            raise AdjudicationError(f"{candidate_id}: enumeration does not identify its hashed artifact")


def admit_review(campaign_root: Path, review_path: Path) -> Path:
    """Validate and atomically admit one complete 109-unit review artifact."""

    root = Path(campaign_root).resolve()
    manifest = _load_json(root / "frozen_manifest.json")
    review = _load_json(Path(review_path))
    unit_id = str(review.get("unit_id") or "")
    unit = next(
        (item for item in _mapping_rows(manifest.get("review_units")) if item.get("unit_id") == unit_id),
        None,
    )
    if unit is None:
        raise AdjudicationError(f"unknown review unit: {unit_id!r}")
    decisions = _mapping_rows(review.get("decisions"))
    decision_ids = [str(item.get("candidate_id") or "") for item in decisions]
    expected_ids = [str(item) for item in _sequence(unit.get("candidate_ids"))]
    _require_exact_ids(decision_ids, expected_ids, context=f"review unit {unit_id}")

    candidates = {str(item.get("candidate_id") or ""): item for item in _mapping_rows(manifest.get("candidates"))}
    shared = _mapping_rows(review.get("shared_evidence_refs"))
    _validate_evidence_refs(root, shared)
    for decision in decisions:
        candidate_id = str(decision.get("candidate_id") or "")
        binding = _load_json(root / "bindings" / f"{candidate_id}.json")
        validate_decision(
            decision,
            candidate=candidates[candidate_id],
            prepared_binding=binding,
            campaign_root=root,
            shared_evidence_refs=shared,
        )
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": CAMPAIGN_KIND + "_review",
        "unit_id": unit_id,
        "shared_evidence_refs": sorted(shared, key=_evidence_sort_key),
        "decisions": sorted(decisions, key=lambda item: str(item.get("candidate_id") or "")),
    }
    destination = root / "reviews" / f"{unit_id}.json"
    _atomic_json(destination, normalized)
    return destination


def finalize_campaign(campaign_root: Path) -> CampaignResult:
    """Finalize an exhaustive ledger or fail without weakening an evidence gate."""

    root = Path(campaign_root).resolve()
    manifest_path = root / "frozen_manifest.json"
    manifest = _load_json(manifest_path)
    _verify_frozen_inputs(root, manifest)
    candidates = {str(item.get("candidate_id") or ""): item for item in _mapping_rows(manifest.get("candidates"))}
    reviews: list[Mapping[str, Any]] = []
    decisions: list[Mapping[str, Any]] = []
    for unit in _mapping_rows(manifest.get("review_units")):
        unit_id = str(unit.get("unit_id") or "")
        review_path = root / "reviews" / f"{unit_id}.json"
        if not review_path.is_file():
            raise AdjudicationError(f"missing review for unit {unit_id}")
        review = _load_json(review_path)
        reviews.append(
            {
                "unit_id": unit_id,
                "path": _relative(root, review_path),
                "sha256": sha256_file(review_path),
            }
        )
        review_decisions = _mapping_rows(review.get("decisions"))
        expected_ids = [str(item) for item in _sequence(unit.get("candidate_ids"))]
        _require_exact_ids(
            [str(item.get("candidate_id") or "") for item in review_decisions],
            expected_ids,
            context=f"review unit {unit_id}",
        )
        shared = _mapping_rows(review.get("shared_evidence_refs"))
        for decision in review_decisions:
            candidate_id = str(decision.get("candidate_id") or "")
            if candidate_id not in candidates:
                raise AdjudicationError(f"unknown candidate ID in review: {candidate_id}")
            binding = _load_json(root / "bindings" / f"{candidate_id}.json")
            validate_decision(
                decision,
                candidate=candidates[candidate_id],
                prepared_binding=binding,
                campaign_root=root,
                shared_evidence_refs=shared,
            )
            decisions.append(_ledger_decision(decision, candidates[candidate_id], shared))

    frozen_ids = sorted(candidates)
    _require_exact_ids(
        [str(item.get("candidate_id") or "") for item in decisions],
        frozen_ids,
        context="final ledger",
    )
    decisions = sorted(decisions, key=lambda item: str(item.get("candidate_id") or ""))
    decision_hash = sha256_json(decisions)
    ledger = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": CAMPAIGN_KIND + "_ledger",
        "strict_hybrid": True,
        "frozen_manifest": {
            "path": _relative(root, manifest_path),
            "sha256": sha256_file(manifest_path),
            "candidate_ids_sha256": str(manifest.get("candidate_ids_sha256") or ""),
        },
        "tool_hashes": _mapping_rows(manifest.get("tool_hashes")),
        "candidate_count": len(decisions),
        "decision_set_sha256": decision_hash,
        "reviews": sorted(reviews, key=lambda item: item["unit_id"]),
        "decisions": decisions,
    }
    ledger_path = root / "adjudication_ledger.json"
    _atomic_json(ledger_path, ledger)

    states = _load_frozen_states(root, manifest)
    derived = _derive_candidate_states(states, decisions, root)
    derived_path = root / "derived" / "candidate_states.json"
    _atomic_json(
        derived_path,
        {
            "schema_version": 2,
            "generated_at": "frozen-adjudication-v1",
            "candidate_states": derived,
        },
    )
    reports = _collect_reportable_reports(states, decisions, root)
    reports_path = root / "reports" / "reports.json"
    _atomic_json(reports_path, {"schema_version": 2, "vulnerabilities": reports})
    summary = _build_summary(decisions, candidates, decision_hash, ledger_path, derived_path, reports_path)
    summary_path = root / "summary.json"
    _atomic_json(summary_path, summary)
    return CampaignResult(ledger_path, derived_path, reports_path, summary_path)


def _build_review_units(candidates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[str]] = {}
    for candidate in candidates:
        key = (
            str(candidate.get("binary") or ""),
            str(candidate.get("function_name") or ""),
            str(candidate.get("vulnerability_type") or ""),
        )
        grouped.setdefault(key, []).append(str(candidate.get("candidate_id") or ""))
    rows: list[dict[str, Any]] = []
    for key in sorted(grouped):
        binary, function, vulnerability_type = key
        ids = sorted(grouped[key])
        unit_id = hashlib.sha256("\0".join(key).encode("utf-8")).hexdigest()[:16]
        rows.append(
            {
                "unit_id": unit_id,
                "binary": binary,
                "function_name": function,
                "vulnerability_type": vulnerability_type,
                "candidate_ids": ids,
                "candidate_count": len(ids),
            }
        )
    return rows


def _normalized_pcode_rows(function: Mapping[str, Any], key: str, default_pcode: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in _mapping_rows(function.get(key)):
        address = _normalize_address(
            raw.get("operation_address") or raw.get("call_address") or raw.get("address")
        )
        if not _is_numeric_address(address):
            continue
        pcode = str(raw.get("pcode") or default_pcode).upper()
        if not pcode:
            continue
        if key == "pcode_calls" and pcode not in {"CALL", "CALLIND"}:
            pcode = default_pcode
        constants = {
            int(item)
            for item in _sequence(raw.get("address_constants"))
            if isinstance(item, int)
        }
        semantic_labels = sorted(
            {
                str(name)
                for region in _mapping_rows(function.get("stack_regions"))
                if int(region.get("start_offset") or 0) in constants
                for name in _sequence(region.get("var_names"))
                if str(name)
            }
        )
        rows.append(
            {
                "address": address,
                "pcode": pcode,
                "width_bytes": int(
                    raw.get("write_width")
                    or raw.get("read_width")
                    or _mapping(raw.get("output")).get("size_bytes")
                    or 0
                ),
                "metadata": dict(raw),
                "semantic_labels": semantic_labels,
            }
        )
    return rows


def _nearest_semantic_pcode_match(
    state: CandidateState,
    rows: Sequence[Mapping[str, Any]],
    line_addresses: Sequence[str],
) -> Mapping[str, Any] | None:
    """Bind decompiler-only locations using varnodes plus nearest mapped instruction.

    Ghidra may attach a high-level C statement to a register-producing
    instruction while the corresponding LOAD/STORE p-code operation occurs a
    few bytes earlier.  This fallback requires both an exact exported p-code
    row and matching identifier semantics; proximity alone is never enough.
    """

    expected = _candidate_identifiers(state)
    numeric_lines = [int(item, 16) for item in line_addresses if _is_numeric_address(item)]
    if not expected or not numeric_lines:
        return None
    scored: list[tuple[int, int, str, Mapping[str, Any]]] = []
    for row in rows:
        address = str(row.get("address") or "")
        if not _is_numeric_address(address):
            continue
        metadata_text = json.dumps(
            {
                "metadata": row.get("metadata") or {},
                "semantic_labels": row.get("semantic_labels") or [],
            },
            sort_keys=True,
        )
        row_identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", metadata_text))
        overlap = expected & row_identifiers
        if not overlap:
            continue
        distance = min(abs(int(address, 16) - line) for line in numeric_lines)
        if distance > 64:
            continue
        scored.append((-len(overlap), distance, address, row))
    if not scored:
        return None
    scored.sort(key=lambda item: (item[0], item[1], int(item[2], 16)))
    best = scored[0]
    tied = [item for item in scored if item[:2] == best[:2]]
    if len(tied) != 1:
        return None
    return best[3]


def _token_operation_match(
    state: CandidateState,
    line_rows: Sequence[Mapping[str, Any]],
    operations: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    expected = _candidate_identifiers(state)
    if not expected or not operations:
        return None
    requested = {
        (
            str(item.get("operation_address") or "").upper(),
            str(item.get("pcode") or "").upper(),
        )
        for line in line_rows
        for item in _mapping_rows(line.get("token_operations"))
        if str(item.get("token") or "") in expected
    }
    requested.discard(("", ""))
    matches = [
        row
        for row in operations
        if (str(row.get("address") or "").upper(), str(row.get("pcode") or "").upper())
        in requested
    ]
    identities = {(str(row.get("address") or ""), str(row.get("pcode") or "")) for row in matches}
    if len(identities) != 1:
        return None
    return matches[0]


def _line_token_pcode_match(
    line_rows: Sequence[Mapping[str, Any]],
    operations: Sequence[Mapping[str, Any]],
    pcode: str,
) -> Mapping[str, Any] | None:
    """Select one exact operation kind from decompiler token metadata.

    A token naming the destination expression can map to address-calculation
    p-code (for example ``PTRADD`` or ``CAST``), while the assignment token at
    the same sequence address maps to the actual ``STORE``.  Spatial evidence
    must bind the latter operation, irrespective of which expression token
    carried the candidate identifier.
    """

    expected_pcode = pcode.upper()
    requested = {
        (
            str(item.get("operation_address") or "").upper(),
            str(item.get("pcode") or "").upper(),
        )
        for line in line_rows
        for item in _mapping_rows(line.get("token_operations"))
        if str(item.get("pcode") or "").upper() == expected_pcode
    }
    requested.discard(("", expected_pcode))
    matches = [
        row
        for row in operations
        if (str(row.get("address") or "").upper(), str(row.get("pcode") or "").upper())
        in requested
    ]
    identities = {(str(row.get("address") or ""), str(row.get("pcode") or "")) for row in matches}
    if len(identities) != 1:
        return None
    return matches[0]


def _named_call_token_match(
    state: CandidateState,
    line_rows: Sequence[Mapping[str, Any]],
    calls: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    name = str(state.operation.get("name") or state.sink.get("name") or "").lower()
    if not name:
        return None
    addresses = {
        _normalize_address(item.get("operation_address"))
        for line in line_rows
        for item in _mapping_rows(line.get("token_operations"))
        if name in str(item.get("token") or "").lower()
    }
    addresses.discard("")
    matches = [row for row in calls if str(row.get("address") or "") in addresses]
    if len({str(row.get("address") or "") for row in matches}) != 1:
        return None
    return matches[0]


def _x86_return_address_store_match(
    state: CandidateState,
    stores: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    """Recognize decompiler-emitted stack stores that are x86 CALL semantics.

    A pushed return address is exactly the address following the CALL.  Ghidra
    can render that p-code STORE as an apparent C assignment into a small local
    stack object.  The literal successor address gives an exact, non-textual
    instruction binding once it selects one exported STORE within the maximum
    x86 instruction length.
    """

    line = str(state.location.get("line_text") or "")
    match = re.search(r"=\s*(0x[0-9a-fA-F]+)\s*;?\s*$", line)
    if match is None:
        return None
    successor = int(match.group(1), 16)
    matches = []
    for row in stores:
        address = str(row.get("address") or "")
        if not _is_numeric_address(address):
            continue
        distance = successor - int(address, 16)
        if 1 <= distance <= 15:
            matches.append(row)
    if len({str(row.get("address") or "") for row in matches}) != 1:
        return None
    return matches[0]


def _interprocedural_store_match(
    state: CandidateState,
    functions: Sequence[Mapping[str, Any]],
) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    static = _mapping(state.type_facts.get("static_candidate"))
    if not str(static.get("kind") or "").startswith("interprocedural_"):
        return None
    callee_names = set(re.findall(r"\bFUN_[0-9A-Fa-f]+\b", str(state.location.get("line_text") or "")))
    callees = [function for function in functions if str(function.get("name") or "") in callee_names]
    if len(callees) != 1:
        return None
    callee = callees[0]
    stores = _normalized_pcode_rows(callee, "pcode_stores", "STORE")
    offset_expr = str(static.get("offset_expr") or "")
    offset_identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", offset_expr))
    offset_constants = {int(item) for item in re.findall(r"(?<![A-Za-z_])-?\d+", offset_expr)}
    source_role = _mapping(
        _mapping(_mapping(static.get("classification_trace")).get("source_to_write")).get("roles")
    ).get("write_source")
    source_expr = str(_mapping(source_role).get("expr") or "")
    source_constants = {int(item) for item in re.findall(r"(?<![A-Za-z_])-?\d+", source_expr)}
    scored: list[tuple[int, int, Mapping[str, Any]]] = []
    for row in stores:
        metadata = _mapping(row.get("metadata"))
        variables = {str(item) for item in _sequence(metadata.get("address_vars"))}
        constants = {
            int(item)
            for item in _sequence(metadata.get("address_constants"))
            if isinstance(item, int)
        }
        if "param_1" not in variables:
            continue
        offset_overlap = len(offset_identifiers & variables)
        offset_constant_overlap = len(offset_constants & constants)
        source_constant_overlap = len(source_constants & constants)
        if not (offset_overlap or offset_constant_overlap or source_constant_overlap):
            continue
        score = 4 * offset_overlap + 3 * offset_constant_overlap + 2 * source_constant_overlap
        width_delta = abs(int(row.get("width_bytes") or 0) - int(static.get("write_size_bytes") or 0))
        scored.append((-score, width_delta, row))
    if not scored:
        return None
    scored.sort(key=lambda item: (item[0], item[1], int(str(item[2].get("address")), 16)))
    best = scored[0]
    if sum(1 for item in scored if item[:2] == best[:2]) != 1:
        return None
    return callee, best[2]


def _candidate_identifiers(state: CandidateState) -> set[str]:
    fragments: list[str] = [
        str(state.location.get("line_text") or ""),
        str(state.affected_object.get("label") or ""),
        str(state.affected_object.get("identity") or ""),
        str(state.sink.get("target_buffer") or ""),
        str(state.source.get("expression") or ""),
    ]
    for mapping in (state.operation, state.sink):
        roles = mapping.get("argument_roles")
        if isinstance(roles, Mapping):
            fragments.extend(str(value) for value in roles.values())
    static = state.type_facts.get("static_candidate")
    if isinstance(static, Mapping):
        fragments.extend(
            str(static.get(key) or "")
            for key in ("offset_expr", "write_size_expr", "source_expression", "target_buffer")
        )
    ignored = {
        "long",
        "int",
        "char",
        "undefined",
        "undefined1",
        "undefined2",
        "undefined4",
        "undefined8",
        "void",
        "line",
        "stack",
        "local",
    }
    return {
        token
        for token in re.findall(r"\b[A-Za-z_]\w*\b", " ".join(fragments))
        if token not in ignored and not token.startswith("FUN_")
    }


def _resolved_operation(
    state: CandidateState,
    function: Mapping[str, Any],
    row: Mapping[str, Any],
    basis: str,
) -> dict[str, Any]:
    return {
        "status": "resolved",
        "address": str(row.get("address") or ""),
        "pcode": str(row.get("pcode") or ""),
        "width_bytes": int(row.get("width_bytes") or 0),
        "function_name": str(function.get("name") or state.location.get("function_name") or ""),
        "function_address": _normalize_address(function.get("address")),
        "source_line": int(state.location.get("line_number") or 0),
        "mapping_basis": basis,
        "pcode_record": _mapping(row.get("metadata")),
    }


def _unresolved_operation(
    state: CandidateState,
    reason: str,
    *,
    function_address: str = "",
    candidate_addresses: Sequence[str] = (),
) -> dict[str, Any]:
    return {
        "status": "unresolved",
        "address": "",
        "pcode": "",
        "width_bytes": 0,
        "function_name": str(state.location.get("function_name") or ""),
        "function_address": function_address or _normalize_address(state.location.get("address")),
        "source_line": int(state.location.get("line_number") or 0),
        "mapping_basis": "",
        "reason": reason,
        "candidate_addresses": list(candidate_addresses),
    }


def _validate_operation(
    candidate_id: str,
    operation: Mapping[str, Any],
    prepared: Mapping[str, Any],
    vulnerability_type: str,
) -> None:
    address = str(operation.get("address") or "")
    if not _HEX_ADDRESS.fullmatch(address) or ":" in address:
        raise AdjudicationError(f"{candidate_id}: operation address must be exact numeric hexadecimal")
    for key in ("address", "pcode", "function_name", "function_address", "source_line"):
        if operation.get(key) != prepared.get(key):
            raise AdjudicationError(f"{candidate_id}: operation disagrees with frozen binding field {key}")
    if str(operation.get("status") or "") != "resolved":
        raise AdjudicationError(f"{candidate_id}: operation binding is unresolved")
    if vulnerability_type in SPATIAL_TYPES and str(operation.get("pcode") or "") != "STORE":
        raise AdjudicationError(f"{candidate_id}: spatial candidate requires an exact p-code STORE")


def _required_obligations(
    *,
    vulnerability_type: str,
    decision: str,
    basis: str,
) -> tuple[set[str], list[set[str]]]:
    required = {"exact_operation", "source_or_binary_binding"}
    alternatives: list[set[str]] = []
    if vulnerability_type in UNINITIALIZED_TYPES:
        if decision == "bug":
            required |= {"read_before_write", "real_entry_reachability", "attacker_or_boundary_control"}
        elif basis == "source_proves_safety":
            required.add("all_path_initialization")
    elif vulnerability_type in SPATIAL_TYPES:
        required |= {"exact_store", "object_identity", "capacity", "offset_relation"}
        if decision == "bug":
            required |= {"feasible_out_of_bounds", "real_entry_reachability", "attacker_or_boundary_control"}
        elif basis == "source_proves_safety":
            required.add("bounds_proven")
    elif vulnerability_type in NULL_TYPES:
        required.add("exact_zero_capable_access")
        if decision == "bug":
            required |= {"zero_address_feasible", "real_entry_reachability", "attacker_or_boundary_control"}
        elif basis == "source_proves_safety":
            alternatives.append({"dominating_non_null", "allocation_contract"})
    elif vulnerability_type in EFFECT_TYPES:
        required.add("trust_boundary_modeled")
        if decision == "bug":
            required |= {"boundary_escape", "real_entry_reachability", "attacker_or_boundary_control"}
        elif basis == "intentional_no_boundary":
            required |= {"intended_effect", "no_security_boundary"}
        elif basis == "source_proves_safety":
            required.add("input_cannot_alter_effect")
    elif vulnerability_type in LEAK_TYPES:
        required.add("ownership_lifetime_modeled")
        if decision == "bug":
            required |= {
                "repeatable_external_action",
                "unbounded_unreleased_generations",
                "real_entry_reachability",
            }
        elif basis == "source_proves_safety":
            alternatives.append({"ownership_transfer", "bounded_lifetime", "later_cleanup"})
    elif vulnerability_type in LIFETIME_TYPES:
        required.add("resource_lifetime_modeled")
        if decision == "bug":
            required |= {
                "same_resource_generation",
                "ordered_events",
                "violation",
                "real_entry_reachability",
                "attacker_or_boundary_control",
            }
        elif basis == "source_proves_safety":
            alternatives.append(
                {
                    "mutually_exclusive_paths",
                    "different_resource_generation",
                    "terminating_path",
                    "ownership_cleanup",
                }
            )
    else:
        raise AdjudicationError(f"unsupported adjudication vulnerability type: {vulnerability_type!r}")

    if decision == "not_bug":
        basis_obligation = {
            "cfg_smt_path_infeasible": "violating_path_infeasible",
            "verified_modeling_error": "semantics_absent",
            "unreachable_all_entries": "unreachable_all_entries",
            "exhaustive_finite_dynamic": "finite_domain_exhausted",
        }.get(basis)
        if basis_obligation:
            required.add(basis_obligation)
    return required, alternatives


def _validate_satisfied_obligation(
    candidate_id: str,
    name: str,
    obligations: Mapping[str, Any],
    verified_hashes: set[str],
) -> None:
    if not _obligation_is_satisfied(obligations.get(name), verified_hashes):
        raise AdjudicationError(f"{candidate_id}: obligation {name!r} is not satisfied by hashed evidence")


def _obligation_is_satisfied(raw: Any, verified_hashes: set[str]) -> bool:
    obligation = _mapping(raw)
    refs = {str(item).lower() for item in _sequence(obligation.get("evidence_refs"))}
    return obligation.get("status") == "satisfied" and bool(refs) and refs <= verified_hashes


def _validate_evidence_refs(root: Path, rows: Sequence[Mapping[str, Any]]) -> set[str]:
    hashes: set[str] = set()
    for raw in rows:
        path_text = str(raw.get("path") or "")
        expected = str(raw.get("sha256") or "").lower()
        kind = str(raw.get("kind") or "")
        if not path_text or not kind or not _SHA256.fullmatch(expected):
            raise AdjudicationError("evidence reference requires path, kind, and SHA-256")
        path = _contained_path(root, path_text)
        if not path.is_file():
            raise AdjudicationError(f"evidence artifact is missing: {path_text}")
        actual = sha256_file(path)
        if actual != expected:
            raise AdjudicationError(
                f"evidence hash mismatch for {path_text}: expected {expected}, got {actual}"
            )
        hashes.add(expected)
    return hashes


def _verify_frozen_inputs(root: Path, manifest: Mapping[str, Any]) -> None:
    if int(manifest.get("schema_version") or 0) != SCHEMA_VERSION:
        raise AdjudicationError("unsupported or missing adjudication frozen-manifest schema")
    for raw in _mapping_rows(manifest.get("inputs")):
        for path_key, hash_key in (
            ("binary_path", "binary_sha256"),
            ("candidate_states_path", "candidate_states_sha256"),
            ("export_manifest_path", "export_manifest_sha256"),
        ):
            path = _contained_path(root, str(raw.get(path_key) or ""))
            expected = str(raw.get(hash_key) or "")
            if not path.is_file() or sha256_file(path) != expected:
                raise AdjudicationError(f"frozen input changed: {raw.get(path_key)}")
    for raw in _mapping_rows(manifest.get("tool_hashes")):
        path = _contained_path(root, str(raw.get("path") or ""))
        if not path.is_file() or sha256_file(path) != str(raw.get("sha256") or ""):
            raise AdjudicationError(f"frozen tool input changed: {raw.get('path')}")
    input_hashes = {
        str(item.get("binary") or ""): str(item.get("binary_sha256") or "")
        for item in _mapping_rows(manifest.get("inputs"))
    }
    for raw in _mapping_rows(manifest.get("reference_build_mappings")):
        name = str(raw.get("binary") or "")
        path = _contained_path(root, str(raw.get("path") or ""))
        if not path.is_file() or sha256_file(path) != str(raw.get("sha256") or ""):
            raise AdjudicationError(f"frozen reference mapping changed: {raw.get('path')}")
        _validate_reference_build_mapping(
            root,
            _load_json(path),
            expected_name=name,
            expected_binary_sha256=input_hashes.get(name, ""),
        )


def _load_frozen_states(root: Path, manifest: Mapping[str, Any]) -> dict[str, CandidateState]:
    result: dict[str, CandidateState] = {}
    for raw in _mapping_rows(manifest.get("inputs")):
        path = _contained_path(root, str(raw.get("candidate_states_path") or ""))
        for state in load_candidate_states(path):
            if state.candidate_id in result:
                raise AdjudicationError(f"duplicate frozen candidate state: {state.candidate_id}")
            result[state.candidate_id] = state
    return result


def _derive_candidate_states(
    states: Mapping[str, CandidateState],
    decisions: Sequence[Mapping[str, Any]],
    root: Path,
) -> list[dict[str, Any]]:
    decision_by_id = {str(item.get("candidate_id") or ""): item for item in decisions}
    rows: list[dict[str, Any]] = []
    for candidate_id in sorted(states):
        state = states[candidate_id]
        decision = decision_by_id[candidate_id]
        payload = state.to_dict()
        reportable = _decision_reportable(state, decision, root)
        if decision["decision"] == "not_bug":
            payload["status"] = "rejected"
            payload["blockers"] = []
        elif reportable:
            payload["status"] = "report_ready"
            payload["blockers"] = []
        metadata = dict(payload.get("metadata") or {})
        metadata["adjudication"] = {
            "decision": decision["decision"],
            "basis": decision["basis"],
            "decision_sha256": sha256_json(decision),
            "schema_v2_report_gate_passed": reportable,
        }
        payload["metadata"] = metadata
        rows.append(payload)
    return rows


def _decision_reportable(state: CandidateState, decision: Mapping[str, Any], root: Path) -> bool:
    if decision.get("decision") != "bug":
        return False
    gate = _mapping(decision.get("report_gate"))
    proof_path_text = str(gate.get("proof_result_path") or "")
    if not proof_path_text:
        return False
    proof_path = _contained_path(root, proof_path_text)
    if not proof_path.is_file() or sha256_file(proof_path) != str(gate.get("proof_result_sha256") or ""):
        raise AdjudicationError(f"{state.candidate_id}: report-gate proof artifact changed")
    raw = _load_json(proof_path)
    if "proof_results" in raw:
        matches = [
            item
            for item in _mapping_rows(raw.get("proof_results"))
            if str(item.get("candidate_id") or "") == state.candidate_id
        ]
        if len(matches) != 1:
            raise AdjudicationError(f"{state.candidate_id}: report-gate proof result is missing or duplicated")
        raw = matches[0]
    proof = ProofResult.from_dict(raw)
    return proof_result_reportable(state, proof)


def _collect_reportable_reports(
    states: Mapping[str, CandidateState],
    decisions: Sequence[Mapping[str, Any]],
    root: Path,
) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for decision in decisions:
        candidate_id = str(decision.get("candidate_id") or "")
        if not _decision_reportable(states[candidate_id], decision, root):
            continue
        gate = _mapping(decision.get("report_gate"))
        report_path_text = str(gate.get("report_path") or "")
        if not report_path_text:
            raise AdjudicationError(f"{candidate_id}: reportable bug lacks a schema-v2 report artifact")
        report_path = _contained_path(root, report_path_text)
        if not report_path.is_file() or sha256_file(report_path) != str(gate.get("report_sha256") or ""):
            raise AdjudicationError(f"{candidate_id}: schema-v2 report artifact changed")
        report = _load_json(report_path)
        if int(report.get("schema_version") or 0) != 2:
            raise AdjudicationError(f"{candidate_id}: report artifact is not schema v2")
        if str(report.get("candidate_id") or "") != candidate_id:
            raise AdjudicationError(f"{candidate_id}: report artifact candidate mismatch")
        reports.append(report)
    return sorted(reports, key=lambda item: str(item.get("candidate_id") or ""))


def _ledger_decision(
    decision: Mapping[str, Any],
    candidate: Mapping[str, Any],
    shared: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    allowed = {
        "candidate_id",
        "decision",
        "basis",
        "rationale",
        "binary_operation",
        "source_binding",
        "entry_proof",
        "obligations",
        "evidence_refs",
        "dynamic_proof",
        "finite_enumeration",
        "report_gate",
    }
    payload = {key: decision[key] for key in sorted(allowed) if key in decision}
    payload["binary"] = str(candidate.get("binary") or "")
    payload["vulnerability_type"] = str(candidate.get("vulnerability_type") or "")
    payload["shared_evidence_refs"] = sorted(_mapping_rows(shared), key=_evidence_sort_key)
    return payload


def _build_summary(
    decisions: Sequence[Mapping[str, Any]],
    candidates: Mapping[str, Mapping[str, Any]],
    decision_hash: str,
    ledger_path: Path,
    states_path: Path,
    reports_path: Path,
) -> dict[str, Any]:
    by_decision = Counter(str(item.get("decision") or "") for item in decisions)
    by_binary = Counter(str(item.get("binary") or "") for item in decisions)
    by_type = Counter(str(item.get("vulnerability_type") or "") for item in decisions)
    cross = Counter(
        (
            str(item.get("binary") or ""),
            str(item.get("vulnerability_type") or ""),
            str(item.get("decision") or ""),
        )
        for item in decisions
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": CAMPAIGN_KIND + "_summary",
        "candidate_count": len(candidates),
        "decision_count": len(decisions),
        "unique_candidate_count": len({str(item.get("candidate_id") or "") for item in decisions}),
        "decision_set_sha256": decision_hash,
        "counts_by_decision": dict(sorted(by_decision.items())),
        "counts_by_binary": dict(sorted(by_binary.items())),
        "counts_by_vulnerability_type": dict(sorted(by_type.items())),
        "counts_by_binary_type_decision": [
            {"binary": key[0], "vulnerability_type": key[1], "decision": key[2], "count": value}
            for key, value in sorted(cross.items())
        ],
        "artifacts": {
            "ledger": {"path": ledger_path.name, "sha256": sha256_file(ledger_path)},
            "derived_candidate_states": {
                "path": str(states_path.relative_to(ledger_path.parent)),
                "sha256": sha256_file(states_path),
            },
            "reports": {
                "path": str(reports_path.relative_to(ledger_path.parent)),
                "sha256": sha256_file(reports_path),
            },
        },
    }


def _freeze_tool_hashes(root: Path, paths: Sequence[Path]) -> list[dict[str, str]]:
    destination = root / "frozen" / "tools"
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, source in enumerate(Path(path).resolve() for path in paths):
        if not source.is_file():
            raise AdjudicationError(f"tool input is missing: {source}")
        name = f"{index:02d}-{_safe_name(source.name)}"
        if name in seen:
            raise AdjudicationError(f"duplicate frozen tool name: {name}")
        seen.add(name)
        target = destination / name
        _copy_exact(source, target)
        rows.append({"path": _relative(root, target), "sha256": sha256_file(target)})
    return rows


def _freeze_reference_mappings(
    root: Path,
    paths: Mapping[str, Path],
    *,
    inputs: Sequence[Mapping[str, Any]],
) -> list[dict[str, str]]:
    if not paths:
        return []
    expected = {str(item.get("binary") or "") for item in inputs}
    if set(paths) != expected:
        raise AdjudicationError(
            "reference mapping target set mismatch: "
            f"expected {sorted(expected)}, got {sorted(paths)}"
        )
    expected_hashes = {
        str(item.get("binary") or ""): str(item.get("binary_sha256") or "")
        for item in inputs
    }
    rows: list[dict[str, str]] = []
    for name in sorted(paths):
        source = Path(paths[name]).resolve()
        mapping = _load_json(source)
        _validate_reference_build_mapping(
            root,
            mapping,
            expected_name=name,
            expected_binary_sha256=expected_hashes[name],
        )
        destination = root / "frozen" / "reference_build_mappings" / f"{_safe_name(name)}.json"
        _copy_exact(source, destination)
        rows.append(
            {
                "binary": name,
                "path": _relative(root, destination),
                "sha256": sha256_file(destination),
            }
        )
    return rows


def _validate_reference_build_mapping(
    root: Path,
    mapping: Mapping[str, Any],
    *,
    expected_name: str,
    expected_binary_sha256: str,
) -> None:
    if int(mapping.get("schema_version") or 0) != SCHEMA_VERSION:
        raise AdjudicationError(f"{expected_name} reference mapping has the wrong schema")
    if str(mapping.get("binary") or "") != expected_name:
        raise AdjudicationError(f"{expected_name} reference mapping names another binary")
    sdk = _mapping(mapping.get("sdk"))
    sdk_path = _contained_path(root, str(sdk.get("path") or ""))
    if not sdk_path.is_file() or sha256_file(sdk_path) != str(sdk.get("sha256") or ""):
        raise AdjudicationError(f"{expected_name} reference mapping SDK artifact changed")
    if str(sdk.get("sha256") or "") != OPENWRT_24_10_4_X86_64_SDK_SHA256:
        raise AdjudicationError(f"{expected_name} reference mapping uses the wrong SDK")

    source = _mapping(mapping.get("source"))
    source_path = _contained_path(root, str(source.get("path") or ""))
    if not source_path.is_dir() or _git_head(source_path) != str(source.get("commit") or ""):
        raise AdjudicationError(f"{expected_name} reference source checkout changed")

    frozen = _mapping(mapping.get("frozen_binary"))
    reference = _mapping(mapping.get("reference_binary"))
    frozen_path = _contained_path(root, str(frozen.get("path") or ""))
    reference_path = _contained_path(root, str(reference.get("path") or ""))
    if not frozen_path.is_file() or sha256_file(frozen_path) != str(frozen.get("sha256") or ""):
        raise AdjudicationError(f"{expected_name} mapped frozen binary changed")
    if str(frozen.get("sha256") or "") != expected_binary_sha256:
        raise AdjudicationError(f"{expected_name} reference mapping targets another frozen binary")
    if not reference_path.is_file() or sha256_file(reference_path) != str(
        reference.get("sha256") or ""
    ):
        raise AdjudicationError(f"{expected_name} reference binary changed")
    actual_frozen_code = executable_segment_fingerprint(frozen_path)
    actual_reference_code = executable_segment_fingerprint(reference_path)
    if actual_frozen_code != _mapping(frozen.get("executable_segments")):
        raise AdjudicationError(f"{expected_name} frozen executable-segment fingerprint changed")
    if actual_reference_code != _mapping(reference.get("executable_segments")):
        raise AdjudicationError(f"{expected_name} reference executable-segment fingerprint changed")
    match = actual_frozen_code == actual_reference_code
    if mapping.get("code_bytes_match") is not match:
        raise AdjudicationError(f"{expected_name} reference code-match declaration is inconsistent")
    if mapping.get("direct_source_mapping_allowed") is not match:
        raise AdjudicationError(f"{expected_name} direct-mapping declaration is inconsistent")


def _require_exact_ids(actual: Sequence[str], expected: Sequence[str], *, context: str) -> None:
    counts = Counter(actual)
    duplicates = sorted(key for key, count in counts.items() if count > 1)
    if duplicates:
        raise AdjudicationError(f"{context} contains duplicate candidate IDs: {duplicates}")
    actual_set = set(actual)
    expected_set = set(expected)
    missing = sorted(expected_set - actual_set)
    unknown = sorted(actual_set - expected_set)
    if missing or unknown:
        raise AdjudicationError(f"{context} candidate mismatch; missing={missing}, unknown={unknown}")


def _copy_exact(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file():
        if sha256_file(destination) != sha256_file(source):
            raise AdjudicationError(f"frozen destination already differs: {destination}")
        return
    temporary = destination.with_name(destination.name + ".tmp")
    shutil.copyfile(source, temporary)
    os.replace(temporary, destination)


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _load_json(path: Path) -> dict[str, Any]:
    if not Path(path).is_file():
        raise AdjudicationError(f"JSON artifact is missing: {path}")
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdjudicationError(f"invalid JSON artifact {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise AdjudicationError(f"JSON artifact must be an object: {path}")
    return dict(payload)


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _mapping_rows(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in _sequence(value) if isinstance(item, Mapping)]


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _normalize_address(value: Any) -> str:
    text = str(value or "").strip()
    if not _HEX_ADDRESS.fullmatch(text):
        return ""
    return f"0x{int(text, 16):X}"


def _is_numeric_address(value: Any) -> bool:
    return bool(_HEX_ADDRESS.fullmatch(str(value or "").strip()))


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "artifact"


def _relative(root: Path, path: Path) -> str:
    return str(Path(path).resolve().relative_to(Path(root).resolve()))


def _contained_existing_file(root: Path, path: Path, label: str) -> Path:
    contained = _contained_path(root, str(path))
    if not contained.is_file():
        raise AdjudicationError(f"{label} is missing: {path}")
    return contained


def _contained_existing_directory(root: Path, path: Path, label: str) -> Path:
    contained = _contained_path(root, str(path))
    if not contained.is_dir():
        raise AdjudicationError(f"{label} is missing: {path}")
    return contained


def _contained_path(root: Path, path_text: str) -> Path:
    if not path_text:
        raise AdjudicationError("artifact path is empty")
    path = (root / path_text).resolve() if not Path(path_text).is_absolute() else Path(path_text).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise AdjudicationError(f"artifact escapes campaign root: {path_text}") from exc
    return path


def _git_head(path: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AdjudicationError(f"cannot read source commit at {path}: {exc}") from exc
    commit = result.stdout.strip().lower()
    if not _COMMIT.fullmatch(commit):
        raise AdjudicationError(f"invalid source commit returned at {path}: {commit!r}")
    return commit


def _text_symbol_count(path: Path) -> int:
    try:
        result = subprocess.run(
            ["nm", "-S", "--defined-only", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AdjudicationError(f"cannot inspect reference symbols in {path}: {exc}") from exc
    count = 0
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[-2] in {"T", "t"}:
            count += 1
    return count


def _elf_load_segments(path: Path) -> list[dict[str, Any]]:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise AdjudicationError(f"cannot read ELF {path}: {exc}") from exc
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise AdjudicationError(f"not an ELF file: {path}")
    elf_class = data[4]
    byte_order = data[5]
    if byte_order not in {1, 2}:
        raise AdjudicationError(f"unsupported ELF byte order in {path}")
    endian = "<" if byte_order == 1 else ">"
    try:
        if elf_class == 2:
            header = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
            program_offset, entry_size, entry_count = header[4], header[8], header[9]
            program_format = endian + "IIQQQQQQ"
            expected_size = struct.calcsize(program_format)
        elif elf_class == 1:
            header = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
            program_offset, entry_size, entry_count = header[4], header[8], header[9]
            program_format = endian + "IIIIIIII"
            expected_size = struct.calcsize(program_format)
        else:
            raise AdjudicationError(f"unsupported ELF class in {path}")
    except struct.error as exc:
        raise AdjudicationError(f"truncated ELF header in {path}") from exc
    if entry_size < expected_size or entry_count <= 0:
        raise AdjudicationError(f"ELF has no valid program headers: {path}")

    result: list[dict[str, Any]] = []
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        try:
            values = struct.unpack_from(program_format, data, offset)
        except struct.error as exc:
            raise AdjudicationError(f"truncated ELF program headers in {path}") from exc
        if elf_class == 2:
            segment_type, flags, file_offset, virtual_address, _, file_size, _, _ = values
        else:
            segment_type, file_offset, virtual_address, _, file_size, _, flags, _ = values
        if segment_type != 1:
            continue
        end = file_offset + file_size
        if end > len(data):
            raise AdjudicationError(f"ELF load segment exceeds file bounds: {path}")
        result.append(
            {
                "flags": flags,
                "file_offset": file_offset,
                "virtual_address": virtual_address,
                "data": data[file_offset:end],
            }
        )
    return result


def _evidence_ref(root: Path, path: Path, kind: str) -> dict[str, str]:
    return {"path": _relative(root, path), "sha256": sha256_file(path), "kind": kind}


def _evidence_sort_key(item: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(item.get("path") or ""),
        str(item.get("sha256") or ""),
        str(item.get("kind") or ""),
    )
