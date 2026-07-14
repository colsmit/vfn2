"""Generate checked adjudication certificates and complete review proposals."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from binary_agent.adjudication import AdjudicationError, admit_review
from binary_agent import adjudication_certificates as checker_module
from binary_agent import adjudication_investigation as investigation_module
from binary_agent import adjudication_verifier as verifier_module
from binary_agent.adjudication_investigation import (
    InvestigationProvider,
    run_investigation_stage,
)
from binary_agent.adjudication_certificates import (
    C_DECLARATION_INIT_RULE,
    C_CHECKED_API_OUTPUT_RULE,
    C_ARRAY_OBJECT_RULE,
    C_GUARDED_FIXED_ARRAY_RULE,
    C_HTML_ESCAPE_RULE,
    C_JAIL_ARGV_RULE,
    C_READ_TERMINATOR_RULE,
    C_TYPED_LINK_STORE_RULE,
    C_BOUNDED_WRAPPER_READ_RULE,
    C_MASKED_RING_INDEX_RULE,
    C_TRAILING_ESCAPE_RULE,
    C_MACRO_TYPED_MEMBER_RULE,
    C_BOUNDED_TYPED_BYTE_STORE_RULE,
    C_STRUCT_OUTPUT_INIT_RULE,
    C_FIXED_PATH_EFFECT_RULE,
    C_RETURNED_ALLOCATION_RULE,
    C_COLLECTION_CLEANUP_RULE,
    C_CLIENT_ALLOCATION_RULE,
    C_INTENDED_EXEC_EFFECT_RULE,
    C_INTENDED_PATH_EFFECT_RULE,
    C_STARTUP_ALLOCATION_RULE,
    C_SIZEOF_MEMBER_COPY_RULE,
    C_STRCHR_INPLACE_RULE,
    C_PROCESS_VARS_COPY_RULE,
    C_PROCESS_SPLIT_LIFETIME_RULE,
    C_INITTAB_TAGS_RULE,
    C_URLDECODE_RULE,
    C_SUBSTRING_INDEX_RULE,
    C_STATIC_TABLE_INDEX_RULE,
    C_FIND_IDX_RULE,
    MUSL_ERRNO_RULE,
    C_DIRLIST_FILE_RULE,
    MUSL_GLOB_RULE,
    C_TYPED_MEMBER_RULE,
    LIBUBOX_JSON_ABORT_RULE,
    C_TRUSTED_ALLOC_RULE,
    C_CLIENT_CONTEXT_RULE,
    LIBUBOX_BLOBMSG_VALUE_RULE,
    C_GUARDED_POINTER_RULE,
    C_IMMEDIATE_ASSIGNMENT_RULE,
    C_INPLACE_RULE,
    C_ASSIGNMENT_RULE,
    C_REALLOC_RULE,
    C_VLA_RULE,
    CERTIFICATE_KIND,
    GHIDRA_INDIRECT_RULE,
    GHIDRA_IMPORT_CAST_RULE,
    LIBUBOX_LIST_RULE,
    LIBUBOX_BLOBMSG_INIT_RULE,
    LIBUBOX_CALLOC_INIT_RULE,
    LIBUBOX_FOREACH_INIT_RULE,
    REGISTERED_RULES,
    RULE_BASES,
    RULE_DECISIONS,
    SEMANTIC_INVESTIGATION_RULE,
    X86_CALL_RULE,
    X86_PCODE_CALL_RULE,
    CertificateError,
    CampaignContextIndex,
    RuleNotApplicable,
    check_certificate,
    derive_rule_proof,
)


AUTOPROVE_KIND = "strict_hybrid_binary_adjudication_autoprove"
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class AutoproveResult:
    summary_path: Path
    residual_queue_path: Path
    proven_candidates: int
    residual_candidates: int
    complete_units: int
    admitted_units: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary_path": str(self.summary_path),
            "residual_queue_path": str(self.residual_queue_path),
            "proven_candidates": self.proven_candidates,
            "residual_candidates": self.residual_candidates,
            "complete_units": self.complete_units,
            "admitted_units": self.admitted_units,
        }


def run_autoprove(
    campaign_root: Path,
    *,
    admit: bool = False,
    direct_provider: InvestigationProvider | None = None,
    agent_provider: InvestigationProvider | None = None,
    direct_call_cap: int | None = None,
    agent_call_cap: int | None = None,
) -> AutoproveResult:
    """Run every registered rule and admit only completely certified units."""

    root = Path(campaign_root).resolve()
    manifest_path = root / "frozen_manifest.json"
    context_index = CampaignContextIndex.build(root)
    manifest = context_index.manifest
    autoprove_root = root / "autoprove"
    tool_refs = _freeze_tools(root, autoprove_root)
    run_id = _tool_run_id(tool_refs)
    run_root = autoprove_root / "runs" / run_id
    certificates: dict[str, dict[str, str]] = {}
    proofs: dict[str, Mapping[str, Any]] = {}
    residual_rows: list[dict[str, Any]] = []
    rule_counts: Counter[str] = Counter()

    candidates = sorted(
        _mapping_rows(manifest.get("candidates")),
        key=lambda item: (
            str(item.get("binary") or ""),
            str(item.get("candidate_id") or ""),
        ),
    )
    for candidate in candidates:
        candidate_id = str(candidate.get("candidate_id") or "")
        context = context_index.load(candidate_id)
        attempts: list[dict[str, str]] = []
        selected_rule = ""
        proof: Mapping[str, Any] | None = None
        for rule_id in REGISTERED_RULES:
            try:
                proof = derive_rule_proof(context, rule_id)
                selected_rule = rule_id
                break
            except RuleNotApplicable as exc:
                attempts.append({"rule_id": rule_id, "reason": str(exc)})
        if proof is None:
            residual_rows.append(
                {
                    "candidate_id": candidate_id,
                    "binary": str(candidate.get("binary") or ""),
                    "vulnerability_type": str(candidate.get("vulnerability_type") or ""),
                    "unit_id": _unit_id_for_candidate(manifest, candidate_id),
                    "status": "residual",
                    "attempts": attempts,
                }
            )
            continue

        binding_path = root / "bindings" / f"{candidate_id}.json"
        certificate = {
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": CERTIFICATE_KIND,
            "candidate_id": candidate_id,
            "binary": str(candidate.get("binary") or ""),
            "vulnerability_type": str(candidate.get("vulnerability_type") or ""),
            "decision": RULE_DECISIONS[selected_rule],
            "basis": RULE_BASES[selected_rule],
            "rule_id": selected_rule,
            "frozen_manifest": {
                "path": "frozen_manifest.json",
                "sha256": _sha256_file(manifest_path),
            },
            "prepared_binding": {
                "path": str(binding_path.relative_to(root)),
                "sha256": _sha256_file(binding_path),
                "address": str(context.binding.get("address") or ""),
                "pcode": str(context.binding.get("pcode") or ""),
            },
            "tools": tool_refs,
            "proof": proof,
        }
        certificate_path = run_root / "certificates" / f"{candidate_id}.json"
        _write_exact_json(certificate_path, certificate)
        check_certificate(root, certificate_path, _context=context)
        certificate_hash = _sha256_file(certificate_path)
        certificates[candidate_id] = {
            "path": str(certificate_path.relative_to(root)),
            "sha256": certificate_hash,
            "kind": {
                "source_proves_safety": "source_review",
                "intentional_no_boundary": "trust_boundary_review",
                "verified_modeling_error": "analyzer_model_refutation",
                "exact_source_feasible_violation": "source_review",
            }[RULE_BASES[selected_rule]],
            "rule_id": selected_rule,
        }
        proofs[candidate_id] = proof
        rule_counts[selected_rule] += 1

    investigation_summary: Mapping[str, Any] = {}
    residual_ids = [str(row.get("candidate_id") or "") for row in residual_rows]
    if residual_ids:
        stage = run_investigation_stage(
            root,
            direct_provider=direct_provider,
            agent_provider=agent_provider,
            output_dir=run_root / "investigation",
            candidate_ids=residual_ids,
            direct_call_cap=direct_call_cap,
            agent_call_cap=agent_call_cap,
            _context_index=context_index,
        )
        investigation_summary = {
            **stage.to_dict(),
            "summary_path": str(stage.summary_path.relative_to(root)),
            "summary_sha256": _sha256_file(stage.summary_path),
        }
        for candidate_id, reference in stage.verified.items():
            context = context_index.load(candidate_id)
            verified_path = root / str(reference.get("verified_path") or "")
            verified_payload = _load_json(verified_path)
            proof = _mapping(verified_payload.get("proof"))
            binding_path = root / "bindings" / f"{candidate_id}.json"
            certificate = {
                "schema_version": SCHEMA_VERSION,
                "artifact_kind": CERTIFICATE_KIND,
                "candidate_id": candidate_id,
                "binary": str(context.candidate.get("binary") or ""),
                "vulnerability_type": str(context.candidate.get("vulnerability_type") or ""),
                "decision": str(reference.get("decision") or ""),
                "basis": str(reference.get("basis") or ""),
                "rule_id": SEMANTIC_INVESTIGATION_RULE,
                "frozen_manifest": {
                    "path": "frozen_manifest.json",
                    "sha256": _sha256_file(manifest_path),
                },
                "prepared_binding": {
                    "path": str(binding_path.relative_to(root)),
                    "sha256": _sha256_file(binding_path),
                    "address": str(context.binding.get("address") or ""),
                    "pcode": str(context.binding.get("pcode") or ""),
                },
                "tools": tool_refs,
                "investigation": {
                    "pack": {
                        "path": str(reference.get("pack_path") or ""),
                        "sha256": str(reference.get("pack_sha256") or ""),
                    },
                    "proposal": {
                        "path": str(reference.get("proposal_path") or ""),
                        "sha256": str(reference.get("proposal_sha256") or ""),
                    },
                    "verified": {
                        "path": str(reference.get("verified_path") or ""),
                        "sha256": str(reference.get("verified_sha256") or ""),
                    },
                },
                "proof": proof,
            }
            certificate_path = run_root / "certificates" / f"{candidate_id}.json"
            _write_exact_json(certificate_path, certificate)
            check_certificate(root, certificate_path, _context=context)
            certificate_hash = _sha256_file(certificate_path)
            certificates[candidate_id] = {
                "path": str(certificate_path.relative_to(root)),
                "sha256": certificate_hash,
                "kind": {
                    "exact_source_feasible_violation": "source_review",
                    "source_proves_safety": "source_review",
                    "cfg_smt_path_infeasible": "cfg_smt_proof",
                    "verified_modeling_error": "analyzer_model_refutation",
                    "intentional_no_boundary": "trust_boundary_review",
                    "unreachable_all_entries": "reachability_proof",
                    "exhaustive_finite_dynamic": "finite_enumeration",
                }[str(reference.get("basis") or "")],
                "rule_id": SEMANTIC_INVESTIGATION_RULE,
            }
            proofs[candidate_id] = proof
            rule_counts[SEMANTIC_INVESTIGATION_RULE] += 1
        unresolved = set(stage.residual_candidate_ids)
        residual_rows = [
            {**row, "investigation_status": "residual"}
            for row in residual_rows
            if str(row.get("candidate_id") or "") in unresolved
        ]

    residual_queue = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": AUTOPROVE_KIND + "_residual_queue",
        "frozen_manifest_sha256": _sha256_file(manifest_path),
        "registered_rules": list(REGISTERED_RULES),
        "candidate_count": len(candidates),
        "proven_count": len(certificates),
        "residual_count": len(residual_rows),
        "residual_candidates": residual_rows,
        "investigation": investigation_summary,
    }
    residual_path = run_root / "residual_queue.json"
    _atomic_json(residual_path, residual_queue)

    complete_units = 0
    admitted_units = 0
    partial_units = 0
    proposal_refs: list[dict[str, Any]] = []
    for unit in _mapping_rows(manifest.get("review_units")):
        unit_id = str(unit.get("unit_id") or "")
        ids = [str(item) for item in _sequence(unit.get("candidate_ids"))]
        covered = [candidate_id for candidate_id in ids if candidate_id in certificates]
        if covered and len(covered) != len(ids):
            partial_units += 1
        if len(covered) != len(ids):
            continue
        complete_units += 1
        decisions = [
            _decision_for_certificate(
                root,
                candidate_id,
                certificates[candidate_id],
                proofs[candidate_id],
            )
            for candidate_id in ids
        ]
        proposal = {
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": "strict_hybrid_binary_adjudication_review",
            "unit_id": unit_id,
            "shared_evidence_refs": [],
            "decisions": sorted(decisions, key=lambda item: item["candidate_id"]),
        }
        proposal_path = run_root / "review_proposals" / f"{unit_id}.json"
        _write_exact_json(proposal_path, proposal)
        proposal_ref = {
            "unit_id": unit_id,
            "path": str(proposal_path.relative_to(root)),
            "sha256": _sha256_file(proposal_path),
            "candidate_count": len(ids),
            "admitted": False,
        }
        if admit:
            admitted_path = root / "reviews" / f"{unit_id}.json"
            if admitted_path.exists():
                proposal_ref["admission_status"] = "preserved_existing_review"
            else:
                admit_review(root, proposal_path)
                admitted_units += 1
                proposal_ref["admitted"] = True
                proposal_ref["admission_status"] = "admitted"
                proposal_ref["admitted_sha256"] = _sha256_file(admitted_path)
        proposal_refs.append(proposal_ref)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": AUTOPROVE_KIND + "_summary",
        "run_id": run_id,
        "frozen_manifest": {
            "path": "frozen_manifest.json",
            "sha256": _sha256_file(manifest_path),
        },
        "tools": tool_refs,
        "candidate_count": len(candidates),
        "proven_candidate_count": len(certificates),
        "residual_candidate_count": len(residual_rows),
        "counts_by_rule": dict(sorted(rule_counts.items())),
        "review_unit_count": len(_mapping_rows(manifest.get("review_units"))),
        "complete_unit_count": complete_units,
        "partial_unit_count": partial_units,
        "admitted_unit_count": admitted_units,
        "certificates": [
            {"candidate_id": candidate_id, **certificates[candidate_id]}
            for candidate_id in sorted(certificates)
        ],
        "review_proposals": proposal_refs,
        "residual_queue": {
            "path": str(residual_path.relative_to(root)),
            "sha256": _sha256_file(residual_path),
        },
        "investigation": investigation_summary,
    }
    summary_path = autoprove_root / "summary.json"
    _atomic_json(summary_path, summary)
    return AutoproveResult(
        summary_path=summary_path,
        residual_queue_path=residual_path,
        proven_candidates=len(certificates),
        residual_candidates=len(residual_rows),
        complete_units=complete_units,
        admitted_units=admitted_units,
    )


def check_all_certificates(campaign_root: Path) -> dict[str, Any]:
    """Check certificate bytes and the exhaustive proven/residual partition."""

    root = Path(campaign_root).resolve()
    manifest_path = root / "frozen_manifest.json"
    manifest = _load_json(manifest_path)
    summary = _load_json(root / "autoprove" / "summary.json")
    if int(summary.get("schema_version") or 0) != SCHEMA_VERSION:
        raise CertificateError("autoprove summary has the wrong schema version")
    if str(summary.get("artifact_kind") or "") != AUTOPROVE_KIND + "_summary":
        raise CertificateError("artifact is not an autoprove summary")

    manifest_ref = _mapping(summary.get("frozen_manifest"))
    referenced_manifest = _contained_file(
        root,
        str(manifest_ref.get("path") or ""),
        "summary frozen manifest",
    )
    if referenced_manifest != manifest_path.resolve():
        raise CertificateError("autoprove summary references another frozen manifest")
    if _sha256_file(referenced_manifest) != str(manifest_ref.get("sha256") or ""):
        raise CertificateError("autoprove summary frozen-manifest hash changed")

    tools = _mapping(summary.get("tools"))
    tool_hashes: dict[str, str] = {}
    for label, live_path in _live_tool_paths().items():
        reference = _mapping(tools.get(label))
        frozen_tool = _contained_file(
            root,
            str(reference.get("path") or ""),
            f"summary {label}",
        )
        expected_hash = str(reference.get("sha256") or "")
        if _sha256_file(frozen_tool) != expected_hash:
            raise CertificateError(f"autoprove summary {label} hash changed")
        if _sha256_file(live_path) != expected_hash:
            raise CertificateError(f"running {label} differs from the autoprove summary")
        tool_hashes[label] = expected_hash
    expected_run_id = _tool_run_id(
        {label: {"sha256": digest} for label, digest in tool_hashes.items()}
    )
    if str(summary.get("run_id") or "") != expected_run_id:
        raise CertificateError("autoprove summary run ID does not match its tools")

    context_index = CampaignContextIndex.build(root)
    certificate_rows = _mapping_rows(summary.get("certificates"))
    certificate_ids = [str(item.get("candidate_id") or "") for item in certificate_rows]
    if len(certificate_ids) != len(set(certificate_ids)):
        raise CertificateError("autoprove summary contains duplicate certificate IDs")
    checked: list[dict[str, Any]] = []
    for reference in sorted(
        certificate_rows,
        key=lambda item: context_index.sort_key(str(item.get("candidate_id") or "")),
    ):
        certificate_path = _contained_file(
            root,
            str(reference.get("path") or ""),
            "summary certificate",
        )
        if _sha256_file(certificate_path) != str(reference.get("sha256") or ""):
            raise CertificateError("autoprove summary certificate hash changed")
        candidate_id = str(reference.get("candidate_id") or "")
        certificate = check_certificate(
            root,
            certificate_path,
            _context=context_index.load(candidate_id),
        )
        if str(certificate.get("candidate_id") or "") != str(
            reference.get("candidate_id") or ""
        ):
            raise CertificateError("summary certificate candidate ID changed")
        if str(certificate.get("rule_id") or "") != str(reference.get("rule_id") or ""):
            raise CertificateError("summary certificate rule changed")
        checked.append(certificate)

    residual_ref = _mapping(summary.get("residual_queue"))
    residual_path = _contained_file(
        root,
        str(residual_ref.get("path") or ""),
        "summary residual queue",
    )
    if _sha256_file(residual_path) != str(residual_ref.get("sha256") or ""):
        raise CertificateError("autoprove summary residual-queue hash changed")
    residual = _load_json(residual_path)
    if str(residual.get("artifact_kind") or "") != AUTOPROVE_KIND + "_residual_queue":
        raise CertificateError("artifact is not an autoprove residual queue")
    if str(residual.get("frozen_manifest_sha256") or "") != _sha256_file(manifest_path):
        raise CertificateError("residual queue references another frozen manifest")
    if residual.get("registered_rules") != list(REGISTERED_RULES):
        raise CertificateError("residual queue rule registry changed")
    residual_rows = _mapping_rows(residual.get("residual_candidates"))
    residual_ids = [str(item.get("candidate_id") or "") for item in residual_rows]
    if len(residual_ids) != len(set(residual_ids)):
        raise CertificateError("residual queue contains duplicate candidate IDs")

    frozen_ids = {
        str(item.get("candidate_id") or "")
        for item in _mapping_rows(manifest.get("candidates"))
    }
    proven_ids = set(certificate_ids)
    queued_ids = set(residual_ids)
    if proven_ids & queued_ids:
        raise CertificateError("a candidate is both certified and residual")
    if proven_ids | queued_ids != frozen_ids:
        missing = sorted(frozen_ids - proven_ids - queued_ids)
        unknown = sorted((proven_ids | queued_ids) - frozen_ids)
        raise CertificateError(
            f"autoprove partition mismatch: missing={missing}, unknown={unknown}"
        )
    if _integer_field(summary, "candidate_count") != len(frozen_ids):
        raise CertificateError("autoprove summary candidate count changed")
    if _integer_field(summary, "proven_candidate_count") != len(proven_ids):
        raise CertificateError("autoprove summary proven count changed")
    if _integer_field(summary, "residual_candidate_count") != len(queued_ids):
        raise CertificateError("autoprove summary residual count changed")
    if _integer_field(residual, "candidate_count") != len(frozen_ids):
        raise CertificateError("residual queue candidate count changed")
    if _integer_field(residual, "proven_count") != len(proven_ids):
        raise CertificateError("residual queue proven count changed")
    if _integer_field(residual, "residual_count") != len(queued_ids):
        raise CertificateError("residual queue residual count changed")

    counts = Counter(str(item.get("rule_id") or "") for item in checked)
    expected_counts = dict(sorted(counts.items()))
    if _mapping(summary.get("counts_by_rule")) != expected_counts:
        raise CertificateError("autoprove summary rule counts changed")
    return {
        "checked_certificate_count": len(checked),
        "residual_candidate_count": len(residual_ids),
        "partition_candidate_count": len(frozen_ids),
        "counts_by_rule": expected_counts,
    }


def _decision_for_certificate(
    root: Path,
    candidate_id: str,
    certificate_ref: Mapping[str, str],
    proof: Mapping[str, Any],
) -> dict[str, Any]:
    binding_path = root / "bindings" / f"{candidate_id}.json"
    binding = _load_json(binding_path)
    binding_ref = {
        "path": str(binding_path.relative_to(root)),
        "sha256": _sha256_file(binding_path),
        "kind": "exact_binary_operation",
    }
    evidence_hash = str(certificate_ref["sha256"])
    claims = _mapping(proof.get("claims"))
    obligations = {
        name: {"status": "satisfied", "evidence_refs": [evidence_hash]}
        for name, satisfied in sorted(claims.items())
        if satisfied is True
    }
    rule_id = str(certificate_ref.get("rule_id") or "")
    certificate = _load_json(root / str(certificate_ref.get("path") or ""))
    basis = (
        str(certificate.get("basis") or "")
        if rule_id == SEMANTIC_INVESTIGATION_RULE
        else RULE_BASES.get(rule_id)
    )
    if not basis:
        raise CertificateError(f"no registered basis for rule {rule_id!r}")
    evidence_refs: list[dict[str, str]] = [binding_ref, dict(certificate_ref)]
    source_binding: Mapping[str, Any] | None = None
    if basis in {
        "source_proves_safety",
        "intentional_no_boundary",
        "exact_source_feasible_violation",
    }:
        source_binding = _mapping(proof.get("source_binding"))
        if rule_id == SEMANTIC_INVESTIGATION_RULE:
            investigation = _mapping(certificate.get("investigation"))
            pack_ref = _mapping(investigation.get("pack"))
            proposal_ref = _mapping(investigation.get("proposal"))
            verified_ref = _mapping(investigation.get("verified"))
            pack = _load_json(root / str(pack_ref.get("path") or ""))
            source_binding = _mapping(_mapping(pack.get("source_context")).get("binding"))
            for kind, reference in (
                ("investigation_pack", pack_ref),
                ("untrusted_investigation_proposal", proposal_ref),
                ("verified_semantic_investigation", verified_ref),
            ):
                evidence_refs.append(
                    {
                        "path": str(reference.get("path") or ""),
                        "sha256": str(reference.get("sha256") or ""),
                        "kind": kind,
                    }
                )
            verified_payload = _load_json(root / str(verified_ref.get("path") or ""))
            evidence_refs.extend(_mapping_rows(verified_payload.get("evidence_refs")))
        source_path = root / str(source_binding.get("source_path") or "")
        source_ref = {
            "path": str(source_binding.get("source_path") or ""),
            "sha256": _sha256_file(source_path),
            "kind": "source_review",
        }
        if source_ref["sha256"] != str(source_binding.get("source_sha256") or ""):
            raise CertificateError("source proof hash changed while rendering a decision")
        evidence_refs.append(source_ref)
        for additional in _mapping_rows(proof.get("additional_source_refs")):
            additional_path = root / str(additional.get("path") or "")
            additional_ref = {
                "path": str(additional.get("path") or ""),
                "sha256": _sha256_file(additional_path),
                "kind": "source_review",
            }
            if additional_ref["sha256"] != str(additional.get("sha256") or ""):
                raise CertificateError("additional source proof hash changed")
            evidence_refs.append(additional_ref)
    if rule_id == SEMANTIC_INVESTIGATION_RULE:
        claim = str(proof.get("rule_claim") or "the exact operation satisfies the checked semantic relation")
        rationale = (
            "A deterministic semantic verifier re-derived the exact source and binary path: "
            + claim.rstrip(".")
            + ". Provider output is retained only as an untrusted proposal."
        )
    elif rule_id == X86_CALL_RULE:
        rationale = (
            "Frozen machine bytes decode as an x86 CALL whose architectural push stores "
            "the exact successor in a newly reserved eight-byte return slot; the alleged "
            "decompiler array is therefore not the STORE object."
        )
    elif rule_id == X86_PCODE_CALL_RULE:
        rationale = (
            "The exact frozen instruction is an x86 CALL, so its only STORE is the implicit "
            "eight-byte return-slot push; the candidate's selected C object is not written."
        )
    elif rule_id == LIBUBOX_LIST_RULE:
        rationale = (
            "Byte-identical reference DWARF binds the exact STORE to a pointer-width field "
            "assignment in the two-pointer libubox list_head type; the decompiler-selected "
            "object and capacity are therefore a modeling error."
        )
    elif rule_id == GHIDRA_INDIRECT_RULE:
        rationale = (
            "The selected high-p-code INDIRECT is a Ghidra call-effect annotation attached "
            "to the exact frozen CALL, not a runtime read of the candidate local."
        )
    elif rule_id == GHIDRA_IMPORT_CAST_RULE:
        rationale = (
            "The selected CAST loads a frozen dynamic relocation for an imported function and "
            "feeds it directly to CALLIND; it does not read the alleged uninitialized local."
        )
    elif rule_id == C_VLA_RULE:
        rationale = (
            "Exact byte-matched source declares an N+1-byte VLA and writes its terminator at "
            "index N under the positive-size branch, proving the STORE remains in bounds."
        )
    elif rule_id == C_INPLACE_RULE:
        rationale = (
            "Exact byte-matched source writes only after the loop condition reads a present "
            "non-NUL byte at the same index in the duplicated string, proving the byte in bounds."
        )
    elif rule_id == C_REALLOC_RULE:
        rationale = (
            "Exact byte-matched source shows the STORE targets a static pointer assigned from "
            "realloc, refuting the candidate's claimed stack object and stack-overflow semantics."
        )
    elif rule_id == LIBUBOX_BLOBMSG_INIT_RULE:
        rationale = (
            "Exact caller source passes the complete local table to pinned libubox "
            "blobmsg_parse, whose first statement zero-initializes every slot before any return."
        )
    elif rule_id == C_ASSIGNMENT_RULE:
        rationale = (
            "Exact byte-matched source unconditionally assigns the local before a terminating "
            "false-path guard, so every path reaching the selected use carries an initialized value."
        )
    elif rule_id == C_IMMEDIATE_ASSIGNMENT_RULE:
        rationale = (
            "Exact byte-matched source unconditionally assigns the local in the immediately "
            "preceding statement, so every path reaching the selected use has initialized it."
        )
    elif rule_id == C_DECLARATION_INIT_RULE:
        rationale = (
            "The exact initialization COPY is bound to a literal declaration initializer, "
            "which defines the local as it enters scope."
        )
    elif rule_id == LIBUBOX_CALLOC_INIT_RULE:
        rationale = (
            "Exact caller source returns on calloc_a failure, while the pinned libubox success "
            "path assigns every auxiliary output pointer before the selected use."
        )
    elif rule_id == LIBUBOX_FOREACH_INIT_RULE:
        rationale = (
            "The exact source invokes a pinned libubox foreach macro whose for initializer "
            "defines both the cursor and remaining-byte counter before the selected update."
        )
    elif rule_id == C_CHECKED_API_OUTPUT_RULE:
        rationale = (
            "Exact source reaches the selected output-object use only after stat/glob reports "
            "success; all failure paths return, break, or jump past the use."
        )
    elif rule_id == C_GUARDED_POINTER_RULE:
        rationale = (
            "An exact source guard dominates the selected pointer dereference and terminates or "
            "leaves the path whenever that pointer is null."
        )
    elif rule_id == C_ARRAY_OBJECT_RULE:
        rationale = (
            "The exact LOAD/STORE is based on a declared stack/static array or string literal, "
            "whose language-level object address cannot be null."
        )
    elif rule_id == C_READ_TERMINATOR_RULE:
        rationale = (
            "The exact terminator STORE uses a positive read count bounded by the N-1 request, "
            "so its one-byte write remains within the N-byte local array."
        )
    elif rule_id == C_TYPED_LINK_STORE_RULE:
        rationale = (
            "The exact pointer-width STORE updates a pointer-to-pointer cursor initialized to a "
            "typed head field and advanced only to same-type next fields."
        )
    elif rule_id == C_BOUNDED_WRAPPER_READ_RULE:
        rationale = (
            "The pinned read wrapper returns no more than its capacity-minus-one request, and the "
            "exact one-byte terminator STORE occurs only on its nonnegative result path."
        )
    elif rule_id == C_MASKED_RING_INDEX_RULE:
        rationale = (
            "The exact pointer STORE uses a static-zero index whose only update masks it into the "
            "declared power-of-two array range."
        )
    elif rule_id == C_TRAILING_ESCAPE_RULE:
        rationale = (
            "The odd trailing-escape branch implies a positive string length, and both allocation "
            "paths retain at least that complete string before the exact length-minus-one STORE."
        )
    elif rule_id == C_MACRO_TYPED_MEMBER_RULE:
        rationale = (
            "The exact STORE's source macro expands to a declared struct member; its fixed-width "
            "scalar or constant in-range pointer-array element fully contains the write."
        )
    elif rule_id == C_BOUNDED_TYPED_BYTE_STORE_RULE:
        rationale = (
            "The exact one-byte STORE indexes a fixed array member through its typed pointer; "
            "zero initialization and the only loop increment guard keep that byte index within "
            "the declared member capacity."
        )
    elif rule_id == C_STRUCT_OUTPUT_INIT_RULE:
        rationale = (
            "A dominating exact call passes the containing stack object to a typed output "
            "parameter whose first unconditional action zeroes the complete compiled struct; "
            "the selected later CALL therefore cannot consume uninitialized bytes."
        )
    elif rule_id == C_GUARDED_FIXED_ARRAY_RULE:
        rationale = (
            "A zero-initialized index and capacity guard dominate the exact fixed-array STORE, "
            "proving the write index is below the declared element count."
        )
    elif rule_id == C_HTML_ESCAPE_RULE:
        rationale = (
            "The exact byte STORE consumes the one-byte budget reserved for that plain input "
            "character by the sizing pass, with a separate byte reserved for termination."
        )
    elif rule_id == C_JAIL_ARGV_RULE:
        rationale = (
            "The caller allocates at least five pointer slots for jail arguments, and the exact "
            "STORE is one of jail_run's first five appends."
        )
    elif rule_id == C_FIXED_PATH_EFFECT_RULE:
        rationale = (
            "The exact open/stat effect uses a compile-time fixed system path for standard I/O, "
            "device-directory scoping, or sandbox-helper discovery, with no input-controlled bytes."
        )
    elif rule_id == C_RETURNED_ALLOCATION_RULE:
        rationale = (
            "The allocating function returns the exact allocation to its caller and retains no "
            "owning reference, establishing an explicit ownership transfer rather than a leak."
        )
    elif rule_id == C_COLLECTION_CLEANUP_RULE:
        rationale = (
            "Exact source transfers the allocation into a managed collection whose registered "
            "removal path removes and frees that allocation."
        )
    elif rule_id == C_CLIENT_ALLOCATION_RULE:
        rationale = (
            "The static pending-client cache is bounded to one allocation; accepted clients move "
            "to the client list and client_close removes and frees each one."
        )
    elif rule_id == C_INTENDED_EXEC_EFFECT_RULE:
        rationale = (
            "The exact call is the component's intended direct-exec boundary for a configured "
            "service, worker, init script, or CGI script; no shell reparses the argv elements."
        )
    elif rule_id == C_INTENDED_PATH_EFFECT_RULE:
        rationale = (
            "The exact open/fopen/freopen stays within its enumerated configuration, device, "
            "upload-file, pidfile, or document-root boundary and performs the intended effect."
        )
    elif rule_id == C_STARTUP_ALLOCATION_RULE:
        rationale = (
            "The allocation enters a collection populated only from finite startup input and "
            "retained for the process lifetime, so no repeatable external action creates an "
            "unbounded sequence of unreleased generations."
        )
    elif rule_id == C_SIZEOF_MEMBER_COPY_RULE:
        rationale = (
            "The exact memcpy length is sizeof the typed destination member, so the copy cannot "
            "extend beyond that member's capacity."
        )
    elif rule_id == C_STRCHR_INPLACE_RULE:
        rationale = (
            "The exact byte STORE replaces a successful strchr match within the fixed source "
            "array, and the null result is excluded by the enclosing guard."
        )
    elif rule_id == C_PROCESS_VARS_COPY_RULE:
        rationale = (
            "The compile-time BUILD_BUG_ON covers the header prefix plus sizeof(extra_vars), "
            "proving the exact memcpy STORE remains within uh_buf."
        )
    elif rule_id == C_INITTAB_TAGS_RULE:
        rationale = (
            "The exact STORE is indexed from TAG_ID through TAG_PROCESS into a TAG_PROCESS+1 "
            "element local array."
        )
    elif rule_id == C_URLDECODE_RULE:
        rationale = (
            "The decoder caps len at blen, and every exact source caller reserves an additional "
            "byte beyond blen for the selected terminator STORE."
        )
    elif rule_id == C_SUBSTRING_INDEX_RULE:
        rationale = (
            "A successful five-byte strstr match makes index five a valid terminator or suffix "
            "byte, and C short-circuit evaluation excludes index six when that byte is NUL."
        )
    elif rule_id == C_STATIC_TABLE_INDEX_RULE:
        rationale = (
            "The exact PTRADD uses a loop index initialized to zero and bounded by ARRAY_SIZE "
            "over the statically initialized handlers table."
        )
    elif rule_id == C_FIND_IDX_RULE:
        rationale = (
            "Every call to the static helper passes a language-level static array, its exact "
            "ARRAY_SIZE, and a string token excluded from the null path."
        )
    elif rule_id == MUSL_ERRNO_RULE:
        rationale = (
            "The exact LOAD is a range-guarded compiler switch-table access to static storage; "
            "the alleged nullable source pointer is absent from the machine operation."
        )
    elif rule_id == C_DIRLIST_FILE_RULE:
        rationale = (
            "The sole caller proves local_path_len is strictly below uh_buf capacity before "
            "deriving file, so the selected one-byte terminator remains inside uh_buf."
        )
    elif rule_id == MUSL_GLOB_RULE:
        rationale = (
            "The SDK-pinned musl implementation initializes gl_pathc and gl_pathv before every "
            "non-append return, including errors, so the selected use is always initialized."
        )
    elif rule_id == C_TYPED_MEMBER_RULE:
        rationale = (
            "The exact four-byte STORE is the declared unsigned member of the sole static "
            "struct progress caller object and cannot exceed that member."
        )
    elif rule_id == LIBUBOX_JSON_ABORT_RULE:
        rationale = (
            "The exact one-byte STORE is the SDK-pinned inline assignment to the bool abort "
            "member of json_script_ctx, refuting the alleged array-write semantics."
        )
    elif rule_id == C_TRUSTED_ALLOC_RULE:
        rationale = (
            "All shipped entries to this bounded allocation site are enumerated privileged "
            "startup or service-control paths, so attacker input crosses no security boundary."
        )
    elif rule_id == C_CLIENT_CONTEXT_RULE:
        rationale = (
            "Every shipped direct or plugin call passes its live client object, and client "
            "allocation is checked before the callbacks that recover that containing object."
        )
    elif rule_id == LIBUBOX_BLOBMSG_VALUE_RULE:
        rationale = (
            "The exact LOAD consumes blobmsg_data from a parser-initialized and explicitly "
            "guarded table slot, not the alleged uninitialized source local."
        )
    elif rule_id == C_PROCESS_SPLIT_LIFETIME_RULE:
        rationale = (
            "Exact source proves the first descriptor operation cannot reach the later one: "
            "they are separated into child and parent processes, or the first path calls a "
            "source-declared non-returning error routine."
        )
    else:
        raise CertificateError(f"no decision rendering for rule {rule_id!r}")
    decision = {
        "candidate_id": candidate_id,
        "decision": (
            str(certificate.get("decision") or "")
            if rule_id == SEMANTIC_INVESTIGATION_RULE
            else RULE_DECISIONS[rule_id]
        ),
        "basis": basis,
        "rationale": rationale,
        "binary_operation": binding,
        "evidence_refs": evidence_refs,
        "obligations": obligations,
    }
    if source_binding is not None:
        decision["source_binding"] = dict(source_binding)
    entry_proof = _mapping(proof.get("entry_proof"))
    if entry_proof:
        decision["entry_proof"] = dict(entry_proof)
    return decision


def _freeze_tools(root: Path, autoprove_root: Path) -> dict[str, dict[str, str]]:
    sources = _live_tool_paths()
    result: dict[str, dict[str, str]] = {}
    for label, source in sources.items():
        digest = _sha256_file(source)
        destination = autoprove_root / "tools" / f"{digest[:16]}-{source.name}"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if _sha256_file(destination) != digest:
                raise CertificateError(f"frozen autoprove {label} differs")
        else:
            temporary = destination.with_name(destination.name + ".tmp")
            shutil.copyfile(source, temporary)
            os.replace(temporary, destination)
        result[label] = {
            "path": str(destination.relative_to(root)),
            "sha256": digest,
        }
    return result


def _live_tool_paths() -> dict[str, Path]:
    return {
        "generator": Path(__file__).resolve(),
        "checker": Path(checker_module.__file__).resolve(),
        "investigation": Path(investigation_module.__file__).resolve(),
        "verifier": Path(verifier_module.__file__).resolve(),
    }


def _tool_run_id(tool_refs: Mapping[str, Mapping[str, str]]) -> str:
    payload = "".join(
        f"{label}:{str(_mapping(reference).get('sha256') or '')};"
        for label, reference in sorted(tool_refs.items())
    )
    return hashlib.sha256(payload.encode("ascii")).hexdigest()[:16]


def _unit_id_for_candidate(manifest: Mapping[str, Any], candidate_id: str) -> str:
    matches = [
        str(unit.get("unit_id") or "")
        for unit in _mapping_rows(manifest.get("review_units"))
        if candidate_id in [str(item) for item in _sequence(unit.get("candidate_ids"))]
    ]
    if len(matches) != 1:
        raise CertificateError(f"candidate {candidate_id} is not in exactly one review unit")
    return matches[0]


def _write_exact_json(path: Path, payload: Any) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if path.exists():
        if path.read_text(encoding="utf-8") != text:
            raise CertificateError(f"immutable autoprove artifact differs: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_text(path, text)


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _atomic_text(path: Path, text: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CertificateError(f"invalid JSON artifact {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise CertificateError(f"JSON artifact must be an object: {path}")
    return dict(payload)


def _contained_file(root: Path, value: Path | str, label: str) -> Path:
    path = Path(value)
    candidate = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise CertificateError(f"{label} escapes the campaign root: {value}") from exc
    if not candidate.is_file():
        raise CertificateError(f"{label} is missing: {value}")
    return candidate


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _integer_field(value: Mapping[str, Any], name: str) -> int:
    raw = value.get(name)
    if isinstance(raw, bool) or not isinstance(raw, int):
        return -1
    return raw


def _mapping_rows(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in _sequence(value) if isinstance(item, Mapping)]


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    return []
