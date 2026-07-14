"""Independent checkers for deterministic adjudication proof certificates.

The autoprove generator is intentionally not trusted.  This module reloads the
frozen campaign, re-derives a registered proof from immutable inputs, and
accepts a certificate only when its complete proof payload matches.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
CERTIFICATE_KIND = "strict_hybrid_binary_adjudication_autoprove_certificate"
X86_CALL_RULE = "x86_call_return_slot_v1"
X86_PCODE_CALL_RULE = "x86_call_pcode_store_v1"
LIBUBOX_LIST_RULE = "libubox_typed_list_store_v1"
GHIDRA_INDIRECT_RULE = "ghidra_indirect_call_effect_v1"
GHIDRA_IMPORT_CAST_RULE = "ghidra_import_pointer_cast_v1"
C_VLA_RULE = "c_vla_index_capacity_v1"
C_INPLACE_RULE = "c_guarded_inplace_byte_store_v1"
C_REALLOC_RULE = "c_realloc_nonstack_object_v1"
LIBUBOX_BLOBMSG_INIT_RULE = "libubox_blobmsg_parse_initializes_table_v1"
C_ASSIGNMENT_RULE = "c_unconditional_assignment_before_use_v1"
C_IMMEDIATE_ASSIGNMENT_RULE = "c_immediate_unconditional_assignment_v1"
C_DECLARATION_INIT_RULE = "c_declaration_initializer_v1"
LIBUBOX_CALLOC_INIT_RULE = "libubox_checked_calloc_a_outputs_v1"
LIBUBOX_FOREACH_INIT_RULE = "libubox_foreach_macro_initializes_v1"
C_CHECKED_API_OUTPUT_RULE = "c_checked_api_output_initialization_v1"
C_GUARDED_POINTER_RULE = "c_dominating_nonnull_guard_v1"
C_ARRAY_OBJECT_RULE = "c_array_object_nonnull_v1"
C_READ_TERMINATOR_RULE = "c_read_terminator_bounds_v1"
C_TYPED_LINK_STORE_RULE = "c_typed_link_pointer_store_v1"
C_BOUNDED_WRAPPER_READ_RULE = "c_bounded_wrapper_read_terminator_v1"
C_MASKED_RING_INDEX_RULE = "c_masked_static_ring_index_v1"
C_TRAILING_ESCAPE_RULE = "c_trailing_escape_terminator_v1"
C_MACRO_TYPED_MEMBER_RULE = "c_macro_typed_member_store_v1"
C_BOUNDED_TYPED_BYTE_STORE_RULE = "c_bounded_typed_byte_array_store_v1"
C_STRUCT_OUTPUT_INIT_RULE = "c_struct_output_memset_initialization_v1"
C_GUARDED_FIXED_ARRAY_RULE = "c_guarded_fixed_array_index_v1"
C_HTML_ESCAPE_RULE = "c_html_escape_capacity_v1"
C_JAIL_ARGV_RULE = "c_jail_argv_capacity_v1"
C_FIXED_PATH_EFFECT_RULE = "c_fixed_path_effect_v1"
C_RETURNED_ALLOCATION_RULE = "c_returned_allocation_ownership_v1"
C_COLLECTION_CLEANUP_RULE = "c_collection_allocation_cleanup_v1"
C_CLIENT_ALLOCATION_RULE = "c_client_allocation_cleanup_v1"
C_INTENDED_EXEC_EFFECT_RULE = "c_intended_exec_effect_v1"
C_INTENDED_PATH_EFFECT_RULE = "c_intended_path_effect_v1"
C_STARTUP_ALLOCATION_RULE = "c_startup_collection_bounded_lifetime_v1"
C_SIZEOF_MEMBER_COPY_RULE = "c_sizeof_member_copy_bounds_v1"
C_STRCHR_INPLACE_RULE = "c_strchr_inplace_store_bounds_v1"
C_PROCESS_VARS_COPY_RULE = "c_process_vars_copy_bounds_v1"
C_INITTAB_TAGS_RULE = "c_inittab_tags_bounds_v1"
C_URLDECODE_RULE = "c_urldecode_caller_capacity_v1"
C_SUBSTRING_INDEX_RULE = "c_substring_suffix_index_bounds_v1"
C_STATIC_TABLE_INDEX_RULE = "c_static_table_loop_initialization_v1"
C_FIND_IDX_RULE = "c_find_idx_caller_contract_v1"
MUSL_ERRNO_RULE = "musl_errno_tls_nonnull_v1"
C_DIRLIST_FILE_RULE = "c_dirlist_caller_capacity_v1"
MUSL_GLOB_RULE = "musl_glob_output_initialization_v1"
C_TYPED_MEMBER_RULE = "c_typed_member_store_bounds_v1"
LIBUBOX_JSON_ABORT_RULE = "libubox_json_script_abort_member_v1"
C_TRUSTED_ALLOC_RULE = "c_bounded_trusted_allocation_v1"
C_CLIENT_CONTEXT_RULE = "c_live_client_context_nonnull_v1"
LIBUBOX_BLOBMSG_VALUE_RULE = "libubox_guarded_blobmsg_value_v1"
C_PROCESS_SPLIT_LIFETIME_RULE = "c_process_split_lifetime_v1"
SEMANTIC_INVESTIGATION_RULE = "semantic_investigation_v1"
REGISTERED_RULES = (
    X86_CALL_RULE,
    X86_PCODE_CALL_RULE,
    LIBUBOX_LIST_RULE,
    GHIDRA_INDIRECT_RULE,
    GHIDRA_IMPORT_CAST_RULE,
    C_VLA_RULE,
    C_INPLACE_RULE,
    C_REALLOC_RULE,
    LIBUBOX_BLOBMSG_INIT_RULE,
    C_ASSIGNMENT_RULE,
    C_IMMEDIATE_ASSIGNMENT_RULE,
    C_DECLARATION_INIT_RULE,
    LIBUBOX_CALLOC_INIT_RULE,
    LIBUBOX_FOREACH_INIT_RULE,
    C_CHECKED_API_OUTPUT_RULE,
    C_GUARDED_POINTER_RULE,
    C_ARRAY_OBJECT_RULE,
    C_READ_TERMINATOR_RULE,
    C_TYPED_LINK_STORE_RULE,
    C_BOUNDED_WRAPPER_READ_RULE,
    C_MASKED_RING_INDEX_RULE,
    C_TRAILING_ESCAPE_RULE,
    C_MACRO_TYPED_MEMBER_RULE,
    C_BOUNDED_TYPED_BYTE_STORE_RULE,
    C_STRUCT_OUTPUT_INIT_RULE,
    C_GUARDED_FIXED_ARRAY_RULE,
    C_HTML_ESCAPE_RULE,
    C_JAIL_ARGV_RULE,
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
    C_PROCESS_SPLIT_LIFETIME_RULE,
)
RULE_BASES = {
    X86_CALL_RULE: "verified_modeling_error",
    X86_PCODE_CALL_RULE: "verified_modeling_error",
    LIBUBOX_LIST_RULE: "verified_modeling_error",
    GHIDRA_INDIRECT_RULE: "verified_modeling_error",
    GHIDRA_IMPORT_CAST_RULE: "verified_modeling_error",
    C_VLA_RULE: "source_proves_safety",
    C_INPLACE_RULE: "source_proves_safety",
    C_REALLOC_RULE: "verified_modeling_error",
    LIBUBOX_BLOBMSG_INIT_RULE: "source_proves_safety",
    C_ASSIGNMENT_RULE: "source_proves_safety",
    C_IMMEDIATE_ASSIGNMENT_RULE: "source_proves_safety",
    C_DECLARATION_INIT_RULE: "source_proves_safety",
    LIBUBOX_CALLOC_INIT_RULE: "source_proves_safety",
    LIBUBOX_FOREACH_INIT_RULE: "source_proves_safety",
    C_CHECKED_API_OUTPUT_RULE: "source_proves_safety",
    C_GUARDED_POINTER_RULE: "source_proves_safety",
    C_ARRAY_OBJECT_RULE: "source_proves_safety",
    C_READ_TERMINATOR_RULE: "source_proves_safety",
    C_TYPED_LINK_STORE_RULE: "source_proves_safety",
    C_BOUNDED_WRAPPER_READ_RULE: "source_proves_safety",
    C_MASKED_RING_INDEX_RULE: "source_proves_safety",
    C_TRAILING_ESCAPE_RULE: "source_proves_safety",
    C_MACRO_TYPED_MEMBER_RULE: "source_proves_safety",
    C_BOUNDED_TYPED_BYTE_STORE_RULE: "source_proves_safety",
    C_STRUCT_OUTPUT_INIT_RULE: "source_proves_safety",
    C_GUARDED_FIXED_ARRAY_RULE: "source_proves_safety",
    C_HTML_ESCAPE_RULE: "source_proves_safety",
    C_JAIL_ARGV_RULE: "source_proves_safety",
    C_FIXED_PATH_EFFECT_RULE: "intentional_no_boundary",
    C_RETURNED_ALLOCATION_RULE: "source_proves_safety",
    C_COLLECTION_CLEANUP_RULE: "source_proves_safety",
    C_CLIENT_ALLOCATION_RULE: "source_proves_safety",
    C_INTENDED_EXEC_EFFECT_RULE: "intentional_no_boundary",
    C_INTENDED_PATH_EFFECT_RULE: "intentional_no_boundary",
    C_STARTUP_ALLOCATION_RULE: "source_proves_safety",
    C_SIZEOF_MEMBER_COPY_RULE: "source_proves_safety",
    C_STRCHR_INPLACE_RULE: "source_proves_safety",
    C_PROCESS_VARS_COPY_RULE: "source_proves_safety",
    C_INITTAB_TAGS_RULE: "source_proves_safety",
    C_URLDECODE_RULE: "source_proves_safety",
    C_SUBSTRING_INDEX_RULE: "source_proves_safety",
    C_STATIC_TABLE_INDEX_RULE: "source_proves_safety",
    C_FIND_IDX_RULE: "source_proves_safety",
    MUSL_ERRNO_RULE: "verified_modeling_error",
    C_DIRLIST_FILE_RULE: "source_proves_safety",
    MUSL_GLOB_RULE: "source_proves_safety",
    C_TYPED_MEMBER_RULE: "source_proves_safety",
    LIBUBOX_JSON_ABORT_RULE: "verified_modeling_error",
    C_TRUSTED_ALLOC_RULE: "intentional_no_boundary",
    C_CLIENT_CONTEXT_RULE: "source_proves_safety",
    LIBUBOX_BLOBMSG_VALUE_RULE: "verified_modeling_error",
    C_PROCESS_SPLIT_LIFETIME_RULE: "source_proves_safety",
}
RULE_DECISIONS = {
    rule_id: (
        "bug"
        if basis == "exact_source_feasible_violation"
        else "not_bug"
    )
    for rule_id, basis in RULE_BASES.items()
}
OPENWRT_24_10_4_X86_64_SDK_SHA256 = (
    "229e871f734a2cee5ce3ad6a3e98d3836b0899bfdeaea4d9c2c5cc7b1fce1407"
)
MUSL_1_2_5_SHA256 = (
    "a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4"
)
SPATIAL_TYPES = frozenset({"stack_overflow", "out_of_bounds_write"})
_RETURN_LITERAL = re.compile(r"=\s*(0x[0-9a-fA-F]+)\s*;?\s*$")
_LOCATION = re.compile(r"^(?P<path>.*):(?P<line>\d+)(?:\s+\(.*\))?$")
_LIST_STATEMENTS = {
    ("_list_add", 107): "next->prev = _new;",
    ("_list_add", 108): "_new->next = next;",
    ("_list_add", 109): "_new->prev = prev;",
    ("_list_add", 110): "prev->next = _new;",
    ("list_del", 99): "entry->next = entry->prev = NULL;",
}


class CertificateError(ValueError):
    """Raised when a certificate or a frozen proof input is inconsistent."""


class RuleNotApplicable(LookupError):
    """Raised when a sound registered proof rule does not cover a candidate."""


@dataclass(frozen=True)
class CampaignContext:
    root: Path
    manifest: Mapping[str, Any]
    candidate: Mapping[str, Any]
    state: Mapping[str, Any]
    binding: Mapping[str, Any]
    input_row: Mapping[str, Any]
    binary_path: Path
    export_manifest: Mapping[str, Any]
    cache: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)
    shared_cache: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


class CampaignContextIndex:
    """Prevalidate and reuse immutable campaign inputs for one batch stage.

    Normalized Ghidra exports can be hundreds of megabytes.  Loading one for
    every candidate made an otherwise deterministic campaign take hours.  The
    index validates every shared frozen input once, parses candidate states
    once, and keeps at most one parsed export active.  Batch callers must group
    work by binary; a new command constructs a fresh index and therefore
    revalidates disk state independently.
    """

    def __init__(
        self,
        *,
        root: Path,
        manifest: Mapping[str, Any],
        candidates: Mapping[str, Mapping[str, Any]],
        inputs: Mapping[str, Mapping[str, Any]],
        states: Mapping[str, Mapping[str, Mapping[str, Any]]],
        binary_paths: Mapping[str, Path],
        export_paths: Mapping[str, Path],
    ) -> None:
        self.root = root
        self.manifest = manifest
        self._candidates = candidates
        self._inputs = inputs
        self._states = states
        self._binary_paths = binary_paths
        self._export_paths = export_paths
        self._active_export_binary = ""
        self._active_export: Mapping[str, Any] | None = None
        self._shared_caches: dict[str, dict[str, Any]] = {}

    @classmethod
    def build(cls, campaign_root: Path) -> "CampaignContextIndex":
        root = Path(campaign_root).resolve()
        manifest_path = root / "frozen_manifest.json"
        manifest = _load_json(manifest_path)

        candidate_rows = _mapping_rows(manifest.get("candidates"))
        candidates = {
            str(item.get("candidate_id") or ""): item
            for item in candidate_rows
            if str(item.get("candidate_id") or "")
        }
        if len(candidates) != len(candidate_rows):
            raise CertificateError("frozen manifest has duplicate or empty candidate IDs")

        input_rows = _mapping_rows(manifest.get("inputs"))
        inputs = {
            str(item.get("binary") or ""): item
            for item in input_rows
            if str(item.get("binary") or "")
        }
        if len(inputs) != len(input_rows):
            raise CertificateError("frozen manifest has duplicate or empty input binaries")

        states: dict[str, Mapping[str, Mapping[str, Any]]] = {}
        binary_paths: dict[str, Path] = {}
        export_paths: dict[str, Path] = {}
        for binary, input_row in inputs.items():
            states_path = _contained_file(
                root,
                str(input_row.get("candidate_states_path") or ""),
                "states",
            )
            if _sha256_file(states_path) != str(input_row.get("candidate_states_sha256") or ""):
                raise CertificateError(f"frozen candidate states changed for {binary}")
            states_payload = _load_json(states_path)
            state_rows = _mapping_rows(states_payload.get("candidate_states"))
            state_index = {
                str(item.get("candidate_id") or ""): item
                for item in state_rows
                if str(item.get("candidate_id") or "")
            }
            if len(state_index) != len(state_rows):
                raise CertificateError(
                    f"frozen candidate states have duplicate or empty IDs for {binary}"
                )
            states[binary] = state_index

            binary_path = _contained_file(
                root,
                str(input_row.get("binary_path") or ""),
                "binary",
            )
            if _sha256_file(binary_path) != str(input_row.get("binary_sha256") or ""):
                raise CertificateError(f"frozen binary changed for {binary}")
            binary_paths[binary] = binary_path

            export_path = _contained_file(
                root,
                str(input_row.get("export_manifest_path") or ""),
                "export manifest",
            )
            if _sha256_file(export_path) != str(input_row.get("export_manifest_sha256") or ""):
                raise CertificateError(f"frozen export manifest changed for {binary}")
            export_paths[binary] = export_path

        for candidate_id, candidate in candidates.items():
            binary = str(candidate.get("binary") or "")
            if binary not in inputs:
                raise CertificateError(f"frozen input row is missing for {binary}")
            if candidate_id not in states[binary]:
                raise CertificateError(f"candidate state is missing for {candidate_id}")

        return cls(
            root=root,
            manifest=manifest,
            candidates=candidates,
            inputs=inputs,
            states=states,
            binary_paths=binary_paths,
            export_paths=export_paths,
        )

    def binary_for_candidate(self, candidate_id: str) -> str:
        candidate = self._candidates.get(candidate_id)
        if candidate is None:
            raise CertificateError(f"unknown frozen candidate: {candidate_id}")
        return str(candidate.get("binary") or "")

    def sort_key(self, candidate_id: str) -> tuple[str, str]:
        return self.binary_for_candidate(candidate_id), candidate_id

    def load(self, candidate_id: str) -> CampaignContext:
        candidate = self._candidates.get(candidate_id)
        if candidate is None:
            raise CertificateError(f"unknown frozen candidate: {candidate_id}")
        binary = str(candidate.get("binary") or "")
        input_row = self._inputs[binary]
        state = self._states[binary].get(candidate_id)
        if state is None:
            raise CertificateError(f"candidate state is missing for {candidate_id}")

        if self._active_export_binary != binary or self._active_export is None:
            self._active_export = _load_json(self._export_paths[binary])
            self._active_export_binary = binary

        binding_path = self.root / "bindings" / f"{candidate_id}.json"
        binding = _load_json(binding_path)
        if str(binding.get("candidate_id") or "") != candidate_id:
            raise CertificateError(f"prepared binding names another candidate: {candidate_id}")
        if str(binding.get("binary") or "") != binary:
            raise CertificateError(f"prepared binding names another binary: {candidate_id}")

        return CampaignContext(
            root=self.root,
            manifest=self.manifest,
            candidate=candidate,
            state=state,
            binding=binding,
            input_row=input_row,
            binary_path=self._binary_paths[binary],
            export_manifest=self._active_export,
            shared_cache=self._shared_caches.setdefault(binary, {}),
        )


def check_certificate(
    campaign_root: Path,
    certificate_path: Path,
    *,
    _context: CampaignContext | None = None,
) -> dict[str, Any]:
    """Recompute and validate one certificate from frozen campaign bytes."""

    root = Path(campaign_root).resolve()
    certificate_file = _contained_file(root, certificate_path, "certificate")
    certificate = _load_json(certificate_file)
    if int(certificate.get("schema_version") or 0) != SCHEMA_VERSION:
        raise CertificateError("certificate has the wrong schema version")
    if str(certificate.get("artifact_kind") or "") != CERTIFICATE_KIND:
        raise CertificateError("artifact is not an autoprove certificate")
    candidate_id = str(certificate.get("candidate_id") or "")
    rule_id = str(certificate.get("rule_id") or "")
    if rule_id not in (*REGISTERED_RULES, SEMANTIC_INVESTIGATION_RULE):
        raise CertificateError(f"unsupported certificate rule: {rule_id!r}")

    context = _context or load_campaign_context(root, candidate_id)
    if context.root != root:
        raise CertificateError("prevalidated context belongs to another campaign")
    if str(context.candidate.get("candidate_id") or "") != candidate_id:
        raise CertificateError("prevalidated context belongs to another candidate")
    _check_manifest_reference(context, certificate)
    _check_tool_references(root, certificate)
    _check_binding_reference(context, certificate)
    if str(certificate.get("binary") or "") != str(context.candidate.get("binary") or ""):
        raise CertificateError("certificate binary does not match the frozen candidate")
    if str(certificate.get("vulnerability_type") or "") != str(
        context.candidate.get("vulnerability_type") or ""
    ):
        raise CertificateError("certificate vulnerability type does not match")
    if rule_id == SEMANTIC_INVESTIGATION_RULE:
        _check_semantic_investigation_certificate(root, certificate)
    else:
        if certificate.get("decision") != RULE_DECISIONS[rule_id]:
            raise CertificateError("certificate decision does not match its registered rule")
        if certificate.get("basis") != RULE_BASES[rule_id]:
            raise CertificateError("certificate basis does not match its registered rule")
        expected = derive_rule_proof(context, rule_id)
        if certificate.get("proof") != expected:
            raise CertificateError("certificate proof payload does not match independent derivation")
    return certificate


def _check_semantic_investigation_certificate(
    root: Path,
    certificate: Mapping[str, Any],
) -> None:
    """Re-run the semantic verifier from the certificate's immutable proposal."""

    from binary_agent.adjudication_verifier import verify_investigation_proposal

    investigation = _mapping(certificate.get("investigation"))
    paths: dict[str, Path] = {}
    for label in ("pack", "proposal", "verified"):
        reference = _mapping(investigation.get(label))
        path = _contained_file(root, str(reference.get("path") or ""), label)
        if _sha256_file(path) != str(reference.get("sha256") or ""):
            raise CertificateError(f"semantic investigation {label} hash changed")
        paths[label] = path
    result = verify_investigation_proposal(root, paths["pack"], paths["proposal"])
    if not result.verified:
        raise CertificateError(
            f"semantic investigation no longer verifies: {result.rejection_reason}"
        )
    expected = json.loads(json.dumps(result.to_dict(), sort_keys=True))
    if _load_json(paths["verified"]) != expected:
        raise CertificateError("verified investigation payload changed")
    if str(certificate.get("candidate_id") or "") != result.candidate_id:
        raise CertificateError("semantic investigation candidate changed")
    if certificate.get("decision") != result.decision:
        raise CertificateError("certificate decision differs from semantic verification")
    if certificate.get("basis") != result.basis:
        raise CertificateError("certificate basis differs from semantic verification")
    if certificate.get("proof") != result.proof:
        raise CertificateError("certificate proof differs from semantic verification")


def load_campaign_context(campaign_root: Path, candidate_id: str) -> CampaignContext:
    """Independently validate disk state and load one candidate context."""

    return CampaignContextIndex.build(campaign_root).load(candidate_id)


def derive_rule_proof(context: CampaignContext, rule_id: str) -> dict[str, Any]:
    if rule_id == X86_CALL_RULE:
        return _derive_x86_call_return_slot(context)
    if rule_id == X86_PCODE_CALL_RULE:
        return _derive_x86_call_pcode_store(context)
    if rule_id == LIBUBOX_LIST_RULE:
        return _derive_libubox_list_store(context)
    if rule_id == GHIDRA_INDIRECT_RULE:
        return _derive_ghidra_indirect_call_effect(context)
    if rule_id == GHIDRA_IMPORT_CAST_RULE:
        return _derive_ghidra_import_pointer_cast(context)
    if rule_id == C_VLA_RULE:
        return _derive_c_vla_index_capacity(context)
    if rule_id == C_INPLACE_RULE:
        return _derive_c_guarded_inplace_store(context)
    if rule_id == C_REALLOC_RULE:
        return _derive_c_realloc_nonstack_object(context)
    if rule_id == LIBUBOX_BLOBMSG_INIT_RULE:
        return _derive_libubox_blobmsg_initialization(context)
    if rule_id == C_ASSIGNMENT_RULE:
        return _derive_c_unconditional_assignment(context)
    if rule_id == C_IMMEDIATE_ASSIGNMENT_RULE:
        return _derive_c_immediate_assignment(context)
    if rule_id == C_DECLARATION_INIT_RULE:
        return _derive_c_declaration_initializer(context)
    if rule_id == LIBUBOX_CALLOC_INIT_RULE:
        return _derive_libubox_checked_calloc_outputs(context)
    if rule_id == LIBUBOX_FOREACH_INIT_RULE:
        return _derive_libubox_foreach_initialization(context)
    if rule_id == C_CHECKED_API_OUTPUT_RULE:
        return _derive_c_checked_api_output(context)
    if rule_id == C_GUARDED_POINTER_RULE:
        return _derive_c_guarded_pointer(context)
    if rule_id == C_ARRAY_OBJECT_RULE:
        return _derive_c_array_object(context)
    if rule_id == C_READ_TERMINATOR_RULE:
        return _derive_c_read_terminator(context)
    if rule_id == C_TYPED_LINK_STORE_RULE:
        return _derive_c_typed_link_store(context)
    if rule_id == C_BOUNDED_WRAPPER_READ_RULE:
        return _derive_c_bounded_wrapper_read(context)
    if rule_id == C_MASKED_RING_INDEX_RULE:
        return _derive_c_masked_ring_index(context)
    if rule_id == C_TRAILING_ESCAPE_RULE:
        return _derive_c_trailing_escape_terminator(context)
    if rule_id == C_MACRO_TYPED_MEMBER_RULE:
        return _derive_c_macro_typed_member(context)
    if rule_id == C_BOUNDED_TYPED_BYTE_STORE_RULE:
        return _derive_c_bounded_typed_byte_store(context)
    if rule_id == C_STRUCT_OUTPUT_INIT_RULE:
        return _derive_c_struct_output_initialization(context)
    if rule_id == C_GUARDED_FIXED_ARRAY_RULE:
        return _derive_c_guarded_fixed_array(context)
    if rule_id == C_HTML_ESCAPE_RULE:
        return _derive_c_html_escape(context)
    if rule_id == C_JAIL_ARGV_RULE:
        return _derive_c_jail_argv(context)
    if rule_id == C_FIXED_PATH_EFFECT_RULE:
        return _derive_c_fixed_path_effect(context)
    if rule_id == C_RETURNED_ALLOCATION_RULE:
        return _derive_c_returned_allocation(context)
    if rule_id == C_COLLECTION_CLEANUP_RULE:
        return _derive_c_collection_cleanup(context)
    if rule_id == C_CLIENT_ALLOCATION_RULE:
        return _derive_c_client_allocation(context)
    if rule_id == C_INTENDED_EXEC_EFFECT_RULE:
        return _derive_c_intended_exec_effect(context)
    if rule_id == C_INTENDED_PATH_EFFECT_RULE:
        return _derive_c_intended_path_effect(context)
    if rule_id == C_STARTUP_ALLOCATION_RULE:
        return _derive_c_startup_allocation(context)
    if rule_id == C_SIZEOF_MEMBER_COPY_RULE:
        return _derive_c_sizeof_member_copy(context)
    if rule_id == C_STRCHR_INPLACE_RULE:
        return _derive_c_strchr_inplace(context)
    if rule_id == C_PROCESS_VARS_COPY_RULE:
        return _derive_c_process_vars_copy(context)
    if rule_id == C_INITTAB_TAGS_RULE:
        return _derive_c_inittab_tags(context)
    if rule_id == C_URLDECODE_RULE:
        return _derive_c_urldecode(context)
    if rule_id == C_SUBSTRING_INDEX_RULE:
        return _derive_c_substring_index(context)
    if rule_id == C_STATIC_TABLE_INDEX_RULE:
        return _derive_c_static_table_index(context)
    if rule_id == C_FIND_IDX_RULE:
        return _derive_c_find_idx(context)
    if rule_id == MUSL_ERRNO_RULE:
        return _derive_musl_errno(context)
    if rule_id == C_DIRLIST_FILE_RULE:
        return _derive_c_dirlist_file(context)
    if rule_id == MUSL_GLOB_RULE:
        return _derive_musl_glob(context)
    if rule_id == C_TYPED_MEMBER_RULE:
        return _derive_c_typed_member(context)
    if rule_id == LIBUBOX_JSON_ABORT_RULE:
        return _derive_libubox_json_abort(context)
    if rule_id == C_TRUSTED_ALLOC_RULE:
        return _derive_c_trusted_allocation(context)
    if rule_id == C_CLIENT_CONTEXT_RULE:
        return _derive_c_client_context(context)
    if rule_id == LIBUBOX_BLOBMSG_VALUE_RULE:
        return _derive_libubox_blobmsg_value(context)
    if rule_id == C_PROCESS_SPLIT_LIFETIME_RULE:
        return _derive_c_process_split_lifetime(context)
    raise RuleNotApplicable(f"unregistered rule {rule_id!r}")


def try_registered_rules(context: CampaignContext) -> tuple[str, dict[str, Any], list[dict[str, str]]]:
    residual: list[dict[str, str]] = []
    for rule_id in REGISTERED_RULES:
        try:
            return rule_id, derive_rule_proof(context, rule_id), residual
        except RuleNotApplicable as exc:
            residual.append({"rule_id": rule_id, "reason": str(exc)})
    raise RuleNotApplicable(json.dumps(residual, sort_keys=True))


def _derive_x86_call_return_slot(context: CampaignContext) -> dict[str, Any]:
    state = context.state
    binding = context.binding
    if str(state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(binding.get("mapping_basis") or "") != "x86_call_return_address_store":
        raise RuleNotApplicable("prepared binding is not an x86 call-return store")
    if str(binding.get("pcode") or "") != "STORE":
        raise CertificateError("x86 call-return binding is not a STORE")
    line_text = str(_mapping(state.get("location")).get("line_text") or "")
    literal_match = _RETURN_LITERAL.search(line_text)
    if literal_match is None:
        raise RuleNotApplicable("decompiler statement has no written successor literal")

    operation_address = _hex_int(binding.get("address"), "operation address")
    vma, file_offset, instruction_bytes = _operation_bytes(context, operation_address, 15)
    instruction_length, encoding_kind = _decode_x86_call(instruction_bytes)
    successor = operation_address + instruction_length
    literal = int(literal_match.group(1), 16)
    if literal != successor:
        raise CertificateError(
            f"written literal {hex(literal)} is not CALL successor {hex(successor)}"
        )
    width = int(binding.get("width_bytes") or 0)
    pointer_width = int(context.export_manifest.get("pointer_size_bytes") or 0)
    if width != 8 or pointer_width != 8:
        raise CertificateError("x86-64 CALL return-slot proof requires an 8-byte STORE")
    processor = str(context.export_manifest.get("processor") or "").lower()
    if processor != "x86":
        raise CertificateError("CALL return-slot rule requires the x86 processor")

    return {
        "rule_claim": "candidate models architectural CALL return-slot semantics as a C array write",
        "instruction": {
            "operation_address": _hex(operation_address),
            "elf_virtual_address": _hex(vma),
            "file_offset": file_offset,
            "encoding": instruction_bytes[:instruction_length].hex(),
            "encoding_kind": encoding_kind,
            "length_bytes": instruction_length,
            "successor_address": _hex(successor),
            "written_literal": _hex(literal),
        },
        "architectural_store": {
            "object_identity": "x86_64_call_return_slot",
            "capacity_bytes": 8,
            "write_width_bytes": width,
            "write_offset_bytes": 0,
            "stack_effect": "RSP is decremented by 8 before the successor address is stored",
        },
        "candidate_object_refuted": str(
            _mapping(state.get("affected_object")).get("identity") or ""
        ),
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "semantics_absent": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
        },
    }


def _derive_x86_call_pcode_store(context: CampaignContext) -> dict[str, Any]:
    state = context.state
    binding = context.binding
    if str(state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(binding.get("pcode") or "") != "STORE":
        raise RuleNotApplicable("prepared operation is not a STORE")
    width = int(binding.get("width_bytes") or 0)
    pointer_width = int(context.export_manifest.get("pointer_size_bytes") or 0)
    if width != 8 or pointer_width != 8:
        raise RuleNotApplicable("operation is not an x86-64 return-slot-width STORE")
    if str(context.export_manifest.get("processor") or "").lower() != "x86":
        raise RuleNotApplicable("candidate is not from an x86 binary")

    operation_address = _hex_int(binding.get("address"), "operation address")
    vma, file_offset, instruction_bytes = _operation_bytes(context, operation_address, 15)
    try:
        instruction_length, encoding_kind = _decode_x86_call(instruction_bytes)
    except CertificateError as exc:
        raise RuleNotApplicable("frozen STORE address is not an x86 CALL") from exc
    successor = operation_address + instruction_length
    return {
        "rule_claim": "the exact p-code STORE is the implicit return-slot effect of an x86 CALL",
        "instruction": {
            "operation_address": _hex(operation_address),
            "elf_virtual_address": _hex(vma),
            "file_offset": file_offset,
            "encoding": instruction_bytes[:instruction_length].hex(),
            "encoding_kind": encoding_kind,
            "length_bytes": instruction_length,
            "successor_address": _hex(successor),
        },
        "architectural_store": {
            "object_identity": "x86_64_call_return_slot",
            "capacity_bytes": 8,
            "write_width_bytes": width,
            "write_offset_bytes": 0,
            "stack_effect": "RSP is decremented by 8 before the successor address is stored",
        },
        "candidate_object_refuted": str(
            _mapping(state.get("affected_object")).get("identity") or ""
        ),
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "semantics_absent": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
        },
    }


def _derive_libubox_list_store(context: CampaignContext) -> dict[str, Any]:
    state = context.state
    binding = context.binding
    if str(state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(binding.get("pcode") or "") != "STORE":
        raise RuleNotApplicable("prepared operation is not a STORE")
    pointer_width = int(context.export_manifest.get("pointer_size_bytes") or 0)
    if pointer_width != 8 or int(binding.get("width_bytes") or 0) != pointer_width:
        raise RuleNotApplicable("operation is not a pointer-width list field STORE")

    mapping = _reference_mapping(context)
    reference_path = _contained_file(
        context.root,
        str(_mapping(mapping.get("reference_binary")).get("path") or ""),
        "reference binary",
    )
    operation_address = _hex_int(binding.get("address"), "operation address")
    operation_mapping = _reference_operation_mapping(context, mapping, operation_address)
    vma = int(operation_mapping["reference_vma"])
    frames = _addr2line_frames(reference_path, vma)
    helper_frame = next(
        (
            frame
            for frame in frames
            if (str(frame.get("function") or ""), int(frame.get("line") or 0))
            in _LIST_STATEMENTS
        ),
        None,
    )
    if helper_frame is None:
        raise RuleNotApplicable("reference DWARF does not map the STORE to a typed list helper")
    source_path = _resolve_campaign_frame_file(
        context.root,
        str(helper_frame.get("path") or ""),
        "libubox list source",
    )
    source_lines = _read_source_text(source_path).splitlines()
    line_number = int(helper_frame["line"])
    if line_number > len(source_lines):
        raise CertificateError("DWARF list source line is outside the source file")
    source_text = source_lines[line_number - 1].strip()
    expected_text = _LIST_STATEMENTS[(str(helper_frame["function"]), line_number)]
    if source_text != expected_text:
        raise CertificateError("typed list helper source statement changed")
    source_blob = "\n".join(source_lines)
    if not re.search(
        r"struct\s+list_head\s*\{\s*struct\s+list_head\s*\*next;\s*"
        r"struct\s+list_head\s*\*prev;\s*\};",
        source_blob,
        re.DOTALL,
    ):
        raise CertificateError("libubox list_head is not the expected two-pointer object")
    sdk = _mapping(mapping.get("sdk"))
    sdk_path = _contained_file(context.root, str(sdk.get("path") or ""), "SDK archive")
    sdk_hash = _sha256_file(sdk_path)
    if sdk_hash != str(sdk.get("sha256") or "") or sdk_hash != OPENWRT_24_10_4_X86_64_SDK_SHA256:
        raise CertificateError("typed list proof is not bound to the pinned OpenWrt SDK")

    normalized_frames = [
        {
            "function": str(frame.get("function") or ""),
            "path": _normalized_frame_path(context.root, str(frame.get("path") or "")),
            "line": int(frame.get("line") or 0),
        }
        for frame in frames
    ]
    allowed_offsets = [0, pointer_width]
    return {
        "rule_claim": "candidate assigns a decompiler object to a typed intrusive-list field STORE",
        "operation_address": _hex(operation_address),
        "elf_virtual_address": _hex(vma),
        "operation_mapping": operation_mapping,
        "dwarf_frames": normalized_frames,
        "typed_source": {
            "path": _relative_if_contained(context.root, source_path),
            "sha256": _sha256_file(source_path),
            "function": str(helper_frame["function"]),
            "line": line_number,
            "statement": source_text,
            "sdk_sha256": sdk_hash,
        },
        "object_layout": {
            "type": "struct list_head",
            "capacity_bytes": 2 * pointer_width,
            "field_width_bytes": pointer_width,
            "allowed_field_offsets": allowed_offsets,
            "store_width_bytes": int(binding.get("width_bytes") or 0),
        },
        "candidate_object_refuted": str(
            _mapping(state.get("affected_object")).get("identity") or ""
        ),
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "semantics_absent": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
        },
    }


def _derive_ghidra_indirect_call_effect(context: CampaignContext) -> dict[str, Any]:
    state = context.state
    binding = context.binding
    if str(state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    if str(binding.get("pcode") or "") != "INDIRECT":
        raise RuleNotApplicable("prepared operation is not a Ghidra INDIRECT")

    operation_address = _hex_int(binding.get("address"), "operation address")
    function = _bound_export_function(context)
    operations = [
        item
        for item in _mapping_rows(function.get("pcode_operations"))
        if str(item.get("operation_address") or "").lower()
        == str(binding.get("address") or "").lower()
    ]
    selected = _mapping(binding.get("pcode_record"))
    if selected not in operations or str(selected.get("pcode") or "") != "INDIRECT":
        raise CertificateError("prepared INDIRECT is absent from the frozen high-p-code export")
    inputs = _mapping_rows(selected.get("inputs"))
    output = _mapping(selected.get("output"))
    if len(inputs) != 2 or str(inputs[1].get("address_space") or "") != "const":
        raise RuleNotApplicable("INDIRECT lacks Ghidra's call-effect operation reference")
    if not output or not inputs[0]:
        raise RuleNotApplicable("INDIRECT lacks its annotation input or output")
    call_ops = [
        item for item in operations if str(item.get("pcode") or "") in {"CALL", "CALLIND"}
    ]
    if len(call_ops) != 1:
        raise RuleNotApplicable("operation address is not associated with one high-p-code call")
    if str(context.export_manifest.get("processor") or "").lower() != "x86":
        raise RuleNotApplicable("call-effect rule currently requires an x86 binary")
    vma, file_offset, instruction_bytes = _operation_bytes(context, operation_address, 15)
    try:
        instruction_length, encoding_kind = _decode_x86_call(instruction_bytes)
    except CertificateError as exc:
        raise RuleNotApplicable("frozen INDIRECT address is not an x86 CALL") from exc

    return {
        "rule_claim": "Ghidra INDIRECT is a call-effect dataflow annotation, not a runtime read",
        "instruction": {
            "operation_address": _hex(operation_address),
            "elf_virtual_address": _hex(vma),
            "file_offset": file_offset,
            "encoding": instruction_bytes[:instruction_length].hex(),
            "encoding_kind": encoding_kind,
            "length_bytes": instruction_length,
        },
        "high_pcode": {
            "call_opcode": str(call_ops[0].get("pcode") or ""),
            "annotation_opcode": "INDIRECT",
            "annotation_input": inputs[0],
            "annotation_output": output,
            "operation_reference": inputs[1],
            "candidate_expression": str(_mapping(state.get("source")).get("expression") or ""),
            "runtime_effect": "none; annotation describes storage possibly affected by the call",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "semantics_absent": True,
        },
    }


def _derive_ghidra_import_pointer_cast(context: CampaignContext) -> dict[str, Any]:
    """Refute CASTs that load a dynamic function pointer for a CALLIND."""

    if str(context.state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    binding = context.binding
    if str(binding.get("pcode") or "") != "CAST":
        raise RuleNotApplicable("prepared operation is not a high-p-code CAST")
    selected = _mapping(binding.get("pcode_record"))
    inputs = _mapping_rows(selected.get("inputs"))
    output = _mapping(selected.get("output"))
    pointer_width = int(context.export_manifest.get("pointer_size_bytes") or 0)
    if (
        len(inputs) != 1
        or str(inputs[0].get("address_space") or "") != "ram"
        or str(output.get("address_space") or "") != "unique"
        or int(inputs[0].get("size_bytes") or 0) != pointer_width
        or int(output.get("size_bytes") or 0) != pointer_width
    ):
        raise RuleNotApplicable("CAST is not from a static pointer slot to a call temporary")
    pointer_name = str(inputs[0].get("var_name") or "")
    if not pointer_name.startswith("PTR_"):
        raise RuleNotApplicable("CAST input is not a Ghidra pointer symbol")

    function = _bound_export_function(context)
    operation_address = _hex_int(binding.get("address"), "operation address")
    operations = [
        item
        for item in _mapping_rows(function.get("pcode_operations"))
        if str(item.get("operation_address") or "").lower()
        == str(binding.get("address") or "").lower()
    ]
    if selected not in operations:
        raise CertificateError("prepared CAST is absent from the frozen high-p-code export")
    call_ops = [item for item in operations if str(item.get("pcode") or "") == "CALLIND"]
    if len(call_ops) != 1:
        raise RuleNotApplicable("CAST is not attached to exactly one indirect call")
    call_inputs = _mapping_rows(call_ops[0].get("inputs"))
    if not call_inputs or call_inputs[0] != output:
        raise RuleNotApplicable("CAST output does not feed the CALLIND target")
    if str(context.export_manifest.get("processor") or "").lower() != "x86":
        raise RuleNotApplicable("import-pointer CAST rule currently requires an x86 binary")

    vma, file_offset, instruction_bytes = _operation_bytes(context, operation_address, 15)
    try:
        instruction_length, encoding_kind = _decode_x86_call(instruction_bytes)
    except CertificateError as exc:
        raise RuleNotApplicable("frozen CAST address is not an x86 CALL") from exc
    if not encoding_kind.endswith("indirect_ff_group2"):
        raise RuleNotApplicable("CALLIND topology is not backed by an indirect x86 CALL")
    relocation = _dynamic_function_relocation(
        context,
        _hex_int(inputs[0].get("address"), "CAST input address"),
    )
    symbol = str(relocation["symbol"])
    expected_symbol = pointer_name[len("PTR_") :]
    suffix = re.search(r"_(?:00)?[0-9a-fA-F]{6,16}$", expected_symbol)
    if suffix is not None:
        expected_symbol = expected_symbol[: suffix.start()]
    if expected_symbol != symbol:
        raise CertificateError("Ghidra pointer name disagrees with the dynamic relocation symbol")

    return {
        "rule_claim": (
            "the exact CAST converts a loader-populated imported function pointer into the "
            "target consumed by CALLIND"
        ),
        "instruction": {
            "operation_address": _hex(operation_address),
            "elf_virtual_address": _hex(vma),
            "file_offset": file_offset,
            "encoding": instruction_bytes[:instruction_length].hex(),
            "encoding_kind": encoding_kind,
            "length_bytes": instruction_length,
        },
        "high_pcode": {
            "cast_input": inputs[0],
            "cast_output": output,
            "call_target": call_inputs[0],
            "call_opcode": "CALLIND",
        },
        "dynamic_relocation": relocation,
        "candidate_expression_refuted": str(
            _mapping(context.state.get("source")).get("expression") or ""
        ),
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "semantics_absent": True,
        },
    }


def _derive_c_vla_index_capacity(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("candidate is not a one-byte STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    match = re.fullmatch(r"(?P<buffer>[A-Za-z_]\w*)\[(?P<index>[A-Za-z_]\w*)\]\s*=\s*'\\0';", statement)
    if match is None:
        raise RuleNotApplicable("exact source line is not a VLA terminator STORE")
    buffer_name = match.group("buffer")
    index_name = match.group("index")
    prefix = "\n".join(line.strip() for line in lines[max(0, line_number - 12) : line_number])
    required = (
        rf"if\s*\(\s*{re.escape(index_name)}\s*>\s*0\s*\)",
        rf"char\s+{re.escape(buffer_name)}\s*\[\s*{re.escape(index_name)}\s*\+\s*1\s*\]\s*;",
        rf"memset\s*\(\s*{re.escape(buffer_name)}\s*,\s*' '\s*,\s*{re.escape(index_name)}\s*\)\s*;",
    )
    if not all(re.search(pattern, prefix) for pattern in required):
        raise RuleNotApplicable("VLA declaration, positive guard, and initialization are not all present")
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the exact STORE writes the VLA terminator at index N in an N+1-byte object",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
        },
        "object_layout": {
            "object_identity": f"vla:{buffer_name}",
            "capacity_expression": f"{index_name} + 1",
            "write_offset_expression": index_name,
            "write_width_bytes": 1,
            "proven_relation": f"0 <= {index_name} < {index_name} + 1",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_guarded_inplace_store(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("candidate is not a one-byte STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    match = re.fullmatch(
        r"(?P<buffer>[A-Za-z_]\w*)\[(?P<index>[A-Za-z_]\w*)\]\s*=\s*'\s';",
        statement,
    )
    if match is None:
        raise RuleNotApplicable("exact source line is not an in-place byte substitution")
    buffer_name = match.group("buffer")
    index_name = match.group("index")
    prefix = "\n".join(line.strip() for line in lines[max(0, line_number - 14) : line_number])
    required = (
        rf"{re.escape(buffer_name)}\s*=\s*strdup\s*\(\s*{re.escape(buffer_name)}\s*\)\s*;",
        rf"for\s*\(\s*{re.escape(index_name)}\s*=\s*0\s*;\s*"
        rf"{re.escape(buffer_name)}\[{re.escape(index_name)}\]\s*;\s*"
        rf"{re.escape(index_name)}\+\+\s*\)",
        rf"if\s*\(\s*{re.escape(buffer_name)}\[{re.escape(index_name)}\]\s*==\s*'\+'\s*\)",
    )
    if not all(re.search(pattern, prefix) for pattern in required):
        raise RuleNotApplicable("strdup origin and loop guards do not dominate the byte STORE")
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the exact STORE replaces a byte already proven present by the loop condition",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
        },
        "object_layout": {
            "object_identity": f"strdup_allocation:{buffer_name}",
            "capacity_expression": f"strlen({buffer_name}) + 1",
            "write_offset_expression": index_name,
            "write_width_bytes": 1,
            "proven_relation": f"{buffer_name}[{index_name}] != 0 before the STORE",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_realloc_nonstack_object(context: CampaignContext) -> dict[str, Any]:
    state = context.state
    if str(state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("candidate is not a one-byte STORE")
    affected = _mapping(state.get("affected_object"))
    if str(affected.get("kind") or "") != "stack":
        raise RuleNotApplicable("candidate does not allege a stack object")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    match = re.fullmatch(r"\*(?P<pointer>[A-Za-z_]\w*)\s*=\s*'\\0';", statement)
    if match is None:
        raise RuleNotApplicable("exact source line is not a pointer terminator STORE")
    pointer = match.group("pointer")
    source_blob = "\n".join(lines)
    if not re.search(rf"static\s+char\s*\*\s*{re.escape(pointer)}\s*;", source_blob):
        raise RuleNotApplicable("STORE pointer is not a static non-stack pointer")
    prefix = "\n".join(line.strip() for line in lines[max(0, line_number - 12) : line_number])
    allocation = re.search(
        rf"{re.escape(pointer)}\s*=\s*realloc\s*\(\s*{re.escape(pointer)}\s*,\s*(?P<size>[A-Za-z_]\w*)\s*\)\s*;",
        prefix,
    )
    if allocation is None:
        raise RuleNotApplicable("static pointer is not assigned from realloc before the STORE")
    size_name = allocation.group("size")
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the alleged stack STORE targets a static pointer assigned from realloc",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
        },
        "object_layout": {
            "object_identity": f"realloc_allocation:{pointer}",
            "capacity_expression": size_name,
            "write_offset_bytes": 0,
            "write_width_bytes": 1,
            "candidate_object_refuted": str(affected.get("identity") or ""),
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "semantics_absent": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
        },
    }


def _derive_libubox_blobmsg_initialization(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    function_name = str(frame["function"])
    function_prefix = _source_function_prefix(lines, function_name, line_number)
    macro_line: int | None = None
    reads_table = re.search(r"\btb\b", statement) is not None
    macro_call = re.match(r"(?P<name>[A-Za-z_]\w*)\s*\(", statement)
    if not reads_table and macro_call is not None:
        definition = re.compile(
            rf"^\s*#\s*define\s+{re.escape(macro_call.group('name'))}\s*\("
        )
        for index in range(line_number - 1, -1, -1):
            if not definition.search(lines[index]):
                continue
            macro_lines = [lines[index]]
            cursor = index
            while macro_lines[-1].rstrip().endswith("\\") and cursor + 1 < len(lines):
                cursor += 1
                macro_lines.append(lines[cursor])
            if re.search(r"\btb\s*\[", "\n".join(macro_lines)):
                reads_table = True
                macro_line = index + 1
            break
    if not reads_table:
        raise RuleNotApplicable("exact source operation does not read a parsed attribute table")
    parameter_table = re.search(
        rf"\b{re.escape(function_name)}\s*\([^)]*"
        r"struct\s+blob_attr\s*\*\s*\*\s*tb\s*\)",
        function_prefix,
        re.DOTALL,
    )
    if parameter_table is not None:
        return _derive_parameter_blobmsg_initialization(
            context,
            source,
            function_name=function_name,
            line_number=line_number,
            statement=statement,
            macro_line=macro_line,
        )
    array_declarations = list(
        re.finditer(
            r"struct\s+blob_attr\s*\*\s*tb\s*\[\s*(?P<count>(?:[A-Za-z_]\w*|\d+))\s*\]\s*;",
            function_prefix,
        )
    )
    scalar_declarations = list(
        re.finditer(r"struct\s+blob_attr\s*\*\s*tb\s*;", function_prefix)
    )
    if array_declarations:
        declaration = array_declarations[-1]
        count_name = declaration.group("count")
        expected_table_argument = "tb"
    elif scalar_declarations:
        declaration = scalar_declarations[-1]
        count_name = "1"
        expected_table_argument = "&tb"
    else:
        raise RuleNotApplicable("source function has no blob attribute table declaration")
    parse_pattern = re.compile(
        r"(?P<function>blobmsg_parse(?:_array)?)\s*\(\s*"
        r"(?P<policy>&?[A-Za-z_]\w*)\s*,\s*(?P<count>[^,]+?)\s*,\s*"
        r"(?P<table>&?tb)\s*,[^;]*\)\s*;",
        re.DOTALL,
    )
    parse_calls = [
        match
        for match in parse_pattern.finditer(function_prefix)
        if match.group("table") == expected_table_argument
        and match.start() > declaration.end()
    ]
    if not parse_calls:
        raise RuleNotApplicable("blobmsg_parse does not initialize the table before this use")
    parse_call = parse_calls[-1]
    count_expression = " ".join(parse_call.group("count").split())
    count_is_capacity = count_expression == count_name or count_expression == "ARRAY_SIZE(tb)"
    if not count_is_capacity and count_expression.startswith("ARRAY_SIZE("):
        policy_name = parse_call.group("policy").lstrip("&")
        count_is_capacity = re.search(
            rf"\b{re.escape(policy_name)}\s*\[\s*{re.escape(count_name)}\s*\]",
            "\n".join(lines[:line_number]),
        ) is not None
    if not count_is_capacity:
        raise RuleNotApplicable("blobmsg parser count is not proven equal to table capacity")

    parse_function = parse_call.group("function")
    dependency = _libubox_blobmsg_contract(
        context,
        _mapping(source.get("mapping")),
        function=parse_function,
    )
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "blobmsg_parse zero-initializes every table slot before parsing or returning",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "table": "tb",
            "element_count": count_name,
            "parser_count_expression": count_expression,
        },
        "dependency_contract": dependency,
        "additional_source_refs": [
            dependency["package_makefile"],
            dependency["source_archive"],
        ],
        "initialization": {
            "destination": "tb",
            "byte_count_expression": f"{count_name} * sizeof(*tb)",
            "value": 0,
            "path_coverage": f"first statement of {parse_function}, before every return",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "all_path_initialization": True,
        },
    }


def _derive_c_unconditional_assignment(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    function_prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
    assignments = list(
        re.finditer(
            r"(?m)^\s*(?P<variable>[A-Za-z_]\w*)\s*=\s*tb\s*\[[^\]]+\]\s*;\s*$",
            function_prefix,
        )
    )
    selected: re.Match[str] | None = None
    for assignment in assignments:
        variable = assignment.group("variable")
        if not re.search(rf"\b{re.escape(variable)}\b", statement):
            continue
        tail = function_prefix[assignment.end() :]
        guard = re.search(
            rf"if\s*\(\s*!\s*{re.escape(variable)}\s*\)\s*\{{[^}}]*\breturn\b[^;]*;[^}}]*\}}",
            tail,
            re.DOTALL,
        )
        if guard is not None:
            selected = assignment
            break
    if selected is None:
        raise RuleNotApplicable("no unconditional assignment and terminating guard dominate this use")
    variable = selected.group("variable")
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "an unconditional assignment and terminating guard dominate the exact use",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
        },
        "initialization": {
            "variable": variable,
            "assignment": selected.group(0).strip(),
            "path_coverage": "unconditional assignment before a false-path return guard",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "all_path_initialization": True,
        },
    }


def _derive_c_immediate_assignment(context: CampaignContext) -> dict[str, Any]:
    """Prove a local initialized by the immediately preceding source statement."""

    if str(context.state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()

    assignment_index = line_number - 2
    while assignment_index >= 0:
        preceding = lines[assignment_index].strip()
        if not preceding or preceding.startswith(("//", "/*", "*", "*/")):
            assignment_index -= 1
            continue
        break
    if assignment_index < 0:
        raise RuleNotApplicable("exact use has no preceding source statement")
    assignment = lines[assignment_index].strip()
    match = re.fullmatch(
        r"(?P<variable>[A-Za-z_]\w*)\s*=\s*(?P<expression>[^;]+)\s*;",
        assignment,
    )
    if match is None:
        match = re.fullmatch(
            r"(?:(?:const|static|volatile|signed|unsigned|long|short)\s+)*"
            r"(?:struct\s+[A-Za-z_]\w*|[A-Za-z_]\w*)"
            r"(?:\s+|\s*\*+\s*)(?P<variable>[A-Za-z_]\w*)\s*=\s*"
            r"(?P<expression>[A-Za-z_]\w*\([^;]*\))\s*;",
            assignment,
        )
    if match is None:
        raise RuleNotApplicable(
            "preceding statement is not an unconditional assignment or call initializer"
        )
    assignment_indent = lines[assignment_index][: len(lines[assignment_index]) - len(lines[assignment_index].lstrip())]
    use_indent = lines[line_number - 1][: len(lines[line_number - 1]) - len(lines[line_number - 1].lstrip())]
    if assignment_indent != use_indent:
        raise RuleNotApplicable("assignment and use are not in the same lexical source block")
    controller_index = assignment_index - 1
    while controller_index >= 0 and not lines[controller_index].strip():
        controller_index -= 1
    if controller_index >= 0:
        controller = lines[controller_index].strip()
        if re.match(r"(?:if|for|while)\s*\(|else\b", controller) and "{" not in controller:
            raise RuleNotApplicable("preceding assignment is controlled by an unbraced branch")
    variable = match.group("variable")
    if not re.search(rf"\b{re.escape(variable)}\b", statement):
        raise RuleNotApplicable("preceding assignment does not define the exact source use")
    if str(context.binding.get("pcode") or "") not in {
        "BOOL_AND",
        "BOOL_NEGATE",
        "BOOL_OR",
        "CAST",
        "COPY",
        "INT_EQUAL",
        "INT_LESS",
        "INT_LESSEQUAL",
        "INT_NOTEQUAL",
        "LOAD",
        "PTRADD",
        "PTRSUB",
    }:
        raise RuleNotApplicable("exact p-code is not a local use operation")

    assignment_line = assignment_index + 1
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[assignment_line, line_number],
    )
    return {
        "rule_claim": "the immediately preceding unconditional statement initializes the local",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "assignment_line": assignment_line,
            "assignment": assignment,
            "use_line": line_number,
            "use": statement,
        },
        "initialization": {
            "variable": variable,
            "expression": match.group("expression").strip(),
            "path_coverage": (
                "every path reaching the immediately following source statement executes "
                "the assignment in the same lexical block"
            ),
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "all_path_initialization": True,
        },
    }


def _derive_parameter_blobmsg_initialization(
    context: CampaignContext,
    source: Mapping[str, Any],
    *,
    function_name: str,
    line_number: int,
    statement: str,
    macro_line: int | None,
) -> dict[str, Any]:
    lines = source["lines"]
    source_text = "\n".join(lines)
    call_pattern = re.compile(
        rf"\b{re.escape(function_name)}\s*\(\s*[^,;]+\s*,\s*"
        r"(?P<table>[A-Za-z_]\w*)\s*\)\s*;"
    )
    calls = list(call_pattern.finditer(source_text))
    if len(calls) != 1:
        raise RuleNotApplicable(
            f"parsed-table helper has {len(calls)} source call sites instead of one"
        )
    call = calls[0]
    table = call.group("table")
    prefix = source_text[: call.start()]
    declarations = list(
        re.finditer(
            rf"struct\s+blob_attr\s*\*\s*{re.escape(table)}\s*\[\s*"
            r"(?P<count>[A-Za-z_]\w*|\d+)\s*\]\s*;",
            prefix,
        )
    )
    if not declarations:
        raise RuleNotApplicable("caller does not declare the passed blob attribute table")
    declaration = declarations[-1]
    count_name = declaration.group("count")
    parser_pattern = re.compile(
        r"(?P<function>blobmsg_parse(?:_array)?)\s*\(\s*"
        r"(?P<policy>&?[A-Za-z_]\w*)\s*,\s*(?P<count>[^,]+?)\s*,\s*"
        rf"{re.escape(table)}\s*,[^;]*\)\s*;",
        re.DOTALL,
    )
    parser_calls = [
        match
        for match in parser_pattern.finditer(
            source_text, declaration.end(), call.start()
        )
    ]
    if len(parser_calls) != 1:
        raise RuleNotApplicable(
            "caller does not initialize the passed table exactly once before the call"
        )
    parser = parser_calls[0]
    count_expression = " ".join(parser.group("count").split())
    if count_expression not in {count_name, f"ARRAY_SIZE({table})"}:
        raise RuleNotApplicable("caller parser count does not equal the table capacity")
    parse_function = parser.group("function")
    dependency = _libubox_blobmsg_contract(
        context,
        _mapping(source.get("mapping")),
        function=parse_function,
    )

    def source_line(offset: int) -> int:
        return source_text[:offset].count("\n") + 1

    declaration_line = source_line(declaration.start())
    parser_line = source_line(parser.start())
    call_line = source_line(call.start())
    evidence_lines = [line_number, declaration_line, parser_line, call_line]
    if macro_line is not None:
        evidence_lines.append(macro_line)
    evidence_lines = sorted(set(evidence_lines))
    source_binding = _source_binding(
        context,
        source,
        source_function=function_name,
        source_lines=evidence_lines,
    )
    return {
        "rule_claim": (
            "the sole caller passes a full-capacity table initialized by blobmsg_parse, "
            "and the exact helper expression assigns its local from that table"
        ),
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": function_name,
            "line": line_number,
            "statement": statement,
            "macro_definition_line": macro_line,
        },
        "caller_contract": {
            "caller_count": 1,
            "table": table,
            "element_count": count_name,
            "declaration_line": declaration_line,
            "parser_line": parser_line,
            "call_line": call_line,
            "parser_count_expression": count_expression,
        },
        "dependency_contract": dependency,
        "additional_source_refs": [
            dependency["package_makefile"],
            dependency["source_archive"],
        ],
        "initialization": {
            "destination": table,
            "byte_count_expression": f"{count_name} * sizeof(*{table})",
            "value": 0,
            "path_coverage": (
                f"{parse_function} initializes every table slot before the sole call to "
                f"{function_name}"
            ),
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "all_path_initialization": True,
        },
    }


def _derive_c_declaration_initializer(context: CampaignContext) -> dict[str, Any]:
    """Recognize only literal local initializers represented by assignment p-code."""

    if str(context.state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    if str(context.binding.get("pcode") or "") != "COPY":
        raise RuleNotApplicable("exact p-code is not an initialization COPY")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    declaration = re.fullmatch(
        r"(?:(?:const|static|volatile|signed|unsigned|long|short)\s+)*"
        r"(?:struct\s+[A-Za-z_]\w*|[A-Za-z_]\w*)"
        r"(?:\s+|\s*\*+\s*)(?P<variable>[A-Za-z_]\w*)\s*=\s*"
        r"(?P<initializer>(?:\"(?:\\.|[^\"\\])*\")|(?:'(?:\\.|[^'\\])')|"
        r"(?:[-+]?(?:0[xX][0-9A-Fa-f]+|\d+)(?:[uUlL]*))|NULL|true|false)\s*;",
        statement,
    )
    if declaration is None:
        raise RuleNotApplicable("exact source statement is not a literal declaration initializer")

    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the exact initialization COPY assigns a literal in the declaration",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
        },
        "initialization": {
            "variable": declaration.group("variable"),
            "initializer": declaration.group("initializer"),
            "path_coverage": "the declaration initializes the local as it enters scope",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "all_path_initialization": True,
        },
    }


def _derive_libubox_checked_calloc_outputs(context: CampaignContext) -> dict[str, Any]:
    """Prove checked calloc_a auxiliary outputs initialized on the success path."""

    if str(context.state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    function_prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
    calls = list(
        re.finditer(
            r"(?P<primary>[A-Za-z_]\w*)\s*=\s*calloc_a\s*\((?P<arguments>.*?)\)\s*;",
            function_prefix,
            re.DOTALL,
        )
    )
    if not calls:
        raise RuleNotApplicable("source function has no preceding calloc_a assignment")
    selected = calls[-1]
    primary = selected.group("primary")
    outputs = re.findall(r"&\s*([A-Za-z_]\w*)", selected.group("arguments"))
    if not outputs:
        raise RuleNotApplicable("calloc_a call has no auxiliary output pointers")
    used_outputs = [
        variable
        for variable in outputs
        if re.search(rf"\b{re.escape(variable)}\b", statement)
    ]
    if not used_outputs:
        raise RuleNotApplicable("exact source statement does not use a calloc_a output")

    tail = function_prefix[selected.end() :]
    guard = re.search(
        rf"if\s*\(\s*!\s*{re.escape(primary)}\s*\)\s*"
        rf"(?:return\b[^;]*;|\{{(?:(?!\}}).)*\breturn\b[^;]*;(?:(?!\}}).)*\}})",
        tail,
        re.DOTALL,
    )
    if guard is None:
        raise RuleNotApplicable("calloc_a result has no terminating failure guard before this use")
    if str(context.binding.get("pcode") or "") not in {
        "CALL",
        "CALLIND",
        "CAST",
        "COPY",
        "LOAD",
        "STORE",
    }:
        raise RuleNotApplicable("exact p-code is not an operation that consumes the output")

    dependency = _libubox_calloc_contract(context, _mapping(source.get("mapping")))
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": (
            "a terminating allocation-failure guard restricts the use to calloc_a's success "
            "path, where every auxiliary pointer is assigned"
        ),
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "allocation": " ".join(selected.group(0).split()),
            "failure_guard": " ".join(guard.group(0).split()),
        },
        "dependency_contract": dependency,
        "additional_source_refs": [
            dependency["package_makefile"],
            dependency["source_archive"],
        ],
        "initialization": {
            "allocation_result": primary,
            "auxiliary_outputs": outputs,
            "outputs_used_by_exact_statement": used_outputs,
            "path_coverage": (
                "failure returns before the use; successful __calloc_a assigns every "
                "non-null vararg output before returning"
            ),
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "all_path_initialization": True,
        },
    }


def _derive_libubox_foreach_initialization(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    if str(context.binding.get("pcode") or "") != "INT_SUB":
        raise RuleNotApplicable("exact p-code is not the foreach loop update")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    invocation = re.fullmatch(
        r"(?P<macro>blob(?:msg)?_for_each_attr)\s*\(\s*"
        r"(?P<position>[A-Za-z_]\w*)\s*,\s*(?P<attribute>.+)\s*,\s*"
        r"(?P<remaining>[A-Za-z_]\w*)\s*\)\s*\{?",
        statement,
    )
    if invocation is None:
        raise RuleNotApplicable("exact source line is not a libubox foreach invocation")
    dependency = _libubox_foreach_contract(
        context,
        _mapping(source.get("mapping")),
        macro=invocation.group("macro"),
    )
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the pinned libubox foreach macro initializes both loop locals before testing or updating them",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
        },
        "dependency_contract": dependency,
        "additional_source_refs": [
            dependency["package_makefile"],
            dependency["source_archive"],
        ],
        "initialization": {
            "position_variable": invocation.group("position"),
            "remaining_variable": invocation.group("remaining"),
            "path_coverage": "the for-loop initializer executes before its condition and update",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "all_path_initialization": True,
        },
    }


def _derive_c_checked_api_output(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement_lines = [lines[line_number - 1].strip()]
    cursor = line_number
    while ";" not in " ".join(statement_lines) and cursor < min(len(lines), line_number + 12):
        statement_lines.append(lines[cursor].strip())
        cursor += 1
    statement = " ".join(item for item in statement_lines if item)
    function_prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
    selected: dict[str, str] | None = None

    direct_pattern = re.compile(
        r"if\s*\(\s*(?P<api>stat|glob)\s*\((?P<arguments>[^;]*?&\s*"
        r"(?P<output>[A-Za-z_]\w*)[^;]*?)\)\s*\)\s*"
        r"(?P<failure>return\b[^;]*;|break\s*;|goto\s+[A-Za-z_]\w*\s*;|"
        r"\{(?:(?!\}).)*(?:return\b[^;]*;|break\s*;|goto\s+[A-Za-z_]\w*\s*;)(?:(?!\}).)*\})",
        re.DOTALL,
    )
    for match in direct_pattern.finditer(function_prefix):
        output = match.group("output")
        if re.search(rf"\b{re.escape(output)}\b", statement):
            selected = {
                "api": match.group("api"),
                "output": output,
                "call": f"{match.group('api')}({match.group('arguments')})",
                "failure_guard": match.group(0),
            }

    assigned_pattern = re.compile(
        r"(?P<result>[A-Za-z_]\w*)\s*=\s*(?P<api>stat|glob)\s*\("
        r"(?P<arguments>[^;]*?&\s*(?P<output>[A-Za-z_]\w*)[^;]*?)\)\s*;"
        r"(?P<middle>.*?)if\s*\(\s*(?P=result)\s*\)\s*"
        r"(?P<failure>return\b[^;]*;|break\s*;|goto\s+[A-Za-z_]\w*\s*;|"
        r"\{(?:(?!\}).)*(?:return\b[^;]*;|break\s*;|goto\s+[A-Za-z_]\w*\s*;)(?:(?!\}).)*\})",
        re.DOTALL,
    )
    for match in assigned_pattern.finditer(function_prefix):
        output = match.group("output")
        if re.search(rf"\b{re.escape(output)}\b", statement):
            selected = {
                "api": match.group("api"),
                "output": output,
                "call": f"{match.group('api')}({match.group('arguments')})",
                "failure_guard": f"if ({match.group('result')}) {match.group('failure')}",
            }
    if selected is None:
        raise RuleNotApplicable("no checked stat/glob output dominates this exact use")

    dependency = _sdk_api_contract(
        context,
        _mapping(source.get("mapping")),
        api=selected["api"],
    )
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=list(range(line_number, cursor + 1)),
    )
    return {
        "rule_claim": "the API output is used only on the documented successful return path",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "call": " ".join(selected["call"].split()),
            "failure_guard": " ".join(selected["failure_guard"].split()),
        },
        "dependency_contract": dependency,
        "additional_source_refs": [
            dependency["sdk_archive"],
            dependency["api_header"],
        ],
        "initialization": {
            "output": selected["output"],
            "api": selected["api"],
            "success_return": 0,
            "path_coverage": "every nonzero return exits or skips past the exact use",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "all_path_initialization": True,
        },
    }


def _derive_c_guarded_pointer(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "null_pointer_dereference":
        raise RuleNotApplicable("candidate is not a null-dereference candidate")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    pointers = set(re.findall(r"\b([A-Za-z_]\w*)\s*(?:->|\[)", statement))
    pointers.update(re.findall(r"(?<![A-Za-z0-9_)])\*\s*([A-Za-z_]\w*)", statement))
    pointers.update(
        re.findall(r"(?<![A-Za-z0-9_)])\*\s*\(\s*([A-Za-z_]\w*)", statement)
    )
    if len(pointers) != 1:
        raise RuleNotApplicable("exact source statement does not have one explicit pointer dereference")
    pointer = next(iter(pointers))
    function_prefix = _source_function_prefix(lines, str(frame["function"]), line_number)

    assignments = list(
        re.finditer(
            rf"(?m)^\s*(?:(?:struct\s+)?[A-Za-z_]\w*(?:\s+|\s*\*+\s*))?"
            rf"{re.escape(pointer)}\s*=",
            function_prefix,
        )
    )
    last_assignment = assignments[-1].end() if assignments else 0
    tail = function_prefix[last_assignment:]
    negative = list(
        re.finditer(
            rf"if\s*\(\s*!\s*{re.escape(pointer)}\s*\)\s*"
            rf"(?:return\b[^;]*;|break\s*;|continue\s*;|goto\s+[A-Za-z_]\w*\s*;|"
            rf"\{{(?:(?!\}}).)*(?:return\b[^;]*;|break\s*;|continue\s*;|"
            rf"goto\s+[A-Za-z_]\w*\s*;)(?:(?!\}}).)*\}})",
            tail,
            re.DOTALL,
        )
    )
    guard_text = ""
    guard_kind = ""
    if negative:
        selected_guard = negative[-1]
        after_guard = tail[selected_guard.end() :]
        if not re.search(rf"(?m)^\s*{re.escape(pointer)}\s*=", after_guard):
            guard_text = selected_guard.group(0)
            guard_kind = "terminating_false_path"
    if not guard_text:
        positive = list(
            re.finditer(
                rf"if\s*\(\s*{re.escape(pointer)}\s*\)\s*\{{",
                function_prefix,
            )
        )
        for selected_guard in reversed(positive):
            block = function_prefix[selected_guard.end() :]
            depth = 1
            for character in block:
                if character == "{":
                    depth += 1
                elif character == "}":
                    depth -= 1
                    if depth == 0:
                        break
            else:
                guard_text = selected_guard.group(0)
                guard_kind = "enclosing_positive_branch"
                break
    if not guard_text:
        raise RuleNotApplicable("no dominating non-null guard proves the explicit dereference")

    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "a dominating source guard excludes the null path before the exact dereference",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "guard": " ".join(guard_text.split()),
        },
        "non_null_proof": {
            "pointer": pointer,
            "guard_kind": guard_kind,
            "path_coverage": "the exact dereference is unreachable when the pointer is null",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_zero_capable_access": True,
            "dominating_non_null": True,
        },
    }


def _derive_c_array_object(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "null_pointer_dereference":
        raise RuleNotApplicable("candidate is not a null-dereference candidate")
    if str(context.binding.get("pcode") or "") not in {"LOAD", "STORE"}:
        raise RuleNotApplicable("exact operation is not a memory access")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    literal = re.search(r'(?P<literal>"(?:\\.|[^"\\])+")\s*\[', statement)
    declaration_text = ""
    capacity = ""
    object_name = ""
    storage = "string_literal"
    if literal is not None:
        object_name = literal.group("literal")
        capacity = str(len(bytes(literal.group("literal")[1:-1], "utf-8")) + 1)
        declaration_text = literal.group("literal")
    else:
        indexed_names = set(re.findall(r"\b([A-Za-z_]\w*)\s*\[", statement))
        if len(indexed_names) > 1:
            disassembly = _disassembly_window(context, before=16, after=8)
            indexed_names = {
                name for name in indexed_names if f"<{name}>" in disassembly
            }
        if not indexed_names:
            source_prefix = "\n".join(lines[:line_number])
            referenced_arrays = {
                name
                for name in re.findall(r"\b([A-Za-z_]\w*)\b", statement)
                if re.search(
                    rf"(?m)^\s*[^;()=\n]+\b{re.escape(name)}\s*\[[^\]]+\]",
                    source_prefix,
                )
            }
            indexed_names = referenced_arrays
        if len(indexed_names) != 1:
            raise RuleNotApplicable("exact operation is not bound to one indexed source object")
        selected_name = next(iter(indexed_names))
        function_prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
        source_prefix = "\n".join(lines[:line_number])
        declaration_pattern = re.compile(
            r"(?m)^\s*(?P<static>static\s+)?(?:const\s+)?[^;()=\n]+?"
            r"(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<capacity>[^\]]*)\s*\]\s*"
            r"(?P<tail>=|;|\{)",
        )
        declarations = []
        for match in declaration_pattern.finditer(source_prefix):
            name = match.group("name")
            if name != selected_name:
                continue
            declarations.append(match)
        declaration_ref: dict[str, str] | None = None
        if len(declarations) == 1:
            declaration = declarations[0]
            object_name = declaration.group("name")
            function_header = function_prefix.split("{", 1)[0]
            if re.search(rf"\([^)]*\b{re.escape(object_name)}\b[^)]*\)", function_header):
                raise RuleNotApplicable("a pointer parameter shadows the same-named array declaration")
            capacity = declaration.group("capacity").strip() or "initializer_element_count"
            declaration_text = declaration.group(0).strip()
            storage = (
                "static_array"
                if declaration.group("static")
                else (
                    "automatic_array"
                    if declaration_text in function_prefix
                    else "static_duration_array"
                )
            )
        elif not declarations:
            external = _unique_source_array_definition(source, selected_name)
            object_name = selected_name
            capacity = external["capacity"]
            declaration_text = external["declaration"]
            storage = "static_duration_array"
            declaration_ref = {
                "path": external["path"],
                "sha256": external["sha256"],
                "kind": "source_review",
            }
        else:
            raise RuleNotApplicable("exact source use has ambiguous array declarations")
    if capacity in {"0", "0U", "0u"}:
        raise RuleNotApplicable("source array has zero capacity")

    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    proof = {
        "rule_claim": "the exact memory access is based on a language-level array object whose address is non-null",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "declaration": declaration_text,
        },
        "non_null_proof": {
            "object": object_name,
            "storage": storage,
            "capacity_expression": capacity,
            "path_coverage": "an array expression designates its allocated stack/static/literal object",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_zero_capable_access": True,
            "dominating_non_null": True,
        },
    }
    if literal is None and declaration_ref is not None:
        proof["additional_source_refs"] = [declaration_ref]
    return proof


def _derive_c_read_terminator(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("candidate is not a one-byte STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    store = re.fullmatch(
        r"(?P<buffer>[A-Za-z_]\w*)\[(?P<count>[A-Za-z_]\w*)\]\s*=\s*0\s*;",
        statement,
    )
    if store is None:
        raise RuleNotApplicable("exact source line is not a read terminator STORE")
    buffer_name = store.group("buffer")
    count_name = store.group("count")
    function_prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
    declaration = re.search(
        rf"char\s+{re.escape(buffer_name)}\s*\[\s*(?P<capacity>[^\]]+)\s*\]",
        function_prefix,
    )
    read_call = re.search(
        rf"{re.escape(count_name)}\s*=\s*read\s*\([^,]+,\s*{re.escape(buffer_name)}\s*,\s*"
        rf"sizeof\s*\(\s*{re.escape(buffer_name)}\s*\)\s*-\s*1\s*\)\s*;",
        function_prefix,
    )
    failure_guard = re.search(
        rf"if\s*\(\s*{re.escape(count_name)}\s*<=\s*0\s*\)\s*return\b[^;]*;",
        function_prefix,
        re.DOTALL,
    )
    if declaration is None or read_call is None or failure_guard is None:
        raise RuleNotApplicable("read count, capacity, and positive-result guard are incomplete")
    dependency = _sdk_api_contract(
        context,
        _mapping(source.get("mapping")),
        api="read",
    )
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    capacity = " ".join(declaration.group("capacity").split())
    return {
        "rule_claim": "successful read count is positive and no greater than the N-1 request",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "read_call": read_call.group(0),
            "failure_guard": " ".join(failure_guard.group(0).split()),
        },
        "dependency_contract": dependency,
        "additional_source_refs": [dependency["sdk_archive"], dependency["api_header"]],
        "object_layout": {
            "object_identity": f"automatic_array:{buffer_name}",
            "capacity_expression": capacity,
            "write_offset_expression": count_name,
            "write_width_bytes": 1,
            "proven_relation": f"0 < {count_name} <= sizeof({buffer_name}) - 1",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_typed_link_store(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    pointer_size = int(context.export_manifest.get("pointer_size_bytes") or 0)
    if (
        str(context.binding.get("pcode") or "") != "STORE"
        or int(context.binding.get("width_bytes") or 0) != pointer_size
        or pointer_size <= 0
    ):
        raise RuleNotApplicable("candidate is not a pointer-width STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    store = re.fullmatch(
        r"\*(?P<link>[A-Za-z_]\w*)\s*=\s*"
        r"(?P<node>[A-Za-z_]\w*)->(?P<next>[A-Za-z_]\w*)\s*;",
        statement,
    )
    if store is None:
        raise RuleNotApplicable("exact source line is not a pointer-to-pointer link STORE")
    link = store.group("link")
    node = store.group("node")
    next_field = store.group("next")
    prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
    function_text = _source_function_text(lines, str(frame["function"]), line_number)
    base = re.search(
        rf"(?P<type>[A-Za-z_]\w*)\s*\*\*\s*{re.escape(link)}\s*=\s*"
        rf"&(?P<owner>[A-Za-z_]\w*)->(?P<head>[A-Za-z_]\w*)\s*;",
        prefix,
    )
    if base is None:
        raise RuleNotApplicable("link cursor has no typed member-address initializer")
    element_type = base.group("type")
    required = (
        rf"\b{re.escape(element_type)}\s*\*\s*{re.escape(node)}\s*;",
        rf"while\s*\(\s*\(\s*{re.escape(node)}\s*=\s*\*{re.escape(link)}\s*\)\s*"
        rf"!=\s*NULL\s*\)",
        rf"\b{re.escape(link)}\s*=\s*&{re.escape(node)}->{re.escape(next_field)}\s*;",
    )
    if not all(re.search(pattern, prefix) for pattern in required):
        raise RuleNotApplicable("typed cursor loop and link-field induction are incomplete")
    source_text = "\n".join(lines)
    type_body = re.search(
        rf"typedef\s+struct\s+{re.escape(element_type)}\s*\{{(?P<body>.*?)\}}\s*"
        rf"{re.escape(element_type)}\s*;",
        source_text,
        re.DOTALL,
    )
    if type_body is None or re.search(
        rf"struct\s+{re.escape(element_type)}\s*\*\s*{re.escape(next_field)}\s*;",
        type_body.group("body"),
    ) is None:
        raise RuleNotApplicable("next field is not a same-type pointer member")
    head_field = base.group("head")
    typed_head_declarations = re.findall(
        rf"(?:struct\s+)?{re.escape(element_type)}\s*\*\s*{re.escape(head_field)}\s*;",
        source_text,
    )
    if len(typed_head_declarations) != 1:
        raise RuleNotApplicable("head field does not have one same-type pointer declaration")
    step_assignments = re.findall(
        rf"(?<!\*)\b{re.escape(link)}\s*=\s*(?P<rhs>[^;]+);",
        function_text,
    )
    if [" ".join(item.split()) for item in step_assignments] != [
        f"&{node}->{next_field}"
    ]:
        raise RuleNotApplicable("link cursor has an unproved reassignment")
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the pointer-to-pointer cursor always designates a pointer-width link member",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "base_cursor": " ".join(base.group(0).split()),
            "inductive_cursor": f"{link} = &{node}->{next_field};",
        },
        "object_layout": {
            "object_identity": (
                f"typed_member:{base.group('owner')}->{head_field} or "
                f"{node}->{next_field}"
            ),
            "capacity_expression": f"sizeof({element_type} *)",
            "write_offset_bytes": 0,
            "write_width_bytes": pointer_size,
            "proven_relation": "STORE width equals either destination link member width",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_bounded_wrapper_read(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("candidate is not a one-byte STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    store = re.fullmatch(
        r"(?P<buffer>[A-Za-z_]\w*)\[(?P<count>[A-Za-z_]\w*)\]\s*=\s*"
        r"(?:0|'\\0')\s*;",
        statement,
    )
    if store is None:
        raise RuleNotApplicable("exact source line is not a wrapper-read terminator STORE")
    buffer_name = store.group("buffer")
    count_name = store.group("count")
    prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
    call = re.search(
        rf"(?:int|ssize_t)\s+{re.escape(count_name)}\s*=\s*"
        rf"open_read_close\s*\([^,]+,\s*{re.escape(buffer_name)}\s*,\s*"
        rf"(?P<capacity>[A-Za-z_]\w*)\s*-\s*1\s*\)\s*;",
        prefix,
    )
    positive_branch = re.search(
        rf"if\s*\(\s*{re.escape(count_name)}\s*<\s*0\s*\)\s*\{{.*?\}}\s*"
        rf"else\s*\{{(?:(?!\}}).)*?{re.escape(buffer_name)}\s*\[\s*"
        rf"{re.escape(count_name)}\s*\]\s*=",
        prefix,
        re.DOTALL,
    )
    if call is None or positive_branch is None:
        raise RuleNotApplicable("wrapper request and nonnegative-result branch are incomplete")
    capacity_name = call.group("capacity")
    source_text = "\n".join(lines)
    alias = re.search(
        rf"^\s*#\s*define\s+{re.escape(buffer_name)}\s+(?P<object>[A-Za-z_]\w*)\s*$",
        source_text,
        re.MULTILINE,
    )
    if alias is None:
        raise RuleNotApplicable("read buffer is not a direct named-object macro alias")
    object_name = alias.group("object")
    read_path, read_text, read_ref = _pinned_source_file(
        context, source, "libbb/read.c", "bounded read wrapper source"
    )
    wrapper_patterns = (
        r"ssize_t\s+FAST_FUNC\s+safe_read\s*\([^)]*size_t\s+count\s*\).*?"
        r"n\s*=\s*read\s*\(\s*fd\s*,\s*buf\s*,\s*count\s*\)\s*;",
        r"ssize_t\s+FAST_FUNC\s+full_read\s*\([^)]*size_t\s+len\s*\).*?"
        r"while\s*\(\s*len\s*\).*?cc\s*=\s*safe_read\s*\(\s*fd\s*,\s*buf\s*,\s*len\s*\)\s*;"
        r".*?total\s*\+=\s*cc\s*;\s*len\s*-=\s*cc\s*;.*?return\s+total\s*;",
        r"ssize_t\s+FAST_FUNC\s+read_close\s*\([^)]*size_t\s+size\s*\).*?"
        r"size\s*=\s*full_read\s*\(\s*fd\s*,\s*buf\s*,\s*size\s*\)\s*;.*?return\s+size\s*;",
        r"ssize_t\s+FAST_FUNC\s+open_read_close\s*\([^)]*size_t\s+size\s*\).*?"
        r"return\s+read_close\s*\(\s*fd\s*,\s*buf\s*,\s*size\s*\)\s*;",
    )
    if not all(re.search(pattern, read_text, re.DOTALL) for pattern in wrapper_patterns):
        raise RuleNotApplicable(f"bounded wrapper implementation changed in {read_path.name}")
    _common_path, common_text, common_ref = _pinned_source_file(
        context, source, "libbb/common_bufsiz.c", "common buffer definition"
    )
    if re.search(
        rf"char\s+{re.escape(object_name)}\s*\[\s*{re.escape(capacity_name)}\s*\]",
        common_text,
    ) is None:
        raise RuleNotApplicable("common buffer definition and request capacity differ")
    symbol = _reference_defined_data_symbol(context, source, object_name)
    if int(symbol["size_bytes"]) <= 1:
        raise RuleNotApplicable("reference common buffer has no terminator capacity")
    dependency = _sdk_api_contract(context, _mapping(source.get("mapping")), api="read")
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the wrapper returns at most its capacity-minus-one request before the terminator STORE",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "read_call": " ".join(call.group(0).split()),
            "success_path": f"{count_name} >= 0 in the else branch",
        },
        "dependency_contract": dependency,
        "additional_source_refs": [
            read_ref,
            common_ref,
            dependency["sdk_archive"],
            dependency["api_header"],
        ],
        "reference_object": symbol,
        "object_layout": {
            "object_identity": f"static_array:{object_name}",
            "capacity_expression": capacity_name,
            "capacity_bytes_in_reference": int(symbol["size_bytes"]),
            "write_offset_expression": count_name,
            "write_width_bytes": 1,
            "proven_relation": f"0 <= {count_name} <= {capacity_name} - 1",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_masked_ring_index(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    pointer_size = int(context.export_manifest.get("pointer_size_bytes") or 0)
    if (
        str(context.binding.get("pcode") or "") != "STORE"
        or int(context.binding.get("width_bytes") or 0) != pointer_size
        or pointer_size <= 0
    ):
        raise RuleNotApplicable("candidate is not a pointer-width STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    store = re.fullmatch(
        r"(?P<array>[A-Za-z_]\w*)\[(?P<index>[A-Za-z_]\w*)\]\s*=\s*.+;",
        statement,
    )
    if store is None:
        raise RuleNotApplicable("exact source line is not an indexed pointer STORE")
    array_name = store.group("array")
    index_name = store.group("index")
    prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
    function_tail = "\n".join(lines[line_number - 1 :])
    declaration = re.search(
        rf"static\s+[^;\n]*\*\s*{re.escape(array_name)}\s*\[\s*(?P<count>\d+)\s*\]\s*;",
        prefix,
    )
    index_declaration = re.search(
        rf"static\s+(?P<type>(?:u?int\d+_t|unsigned(?:\s+\w+)*|size_t))\s+"
        rf"{re.escape(index_name)}\s*;(?:\s*/\*\s*=\s*0\s*\*/)?",
        prefix,
    )
    update = re.search(
        rf"{re.escape(index_name)}\s*=\s*\(\s*{re.escape(index_name)}\s*\+\s*1\s*\)\s*"
        rf"&\s*\(\s*ARRAY_SIZE\s*\(\s*{re.escape(array_name)}\s*\)\s*-\s*1\s*\)\s*;",
        function_tail,
    )
    if declaration is None or index_declaration is None or update is None:
        raise RuleNotApplicable("static array, zero index, and masked update are incomplete")
    capacity = int(declaration.group("count"))
    if capacity <= 0 or capacity & (capacity - 1):
        raise RuleNotApplicable("masked ring capacity is not a positive power of two")
    source_text = "\n".join(lines)
    assignments = re.findall(rf"\b{re.escape(index_name)}\s*=\s*([^;]+);", source_text)
    if len(assignments) != 1 or "ARRAY_SIZE" not in assignments[0]:
        raise RuleNotApplicable("ring index has another source-level assignment")
    _header_path, header_text, header_ref = _pinned_source_file(
        context, source, "include/libbb.h", "ARRAY_SIZE definition"
    )
    if re.search(
        r"^\s*#\s*define\s+ARRAY_SIZE\s*\(\s*x\s*\)\s*"
        r"\(\(unsigned\)\(sizeof\(x\)\s*/\s*sizeof\(\(x\)\[0\]\)\)\)",
        header_text,
        re.MULTILINE,
    ) is None:
        raise RuleNotApplicable("ARRAY_SIZE definition changed")
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the static-zero ring index is masked into the power-of-two array range after every use",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "array_declaration": " ".join(declaration.group(0).split()),
            "index_declaration": " ".join(index_declaration.group(0).split()),
            "index_update": " ".join(update.group(0).split()),
        },
        "additional_source_refs": [header_ref],
        "object_layout": {
            "object_identity": f"static_array:{array_name}",
            "capacity_elements": capacity,
            "write_index_expression": index_name,
            "write_width_bytes": pointer_size,
            "proven_relation": f"0 <= {index_name} <= {capacity - 1}",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_trailing_escape_terminator(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("candidate is not a one-byte STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    store = re.fullmatch(
        r"(?P<buffer>(?:[A-Za-z_]\w*\.)?[A-Za-z_]\w*)\s*"
        r"\[\s*(?P<len>[A-Za-z_]\w*)\s*-\s*1\s*\]\s*=\s*(?:0|'\\0')\s*;",
        statement,
    )
    if store is None:
        raise RuleNotApplicable("exact source line is not a length-minus-one terminator STORE")
    if str(frame.get("function") or "") != "add_cmd":
        raise RuleNotApplicable("trailing-escape proof is not in add_cmd")
    buffer_name = store.group("buffer")
    len_name = store.group("len")
    prefix = _source_function_prefix(lines, "add_cmd", line_number)
    required = (
        rf"(?P<n>[A-Za-z_]\w*)\s*=\s*{re.escape(len_name)}\s*=\s*strlen\s*\(\s*cmdstr\s*\)\s*;",
        rf"while\s*\(\s*(?P<n>[A-Za-z_]\w*)\s*&&\s*cmdstr\s*\[\s*(?P=n)\s*-\s*1\s*\]\s*==\s*'\\\\'\s*\)\s*(?P=n)--\s*;",
        rf"if\s*\(\s*\(\s*{re.escape(len_name)}\s*-\s*(?P<n>[A-Za-z_]\w*)\s*\)\s*&\s*1\s*\)\s*\{{",
        rf"if\s*\(\s*!{re.escape(buffer_name)}\s*\)\s*"
        rf"{re.escape(buffer_name)}\s*=\s*xstrdup\s*\(\s*cmdstr\s*\)\s*;",
        r"cmdstr\s*=\s*G\.add_cmd_line\s*=\s*tp\s*;",
        r"tp\s*=\s*xasprintf\s*\(\s*\"%s\\n%s\"\s*,\s*G\.add_cmd_line\s*,\s*cmdstr\s*\)\s*;",
    )
    matches = [re.search(pattern, prefix) for pattern in required]
    if any(match is None for match in matches):
        raise RuleNotApplicable("length parity and both allocation paths are incomplete")
    n_name = matches[0].group("n")  # type: ignore[union-attr]
    if matches[1].group("n") != n_name or matches[2].group("n") != n_name:  # type: ignore[union-attr]
        raise RuleNotApplicable("trailing-run counter is inconsistent")
    _allocator_path, allocator_text, allocator_ref = _pinned_source_file(
        context, source, "libbb/xfuncs_printf.c", "string allocation wrappers"
    )
    allocator_patterns = (
        r"char\*\s+FAST_FUNC\s+xstrdup\s*\([^)]*\).*?t\s*=\s*strdup\s*\(\s*s\s*\)\s*;"
        r".*?if\s*\(\s*t\s*==\s*NULL\s*\).*?return\s+t\s*;",
        r"char\*\s+FAST_FUNC\s+xasprintf\s*\([^)]*\).*?"
        r"r\s*=\s*vasprintf\s*\(\s*&string_ptr\s*,\s*format\s*,\s*p\s*\)\s*;"
        r".*?if\s*\(\s*r\s*<\s*0\s*\).*?return\s+string_ptr\s*;",
    )
    if not all(re.search(pattern, allocator_text, re.DOTALL) for pattern in allocator_patterns):
        raise RuleNotApplicable("string allocation wrapper contracts changed")
    source_binding = _source_binding(
        context,
        source,
        source_function="add_cmd",
        source_lines=[line_number],
    )
    return {
        "rule_claim": "odd trailing-escape parity implies positive length and both paths allocate the complete command string",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "add_cmd",
            "line": line_number,
            "statement": statement,
            "length_initialization": " ".join(matches[0].group(0).split()),  # type: ignore[union-attr]
            "trailing_scan": " ".join(matches[1].group(0).split()),  # type: ignore[union-attr]
            "parity_guard": " ".join(matches[2].group(0).split()),  # type: ignore[union-attr]
        },
        "additional_source_refs": [allocator_ref],
        "object_layout": {
            "object_identity": f"allocated_string:{buffer_name}",
            "capacity_expression": f"{len_name} + 1",
            "write_offset_expression": f"{len_name} - 1",
            "write_width_bytes": 1,
            "proven_relation": (
                f"({len_name} - {n_name}) is odd, so 1 <= {len_name}; "
                f"therefore 0 <= {len_name} - 1 < {len_name} + 1"
            ),
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_macro_typed_member(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE":
        raise RuleNotApplicable("exact operation is not a STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    array_store = re.fullmatch(
        r"(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<index>0x[0-9a-fA-F]+|\d+)\s*\]\s*=\s*.+;",
        statement,
    )
    scalar_store = re.fullmatch(
        r"(?P<name>[A-Za-z_]\w*)\s*=\s*.+;",
        statement,
    )
    store = array_store or scalar_store
    if store is None:
        raise RuleNotApplicable("exact source line is not a macro-backed member STORE")
    name = store.group("name")
    source_text = "\n".join(lines)
    macro_matches = re.findall(
        rf"^\s*#\s*define\s+{re.escape(name)}\s+\(\s*"
        rf"(?P<base>[A-Za-z_]\w*)\s*\.\s*(?P<field>[A-Za-z_]\w*)\s*\)\s*$",
        source_text,
        re.MULTILINE,
    )
    if len(macro_matches) != 1 or macro_matches[0][1] != name:
        raise RuleNotApplicable("STORE name does not expand to one same-named struct member")
    base_name, field_name = macro_matches[0]
    declaration_text = re.sub(r"/\*.*?\*/", " ", source_text, flags=re.DOTALL)
    width = int(context.binding.get("width_bytes") or 0)
    pointer_size = int(context.export_manifest.get("pointer_size_bytes") or 0)
    additional_refs: list[dict[str, str]] = []
    if array_store is not None:
        declarations = list(
            re.finditer(
                rf"(?P<type>(?:const\s+|volatile\s+|signed\s+|unsigned\s+)*"
                rf"[A-Za-z_]\w*)\s*(?P<pointer>\*+)\s*{re.escape(field_name)}\s*"
                rf"\[\s*(?P<count>0x[0-9a-fA-F]+|\d+)\s*\]\s*;",
                declaration_text,
            )
        )
        if len(declarations) != 1:
            raise RuleNotApplicable("macro array member has no unique pointer-array declaration")
        declaration = declarations[0]
        capacity = int(declaration.group("count"), 0)
        index = int(array_store.group("index"), 0)
        if width != pointer_size or pointer_size <= 0:
            raise RuleNotApplicable("array member STORE is not pointer-width")
        if not 0 <= index < capacity:
            raise RuleNotApplicable("constant member index is outside its declared array")
        object_layout = {
            "object_identity": f"typed_member:{base_name}.{field_name}",
            "capacity_expression": f"{capacity} * sizeof({declaration.group('type')} *)",
            "capacity_elements": capacity,
            "write_index": index,
            "write_width_bytes": width,
            "proven_relation": f"0 <= {index} < {capacity}",
        }
        member_declaration = " ".join(declaration.group(0).split())
    else:
        declarations = list(
            re.finditer(
                rf"(?P<qualifiers>(?:(?:const|volatile)\s+)*)"
                rf"(?P<type>smallint|u?int(?:8|16|32|64)_t|signed\s+char|unsigned\s+char|char)\s+"
                rf"{re.escape(field_name)}\s*;",
                declaration_text,
            )
        )
        if len(declarations) != 1:
            raise RuleNotApplicable("macro scalar member has no unique fixed-width declaration")
        declaration = declarations[0]
        type_name = " ".join(declaration.group("type").split())
        fixed_widths = {
            "char": 1,
            "signed char": 1,
            "unsigned char": 1,
            "int8_t": 1,
            "uint8_t": 1,
            "int16_t": 2,
            "uint16_t": 2,
            "int32_t": 4,
            "uint32_t": 4,
            "int64_t": 8,
            "uint64_t": 8,
        }
        expected_width = fixed_widths.get(type_name)
        if type_name == "smallint":
            if (
                str(context.export_manifest.get("processor") or "") != "x86"
                or pointer_size != 8
            ):
                raise RuleNotApplicable("smallint width is not proven for this architecture")
            _platform_path, platform_text, platform_ref = _pinned_source_file(
                context, source, "include/platform.h", "smallint definition"
            )
            if re.search(
                r"#if\s+defined\(i386\).*?defined\(__x86_64__\).*?"
                r"typedef\s+signed\s+char\s+smallint\s*;",
                platform_text,
                re.DOTALL,
            ) is None:
                raise RuleNotApplicable("x86_64 smallint definition changed")
            additional_refs.append(platform_ref)
            expected_width = 1
        if expected_width is None or width != expected_width:
            raise RuleNotApplicable("scalar member STORE width differs from its declared type")
        object_layout = {
            "object_identity": f"typed_member:{base_name}.{field_name}",
            "capacity_expression": f"sizeof({base_name}.{field_name})",
            "write_offset_bytes": 0,
            "write_width_bytes": width,
            "proven_relation": "STORE width equals the fixed-width scalar member capacity",
        }
        member_declaration = " ".join(declaration.group(0).split())
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    proof = {
        "rule_claim": "the source macro binds the exact STORE to a declared fixed-capacity struct member",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "macro_expansion": f"{name} -> ({base_name}.{field_name})",
            "member_declaration": member_declaration,
        },
        "object_layout": object_layout,
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }
    if additional_refs:
        proof["additional_source_refs"] = additional_refs
    return proof


def _derive_c_bounded_typed_byte_store(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if (
        str(context.binding.get("pcode") or "") != "STORE"
        or int(context.binding.get("width_bytes") or 0) != 1
    ):
        raise RuleNotApplicable("exact operation is not a one-byte STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    store = re.fullmatch(
        r"\(\(\s*(?P<byte_type>u?int8_t|unsigned\s+char|signed\s+char|char)"
        r"\s*\*\s*\)\s*(?P<object>[A-Za-z_]\w*)\s*->\s*"
        r"(?P<field>[A-Za-z_]\w*)\s*\)\s*\[\s*"
        r"(?P<index>[A-Za-z_]\w*)\s*\]\s*=\s*.+;",
        statement,
    )
    if store is None:
        raise RuleNotApplicable("exact source line is not a typed byte view member STORE")
    object_name = store.group("object")
    field_name = store.group("field")
    index_name = store.group("index")
    function_text = _source_function_text(
        lines,
        str(frame["function"]),
        line_number,
    )
    parameter = re.search(
        rf"\b(?P<type>[A-Za-z_]\w*)\s*\*\s*{re.escape(object_name)}\b",
        function_text,
    )
    if parameter is None:
        raise RuleNotApplicable("STORE base is not a typed pointer parameter")
    record_type = parameter.group("type")
    initialization_rows = [
        number
        for number, line in enumerate(lines, start=1)
        if re.search(
            rf"\bunsigned\s+{re.escape(index_name)}\s*=\s*0\s*;",
            line,
        )
    ]
    if len(initialization_rows) != 1 or initialization_rows[0] >= line_number:
        raise RuleNotApplicable("byte index has no unique zero initialization before STORE")
    guard = re.search(
        rf"if\s*\(\s*[^)]*?&&\s*\+\+\s*{re.escape(index_name)}\s*"
        rf"<=\s*(?P<bound>0x[0-9a-fA-F]+|\d+)\s*\)\s*\{{"
        rf"(?P<body>[^{{}}]*)\}}",
        function_text,
        re.DOTALL,
    )
    statement_offset = function_text.find(statement)
    if (
        guard is None
        or statement_offset < 0
        or guard.start() <= statement_offset
        or re.search(r"\bcontinue\s*;", guard.group("body")) is None
        or re.match(r"\s*return\s+-1\s*;\s*\}", function_text[guard.end() :])
        is None
    ):
        raise RuleNotApplicable("failed index guard can reach another loop iteration")
    assignment_count = len(
        re.findall(
            rf"(?<![=!<>])\b{re.escape(index_name)}\s*=(?!=)",
            function_text,
        )
    )
    increment_count = len(
        re.findall(rf"\+\+\s*\b{re.escape(index_name)}\b", function_text)
    )
    forbidden_mutations = re.search(
        rf"(?:\b{re.escape(index_name)}\s*\+\+|--\s*\b{re.escape(index_name)}\b|"
        rf"\b{re.escape(index_name)}\s*--|\b{re.escape(index_name)}\s*[+\-*/%&|^]=)",
        function_text,
    )
    if assignment_count != 1 or increment_count != 1 or forbidden_mutations is not None:
        raise RuleNotApplicable("byte index has additional mutations")
    source_path = Path(source["source_path"])
    source_text = "\n".join(lines)
    declaration_inputs: list[tuple[Path, str]] = [(source_path, source_text)]
    for include_name in re.findall(
        r'^\s*#\s*include\s+"(?P<name>[^"/]+)"\s*$',
        source_text,
        re.MULTILINE,
    ):
        included = source_path.parent / include_name
        if included.is_file():
            declaration_inputs.append((included, _read_source_text(included)))
    type_matches: list[tuple[Path, re.Match[str], re.Match[str]]] = []
    type_pattern = re.compile(
        rf"typedef\s+struct(?:\s+[A-Za-z_]\w*)?\s*\{{(?P<body>.*?)\}}\s*"
        rf"{re.escape(record_type)}\s*;",
        re.DOTALL,
    )
    field_pattern = re.compile(
        rf"(?P<type>u?int(?:8|16|32|64)_t|unsigned\s+char|signed\s+char|char)"
        rf"\s+{re.escape(field_name)}\s*\[\s*(?P<count>0x[0-9a-fA-F]+|\d+)\s*\]\s*;"
    )
    for path, text in declaration_inputs:
        uncommented = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
        for type_match in type_pattern.finditer(uncommented):
            field_match = field_pattern.search(type_match.group("body"))
            if field_match is not None:
                type_matches.append((path, type_match, field_match))
    if len(type_matches) != 1:
        raise RuleNotApplicable("typed pointer has no unique included fixed-array member")
    declaration_path, _type_match, field_match = type_matches[0]
    element_type = " ".join(field_match.group("type").split())
    element_widths = {
        "char": 1,
        "signed char": 1,
        "unsigned char": 1,
        "int8_t": 1,
        "uint8_t": 1,
        "int16_t": 2,
        "uint16_t": 2,
        "int32_t": 4,
        "uint32_t": 4,
        "int64_t": 8,
        "uint64_t": 8,
    }
    element_width = element_widths[element_type]
    element_count = int(field_match.group("count"), 0)
    capacity_bytes = element_width * element_count
    upper_bound = int(guard.group("bound"), 0)
    if upper_bound + 1 > capacity_bytes:
        raise RuleNotApplicable("guarded byte index can exceed the member capacity")
    guard_lines = [
        number
        for number, line in enumerate(lines, start=1)
        if re.search(
            rf"\+\+\s*{re.escape(index_name)}\s*<=\s*{re.escape(guard.group('bound'))}",
            line,
        )
    ]
    if len(guard_lines) != 1:
        raise RuleNotApplicable("index guard has no unique source line")
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=sorted({initialization_rows[0], line_number, guard_lines[0]}),
    )
    declaration_ref = {
        "path": _relative_if_contained(context.root, declaration_path),
        "sha256": _sha256_file(declaration_path),
        "kind": "source_review",
    }
    return {
        "rule_claim": "the only byte-index induction is zero initialization followed by a terminating inclusive upper-bound guard",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "index_initialization_line": initialization_rows[0],
            "index_guard_line": guard_lines[0],
            "member_declaration": " ".join(field_match.group(0).split()),
        },
        "additional_source_refs": [declaration_ref],
        "object_layout": {
            "object_identity": f"typed_member:{object_name}->{field_name}",
            "capacity_expression": f"{element_count} * sizeof({element_type})",
            "capacity_bytes": capacity_bytes,
            "write_offset_expression": index_name,
            "write_width_bytes": 1,
            "proven_relation": f"0 <= {index_name} <= {upper_bound} < {capacity_bytes}",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_struct_output_initialization(context: CampaignContext) -> dict[str, Any]:
    """Prove a split stack local is covered by a dominating typed output init.

    Optimized binaries commonly split one source struct into many decompiler
    locals.  A call that initializes the source object then appears as a set of
    INDIRECT effects, while later field uses are reported as independent
    uninitialized values.  This rule joins the exact later CALL input back to
    the stack aggregate passed to a verified source callee, checks dominance,
    and uses the reference build's DWARF layout for the byte-range relation.
    """

    if str(context.state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    if str(context.binding.get("pcode") or "") not in {"CALL", "CALLIND"}:
        raise RuleNotApplicable("exact candidate operation is not a CALL")
    selected = _mapping(context.binding.get("pcode_record"))
    if str(selected.get("pcode") or "") != str(context.binding.get("pcode") or ""):
        raise CertificateError("prepared CALL record disagrees with its p-code identity")
    expression = str(_mapping(context.state.get("source")).get("expression") or "")
    selected_inputs = (
        _mapping_rows(selected.get("inputs"))
        if selected.get("inputs") is not None
        else _mapping_rows(selected.get("args"))
    )
    candidate_inputs = [
        item
        for item in selected_inputs
        if _stack_var_name(item) == expression
    ]
    if len(candidate_inputs) != 1:
        raise RuleNotApplicable("exact CALL does not consume the alleged stack local once")
    candidate_input = candidate_inputs[0]
    try:
        candidate_offset = _integer_value(
            candidate_input.get("stack_offset"), "candidate stack offset"
        )
    except CertificateError as exc:
        raise RuleNotApplicable("exact CALL input is not a stack byte range") from exc
    candidate_width = int(candidate_input.get("size_bytes") or 0)
    if candidate_width <= 0:
        raise RuleNotApplicable("exact CALL input has no positive byte width")

    function = _bound_export_function(context)
    candidate_address = _hex_int(context.binding.get("address"), "candidate CALL address")
    initializers = _struct_output_initializers(context, function)
    matches: list[dict[str, Any]] = []
    for initializer in initializers:
        base_offset = int(initializer["stack_base_offset"])
        layout = _mapping(initializer.get("compiled_layout"))
        capacity = int(layout.get("size_bytes") or 0)
        relative_offset = candidate_offset - base_offset
        if relative_offset < 0 or relative_offset + candidate_width > capacity:
            continue
        relation = _cfg_dominance_relation(
            function,
            str(initializer["call_address"]),
            _hex(candidate_address),
        )
        if not relation["feasible"] or not relation["before_dominates_after"]:
            continue
        members = [
            member
            for member in _mapping_rows(layout.get("members"))
            if int(member.get("offset_bytes") or 0) < relative_offset + candidate_width
            and relative_offset
            < int(member.get("offset_bytes") or 0) + int(member.get("size_bytes") or 0)
        ]
        use_lines = _struct_member_use_lines(
            _mapping(initializer.get("caller_source")),
            str(initializer["source_variable"]),
            [str(member.get("name") or "") for member in members],
            after_line=int(initializer["source_call_line"]),
        )
        if not members or not use_lines:
            continue
        matches.append(
            {
                **initializer,
                "candidate_relative_offset": relative_offset,
                "candidate_members": members,
                "candidate_source_use_lines": use_lines,
                "cfg_relation": relation,
            }
        )
    if len(matches) != 1:
        raise RuleNotApplicable("no unique dominating typed whole-struct initializer covers the CALL input")
    match = matches[0]

    mapping = _reference_mapping(context)
    candidate_mapping = _reference_operation_mapping(context, mapping, candidate_address)
    caller_source = _mapping(match.get("caller_source"))
    caller_names = {
        _normalized_c_function_name(item)
        for item in _string_rows(candidate_mapping.get("reference_function_names"))
    }
    if str(caller_source.get("function") or "") not in caller_names:
        raise RuleNotApplicable("candidate operation maps to another source function")
    source_context = {
        "mapping": mapping,
        "operation_mapping": candidate_mapping,
        "source_path": Path(str(caller_source["path"])),
    }
    source_lines = sorted(
        {
            int(match["source_declaration_line"]),
            int(match["source_call_line"]),
            *[int(item) for item in match["candidate_source_use_lines"]],
        }
    )
    source_binding = _source_binding(
        context,
        source_context,
        source_function=str(caller_source["function"]),
        source_lines=source_lines,
    )
    callee_source = _mapping(match.get("callee_source"))
    struct_source = _mapping(match.get("struct_source"))
    additional_refs = _deduplicated_source_refs(
        context,
        [Path(str(callee_source["path"])), Path(str(struct_source["path"]))],
    )
    layout = _mapping(match.get("compiled_layout"))
    return {
        "rule_claim": "a dominating typed output call unconditionally zero-initializes every byte of the containing compiled struct",
        "operation_address": _hex(candidate_address),
        "source_binding": source_binding,
        "initializer": {
            "call_address": str(match["call_address"]),
            "callee_address": str(match["callee_address"]),
            "callee_function": str(callee_source["function"]),
            "output_parameter_index": int(match["output_parameter_index"]),
            "output_parameter": str(match["output_parameter"]),
            "memset_line": int(match["memset_line"]),
            "memset_statement": str(match["memset_statement"]),
            "source_call_line": int(match["source_call_line"]),
            "source_call_statement": str(match["source_call_statement"]),
            "source_variable": str(match["source_variable"]),
            "cfg_relation": _mapping(match.get("cfg_relation")),
            "callee_source_binding": _mapping(match.get("callee_source_binding")),
        },
        "compiled_object": {
            "type": f"struct {layout['name']}",
            "reference_binary_path": str(layout["reference_binary_path"]),
            "reference_binary_sha256": str(layout["reference_binary_sha256"]),
            "capacity_bytes": int(layout["size_bytes"]),
            "stack_base_offset": int(match["stack_base_offset"]),
            "candidate_stack_offset": candidate_offset,
            "candidate_relative_offset": int(match["candidate_relative_offset"]),
            "candidate_width_bytes": candidate_width,
            "overlapping_members": [
                {
                    "name": str(item.get("name") or ""),
                    "offset_bytes": int(item.get("offset_bytes") or 0),
                    "size_bytes": int(item.get("size_bytes") or 0),
                }
                for item in match["candidate_members"]
            ],
            "proven_relation": (
                f"0 <= {int(match['candidate_relative_offset'])} and "
                f"{int(match['candidate_relative_offset'])} + {candidate_width} "
                f"<= {int(layout['size_bytes'])}"
            ),
        },
        "additional_source_refs": additional_refs,
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "all_path_initialization": True,
            "cfg_dominance": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
        },
    }


def _derive_c_guarded_fixed_array(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE":
        raise RuleNotApplicable("candidate operation is not a STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    store = re.match(
        r"(?P<array>[A-Za-z_]\w*)\[(?P<index>[A-Za-z_]\w*)\]\s*=",
        statement,
    )
    if store is None:
        raise RuleNotApplicable("exact source line is not a fixed-array indexed STORE")
    array_name = store.group("array")
    index_name = store.group("index")
    function_prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
    declarations = list(re.finditer(
        rf"[A-Za-z_]\w*(?:_t)?\s+{re.escape(array_name)}\s*\[\s*(?P<capacity>\d+)\s*\]",
        function_prefix,
    ))
    if not declarations:
        raise RuleNotApplicable("indexed STORE is not to a numeric fixed-size local array")
    declaration = declarations[-1]
    capacity = int(declaration.group("capacity"))
    initialization = re.search(
        rf"(?:int|size_t|unsigned(?:\s+int)?)\s+{re.escape(index_name)}\s*=\s*0\s*;",
        function_prefix,
    )
    guard = re.search(
        rf"if\s*\(\s*{re.escape(index_name)}\s*>=\s*{capacity}\s*\)\s*break\s*;",
        function_prefix,
        re.DOTALL,
    )
    if initialization is None or guard is None:
        raise RuleNotApplicable("zero initialization and capacity guard do not dominate the STORE")
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "a capacity guard exits the loop before the exact fixed-array STORE",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "guard": " ".join(guard.group(0).split()),
        },
        "object_layout": {
            "object_identity": f"automatic_array:{array_name}",
            "capacity_elements": capacity,
            "element_width_bytes": int(context.binding.get("width_bytes") or 0),
            "write_index_expression": index_name,
            "proven_relation": f"0 <= {index_name} < {capacity}",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_html_escape(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("candidate is not a one-byte STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    if not re.fullmatch(r"\*(?P<pointer>[A-Za-z_]\w*)\+\+\s*=\s*.+;", statement):
        raise RuleNotApplicable("exact source line is not the HTML escape byte STORE")
    function_prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
    required = (
        r"for\s*\(\s*i\s*=\s*0\s*,\s*len\s*=\s*1\s*;\s*str\[i\]\s*;\s*i\+\+\s*\)",
        r"len\s*\+=\s*6\s*;",
        r"else\s+len\+\+\s*;",
        r"copy\s*=\s*calloc\s*\(\s*1\s*,\s*len\s*\)\s*;",
        r"if\s*\(\s*!copy\s*\)\s*return\s+NULL\s*;",
        r"for\s*\(\s*i\s*=\s*0\s*,\s*p\s*=\s*copy\s*;\s*str\[i\]\s*;\s*i\+\+\s*\)",
        r"p\s*\+=\s*sprintf\s*\(\s*p\s*,\s*\"&#x%02x;\"",
    )
    if not all(re.search(pattern, function_prefix, re.DOTALL) for pattern in required):
        raise RuleNotApplicable("HTML output sizing and write loops do not match the proven form")
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the first pass reserves one byte per plain character, six per escaped character, and one terminator",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
        },
        "object_layout": {
            "object_identity": "calloc_allocation:copy",
            "capacity_expression": "1 + sum(6 if HTML-special else 1 for each input byte)",
            "write_offset_expression": "p - copy",
            "write_width_bytes": 1,
            "proven_relation": "plain-byte STORE consumes exactly its one-byte first-pass budget",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_jail_argv(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE" or int(
        context.binding.get("width_bytes") or 0
    ) != int(context.export_manifest.get("pointer_size_bytes") or 0):
        raise RuleNotApplicable("candidate is not a pointer-width STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    if str(frame.get("function") or "") != "jail_run":
        raise RuleNotApplicable("exact source operation is not in jail_run")
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    if not re.fullmatch(r"argv\[argc\+\+\]\s*=\s*.+;", statement):
        raise RuleNotApplicable("exact source line is not an argv append")
    function_prefix = _source_function_prefix(lines, "jail_run", line_number)
    append_count = len(re.findall(r"argv\[argc\+\+\]\s*=", function_prefix))
    write_index = append_count - 1
    if not 0 <= write_index < 5:
        raise RuleNotApplicable("argv append is outside the unconditional minimum capacity")
    source_text = "\n".join(lines)
    required = (
        r"jail->argc\s*=\s*4\s*;",
        r"int\s+argc\s*=\s*1\s*;\s*/\*\s*NULL terminated\s*\*/",
        r"argv\s*=\s*alloca\s*\(\s*sizeof\(char \*\)\s*\*\s*\(argc\s*\+\s*in->jail.argc\)\s*\)\s*;",
        r"argc\s*=\s*0\s*;",
    )
    if not all(re.search(pattern, source_text) for pattern in required):
        raise RuleNotApplicable("caller allocation and minimum jail capacity are not proven")
    source_binding = _source_binding(
        context,
        source,
        source_function="jail_run",
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the caller reserves at least five argv slots before jail_run appends its first five entries",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "jail_run",
            "line": line_number,
            "statement": statement,
        },
        "object_layout": {
            "object_identity": "caller_alloca:argv",
            "capacity_expression": "command_argc_with_NULL + in->jail.argc",
            "minimum_capacity_elements": 5,
            "write_index": write_index,
            "write_width_bytes": int(context.binding.get("width_bytes") or 0),
            "proven_relation": f"0 <= {write_index} < 5 <= allocated pointer slots",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_fixed_path_effect(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "path_traversal":
        raise RuleNotApplicable("candidate is not a path-effect candidate")
    if str(context.binding.get("pcode") or "") not in {"CALL", "CALLIND"}:
        raise RuleNotApplicable("exact operation is not a call")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    call = re.search(
        r"(?P<api>open|stat)\s*\(\s*(?P<path>\"[^\"]+\"|[A-Z_][A-Z0-9_]*)\s*[,)]",
        statement,
    )
    if call is None:
        raise RuleNotApplicable("exact path effect does not use a fixed literal or macro")
    path_token = call.group("path")
    resolved_path = path_token[1:-1] if path_token.startswith('"') else ""
    macro_definition = ""
    if not resolved_path:
        macro = re.search(
            rf"(?m)^\s*#define\s+{re.escape(path_token)}\s+\"(?P<path>[^\"]+)\"\s*$",
            "\n".join(lines),
        )
        if macro is None:
            raise RuleNotApplicable("fixed path macro is not defined in the exact source file")
        resolved_path = macro.group("path")
        macro_definition = macro.group(0).strip()
    allowed = {
        ("open", "/dev/null"): "fixed null device for process standard I/O",
        ("open", "/dev"): "fixed device-directory descriptor for constrained openat",
        ("stat", "/sbin/ujail"): "fixed installed sandbox-helper existence check",
    }
    intent = allowed.get((call.group("api"), resolved_path))
    if intent is None:
        raise RuleNotApplicable("fixed path is not an enumerated intentional system target")

    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the exact effect uses a compile-time fixed system path with no input substitution",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "macro_definition": macro_definition,
        },
        "trust_boundary": {
            "api": call.group("api"),
            "path_token": path_token,
            "resolved_path": resolved_path,
            "intent": intent,
            "attacker_controlled_path_bytes": 0,
            "boundary_result": "no path traversal or argument alteration is possible",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "trust_boundary_modeled": True,
            "intended_effect": True,
            "no_security_boundary": True,
        },
    }


def _derive_c_returned_allocation(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "memory_leak":
        raise RuleNotApplicable("candidate is not a leak candidate")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    allocation = re.fullmatch(
        r"(?P<variable>[A-Za-z_]\w*)\s*=\s*(?P<api>calloc|malloc|realloc)\s*\(.+\)\s*;",
        statement,
    )
    if allocation is None:
        raise RuleNotApplicable("exact source line is not a returned allocation assignment")
    function_prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
    function_start = "\n".join(lines).find(function_prefix.split("\n", 1)[0])
    function_tail = "\n".join(lines)[max(0, function_start) :]
    variable = allocation.group("variable")
    if not re.search(rf"\breturn\s+{re.escape(variable)}\s*;", function_tail):
        raise RuleNotApplicable("allocated value is not returned to the caller")
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the allocation is returned as the function result and ownership transfers to the caller",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "return_statement": f"return {variable};",
        },
        "ownership": {
            "allocation": variable,
            "transfer": "function return value",
            "lifetime_result": "not retained by the allocating function",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "ownership_lifetime_modeled": True,
            "ownership_transfer": True,
        },
    }


def _derive_c_collection_cleanup(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "memory_leak":
        raise RuleNotApplicable("candidate is not a leak candidate")
    source = _exact_source_context(context)
    frame = source["frame"]
    function = str(frame["function"])
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    allocation = re.search(
        r"(?P<target>[A-Za-z_]\w*(?:->[A-Za-z_]\w*)?)\s*=\s*(?:calloc|malloc)\s*\(",
        statement,
    )
    if allocation is None:
        raise RuleNotApplicable("exact source line is not a collection-owned allocation")
    target = allocation.group("target")
    contracts: dict[tuple[str, str], tuple[str, tuple[str, ...]]] = {
        ("handle_button_complete", "b"): (
            "button timer list",
            (
                r"list_add\s*\(\s*&b->list\s*,\s*&button_timer\s*\)",
                r"button_free\s*\([^)]*\).*?free\s*\(\s*b\s*\)",
                r"handle_button_timeout\s*\([^)]*\).*?button_free\s*\(\s*b\s*\)",
            ),
        ),
        ("handle_button_complete", "b->data"): (
            "button timer payload",
            (
                r"list_add\s*\(\s*&b->list\s*,\s*&button_timer\s*\)",
                r"button_free\s*\([^)]*\).*?free\s*\(\s*b->data\s*\)",
                r"handle_button_timeout\s*\([^)]*\).*?button_free\s*\(\s*b\s*\)",
            ),
        ),
        ("blobmsg_list_fill", "ptr"): (
            "blobmsg AVL collection",
            (
                r"avl_insert\s*\(\s*tree\s*,\s*&node->avl\s*\)",
                r"blobmsg_list_free\s*\([^)]*\).*?avl_remove_all_elements.*?free\s*\(\s*ptr\s*\)",
            ),
        ),
        ("add_subsystem", "nh"): (
            "hotplug subsystem list",
            (
                r"list_add\s*\(\s*&nh->list\s*,\s*&subsystems\s*\)",
                r"remove_subsystem\s*\([^)]*\).*?list_del\s*\(\s*&h->list\s*\).*?free\s*\(\s*h\s*\)",
            ),
        ),
    }
    contract = contracts.get((function, target))
    if contract is None:
        raise RuleNotApplicable("allocation is not in a registered collection lifecycle")
    source_text = "\n".join(lines)
    if not all(re.search(pattern, source_text, re.DOTALL) for pattern in contract[1]):
        raise RuleNotApplicable("collection insertion and cleanup paths do not match")
    source_binding = _source_binding(
        context,
        source,
        source_function=function,
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the allocation transfers into a collection with an explicit removal/free lifecycle",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": function,
            "line": line_number,
            "statement": statement,
        },
        "ownership": {
            "allocation": target,
            "collection": contract[0],
            "transfer": "collection insertion",
            "cleanup": "registered removal path frees the allocation",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "ownership_lifetime_modeled": True,
            "later_cleanup": True,
        },
    }


def _derive_c_client_allocation(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "memory_leak":
        raise RuleNotApplicable("candidate is not a leak candidate")
    source = _exact_source_context(context)
    frame = source["frame"]
    if str(frame.get("function") or "") != "uh_accept_client":
        raise RuleNotApplicable("allocation is not the uhttpd client cache")
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    if statement != "next_client = calloc(1, sizeof(*next_client));":
        raise RuleNotApplicable("exact source line is not the cached client allocation")
    source_text = "\n".join(lines)
    required = (
        r"static\s+struct\s+client\s*\*next_client\s*;",
        r"if\s*\(\s*!next_client\s*\)\s*next_client\s*=\s*calloc",
        r"list_add_tail\s*\(\s*&cl->list\s*,\s*&clients\s*\)",
        r"next_client\s*=\s*NULL\s*;",
        r"list_del\s*\(\s*&cl->list\s*\).*?free\s*\(\s*cl\s*\)",
    )
    if not all(re.search(pattern, source_text, re.DOTALL) for pattern in required):
        raise RuleNotApplicable("client cache transfer and cleanup lifecycle do not match")
    source_binding = _source_binding(
        context,
        source,
        source_function="uh_accept_client",
        source_lines=[line_number],
    )
    return {
        "rule_claim": "at most one client is cached; accepted clients transfer to a list and are freed on close",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "uh_accept_client",
            "line": line_number,
            "statement": statement,
        },
        "ownership": {
            "allocation": "next_client",
            "cache_bound": 1,
            "transfer": "accepted client list",
            "cleanup": "client_close removes and frees accepted clients",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "ownership_lifetime_modeled": True,
            "bounded_lifetime": True,
            "later_cleanup": True,
        },
    }


def _derive_c_intended_exec_effect(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "argument_injection":
        raise RuleNotApplicable("candidate is not an argument-effect candidate")
    if str(context.binding.get("pcode") or "") not in {"CALL", "CALLIND"}:
        raise RuleNotApplicable("exact operation is not a call")
    source = _exact_source_context(context)
    frame = source["frame"]
    function = str(frame["function"])
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    source_text = "\n".join(lines)
    contracts: dict[str, dict[str, Any]] = {
        "q_initd_run": {
            "statement": r"execlp\s*\(\s*s->file\s*,\s*s->file\s*,\s*s->param\s*,\s*NULL\s*\)\s*;",
            "required": (
                r"glob\s*\(\s*dir\s*,\s*GLOB_NOESCAPE\s*\|\s*GLOB_MARK",
                r"add_initd\s*\(\s*q\s*,\s*gl\.gl_pathv\[j\]\s*,\s*param\s*\)",
            ),
            "boundary": "OpenWrt init-script enumeration plus an internal lifecycle verb",
            "intent": "execute the selected init script without shell parsing",
        },
        "instance_run": {
            "statement": r"execvp\s*\(\s*argv\[0\]\s*,\s*argv\s*\)\s*;",
            "required": (
                r"blobmsg_for_each_attr\s*\(\s*cur\s*,\s*in->command\s*,\s*rem\s*\)",
                r"argv\[argc\]\s*=\s*NULL\s*;",
            ),
            "boundary": "privileged service configuration represented as an explicit argv vector",
            "intent": "launch the configured supervised service without shell parsing",
        },
        "fork_worker": {
            "statement": r"execvp\s*\(\s*a->argv\[0\]\s*,\s*a->argv\s*\)\s*;",
            "required": (
                r"static\s+void\s+fork_worker\s*\(\s*struct init_action \*a\s*\)",
                r"a->argv\[i\]\s*=\s*tok\s*;",
            ),
            "boundary": "configured procd worker action represented as an explicit argv vector",
            "intent": "launch the configured worker without shell parsing",
        },
        "cgi_main": {
            "statement": r"execl\s*\(\s*ip->path\s*,\s*ip->path\s*,\s*pi->phys\s*,\s*NULL\s*\)\s*;",
            "required": (
                r"const\s+struct\s+interpreter\s*\*ip\s*=\s*pi->ip\s*;",
                r"check_cgi_path",
                r"struct\s+dispatch_handler\s+cgi_dispatch",
            ),
            "boundary": "configured CGI interpreter plus docroot-resolved script path",
            "intent": "perform CGI dispatch with fixed argv element boundaries and no shell",
        },
    }
    contract = contracts.get(function)
    if contract is None or re.fullmatch(contract["statement"], statement) is None:
        raise RuleNotApplicable("exact call is not a registered intended execution effect")
    if not all(re.search(pattern, source_text, re.DOTALL) for pattern in contract["required"]):
        raise RuleNotApplicable("execution origin and explicit-vector contract do not match")
    source_binding = _source_binding(
        context,
        source,
        source_function=function,
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the exact call is the component's intended direct-exec boundary, not command parsing",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": function,
            "line": line_number,
            "statement": statement,
        },
        "trust_boundary": {
            "configuration_boundary": contract["boundary"],
            "intended_effect": contract["intent"],
            "shell_interpretation": False,
            "argv_element_boundaries_preserved": True,
            "boundary_result": "no escape from the enumerated service/CGI execution boundary",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "trust_boundary_modeled": True,
            "intended_effect": True,
            "no_security_boundary": True,
        },
    }


def _derive_c_intended_path_effect(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "path_traversal":
        raise RuleNotApplicable("candidate is not a path-effect candidate")
    if str(context.binding.get("pcode") or "") not in {"CALL", "CALLIND"}:
        raise RuleNotApplicable("exact operation is not a call")
    source = _exact_source_context(context)
    frame = source["frame"]
    function = str(frame["function"])
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    source_text = "\n".join(lines)
    contracts: dict[str, dict[str, Any]] = {
        "patch_fd": {
            "statements": (
                r"nfd\s*=\s*open\s*\(\s*device\s*,\s*flags\s*\)\s*;",
                r"nfd\s*=\s*openat\s*\(\s*dfd\s*,\s*device\s*,\s*flags\s*\)\s*;",
            ),
            "required": (
                r"if\s*\(\s*\*device\s*!=\s*'/'\s*\)",
                r"dfd\s*=\s*open\s*\(\s*\"/dev\"\s*,\s*O_PATH\|O_DIRECTORY\s*\)",
                r"if\s*\(\s*nfd\s*<\s*0\s*&&\s*strcmp\s*\(\s*device\s*,\s*\"/dev/null\"\s*\)\s*\)",
            ),
            "boundary": "boot-console device selection; relative names are anchored under /dev",
            "intent": "replace a standard-I/O descriptor with the selected console device",
        },
        "set_stdio": {
            "statements": (
                r"!freopen\s*\(\s*tty\s*,\s*\"[rw]\"\s*,\s*(?:stdin|stdout|stderr)\s*\)\s*(?:\|\||\))?",
            ),
            "required": (
                r"chdir\s*\(\s*\"/dev\"\s*\)",
                r"set_stdio\s*\(\s*\"console\"\s*\)",
            ),
            "boundary": "internally selected boot console under the /dev working directory",
            "intent": "attach procd standard streams to the system console",
        },
        "instance_writepid": {
            "statements": (r"_pidfile\s*=\s*fopen\s*\(\s*in->pidfile\s*,\s*\"w\"\s*\)\s*;",),
            "required": (
                r"if\s*\(\s*!in->pidfile\s*\)",
                r"fprintf\s*\(\s*_pidfile\s*,\s*\"%d\\n\"\s*,\s*in->proc.pid\s*\)",
            ),
            "boundary": "privileged service configuration pidfile destination",
            "intent": "write the supervised service PID to its configured pidfile",
        },
        "init_request": {
            "statements": (r"input_file\s*=\s*fopen\s*\(\s*post_file\s*,\s*\"r\"\s*\)\s*;",),
            "required": (
                r"--post-file",
                r"post_file",
            ),
            "boundary": "local uclient-fetch command-line upload-file option",
            "intent": "read the explicitly requested local request body file",
        },
        "uh_file_request": {
            "statements": (r"fd\s*=\s*open\s*\(\s*pi->phys\s*,\s*O_RDONLY\s*\)\s*;",),
            "required": (
                r"strncmp\s*\(\s*path_phys\s*,\s*docroot\s*,\s*docroot_len\s*\)\s*!=\s*0",
                r"p\.phys\s*=\s*path_phys\s*;",
                r"dispatch_find\s*\(\s*url\s*,\s*pi\s*\)",
            ),
            "boundary": "canonicalized path constrained to the configured HTTP document root",
            "intent": "open the resolved static file for serving",
        },
    }
    contract = contracts.get(function)
    if contract is None or not any(
        re.fullmatch(pattern, statement) for pattern in contract["statements"]
    ):
        raise RuleNotApplicable("exact call is not a registered intended path effect")
    if not all(re.search(pattern, source_text, re.DOTALL) for pattern in contract["required"]):
        raise RuleNotApplicable("path origin and containment contract do not match")
    source_binding = _source_binding(
        context,
        source,
        source_function=function,
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the exact path effect stays within its explicit configuration or content-serving boundary",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": function,
            "line": line_number,
            "statement": statement,
        },
        "trust_boundary": {
            "configuration_boundary": contract["boundary"],
            "intended_effect": contract["intent"],
            "boundary_result": "path bytes cannot escape the enumerated intended target boundary",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "trust_boundary_modeled": True,
            "intended_effect": True,
            "no_security_boundary": True,
        },
    }


def _derive_c_startup_allocation(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "memory_leak":
        raise RuleNotApplicable("candidate is not a leak candidate")
    source = _exact_source_context(context)
    frame = source["frame"]
    function = str(frame["function"])
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    if re.search(r"(?:calloc|malloc)\s*\(", statement) is None:
        raise RuleNotApplicable("exact source line is not an allocation")
    contracts: dict[str, dict[str, Any]] = {
        "procd_inittab": {
            "targets": ("line", "a"),
            "current": (
                r"while\s*\(\s*fgets\s*\(\s*line\s*,\s*LINE_LEN\s*,\s*fp\s*\)\s*\)",
                r"list_add_tail\s*\(\s*&a->list\s*,\s*&actions\s*\)",
                r"free\s*\(\s*line\s*\)\s*;\s*free\s*\(\s*a\s*\)",
            ),
            "caller": "state.c",
            "caller_pattern": r"case\s+STATE_INIT\s*:.*?procd_inittab\s*\(\s*\)",
            "bound": "at most one retained action per finite /etc/inittab input line",
        },
        "uh_handler_add": {
            "targets": ("h",),
            "current": (r"list_add_tail\s*\(\s*&h->list\s*,\s*&handlers\s*\)",),
            "caller": "main.c",
            "caller_pattern": r"case\s+'H'\s*:.*?uh_handler_add\s*\(\s*optarg\s*\)",
            "bound": "at most one retained handler per finite startup -H option",
        },
        "uh_socket_bind": {
            "targets": ("l",),
            "current": (r"list_add_tail\s*\(\s*&l->list\s*,\s*&listeners\s*\)",),
            "caller": "main.c",
            "caller_pattern": r"add_listener_arg\s*\([^)]*\).*?uh_socket_bind",
            "bound": "finite startup listener/address enumeration",
        },
        "uh_index_add": {
            "targets": ("idx",),
            "current": (r"list_add_tail\s*\(\s*&idx->list\s*,\s*&index_files\s*\)",),
            "caller": "main.c",
            "caller_pattern": r"uh_index_add\s*\(",
            "bound": "defaults plus finite startup configuration/CLI index entries",
        },
    }
    contract = contracts.get(function)
    if contract is None:
        raise RuleNotApplicable("allocation is not in a registered startup collection")
    assignment = re.search(
        r"(?P<target>[A-Za-z_]\w*)\s*=\s*(?:calloc|malloc)\s*\(",
        statement,
    )
    if assignment is None or assignment.group("target") not in contract["targets"]:
        raise RuleNotApplicable("startup allocation target does not match its collection")
    source_text = "\n".join(lines)
    if not all(re.search(pattern, source_text, re.DOTALL) for pattern in contract["current"]):
        raise RuleNotApplicable("startup collection insertion/bound does not match")
    caller = _contained_file(
        context.root,
        Path(source["source_root"]) / str(contract["caller"]),
        "startup allocation caller source",
    )
    caller_text = _read_source_text(caller)
    if re.search(str(contract["caller_pattern"]), caller_text, re.DOTALL) is None:
        raise RuleNotApplicable("allocation function is not bound to the startup caller")
    caller_ref = {
        "path": _relative_if_contained(context.root, caller),
        "sha256": _sha256_file(caller),
        "kind": "source_review",
    }
    source_binding = _source_binding(
        context,
        source,
        source_function=function,
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the allocation is retained only in a finite startup-populated process-lifetime collection",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": function,
            "line": line_number,
            "statement": statement,
        },
        "additional_source_refs": [caller_ref],
        "ownership": {
            "allocation": assignment.group("target"),
            "collection_population": "startup only",
            "lifetime": "process lifetime",
            "bound": contract["bound"],
            "repeatable_external_action": False,
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "ownership_lifetime_modeled": True,
            "bounded_lifetime": True,
        },
    }


def _derive_c_sizeof_member_copy(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE":
        raise RuleNotApplicable("candidate operation is not a STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    copy = re.fullmatch(
        r"memcpy\s*\(\s*&(?P<object>[A-Za-z_]\w*)->(?P<field>[A-Za-z_]\w*)\s*,\s*"
        r"(?P<src>.+)\s*,\s*sizeof\s*\(\s*(?P=object)->(?P=field)\s*\)\s*\)\s*;",
        statement,
    )
    if copy is None:
        raise RuleNotApplicable("exact source line is not a sizeof-destination member copy")
    function_prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
    if re.search(
        rf"struct\s+[A-Za-z_]\w*\s*\*\s*{re.escape(copy.group('object'))}\b",
        function_prefix,
    ) is None:
        raise RuleNotApplicable("copy destination is not a typed struct pointer")
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    destination = f"{copy.group('object')}->{copy.group('field')}"
    return {
        "rule_claim": "the copy length is exactly sizeof the typed destination member",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
        },
        "object_layout": {
            "object_identity": f"typed_member:{destination}",
            "capacity_expression": f"sizeof({destination})",
            "write_offset_bytes": 0,
            "write_width_expression": f"sizeof({destination})",
            "proven_relation": "copy width equals destination member capacity",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_strchr_inplace(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("candidate is not a one-byte STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    store = re.fullmatch(r"\*(?P<pointer>[A-Za-z_]\w*)\+*\s*=\s*0\s*;", statement)
    if store is None:
        raise RuleNotApplicable("exact source line is not an in-place pointer byte STORE")
    pointer = store.group("pointer")
    function_prefix = _source_function_prefix(lines, str(frame["function"]), line_number)
    origin = re.search(
        rf"{re.escape(pointer)}\s*=\s*strchr\s*\(\s*(?P<buffer>[A-Za-z_]\w*)\s*,[^;]+\)\s*;",
        function_prefix,
    )
    positive_guard = re.search(rf"if\s*\(\s*{re.escape(pointer)}\s*\)\s*\{{", function_prefix)
    if origin is None or positive_guard is None:
        raise RuleNotApplicable("strchr origin and positive guard do not dominate the STORE")
    buffer_name = origin.group("buffer")
    declaration_ref: dict[str, str] | None = None
    if re.search(
        rf"static\s+[^;\n]+\b{re.escape(buffer_name)}\s*\[[^\]]+\]",
        "\n".join(lines),
    ) is None:
        external = _unique_source_array_definition(source, buffer_name)
        declaration_ref = {
            "path": external["path"],
            "sha256": external["sha256"],
            "kind": "source_review",
        }
    source_binding = _source_binding(
        context,
        source,
        source_function=str(frame["function"]),
        source_lines=[line_number],
    )
    proof = {
        "rule_claim": "strchr returns either null or an address of the matched byte within the source array",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": str(frame["function"]),
            "line": line_number,
            "statement": statement,
            "origin": origin.group(0),
        },
        "object_layout": {
            "object_identity": f"static_array:{buffer_name}",
            "capacity_expression": f"sizeof({buffer_name})",
            "write_offset_expression": f"{pointer} - {buffer_name}",
            "write_width_bytes": 1,
            "proven_relation": "the successful strchr result designates an existing array byte",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }
    if declaration_ref is not None:
        proof["additional_source_refs"] = [declaration_ref]
    return proof


def _derive_c_process_vars_copy(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE":
        raise RuleNotApplicable("candidate operation is not a STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    if str(frame.get("function") or "") != "uh_get_process_vars":
        raise RuleNotApplicable("exact source operation is not in uh_get_process_vars")
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    if statement != "memcpy(&vars[i], extra_vars, sizeof(extra_vars));":
        raise RuleNotApplicable("exact source line is not the extra-vars copy")
    source_text = "\n".join(lines)
    required = (
        r"struct\s+env_var\s*\*vars\s*=\s*\(void \*\)\s*uh_buf\s*;",
        r"len\s*=\s*ARRAY_SIZE\(proc_header_env\)\s*;.*?len\s*\+=\s*ARRAY_SIZE\(extra_vars\)\s*;.*?len\s*\*=\s*sizeof\(struct env_var\)\s*;",
        r"BUILD_BUG_ON\s*\(\s*sizeof\(uh_buf\)\s*<\s*len\s*\)\s*;",
        r"for\s*\(\s*i\s*=\s*0\s*;\s*i\s*<\s*ARRAY_SIZE\(proc_header_env\)\s*;\s*i\+\+\s*\)",
    )
    if not all(re.search(pattern, source_text, re.DOTALL) for pattern in required):
        raise RuleNotApplicable("compile-time destination bound and prefix count do not match")
    source_binding = _source_binding(
        context,
        source,
        source_function="uh_get_process_vars",
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the compile-time buffer assertion covers the header prefix plus the exact extra-vars copy",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "uh_get_process_vars",
            "line": line_number,
            "statement": statement,
        },
        "object_layout": {
            "object_identity": "static_array:uh_buf as struct env_var[]",
            "capacity_expression": "sizeof(uh_buf)",
            "write_offset_expression": "ARRAY_SIZE(proc_header_env) * sizeof(struct env_var)",
            "write_width_expression": "sizeof(extra_vars)",
            "proven_relation": "BUILD_BUG_ON rejects any combined size larger than uh_buf",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_inittab_tags(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE":
        raise RuleNotApplicable("candidate operation is not a STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    if str(frame.get("function") or "") != "procd_inittab":
        raise RuleNotApplicable("exact source operation is not in procd_inittab")
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    if re.fullmatch(r"tags\[i\]\s*=\s*&line\[matches\[i\s*\+\s*1\]\.rm_so\]\s*;", statement) is None:
        raise RuleNotApplicable("exact source line is not the inittab tags STORE")
    function_prefix = _source_function_prefix(lines, "procd_inittab", line_number)
    required = (
        r"char\s*\*tags\s*\[\s*TAG_PROCESS\s*\+\s*1\s*\]\s*;",
        r"for\s*\(\s*i\s*=\s*TAG_ID\s*;\s*i\s*<=\s*TAG_PROCESS\s*;\s*i\+\+\s*\)",
    )
    if not all(re.search(pattern, function_prefix) for pattern in required):
        raise RuleNotApplicable("tags capacity and inclusive enum loop do not match")
    source_binding = _source_binding(
        context,
        source,
        source_function="procd_inittab",
        source_lines=[line_number],
    )
    return {
        "rule_claim": "the enum-bounded loop indexes a TAG_PROCESS+1 element local array",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "procd_inittab",
            "line": line_number,
            "statement": statement,
        },
        "object_layout": {
            "object_identity": "automatic_array:tags",
            "capacity_expression": "TAG_PROCESS + 1",
            "write_index_expression": "i",
            "write_width_bytes": int(context.binding.get("width_bytes") or 0),
            "proven_relation": "TAG_ID <= i <= TAG_PROCESS < TAG_PROCESS + 1",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_c_urldecode(context: CampaignContext) -> dict[str, Any]:
    vulnerability_type = str(context.state.get("vulnerability_type") or "")
    if vulnerability_type not in SPATIAL_TYPES | {"null_pointer_dereference"}:
        raise RuleNotApplicable("candidate is not a spatial or null URL-decoder access")
    if str(context.binding.get("pcode") or "") != "STORE" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("candidate is not a one-byte STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    if str(frame.get("function") or "") != "uh_urldecode":
        raise RuleNotApplicable("exact source operation is not in uh_urldecode")
    lines = source["lines"]
    line_number = int(frame["line"])
    statement = lines[line_number - 1].strip()
    if statement != "buf[len] = 0;":
        raise RuleNotApplicable("exact source line is not the URL-decode terminator")
    source_text = "\n".join(lines)
    if re.search(r"for\s*\([^;]+;\s*\(i\s*<\s*slen\)\s*&&\s*\(len\s*<\s*blen\)", source_text) is None:
        raise RuleNotApplicable("decode loop no longer caps output length at blen")
    caller_refs: list[dict[str, str]] = []
    caller_contracts = {
        "main.c": (
            r"port\s*=\s*alloca\s*\(\s*strlen\(optarg\)\s*\+\s*1\s*\)",
            r"uh_urldecode\s*\(\s*port\s*,\s*opt\s*,\s*optarg\s*,\s*opt\s*\)",
        ),
        "file.c": (
            r"uh_urldecode\s*\(\s*&uh_buf\[docroot_len\]\s*,\s*sizeof\(uh_buf\)\s*-\s*docroot_len\s*-\s*1",
        ),
    }
    for name, patterns in caller_contracts.items():
        caller = _contained_file(
            context.root,
            Path(source["source_root"]) / name,
            "URL-decode caller source",
        )
        caller_text = _read_source_text(caller)
        if not all(re.search(pattern, caller_text, re.DOTALL) for pattern in patterns):
            raise RuleNotApplicable(f"URL-decode caller capacity changed in {name}")
        caller_refs.append(
            {
                "path": _relative_if_contained(context.root, caller),
                "sha256": _sha256_file(caller),
                "kind": "source_review",
            }
        )
    source_binding = _source_binding(
        context,
        source,
        source_function="uh_urldecode",
        source_lines=[line_number],
    )
    claims = {
        "exact_operation": True,
        "source_or_binary_binding": True,
    }
    if vulnerability_type in SPATIAL_TYPES:
        claims.update(
            {
                "exact_store": True,
                "object_identity": True,
                "capacity": True,
                "offset_relation": True,
                "bounds_proven": True,
            }
        )
    else:
        claims.update(
            {
                "exact_zero_capable_access": True,
                "dominating_non_null": True,
            }
        )
    return {
        "rule_claim": "every frozen caller reserves one byte beyond blen for the decoder terminator",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "uh_urldecode",
            "line": line_number,
            "statement": statement,
        },
        "additional_source_refs": caller_refs,
        "object_layout": {
            "object_identity": "caller-provided decode buffer",
            "capacity_expression": "blen + 1 or greater at every call site",
            "write_offset_expression": "len",
            "write_width_bytes": 1,
            "proven_relation": "0 <= len <= blen < caller buffer capacity",
        },
        "claims": claims,
    }


def _derive_c_substring_index(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "null_pointer_dereference":
        raise RuleNotApplicable("candidate is not a null-dereference candidate")
    if str(context.binding.get("pcode") or "") != "LOAD" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("exact operation is not a one-byte LOAD")
    source = _exact_source_context(context)
    frame = source["frame"]
    if str(frame.get("function") or "") != "client_parse_header":
        raise RuleNotApplicable("exact source function is not client_parse_header")
    line_number = int(frame["line"])
    statement = source["lines"][line_number - 1].strip()
    if statement != "if (str[5] && str[6] == '.') {":
        raise RuleNotApplicable("exact source line is not the guarded substring suffix test")
    prefix = _source_function_prefix(source["lines"], "client_parse_header", line_number)
    origin = '(str = strstr(val, "MSIE ")) != NULL'
    if origin not in prefix:
        raise RuleNotApplicable("substring success guard no longer dominates the indexed LOAD")
    source_binding = _source_binding(
        context, source, source_function="client_parse_header", source_lines=[line_number]
    )
    return {
        "rule_claim": "a successful five-byte substring match makes index 5 valid, and short-circuit evaluation guards index 6",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "client_parse_header",
            "line": line_number,
            "statement": statement,
            "origin_guard": origin,
        },
        "non_null_proof": {
            "pointer": "str",
            "matched_literal_bytes": 5,
            "path_coverage": "strstr success proves str[0..4] exist and str[5] is at least the terminating byte; str[6] is evaluated only if str[5] is nonzero",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_zero_capable_access": True,
            "dominating_non_null": True,
        },
    }


def _derive_c_static_table_index(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    if str(context.binding.get("pcode") or "") != "PTRADD":
        raise RuleNotApplicable("exact operation is not an indexed PTRADD")
    source = _exact_source_context(context)
    frame = source["frame"]
    if str(frame.get("function") or "") != "rule_handle_command":
        raise RuleNotApplicable("exact source function is not rule_handle_command")
    line_number = int(frame["line"])
    statement = source["lines"][line_number - 1].strip()
    if statement != "if (handlers[i].atomic)":
        raise RuleNotApplicable("exact source line is not the handlers table access")
    source_text = "\n".join(source["lines"])
    prefix = _source_function_prefix(source["lines"], "rule_handle_command", line_number)
    if "} handlers[] = {" not in source_text or not re.search(
        r"for\s*\(\s*i\s*=\s*0\s*;\s*i\s*<\s*ARRAY_SIZE\(handlers\)\s*;\s*i\+\+\s*\)",
        prefix,
    ):
        raise RuleNotApplicable("static table definition or complete loop initializer changed")
    source_binding = _source_binding(
        context, source, source_function="rule_handle_command", source_lines=[line_number]
    )
    return {
        "rule_claim": "the loop initializer defines i and ARRAY_SIZE bounds every indexed access to the initialized static handlers table",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "rule_handle_command",
            "line": line_number,
            "statement": statement,
        },
        "initialization": {
            "variable": "i",
            "initializer": "i = 0",
            "upper_bound": "ARRAY_SIZE(handlers)",
            "object": "static initialized handlers[]",
            "path_coverage": "the for initializer executes before every loop-body PTRADD",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "all_path_initialization": True,
        },
    }


def _derive_c_find_idx(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "null_pointer_dereference":
        raise RuleNotApplicable("candidate is not a null-dereference candidate")
    if str(context.binding.get("pcode") or "") != "LOAD":
        raise RuleNotApplicable("exact operation is not a LOAD")
    source = _exact_source_context(context)
    frame = source["frame"]
    if str(frame.get("function") or "") != "find_idx":
        raise RuleNotApplicable("exact source function is not find_idx")
    line_number = int(frame["line"])
    statement = source["lines"][line_number - 1].strip()
    if statement != "if (!strcmp(list[i], str))":
        raise RuleNotApplicable("exact source line is not the find_idx list access")
    source_text = "\n".join(source["lines"])
    calls = re.findall(r"find_idx\s*\(([^;]+)\)\s*;", source_text)
    expected = {
        "http_methods, ARRAY_SIZE(http_methods), type",
        "http_versions, ARRAY_SIZE(http_versions), version",
    }
    normalized = {" ".join(call.split()) for call in calls}
    if normalized != expected:
        raise RuleNotApplicable("the complete static find_idx caller set changed")
    if not all(
        token in source_text
        for token in (
            "const char * const http_versions[] = {",
            "const char * const http_methods[] = {",
            "if (!type || !path || !version)",
        )
    ):
        raise RuleNotApplicable("caller array definitions or token guard changed")
    source_binding = _source_binding(
        context, source, source_function="find_idx", source_lines=[line_number]
    )
    return {
        "rule_claim": "the static helper has exactly two callers, both passing non-null static arrays with their ARRAY_SIZE and checked string tokens",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "find_idx",
            "line": line_number,
            "statement": statement,
        },
        "non_null_proof": {
            "pointer": "list",
            "callers": sorted(expected),
            "path_coverage": "all calls to the static helper use language-level arrays and the loop is bounded by the matching array size",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_zero_capable_access": True,
            "dominating_non_null": True,
        },
    }


def _derive_musl_errno(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "null_pointer_dereference":
        raise RuleNotApplicable("candidate is not a null-dereference candidate")
    if str(context.binding.get("pcode") or "") != "LOAD" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("exact operation is not the compiler switch-table byte LOAD")
    source = _exact_source_context(context)
    frame = source["frame"]
    line_number = int(frame["line"])
    statement = source["lines"][line_number - 1].strip()
    if str(frame.get("function") or "") != "service_handle_kill" or statement != "switch (errno) {":
        raise RuleNotApplicable("exact source is not the errno switch")
    disassembly = _disassembly_window(context, before=64, after=8)
    if "<__errno_location@Base>" not in disassembly or "<CSWTCH." not in disassembly:
        raise RuleNotApplicable("binary operation is not the bounded compiler switch table")
    source_binding = _source_binding(
        context, source, source_function="service_handle_kill", source_lines=[line_number]
    )
    return {
        "rule_claim": "the exact LOAD addresses a compiler-emitted static switch table after a range guard, not a nullable source pointer",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "service_handle_kill",
            "line": line_number,
            "statement": statement,
        },
        "binary_topology": {
            "disassembly": disassembly,
            "object": "CSWTCH static read-only table",
            "guard": "unsigned range comparison branches around the table LOAD",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_zero_capable_access": True,
            "semantics_absent": True,
        },
    }


def _derive_c_dirlist_file(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("exact operation is not a one-byte STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    line_number = int(frame["line"])
    statement = source["lines"][line_number - 1].strip()
    if str(frame.get("function") or "") != "list_entries" or statement != "*file = 0;":
        raise RuleNotApplicable("exact source is not the directory-list terminator")
    source_text = "\n".join(source["lines"])
    required = (
        "file = local_path + local_path_len;",
        'snprintf(file, max_name_len, "%s", name);',
        "if (path_len > 0 && path_len < sizeof(uh_buf))",
        "path_len, sizeof(uh_buf) - path_len);",
    )
    if not all(item in source_text for item in required):
        raise RuleNotApplicable("directory-list caller capacity contract changed")
    if len(re.findall(r"\blist_entries\s*\(", source_text)) != 2:
        raise RuleNotApplicable("list_entries no longer has one definition and one call")
    source_binding = _source_binding(
        context, source, source_function="list_entries", source_lines=[line_number]
    )
    return {
        "rule_claim": "the sole caller proves local_path_len is below uh_buf capacity before deriving file and the remaining snprintf capacity",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "list_entries",
            "line": line_number,
            "statement": statement,
        },
        "object_layout": {
            "object_identity": "static array uh_buf[4096] via local_path",
            "capacity_expression": "sizeof(uh_buf)",
            "write_offset_expression": "local_path_len",
            "write_width_bytes": 1,
            "proven_relation": "0 < local_path_len < sizeof(uh_buf)",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_musl_glob(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    if str(context.binding.get("pcode") or "") != "CAST":
        raise RuleNotApplicable("exact operation is not the glob result CAST")
    source = _exact_source_context(context)
    frame = source["frame"]
    line_number = int(frame["line"])
    statement = source["lines"][line_number - 1].strip()
    if str(frame.get("function") or "") != "init_ca_cert" or "gl.gl_pathv[i]" not in statement:
        raise RuleNotApplicable("exact source is not the glob path-vector use")
    prefix = _source_function_prefix(source["lines"], "init_ca_cert", line_number)
    if 'glob("/etc/ssl/certs/*.crt", 0, NULL, &gl);' not in prefix:
        raise RuleNotApplicable("glob call no longer uses non-append flags and the same output")
    mapping = _mapping(source.get("mapping"))
    sdk_ref = _mapping(mapping.get("sdk"))
    sdk_archive = _contained_file(
        context.root, str(sdk_ref.get("path") or ""), "OpenWrt SDK archive"
    )
    if _sha256_file(sdk_archive) != OPENWRT_24_10_4_X86_64_SDK_SHA256:
        raise CertificateError("glob contract is not bound to the pinned SDK")
    sdk_root = sdk_archive.with_name(sdk_archive.name[: -len(".tar.zst")])
    info = _contained_file(
        context.root,
        next((sdk_root / "staging_dir").glob("toolchain-*/info.mk")),
        "SDK toolchain info",
    )
    if "LIBC_VERSION=1.2.5" not in _read_source_text(info):
        raise CertificateError("SDK toolchain no longer pins musl 1.2.5")
    musl_archive = _contained_file(
        context.root,
        "reference-sources/musl/musl-1.2.5.tar.gz",
        "musl source archive",
    )
    if _sha256_file(musl_archive) != MUSL_1_2_5_SHA256:
        raise CertificateError("musl 1.2.5 source archive hash changed")
    with tarfile.open(musl_archive, "r:gz") as archive:
        member = archive.getmember("musl-1.2.5/src/regex/glob.c")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise CertificateError("musl archive glob.c is unreadable")
        glob_source = extracted.read()
    glob_text = glob_source.decode("utf-8")
    initialization = re.search(
        r"if\s*\(\s*!\(flags\s*&\s*GLOB_APPEND\)\s*\)\s*\{[^}]*"
        r"g->gl_pathc\s*=\s*0\s*;[^}]*g->gl_pathv\s*=\s*NULL\s*;",
        glob_text,
        re.DOTALL,
    )
    if initialization is None:
        raise CertificateError("musl glob no longer initializes non-append output first")
    source_binding = _source_binding(
        context, source, source_function="init_ca_cert", source_lines=[line_number]
    )
    return {
        "rule_claim": "pinned musl initializes gl_pathc and gl_pathv before every non-append glob result, including errors",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "init_ca_cert",
            "line": line_number,
            "statement": statement,
        },
        "additional_source_refs": [
            {
                "path": _relative_if_contained(context.root, info),
                "sha256": _sha256_file(info),
                "kind": "source_review",
            },
            {
                "path": _relative_if_contained(context.root, musl_archive),
                "sha256": _sha256_file(musl_archive),
                "kind": "source_review",
            },
        ],
        "dependency_contract": {
            "implementation": "musl 1.2.5 src/regex/glob.c",
            "member_sha256": hashlib.sha256(glob_source).hexdigest(),
            "initialization": " ".join(initialization.group(0).split()),
            "flags": 0,
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "all_path_initialization": True,
        },
    }


def _derive_c_typed_member(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE":
        raise RuleNotApplicable("exact operation is not a STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    line_number = int(frame["line"])
    statement = source["lines"][line_number - 1].strip()
    if str(frame.get("function") or "") != "progress_update" or statement != "p->last_update_sec = elapsed;":
        raise RuleNotApplicable("exact source is not the progress structure member STORE")
    header = _contained_file(
        context.root,
        Path(source["source_root"]) / "progress.h",
        "progress structure header",
    )
    header_text = _read_source_text(header)
    if not re.search(
        r"struct\s+progress\s*\{[^}]*unsigned\s+int\s+last_update_sec\s*;[^}]*\}",
        header_text,
        re.DOTALL,
    ):
        raise RuleNotApplicable("typed member definition changed")
    callers = _contained_file(
        context.root,
        Path(source["source_root"]) / "uclient-fetch.c",
        "progress caller source",
    )
    caller_text = _read_source_text(callers)
    if "static struct progress pmt;" not in caller_text or "progress_update(&pmt," not in caller_text:
        raise RuleNotApplicable("progress_update caller no longer passes the static object")
    source_binding = _source_binding(
        context, source, source_function="progress_update", source_lines=[line_number]
    )
    return {
        "rule_claim": "the exact four-byte STORE targets the declared unsigned member of the sole static struct progress caller object",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "progress_update",
            "line": line_number,
            "statement": statement,
        },
        "additional_source_refs": [
            {"path": _relative_if_contained(context.root, header), "sha256": _sha256_file(header), "kind": "source_review"},
            {"path": _relative_if_contained(context.root, callers), "sha256": _sha256_file(callers), "kind": "source_review"},
        ],
        "object_layout": {
            "object_identity": "static struct progress pmt",
            "capacity_expression": "sizeof(pmt.last_update_sec)",
            "write_offset_expression": "offsetof(struct progress, last_update_sec)",
            "write_width_bytes": 4,
            "proven_relation": "the compiler STORE width equals the declared unsigned int member width",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "bounds_proven": True,
        },
    }


def _derive_libubox_json_abort(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") not in SPATIAL_TYPES:
        raise RuleNotApplicable("candidate is not spatial")
    if str(context.binding.get("pcode") or "") != "STORE" or int(
        context.binding.get("width_bytes") or 0
    ) != 1:
        raise RuleNotApplicable("exact operation is not a one-byte STORE")
    source = _exact_source_context(context)
    frame = source["frame"]
    line_number = int(frame["line"])
    statement = source["lines"][line_number - 1].strip()
    if str(frame.get("function") or "") != "handle_redirect" or statement != "json_script_abort(ctx);":
        raise RuleNotApplicable("exact source is not the inlined json_script_abort call")
    disassembly = _disassembly_window(context, before=16, after=8)
    if not re.search(r"movb\s+\$0x1,0x54\(%rbp\)", disassembly):
        raise RuleNotApplicable("exact STORE is not the inlined abort member assignment")
    mapping = _mapping(source.get("mapping"))
    sdk_archive = _contained_file(
        context.root,
        str(_mapping(mapping.get("sdk")).get("path") or ""),
        "OpenWrt SDK archive",
    )
    if _sha256_file(sdk_archive) != OPENWRT_24_10_4_X86_64_SDK_SHA256:
        raise CertificateError("json_script contract is not bound to the pinned SDK")
    sdk_root = sdk_archive.with_name(sdk_archive.name[: -len(".tar.zst")])
    headers = sorted((sdk_root / "staging_dir").glob("target-*/usr/include/libubox/json_script.h"))
    if len(headers) != 1:
        raise CertificateError("pinned SDK lacks one target json_script.h")
    header = _contained_file(context.root, headers[0], "json_script header")
    header_text = _read_source_text(header)
    if "bool abort;" not in header_text or not re.search(
        r"json_script_abort\s*\([^)]*ctx\)\s*\{\s*ctx->abort\s*=\s*true\s*;\s*\}",
        header_text,
        re.DOTALL,
    ):
        raise CertificateError("json_script abort member contract changed")
    source_binding = _source_binding(
        context, source, source_function="handle_redirect", source_lines=[line_number]
    )
    return {
        "rule_claim": "the exact STORE is the pinned inline assignment to json_script_ctx.abort, not an array write",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "handle_redirect",
            "line": line_number,
            "statement": statement,
        },
        "additional_source_refs": [
            {"path": _relative_if_contained(context.root, header), "sha256": _sha256_file(header), "kind": "source_review"}
        ],
        "object_layout": {
            "object_identity": "struct json_script_ctx.abort",
            "capacity_expression": "sizeof(ctx->abort)",
            "write_offset_bytes": 84,
            "write_width_bytes": 1,
            "proven_relation": "the exact offset and width are the pinned bool abort member",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_store": True,
            "object_identity": True,
            "capacity": True,
            "offset_relation": True,
            "semantics_absent": True,
        },
    }


def _derive_c_trusted_allocation(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "null_pointer_dereference":
        raise RuleNotApplicable("candidate is not a null-dereference candidate")
    source = _exact_source_context(context)
    frame = source["frame"]
    function = str(frame.get("function") or "")
    line_number = int(frame["line"])
    statement = source["lines"][line_number - 1].strip()
    specifications = {
        "procd_inittab": {
            "statement": "a->argv[i] = NULL;",
            "required": ("void procd_inittab(void)", "a = calloc(1, sizeof(struct init_action));"),
            "boundary": "privileged boot-time inittab file",
        },
        "watch_add": {
            "statement": "list_add(&o->list, &watch_objects);",
            "required": ("watch_add(const char *_name, void *id)", "struct watch_object *o = calloc_a(sizeof(*o),"),
            "boundary": "privileged procd service-instance control plane",
        },
        "uh_interpreter_add": {
            "statement": "in->ext = strcpy(new_ext, ext);",
            "required": ("uh_interpreter_add(const char *ext, const char *path)", "in = calloc_a(sizeof(*in),"),
            "boundary": "privileged uhttpd startup configuration",
        },
    }
    specification = specifications.get(function)
    if specification is None or statement != specification["statement"]:
        raise RuleNotApplicable("exact source is not a registered trusted allocation site")
    source_text = "\n".join(source["lines"])
    if not all(item in source_text for item in specification["required"]):
        raise RuleNotApplicable("trusted allocation topology changed")
    caller_refs: list[dict[str, str]] = []
    if function == "watch_add":
        caller = _contained_file(
            context.root,
            Path(source["source_root"]) / "service" / "instance.c",
            "watch_add caller",
        )
        if len(re.findall(r"\bwatch_add\s*\(", _read_source_text(caller))) != 1:
            raise RuleNotApplicable("watch_add caller enumeration changed")
        caller_refs.append({"path": _relative_if_contained(context.root, caller), "sha256": _sha256_file(caller), "kind": "trust_boundary_review"})
    elif function == "uh_interpreter_add":
        caller = _contained_file(
            context.root, Path(source["source_root"]) / "main.c", "interpreter callers"
        )
        if len(re.findall(r"\buh_interpreter_add\s*\(", _read_source_text(caller))) != 2:
            raise RuleNotApplicable("interpreter caller enumeration changed")
        caller_refs.append({"path": _relative_if_contained(context.root, caller), "sha256": _sha256_file(caller), "kind": "trust_boundary_review"})
    source_binding = _source_binding(
        context, source, source_function=function, source_lines=[line_number]
    )
    return {
        "rule_claim": "the allocation site is reachable only from an enumerated privileged startup or service-control boundary, not attacker input",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": function,
            "line": line_number,
            "statement": statement,
        },
        "additional_source_refs": caller_refs,
        "trust_boundary": {
            "mode": specification["boundary"],
            "allocation_size_control": "constant structure size plus trusted configuration strings",
            "entry_enumeration": "all shipped callers are startup or privileged control-plane paths",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_zero_capable_access": True,
            "trust_boundary_modeled": True,
            "intended_effect": True,
            "no_security_boundary": True,
        },
    }


def _derive_c_client_context(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "null_pointer_dereference":
        raise RuleNotApplicable("candidate is not a null-dereference candidate")
    source = _exact_source_context(context)
    frame = source["frame"]
    line_number = int(frame["line"])
    statement = source["lines"][line_number - 1].strip()
    if str(frame.get("function") or "") != "uh_http_header" or not statement.startswith("ustream_printf(cl->us,"):
        raise RuleNotApplicable("exact source is not the live client stream access")
    source_root = Path(source["source_root"])
    call_refs: list[dict[str, str]] = []
    call_count = 0
    for path in sorted(source_root.glob("*.c")):
        text = _read_source_text(path)
        calls = re.findall(r"(?:uh_|ops->)http_header\s*\(\s*([^,]+),", text)
        if not calls:
            continue
        normalized_calls = [" ".join(argument.split()) for argument in calls]
        actual_calls = [
            argument for argument in normalized_calls if argument != "struct client *cl"
        ]
        if any(argument != "cl" for argument in actual_calls):
            raise RuleNotApplicable("a shipped http_header caller does not pass its live client")
        call_count += len(actual_calls)
        call_refs.append({"path": _relative_if_contained(context.root, path), "sha256": _sha256_file(path), "kind": "source_review"})
    if call_count != 13:
        raise RuleNotApplicable(f"shipped http_header call enumeration changed ({call_count})")
    client_source = "\n".join(source["lines"])
    if not all(
        item in client_source
        for item in (
            "next_client = calloc(1, sizeof(*next_client));",
            "if (!next_client)",
            "struct client *cl = container_of(s, struct client, sfd.stream);",
        )
    ):
        raise RuleNotApplicable("client allocation or callback recovery contract changed")
    source_binding = _source_binding(
        context, source, source_function="uh_http_header", source_lines=[line_number]
    )
    return {
        "rule_claim": "every shipped direct/plugin caller passes its live client object, whose allocation is checked before callback registration",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "uh_http_header",
            "line": line_number,
            "statement": statement,
        },
        "additional_source_refs": call_refs,
        "non_null_proof": {
            "pointer": "cl",
            "enumerated_call_count": call_count,
            "path_coverage": "checked allocation creates the client and registered callbacks recover that containing live object",
        },
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "exact_zero_capable_access": True,
            "dominating_non_null": True,
        },
    }


def _derive_libubox_blobmsg_value(context: CampaignContext) -> dict[str, Any]:
    if str(context.state.get("vulnerability_type") or "") != "uninitialized_memory_use":
        raise RuleNotApplicable("candidate is not an uninitialized-use candidate")
    if str(context.binding.get("pcode") or "") != "LOAD" or int(
        context.binding.get("width_bytes") or 0
    ) != 4:
        raise RuleNotApplicable("exact operation is not the four-byte blob value LOAD")
    source = _exact_source_context(context)
    frame = source["frame"]
    if str(frame.get("function") or "") != "handle_redirect":
        raise RuleNotApplicable("exact source function is not handle_redirect")
    source_text = "\n".join(source["lines"])
    required = (
        "struct blob_attr *tb[3];",
        "blobmsg_parse_array(policy, ARRAY_SIZE(policy), tb,",
        "if (tb[1]) {",
        "code = blobmsg_get_u32(tb[1]);",
    )
    if not all(item in source_text for item in required):
        raise RuleNotApplicable("guarded blobmsg value topology changed")
    disassembly = _disassembly_window(context, before=24, after=8)
    if "<blobmsg_data>" not in disassembly or not re.search(r"mov\s+\(%rax\),%esi", disassembly):
        raise RuleNotApplicable("exact LOAD is not fed by the guarded blobmsg_data result")
    dependency = _libubox_blobmsg_contract(
        context, _mapping(source.get("mapping")), function="blobmsg_parse_array"
    )
    source_binding = _source_binding(
        context, source, source_function="handle_redirect", source_lines=[53, 57, 58]
    )
    return {
        "rule_claim": "the exact LOAD consumes guarded blobmsg_data from an initialized parser table, not the alleged uninitialized local",
        "operation_address": str(context.binding.get("address") or ""),
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": "handle_redirect",
            "lines": [53, 57, 58],
            "statement": "if (tb[1]) code = blobmsg_get_u32(tb[1]);",
        },
        "dependency_contract": dependency,
        "additional_source_refs": [dependency["package_makefile"], dependency["source_archive"]],
        "binary_topology": {"disassembly": disassembly, "value_source": "blobmsg_data(tb[1])"},
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "semantics_absent": True,
        },
    }


def _derive_c_process_split_lifetime(context: CampaignContext) -> dict[str, Any]:
    vulnerability_type = str(context.state.get("vulnerability_type") or "")
    if vulnerability_type not in {"double_close", "use_after_close"}:
        raise RuleNotApplicable("candidate is not a descriptor-lifetime candidate")
    first_address = str(_mapping(context.state.get("source")).get("operation_address") or "")
    if not first_address:
        raise RuleNotApplicable("candidate has no exact first lifetime operation")
    sink_address = str(context.binding.get("address") or "")
    first_contexts = _source_contexts_for_operation(context, first_address)
    sink_contexts = _source_contexts_for_operation(context, sink_address)

    matches: list[tuple[int, int, int, dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for first_index, first in enumerate(first_contexts):
        for sink_index, sink in enumerate(sink_contexts):
            if Path(first["source_path"]) != Path(sink["source_path"]):
                continue
            first_frame = _mapping(first.get("frame"))
            sink_frame = _mapping(sink.get("frame"))
            if str(first_frame.get("function") or "") != str(
                sink_frame.get("function") or ""
            ):
                continue
            first_line = int(first_frame.get("line") or 0)
            sink_line = int(sink_frame.get("line") or 0)
            classification = _classify_process_split(
                first["lines"], first_line=first_line, sink_line=sink_line
            )
            if classification is not None:
                matches.append(
                    (
                        first_index + sink_index,
                        first_index,
                        sink_index,
                        first,
                        sink,
                        classification,
                    )
                )
    if not matches:
        raise RuleNotApplicable(
            "exact source does not prove a process split or terminating first-operation path"
        )
    _, _, _, first, sink, control_flow = min(matches, key=lambda item: item[:3])
    first_frame = _mapping(first.get("frame"))
    sink_frame = _mapping(sink.get("frame"))
    first_line = int(first_frame["line"])
    sink_line = int(sink_frame["line"])
    evidence_lines = sorted(
        {
            first_line,
            sink_line,
            *(int(item) for item in control_flow.get("evidence_lines", [])),
        }
    )
    source_function = str(first_frame.get("function") or "")
    source_binding = _source_binding(
        context,
        first,
        source_function=source_function,
        source_lines=evidence_lines,
    )
    process_contract: dict[str, Any] | None = None
    additional_refs: list[dict[str, str]] = []
    if str(control_flow.get("kind") or "") in {"fork_if_child", "fork_switch_child"}:
        process_contract = _sdk_process_contract(
            context,
            _mapping(first.get("mapping")),
            require_exec=bool(control_flow.get("exec_function")),
        )
        additional_refs.extend(
            [process_contract["sdk_archive"], process_contract["process_header"]]
        )

    first_exact = first_contexts[0]
    sink_exact = sink_contexts[0]
    first_exact_frame = _mapping(first_exact.get("frame"))
    sink_exact_frame = _mapping(sink_exact.get("frame"))
    proof: dict[str, Any] = {
        "rule_claim": (
            "the first and later descriptor operations are mutually exclusive across "
            "a child/parent process split"
            if process_contract is not None
            else "the first descriptor operation is followed by a verified non-returning error path"
        ),
        "operation_address": sink_address,
        "source_binding": source_binding,
        "source_excerpt": {
            "path": source_binding["source_path"],
            "sha256": source_binding["source_sha256"],
            "function": source_function,
            "lines": evidence_lines,
            "statements": [
                first["lines"][line - 1].strip()
                for line in evidence_lines
                if 0 < line <= len(first["lines"])
            ],
        },
        "exact_lifetime_operations": {
            "first": {
                "address": first_address,
                "source_path": _relative_if_contained(
                    context.root, Path(first_exact["source_path"])
                ),
                "function": str(first_exact_frame.get("function") or ""),
                "line": int(first_exact_frame.get("line") or 0),
            },
            "later": {
                "address": sink_address,
                "source_path": _relative_if_contained(
                    context.root, Path(sink_exact["source_path"])
                ),
                "function": str(sink_exact_frame.get("function") or ""),
                "line": int(sink_exact_frame.get("line") or 0),
            },
        },
        "control_flow": control_flow,
        "additional_source_refs": additional_refs,
        "claims": {
            "exact_operation": True,
            "source_or_binary_binding": True,
            "resource_lifetime_modeled": True,
            "mutually_exclusive_paths": process_contract is not None,
            "terminating_path": process_contract is None,
        },
    }
    if process_contract is not None:
        proof["process_contract"] = process_contract
    return proof


def _classify_process_split(
    lines: Sequence[str],
    *,
    first_line: int,
    sink_line: int,
) -> dict[str, Any] | None:
    """Conservatively recognize source shapes that separate lifetime events."""

    if not (0 < first_line < sink_line <= len(lines)):
        return None
    pairs = _c_brace_pairs(lines)

    # A direct fork switch has a child case containing the first event and a
    # distinct parent/default case containing the later event.  The child must
    # either replace its process image or return on exec failure.
    for open_line, close_line in pairs:
        if not (open_line <= first_line < sink_line <= close_line):
            continue
        header_start, header = _c_block_header(lines, open_line)
        if not re.search(r"\bswitch\s*\([^)]*\bfork\s*\(", header, re.DOTALL):
            continue
        case_zero = _first_matching_line(lines, open_line, first_line, r"^\s*case\s+0\s*:")
        default = _first_matching_line(lines, first_line + 1, sink_line, r"^\s*default\s*:")
        if case_zero is None or default is None:
            continue
        child_text = "\n".join(lines[first_line - 1 : default - 1])
        exec_match = re.search(r"\b(exec(?:l|v|le|ve|lp|vp))\s*\(", child_text)
        if exec_match is None or not re.search(r"\breturn\b", child_text[exec_match.end() :]):
            continue
        exec_line = first_line + child_text[: exec_match.start()].count("\n")
        return_line = first_line + child_text[: child_text.rfind("return")].count("\n")
        return {
            "kind": "fork_switch_child",
            "fork_function": "fork",
            "exec_function": exec_match.group(1),
            "child_case_line": case_zero,
            "parent_case_line": default,
            "switch_header_start_line": header_start,
            "switch_open_line": open_line,
            "switch_close_line": close_line,
            "exec_line": exec_line,
            "failure_return_line": return_line,
            "reason": (
                "fork returns zero only in the child; successful exec replaces that process, "
                "and exec failure returns before the parent/default operations"
            ),
            "evidence_lines": [
                header_start,
                case_zero,
                first_line,
                exec_line,
                return_line,
                default,
                sink_line,
            ],
        }

    # A braced `if (fork-wrapper(...) == 0)` child path must terminate through
    # a source-declared NORETURN function before control can reach parent code.
    for open_line, close_line in pairs:
        if not (open_line <= first_line <= close_line < sink_line):
            continue
        header_start, header = _c_block_header(lines, open_line)
        if not re.search(r"\bif\s*\(", header):
            continue
        fork_match = re.search(r"\b(fork\w*)\s*\([^;]*\)\s*==\s*0", header, re.DOTALL)
        if fork_match is None:
            continue
        terminal = _noreturn_call_after(lines, first_line, close_line)
        if terminal is None:
            continue
        wrapper = None
        fork_function = fork_match.group(1)
        if fork_function != "fork":
            wrapper = _fork_wrapper_contract(lines, fork_function)
            if wrapper is None:
                continue
        evidence_lines = [
            header_start,
            first_line,
            int(terminal["call_line"]),
            int(terminal["declaration_line"]),
            close_line,
            sink_line,
        ]
        if terminal.get("macro_line"):
            evidence_lines.append(int(terminal["macro_line"]))
        if wrapper is not None:
            evidence_lines.extend(int(item) for item in wrapper["evidence_lines"])
        return {
            "kind": "fork_if_child",
            "fork_function": fork_function,
            "child_if_header_start_line": header_start,
            "child_open_line": open_line,
            "child_close_line": close_line,
            "terminal": terminal,
            "fork_wrapper": wrapper,
            "reason": (
                "the zero fork result selects only the child, and a source-declared "
                "NORETURN call prevents the child from reaching the later parent operation"
            ),
            "evidence_lines": evidence_lines,
        }

    # An earlier event in a completed conditional cannot reach a later event
    # when every suffix of that conditional calls a source-declared NORETURN
    # routine (directly or through a macro).
    for open_line, close_line in pairs:
        if not (open_line <= first_line <= close_line < sink_line):
            continue
        header_start, header = _c_block_header(lines, open_line)
        if not re.search(r"\bif\s*\(", header):
            continue
        terminal = _noreturn_call_after(lines, first_line, close_line)
        if terminal is None:
            continue
        evidence_lines = [
            header_start,
            first_line,
            int(terminal["call_line"]),
            int(terminal["declaration_line"]),
            close_line,
            sink_line,
        ]
        if terminal.get("macro_line"):
            evidence_lines.append(int(terminal["macro_line"]))
        return {
            "kind": "terminating_error_block",
            "if_header_start_line": header_start,
            "block_open_line": open_line,
            "block_close_line": close_line,
            "terminal": terminal,
            "reason": "the first operation's conditional path terminates before the later operation",
            "evidence_lines": evidence_lines,
        }
    return None


def _c_brace_pairs(lines: Sequence[str]) -> list[tuple[int, int]]:
    stack: list[int] = []
    pairs: list[tuple[int, int]] = []
    in_block_comment = False
    for line_number, raw_line in enumerate(lines, start=1):
        index = 0
        in_string = ""
        while index < len(raw_line):
            char = raw_line[index]
            following = raw_line[index + 1] if index + 1 < len(raw_line) else ""
            if in_block_comment:
                if char == "*" and following == "/":
                    in_block_comment = False
                    index += 2
                    continue
                index += 1
                continue
            if not in_string and char == "/" and following == "*":
                in_block_comment = True
                index += 2
                continue
            if not in_string and char == "/" and following == "/":
                break
            if char in {'"', "'"}:
                if in_string == char:
                    in_string = ""
                elif not in_string:
                    in_string = char
                index += 1
                continue
            if in_string:
                if char == "\\":
                    index += 2
                else:
                    index += 1
                continue
            if char == "{":
                stack.append(line_number)
            elif char == "}" and stack:
                pairs.append((stack.pop(), line_number))
            index += 1
    return sorted(pairs, key=lambda item: (item[0], -item[1]))


def _c_block_header(lines: Sequence[str], open_line: int) -> tuple[int, str]:
    start = open_line
    while start > 1 and open_line - start < 5:
        previous = lines[start - 2].strip()
        if (
            not previous
            or previous.endswith((";", "}", "{", "*/"))
            or re.match(r"^(?:case\b|default\s*:)", previous)
        ):
            break
        start -= 1
    return start, "\n".join(lines[start - 1 : open_line])


def _first_matching_line(
    lines: Sequence[str], start: int, stop: int, pattern: str
) -> int | None:
    regex = re.compile(pattern)
    for line_number in range(max(1, start), min(len(lines), stop) + 1):
        if regex.search(lines[line_number - 1]):
            return line_number
    return None


def _noreturn_call_after(
    lines: Sequence[str], start_line: int, stop_line: int
) -> dict[str, Any] | None:
    source_text = "\n".join(lines)
    region = "\n".join(lines[start_line:stop_line])
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", region):
        call = match.group(1)
        if call in {"if", "for", "while", "switch", "sizeof"}:
            continue
        call_line = start_line + 1 + region[: match.start()].count("\n")
        terminal = call
        macro_line: int | None = None
        macro = re.search(
            rf"(?m)^\s*#\s*define\s+{re.escape(call)}\s*\([^\n]*\)\s+"
            rf"(?P<target>[A-Za-z_]\w*)\s*\(",
            source_text,
        )
        if macro is not None:
            terminal = macro.group("target")
            macro_line = source_text[: macro.start()].count("\n") + 1
        declarations = (
            rf"\b{re.escape(terminal)}\s*\([^;{{}}]*\)\s*NORETURN\s*;",
            rf"NORETURN[^;{{}}]{{0,100}}\b{re.escape(terminal)}\s*\(",
        )
        declaration: re.Match[str] | None = None
        for pattern in declarations:
            declaration = re.search(pattern, source_text, re.DOTALL)
            if declaration is not None:
                break
        if declaration is None:
            continue
        declaration_line = source_text[: declaration.start()].count("\n") + 1
        return {
            "call": call,
            "call_line": call_line,
            "noreturn_function": terminal,
            "declaration_line": declaration_line,
            "macro_line": macro_line,
        }
    return None


def _fork_wrapper_contract(lines: Sequence[str], function: str) -> dict[str, Any] | None:
    for open_line, close_line in _c_brace_pairs(lines):
        header_start, header = _c_block_header(lines, open_line)
        if not re.search(rf"\b{re.escape(function)}\s*\(", header):
            continue
        if re.search(r"\b(?:if|for|while|switch)\s*\(", header):
            continue
        body = "\n".join(lines[open_line - 1 : close_line])
        fork_line = _first_matching_line(lines, open_line, close_line, r"\bfork\s*\(")
        child_line = _first_matching_line(lines, open_line, close_line, r"\bpid\s*==\s*0\b")
        return_line = _first_matching_line(lines, open_line, close_line, r"\breturn\s+pid\s*;")
        if fork_line is None or child_line is None or return_line is None:
            continue
        if not re.search(r"\bpid\s*=\s*fork\s*\(\s*\)\s*;", body):
            continue
        return {
            "function": function,
            "definition_start_line": header_start,
            "definition_end_line": close_line,
            "fork_line": fork_line,
            "child_dispatch_line": child_line,
            "return_line": return_line,
            "evidence_lines": [header_start, fork_line, child_line, return_line],
        }
    return None


def _unique_source_array_definition(
    source: Mapping[str, Any],
    name: str,
) -> dict[str, str]:
    source_root = Path(source["source_root"])
    pattern = re.compile(
        rf"(?m)^[ \t]*(?P<declaration>(?P<prefix>[^;()=\[\]\n]+?)"
        rf"\b{re.escape(name)}\s*\[\s*(?P<capacity>[^\]]*)\s*\]\s*(?:=|;|\{{))"
    )
    matches: list[tuple[Path, re.Match[str]]] = []
    for path in sorted((*source_root.rglob("*.c"), *source_root.rglob("*.h"))):
        text = _read_source_text(path)
        matches.extend(
            (path, match)
            for match in pattern.finditer(text)
            if match.group("prefix").strip()
            and not match.group("prefix").lstrip().startswith("extern ")
        )
    if len(matches) != 1:
        raise RuleNotApplicable(
            f"pinned source has {len(matches)} non-extern definitions for array {name}"
        )
    path, match = matches[0]
    return {
        "path": _relative_if_contained(Path(source_root).parents[1], path),
        "sha256": _sha256_file(path),
        "capacity": match.group("capacity").strip() or "initializer_element_count",
        "declaration": " ".join(match.group("declaration").split()),
    }


def _disassembly_window(
    context: CampaignContext,
    *,
    before: int,
    after: int,
) -> str:
    mapping = _reference_mapping(context)
    reference = _contained_file(
        context.root,
        str(_mapping(mapping.get("reference_binary")).get("path") or ""),
        "reference binary",
    )
    operation_address = _hex_int(context.binding.get("address"), "operation address")
    operation_mapping = _reference_operation_mapping(context, mapping, operation_address)
    vma = int(operation_mapping["reference_vma"])
    try:
        result = subprocess.run(
            [
                "objdump",
                "-d",
                f"--start-address={max(0, vma - before)}",
                f"--stop-address={vma + after}",
                str(reference),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"cannot disassemble the exact operation window: {exc}") from exc
    return result.stdout


def _pinned_source_file(
    context: CampaignContext,
    source: Mapping[str, Any],
    relative_path: str,
    label: str,
) -> tuple[Path, str, dict[str, str]]:
    source_root = _contained_directory(
        context.root,
        Path(source["source_root"]),
        "source checkout",
    )
    path = _contained_file(context.root, source_root / relative_path, label)
    return (
        path,
        _read_source_text(path),
        {
            "path": _relative_if_contained(context.root, path),
            "sha256": _sha256_file(path),
            "kind": "source_review",
        },
    )


def _reference_defined_data_symbol(
    context: CampaignContext,
    source: Mapping[str, Any],
    name: str,
) -> dict[str, Any]:
    cache = context.shared_cache.setdefault("reference_data_symbols", {})
    if isinstance(cache, dict) and isinstance(cache.get(name), Mapping):
        return dict(cache[name])
    mapping = _mapping(source.get("mapping"))
    reference_path = _contained_file(
        context.root,
        str(_mapping(mapping.get("reference_binary")).get("path") or ""),
        "reference binary",
    )
    try:
        result = subprocess.run(
            ["nm", "-S", "--defined-only", str(reference_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"cannot enumerate reference data symbols: {exc}") from exc
    pattern = re.compile(
        r"^(?P<address>[0-9a-fA-F]+)\s+(?P<size>[0-9a-fA-F]+)\s+"
        r"(?P<type>[bBdDrRsSgGcCvV])\s+(?P<name>\S+)$"
    )
    matches: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        match = pattern.match(line.strip())
        if match is None or match.group("name") != name:
            continue
        matches.append(
            {
                "name": name,
                "address": _hex(int(match.group("address"), 16)),
                "size_bytes": int(match.group("size"), 16),
                "symbol_type": match.group("type"),
                "reference_binary_path": _relative_if_contained(context.root, reference_path),
                "reference_binary_sha256": _sha256_file(reference_path),
            }
        )
    if len(matches) != 1:
        raise RuleNotApplicable(f"reference build lacks one defined data symbol {name}")
    if isinstance(cache, dict):
        cache[name] = matches[0]
    return matches[0]


def _struct_output_initializers(
    context: CampaignContext,
    function: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Enumerate typed whole-struct output initializers in one frozen function."""

    function_address = str(function.get("address") or "").lower()
    cache = context.shared_cache.setdefault("struct_output_initializers", {})
    if isinstance(cache, dict) and isinstance(cache.get(function_address), list):
        return [dict(item) for item in cache[function_address]]

    mapping = _reference_mapping(context)
    source_mapping = _mapping(mapping.get("source"))
    source_root = _contained_directory(
        context.root,
        str(source_mapping.get("path") or ""),
        "source checkout",
    )
    if _git_head(source_root) != str(source_mapping.get("commit") or "").lower():
        raise CertificateError("source checkout no longer matches the reference mapping commit")

    operations = _mapping_rows(function.get("pcode_operations"))
    producers: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    for operation in operations:
        if str(operation.get("pcode") or "") != "PTRSUB":
            continue
        output = _mapping(operation.get("output"))
        identity = _varnode_identity(output)
        if identity is not None:
            producers.setdefault(identity, []).append(operation)

    results: list[dict[str, Any]] = []
    for call in _mapping_rows(function.get("pcode_calls")):
        if str(call.get("pcode") or "") != "CALL":
            continue
        try:
            call_address = _hex_int(call.get("call_address"), "initializer CALL address")
            callee_address = _hex_int(call.get("callee_address"), "initializer callee address")
        except CertificateError:
            continue
        try:
            callee_mapping = _reference_operation_mapping(context, mapping, callee_address)
        except RuleNotApplicable:
            continue
        callee_names = _string_rows(callee_mapping.get("reference_function_names"))
        try:
            callee_source = _source_function_for_symbols(context, source_root, callee_names)
        except RuleNotApplicable:
            continue
        contracts = _whole_struct_memset_contract(callee_source)
        if not contracts:
            continue
        args = _mapping_rows(call.get("args"))
        for contract in contracts:
            argument_index = int(contract["parameter_index"])
            if argument_index >= len(args):
                continue
            argument = args[argument_index]
            identity = _varnode_identity(argument)
            pointer_producers = [
                item
                for item in (producers.get(identity, []) if identity is not None else [])
                if _hex_int(item.get("operation_address"), "stack pointer producer address")
                <= call_address
            ]
            if not pointer_producers:
                continue
            latest_address = max(
                _hex_int(item.get("operation_address"), "stack pointer producer address")
                for item in pointer_producers
            )
            latest_producers = [
                item
                for item in pointer_producers
                if _hex_int(item.get("operation_address"), "stack pointer producer address")
                == latest_address
            ]
            if len(latest_producers) != 1:
                continue
            producer = latest_producers[0]
            producer_address = _hex_int(
                producer.get("operation_address"), "stack pointer producer address"
            )
            if producer_address > call_address:
                continue
            constants = [
                int(item["constant"])
                for item in _mapping_rows(producer.get("inputs"))
                if isinstance(item.get("constant"), int)
            ]
            if len(constants) != 1 or constants[0] >= 0:
                continue
            struct_type = str(contract["struct_type"])
            try:
                layout = _reference_struct_layout(context, mapping, struct_type)
                caller_mapping = _reference_operation_mapping(context, mapping, call_address)
                caller_source = _source_function_for_symbols(
                    context,
                    source_root,
                    _string_rows(caller_mapping.get("reference_function_names")),
                )
                source_call = _typed_output_source_call(
                    caller_source,
                    callee_function=str(callee_source["function"]),
                    struct_type=struct_type,
                )
                struct_source = _source_struct_definition(
                    context,
                    source_root,
                    struct_type,
                    [str(item.get("name") or "") for item in layout["members"]],
                )
            except RuleNotApplicable:
                continue
            callee_context = {
                "mapping": mapping,
                "operation_mapping": callee_mapping,
                "source_path": Path(str(callee_source["path"])),
            }
            callee_binding = _source_binding(
                context,
                callee_context,
                source_function=str(callee_source["function"]),
                source_lines=[int(contract["memset_line"])],
            )
            results.append(
                {
                    "call_address": _hex(call_address),
                    "callee_address": _hex(callee_address),
                    "output_parameter_index": argument_index,
                    "output_parameter": str(contract["parameter_name"]),
                    "stack_base_offset": constants[0],
                    "memset_line": int(contract["memset_line"]),
                    "memset_statement": str(contract["memset_statement"]),
                    "compiled_layout": layout,
                    "callee_source": callee_source,
                    "callee_source_binding": callee_binding,
                    "caller_source": caller_source,
                    "struct_source": struct_source,
                    **source_call,
                }
            )
    unique: dict[tuple[int, int, str], dict[str, Any]] = {}
    for result in results:
        key = (
            _hex_int(result["call_address"], "initializer CALL address"),
            int(result["output_parameter_index"]),
            str(result["source_variable"]),
        )
        unique[key] = result
    normalized = [unique[key] for key in sorted(unique)]
    if isinstance(cache, dict):
        cache[function_address] = normalized
    return [dict(item) for item in normalized]


def _normalized_c_function_name(value: str) -> str:
    name = str(value or "").split("@", 1)[0]
    while True:
        normalized = re.sub(
            r"\.(?:constprop|isra|part|cold|lto_priv)(?:\.\d+|\.\d+\.\d+)?$",
            "",
            name,
        )
        if normalized == name:
            return name
        name = normalized


def _source_function_for_symbols(
    context: CampaignContext,
    source_root: Path,
    symbol_names: Sequence[str],
) -> dict[str, Any]:
    names = sorted(
        {
            _normalized_c_function_name(name)
            for name in symbol_names
            if _normalized_c_function_name(name)
        }
    )
    if not names:
        raise RuleNotApplicable("reference function has no source-level symbol name")
    index = _source_function_index(context, source_root)
    matches = [item for name in names for item in index.get(name, [])]
    by_location = {
        (str(item["path"]), int(item["start_line"]), int(item["end_line"])): item
        for item in matches
    }
    if len(by_location) != 1:
        raise RuleNotApplicable("reference symbol has no unique pinned source definition")
    return dict(next(iter(by_location.values())))


def _source_function_index(
    context: CampaignContext,
    source_root: Path,
) -> dict[str, list[dict[str, Any]]]:
    cache_key = f"source_function_index:{source_root.resolve()}"
    cached = context.shared_cache.get(cache_key)
    if isinstance(cached, dict):
        return cached
    index: dict[str, list[dict[str, Any]]] = {}
    paths = sorted(
        path
        for suffix in ("*.c", "*.h")
        for path in source_root.rglob(suffix)
        if ".git" not in path.parts
    )
    for path in paths:
        lines = _read_source_text(path).splitlines()
        for open_line, close_line in _c_brace_pairs(lines):
            header_start, header = _c_block_header(lines, open_line)
            header_without_brace = header.rsplit("{", 1)[0]
            matches = list(re.finditer(r"\b([A-Za-z_]\w*)\s*\(", header_without_brace))
            if not matches:
                continue
            function = matches[-1].group(1)
            if function in {"if", "for", "while", "switch"} or ";" in header_without_brace:
                continue
            index.setdefault(function, []).append(
                {
                    "function": function,
                    "path": path,
                    "lines": lines,
                    "start_line": header_start,
                    "open_line": open_line,
                    "end_line": close_line,
                    "header": header,
                    "text": "\n".join(lines[header_start - 1 : close_line]),
                }
            )
    context.shared_cache[cache_key] = index
    return index


def _whole_struct_memset_contract(source: Mapping[str, Any]) -> list[dict[str, Any]]:
    function = str(source.get("function") or "")
    text = str(source.get("text") or "")
    signature = re.search(
        rf"\b{re.escape(function)}\s*\((?P<parameters>.*?)\)\s*\{{",
        text,
        re.DOTALL,
    )
    if signature is None:
        return []
    parameters = _split_c_parameters(signature.group("parameters"))
    lines = list(source.get("lines") or [])
    open_line = int(source.get("open_line") or 0)
    end_line = int(source.get("end_line") or 0)
    results: list[dict[str, Any]] = []
    for index, parameter in enumerate(parameters):
        typed = re.fullmatch(
            r"\s*(?:const\s+)?struct\s+(?P<type>[A-Za-z_]\w*)\s*\*\s*"
            r"(?P<name>[A-Za-z_]\w*)\s*",
            parameter,
        )
        if typed is None:
            continue
        parameter_name = typed.group("name")
        pattern = re.compile(
            rf"^\s*memset\s*\(\s*{re.escape(parameter_name)}\s*,\s*0\s*,\s*"
            rf"sizeof\s*\(\s*\*\s*{re.escape(parameter_name)}\s*\)\s*\)\s*;\s*$"
        )
        memset_lines = [
            line_number
            for line_number in range(open_line + 1, end_line)
            if pattern.match(lines[line_number - 1])
        ]
        if len(memset_lines) != 1:
            continue
        memset_line = memset_lines[0]
        prefix = "\n".join(lines[open_line: memset_line - 1])
        if re.search(r"\b(?:if|for|while|switch|return|goto)\b|[{}]", prefix):
            continue
        results.append(
            {
                "parameter_index": index,
                "parameter_name": parameter_name,
                "struct_type": typed.group("type"),
                "memset_line": memset_line,
                "memset_statement": lines[memset_line - 1].strip(),
            }
        )
    return results


def _split_c_parameters(value: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(value):
        if character in "([":
            depth += 1
        elif character in ")]":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    if tail and tail != "void":
        parts.append(tail)
    return parts


def _typed_output_source_call(
    caller: Mapping[str, Any],
    *,
    callee_function: str,
    struct_type: str,
) -> dict[str, Any]:
    text = str(caller.get("text") or "")
    start_line = int(caller.get("start_line") or 0)
    calls = list(
        re.finditer(
            rf"\b{re.escape(callee_function)}\s*\((?P<args>[^;]*?)\)\s*;",
            text,
            re.DOTALL,
        )
    )
    matches: list[dict[str, Any]] = []
    for call in calls:
        variables = re.findall(r"&\s*([A-Za-z_]\w*)\b", call.group("args"))
        for variable in sorted(set(variables)):
            declarations = list(
                re.finditer(
                    rf"\bstruct\s+{re.escape(struct_type)}\s+"
                    rf"{re.escape(variable)}\s*;",
                    text[: call.start()],
                )
            )
            if len(declarations) != 1:
                continue
            matches.append(
                {
                    "source_variable": variable,
                    "source_declaration_line": (
                        start_line + text[: declarations[0].start()].count("\n")
                    ),
                    "source_call_line": start_line + text[: call.start()].count("\n"),
                    "source_call_statement": " ".join(call.group(0).split()),
                }
            )
    if len(matches) != 1:
        raise RuleNotApplicable("caller has no unique typed address-of output call")
    return matches[0]


def _source_struct_definition(
    context: CampaignContext,
    source_root: Path,
    name: str,
    member_names: Sequence[str],
) -> dict[str, Any]:
    cache = context.shared_cache.setdefault("source_struct_definitions", {})
    if isinstance(cache, dict) and isinstance(cache.get(name), Mapping):
        return dict(cache[name])
    matches: list[dict[str, Any]] = []
    for suffix in ("*.c", "*.h"):
        for path in sorted(source_root.rglob(suffix)):
            if ".git" in path.parts:
                continue
            lines = _read_source_text(path).splitlines()
            for open_line, close_line in _c_brace_pairs(lines):
                header_start, header = _c_block_header(lines, open_line)
                if re.search(rf"\bstruct\s+{re.escape(name)}\s*\{{", header) is None:
                    continue
                body = "\n".join(lines[header_start - 1 : close_line])
                if not all(re.search(rf"\b{re.escape(member)}\b", body) for member in member_names):
                    continue
                matches.append(
                    {
                        "name": name,
                        "path": path,
                        "start_line": header_start,
                        "end_line": close_line,
                        "declaration": " ".join(body.split()),
                    }
                )
    if len(matches) != 1:
        raise RuleNotApplicable("compiled struct has no unique complete source declaration")
    if isinstance(cache, dict):
        cache[name] = matches[0]
    return dict(matches[0])


def _reference_struct_layout(
    context: CampaignContext,
    mapping: Mapping[str, Any],
    name: str,
) -> dict[str, Any]:
    cache = context.shared_cache.setdefault("reference_struct_layouts", {})
    if isinstance(cache, dict) and isinstance(cache.get(name), Mapping):
        return dict(cache[name])
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]
    except ImportError as exc:
        raise CertificateError("pyelftools is required for compiled struct layouts") from exc
    reference_path = _contained_file(
        context.root,
        str(_mapping(mapping.get("reference_binary")).get("path") or ""),
        "reference binary",
    )
    layouts: dict[tuple[Any, ...], dict[str, Any]] = {}
    with reference_path.open("rb") as handle:
        elf = ELFFile(handle)
        if not elf.has_dwarf_info():
            raise RuleNotApplicable("reference binary has no DWARF struct layout")
        for compilation_unit in elf.get_dwarf_info().iter_CUs():
            for die in compilation_unit.iter_DIEs():
                if die.tag != "DW_TAG_structure_type" or _dwarf_name(die) != name:
                    continue
                size_attr = die.attributes.get("DW_AT_byte_size")
                if size_attr is None or not die.has_children:
                    continue
                members: list[dict[str, Any]] = []
                valid = True
                for child in die.iter_children():
                    if child.tag != "DW_TAG_member":
                        continue
                    member_name = _dwarf_name(child)
                    location = child.attributes.get("DW_AT_data_member_location")
                    member_type = child.get_DIE_from_attribute("DW_AT_type")
                    member_size = _dwarf_type_size(member_type, set())
                    if (
                        not member_name
                        or location is None
                        or not isinstance(location.value, int)
                        or member_size is None
                        or member_size <= 0
                    ):
                        valid = False
                        break
                    members.append(
                        {
                            "name": member_name,
                            "offset_bytes": int(location.value),
                            "size_bytes": int(member_size),
                        }
                    )
                if not valid or not members:
                    continue
                size = int(size_attr.value)
                if any(
                    int(item["offset_bytes"]) + int(item["size_bytes"]) > size
                    for item in members
                ):
                    continue
                key = (
                    size,
                    tuple(
                        (item["name"], item["offset_bytes"], item["size_bytes"])
                        for item in members
                    ),
                )
                layouts[key] = {
                    "name": name,
                    "size_bytes": size,
                    "members": members,
                    "reference_binary_path": _relative_if_contained(context.root, reference_path),
                    "reference_binary_sha256": _sha256_file(reference_path),
                }
    if len(layouts) != 1:
        raise RuleNotApplicable("reference DWARF has no unique complete struct layout")
    result = next(iter(layouts.values()))
    if isinstance(cache, dict):
        cache[name] = result
    return dict(result)


def _dwarf_name(die: Any) -> str:
    attribute = die.attributes.get("DW_AT_name") if die is not None else None
    value = attribute.value if attribute is not None else b""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value or "")


def _dwarf_type_size(die: Any, seen: set[int]) -> int | None:
    if die is None or int(die.offset) in seen:
        return None
    seen.add(int(die.offset))
    size = die.attributes.get("DW_AT_byte_size")
    if size is not None and isinstance(size.value, int):
        return int(size.value)
    if die.tag == "DW_TAG_array_type":
        element = die.get_DIE_from_attribute("DW_AT_type")
        element_size = _dwarf_type_size(element, seen)
        if element_size is None:
            return None
        count = 1
        for child in die.iter_children():
            if child.tag != "DW_TAG_subrange_type":
                continue
            count_attr = child.attributes.get("DW_AT_count")
            upper = child.attributes.get("DW_AT_upper_bound")
            lower = child.attributes.get("DW_AT_lower_bound")
            if count_attr is not None and isinstance(count_attr.value, int):
                count *= int(count_attr.value)
            elif upper is not None and isinstance(upper.value, int):
                lower_value = int(lower.value) if lower is not None else 0
                count *= int(upper.value) - lower_value + 1
            else:
                return None
        return element_size * count
    target = die.get_DIE_from_attribute("DW_AT_type")
    return _dwarf_type_size(target, seen) if target is not None else None


def _cfg_dominance_relation(
    function: Mapping[str, Any],
    before_address: str,
    after_address: str,
) -> dict[str, Any]:
    from binary_agent.analysis.program_index import IndexedBasicBlock, _cfg_event_relation

    name = str(function.get("name") or "")
    blocks = [
        IndexedBasicBlock(
            function_name=name,
            start_address=str(item.get("start") or ""),
            end_address=str(item.get("end") or ""),
            successors=tuple(str(value) for value in item.get("successors", []) if value),
        )
        for item in _mapping_rows(function.get("basic_blocks"))
    ]
    relation = _cfg_event_relation(blocks, before_address, after_address)
    return {
        "relation": relation.relation,
        "feasible": relation.feasible,
        "before_dominates_after": relation.before_dominates_after,
        "same_block": relation.same_block,
        "evidence": relation.evidence,
    }


def _struct_member_use_lines(
    source: Mapping[str, Any],
    variable: str,
    member_names: Sequence[str],
    *,
    after_line: int,
) -> list[int]:
    lines = list(source.get("lines") or [])
    end_line = int(source.get("end_line") or 0)
    patterns = [
        re.compile(rf"\b{re.escape(variable)}\s*\.\s*{re.escape(name)}\b")
        for name in member_names
        if name
    ]
    return [
        line_number
        for line_number in range(after_line + 1, end_line + 1)
        if any(pattern.search(lines[line_number - 1]) for pattern in patterns)
    ]


def _stack_var_name(value: Mapping[str, Any]) -> str:
    stack_ref = _mapping(value.get("stack_ref"))
    return str(stack_ref.get("var_name") or value.get("var_name") or "")


def _varnode_identity(value: Mapping[str, Any]) -> tuple[str, str, int] | None:
    address_space = str(value.get("address_space") or "")
    address = str(value.get("address") or "").lower()
    size = int(value.get("size_bytes") or 0)
    if not address_space or not address or size <= 0:
        return None
    return address_space, address, size


def _integer_value(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise CertificateError(f"{label} is not an integer")
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError) as exc:
        raise CertificateError(f"{label} is not an integer") from exc


def _string_rows(value: Any) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _deduplicated_source_refs(
    context: CampaignContext,
    paths: Sequence[Path],
) -> list[dict[str, str]]:
    refs: dict[str, dict[str, str]] = {}
    for path in paths:
        relative = _relative_if_contained(context.root, path)
        refs[relative] = {
            "path": relative,
            "sha256": _sha256_file(path),
            "kind": "source_review",
        }
    return [refs[key] for key in sorted(refs)]


def _source_function_prefix(lines: Sequence[str], function: str, line_number: int) -> str:
    target_index = line_number - 1
    start = -1
    function_pattern = re.compile(rf"\b{re.escape(function)}\s*\(")
    for index in range(target_index, -1, -1):
        if function_pattern.search(lines[index]):
            start = index
            break
    if start < 0:
        raise RuleNotApplicable("cannot locate the exact source function definition")
    return "\n".join(lines[start : target_index + 1])


def _source_function_text(lines: Sequence[str], function: str, line_number: int) -> str:
    function_pattern = re.compile(rf"\b{re.escape(function)}\s*\(")
    for open_line, close_line in _c_brace_pairs(lines):
        if not (open_line <= line_number <= close_line):
            continue
        header_start, header = _c_block_header(lines, open_line)
        if function_pattern.search(header) and not re.search(
            r"\b(?:if|for|while|switch)\s*\(", header
        ):
            return "\n".join(lines[header_start - 1 : close_line])
    raise RuleNotApplicable("cannot locate the complete exact source function")


def _libubox_blobmsg_contract(
    context: CampaignContext,
    mapping: Mapping[str, Any],
    *,
    function: str = "blobmsg_parse",
) -> dict[str, Any]:
    if function not in {"blobmsg_parse", "blobmsg_parse_array"}:
        raise CertificateError(f"unsupported libubox parser contract: {function}")
    sdk_ref = _mapping(mapping.get("sdk"))
    sdk_archive = _contained_file(
        context.root,
        str(sdk_ref.get("path") or ""),
        "OpenWrt SDK archive",
    )
    sdk_hash = _sha256_file(sdk_archive)
    if sdk_hash != str(sdk_ref.get("sha256") or "") or sdk_hash != OPENWRT_24_10_4_X86_64_SDK_SHA256:
        raise CertificateError("blobmsg contract is not bound to the pinned OpenWrt SDK")
    sdk_name = sdk_archive.name
    if not sdk_name.endswith(".tar.zst"):
        raise CertificateError("pinned SDK archive name is unexpected")
    sdk_root = sdk_archive.with_name(sdk_name[: -len(".tar.zst")])
    if not sdk_root.is_dir():
        raise CertificateError("extracted pinned SDK is missing")
    makefile = _contained_file(
        context.root,
        sdk_root / "feeds" / "base" / "package" / "libs" / "libubox" / "Makefile",
        "libubox package Makefile",
    )
    makefile_text = _read_source_text(makefile)
    version_match = re.search(r"^PKG_SOURCE_VERSION:=(?P<value>[0-9a-f]{40})$", makefile_text, re.MULTILINE)
    mirror_match = re.search(r"^PKG_MIRROR_HASH:=(?P<value>[0-9a-f]{64})$", makefile_text, re.MULTILINE)
    if version_match is None or mirror_match is None:
        raise CertificateError("libubox package pin is incomplete")
    archives = sorted((sdk_root / "dl").glob("libubox-*.tar.zst"))
    if len(archives) != 1:
        raise CertificateError("pinned SDK does not contain exactly one libubox source archive")
    source_archive = _contained_file(context.root, archives[0], "libubox source archive")
    source_hash = _sha256_file(source_archive)
    if source_hash != mirror_match.group("value"):
        raise CertificateError("libubox source archive hash disagrees with its package pin")
    try:
        listing = subprocess.run(
            ["tar", "--zstd", "-tf", str(source_archive)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"cannot list the pinned libubox source archive: {exc}") from exc
    members = [line for line in listing.stdout.splitlines() if line.endswith("/blobmsg.c")]
    if len(members) != 1:
        raise CertificateError("libubox archive does not contain one blobmsg.c")
    try:
        extraction = subprocess.run(
            ["tar", "--zstd", "-xOf", str(source_archive), members[0]],
            check=True,
            capture_output=True,
            timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"cannot read blobmsg.c from the pinned archive: {exc}") from exc
    source_text = extraction.stdout.decode("utf-8")
    function_match = re.search(
        rf"int\s+{re.escape(function)}\s*\([^)]*\)\s*\{{(?P<body>.*?)\n\}}",
        source_text,
        re.DOTALL,
    )
    if function_match is None:
        raise CertificateError(f"pinned libubox source lacks {function}")
    body = function_match.group("body")
    initialization = "memset(tb, 0, policy_len * sizeof(*tb));"
    position = body.find(initialization)
    first_return = body.find("return")
    if position < 0 or (first_return >= 0 and position > first_return):
        raise CertificateError(f"{function} does not initialize the table before every return")
    return {
        "package_commit": version_match.group("value"),
        "package_makefile": {
            "path": _relative_if_contained(context.root, makefile),
            "sha256": _sha256_file(makefile),
            "kind": "source_review",
        },
        "source_archive": {
            "path": _relative_if_contained(context.root, source_archive),
            "sha256": source_hash,
            "kind": "source_review",
        },
        "archive_member": members[0],
        "member_sha256": hashlib.sha256(extraction.stdout).hexdigest(),
        "function": function,
        "initialization_statement": initialization,
        "sdk_sha256": sdk_hash,
    }


def _libubox_calloc_contract(
    context: CampaignContext,
    mapping: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify calloc_a output initialization in the exact pinned libubox archive."""

    package = _libubox_blobmsg_contract(context, mapping)
    source_archive = _contained_file(
        context.root,
        str(_mapping(package.get("source_archive")).get("path") or ""),
        "libubox source archive",
    )
    try:
        listing = subprocess.run(
            ["tar", "--zstd", "-tf", str(source_archive)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"cannot list the pinned libubox source archive: {exc}") from exc
    members = [line for line in listing.stdout.splitlines() if line.endswith("/utils.c")]
    if len(members) != 1:
        raise CertificateError("libubox archive does not contain one utils.c")
    try:
        extraction = subprocess.run(
            ["tar", "--zstd", "-xOf", str(source_archive), members[0]],
            check=True,
            capture_output=True,
            timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"cannot read utils.c from the pinned archive: {exc}") from exc
    source_text = extraction.stdout.decode("utf-8")
    function_match = re.search(
        r"void\s*\*\s*__calloc_a\s*\([^)]*\)\s*\{(?P<body>.*?)^\}",
        source_text,
        re.DOTALL | re.MULTILINE,
    )
    if function_match is None:
        raise CertificateError("pinned libubox source lacks __calloc_a")
    body = function_match.group("body")
    allocation = body.find("ptr = calloc(1, alloc_len);")
    failure = re.search(r"if\s*\(\s*!ptr\s*\)\s*\{[^}]*return\s+NULL\s*;[^}]*\}", body, re.DOTALL)
    output_assignment = body.find("*cur_addr = &ptr[alloc_len];")
    success_return = body.find("return ret;")
    if (
        allocation < 0
        or failure is None
        or output_assignment < 0
        or success_return < 0
        or not allocation < failure.start() < output_assignment < success_return
    ):
        raise CertificateError("__calloc_a allocation/output control flow changed")
    macro = re.search(
        r"#define\s+foreach_arg\([^\n]*\)\s*\\\n(?P<body>(?:.*\\\n){2}.*)",
        source_text,
    )
    if macro is None:
        raise CertificateError("pinned libubox source lacks the foreach_arg contract")
    macro_text = " ".join(macro.group(0).replace("\\", " ").split())
    if "_addr;" not in macro_text or "va_arg(_arg, void **)" not in macro_text:
        raise CertificateError("foreach_arg no longer enumerates every non-null output pointer")
    return {
        "package_commit": package["package_commit"],
        "package_makefile": package["package_makefile"],
        "source_archive": package["source_archive"],
        "archive_member": members[0],
        "member_sha256": hashlib.sha256(extraction.stdout).hexdigest(),
        "function": "__calloc_a",
        "allocation_statement": "ptr = calloc(1, alloc_len);",
        "failure_result": "NULL before auxiliary output assignment",
        "output_statement": "*cur_addr = &ptr[alloc_len];",
        "success_result": "ret after every non-null vararg output",
        "enumeration_macro": macro_text,
        "sdk_sha256": package["sdk_sha256"],
    }


def _libubox_foreach_contract(
    context: CampaignContext,
    mapping: Mapping[str, Any],
    *,
    macro: str,
) -> dict[str, Any]:
    if macro not in {"blob_for_each_attr", "blobmsg_for_each_attr"}:
        raise CertificateError(f"unsupported libubox foreach macro: {macro}")
    package = _libubox_blobmsg_contract(context, mapping)
    source_archive = _contained_file(
        context.root,
        str(_mapping(package.get("source_archive")).get("path") or ""),
        "libubox source archive",
    )
    header_name = "blobmsg.h" if macro.startswith("blobmsg") else "blob.h"
    try:
        listing = subprocess.run(
            ["tar", "--zstd", "-tf", str(source_archive)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        )
        members = [
            line for line in listing.stdout.splitlines() if line.endswith("/" + header_name)
        ]
        if len(members) != 1:
            raise CertificateError(f"libubox archive does not contain one {header_name}")
        extraction = subprocess.run(
            ["tar", "--zstd", "-xOf", str(source_archive), members[0]],
            check=True,
            capture_output=True,
            timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"cannot read {header_name} from pinned libubox: {exc}") from exc
    source_text = extraction.stdout.decode("utf-8")
    macro_match = re.search(
        rf"#define\s+{re.escape(macro)}\([^\n]*\)\s*\\\n"
        rf"(?P<body>(?:.*\\\n){{3}}.*)",
        source_text,
    )
    if macro_match is None:
        raise CertificateError(f"pinned libubox source lacks {macro}")
    macro_text = " ".join(macro_match.group(0).replace("\\", " ").split())
    if not re.search(r"for\s*\(\s*rem\s*=.*:\s*0\s*,", macro_text):
        raise CertificateError(f"{macro} no longer initializes rem in the for initializer")
    if not re.search(r"pos\s*=\s*\(struct blob_attr \*\)", macro_text):
        raise CertificateError(f"{macro} no longer initializes pos in the for initializer")
    return {
        "package_commit": package["package_commit"],
        "package_makefile": package["package_makefile"],
        "source_archive": package["source_archive"],
        "archive_member": members[0],
        "member_sha256": hashlib.sha256(extraction.stdout).hexdigest(),
        "macro": macro,
        "macro_definition": macro_text,
        "sdk_sha256": package["sdk_sha256"],
    }


def _sdk_api_contract(
    context: CampaignContext,
    mapping: Mapping[str, Any],
    *,
    api: str,
) -> dict[str, Any]:
    if api not in {"stat", "glob", "read"}:
        raise CertificateError(f"unsupported checked API contract: {api}")
    sdk_ref = _mapping(mapping.get("sdk"))
    sdk_archive = _contained_file(
        context.root,
        str(sdk_ref.get("path") or ""),
        "OpenWrt SDK archive",
    )
    sdk_hash = _sha256_file(sdk_archive)
    if sdk_hash != str(sdk_ref.get("sha256") or "") or sdk_hash != OPENWRT_24_10_4_X86_64_SDK_SHA256:
        raise CertificateError("API contract is not bound to the pinned OpenWrt SDK")
    if not sdk_archive.name.endswith(".tar.zst"):
        raise CertificateError("pinned SDK archive name is unexpected")
    sdk_root = sdk_archive.with_name(sdk_archive.name[: -len(".tar.zst")])
    if not sdk_root.is_dir():
        raise CertificateError("extracted pinned SDK is missing")
    relative_header = {
        "stat": Path("sys/stat.h"),
        "glob": Path("glob.h"),
        "read": Path("unistd.h"),
    }[api]
    headers = sorted((sdk_root / "staging_dir").glob(f"toolchain-*/include/{relative_header}"))
    headers = [
        _contained_file(context.root, header, f"SDK {api} header") for header in headers
    ]
    if len(headers) != 1:
        raise CertificateError(f"pinned SDK does not contain exactly one {api} header")
    header = headers[0]
    header_text = _read_source_text(header)
    declaration = {
        "stat": r"int\s+stat\s*\([^;]*struct\s+stat\s*\*[^;]*\)\s*;",
        "glob": r"int\s+glob\s*\([^;]*glob_t\s*\*[^;]*\)\s*;",
        "read": r"ssize_t\s+read\s*\([^;]*void\s*\*[^;]*size_t[^;]*\)\s*;",
    }[api]
    match = re.search(declaration, header_text, re.DOTALL)
    if match is None:
        raise CertificateError(f"pinned SDK header lacks the {api} output signature")
    return {
        "sdk_archive": {
            "path": _relative_if_contained(context.root, sdk_archive),
            "sha256": sdk_hash,
            "kind": "source_review",
        },
        "api_header": {
            "path": _relative_if_contained(context.root, header),
            "sha256": _sha256_file(header),
            "kind": "source_review",
        },
        "api": api,
        "declaration": " ".join(match.group(0).split()),
        "success_contract": (
            "a positive return is no greater than the requested byte count"
            if api == "read"
            else "return value 0 initializes the caller-provided output object"
        ),
        "sdk_sha256": sdk_hash,
    }


def _sdk_process_contract(
    context: CampaignContext,
    mapping: Mapping[str, Any],
    *,
    require_exec: bool,
) -> dict[str, Any]:
    sdk_ref = _mapping(mapping.get("sdk"))
    sdk_archive = _contained_file(
        context.root,
        str(sdk_ref.get("path") or ""),
        "OpenWrt SDK archive",
    )
    sdk_hash = _sha256_file(sdk_archive)
    if sdk_hash != str(sdk_ref.get("sha256") or "") or sdk_hash != OPENWRT_24_10_4_X86_64_SDK_SHA256:
        raise CertificateError("process contract is not bound to the pinned OpenWrt SDK")
    if not sdk_archive.name.endswith(".tar.zst"):
        raise CertificateError("pinned SDK archive name is unexpected")
    sdk_root = sdk_archive.with_name(sdk_archive.name[: -len(".tar.zst")])
    if not sdk_root.is_dir():
        raise CertificateError("extracted pinned SDK is missing")
    headers = sorted((sdk_root / "staging_dir").glob("toolchain-*/include/unistd.h"))
    headers = [
        _contained_file(context.root, header, "SDK process header") for header in headers
    ]
    if len(headers) != 1:
        raise CertificateError("pinned SDK does not contain exactly one process header")
    header = headers[0]
    header_text = _read_source_text(header)
    fork_match = re.search(r"pid_t\s+fork\s*\(\s*void\s*\)\s*;", header_text)
    if fork_match is None:
        raise CertificateError("pinned SDK process header lacks fork")
    exec_declarations = re.findall(
        r"int\s+(exec(?:l|v|le|ve|lp|vp))\s*\([^;]*\)\s*;",
        header_text,
        re.DOTALL,
    )
    if require_exec and not exec_declarations:
        raise CertificateError("pinned SDK process header lacks exec declarations")
    return {
        "sdk_archive": {
            "path": _relative_if_contained(context.root, sdk_archive),
            "sha256": sdk_hash,
            "kind": "source_review",
        },
        "process_header": {
            "path": _relative_if_contained(context.root, header),
            "sha256": _sha256_file(header),
            "kind": "source_review",
        },
        "fork_declaration": " ".join(fork_match.group(0).split()),
        "exec_declarations": sorted(set(exec_declarations)),
        "process_semantics": (
            "fork returns zero in the child and the child has a separate descriptor table; "
            "successful exec replaces only that child process image"
        ),
        "sdk_sha256": sdk_hash,
    }


def _bound_export_function(context: CampaignContext) -> Mapping[str, Any]:
    name = str(context.binding.get("function_name") or "")
    address = str(context.binding.get("function_address") or "").lower()
    matches = [
        item
        for item in _mapping_rows(context.export_manifest.get("functions"))
        if str(item.get("name") or "") == name
        and str(item.get("address") or "").lower() == address
    ]
    if len(matches) != 1:
        raise CertificateError("prepared operation function is absent from the frozen export")
    return matches[0]


def _exact_source_context(context: CampaignContext) -> dict[str, Any]:
    cached = context.cache.get("exact_source_context")
    if isinstance(cached, Mapping):
        return dict(cached)
    cached_error = context.cache.get("exact_source_context_error")
    if isinstance(cached_error, str):
        raise RuleNotApplicable(cached_error)

    if (
        str(context.binding.get("status") or "") != "resolved"
        or not str(context.binding.get("address") or "")
        or not str(context.binding.get("pcode") or "")
    ):
        reason = "candidate has no resolved exact binary operation"
        context.cache["exact_source_context_error"] = reason
        raise RuleNotApplicable(reason)

    contexts = _source_contexts_for_operation(
        context, str(context.binding.get("address") or "")
    )
    result = contexts[0]
    context.cache["exact_source_context"] = result
    return result


def _source_contexts_for_operation(
    context: CampaignContext, operation_address_value: str
) -> list[dict[str, Any]]:
    operation_address = _hex_int(operation_address_value, "operation address")
    cache = context.cache.setdefault("source_contexts_by_operation", {})
    if isinstance(cache, dict):
        cached = cache.get(operation_address)
        if isinstance(cached, list):
            return [dict(item) for item in cached]
        if isinstance(cached, str):
            raise RuleNotApplicable(cached)

    mapping = _reference_mapping(context)
    reference_path = _contained_file(
        context.root,
        str(_mapping(mapping.get("reference_binary")).get("path") or ""),
        "reference binary",
    )
    operation_mapping = _reference_operation_mapping(context, mapping, operation_address)
    vma = int(operation_mapping["reference_vma"])
    frames = _addr2line_frames(reference_path, vma)
    source_mapping = _mapping(mapping.get("source"))
    source_root = _contained_directory(
        context.root,
        str(source_mapping.get("path") or ""),
        "source checkout",
    )
    expected_commit = str(source_mapping.get("commit") or "").lower()
    if _git_head(source_root) != expected_commit:
        raise CertificateError("source checkout no longer matches the reference mapping commit")
    results: list[dict[str, Any]] = []
    for frame in frames:
        source_path = _resolve_frame_source(source_root, str(frame.get("path") or ""))
        if source_path is None:
            continue
        lines = _read_source_text(source_path).splitlines()
        line_number = int(frame.get("line") or 0)
        if 0 < line_number <= len(lines):
            results.append({
                "mapping": mapping,
                "operation_mapping": operation_mapping,
                "frame": frame,
                "source_path": source_path,
                "source_root": source_root,
                "lines": lines,
                "vma": vma,
            })
    if results:
        if isinstance(cache, dict):
            cache[operation_address] = results
        return [dict(item) for item in results]
    reason = "reference DWARF does not resolve to the pinned source checkout"
    if isinstance(cache, dict):
        cache[operation_address] = reason
    raise RuleNotApplicable(reason)


def _source_binding(
    context: CampaignContext,
    source: Mapping[str, Any],
    *,
    source_function: str,
    source_lines: Sequence[int],
) -> dict[str, Any]:
    mapping = _mapping(source.get("mapping"))
    source_mapping = _mapping(mapping.get("source"))
    frozen = _mapping(mapping.get("frozen_binary"))
    reference = _mapping(mapping.get("reference_binary"))
    source_path = Path(source["source_path"])
    operation_mapping = _mapping(source.get("operation_mapping"))
    basis = str(operation_mapping.get("mapping_basis") or "")
    result = {
        "source_path": _relative_if_contained(context.root, source_path),
        "source_sha256": _sha256_file(source_path),
        "source_commit": str(source_mapping.get("commit") or ""),
        "source_function": source_function,
        "source_lines": [int(item) for item in source_lines],
        "mapping_basis": basis,
        "frozen_binary_sha256": str(frozen.get("sha256") or ""),
    }
    if basis == "exact_code_bytes":
        result.update(
            {
                "frozen_code_sha256": str(
                    _mapping(frozen.get("executable_segments")).get("sha256") or ""
                ),
                "reference_code_sha256": str(
                    _mapping(reference.get("executable_segments")).get("sha256") or ""
                ),
                "code_bytes_match": True,
            }
        )
    elif basis == "function_fingerprint":
        result.update(
            {
                "frozen_function_sha256": str(
                    operation_mapping.get("frozen_function_sha256") or ""
                ),
                "reference_function_sha256": str(
                    operation_mapping.get("reference_function_sha256") or ""
                ),
                "constants_match": operation_mapping.get("constants_match") is True,
                "call_topology_match": operation_mapping.get("call_topology_match") is True,
                "constant_signature_sha256": str(
                    operation_mapping.get("constant_signature_sha256") or ""
                ),
                "call_topology_sha256": str(
                    operation_mapping.get("call_topology_sha256") or ""
                ),
                "control_flow_sha256": str(
                    operation_mapping.get("control_flow_sha256") or ""
                ),
                "relocation_shape_sha256": str(
                    operation_mapping.get("relocation_shape_sha256") or ""
                ),
                "frozen_function_address": str(
                    operation_mapping.get("frozen_function_address") or ""
                ),
                "reference_function_address": str(
                    operation_mapping.get("reference_function_address") or ""
                ),
            }
        )
    else:
        raise CertificateError("source context has no verified mapping basis")
    return result


def _resolve_frame_source(source_root: Path, value: str) -> Path | None:
    path = Path(value)
    if path.is_absolute():
        try:
            path.resolve().relative_to(source_root.resolve())
        except ValueError:
            pass
        else:
            return path.resolve() if path.is_file() else None
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for index in range(len(parts)):
        candidate = source_root.joinpath(*parts[index:]).resolve()
        try:
            candidate.relative_to(source_root.resolve())
        except ValueError:
            continue
        if candidate.is_file():
            return candidate
    return None


def _resolve_campaign_frame_file(root: Path, value: str, label: str) -> Path:
    """Relocate an absolute DWARF build path into a copied campaign tree."""

    campaign_root = root.resolve()
    raw = Path(value)
    if raw.is_absolute():
        resolved = raw.resolve()
        try:
            resolved.relative_to(campaign_root)
        except ValueError:
            pass
        else:
            if resolved.is_file():
                return resolved
    parts = raw.parts[1:] if raw.is_absolute() else raw.parts
    for index in range(len(parts)):
        candidate = campaign_root.joinpath(*parts[index:]).resolve()
        try:
            candidate.relative_to(campaign_root)
        except ValueError:
            continue
        if candidate.is_file():
            return candidate
    raise CertificateError(f"{label} cannot be relocated inside the campaign: {value}")


def _git_head(source_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"cannot verify source checkout commit: {exc}") from exc
    commit = result.stdout.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise CertificateError("source checkout returned an invalid commit")
    return commit


def _reference_mapping(context: CampaignContext) -> Mapping[str, Any]:
    cached = context.cache.get("reference_mapping")
    if isinstance(cached, Mapping):
        return cached
    cached_error = context.cache.get("reference_mapping_error")
    if isinstance(cached_error, str):
        raise RuleNotApplicable(cached_error)

    binary = str(context.candidate.get("binary") or "")
    row = next(
        (
            item
            for item in _mapping_rows(context.manifest.get("reference_build_mappings"))
            if item.get("binary") == binary
        ),
        None,
    )
    if row is None:
        reason = "campaign has no reference-build mapping for this binary"
        context.cache["reference_mapping_error"] = reason
        raise RuleNotApplicable(reason)
    mapping_path = _contained_file(context.root, str(row.get("path") or ""), "reference mapping")
    if _sha256_file(mapping_path) != str(row.get("sha256") or ""):
        raise CertificateError("frozen reference mapping changed")
    mapping = _load_json(mapping_path)
    frozen = _mapping(mapping.get("frozen_binary"))
    reference = _mapping(mapping.get("reference_binary"))
    frozen_path = _contained_file(context.root, str(frozen.get("path") or ""), "mapped frozen binary")
    reference_path = _contained_file(context.root, str(reference.get("path") or ""), "reference binary")
    if _sha256_file(frozen_path) != str(frozen.get("sha256") or ""):
        raise CertificateError("mapped frozen binary changed")
    if _sha256_file(reference_path) != str(reference.get("sha256") or ""):
        raise CertificateError("reference binary changed")
    if str(frozen.get("sha256") or "") != str(context.input_row.get("binary_sha256") or ""):
        raise CertificateError("reference mapping names another frozen binary")
    frozen_code = _executable_fingerprint(frozen_path)
    reference_code = _executable_fingerprint(reference_path)
    if frozen_code != _mapping(frozen.get("executable_segments")):
        raise CertificateError("frozen executable fingerprint disagrees with mapping")
    if reference_code != _mapping(reference.get("executable_segments")):
        raise CertificateError("reference executable fingerprint disagrees with mapping")
    exact_match = frozen_code == reference_code
    if mapping.get("code_bytes_match") is not exact_match:
        raise CertificateError("reference mapping executable-match flag is inconsistent")
    if mapping.get("direct_source_mapping_allowed") is not exact_match:
        raise CertificateError("reference mapping direct-source flag is inconsistent")
    expected_policy = "exact_code_bytes" if exact_match else "function_fingerprint_required"
    if str(mapping.get("mismatch_policy") or "") != expected_policy:
        raise CertificateError("reference mapping mismatch policy is inconsistent")
    context.cache["reference_mapping"] = mapping
    return mapping


def _reference_operation_mapping(
    context: CampaignContext,
    mapping: Mapping[str, Any],
    operation_address: int,
) -> dict[str, Any]:
    cache = context.cache.setdefault("reference_operation_mappings", {})
    if isinstance(cache, dict) and operation_address in cache:
        cached = cache[operation_address]
        if isinstance(cached, Mapping):
            return dict(cached)
        raise RuleNotApplicable(str(cached))

    frozen_vma, _, _ = _operation_bytes(context, operation_address, 1)
    if mapping.get("code_bytes_match") is True:
        result = {
            "mapping_basis": "exact_code_bytes",
            "frozen_vma": frozen_vma,
            "reference_vma": frozen_vma,
        }
        if isinstance(cache, dict):
            cache[operation_address] = result
        return result

    function = _export_function_for_operation(context, operation_address)
    function_address = _hex_int(function.get("address"), "export function address")
    frozen_function_vma, _, _ = _operation_bytes(context, function_address, 1)
    function_size = int(function.get("body_size_bytes") or 0)
    if function_size <= 0:
        reason = "frozen export function has no positive byte size"
        if isinstance(cache, dict):
            cache[operation_address] = reason
        raise RuleNotApplicable(reason)
    operation_offset = frozen_vma - frozen_function_vma
    frozen_path = _contained_file(
        context.root,
        str(_mapping(mapping.get("frozen_binary")).get("path") or ""),
        "mapped frozen binary",
    )
    reference_path = _contained_file(
        context.root,
        str(_mapping(mapping.get("reference_binary")).get("path") or ""),
        "reference binary",
    )
    frozen_fingerprint = _normalized_function_fingerprint(
        frozen_path, frozen_function_vma, function_size
    )
    if operation_offset not in frozen_fingerprint["instruction_offsets"]:
        reason = "exact operation is not a decoded instruction in its frozen function"
        if isinstance(cache, dict):
            cache[operation_address] = reason
        raise RuleNotApplicable(reason)
    matches = [
        item
        for item in _reference_function_index(context, reference_path).get(function_size, [])
        if item["normalized_function_sha256"]
        == frozen_fingerprint["normalized_function_sha256"]
        and item["constant_signature_sha256"]
        == frozen_fingerprint["constant_signature_sha256"]
        and item["call_topology_sha256"] == frozen_fingerprint["call_topology_sha256"]
        and item["control_flow_sha256"] == frozen_fingerprint["control_flow_sha256"]
        and item["relocation_shape_sha256"]
        == frozen_fingerprint["relocation_shape_sha256"]
    ]
    if len(matches) != 1:
        reason = (
            "normalized function fingerprint is absent from the reference build"
            if not matches
            else "normalized function fingerprint is ambiguous in the reference build"
        )
        if isinstance(cache, dict):
            cache[operation_address] = reason
        raise RuleNotApplicable(reason)
    match = matches[0]
    if operation_offset not in match["instruction_offsets"]:
        raise CertificateError("matched function instruction offsets changed")
    result = {
        "mapping_basis": "function_fingerprint",
        "frozen_vma": frozen_vma,
        "reference_vma": int(match["address"]) + operation_offset,
        "operation_offset": operation_offset,
        "function_size_bytes": function_size,
        "frozen_function_address": _hex(frozen_function_vma),
        "reference_function_address": _hex(int(match["address"])),
        "reference_function_names": list(match["names"]),
        "frozen_function_sha256": frozen_fingerprint["normalized_function_sha256"],
        "reference_function_sha256": match["normalized_function_sha256"],
        "constant_signature_sha256": frozen_fingerprint["constant_signature_sha256"],
        "call_topology_sha256": frozen_fingerprint["call_topology_sha256"],
        "control_flow_sha256": frozen_fingerprint["control_flow_sha256"],
        "relocation_shape_sha256": frozen_fingerprint["relocation_shape_sha256"],
        "constants_match": True,
        "call_topology_match": True,
    }
    if isinstance(cache, dict):
        cache[operation_address] = result
    return result


def _export_function_for_operation(
    context: CampaignContext, operation_address: int
) -> Mapping[str, Any]:
    matches: list[Mapping[str, Any]] = []
    for function in _mapping_rows(context.export_manifest.get("functions")):
        blocks = _mapping_rows(function.get("basic_blocks"))
        if any(
            _hex_int(block.get("start"), "basic block start")
            <= operation_address
            <= _hex_int(block.get("end"), "basic block end")
            for block in blocks
        ):
            matches.append(function)
    if len(matches) != 1:
        raise RuleNotApplicable("exact operation is not in one frozen export function")
    return matches[0]


def _reference_function_index(
    context: CampaignContext, reference_path: Path
) -> dict[int, list[dict[str, Any]]]:
    cached = context.shared_cache.get("reference_function_index")
    if isinstance(cached, dict):
        return cached
    try:
        result = subprocess.run(
            ["nm", "-n", "-S", "--defined-only", str(reference_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"cannot enumerate reference text symbols: {exc}") from exc
    symbols: dict[tuple[int, int], set[str]] = {}
    pattern = re.compile(
        r"^(?P<address>[0-9a-fA-F]+)\s+(?P<size>[0-9a-fA-F]+)\s+"
        r"(?P<type>[tTwW])\s+(?P<name>.+)$"
    )
    for line in result.stdout.splitlines():
        match = pattern.match(line.strip())
        if match is None:
            continue
        address = int(match.group("address"), 16)
        size = int(match.group("size"), 16)
        if size <= 0:
            continue
        symbols.setdefault((address, size), set()).add(match.group("name"))
    by_size: dict[int, list[dict[str, Any]]] = {}
    for (address, size), names in sorted(symbols.items()):
        try:
            fingerprint = _normalized_function_fingerprint(reference_path, address, size)
        except RuleNotApplicable:
            continue
        by_size.setdefault(size, []).append(
            {"address": address, "names": sorted(names), **fingerprint}
        )
    context.shared_cache["reference_function_index"] = by_size
    return by_size


def _normalized_function_fingerprint(
    binary_path: Path, function_vma: int, function_size: int
) -> dict[str, Any]:
    try:
        from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_64, Cs
        from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    except ImportError as exc:
        raise CertificateError("Capstone is required for function fingerprint mapping") from exc

    data, elf_type, segments = _elf_layout(binary_path)
    if elf_type not in {2, 3} or data[4] != 2 or data[5] != 1:
        raise RuleNotApplicable("function fingerprint supports little-endian x86-64 ELF only")
    function_bytes = _elf_bytes_at_vma(data, segments, function_vma, function_size)
    load_ranges = [
        (int(segment["virtual_address"]), int(segment["virtual_address"]) + int(segment["file_size"]))
        for segment in segments
    ]

    def is_loaded_address(value: int) -> bool:
        # Small integers are overwhelmingly literal constants even when an
        # ET_DYN image has a zero-based load segment.  Absolute encoded code or
        # data addresses on the supported x86-64 targets are not below 64 KiB.
        return abs(value) >= 0x10000 and any(
            start <= value < end for start, end in load_ranges
        )

    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    disassembler.skipdata = True
    normalized = bytearray()
    constants: list[str] = []
    calls: list[str] = []
    control_flow: list[str] = []
    relocations: list[str] = []
    instruction_offsets: list[int] = []
    for instruction in disassembler.disasm(function_bytes, function_vma):
        offset = int(instruction.address) - function_vma
        instruction_offsets.append(offset)
        encoded = bytearray(instruction.bytes)
        if instruction.id != 0:
            is_call = instruction.group(CS_GRP_CALL)
            is_jump = instruction.group(CS_GRP_JUMP)
            is_control = is_call or is_jump
            immediate_operands = [
                operand for operand in instruction.operands if operand.type == X86_OP_IMM
            ]
            memory_operands = [
                operand.mem for operand in instruction.operands if operand.type == X86_OP_MEM
            ]
            address_immediate = any(
                is_loaded_address(int(operand.imm)) for operand in immediate_operands
            )
            address_displacement = any(
                memory.base == X86_REG_RIP or is_loaded_address(int(memory.disp))
                for memory in memory_operands
            )
            if (is_control or address_immediate) and instruction.imm_size:
                start = int(instruction.imm_offset)
                size = int(instruction.imm_size)
                encoded[start : start + size] = b"\0" * size
            if address_displacement and instruction.disp_size:
                start = int(instruction.disp_offset)
                size = int(instruction.disp_size)
                encoded[start : start + size] = b"\0" * size
            for operand in immediate_operands:
                value = int(operand.imm)
                if not is_control and not is_loaded_address(value):
                    constants.append(f"{offset}:{int(operand.size)}:{value}")
            if is_call:
                kind = "direct" if immediate_operands else "indirect"
                scope = "external"
                if immediate_operands:
                    target = int(immediate_operands[0].imm)
                    if function_vma <= target < function_vma + function_size:
                        scope = f"internal:{target - function_vma}"
                calls.append(f"{offset}:{kind}:{scope}")
            if is_control and immediate_operands:
                target = int(immediate_operands[0].imm)
                scope = (
                    f"internal:{target - function_vma}"
                    if function_vma <= target < function_vma + function_size
                    else "external"
                )
                control_flow.append(f"{offset}:{instruction.mnemonic}:{scope}")
            if address_immediate:
                relocations.append(f"{offset}:immediate")
            if address_displacement:
                relocations.append(f"{offset}:memory")
        normalized.extend(struct.pack(">H", len(encoded)))
        normalized.extend(encoded)

    def signature(items: Sequence[str]) -> str:
        return hashlib.sha256("\n".join(items).encode("utf-8")).hexdigest()

    constant_hash = signature(constants)
    call_hash = signature(calls)
    control_hash = signature(control_flow)
    relocation_hash = signature(relocations)
    digest = hashlib.sha256()
    digest.update(normalized)
    for item in (constant_hash, call_hash, control_hash, relocation_hash):
        digest.update(item.encode("ascii"))
    return {
        "normalized_function_sha256": digest.hexdigest(),
        "constant_signature_sha256": constant_hash,
        "call_topology_sha256": call_hash,
        "control_flow_sha256": control_hash,
        "relocation_shape_sha256": relocation_hash,
        "instruction_offsets": instruction_offsets,
    }


def _elf_bytes_at_vma(
    data: bytes,
    segments: Sequence[Mapping[str, int]],
    virtual_address: int,
    count: int,
) -> bytes:
    for segment in segments:
        start = int(segment["virtual_address"])
        size = int(segment["file_size"])
        if start <= virtual_address and virtual_address + count <= start + size:
            offset = int(segment["file_offset"]) + virtual_address - start
            return data[offset : offset + count]
    raise RuleNotApplicable("function bytes are outside the ELF load segments")


def _operation_bytes(
    context: CampaignContext,
    operation_address: int,
    count: int,
) -> tuple[int, int, bytes]:
    data, elf_type, segments = _elf_layout(context.binary_path)
    image_base = int(context.export_manifest.get("image_base") or 0)
    virtual_address = operation_address - image_base if elf_type == 3 else operation_address
    for segment in segments:
        if not int(segment["flags"]) & 1:
            continue
        start = int(segment["virtual_address"])
        size = int(segment["file_size"])
        if start <= virtual_address < start + size:
            file_offset = int(segment["file_offset"]) + virtual_address - start
            if file_offset + count > len(data):
                raise CertificateError("operation bytes exceed the frozen binary")
            return virtual_address, file_offset, data[file_offset : file_offset + count]
    raise CertificateError("operation address is outside every executable ELF segment")


def _dynamic_function_relocation(
    context: CampaignContext,
    logical_address: int,
) -> dict[str, Any]:
    """Resolve one frozen dynamic GOT relocation without trusting Ghidra names."""

    _, elf_type, _ = _elf_layout(context.binary_path)
    image_base = int(context.export_manifest.get("image_base") or 0)
    virtual_address = logical_address - image_base if elf_type == 3 else logical_address
    try:
        result = subprocess.run(
            ["readelf", "-rWD", str(context.binary_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"cannot read frozen dynamic relocations: {exc}") from exc
    matches: list[dict[str, Any]] = []
    pattern = re.compile(
        r"^\s*(?P<offset>[0-9a-fA-F]+)\s+"
        r"(?P<info>[0-9a-fA-F]+)\s+"
        r"(?P<type>R_X86_64_[A-Z0-9_]+)\s+"
        r"(?P<value>[0-9a-fA-F]+)\s+"
        r"(?P<symbol>\S+)\s+\+\s+(?P<addend>-?\d+)\s*$"
    )
    for line in result.stdout.splitlines():
        match = pattern.match(line)
        if match is None or int(match.group("offset"), 16) != virtual_address:
            continue
        matches.append(
            {
                "offset": _hex(virtual_address),
                "type": match.group("type"),
                "symbol": match.group("symbol").split("@", 1)[0],
                "addend": int(match.group("addend")),
            }
        )
    if len(matches) != 1:
        raise RuleNotApplicable("CAST input is not one exact frozen dynamic relocation")
    relocation = matches[0]
    if relocation["type"] not in {"R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"}:
        raise RuleNotApplicable("dynamic relocation is not a loader-populated function slot")
    if relocation["addend"] != 0:
        raise RuleNotApplicable("dynamic function relocation has a nonzero addend")
    return relocation


def _decode_x86_call(data: bytes) -> tuple[int, str]:
    prefix_bytes = {
        0x26,
        0x2E,
        0x36,
        0x3E,
        0x64,
        0x65,
        0x66,
        0x67,
        0xF0,
        0xF2,
        0xF3,
    }
    cursor = 0
    while cursor < len(data) and (
        data[cursor] in prefix_bytes or 0x40 <= data[cursor] <= 0x4F
    ):
        cursor += 1
    if cursor >= 15:
        raise CertificateError("x86 CALL has too many instruction prefixes")
    prefix_kind = "prefixed_" if cursor else ""
    if len(data) >= cursor + 5 and data[cursor] == 0xE8:
        return cursor + 5, prefix_kind + "direct_rel32"
    if len(data) < cursor + 2 or data[cursor] != 0xFF:
        raise CertificateError("frozen operation bytes do not encode an x86 CALL")
    modrm = data[cursor + 1]
    if ((modrm >> 3) & 0x7) != 2:
        raise CertificateError("x86 FF instruction is not a near indirect CALL")
    mod = modrm >> 6
    rm = modrm & 0x7
    length = cursor + 2
    if mod != 3 and rm == 4:
        if len(data) <= length:
            raise CertificateError("truncated x86 CALL SIB byte")
        sib = data[length]
        length += 1
        base = sib & 0x7
        if mod == 0 and base == 5:
            length += 4
    if mod == 0 and rm == 5:
        length += 4
    elif mod == 1:
        length += 1
    elif mod == 2:
        length += 4
    if len(data) < length:
        raise CertificateError("truncated x86 indirect CALL")
    return length, prefix_kind + "indirect_ff_group2"


def _addr2line_frames(reference_binary: Path, virtual_address: int) -> list[dict[str, Any]]:
    errors: list[str] = []
    # GNU addr2line 2.42 can fail to decode otherwise valid GCC LTO inline
    # ranges.  LLVM and elfutils consume the same immutable DWARF and provide
    # an independent deterministic fallback without weakening the mapping.
    for executable in ("addr2line", "llvm-addr2line", "eu-addr2line"):
        try:
            result = subprocess.run(
                [executable, "-f", "-i", "-e", str(reference_binary), hex(virtual_address)],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
                env={**os.environ, "LC_ALL": "C"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"{executable}: {exc}")
            continue
        rows = [line.strip() for line in result.stdout.splitlines()]
        frames: list[dict[str, Any]] = []
        for index in range(0, len(rows) - 1, 2):
            location = _LOCATION.match(rows[index + 1])
            if location is None or rows[index] == "??":
                continue
            frames.append(
                {
                    "function": rows[index],
                    "path": location.group("path"),
                    "line": int(location.group("line")),
                }
            )
        if frames:
            return frames
    if errors and len(errors) == 3:
        raise RuleNotApplicable("address-to-line tools are unavailable: " + "; ".join(errors))
    return []


def _check_manifest_reference(context: CampaignContext, certificate: Mapping[str, Any]) -> None:
    reference = _mapping(certificate.get("frozen_manifest"))
    path = _contained_file(context.root, str(reference.get("path") or ""), "frozen manifest")
    if path != context.root / "frozen_manifest.json":
        raise CertificateError("certificate references another frozen manifest")
    if _sha256_file(path) != str(reference.get("sha256") or ""):
        raise CertificateError("certificate frozen-manifest hash changed")


def _check_tool_references(root: Path, certificate: Mapping[str, Any]) -> None:
    tools = _mapping(certificate.get("tools"))
    checker = _mapping(tools.get("checker"))
    generator = _mapping(tools.get("generator"))
    for label, reference in (("checker", checker), ("generator", generator)):
        path = _contained_file(root, str(reference.get("path") or ""), label)
        if _sha256_file(path) != str(reference.get("sha256") or ""):
            raise CertificateError(f"certificate {label} tool changed")
    if _sha256_file(Path(__file__).resolve()) != str(checker.get("sha256") or ""):
        raise CertificateError("running checker differs from the certificate checker")
    if str(certificate.get("rule_id") or "") == SEMANTIC_INVESTIGATION_RULE:
        from binary_agent import adjudication_investigation, adjudication_verifier

        for label, live in (
            ("investigation", Path(adjudication_investigation.__file__).resolve()),
            ("verifier", Path(adjudication_verifier.__file__).resolve()),
        ):
            reference = _mapping(tools.get(label))
            path = _contained_file(root, str(reference.get("path") or ""), label)
            if _sha256_file(path) != str(reference.get("sha256") or ""):
                raise CertificateError(f"certificate {label} tool changed")
            if _sha256_file(live) != str(reference.get("sha256") or ""):
                raise CertificateError(f"running {label} differs from the certificate")


def _check_binding_reference(context: CampaignContext, certificate: Mapping[str, Any]) -> None:
    reference = _mapping(certificate.get("prepared_binding"))
    path = _contained_file(context.root, str(reference.get("path") or ""), "prepared binding")
    expected = context.root / "bindings" / f"{context.candidate.get('candidate_id')}.json"
    if path != expected or _sha256_file(path) != str(reference.get("sha256") or ""):
        raise CertificateError("certificate prepared binding changed")
    if str(reference.get("address") or "") != str(context.binding.get("address") or ""):
        raise CertificateError("certificate operation address changed")
    if str(reference.get("pcode") or "") != str(context.binding.get("pcode") or ""):
        raise CertificateError("certificate p-code changed")


def _elf_layout(path: Path) -> tuple[bytes, int, list[dict[str, int]]]:
    data = Path(path).read_bytes()
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise CertificateError(f"not an ELF file: {path}")
    elf_class = data[4]
    byte_order = data[5]
    if byte_order not in {1, 2}:
        raise CertificateError(f"unsupported ELF byte order: {path}")
    endian = "<" if byte_order == 1 else ">"
    try:
        if elf_class == 2:
            header = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
            program_offset, entry_size, entry_count = header[4], header[8], header[9]
            program_format = endian + "IIQQQQQQ"
        elif elf_class == 1:
            header = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
            program_offset, entry_size, entry_count = header[4], header[8], header[9]
            program_format = endian + "IIIIIIII"
        else:
            raise CertificateError(f"unsupported ELF class: {path}")
    except struct.error as exc:
        raise CertificateError(f"truncated ELF header: {path}") from exc
    expected_size = struct.calcsize(program_format)
    if entry_size < expected_size or entry_count <= 0:
        raise CertificateError(f"ELF has no valid program headers: {path}")
    segments: list[dict[str, int]] = []
    for index in range(entry_count):
        try:
            values = struct.unpack_from(program_format, data, program_offset + index * entry_size)
        except struct.error as exc:
            raise CertificateError(f"truncated ELF program headers: {path}") from exc
        if elf_class == 2:
            segment_type, flags, file_offset, virtual_address, _, file_size, _, _ = values
        else:
            segment_type, file_offset, virtual_address, _, file_size, _, flags, _ = values
        if segment_type != 1:
            continue
        if file_offset + file_size > len(data):
            raise CertificateError(f"ELF load segment exceeds file bounds: {path}")
        segments.append(
            {
                "flags": int(flags),
                "file_offset": int(file_offset),
                "virtual_address": int(virtual_address),
                "file_size": int(file_size),
            }
        )
    return data, int(header[0]), segments


def _executable_fingerprint(path: Path) -> dict[str, Any]:
    data, _, segments = _elf_layout(path)
    digest = hashlib.sha256()
    total = 0
    count = 0
    for segment in segments:
        if not segment["flags"] & 1:
            continue
        start = segment["file_offset"]
        size = segment["file_size"]
        payload = data[start : start + size]
        digest.update(struct.pack(">Q", len(payload)))
        digest.update(payload)
        total += len(payload)
        count += 1
    if not count:
        raise CertificateError(f"ELF has no executable load segment: {path}")
    return {"sha256": digest.hexdigest(), "size_bytes": total, "segment_count": count}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CertificateError(f"invalid JSON artifact {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise CertificateError(f"JSON artifact must be an object: {path}")
    return dict(payload)


def _read_source_text(path: Path) -> str:
    """Decode pinned source without assuming every comment is UTF-8.

    C tokens used by the proof rules are ASCII. UTF-8 is preferred, while a
    Latin-1 fallback preserves every byte one-to-one for older source trees
    that contain non-UTF-8 author or copyright text.
    """

    data = Path(path).read_bytes()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


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


def _contained_directory(root: Path, value: Path | str, label: str) -> Path:
    path = Path(value)
    candidate = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise CertificateError(f"{label} escapes the campaign root: {value}") from exc
    if not candidate.is_dir():
        raise CertificateError(f"{label} is missing: {value}")
    return candidate


def _relative_if_contained(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(root))
    except ValueError as exc:
        raise CertificateError(f"source path escapes the campaign root: {path}") from exc


def _normalized_frame_path(root: Path, value: str) -> str:
    """Keep compiler-relative display paths distinct from evidence paths."""

    path = Path(value)
    if not path.is_absolute():
        return value
    return _relative_if_contained(
        root,
        _resolve_campaign_frame_file(root, value, "DWARF frame source"),
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _mapping_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _hex_int(value: Any, label: str) -> int:
    text = str(value or "")
    if not re.fullmatch(r"0x[0-9A-Fa-f]+", text):
        raise CertificateError(f"invalid {label}: {value!r}")
    return int(text, 16)


def _hex(value: int) -> str:
    return f"0x{value:X}"
