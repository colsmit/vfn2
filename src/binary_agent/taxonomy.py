"""Canonical vulnerability taxonomy and proof-policy registry.

This module is deliberately neutral: discovery, replay, promotion, and reporting
all import the same immutable specifications instead of maintaining local sets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


ACTIVE_BACKENDS = frozenset(
    {"memory_access", "memory_lifetime", "semantic_effect", "static_evidence"}
)
RESERVED_BACKENDS = frozenset(
    {"resource_usage", "concurrency", "control_flow", "crypto_protocol", "protocol_logic"}
)
PROOF_POLICIES = ACTIVE_BACKENDS


@dataclass(frozen=True)
class VulnerabilitySpec:
    """One terminal security claim and the backend responsible for proving it."""

    name: str
    backend: str
    mechanism: str
    proof_policy: str
    effect_kind: str
    cwe_ids: tuple[str, ...]
    default_severity: str


def _spec(
    name: str,
    backend: str,
    mechanism: str,
    cwe_ids: tuple[str, ...],
    severity: str,
    *,
    effect_kind: str = "",
) -> VulnerabilitySpec:
    return VulnerabilitySpec(
        name=name,
        backend=backend,
        mechanism=mechanism,
        proof_policy=backend,
        effect_kind=effect_kind,
        cwe_ids=cwe_ids,
        default_severity=severity,
    )


_SPECS = (
    # Spatial memory access. Arithmetic defects are root causes, not entries.
    _spec("stack_overflow", "memory_access", "out_of_bounds_write", ("CWE-121",), "high"),
    _spec("heap_overflow", "memory_access", "out_of_bounds_write", ("CWE-122",), "high"),
    _spec("out_of_bounds_write", "memory_access", "out_of_bounds_write", ("CWE-787",), "high"),
    _spec("out_of_bounds_read", "memory_access", "out_of_bounds_read", ("CWE-125",), "high"),
    _spec("null_pointer_dereference", "memory_access", "null_dereference", ("CWE-476",), "medium"),
    _spec("uninitialized_memory_use", "memory_access", "undefined_read", ("CWE-457",), "high"),
    _spec("overlapping_memory_copy", "memory_access", "overlapping_ranges", ("CWE-475",), "high"),
    # Resource lifetime and ownership.
    _spec("use_after_free", "memory_lifetime", "use_after_release", ("CWE-416",), "critical"),
    _spec("double_free", "memory_lifetime", "duplicate_release", ("CWE-415",), "critical"),
    _spec("invalid_free", "memory_lifetime", "invalid_release", ("CWE-590",), "high"),
    _spec("memory_leak", "memory_lifetime", "live_at_scope_exit", ("CWE-401",), "medium"),
    _spec("mismatched_deallocator", "memory_lifetime", "allocator_family_mismatch", ("CWE-762",), "high"),
    _spec("double_close", "memory_lifetime", "duplicate_handle_close", ("CWE-1341",), "high"),
    _spec("use_after_close", "memory_lifetime", "handle_use_after_close", ("CWE-672",), "high"),
    # Concrete process-visible effects.
    _spec("command_injection", "semantic_effect", "shell_metacharacter_injection", ("CWE-78",), "critical", effect_kind="command_effect"),
    _spec("path_traversal", "semantic_effect", "directory_escape", ("CWE-22",), "high", effect_kind="filesystem_read_escape"),
    _spec("unsafe_file_write", "semantic_effect", "attacker_selected_write", ("CWE-73",), "high", effect_kind="filesystem_write_escape"),
    _spec("format_string", "semantic_effect", "attacker_controlled_format", ("CWE-134",), "high", effect_kind="format_string_effect"),
    _spec("credential_disclosure", "semantic_effect", "secret_output", ("CWE-200", "CWE-522"), "high", effect_kind="credential_disclosure"),
    _spec("auth_bypass", "semantic_effect", "authorization_decision_bypass", ("CWE-287",), "critical", effect_kind="auth_bypass_effect"),
    _spec("sql_injection", "semantic_effect", "query_text_injection", ("CWE-89",), "critical", effect_kind="query_execution"),
    _spec("argument_injection", "semantic_effect", "process_argument_injection", ("CWE-88",), "high", effect_kind="process_argv"),
    _spec("code_injection", "semantic_effect", "dynamic_code_evaluation", ("CWE-94",), "critical", effect_kind="code_evaluation"),
    _spec("server_side_request_forgery", "semantic_effect", "attacker_selected_outbound_target", ("CWE-918",), "high", effect_kind="outbound_connection"),
    _spec("http_header_injection", "semantic_effect", "header_delimiter_injection", ("CWE-113",), "high", effect_kind="http_header_emission"),
    _spec("log_injection", "semantic_effect", "log_delimiter_injection", ("CWE-117",), "medium", effect_kind="log_emission"),
    _spec("open_redirect", "semantic_effect", "attacker_selected_redirect", ("CWE-601",), "medium", effect_kind="redirect_emission"),
    # Exact reachable literals or security configuration.
    _spec("hardcoded_credential", "static_evidence", "embedded_credential", ("CWE-798",), "high", effect_kind="embedded_secret"),
    _spec("default_credential", "static_evidence", "shipped_default_credential", ("CWE-1392",), "critical", effect_kind="default_credential"),
    _spec("embedded_private_key", "static_evidence", "embedded_private_key", ("CWE-321",), "critical", effect_kind="private_key_literal"),
    _spec("embedded_api_token", "static_evidence", "embedded_api_token", ("CWE-798",), "high", effect_kind="api_token_literal"),
    _spec("weak_cryptography", "static_evidence", "weak_algorithm_configuration", ("CWE-327",), "high", effect_kind="weak_crypto_configuration"),
    _spec("insecure_randomness", "static_evidence", "non_cryptographic_randomness", ("CWE-338",), "high", effect_kind="insecure_random_api"),
    _spec("disabled_certificate_validation", "static_evidence", "certificate_validation_disabled", ("CWE-295",), "critical", effect_kind="tls_validation_configuration"),
)

VULNERABILITY_SPECS: Mapping[str, VulnerabilitySpec] = {spec.name: spec for spec in _SPECS}


def validate_taxonomy(specs: Iterable[VulnerabilitySpec] = _SPECS) -> None:
    """Raise a descriptive error when the canonical registry is incomplete."""

    rows = tuple(specs)
    names = [row.name for row in rows]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"Duplicate vulnerability types: {', '.join(duplicates)}")
    for row in rows:
        if not row.name:
            raise ValueError("Vulnerability type names must be non-empty")
        if row.backend not in ACTIVE_BACKENDS:
            raise ValueError(f"{row.name}: unknown active backend {row.backend!r}")
        if row.proof_policy not in PROOF_POLICIES:
            raise ValueError(f"{row.name}: invalid proof policy {row.proof_policy!r}")
        if row.proof_policy != row.backend:
            raise ValueError(f"{row.name}: proof policy must match its sole backend")
        if not row.mechanism:
            raise ValueError(f"{row.name}: mechanism is required")
        if not row.cwe_ids or any(not item.startswith("CWE-") for item in row.cwe_ids):
            raise ValueError(f"{row.name}: at least one normalized CWE id is required")
        if row.default_severity not in {"low", "medium", "high", "critical"}:
            raise ValueError(f"{row.name}: invalid default severity {row.default_severity!r}")


def get_vulnerability_spec(name: str) -> VulnerabilitySpec:
    try:
        return VULNERABILITY_SPECS[str(name)]
    except KeyError as exc:
        raise ValueError(f"Unknown vulnerability type: {name!r}") from exc


def vulnerability_types_for_backend(backend: str) -> frozenset[str]:
    if backend not in ACTIVE_BACKENDS:
        raise ValueError(f"Unknown discovery backend: {backend!r}")
    return frozenset(name for name, spec in VULNERABILITY_SPECS.items() if spec.backend == backend)


def validate_selection(
    backends: Iterable[str] | None = None,
    vulnerability_types: Iterable[str] | None = None,
) -> tuple[frozenset[str], frozenset[str]]:
    selected_backends = frozenset(backends or ACTIVE_BACKENDS)
    unknown_backends = selected_backends - ACTIVE_BACKENDS
    if unknown_backends:
        raise ValueError(f"Unknown discovery backend(s): {', '.join(sorted(unknown_backends))}")
    selected_types = frozenset(vulnerability_types or VULNERABILITY_SPECS)
    unknown_types = selected_types - VULNERABILITY_SPECS.keys()
    if unknown_types:
        raise ValueError(f"Unknown vulnerability type(s): {', '.join(sorted(unknown_types))}")
    mismatched = sorted(name for name in selected_types if VULNERABILITY_SPECS[name].backend not in selected_backends)
    if mismatched:
        raise ValueError(
            "Vulnerability type selection is outside the selected backends: "
            + ", ".join(mismatched)
        )
    return selected_backends, selected_types


validate_taxonomy()
