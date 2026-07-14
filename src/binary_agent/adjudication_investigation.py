"""Untrusted investigation providers and immutable adjudication evidence packs.

This module is deliberately separate from review admission.  A provider can
suggest a decision or an experiment, but its output is only a proposal.  The
semantic verifier is responsible for turning a proposal into checked evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from binary_agent.adjudication import sha256_file
from binary_agent.adjudication_certificates import (
    CertificateError,
    RuleNotApplicable,
    _disassembly_window,
    _exact_source_context,
    _mapping,
    _mapping_rows,
    _relative_if_contained,
    load_campaign_context,
)


SCHEMA_VERSION = 1
PACK_KIND = "binary_adjudication_investigation_pack"
PROPOSAL_KIND = "binary_adjudication_investigation_proposal"
ATTEMPT_KIND = "binary_adjudication_investigation_attempt"
ALLOWED_TIERS = frozenset({"direct", "agent"})
ALLOWED_PROPOSED_DECISIONS = frozenset({"bug", "not_bug", "escalate"})
ALLOWED_CLAIM_KINDS = frozenset(
    {
        "spatial_path",
        "null_path",
        "initialization_path",
        "ownership_path",
        "trust_boundary",
        "modeling_error",
        "unresolved",
    }
)


class InvestigationError(ValueError):
    """Raised when a pack or untrusted provider result violates its contract."""


class InvestigationProvider(Protocol):
    """Provider-neutral interface shared by direct models and coding agents."""

    def investigate(
        self,
        pack: Mapping[str, Any],
        *,
        tier: str,
    ) -> Mapping[str, Any]:
        """Return one untrusted proposal for a checked investigation pack."""


@dataclass(frozen=True)
class ExternalCommandInvestigationProvider:
    """Exchange one JSON pack/proposal with an external command.

    The command receives the complete pack on standard input.  It runs from a
    caller-selected task directory so a coding-agent adapter can inspect only
    the files deliberately copied or linked there.  Provider metadata is added
    under the reserved ``_provider_metadata`` key and is never interpreted as
    proof.
    """

    command: Sequence[str]
    timeout_seconds: float | None = None
    max_output_bytes: int = 1_000_000
    working_directory: Path | None = None
    environment: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.command:
            raise ValueError("Investigation provider command must not be empty.")
        if self.max_output_bytes <= 0:
            raise ValueError("Investigation provider output limit must be positive.")

    @classmethod
    def from_command_string(
        cls,
        command: str,
        *,
        timeout_seconds: float | None = None,
        max_output_bytes: int = 1_000_000,
        working_directory: Path | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> "ExternalCommandInvestigationProvider":
        return cls(
            shlex.split(command),
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            working_directory=working_directory,
            environment=dict(environment or {}),
        )

    def investigate(
        self,
        pack: Mapping[str, Any],
        *,
        tier: str,
    ) -> Mapping[str, Any]:
        if tier not in ALLOWED_TIERS:
            raise InvestigationError(f"unsupported investigation tier: {tier!r}")
        command = [str(item) for item in self.command]
        env = dict(os.environ)
        env.update({str(key): str(value) for key, value in self.environment.items()})
        env["BINARY_AGENT_ADJUDICATION_TIER"] = tier
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                input=_canonical_json_bytes(pack),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout_seconds,
                check=False,
                cwd=str(self.working_directory) if self.working_directory else None,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise InvestigationError(
                f"investigation provider timed out after {self.timeout_seconds} seconds"
            ) from exc
        except OSError as exc:
            raise InvestigationError(f"cannot execute investigation provider: {exc}") from exc
        duration = time.monotonic() - started
        if completed.returncode != 0:
            raise InvestigationError(
                "investigation provider exited with status "
                f"{completed.returncode}; stderr_sha256={hashlib.sha256(completed.stderr).hexdigest()}"
            )
        if len(completed.stdout) > self.max_output_bytes:
            raise InvestigationError(
                f"investigation provider output exceeds {self.max_output_bytes} bytes"
            )
        if not completed.stdout.strip():
            raise InvestigationError("investigation provider produced no JSON")
        try:
            proposal = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvestigationError("investigation provider produced invalid JSON") from exc
        if not isinstance(proposal, Mapping):
            raise InvestigationError("investigation provider output must be a JSON object")
        result = dict(proposal)
        result["_provider_metadata"] = {
            "tier": tier,
            "command": command,
            "command_executable": _command_identity(command[0]),
            "duration_seconds": round(duration, 6),
            "exit_status": completed.returncode,
            "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
            "stderr_size_bytes": len(completed.stderr),
            "max_output_bytes": self.max_output_bytes,
        }
        return result


@dataclass(frozen=True)
class InvestigationAttempt:
    candidate_id: str
    tier: str
    status: str
    pack_path: str
    pack_sha256: str
    proposal_path: str = ""
    proposal_sha256: str = ""
    error: str = ""
    provider_metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class InvestigationPackResult:
    path: Path
    sha256: str
    candidate_id: str


def build_investigation_pack(
    campaign_root: Path,
    candidate_id: str,
    output_dir: Path,
) -> Path:
    """Write a deterministic, label-free evidence pack for one frozen candidate."""

    root = Path(campaign_root).resolve()
    context = load_campaign_context(root, candidate_id)
    binding_path = root / "bindings" / f"{candidate_id}.json"
    manifest_path = root / "frozen_manifest.json"
    source = _exact_source_context(context)
    source_path = Path(source["source_path"]).resolve()
    source_text = source_path.read_text(encoding="utf-8")
    frame = _mapping(source.get("frame"))
    function_name = str(frame.get("function") or context.binding.get("function_name") or "")
    line_number = int(frame.get("line") or 0)
    function_text, function_start_line, operation_line_in_function = _extract_c_function(
        source_text,
        function_name=function_name,
        approximate_line=line_number,
    )
    function_sha256 = hashlib.sha256(function_text.encode("utf-8")).hexdigest()

    input_row = context.input_row
    state_path = root / str(input_row.get("candidate_states_path") or "")
    binary_path = root / str(input_row.get("binary_path") or "")
    export_path = root / str(input_row.get("export_manifest_path") or "")
    mapping_ref = next(
        (
            item
            for item in _mapping_rows(context.manifest.get("reference_build_mappings"))
            if str(item.get("binary") or "") == str(context.candidate.get("binary") or "")
        ),
        None,
    )
    if mapping_ref is None:
        raise InvestigationError("candidate has no frozen reference-build mapping")
    mapping_path = root / str(mapping_ref.get("path") or "")
    mapping_payload = _load_json(mapping_path)
    source_mapping = _mapping(mapping_payload.get("source"))
    source_root = root / str(source_mapping.get("path") or "")
    source_tree = _source_tree_inventory(root, source_root)

    pack = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": PACK_KIND,
        "candidate_id": candidate_id,
        "binary": str(context.candidate.get("binary") or ""),
        "vulnerability_type": str(context.candidate.get("vulnerability_type") or ""),
        "candidate": context.candidate,
        "candidate_state": context.state,
        "exact_operation": context.binding,
        "source_context": {
            "path": _relative_if_contained(root, source_path),
            "sha256": sha256_file(source_path),
            "commit": str(_mapping(source["mapping"]).get("source", {}).get("commit") or "")
            if isinstance(_mapping(source["mapping"]).get("source"), Mapping)
            else "",
            "function": function_name,
            "function_start_line": function_start_line,
            "operation_line_in_function": operation_line_in_function,
            "function_sha256": function_sha256,
            "function_text": function_text,
        },
        "source_tree": source_tree,
        "binary_context": {
            "disassembly_window": _disassembly_window(context, before=96, after=128),
            "export_function": _export_function(context),
        },
        "entry_surfaces": _candidate_entry_surfaces(context.export_manifest, context.binding),
        "proof_contract": _proof_contract(str(context.candidate.get("vulnerability_type") or "")),
        "proposal_contract": {
            "artifact_kind": PROPOSAL_KIND,
            "allowed_decisions": sorted(ALLOWED_PROPOSED_DECISIONS),
            "allowed_claim_kinds": sorted(ALLOWED_CLAIM_KINDS),
            "model_is_not_authority": True,
            "required_fields": [
                "schema_version",
                "artifact_kind",
                "candidate_id",
                "proposed_decision",
                "claim_kind",
                "exact_operation",
                "path_steps",
                "claims",
                "root_cause",
                "nearby_defects",
            ],
        },
        "input_refs": [
            _file_ref(root, manifest_path, "frozen_manifest"),
            _file_ref(root, state_path, "candidate_states_v2"),
            _file_ref(root, binary_path, "frozen_binary"),
            _file_ref(root, export_path, "ghidra_export_manifest"),
            _file_ref(root, binding_path, "exact_binary_operation"),
            _file_ref(root, mapping_path, "reference_build_mapping"),
            _file_ref(root, source_path, "exact_source"),
        ],
    }
    output = Path(output_dir) / f"{_safe_stem(candidate_id)}.json"
    _write_exact_json(output, pack)
    return output


def check_investigation_pack(campaign_root: Path, pack_path: Path) -> Mapping[str, Any]:
    """Reload a pack and verify it is an exact derivation of frozen inputs."""

    root = Path(campaign_root).resolve()
    path = Path(pack_path).resolve()
    pack = _load_json(path)
    if int(pack.get("schema_version") or 0) != SCHEMA_VERSION:
        raise InvestigationError("investigation pack has the wrong schema version")
    if str(pack.get("artifact_kind") or "") != PACK_KIND:
        raise InvestigationError("artifact is not an investigation pack")
    candidate_id = str(pack.get("candidate_id") or "")
    with tempfile.TemporaryDirectory(prefix="adjudication_pack_check_") as raw:
        expected_path = build_investigation_pack(root, candidate_id, Path(raw))
        expected = expected_path.read_bytes()
    if path.read_bytes() != expected:
        raise InvestigationError("investigation pack differs from frozen evidence derivation")
    return pack


def validate_proposal_shape(
    proposal: Mapping[str, Any],
    *,
    candidate_id: str,
) -> dict[str, Any]:
    """Validate syntax only; semantic verification happens in another module."""

    data = {key: value for key, value in proposal.items() if key != "_provider_metadata"}
    if int(data.get("schema_version") or 0) != SCHEMA_VERSION:
        raise InvestigationError("proposal has the wrong schema version")
    if str(data.get("artifact_kind") or "") != PROPOSAL_KIND:
        raise InvestigationError("provider output is not an investigation proposal")
    if str(data.get("candidate_id") or "") != candidate_id:
        raise InvestigationError("proposal candidate does not match its pack")
    decision = str(data.get("proposed_decision") or "")
    if decision not in ALLOWED_PROPOSED_DECISIONS:
        raise InvestigationError(f"unsupported proposed decision: {decision!r}")
    claim_kind = str(data.get("claim_kind") or "")
    if claim_kind not in ALLOWED_CLAIM_KINDS:
        raise InvestigationError(f"unsupported proposal claim kind: {claim_kind!r}")
    for key in ("exact_operation", "claims", "root_cause"):
        if not isinstance(data.get(key), Mapping):
            raise InvestigationError(f"proposal field {key!r} must be an object")
    for key in ("path_steps", "nearby_defects"):
        if not isinstance(data.get(key), list):
            raise InvestigationError(f"proposal field {key!r} must be a list")
    return data


def run_provider_attempt(
    campaign_root: Path,
    pack_path: Path,
    provider: InvestigationProvider,
    *,
    tier: str,
    output_dir: Path,
) -> InvestigationAttempt:
    """Run one untrusted provider and persist an immutable proposal or error."""

    if tier not in ALLOWED_TIERS:
        raise InvestigationError(f"unsupported investigation tier: {tier!r}")
    root = Path(campaign_root).resolve()
    pack = check_investigation_pack(root, pack_path)
    candidate_id = str(pack.get("candidate_id") or "")
    attempt_root = Path(output_dir) / tier / _safe_stem(candidate_id)
    attempt_root.mkdir(parents=True, exist_ok=True)
    pack_hash = sha256_file(Path(pack_path))
    try:
        raw = provider.investigate(pack, tier=tier)
        provider_metadata = dict(_mapping(raw.get("_provider_metadata")))
        proposal = validate_proposal_shape(raw, candidate_id=candidate_id)
        proposal_path = attempt_root / "proposal.json"
        _write_exact_json(proposal_path, proposal)
        return InvestigationAttempt(
            candidate_id=candidate_id,
            tier=tier,
            status="proposed",
            pack_path=_relative_if_contained(root, Path(pack_path)),
            pack_sha256=pack_hash,
            proposal_path=_relative_if_contained(root, proposal_path),
            proposal_sha256=sha256_file(proposal_path),
            provider_metadata=provider_metadata,
        )
    except (InvestigationError, OSError, ValueError) as exc:
        error_path = attempt_root / "error.json"
        error_payload = {
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": ATTEMPT_KIND + "_error",
            "candidate_id": candidate_id,
            "tier": tier,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        _write_exact_json(error_path, error_payload)
        return InvestigationAttempt(
            candidate_id=candidate_id,
            tier=tier,
            status="error",
            pack_path=_relative_if_contained(root, Path(pack_path)),
            pack_sha256=pack_hash,
            error=str(exc),
        )


def _extract_c_function(
    source_text: str,
    *,
    function_name: str,
    approximate_line: int,
) -> tuple[str, int, int]:
    """Return a complete C function using a lexical brace mask.

    This locator intentionally uses no expected source line.  The line from
    DWARF is only a disambiguating position when a name occurs more than once.
    Comments and string/character literals are blanked before matching braces.
    """

    masked = _c_lexical_mask(source_text)
    pattern = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    candidates: list[tuple[int, int]] = []
    for match in pattern.finditer(masked):
        brace = masked.find("{", match.end())
        semicolon = masked.find(";", match.end())
        if brace < 0 or (0 <= semicolon < brace):
            continue
        close = _matching_brace(masked, brace)
        if close is not None:
            candidates.append((match.start(), close + 1))
    if not candidates:
        raise InvestigationError(f"cannot locate source function {function_name!r}")
    approximate_offset = _line_start_offset(source_text, approximate_line)
    containing = [item for item in candidates if item[0] <= approximate_offset < item[1]]
    start, end = containing[0] if len(containing) == 1 else min(
        candidates,
        key=lambda item: abs(item[0] - approximate_offset),
    )
    line_start = source_text.rfind("\n", 0, start) + 1
    function_text = source_text[line_start:end].rstrip() + "\n"
    function_start_line = source_text.count("\n", 0, line_start) + 1
    operation_line = max(1, approximate_line - function_start_line + 1)
    return function_text, function_start_line, operation_line


def _c_lexical_mask(text: str) -> str:
    result = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                result[index] = result[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == "/" and nxt == "*":
                result[index] = result[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char in {'"', "'"}:
                quote = char
                result[index] = " "
                state = "quoted"
                index += 1
                continue
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                result[index] = " "
            index += 1
            continue
        elif state == "block_comment":
            if char == "*" and nxt == "/":
                result[index] = result[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                result[index] = " "
            index += 1
            continue
        elif state == "quoted":
            if char == "\\" and nxt:
                result[index] = result[index + 1] = " "
                index += 2
                continue
            if char == quote:
                result[index] = " "
                state = "code"
            elif char != "\n":
                result[index] = " "
            index += 1
            continue
        index += 1
    return "".join(result)


def _matching_brace(masked: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _line_start_offset(text: str, line_number: int) -> int:
    if line_number <= 1:
        return 0
    offset = 0
    for _ in range(line_number - 1):
        found = text.find("\n", offset)
        if found < 0:
            return len(text)
        offset = found + 1
    return offset


def _export_function(context: Any) -> Mapping[str, Any]:
    address = str(context.binding.get("function_address") or "").lower()
    name = str(context.binding.get("function_name") or "")
    matches = [
        item
        for item in _mapping_rows(context.export_manifest.get("functions"))
        if str(item.get("address") or "").lower() == address
        and str(item.get("name") or "") == name
    ]
    if len(matches) != 1:
        raise InvestigationError("exact operation function is absent from export manifest")
    return matches[0]


def _candidate_entry_surfaces(
    manifest: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    function_address = str(binding.get("function_address") or "").lower()
    surfaces = _mapping_rows(manifest.get("entry_surfaces"))
    selected = [
        item
        for item in surfaces
        if str(item.get("function_address") or item.get("address") or "").lower()
        == function_address
    ]
    return selected or surfaces


def _proof_contract(vulnerability_type: str) -> Mapping[str, Any]:
    common = ["exact_operation", "source_or_binary_binding", "real_entry_reachability"]
    if vulnerability_type in {"stack_overflow", "out_of_bounds_write"}:
        required = common + ["exact_store", "object_identity", "capacity", "offset_relation"]
    elif vulnerability_type == "null_pointer_dereference":
        required = common + ["pointer_origin", "null_path", "earliest_fault"]
    elif vulnerability_type == "uninitialized_memory_use":
        required = common + ["definition_paths", "use_path"]
    elif vulnerability_type == "memory_leak":
        required = common + ["ownership", "lifetime", "repeatable_external_action"]
    else:
        required = common + ["trust_boundary", "attacker_control"]
    return {
        "vulnerability_type": vulnerability_type,
        "required_claims": required,
        "negative_evidence_is_insufficient": True,
        "exact_candidate_cannot_be_replaced_by_nearby_defect": True,
    }


def _file_ref(root: Path, path: Path, kind: str) -> Mapping[str, str]:
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise InvestigationError(f"evidence path escapes campaign root: {path}") from exc
    if not resolved.is_file():
        raise InvestigationError(f"evidence file is missing: {path}")
    return {
        "path": str(resolved.relative_to(root)),
        "sha256": sha256_file(resolved),
        "kind": kind,
    }


def _source_tree_inventory(root: Path, source_root: Path) -> Mapping[str, Any]:
    """Hash the C source corpus used for cross-file reachability proofs."""

    resolved = source_root.resolve()
    try:
        relative_root = resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise InvestigationError(f"source root escapes campaign root: {source_root}") from exc
    if not resolved.is_dir():
        raise InvestigationError(f"mapped source root is missing: {source_root}")
    files = [
        {
            "path": str(path.resolve().relative_to(root.resolve())),
            "sha256": sha256_file(path),
        }
        for path in sorted(resolved.rglob("*"))
        if path.is_file() and path.suffix.lower() in {".c", ".h"}
    ]
    if not files:
        raise InvestigationError(f"mapped source root has no C source files: {source_root}")
    digest = hashlib.sha256(_canonical_json_bytes({"files": files})).hexdigest()
    return {
        "root": str(relative_root),
        "sha256": digest,
        "files": files,
    }


def _command_identity(value: str) -> Mapping[str, Any]:
    candidate = Path(value)
    if candidate.is_file():
        return {
            "path": str(candidate.resolve()),
            "sha256": sha256_file(candidate.resolve()),
        }
    return {"path": value, "sha256": ""}


def _safe_stem(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)[:180] or "candidate"


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_exact_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _canonical_json_bytes(value)
    if path.exists():
        if path.read_bytes() != data:
            raise InvestigationError(f"immutable investigation artifact differs: {path}")
        return
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
    os.replace(temporary, path)


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvestigationError(f"cannot load JSON artifact {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise InvestigationError(f"JSON artifact must be an object: {path}")
    return value
