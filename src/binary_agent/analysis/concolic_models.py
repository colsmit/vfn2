"""Stable data models shared by concolic analysis and callers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class CrashWitness:
    """Concrete input and execution notes produced by a concolic backend."""

    input_model: str
    stdin: bytes | None = None
    argv: tuple[bytes, ...] = ()
    file_inputs: Mapping[str, bytes] = field(default_factory=dict)
    env: Mapping[str, bytes] = field(default_factory=dict)
    function_args: Mapping[str, str] = field(default_factory=dict)
    reached_addresses: tuple[str, ...] = ()
    crash_signal: str = ""
    simulated_invalid_write: str = ""
    solver_model: Mapping[str, Any] = field(default_factory=dict)
    logs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_model": self.input_model,
            "stdin_hex": self.stdin.hex() if self.stdin is not None else "",
            "argv_hex": [item.hex() for item in self.argv],
            "file_inputs_hex": {str(key): value.hex() for key, value in self.file_inputs.items()},
            "env_hex": {str(key): value.hex() for key, value in self.env.items()},
            "function_args": dict(self.function_args),
            "reached_addresses": list(self.reached_addresses),
            "crash_signal": self.crash_signal,
            "simulated_invalid_write": self.simulated_invalid_write,
            "solver_model": dict(self.solver_model),
            "logs": list(self.logs),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CrashWitness":
        return cls(
            input_model=str(data.get("input_model") or ""),
            stdin=_bytes_from_hex(data.get("stdin_hex")),
            argv=tuple(_bytes_from_hex(item) or b"" for item in _coerce_sequence(data.get("argv_hex", []))),
            file_inputs={
                str(key): _bytes_from_hex(value) or b""
                for key, value in (data.get("file_inputs_hex") or {}).items()
            }
            if isinstance(data.get("file_inputs_hex"), Mapping)
            else {},
            env={str(key): _bytes_from_hex(value) or b"" for key, value in (data.get("env_hex") or {}).items()}
            if isinstance(data.get("env_hex"), Mapping)
            else {},
            function_args=dict(data.get("function_args") or {}) if isinstance(data.get("function_args"), Mapping) else {},
            reached_addresses=tuple(str(item) for item in _coerce_sequence(data.get("reached_addresses", []))),
            crash_signal=str(data.get("crash_signal") or ""),
            simulated_invalid_write=str(data.get("simulated_invalid_write") or ""),
            solver_model=dict(data.get("solver_model") or {}) if isinstance(data.get("solver_model"), Mapping) else {},
            logs=tuple(str(item) for item in _coerce_sequence(data.get("logs", []))),
        )

@dataclass(frozen=True)
class ConcolicRequest:
    """Validated backend request for one evidence-pack candidate."""

    candidate_id: str
    binary_path: Path
    export_dir: Path | None = None
    backend: str = "angr"
    target_address: str = ""
    sink_address: str = ""
    input_model: str = "argv"
    symbolic_bytes: int = 256
    constraints: tuple[str, ...] = ()
    timeout_seconds: float = 30.0
    extra_branch_goal: str = ""
    waypoint_addresses: tuple[str, ...] = ()
    allowed_stubs: tuple[str, ...] = ()
    seed_mutations: tuple[str, ...] = ()
    target_resolution: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "binary_path": str(self.binary_path),
            "export_dir": str(self.export_dir) if self.export_dir is not None else "",
            "backend": self.backend,
            "target_address": self.target_address,
            "sink_address": self.sink_address,
            "input_model": self.input_model,
            "symbolic_bytes": self.symbolic_bytes,
            "constraints": list(self.constraints),
            "timeout_seconds": self.timeout_seconds,
            "extra_branch_goal": self.extra_branch_goal,
            "waypoint_addresses": list(self.waypoint_addresses),
            "allowed_stubs": list(self.allowed_stubs),
            "seed_mutations": list(self.seed_mutations),
            "target_resolution": dict(self.target_resolution),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ConcolicRequest":
        export_dir = str(data.get("export_dir") or "")
        return cls(
            candidate_id=str(data.get("candidate_id") or ""),
            binary_path=Path(str(data.get("binary_path") or "")),
            export_dir=Path(export_dir) if export_dir else None,
            backend=str(data.get("backend") or "angr"),
            target_address=str(data.get("target_address") or ""),
            sink_address=str(data.get("sink_address") or ""),
            input_model=str(data.get("input_model") or "argv"),
            symbolic_bytes=int(data.get("symbolic_bytes") or 256),
            constraints=tuple(str(item) for item in _coerce_sequence(data.get("constraints", []))),
            timeout_seconds=float(data.get("timeout_seconds") or 30.0),
            extra_branch_goal=str(data.get("extra_branch_goal") or ""),
            waypoint_addresses=tuple(str(item) for item in _coerce_sequence(data.get("waypoint_addresses", []))),
            allowed_stubs=tuple(str(item) for item in _coerce_sequence(data.get("allowed_stubs", []))),
            seed_mutations=tuple(str(item) for item in _coerce_sequence(data.get("seed_mutations", []))),
            target_resolution=dict(data.get("target_resolution") or {})
            if isinstance(data.get("target_resolution"), Mapping)
            else {},
        )

@dataclass(frozen=True)
class AddressTranslation:
    ghidra_address: str
    relative_address: int
    loader_address: int
    image_base: int
    loader_base: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "ghidra_address": self.ghidra_address,
            "relative_address": f"0x{self.relative_address:x}",
            "loader_address": f"0x{self.loader_address:x}",
            "image_base": f"0x{self.image_base:x}",
            "loader_base": f"0x{self.loader_base:x}",
        }

@dataclass(frozen=True)
class ConcolicRunResult:
    output_dir: Path
    written: tuple[Path, ...] = ()
    skipped: tuple[str, ...] = ()
    errors: Mapping[str, str] = field(default_factory=dict)
    verdict_counts: Mapping[str, int] = field(default_factory=dict)
    eligible_count: int = 0
    scheduled_count: int = 0
    attempted_count: int = 0
    timed_out_count: int = 0
    memory_limited_count: int = 0
    diagnostic_counts: Mapping[str, int] = field(default_factory=dict)

    @property
    def written_count(self) -> int:
        return len(self.written)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    def to_dict(self) -> dict[str, Any]:
        covered = self.attempted_count + self.skipped_count
        return {
            "output_dir": str(self.output_dir),
            "written": [str(path) for path in self.written],
            "skipped": list(self.skipped),
            "errors": dict(self.errors),
            "verdict_counts": dict(self.verdict_counts),
            "eligible_count": self.eligible_count,
            "scheduled_count": self.scheduled_count,
            "attempted_count": self.attempted_count,
            "timed_out_count": self.timed_out_count,
            "memory_limited_count": self.memory_limited_count,
            "diagnostic_counts": dict(self.diagnostic_counts),
            "attempt_coverage": round(covered / self.eligible_count, 4) if self.eligible_count else 1.0,
        }

@dataclass(frozen=True)
class ConcolicToolConfig:
    """Execution limits for controller-loop ``run_concolic_poc`` requests."""

    binary_path: Path
    output_dir: Path
    export_dir: Path | None = None
    backend: str = "angr"
    timeout_seconds: float = 30.0
    max_symbolic_bytes: int = 512
    overwrite: bool = True
    ghidra_dynamic_proof: bool = False
    ghidra_dir: Path | None = None
    ghidra_dynamic_max_steps: int = 2048

@dataclass(frozen=True)
class PcodeTraceRequest:
    """Validated request for Ghidra concrete p-code trace artifacts."""

    candidate_id: str
    binary_path: Path
    output_path: Path
    ghidra_dir: Path | None = None
    function_address: str = ""
    start_address: str = ""
    target_address: str = ""
    input_model: str = ""
    max_steps: int = 2048
    timeout_seconds: float = 30.0
    sink_name: str = ""
    target_buffer: str = ""
    offset_expr: str = ""
    line_text: str = ""
    line_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "binary_path": str(self.binary_path),
            "output_path": str(self.output_path),
            "ghidra_dir": str(self.ghidra_dir) if self.ghidra_dir is not None else "",
            "function_address": self.function_address,
            "start_address": self.start_address,
            "target_address": self.target_address,
            "input_model": self.input_model,
            "max_steps": self.max_steps,
            "timeout_seconds": self.timeout_seconds,
            "sink_name": self.sink_name,
            "target_buffer": self.target_buffer,
            "offset_expr": self.offset_expr,
            "line_text": self.line_text,
            "line_number": self.line_number,
        }

@dataclass(frozen=True)
class GhidraDynamicProofRequest:
    """Validated request for Ghidra concrete memory-safety proof artifacts."""

    candidate_id: str
    binary_path: Path
    output_path: Path
    ghidra_dir: Path | None = None
    function_address: str = ""
    start_address: str = ""
    sink_address: str = ""
    proof_scope: str = ""
    input_model: str = ""
    env_name: str = ""
    env_values: Mapping[str, str] = field(default_factory=dict)
    concrete_input_hex: str = ""
    argv_values: tuple[str, ...] = ()
    stdin_input_hex: str = ""
    file_input_hex: str = ""
    file_name: str = ""
    process_input_source: str = ""
    process_input_evidence: Mapping[str, Any] = field(default_factory=dict)
    process_input_setup_reason: str = ""
    static_path_addresses: tuple[str, ...] = ()
    function_harness: Mapping[str, Any] = field(default_factory=dict)
    max_steps: int = 2048
    timeout_seconds: float = 30.0
    sink_name: str = ""
    vulnerability_type: str = "memory_overflow"
    write_relation: str = ""
    target_buffer: str = ""
    destination_kind: str = ""
    capacity_bytes: int = 0
    capacity_source: str = ""
    capacity_basis: str = ""
    offset_expr: str = "0"
    write_size_bytes: int = 0
    line_text: str = ""
    line_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "binary_path": str(self.binary_path),
            "output_path": str(self.output_path),
            "ghidra_dir": str(self.ghidra_dir) if self.ghidra_dir is not None else "",
            "function_address": self.function_address,
            "start_address": self.start_address,
            "sink_address": self.sink_address,
            "proof_scope": self.proof_scope,
            "input_model": self.input_model,
            "env_name": self.env_name,
            "env_values": dict(self.env_values),
            "concrete_input_hex": self.concrete_input_hex,
            "argv_values": list(self.argv_values),
            "stdin_input_hex": self.stdin_input_hex,
            "file_input_hex": self.file_input_hex,
            "file_name": self.file_name,
            "process_input_source": self.process_input_source,
            "process_input_evidence": dict(self.process_input_evidence),
            "process_input_setup_reason": self.process_input_setup_reason,
            "static_path_addresses": list(self.static_path_addresses),
            "function_harness": dict(self.function_harness),
            "max_steps": self.max_steps,
            "timeout_seconds": self.timeout_seconds,
            "sink_name": self.sink_name,
            "vulnerability_type": self.vulnerability_type,
            "write_relation": self.write_relation,
            "target_buffer": self.target_buffer,
            "destination_kind": self.destination_kind,
            "capacity_bytes": self.capacity_bytes,
            "capacity_source": self.capacity_source,
            "capacity_basis": self.capacity_basis,
            "offset_expr": self.offset_expr,
            "write_size_bytes": self.write_size_bytes,
            "line_text": self.line_text,
            "line_number": self.line_number,
        }


def _bytes_from_hex(value: Any) -> bytes | None:
    text = str(value or "")
    if not text:
        return None
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def _coerce_sequence(value: Any) -> list[Any]:
    if isinstance(value, str):
        return [value] if value else []
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        return []
    return list(value)


__all__ = (
    "CrashWitness",
    "ConcolicRequest",
    "AddressTranslation",
    "ConcolicRunResult",
    "ConcolicToolConfig",
    "PcodeTraceRequest",
    "GhidraDynamicProofRequest",
)
