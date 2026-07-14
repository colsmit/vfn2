"""Fail-closed OpenWrt ubus transaction planning and exact-hit attribution.

This module deliberately separates route evidence from vulnerability proof.  A
transaction-specific instruction hit says which process input reached an exact
machine operation; it never says that the operation had an unsafe effect.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import shlex
import shutil
import signal
import struct
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence

from binary_agent.replay.shim_sources import _QEMU_EXACT_INSTRUCTION_PLUGIN_SOURCE


TRANSACTION_PLAN_SCHEMA_VERSION = 1
TRACE_SCHEMA_VERSION = 1
SAFE_QUERY_METHODS = frozenset({"status", "dump", "list", "info"})
UNSAFE_METHOD_TOKENS = frozenset(
    {"set", "add", "remove", "delete", "up", "down", "reload", "restart", "enable", "disable", "write"}
)
SUPPORTED_UBUS_TYPES = frozenset({"string", "integer", "int32", "int64", "boolean", "bool", "double", "array", "table", "object"})
BROAD_BIND_TARGETS = frozenset({"/", "/lib", "/usr", "/bin", "/sbin"})
_NUMERIC_ADDRESS = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)$")
_OBJECT_LINE = re.compile(r"^\s*['\"](?P<object>[^'\"]+)['\"](?:\s*@[^\s]+)?\s*(?::\s*\{)?\s*$")
_METHOD_LINE = re.compile(r"^\s*['\"](?P<method>[^'\"]+)['\"]\s*:\s*(?P<schema>\{.*\})\s*,?\s*$")


@dataclass(frozen=True)
class FirmwareTransaction:
    """One safe, canonical ubus call variant."""

    protocol: str
    object_name: str
    method_name: str
    schema: tuple[tuple[str, str], ...]
    arguments: tuple[tuple[str, Any], ...]
    safety_classification: str
    timeout_seconds: float
    setup_key: str
    variant_id: str

    @classmethod
    def create(
        cls,
        *,
        object_name: str,
        method_name: str,
        schema: Mapping[str, str] | Sequence[tuple[str, str]],
        arguments: Mapping[str, Any] | Sequence[tuple[str, Any]],
        timeout_seconds: float = 5.0,
        setup_key: str = "",
        protocol: str = "ubus",
        safety_classification: str = "query_only_inert_payload",
    ) -> "FirmwareTransaction":
        schema_items = tuple(sorted((str(key), str(value)) for key, value in dict(schema).items()))
        argument_items = tuple(sorted((str(key), _freeze_json_value(value)) for key, value in dict(arguments).items()))
        identity = {
            "protocol": str(protocol),
            "object": str(object_name),
            "method": str(method_name),
            "schema": list(schema_items),
            "arguments": [[key, _thaw_json_value(value)] for key, value in argument_items],
            "safety_classification": str(safety_classification),
            "timeout_seconds": round(max(0.1, float(timeout_seconds)), 6),
            "setup_key": str(setup_key),
        }
        variant_id = hashlib.sha256(_canonical_json(identity).encode()).hexdigest()[:20]
        return cls(
            protocol=str(protocol),
            object_name=str(object_name),
            method_name=str(method_name),
            schema=schema_items,
            arguments=argument_items,
            safety_classification=str(safety_classification),
            timeout_seconds=max(0.1, float(timeout_seconds)),
            setup_key=str(setup_key),
            variant_id=variant_id,
        )

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(_canonical_json(self.to_dict(include_variant=False)).encode()).hexdigest()

    def to_dict(self, *, include_variant: bool = True) -> dict[str, Any]:
        payload = {
            "protocol": self.protocol,
            "object": self.object_name,
            "method": self.method_name,
            "schema": {key: value for key, value in self.schema},
            "arguments": {key: _thaw_json_value(value) for key, value in self.arguments},
            "safety_classification": self.safety_classification,
            "timeout_seconds": self.timeout_seconds,
            "setup_key": self.setup_key,
            "fingerprint": self.fingerprint if include_variant else "",
        }
        if include_variant:
            payload["variant_id"] = self.variant_id
        else:
            payload.pop("fingerprint")
        return payload


@dataclass(frozen=True)
class FirmwareTransactionPlan:
    """Immutable safe-call portfolio for one firmware target."""

    target_binary: str
    binary_sha256: str
    protocol: str
    setup_key: str
    transactions: tuple[FirmwareTransaction, ...]
    discovery_artifacts: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": TRANSACTION_PLAN_SCHEMA_VERSION,
            "artifact_kind": "firmware_transaction_plan",
            "target_binary": self.target_binary,
            "binary_sha256": self.binary_sha256,
            "protocol": self.protocol,
            "setup_key": self.setup_key,
            "transactions": [item.to_dict() for item in self.transactions],
            "discovery_artifacts": list(self.discovery_artifacts),
            "blockers": list(self.blockers),
            "authority": "safe_route_inputs_not_vulnerability_evidence",
        }
        payload["plan_fingerprint"] = hashlib.sha256(_canonical_json(payload).encode()).hexdigest()
        return payload


@dataclass(frozen=True)
class UbusReadiness:
    status: str
    objects: tuple[str, ...]
    selected_methods: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return self.status == "observed_ready" and not self.blockers

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "objects": list(self.objects),
            "selected_methods": [list(item) for item in self.selected_methods],
            "blockers": list(self.blockers),
            "readiness_gate": "target_objects_published_and_selected_schemas_parseable",
        }


@dataclass(frozen=True)
class FirmwareTransactionCampaignResult:
    status: str
    target: str
    plan: Mapping[str, Any]
    readiness: Mapping[str, Any]
    observations: tuple[Mapping[str, Any], ...]
    idle_hits: tuple[Mapping[str, Any], ...]
    artifacts: tuple[str, ...]
    blocker: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "artifact_kind": "firmware_transaction_exact_route_campaign",
            "status": self.status,
            "target": self.target,
            "plan": dict(self.plan),
            "readiness": dict(self.readiness),
            "observations": [dict(item) for item in self.observations],
            "idle_hits": [dict(item) for item in self.idle_hits],
            "artifacts": list(self.artifacts),
            "blocker": self.blocker,
            "setup_evidence_is_not_proof": True,
            "routing_evidence_only": True,
        }


def parse_ubus_verbose_list(output: str) -> dict[str, dict[str, dict[str, str]]]:
    """Parse ``ubus -v list`` output into object/method/field types.

    OpenWrt versions vary between a line-oriented display and a JSON-shaped
    display.  Both are accepted, but every method schema must be an object of
    string field types.  Malformed or unsupported fields raise ``ValueError``.
    """

    text = str(output or "").strip()
    if not text:
        return {}
    parsed_json = _parse_ubus_json(text)
    if parsed_json is not None:
        return parsed_json
    objects: dict[str, dict[str, dict[str, str]]] = {}
    current_object = ""
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip()
        object_match = _OBJECT_LINE.match(line)
        if object_match and not line.startswith((" ", "\t")):
            current_object = object_match.group("object")
            objects.setdefault(current_object, {})
            continue
        method_match = _METHOD_LINE.match(line)
        if method_match:
            if not current_object:
                raise ValueError(f"ubus method appears before object on line {line_number}")
            schema = _parse_method_schema(method_match.group("schema"), line_number=line_number)
            objects[current_object][method_match.group("method")] = schema
            continue
        if line.strip() in {"", "}", "},"}:
            continue
        raise ValueError(f"unparseable ubus verbose-list line {line_number}: {line.strip()[:120]}")
    return objects


def inert_payload(schema: Mapping[str, str]) -> dict[str, Any]:
    """Generate deterministic non-mutating placeholder values for one schema."""

    result: dict[str, Any] = {}
    for name, raw_type in sorted(schema.items()):
        normalized = str(raw_type or "").strip().lower()
        if normalized not in SUPPORTED_UBUS_TYPES:
            raise ValueError(f"unsupported ubus argument type:{raw_type}")
        if normalized == "string":
            value: Any = ""
        elif normalized in {"integer", "int32", "int64"}:
            value = 0
        elif normalized in {"boolean", "bool"}:
            value = False
        elif normalized == "double":
            value = 0.0
        elif normalized == "array":
            value = []
        else:
            value = {}
        result[str(name)] = value
    return result


def is_safe_ubus_method(method_name: str) -> bool:
    """Admit only explicitly query-shaped methods and deny mutation tokens."""

    lowered = str(method_name or "").strip().lower()
    if not lowered:
        return False
    tokens = {item for item in re.split(r"[^a-z0-9]+", lowered) if item}
    if tokens & UNSAFE_METHOD_TOKENS:
        return False
    if any(lowered == token or lowered.startswith(token + "_") for token in UNSAFE_METHOD_TOKENS):
        return False
    return lowered in SAFE_QUERY_METHODS or lowered.startswith("get")


def build_transaction_plan(
    *,
    target_binary: Path,
    schemas: Mapping[str, Mapping[str, Mapping[str, str]]],
    setup_key: str,
    timeout_seconds: float = 5.0,
    selected_pairs: Iterable[tuple[str, str]] | None = None,
    discovery_artifacts: Sequence[str] = (),
    include_omitted_optional_variant: bool = True,
) -> FirmwareTransactionPlan:
    selected = set(selected_pairs or ())
    transactions: list[FirmwareTransaction] = []
    blockers: list[str] = []
    for object_name in sorted(schemas):
        methods = schemas[object_name]
        for method_name in sorted(methods):
            if selected and (object_name, method_name) not in selected:
                continue
            if not is_safe_ubus_method(method_name):
                blockers.append(f"unsafe_method_suppressed:{object_name}:{method_name}")
                continue
            try:
                arguments = inert_payload(methods[method_name])
            except ValueError as exc:
                blockers.append(f"unsupported_schema:{object_name}:{method_name}:{exc}")
                continue
            variants = [arguments]
            if include_omitted_optional_variant and arguments:
                # ubus method policies describe accepted fields, not required
                # fields.  The empty-object call is therefore a distinct,
                # inert schema-derived variant and is useful for callbacks
                # that take an optional selector.
                variants.insert(0, {})
            for variant in variants:
                transactions.append(
                    FirmwareTransaction.create(
                        object_name=object_name,
                        method_name=method_name,
                        schema=methods[method_name],
                        arguments=variant,
                        timeout_seconds=timeout_seconds,
                        setup_key=setup_key,
                    )
                )
    binary = Path(target_binary).expanduser().resolve()
    binary_hash = _sha256_file(binary) if binary.is_file() else ""
    return FirmwareTransactionPlan(
        target_binary=str(binary),
        binary_sha256=binary_hash,
        protocol="ubus",
        setup_key=str(setup_key),
        transactions=tuple(transactions),
        discovery_artifacts=tuple(str(item) for item in discovery_artifacts),
        blockers=tuple(sorted(blockers)),
    )


def publication_acl(
    *,
    user: str = "replay",
    object_names: Sequence[str] = ("*",),
    method_names: Sequence[str] = (),
) -> dict[str, Any]:
    names = sorted({str(item) for item in object_names if str(item)})
    if not names:
        raise ValueError("publication ACL requires at least one object")
    query_methods = set(SAFE_QUERY_METHODS)
    for method_name in method_names:
        if not is_safe_ubus_method(method_name):
            raise ValueError(f"unsafe discovery method rejected:{method_name}")
        query_methods.add(str(method_name))
    return {
        "user": str(user),
        "publish": names,
        # An access row is also required for ubusd to retain a credentialed
        # ACL file.  Only the query-shaped names needed for discovery are
        # exposed; mutation methods remain unavailable.
        "access": {
            "*": {"methods": sorted(query_methods)},
        },
    }


def selected_call_acl(transactions: Sequence[FirmwareTransaction], *, user: str = "replay") -> dict[str, Any]:
    access: dict[str, dict[str, list[str]]] = {}
    publish: set[str] = set()
    for transaction in transactions:
        if transaction.safety_classification != "query_only_inert_payload" or not is_safe_ubus_method(transaction.method_name):
            raise ValueError(f"unsafe transaction cannot enter ACL:{transaction.object_name}:{transaction.method_name}")
        publish.add(transaction.object_name)
        access.setdefault(transaction.object_name, {"methods": []})["methods"].append(transaction.method_name)
    if not access:
        raise ValueError("selected ACL requires at least one safe transaction")
    return {
        "user": str(user),
        "publish": sorted(publish),
        "access": {
            object_name: {"methods": sorted(set(row["methods"]))}
            for object_name, row in sorted(access.items())
        },
    }


def write_acl(path: Path, acl: Mapping[str, Any]) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(dict(acl), indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(destination)
    destination.chmod(0o600)
    return destination


def validate_targeted_binds(binds: Mapping[str, Path | str] | Sequence[tuple[str, Path | str]]) -> tuple[tuple[str, str], ...]:
    normalized: list[tuple[str, str]] = []
    for target, source in dict(binds).items():
        target_path = str(PurePosixPath(str(target)))
        if not target_path.startswith("/") or target_path in BROAD_BIND_TARGETS:
            raise ValueError(f"broad or relative PRoot bind rejected:{target}")
        source_path = Path(source).expanduser().resolve()
        if not source_path.exists():
            raise ValueError(f"PRoot bind source missing:{source_path}")
        normalized.append((target_path, str(source_path)))
    return tuple(sorted(normalized))


def build_proot_fake_root_command(
    proot_bin: Path | str,
    command: Sequence[str],
    *,
    binds: Mapping[str, Path | str] | Sequence[tuple[str, Path | str]] = (),
) -> list[str]:
    proot = Path(proot_bin).expanduser().resolve()
    if not proot.is_file() or not os.access(proot, os.X_OK):
        raise ValueError(f"PRoot executable unavailable:{proot}")
    if not command:
        raise ValueError("PRoot command is empty")
    argv = [str(proot), "-0"]
    for target, source in validate_targeted_binds(binds):
        argv.extend(["-b", f"{source}:{target}"])
    argv.extend(str(item) for item in command)
    return argv


def assess_ubus_readiness(
    schemas: Mapping[str, Mapping[str, Mapping[str, str]]],
    selected_pairs: Sequence[tuple[str, str]],
    *,
    required_object_prefixes: Sequence[str] = (),
) -> UbusReadiness:
    blockers: list[str] = []
    objects = tuple(sorted(str(item) for item in schemas))
    if not objects:
        blockers.append("no_target_objects_published")
    if not selected_pairs:
        blockers.append("no_selected_transactions")
    for prefix in required_object_prefixes:
        if not any(name == prefix or name.startswith(prefix + ".") for name in objects):
            blockers.append(f"required_object_not_published:{prefix}")
    for object_name, method_name in selected_pairs:
        method_schema = schemas.get(object_name, {}).get(method_name)
        if method_schema is None:
            blockers.append(f"selected_schema_missing:{object_name}:{method_name}")
            continue
        if not is_safe_ubus_method(method_name):
            blockers.append(f"selected_method_unsafe:{object_name}:{method_name}")
            continue
        try:
            inert_payload(method_schema)
        except ValueError as exc:
            blockers.append(f"selected_schema_unsupported:{object_name}:{method_name}:{exc}")
    return UbusReadiness(
        status="observed_ready" if objects and selected_pairs and not blockers else "unsupported",
        objects=objects,
        selected_methods=tuple(sorted((str(left), str(right)) for left, right in selected_pairs)),
        blockers=tuple(blockers),
    )


class TransactionTraceAttributor:
    """Bracket calls by raw trace byte offsets and normalize exact hits."""

    def __init__(
        self,
        trace_path: Path,
        bracket_path: Path,
        *,
        require_initialization_baseline: bool = False,
    ) -> None:
        self.trace_path = Path(trace_path)
        self.bracket_path = Path(bracket_path)
        self.trace_path.parent.mkdir(parents=True, exist_ok=True)
        self.bracket_path.parent.mkdir(parents=True, exist_ok=True)
        self.trace_path.touch(exist_ok=True)
        self.bracket_path.touch(exist_ok=True)
        self.require_initialization_baseline = bool(require_initialization_baseline)

    def mark_initialization_baseline(
        self,
        transaction: FirmwareTransaction,
        *,
        quiet_seconds: float,
    ) -> dict[str, Any]:
        marker = {
            "schema_version": TRACE_SCHEMA_VERSION,
            "event": "initialization_baseline",
            "variant_id": transaction.variant_id,
            "transaction_fingerprint": transaction.fingerprint,
            "monotonic_ns": time.monotonic_ns(),
            "trace_offset": self.trace_path.stat().st_size,
            "quiet_seconds": max(0.0, float(quiet_seconds)),
            "setup_evidence_only": True,
            "routing_evidence": False,
        }
        self._append_bracket(marker)
        return marker

    def begin_readiness_attempt(self, transaction: FirmwareTransaction) -> dict[str, Any]:
        marker = {
            "schema_version": TRACE_SCHEMA_VERSION,
            "event": "readiness_attempt_start",
            "variant_id": transaction.variant_id,
            "transaction_fingerprint": transaction.fingerprint,
            "monotonic_ns": time.monotonic_ns(),
            "trace_offset": self.trace_path.stat().st_size,
            "setup_evidence_only": True,
            "routing_evidence": False,
        }
        self._append_bracket(marker)
        return marker

    def end_readiness_attempt(
        self,
        transaction: FirmwareTransaction,
        start: Mapping[str, Any],
        *,
        returncode: int,
    ) -> dict[str, Any]:
        marker = {
            "schema_version": TRACE_SCHEMA_VERSION,
            "event": "readiness_attempt_end",
            "variant_id": transaction.variant_id,
            "transaction_fingerprint": transaction.fingerprint,
            "monotonic_ns": time.monotonic_ns(),
            "trace_offset": self.trace_path.stat().st_size,
            "start_trace_offset": int(start.get("trace_offset") or 0),
            "returncode": int(returncode),
            "setup_evidence_only": True,
            "routing_evidence": False,
        }
        self._append_bracket(marker)
        return marker

    def begin(self, transaction: FirmwareTransaction) -> dict[str, Any]:
        if self.require_initialization_baseline and _load_initialization_baseline(
            self.bracket_path
        ) is None:
            raise ValueError("transaction measurement requires initialization baseline")
        marker = {
            "schema_version": TRACE_SCHEMA_VERSION,
            "event": "transaction_start",
            "variant_id": transaction.variant_id,
            "transaction_fingerprint": transaction.fingerprint,
            "monotonic_ns": time.monotonic_ns(),
            "trace_offset": self.trace_path.stat().st_size,
        }
        self._append_bracket(marker)
        return marker

    def end(self, transaction: FirmwareTransaction, start: Mapping[str, Any], *, returncode: int) -> dict[str, Any]:
        marker = {
            "schema_version": TRACE_SCHEMA_VERSION,
            "event": "transaction_end",
            "variant_id": transaction.variant_id,
            "transaction_fingerprint": transaction.fingerprint,
            "monotonic_ns": time.monotonic_ns(),
            "trace_offset": self.trace_path.stat().st_size,
            "returncode": int(returncode),
            "start_trace_offset": int(start.get("trace_offset") or 0),
        }
        self._append_bracket(marker)
        return marker

    def run(
        self,
        transaction: FirmwareTransaction,
        call: Callable[[], subprocess.CompletedProcess[Any]],
    ) -> subprocess.CompletedProcess[Any]:
        start = self.begin(transaction)
        try:
            completed = call()
        except Exception:
            self.end(transaction, start, returncode=125)
            raise
        self.end(transaction, start, returncode=int(completed.returncode))
        return completed

    def normalize(self, operation_addresses: Sequence[str | int], *, backend: str = "qemu_plugin") -> list[dict[str, Any]]:
        addresses = tuple(_numeric_address(item) for item in operation_addresses)
        spans = _load_transaction_spans(self.bracket_path)
        hits = _load_trace_hits(self.trace_path)
        baseline = _load_initialization_baseline(self.bracket_path)
        rows: list[dict[str, Any]] = []
        for span in spans:
            for address in addresses:
                matching = [
                    hit for hit in hits
                    if int(hit["offset"]) >= int(span["start_offset"])
                    and int(hit["offset"]) < int(span["end_offset"])
                    and int(hit["address_int"]) == address
                ]
                rows.append(
                    {
                        "schema_version": TRACE_SCHEMA_VERSION,
                        "artifact_kind": "transaction_exact_operation_reach",
                        "status": "observed" if matching else "not_observed",
                        "operation_address": hex(address),
                        "variant_id": span["variant_id"],
                        "transaction_fingerprint": span["transaction_fingerprint"],
                        "hit_count": len(matching),
                        "backend": backend,
                        "artifact_refs": [str(self.trace_path), str(self.bracket_path)],
                        "initialization_baseline_offset": (
                            int(baseline["trace_offset"]) if baseline is not None else None
                        ),
                        "routing_evidence_only": True,
                        "vulnerability_effect_claimed": False,
                    }
                )
        return rows

    def idle_hits(self) -> list[dict[str, Any]]:
        spans = _load_transaction_spans(self.bracket_path)
        readiness_spans = _load_readiness_spans(self.bracket_path)
        hits = _load_trace_hits(self.trace_path)
        baseline = _load_initialization_baseline(self.bracket_path)
        baseline_offset = int(baseline["trace_offset"]) if baseline is not None else None
        rows: list[dict[str, Any]] = []
        for hit in hits:
            if any(span["start_offset"] <= hit["offset"] < span["end_offset"] for span in spans):
                continue
            if any(
                span["start_offset"] <= hit["offset"] < span["end_offset"]
                for span in readiness_spans
            ):
                phase = "readiness_transaction_setup"
            elif baseline_offset is None or int(hit["offset"]) < baseline_offset:
                phase = "startup_or_setup"
            else:
                phase = "idle_after_initialization"
            rows.append(
                {
                    **hit,
                    "phase": phase,
                    "setup_evidence_only": True,
                    "routing_evidence": False,
                }
            )
        return rows

    def _append_bracket(self, payload: Mapping[str, Any]) -> None:
        with self.bracket_path.open("a", encoding="utf-8") as handle:
            handle.write(_canonical_json(payload) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


class FirmwareTransactionSession:
    """Own reusable broker/target/tracer processes and always clean them up."""

    def __init__(self, candidate_dir: Path, attributor: TransactionTraceAttributor) -> None:
        self.candidate_dir = Path(candidate_dir)
        self.attributor = attributor
        self._processes: list[subprocess.Popen[Any]] = []
        self._cleanup_paths: list[Path] = []
        self._closed = False

    def own_process(self, process: subprocess.Popen[Any]) -> None:
        self._processes.append(process)

    def own_path(self, path: Path) -> None:
        self._cleanup_paths.append(Path(path))

    def execute(
        self,
        transaction: FirmwareTransaction,
        ubus_client: Sequence[str],
        *,
        socket_path: Path,
    ) -> subprocess.CompletedProcess[str]:
        return self.attributor.run(
            transaction,
            lambda: self.execute_unmeasured(
                transaction,
                ubus_client,
                socket_path=socket_path,
            ),
        )

    def execute_unmeasured(
        self,
        transaction: FirmwareTransaction,
        ubus_client: Sequence[str],
        *,
        socket_path: Path,
    ) -> subprocess.CompletedProcess[str]:
        """Execute one admitted setup/readiness call outside proof brackets."""

        if not is_safe_ubus_method(transaction.method_name):
            raise ValueError("unsafe ubus method execution refused")
        payload = json.dumps(
            {key: _thaw_json_value(value) for key, value in transaction.arguments},
            separators=(",", ":"),
            sort_keys=True,
        )
        argv = [
            *[str(item) for item in ubus_client],
            "-s",
            str(socket_path),
            "call",
            transaction.object_name,
            transaction.method_name,
            payload,
        ]
        return subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=transaction.timeout_seconds,
            check=False,
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for process in reversed(self._processes):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (OSError, ProcessLookupError):
                    try:
                        process.terminate()
                    except (OSError, ProcessLookupError):
                        pass
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        try:
                            process.kill()
                        except (OSError, ProcessLookupError):
                            pass
                    try:
                        process.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        pass
        for path in reversed(self._cleanup_paths):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink(missing_ok=True)

    def __enter__(self) -> "FirmwareTransactionSession":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def establish_transaction_readiness(
    transactions: Sequence[FirmwareTransaction],
    execute: Callable[[FirmwareTransaction], subprocess.CompletedProcess[str]],
    attributor: TransactionTraceAttributor,
    *,
    processes: Sequence[subprocess.Popen[Any]] = (),
    timeout_seconds: float = 5.0,
    quiet_seconds: float = 0.15,
    poll_seconds: float = 0.02,
    artifact_path: Path | None = None,
) -> dict[str, Any]:
    """Prove dispatch-loop readiness before opening measured trace brackets.

    Publication can precede target initialization.  This barrier therefore
    executes admitted query variants without attribution until one completes,
    then requires an unchanged exact-trace size for a quiet interval.  Every
    barrier call and hit remains setup evidence and cannot establish routing.
    """

    deadline = time.monotonic() + max(0.2, float(timeout_seconds))
    attempts: list[dict[str, Any]] = []

    def record(payload: Mapping[str, Any]) -> None:
        if artifact_path is not None:
            _write_json(artifact_path, payload)

    for transaction in transactions:
        if time.monotonic() >= deadline:
            break
        if not is_safe_ubus_method(transaction.method_name):
            raise ValueError(f"unsafe readiness transaction refused:{transaction.variant_id}")
        if any(process.poll() is not None for process in processes):
            raise ValueError("target exited before execution readiness")
        readiness_start = attributor.begin_readiness_attempt(transaction)
        try:
            completed = execute(transaction)
        except Exception:
            attributor.end_readiness_attempt(
                transaction,
                readiness_start,
                returncode=125,
            )
            raise
        readiness_end = attributor.end_readiness_attempt(
            transaction,
            readiness_start,
            returncode=int(completed.returncode),
        )
        attempt = {
            "variant_id": transaction.variant_id,
            "transaction_fingerprint": transaction.fingerprint,
            "object": transaction.object_name,
            "method": transaction.method_name,
            "returncode": int(completed.returncode),
            "stdout": str(completed.stdout or "")[-4000:],
            "stderr": str(completed.stderr or "")[-4000:],
            "setup_evidence_only": True,
            "start_trace_offset": int(readiness_start["trace_offset"]),
            "end_trace_offset": int(readiness_end["trace_offset"]),
        }
        attempts.append(attempt)
        denied = any(
            token in attempt["stderr"].lower()
            for token in ("permission denied", "access denied")
        )
        if denied:
            payload = {
                "schema_version": 1,
                "status": "unsupported",
                "blocker": "readiness_acl_denied",
                "attempts": attempts,
                "setup_evidence_only": True,
            }
            record(payload)
            raise ValueError("readiness ACL denied")
        if completed.returncode != 0:
            continue
        remaining = max(0.0, deadline - time.monotonic())
        if not _wait_for_trace_quiescence(
            attributor.trace_path,
            processes=processes,
            timeout_seconds=remaining,
            quiet_seconds=quiet_seconds,
            poll_seconds=poll_seconds,
        ):
            payload = {
                "schema_version": 1,
                "status": "unsupported",
                "blocker": "exact_trace_did_not_quiesce",
                "attempts": attempts,
                "setup_evidence_only": True,
            }
            record(payload)
            raise ValueError("exact trace did not quiesce after readiness call")
        baseline = attributor.mark_initialization_baseline(
            transaction,
            quiet_seconds=quiet_seconds,
        )
        payload = {
            "schema_version": 1,
            "artifact_kind": "firmware_transaction_execution_readiness",
            "status": "observed_ready",
            "readiness_variant_id": transaction.variant_id,
            "attempts": attempts,
            "baseline": baseline,
            "readiness_gate": "successful_safe_dispatch_then_exact_trace_quiescence",
            "setup_evidence_only": True,
            "routing_evidence": False,
        }
        record(payload)
        return payload
    payload = {
        "schema_version": 1,
        "status": "unsupported",
        "blocker": "no_safe_transaction_completed",
        "attempts": attempts,
        "setup_evidence_only": True,
    }
    record(payload)
    raise ValueError("no safe transaction completed before readiness deadline")


def _wait_for_trace_quiescence(
    trace_path: Path,
    *,
    processes: Sequence[subprocess.Popen[Any]],
    timeout_seconds: float,
    quiet_seconds: float,
    poll_seconds: float,
) -> bool:
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    stable_since = time.monotonic()
    previous_size = Path(trace_path).stat().st_size
    while time.monotonic() <= deadline:
        if any(process.poll() is not None for process in processes):
            return False
        current_size = Path(trace_path).stat().st_size
        now = time.monotonic()
        if current_size != previous_size:
            previous_size = current_size
            stable_since = now
        elif now - stable_since >= max(0.0, float(quiet_seconds)):
            return True
        time.sleep(max(0.001, min(float(poll_seconds), max(0.001, deadline - now))))
    return False


def transaction_variant_score(
    *,
    callback_distance: int | None,
    schema_field_count: int,
    setup_reused: bool,
    estimated_marginal_seconds: float,
    prior_observed_reaches: int,
) -> float:
    """Label-blind adaptive utility for one transaction variant."""

    proximity = 0.0 if callback_distance is None or callback_distance < 0 else 4.0 / (1.0 + callback_distance)
    complexity = 2.0 / (1.0 + max(0, int(schema_field_count)))
    reuse = 2.0 if setup_reused else 0.0
    feedback = min(4.0, max(0, int(prior_observed_reaches)) * 1.5)
    cost = max(0.05, float(estimated_marginal_seconds))
    return (proximity + complexity + reuse + feedback) / cost


def recover_ubus_method_callbacks(
    binary_path: Path,
    method_names: Sequence[str],
    *,
    image_base: int,
) -> dict[str, tuple[str, ...]]:
    """Recover exact callback entries from static ``ubus_method`` records.

    The OpenWrt x86-64 method record begins with a method-name pointer and a
    callback pointer.  This parser accepts only pointers backed by an
    executable ELF load segment, so arbitrary string adjacency cannot become
    an entry surface.
    """

    binary = Path(binary_path).expanduser().resolve()
    data = binary.read_bytes()
    segments, pie = _elf_load_segments(binary)

    def file_offset_to_vaddr(offset: int) -> int | None:
        for file_offset, virtual_address, file_size, _executable in segments:
            if file_offset <= offset < file_offset + file_size:
                return virtual_address + offset - file_offset
        return None

    def executable(value: int) -> bool:
        return any(
            is_executable and virtual_address <= value < virtual_address + file_size
            for _file_offset, virtual_address, file_size, is_executable in segments
        )

    recovered: dict[str, tuple[str, ...]] = {}
    for method_name in sorted({str(item) for item in method_names if str(item)}):
        handlers: set[str] = set()
        start = 0
        literal = method_name.encode("utf-8") + b"\0"
        while True:
            string_offset = data.find(literal, start)
            if string_offset < 0:
                break
            start = string_offset + 1
            string_vaddr = file_offset_to_vaddr(string_offset)
            if string_vaddr is None:
                continue
            pointer = struct.pack("<Q", string_vaddr)
            reference_start = 0
            while True:
                reference = data.find(pointer, reference_start)
                if reference < 0:
                    break
                reference_start = reference + 1
                if reference + 16 > len(data):
                    continue
                handler_vaddr = struct.unpack_from("<Q", data, reference + 8)[0]
                if not executable(handler_vaddr):
                    continue
                static_address = handler_vaddr + int(image_base) if pie else handler_vaddr
                handlers.add(f"0x{static_address:X}")
        recovered[method_name] = tuple(sorted(handlers, key=lambda item: int(item, 16)))
    return recovered


def compile_qemu_instruction_tracer(
    output_dir: Path,
    operation_addresses: Sequence[str | int],
    *,
    qemu_user_bin: Path | str,
    image_base: int,
    binary_name: str = "",
) -> dict[str, Any]:
    """Build the multi-address append-only instruction tracer."""

    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    normalized = [
        f"0x{value:X}"
        for value in dict.fromkeys(_numeric_address(item) for item in operation_addresses)
    ]
    if not normalized:
        return {"status": "unsupported", "blocker": "no_exact_numeric_operations"}
    if len(normalized) > 256:
        return {"status": "unsupported", "blocker": "qemu_instruction_target_limit_exceeded"}
    compiler = shutil.which(os.getenv("CC", "")) if os.getenv("CC") else None
    compiler = compiler or shutil.which("gcc") or shutil.which("cc")
    qemu = Path(qemu_user_bin).expanduser().resolve()
    include_candidates = (
        qemu.parents[1] / "include",
        Path("/usr/include"),
        Path("/usr/local/include"),
        Path("/home/linuxbrew/.linuxbrew/include"),
    )
    include = next((item for item in include_candidates if (item / "qemu-plugin.h").is_file()), None)
    pkg_config = shutil.which("pkg-config")
    if not compiler or not include or not pkg_config:
        return {"status": "unsupported", "blocker": "qemu_plugin_toolchain_missing"}
    flags = subprocess.run(
        [pkg_config, "--cflags", "--libs", "glib-2.0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5.0,
        check=False,
    )
    if flags.returncode != 0:
        return {"status": "unsupported", "blocker": "glib_pkg_config_unavailable"}
    source = output / "qemu_exact_instruction_plugin.c"
    shared = output / "qemu_exact_instruction_plugin.so"
    build = output / "qemu_exact_instruction_plugin_build.json"
    trace = output / "qemu_exact_instruction_hits.jsonl"
    source.write_text(_QEMU_EXACT_INSTRUCTION_PLUGIN_SOURCE)
    command = [
        compiler,
        "-fPIC",
        "-shared",
        "-O2",
        "-Wall",
        "-I",
        str(include),
        "-o",
        str(shared),
        str(source),
        *shlex.split(flags.stdout),
    ]
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15.0,
        check=False,
    )
    _write_json(
        build,
        {
            "argv": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
            "operation_addresses": normalized,
            "image_base": f"0x{int(image_base):X}",
        },
    )
    if completed.returncode != 0 or not shared.is_file():
        return {
            "status": "unsupported",
            "blocker": "qemu_instruction_plugin_compilation_failed",
            "artifacts": [str(source), str(build)],
        }
    options = ",".join(
        (
            f"file={shared}",
            f"targets={';'.join(normalized)}",
            f"image_base=0x{int(image_base):X}",
            f"binary_name={str(binary_name)}",
            f"out={trace}",
        )
    )
    return {
        "status": "configured",
        "plugin_args": ["-plugin", options],
        "trace_path": str(trace),
        "artifacts": [str(source), str(shared), str(build), str(trace)],
    }


def run_openwrt_ubus_transactions(
    rootfs_path: Path,
    target_binary: Path,
    output_dir: Path,
    *,
    operation_addresses: Sequence[str | int],
    image_base: int,
    selected_pairs: Sequence[tuple[str, str]] = (),
    qemu_user_bin: Path | str = "qemu-x86_64",
    proot_bin: Path | str = "tools/proot",
    timeout_seconds: float = 5.0,
) -> FirmwareTransactionCampaignResult:
    """Discover, authorize, and execute one reusable safe ubus session.

    The first broker permits publication plus query-shaped schema discovery.
    The second broker contains only selected object/method pairs.  Both broker
    and target run through PRoot fake-root mode, and all runtime state is
    deleted after evidence has been copied to ``output_dir``.
    """

    source_rootfs = Path(rootfs_path).expanduser().resolve()
    binary_source = Path(target_binary).expanduser().resolve()
    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    qemu = Path(shutil.which(str(qemu_user_bin)) or str(qemu_user_bin)).expanduser().resolve()
    proot = Path(proot_bin).expanduser().resolve()
    target_name = binary_source.name
    artifacts: list[str] = []
    empty_result = FirmwareTransactionCampaignResult(
        status="unsupported",
        target=target_name,
        plan={},
        readiness={},
        observations=(),
        idle_hits=(),
        artifacts=(),
        blocker="",
    )
    if target_name not in {"netifd", "rpcd"}:
        return dataclass_replace(empty_result, blocker="unsupported_firmware_transaction_target")
    if not source_rootfs.is_dir() or not binary_source.is_file() or not qemu.is_file() or not proot.is_file():
        return dataclass_replace(empty_result, blocker="firmware_transaction_prerequisite_missing")
    tracer = compile_qemu_instruction_tracer(
        output / "tracer",
        operation_addresses,
        qemu_user_bin=qemu,
        image_base=image_base,
        binary_name=target_name,
    )
    artifacts.extend(str(item) for item in tracer.get("artifacts", []) or [])
    if tracer.get("status") != "configured":
        return dataclass_replace(
            empty_result,
            artifacts=tuple(artifacts),
            blocker=str(tracer.get("blocker") or "qemu_instruction_tracer_unsupported"),
        )

    with tempfile.TemporaryDirectory(prefix=f"binary-agent-{target_name}-", dir="/tmp") as temporary:
        runtime = Path(temporary)
        copied_rootfs = runtime / "rootfs"
        shutil.copytree(source_rootfs, copied_rootfs, symlinks=True)
        _ensure_runtime_principal(copied_rootfs)
        socket_path = runtime / "ubus.sock"
        publication_dir = runtime / "publication-acl"
        publication_dir.mkdir()
        principal = pwd.getpwuid(os.getuid()).pw_name
        publication = write_acl(
            publication_dir / "replay.json",
            publication_acl(
                user=principal,
                method_names=tuple(method for _object, method in selected_pairs),
            ),
        )
        publication_artifact = output / "publication_acl.json"
        shutil.copy2(publication, publication_artifact)
        artifacts.append(str(publication_artifact))
        first_processes: list[subprocess.Popen[Any]] = []
        try:
            first_processes, discovery = _start_transaction_stage(
                copied_rootfs,
                binary_source,
                target_name=target_name,
                qemu=qemu,
                proot=proot,
                acl_dir=publication_dir,
                socket_path=socket_path,
                runtime=runtime,
                output=output / "discovery-stage",
                timeout_seconds=timeout_seconds,
                plugin_args=(),
            )
            schemas = parse_ubus_verbose_list(str(discovery.get("stdout") or ""))
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            return dataclass_replace(
                empty_result,
                artifacts=tuple(artifacts),
                blocker=f"ubus_schema_discovery_failed:{type(exc).__name__}",
            )
        finally:
            _stop_processes(first_processes)
            socket_path.unlink(missing_ok=True)
        artifacts.extend(_stage_artifacts(output / "discovery-stage"))
        discovery_path = output / "ubus_verbose_list.txt"
        discovery_path.write_text(str(discovery.get("stdout") or ""))
        artifacts.append(str(discovery_path))
        available_safe = tuple(
            (object_name, method_name)
            for object_name in sorted(schemas)
            for method_name in sorted(schemas[object_name])
            if is_safe_ubus_method(method_name)
        )
        chosen = tuple(selected_pairs) if selected_pairs else available_safe
        readiness = assess_ubus_readiness(
            schemas,
            chosen,
            required_object_prefixes=("network",) if target_name == "netifd" else (),
        )
        if not readiness.ready:
            return dataclass_replace(
                empty_result,
                readiness=readiness.to_dict(),
                artifacts=tuple(artifacts),
                blocker="ubus_target_readiness_failed",
            )
        setup_key = hashlib.sha256(
            f"{_sha256_file(binary_source)}:{target_name}:{principal}".encode()
        ).hexdigest()[:20]
        plan = build_transaction_plan(
            target_binary=binary_source,
            schemas=schemas,
            setup_key=setup_key,
            timeout_seconds=timeout_seconds,
            selected_pairs=chosen,
            discovery_artifacts=(str(discovery_path),),
        )
        if not plan.transactions:
            return dataclass_replace(
                empty_result,
                plan=plan.to_dict(),
                readiness=readiness.to_dict(),
                artifacts=tuple(artifacts),
                blocker="no_safe_ubus_transactions",
            )
        plan_path = output / "transaction_plan.json"
        _write_json(plan_path, plan.to_dict())
        artifacts.append(str(plan_path))
        selected_dir = runtime / "selected-acl"
        selected_dir.mkdir()
        selected = write_acl(
            selected_dir / "replay.json",
            selected_call_acl(plan.transactions, user=principal),
        )
        selected_artifact = output / "selected_call_acl.json"
        shutil.copy2(selected, selected_artifact)
        artifacts.append(str(selected_artifact))
        trace_path = Path(str(tracer["trace_path"]))
        bracket_path = output / "transaction_brackets.jsonl"
        attributor = TransactionTraceAttributor(
            trace_path,
            bracket_path,
            require_initialization_baseline=True,
        )
        stage_processes: list[subprocess.Popen[Any]] = []
        call_rows: list[dict[str, Any]] = []
        campaign_readiness = readiness.to_dict()
        barrier_path = output / "execution_readiness_barrier.json"
        try:
            stage_processes, second_discovery = _start_transaction_stage(
                copied_rootfs,
                binary_source,
                target_name=target_name,
                qemu=qemu,
                proot=proot,
                acl_dir=selected_dir,
                socket_path=socket_path,
                runtime=runtime,
                output=output / "execution-stage",
                timeout_seconds=timeout_seconds,
                plugin_args=tuple(str(item) for item in tracer["plugin_args"]),
            )
            second_schemas = parse_ubus_verbose_list(str(second_discovery.get("stdout") or ""))
            second_readiness = assess_ubus_readiness(second_schemas, chosen)
            if not second_readiness.ready:
                raise ValueError("selected ACL readiness failed")
            client = [str(qemu), "-L", str(copied_rootfs), str(copied_rootfs / "bin" / "ubus")]
            session = FirmwareTransactionSession(output, attributor)
            execution_barrier = establish_transaction_readiness(
                plan.transactions,
                lambda transaction: session.execute_unmeasured(
                    transaction,
                    client,
                    socket_path=socket_path,
                ),
                attributor,
                processes=stage_processes,
                timeout_seconds=max(timeout_seconds, timeout_seconds * len(plan.transactions)),
                artifact_path=barrier_path,
            )
            campaign_readiness = {
                **campaign_readiness,
                "execution_barrier": execution_barrier,
            }
            for transaction in plan.transactions:
                completed = session.execute(
                    transaction,
                    client,
                    socket_path=socket_path,
                )
                call_rows.append(
                    {
                        "variant_id": transaction.variant_id,
                        "transaction_fingerprint": transaction.fingerprint,
                        "returncode": completed.returncode,
                        "stdout": completed.stdout[-4000:],
                        "stderr": completed.stderr[-4000:],
                    }
                )
                denied = "permission denied" in completed.stderr.lower() or "access denied" in completed.stderr.lower()
                if denied:
                    raise ValueError(f"ubus_acl_denied:{transaction.variant_id}")
            time.sleep(0.05)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            blocker = f"firmware_transaction_execution_failed:{exc}"
        else:
            blocker = ""
        finally:
            _stop_processes(stage_processes)
            socket_path.unlink(missing_ok=True)
        artifacts.extend(_stage_artifacts(output / "execution-stage"))
        if barrier_path.is_file():
            artifacts.append(str(barrier_path))
        observations = attributor.normalize(operation_addresses, backend="qemu_plugin_multi_instruction_v1")
        if blocker:
            existing = {
                (str(item.get("variant_id") or ""), str(item.get("operation_address") or "").lower()): item
                for item in observations
            }
            observations = []
            for transaction in plan.transactions:
                for raw_address in operation_addresses:
                    address = hex(_numeric_address(raw_address))
                    prior = existing.get((transaction.variant_id, address.lower()), {})
                    observations.append(
                        {
                            "schema_version": TRACE_SCHEMA_VERSION,
                            "artifact_kind": "transaction_exact_operation_reach",
                            "operation_address": address,
                            "variant_id": transaction.variant_id,
                            "transaction_fingerprint": transaction.fingerprint,
                            "hit_count": int(prior.get("hit_count") or 0),
                            "backend": "qemu_plugin_multi_instruction_v1",
                            "artifact_refs": [str(trace_path), str(bracket_path)],
                            "routing_evidence_only": True,
                            "vulnerability_effect_claimed": False,
                            "status": "unsupported",
                            "blocker": blocker,
                        }
                    )
        idle_hits = attributor.idle_hits()
        calls_path = output / "transactions.json"
        observations_path = output / "transaction_observations.json"
        idle_path = output / "idle_startup_hits.json"
        _write_json(calls_path, {"schema_version": 1, "calls": call_rows})
        _write_json(observations_path, {"schema_version": 1, "observations": observations})
        _write_json(idle_path, {"schema_version": 1, "hits": idle_hits})
        artifacts.extend((str(bracket_path), str(calls_path), str(observations_path), str(idle_path)))
        result = FirmwareTransactionCampaignResult(
            status="observed" if not blocker else "unsupported",
            target=target_name,
            plan=plan.to_dict(),
            readiness=campaign_readiness,
            observations=tuple(observations),
            idle_hits=tuple(idle_hits),
            artifacts=tuple(dict.fromkeys(artifacts)),
            blocker=blocker,
        )
        _write_json(output / "result.json", result.to_dict())
        return result


def dataclass_replace(
    value: FirmwareTransactionCampaignResult,
    **updates: Any,
) -> FirmwareTransactionCampaignResult:
    payload = {
        "status": value.status,
        "target": value.target,
        "plan": value.plan,
        "readiness": value.readiness,
        "observations": value.observations,
        "idle_hits": value.idle_hits,
        "artifacts": value.artifacts,
        "blocker": value.blocker,
        **updates,
    }
    return FirmwareTransactionCampaignResult(**payload)


def _start_transaction_stage(
    copied_rootfs: Path,
    _binary_source: Path,
    *,
    target_name: str,
    qemu: Path,
    proot: Path,
    acl_dir: Path,
    socket_path: Path,
    runtime: Path,
    output: Path,
    timeout_seconds: float,
    plugin_args: Sequence[str],
) -> tuple[list[subprocess.Popen[Any]], dict[str, Any]]:
    output.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    processes: list[subprocess.Popen[Any]] = []
    broker_command = build_proot_fake_root_command(
        proot,
        [
            str(qemu),
            "-L",
            str(copied_rootfs),
            str(copied_rootfs / "sbin" / "ubusd"),
            "-A",
            str(acl_dir),
            "-s",
            str(socket_path),
        ],
    )
    try:
        broker = _spawn_logged(broker_command, output / "ubusd")
        processes.append(broker)
        _wait_for_socket(socket_path, broker, timeout_seconds)
        binds = _target_binds(copied_rootfs, target_name)
        target_command = build_proot_fake_root_command(
            proot,
            _target_command(
                copied_rootfs,
                target_name,
                qemu,
                socket_path,
                runtime,
                plugin_args,
            ),
            binds=binds,
        )
        target = _spawn_logged(target_command, output / target_name)
        processes.append(target)
        client = [
            str(qemu),
            "-L",
            str(copied_rootfs),
            str(copied_rootfs / "bin" / "ubus"),
            "-s",
            str(socket_path),
            "-v",
            "list",
        ]
        deadline = time.monotonic() + max(0.2, float(timeout_seconds))
        last = subprocess.CompletedProcess(client, 255, "", "target objects not ready")
        while time.monotonic() < deadline:
            if broker.poll() is not None or target.poll() is not None:
                break
            last = subprocess.run(
                client,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=max(0.2, float(timeout_seconds)),
                check=False,
            )
            if last.returncode == 0 and last.stdout.strip():
                break
            time.sleep(0.03)
        discovery = {
            "argv": client,
            "returncode": last.returncode,
            "stdout": last.stdout,
            "stderr": last.stderr,
        }
        _write_json(output / "readiness_probe.json", discovery)
        if last.returncode != 0 or not last.stdout.strip():
            raise ValueError("target did not publish parseable ubus objects")
        return processes, discovery
    except Exception:
        _stop_processes(processes)
        raise


def _stage_artifacts(stage_dir: Path) -> list[str]:
    return [
        str(path)
        for path in sorted(Path(stage_dir).glob("*"))
        if path.is_file()
    ]


def _target_binds(rootfs: Path, target_name: str) -> dict[str, Path]:
    if target_name == "netifd":
        requested = {
            "/lib/netifd": rootfs / "lib" / "netifd",
            "/lib/functions.sh": rootfs / "lib" / "functions.sh",
            "/lib/functions": rootfs / "lib" / "functions",
            "/usr/share/libubox": rootfs / "usr" / "share" / "libubox",
        }
    else:
        requested = {
            "/usr/lib/rpcd": rootfs / "usr" / "lib" / "rpcd",
            "/usr/share/rpcd": rootfs / "usr" / "share" / "rpcd",
            "/etc/config": rootfs / "etc" / "config",
        }
    return {target: source for target, source in requested.items() if source.exists()}


def _target_command(
    rootfs: Path,
    target_name: str,
    qemu: Path,
    socket_path: Path,
    runtime: Path,
    plugin_args: Sequence[str],
) -> list[str]:
    prefix = [str(qemu), *plugin_args, "-L", str(rootfs), str(rootfs / "sbin" / target_name)]
    if target_name == "rpcd":
        return [*prefix, "-s", str(socket_path), "-t", "5"]
    network = runtime / "network.conf"
    resolver = runtime / "resolv.conf"
    network.touch(exist_ok=True)
    resolver.touch(exist_ok=True)
    return [
        *prefix,
        "-s",
        str(socket_path),
        "-p",
        "/lib/netifd",
        "-c",
        str(network),
        "-h",
        str(runtime / "disabled-hotplug"),
        "-r",
        str(resolver),
        "-S",
    ]


def _spawn_logged(command: Sequence[str], prefix: Path) -> subprocess.Popen[Any]:
    stdout = prefix.with_suffix(".stdout.log").open("w")
    stderr = prefix.with_suffix(".stderr.log").open("w")
    process = subprocess.Popen(
        [str(item) for item in command],
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
        text=True,
    )
    stdout.close()
    stderr.close()
    return process


def _wait_for_socket(path: Path, process: subprocess.Popen[Any], timeout: float) -> None:
    deadline = time.monotonic() + max(0.2, float(timeout))
    while time.monotonic() < deadline:
        if path.is_socket():
            return
        if process.poll() is not None:
            break
        time.sleep(0.02)
    raise ValueError("ubusd socket did not become ready")


def _stop_processes(processes: Sequence[subprocess.Popen[Any]]) -> None:
    for process in reversed(processes):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
    deadline = time.monotonic() + 1.0
    for process in reversed(processes):
        if process.poll() is not None:
            continue
        try:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass


def _ensure_runtime_principal(rootfs: Path) -> None:
    user = pwd.getpwuid(os.getuid()).pw_name
    passwd_path = rootfs / "etc" / "passwd"
    group_path = rootfs / "etc" / "group"
    passwd_text = passwd_path.read_text(errors="replace")
    group_text = group_path.read_text(errors="replace")
    if not any(
        len(parts) > 2 and parts[2].isdigit() and int(parts[2]) == os.getuid()
        for line in passwd_text.splitlines()
        if (parts := line.split(":"))
    ):
        passwd_path.write_text(
            passwd_text.rstrip("\n")
            + f"\n{user}:x:{os.getuid()}:{os.getgid()}:replay:/tmp:/bin/false\n"
        )
    if not any(
        len(parts) > 2 and parts[2].isdigit() and int(parts[2]) == os.getgid()
        for line in group_text.splitlines()
        if (parts := line.split(":"))
    ):
        group_path.write_text(group_text.rstrip("\n") + f"\n{user}:x:{os.getgid()}:\n")


def _elf_load_segments(binary: Path) -> tuple[list[tuple[int, int, int, bool]], bool]:
    headers = subprocess.run(
        ["readelf", "-h", "-lW", str(binary)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5.0,
        check=False,
    )
    if headers.returncode != 0:
        raise ValueError("ELF headers unavailable for ubus callback recovery")
    pie = bool(re.search(r"Type:\s+DYN", headers.stdout))
    segments: list[tuple[int, int, int, bool]] = []
    for line in headers.stdout.splitlines():
        fields = line.split()
        if not fields or fields[0] != "LOAD" or len(fields) < 8:
            continue
        segments.append(
            (
                int(fields[1], 16),
                int(fields[2], 16),
                int(fields[4], 16),
                "E" in fields[6:-1],
            )
        )
    if not segments:
        raise ValueError("ELF has no load segments")
    return segments, pie


def _parse_ubus_json(text: str) -> dict[str, dict[str, dict[str, str]]] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, Mapping):
        raise ValueError("ubus verbose-list JSON must be an object")
    result: dict[str, dict[str, dict[str, str]]] = {}
    for object_name, raw_methods in payload.items():
        if not isinstance(raw_methods, Mapping):
            raise ValueError(f"ubus object methods are not an object:{object_name}")
        methods: dict[str, dict[str, str]] = {}
        for method_name, raw_schema in raw_methods.items():
            if not isinstance(raw_schema, Mapping):
                raise ValueError(f"ubus method schema is not an object:{object_name}:{method_name}")
            methods[str(method_name)] = _validate_schema(raw_schema)
        result[str(object_name)] = methods
    return result


def _parse_method_schema(raw: str, *, line_number: int) -> dict[str, str]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid ubus method schema on line {line_number}:{exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError(f"ubus method schema on line {line_number} is not an object")
    return _validate_schema(payload)


def _validate_schema(schema: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for field, raw_type in schema.items():
        if not isinstance(raw_type, str) or not raw_type.strip():
            raise ValueError(f"ubus schema field lacks a string type:{field}")
        result[str(field)] = raw_type.strip()
    return result


def _load_transaction_spans(path: Path) -> list[dict[str, Any]]:
    starts: dict[tuple[str, str], list[dict[str, Any]]] = {}
    spans: list[dict[str, Any]] = []
    for payload in _json_lines(path):
        key = (str(payload.get("variant_id") or ""), str(payload.get("transaction_fingerprint") or ""))
        if payload.get("event") == "transaction_start":
            starts.setdefault(key, []).append(payload)
        elif payload.get("event") == "transaction_end" and starts.get(key):
            start = starts[key].pop(0)
            spans.append(
                {
                    "variant_id": key[0],
                    "transaction_fingerprint": key[1],
                    "start_offset": int(start.get("trace_offset") or 0),
                    "end_offset": int(payload.get("trace_offset") or 0),
                }
            )
    return spans


def _load_initialization_baseline(path: Path) -> dict[str, Any] | None:
    baselines = [
        payload
        for payload in _json_lines(path)
        if payload.get("event") == "initialization_baseline"
    ]
    return baselines[-1] if baselines else None


def _load_readiness_spans(path: Path) -> list[dict[str, Any]]:
    starts: dict[tuple[str, str], list[dict[str, Any]]] = {}
    spans: list[dict[str, Any]] = []
    for payload in _json_lines(path):
        key = (
            str(payload.get("variant_id") or ""),
            str(payload.get("transaction_fingerprint") or ""),
        )
        if payload.get("event") == "readiness_attempt_start":
            starts.setdefault(key, []).append(payload)
        elif payload.get("event") == "readiness_attempt_end" and starts.get(key):
            start = starts[key].pop(0)
            spans.append(
                {
                    "variant_id": key[0],
                    "transaction_fingerprint": key[1],
                    "start_offset": int(start.get("trace_offset") or 0),
                    "end_offset": int(payload.get("trace_offset") or 0),
                }
            )
    return spans


def _load_trace_hits(path: Path) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    with Path(path).open("rb") as handle:
        while True:
            offset = handle.tell()
            raw = handle.readline()
            if not raw:
                break
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, Mapping):
                continue
            address = payload.get("operation_address") or payload.get("instruction_address") or payload.get("address")
            try:
                address_int = _numeric_address(address)
            except ValueError:
                continue
            hits.append({**dict(payload), "offset": offset, "address_int": address_int})
    return hits


def _json_lines(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in Path(path).read_text(errors="replace").splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _numeric_address(value: str | int | Any) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean is not a machine address")
    if isinstance(value, int):
        address = value
    else:
        text = str(value or "").strip()
        if not _NUMERIC_ADDRESS.fullmatch(text):
            raise ValueError(f"operation address is not exact numeric:{value}")
        address = int(text, 0)
    if address < 0:
        raise ValueError("operation address is negative")
    return address


def _freeze_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(sorted((str(key), _freeze_json_value(item)) for key, item in value.items()))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(_freeze_json_value(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError(f"transaction argument is not JSON-compatible:{type(value).__name__}")


def _thaw_json_value(value: Any) -> Any:
    if isinstance(value, tuple):
        if all(isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str) for item in value):
            return {key: _thaw_json_value(item) for key, item in value}
        return [_thaw_json_value(item) for item in value]
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n")
    temporary.replace(destination)


__all__ = (
    "FirmwareTransaction",
    "FirmwareTransactionPlan",
    "FirmwareTransactionCampaignResult",
    "FirmwareTransactionSession",
    "TransactionTraceAttributor",
    "UbusReadiness",
    "assess_ubus_readiness",
    "establish_transaction_readiness",
    "build_proot_fake_root_command",
    "build_transaction_plan",
    "compile_qemu_instruction_tracer",
    "inert_payload",
    "is_safe_ubus_method",
    "parse_ubus_verbose_list",
    "publication_acl",
    "recover_ubus_method_callbacks",
    "run_openwrt_ubus_transactions",
    "selected_call_acl",
    "transaction_variant_score",
    "validate_targeted_binds",
    "write_acl",
)
