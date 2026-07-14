"""Freeze and verify immutable research-corpus inputs."""

from __future__ import annotations

import hashlib
import json
import os
import resource
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.research_metrics import CaseOutcome, compute_research_metrics


FROZEN_CORPUS_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class FrozenCase:
    case_id: str
    lane: str
    vulnerability_type: str
    comparison_group: str
    binary_path: str
    binary_sha256: str
    source_path: str
    source_sha256: str
    compile_command: tuple[str, ...]
    process: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["id"] = payload.pop("case_id")
        payload["compile_command"] = list(self.compile_command)
        payload["process"] = dict(self.process)
        return payload


@dataclass(frozen=True)
class FrozenCorpus:
    corpus_id: str
    corpus_dir: str
    analyzer_sha256: str
    upstream: Mapping[str, Any]
    cases: tuple[FrozenCase, ...]
    frozen_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": FROZEN_CORPUS_SCHEMA_VERSION,
            "artifact_kind": "frozen_research_corpus",
            "corpus_id": self.corpus_id,
            "corpus_dir": self.corpus_dir,
            "analyzer_sha256": self.analyzer_sha256,
            "upstream": dict(self.upstream),
            "frozen_at": self.frozen_at,
            "cases": [item.to_dict() for item in self.cases],
        }


@dataclass(frozen=True)
class ResearchEvaluation:
    run_id: str
    run_dir: str
    corpus_id: str
    scheduler: str
    analyzer_sha256: str
    frozen_analyzer_sha256: str
    cases: tuple[Mapping[str, Any], ...]
    metrics: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "artifact_kind": "frozen_research_evaluation",
            "run_id": self.run_id,
            "run_dir": self.run_dir,
            "corpus_id": self.corpus_id,
            "scheduler": self.scheduler,
            "analyzer_sha256": self.analyzer_sha256,
            "frozen_analyzer_sha256": self.frozen_analyzer_sha256,
            "cases": [dict(item) for item in self.cases],
            "metrics": dict(self.metrics),
        }


def freeze_research_corpus(
    candidate_manifest: Path,
    output_root: Path,
    *,
    source_root: Path,
    repo_root: Path | None = None,
) -> FrozenCorpus:
    """Build, copy, and hash a candidate manifest exactly once."""

    repository = (repo_root or Path.cwd()).expanduser().resolve()
    manifest_path = Path(candidate_manifest).expanduser().resolve()
    payload = _load_json(manifest_path)
    corpus_id = _safe_name(payload.get("corpus_id"))
    if not corpus_id:
        raise ValueError("candidate manifest must declare corpus_id")
    root = Path(output_root).expanduser()
    if not root.is_absolute():
        root = repository / root
    corpus_dir = root.resolve() / corpus_id
    if corpus_dir.exists():
        raise FileExistsError(f"frozen corpus already exists: {corpus_dir}")
    source_base = Path(source_root).expanduser().resolve()
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("candidate manifest must contain a non-empty cases list")
    corpus_dir.mkdir(parents=True)
    cases: list[FrozenCase] = []
    try:
        for raw in raw_cases:
            if not isinstance(raw, Mapping):
                raise ValueError("every candidate case must be an object")
            cases.append(_freeze_case(raw, source_base, corpus_dir))
        frozen = FrozenCorpus(
            corpus_id=corpus_id,
            corpus_dir=str(corpus_dir),
            analyzer_sha256=analyzer_tree_sha256(repository),
            upstream=dict(payload.get("upstream") or {}),
            cases=tuple(cases),
            frozen_at=datetime.now(timezone.utc).isoformat(),
        )
        _write_json_atomic(corpus_dir / "frozen_manifest.json", frozen.to_dict())
        _write_json_atomic(
            corpus_dir / "inventory.json",
            {
                "schema_version": 1,
                "artifact_kind": "frozen_research_corpus_inventory",
                "files": _inventory(corpus_dir),
            },
        )
        return frozen
    except Exception:
        shutil.rmtree(corpus_dir, ignore_errors=True)
        raise


def verify_frozen_corpus(path: Path) -> dict[str, Any]:
    """Verify immutable binary and source hashes without running analysis."""

    manifest_path = Path(path).expanduser().resolve()
    payload = _load_json(manifest_path)
    if int(payload.get("schema_version") or 0) != FROZEN_CORPUS_SCHEMA_VERSION:
        raise ValueError("unsupported frozen corpus schema")
    corpus_dir = manifest_path.parent
    failures: list[dict[str, str]] = []
    for raw in payload.get("cases", []):
        if not isinstance(raw, Mapping):
            failures.append({"id": "", "kind": "invalid_case"})
            continue
        case_id = str(raw.get("id") or "")
        for kind in ("binary", "source"):
            relative = str(raw.get(f"{kind}_path") or "")
            expected = str(raw.get(f"{kind}_sha256") or "")
            target = corpus_dir / relative
            if not target.is_file():
                failures.append({"id": case_id, "kind": kind, "reason": "missing"})
            elif _sha256(target) != expected:
                failures.append({"id": case_id, "kind": kind, "reason": "hash_mismatch"})
    return {
        "schema_version": 1,
        "artifact_kind": "frozen_research_corpus_verification",
        "corpus_id": str(payload.get("corpus_id") or ""),
        "verified": not failures,
        "case_count": len(payload.get("cases", [])),
        "failures": failures,
    }


def evaluate_frozen_corpus(
    frozen_manifest: Path,
    output_root: Path,
    *,
    scheduler: str = "adaptive",
    candidate_budget: int = 8,
    wall_budget_seconds: float = 120.0,
    cpu_budget_seconds: float = 120.0,
    proof_timeout_seconds: float = 15.0,
    proof_jobs: int = 1,
    ghidra_dir: Path | None = None,
    repo_root: Path | None = None,
) -> ResearchEvaluation:
    """Run one immutable corpus without mutating its manifest or expectations."""

    repository = (repo_root or Path.cwd()).expanduser().resolve()
    manifest_path = Path(frozen_manifest).expanduser().resolve()
    verification = verify_frozen_corpus(manifest_path)
    if not verification["verified"]:
        raise ValueError(f"frozen corpus verification failed: {verification['failures']}")
    frozen = _load_json(manifest_path)
    root = Path(output_root).expanduser()
    if not root.is_absolute():
        root = repository / root
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    run_id = _available_run_id(root)
    run_dir = root / run_id
    run_dir.mkdir()
    case_rows: list[dict[str, Any]] = []
    outcomes: list[CaseOutcome] = []
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["BINARY_AGENT_GHIDRA_HOME"] = str(root / "cache" / "ghidra_home")
    if ghidra_dir is not None:
        environment["GHIDRA_INSTALL_DIR"] = str(Path(ghidra_dir).expanduser().resolve())
    for raw in frozen.get("cases", []):
        if not isinstance(raw, Mapping):
            continue
        row, outcome = _evaluate_case(
            raw,
            corpus_dir=manifest_path.parent,
            run_dir=run_dir,
            cache_dir=root / "cache",
            repository=repository,
            environment=environment,
            scheduler=scheduler,
            candidate_budget=candidate_budget,
            wall_budget_seconds=wall_budget_seconds,
            cpu_budget_seconds=cpu_budget_seconds,
            proof_timeout_seconds=proof_timeout_seconds,
            proof_jobs=proof_jobs,
            ghidra_dir=ghidra_dir,
        )
        case_rows.append(row)
        outcomes.append(outcome)
    metrics = compute_research_metrics(outcomes).to_dict()
    result = ResearchEvaluation(
        run_id=run_id,
        run_dir=str(run_dir),
        corpus_id=str(frozen.get("corpus_id") or ""),
        scheduler=scheduler,
        analyzer_sha256=analyzer_tree_sha256(repository),
        frozen_analyzer_sha256=str(frozen.get("analyzer_sha256") or ""),
        cases=tuple(case_rows),
        metrics=metrics,
    )
    summary_path = run_dir / "research_evaluation_summary.json"
    _write_json_atomic(summary_path, result.to_dict())
    _write_json_atomic(
        root / "latest.json",
        {
            "schema_version": 1,
            "artifact_kind": "frozen_research_evaluation_latest",
            "run_id": run_id,
            "run_dir": str(run_dir),
            "corpus_id": result.corpus_id,
            "summary_path": str(summary_path),
        },
    )
    return result


def analyzer_tree_sha256(repo_root: Path) -> str:
    """Fingerprint analyzer behavior without requiring a Git checkout."""

    digest = hashlib.sha256()
    repository = Path(repo_root).resolve()
    roots = (repository / "src", repository / "ghidra_scripts", repository / "scripts")
    paths = sorted(
        path
        for root in roots
        if root.exists()
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".py", ".json"}
    )
    for path in paths:
        digest.update(str(path.relative_to(repository)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _evaluate_case(
    raw: Mapping[str, Any],
    *,
    corpus_dir: Path,
    run_dir: Path,
    cache_dir: Path,
    repository: Path,
    environment: Mapping[str, str],
    scheduler: str,
    candidate_budget: int,
    wall_budget_seconds: float,
    cpu_budget_seconds: float,
    proof_timeout_seconds: float,
    proof_jobs: int,
    ghidra_dir: Path | None,
) -> tuple[dict[str, Any], CaseOutcome]:
    case_id = str(raw.get("id") or "")
    lane = str(raw.get("lane") or "")
    vulnerability_type = str(raw.get("vulnerability_type") or "")
    binary = corpus_dir / str(raw.get("binary_path") or "")
    case_dir = run_dir / "cases" / case_id
    output_dir = case_dir / "toolchain"
    case_dir.mkdir(parents=True)
    process_path = case_dir / "process_input.json"
    _write_json_atomic(
        process_path,
        {"schema_version": 2, **dict(raw.get("process") or {})},
    )
    command = [
        str(repository / ".venv" / "bin" / "python"),
        "-m",
        "binary_agent.cli.toolchain",
        str(binary),
        "--output-root",
        str(output_dir),
        "--cache-dir",
        str(cache_dir / "decomp"),
        "--analysis-cache-dir",
        str(cache_dir / "analysis"),
        "--stages",
        "intake,discovery,refinement,proof,replay,report",
        "--vulnerability-types",
        vulnerability_type,
        "--process-input-json",
        str(process_path),
        "--proof-scheduler",
        scheduler,
        "--proof-candidate-budget",
        str(max(0, candidate_budget)),
        "--proof-wall-budget-seconds",
        str(max(0.0, wall_budget_seconds)),
        "--proof-cpu-budget-seconds",
        str(max(0.0, cpu_budget_seconds)),
        "--proof-timeout-seconds",
        str(max(0.1, proof_timeout_seconds)),
        "--proof-jobs",
        str(max(1, proof_jobs)),
        "--hypothesis-policy",
        "off",
        "--overwrite",
    ]
    if ghidra_dir is not None:
        command.extend(["--ghidra-dir", str(Path(ghidra_dir).expanduser().resolve())])
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.perf_counter()
    timeout = max(300.0, wall_budget_seconds + 300.0 if wall_budget_seconds else 1800.0)
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=repository,
            env=dict(environment),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        returncode = completed.returncode
        stdout, stderr = completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = 124
        stdout = str(exc.stdout or "")
        stderr = str(exc.stderr or "") + "\ncase_timeout"
    wall_seconds = time.perf_counter() - started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_seconds = max(0.0, (after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime))
    (case_dir / "stdout.log").write_text(stdout)
    (case_dir / "stderr.log").write_text(stderr)
    actual_run = _latest_toolchain_run(output_dir, binary.name)
    candidates = _json_rows(actual_run / "discovery" / "candidates.json", "candidates") if actual_run else []
    proofs = _json_rows(actual_run / "proof" / "proof_results.json", "proof_results") if actual_run else []
    reports = _json_rows(actual_run / "report" / "vulnerabilities.json", "vulnerabilities") if actual_run else []
    scheduler_metrics = _load_json_optional(actual_run / "proof" / "scheduler_metrics.json") if actual_run else {}
    attempted = int(scheduler_metrics.get("selected_candidates") or 0)
    completed_proofs = sum(str(item.get("status") or "") in {"proven", "refuted"} for item in proofs)
    blockers = sorted(
        {
            str(item.get("blocker") or "")
            for item in proofs
            if str(item.get("blocker") or "")
        }
    )
    if timed_out:
        blockers.append("case_timeout")
    if returncode != 0:
        blockers.append(f"toolchain_exit_{returncode}")
    matching_reports = [item for item in reports if str(item.get("vulnerability_type") or item.get("vulnerability") or "") == vulnerability_type]
    decision = _case_decision(
        lane,
        candidate_count=len(candidates),
        proof_rows=proofs,
        report_count=len(matching_reports),
        returncode=returncode,
    )
    if decision == "blocked" and not blockers:
        blockers.append("proof_incomplete")
    row = {
        "id": case_id,
        "lane": lane,
        "vulnerability_type": vulnerability_type,
        "decision": decision,
        "returncode": returncode,
        "candidate_count": len(candidates),
        "attempted_proofs": attempted,
        "completed_proofs": completed_proofs,
        "report_count": len(matching_reports),
        "wall_seconds": round(wall_seconds, 6),
        "cpu_seconds": round(cpu_seconds, 6),
        "blockers": blockers,
        "run_dir": str(actual_run) if actual_run else "",
        "stdout_path": str(case_dir / "stdout.log"),
        "stderr_path": str(case_dir / "stderr.log"),
        "command": command,
    }
    outcome = CaseOutcome(
        case_id=case_id,
        lane=lane,
        decision=decision,
        candidate_count=len(candidates),
        attempted_proofs=attempted,
        completed_proofs=completed_proofs,
        report_count=len(matching_reports),
        wall_seconds=wall_seconds,
        cpu_seconds=cpu_seconds,
        blockers=tuple(blockers),
        time_to_first_proof_seconds=wall_seconds if matching_reports else None,
    )
    return row, outcome


def _case_decision(
    lane: str,
    *,
    candidate_count: int,
    proof_rows: Sequence[Mapping[str, Any]],
    report_count: int,
    returncode: int,
) -> str:
    if report_count:
        return "reported" if lane == "vulnerable" else "false_positive"
    if returncode != 0:
        return "blocked"
    decisive = [str(item.get("status") or "") for item in proof_rows if str(item.get("status") or "") in {"proven", "refuted"}]
    unresolved = [str(item.get("status") or "") for item in proof_rows if str(item.get("status") or "") in {"inconclusive", "unsupported"}]
    if candidate_count == 0:
        return "missed" if lane == "vulnerable" else "clean"
    if decisive and not unresolved and all(item == "refuted" for item in decisive):
        return "missed" if lane == "vulnerable" else "clean"
    return "blocked"


def _latest_toolchain_run(output_dir: Path, binary_name: str) -> Path | None:
    parent = output_dir / binary_name
    runs = sorted(path for path in parent.glob("*") if path.is_dir()) if parent.exists() else []
    return runs[-1] if runs else None


def _json_rows(path: Path, key: str) -> list[dict[str, Any]]:
    payload = _load_json_optional(path)
    rows = payload.get(key)
    return [dict(item) for item in rows] if isinstance(rows, list) else []


def _load_json_optional(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text() or "{}")
    except (OSError, json.JSONDecodeError):
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}


def _available_run_id(root: Path) -> str:
    base = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if not (root / base).exists():
        return base
    index = 1
    while (root / f"{base}-{index:03d}").exists():
        index += 1
    return f"{base}-{index:03d}"


def _freeze_case(raw: Mapping[str, Any], source_root: Path, corpus_dir: Path) -> FrozenCase:
    case_id = _safe_name(raw.get("id"))
    lane = str(raw.get("lane") or "")
    vulnerability_type = str(raw.get("vulnerability_type") or "")
    comparison_group = str(raw.get("comparison_group") or "")
    if not all((case_id, lane in {"vulnerable", "fixed"}, vulnerability_type, comparison_group)):
        raise ValueError(f"invalid candidate case: {case_id or '<unnamed>'}")
    source_relative = Path(str(raw.get("source") or ""))
    source = (source_root / source_relative).resolve()
    if source_root not in source.parents or not source.is_file():
        raise ValueError(f"case {case_id}: source is missing or escapes source_root")
    copied_source = corpus_dir / "sources" / case_id / source.name
    copied_source.parent.mkdir(parents=True)
    shutil.copy2(source, copied_source)
    compile_spec = raw.get("compile") if isinstance(raw.get("compile"), Mapping) else {}
    compiler = shutil.which(str(compile_spec.get("compiler") or "cc"))
    if not compiler:
        raise RuntimeError(f"case {case_id}: compiler unavailable")
    output = corpus_dir / "binaries" / case_id
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [compiler]
    for flag in _strings(compile_spec.get("flags")):
        command.append(flag)
    for define in _strings(compile_spec.get("defines")):
        command.append(f"-D{define}")
    for include in _strings(compile_spec.get("include_dirs")):
        path = (source_root / include).resolve()
        command.extend(["-I", str(path)])
    command.append(str(source))
    for support in _strings(compile_spec.get("support_sources")):
        path = (source_root / support).resolve()
        if not path.is_file():
            raise ValueError(f"case {case_id}: support source is missing: {support}")
        command.append(str(path))
    command.extend(["-o", str(output)])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    build_log = corpus_dir / "build_logs" / f"{case_id}.json"
    build_log.parent.mkdir(parents=True, exist_ok=True)
    _write_json_atomic(
        build_log,
        {
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        },
    )
    if completed.returncode != 0 or not output.is_file():
        raise RuntimeError(f"case {case_id}: compilation failed; see {build_log}")
    strip = shutil.which("strip")
    if bool(compile_spec.get("strip", True)) and strip:
        subprocess.run([strip, "--strip-all", str(output)], check=True)
    return FrozenCase(
        case_id=case_id,
        lane=lane,
        vulnerability_type=vulnerability_type,
        comparison_group=comparison_group,
        binary_path=str(output.relative_to(corpus_dir)),
        binary_sha256=_sha256(output),
        source_path=str(copied_source.relative_to(corpus_dir)),
        source_sha256=_sha256(copied_source),
        compile_command=tuple(command),
        process=dict(raw.get("process") or {}),
    )


def _inventory(root: Path) -> list[dict[str, Any]]:
    return [
        {"path": str(path.relative_to(root)), "sha256": _sha256(path), "size": path.stat().st_size}
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "inventory.json"
    ]


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence):
        return [str(item) for item in value]
    raise ValueError("compile list fields must be strings or arrays")


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain an object")
    return payload


def _safe_name(value: Any) -> str:
    text = "".join(character if character.isalnum() or character in "-_" else "-" for character in str(value or ""))
    return text.strip("-")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)
