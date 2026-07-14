"""Durable orchestration for the repository's registered research corpora."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.corpus_runner import load_corpus_manifest, run_corpus


REGISTERED_CORPORA = (
    ("semantic", Path("tests/fixtures/schema2_registered_semantic/manifest.json"), True),
    ("memory", Path("tests/fixtures/schema2_registered_memory/manifest.json"), False),
    ("static", Path("tests/fixtures/schema2_registered_static/manifest.json"), True),
)
EVIDENCE_FILENAMES = frozenset(
    {"candidates.json", "proof_results.json", "vulnerabilities.json"}
)


@dataclass(frozen=True)
class ResearchCorpusResult:
    corpus_id: str
    manifest_path: str
    status: str
    run_dir: str = ""
    summary_path: str = ""
    summary_sha256: str = ""
    accepted: bool = False
    totals: Mapping[str, Any] = field(default_factory=dict)
    evidence_artifacts: tuple[Mapping[str, str], ...] = ()
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["totals"] = dict(self.totals or {})
        payload["evidence_artifacts"] = [dict(item) for item in self.evidence_artifacts]
        return payload


@dataclass(frozen=True)
class ResearchMatrixResult:
    run_id: str
    mode: str
    run_dir: str
    accepted: bool
    corpora: tuple[ResearchCorpusResult, ...]
    totals: Mapping[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "artifact_kind": "registered_research_matrix_summary",
            "run_id": self.run_id,
            "mode": self.mode,
            "run_dir": self.run_dir,
            "accepted": self.accepted,
            "corpora": [item.to_dict() for item in self.corpora],
            "totals": dict(self.totals),
        }


def run_registered_matrix(
    output_root: Path,
    *,
    mode: str,
    run_id: str | None = None,
    overwrite_run: bool = False,
    repo_root: Path | None = None,
) -> ResearchMatrixResult:
    """Run the registered matrix below a durable research output root."""

    if mode not in {"lightweight", "full"}:
        raise ValueError(f"Unsupported research matrix mode: {mode!r}")
    repository = (repo_root or Path.cwd()).expanduser().resolve()
    root = output_root.expanduser()
    if not root.is_absolute():
        root = repository / root
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    selected_run_id = run_id or _available_run_id(root)
    run_dir = (root / selected_run_id).resolve()
    if root not in run_dir.parents:
        raise ValueError("Research run directory must remain below output_root")
    if run_dir.exists():
        if not overwrite_run:
            raise FileExistsError(f"Research run already exists: {run_dir}")
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)

    corpus_results: list[ResearchCorpusResult] = []
    for label, manifest_relative, lightweight_supported in REGISTERED_CORPORA:
        manifest_path = (repository / manifest_relative).resolve()
        manifest = load_corpus_manifest(manifest_path)
        if mode == "lightweight" and not lightweight_supported:
            corpus_results.append(
                ResearchCorpusResult(
                    corpus_id=manifest.corpus_id,
                    manifest_path=str(manifest_path),
                    status="skipped_requires_full_ghidra",
                    totals={},
                    reason="exact null and lifetime process proof require full Ghidra mode",
                )
            )
            continue
        corpus_dir = run_dir / label
        cache_dir = root / "cache" / label
        configured = replace(manifest, cache_dir=cache_dir)
        summary = run_corpus(configured, corpus_dir, mode=mode)
        summary_path = corpus_dir / "corpus_summary.json"
        evidence = _evidence_inventory(corpus_dir, run_dir)
        corpus_results.append(
            ResearchCorpusResult(
                corpus_id=summary.corpus_id,
                manifest_path=str(manifest_path),
                status="completed" if summary.accepted else "failed",
                run_dir=str(corpus_dir),
                summary_path=str(summary_path),
                summary_sha256=_sha256(summary_path),
                accepted=summary.accepted,
                totals=dict(summary.totals),
                evidence_artifacts=evidence,
                reason="" if summary.accepted else "; ".join(summary.errors),
            )
        )

    completed = [item for item in corpus_results if item.status in {"completed", "failed"}]
    result = ResearchMatrixResult(
        run_id=selected_run_id,
        mode=mode,
        run_dir=str(run_dir),
        accepted=bool(completed) and all(item.accepted for item in completed),
        corpora=tuple(corpus_results),
        totals=_aggregate_totals(corpus_results),
    )
    summary_path = run_dir / "research_matrix_summary.json"
    _write_json_atomic(summary_path, result.to_dict())
    _write_json_atomic(
        root / "latest.json",
        {
            "schema_version": 1,
            "artifact_kind": "registered_research_matrix_latest",
            "run_id": result.run_id,
            "mode": result.mode,
            "run_dir": result.run_dir,
            "accepted": result.accepted,
            "summary_path": str(summary_path),
            "summary_sha256": _sha256(summary_path),
        },
    )
    return result


def _available_run_id(root: Path) -> str:
    base = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if not (root / base).exists():
        return base
    for index in range(1, 1000):
        candidate = f"{base}-{index:03d}"
        if not (root / candidate).exists():
            return candidate
    raise RuntimeError("Unable to allocate a unique research run id")


def _evidence_inventory(corpus_dir: Path, run_dir: Path) -> tuple[Mapping[str, str], ...]:
    rows: list[dict[str, str]] = []
    for path in sorted(corpus_dir.rglob("*.json")):
        if path.name not in EVIDENCE_FILENAMES:
            continue
        rows.append(
            {
                "path": str(path.relative_to(run_dir)),
                "sha256": _sha256(path),
                "kind": path.name.removesuffix(".json"),
            }
        )
    return tuple(rows)


def _aggregate_totals(corpora: Sequence[ResearchCorpusResult]) -> dict[str, int]:
    keys = ("lane_count", "candidates", "proof_results", "proven", "reports", "fixed_reports")
    totals = {key: 0 for key in keys}
    totals["completed_corpora"] = 0
    totals["skipped_corpora"] = 0
    for corpus in corpora:
        if corpus.status == "completed":
            totals["completed_corpora"] += 1
        elif corpus.status.startswith("skipped"):
            totals["skipped_corpora"] += 1
        for key in keys:
            totals[key] += int((corpus.totals or {}).get(key, 0) or 0)
    return totals


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)
