"""Acquire, inventory, and evaluate explicitly listed firmware archives."""

from __future__ import annotations

import hashlib
import json
import os
import resource
import shutil
import subprocess
import tarfile
import time
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from binary_agent.intake import run_intake


FIRMWARE_CAMPAIGN_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class FirmwareCampaignResult:
    campaign_id: str
    run_dir: str
    images: tuple[Mapping[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        totals = Counter()
        for image in self.images:
            for key in (
                "binaries_inventoried",
                "binaries_analyzed",
                "candidate_count",
                "attempted_proofs",
                "completed_proofs",
                "report_count",
            ):
                totals[key] += int(image.get(key) or 0)
        return {
            "schema_version": FIRMWARE_CAMPAIGN_SCHEMA_VERSION,
            "artifact_kind": "untouched_firmware_campaign",
            "campaign_id": self.campaign_id,
            "run_dir": self.run_dir,
            "image_count": len(self.images),
            "totals": dict(totals),
            "images": [dict(item) for item in self.images],
        }


def run_firmware_campaign(
    manifest_path: Path,
    output_root: Path,
    *,
    scheduler: str = "adaptive",
    candidate_budget: int = 64,
    wall_budget_seconds: float = 3600.0,
    cpu_budget_seconds: float = 3600.0,
    proof_timeout_seconds: float = 30.0,
    proof_jobs: int = 1,
    ghidra_dir: Path | None = None,
    repo_root: Path | None = None,
) -> FirmwareCampaignResult:
    """Run a bounded campaign without treating blocked work as clean."""

    repository = (repo_root or Path.cwd()).expanduser().resolve()
    manifest_file = Path(manifest_path).expanduser().resolve()
    manifest = _load_json(manifest_file)
    if int(manifest.get("schema_version") or 0) != FIRMWARE_CAMPAIGN_SCHEMA_VERSION:
        raise ValueError("unsupported firmware campaign schema")
    campaign_id = _safe_name(str(manifest.get("campaign_id") or ""))
    images = manifest.get("images")
    if not campaign_id or not isinstance(images, list) or not images:
        raise ValueError("campaign manifest requires campaign_id and a non-empty images list")
    root = Path(output_root).expanduser()
    if not root.is_absolute():
        root = repository / root
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    run_id = _available_run_id(root)
    run_dir = root / run_id
    run_dir.mkdir()
    shutil.copy2(manifest_file, run_dir / "input_manifest.json")
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["BINARY_AGENT_GHIDRA_HOME"] = str(root / "cache" / "ghidra_home")
    if ghidra_dir is not None:
        environment["GHIDRA_INSTALL_DIR"] = str(Path(ghidra_dir).expanduser().resolve())

    rows: list[Mapping[str, Any]] = []
    for raw in images:
        if not isinstance(raw, Mapping):
            raise ValueError("every firmware image must be an object")
        rows.append(
            _run_image(
                raw,
                manifest_dir=manifest_file.parent,
                campaign_dir=run_dir,
                campaign_cache_dir=root / "cache",
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
        )
    result = FirmwareCampaignResult(campaign_id, str(run_dir), tuple(rows))
    _write_json(run_dir / "firmware_campaign_summary.json", result.to_dict())
    _write_json(
        root / "latest.json",
        {
            "schema_version": 1,
            "artifact_kind": "firmware_campaign_latest",
            "campaign_id": campaign_id,
            "run_id": run_id,
            "run_dir": str(run_dir),
            "summary_path": str(run_dir / "firmware_campaign_summary.json"),
        },
    )
    return result


def _run_image(
    raw: Mapping[str, Any],
    *,
    manifest_dir: Path,
    campaign_dir: Path,
    campaign_cache_dir: Path,
    repository: Path,
    environment: Mapping[str, str],
    scheduler: str,
    candidate_budget: int,
    wall_budget_seconds: float,
    cpu_budget_seconds: float,
    proof_timeout_seconds: float,
    proof_jobs: int,
    ghidra_dir: Path | None,
) -> Mapping[str, Any]:
    image_id = _safe_name(str(raw.get("id") or ""))
    expected_sha256 = str(raw.get("sha256") or "").lower()
    if not image_id or len(expected_sha256) != 64:
        raise ValueError("every firmware image requires id and a pinned sha256")
    image_dir = campaign_dir / "images" / image_id
    download_dir = image_dir / "acquisition"
    rootfs_dir = image_dir / "rootfs"
    download_dir.mkdir(parents=True)
    archive = download_dir / _safe_archive_name(raw)
    source = _acquire(raw, manifest_dir, archive)
    archive_sha256 = _sha256_file(archive)
    if archive_sha256 != expected_sha256:
        raise ValueError(f"firmware hash mismatch for {image_id}: {archive_sha256}")
    extraction_normalizations = _extract_archive(archive, rootfs_dir, str(raw.get("archive_type") or "tar"))
    tree_sha256 = _tree_sha256(rootfs_dir)

    intake_dir = image_dir / "inventory"
    intake = run_intake(rootfs_dir, intake_dir, overwrite=True)
    binaries_payload = _load_json(intake.binaries_path)
    inventory_entries = [item for item in binaries_payload.get("binaries", []) if isinstance(item, Mapping)]
    binaries = [
        item
        for item in inventory_entries
        if "elf" in str(item.get("architecture") or "").lower()
        and "executable" in str(item.get("architecture") or "").lower()
        and "shared object" not in str(item.get("architecture") or "").lower()
    ]
    architectures = Counter(str(item.get("architecture") or "unknown") for item in binaries)
    regex = str(raw.get("binary_regex") or "")
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    toolchain_root = image_dir / "toolchain"
    command = [
        str(repository / ".venv" / "bin" / "python"),
        "-m",
        "binary_agent.cli.toolchain",
        str(rootfs_dir),
        "--output-root",
        str(toolchain_root),
        "--cache-dir",
        str(campaign_cache_dir / "decomp"),
        "--analysis-cache-dir",
        str(campaign_cache_dir / "analysis"),
        "--stages",
        "intake,discovery,refinement,proof,replay,report",
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
    if regex:
        command.extend(["--firmware-binary-regex", regex])
    if ghidra_dir is not None:
        command.extend(["--ghidra-dir", str(Path(ghidra_dir).expanduser().resolve())])
    completed = subprocess.run(
        command,
        cwd=repository,
        env=dict(environment),
        capture_output=True,
        text=True,
        check=False,
    )
    wall_seconds = time.monotonic() - started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_seconds = (after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime)
    (image_dir / "toolchain.stdout.txt").write_text(completed.stdout)
    (image_dir / "toolchain.stderr.txt").write_text(completed.stderr)
    toolchain_run = _latest_toolchain_run(toolchain_root, rootfs_dir.name)
    facts = _collect_toolchain_facts(toolchain_run)
    disclosure_packages = _write_disclosure_packages(
        image_dir / "disclosure_packages",
        image_id=image_id,
        archive_sha256=archive_sha256,
        tree_sha256=tree_sha256,
        toolchain_run=toolchain_run,
        reports=facts.pop("reports"),
    )
    analyzed = facts.get("binaries_analyzed", 0)
    return {
        "id": image_id,
        "source": source,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "archive_path": str(archive),
        "archive_sha256": archive_sha256,
        "tree_sha256": tree_sha256,
        "extraction_normalizations": extraction_normalizations,
        "license": str(raw.get("license") or "unspecified"),
        "redistribution_note": str(raw.get("redistribution_note") or ""),
        "binary_regex": regex,
        "binaries_inventoried": len(binaries),
        "intake_executable_entries": len(inventory_entries),
        "binaries_analyzed": analyzed,
        "architectures": dict(sorted(architectures.items())),
        "scheduler": scheduler,
        "candidate_budget": candidate_budget,
        "wall_budget_seconds": wall_budget_seconds,
        "cpu_budget_seconds": cpu_budget_seconds,
        "wall_seconds": wall_seconds,
        "cpu_seconds": cpu_seconds,
        "toolchain_returncode": completed.returncode,
        "toolchain_run": str(toolchain_run) if toolchain_run else "",
        "disclosure_packages": disclosure_packages,
        **facts,
    }


def _acquire(raw: Mapping[str, Any], manifest_dir: Path, destination: Path) -> str:
    url = str(raw.get("url") or "").strip()
    local = str(raw.get("path") or "").strip()
    if bool(url) == bool(local):
        raise ValueError("firmware image must declare exactly one of url or path")
    if local:
        source = Path(local).expanduser()
        if not source.is_absolute():
            source = manifest_dir / source
        source = source.resolve()
        if not source.is_file():
            raise FileNotFoundError(source)
        shutil.copy2(source, destination)
        return str(source)
    if not url.startswith(("https://", "http://")):
        raise ValueError("firmware URL must use HTTP or HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "vulnfinder2-research/1"})
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as handle:
        shutil.copyfileobj(response, handle)
    return url


def _extract_archive(archive: Path, destination: Path, archive_type: str) -> list[Mapping[str, str]]:
    if archive_type not in {"tar", "tar.gz", "tgz"}:
        raise ValueError(f"unsupported archive_type: {archive_type}")
    destination.mkdir(parents=True)
    root = destination.resolve()
    normalizations: list[Mapping[str, str]] = []
    with tarfile.open(archive, "r:*") as bundle:
        members = bundle.getmembers()
        for member in members:
            target = (destination / member.name).resolve()
            if target != root and root not in target.parents:
                raise ValueError(f"unsafe archive member: {member.name}")
            if member.isdev() or member.isfifo():
                raise ValueError(f"unsupported special archive member: {member.name}")
            if member.issym() or member.islnk():
                if Path(member.linkname).is_absolute():
                    original = member.linkname
                    in_root_target = root / member.linkname.lstrip("/")
                    member.linkname = os.path.relpath(in_root_target, target.parent if member.issym() else root)
                    normalizations.append(
                        {
                            "kind": "absolute_link_rebased_within_rootfs",
                            "path": member.name,
                            "original_target": original,
                            "extracted_target": member.linkname,
                        }
                    )
                link_base = target.parent if member.issym() else root
                link_target = (link_base / member.linkname).resolve()
                if link_target != root and root not in link_target.parents:
                    raise ValueError(f"unsafe archive link: {member.name} -> {member.linkname}")
        data_filter = getattr(tarfile, "data_filter", None)
        if data_filter is None:  # Python 3.10/3.11 compatibility after validation above.
            bundle.extractall(destination, members=members)
        else:
            bundle.extractall(destination, members=members, filter="data")
    return normalizations


def _collect_toolchain_facts(run_dir: Path | None) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "binaries_analyzed": 0,
        "candidate_count": 0,
        "attempted_proofs": 0,
        "completed_proofs": 0,
        "report_count": 0,
        "blockers": {},
        "reports": [],
    }
    if run_dir is None:
        return facts
    summary = _load_json_if_present(run_dir / "firmware_run_summary.json")
    facts["binaries_analyzed"] = len(summary.get("binaries_analyzed", []))
    facts["candidate_count"] = int(summary.get("candidate_total") or 0)
    facts["report_count"] = int(summary.get("report_count") or 0)
    scheduler = _load_json_if_present(run_dir / "proof" / "scheduler_metrics.json")
    execution_recorded = scheduler.get("budget_stop_reason") not in {None, "", "not_recorded"}
    facts["attempted_proofs"] = int(
        scheduler.get("actual_executed_attempts", scheduler.get("actual_executed_candidates"))
        if execution_recorded
        else scheduler.get("selected_candidates") or 0
    )
    facts["proof_actual_wall_seconds"] = float(scheduler.get("actual_wall_seconds") or 0.0)
    facts["proof_actual_cpu_seconds"] = float(scheduler.get("actual_cpu_seconds") or 0.0)
    facts["proof_budget_stop_reason"] = str(scheduler.get("budget_stop_reason") or "")
    proof = _load_json_if_present(run_dir / "proof" / "metrics.json")
    proof_outcomes = proof.get("proof_outcomes") if isinstance(proof, Mapping) else {}
    proof_outcomes = proof_outcomes if isinstance(proof_outcomes, Mapping) else {}
    facts["completed_proofs"] = int(proof_outcomes.get("proven") or 0) + int(proof_outcomes.get("refuted") or 0)
    facts["blockers"] = dict(proof.get("normalized_blocker_totals") or {}) if isinstance(proof, Mapping) else {}
    reports = _load_json_if_present(run_dir / "report" / "vulnerabilities.json")
    raw_reports = reports.get("vulnerabilities", []) if isinstance(reports, Mapping) else reports
    facts["reports"] = raw_reports if isinstance(raw_reports, list) else []
    return facts


def _write_disclosure_packages(
    output_dir: Path,
    *,
    image_id: str,
    archive_sha256: str,
    tree_sha256: str,
    toolchain_run: Path | None,
    reports: list[Any],
) -> list[str]:
    paths: list[str] = []
    for index, raw in enumerate(reports, start=1):
        if not isinstance(raw, Mapping):
            continue
        candidate_id = _safe_name(str(raw.get("candidate_id") or f"finding-{index}"))
        package = output_dir / candidate_id
        package.mkdir(parents=True, exist_ok=True)
        redacted = _redact_sensitive(raw)
        _write_json(package / "finding.json", redacted)
        _write_json(
            package / "manifest.json",
            {
                "schema_version": 1,
                "artifact_kind": "unsent_firmware_disclosure_package",
                "image_id": image_id,
                "candidate_id": candidate_id,
                "archive_sha256": archive_sha256,
                "tree_sha256": tree_sha256,
                "toolchain_run": str(toolchain_run) if toolchain_run else "",
                "status": "local_draft_not_sent",
            },
        )
        (package / "draft.md").write_text(
            "\n".join(
                [
                    f"# Unsent research finding: {candidate_id}",
                    "",
                    f"Firmware image: `{image_id}`",
                    f"Archive SHA-256: `{archive_sha256}`",
                    f"Extracted tree SHA-256: `{tree_sha256}`",
                    "",
                    "This package was generated only after the ordinary schema-v2 proof gate. ",
                    "It is a local research draft and has not been transmitted. Review the attached ",
                    "redacted finding and the referenced durable toolchain artifacts before disclosure.",
                    "",
                ]
            )
        )
        paths.append(str(package))
    return paths


def _redact_sensitive(value: Any, key: str = "") -> Any:
    sensitive = any(token in key.lower() for token in ("password", "credential", "secret", "token", "private_key", "literal"))
    if sensitive and value not in (None, "", [], {}):
        digest = hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()
        return {"redacted": True, "sha256": digest}
    if isinstance(value, Mapping):
        return {str(item_key): _redact_sensitive(item, str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_redact_sensitive(item, key) for item in value]
    return value


def _latest_toolchain_run(root: Path, target_name: str) -> Path | None:
    parent = root / target_name
    candidates = sorted((item for item in parent.glob("*") if item.is_dir()), reverse=True) if parent.is_dir() else []
    return candidates[0] if candidates else None


def _safe_archive_name(raw: Mapping[str, Any]) -> str:
    source = str(raw.get("url") or raw.get("path") or "firmware.tar")
    name = source.rsplit("/", 1)[-1].split("?", 1)[0]
    return _safe_name(name) or "firmware.tar"


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode())
        if path.is_symlink():
            digest.update(b"L")
            digest.update(os.readlink(path).encode())
        elif path.is_file():
            digest.update(b"F")
            digest.update(oct(path.stat().st_mode & 0o7777).encode())
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        elif path.is_dir():
            digest.update(b"D")
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _available_run_id(root: Path) -> str:
    base = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    candidate = base
    counter = 1
    while (root / candidate).exists():
        candidate = f"{base}-{counter}"
        counter += 1
    return candidate


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)[:160]


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _load_json_if_present(path: Path) -> Any:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)
