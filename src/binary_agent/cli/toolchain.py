"""Run decompilation and deterministic analysis in one command."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from binary_agent.analysis.confirmation import build_evidence_pack_v3
from binary_agent.analysis.concolic import (
    CONCOLIC_RUN_SUMMARY,
    CONCOLIC_VERDICTS,
    infer_process_input_fact,
    resolve_memory_safety_target,
    run_concolic_evidence_dir,
)
from binary_agent.analysis.entrypoints import EntryPointDeriver
from binary_agent.analysis.hypothesis_generation import run_hypothesis_stage
from binary_agent.data.manifest import write_normalized_manifest
from binary_agent.discovery import (
    DEFAULT_SEMANTIC_SEED_CLASSES,
    discover_candidates,
    load_discovery_context,
    run_semantic_seed_stage,
    semantic_seed_candidates_from_artifacts,
    write_discovery_candidates,
)
from binary_agent.execution_envelope import discover_execution_envelope
from binary_agent.intake import run_intake
from binary_agent.pipeline import (
    ArtifactIndex,
    load_candidate_states,
    load_proof_results,
    write_candidate_states,
    write_bug_bounty_evidence_artifacts,
    write_proof_results,
    write_source_to_sink_trace_artifacts,
)
from binary_agent.proof import proof_metrics, proof_results_from_replay
from binary_agent.proof_routing import RouteExecutionContext, execute_route_orchestration
from binary_agent.promotion import (
    apply_replay_results,
    candidate_needs_exact_memory_operation,
    promote_for_replay,
    promote_proof_ready,
    promote_with_proof_results,
    write_promotion_artifacts,
)
from binary_agent.replay import (
    ExternalCommandReplayRepairProvider,
    build_replay_plan,
    import_concolic_replay_results,
    run_replay_plan,
)
from binary_agent.reporting import (
    build_lean_reports,
    report_vulnerability_type,
    write_lean_reports,
    write_vendor_evidence_bundles,
)
from binary_agent.scheduling import SCHEDULER_POLICIES, ProofBudget, schedule_proofs
from binary_agent.utils.env import load_dotenv_if_available
from binary_agent.utils.time import utc_timestamp


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DECOMP_SCRIPT = REPO_ROOT / "scripts" / "decompile.py"
DECOMPILATION_CACHE_FINGERPRINT = ".exporter_fingerprint"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Ghidra export plus deterministic stack-overflow analysis.")
    parser.add_argument("binary", type=Path, help="Path to the stripped binary, firmware rootfs directory, or extracted firmware tree to analyze.")
    parser.add_argument("--ghidra-dir", type=Path, default=None, help="Override Ghidra installation directory.")
    parser.add_argument("--output-root", type=Path, default=Path("runs"), help="Directory for combined outputs.")
    parser.add_argument("--cache-dir", type=Path, default=Path("cache/decomp"), help="Directory for cached decompilation artifacts.")
    parser.add_argument("--decompile-script", type=Path, default=DEFAULT_DECOMP_SCRIPT, help="Path to decompile helper script.")
    parser.add_argument("--skip", type=int, default=0, help="Skip the first N functions before analysis.")
    parser.add_argument("--sample", type=int, default=None, help="Limit analysis to N functions after skipping.")
    parser.add_argument("--operation-specs", type=Path, default=None, help="Override operation_specs.json path.")
    parser.add_argument("--analysis-cache-dir", type=Path, default=None, help="Directory for fact-v3 analysis cache files.")
    parser.add_argument(
        "--persist-debug-facts",
        action="store_true",
        help="Persist debug-only suppressed findings alongside public artifacts.",
    )
    parser.add_argument(
        "--stages",
        default="all",
        help="Comma-separated stages: all,intake,semantic_seed,discovery,refinement,proof,hypothesis,replay,report.",
    )
    parser.add_argument(
        "--replay-mode",
        choices=("auto", "native", "function_harness", "qemu_user", "qemu_system", "container_service", "off"),
        default="auto",
        help="Replay backend mode for proof-gated runs.",
    )
    parser.add_argument("--overwrite", action="store_true", help="Overwrite generated proof-gated artifacts.")
    parser.add_argument(
        "--discovery-backends",
        default="",
        help="Comma-separated discovery backends; omitted selects all registered backends.",
    )
    parser.add_argument(
        "--vulnerability-types",
        default="",
        help="Comma-separated terminal vulnerability types; omitted selects every registered type.",
    )
    parser.add_argument(
        "--process-input-json",
        type=Path,
        default=None,
        help="Optional schema-v2 concrete process-input configuration used by proof and replay.",
    )
    parser.add_argument(
        "--firmware-binary-regex",
        default="",
        help="For firmware/rootfs targets, analyze only executable ELF paths whose relative path or basename matches this regex.",
    )
    parser.add_argument(
        "--concolic-verdict-dir",
        type=Path,
        default=None,
        help="Import artifact-backed concolic verdicts as replay confirmations for matching candidates.",
    )
    parser.add_argument("--proof-backend", choices=("angr",), default="angr", help="Backend for the proof stage.")
    parser.add_argument(
        "--proof-target-candidate-id",
        default="",
        help="Run proof only for one candidate id.",
    )
    parser.add_argument(
        "--proof-symbolic-bytes",
        type=int,
        default=0,
        help="Exact symbolic byte budget for proof. Default derives from destination capacity in evidence packs.",
    )
    parser.add_argument(
        "--proof-max-symbolic-bytes",
        type=int,
        default=4096,
        help="Upper bound for evidence-derived proof symbolic bytes.",
    )
    parser.add_argument(
        "--proof-timeout-seconds",
        type=float,
        default=60.0,
        help="Per-candidate proof-stage timeout.",
    )
    parser.add_argument(
        "--proof-dynamic-max-steps",
        type=int,
        default=20000,
        help="Maximum Ghidra dynamic instructions to replay per proof attempt.",
    )
    parser.add_argument(
        "--proof-memory-limit-mb",
        type=int,
        default=8192,
        help="Hard address-space limit for each isolated proof worker; 0 disables the limit.",
    )
    parser.add_argument(
        "--proof-jobs",
        type=int,
        default=1,
        help="Maximum proof candidates to analyze concurrently.",
    )
    parser.add_argument(
        "--proof-scheduler",
        choices=tuple(sorted(SCHEDULER_POLICIES)),
        default="exhaustive",
        help="Select a deterministic proof-portfolio scheduling policy.",
    )
    parser.add_argument(
        "--proof-candidate-budget",
        type=int,
        default=0,
        help="Maximum candidates selected for expensive proof; 0 is unlimited.",
    )
    parser.add_argument(
        "--proof-wall-budget-seconds",
        type=float,
        default=0.0,
        help="Scheduler wall-time estimate budget across candidates; 0 is unlimited.",
    )
    parser.add_argument(
        "--proof-cpu-budget-seconds",
        type=float,
        default=0.0,
        help="Scheduler estimated CPU-time budget across candidates; 0 is unlimited.",
    )
    parser.add_argument(
        "--llm-hypothesis-provider-command",
        default="",
        help="Opt-in command that reads one evidence pack from stdin and emits hypothesis JSON. Use auto for the built-in OpenRouter provider.",
    )
    parser.add_argument(
        "--llm-semantic-seed-provider-command",
        default="",
        help="Opt-in command that reads semantic seed packs from stdin and emits seed JSON. Use auto for the built-in OpenRouter provider.",
    )
    parser.add_argument(
        "--semantic-seed-classes",
        default=",".join(DEFAULT_SEMANTIC_SEED_CLASSES),
        help="Comma-separated semantic seed classes to run.",
    )
    parser.add_argument(
        "--semantic-seed-max-clusters-per-class",
        type=int,
        default=12,
        help="Maximum deterministic feature clusters sent per class.",
    )
    parser.add_argument(
        "--semantic-seed-max-zoom-seeds",
        type=int,
        default=24,
        help="Maximum accepted clusters that receive targeted zoom packs.",
    )
    parser.add_argument(
        "--semantic-seed-max-seeds-per-function-class",
        type=int,
        default=2,
        help="Maximum accepted semantic seeds per function and vulnerability class.",
    )
    parser.add_argument(
        "--semantic-seed-provider-timeout-seconds",
        type=float,
        default=120.0,
        help="Timeout for each semantic seed provider invocation.",
    )
    parser.add_argument(
        "--llm-hypothesis-fixtures",
        type=Path,
        default=None,
        help="Deterministic fixture directory for hypothesis-stage CI/tests.",
    )
    parser.add_argument(
        "--llm-hypothesis-systems",
        default="L2,L3",
        help="Comma-separated hypothesis systems to run, default L2,L3.",
    )
    parser.add_argument(
        "--llm-hypothesis-provider-timeout-seconds",
        type=float,
        default=120.0,
        help="Timeout for each hypothesis provider invocation.",
    )
    parser.add_argument(
        "--hypothesis-policy",
        choices=("blocked-only", "always", "off"),
        default="blocked-only",
        help="When to call the hypothesis provider. Default only calls for candidates without a concrete replay plan.",
    )
    parser.add_argument(
        "--max-hypothesis-calls-per-run",
        type=int,
        default=32,
        help="Hard cap on live hypothesis provider calls for one run.",
    )
    parser.add_argument(
        "--max-hypothesis-calls-per-candidate",
        type=int,
        default=1,
        help="Hard cap on live hypothesis provider calls for one candidate.",
    )
    parser.add_argument(
        "--max-replay-requests-per-candidate",
        type=int,
        default=3,
        help="Maximum selected replay requests per candidate after LLM and deterministic planning.",
    )
    parser.add_argument(
        "--llm-repair-provider-command",
        default="",
        help="Opt-in command that reads failed replay summaries and emits repaired replay/environment JSON. Use auto for the built-in OpenRouter provider.",
    )
    parser.add_argument(
        "--llm-repair-max-attempts",
        type=int,
        default=2,
        help="Maximum provider repair attempts per failed replay request.",
    )
    parser.add_argument(
        "--llm-repair-provider-timeout-seconds",
        type=float,
        default=120.0,
        help="Timeout for each replay repair provider invocation.",
    )
    parser.add_argument(
        "--require-live-llm",
        action="store_true",
        help="Fail if enabled semantic seed or hypothesis stages do not use live model calls.",
    )
    return parser.parse_args()


def _binary_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as inp:
        for chunk in iter(lambda: inp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decompilation_cache_fingerprint(decompile_script: Path) -> str:
    digest = hashlib.sha256()
    paths = [
        Path(decompile_script),
        REPO_ROOT / "ghidra_scripts" / "enable_paramid.py",
        REPO_ROOT / "ghidra_scripts" / "export_functions.py",
        REPO_ROOT / "ghidra_scripts" / "raw_seed_functions.py",
    ]
    for path in paths:
        digest.update(str(path.name).encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _find_export_dir(root: Path) -> Path:
    candidates = sorted(root.glob("**/decompiled"))
    if not candidates:
        raise RuntimeError("Unable to locate decompiled output directory.")
    return candidates[-1]


def run_decompilation(
    binary_path: Path,
    args: argparse.Namespace,
    output_root: Path,
    *,
    run_dir: Path | None = None,
) -> Path:
    binary_hash = _binary_hash(binary_path)
    exporter_fingerprint = _decompilation_cache_fingerprint(args.decompile_script)
    cache_dir = args.cache_dir.resolve() if args.cache_dir else None
    cached_export_dir: Path | None = None

    if cache_dir:
        cache_entry = cache_dir / binary_path.name / binary_hash
        candidate = cache_entry / "decompiled"
        fingerprint_path = cache_entry / DECOMPILATION_CACHE_FINGERPRINT
        cached_fingerprint = fingerprint_path.read_text().strip() if fingerprint_path.exists() else ""
        if (candidate / "manifest_normalized.json").exists() and cached_fingerprint == exporter_fingerprint:
            print(f"[+] Reusing cached decompilation for hash {binary_hash}")
            cached_export_dir = candidate
        else:
            cache_entry.mkdir(parents=True, exist_ok=True)

    if cached_export_dir is not None:
        return cached_export_dir

    if run_dir is None:
        timestamp = utc_timestamp()
        run_dir = output_root / binary_path.name / timestamp
    decompile_args = [
        sys.executable,
        str(args.decompile_script),
        str(binary_path),
        "--output-dir",
        str(run_dir / "artifacts"),
    ]
    if args.ghidra_dir:
        decompile_args.extend(["--ghidra-dir", str(args.ghidra_dir)])

    print(f"[+] Running decompilation: {' '.join(decompile_args)}")
    result = subprocess.run(decompile_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if result.returncode != 0:
        print(result.stdout)
        raise RuntimeError(f"Decompilation failed with exit code {result.returncode}")
    print(result.stdout)

    export_dir = _find_export_dir(run_dir / "artifacts")
    write_normalized_manifest(export_dir)

    if cache_dir:
        cache_entry = cache_dir / binary_path.name / binary_hash
        cache_entry.mkdir(parents=True, exist_ok=True)
        cache_target = cache_entry / "decompiled"
        if cache_target.is_symlink():
            cache_target.unlink()
        elif cache_target.exists():
            shutil.rmtree(cache_target)
        shutil.copytree(export_dir, cache_target)
        (cache_entry / DECOMPILATION_CACHE_FINGERPRINT).write_text(exporter_fingerprint + "\n")
        export_dir = cache_target
        print(f"[+] Cached decompilation at {cache_target}")

    return export_dir


def main() -> None:
    load_dotenv_if_available()
    args = parse_args()
    binary_path = args.binary.resolve()
    if not binary_path.exists():
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    output_root = args.output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    if args.cache_dir:
        args.cache_dir.resolve().mkdir(parents=True, exist_ok=True)

    stages = _parse_stages(args.stages)
    if binary_path.is_dir():
        _run_proof_gated_firmware_toolchain(binary_path, args, output_root, stages)
        return
    _run_proof_gated_toolchain(binary_path, args, output_root, stages)


def _parse_stages(raw: str) -> set[str]:
    stages = {item.strip() for item in str(raw or "all").split(",") if item.strip()}
    if not stages or "all" in stages:
        return {"intake", "semantic_seed", "discovery", "refinement", "proof", "hypothesis", "replay", "report"}
    valid = {"intake", "semantic_seed", "discovery", "refinement", "proof", "hypothesis", "replay", "report"}
    unknown = stages - valid
    if unknown:
        raise ValueError(f"Unknown stage(s): {', '.join(sorted(unknown))}")
    return stages


def _run_proof_gated_toolchain(
    binary_path: Path,
    args: argparse.Namespace,
    output_root: Path,
    stages: set[str],
) -> None:
    run_dir = output_root / binary_path.name / utc_timestamp()
    run_dir.mkdir(parents=True, exist_ok=True)
    artifact_index = ArtifactIndex()
    process_input_override = _load_process_input_override(getattr(args, "process_input_json", None))
    export_dir = run_decompilation(binary_path, args, output_root, run_dir=run_dir)
    artifact_index.add(export_dir, kind="ghidra_export", stage="decompile", description="Ghidra decompiled export")

    intake_dir = run_dir / "intake"
    if "intake" in stages:
        intake_result = run_intake(binary_path, intake_dir, export_dir=export_dir, overwrite=True)
        for key, value in intake_result.to_dict().items():
            if key.endswith("_path"):
                artifact_index.add(value, kind=key.removesuffix("_path"), stage="intake")
        print(f"[+] Intake artifacts written to {intake_dir}")

    states = []
    proof_results = []
    events = []
    lift = []
    promotion_dir = run_dir / "promotion"
    semantic_seed_dir = run_dir / "semantic_seeds"
    if "semantic_seed" in stages:
        seed_result = run_semantic_seed_stage(
            export_dir,
            semantic_seed_dir,
            binary_path=binary_path,
            intake_dir=intake_dir if intake_dir.exists() else None,
            provider_command=_llm_provider_command(args.llm_semantic_seed_provider_command, "llm_semantic_seed_provider.py"),
            classes=_csv_items(args.semantic_seed_classes),
            max_clusters_per_class=args.semantic_seed_max_clusters_per_class,
            max_zoom_seeds=args.semantic_seed_max_zoom_seeds,
            max_seeds_per_function_class=args.semantic_seed_max_seeds_per_function_class,
            provider_timeout_seconds=args.semantic_seed_provider_timeout_seconds,
            cache_dir=args.cache_dir.resolve() if args.cache_dir else None,
        )
        _index_semantic_seed_artifacts(artifact_index, seed_result)
        _enforce_live_llm_if_required(args, seed_result.summary_path, "semantic_seed")
        states = semantic_seed_candidates_from_artifacts(semantic_seed_dir, binary_path=binary_path)
        states_path = promotion_dir / "candidate_states.json"
        if not ({"discovery", "refinement"} & stages):
            write_candidate_states(states, states_path)
        artifact_index.add(states_path, kind="candidate_states", stage="semantic_seed")
        print(
            "[+] Semantic seed stage "
            f"{'enabled' if seed_result.summary.get('enabled') else 'skipped'}: "
            f"accepted={seed_result.summary.get('accepted_count', 0)}, "
            f"rejected={seed_result.summary.get('rejected_count', 0)}"
        )

    if "discovery" in stages:
        context = load_discovery_context(export_dir, intake_dir=intake_dir if intake_dir.exists() else None)
        backend_names = _csv_items(args.discovery_backends) or None
        vulnerability_types = _csv_items(args.vulnerability_types) or None
        states = discover_candidates(
            context,
            backend_names=backend_names,
            vulnerability_types=vulnerability_types,
        )
        if semantic_seed_dir.exists():
            states = semantic_seed_candidates_from_artifacts(semantic_seed_dir, base_states=states, binary_path=binary_path)
        discovery_path = write_discovery_candidates(states, run_dir / "discovery")
        artifact_index.add(discovery_path, kind="candidates", stage="discovery")
        states_path = promotion_dir / "candidate_states.json"
        write_candidate_states(states, states_path)
        artifact_index.add(states_path, kind="candidate_states", stage="discovery")
        print(f"[+] Discovery emitted {len(states)} candidates")

    if "refinement" in stages:
        if not states:
            states = load_candidate_states(promotion_dir / "candidate_states.json")
        evidence_dir = run_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        index_entries = []
        entrypoint_derivers: dict[str, EntryPointDeriver] = {}
        refined_states = []
        for state in states:
            path = evidence_dir / f"{_safe_name(state.candidate_id)}.json"
            entrypoint_derivation = _entrypoint_derivation_for_state(
                state,
                fallback_export_dir=export_dir,
                deriver_cache=entrypoint_derivers,
                intake_facts=None,
            )
            state = _state_with_entrypoint_derivation(state, entrypoint_derivation)
            if process_input_override:
                state = _state_with_process_input_override(state, process_input_override)
            state, pack = _state_and_pack_with_process_input(
                state,
                decompiler_context={"export_dir": str(export_dir)},
                entrypoint_derivation=entrypoint_derivation,
            )
            state, pack = _state_and_pack_with_exact_memory_operation(
                state,
                pack,
                binary_path=binary_path,
                export_dir=export_dir,
                decompiler_context={"export_dir": str(export_dir)},
                entrypoint_derivation=entrypoint_derivation,
            )
            refined_states.append(state)
            path.write_text(
                json.dumps(
                    pack,
                    indent=2,
                    sort_keys=True,
                )
            )
            artifact_index.add(path, kind="evidence_pack_v3", stage="refinement", candidate_id=state.candidate_id)
            index_entries.append({"candidate_id": state.candidate_id, "path": path.name})
        states = refined_states
        evidence_index = evidence_dir / "index.json"
        evidence_index.write_text(json.dumps({"schema_version": 3, "evidence_packs": index_entries}, indent=2, sort_keys=True))
        artifact_index.add(evidence_index, kind="evidence_index", stage="refinement")
        states, proof_events, proof_lift = promote_proof_ready(states)
        events.extend(proof_events)
        lift.extend(proof_lift)
        artifacts = write_promotion_artifacts(states, events, lift, promotion_dir)
        for kind, path in artifacts.items():
            artifact_index.add(path, kind=kind, stage="refinement")
        print(f"[+] Refinement promoted {sum(1 for state in states if state.status == 'proof_ready')} proof-ready candidates")

    if "hypothesis" in stages:
        if not states:
            states = load_candidate_states(promotion_dir / "candidate_states.json")
        evidence_dir = run_dir / "evidence"
        hypothesis_dir = run_dir / "hypotheses"
        preliminary_plan = build_replay_plan(
            states,
            binary_path=binary_path,
            mode=args.replay_mode,
            evidence_dir=evidence_dir if evidence_dir.exists() else None,
            max_requests_per_candidate=args.max_replay_requests_per_candidate,
        )
        result = run_hypothesis_stage(
            evidence_dir,
            hypothesis_dir,
            provider_command=_llm_provider_command(args.llm_hypothesis_provider_command, "llm_hypothesis_provider.py"),
            fixtures_dir=args.llm_hypothesis_fixtures,
            systems=_csv_items(args.llm_hypothesis_systems),
            candidate_states=states,
            replay_plan=preliminary_plan,
            hypothesis_policy=args.hypothesis_policy,
            max_hypothesis_calls_per_run=args.max_hypothesis_calls_per_run,
            max_hypothesis_calls_per_candidate=args.max_hypothesis_calls_per_candidate,
            provider_timeout_seconds=args.llm_hypothesis_provider_timeout_seconds,
        )
        for path in [
            result.summary_path,
            result.lift_summary_path,
            result.accepted_index_path,
            result.rejected_index_path,
            *result.artifact_paths,
            *result.raw_paths,
        ]:
            artifact_index.add(path, kind=_hypothesis_artifact_kind(path, hypothesis_dir), stage="hypothesis")
        _enforce_live_llm_if_required(args, result.summary_path, "hypothesis")
        summary = _load_json(result.summary_path)
        status = "validated" if summary.get("enabled") else "skipped"
        print(f"[+] Hypothesis stage {status}: accepted={summary.get('accepted_count', 0)}, rejected={summary.get('rejected_count', 0)}")

    if "proof" in stages:
        if not states:
            states = load_candidate_states(promotion_dir / "candidate_states.json")
        proof_results = _run_route_specific_proof_stage(
            states,
            args=args,
            proof_dir=run_dir / "proof",
            evidence_dir=run_dir / "evidence",
            artifact_index=artifact_index,
            context_for_state=lambda state: _route_context(
                state,
                args=args,
                proof_dir=run_dir / "proof" / "routes",
                evidence_dir=run_dir / "evidence",
                binary_path=binary_path,
                export_dir=export_dir,
            ),
        )

    if "replay" in stages:
        if not states:
            states = load_candidate_states(promotion_dir / "candidate_states.json")
        replay_dir = run_dir / "replay"
        hypothesis_dir = run_dir / "hypotheses"
        evidence_dir = run_dir / "evidence"
        route_specific = (run_dir / "proof" / "route_attempts.json").is_file()
        concolic_verdict_dir = _replay_concolic_verdict_dir(args, run_dir / "proof")
        results = []
        if concolic_verdict_dir is not None and not route_specific:
            replay_eligible_ids = {state.candidate_id for state in states if state.status != "rejected"}
            results = import_concolic_replay_results(
                concolic_verdict_dir,
                replay_dir,
                candidate_ids=replay_eligible_ids,
                evidence_dir=evidence_dir if evidence_dir.exists() else None,
            )
            if results:
                request_refs = _request_artifact_refs_from_results(results)
                artifact_confirmed_ids = {
                    result.candidate_id
                    for result in results
                    if result.result == "confirmed" and result.mode == "ghidra_process"
                }
                states, replay_ready_events = promote_for_replay(
                    states,
                    request_artifacts=request_refs,
                    artifact_confirmed_candidate_ids=artifact_confirmed_ids,
                )
                events.extend(replay_ready_events)
            print(f"[+] Imported {len(results)} matching concolic replay confirmations")
        imported_results = list(results)
        needs_structural_semantic_replay = any(
            state.backend == "semantic_effect"
            and not any(
                result.candidate_id == state.candidate_id
                and isinstance(result.control_result.get("proof_observation"), Mapping)
                and result.control_result["proof_observation"].get("status") == "observed"
                for result in results
            )
            for state in states
        )
        if not route_specific and (not results or needs_structural_semantic_replay):
            plan = build_replay_plan(
                states,
                binary_path=binary_path,
                mode=args.replay_mode,
                hypothesis_artifacts_dir=hypothesis_dir if hypothesis_dir.exists() else None,
                evidence_dir=evidence_dir if evidence_dir.exists() else None,
                max_requests_per_candidate=args.max_replay_requests_per_candidate,
            )
            plan_path = plan.write(replay_dir / "replay_plan.json")
            artifact_index.add(plan_path, kind="replay_plan", stage="replay")
            requests = plan.requests
            request_refs = _request_artifact_refs(requests, replay_dir)
            states, replay_ready_events = promote_for_replay(states, request_artifacts=request_refs)
            events.extend(replay_ready_events)
            deterministic_results = run_replay_plan(
                plan,
                replay_dir,
                evidence_dir=evidence_dir if evidence_dir.exists() else None,
                repair_provider=_repair_provider(args),
                repair_max_attempts=args.llm_repair_max_attempts,
            )
            results = _merge_replay_evidence(imported_results, deterministic_results)
        for result in results:
            for path in result.artifacts:
                artifact_index.add(
                    path,
                    kind="replay_artifact",
                    stage="replay",
                    candidate_id=result.candidate_id,
                    metadata={"result": result.result},
                )
        _index_replay_sidecars(artifact_index, replay_dir)
        if results:
            states, replay_events, replay_lift = apply_replay_results(states, results)
            events.extend(replay_events)
            lift.extend(replay_lift)
        proof_results = (
            load_proof_results(run_dir / "proof" / "proof_results.json")
            if route_specific
            else proof_results_from_replay(states, results)
        )
        proof_results_path = write_proof_results(proof_results, run_dir / "proof" / "proof_results.json")
        proof_metrics_path = run_dir / "proof" / "metrics.json"
        proof_metrics_path.write_text(json.dumps(proof_metrics(proof_results), indent=2, sort_keys=True))
        artifact_index.add(proof_results_path, kind="proof_results_v2", stage="replay")
        artifact_index.add(proof_metrics_path, kind="proof_metrics_v2", stage="replay")
        states, proof_result_events = promote_with_proof_results(states, proof_results)
        events.extend(proof_result_events)
        states, source_trace_artifacts = write_source_to_sink_trace_artifacts(states, promotion_dir / "source_to_sink")
        for candidate_id, path in source_trace_artifacts.items():
            artifact_index.add(path, kind="source_to_sink_trace", stage="replay", candidate_id=candidate_id)
        artifacts = write_promotion_artifacts(states, events, lift, promotion_dir)
        for kind, path in artifacts.items():
            artifact_index.add(path, kind=kind, stage="replay")
        print(
            f"[+] Replay consumed {len(proof_results)} route-specific proof results"
            if route_specific
            else f"[+] Replay produced {len(results)} result artifacts"
        )

    if "report" in stages:
        if not states:
            states = load_candidate_states(promotion_dir / "candidate_states.json")
        proof_results_path = run_dir / "proof" / "proof_results.json"
        if not proof_results and proof_results_path.exists():
            proof_results = load_proof_results(proof_results_path)
        report_dir = run_dir / "report"
        states, source_trace_artifacts = write_source_to_sink_trace_artifacts(states, report_dir / "source_to_sink")
        for candidate_id, path in source_trace_artifacts.items():
            artifact_index.add(path, kind="source_to_sink_trace", stage="report", candidate_id=candidate_id)
        states, bug_bounty_evidence_artifacts = write_bug_bounty_evidence_artifacts(states, report_dir / "bug_bounty_evidence")
        for candidate_id, path in bug_bounty_evidence_artifacts.items():
            artifact_index.add(path, kind="bug_bounty_evidence", stage="report", candidate_id=candidate_id)
        reports = build_lean_reports(states)
        written = write_lean_reports(reports, report_dir)
        vendor_bundles = write_vendor_evidence_bundles(
            states,
            report_dir / "vendor_evidence",
            intake_dir=intake_dir if intake_dir.exists() else None,
        )
        report_artifacts = {
            candidate_id: str(path)
            for candidate_id, path in written.items()
            if candidate_id not in {"json", "readme"}
        }
        for bundle in vendor_bundles:
            report_artifacts.setdefault(bundle.candidate_id, str(bundle.report_path))
        states, report_events = promote_with_proof_results(
            states,
            proof_results,
            report_artifacts=report_artifacts,
        )
        events.extend(report_events)
        artifacts = write_promotion_artifacts(states, events, lift, promotion_dir)
        for kind, path in {**written, **artifacts}.items():
            artifact_index.add(path, kind=str(kind), stage="report")
        for bundle in vendor_bundles:
            artifact_index.add(bundle.manifest_path, kind="vendor_evidence_manifest", stage="report", candidate_id=bundle.candidate_id)
            artifact_index.add(bundle.report_path, kind="vendor_report", stage="report", candidate_id=bundle.candidate_id)
        print(f"[+] Reports written to {report_dir} ({len(reports)} replay-backed issues)")

    artifact_index.write(run_dir / "artifact_index.json")
    print(f"[+] Proof-gated run directory: {run_dir}")


def _merge_replay_evidence(imported: Sequence[Any], deterministic: Sequence[Any]) -> list[Any]:
    """Keep exact trace artifacts while preferring structural process results."""

    by_id = {item.candidate_id: item for item in imported}
    for result in deterministic:
        previous = by_id.get(result.candidate_id)
        if previous is None:
            by_id[result.candidate_id] = result
            continue
        by_id[result.candidate_id] = replace(
            result,
            artifacts=list(
                dict.fromkeys([*previous.artifacts, *result.artifacts])
            ),
            artifact_refs=list(
                dict.fromkeys(
                    [
                        *[json.dumps(item, sort_keys=True) for item in previous.artifact_refs],
                        *[json.dumps(item, sort_keys=True) for item in result.artifact_refs],
                    ]
                )
            ),
        )
    normalized = []
    for result in by_id.values():
        if result.artifact_refs and isinstance(result.artifact_refs[0], str):
            result = replace(
                result,
                artifact_refs=[json.loads(item) for item in result.artifact_refs],
            )
        normalized.append(result)
    return normalized


def _run_proof_gated_firmware_toolchain(
    target_path: Path,
    args: argparse.Namespace,
    output_root: Path,
    stages: set[str],
) -> None:
    run_dir = output_root / target_path.name / utc_timestamp()
    run_dir.mkdir(parents=True, exist_ok=True)
    artifact_index = ArtifactIndex()
    process_input_override = _load_process_input_override(getattr(args, "process_input_json", None))

    intake_dir = run_dir / "intake"
    intake_result = run_intake(target_path, intake_dir, overwrite=True)
    for key, value in intake_result.to_dict().items():
        if key.endswith("_path"):
            artifact_index.add(value, kind=key.removesuffix("_path"), stage="intake")
    intake_facts = _load_intake_facts(intake_dir)
    binary_rows = _select_firmware_binary_rows(intake_facts, args.firmware_binary_regex)
    if not binary_rows:
        raise RuntimeError("Firmware intake did not find any matching executable ELF binaries to analyze.")
    print(f"[+] Firmware intake selected {len(binary_rows)} executable ELF binaries")

    backend_names = _csv_items(args.discovery_backends) or None
    vulnerability_types = _csv_items(args.vulnerability_types) or None
    states = []
    proof_results = []
    events = []
    lift = []
    binary_summaries: list[dict[str, Any]] = []
    promotion_dir = run_dir / "promotion"

    if "semantic_seed" in stages or "discovery" in stages:
        for row in binary_rows:
            binary_file = Path(str(row["path"]))
            binary_key = _firmware_binary_key(row)
            binary_run_dir = run_dir / "binaries" / binary_key
            export_dir = run_decompilation(binary_file, args, output_root, run_dir=binary_run_dir)
            artifact_index.add(
                export_dir,
                kind="ghidra_export",
                stage="decompile",
                description=f"Ghidra decompiled export for {row.get('relative_path') or binary_file.name}",
                metadata={"binary": row.get("relative_path") or binary_file.name},
            )
            semantic_seed_dir = binary_run_dir / "semantic_seeds"
            binary_states = []
            if "semantic_seed" in stages:
                seed_result = run_semantic_seed_stage(
                    export_dir,
                    semantic_seed_dir,
                    binary_path=binary_file,
                    intake_dir=intake_dir,
                    provider_command=_llm_provider_command(args.llm_semantic_seed_provider_command, "llm_semantic_seed_provider.py"),
                    classes=_csv_items(args.semantic_seed_classes),
                    max_clusters_per_class=args.semantic_seed_max_clusters_per_class,
                    max_zoom_seeds=args.semantic_seed_max_zoom_seeds,
                    max_seeds_per_function_class=args.semantic_seed_max_seeds_per_function_class,
                    provider_timeout_seconds=args.semantic_seed_provider_timeout_seconds,
                    cache_dir=args.cache_dir.resolve() if args.cache_dir else None,
                )
                _index_semantic_seed_artifacts(artifact_index, seed_result, metadata={"binary": row.get("relative_path", "")})
                _enforce_live_llm_if_required(args, seed_result.summary_path, "semantic_seed")
                binary_states = semantic_seed_candidates_from_artifacts(semantic_seed_dir, binary_path=binary_file)
            if "discovery" in stages:
                context = load_discovery_context(export_dir, intake_dir=intake_dir)
                discovered = discover_candidates(
                    context,
                    backend_names=backend_names,
                    vulnerability_types=vulnerability_types,
                )
                binary_states = (
                    semantic_seed_candidates_from_artifacts(semantic_seed_dir, base_states=discovered, binary_path=binary_file)
                    if semantic_seed_dir.exists()
                    else discovered
                )
                discovery_path = write_discovery_candidates(binary_states, binary_run_dir / "discovery")
                artifact_index.add(discovery_path, kind="candidates", stage="discovery", metadata={"binary": row.get("relative_path", "")})
            binary_states = [
                _enrich_firmware_state(state, row, target_path, intake_facts, export_dir=export_dir)
                for state in binary_states
            ]
            states.extend(binary_states)
            binary_summaries.append(
                {
                    "binary": row.get("relative_path") or binary_file.name,
                    "path": str(binary_file),
                    "export_dir": str(export_dir),
                    "candidate_count": len(binary_states),
                }
            )
            print(f"[+] {row.get('relative_path') or binary_file.name}: {len(binary_states)} candidates")
        if "discovery" in stages:
            discovery_path = write_discovery_candidates(states, run_dir / "discovery")
            artifact_index.add(discovery_path, kind="candidates", stage="discovery")
            states_path = write_candidate_states(states, promotion_dir / "candidate_states.json")
            artifact_index.add(states_path, kind="candidate_states", stage="discovery")
        elif "semantic_seed" in stages:
            states_path = write_candidate_states(states, promotion_dir / "candidate_states.json")
            artifact_index.add(states_path, kind="candidate_states", stage="semantic_seed")

    if "refinement" in stages:
        if not states:
            states = load_candidate_states(promotion_dir / "candidate_states.json")
        evidence_dir = run_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        index_entries = []
        entrypoint_derivers: dict[str, EntryPointDeriver] = {}
        refined_states = []
        for state in states:
            path = evidence_dir / f"{_safe_name(state.candidate_id)}.json"
            entrypoint_derivation = _entrypoint_derivation_for_state(
                state,
                fallback_export_dir=None,
                deriver_cache=entrypoint_derivers,
                intake_facts=intake_facts,
            )
            state = _state_with_entrypoint_derivation(state, entrypoint_derivation)
            if process_input_override:
                state = _state_with_process_input_override(state, process_input_override)
            export_dir_for_state = _state_export_dir(state, fallback_export_dir=None)
            state_binary = Path(str(state.target.get("path") or ""))
            state, pack = _state_and_pack_with_process_input(
                state,
                decompiler_context={"export_dir": str(export_dir_for_state)} if export_dir_for_state else None,
                intake_facts=_scoped_intake_facts_for_state(state, intake_facts),
                entrypoint_derivation=entrypoint_derivation,
            )
            state, pack = _state_and_pack_with_exact_memory_operation(
                state,
                pack,
                binary_path=state_binary,
                export_dir=export_dir_for_state,
                decompiler_context={"export_dir": str(export_dir_for_state)} if export_dir_for_state else None,
                intake_facts=_scoped_intake_facts_for_state(state, intake_facts),
                entrypoint_derivation=entrypoint_derivation,
            )
            refined_states.append(state)
            path.write_text(
                json.dumps(
                    pack,
                    indent=2,
                    sort_keys=True,
                )
            )
            artifact_index.add(path, kind="evidence_pack_v3", stage="refinement", candidate_id=state.candidate_id)
            index_entries.append({"candidate_id": state.candidate_id, "path": path.name})
        states = refined_states
        evidence_index = evidence_dir / "index.json"
        evidence_index.write_text(json.dumps({"schema_version": 3, "evidence_packs": index_entries}, indent=2, sort_keys=True))
        artifact_index.add(evidence_index, kind="evidence_index", stage="refinement")
        states, proof_events, proof_lift = promote_proof_ready(states)
        events.extend(proof_events)
        lift.extend(proof_lift)
        artifacts = write_promotion_artifacts(states, events, lift, promotion_dir)
        for kind, path in artifacts.items():
            artifact_index.add(path, kind=kind, stage="refinement")
        print(f"[+] Firmware refinement promoted {sum(1 for state in states if state.status == 'proof_ready')} proof-ready candidates")

    if "hypothesis" in stages:
        if not states:
            states = load_candidate_states(promotion_dir / "candidate_states.json")
        evidence_dir = run_dir / "evidence"
        hypothesis_dir = run_dir / "hypotheses"
        preliminary_plan = build_replay_plan(
            states,
            mode=args.replay_mode,
            evidence_dir=evidence_dir if evidence_dir.exists() else None,
            max_requests_per_candidate=args.max_replay_requests_per_candidate,
        )
        result = run_hypothesis_stage(
            evidence_dir,
            hypothesis_dir,
            provider_command=_llm_provider_command(args.llm_hypothesis_provider_command, "llm_hypothesis_provider.py"),
            fixtures_dir=args.llm_hypothesis_fixtures,
            systems=_csv_items(args.llm_hypothesis_systems),
            candidate_states=states,
            replay_plan=preliminary_plan,
            hypothesis_policy=args.hypothesis_policy,
            max_hypothesis_calls_per_run=args.max_hypothesis_calls_per_run,
            max_hypothesis_calls_per_candidate=args.max_hypothesis_calls_per_candidate,
            provider_timeout_seconds=args.llm_hypothesis_provider_timeout_seconds,
        )
        for path in [
            result.summary_path,
            result.lift_summary_path,
            result.accepted_index_path,
            result.rejected_index_path,
            *result.artifact_paths,
            *result.raw_paths,
        ]:
            artifact_index.add(path, kind=_hypothesis_artifact_kind(path, hypothesis_dir), stage="hypothesis")
        _enforce_live_llm_if_required(args, result.summary_path, "hypothesis")
        summary = _load_json(result.summary_path)
        status = "validated" if summary.get("enabled") else "skipped"
        print(f"[+] Firmware hypothesis stage {status}: accepted={summary.get('accepted_count', 0)}, rejected={summary.get('rejected_count', 0)}")

    if "proof" in stages:
        if not states:
            states = load_candidate_states(promotion_dir / "candidate_states.json")
        evidence_dir = run_dir / "evidence"
        proof_dir = run_dir / "proof"
        proof_results = _run_route_specific_proof_stage(
            states,
            args=args,
            proof_dir=proof_dir,
            evidence_dir=evidence_dir,
            artifact_index=artifact_index,
            context_for_state=lambda state: _route_context(
                state,
                args=args,
                proof_dir=proof_dir / "routes",
                evidence_dir=evidence_dir,
                binary_path=Path(str(state.target.get("path") or "")),
                export_dir=_state_export_dir(state, fallback_export_dir=None),
            ),
        )
        print(f"[+] Firmware route proof stage ran {len(proof_results)} normalized candidate results")

    replay_results = []
    if "replay" in stages:
        if not states:
            states = load_candidate_states(promotion_dir / "candidate_states.json")
        replay_dir = run_dir / "replay"
        evidence_dir = run_dir / "evidence"
        route_specific = (run_dir / "proof" / "route_attempts.json").is_file()
        concolic_verdict_dir = _replay_concolic_verdict_dir(args, run_dir / "proof")
        if concolic_verdict_dir is not None and not route_specific:
            replay_eligible_ids = {state.candidate_id for state in states if state.status != "rejected"}
            replay_results = import_concolic_replay_results(
                concolic_verdict_dir,
                replay_dir,
                candidate_ids=replay_eligible_ids,
                evidence_dir=evidence_dir if evidence_dir.exists() else None,
            )
            if replay_results:
                request_refs = _request_artifact_refs_from_results(replay_results)
                artifact_confirmed_ids = {
                    result.candidate_id
                    for result in replay_results
                    if result.result == "confirmed" and result.mode == "ghidra_process"
                }
                states, replay_ready_events = promote_for_replay(
                    states,
                    request_artifacts=request_refs,
                    artifact_confirmed_candidate_ids=artifact_confirmed_ids,
                )
                events.extend(replay_ready_events)
            print(f"[+] Imported {len(replay_results)} matching concolic replay confirmations")
        if not replay_results and not route_specific:
            hypothesis_dir = run_dir / "hypotheses"
            plan = build_replay_plan(
                states,
                mode=args.replay_mode,
                hypothesis_artifacts_dir=hypothesis_dir if hypothesis_dir.exists() else None,
                evidence_dir=evidence_dir if evidence_dir.exists() else None,
                max_requests_per_candidate=args.max_replay_requests_per_candidate,
            )
            plan_path = plan.write(replay_dir / "replay_plan.json")
            artifact_index.add(plan_path, kind="replay_plan", stage="replay")
            requests = plan.requests
            request_refs = _request_artifact_refs(requests, replay_dir)
            states, replay_ready_events = promote_for_replay(states, request_artifacts=request_refs)
            events.extend(replay_ready_events)
            replay_results = run_replay_plan(
                plan,
                replay_dir,
                evidence_dir=evidence_dir if evidence_dir.exists() else None,
                repair_provider=_repair_provider(args),
                repair_max_attempts=args.llm_repair_max_attempts,
            )
        for result in replay_results:
            for path in result.artifacts:
                artifact_index.add(
                    path,
                    kind="replay_artifact",
                    stage="replay",
                    candidate_id=result.candidate_id,
                    metadata={"result": result.result, "mode": result.mode},
                )
        _index_replay_sidecars(artifact_index, replay_dir)
        if replay_results:
            states, replay_events, replay_lift = apply_replay_results(states, replay_results)
            events.extend(replay_events)
            lift.extend(replay_lift)
        proof_results = (
            load_proof_results(run_dir / "proof" / "proof_results.json")
            if route_specific
            else proof_results_from_replay(states, replay_results)
        )
        proof_results_path = write_proof_results(proof_results, run_dir / "proof" / "proof_results.json")
        proof_metrics_path = run_dir / "proof" / "metrics.json"
        proof_metrics_path.write_text(json.dumps(proof_metrics(proof_results), indent=2, sort_keys=True))
        artifact_index.add(proof_results_path, kind="proof_results_v2", stage="replay")
        artifact_index.add(proof_metrics_path, kind="proof_metrics_v2", stage="replay")
        states, proof_result_events = promote_with_proof_results(states, proof_results)
        events.extend(proof_result_events)
        states, source_trace_artifacts = write_source_to_sink_trace_artifacts(states, promotion_dir / "source_to_sink")
        for candidate_id, path in source_trace_artifacts.items():
            artifact_index.add(path, kind="source_to_sink_trace", stage="replay", candidate_id=candidate_id)
        artifacts = write_promotion_artifacts(states, events, lift, promotion_dir)
        for kind, path in artifacts.items():
            artifact_index.add(path, kind=kind, stage="replay")

    vendor_bundles = []
    if "report" in stages:
        if not states:
            states = load_candidate_states(promotion_dir / "candidate_states.json")
        proof_results_path = run_dir / "proof" / "proof_results.json"
        if not proof_results and proof_results_path.exists():
            proof_results = load_proof_results(proof_results_path)
        report_dir = run_dir / "report"
        states, source_trace_artifacts = write_source_to_sink_trace_artifacts(states, report_dir / "source_to_sink")
        for candidate_id, path in source_trace_artifacts.items():
            artifact_index.add(path, kind="source_to_sink_trace", stage="report", candidate_id=candidate_id)
        states, bug_bounty_evidence_artifacts = write_bug_bounty_evidence_artifacts(states, report_dir / "bug_bounty_evidence")
        for candidate_id, path in bug_bounty_evidence_artifacts.items():
            artifact_index.add(path, kind="bug_bounty_evidence", stage="report", candidate_id=candidate_id)
        reports = build_lean_reports(states)
        written = write_lean_reports(reports, report_dir)
        vendor_bundles = write_vendor_evidence_bundles(
            states,
            report_dir / "vendor_evidence",
            intake_dir=intake_dir,
        )
        report_artifacts = {
            candidate_id: str(path)
            for candidate_id, path in written.items()
            if candidate_id not in {"json", "readme"}
        }
        for bundle in vendor_bundles:
            report_artifacts.setdefault(bundle.candidate_id, str(bundle.report_path))
        states, report_events = promote_with_proof_results(
            states,
            proof_results,
            report_artifacts=report_artifacts,
        )
        events.extend(report_events)
        artifacts = write_promotion_artifacts(states, events, lift, promotion_dir)
        for kind, path in {**written, **artifacts}.items():
            artifact_index.add(path, kind=str(kind), stage="report")
        for bundle in vendor_bundles:
            artifact_index.add(bundle.manifest_path, kind="vendor_evidence_manifest", stage="report", candidate_id=bundle.candidate_id)
            artifact_index.add(bundle.report_path, kind="vendor_report", stage="report", candidate_id=bundle.candidate_id)
            artifact_index.add(bundle.reproducer_path, kind="vendor_reproducer", stage="report", candidate_id=bundle.candidate_id)
        summary_paths = _write_firmware_run_summary(
            run_dir,
            target_path,
            states,
            binary_summaries,
            len(replay_results),
            len(reports),
            len(vendor_bundles),
        )
        for kind, path in summary_paths.items():
            artifact_index.add(path, kind=kind, stage="report")
        print(f"[+] Firmware reports written to {report_dir} ({len(reports)} replay-backed issues, {len(vendor_bundles)} vendor bundles)")

    artifact_index.write(run_dir / "artifact_index.json")
    print(f"[+] Proof-gated firmware run directory: {run_dir}")


def _csv_items(raw: str | Sequence[str]) -> list[str]:
    if isinstance(raw, str):
        return [item.strip() for item in raw.split(",") if item.strip()]
    return [str(item).strip() for item in raw if str(item).strip()]


def _repair_provider(args: argparse.Namespace):
    command = _llm_provider_command(getattr(args, "llm_repair_provider_command", ""), "llm_replay_repair_provider.py")
    if not command:
        return None
    return ExternalCommandReplayRepairProvider.from_command_string(
        command,
        timeout_seconds=float(getattr(args, "llm_repair_provider_timeout_seconds", 120.0) or 120.0),
    )


def _llm_provider_command(raw: str | Sequence[str], script_name: str) -> str:
    if not isinstance(raw, str):
        return shlex.join([str(item) for item in raw]) if raw else ""
    command = raw.strip()
    if command.lower() != "auto":
        return command
    script = Path(__file__).resolve().parents[3] / "scripts" / script_name
    return shlex.join([sys.executable, str(script), "--yes-live"])


def _run_concolic_proof_stage(
    *,
    binary_path: Path,
    export_dir: Path | None,
    evidence_dir: Path,
    proof_dir: Path,
    args: argparse.Namespace,
    artifact_index: ArtifactIndex,
    target_candidate_id: str = "",
    target_candidate_ids: Sequence[str] | None = None,
) -> None:
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.exists():
        raise RuntimeError("Proof stage requires refinement evidence; include the refinement stage first.")
    proof_dir.mkdir(parents=True, exist_ok=True)
    proof_target_candidate_id = target_candidate_id or str(getattr(args, "proof_target_candidate_id", "") or "")
    proof_target_candidate_ids = None if proof_target_candidate_id else (
        tuple(target_candidate_ids) if target_candidate_ids is not None else None
    )
    symbolic_bytes = int(getattr(args, "proof_symbolic_bytes", 0) or 0)
    if symbolic_bytes <= 0:
        symbolic_bytes = _derive_proof_symbolic_bytes(
            evidence_dir,
            max_bytes=int(getattr(args, "proof_max_symbolic_bytes", 4096) or 4096),
            target_candidate_id=proof_target_candidate_id,
            target_candidate_ids=proof_target_candidate_ids,
        )
    result = run_concolic_evidence_dir(
        evidence_dir,
        binary_path=binary_path,
        output_dir=proof_dir,
        export_dir=export_dir,
        backend=str(getattr(args, "proof_backend", "angr") or "angr"),
        symbolic_bytes=symbolic_bytes,
        timeout_seconds=float(getattr(args, "proof_timeout_seconds", 60.0) or 60.0),
        ghidra_dynamic_proof=True,
        ghidra_dynamic_max_steps=int(getattr(args, "proof_dynamic_max_steps", 20000) or 20000),
        ghidra_dir=_effective_ghidra_dir(args),
        target_candidate_id=proof_target_candidate_id,
        target_candidate_ids=proof_target_candidate_ids,
        overwrite=bool(getattr(args, "overwrite", False)),
        continue_on_error=True,
        jobs=int(getattr(args, "proof_jobs", 1) or 1),
        isolate_candidates=True,
        memory_limit_mb=int(getattr(args, "proof_memory_limit_mb", 8192) or 0),
    )
    _index_concolic_proof_artifacts(artifact_index, Path(result.output_dir))
    counts = {verdict: result.verdict_counts.get(verdict, 0) for verdict in sorted(CONCOLIC_VERDICTS)}
    summary = ", ".join(f"{verdict}={count}" for verdict, count in counts.items() if count)
    print(
        f"[+] Proof stage wrote {result.written_count} concolic verdicts to {result.output_dir} "
        f"({summary or 'no_verdicts'}, attempted={result.attempted_count}/{result.eligible_count}, "
        f"errors={result.error_count}, skipped={result.skipped_count}, "
        f"symbolic_bytes={symbolic_bytes})"
    )


def _route_context(
    state: Any,
    *,
    args: argparse.Namespace,
    proof_dir: Path,
    evidence_dir: Path,
    binary_path: Path,
    export_dir: Path | None,
) -> RouteExecutionContext:
    symbolic_bytes = int(getattr(args, "proof_symbolic_bytes", 0) or 0)
    if symbolic_bytes <= 0:
        symbolic_bytes = _derive_proof_symbolic_bytes(
            evidence_dir,
            max_bytes=int(getattr(args, "proof_max_symbolic_bytes", 4096) or 4096),
            target_candidate_id=state.candidate_id,
        )
    target = state.target if isinstance(getattr(state, "target", None), Mapping) else {}
    rootfs_raw = target.get("firmware_target") or target.get("rootfs_path") or ""
    rootfs_path = Path(str(rootfs_raw)).expanduser().resolve() if rootfs_raw else None
    if rootfs_path is not None and not rootfs_path.is_dir():
        rootfs_path = None
    envelope = discover_execution_envelope(
        Path(binary_path),
        rootfs_path=rootfs_path,
        cache_dir=Path(proof_dir).parent / "execution_envelopes" / "cache",
    )
    return RouteExecutionContext(
        binary_path=Path(binary_path),
        export_dir=Path(export_dir) if export_dir is not None else None,
        evidence_dir=Path(evidence_dir),
        output_dir=Path(proof_dir),
        timeout_seconds=float(getattr(args, "proof_timeout_seconds", 60.0) or 60.0),
        ghidra_dir=_effective_ghidra_dir(args),
        memory_limit_mb=int(getattr(args, "proof_memory_limit_mb", 8192) or 0),
        symbolic_bytes=max(1, symbolic_bytes),
        ghidra_dynamic_max_steps=int(getattr(args, "proof_dynamic_max_steps", 20000) or 20000),
        execution_envelope=envelope,
        rootfs_path=Path(envelope.rootfs_path) if envelope.rootfs_path else None,
    )


def _run_route_specific_proof_stage(
    states: Sequence[Any],
    *,
    args: argparse.Namespace,
    proof_dir: Path,
    evidence_dir: Path,
    artifact_index: ArtifactIndex,
    context_for_state: Callable[[Any], RouteExecutionContext],
) -> list[Any]:
    requested = str(getattr(args, "proof_target_candidate_id", "") or "")
    eligible = [
        state
        for state in states
        if state.status == "proof_ready" and (not requested or state.candidate_id == requested)
    ]
    budget = ProofBudget(
        max_candidates=max(0, int(getattr(args, "proof_candidate_budget", 0) or 0)),
        max_wall_seconds=max(0.0, float(getattr(args, "proof_wall_budget_seconds", 0.0) or 0.0)),
        max_estimated_cpu_seconds=max(0.0, float(getattr(args, "proof_cpu_budget_seconds", 0.0) or 0.0)),
    )
    orchestration = execute_route_orchestration(
        eligible,
        context_for_state=context_for_state,
        budget=budget,
        policy=str(getattr(args, "proof_scheduler", "exhaustive") or "exhaustive"),
    )
    proof_dir.mkdir(parents=True, exist_ok=True)
    route_path = proof_dir / "route_attempts.json"
    route_path.write_text(json.dumps(orchestration.to_dict(), indent=2, sort_keys=True))
    attempts = [
        {
            "rank": index,
            "candidate_id": result.candidate_id,
            "route": result.route,
            "variant_id": result.variant_id,
            "execution_family": result.execution_family,
            "status": result.status,
            "duration_seconds": round(result.duration_seconds, 6),
            "cpu_seconds": round(result.cpu_seconds, 6),
        }
        for index, result in enumerate(orchestration.attempts, start=1)
    ]
    schedule_path = proof_dir / "schedule.json"
    schedule_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "artifact_kind": "executed_proof_route_schedule",
                "policy": orchestration.policy,
                "budget": {
                    "max_candidates": budget.max_candidates,
                    "max_wall_seconds": budget.max_wall_seconds,
                    "max_estimated_cpu_seconds": budget.max_estimated_cpu_seconds,
                },
                "attempts": attempts,
                "stop_reason": orchestration.stop_reason,
                "unattempted_candidate_ids": list(orchestration.unattempted_candidate_ids),
            },
            indent=2,
            sort_keys=True,
        )
    )
    proof_results = _best_route_proof_results(orchestration.attempts)
    proof_results_path = write_proof_results(proof_results, proof_dir / "proof_results.json")
    metrics_path = proof_dir / "scheduler_metrics.json"
    metrics_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "artifact_kind": "proof_scheduler_metrics",
                "policy": orchestration.policy,
                "eligible_candidates": len(eligible),
                "selected_candidates": len(orchestration.attempts),
                "actual_executed_attempts": len(orchestration.attempts),
                "actual_executed_candidates": len({item.candidate_id for item in orchestration.attempts}),
                "deferred_candidates": len(orchestration.unattempted_candidate_ids),
                "actual_wall_seconds": round(orchestration.wall_seconds, 6),
                "actual_cpu_seconds": round(orchestration.cpu_seconds, 6),
                "budget_stop_reason": orchestration.stop_reason,
                "execution_adapter": "route_specific_registry",
                "route_counts": _count_values(item.route for item in orchestration.attempts),
                "execution_family_counts": _count_values(item.execution_family for item in orchestration.attempts),
                "outcome_counts": _count_values(item.status for item in orchestration.attempts),
            },
            indent=2,
            sort_keys=True,
        )
    )
    for path, kind in (
        (route_path, "proof_route_attempts"),
        (schedule_path, "proof_schedule"),
        (proof_results_path, "proof_results_v2"),
        (metrics_path, "proof_scheduler_metrics"),
    ):
        artifact_index.add(path, kind=kind, stage="proof")
    for result in orchestration.attempts:
        for raw_path in result.artifact_paths:
            path = Path(raw_path)
            if path.exists():
                artifact_index.add(
                    path,
                    kind="proof_route_artifact",
                    stage="proof",
                    candidate_id=result.candidate_id,
                    metadata={"route": result.route, "execution_family": result.execution_family},
                )
    print(
        f"[+] Route proof scheduler executed {len(orchestration.attempts)} attempts for "
        f"{len({item.candidate_id for item in orchestration.attempts})}/{len(eligible)} candidates "
        f"(policy={orchestration.policy}, stop={orchestration.stop_reason})"
    )
    return proof_results


def _best_route_proof_results(attempts: Sequence[Any]) -> list[Any]:
    by_id: dict[str, Any] = {}
    rank = {"proven": 4, "refuted": 3, "inconclusive": 2, "unsupported": 1}
    for attempt in attempts:
        proof = attempt.proof_result
        previous = by_id.get(proof.candidate_id)
        if previous is None or rank.get(proof.status, 0) >= rank.get(previous.status, 0):
            by_id[proof.candidate_id] = proof
    return [by_id[candidate_id] for candidate_id in sorted(by_id)]


def _write_proof_schedule(
    states: Sequence[Any],
    args: argparse.Namespace,
    proof_dir: Path,
    artifact_index: ArtifactIndex,
) -> list[str]:
    eligible = [state for state in states if state.status == "proof_ready"]
    requested = str(getattr(args, "proof_target_candidate_id", "") or "")
    if requested:
        eligible = [state for state in eligible if state.candidate_id == requested]
    budget = ProofBudget(
        max_candidates=max(0, int(getattr(args, "proof_candidate_budget", 0) or 0)),
        max_wall_seconds=max(0.0, float(getattr(args, "proof_wall_budget_seconds", 0.0) or 0.0)),
        max_estimated_cpu_seconds=max(0.0, float(getattr(args, "proof_cpu_budget_seconds", 0.0) or 0.0)),
    )
    schedule = schedule_proofs(
        eligible,
        plans=None,
        budget=budget,
        policy=str(getattr(args, "proof_scheduler", "exhaustive") or "exhaustive"),
    )
    proof_dir.mkdir(parents=True, exist_ok=True)
    path = proof_dir / "schedule.json"
    path.write_text(json.dumps(schedule.to_dict(), indent=2, sort_keys=True))
    metrics_path = proof_dir / "scheduler_metrics.json"
    metrics_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_kind": "proof_scheduler_metrics",
                "policy": schedule.policy,
                "eligible_candidates": len(eligible),
                "selected_candidates": len(schedule.attempts),
                "deferred_candidates": len(schedule.deferred),
                "estimated_cpu_seconds": round(schedule.estimated_cpu_seconds, 6),
                "execution_adapter": "existing_hybrid_proof_pipeline",
                "route_counts": _count_values(item.route for item in schedule.attempts),
                "deferred_reason_counts": _count_values(item.reason for item in schedule.deferred),
                "actual_executed_candidates": 0,
                "actual_wall_seconds": 0.0,
                "actual_cpu_seconds": 0.0,
                "budget_stop_reason": "not_recorded",
            },
            indent=2,
            sort_keys=True,
        )
    )
    artifact_index.add(path, kind="proof_schedule", stage="proof")
    artifact_index.add(metrics_path, kind="proof_scheduler_metrics", stage="proof")
    print(
        f"[+] Proof scheduler selected {len(schedule.attempts)}/{len(eligible)} candidates "
        f"(policy={schedule.policy}, estimated_cpu_seconds={schedule.estimated_cpu_seconds:.2f})"
    )
    return [item.candidate_id for item in schedule.attempts]


def _record_proof_schedule_execution(
    metrics_path: Path,
    *,
    executed_candidates: int,
    actual_wall_seconds: float,
    actual_cpu_seconds: float,
    budget_stop_reason: str,
) -> None:
    payload = _load_json(metrics_path)
    payload.update(
        {
            "actual_executed_candidates": executed_candidates,
            "actual_wall_seconds": round(max(0.0, actual_wall_seconds), 6),
            "actual_cpu_seconds": round(max(0.0, actual_cpu_seconds), 6),
            "budget_stop_reason": budget_stop_reason or "completed_schedule",
            "scheduled_not_executed": max(
                0,
                int(payload.get("selected_candidates") or 0) - executed_candidates,
            ),
        }
    )
    metrics_path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def _count_values(values: Sequence[str] | Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _replay_concolic_verdict_dir(args: argparse.Namespace, proof_dir: Path) -> Path | None:
    if args.concolic_verdict_dir:
        return args.concolic_verdict_dir.resolve()
    proof_dir = Path(proof_dir)
    if proof_dir.exists():
        return proof_dir
    return None


def _effective_ghidra_dir(args: argparse.Namespace) -> Path | None:
    if args.ghidra_dir:
        return Path(args.ghidra_dir)
    raw = os.getenv("GHIDRA_INSTALL_DIR", "").strip()
    return Path(raw) if raw else None


def _derive_proof_symbolic_bytes(
    evidence_dir: Path,
    *,
    max_bytes: int,
    target_candidate_id: str = "",
    target_candidate_ids: Sequence[str] | None = None,
) -> int:
    max_bytes = max(1, int(max_bytes or 4096))
    desired = 256
    matched = False
    packs: list[tuple[Path, Mapping[str, Any]]] = []
    for path in sorted(Path(evidence_dir).glob("*.json")):
        if path.name == "index.json":
            continue
        pack = _load_json(path)
        if not pack:
            continue
        packs.append((path, pack))
    wanted_ids = {target_candidate_id} if target_candidate_id else (
        set(target_candidate_ids) if target_candidate_ids is not None else None
    )
    if wanted_ids is not None:
        packs = [(path, pack) for path, pack in packs if str(pack.get("candidate_id") or "") in wanted_ids]
    for _path, pack in packs:
        if wanted_ids is None and not _proof_budget_pack_matches(pack):
            continue
        matched = True
        candidate = _pack_candidate(pack)
        capacity = _int_value(candidate.get("capacity_bytes"), 0)
        write_size = _int_value(candidate.get("write_size_bytes"), 0)
        desired = max(desired, capacity + 1 if capacity > 0 else 0, write_size)
    if target_candidate_id and not matched:
        for path in sorted(Path(evidence_dir).glob("*.json")):
            if path.name == "index.json":
                continue
            pack = _load_json(path)
            if str(pack.get("candidate_id") or "") != target_candidate_id:
                continue
            candidate = _pack_candidate(pack)
            capacity = _int_value(candidate.get("capacity_bytes"), 0)
            write_size = _int_value(candidate.get("write_size_bytes"), 0)
            desired = max(desired, capacity + 1 if capacity > 0 else 0, write_size)
            break
    return max(1, min(desired, max_bytes))


def _proof_budget_pack_matches(pack: Mapping[str, Any]) -> bool:
    candidate = _pack_candidate(pack)
    sink = str(candidate.get("sink") or "").lower()
    sink = sink.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
    if sink not in {
        "read",
        "fread",
        "fgets",
        "gets",
        "memcpy",
        "memmove",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "sprintf",
        "snprintf",
        "vsprintf",
        "vsnprintf",
    }:
        return False
    destination = str(candidate.get("destination_kind") or "").lower()
    if not any(kind in destination for kind in ("stack", "heap", "global")):
        return False
    capacity = _int_value(candidate.get("capacity_bytes"), 0)
    if capacity <= 0:
        return False
    write_size = _int_value(candidate.get("write_size_bytes"), 0)
    relation = str(candidate.get("write_relation") or "")
    verdict = str(candidate.get("verdict") or "")
    proof = pack.get("proof_obligation") if isinstance(pack.get("proof_obligation"), Mapping) else {}
    proof_relation = str(proof.get("relation") or "")
    return (
        write_size > capacity
        or relation in {"proven_overflow", "unbounded"}
        or verdict in {"overflow", "unbounded"}
        or proof_relation in {"proven_overflow", "unbounded"}
    )


def _pack_candidate(pack: Mapping[str, Any]) -> Mapping[str, Any]:
    candidate = pack.get("deterministic_candidate")
    if isinstance(candidate, Mapping):
        return candidate
    candidate = pack.get("candidate")
    if isinstance(candidate, Mapping):
        return candidate
    return {}


def _int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _index_concolic_proof_artifacts(artifact_index: ArtifactIndex, proof_dir: Path) -> None:
    summary_path = Path(proof_dir) / CONCOLIC_RUN_SUMMARY
    if summary_path.exists():
        artifact_index.add(summary_path, kind="concolic_run_summary", stage="proof")
    for path in sorted(Path(proof_dir).rglob("*.json")):
        if path == summary_path:
            continue
        if path.name == "verdict.json":
            kind = "concolic_verdict"
        elif path.name == "request.json":
            kind = "concolic_request"
        elif path.name == "ghidra_dynamic_proof.json":
            kind = "ghidra_dynamic_proof"
        elif path.name == "ghidra_dynamic_proof_unsupported.json":
            kind = "ghidra_dynamic_proof_unsupported"
        elif path.name == "replay.json":
            kind = "concolic_replay"
        else:
            continue
        artifact_index.add(path, kind=kind, stage="proof")


def _index_semantic_seed_artifacts(
    artifact_index: ArtifactIndex,
    result,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> None:
    stage_metadata = dict(metadata or {})
    for path in [
        result.summary_path,
        result.feature_index_summary_path,
        result.accepted_index_path,
        result.rejected_index_path,
        *result.cluster_pack_paths,
        *result.zoom_pack_paths,
        *result.raw_paths,
        *result.accepted_seed_paths,
        *result.rejected_seed_paths,
    ]:
        artifact_index.add(
            path,
            kind=_semantic_seed_artifact_kind(Path(path), Path(result.output_dir)),
            stage="semantic_seed",
            metadata=stage_metadata,
        )


def _semantic_seed_artifact_kind(path: Path, semantic_seed_dir: Path) -> str:
    if path.name == "summary.json":
        return "semantic_seed_summary"
    if path.name == "feature_index_summary.json":
        return "semantic_seed_feature_index"
    if path.name == "accepted_index.json":
        return "semantic_seed_accepted_index"
    if path.name == "rejected_index.json":
        return "semantic_seed_rejected_index"
    try:
        first = path.relative_to(semantic_seed_dir).parts[0]
    except ValueError:
        first = ""
    if first == "cluster_packs":
        return "semantic_seed_cluster_pack"
    if first == "zoom_packs":
        return "semantic_seed_zoom_pack"
    if first == "raw":
        return "semantic_seed_raw_provider_output"
    if first == "accepted":
        return "semantic_seed_accepted"
    if first == "rejected":
        return "semantic_seed_rejected"
    return "semantic_seed_artifact"


def _enforce_live_llm_if_required(args: argparse.Namespace, summary_path: Path, stage: str) -> None:
    if not bool(getattr(args, "require_live_llm", False)):
        return
    summary = _load_json(Path(summary_path))
    provider = str(summary.get("provider") or "")
    command = str(summary.get("provider_command") or "")
    blocked_provider_tokens = ("fixture", "disabled", "smoke", "deterministic", "fake")
    if not summary.get("enabled"):
        raise RuntimeError(f"--require-live-llm requires enabled {stage} provider; summary={summary_path}")
    lowered = f"{provider} {command}".lower()
    if any(token in lowered for token in blocked_provider_tokens):
        raise RuntimeError(f"--require-live-llm rejects non-live {stage} provider {provider!r}")
    if int(summary.get("model_calls") or 0) <= 0:
        raise RuntimeError(f"--require-live-llm requires {stage} model_calls > 0; summary={summary_path}")


def _hypothesis_artifact_kind(path: Path, hypothesis_dir: Path) -> str:
    path = Path(path)
    if path.name == "summary.json":
        return "hypothesis_summary"
    if path.name == "lift_summary.json":
        return "hypothesis_lift_summary"
    if path.name == "accepted_index.json":
        return "hypothesis_accepted_index"
    if path.name == "rejected_index.json":
        return "hypothesis_rejected_index"
    try:
        first = path.relative_to(hypothesis_dir).parts[0]
    except ValueError:
        first = ""
    if first == "raw":
        return "hypothesis_raw_provider_output"
    return "hypothesis_artifact"


def _index_replay_sidecars(artifact_index: ArtifactIndex, replay_dir: Path) -> None:
    for path in sorted(Path(replay_dir).glob("**/*.json")):
        name = path.name
        if name == "request.json":
            kind = "replay_request"
        elif name == "result.json":
            kind = "replay_result"
        elif name == "repair_attempts.json":
            kind = "replay_repair_attempts"
        elif name.startswith("skipped_"):
            kind = "replay_skipped_alternative"
        elif name in {"dynamic_overflow_observation.json", "target_overflow_observation.json"} or (
            name.startswith("dynamic_") and name.endswith("_observation.json")
        ):
            kind = "proof_observation"
        else:
            continue
        artifact_index.add(path, kind=kind, stage="replay")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text() or "{}")
    except (OSError, json.JSONDecodeError):
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}


def _request_artifact_refs(requests, replay_dir: Path) -> dict[str, str]:
    replay_dir.mkdir(parents=True, exist_ok=True)
    refs: dict[str, str] = {}
    rows = []
    for request in requests:
        path = replay_dir / _safe_name(request.candidate_id) / "request.json"
        refs[request.candidate_id] = str(path)
        rows.append({"candidate_id": request.candidate_id, "path": str(path)})
    (replay_dir / "replay_requests.json").write_text(json.dumps({"replay_requests": rows}, indent=2, sort_keys=True))
    return refs


def _request_artifact_refs_from_results(results) -> dict[str, str]:
    refs: dict[str, str] = {}
    for result in results:
        for raw in result.artifacts:
            if Path(raw).name == "request.json":
                refs[result.candidate_id] = str(raw)
                break
    return refs


def _load_intake_facts(intake_dir: Path) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    for name in ("target", "binaries", "services", "routes", "configs", "analysis_manifest"):
        path = intake_dir / f"{name}.json"
        if not path.exists():
            continue
        try:
            facts[name] = json.loads(path.read_text() or "{}")
        except json.JSONDecodeError:
            facts[name] = {}
    return facts


def _select_firmware_binary_rows(intake_facts: Mapping[str, Any], pattern: str = "") -> list[dict[str, Any]]:
    binaries = intake_facts.get("binaries") if isinstance(intake_facts, Mapping) else {}
    rows = binaries.get("binaries", []) if isinstance(binaries, Mapping) else []
    compiled = re.compile(pattern) if pattern else None
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in rows:
        if not isinstance(item, Mapping):
            continue
        row = dict(item)
        architecture = str(row.get("architecture") or "").lower()
        relative = str(row.get("relative_path") or row.get("path") or "")
        basename = Path(relative).name
        if "elf" not in architecture or "executable" not in architecture:
            continue
        if "shared object" in architecture:
            continue
        if compiled and not (compiled.search(relative) or compiled.search(basename)):
            continue
        path = str(row.get("path") or "")
        if not path or path in seen:
            continue
        seen.add(path)
        selected.append(row)
    return sorted(selected, key=lambda row: str(row.get("relative_path") or row.get("path") or ""))


def _enrich_firmware_state(
    state,
    binary_row: Mapping[str, Any],
    target_path: Path,
    intake_facts: Mapping[str, Any],
    *,
    export_dir: Path | None = None,
):
    target = dict(state.target)
    version = _firmware_version(target_path)
    target.update(
        {
            "firmware_target": str(target_path),
            "firmware_version": version,
            "path": str(binary_row.get("path") or ""),
            "relative_path": str(binary_row.get("relative_path") or ""),
            "sha256": str(binary_row.get("sha256") or ""),
            "size_bytes": binary_row.get("size_bytes", ""),
            "architecture": str(binary_row.get("architecture") or ""),
            "component": str(binary_row.get("relative_path") or target.get("component") or target.get("binary") or ""),
            "version": version,
        }
    )
    if export_dir is not None:
        target["export_dir"] = str(export_dir)
    metadata = dict(state.metadata)
    metadata["firmware_binary"] = str(binary_row.get("relative_path") or "")
    services = _services_for_binary(binary_row, intake_facts)
    if services:
        metadata["firmware_services"] = services
    return state.with_updates(target=target, metadata=metadata)


def _entrypoint_derivation_for_state(
    state,
    *,
    fallback_export_dir: Path | None,
    deriver_cache: dict[str, EntryPointDeriver],
    intake_facts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    export_dir = _state_export_dir(state, fallback_export_dir=fallback_export_dir)
    if export_dir is None:
        return {
            "schema_version": 1,
            "status": "blocked",
            "blockers": ["export_dir_unavailable"],
            "no_text_matching": True,
        }
    key = str(export_dir.resolve())
    try:
        deriver = deriver_cache.get(key)
        if deriver is None:
            deriver = EntryPointDeriver.from_export_dir(export_dir)
            deriver_cache[key] = deriver
        candidate = state.to_dict() if hasattr(state, "to_dict") else dict(state)
        return deriver.derive_for_candidate(candidate, intake_facts=intake_facts).to_dict()
    except Exception as exc:
        return {
            "schema_version": 1,
            "status": "blocked",
            "blockers": [f"entrypoint_derivation_failed:{exc}"],
            "no_text_matching": True,
            "evidence": {"export_dir": str(export_dir)},
        }


def _state_with_entrypoint_derivation(state, entrypoint_derivation: Mapping[str, Any]):
    type_facts = dict(getattr(state, "type_facts", {}) or {})
    type_facts["entrypoint_derivation"] = dict(entrypoint_derivation)
    return state.with_updates(type_facts=type_facts)


def _state_with_process_input_override(state, process_input: Mapping[str, Any]):
    type_facts = dict(getattr(state, "type_facts", {}) or {})
    type_facts["process_input"] = dict(process_input)
    return state.with_updates(type_facts=type_facts)


def _load_process_input_override(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    config_path = Path(path).resolve()
    payload = json.loads(config_path.read_text() or "{}")
    if not isinstance(payload, Mapping) or int(payload.get("schema_version", 0) or 0) != 2:
        raise ValueError(f"Process input configuration {config_path} must use schema v2")
    declared_effect = _declared_process_effect(payload)
    if declared_effect:
        raise ValueError(
            f"Process input configuration {config_path} may describe observation setup but cannot declare {declared_effect}"
        )
    input_model = str(payload.get("input_model") or "")
    if not input_model:
        raise ValueError(f"Process input configuration {config_path} is missing input_model")
    argv = payload.get("argv_values") or payload.get("argv") or ["program"]
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise ValueError(f"Process input configuration {config_path} argv_values must be a string list")
    normalized: dict[str, Any] = {
        "input_model": input_model,
        "argv_values": list(argv),
        "process_input_source": str(payload.get("process_input_source") or "user_supplied_concrete_witness"),
        "process_input_evidence": dict(payload.get("process_input_evidence") or {}),
        "inferred": False,
    }
    for path_key, hex_key in (("stdin_path", "stdin_input_hex"), ("file_path", "file_input_hex")):
        raw_path = str(payload.get(path_key) or "")
        if not raw_path:
            continue
        source_path = Path(raw_path)
        if not source_path.is_absolute():
            source_path = config_path.parent / source_path
        source_path = source_path.resolve()
        normalized[hex_key] = source_path.read_bytes().hex()
        normalized["process_input_evidence"] = {
            **dict(normalized["process_input_evidence"]),
            path_key: str(source_path),
        }
        if path_key == "file_path":
            normalized["file_name"] = str(payload.get("file_name") or source_path.name)
    for key in ("stdin_input_hex", "file_input_hex", "file_name", "env_name"):
        if payload.get(key):
            normalized[key] = str(payload[key])
    if isinstance(payload.get("env_values"), Mapping):
        normalized["env_values"] = {str(key): str(value) for key, value in payload["env_values"].items()}
    for key in (
        "env",
        "cwd",
        "workdir",
        "proof_file",
        "proof_files",
        "database_path",
        "log_path",
        "outbound_listener",
        "proof_oracle",
        "oracle_setup",
        "timeout_seconds",
        "stdin",
    ):
        value = payload.get(key)
        if value not in (None, "", [], {}):
            normalized[key] = value
    return normalized


def _declared_process_effect(value: Any, path: str = "") -> str:
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key)
            child_path = f"{path}.{name}" if path else name
            if name in {"bug_observed", "effect_observed", "sink_reached"} and item is True:
                return child_path
            if name == "status" and str(item).lower() in {"observed", "confirmed", "proven"}:
                return child_path
            found = _declared_process_effect(item, child_path)
            if found:
                return found
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found = _declared_process_effect(item, f"{path}[{index}]")
            if found:
                return found
    return ""


def _state_and_pack_with_process_input(state, **pack_kwargs: Any):
    pack = build_evidence_pack_v3(state.to_dict(), **pack_kwargs)
    type_facts = dict(getattr(state, "type_facts", {}) or {})
    if isinstance(type_facts.get("process_input"), Mapping):
        return state, pack
    process_input = infer_process_input_fact(pack)
    if not process_input:
        return state, pack
    updated = state.with_updates(type_facts={**type_facts, "process_input": process_input})
    return updated, build_evidence_pack_v3(updated.to_dict(), **pack_kwargs)


def _state_and_pack_with_exact_memory_operation(
    state,
    pack: Mapping[str, Any],
    *,
    binary_path: Path,
    export_dir: Path | None,
    **pack_kwargs: Any,
):
    if not candidate_needs_exact_memory_operation(state):
        return state, pack
    resolution = resolve_memory_safety_target(
        pack,
        binary_path=binary_path,
        export_dir=export_dir,
    )
    operation_address = str(
        resolution.get("sink_address")
        or resolution.get("callsite_address")
        or resolution.get("target_address")
        or ""
    )
    function_address = str(state.location.get("address") or "")
    if not operation_address or (function_address and operation_address.lower() == function_address.lower()):
        return state, pack
    sink = {**state.sink, "operation_address": operation_address}
    type_facts = dict(state.type_facts)
    static_candidate = dict(type_facts.get("static_candidate") or {})
    if static_candidate:
        static_candidate["operation_address"] = operation_address
        type_facts["static_candidate"] = static_candidate
    type_facts["exact_sink_resolution"] = dict(resolution)
    updated = state.with_updates(sink=sink, type_facts=type_facts)
    return updated, build_evidence_pack_v3(updated.to_dict(), **pack_kwargs)


def _state_export_dir(state, *, fallback_export_dir: Path | None) -> Path | None:
    target = dict(getattr(state, "target", {}) or {})
    raw = str(target.get("export_dir") or "")
    if raw:
        path = Path(raw)
        if path.exists() and path.is_dir():
            return path
    if fallback_export_dir is not None and Path(fallback_export_dir).exists():
        return Path(fallback_export_dir)
    return None


def _services_for_binary(binary_row: Mapping[str, Any], intake_facts: Mapping[str, Any]) -> list[dict[str, Any]]:
    relative = str(binary_row.get("relative_path") or "")
    name = Path(relative).name
    services_payload = intake_facts.get("services") if isinstance(intake_facts, Mapping) else {}
    services = services_payload.get("services", []) if isinstance(services_payload, Mapping) else []
    matched = []
    for item in services:
        if not isinstance(item, Mapping):
            continue
        exec_text = str(item.get("exec") or "")
        if name and name in exec_text:
            matched.append(dict(item))
    return matched


def _scoped_intake_facts_for_state(state, intake_facts: Mapping[str, Any]) -> dict[str, Any]:
    target = dict(intake_facts.get("target") or {}) if isinstance(intake_facts.get("target"), Mapping) else {}
    target_info = dict(state.target)
    desired_path = str(target_info.get("path") or "")
    desired_relative = str(target_info.get("relative_path") or "")
    desired_sha = str(target_info.get("sha256") or "")
    binaries_payload = intake_facts.get("binaries") if isinstance(intake_facts, Mapping) else {}
    binary_rows = binaries_payload.get("binaries", []) if isinstance(binaries_payload, Mapping) else []
    selected_binary = []
    for item in binary_rows:
        if not isinstance(item, Mapping):
            continue
        if desired_sha and str(item.get("sha256") or "") == desired_sha:
            selected_binary = [dict(item)]
            break
        if desired_path and str(item.get("path") or "") == desired_path:
            selected_binary = [dict(item)]
            break
        if desired_relative and str(item.get("relative_path") or "") == desired_relative:
            selected_binary = [dict(item)]
            break
    services = _services_for_binary(selected_binary[0], intake_facts) if selected_binary else []
    return {
        "target": target,
        "binaries": {"schema_version": 1, "binaries": selected_binary},
        "services": {"schema_version": 1, "services": services},
        "routes": {"schema_version": 1, "routes": []},
        "configs": {"schema_version": 1, "configs": []},
    }


def _firmware_binary_key(row: Mapping[str, Any]) -> str:
    return _safe_name(str(row.get("relative_path") or Path(str(row.get("path") or "binary")).name).replace("/", "__"))


def _firmware_version(path: Path) -> str:
    match = re.search(r"Release_([^/]+)", str(path))
    return match.group(1) if match else path.name


def _write_firmware_run_summary(
    run_dir: Path,
    target_path: Path,
    states: Sequence[Any],
    binary_summaries: Sequence[Mapping[str, Any]],
    imported_replay_results: int,
    report_count: int,
    vendor_bundle_count: int,
) -> dict[str, Path]:
    status_counts: dict[str, int] = {}
    vuln_counts: dict[str, int] = {}
    report_vuln_counts: dict[str, int] = {}
    report_ready_by_binary: dict[str, int] = {}
    for state in states:
        status_counts[state.status] = status_counts.get(state.status, 0) + 1
        vuln_counts[state.vulnerability_type] = vuln_counts.get(state.vulnerability_type, 0) + 1
        if state.status == "report_ready":
            binary = str(state.target.get("relative_path") or state.target.get("binary") or "unknown")
            report_ready_by_binary[binary] = report_ready_by_binary.get(binary, 0) + 1
            report_vuln = report_vulnerability_type(state)
            report_vuln_counts[report_vuln] = report_vuln_counts.get(report_vuln, 0) + 1
    payload = {
        "schema_version": 1,
        "target": str(target_path),
        "firmware_version": _firmware_version(target_path),
        "binaries_analyzed": list(binary_summaries),
        "candidate_total": len(states),
        "status_counts": status_counts,
        "vulnerability_type_counts": vuln_counts,
        "report_vulnerability_type_counts": report_vuln_counts,
        "imported_replay_results": imported_replay_results,
        "report_count": report_count,
        "vendor_bundle_count": vendor_bundle_count,
        "report_ready_by_binary": report_ready_by_binary,
    }
    summary_path = run_dir / "firmware_run_summary.json"
    summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    review_path = run_dir / "report" / "vendor_review_summary.md"
    review_path.parent.mkdir(parents=True, exist_ok=True)
    review_lines = [
        f"# Firmware Vendor Review Summary",
        "",
        f"- Target: `{target_path}`",
        f"- Firmware version: `{payload['firmware_version']}`",
        f"- Binaries analyzed: `{len(binary_summaries)}`",
        f"- Candidates discovered: `{len(states)}`",
        f"- Imported replay confirmations: `{imported_replay_results}`",
        f"- Report-ready findings: `{status_counts.get('report_ready', 0)}`",
        f"- Vendor evidence bundles: `{vendor_bundle_count}`",
        "",
        "## Report-Ready Findings By Vulnerability Type",
        *[f"- `{vulnerability_type}`: {count}" for vulnerability_type, count in sorted(report_vuln_counts.items())],
        "",
        "## Report-Ready Findings By Binary",
        *[f"- `{binary}`: {count}" for binary, count in sorted(report_ready_by_binary.items())],
        "",
    ]
    review_path.write_text("\n".join(review_lines))
    return {"firmware_run_summary": summary_path, "vendor_review_summary": review_path}


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)[:120] or "candidate"


if __name__ == "__main__":
    main()
