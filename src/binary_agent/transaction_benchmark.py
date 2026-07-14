"""Freeze and evaluate the label-blind OpenWrt ubus scheduling benchmark."""

from __future__ import annotations

import hashlib
import json
import random
import shutil
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.firmware_transactions import transaction_variant_score


TRANSACTION_BENCHMARK_SCHEMA_VERSION = 2
LEGACY_TRANSACTION_BENCHMARK_CORPUS_ID = "openwrt-ubus-route-v2"
PREVIOUS_TRANSACTION_BENCHMARK_CORPUS_ID = "openwrt-ubus-route-v4"
TRANSACTION_BENCHMARK_CORPUS_ID = "openwrt-ubus-route-v5"
POLICIES = ("adaptive", "static-rank", "seeded-random", "exhaustive")


def freeze_transaction_benchmark(
    campaign_root: Path,
    rootfs_path: Path,
    exports: Mapping[str, Path | str],
    output_root: Path,
    *,
    corpus_id: str = TRANSACTION_BENCHMARK_CORPUS_ID,
) -> Path:
    """Seal real transaction inputs and labels into separate artifacts."""

    campaigns = Path(campaign_root).expanduser().resolve()
    source_rootfs = Path(rootfs_path).expanduser().resolve()
    output = Path(output_root).expanduser().resolve() / corpus_id
    if output.exists():
        raise FileExistsError(f"transaction benchmark already exists: {output}")
    if not source_rootfs.is_dir():
        raise ValueError("transaction benchmark rootfs is missing")
    roles = {"netifd": "calibration", "rpcd": "holdout"}
    prepared: dict[str, dict[str, Any]] = {}
    all_transaction_count = 0
    any_observed_candidate_operation = False
    for target, role in roles.items():
        source = campaigns / target
        result = _load_json(source / "result.json")
        plan = dict(result.get("plan") or {})
        transactions = [dict(item) for item in plan.get("transactions", []) if isinstance(item, Mapping)]
        observations = [dict(item) for item in result.get("observations", []) if isinstance(item, Mapping)]
        if result.get("status") != "observed" or not transactions:
            raise ValueError(f"transaction source is not observed:{target}")
        _validate_execution_baseline(result, source / "transaction_brackets.jsonl", target)
        unique_reached = {
            str(item.get("operation_address") or "")
            for item in observations
            if item.get("status") == "observed"
        }
        if len(unique_reached) < 2:
            raise ValueError(f"transaction source lacks two exact operations:{target}")
        statuses = {str(item.get("status") or "") for item in observations}
        if not {"observed", "not_observed"}.issubset(statuses):
            raise ValueError(f"transaction source lacks reaching and non-reaching pairs:{target}")
        by_operation: dict[str, set[str]] = {}
        all_variants = {str(item.get("variant_id") or "") for item in transactions}
        for item in observations:
            if item.get("status") == "observed":
                by_operation.setdefault(str(item.get("operation_address") or ""), set()).add(
                    str(item.get("variant_id") or "")
                )
        if not any(variants and variants != all_variants for variants in by_operation.values()):
            raise ValueError(f"transaction source lacks a selective operation:{target}")
        all_transaction_count += len(transactions)
        prepared[target] = {
            "role": role,
            "source": source,
            "result": result,
            "transactions": transactions,
            "observations": observations,
        }
    if all_transaction_count < 12:
        raise ValueError("transaction benchmark requires at least twelve safe variants")

    output.mkdir(parents=True)
    try:
        frozen_rootfs = output / "rootfs"
        shutil.copytree(source_rootfs, frozen_rootfs, symlinks=True)
        target_rows = []
        label_payload: dict[str, Any] = {
            "schema_version": 2,
            "artifact_kind": "openwrt_ubus_route_evaluation_labels",
            "policy_input": False,
            "targets": {},
        }
        for target, row in prepared.items():
            source = row["source"]
            binary_source = source_rootfs / "sbin" / target
            export_source = Path(exports[target]).expanduser().resolve()
            if not binary_source.is_file() or not export_source.is_dir():
                raise ValueError(f"binary or export missing:{target}")
            binary = output / "binaries" / target
            binary.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(binary_source, binary)
            export = output / "exports" / target
            shutil.copytree(export_source, export, symlinks=True)
            inputs = output / "inputs" / target
            inputs.mkdir(parents=True)
            copied: dict[str, Path] = {}
            for name in (
                "ubus_verbose_list.txt",
                "transaction_plan.json",
                "operation_catalog.json",
                "publication_acl.json",
                "selected_call_acl.json",
                "transaction_brackets.jsonl",
                "transactions.json",
                "execution_readiness_barrier.json",
                "transaction_observations.json",
                "idle_startup_hits.json",
            ):
                source_file = source / name
                if not source_file.is_file():
                    raise ValueError(f"campaign input missing:{target}:{name}")
                destination = inputs / name
                shutil.copy2(source_file, destination)
                copied[name] = destination
            operation_catalog = _load_json(copied["operation_catalog.json"])
            candidate_operations = [
                str(item.get("address") or "")
                for item in operation_catalog.get("operations", []) or []
                if isinstance(item, Mapping)
                and any(
                    isinstance(role, Mapping) and role.get("kind") == "candidate_operation"
                    for role in item.get("roles", []) or []
                )
            ]
            observed_addresses = {
                str(item.get("operation_address") or "").lower()
                for item in row["observations"]
                if item.get("status") == "observed"
            }
            any_observed_candidate_operation = any_observed_candidate_operation or any(
                address.lower() in observed_addresses for address in candidate_operations
            )
            features = _transaction_features(
                row["transactions"],
                operation_catalog,
                copied["transaction_brackets.jsonl"],
            )
            features_path = inputs / "policy_features.json"
            _write_json(
                features_path,
                {
                    "schema_version": 2,
                    "artifact_kind": "transaction_policy_inputs",
                    "ground_truth_reach_labels_present": False,
                    "transactions": features,
                },
            )
            label_payload["targets"][target] = {
                "observations": row["observations"],
                "idle_hits": list(row["result"].get("idle_hits", []) or []),
            }
            target_rows.append(
                {
                    "target": target,
                    "evaluation_role": row["role"],
                    "binary_path": str(binary.relative_to(output)),
                    "binary_sha256": _sha256_file(binary),
                    "export_path": str(export.relative_to(output)),
                    "export_sha256": _tree_sha256(export),
                    "schema_path": str(copied["ubus_verbose_list.txt"].relative_to(output)),
                    "schema_sha256": _sha256_file(copied["ubus_verbose_list.txt"]),
                    "transaction_path": str(copied["transaction_plan.json"].relative_to(output)),
                    "transaction_sha256": _sha256_file(copied["transaction_plan.json"]),
                    "operation_path": str(copied["operation_catalog.json"].relative_to(output)),
                    "operation_sha256": _sha256_file(copied["operation_catalog.json"]),
                    "setup_path": str(copied["selected_call_acl.json"].relative_to(output)),
                    "setup_sha256": _sha256_file(copied["selected_call_acl.json"]),
                    "readiness_path": str(
                        copied["execution_readiness_barrier.json"].relative_to(output)
                    ),
                    "readiness_sha256": _sha256_file(
                        copied["execution_readiness_barrier.json"]
                    ),
                    "observation_path": str(
                        copied["transaction_observations.json"].relative_to(output)
                    ),
                    "observation_sha256": _sha256_file(
                        copied["transaction_observations.json"]
                    ),
                    "idle_path": str(copied["idle_startup_hits.json"].relative_to(output)),
                    "idle_sha256": _sha256_file(copied["idle_startup_hits.json"]),
                    "policy_features_path": str(features_path.relative_to(output)),
                    "policy_features_sha256": _sha256_file(features_path),
                    "transaction_count": len(row["transactions"]),
                    "exact_operation_count": len(
                        {
                            str(item.get("operation_address") or "")
                            for item in row["observations"]
                        }
                    ),
                    "candidate_operation_count": len(set(candidate_operations)),
                }
            )
        if not any_observed_candidate_operation:
            raise ValueError("transaction benchmark lacks an observed candidate operation")
        labels = output / "evaluation_labels.json"
        _write_json(labels, label_payload)
        manifest = output / "frozen_manifest.json"
        _write_json(
            manifest,
            {
                "schema_version": 2,
                "artifact_kind": "frozen_openwrt_ubus_route_benchmark",
                "corpus_id": corpus_id,
                "frozen_at": datetime.now(timezone.utc).isoformat(),
                "rootfs_path": str(frozen_rootfs.relative_to(output)),
                "rootfs_sha256": _tree_sha256(frozen_rootfs),
                "evaluation_labels_path": str(labels.relative_to(output)),
                "evaluation_labels_sha256": _sha256_file(labels),
                "labels_available_to_scheduling_policies": False,
                "supersedes_corpus_id": PREVIOUS_TRANSACTION_BENCHMARK_CORPUS_ID,
                "superseded_corpus_ids": [
                    LEGACY_TRANSACTION_BENCHMARK_CORPUS_ID,
                    "openwrt-ubus-route-v3",
                    PREVIOUS_TRANSACTION_BENCHMARK_CORPUS_ID,
                ],
                "measurement_integrity": {
                    "post_dispatch_readiness_barrier_required": True,
                    "exact_trace_quiescence_required": True,
                    "setup_and_startup_evidence_excluded": True,
                },
                "limits": {
                    "transactions": 4,
                    "wall_seconds_per_target": 60.0,
                    "cpu_seconds_per_target": 60.0,
                    "warm_repetitions": 3,
                },
                "primary_metrics": [
                    "unique_exact_operations_after_four_transactions",
                    "area_under_cumulative_reach_curve",
                    "time_to_first_reach_seconds",
                    "wall_seconds",
                    "cpu_seconds",
                    "setup_reuse_count",
                ],
                "measurement_basis": {
                    "wall_seconds": "monotonic transaction-bracket duration",
                    "cpu_seconds": "conservative wall-duration upper bound when per-process CPU telemetry is unavailable",
                },
                "targets": target_rows,
            },
        )
        return manifest
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def verify_transaction_benchmark(manifest_path: Path) -> dict[str, Any]:
    manifest_file = Path(manifest_path).expanduser().resolve()
    payload = _load_json(manifest_file)
    if int(payload.get("schema_version") or 0) != 2:
        raise ValueError("unsupported transaction benchmark schema")
    root = manifest_file.parent
    failures = []
    rootfs = root / str(payload.get("rootfs_path") or "")
    if not rootfs.is_dir() or _tree_sha256(rootfs) != str(payload.get("rootfs_sha256") or ""):
        failures.append({"kind": "rootfs", "reason": "missing_or_hash_mismatch"})
    labels = root / str(payload.get("evaluation_labels_path") or "")
    if not labels.is_file() or _sha256_file(labels) != str(payload.get("evaluation_labels_sha256") or ""):
        failures.append({"kind": "evaluation_labels", "reason": "missing_or_hash_mismatch"})
    roles = set()
    transaction_count = 0
    for raw in payload.get("targets", []) or []:
        if not isinstance(raw, Mapping):
            failures.append({"kind": "target", "reason": "invalid"})
            continue
        target = str(raw.get("target") or "")
        roles.add(str(raw.get("evaluation_role") or ""))
        transaction_count += int(raw.get("transaction_count") or 0)
        for kind in ("binary", "schema", "transaction", "operation", "setup", "policy_features"):
            path = root / str(raw.get(f"{kind}_path") or "")
            expected = str(raw.get(f"{kind}_sha256") or "")
            if not path.is_file() or _sha256_file(path) != expected:
                failures.append({"target": target, "kind": kind, "reason": "missing_or_hash_mismatch"})
        for kind in ("readiness", "observation", "idle"):
            if f"{kind}_path" not in raw and f"{kind}_sha256" not in raw:
                continue
            path = root / str(raw.get(f"{kind}_path") or "")
            expected = str(raw.get(f"{kind}_sha256") or "")
            if not path.is_file() or _sha256_file(path) != expected:
                failures.append(
                    {"target": target, "kind": kind, "reason": "missing_or_hash_mismatch"}
                )
        export = root / str(raw.get("export_path") or "")
        if not export.is_dir() or _tree_sha256(export) != str(raw.get("export_sha256") or ""):
            failures.append({"target": target, "kind": "export", "reason": "missing_or_hash_mismatch"})
    if roles != {"calibration", "holdout"}:
        failures.append({"kind": "roles", "reason": "calibration_and_holdout_required"})
    if transaction_count < 12:
        failures.append({"kind": "transactions", "reason": "at_least_twelve_required"})
    return {
        "schema_version": 2,
        "artifact_kind": "openwrt_ubus_route_benchmark_verification",
        "verified": not failures,
        "corpus_id": str(payload.get("corpus_id") or ""),
        "target_count": len(payload.get("targets", []) or []),
        "transaction_count": transaction_count,
        "failures": failures,
    }


def evaluate_transaction_benchmark(
    manifest_path: Path,
    output_root: Path,
    *,
    repetitions: int = 3,
    transaction_limit: int = 4,
    wall_limit_seconds: float = 60.0,
    cpu_limit_seconds: float = 60.0,
    seed: str | None = None,
) -> dict[str, Any]:
    """Compare four policies without exposing future labels to schedulers."""

    manifest_file = Path(manifest_path).expanduser().resolve()
    verification = verify_transaction_benchmark(manifest_file)
    if not verification["verified"]:
        raise ValueError(f"transaction benchmark verification failed:{verification['failures']}")
    manifest = _load_json(manifest_file)
    effective_seed = str(seed or manifest.get("corpus_id") or TRANSACTION_BENCHMARK_CORPUS_ID)
    frozen_limits = dict(manifest.get("limits") or {})
    if (
        int(transaction_limit) != int(frozen_limits.get("transactions") or 0)
        or float(wall_limit_seconds) != float(frozen_limits.get("wall_seconds_per_target") or 0.0)
        or float(cpu_limit_seconds) != float(frozen_limits.get("cpu_seconds_per_target") or 0.0)
    ):
        raise ValueError("benchmark policies must use the identical frozen limits")
    root = manifest_file.parent
    labels = _load_json(root / str(manifest["evaluation_labels_path"]))
    output = Path(output_root).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    run = output / datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    run.mkdir()
    rows: dict[str, list[dict[str, Any]]] = {policy: [] for policy in POLICIES}
    for target_row in manifest.get("targets", []) or []:
        target = str(target_row["target"])
        role = str(target_row["evaluation_role"])
        policy_inputs = _load_json(root / str(target_row["policy_features_path"]))
        transactions = [
            dict(item)
            for item in policy_inputs.get("transactions", []) or []
            if isinstance(item, Mapping)
        ]
        target_labels = dict(dict(labels.get("targets") or {}).get(target) or {})
        observed_by_variant: dict[str, set[str]] = {}
        for observation in target_labels.get("observations", []) or []:
            if isinstance(observation, Mapping) and observation.get("status") == "observed":
                observed_by_variant.setdefault(str(observation.get("variant_id") or ""), set()).add(
                    str(observation.get("operation_address") or "")
                )
        for policy in POLICIES:
            for repetition in range(1, max(1, int(repetitions)) + 1):
                schedule = _schedule_policy(
                    transactions,
                    policy,
                    limit=transaction_limit,
                    seed=f"{effective_seed}:{target}:{repetition}",
                    observe=lambda variant_id: observed_by_variant.get(variant_id, set()),
                    wall_limit_seconds=wall_limit_seconds,
                    cpu_limit_seconds=cpu_limit_seconds,
                )
                metric = _schedule_metrics(schedule, observed_by_variant)
                row = {
                    "target": target,
                    "evaluation_role": role,
                    "policy": policy,
                    "repetition": repetition,
                    "limits": {
                        "transactions": transaction_limit,
                        "wall_seconds": wall_limit_seconds,
                        "cpu_seconds": cpu_limit_seconds,
                    },
                    "labels_available_to_policy": False,
                    "online_observed_feedback": policy == "adaptive",
                    "schedule": [str(item["variant_id"]) for item in schedule],
                    **metric,
                }
                _write_json(run / target / policy / f"repeat-{repetition}.json", row)
                rows[policy].append(row)
    medians = {policy: _policy_medians(policy_rows) for policy, policy_rows in rows.items()}
    first_schedules = {
        policy: tuple(
            tuple(row["schedule"])
            for row in policy_rows
            if int(row["repetition"]) == 1
        )
        for policy, policy_rows in rows.items()
    }
    schedules_differ = len({value for value in first_schedules.values()}) == len(POLICIES)
    baseline_names = tuple(item for item in POLICIES if item != "adaptive")
    adaptive = medians["adaptive"]
    strict_reach_advantage = all(
        adaptive["unique_exact_operations_after_four_transactions"]
        > medians[name]["unique_exact_operations_after_four_transactions"]
        for name in baseline_names
    )
    best_wall = min(medians[name]["wall_seconds"] for name in baseline_names)
    best_cpu = min(medians[name]["cpu_seconds"] for name in baseline_names)
    within_cost = adaptive["wall_seconds"] <= 1.1 * best_wall and adaptive["cpu_seconds"] <= 1.1 * best_cpu
    supports = schedules_differ and strict_reach_advantage and within_cost
    summary = {
        "schema_version": 2,
        "artifact_kind": "openwrt_ubus_transaction_scheduling_benchmark",
        "corpus_id": str(manifest.get("corpus_id") or ""),
        "run_dir": str(run),
        "repetitions": max(1, int(repetitions)),
        "policies": {policy: {"runs": policy_rows, "median": medians[policy]} for policy, policy_rows in rows.items()},
        "schedules_genuinely_different": schedules_differ,
        "labels_available_to_scheduling_policies": False,
        "identical_limits": True,
        "measurement_basis": dict(manifest.get("measurement_basis") or {}),
        "supports_efficiency_hypothesis": supports,
        "efficiency_hypothesis": "accepted" if supports else "rejected",
        "interpretation": (
            "Adaptive has strictly greater median exact-operation reach than every baseline within the 110% cost gate."
            if supports
            else "Valid null result: adaptive did not satisfy the pre-registered strict reach and cost gate."
        ),
    }
    _write_json(run / "summary.json", summary)
    return summary


def _transaction_features(
    transactions: Sequence[Mapping[str, Any]],
    operation_catalog: Mapping[str, Any],
    bracket_path: Path,
) -> list[dict[str, Any]]:
    candidate_addresses = []
    callback_by_method: dict[str, list[int]] = {}
    for raw in operation_catalog.get("operations", []) or []:
        if not isinstance(raw, Mapping):
            continue
        address = int(str(raw.get("address") or "0"), 0)
        for role in raw.get("roles", []) or []:
            if not isinstance(role, Mapping):
                continue
            if role.get("kind") == "candidate_operation":
                candidate_addresses.append(address)
            elif role.get("kind") == "callback_probe":
                callback_by_method.setdefault(str(role.get("method") or ""), []).append(address)
    durations = _bracket_durations(bracket_path)
    rows = []
    for raw in transactions:
        method = str(raw.get("method") or "")
        callbacks = callback_by_method.get(method, [])
        distance = min(
            (abs(callback - candidate) for callback in callbacks for candidate in candidate_addresses),
            default=None,
        )
        measured = max(0.001, durations.get(str(raw.get("variant_id") or ""), 0.01))
        rows.append(
            {
                "variant_id": str(raw.get("variant_id") or ""),
                "object": str(raw.get("object") or ""),
                "method": method,
                "setup_key": str(raw.get("setup_key") or ""),
                "schema_field_count": len(dict(raw.get("schema") or {})),
                "callback_distance": distance,
                "estimated_marginal_seconds": measured,
                "measured_wall_seconds": measured,
                "measured_cpu_seconds": measured,
                "static_features_only": True,
            }
        )
    return rows


def _validate_execution_baseline(
    result: Mapping[str, Any],
    bracket_path: Path,
    target: str,
) -> None:
    readiness = dict(result.get("readiness") or {})
    barrier = dict(readiness.get("execution_barrier") or {})
    baseline = dict(barrier.get("baseline") or {})
    if (
        barrier.get("status") != "observed_ready"
        or barrier.get("setup_evidence_only") is not True
        or baseline.get("event") != "initialization_baseline"
    ):
        raise ValueError(f"transaction source lacks execution readiness baseline:{target}")
    baseline_offset = int(baseline.get("trace_offset") or 0)
    starts = []
    baseline_markers = []
    for line in Path(bracket_path).read_text(errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("event") == "initialization_baseline":
            baseline_markers.append(row)
        elif row.get("event") == "transaction_start":
            starts.append(int(row.get("trace_offset") or 0))
    if len(baseline_markers) != 1 or not starts or any(offset < baseline_offset for offset in starts):
        raise ValueError(f"measured transaction precedes execution baseline:{target}")
    for observation in result.get("observations", []) or []:
        if not isinstance(observation, Mapping):
            continue
        if int(observation.get("initialization_baseline_offset") or -1) != baseline_offset:
            raise ValueError(f"transaction observation lacks matching baseline:{target}")


def _schedule_policy(
    transactions: Sequence[Mapping[str, Any]],
    policy: str,
    *,
    limit: int,
    seed: str,
    observe: Any,
    wall_limit_seconds: float = float("inf"),
    cpu_limit_seconds: float = float("inf"),
) -> list[dict[str, Any]]:
    if policy not in POLICIES:
        raise ValueError(f"unsupported transaction policy:{policy}")
    remaining = [dict(item) for item in transactions]
    selected: list[dict[str, Any]] = []
    prior_by_method: dict[str, int] = {}
    wall_used = 0.0
    cpu_used = 0.0
    rng = random.Random(seed)
    if policy == "seeded-random":
        rng.shuffle(remaining)
    elif policy == "exhaustive":
        remaining.sort(key=lambda item: (str(item["object"]), str(item["method"]), str(item["variant_id"])))
    while remaining and len(selected) < max(0, int(limit)):
        if policy in {"adaptive", "static-rank"}:
            remaining.sort(
                key=lambda item: (
                    -transaction_variant_score(
                        callback_distance=item.get("callback_distance"),
                        schema_field_count=int(item.get("schema_field_count") or 0),
                        setup_reused=bool(selected),
                        estimated_marginal_seconds=float(item.get("estimated_marginal_seconds") or 0.01),
                        prior_observed_reaches=(
                            prior_by_method.get(str(item.get("method") or ""), 0)
                            if policy == "adaptive"
                            else 0
                        ),
                    ),
                    str(item["variant_id"]),
                )
            )
        chosen = remaining.pop(0)
        marginal_wall = max(0.0, float(chosen.get("measured_wall_seconds") or 0.0))
        marginal_cpu = max(0.0, float(chosen.get("measured_cpu_seconds") or 0.0))
        if (
            wall_used + marginal_wall > max(0.0, float(wall_limit_seconds))
            or cpu_used + marginal_cpu > max(0.0, float(cpu_limit_seconds))
        ):
            continue
        selected.append(chosen)
        wall_used += marginal_wall
        cpu_used += marginal_cpu
        if policy == "adaptive":
            observed = observe(str(chosen["variant_id"]))
            prior_by_method[str(chosen.get("method") or "")] = len(observed)
    return selected


def _schedule_metrics(
    schedule: Sequence[Mapping[str, Any]],
    observed_by_variant: Mapping[str, set[str]],
) -> dict[str, Any]:
    reached: set[str] = set()
    cumulative = []
    time_elapsed = 0.0
    time_to_first: float | None = None
    wall = 0.0
    cpu = 0.0
    setup_keys: set[str] = set()
    reuse = 0
    for item in schedule:
        wall += float(item.get("measured_wall_seconds") or 0.0)
        cpu += float(item.get("measured_cpu_seconds") or 0.0)
        time_elapsed = wall
        before = len(reached)
        reached.update(observed_by_variant.get(str(item.get("variant_id") or ""), set()))
        if time_to_first is None and len(reached) > before:
            time_to_first = time_elapsed
        cumulative.append(len(reached))
        setup_key = str(item.get("setup_key") or "")
        if setup_key in setup_keys:
            reuse += 1
        setup_keys.add(setup_key)
    return {
        "unique_exact_operations_after_four_transactions": len(reached),
        "area_under_cumulative_reach_curve": float(sum(cumulative)),
        "cumulative_unique_reaches": cumulative,
        "time_to_first_reach_seconds": time_to_first,
        "wall_seconds": wall,
        "cpu_seconds": cpu,
        "setup_reuse_count": reuse,
    }


def _policy_medians(rows: Sequence[Mapping[str, Any]]) -> dict[str, float | None]:
    metrics = (
        "unique_exact_operations_after_four_transactions",
        "area_under_cumulative_reach_curve",
        "wall_seconds",
        "cpu_seconds",
        "setup_reuse_count",
    )
    result: dict[str, float | None] = {
        key: statistics.median(float(row.get(key) or 0.0) for row in rows)
        for key in metrics
    }
    first = [float(row["time_to_first_reach_seconds"]) for row in rows if row.get("time_to_first_reach_seconds") is not None]
    result["time_to_first_reach_seconds"] = statistics.median(first) if first else None
    return result


def _bracket_durations(path: Path) -> dict[str, float]:
    starts: dict[str, list[int]] = {}
    durations: dict[str, list[float]] = {}
    for line in Path(path).read_text(errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        variant = str(row.get("variant_id") or "")
        if row.get("event") == "transaction_start":
            starts.setdefault(variant, []).append(int(row.get("monotonic_ns") or 0))
        elif row.get("event") == "transaction_end" and starts.get(variant):
            start = starts[variant].pop(0)
            durations.setdefault(variant, []).append(max(0.0, (int(row.get("monotonic_ns") or 0) - start) / 1e9))
    return {variant: statistics.median(values) for variant, values in durations.items()}


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(Path(root).rglob("*"), key=lambda item: item.as_posix()):
        digest.update(path.relative_to(root).as_posix().encode())
        if path.is_symlink():
            digest.update(b"L" + str(path.readlink()).encode())
        elif path.is_file():
            digest.update(b"F" + _sha256_file(path).encode())
        elif path.is_dir():
            digest.update(b"D")
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object:{path}")
    return payload


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n")
    temporary.replace(destination)


__all__ = (
    "TRANSACTION_BENCHMARK_CORPUS_ID",
    "evaluate_transaction_benchmark",
    "freeze_transaction_benchmark",
    "verify_transaction_benchmark",
)
