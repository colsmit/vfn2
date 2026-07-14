from binary_agent.transaction_benchmark import (
    POLICIES,
    _schedule_metrics,
    _schedule_policy,
)


def _policy_inputs() -> list[dict]:
    return [
        {
            "variant_id": variant_id,
            "object": object_name,
            "method": method,
            "setup_key": "shared",
            "schema_field_count": fields,
            "callback_distance": distance,
            "estimated_marginal_seconds": 1.0,
            "measured_wall_seconds": 1.0,
            "measured_cpu_seconds": 0.5,
            "static_features_only": True,
        }
        for variant_id, object_name, method, fields, distance in (
            ("a", "z", "status", 0, 0),
            ("b", "y", "status", 0, 10),
            ("c", "x", "dump", 0, 1),
            ("d", "w", "list", 1, 2),
            ("e", "v", "info", 4, 3),
            ("f", "u", "getData", 2, None),
        )
    ]


def test_transaction_policies_use_label_free_inputs_and_choose_distinct_schedules() -> None:
    features = _policy_inputs()
    assert all("observed_operations" not in row for row in features)
    schedules = {}
    for policy in POLICIES:
        schedule = _schedule_policy(
            features,
            policy,
            limit=4,
            seed="frozen-seed",
            observe=lambda variant_id: {"0x401000", "0x401010"} if variant_id == "a" else set(),
        )
        schedules[policy] = tuple(row["variant_id"] for row in schedule)
    assert len(set(schedules.values())) == len(POLICIES)
    assert schedules["adaptive"] != schedules["static-rank"]


def test_transaction_schedule_metrics_count_unique_reach_and_setup_reuse() -> None:
    schedule = _policy_inputs()[:4]
    metrics = _schedule_metrics(
        schedule,
        {
            "a": {"0x401000"},
            "b": {"0x401000", "0x401010"},
            "d": {"0x401020"},
        },
    )
    assert metrics["unique_exact_operations_after_four_transactions"] == 3
    assert metrics["cumulative_unique_reaches"] == [1, 2, 2, 3]
    assert metrics["area_under_cumulative_reach_curve"] == 8.0
    assert metrics["wall_seconds"] == 4.0
    assert metrics["cpu_seconds"] == 2.0
    assert metrics["setup_reuse_count"] == 3


def test_transaction_policy_enforces_wall_and_cpu_budgets() -> None:
    schedule = _schedule_policy(
        _policy_inputs(),
        "exhaustive",
        limit=4,
        seed="frozen-seed",
        observe=lambda _variant_id: set(),
        wall_limit_seconds=2.1,
        cpu_limit_seconds=1.1,
    )
    assert len(schedule) == 2
    metrics = _schedule_metrics(schedule, {})
    assert metrics["wall_seconds"] <= 2.1
    assert metrics["cpu_seconds"] <= 1.1
