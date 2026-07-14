import pytest

from binary_agent.yield_model import YieldTrainingRecord, fit_route_yield_model


def test_yield_model_is_smoothed_deterministic_and_calibration_only() -> None:
    records = [
        YieldTrainingRecord("a", "double_free", "native_ledger", "proven", "calibration"),
        YieldTrainingRecord("b", "double_free", "native_ledger", "refuted", "calibration"),
        YieldTrainingRecord("c", "double_free", "native_ledger", "proven", "holdout"),
        YieldTrainingRecord("d", "uninitialized_memory_use", "qemu_user", "inconclusive", "calibration"),
    ]
    first = fit_route_yield_model(records)
    second = fit_route_yield_model(list(reversed(records)))
    assert first == second
    assert first.training_record_count == 3
    native = first.estimate("double_free", "native_ledger")
    assert native.source == "taxonomy_route"
    assert native.report_probability == 0.5
    assert native.completion_probability == 0.75
    qemu = first.estimate("use_after_free", "qemu_user")
    assert qemu.source == "route_backoff"
    assert qemu.report_probability == pytest.approx(1 / 3)
    assert "no_expected_or_holdout_labels" in first.to_dict()["authority"]
