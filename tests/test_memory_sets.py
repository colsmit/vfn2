from binary_agent.analysis.memory_sets import (
    MemObject,
    OffsetSet,
    WriteSet,
    classify_write,
    offset_set_from_expr,
)


def _object(size: int = 16) -> MemObject:
    return MemObject(object_id="stack:buf", label="buf", capacity_bytes=size)


def test_constant_write_inside_capacity_is_safe() -> None:
    result = classify_write(WriteSet(_object(), OffsetSet.single(4), width_bytes=4, width_expr="4"))

    assert result.status == "safe"
    assert result.relation == "proven_safe"


def test_constant_write_past_capacity_is_overflow() -> None:
    result = classify_write(WriteSet(_object(), OffsetSet.single(14), width_bytes=4, width_expr="4"))

    assert result.status == "overflow"
    assert result.relation == "proven_overflow"


def test_symbolic_offset_with_known_object_is_candidate() -> None:
    result = classify_write(WriteSet(_object(), offset_set_from_expr("i"), width_bytes=1, width_expr="1"))

    assert result.status == "candidate"
    assert result.relation == "symbolic_offset"


def test_interval_that_may_leave_capacity_is_candidate() -> None:
    result = classify_write(WriteSet(_object(), OffsetSet.interval(0, 20, expr="0..19"), width_bytes=1))

    assert result.status == "candidate"
    assert result.relation == "symbolic_offset"


def test_interval_entirely_past_capacity_is_overflow() -> None:
    result = classify_write(WriteSet(_object(), OffsetSet.interval(20, 24, expr="20..23"), width_bytes=1))

    assert result.status == "overflow"
    assert result.relation == "proven_overflow"


def test_offset_set_union_and_difference_stay_compact() -> None:
    offsets = OffsetSet.interval(0, 8).union(OffsetSet.interval(8, 16))
    remaining = offsets.difference(OffsetSet.interval(4, 12))

    assert offsets.intervals == (OffsetSet.interval(0, 16).intervals[0],)
    assert remaining.intervals == (
        OffsetSet.interval(0, 4).intervals[0],
        OffsetSet.interval(12, 16).intervals[0],
    )


def test_width_larger_than_capacity_is_overflow_even_with_symbolic_offset() -> None:
    result = classify_write(WriteSet(_object(), offset_set_from_expr("used"), width_bytes=32, width_expr="32"))

    assert result.status == "overflow"
    assert result.relation == "proven_overflow"
