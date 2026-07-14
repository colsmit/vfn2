"""Small memory-set domain for deterministic write classification.

The domain intentionally models only facts we can state cheaply:
object identity, byte capacity, byte offsets, and write width.  Unknown
symbolic values stay symbolic instead of being ranked or guessed.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable, Literal, Optional, Sequence


ClassificationStatus = Literal["safe", "candidate", "overflow"]


@dataclass(frozen=True)
class MemObject:
    """A memory object with a known identity and optional fixed capacity."""

    object_id: str
    label: str
    capacity_bytes: int = 0
    kind: str = "stack"
    capacity_expr: str = ""
    capacity_source: str = ""

    @property
    def has_fixed_capacity(self) -> bool:
        return self.capacity_bytes > 0


@dataclass(frozen=True, order=True)
class OffsetInterval:
    """Half-open byte-offset range.

    ``start`` and ``end`` are concrete when known.  The optional ``stride`` is
    retained so loop-like stores can be represented without enumerating bytes.
    """

    start: int
    end: int
    stride: int = 1

    def __post_init__(self) -> None:
        if self.end < self.start:
            raise ValueError("offset interval end must be >= start")
        if self.stride <= 0:
            raise ValueError("offset interval stride must be positive")

    @property
    def empty(self) -> bool:
        return self.start == self.end

    def shifted(self, amount: int) -> "OffsetInterval":
        return OffsetInterval(self.start + amount, self.end + amount, self.stride)

    def intersects(self, other: "OffsetInterval") -> bool:
        return self.start < other.end and other.start < self.end

    def contains_interval(self, other: "OffsetInterval") -> bool:
        return self.start <= other.start and other.end <= self.end


@dataclass(frozen=True)
class OffsetSet:
    """Compact set of possible byte offsets into one memory object."""

    intervals: tuple[OffsetInterval, ...] = ()
    expr: str = ""
    unknown: bool = False

    @classmethod
    def unknown_expr(cls, expr: str = "") -> "OffsetSet":
        return cls(expr=normalize_expr(expr), unknown=True)

    @classmethod
    def single(cls, offset: int, *, expr: str = "") -> "OffsetSet":
        return cls((OffsetInterval(offset, offset + 1),), expr=normalize_expr(expr or str(offset)))

    @classmethod
    def interval(cls, start: int, end: int, *, stride: int = 1, expr: str = "") -> "OffsetSet":
        if start == end:
            return cls(expr=normalize_expr(expr))
        return cls((OffsetInterval(start, end, stride),), expr=normalize_expr(expr))

    @property
    def is_empty(self) -> bool:
        return not self.unknown and not self.intervals

    @property
    def is_concrete(self) -> bool:
        return not self.unknown and bool(self.intervals)

    @property
    def min_start(self) -> Optional[int]:
        if not self.intervals:
            return None
        return min(interval.start for interval in self.intervals)

    @property
    def max_start(self) -> Optional[int]:
        if not self.intervals:
            return None
        return max(interval.end - 1 for interval in self.intervals if not interval.empty)

    def shifted(self, amount: int) -> "OffsetSet":
        if self.unknown:
            return self
        return OffsetSet(tuple(interval.shifted(amount) for interval in self.intervals), self.expr, False)

    def union(self, other: "OffsetSet") -> "OffsetSet":
        if self.unknown or other.unknown:
            expr = " | ".join(item for item in (self.expr, other.expr) if item)
            return OffsetSet.unknown_expr(expr)
        merged: list[OffsetInterval] = []
        for interval in sorted(self.intervals + other.intervals):
            if interval.empty:
                continue
            if not merged:
                merged.append(interval)
                continue
            previous = merged[-1]
            if previous.end >= interval.start and previous.stride == interval.stride:
                merged[-1] = OffsetInterval(previous.start, max(previous.end, interval.end), previous.stride)
            else:
                merged.append(interval)
        expr = " | ".join(item for item in (self.expr, other.expr) if item)
        return OffsetSet(tuple(merged), expr, False)

    def difference(self, other: "OffsetSet") -> "OffsetSet":
        if self.unknown:
            return self
        if other.unknown:
            return OffsetSet(expr=self.expr)
        remaining = list(self.intervals)
        for remove in other.intervals:
            next_remaining: list[OffsetInterval] = []
            for interval in remaining:
                if not interval.intersects(remove):
                    next_remaining.append(interval)
                    continue
                if interval.start < remove.start:
                    next_remaining.append(OffsetInterval(interval.start, min(remove.start, interval.end), interval.stride))
                if remove.end < interval.end:
                    next_remaining.append(OffsetInterval(max(remove.end, interval.start), interval.end, interval.stride))
            remaining = next_remaining
        return OffsetSet(tuple(interval for interval in remaining if not interval.empty), self.expr, False)

    def intersects(self, other: "OffsetSet") -> bool:
        if self.unknown or other.unknown:
            return True
        return any(left.intersects(right) for left in self.intervals for right in other.intervals)

    def subset_of(self, other: "OffsetSet") -> bool:
        if self.unknown:
            return False
        if other.unknown:
            return True
        return all(any(container.contains_interval(item) for container in other.intervals) for item in self.intervals)


@dataclass(frozen=True)
class WriteSet:
    """A byte write into a single memory object."""

    memory: MemObject
    offsets: OffsetSet
    width_bytes: Optional[int] = None
    width_expr: str = ""


@dataclass(frozen=True)
class WriteClassification:
    status: ClassificationStatus
    relation: str
    condition: str

    @property
    def is_candidate(self) -> bool:
        return self.status in {"candidate", "overflow"}


def normalize_expr(expr: str) -> str:
    text = str(expr or "").strip()
    while text.startswith("(") and text.endswith(")") and _matching_paren_is_outer(text):
        text = text[1:-1].strip()
    cast_pattern = re.compile(
        r"\(\s*(?:unsigned\s+|signed\s+)?"
        r"(?:char|short|int|long|ulong|uint|size_t|byte|undefined\d*|"
        r"[A-Za-z_][A-Za-z0-9_]*\s+\*)\s*\*?\s*\)"
    )
    previous = None
    while previous != text:
        previous = text
        text = cast_pattern.sub("", text).strip()
        while text.startswith("(") and text.endswith(")") and _matching_paren_is_outer(text):
            text = text[1:-1].strip()
    text = re.sub(r"\s+", " ", text).strip()
    if text.startswith("+"):
        text = text[1:].strip()
    return text


def offset_set_from_expr(
    expr: str,
    *,
    resolve_int: Optional[Callable[[str], Optional[int]]] = None,
) -> OffsetSet:
    normalized = normalize_expr(expr)
    if not normalized:
        return OffsetSet.single(0, expr="0")
    value = resolve_int(normalized) if resolve_int is not None else eval_int_expr(normalized)
    if value is not None:
        return OffsetSet.single(value, expr=normalized)
    return OffsetSet.unknown_expr(normalized)


def classify_write(write: WriteSet) -> WriteClassification:
    memory = write.memory
    if not memory.object_id:
        return WriteClassification("candidate", "unknown_destination", "write destination identity is unknown")
    if write.width_bytes is None:
        return WriteClassification(
            "candidate",
            "symbolic_size",
            f"write size {write.width_expr or 'unknown'} is not statically bounded",
        )
    if write.width_bytes < 0:
        return WriteClassification("candidate", "symbolic_size", "write size is negative or invalid")
    if not memory.has_fixed_capacity:
        capacity = memory.capacity_expr or "unknown"
        return WriteClassification(
            "candidate",
            "symbolic_capacity",
            f"{memory.label} capacity is modeled by {capacity}, not a fixed byte count",
        )
    capacity = memory.capacity_bytes
    if write.width_bytes > capacity:
        return WriteClassification(
            "overflow",
            "proven_overflow",
            f"write size {write.width_bytes} exceeds {capacity}-byte destination",
        )
    if write.offsets.unknown or not write.offsets.intervals:
        expr = write.offsets.expr or "unknown"
        return WriteClassification(
            "candidate",
            "symbolic_offset",
            f"write offset {expr} is not proven within {capacity}-byte destination",
        )

    safe_start = 0
    safe_end = capacity - write.width_bytes
    min_start = write.offsets.min_start
    max_start = write.offsets.max_start
    if min_start is None or max_start is None:
        return WriteClassification("candidate", "symbolic_offset", "write offset set is empty or unresolved")
    if safe_start <= min_start and max_start <= safe_end:
        return WriteClassification(
            "safe",
            "proven_safe",
            f"write byte range stays within 0..{capacity - 1}",
        )
    if max_start < safe_start or min_start > safe_end:
        return WriteClassification(
            "overflow",
            "proven_overflow",
            _outside_condition(write.offsets, write.width_bytes, capacity),
        )
    return WriteClassification(
        "candidate",
        "symbolic_offset",
        _possible_outside_condition(write.offsets, write.width_bytes, capacity),
    )


def eval_int_expr(expr: str) -> Optional[int]:
    text = normalize_expr(expr)
    if not text:
        return None
    literal = parse_int_literal(text)
    if literal is not None:
        return literal
    if not re.fullmatch(r"[0-9xXa-fA-F+\-*/%() <>&|]+", text):
        return None
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError:
        return None
    try:
        return int(_eval_ast_int(tree.body))
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def parse_int_literal(text: str) -> Optional[int]:
    cleaned = normalize_expr(text)
    if not cleaned:
        return None
    try:
        return int(cleaned, 0)
    except ValueError:
        return None


def _outside_condition(offsets: OffsetSet, width: int, capacity: int) -> str:
    min_start = offsets.min_start
    max_start = offsets.max_start
    if min_start is None or max_start is None:
        return f"write offset is outside {capacity}-byte destination"
    if min_start == max_start:
        return f"write byte range {min_start}..{min_start + width - 1} outside {capacity}-byte destination"
    return (
        f"write offset range {min_start}..{max_start} with width {width} "
        f"is outside {capacity}-byte destination"
    )


def _possible_outside_condition(offsets: OffsetSet, width: int, capacity: int) -> str:
    min_start = offsets.min_start
    max_start = offsets.max_start
    if min_start is None or max_start is None:
        return f"write offset is not proven within {capacity}-byte destination"
    return (
        f"write offset range {min_start}..{max_start} with width {width} "
        f"is not proven within {capacity}-byte destination"
    )


def _matching_paren_is_outer(text: str) -> bool:
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(text) - 1:
                return False
    return depth == 0


def _eval_ast_int(node: ast.AST) -> int:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return int(node.value)
    if isinstance(node, ast.UnaryOp):
        value = _eval_ast_int(node.operand)
        if isinstance(node.op, ast.USub):
            return -value
        if isinstance(node.op, ast.UAdd):
            return value
        if isinstance(node.op, ast.Invert):
            return ~value
    if isinstance(node, ast.BinOp):
        left = _eval_ast_int(node.left)
        right = _eval_ast_int(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.FloorDiv):
            return left // right
        if isinstance(node.op, ast.Div):
            return left // right
        if isinstance(node.op, ast.Mod):
            return left % right
        if isinstance(node.op, ast.LShift):
            return left << right
        if isinstance(node.op, ast.RShift):
            return left >> right
        if isinstance(node.op, ast.BitOr):
            return left | right
        if isinstance(node.op, ast.BitAnd):
            return left & right
        if isinstance(node.op, ast.BitXor):
            return left ^ right
    raise ValueError("unsupported integer expression")
