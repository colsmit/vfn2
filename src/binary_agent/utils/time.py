"""Small time helpers shared across CLI entry points."""

from __future__ import annotations

from datetime import datetime, timezone


TIMESTAMP_FORMAT = "%Y%m%d-%H%M%S"


def utc_timestamp(fmt: str = TIMESTAMP_FORMAT) -> str:
    """Return a stable UTC timestamp string without naive datetime APIs."""
    return datetime.now(timezone.utc).strftime(fmt)
