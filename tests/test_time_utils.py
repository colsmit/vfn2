from __future__ import annotations

from datetime import datetime

from binary_agent.utils.time import TIMESTAMP_FORMAT, utc_timestamp


def test_utc_timestamp_matches_default_format() -> None:
    timestamp = utc_timestamp()

    assert datetime.strptime(timestamp, TIMESTAMP_FORMAT).strftime(TIMESTAMP_FORMAT) == timestamp
