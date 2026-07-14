"""Environment variable helpers used by experimental workflows."""

from __future__ import annotations

import os
from typing import Any, Callable

try:
    from dotenv import load_dotenv as _load_dotenv
except ModuleNotFoundError:  # pragma: no cover - exercised via monkeypatch in tests
    _load_dotenv: Callable[..., bool] | None = None


def load_dotenv_if_available(*args: Any, **kwargs: Any) -> bool:
    """Load a .env file when python-dotenv is installed."""
    if _load_dotenv is None:
        return False
    return bool(_load_dotenv(*args, **kwargs))


def env_flag(name: str, default: bool = False) -> bool:
    """Parse a boolean environment flag with conservative defaults."""
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default
