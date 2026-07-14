"""Heuristics for identifying pthread start routines inside decompiled text."""

from __future__ import annotations

import re
from typing import Iterable, Set


_PTHREAD_CREATE_ARG = re.compile(r"(?:_)?pthread_create\s*\([^,]+,[^,]+,([^,]+),", re.IGNORECASE | re.DOTALL)


def _clean_thread_target(raw: str) -> str:
    """Best-effort cleanup for the pthread start-routine argument."""
    target = raw.strip()
    target = re.sub(r"\([^)]*\)", "", target)
    target = target.replace("&", "").replace("*", "")
    target = target.strip()
    parts = re.split(r"\s+", target)
    if not parts:
        return ""
    candidate = parts[-1].strip(" ,")
    return candidate


def find_thread_start_functions(text: str) -> Set[str]:
    """
    Return the set of symbol names that appear as pthread start routines.

    This is a heuristic that looks for pthread_create calls and attempts to
    parse the third argument into a plausible symbol name.
    """
    results: Set[str] = set()
    if not text:
        return results
    for match in _PTHREAD_CREATE_ARG.findall(text):
        cleaned = _clean_thread_target(match)
        if cleaned:
            results.add(cleaned)
    return results
