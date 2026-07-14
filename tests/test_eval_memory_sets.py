import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


_EVAL_PATH = Path(__file__).resolve().parents[1] / "scripts" / "eval_memory_sets.py"
_SPEC = importlib.util.spec_from_file_location("eval_memory_sets", _EVAL_PATH)
eval_memory_sets = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
sys.modules[_SPEC.name] = eval_memory_sets
_SPEC.loader.exec_module(eval_memory_sets)


def _candidate(**overrides):
    data = {
        "function_name": "caller",
        "source_symbol": "",
        "demangled_name": "",
        "line_text": "",
        "evidence": [],
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_target_hit_counts_interprocedural_callsite_line() -> None:
    candidates = [
        _candidate(
            function_name="decNumberCompareTotalMag",
            line_text="decNumberCopy(pdVar3,lhs);",
        )
    ]

    assert eval_memory_sets._target_hit(candidates, "decNumberCopy")


def test_target_hit_does_not_text_match_short_names() -> None:
    candidates = [_candidate(function_name="helper", line_text="main(local_20);")]

    assert not eval_memory_sets._target_hit(candidates, "main")
