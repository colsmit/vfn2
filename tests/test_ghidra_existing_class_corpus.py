import os
from pathlib import Path

import pytest

from binary_agent.corpus_runner import load_corpus_manifest, run_corpus


MANIFEST = Path(__file__).parent / "fixtures" / "schema2_ghidra_completeness" / "manifest.json"
GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR", ""))
RUN_GHIDRA = os.environ.get("BINARY_AGENT_RUN_GHIDRA_VALIDATION") == "1"


@pytest.mark.skipif(
    not RUN_GHIDRA or not (GHIDRA_DIR / "support" / "analyzeHeadless").exists(),
    reason="set BINARY_AGENT_RUN_GHIDRA_VALIDATION=1 and GHIDRA_INSTALL_DIR to run the full stripped-binary matrix",
)
def test_full_ghidra_existing_class_pairs_report_only_vulnerable_lanes(tmp_path: Path) -> None:
    summary = run_corpus(load_corpus_manifest(MANIFEST), tmp_path / "run", mode="full")

    assert summary.accepted is True
    assert summary.totals["candidates"] == 5
    assert summary.totals["proven"] == 5
    assert summary.totals["reports"] == 5
    assert summary.totals["fixed_reports"] == 0
    assert not summary.errors
