import hashlib
import json
from pathlib import Path

from binary_agent.research_matrix import run_registered_matrix


def test_lightweight_research_matrix_is_durable_hashed_and_non_destructive(tmp_path: Path) -> None:
    root = tmp_path / "research"
    first = run_registered_matrix(
        root,
        mode="lightweight",
        run_id="first",
        repo_root=Path(__file__).resolve().parents[1],
    )

    assert first.accepted is True
    assert first.totals["reports"] == 13
    assert first.totals["fixed_reports"] == 0
    assert first.totals["completed_corpora"] == 2
    assert first.totals["skipped_corpora"] == 1
    assert any(item.status == "skipped_requires_full_ghidra" for item in first.corpora)
    for corpus in first.corpora:
        if corpus.status != "completed":
            continue
        summary = Path(corpus.summary_path)
        assert summary.is_file()
        assert hashlib.sha256(summary.read_bytes()).hexdigest() == corpus.summary_sha256
        assert corpus.evidence_artifacts
        for artifact in corpus.evidence_artifacts:
            path = Path(first.run_dir) / artifact["path"]
            assert path.is_file()
            assert hashlib.sha256(path.read_bytes()).hexdigest() == artifact["sha256"]

    second = run_registered_matrix(
        root,
        mode="lightweight",
        run_id="second",
        repo_root=Path(__file__).resolve().parents[1],
    )
    latest = json.loads((root / "latest.json").read_text())

    assert Path(first.run_dir).is_dir()
    assert Path(second.run_dir).is_dir()
    assert latest["run_id"] == "second"
    assert latest["accepted"] is True
    summary_path = Path(latest["summary_path"])
    assert hashlib.sha256(summary_path.read_bytes()).hexdigest() == latest["summary_sha256"]
