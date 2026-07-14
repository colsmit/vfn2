import json
from pathlib import Path

from binary_agent.research_validation import (
    collect_research_preflight,
    run_research_validation,
)


def test_preflight_separates_missing_required_from_external_blocker(tmp_path: Path) -> None:
    rows = collect_research_preflight(
        tmp_path,
        {"PATH": "", "GHIDRA_INSTALL_DIR": str(tmp_path / "missing-ghidra")},
    )
    by_name = {item.name: item for item in rows}

    assert by_name["tool:cc"].status == "missing"
    assert by_name["ghidra"].status == "missing"
    assert by_name["sample:vuln_demo"].status == "missing"
    assert by_name["external:linked_openssl_heartbleed"].status == "external_blocked"


def test_preflight_only_writes_durable_summary_and_latest_pointer(tmp_path: Path) -> None:
    output = tmp_path / "validation"
    result = run_research_validation(
        output,
        repo_root=Path(__file__).resolve().parents[1],
        environment={"PATH": ""},
    )
    latest = json.loads((output / "latest.json").read_text())

    assert result.status == "passed"
    assert result.commands == ()
    assert Path(result.run_dir, "research_validation_summary.json").is_file()
    assert latest["run_id"] == result.run_id
    assert latest["status"] == "passed"
