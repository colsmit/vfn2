from __future__ import annotations

import hashlib
import json
from pathlib import Path

from binary_agent.portfolio_benchmark import (
    portfolio_oracle_bound,
    prepare_firmware_rootfs_fixture,
)


def test_portfolio_oracle_bound_is_evaluation_only_and_budgeted() -> None:
    cases = [
        {"candidate_id": "positive-b", "expected_report": True},
        {"candidate_id": "unknown", "expected_report": None},
        {"candidate_id": "positive-a", "expected_report": True},
        {"candidate_id": "negative", "expected_report": False},
    ]
    bound = portfolio_oracle_bound(cases, 1)
    assert bound["max_reports"] == 1
    assert bound["selected_candidate_ids"] == ["positive-a"]
    assert "evaluation_only" in bound["authority"]


def test_prepare_firmware_rootfs_fixture_preserves_frozen_binary_hashes(tmp_path: Path) -> None:
    binaries = tmp_path / "binaries"
    binaries.mkdir()
    cases = []
    for case_id in ("cwe415-free-vulnerable", "cwe415-free-fixed"):
        binary = binaries / case_id
        binary.write_bytes(case_id.encode())
        cases.append(
            {
                "id": case_id,
                "binary_path": str(binary.relative_to(tmp_path)),
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            }
        )
    source_manifest = tmp_path / "frozen_manifest.json"
    source_manifest.write_text(json.dumps({"cases": cases}))
    fixture = prepare_firmware_rootfs_fixture(source_manifest, tmp_path / "fixture")
    payload = json.loads(fixture.read_text())
    assert [item["expected_reports"] for item in payload["cases"]] == [1, 0]
    assert (fixture.parent / "rootfs/usr/bin/double-free-vulnerable").is_file()
    assert (fixture.parent / "rootfs/usr/bin/double-free-fixed").is_file()
