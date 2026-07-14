"""Run deterministic analysis on an existing Ghidra export."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from binary_agent.analysis.candidates import run_static_pipeline
from binary_agent.reporting import save_report_json, write_markdown_reports
from binary_agent.reporting.models import AnalysisReport


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run deterministic diagnostic analysis on an existing Ghidra export."
    )
    parser.add_argument("export_dir", type=Path, help="Path to the decompiled export directory.")
    parser.add_argument("--output", type=Path, default=None, help="Where to write the combined JSON report.")
    parser.add_argument("--skip", type=int, default=0, help="Skip the first N functions before analysis.")
    parser.add_argument("--sample", type=int, default=None, help="Limit analysis to N functions after skipping.")
    parser.add_argument("--operation-specs", type=Path, default=None, help="Override operation_specs.json path.")
    parser.add_argument("--analysis-cache-dir", type=Path, default=None, help="Directory for analysis cache files.")
    parser.add_argument(
        "--persist-debug-facts",
        action="store_true",
        help="Persist debug-only suppressed findings alongside public artifacts.",
    )
    parser.add_argument("--write-evidence-packs", type=Path, default=None, help="Directory for evidence-pack JSON files.")
    parser.add_argument("--confirmation-dir", type=Path, default=None, help="Directory containing replay confirmations.")
    parser.add_argument(
        "--report-policy",
        choices=("deterministic", "confirmed"),
        default=None,
        help="Use deterministic diagnostics or report only externally confirmed candidates.",
    )
    parser.add_argument("--report-dir", type=Path, default=None, help="Directory for Markdown reports.")
    return parser.parse_args()


def run_pipeline(
    export_dir: Path,
    *,
    skip: int = 0,
    sample: Optional[int] = None,
    operation_specs_path: Optional[Path] = None,
    persist_debug_facts: bool = False,
    cache_dir: Optional[Path] = None,
    write_evidence_packs_dir: Optional[Path] = None,
    confirmation_dir: Optional[Path] = None,
    report_policy: Optional[str] = None,
) -> AnalysisReport:
    """Analyze an export without decompiling or running proof/replay stages.

    The production proof path is ``binary_agent.cli.toolchain``.  This function
    remains the narrow diagnostic path for already-produced exports and for
    loading replay confirmations produced elsewhere.
    """
    return run_static_pipeline(
        export_dir,
        skip=skip,
        sample=sample,
        operation_specs_path=operation_specs_path,
        persist_debug_facts=persist_debug_facts,
        cache_dir=cache_dir,
        write_evidence_packs_dir=write_evidence_packs_dir,
        confirmation_dir=confirmation_dir,
        report_policy=report_policy,
    )


def main() -> None:
    args = parse_args()
    report = run_pipeline(
        args.export_dir,
        skip=args.skip,
        sample=args.sample,
        operation_specs_path=args.operation_specs,
        persist_debug_facts=args.persist_debug_facts,
        cache_dir=args.analysis_cache_dir,
        write_evidence_packs_dir=args.write_evidence_packs,
        confirmation_dir=args.confirmation_dir,
        report_policy=args.report_policy,
    )

    output_path: Optional[Path] = None
    if args.output:
        output_path = args.output.resolve()
        save_report_json(report, output_path)
        print(f"[+] Report saved to {output_path}")
    else:
        print(json.dumps(report.to_dict(), indent=2))

    if args.report_dir:
        report_dir = args.report_dir.resolve()
    elif output_path:
        report_dir = output_path.parent / f"{output_path.stem}_reports"
    else:
        report_dir = Path("runs") / f"{report.config.binary}_{report.config.run_label}_reports"
    write_markdown_reports(report.vulnerability_reports, report_dir, report.config)
    issue_count = len(report.vulnerability_reports)
    print(f"[+] Vulnerability reports saved to {report_dir} ({issue_count} issue{'s' if issue_count != 1 else ''})")


if __name__ == "__main__":
    main()
