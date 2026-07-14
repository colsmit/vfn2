#!/usr/bin/env python3
"""Run a small report-backed corpus of known overflow binaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


TRUE_OVERFLOW_LANE = "true_overflow"
DIAGNOSTIC_LANE = "diagnostic"
NEGATIVE_LANE = "negative"
KNOWN_LANES = {TRUE_OVERFLOW_LANE, DIAGNOSTIC_LANE, NEGATIVE_LANE}
DEFAULT_CORPUS_STAGES = "intake,discovery,refinement,proof,replay,report"
DEFAULT_LLM_CORPUS_STAGES = "intake,discovery,refinement,hypothesis,proof,replay,report"
DEFAULT_LLM_HYPOTHESIS_CALLS_PER_RUN = 8
DEFAULT_REGRESSION_SUBSET_IDS = {
    "gzip-1.2.4",
    "sharutils-4.2.1-shar",
    "sharutils-4.2.1-unshar",
    "tar-1.34-cve-2022-48303-from-header",
    "unzip-5.50-wildzipfn",
    "goahead-2.1-cve-2002-1951-http-get",
    "guarded-heartbleed-slice",
}

DEFAULT_CASES: list[dict[str, Any]] = [
    {
        "id": "ncompress-4.2.4-compress",
        "binary": "tmp/known_overflow_sources/ncompress-4.2.4/compress_stripped",
        "lane": TRUE_OVERFLOW_LANE,
        "vuln_family": "stack_overflow",
        "expected_issue_count": 1,
        "expected_overflow_witnesses": 1,
    },
    {
        "id": "gzip-1.2.4",
        "binary": "tmp/known_overflow_sources/gzip-1.2.4/gzip_stripped",
        "lane": TRUE_OVERFLOW_LANE,
        "vuln_family": "out_of_bounds_write",
        "expected_outcome": "caught",
        "expected_issue_count": 1,
        "expected_overflow_witnesses": 1,
    },
    {
        "id": "gzip-1.2.4-gunzip",
        "binary": "tmp/known_overflow_sources/gzip-1.2.4/gunzip_stripped",
        "lane": TRUE_OVERFLOW_LANE,
        "vuln_family": "out_of_bounds_write",
        "expected_outcome": "caught",
        "expected_issue_count": 1,
        "expected_overflow_witnesses": 1,
    },
    {
        "id": "gzip-1.2.4-zcat",
        "binary": "tmp/known_overflow_sources/gzip-1.2.4/zcat_stripped",
        "lane": TRUE_OVERFLOW_LANE,
        "vuln_family": "out_of_bounds_write",
        "expected_outcome": "caught",
        "expected_issue_count": 1,
        "expected_overflow_witnesses": 1,
    },
    {
        "id": "sharutils-4.2.1-shar",
        "binary": "tmp/known_overflow_sources/sharutils-4.2.1/src/shar_stripped",
        "lane": TRUE_OVERFLOW_LANE,
        "vuln_family": "out_of_bounds_write",
        "expected_outcome": "caught",
        "expected_issue_count": 1,
        "expected_overflow_witnesses": 1,
    },
    {
        "id": "sharutils-4.2.1-unshar",
        "binary": "tmp/known_overflow_sources/sharutils-4.2.1/src/unshar_stripped",
        "lane": TRUE_OVERFLOW_LANE,
        "vuln_family": "stack_overflow",
        "expected_outcome": "caught",
        "expected_issue_count": 1,
        "expected_overflow_witnesses": 1,
    },
    {
        "id": "unarj-2.63a-arj-filename",
        "binary": "tmp/known_overflow_sources/unarj-2.63a/unarj_stripped",
        "lane": DIAGNOSTIC_LANE,
        "vuln_family": "diagnostic_static_false_positive",
        "diagnostic_kind": "static_false_positive_bounded_copy",
        "expected_outcome": "known_miss",
        "known_issue_count": 0,
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
        "expected_failure_reason": "timeout",
        "allow_backend_missing_known_miss": True,
        "failure_detail": "arj_filename_copy_bounded_by_strncopy_not_a_true_overflow",
    },
    {
        "id": "ncompress-4.2.4-readdir-name",
        "binary": "tmp/known_overflow_sources/ncompress-4.2.4/compress_stripped",
        "lane": DIAGNOSTIC_LANE,
        "vuln_family": "diagnostic_unsupported_input_source",
        "diagnostic_kind": "unsupported_directory_iteration_source",
        "expected_outcome": "known_miss",
        "known_issue_count": 0,
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
        "expected_failure_reason": "backend_error",
        "failure_detail": "directory-entry names remain unsupported process input, not a confirmed overflow",
        "proof_timeout_seconds": 45.0,
        "proof_dynamic_max_steps": 30000,
    },
    {
        "id": "sharutils-4.2.1-uudecode-sscanf-split-stack",
        "binary": "tmp/known_overflow_sources/sharutils-4.2.1/src/uudecode_stripped",
        "lane": DIAGNOSTIC_LANE,
        "vuln_family": "diagnostic_split_stack_false_witness",
        "diagnostic_kind": "split_stack_unbounded_scanf_false_witness",
        "expected_outcome": "known_miss",
        "known_issue_count": 0,
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
        "expected_failure_reason": "timeout",
        "allow_backend_missing_known_miss": True,
        "failure_detail": "bounded fgets source cannot overflow the recovered 16 KiB stack aggregate",
        "proof_timeout_seconds": 45.0,
        "proof_dynamic_max_steps": 30000,
    },
    {
        "id": "sharutils-4.15.2-unshar-cve-2018-1000097",
        "binary": "tmp/known_overflow_sources/sharutils-4.15.2/src/unshar_stripped",
        "lane": DIAGNOSTIC_LANE,
        "vuln_family": "diagnostic_heap_overflow_known_miss",
        "diagnostic_kind": "source_backed_heap_overflow_not_native",
        "known_vuln_family": "heap_overflow",
        "expected_outcome": "known_miss",
        "known_issue_count": 1,
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
        "expected_failure_reason": "backend_error",
        "allow_backend_missing_known_miss": True,
        "failure_detail": "CVE-2018-1000097 is a source-backed unshar heap overflow; current proof produced no replay-backed report.",
        "proof_timeout_seconds": 45.0,
        "proof_dynamic_max_steps": 30000,
    },
    {
        "id": "tar-1.34-cve-2022-48303-from-header",
        "binary": "tmp/known_overflow_sources/tar-1.34/src/tar_stripped",
        "lane": TRUE_OVERFLOW_LANE,
        "vuln_family": "out_of_bounds_read",
        "known_vuln_family": "out_of_bounds_read",
        "expected_outcome": "caught",
        "known_issue_count": 1,
        "expected_issue_count": 1,
        "expected_overflow_witnesses": 1,
        "proof_timeout_seconds": 45.0,
        "proof_dynamic_max_steps": 30000,
        "case_timeout_seconds": 360.0,
    },
    {
        "id": "tiff-3.9.4-tiff2pdf-cve-2012-2113",
        "binary": "tmp/known_overflow_sources/tiff-3.9.4/tools/tiff2pdf_stripped",
        "lane": DIAGNOSTIC_LANE,
        "vuln_family": "diagnostic_integer_heap_overflow_known_miss",
        "diagnostic_kind": "source_backed_integer_heap_overflow_not_native",
        "known_vuln_family": "integer_overflow_to_heap_overflow",
        "expected_outcome": "known_miss",
        "known_issue_count": 1,
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
        "expected_failure_reason": "backend_error",
        "allow_backend_missing_known_miss": True,
        "failure_detail": "CVE-2012-2113 is a source-backed tiff2pdf integer overflow leading to heap overflow; current proof produced no replay-backed report.",
        "proof_timeout_seconds": 45.0,
        "proof_dynamic_max_steps": 30000,
    },
    {
        "id": "unzip-5.50-wildzipfn",
        "binary": "tmp/known_overflow_sources/unzip-5.50/unzip_stripped",
        "lane": TRUE_OVERFLOW_LANE,
        "vuln_family": "out_of_bounds_write",
        "expected_outcome": "caught",
        "expected_issue_count": 1,
        "expected_overflow_witnesses": 1,
        "proof_timeout_seconds": 90.0,
        "proof_dynamic_max_steps": 100000,
        "case_timeout_seconds": 240.0,
    },
    {
        "id": "goahead-2.1-cve-2002-1951-http-get",
        "binary": "tmp/known_overflow_sources/goahead-2.1/LINUX/webs_stripped",
        "lane": DIAGNOSTIC_LANE,
        "vuln_family": "diagnostic_http_daemon_known_overflow",
        "diagnostic_kind": "source_backed_http_daemon_overflow_not_native",
        "known_vuln_family": "out_of_bounds_write",
        "expected_outcome": "known_miss",
        "known_issue_count": 1,
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
        "expected_failure_reason": "backend_error",
        "allow_backend_missing_known_miss": True,
        "failure_detail": "CVE-2002-1951 is a source-backed GoAhead HTTP daemon overflow; current full static proof pipeline has not produced a replay-backed report.",
        "proof_timeout_seconds": 45.0,
        "proof_dynamic_max_steps": 30000,
        "process_input_model": "http_daemon",
        "replay_hints": {
            "http_daemon": {"port": 18080, "method": "GET", "path": "/{payload}"},
        },
    },
    {
        "id": "guarded-heartbleed-slice",
        "binary": "tmp/negative_overflow_sources/guarded_heartbleed/guarded_heartbleed_stripped",
        "lane": NEGATIVE_LANE,
        "vuln_family": "guarded_out_of_bounds_read",
        "expected_outcome": "clean",
        "expected_issue_count": 0,
        "expected_overflow_witnesses": 0,
        "expected_suppression_reason": "no_reported_candidates",
    },
]

DEFAULT_KNOWN_VULN_FAMILIES = {
    "ncompress-4.2.4-compress": "stack_overflow",
    "gzip-1.2.4": "out_of_bounds_write",
    "gzip-1.2.4-gunzip": "out_of_bounds_write",
    "gzip-1.2.4-zcat": "out_of_bounds_write",
    "sharutils-4.2.1-shar": "out_of_bounds_write",
    "sharutils-4.2.1-unshar": "stack_overflow",
    "unzip-5.50-wildzipfn": "out_of_bounds_write",
    "goahead-2.1-cve-2002-1951-http-get": "out_of_bounds_write",
    "sharutils-4.15.2-unshar-cve-2018-1000097": "heap_overflow",
    "tar-1.34-cve-2022-48303-from-header": "out_of_bounds_read",
    "tiff-3.9.4-tiff2pdf-cve-2012-2113": "integer_overflow_to_heap_overflow",
}

CASE_PROVENANCE: dict[str, dict[str, Any]] = {
    "ncompress-4.2.4-compress": {
        "package": "ncompress",
        "version": "4.2.4",
        "source_url": "https://downloads.sourceforge.net/project/ncompress/old%20releases/ncompress-4.2.4.tar.gz",
        "advisory_ids": ["VU#176363"],
        "advisory_urls": ["https://www.kb.cert.org/vuls/id/176363"],
        "fix_reference_urls": [],
        "source_file": "compress42.c",
        "source_function": "main",
        "evidence_summary": "Long filename is copied into fixed stack path buffers with strcpy/strcat.",
    },
    "gzip-1.2.4": {
        "package": "gzip",
        "version": "1.2.4",
        "source_url": "https://ftp.gnu.org/gnu/gzip/gzip-1.2.4.tar.gz",
        "advisory_ids": ["gzip-upstream-ancient-advisory"],
        "advisory_urls": ["https://www.gzip.org/ancient/"],
        "fix_reference_urls": ["https://www.gzip.org/ancient/"],
        "source_file": "gzip.c",
        "source_function": "treat_file",
        "evidence_summary": "Long input filename reaches fixed global filename buffers through strcpy.",
    },
    "gzip-1.2.4-gunzip": {
        "package": "gzip",
        "version": "1.2.4",
        "source_url": "https://ftp.gnu.org/gnu/gzip/gzip-1.2.4.tar.gz",
        "advisory_ids": ["gzip-upstream-ancient-advisory"],
        "advisory_urls": ["https://www.gzip.org/ancient/"],
        "fix_reference_urls": ["https://www.gzip.org/ancient/"],
        "source_file": "gzip.c",
        "source_function": "treat_file",
        "evidence_summary": "gunzip shares gzip's fixed filename buffer copy path.",
    },
    "gzip-1.2.4-zcat": {
        "package": "gzip",
        "version": "1.2.4",
        "source_url": "https://ftp.gnu.org/gnu/gzip/gzip-1.2.4.tar.gz",
        "advisory_ids": ["gzip-upstream-ancient-advisory"],
        "advisory_urls": ["https://www.gzip.org/ancient/"],
        "fix_reference_urls": ["https://www.gzip.org/ancient/"],
        "source_file": "gzip.c",
        "source_function": "treat_file",
        "evidence_summary": "zcat shares gzip's fixed filename buffer copy path.",
    },
    "sharutils-4.2.1-shar": {
        "package": "sharutils",
        "version": "4.2.1",
        "source_url": "https://ftp.gnu.org/gnu/sharutils/sharutils-4.2.1.tar.gz",
        "advisory_ids": ["CVE-2004-1772"],
        "advisory_urls": ["https://security-tracker.debian.org/tracker/source-package/sharutils"],
        "fix_reference_urls": [],
        "source_file": "src/shar.c",
        "source_function": "main",
        "evidence_summary": "Long option value reaches fixed output_base_name storage through strcpy.",
    },
    "sharutils-4.2.1-unshar": {
        "package": "sharutils",
        "version": "4.2.1",
        "source_url": "https://ftp.gnu.org/gnu/sharutils/sharutils-4.2.1.tar.gz",
        "advisory_ids": ["CVE-2004-1773"],
        "advisory_urls": ["https://security-tracker.debian.org/tracker/source-package/sharutils"],
        "fix_reference_urls": [],
        "source_file": "src/unshar.c",
        "source_function": "main",
        "evidence_summary": "Input path reaches NAME_BUFFER_SIZE stack buffers through stpcpy.",
    },
    "unarj-2.63a-arj-filename": {
        "package": "unarj",
        "version": "2.63a",
        "source_url": "https://www.ibiblio.org/pub/Linux/utils/compress/unarj-2.63a.tar.gz",
        "advisory_ids": [],
        "advisory_urls": [],
        "fix_reference_urls": [],
        "source_file": "unarj.c",
        "source_function": "read_header",
        "evidence_summary": "Diagnostic false positive: archive filename is copied with bounded strncopy before later strcpy uses.",
    },
    "ncompress-4.2.4-readdir-name": {
        "package": "ncompress",
        "version": "4.2.4",
        "source_url": "https://downloads.sourceforge.net/project/ncompress/old%20releases/ncompress-4.2.4.tar.gz",
        "advisory_ids": ["VU#176363"],
        "advisory_urls": ["https://www.kb.cert.org/vuls/id/176363"],
        "fix_reference_urls": [],
        "source_file": "compress42.c",
        "source_function": "compdir",
        "evidence_summary": "Diagnostic known miss: directory entry names remain unsupported process input.",
    },
    "sharutils-4.2.1-uudecode-sscanf-split-stack": {
        "package": "sharutils",
        "version": "4.2.1",
        "source_url": "https://ftp.gnu.org/gnu/sharutils/sharutils-4.2.1.tar.gz",
        "advisory_ids": [],
        "advisory_urls": [],
        "fix_reference_urls": [],
        "source_file": "src/uudecode.c",
        "source_function": "main",
        "evidence_summary": "Diagnostic false witness: sscanf target is fed by bounded fgets into a large stack buffer.",
    },
    "sharutils-4.15.2-unshar-cve-2018-1000097": {
        "package": "sharutils",
        "version": "4.15.2",
        "source_url": "https://ftp.gnu.org/gnu/sharutils/sharutils-4.15.2.tar.gz",
        "advisory_ids": ["CVE-2018-1000097"],
        "advisory_urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-1000097",
            "https://lists.gnu.org/archive/html/bug-gnu-utils/2018-02/msg00004.html",
        ],
        "fix_reference_urls": ["https://lists.gnu.org/archive/html/bug-gnu-utils/2018-02/msg00005.html"],
        "source_file": "src/unshar.c",
        "source_function": "looks_like_c_code",
        "evidence_summary": "Source-backed heap overflow in unshar C-code detection path; current binary pipeline emits no report.",
    },
    "tar-1.34-cve-2022-48303-from-header": {
        "package": "tar",
        "version": "1.34",
        "source_url": "https://ftp.gnu.org/gnu/tar/tar-1.34.tar.gz",
        "advisory_ids": ["CVE-2022-48303"],
        "advisory_urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-48303",
            "https://security-tracker.debian.org/tracker/CVE-2022-48303",
        ],
        "fix_reference_urls": ["https://security-tracker.debian.org/tracker/CVE-2022-48303"],
        "source_file": "src/list.c",
        "source_function": "from_header",
        "evidence_summary": "Source-backed one-byte OOB read in trailing-NUL trimming of tar header numeric fields.",
    },
    "tiff-3.9.4-tiff2pdf-cve-2012-2113": {
        "package": "libtiff",
        "version": "3.9.4",
        "source_url": "https://download.osgeo.org/libtiff/old/tiff-3.9.4.tar.gz",
        "advisory_ids": ["CVE-2012-2113"],
        "advisory_urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2012-2113",
            "https://security-tracker.debian.org/tracker/CVE-2012-2113",
        ],
        "fix_reference_urls": ["https://security-tracker.debian.org/tracker/CVE-2012-2113"],
        "source_file": "tools/tiff2pdf.c",
        "source_function": "t2p_read_tiff_data",
        "evidence_summary": "Source-backed integer overflow in tiff2pdf size computation can lead to heap overflow.",
    },
    "unzip-5.50-wildzipfn": {
        "package": "unzip",
        "version": "5.50",
        "source_url": "https://ifarchive.org/if-archive/download-tools/unzip550.tar.gz",
        "advisory_ids": ["CVE-2005-4667"],
        "advisory_urls": ["https://nvd.nist.gov/vuln/detail/CVE-2005-4667"],
        "fix_reference_urls": [],
        "source_file": "unix/unix.c",
        "source_function": "do_wild",
        "evidence_summary": "Long wildcard zip filename reaches fixed matchname buffer through strcpy.",
    },
    "goahead-2.1-cve-2002-1951-http-get": {
        "package": "GoAhead WebServer",
        "version": "2.1",
        "source_url": "https://github.com/trenta3/goahead-versions/blob/master/00828427Webs21.tar.gz",
        "advisory_ids": ["CVE-2002-1951"],
        "advisory_urls": [
            "https://github.com/advisories/GHSA-pjq4-wc4r-3mcf",
            "https://vulmon.com/searchpage?q=goahead%20webserver%202.1",
        ],
        "fix_reference_urls": [],
        "source_file": "webs.c",
        "source_function": "websUrlHandlerRequest",
        "evidence_summary": "Remote HTTP GET path with many subdirectories is a source-backed GoAhead WebServer 2.1 buffer-overflow advisory case.",
    },
    "guarded-heartbleed-slice": {
        "package": "guarded-heartbleed-slice",
        "version": "local",
        "source_url": "local_fixture",
        "advisory_ids": [],
        "advisory_urls": [],
        "fix_reference_urls": [],
        "source_file": "tmp/negative_overflow_sources/guarded_heartbleed",
        "source_function": "main",
        "evidence_summary": "Negative fixture: bounds guard prevents the modeled Heartbleed-style read from reporting.",
    },
}

REQUIRED_PROVENANCE_FIELDS = (
    "package",
    "version",
    "source_url",
    "source_file",
    "source_function",
    "evidence_summary",
)

FROZEN_MANIFEST_SCHEMA_VERSION = 1
FROZEN_CASE_FIELDS = {
    "id",
    "binary",
    "binary_sha256",
    "lane",
    "expected_outcome",
    "vuln_family",
    "known_vuln_family",
    "provenance",
    "process_input_model",
    "replay_hints",
}
FORBIDDEN_FROZEN_CASE_FIELDS = {
    "address",
    "candidate_id",
    "candidate_ids",
    "expected_failure_reason",
    "expected_overflow_witnesses",
    "function_address",
    "operation_address",
    "proof_target_candidate_id",
    "sink_address",
}
BLOCKING_FAILURE_REASONS = {
    "backend_error",
    "missing_binary",
    "missing_run_dir",
    "proof_timeout",
    "timeout",
}
ANALYZER_INPUTS = ("src", "scripts", "ghidra_scripts", "pyproject.toml")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, help="Optional JSON file with a cases list.")
    parser.add_argument(
        "--write-frozen-manifest",
        type=Path,
        help="Hash an external corpus and the current analyzer, write the frozen manifest, and exit.",
    )
    parser.add_argument("--case", action="append", dest="case_ids", help="Run only this case id. Repeatable.")
    parser.add_argument("--lane", action="append", choices=sorted(KNOWN_LANES), help="Run only this corpus lane.")
    parser.add_argument(
        "--regression-subset",
        action="store_true",
        help="Run a stable subset of the development regression corpus.",
    )
    parser.add_argument("--output-root", type=Path, default=Path("tmp/known_overflow_corpus"))
    parser.add_argument("--cache-dir", type=Path, default=Path("cache/decomp"))
    parser.add_argument("--stages", default=DEFAULT_CORPUS_STAGES, help="Toolchain stages for cases without an override.")
    parser.add_argument(
        "--full-llm-path",
        action="store_true",
        help="Use the full evidence->hypothesis->replay/repair->report stages and default live providers when not overridden.",
    )
    parser.add_argument("--proof-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--proof-dynamic-max-steps", type=int, default=20000)
    parser.add_argument("--proof-jobs", type=int, default=1)
    parser.add_argument("--proof-memory-limit-mb", type=int, default=8192)
    parser.add_argument("--ghidra-dir", type=Path, help="Ghidra install used by proof stages. Defaults to repo-local ghidra_downloads.")
    parser.add_argument("--case-timeout-seconds", type=float, default=0.0)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--summary", type=Path, help="Summary JSON path. Defaults under output-root.")
    parser.add_argument("--require-passed", type=int, default=None, help="Fail unless at least this many cases pass.")
    parser.add_argument(
        "--require-true-overflow-passed",
        type=int,
        default=None,
        help="Fail unless at least this many true-overflow cases pass.",
    )
    parser.add_argument(
        "--require-diagnostics-passed",
        type=int,
        default=None,
        help="Fail unless at least this many diagnostic cases pass.",
    )
    parser.add_argument(
        "--require-negative-passed",
        type=int,
        default=None,
        help="Fail unless at least this many negative cases pass.",
    )
    parser.add_argument(
        "--require-regression-subset-passed",
        type=int,
        default=None,
        help="Fail unless at least this many cases in the regression subset pass.",
    )
    parser.add_argument(
        "--require-family-passed",
        action="append",
        default=[],
        metavar="FAMILY=COUNT",
        help="Fail unless at least COUNT cases in vulnerability family FAMILY pass. Repeatable.",
    )
    parser.add_argument(
        "--require-known-vuln-family-passed",
        action="append",
        default=[],
        metavar="FAMILY=COUNT",
        help="Fail unless at least COUNT source-backed known-vulnerability family cases pass. Repeatable.",
    )
    parser.add_argument(
        "--require-provenance",
        action="store_true",
        help="Fail unless every selected case has the required source provenance fields.",
    )
    parser.add_argument("--llm-hypothesis-provider-command", default="", help="Provider command for hypothesis stage; auto uses bundled live provider.")
    parser.add_argument("--llm-hypothesis-fixtures", type=Path, default=None, help="Fixture directory for hypothesis stage.")
    parser.add_argument("--llm-hypothesis-systems", default="L2", help="Comma-separated hypothesis systems for corpus runs.")
    parser.add_argument("--llm-hypothesis-provider-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--hypothesis-policy", choices=("blocked-only", "always", "off"), default="blocked-only")
    parser.add_argument("--max-hypothesis-calls-per-run", type=int, default=DEFAULT_LLM_HYPOTHESIS_CALLS_PER_RUN)
    parser.add_argument("--max-hypothesis-calls-per-candidate", type=int, default=1)
    parser.add_argument("--llm-repair-provider-command", default="", help="Replay repair provider command; auto uses bundled live provider.")
    parser.add_argument("--llm-repair-provider-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--llm-repair-max-attempts", type=int, default=2)
    parser.add_argument("--require-live-llm", action="store_true", help="Forward live-LLM enforcement to toolchain.")
    return parser.parse_args(argv)


def load_cases(manifest: Path | None) -> list[dict[str, Any]]:
    if manifest is None:
        return [dict(case) for case in DEFAULT_CASES]
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    cases = payload.get("cases") if isinstance(payload, dict) else payload
    if not isinstance(cases, list):
        raise ValueError(f"{manifest} must contain a JSON list or an object with a cases list")
    return [dict(case) for case in cases]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyzer_sha256(repo_root: Path) -> str:
    """Hash the analyzer inputs using stable relative paths and file bytes."""
    files: list[Path] = []
    for name in ANALYZER_INPUTS:
        path = repo_root / name
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file()
                and "__pycache__" not in candidate.parts
                and candidate.suffix not in {".pyc", ".pyo"}
            )
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: item.relative_to(repo_root).as_posix()):
        relative = path.relative_to(repo_root).as_posix().encode("utf-8")
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def _manifest_payload(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _external_binary_path(manifest: Path, case: Mapping[str, Any]) -> Path:
    raw_path = str(case.get("binary") or "")
    if not raw_path:
        raise ValueError(f"case {case.get('id') or '<unknown>'} is missing binary")
    path = Path(raw_path)
    return path if path.is_absolute() else manifest.parent / path


def _validate_external_cases(cases: Any, *, require_hash: bool) -> list[dict[str, Any]]:
    if not isinstance(cases, list) or not cases:
        raise ValueError("frozen corpus must contain a non-empty cases list")
    validated: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw_case in enumerate(cases):
        if not isinstance(raw_case, Mapping):
            raise ValueError(f"case {index} must be a JSON object")
        case = dict(raw_case)
        case_id = str(case.get("id") or "")
        if not case_id:
            raise ValueError(f"case {index} is missing id")
        if case_id in seen_ids:
            raise ValueError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        forbidden = sorted(FORBIDDEN_FROZEN_CASE_FIELDS.intersection(case))
        unsupported = sorted(set(case) - FROZEN_CASE_FIELDS)
        if forbidden:
            raise ValueError(f"case {case_id} contains forbidden internal field(s): {', '.join(forbidden)}")
        if unsupported:
            raise ValueError(f"case {case_id} contains unsupported field(s): {', '.join(unsupported)}")
        lane = str(case.get("lane") or "")
        outcome = str(case.get("expected_outcome") or "")
        if (lane, outcome) not in {
            (TRUE_OVERFLOW_LANE, "caught"),
            (NEGATIVE_LANE, "clean"),
        }:
            raise ValueError(
                f"case {case_id} must be true_overflow/caught or negative/clean, got {lane or '-'} / {outcome or '-'}"
            )
        if not str(case.get("vuln_family") or ""):
            raise ValueError(f"case {case_id} is missing vuln_family")
        provenance = case.get("provenance")
        if not isinstance(provenance, Mapping):
            raise ValueError(f"case {case_id} is missing provenance")
        missing = missing_provenance_fields(provenance)
        if missing:
            raise ValueError(f"case {case_id} provenance is missing: {', '.join(missing)}")
        references = [
            *list(provenance.get("advisory_urls") or []),
            *list(provenance.get("fix_reference_urls") or []),
        ]
        if not any(str(reference) for reference in references):
            raise ValueError(f"case {case_id} provenance requires an advisory or fix reference URL")
        if require_hash:
            binary_hash = str(case.get("binary_sha256") or "")
            if not re.fullmatch(r"[0-9a-f]{64}", binary_hash):
                raise ValueError(f"case {case_id} has an invalid binary_sha256")
        validated.append(case)
    return validated


def freeze_manifest(source: Path, destination: Path, repo_root: Path) -> dict[str, Any]:
    source = source.resolve()
    destination = destination.resolve()
    payload = _manifest_payload(source)
    corpus_id = str(payload.get("corpus_id") or "")
    if not corpus_id:
        raise ValueError(f"{source} is missing corpus_id")
    cases = _validate_external_cases(payload.get("cases"), require_hash=False)
    frozen_cases: list[dict[str, Any]] = []
    for case in cases:
        binary_path = _external_binary_path(source, case).resolve()
        if not binary_path.is_file():
            raise ValueError(f"case {case['id']} binary does not exist: {binary_path}")
        frozen_case = dict(case)
        frozen_case["binary"] = os.path.relpath(binary_path, destination.parent)
        frozen_case["binary_sha256"] = sha256_file(binary_path)
        frozen_cases.append(frozen_case)
    frozen = {
        "schema_version": FROZEN_MANIFEST_SCHEMA_VERSION,
        "corpus_id": corpus_id,
        "frozen_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "analyzer_sha256": analyzer_sha256(repo_root),
        "cases": frozen_cases,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(frozen, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    validate_frozen_manifest(destination, repo_root)
    return frozen


def validate_frozen_manifest(path: Path, repo_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = path.resolve()
    payload = _manifest_payload(path)
    if int(payload.get("schema_version") or 0) != FROZEN_MANIFEST_SCHEMA_VERSION:
        raise ValueError(f"{path} has unsupported frozen manifest schema_version")
    if not str(payload.get("corpus_id") or "") or not str(payload.get("frozen_at") or ""):
        raise ValueError(f"{path} is missing corpus_id or frozen_at")
    expected_analyzer = str(payload.get("analyzer_sha256") or "")
    actual_analyzer = analyzer_sha256(repo_root)
    if expected_analyzer != actual_analyzer:
        raise ValueError(
            f"analyzer SHA-256 mismatch: manifest has {expected_analyzer or '<missing>'}, current analyzer is {actual_analyzer}"
        )
    cases = _validate_external_cases(payload.get("cases"), require_hash=True)
    resolved_cases: list[dict[str, Any]] = []
    for case in cases:
        binary_path = _external_binary_path(path, case).resolve()
        if not binary_path.is_file():
            raise ValueError(f"case {case['id']} binary does not exist: {binary_path}")
        expected_binary = str(case["binary_sha256"])
        actual_binary = sha256_file(binary_path)
        if expected_binary != actual_binary:
            raise ValueError(
                f"case {case['id']} binary SHA-256 mismatch: manifest has {expected_binary}, file has {actual_binary}"
            )
        resolved = dict(case)
        resolved["binary"] = str(binary_path)
        if resolved["expected_outcome"] == "caught":
            resolved.update(expected_issue_count=1, expected_overflow_witnesses=1)
        else:
            resolved.update(expected_issue_count=0, expected_overflow_witnesses=0)
        resolved_cases.append(resolved)
    return payload, resolved_cases


def select_cases(
    cases: list[dict[str, Any]],
    case_ids: list[str] | None,
    lanes: list[str] | None = None,
) -> list[dict[str, Any]]:
    selected = cases
    if not case_ids:
        if lanes:
            wanted_lanes = set(lanes)
            selected = [case for case in selected if str(case.get("lane") or TRUE_OVERFLOW_LANE) in wanted_lanes]
        return selected
    wanted = set(case_ids)
    selected = [case for case in selected if str(case.get("id")) in wanted]
    missing = sorted(wanted - {str(case.get("id")) for case in selected})
    if missing:
        raise ValueError(f"unknown corpus case id(s): {', '.join(missing)}")
    if lanes:
        wanted_lanes = set(lanes)
        selected = [case for case in selected if str(case.get("lane") or TRUE_OVERFLOW_LANE) in wanted_lanes]
    return selected


def select_regression_subset(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = [
        case
        for case in cases
        if bool(case.get("regression_subset", False))
        or str(case.get("id") or "") in DEFAULT_REGRESSION_SUBSET_IDS
    ]
    missing = sorted(DEFAULT_REGRESSION_SUBSET_IDS - {str(case.get("id") or "") for case in selected})
    if missing:
        raise ValueError(f"default regression subset is missing case id(s): {', '.join(missing)}")
    return selected


def parse_run_dir(stdout: str) -> str:
    matches = re.findall(r"Proof-gated run directory:\s*(.+)", stdout)
    return matches[-1].strip() if matches else ""


def latest_run_dir(case_root: Path, binary_name: str) -> Path | None:
    binary_root = case_root / binary_name
    if not binary_root.exists():
        return None
    run_dirs = [path for path in binary_root.iterdir() if path.is_dir()]
    return max(run_dirs, key=lambda path: path.stat().st_mtime) if run_dirs else None


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    return payload if isinstance(payload, dict) else {}


def report_issue_count(run_dir: Path) -> int:
    vulnerabilities = load_json(run_dir / "report" / "vulnerabilities.json").get("vulnerabilities")
    if isinstance(vulnerabilities, list):
        return len(vulnerabilities)
    return len(list((run_dir / "report").glob("[0-9][0-9][0-9]_*.md")))


def memory_safety_witness_count(verdict_counts: Mapping[str, Any]) -> int:
    return int(verdict_counts.get("overflow_witness") or 0) + int(verdict_counts.get("memory_violation_witness") or 0)


def classify_failure(case: dict[str, Any], run_dir: Path | None, exit_code: int) -> str:
    expected_issues = int(case.get("expected_issue_count", 0))
    expected_witnesses = int(case.get("expected_overflow_witnesses", 0))
    expected_outcome = str(case.get("expected_outcome") or "caught")
    if exit_code == 124:
        return "proof_timeout"
    if exit_code == 127:
        return "missing_binary"
    if exit_code != 0:
        return f"toolchain_exit_{exit_code}"
    if run_dir is None:
        return "missing_run_dir"
    proof_summary = load_json(run_dir / "proof" / "_concolic_run_summary.json")
    verdict_counts = proof_summary.get("verdict_counts") if isinstance(proof_summary.get("verdict_counts"), dict) else {}
    overflow_witnesses = memory_safety_witness_count(verdict_counts)
    issue_count = report_issue_count(run_dir)
    if issue_count > expected_issues:
        return "unexpected_report_count"
    if overflow_witnesses > expected_witnesses:
        return "unexpected_overflow_witness"
    if (
        expected_outcome == "caught"
        and issue_count == expected_issues
        and overflow_witnesses == expected_witnesses
    ):
        return "none"
    if expected_outcome == "clean" and issue_count == 0 and overflow_witnesses == 0:
        for reason in ("backend_error", "timeout"):
            if int(verdict_counts.get(reason) or 0) > 0:
                return reason
        return "none"
    for reason in ("backend_error", "timeout", "path_unsat", "guard_refuted", "target_reached", "crash_reproduced"):
        if int(verdict_counts.get(reason) or 0) > 0:
            return reason
    if issue_count < expected_issues:
        return "missing_report_issue"
    if overflow_witnesses < expected_witnesses:
        return "missing_overflow_witness"
    return "none"


def clean_suppression_reason(verdict_counts: Mapping[str, Any], issue_count: int, overflow_witnesses: int) -> str:
    if issue_count != 0 or overflow_witnesses != 0:
        return ""
    for reason in ("guard_refuted", "path_unsat", "safety_proven", "target_reached", "backend_error", "timeout"):
        if int(verdict_counts.get(reason) or 0) > 0:
            return reason
    return "no_reported_candidates"


def backend_missing_reason(run_dir: Path | None) -> str:
    if run_dir is None:
        return ""
    proof_dir = run_dir / "proof"
    if not proof_dir.exists():
        return ""
    for path in sorted(proof_dir.glob("*/verdict.json")):
        payload = load_json(path)
        text = json.dumps(
            {
                "rationale": payload.get("rationale", ""),
                "errors": payload.get("errors", []),
            },
            sort_keys=True,
        )
        if "No module named 'angr'" in text or "angr backend is not available" in text:
            return "optional_backend_missing:angr"
    return ""


def llm_run_metrics(run_dir: Path | None) -> dict[str, Any]:
    if run_dir is None:
        return {}
    hypothesis_dir = run_dir / "hypotheses"
    hypothesis_summary = load_json(hypothesis_dir / "summary.json")
    accepted_index = load_json(run_dir / "hypotheses" / "accepted_index.json")
    rejected_index = load_json(run_dir / "hypotheses" / "rejected_index.json")
    partial_hypotheses = _partial_hypothesis_artifacts(hypothesis_dir) if not hypothesis_summary else []
    replay_results = _root_replay_results(run_dir / "replay")
    repair_attempts = _repair_attempts(run_dir / "replay")
    confirmed = [
        result
        for result in replay_results
        if result.get("result") == "confirmed" and result.get("sink_reached") and result.get("bug_observed")
    ]
    return {
        "hypothesis_enabled": bool(hypothesis_summary.get("enabled", False) or partial_hypotheses),
        "hypothesis_candidate_count": int(hypothesis_summary.get("candidate_count") or 0),
        "hypothesis_eligible_candidate_count": int(hypothesis_summary.get("eligible_candidate_count") or 0),
        "hypothesis_provider_calls": int(hypothesis_summary.get("provider_calls") or 0)
        or int(_partial_cost_sum(partial_hypotheses, "model_calls")),
        "hypothesis_accepted_count": _index_count(
            accepted_index,
            "accepted",
            hypothesis_summary.get("accepted_count") or _partial_validation_count(partial_hypotheses, accepted=True),
        ),
        "hypothesis_rejected_count": _index_count(
            rejected_index,
            "rejected",
            hypothesis_summary.get("rejected_count") or _partial_validation_count(partial_hypotheses, accepted=False),
        ),
        "model_calls": int(hypothesis_summary.get("model_calls") or 0) or int(_partial_cost_sum(partial_hypotheses, "model_calls")),
        "input_tokens": int(hypothesis_summary.get("input_tokens") or 0) or _partial_cost_sum(partial_hypotheses, "input_tokens"),
        "output_tokens": int(hypothesis_summary.get("output_tokens") or 0) or _partial_cost_sum(partial_hypotheses, "output_tokens"),
        "total_tokens": int(hypothesis_summary.get("total_tokens") or 0) or _partial_cost_sum(partial_hypotheses, "total_tokens"),
        "llm_wall_time_seconds": float(hypothesis_summary.get("wall_time_seconds") or 0.0)
        or round(float(_partial_cost_sum(partial_hypotheses, "wall_time_seconds")), 3),
        "json_repair_count": int(hypothesis_summary.get("json_repair_count") or 0)
        or _partial_cost_sum(partial_hypotheses, "json_repair_count"),
        "replay_result_count": len(replay_results),
        "replay_confirmed_count": len(confirmed),
        "repair_attempt_count": sum(len(item.get("attempts") or []) for item in repair_attempts if isinstance(item, Mapping)),
        "repair_confirmed_count": sum(1 for item in repair_attempts if _repair_final_confirmed(item)),
        "report_deduped_issue_count": report_issue_count(run_dir),
    }


def _json_rows(path: Path, key: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    rows = payload.get(key, []) if isinstance(payload, Mapping) else payload
    return [dict(row) for row in rows if isinstance(row, Mapping)] if isinstance(rows, list) else []


def pipeline_stage_metrics(run_dir: Path | None) -> dict[str, Any]:
    if run_dir is None:
        return {
            "discovery_candidates": 0,
            "proof_ready_candidates": 0,
            "proof_eligible_candidates": 0,
            "proof_attempted_candidates": 0,
            "proof_skipped_candidates": 0,
            "proof_timed_out_candidates": 0,
            "proof_memory_limited_candidates": 0,
            "proof_diagnostic_counts": {},
            "proof_attempt_coverage": None,
            "proof_verdicts": 0,
            "replay_attempts": 0,
            "replay_confirmations": 0,
            "reports": 0,
        }
    discovered = _json_rows(run_dir / "discovery" / "candidates.json", "candidates")
    promotion_events = _json_rows(run_dir / "promotion" / "promotion_events.json", "promotion_events")
    proof_ready = {
        str(event.get("candidate_id") or "")
        for event in promotion_events
        if event.get("to_status") == "proof_ready" and event.get("candidate_id")
    }
    proof_summary = load_json(run_dir / "proof" / "_concolic_run_summary.json")
    verdict_counts = proof_summary.get("verdict_counts") if isinstance(proof_summary.get("verdict_counts"), Mapping) else {}
    eligible_count = int(proof_summary.get("eligible_count") or 0)
    attempted_count = int(proof_summary.get("attempted_count") or 0)
    replay_results = _root_replay_results(run_dir / "replay")
    confirmed = [
        result
        for result in replay_results
        if result.get("result") == "confirmed" and result.get("sink_reached") and result.get("bug_observed")
    ]
    return {
        "discovery_candidates": len(discovered),
        "proof_ready_candidates": len(proof_ready),
        "proof_eligible_candidates": eligible_count,
        "proof_attempted_candidates": attempted_count,
        "proof_skipped_candidates": len(proof_summary.get("skipped") or []),
        "proof_timed_out_candidates": int(proof_summary.get("timed_out_count") or 0),
        "proof_memory_limited_candidates": int(proof_summary.get("memory_limited_count") or 0),
        "proof_diagnostic_counts": dict(proof_summary.get("diagnostic_counts") or {})
        if isinstance(proof_summary.get("diagnostic_counts"), Mapping)
        else {},
        "proof_attempt_coverage": _rate(attempted_count + len(proof_summary.get("skipped") or []), eligible_count),
        "proof_verdicts": sum(int(value or 0) for value in verdict_counts.values()),
        "replay_attempts": len(replay_results),
        "replay_confirmations": len(confirmed),
        "reports": report_issue_count(run_dir),
    }


def execution_status(failure_reason: str, exit_code: int, run_dir: Path | None) -> str:
    if (
        exit_code != 0
        or run_dir is None
        or failure_reason in BLOCKING_FAILURE_REASONS
        or failure_reason.startswith("toolchain_exit_")
    ):
        return "blocked"
    return "completed"


def _partial_hypothesis_artifacts(hypothesis_dir: Path) -> list[dict[str, Any]]:
    if not hypothesis_dir.exists():
        return []
    artifacts: list[dict[str, Any]] = []
    for path in sorted(hypothesis_dir.glob("*/*.json")):
        if path.parent.name == "raw":
            continue
        payload = load_json(path)
        if payload:
            artifacts.append(payload)
    return artifacts


def _partial_cost_sum(artifacts: list[Mapping[str, Any]], key: str) -> int | float:
    total: int | float = 0
    for artifact in artifacts:
        cost = artifact.get("cost_metadata") if isinstance(artifact.get("cost_metadata"), Mapping) else {}
        value = cost.get(key)
        if isinstance(value, (int, float)):
            total += value
    return total


def _partial_validation_count(artifacts: list[Mapping[str, Any]], *, accepted: bool) -> int:
    count = 0
    for artifact in artifacts:
        validator = artifact.get("validator_result") if isinstance(artifact.get("validator_result"), Mapping) else {}
        if accepted and validator.get("accepted") is True:
            count += 1
        elif not accepted and validator.get("accepted") is False:
            count += 1
        elif not accepted and artifact.get("failure_reason"):
            count += 1
    return count


def _index_count(payload: Mapping[str, Any], key: str, fallback: Any = 0) -> int:
    rows = payload.get(key)
    if isinstance(rows, list):
        return len(rows)
    return int(fallback or 0)


def _root_replay_results(replay_dir: Path) -> list[dict[str, Any]]:
    if not replay_dir.exists():
        return []
    results: list[dict[str, Any]] = []
    for path in sorted(replay_dir.glob("*/result.json")):
        payload = load_json(path)
        if payload:
            results.append(payload)
    return results


def _repair_attempts(replay_dir: Path) -> list[dict[str, Any]]:
    if not replay_dir.exists():
        return []
    return [payload for payload in (load_json(path) for path in sorted(replay_dir.glob("*/repair/repair_attempts.json"))) if payload]


def _repair_final_confirmed(payload: Mapping[str, Any]) -> bool:
    final = payload.get("final_result") if isinstance(payload.get("final_result"), Mapping) else {}
    return bool(final.get("result") == "confirmed" and final.get("sink_reached") and final.get("bug_observed"))


def partial_run_diagnostics(run_dir: Path | None) -> dict[str, Any]:
    if run_dir is None:
        return {"partial_stage": "startup", "existing_stages": [], "proof_json_count": 0}
    stage_names = ("decompiled", "evidence", "promotion", "proof", "replay", "report")
    existing_stages = [name for name in stage_names if (run_dir / name).exists()]
    proof_dir = run_dir / "proof"
    proof_json = sorted(proof_dir.rglob("*.json")) if proof_dir.exists() else []
    proof_summary = proof_dir / "_concolic_run_summary.json"
    if proof_dir.exists() and not proof_summary.exists():
        partial_stage = "proof"
    elif proof_summary.exists() and not (run_dir / "report" / "vulnerabilities.json").exists():
        partial_stage = "report"
    elif existing_stages:
        partial_stage = existing_stages[-1]
    else:
        partial_stage = "startup"
    return {
        "partial_stage": partial_stage,
        "existing_stages": existing_stages,
        "proof_summary_present": proof_summary.exists(),
        "proof_candidate_dirs": sum(1 for path in proof_dir.iterdir() if path.is_dir()) if proof_dir.exists() else 0,
        "proof_json_count": len(proof_json),
        "last_proof_artifacts": [str(path.relative_to(run_dir)) for path in proof_json[-8:]],
    }


def case_provenance(case: Mapping[str, Any]) -> dict[str, Any]:
    raw = case.get("provenance")
    if isinstance(raw, Mapping):
        return dict(raw)
    return dict(CASE_PROVENANCE.get(str(case.get("id") or ""), {}))


def case_known_vuln_family(case: Mapping[str, Any]) -> str:
    family = str(case.get("known_vuln_family") or "")
    if family:
        return family
    case_id = str(case.get("id") or "")
    if case_id in DEFAULT_KNOWN_VULN_FAMILIES:
        return DEFAULT_KNOWN_VULN_FAMILIES[case_id]
    expected_outcome = str(case.get("expected_outcome") or "caught")
    return str(case.get("vuln_family") or "") if expected_outcome == "caught" else ""


def missing_provenance_fields(provenance: Mapping[str, Any]) -> list[str]:
    return [field for field in REQUIRED_PROVENANCE_FIELDS if not str(provenance.get(field) or "")]


def evaluate_run(case: dict[str, Any], run_dir: Path | None, exit_code: int) -> dict[str, Any]:
    expected_issues = int(case.get("expected_issue_count", 0))
    expected_witnesses = int(case.get("expected_overflow_witnesses", 0))
    expected_outcome = str(case.get("expected_outcome") or "caught")
    expected_failure_reason = str(case.get("expected_failure_reason") or "none")
    expected_suppression_reason = str(case.get("expected_suppression_reason") or "")
    proof_summary = load_json(run_dir / "proof" / "_concolic_run_summary.json") if run_dir else {}
    verdict_counts = proof_summary.get("verdict_counts") if isinstance(proof_summary.get("verdict_counts"), dict) else {}
    overflow_witnesses = memory_safety_witness_count(verdict_counts)
    issue_count = report_issue_count(run_dir) if run_dir else 0
    failure_reason = classify_failure(case, run_dir, exit_code)
    missing_backend = backend_missing_reason(run_dir) if failure_reason == "backend_error" else ""
    suppression_reason = (
        clean_suppression_reason(verdict_counts, issue_count, overflow_witnesses) if expected_outcome == "clean" else ""
    )
    caught = (
        exit_code == 0
        and run_dir is not None
        and overflow_witnesses == expected_witnesses
        and issue_count == expected_issues
        and failure_reason == "none"
    )
    known_miss = (
        expected_outcome == "known_miss"
        and issue_count == expected_issues
        and overflow_witnesses == expected_witnesses
        and failure_reason == expected_failure_reason
    )
    backend_limited_known_miss = (
        expected_outcome == "known_miss"
        and bool(case.get("allow_backend_missing_known_miss", False))
        and issue_count == expected_issues
        and overflow_witnesses == expected_witnesses
        and failure_reason == "backend_error"
        and bool(missing_backend)
    )
    clean = (
        expected_outcome == "clean"
        and exit_code == 0
        and run_dir is not None
        and issue_count == 0
        and overflow_witnesses == 0
        and failure_reason == expected_failure_reason
        and (not expected_suppression_reason or suppression_reason == expected_suppression_reason)
    )
    if expected_outcome == "caught":
        passed = caught
    elif expected_outcome == "known_miss":
        passed = known_miss or backend_limited_known_miss
    else:
        passed = clean
    provenance = case_provenance(case)
    return {
        "id": case.get("id"),
        "binary_sha256": str(case.get("binary_sha256") or ""),
        "lane": str(case.get("lane") or TRUE_OVERFLOW_LANE),
        "regression_subset": bool(case.get("regression_subset", False))
        or str(case.get("id") or "") in DEFAULT_REGRESSION_SUBSET_IDS,
        "vuln_family": str(case.get("vuln_family") or "unspecified"),
        "known_vuln_family": case_known_vuln_family(case),
        "diagnostic_kind": str(case.get("diagnostic_kind") or ""),
        "process_input_model": str(case.get("process_input_model") or ""),
        "replay_hints": dict(case.get("replay_hints") or {}) if isinstance(case.get("replay_hints"), Mapping) else {},
        "provenance": provenance,
        "missing_provenance_fields": missing_provenance_fields(provenance),
        "passed": passed,
        "expected_outcome": expected_outcome,
        "exit_code": exit_code,
        "run_dir": str(run_dir) if run_dir else "",
        "known_issue_count": int(case.get("known_issue_count", expected_issues)),
        "expected_issue_count": expected_issues,
        "issue_count": issue_count,
        "expected_overflow_witnesses": expected_witnesses,
        "overflow_witnesses": overflow_witnesses,
        "memory_safety_witnesses": overflow_witnesses,
        "expected_failure_reason": expected_failure_reason,
        "failure_reason": failure_reason,
        "execution_status": execution_status(failure_reason, exit_code, run_dir),
        "backend_missing_reason": missing_backend,
        "expected_suppression_reason": expected_suppression_reason,
        "suppression_reason": suppression_reason,
        "failure_detail": str(case.get("failure_detail") or ""),
        "timeout_diagnostics": partial_run_diagnostics(run_dir) if exit_code == 124 else {},
        "verdict_counts": verdict_counts,
        "pipeline_metrics": pipeline_stage_metrics(run_dir),
        "llm_metrics": llm_run_metrics(run_dir),
    }


def toolchain_command(
    case: dict[str, Any],
    binary_path: Path,
    case_root: Path,
    cache_dir: Path,
    timeout_seconds: float,
    dynamic_max_steps: int,
    stages: str,
    overwrite: bool,
    ghidra_dir: Path | None = None,
    llm_options: Mapping[str, Any] | None = None,
    proof_jobs: int = 1,
    proof_memory_limit_mb: int = 8192,
) -> list[str]:
    case_stages = str(case.get("stages") or stages or DEFAULT_CORPUS_STAGES)
    command = [
        sys.executable,
        "-m",
        "binary_agent.cli.toolchain",
        str(binary_path),
        "--output-root",
        str(case_root),
        "--cache-dir",
        str(cache_dir),
        "--stages",
        case_stages,
        "--proof-timeout-seconds",
        str(float(case.get("proof_timeout_seconds", timeout_seconds))),
        "--proof-dynamic-max-steps",
        str(int(case.get("proof_dynamic_max_steps", dynamic_max_steps))),
        "--proof-jobs",
        str(int(proof_jobs)),
        "--proof-memory-limit-mb",
        str(int(proof_memory_limit_mb)),
    ]
    if ghidra_dir is not None:
        command.extend(["--ghidra-dir", str(ghidra_dir)])
    if overwrite:
        command.append("--overwrite")
    _append_llm_options(command, llm_options or {})
    return command


def _append_llm_options(command: list[str], options: Mapping[str, Any]) -> None:
    option_pairs = (
        ("llm_hypothesis_provider_command", "--llm-hypothesis-provider-command"),
        ("llm_hypothesis_systems", "--llm-hypothesis-systems"),
        ("llm_hypothesis_provider_timeout_seconds", "--llm-hypothesis-provider-timeout-seconds"),
        ("hypothesis_policy", "--hypothesis-policy"),
        ("max_hypothesis_calls_per_run", "--max-hypothesis-calls-per-run"),
        ("max_hypothesis_calls_per_candidate", "--max-hypothesis-calls-per-candidate"),
        ("llm_repair_provider_command", "--llm-repair-provider-command"),
        ("llm_repair_provider_timeout_seconds", "--llm-repair-provider-timeout-seconds"),
        ("llm_repair_max_attempts", "--llm-repair-max-attempts"),
    )
    for key, flag in option_pairs:
        value = options.get(key)
        if value in (None, ""):
            continue
        command.extend([flag, str(value)])
    fixtures = options.get("llm_hypothesis_fixtures")
    if fixtures:
        command.extend(["--llm-hypothesis-fixtures", str(fixtures)])
    if options.get("require_live_llm"):
        command.append("--require-live-llm")


def run_case(
    repo_root: Path,
    case: dict[str, Any],
    output_root: Path,
    cache_dir: Path,
    timeout_seconds: float,
    dynamic_max_steps: int,
    ghidra_dir: Path | None,
    case_timeout_seconds: float,
    stages: str,
    overwrite: bool,
    llm_options: Mapping[str, Any] | None = None,
    proof_jobs: int = 1,
    proof_memory_limit_mb: int = 8192,
) -> dict[str, Any]:
    case_id = str(case.get("id") or "")
    if not case_id:
        raise ValueError("corpus case missing id")
    binary_path = Path(str(case.get("binary") or ""))
    if not binary_path.is_absolute():
        binary_path = repo_root / binary_path
    case_root = output_root / case_id
    case_root.mkdir(parents=True, exist_ok=True)
    if not binary_path.exists():
        result = evaluate_run(case, None, 127)
        result.update({"error": f"missing binary: {binary_path}", "command": []})
        return result

    command = toolchain_command(
        case,
        binary_path,
        case_root,
        cache_dir,
        timeout_seconds,
        dynamic_max_steps,
        stages,
        overwrite,
        ghidra_dir,
        llm_options,
        proof_jobs,
        proof_memory_limit_mb,
    )
    env = os.environ.copy()
    src_path = str(repo_root / "src")
    env["PYTHONPATH"] = src_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    started = time.monotonic()
    case_timeout = float(case.get("case_timeout_seconds", case_timeout_seconds) or 0.0)
    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=case_timeout if case_timeout > 0 else None,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = _timeout_output(exc.stdout)
        stderr = _timeout_output(exc.stderr)
    duration_seconds = time.monotonic() - started
    (case_root / "toolchain.stdout.log").write_text(stdout, encoding="utf-8")
    (case_root / "toolchain.stderr.log").write_text(stderr, encoding="utf-8")
    run_dir_text = parse_run_dir(stdout)
    run_dir = Path(run_dir_text) if run_dir_text else latest_run_dir(case_root, binary_path.name)
    result = evaluate_run(case, run_dir, exit_code)
    result.update(
        {
            "duration_seconds": round(duration_seconds, 3),
            "command": command,
            "stdout_log": str(case_root / "toolchain.stdout.log"),
            "stderr_log": str(case_root / "toolchain.stderr.log"),
            "configured_proof_memory_limit_mb": int(proof_memory_limit_mb),
        }
    )
    return result


def _timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def default_ghidra_dir(repo_root: Path) -> Path | None:
    root = repo_root / "ghidra_downloads"
    if not root.exists():
        return None
    for candidate in sorted(root.glob("ghidra_*"), reverse=True):
        support = candidate / "support"
        if (support / "analyzeHeadless").exists() or any(
            (support / name).exists() for name in ("pyGhidraRun", "pyghidraRun")
        ):
            return candidate
    return None


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def evaluation_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    positives = [result for result in results if result.get("expected_outcome") == "caught"]
    negatives = [result for result in results if result.get("expected_outcome") == "clean"]
    completed_positives = [result for result in positives if result.get("execution_status", "completed") == "completed"]
    completed_negatives = [result for result in negatives if result.get("execution_status", "completed") == "completed"]
    blocked = [result for result in results if result.get("execution_status") == "blocked"]
    detected = [result for result in completed_positives if result.get("passed")]
    clean = [result for result in completed_negatives if result.get("passed")]
    false_positive = [
        result
        for result in completed_negatives
        if int(result.get("issue_count") or 0) > 0 or int(result.get("memory_safety_witnesses") or result.get("overflow_witnesses") or 0) > 0
    ]
    stage_keys = (
        "discovery_candidates",
        "proof_ready_candidates",
        "proof_eligible_candidates",
        "proof_attempted_candidates",
        "proof_skipped_candidates",
        "proof_timed_out_candidates",
        "proof_memory_limited_candidates",
        "proof_verdicts",
        "replay_attempts",
        "replay_confirmations",
        "reports",
    )
    stage_totals = {key: 0 for key in stage_keys}
    diagnostic_totals: dict[str, int] = {}
    for result in results:
        metrics = result.get("pipeline_metrics") if isinstance(result.get("pipeline_metrics"), Mapping) else {}
        for key in stage_keys:
            stage_totals[key] += int(metrics.get(key) or 0)
        diagnostic_counts = metrics.get("proof_diagnostic_counts")
        if isinstance(diagnostic_counts, Mapping):
            for key, value in diagnostic_counts.items():
                diagnostic_totals[str(key)] = diagnostic_totals.get(str(key), 0) + int(value or 0)
    stage_totals["proof_attempt_coverage"] = _rate(
        stage_totals["proof_attempted_candidates"] + stage_totals["proof_skipped_candidates"],
        stage_totals["proof_eligible_candidates"],
    )
    stage_totals["proof_diagnostic_counts"] = dict(sorted(diagnostic_totals.items()))
    return {
        "selected_cases": len(results),
        "selected_positives": len(positives),
        "selected_negatives": len(negatives),
        "completed_cases": len(results) - len(blocked),
        "completed_positives": len(completed_positives),
        "completed_negatives": len(completed_negatives),
        "detected_positives": len(detected),
        "missed_positives": len(completed_positives) - len(detected),
        "clean_negatives": len(clean),
        "false_positive_negatives": len(false_positive),
        "other_negative_failures": len(completed_negatives) - len(clean) - len(false_positive),
        "blocked_cases": len(blocked),
        "blocked_case_details": [
            {"id": result.get("id"), "reason": result.get("failure_reason")}
            for result in blocked
        ],
        "coverage": _rate(len(results) - len(blocked), len(results)),
        "positive_coverage": _rate(len(completed_positives), len(positives)),
        "negative_coverage": _rate(len(completed_negatives), len(negatives)),
        "conditional_recall": _rate(len(detected), len(completed_positives)),
        "conditional_false_positive_rate": _rate(len(false_positive), len(completed_negatives)),
        "configured_proof_memory_limit_mb": max(
            (int(result.get("configured_proof_memory_limit_mb") or 0) for result in results),
            default=0,
        ),
        "stage_totals": stage_totals,
    }


def summary_payload(
    results: list[dict[str, Any]],
    evaluation_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    passed = sum(1 for result in results if result.get("passed"))
    lane_counts: dict[str, dict[str, int]] = {}
    family_counts: dict[str, dict[str, int]] = {}
    known_family_counts: dict[str, dict[str, int]] = {}
    caught_family_counts: dict[str, int] = {}
    regression_subset_passed = 0
    for result in results:
        if result.get("regression_subset") and result.get("passed"):
            regression_subset_passed += 1
        lane = str(result.get("lane") or TRUE_OVERFLOW_LANE)
        counts = lane_counts.setdefault(lane, {"passed": 0, "failed": 0, "total": 0})
        counts["total"] += 1
        if result.get("passed"):
            counts["passed"] += 1
        else:
            counts["failed"] += 1
        family = str(result.get("vuln_family") or "unspecified")
        family_stats = family_counts.setdefault(family, {"passed": 0, "failed": 0, "total": 0})
        family_stats["total"] += 1
        if result.get("passed"):
            family_stats["passed"] += 1
        else:
            family_stats["failed"] += 1
        known_family = str(result.get("known_vuln_family") or "")
        if known_family:
            known_stats = known_family_counts.setdefault(known_family, {"passed": 0, "failed": 0, "total": 0})
            known_stats["total"] += 1
            if result.get("passed"):
                known_stats["passed"] += 1
            else:
                known_stats["failed"] += 1
            if result.get("expected_outcome") == "caught" and result.get("passed"):
                caught_family_counts[known_family] = caught_family_counts.get(known_family, 0) + 1
    payload = {
        "schema_version": 1,
        "passed": passed,
        "failed": len(results) - passed,
        "lanes": lane_counts,
        "families": family_counts,
        "known_vuln_families": known_family_counts,
        "caught_known_vuln_families": dict(sorted(caught_family_counts.items())),
        "regression_subset_passed": regression_subset_passed,
        "regression_subset_total": sum(1 for result in results if result.get("regression_subset")),
        "llm_metrics": aggregate_llm_metrics(results),
        "provenance_complete": sum(1 for result in results if not result.get("missing_provenance_fields")),
        "provenance_total": len(results),
        "true_overflow_passed": lane_counts.get(TRUE_OVERFLOW_LANE, {}).get("passed", 0),
        "true_overflow_total": lane_counts.get(TRUE_OVERFLOW_LANE, {}).get("total", 0),
        "diagnostics_passed": lane_counts.get(DIAGNOSTIC_LANE, {}).get("passed", 0),
        "diagnostics_total": lane_counts.get(DIAGNOSTIC_LANE, {}).get("total", 0),
        "negative_passed": lane_counts.get(NEGATIVE_LANE, {}).get("passed", 0),
        "negative_total": lane_counts.get(NEGATIVE_LANE, {}).get("total", 0),
        "caught": sum(1 for result in results if result.get("expected_outcome") == "caught" and result.get("passed")),
        "known_misses": sum(
            1 for result in results if result.get("expected_outcome") == "known_miss" and result.get("passed")
        ),
        "clean_negatives": sum(
            1 for result in results if result.get("expected_outcome") == "clean" and result.get("passed")
        ),
        "cases": results,
    }
    payload["evaluation_metrics"] = evaluation_metrics(results)
    if evaluation_identity:
        payload["evaluation_identity"] = dict(evaluation_identity)
    return payload


def aggregate_llm_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    keys = (
        "hypothesis_provider_calls",
        "hypothesis_accepted_count",
        "hypothesis_rejected_count",
        "model_calls",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "json_repair_count",
        "replay_result_count",
        "replay_confirmed_count",
        "repair_attempt_count",
        "repair_confirmed_count",
        "report_deduped_issue_count",
    )
    totals = {key: 0 for key in keys}
    totals["llm_wall_time_seconds"] = 0.0
    totals["hypothesis_enabled_cases"] = 0
    for result in results:
        metrics = result.get("llm_metrics") if isinstance(result.get("llm_metrics"), Mapping) else {}
        if not metrics:
            continue
        if metrics.get("hypothesis_enabled"):
            totals["hypothesis_enabled_cases"] += 1
        for key in keys:
            totals[key] += int(metrics.get(key) or 0)
        totals["llm_wall_time_seconds"] += float(metrics.get("llm_wall_time_seconds") or 0.0)
    totals["llm_wall_time_seconds"] = round(totals["llm_wall_time_seconds"], 3)
    return totals


def write_summary(
    summary_path: Path,
    results: list[dict[str, Any]],
    evaluation_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    payload = summary_payload(results, evaluation_identity)
    summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


def requirement_failures(payload: dict[str, Any], args: argparse.Namespace) -> list[str]:
    checks = [
        ("passed", args.require_passed),
        ("true_overflow_passed", args.require_true_overflow_passed),
        ("diagnostics_passed", args.require_diagnostics_passed),
        ("negative_passed", args.require_negative_passed),
        ("regression_subset_passed", getattr(args, "require_regression_subset_passed", None)),
    ]
    failures = []
    for key, minimum in checks:
        if minimum is None:
            continue
        actual = int(payload.get(key) or 0)
        if actual < int(minimum):
            failures.append(f"{key}={actual} < required {minimum}")
    families = payload.get("families") if isinstance(payload.get("families"), Mapping) else {}
    for raw_requirement in args.require_family_passed or []:
        family, minimum = parse_count_requirement(str(raw_requirement), "--require-family-passed")
        family_payload = families.get(family) if isinstance(families.get(family), Mapping) else {}
        actual = int(family_payload.get("passed") or 0)
        if actual < minimum:
            failures.append(f"families.{family}.passed={actual} < required {minimum}")
    known_families = (
        payload.get("known_vuln_families") if isinstance(payload.get("known_vuln_families"), Mapping) else {}
    )
    for raw_requirement in args.require_known_vuln_family_passed or []:
        family, minimum = parse_count_requirement(str(raw_requirement), "--require-known-vuln-family-passed")
        family_payload = known_families.get(family) if isinstance(known_families.get(family), Mapping) else {}
        actual = int(family_payload.get("passed") or 0)
        if actual < minimum:
            failures.append(f"known_vuln_families.{family}.passed={actual} < required {minimum}")
    if args.require_provenance:
        for result in payload.get("cases") or []:
            if not isinstance(result, Mapping):
                continue
            missing = result.get("missing_provenance_fields")
            if isinstance(missing, list) and missing:
                failures.append(f"cases.{result.get('id')}.provenance missing {','.join(map(str, missing))}")
    return failures


def parse_count_requirement(raw: str, option_name: str) -> tuple[str, int]:
    name, separator, count_text = raw.partition("=")
    name = name.strip()
    if not separator or not name:
        raise ValueError(f"{option_name} expects FAMILY=COUNT, got {raw!r}")
    try:
        count = int(count_text)
    except ValueError as exc:
        raise ValueError(f"{option_name} expects an integer count, got {raw!r}") from exc
    if count < 0:
        raise ValueError(f"{option_name} count must be non-negative, got {raw!r}")
    return name, count


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    if args.write_frozen_manifest is not None:
        if args.manifest is None:
            raise ValueError("--write-frozen-manifest requires --manifest")
        destination = args.write_frozen_manifest.resolve()
        frozen = freeze_manifest(args.manifest, destination, repo_root)
        print(f"[+] Frozen corpus {frozen['corpus_id']} written to {destination}")
        print(f"[+] Analyzer SHA-256: {frozen['analyzer_sha256']}")
        print(f"[+] Manifest SHA-256: {sha256_file(destination)}")
        return 0
    evaluation_identity: dict[str, Any] | None = None
    if args.manifest is not None:
        manifest_payload = _manifest_payload(args.manifest)
        if "corpus_id" in manifest_payload:
            manifest_payload, loaded_cases = validate_frozen_manifest(args.manifest, repo_root)
            evaluation_identity = {
                "corpus_id": manifest_payload["corpus_id"],
                "frozen_at": manifest_payload["frozen_at"],
                "analyzer_sha256": manifest_payload["analyzer_sha256"],
                "manifest_sha256": sha256_file(args.manifest),
            }
        else:
            loaded_cases = load_cases(args.manifest)
    else:
        loaded_cases = load_cases(None)
    if args.regression_subset:
        loaded_cases = select_regression_subset(loaded_cases)
    cases = select_cases(loaded_cases, args.case_ids, args.lane)
    output_root = args.output_root if args.output_root.is_absolute() else repo_root / args.output_root
    cache_dir = args.cache_dir if args.cache_dir.is_absolute() else repo_root / args.cache_dir
    ghidra_dir = args.ghidra_dir if args.ghidra_dir else default_ghidra_dir(repo_root)
    if ghidra_dir is not None and not ghidra_dir.is_absolute():
        ghidra_dir = repo_root / ghidra_dir
    stages = DEFAULT_LLM_CORPUS_STAGES if args.full_llm_path and args.stages == DEFAULT_CORPUS_STAGES else args.stages
    llm_options = llm_options_from_args(args)
    results = [
        run_case(
            repo_root,
            case,
            output_root,
            cache_dir,
            args.proof_timeout_seconds,
            args.proof_dynamic_max_steps,
            ghidra_dir,
            args.case_timeout_seconds,
            stages,
            args.overwrite,
            llm_options,
            args.proof_jobs,
            args.proof_memory_limit_mb,
        )
        for case in cases
    ]
    summary_path = args.summary or output_root / "summary.json"
    if not summary_path.is_absolute():
        summary_path = repo_root / summary_path
    payload = write_summary(summary_path, results, evaluation_identity)
    for result in results:
        status = "PASS" if result.get("passed") else "FAIL"
        diagnostics = result.get("timeout_diagnostics") if isinstance(result.get("timeout_diagnostics"), dict) else {}
        timeout_text = f" stage={diagnostics.get('partial_stage')}" if diagnostics else ""
        print(
            f"[{status}] {result['id']}: "
            f"lane={result['lane']} "
            f"family={result['vuln_family']} "
            f"known_family={result.get('known_vuln_family') or '-'} "
            f"outcome={result['expected_outcome']} "
            f"issues={result['issue_count']}/{result['expected_issue_count']} "
            f"memory_witnesses={result['memory_safety_witnesses']}/{result['expected_overflow_witnesses']} "
            f"llm_calls={result.get('llm_metrics', {}).get('model_calls', 0) if isinstance(result.get('llm_metrics'), Mapping) else 0} "
            f"reason={result['failure_reason']}{timeout_text} "
            f"run={result.get('run_dir') or '-'}"
        )
    gate_failures = requirement_failures(payload, args)
    for failure in gate_failures:
        print(f"[FAIL] gate: {failure}")
    print(f"[+] Summary written to {summary_path}")
    return 0 if all(result.get("passed") for result in results) and not gate_failures else 1


def llm_options_from_args(args: argparse.Namespace) -> dict[str, Any]:
    hypothesis_command = str(args.llm_hypothesis_provider_command or "")
    repair_command = str(args.llm_repair_provider_command or "")
    llm_enabled = (
        args.full_llm_path
        or bool(hypothesis_command)
        or args.llm_hypothesis_fixtures is not None
        or bool(repair_command)
        or bool(args.require_live_llm)
    )
    if not llm_enabled:
        return {}
    if args.full_llm_path:
        if not hypothesis_command and args.llm_hypothesis_fixtures is None:
            hypothesis_command = "auto"
        if not repair_command:
            repair_command = "auto"
    return {
        "llm_hypothesis_provider_command": hypothesis_command,
        "llm_hypothesis_fixtures": args.llm_hypothesis_fixtures,
        "llm_hypothesis_systems": args.llm_hypothesis_systems,
        "llm_hypothesis_provider_timeout_seconds": args.llm_hypothesis_provider_timeout_seconds,
        "hypothesis_policy": args.hypothesis_policy,
        "max_hypothesis_calls_per_run": args.max_hypothesis_calls_per_run,
        "max_hypothesis_calls_per_candidate": args.max_hypothesis_calls_per_candidate,
        "llm_repair_provider_command": repair_command,
        "llm_repair_provider_timeout_seconds": args.llm_repair_provider_timeout_seconds,
        "llm_repair_max_attempts": args.llm_repair_max_attempts,
        "require_live_llm": args.require_live_llm,
    }


if __name__ == "__main__":
    raise SystemExit(main())
