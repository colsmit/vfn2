"""Run concolic verification over evidence-pack JSON files."""

from __future__ import annotations

import argparse
from pathlib import Path

from binary_agent.analysis.concolic import CONCOLIC_VERDICTS, run_concolic_evidence_dir
from binary_agent.utils.env import load_dotenv_if_available


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate concolic verification verdicts from evidence packs.")
    parser.add_argument("evidence_dir", type=Path, help="Directory produced by --write-evidence-packs.")
    parser.add_argument("--binary", type=Path, required=True, help="Native binary to execute symbolically/concolically.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory for concolic verdict JSON files.")
    parser.add_argument(
        "--export-dir",
        type=Path,
        default=None,
        help="Optional decompiled export directory used for image-base address translation.",
    )
    parser.add_argument("--backend", choices=("angr",), default="angr", help="Concolic backend to use.")
    parser.add_argument(
        "--input-model",
        choices=("argv", "stdin", "file", "env", "env_file", "argv_file_stdin", "function_harness"),
        default="",
        help="Override the evidence-pack input model inference.",
    )
    parser.add_argument(
        "--symbolic-bytes",
        type=int,
        default=256,
        help="Maximum symbolic input bytes to create per candidate.",
    )
    parser.add_argument(
        "--timeout-seconds",
        "--timeout",
        dest="timeout_seconds",
        type=float,
        default=30.0,
        help="Per-candidate backend timeout.",
    )
    parser.add_argument(
        "--memory-limit-mb",
        type=int,
        default=8192,
        help="Hard address-space limit for each isolated candidate worker; 0 disables the limit.",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Maximum candidates to analyze concurrently.",
    )
    parser.add_argument(
        "--pcode-trace",
        action="store_true",
        help="Write a Ghidra p-code trace or explicit unsupported artifact for each candidate.",
    )
    parser.add_argument(
        "--ghidra-dir",
        type=Path,
        default=None,
        help="Ghidra installation directory used when --pcode-trace or --ghidra-dynamic-proof is enabled.",
    )
    parser.add_argument(
        "--ghidra-dynamic-proof",
        action="store_true",
        help="Run Ghidra dynamic exact-sink overflow proof for concrete concolic witnesses.",
    )
    parser.add_argument(
        "--ghidra-dynamic-max-steps",
        type=int,
        default=2048,
        help="Maximum Ghidra dynamic instructions to replay per proof attempt.",
    )
    parser.add_argument(
        "--llm-controller",
        action="store_true",
        help="Honor bounded run_concolic_poc tool requests embedded in evidence packs.",
    )
    parser.add_argument(
        "--target-candidate-id",
        default="",
        help="Run only the matching candidate id.",
    )
    parser.add_argument(
        "--target-selector",
        choices=(
            "",
            "all",
            "direct_stack_overflow",
            "direct_heap_overflow",
            "direct_memory_overflow",
            "proof_ready_memory",
        ),
        default="",
        help="Select candidate subset before concolic execution.",
    )
    parser.add_argument(
        "--target-limit",
        type=int,
        default=0,
        help="Maximum selected candidates to run after deterministic sorting; 0 means no limit.",
    )
    parser.add_argument("--overwrite", action="store_true", help="Rewrite existing concolic verdict files.")
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Record request/backend failures as backend_error verdicts instead of stopping the run.",
    )
    return parser.parse_args()


def main() -> None:
    load_dotenv_if_available()
    args = parse_args()
    result = run_concolic_evidence_dir(
        args.evidence_dir,
        binary_path=args.binary,
        output_dir=args.output_dir,
        export_dir=args.export_dir,
        backend=args.backend,
        input_model=args.input_model,
        symbolic_bytes=args.symbolic_bytes,
        timeout_seconds=args.timeout_seconds,
        pcode_trace=args.pcode_trace,
        ghidra_dynamic_proof=args.ghidra_dynamic_proof,
        ghidra_dynamic_max_steps=args.ghidra_dynamic_max_steps,
        ghidra_dir=args.ghidra_dir,
        llm_controller=args.llm_controller,
        target_candidate_id=args.target_candidate_id,
        target_selector=args.target_selector,
        target_limit=args.target_limit,
        jobs=args.jobs,
        isolate_candidates=True,
        memory_limit_mb=args.memory_limit_mb,
        overwrite=args.overwrite,
        continue_on_error=args.continue_on_error,
    )
    counts = {verdict: result.verdict_counts.get(verdict, 0) for verdict in sorted(CONCOLIC_VERDICTS)}
    summary = ", ".join(f"{verdict}={count}" for verdict, count in counts.items() if count)
    print(
        f"[+] Wrote {result.written_count} concolic verdicts to {result.output_dir} "
        f"({summary or 'no_verdicts'}, errors={result.error_count}, skipped={result.skipped_count})"
    )


if __name__ == "__main__":
    main()
