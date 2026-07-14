# Exhaustive isolated-proof regression — 2026-07-09

Status: proof-attempt coverage complete; all four cases remain scientifically blocked.

This reruns the previously exposed Potrace and jhead pairs after removing proof-candidate ranking from canonical membership and isolating every proof attempt in a fresh bounded process. It is regression evidence for execution mechanics only. Because these binaries informed the change, this run is not evidence of generalization or accuracy.

## Frozen identity

- Corpus: `vulnfinder2-exhaustive-regression-20260709-v2`
- Frozen at: `2026-07-09T22:44:13+00:00`
- Analyzer SHA-256: `158b39977dd0689cd587cd2c888f9bce1f9d8f621a7b80d093b9101b23e9b517`
- Frozen manifest SHA-256: `c1e4cd28d699c8b0afbc76a26b27cee41048e9d033bdca5a5d868c71f5102e4f`
- Result summary SHA-256: `1301039ea70c304a8a1616521578d9fd4e83d9a4ebafb5930460bcdf7d0ddc45`
- Raw external evaluation root: `/tmp/vulnfinder2-frozen-eval-20260709`

The analyzer hash was recomputed after execution and matched the frozen value. Sources, binaries, build flags, and ground truth are unchanged from [the original baseline](evaluation_baseline_20260709.md).

## Execution contract

Every post-refinement `proof_ready` candidate was passed by exact ID to the proof stage. Each candidate ran in a fresh process with a five-second backend timeout, a hard parent-enforced wall-clock bound, a 4096 MiB address-space limit, and at most two concurrent workers. No candidate-count cap or semantic candidate selector was used.

```text
.venv/bin/python scripts/run_known_overflow_corpus.py \
  --manifest /tmp/vulnfinder2-frozen-eval-20260709/frozen_manifest_exhaustive.json \
  --stages intake,discovery,refinement,proof,replay,report \
  --output-root /tmp/vulnfinder2-frozen-eval-20260709/runs_exhaustive \
  --cache-dir /tmp/vulnfinder2-frozen-eval-20260709/cache \
  --ghidra-dir /tmp/vulnfinder2-frozen-eval-20260709/tooling/ghidra_12.1.2_PUBLIC \
  --proof-timeout-seconds 5 \
  --proof-dynamic-max-steps 50000 \
  --proof-jobs 2 \
  --proof-memory-limit-mb 4096 \
  --case-timeout-seconds 900 \
  --summary /tmp/vulnfinder2-frozen-eval-20260709/exhaustive_summary.json
```

## Results

| Case | Discovered | Proof-ready | Attempted | Verdicts | Replay / reports | Duration | Status |
|---|---:|---:|---:|---|---:|---:|---|
| Potrace 1.12 vulnerable | 182 | 60 | 60/60 | 60 timeout | 59 / 0 | 205.311 s | Blocked |
| Potrace 1.13 fixed | 191 | 63 | 63/63 | 63 timeout | 63 / 0 | 217.321 s | Blocked |
| jhead vulnerable | 119 | 31 | 31/31 | 24 path-unsat, 1 target-reached, 6 timeout | 1 / 0 | 49.226 s | Blocked |
| jhead fixed | 119 | 31 | 31/31 | 24 path-unsat, 1 target-reached, 6 timeout | 1 / 0 | 47.522 s | Blocked |

Aggregate accounting:

- Eligible and attempted: 185/185; attempt coverage 1.0
- Explicit timeouts: 135; memory-limit failures: 0; skipped existing results: 0
- Proof verdict artifacts: 185, up from 8 in the original run
- Replay attempts: 124; replay confirmations: 0; reports: 0
- Completed cases: 0/4; all four are blocked, so recall and false-positive rate are undefined
- No proof worker remained after the runner exited; sampled parent RSS stayed below 80 MiB while isolated workers held their own proof state

## Assessment

The execution milestone succeeded: ranking no longer decides canonical proof membership, every promoted candidate receives a bounded attempt, state is released between candidates, and incomplete proof is explicit. The original baseline's apparent clean jhead fixed result is no longer admissible because both sides contain unresolved timeouts.

The research result remains blocked. Exhaustiveness increased the observed verdict set from 8 to 185 without producing a replay confirmation or report. Potrace's proof model timed out for every candidate, and the jhead vulnerable/fixed pair remained behaviorally indistinguishable. The next work should improve proof input modeling and path feasibility on individual candidates while retaining exhaustive membership; reintroducing candidate ranking as a cutoff would only hide the unresolved proof failures.

## Validation associated with the change

- Focused behavioral tests: 192 passed, 2 skipped
- Full suite after reduction: 613 passed, 6 skipped
- Bytecode compilation: passed
- Dependency consistency: no broken requirements
- Public concolic CLI isolation check: 2/2 real attempts, no surviving worker
- Frozen paired regression: 185/185 attempts, all incomplete outcomes explicit

## Limitations

The five-second per-candidate budget deliberately bounds this regression and is not evidence that candidates are intrinsically unprovable. `RLIMIT_AS` is a POSIX mechanism and the process-group cleanup guarantees are strongest on Linux. The corpus has only two already-seen vulnerable/fixed pairs, so no accuracy or generalization claim follows from this run.
