# Capability and detection-cleanup follow-up (2026-07-09)

This is a development-visible regression, not generalization evidence. Potrace and jhead were used while implementing the analyzer changes.

## Frozen identity and command

- Corpus: `vulnfinder2-exhaustive-regression-20260709-v2`
- Analyzer SHA-256: `4b1268deec1455e0b22d57fac9f36293ce3600b6df180bc5f356fd5ca4e3300a`
- Manifest SHA-256: `e599f1c6eb4f2bdf88cad92eefd05f61f6a992784398a893fc2f6167d9ca4262`
- Frozen manifest: `/tmp/vulnfinder2-frozen-eval-20260709/frozen_manifest_capability_clean.json`
- Raw summary: `/tmp/vulnfinder2-capability-regression-20260709/summary-clean.json`

The run used the full `intake,discovery,refinement,proof,replay,report` path, no target selector, two isolated proof workers, a 4096 MiB angr-worker limit, ten-second symbolic budgets, and 100,000 Ghidra dynamic steps. Every promoted candidate was attempted.

## Results

| Case | Eligible / attempted | Diagnostics | Witnesses | Reports | Evaluation |
| --- | ---: | --- | ---: | ---: | --- |
| Potrace 1.12 vulnerable | 10 / 10 | 1 violation proven; 9 wall timeouts | 1 | 1 | pass |
| Potrace 1.13 fixed | 8 / 8 | 8 wall timeouts | 0 | 0 | blocked, not clean |
| jhead vulnerable | 1 / 1 | 1 path exhausted | 0 | 0 | miss |
| jhead fixed | 1 / 1 | 1 path exhausted | 0 | 0 | pass |

Aggregate proof coverage was 20/20. Diagnostics were one `complete:memory_violation_proven`, 17 `exploration:wall_timeout`, and two `reachability:path_exhausted`. Conditional recall on the two completed positive cases was 0.5; completed-negative false-positive rate was 0.0. Potrace fixed is excluded from that negative rate because all its proof attempts timed out.

## Potrace vertical slice

The stripped 1.12 export contains two decompiler-style pointer loads through `calloc(ncolors, 4)` whose offsets are traced to `fgetc`. Ghidra token/p-code metadata resolves them to exact instructions. The fixed 1.13 counterparts are suppressed by their recovered `index < ncolors` guards.

The ordinary CLI selected a binary `file` model and a 62-byte indexed BMP without a target override. For the reachable 1.12 path it reached `0x10618c`, recovered a four-byte runtime allocation, observed a read at offset 1020 from palette index `0xff`, and proved four out-of-bounds bytes. Replay confirmed the proof and one report was emitted. The fixed binary emitted no witness or report, but unrelated candidates timed out, so it remains blocked rather than proven clean.

## Detection cleanup

The initial follow-up briefly proved an intentional constant `memset` in both jhead versions because function reachability was treated as attacker control. That result was rejected as a false positive. The final frozen analyzer requires controlled source, size, or offset evidence for static memory promotion; reachability alone no longer suffices. This reduced the four-case proof set from the prior 185 attempts to 20 while retaining full coverage of the remaining promoted set and the Potrace candidate.

## Limitations

- The jhead CVE remains missed. Its single remaining proof candidate exhausts the modeled path on both versions.
- Seventeen unrelated promoted candidates still consume their symbolic budget, so promotion and path modeling remain the main cleanup targets.
- A fixed binary with timeouts is not evidence of absence; Potrace 1.13 is reported as blocked despite the correct CVE-pattern differential.
- These pairs were development-visible and support implementation validation only.
