# Independent paired-corpus baseline — 2026-07-09

Status: completed run, incomplete evidence because 2 of 4 cases were blocked.

This is the first frozen external evaluation of the deterministic binary-only path: stripped binary → discovery → refinement → proof → replay → report. The protocol was written before the packages were selected. Potrace and jhead did not appear in the repository before selection. These cases are no longer unseen after this run and must be treated only as regression cases from now on.

## Frozen identity

- Corpus: `vulnfinder2-independent-pairs-20260709-v1`
- Frozen at: `2026-07-09T21:56:50+00:00`
- Analyzer SHA-256: `807c9e15649d8a4ef64cc9d48274b1c3a2de68692ae84d41fb5fc64a5d8efc0c`
- Frozen manifest SHA-256: `3edbf7246cb43a00cf9c64f532744cad38da540816110bad8841959ec9184df8`
- Baseline summary SHA-256: `27f8afa9bec4f6347b0f541375203f050678c845f9be977d950e793a3460c927`
- Ghidra: 12.1.2; archive SHA-256 `b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d`
- Raw external evaluation root: `/tmp/vulnfinder2-frozen-eval-20260709`

The analyzer hash was recomputed after the run and matched the frozen value. All four binary hashes were verified before execution. The manifest contains no candidate ID, function address, operation address, or sink address.

## Corpus and builds

Both sides of each pair were built with GCC 13.3.0 using identical flags:

```text
CFLAGS=-O2 -g0 -fno-omit-frame-pointer -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS=-pie -Wl,-z,relro,-z,now
postprocess=strip --strip-all
```

| Pair | Ground truth | Source/fix evidence | Binary SHA-256 |
|---|---|---|---|
| Potrace 1.12 | CVE-2016-8703 vulnerable; heap overflow in `bm_readbody_bmp` | [CVE record](https://www.cve.org/CVERecord?id=CVE-2016-8703), [upstream source](https://potrace.sourceforge.net/download/1.12/potrace-1.12.tar.gz), [upstream changelog](https://potrace.sourceforge.net/ChangeLog) | `6dbdbf5ce6d8446809d00a2a9e8743d0c3316d0627d2ec2b71232e2b3eb3544c` |
| Potrace 1.13 | Fixed counterpart | [upstream source](https://potrace.sourceforge.net/download/1.13/potrace-1.13.tar.gz) | `e29616dbad9fbe641669537b5706e7df2e74b893ecd252f090a4ada6c4f21cc8` |
| jhead `59c457e` | CVE-2021-3496 vulnerable; heap out-of-bounds read in Canon maker-note parsing | [upstream report](https://github.com/Matthias-Wandel/jhead/issues/33), [parent source](https://github.com/Matthias-Wandel/jhead/tree/59c457e26c46ed39ebf2ba2c703463505ef15b63) | `d04fbde48b67086d7fc218345cd3055c7acd8d6b24ea007a175a88bacc1df54f` |
| jhead `ca2973f` | Direct fixed commit | [upstream fix](https://github.com/Matthias-Wandel/jhead/commit/ca2973f4ce79279c15a09cf400648a757c1721b0) | `0890cb3654ed9ce10f6e785974f7362fa10250b94191512348f5c2bc519a27a2` |

Potrace archive hashes were `b0bbf1d7badbebfcb992280f038936281b47ddbae212e8ae91e863ce0b76173b` for 1.12 and `6252438b6b6644b9b6298056b4c5de3690a1d4e862b66889abe21eecdf16b784` for 1.13. Full build metadata remains in the external root.

## Fixed run command

```text
.venv/bin/python scripts/run_known_overflow_corpus.py \
  --manifest /tmp/vulnfinder2-frozen-eval-20260709/frozen_manifest.json \
  --stages intake,discovery,refinement,proof,replay,report \
  --output-root /tmp/vulnfinder2-frozen-eval-20260709/runs \
  --cache-dir /tmp/vulnfinder2-frozen-eval-20260709/cache \
  --ghidra-dir /tmp/vulnfinder2-frozen-eval-20260709/tooling/ghidra_12.1.2_PUBLIC \
  --proof-timeout-seconds 120 \
  --proof-dynamic-max-steps 50000 \
  --case-timeout-seconds 600 \
  --summary /tmp/vulnfinder2-frozen-eval-20260709/baseline_summary.json
```

Live model stages were disabled. No exact candidate selector was supplied.

## Results

| Case | Status | Discovery → proof-ready → verdicts | Replay confirmations / reports | Result |
|---|---:|---:|---:|---|
| Potrace 1.12 vulnerable | Blocked | 182 → 60 → 2 | 0 / 0 | Both proof verdicts timed out; full path emitted no report |
| Potrace 1.13 fixed | Blocked | 191 → 63 → 0 | 0 / 0 | Outer 600-second limit expired during proof |
| jhead vulnerable | Completed | 119 → 31 → 3 | 0 / 0 | Miss; all three selected proofs were `path_unsat` |
| jhead fixed | Completed | 119 → 31 → 3 | 0 / 0 | Clean output; all three selected proofs were `path_unsat` |

Aggregate accounting:

- Coverage: 2/4 cases (50%)
- Positive coverage: 1/2; conditional recall: 0/1
- Negative coverage: 1/2; conditional false-positive rate: 0/1
- Completed positives: 1; detected: 0; missed: 1
- Completed negatives: 1; clean: 1; false-positive: 0
- Blocked: 2; neither blocked case was counted as a miss or clean rejection
- Stage totals: 611 discovered candidates, 185 proof-ready candidates, 8 proof verdicts, 117 replay-result artifacts, 0 replay confirmations, 0 reports

## Assessment

The baseline does not support an accuracy claim. Half the corpus was blocked, and the only completed vulnerable case was missed.

The strongest observed bottleneck was partial proof coverage coupled to retained proof state. Potrace promoted 60–63 candidates per binary, selected a bounded subset, grew to roughly 13–16 GB RSS during proof, and could not complete both sides of the pair within the fixed budget. Increasing time alone would not address either omitted candidates or retained state.

The jhead pair completed, but both binaries followed the same measured path: 119 discoveries, 31 proof-ready candidates, the same three proof targets, three `path_unsat` verdicts, and no report. The clean fixed result therefore has weak evidentiary value: the paired vulnerable binary was not distinguished. Candidate ranking was subsequently removed from canonical membership rather than improved, because every promoted candidate must be tested. The [exhaustive isolated follow-up](evaluation_exhaustive_followup_20260709.md) attempted all 185 proof-ready candidates and made the remaining proof failures explicit. These four binaries must not be used to claim generalization.

## Limitations

This is a deliberately small two-pair evaluation on x86-64 Linux. It measures the current deterministic path only, not the model-assisted stages. It does not establish broad class coverage, and the conditional rates have denominator one. Potrace's blocked pair prevents any conclusion about its vulnerable/fixed distinction. The external raw artifacts are intentionally not part of the repository and may be removed only after any desired independent audit.
