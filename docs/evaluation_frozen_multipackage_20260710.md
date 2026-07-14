# Frozen multi-package memory-safety evaluation

## Result

Status: blocked. The six-case protocol completed with full proof-attempt coverage, but no case produced a decisive proof result. Conditional recall and false-positive rate are therefore undefined, not zero.

| Package / class | Vulnerable revision | Fixed revision | Discovery each | Proof-ready / attempted each | Witnesses / reports |
| --- | --- | --- | ---: | ---: | ---: |
| GNU patch / double free | `dce4683c` | `15b158db` | 507 | 19 / 19 | 0 / 0 |
| libtiff tiffcrop / heap overflow | `5e180045` | `232282fd` | 1,152 | 23 / 23 | 0 / 0 |
| mruby / use after free | `70e57468` | `2742ded3` | 1,622 | 18 / 18 | 0 / 0 |

Across all six binaries, discovery emitted 6,562 candidates and proof attempted 120/120 eligible candidates. The verdict diagnostics were 80 backend setup errors and 40 wall timeouts. Replay imported no confirmation and reporting emitted no issue. All three fixed cases remain blocked because a backend error or timeout is not evidence that a binary is clean.

## Freeze identity

- Corpus: `unseen-multipackage-memory-safety-20260710`
- Analyzer SHA-256: `6bf23dde84b5aebc8d0bd9acd06c1f06ef07aba4247f83e6c687d40195e451bd`
- Manifest SHA-256: `91aa8d4ed4a4c2534be0c3edb3a261aaf7c0ce5bb80a6771092267a14894dccd`
- Frozen manifest: `/tmp/vulnfinder2-frozen-multipackage-20260710/frozen-manifest.json`
- Raw summary: `/tmp/vulnfinder2-frozen-multipackage-20260710/evaluation-summary.json`
- Raw runs: `/tmp/vulnfinder2-frozen-multipackage-20260710/runs`

The stripped binary hashes are:

- GNU patch vulnerable `82a3e056a4048bdd5fa08e41371496c79230e91d4025fd7fc6c229075cbaf500`
- GNU patch fixed `9072deadb84c01aad42a286fc5b8df2f840e7884eb1ebf9d844f4fba08df03b9`
- libtiff vulnerable `0162e14a35ec8e7675bcd60258bb5f7966719a68b380725b7858b40c91476830`
- libtiff fixed `f2d17a148a12b3b2e46e3947825511e9e195d431b525d03596805c14aa6d00c4`
- mruby vulnerable `dc44ee4c9f1608ac6c4982ae836eefe73c821e78bac674d01d34229f688f4380`
- mruby fixed `120581553804cf2a01c4826a82904f2c25f2b8bd45d8a2640098401672a40062`

Each pair used identical `-O0 -g0 -fno-inline -fno-omit-frame-pointer -fPIE` compilation, PIE plus RELRO/NOW linking, and stripping. The suite used 15-second per-candidate proof limits, 30,000 dynamic steps, four workers, a configured 4 GiB per-worker memory limit, and a 900-second per-case wall cap. No case hit the case cap.

## Selection and provenance

The analyzer hash was recorded before package selection. The packages were absent from the earlier development and frozen corpora. Each pair is an adjacent public upstream vulnerable/fixed revision:

- GNU patch CVE-2019-20633, `another_hunk` in `src/pch.c`
- libtiff CVE-2022-0891, `extractImageSection` in `tools/tiffcrop.c`
- mruby CVE-2020-6838, VM stack handling in `mrb_funcall_with_block`

Upstream reproducer inputs were archived externally for ground-truth review but were not passed to discovery, target resolution, or proof. No analyzer input changed between pre-selection hashing and completion of all six cases.

## Interpretation

The run establishes protocol integrity and exposes a backend-completion hole, not package-level detection capability. Candidate discovery and exhaustive scheduling scale to these binaries, but the present proof models do not complete the relevant parser and VM paths. The almost identical candidate and verdict counts within each vulnerable/fixed pair also show that this suite found no usable differential signal. Future work should address the 80 setup errors first, then the 40 paths that consumed their full wall budget; adding more detection classes would not improve these results.
