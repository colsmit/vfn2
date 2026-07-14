# Frozen lifetime evaluation: NASM CVE-2020-24978

## Result

Status: blocked. The protocol was preserved, but the analyzer did not distinguish the vulnerable and fixed binaries within the fixed wall budget. This is not evidence that the fixed binary is clean.

| Case | Discovery | Proof-ready | Completed before cap | Replay | Reports | Classification |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| vulnerable parent `0491fda8` | 1,567 | 80 | 8 partial candidate artifacts | 0 | 0 | blocked/missed |
| fixed `8806c3ca` | 1,570 | 80 | 8 partial candidate artifacts | 0 | 0 | blocked |

Each case used a 90-second per-candidate proof budget, 100,000 dynamic steps, one proof worker, an 8 GiB worker limit, and a 900-second case wall cap. Both stopped in proof before `_concolic_run_summary.json` could be written. The completed candidates were unrelated overflow candidates and timed out before the known lifetime site was attempted.

## Freeze identity

- Analyzer SHA-256: `a4a44bf946c1ca17e7d9abccae90c983affa38cc1043ed4895d4f2954a2a1aa6`
- Manifest SHA-256: `e5920da4f72124fdc66eeb0499f20416e07d372b88196fbe9cc2a0d0f1bf0197`
- Vulnerable binary SHA-256: `249a0c244643d7f8c756768a5f62ac60beadb9f4102b74a022c96ac12b7ba487`
- Fixed binary SHA-256: `c873ac68585a9b9b7d85466124d221723c5567fc9d87082dcf454d4904f1fae3`
- Raw artifacts: `/tmp/vulnfinder2-frozen-lifetime-20260710`
- Machine-readable summary: `/tmp/vulnfinder2-frozen-lifetime-20260710/evaluation-summary.json`

The vulnerable build is the parent of upstream fix commit `8806c3ca007b84accac21dd88b900fb03614ceb7`. Both binaries were built at `-O0 -g0 -fno-inline -fno-omit-frame-pointer -fPIE`, linked as PIE with RELRO/NOW, then stripped identically.

## Independent ground truth

The vendor Bugzilla attachment was recovered from the Internet Archive and saved externally as `nasm-poc.asm`, SHA-256 `5b46fb1b659850b7fb529d3cfdda0e49d8e91e38db5882ec45303f1a8aefcd0f`. With `-f win`, the vulnerable stripped binary exits 134 after glibc reports a double free. The fixed stripped binary exits 1 with parser diagnostics and no allocator failure.

The PoC established the pair's ground truth; it was not injected into analyzer discovery, targeting, or proof.

## Interpretation

The lifetime implementation can prove concrete object identity on compiled stripped local programs, but this frozen package exposes a larger remaining constraint: broad promotion plus sequential 90-second proofs prevents a relevant candidate from being reached in a large binary. Candidate ranking remains absent, as required. The next improvement must reduce false proof readiness or make individual proofs complete sooner using exact targets and correct process state; it must not silently skip promoted candidates.
