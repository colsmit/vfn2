# Frozen unseen evaluation: GNU cflow CVE-2019-16165

## Protocol

The analyzer was hashed before selecting an evaluation target. Its pre-selection SHA-256 was `4b1268deec1455e0b22d57fac9f36293ce3600b6df180bc5f356fd5ca4e3300a`. GNU cflow was absent from the repository and development corpus. After that hash was recorded, the target was fixed as CVE-2019-16165: the upstream report demonstrates a heap use-after-free in `reference`, and upstream commit `b9a7cd5e9d4efb54141dd0d11c319bb97a4600c6` says it fixes the CVE by clearing the static caller before its symbol storage is freed.

The matched source revisions were the fix's direct parent, `99179c774509f800966341743fb8c53517b79806`, and the fix itself. Both were compiled from the same checkout with:

    CPPFLAGS='-include stdarg.h'
    CFLAGS='-O2 -g0 -fno-omit-frame-pointer -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE'
    LDFLAGS='-pie -Wl,-z,relro,-z,now'

The forced standard header is identical on both sides and is needed because this old source omits `stdarg.h` on a code path exposed by modern GCC. Both PIE executables were stripped with `strip --strip-all`. No source patch was applied.

The frozen corpus is `vulnfinder2-unseen-cflow-cve-2019-16165-20260710-v1`. The frozen manifest SHA-256 is `684b99f53ff5b1a98531e5343dafe264301f95fccd2f008d242e73ec626fd686`; it independently reproduced the pre-selection analyzer hash. Binary hashes are:

- vulnerable: `a28c8a04b5c709d66a7f6dc9d397849eb6f4f3ff7e7df738059874dc15c927f4`
- fixed: `d7aa9a1981ccfa52d6c7709f0820e744bb15eadba8aca1923796447bc8e70946`

The selector-free run used the full `intake,discovery,refinement,proof,replay,report` path, two proof workers, a 4096 MiB worker limit, ten-second proof budgets, 100,000 dynamic steps, and a 900-second case limit:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/run_known_overflow_corpus.py \
      --manifest /tmp/vulnfinder2-unseen-eval-20260710-cflow/frozen_manifest.json \
      --output-root /tmp/vulnfinder2-unseen-eval-20260710-cflow/runs \
      --cache-dir /tmp/vulnfinder2-unseen-eval-20260710-cflow/cache \
      --summary /tmp/vulnfinder2-unseen-eval-20260710-cflow/summary.json \
      --ghidra-dir /tmp/vulnfinder2-frozen-eval-20260709/tooling/ghidra_12.1.2_PUBLIC \
      --proof-jobs 2 --proof-memory-limit-mb 4096 \
      --proof-timeout-seconds 10 --proof-dynamic-max-steps 100000 \
      --case-timeout-seconds 900 --overwrite

Primary evidence:

- upstream report: <https://lists.gnu.org/archive/html/bug-cflow/2019-04/msg00001.html>
- upstream fix: <https://cgit.git.savannah.gnu.org/cgit/cflow.git/commit/?id=b9a7cd5e9d4efb54141dd0d11c319bb97a4600c6>

## Result

This was an honest blocked evaluation, not a detection success. The vulnerable side produced 377 discovery candidates and the fixed side 378. Each side had ten proof-eligible candidates, and all 20/20 were attempted. Neither side produced a witness, replay confirmation, or report. Eighteen verdicts ended at `exploration:wall_timeout`; two ended at `target_resolution:target_equals_harness_entry`. Both cases are therefore blocked, so neither recall nor false-positive rate is defined for this pair.

The existing deterministic UAF module emitted 14 UAF candidates on each side and did not distinguish the upstream fix. This exposes a specific detection limitation: text-local allocation/release/use matching does not model cflow's cross-function static-pointer lifetime. The run does establish frozen execution integrity and exhaustive attempt coverage, but it provides no evidence of unseen UAF capability.

Raw sources, builds, frozen manifest, exports, proof artifacts, and summary remain outside the repository under `/tmp/vulnfinder2-unseen-eval-20260710-cflow`.
