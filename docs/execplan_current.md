# Adjudicate every frozen OpenWrt candidate into two final buckets

This ExecPlan is a living document maintained in accordance with `PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current while implementation and the evidence campaign proceed.

## Purpose / Big Picture

The existing OpenWrt audit stops at 218 `needs_refinement` hypotheses. After this milestone a reviewer can prepare the immutable inventory, submit source or dynamic reviews, and finalize an authoritative ledger in which each frozen candidate ID occurs exactly once with only `bug` or `not_bug` as its decision. Finalization rejects missing, duplicate, unknown, weakly justified, or unhashed evidence instead of treating timeouts, failed replay, missing tooling, or silence as safety.

A security bug is a reachable defect in the shipped binary, including attacker-triggerable memory corruption, crash or denial of service, unbounded resource exhaustion, or an effect that crosses an intended trust boundary. Exact source proof may authorize the `bug` decision, but only the existing schema-v2 dynamic report gate may authorize a vulnerability report. The final ledger therefore remains separate from candidate and report schema v2.

The observable interface is `python -m binary_agent.cli.run_adjudication` with `prepare`, `review`, and `finalize` subcommands. The OpenWrt campaign writes only below `.ai/runs/openwrt-four-binary-adjudication-v1`. A successful finalization emits `adjudication_ledger.json`, derived schema-v2 candidate states, dynamically reportable schema-v2 reports, and a reconciliation summary. It succeeds twice with byte-identical decisions and hashes.

## Progress

- [x] (2026-07-14 03:20Z) Re-read `PLANS.md`, the prior living ExecPlan, the frozen v5 audit summary, all four v5 candidate-state files, normalized Ghidra manifests, schema-v2 candidate models, promotion gates, report gates, and entrypoint recovery.
- [x] (2026-07-14 03:28Z) Verified that v5 contains exactly 218 unique candidate IDs in exactly 109 `(binary, function, vulnerability class)` units. Counts are 116 uninitialized uses, 41 spatial writes, 32 null dereferences, 18 path or argument effects, and 11 leaks; binary totals are 131 procd, 2 ubus, 8 uclient-fetch, and 77 uhttpd.
- [x] (2026-07-14 03:31Z) Verified the official OpenWrt 24.10.4 x86/64 SDK filename and published SHA-256 `229e871f734a2cee5ce3ad6a3e98d3836b0899bfdeaea4d9c2c5cc7b1fce1407` from the release index.
- [x] (2026-07-14) Implemented immutable campaign preparation, exact operation binding, source/reference-build binding validation, evidence hashing, and 109 review-unit templates.
- [x] (2026-07-14) Implemented review admission and strict two-bucket finalization, including allowed bases, class obligations, report-gate separation, derived states, reconciliation, and deterministic output.
- [x] (2026-07-14) Extended generic entry recovery to structured uloop, runqueue, HTTP, and CGI callback registrations while retaining generic ELF-entry-to-main recovery and structured ubus recovery.
- [x] (2026-07-14) Added focused unit tests for completeness, duplicate and unknown IDs, weak negatives, source/build mismatch, exact STORE association, entry surfaces, allowed bases, obligations, evidence fan-out, and report separation.
- [x] (2026-07-14) Reacquired the four exact source commits and pinned SDK under the campaign directory, built symbol-rich references, and recorded exact-code source mappings without changing v5 inputs or hashes.
- [x] (2026-07-14) Exported complete high p-code and per-token operation mappings from all four frozen binaries. All 218 bindings resolve to numeric operations and all 41 spatial rows bind exact `STORE` operations.
- [x] (2026-07-14) Froze the real campaign manifest and 109 templates under `.ai/runs/openwrt-four-binary-adjudication-v1`; identical re-preparation preserved manifest SHA-256 `14d3dd5a7a6890d00224945ad5abca1017776bdc67addff07f8cd71eb240746c`.
- [x] (2026-07-14) Extended the independent certificate registry to cover definite assignment, exact object/capacity relations, non-null guards and caller contracts, ownership/lifetime, intended trust boundaries, and exact source-feasible violations. The checked partition now contains all 218 candidates with zero residual rows.
- [x] (2026-07-14) Admitted all 109 complete review units. The authoritative result is 215 `not_bug` decisions and three source-proven `bug` decisions: `56dd650f8163783e`, `81c149573838359b`, and `e6827c82f2beab13`.
- [x] (2026-07-14) Finalized twice with byte-identical output. Both runs produced ledger SHA-256 `9053642e51fb38d869f16fa4c0b7a4d6c9c6effc446b29dc9b3543aa8328d213`, summary SHA-256 `43b0f556c41cce3d48ffec0d475cf7896e21f4a2ef893240ee6852d089d1efc9`, and decision-set SHA-256 `97dfce654f5ddb81cab533368026f5014d932c0531acdca5ed280a6c9ecc9edf`.
- [x] (2026-07-14) Exercised the real finalization gate: it exited 2 on missing unit `679d9bd46eb7b6de` and wrote no ledger.
- [x] (2026-07-14) Ran repository verification: 926 tests passed and 5 skipped; compileall succeeded; pip reported no broken requirements.
- [x] (2026-07-14) Added proof-producing automation beside the frozen adjudication tools. The first rules independently verify x86 `CALL` return-slot stores and typed libubox intrusive-list field stores, emit hashed certificates, assemble only complete units, and leave every unsupported row in a residual queue.
- [x] (2026-07-14) Ran the automation against the real campaign and admitted 13 complete units containing 19 `not_bug` decisions. The independent checker proves that 19 certified plus 199 residual IDs partition all 218 frozen candidates exactly.
- [x] (2026-07-14) Re-ran generation and checking with identical tool/input bytes. Both runs produced run ID `6e486aaf4644368e` and byte-identical summary SHA-256 `f53a967b10147b5d86ffbd77ede7f460ef36a839418e29c8ae361c5423c22fe5`.
- [x] (2026-07-14) Ran final repository verification after automation: 933 tests passed and 5 skipped; compileall succeeded; pip reported no broken requirements.
- [x] (2026-07-14) Ran final repository verification after exhaustive adjudication: 946 tests passed and 5 skipped; compileall succeeded; pip reported no broken requirements.

## Surprises & Discoveries

- Observation: The frozen inventory already has the requested 109 natural review units, even though no adjudication model exists.
  Evidence: grouping all v5 states by target binary, `location.function_name`, and `vulnerability_type` produces 109 unique keys and 218 unique IDs.

- Observation: Candidate `location.address` usually names the containing function, not the memory instruction, and 23 `sink.operation_address` values are empty.
  Evidence: every state has a location address, but the first procd stack candidate uses `0x109606`, the function entry, while its normalized manifest contains distinct numeric `pcode_stores`. Preparation must resolve a candidate line to an exported STORE and finalization must never accept the function address as a spatial operation merely because it is hexadecimal.

- Observation: The prior source audit authoritatively refutes only seven initial proof-ready candidates and three extra semantic candidates; it does not affirmatively decide the retained 218.
  Evidence: `audit_summary.json` labels all 218 retained rows `needs_refinement` and its narrative explicitly says no real vulnerability was proven, which is not itself an allowed `not_bug` basis.

- Observation: Symbol-rich SDK rebuilds reproduce every executable `PT_LOAD` segment byte-for-byte for all four frozen binaries.
  Evidence: each mapping under `reference-builds/mappings` records equal executable-segment size and SHA-256 for the frozen and reference binary, so direct address-to-source review is permitted for procd, ubus, uclient-fetch, and uhttpd.

- Observation: C-line address lists alone were insufficient for exact operation binding, but complete high p-code plus decompiler-token mappings resolve the full inventory.
  Evidence: the finalized operation-export smoke contains 218 resolved operations. The resolver uses 137 explicit addresses, 61 token mappings, ten x86 call return-address stores, six named calls, three interprocedural stores, and one semantic mapping; every one of the 41 spatial bindings is a `STORE`.

- Observation: a destination-expression token can identify `CAST` or `PTRADD` at the same sequence address as the actual write.
  Evidence: two uhttpd spatial rows initially selected address-calculation p-code. The generic resolver now selects the unique token-mapped `STORE`, with a regression test covering that decompiler form.

- Observation: nineteen spatial candidates currently fall into two proof-friendly systematic families.
  Evidence: ten bindings identify apparent writes whose frozen x86 bytes are `CALL` instructions and whose written literal equals the instruction successor; nine further operations map through the byte-identical reference DWARF to pointer-width assignments in libubox `struct list_head` helpers.

- Observation: conservative proof automation materially reduces review work without making absence-of-proof decisions.
  Evidence: the real run independently checked ten `x86_call_return_slot_v1` and nine `libubox_typed_list_store_v1` certificates, admitted only 13 wholly covered units, withheld three partially covered units, and queued the remaining 199 IDs. The residual classes are 116 uninitialized uses, 32 null dereferences, 14 path effects, 13 stack writes, 11 leaks, nine other OOB writes, and four argument effects.

- Observation: exact source/path reasoning identified three security-relevant defects after the systematic false positives were removed.
  Evidence: two byte-matched `uh_path_lookup` STOREs can address offset `PATH_MAX` after appending a slash to a `PATH_MAX-1` canonical directory; a third exact STORE in `uh_defer_script` dereferences the unchecked result of pinned libubox `calloc_a` on a remote HTTP request path. Each certificate includes the exact operation, feasible violating relation, real entry chain, and attacker-controlled boundary.

- Observation: source-proven bugs remain intentionally separate from published schema-v2 reports.
  Evidence: the final ledger contains three `bug` decisions, while `reports/reports.json` contains zero vulnerabilities because none has an existing schema-v2 dynamic proof satisfying the report gate. Their derived states retain `needs_refinement` with adjudication metadata; all 215 `not_bug` rows become `rejected`.

## Decision Log

- Decision: Keep adjudication as a new module and artifact schema rather than changing `CandidateState` or vulnerability report schema v2.
  Rationale: the ledger answers a different, exhaustive research question; reportability remains controlled by the existing dynamic proof gate.
  Date/Author: 2026-07-14 / Codex

- Decision: Make evidence references structured `(path, sha256, kind)` records and verify their bytes during review and finalization.
  Rationale: a path alone is mutable and cannot satisfy the immutable-evidence requirement.
  Date/Author: 2026-07-14 / Codex

- Decision: Treat operation resolution and decision proof as separate gates.
  Rationale: locating a real instruction proves what code was analyzed, not whether its behavior is safe or exploitable.
  Date/Author: 2026-07-14 / Codex

- Decision: Allow one unit review artifact to fan out to several candidate rows only when it enumerates every covered candidate ID and contains candidate-specific operations and obligations.
  Rationale: this preserves the 109-unit workflow without weakening the requirement for 218 individual decisions.
  Date/Author: 2026-07-14 / Codex

- Decision: Export every high p-code operation and its decompiler-token association instead of synthesizing operation addresses from C line numbers.
  Rationale: the candidate location is a decompiler statement, while strict spatial evidence requires the exact numeric `STORE`; token metadata preserves that association without text inference.
  Date/Author: 2026-07-14 / Codex

- Decision: Add autoproving as new modules and a separate CLI rather than changing the already-frozen adjudication implementation.
  Rationale: the existing campaign hashes its preparation, review, and finalization tools. Additive automation can identify its own generator and checker hashes in every certificate while preserving that immutable boundary.
  Date/Author: 2026-07-14 / Codex

- Decision: Automation may emit a final decision only from a certificate recomputed by a separate checker; unsupported, ambiguous, or unavailable-tool cases remain residual.
  Rationale: a proof-producing rule can authorize a strict-hybrid basis, while a classifier score or failed attempt cannot.
  Date/Author: 2026-07-14 / Codex

- Decision: Authorize deterministic source-proven `bug` certificates in addition to `not_bug` certificates, but do not attach a schema-v2 report gate unless an existing dynamic proof passes it.
  Rationale: the two-bucket ledger permits exact source proof of feasibility, entry reachability, and attacker control, while vulnerability publication remains independently gated.
  Date/Author: 2026-07-14 / Codex

## Outcomes & Retrospective

The adjudication infrastructure, exact OpenWrt SDK/source binding, operation exports, proof-producing automation, and validation suite are complete. Preparation produces exactly 218 resolved candidate templates in 109 units, including exact `STORE` operations for every spatial candidate. All four symbol-rich references match the shipped executable bytes.

The completed campaign independently checks one immutable certificate for every frozen ID and has no residual queue. All 109 units are admitted. The final ledger reconciles to 215 `not_bug` and three `bug` decisions across the original binary and vulnerability-class totals. The bugs are two `PATH_MAX` boundary writes in uhttpd path lookup and one unchecked `calloc_a` result on the remote uhttpd deferred-script path.

Finalization succeeded twice with identical decision bytes and hashes. The three source-proven bugs do not create vulnerability reports because the existing schema-v2 dynamic report gate has not passed; this is the intended separation, not an unresolved adjudication. Full repository verification finished with 946 passing tests, five skips, successful compileall, and no broken requirements.

## Context and Orientation

Core Python code is under `src/binary_agent`. Schema-v2 candidate lifecycle types and JSON loaders are in `src/binary_agent/pipeline/models.py`; promotion and report gates are in `src/binary_agent/promotion/gates.py` and `src/binary_agent/proof.py`; deterministic entrypoint recovery is in `src/binary_agent/analysis/entrypoints.py` and `src/binary_agent/analysis/program_index.py`.

The immutable inputs are the four final `candidate_states.json` files under `.ai/runs/random-binary-audit/20260714-openwrt-batch-v5` and the binary/source/hash catalog in that directory's `audit_summary.json`. Their target binaries live in the frozen OpenWrt root filesystem under `.ai/runs/research-corpora/openwrt-ubus-route-v4/rootfs`. Cached Ghidra exports keyed by exact binary SHA-256 live under `.ai/runs/firmware-campaigns/cache/decomp`.

An adjudication basis is the affirmative proof form that authorizes a decision. A `bug` basis is either a schema-v2 dynamic proof of a concrete invariant violation or exact source proof of a feasible violation with a real entry path and attacker or trust-boundary control. A `not_bug` basis is exact source safety, complete CFG/SMT infeasibility, verified absence of the alleged semantics due to a modeling error, an intentional operation that crosses no security boundary, proof of unreachability from every enumerated entry, or exhaustive dynamic enumeration over a finite domain. A negative replay, timeout, sanitizer silence, missing harness, unsupported tool, or lack of proof is never a basis.

A source binding connects the shipped instruction to upstream source. Direct address-to-line binding is allowed only when reference-build code bytes match the frozen binary. If the build differs, the binding must instead record an equal function-byte fingerprint plus matching constants and call topology, and mark that weaker basis explicitly. A binary operation binding identifies a numeric instruction from normalized p-code metadata. For spatial candidates it must name a `STORE`; synthetic strings such as `0x...:line:...`, function-entry stand-ins, and missing operation addresses are invalid.

## Plan of Work

Add `src/binary_agent/adjudication.py`. Define immutable data models and validators for frozen candidates, evidence references, binary operations, source bindings, entry proofs, decision rows, and the final ledger. `prepare_campaign` will hash and copy the four state inputs and relevant normalized manifests into the campaign root, verify candidate and binary hashes against the prior audit, resolve exact normalized p-code operations, enumerate entry surfaces, and emit 109 deterministic review templates. It must not infer decisions.

Add `src/binary_agent/cli/run_adjudication.py` with `prepare`, `review`, and `finalize` subcommands. Review admission will validate unit membership, candidate uniqueness, allowed decision vocabulary, evidence hashes, source-build compatibility, exact operations, the chosen basis, and class-specific obligations before atomically writing one review file. Finalization repeats all validation from bytes on disk, requires exact set equality with the frozen inventory, and writes deterministic output.

Add `src/binary_agent/adjudication_certificates.py` as a small independent checker and `src/binary_agent/adjudication_autoprove.py` as the generator/orchestrator. The generator tries only registered proof rules, writes one immutable certificate per proven candidate, invokes the checker from certificate bytes, writes a residual record for every other candidate, and creates a review proposal only when every ID in a frozen unit is certified. `src/binary_agent/cli/run_adjudication_autoprove.py` exposes `run` and `check` modes without modifying the already-frozen core CLI. An optional `--admit` flag passes only complete checked proposals through the existing `admit_review` validator.

Finalization will derive copies of the schema-v2 states. Every `not_bug` row becomes `rejected`. A `bug` row becomes `report_ready` only if the existing report gate accepts an attached schema-v2 proof result; otherwise the original status is retained and an adjudication note records the source-proven bug. Reports are copied or produced only for dynamically reportable bugs. The authoritative ledger never changes the v5 files.

Extend `src/binary_agent/analysis/entrypoints.py` and `src/binary_agent/analysis/program_index.py` so complete structured callback registration metadata yields explicit entry surfaces for ubus methods, uloop callbacks, runqueue callbacks, HTTP handlers, and CGI handlers. Preserve the existing generic `__libc_start_main` handoff recovery from the ELF entry stub. Incomplete text guesses must not become structured surfaces.

Build the real campaign below `.ai/runs/openwrt-four-binary-adjudication-v1`. Download the official SDK archive into this directory, verify its SHA-256 before extraction, and keep all SDK/source/build trees below the same root or `/tmp`. Clone the exact procd, ubus, uclient, and uhttpd commits cataloged in v5. Build symbol-rich reference binaries with the SDK when the package build is reproducible; otherwise freeze the build mismatch and use only verified function fingerprints with constants and call topology. Never claim direct source mapping from a mismatched build.

Review each of the 109 units. Uninitialized rows require all-path source or High-SSA initialization for safety, or a feasible read-before-write path plus entry reach for a bug. Spatial writes require exact STORE, actual object and capacity, and the offset relation. Null rows require a dominating non-null proof or a feasible exact zero-address access. Path and argument effects require the real trust boundary; intended configuration, service execution, or CGI dispatch is safe only when no boundary escape occurs. Leak rows require ownership transfer, bounded lifetime, or cleanup for safety, while a bug requires repeatable external reach and unbounded unreleased generations.

## Concrete Steps

From `/home/colsmit/Documents/work/vulnfinder2`, run focused tests during implementation:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider tests/test_adjudication.py tests/test_entrypoints.py

Prepare the real campaign with explicit inputs and mappings using the CLI help as the authoritative argument reference:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m binary_agent.cli.run_adjudication prepare --help

Submit one completed unit artifact at a time:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m binary_agent.cli.run_adjudication review --help

Generate and independently check conservative proof certificates; `--admit` writes only wholly covered units through the normal review gate:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m binary_agent.cli.run_adjudication_autoprove run .ai/runs/openwrt-four-binary-adjudication-v1 --admit
    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m binary_agent.cli.run_adjudication_autoprove check .ai/runs/openwrt-four-binary-adjudication-v1

Finalize only after all 109 unit reviews are accepted:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m binary_agent.cli.run_adjudication finalize .ai/runs/openwrt-four-binary-adjudication-v1

Run final repository verification:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider
    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q src scripts ghidra_scripts tests
    .venv/bin/pip check

## Validation and Acceptance

Focused tests must show that preparation preserves all 218 IDs and creates 109 units; finalization rejects a missing, duplicate, or unknown ID; all non-binary decisions and weak negative bases fail; a direct source binding fails when build code differs; a fingerprint binding fails without equal function bytes, constants, and call topology; a spatial row fails without a numeric p-code STORE; generic main and each structured callback family become entry surfaces; every allowed decision basis has a positive and relevant negative test; class obligations cannot be bypassed by generic rationale text; one hashed unit artifact can cover several explicitly enumerated rows; and a source-proven bug does not automatically produce a schema-v2 report.

Real acceptance requires exactly 218 unique decisions, no unresolved internal states, exact set equality with frozen v5, all evidence hashes verified, and reconciliation by binary and vulnerability class. Every `bug` must meet strict hybrid proof. Every `not_bug` must contain an affirmative refutation. The ledger must finalize twice with identical decision rows and content hashes. The four original v5 state hashes, binary hashes, and all v1-v5 artifacts must remain unchanged.

## Idempotence and Recovery

Preparation uses atomic writes and refuses to replace a frozen manifest whose input hashes differ. Re-running it with identical bytes is safe. Review replaces only the named unit after validating the complete incoming artifact. Finalization writes temporary files and renames them only after every gate succeeds, so a failure leaves the last accepted ledger untouched. SDK archives are verified before extraction. Source checkouts and build trees are disposable and may be recreated from recorded repository URLs and commits. No cleanup command may delete original v1-v5 artifacts.

## Artifacts and Notes

The final artifact root is `.ai/runs/openwrt-four-binary-adjudication-v1`. It contains the frozen manifest and copied state/manifests, source/reference-build mappings, per-unit reviews and evidence, `adjudication_ledger.json`, derived schema-v2 states, dynamically authorized schema-v2 reports, and a summary. Original source artifacts remain outside this root and read-only; their hashes are copied into the frozen manifest.

## Interfaces and Dependencies

`binary_agent.adjudication.prepare_campaign(...)` accepts paths to the audit summary, candidate-state files, normalized Ghidra manifests, frozen binaries, and an output directory, returning the frozen manifest path. `admit_review(campaign_root, review_path)` validates and atomically stores one unit review. `finalize_campaign(campaign_root)` returns a result containing ledger, derived-state, report, and summary paths. `validate_decision(...)`, `validate_source_binding(...)`, and `resolve_exact_operation(...)` remain separately testable pure functions where possible.

The implementation uses only the Python standard library and existing repository models. Network download, Git, SDK tools, Ghidra, QEMU, and concolic engines are research-time inputs, not production dependencies.

Plan revision note (2026-07-14): replaced the completed transaction/reproducer plan with the single exhaustive OpenWrt adjudication milestone requested by the user, and recorded the verified starting counts and current operation-address limitation.
