# Scale autonomous adjudication across additional OpenWrt binaries

This ExecPlan is a living document maintained in accordance with `PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current while implementation proceeds.

## Purpose / Big Picture

The project has already finalized a strict, verifier-gated ledger for 218 candidates from four OpenWrt binaries. The next useful test is not another hand-picked example; it is a larger, label-blind batch that exercises different programs and forces the automation to reveal its scaling limits and unsupported semantics.

After this milestone, a user can run the current pipeline over three additional shipped OpenWrt 24.10.4 x86/64 programs—`rpcd`, `netifd`, and `busybox`—without manually editing candidate decisions. The campaign must freeze exact shipped binaries and exports, use exact source or binary evidence for every admitted decision, group duplicate symptoms by root cause, and leave unsupported work explicitly residual. When the run exposes a general analyzer or orchestration defect, this milestone fixes the general mechanism with regression coverage and reruns the batch. It never adds candidate-ID suppression lists or treats failed proof as safety.

The observable outcome is a campaign below `.ai/runs/openwrt-more-binaries-v1` whose summary reports the deterministic first-pass coverage, remaining review units, verified target bugs if any, and general automation improvements. The repository test suite and an end-to-end rerun must demonstrate that the improvements preserve the earlier strict-hybrid guarantees.

## Progress

- [x] (2026-07-14 16:34Z) Selected `rpcd`, `netifd`, and `busybox` before inspecting their current candidate output; froze shipped binary SHA-256 values and package versions.
- [x] (2026-07-14 16:42Z) Re-exported all three binaries with the current Ghidra exporter and ran intake, deterministic discovery, exact-operation refinement, and promotion. The authoritative inventory contains 1,181 candidates in 699 review units: 64 `rpcd`, 364 `netifd`, and 753 `busybox`.
- [x] (2026-07-14 16:43Z) Prepared a strict adjudication campaign with all 1,181 unique candidate IDs and exact frozen binary/export bindings. Source/reference mappings are intentionally not yet admitted so the first pass measures binary-only automation.
- [x] (2026-07-14 16:45Z) Started the binary-only autonomous pass and stopped it after measuring a campaign-context scaling defect: each candidate reparsed and rehashed a 19–209 MB export manifest. Eleven early candidates were soundly rejected as Ghidra import-cast or indirect-call artifacts, but the projected full pass was hours.
- [x] (2026-07-14 16:49Z) Implemented a stage-scoped, immutable campaign context index that verifies each frozen input once, parses each large manifest once per grouped binary, and preserves independent single-certificate checking.
- [x] (2026-07-14 16:49Z) Added regression tests for batch reuse, tampered-export rejection at index construction, candidate isolation, and fresh one-certificate revalidation. The focused suites pass 42 tests.
- [x] (2026-07-14 16:50Z) Reran the complete binary-only pass in 5.11 seconds with 962,808 KiB peak RSS. It produced 161 checked `not_bug` modeling-error certificates, 1,020 residuals, 44 complete review units, and 46 partial units. The independent check reproduced all 161 certificates in 4.19 seconds.
- [x] (2026-07-14 17:19Z) Rebuilt all three binaries from exact source pins with the OpenWrt 24.10.4 x86/64 SDK. `rpcd` and `busybox` match the shipped executable bytes; `netifd` differs globally and therefore remains forbidden from using a direct whole-binary source mapping.
- [x] (2026-07-14 17:20Z) Corrected two general lifetime-analysis errors: numeric constants no longer merge unrelated resource identities, and a dominating direct reassignment starts a new resource generation. Fresh discovery contains 1,171 candidates in 689 units: 63 `rpcd`, 364 `netifd`, and 744 `busybox`.
- [x] (2026-07-14 17:29Z) Added GNU/LLVM/elfutils `addr2line` fallback for valid GCC LTO DWARF and ran source-backed rules. The first corrected source pass produced 209 affirmative `not_bug` certificates and 962 residuals.
- [x] (2026-07-14 17:48Z) Added a verifier-recomputed process-split lifetime rule. It rejected all ten surviving lifetime claims by proving a child/parent `fork` split or a source-declared non-returning error path. The checked partition became 219 certificates and 952 residuals.
- [x] (2026-07-14 18:20Z) Implemented relocation-aware, unique per-function fingerprint mapping for the globally mismatched `netifd` build. It preserves literal constants and internal control flow while separately checking relocation shape and ordered call topology. This mapped 317 resolved operations, enabled source review for 316 candidates, and raised checked coverage to 301 with 870 residuals.
- [x] (2026-07-14 18:42Z) Extended the libubox table-initialization proof across a static helper parameter and its unique caller. It proved 48 additional candidates across bonding, bridge, veth, vlandev, macvlan, and VRF helpers. The authoritative run now has 349 independently checked `not_bug` certificates, 822 residuals, 108 complete units, and 63 partial units.
- [x] (2026-07-14 19:05Z) Corrected three general candidate-modeling errors: global pointer slots are no longer confused with their pointees, summary-derived writes retain their exact callee STORE, and nested callees retain the correct source/operation binding. Fresh discovery reduced the inventory to 975 candidates before exact-token expansion.
- [x] (2026-07-14 19:18Z) Added five conservative source contracts for typed link stores, bounded wrapper terminators, masked static ring indexes, trailing escape terminators, and macro-expanded typed members. Added a sixth contract for a guarded typed byte-array store. The checked source pass reached 357 certificates over a 976-record inventory.
- [x] (2026-07-14 19:53Z) Replaced fallback `function:line` uninitialized locations with exact token-to-p-code identities, preserved the opcode in candidate schema-v2 state, and prevented clustering from merging distinct token operations. Fixed adjudication of multiple p-code rows at one instruction so a declared CALL cannot bind to a PTRSUB, CAST, or INDIRECT at the same address.
- [x] (2026-07-14 20:03Z) Added a generic typed whole-struct output-initialization proof. It maps the initializer callee by function fingerprint, verifies an unconditional `memset(out, 0, sizeof(*out))`, proves CFG dominance, reads the compiled struct layout from reference DWARF, and resolved all 32 `device_dump_status` split-local findings.
- [x] (2026-07-14 20:09Z) Regenerated all three inventories after discovering that `netifd` and `rpcd` also contained pre-opcode fallback rows. The authoritative 976-record inventory now has 976 resolved bindings, 253 token-derived opcode matches, and zero synthetic uninitialized operations.
- [x] (2026-07-14 20:14Z) Ran and independently checked `.ai/runs/openwrt-more-binaries-v1/exact-machine-campaign-v3`. Both commands reproduce 259 checked certificates and 717 residuals. The reduction from 357 is intentional: exact p-code identity revoked 139 earlier same-address Ghidra modeling-error proofs, while the struct rule and other exact bindings added 41 sound proofs.
- [x] (2026-07-14 20:44Z) Resolved all 13 `netifd` `FUN_00409d1c` rows and ten of the eleven residual `FUN_0040ba5d` rows with a generalized libubox `blobmsg_parse` table proof. The rule now recognizes mixed pointer declarations, exact caller/inline DWARF frames, and guarded aliases in braced or immediate unbraced `if` bodies; undersized parse counts and short-circuit assignments remain residual in regression tests.
- [x] (2026-07-14 20:52Z) Resolved all 11 BusyBox `FUN_004480cc` rows. Ten have a compiled `struct stat` object whose every reaching path follows successful `stat` or `lstat`; one candidate is a verified modeling error because the exact call passes only the object's output address. Unsafe fallthrough and false success-flag counterexamples are rejected.
- [x] (2026-07-14 21:01Z) Proved the last `netifd` `FUN_0040ba5d` row is a real source-proven bug. Exact CALLIND `0x40BA9B` passes uninitialized stack slot `local_108` to `strcpy` when `__calloc_a` returns before assigning `iface_name`. The registered `add_dynamic` ubus entry is recovered from frozen method record `0x439300`; its hidden handler at `0x4157B9` uniquely fingerprint-matches pinned `netifd_add_dynamic` at `0x41580F` and passes a request string to `interface_alloc`.
- [x] (2026-07-14 21:18Z) Prepared current-tool-hash campaign `.ai/runs/openwrt-more-binaries-v1/exact-machine-campaign-v5`, ran it twice with admission, and independently re-derived all certificates. Both runs are byte-identical across the summary, residual queue, 308 certificates, and 91 admitted reviews. The exact partition is 307 `not_bug`, one source-proven `bug`, and 668 residuals.
- [x] (2026-07-14 21:18Z) Corrected admission-summary idempotence discovered during the first sibling rerun. `admitted_unit_count` now describes the resulting admitted state and existing reviews are revalidated and normalized, rather than reporting only files newly written by one invocation.
- [x] (2026-07-14 21:32Z) Preserved separately authored valid reviews during idempotent admission, added a regression test, and froze authoritative current-tool-hash campaign `.ai/runs/openwrt-more-binaries-v1/exact-machine-campaign-v6`. Two admitted runs and a fresh independent check reproduce 308 certificates, 668 residuals, and 91 admitted units with identical artifact hashes.
- [x] (2026-07-14 21:34Z) Completed repository-wide validation after the review-preservation regression: 1,017 tests passed and five skipped; `compileall` succeeded; `pip check` reported no broken requirements. Removed generated repository bytecode caches afterward.
- [x] (2026-07-14 22:19Z) Corrected the only Python 3.10 CI incompatibility by computing lifetime-token normalization before its f-string. Python 3.10.20 now compiles the entire tree and passes the 117 focused backend/corpus tests.
- [x] (2026-07-14 22:19Z) Froze authoritative current-tool-hash campaign `.ai/runs/openwrt-more-binaries-v1/exact-machine-campaign-v7`. Two admitted runs are byte-identical across summary, residual, certificate, and review artifacts; a fresh independent check reproduces 308 certificates, 668 residuals, and 91 admitted units.
- [x] (2026-07-14 22:19Z) Repeated repository-wide validation after the compatibility correction: 1,017 tests passed and five skipped; `compileall` succeeded under both Python 3.10.20 and the project Python 3.12.3; `pip check` reported no broken requirements.
- [ ] Publish the completed iteration to draft PR #1 and independently audit the pushed state.
- [x] (2026-07-14 20:15Z) Completed repository-wide validation: 1,007 tests passed and five skipped; `compileall` succeeded; `pip check` reported no broken requirements. The independent campaign check reproduced all 259 certificates and 717 residuals.
- [x] (2026-07-14 18:56Z) Committed and published the earlier 1,171-record milestone to `origin/main` as `b4b2637`. No generated run artifact was committed; that superseded campaign correctly emitted no final ledger while 822 rows lacked affirmative proof.
- [x] (2026-07-14 20:18Z) Committed the exact-operation iteration as `b6b4c03`, pushed `agent/enforce-exact-pcode-adjudication`, and opened draft PR #1 against `main`. Generated `.ai/runs` evidence remains ignored and was not committed.

## Surprises & Discoveries

- Observation: refreshing the exports under current Ghidra changed the normalized export hashes and reduced the authoritative candidate inventory from the diagnostic pass of 1,254 to 1,181 once intake-aware refinement was included.
  Evidence: the final toolchain logs report 64, 364, and 753 candidates, compared with the initial export-only discovery counts of 65, 407, and 782.

- Observation: only 20 of 1,181 candidates reached the legacy `proof_ready` state, and all 20 are lifetime-management claims (`double_close`, `use_after_close`, or `mismatched_deallocator`).
  Evidence: `rpcd` has eight proof-ready lifetime rows, `busybox` has twelve, and `netifd` has none. This makes lifetime modeling the first target-specific review cluster, but proof readiness is not a final decision.

- Observation: the autonomous adjudicator is computationally quadratic in practice with respect to candidate count and export size because `load_campaign_context` parses the complete per-binary export for every candidate, while `check_certificate` immediately repeats the work.
  Evidence: the frozen manifests are 19 MB for `rpcd`, 118 MB for `netifd`, and 209 MB for `busybox`. The interrupted first pass consumed about 90 seconds near 100% CPU while processing only the earliest portion of the sorted inventory.

- Observation: even without source mappings, the verifier already rejects Ghidra-only semantics deterministically.
  Evidence: the completed pass produced 96 `ghidra_import_pointer_cast_v1`, 41 `ghidra_indirect_call_effect_v1`, 19 `x86_call_return_slot_v1`, and five `x86_call_pcode_store_v1` certificates.

- Observation: stage-scoped reuse changes the large-campaign runtime by more than three orders of magnitude without changing proof rules.
  Evidence: the interrupted baseline was processing only the earliest candidates after about 90 seconds. The complete optimized pass took 5.11 seconds and its independent check took 4.19 seconds.

- Observation: Ghidra merged descriptor variables through numeric constants and across later assignments, producing ten net lifetime candidates that did not exist in source semantics.
  Evidence: the general alias and resource-generation corrections reduced discovery from 1,181 to 1,171 candidates. Exact source then proved the ten surviving lifetime rows were separated by `fork` or a non-returning error path.

- Observation: GNU binutils 2.42 can report `?:?` for valid GCC LTO DWARF that LLVM and elfutils resolve to exact inline/caller frames.
  Evidence: the fallback unlocked 32 additional source proofs and exact contexts for the lifetime candidates without changing reference bytes.

- Observation: a globally different reference executable can still support strict source binding for every candidate-bearing function when relocation-aware fingerprints are unique.
  Evidence: the `netifd` executable segments differ by 182 bytes, but all 96 functions containing its 321 residual candidates have unique normalized matches. Of those rows, 317 have resolved exact operations, 316 map through DWARF, and four remain unresolved rather than being guessed.

- Observation: source access alone is not enough; reusable interprocedural contracts materially improve autonomous coverage.
  Evidence: proving that a unique caller parses a full-capacity libubox table before passing it to a static helper resolved 48 candidates with one rule and no candidate-ID exceptions.

- Observation: the seven semantic-investigation certificates enabled by `netifd` source are all affirmative safety proofs, not target bugs.
  Evidence: six prove the proposed null path must fault at an earlier dereference and one proves a dominating terminating null guard. No model provider was invoked.

- Observation: exact operation addresses are not sufficient when Ghidra emits several high-p-code operations for one machine instruction.
  Evidence: the frozen netifd CALL at `0x427033` also carries many INDIRECT effects and two PTRSUB helpers. The old address-only resolver selected a PTRSUB; the corrected resolver selects CALL from the candidate's declared operation kind. Across the campaign, exact opcode binding revoked 98 import-CAST and 41 INDIRECT certificates that had been attached to the wrong same-address operation.

- Observation: optimizer scalar replacement can turn one initialized source struct into dozens of decompiler locals without preserving a source line for the LTO clone.
  Evidence: 32 `FUN_00426e8e` findings occupy offsets 16 through 116 of one 120-byte `device_settings` object. The exact call to `device_merge_settings` dominates every flagged use, the callee starts with `memset(n, 0, sizeof(*n))`, and reference DWARF maps every byte range into the compiled object.

- Observation: exact-token expansion must run on every binary, even when candidate counts do not change.
  Evidence: regenerated `netifd` replaced 136 IDs one-for-one, regenerated `rpcd` replaced nine, and final `busybox` replaced its last text-derived indirect-import row. Campaign v3 has 253 token-derived candidates whose frozen opcode exactly matches the prepared binding and zero synthetic uninitialized operations.

- Observation: stricter evidence can lower the automation coverage number while increasing confidence.
  Evidence: the source-backed pre-opcode pass reported 357 proofs. Campaign v3 reports 259 because 139 unsound same-address Ghidra proofs were removed and only 41 independently valid replacements were admitted, including all 32 struct-initialization rows.

- Observation: libubox definite assignment was hidden by ordinary C surface variation rather than different semantics.
  Evidence: mixed declarations such as `struct blob_attr *tb[MAX], *cur;`, caller/inline DWARF frame ordering, and immediate unbraced `if ((cur = tb[index]))` bodies accounted for 27 additional checked table proofs. Counterexamples with `MAX - 1` parse capacity or a short-circuit prefix remain residual.

- Observation: one machine comparison can consume fields from two compiled `struct stat` objects, so a source-line-only proof cannot identify which initialized object owns a candidate local.
  Evidence: the BusyBox proof reads exact CALL output-pointer p-code and 144-byte reference DWARF layouts to distinguish same-line objects. Campaign v6 has 32 checked stat-family initialization certificates and seven output-address modeling-error certificates.

- Observation: Ghidra can miss a real registered callback even when the shipped binary retains an unambiguous entry surface.
  Evidence: the frozen export has no `entry_surfaces` row for `netifd_add_dynamic`, but frozen `struct ubus_method` record `0x439300` names `add_dynamic` and points to `0x4157B9`. The 157-byte handler's normalized bytes, constants, calls, control flow, and relocation shape match the pinned reference callback. That path reaches the unchecked `calloc_a` auxiliary output used at exact CALLIND `0x40BA9B`.

- Observation: an otherwise content-addressed run was not fully idempotent because admission counted writes rather than state.
  Evidence: the first v4 repeat preserved identical certificate and residual hashes but changed `admitted_unit_count` from 91 to zero. After the general correction and review-preservation hardening, both v6 runs retain 91 and reproduce summary SHA-256 `b44503dd81df0aa28ff2864b6e47424531602b7a1855dfc9055bc9cd5975be5a` exactly.

## Decision Log

- Decision: use the intake-aware full toolchain outputs as the authoritative inventory instead of the earlier export-only diagnostic states.
  Rationale: intake supplies real entry surfaces and refinement binds exact p-code operations. The diagnostic run was useful for sizing but is not sufficient final evidence.
  Date/Author: 2026-07-14 / Codex

- Decision: measure binary-only deterministic coverage before adding source mappings or model providers.
  Rationale: this isolates what the shipped bytes and decompiler metadata can already prove and gives a clean baseline for the marginal value of source and model tiers.
  Date/Author: 2026-07-14 / Codex

- Decision: stop the projected multi-hour pass and fix context reuse as a general stage-level abstraction.
  Rationale: reparsing hundreds of megabytes per candidate is an orchestration defect, not legitimate proof cost. A stage-scoped index can validate immutable inputs once without weakening the public one-certificate checker used for independent reproduction.
  Date/Author: 2026-07-14 / Codex

- Decision: the campaign may retain residuals while work is actively in progress, but no residual, timeout, provider failure, or proof absence may become `not_bug`.
  Rationale: the strict-hybrid evidence standard is more important than an artificial completion count. Final decisions require affirmative proof.
  Date/Author: 2026-07-14 / Codex

- Decision: accept a mismatched reference build only at individual functions whose relocation-aware normalized byte fingerprint is unique and whose constants, control-flow, relocation shape, and call topology signatures match.
  Rationale: rejecting all `netifd` source loses valid evidence, while accepting a global mismatch is unsound. Per-function matching implements the planned weaker mapping basis and records it explicitly in every source binding.
  Date/Author: 2026-07-14 / Codex

- Decision: treat process separation and non-returning paths as positive lifetime refutations, not as negative replay evidence.
  Rationale: source and pinned SDK contracts affirmatively prove that the alleged pair of descriptor events cannot occur in one resource generation. This is stronger than observing that a replay did not fail.
  Date/Author: 2026-07-14 / Codex

- Decision: expand source rules by structural caller contracts rather than helper-name allowlists.
  Rationale: the unique-caller libubox rule naturally covered seven candidates beyond the initial bonding/bridge cluster and remains independently recomputable on future binaries.
  Date/Author: 2026-07-14 / Codex

- Decision: a candidate-declared p-code opcode takes precedence over every other operation at the same machine address; a missing declared opcode may use only the conservative compatibility path.
  Rationale: an address identifies an instruction, not a unique high-p-code semantic operation. Allowing a CALL candidate to bind to a same-address CAST, PTRSUB, or INDIRECT can manufacture a modeling-error proof for semantics the candidate never alleged.
  Date/Author: 2026-07-14 / Codex

- Decision: revoke previously admitted coverage when exact-operation re-binding invalidates its proof, even if the headline proof count falls.
  Rationale: coverage is useful only when every certificate proves the frozen candidate's operation. The 139 revoked certificates return to the residual queue rather than being grandfathered or suppressed.
  Date/Author: 2026-07-14 / Codex

- Decision: prove scalar-replaced struct initialization by joining binary SSA, CFG dominance, reference symbols, pinned source, and compiled DWARF layout.
  Rationale: source text alone cannot show which decompiler local belongs to the source struct, while binary stack offsets alone cannot establish the callee's all-path initialization contract. The combined proof is general and independently recomputable.
  Date/Author: 2026-07-14 / Codex

- Decision: preserve every prepared or failed campaign as an immutable sibling after candidate states or checker bytes change.
  Rationale: frozen tool hashes and candidate hashes are part of the evidence. Re-preparing `pcode-disambiguated-campaign-v1`, v2, and the authoritative `exact-machine-campaign-v3` makes the correction chain auditable without mutating prior results.
  Date/Author: 2026-07-14 / Codex

- Decision: classify the unchecked `calloc_a` auxiliary output as `bug`, but do not generate a schema-v2 vulnerability report.
  Rationale: pinned libubox proves a feasible allocation-failure path returns before defining the output, the exact frozen `strcpy` consumes that output, and a recovered registered ubus request path reaches it. This satisfies strict source-bug obligations, while no existing schema-v2 dynamic proof passes the separate publication gate.
  Date/Author: 2026-07-14 / Codex

- Decision: recover missing ubus callback entry surfaces from compiled method-table records and function fingerprints rather than trusting a source registration alone.
  Rationale: source proves intended registration, while the frozen data record and unique handler fingerprint prove that the shipped stripped executable contains the same callback even when Ghidra omitted it from the function inventory.
  Date/Author: 2026-07-14 / Codex

- Decision: make repeated admission describe and revalidate the resulting review state.
  Rationale: a deterministic run summary must not depend on whether identical review bytes already exist. Always normalizing the same complete proposal preserves evidence validation and produces stable summary, review, certificate, and residual hashes.
  Date/Author: 2026-07-14 / Codex

## Outcomes & Retrospective

The milestone remains in progress pending publication audit, but the three selected high-value clusters are complete. Campaign v7 independently reproduces 308 certificates over the unchanged 976-candidate inventory: 307 affirmative `not_bug` decisions and one real source-proven bug. General rules resolved 49 rows beyond v3: 27 additional blobmsg table rows, 16 additional checked stat-family rows, seven output-address modeling errors, and the allocator bug, offset by two rows that moved from a later array-object rule to the more exact output-address rule. This is 31.6% checked coverage, up from 26.5%, with no candidate-ID exceptions.

No exhaustive ledger is emitted because 668 rows still lack affirmative proof. The bug is not a published vulnerability: it is an unchecked low-memory failure in a registered control-plane path, and the dynamic schema-v2 report gate remains unsatisfied. The main lessons are that source invariants need compiled object identity, stripped callback reachability can be recovered from registered data structures, and deterministic automation includes idempotent artifact state as well as deterministic decisions.

## Context and Orientation

Core code lives under `src/binary_agent`. `src/binary_agent/adjudication.py` copies exact inputs into a campaign and creates one binding for every candidate. `src/binary_agent/adjudication_autoprove.py` tries registered deterministic proof rules, writes checked certificates, and optionally admits complete review units. `src/binary_agent/adjudication_certificates.py` defines `CampaignContext`, loads frozen inputs through `load_campaign_context`, derives rule proofs, and independently checks certificates. `src/binary_agent/adjudication_investigation.py` packages residual candidates for optional direct-model or coding-agent providers; all provider proposals remain untrusted until `src/binary_agent/adjudication_verifier.py` checks them.

A campaign context is the immutable evidence needed to evaluate one candidate: the frozen campaign manifest, candidate state, exact operation binding, shipped binary, and normalized Ghidra export. The normalized export can be hundreds of megabytes because it includes every recovered function and p-code operation. A campaign context index in this plan means a stage-local object that verifies each frozen file hash once, parses each shared JSON file once, indexes candidates by ID, and returns candidate-specific immutable views. It is not a global cache and must not survive across commands or conceal file mutations from a later independent check.

The research artifacts live below `.ai/runs/openwrt-more-binaries-v1` and are intentionally ignored by Git. The shipped binaries come from the extracted OpenWrt root filesystem at `.ai/runs/firmware-campaigns/20260712-232226/images/openwrt-24.10.4-x86-64-rootfs/rootfs`. The normalized exports live in the SHA-keyed cache under `.ai/runs/firmware-campaigns/cache/decomp`. The current immutable campaign root is `.ai/runs/openwrt-more-binaries-v1/exact-machine-campaign-v7`, prepared from the unchanged v3 input hashes with current checker/generator hashes. Earlier `lifetime-fixed`, `exact-token-fixed`, `pcode-disambiguated`, v3, and superseded v4/v5/v6 campaigns remain reproducibility evidence and are not authoritative.

The selected package source commits are `bba95191ff2f22c9118a1ba1355b83afaa277ae3` for `rpcd` and `7901e66c5f273bceee8981bc8a0c8b0e60945f60` for `netifd`. BusyBox is OpenWrt's patched 1.36.1-r2 package, so its eventual reference mapping must cover both the upstream source and the exact OpenWrt patch/configuration set. The official SDK and OpenWrt buildroot already exist below `.ai/runs/openwrt-four-binary-adjudication-v1`; reuse verified bytes but copy or reference them only within `.ai/runs`.

## Plan of Work

First, add a stage-scoped campaign context index in `src/binary_agent/adjudication_certificates.py`. Construction must resolve and hash-check `frozen_manifest.json`, every referenced candidate-state file, shipped binary, export manifest, binding file, and candidate membership. It should parse shared JSON payloads once and expose `load(candidate_id) -> CampaignContext`. Keep `load_campaign_context` as the independent one-shot API, implemented through a fresh index or equivalent strict path, so callers outside a batch do not acquire hidden global state.

Next, modify `run_autoprove` in `src/binary_agent/adjudication_autoprove.py` to construct one index and reuse it for deterministic derivation and immediate certificate checking. Extend `check_certificate` with a private or keyword-only prevalidated context parameter, or add an internal checked helper, so the batch can avoid reloading while the public default still independently verifies disk state. Make `check_all_certificates` construct a fresh index for its entire independent pass. If investigation pack generation repeatedly reloads the same campaign, thread the same abstraction through that stage without permitting providers to access mutable repository state.

Add focused tests in `tests/test_adjudication_autoprove.py`. Instrument JSON loading or use a small fake campaign to assert that a multi-candidate same-binary batch parses its export once. Mutate a frozen input before index construction and require rejection. Ensure an unknown candidate and a candidate from another binary cannot receive the wrong state, binding, or export. Ensure a normal one-certificate `check_certificate` still notices post-run tampering. Record a benchmark from the 1,181-candidate campaign.

The context optimization, source builds, corrected rediscovery, exact opcode binding, lifetime refutation, function-fingerprint mapping, blobmsg/stat-family contracts, callback recovery, and idempotent admission are complete. Continue from authoritative residual run `ed205d0fd2dc89b1` in `exact-machine-campaign-v7`. Cluster rows by binary, source-bound function, vulnerability class, and exact p-code opcode. The next largest complete semantic units are nine BusyBox uninitialized rows each in `FUN_0040a71c`, `FUN_00414f83`, and `FUN_00412b3e`, followed by eight in `FUN_00410f12`. Before adding a rule, recover the exact source function, compiled object, and all reaching paths, then require the proof to reject an unsafe counterexample fixture.

Extend deterministic rules only when a source structure gives a conservative reusable proof. Do not restore the removed Ghidra CAST/INDIRECT counts unless the candidate's own frozen p-code identity is CAST or INDIRECT. Use direct-model or coding-agent tiers only after provider credentials or tools exist, and keep their proposals untrusted until the existing verifier accepts exact evidence.

Any target bug must still be checked at its exact operation and reachable entry surface. Any systematic false positive must become a general analyzer correction with a regression test, followed by rediscovery and a freshly prepared campaign when candidate semantics change. A certificate-rule improvement may rerun the same immutable campaign because it changes only derived evidence, not frozen inputs.

## Concrete Steps

Work from `/home/colsmit/Documents/work/vulnfinder2`.

Run focused loader and certificate tests while implementing:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider tests/test_adjudication_autoprove.py tests/test_adjudication_investigation.py

Rerun and independently check the current immutable campaign:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m binary_agent.cli.run_adjudication_autoprove run --admit .ai/runs/openwrt-more-binaries-v1/exact-machine-campaign-v7
    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m binary_agent.cli.run_adjudication_autoprove check .ai/runs/openwrt-more-binaries-v1/exact-machine-campaign-v7

The command must complete in minutes rather than hours, and `candidate_count` must remain 976. The current expected result is 308 checked certificates, 668 residuals, 91 complete/admitted units, and run ID `ed205d0fd2dc89b1`; `check` must reproduce all certificate counts. A second unchanged `run --admit` must preserve exact summary, residual, certificate-tree, and review-tree hashes.

After source mappings and semantic investigation are complete, run the full repository validation:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider
    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q src scripts ghidra_scripts tests
    .venv/bin/pip check

## Validation and Acceptance

The context optimization is accepted: a same-binary multi-candidate run parses each large export and candidate-state artifact once per command, all frozen hashes are checked before use, independent checking still detects later tampering, and regression tests pass. The corrected 976-candidate source-backed pass must finish without candidate loss or duplicate IDs and its independent check must reproduce every certificate. No uninitialized candidate may retain a synthetic `function:line` operation, and a declared p-code opcode must never bind to a different same-address opcode.

The target campaign is accepted incrementally. Every admitted decision must be `bug` or `not_bug` and reference exact hashed evidence. Every `bug` must prove a reachable security-relevant defect in the shipped binary. Every `not_bug` must affirmatively prove safety, infeasibility, intentional boundary behavior, unreachable code, exhaustive finite enumeration, or a verified modeling error. Provider output alone, sanitizer silence, one negative replay, timeout, or missing tooling is never sufficient.

If every candidate cannot yet satisfy the evidence gate, the campaign summary must preserve an exact residual partition and explain the unsupported semantic clusters. That result is still useful progress toward a fully automated pipeline, but the final ledger must not be emitted until every frozen candidate has one sound decision. Counts must reconcile by binary, class, rule, decision, and root cause.

## Idempotence and Recovery

The prepared campaign is immutable. Rerunning unchanged tool bytes uses a content-derived autoprove run ID and must reproduce identical summary, residual, certificate, and admitted-review bytes. An interrupted autoprove run may leave files only under its generated run directory; prepare a clean sibling campaign before measuring again. Never modify frozen candidate states, manifests, bindings, or the earlier OpenWrt v1–v5 and acceptance campaigns.

Stage-scoped indexes exist only in memory. They may assume files remain immutable during one command after their hashes are checked, but a new command must rebuild and revalidate the index. Dynamic work, if needed, runs only against copied root filesystems with networking disabled, bounded processes, fake effect targets, and complete cleanup.

## Artifacts and Notes

The current authoritative hashes and counts are recorded in `.ai/runs/openwrt-more-binaries-v1/exact-machine-operation-audit.json`. The initial selection snapshot is `.ai/runs/openwrt-more-binaries-v1/selection.json`. Toolchain outputs for the exact-operation regeneration are below `.ai/runs/openwrt-more-binaries-v1/toolchain-exact-machine-v19` and `.ai/runs/openwrt-more-binaries-v1/toolchain-pcode-disambiguated-v18`.

The baseline and optimized rerun showed:

    frozen export sizes: rpcd 19 MB, netifd 118 MB, busybox 209 MB
    frozen candidates: 1,181
    review units: 699
    early checked modeling-error certificates: 11
    observed process state: about 100% CPU in repeated json.loads
    optimized full pass: 161 certificates, 1,020 residuals, 5.11 seconds
    optimized independent check: 161 certificates, 4.19 seconds

The superseded v3 source-backed exact-operation run showed:

    corrected frozen candidates: 976
    resolved exact bindings: 976
    exact token/opcode bindings: 253
    synthetic uninitialized operations: 0
    authoritative run ID: f1599e2fe0ada9ee
    checked not_bug certificates: 259
    struct-output initialization certificates: 32
    target bugs: 0
    residual candidates: 717
    complete units: 84
    run time / peak RSS: 2:49.80 / 1,040,404 KiB
    independent check: 259 certificates, 717 residuals, 0:37.66

The current v7 cluster-resolution run shows:

    frozen manifest SHA-256: 67c8745953428cab50d355741916529a504a6a15972ecee30741e1845978f128
    authoritative run ID: ed205d0fd2dc89b1
    checked decisions: 307 not_bug, 1 bug
    residual candidates: 668
    complete/admitted units: 91 / 91
    decision counts by binary: busybox 82 not_bug; netifd 202 not_bug + 1 bug; rpcd 23 not_bug
    blobmsg table certificates: 104
    checked stat-family certificates: 32
    stat output-address modeling errors: 7
    unchecked calloc_a output bugs: 1
    summary SHA-256: 791e37a8f3c9ac78967edb1c7ce8ace82c3710da2eea9b863089b0ccb59c0d06
    residual SHA-256: f14c2fd390169a5a2bd717c941d2cff5911372b50c2bcb03ec41e7afda46a92b
    certificate-tree SHA-256: 1c1ddee041515ec7c79ff13cc1bccf15dbc82f0dc4d22652920feda29ad3d016
    review-tree SHA-256: db9b8c0af74d5e808f2ea2820ab34a9a3df26addba155459eef4347ad5391017
    repeated run: all four hashes identical
    independent check: 308 certificates, 668 residuals

## Interfaces and Dependencies

In `src/binary_agent/adjudication_certificates.py`, add a batch abstraction with an interface equivalent to:

    class CampaignContextIndex:
        @classmethod
        def build(cls, campaign_root: Path) -> CampaignContextIndex: ...
        def load(self, candidate_id: str) -> CampaignContext: ...

The exact dataclass fields are implementation details, but the object must own prevalidated manifest/input/state/export indexes and must never accept candidate data from provider output.

Keep these public behaviors stable:

    def load_campaign_context(campaign_root: Path, candidate_id: str) -> CampaignContext: ...
    def check_certificate(campaign_root: Path, certificate_path: Path) -> dict[str, Any]: ...

Internal batch callers may pass a prevalidated context or index through a keyword-only argument, but ordinary callers must receive fresh disk validation. Use existing project dependencies only. The function-fingerprint mapper uses the already-required Capstone package to decode x86-64 instructions while normalizing only proven code/data address fields.

Revision note (2026-07-14 18:45Z): updated the plan after corrected rediscovery, exact source builds, lifetime refutation, relocation-aware `netifd` function mapping, and interprocedural libubox table proofs raised independently checked coverage to 349 of 1,171 candidates.

Revision note (2026-07-14 20:15Z): superseded the 1,171-record checkpoint after general candidate-modeling corrections and exact token-to-p-code expansion. Recorded the 976-record exact-operation campaign, the deliberate revocation of 139 wrong-operation certificates, the 32-row compiled struct initializer proof, the 259/717 checked partition, and the next residual clusters.

Revision note (2026-07-14 21:19Z): completed the three selected residual clusters with generalized blobmsg and stat-family proofs, recorded the real unchecked `calloc_a` output bug and frozen ubus callback recovery, fixed admission idempotence, and made exact-machine campaign v5 authoritative at 308 checked decisions and 668 residuals.

Revision note (2026-07-14 21:34Z): recorded final local verification of 1,017 passing tests, five skips, successful compilation, dependency consistency, and repository cache cleanup before publication.

Revision note (2026-07-14 21:32Z): hardened idempotent admission to preserve separately authored valid reviews and superseded v5 with current-tool-hash campaign v6. Recorded the v6 run ID, manifest hash, byte-identical repeat hashes, and independent 308/668 partition check.

Revision note (2026-07-14 22:19Z): corrected the Python 3.10 discovery syntax exposed by draft-PR CI, superseded v6 with current-tool-hash campaign v7, and recorded its byte-identical rerun, fresh independent 308/668 check, and repository-wide validation.
