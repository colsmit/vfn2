# Build an autonomous, verifier-gated binary adjudication pipeline

This ExecPlan is a living document maintained in accordance with `PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current while implementation proceeds.

## Purpose / Big Picture

The project can already decompile binaries, generate candidates, package evidence, ask language models for hypotheses, attempt replay, and finalize a strict two-bucket ledger. Its remaining manual bottleneck is adjudication: the OpenWrt campaign reached a complete ledger only after source-specific proof rules were written by hand. Those rules can be replayed automatically, but they do not constitute automatic discovery, and one of them incorrectly marked a downstream null store as reachable even though an earlier memory copy would fault first.

After this milestone, a user can give the pipeline a prepared binary campaign and run one unattended adjudication command. General deterministic analyses handle cases they can prove. A direct OpenAI-compatible model reviews small, bounded evidence packs when semantic interpretation is needed. A configurable coding-agent command, such as Pi in noninteractive exec mode, handles cases that need source navigation, binary inspection, harness construction, or replay repair. Both model tiers are untrusted: they may propose claims, experiments, and root-cause groups, but only deterministic validators can admit `bug` or `not_bug` decisions.

The main demonstration is a clean rerun of the frozen 218-candidate OpenWrt campaign. It must produce two bug candidate rows for one low-severity path-boundary root cause, reject the downstream `dr->path` null candidate because its violating path faults earlier, and separately record the nearby unchecked allocation defect without promoting it as the frozen candidate. A second demonstration must use holdout examples not inspected while authoring the validators. The command must preserve hashes, provider provenance, model cost, agent transcripts, experiment artifacts, and final root-cause groups.

## Progress

- [x] (2026-07-14 15:28Z) Re-read `PLANS.md`, replaced the completed OpenWrt plan with this autonomous-adjudication plan, and audited the existing adjudication, certificate, direct-model, external-command, replay-repair, and test interfaces.
- [x] (2026-07-14 15:28Z) Confirmed the current OpenWrt bug rules are source-specific: `c_path_max_trailing_slash_overflow_v1` requires `uh_path_lookup` source lines 238 or 271, and `c_remote_unchecked_calloc_v1` requires the literal `dr->path = true;` statement.
- [x] (2026-07-14 15:28Z) Confirmed the host has no `pi` executable. The coding-agent integration must therefore be provider-neutral and testable with fixture executables; a real Pi command is optional runtime configuration rather than a development dependency.
- [x] (2026-07-14 15:35Z) Implemented deterministic, label-free investigation packs, exact pack re-derivation, a bounded external-command provider, proposal-shape validation, immutable proposal/error artifacts, and six focused tests.
- [x] (2026-07-14 16:04Z) Implemented the direct OpenAI-compatible provider script, immutable source-tree inventory, provider cost/provenance capture, and provider-neutral external-command adapter. Tiered campaign orchestration and call caps remain part of the integration milestone below.
- [x] (2026-07-14 16:34Z) Implemented general null verification with earliest-fault rejection. The frozen downstream allocation candidate is deterministically `not_bug` because `memcpy` faults first, while the unchecked allocation is retained as a nearby defect.
- [x] (2026-07-14 17:02Z) Implemented source callback/table call-graph reachability, exact array capacity recovery from source or symbol-rich binary symbols, `realpath` maximum-length dataflow, STORE-width/offset proof, downstream signed-promotion/list-initialization/layout proof, and causal root hashing. The untouched OpenWrt evidence now yields two verified bug rows with the same root-cause ID.
- [x] (2026-07-14 17:18Z) Added campaign-level root grouping and a generic semantic-investigation certificate. Certificate checking reloads the hashed pack and proposal, reruns the semantic verifier, and compares the complete verified payload; provider prose cannot alter a checked proof.
- [x] (2026-07-14 17:24Z) Integrated deterministic/direct/agent investigation tiers with autoprove and review rendering, added CLI provider commands/timeouts/call caps, and deleted both source-specific OpenWrt positive rules and their exact-line test.
- [x] (2026-07-14 17:29Z) Ran the existing frozen campaign unattended under tool run `59597ef9ac95293a`: 218 certificates, zero residuals, two semantic bug rows, one semantic `not_bug` row, one root group, one nearby allocation defect, and no model calls. An independent check re-derived all 218 certificates.
- [x] (2026-07-14 18:04Z) Finished adversarial and holdout coverage for renamed/shifted spatial stores, a guarded spatial variant, first/later null dereferences, proposal and certificate tampering, provider escalation, CFG-proof admission, and relocatable absolute DWARF paths.
- [x] (2026-07-14 18:01Z) Created `.ai/runs/openwrt-four-binary-adjudication-autonomous-acceptance` from frozen inputs with no reviews or generated decisions. One unattended pass admitted all 109 units and independently rechecked all 218 certificates. Finalization twice produced byte-identical hashes: ledger `e43451e6303d63bfe2daa6274e525947b5bf7ee8d3a808b0d33dfd8d220fb04f`, derived states `5804d22a799b46264534d3f1a27ec17905f726ee8401288e6f8f43a70082a8ea`, reports `a435f4bf016a64915bfba75714b9f2b59a0996e3ea04485ca0fb80a99a7a4cb2`, summary `52173b5c61810e85a31bf3d321b37df67a66c959d08756580cbb57fc89b2fc15`, and root groups `c433a973b5f1fcaae308d1dd8ec4bda928a014a9fffecae06e1a0d00bfa47814`.
- [x] (2026-07-14 18:10Z) Ran the full verification suite (`965 passed, 5 skipped`), compileall, and `pip check`; committed the milestone and pushed it to `origin/main` in `colsmit/vfn2`.

## Surprises & Discoveries

- Observation: the existing “independent checker” is independent of the generator but not independent of the semantic rule being checked.
  Evidence: `check_certificate` in `src/binary_agent/adjudication_certificates.py` calls `derive_rule_proof` again and compares payloads. This detects tampering and drift, but a mistaken premise shared by the registered rule is accepted twice.

- Observation: the OpenWrt allocation rule proves a real nearby robustness defect but not the exact frozen candidate.
  Evidence: source in the frozen campaign calls `memcpy(&dr->pi, pi, sizeof(*pi))` before `dr->path = true`; frozen disassembly likewise performs the copy before the candidate STORE. Under `dr == NULL`, the earlier operation faults and the exact candidate cannot execute.

- Observation: the two path candidates are separate exact STORE operations but share one capacity error.
  Evidence: `path_phys` is a `PATH_MAX` array immediately followed by static `struct path_info p` in the frozen binary. A `realpath` result of `PATH_MAX - 1` bytes leaves no room for appending both slash and terminator. The later index-loop STORE is reached through the same one-past pointer and must be grouped with the append STORE.

- Observation: provider-neutral subprocess seams already exist and should be reused.
  Evidence: `ExternalCommandSemanticSeedProvider`, `ExternalCommandHypothesisProvider`, and `ExternalCommandReplayRepairProvider` exchange JSON over standard input/output, enforce timeouts, and keep model output behind deterministic validators.

- Observation: frozen entry-surface metadata alone is insufficient for uhttpd, but the source contains a recoverable callback chain.
  Evidence: the new source graph recognizes function-pointer registration and callback tables and reaches the target function from registered handlers. Every file on the selected path is included in the pack's hashed source-tree inventory.

- Observation: exact symbol layout resolves the downstream-path ambiguity without replay.
  Evidence: the exact-code reference binary reports the 4096-byte pathname array immediately followed by a 200-byte static object. The second STORE can execute after the first one-past write; the default nonempty index list, signed-to-unsigned comparison, copy, and failing `stat` path are all present in hashed source.

- Observation: exact reference binaries are portable, but their DWARF file names can contain the absolute path of the build campaign.
  Evidence: the first clean copy stopped when a list-helper frame named the original campaign. The checker now relocates the longest existing path suffix below the copied campaign and still hashes the relocated file; a regression test covers this behavior.

- Observation: semantic certificates need evidence kinds based on the admitted basis, not on the implementation language of the verifier.
  Evidence: the clean run rejected the corrected null row until its generic certificate reference was classified as `cfg_smt_proof` rather than `source_review`. Basis-to-kind mapping is now explicit and tested through review admission.

## Decision Log

- Decision: build a new investigation stage rather than allowing language models to emit final review files.
  Rationale: a final review file is authoritative after admission. Model output must remain a proposal so unsupported prose or a plausible but unreachable path cannot bypass the evidence gate.
  Date/Author: 2026-07-14 / Codex

- Decision: use one provider protocol for both direct-model and coding-agent tiers, with tier-specific execution metadata.
  Rationale: the pipeline should route work by complexity without coupling core code to OpenRouter, Pi, Codex, or any other vendor. Direct API scripts and agent executables can both consume the same immutable pack and return the same proposal schema.
  Date/Author: 2026-07-14 / Codex

- Decision: validate claims by semantic shape and frozen evidence, never by candidate ID, fixed source line number, or a suppression list.
  Rationale: the current rules can reproduce known labels but cannot generalize. Holdout behavior is the acceptance test for this decision.
  Date/Author: 2026-07-14 / Codex

- Decision: model “earliest fault” explicitly for null and spatial paths.
  Rationale: exact-operation adjudication asks whether the selected binary operation executes on the violating path. A real earlier defect does not make an unreachable downstream candidate true, but it should be retained as a nearby defect for later candidate generation.
  Date/Author: 2026-07-14 / Codex

- Decision: keep deterministic rules as the first and cheapest tier, but require the autonomous path to reject rules containing frozen candidate IDs or exact source-line predicates.
  Rationale: reusable architecture and library contracts are valuable. Per-example answers hidden in code are not automation.
  Date/Author: 2026-07-14 / Codex

- Decision: hash the complete mapped C source inventory in each investigation pack.
  Rationale: callback recovery, wrapper contracts, and initialization proofs cross translation units. Exact-function hashing alone would allow the verifier to consume unrecorded mutable evidence.
  Date/Author: 2026-07-14 / Codex

## Outcomes & Retrospective

The autonomous stage is implemented and accepted on the frozen 218-candidate campaign. It produced 2 `bug` and 216 `not_bug` rows, zero residuals, one grouped path defect, one nearby unchecked-allocation defect, and zero schema-v2 vulnerability reports. No direct-model or coding-agent call was needed for this inventory because the deterministic tier proved all three former residuals; those provider tiers remain available and bounded for future binaries.

## Context and Orientation

The package lives in `src/binary_agent`. `src/binary_agent/adjudication.py` prepares immutable campaigns, validates review units, and finalizes ledgers. `src/binary_agent/adjudication_autoprove.py` tries registered deterministic rules and turns checked certificates into review proposals. `src/binary_agent/adjudication_certificates.py` contains those rules and their checker. The current two positive rules at the end of that file recognize exact OpenWrt functions and lines; they are the first rules this milestone must retire.

An investigation pack is a JSON document containing only immutable inputs needed to reason about one candidate: the frozen candidate row, exact binary operation, source/build binding, function source, bounded disassembly and p-code windows, entry surfaces, relevant library contracts, class-specific proof obligations, and hashes for every referenced file. It deliberately contains no expected label.

An investigation proposal is untrusted JSON returned by either model tier. It identifies a claim type, proposed decision, exact operation, symbolic path steps, object and capacity facts or pointer/null facts, entry reachability facts, requested experiments, possible earlier faults, nearby defects, and a root-cause fingerprint. It may quote source locations for navigation, but the verifier reloads those bytes and discovers locations itself; line numbers supplied by the model are never authority.

A verified investigation is a deterministic artifact produced after checking a proposal against frozen files. It either contains a complete proof suitable for a certificate or a structured rejection explaining which obligation failed. A coding-agent transcript or direct-model response is evidence about how a proposal was generated, not evidence that its security claim is correct.

A root-cause group connects candidate decisions that arise from the same defect. Its identity is a hash of the binary hash, containing function, causal operation, object identity, and normalized defect relation. Candidate IDs are members, not ingredients used to recognize the defect. A nearby defect is a verified source or binary operation discovered while rejecting a frozen candidate; it is recorded for future candidate generation but cannot silently replace the candidate being adjudicated.

## Plan of Work

Create `src/binary_agent/adjudication_investigation.py`. Define dataclasses and JSON validation for packs, proposals, provider attempts, verified investigations, nearby defects, and root-cause groups. Reuse the campaign containment and hashing discipline from `adjudication.py`; expose narrow public helpers from that module instead of copying unsafe path logic. Pack generation must be deterministic and idempotent. It must locate the exact function source through the existing reference mapping, include the entire containing function rather than a hand-selected few lines, and include bounded predecessor/successor machine operations so earliest-fault reasoning is possible.

In the same module, define an `InvestigationProvider` protocol with a method accepting a JSON-compatible pack and returning a JSON-compatible proposal. Add `ExternalCommandInvestigationProvider`, which sends one pack on standard input, receives one proposal on standard output, enforces a timeout and output-size limit, runs in a campaign-local task directory, and records command identity, executable hash when it is a file, exit status, duration, and standard-error hash. The core must not assume a particular agent command. A configured command such as `pi --mode exec ...` is data supplied at runtime.

Create `scripts/llm_adjudication_provider.py` using the existing helpers in `scripts/llm_provider_common.py`. It must support an OpenAI-compatible endpoint, request JSON output, include the proposal schema in its system prompt, attach token and wall-time cost metadata, and never read arbitrary repository files. The bounded pack is its complete input. Add configuration keys to `.env.example` for model, URL, key environment variable, timeout, and direct-to-agent escalation policy.

Create `src/binary_agent/adjudication_verifier.py`. It must validate proposals without trusting model conclusions. Implement a small source-function tokenizer that strips comments and strings safely enough to identify statements, nested blocks, branches, assignments, calls, array declarations, pointer arithmetic, member dereferences, and guards. Preserve source byte offsets so facts can be hashed and independently relocated. This is not a full C compiler; ambiguous constructs must reject or escalate rather than guess.

Implement a null-path verifier that finds the allocation or pointer origin named by the proposal, walks all straight-line operations and branch guards leading to the exact mapped operation, and enumerates every earlier dereference of the same pointer. An allocation-failure claim for a later operation is valid only if no earlier operation must fault. If an earlier fault exists, produce a `not_bug` proof for the exact candidate using complete path infeasibility and emit a nearby-defect record for the unchecked origin plus earliest dereference.

Implement a spatial verifier that obtains object capacity from a declaration, debug/source type, or binary symbol size; derives pointer offsets from assignments and increments; and applies registered API contracts such as `realpath` returning a string of at most `PATH_MAX - 1` bytes. It must evaluate the exact STORE width and all written offsets. For a downstream STORE, it must verify the branches and preceding calls that make that operation execute. Signed-to-unsigned comparisons and external-call outcomes must be explicit facts, not model prose.

Implement root-cause grouping after verification. Normalize the causal operation and defect relation, calculate the group hash, ensure all members have the same frozen binary and compatible causal facts, and write a campaign-level group index. The two path candidate operations should have distinct decision rows but one group. The allocation nearby defect must not join that group and must not become a frozen decision.

Extend `src/binary_agent/adjudication_autoprove.py` with a tiered mode. It first runs registered general deterministic rules. Residual candidates receive direct-model proposals if configured. Rejected or escalation-requested direct proposals receive coding-agent attempts if configured. Every attempt is immutable. Only `adjudication_verifier.py` may create a checked investigation. Checked investigations become certificates through a single generic certificate kind whose checker re-runs the semantic verifier from frozen evidence. Provider absence, timeout, invalid JSON, unsupported syntax, or failed experiment remains a residual state and can never become `not_bug`.

Remove `C_PATH_APPEND_BUG_RULE`, `C_REMOTE_CALLOC_BUG_RULE`, their derivation functions, and tests that manufacture the exact OpenWrt line numbers. Replace them with behavior tests using renamed functions, shifted lines, different variable names, and equivalent source structure. Add a static guard test that fails if autonomous rule or verifier source contains a frozen 16-hex candidate ID, matches a required exact source line number, or imports a candidate-specific suppression table.

Add `src/binary_agent/cli/run_adjudication_investigation.py` with `prepare`, `run`, `check`, and `finalize` modes, or extend the existing autoprove CLI if doing so yields a clearer single command. The unattended command must accept direct-provider and agent-provider commands, per-tier timeouts and call caps, and a clean campaign root. It must print counts for deterministic proofs, direct attempts, agent attempts, verified decisions, residuals, nearby defects, and root-cause groups.

Create holdout fixtures under `tests/fixtures/adjudication_holdout`. Include at least: a renamed PATH_MAX append flaw with shifted source layout; a safe append with an explicit two-byte capacity guard; an unchecked allocation whose exact candidate is the first dereference; an unchecked allocation whose candidate is preceded by another dereference; and two different downstream STORE candidates sharing one causal append. The tests must not use OpenWrt names or candidate IDs.

Finally, create a clean campaign copy below `.ai/runs` from the frozen manifest and immutable inputs, excluding existing reviews, autoprove output, and final ledgers. Run the autonomous command with no hand-edited reviews. Compare all 218 decisions and verify exactly two bug candidate rows, one path root-cause group, the rejected downstream allocation candidate, one nearby allocation defect, zero unhashed evidence, and deterministic second-run hashes. Run holdout evaluation and the full repository test commands.

## Concrete Steps

Work from `/home/colsmit/Documents/work/vulnfinder2`.

First implement and test pack generation and provider contracts:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider tests/test_adjudication_investigation.py -k 'pack or provider'

Then implement and test the semantic verifier and grouping:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider tests/test_adjudication_investigation.py -k 'reachability or earliest or bounds or root_cause or nearby'

Run the holdout suite without access to OpenWrt labels:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider tests/test_adjudication_holdout.py

Exercise the campaign CLI twice on a clean copy. The exact command will be recorded here after the CLI name and provider flags stabilize. Expected summary fields are:

    candidate_count: 218
    bug_candidate_count: 2
    not_bug_candidate_count: 216
    residual_candidate_count: 0
    root_cause_group_count_for_bug_candidates: 1
    nearby_defect_count_for_rejected_allocation_candidate: 1

Run final verification:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider
    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q src scripts ghidra_scripts tests
    .venv/bin/pip check

## Validation and Acceptance

Pack generation is accepted when two runs over unchanged frozen inputs produce byte-identical packs and all references verify by hash. A pack must fail checking after any referenced source, binary, mapping, or tool byte changes.

Provider orchestration is accepted when fixture direct and agent commands can propose work, timeouts and malformed JSON are recorded without decisions, cost/provenance fields survive into the summary, and no provider output can be admitted directly as a review.

Null verification is accepted when the same general code proves a first null dereference feasible and a later null dereference infeasible due to an earlier mandatory fault. The OpenWrt `dr->path` case must take the latter path and emit a nearby unchecked-allocation defect.

Spatial verification is accepted when renamed and line-shifted holdout source produces the same result, the guarded variant is safe, STORE widths and offsets are checked against actual object capacity, and the OpenWrt operations at `0x1076C2` and `0x1077CA` become two bug rows in one root-cause group.

The full milestone is accepted only when a clean unattended OpenWrt run finalizes all 218 IDs with 2/216 decisions, zero residuals, one grouped path defect, the separate nearby allocation record, and identical decision/group hashes on a second run. No schema-v2 vulnerability report is emitted without the existing dynamic report gate. Holdout tests and all repository tests must pass.

## Idempotence and Recovery

All stage outputs live below a selected campaign root and use content hashes or deterministic run IDs. Re-running unchanged inputs must preserve bytes. Provider attempts are append-safe immutable artifacts; a partially written attempt is created through a temporary file and atomic rename. A failed provider does not alter admitted reviews. To retry with a different provider, use a new run directory derived from provider and tool hashes.

Never edit frozen v1-v5 artifacts. Build clean campaign copies with hard links or verified copies under `.ai/runs`, and remove only generated directories inside the selected copy. Dynamic experiments remain network-disabled and bounded by the existing execution envelope. The coding-agent working directory contains copied or read-only evidence plus a dedicated artifact output directory; it must not receive credentials in its pack or transcript.

## Artifacts and Notes

The current source-specific positive rules are located at:

    src/binary_agent/adjudication_certificates.py:_derive_c_path_append_bug
    src/binary_agent/adjudication_certificates.py:_derive_c_remote_calloc_bug

The existing provider patterns to reuse are located at:

    src/binary_agent/discovery/semantic_seed.py:ExternalCommandSemanticSeedProvider
    src/binary_agent/analysis/hypothesis_generation.py:ExternalCommandHypothesisProvider
    src/binary_agent/replay/repair.py:ExternalCommandReplayRepairProvider
    scripts/llm_provider_common.py

The first audit transcript was:

    $ command -v pi
    # no output

    $ rg '^def _derive_c_(path_append_bug|remote_calloc_bug)' src/binary_agent/adjudication_certificates.py
    3657:def _derive_c_path_append_bug(...)
    3737:def _derive_c_remote_calloc_bug(...)

## Interfaces and Dependencies

In `src/binary_agent/adjudication_investigation.py`, define these stable interfaces:

    class InvestigationProvider(Protocol):
        def investigate(self, pack: Mapping[str, Any], *, tier: str) -> Mapping[str, Any]: ...

    @dataclass(frozen=True)
    class ExternalCommandInvestigationProvider:
        command: Sequence[str]
        timeout_seconds: float | None = None
        max_output_bytes: int = 1_000_000

    def build_investigation_pack(campaign_root: Path, candidate_id: str, output_dir: Path) -> Path: ...

    def run_investigation_stage(
        campaign_root: Path,
        *,
        direct_provider: InvestigationProvider | None,
        agent_provider: InvestigationProvider | None,
        output_dir: Path,
        candidate_ids: Sequence[str] | None = None,
    ) -> InvestigationStageResult: ...

In `src/binary_agent/adjudication_verifier.py`, define:

    def verify_investigation_proposal(
        campaign_root: Path,
        pack_path: Path,
        proposal_path: Path,
    ) -> VerifiedInvestigation: ...

    def verify_null_path(...): ...
    def verify_spatial_path(...): ...
    def group_verified_investigations(...): ...

Use only the Python standard library and existing project dependencies unless a parser prototype proves that a new dependency materially improves soundness and can be pinned. Direct API calls must remain in scripts or provider adapters so importing the core package never requires network access. Coding-agent commands are external optional tools and must not become package dependencies.

Revision note (2026-07-14 15:28Z): replaced the completed binary-adjudication plan with the autonomous, tiered, verifier-gated adjudication milestone after the OpenWrt audit showed that replayable hand-written rules were the principal obstacle to a genuinely automated pipeline.

Revision note (2026-07-14 18:10Z): completed the milestone after a clean 218-candidate run, independent certificate recheck, deterministic double finalization, holdout/adversarial suite, and full repository verification.
