# binary-scan-agent

`binary-scan-agent` is a research pipeline for proof-gated vulnerability analysis of stripped binaries and firmware trees. Deterministic analysis discovers candidates, symbolic and Ghidra execution build exact evidence, concrete replay checks dynamic witnesses, and only candidates that satisfy their taxonomy proof policy are promoted to vulnerability reports.

LLMs are optional. They may propose semantic seeds, environment hypotheses, or replay repairs, but their output is validated and never constitutes a vulnerability verdict.

## Research scope

The canonical registry currently contains 34 vulnerability names across four proof backends:

- `memory_access` proves exact invalid reads or writes, including overflow, null access, undefined reads, and overlapping copies.
- `memory_lifetime` proves generation-aware resource misuse such as use-after-free, duplicate release, mismatched release, and live resources at scope exit.
- `semantic_effect` proves a process-visible effect such as command, query, code, header, log, redirect, or outbound-network behavior at an exact operation.
- `static_evidence` proves an exact reachable literal consumer or security configuration while redacting sensitive literal values from artifacts.

The strongest general path remains native memory analysis around modeled C library and direct memory operations. The registered semantic and static slices are exact regression contracts, not a claim that arbitrary application protocols are completely modeled. Coverage remains incomplete for complex services, unsupported process inputs, and unmodeled libraries. Existing known-vulnerability cases are development regressions, not held-out evidence. A genuinely unseen evaluation corpus must be frozen externally before it can support generalization claims.

Fortified calls are modeled as checked operations. If `__strcpy_chk` or another checked call aborts before an invalid write, the pipeline must not report memory corruption. Native fortify diagnostics also veto a contradictory emulated overflow result.

## Install

Python 3.10 or newer is required.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,concolic]'
```

Set `GHIDRA_INSTALL_DIR` to an installed Ghidra directory, or let `scripts/decompile.py` use its documented bootstrap behavior. Copy `.env.example` only for settings you actually use.

## Canonical workflow

Build the sample binaries:

```bash
make -C samples/vuln_demo clean all
```

Run the complete proof-gated toolchain:

```bash
python -m binary_agent.cli.toolchain \
  samples/vuln_demo/build/vuln_demo_stripped
```

The default stages are:

```text
intake -> semantic_seed -> discovery -> refinement -> proof -> hypothesis -> replay -> report
```

Semantic-seed and hypothesis stages are deterministic unless an explicit provider command is supplied. Every promoted proof-ready candidate is attempted in a fresh process. Typical bounded proof controls are `--proof-timeout-seconds`, `--proof-memory-limit-mb`, `--proof-dynamic-max-steps`, and `--proof-jobs`. Use `--stages` to rerun a subset of the current pipeline; there is no legacy toolchain mode.

Each run is written under `runs/<target>/<timestamp>/`. Important artifacts include candidate states, schema-v3 evidence packs, concolic verdicts, replay results, promotion decisions, lean reports, and vendor evidence bundles.

The sample also builds `vuln_demo_fortified_stripped`. It is a negative regression for the proof boundary: the fortified call prevents the overwrite and must produce no memory-corruption report.

## Existing-export diagnostics

To inspect an existing Ghidra export without running proof and replay:

```bash
python -m binary_agent.cli.run_pipeline artifacts/<binary>/<timestamp>/decompiled
```

This is a deterministic diagnostic interface, not the production proof path. `--report-policy confirmed --confirmation-dir DIR` can load replay confirmations produced elsewhere. New evidence packs written by this command use schema v3.

To decompile only:

```bash
python scripts/decompile.py samples/vuln_demo/build/vuln_demo_stripped
```

## Optional model providers

The current model-assisted stages are enabled explicitly:

```bash
python -m binary_agent.cli.toolchain TARGET \
  --llm-semantic-seed-provider-command auto \
  --llm-hypothesis-provider-command auto \
  --llm-repair-provider-command auto
```

Set `OPENROUTER_API_KEY` or point `OPENROUTER_API_KEY_FILE` at a key file. Provider helpers only inspect the explicit path and local `secrets/` files; they do not search sibling repositories. Stage-specific model, base-URL, and API-key environment overrides are listed in `.env.example`.

Use `--require-live-llm` when a run must fail rather than silently execute without live model calls.

## Regression and capability evaluation

Run the development corpus without targeting known candidate addresses:

```bash
python scripts/run_known_overflow_corpus.py \
  --regression-subset \
  --output-root /tmp/vulnfinder2-regressions
```

Run a capability sweep over a target manifest:

```bash
python -m binary_agent.cli.run_capability_sweep TARGETS.json \
  --output-dir /tmp/vulnfinder2-sweep
```

Run a normalized benchmark suite:

```bash
python -m binary_agent.cli.run_capability_benchmark SUITE.json \
  --output-dir /tmp/vulnfinder2-benchmark
```

Blocked targets and missing inputs are recorded separately. They do not count as clean negatives or passed targets. Target manifests describe inputs and expectations; a manifest is not benchmark evidence by itself.

Run the repository-contained schema-v2 vulnerable/fixed corpus:

```bash
python -m binary_agent.cli.run_corpus \
  tests/fixtures/schema2_corpus/manifest.json \
  --output-dir /tmp/vulnfinder2-schema2-ci \
  --mode lightweight
```

Full Ghidra-backed manifests use `--mode full`. See [docs/corpus_runner.md](docs/corpus_runner.md) for the manifest, cache, differential, and CI contracts.

## Validation

```bash
python -m pytest
python -m compileall -q src scripts ghidra_scripts
python -m pip check
```

Optional real-Ghidra tests require `GHIDRA_INSTALL_DIR` and the built sample binaries. Generated runs, caches, and corpus sources belong in ignored directories or `/tmp`, not in source control.

## Durable research matrix

Use the registered research matrix when an experiment should survive ordinary `/tmp` cleanup:

```bash
python -m binary_agent.cli.run_research_matrix \
  --mode lightweight \
  --output-root .ai/runs/registered-matrix
```

Lightweight mode runs the semantic and static registered pairs and records the exact null/leak matrix as `skipped_requires_full_ghidra`. Full mode runs all thirty registered lanes:

```bash
python -m binary_agent.cli.run_research_matrix \
  --mode full \
  --output-root .ai/runs/registered-matrix
```

Each invocation creates a timestamped experiment, reuses shared per-corpus Ghidra caches, writes `research_matrix_summary.json`, hashes candidate/proof/report JSON, and atomically updates `.ai/runs/registered-matrix/latest.json`. These are ignored workstation research artifacts; do not commit them.

## Validation tiers

The ordinary suite is deterministic and does not require Ghidra:

```bash
python -m pytest
```

Research preflight reports native tools, optional Python analysis packages, built samples, Ghidra, and external-corpus availability separately:

```bash
python -m binary_agent.cli.run_research_validation \
  --preflight-only \
  --output-root .ai/runs/research-validation
```

Live Ghidra tests require `BINARY_AGENT_RUN_GHIDRA_VALIDATION=1`, `GHIDRA_INSTALL_DIR`, and `make -C samples/vuln_demo all`. The historical linked OpenSSL Heartbleed harness is an external evaluation input; if it is absent, preflight records `external_blocked` rather than treating it as a clean result.

To build the samples and run both available live-Ghidra tiers into durable logs:

```bash
python -m binary_agent.cli.run_research_validation \
  --ghidra-dir /path/to/ghidra \
  --build-samples \
  --run-live-ghidra \
  --output-root .ai/runs/research-validation
```

This runs the three in-repository process validations and the existing-class vulnerable/fixed matrix. It invokes tests through the active Python interpreter so copied virtual environments with stale generated launcher shebangs cannot silently select another checkout.

## Repository layout

- `src/binary_agent/analysis`: deterministic facts, candidates, source taint, concolic models, and proof logic
- `src/binary_agent/cli`: the proof-gated toolchain and focused stage CLIs
- `src/binary_agent/discovery`, `pipeline`, `promotion`, `replay`: the candidate lifecycle
- `src/binary_agent/reporting`: artifact-bound JSON, Markdown, and vendor reports
- `ghidra_scripts`: Ghidra export, trace, and dynamic-proof scripts
- `scripts`: reproducible build, evaluation, and provider helpers
- `tests`: deterministic and optional real-tool regressions
- `docs/execplan_current.md`: the sole active implementation plan
- `docs/corpus_runner.md`: schema-v2 vulnerable/fixed corpus runner usage

The project intentionally exposes module commands rather than installed console scripts. It is research code at version `0.1.0`, not a packaged end-user scanner.
