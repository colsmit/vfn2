# Schema-v2 corpus runner

Run the repository-contained compiled vulnerable/fixed lanes with:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m binary_agent.cli.run_corpus \
      tests/fixtures/schema2_corpus/manifest.json \
      --output-dir /tmp/vulnfinder2-schema2-ci \
      --mode lightweight

The command validates the manifest, compiles source lanes outside the repository, runs discovery and the taxonomy-selected proof gate, compares vulnerable/fixed partners, and exits nonzero on an expectation regression. It writes `corpus_summary.json`, `pair_differential.json`, the resolved manifest, and per-lane raw schema-v2 artifacts. Reusing a nonempty output directory requires `--overwrite`; unsafe roots such as the repository, home directory, and filesystem root are rejected.

Full mode accepts binary lanes and delegates each target to the production toolchain:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m binary_agent.cli.run_corpus \
      /path/to/full-corpus.json \
      --output-dir /tmp/vulnfinder2-schema2-full \
      --mode full \
      --overwrite

Set top-level `cache_dir` in the manifest to a persistent decompilation cache. Cache entries remain guarded by the toolchain's binary hash and exporter fingerprint. Full runs also emit a capability-sweep summary. `GHIDRA_INSTALL_DIR` must identify the local Ghidra installation.

Each comparison group must have exactly one `vulnerable` lane and one `fixed` lane. Lane expectations are `expected_positives`, `expected_negatives`, or `allowed_blocked`; `vulnerability_types` controls analysis selection. `process` or `process_input` supplies concrete replay setup. Pair-aware suppression exists only in `pair_differential.json`: raw candidates and proof results are never deleted or rewritten.

## Registered research matrix

The repository has three authoritative registered manifests:

- `tests/fixtures/schema2_registered_semantic/manifest.json` contains seven vulnerable/fixed semantic pairs.
- `tests/fixtures/schema2_registered_memory/manifest.json` contains the null-dereference and memory-leak pairs.
- `tests/fixtures/schema2_registered_static/manifest.json` contains six vulnerable/fixed static-evidence pairs.

Run them as one durable workstation experiment with:

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m binary_agent.cli.run_research_matrix \
      --mode full \
      --output-root .ai/runs/registered-matrix

The matrix runner creates one timestamp directory per invocation and keeps content-addressed Ghidra caches under `.ai/runs/registered-matrix/cache`. Its aggregate `research_matrix_summary.json` contains the individual corpus totals and a SHA-256 inventory of every candidates, proof-results, and vulnerabilities JSON artifact. `latest.json` is replaced atomically only after the aggregate summary is complete.

For a fast deterministic check, use `--mode lightweight`. The semantic and static pairs execute normally and must yield thirteen vulnerable reports and zero fixed reports. The memory pair is recorded as `skipped_requires_full_ghidra` because its exact null address and allocation-generation proof intentionally require full Ghidra/native execution. A skipped full-only corpus is not counted as clean or failed.

Outputs below `.ai/runs` are ignored research evidence. They survive ordinary `/tmp` cleanup but remain generated data and must not be committed.
