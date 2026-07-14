# Repository Guidelines

## Project Structure
- Core code lives under `src/binary_agent`.
- Deterministic analysis lives in `analysis/`, CLI entry points in `cli/`, manifest helpers in `data/`, export loading in `ingest/`, and JSON/Markdown output in `reporting/`.
- Helper scripts live in `scripts/`; the sole active plan is `docs/execplan_current.md`.
- Unit tests mirror the package layout inside `tests/`, with shared fixtures in `tests/utils.py`.

## Build, Test, And Development Commands
- Create a virtualenv and install dependencies: `python3.10 -m venv .venv && source .venv/bin/activate && pip install -e .[dev]`.
- Decompile a stripped binary only: `python scripts/decompile.py samples/vuln_demo/build/vuln_demo_stripped`.
- Run deterministic analysis on an existing export: `python -m binary_agent.cli.run_pipeline artifacts/<binary>/<timestamp>/decompiled`.
- Full toolchain: `python -m binary_agent.cli.toolchain samples/vuln_demo/build/vuln_demo_stripped`.
- Execute the test suite: `pytest`.

## Coding Style
- Target Python 3.10+ with type hints and dataclasses where appropriate.
- Prefer 4-space indentation and descriptive snake_case identifiers.
- Align new modules with the existing package layout; CLI entry points belong in `binary_agent.cli`.
- No formatter is enforced yet; follow PEP 8 for spacing and import order.

## Testing Guidelines
- Tests use `pytest`; name files `test_*.py` and functions `test_*`.
- Cover new deterministic candidate behavior with unit tests or fixed export fixtures.
- When touching manifest ingestion, include regression cases for edge conditions.

## Commit And PR Guidelines
- Commit messages should be terse imperative summaries.
- Pull requests should describe the change, testing performed, and relevant artifact paths or sample CLI output.
- Never commit secrets or generated run outputs.

## Security And Configuration
- Document new environment variables in `.env.example`.
- Ensure scripts respect `GHIDRA_INSTALL_DIR`.

## ExecPlans
When writing complex features or significant refactors, use an ExecPlan as described in `PLANS.md`.
