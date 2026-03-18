# Testing Seams

These are the seams the project intentionally supports for tests. Anything outside this list should be treated as accidental compatibility and reduced over time.

## Public seams

- `R2Inspector(...)` constructor injection:
  - `adapter`
  - `registry_factory`
  - `pipeline_builder_factory`
  - `config_factory`
  - `file_validator_factory`
  - `result_aggregator_factory`
  - `memory_monitor`
  - `cleanup_callback`
- `R2Session` runtime behavior controlled by environment for test-mode thresholds.
- Analyzer constructors that accept adapters or file paths.
- CLI command objects instantiated through command/context factories.

## Legitimate test seams

- Shared helpers under `tests/helpers/`
- Fake adapters, fake registries, and explicit builders in `tests/factories/`
- Fresh module import helpers for import-time fallback branches

## Seams to reduce over time

- Monkeypatching module globals in `cli_main`, `analysis_runner`, `batch_processing`, or command modules
- Patching analyzer module globals only to force import-time availability flags
- Patching internal helper aliases when constructor injection or a fake object would be sufficient

## Rule of thumb

If a test must patch a module-level symbol in product code, prefer first:

1. constructor injection
2. a shared fake/builder from `tests/helpers` or `tests/factories`
3. a narrow wrapper helper owned by tests

Only keep direct module monkeypatching when the behavior under test is itself import-time or module-level.
