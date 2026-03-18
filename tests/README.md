# Test Taxonomy

This suite contains three broad categories of tests:

- Product tests: direct behavior checks for public modules, domain rules, adapters, CLI flows, and integration paths.
- Guardrail tests: architecture, structure, size, import, and complexity checks that keep the codebase from drifting.
- Historical coverage tests: older targeted files created to close specific uncovered branches. These usually use filename tokens such as `block`, `wave`, `gaps`, `remaining_edges`, `coverage`, or `bridge`.

Physical layout during the migration:

- `tests/unit/product/`
- `tests/unit/guardrails/`
- `tests/unit/historical/`
- `tests/integration/product/`
- `tests/integration/historical/`

Shared helpers for tests live under:
- `tests/helpers/`

Historical coverage tests are still valid, but they are maintenance debt:

- They should not be the default pattern for adding new tests.
- New tests should prefer behavior-oriented names and user-visible intent.
- The historical inventory is intentionally frozen by guardrails so it does not keep expanding.

Allowed uses of `runpy` in tests are limited to package entrypoints such as `r2inspect` and `r2inspect.__main__`. Internal modules should be imported with `importlib` instead.
