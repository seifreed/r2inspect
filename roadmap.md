# Test Roadmap

<!-- markdownlint-disable MD013 -->

This roadmap enumerates test coverage needed to fully cover the project. It is organized in phases so you can land value early and build toward full coverage.

Legend:

- [ ] not started
- [~] in progress
- [x] done

## Phase 0 - Test foundations

- [x] Create `tests/` layout with pytest discovery (`tests/unit`, `tests/integration`, `tests/e2e`, `tests/fixtures`)
- [ ] Add `tests/conftest.py` with shared fixtures (temp dirs, sample binaries, fake r2pipe, deterministic clock)
- [ ] Add CI-friendly markers (`unit`, `integration`, `slow`, `requires_r2`, `requires_*`)
- [ ] Add minimal smoke test to ensure pytest discovery works
- [ ] Define golden-output strategy (snapshots or JSON fixtures)
- [ ] Document how to run tests locally and in CI

## Phase 1 - Core unit tests (fast, no external deps)

### Core runtime

- [x] `r2inspect/core/file_validator.py` input validation and error paths
- [x] `r2inspect/core/r2_session.py` session lifecycle, error handling, timeout paths
- [x] `r2inspect/core/inspector.py` orchestration logic with mocked analyzers
- [x] `r2inspect/core/pipeline_builder.py` stage assembly, optional/required logic
- [x] `r2inspect/core/result_aggregator.py` merge logic and edge cases

### Pipeline

- [ ] `r2inspect/pipeline/analysis_pipeline.py` dependency resolution, skip logic, error handling
- [ ] `r2inspect/pipeline/stages.py` hashing/detection/format stage behavior with stub analyzers

### Adapters

- [x] `r2inspect/adapters/validation.py` response validation and sanitization
- [x] `r2inspect/adapters/r2pipe_adapter.py` adapter behavior and command execution

### Registry and lazy loading

- [ ] `r2inspect/registry/analyzer_registry.py` registration modes, metadata extraction, dependency order
- [x] `r2inspect/registry/default_registry.py` ensures expected analyzers registered
- [x] `r2inspect/lazy_loader.py` caching behavior, load failures, stats

### Schemas and conversions

- [x] `r2inspect/schemas/base.py` data validation behaviors
- [x] `r2inspect/schemas/format.py` format mapping rules
- [x] `r2inspect/schemas/metadata.py` metadata parsing
- [x] `r2inspect/schemas/security.py` score computation edge cases
- [x] `r2inspect/schemas/results.py` `from_dict` for minimal and full payloads
- [x] `r2inspect/schemas/converters.py` expected mapping behavior
- [x] `r2inspect/schemas/hashing.py` field normalization

### Utilities and helpers

- [x] `r2inspect/utils/r2_helpers.py` safe command wrappers
- [x] `r2inspect/utils/r2_suppress.py` suppression and fallback handling
- [x] `r2inspect/utils/hashing.py` deterministic hashing helpers
- [x] `r2inspect/utils/magic_detector.py` file type detection
- [x] `r2inspect/utils/output.py` CSV/JSON extraction helpers
- [x] `r2inspect/utils/retry_manager.py` retry policy and backoff
- [x] `r2inspect/utils/rate_limiter.py` limits enforced
- [x] `r2inspect/utils/circuit_breaker.py` open/close transitions
- [x] `r2inspect/utils/memory_manager.py` guardrails
- [x] `r2inspect/utils/error_handler.py` normalization paths
- [x] `r2inspect/utils/logger.py` configuration defaults

### Config

- [x] `r2inspect/config.py` defaults and overrides
- [x] `r2inspect/config_schemas/builder.py` schema building
- [x] `r2inspect/config_schemas/schemas.py` schema validation

### CLI (unit)

- [x] `r2inspect/cli/validators.py` input validation
- [x] `r2inspect/cli/analysis_runner.py` argument handling with stub pipeline
- [x] `r2inspect/cli/commands/*.py` command routing
- [x] `r2inspect/cli/display.py` formatting (minimal, deterministic checks)
- [x] `r2inspect/cli/batch_processing.py` batch inputs and error propagation
- [x] `r2inspect/cli/batch_output.py` output formats and edge cases
- [x] `r2inspect/cli_main.py` dispatch behavior

## Phase 2 - Module unit tests (mocked r2pipe)

Each analyzer should have unit tests that validate:

- correct handling of missing/empty r2 responses
- safe defaults when fields are absent
- deterministic outputs on provided fixtures

### PE/ELF/Mach-O format analyzers

- [x] `r2inspect/modules/pe_analyzer.py`
- [x] `r2inspect/modules/elf_analyzer.py`
- [x] `r2inspect/modules/macho_analyzer.py`

### PE adjunct analyzers

- [x] `r2inspect/modules/resource_analyzer.py`
- [x] `r2inspect/modules/rich_header_analyzer.py`
- [x] `r2inspect/modules/authenticode_analyzer.py`
- [x] `r2inspect/modules/import_analyzer.py`
- [x] `r2inspect/modules/export_analyzer.py`
- [x] `r2inspect/modules/section_analyzer.py`
- [x] `r2inspect/modules/overlay_analyzer.py`
- [x] `r2inspect/modules/exploit_mitigation_analyzer.py`

### Detection analyzers

- [x] `r2inspect/modules/packer_detector.py`
- [x] `r2inspect/modules/anti_analysis.py`
- [x] `r2inspect/modules/compiler_detector.py`
- [x] `r2inspect/modules/crypto_analyzer.py`
- [x] `r2inspect/modules/yara_analyzer.py` (mock yara hits)

### Hashing/similarity analyzers

- [x] `r2inspect/modules/ssdeep_analyzer.py`
- [x] `r2inspect/modules/tlsh_analyzer.py`
- [x] `r2inspect/modules/telfhash_analyzer.py`
- [x] `r2inspect/modules/impfuzzy_analyzer.py`
- [x] `r2inspect/modules/ccbhash_analyzer.py`
- [x] `r2inspect/modules/simhash_analyzer.py`
- [x] `r2inspect/modules/binlex_analyzer.py`
- [x] `r2inspect/modules/binbloom_analyzer.py`
- [x] `r2inspect/modules/bindiff_analyzer.py`
- [x] `r2inspect/modules/string_analyzer.py`
- [x] `r2inspect/modules/function_analyzer.py`

## Phase 3 - Integration tests (real r2pipe + fixtures)

### Fixture set

- [x] Curate minimal sample binaries for PE/ELF/Mach-O (safe, non-malicious)
- [x] Add fixtures for edge cases: packed sample, high entropy, missing headers, tiny files
- [x] Add expected output JSON per fixture

### Integration suites

- [x] Analyze each fixture end-to-end via `R2Inspector` and compare to golden output
- [x] Validate pipeline dependency resolution with optional analyzers toggled
- [x] Validate config-driven behavior (disable analyzers, set timeouts)
- [x] Validate lazy-loader impact on loaded analyzers count

## Phase 4 - CLI and UX tests

- [x] `r2inspect` CLI smoke tests (help, version, config show)
- [x] `analyze` command on fixture, validate output files
- [x] `batch` command on a directory, verify per-file results
- [x] Verify interactive mode minimal flows

## Phase 5 - Security, resilience, and error handling

- [x] Bandit-aligned negative tests (timeouts, invalid inputs, missing deps)
- [x] Ensure safe failure on missing optional libs (yara, ssdeep, tlsh, pybloom)
- [x] Regression tests for previous parsing bugs
- [x] Deserialization safety test for binbloom JSON input

## Phase 6 - Performance and resource usage

- [x] Benchmarks guarded by `slow` marker
- [x] Import-time and registry-creation baselines
- [x] Memory usage baseline and regression thresholds
- [x] Lazy loading effectiveness metrics

## Phase 7 - Coverage completion

- [x] Add coverage reporting in CI (`pytest --cov=r2inspect`)
- [x] Enforce minimum coverage target (start at 60%, raise to 80%+)
- [x] Add mutation tests for critical components (optional)

## Acceptance criteria for “complete coverage”

- [x] All modules covered by unit tests
- [x] All analyzers covered by integration fixtures
- [x] CLI workflows validated
- [x] Critical failure paths validated
- [x] Coverage target met and stable in CI
