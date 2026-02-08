# Test Coverage Plan

Objective: enumerate missing tests to close current coverage gaps and improve behavioral confidence. Each phase is designed to be runnable and independently valuable.

## Running tests

Local quick run:

```bash
pytest -q
```

Run only unit tests:

```bash
pytest -q -m unit
```

Run integration or end-to-end tests:

```bash
pytest -q -m integration
pytest -q -m e2e
```

Skip slow tests:

```bash
pytest -q -m "not slow"
```

Notes:

- Tests tagged `requires_r2` will be skipped automatically if `r2` is not installed.
- Golden outputs live in `tests/fixtures/golden`.

Phase 1: CLI surface + output formatting

- [x] `r2inspect/cli/display.py` table renderers: PE/ELF/Mach-O summary tables and edge cases (empty data, missing keys)
- [x] `r2inspect/cli/display.py` hash/strings/sections formatting with large inputs and truncation
- [x] `r2inspect/cli/analysis_runner.py` error paths for invalid output paths and JSON/CSV write failures
- [x] `r2inspect/cli/batch_output.py` JSON/CSV batch aggregation edge cases (empty batch, mixed errors)
- [x] `r2inspect/cli/batch_processing.py` progress + parallel processing with small batch and deterministic results
- [x] `r2inspect/cli/interactive.py` non-interactive helpers and graceful exit flow

Phase 2: Pipeline + orchestration

- [x] `r2inspect/pipeline/analysis_pipeline.py` sequential execution order and dependency resolution
- [x] `r2inspect/pipeline/analysis_pipeline.py` parallel scheduling: optional stages, timeouts, failure isolation
- [x] `r2inspect/pipeline/stages.py` FileInfo/FormatDetection/FormatAnalysis branches for PE/ELF/Mach-O/Unknown
- [x] `r2inspect/pipeline/stages.py` hashing/detection/security stages with minimal mock r2 output
- [x] `r2inspect/core/inspector.py` pipeline wiring: enable/disable options and result aggregation correctness

Phase 3: Core abstractions + registry

- [x] `r2inspect/abstractions/analysis_result.py` validation boundaries, error states, serialization
- [x] `r2inspect/abstractions/base_analyzer.py` lifecycle hooks and error handling paths
- [x] `r2inspect/abstractions/hashing_strategy.py` strategy selection and fallback handling
- [x] `r2inspect/registry/analyzer_registry.py` load/unload, category filters, optional dependency gating
- [x] `r2inspect/error_handling/*` policy/preset combinations and circuit integration

Phase 4: Format analyzers (deep coverage)

- [x] `r2inspect/modules/pe_analyzer.py` header parsing branches (PE32/PE32+, section flags)
- [x] `r2inspect/modules/elf_analyzer.py` section/program header parsing and note handling
- [x] `r2inspect/modules/macho_analyzer.py` load command variants and SDK version logic
- [x] `r2inspect/modules/rich_header_analyzer.py` malformed headers and recovery logic
- [x] `r2inspect/modules/overlay_analyzer.py` signature scanning with multiple embedded formats

Phase 5: Detection + security analyzers

- [x] `r2inspect/modules/anti_analysis.py` uncommon indicators and weighted scoring edges
- [x] `r2inspect/modules/crypto_analyzer.py` suspicious constants and false positive filters
- [x] `r2inspect/modules/packer_detector.py` low-confidence detections and scoring thresholds
- [x] `r2inspect/modules/exploit_mitigation_analyzer.py` DLL characteristics and missing fields
- [x] `r2inspect/modules/authenticode_analyzer.py` signature parsing failures and fallbacks

Phase 6: Hashing/similarity analyzers

- [x] `r2inspect/modules/ssdeep_analyzer.py` missing binary/invalid output handling
- [x] `r2inspect/modules/tlsh_analyzer.py` error paths when library missing or hash invalid
- [x] `r2inspect/modules/telfhash_analyzer.py` symbol filter edge cases and malformed ELF data
- [x] `r2inspect/modules/impfuzzy_analyzer.py` import normalization corner cases
- [x] `r2inspect/modules/simhash_analyzer.py` large feature sets and similarity thresholds
- [x] `r2inspect/modules/binbloom_analyzer.py` persistence/deserialize roundtrip and bloom sizing
- [x] `r2inspect/modules/binlex_analyzer.py` opcode normalization and token limits
- [x] `r2inspect/modules/bindiff_analyzer.py` diff scoring boundaries and empty functions
- [x] `r2inspect/modules/ccbhash_analyzer.py` function hash collisions and normalization

Phase 7: Metadata analyzers

- [x] `r2inspect/modules/import_analyzer.py` missing imports, ordinal-only imports, empty tables
- [x] `r2inspect/modules/export_analyzer.py` export sorting and metadata defaults
- [x] `r2inspect/modules/section_analyzer.py` permissions parsing and entropy boundaries
- [x] `r2inspect/modules/function_analyzer.py` call graph stats, unknown mnemonics, empty output
- [x] `r2inspect/modules/string_analyzer.py` decoding errors and min-length filtering
- [x] `r2inspect/modules/resource_analyzer.py` malformed resource tree and binary extraction

Phase 8: Utilities + reliability

- [x] `r2inspect/utils/magic_detector.py` rare formats and invalid buffers
- [x] `r2inspect/utils/rate_limiter.py` concurrency limits and error accounting
- [x] `r2inspect/utils/memory_manager.py` large input truncation + stats reporting
- [x] `r2inspect/utils/output.py` summary formatting for empty/partial results
- [x] `r2inspect/utils/r2_helpers.py` text fallback parsing and weird encodings
- [x] `r2inspect/utils/retry_manager.py` jitter/backoff distributions and cancellation

Phase 9: Integration + fixtures

- [x] Add more real binaries to `samples/fixtures` (packed/obfuscated, malformed headers)
- [x] End-to-end analysis on each fixture with expected JSON snapshots
- [x] Batch mode integration: mixed file types, errors, and CSV outputs
- [x] Interactive mode integration: scripted input sequences and graceful exit

Phase 10: Performance + regression

- [x] Baseline timing tests for pipeline stages with fixture binaries
- [x] Memory baseline tests for large inputs
- [x] Regression tests for previously fixed bugs and edge cases

Phase 11: CLI validation + config tooling

- [x] `r2inspect/cli/commands/base.py` quiet logging, thread settings, context defaults
- [x] `r2inspect/cli/commands/config_command.py` YARA listing paths, empty dirs, size formatting
- [x] `r2inspect/cli/validators.py` file/batch/output/config/yara validation branches
- [x] `r2inspect/config_schemas/builder.py` chained builder coverage and preset configs

Phase 12: Config schema validation

- [x] `r2inspect/config_schemas/schemas.py` validation errors and type checks

Phase 13: Core file validation

- [x] `r2inspect/core/file_validator.py` size/exists/memory/readability paths
- [x] `r2inspect/core/file_validator.py` exception path and unreadable file handling

Phase 14: Adapter validation utils

- [x] `r2inspect/adapters/validation.py` sanitization, type validation, size/address parsing

Phase 15: R2Pipe adapter (real r2)

- [x] `r2inspect/adapters/r2pipe_adapter.py` file info/sections/imports/exports/symbols/strings/functions/read/execute
- [x] `r2inspect/adapters/r2pipe_adapter.py` cached query and text command branches

Phase 16: Config manager

- [x] `r2inspect/config.py` load/save errors, dict access, merge edge cases

Phase 17: Security path validators

- [x] `r2inspect/security/validators.py` dangerous chars, allowed dirs, sanitization

Phase 18: Resource analyzer helpers

- [x] `r2inspect/modules/resource_analyzer.py` entropy/pattern/version/suspicious helpers

Phase 19: Inspector helpers

- [x] `r2inspect/core/inspector.py` \_as_dict/\_as_bool_dict/\_as_str utilities

Phase 20: Interactive CLI

- [x] `r2inspect/cli/interactive.py` run loop with real stdin session

Phase 21: Analysis runner helpers

- [x] `r2inspect/cli/analysis_runner.py` output setup, formatting, and status helpers
- [x] `r2inspect/cli/analysis_runner.py` console/JSON/CSV output branches

Phase 22: Interactive module helpers

- [x] `r2inspect/cli/interactive.py` strings/info display and interactive loop

Phase 23: Inspector wrapper methods

- [x] `r2inspect/core/inspector.py` wrapper method coverage on real fixture

Phase 24: Analyze command helpers

- [x] `r2inspect/cli/commands/analyze_command.py` status, stats gating, JSON/CSV output

Phase 25: Batch processing helpers

- [x] `r2inspect/cli/batch_processing.py` signatures, CSV helpers, stats updates

Phase 26: CLI entrypoint

- [x] `r2inspect/cli_main.py` version and list-yara paths via CLI

Phase 27: Batch output helpers

- [x] `r2inspect/cli/batch_output.py` summary/CSV helpers and file type formatting

Phase 28: Interactive command

- [x] `r2inspect/cli/commands/interactive_command.py` execute flow via stdin

Phase 29: Batch command

- [x] `r2inspect/cli/commands/batch_command.py` helper options and empty batch path

Phase 30: Display helpers

- [x] `r2inspect/cli/display.py` hash/validation/error/retry display helpers

Phase 31: Analyzer registry

- [x] `r2inspect/registry/analyzer_registry.py` register/query/ordering/env lazy loading
- [x] `r2inspect/registry/analyzer_registry.py` auto-metadata extraction and validation errors
- [x] `r2inspect/registry/analyzer_registry.py` entry point loading no-op path
- [x] `r2inspect/registry/analyzer_registry.py` entry point callable/class handling

Phase 32: Config command

- [x] `r2inspect/cli/commands/config_command.py` no-op path

Phase 33: Display sections

- [x] `r2inspect/cli/display.py` pe/security/ssdeep/tlsh/telfhash displays
- [x] `r2inspect/cli/display.py` rich header and similarity displays
- [x] `r2inspect/cli/display.py` binlex/binbloom/indicators displays
- [x] `r2inspect/cli/display.py` impfuzzy/ccbhash/simhash displays

Phase 34: Inspector error handling

- [x] `r2inspect/core/inspector.py` MemoryError and generic exception paths

Phase 35: Interactive real loop and handlers

- [x] `r2inspect/cli/interactive.py` in-process REPL commands and handlers
- [x] `r2inspect/cli/commands/interactive_command.py` in-process loop and real handlers

Phase 36: R2 session lifecycle

- [x] `r2inspect/core/r2_session.py` open/close/basic info/analysis branches

Phase 37: Analysis runner outputs

- [x] `r2inspect/cli/analysis_runner.py` output setup, JSON/CSV writers, main error handler

Phase 38: R2Pipe adapter real usage

- [x] `r2inspect/adapters/r2pipe_adapter.py` real adapter calls, caching, execute_command, read_bytes errors

Phase 39: Batch processing real paths

- [x] `r2inspect/cli/batch_processing.py` process_single_file/process_files_parallel and file discovery/summary/output dir

Phase 40: Batch output summary

- [x] `r2inspect/cli/batch_output.py` summary creation and table helpers

Phase 41: CLI commands real execution

- [x] `r2inspect/cli/commands/analyze_command.py` real execute paths (JSON/CSV/console)
- [x] `r2inspect/cli/commands/batch_command.py` real batch execution

Phase 42: CLI error and interrupt paths

- [x] `r2inspect/cli/commands/analyze_command.py` error handling paths
- [x] `r2inspect/cli/commands/batch_command.py` quiet/no-files/error handling
- [x] `r2inspect/cli/interactive.py` EOF and KeyboardInterrupt branches

Phase 43: Utility coverage

- [x] `r2inspect/utils/circuit_breaker.py` state transitions and r2 command wrapper
- [x] `r2inspect/utils/hashing.py` hashing success/error/imphash/ssdeep paths

Phase 44: Error handling utilities

- [x] `r2inspect/utils/error_handler.py` classification/recovery/decorator/safe_execute paths

Phase 45: Rate limiting and retry

- [x] `r2inspect/utils/rate_limiter.py` token/adaptive/batch limiter paths
- [x] `r2inspect/utils/retry_manager.py` retry success/failure paths

Phase 46: Hashing strategy and adapter edge paths

- [x] `r2inspect/abstractions/hashing_strategy.py` stat error handling and analyze path
- [x] `r2inspect/adapters/r2pipe_adapter.py` invalid JSON response handling via cached query

Phase 47: Schemas and validators coverage

- [x] `r2inspect/schemas/base.py` validators and safe dump
- [x] `r2inspect/schemas/format.py` validators and helper selectors
- [x] `r2inspect/schemas/hashing.py` validators and hash validity checks
- [x] `r2inspect/schemas/converters.py` conversion error paths and helpers
- [x] `r2inspect/security/validators.py` path and YARA validation paths
- [x] `r2inspect/error_handling/presets.py` helper defaults and custom policy
- [x] `r2inspect/cli/commands/base.py` context setup and thread config

Phase 48: Security schemas

- [x] `r2inspect/schemas/security.py` validators and helper methods

Phase 49: Dataclass results, validation, and CLI utils

- [x] `r2inspect/schemas/results.py` dataclass helpers, summary, from_dict loaders
- [x] `r2inspect/adapters/validation.py` sanitization and validation helpers
- [x] `r2inspect/cli/validators.py` file/batch/output/config/xor validations
- [x] `r2inspect/utils/r2_suppress.py` suppressors and fallback paths
- [x] `r2inspect/utils/logger.py` logger setup and batch level toggles

Phase 50: R2 helpers

- [x] `r2inspect/utils/r2_helpers.py` validation, PE/ELF/Mach-O parsing, retry wrappers

Phase 51: Lazy loader

- [x] `r2inspect/lazy_loader.py` registration, caching, stats, and error paths

Phase 52: Output formatting

- [x] `r2inspect/utils/output.py` CSV/JSON and table formatting helpers

Phase 53: Memory management

- [x] `r2inspect/utils/memory_manager.py` limits, callbacks, and safe operations

Phase 54: Magic detection

- [x] `r2inspect/utils/magic_detector.py` PE/ELF/Mach-O/docx/fallback detection

Phase 55: Unified error handling

- [x] `r2inspect/error_handling/unified_handler.py` retry, fallback, circuit breaker

Phase 56: String analyzer

- [x] `r2inspect/modules/string_analyzer.py` extraction and helpers with real r2

Phase 57: Export analyzer

- [x] `r2inspect/modules/export_analyzer.py` characteristics and stats with real r2

Phase 58: Section analyzer

- [x] `r2inspect/modules/section_analyzer.py` analysis and helper paths with real r2

Phase 59: Overlay analyzer

- [x] `r2inspect/modules/overlay_analyzer.py` overlay detection on real file

Phase 60: Import analyzer

- [x] `r2inspect/modules/import_analyzer.py` API usage, obfuscation, anomalies, DLL analysis

Phase 61: Function analyzer

- [x] `r2inspect/modules/function_analyzer.py` function enumeration and MACHOC hashes

Phase 62: Crypto analyzer

- [x] `r2inspect/modules/crypto_analyzer.py` detection flow with real r2

Phase 63: Packer detector

- [x] `r2inspect/modules/packer_detector.py` entropy/signature detection with real r2

Phase 64: Format and security analyzers

- [x] `r2inspect/modules/pe_analyzer.py` basic PE analysis with real r2
- [x] `r2inspect/modules/elf_analyzer.py` basic ELF analysis with real r2
- [x] `r2inspect/modules/macho_analyzer.py` basic Mach-O analysis with real r2
- [x] `r2inspect/modules/authenticode_analyzer.py` authenticode scan with real r2
- [x] `r2inspect/modules/exploit_mitigation_analyzer.py` mitigation scan with real r2

Phase 65: Hashing and resource analyzers

- [x] `r2inspect/modules/resource_analyzer.py` basic resource scan with real r2
- [x] `r2inspect/modules/rich_header_analyzer.py` basic rich header scan with real r2
- [x] `r2inspect/modules/ssdeep_analyzer.py` ssdeep hashing
- [x] `r2inspect/modules/tlsh_analyzer.py` TLSH hashing and sections
- [x] `r2inspect/modules/impfuzzy_analyzer.py` impfuzzy hashing

Phase 66: Similarity and lexical analyzers

- [x] `r2inspect/modules/simhash_analyzer.py` SimHash analysis with real r2
- [x] `r2inspect/modules/telfhash_analyzer.py` telfhash analysis with real r2
- [x] `r2inspect/modules/yara_analyzer.py` YARA rule listing/scan path
- [x] `r2inspect/modules/binlex_analyzer.py` binlex analysis with real r2
- [x] `r2inspect/modules/binbloom_analyzer.py` binbloom analysis with real r2

Phase 67: Interfaces and display helpers

- [x] `r2inspect/__version__.py` metadata exposure
- [x] `r2inspect/interfaces/binary_analyzer.py` protocol runtime checks
- [x] `r2inspect/cli/display.py` simhash hex formatting
- [x] `r2inspect/cli/display.py` binbloom group rendering
- [x] `r2inspect/cli/display.py` binbloom signature details rendering

Phase 68: Detection and diff analyzers

- [x] `r2inspect/modules/anti_analysis.py` anti-analysis detection with real r2
- [x] `r2inspect/modules/bindiff_analyzer.py` bindiff analysis and comparison
- [x] `r2inspect/modules/compiler_detector.py` compiler detection with real r2
- [x] `r2inspect/modules/ccbhash_analyzer.py` detailed CCBHash analysis with real r2
- [x] `r2inspect/cli/display.py` bindiff display rendering

Phase 69: Hashing helpers and utilities

- [x] `r2inspect/modules/ssdeep_analyzer.py` output parsing and temp file handling
- [x] `r2inspect/modules/tlsh_analyzer.py` similarity level mapping
- [x] `r2inspect/modules/telfhash_analyzer.py` compare/lookup edge paths
- [x] `r2inspect/utils/output.py` JSON error fallback
- [x] `r2inspect/utils/logger.py` batch logging level changes

Phase 70: Adapter and validation coverage

- [x] `r2inspect/adapters/r2pipe_adapter.py` basic operations and edge cases
- [x] `r2inspect/adapters/validation.py` data validation, sanitization, and parsing
- [x] `r2inspect/adapters/validation.py` address/size validation errors
- [x] `r2inspect/utils/r2_suppress.py` suppressors and default handling
- [x] `r2inspect/adapters/r2pipe_adapter.py` execute/read byte error paths

Phase 71: Error handling, retry, rate limiting, and helpers

- [x] `r2inspect/utils/error_handler.py` recovery paths and stats
- [x] `r2inspect/utils/retry_manager.py` retry behavior and non-retry errors
- [x] `r2inspect/utils/rate_limiter.py` token bucket and batch limiter stats
- [x] `r2inspect/utils/magic_detector.py` DOCX detection and fallback scripts
- [x] `r2inspect/cli/analysis_runner.py` helper outputs and default paths

Phase 72: Registry, pipeline, and core session

- [x] `r2inspect/registry/analyzer_registry.py` registration and lazy loading
- [x] `r2inspect/pipeline/analysis_pipeline.py` parallel timeout handling
- [x] `r2inspect/pipeline/analysis_pipeline.py` progress callback error handling
- [x] `r2inspect/core/result_aggregator.py` indicators and summary generation
- [x] `r2inspect/core/r2_session.py` open/close lifecycle with real r2pipe

Phase 73: Additional helpers and caching

- [x] `r2inspect/utils/retry_manager.py` retryable commands and delay strategies
- [x] `r2inspect/utils/rate_limiter.py` cleanup memory helper
- [x] `r2inspect/utils/magic_detector.py` caching behavior
- [x] `r2inspect/pipeline/analysis_pipeline.py` execute_with_progress
- [x] `r2inspect/adapters/r2pipe_adapter.py` cached query reuse

Phase 74: Authenticode, resources, and display helpers

- [x] `r2inspect/modules/authenticode_analyzer.py` helper parsing and patterns
- [x] `r2inspect/modules/resource_analyzer.py` entropy, resource types, and header parsing
- [x] `r2inspect/pipeline/analysis_pipeline.py` thread-safe context operations
- [x] `r2inspect/cli/display.py` MACHOC function display
- [x] `r2inspect/utils/magic_detector.py` format helper methods

Phase 75: Rich header and resource helpers (10 files)

- [x] `r2inspect/modules/rich_header_analyzer.py` helper validation and positions
- [x] `r2inspect/modules/rich_header_analyzer.py` decoding and checksum
- [x] `r2inspect/modules/rich_header_analyzer.py` signature search helpers
- [x] `r2inspect/modules/resource_analyzer.py` version string extraction
- [x] `r2inspect/modules/resource_analyzer.py` suspicious resource checks
- [x] `r2inspect/modules/authenticode_analyzer.py` signature integrity checks
- [x] `r2inspect/utils/output.py` extract_names_from_list
- [x] `r2inspect/cli/analysis_runner.py` status output helper
- [x] `r2inspect/utils/magic_detector.py` PE validation helper
- [x] `r2inspect/utils/magic_detector.py` fallback executable extension
