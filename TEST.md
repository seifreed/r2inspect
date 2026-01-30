# Test Coverage Plan

Objective: enumerate missing tests to close current coverage gaps and improve behavioral confidence. Each phase is designed to be runnable and independently valuable.

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
