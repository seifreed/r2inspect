# Changelog

All notable changes are documented here. The project follows Semantic
Versioning and keeps unreleased work at the top.

## Unreleased

## 4.1.0 - 2026-11-09

### Added

- Added centralized production logging and observability with structured events,
  correlation context, secret redaction, and lifecycle instrumentation across
  analysis, pipelines, APIs, jobs, external commands, retries, cache, and rule packs.
- Added explicit analyzer execution states and carried structured analyzer issues
  through registered analyzers and report envelopes, including standalone stages
  and canonical analyzer IDs.

### Changed

- Prevented batch reports from overwriting existing output files.
- Measured hash durations with a monotonic clock and made governance gates tolerate
  filesystem clock skew.
- Expanded observability, architecture, and validation documentation.

### Fixed

- Removed legacy indicator findings and corrected report findings to use native
  structured issues.
- Expanded Windows test coverage and removed machine-specific fixture paths.
- Hardened container dependencies and made CI downloads resilient across Windows,
  macOS, and Linux, including supported macOS runners and OpenSSL 3 for YARA builds.

## 4.0.0 - 2026-09-04

### Changed

- Made CI, distribution smoke tests, and container validation release gates.
- Pinned radare2, fixtures, image dependencies, and reproducible container inputs.
- Added multi-platform container smoke tests, SBOM/provenance publication, signing,
  and vulnerability scanning.
- Corrected analyzer plugin category discovery and packer import error handling.
- Added explicit POSIX test markers and portable Windows resource checks.
- Added project architecture, output, SDK, methodology, limitation, benchmark,
  threat model, security, and contribution documentation.
- Added the strict `r2inspect.report/v1` schema and envelope for CLI and batch
  JSON, including normalized format/security fields and analyzer outcomes.
- Populated report provenance from the running Git checkout and radare2 binary,
  preserving unknown PE, ELF, and Mach-O mitigations as unknown instead of false.
- Added declarative `AnalyzerSpec` plugin discovery without analyzer construction.
- Added `fast`, `standard`, and `deep` analysis cost profiles across single-file,
  batch, interactive, and report workflows.
- Added a reproducible report-v1 precision benchmark scorer and manifest format.
- Added optional capa capability and FLOSS string integrations to the deep profile.
- Split PE, YARA, and similarity engines into optional dependency groups and
  documented the tested Python 3.11–3.14 support boundary (primary: 3.13).
- Added a golden compatibility projection for PE, ELF, and Mach-O report-v1 output.
- Required a contextual read/delta/branch pattern before timing observations become
  an anti-analysis verdict.
- Made `r2inspect.report/v1` and `r2inspect.batch/v1` the default JSON contracts.
- Added analyzer-owned findings with stable rule IDs, evidence, locations, and
  ATT&CK/MBC mappings for packer, anti-analysis, YARA, and correlated behavior.
- Added the deprecated `--legacy-json` compatibility option for migration from 3.x.
- Replaced the minimal core format detectors with bounded PE, ELF, and Mach-O
  parsers and added typed, normalized backend consensus discrepancies.
- Made the forensic profile preserve radare2 command provenance, full FLOSS and
  native external-tool output, evidence byte snippets, and hashed
  `r2inspect.forensic/v1` chain-of-custody bundles.
- Integrated signed Ed25519 YARA packs into scanning with safe manifest paths,
  content-aware compilation caching, report provenance, and
  `rules build|sign|verify|install|list|update` commands.
- Bounded external-tool output, memory, CPU, and process usage; added an optional
  sandbox prefix and recorded executable, version, binary, and rules provenance.
- Corrected SARIF file/virtual address semantics and added official SARIF, STIX,
  and PyMISP validation for deterministic exporter fixtures.
- Added a plugin conformance command for declarative metadata, runtime
  construction, and optional sample execution checks.
- Added a strict MkDocs site and pinned GitHub Pages publication workflow.

## 3.0.0

- Current stable baseline before the release-hardening work above.
