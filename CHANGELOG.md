# Changelog

All notable changes are documented here. The project follows Semantic
Versioning and keeps unreleased work at the top.

## Unreleased

## 4.0.0 - 2026-09-04

### Changed

- Made CI, distribution smoke tests, and container validation release gates.
- Pinned radare2, fixtures, image dependencies, and reproducible container inputs.
- Added multi-platform container smoke tests, SBOM/provenance publication, signing,
  and vulnerability scanning.
- Corrected analyzer plugin category discovery and packer import error handling.
- Added explicit POSIX test markers and portable Windows resource checks.
- Added project architecture, output, SDK, methodology, limitation, benchmark,
  threat model, security, contribution, and roadmap documentation.
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
  documented the tested Python 3.13+ support boundary.
- Added a golden compatibility projection for PE, ELF, and Mach-O report-v1 output.
- Required a contextual read/delta/branch pattern before timing observations become
  an anti-analysis verdict.
- Made `r2inspect.report/v1` and `r2inspect.batch/v1` the default JSON contracts.
- Added analyzer-owned findings with stable rule IDs, evidence, locations, and
  ATT&CK/MBC mappings for packer, anti-analysis, YARA, and correlated behavior.
- Added the deprecated `--legacy-json` compatibility option for migration from 3.x.

## 3.0.0

- Current stable baseline before the release-hardening work above.
