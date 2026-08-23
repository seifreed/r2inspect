# Changelog

All notable changes are documented here. The project follows Semantic
Versioning and keeps unreleased work at the top.

## Unreleased

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

## 3.0.0

- Current stable baseline before the release-hardening work above.
