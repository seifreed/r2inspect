# Architecture

r2inspect is an orchestration and reporting layer around radare2-backed binary
analysis. The normal request path is:

```text
CLI or library
  -> create_inspector
  -> BinaryInspector
  -> R2Inspector, CoreBackendInspector, or ConsensusInspector
  -> AnalyzeBinaryUseCase
  -> AnalysisService
  -> AnalysisPipeline
  -> ordered pipeline stages
  -> registered analyzers
  -> R2PipeAdapter / R2Session
  -> radare2
```

## Layers

- `r2inspect/cli`: command parsing, interactive mode, batch execution, and output.
- `r2inspect/application`: use cases, service orchestration, and result mapping.
- `r2inspect/pipeline`: ordered stages for format, metadata, security, hashes,
  detections, indicators, and aggregation.
- `r2inspect/registry`: analyzer metadata, lazy loading, entry points, dependency
  ordering, and format/category queries.
- `r2inspect/modules`: concrete analyzers and evidence extraction.
- `r2inspect/domain` and `r2inspect/schemas`: domain logic and validation models.
- `r2inspect/adapters` and `r2inspect/infrastructure`: radare2 integration,
  sessions, limits, retries, and runtime services.
- `r2inspect/backends`: dependency-free PE, ELF, and Mach-O structural parsers
  plus normalized cross-backend comparison.

Pipeline stages depend on small protocols from `r2inspect/interfaces`, not on
the concrete registry or adapter. Analyzer dependencies are resolved by the
registry before execution. Lazy registrations import an analyzer only when its
class is requested.

## Extension points

- Python entry points in the `r2inspect.analyzers` group.
- Direct `AnalyzerRegistry.register()` calls.
- Pipeline-facing protocol implementations for registries, factories, and file
  services.

radare2 remains the default full-analysis backend. The built-in `pe-core`,
`elf-core`, and `macho-core` backends independently parse headers, sections,
imports/exports, mitigations, overlays, signatures, and build identifiers. The
`consensus` backend runs r2 and one core parser and preserves typed differences.
