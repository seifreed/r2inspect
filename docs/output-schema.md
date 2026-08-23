# Output Contract

## Current 3.0 contract

`AnalyzeBinaryUseCase` returns the validated `AnalysisResult` model produced by
the pipeline result mapper. Individual analyzers still return dictionaries and
the JSON formatter currently serializes otherwise unsupported values as text.
Consumers must therefore treat the 3.0 JSON shape as beta, not as a stable wire
contract.

Top-level data is organized by pipeline stage and can include file information,
format-specific PE/ELF/Mach-O data, hashes, security results, detections,
indicators, errors, and performance statistics. Optional analyzers may omit
their section or report it as unavailable.

## Planned stable contract

The first stable wire contract will identify itself as:

```json
{"schema_version": "r2inspect.report/v1"}
```

It will contain tool and backend provenance, analysis identity and profile,
sample hashes and format, normalized and format-specific security properties,
findings, evidence locations, artifacts, capabilities, similarity results,
analyzer outcomes, errors, warnings, and metrics.

Analyzer outcomes will distinguish `completed`, `not_detected`,
`not_applicable`, `unsupported`, `dependency_unavailable`,
`skipped_by_profile`, `timed_out`, and `failed`. An extraction failure must
never be represented as absence or a clean result.

Breaking changes to `r2inspect.report/v1` require a new schema identifier.
Additive optional fields remain compatible within v1.
