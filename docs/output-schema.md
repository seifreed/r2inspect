# Output Contract

## Versioned JSON contract

`AnalyzeBinaryUseCase` returns the validated `AnalysisResult` model produced by
the pipeline result mapper. Pipeline analyzer payloads carry the typed
`r2inspect.analyzer/v1` metadata envelope while remaining mapping-compatible;
console/CSV output retains the legacy layout. JSON output from single-file and
batch analysis is wrapped in the strict `r2inspect.report/v1` model. Unsupported
objects fail serialization instead of being silently converted to text.

`--legacy-json` temporarily restores the pre-v4 per-sample JSON shape and must
be combined with `--json`. It is deprecated and scheduled for removal in v5.
Batch summaries remain `r2inspect.batch/v1` even when legacy per-sample files
are requested, so the v3 overwrite behavior is not reintroduced.

Top-level data is organized by pipeline stage and can include file information,
format-specific PE/ELF/Mach-O data, hashes, security results, detections,
indicators, errors, and performance statistics. Optional analyzers may omit
their section or report it as unavailable.

## Stable contract

The wire contract identifies itself as:

```json
{"schema_version": "r2inspect.report/v1"}
```

The generated [JSON Schema](../r2inspect/schemas/r2inspect.report.v1.schema.json)
is included in source and wheel distributions.

It contains tool and backend provenance, analysis identity and profile,
sample hashes and format, normalized and format-specific security properties,
findings, evidence locations, artifacts, capabilities, similarity results,
analyzer outcomes, errors, warnings, and metrics.

The CLI detects the current Git commit and `r2 -v` output once per process.
Packaged builds can set `R2INSPECT_COMMIT` and `R2INSPECT_RADARE2_VERSION` to
provide immutable build provenance. An absent or unsupported mitigation is
`null`; `false` is reserved for a mitigation that was evaluated and found
disabled.

Analyzer outcomes distinguish `completed`, `not_detected`,
`not_applicable`, `unsupported`, `dependency_unavailable`,
`skipped_by_profile`, `timed_out`, and `failed`. An extraction failure must
never be represented as absence or a clean result.

Breaking changes to `r2inspect.report/v1` require a new schema identifier.
Additive optional fields remain compatible within v1.

The `extras` object preserves the legacy pipeline result during migration. It is
JSON-strict but is not itself a stable sub-schema; consumers should prefer the
typed top-level fields.

For `--profile forensic`, `extras.forensic` references the evidence directory,
the `r2inspect.forensic/v1` chain-of-custody manifest, its SHA-256 digest, and
the hashed artifacts. The manifest includes UTC timestamps, redacted effective
configuration, radare2 commands, complete errors and warnings, and bounded byte
snippets associated with findings.
