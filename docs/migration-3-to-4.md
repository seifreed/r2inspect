# Migrating from r2inspect 3.x to 4.0

## JSON output

`r2inspect -j` now emits `r2inspect.report/v1`. Batch runs write one report per
sample and a separate `r2inspect.batch/v1` index containing report paths and
statuses.

During migration, `r2inspect -j --legacy-json` emits the pre-v4 per-sample
payload. The option is deprecated and will be removed in v5. Batch summaries
always use `r2inspect.batch/v1`.

## Field mapping

| 3.x field | 4.0 field |
| --- | --- |
| `file_info` | `sample` and `format.common` |
| `security` / format security fields | `security` |
| `indicators` | `findings` |
| analyzer result dictionaries | `analyzers` plus `extras` |
| hashing similarities | `similarity` |
| top-level analysis errors | `errors` |

The original pipeline payload remains available in `extras` for transition
code, but it is not a stable schema. New integrations should consume the typed
top-level fields and validate against the published JSON Schemas.

## Analyzer results

Every selected analyzer now has an outcome with an explicit status. Treat
`not_detected`, `not_applicable`, `dependency_unavailable`, `partial`,
`timed_out`, and `failed` as distinct states; do not infer state from error
message text or from an empty payload.

Findings now carry stable `rule_id`, severity, confidence, source analyzer,
method, evidence, locations, and ATT&CK/MBC mappings. Legacy
`legacy.indicator.*` identifiers are not stable replacements for native rule
IDs.
