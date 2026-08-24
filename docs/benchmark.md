# Benchmark Policy

The public fixture set is a cross-platform smoke corpus with independent labels
and SHA-256 values. It contains PE, ELF, Mach-O, stripped Mach-O, malformed,
high-entropy, packed, and tiny samples pinned to commit `1d8a0ac` of
`r2inspect-test-binaries`.

## Public benchmark

The public sanitized corpus is stored in the fixture repository's
`benchmark/corpus.json`. Every sample has provenance, a content hash, and labels
independent of the detector under test. The scheduled workflow runs it nightly
and stores reports plus aggregate metrics as an artifact.

## Metrics

Each analyzer report will include precision, recall, false-positive and
false-negative rates, unknown/error/timeout rates, completion rate, latency
median/P95/P99, peak memory, platform variance, and radare2-version variance.

Initial release goals are zero crashes or hangs, more than 99 percent completion
for valid supported binaries, less than 1 percent false positives for
high-severity findings, and no extraction error silently converted to
`not_detected`.

Private malware and benignware evaluation is supported by the same scheduled
workflow when `R2INSPECT_PRIVATE_CORPUS_URL` and
`R2INSPECT_PRIVATE_CORPUS_SHA256` secrets are configured. The archive must
contain `manifest.json` and its samples; only aggregate metrics are uploaded.
Benchmark tooling and sanitized manifests are versioned with the report schema
so release-to-release comparisons remain reproducible.

## Reproducible evaluation

Create a manifest next to strict report-v1 files:

```json
{
  "cases": [
    {"report": "reports/sample.json", "expected_rule_ids": ["packer.upx"]}
  ]
}
```

Labels must be assigned independently of r2inspect. Evaluate it with:

```bash
python benchmarks/evaluate_reports.py corpus/manifest.json --output metrics.json
```

The versioned output reports finding precision/recall, explicit analyzer status
rates, and median/P95/P99 latency. A manifest pins the exact reports evaluated,
so public and private corpora use the same scorer without publishing samples.
