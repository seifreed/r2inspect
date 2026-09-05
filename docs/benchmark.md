# Benchmark Policy

The public fixture set is a cross-platform smoke corpus with independent labels
and SHA-256 values. It contains PE, ELF, Mach-O, stripped Mach-O, malformed,
high-entropy, packed, and tiny samples pinned to commit
`1d8a0ac76d92dfd68587ba30b1c987b78b59009a` of
`r2inspect-test-binaries`.

## Public benchmark

The public sanitized corpus is stored in the fixture repository's
`benchmark/corpus.json`. Every sample has provenance, a content hash, and labels
independent of the detector under test. The scheduled workflow runs it nightly
and stores reports plus aggregate metrics as an artifact.

The Linux/Python 3.13 pull-request job runs the small public corpus as a required
gate. The scheduled workflow also supports a licensed real-labeled corpus supplied
as a private archive through `R2INSPECT_REAL_CORPUS_URL`,
`R2INSPECT_REAL_CORPUS_SHA256`, and `R2INSPECT_REAL_CORPUS_TOKEN`. Its manifest
must declare `"corpus_kind": "real_labeled"`, provenance, an
`evaluation_role` of `calibration` or `holdout`, a `sample_type` for every case,
independent labels, and SHA-256 values. Samples are never uploaded; only aggregate
metrics are.

The release holdout in `benchmarks/a1000_release_manifest.json` uses the
authorized A1000 API for 100 malware and 100 benign PE hashes, plus pinned
fixtures from `r2inspect-test-binaries`. `benchmarks/materialize_a1000_corpus.py`
downloads missing samples, verifies every SHA-256, and writes the runner manifest
without storing binaries in Git. A1000 classification is calibrated with the
function-count strategy (`min_functions=637`); its measured result is recorded in
`benchmarks/a1000_classification_calibration.json`. A1000 finding labels remain
visible in the metrics as diagnostic evidence because TitaniumCore tags are not an
exhaustive annotation of every r2inspect rule.

## Metrics

Metrics separate execution failures, unavailable dependencies, non-applicable
analyzers, and timeouts. Finding precision and recall are reported only for cases
with `expected_rule_ids` or structured `expected_findings`; unlabeled findings are
not counted as false positives. Results also include per-rule and per-category
scores, latency median/P95/P99, peak memory, platform variance, and radare2-version
variance.

Initial release goals are zero crashes or hangs, more than 99 percent completion
for valid supported binaries, less than 1 percent false positives for
high-severity findings, and no extraction error silently converted to
`not_detected`.

Private holdout evaluation runs in the same scheduled workflow from the
private `r2inspect-private-binaries` repository. It requires the repository
tarball URL, SHA-256, and read token in
`R2INSPECT_PRIVATE_CORPUS_URL`, `R2INSPECT_PRIVATE_CORPUS_SHA256`, and
`R2INSPECT_PRIVATE_CORPUS_TOKEN`. The current gate requires precision and
recall of at least 0.9. Analyzer errors remain visible in the uploaded
`metrics.json` rather than being converted into clean/not-detected results.
Only aggregate metrics are uploaded.
Benchmark tooling and sanitized manifests are versioned with the report schema
so release-to-release comparisons remain reproducible.

Stable tags and direct PyPI publications also invoke the benchmark workflow as
a required release gate. Archive-backed manifests keep the strict 0.9 finding
and classification thresholds. The A1000 holdout keeps the corpus-size,
calibrated classification, evidence/location, execution-failure, and dependency
checks; finding precision/recall are reported diagnostically because its provider
tags do not exhaustively label every detector rule. TestPyPI remains available
without private corpus credentials.

Each nightly public artifact also contains `history.json`, a rolling 365-run
history restored from the previous successful run, plus `dashboard.md`. The
same dashboard is published in the GitHub Actions run summary. Clustering is
calibrated separately against independently assigned related-sample labels in
the real public corpus; its selected threshold and pairwise precision/recall
are stored in `expanded-real-clustering-results/clustering.json`. The binary
classification gate keeps its `fast` profile while clustering is calibrated
from separate `standard` reports that include similarity hashes.

The checked-in calibration uses 19 real public samples and 171 labeled pairs.
At the default threshold `0.8875`, pairwise precision is 1.0, recall is 0.5,
and F1 is 0.667. This favors analyst-triage precision; the missed related pair
is retained in the metrics rather than hidden by relabeling.

## Reproducible evaluation

Create a manifest next to strict report-v1 files:

```json
{
  "cases": [
    {
      "report": "reports/sample.json",
      "expected_findings": [
        {"rule_id": "packer.upx", "category": "packer"}
      ]
    }
  ]
}
```

Labels must be assigned independently of r2inspect. Evaluate it with:

```bash
python benchmarks/evaluate_reports.py corpus/manifest.json --output metrics.json
# Compare the same labeled cases with a previous run.
python benchmarks/evaluate_reports.py corpus/manifest.json \
  --baseline-manifest previous/manifest.json
```

The versioned output reports finding precision/recall, explicit analyzer status
rates, per-analyzer latency/failure rates, peak-memory distribution, platform and
radare2-version metrics, and differential finding changes. A manifest pins the
exact reports evaluated, so public and private corpora use the same scorer
without publishing samples.

Optional specialist differential testing runs capa, FLOSS, or YARA and records
agreement/disagreement alongside the benchmark manifest:

```bash
python benchmarks/run_corpus.py corpus/manifest.json \
  --corpus-dir corpus --output-dir results \
  --differential-tool capa --differential-tool floss
```
