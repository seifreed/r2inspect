# Public real corpus

`real_public_corpus.py` fetches 19 independently labeled or explicitly unknown samples from two pinned
[`mandiant/capa-testfiles`](https://github.com/mandiant/capa-testfiles) commit
and [`r2inspect-test-binaries`](https://github.com/seifreed/r2inspect-test-binaries)
commits without checking samples into this repository. Eight samples are the
book's Practical Malware Analysis lab specimens and are labeled `malware`; the
two `kernel32` fixtures, `microsocks` upstream ELF, four independently maintained
hello-world fixtures, and two edge fixtures are labeled `benign`. The malformed
and tiny edge fixtures are retained as `unknown` robustness cases. Every download
is checked against a SHA-256 listed in the generated manifest.

Run the corpus with specialist differential tools. FLOSS is invoked in bounded
static-string mode because that is the same evidence domain exposed by the
native report and avoids unbounded decoded-string analysis on system DLLs:

```sh
python benchmarks/real_public_corpus.py /tmp/r2inspect-real
python benchmarks/run_corpus.py /tmp/r2inspect-real/manifest.json \
  --corpus-dir /tmp/r2inspect-real \
  --output-dir /tmp/r2inspect-real-results \
  --differential-tool capa --differential-tool floss
python benchmarks/evaluate_reports.py \
  /tmp/r2inspect-real-results/manifest.json \
  --output /tmp/r2inspect-real-results/metrics.json
```

The `classification` block is explicit and requires bounded complexity plus
independent severe categories, or a contextual medium `Suspicious API` or
`Behavior Cluster` finding. Oversized import/export/function tables are
excluded because they otherwise create generic-signature false positives in
system DLLs; unknown labels are excluded from the denominator. The class score is triage
evidence, not a claim that a static finding alone proves maliciousness. The
The previous 15-sample evidence snapshot scores 1.0 precision, 1.0 recall, and
0.0 FPR; see docs/benchmark-real-public-2026-08-26.json. The four new edge cases
extend robustness coverage and require a fresh run before their metrics are
published. Differential specialist evidence remains scoped to the original
11-case calibrated subset. capa
static analysis explicitly skips samples over 512 KiB as `skipped_by_profile`
to avoid unbounded system-DLL runs; FLOSS remains static-only and bounded.

Set `R2INSPECT_DIFFERENTIAL_TIMEOUT_SECONDS` to bound specialist execution
locally; CI keeps the default 120-second limit and records timeout states.
The native FLOSS analyzer uses the same static-only mode when it is available.
