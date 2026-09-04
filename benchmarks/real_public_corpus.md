# Public real corpus

`real_public_corpus.py` fetches 19 independently labeled or explicitly unknown samples from two pinned
[`mandiant/capa-testfiles`](https://github.com/mandiant/capa-testfiles) commit
and [`r2inspect-test-binaries`](https://github.com/seifreed/r2inspect-test-binaries)
commits without checking samples into this repository. Eight samples are the
book's Practical Malware Analysis lab specimens and are labeled `malware`; the
two `kernel32` fixtures, `microsocks` upstream ELF, four independently maintained
hello-world fixtures, and the high-entropy edge fixture are labeled `benign`. The
synthetic packed edge fixture, malformed edge fixture, and tiny edge fixture are
retained as `unknown` robustness/calibration cases. Every download
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

The manifest declares this corpus as `calibration` and classifies each sample as
benignware, malware, administrative tool, system library, malformed, or unknown.
The `classification` block is explicit and requires bounded complexity plus
independent severe categories, or a contextual medium `behavior` finding whose
API references occur in the same function. Oversized import/export/function tables are
excluded because they otherwise create generic-signature false positives in
system DLLs; unknown labels are excluded from the denominator. The class score is triage
evidence, not a claim that a static finding alone proves maliciousness. The
previous 15-sample evidence snapshot scores 1.0 precision, 1.0 recall, and
0.0 FPR; see docs/benchmark-real-public-2026-08-26.json. A fresh 19-case local
run on macOS ARM64 with radare2 6.2.0 scores 1.0 precision, 1.0 recall, and
0.0 FPR for calibrated classification (8 true positives, 8 true negatives, 0
false positives, 0 false negatives, and 3 unknown cases), with 248 completed,
33 not-applicable, 10 not-detected, 152 profile-skipped, and zero failed analyzer
outcomes. The generated
`metrics.json` keeps those per-analyzer statuses, latency, memory, platform, and
radare2-version metrics.
The aggregate finding score is intentionally not treated as detector precision:
these corpus cases do not declare expected findings and are excluded from that
metric instead of being counted as false positives. Differential
specialist evidence remains scoped to the original 11-case calibrated subset.
capa
static analysis explicitly skips samples over 512 KiB as `skipped_by_profile`
to avoid unbounded system-DLL runs; FLOSS remains static-only and bounded.

Set `R2INSPECT_DIFFERENTIAL_TIMEOUT_SECONDS` to bound specialist execution
locally; CI keeps the default 120-second limit and records timeout states.
The native FLOSS analyzer uses the same static-only mode when it is available.
