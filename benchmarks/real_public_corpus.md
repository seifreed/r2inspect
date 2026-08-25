# Public real corpus

`real_public_corpus.py` fetches 11 samples from the pinned
[`mandiant/capa-testfiles`](https://github.com/mandiant/capa-testfiles) commit
without checking samples into this repository. Eight samples are the book's
Practical Malware Analysis lab specimens and are labeled `malware`; the two
`kernel32` fixtures and `microsocks` upstream ELF are labeled `benign` from
their source provenance. Every download is checked against a SHA-256 listed in
the generated manifest.

Run the corpus with specialist differential tools:

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

The `classification` block is explicit and requires independent high/critical
categories, while excluding oversized import/export/function tables that
otherwise create generic-signature false positives in system DLLs. A lone
medium suspicious-API signal is accepted only within those complexity bounds;
unknown labels are excluded from the denominator. The class score is triage
evidence, not a claim that a static finding alone proves maliciousness. The
current 11-sample snapshot scores 1.0 precision, 1.0 recall, and 0.0 FPR;
the small corpus must be expanded before treating those numbers as release-wide
performance.

Set `R2INSPECT_DIFFERENTIAL_TIMEOUT_SECONDS` to bound specialist execution
locally; CI keeps the default 120-second limit and records timeout states.
