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

The `classification` block is explicit and uses only high or critical
findings for the binary class score; unknown labels are excluded from the
denominator. The class score is triage evidence, not a claim that a static
finding alone proves maliciousness.

Set `R2INSPECT_DIFFERENTIAL_TIMEOUT_SECONDS` to bound specialist execution
locally; CI keeps the default 120-second limit and records timeout states.
