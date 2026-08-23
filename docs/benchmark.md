# Benchmark Policy

The current fixture set is a cross-platform smoke corpus, not evidence of
detector accuracy. It contains PE, ELF, Mach-O, stripped Mach-O, malformed,
high-entropy, packed, and tiny samples pinned to a repository commit.

## Public benchmark

The public sanitized corpus will include synthetic and redistributable benign
and positive cases across formats, architectures, compilers, mitigations,
packers, and malformed inputs. Every sample requires provenance, a content hash,
and labels independent of the detector under test.

## Metrics

Each analyzer report will include precision, recall, false-positive and
false-negative rates, unknown/error/timeout rates, completion rate, latency
median/P95/P99, peak memory, platform variance, and radare2-version variance.

Initial release goals are zero crashes or hangs, more than 99 percent completion
for valid supported binaries, less than 1 percent false positives for
high-severity findings, and no extraction error silently converted to
`not_detected`.

Private malware and benignware evaluation runs nightly and publishes aggregate
metrics only. Benchmark tooling and sanitized manifests will be versioned with
the report schema so release-to-release comparisons remain reproducible.
