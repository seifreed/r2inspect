# Limitations

- Static analysis cannot prove runtime behavior and can be defeated by packing,
  encryption, self-modification, environment checks, or backend blind spots.
- Detector scores are heuristics; most are not yet calibrated on a published
  representative corpus.
- The stable `r2inspect.report/v1` contract is not implemented in 3.0. Current
  JSON consumers must tolerate additive and structural changes.
- radare2 is the production extraction backend. Its parsing and analysis errors
  can make downstream results incomplete.
- PE, ELF, and Mach-O analyzers expose different format-specific detail; common
  mitigation normalization is still in progress.
- Optional YARA and similarity dependencies may be unavailable on a platform.
- Windows skips tests that fundamentally require POSIX permissions, signals, or
  Unix sockets, while retaining real radare2 smoke and integration coverage.
- Very large or malformed binaries are bounded to protect memory and runtime;
  bounded analysis can omit evidence.

Use r2inspect for triage and evidence collection, not as the sole basis for an
automated malicious/benign decision.
