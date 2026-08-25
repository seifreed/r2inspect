# Limitations

- Static analysis cannot prove runtime behavior and can be defeated by packing,
  encryption, self-modification, environment checks, or backend blind spots.
- Detector scores are heuristics; most are not yet calibrated on a published
  representative corpus.
- `r2inspect.report/v1` preserves analyzer-specific legacy data in `extras`;
  that compatibility object is not a stable sub-schema.
- radare2 is the production extraction backend. Its parsing and analysis errors
  can make downstream results incomplete.
- PE, ELF, and Mach-O analyzers expose different format-specific detail; common
  mitigation normalization is still in progress.
- Optional YARA and similarity dependencies may be unavailable on a platform.
- Python 3.11 through 3.14 are supported; the compatibility workflow covers
  3.11/3.12 while the full radare2 matrix remains on 3.13/3.14.
- The base package contains the r2 pipeline and report contract. The `pe`,
  `yara`, and `similarity` extras install optional engines; `elf` and `macho`
  are dependency-free deployment markers, and `all` installs every Python
  analyzer dependency. capa and FLOSS remain external executables.
- Windows skips tests that fundamentally require POSIX permissions, signals, or
  Unix sockets, while retaining real radare2 smoke and integration coverage.
- Very large or malformed binaries are bounded to protect memory and runtime;
  bounded analysis can omit evidence.

Use r2inspect for triage and evidence collection, not as the sole basis for an
automated malicious/benign decision.
