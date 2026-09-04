# Reporting Workflows

The CLI produces strict `r2inspect.report/v1` JSON. That artifact can be
converted without network access:

```bash
r2inspect-export report.json --format html --output report.html
r2inspect-export report.json --format sarif --output report.sarif.json
r2inspect-export report.json --format misp --output report.misp.json
r2inspect-export report.json --format stix --output report.stix.json
```

Compare two reports by stable finding and analyzer identifiers:

```bash
r2inspect-compare baseline.json candidate.json
r2inspect-baseline baseline.json candidate.json --fail-on-change
r2inspect --explain finding-abc123 report.json
r2inspect-cluster reports/*.json --threshold 0.5
r2inspect-cluster reports/*.json --index similarity.sqlite3
r2inspect-cluster --index similarity.sqlite3 --query SAMPLE_SHA256
r2inspect-rules-verify ./rule-pack --public-key analyst-ed25519.pub
```

Batch runs can persist successful results and resume after interruption. Cache
entries are keyed by the sample SHA-256 and the effective analysis configuration:

```bash
r2inspect --batch samples/ -j --cache output/batch-cache.sqlite3
r2inspect --batch samples/ -j --cache output/batch-cache.sqlite3 --resume
```

Use `r2inspect --backend consensus --consensus-backend pe-core sample.exe` (or
the matching ELF/Mach-O core backend) to retain typed field-level disagreements
between radare2 and the independent parser. Rule packs are managed with
`r2inspect rules build|sign|verify|install|list|update`; see the analyzer SDK for
the signed-pack contract.

The exports are deterministic projections of the report contract. They do not
claim that a finding is malicious; consumers should preserve the source
analyzer, confidence, evidence, and report provenance. Explanations include
the evidence, locations, and ready-to-run radare2 seek/disassembly commands.
Rule packs use a versioned manifest, SHA-256 file hashes, and Ed25519
signatures; updating a pack means replacing the verified directory atomically.
