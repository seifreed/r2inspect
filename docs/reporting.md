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
```

The exports are deterministic projections of the report contract. They do not
claim that a finding is malicious; consumers should preserve the source
analyzer, confidence, evidence, and report provenance.
