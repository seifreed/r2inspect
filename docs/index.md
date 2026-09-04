# r2inspect documentation

r2inspect is a Python malware-analysis framework built on radare2. It exposes a
strict `r2inspect.report/v1` contract, bounded batch and forensic profiles,
independent PE/ELF/Mach-O parsers, typed consensus results, signed YARA packs,
and deterministic exports for analyst tooling.

## Start here

Install the package and analyze a file:

```bash
pip install r2inspect
r2inspect --json --profile standard sample.bin
```

Use the [report contract](output-schema.md) for integrations, the
[reporting workflows](reporting.md) for export and comparison commands, and the
[analyzer SDK](analyzer-sdk.md) for third-party plugins.

The source repository contains the complete
[installation and CLI reference](https://github.com/seifreed/r2inspect#readme).
