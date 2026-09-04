# Analyzer SDK

External analyzers are discovered from the `r2inspect.analyzers` Python entry
point group. A plugin may expose a `BaseAnalyzer` subclass or a callable that
receives the registry.

## Analyzer class

```python
from typing import Any

from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.registry import AnalyzerCategory, AnalyzerSpec


class ExampleAnalyzer(BaseAnalyzer):
    spec = AnalyzerSpec(
        id="vendor.example",
        version="1.0.0",
        category=AnalyzerCategory.DETECTION,
        formats=frozenset({"PE"}),
        architectures=frozenset({"x86", "x86_64"}),
        output_schema="vendor.example/v1",
    )

    def analyze(self) -> dict[str, Any]:
        return {"available": True, "detected": False, "evidence": []}
```

Register it in the plugin package:

```toml
[project.entry-points."r2inspect.analyzers"]
example = "vendor_plugin:ExampleAnalyzer"
```

The loader reads `AnalyzerSpec` without constructing the analyzer. Classes
without a spec retain the legacy metadata-method discovery path; callable entry
points should call `registry.register()` with an explicit category and formats.

Constructors must accept the runtime dependencies used by the analyzer factory:
`adapter`, `r2`, `config`, and `filepath`/`filename` as applicable. Do not open
sessions or perform analysis at import time. Return JSON-compatible values and
preserve extraction errors as explicit unavailable/failed results.

## Independent backends

Backend packages can expose an independent implementation through the
`r2inspect.backends` entry point group. The factory receives `filename` plus
optional configuration and must return a `BinaryInspector`: `analyze`, `close`,
`__enter__`, and `__exit__` are required and checked when the backend loads:

```toml
[project.entry-points."r2inspect.backends"]
pe-core = "vendor_pe_core:create_backend"
```

`r2inspect --backend consensus --consensus-backend pe-core sample.bin` runs
radare2 and the independent backend and preserves field-level disagreements as
`backend_disagreement` records instead of silently choosing a value. Each record
contains the canonical field path, both backend names and values, severity, and
status. Built-in `pe-core`, `elf-core`, and `macho-core` implementations provide
this independent structural view without radare2 or optional Python parsers.

## Optional engines

The `deep` and `forensic` profiles run `capa -j` and `floss -j` when those executables are on
`PATH`. Missing tools produce `dependency_unavailable` analyzer outcomes. capa
rules are exposed as report capabilities and FLOSS strings as report artifacts;
their native JSON remains available in `extras`.
