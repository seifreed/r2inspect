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
