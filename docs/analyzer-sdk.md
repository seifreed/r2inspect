# Analyzer SDK

External analyzers are discovered from the `r2inspect.analyzers` Python entry
point group. A plugin may expose a `BaseAnalyzer` subclass or a callable that
receives the registry.

## Analyzer class

```python
from typing import Any

from r2inspect.abstractions.base_analyzer import BaseAnalyzer


class ExampleAnalyzer(BaseAnalyzer):
    def get_name(self) -> str:
        return "vendor.example"

    def get_category(self) -> str:
        return "detection"

    def get_supported_formats(self) -> set[str]:
        return {"PE"}

    def analyze(self) -> dict[str, Any]:
        return {"available": True, "detected": False, "evidence": []}
```

Register it in the plugin package:

```toml
[project.entry-points."r2inspect.analyzers"]
example = "vendor_plugin:ExampleAnalyzer"
```

The loader derives name, category, formats, and description from a
`BaseAnalyzer` class without constructing it. Non-`BaseAnalyzer` classes default
to metadata; callable entry points should call `registry.register()` with an
explicit category and supported formats.

Constructors must accept the runtime dependencies used by the analyzer factory:
`adapter`, `r2`, `config`, and `filepath`/`filename` as applicable. Do not open
sessions or perform analysis at import time. Return JSON-compatible values and
preserve extraction errors as explicit unavailable/failed results.
