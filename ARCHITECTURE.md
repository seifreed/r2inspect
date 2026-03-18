# Architecture Decisions Document

This document captures the key architectural decisions made in r2inspect, following Clean Architecture and Clean Code principles.

## Table of Contents

1. [Layer Structure](#layer-structure)
2. [Dependency Rule](#dependency-rule)
3. [Interface Segregation](#interface-segregation)
4. [Entity Organization](#entity-organization)
5. [Domain Services](#domain-services)
6. [Re-exports Pattern](#re-exports-pattern)
7. [Testing Strategy](#testing-strategy)

---

## Layer Structure

r2inspect follows Clean Architecture with concentric layers:

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI (Presentation)                    │
│  cli/commands/*.py → cli/presenter.py                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Application Layer                       │
│  core/inspector.py → pipeline/*.py → registry/*.py          │
│  modules/*_analyzer.py (use case orchestration)             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        Domain Layer                          │
│  domain/entities.py → domain/formats/*.py → domain/services/ │
│  domain/analysis/*.py → domain/hashing/*.py                  │
│  (NO imports from outer layers - stdlib only)                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Infrastructure Layer                      │
│  adapters/r2pipe_adapter.py → infrastructure/*.py           │
│  (Implements interfaces defined in domain)                  │
└─────────────────────────────────────────────────────────────┘
```

### Key Directories

| Directory | Layer | Purpose |
|-----------|-------|---------|
| `domain/` | Innermost | Pure business logic, entities, domain services |
| `interfaces/` | Contract | Protocol definitions (dependency inversion) |
| `core/` | Application | Use case orchestration (R2Inspector, PipelineBuilder) |
| `adapters/` | Infrastructure | External system adapters (radare2, libmagic) |
| `modules/` | Application | Analyzer implementations |
| `infrastructure/` | Infrastructure | Cross-cutting concerns (logging, memory, error handling) |
| `cli/` | Presentation | User interface layer |
| `schemas/` | DTO | Data transfer objects (re-export from domain) |

---

## Dependency Rule

**Decision:** Dependencies point inward. Domain layer has NO dependencies on outer layers.

### Enforcement

1. **Domain files use only stdlib:**
   ```python
   # domain/formats/crypto.py - CORRECT
   import re
   from typing import Any
   # No infrastructure imports!
   ```

2. **Architecture tests enforce this:**
   ```python
   # tests/unit/guardrails/test_architecture_import_rules.py
   def test_domain_does_not_depend_on_outer_layers():
       # Fails if domain imports from infrastructure/adapters/modules
   ```

3. **Re-exports pattern for backward compatibility:**
   ```python
   # modules/crypto_domain.py - Pure re-export
   from ..domain.formats.crypto import CRYPTO_PATTERNS
   __all__ = ["CRYPTO_PATTERNS"]
   ```

---

## Interface Segregation

**Decision:** `BinaryAnalyzerInterface` is split into 11 focused sub-protocols.

### Rationale

Instead of one monolithic interface, consumers depend only on the capabilities they need:

```python
# interfaces/binary_analyzer_protocols.py

@runtime_checkable
class CoreQueryProvider(Protocol):
    """Basic file metadata queries."""
    def get_file_info(self) -> dict[str, Any]: ...
    def get_entry_info(self) -> list[dict[str, Any]]: ...

@runtime_checkable
class SectionProvider(Protocol):
    """Section-level information."""
    def get_sections(self) -> list[dict[str, Any]]: ...

@runtime_checkable
class StringProvider(Protocol):
    """String extraction capabilities."""
    def get_strings(self) -> list[dict[str, Any]]: ...

# ... 8 more focused protocols

@runtime_checkable
class BinaryAnalyzerInterface(
    CoreQueryProvider,
    SectionProvider,
    StringProvider,
    # ... all sub-protocols
    Protocol,
):
    """Full analysis interface - union of all sub-protocols."""
```

### Benefits

1. Analyzers declare only the protocols they need
2. Easier to mock for testing
3. Clear contract between layers
4. Follows Interface Segregation Principle (ISP)

---

## Entity Organization

**Decision:** Domain entities are pure dataclasses in `domain/entities.py` and `domain/format_types.py`.

### Structure

```
domain/
├── entities.py              # FileInfo, ImportInfo, HashingResult, etc.
├── format_types.py          # SectionInfo, SecurityFeatures (format-specific)
├── results.py               # AnalyzerResult, HashResult
├── constants.py             # Business constants (THRESHOLDS, RISK_LEVELS)
├── analysis_runtime.py      # Runtime stats (AnalysisRuntimeStats)
└── result_builder.py        # Builds typed AnalysisResult from dict
```

### Why dataclasses?

1. **Immutable** (with `frozen=True` option)
2. **Type-safe** (full type hints)
3. **No external dependencies**
4. **Easy serialization** (`to_dict()` method)

### Example

```python
# domain/entities.py
@dataclass
class FileInfo:
    name: str = ""
    path: str = ""
    size: int = 0
    md5: str = ""
    sha256: str = ""
    # ... no methods, just data

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
```

---

## Domain Services

**Decision:** Pure domain logic lives in `domain/formats/` and `domain/analysis/`.

### When to use domain/services/ vs domain/formats/?

| Location | Purpose | Example |
|----------|---------|--------|
| `domain/formats/` | Format-specific logic (PE, ELF, Mach-O) | `elf.py`, `pe_info.py`, `telfhash.py` |
| `domain/analysis/` | Cross-format analysis logic | `import_risk.py`, `import_collection.py` |
| `domain/hashing/` | Hashing/comparison algorithms | `simhash_compare.py` |
| `domain/services/` | Complex domain workflows | `binbloom.py`, `function_analysis.py` |

### Pure vs Infrastructure-Dependent

```
PURE (domain/)              HYBRID (modules/)
─────────────────────────────────────────────────────
normalize_telfhash_value()  analyze_import()
get_risk_level()            collect_imports()
filter_symbols()            [calls adapter._cmdj()]
```

Hybrid files in `modules/` re-export pure functions from `domain/`:

```python
# modules/import_analyzer_support.py
from ..domain.analysis.import_risk import (
    get_risk_level,           # Pure domain function
    count_suspicious_indicators,
)

def analyze_import(imp, analyzer, *, logger):  # Infrastructure-dependent
    # Uses analyzer._calculate_risk_score()
```

---

## Re-exports Pattern

**Decision:** Files in `modules/` re-export domain functions for backward compatibility.

### Pattern

```python
# Before (monolithic in modules/):
# modules/import_analyzer_support.py contained ALL functions

# After (split):
# domain/analysis/import_risk.py - Pure functions
# modules/import_analyzer_support.py - Re-export + infrastructure code
```

### Example Re-export

```python
# modules/anti_analysis_domain.py
"""DEPRECATED: Import from r2inspect.domain.formats.anti_analysis instead."""

from ..domain.formats.anti_analysis import (
    ANTI_DEBUG_APIS,
    VM_ARTIFACTS,
    SANDBOX_INDICATORS,
    SUSPICIOUS_API_CATEGORIES,
)

__all__ = ["ANTI_DEBUG_APIS", "VM_ARTIFACTS", ...]
```

### Benefits

1. Existing code continues to work
2. New code can import directly from domain
3. Gradual migration path
4. Clear deprecation path

---

## Factory Pattern

**Decision:** `factory.py` is the composition root.

```python
# factory.py
def create_inspector(filename: str, config: Config | None = None) -> R2Inspector:
    # Composition root - wires all dependencies
    cfg = config or Config()
    session = R2Session(filename)
    r2 = session.open(file_size_mb)

    adapter = R2PipeAdapter(r2)
    registry = create_default_registry()
    pipeline_builder = PipelineBuilder(adapter, registry, cfg, filename, ...)

    deps = InspectorDependencies(
        adapter=adapter,
        registry_factory=create_default_registry,
        pipeline_builder_factory=...,
        cleanup_callback=session.close,
    )

    return R2Inspector(filename, cfg, deps=deps)
```

### Why Composition Root?

1. **Single place** for dependency wiring
2. **Testable** - can inject mocks
3. **Clear lifecycle** - resources cleaned up properly
4. **No service locator** anti-pattern

---

## Testing Strategy

### Architecture Guardrails

```python
# tests/unit/guardrails/test_architecture_import_rules.py

def test_domain_does_not_depend_on_outer_layers():
    """Domain files must not import from infrastructure/adapters/modules."""

def test_pipeline_does_not_import_adapters_directly():
    """Pipeline uses interfaces, not concrete adapters."""

def test_cli_does_not_import_domain_directly():
    """CLI goes through application layer."""
```

### No Mocks Policy

**Decision:** Use `FakeR2` pattern instead of mocking.

```python
# tests/conftest.py
class FakeR2:
    """Test double that mimics r2pipe without radare2 binary."""

    def cmd(self, command: str) -> str:
        # Returns canned responses for testing
        return FAKE_RESPONSES.get(command, "")

    def cmdj(self, command: str) -> Any:
        return FAKE_JSON.get(command, {})
```

### Why No Mocks?

1. **More realistic** - tests actual behavior
2. **Less brittle** - no mock implementation details
3. **Better coverage** - tests integration points
4. **Cleaner tests** - no mock setup/teardown

---

## Key Architectural Patterns

### 1. Pipeline Pattern

```python
# pipeline/analysis_pipeline.py
class AnalysisPipeline:
    def execute_sequential(self, stages: list[str]) -> dict[str, Any]:
        for stage in stages:
            result = self._execute_stage(stage)
            results[stage] = result
        return results
```

### 2. Registry Pattern

```python
# registry/default_registry.py
def create_default_registry() -> AnalyzerRegistry:
    registry = AnalyzerRegistry()
    registry.register("pe_analyzer", PEAnalyzerFactory())
    registry.register("elf_analyzer", ELFAnalyzerFactory())
    # ...
    return registry
```

### 3. Builder Pattern

```python
# core/pipeline_builder.py
class PipelineBuilder:
    def build_sequential_pipeline(self) -> AnalysisPipeline:
        pipeline = AnalysisPipeline(self.adapter, self.registry)
        pipeline.add_stage("metadata", self._metadata_stage)
        pipeline.add_stage("hashing", self._hashing_stage)
        return pipeline
```

---

## Migration Guide

### Adding New Domain Logic

1. Create pure function in `domain/formats/` or `domain/analysis/`
2. Export from `domain/__init__.py`
3. Create re-export in `modules/` if needed for backward compatibility
4. Add architecture test

### Adding New Analyzer

1. Create analyzer in `modules/xxx_analyzer.py`
2. Import domain logic from `domain/`
3. Register in `registry/default_registry.py`
4. Add tests

### Adding New Entity

1. Add dataclass in `domain/entities.py`
2. Add builder function in `domain/result_builder.py`
3. Re-export from `schemas/results_entities.py`

---

## References

- [Clean Architecture by Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [Interface Segregation Principle](https://en.wikipedia.org/wiki/Interface_segregation_principle)
- [Dependency Inversion Principle](https://en.wikipedia.org/wiki/Dependency_inversion_principle)
- [Composition Root Pattern](https://blog.ploeh.dk/2011/07/28/CompositionRoot/)
