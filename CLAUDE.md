# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is r2inspect

r2inspect is a malware analysis framework that automates static inspection of PE, ELF, and Mach-O binaries using radare2/r2pipe. It provides hashing (ssdeep, TLSH, SimHash, MACHOC, RichPE, Telfhash), detection heuristics (packer, crypto, anti-analysis), YARA scanning, and structured output (console/JSON/CSV).

## Prerequisites

- Python 3.13+ (3.14 supported)
- radare2 installed and in PATH
- libmagic (`brew install libmagic` on macOS, `apt install libmagic-dev` on Linux)
- Virtual environment: `.venv` (primary) or `venv` (legacy)

## Common Commands

```bash
# Install in development mode
pip install -e ".[dev]"

# Run all unit tests
pytest tests/unit/ -x -q

# Run a single test file
pytest tests/unit/test_smoke.py -x -v

# Run a single test by name
pytest tests/unit/test_smoke.py -k "test_function_name" -v

# Run integration tests (requires radare2 + test binaries)
pytest tests/integration/ -x -q

# Run with coverage
pytest tests/unit/ --cov=r2inspect --cov-report=term-missing

# Lint
ruff check r2inspect/
black --check r2inspect/

# Format
black r2inspect/
ruff check --fix r2inspect/

# Type check
mypy r2inspect/

# Run the CLI
r2inspect samples/fixtures/hello_pe.exe
r2inspect -j samples/fixtures/hello_pe.exe  # JSON output
```

## Architecture

### Core Flow

```
CLI (click) -> create_inspector() -> R2Inspector -> AnalysisPipeline -> analyzer modules
                                  -> R2PipeAdapter -> r2pipe -> radare2
```

### Key Layers

- **`factory.py`** — `create_inspector()` wires up adapter, registry, pipeline builder, and returns a context-managed `R2Inspector`
- **`core/inspector.py`** — `R2Inspector` is the main analysis facade; uses mixins (`InspectorExecutionMixin`, `InspectorLifecycleMixin`) for organization
- **`adapters/r2pipe_adapter.py`** — `R2PipeAdapter` implements `BinaryAnalyzerInterface`, wrapping r2pipe with validation and error handling
- **`interfaces/core.py`** — Protocol-based interfaces (`ConfigLike`, `FileValidatorLike`, `R2CommandInterface`, `AnalyzerBackend`, etc.) for dependency inversion
- **`pipeline/`** — `AnalysisPipeline` orchestrates stages (metadata, format, hashing, detection, security) with parallel/sequential execution; stages defined in `stages_*.py`
- **`registry/`** — `AnalyzerRegistry` maps analyzer names to metadata and factory functions; `default_registry_data.py` contains all registrations
- **`modules/`** — Individual analyzers (anti_analysis, authenticode, bindiff, compiler_detector, crypto, function_analyzer, import_analyzer, pe_analyzer, section_analyzer, simhash, ssdeep, tlsh, yara, etc.)
- **`infrastructure/`** — Cross-cutting concerns: logging, memory monitoring, circuit breaker, rate limiter, retry manager, hashing utilities, magic detection
- **`schemas/`** — Pydantic models for analysis results, converters, and serialization
- **`cli/`** — Click commands, display/output formatting, batch processing, interactive mode
- **`error_handling/`** — Unified error handler with classifier, severity levels, and recovery policies

### Analyzer Pattern

Analyzers inherit from `BaseAnalyzer` (in `abstractions/base_analyzer.py`) and implement an `analyze(adapter)` method. They are registered in `registry/default_registry_data.py` with format support metadata (PE, ELF, Mach-O) and category tags.

### Testing

- **Unit tests** (`tests/unit/`): Do not require radare2. Use `FakeR2` mock objects for adapter testing.
- **Integration tests** (`tests/integration/`): Require radare2 and test binary fixtures. Fixtures resolved via `R2INSPECT_TEST_BINARIES_DIR` env var or `../r2inspect-test-binaries/` sibling directory.
- Test resource limits are enforced in `conftest.py` (1 worker, 1GB memory, 5min CPU).
- Pytest markers: `unit`, `integration`, `requires_r2`, `slow`.

### Configuration

`Config` class in `config.py` wraps Pydantic-validated `R2InspectConfig` (in `config_schemas/schemas.py`). Supports JSON config files and environment variable overrides.

## Style

- Line length: 100 (black + ruff)
- Formatter: black, linter: ruff
- Import style: isort with black profile
- No mocks in tests — use `FakeR2` pattern or real fixtures
