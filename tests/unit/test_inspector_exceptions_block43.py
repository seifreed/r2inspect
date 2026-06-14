from __future__ import annotations

from pathlib import Path
from typing import Any

from r2inspect.factory import create_inspector


class _BoomBuilder:
    """Pipeline builder double whose build() raises, to exercise analyze's error path."""

    def build(self, _options: Any) -> Any:
        raise RuntimeError("boom")


class _MemoryErrorPipeline:
    def execute(self, *_args: Any, **_kwargs: Any) -> Any:
        raise MemoryError()


class _MemoryErrorBuilder:
    """Pipeline builder double whose pipeline raises MemoryError on execute."""

    def build(self, _options: Any) -> Any:
        return _MemoryErrorPipeline()


def test_analyze_handles_exception():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        return

    with create_inspector(str(sample)) as inspector:
        inspector._pipeline_builder = _BoomBuilder()
        result = inspector.analyze(full_analysis=False)
        assert "error" in result


def test_analyze_handles_memoryerror():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        return

    with create_inspector(str(sample)) as inspector:
        inspector._pipeline_builder = _MemoryErrorBuilder()
        result = inspector.analyze(full_analysis=False)
        assert result.get("error") == "Memory limit exceeded"
