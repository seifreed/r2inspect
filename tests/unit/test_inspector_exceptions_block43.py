from __future__ import annotations

from pathlib import Path

from r2inspect.factory import create_inspector


def test_analyze_handles_exception():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        return

    with create_inspector(str(sample)) as inspector:

        def _boom(_opts):
            raise RuntimeError("boom")

        inspector._pipeline_builder.build = _boom  # type: ignore[method-assign]
        result = inspector.analyze(full_analysis=False)
        assert "error" in result


def test_analyze_handles_memoryerror():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        return

    with create_inspector(str(sample)) as inspector:

        class DummyPipeline:
            def execute(self, *args, **kwargs):
                raise MemoryError()

        def _build(_opts):
            return DummyPipeline()

        inspector._pipeline_builder.build = _build  # type: ignore[method-assign]
        result = inspector.analyze(full_analysis=False)
        assert result.get("error") == "Memory limit exceeded"
