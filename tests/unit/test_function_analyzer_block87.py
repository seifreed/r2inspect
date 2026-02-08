from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.function_analyzer import FunctionAnalyzer


def test_function_analyzer_basic():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        analyzer = FunctionAnalyzer(R2PipeAdapter(r2))
        result = analyzer.analyze_functions()
        assert "total_functions" in result
        assert "machoc_hashes" in result
    finally:
        r2.quit()
