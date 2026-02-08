from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.binbloom_analyzer import BinbloomAnalyzer


def test_binbloom_analyzer_basic():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = BinbloomAnalyzer(adapter, str(sample))
        result = analyzer.analyze()
        assert "available" in result

        if result["available"]:
            assert result["analyzed_functions"] <= result["total_functions"]
            assert isinstance(result["function_signatures"], dict)
            assert isinstance(result["bloom_stats"], dict)
            assert result["capacity"] > 0
        else:
            assert result.get("library_available") is False
            assert "pybloom" in (result.get("error") or "").lower()
    finally:
        r2.quit()
