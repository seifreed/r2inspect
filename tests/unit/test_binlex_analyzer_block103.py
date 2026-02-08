from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.binlex_analyzer import BinlexAnalyzer


def test_binlex_analyzer_basic():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        analyzer = BinlexAnalyzer(R2PipeAdapter(r2), str(sample))
        result = analyzer.analyze(ngram_sizes=[2])
        assert result["ngram_sizes"] == [2]
        assert "available" in result
        if result["available"]:
            assert result["analyzed_functions"] <= result["total_functions"]
            assert isinstance(result["function_signatures"], dict)
            assert isinstance(result["top_ngrams"], dict)
        else:
            assert isinstance(result.get("error"), str)
    finally:
        r2.quit()
