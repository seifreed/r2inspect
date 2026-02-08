from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer


def test_bindiff_analyzer_real_fixture():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        analyzer = BinDiffAnalyzer(R2PipeAdapter(r2), str(sample))
        result = analyzer.analyze()
        assert result.get("comparison_ready") is True
        assert "structural_features" in result
        assert "function_features" in result
        assert "string_features" in result
        assert "byte_features" in result
        assert "behavioral_features" in result

        comparison = analyzer.compare_with(result)
        assert "overall_similarity" in comparison
        assert 0.0 <= comparison.get("overall_similarity", 0.0) <= 1.0
    finally:
        r2.quit()
