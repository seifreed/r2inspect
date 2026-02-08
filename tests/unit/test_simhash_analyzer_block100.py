from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.simhash_analyzer import SimHashAnalyzer


def test_simhash_analyzer_basic():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = SimHashAnalyzer(adapter, str(sample))
        result = analyzer.analyze()
        assert result["hash_type"] == "simhash"
        assert "available" in result

        if SimHashAnalyzer.is_available():
            # When available, analyze_detailed returns structure with stats.
            detailed = analyzer.analyze_detailed()
            assert detailed.get("library_available") is True
            assert "feature_stats" in detailed
        else:
            # When missing, analyzer should report unavailable with error.
            assert result["available"] is False
            assert "simhash" in (result["error"] or "").lower()
            detailed = analyzer.analyze_detailed()
            assert detailed["available"] is False
            assert detailed["library_available"] is False
    finally:
        r2.quit()
