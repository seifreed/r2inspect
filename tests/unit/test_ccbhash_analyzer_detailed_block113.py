from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer


def test_ccbhash_analyzer_detailed_real_fixture():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = CCBHashAnalyzer(adapter, str(sample))
        detailed = analyzer.analyze_functions()
        assert "available" in detailed
        assert "total_functions" in detailed
        assert "analyzed_functions" in detailed
        assert "binary_ccbhash" in detailed
        if detailed["available"]:
            assert detailed["analyzed_functions"] <= detailed["total_functions"]
            assert detailed["binary_ccbhash"]
        else:
            assert isinstance(detailed.get("error"), str)
    finally:
        r2.quit()
