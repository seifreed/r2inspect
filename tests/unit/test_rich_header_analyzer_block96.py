from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.rich_header_analyzer import RichHeaderAnalyzer


def test_rich_header_analyzer_basic():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = RichHeaderAnalyzer(adapter, str(sample))
        result = analyzer.analyze()
        assert "available" in result
        assert "rich_header" in result or "error" in result
    finally:
        r2.quit()
