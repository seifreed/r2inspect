from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer


def test_tlsh_analyzer_basic():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = TLSHAnalyzer(adapter, str(sample))
        result = analyzer.analyze()
        assert "available" in result
        sections = analyzer.analyze_sections()
        assert "available" in sections
    finally:
        r2.quit()
