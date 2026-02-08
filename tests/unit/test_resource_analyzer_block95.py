from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.resource_analyzer import ResourceAnalyzer


def test_resource_analyzer_basic():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        analyzer = ResourceAnalyzer(R2PipeAdapter(r2))
        result = analyzer.analyze()
        assert "has_resources" in result
        assert "resources" in result
    finally:
        r2.quit()
