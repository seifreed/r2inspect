from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.modules.macho_analyzer import MachOAnalyzer


def test_macho_analyzer_basic(tmp_path: Path):
    sample = Path("samples/fixtures/hello_macho")
    assert sample.exists()

    config = Config(str(tmp_path / "config.json"))
    r2 = r2pipe.open(str(sample), flags=["-2"])
    adapter = R2PipeAdapter(r2)
    try:
        analyzer = MachOAnalyzer(adapter=adapter, config=config)
        result = analyzer.analyze()
        assert result.get("format")
        assert "security_features" in result
    finally:
        r2.quit()
