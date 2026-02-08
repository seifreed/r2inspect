from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.modules.crypto_analyzer import CryptoAnalyzer


def test_crypto_analyzer_detect(tmp_path: Path):
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    config = Config(str(tmp_path / "config.json"))
    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        analyzer = CryptoAnalyzer(R2PipeAdapter(r2), config)
        result = analyzer.detect()
        assert "algorithms" in result
        assert "constants" in result
        assert "entropy_analysis" in result
    finally:
        r2.quit()
