from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.modules.elf_analyzer import ELFAnalyzer


def test_elf_analyzer_basic(tmp_path: Path):
    sample = Path("samples/fixtures/hello_elf")
    assert sample.exists()

    config = Config(str(tmp_path / "config.json"))
    r2 = r2pipe.open(str(sample), flags=["-2"])
    adapter = R2PipeAdapter(r2)
    try:
        analyzer = ELFAnalyzer(adapter=adapter, config=config)
        result = analyzer.analyze()
        assert result.get("format") in {"ELF", "ELF32", "ELF64", "Unknown"}
        assert "security_features" in result
    finally:
        r2.quit()
