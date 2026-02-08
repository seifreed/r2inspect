from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.modules.string_analyzer import StringAnalyzer
from r2inspect.modules.string_domain import parse_search_results, xor_string


def test_string_analyzer_basic(tmp_path: Path):
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    config = Config(str(tmp_path / "config.json"))
    r2 = r2pipe.open(str(sample), flags=["-2"])
    adapter = R2PipeAdapter(r2)
    try:
        analyzer = StringAnalyzer(adapter=adapter, config=config)
        result = analyzer.analyze()
        assert "strings" in result
        assert result["available"] in {True, False}
        # Exercise helper methods
        assert xor_string("A", 1) == "@"
        assert parse_search_results("0x10 test\n0x20") == ["0x10", "0x20"]
    finally:
        r2.quit()
