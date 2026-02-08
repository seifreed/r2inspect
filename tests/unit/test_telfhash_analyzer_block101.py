from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer


def test_telfhash_analyzer_basic():
    sample = Path("samples/fixtures/hello_elf")
    assert sample.exists()

    r2 = r2pipe.open(str(sample), flags=["-2"])
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = TelfhashAnalyzer(adapter, str(sample))
        result = analyzer.analyze()
        assert result["hash_type"] == "telfhash"
        assert "available" in result

        symbols = analyzer.analyze_symbols()
        assert "available" in symbols
        assert "is_elf" in symbols
        if symbols["available"]:
            assert symbols["is_elf"] is True
            assert symbols["symbol_count"] >= 0
            assert symbols["filtered_symbols"] >= 0
        else:
            assert "telfhash" in (symbols.get("error") or "").lower()
    finally:
        r2.quit()
