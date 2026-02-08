from __future__ import annotations

from pathlib import Path

from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer


def test_telfhash_compare_empty_returns_none():
    assert TelfhashAnalyzer.compare_hashes("", "") is None


def test_telfhash_calculate_missing_file(tmp_path: Path):
    missing = tmp_path / "missing.bin"
    result = TelfhashAnalyzer.calculate_telfhash_from_file(str(missing))
    assert result is None or result == []
