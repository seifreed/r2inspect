from __future__ import annotations

from pathlib import Path

from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer


def test_ssdeep_analyzer_basic():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    analyzer = SSDeepAnalyzer(filepath=str(sample))
    result = analyzer.analyze()
    assert "available" in result
    assert "hash_value" in result
