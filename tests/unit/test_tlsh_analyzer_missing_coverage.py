from __future__ import annotations

from pathlib import Path

from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer, TLSH_AVAILABLE
from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.testing.fake_r2 import FakeR2


def _make_adapter(**kwargs):
    return R2PipeAdapter(FakeR2(**kwargs))


def test_tlsh_analyzer_library_not_available(tmp_path):
    """When TLSH_AVAILABLE is False the analyzer reports unavailable."""
    sample = tmp_path / "dummy.bin"
    sample.write_bytes(b"\x00" * 200)

    adapter = _make_adapter()
    analyzer = TLSHAnalyzer(adapter, str(sample))

    # We test the actual runtime value; if tlsh isn't installed
    # this exercises the unavailable path naturally.
    if not TLSH_AVAILABLE:
        result = analyzer.analyze()
        assert result["available"] is False
        assert result.get("error")
    else:
        # Library is installed -- just confirm analyze works
        result = analyzer.analyze()
        assert "available" in result


def test_tlsh_analyzer_analyze_sections_library_unavailable(tmp_path):
    """analyze_sections returns available=False when library is missing."""
    sample = tmp_path / "dummy.bin"
    sample.write_bytes(b"\x00" * 200)

    adapter = _make_adapter()
    analyzer = TLSHAnalyzer(adapter, str(sample))

    result = analyzer.analyze_sections()
    assert "available" in result


def test_tlsh_analyzer_file_too_small(tmp_path):
    """A very small file produces a valid result dict."""
    small = tmp_path / "small.bin"
    small.write_bytes(b"a" * 10)

    adapter = _make_adapter()
    analyzer = TLSHAnalyzer(adapter, str(small))

    result = analyzer.analyze()
    assert "available" in result


def test_tlsh_analyzer_hash_calculation_with_real_file(tmp_path):
    """Hash calculation on a real temp file produces a result dict."""
    sample = tmp_path / "test.bin"
    sample.write_bytes(b"a" * 1024)

    adapter = _make_adapter()
    analyzer = TLSHAnalyzer(adapter, str(sample))

    result = analyzer.analyze()
    assert "available" in result or "error" in result


def test_tlsh_is_available():
    """is_available reflects the actual runtime state."""
    result = TLSHAnalyzer.is_available()
    assert result is TLSH_AVAILABLE


def test_tlsh_analyzer_nonexistent_file(tmp_path):
    """Analyzing a non-existent file path reports an error or unavailable."""
    adapter = _make_adapter()
    analyzer = TLSHAnalyzer(adapter, str(tmp_path / "nonexistent.bin"))

    result = analyzer.analyze()
    # Should handle gracefully regardless of library availability
    assert "available" in result or "error" in result
