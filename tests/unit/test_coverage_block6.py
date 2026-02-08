from __future__ import annotations

from pathlib import Path
from typing import Any

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.ssdeep_analyzer import SSDEEP_LIBRARY_AVAILABLE, SSDeepAnalyzer
from r2inspect.modules.tlsh_analyzer import TLSH_AVAILABLE, TLSHAnalyzer


def test_tlsh_analyzer_small_inputs(tmp_path: Path) -> None:
    sample = tmp_path / "tiny.bin"
    sample.write_bytes(b"1234")

    analyzer = TLSHAnalyzer(None, str(sample))
    assert analyzer._calculate_tlsh_from_hex("") is None
    assert analyzer._calculate_tlsh_from_hex("00") is None
    assert analyzer._calculate_binary_tlsh() is None

    if TLSH_AVAILABLE:
        hex_data = (b"A" * 100).hex()
        assert analyzer._calculate_tlsh_from_hex(hex_data)


def test_tlsh_analyzer_sections_real_fixture() -> None:
    if not TLSH_AVAILABLE:
        return

    r2 = r2pipe.open("samples/fixtures/hello_pe.exe")
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = TLSHAnalyzer(adapter, "samples/fixtures/hello_pe.exe")
        result = analyzer.analyze_sections()
    finally:
        r2.quit()

    assert result["available"] is True
    assert "section_tlsh" in result
    assert "function_tlsh" in result


def test_ssdeep_analyzer_real_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc" * 100)

    analyzer = SSDeepAnalyzer(str(sample))
    result = analyzer.analyze()

    if SSDeepAnalyzer.is_available():
        assert result["available"] is True
        assert result.get("hash_value")
    else:
        assert result["available"] is False
        assert "SSDeep not available" in result["error"]

    if SSDEEP_LIBRARY_AVAILABLE:
        hash_value, method, error = analyzer._calculate_hash()
        assert error is None
        assert method in {"python_library", "system_binary", None}
        assert hash_value
