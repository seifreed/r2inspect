from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer
from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer


def test_telfhash_non_elf_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"ZZZZ")

    analyzer = TelfhashAnalyzer(None, str(sample))
    result = analyzer.analyze()
    assert result["available"] in {True, False}
    assert result["hash_type"] == "telfhash"
    assert result["error"]


def test_ccbhash_compare_and_binary_ccbhash() -> None:
    assert CCBHashAnalyzer.compare_hashes("a", "a") is True
    assert CCBHashAnalyzer.compare_hashes("a", "b") is False
    assert CCBHashAnalyzer.compare_hashes("", "b") is None

    ccb = CCBHashAnalyzer(None, "samples/fixtures/hello_pe.exe")
    combined = ccb._calculate_binary_ccbhash({"f": {"ccbhash": "abc"}})
    assert combined


def test_ccbhash_function_ccbhash_real() -> None:
    r2 = r2pipe.open("samples/fixtures/hello_pe.exe")
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = CCBHashAnalyzer(adapter, "samples/fixtures/hello_pe.exe")
        functions = analyzer._extract_functions()
        if functions:
            func = functions[0]
            value = analyzer._calculate_function_ccbhash(func["addr"], func.get("name", "f"))
            assert value
    finally:
        r2.quit()
