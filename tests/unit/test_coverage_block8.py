from __future__ import annotations

from pathlib import Path

import r2pipe

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.simhash_analyzer import SIMHASH_AVAILABLE, SimHashAnalyzer

PE_FIXTURE = "samples/fixtures/hello_pe.exe"


def test_ccbhash_analyzer_real_fixture() -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = CCBHashAnalyzer(adapter, PE_FIXTURE)
        result = analyzer.analyze_functions()
        summary = analyzer.analyze()
    finally:
        r2.quit()

    assert "total_functions" in result
    assert "analyzed_functions" in result
    if result["available"]:
        assert result["function_hashes"]
        assert result["binary_ccbhash"]
    if summary.get("hash_value"):
        assert summary["hash_value"]
    else:
        assert summary.get("error") is not None


def test_ccbhash_helpers_and_compare() -> None:
    r2 = r2pipe.open(PE_FIXTURE)
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = CCBHashAnalyzer(adapter, PE_FIXTURE)
        functions = analyzer._extract_functions()
        assert isinstance(functions, list)
        if functions:
            name = functions[0].get("name")
            if name:
                assert analyzer.get_function_ccbhash(name)
    finally:
        r2.quit()

    assert CCBHashAnalyzer.compare_hashes("a", "a") is True
    assert CCBHashAnalyzer.compare_hashes("a", "b") is False
    assert CCBHashAnalyzer.compare_hashes("", "b") is None
    assert CCBHashAnalyzer.compare_ccbhashes("", "b") is False

    calc = CCBHashAnalyzer.calculate_ccbhash_from_file(PE_FIXTURE)
    assert calc is None or isinstance(calc, dict)

    function_hashes = {
        "f1": {"ccbhash": "aaa"},
        "f2": {"ccbhash": "aaa"},
        "f3": {"ccbhash": "bbb"},
    }
    groups = analyzer._find_similar_functions(function_hashes)
    assert groups and groups[0]["count"] == 2
    assert analyzer._calculate_binary_ccbhash(function_hashes)


def test_impfuzzy_process_imports() -> None:
    analyzer = ImpfuzzyAnalyzer(None, PE_FIXTURE)
    imports_data = [
        {"libname": "KERNEL32.DLL", "name": "CreateFileA"},
        {"lib": "user32", "func": "MessageBoxA"},
        {"library": "advapi32", "function": "RegOpenKeyA"},
        {"module": "ws2_32", "symbol": "connect"},
        {"libname": "KERNEL32.DLL", "name": "ord_123"},
        "bad",
    ]
    processed = analyzer._process_imports(imports_data)
    assert "kernel32.createfilea" in processed
    assert "user32.messageboxa" in processed
    assert "advapi32.regopenkeya" in processed
    assert "ws2_32.connect" in processed
    assert all("ord_" not in item for item in processed)


def test_impfuzzy_is_pe_file(tmp_path: Path) -> None:
    analyzer = ImpfuzzyAnalyzer(None, PE_FIXTURE)
    assert analyzer._is_pe_file() is True

    non_pe = tmp_path / "sample.bin"
    non_pe.write_bytes(b"ZZ")
    analyzer = ImpfuzzyAnalyzer(None, str(non_pe))
    assert analyzer._is_pe_file() is False


def test_simhash_helpers() -> None:
    if not SIMHASH_AVAILABLE:
        return

    r2 = r2pipe.open(PE_FIXTURE)
    try:
        adapter = R2PipeAdapter(r2)
        analyzer = SimHashAnalyzer(adapter, PE_FIXTURE)
    finally:
        r2.quit()

    assert analyzer._get_length_category(1) == "short"
    assert analyzer._get_length_category(10) == "medium"
    assert analyzer._get_length_category(50) == "long"
    assert analyzer._get_length_category(200) == "very_long"

    assert analyzer._classify_string_type("http://example.com") == "url"
    assert analyzer._classify_string_type("C:\\Windows\\System32") == "path"
    assert analyzer._classify_string_type("HKEY_LOCAL_MACHINE") == "registry"
    assert analyzer._classify_string_type("LoadLibraryA") == "api"
    assert analyzer._classify_string_type("error occurred") == "error"

    assert analyzer._classify_opcode_type("jmp") == "control"
    assert analyzer._classify_opcode_type("mov") == "data"
    assert analyzer._classify_opcode_type("add") == "arithmetic"
    assert analyzer._classify_opcode_type("xor") == "logical"
    assert analyzer._classify_opcode_type("cmp") == "compare"
    assert analyzer._classify_opcode_type("rep") == "string"
    assert analyzer._classify_opcode_type("noop") == "other"

    assert SimHashAnalyzer.compare_hashes("0x1", "0x1") == 0
    assert SimHashAnalyzer.compare_hashes("", "0x1") is None
    assert SimHashAnalyzer.compare_hashes("invalid", "0x1") is None
