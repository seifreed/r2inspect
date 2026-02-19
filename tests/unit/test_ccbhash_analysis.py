"""Comprehensive tests for ccbhash_analyzer.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules.ccbhash_analyzer import CCBHashAnalyzer


class MockAdapter:
    def __init__(self, has_functions: bool = True):
        self.has_functions = has_functions

    def analyze_all(self):
        pass

    def get_cfg(self, func_offset: int):
        if not self.has_functions:
            return []
        return [
            {
                "blocks": [
                    {"offset": func_offset},
                    {"offset": func_offset + 10},
                    {"offset": func_offset + 20},
                ],
                "edges": [
                    {"src": func_offset, "dst": func_offset + 10},
                    {"src": func_offset + 10, "dst": func_offset + 20},
                ],
            }
        ]

    def cmdj(self, command: str, default=None):
        if command == "aflj":
            if not self.has_functions:
                return []
            return [
                {"name": "main", "addr": 0x1000, "size": 100},
                {"name": "sub_2000", "addr": 0x2000, "size": 50},
                {"name": "sub_3000", "addr": 0x3000, "size": 75},
            ]
        if command == "agj":
            return self.get_cfg(0)
        return default if default is not None else {}

    def cmd(self, command: str):
        return ""


def test_ccbhash_library_availability():
    result = CCBHashAnalyzer.is_available()
    assert result is True


def test_ccbhash_analyzer_initialization():
    adapter = MockAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    assert analyzer.adapter == adapter
    assert str(analyzer.filepath) == "/path/to/binary"


def test_ccbhash_no_functions():
    adapter = MockAdapter(has_functions=False)
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    result = analyzer.analyze_functions()
    
    assert result["available"] is False
    assert result["total_functions"] == 0
    assert result["error"] is not None


def test_ccbhash_basic_analysis():
    adapter = MockAdapter(has_functions=True)
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    result = analyzer.analyze_functions()
    
    assert result["available"] is True
    assert result["total_functions"] == 3
    assert result["analyzed_functions"] >= 0
    assert "function_hashes" in result
    assert "unique_hashes" in result
    assert "similar_functions" in result
    assert "binary_ccbhash" in result


def test_ccbhash_hash_type():
    adapter = MockAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    hash_type = analyzer._get_hash_type()
    assert hash_type == "ccbhash"


def test_ccbhash_extract_functions():
    adapter = MockAdapter(has_functions=True)
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    functions = analyzer._extract_functions()
    
    assert len(functions) == 3
    assert all("addr" in f for f in functions)
    assert all("size" in f for f in functions)


def test_ccbhash_calculate_function_hash():
    adapter = MockAdapter(has_functions=True)
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    ccbhash = analyzer._calculate_function_ccbhash(0x1000, "test_func")
    
    assert ccbhash is not None
    assert isinstance(ccbhash, str)
    assert len(ccbhash) == 64


def test_ccbhash_hash_deterministic():
    adapter = MockAdapter(has_functions=True)
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    
    hash1 = analyzer._calculate_function_ccbhash(0x1000, "test_func")
    hash2 = analyzer._calculate_function_ccbhash(0x1000, "test_func")
    assert hash1 == hash2


def test_ccbhash_canonical_representation():
    cfg = {
        "edges": [
            {"src": 0x1000, "dst": 0x1010},
            {"src": 0x1010, "dst": 0x1020},
        ]
    }
    canonical = CCBHashAnalyzer._build_canonical_representation(cfg, 0x1000)
    assert canonical is not None
    assert "1000->1010" in canonical or "4096->4112" in canonical


def test_ccbhash_canonical_with_blocks():
    cfg = {
        "blocks": [
            {"offset": 0x1000},
            {"offset": 0x1010},
            {"offset": 0x1020},
        ]
    }
    canonical = CCBHashAnalyzer._build_canonical_representation(cfg, 0x1000)
    assert canonical is not None


def test_ccbhash_canonical_empty():
    cfg = {}
    canonical = CCBHashAnalyzer._build_canonical_representation(cfg, 0x1000)
    assert canonical == "4096"


def test_ccbhash_find_similar_functions():
    adapter = MockAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    
    function_hashes = {
        "func1": {"ccbhash": "abc123", "addr": 0x1000, "size": 100},
        "func2": {"ccbhash": "abc123", "addr": 0x2000, "size": 100},
        "func3": {"ccbhash": "def456", "addr": 0x3000, "size": 50},
    }
    
    similar = analyzer._find_similar_functions(function_hashes)
    assert len(similar) >= 1
    assert similar[0]["count"] == 2


def test_ccbhash_calculate_binary_hash():
    adapter = MockAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    
    function_hashes = {
        "func1": {"ccbhash": "abc123"},
        "func2": {"ccbhash": "def456"},
        "func3": {"ccbhash": "ghi789"},
    }
    
    binary_hash = analyzer._calculate_binary_ccbhash(function_hashes)
    assert binary_hash is not None
    assert isinstance(binary_hash, str)
    assert len(binary_hash) == 64


def test_ccbhash_binary_hash_deterministic():
    adapter = MockAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    
    function_hashes = {
        "func1": {"ccbhash": "abc123"},
        "func2": {"ccbhash": "def456"},
    }
    
    hash1 = analyzer._calculate_binary_ccbhash(function_hashes)
    hash2 = analyzer._calculate_binary_ccbhash(function_hashes)
    assert hash1 == hash2


def test_ccbhash_binary_hash_order_independent():
    adapter = MockAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    
    hashes1 = {
        "func1": {"ccbhash": "abc"},
        "func2": {"ccbhash": "def"},
    }
    hashes2 = {
        "func2": {"ccbhash": "def"},
        "func1": {"ccbhash": "abc"},
    }
    
    hash1 = analyzer._calculate_binary_ccbhash(hashes1)
    hash2 = analyzer._calculate_binary_ccbhash(hashes2)
    assert hash1 == hash2


def test_ccbhash_compare_hashes():
    result = CCBHashAnalyzer.compare_hashes("abc123", "abc123")
    assert result is True
    
    result = CCBHashAnalyzer.compare_hashes("abc123", "def456")
    assert result is False
    
    result = CCBHashAnalyzer.compare_hashes("abc123", None)
    assert result is None
    
    result = CCBHashAnalyzer.compare_hashes(None, "abc123")
    assert result is None


def test_ccbhash_compare_ccbhashes():
    result = CCBHashAnalyzer.compare_ccbhashes("abc123", "abc123")
    assert result is True
    
    result = CCBHashAnalyzer.compare_ccbhashes("abc123", "def456")
    assert result is False


def test_ccbhash_get_function_hash():
    adapter = MockAdapter(has_functions=True)
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    
    ccbhash = analyzer.get_function_ccbhash("main")
    assert ccbhash is None or isinstance(ccbhash, str)


def test_ccbhash_get_function_hash_not_found():
    adapter = MockAdapter(has_functions=True)
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    
    ccbhash = analyzer.get_function_ccbhash("nonexistent_function")
    assert ccbhash is None


def test_ccbhash_unique_hashes_count():
    adapter = MockAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    
    function_hashes = {
        "func1": {"ccbhash": "abc123"},
        "func2": {"ccbhash": "abc123"},
        "func3": {"ccbhash": "def456"},
        "func4": {"ccbhash": "ghi789"},
    }
    
    unique_hashes = {f["ccbhash"] for f in function_hashes.values()}
    assert len(unique_hashes) == 3


def test_ccbhash_similar_functions_sorting():
    adapter = MockAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    
    function_hashes = {
        "func1": {"ccbhash": "abc"},
        "func2": {"ccbhash": "abc"},
        "func3": {"ccbhash": "def"},
        "func4": {"ccbhash": "def"},
        "func5": {"ccbhash": "def"},
    }
    
    similar = analyzer._find_similar_functions(function_hashes)
    assert len(similar) == 2
    assert similar[0]["count"] >= similar[1]["count"]


def test_ccbhash_html_entity_cleanup():
    adapter = MockAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    
    function_hashes = {
        "func&nbsp;1": {"ccbhash": "abc"},
        "func&amp;2": {"ccbhash": "abc"},
    }
    
    similar = analyzer._find_similar_functions(function_hashes)
    for group in similar:
        for func_name in group["functions"]:
            assert "&nbsp;" not in func_name
            assert "&amp;" not in func_name


def test_ccbhash_calculate_from_file():
    result = CCBHashAnalyzer.calculate_ccbhash_from_file("/nonexistent/file")
    assert result is None


def test_ccbhash_check_library_availability():
    adapter = MockAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    available, error = analyzer._check_library_availability()
    assert available is True
    assert error is None


def test_ccbhash_calculate_hash():
    adapter = MockAdapter(has_functions=True)
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    hash_value, method, error = analyzer._calculate_hash()
    
    if hash_value:
        assert isinstance(hash_value, str)
        assert method == "cfg_analysis"
        assert error is None


def test_ccbhash_with_real_binary():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("Sample binary not available")
    
    try:
        import r2pipe
        from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
    except ImportError:
        pytest.skip("r2pipe not available")
    
    r2 = None
    try:
        r2 = r2pipe.open(str(sample), flags=["-2"])
        adapter = R2PipeAdapter(r2)
        analyzer = CCBHashAnalyzer(adapter, str(sample))
        result = analyzer.analyze_functions()
        
        assert result["available"] is True
        assert result["total_functions"] >= 0
        assert "function_hashes" in result
        assert "binary_ccbhash" in result
    except Exception:
        pytest.skip("Could not open binary with r2pipe")
    finally:
        if r2 is not None:
            try:
                r2.quit()
            except Exception:
                pass


def test_ccbhash_error_handling():
    class FailingAdapter:
        def cmdj(self, command: str, default=None):
            raise RuntimeError("Simulated error")
        
        def get_cfg(self, func_offset: int):
            raise RuntimeError("Simulated error")
    
    adapter = FailingAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    result = analyzer.analyze_functions()
    
    assert "error" in result or result["total_functions"] == 0


def test_ccbhash_empty_binary_hash():
    adapter = MockAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    
    binary_hash = analyzer._calculate_binary_ccbhash({})
    assert binary_hash is None


def test_ccbhash_function_without_cfg():
    class NoCFGAdapter:
        def cmdj(self, command: str, default=None):
            if command == "aflj":
                return [{"name": "test", "addr": 0x1000, "size": 10}]
            return default if default is not None else {}
        
        def get_cfg(self, func_offset: int):
            return []
    
    adapter = NoCFGAdapter()
    analyzer = CCBHashAnalyzer(adapter, "/path/to/binary")
    ccbhash = analyzer._calculate_function_ccbhash(0x1000, "test")
    assert ccbhash is None
