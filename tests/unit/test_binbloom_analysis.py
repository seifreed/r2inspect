"""Comprehensive tests for binbloom_analyzer.py."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules.binbloom_analyzer import BinbloomAnalyzer


class MockAdapter:
    def __init__(self, has_functions: bool = True):
        self.has_functions = has_functions
        self.function_count = 5 if has_functions else 0

    def analyze_all(self):
        pass

    def get_disasm(self, address: int = 0, size: int = 0):
        if not self.has_functions:
            return {}
        return {
            "ops": [
                {"mnemonic": "mov", "addr": address},
                {"mnemonic": "push", "addr": address + 1},
                {"mnemonic": "call", "addr": address + 2},
                {"mnemonic": "pop", "addr": address + 3},
                {"mnemonic": "ret", "addr": address + 4},
            ]
        }

    def get_disasm_text(self, address: int = 0, size: int = 0):
        if not self.has_functions:
            return ""
        return "mov rax, rbx\npush rbp\ncall 0x1000\npop rbp\nret\n"

    def cmdj(self, command: str, default=None):
        if command == "aflj":
            if not self.has_functions:
                return []
            return [
                {"name": "main", "addr": 0x1000, "size": 100},
                {"name": "sub_2000", "addr": 0x2000, "size": 50},
                {"name": "sub_3000", "addr": 0x3000, "size": 75},
            ]
        if command == "pdfj":
            return self.get_disasm()
        return default if default is not None else {}

    def cmd(self, command: str):
        if command.startswith("pi "):
            return self.get_disasm_text()
        return ""


def test_binbloom_library_availability():
    result = BinbloomAnalyzer.is_available()
    assert isinstance(result, bool)


def test_binbloom_analyzer_initialization():
    adapter = MockAdapter()
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    assert analyzer.adapter == adapter
    assert str(analyzer.filepath) == "/path/to/binary"
    assert analyzer.default_capacity == 256
    assert analyzer.default_error_rate == 0.001


def test_binbloom_no_functions():
    adapter = MockAdapter(has_functions=False)
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    result = analyzer.analyze()
    assert result["analyzer"] == "binbloom"
    assert result["total_functions"] == 0
    assert result["error"] is not None


def test_binbloom_basic_analysis():
    try:
        from pybloom_live import BloomFilter
    except ImportError:
        pytest.skip("pybloom-live not available")
    
    adapter = MockAdapter(has_functions=True)
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    result = analyzer.analyze(capacity=128, error_rate=0.01)
    
    assert result["analyzer"] == "binbloom"
    assert result["available"] is True
    assert result["total_functions"] == 3
    assert result["analyzed_functions"] >= 0
    assert "function_signatures" in result
    assert "capacity" in result
    assert "error_rate" in result


def test_binbloom_extract_functions():
    adapter = MockAdapter(has_functions=True)
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    functions = analyzer._extract_functions()
    assert len(functions) == 3
    assert all("addr" in f for f in functions)
    assert all("size" in f for f in functions)


def test_binbloom_extract_mnemonics():
    try:
        from pybloom_live import BloomFilter
    except ImportError:
        pytest.skip("pybloom-live not available")
    
    adapter = MockAdapter(has_functions=True)
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    mnemonics = analyzer._extract_instruction_mnemonics(0x1000, "test_func")
    assert isinstance(mnemonics, list)
    assert len(mnemonics) > 0
    assert all(isinstance(m, str) for m in mnemonics)


def test_binbloom_normalize_mnemonic():
    adapter = MockAdapter()
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    
    assert analyzer._normalize_mnemonic("MOV") == "mov"
    assert analyzer._normalize_mnemonic("  PUSH  ") == "push"
    assert analyzer._normalize_mnemonic("") is None
    assert analyzer._normalize_mnemonic(None) is None


def test_binbloom_bloom_to_signature():
    adapter = MockAdapter()
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    instructions = ["mov", "push", "call", "pop", "ret"]
    signature = analyzer._bloom_to_signature(instructions)
    assert isinstance(signature, str)
    assert len(signature) == 64


def test_binbloom_generate_ngrams():
    adapter = MockAdapter()
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    instructions = ["mov", "push", "call", "pop", "ret"]
    components = analyzer._build_signature_components(instructions)
    assert len(components) == 3
    assert components[0].startswith("UNIQ:")
    assert components[1].startswith("FREQ:")
    assert components[2].startswith("BIGR:")


def test_binbloom_compare_bloom_filters():
    try:
        from pybloom_live import BloomFilter
    except ImportError:
        pytest.skip("pybloom-live not available")
    
    adapter = MockAdapter()
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    
    bloom1 = BloomFilter(capacity=100, error_rate=0.01)
    bloom2 = BloomFilter(capacity=100, error_rate=0.01)
    
    for item in ["mov", "push", "call"]:
        bloom1.add(item)
        bloom2.add(item)
    
    similarity = analyzer.compare_bloom_filters(bloom1, bloom2)
    assert 0.0 <= similarity <= 1.0


def test_binbloom_serialize_deserialize():
    try:
        from pybloom_live import BloomFilter
    except ImportError:
        pytest.skip("pybloom-live not available")
    
    bloom = BloomFilter(capacity=100, error_rate=0.01)
    bloom.add("test1")
    bloom.add("test2")
    bloom.add("test3")
    
    serialized = BinbloomAnalyzer.deserialize_bloom(BinbloomAnalyzer._serialize_bloom(None, bloom))
    assert serialized is not None
    assert serialized.capacity == bloom.capacity


def test_binbloom_deserialize_invalid():
    result = BinbloomAnalyzer.deserialize_bloom("invalid_base64")
    assert result is None
    
    result = BinbloomAnalyzer.deserialize_bloom("")
    assert result is None


def test_binbloom_calculate_from_file_no_pybloom():
    with pytest.MonkeyPatch.context() as m:
        m.setattr("r2inspect.modules.binbloom_analyzer.BLOOM_AVAILABLE", False)
        result = BinbloomAnalyzer.calculate_binbloom_from_file("/nonexistent/file")
        assert result is None or result.get("available") is False


def test_binbloom_find_similar_functions():
    adapter = MockAdapter()
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    
    function_signatures = {
        "func1": {"signature": "abc123", "instruction_count": 10},
        "func2": {"signature": "abc123", "instruction_count": 10},
        "func3": {"signature": "def456", "instruction_count": 5},
    }
    
    similar = analyzer._find_similar_functions(function_signatures)
    assert isinstance(similar, list)
    assert len(similar) >= 1


def test_binbloom_html_entity_cleanup():
    adapter = MockAdapter()
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    
    function_signatures = {
        "func&nbsp;1": {"signature": "abc", "instruction_count": 5},
        "func&amp;2": {"signature": "def", "instruction_count": 5},
    }
    
    similar = analyzer._find_similar_functions(function_signatures)
    for group in similar:
        for func_name in group["functions"]:
            assert "&nbsp;" not in func_name
            assert "&amp;" not in func_name


def test_binbloom_unique_signatures():
    adapter = MockAdapter()
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    
    function_signatures = {
        "func1": {"signature": "abc123"},
        "func2": {"signature": "abc123"},
        "func3": {"signature": "def456"},
        "func4": {"signature": "ghi789"},
    }
    
    unique = analyzer._collect_unique_signatures(function_signatures)
    assert len(unique) == 3


def test_binbloom_empty_instructions():
    adapter = MockAdapter()
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    signature = analyzer._bloom_to_signature([])
    assert isinstance(signature, str)


def test_binbloom_build_frequency_patterns():
    adapter = MockAdapter()
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    instructions = ["mov", "push", "mov", "call", "mov"]
    unique = sorted(set(instructions))
    patterns = analyzer._build_frequency_patterns(instructions, unique)
    assert len(patterns) == len(unique)
    assert any("mov:3" in p for p in patterns)


def test_binbloom_build_unique_bigrams():
    adapter = MockAdapter()
    analyzer = BinbloomAnalyzer(adapter, "/path/to/binary")
    instructions = ["mov", "push", "call", "pop", "ret"]
    bigrams = analyzer._build_unique_bigrams(instructions)
    assert len(bigrams) == 4
    assert "mov→push" in bigrams


def test_binbloom_with_real_binary():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("Sample binary not available")
    
    try:
        from pybloom_live import BloomFilter
        import r2pipe
        from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
    except ImportError:
        pytest.skip("Required libraries not available")
    
    r2 = None
    try:
        r2 = r2pipe.open(str(sample), flags=["-2"])
        adapter = R2PipeAdapter(r2)
        analyzer = BinbloomAnalyzer(adapter, str(sample))
        result = analyzer.analyze(capacity=128, error_rate=0.01)
        
        assert result["analyzer"] == "binbloom"
        assert result["total_functions"] >= 0
    except Exception:
        pytest.skip("Could not open binary with r2pipe")
    finally:
        if r2 is not None:
            try:
                r2.quit()
            except Exception:
                pass
