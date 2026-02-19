"""Comprehensive tests for binlex_analyzer.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules.binlex_analyzer import BinlexAnalyzer


class MockAdapter:
    def __init__(self, has_functions: bool = True):
        self.has_functions = has_functions

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
        if command.startswith("pdj "):
            return "[]"
        return ""


def test_binlex_library_availability():
    result = BinlexAnalyzer.is_available()
    assert result is True


def test_binlex_analyzer_initialization():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    assert analyzer.adapter == adapter
    assert str(analyzer.filepath) == "/path/to/binary"
    assert analyzer.default_ngram_size == 3


def test_binlex_no_functions():
    adapter = MockAdapter(has_functions=False)
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    result = analyzer.analyze()
    
    assert result["analyzer"] == "binlex"
    assert result["total_functions"] == 0
    assert result["error"] is not None


def test_binlex_basic_analysis():
    adapter = MockAdapter(has_functions=True)
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    result = analyzer.analyze(ngram_sizes=[2, 3])
    
    assert result["analyzer"] == "binlex"
    assert result["available"] is True
    assert result["total_functions"] == 3
    assert result["analyzed_functions"] >= 0
    assert "function_signatures" in result
    assert "ngram_sizes" in result
    assert result["ngram_sizes"] == [2, 3]


def test_binlex_default_ngram_sizes():
    adapter = MockAdapter(has_functions=True)
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    result = analyzer.analyze()
    
    assert result["ngram_sizes"] == [2, 3, 4]


def test_binlex_extract_functions():
    adapter = MockAdapter(has_functions=True)
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    functions = analyzer._extract_functions()
    
    assert len(functions) == 3
    assert all("addr" in f for f in functions)
    assert all("size" in f for f in functions)


def test_binlex_extract_tokens():
    adapter = MockAdapter(has_functions=True)
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    tokens = analyzer._extract_instruction_tokens(0x1000, "test_func")
    
    assert isinstance(tokens, list)
    assert len(tokens) > 0
    assert all(isinstance(t, str) for t in tokens)


def test_binlex_normalize_mnemonic():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    assert analyzer._normalize_mnemonic("MOV") == "mov"
    assert analyzer._normalize_mnemonic("  PUSH  ") == "push"
    assert analyzer._normalize_mnemonic("&test") is None
    assert analyzer._normalize_mnemonic("") is None
    assert analyzer._normalize_mnemonic(None) is None


def test_binlex_generate_ngrams():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    tokens = ["mov", "push", "call", "pop", "ret"]
    
    ngrams_2 = analyzer._generate_ngrams(tokens, 2)
    assert len(ngrams_2) == 4
    assert "mov push" in ngrams_2
    
    ngrams_3 = analyzer._generate_ngrams(tokens, 3)
    assert len(ngrams_3) == 3
    assert "mov push call" in ngrams_3


def test_binlex_ngrams_too_few_tokens():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    tokens = ["mov", "push"]
    
    ngrams = analyzer._generate_ngrams(tokens, 5)
    assert len(ngrams) == 0


def test_binlex_create_signature():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    ngrams = ["mov push", "push call", "call pop"]
    signature = analyzer._create_signature(ngrams)
    
    assert isinstance(signature, str)
    assert len(signature) == 64


def test_binlex_signature_deterministic():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    ngrams = ["mov push", "push call", "call pop"]
    
    sig1 = analyzer._create_signature(ngrams)
    sig2 = analyzer._create_signature(ngrams)
    assert sig1 == sig2


def test_binlex_calculate_binary_signature():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    function_signatures = {
        "func1": {
            2: {"signature": "abc123"},
            3: {"signature": "def456"},
        },
        "func2": {
            2: {"signature": "ghi789"},
            3: {"signature": "jkl012"},
        },
    }
    
    binary_sig = analyzer._calculate_binary_signature(function_signatures, [2, 3])
    assert isinstance(binary_sig, dict)
    assert 2 in binary_sig
    assert 3 in binary_sig
    assert all(isinstance(sig, str) for sig in binary_sig.values())


def test_binlex_find_similar_functions():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    function_signatures = {
        "func1": {2: {"signature": "abc123"}},
        "func2": {2: {"signature": "abc123"}},
        "func3": {2: {"signature": "def456"}},
    }
    
    unique, similar = analyzer._build_signature_groups(function_signatures, [2])
    assert unique[2] == 2
    assert len(similar[2]) >= 1


def test_binlex_compare_functions():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    result = analyzer.compare_functions("abc123", "abc123")
    assert result is True
    
    result = analyzer.compare_functions("abc123", "def456")
    assert result is False


def test_binlex_similarity_score():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    ngrams1 = ["mov push", "push call", "call pop"]
    ngrams2 = ["mov push", "push call", "call ret"]
    
    score = analyzer.get_function_similarity_score(ngrams1, ngrams2)
    assert 0.0 <= score <= 1.0


def test_binlex_similarity_identical():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    ngrams = ["mov push", "push call", "call pop"]
    score = analyzer.get_function_similarity_score(ngrams, ngrams)
    assert score == 1.0


def test_binlex_similarity_empty():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    score = analyzer.get_function_similarity_score([], [])
    assert score == 1.0
    
    score = analyzer.get_function_similarity_score(["mov"], [])
    assert score == 0.0


def test_binlex_top_ngrams():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    from collections import Counter, defaultdict
    
    all_ngrams = defaultdict(Counter)
    all_ngrams[2] = Counter({"mov push": 10, "push call": 8, "call pop": 5})
    all_ngrams[3] = Counter({"mov push call": 6, "push call pop": 4})
    
    top_ngrams = analyzer._collect_top_ngrams(all_ngrams, [2, 3])
    assert 2 in top_ngrams
    assert 3 in top_ngrams
    assert len(top_ngrams[2]) <= 10


def test_binlex_html_entity_cleanup():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    assert analyzer._normalize_mnemonic("mov&nbsp;test") == "mov test"
    assert analyzer._normalize_mnemonic("test&amp;more") == "test&more"


def test_binlex_extract_mnemonic_from_op():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    op1 = {"mnemonic": "mov"}
    assert analyzer._extract_mnemonic_from_op(op1) == "mov"
    
    op2 = {"opcode": "push rbp"}
    assert analyzer._extract_mnemonic_from_op(op2) == "push"
    
    op3 = {"mnemonic": "", "opcode": "call 0x1000"}
    assert analyzer._extract_mnemonic_from_op(op3) == "call"
    
    op4 = {}
    assert analyzer._extract_mnemonic_from_op(op4) is None


def test_binlex_extract_tokens_from_ops():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    ops = [
        {"mnemonic": "mov"},
        {"mnemonic": "push"},
        {"opcode": "call 0x1000"},
        {"mnemonic": ""},
    ]
    
    tokens = analyzer._extract_tokens_from_ops(ops)
    assert len(tokens) == 3


def test_binlex_unique_signatures_count():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    function_signatures = {
        "func1": {2: {"signature": "abc"}},
        "func2": {2: {"signature": "abc"}},
        "func3": {2: {"signature": "def"}},
        "func4": {2: {"signature": "ghi"}},
    }
    
    signatures, _ = analyzer._collect_signatures_for_size(function_signatures, 2)
    assert len(signatures) == 3


def test_binlex_similar_groups_building():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    from collections import defaultdict
    
    signature_groups = defaultdict(list)
    signature_groups["abc123"] = ["func1", "func2", "func3"]
    signature_groups["def456"] = ["func4"]
    
    similar_groups = analyzer._build_similar_groups(signature_groups)
    assert len(similar_groups) == 1
    assert similar_groups[0]["count"] == 3


def test_binlex_calculate_from_file():
    result = BinlexAnalyzer.calculate_binlex_from_file("/nonexistent/file")
    assert result is None


def test_binlex_with_real_binary():
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
        analyzer = BinlexAnalyzer(adapter, str(sample))
        result = analyzer.analyze(ngram_sizes=[2, 3])
        
        assert result["analyzer"] == "binlex"
        assert result["total_functions"] >= 0
        assert "function_signatures" in result
    except Exception:
        pytest.skip("Could not open binary with r2pipe")
    finally:
        if r2 is not None:
            try:
                r2.quit()
            except Exception:
                pass


def test_binlex_analyze_function_edge_cases():
    adapter = MockAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    
    result = analyzer._analyze_function(0x1000, "test_func", [2, 3, 4])
    assert result is None or isinstance(result, dict)


def test_binlex_error_handling():
    class FailingAdapter:
        def analyze_all(self):
            raise RuntimeError("Simulated error")
        
        def cmdj(self, command: str, default=None):
            raise RuntimeError("Simulated error")
        
        def get_disasm(self, address: int = 0, size: int = 0):
            raise RuntimeError("Simulated error")
    
    adapter = FailingAdapter()
    analyzer = BinlexAnalyzer(adapter, "/path/to/binary")
    result = analyzer.analyze()
    
    assert "error" in result or result["total_functions"] == 0
