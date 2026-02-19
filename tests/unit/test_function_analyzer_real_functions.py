#!/usr/bin/env python3
"""Comprehensive tests for function_analyzer.py - focusing on real analysis without mocks."""

from unittest.mock import MagicMock
from pathlib import Path
import tempfile

from r2inspect.modules.function_analyzer import FunctionAnalyzer
from r2inspect.modules.function_domain import machoc_hash_from_mnemonics


class MinimalAdapter:
    """Minimal test adapter for function analysis."""
    
    def __init__(self):
        self.commands = {}
        self.json_commands = {}
        
    def cmd(self, command):
        return self.commands.get(command, "")
    
    def cmdj(self, command, default=None):
        return self.json_commands.get(command, default)


def test_function_analyzer_initialization_basic():
    """Test basic FunctionAnalyzer initialization."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    assert analyzer.adapter is adapter
    assert analyzer.r2 is adapter
    assert analyzer.config is None
    assert analyzer.functions_cache is None


def test_function_analyzer_initialization_with_config():
    """Test FunctionAnalyzer initialization with config."""
    adapter = MinimalAdapter()
    config = MagicMock()
    analyzer = FunctionAnalyzer(adapter, config=config)
    
    assert analyzer.config is config


def test_function_analyzer_initialization_with_filename():
    """Test FunctionAnalyzer initialization with filename."""
    adapter = MinimalAdapter()
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"\x00" * 1024)
        tf.flush()
        filename = tf.name
    
    try:
        analyzer = FunctionAnalyzer(adapter, filename=filename)
        assert analyzer._file_size_mb is not None
        assert analyzer._file_size_mb < 1.0
    finally:
        Path(filename).unlink()


def test_get_file_size_mb_nonexistent():
    """Test _get_file_size_mb with nonexistent file."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter, filename="/nonexistent/file.bin")
    assert analyzer._file_size_mb is None


def test_get_file_size_mb_none():
    """Test _get_file_size_mb with None filename."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter, filename=None)
    assert analyzer._file_size_mb is None


def test_should_run_full_analysis_no_file_size():
    """Test _should_run_full_analysis with no file size."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    assert analyzer._should_run_full_analysis() is True


def test_should_run_full_analysis_small_file():
    """Test _should_run_full_analysis with small file."""
    adapter = MinimalAdapter()
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"\x00" * 1024)
        tf.flush()
        filename = tf.name
    
    try:
        analyzer = FunctionAnalyzer(adapter, filename=filename)
        assert analyzer._should_run_full_analysis() is True
    finally:
        Path(filename).unlink()


def test_should_run_full_analysis_with_deep_analysis_config():
    """Test _should_run_full_analysis with deep_analysis config."""
    adapter = MinimalAdapter()
    config = MagicMock()
    config.typed_config.analysis.deep_analysis = True
    analyzer = FunctionAnalyzer(adapter, config=config)
    assert analyzer._should_run_full_analysis() is True


def test_should_run_full_analysis_config_exception():
    """Test _should_run_full_analysis handles config exceptions."""
    adapter = MinimalAdapter()
    config = MagicMock()
    config.typed_config = None
    analyzer = FunctionAnalyzer(adapter, config=config)
    assert analyzer._should_run_full_analysis() is True


def test_analyze_functions_no_functions():
    """Test analyze_functions when no functions are found."""
    adapter = MinimalAdapter()
    adapter.json_commands["aflj"] = []
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer.analyze_functions()
    assert result["total_functions"] == 0
    assert result["machoc_hashes"] == {}
    assert "error" in result


def test_analyze_functions_with_functions():
    """Test analyze_functions with actual functions."""
    adapter = MinimalAdapter()
    functions = [
        {"name": "main", "addr": 0x1000, "size": 100},
        {"name": "func1", "addr": 0x2000, "size": 50},
    ]
    adapter.json_commands["aflj"] = functions
    
    ops = [{"opcode": "push ebp"}, {"opcode": "mov ebp, esp"}]
    adapter.json_commands["pdfj @ 4096"] = {"ops": ops}
    adapter.json_commands["pdfj @ 8192"] = {"ops": ops}
    
    analyzer = FunctionAnalyzer(adapter)
    result = analyzer.analyze_functions()
    
    assert result["total_functions"] == 2
    assert "machoc_hashes" in result
    assert "function_stats" in result


def test_analyze_functions_error_handling():
    """Test analyze_functions handles errors gracefully."""
    adapter = MinimalAdapter()
    
    def raise_error(cmd, default=None):
        raise Exception("Test error")
    
    adapter.cmdj = raise_error
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer.analyze_functions()
    assert result["total_functions"] == 0
    assert "error" in result


def test_generate_function_stats_empty():
    """Test _generate_function_stats with empty list."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._generate_function_stats([])
    assert result == {}


def test_generate_function_stats_basic():
    """Test _generate_function_stats with functions."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    functions = [
        {"name": "func1", "size": 100, "type": "fcn"},
        {"name": "func2", "size": 200, "type": "fcn"},
        {"name": "func3", "size": 150, "type": "imp"},
    ]
    
    result = analyzer._generate_function_stats(functions)
    
    assert result["total_functions"] == 3
    assert result["functions_with_size"] == 3
    assert result["avg_function_size"] == 150.0
    assert result["min_function_size"] == 100
    assert result["max_function_size"] == 200
    assert result["total_code_size"] == 450


def test_generate_function_stats_with_types():
    """Test _generate_function_stats categorizes function types."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    functions = [
        {"name": "func1", "size": 100, "type": "fcn"},
        {"name": "func2", "size": 200, "type": "fcn"},
        {"name": "func3", "size": 150, "type": "imp"},
    ]
    
    result = analyzer._generate_function_stats(functions)
    
    assert "function_types" in result
    assert result["function_types"]["fcn"] == 2
    assert result["function_types"]["imp"] == 1


def test_generate_function_stats_largest_functions():
    """Test _generate_function_stats identifies largest functions."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    functions = [
        {"name": "small", "size": 10},
        {"name": "large", "size": 1000},
        {"name": "medium", "size": 100},
    ]
    
    result = analyzer._generate_function_stats(functions)
    
    assert "largest_functions" in result
    assert len(result["largest_functions"]) == 3
    assert result["largest_functions"][0][0] == "large"
    assert result["largest_functions"][0][1] == 1000


def test_generate_function_stats_error_handling():
    """Test _generate_function_stats handles errors."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._generate_function_stats(None)
    assert result == {}


def test_get_function_similarity_basic():
    """Test get_function_similarity finds duplicate hashes."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    hashes = {
        "func1": "hash_a",
        "func2": "hash_a",
        "func3": "hash_b",
        "func4": "hash_b",
        "func5": "hash_c",
    }
    
    result = analyzer.get_function_similarity(hashes)
    
    assert len(result) == 2
    assert "hash_a" in result
    assert "hash_b" in result
    assert "hash_c" not in result
    assert len(result["hash_a"]) == 2
    assert len(result["hash_b"]) == 2


def test_get_function_similarity_no_duplicates():
    """Test get_function_similarity with no duplicates."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    hashes = {
        "func1": "hash_a",
        "func2": "hash_b",
        "func3": "hash_c",
    }
    
    result = analyzer.get_function_similarity(hashes)
    assert len(result) == 0


def test_get_function_similarity_error_handling():
    """Test get_function_similarity handles errors."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer.get_function_similarity(None)
    assert result == {}


def test_generate_machoc_summary_basic():
    """Test generate_machoc_summary with valid data."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    analysis_results = {
        "machoc_hashes": {
            "func1": "hash_a",
            "func2": "hash_a",
            "func3": "hash_b",
        }
    }
    
    result = analyzer.generate_machoc_summary(analysis_results)
    
    assert result["total_functions_hashed"] == 3
    assert result["unique_machoc_hashes"] == 2
    assert result["duplicate_function_groups"] == 1
    assert result["total_duplicate_functions"] == 2


def test_generate_machoc_summary_no_hashes():
    """Test generate_machoc_summary with no hashes."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer.generate_machoc_summary({})
    assert "error" in result


def test_generate_machoc_summary_with_similarities():
    """Test generate_machoc_summary includes similarity details."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    analysis_results = {
        "machoc_hashes": {
            "func1": "hash_a",
            "func2": "hash_a",
            "func3": "hash_a",
            "func4": "hash_b",
            "func5": "hash_b",
        }
    }
    
    result = analyzer.generate_machoc_summary(analysis_results)
    
    assert "similarities" in result
    assert "most_common_patterns" in result
    assert len(result["most_common_patterns"]) > 0


def test_generate_machoc_summary_error_handling():
    """Test generate_machoc_summary handles errors."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer.generate_machoc_summary(None)
    assert "error" in result


def test_calculate_cyclomatic_complexity_no_addr():
    """Test _calculate_cyclomatic_complexity with no address."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._calculate_cyclomatic_complexity({})
    assert result == 0


def test_calculate_cyclomatic_complexity_with_blocks():
    """Test _calculate_cyclomatic_complexity with CFG blocks."""
    adapter = MinimalAdapter()
    blocks = [
        {"jump": 0x2000, "fail": 0x2010},
        {"jump": 0x2020},
        {},
    ]
    adapter.json_commands["agj @ 4096"] = blocks
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._calculate_cyclomatic_complexity({"addr": 0x1000})
    assert result >= 1


def test_calculate_cyclomatic_complexity_error():
    """Test _calculate_cyclomatic_complexity handles errors."""
    adapter = MinimalAdapter()
    
    def raise_error(cmd, default=None):
        raise Exception("Test error")
    
    adapter.cmdj = raise_error
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._calculate_cyclomatic_complexity({"addr": 0x1000})
    assert result == 0


def test_classify_function_type_library():
    """Test _classify_function_type for library functions."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    assert analyzer._classify_function_type("lib.printf", {}) == "library"
    assert analyzer._classify_function_type("kernel32.CreateFile", {}) == "library"


def test_classify_function_type_thunk():
    """Test _classify_function_type for thunk functions."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    assert analyzer._classify_function_type("j_printf", {}) == "thunk"
    assert analyzer._classify_function_type("some_thunk", {}) == "thunk"
    assert analyzer._classify_function_type("small_func", {"size": 5}) == "thunk"


def test_classify_function_type_user():
    """Test _classify_function_type for user functions."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    assert analyzer._classify_function_type("main", {"size": 100}) == "user"
    assert analyzer._classify_function_type("sub_401000", {"size": 100}) == "user"


def test_classify_function_type_unknown():
    """Test _classify_function_type for unknown functions."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    assert analyzer._classify_function_type("weird_name", {"size": 100}) == "unknown"


def test_classify_function_type_error():
    """Test _classify_function_type handles errors."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._classify_function_type(None, {})
    assert result == "unknown"


def test_calculate_std_dev_empty():
    """Test _calculate_std_dev with empty list."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._calculate_std_dev([])
    assert result == 0.0


def test_calculate_std_dev_single_value():
    """Test _calculate_std_dev with single value."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._calculate_std_dev([5.0])
    assert result == 0.0


def test_calculate_std_dev_multiple_values():
    """Test _calculate_std_dev with multiple values."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
    result = analyzer._calculate_std_dev(values)
    assert result > 0.0


def test_calculate_std_dev_error():
    """Test _calculate_std_dev handles errors."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._calculate_std_dev([1, "invalid"])
    assert result == 0.0


def test_analyze_function_coverage_basic():
    """Test _analyze_function_coverage with functions."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    functions = [
        {"size": 100, "nbbs": 5},
        {"size": 200, "nbbs": 10},
        {"size": 0},
    ]
    
    result = analyzer._analyze_function_coverage(functions)
    
    assert result["total_functions"] == 3
    assert result["functions_with_size"] == 2
    assert result["functions_with_blocks"] == 2
    assert result["total_code_coverage"] == 300
    assert result["avg_function_size"] == 150.0


def test_analyze_function_coverage_percentages():
    """Test _analyze_function_coverage calculates percentages."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    functions = [
        {"size": 100, "nbbs": 5},
        {"size": 0, "nbbs": 0},
    ]
    
    result = analyzer._analyze_function_coverage(functions)
    
    assert "size_coverage_percent" in result
    assert "block_coverage_percent" in result
    assert result["size_coverage_percent"] == 50.0
    assert result["block_coverage_percent"] == 50.0


def test_analyze_function_coverage_error():
    """Test _analyze_function_coverage handles errors."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._analyze_function_coverage(None)
    assert result == {}


def test_process_single_function_hash_no_address():
    """Test _process_single_function_hash with no address."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    func = {"name": "test"}
    result = analyzer._process_single_function_hash(func, 0, 1)
    assert result is None


def test_extract_mnemonics_from_ops_delegation():
    """Test _extract_mnemonics_from_ops delegates correctly."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    ops = [
        {"opcode": "mov eax, ebx"},
        {"opcode": "push ecx"},
    ]
    
    result = analyzer._extract_mnemonics_from_ops(ops)
    assert result == ["mov", "push"]


def test_function_analyzer_caching():
    """Test that function cache works correctly."""
    adapter = MinimalAdapter()
    functions = [{"name": "main", "addr": 0x1000}]
    adapter.json_commands["aflj"] = functions
    
    analyzer = FunctionAnalyzer(adapter)
    
    result1 = analyzer._get_functions()
    result2 = analyzer._get_functions()
    
    assert result1 is result2
    assert analyzer.functions_cache is not None


def test_function_analyzer_stats_no_sizes():
    """Test function stats when no functions have sizes."""
    adapter = MinimalAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    functions = [
        {"name": "func1", "type": "fcn"},
        {"name": "func2", "type": "fcn"},
    ]
    
    result = analyzer._generate_function_stats(functions)
    
    assert result["total_functions"] == 2
    assert result["functions_with_size"] == 0
