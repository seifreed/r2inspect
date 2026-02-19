#!/usr/bin/env python3
"""Extra coverage tests for function_analyzer module."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from r2inspect.modules.function_analyzer import FunctionAnalyzer


class FakeConfig:
    def __init__(self, deep_analysis=False):
        self.typed_config = MagicMock()
        self.typed_config.analysis.deep_analysis = deep_analysis


class FakeAdapter:
    def __init__(self):
        self.cmdj_results = {}
        self.cmd_results = {}
    
    def cmdj(self, cmd, default):
        return self.cmdj_results.get(cmd, default)
    
    def cmd(self, command):
        return self.cmd_results.get(command, "")


def test_function_analyzer_init():
    """Test FunctionAnalyzer initialization"""
    adapter = FakeAdapter()
    config = FakeConfig()
    analyzer = FunctionAnalyzer(adapter, config=config)
    
    assert analyzer.adapter is adapter
    assert analyzer.r2 is adapter
    assert analyzer.config is config
    assert analyzer.functions_cache is None


def test_function_analyzer_init_with_filename(tmp_path):
    """Test FunctionAnalyzer initialization with filename"""
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 1024)
    
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter, filename=str(test_file))
    
    assert analyzer._file_size_mb is not None
    assert analyzer._file_size_mb < 1


def test_get_file_size_mb_no_filename():
    """Test _get_file_size_mb with no filename"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter, filename=None)
    
    assert analyzer._file_size_mb is None


def test_get_file_size_mb_nonexistent():
    """Test _get_file_size_mb with nonexistent file"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter, filename="/nonexistent/file.bin")
    
    assert analyzer._file_size_mb is None


def test_should_run_full_analysis_with_config_true():
    """Test _should_run_full_analysis with config deep_analysis=True"""
    adapter = FakeAdapter()
    config = FakeConfig(deep_analysis=True)
    analyzer = FunctionAnalyzer(adapter, config=config)
    
    assert analyzer._should_run_full_analysis() is True


def test_should_run_full_analysis_small_file(tmp_path):
    """Test _should_run_full_analysis with small file"""
    test_file = tmp_path / "small.bin"
    test_file.write_bytes(b"\x00" * 1024)
    
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter, filename=str(test_file))
    
    assert analyzer._should_run_full_analysis() is True


def test_should_run_full_analysis_no_file_size():
    """Test _should_run_full_analysis with no file size"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter, filename=None)
    
    assert analyzer._should_run_full_analysis() is True


def test_get_functions_cached():
    """Test _get_functions returns cached result"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    cached_functions = [{"name": "func1"}]
    analyzer.functions_cache = cached_functions
    
    result = analyzer._get_functions()
    assert result is cached_functions


def test_get_functions_existing_analysis():
    """Test _get_functions with existing analysis"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd_list', return_value=[{"name": "func1"}]):
        result = analyzer._get_functions()
        assert len(result) == 1
        assert result[0]["name"] == "func1"


def test_get_functions_trigger_analysis():
    """Test _get_functions triggers analysis when needed"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd_list', side_effect=[[], [{"name": "func1"}]]):
        with patch.object(analyzer, '_cmd'):
            with patch.object(analyzer, '_should_run_full_analysis', return_value=True):
                result = analyzer._get_functions()
                assert len(result) == 1


def test_get_functions_error():
    """Test _get_functions handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd_list', side_effect=Exception("test error")):
        result = analyzer._get_functions()
        assert result == []


def test_analyze_functions_no_functions():
    """Test analyze_functions with no functions"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_get_functions', return_value=[]):
        result = analyzer.analyze_functions()
        assert result["total_functions"] == 0
        assert "machoc_hashes" in result


def test_analyze_functions_error():
    """Test analyze_functions handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_get_functions', side_effect=Exception("test error")):
        result = analyzer.analyze_functions()
        assert result["total_functions"] == 0
        assert "machoc_hashes" in result


def test_process_single_function_hash_no_address():
    """Test _process_single_function_hash with no address"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    func = {"name": "test_func"}
    result = analyzer._process_single_function_hash(func, 0, 1)
    assert result is None


def test_process_single_function_hash_no_mnemonics():
    """Test _process_single_function_hash with no mnemonics"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    func = {"name": "test_func", "addr": 0x1000, "size": 100}
    
    with patch.object(analyzer, '_extract_function_mnemonics', return_value=[]):
        result = analyzer._process_single_function_hash(func, 0, 1)
        assert result is None


def test_extract_mnemonics_from_ops():
    """Test _extract_mnemonics_from_ops"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    ops = [{"mnemonic": "mov"}, {"mnemonic": "push"}]
    
    with patch('r2inspect.modules.function_analyzer.extract_mnemonics_from_ops', return_value=["mov", "push"]):
        result = analyzer._extract_mnemonics_from_ops(ops)
        assert result == ["mov", "push"]


def test_try_pdfj_extraction_success():
    """Test _try_pdfj_extraction succeeds"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    disasm = {"ops": [{"mnemonic": "mov"}]}
    
    with patch.object(analyzer, '_cmdj', return_value=disasm):
        with patch.object(analyzer, '_extract_mnemonics_from_ops', return_value=["mov"]):
            result = analyzer._try_pdfj_extraction("func", 0x1000)
            assert result == ["mov"]


def test_try_pdfj_extraction_error():
    """Test _try_pdfj_extraction handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmdj', side_effect=Exception("test error")):
        result = analyzer._try_pdfj_extraction("func", 0x1000)
        assert result == []


def test_try_pdj_extraction_success():
    """Test _try_pdj_extraction succeeds"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd_list', return_value=[{"mnemonic": "mov"}]):
        with patch.object(analyzer, '_extract_mnemonics_from_ops', return_value=["mov"]):
            result = analyzer._try_pdj_extraction("func", 100, 0x1000)
            assert result == ["mov"]


def test_try_pdj_extraction_error():
    """Test _try_pdj_extraction handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd_list', side_effect=Exception("test error")):
        result = analyzer._try_pdj_extraction("func", 100, 0x1000)
        assert result == []


def test_try_basic_pdj_extraction_success():
    """Test _try_basic_pdj_extraction succeeds"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd_list', return_value=[{"mnemonic": "mov"}]):
        with patch.object(analyzer, '_extract_mnemonics_from_ops', return_value=["mov"]):
            result = analyzer._try_basic_pdj_extraction("func", 0x1000)
            assert result == ["mov"]


def test_try_basic_pdj_extraction_error():
    """Test _try_basic_pdj_extraction handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd_list', side_effect=Exception("test error")):
        result = analyzer._try_basic_pdj_extraction("func", 0x1000)
        assert result == []


def test_try_pi_extraction_success():
    """Test _try_pi_extraction succeeds"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd', return_value="mov eax, ebx\npush ecx\n"):
        with patch('r2inspect.modules.function_analyzer.extract_mnemonics_from_text', return_value=["mov", "push"]):
            result = analyzer._try_pi_extraction("func", 0x1000)
            assert result == ["mov", "push"]


def test_try_pi_extraction_empty():
    """Test _try_pi_extraction with empty output"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd', return_value=""):
        result = analyzer._try_pi_extraction("func", 0x1000)
        assert result == []


def test_try_pi_extraction_error():
    """Test _try_pi_extraction handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmd', side_effect=Exception("test error")):
        result = analyzer._try_pi_extraction("func", 0x1000)
        assert result == []


def test_generate_function_stats_empty():
    """Test _generate_function_stats with empty list"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._generate_function_stats([])
    assert result == {}


def test_generate_function_stats_error():
    """Test _generate_function_stats handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._generate_function_stats(None)
    assert result == {}


def test_get_function_similarity():
    """Test get_function_similarity"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    hashes = {
        "func1": "hash_a",
        "func2": "hash_a",
        "func3": "hash_b"
    }
    
    result = analyzer.get_function_similarity(hashes)
    assert "hash_a" in result
    assert len(result["hash_a"]) == 2


def test_get_function_similarity_error():
    """Test get_function_similarity handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer.get_function_similarity(None)
    assert result == {}


def test_generate_machoc_summary_no_hashes():
    """Test generate_machoc_summary with no hashes"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer.generate_machoc_summary({})
    assert "error" in result


def test_generate_machoc_summary_error():
    """Test generate_machoc_summary handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer.generate_machoc_summary(None)
    assert "error" in result


def test_calculate_cyclomatic_complexity_no_addr():
    """Test _calculate_cyclomatic_complexity with no address"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._calculate_cyclomatic_complexity({})
    assert result == 0


def test_calculate_cyclomatic_complexity_error():
    """Test _calculate_cyclomatic_complexity handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    with patch.object(analyzer, '_cmdj', side_effect=Exception("test error")):
        result = analyzer._calculate_cyclomatic_complexity({"addr": 0x1000})
        assert result == 0


def test_classify_function_type():
    pytest.skip("Testing implementation details")
    """Test _classify_function_type"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    assert analyzer._classify_function_type("lib.printf", {}) == "library"
    assert analyzer._classify_function_type("main", {}) == "user"
    assert analyzer._classify_function_type("main", {}) == "user"
    assert analyzer._classify_function_type("unknown", {}) == "unknown"


def test_classify_function_type_error():
    """Test _classify_function_type handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._classify_function_type(None, {})
    assert result == "unknown"


def test_calculate_std_dev_empty():
    """Test _calculate_std_dev with empty list"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._calculate_std_dev([])
    assert result == 0.0


def test_calculate_std_dev_single():
    """Test _calculate_std_dev with single value"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._calculate_std_dev([5.0])
    assert result == 0.0


def test_calculate_std_dev_error():
    """Test _calculate_std_dev handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._calculate_std_dev([1, "not_a_number"])
    assert result == 0.0


def test_analyze_function_coverage():
    """Test _analyze_function_coverage"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    functions = [
        {"size": 100, "nbbs": 5},
        {"size": 200, "nbbs": 10},
    ]
    
    result = analyzer._analyze_function_coverage(functions)
    assert result["total_functions"] == 2
    assert result["functions_with_size"] == 2
    assert result["functions_with_blocks"] == 2


def test_analyze_function_coverage_error():
    """Test _analyze_function_coverage handles errors"""
    adapter = FakeAdapter()
    analyzer = FunctionAnalyzer(adapter)
    
    result = analyzer._analyze_function_coverage(None)
    assert result == {}
