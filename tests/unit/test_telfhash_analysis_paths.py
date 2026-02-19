"""Comprehensive tests for telfhash_analyzer.py - analysis paths and symbol processing."""

from pathlib import Path
from unittest.mock import Mock, patch

from r2inspect.modules.telfhash_analyzer import TelfhashAnalyzer

SAMPLES_DIR = Path(__file__).parent.parent.parent / "samples" / "fixtures"
HELLO_ELF = SAMPLES_DIR / "hello_elf"


def test_analyze_symbols_not_available():
    """Test analyze_symbols when telfhash not available."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", False):
        result = analyzer.analyze_symbols()
        
        assert result["available"] is False
        assert "not available" in result["error"]


def test_analyze_symbols_not_elf():
    """Test analyze_symbols when file is not ELF."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._is_elf_file = Mock(return_value=False)
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True):
        result = analyzer.analyze_symbols()
        
        assert result["available"] is True
        assert result["is_elf"] is False
        assert "not an ELF" in result["error"]


def test_analyze_symbols_success():
    """Test analyze_symbols with successful analysis."""
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    analyzer._get_elf_symbols = Mock(return_value=[
        {"name": "func1", "type": "FUNC", "bind": "GLOBAL"},
        {"name": "func2", "type": "FUNC", "bind": "GLOBAL"}
    ])
    analyzer._filter_symbols_for_telfhash = Mock(return_value=[
        {"name": "func1", "type": "FUNC", "bind": "GLOBAL"}
    ])
    analyzer._extract_symbol_names = Mock(return_value=["func1"])
    
    mock_result = [{"telfhash": "T1234HASH"}]
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        result = analyzer.analyze_symbols()
        
        assert result["available"] is True
        assert result["is_elf"] is True
        assert result["telfhash"] == "T1234HASH"
        assert result["symbol_count"] == 2
        assert result["filtered_symbols"] == 1
        assert result["symbols_used"] == ["func1"]


def test_analyze_symbols_telfhash_exception():
    """Test analyze_symbols when telfhash calculation fails."""
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    analyzer._get_elf_symbols = Mock(return_value=[])
    analyzer._filter_symbols_for_telfhash = Mock(return_value=[])
    analyzer._extract_symbol_names = Mock(return_value=[])
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", side_effect=Exception("Calc error")):
        result = analyzer.analyze_symbols()
        
        assert result["available"] is True
        assert result["is_elf"] is True
        assert "failed" in result["error"]


def test_analyze_symbols_general_exception():
    """Test analyze_symbols with general exception."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._is_elf_file = Mock(side_effect=Exception("General error"))
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True):
        result = analyzer.analyze_symbols()
        
        assert "error" in result
        assert "General error" in result["error"]


def test_is_elf_file_via_is_elf_file_util():
    """Test _is_elf_file using is_elf_file utility."""
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    analyzer.r2 = Mock()
    
    with patch("r2inspect.modules.telfhash_analyzer.is_elf_file", return_value=True):
        result = analyzer._is_elf_file()
        
        assert result is True


def test_is_elf_file_via_has_elf_symbols():
    """Test _is_elf_file via _has_elf_symbols."""
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    analyzer.r2 = Mock()
    analyzer._cmdj = Mock(return_value={"bin": {"os": "linux"}})
    analyzer._cmd_list = Mock(return_value=[{"name": "symbol1"}])
    
    with patch("r2inspect.modules.telfhash_analyzer.is_elf_file", return_value=False):
        result = analyzer._is_elf_file()
        
        assert result is True


def test_is_elf_file_no_r2():
    """Test _is_elf_file when r2 is None."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer.r2 = None
    
    result = analyzer._is_elf_file()
    
    assert result is False


def test_is_elf_file_exception():
    """Test _is_elf_file with exception."""
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    analyzer.r2 = Mock()
    
    with patch("r2inspect.modules.telfhash_analyzer.is_elf_file", side_effect=Exception("Check error")):
        result = analyzer._is_elf_file()
        
        assert result is False


def test_has_elf_symbols_success():
    """Test _has_elf_symbols with success."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._cmd_list = Mock(return_value=[{"name": "sym"}])
    
    info_cmd = {"bin": {"os": "linux"}}
    result = analyzer._has_elf_symbols(info_cmd)
    
    assert result is True


def test_has_elf_symbols_unix():
    """Test _has_elf_symbols with unix os."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._cmd_list = Mock(return_value=[{"name": "sym"}])
    
    info_cmd = {"bin": {"os": "unix"}}
    result = analyzer._has_elf_symbols(info_cmd)
    
    assert result is True


def test_has_elf_symbols_no_symbols():
    """Test _has_elf_symbols with no symbols."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._cmd_list = Mock(return_value=[])
    
    info_cmd = {"bin": {"os": "linux"}}
    result = analyzer._has_elf_symbols(info_cmd)
    
    assert result is False


def test_has_elf_symbols_no_info():
    """Test _has_elf_symbols with no info_cmd."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._cmd_list = Mock(return_value=[{"name": "sym"}])
    
    result = analyzer._has_elf_symbols(None)
    
    assert result is False


def test_has_elf_symbols_exception():
    """Test _has_elf_symbols with exception."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._cmd_list = Mock(side_effect=Exception("Cmd error"))
    
    info_cmd = {"bin": {"os": "linux"}}
    result = analyzer._has_elf_symbols(info_cmd)
    
    assert result is False


def test_get_elf_symbols_success():
    """Test _get_elf_symbols with success."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._cmd_list = Mock(return_value=[
        {"name": "main", "type": "FUNC"},
        {"name": "helper", "type": "FUNC"}
    ])
    
    result = analyzer._get_elf_symbols()
    
    assert len(result) == 2
    assert result[0]["name"] == "main"


def test_get_elf_symbols_empty():
    """Test _get_elf_symbols with no symbols."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._cmd_list = Mock(return_value=[])
    
    result = analyzer._get_elf_symbols()
    
    assert result == []


def test_get_elf_symbols_exception():
    """Test _get_elf_symbols with exception."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    analyzer._cmd_list = Mock(side_effect=Exception("Symbol error"))
    
    result = analyzer._get_elf_symbols()
    
    assert result == []


def test_filter_symbols_for_telfhash():
    """Test _filter_symbols_for_telfhash filtering logic."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    
    symbols = [
        {"name": "main", "type": "FUNC", "bind": "GLOBAL"},
        {"name": "helper", "type": "OBJECT", "bind": "WEAK"},
        {"name": "local_func", "type": "FUNC", "bind": "LOCAL"},
        {"name": "__internal", "type": "FUNC", "bind": "GLOBAL"},
        {"name": "section", "type": "SECTION", "bind": "LOCAL"},
        {"name": "", "type": "FUNC", "bind": "GLOBAL"},
        {"name": "a", "type": "FUNC", "bind": "GLOBAL"}
    ]
    
    result = analyzer._filter_symbols_for_telfhash(symbols)
    
    assert len(result) == 2
    assert result[0]["name"] == "main"
    assert result[1]["name"] == "helper"


def test_should_skip_symbol_short_names():
    """Test _should_skip_symbol with short names."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    
    assert analyzer._should_skip_symbol("a") is True
    assert analyzer._should_skip_symbol("") is True
    assert analyzer._should_skip_symbol("ab") is False


def test_should_skip_symbol_patterns():
    """Test _should_skip_symbol with various patterns."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    
    assert analyzer._should_skip_symbol("__internal") is True
    assert analyzer._should_skip_symbol("_GLOBAL_OFFSET_TABLE_") is True
    assert analyzer._should_skip_symbol("_DYNAMIC") is True
    assert analyzer._should_skip_symbol(".Lstart") is True
    assert analyzer._should_skip_symbol("_edata") is True
    assert analyzer._should_skip_symbol("_end") is True
    assert analyzer._should_skip_symbol("_start") is True
    assert analyzer._should_skip_symbol("normal_function") is False


def test_extract_symbol_names():
    """Test _extract_symbol_names sorting."""
    analyzer = TelfhashAnalyzer(Mock(), "/test/file")
    
    symbols = [
        {"name": "zebra"},
        {"name": "apple"},
        {"name": ""},
        {"name": "banana"}
    ]
    
    result = analyzer._extract_symbol_names(symbols)
    
    assert result == ["apple", "banana", "zebra"]


def test_compare_hashes_success():
    """Test compare_hashes with success."""
    mock_ssdeep = Mock()
    mock_ssdeep.compare.return_value = 75
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.get_ssdeep", return_value=mock_ssdeep):
        result = TelfhashAnalyzer.compare_hashes("HASH1", "HASH2")
        
        assert result == 75


def test_compare_hashes_not_available():
    """Test compare_hashes when telfhash not available."""
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", False):
        result = TelfhashAnalyzer.compare_hashes("HASH1", "HASH2")
        
        assert result is None


def test_compare_hashes_empty_hash1():
    """Test compare_hashes with empty first hash."""
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True):
        result = TelfhashAnalyzer.compare_hashes("", "HASH2")
        
        assert result is None


def test_compare_hashes_empty_hash2():
    """Test compare_hashes with empty second hash."""
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True):
        result = TelfhashAnalyzer.compare_hashes("HASH1", "")
        
        assert result is None


def test_compare_hashes_no_ssdeep():
    """Test compare_hashes when ssdeep not available."""
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.get_ssdeep", return_value=None):
        result = TelfhashAnalyzer.compare_hashes("HASH1", "HASH2")
        
        assert result is None


def test_compare_hashes_exception():
    """Test compare_hashes with exception."""
    mock_ssdeep = Mock()
    mock_ssdeep.compare.side_effect = Exception("Compare error")
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.get_ssdeep", return_value=mock_ssdeep):
        result = TelfhashAnalyzer.compare_hashes("HASH1", "HASH2")
        
        assert result is None


def test_analyze_symbols_with_dict_result():
    """Test analyze_symbols when telfhash returns dict."""
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    analyzer._get_elf_symbols = Mock(return_value=[])
    analyzer._filter_symbols_for_telfhash = Mock(return_value=[])
    analyzer._extract_symbol_names = Mock(return_value=[])
    
    mock_result = {"telfhash": "T5678DICT"}
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        result = analyzer.analyze_symbols()
        
        assert result["telfhash"] == "T5678DICT"


def test_analyze_symbols_with_string_result():
    """Test analyze_symbols when telfhash returns string."""
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    analyzer._get_elf_symbols = Mock(return_value=[])
    analyzer._filter_symbols_for_telfhash = Mock(return_value=[])
    analyzer._extract_symbol_names = Mock(return_value=[])
    
    mock_result = "T9999STR"
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        result = analyzer.analyze_symbols()
        
        assert result["telfhash"] == "T9999STR"


def test_analyze_symbols_with_msg_list():
    """Test analyze_symbols when telfhash returns list with msg."""
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    analyzer._get_elf_symbols = Mock(return_value=[])
    analyzer._filter_symbols_for_telfhash = Mock(return_value=[])
    analyzer._extract_symbol_names = Mock(return_value=[])
    
    mock_result = [{"msg": "Error message", "telfhash": None}]
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        result = analyzer.analyze_symbols()
        
        assert "Error message" in result["error"]


def test_analyze_symbols_with_msg_dict():
    """Test analyze_symbols when telfhash returns dict with msg."""
    adapter = Mock()
    analyzer = TelfhashAnalyzer(adapter, "/test/file")
    analyzer._is_elf_file = Mock(return_value=True)
    analyzer._get_elf_symbols = Mock(return_value=[])
    analyzer._filter_symbols_for_telfhash = Mock(return_value=[])
    analyzer._extract_symbol_names = Mock(return_value=[])
    
    mock_result = {"msg": "Dict error", "telfhash": None}
    
    with patch("r2inspect.modules.telfhash_analyzer.TELFHASH_AVAILABLE", True), \
         patch("r2inspect.modules.telfhash_analyzer.telfhash", return_value=mock_result):
        result = analyzer.analyze_symbols()
        
        assert "Dict error" in result["error"]
