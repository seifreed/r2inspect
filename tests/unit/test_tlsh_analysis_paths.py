"""Comprehensive tests for tlsh_analyzer.py - analysis paths and comparison logic."""

from pathlib import Path
from unittest.mock import Mock, patch

from r2inspect.modules.tlsh_analyzer import TLSHAnalyzer

SAMPLES_DIR = Path(__file__).parent.parent.parent / "samples" / "fixtures"


def test_analyze_sections_not_available():
    """Test analyze_sections when TLSH not available."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", False):
        result = analyzer.analyze_sections()
        
        assert result["available"] is False
        assert "not installed" in result["error"]


def test_analyze_sections_success():
    """Test analyze_sections with success."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", True), \
         patch.object(analyzer, "_calculate_binary_tlsh", return_value="BINARY_HASH"), \
         patch.object(analyzer, "_calculate_section_tlsh", return_value={".text": "TEXT_HASH", ".data": "DATA_HASH"}), \
         patch.object(analyzer, "_calculate_function_tlsh", return_value={"func1": "FUNC_HASH"}):
        result = analyzer.analyze_sections()
        
        assert result["available"] is True
        assert result["binary_tlsh"] == "BINARY_HASH"
        assert result["text_section_tlsh"] == "TEXT_HASH"
        assert result["stats"]["sections_analyzed"] == 2
        assert result["stats"]["sections_with_tlsh"] == 2
        assert result["stats"]["functions_analyzed"] == 1
        assert result["stats"]["functions_with_tlsh"] == 1


def test_analyze_sections_with_none_hashes():
    """Test analyze_sections with some None hashes."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", True), \
         patch.object(analyzer, "_calculate_binary_tlsh", return_value="BINARY"), \
         patch.object(analyzer, "_calculate_section_tlsh", return_value={".text": "TEXT", ".data": None}), \
         patch.object(analyzer, "_calculate_function_tlsh", return_value={"func1": None, "func2": "HASH"}):
        result = analyzer.analyze_sections()
        
        assert result["stats"]["sections_analyzed"] == 2
        assert result["stats"]["sections_with_tlsh"] == 1
        assert result["stats"]["functions_analyzed"] == 2
        assert result["stats"]["functions_with_tlsh"] == 1


def test_analyze_sections_exception():
    """Test analyze_sections with exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.TLSH_AVAILABLE", True), \
         patch.object(analyzer, "_calculate_binary_tlsh", side_effect=Exception("Test error")):
        result = analyzer.analyze_sections()
        
        assert result["available"] is False
        assert "error" in result


def test_calculate_section_tlsh_success():
    """Test _calculate_section_tlsh with success."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    sections = [
        {"name": ".text", "vaddr": 0x1000, "size": 500},
        {"name": ".data", "vaddr": 0x2000, "size": 200}
    ]
    
    with patch.object(analyzer, "_get_sections", return_value=sections), \
         patch.object(analyzer, "_read_bytes_hex", return_value="AA" * 500), \
         patch.object(analyzer, "_calculate_tlsh_from_hex", return_value="SECTION_HASH"):
        result = analyzer._calculate_section_tlsh()
        
        assert ".text" in result
        assert ".data" in result
        assert result[".text"] == "SECTION_HASH"


def test_calculate_section_tlsh_empty_size():
    """Test _calculate_section_tlsh with zero size section."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    sections = [
        {"name": ".bss", "vaddr": 0x1000, "size": 0}
    ]
    
    with patch.object(analyzer, "_get_sections", return_value=sections):
        result = analyzer._calculate_section_tlsh()
        
        assert ".bss" in result
        assert result[".bss"] is None


def test_calculate_section_tlsh_very_large():
    """Test _calculate_section_tlsh with very large section."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    sections = [
        {"name": ".huge", "vaddr": 0x1000, "size": 100 * 1024 * 1024}
    ]
    
    with patch.object(analyzer, "_get_sections", return_value=sections):
        result = analyzer._calculate_section_tlsh()
        
        assert ".huge" in result
        assert result[".huge"] is None


def test_calculate_section_tlsh_no_sections():
    """Test _calculate_section_tlsh with no sections."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "_get_sections", return_value=[]):
        result = analyzer._calculate_section_tlsh()
        
        assert result == {}


def test_calculate_section_tlsh_section_exception():
    """Test _calculate_section_tlsh with exception in section processing."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    sections = [
        {"name": ".text", "vaddr": 0x1000, "size": 500}
    ]
    
    with patch.object(analyzer, "_get_sections", return_value=sections), \
         patch.object(analyzer, "_read_bytes_hex", side_effect=Exception("Read error")):
        result = analyzer._calculate_section_tlsh()
        
        assert ".text" in result
        assert result[".text"] is None


def test_calculate_section_tlsh_general_exception():
    """Test _calculate_section_tlsh with general exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "_get_sections", side_effect=Exception("General error")):
        result = analyzer._calculate_section_tlsh()
        
        assert result == {}


def test_calculate_function_tlsh_success():
    """Test _calculate_function_tlsh with success."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    functions = [
        {"name": "main", "addr": 0x1000, "size": 200},
        {"name": "helper", "addr": 0x2000, "size": 100}
    ]
    
    with patch.object(analyzer, "_get_functions", return_value=functions), \
         patch.object(analyzer, "_read_bytes_hex", return_value="BB" * 200), \
         patch.object(analyzer, "_calculate_tlsh_from_hex", return_value="FUNC_HASH"):
        result = analyzer._calculate_function_tlsh()
        
        assert "main" in result
        assert "helper" in result
        assert result["main"] == "FUNC_HASH"


def test_calculate_function_tlsh_malformed_data():
    """Test _calculate_function_tlsh with malformed function data."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    functions = [
        "not a dict",
        {"name": "valid", "addr": 0x1000, "size": 100}
    ]
    
    with patch.object(analyzer, "_get_functions", return_value=functions), \
         patch.object(analyzer, "_read_bytes_hex", return_value="CC" * 100), \
         patch.object(analyzer, "_calculate_tlsh_from_hex", return_value="HASH"):
        result = analyzer._calculate_function_tlsh()
        
        assert "valid" in result
        assert len(result) == 1


def test_calculate_function_tlsh_zero_size():
    """Test _calculate_function_tlsh with zero size function."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    functions = [
        {"name": "empty", "addr": 0x1000, "size": 0}
    ]
    
    with patch.object(analyzer, "_get_functions", return_value=functions):
        result = analyzer._calculate_function_tlsh()
        
        assert "empty" in result
        assert result["empty"] is None


def test_calculate_function_tlsh_no_addr():
    """Test _calculate_function_tlsh with no address."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    functions = [
        {"name": "noaddr", "size": 100}
    ]
    
    with patch.object(analyzer, "_get_functions", return_value=functions):
        result = analyzer._calculate_function_tlsh()
        
        assert "noaddr" in result
        assert result["noaddr"] is None


def test_calculate_function_tlsh_very_large():
    """Test _calculate_function_tlsh with very large function."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    functions = [
        {"name": "huge", "addr": 0x1000, "size": 200000}
    ]
    
    with patch.object(analyzer, "_get_functions", return_value=functions):
        result = analyzer._calculate_function_tlsh()
        
        assert "huge" in result
        assert result["huge"] is None


def test_calculate_function_tlsh_limit():
    """Test _calculate_function_tlsh with function limit."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    functions = [{"name": f"func{i}", "addr": 0x1000 + i * 100, "size": 100} for i in range(60)]
    
    with patch.object(analyzer, "_get_functions", return_value=functions), \
         patch.object(analyzer, "_read_bytes_hex", return_value="DD" * 100), \
         patch.object(analyzer, "_calculate_tlsh_from_hex", return_value="HASH"):
        result = analyzer._calculate_function_tlsh()
        
        assert len(result) == 50


def test_calculate_function_tlsh_no_functions():
    """Test _calculate_function_tlsh with no functions."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "_get_functions", return_value=[]):
        result = analyzer._calculate_function_tlsh()
        
        assert result == {}


def test_calculate_function_tlsh_function_exception():
    """Test _calculate_function_tlsh with exception in function processing."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    functions = [
        {"name": "func1", "addr": 0x1000, "size": 100}
    ]
    
    with patch.object(analyzer, "_get_functions", return_value=functions), \
         patch.object(analyzer, "_read_bytes_hex", side_effect=Exception("Read error")):
        result = analyzer._calculate_function_tlsh()
        
        assert "func1" in result
        assert result["func1"] is None


def test_calculate_function_tlsh_general_exception():
    """Test _calculate_function_tlsh with general exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "_get_functions", side_effect=Exception("General error")):
        result = analyzer._calculate_function_tlsh()
        
        assert result == {}


def test_get_sections():
    """Test _get_sections method."""
    adapter = Mock()
    adapter.get_sections.return_value = [{"name": ".text"}]
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._get_sections()
    
    assert len(result) == 1
    assert result[0]["name"] == ".text"


def test_get_sections_no_adapter():
    """Test _get_sections with no adapter."""
    analyzer = TLSHAnalyzer(None, "/test/file")
    
    result = analyzer._get_sections()
    
    assert result == []


def test_get_sections_no_method():
    """Test _get_sections when adapter has no get_sections method."""
    adapter = Mock(spec=[])
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._get_sections()
    
    assert result == []


def test_get_functions():
    """Test _get_functions method."""
    adapter = Mock()
    adapter.get_functions.return_value = [{"name": "main"}]
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._get_functions()
    
    assert len(result) == 1
    assert result[0]["name"] == "main"


def test_get_functions_no_adapter():
    """Test _get_functions with no adapter."""
    analyzer = TLSHAnalyzer(None, "/test/file")
    
    result = analyzer._get_functions()
    
    assert result == []


def test_get_functions_no_method():
    """Test _get_functions when adapter has no get_functions method."""
    adapter = Mock(spec=[])
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._get_functions()
    
    assert result == []


def test_read_bytes_hex():
    """Test _read_bytes_hex method."""
    adapter = Mock()
    adapter.read_bytes.return_value = b"\x01\x02\x03\x04"
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._read_bytes_hex(0x1000, 4)
    
    assert result == "01020304"


def test_read_bytes_hex_empty():
    """Test _read_bytes_hex with empty data."""
    adapter = Mock()
    adapter.read_bytes.return_value = b""
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._read_bytes_hex(0x1000, 0)
    
    assert result is None


def test_read_bytes_hex_none():
    """Test _read_bytes_hex with None data."""
    adapter = Mock()
    adapter.read_bytes.return_value = None
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._read_bytes_hex(0x1000, 4)
    
    assert result is None


def test_read_bytes_hex_exception():
    """Test _read_bytes_hex with exception."""
    adapter = Mock()
    adapter.read_bytes.side_effect = Exception("Read error")
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._read_bytes_hex(0x1000, 4)
    
    assert result is None


def test_read_bytes_hex_no_adapter():
    """Test _read_bytes_hex with no adapter."""
    analyzer = TLSHAnalyzer(None, "/test/file")
    
    result = analyzer._read_bytes_hex(0x1000, 4)
    
    assert result is None


def test_read_bytes_hex_no_method():
    """Test _read_bytes_hex when adapter has no read_bytes method."""
    adapter = Mock(spec=[])
    analyzer = TLSHAnalyzer(adapter, "/test/file")
    
    result = analyzer._read_bytes_hex(0x1000, 4)
    
    assert result is None


def test_compare_tlsh_success():
    """Test compare_tlsh method."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.tlsh.diff", return_value=25):
        result = analyzer.compare_tlsh("HASH1", "HASH2")
        
        assert result == 25


def test_compare_tlsh_empty_hash1():
    """Test compare_tlsh with empty first hash."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    result = analyzer.compare_tlsh("", "HASH2")
    
    assert result is None


def test_compare_tlsh_empty_hash2():
    """Test compare_tlsh with empty second hash."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    result = analyzer.compare_tlsh("HASH1", "")
    
    assert result is None


def test_compare_tlsh_exception():
    """Test compare_tlsh with exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch("r2inspect.modules.tlsh_analyzer.tlsh.diff", side_effect=Exception("Compare error")):
        result = analyzer.compare_tlsh("HASH1", "HASH2")
        
        assert result is None


def test_find_similar_sections_success():
    """Test find_similar_sections with success."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "analyze", return_value={
        "available": True,
        "section_tlsh": {
            ".text": "HASH1",
            ".data": "HASH2",
            ".rdata": "HASH3"
        }
    }), \
    patch.object(analyzer, "compare_tlsh", side_effect=lambda h1, h2: 30 if h1 != h2 else 0):
        result = analyzer.find_similar_sections(threshold=100)
        
        assert len(result) > 0
        assert all("section1" in r and "section2" in r for r in result)


def test_find_similar_sections_not_available():
    """Test find_similar_sections when not available."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "analyze", return_value={"available": False}):
        result = analyzer.find_similar_sections()
        
        assert result == []


def test_find_similar_sections_skip_none_hashes():
    """Test find_similar_sections skips None hashes."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "analyze", return_value={
        "available": True,
        "section_tlsh": {
            ".text": "HASH1",
            ".data": None,
            ".rdata": "HASH2"
        }
    }), \
    patch.object(analyzer, "compare_tlsh", return_value=30):
        result = analyzer.find_similar_sections(threshold=100)
        
        assert all(r["section1"] != ".data" and r["section2"] != ".data" for r in result)


def test_find_similar_sections_above_threshold():
    """Test find_similar_sections filters by threshold."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "analyze", return_value={
        "available": True,
        "section_tlsh": {
            ".text": "HASH1",
            ".data": "HASH2"
        }
    }), \
    patch.object(analyzer, "compare_tlsh", return_value=150):
        result = analyzer.find_similar_sections(threshold=100)
        
        assert result == []


def test_find_similar_sections_exception():
    """Test find_similar_sections with exception."""
    analyzer = TLSHAnalyzer(Mock(), "/test/file")
    
    with patch.object(analyzer, "analyze", side_effect=Exception("Error")):
        result = analyzer.find_similar_sections()
        
        assert result == []
