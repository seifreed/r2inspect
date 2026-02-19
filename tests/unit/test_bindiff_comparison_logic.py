"""Comprehensive tests for bindiff_analyzer.py - comparison logic."""

from pathlib import Path
from unittest.mock import Mock, patch

from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

SAMPLES_DIR = Path(__file__).parent.parent.parent / "samples" / "fixtures"


def test_compare_with_success():
    """Test compare_with method with success."""
    adapter = Mock()
    adapter.get_file_info.return_value = {}
    adapter.get_sections.return_value = []
    adapter.get_imports.return_value = []
    adapter.get_exports.return_value = []
    adapter.get_functions.return_value = []
    adapter.get_strings.return_value = []
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file1.exe")
    
    other_results = {
        "filename": "file2.exe",
        "comparison_ready": True,
        "structural_features": {},
        "function_features": {},
        "string_features": {},
        "byte_features": {},
        "behavioral_features": {}
    }
    
    with patch.object(analyzer, "_compare_structural", return_value=0.8), \
         patch.object(analyzer, "_compare_functions", return_value=0.7), \
         patch.object(analyzer, "_compare_strings", return_value=0.9), \
         patch.object(analyzer, "_compare_bytes", return_value=0.6), \
         patch.object(analyzer, "_compare_behavioral", return_value=0.75), \
         patch("r2inspect.modules.bindiff_analyzer.calculate_overall_similarity", return_value=0.75), \
         patch("r2inspect.modules.bindiff_analyzer.categorize_similarity", return_value="Similar"):
        result = analyzer.compare_with(other_results)
        
        assert result["binary_a"] == "file1.exe"
        assert result["binary_b"] == "file2.exe"
        assert result["overall_similarity"] == 0.75
        assert result["similarity_level"] == "Similar"


def test_compare_with_not_ready():
    """Test compare_with when one binary is not ready."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file1.exe")
    
    other_results = {
        "comparison_ready": False
    }
    
    with patch.object(analyzer, "analyze", return_value={"comparison_ready": True}):
        result = analyzer.compare_with(other_results)
        
        assert "error" in result
        assert result["similarity_score"] == 0.0


def test_compare_with_exception():
    """Test compare_with with exception."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file1.exe")
    
    with patch.object(analyzer, "analyze", side_effect=Exception("Test error")):
        result = analyzer.compare_with({})
        
        assert "error" in result
        assert result["similarity_score"] == 0.0


def test_compare_structural_success():
    """Test _compare_structural method."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    a = {"structural_features": {"file_type": "pe"}}
    b = {"structural_features": {"file_type": "pe"}}
    
    with patch("r2inspect.modules.bindiff_analyzer.compare_structural_features", return_value=0.9):
        result = analyzer._compare_structural(a, b)
        
        assert result == 0.9


def test_compare_structural_exception():
    """Test _compare_structural with exception."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.compare_structural_features", side_effect=Exception("Error")):
        result = analyzer._compare_structural({}, {})
        
        assert result == 0.0


def test_compare_functions_success():
    """Test _compare_functions method."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    a = {"function_features": {"function_count": 10}}
    b = {"function_features": {"function_count": 12}}
    
    with patch("r2inspect.modules.bindiff_analyzer.compare_function_features", return_value=0.85):
        result = analyzer._compare_functions(a, b)
        
        assert result == 0.85


def test_compare_functions_exception():
    """Test _compare_functions with exception."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.compare_function_features", side_effect=Exception("Error")):
        result = analyzer._compare_functions({}, {})
        
        assert result == 0.0


def test_compare_strings_success():
    """Test _compare_strings method."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    a = {"string_features": {"total_strings": 50}}
    b = {"string_features": {"total_strings": 48}}
    
    with patch("r2inspect.modules.bindiff_analyzer.compare_string_features", return_value=0.95):
        result = analyzer._compare_strings(a, b)
        
        assert result == 0.95


def test_compare_strings_exception():
    """Test _compare_strings with exception."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.compare_string_features", side_effect=Exception("Error")):
        result = analyzer._compare_strings({}, {})
        
        assert result == 0.0


def test_compare_bytes_success():
    """Test _compare_bytes method."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    a = {"byte_features": {"rolling_hash": "hash1"}}
    b = {"byte_features": {"rolling_hash": "hash2"}}
    
    with patch("r2inspect.modules.bindiff_analyzer.compare_byte_features", return_value=0.7):
        result = analyzer._compare_bytes(a, b)
        
        assert result == 0.7


def test_compare_bytes_exception():
    """Test _compare_bytes with exception."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.compare_byte_features", side_effect=Exception("Error")):
        result = analyzer._compare_bytes({}, {})
        
        assert result == 0.0


def test_compare_behavioral_success():
    """Test _compare_behavioral method."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    a = {"behavioral_features": {"crypto_apis": 5}}
    b = {"behavioral_features": {"crypto_apis": 4}}
    
    with patch("r2inspect.modules.bindiff_analyzer.compare_behavioral_features", return_value=0.8):
        result = analyzer._compare_behavioral(a, b)
        
        assert result == 0.8


def test_compare_behavioral_exception():
    """Test _compare_behavioral with exception."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.compare_behavioral_features", side_effect=Exception("Error")):
        result = analyzer._compare_behavioral({}, {})
        
        assert result == 0.0


def test_extract_function_features_no_analyze_all():
    """Test _extract_function_features when adapter has no analyze_all."""
    adapter = Mock(spec=["get_functions"])
    adapter.get_functions.return_value = []
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.cmd_helper") as mock_cmd:
        result = analyzer._extract_function_features()
        
        mock_cmd.assert_called_once()


def test_extract_function_features_empty_cfg():
    """Test _extract_function_features with empty CFG."""
    adapter = Mock()
    adapter.get_functions.return_value = [
        {"name": "main", "size": 200, "offset": 0x1000}
    ]
    adapter.get_cfg.return_value = []
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.cmd_helper"):
        result = analyzer._extract_function_features()
        
        assert "cfg_features" in result


def test_extract_function_features_cfg_other_type():
    """Test _extract_function_features with CFG as other type."""
    adapter = Mock()
    adapter.get_functions.return_value = [
        {"name": "main", "size": 200, "offset": 0x1000}
    ]
    adapter.get_cfg.return_value = "invalid"
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.cmd_helper"):
        result = analyzer._extract_function_features()
        
        assert "cfg_features" in result


def test_extract_function_features_complexity_calculation():
    """Test _extract_function_features calculates complexity."""
    adapter = Mock()
    adapter.get_functions.return_value = [
        {"name": "main", "size": 200, "offset": 0x1000}
    ]
    adapter.get_cfg.return_value = {
        "blocks": [{"addr": 0x1000}, {"addr": 0x1010}, {"addr": 0x1020}],
        "edges": [{"from": 0x1000, "to": 0x1010}, {"from": 0x1000, "to": 0x1020}]
    }
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.cmd_helper"), \
         patch("r2inspect.modules.bindiff_analyzer.calculate_cyclomatic_complexity", return_value=3):
        result = analyzer._extract_function_features()
        
        assert len(result["cfg_features"]) > 0
        assert result["cfg_features"][0]["complexity"] == 3


def test_extract_string_features_with_duplicates():
    """Test _extract_string_features with duplicate strings."""
    adapter = Mock()
    adapter.get_strings.return_value = [
        {"string": "test"},
        {"string": "test"},
        {"string": "other"}
    ]
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.is_api_string", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.is_path_string", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.is_url_string", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.is_registry_string", return_value=False):
        result = analyzer._extract_string_features()
        
        assert result["total_strings"] == 3
        assert result["unique_strings"] == 2


def test_extract_string_features_categorized():
    """Test _extract_string_features categorized strings dict."""
    adapter = Mock()
    adapter.get_strings.return_value = [
        {"string": "api1"},
        {"string": "path1"}
    ]
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.is_api_string", side_effect=lambda s: "api" in s), \
         patch("r2inspect.modules.bindiff_analyzer.is_path_string", side_effect=lambda s: "path" in s), \
         patch("r2inspect.modules.bindiff_analyzer.is_url_string", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.is_registry_string", return_value=False):
        result = analyzer._extract_string_features()
        
        assert "categorized_strings" in result
        assert result["categorized_strings"]["API"] == 1
        assert result["categorized_strings"]["Paths"] == 1


def test_extract_byte_features_rolling_hash_exception():
    """Test _extract_byte_features when rolling hash calculation fails."""
    adapter = Mock()
    adapter.get_entropy_pattern = Mock(return_value="entropy")
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.default_file_system.read_bytes", side_effect=Exception("Read error")):
        result = analyzer._extract_byte_features()
        
        assert "entropy_pattern" in result
        assert "rolling_hash" not in result


def test_extract_structural_features_section_names_sorted():
    """Test _extract_structural_features sorts section names."""
    adapter = Mock()
    adapter.get_file_info.return_value = {}
    adapter.get_sections.return_value = [
        {"name": ".text"},
        {"name": ".data"},
        {"name": ".bss"}
    ]
    adapter.get_imports.return_value = []
    adapter.get_exports.return_value = []
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_structural_features()
    
    assert result["section_names"] == [".bss", ".data", ".text"]


def test_extract_structural_features_imported_dlls_unique():
    """Test _extract_structural_features unique DLL list."""
    adapter = Mock()
    adapter.get_file_info.return_value = {}
    adapter.get_sections.return_value = []
    adapter.get_imports.return_value = [
        {"libname": "kernel32.dll", "name": "CreateFileA"},
        {"libname": "kernel32.dll", "name": "WriteFile"},
        {"libname": "user32.dll", "name": "MessageBoxA"}
    ]
    adapter.get_exports.return_value = []
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_structural_features()
    
    assert len(result["imported_dlls"]) == 2
    assert "kernel32.dll" in result["imported_dlls"]
    assert "user32.dll" in result["imported_dlls"]


def test_compare_with_full_integration():
    """Test compare_with with full feature extraction."""
    adapter1 = Mock()
    adapter1.get_file_info.return_value = {"core": {"format": "pe"}, "bin": {"arch": "x86"}}
    adapter1.get_sections.return_value = [{"name": ".text", "size": 5000, "perm": "r-x"}]
    adapter1.get_imports.return_value = [{"libname": "kernel32.dll", "name": "CreateFileA"}]
    adapter1.get_exports.return_value = []
    adapter1.get_functions.return_value = [{"name": "main", "size": 200, "offset": 0x1000}]
    adapter1.get_strings.return_value = [{"string": "test"}]
    adapter1.get_cfg.return_value = {}
    
    analyzer1 = BinDiffAnalyzer(adapter1, "/test/file1.exe")
    
    adapter2 = Mock()
    adapter2.get_file_info.return_value = {"core": {"format": "pe"}, "bin": {"arch": "x86"}}
    adapter2.get_sections.return_value = [{"name": ".text", "size": 5000, "perm": "r-x"}]
    adapter2.get_imports.return_value = [{"libname": "kernel32.dll", "name": "CreateFileA"}]
    adapter2.get_exports.return_value = []
    adapter2.get_functions.return_value = [{"name": "main", "size": 200, "offset": 0x1000}]
    adapter2.get_strings.return_value = [{"string": "test"}]
    adapter2.get_cfg.return_value = {}
    
    analyzer2 = BinDiffAnalyzer(adapter2, "/test/file2.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.cmd_helper"), \
         patch("r2inspect.modules.bindiff_analyzer.default_file_system.read_bytes", return_value=b"data"), \
         patch("r2inspect.modules.bindiff_analyzer.calculate_rolling_hash", return_value="hash"), \
         patch("r2inspect.modules.bindiff_analyzer.is_api_string", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.is_path_string", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.is_url_string", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.is_registry_string", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.has_crypto_indicators", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.has_network_indicators", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.has_persistence_indicators", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.is_suspicious_api", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.is_crypto_api", return_value=False), \
         patch("r2inspect.modules.bindiff_analyzer.is_network_api", return_value=False):
        
        other_results = analyzer2.analyze()
        
        with patch("r2inspect.modules.bindiff_analyzer.compare_structural_features", return_value=1.0), \
             patch("r2inspect.modules.bindiff_analyzer.compare_function_features", return_value=1.0), \
             patch("r2inspect.modules.bindiff_analyzer.compare_string_features", return_value=1.0), \
             patch("r2inspect.modules.bindiff_analyzer.compare_byte_features", return_value=1.0), \
             patch("r2inspect.modules.bindiff_analyzer.compare_behavioral_features", return_value=1.0), \
             patch("r2inspect.modules.bindiff_analyzer.calculate_overall_similarity", return_value=1.0), \
             patch("r2inspect.modules.bindiff_analyzer.categorize_similarity", return_value="Identical"):
            result = analyzer1.compare_with(other_results)
            
            assert result["overall_similarity"] == 1.0
            assert result["similarity_level"] == "Identical"
