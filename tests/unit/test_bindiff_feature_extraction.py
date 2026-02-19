"""Comprehensive tests for bindiff_analyzer.py - feature extraction."""

import hashlib
from pathlib import Path
from unittest.mock import Mock, patch

from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

SAMPLES_DIR = Path(__file__).parent.parent.parent / "samples" / "fixtures"


def test_init():
    """Test BinDiffAnalyzer initialization."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    assert analyzer.adapter is adapter
    assert analyzer.r2 is adapter
    assert analyzer.filepath == "/test/file.exe"
    assert analyzer.filename == "file.exe"


def test_analyze_success():
    """Test analyze method with success."""
    adapter = Mock()
    adapter.get_file_info.return_value = {"core": {"format": "pe"}, "bin": {"arch": "x86"}}
    adapter.get_sections.return_value = []
    adapter.get_imports.return_value = []
    adapter.get_exports.return_value = []
    adapter.get_functions.return_value = []
    adapter.get_strings.return_value = []
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch.object(analyzer, "_extract_structural_features", return_value={}), \
         patch.object(analyzer, "_extract_function_features", return_value={}), \
         patch.object(analyzer, "_extract_string_features", return_value={}), \
         patch.object(analyzer, "_extract_byte_features", return_value={}), \
         patch.object(analyzer, "_extract_behavioral_features", return_value={}), \
         patch.object(analyzer, "_generate_comparison_signatures", return_value={}):
        result = analyzer.analyze()
        
        assert result["filename"] == "file.exe"
        assert result["comparison_ready"] is True
        assert "structural_features" in result
        assert "function_features" in result
        assert "signatures" in result


def test_analyze_exception():
    """Test analyze method with exception."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch.object(analyzer, "_extract_structural_features", side_effect=Exception("Test error")):
        result = analyzer.analyze()
        
        assert result["comparison_ready"] is False
        assert "error" in result
        assert "Test error" in result["error"]


def test_extract_structural_features_success():
    """Test _extract_structural_features with complete data."""
    adapter = Mock()
    adapter.get_file_info.return_value = {
        "core": {"format": "pe", "size": 100000},
        "bin": {"arch": "x86", "bits": 32, "endian": "little"}
    }
    adapter.get_sections.return_value = [
        {"name": ".text", "size": 5000, "perm": "r-x"},
        {"name": ".data", "size": 2000, "perm": "rw-"}
    ]
    adapter.get_imports.return_value = [
        {"libname": "kernel32.dll", "name": "CreateFileA"},
        {"libname": "kernel32.dll", "name": "WriteFile"}
    ]
    adapter.get_exports.return_value = [
        {"name": "ExportedFunc"}
    ]
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_structural_features()
    
    assert result["file_type"] == "pe"
    assert result["architecture"] == "x86"
    assert result["bits"] == 32
    assert result["file_size"] == 100000
    assert result["section_count"] == 2
    assert ".text" in result["section_names"]
    assert result["executable_sections"] == 1
    assert result["writable_sections"] == 1
    assert result["import_count"] == 2
    assert result["export_count"] == 1


def test_extract_structural_features_empty():
    """Test _extract_structural_features with empty data."""
    adapter = Mock()
    adapter.get_file_info.return_value = {}
    adapter.get_sections.return_value = []
    adapter.get_imports.return_value = []
    adapter.get_exports.return_value = []
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_structural_features()
    
    assert isinstance(result, dict)


def test_extract_structural_features_exception():
    """Test _extract_structural_features with exception."""
    adapter = Mock()
    adapter.get_file_info.side_effect = Exception("Error")
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_structural_features()
    
    assert isinstance(result, dict)


def test_extract_function_features_success():
    """Test _extract_function_features with success."""
    adapter = Mock()
    adapter.get_functions.return_value = [
        {"name": "main", "size": 200, "offset": 0x1000},
        {"name": "helper", "size": 100, "offset": 0x2000}
    ]
    adapter.get_cfg.return_value = [{
        "blocks": [{"addr": 0x1000}, {"addr": 0x1010}],
        "edges": [{"from": 0x1000, "to": 0x1010}]
    }]
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.cmd_helper"):
        result = analyzer._extract_function_features()
        
        assert result["function_count"] == 2
        assert len(result["function_sizes"]) == 2
        assert "main" in result["function_names"]


def test_extract_function_features_with_analyze_all():
    """Test _extract_function_features using analyze_all."""
    adapter = Mock()
    adapter.analyze_all = Mock()
    adapter.get_functions.return_value = []
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_function_features()
    
    adapter.analyze_all.assert_called_once()


def test_extract_function_features_cfg_dict():
    """Test _extract_function_features with CFG as dict."""
    adapter = Mock()
    adapter.get_functions.return_value = [
        {"name": "main", "size": 200, "offset": 0x1000}
    ]
    adapter.get_cfg.return_value = {
        "blocks": [{"addr": 0x1000}, {"addr": 0x1010}],
        "edges": [{"from": 0x1000, "to": 0x1010}]
    }
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.cmd_helper"):
        result = analyzer._extract_function_features()
        
        assert "cfg_features" in result


def test_extract_function_features_exception():
    """Test _extract_function_features with exception."""
    adapter = Mock()
    adapter.get_functions.side_effect = Exception("Error")
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_function_features()
    
    assert isinstance(result, dict)


def test_extract_string_features_success():
    """Test _extract_string_features with success."""
    adapter = Mock()
    adapter.get_strings.return_value = [
        {"string": "CreateFileA"},
        {"string": "C:\\Windows\\System32"},
        {"string": "http://example.com"},
        {"string": "HKLM\\Software\\Test"}
    ]
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.is_api_string", side_effect=lambda s: s == "CreateFileA"), \
         patch("r2inspect.modules.bindiff_analyzer.is_path_string", side_effect=lambda s: "Windows" in s), \
         patch("r2inspect.modules.bindiff_analyzer.is_url_string", side_effect=lambda s: "http" in s), \
         patch("r2inspect.modules.bindiff_analyzer.is_registry_string", side_effect=lambda s: "HKLM" in s):
        result = analyzer._extract_string_features()
        
        assert result["total_strings"] == 4
        assert result["unique_strings"] == 4
        assert len(result["api_strings"]) == 1
        assert len(result["path_strings"]) == 1
        assert len(result["url_strings"]) == 1
        assert len(result["registry_strings"]) == 1
        assert "string_signature" in result


def test_extract_string_features_empty():
    """Test _extract_string_features with empty strings."""
    adapter = Mock()
    adapter.get_strings.return_value = []
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_string_features()
    
    assert isinstance(result, dict)


def test_extract_string_features_exception():
    """Test _extract_string_features with exception."""
    adapter = Mock()
    adapter.get_strings.side_effect = Exception("Error")
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_string_features()
    
    assert isinstance(result, dict)


def test_extract_byte_features_success():
    """Test _extract_byte_features with success."""
    adapter = Mock()
    adapter.get_entropy_pattern = Mock(return_value="entropy_data")
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.default_file_system.read_bytes", return_value=b"test data"):
        result = analyzer._extract_byte_features()
        
        assert "entropy_pattern" in result
        assert "rolling_hash" in result


def test_extract_byte_features_cmd_helper():
    """Test _extract_byte_features using cmd_helper."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.cmd_helper", return_value="entropy_output"):
        result = analyzer._extract_byte_features()
        
        assert "entropy_pattern" in result


def test_extract_byte_features_exception():
    """Test _extract_byte_features with exception."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.cmd_helper", side_effect=Exception("Error")):
        result = analyzer._extract_byte_features()
        
        assert isinstance(result, dict)


def test_extract_behavioral_features_success():
    """Test _extract_behavioral_features with success."""
    adapter = Mock()
    adapter.get_strings.return_value = [
        {"string": "aes"},
        {"string": "http://"},
        {"string": "autorun"}
    ]
    adapter.get_imports.return_value = [
        {"name": "VirtualAlloc"},
        {"name": "CryptEncrypt"},
        {"name": "connect"}
    ]
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    with patch("r2inspect.modules.bindiff_analyzer.has_crypto_indicators", side_effect=lambda s: "aes" in s.lower()), \
         patch("r2inspect.modules.bindiff_analyzer.has_network_indicators", side_effect=lambda s: "http" in s.lower()), \
         patch("r2inspect.modules.bindiff_analyzer.has_persistence_indicators", side_effect=lambda s: "autorun" in s.lower()), \
         patch("r2inspect.modules.bindiff_analyzer.is_suspicious_api", side_effect=lambda s: "VirtualAlloc" in s), \
         patch("r2inspect.modules.bindiff_analyzer.is_crypto_api", side_effect=lambda s: "Crypt" in s), \
         patch("r2inspect.modules.bindiff_analyzer.is_network_api", side_effect=lambda s: "connect" in s):
        result = analyzer._extract_behavioral_features()
        
        assert result["crypto_indicators"] == 1
        assert result["network_indicators"] == 1
        assert result["persistence_indicators"] == 1
        assert result["suspicious_apis"] == 1
        assert result["crypto_apis"] == 1
        assert result["network_apis"] == 1


def test_extract_behavioral_features_empty():
    """Test _extract_behavioral_features with empty data."""
    adapter = Mock()
    adapter.get_strings.return_value = []
    adapter.get_imports.return_value = []
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_behavioral_features()
    
    assert isinstance(result, dict)


def test_extract_behavioral_features_exception():
    """Test _extract_behavioral_features with exception."""
    adapter = Mock()
    adapter.get_strings.side_effect = Exception("Error")
    
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_behavioral_features()
    
    assert isinstance(result, dict)


def test_generate_comparison_signatures():
    """Test _generate_comparison_signatures."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    results = {
        "structural_features": {"file_type": "pe"},
        "function_features": {"function_count": 10},
        "string_features": {"total_strings": 50},
        "behavioral_features": {"crypto_apis": 2}
    }
    
    with patch("r2inspect.modules.bindiff_analyzer.build_struct_signature", return_value="struct_data"), \
         patch("r2inspect.modules.bindiff_analyzer.build_function_signature", return_value="func_data"), \
         patch("r2inspect.modules.bindiff_analyzer.build_string_signature", return_value="string_data"), \
         patch("r2inspect.modules.bindiff_analyzer.build_behavioral_signature", return_value="behav_data"):
        signatures = analyzer._generate_comparison_signatures(results)
        
        assert "structural" in signatures
        assert "function" in signatures
        assert "string" in signatures
        assert "behavioral" in signatures
        assert all(isinstance(v, str) for v in signatures.values())


def test_generate_comparison_signatures_exception():
    """Test _generate_comparison_signatures with exception."""
    adapter = Mock()
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    
    results = {}
    
    with patch("r2inspect.modules.bindiff_analyzer.build_struct_signature", side_effect=Exception("Error")):
        signatures = analyzer._generate_comparison_signatures(results)
        
        assert isinstance(signatures, dict)
