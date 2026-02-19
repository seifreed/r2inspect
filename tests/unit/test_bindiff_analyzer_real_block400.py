"""Comprehensive tests for bindiff analyzer - targeting 12% -> 100% coverage"""
import pytest
from pathlib import Path
from unittest.mock import Mock

from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer


class MockAdapter:
    def __init__(self, responses=None):
        self.responses = responses or {}
    
    def get_file_info(self):
        return self.responses.get("file_info", {})
    
    def get_sections(self):
        return self.responses.get("sections", [])
    
    def get_imports(self):
        return self.responses.get("imports", [])
    
    def get_exports(self):
        return self.responses.get("exports", [])
    
    def get_functions(self):
        return self.responses.get("functions", [])
    
    def get_strings(self):
        return self.responses.get("strings", [])
    
    def get_cfg(self, addr):
        return self.responses.get(f"cfg_{addr}", {})
    
    def analyze_all(self):
        pass


def test_bindiff_basic_analysis(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"MZ" + b"\x00" * 100)
    
    adapter = MockAdapter({
        "file_info": {
            "core": {"format": "PE32", "size": 1000},
            "bin": {"arch": "x86", "bits": 32, "endian": "little"}
        }
    })
    
    analyzer = BinDiffAnalyzer(adapter, str(test_file))
    result = analyzer.analyze()
    
    assert result["filename"] == "test.bin"
    assert result["comparison_ready"] is True
    assert "structural_features" in result


def test_bindiff_structural_features(tmp_path):
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 100)
    
    adapter = MockAdapter({
        "file_info": {
            "core": {"format": "PE32", "size": 5000},
            "bin": {"arch": "x86", "bits": 32, "endian": "little"}
        },
        "sections": [
            {"name": ".text", "size": 1000, "perm": "--x"},
            {"name": ".data", "size": 500, "perm": "-rw"},
        ],
        "imports": [
            {"libname": "kernel32.dll", "name": "CreateFile"},
            {"libname": "user32.dll", "name": "MessageBoxA"},
        ],
        "exports": [
            {"name": "ExportedFunc1"},
        ]
    })
    
    analyzer = BinDiffAnalyzer(adapter, str(test_file))
    result = analyzer.analyze()
    
    struct = result["structural_features"]
    assert struct["file_type"] == "PE32"
    assert struct["architecture"] == "x86"
    assert struct["bits"] == 32
    assert struct["section_count"] == 2
    assert struct["import_count"] == 2
    assert struct["export_count"] == 1


def test_bindiff_function_features(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = MockAdapter({
        "file_info": {"core": {}, "bin": {}},
        "functions": [
            {"offset": 0x1000, "name": "func1", "size": 100},
            {"offset": 0x2000, "name": "func2", "size": 200},
        ]
    })
    
    analyzer = BinDiffAnalyzer(adapter, str(test_file))
    result = analyzer.analyze()
    
    func_features = result["function_features"]
    assert func_features["function_count"] == 2
    assert 100 in func_features["function_sizes"]
    assert 200 in func_features["function_sizes"]


def test_bindiff_string_features(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = MockAdapter({
        "file_info": {"core": {}, "bin": {}},
        "strings": [
            {"string": "Hello World"},
            {"string": "C:\\Windows\\System32"},
            {"string": "http://example.com"},
        ]
    })
    
    analyzer = BinDiffAnalyzer(adapter, str(test_file))
    result = analyzer.analyze()
    
    str_features = result["string_features"]
    assert str_features["total_strings"] == 3
    assert "string_signature" in str_features


def test_bindiff_comparison(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = MockAdapter({
        "file_info": {
            "core": {"format": "PE32", "size": 1000},
            "bin": {"arch": "x86", "bits": 32}
        },
        "sections": [{"name": ".text", "size": 500, "perm": "--x"}],
        "imports": [{"libname": "kernel32.dll", "name": "CreateFile"}],
        "functions": [{"offset": 0x1000, "size": 100}],
        "strings": [{"string": "test"}],
    })
    
    analyzer = BinDiffAnalyzer(adapter, str(test_file))
    
    other_results = {
        "filename": "other.bin",
        "comparison_ready": True,
        "structural_features": {
            "file_type": "PE32",
            "architecture": "x86",
            "bits": 32,
            "section_count": 1,
            "import_count": 1,
        },
        "function_features": {"function_count": 1, "function_sizes": [100]},
        "string_features": {"total_strings": 1, "unique_strings": 1},
        "byte_features": {},
        "behavioral_features": {},
    }
    
    comparison = analyzer.compare_with(other_results)
    assert "overall_similarity" in comparison
    assert "similarity_level" in comparison


def test_bindiff_error_handling(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = MockAdapter()
    adapter.get_file_info = Mock(side_effect=Exception("Test error"))
    
    analyzer = BinDiffAnalyzer(adapter, str(test_file))
    result = analyzer.analyze()
    
    assert "error" in result
    assert result["comparison_ready"] is False


def test_bindiff_cfg_features(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = MockAdapter({
        "file_info": {"core": {}, "bin": {}},
        "functions": [
            {"offset": 0x1000, "name": "func1", "size": 100},
        ],
        "cfg_0x1000": {
            "blocks": [1, 2, 3],
            "edges": [[0, 1], [1, 2]]
        }
    })
    
    analyzer = BinDiffAnalyzer(adapter, str(test_file))
    result = analyzer.analyze()
    
    func_features = result["function_features"]
    assert "cfg_features" in func_features


def test_bindiff_behavioral_features(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = MockAdapter({
        "file_info": {"core": {}, "bin": {}},
        "strings": [
            {"string": "CryptEncrypt"},
            {"string": "socket"},
            {"string": "RegSetValueEx"},
        ],
        "imports": [
            {"name": "VirtualAlloc"},
            {"name": "CreateRemoteThread"},
        ]
    })
    
    analyzer = BinDiffAnalyzer(adapter, str(test_file))
    result = analyzer.analyze()
    
    behav = result["behavioral_features"]
    assert "suspicious_apis" in behav or "crypto_indicators" in behav


def test_bindiff_signatures(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = MockAdapter({
        "file_info": {
            "core": {"format": "PE32"},
            "bin": {"arch": "x86", "bits": 32}
        },
        "sections": [{"name": ".text"}],
        "functions": [{"offset": 0x1000}],
        "strings": [{"string": "test"}],
    })
    
    analyzer = BinDiffAnalyzer(adapter, str(test_file))
    result = analyzer.analyze()
    
    sigs = result["signatures"]
    assert "structural" in sigs
    assert "function" in sigs
    assert "string" in sigs
    assert "behavioral" in sigs


def test_bindiff_comparison_not_ready(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    adapter = MockAdapter({"file_info": {"core": {}, "bin": {}}})
    analyzer = BinDiffAnalyzer(adapter, str(test_file))
    
    other_results = {"comparison_ready": False}
    comparison = analyzer.compare_with(other_results)
    
    assert "error" in comparison
    assert comparison["similarity_score"] == 0.0
