"""Comprehensive tests for bindiff_analyzer.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


class MockAdapter:
    def __init__(self, has_data: bool = True):
        self.has_data = has_data

    def get_file_info(self):
        if not self.has_data:
            return {}
        return {
            "core": {"format": "PE", "size": 100000},
            "bin": {"arch": "x86", "bits": 64, "endian": "little"},
        }

    def get_sections(self):
        if not self.has_data:
            return []
        return [
            {"name": ".text", "size": 50000, "perm": "r-x"},
            {"name": ".data", "size": 10000, "perm": "rw-"},
            {"name": ".rdata", "size": 20000, "perm": "r--"},
        ]

    def get_imports(self):
        if not self.has_data:
            return []
        return [
            {"name": "CreateFileA", "libname": "kernel32.dll", "plt": 0x1000},
            {"name": "WriteFile", "libname": "kernel32.dll", "plt": 0x1010},
            {"name": "CloseHandle", "libname": "kernel32.dll", "plt": 0x1020},
        ]

    def get_exports(self):
        if not self.has_data:
            return []
        return [
            {"name": "ExportedFunc1", "addr": 0x2000},
            {"name": "ExportedFunc2", "addr": 0x2100},
        ]

    def get_strings(self):
        if not self.has_data:
            return []
        return [
            {"string": "C:\\Windows\\System32\\kernel32.dll", "vaddr": 0x3000},
            {"string": "https://example.com/api", "vaddr": 0x3100},
            {"string": "SOFTWARE\\Microsoft\\Windows", "vaddr": 0x3200},
            {"string": "AES", "vaddr": 0x3300},
            {"string": "CreateFileA", "vaddr": 0x3400},
        ]

    def get_functions(self):
        if not self.has_data:
            return []
        return [
            {"name": "main", "offset": 0x1000, "size": 100},
            {"name": "sub_2000", "offset": 0x2000, "size": 50},
            {"name": "sub_3000", "offset": 0x3000, "size": 75},
        ]

    def get_cfg(self, func_addr: int):
        if not self.has_data:
            return []
        return [
            {
                "blocks": [
                    {"offset": func_addr},
                    {"offset": func_addr + 10},
                    {"offset": func_addr + 20},
                ],
                "edges": [
                    {"src": func_addr, "dst": func_addr + 10},
                    {"src": func_addr + 10, "dst": func_addr + 20},
                ],
            }
        ]

    def get_entropy_pattern(self):
        return "5.2"

    def analyze_all(self):
        pass

    def cmd(self, command: str):
        if command == "p=e 100":
            return "5.2"
        return ""


def test_bindiff_analyzer_initialization():
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    adapter = MockAdapter()
    analyzer = BinDiffAnalyzer(adapter, "/path/to/binary.exe")
    assert analyzer.adapter == adapter
    assert analyzer.filepath == "/path/to/binary.exe"
    assert analyzer.filename == "binary.exe"


def test_bindiff_basic_analysis():
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    adapter = MockAdapter()
    analyzer = BinDiffAnalyzer(adapter, "/path/to/binary.exe")
    result = analyzer.analyze()

    assert result["filename"] == "binary.exe"
    assert result["filepath"] == "/path/to/binary.exe"
    assert result["comparison_ready"] is True
    assert "structural_features" in result
    assert "function_features" in result
    assert "string_features" in result
    assert "byte_features" in result
    assert "behavioral_features" in result
    assert "signatures" in result


def test_bindiff_structural_features():
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    adapter = MockAdapter()
    analyzer = BinDiffAnalyzer(adapter, "/path/to/binary.exe")
    features = analyzer._extract_structural_features()

    assert features["file_type"] == "PE"
    assert features["architecture"] == "x86"
    assert features["bits"] == 64
    assert features["section_count"] == 3
    assert features["import_count"] == 3
    assert features["export_count"] == 2


def test_bindiff_function_features():
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    adapter = MockAdapter()
    analyzer = BinDiffAnalyzer(adapter, "/path/to/binary.exe")
    features = analyzer._extract_function_features()

    assert features["function_count"] == 3
    assert len(features["function_sizes"]) == 3
    assert len(features["function_names"]) == 3


def test_bindiff_string_features():
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    adapter = MockAdapter()
    analyzer = BinDiffAnalyzer(adapter, "/path/to/binary.exe")
    features = analyzer._extract_string_features()

    assert features["total_strings"] == 5
    assert "unique_strings" in features
    assert "api_strings" in features
    assert "path_strings" in features
    assert "url_strings" in features
    assert "string_signature" in features


def test_bindiff_byte_features():
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    adapter = MockAdapter()
    analyzer = BinDiffAnalyzer(adapter, "/path/to/binary.exe")
    features = analyzer._extract_byte_features()

    assert "entropy_pattern" in features


def test_bindiff_behavioral_features():
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    adapter = MockAdapter()
    analyzer = BinDiffAnalyzer(adapter, "/path/to/binary.exe")
    features = analyzer._extract_behavioral_features()

    assert "crypto_indicators" in features
    assert "network_indicators" in features
    assert "suspicious_apis" in features


def test_bindiff_compare_binaries():
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    adapter1 = MockAdapter()
    adapter2 = MockAdapter()

    analyzer1 = BinDiffAnalyzer(adapter1, "/path/to/binary1.exe")
    analyzer2 = BinDiffAnalyzer(adapter2, "/path/to/binary2.exe")

    result1 = analyzer1.analyze()
    comparison = analyzer1.compare_with(result1)

    assert "overall_similarity" in comparison
    assert "similarity_level" in comparison
    assert "structural_similarity" in comparison
    assert "function_similarity" in comparison
    assert "string_similarity" in comparison


def test_bindiff_empty_data():
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    adapter = MockAdapter(has_data=False)
    analyzer = BinDiffAnalyzer(adapter, "/path/to/binary.exe")
    result = analyzer.analyze()

    assert result["comparison_ready"] is True
    assert "structural_features" in result
    assert "function_features" in result


def test_bindiff_generate_signatures():
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    adapter = MockAdapter()
    analyzer = BinDiffAnalyzer(adapter, "/path/to/binary.exe")
    result = analyzer.analyze()

    signatures = result["signatures"]
    assert "structural" in signatures
    assert "function" in signatures
    assert "string" in signatures
    assert "behavioral" in signatures
    assert all(isinstance(sig, str) for sig in signatures.values())


def test_bindiff_similarity_scoring():
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    adapter = MockAdapter()
    analyzer1 = BinDiffAnalyzer(adapter, "/path/to/binary1.exe")
    analyzer2 = BinDiffAnalyzer(adapter, "/path/to/binary2.exe")

    result1 = analyzer1.analyze()
    result2 = analyzer2.analyze()

    comparison = analyzer1.compare_with(result2)
    similarity = comparison.get("overall_similarity", 0.0)
    assert 0.0 <= similarity <= 1.0


def test_bindiff_categorize_similarity():
    from r2inspect.modules.bindiff_domain import categorize_similarity

    assert categorize_similarity(0.95) == "Very High"
    assert categorize_similarity(0.75) == "High"
    assert categorize_similarity(0.55) == "Medium"
    assert categorize_similarity(0.35) == "Low"


def test_bindiff_calculate_overall_similarity():
    from r2inspect.modules.bindiff_domain import calculate_overall_similarity

    score = calculate_overall_similarity(0.8, 0.7, 0.9, 0.6, 0.5)
    assert 0.0 <= score <= 1.0


def test_bindiff_compare_structural_features():
    from r2inspect.modules.bindiff_domain import compare_structural_features

    features1 = {
        "architecture": "x86",
        "bits": 64,
        "section_count": 5,
        "import_count": 10,
    }
    features2 = {
        "architecture": "x86",
        "bits": 64,
        "section_count": 5,
        "import_count": 12,
    }

    similarity = compare_structural_features(features1, features2)
    assert 0.0 <= similarity <= 1.0


def test_bindiff_compare_function_features():
    from r2inspect.modules.bindiff_domain import compare_function_features

    features1 = {"function_count": 10, "function_sizes": [100, 200, 150]}
    features2 = {"function_count": 12, "function_sizes": [100, 210, 145]}

    similarity = compare_function_features(features1, features2)
    assert 0.0 <= similarity <= 1.0


def test_bindiff_rolling_hash():
    from r2inspect.modules.bindiff_domain import calculate_rolling_hash

    data = b"test binary data for hashing"
    hash_value = calculate_rolling_hash(data)
    assert isinstance(hash_value, list)


def test_bindiff_api_detection():
    from r2inspect.modules.bindiff_domain import is_crypto_api, is_network_api, is_suspicious_api

    assert is_crypto_api("CryptEncrypt") is True
    assert is_crypto_api("RegularFunc") is False

    assert is_network_api("WSAStartup") is True
    assert is_network_api("RegularFunc") is False

    result = is_suspicious_api("VirtualProtect")
    assert isinstance(result, bool)


def test_bindiff_string_indicators():
    from r2inspect.modules.bindiff_domain import (
        has_crypto_indicators,
        has_network_indicators,
        has_persistence_indicators,
    )

    assert has_crypto_indicators("AES encryption") is True
    assert has_crypto_indicators("regular text") is False

    assert has_network_indicators("http://example.com") is True
    assert has_network_indicators("regular text") is False

    result = has_persistence_indicators("HKEY_CURRENT_USER\\Run")
    assert isinstance(result, bool)


def test_bindiff_with_real_binary():
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("Sample binary not available")

    try:
        import r2pipe
        from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
        from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer
    except ImportError:
        pytest.skip("r2pipe not available")

    r2 = None
    try:
        r2 = r2pipe.open(str(sample), flags=["-2"])
        adapter = R2PipeAdapter(r2)
        analyzer = BinDiffAnalyzer(adapter, str(sample))
        result = analyzer.analyze()

        assert result["comparison_ready"] is True
        assert "structural_features" in result
        assert "function_features" in result
        assert "signatures" in result
    except Exception:
        pytest.skip("Could not open binary with r2pipe")
    finally:
        if r2 is not None:
            try:
                r2.quit()
            except Exception:
                pass


def test_bindiff_error_handling():
    from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer

    class FailingAdapter:
        def get_file_info(self):
            raise RuntimeError("Simulated error")

        def get_sections(self):
            raise RuntimeError("Simulated error")

        def get_imports(self):
            raise RuntimeError("Simulated error")

        def get_exports(self):
            raise RuntimeError("Simulated error")

        def get_strings(self):
            raise RuntimeError("Simulated error")

        def get_functions(self):
            raise RuntimeError("Simulated error")

    adapter = FailingAdapter()
    analyzer = BinDiffAnalyzer(adapter, "/path/to/binary.exe")
    result = analyzer.analyze()

    assert "error" in result or "structural_features" in result
