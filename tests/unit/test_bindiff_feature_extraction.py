"""Comprehensive tests for bindiff_analyzer.py - feature extraction.

All tests use real objects (FakeR2 + R2PipeAdapter) instead of mocks.
Domain functions are tested directly with real data.
"""

import hashlib
import os
import tempfile
from pathlib import Path

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer
from r2inspect.modules.bindiff_domain import (
    build_behavioral_signature,
    build_function_signature,
    build_string_signature,
    build_struct_signature,
    calculate_cyclomatic_complexity,
    calculate_rolling_hash,
    categorize_similarity,
    has_crypto_indicators,
    has_network_indicators,
    has_persistence_indicators,
    is_crypto_api,
    is_network_api,
    is_suspicious_api,
)
from r2inspect.modules.string_classification import (
    is_api_string,
    is_path_string,
    is_registry_string,
    is_url_string,
)

SAMPLES_DIR = Path(__file__).parent.parent.parent / "samples" / "fixtures"


# ---------------------------------------------------------------------------
# FakeR2 + helpers
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe stand-in that returns pre-configured responses."""

    def __init__(self, cmdj_map=None, cmd_map=None):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command):
        return self.cmdj_map.get(command, {})

    def cmd(self, command):
        return self.cmd_map.get(command, "")


def _make_adapter(cmdj_map=None, cmd_map=None):
    """Build a real R2PipeAdapter backed by a FakeR2."""
    return R2PipeAdapter(FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map))


def _make_analyzer(filepath="/test/file.exe", cmdj_map=None, cmd_map=None):
    """Build a BinDiffAnalyzer with a real adapter."""
    adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return BinDiffAnalyzer(adapter, filepath)


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


def test_init():
    """Test BinDiffAnalyzer initialization."""
    analyzer = _make_analyzer("/test/file.exe")

    assert analyzer.adapter is not None
    assert analyzer.r2 is analyzer.adapter
    assert analyzer.filepath == "/test/file.exe"
    assert analyzer.filename == "file.exe"


# ---------------------------------------------------------------------------
# Full analyze() flow
# ---------------------------------------------------------------------------


def test_analyze_success():
    """Test analyze method with a fully wired FakeR2 adapter."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        tmp.write(b"\x00" * 256)
        tmp_path = tmp.name

    try:
        cmdj_map = {
            "ij": {
                "core": {"format": "pe", "size": 256},
                "bin": {"arch": "x86", "bits": 32, "endian": "little"},
            },
            "iSj": [{"name": ".text", "size": 200, "perm": "r-x"}],
            "iij": [{"libname": "kernel32.dll", "name": "CreateFileA"}],
            "iEj": [{"name": "DllMain"}],
            "aflj": [{"name": "main", "size": 100, "offset": 0x1000}],
            "izzj": [{"string": "CreateFileA"}, {"string": "hello"}],
            "agj @ 0x1000": [{"blocks": [{"addr": 0x1000}], "edges": []}],
        }
        cmd_map = {
            "aaa": "",
            "p=e 100": "0.5 0.6 0.7",
        }
        analyzer = _make_analyzer(tmp_path, cmdj_map=cmdj_map, cmd_map=cmd_map)
        result = analyzer.analyze()

        assert result["filename"] == Path(tmp_path).name
        assert result["comparison_ready"] is True
        assert "structural_features" in result
        assert "function_features" in result
        assert "string_features" in result
        assert "byte_features" in result
        assert "behavioral_features" in result
        assert "signatures" in result
    finally:
        os.unlink(tmp_path)


def test_analyze_exception():
    """Test analyze method when structural extraction raises via bad adapter data.

    The error handler in build_analysis catches per-feature errors gracefully,
    so we force a top-level error by using a filepath that triggers an error
    inside _extract_byte_features (file not found) while still getting a result.
    With no valid data from any adapter method, the result should still be valid.
    """
    # Use a cmdj_map where ij raises to trigger the outer except in analyze()
    fake_r2 = FakeR2()

    # Override cmdj to always raise
    def _cmdj_raise(command):
        raise RuntimeError("Simulated r2 crash")

    fake_r2.cmdj = _cmdj_raise
    fake_r2.cmd = lambda c: ""

    adapter = R2PipeAdapter(fake_r2)
    analyzer = BinDiffAnalyzer(adapter, "/nonexistent/file.exe")

    # The per-feature extractors catch exceptions internally and return {},
    # so analyze() should still succeed with comparison_ready=True.
    # But _extract_byte_features -> _read_file_head will fail on the
    # nonexistent file; that's caught internally too.
    result = analyzer.analyze()
    # The result should be a dict in either case
    assert isinstance(result, dict)
    assert "filename" in result


# ---------------------------------------------------------------------------
# Structural features
# ---------------------------------------------------------------------------


def test_extract_structural_features_success():
    """Test _extract_structural_features with complete data."""
    cmdj_map = {
        "ij": {
            "core": {"format": "pe", "size": 100000},
            "bin": {"arch": "x86", "bits": 32, "endian": "little"},
        },
        "iSj": [
            {"name": ".text", "size": 5000, "perm": "r-x"},
            {"name": ".data", "size": 2000, "perm": "rw-"},
        ],
        "iij": [
            {"libname": "kernel32.dll", "name": "CreateFileA"},
            {"libname": "kernel32.dll", "name": "WriteFile"},
        ],
        "iEj": [{"name": "ExportedFunc"}],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
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


def test_extract_structural_features_accepts_library_key():
    """Test _extract_structural_features accepts normalized import library field."""
    cmdj_map = {
        "ij": {
            "core": {"format": "pe", "size": 100000},
            "bin": {"arch": "x86", "bits": 32, "endian": "little"},
        },
        "iSj": [],
        "iij": [{"library": "kernel32.dll", "name": "CreateFileA"}],
        "iEj": [],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._extract_structural_features()

    assert result["imported_dlls"] == ["kernel32.dll"]
    assert result["imported_functions"] == ["CreateFileA"]


def test_extract_structural_features_empty():
    """Test _extract_structural_features with empty data."""
    cmdj_map = {"ij": {}, "iSj": [], "iij": [], "iEj": []}
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._extract_structural_features()

    assert isinstance(result, dict)


def test_extract_structural_features_exception():
    """Test _extract_structural_features with exception from adapter."""
    fake_r2 = FakeR2()
    fake_r2.cmdj = lambda c: (_ for _ in ()).throw(RuntimeError("Error"))
    adapter = R2PipeAdapter(fake_r2)
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_structural_features()

    # The method catches exceptions internally and returns whatever it gathered
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Function features
# ---------------------------------------------------------------------------


def test_extract_function_features_success():
    """Test _extract_function_features with functions and CFG."""
    cmdj_map = {
        "aflj": [
            {"name": "main", "size": 200, "offset": 0x1000},
            {"name": "helper", "size": 100, "offset": 0x2000},
        ],
        "agj @ 0x1000": [
            {
                "blocks": [{"addr": 0x1000}, {"addr": 0x1010}],
                "edges": [{"from": 0x1000, "to": 0x1010}],
            }
        ],
        "agj @ 0x2000": [{"blocks": [{"addr": 0x2000}], "edges": []}],
    }
    cmd_map = {"aaa": ""}
    analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)
    result = analyzer._extract_function_features()

    assert result["function_count"] == 2
    assert len(result["function_sizes"]) == 2
    assert "main" in result["function_names"]


def test_extract_function_features_with_analyze_all():
    """Test _extract_function_features calls analyze_all on adapter."""
    cmdj_map = {"aflj": []}
    cmd_map = {"aaa": ""}
    analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)
    # The adapter has analyze_all (from R2PipeTextQueryMixin), so it will be called
    result = analyzer._extract_function_features()

    assert isinstance(result, dict)


def test_extract_function_features_cfg_dict():
    """Test _extract_function_features with CFG returned as dict."""
    cmdj_map = {
        "aflj": [{"name": "main", "size": 200, "offset": 0x1000}],
        # Return a dict (not wrapped in a list) -- the adapter's get_cfg
        # for a specific address normally returns a list, but the extraction
        # code handles both dict and list forms.
        "agj @ 0x1000": {
            "blocks": [{"addr": 0x1000}, {"addr": 0x1010}],
            "edges": [{"from": 0x1000, "to": 0x1010}],
        },
    }
    cmd_map = {"aaa": ""}
    analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)
    result = analyzer._extract_function_features()

    assert "cfg_features" in result


def test_extract_function_features_exception():
    """Test _extract_function_features with exception from adapter."""
    fake_r2 = FakeR2()
    fake_r2.cmdj = lambda c: (_ for _ in ()).throw(RuntimeError("Error"))
    adapter = R2PipeAdapter(fake_r2)
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_function_features()

    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# String features
# ---------------------------------------------------------------------------


def test_extract_string_features_success():
    """Test _extract_string_features with various string categories."""
    cmdj_map = {
        "izzj": [
            {"string": "CreateFileA"},
            {"string": "C:\\Windows\\System32"},
            {"string": "http://example.com"},
            {"string": "HKLM\\Software\\Test"},
        ],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._extract_string_features()

    assert result["total_strings"] == 4
    assert result["unique_strings"] == 4
    # Verify the real classification functions work
    assert len(result["api_strings"]) >= 1  # CreateFileA matches
    assert len(result["path_strings"]) >= 1  # C:\Windows\...
    assert len(result["url_strings"]) >= 1  # http://...
    assert len(result["registry_strings"]) >= 1  # HKLM\...
    assert "string_signature" in result


def test_extract_string_features_empty():
    """Test _extract_string_features with empty strings."""
    cmdj_map = {"izzj": []}
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._extract_string_features()

    assert isinstance(result, dict)


def test_extract_string_features_exception():
    """Test _extract_string_features with exception from adapter."""
    fake_r2 = FakeR2()
    fake_r2.cmdj = lambda c: (_ for _ in ()).throw(RuntimeError("Error"))
    adapter = R2PipeAdapter(fake_r2)
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_string_features()

    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Byte features
# ---------------------------------------------------------------------------


def test_extract_byte_features_success():
    """Test _extract_byte_features with a real temp file."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        tmp.write(b"A" * 8192)
        tmp_path = tmp.name

    try:
        cmd_map = {"p=e 100": "0.5 0.6 0.7"}
        analyzer = _make_analyzer(tmp_path, cmd_map=cmd_map)
        result = analyzer._extract_byte_features()

        assert "entropy_pattern" in result
        assert "rolling_hash" in result
    finally:
        os.unlink(tmp_path)


def test_extract_byte_features_cmd_helper():
    """Test _extract_byte_features falls back to cmd_helper for entropy."""
    cmd_map = {"p=e 100": "entropy_output"}
    analyzer = _make_analyzer("/nonexistent/file.exe", cmd_map=cmd_map)
    result = analyzer._extract_byte_features()

    # Entropy pattern should still be captured from the cmd output
    assert "entropy_pattern" in result


def test_extract_byte_features_exception():
    """Test _extract_byte_features with exception from adapter."""
    fake_r2 = FakeR2()
    fake_r2.cmd = lambda c: (_ for _ in ()).throw(RuntimeError("Error"))
    adapter = R2PipeAdapter(fake_r2)
    analyzer = BinDiffAnalyzer(adapter, "/nonexistent/file.exe")
    result = analyzer._extract_byte_features()

    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Behavioral features
# ---------------------------------------------------------------------------


def test_extract_behavioral_features_success():
    """Test _extract_behavioral_features with indicator-bearing strings and imports."""
    cmdj_map = {
        "izzj": [
            {"string": "aes_encrypt"},
            {"string": "http://malware.c2"},
            {"string": "autorun_startup"},
        ],
        "iij": [
            {"name": "VirtualAllocEx"},
            {"name": "CryptEncrypt"},
            {"name": "connect"},
        ],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._extract_behavioral_features()

    # Verify real indicator functions detect these
    assert result["crypto_indicators"] >= 1  # "aes_encrypt" contains "aes"
    assert result["network_indicators"] >= 1  # "http://..." contains "http"
    assert result["persistence_indicators"] >= 1  # "autorun_startup" contains "autorun"
    assert result["suspicious_apis"] >= 1  # VirtualAllocEx matches
    assert result["crypto_apis"] >= 1  # CryptEncrypt matches
    assert result["network_apis"] >= 1  # connect matches


def test_extract_behavioral_features_empty():
    """Test _extract_behavioral_features with empty data."""
    cmdj_map = {"izzj": [], "iij": []}
    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = analyzer._extract_behavioral_features()

    assert isinstance(result, dict)


def test_extract_behavioral_features_exception():
    """Test _extract_behavioral_features with exception from adapter."""
    fake_r2 = FakeR2()
    fake_r2.cmdj = lambda c: (_ for _ in ()).throw(RuntimeError("Error"))
    adapter = R2PipeAdapter(fake_r2)
    analyzer = BinDiffAnalyzer(adapter, "/test/file.exe")
    result = analyzer._extract_behavioral_features()

    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Comparison signatures
# ---------------------------------------------------------------------------


def test_generate_comparison_signatures():
    """Test _generate_comparison_signatures with real domain functions."""
    analyzer = _make_analyzer()

    results = {
        "structural_features": {
            "file_type": "pe",
            "architecture": "x86",
            "section_names": [".text"],
        },
        "function_features": {"function_count": 10, "function_names": ["main", "init"]},
        "string_features": {
            "total_strings": 50,
            "api_strings": ["CreateFileA"],
            "path_strings": [],
        },
        "behavioral_features": {
            "crypto_indicators": 2,
            "network_indicators": 1,
            "suspicious_apis": 0,
        },
    }

    signatures = analyzer._generate_comparison_signatures(results)

    assert "structural" in signatures
    assert "function" in signatures
    assert "string" in signatures
    assert "behavioral" in signatures
    # All values should be MD5 hex digests (32 hex chars)
    assert all(isinstance(v, str) and len(v) == 32 for v in signatures.values())


def test_generate_comparison_signatures_empty():
    """Test _generate_comparison_signatures with empty results."""
    analyzer = _make_analyzer()
    signatures = analyzer._generate_comparison_signatures({})

    assert isinstance(signatures, dict)
    # Should still produce signatures from empty feature dicts
    assert len(signatures) == 4


# ---------------------------------------------------------------------------
# Domain functions tested directly
# ---------------------------------------------------------------------------


class TestDomainFunctions:
    """Test bindiff domain functions directly with real data."""

    def test_has_crypto_indicators_positive(self):
        assert has_crypto_indicators("aes_key_schedule") is True
        assert has_crypto_indicators("sha256sum") is True
        assert has_crypto_indicators("encrypt_data") is True

    def test_has_crypto_indicators_negative(self):
        assert has_crypto_indicators("hello_world") is False

    def test_has_network_indicators_positive(self):
        assert has_network_indicators("http://example.com") is True
        assert has_network_indicators("tcp_connect") is True

    def test_has_network_indicators_negative(self):
        assert has_network_indicators("local_variable") is False

    def test_has_persistence_indicators_positive(self):
        assert has_persistence_indicators("autorun_key") is True
        assert has_persistence_indicators("create_service") is True

    def test_has_persistence_indicators_negative(self):
        assert has_persistence_indicators("print_message") is False

    def test_is_suspicious_api(self):
        assert is_suspicious_api("CreateRemoteThread") is True
        assert is_suspicious_api("VirtualAllocEx") is True
        assert is_suspicious_api("printf") is False

    def test_is_crypto_api(self):
        assert is_crypto_api("CryptEncrypt") is True
        assert is_crypto_api("CryptDecrypt") is True
        assert is_crypto_api("malloc") is False

    def test_is_network_api(self):
        assert is_network_api("WSAStartup") is True
        assert is_network_api("connect") is True
        assert is_network_api("free") is False

    def test_build_struct_signature(self):
        sig = build_struct_signature(
            {"file_type": "pe", "architecture": "x86", "section_names": [".text", ".data"]}
        )
        assert sig == "pe-x86-2"

    def test_build_struct_signature_empty(self):
        sig = build_struct_signature({})
        assert sig == "--0"

    def test_build_function_signature(self):
        sig = build_function_signature({"function_count": 10, "function_names": ["main", "init"]})
        assert sig == "10-2"

    def test_build_function_signature_empty(self):
        sig = build_function_signature({})
        assert sig == "0-0"

    def test_build_string_signature(self):
        sig = build_string_signature(
            {"total_strings": 50, "api_strings": ["CreateFileA"], "path_strings": []}
        )
        assert sig == "50-1-0"

    def test_build_behavioral_signature(self):
        sig = build_behavioral_signature(
            {"crypto_indicators": 2, "network_indicators": 1, "suspicious_apis": 3}
        )
        assert sig == "2-1-3"

    def test_build_behavioral_signature_empty(self):
        sig = build_behavioral_signature({})
        assert sig == "0-0-0"

    def test_calculate_cyclomatic_complexity(self):
        cfg = {
            "blocks": [{"addr": 1}, {"addr": 2}, {"addr": 3}],
            "edges": [{"from": 1, "to": 2}, {"from": 2, "to": 3}],
        }
        # E - N + 2 = 2 - 3 + 2 = 1
        assert calculate_cyclomatic_complexity(cfg) == 1

    def test_calculate_cyclomatic_complexity_empty(self):
        assert calculate_cyclomatic_complexity({}) == 0
        assert calculate_cyclomatic_complexity({"blocks": [], "edges": []}) == 0

    def test_calculate_rolling_hash(self):
        data = b"A" * 200
        hashes = calculate_rolling_hash(data)
        assert isinstance(hashes, list)
        assert len(hashes) > 0
        # All hashes for identical windows should be equal
        assert len(set(hashes)) == 1

    def test_calculate_rolling_hash_short_data(self):
        data = b"AB"
        hashes = calculate_rolling_hash(data, window_size=64)
        # Data shorter than window -> no hashes
        assert hashes == []

    def test_categorize_similarity(self):
        assert categorize_similarity(0.9) == "Very High"
        assert categorize_similarity(0.8) == "Very High"
        assert categorize_similarity(0.7) == "High"
        assert categorize_similarity(0.5) == "Medium"
        assert categorize_similarity(0.3) == "Low"
        assert categorize_similarity(0.1) == "Very Low"
        assert categorize_similarity(0.0) == "Very Low"


class TestStringClassification:
    """Test string classification functions directly."""

    def test_is_api_string(self):
        assert is_api_string("CreateFileA") is True
        assert is_api_string("GetProcAddress") is True
        assert is_api_string("hello_world") is False

    def test_is_path_string(self):
        assert is_path_string("C:\\Windows\\System32") is True
        assert is_path_string("/usr/bin/ls") is True
        assert is_path_string("hello") is False
        # http URLs should not be classified as paths
        assert is_path_string("http://example.com/path") is False

    def test_is_url_string(self):
        assert is_url_string("http://example.com") is True
        assert is_url_string("https://secure.example.com") is True
        assert is_url_string("ftp://files.example.com") is True
        assert is_url_string("not_a_url") is False

    def test_is_registry_string(self):
        assert is_registry_string("HKLM\\Software\\Test") is True
        assert is_registry_string("HKCU\\Environment") is True
        assert is_registry_string("SOFTWARE\\Microsoft") is True
        assert is_registry_string("not_a_registry_key") is False
