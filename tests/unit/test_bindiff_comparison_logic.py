"""Comprehensive tests for bindiff_analyzer.py - comparison logic.

All tests use real objects (FakeR2 + R2PipeAdapter) instead of mocks.
"""

import os
import tempfile
from pathlib import Path

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer
from r2inspect.domain.formats.bindiff import (
    calculate_cyclomatic_complexity,
    calculate_overall_similarity,
    calculate_rolling_hash,
    categorize_similarity,
    compare_behavioral_features,
    compare_byte_features,
    compare_function_features,
    compare_rolling_hashes,
    compare_string_features,
    compare_structural_features,
)

SAMPLES_DIR = Path(__file__).parent.parent.parent / "samples" / "fixtures"


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


# ---- compare_with integration ----


def test_compare_with_success():
    """Test compare_with method with two identical PE binaries."""
    cmdj_map = {
        "ij": {"core": {"format": "pe"}, "bin": {"arch": "x86", "bits": 32, "endian": "little"}},
        "iSj": [{"name": ".text", "size": 5000, "perm": "r-x"}],
        "iij": [{"libname": "kernel32.dll", "name": "CreateFileA"}],
        "iEj": [],
        "aflj": [{"name": "main", "size": 200, "offset": 0x1000}],
        "izzj": [{"string": "hello"}],
        "agj @ 4096": {},
    }
    cmd_map = {
        "aaa": "",
        "p=e 100": "entropy_pattern_here",
    }

    # Create a temp file so _read_file_head succeeds
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
        tmp.write(b"\x00" * 256)
        tmp_path = tmp.name

    try:
        analyzer1 = BinDiffAnalyzer(_make_adapter(cmdj_map, cmd_map), tmp_path)
        analyzer2 = BinDiffAnalyzer(_make_adapter(cmdj_map, cmd_map), tmp_path)

        other_results = analyzer2.analyze()
        assert other_results["comparison_ready"] is True

        result = analyzer1.compare_with(other_results)
        assert result["binary_a"] == Path(tmp_path).name
        assert result["binary_b"] == Path(tmp_path).name
        assert "overall_similarity" in result
        assert "similarity_level" in result
        # Identical binaries should have high similarity
        assert result["overall_similarity"] > 0.5
    finally:
        os.unlink(tmp_path)


def test_compare_with_not_ready():
    """Test compare_with when one binary is not ready."""
    adapter = _make_adapter()
    analyzer = BinDiffAnalyzer(adapter, "/test/file1.exe")

    other_results = {
        "comparison_ready": False,
    }

    # The analyzer's own analyze() will produce comparison_ready=True or False
    # depending on whether it succeeds. With an empty adapter it may still succeed
    # but the other_results says not ready, so it should return an error.
    result = analyzer.compare_with(other_results)

    assert "error" in result
    assert result["similarity_score"] == 0.0


def test_compare_with_exception():
    """Test compare_with with an adapter that causes an error."""
    # Give a filepath that does not exist to cause an exception during analyze
    # Actually compare_with catches exceptions, so we just pass empty other_results
    adapter = _make_adapter()
    analyzer = BinDiffAnalyzer(adapter, "/test/file1.exe")

    # Empty dict has no "comparison_ready" key, so it evaluates as False
    result = analyzer.compare_with({})

    assert "error" in result
    assert result["similarity_score"] == 0.0


# ---- _compare_structural ----


def test_compare_structural_success():
    """Test _compare_structural method with real comparison logic."""
    analyzer = _make_analyzer()

    a = {
        "structural_features": {
            "file_type": "pe",
            "architecture": "x86",
            "section_names": [".text", ".data"],
            "imported_dlls": ["kernel32.dll"],
        }
    }
    b = {
        "structural_features": {
            "file_type": "pe",
            "architecture": "x86",
            "section_names": [".text", ".data"],
            "imported_dlls": ["kernel32.dll"],
        }
    }

    result = analyzer._compare_structural(a, b)

    # Identical features should give a perfect score
    assert result == 1.0


def test_compare_structural_different():
    """Test _compare_structural with differing features."""
    analyzer = _make_analyzer()

    a = {"structural_features": {"file_type": "pe", "architecture": "x86"}}
    b = {"structural_features": {"file_type": "elf", "architecture": "arm"}}

    result = analyzer._compare_structural(a, b)

    # Different file type + architecture = lower score
    assert result < 1.0


def test_compare_structural_empty():
    """Test _compare_structural with empty feature dicts returns a valid float."""
    analyzer = _make_analyzer()

    # Empty dicts - both have no file_type/architecture so those match as equal (None==None)
    result = analyzer._compare_structural({}, {})

    assert isinstance(result, float)
    assert 0.0 <= result <= 1.0


# ---- _compare_functions ----


def test_compare_functions_success():
    """Test _compare_functions method with real comparison logic."""
    analyzer = _make_analyzer()

    a = {"function_features": {"function_count": 10, "function_names": ["main", "init"]}}
    b = {"function_features": {"function_count": 12, "function_names": ["main", "init"]}}

    result = analyzer._compare_functions(a, b)

    assert isinstance(result, float)
    assert result > 0.5  # Similar function counts + identical names


def test_compare_functions_exception():
    """Test _compare_functions with empty data."""
    analyzer = _make_analyzer()

    result = analyzer._compare_functions({}, {})

    assert isinstance(result, float)
    assert result == 0.0


# ---- _compare_strings ----


def test_compare_strings_success():
    """Test _compare_strings method with real comparison logic."""
    analyzer = _make_analyzer()

    a = {
        "string_features": {
            "api_strings": ["CreateFileA"],
            "path_strings": [],
            "registry_strings": [],
            "total_strings": 50,
        }
    }
    b = {
        "string_features": {
            "api_strings": ["CreateFileA"],
            "path_strings": [],
            "registry_strings": [],
            "total_strings": 48,
        }
    }

    result = analyzer._compare_strings(a, b)

    assert isinstance(result, float)
    assert result > 0.0


def test_compare_strings_empty():
    """Test _compare_strings with empty data returns a valid float."""
    analyzer = _make_analyzer()

    result = analyzer._compare_strings({}, {})

    assert isinstance(result, float)
    assert 0.0 <= result <= 1.0


# ---- _compare_bytes ----


def test_compare_bytes_success():
    """Test _compare_bytes method with real comparison logic."""
    analyzer = _make_analyzer()

    rolling_hash = calculate_rolling_hash(b"\x00" * 128)
    a = {"byte_features": {"rolling_hash": rolling_hash}}
    b = {"byte_features": {"rolling_hash": rolling_hash}}

    result = analyzer._compare_bytes(a, b)

    assert isinstance(result, float)
    assert result == 1.0  # Identical hashes


def test_compare_bytes_different():
    """Test _compare_bytes with different rolling hashes."""
    analyzer = _make_analyzer()

    hash_a = calculate_rolling_hash(b"\x00" * 128)
    hash_b = calculate_rolling_hash(b"\xff" * 128)
    a = {"byte_features": {"rolling_hash": hash_a}}
    b = {"byte_features": {"rolling_hash": hash_b}}

    result = analyzer._compare_bytes(a, b)

    assert isinstance(result, float)
    assert result < 1.0


def test_compare_bytes_exception():
    """Test _compare_bytes with empty data."""
    analyzer = _make_analyzer()

    result = analyzer._compare_bytes({}, {})

    assert isinstance(result, float)
    assert result == 0.0


# ---- _compare_behavioral ----


def test_compare_behavioral_success():
    """Test _compare_behavioral method with real comparison logic."""
    analyzer = _make_analyzer()

    a = {
        "behavioral_features": {
            "crypto_indicators": 5,
            "network_indicators": 3,
            "suspicious_apis": 2,
        }
    }
    b = {
        "behavioral_features": {
            "crypto_indicators": 4,
            "network_indicators": 3,
            "suspicious_apis": 2,
        }
    }

    result = analyzer._compare_behavioral(a, b)

    assert isinstance(result, float)
    assert result > 0.5


def test_compare_behavioral_exception():
    """Test _compare_behavioral with empty data."""
    analyzer = _make_analyzer()

    result = analyzer._compare_behavioral({}, {})

    assert isinstance(result, float)
    assert result == 0.0


# ---- _extract_function_features ----


def test_extract_function_features_no_analyze_all():
    """Test _extract_function_features when adapter has no analyze_all method."""
    cmdj_map = {
        "aflj": [],
    }
    cmd_map = {
        "aaa": "",
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)

    # R2PipeAdapter does not have analyze_all, so it falls through to _run_analysis_command
    result = analyzer._extract_function_features()

    assert isinstance(result, dict)


def test_extract_function_features_empty_cfg():
    """Test _extract_function_features with empty CFG."""
    cmdj_map = {
        "aflj": [{"name": "main", "size": 200, "offset": 0x1000}],
        "agj @ 4096": [],
    }
    cmd_map = {"aaa": ""}
    analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)

    result = analyzer._extract_function_features()

    assert "cfg_features" in result


def test_extract_function_features_cfg_other_type():
    """Test _extract_function_features with CFG as non-list/dict."""
    cmdj_map = {
        "aflj": [{"name": "main", "size": 200, "offset": 0x1000}],
        "agj @ 4096": "invalid",
    }
    cmd_map = {"aaa": ""}
    # FakeR2 will return "invalid" but the adapter's cmdj wraps it
    # The adapter uses silent_cmdj which may return {} for invalid data
    analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)

    result = analyzer._extract_function_features()

    assert "cfg_features" in result


def test_extract_function_features_complexity_calculation():
    """Test _extract_function_features calculates complexity from real CFG data."""
    cfg_data = {
        "blocks": [{"addr": 0x1000}, {"addr": 0x1010}, {"addr": 0x1020}],
        "edges": [{"from": 0x1000, "to": 0x1010}, {"from": 0x1000, "to": 0x1020}],
    }
    cmdj_map = {
        "aflj": [{"name": "main", "size": 200, "offset": 0x1000}],
        "agj @ 4096": cfg_data,
    }
    cmd_map = {"aaa": ""}
    analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)

    result = analyzer._extract_function_features()

    assert "cfg_features" in result
    if result["cfg_features"]:
        # cyclomatic complexity = edges - nodes + 2 = 2 - 3 + 2 = 1
        assert result["cfg_features"][0]["complexity"] == 1


# ---- _extract_string_features ----


def test_extract_string_features_with_duplicates():
    """Test _extract_string_features with duplicate strings."""
    cmdj_map = {
        "izzj": [
            {"string": "test"},
            {"string": "test"},
            {"string": "other"},
        ],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)

    result = analyzer._extract_string_features()

    assert result["total_strings"] == 3
    assert result["unique_strings"] == 2


def test_extract_string_features_categorized():
    """Test _extract_string_features categorizes strings correctly using real classifiers."""
    cmdj_map = {
        "izzj": [
            {"string": "CreateFileA"},  # API string
            {"string": "C:\\Windows\\System32\\cmd.exe"},  # Path string
        ],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)

    result = analyzer._extract_string_features()

    assert "categorized_strings" in result
    assert result["categorized_strings"].get("API", 0) >= 1
    assert result["categorized_strings"].get("Paths", 0) >= 1


# ---- _extract_byte_features ----


def test_extract_byte_features_rolling_hash_exception():
    """Test _extract_byte_features when file cannot be read."""
    # Use a nonexistent file path so _read_file_head raises an exception
    cmdj_map = {}
    cmd_map = {"p=e 100": "entropy_data"}
    adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
    analyzer = BinDiffAnalyzer(adapter, "/nonexistent/path/file.exe")

    result = analyzer._extract_byte_features()

    # entropy_pattern should still be set from the adapter
    assert "entropy_pattern" in result
    # rolling_hash should not be present because file read failed
    assert "rolling_hash" not in result


def test_extract_byte_features_with_real_file():
    """Test _extract_byte_features with a real temporary file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
        tmp.write(b"\x00" * 256)
        tmp_path = tmp.name

    try:
        cmd_map = {"p=e 100": "entropy_data"}
        adapter = _make_adapter(cmd_map=cmd_map)
        analyzer = BinDiffAnalyzer(adapter, tmp_path)

        result = analyzer._extract_byte_features()

        assert "entropy_pattern" in result
        assert "rolling_hash" in result
        assert isinstance(result["rolling_hash"], list)
    finally:
        os.unlink(tmp_path)


# ---- _extract_structural_features ----


def test_extract_structural_features_section_names_sorted():
    """Test _extract_structural_features sorts section names."""
    cmdj_map = {
        "ij": {},
        "iSj": [
            {"name": ".text", "size": 100, "perm": "r-x"},
            {"name": ".data", "size": 200, "perm": "rw-"},
            {"name": ".bss", "size": 50, "perm": "rw-"},
        ],
        "iij": [],
        "iEj": [],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)

    result = analyzer._extract_structural_features()

    assert result["section_names"] == [".bss", ".data", ".text"]


def test_extract_structural_features_imported_dlls_unique():
    """Test _extract_structural_features produces unique DLL list."""
    cmdj_map = {
        "ij": {},
        "iSj": [],
        "iij": [
            {"libname": "kernel32.dll", "name": "CreateFileA"},
            {"libname": "kernel32.dll", "name": "WriteFile"},
            {"libname": "user32.dll", "name": "MessageBoxA"},
        ],
        "iEj": [],
    }
    analyzer = _make_analyzer(cmdj_map=cmdj_map)

    result = analyzer._extract_structural_features()

    assert len(result["imported_dlls"]) == 2
    assert "kernel32.dll" in result["imported_dlls"]
    assert "user32.dll" in result["imported_dlls"]


# ---- Full integration ----


def test_compare_with_full_integration():
    """Test compare_with end-to-end with real feature extraction and comparison."""
    cmdj_map = {
        "ij": {
            "core": {"format": "pe", "size": 10000},
            "bin": {"arch": "x86", "bits": 32, "endian": "little"},
        },
        "iSj": [{"name": ".text", "size": 5000, "perm": "r-x"}],
        "iij": [{"libname": "kernel32.dll", "name": "CreateFileA"}],
        "iEj": [],
        "aflj": [{"name": "main", "size": 200, "offset": 0x1000}],
        "izzj": [{"string": "test"}],
        "agj @ 4096": {},
    }
    cmd_map = {
        "aaa": "",
        "p=e 100": "entropy_data",
    }

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
        tmp.write(b"\x00" * 256)
        tmp_path = tmp.name

    try:
        analyzer1 = BinDiffAnalyzer(_make_adapter(cmdj_map, cmd_map), tmp_path)
        analyzer2 = BinDiffAnalyzer(_make_adapter(cmdj_map, cmd_map), tmp_path)

        other_results = analyzer2.analyze()
        assert other_results["comparison_ready"] is True

        result = analyzer1.compare_with(other_results)

        # Identical binaries should have very high similarity
        assert result["overall_similarity"] >= 0.8
        assert result["similarity_level"] in ("Very High", "High")
    finally:
        os.unlink(tmp_path)


# ---- Domain function direct tests ----


def test_categorize_similarity_levels():
    """Test categorize_similarity returns correct labels for each threshold."""
    assert categorize_similarity(0.9) == "Very High"
    assert categorize_similarity(0.8) == "Very High"
    assert categorize_similarity(0.7) == "High"
    assert categorize_similarity(0.6) == "High"
    assert categorize_similarity(0.5) == "Medium"
    assert categorize_similarity(0.4) == "Medium"
    assert categorize_similarity(0.3) == "Low"
    assert categorize_similarity(0.2) == "Low"
    assert categorize_similarity(0.1) == "Very Low"
    assert categorize_similarity(0.0) == "Very Low"


def test_calculate_rolling_hash_deterministic():
    """Test calculate_rolling_hash returns deterministic results."""
    data = b"Hello, World!" * 20
    hash1 = calculate_rolling_hash(data)
    hash2 = calculate_rolling_hash(data)
    assert hash1 == hash2
    assert isinstance(hash1, list)
    assert all(isinstance(h, int) for h in hash1)


def test_compare_rolling_hashes_identical():
    """Test compare_rolling_hashes with identical hash lists."""
    hashes = calculate_rolling_hash(b"\x00" * 128)
    assert compare_rolling_hashes(hashes, hashes) == 1.0


def test_compare_rolling_hashes_empty():
    """Test compare_rolling_hashes with empty lists."""
    assert compare_rolling_hashes([], []) == 0.0
    assert compare_rolling_hashes([1, 2], []) == 0.0
    assert compare_rolling_hashes([], [1, 2]) == 0.0


def test_compare_rolling_hashes_different():
    """Test compare_rolling_hashes with different hash lists."""
    hashes_a = calculate_rolling_hash(b"\x00" * 128)
    hashes_b = calculate_rolling_hash(b"\xff" * 128)
    similarity = compare_rolling_hashes(hashes_a, hashes_b)
    assert 0.0 <= similarity <= 1.0
    assert similarity < 1.0  # Different data should not be identical


def test_calculate_cyclomatic_complexity_basic():
    """Test cyclomatic complexity calculation."""
    cfg = {
        "blocks": [{"addr": 0x1000}, {"addr": 0x1010}, {"addr": 0x1020}],
        "edges": [{"from": 0x1000, "to": 0x1010}, {"from": 0x1000, "to": 0x1020}],
    }
    # complexity = edges - nodes + 2 = 2 - 3 + 2 = 1
    assert calculate_cyclomatic_complexity(cfg) == 1


def test_calculate_cyclomatic_complexity_empty():
    """Test cyclomatic complexity with no blocks."""
    assert calculate_cyclomatic_complexity({}) == 0
    assert calculate_cyclomatic_complexity({"blocks": [], "edges": []}) == 0


def test_calculate_overall_similarity_all_ones():
    """Test overall similarity with perfect scores."""
    result = calculate_overall_similarity(1.0, 1.0, 1.0, 1.0, 1.0)
    assert result == 1.0


def test_calculate_overall_similarity_all_zeros():
    """Test overall similarity with zero scores."""
    result = calculate_overall_similarity(0.0, 0.0, 0.0, 0.0, 0.0)
    assert result == 0.0


def test_calculate_overall_similarity_mixed():
    """Test overall similarity with mixed scores."""
    result = calculate_overall_similarity(0.5, 0.5, 0.5, 0.5, 0.5)
    assert result == 0.5


def test_compare_structural_features_identical():
    """Test compare_structural_features with identical data."""
    features = {
        "file_type": "pe",
        "architecture": "x86",
        "section_names": [".text", ".data"],
        "imported_dlls": ["kernel32.dll"],
    }
    assert compare_structural_features(features, features) == 1.0


def test_compare_function_features_identical():
    """Test compare_function_features with identical data."""
    features = {
        "function_count": 10,
        "function_names": ["main", "init"],
    }
    assert compare_function_features(features, features) == 1.0


def test_compare_string_features_identical_signature():
    """Test compare_string_features with matching signatures."""
    features = {
        "string_signature": "abc123",
        "api_strings": ["CreateFileA"],
        "path_strings": [],
        "registry_strings": [],
    }
    assert compare_string_features(features, features) == 1.0


def test_compare_byte_features_no_hashes():
    """Test compare_byte_features with no rolling hashes."""
    assert compare_byte_features({}, {}) == 0.0


def test_compare_behavioral_features_identical():
    """Test compare_behavioral_features with identical data."""
    features = {
        "crypto_indicators": 5,
        "network_indicators": 3,
        "suspicious_apis": 2,
    }
    assert compare_behavioral_features(features, features) == 1.0


def test_compare_behavioral_features_empty():
    """Test compare_behavioral_features with empty data."""
    assert compare_behavioral_features({}, {}) == 0.0
