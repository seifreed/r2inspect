"""Comprehensive tests for bindiff analyzer - targeting 100% coverage.

NO mocks, NO monkeypatch, NO @patch.
Uses FakeR2 + R2PipeAdapter for BinDiffAnalyzer through the production
adapter stack.  Tests domain functions directly where appropriate.
"""

from __future__ import annotations

import hashlib

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer
from r2inspect.modules.bindiff_domain import (
    build_behavioral_signature,
    build_function_signature,
    build_string_signature,
    build_struct_signature,
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


# ---------------------------------------------------------------------------
# FakeR2 -- deterministic stand-in for r2pipe
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal r2pipe stand-in that returns pre-configured JSON responses."""

    def __init__(
        self,
        cmd_map: dict | None = None,
        cmdj_map: dict | None = None,
    ) -> None:
        self._cmd_map = cmd_map or {}
        self._cmdj_map = cmdj_map or {}

    def cmd(self, command: str) -> str:
        return self._cmd_map.get(command, "")

    def cmdj(self, command: str):
        return self._cmdj_map.get(command)


# ---------------------------------------------------------------------------
# Builder helpers
# ---------------------------------------------------------------------------

_FILE_INFO = {
    "core": {"format": "PE32", "size": 5000},
    "bin": {"arch": "x86", "bits": 32, "endian": "little"},
}

_SECTIONS = [
    {"name": ".text", "size": 1000, "perm": "--x"},
    {"name": ".data", "size": 500, "perm": "-rw"},
]

_IMPORTS = [
    {"libname": "kernel32.dll", "name": "CreateFile"},
    {"libname": "user32.dll", "name": "MessageBoxA"},
]

_EXPORTS = [{"name": "ExportedFunc1"}]

_FUNCTIONS = [
    {"offset": 0x1000, "name": "func1", "size": 100},
    {"offset": 0x2000, "name": "func2", "size": 200},
]

_STRINGS = [
    {"string": "Hello World"},
    {"string": "C:\\Windows\\System32"},
    {"string": "http://example.com"},
]


def _build_adapter(
    file_info: dict | None = _FILE_INFO,
    sections: list | None = None,
    imports: list | None = None,
    exports: list | None = None,
    functions: list | None = None,
    strings: list | None = None,
    cfg_map: dict | None = None,
    cmd_map_extra: dict | None = None,
) -> R2PipeAdapter:
    """Build an R2PipeAdapter backed by FakeR2 with pre-configured data."""
    cmdj: dict = {}
    if file_info is not None:
        cmdj["ij"] = file_info
    if sections is not None:
        cmdj["iSj"] = sections
    if imports is not None:
        cmdj["iij"] = imports
    if exports is not None:
        cmdj["iEj"] = exports
    if functions is not None:
        cmdj["aflj"] = functions
    if strings is not None:
        cmdj["izzj"] = strings
    # Register CFG responses per address
    if cfg_map:
        for addr, cfg_data in cfg_map.items():
            cmdj[f"agj @ {addr}"] = cfg_data

    cmd_map: dict = {}
    if cmd_map_extra:
        cmd_map.update(cmd_map_extra)

    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj))


def _build_analyzer(
    tmp_path,
    filename: str = "test.exe",
    file_content: bytes = b"MZ" + b"\x00" * 100,
    **adapter_kwargs,
) -> BinDiffAnalyzer:
    """Build a BinDiffAnalyzer with a real temp file + FakeR2 adapter."""
    test_file = tmp_path / filename
    test_file.write_bytes(file_content)
    adapter = _build_adapter(**adapter_kwargs)
    return BinDiffAnalyzer(adapter, str(test_file))


# ===========================================================================
# Tests: BinDiffAnalyzer.analyze() through FakeR2 + R2PipeAdapter
# ===========================================================================


class TestBinDiffBasicAnalysis:
    """Basic analysis returns expected top-level keys."""

    def test_basic_analysis_keys(self, tmp_path):
        analyzer = _build_analyzer(tmp_path, file_info=_FILE_INFO)
        result = analyzer.analyze()

        assert result["filename"] == "test.exe"
        assert result["comparison_ready"] is True
        assert "structural_features" in result
        assert "function_features" in result
        assert "string_features" in result
        assert "byte_features" in result
        assert "behavioral_features" in result
        assert "signatures" in result

    def test_filepath_preserved(self, tmp_path):
        analyzer = _build_analyzer(tmp_path, filename="sample.bin")
        result = analyzer.analyze()
        assert result["filename"] == "sample.bin"
        assert result["filepath"].endswith("sample.bin")


class TestBinDiffStructuralFeatures:
    """Structural feature extraction via the real adapter stack."""

    def test_structural_features_populated(self, tmp_path):
        analyzer = _build_analyzer(
            tmp_path,
            file_info=_FILE_INFO,
            sections=_SECTIONS,
            imports=_IMPORTS,
            exports=_EXPORTS,
        )
        result = analyzer.analyze()
        struct = result["structural_features"]

        assert struct["file_type"] == "PE32"
        assert struct["architecture"] == "x86"
        assert struct["bits"] == 32
        assert struct["endian"] == "little"
        assert struct["file_size"] == 5000
        assert struct["section_count"] == 2
        assert struct["import_count"] == 2
        assert struct["export_count"] == 1
        assert ".text" in struct["section_names"]
        assert "kernel32.dll" in struct["imported_dlls"]
        assert "ExportedFunc1" in struct["exported_functions"]

    def test_structural_features_empty_adapter(self, tmp_path):
        """When no data is returned, structural features degrade to empty dict."""
        analyzer = _build_analyzer(tmp_path, file_info={"core": {}, "bin": {}})
        result = analyzer.analyze()
        struct = result["structural_features"]
        # Should still have keys but with default/empty values
        assert struct.get("file_type", "") == ""
        assert struct.get("bits", 0) == 0

    def test_executable_and_writable_section_counts(self, tmp_path):
        analyzer = _build_analyzer(
            tmp_path,
            file_info=_FILE_INFO,
            sections=_SECTIONS,
        )
        result = analyzer.analyze()
        struct = result["structural_features"]
        assert struct["executable_sections"] == 1
        assert struct["writable_sections"] == 1


class TestBinDiffFunctionFeatures:
    """Function feature extraction via the real adapter stack."""

    def test_function_features_populated(self, tmp_path):
        analyzer = _build_analyzer(tmp_path, functions=_FUNCTIONS)
        result = analyzer.analyze()
        func_feat = result["function_features"]

        assert func_feat["function_count"] == 2
        assert 100 in func_feat["function_sizes"]
        assert 200 in func_feat["function_sizes"]
        assert "func1" in func_feat["function_names"]
        assert "func2" in func_feat["function_names"]

    def test_function_cfg_features(self, tmp_path):
        cfg_data = [{"blocks": [1, 2, 3], "edges": [[0, 1], [1, 2]]}]
        analyzer = _build_analyzer(
            tmp_path,
            functions=[{"offset": 0x1000, "name": "func1", "size": 100}],
            cfg_map={0x1000: cfg_data},
        )
        result = analyzer.analyze()
        func_feat = result["function_features"]
        assert "cfg_features" in func_feat
        assert len(func_feat["cfg_features"]) == 1
        assert func_feat["cfg_features"][0]["nodes"] == 3
        assert func_feat["cfg_features"][0]["edges"] == 2

    def test_function_features_empty(self, tmp_path):
        analyzer = _build_analyzer(tmp_path, functions=[])
        result = analyzer.analyze()
        assert (
            result["function_features"] == {}
            or result["function_features"].get("function_count", 0) == 0
        )


class TestBinDiffStringFeatures:
    """String feature extraction via the real adapter stack."""

    def test_string_features_populated(self, tmp_path):
        analyzer = _build_analyzer(tmp_path, strings=_STRINGS)
        result = analyzer.analyze()
        str_feat = result["string_features"]

        assert str_feat["total_strings"] == 3
        assert str_feat["unique_strings"] == 3
        assert "string_signature" in str_feat
        # Path string detected
        assert len(str_feat["path_strings"]) >= 1
        # URL string detected
        assert len(str_feat["url_strings"]) >= 1

    def test_string_signature_deterministic(self, tmp_path):
        """Same strings produce the same signature."""
        a = _build_analyzer(tmp_path, filename="a.bin", strings=_STRINGS)
        b = _build_analyzer(tmp_path, filename="b.bin", strings=_STRINGS)
        sig_a = a.analyze()["string_features"]["string_signature"]
        sig_b = b.analyze()["string_features"]["string_signature"]
        assert sig_a == sig_b

    def test_string_features_empty(self, tmp_path):
        analyzer = _build_analyzer(tmp_path, strings=[])
        result = analyzer.analyze()
        assert result["string_features"].get("total_strings", 0) == 0


class TestBinDiffBehavioralFeatures:
    """Behavioral feature extraction via the real adapter stack."""

    def test_behavioral_features_with_indicators(self, tmp_path):
        suspicious_strings = [
            {"string": "CryptEncrypt"},
            {"string": "socket"},
            {"string": "RegSetValueEx"},
        ]
        suspicious_imports = [
            {"name": "VirtualAllocEx"},
            {"name": "CreateRemoteThread"},
        ]
        analyzer = _build_analyzer(
            tmp_path,
            strings=suspicious_strings,
            imports=suspicious_imports,
        )
        result = analyzer.analyze()
        behav = result["behavioral_features"]

        assert behav["crypto_indicators"] >= 1
        assert behav["network_indicators"] >= 1
        assert behav["suspicious_apis"] >= 1

    def test_behavioral_features_crypto_apis(self, tmp_path):
        analyzer = _build_analyzer(
            tmp_path,
            imports=[{"name": "CryptEncrypt"}, {"name": "CryptDecrypt"}],
        )
        result = analyzer.analyze()
        behav = result["behavioral_features"]
        assert behav["crypto_apis"] == 2

    def test_behavioral_features_network_apis(self, tmp_path):
        analyzer = _build_analyzer(
            tmp_path,
            imports=[{"name": "WSAStartup"}, {"name": "InternetOpen"}],
        )
        result = analyzer.analyze()
        behav = result["behavioral_features"]
        assert behav["network_apis"] == 2


class TestBinDiffByteFeatures:
    """Byte feature extraction (entropy pattern, rolling hash)."""

    def test_byte_features_rolling_hash(self, tmp_path):
        content = b"MZ" + bytes(range(256)) * 40  # > 8192 bytes
        analyzer = _build_analyzer(tmp_path, file_content=content)
        result = analyzer.analyze()
        byte_feat = result["byte_features"]
        assert "rolling_hash" in byte_feat
        assert isinstance(byte_feat["rolling_hash"], list)
        assert len(byte_feat["rolling_hash"]) > 0

    def test_byte_features_entropy_pattern(self, tmp_path):
        analyzer = _build_analyzer(
            tmp_path,
            cmd_map_extra={"p=e 100": "===###==="},
        )
        result = analyzer.analyze()
        byte_feat = result["byte_features"]
        assert byte_feat.get("entropy_pattern") == "===###==="


class TestBinDiffSignatures:
    """Signature generation from analysis results."""

    def test_signatures_present(self, tmp_path):
        analyzer = _build_analyzer(
            tmp_path,
            file_info=_FILE_INFO,
            sections=_SECTIONS,
            functions=_FUNCTIONS,
            strings=_STRINGS,
        )
        result = analyzer.analyze()
        sigs = result["signatures"]

        assert "structural" in sigs
        assert "function" in sigs
        assert "string" in sigs
        assert "behavioral" in sigs
        # Each signature is an md5 hex digest
        for key in ("structural", "function", "string", "behavioral"):
            assert len(sigs[key]) == 32

    def test_signatures_deterministic(self, tmp_path):
        kwargs = {
            "file_info": _FILE_INFO,
            "sections": _SECTIONS,
            "functions": _FUNCTIONS,
            "strings": _STRINGS,
        }
        a = _build_analyzer(tmp_path, filename="a.bin", **kwargs)
        b = _build_analyzer(tmp_path, filename="b.bin", **kwargs)
        for key in ("structural", "function", "string", "behavioral"):
            assert a.analyze()["signatures"][key] == b.analyze()["signatures"][key]


class TestBinDiffComparison:
    """compare_with() through the real adapter stack."""

    def _make_other_results(self, **overrides) -> dict:
        base = {
            "filename": "other.bin",
            "comparison_ready": True,
            "structural_features": {
                "file_type": "PE32",
                "architecture": "x86",
                "bits": 32,
                "section_count": 1,
                "import_count": 1,
                "section_names": [".text"],
                "imported_dlls": ["kernel32.dll"],
            },
            "function_features": {
                "function_count": 1,
                "function_sizes": [100],
                "function_names": ["func1"],
            },
            "string_features": {
                "total_strings": 1,
                "unique_strings": 1,
                "api_strings": [],
                "path_strings": [],
                "url_strings": [],
                "registry_strings": [],
            },
            "byte_features": {},
            "behavioral_features": {},
        }
        base.update(overrides)
        return base

    def test_comparison_returns_similarity(self, tmp_path):
        analyzer = _build_analyzer(
            tmp_path,
            file_info=_FILE_INFO,
            sections=[{"name": ".text", "size": 500, "perm": "--x"}],
            imports=[{"libname": "kernel32.dll", "name": "CreateFile"}],
            functions=[{"offset": 0x1000, "name": "func1", "size": 100}],
            strings=[{"string": "test"}],
        )
        comparison = analyzer.compare_with(self._make_other_results())

        assert "overall_similarity" in comparison
        assert "similarity_level" in comparison
        assert isinstance(comparison["overall_similarity"], float)
        assert 0.0 <= comparison["overall_similarity"] <= 1.0

    def test_comparison_not_ready(self, tmp_path):
        analyzer = _build_analyzer(tmp_path)
        comparison = analyzer.compare_with({"comparison_ready": False})

        assert "error" in comparison
        assert comparison["similarity_score"] == 0.0

    def test_comparison_binary_names(self, tmp_path):
        analyzer = _build_analyzer(
            tmp_path,
            filename="sample_a.bin",
            file_info=_FILE_INFO,
            sections=_SECTIONS,
            imports=_IMPORTS,
            functions=_FUNCTIONS,
            strings=_STRINGS,
        )
        other = self._make_other_results()
        comparison = analyzer.compare_with(other)
        assert comparison["binary_a"] == "sample_a.bin"
        assert comparison["binary_b"] == "other.bin"


class TestBinDiffErrorHandling:
    """Graceful degradation when adapter raises."""

    def test_error_during_analysis(self, tmp_path):
        """An adapter whose get_file_info raises still produces a result."""
        # Use an adapter that will raise on file_info
        test_file = tmp_path / "bad.bin"
        test_file.write_bytes(b"\x00" * 10)

        class FailingR2:
            def cmd(self, command: str) -> str:
                raise RuntimeError("r2 not available")

            def cmdj(self, command: str):
                raise RuntimeError("r2 not available")

        adapter = R2PipeAdapter(FailingR2())
        analyzer = BinDiffAnalyzer(adapter, str(test_file))
        result = analyzer.analyze()

        assert isinstance(result, dict)
        assert "comparison_ready" in result


# ===========================================================================
# Tests: Domain functions (pure, no adapter needed)
# ===========================================================================


class TestCyclomaticComplexity:
    def test_basic_cfg(self):
        cfg = {"blocks": [1, 2, 3], "edges": [[0, 1], [1, 2]]}
        assert calculate_cyclomatic_complexity(cfg) == 1  # 2 - 3 + 2

    def test_empty_cfg(self):
        assert calculate_cyclomatic_complexity({}) == 0

    def test_single_block(self):
        cfg = {"blocks": [1], "edges": []}
        assert calculate_cyclomatic_complexity(cfg) == 1  # 0 - 1 + 2

    def test_invalid_cfg(self):
        assert calculate_cyclomatic_complexity(None) == 0  # type: ignore[arg-type]


class TestRollingHash:
    def test_deterministic(self):
        data = b"A" * 200
        h1 = calculate_rolling_hash(data)
        h2 = calculate_rolling_hash(data)
        assert h1 == h2

    def test_different_data_different_hash(self):
        h1 = calculate_rolling_hash(b"A" * 200)
        h2 = calculate_rolling_hash(b"B" * 200)
        assert h1 != h2

    def test_max_100_hashes(self):
        data = b"\x00" * 500
        result = calculate_rolling_hash(data)
        assert len(result) <= 100

    def test_short_data(self):
        # Less than window_size=64 returns empty
        result = calculate_rolling_hash(b"\x00" * 10)
        assert result == []


class TestCategorizeSimilarity:
    @pytest.mark.parametrize(
        "score, expected",
        [
            (1.0, "Very High"),
            (0.8, "Very High"),
            (0.7, "High"),
            (0.6, "High"),
            (0.5, "Medium"),
            (0.4, "Medium"),
            (0.3, "Low"),
            (0.2, "Low"),
            (0.1, "Very Low"),
            (0.0, "Very Low"),
        ],
    )
    def test_thresholds(self, score, expected):
        assert categorize_similarity(score) == expected


class TestIndicatorDetection:
    def test_has_crypto_indicators(self):
        assert has_crypto_indicators("CryptEncrypt") is True
        assert has_crypto_indicators("AES_KEY") is True
        assert has_crypto_indicators("hello world") is False

    def test_has_network_indicators(self):
        assert has_network_indicators("http://example.com") is True
        assert has_network_indicators("socket_connect") is True
        assert has_network_indicators("hello world") is False

    def test_has_persistence_indicators(self):
        assert has_persistence_indicators("autorun") is True
        assert has_persistence_indicators("registry key") is True
        assert has_persistence_indicators("hello world") is False

    def test_is_suspicious_api(self):
        assert is_suspicious_api("CreateRemoteThread") is True
        assert is_suspicious_api("WriteProcessMemory") is True
        assert is_suspicious_api("printf") is False

    def test_is_crypto_api(self):
        assert is_crypto_api("CryptEncrypt") is True
        assert is_crypto_api("CryptDecrypt") is True
        assert is_crypto_api("ReadFile") is False

    def test_is_network_api(self):
        assert is_network_api("WSAStartup") is True
        assert is_network_api("InternetOpen") is True
        assert is_network_api("ReadFile") is False


class TestSignatureBuilders:
    def test_build_struct_signature(self):
        features = {"file_type": "PE32", "architecture": "x86", "section_names": [".text", ".data"]}
        sig = build_struct_signature(features)
        assert "PE32" in sig
        assert "x86" in sig

    def test_build_function_signature(self):
        features = {"function_count": 5, "function_names": ["a", "b", "c"]}
        sig = build_function_signature(features)
        assert "5" in sig
        assert "3" in sig

    def test_build_string_signature(self):
        features = {"total_strings": 10, "api_strings": ["a"], "path_strings": ["b", "c"]}
        sig = build_string_signature(features)
        assert "10" in sig

    def test_build_behavioral_signature(self):
        features = {"crypto_indicators": 2, "network_indicators": 1, "suspicious_apis": 3}
        sig = build_behavioral_signature(features)
        assert "2" in sig
        assert "1" in sig
        assert "3" in sig


class TestComparisonFunctions:
    """Domain comparison functions tested directly."""

    def test_compare_structural_identical(self):
        a = {
            "file_type": "PE32",
            "architecture": "x86",
            "section_names": [".text"],
            "imported_dlls": ["kernel32.dll"],
        }
        score = compare_structural_features(a, a)
        assert score == 1.0

    def test_compare_structural_different(self):
        a = {"file_type": "PE32", "architecture": "x86", "section_names": [".text"]}
        b = {"file_type": "ELF", "architecture": "arm", "section_names": [".init"]}
        score = compare_structural_features(a, b)
        assert score < 0.5

    def test_compare_function_identical(self):
        a = {"function_count": 10, "function_names": ["main", "init"]}
        score = compare_function_features(a, a)
        assert score == 1.0

    def test_compare_function_different(self):
        a = {"function_count": 100, "function_names": ["main"]}
        b = {"function_count": 1, "function_names": ["entry"]}
        score = compare_function_features(a, b)
        assert score < 0.5

    def test_compare_string_identical_signature(self):
        a = {"string_signature": "abc123"}
        score = compare_string_features(a, a)
        assert score == 1.0

    def test_compare_string_different(self):
        a = {
            "string_signature": "abc",
            "api_strings": ["a"],
            "path_strings": [],
            "registry_strings": [],
        }
        b = {
            "string_signature": "def",
            "api_strings": ["b"],
            "path_strings": [],
            "registry_strings": [],
        }
        score = compare_string_features(a, b)
        assert 0.0 <= score <= 1.0

    def test_compare_byte_features_empty(self):
        score = compare_byte_features({}, {})
        assert score == 0.0

    def test_compare_byte_features_with_hashes(self):
        a = {"rolling_hash": [1, 2, 3, 4, 5]}
        score = compare_byte_features(a, a)
        assert score == 1.0

    def test_compare_behavioral_identical(self):
        a = {"crypto_indicators": 5, "network_indicators": 3, "suspicious_apis": 2}
        score = compare_behavioral_features(a, a)
        assert score == 1.0

    def test_compare_behavioral_empty(self):
        score = compare_behavioral_features({}, {})
        assert score == 0.0

    def test_compare_rolling_hashes_identical(self):
        h = [1, 2, 3, 4, 5]
        assert compare_rolling_hashes(h, h) == 1.0

    def test_compare_rolling_hashes_disjoint(self):
        assert compare_rolling_hashes([1, 2], [3, 4]) == 0.0

    def test_compare_rolling_hashes_empty(self):
        assert compare_rolling_hashes([], [1, 2]) == 0.0

    def test_calculate_overall_similarity(self):
        score = calculate_overall_similarity(1.0, 1.0, 1.0, 1.0, 1.0)
        assert score == 1.0

    def test_calculate_overall_similarity_zero(self):
        score = calculate_overall_similarity(0.0, 0.0, 0.0, 0.0, 0.0)
        assert score == 0.0

    def test_calculate_overall_similarity_mixed(self):
        score = calculate_overall_similarity(0.5, 0.5, 0.5, 0.5, 0.5)
        assert score == 0.5


class TestStringClassification:
    """Direct tests for string classification helpers used by BinDiff."""

    def test_is_api_string(self):
        assert is_api_string("CreateFile") is True

    def test_is_path_string(self):
        assert is_path_string("C:\\Windows\\System32") is True

    def test_is_url_string(self):
        assert is_url_string("http://example.com") is True

    def test_is_registry_string(self):
        assert is_registry_string("HKEY_LOCAL_MACHINE\\SOFTWARE") is True


class TestBinDiffStaticMethods:
    """Verify static methods on BinDiffAnalyzer delegate correctly."""

    def test_static_rolling_hash(self):
        result = BinDiffAnalyzer._calculate_rolling_hash(b"X" * 200)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_static_cyclomatic_complexity(self):
        assert (
            BinDiffAnalyzer._calculate_cyclomatic_complexity({"blocks": [1, 2], "edges": [[0, 1]]})
            == 1
        )

    def test_static_categorize_similarity(self):
        assert BinDiffAnalyzer._categorize_similarity(0.9) == "Very High"

    def test_static_indicator_methods(self):
        assert BinDiffAnalyzer._has_crypto_indicators("AES") is True
        assert BinDiffAnalyzer._has_network_indicators("http") is True
        assert BinDiffAnalyzer._has_persistence_indicators("autorun") is True
        assert BinDiffAnalyzer._is_suspicious_api("CreateRemoteThread") is True
        assert BinDiffAnalyzer._is_crypto_api("CryptEncrypt") is True
        assert BinDiffAnalyzer._is_network_api("WSAStartup") is True

    def test_static_string_classification(self):
        assert BinDiffAnalyzer._is_api_string("CreateFile") is True
        assert BinDiffAnalyzer._is_path_string("C:\\test") is True
        assert BinDiffAnalyzer._is_url_string("http://x") is True
        assert BinDiffAnalyzer._is_registry_string("HKEY_LOCAL_MACHINE\\SOFTWARE") is True
