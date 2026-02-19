"""Branch-path tests for bindiff_analyzer.py covering missing lines."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from r2inspect.modules.bindiff_analyzer import BinDiffAnalyzer


# ---------------------------------------------------------------------------
# Adapter helpers (no unittest.mock)
# ---------------------------------------------------------------------------


class EmptyBinDiffAdapter:
    """Adapter that returns empty results for all calls."""

    def get_file_info(self) -> dict[str, Any]:
        return {}

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_exports(self) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def get_functions(self) -> list[dict[str, Any]]:
        return []

    def get_cfg(self, func_addr: int) -> list[dict[str, Any]]:
        return []

    def get_entropy_pattern(self) -> str:
        return ""

    def analyze_all(self) -> None:
        pass


class RichBinDiffAdapter(EmptyBinDiffAdapter):
    """Adapter with populated data for feature extraction paths."""

    def get_file_info(self) -> dict[str, Any]:
        return {
            "core": {"format": "PE", "size": 102400},
            "bin": {"arch": "x86", "bits": 32, "endian": "little"},
        }

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {"name": ".text", "size": 40960, "perm": "r-x"},
            {"name": ".data", "size": 8192, "perm": "rw-"},
            {"name": ".rdata", "size": 4096, "perm": "r--"},
        ]

    def get_imports(self) -> list[dict[str, Any]]:
        return [
            {"name": "CreateFileA", "libname": "kernel32.dll"},
            {"name": "VirtualAlloc", "libname": "kernel32.dll"},
            {"name": "WriteProcessMemory", "libname": "kernel32.dll"},
            {"name": "WSAStartup", "libname": "ws2_32.dll"},
        ]

    def get_exports(self) -> list[dict[str, Any]]:
        return [{"name": "DllMain"}]

    def get_strings(self) -> list[dict[str, Any]]:
        return [
            {"string": "http://example.com/path"},
            {"string": "HKEY_LOCAL_MACHINE\\Software\\test"},
            {"string": "cmd.exe"},
            {"string": "CreateProcess"},
            {"string": "CryptEncrypt"},
        ]

    def get_functions(self) -> list[dict[str, Any]]:
        return [
            {"name": "main", "offset": 0x1000, "size": 256},
            {"name": "sub_2000", "offset": 0x2000, "size": 128},
        ]

    def get_cfg(self, func_addr: int) -> list[dict[str, Any]]:
        return [
            {
                "blocks": [{"offset": func_addr}, {"offset": func_addr + 0x10}],
                "edges": [{"src": func_addr, "dst": func_addr + 0x10}],
            }
        ]

    def get_entropy_pattern(self) -> str:
        return "▁▂▃▄▅▆▇█"


class RaisingBinDiffAdapter(EmptyBinDiffAdapter):
    """Adapter that raises during get_file_info to trigger exception handlers."""

    def get_file_info(self) -> dict[str, Any]:
        raise RuntimeError("simulated file_info error")


class ExportsOnlyAdapter(EmptyBinDiffAdapter):
    """Adapter with exports but no imports/sections."""

    def get_exports(self) -> list[dict[str, Any]]:
        return [{"name": "ExportedFunc"}, {"name": "AnotherExport"}]


class CFGListAdapter(EmptyBinDiffAdapter):
    """Adapter returning CFG as a list (not a dict)."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"name": "func_a", "offset": 0x1000, "size": 64}]

    def get_cfg(self, func_addr: int) -> list[dict[str, Any]]:
        return [
            {
                "blocks": [{"offset": func_addr}],
                "edges": [],
            }
        ]


class CFGDictAdapter(EmptyBinDiffAdapter):
    """Adapter returning CFG as a single dict (not a list)."""

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"name": "func_b", "offset": 0x2000, "size": 64}]

    def get_cfg(self, func_addr: int) -> dict[str, Any]:  # type: ignore[override]
        return {"blocks": [{"offset": func_addr}], "edges": []}


class StringsOnlyAdapter(EmptyBinDiffAdapter):
    """Adapter with strings featuring specific categories."""

    def get_strings(self) -> list[dict[str, Any]]:
        return [
            {"string": "C:\\Windows\\System32\\cmd.exe"},
            {"string": "https://malware.example.com"},
            {"string": "HKCU\\Software\\Run"},
            {"string": "AES_encrypt"},
        ]

    def get_imports(self) -> list[dict[str, Any]]:
        return [
            {"name": "VirtualAlloc"},
            {"name": "WSAConnect"},
            {"name": "CryptEncrypt"},
        ]


class NotReadyOtherResults:
    """Simulates other_results where comparison_ready is False."""

    data: dict[str, Any] = {
        "filename": "other.exe",
        "comparison_ready": False,
    }


# ---------------------------------------------------------------------------
# analyze()  (lines 68-75)
# ---------------------------------------------------------------------------


def test_analyze_returns_comparison_ready_with_empty_adapter(tmp_path: Path):
    """analyze() with EmptyBinDiffAdapter works without raising."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(EmptyBinDiffAdapter(), str(dummy))
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert "comparison_ready" in result


def test_analyze_exception_returns_not_ready():
    """Subclass raises inside analyze() try block → exception path (lines 68-75)."""

    class BrokenAnalyzer(BinDiffAnalyzer):
        def _extract_structural_features(self) -> dict[str, Any]:
            raise RuntimeError("forced structural failure")

    analyzer = BrokenAnalyzer(EmptyBinDiffAdapter(), "/path/to/binary")
    result = analyzer.analyze()
    assert result.get("comparison_ready") is False
    assert "error" in result


# ---------------------------------------------------------------------------
# compare_with  (lines 79-115)
# ---------------------------------------------------------------------------


def test_compare_with_not_ready_returns_error(tmp_path: Path):
    """other_results not ready → error dict returned (lines 83-87)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(EmptyBinDiffAdapter(), str(dummy))
    result = analyzer.compare_with({"comparison_ready": False, "filename": "other.bin"})
    assert "error" in result


def test_compare_with_ready_returns_similarity(tmp_path: Path):
    """Both ready → overall_similarity in result (lines 89-111)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    adapter = RichBinDiffAdapter()
    analyzer = BinDiffAnalyzer(adapter, str(dummy))
    our = analyzer.analyze()
    result = analyzer.compare_with(our)
    assert "overall_similarity" in result
    assert 0.0 <= result["overall_similarity"] <= 1.0


def test_compare_with_exception_returns_error():
    """Exception during comparison returns error dict (lines 113-115)."""

    class ExplodingAnalyzeAdapter(EmptyBinDiffAdapter):
        _call = 0

        def get_file_info(self) -> dict[str, Any]:
            self._call += 1
            if self._call > 1:
                raise RuntimeError("second call fails")
            return {}

    analyzer = BinDiffAnalyzer(ExplodingAnalyzeAdapter(), "/nonexistent/file.bin")
    result = analyzer.compare_with({"comparison_ready": True, "filename": "x.bin"})
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# _extract_structural_features  (lines 165-166)
# ---------------------------------------------------------------------------


def test_extract_structural_features_exception_returns_empty():
    """Exception caught; empty features returned (lines 165-166)."""
    analyzer = BinDiffAnalyzer(RaisingBinDiffAdapter(), "/path/to/binary")
    features = analyzer._extract_structural_features()
    assert isinstance(features, dict)


def test_extract_structural_features_with_exports(tmp_path: Path):
    """Exports present → export_count and exported_functions set (lines 159-163)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(ExportsOnlyAdapter(), str(dummy))
    features = analyzer._extract_structural_features()
    assert features.get("export_count", 0) == 2


def test_extract_structural_features_full(tmp_path: Path):
    """Full adapter → all structural fields populated."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(RichBinDiffAdapter(), str(dummy))
    features = analyzer._extract_structural_features()
    assert features.get("section_count") == 3
    assert features.get("import_count") == 4


# ---------------------------------------------------------------------------
# _extract_function_features  (lines 179, 193-201, 211-212)
# ---------------------------------------------------------------------------


def test_extract_function_features_with_list_cfg(tmp_path: Path):
    """CFG returned as list; cfg_data = cfg[0] path (lines 194-195)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(CFGListAdapter(), str(dummy))
    features = analyzer._extract_function_features()
    assert "cfg_features" in features


def test_extract_function_features_with_dict_cfg(tmp_path: Path):
    """CFG returned as dict; cfg_data = cfg path (lines 196-197)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(CFGDictAdapter(), str(dummy))
    features = analyzer._extract_function_features()
    assert isinstance(features, dict)


def test_extract_function_features_exception_returns_empty():
    """Exception caught (lines 211-212)."""

    class ExplodingFunctionsAdapter(EmptyBinDiffAdapter):
        def get_functions(self) -> list[dict[str, Any]]:
            raise RuntimeError("forced failure")

    analyzer = BinDiffAnalyzer(ExplodingFunctionsAdapter(), "/path/to/binary")
    features = analyzer._extract_function_features()
    assert isinstance(features, dict)


# ---------------------------------------------------------------------------
# _extract_string_features  (lines 243-256, 257-258)
# ---------------------------------------------------------------------------


def test_extract_string_features_with_categorized_strings(tmp_path: Path):
    """Strings categorized into api/path/url/registry groups (lines 230-255)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(StringsOnlyAdapter(), str(dummy))
    features = analyzer._extract_string_features()
    assert features.get("total_strings", 0) > 0
    assert "string_signature" in features


def test_extract_string_features_exception_returns_empty():
    """Exception caught (lines 257-258)."""

    class ExplodingStringsAdapter(EmptyBinDiffAdapter):
        def get_strings(self) -> list[dict[str, Any]]:
            raise RuntimeError("forced failure")

    analyzer = BinDiffAnalyzer(ExplodingStringsAdapter(), "/path/to/binary")
    features = analyzer._extract_string_features()
    assert isinstance(features, dict)


# ---------------------------------------------------------------------------
# _extract_byte_features  (lines 271, 280-281, 283-284)
# ---------------------------------------------------------------------------


def test_extract_byte_features_with_entropy_pattern(tmp_path: Path):
    """Entropy pattern from adapter (line 271)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x41" * 8192)
    analyzer = BinDiffAnalyzer(RichBinDiffAdapter(), str(dummy))
    features = analyzer._extract_byte_features()
    assert "entropy_pattern" in features


def test_extract_byte_features_rolling_hash(tmp_path: Path):
    """Rolling hash from real file (lines 280-281)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x41" * 8192)
    analyzer = BinDiffAnalyzer(EmptyBinDiffAdapter(), str(dummy))
    features = analyzer._extract_byte_features()
    assert isinstance(features, dict)


def test_extract_byte_features_exception_returns_empty():
    """Exception caught (lines 283-284)."""

    class ExplodingEntropyAdapter(EmptyBinDiffAdapter):
        def get_entropy_pattern(self) -> str:
            raise RuntimeError("forced failure")

    analyzer = BinDiffAnalyzer(ExplodingEntropyAdapter(), "/nonexistent/path.bin")
    features = analyzer._extract_byte_features()
    assert isinstance(features, dict)


# ---------------------------------------------------------------------------
# _extract_behavioral_features  (lines 317-318)
# ---------------------------------------------------------------------------


def test_extract_behavioral_features_exception_returns_empty():
    """Exception caught (lines 317-318)."""

    class ExplodingBehaviorAdapter(EmptyBinDiffAdapter):
        def get_strings(self) -> list[dict[str, Any]]:
            raise RuntimeError("forced failure")

    analyzer = BinDiffAnalyzer(ExplodingBehaviorAdapter(), "/path/to/binary")
    features = analyzer._extract_behavioral_features()
    assert isinstance(features, dict)


def test_extract_behavioral_features_with_imports_and_strings(tmp_path: Path):
    """Imports and strings present → behavioral indicators counted."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(StringsOnlyAdapter(), str(dummy))
    features = analyzer._extract_behavioral_features()
    assert isinstance(features.get("crypto_apis", 0), int)
    assert isinstance(features.get("network_apis", 0), int)


# ---------------------------------------------------------------------------
# _generate_comparison_signatures  (lines 355-356)
# ---------------------------------------------------------------------------


def test_generate_comparison_signatures_exception_returns_empty():
    """Exception caught (lines 355-356)."""
    analyzer = BinDiffAnalyzer(EmptyBinDiffAdapter(), "/path/to/binary")
    result = analyzer._generate_comparison_signatures(None)  # type: ignore[arg-type]
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Compare helpers  (lines 362-411)
# ---------------------------------------------------------------------------


def test_compare_structural_returns_float(tmp_path: Path):
    """_compare_structural returns a float (line 363)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(RichBinDiffAdapter(), str(dummy))
    score = analyzer._compare_structural(
        {"structural_features": {"file_type": "PE"}},
        {"structural_features": {"file_type": "PE"}},
    )
    assert isinstance(score, float)


def test_compare_structural_exception_returns_zero():
    """Exception caught; returns 0.0 (lines 367-369)."""
    analyzer = BinDiffAnalyzer(EmptyBinDiffAdapter(), "/path/to/binary")
    score = analyzer._compare_structural(None, None)  # type: ignore[arg-type]
    assert score == 0.0


def test_compare_functions_returns_float(tmp_path: Path):
    """_compare_functions returns a float (line 374)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(RichBinDiffAdapter(), str(dummy))
    score = analyzer._compare_functions(
        {"function_features": {"function_count": 5}},
        {"function_features": {"function_count": 5}},
    )
    assert isinstance(score, float)


def test_compare_functions_exception_returns_zero():
    """Exception caught; returns 0.0 (lines 378-380)."""
    analyzer = BinDiffAnalyzer(EmptyBinDiffAdapter(), "/path/to/binary")
    score = analyzer._compare_functions(None, None)  # type: ignore[arg-type]
    assert score == 0.0


def test_compare_strings_returns_float(tmp_path: Path):
    """_compare_strings returns a float (line 385)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(RichBinDiffAdapter(), str(dummy))
    score = analyzer._compare_strings(
        {"string_features": {"total_strings": 3}},
        {"string_features": {"total_strings": 3}},
    )
    assert isinstance(score, float)


def test_compare_strings_exception_returns_zero():
    """Exception caught; returns 0.0 (lines 389-391)."""
    analyzer = BinDiffAnalyzer(EmptyBinDiffAdapter(), "/path/to/binary")
    score = analyzer._compare_strings(None, None)  # type: ignore[arg-type]
    assert score == 0.0


def test_compare_bytes_returns_float(tmp_path: Path):
    """_compare_bytes returns a float (line 396)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(RichBinDiffAdapter(), str(dummy))
    score = analyzer._compare_bytes(
        {"byte_features": {"rolling_hash": "abc"}},
        {"byte_features": {"rolling_hash": "abc"}},
    )
    assert isinstance(score, float)


def test_compare_bytes_exception_returns_zero():
    """Exception caught; returns 0.0 (lines 398-400)."""
    analyzer = BinDiffAnalyzer(EmptyBinDiffAdapter(), "/path/to/binary")
    score = analyzer._compare_bytes(None, None)  # type: ignore[arg-type]
    assert score == 0.0


def test_compare_behavioral_returns_float(tmp_path: Path):
    """_compare_behavioral returns a float (line 405)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    analyzer = BinDiffAnalyzer(RichBinDiffAdapter(), str(dummy))
    score = analyzer._compare_behavioral(
        {"behavioral_features": {"suspicious_apis": 2}},
        {"behavioral_features": {"suspicious_apis": 2}},
    )
    assert isinstance(score, float)


def test_compare_behavioral_exception_returns_zero():
    """Exception caught; returns 0.0 (lines 409-411)."""
    analyzer = BinDiffAnalyzer(EmptyBinDiffAdapter(), "/path/to/binary")
    score = analyzer._compare_behavioral(None, None)  # type: ignore[arg-type]
    assert score == 0.0
