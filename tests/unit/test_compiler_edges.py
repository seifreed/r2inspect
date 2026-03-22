"""Edge case tests for compiler_detector.py - covering missing branches.

All tests use FakeR2 + R2PipeAdapter instead of mocks.
"""

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.compiler_detector import CompilerDetector
from r2inspect.testing.fake_r2 import FakeR2


def _make_detector(*, cmdj_map=None, cmd_map=None):
    """Build a CompilerDetector backed by FakeR2 + R2PipeAdapter."""
    r2 = FakeR2(cmd_map=cmd_map or {}, cmdj_map=cmdj_map or {})
    adapter = R2PipeAdapter(r2)
    return CompilerDetector(adapter)


# ---------------------------------------------------------------------------
# _apply_rich_header_detection  (relies on _analyze_rich_header which calls
# _get_file_info -> adapter.get_file_info -> cmdj("ij") and then
# RichHeaderAnalyzer.  Since RichHeaderAnalyzer is a full module, we exercise
# the code paths through the real method by controlling ij responses.)
# ---------------------------------------------------------------------------


def test_apply_rich_header_detection_not_available():
    """Rich header path when file info lacks core -> returns {}."""
    detector = _make_detector(cmdj_map={"ij": {}})
    results = {}

    result = detector._apply_rich_header_detection(results)

    # _analyze_rich_header returns {} when "core" not in file_info
    # apply_rich_header_detection stores it as rich_header_info and returns False
    assert result is False


def test_apply_rich_header_detection_no_core():
    """Rich header path when ij returns None."""
    detector = _make_detector(cmdj_map={"ij": None})
    results = {}

    result = detector._apply_rich_header_detection(results)

    assert result is False


# ---------------------------------------------------------------------------
# _score_compilers
# ---------------------------------------------------------------------------


def test_score_compilers_empty():
    detector = _make_detector()
    detector.compiler_signatures = {}

    result = detector._score_compilers([], [], [], [])

    assert result == {}


# ---------------------------------------------------------------------------
# _apply_best_compiler
# ---------------------------------------------------------------------------


def test_apply_best_compiler_empty_scores():
    detector = _make_detector()
    results = {}

    detector._apply_best_compiler(results, {}, [], [], "PE")

    assert results == {}


def test_apply_best_compiler_low_score():
    detector = _make_detector()
    results = {}

    detector._apply_best_compiler(results, {"GCC": 0.2}, [], [], "ELF")

    # Score 0.2 <= 0.3 threshold -> no detection
    assert results == {}


def test_apply_best_compiler_high_score():
    detector = _make_detector()
    results = {}

    detector._apply_best_compiler(
        results,
        {"GCC": 0.8, "Clang": 0.5},
        ["GCC version"],
        [],
        "ELF",
    )

    assert results["detected"] is True
    assert results["compiler"] == "GCC"
    assert results["confidence"] == 0.8
    assert results["details"]["file_format"] == "ELF"


# ---------------------------------------------------------------------------
# _get_file_format
# ---------------------------------------------------------------------------


def test_get_file_format_pe():
    detector = _make_detector(cmdj_map={"ij": {"bin": {"class": "PE32"}}})

    result = detector._get_file_format()

    assert result == "PE"


def test_get_file_format_elf():
    detector = _make_detector(cmdj_map={"ij": {"bin": {"class": "ELF64"}}})

    result = detector._get_file_format()

    assert result == "ELF"


def test_get_file_format_macho():
    detector = _make_detector(cmdj_map={"ij": {"bin": {"class": "Mach-O64"}}})

    result = detector._get_file_format()

    assert result == "Mach-O"


def test_get_file_format_unknown():
    detector = _make_detector(cmdj_map={"ij": {"bin": {"class": "UNKNOWN"}}})

    result = detector._get_file_format()

    assert result == "Unknown"


def test_get_file_format_no_bin():
    detector = _make_detector(cmdj_map={"ij": {}})

    result = detector._get_file_format()

    assert result == "Unknown"


def test_get_file_format_no_info():
    """When ij returns None, get_file_info returns {} -> Unknown."""
    detector = _make_detector(cmdj_map={"ij": None})

    result = detector._get_file_format()

    assert result == "Unknown"


# ---------------------------------------------------------------------------
# _get_strings
# ---------------------------------------------------------------------------


def test_get_strings_from_adapter():
    detector = _make_detector(
        cmdj_map={
            "izzj": [
                {"string": "Hello"},
                {"string": "World"},
                {"other": "field"},
            ]
        }
    )

    result = detector._get_strings()

    assert "Hello" in result
    assert "World" in result


def test_get_strings_empty():
    detector = _make_detector(cmdj_map={"izzj": []})

    result = detector._get_strings()

    assert isinstance(result, list)
    assert result == []


# ---------------------------------------------------------------------------
# _get_imports
# ---------------------------------------------------------------------------


def test_get_imports_from_adapter():
    detector = _make_detector(cmdj_map={"iij": [{"name": "CreateProcess", "ordinal": 1}]})

    result = detector._get_imports()

    assert isinstance(result, list)


def test_get_imports_empty():
    detector = _make_detector(cmdj_map={"iij": []})

    result = detector._get_imports()

    assert result == []


# ---------------------------------------------------------------------------
# _get_sections
# ---------------------------------------------------------------------------


def test_get_sections_from_adapter():
    detector = _make_detector(cmdj_map={"iSj": [{"name": ".text", "size": 1000}]})

    result = detector._get_sections()

    assert isinstance(result, list)


def test_get_sections_empty():
    detector = _make_detector(cmdj_map={"iSj": []})

    result = detector._get_sections()

    assert result == []


# ---------------------------------------------------------------------------
# _get_symbols
# ---------------------------------------------------------------------------


def test_get_symbols_from_adapter():
    detector = _make_detector(cmdj_map={"isj": [{"name": "main", "vaddr": 0x400000}]})

    result = detector._get_symbols()

    assert isinstance(result, list)


def test_get_symbols_empty():
    detector = _make_detector(cmdj_map={"isj": []})

    result = detector._get_symbols()

    assert result == []


# ---------------------------------------------------------------------------
# _analyze_rich_header
# ---------------------------------------------------------------------------


def test_analyze_rich_header_no_file_info():
    """ij returns None -> get_file_info returns {} -> no 'core' -> {}."""
    detector = _make_detector(cmdj_map={"ij": None})

    result = detector._analyze_rich_header()

    assert result == {}


def test_analyze_rich_header_no_core():
    """ij returns dict without 'core' key."""
    detector = _make_detector(cmdj_map={"ij": {"bin": {"class": "PE32"}}})

    result = detector._analyze_rich_header()

    assert result == {}


def test_analyze_rich_header_no_file():
    """core present but no 'file' key."""
    detector = _make_detector(cmdj_map={"ij": {"core": {}}})

    result = detector._analyze_rich_header()

    assert result == {}


# ---------------------------------------------------------------------------
# Version detectors (simple passthrough, always "Unknown" for these)
# ---------------------------------------------------------------------------


def test_detect_intel_version():
    detector = _make_detector()

    result = detector._detect_intel_version([], [])

    assert result == "Unknown"


def test_detect_borland_version():
    detector = _make_detector()

    result = detector._detect_borland_version([], [])

    assert result == "Unknown"


def test_detect_mingw_version():
    detector = _make_detector()

    result = detector._detect_mingw_version([], [])

    assert result == "Unknown"


def test_detect_delphi_version():
    detector = _make_detector()

    result = detector._detect_delphi_version([], [])

    assert result == "Unknown"


# ---------------------------------------------------------------------------
# _coerce_dict_list (static method)
# ---------------------------------------------------------------------------


def test_coerce_dict_list_dict():
    detector = _make_detector()

    result = detector._coerce_dict_list({"key": "value"})

    assert result == [{"key": "value"}]


def test_coerce_dict_list_non_dict():
    detector = _make_detector()

    result = detector._coerce_dict_list("string")

    assert result == []


def test_coerce_dict_list_mixed():
    detector = _make_detector()

    result = detector._coerce_dict_list([{"a": 1}, "not_dict", {"b": 2}])

    assert len(result) == 2
    assert {"a": 1} in result
    assert {"b": 2} in result


# ---------------------------------------------------------------------------
# _get_file_info
# ---------------------------------------------------------------------------


def test_get_file_info_returns_dict():
    detector = _make_detector(cmdj_map={"ij": {"core": {"file": "/bin/ls"}}})

    result = detector._get_file_info()

    assert isinstance(result, dict)
    assert result.get("core", {}).get("file") == "/bin/ls"


def test_get_file_info_empty():
    """When ij returns None, get_file_info returns {}."""
    detector = _make_detector(cmdj_map={"ij": None})

    result = detector._get_file_info()

    assert result == {}


# ---------------------------------------------------------------------------
# _get_imports_raw
# ---------------------------------------------------------------------------


def test_get_imports_raw_adapter_method():
    detector = _make_detector(cmdj_map={"iij": [{"name": "CreateProcess", "ordinal": 1}]})

    result = detector._get_imports_raw()

    assert isinstance(result, list)
    assert len(result) >= 1


# ---------------------------------------------------------------------------
# _get_sections_raw
# ---------------------------------------------------------------------------


def test_get_sections_raw_adapter_method():
    detector = _make_detector(cmdj_map={"iSj": [{"name": ".text", "size": 1000}]})

    result = detector._get_sections_raw()

    assert isinstance(result, list)
    assert len(result) >= 1


# ---------------------------------------------------------------------------
# _get_symbols_raw
# ---------------------------------------------------------------------------


def test_get_symbols_raw_adapter_method():
    detector = _make_detector(cmdj_map={"isj": [{"name": "main", "vaddr": 0x400000}]})

    result = detector._get_symbols_raw()

    assert isinstance(result, list)
    assert len(result) >= 1


# ---------------------------------------------------------------------------
# _detect_compiler_version dispatching
# ---------------------------------------------------------------------------


def test_detect_compiler_version_gcc():
    detector = _make_detector()

    result = detector._detect_compiler_version("GCC", ["GCC: (Ubuntu 4.8.5) 4.8.5"], [])

    # Real GCC version detection should parse the version string
    assert isinstance(result, str)


def test_detect_compiler_version_unknown_compiler():
    detector = _make_detector()

    result = detector._detect_compiler_version("UnknownCompiler", [], [])

    assert result == "Unknown"


# ---------------------------------------------------------------------------
# Full detect_compiler integration
# ---------------------------------------------------------------------------


def test_detect_compiler_elf_unknown():
    """Full detection with ELF format, no matching signatures."""
    detector = _make_detector(
        cmdj_map={
            "ij": {"bin": {"class": "ELF64"}},
            "izzj": [],
            "iij": [],
            "iSj": [],
            "isj": [],
        }
    )

    result = detector.detect_compiler()

    assert isinstance(result, dict)
    assert "detected" in result
    assert "compiler" in result


def test_detect_compiler_pe_no_rich_header():
    """PE format but no rich header -> falls through to scoring."""
    detector = _make_detector(
        cmdj_map={
            "ij": {"bin": {"class": "PE32"}},
            "izzj": [],
            "iij": [],
            "iSj": [],
            "isj": [],
        }
    )

    result = detector.detect_compiler()

    assert isinstance(result, dict)
    assert "detected" in result
