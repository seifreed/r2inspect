#!/usr/bin/env python3
"""Extra coverage tests for compiler_detector module.

No unittest.mock, no MagicMock, no patch. Real objects and plain adapters only.
"""

import pytest

from r2inspect.modules.compiler_detector import CompilerDetector


class FakeAdapter:
    def __init__(self, file_info=None, imports=None, sections=None, symbols=None, strings=None):
        self._file_info = file_info or {}
        self._imports = imports or []
        self._sections = sections or []
        self._symbols = symbols or []
        self._strings = strings or []

    def get_file_info(self):
        return self._file_info

    def get_imports(self):
        return self._imports

    def get_sections(self):
        return self._sections

    def get_symbols(self):
        return self._symbols

    def get_strings(self):
        return self._strings

    def cmd(self, command):
        return ""

    def cmdj(self, command, default=None):
        return default


def test_compiler_detector_init():
    """Test CompilerDetector initialization"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter, config=None)

    assert detector.adapter is adapter
    assert detector.r2 is adapter
    assert detector.config is None
    assert "MSVC" in detector.compiler_signatures
    assert "MSVCR140.dll" in detector.msvc_versions


def test_get_file_format_pe():
    """Test _get_file_format for PE files"""
    file_info = {"bin": {"class": "PE32"}}
    adapter = FakeAdapter(file_info=file_info)
    detector = CompilerDetector(adapter)

    fmt = detector._get_file_format()
    assert fmt == "PE"


def test_get_file_format_elf():
    """Test _get_file_format for ELF files"""
    file_info = {"bin": {"class": "ELF64"}}
    adapter = FakeAdapter(file_info=file_info)
    detector = CompilerDetector(adapter)

    fmt = detector._get_file_format()
    assert fmt == "ELF"


def test_get_file_format_macho():
    """Test _get_file_format for Mach-O files"""
    file_info = {"bin": {"class": "MACH064"}}
    adapter = FakeAdapter(file_info=file_info)
    detector = CompilerDetector(adapter)

    fmt = detector._get_file_format()
    assert fmt == "Mach-O"


def test_get_file_format_unknown():
    """Test _get_file_format for unknown format"""
    file_info = {"bin": {"class": "UNKNOWN"}}
    adapter = FakeAdapter(file_info=file_info)
    detector = CompilerDetector(adapter)

    fmt = detector._get_file_format()
    assert fmt == "Unknown"


def test_get_file_format_no_bin():
    """Test _get_file_format with missing bin info"""
    adapter = FakeAdapter(file_info={})
    detector = CompilerDetector(adapter)

    fmt = detector._get_file_format()
    assert fmt == "Unknown"


def test_get_file_format_error():
    """Test _get_file_format handles errors when adapter raises"""

    class ErrorAdapter(FakeAdapter):
        def get_file_info(self):
            raise Exception("test error")

    adapter = ErrorAdapter()
    detector = CompilerDetector(adapter)
    fmt = detector._get_file_format()
    assert fmt == "Unknown"


def test_get_strings_with_adapter():
    """Test _get_strings uses adapter when available"""
    strings = [{"string": "test1"}, {"string": "test2"}, {"other": "skip"}]
    adapter = FakeAdapter(strings=strings)
    detector = CompilerDetector(adapter)

    result = detector._get_strings()
    assert result == ["test1", "test2"]


def test_get_strings_error():
    """Test _get_strings handles errors"""

    class ErrorAdapter(FakeAdapter):
        def get_strings(self):
            raise Exception("test error")

    adapter = ErrorAdapter()
    detector = CompilerDetector(adapter)

    result = detector._get_strings()
    assert result == []


def test_get_imports():
    """Test _get_imports"""
    imports = [{"name": "CreateFileA"}, {"name": "RegSetValue"}]
    adapter = FakeAdapter(imports=imports)
    detector = CompilerDetector(adapter)

    result = detector._get_imports()
    assert isinstance(result, list)


def test_get_imports_error():
    """Test _get_imports handles errors"""

    class ErrorAdapter(FakeAdapter):
        def get_imports(self):
            raise Exception("test error")

    adapter = ErrorAdapter()
    detector = CompilerDetector(adapter)

    result = detector._get_imports()
    assert result == []


def test_get_sections():
    """Test _get_sections"""
    sections = [{"name": ".text"}, {"name": ".data"}]
    adapter = FakeAdapter(sections=sections)
    detector = CompilerDetector(adapter)

    result = detector._get_sections()
    assert isinstance(result, list)


def test_get_sections_error():
    """Test _get_sections handles errors"""

    class ErrorAdapter(FakeAdapter):
        def get_sections(self):
            raise Exception("test error")

    adapter = ErrorAdapter()
    detector = CompilerDetector(adapter)

    result = detector._get_sections()
    assert result == []


def test_get_symbols():
    """Test _get_symbols"""
    symbols = [{"name": "main"}, {"name": "printf"}]
    adapter = FakeAdapter(symbols=symbols)
    detector = CompilerDetector(adapter)

    result = detector._get_symbols()
    assert isinstance(result, list)


def test_get_symbols_error():
    """Test _get_symbols handles errors"""

    class ErrorAdapter(FakeAdapter):
        def get_symbols(self):
            raise Exception("test error")

    adapter = ErrorAdapter()
    detector = CompilerDetector(adapter)

    result = detector._get_symbols()
    assert result == []


def test_coerce_dict_list_with_list():
    """Test _coerce_dict_list with list input"""
    input_list = [{"a": 1}, {"b": 2}, "not_dict"]
    result = CompilerDetector._coerce_dict_list(input_list)
    assert result == [{"a": 1}, {"b": 2}]


def test_coerce_dict_list_with_dict():
    """Test _coerce_dict_list with dict input"""
    input_dict = {"a": 1}
    result = CompilerDetector._coerce_dict_list(input_dict)
    assert result == [{"a": 1}]


def test_coerce_dict_list_with_other():
    """Test _coerce_dict_list with other types"""
    assert CompilerDetector._coerce_dict_list("string") == []
    assert CompilerDetector._coerce_dict_list(123) == []
    assert CompilerDetector._coerce_dict_list(None) == []


def test_get_imports_raw():
    """Test _get_imports_raw returns list"""
    imports = [{"name": "test"}]
    adapter = FakeAdapter(imports=imports)
    detector = CompilerDetector(adapter)

    result = detector._get_imports_raw()
    assert isinstance(result, list)


def test_get_sections_raw():
    """Test _get_sections_raw returns list"""
    sections = [{"name": ".text"}]
    adapter = FakeAdapter(sections=sections)
    detector = CompilerDetector(adapter)

    result = detector._get_sections_raw()
    assert isinstance(result, list)


def test_get_symbols_raw():
    """Test _get_symbols_raw returns list"""
    symbols = [{"name": "main"}]
    adapter = FakeAdapter(symbols=symbols)
    detector = CompilerDetector(adapter)

    result = detector._get_symbols_raw()
    assert isinstance(result, list)


def test_detect_intel_version():
    """Test _detect_intel_version returns Unknown"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_intel_version([], [])
    assert result == "Unknown"


def test_detect_borland_version():
    """Test _detect_borland_version returns Unknown"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_borland_version([], [])
    assert result == "Unknown"


def test_detect_mingw_version():
    """Test _detect_mingw_version returns Unknown"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_mingw_version([], [])
    assert result == "Unknown"


def test_detect_delphi_version():
    """Test _detect_delphi_version returns Unknown"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_delphi_version([], [])
    assert result == "Unknown"


def test_detect_compiler_version_msvc():
    """Test _detect_compiler_version calls MSVC detector"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_compiler_version("MSVC", ["MSVCR140.dll"], ["MSVCR140.dll"])
    assert isinstance(result, str)


def test_detect_compiler_version_gcc():
    """Test _detect_compiler_version calls GCC detector"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_compiler_version("GCC", ["GCC: (Ubuntu 9.3.0)"], [])
    assert isinstance(result, str)


def test_detect_compiler_version_clang():
    """Test _detect_compiler_version calls Clang detector"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_compiler_version("Clang", ["clang version 11.0"], [])
    assert isinstance(result, str)


def test_detect_compiler_version_go():
    """Test _detect_compiler_version calls Go detector"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_compiler_version("Go", ["go1.16"], [])
    assert isinstance(result, str)


def test_detect_compiler_version_rust():
    """Test _detect_compiler_version calls Rust detector"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_compiler_version("Rust", ["rustc 1.50"], [])
    assert isinstance(result, str)


def test_detect_compiler_version_unknown_compiler():
    """Test _detect_compiler_version returns Unknown for unknown compiler"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_compiler_version("UnknownCompiler", [], [])
    assert result == "Unknown"


def test_detect_compiler_no_signatures():
    """Test detect_compiler with no matching signatures"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector.detect_compiler()
    # With empty adapter, no signatures match; compiler should be Unknown.
    assert isinstance(result, dict)
    assert result.get("compiler", "Unknown") == "Unknown"


def test_detect_compiler_error():
    """Test detect_compiler handles errors"""

    class ErrorAdapter(FakeAdapter):
        def get_file_info(self):
            raise Exception("test error")

        def get_imports(self):
            raise Exception("test error")

        def get_sections(self):
            raise Exception("test error")

        def get_symbols(self):
            raise Exception("test error")

        def get_strings(self):
            raise Exception("test error")

    adapter = ErrorAdapter()
    detector = CompilerDetector(adapter)

    result = detector.detect_compiler()
    assert isinstance(result, dict)
    # With all-error adapter, detection fails gracefully.
    assert result.get("detected") is False or "error" in result


def test_analyze_rich_header_no_file_info():
    """Test _analyze_rich_header with no file info"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._analyze_rich_header()
    assert isinstance(result, dict)


def test_analyze_rich_header_no_filepath():
    """Test _analyze_rich_header with no filepath in file info"""
    file_info = {"core": {}}
    adapter = FakeAdapter(file_info=file_info)
    detector = CompilerDetector(adapter)

    result = detector._analyze_rich_header()
    assert isinstance(result, dict)


def test_analyze_rich_header_error():
    """Test _analyze_rich_header handles errors"""

    class ErrorAdapter(FakeAdapter):
        def get_file_info(self):
            raise Exception("test error")

    adapter = ErrorAdapter()
    detector = CompilerDetector(adapter)

    result = detector._analyze_rich_header()
    assert result == {}


def test_apply_rich_header_detection_not_available():
    """Test _apply_rich_header_detection when rich header not available"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    results = {"detected": False}
    should_return = detector._apply_rich_header_detection(results)
    assert should_return is False


def test_score_compilers():
    """Test _score_compilers returns dict"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    scores = detector._score_compilers([], [], [], [])
    assert isinstance(scores, dict)


def test_apply_best_compiler_no_scores():
    """Test _apply_best_compiler with empty scores"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    results = {}
    detector._apply_best_compiler(results, {}, [], [], "PE")
    assert "detected" not in results


def test_detect_msvc_version_delegation():
    """Test _detect_msvc_version delegates correctly"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_msvc_version(["VCRUNTIME140.dll"], ["VCRUNTIME140.dll"])
    assert isinstance(result, str)


def test_detect_gcc_version_delegation():
    """Test _detect_gcc_version delegates correctly"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_gcc_version(["GCC: (Ubuntu 9.3.0)"], [])
    assert isinstance(result, str)


def test_detect_clang_version_delegation():
    """Test _detect_clang_version delegates correctly"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_clang_version(["clang version 11.0"], [])
    assert isinstance(result, str)


def test_detect_go_version_delegation():
    """Test _detect_go_version delegates correctly"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_go_version(["go1.16"], [])
    assert isinstance(result, str)


def test_detect_rust_version_delegation():
    """Test _detect_rust_version delegates correctly"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._detect_rust_version(["rustc 1.50"], [])
    assert isinstance(result, str)


def test_get_strings_raw():
    """Test _get_strings_raw"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._get_strings_raw()
    assert isinstance(result, str)


def test_get_strings_raw_returns_string():
    """Test _get_strings_raw returns empty string for adapter with empty cmd"""
    adapter = FakeAdapter()
    detector = CompilerDetector(adapter)

    result = detector._get_strings_raw()
    assert result == ""
