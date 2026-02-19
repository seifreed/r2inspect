"""Edge case tests for compiler_detector.py - covering missing branches."""

from unittest.mock import Mock

from r2inspect.modules.compiler_detector import CompilerDetector


def test_apply_rich_header_detection_not_available():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    detector._analyze_rich_header = Mock(return_value={"available": False})
    results = {}
    
    result = detector._apply_rich_header_detection(results)
    
    assert result is False
    assert results["rich_header_info"]["available"] is False


def test_apply_rich_header_detection_no_compilers():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    detector._analyze_rich_header = Mock(return_value={"available": True, "compilers": []})
    results = {}
    
    result = detector._apply_rich_header_detection(results)
    
    assert result is False


def test_apply_rich_header_detection_msvc_success():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    detector._analyze_rich_header = Mock(return_value={
        "available": True,
        "compilers": [{"compiler_name": "MSVC 19.0"}]
    })
    results = {}
    
    result = detector._apply_rich_header_detection(results)
    
    assert result is True
    assert results["detected"] is True
    assert results["compiler"] == "MSVC"
    assert results["confidence"] == 0.95


def test_apply_rich_header_detection_utc_success():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    detector._analyze_rich_header = Mock(return_value={
        "available": True,
        "compilers": [{"compiler_name": "Utc"}]
    })
    results = {}
    
    result = detector._apply_rich_header_detection(results)
    
    assert result is True
    assert results["compiler"] == "MSVC"


def test_apply_rich_header_detection_non_msvc():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    detector._analyze_rich_header = Mock(return_value={
        "available": True,
        "compilers": [{"compiler_name": "GCC"}]
    })
    results = {}
    
    result = detector._apply_rich_header_detection(results)
    
    assert result is False


def test_score_compilers_empty():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    detector.compiler_signatures = {}
    
    result = detector._score_compilers([], [], [], [])
    
    assert result == {}


def test_apply_best_compiler_empty_scores():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    results = {}
    
    detector._apply_best_compiler(results, {}, [], [], "PE")
    
    assert results == {}


def test_apply_best_compiler_low_score():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    results = {}
    
    detector._apply_best_compiler(results, {"GCC": 0.2}, [], [], "ELF")
    
    assert results == {}


def test_apply_best_compiler_high_score():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    detector._detect_compiler_version = Mock(return_value="4.8.5")
    results = {}
    
    detector._apply_best_compiler(
        results,
        {"GCC": 0.8, "Clang": 0.5},
        ["GCC version"],
        [],
        "ELF"
    )
    
    assert results["detected"] is True
    assert results["compiler"] == "GCC"
    assert results["confidence"] == 0.8
    assert results["version"] == "4.8.5"
    assert results["details"]["file_format"] == "ELF"


def test_get_file_format_pe():
    adapter = Mock()
    adapter.get_file_info.return_value = {"bin": {"class": "PE32"}}
    detector = CompilerDetector(adapter)
    
    result = detector._get_file_format()
    
    assert result == "PE"


def test_get_file_format_elf():
    adapter = Mock()
    adapter.get_file_info.return_value = {"bin": {"class": "ELF64"}}
    detector = CompilerDetector(adapter)
    
    result = detector._get_file_format()
    
    assert result == "ELF"


def test_get_file_format_macho():
    adapter = Mock()
    adapter.get_file_info.return_value = {"bin": {"class": "Mach-O64"}}
    detector = CompilerDetector(adapter)
    
    result = detector._get_file_format()
    
    assert result == "Mach-O"


def test_get_file_format_unknown():
    adapter = Mock()
    adapter.get_file_info.return_value = {"bin": {"class": "UNKNOWN"}}
    detector = CompilerDetector(adapter)
    
    result = detector._get_file_format()
    
    assert result == "Unknown"


def test_get_file_format_no_bin():
    adapter = Mock()
    adapter.get_file_info.return_value = {}
    detector = CompilerDetector(adapter)
    
    result = detector._get_file_format()
    
    assert result == "Unknown"


def test_get_file_format_exception():
    adapter = Mock()
    adapter.get_file_info.side_effect = Exception("Error")
    detector = CompilerDetector(adapter)
    
    result = detector._get_file_format()
    
    assert result == "Unknown"


def test_get_strings_from_adapter():
    adapter = Mock()
    adapter.get_strings.return_value = [
        {"string": "Hello"},
        {"string": "World"},
        {"other": "field"}
    ]
    detector = CompilerDetector(adapter)
    
    result = detector._get_strings()
    
    assert "Hello" in result
    assert "World" in result


def test_get_strings_no_adapter_method():
    adapter = Mock(spec=[])
    detector = CompilerDetector(adapter)
    detector._get_strings_raw = Mock(return_value="raw strings\nmore strings")
    
    result = detector._get_strings()
    
    assert isinstance(result, list)


def test_get_imports_exception():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    detector._get_imports_raw = Mock(side_effect=Exception("Error"))
    
    result = detector._get_imports()
    
    assert result == []


def test_get_sections_exception():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    detector._get_sections_raw = Mock(side_effect=Exception("Error"))
    
    result = detector._get_sections()
    
    assert result == []


def test_get_symbols_exception():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    detector._get_symbols_raw = Mock(side_effect=Exception("Error"))
    
    result = detector._get_symbols()
    
    assert result == []


def test_analyze_rich_header_exception():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    detector._get_file_info = Mock(side_effect=Exception("Error getting file info"))
    
    result = detector._analyze_rich_header()
    
    assert result == {}


def test_analyze_rich_header_no_file_info():
    adapter = Mock()
    adapter.get_file_info.return_value = None
    detector = CompilerDetector(adapter)
    
    result = detector._analyze_rich_header()
    
    assert result == {}


def test_analyze_rich_header_no_core():
    adapter = Mock()
    adapter.get_file_info.return_value = {}
    detector = CompilerDetector(adapter)
    
    result = detector._analyze_rich_header()
    
    assert result == {}


def test_analyze_rich_header_no_file():
    adapter = Mock()
    adapter.get_file_info.return_value = {"core": {}}
    detector = CompilerDetector(adapter)
    
    result = detector._analyze_rich_header()
    
    assert result == {}


def test_detect_intel_version():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    
    result = detector._detect_intel_version([], [])
    
    assert result == "Unknown"


def test_detect_borland_version():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    
    result = detector._detect_borland_version([], [])
    
    assert result == "Unknown"


def test_detect_mingw_version():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    
    result = detector._detect_mingw_version([], [])
    
    assert result == "Unknown"


def test_detect_delphi_version():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    
    result = detector._detect_delphi_version([], [])
    
    assert result == "Unknown"


def test_coerce_dict_list_dict():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    
    result = detector._coerce_dict_list({"key": "value"})
    
    assert result == [{"key": "value"}]


def test_coerce_dict_list_non_dict():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    
    result = detector._coerce_dict_list("string")
    
    assert result == []


def test_coerce_dict_list_mixed():
    adapter = Mock()
    detector = CompilerDetector(adapter)
    
    result = detector._coerce_dict_list([{"a": 1}, "not_dict", {"b": 2}])
    
    assert len(result) == 2
    assert {"a": 1} in result
    assert {"b": 2} in result


def test_get_file_info_no_adapter_method():
    adapter = None
    detector = CompilerDetector(adapter)
    
    result = detector._get_file_info()
    
    assert result == {}


def test_get_imports_raw_adapter_method():
    adapter = Mock()
    adapter.get_imports.return_value = [{"dll": "kernel32.dll", "name": "CreateProcess"}]
    detector = CompilerDetector(adapter)
    
    result = detector._get_imports_raw()
    
    assert len(result) == 1
    assert result[0]["dll"] == "kernel32.dll"


def test_get_sections_raw_adapter_method():
    adapter = Mock()
    adapter.get_sections.return_value = [{"name": ".text", "size": 1000}]
    detector = CompilerDetector(adapter)
    
    result = detector._get_sections_raw()
    
    assert len(result) == 1
    assert result[0]["name"] == ".text"


def test_get_symbols_raw_adapter_method():
    adapter = Mock()
    adapter.get_symbols.return_value = [{"name": "main", "address": 0x400000}]
    detector = CompilerDetector(adapter)
    
    result = detector._get_symbols_raw()
    
    assert len(result) == 1
    assert result[0]["name"] == "main"
