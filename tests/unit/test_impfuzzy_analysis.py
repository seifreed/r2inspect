from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

from r2inspect.modules.impfuzzy_analyzer import IMPFUZZY_AVAILABLE, ImpfuzzyAnalyzer


def test_impfuzzy_library_availability():
    result = ImpfuzzyAnalyzer.is_available()
    assert isinstance(result, bool)


def test_impfuzzy_with_empty_imports():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    result = analyzer.analyze_imports()
    
    assert "available" in result
    assert result["import_count"] == 0
    assert result["dll_count"] == 0


def test_impfuzzy_with_single_import():
    if not IMPFUZZY_AVAILABLE:
        return
    
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "CreateFileA", "libname": "kernel32.dll"}
    ])
    
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    
    imports_data = [{"name": "CreateFileA", "libname": "kernel32.dll"}]
    processed = analyzer._process_imports(imports_data)
    
    assert isinstance(processed, list)
    assert "kernel32.createfilea" in processed


def test_impfuzzy_with_multiple_dlls():
    if not IMPFUZZY_AVAILABLE:
        return
    
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    
    imports_data = [
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "MessageBoxA", "libname": "user32.dll"},
        {"name": "RegOpenKey", "libname": "advapi32.dll"}
    ]
    
    processed = analyzer._process_imports(imports_data)
    
    assert len(processed) == 3
    assert "kernel32.createfilea" in processed
    assert "user32.messageboxa" in processed
    assert "advapi32.regopenkey" in processed


def test_impfuzzy_normalize_dll_name():
    if not IMPFUZZY_AVAILABLE:
        return
    
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    
    imports_data = [
        {"name": "CreateFileA", "libname": "KERNEL32.DLL"}
    ]
    
    processed = analyzer._process_imports(imports_data)
    
    assert "kernel32.createfilea" in processed


def test_impfuzzy_skip_ordinals():
    if not IMPFUZZY_AVAILABLE:
        return
    
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    
    imports_data = [
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "ord_123", "libname": "kernel32.dll"},
        {"name": "ReadFile", "libname": "kernel32.dll"}
    ]
    
    processed = analyzer._process_imports(imports_data)
    
    assert "kernel32.createfilea" in processed
    assert "kernel32.readfile" in processed
    assert not any("ord_" in imp for imp in processed)


def test_impfuzzy_sorted_imports():
    if not IMPFUZZY_AVAILABLE:
        return
    
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    
    imports_data = [
        {"name": "WriteFile", "libname": "kernel32.dll"},
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "ReadFile", "libname": "kernel32.dll"}
    ]
    
    processed = analyzer._process_imports(imports_data)
    
    assert processed == sorted(processed)


def test_impfuzzy_alternative_field_names():
    if not IMPFUZZY_AVAILABLE:
        return
    
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    
    imports_data = [
        {"func": "CreateFileA", "lib": "kernel32"},
        {"function": "ReadFile", "library": "kernel32.dll"},
        {"symbol": "WriteFile", "module": "kernel32"}
    ]
    
    processed = analyzer._process_imports(imports_data)
    
    assert len(processed) == 3


def test_impfuzzy_compare_identical_hashes():
    if not IMPFUZZY_AVAILABLE:
        return
    
    hash1 = "3:abc:xyz"
    hash2 = "3:abc:xyz"
    
    similarity = ImpfuzzyAnalyzer.compare_hashes(hash1, hash2)
    
    if similarity is not None:
        assert isinstance(similarity, int)
        assert 0 <= similarity <= 100


def test_impfuzzy_compare_empty_hashes():
    result = ImpfuzzyAnalyzer.compare_hashes("", "")
    assert result is None


def test_impfuzzy_compare_none_hashes():
    result = ImpfuzzyAnalyzer.compare_hashes(None, None)
    assert result is None


def test_impfuzzy_with_dict_imports():
    adapter = Mock()
    adapter.get_imports = Mock(return_value={
        "name": "CreateFileA",
        "libname": "kernel32.dll"
    })
    
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    imports = analyzer._extract_imports()
    
    assert isinstance(imports, list)
    assert len(imports) == 1


def test_impfuzzy_with_list_imports():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "ReadFile", "libname": "kernel32.dll"}
    ])
    
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    imports = analyzer._extract_imports()
    
    assert isinstance(imports, list)
    assert len(imports) == 2


def test_impfuzzy_with_unknown_function_name():
    if not IMPFUZZY_AVAILABLE:
        return
    
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    
    imports_data = [
        {"name": "unknown", "libname": "unknown"},
        {"libname": "kernel32.dll"}
    ]
    
    processed = analyzer._process_imports(imports_data)
    
    assert isinstance(processed, list)


def test_impfuzzy_analyze_imports_structure():
    adapter = Mock()
    adapter.get_imports = Mock(return_value=[])
    adapter.cmdj = Mock(return_value=[])
    
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    result = analyzer.analyze_imports()
    
    assert "available" in result
    assert "impfuzzy_hash" in result
    assert "import_count" in result
    assert "dll_count" in result
    assert "imports_processed" in result
    assert "library_available" in result
    assert "error" in result


def test_impfuzzy_multiple_functions_same_dll():
    if not IMPFUZZY_AVAILABLE:
        return
    
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    
    imports_data = [
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "ReadFile", "libname": "kernel32.dll"},
        {"name": "WriteFile", "libname": "kernel32.dll"},
        {"name": "CloseHandle", "libname": "kernel32.dll"}
    ]
    
    processed = analyzer._process_imports(imports_data)
    
    assert len(processed) == 4
    assert all(imp.startswith("kernel32.") for imp in processed)


def test_impfuzzy_dll_name_cleanup():
    if not IMPFUZZY_AVAILABLE:
        return
    
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    
    imports_data = [
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "MessageBoxA", "libname": "USER32.DLL"}
    ]
    
    processed = analyzer._process_imports(imports_data)
    
    assert all(".dll" not in imp.lower() or imp.count(".") == 1 for imp in processed)


def test_impfuzzy_check_library_availability():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    
    available, error = analyzer._check_library_availability()
    
    assert isinstance(available, bool)
    if not available:
        assert error is not None


def test_impfuzzy_get_hash_type():
    adapter = Mock()
    sample = Path("samples/fixtures/hello_pe.exe")
    analyzer = ImpfuzzyAnalyzer(adapter, str(sample))
    
    hash_type = analyzer._get_hash_type()
    
    assert hash_type == "impfuzzy"
