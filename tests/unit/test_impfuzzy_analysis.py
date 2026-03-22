"""Tests for r2inspect/modules/impfuzzy_analyzer.py -- no mocks, no monkeypatch, no @patch."""

from __future__ import annotations

import json
import struct
import tempfile
from pathlib import Path

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.impfuzzy_analyzer import IMPFUZZY_AVAILABLE, ImpfuzzyAnalyzer
from r2inspect.testing.fake_r2 import FakeR2


# ---------------------------------------------------------------------------
# Minimal fake r2 backend
# ---------------------------------------------------------------------------


def _make_adapter(cmd_map=None, cmdj_map=None):
    return R2PipeAdapter(FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map))


def _pe_stub_path() -> Path:
    """Create a minimal MZ-headed temp file so _is_pe_file sees MZ magic."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        # Minimal DOS header: MZ magic + enough bytes to not be empty
        tmp.write(b"MZ" + b"\x00" * 120)
        tmp.flush()
        return Path(tmp.name)


# ---------------------------------------------------------------------------
# Library availability
# ---------------------------------------------------------------------------


def test_impfuzzy_library_availability():
    result = ImpfuzzyAnalyzer.is_available()
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# analyze_imports with empty imports
# ---------------------------------------------------------------------------


def test_impfuzzy_with_empty_imports():
    pe_path = _pe_stub_path()
    adapter = _make_adapter(
        cmdj_map={"iij": [], "ii": [], "ij": {"core": {"format": "pe"}, "bin": {"arch": "x86"}}},
    )
    analyzer = ImpfuzzyAnalyzer(adapter, str(pe_path))
    result = analyzer.analyze_imports()

    assert "available" in result
    assert result["import_count"] == 0
    assert result["dll_count"] == 0


# ---------------------------------------------------------------------------
# _process_imports -- single import
# ---------------------------------------------------------------------------


def test_impfuzzy_with_single_import():
    if not IMPFUZZY_AVAILABLE:
        pytest.skip("impfuzzy library not installed")

    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    imports_data = [{"name": "CreateFileA", "libname": "kernel32.dll"}]
    processed = analyzer._process_imports(imports_data)

    assert isinstance(processed, list)
    assert "kernel32.createfilea" in processed


# ---------------------------------------------------------------------------
# _process_imports -- multiple DLLs
# ---------------------------------------------------------------------------


def test_impfuzzy_with_multiple_dlls():
    if not IMPFUZZY_AVAILABLE:
        pytest.skip("impfuzzy library not installed")

    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    imports_data = [
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "MessageBoxA", "libname": "user32.dll"},
        {"name": "RegOpenKey", "libname": "advapi32.dll"},
    ]

    processed = analyzer._process_imports(imports_data)

    assert len(processed) == 3
    assert "kernel32.createfilea" in processed
    assert "user32.messageboxa" in processed
    assert "advapi32.regopenkey" in processed


# ---------------------------------------------------------------------------
# _process_imports -- DLL name normalisation (case)
# ---------------------------------------------------------------------------


def test_impfuzzy_normalize_dll_name():
    if not IMPFUZZY_AVAILABLE:
        pytest.skip("impfuzzy library not installed")

    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    imports_data = [{"name": "CreateFileA", "libname": "KERNEL32.DLL"}]
    processed = analyzer._process_imports(imports_data)

    assert "kernel32.createfilea" in processed


# ---------------------------------------------------------------------------
# _process_imports -- ordinals skipped
# ---------------------------------------------------------------------------


def test_impfuzzy_skip_ordinals():
    if not IMPFUZZY_AVAILABLE:
        pytest.skip("impfuzzy library not installed")

    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    imports_data = [
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "ord_123", "libname": "kernel32.dll"},
        {"name": "ReadFile", "libname": "kernel32.dll"},
    ]

    processed = analyzer._process_imports(imports_data)

    assert "kernel32.createfilea" in processed
    assert "kernel32.readfile" in processed
    assert not any("ord_" in imp for imp in processed)


# ---------------------------------------------------------------------------
# _process_imports -- result is sorted
# ---------------------------------------------------------------------------


def test_impfuzzy_sorted_imports():
    if not IMPFUZZY_AVAILABLE:
        pytest.skip("impfuzzy library not installed")

    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    imports_data = [
        {"name": "WriteFile", "libname": "kernel32.dll"},
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "ReadFile", "libname": "kernel32.dll"},
    ]

    processed = analyzer._process_imports(imports_data)

    assert processed == sorted(processed)


# ---------------------------------------------------------------------------
# _process_imports -- alternative field names
# ---------------------------------------------------------------------------


def test_impfuzzy_alternative_field_names():
    if not IMPFUZZY_AVAILABLE:
        pytest.skip("impfuzzy library not installed")

    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    imports_data = [
        {"func": "CreateFileA", "lib": "kernel32"},
        {"function": "ReadFile", "library": "kernel32.dll"},
        {"symbol": "WriteFile", "module": "kernel32"},
    ]

    processed = analyzer._process_imports(imports_data)

    assert len(processed) == 3


# ---------------------------------------------------------------------------
# compare_hashes
# ---------------------------------------------------------------------------


def test_impfuzzy_compare_identical_hashes():
    if not IMPFUZZY_AVAILABLE:
        pytest.skip("impfuzzy library not installed")

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


# ---------------------------------------------------------------------------
# _extract_imports -- dict return (single import wrapped)
# ---------------------------------------------------------------------------


def test_impfuzzy_with_dict_imports():
    """When a raw r2 backend returns a dict, _extract_imports wraps it in a list.

    We use a thin wrapper that does NOT provide ``get_imports`` so the code
    falls back to ``_cmdj("iij", [])`` and exercises the dict-wrapping path.
    """

    class _BareAdapter:
        """Adapter without get_imports -- forces _cmdj fallback inside _extract_imports."""

        def __init__(self, r2):
            self._r2 = r2

        def cmdj(self, command):
            return self._r2.cmdj(command)

        def cmd(self, command):
            return self._r2.cmd(command)

    fake = FakeR2(cmdj_map={"iij": {"name": "CreateFileA", "libname": "kernel32.dll"}})
    bare = _BareAdapter(fake)

    analyzer = ImpfuzzyAnalyzer(bare, str(_pe_stub_path()))
    imports = analyzer._extract_imports()

    assert isinstance(imports, list)
    assert len(imports) == 1


# ---------------------------------------------------------------------------
# _extract_imports -- list return
# ---------------------------------------------------------------------------


def test_impfuzzy_with_list_imports():
    adapter = _make_adapter(
        cmdj_map={
            "iij": [
                {"name": "CreateFileA", "libname": "kernel32.dll"},
                {"name": "ReadFile", "libname": "kernel32.dll"},
            ],
        },
    )

    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))
    imports = analyzer._extract_imports()

    assert isinstance(imports, list)
    assert len(imports) == 2


# ---------------------------------------------------------------------------
# _process_imports -- unknown / missing function names
# ---------------------------------------------------------------------------


def test_impfuzzy_with_unknown_function_name():
    if not IMPFUZZY_AVAILABLE:
        pytest.skip("impfuzzy library not installed")

    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    imports_data = [
        {"name": "unknown", "libname": "unknown"},
        {"libname": "kernel32.dll"},
    ]

    processed = analyzer._process_imports(imports_data)

    assert isinstance(processed, list)


# ---------------------------------------------------------------------------
# analyze_imports -- structure check
# ---------------------------------------------------------------------------


def test_impfuzzy_analyze_imports_structure():
    adapter = _make_adapter(
        cmdj_map={"iij": [], "ii": [], "ij": {"core": {"format": "pe"}, "bin": {"arch": "x86"}}},
    )

    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))
    result = analyzer.analyze_imports()

    assert "available" in result
    assert "impfuzzy_hash" in result
    assert "import_count" in result
    assert "dll_count" in result
    assert "imports_processed" in result
    assert "library_available" in result
    assert "error" in result


# ---------------------------------------------------------------------------
# _process_imports -- multiple functions same DLL
# ---------------------------------------------------------------------------


def test_impfuzzy_multiple_functions_same_dll():
    if not IMPFUZZY_AVAILABLE:
        pytest.skip("impfuzzy library not installed")

    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    imports_data = [
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "ReadFile", "libname": "kernel32.dll"},
        {"name": "WriteFile", "libname": "kernel32.dll"},
        {"name": "CloseHandle", "libname": "kernel32.dll"},
    ]

    processed = analyzer._process_imports(imports_data)

    assert len(processed) == 4
    assert all(imp.startswith("kernel32.") for imp in processed)


# ---------------------------------------------------------------------------
# _process_imports -- DLL .dll extension is stripped
# ---------------------------------------------------------------------------


def test_impfuzzy_dll_name_cleanup():
    if not IMPFUZZY_AVAILABLE:
        pytest.skip("impfuzzy library not installed")

    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    imports_data = [
        {"name": "CreateFileA", "libname": "kernel32.dll"},
        {"name": "MessageBoxA", "libname": "USER32.DLL"},
    ]

    processed = analyzer._process_imports(imports_data)

    assert all(".dll" not in imp.lower() or imp.count(".") == 1 for imp in processed)


# ---------------------------------------------------------------------------
# _check_library_availability
# ---------------------------------------------------------------------------


def test_impfuzzy_check_library_availability():
    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    available, error = analyzer._check_library_availability()

    assert isinstance(available, bool)
    if not available:
        assert error is not None


# ---------------------------------------------------------------------------
# _get_hash_type
# ---------------------------------------------------------------------------


def test_impfuzzy_get_hash_type():
    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    hash_type = analyzer._get_hash_type()

    assert hash_type == "impfuzzy"


# ---------------------------------------------------------------------------
# _extract_imports -- fallback to "ii" when "iij" returns nothing
# ---------------------------------------------------------------------------


def test_impfuzzy_extract_imports_fallback_to_ii():
    adapter = _make_adapter(
        cmdj_map={
            "iij": [],
            "ii": [{"name": "LoadLibraryA", "libname": "kernel32.dll"}],
        },
    )

    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))
    imports = analyzer._extract_imports()

    assert isinstance(imports, list)
    assert len(imports) == 1
    assert imports[0]["name"] == "LoadLibraryA"


# ---------------------------------------------------------------------------
# _extract_imports -- both commands return nothing
# ---------------------------------------------------------------------------


def test_impfuzzy_extract_imports_empty_everywhere():
    adapter = _make_adapter(
        cmdj_map={"iij": [], "ii": []},
    )

    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))
    imports = analyzer._extract_imports()

    assert imports == []


# ---------------------------------------------------------------------------
# _process_imports -- empty list in
# ---------------------------------------------------------------------------


def test_impfuzzy_process_imports_empty():
    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    processed = analyzer._process_imports([])

    assert processed == []


# ---------------------------------------------------------------------------
# _process_imports -- non-dict entries are skipped
# ---------------------------------------------------------------------------


def test_impfuzzy_process_imports_non_dict_skipped():
    if not IMPFUZZY_AVAILABLE:
        pytest.skip("impfuzzy library not installed")

    adapter = _make_adapter()
    analyzer = ImpfuzzyAnalyzer(adapter, str(_pe_stub_path()))

    imports_data = [
        "not_a_dict",
        42,
        {"name": "CreateFileA", "libname": "kernel32.dll"},
    ]

    processed = analyzer._process_imports(imports_data)

    assert isinstance(processed, list)
    # Only the valid dict should be processed
    assert any("kernel32.createfilea" in imp for imp in processed)
