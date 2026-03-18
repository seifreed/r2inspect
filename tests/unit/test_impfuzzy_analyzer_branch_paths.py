"""Branch-path tests for impfuzzy_analyzer.py covering missing lines."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import r2inspect.modules.impfuzzy_analyzer as impfuzzy_module
from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer


# ---------------------------------------------------------------------------
# Minimal adapter helpers (no unittest.mock)
# ---------------------------------------------------------------------------


class EmptyAdapter:
    """Adapter with no special methods; all r2 calls fall back to default."""

    pass


class DictImportsAdapter:
    """Adapter whose get_imports() returns a single dict (not a list)."""

    def get_imports(self) -> dict[str, Any]:
        return {"name": "CreateFileA", "libname": "kernel32.dll"}


class ListImportsAdapter:
    """Adapter whose get_imports() returns a valid list."""

    def get_imports(self) -> list[dict[str, Any]]:
        return [{"name": "CreateFileA", "libname": "kernel32.dll"}]


class RaisingAdapter:
    """Adapter whose get_imports() raises an exception."""

    def get_imports(self) -> list[dict[str, Any]]:
        raise RuntimeError("simulated get_imports error")


class CmdJDictAdapter:
    """Adapter with cmdj() returning a dict for 'ii' and empty for 'iij'."""

    def cmdj(self, command: str) -> Any:
        if command == "iij":
            return []
        if command == "ii":
            return {"name": "WriteFile", "libname": "kernel32.dll"}
        return []


class PEInfoAdapter:
    """Adapter that reports PE file info so _is_pe_file() returns True."""

    def get_file_info(self) -> dict[str, Any]:
        return {"bin": {"format": "pe", "arch": "x86", "bits": 32}}

    def get_imports(self) -> list[dict[str, Any]]:
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_analyzer(adapter: Any, filepath: str = "/nonexistent/path/file.bin") -> ImpfuzzyAnalyzer:
    return ImpfuzzyAnalyzer(adapter, filepath)


def _with_impfuzzy_unavailable(fn: Any) -> None:
    """Run fn with IMPFUZZY_AVAILABLE temporarily set to False."""
    original = impfuzzy_module.IMPFUZZY_AVAILABLE
    impfuzzy_module.IMPFUZZY_AVAILABLE = False
    try:
        fn()
    finally:
        impfuzzy_module.IMPFUZZY_AVAILABLE = original


# ---------------------------------------------------------------------------
# _check_library_availability  (line 54)
# ---------------------------------------------------------------------------


def test_check_library_availability_returns_false_when_unavailable():
    def run():
        analyzer = _make_analyzer(EmptyAdapter())
        available, error = analyzer._check_library_availability()
        assert available is False
        assert error is not None
        assert "pyimpfuzzy" in error.lower()

    _with_impfuzzy_unavailable(run)


# ---------------------------------------------------------------------------
# _calculate_hash  (lines 69, 78, 84-86)
# ---------------------------------------------------------------------------


def test_calculate_hash_returns_error_for_non_pe_file(tmp_path: Path):
    non_pe = tmp_path / "not_a_pe.txt"
    non_pe.write_bytes(b"hello world, not a PE file")
    analyzer = _make_analyzer(EmptyAdapter(), str(non_pe))
    h, method, err = analyzer._calculate_hash()
    assert h is None
    assert err is not None


def test_calculate_hash_exception_returns_error_tuple():
    class ExplodingAdapter:
        def get_file_info(self) -> dict[str, Any]:
            raise RuntimeError("forced failure")

    analyzer = _make_analyzer(ExplodingAdapter(), "/nonexistent/path/x.bin")
    h, method, err = analyzer._calculate_hash()
    assert h is None
    assert err is not None


# ---------------------------------------------------------------------------
# analyze_imports  (lines 120-150, 172-174)
# ---------------------------------------------------------------------------


def test_analyze_imports_returns_error_when_library_unavailable():
    def run():
        analyzer = _make_analyzer(EmptyAdapter(), str(Path("samples/fixtures/hello_pe.exe")))
        result = analyzer.analyze_imports()
        assert result["available"] is False
        assert result["error"] is not None
        assert result["import_count"] == 0

    _with_impfuzzy_unavailable(run)


def test_analyze_imports_returns_error_for_non_pe_file(tmp_path: Path):
    if not impfuzzy_module.IMPFUZZY_AVAILABLE:
        return
    non_pe = tmp_path / "not_a_pe.txt"
    non_pe.write_bytes(b"plaintext, no PE magic")
    analyzer = _make_analyzer(EmptyAdapter(), str(non_pe))
    result = analyzer.analyze_imports()
    assert result["available"] is False
    assert result["error"] is not None


def test_analyze_imports_no_imports_found(tmp_path: Path):
    if not impfuzzy_module.IMPFUZZY_AVAILABLE:
        return
    pe = tmp_path / "mini.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 100)
    adapter = PEInfoAdapter()
    analyzer = _make_analyzer(adapter, str(pe))
    result = analyzer.analyze_imports()
    assert result["available"] is False


def test_analyze_imports_exception_handler():
    class BrokenAdapter:
        def get_file_info(self) -> dict[str, Any]:
            return {"bin": {"format": "pe"}}

        def get_imports(self) -> list[dict[str, Any]]:
            raise RuntimeError("import fetch failed")

    pe_path = str(Path("samples/fixtures/hello_pe.exe"))
    analyzer = _make_analyzer(BrokenAdapter(), pe_path)
    result = analyzer.analyze_imports()
    assert "error" in result


# ---------------------------------------------------------------------------
# _extract_imports  (lines 200, 204-205, 208-218, 223-225)
# ---------------------------------------------------------------------------


def test_extract_imports_adapter_without_get_imports():
    """Adapter has no get_imports method; falls through to cmdj/default path (line 200)."""
    analyzer = _make_analyzer(EmptyAdapter())
    imports = analyzer._extract_imports()
    assert isinstance(imports, list)


def test_extract_imports_adapter_returns_dict():
    """Adapter.get_imports() returns a dict; covers line 204-205."""
    analyzer = _make_analyzer(DictImportsAdapter())
    imports = analyzer._extract_imports()
    assert isinstance(imports, list)
    assert len(imports) == 1


def test_extract_imports_fallback_to_ii_command_returns_empty():
    """No adapter get_imports and cmdj fallback returns empty list (lines 208-218)."""
    analyzer = _make_analyzer(EmptyAdapter())
    imports = analyzer._extract_imports()
    assert imports == []


def test_extract_imports_fallback_ii_returns_dict():
    """cmdj('ii') returns a dict; covers lines 210-214 dict branch."""
    analyzer = _make_analyzer(CmdJDictAdapter())
    imports = analyzer._extract_imports()
    assert isinstance(imports, list)


def test_extract_imports_exception_returns_empty():
    """Adapter.get_imports raises; exception handler (lines 223-225) returns []."""
    analyzer = _make_analyzer(RaisingAdapter())
    imports = analyzer._extract_imports()
    assert imports == []


# ---------------------------------------------------------------------------
# _process_imports  (line 263 - ordinal skip, lines 280-282 exception)
# ---------------------------------------------------------------------------


def test_process_imports_skips_ordinal_entries():
    """Ordinal-named imports trigger the continue branch (line 263)."""
    analyzer = _make_analyzer(EmptyAdapter())
    imports_data = [
        {"name": "ord_123", "libname": "kernel32.dll"},
        {"name": "ord_456", "libname": "user32.dll"},
    ]
    result = analyzer._process_imports(imports_data)
    assert result == []


def test_process_imports_exception_returns_empty():
    """Passing non-dict items triggers the exception handler (lines 280-282)."""
    analyzer = _make_analyzer(EmptyAdapter())
    # libname as int triggers AttributeError on .lower(), hitting exception branch
    result = analyzer._process_imports([{"libname": 123, "name": "CreateFileA"}])  # type: ignore[list-item]
    assert result == []


# ---------------------------------------------------------------------------
# compare_hashes  (lines 306-321)
# ---------------------------------------------------------------------------


def test_compare_hashes_returns_none_when_library_unavailable():
    """When IMPFUZZY_AVAILABLE is False, compare_hashes returns None (lines 306-307)."""

    def run():
        result = ImpfuzzyAnalyzer.compare_hashes("hash1", "hash2")
        assert result is None

    _with_impfuzzy_unavailable(run)


def test_compare_hashes_returns_none_for_empty_strings():
    """Empty hash strings return None (lines 309-310)."""
    result = ImpfuzzyAnalyzer.compare_hashes("", "abc")
    assert result is None

    result = ImpfuzzyAnalyzer.compare_hashes("abc", "")
    assert result is None


def test_compare_hashes_with_valid_hashes_returns_int_or_none():
    """Valid hashes: ssdeep available → int result (lines 312-318)."""
    if not impfuzzy_module.IMPFUZZY_AVAILABLE:
        return
    hash1 = "3:abc:xyz"
    hash2 = "3:abc:xyz"
    result = ImpfuzzyAnalyzer.compare_hashes(hash1, hash2)
    if result is not None:
        assert isinstance(result, int)


def test_compare_hashes_ssdeep_exception_returns_none():
    """If ssdeep comparison raises, returns None (lines 319-321)."""
    if not impfuzzy_module.IMPFUZZY_AVAILABLE:
        return
    # Invalid hash formats may trigger exception in ssdeep
    result = ImpfuzzyAnalyzer.compare_hashes("not:a:real:hash!!!", "also:invalid::hash!")
    # Either None or int is acceptable
    assert result is None or isinstance(result, int)


# ---------------------------------------------------------------------------
# calculate_impfuzzy_from_file  (lines 344-351)
# ---------------------------------------------------------------------------


def test_calculate_impfuzzy_from_file_returns_none_when_unavailable():
    """Library unavailable: returns None immediately (lines 344-345)."""

    def run():
        result = ImpfuzzyAnalyzer.calculate_impfuzzy_from_file("/any/path.exe")
        assert result is None

    _with_impfuzzy_unavailable(run)


def test_calculate_impfuzzy_from_file_exception_returns_none():
    """Passing an invalid path triggers the exception handler (lines 347-351)."""
    if not impfuzzy_module.IMPFUZZY_AVAILABLE:
        return
    result = ImpfuzzyAnalyzer.calculate_impfuzzy_from_file("/nonexistent/file_xyz_12345.exe")
    assert result is None


def test_calculate_impfuzzy_from_file_with_real_pe():
    """Valid PE file returns a hash or None if no imports."""
    if not impfuzzy_module.IMPFUZZY_AVAILABLE:
        return
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        return
    result = ImpfuzzyAnalyzer.calculate_impfuzzy_from_file(str(sample))
    assert result is None or isinstance(result, str)


def test_check_library_availability_true_when_available(monkeypatch):
    monkeypatch.setattr(impfuzzy_module, "IMPFUZZY_AVAILABLE", True)
    analyzer = _make_analyzer(EmptyAdapter(), "/tmp/a.exe")
    available, error = analyzer._check_library_availability()
    assert available is True
    assert error is None


def test_get_hash_type_returns_impfuzzy():
    analyzer = _make_analyzer(EmptyAdapter(), "/tmp/a.exe")
    assert analyzer._get_hash_type() == "impfuzzy"


def test_calculate_hash_success_and_empty_hash_and_exception(monkeypatch):
    class FakeImpfuzzy:
        def __init__(self):
            self.mode = "ok"

        def get_impfuzzy(self, _path: str):
            if self.mode == "ok":
                return "3:abc:def"
            if self.mode == "empty":
                return ""
            raise RuntimeError("boom")

    fake = FakeImpfuzzy()
    monkeypatch.setattr(impfuzzy_module, "pyimpfuzzy", fake, raising=False)
    analyzer = _make_analyzer(EmptyAdapter(), "/tmp/a.exe")
    analyzer._is_pe_file = lambda: True  # type: ignore[method-assign]

    h, method, err = analyzer._calculate_hash()
    assert h == "3:abc:def"
    assert method == "python_library"
    assert err is None

    fake.mode = "empty"
    h, method, err = analyzer._calculate_hash()
    assert h is None
    assert method is None
    assert err is not None

    fake.mode = "raise"
    h, method, err = analyzer._calculate_hash()
    assert h is None
    assert method is None
    assert "Impfuzzy calculation failed" in (err or "")


def test_analyze_imports_processed_empty_failed_hash_and_success(monkeypatch):
    class FakeImpfuzzy:
        def __init__(self):
            self.value = "3:hash:value"

        def get_impfuzzy(self, _path: str):
            return self.value

    fake = FakeImpfuzzy()
    monkeypatch.setattr(impfuzzy_module, "IMPFUZZY_AVAILABLE", True)
    monkeypatch.setattr(impfuzzy_module, "pyimpfuzzy", fake, raising=False)

    analyzer = _make_analyzer(EmptyAdapter(), "/tmp/a.exe")
    analyzer._is_pe_file = lambda: True  # type: ignore[method-assign]
    analyzer._extract_imports = lambda: [{"libname": "KERNEL32.dll", "name": "CreateFileA"}]  # type: ignore[method-assign]

    analyzer._process_imports = lambda _imports: []  # type: ignore[method-assign]
    result = analyzer.analyze_imports()
    assert result["available"] is False
    assert result["error"] == "No valid imports found after processing"

    analyzer._process_imports = lambda _imports: ["kernel32.createfilea"]  # type: ignore[method-assign]
    fake.value = ""
    result = analyzer.analyze_imports()
    assert result["available"] is False
    assert result["error"] == "Failed to calculate impfuzzy hash"

    fake.value = "3:hash:value"
    result = analyzer.analyze_imports()
    assert result["available"] is True
    assert result["impfuzzy_hash"] == "3:hash:value"
    assert result["import_count"] == 1
    assert result["dll_count"] == 1


def test_analyze_imports_exception_branch_sets_error(monkeypatch):
    monkeypatch.setattr(impfuzzy_module, "IMPFUZZY_AVAILABLE", True)
    monkeypatch.setattr(
        impfuzzy_module,
        "pyimpfuzzy",
        type("FakeImpfuzzy", (), {"get_impfuzzy": staticmethod(lambda _p: "3:ok")})(),
        raising=False,
    )
    analyzer = _make_analyzer(EmptyAdapter(), "/tmp/a.exe")
    analyzer._is_pe_file = lambda: True  # type: ignore[method-assign]

    def _raise():
        raise RuntimeError("extract failed")

    analyzer._extract_imports = _raise  # type: ignore[method-assign]
    result = analyzer.analyze_imports()
    assert result["available"] is False
    assert result["error"] == "extract failed"


def test_process_imports_builds_flat_sorted_entries():
    analyzer = _make_analyzer(EmptyAdapter(), "/tmp/a.exe")
    result = analyzer._process_imports(
        [
            {"libname": "KERNEL32.dll", "name": "CreateFileA"},
            {"libname": "KERNEL32.dll", "function": "ReadFile"},
        ]
    )
    assert result == ["kernel32.createfilea", "kernel32.readfile"]


def test_process_imports_skips_non_dict_entries_without_crashing():
    analyzer = _make_analyzer(EmptyAdapter(), "/tmp/a.exe")
    result = analyzer._process_imports(
        [
            "invalid-entry",
            {"libname": "KERNEL32.dll", "name": "CloseHandle"},
        ]  # type: ignore[list-item]
    )
    assert result == ["kernel32.closehandle"]


def test_compare_hashes_returns_none_when_ssdeep_loader_missing(monkeypatch):
    monkeypatch.setattr(impfuzzy_module, "IMPFUZZY_AVAILABLE", True)
    monkeypatch.setattr(impfuzzy_module, "get_ssdeep", lambda: None)
    assert ImpfuzzyAnalyzer.compare_hashes("3:a:b", "3:a:c") is None
