from __future__ import annotations

from r2inspect.modules.pe_imports import (
    calculate_imphash,
    compute_imphash,
    fetch_imports,
    group_imports_by_library,
    normalize_library_name,
)


class _FakeLogger:
    def debug(self, msg: str) -> None:
        pass

    def error(self, msg: str) -> None:
        pass


class _AdapterWithGetImports:
    def get_imports(self) -> list[dict]:
        return [
            {"name": "CreateFileA", "libname": "kernel32.dll"},
            {"name": "ReadFile", "libname": "kernel32.dll"},
            {"name": "MessageBoxA", "libname": "user32.dll"},
        ]


class _AdapterWithoutGetImports:
    pass


def test_fetch_imports_uses_adapter_get_imports() -> None:
    adapter = _AdapterWithGetImports()
    result = fetch_imports(adapter)
    assert len(result) == 3
    assert result[0]["name"] == "CreateFileA"


def test_fetch_imports_fallback_without_method() -> None:
    adapter = _AdapterWithoutGetImports()
    result = fetch_imports(adapter)
    assert isinstance(result, list)


def test_fetch_imports_none_adapter_returns_empty() -> None:
    result = fetch_imports(None)
    assert result == []


def test_group_imports_skips_missing_name_key() -> None:
    imports = [
        {"libname": "kernel32.dll"},
        {"libname": "kernel32.dll", "name": "CreateFileA"},
    ]
    result = group_imports_by_library(imports)
    assert "kernel32.dll" in result
    assert len(result["kernel32.dll"]) == 1


def test_group_imports_skips_empty_name() -> None:
    imports = [
        {"libname": "kernel32.dll", "name": ""},
        {"libname": "kernel32.dll", "name": "   "},
        {"libname": "kernel32.dll", "name": "ReadFile"},
    ]
    result = group_imports_by_library(imports)
    assert len(result["kernel32.dll"]) == 1


def test_group_imports_uses_unknown_for_missing_libname() -> None:
    imports = [
        {"name": "SomeFunc"},
        {"name": "OtherFunc", "libname": ""},
        {"name": "ThirdFunc", "libname": "   "},
    ]
    result = group_imports_by_library(imports)
    assert "unknown" in result
    assert len(result["unknown"]) == 3


def test_group_imports_non_dict_entries_skipped() -> None:
    imports = [
        {"libname": "kernel32.dll", "name": "CreateFileA"},
        "not_a_dict",
        42,
        None,
    ]
    result = group_imports_by_library(imports)
    assert "kernel32.dll" in result


def test_normalize_library_name_bytes_input() -> None:
    result = normalize_library_name(b"KERNEL32.DLL", ["dll", "ocx", "sys"])
    assert result == "kernel32"


def test_normalize_library_name_strips_extension() -> None:
    result = normalize_library_name("ntdll.dll", ["dll"])
    assert result == "ntdll"


def test_normalize_library_name_no_extension_match() -> None:
    result = normalize_library_name("ntdll.xyz", ["dll", "sys"])
    assert result == "ntdll.xyz"


def test_normalize_library_name_lowercases() -> None:
    result = normalize_library_name("KERNEL32.DLL", ["dll"])
    assert result == "kernel32"


def test_compute_imphash_empty_returns_empty_string() -> None:
    result = compute_imphash([])
    assert result == ""


def test_compute_imphash_returns_md5_hex() -> None:
    result = compute_imphash(["kernel32.createfilea", "kernel32.readfile"])
    assert len(result) == 32
    assert result.islower()


def test_compute_imphash_consistent() -> None:
    imports = ["kernel32.createfilea", "user32.messageboxw"]
    r1 = compute_imphash(imports)
    r2 = compute_imphash(imports)
    assert r1 == r2


def test_calculate_imphash_returns_string() -> None:
    logger = _FakeLogger()
    adapter = _AdapterWithGetImports()
    result = calculate_imphash(adapter, logger)
    assert isinstance(result, str)
    assert len(result) == 32


def test_calculate_imphash_no_imports_returns_empty() -> None:
    class _NoImportsAdapter:
        def get_imports(self) -> list:
            return []

    logger = _FakeLogger()
    result = calculate_imphash(_NoImportsAdapter(), logger)
    assert result == ""


def test_calculate_imphash_none_adapter_returns_empty() -> None:
    logger = _FakeLogger()
    result = calculate_imphash(None, logger)
    assert result == ""


def test_calculate_imphash_with_bytes_funcname() -> None:
    class _BytesAdapter:
        def get_imports(self) -> list:
            return [
                {"name": b"CreateFileA", "libname": "kernel32.dll"},
            ]

    logger = _FakeLogger()
    result = calculate_imphash(_BytesAdapter(), logger)
    assert isinstance(result, str)


def test_calculate_imphash_skips_empty_funcname() -> None:
    class _SomeEmptyAdapter:
        def get_imports(self) -> list:
            return [
                {"name": "", "libname": "kernel32.dll"},
                {"name": "ReadFile", "libname": "kernel32.dll"},
            ]

    logger = _FakeLogger()
    result = calculate_imphash(_SomeEmptyAdapter(), logger)
    assert isinstance(result, str)
    assert len(result) == 32
