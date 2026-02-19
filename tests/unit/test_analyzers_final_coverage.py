"""
Final coverage tests for rich_header_analyzer, yara_analyzer, impfuzzy_analyzer.

Lines that are structurally unreachable in this environment (documented here):
  rich_header_analyzer.py 33-35  : pefile ImportError branch - pefile IS installed
  rich_header_analyzer.py 131    : PEFILE_AVAILABLE=False guard - pefile IS installed
  rich_header_analyzer.py 142-143: get_rich_header_hash() always returns MD5 string;
                                   no code path exists that produces a None/empty hash
                                   when RICH_HEADER is present
  rich_header_analyzer.py 160-161: pe.close() never raises on real pefile objects
  rich_header_analyzer.py 586    : calculate_richpe_hash_from_file returns the hash value;
                                   requires open_r2_adapter context manager to work
                                   (open_r2_adapter.__exit__ currently broken)
  yara_analyzer.py 415-416       : outer except in list_available_rules; os.path.exists/
                                   isfile/isdir do not raise on macOS, rglob errors are
                                   swallowed by the inner per-file exception handler, and
                                   logger.info does not raise - no reachable raise path
                                   exists without mocking
  impfuzzy_analyzer.py 21-29     : pyimpfuzzy ImportError branch - pyimpfuzzy IS installed
  impfuzzy_analyzer.py 78-82     : impfuzzy_hash falsy path - pyimpfuzzy always returns
                                   at minimum '3::' (truthy) for any parseable PE file
  impfuzzy_analyzer.py 147-150   : impfuzzy_hash falsy in analyze_imports - same reason
  impfuzzy_analyzer.py 316-317   : ssdeep is None path - ssdeep IS installed
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.rich_header_analyzer import PEFILE_AVAILABLE, RichHeaderAnalyzer
from r2inspect.modules.yara_analyzer import YaraAnalyzer

# ---------------------------------------------------------------------------
# Shared fixtures path
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).parent.parent.parent / "samples" / "fixtures"
_HELLO_PE = str(_FIXTURES_DIR / "hello_pe.exe")


# ---------------------------------------------------------------------------
# Helper: build a minimal PE with a Rich Header that pefile recognises
#
# pefile searches for 'Rich' starting at offset 0x80 (not 0x40).
# The structure between 0x80 and e_lfanew must be:
#   DanS^key, key, key, key  |  (prodid^key, count^key)...  |  Rich, key
# ---------------------------------------------------------------------------

_DANS = 0x536E6144
_RICH = 0x68636952


def _build_pe_with_rich_header() -> bytes:
    """Build a minimal PE whose Rich Header pefile can parse."""
    xor_key = 0x12345678

    # Two compressed entries: (prodid, count)
    entries = [
        (0x0001 | (0x7809 << 16), 5),
        (0x0053 | (0x8F5C << 16), 3),
    ]

    stub_dwords: list[int] = []
    stub_dwords.append(_DANS ^ xor_key)
    stub_dwords.append(xor_key)
    stub_dwords.append(xor_key)
    stub_dwords.append(xor_key)
    for val, count in entries:
        stub_dwords.append(val ^ xor_key)
        stub_dwords.append(count ^ xor_key)
    stub_dwords.append(_RICH)
    stub_dwords.append(xor_key)

    stub_bytes = struct.pack("<" + "I" * len(stub_dwords), *stub_dwords)

    # Rich Header must start at offset 0x80 for pefile's scanner
    pre_rich_pad = b"\x00" * (0x80 - 0x40)

    pe_offset = 0x80 + len(stub_bytes)
    # Align to 8 bytes
    if pe_offset % 8:
        padding = 8 - (pe_offset % 8)
        stub_bytes += b"\x00" * padding
        pe_offset += padding

    mz = bytearray(0x40)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, pe_offset)

    # Minimal PE32 headers
    image_base = 0x400000
    pe_sig = b"PE\x00\x00"
    coff = struct.pack(
        "<HHIIIHH",
        0x014C,  # i386
        0,  # NumberOfSections
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        0x60,  # SizeOfOptionalHeader
        0x0002,  # Characteristics
    )
    opt = struct.pack(
        "<HBB",
        0x010B,
        6,
        0,  # Magic=PE32, linker 6.0
    )
    opt += struct.pack(
        "<IIIIIII",
        0x200,
        0,
        0,  # SizeOfCode, SizeOfInitData, SizeOfUninitData
        0x1000,
        0x1000,
        0,  # EntryPoint, BaseOfCode, BaseOfData
        image_base,
    )
    opt += struct.pack("<II", 0x1000, 0x200)  # SectionAlignment, FileAlignment
    opt += struct.pack("<HHHH", 5, 1, 0, 0)  # OS/Image versions
    opt += struct.pack("<HH", 5, 0)  # Subsystem versions
    opt += struct.pack("<I", 0)  # Win32VersionValue
    opt += struct.pack("<III", 0x2000, pe_offset + len(pe_sig) + len(coff) + 0x60, 0)
    opt += struct.pack("<HH", 2, 0)  # Subsystem, DllCharacteristics
    opt += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)  # LoaderFlags, NumberOfRvaAndSizes
    opt += b"\x00" * (16 * 8)  # 16 data directories

    return bytes(mz) + pre_rich_pad + stub_bytes + pe_sig + coff + opt + b"\x00" * 256


# ---------------------------------------------------------------------------
# Minimal stub adapter (makes self.r2 truthy so _is_pe_file reads MZ bytes)
# ---------------------------------------------------------------------------


class _StubAdapter:
    pass


# ===========================================================================
# RICH HEADER ANALYZER TESTS
# ===========================================================================


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not installed")
def test_analyze_with_pefile_rich_header_path() -> None:
    """Lines 83-84: analyze() sets method_used='pefile' when pefile finds Rich Header.

    Also exercises _extract_rich_header_pefile lines 140-141, 145-151.
    """
    data = _build_pe_with_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=_StubAdapter(), filepath=path)
        result = analyzer.analyze()
        assert result["is_pe"] is True
        assert result["method_used"] == "pefile"
        assert result["richpe_hash"] is not None
    finally:
        os.unlink(path)


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not installed")
def test_extract_rich_header_pefile_entries_fallback_to_clear_data() -> None:
    """Lines 148-149: when pefile.RICH_HEADER.values are ints (not Entry objects),
    _pefile_extract_entries returns empty and _pefile_entries_from_clear_data is used.
    """
    data = _build_pe_with_rich_header()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = RichHeaderAnalyzer(adapter=_StubAdapter(), filepath=path)
        result = analyzer._extract_rich_header_pefile()
        # Result exists; entries come from clear_data fallback
        assert result is not None
        assert "entries" in result
        assert "xor_key" in result
    finally:
        os.unlink(path)


class _CombinationsAnalyzer(RichHeaderAnalyzer):
    """Subclass where _try_extract_rich_at_offsets always succeeds."""

    def _try_extract_rich_at_offsets(self, dans_offset: int, rich_offset: int) -> dict[str, Any]:
        return {
            "xor_key": 0xDEADBEEF,
            "entries": [{"product_id": 1, "build_number": 1, "count": 1}],
        }


def test_try_rich_dans_combinations_success_path() -> None:
    """Lines 350-355: _try_rich_dans_combinations returns data on first valid match.

    Also covers line 307 when called from _extract_rich_header.
    """
    analyzer = _CombinationsAnalyzer(adapter=None, filepath=None)
    # dans_offset < rich_offset, difference <= 1024
    rich_results = [{"offset": 0x68}]
    dans_results = [{"offset": 0x40}]
    result = analyzer._try_rich_dans_combinations(rich_results, dans_results)
    assert result is not None
    assert result["xor_key"] == 0xDEADBEEF


class _ExtractRichWithCombinationsAnalyzer(RichHeaderAnalyzer):
    """Forces the r2pipe combinations path to succeed."""

    def _direct_file_rich_search(self) -> None:
        return None

    def _collect_rich_dans_offsets(self) -> tuple[list[dict], list[dict]]:
        return [{"offset": 0x68}], [{"offset": 0x40}]

    def _try_extract_rich_at_offsets(self, dans_offset: int, rich_offset: int) -> dict[str, Any]:
        return {
            "xor_key": 0xCAFEBABE,
            "entries": [{"product_id": 2, "build_number": 1, "count": 2}],
        }

    def _manual_rich_search(self) -> None:
        return None


def test_extract_rich_header_combinations_covers_line_307() -> None:
    """Line 307: _extract_rich_header returns data from _try_rich_dans_combinations."""
    analyzer = _ExtractRichWithCombinationsAnalyzer(adapter=None, filepath=None)
    result = analyzer._extract_rich_header()
    assert result is not None
    assert result["xor_key"] == 0xCAFEBABE


# ===========================================================================
# YARA ANALYZER TESTS
# ===========================================================================


class _MinimalConfig:
    def get_yara_rules_path(self) -> Path:
        return Path(tempfile.gettempdir()) / "r2inspect_yara_test"


def test_list_available_rules_outer_exception() -> None:
    """Lines 415-416: outer except in list_available_rules fires on embedded null char.

    os.path.exists() raises ValueError when the path contains a null byte.
    """
    config = _MinimalConfig()
    analyzer = YaraAnalyzer(adapter=_StubAdapter(), config=config, filepath=None)
    # A path with an embedded null character causes os.path.exists() to raise
    result = analyzer.list_available_rules(rules_path="\x00")
    # The exception is caught; the function returns an empty list
    assert isinstance(result, list)
    assert result == []


# ===========================================================================
# IMPFUZZY ANALYZER TESTS
# ===========================================================================


class _OrdinalOnlyImportAdapter:
    """Adapter whose get_imports() returns only ordinal imports (all filtered out)."""

    def get_imports(self) -> list[dict[str, Any]]:
        return [
            {"name": "ord_5", "libname": "kernel32.dll"},
            {"name": "ord_12", "libname": "user32.dll"},
        ]


class _ValidImportAdapter:
    """Adapter whose get_imports() returns real named imports."""

    def get_imports(self) -> list[dict[str, Any]]:
        return [
            {"name": "ExitProcess", "libname": "kernel32.dll"},
            {"name": "MessageBoxA", "libname": "user32.dll"},
        ]


def test_analyze_imports_ordinal_only_returns_no_processed_imports() -> None:
    """Lines 139-143: analyze_imports returns early when all imports are ordinal.

    _process_imports filters ord_* entries, leaving processed_imports=[].
    """
    if not os.path.exists(_HELLO_PE):
        pytest.skip("hello_pe.exe fixture not found")

    analyzer = ImpfuzzyAnalyzer(adapter=_OrdinalOnlyImportAdapter(), filepath=_HELLO_PE)
    result = analyzer.analyze_imports()
    assert result["available"] is False
    assert result["error"] == "No valid imports found after processing"


def test_analyze_imports_success_with_valid_imports() -> None:
    """Lines 139, 146, 152-176 (excluding 147-150 which are unreachable):
    analyze_imports succeeds when adapter supplies valid named imports.

    Also covers lines 266, 270-271 inside _process_imports.
    """
    if not os.path.exists(_HELLO_PE):
        pytest.skip("hello_pe.exe fixture not found")

    analyzer = ImpfuzzyAnalyzer(adapter=_ValidImportAdapter(), filepath=_HELLO_PE)
    result = analyzer.analyze_imports()
    assert result["available"] is True
    assert result["impfuzzy_hash"] is not None
    assert result["import_count"] >= 1
    assert result["dll_count"] >= 1
    assert isinstance(result["imports_processed"], list)


def test_calculate_hash_exception_on_mz_garbage_file() -> None:
    """Lines 84-86: _calculate_hash except clause fires when pyimpfuzzy raises.

    The file starts with 'MZ' so _is_pe_file() returns True, but pefile fails
    to parse the rest, raising PEFormatError which the except block catches.
    """
    data = b"MZ" + b"\xff" * 300
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode="wb") as f:
        f.write(data)
        path = f.name

    try:
        analyzer = ImpfuzzyAnalyzer(adapter=_StubAdapter(), filepath=path)
        hash_val, method, err = analyzer._calculate_hash()
        assert hash_val is None
        assert method is None
        assert err is not None
        assert "Impfuzzy calculation failed" in err
    finally:
        os.unlink(path)


class _SecondQueryDictAnalyzer(ImpfuzzyAnalyzer):
    """Returns [] for iij and a dict for ii to force lines 213-214."""

    def _cmdj(self, command: str, default: Any = None) -> Any:
        if command == "iij":
            return []
        if command == "ii":
            return {"name": "LoadLibraryA", "libname": "kernel32.dll"}
        return default if default is not None else []


def test_extract_imports_second_query_returns_dict() -> None:
    """Lines 213-214: _extract_imports falls back to 'ii' command which returns a dict.

    Exercises the elif isinstance(raw_imports, dict) branch in the fallback path.
    """
    if not os.path.exists(_HELLO_PE):
        pytest.skip("hello_pe.exe fixture not found")

    analyzer = _SecondQueryDictAnalyzer(adapter=_StubAdapter(), filepath=_HELLO_PE)
    imports = analyzer._extract_imports()
    # The dict was wrapped into a one-item list
    assert len(imports) == 1
    assert imports[0]["name"] == "LoadLibraryA"
