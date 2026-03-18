from __future__ import annotations

import os
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from r2inspect.modules.impfuzzy_analyzer import ImpfuzzyAnalyzer
from r2inspect.modules.rich_header_analyzer import PEFILE_AVAILABLE, RichHeaderAnalyzer
from r2inspect.modules.yara_analyzer import YaraAnalyzer


_FIXTURES_DIR = PROJECT_ROOT / "samples" / "fixtures"
_HELLO_PE = str(_FIXTURES_DIR / "hello_pe.exe")
_DANS = 0x536E6144
_RICH = 0x68636952


class StubAdapter:
    pass


class MinimalYaraConfig:
    def get_yara_rules_path(self) -> Path:
        return Path(tempfile.gettempdir()) / "r2inspect_yara_test"


class OrdinalOnlyImportAdapter:
    def get_imports(self) -> list[dict[str, Any]]:
        return [
            {"name": "ord_5", "libname": "kernel32.dll"},
            {"name": "ord_12", "libname": "user32.dll"},
        ]


class ValidImportAdapter:
    def get_imports(self) -> list[dict[str, Any]]:
        return [
            {"name": "ExitProcess", "libname": "kernel32.dll"},
            {"name": "MessageBoxA", "libname": "user32.dll"},
        ]


def _build_pe_with_rich_header() -> bytes:
    xor_key = 0x12345678
    entries = [
        (0x0001 | (0x7809 << 16), 5),
        (0x0053 | (0x8F5C << 16), 3),
    ]

    stub_dwords = [_DANS ^ xor_key, xor_key, xor_key, xor_key]
    for value, count in entries:
        stub_dwords.append(value ^ xor_key)
        stub_dwords.append(count ^ xor_key)
    stub_dwords.extend([_RICH, xor_key])
    stub_bytes = struct.pack("<" + "I" * len(stub_dwords), *stub_dwords)

    pre_rich_pad = b"\x00" * (0x80 - 0x40)
    pe_offset = 0x80 + len(stub_bytes)
    if pe_offset % 8:
        pad = 8 - (pe_offset % 8)
        stub_bytes += b"\x00" * pad
        pe_offset += pad

    mz = bytearray(0x40)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, pe_offset)

    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x014C, 0, 0, 0, 0, 0x60, 0x0002)
    opt = struct.pack("<HBB", 0x010B, 6, 0)
    opt += struct.pack("<IIIIIII", 0x200, 0, 0, 0x1000, 0x1000, 0, 0x400000)
    opt += struct.pack("<II", 0x1000, 0x200)
    opt += struct.pack("<HHHH", 5, 1, 0, 0)
    opt += struct.pack("<HH", 5, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<III", 0x2000, pe_offset + len(pe_sig) + len(coff) + 0x60, 0)
    opt += struct.pack("<HH", 2, 0)
    opt += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)
    opt += b"\x00" * (16 * 8)

    return bytes(mz) + pre_rich_pad + stub_bytes + pe_sig + coff + opt + b"\x00" * 256


def _write_tmp(data: bytes, suffix: str = ".exe") -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode="wb") as handle:
        handle.write(data)
    return handle.name


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not installed")
def test_rich_header_pefile_path_extracts_hash_and_entries() -> None:
    path = _write_tmp(_build_pe_with_rich_header())
    try:
        analyzer = RichHeaderAnalyzer(adapter=StubAdapter(), filepath=path)
        result = analyzer.analyze()

        assert result["is_pe"] is True
        assert result["method_used"] == "pefile"
        assert result["richpe_hash"]
        extracted = analyzer._extract_rich_header_pefile()
        assert extracted is not None
        assert extracted["entries"]
    finally:
        os.unlink(path)


def test_yara_and_impfuzzy_fail_safely_on_edge_inputs() -> None:
    yara = YaraAnalyzer(adapter=StubAdapter(), config=MinimalYaraConfig(), filepath=None)
    assert yara.list_available_rules(rules_path="\x00") == []

    if os.path.exists(_HELLO_PE) and ImpfuzzyAnalyzer.is_available():
        ordinal = ImpfuzzyAnalyzer(adapter=OrdinalOnlyImportAdapter(), filepath=_HELLO_PE)
        ordinal_result = ordinal.analyze_imports()
        assert ordinal_result["available"] is False
        assert ordinal_result["error"] == "No valid imports found after processing"

        valid = ImpfuzzyAnalyzer(adapter=ValidImportAdapter(), filepath=_HELLO_PE)
        valid_result = valid.analyze_imports()
        assert valid_result["available"] is True
        assert valid_result["impfuzzy_hash"]
        assert valid_result["dll_count"] >= 1


def test_impfuzzy_reports_parse_failure_for_malformed_mz_file() -> None:
    path = _write_tmp(b"MZ" + b"\xff" * 300)
    try:
        analyzer = ImpfuzzyAnalyzer(adapter=StubAdapter(), filepath=path)
        hash_value, method, error = analyzer._calculate_hash()
        assert hash_value is None
        assert method is None
        assert error is not None
        assert "Impfuzzy calculation failed" in error
    finally:
        os.unlink(path)
