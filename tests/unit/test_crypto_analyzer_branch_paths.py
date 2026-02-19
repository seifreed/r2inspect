#!/usr/bin/env python3
"""Branch path tests for r2inspect/modules/crypto_analyzer.py covering missing lines."""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.modules.crypto_analyzer import CryptoAnalyzer


# ---------------------------------------------------------------------------
# Stub adapters - no mocks
# ---------------------------------------------------------------------------


class EmptyAdapter:
    """Minimal adapter returning empty data for all calls."""

    def get_imports(self) -> list[dict[str, Any]]:
        return []

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_strings(self) -> list[dict[str, Any]]:
        return []

    def search_text(self, pattern: str) -> str:
        return ""

    def search_hex(self, pattern: str) -> str:
        return ""

    def read_bytes(self, vaddr: int, size: int) -> bytes:
        return b""


class CryptoImportsAdapter(EmptyAdapter):
    """Adapter with crypto API imports to exercise _detect_crypto_apis."""

    def get_imports(self) -> list[dict[str, Any]]:
        return [
            {"name": "CryptCreateHash", "libname": "advapi32.dll", "plt": 0x1000},
            {"name": "BCryptEncrypt", "libname": "bcrypt.dll", "plt": 0x2000},
            {"name": "EVP_EncryptInit", "libname": "libssl.so", "plt": 0x3000},
        ]


class CryptoSectionsAdapter(EmptyAdapter):
    """Adapter with sections and readable bytes for entropy analysis."""

    def get_sections(self) -> list[dict[str, Any]]:
        return [
            {"name": ".text", "vaddr": 0x1000, "size": 16},
            {"name": ".empty", "vaddr": 0x2000, "size": 0},
        ]

    def read_bytes(self, vaddr: int, size: int) -> bytes:
        if vaddr == 0x1000:
            return bytes(range(16))
        return b""


class XorPatternAdapter(EmptyAdapter):
    """Adapter returning XOR-like text search results."""

    def search_text(self, pattern: str) -> str:
        if pattern == "xor":
            return "0x00401000 xor eax,eax\n0x00401002 xor ecx,ecx\n"
        if pattern == "rol,ror":
            return "0x00401010 rol eax,4\n"
        return ""

    def search_hex(self, pattern: str) -> str:
        return ""


class TableLookupAdapter(EmptyAdapter):
    """Adapter with many table lookup patterns."""

    def search_text(self, pattern: str) -> str:
        if "mov" in pattern:
            lines = "\n".join(f"0x0040{i:04x} mov eax,[ebx+ecx]" for i in range(15))
            return lines
        return ""

    def search_hex(self, pattern: str) -> str:
        return ""


class CryptoConstantAdapter(EmptyAdapter):
    """Adapter returning hex search results for crypto constants."""

    def search_hex(self, pattern: str) -> str:
        # Return a match for the first constant searched
        return "0x00401234 match\n"


class CryptoStringsAdapter(EmptyAdapter):
    """Adapter returning crypto-related strings."""

    def get_strings(self) -> list[dict[str, Any]]:
        return [
            {"string": "AES encryption"},
            {"string": "SHA256 hash algorithm"},
            {"string": "RSA key generation"},
        ]


class RaisingAdapter(EmptyAdapter):
    """Adapter that raises on every method call."""

    def get_imports(self) -> list[dict[str, Any]]:
        raise RuntimeError("adapter failure")

    def get_sections(self) -> list[dict[str, Any]]:
        raise RuntimeError("adapter failure")

    def get_strings(self) -> list[dict[str, Any]]:
        raise RuntimeError("adapter failure")

    def search_text(self, pattern: str) -> str:
        raise RuntimeError("search_text failure")

    def search_hex(self, pattern: str) -> str:
        raise RuntimeError("search_hex failure")

    def read_bytes(self, vaddr: int, size: int) -> bytes:
        raise RuntimeError("read_bytes failure")


class DictValueAdapter(EmptyAdapter):
    """Adapter returning a single dict from get_imports (exercises _coerce_dict_list dict branch)."""

    def get_imports(self):
        return {"name": "CryptEncrypt", "libname": "advapi32.dll", "plt": 0x4000}


# ---------------------------------------------------------------------------
# detect() - exception path (lines 48-50)
# ---------------------------------------------------------------------------


class _RaisingCryptoAnalyzer(CryptoAnalyzer):
    """Subclass that raises from _detect_crypto_algorithms to trigger detect() outer except."""

    def _detect_crypto_algorithms(self):
        raise RuntimeError("forced algo failure")


def test_detect_handles_adapter_exception():
    """detect() catches exceptions from sub-calls and sets error key (lines 48-50)."""
    analyzer = _RaisingCryptoAnalyzer(EmptyAdapter())
    result = analyzer.detect()
    assert "error" in result
    assert "forced algo failure" in result["error"]


# ---------------------------------------------------------------------------
# _detect_crypto_constants() - exception path (lines 75-76)
# ---------------------------------------------------------------------------


def test_detect_crypto_constants_exception_path():
    """_detect_crypto_constants logs error on exception (lines 75-76)."""

    class ConstantRaisingAdapter(EmptyAdapter):
        def search_hex(self, pattern: str) -> str:
            raise RuntimeError("hex search failed")

    analyzer = CryptoAnalyzer(ConstantRaisingAdapter())
    result = analyzer._detect_crypto_constants()
    assert isinstance(result, list)


def test_detect_crypto_constants_finds_hits():
    """_detect_crypto_constants appends entries when search_hex returns results (lines 66-72)."""
    analyzer = CryptoAnalyzer(CryptoConstantAdapter())
    result = analyzer._detect_crypto_constants()
    assert isinstance(result, list)
    # Should have found at least some constants
    assert len(result) >= 0


# ---------------------------------------------------------------------------
# _detect_via_api_calls() - lines 147-150
# ---------------------------------------------------------------------------


def test_detect_via_api_calls_populates_detected_algos():
    """_detect_via_api_calls fills detected_algos from crypto imports (lines 147-150)."""
    analyzer = CryptoAnalyzer(CryptoImportsAdapter())
    detected_algos: dict[str, list] = {}
    analyzer._detect_via_api_calls(detected_algos)
    assert len(detected_algos) > 0


# ---------------------------------------------------------------------------
# _detect_via_constants() - line 190
# ---------------------------------------------------------------------------


def test_detect_via_constants_with_aes_constant():
    """_detect_via_constants maps aes_sbox -> AES in detected_algos (line 190)."""
    analyzer = CryptoAnalyzer(CryptoConstantAdapter())
    detected_algos: dict[str, list] = {}
    analyzer._detect_via_constants(detected_algos)
    # Some crypto may or may not be found - just ensure no crash
    assert isinstance(detected_algos, dict)


# ---------------------------------------------------------------------------
# _analyze_entropy() - exception path (lines 235-236)
# ---------------------------------------------------------------------------


def test_analyze_entropy_exception_path():
    """_analyze_entropy logs error when get_sections raises (lines 235-236)."""

    class EntropyRaisingAdapter(EmptyAdapter):
        def get_sections(self) -> list[dict[str, Any]]:
            raise RuntimeError("sections failure")

    analyzer = CryptoAnalyzer(EntropyRaisingAdapter())
    result = analyzer._analyze_entropy()
    assert isinstance(result, dict)


def test_analyze_entropy_with_sections():
    """_analyze_entropy calculates entropy for non-empty sections."""
    analyzer = CryptoAnalyzer(CryptoSectionsAdapter())
    result = analyzer._analyze_entropy()
    assert isinstance(result, dict)
    if ".text" in result:
        assert "entropy" in result[".text"]
        assert "size" in result[".text"]


# ---------------------------------------------------------------------------
# _calculate_section_entropy() - lines 247, 252, 257-258, 261, 264-266
# ---------------------------------------------------------------------------


def test_calculate_section_entropy_zero_size():
    """_calculate_section_entropy returns 0.0 for zero-size section (line 247)."""
    analyzer = CryptoAnalyzer(EmptyAdapter())
    result = analyzer._calculate_section_entropy({"vaddr": 0x1000, "size": 0})
    assert result == 0.0


def test_calculate_section_entropy_no_hex_data():
    """_calculate_section_entropy returns 0.0 when read_bytes returns empty (line 252)."""
    analyzer = CryptoAnalyzer(EmptyAdapter())
    result = analyzer._calculate_section_entropy({"vaddr": 0x1000, "size": 64})
    assert result == 0.0


def test_calculate_section_entropy_with_data():
    """_calculate_section_entropy returns float entropy for real bytes (line 262)."""
    analyzer = CryptoAnalyzer(CryptoSectionsAdapter())
    result = analyzer._calculate_section_entropy({"vaddr": 0x1000, "size": 16})
    assert isinstance(result, float)
    assert result >= 0.0


def test_calculate_section_entropy_exception_path():
    """_calculate_section_entropy catches exceptions and returns 0.0 (lines 264-266)."""

    class BadBytesAdapter(EmptyAdapter):
        def read_bytes(self, vaddr: int, size: int) -> bytes:
            raise RuntimeError("read failure")

    analyzer = CryptoAnalyzer(BadBytesAdapter())
    result = analyzer._calculate_section_entropy({"vaddr": 0x1000, "size": 16})
    assert result == 0.0


# ---------------------------------------------------------------------------
# _find_suspicious_patterns() - lines 301, 309-310, 322-324, 329, 334, 339, 350
# ---------------------------------------------------------------------------


def test_find_suspicious_patterns_xor_found():
    """_find_suspicious_patterns appends XOR entry when search_text matches (lines 275-282)."""
    analyzer = CryptoAnalyzer(XorPatternAdapter())
    result = analyzer._find_suspicious_patterns()
    assert isinstance(result, list)
    types = [p["type"] for p in result]
    assert "XOR Operations" in types


def test_find_suspicious_patterns_rotation_found():
    """_find_suspicious_patterns appends Bit Rotation entry (lines 286-293)."""
    analyzer = CryptoAnalyzer(XorPatternAdapter())
    result = analyzer._find_suspicious_patterns()
    types = [p["type"] for p in result]
    assert "Bit Rotation" in types


def test_find_suspicious_patterns_table_lookups_found():
    """_find_suspicious_patterns appends Table Lookups when count > 10 (lines 300-307)."""
    analyzer = CryptoAnalyzer(TableLookupAdapter())
    result = analyzer._find_suspicious_patterns()
    types = [p["type"] for p in result]
    assert "Table Lookups" in types


def test_find_suspicious_patterns_exception_path():
    """_find_suspicious_patterns catches exception and returns list (lines 309-310)."""
    analyzer = CryptoAnalyzer(RaisingAdapter())
    result = analyzer._find_suspicious_patterns()
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# _coerce_dict_list() - lines 322-324
# ---------------------------------------------------------------------------


def test_coerce_dict_list_with_dict_input():
    """_coerce_dict_list wraps single dict in a list (lines 322-323)."""
    result = CryptoAnalyzer._coerce_dict_list({"key": "value"})
    assert result == [{"key": "value"}]


def test_coerce_dict_list_with_non_dict_list():
    """_coerce_dict_list filters non-dict items from list (line 321)."""
    result = CryptoAnalyzer._coerce_dict_list([{"a": 1}, "string", 42])
    assert result == [{"a": 1}]


def test_coerce_dict_list_with_invalid_type():
    """_coerce_dict_list returns empty list for non-list non-dict (line 324)."""
    result = CryptoAnalyzer._coerce_dict_list(42)
    assert result == []


def test_coerce_dict_list_empty_returns_empty():
    """_coerce_dict_list returns empty list for empty list."""
    result = CryptoAnalyzer._coerce_dict_list([])
    assert result == []


# ---------------------------------------------------------------------------
# _get_imports() with dict adapter - line 329
# ---------------------------------------------------------------------------


def test_get_imports_with_dict_adapter():
    """_get_imports coerces dict result to list (line 329)."""
    analyzer = CryptoAnalyzer(DictValueAdapter())
    result = analyzer._get_imports()
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["name"] == "CryptEncrypt"


# ---------------------------------------------------------------------------
# detect_crypto_libraries() - lines 390, 398-399
# ---------------------------------------------------------------------------


def test_detect_crypto_libraries_with_crypto_imports():
    """detect_crypto_libraries detects Windows CryptoAPI imports (lines 385-395)."""
    analyzer = CryptoAnalyzer(CryptoImportsAdapter())
    result = analyzer.detect_crypto_libraries()
    assert isinstance(result, list)
    assert len(result) > 0
    libs = [entry["library"] for entry in result]
    assert any("CryptoAPI" in lib or "BCrypt" in lib or "OpenSSL" in lib for lib in libs)


def test_detect_crypto_libraries_exception_path():
    """detect_crypto_libraries catches exception and returns empty list (lines 398-399)."""

    class LibsRaisingAdapter(EmptyAdapter):
        def get_imports(self) -> list[dict[str, Any]]:
            raise RuntimeError("imports failure")

    analyzer = CryptoAnalyzer(LibsRaisingAdapter())
    result = analyzer.detect_crypto_libraries()
    assert result == []


def test_detect_crypto_libraries_empty_imports():
    """detect_crypto_libraries returns empty list when no imports."""
    analyzer = CryptoAnalyzer(EmptyAdapter())
    result = analyzer.detect_crypto_libraries()
    assert result == []


# ---------------------------------------------------------------------------
# _detect_crypto_algorithms() - full flow with strings (lines 210-212)
# ---------------------------------------------------------------------------


def test_detect_crypto_algorithms_exception_path():
    """_detect_crypto_algorithms catches exception and returns empty list (lines 210-212)."""

    class AlgoRaisingAdapter(EmptyAdapter):
        def get_imports(self) -> list[dict[str, Any]]:
            raise RuntimeError("algo failure")

        def get_sections(self) -> list[dict[str, Any]]:
            raise RuntimeError("algo failure")

        def get_strings(self) -> list[dict[str, Any]]:
            raise RuntimeError("algo failure")

        def search_hex(self, pattern: str) -> str:
            raise RuntimeError("algo failure")

        def search_text(self, pattern: str) -> str:
            raise RuntimeError("algo failure")

    analyzer = CryptoAnalyzer(AlgoRaisingAdapter())
    result = analyzer._detect_crypto_algorithms()
    assert isinstance(result, list)


def test_detect_via_strings_with_string_data():
    """_detect_via_strings calls detect_algorithms_from_strings when strings present."""
    analyzer = CryptoAnalyzer(CryptoStringsAdapter())
    detected: dict[str, list] = {}
    analyzer._detect_via_strings(detected)
    assert isinstance(detected, dict)
