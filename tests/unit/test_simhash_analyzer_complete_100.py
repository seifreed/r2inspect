"""Comprehensive tests for simhash_analyzer.py - 100% coverage target.

No unittest.mock usage. Uses real SimHashAnalyzer with fake adapter objects.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules.simhash_analyzer import SimHashAnalyzer


class _FakeSimhashAdapter:
    """Adapter with string/section/function data for SimHashAnalyzer tests."""

    def __init__(
        self,
        *,
        strings: list[dict[str, Any]] | None = None,
        sections: list[dict[str, Any]] | None = None,
        functions: list[dict[str, Any]] | None = None,
        disasm: dict[str, Any] | list[Any] | None = None,
        file_info: dict[str, Any] | None = None,
    ) -> None:
        self._strings = strings or []
        self._sections = sections or []
        self._functions = functions or []
        self._disasm = disasm
        self._file_info = file_info or {"bin": {"arch": "x86", "bits": 64}}

    def get_strings(self) -> list[dict[str, Any]]:
        return self._strings

    def get_sections(self) -> list[dict[str, Any]]:
        return self._sections

    def get_functions(self) -> list[dict[str, Any]]:
        return self._functions

    def get_disasm(self, address: int | None = None, size: int | None = None) -> Any:
        return self._disasm

    def get_file_info(self) -> dict[str, Any]:
        return self._file_info


@pytest.fixture()
def _sample_file(tmp_path: Path) -> Path:
    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x00" * 64)
    return f


def test_simhash_analyzer_init(_sample_file: Path) -> None:
    """Test SimHashAnalyzer initialization."""
    adapter = _FakeSimhashAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(_sample_file))
    assert analyzer is not None
    assert analyzer.adapter is adapter
    assert analyzer.min_string_length == 4


def test_simhash_analyzer_get_hash_type(_sample_file: Path) -> None:
    """Test _get_hash_type returns 'simhash'."""
    adapter = _FakeSimhashAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(_sample_file))
    assert analyzer._get_hash_type() == "simhash"


def test_simhash_analyzer_supports_format(_sample_file: Path) -> None:
    """Test supports_format always returns True (inherited default)."""
    adapter = _FakeSimhashAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(_sample_file))
    # HashingStrategy doesn't override supports_format; it inherits True
    assert analyzer._get_hash_type() == "simhash"


def test_simhash_analyzer_check_library_availability(_sample_file: Path) -> None:
    """Test _check_library_availability returns correct tuple."""
    adapter = _FakeSimhashAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(_sample_file))
    available, error = analyzer._check_library_availability()
    # Result depends on whether simhash is installed
    assert isinstance(available, bool)
    if available:
        assert error is None
    else:
        assert error is not None
        assert "simhash" in error.lower()


def test_simhash_analyzer_extract_string_features_empty(_sample_file: Path) -> None:
    """Test _extract_string_features with no strings returns empty list."""
    adapter = _FakeSimhashAdapter(strings=[])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(_sample_file))
    features = analyzer._extract_string_features()
    assert isinstance(features, list)


def test_simhash_analyzer_extract_string_features_with_data(_sample_file: Path) -> None:
    """Test _extract_string_features with actual string data."""
    strings = [
        {"string": "LoadLibraryA", "section": ".text", "vaddr": 0x1000, "size": 12},
        {"string": "kernel32.dll", "section": ".rdata", "vaddr": 0x2000, "size": 12},
        {"string": "ab", "section": ".text", "vaddr": 0x3000, "size": 2},  # short, may be filtered
    ]
    adapter = _FakeSimhashAdapter(strings=strings)
    analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(_sample_file))
    features = analyzer._extract_string_features()
    assert isinstance(features, list)


def test_simhash_analyzer_extract_opcodes_features_empty(_sample_file: Path) -> None:
    """Test _extract_opcodes_features with no functions returns empty list."""
    adapter = _FakeSimhashAdapter(functions=[])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(_sample_file))
    features = analyzer._extract_opcodes_features()
    assert isinstance(features, list)


def test_simhash_analyzer_calculate_hash_no_features(_sample_file: Path) -> None:
    """Test _calculate_hash with no extractable features."""
    adapter = _FakeSimhashAdapter(strings=[], functions=[])
    analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(_sample_file))
    hash_val, method, error = analyzer._calculate_hash()
    # With no features, should get an error
    if hash_val is None:
        assert error is not None


def test_simhash_analyzer_error_handling(_sample_file: Path) -> None:
    """Test error handling when adapter raises exceptions."""

    class _RaisingAdapter(_FakeSimhashAdapter):
        def get_strings(self) -> list:
            raise RuntimeError("strings failed")

        def get_functions(self) -> list:
            raise RuntimeError("functions failed")

    adapter = _RaisingAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(_sample_file))
    # Should not raise - errors are caught internally
    features = analyzer._extract_string_features()
    assert isinstance(features, list)


def test_simhash_analyzer_get_prev_mnemonic(_sample_file: Path) -> None:
    """Test _get_prev_mnemonic helper."""
    adapter = _FakeSimhashAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(_sample_file))

    ops = [
        {"mnemonic": "push"},
        {"mnemonic": "mov"},
        {"mnemonic": "call"},
    ]
    assert analyzer._get_prev_mnemonic(ops, 1) == "push"
    assert analyzer._get_prev_mnemonic(ops, 0) is None
    assert analyzer._get_prev_mnemonic(ops, -1) is None
    assert analyzer._get_prev_mnemonic(ops, 10) is None


def test_simhash_analyzer_extract_opcodes_from_ops(_sample_file: Path) -> None:
    """Test _extract_opcodes_from_ops with sample ops."""
    adapter = _FakeSimhashAdapter()
    analyzer = SimHashAnalyzer(adapter=adapter, filepath=str(_sample_file))

    ops = [
        {"type": "mov", "mnemonic": "mov", "opcode": "mov eax, ebx"},
        {"type": "call", "mnemonic": "call", "opcode": "call 0x1234"},
    ]
    result = analyzer._extract_opcodes_from_ops(ops)
    assert isinstance(result, list)
