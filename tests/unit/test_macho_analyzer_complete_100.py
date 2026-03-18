"""Comprehensive tests for macho_analyzer.py - 100% coverage target.

No unittest.mock usage. Uses real MachOAnalyzer with fake adapter objects.
"""

from __future__ import annotations

from typing import Any

from r2inspect.modules.macho_analyzer import MachOAnalyzer


class _FakeMachOAdapter:
    """Adapter returning Mach-O data via the method names used by _handle_simple."""

    def __init__(
        self,
        *,
        file_info: dict[str, Any] | None = None,
        headers_json: list[dict[str, Any]] | None = None,
        sections: list[dict[str, Any]] | None = None,
        functions: list[dict[str, Any]] | None = None,
        imports: list[dict[str, Any]] | None = None,
        exports: list[dict[str, Any]] | None = None,
        strings: list[dict[str, Any]] | None = None,
        entry_info: list[dict[str, Any]] | None = None,
    ) -> None:
        self._file_info = file_info or {
            "bin": {
                "arch": "arm",
                "machine": "arm64",
                "bits": 64,
                "endian": "little",
                "class": "MACH064",
                "format": "mach-o",
                "baddr": 0x100000000,
                "cpu": "aarch64",
                "filetype": "EXECUTE",
            }
        }
        self._headers_json = headers_json or []
        self._sections = sections or []
        self._functions = functions or []
        self._imports = imports or []
        self._exports = exports or []
        self._strings = strings or []
        self._entry_info = entry_info or []

    def get_file_info(self) -> dict[str, Any]:
        return self._file_info

    def get_headers_json(self) -> list[dict[str, Any]]:
        return self._headers_json

    def get_sections(self) -> list[dict[str, Any]]:
        return self._sections

    def get_functions(self) -> list[dict[str, Any]]:
        return self._functions

    def get_imports(self) -> list[dict[str, Any]]:
        return self._imports

    def get_exports(self) -> list[dict[str, Any]]:
        return self._exports

    def get_strings(self) -> list[dict[str, Any]]:
        return self._strings

    def get_entry_info(self) -> list[dict[str, Any]]:
        return self._entry_info


def test_macho_analyzer_init() -> None:
    """Test MachOAnalyzer initialization."""
    adapter = _FakeMachOAdapter()
    analyzer = MachOAnalyzer(adapter=adapter)
    assert analyzer is not None
    assert analyzer.adapter is adapter


def test_macho_analyzer_get_category() -> None:
    """Test get_category returns 'format'."""
    analyzer = MachOAnalyzer(adapter=_FakeMachOAdapter())
    assert analyzer.get_category() == "format"


def test_macho_analyzer_get_description() -> None:
    """Test get_description returns meaningful text."""
    analyzer = MachOAnalyzer(adapter=_FakeMachOAdapter())
    desc = analyzer.get_description()
    assert "Mach-O" in desc


def test_macho_analyzer_supports_format() -> None:
    """Test supports_format accepts Mach-O format strings."""
    analyzer = MachOAnalyzer(adapter=_FakeMachOAdapter())
    assert analyzer.supports_format("MACH0") is True
    assert analyzer.supports_format("macho") is True
    assert analyzer.supports_format("MACH-O") is True
    assert analyzer.supports_format("MACH064") is True
    assert analyzer.supports_format("PE") is False
    assert analyzer.supports_format("ELF") is False


def test_macho_analyzer_analyze_basic() -> None:
    """Test analyze with basic adapter data."""
    adapter = _FakeMachOAdapter()
    analyzer = MachOAnalyzer(adapter=adapter)
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert result.get("architecture") == "arm"
    assert result.get("bits") == 64


def test_macho_analyzer_analyze_empty_info() -> None:
    """Test analyze when file_info has no 'bin' key."""
    adapter = _FakeMachOAdapter(file_info={})
    analyzer = MachOAnalyzer(adapter=adapter)
    result = analyzer.analyze()
    assert isinstance(result, dict)
    # Architecture should be 'Unknown' or the default
    assert "architecture" in result


def test_macho_analyzer_analyze_with_build_version() -> None:
    """Test analyze with LC_BUILD_VERSION header."""
    headers = [
        {
            "type": "LC_BUILD_VERSION",
            "platform": "macOS",
            "minos": "12.0.0",
            "sdk": "13.0",
        }
    ]
    adapter = _FakeMachOAdapter(headers_json=headers)
    analyzer = MachOAnalyzer(adapter=adapter)
    result = analyzer.analyze()
    assert isinstance(result, dict)


def test_macho_analyzer_analyze_with_version_min() -> None:
    """Test analyze with LC_VERSION_MIN_MACOSX header."""
    headers = [
        {
            "type": "LC_VERSION_MIN_MACOSX",
            "version": "10.15.0",
            "sdk": "11.0",
        }
    ]
    adapter = _FakeMachOAdapter(headers_json=headers)
    analyzer = MachOAnalyzer(adapter=adapter)
    result = analyzer.analyze()
    assert isinstance(result, dict)


def test_macho_analyzer_analyze_with_sections() -> None:
    """Test analyze with section data."""
    sections = [
        {"name": "__text", "size": 1024, "paddr": 0x1000, "vsize": 1024, "flags": 0},
        {"name": "__data", "size": 512, "paddr": 0x2000, "vsize": 512, "flags": 0},
    ]
    adapter = _FakeMachOAdapter(sections=sections)
    analyzer = MachOAnalyzer(adapter=adapter)
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert isinstance(result.get("sections"), list)


def test_macho_analyzer_analyze_error_handling() -> None:
    """Test analyze handles adapter errors gracefully."""

    class _RaisingAdapter(_FakeMachOAdapter):
        def get_file_info(self) -> dict:
            raise RuntimeError("file info failed")

    analyzer = MachOAnalyzer(adapter=_RaisingAdapter())
    result = analyzer.analyze()
    # Should return a result dict even on error
    assert isinstance(result, dict)


def test_macho_analyzer_analyze_none_file_info() -> None:
    """Test analyze when get_file_info returns None."""

    class _NoneInfoAdapter(_FakeMachOAdapter):
        def get_file_info(self) -> None:
            return None

    analyzer = MachOAnalyzer(adapter=_NoneInfoAdapter())
    result = analyzer.analyze()
    assert isinstance(result, dict)
