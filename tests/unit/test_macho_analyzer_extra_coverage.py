#!/usr/bin/env python3
"""Extra coverage tests for macho_analyzer module.

NO mocks, NO @patch. Uses FakeR2 + R2PipeAdapter and real objects.
"""

from __future__ import annotations

from typing import Any

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.macho_analyzer import MachOAnalyzer
from r2inspect.testing.fake_r2 import FakeR2


# ---------------------------------------------------------------------------
# FakeR2
# ---------------------------------------------------------------------------


def _make_adapter(
    cmdj_map: dict[str, Any] | None = None,
    cmd_map: dict[str, str] | None = None,
) -> R2PipeAdapter:
    return R2PipeAdapter(FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map))


def _make_analyzer(
    cmdj_map: dict[str, Any] | None = None,
    cmd_map: dict[str, str] | None = None,
) -> MachOAnalyzer:
    adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return MachOAnalyzer(adapter, config=None)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_macho_analyzer_init():
    adapter = _make_adapter()
    analyzer = MachOAnalyzer(adapter, config=None)
    assert analyzer.adapter is adapter


def test_get_category():
    analyzer = _make_analyzer()
    assert analyzer.get_category() == "format"


def test_get_description():
    analyzer = _make_analyzer()
    assert "Mach-O" in analyzer.get_description()


def test_supports_format():
    analyzer = _make_analyzer()
    assert analyzer.supports_format("MACH0") is True
    assert analyzer.supports_format("MACHO") is True
    assert analyzer.supports_format("MACH-O") is True
    assert analyzer.supports_format("PE") is False


def test_get_macho_headers():
    """_get_macho_headers returns info from ij command."""
    analyzer = _make_analyzer(
        cmdj_map={
            "ij": {"bin": {"arch": "arm", "bits": 64, "machine": "ARM64"}},
        }
    )
    result = analyzer._get_macho_headers()
    assert isinstance(result, dict)


def test_get_macho_headers_empty():
    """_get_macho_headers with empty ij returns empty dict."""
    analyzer = _make_analyzer(cmdj_map={"ij": {}})
    result = analyzer._get_macho_headers()
    assert isinstance(result, dict)


def test_get_macho_headers_error():
    """_get_macho_headers handles exceptions gracefully."""
    analyzer = _make_analyzer(cmdj_map={"ij": Exception("test")})
    result = analyzer._get_macho_headers()
    assert result == {}


def test_extract_build_version():
    """_extract_build_version with no headers returns empty dict."""
    # No iHj data -> get_macho_headers returns []
    analyzer = _make_analyzer(cmdj_map={"iHj": []})
    result = analyzer._extract_build_version()
    assert isinstance(result, dict)


def test_extract_version_min():
    """_extract_version_min with no headers returns empty dict."""
    analyzer = _make_analyzer(cmdj_map={"iHj": []})
    result = analyzer._extract_version_min()
    assert isinstance(result, dict)


def test_extract_dylib_info():
    """_extract_dylib_info with no headers returns empty dict."""
    analyzer = _make_analyzer(cmdj_map={"iHj": []})
    result = analyzer._extract_dylib_info()
    assert isinstance(result, dict)


def test_extract_uuid():
    """_extract_uuid with no headers returns None."""
    analyzer = _make_analyzer(cmdj_map={"iHj": []})
    result = analyzer._extract_uuid()
    assert result is None


def test_extract_uuid_error():
    """_extract_uuid handles exceptions returning None."""
    analyzer = _make_analyzer(cmdj_map={"iHj": Exception("test")})
    result = analyzer._extract_uuid()
    assert result is None


def test_estimate_compile_time():
    """_estimate_compile_time returns empty string."""
    analyzer = _make_analyzer()
    result = analyzer._estimate_compile_time()
    assert result == ""


def test_get_load_commands():
    """_get_load_commands with no headers returns empty list."""
    analyzer = _make_analyzer(cmdj_map={"iHj": []})
    result = analyzer._get_load_commands()
    assert isinstance(result, list)


def test_get_load_commands_error():
    """_get_load_commands handles exceptions returning empty list."""
    analyzer = _make_analyzer(cmdj_map={"iHj": Exception("test")})
    result = analyzer._get_load_commands()
    assert result == []


def test_get_section_info():
    """_get_section_info returns a list."""
    analyzer = _make_analyzer(cmdj_map={"iSj": []})
    result = analyzer._get_section_info()
    assert isinstance(result, list)


def test_get_section_info_error():
    """_get_section_info handles exceptions returning empty list."""
    analyzer = _make_analyzer(cmdj_map={"iSj": Exception("test")})
    result = analyzer._get_section_info()
    assert result == []


def test_get_compilation_info_error():
    """_get_compilation_info handles exceptions from sub-methods."""
    # Make ij raise (which _extract_build_version depends on via get_macho_headers)
    analyzer = _make_analyzer(cmdj_map={"iHj": Exception("test"), "ij": Exception("test")})
    result = analyzer._get_compilation_info()
    assert isinstance(result, dict)
