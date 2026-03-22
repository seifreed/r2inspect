#!/usr/bin/env python3
"""Extra coverage tests for pe_analyzer module.

NO mocks, NO @patch. Uses FakeR2 + R2PipeAdapter and real objects.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.pe_analyzer import PEAnalyzer
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
    filepath: str | None = None,
) -> PEAnalyzer:
    adapter = _make_adapter(cmdj_map=cmdj_map, cmd_map=cmd_map)
    return PEAnalyzer(adapter, config=None, filepath=filepath)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_pe_analyzer_init(tmp_path: Path):
    filepath = str(tmp_path / "test.exe")
    analyzer = _make_analyzer(filepath=filepath)
    assert analyzer.adapter is not None
    assert str(analyzer.filepath) == filepath


def test_get_category():
    analyzer = _make_analyzer()
    assert analyzer.get_category() == "format"


def test_get_description():
    analyzer = _make_analyzer()
    assert "PE" in analyzer.get_description()


def test_supports_format():
    analyzer = _make_analyzer()
    assert analyzer.supports_format("PE") is True
    assert analyzer.supports_format("PE32") is True
    assert analyzer.supports_format("PE32+") is True
    assert analyzer.supports_format("DLL") is True
    assert analyzer.supports_format("EXE") is True
    assert analyzer.supports_format("ELF") is False


def test_analyze_returns_dict(tmp_path: Path):
    """analyze() returns a dict with expected keys even for empty adapter."""
    filepath = str(tmp_path / "test.exe")
    analyzer = _make_analyzer(
        cmdj_map={
            "ij": {"bin": {"arch": "x86", "bits": 32, "format": "pe"}},
            "iij": [],
        },
        filepath=filepath,
    )
    result = analyzer.analyze()
    assert isinstance(result, dict)
    assert "imphash" in result


def test_get_security_features():
    """get_security_features returns a dict."""
    analyzer = _make_analyzer(
        cmdj_map={
            "ij": {"bin": {"flags": []}},
            "iHj": {},
        }
    )
    result = analyzer.get_security_features()
    assert isinstance(result, dict)


def test_get_resource_info():
    """get_resource_info returns a list."""
    analyzer = _make_analyzer(cmdj_map={"iRj": []})
    result = analyzer.get_resource_info()
    assert isinstance(result, list)


def test_get_version_info():
    """get_version_info returns a dict."""
    analyzer = _make_analyzer(cmdj_map={"iVj": {}})
    result = analyzer.get_version_info()
    assert isinstance(result, dict)


def test_calculate_imphash():
    """calculate_imphash returns a string."""
    analyzer = _make_analyzer(cmdj_map={"iij": []})
    result = analyzer.calculate_imphash()
    assert isinstance(result, str)


def test_determine_pe_format():
    """_determine_pe_format returns a format string."""
    analyzer = _make_analyzer()
    result = analyzer._determine_pe_format({"bits": 32}, None)
    assert isinstance(result, str)
