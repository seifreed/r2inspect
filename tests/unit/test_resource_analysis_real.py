#!/usr/bin/env python3
"""Tests for modules/resource_analyzer.py run_resource_analysis function.

Uses FakeR2 + R2PipeAdapter exclusively. NO mocks, NO monkeypatch, NO @patch.
"""

from __future__ import annotations

from typing import Any

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.modules.resource_analyzer import ResourceAnalyzer, run_resource_analysis
from r2inspect.infrastructure.logging import get_logger
from r2inspect.testing.fake_r2 import FakeR2

logger = get_logger(__name__)


def _make_analyzer(
    cmdj_map: dict[str, Any] | None = None,
    cmd_map: dict[str, str] | None = None,
) -> ResourceAnalyzer:
    """Create a ResourceAnalyzer backed by FakeR2 + R2PipeAdapter."""
    fake_r2 = FakeR2(cmdj_map=cmdj_map, cmd_map=cmd_map)
    adapter = R2PipeAdapter(fake_r2)
    return ResourceAnalyzer(adapter=adapter)


# ---------------------------------------------------------------------------
# Basic: no resource directory at all
# ---------------------------------------------------------------------------


def test_run_resource_analysis_basic():
    """No resource directory => available=True, has_resources=False."""
    # iDj returns empty => _get_resource_directory returns None
    analyzer = _make_analyzer(cmdj_map={"iDj": []})
    result = run_resource_analysis(analyzer, logger)

    assert result["available"] is True
    assert result["has_resources"] is False


# ---------------------------------------------------------------------------
# With resources: directory present and parseable entries
# ---------------------------------------------------------------------------


def _bytes_to_hex(data: list[int]) -> str:
    return "".join(f"{b:02x}" for b in data)


def test_run_resource_analysis_with_resources():
    """Resource directory present with two valid entries."""
    resource_bytes_icon = [0x00] * 1024
    resource_bytes_version = [0x00] * 512

    cmdj_map: dict[str, Any] = {
        "iDj": [
            {"name": "RESOURCE", "vaddr": 0x4000, "paddr": 0x3000, "size": 0x1000},
        ],
        "iRj": [
            {
                "name": "icon.ico",
                "type": "RT_ICON",
                "type_id": 3,
                "lang": "en-US",
                "paddr": 0x5000,
                "size": 1024,
                "vaddr": 0x6000,
            },
            {
                "name": "version.res",
                "type": "RT_VERSION",
                "type_id": 16,
                "lang": "en-US",
                "paddr": 0x7000,
                "size": 512,
                "vaddr": 0x8000,
            },
        ],
    }
    cmd_map = {
        f"p8 1024 @ {0x5000}": _bytes_to_hex(resource_bytes_icon),
        f"p8 512 @ {0x7000}": _bytes_to_hex(resource_bytes_version),
    }

    analyzer = _make_analyzer(cmdj_map=cmdj_map, cmd_map=cmd_map)
    result = run_resource_analysis(analyzer, logger)

    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["resource_directory"] is not None
    assert result["total_resources"] == 2


# ---------------------------------------------------------------------------
# Directory present but no parseable resource entries
# ---------------------------------------------------------------------------


def test_run_resource_analysis_no_resources():
    """Resource directory exists but iRj returns empty list."""
    cmdj_map: dict[str, Any] = {
        "iDj": [
            {"name": "RESOURCE", "vaddr": 0x4000, "paddr": 0x3000, "size": 0x1000},
        ],
        "iRj": [],
        # Also need iSj for manual fallback (empty so nothing found)
        "iSj": [],
    }

    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = run_resource_analysis(analyzer, logger)

    assert result["available"] is True
    assert result["has_resources"] is True
    # _parse_resources returns [] and _normalize_resources returns [],
    # so total_resources stays at 0
    assert result["total_resources"] == 0


# ---------------------------------------------------------------------------
# Directory present, _parse_resources returns None (iRj returns None)
# ---------------------------------------------------------------------------


def test_run_resource_analysis_none_resources():
    """Resource directory exists but iRj returns None => empty resources."""
    cmdj_map: dict[str, Any] = {
        "iDj": [
            {"name": "RESOURCE", "vaddr": 0x4000, "paddr": 0x3000, "size": 0x1000},
        ],
        "iRj": None,
        "iSj": [],
    }

    analyzer = _make_analyzer(cmdj_map=cmdj_map)
    result = run_resource_analysis(analyzer, logger)

    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["total_resources"] == 0


# ---------------------------------------------------------------------------
# Exception during resource analysis
# ---------------------------------------------------------------------------


class _RaisingResourceAnalyzer(ResourceAnalyzer):
    """ResourceAnalyzer subclass that raises in _get_resource_directory.

    The real _get_resource_directory catches exceptions internally, so to
    exercise run_resource_analysis's outer except branch we override the
    method to let the error propagate.
    """

    def _get_resource_directory(self) -> dict[str, Any] | None:
        raise RuntimeError("Test error")


def test_run_resource_analysis_exception():
    """Exception propagating from analyzer method => available=False, error set."""
    fake_r2 = FakeR2()
    adapter = R2PipeAdapter(fake_r2)
    analyzer = _RaisingResourceAnalyzer(adapter=adapter)

    result = run_resource_analysis(analyzer, logger)

    assert result["available"] is False
    assert result["has_resources"] is False
    assert "error" in result
    assert "Test error" in result["error"]
