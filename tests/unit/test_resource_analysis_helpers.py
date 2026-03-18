"""Tests for run_resource_analysis using real ResourceAnalyzer + FakeR2Adapter.

NO mocks, NO monkeypatch, NO @patch.
"""

from __future__ import annotations

import pytest
from typing import Any

from r2inspect.modules.resource_analyzer import ResourceAnalyzer, run_resource_analysis
from r2inspect.infrastructure.logging import get_logger

logger = get_logger(__name__)


class FakeR2Adapter:
    """Minimal adapter double exposing only the methods the resource pipeline needs."""

    def __init__(
        self,
        *,
        data_directories: list[dict[str, Any]] | Exception | None = None,
        resources_info: list[dict[str, Any]] | Exception | None = None,
        bytes_at: dict[int, list[int]] | None = None,
    ) -> None:
        self._data_directories = data_directories
        self._resources_info = resources_info
        self._bytes_at = bytes_at or {}

    # --- simple-base-call methods looked up by _SIMPLE_BASE_CALLS ---

    def get_data_directories(self) -> Any:
        if isinstance(self._data_directories, Exception):
            raise self._data_directories
        return self._data_directories

    def get_resources_info(self) -> Any:
        if isinstance(self._resources_info, Exception):
            raise self._resources_info
        return self._resources_info

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_bytes(self, *, address: int, size: int = 0) -> list[int]:
        return self._bytes_at.get(address, [])

    # Stubs the adapter search/dispatch paths may probe
    def get_file_info(self) -> dict[str, Any] | None:
        return None


def _make_analyzer(adapter: FakeR2Adapter) -> ResourceAnalyzer:
    return ResourceAnalyzer(adapter=adapter)


# --- test: no resources (empty data dirs) ---


def test_run_resource_analysis_no_resources():
    adapter = FakeR2Adapter(data_directories=[])
    analyzer = _make_analyzer(adapter)

    result = run_resource_analysis(analyzer, logger)

    assert result["available"] is True
    assert result["has_resources"] is False


def test_run_resource_analysis_no_resources_none_data_dirs():
    adapter = FakeR2Adapter(data_directories=None)
    analyzer = _make_analyzer(adapter)

    result = run_resource_analysis(analyzer, logger)

    assert result["available"] is True
    assert result["has_resources"] is False


# --- test: resources present and parsed ---


def test_run_resource_analysis_with_resources():
    adapter = FakeR2Adapter(
        data_directories=[
            {"name": "RESOURCE", "vaddr": 0x1000, "paddr": 0x800, "size": 0x200},
        ],
        resources_info=[
            {
                "name": "icon_res",
                "type": "ICON",
                "type_id": 3,
                "lang": "ENGLISH",
                "paddr": 0x900,
                "size": 100,
                "vaddr": 0x1100,
            },
            {
                "name": "version_res",
                "type": "VERSION",
                "type_id": 16,
                "lang": "ENGLISH",
                "paddr": 0xA00,
                "size": 200,
                "vaddr": 0x1200,
            },
        ],
    )
    analyzer = _make_analyzer(adapter)

    result = run_resource_analysis(analyzer, logger)

    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["total_resources"] == 2
    # resource_types should have been populated via _analyze_resource_types
    assert isinstance(result.get("resource_types"), list)


# --- test: resource dir present but resource list is empty ---


def test_run_resource_analysis_empty_resource_list():
    adapter = FakeR2Adapter(
        data_directories=[
            {"name": "RESOURCE", "vaddr": 0x1000, "paddr": 0x800, "size": 0x200},
        ],
        resources_info=[],
    )
    analyzer = _make_analyzer(adapter)

    result = run_resource_analysis(analyzer, logger)

    assert result["available"] is True
    assert result["has_resources"] is True
    assert result["total_resources"] == 0


# --- test: exception during init_result_structure (via bad subclass) ---


class _BrokenInitAnalyzer(ResourceAnalyzer):
    """ResourceAnalyzer subclass whose _init_result_structure always raises."""

    def _init_result_structure(self, additional_fields=None):
        raise RuntimeError("Init failed")


def test_run_resource_analysis_exception():
    adapter = FakeR2Adapter(data_directories=[])
    analyzer = _BrokenInitAnalyzer(adapter=adapter)

    result = run_resource_analysis(analyzer, logger)

    assert result["available"] is False
    assert "Init failed" in result.get("error", "")


# --- test: exception during _parse_resources ---


class _BrokenParseAnalyzer(ResourceAnalyzer):
    """ResourceAnalyzer subclass whose _parse_resources always raises."""

    def _parse_resources(self):
        raise RuntimeError("Parse error")


def test_run_resource_analysis_parse_exception():
    adapter = FakeR2Adapter(
        data_directories=[
            {"name": "RESOURCE", "vaddr": 0x1000, "paddr": 0x800, "size": 0x200},
        ],
        resources_info=[],
    )
    analyzer = _BrokenParseAnalyzer(adapter=adapter)

    result = run_resource_analysis(analyzer, logger)

    assert result["available"] is False
    assert "Parse error" in result.get("error", "")
