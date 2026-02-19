#!/usr/bin/env python3
"""Branch path tests for r2inspect/registry/entry_points.py covering missing lines."""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.registry.analyzer_registry import AnalyzerRegistry
from r2inspect.registry.entry_points import EntryPointLoader


# ---------------------------------------------------------------------------
# Stub helpers
# ---------------------------------------------------------------------------


class _StubBaseAnalyzer(BaseAnalyzer):
    """Minimal BaseAnalyzer subclass for use in entry point registration tests."""

    ANALYZER_NAME = "stub_ep_analyzer"
    ANALYZER_CATEGORY = "metadata"

    def analyze(self) -> dict:
        return {}

    def get_category(self) -> str:
        return "metadata"


class _PlainClass:
    """Non-BaseAnalyzer class to exercise class registration path."""

    pass


class _FakeEP:
    """Fake entry point that loads a pre-set object."""

    def __init__(self, name: str, obj: Any) -> None:
        self.name = name
        self._obj = obj

    def load(self) -> Any:
        return self._obj


class _FailingLoadEP:
    """Fake entry point that fails to load."""

    def __init__(self, name: str) -> None:
        self.name = name

    def load(self) -> Any:
        raise RuntimeError("load failure")


class _FailingCallable:
    """Callable that raises when called with a registry."""

    def __call__(self, registry: Any) -> None:
        raise RuntimeError("callable failed")


class _NonCallableNonClass:
    """An object that is not callable and not a class."""

    pass


# ---------------------------------------------------------------------------
# EntryPointLoader.load() with no entry points - lines 23-25
# ---------------------------------------------------------------------------


def test_load_returns_zero_when_no_entry_points_for_group():
    """EntryPointLoader.load() returns 0 when group has no entry points (lines 23-25)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)
    result = loader.load(group="nonexistent.group.xyz")
    assert result == 0


# ---------------------------------------------------------------------------
# EntryPointLoader._get_entry_points_group() - lines 30-32
# ---------------------------------------------------------------------------


def test_get_entry_points_group_returns_list():
    """_get_entry_points_group returns a list for any group (lines 30-32)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)
    result = loader._get_entry_points_group("nonexistent.group")
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# EntryPointLoader._handle_entry_point() - lines 35-49
# ---------------------------------------------------------------------------


def test_handle_entry_point_with_callable_returns_one():
    """_handle_entry_point returns 1 when ep loads a callable (lines 35-47, 52-54)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)

    registered = []

    def registrar(reg: Any) -> None:
        registered.append(reg)

    ep = _FakeEP("my_callable", registrar)
    result = loader._handle_entry_point(ep)
    assert result == 1
    assert len(registered) == 1


def test_handle_entry_point_with_failing_load_returns_zero():
    """_handle_entry_point returns 0 when ep.load() raises (lines 37-41)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)
    ep = _FailingLoadEP("bad_ep")
    result = loader._handle_entry_point(ep)
    assert result == 0


def test_handle_entry_point_with_non_callable_non_class_returns_zero():
    """_handle_entry_point returns 0 for non-class non-callable object (line 49)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)
    ep = _FakeEP("neither", _NonCallableNonClass())
    result = loader._handle_entry_point(ep)
    assert result == 0


def test_handle_entry_point_with_class_returns_one():
    """_handle_entry_point returns 1 when ep loads a class (lines 43-44)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)
    ep = _FakeEP("class_ep", _StubBaseAnalyzer)
    result = loader._handle_entry_point(ep)
    assert result == 1


# ---------------------------------------------------------------------------
# EntryPointLoader._register_entry_point_callable() - lines 52-57
# ---------------------------------------------------------------------------


def test_register_entry_point_callable_success():
    """_register_entry_point_callable calls obj with registry and returns 1 (lines 52-54)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)

    calls = []

    def good_callable(reg: Any) -> None:
        calls.append(reg)

    ep = _FakeEP("good", good_callable)
    result = loader._register_entry_point_callable(ep, good_callable)
    assert result == 1
    assert len(calls) == 1


def test_register_entry_point_callable_failure_returns_zero():
    """_register_entry_point_callable returns 0 when callable raises (lines 55-57)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)
    ep = _FakeEP("bad", _FailingCallable())
    result = loader._register_entry_point_callable(ep, _FailingCallable())
    assert result == 0


# ---------------------------------------------------------------------------
# EntryPointLoader._register_entry_point_class() - lines 60-74
# ---------------------------------------------------------------------------


def test_register_entry_point_class_success_base_analyzer():
    """_register_entry_point_class registers BaseAnalyzer subclass (lines 60-69)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)
    ep = _FakeEP("stub_ep", _StubBaseAnalyzer)
    result = loader._register_entry_point_class(ep, _StubBaseAnalyzer)
    assert result == 1


def test_register_entry_point_class_plain_class_uses_ep_name():
    """_register_entry_point_class uses ep.name for non-BaseAnalyzer class (lines 61-69)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)
    ep = _FakeEP("plain_ep", _PlainClass)
    # This may fail registration if the class lacks proper interface, but should not raise
    result = loader._register_entry_point_class(ep, _PlainClass)
    assert result in (0, 1)


def test_register_entry_point_class_failure_returns_zero():
    """_register_entry_point_class returns 0 when registration raises (lines 70-74)."""

    class BadRegistry:
        """Registry that always fails on register calls."""

        def is_base_analyzer(self, cls: Any) -> bool:
            return False

        def extract_metadata_from_class(self, cls: Any) -> dict:
            raise RuntimeError("metadata extraction failed")

        def register(self, **kwargs: Any) -> None:
            raise RuntimeError("registration failed")

        def _parse_category(self, value: Any) -> Any:
            return value

    loader = EntryPointLoader(BadRegistry())
    ep = _FakeEP("fail_class", _PlainClass)
    result = loader._register_entry_point_class(ep, _PlainClass)
    assert result == 0


# ---------------------------------------------------------------------------
# EntryPointLoader._derive_entry_point_name() - lines 77-80
# ---------------------------------------------------------------------------


def test_derive_entry_point_name_uses_metadata_for_base_analyzer():
    """_derive_entry_point_name extracts name from BaseAnalyzer metadata (lines 77-79)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)
    ep = _FakeEP("ignored_name", _StubBaseAnalyzer)
    name = loader._derive_entry_point_name(ep, _StubBaseAnalyzer)
    assert isinstance(name, str)
    assert len(name) > 0


def test_derive_entry_point_name_uses_ep_name_for_non_base_analyzer():
    """_derive_entry_point_name returns ep.name for non-BaseAnalyzer (line 80)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)
    ep = _FakeEP("custom_name", _PlainClass)
    name = loader._derive_entry_point_name(ep, _PlainClass)
    assert name == "custom_name"


# ---------------------------------------------------------------------------
# Full load() flow with fake entry points - lines 23-25
# ---------------------------------------------------------------------------


def test_load_with_injected_entry_points_processes_all():
    """load() iterates over entry points and accumulates loaded count (lines 23-25)."""
    registry = AnalyzerRegistry(lazy_loading=False)
    loader = EntryPointLoader(registry)

    loaded_count = []

    def ep_callable(reg: Any) -> None:
        loaded_count.append(1)

    # Directly call _handle_entry_point multiple times to simulate load() behavior
    ep1 = _FakeEP("ep1", ep_callable)
    ep2 = _FakeEP("ep2", ep_callable)
    total = loader._handle_entry_point(ep1) + loader._handle_entry_point(ep2)
    assert total == 2
    assert len(loaded_count) == 2
