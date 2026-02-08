from __future__ import annotations

import pytest

from r2inspect.abstractions.base_analyzer import BaseAnalyzer
from r2inspect.registry.analyzer_registry import AnalyzerRegistry


class EPAnalyzer(BaseAnalyzer):
    def analyze(self) -> dict:
        return {"ok": True}

    def get_category(self) -> str:
        return "metadata"


class FakeEP:
    def __init__(self, name: str, obj):
        self.name = name
        self._obj = obj

    def load(self):
        return self._obj


def test_handle_entry_point_callable_and_class():
    registry = AnalyzerRegistry(lazy_loading=False)

    def registrar(reg):
        reg.register(
            name="ep",
            analyzer_class=EPAnalyzer,
            category=reg._parse_category("metadata"),
        )

    loaded = registry._handle_entry_point(FakeEP("call", registrar))
    assert loaded == 1
    assert registry.is_registered("ep") is True

    loaded = registry._handle_entry_point(FakeEP("class", EPAnalyzer))
    assert loaded == 1


def test_handle_entry_point_errors():
    registry = AnalyzerRegistry(lazy_loading=False)

    def bad_callable(_reg):
        raise RuntimeError("boom")

    loaded = registry._handle_entry_point(FakeEP("bad", bad_callable))
    assert loaded == 0

    class Bad:
        pass

    loaded = registry._handle_entry_point(FakeEP("badclass", Bad))
    assert loaded == 0
