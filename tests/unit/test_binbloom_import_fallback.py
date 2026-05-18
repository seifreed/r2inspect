"""Test the pybloom_live import fallback in binbloom_analyzer."""

from __future__ import annotations

from r2inspect.modules import binbloom_analyzer


def test_binbloom_import_fallback_returns_unavailable_on_import_error():
    """A failing importer drives the real ImportError fallback branch
    (-> (None, False)) without poisoning the module table."""

    def _raising_importer() -> object:
        raise ImportError("pybloom_live blocked")

    result, available = binbloom_analyzer._import_bloom_filter(importer=_raising_importer)
    assert result is None
    assert available is False


def test_binbloom_import_succeeds_when_pybloom_live_present():
    """The real import path resolves the BloomFilter class (pybloom_live is
    installed in this environment)."""
    cls, available = binbloom_analyzer._import_bloom_filter()
    assert available is True
    assert cls is not None
