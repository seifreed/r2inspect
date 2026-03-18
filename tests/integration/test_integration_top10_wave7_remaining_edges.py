"""Remaining edge coverage for wave7 top10 modules."""

from __future__ import annotations

import binascii

from r2inspect.modules import string_domain as string_domain_module
from r2inspect.registry.entry_points import EntryPointLoader


class _DummyRegistry:
    pass


class _LoaderForLoop(EntryPointLoader):
    def _get_entry_points_group(self, group: str):  # type: ignore[override]
        assert group == "r2inspect.analyzers"
        return [object(), object(), object()]

    def _handle_entry_point(self, ep):  # type: ignore[override]
        _ = ep
        return 1


def test_entry_points_load_iterates_and_accumulates() -> None:
    loader = _LoaderForLoop(_DummyRegistry())
    assert loader.load() == 3


def test_string_domain_decode_base64_binascii_error(monkeypatch) -> None:
    def _boom(_value: str):
        raise binascii.Error("bad b64")

    monkeypatch.setattr(string_domain_module.base64, "b64decode", _boom)
    assert string_domain_module.decode_base64("QUJDRA==") is None
