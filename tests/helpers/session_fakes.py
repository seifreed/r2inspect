from __future__ import annotations

from typing import Any

from .r2_fakes import FakeR2Adapter


class FakeSession:
    """Small concrete session wrapper for integration-style analyzer tests."""

    def __init__(self, adapter: FakeR2Adapter | None = None) -> None:
        self.adapter = adapter or FakeR2Adapter()
        self.opened = False

    def open(self, *_args: Any, **_kwargs: Any) -> FakeR2Adapter:
        self.opened = True
        self.adapter.open()
        return self.adapter

    def close(self) -> None:
        self.opened = False
        self.adapter.close()
