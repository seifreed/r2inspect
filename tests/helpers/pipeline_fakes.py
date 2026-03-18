from __future__ import annotations

from typing import Any


class FakeAdapter:
    def __init__(self, info: dict[str, Any] | None = None) -> None:
        self._info = info or {}

    def get_file_info(self) -> dict[str, Any] | None:
        return self._info


class FakeConfig:
    pass
