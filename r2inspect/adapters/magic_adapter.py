"""Adapter for optional python-magic integration."""

from __future__ import annotations

from typing import Any


class MagicAdapter:
    """Thin wrapper around python-magic to keep IO details out of callers."""

    def __init__(self) -> None:
        self._magic: Any | None
        try:
            import magic as _magic

            self._magic = _magic
        except Exception:
            self._magic = None

    @property
    def available(self) -> bool:
        return self._magic is not None

    def create_detectors(self) -> tuple[Any, Any] | None:
        if self._magic is None:
            return None
        try:
            return self._magic.Magic(mime=True), self._magic.Magic()
        except Exception:
            return None
