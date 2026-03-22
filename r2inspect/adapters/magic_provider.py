#!/usr/bin/env python3
"""Magic detector provider adapter."""

from __future__ import annotations

from typing import Any

from .magic_adapter import MagicAdapter
from ..interfaces import MagicDetectorProviderLike


class MagicDetectorProvider(MagicDetectorProviderLike):
    """Cache and expose libmagic-backed detectors behind a protocol."""

    def __init__(self, adapter: MagicAdapter | None = None) -> None:
        self._adapter = adapter or MagicAdapter()
        self._detectors: tuple[Any, Any] | None = None
        self._initialized = False

    def get_detectors(self) -> tuple[Any, Any] | None:
        if not self._initialized:
            self._initialized = True
            self._detectors = self._adapter.create_detectors()
        return self._detectors
