"""Adapter for optional python-magic integration."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any

from ..infrastructure.logging import get_logger

logger = get_logger(__name__)


def _default_magic_importer() -> Any:
    import magic as _magic

    return _magic


class MagicAdapter:
    """Thin wrapper around python-magic to keep IO details out of callers."""

    def __init__(
        self,
        platform: str | None = None,
        *,
        importer: Callable[[], Any] | None = None,
    ) -> None:
        self._magic: Any | None
        if (platform if platform is not None else sys.platform) == "win32":
            # python-magic-bin can crash the interpreter on import in some Windows CI images.
            self._magic = None
            return
        resolve = importer if importer is not None else _default_magic_importer
        try:
            self._magic = resolve()
        except Exception as exc:
            logger.exception("Error importing python-magic: %s", exc)
            self._magic = None

    @property
    def available(self) -> bool:
        return self._magic is not None

    def create_detectors(self) -> tuple[Any, Any] | None:
        if self._magic is None:
            return None
        try:
            return self._magic.Magic(mime=True), self._magic.Magic()
        except Exception as exc:
            logger.exception("Error creating python-magic detectors: %s", exc)
            return None
