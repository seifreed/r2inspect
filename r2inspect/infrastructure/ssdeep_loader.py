#!/usr/bin/env python3
"""SSDeep import helper to avoid repeated CFFI reimport warnings."""

from __future__ import annotations

import threading
import warnings
from collections.abc import Callable
from typing import Any

from .logging import get_logger

logger = get_logger(__name__)

_ssdeep_module: Any | None = None
_import_lock = threading.Lock()
warnings.filterwarnings(
    "ignore",
    message=r"reimporting '_ssdeep_cffi_.*'",
    category=UserWarning,
)


def _import_ssdeep() -> Any:
    import ssdeep

    return ssdeep


def get_ssdeep(*, importer: Callable[[], Any] | None = None) -> Any | None:
    """Return the ssdeep module if available, importing it once.

    ``importer`` defaults to a real ``import ssdeep``; tests inject a
    deterministic importer instead of patching ``sys.modules``/``sys.path``.
    """
    global _ssdeep_module
    if _ssdeep_module is not None:
        return _ssdeep_module

    with _import_lock:
        current: Any | None = _ssdeep_module
        if current is not None:
            return current
        try:
            _ssdeep_module = (importer if importer is not None else _import_ssdeep)()
            return _ssdeep_module
        except Exception as exc:
            logger.debug("ssdeep import failed: %s", exc)
            _ssdeep_module = None
            return None


__all__ = ["get_ssdeep"]
