#!/usr/bin/env python3
"""SSDeep import helper to avoid repeated CFFI reimport warnings."""

from __future__ import annotations

import threading
import warnings
from typing import Any

from .logger import get_logger

logger = get_logger(__name__)

_ssdeep_module: Any | None = None
_import_lock = threading.Lock()
warnings.filterwarnings(
    "ignore",
    message=r"reimporting '_ssdeep_cffi_.*'",
    category=UserWarning,
)


def get_ssdeep() -> Any | None:
    """Return the ssdeep module if available, importing it once."""
    global _ssdeep_module
    if _ssdeep_module is not None:
        return _ssdeep_module

    with _import_lock:
        if _ssdeep_module is not None:
            return _ssdeep_module
        try:
            import ssdeep  # type: ignore

            _ssdeep_module = ssdeep
            return _ssdeep_module
        except Exception as exc:
            logger.debug("ssdeep import failed: %s", exc)
            _ssdeep_module = None
            return None
