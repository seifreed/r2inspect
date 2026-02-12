"""Enable coverage collection in subprocesses when configured."""

from __future__ import annotations

import importlib
import os
from types import ModuleType


if os.getenv("COVERAGE_PROCESS_START"):
    coverage_module: ModuleType | None = None
    try:
        coverage_module = importlib.import_module("coverage")
    except Exception:
        coverage_module = None
    if coverage_module is not None:
        try:
            coverage_module.process_startup()
        except Exception:
            pass
