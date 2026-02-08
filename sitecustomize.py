"""Enable coverage collection in subprocesses when configured."""

from __future__ import annotations

import os


if os.getenv("COVERAGE_PROCESS_START"):
    try:
        import coverage
    except Exception:
        coverage = None
    if coverage is not None:
        try:
            coverage.process_startup()
        except Exception:
            pass
