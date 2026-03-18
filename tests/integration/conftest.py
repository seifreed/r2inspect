from __future__ import annotations

import os
from pathlib import Path
import pytest


@pytest.fixture(autouse=True, scope="session")
def _prevent_hard_process_exit_in_integration_suite():
    """Prevent hard exits from interrupting integration coverage aggregation.

    Some batch-processing paths can call ``os._exit`` through forced-shutdown
    helpers. That aborts pytest before coverage/junit writers flush artifacts.
    For integration runs we force the safe-exit behavior and convert hard exits
    into ``SystemExit`` so tests can complete and coverage artifacts are written.
    """
    os.environ.setdefault("R2INSPECT_DISABLE_FORCED_EXIT", "1")
    os.environ.setdefault("R2INSPECT_TEST_SAFE_EXIT", "1")

    original_exit = os._exit

    def _raise_system_exit(code: int = 0) -> None:
        raise SystemExit(code)

    os._exit = _raise_system_exit  # type: ignore[assignment]
    try:
        yield
    finally:
        os._exit = original_exit  # type: ignore[assignment]


@pytest.fixture(autouse=True)
def _force_repo_cwd_for_integration_tests():
    """Keep integration tests on repository root to stabilize relative fixture paths."""
    repo_root = Path(__file__).resolve().parents[2]
    previous = Path.cwd()
    os.chdir(repo_root)
    try:
        yield
    finally:
        os.chdir(previous)
