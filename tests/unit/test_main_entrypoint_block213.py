from __future__ import annotations

import subprocess
import sys


def test_main_entrypoint_invocation() -> None:
    """Invoke r2inspect --help via subprocess to avoid mutating sys.argv."""
    result = subprocess.run(
        [sys.executable, "-m", "r2inspect", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    out = result.stdout
    assert "Usage" in out or "Options" in out or "usage" in out or "options" in out
