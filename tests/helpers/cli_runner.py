from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path


def run_cli(
    args: Sequence[str], *, cwd: str | Path | None = None, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Run the project CLI entrypoint with real process semantics."""

    return subprocess.run(
        [sys.executable, "-m", "r2inspect", *args],
        cwd=str(cwd) if cwd is not None else None,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
