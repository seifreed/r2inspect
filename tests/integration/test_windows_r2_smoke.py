"""Windows-only smoke coverage for the installed radare2 executable."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.skipif(sys.platform != "win32", reason="Windows radare2 smoke test")
def test_windows_radare2_opens_native_pe() -> None:
    target = Path("samples/fixtures/hello_pe.exe")
    executable = shutil.which("r2") or shutil.which("radare2") or "r2"
    result = subprocess.run(
        [executable, "-q", "-c", "ij", str(target)],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip())
    assert isinstance(payload, dict)
    assert payload.get("bin", {}).get("format")
