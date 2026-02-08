from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


def test_cli_version_and_list_yara(tmp_path: Path):
    proc = subprocess.run(
        [sys.executable, "-m", "r2inspect", "--version"],
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 0
    assert "r2inspect" in proc.stdout.lower()

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "demo.yar").write_text("rule demo { condition: true }")

    proc = subprocess.run(
        [sys.executable, "-m", "r2inspect", "--list-yara", "--yara", str(rules_dir)],
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 0
    assert "Available YARA Rules" in proc.stdout
