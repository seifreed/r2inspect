"""FunctionAnalyzer runs basic analysis on huge files instead of skipping.

The always-complete policy means function discovery must work on big binaries.
The session runs aa at open; this fallback in _get_functions fires when aflj is
still empty. aa (not aaa) is used above the very-large threshold so huge files
stay tractable. Uses a real sparse file + a recording adapter -- no mocks, no
monkeypatch.
"""

from __future__ import annotations

from typing import Any

from r2inspect.domain.constants import HUGE_FILE_THRESHOLD_MB
from r2inspect.modules.function_analyzer import FunctionAnalyzer


class _RecordingAdapter:
    """Records fallback cmd() calls; reports no pre-existing functions."""

    def __init__(self) -> None:
        self.commands: list[str] = []

    def get_functions(self) -> list[dict[str, Any]]:
        return []  # aflj -> empty, so analysis is triggered

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        return ""


def _sparse_file(path, size_bytes: int) -> str:
    with open(path, "wb") as handle:
        handle.truncate(size_bytes)
    return str(path)


def test_huge_file_runs_basic_analysis(tmp_path):
    filename = _sparse_file(tmp_path / "huge.bin", (HUGE_FILE_THRESHOLD_MB + 1) * 1024 * 1024)
    adapter = _RecordingAdapter()
    analyzer = FunctionAnalyzer(adapter, filename=filename)

    analyzer._get_functions()

    # Above the very-large threshold: the fast linear aa, never the slow aaa.
    assert "aa" in adapter.commands
    assert "aaa" not in adapter.commands


def test_small_file_still_triggers_full_analysis(tmp_path):
    filename = _sparse_file(tmp_path / "small.bin", 1024)
    adapter = _RecordingAdapter()
    analyzer = FunctionAnalyzer(adapter, filename=filename)

    analyzer._get_functions()

    # <= 10 MB -> full analysis path issues aaa
    assert "aaa" in adapter.commands
