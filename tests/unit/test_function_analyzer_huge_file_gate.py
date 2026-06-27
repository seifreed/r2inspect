"""FunctionAnalyzer must not force aa/aaa on huge files.

Above the huge-file threshold the r2 session skips its initial analysis;
forcing aa/aaa in _get_functions only burns the command timeout and wedges
the shared session. Uses a real sparse file + a recording adapter -- no
mocks, no monkeypatch.
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
        return []  # aflj -> empty, so analysis would be triggered if allowed

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        return ""


def _sparse_file(path, size_bytes: int) -> str:
    with open(path, "wb") as handle:
        handle.truncate(size_bytes)
    return str(path)


def test_huge_file_skips_forced_analysis(tmp_path):
    filename = _sparse_file(tmp_path / "huge.bin", (HUGE_FILE_THRESHOLD_MB + 1) * 1024 * 1024)
    adapter = _RecordingAdapter()
    analyzer = FunctionAnalyzer(adapter, filename=filename)

    functions = analyzer._get_functions()

    assert functions == []
    assert analyzer._should_skip_heavy_analysis() is True
    assert "aa" not in adapter.commands
    assert "aaa" not in adapter.commands


def test_small_file_still_triggers_analysis(tmp_path):
    filename = _sparse_file(tmp_path / "small.bin", 1024)
    adapter = _RecordingAdapter()
    analyzer = FunctionAnalyzer(adapter, filename=filename)

    analyzer._get_functions()

    assert analyzer._should_skip_heavy_analysis() is False
    # <= 10 MB -> full analysis path issues aaa
    assert "aaa" in adapter.commands
