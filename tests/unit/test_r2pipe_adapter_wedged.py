"""Regression: a wedged r2 pipe must fast-fail every command, not deadlock.

When an r2 command times out, its abandoned worker thread stays blocked in the
synchronous pipe. The adapter is marked wedged so subsequent commands return
defaults immediately instead of queuing behind the abandoned read and hanging
forever (observed on a 63 MB Mach-O whose initial ``aa`` never returned).
"""

from __future__ import annotations

from typing import Any

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.infrastructure.r2_command_timeout import is_wedged, mark_wedged


class _RecordingR2:
    def __init__(self) -> None:
        self.cmds: list[str] = []
        self.cmdjs: list[str] = []

    def cmd(self, command: str) -> str:
        self.cmds.append(command)
        return "should-not-be-reached"

    def cmdj(self, command: str) -> Any:
        self.cmdjs.append(command)
        return {"unreached": True}


def test_wedged_adapter_cmd_fast_fails_without_touching_backend() -> None:
    backend = _RecordingR2()
    adapter = R2PipeAdapter(backend)
    mark_wedged(adapter)

    assert is_wedged(adapter) is True
    assert adapter.cmd("aflj") == ""
    assert adapter.cmdj("aflj") is None
    assert backend.cmds == []
    assert backend.cmdjs == []


def test_unwedged_adapter_reaches_backend() -> None:
    backend = _RecordingR2()
    adapter = R2PipeAdapter(backend)

    assert adapter.cmd("i") == "should-not-be-reached"
    assert backend.cmds == ["i"]
