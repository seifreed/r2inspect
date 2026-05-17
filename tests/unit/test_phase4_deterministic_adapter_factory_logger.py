from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.factory import create_inspector
import r2inspect.infrastructure.logging as logger_mod


class _FakeR2:
    def __init__(self) -> None:
        self.cmd_calls: list[str] = []
        self.cmdj_calls: list[str] = []

    def cmd(self, command: str) -> str:
        self.cmd_calls.append(command)
        return "ok"

    def cmdj(self, command: str) -> Any:
        self.cmdj_calls.append(command)
        return {"ok": True}


class _NonListCmdjR2(_FakeR2):
    """cmdj always returns a non-list so list commands fall back to []."""

    def cmdj(self, command: str) -> Any:
        self.cmdj_calls.append(command)
        return {"not": "a list"}


def test_r2pipe_adapter_property_and_empty_and_list_fallback() -> None:
    r2 = _FakeR2()
    adapter = R2PipeAdapter(r2)

    # line 57
    assert adapter.r2 is r2
    # line 63
    assert adapter.execute_command("   ") is None

    # line 70: list command returns [] when cmdj returns non-list
    adapter2 = R2PipeAdapter(_NonListCmdjR2())
    assert adapter2.execute_command("iSj") == []


def test_factory_create_inspector_exception_closes_session() -> None:
    # Real fixture so FileValidator/Path stat succeed; the session and
    # inspector are injected via the create_inspector DI seams.
    close_calls: list[str] = []
    session = SimpleNamespace(
        open=lambda _size_mb: _FakeR2(),
        close=lambda: close_calls.append("closed"),
    )

    def _raise_inspector(**_kwargs: Any) -> Any:
        raise RuntimeError("forced")

    with pytest.raises(RuntimeError, match="forced"):
        create_inspector(
            "samples/fixtures/hello_pe.exe",
            session_factory=lambda _filename: session,
            inspector_factory=_raise_inspector,
        )
    # factory must close the session when inspector construction fails
    assert close_calls == ["closed"]


def test_logger_setup_fallback_console_only() -> None:
    name = "r2inspect.phase4.deterministic.logger"

    # Force file-handler setup to fail and hit the console-only fallback.
    def _failing_file_handler() -> logging.Handler:
        raise RuntimeError("no-file-handler")

    log = logger_mod.setup_logger(
        name=name,
        level=logging.INFO,
        thread_safe=True,
        file_handler_factory=_failing_file_handler,
    )
    assert log.name == name
    assert len(log.handlers) >= 1

    # cleanup handlers to avoid cross-test noise
    for handler in list(log.handlers):
        try:
            handler.close()
        finally:
            log.removeHandler(handler)
