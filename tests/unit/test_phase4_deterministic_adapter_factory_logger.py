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


def test_r2pipe_adapter_property_and_empty_and_list_fallback() -> None:
    r2 = _FakeR2()
    adapter = R2PipeAdapter(r2)

    # line 57
    assert adapter.r2 is r2
    # line 63
    assert adapter.execute_command("   ") is None

    # line 70: list command returns [] when cmdj returns non-list
    r2_non_list = _FakeR2()
    r2_non_list.cmdj = lambda _cmd: {"not": "a list"}  # type: ignore[method-assign]
    adapter2 = R2PipeAdapter(r2_non_list)
    assert adapter2.execute_command("iSj") == []


def test_factory_create_inspector_exception_closes_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "r2inspect.factory.FileValidator",
        lambda _filename: SimpleNamespace(validate=lambda: True),
    )
    monkeypatch.setattr(
        "r2inspect.factory.Path",
        lambda _p: SimpleNamespace(stat=lambda: SimpleNamespace(st_size=1024)),
    )

    close_calls: list[str] = []
    session = SimpleNamespace(
        open=lambda _size_mb: _FakeR2(),
        close=lambda: close_calls.append("closed"),
    )
    monkeypatch.setattr("r2inspect.factory.R2Session", lambda _filename: session)

    def _raise_inspector(**_kwargs: Any) -> Any:
        raise RuntimeError("forced")

    monkeypatch.setattr("r2inspect.factory.R2Inspector", _raise_inspector)

    with pytest.raises(RuntimeError, match="forced"):
        create_inspector("dummy.bin")
    # lines 64-66
    assert close_calls == ["closed"]


def test_logger_setup_fallback_console_only(monkeypatch: pytest.MonkeyPatch) -> None:
    name = "r2inspect.phase4.deterministic.logger"

    # Force file handler setup to fail and hit fallback branch (lines 87-95).
    monkeypatch.setattr(
        "logging.handlers.RotatingFileHandler",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("no-file-handler")),
    )

    log = logger_mod.setup_logger(name=name, level=logging.INFO, thread_safe=True)
    assert log.name == name
    assert len(log.handlers) >= 1

    # cleanup handlers to avoid cross-test noise
    for handler in list(log.handlers):
        try:
            handler.close()
        finally:
            log.removeHandler(handler)
