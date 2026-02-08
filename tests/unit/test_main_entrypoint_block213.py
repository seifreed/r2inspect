from __future__ import annotations

import runpy
import sys

import pytest


def test_main_entrypoint_invocation(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["r2inspect", "--help"])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("r2inspect.__main__", run_name="__main__")
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "Usage" in out or "Options" in out
