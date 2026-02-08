from __future__ import annotations

import sys

from r2inspect.utils.r2_suppress import R2PipeErrorSuppressor, silent_cmdj, suppress_r2pipe_errors


def test_r2pipe_error_suppressor_restores_stderr():
    original = sys.stderr
    with R2PipeErrorSuppressor():
        assert sys.stderr is not original
    assert sys.stderr is original


def test_silent_cmdj_with_none_instance_returns_default():
    assert silent_cmdj(None, "ij", default={"ok": True}) == {"ok": True}


def test_suppress_r2pipe_errors_context_manager():
    original = sys.stderr
    with suppress_r2pipe_errors():
        assert sys.stderr is not original
    assert sys.stderr is original
