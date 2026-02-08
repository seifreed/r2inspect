from __future__ import annotations

import json

from r2inspect.utils.r2_suppress import (
    R2PipeErrorSuppressor,
    _parse_raw_result,
    silent_cmdj,
    suppress_r2pipe_errors,
)


class DummyR2:
    def __init__(self, cmdj_result=None, cmd_result=""):
        self._cmdj_result = cmdj_result
        self._cmd_result = cmd_result

    def cmdj(self, command):
        if command == "err":
            raise OSError("fail")
        if command == "jsonerr":
            raise json.JSONDecodeError("bad", "doc", 0)
        return self._cmdj_result

    def cmd(self, command):
        return self._cmd_result


def test_parse_raw_result():
    assert _parse_raw_result("{}") == {}
    assert _parse_raw_result('  {"a":1}  ') == {"a": 1}
    assert _parse_raw_result(" ok ") is None
    assert _parse_raw_result(" ") is None


def test_silent_cmdj_paths():
    assert silent_cmdj(None, "ij", default={"a": 1}) == {"a": 1}

    r2 = DummyR2(cmdj_result={"ok": True})
    assert silent_cmdj(r2, "ij", default=None) == {"ok": True}

    r2_err = DummyR2(cmdj_result=None)
    assert silent_cmdj(r2_err, "err", default=[]) == []

    r2_text = DummyR2(cmdj_result=None, cmd_result='{"x": 2}')
    assert silent_cmdj(r2_text, "jsonerr", default=None) == {"x": 2}

    r2_plain = DummyR2(cmdj_result=None, cmd_result="OK")
    assert silent_cmdj(r2_plain, "jsonerr", default=None) is None


def test_context_managers_restore_stderr():
    with R2PipeErrorSuppressor() as ctx:
        assert ctx.original_stderr is not None

    with suppress_r2pipe_errors():
        pass
