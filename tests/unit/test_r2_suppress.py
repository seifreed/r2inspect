import json

from r2inspect.utils.r2_suppress import _parse_raw_result, silent_cmdj


class FakeR2:
    def __init__(self, cmdj_result=None, cmd_result=""):
        self.cmdj_result = cmdj_result
        self.cmd_result = cmd_result

    def cmdj(self, _command):
        if isinstance(self.cmdj_result, Exception):
            raise self.cmdj_result
        return self.cmdj_result

    def cmd(self, _command):
        if isinstance(self.cmd_result, Exception):
            raise self.cmd_result
        return self.cmd_result


def test_parse_raw_result_json():
    payload = {"a": 1}
    assert _parse_raw_result(json.dumps(payload)) == payload


def test_parse_raw_result_text():
    assert _parse_raw_result("hello") == "hello"
    assert _parse_raw_result(" ") is None


def test_silent_cmdj_returns_default_on_none_instance():
    assert silent_cmdj(None, "ij", default={}) == {}


def test_silent_cmdj_uses_cmdj_result():
    r2 = FakeR2(cmdj_result={"ok": True})
    assert silent_cmdj(r2, "ij", default={}) == {"ok": True}


def test_silent_cmdj_falls_back_to_cmd_parse():
    r2 = FakeR2(
        cmdj_result=json.JSONDecodeError("bad", "doc", 0),
        cmd_result='{"k": 1}',
    )
    assert silent_cmdj(r2, "ij", default={}) == {"k": 1}
