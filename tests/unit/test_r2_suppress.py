import json

from r2inspect.infrastructure.r2_suppress import _parse_raw_result, silent_cmdj
from r2inspect.testing.fake_r2 import FakeR2


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
