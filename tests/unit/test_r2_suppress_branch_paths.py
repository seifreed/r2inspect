"""Branch-path coverage for r2inspect/utils/r2_suppress.py."""

from __future__ import annotations

import sys

from r2inspect.utils.r2_suppress import (
    R2PipeErrorSuppressor,
    _parse_raw_result,
    _try_cmd_parse,
    _try_cmdj,
    silent_cmdj,
    suppress_r2pipe_errors,
)


# ---------------------------------------------------------------------------
# Minimal fake r2 helpers
# ---------------------------------------------------------------------------


class FakeR2WithOsError:
    """Raises OSError from cmdj to exercise the OSError branch in _try_cmdj."""

    def cmdj(self, _command: str):
        raise OSError("pipe broken")

    def cmd(self, _command: str) -> str:
        return ""


class FakeR2WithValueError:
    """Raises ValueError from cmdj so silent_cmdj's outer except fires."""

    def cmdj(self, _command: str):
        raise ValueError("unexpected error")

    def cmd(self, _command: str) -> str:
        return ""


class FakeR2WithCmdJson:
    """Returns JSON text from cmd so _try_cmd_parse returns a dict."""

    def __init__(self, cmd_text: str = '{"key": "val"}') -> None:
        self._cmd_text = cmd_text

    def cmdj(self, _command: str):
        return None

    def cmd(self, _command: str) -> str:
        return self._cmd_text


class FalsyR2:
    """Evaluates to False so the early-exit branch in silent_cmdj fires."""

    def __bool__(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# R2PipeErrorSuppressor
# ---------------------------------------------------------------------------


def test_r2pipe_error_suppressor_context_manager_restores_stderr():
    original_stderr = sys.stderr
    original_stdout = sys.stdout
    with R2PipeErrorSuppressor():
        assert sys.stderr is not original_stderr
        assert sys.stdout is not original_stdout
    assert sys.stderr is original_stderr
    assert sys.stdout is original_stdout


# ---------------------------------------------------------------------------
# silent_cmdj – early-exit when r2_instance is falsy (line 69)
# ---------------------------------------------------------------------------


def test_silent_cmdj_returns_default_for_falsy_instance():
    falsy = FalsyR2()
    result = silent_cmdj(falsy, "ij", default={"sentinel": True})
    assert result == {"sentinel": True}


def test_silent_cmdj_returns_none_default_for_falsy_instance():
    falsy = FalsyR2()
    result = silent_cmdj(falsy, "ij", default=None)
    assert result is None


# ---------------------------------------------------------------------------
# silent_cmdj – outer except Exception branch (lines 80-82)
# ---------------------------------------------------------------------------


def test_silent_cmdj_catches_non_oserror_from_cmdj():
    r2 = FakeR2WithValueError()
    result = silent_cmdj(r2, "ij", default={"fallback": 1})
    assert result == {"fallback": 1}


def test_silent_cmdj_catches_non_oserror_returns_none_default():
    r2 = FakeR2WithValueError()
    result = silent_cmdj(r2, "ij", default=None)
    assert result is None


# ---------------------------------------------------------------------------
# _try_cmdj – OSError branch (lines 90-91)
# ---------------------------------------------------------------------------


def test_try_cmdj_returns_default_on_oserror():
    r2 = FakeR2WithOsError()
    result = _try_cmdj(r2, "ij", default={"default": True})
    assert result == {"default": True}


def test_try_cmdj_returns_none_default_on_oserror():
    r2 = FakeR2WithOsError()
    result = _try_cmdj(r2, "ij", default=None)
    assert result is None


# ---------------------------------------------------------------------------
# _try_cmd_parse (lines 97-103)
# ---------------------------------------------------------------------------


def test_try_cmd_parse_returns_parsed_dict_from_json_cmd_output():
    r2 = FakeR2WithCmdJson('{"parsed": 42}')
    result = _try_cmd_parse(r2, "ij", default={})
    assert result == {"parsed": 42}


def test_try_cmd_parse_returns_default_when_cmd_returns_empty():
    r2 = FakeR2WithCmdJson("")
    result = _try_cmd_parse(r2, "ij", default={"default": 1})
    assert result == {"default": 1}


def test_try_cmd_parse_returns_default_when_cmd_returns_whitespace_only():
    r2 = FakeR2WithCmdJson("   ")
    result = _try_cmd_parse(r2, "ij", default={"def": 2})
    assert result == {"def": 2}


def test_try_cmd_parse_returns_raw_text_when_not_valid_json():
    # _parse_raw_result returns the stripped text when len > 2 and not JSON
    r2 = FakeR2WithCmdJson("hello world")
    result = _try_cmd_parse(r2, "ij", default=None)
    assert result == "hello world"


def test_try_cmd_parse_returns_default_when_parsed_result_is_none():
    # Two-character non-JSON yields None from _parse_raw_result, so default returned
    r2 = FakeR2WithCmdJson("ab")
    result = _try_cmd_parse(r2, "ij", default={"d": 0})
    assert result == {"d": 0}


# ---------------------------------------------------------------------------
# _parse_raw_result (lines 107-114)
# ---------------------------------------------------------------------------


def test_parse_raw_result_valid_json_list():
    result = _parse_raw_result('[1, 2, 3]')
    assert result == [1, 2, 3]


def test_parse_raw_result_valid_json_int():
    result = _parse_raw_result('42')
    assert result == 42


def test_parse_raw_result_invalid_json_long_text():
    result = _parse_raw_result("not json data")
    assert result == "not json data"


def test_parse_raw_result_invalid_json_short_text_returns_none():
    # Length <= 2 after strip → returns None
    result = _parse_raw_result("ab")
    assert result is None


def test_parse_raw_result_invalid_json_single_char_returns_none():
    result = _parse_raw_result("x")
    assert result is None


def test_parse_raw_result_strips_whitespace_before_returning():
    result = _parse_raw_result("  some text  ")
    assert result == "some text"


# ---------------------------------------------------------------------------
# suppress_r2pipe_errors context manager (lines 120-121)
# ---------------------------------------------------------------------------


def test_suppress_r2pipe_errors_yields_and_restores_streams():
    original_stderr = sys.stderr
    original_stdout = sys.stdout
    with suppress_r2pipe_errors():
        assert sys.stderr is not original_stderr
        assert sys.stdout is not original_stdout
    assert sys.stderr is original_stderr
    assert sys.stdout is original_stdout


def test_suppress_r2pipe_errors_body_executes_normally():
    executed = []
    with suppress_r2pipe_errors():
        executed.append(True)
    assert executed == [True]
