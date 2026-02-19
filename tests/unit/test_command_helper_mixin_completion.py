from __future__ import annotations

from typing import Any

from r2inspect.abstractions.command_helper_mixin import CommandHelperMixin


class TestClass(CommandHelperMixin):
    def __init__(self, adapter: Any, r2: Any):
        self.adapter = adapter
        self.r2 = r2


def test_mixin_cmd_calls_helper() -> None:
    obj = TestClass(adapter=None, r2=None)
    result = obj._cmd("test")
    assert isinstance(result, str)


def test_mixin_cmdj_calls_helper() -> None:
    obj = TestClass(adapter=None, r2=None)
    result = obj._cmdj("test", default={})
    assert result == {}


def test_mixin_cmd_list_calls_helper() -> None:
    obj = TestClass(adapter=None, r2=None)
    result = obj._cmd_list("test")
    assert isinstance(result, list)
