"""Comprehensive tests for r2pipe_adapter.py - 100% coverage target.

All tests use FakeR2 + real R2PipeAdapter code paths. No mocks, no
monkeypatch, no @patch.
"""

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


class FakeR2:
    """Minimal r2pipe stand-in that drives the real adapter code."""

    def __init__(self, cmdj_map=None, cmd_map=None):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command):
        return self.cmdj_map.get(command)

    def cmd(self, command):
        return self.cmd_map.get(command, "")


class FakeR2NonString:
    """FakeR2 whose cmd() returns a non-string value."""

    def __init__(self, value):
        self._value = value

    def cmdj(self, command):
        return None

    def cmd(self, command):
        return self._value


# -------------------------------------------------------------------
# Initialization
# -------------------------------------------------------------------


def test_init_success():
    """R2PipeAdapter accepts a valid r2 instance."""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    assert adapter._r2 is r2


def test_init_none_raises():
    """R2PipeAdapter rejects None with ValueError."""
    with pytest.raises(ValueError, match="cannot be None"):
        R2PipeAdapter(None)


# -------------------------------------------------------------------
# cmd / cmdj
# -------------------------------------------------------------------


def test_cmd_returns_string():
    """cmd() returns the string result from r2."""
    r2 = FakeR2(cmd_map={"iSj": "test result"})
    adapter = R2PipeAdapter(r2)
    assert adapter.cmd("iSj") == "test result"


def test_cmd_non_string_coerced():
    """cmd() coerces non-string return values via str()."""
    r2 = FakeR2NonString(12345)
    adapter = R2PipeAdapter(r2)
    assert adapter.cmd("anything") == "12345"


def test_cmdj_returns_parsed_json():
    """cmdj() delegates through silent_cmdj and returns parsed data."""
    r2 = FakeR2(cmdj_map={"iij": {"info": "data"}})
    adapter = R2PipeAdapter(r2)
    result = adapter.cmdj("iij")
    assert result == {"info": "data"}


# -------------------------------------------------------------------
# _cached_query — list paths
# -------------------------------------------------------------------


def test_cached_query_list_cached():
    """_cached_query returns cached list without hitting r2 again."""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    adapter._cache["iSj"] = [{"test": "data"}]
    result = adapter._cached_query("iSj", "list")
    assert result == [{"test": "data"}]


def test_cached_query_list_not_cached():
    """_cached_query fetches, validates, caches, and returns a list."""
    r2 = FakeR2(cmdj_map={"iSj": [{"name": ".text"}]})
    adapter = R2PipeAdapter(r2)

    result = adapter._cached_query("iSj", "list")
    assert result == [{"name": ".text"}]
    assert "iSj" in adapter._cache


def test_cached_query_invalid_response_list():
    """_cached_query returns empty list when r2 gives None/invalid data."""
    r2 = FakeR2(cmdj_map={"iSj": None})
    adapter = R2PipeAdapter(r2)

    result = adapter._cached_query("iSj", "list", error_msg="No sections")
    assert result == []


def test_cached_query_custom_default_list():
    """_cached_query uses the caller-supplied default for invalid list data."""
    r2 = FakeR2(cmdj_map={"iSj": None})
    adapter = R2PipeAdapter(r2)

    sentinel = [{"default": "value"}]
    result = adapter._cached_query("iSj", "list", default=sentinel)
    assert result == sentinel


def test_cached_query_no_cache_list():
    """_cached_query with cache=False skips caching."""
    r2 = FakeR2(cmdj_map={"iSj": [{"name": ".data"}]})
    adapter = R2PipeAdapter(r2)

    result = adapter._cached_query("iSj", "list", cache=False)
    assert result == [{"name": ".data"}]
    assert "iSj" not in adapter._cache


# -------------------------------------------------------------------
# _cached_query — dict paths
# -------------------------------------------------------------------


def test_cached_query_dict_cached():
    """_cached_query returns cached dict without hitting r2 again."""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    adapter._cache["iij"] = {"test": "data"}
    result = adapter._cached_query("iij", "dict")
    assert result == {"test": "data"}


def test_cached_query_dict_not_cached():
    """_cached_query fetches, validates, caches, and returns a dict."""
    r2 = FakeR2(cmdj_map={"iij": {"arch": "x86"}})
    adapter = R2PipeAdapter(r2)

    result = adapter._cached_query("iij", "dict")
    assert result == {"arch": "x86"}


def test_cached_query_invalid_response_dict():
    """_cached_query returns empty dict when r2 gives None/invalid data."""
    r2 = FakeR2(cmdj_map={"iij": None})
    adapter = R2PipeAdapter(r2)

    result = adapter._cached_query("iij", "dict")
    assert result == {}


# -------------------------------------------------------------------
# __repr__ / __str__
# -------------------------------------------------------------------


def test_repr():
    """__repr__ includes the class name."""
    adapter = R2PipeAdapter(FakeR2())
    assert "R2PipeAdapter" in repr(adapter)


def test_str():
    """__str__ mentions radare2."""
    adapter = R2PipeAdapter(FakeR2())
    assert "radare2" in str(adapter)


# -------------------------------------------------------------------
# _maybe_force_error
# -------------------------------------------------------------------


def test_maybe_force_error_no_injector():
    """No error when fault_injector is None (default)."""
    adapter = R2PipeAdapter(FakeR2())
    adapter._maybe_force_error("test_method")  # should not raise


def test_maybe_force_error_with_injector():
    """fault_injector is called and may raise."""

    def _injector(method: str) -> None:
        raise RuntimeError("Forced adapter error")

    adapter = R2PipeAdapter(FakeR2(), fault_injector=_injector)
    with pytest.raises(RuntimeError, match="Forced adapter error"):
        adapter._maybe_force_error("test_method")


def test_maybe_force_error_injector_selective():
    """fault_injector can selectively raise based on method name."""

    def _injector(method: str) -> None:
        if method == "test_method":
            raise RuntimeError("Forced adapter error")

    adapter = R2PipeAdapter(FakeR2(), fault_injector=_injector)
    with pytest.raises(RuntimeError, match="Forced adapter error"):
        adapter._maybe_force_error("test_method")
    # Different method does not raise
    adapter._maybe_force_error("other_method")


# -------------------------------------------------------------------
# Class attributes
# -------------------------------------------------------------------


def test_thread_safe_attribute():
    """thread_safe class attribute is False."""
    assert R2PipeAdapter.thread_safe is False
