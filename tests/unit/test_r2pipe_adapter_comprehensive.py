#!/usr/bin/env python3
"""
Comprehensive tests for r2inspect/adapters/r2pipe_adapter.py

Tests initialization, caching, error handling, forced errors, and all adapter methods.
Uses real objects (FakeR2) instead of mocks throughout.
"""

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


class FakeR2:
    """Minimal r2pipe-compatible fake for testing."""

    def __init__(self, cmdj_map=None, cmd_map=None):
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}
        self.cmdj_calls = []
        self.cmd_calls = []

    def cmdj(self, command):
        self.cmdj_calls.append(command)
        if command in self.cmdj_map:
            val = self.cmdj_map[command]
            if isinstance(val, Exception):
                raise val
            return val
        return {}

    def cmd(self, command):
        self.cmd_calls.append(command)
        if command in self.cmd_map:
            val = self.cmd_map[command]
            if isinstance(val, Exception):
                raise val
            return val
        return ""


class ErrorR2(FakeR2):
    """FakeR2 subclass that raises on cmdj calls."""

    def __init__(self, exc=None):
        super().__init__()
        self._exc = exc or ValueError("cmdj error")

    def cmdj(self, command):
        self.cmdj_calls.append(command)
        raise self._exc


# ---------------------------------------------------------------------------
# Initialization tests
# ---------------------------------------------------------------------------


def test_r2pipe_adapter_init_success():
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)

    assert adapter._r2 is r2
    assert adapter._cache == {}


def test_r2pipe_adapter_init_none_raises():
    with pytest.raises(ValueError, match="cannot be None"):
        R2PipeAdapter(None)


def test_r2pipe_adapter_thread_safe_flag():
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)

    assert adapter.thread_safe is False


# ---------------------------------------------------------------------------
# cmd and cmdj tests
# ---------------------------------------------------------------------------


def test_cmd_returns_string():
    r2 = FakeR2(cmd_map={"test": "output"})
    adapter = R2PipeAdapter(r2)
    result = adapter.cmd("test")

    assert result == "output"
    assert r2.cmd_calls == ["test"]


def test_cmd_converts_non_string_to_string():
    r2 = FakeR2()
    # Override cmd to return int
    r2.cmd = lambda command: 123
    adapter = R2PipeAdapter(r2)
    result = adapter.cmd("test")

    assert result == "123"
    assert isinstance(result, str)


def test_cmdj_returns_data():
    r2 = FakeR2(cmdj_map={"test": {"data": "value"}})
    adapter = R2PipeAdapter(r2)
    result = adapter.cmdj("test")

    assert result == {"data": "value"}


def test_cmdj_returns_none_on_error():
    r2 = ErrorR2(exc=ValueError("parse error"))
    adapter = R2PipeAdapter(r2)
    result = adapter.cmdj("test")

    # silent_cmdj catches the ValueError and falls back
    assert result is None or result == {}


# ---------------------------------------------------------------------------
# _cached_query tests
# ---------------------------------------------------------------------------


def test_cached_query_list_success():
    data = [{"name": ".text", "size": 1024}, {"name": ".data", "size": 512}]
    r2 = FakeR2(cmdj_map={"iSj": data})
    adapter = R2PipeAdapter(r2)
    result = adapter._cached_query("iSj", "list")

    assert isinstance(result, list)
    assert len(result) >= 1
    assert "iSj" in adapter._cache


def test_cached_query_dict_success():
    data = {"bin": {"arch": "x86"}, "core": {"format": "pe"}}
    r2 = FakeR2(cmdj_map={"ij": data})
    adapter = R2PipeAdapter(r2)
    result = adapter._cached_query("ij", "dict")

    assert isinstance(result, dict)
    assert len(result) >= 1
    assert "ij" in adapter._cache


def test_cached_query_uses_cache():
    cached_data = [{"cached": True}]
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    adapter._cache["iSj"] = cached_data

    result = adapter._cached_query("iSj", "list")

    assert result == cached_data
    # The underlying r2 should NOT have been called since cache was hit
    assert "iSj" not in r2.cmdj_calls


def test_cached_query_cache_disabled():
    data = [{"name": ".text", "size": 100}]
    r2 = FakeR2(cmdj_map={"iSj": data})
    adapter = R2PipeAdapter(r2)
    result = adapter._cached_query("iSj", "list", cache=False)

    assert isinstance(result, list)
    assert "iSj" not in adapter._cache


def test_cached_query_invalid_response_returns_default_list():
    # Empty list from r2 -> is_valid_r2_response returns False
    r2 = FakeR2(cmdj_map={"iSj": []})
    adapter = R2PipeAdapter(r2)
    result = adapter._cached_query("iSj", "list", error_msg="Test error")

    assert result == []


def test_cached_query_invalid_response_returns_default_dict():
    # Empty dict from r2 -> is_valid_r2_response returns False
    r2 = FakeR2(cmdj_map={"ij": {}})
    adapter = R2PipeAdapter(r2)
    result = adapter._cached_query("ij", "dict", error_msg="Test error")

    assert result == {}


def test_cached_query_custom_default_list():
    custom_default = [{"default": True}]
    r2 = FakeR2(cmdj_map={"iSj": []})
    adapter = R2PipeAdapter(r2)
    result = adapter._cached_query("iSj", "list", default=custom_default)

    assert result == custom_default


def test_cached_query_custom_default_dict():
    custom_default = {"default": "value"}
    r2 = FakeR2(cmdj_map={"ij": {}})
    adapter = R2PipeAdapter(r2)
    result = adapter._cached_query("ij", "dict", default=custom_default)

    assert result == custom_default


def test_cached_query_logs_error_msg(capfd):
    """When an invalid response occurs with error_msg, debug logging is triggered."""
    r2 = FakeR2(cmdj_map={"iSj": []})
    adapter = R2PipeAdapter(r2)
    # Just verify it doesn't raise; the debug log goes to the logger
    result = adapter._cached_query("iSj", "list", error_msg="Custom error")
    assert result == []


def test_cached_query_no_log_without_error_msg():
    """When no error_msg is provided, behavior should still be correct."""
    r2 = FakeR2(cmdj_map={"iSj": []})
    adapter = R2PipeAdapter(r2)
    result = adapter._cached_query("iSj", "list")
    assert result == []


def test_cached_query_caches_valid_response():
    data = [{"item": 1}]
    r2 = FakeR2(cmdj_map={"cmd": data})
    adapter = R2PipeAdapter(r2)
    adapter._cached_query("cmd", "list", cache=True)

    assert "cmd" in adapter._cache
    assert adapter._cache["cmd"] == data


def test_cached_query_does_not_cache_when_disabled():
    data = [{"item": 1}]
    r2 = FakeR2(cmdj_map={"cmd": data})
    adapter = R2PipeAdapter(r2)
    adapter._cached_query("cmd", "list", cache=False)

    assert "cmd" not in adapter._cache


# ---------------------------------------------------------------------------
# _maybe_force_error tests
# ---------------------------------------------------------------------------


def _always_raise(method: str) -> None:
    raise RuntimeError("Forced adapter error")


def _selective_raise(*target_methods: str):
    def _injector(method: str) -> None:
        if method in target_methods:
            raise RuntimeError("Forced adapter error")

    return _injector


def test_maybe_force_error_no_injector():
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    # Should not raise when no fault_injector is set
    adapter._maybe_force_error("test_method")


def test_maybe_force_error_with_injector_raises():
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2, fault_injector=_always_raise)
    with pytest.raises(RuntimeError, match="Forced adapter error"):
        adapter._maybe_force_error("test_method")


def test_maybe_force_error_selective_match():
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2, fault_injector=_selective_raise("test_method"))
    with pytest.raises(RuntimeError, match="Forced adapter error"):
        adapter._maybe_force_error("test_method")


def test_maybe_force_error_selective_no_match():
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2, fault_injector=_selective_raise("other_method"))
    # Should not raise for a non-matching method name
    adapter._maybe_force_error("test_method")


# ---------------------------------------------------------------------------
# __repr__ and __str__ tests
# ---------------------------------------------------------------------------


def test_repr():
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    result = repr(adapter)

    assert "R2PipeAdapter" in result
    assert "r2_instance=" in result


def test_str():
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    result = str(adapter)

    assert result == "R2PipeAdapter for radare2 binary analysis"


# ---------------------------------------------------------------------------
# Integration tests with _cached_query and force errors
# ---------------------------------------------------------------------------


def test_cached_query_with_forced_error():
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2, fault_injector=_selective_raise("_cached_query"))
    with pytest.raises(RuntimeError, match="Forced adapter error"):
        adapter._cached_query("iSj", "list")


def test_cached_query_without_forced_error_when_other_method():
    data = [{"name": ".text", "size": 1024}]
    r2 = FakeR2(cmdj_map={"iSj": data})
    adapter = R2PipeAdapter(r2, fault_injector=_selective_raise("other_method"))
    result = adapter._cached_query("iSj", "list")
    assert isinstance(result, list)
    assert len(result) >= 1


# ---------------------------------------------------------------------------
# Cache type casting tests
# ---------------------------------------------------------------------------


def test_cached_query_returns_list_type():
    data = [{"item": 1}]
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    adapter._cache["cmd"] = data

    result = adapter._cached_query("cmd", "list")

    assert isinstance(result, list)
    assert result == data


def test_cached_query_returns_dict_type():
    data = {"key": "value"}
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    adapter._cache["cmd"] = data

    result = adapter._cached_query("cmd", "dict")

    assert isinstance(result, dict)
    assert result == data


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_cached_query_empty_list_is_invalid():
    r2 = FakeR2(cmdj_map={"iSj": []})
    adapter = R2PipeAdapter(r2)
    result = adapter._cached_query("iSj", "list")

    assert result == []


def test_cached_query_empty_dict_is_invalid():
    r2 = FakeR2(cmdj_map={"ij": {}})
    adapter = R2PipeAdapter(r2)
    result = adapter._cached_query("ij", "dict")

    assert result == {}


def test_cached_query_validation_failure_returns_default():
    # None from cmdj -> validation returns [] -> is_valid_r2_response returns False
    r2 = FakeR2(cmdj_map={"iSj": None})
    adapter = R2PipeAdapter(r2)
    result = adapter._cached_query("iSj", "list")

    assert result == []


def test_cmd_empty_string():
    r2 = FakeR2(cmd_map={"test": ""})
    adapter = R2PipeAdapter(r2)
    result = adapter.cmd("test")

    assert result == ""


def test_cmdj_empty_result():
    r2 = FakeR2(cmdj_map={"test": None})
    adapter = R2PipeAdapter(r2)
    result = adapter.cmdj("test")

    # silent_cmdj with None may return None or default
    assert result is None or result == {}


def test_cached_query_uses_safe_cmd_list():
    """Verify _cached_query with list type actually invokes the r2 backend."""
    data = [{"item": 1}]
    r2 = FakeR2(cmdj_map={"iSj": data})
    adapter = R2PipeAdapter(r2)
    adapter._cached_query("iSj", "list")

    # The underlying r2 was called (via safe_cmd_list -> safe_cmdj -> cmdj)
    assert len(r2.cmdj_calls) >= 1


def test_cached_query_uses_safe_cmd_dict():
    """Verify _cached_query with dict type actually invokes the r2 backend."""
    data = {"key": "value"}
    r2 = FakeR2(cmdj_map={"ij": data})
    adapter = R2PipeAdapter(r2)
    adapter._cached_query("ij", "dict")

    assert len(r2.cmdj_calls) >= 1


# ---------------------------------------------------------------------------
# Comprehensive force error testing for all methods
# ---------------------------------------------------------------------------


def test_force_error_all_methods():
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2, fault_injector=_always_raise)

    methods = [
        "_cached_query",
        "get_file_info",
        "get_sections",
        "get_imports",
        "custom_method",
    ]

    for method in methods:
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error(method)


def test_initialization_logging():
    """Adapter initialization should complete without errors."""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    # The logger.debug call happens internally; just verify construction succeeds
    assert adapter._r2 is r2


def test_cache_persistence_across_calls():
    """Multiple cached queries should coexist in the cache."""
    r2 = FakeR2(
        cmdj_map={
            "cmd1": [{"first": 1}],
            "cmd2": {"second": 2},
        }
    )
    adapter = R2PipeAdapter(r2)

    adapter._cached_query("cmd1", "list")
    adapter._cached_query("cmd2", "dict")

    assert "cmd1" in adapter._cache
    assert "cmd2" in adapter._cache
    assert len(adapter._cache) == 2


def test_cached_query_with_none_default():
    r2 = FakeR2(cmdj_map={"cmd": []})
    adapter = R2PipeAdapter(r2)
    result = adapter._cached_query("cmd", "list", default=None)

    # default=None means fall back to [] for list type
    assert result == []


def test_maybe_force_error_noop_injector():
    """A fault_injector that does nothing is equivalent to no injector."""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2, fault_injector=lambda method: None)
    adapter._maybe_force_error("test_method")  # should not raise


def test_cmd_with_complex_output():
    r2 = FakeR2(cmd_map={"test": "line1\nline2\nline3"})
    adapter = R2PipeAdapter(r2)
    result = adapter.cmd("test")

    assert result == "line1\nline2\nline3"
    assert isinstance(result, str)


def test_cmdj_with_list_result():
    r2 = FakeR2(cmdj_map={"test": [1, 2, 3]})
    adapter = R2PipeAdapter(r2)
    result = adapter.cmdj("test")

    assert result == [1, 2, 3]


def test_cmdj_with_dict_result():
    r2 = FakeR2(cmdj_map={"test": {"key": "value"}})
    adapter = R2PipeAdapter(r2)
    result = adapter.cmdj("test")

    assert result == {"key": "value"}


# ---------------------------------------------------------------------------
# Additional behavior-based tests (replacing mock-interaction tests)
# ---------------------------------------------------------------------------


def test_cached_query_second_call_uses_cache():
    """Calling _cached_query twice should use cache on second call."""
    call_count = 0
    original_data = [{"name": ".text", "size": 200}]

    class CountingR2(FakeR2):
        def cmdj(self, command):
            nonlocal call_count
            call_count += 1
            return original_data

    r2 = CountingR2()
    adapter = R2PipeAdapter(r2)

    result1 = adapter._cached_query("iSj", "list")
    first_call_count = call_count

    result2 = adapter._cached_query("iSj", "list")
    second_call_count = call_count

    # Second call should not have increased the r2 call count
    assert second_call_count == first_call_count
    assert result1 == result2


def test_r2_property_accessor():
    """The r2 property should return the underlying r2 instance."""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    assert adapter.r2 is r2


def test_execute_command_json_list():
    """execute_command should return list for list-type JSON commands."""
    data = [{"name": "main", "size": 42}]
    r2 = FakeR2(cmdj_map={"iSj": data})
    adapter = R2PipeAdapter(r2)
    result = adapter.execute_command("iSj")
    assert isinstance(result, list)


def test_execute_command_json_dict():
    """execute_command should return dict for dict-type JSON commands."""
    data = {"bin": {"arch": "x86"}}
    r2 = FakeR2(cmdj_map={"ij": data})
    adapter = R2PipeAdapter(r2)
    result = adapter.execute_command("ij")
    assert isinstance(result, dict)


def test_execute_command_text():
    """execute_command should return text for non-JSON commands."""
    r2 = FakeR2(cmd_map={"pd 10": "0x0040 mov eax, 0"})
    adapter = R2PipeAdapter(r2)
    result = adapter.execute_command("pd 10")
    assert isinstance(result, str)
    assert "mov" in result


def test_execute_command_empty_returns_none():
    """execute_command with empty command should return None."""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    result = adapter.execute_command("")
    assert result is None


def test_execute_command_whitespace_returns_none():
    """execute_command with whitespace-only command should return None."""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    result = adapter.execute_command("   ")
    assert result is None
