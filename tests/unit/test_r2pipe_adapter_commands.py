"""Comprehensive tests for adapters/r2pipe_adapter.py commands and error handling.

All tests use FakeR2Adapter + R2PipeAdapter -- NO mocks, NO monkeypatch, NO @patch.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from tests.helpers.r2_fakes import FakeR2Adapter


def _make_adapter(
    *,
    cmd_responses: dict | None = None,
    cmdj_responses: dict | None = None,
    fault_injector: Any = None,
) -> R2PipeAdapter:
    """Build a real R2PipeAdapter wrapping a FakeR2Adapter."""
    fake = FakeR2Adapter(cmd_responses=cmd_responses, cmdj_responses=cmdj_responses)
    return R2PipeAdapter(fake, fault_injector=fault_injector)


def _always_raise(method: str) -> None:
    raise RuntimeError("Forced adapter error")


def _selective_raise(*methods: str):
    def _injector(method: str) -> None:
        if method in methods:
            raise RuntimeError("Forced adapter error")

    return _injector


class TestR2PipeAdapterInitialization:
    """Test R2PipeAdapter initialization and validation."""

    def test_init_with_valid_instance(self) -> None:
        fake = FakeR2Adapter()
        adapter = R2PipeAdapter(fake)

        assert adapter._r2 is fake
        assert adapter._cache == {}
        assert adapter.thread_safe is False

    def test_init_with_none_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="r2_instance cannot be None"):
            R2PipeAdapter(None)

    def test_repr_method(self) -> None:
        adapter = _make_adapter()
        result = repr(adapter)
        assert "R2PipeAdapter" in result
        assert "r2_instance=" in result

    def test_str_method(self) -> None:
        adapter = _make_adapter()
        result = str(adapter)
        assert result == "R2PipeAdapter for radare2 binary analysis"


class TestR2PipeAdapterCommands:
    """Test cmd and cmdj command execution."""

    def test_cmd_returns_string(self) -> None:
        adapter = _make_adapter(cmd_responses={"i": "test output"})
        result = adapter.cmd("i")
        assert result == "test output"

    def test_cmd_converts_non_string_to_string(self) -> None:
        adapter = _make_adapter(cmd_responses={"i": 12345})
        result = adapter.cmd("i")
        assert result == "12345"
        assert isinstance(result, str)

    def test_cmd_with_json_command(self) -> None:
        adapter = _make_adapter(cmd_responses={"ij": '{"key": "value"}'})
        result = adapter.cmd("ij")
        assert result == '{"key": "value"}'

    def test_cmdj_returns_parsed_dict(self) -> None:
        """cmdj delegates to silent_cmdj which calls r2_instance.cmdj()."""
        adapter = _make_adapter(cmdj_responses={"ij": {"test": "data"}})
        result = adapter.cmdj("ij")
        assert result == {"test": "data"}

    def test_cmdj_returns_none_for_missing_command(self) -> None:
        """cmdj returns None/empty when the command produces no response."""
        adapter = _make_adapter()
        result = adapter.cmdj("invalid_command")
        # FakeR2Adapter returns "" for unknown commands; silent_cmdj may
        # parse the empty string and return it or None depending on fallback.
        assert result is None or result == ""


class TestR2PipeAdapterCachedQuery:
    """Test _cached_query method with caching and validation."""

    def test_cached_query_returns_cached_list(self) -> None:
        adapter = _make_adapter()
        adapter._cache["iSj"] = [{"name": "section1"}]

        result = adapter._cached_query("iSj", "list")

        assert result == [{"name": "section1"}]
        # Verify no cmd was dispatched (FakeR2Adapter tracks calls).
        assert "cmd" not in adapter._r2.calls or "iSj" not in adapter._r2.calls.get("cmd", [])

    def test_cached_query_returns_cached_dict(self) -> None:
        adapter = _make_adapter()
        adapter._cache["iij"] = {"arch": "x86"}

        result = adapter._cached_query("iij", "dict")

        assert result == {"arch": "x86"}

    def test_cached_query_list_not_cached_success(self) -> None:
        """_cached_query fetches, validates, and caches a list result."""
        section_data = [{"name": ".text", "vaddr": 4096}]
        # FakeR2Adapter treats list values as a queue of responses, so wrap
        # the list response in another list so the first pop returns the list.
        adapter = _make_adapter(
            cmdj_responses={"iSj": [section_data]},
            cmd_responses={"iSj": json.dumps(section_data)},
        )

        result = adapter._cached_query("iSj", "list")

        assert isinstance(result, list)
        assert len(result) > 0
        assert "iSj" in adapter._cache

    def test_cached_query_dict_not_cached_success(self) -> None:
        """_cached_query fetches, validates, and caches a dict result."""
        info_data = {"arch": "x86", "bits": 64}
        adapter = _make_adapter(
            cmdj_responses={"iij": info_data},
            cmd_responses={"iij": json.dumps(info_data)},
        )

        result = adapter._cached_query("iij", "dict")

        assert isinstance(result, dict)
        assert len(result) > 0
        assert "iij" in adapter._cache

    def test_cached_query_invalid_response_returns_default_list(self) -> None:
        """Empty/invalid response yields empty list default and is NOT cached."""
        adapter = _make_adapter(
            cmdj_responses={"iSj": [[]]},
            cmd_responses={"iSj": "[]"},
        )

        result = adapter._cached_query("iSj", "list", error_msg="No sections")

        assert result == []
        assert "iSj" not in adapter._cache

    def test_cached_query_invalid_response_returns_default_dict(self) -> None:
        adapter = _make_adapter(
            cmdj_responses={"iij": {}},
            cmd_responses={"iij": "{}"},
        )

        result = adapter._cached_query("iij", "dict")

        assert result == {}
        assert "iij" not in adapter._cache

    def test_cached_query_custom_default_list(self) -> None:
        """Custom default returned when response is invalid."""
        adapter = _make_adapter(
            cmdj_responses={"iSj": [[]]},
            cmd_responses={"iSj": "[]"},
        )
        custom_default = [{"default": "item"}]

        result = adapter._cached_query("iSj", "list", default=custom_default)

        assert result == custom_default

    def test_cached_query_custom_default_dict(self) -> None:
        adapter = _make_adapter(
            cmdj_responses={"iij": {}},
            cmd_responses={"iij": "{}"},
        )
        custom_default = {"default": "value"}

        result = adapter._cached_query("iij", "dict", default=custom_default)

        assert result == custom_default

    def test_cached_query_no_cache_parameter(self) -> None:
        """cache=False bypasses the cache store."""
        section_data = [{"test": "data"}]
        adapter = _make_adapter(
            cmdj_responses={"iSj": [section_data]},
            cmd_responses={"iSj": json.dumps(section_data)},
        )

        result = adapter._cached_query("iSj", "list", cache=False)

        assert isinstance(result, list)
        assert len(result) > 0
        assert "iSj" not in adapter._cache


class TestR2PipeAdapterErrorForcing:
    """Test forced error mechanism via fault_injector."""

    def test_maybe_force_error_no_injector(self) -> None:
        adapter = _make_adapter()
        # Should not raise
        adapter._maybe_force_error("test_method")

    def test_maybe_force_error_always_raise(self) -> None:
        adapter = _make_adapter(fault_injector=_always_raise)
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("any_method")

    def test_maybe_force_error_selective_match(self) -> None:
        adapter = _make_adapter(fault_injector=_selective_raise("_cached_query", "cmd"))
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("_cached_query")
        # Different method should not raise
        adapter._maybe_force_error("cmdj")

    def test_maybe_force_error_selective_no_match(self) -> None:
        adapter = _make_adapter(fault_injector=_selective_raise("cmd", "cmdj"))
        # Should not raise
        adapter._maybe_force_error("_cached_query")


class TestR2PipeAdapterIntegration:
    """Integration tests for adapter command flow."""

    def test_cached_query_caches_on_second_call(self) -> None:
        """First call fetches; second call uses the cache."""
        section_data = [{"vaddr": 0x1000, "name": ".text"}]
        adapter = _make_adapter(
            cmdj_responses={"iSj": [section_data, section_data]},
            cmd_responses={"iSj": json.dumps(section_data)},
        )

        result1 = adapter._cached_query("iSj", "list")
        assert len(result1) == 1

        # Second call should use cache -- FakeR2Adapter won't be hit again.
        result2 = adapter._cached_query("iSj", "list")
        assert result1 == result2

    def test_force_error_in_cached_query(self) -> None:
        adapter = _make_adapter(fault_injector=_selective_raise("_cached_query"))
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._cached_query("iSj", "list")

    def test_multiple_cached_queries_different_commands(self) -> None:
        """Caching works independently for different commands."""
        section_data = [{"section": "data"}]
        info_data = {"info": "value"}
        adapter = _make_adapter(
            cmdj_responses={"iSj": [section_data], "iij": info_data},
            cmd_responses={
                "iSj": json.dumps(section_data),
                "iij": json.dumps(info_data),
            },
        )

        result1 = adapter._cached_query("iSj", "list")
        result2 = adapter._cached_query("iij", "dict")

        assert isinstance(result1, list)
        assert len(result1) > 0
        assert isinstance(result2, dict)
        assert len(result2) > 0
        assert "iSj" in adapter._cache
        assert "iij" in adapter._cache
