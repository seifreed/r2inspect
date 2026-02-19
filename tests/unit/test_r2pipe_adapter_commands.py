"""Comprehensive tests for adapters/r2pipe_adapter.py commands and error handling."""

from __future__ import annotations

import os
from unittest.mock import Mock, patch

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


class TestR2PipeAdapterInitialization:
    """Test R2PipeAdapter initialization and validation."""

    def test_init_with_valid_instance(self) -> None:
        """Test successful initialization with valid r2pipe instance."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        assert adapter._r2 is mock_r2
        assert adapter._cache == {}
        assert adapter.thread_safe is False

    def test_init_with_none_raises_value_error(self) -> None:
        """Test initialization with None raises ValueError."""
        with pytest.raises(ValueError, match="r2_instance cannot be None"):
            R2PipeAdapter(None)

    def test_repr_method(self) -> None:
        """Test __repr__ returns string representation."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        result = repr(adapter)

        assert "R2PipeAdapter" in result
        assert "r2_instance=" in result

    def test_str_method(self) -> None:
        """Test __str__ returns human-readable representation."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        result = str(adapter)

        assert result == "R2PipeAdapter for radare2 binary analysis"


class TestR2PipeAdapterCommands:
    """Test cmd and cmdj command execution."""

    def test_cmd_returns_string(self) -> None:
        """Test cmd method returns string result."""
        mock_r2 = Mock()
        mock_r2.cmd.return_value = "test output"
        adapter = R2PipeAdapter(mock_r2)

        result = adapter.cmd("i")

        assert result == "test output"
        mock_r2.cmd.assert_called_once_with("i")

    def test_cmd_converts_non_string_to_string(self) -> None:
        """Test cmd method converts non-string results to string."""
        mock_r2 = Mock()
        mock_r2.cmd.return_value = 12345
        adapter = R2PipeAdapter(mock_r2)

        result = adapter.cmd("i")

        assert result == "12345"
        assert isinstance(result, str)

    def test_cmd_with_json_command(self) -> None:
        """Test cmd method with JSON command returns string."""
        mock_r2 = Mock()
        mock_r2.cmd.return_value = '{"key": "value"}'
        adapter = R2PipeAdapter(mock_r2)

        result = adapter.cmd("ij")

        assert result == '{"key": "value"}'

    def test_cmdj_uses_silent_cmdj(self) -> None:
        """Test cmdj method uses silent_cmdj helper."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        with patch("r2inspect.adapters.r2pipe_adapter.silent_cmdj") as mock_silent:
            mock_silent.return_value = {"test": "data"}

            result = adapter.cmdj("ij")

            assert result == {"test": "data"}
            mock_silent.assert_called_once_with(mock_r2, "ij", None)

    def test_cmdj_returns_none_on_error(self) -> None:
        """Test cmdj returns None when silent_cmdj returns None."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        with patch("r2inspect.adapters.r2pipe_adapter.silent_cmdj") as mock_silent:
            mock_silent.return_value = None

            result = adapter.cmdj("invalid_command")

            assert result is None


class TestR2PipeAdapterCachedQuery:
    """Test _cached_query method with caching and validation."""

    def test_cached_query_returns_cached_list(self) -> None:
        """Test _cached_query returns cached list data."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)
        adapter._cache["iSj"] = [{"name": "section1"}]

        result = adapter._cached_query("iSj", "list")

        assert result == [{"name": "section1"}]
        # Ensure no command was executed
        assert not mock_r2.cmd.called

    def test_cached_query_returns_cached_dict(self) -> None:
        """Test _cached_query returns cached dict data."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)
        adapter._cache["iij"] = {"arch": "x86"}

        result = adapter._cached_query("iij", "dict")

        assert result == {"arch": "x86"}
        assert not mock_r2.cmd.called

    def test_cached_query_list_not_cached_success(self) -> None:
        """Test _cached_query executes command and caches list result."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list") as mock_safe_list, patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data"
        ) as mock_validate, patch(
            "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response"
        ) as mock_is_valid:
            mock_safe_list.return_value = [{"test": "data"}]
            mock_validate.return_value = [{"test": "data"}]
            mock_is_valid.return_value = True

            result = adapter._cached_query("iSj", "list")

            assert result == [{"test": "data"}]
            assert adapter._cache["iSj"] == [{"test": "data"}]
            mock_safe_list.assert_called_once_with(adapter, "iSj")
            mock_validate.assert_called_once_with([{"test": "data"}], "list")

    def test_cached_query_dict_not_cached_success(self) -> None:
        """Test _cached_query executes command and caches dict result."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_dict") as mock_safe_dict, patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data"
        ) as mock_validate, patch(
            "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response"
        ) as mock_is_valid:
            mock_safe_dict.return_value = {"arch": "x86"}
            mock_validate.return_value = {"arch": "x86"}
            mock_is_valid.return_value = True

            result = adapter._cached_query("iij", "dict")

            assert result == {"arch": "x86"}
            assert adapter._cache["iij"] == {"arch": "x86"}
            mock_safe_dict.assert_called_once_with(adapter, "iij")

    def test_cached_query_invalid_response_returns_default_list(self) -> None:
        """Test _cached_query returns empty list for invalid response."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list") as mock_safe_list, patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data"
        ) as mock_validate, patch(
            "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response"
        ) as mock_is_valid:
            mock_safe_list.return_value = []
            mock_validate.return_value = []
            mock_is_valid.return_value = False

            result = adapter._cached_query("iSj", "list", error_msg="No sections")

            assert result == []
            assert "iSj" not in adapter._cache

    def test_cached_query_invalid_response_returns_default_dict(self) -> None:
        """Test _cached_query returns empty dict for invalid response."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_dict") as mock_safe_dict, patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data"
        ) as mock_validate, patch(
            "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response"
        ) as mock_is_valid:
            mock_safe_dict.return_value = {}
            mock_validate.return_value = {}
            mock_is_valid.return_value = False

            result = adapter._cached_query("iij", "dict")

            assert result == {}
            assert "iij" not in adapter._cache

    def test_cached_query_custom_default_list(self) -> None:
        """Test _cached_query uses custom default for list on invalid response."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list") as mock_safe_list, patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data"
        ) as mock_validate, patch(
            "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response"
        ) as mock_is_valid:
            mock_safe_list.return_value = []
            mock_validate.return_value = []
            mock_is_valid.return_value = False
            custom_default = [{"default": "item"}]

            result = adapter._cached_query("iSj", "list", default=custom_default)

            assert result == custom_default

    def test_cached_query_custom_default_dict(self) -> None:
        """Test _cached_query uses custom default for dict on invalid response."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_dict") as mock_safe_dict, patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data"
        ) as mock_validate, patch(
            "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response"
        ) as mock_is_valid:
            mock_safe_dict.return_value = {}
            mock_validate.return_value = {}
            mock_is_valid.return_value = False
            custom_default = {"default": "value"}

            result = adapter._cached_query("iij", "dict", default=custom_default)

            assert result == custom_default

    def test_cached_query_no_cache_parameter(self) -> None:
        """Test _cached_query with cache=False doesn't cache results."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list") as mock_safe_list, patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data"
        ) as mock_validate, patch(
            "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response"
        ) as mock_is_valid:
            mock_safe_list.return_value = [{"test": "data"}]
            mock_validate.return_value = [{"test": "data"}]
            mock_is_valid.return_value = True

            result = adapter._cached_query("iSj", "list", cache=False)

            assert result == [{"test": "data"}]
            assert "iSj" not in adapter._cache


class TestR2PipeAdapterErrorForcing:
    """Test forced error mechanism for testing."""

    def test_maybe_force_error_not_set(self) -> None:
        """Test _maybe_force_error does nothing when env var not set."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        # Should not raise
        adapter._maybe_force_error("test_method")

    def test_maybe_force_error_with_value_1(self) -> None:
        """Test _maybe_force_error raises when env var is '1'."""
        original = os.environ.get("R2INSPECT_FORCE_ADAPTER_ERROR")
        try:
            os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "1"
            mock_r2 = Mock()
            adapter = R2PipeAdapter(mock_r2)

            with pytest.raises(RuntimeError, match="Forced adapter error"):
                adapter._maybe_force_error("any_method")
        finally:
            if original is None:
                os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)
            else:
                os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = original

    def test_maybe_force_error_with_true(self) -> None:
        """Test _maybe_force_error raises when env var is 'true'."""
        original = os.environ.get("R2INSPECT_FORCE_ADAPTER_ERROR")
        try:
            os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "true"
            mock_r2 = Mock()
            adapter = R2PipeAdapter(mock_r2)

            with pytest.raises(RuntimeError, match="Forced adapter error"):
                adapter._maybe_force_error("any_method")
        finally:
            if original is None:
                os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)
            else:
                os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = original

    def test_maybe_force_error_with_all(self) -> None:
        """Test _maybe_force_error raises when env var is 'all'."""
        original = os.environ.get("R2INSPECT_FORCE_ADAPTER_ERROR")
        try:
            os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "all"
            mock_r2 = Mock()
            adapter = R2PipeAdapter(mock_r2)

            with pytest.raises(RuntimeError, match="Forced adapter error"):
                adapter._maybe_force_error("any_method")
        finally:
            if original is None:
                os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)
            else:
                os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = original

    def test_maybe_force_error_with_wildcard(self) -> None:
        """Test _maybe_force_error raises when env var is '*'."""
        original = os.environ.get("R2INSPECT_FORCE_ADAPTER_ERROR")
        try:
            os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "*"
            mock_r2 = Mock()
            adapter = R2PipeAdapter(mock_r2)

            with pytest.raises(RuntimeError, match="Forced adapter error"):
                adapter._maybe_force_error("any_method")
        finally:
            if original is None:
                os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)
            else:
                os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = original

    def test_maybe_force_error_specific_method(self) -> None:
        """Test _maybe_force_error raises for specific method name."""
        original = os.environ.get("R2INSPECT_FORCE_ADAPTER_ERROR")
        try:
            os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "_cached_query,cmd"
            mock_r2 = Mock()
            adapter = R2PipeAdapter(mock_r2)

            with pytest.raises(RuntimeError, match="Forced adapter error"):
                adapter._maybe_force_error("_cached_query")

            # Different method should not raise
            adapter._maybe_force_error("cmdj")
        finally:
            if original is None:
                os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)
            else:
                os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = original

    def test_maybe_force_error_method_not_in_list(self) -> None:
        """Test _maybe_force_error doesn't raise for methods not in list."""
        original = os.environ.get("R2INSPECT_FORCE_ADAPTER_ERROR")
        try:
            os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "cmd,cmdj"
            mock_r2 = Mock()
            adapter = R2PipeAdapter(mock_r2)

            # Should not raise
            adapter._maybe_force_error("_cached_query")
        finally:
            if original is None:
                os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)
            else:
                os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = original


class TestR2PipeAdapterIntegration:
    """Integration tests for adapter command flow."""

    def test_cached_query_called_in_cmd_flow(self) -> None:
        """Test that _cached_query integrates with command helpers."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list") as mock_safe_list, patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data"
        ) as mock_validate, patch(
            "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response"
        ) as mock_is_valid:
            mock_safe_list.return_value = [{"vaddr": 0x1000, "name": ".text"}]
            mock_validate.return_value = [{"vaddr": 0x1000, "name": ".text"}]
            mock_is_valid.return_value = True

            # First call should execute command
            result1 = adapter._cached_query("iSj", "list")
            assert len(result1) == 1

            # Second call should use cache
            result2 = adapter._cached_query("iSj", "list")
            assert result1 == result2
            # safe_cmd_list should only be called once
            assert mock_safe_list.call_count == 1

    def test_force_error_in_cached_query(self) -> None:
        """Test forced error mechanism triggers in _cached_query."""
        original = os.environ.get("R2INSPECT_FORCE_ADAPTER_ERROR")
        try:
            os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "_cached_query"
            mock_r2 = Mock()
            adapter = R2PipeAdapter(mock_r2)

            with pytest.raises(RuntimeError, match="Forced adapter error"):
                adapter._cached_query("iSj", "list")
        finally:
            if original is None:
                os.environ.pop("R2INSPECT_FORCE_ADAPTER_ERROR", None)
            else:
                os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = original

    def test_multiple_cached_queries_different_commands(self) -> None:
        """Test caching works independently for different commands."""
        mock_r2 = Mock()
        adapter = R2PipeAdapter(mock_r2)

        with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list") as mock_safe_list, patch(
            "r2inspect.adapters.r2pipe_adapter.safe_cmd_dict"
        ) as mock_safe_dict, patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data"
        ) as mock_validate, patch(
            "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response"
        ) as mock_is_valid:
            mock_safe_list.return_value = [{"section": "data"}]
            mock_safe_dict.return_value = {"info": "value"}
            mock_validate.side_effect = lambda x, y: x
            mock_is_valid.return_value = True

            result1 = adapter._cached_query("iSj", "list")
            result2 = adapter._cached_query("iij", "dict")

            assert result1 == [{"section": "data"}]
            assert result2 == {"info": "value"}
            assert "iSj" in adapter._cache
            assert "iij" in adapter._cache
