#!/usr/bin/env python3
"""
Comprehensive tests for r2inspect/adapters/r2pipe_adapter.py

Tests initialization, caching, error handling, forced errors, and all adapter methods.
Targets 100% coverage including the 69 missing lines.
"""

import os
from unittest.mock import MagicMock, Mock, patch

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


# Initialization tests


def test_r2pipe_adapter_init_success():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    assert adapter._r2 is r2_mock
    assert adapter._cache == {}


def test_r2pipe_adapter_init_none_raises():
    with pytest.raises(ValueError, match="cannot be None"):
        R2PipeAdapter(None)


def test_r2pipe_adapter_thread_safe_flag():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    assert adapter.thread_safe is False


# cmd and cmdj tests


def test_cmd_returns_string():
    r2_mock = Mock()
    r2_mock.cmd.return_value = "output"

    adapter = R2PipeAdapter(r2_mock)
    result = adapter.cmd("test")

    assert result == "output"
    r2_mock.cmd.assert_called_once_with("test")


def test_cmd_converts_non_string_to_string():
    r2_mock = Mock()
    r2_mock.cmd.return_value = 123

    adapter = R2PipeAdapter(r2_mock)
    result = adapter.cmd("test")

    assert result == "123"
    assert isinstance(result, str)


def test_cmdj_uses_silent_cmdj():
    r2_mock = Mock()

    with patch("r2inspect.adapters.r2pipe_adapter.silent_cmdj") as mock_silent:
        mock_silent.return_value = {"data": "value"}

        adapter = R2PipeAdapter(r2_mock)
        result = adapter.cmdj("test")

        assert result == {"data": "value"}
        mock_silent.assert_called_once_with(r2_mock, "test", None)


def test_cmdj_returns_none_on_error():
    r2_mock = Mock()

    with patch("r2inspect.adapters.r2pipe_adapter.silent_cmdj") as mock_silent:
        mock_silent.return_value = None

        adapter = R2PipeAdapter(r2_mock)
        result = adapter.cmdj("test")

        assert result is None


# _cached_query tests


def test_cached_query_list_success():
    r2_mock = Mock()
    data = [{"item": 1}, {"item": 2}]

    with patch(
        "r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=data
    ):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=data
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=True,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("iSj", "list")

                assert result == data
                assert "iSj" in adapter._cache


def test_cached_query_dict_success():
    r2_mock = Mock()
    data = {"key": "value"}

    with patch(
        "r2inspect.adapters.r2pipe_adapter.safe_cmd_dict", return_value=data
    ):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=data
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=True,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("ij", "dict")

                assert result == data
                assert "ij" in adapter._cache


def test_cached_query_uses_cache():
    r2_mock = Mock()
    cached_data = [{"cached": True}]

    adapter = R2PipeAdapter(r2_mock)
    adapter._cache["iSj"] = cached_data

    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list") as mock_cmd:
        result = adapter._cached_query("iSj", "list")

        assert result == cached_data
        mock_cmd.assert_not_called()


def test_cached_query_cache_disabled():
    r2_mock = Mock()
    data = [{"item": 1}]

    with patch(
        "r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=data
    ):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=data
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=True,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("iSj", "list", cache=False)

                assert result == data
                assert "iSj" not in adapter._cache


def test_cached_query_invalid_response_returns_default_list():
    r2_mock = Mock()

    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=[]):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=[]
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=False,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("iSj", "list", error_msg="Test error")

                assert result == []


def test_cached_query_invalid_response_returns_default_dict():
    r2_mock = Mock()

    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_dict", return_value={}):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value={}
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=False,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("ij", "dict", error_msg="Test error")

                assert result == {}


def test_cached_query_custom_default_list():
    r2_mock = Mock()
    custom_default = [{"default": True}]

    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=[]):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=[]
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=False,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("iSj", "list", default=custom_default)

                assert result == custom_default


def test_cached_query_custom_default_dict():
    r2_mock = Mock()
    custom_default = {"default": "value"}

    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_dict", return_value={}):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value={}
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=False,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("ij", "dict", default=custom_default)

                assert result == custom_default


def test_cached_query_logs_error_msg():
    r2_mock = Mock()

    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=[]):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=[]
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=False,
            ):
                with patch("r2inspect.adapters.r2pipe_adapter.logger") as mock_logger:
                    adapter = R2PipeAdapter(r2_mock)
                    adapter._cached_query("iSj", "list", error_msg="Custom error")

                    mock_logger.debug.assert_called_with("Custom error")


def test_cached_query_no_log_without_error_msg():
    r2_mock = Mock()

    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=[]):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=[]
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=False,
            ):
                adapter = R2PipeAdapter(r2_mock)
                
                with patch("r2inspect.adapters.r2pipe_adapter.logger") as mock_logger:
                    adapter._cached_query("iSj", "list")
                    mock_logger.debug.assert_not_called()


def test_cached_query_caches_valid_response():
    r2_mock = Mock()
    data = [{"item": 1}]

    with patch(
        "r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=data
    ):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=data
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=True,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("cmd", "list", cache=True)

                assert "cmd" in adapter._cache
                assert adapter._cache["cmd"] == data


def test_cached_query_does_not_cache_when_disabled():
    r2_mock = Mock()
    data = [{"item": 1}]

    with patch(
        "r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=data
    ):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=data
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=True,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("cmd", "list", cache=False)

                assert "cmd" not in adapter._cache


# _maybe_force_error tests


def test_maybe_force_error_no_env_var():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(os.environ, {}, clear=True):
        adapter._maybe_force_error("test_method")


def test_maybe_force_error_env_var_empty():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": ""}, clear=True):
        adapter._maybe_force_error("test_method")


def test_maybe_force_error_env_var_true():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(
        os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": "true"}, clear=True
    ):
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("test_method")


def test_maybe_force_error_env_var_1():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": "1"}, clear=True):
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("test_method")


def test_maybe_force_error_env_var_yes():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": "yes"}, clear=True):
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("test_method")


def test_maybe_force_error_env_var_all():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": "all"}, clear=True):
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("test_method")


def test_maybe_force_error_env_var_asterisk():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": "*"}, clear=True):
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("test_method")


def test_maybe_force_error_env_var_specific_method():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(
        os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": "test_method"}, clear=True
    ):
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("test_method")


def test_maybe_force_error_env_var_different_method():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(
        os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": "other_method"}, clear=True
    ):
        adapter._maybe_force_error("test_method")


def test_maybe_force_error_env_var_multiple_methods():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(
        os.environ,
        {"R2INSPECT_FORCE_ADAPTER_ERROR": "method1,test_method,method2"},
        clear=True,
    ):
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("test_method")


def test_maybe_force_error_env_var_multiple_methods_not_in_list():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(
        os.environ,
        {"R2INSPECT_FORCE_ADAPTER_ERROR": "method1,method2,method3"},
        clear=True,
    ):
        adapter._maybe_force_error("test_method")


def test_maybe_force_error_env_var_case_insensitive():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": "TRUE"}, clear=True):
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("test_method")


def test_maybe_force_error_env_var_with_spaces():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(
        os.environ,
        {"R2INSPECT_FORCE_ADAPTER_ERROR": "  method1 , test_method , method2  "},
        clear=True,
    ):
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("test_method")


# __repr__ and __str__ tests


def test_repr():
    r2_mock = Mock()
    r2_mock.__repr__ = Mock(return_value="<R2PipeMock>")

    adapter = R2PipeAdapter(r2_mock)
    result = repr(adapter)

    assert "R2PipeAdapter" in result
    assert "r2_instance=" in result


def test_str():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)
    result = str(adapter)

    assert result == "R2PipeAdapter for radare2 binary analysis"


# Integration tests with _cached_query and force errors


def test_cached_query_with_forced_error():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(
        os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": "_cached_query"}, clear=True
    ):
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._cached_query("iSj", "list")


def test_cached_query_without_forced_error_when_other_method():
    r2_mock = Mock()
    data = [{"item": 1}]

    with patch(
        "r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=data
    ):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=data
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=True,
            ):
                adapter = R2PipeAdapter(r2_mock)

                with patch.dict(
                    os.environ,
                    {"R2INSPECT_FORCE_ADAPTER_ERROR": "other_method"},
                    clear=True,
                ):
                    result = adapter._cached_query("iSj", "list")
                    assert result == data


# Cache type casting tests


def test_cached_query_returns_list_type():
    r2_mock = Mock()
    data = [{"item": 1}]
    adapter = R2PipeAdapter(r2_mock)
    adapter._cache["cmd"] = data

    result = adapter._cached_query("cmd", "list")

    assert isinstance(result, list)
    assert result == data


def test_cached_query_returns_dict_type():
    r2_mock = Mock()
    data = {"key": "value"}
    adapter = R2PipeAdapter(r2_mock)
    adapter._cache["cmd"] = data

    result = adapter._cached_query("cmd", "dict")

    assert isinstance(result, dict)
    assert result == data


# Edge cases


def test_cached_query_empty_list_is_invalid():
    r2_mock = Mock()

    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=[]):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=[]
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=False,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("iSj", "list")

                assert result == []


def test_cached_query_empty_dict_is_invalid():
    r2_mock = Mock()

    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_dict", return_value={}):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value={}
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=False,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("ij", "dict")

                assert result == {}


def test_cached_query_validation_failure_returns_default():
    r2_mock = Mock()
    invalid_data = "not a list"

    with patch(
        "r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=invalid_data
    ):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=[]
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=False,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("iSj", "list")

                assert result == []


def test_cmd_empty_string():
    r2_mock = Mock()
    r2_mock.cmd.return_value = ""

    adapter = R2PipeAdapter(r2_mock)
    result = adapter.cmd("test")

    assert result == ""


def test_cmdj_empty_result():
    r2_mock = Mock()

    with patch("r2inspect.adapters.r2pipe_adapter.silent_cmdj", return_value=None):
        adapter = R2PipeAdapter(r2_mock)
        result = adapter.cmdj("test")

        assert result is None


def test_cached_query_uses_safe_cmd_list():
    r2_mock = Mock()
    data = [{"item": 1}]

    with patch(
        "r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=data
    ) as mock_safe:
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=data
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=True,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("iSj", "list")

                mock_safe.assert_called_once_with(adapter, "iSj")


def test_cached_query_uses_safe_cmd_dict():
    r2_mock = Mock()
    data = {"key": "value"}

    with patch(
        "r2inspect.adapters.r2pipe_adapter.safe_cmd_dict", return_value=data
    ) as mock_safe:
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=data
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=True,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("ij", "dict")

                mock_safe.assert_called_once_with(adapter, "ij")


# Comprehensive force error testing for all methods


def test_force_error_all_methods():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    methods = [
        "_cached_query",
        "get_file_info",
        "get_sections",
        "get_imports",
        "custom_method",
    ]

    for method in methods:
        with patch.dict(
            os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": method}, clear=True
        ):
            with pytest.raises(RuntimeError, match="Forced adapter error"):
                adapter._maybe_force_error(method)


def test_initialization_logging():
    r2_mock = Mock()

    with patch("r2inspect.adapters.r2pipe_adapter.logger") as mock_logger:
        adapter = R2PipeAdapter(r2_mock)
        mock_logger.debug.assert_called_with(
            "R2PipeAdapter initialized successfully"
        )


def test_cache_persistence_across_calls():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)
    data1 = [{"first": 1}]
    data2 = {"second": 2}

    with patch(
        "r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=data1
    ):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.safe_cmd_dict", return_value=data2
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.validate_r2_data",
                side_effect=[data1, data2],
            ):
                with patch(
                    "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                    return_value=True,
                ):
                    result1 = adapter._cached_query("cmd1", "list")
                    result2 = adapter._cached_query("cmd2", "dict")

                    assert adapter._cache["cmd1"] == data1
                    assert adapter._cache["cmd2"] == data2
                    assert len(adapter._cache) == 2


def test_cached_query_with_none_default():
    r2_mock = Mock()

    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=[]):
        with patch(
            "r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=[]
        ):
            with patch(
                "r2inspect.adapters.r2pipe_adapter.is_valid_r2_response",
                return_value=False,
            ):
                adapter = R2PipeAdapter(r2_mock)
                result = adapter._cached_query("cmd", "list", default=None)

                assert result == []


def test_maybe_force_error_empty_method_list():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": ","}, clear=True):
        adapter._maybe_force_error("test_method")


def test_maybe_force_error_whitespace_only():
    r2_mock = Mock()
    adapter = R2PipeAdapter(r2_mock)

    with patch.dict(
        os.environ, {"R2INSPECT_FORCE_ADAPTER_ERROR": "   "}, clear=True
    ):
        adapter._maybe_force_error("test_method")


def test_cmd_with_complex_output():
    r2_mock = Mock()
    r2_mock.cmd.return_value = "line1\nline2\nline3"

    adapter = R2PipeAdapter(r2_mock)
    result = adapter.cmd("test")

    assert result == "line1\nline2\nline3"
    assert isinstance(result, str)


def test_cmdj_with_list_result():
    r2_mock = Mock()

    with patch(
        "r2inspect.adapters.r2pipe_adapter.silent_cmdj", return_value=[1, 2, 3]
    ):
        adapter = R2PipeAdapter(r2_mock)
        result = adapter.cmdj("test")

        assert result == [1, 2, 3]


def test_cmdj_with_dict_result():
    r2_mock = Mock()

    with patch(
        "r2inspect.adapters.r2pipe_adapter.silent_cmdj",
        return_value={"key": "value"},
    ):
        adapter = R2PipeAdapter(r2_mock)
        result = adapter.cmdj("test")

        assert result == {"key": "value"}
