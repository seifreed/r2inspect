from __future__ import annotations

import os

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


class FakeR2:
    def __init__(self, cmdj_map: dict | None = None, cmd_map: dict | None = None) -> None:
        self.cmdj_map = cmdj_map or {}
        self.cmd_map = cmd_map or {}

    def cmdj(self, command: str) -> object:
        return self.cmdj_map.get(command)

    def cmd(self, command: str) -> str:
        return self.cmd_map.get(command, "")


def test_r2pipe_adapter_none_instance() -> None:
    """Test R2PipeAdapter raises ValueError with None instance"""
    with pytest.raises(ValueError, match="r2_instance cannot be None"):
        R2PipeAdapter(None)  # type: ignore


def test_cmd_returns_non_string() -> None:
    """Test cmd() when r2.cmd returns non-string"""
    class NonStringR2:
        def cmd(self, _command: str) -> int:
            return 42
        
        def cmdj(self, _command: str) -> object:
            return {}
    
    adapter = R2PipeAdapter(NonStringR2())  # type: ignore
    result = adapter.cmd("test")
    assert result == "42"


def test_cached_query_cache_hit() -> None:
    """Test _cached_query cache behavior"""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    
    # Test that cache parameter works
    # Just verify it doesn't crash with cache=True
    result = adapter._cached_query("iSj", "list", cache=True)
    assert isinstance(result, list)


def test_cached_query_cache_disabled() -> None:
    """Test _cached_query with cache=False"""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    
    # Test cache=False parameter
    result = adapter._cached_query("iSj", "list", cache=False)
    assert isinstance(result, list)


def test_cached_query_dict_type() -> None:
    """Test _cached_query with dict data type"""
    r2 = FakeR2()
    # Set up the adapter to return a valid dict through safe_cmd_dict
    adapter = R2PipeAdapter(r2)
    
    # Mock cmdj to return valid data
    def mock_cmdj(cmd: str) -> object:
        if cmd == "ij":
            return {"arch": "x86"}
        return {}
    
    adapter._r2.cmdj = mock_cmdj
    
    result = adapter._cached_query("ij", "dict")
    assert isinstance(result, dict)


def test_cached_query_dict_default() -> None:
    """Test _cached_query dict type with default value"""
    r2 = FakeR2(cmdj_map={"ij": None})
    adapter = R2PipeAdapter(r2)
    
    default = {"default": "value"}
    result = adapter._cached_query("ij", "dict", default=default)
    assert result == default


def test_cached_query_list_default() -> None:
    """Test _cached_query list type with default value"""
    r2 = FakeR2(cmdj_map={"iSj": None})
    adapter = R2PipeAdapter(r2)
    
    default = [{"default": "section"}]
    result = adapter._cached_query("iSj", "list", default=default)
    assert result == default


def test_cached_query_invalid_response_with_error_msg() -> None:
    """Test _cached_query logs error_msg when response is invalid"""
    r2 = FakeR2(cmdj_map={"iSj": "invalid"})
    adapter = R2PipeAdapter(r2)
    
    result = adapter._cached_query("iSj", "list", error_msg="No sections found")
    assert result == []


def test_repr_method() -> None:
    """Test __repr__ method"""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    
    repr_str = repr(adapter)
    assert "R2PipeAdapter" in repr_str
    assert "r2_instance" in repr_str


def test_str_method() -> None:
    """Test __str__ method"""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    
    str_result = str(adapter)
    assert "R2PipeAdapter" in str_result
    assert "radare2" in str_result


def test_maybe_force_error_not_set() -> None:
    """Test _maybe_force_error when env var not set"""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    
    # Should not raise
    adapter._maybe_force_error("test_method")


def test_maybe_force_error_set_to_1() -> None:
    """Test _maybe_force_error when env var is '1'"""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    
    with pytest.raises(RuntimeError, match="Forced adapter error"):
        os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "1"
        try:
            adapter._maybe_force_error("test_method")
        finally:
            del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


def test_maybe_force_error_set_to_true() -> None:
    """Test _maybe_force_error when env var is 'true'"""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    
    with pytest.raises(RuntimeError, match="Forced adapter error"):
        os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "true"
        try:
            adapter._maybe_force_error("test_method")
        finally:
            del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


def test_maybe_force_error_set_to_yes() -> None:
    """Test _maybe_force_error when env var is 'yes'"""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    
    with pytest.raises(RuntimeError, match="Forced adapter error"):
        os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "yes"
        try:
            adapter._maybe_force_error("test_method")
        finally:
            del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


def test_maybe_force_error_set_to_all() -> None:
    """Test _maybe_force_error when env var is 'all'"""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    
    with pytest.raises(RuntimeError, match="Forced adapter error"):
        os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "all"
        try:
            adapter._maybe_force_error("test_method")
        finally:
            del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


def test_maybe_force_error_set_to_asterisk() -> None:
    """Test _maybe_force_error when env var is '*'"""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    
    with pytest.raises(RuntimeError, match="Forced adapter error"):
        os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "*"
        try:
            adapter._maybe_force_error("test_method")
        finally:
            del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


def test_maybe_force_error_specific_method() -> None:
    """Test _maybe_force_error when env var contains specific method"""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    
    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "test_method,other_method"
    try:
        # Should raise for test_method
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("test_method")
        
        # Should raise for other_method
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("other_method")
        
        # Should not raise for different_method
        adapter._maybe_force_error("different_method")
    finally:
        del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


def test_maybe_force_error_whitespace_handling() -> None:
    """Test _maybe_force_error handles whitespace in method list"""
    r2 = FakeR2()
    adapter = R2PipeAdapter(r2)
    
    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = " method1 , method2 , "
    try:
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("method1")
        
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._maybe_force_error("method2")
        
        # Should not raise for method3
        adapter._maybe_force_error("method3")
    finally:
        del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


def test_cached_query_forced_error() -> None:
    """Test _cached_query with forced error"""
    r2 = FakeR2(cmdj_map={"iSj": [{"name": ".text"}]})
    adapter = R2PipeAdapter(r2)
    
    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "_cached_query"
    try:
        with pytest.raises(RuntimeError, match="Forced adapter error"):
            adapter._cached_query("iSj", "list")
    finally:
        del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]
