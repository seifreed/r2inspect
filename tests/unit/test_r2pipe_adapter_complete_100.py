"""Comprehensive tests for r2pipe_adapter.py - 100% coverage target."""

from unittest.mock import Mock, patch
import os

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


def test_init_success():
    """Test R2PipeAdapter initialization."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    assert adapter._r2 == r2_instance


def test_init_none_raises():
    """Test R2PipeAdapter initialization with None raises ValueError."""
    try:
        R2PipeAdapter(None)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "cannot be None" in str(e)


def test_cmd():
    """Test cmd method."""
    r2_instance = Mock()
    r2_instance.cmd.return_value = "test result"
    adapter = R2PipeAdapter(r2_instance)
    
    result = adapter.cmd("iSj")
    
    assert result == "test result"


def test_cmd_non_string():
    """Test cmd method with non-string return."""
    r2_instance = Mock()
    r2_instance.cmd.return_value = 12345
    adapter = R2PipeAdapter(r2_instance)
    
    result = adapter.cmd("test")
    
    assert result == "12345"


def test_cmdj():
    """Test cmdj method."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    with patch("r2inspect.adapters.r2pipe_adapter.silent_cmdj", return_value={"test": "data"}):
        result = adapter.cmdj("iSj")
        
        assert result == {"test": "data"}


def test_cached_query_list_cached():
    """Test _cached_query with cached list data."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    adapter._cache["iSj"] = [{"test": "data"}]
    
    result = adapter._cached_query("iSj", "list")
    
    assert result == [{"test": "data"}]


def test_cached_query_dict_cached():
    """Test _cached_query with cached dict data."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    adapter._cache["iij"] = {"test": "data"}
    
    result = adapter._cached_query("iij", "dict")
    
    assert result == {"test": "data"}


def test_cached_query_list_not_cached():
    """Test _cached_query with uncached list data."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=[{"test": "data"}]), \
         patch("r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=[{"test": "data"}]), \
         patch("r2inspect.adapters.r2pipe_adapter.is_valid_r2_response", return_value=True):
        result = adapter._cached_query("iSj", "list")
        
        assert result == [{"test": "data"}]
        assert "iSj" in adapter._cache


def test_cached_query_dict_not_cached():
    """Test _cached_query with uncached dict data."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_dict", return_value={"test": "data"}), \
         patch("r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value={"test": "data"}), \
         patch("r2inspect.adapters.r2pipe_adapter.is_valid_r2_response", return_value=True):
        result = adapter._cached_query("iij", "dict")
        
        assert result == {"test": "data"}


def test_cached_query_invalid_response_list():
    """Test _cached_query with invalid response for list."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=None), \
         patch("r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=None), \
         patch("r2inspect.adapters.r2pipe_adapter.is_valid_r2_response", return_value=False):
        result = adapter._cached_query("iSj", "list", error_msg="Test error")
        
        assert result == []


def test_cached_query_invalid_response_dict():
    """Test _cached_query with invalid response for dict."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_dict", return_value=None), \
         patch("r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=None), \
         patch("r2inspect.adapters.r2pipe_adapter.is_valid_r2_response", return_value=False):
        result = adapter._cached_query("iij", "dict")
        
        assert result == {}


def test_cached_query_custom_default_list():
    """Test _cached_query with custom default for list."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=None), \
         patch("r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=None), \
         patch("r2inspect.adapters.r2pipe_adapter.is_valid_r2_response", return_value=False):
        result = adapter._cached_query("iSj", "list", default=[{"default": "value"}])
        
        assert result == [{"default": "value"}]


def test_cached_query_no_cache():
    """Test _cached_query with caching disabled."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    with patch("r2inspect.adapters.r2pipe_adapter.safe_cmd_list", return_value=[{"test": "data"}]), \
         patch("r2inspect.adapters.r2pipe_adapter.validate_r2_data", return_value=[{"test": "data"}]), \
         patch("r2inspect.adapters.r2pipe_adapter.is_valid_r2_response", return_value=True):
        result = adapter._cached_query("iSj", "list", cache=False)
        
        assert result == [{"test": "data"}]
        assert "iSj" not in adapter._cache


def test_repr():
    """Test __repr__ method."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    result = repr(adapter)
    
    assert "R2PipeAdapter" in result


def test_str():
    """Test __str__ method."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    result = str(adapter)
    
    assert "radare2" in result


def test_maybe_force_error_not_set():
    """Test _maybe_force_error when env var not set."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    # Should not raise
    adapter._maybe_force_error("test_method")


def test_maybe_force_error_all():
    """Test _maybe_force_error with 'all' value."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "true"
    try:
        adapter._maybe_force_error("test_method")
        assert False, "Should have raised RuntimeError"
    except RuntimeError as e:
        assert "Forced adapter error" in str(e)
    finally:
        del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


def test_maybe_force_error_specific_method():
    """Test _maybe_force_error with specific method."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "test_method,other_method"
    try:
        adapter._maybe_force_error("test_method")
        assert False, "Should have raised RuntimeError"
    except RuntimeError as e:
        assert "Forced adapter error" in str(e)
    finally:
        del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


def test_maybe_force_error_different_method():
    """Test _maybe_force_error with different method."""
    r2_instance = Mock()
    adapter = R2PipeAdapter(r2_instance)
    
    os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"] = "other_method"
    try:
        # Should not raise
        adapter._maybe_force_error("test_method")
    finally:
        del os.environ["R2INSPECT_FORCE_ADAPTER_ERROR"]


def test_thread_safe_attribute():
    """Test thread_safe class attribute."""
    assert R2PipeAdapter.thread_safe is False
