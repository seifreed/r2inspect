#!/usr/bin/env python3
"""Edge case tests for r2pipe_context.py - 100% coverage."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from r2inspect.adapters.r2pipe_context import open_r2pipe, open_r2_adapter


@pytest.fixture
def sample_binary():
    """Create a minimal valid binary for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"\x7fELF\x00" * 20)
        return f.name


def test_open_r2pipe_default_flags(sample_binary):
    """Test open_r2pipe uses default flags [-2]."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2pipe(sample_binary):
            pass
        
        mock_open.assert_called_once_with(sample_binary, flags=["-2"])


def test_open_r2pipe_custom_flags(sample_binary):
    """Test open_r2pipe with custom flags."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        custom_flags = ["-e", "io.cache=true"]
        with open_r2pipe(sample_binary, flags=custom_flags):
            pass
        
        mock_open.assert_called_once_with(sample_binary, flags=custom_flags)


def test_open_r2pipe_none_flags_uses_default(sample_binary):
    """Test that flags=None uses default [-2]."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2pipe(sample_binary, flags=None):
            pass
        
        mock_open.assert_called_once_with(sample_binary, flags=["-2"])


def test_open_r2pipe_empty_flags_list(sample_binary):
    """Test with empty flags list uses default."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2pipe(sample_binary, flags=[]):
            pass
        
        mock_open.assert_called_once_with(sample_binary, flags=["-2"])


def test_open_r2pipe_yields_r2_instance(sample_binary):
    """Test that context manager yields r2 instance."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2pipe(sample_binary) as r2:
            assert r2 is mock_r2


def test_open_r2pipe_calls_exit_on_success(sample_binary):
    """Test that __exit__ is called on successful completion."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_exit = Mock(return_value=None)
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = mock_exit
        
        with open_r2pipe(sample_binary):
            pass
        
        assert mock_exit.called


def test_open_r2pipe_calls_exit_on_exception(sample_binary):
    """Test that __exit__ is called even on exception."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_exit = Mock(return_value=None)
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = mock_exit
        
        try:
            with open_r2pipe(sample_binary):
                raise ValueError("test error")
        except ValueError:
            pass
        
        assert mock_exit.called


def test_open_r2_adapter_returns_adapter(sample_binary):
    """Test open_r2_adapter returns R2PipeAdapter instance."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2_adapter(sample_binary) as adapter:
            from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
            assert isinstance(adapter, R2PipeAdapter)


def test_open_r2_adapter_default_flags(sample_binary):
    """Test open_r2_adapter passes default flags."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2_adapter(sample_binary):
            pass
        
        mock_open.assert_called_once_with(sample_binary, flags=["-2"])


def test_open_r2_adapter_custom_flags(sample_binary):
    """Test open_r2_adapter with custom flags."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        custom_flags = ["-e", "bin.maxstringlen=1024"]
        with open_r2_adapter(sample_binary, flags=custom_flags):
            pass
        
        mock_open.assert_called_once_with(sample_binary, flags=custom_flags)


def test_open_r2_adapter_none_flags(sample_binary):
    """Test open_r2_adapter with flags=None."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2_adapter(sample_binary, flags=None):
            pass
        
        mock_open.assert_called_once_with(sample_binary, flags=["-2"])


def test_open_r2_adapter_cleanup(sample_binary):
    """Test adapter cleanup on context exit."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_exit = Mock(return_value=None)
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = mock_exit
        
        with open_r2_adapter(sample_binary):
            pass
        
        assert mock_exit.called


def test_open_r2_adapter_cleanup_on_exception(sample_binary):
    """Test adapter cleanup happens even on exception."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_exit = Mock(return_value=None)
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = mock_exit
        
        try:
            with open_r2_adapter(sample_binary):
                raise RuntimeError("adapter error")
        except RuntimeError:
            pass
        
        assert mock_exit.called


def test_nested_r2pipe_contexts(sample_binary):
    """Test multiple nested open_r2pipe contexts."""
    with patch("r2pipe.open") as mock_open:
        mock_r2_1 = Mock(name="r2_1")
        mock_r2_2 = Mock(name="r2_2")
        
        contexts = [
            (mock_r2_1, Mock(return_value=None)),
            (mock_r2_2, Mock(return_value=None))
        ]
        
        call_count = [0]
        def open_side_effect(filepath, flags):
            idx = call_count[0]
            call_count[0] += 1
            ctx = Mock()
            ctx.__enter__ = Mock(return_value=contexts[idx][0])
            ctx.__exit__ = contexts[idx][1]
            return ctx
        
        mock_open.side_effect = open_side_effect
        
        with open_r2pipe(sample_binary) as r2_1:
            assert r2_1 is mock_r2_1
            with open_r2pipe(sample_binary) as r2_2:
                assert r2_2 is mock_r2_2


def test_nested_r2_adapter_contexts(sample_binary):
    """Test multiple nested open_r2_adapter contexts."""
    with patch("r2pipe.open") as mock_open:
        mock_r2_1 = Mock(name="r2_1")
        mock_r2_2 = Mock(name="r2_2")
        
        contexts = [
            (mock_r2_1, Mock(return_value=None)),
            (mock_r2_2, Mock(return_value=None))
        ]
        
        call_count = [0]
        def open_side_effect(filepath, flags):
            idx = call_count[0]
            call_count[0] += 1
            ctx = Mock()
            ctx.__enter__ = Mock(return_value=contexts[idx][0])
            ctx.__exit__ = contexts[idx][1]
            return ctx
        
        mock_open.side_effect = open_side_effect
        
        with open_r2_adapter(sample_binary) as adapter1:
            from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
            assert isinstance(adapter1, R2PipeAdapter)
            
            with open_r2_adapter(sample_binary) as adapter2:
                assert isinstance(adapter2, R2PipeAdapter)


def test_multiple_flags_variations(sample_binary):
    """Test various flag combinations."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        # Test with multiple flags
        flags = ["-e", "io.cache=true", "-e", "bin.cache=true"]
        with open_r2pipe(sample_binary, flags=flags):
            pass
        
        mock_open.assert_called_with(sample_binary, flags=flags)


def test_r2_adapter_preserves_r2_instance(sample_binary):
    """Test that adapter preserves the r2 instance."""
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_r2.cmd = Mock(return_value="test result")
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2_adapter(sample_binary) as adapter:
            result = adapter.cmd("test")
            assert result == "test result"
            mock_r2.cmd.assert_called_once_with("test")
