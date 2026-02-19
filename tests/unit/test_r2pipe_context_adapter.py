#!/usr/bin/env python3
"""Comprehensive tests for r2pipe_context.py to achieve 95%+ coverage."""

import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from r2inspect.adapters.r2pipe_context import open_r2pipe, open_r2_adapter
from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter


@pytest.fixture
def sample_binary(tmp_path):
    binary = tmp_path / "test.bin"
    binary.write_bytes(b"\x7fELF\x00\x00\x00\x00" + b"\x00" * 100)
    return str(binary)


def test_open_r2pipe_basic(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2pipe(sample_binary) as r2:
            assert r2 == mock_r2
        
        mock_open.assert_called_once_with(sample_binary, flags=["-2"])


def test_open_r2pipe_with_custom_flags(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        custom_flags = ["-e", "bin.cache=true"]
        
        with open_r2pipe(sample_binary, flags=custom_flags) as r2:
            assert r2 == mock_r2
        
        mock_open.assert_called_once_with(sample_binary, flags=custom_flags)


def test_open_r2pipe_with_none_flags(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2pipe(sample_binary, flags=None) as r2:
            assert r2 == mock_r2
        
        mock_open.assert_called_once_with(sample_binary, flags=["-2"])


def test_open_r2pipe_cleanup(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_exit = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=Mock())
        mock_open.return_value.__exit__ = mock_exit
        
        with open_r2pipe(sample_binary):
            pass
        
        assert mock_exit.called


def test_open_r2pipe_exception_handling(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_r2.cmd.side_effect = Exception("r2pipe error")
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with pytest.raises(Exception, match="r2pipe error"):
            with open_r2pipe(sample_binary) as r2:
                r2.cmd("test")


def test_open_r2_adapter_basic(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2_adapter(sample_binary) as adapter:
            assert isinstance(adapter, R2PipeAdapter)
            assert adapter.r2 == mock_r2


def test_open_r2_adapter_with_flags(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        custom_flags = ["-e", "io.cache=true"]
        
        with open_r2_adapter(sample_binary, flags=custom_flags) as adapter:
            assert isinstance(adapter, R2PipeAdapter)
        
        mock_open.assert_called_once_with(sample_binary, flags=custom_flags)


def test_open_r2_adapter_with_none_flags(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2_adapter(sample_binary, flags=None) as adapter:
            assert isinstance(adapter, R2PipeAdapter)
        
        mock_open.assert_called_once_with(sample_binary, flags=["-2"])


def test_open_r2_adapter_cleanup(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_exit = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=Mock())
        mock_open.return_value.__exit__ = mock_exit
        
        with open_r2_adapter(sample_binary):
            pass
        
        assert mock_exit.called


def test_open_r2_adapter_operations(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_r2.cmdj.return_value = {"test": "data"}
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with open_r2_adapter(sample_binary) as adapter:
            result = adapter.cmdj("ij")
            assert result == {"test": "data"}


def test_open_r2_adapter_exception_propagation(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_r2 = Mock()
        mock_r2.cmdj.side_effect = RuntimeError("adapter error")
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = Mock(return_value=None)
        
        with pytest.raises(RuntimeError, match="adapter error"):
            with open_r2_adapter(sample_binary) as adapter:
                adapter.cmdj("ij")


def test_nested_context_managers(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_r2_1 = Mock()
        mock_r2_2 = Mock()
        
        call_count = [0]
        
        def open_side_effect(filepath, flags):
            call_count[0] += 1
            if call_count[0] == 1:
                ctx = MagicMock()
                ctx.__enter__ = Mock(return_value=mock_r2_1)
                ctx.__exit__ = Mock(return_value=None)
                return ctx
            else:
                ctx = MagicMock()
                ctx.__enter__ = Mock(return_value=mock_r2_2)
                ctx.__exit__ = Mock(return_value=None)
                return ctx
        
        mock_open.side_effect = open_side_effect
        
        with open_r2pipe(sample_binary) as r2_1:
            assert r2_1 == mock_r2_1
            with open_r2pipe(sample_binary) as r2_2:
                assert r2_2 == mock_r2_2


def test_context_manager_cleanup_on_exception(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_exit = Mock()
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = mock_exit
        
        try:
            with open_r2pipe(sample_binary):
                raise ValueError("test exception")
        except ValueError:
            pass
        
        assert mock_exit.called


def test_open_r2_adapter_resource_management(sample_binary):
    with patch("r2pipe.open") as mock_open:
        mock_exit = Mock()
        mock_r2 = Mock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_r2)
        mock_open.return_value.__exit__ = mock_exit
        
        adapter_ref = None
        with open_r2_adapter(sample_binary) as adapter:
            adapter_ref = adapter
            assert adapter.r2 == mock_r2
        
        assert mock_exit.called
