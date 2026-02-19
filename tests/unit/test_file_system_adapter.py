#!/usr/bin/env python3
"""Comprehensive tests for file_system.py to achieve 95%+ coverage."""

import os
import tempfile
from pathlib import Path

import pytest

from r2inspect.adapters.file_system import FileSystemAdapter, default_file_system


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def test_read_bytes_basic(temp_dir):
    test_file = temp_dir / "test.bin"
    test_data = b"Hello, World!"
    test_file.write_bytes(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_bytes(test_file)
    
    assert result == test_data


def test_read_bytes_with_path_object(temp_dir):
    test_file = temp_dir / "test.bin"
    test_data = b"\x00\x01\x02\x03\x04"
    test_file.write_bytes(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_bytes(Path(test_file))
    
    assert result == test_data


def test_read_bytes_with_string_path(temp_dir):
    test_file = temp_dir / "test.bin"
    test_data = b"binary data"
    test_file.write_bytes(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_bytes(str(test_file))
    
    assert result == test_data


def test_read_bytes_with_size(temp_dir):
    test_file = temp_dir / "test.bin"
    test_data = b"0123456789"
    test_file.write_bytes(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_bytes(test_file, size=5)
    
    assert result == b"01234"


def test_read_bytes_with_offset(temp_dir):
    test_file = temp_dir / "test.bin"
    test_data = b"0123456789"
    test_file.write_bytes(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_bytes(test_file, offset=5)
    
    assert result == b"56789"


def test_read_bytes_with_size_and_offset(temp_dir):
    test_file = temp_dir / "test.bin"
    test_data = b"0123456789ABCDEF"
    test_file.write_bytes(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_bytes(test_file, size=4, offset=6)
    
    assert result == b"6789"


def test_read_bytes_zero_offset(temp_dir):
    test_file = temp_dir / "test.bin"
    test_data = b"test"
    test_file.write_bytes(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_bytes(test_file, offset=0)
    
    assert result == test_data


def test_read_bytes_empty_file(temp_dir):
    test_file = temp_dir / "empty.bin"
    test_file.write_bytes(b"")
    
    adapter = FileSystemAdapter()
    result = adapter.read_bytes(test_file)
    
    assert result == b""


def test_read_text_basic(temp_dir):
    test_file = temp_dir / "test.txt"
    test_data = "Hello, World!"
    test_file.write_text(test_data, encoding="utf-8")
    
    adapter = FileSystemAdapter()
    result = adapter.read_text(test_file)
    
    assert result == test_data


def test_read_text_with_path_object(temp_dir):
    test_file = temp_dir / "test.txt"
    test_data = "Text content"
    test_file.write_text(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_text(Path(test_file))
    
    assert result == test_data


def test_read_text_with_string_path(temp_dir):
    test_file = temp_dir / "test.txt"
    test_data = "String path test"
    test_file.write_text(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_text(str(test_file))
    
    assert result == test_data


def test_read_text_with_encoding(temp_dir):
    test_file = temp_dir / "test.txt"
    test_data = "UTF-8 text"
    test_file.write_text(test_data, encoding="utf-8")
    
    adapter = FileSystemAdapter()
    result = adapter.read_text(test_file, encoding="utf-8")
    
    assert result == test_data


def test_read_text_with_errors_ignore(temp_dir):
    test_file = temp_dir / "test.txt"
    test_file.write_bytes(b"valid\xfftext")
    
    adapter = FileSystemAdapter()
    result = adapter.read_text(test_file, errors="ignore")
    
    assert "valid" in result
    assert "text" in result


def test_read_text_default_errors(temp_dir):
    test_file = temp_dir / "test.txt"
    test_file.write_bytes(b"test\xffdata")
    
    adapter = FileSystemAdapter()
    result = adapter.read_text(test_file)
    
    assert isinstance(result, str)


def test_read_text_unicode(temp_dir):
    test_file = temp_dir / "test.txt"
    test_data = "Unicode: 你好 🎉"
    test_file.write_text(test_data, encoding="utf-8")
    
    adapter = FileSystemAdapter()
    result = adapter.read_text(test_file, encoding="utf-8")
    
    assert result == test_data


def test_read_text_multiline(temp_dir):
    test_file = temp_dir / "test.txt"
    test_data = "Line 1\nLine 2\nLine 3"
    test_file.write_text(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_text(test_file)
    
    assert result == test_data


def test_write_text_basic(temp_dir):
    test_file = temp_dir / "output.txt"
    test_data = "Output data"
    
    adapter = FileSystemAdapter()
    adapter.write_text(test_file, test_data)
    
    assert test_file.read_text() == test_data


def test_write_text_with_path_object(temp_dir):
    test_file = temp_dir / "output.txt"
    test_data = "Path object write"
    
    adapter = FileSystemAdapter()
    adapter.write_text(Path(test_file), test_data)
    
    assert test_file.read_text() == test_data


def test_write_text_with_string_path(temp_dir):
    test_file = temp_dir / "output.txt"
    test_data = "String path write"
    
    adapter = FileSystemAdapter()
    adapter.write_text(str(test_file), test_data)
    
    assert test_file.read_text() == test_data


def test_write_text_with_encoding(temp_dir):
    test_file = temp_dir / "output.txt"
    test_data = "UTF-8 output"
    
    adapter = FileSystemAdapter()
    adapter.write_text(test_file, test_data, encoding="utf-8")
    
    assert test_file.read_text(encoding="utf-8") == test_data


def test_write_text_unicode(temp_dir):
    test_file = temp_dir / "output.txt"
    test_data = "Unicode write: 你好 世界"
    
    adapter = FileSystemAdapter()
    adapter.write_text(test_file, test_data, encoding="utf-8")
    
    assert test_file.read_text(encoding="utf-8") == test_data


def test_write_text_overwrite(temp_dir):
    test_file = temp_dir / "output.txt"
    
    adapter = FileSystemAdapter()
    adapter.write_text(test_file, "First")
    adapter.write_text(test_file, "Second")
    
    assert test_file.read_text() == "Second"


def test_write_text_empty(temp_dir):
    test_file = temp_dir / "output.txt"
    
    adapter = FileSystemAdapter()
    adapter.write_text(test_file, "")
    
    assert test_file.read_text() == ""


def test_write_text_multiline(temp_dir):
    test_file = temp_dir / "output.txt"
    test_data = "Line 1\nLine 2\nLine 3"
    
    adapter = FileSystemAdapter()
    adapter.write_text(test_file, test_data)
    
    assert test_file.read_text() == test_data


def test_default_file_system_instance():
    assert isinstance(default_file_system, FileSystemAdapter)


def test_default_file_system_read(temp_dir):
    test_file = temp_dir / "test.txt"
    test_data = "Default instance test"
    test_file.write_text(test_data)
    
    result = default_file_system.read_text(test_file)
    
    assert result == test_data


def test_default_file_system_write(temp_dir):
    test_file = temp_dir / "output.txt"
    test_data = "Default write"
    
    default_file_system.write_text(test_file, test_data)
    
    assert test_file.read_text() == test_data


def test_read_bytes_large_file(temp_dir):
    test_file = temp_dir / "large.bin"
    test_data = b"\x00" * 1024 * 1024
    test_file.write_bytes(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_bytes(test_file)
    
    assert len(result) == 1024 * 1024


def test_read_bytes_partial_large_file(temp_dir):
    test_file = temp_dir / "large.bin"
    test_data = b"\xFF" * 1024 * 1024
    test_file.write_bytes(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_bytes(test_file, size=1024)
    
    assert len(result) == 1024
    assert result == b"\xFF" * 1024


def test_roundtrip_text(temp_dir):
    test_file = temp_dir / "roundtrip.txt"
    test_data = "Roundtrip test data"
    
    adapter = FileSystemAdapter()
    adapter.write_text(test_file, test_data)
    result = adapter.read_text(test_file)
    
    assert result == test_data


def test_roundtrip_bytes(temp_dir):
    test_file = temp_dir / "roundtrip.bin"
    test_data = b"\x00\x01\x02\x03\x04\x05"
    test_file.write_bytes(test_data)
    
    adapter = FileSystemAdapter()
    result = adapter.read_bytes(test_file)
    
    assert result == test_data
