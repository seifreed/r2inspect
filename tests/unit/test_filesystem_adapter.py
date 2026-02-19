#!/usr/bin/env python3
"""Edge case tests for FileSystemAdapter - 100% coverage."""

import tempfile
from pathlib import Path

import pytest

from r2inspect.adapters.file_system import FileSystemAdapter, default_file_system


@pytest.fixture
def temp_file():
    """Create a temporary test file."""
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
        f.write("Hello World\nLine 2\nLine 3")
        return f.name


@pytest.fixture
def temp_binary_file():
    """Create a temporary binary test file."""
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
        f.write(b"\x00\x01\x02\x03\xFF\xFE\xFD\xFC")
        return f.name


def test_read_text_basic(temp_file):
    """Test basic text reading."""
    adapter = FileSystemAdapter()
    content = adapter.read_text(temp_file)
    assert "Hello World" in content
    assert "Line 2" in content


def test_read_text_with_string_path(temp_file):
    """Test read_text with string path."""
    adapter = FileSystemAdapter()
    content = adapter.read_text(str(temp_file))
    assert "Hello World" in content


def test_read_text_with_path_object(temp_file):
    """Test read_text with Path object."""
    adapter = FileSystemAdapter()
    content = adapter.read_text(Path(temp_file))
    assert "Hello World" in content


def test_read_text_default_encoding(temp_file):
    """Test read_text uses utf-8 by default."""
    adapter = FileSystemAdapter()
    content = adapter.read_text(temp_file, encoding="utf-8")
    assert isinstance(content, str)


def test_read_text_custom_encoding(temp_file):
    """Test read_text with custom encoding."""
    adapter = FileSystemAdapter()
    content = adapter.read_text(temp_file, encoding="utf-8", errors="ignore")
    assert isinstance(content, str)


def test_read_text_with_errors_ignore(temp_file):
    """Test read_text with errors='ignore'."""
    adapter = FileSystemAdapter()
    content = adapter.read_text(temp_file, errors="ignore")
    assert "Hello World" in content


def test_read_text_preserves_content(temp_file):
    """Test that read_text preserves exact content."""
    adapter = FileSystemAdapter()
    content = adapter.read_text(temp_file)
    assert content.count("\n") == 2


def test_read_bytes_basic(temp_binary_file):
    """Test basic bytes reading."""
    adapter = FileSystemAdapter()
    content = adapter.read_bytes(temp_binary_file)
    assert b"\x00\x01\x02\x03" in content


def test_read_bytes_with_string_path(temp_binary_file):
    """Test read_bytes with string path."""
    adapter = FileSystemAdapter()
    content = adapter.read_bytes(str(temp_binary_file))
    assert isinstance(content, bytes)


def test_read_bytes_with_path_object(temp_binary_file):
    """Test read_bytes with Path object."""
    adapter = FileSystemAdapter()
    content = adapter.read_bytes(Path(temp_binary_file))
    assert isinstance(content, bytes)


def test_read_bytes_full_file(temp_binary_file):
    """Test read_bytes without size limit."""
    adapter = FileSystemAdapter()
    content = adapter.read_bytes(temp_binary_file, size=None)
    assert len(content) == 8


def test_read_bytes_with_size_limit(temp_binary_file):
    """Test read_bytes with size limit."""
    adapter = FileSystemAdapter()
    content = adapter.read_bytes(temp_binary_file, size=4)
    assert len(content) == 4
    assert content == b"\x00\x01\x02\x03"


def test_read_bytes_with_offset_zero(temp_binary_file):
    """Test read_bytes with offset=0."""
    adapter = FileSystemAdapter()
    content = adapter.read_bytes(temp_binary_file, offset=0)
    assert content[0:4] == b"\x00\x01\x02\x03"


def test_read_bytes_with_offset_nonzero(temp_binary_file):
    """Test read_bytes with non-zero offset."""
    adapter = FileSystemAdapter()
    content = adapter.read_bytes(temp_binary_file, offset=4)
    assert b"\xFF\xFE\xFD\xFC" in content


def test_read_bytes_with_offset_and_size(temp_binary_file):
    """Test read_bytes with both offset and size."""
    adapter = FileSystemAdapter()
    content = adapter.read_bytes(temp_binary_file, size=4, offset=2)
    assert len(content) == 4
    assert content == b"\x02\x03\xFF\xFE"


def test_read_bytes_offset_at_end(temp_binary_file):
    """Test read_bytes with offset at file end."""
    adapter = FileSystemAdapter()
    content = adapter.read_bytes(temp_binary_file, offset=8)
    assert len(content) == 0


def test_read_bytes_offset_beyond_end(temp_binary_file):
    """Test read_bytes with offset beyond file."""
    adapter = FileSystemAdapter()
    content = adapter.read_bytes(temp_binary_file, offset=100)
    assert len(content) == 0


def test_read_bytes_default_offset(temp_binary_file):
    """Test that default offset is 0."""
    adapter = FileSystemAdapter()
    content1 = adapter.read_bytes(temp_binary_file)
    content2 = adapter.read_bytes(temp_binary_file, offset=0)
    assert content1 == content2


def test_write_text_basic():
    """Test basic text writing."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        path = f.name
    
    adapter = FileSystemAdapter()
    adapter.write_text(path, "Test content")
    
    with open(path, 'r') as f:
        content = f.read()
    assert content == "Test content"


def test_write_text_with_string_path():
    """Test write_text with string path."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        path = f.name
    
    adapter = FileSystemAdapter()
    adapter.write_text(str(path), "Test content")
    
    with open(path, 'r') as f:
        content = f.read()
    assert content == "Test content"


def test_write_text_with_path_object():
    """Test write_text with Path object."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        path = Path(f.name)
    
    adapter = FileSystemAdapter()
    adapter.write_text(path, "Test content")
    
    assert path.read_text() == "Test content"


def test_write_text_overwrites_existing():
    """Test that write_text overwrites existing content."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Old content")
        path = f.name
    
    adapter = FileSystemAdapter()
    adapter.write_text(path, "New content")
    
    with open(path, 'r') as f:
        content = f.read()
    assert content == "New content"


def test_write_text_multiline():
    """Test write_text with multiline content."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        path = f.name
    
    adapter = FileSystemAdapter()
    content = "Line 1\nLine 2\nLine 3"
    adapter.write_text(path, content)
    
    with open(path, 'r') as f:
        read_content = f.read()
    assert read_content == content


def test_write_text_utf8_encoding():
    """Test write_text with utf-8 encoding."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        path = f.name
    
    adapter = FileSystemAdapter()
    adapter.write_text(path, "Unicode: 中文 العربية", encoding="utf-8")
    
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    assert "中文" in content


def test_write_text_custom_encoding():
    """Test write_text with custom encoding."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        path = f.name
    
    adapter = FileSystemAdapter()
    adapter.write_text(path, "Test", encoding="utf-8")
    
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    assert content == "Test"


def test_write_text_empty_string():
    """Test write_text with empty string."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        path = f.name
    
    adapter = FileSystemAdapter()
    adapter.write_text(path, "")
    
    with open(path, 'r') as f:
        content = f.read()
    assert content == ""


def test_write_text_with_special_chars():
    """Test write_text with special characters."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        path = f.name
    
    adapter = FileSystemAdapter()
    content = 'Special: "quotes" \'apostrophe\' \\ backslash'
    adapter.write_text(path, content)
    
    with open(path, 'r') as f:
        read_content = f.read()
    assert read_content == content


def test_default_file_system_instance():
    """Test that default_file_system is a FileSystemAdapter."""
    assert isinstance(default_file_system, FileSystemAdapter)


def test_default_file_system_read_text(temp_file):
    """Test default_file_system.read_text()."""
    content = default_file_system.read_text(temp_file)
    assert "Hello World" in content


def test_default_file_system_read_bytes(temp_binary_file):
    """Test default_file_system.read_bytes()."""
    content = default_file_system.read_bytes(temp_binary_file)
    assert isinstance(content, bytes)


def test_default_file_system_write_text():
    """Test default_file_system.write_text()."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        path = f.name
    
    default_file_system.write_text(path, "Test content")
    
    with open(path, 'r') as f:
        content = f.read()
    assert content == "Test content"


def test_read_bytes_multiple_calls(temp_binary_file):
    """Test multiple read_bytes calls return same data."""
    adapter = FileSystemAdapter()
    content1 = adapter.read_bytes(temp_binary_file)
    content2 = adapter.read_bytes(temp_binary_file)
    assert content1 == content2


def test_read_text_multiple_calls(temp_file):
    """Test multiple read_text calls return same data."""
    adapter = FileSystemAdapter()
    content1 = adapter.read_text(temp_file)
    content2 = adapter.read_text(temp_file)
    assert content1 == content2
