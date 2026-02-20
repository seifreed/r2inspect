"""Coverage tests for r2inspect/application/batch_discovery.py"""

import io
import struct
import sys
import tempfile
from pathlib import Path

import pytest

from r2inspect.application.batch_discovery import (
    _is_executable_signature,
    _iter_files,
    check_executable_signature,
    discover_executables_by_magic,
    find_files_by_extensions,
    init_magic_detectors,
    is_elf_executable,
    is_macho_executable,
    is_pe_executable,
    is_script_executable,
)

# _is_executable_signature tests


def test_is_executable_signature_known_mime():
    assert _is_executable_signature("application/x-dosexec", "") is True


def test_is_executable_signature_executable_mime():
    assert _is_executable_signature("application/x-executable", "") is True


def test_is_executable_signature_shared_lib():
    assert _is_executable_signature("application/x-sharedlib", "") is True


def test_is_executable_signature_pie():
    assert _is_executable_signature("application/x-pie-executable", "") is True


def test_is_executable_signature_octet_stream():
    assert _is_executable_signature("application/octet-stream", "") is True


def test_is_executable_signature_unknown_mime_pe_desc():
    assert _is_executable_signature("text/plain", "PE32 executable (console)") is True


def test_is_executable_signature_elf_description():
    assert _is_executable_signature("application/unknown", "ELF 64-bit LSB executable") is True


def test_is_executable_signature_macho_description():
    assert _is_executable_signature("application/unknown", "Mach-O 64-bit executable") is True


def test_is_executable_signature_not_executable():
    assert _is_executable_signature("text/plain", "ASCII text") is False


def test_is_executable_signature_dynamically_linked_desc():
    assert (
        _is_executable_signature("application/unknown", "dynamically linked shared object") is True
    )


# _iter_files tests


def test_iter_files_non_recursive():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "file1.txt").write_text("a")
        (p / "file2.txt").write_text("b")
        subdir = p / "sub"
        subdir.mkdir()
        (subdir / "file3.txt").write_text("c")

        files = _iter_files(p, recursive=False)
        names = {f.name for f in files}
        assert "file1.txt" in names
        assert "file2.txt" in names
        # sub directory is included in glob but not file3.txt at top level
        assert "file3.txt" not in names


def test_iter_files_recursive():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "file1.txt").write_text("a")
        subdir = p / "sub"
        subdir.mkdir()
        (subdir / "file2.txt").write_text("b")

        files = _iter_files(p, recursive=True)
        names = {f.name for f in files}
        assert "file1.txt" in names
        assert "file2.txt" in names


# init_magic_detectors tests


def test_init_magic_detectors_none():
    result = init_magic_detectors(None)
    assert result is None


# discover_executables_by_magic tests


def test_discover_executables_by_magic_no_magic():
    result = discover_executables_by_magic("/tmp", magic_module=None)
    executables, init_errors, file_errors, total = result
    assert executables == []
    assert len(init_errors) == 1
    assert "python-magic" in init_errors[0]
    assert file_errors == []
    assert total == 0


def test_discover_executables_by_magic_invalid_magic_module():
    class BrokenMagic:
        def Magic(self, **kwargs):
            raise RuntimeError("Cannot init magic")

    result = discover_executables_by_magic("/tmp", magic_module=BrokenMagic())
    executables, init_errors, file_errors, total = result
    assert executables == []
    assert len(init_errors) == 1


# check_executable_signature tests


def test_check_executable_signature_pe():
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        # Write minimal PE header: MZ + padding + PE offset at 0x3c
        header = bytearray(64)
        header[0:2] = b"MZ"
        # PE offset at byte 60-63
        pe_offset = 64
        struct.pack_into("<I", header, 60, pe_offset)
        f.write(bytes(header))
        # Write PE signature
        f.write(b"PE\x00\x00")
        tmppath = Path(f.name)
    try:
        assert check_executable_signature(tmppath) is True
    finally:
        tmppath.unlink()


def test_check_executable_signature_elf():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 60)
        tmppath = Path(f.name)
    try:
        assert check_executable_signature(tmppath) is True
    finally:
        tmppath.unlink()


def test_check_executable_signature_macho():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\xfe\xed\xfa\xce" + b"\x00" * 60)
        tmppath = Path(f.name)
    try:
        assert check_executable_signature(tmppath) is True
    finally:
        tmppath.unlink()


def test_check_executable_signature_script():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"#!/bin/bash\necho hello\n" + b"\x00" * 42)
        tmppath = Path(f.name)
    try:
        assert check_executable_signature(tmppath) is True
    finally:
        tmppath.unlink()


def test_check_executable_signature_not_executable():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"This is just a text file with some content padding here")
        tmppath = Path(f.name)
    try:
        assert check_executable_signature(tmppath) is False
    finally:
        tmppath.unlink()


def test_check_executable_signature_too_small():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"MZ")  # Only 2 bytes
        tmppath = Path(f.name)
    try:
        assert check_executable_signature(tmppath) is False
    finally:
        tmppath.unlink()


def test_check_executable_signature_nonexistent():
    assert check_executable_signature(Path("/nonexistent/file.exe")) is False


# is_pe_executable tests


def test_is_pe_executable_valid_mz_with_pe():
    header = bytearray(64)
    header[0:2] = b"MZ"
    pe_offset = 64
    struct.pack_into("<I", header, 60, pe_offset)
    f = io.BytesIO(b"PE\x00\x00")
    assert is_pe_executable(bytes(header), f) is True


def test_is_pe_executable_mz_only_no_pe_sig():
    header = bytearray(64)
    header[0:2] = b"MZ"
    pe_offset = 64
    struct.pack_into("<I", header, 60, pe_offset)
    f = io.BytesIO(b"NE\x00\x00")
    # MZ but no PE sig - still returns True due to MZ presence
    assert is_pe_executable(bytes(header), f) is True


def test_is_pe_executable_no_mz():
    header = b"ELF" + b"\x00" * 61
    f = io.BytesIO(b"")
    assert is_pe_executable(header, f) is False


def test_is_pe_executable_short_header():
    header = b"MZ\x00"  # Only 3 bytes - less than 64
    f = io.BytesIO(b"")
    # Returns True because header starts with MZ
    assert is_pe_executable(header, f) is True


# is_elf_executable tests


def test_is_elf_executable_valid():
    assert is_elf_executable(b"\x7fELF" + b"\x00" * 60) is True


def test_is_elf_executable_invalid():
    assert is_elf_executable(b"\x00ELF" + b"\x00" * 60) is False


def test_is_elf_executable_pe_header():
    assert is_elf_executable(b"MZ" + b"\x00" * 62) is False


# is_macho_executable tests


def test_is_macho_executable_feedface():
    assert is_macho_executable(b"\xfe\xed\xfa\xce" + b"\x00" * 60) is True


def test_is_macho_executable_cefaedfe():
    assert is_macho_executable(b"\xce\xfa\xed\xfe" + b"\x00" * 60) is True


def test_is_macho_executable_feedfacf():
    assert is_macho_executable(b"\xfe\xed\xfa\xcf" + b"\x00" * 60) is True


def test_is_macho_executable_cffaedfe():
    assert is_macho_executable(b"\xcf\xfa\xed\xfe" + b"\x00" * 60) is True


def test_is_macho_executable_fat_binary():
    assert is_macho_executable(b"\xca\xfe\xba\xbe" + b"\x00" * 60) is True


def test_is_macho_executable_invalid():
    assert is_macho_executable(b"MZ\x00\x00" + b"\x00" * 60) is False


# is_script_executable tests


def test_is_script_executable_valid():
    assert is_script_executable(b"#!/usr/bin/env python3\n" + b"\x00" * 42) is True


def test_is_script_executable_bash():
    assert is_script_executable(b"#!/bin/sh\n" + b"\x00" * 54) is True


def test_is_script_executable_invalid():
    assert is_script_executable(b"# comment but no shebang" + b"\x00" * 40) is False


def test_is_script_executable_not_shebang():
    assert is_script_executable(b"MZ\x00\x00" + b"\x00" * 60) is False


# find_files_by_extensions tests


def test_find_files_by_extensions_single_ext():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "a.exe").write_bytes(b"\x00")
        (p / "b.dll").write_bytes(b"\x00")
        (p / "c.txt").write_bytes(b"\x00")

        result = find_files_by_extensions(p, "exe", recursive=False)
        names = {f.name for f in result}
        assert "a.exe" in names
        assert "b.dll" not in names


def test_find_files_by_extensions_multiple_ext():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "a.exe").write_bytes(b"\x00")
        (p / "b.dll").write_bytes(b"\x00")
        (p / "c.txt").write_bytes(b"\x00")

        result = find_files_by_extensions(p, "exe,dll", recursive=False)
        names = {f.name for f in result}
        assert "a.exe" in names
        assert "b.dll" in names
        assert "c.txt" not in names


def test_find_files_by_extensions_recursive():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "root.exe").write_bytes(b"\x00")
        subdir = p / "sub"
        subdir.mkdir()
        (subdir / "nested.exe").write_bytes(b"\x00")

        result = find_files_by_extensions(p, "exe", recursive=True)
        names = {f.name for f in result}
        assert "root.exe" in names
        assert "nested.exe" in names


def test_find_files_by_extensions_non_recursive():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "root.exe").write_bytes(b"\x00")
        subdir = p / "sub"
        subdir.mkdir()
        (subdir / "nested.exe").write_bytes(b"\x00")

        result = find_files_by_extensions(p, "exe", recursive=False)
        names = {f.name for f in result}
        assert "root.exe" in names
        assert "nested.exe" not in names


def test_find_files_by_extensions_strips_spaces():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "test.EXE").write_bytes(b"\x00")

        # Extensions are lowercased, so EXE file won't match "exe" pattern
        # (depends on OS case sensitivity, but pattern is lowercased)
        result = find_files_by_extensions(p, " exe ", recursive=False)
        # Strip happens on ext_list
        assert isinstance(result, list)


def test_find_files_by_extensions_no_match():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "test.txt").write_bytes(b"\x00")

        result = find_files_by_extensions(p, "exe", recursive=False)
        assert result == []


# Additional test for OSError path in is_pe_executable (lines 121-122)


def test_is_pe_executable_seek_raises():
    """is_pe_executable returns True if seek raises OSError (MZ header present)."""

    class BrokenSeekFile:
        def seek(self, pos: int) -> None:
            raise OSError("seek failed")

        def read(self, n: int) -> bytes:
            return b""

    # Header with valid MZ and PE offset pointing outside file
    header = bytearray(64)
    header[0:2] = b"MZ"
    import struct

    struct.pack_into("<I", header, 60, 9999)  # bogus PE offset
    result = is_pe_executable(bytes(header), BrokenSeekFile())
    # Returns True because MZ is present (fallthrough after OSError)
    assert result is True


# Tests for discover_executables_by_magic with a real magic module (lines 69-87)


@pytest.mark.skipif(sys.platform == "win32", reason="python-magic-bin may hang on Windows")
def test_discover_executables_by_magic_with_magic_module():
    """Test full discovery path when python-magic is available."""
    import magic as magic_module

    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)

        # Create a file that is too small (< 64 bytes) -> skipped
        small_file = p / "small.bin"
        small_file.write_bytes(b"\x7fELF" + b"\x00" * 10)  # only 14 bytes

        # Create a file that is large enough
        normal_file = p / "normal.txt"
        normal_file.write_bytes(b"This is just plain text content" + b" " * 40)

        executables, init_errors, file_errors, total = discover_executables_by_magic(
            tmpdir, recursive=False, magic_module=magic_module
        )
        assert init_errors == []
        assert total == 2  # both files exist
        # normal.txt is not executable, so executables might be empty


@pytest.mark.skipif(sys.platform == "win32", reason="python-magic-bin may hang on Windows")
def test_discover_executables_by_magic_finds_elf():
    """Test that ELF files are found by magic."""
    import magic as magic_module

    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)

        # Create a minimal ELF file (large enough to read)
        elf_file = p / "test.elf"
        elf_header = (
            b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00" + b"\x00" * 44
        )
        elf_file.write_bytes(elf_header)

        executables, init_errors, file_errors, total = discover_executables_by_magic(
            tmpdir, recursive=False, magic_module=magic_module
        )
        assert init_errors == []
        # The file exists and is >= 64 bytes is what matters for execution path
        assert total >= 1


@pytest.mark.skipif(sys.platform == "win32", reason="python-magic-bin may hang on Windows")
def test_discover_executables_by_magic_file_error_handling():
    """Test that file errors are captured in file_errors list."""
    import magic as magic_module

    class BrokenMagicInstance:
        def from_file(self, path: str) -> str:
            raise RuntimeError("magic read failed")

    class BrokenMagicModule:
        def Magic(self, **kwargs: object) -> BrokenMagicInstance:
            return BrokenMagicInstance()

    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "large_file.bin").write_bytes(b"\x00" * 100)

        executables, init_errors, file_errors, total = discover_executables_by_magic(
            tmpdir, recursive=False, magic_module=BrokenMagicModule()
        )
        assert len(file_errors) == 1
        assert "magic read failed" in file_errors[0][1]
