"""Branch-path tests for r2inspect/security/validators.py."""

from __future__ import annotations

import socket
import tempfile
from pathlib import Path

import pytest

from r2inspect.security.validators import FileValidator, validate_file_for_analysis


# ---------------------------------------------------------------------------
# FileValidator.__init__ with invalid allowed_directory
# ---------------------------------------------------------------------------


def test_init_with_nonexistent_allowed_directory_raises():
    with pytest.raises(ValueError, match="Invalid allowed directory"):
        FileValidator(allowed_directory=Path("/this/path/does/not/exist/ever"))


def test_init_with_valid_allowed_directory_resolves_it(tmp_path: Path):
    v = FileValidator(allowed_directory=tmp_path)
    assert v.allowed_directory == tmp_path.resolve()


def test_init_without_allowed_directory_leaves_none():
    v = FileValidator()
    assert v.allowed_directory is None


# ---------------------------------------------------------------------------
# _validate_basic_path branches
# ---------------------------------------------------------------------------


def test_validate_path_empty_string_raises():
    v = FileValidator()
    with pytest.raises(ValueError, match="cannot be empty"):
        v.validate_path("")


def test_validate_path_exceeds_max_length_raises():
    v = FileValidator()
    long_path = "a" * (v.MAX_PATH_LENGTH + 1)
    with pytest.raises(ValueError, match="exceeds maximum"):
        v.validate_path(long_path)


def test_validate_path_null_byte_raises():
    v = FileValidator()
    with pytest.raises(ValueError, match="null byte"):
        v.validate_path("some\x00path")


def test_validate_path_dangerous_characters_raises():
    v = FileValidator()
    with pytest.raises(ValueError, match="dangerous characters"):
        v.validate_path("file;name.txt")


# ---------------------------------------------------------------------------
# _resolve_path with check_exists=False and True
# ---------------------------------------------------------------------------


def test_validate_path_check_exists_false_resolves_nonexistent(tmp_path: Path):
    v = FileValidator()
    ghost = tmp_path / "ghost.bin"
    # File does not exist but check_exists=False should succeed
    result = v.validate_path(str(ghost), check_exists=False)
    assert result == ghost.resolve()


def test_validate_path_check_exists_true_on_existing_file(tmp_path: Path):
    v = FileValidator()
    real_file = tmp_path / "real.txt"
    real_file.write_text("data")
    result = v.validate_path(str(real_file), check_exists=True)
    assert result == real_file.resolve()


def test_validate_path_check_exists_true_on_missing_file_raises(tmp_path: Path):
    v = FileValidator()
    with pytest.raises(ValueError, match="resolution failed|does not exist|No such file"):
        v.validate_path(str(tmp_path / "missing.txt"), check_exists=True)


# ---------------------------------------------------------------------------
# _validate_allowed_directory - path outside allowed dir
# ---------------------------------------------------------------------------


def test_validate_path_outside_allowed_directory_raises(tmp_path: Path):
    subdir = tmp_path / "allowed"
    subdir.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    v = FileValidator(allowed_directory=subdir)
    with pytest.raises(ValueError, match="outside allowed directory"):
        v.validate_path(str(outside))


def test_validate_path_inside_allowed_directory_succeeds(tmp_path: Path):
    subdir = tmp_path / "allowed"
    subdir.mkdir()
    good = subdir / "file.txt"
    good.write_text("ok")
    v = FileValidator(allowed_directory=subdir)
    result = v.validate_path(str(good))
    assert result == good.resolve()


# ---------------------------------------------------------------------------
# _validate_existing_path - check_exists=False early return
# ---------------------------------------------------------------------------


def test_validate_existing_path_not_called_when_check_exists_false(tmp_path: Path):
    v = FileValidator()
    nonexistent = tmp_path / "nope.bin"
    # Should not raise even though path doesn't exist
    result = v.validate_path(str(nonexistent), check_exists=False)
    assert not result.exists()


# ---------------------------------------------------------------------------
# _validate_existing_path - special file (socket)
# ---------------------------------------------------------------------------


def test_validate_existing_path_socket_raises():
    import tempfile
    import os
    # Use a short path in /tmp to avoid AF_UNIX path length limit (108 chars on macOS)
    short_dir = tempfile.mkdtemp(prefix="/tmp/r2t_")
    sock_path = Path(short_dir) / "s.sock"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(sock_path))
        v = FileValidator()
        with pytest.raises(ValueError, match="not a regular file or directory"):
            v.validate_path(str(sock_path), check_exists=True)
    finally:
        sock.close()
        if sock_path.exists():
            sock_path.unlink()
        os.rmdir(short_dir)


# ---------------------------------------------------------------------------
# sanitize_for_subprocess
# ---------------------------------------------------------------------------


def test_sanitize_for_subprocess_returns_absolute_string(tmp_path: Path):
    v = FileValidator()
    real_file = tmp_path / "ok.txt"
    real_file.write_text("ok")
    safe = v.sanitize_for_subprocess(real_file)
    assert isinstance(safe, str)
    assert safe.startswith("/")


def test_sanitize_for_subprocess_non_path_raises_type_error(tmp_path: Path):
    v = FileValidator()
    with pytest.raises(TypeError):
        v.sanitize_for_subprocess("not_a_path")  # type: ignore[arg-type]


def test_sanitize_for_subprocess_dangerous_path_raises(tmp_path: Path):
    v = FileValidator()
    dangerous = tmp_path / "bad$file.txt"
    with pytest.raises(ValueError, match="dangerous characters"):
        v.sanitize_for_subprocess(dangerous)


# ---------------------------------------------------------------------------
# validate_yara_rule_content
# ---------------------------------------------------------------------------


def test_validate_yara_rule_content_empty_raises():
    v = FileValidator()
    with pytest.raises(ValueError, match="cannot be empty"):
        v.validate_yara_rule_content("")


def test_validate_yara_rule_content_too_large_raises():
    v = FileValidator()
    big = "x" * (10 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="exceeds maximum size"):
        v.validate_yara_rule_content(big)


def test_validate_yara_rule_content_dangerous_include_raises():
    v = FileValidator()
    with pytest.raises(ValueError, match="dangerous pattern"):
        v.validate_yara_rule_content('include "bad_file.yar"')


def test_validate_yara_rule_content_non_standard_import_raises():
    v = FileValidator()
    with pytest.raises(ValueError, match="dangerous pattern"):
        v.validate_yara_rule_content('import "shellcode_loader"')


def test_validate_yara_rule_content_standard_import_pe_ok():
    v = FileValidator()
    # pe is a known safe import - should not raise
    v.validate_yara_rule_content('import "pe"\nrule test { condition: pe.is_pe }')


def test_validate_yara_rule_content_line_too_long_raises():
    v = FileValidator()
    long_line = "x" * 10001
    with pytest.raises(ValueError, match="exceeds maximum length"):
        v.validate_yara_rule_content(long_line)


def test_validate_yara_rule_content_valid_rule_passes():
    v = FileValidator()
    good = "rule test_rule { strings: $a = {4D 5A} condition: $a }"
    v.validate_yara_rule_content(good)


# ---------------------------------------------------------------------------
# validate_file_for_analysis
# ---------------------------------------------------------------------------


def test_validate_file_for_analysis_existing_file_returns_path(tmp_path: Path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x4d\x5a\x00")
    result = validate_file_for_analysis(str(f))
    assert result == f.resolve()


def test_validate_file_for_analysis_with_allowed_directory(tmp_path: Path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x4d\x5a\x00")
    result = validate_file_for_analysis(str(f), allowed_directory=str(tmp_path))
    assert result == f.resolve()


def test_validate_file_for_analysis_empty_file_raises(tmp_path: Path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        validate_file_for_analysis(str(empty))


def test_validate_file_for_analysis_file_too_large_raises(tmp_path: Path):
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 10)
    with pytest.raises(ValueError, match="too large"):
        validate_file_for_analysis(str(big), max_size=5)


def test_validate_file_for_analysis_missing_file_raises(tmp_path: Path):
    with pytest.raises(ValueError):
        validate_file_for_analysis(str(tmp_path / "missing.bin"))
