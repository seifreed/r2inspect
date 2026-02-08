from __future__ import annotations

import os
from pathlib import Path

import pytest

from r2inspect.security.validators import FileValidator


def test_validate_path_basic_and_allowed_directory(tmp_path: Path):
    validator = FileValidator(allowed_directory=tmp_path)
    good_file = tmp_path / "good.txt"
    good_file.write_text("ok")

    resolved = validator.validate_path(str(good_file))
    assert resolved == good_file.resolve()

    other_dir = tmp_path.parent
    outside = other_dir / "outside.txt"
    outside.write_text("x")
    with pytest.raises(ValueError):
        validator.validate_path(str(outside))


def test_validate_path_errors(tmp_path: Path):
    validator = FileValidator()

    with pytest.raises(ValueError):
        validator.validate_path("")

    with pytest.raises(ValueError):
        validator.validate_path("\x00")

    with pytest.raises(ValueError):
        validator.validate_path("bad;name")

    long_path = "a" * (validator.MAX_PATH_LENGTH + 1)
    with pytest.raises(ValueError):
        validator.validate_path(long_path)

    missing = tmp_path / "missing.txt"
    with pytest.raises(ValueError):
        validator.validate_path(str(missing), check_exists=True)


def test_sanitize_for_subprocess(tmp_path: Path):
    validator = FileValidator()

    good_file = tmp_path / "ok.txt"
    good_file.write_text("ok")
    safe = validator.sanitize_for_subprocess(good_file)
    assert os.path.isabs(safe)

    with pytest.raises(TypeError):
        validator.sanitize_for_subprocess("not-a-path")

    bad_path = tmp_path / "bad$.txt"
    with pytest.raises(ValueError):
        validator.sanitize_for_subprocess(bad_path)
