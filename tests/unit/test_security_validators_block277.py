from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.security.validators import FileValidator


@pytest.mark.unit
def test_file_validator_basic_and_dangerous_chars(tmp_path: Path) -> None:
    validator = FileValidator()
    sample = tmp_path / "sample.bin"
    sample.write_text("data")

    resolved = validator.validate_path(str(sample), check_exists=True)
    assert resolved == sample.resolve()

    with pytest.raises(ValueError):
        validator.validate_path("", check_exists=False)

    with pytest.raises(ValueError):
        validator.validate_path("bad;name", check_exists=False)


@pytest.mark.unit
def test_file_validator_allowed_directory(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    inside = allowed / "file.bin"
    inside.write_text("ok")

    validator = FileValidator(allowed_directory=allowed)
    assert validator.validate_path(str(inside), check_exists=True) == inside.resolve()

    outside = tmp_path / "outside.bin"
    outside.write_text("no")
    with pytest.raises(ValueError):
        validator.validate_path(str(outside), check_exists=True)


@pytest.mark.unit
def test_file_validator_sanitize_for_subprocess(tmp_path: Path) -> None:
    validator = FileValidator()
    sample = tmp_path / "sample.bin"
    sample.write_text("data")

    resolved = validator.validate_path(str(sample), check_exists=True)
    safe = validator.sanitize_for_subprocess(resolved)
    assert str(sample.resolve()) == safe

    with pytest.raises(TypeError):
        validator.sanitize_for_subprocess("not a path")  # type: ignore[arg-type]
