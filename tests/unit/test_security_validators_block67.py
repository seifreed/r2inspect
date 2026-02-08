from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.security.validators import FileValidator, validate_file_for_analysis


def test_file_validator_basic_path_checks():
    validator = FileValidator()

    with pytest.raises(ValueError):
        validator._validate_basic_path("")

    with pytest.raises(ValueError):
        validator._validate_basic_path("\x00bad")

    with pytest.raises(ValueError):
        validator._validate_basic_path("a" * (validator.MAX_PATH_LENGTH + 1))

    with pytest.raises(ValueError):
        validator.validate_path("bad;name", check_exists=False)


def test_file_validator_allowed_directory(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    good = allowed / "file.bin"
    good.write_text("ok")

    validator = FileValidator(allowed_directory=allowed)
    resolved = validator.validate_path(str(good))
    assert resolved == good.resolve()

    outside = tmp_path / "outside.txt"
    outside.write_text("no")
    with pytest.raises(ValueError):
        validator.validate_path(str(outside))


def test_sanitize_for_subprocess(tmp_path: Path):
    file_path = tmp_path / "file.bin"
    file_path.write_text("ok")
    validator = FileValidator()
    resolved = validator.validate_path(str(file_path))
    assert validator.sanitize_for_subprocess(resolved) == str(resolved.absolute())

    with pytest.raises(TypeError):
        validator.sanitize_for_subprocess(str(file_path))  # type: ignore[arg-type]


def test_validate_yara_rule_content_errors():
    validator = FileValidator()

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("")

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("A" * 5, max_size=1)

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content('include "bad.yar"')

    too_complex = "rule x { condition: " + ("*" * 10001) + " }"
    with pytest.raises(ValueError):
        validator.validate_yara_rule_content(too_complex)

    long_line = "a" * 10001
    with pytest.raises(ValueError):
        validator.validate_yara_rule_content(f"rule x {{ condition: true }}\n{long_line}")


def test_validate_file_for_analysis(tmp_path: Path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(ValueError):
        validate_file_for_analysis(str(empty))

    data = tmp_path / "data.bin"
    data.write_bytes(b"hello")

    with pytest.raises(ValueError):
        validate_file_for_analysis(str(data), max_size=1)

    validated = validate_file_for_analysis(str(data), max_size=1024)
    assert validated == data.resolve()
