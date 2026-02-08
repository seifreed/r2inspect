from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.security.validators import FileValidator, validate_file_for_analysis


def test_file_validator_basic(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_text("x")
    validator = FileValidator(allowed_directory=tmp_path)
    resolved = validator.validate_path(str(file_path))
    assert resolved == file_path.resolve()
    assert validator.sanitize_for_subprocess(resolved).endswith("sample.bin")


def test_file_validator_rejects_dangerous() -> None:
    validator = FileValidator()
    with pytest.raises(ValueError):
        validator.validate_path("bad;rm -rf /")
    with pytest.raises(TypeError):
        validator.sanitize_for_subprocess("not-a-path")  # type: ignore[arg-type]


def test_file_validator_allowed_directory(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    validator = FileValidator(allowed_directory=allowed)
    with pytest.raises(ValueError):
        validator.validate_path(str(outside))


def test_validate_yara_rule_content() -> None:
    validator = FileValidator()
    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("")
    with pytest.raises(ValueError):
        validator.validate_yara_rule_content('include "evil.yar"')
    with pytest.raises(ValueError):
        validator.validate_yara_rule_content('import "badmod"')
    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("rule r { condition: " + ("*" * 10001) + " }")
    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("rule r {\n" + ("a" * 10001) + "\n}")


def test_validate_file_for_analysis(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_text("x")
    validated = validate_file_for_analysis(str(file_path), allowed_directory=str(tmp_path))
    assert validated == file_path.resolve()

    empty_path = tmp_path / "empty.bin"
    empty_path.write_text("")
    with pytest.raises(ValueError):
        validate_file_for_analysis(str(empty_path), allowed_directory=str(tmp_path))
