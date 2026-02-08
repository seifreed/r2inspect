from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.security.validators import FileValidator, validate_file_for_analysis


def test_file_validator_paths(tmp_path: Path) -> None:
    validator = FileValidator(allowed_directory=tmp_path)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    resolved = validator.validate_path(str(sample))
    assert resolved == sample.resolve()
    assert validator.sanitize_for_subprocess(resolved)

    with pytest.raises(ValueError):
        validator.validate_path("")

    with pytest.raises(ValueError):
        validator.validate_path("bad;name")

    outside = tmp_path.parent / "outside.bin"
    outside.write_bytes(b"x")
    with pytest.raises(ValueError):
        validator.validate_path(str(outside))

    with pytest.raises(TypeError):
        validator.sanitize_for_subprocess("not-a-path")  # type: ignore[arg-type]


def test_yara_rule_validation() -> None:
    validator = FileValidator()
    good = "rule test { condition: true }"
    validator.validate_yara_rule_content(good)

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("")

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content('include "evil.yar"')

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content('import "evil"')

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("a" * 11, max_size=10)

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("*" * 10001)

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("x" * 10001)


def test_validate_file_for_analysis(tmp_path: Path) -> None:
    sample = tmp_path / "ok.bin"
    sample.write_bytes(b"data")
    assert validate_file_for_analysis(str(sample), allowed_directory=str(tmp_path)) == sample

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(ValueError):
        validate_file_for_analysis(str(empty), allowed_directory=str(tmp_path))

    large = tmp_path / "large.bin"
    large.write_bytes(b"data")
    with pytest.raises(ValueError):
        validate_file_for_analysis(str(large), allowed_directory=str(tmp_path), max_size=1)
