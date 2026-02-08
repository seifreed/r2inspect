import os
import sys
from pathlib import Path

import pytest

import r2inspect.__main__ as r2_main
from r2inspect import config_store
from r2inspect.security import validators


def test_main_entrypoint_version_exit(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["r2inspect", "--version"])
    exit_code = r2_main.main()
    assert exit_code == 0


def test_config_store_load_and_save(tmp_path, capsys) -> None:
    config_path = tmp_path / "config.json"
    payload = {"a": 1}
    config_store.ConfigStore.save(str(config_path), payload)

    loaded = config_store.ConfigStore.load(str(config_path))
    assert loaded == payload

    missing = config_store.ConfigStore.load(str(tmp_path / "missing.json"))
    assert missing is None
    assert "Warning: Could not load config" in capsys.readouterr().out

    # Force save error by targeting a directory as file path
    bad_path = tmp_path / "dir" / "config.json"
    (tmp_path / "dir").mkdir()
    os.chmod(tmp_path / "dir", 0o400)
    try:
        config_store.ConfigStore.save(str(bad_path), payload)
        assert "Warning: Could not save config" in capsys.readouterr().out
    finally:
        os.chmod(tmp_path / "dir", 0o700)


def test_file_validator_basic_and_allowed_dir(tmp_path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    target = allowed / "file.bin"
    target.write_text("ok")

    validator = validators.FileValidator(allowed_directory=allowed)
    resolved = validator.validate_path(str(target))
    assert resolved == target.resolve()

    outside = tmp_path / "outside.bin"
    outside.write_text("no")
    with pytest.raises(ValueError):
        validator.validate_path(str(outside))

    with pytest.raises(ValueError):
        validators.FileValidator(allowed_directory=tmp_path / "missing")


def test_file_validator_rejects_bad_paths(tmp_path) -> None:
    validator = validators.FileValidator()

    with pytest.raises(ValueError):
        validator.validate_path("")

    with pytest.raises(ValueError):
        validator.validate_path("bad\x00path")

    with pytest.raises(ValueError):
        validator.validate_path("bad;path")

    too_long = "a" * (validators.FileValidator.MAX_PATH_LENGTH + 1)
    with pytest.raises(ValueError):
        validator.validate_path(too_long, check_exists=False)


def test_file_validator_sanitize_for_subprocess(tmp_path) -> None:
    validator = validators.FileValidator()
    path = tmp_path / "file.bin"
    path.write_text("ok")
    resolved = validator.validate_path(str(path))
    assert validator.sanitize_for_subprocess(resolved) == str(path.resolve())

    with pytest.raises(TypeError):
        validator.sanitize_for_subprocess("not-a-path")

    with pytest.raises(ValueError):
        validator.sanitize_for_subprocess(Path("bad;path"))


def test_validate_yara_rule_content() -> None:
    validator = validators.FileValidator()

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("")

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("a" * (10 * 1024 * 1024 + 1))

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content('include "bad"')

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content('import "bad"')

    with pytest.raises(ValueError):
        validator.validate_yara_rule_content("*" * 10001)

    long_line = "a" * 10001
    with pytest.raises(ValueError):
        validator.validate_yara_rule_content(long_line)


def test_validate_file_for_analysis(tmp_path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"x")

    validated = validators.validate_file_for_analysis(str(file_path))
    assert validated == file_path.resolve()

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(ValueError):
        validators.validate_file_for_analysis(str(empty))

    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 10)
    with pytest.raises(ValueError):
        validators.validate_file_for_analysis(str(big), max_size=5)

    directory = tmp_path / "dir"
    directory.mkdir()
    validated_dir = validators.validate_file_for_analysis(str(directory))
    assert validated_dir == directory.resolve()
