from pathlib import Path

from r2inspect.core.file_validator import FileValidator


def test_file_validator_missing_file(tmp_path):
    missing = tmp_path / "missing.bin"
    validator = FileValidator(missing)
    assert validator.validate() is False


def test_file_validator_too_small(tmp_path):
    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"\x00\x01")
    validator = FileValidator(tiny)
    assert validator.validate() is False


def test_file_validator_valid_file(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 100)
    validator = FileValidator(sample)
    assert validator.validate() is True


def test_file_validator_path_object(tmp_path):
    sample = tmp_path / "sample2.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 100)
    validator = FileValidator(Path(sample))
    assert validator.validate() is True
