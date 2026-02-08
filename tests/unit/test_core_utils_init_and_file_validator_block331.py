from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from r2inspect import core, pipeline, registry, utils
from r2inspect.core.file_validator import FileValidator
from r2inspect.utils import memory_manager


@pytest.mark.unit
def test_core_pipeline_registry_utils_exports() -> None:
    # Force module imports for coverage.
    core_module = importlib.import_module("r2inspect.core")
    pipeline_module = importlib.import_module("r2inspect.pipeline")
    registry_module = importlib.import_module("r2inspect.registry")
    utils_module = importlib.import_module("r2inspect.utils")

    # core exports
    assert "R2Inspector" in core_module.__all__
    assert core.MIN_EXECUTABLE_SIZE_BYTES > 0

    # pipeline exports
    assert "AnalysisPipeline" in pipeline_module.__all__
    assert "AnalysisStage" in pipeline_module.__all__

    # registry exports
    assert registry_module.AnalyzerRegistry is not None
    assert registry_module.AnalyzerCategory is not None
    assert registry_module.create_default_registry() is not None

    # utils dynamic exports
    assert callable(utils_module.safe_cmd)
    assert callable(utils_module.safe_cmdj)
    assert callable(utils_module.safe_cmd_list)
    assert callable(utils_module.safe_cmd_dict)


@pytest.mark.unit
def test_file_validator_happy_path(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"A" * 64)
    validator = FileValidator(sample)
    assert validator._file_size_mb() > 0
    assert validator.validate() is True


@pytest.mark.unit
def test_file_validator_empty_and_too_small(tmp_path: Path) -> None:
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert FileValidator(empty).validate() is False

    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"A" * 1)
    validator = FileValidator(tiny)
    assert validator._is_readable() is False
    assert validator.validate() is False


@pytest.mark.unit
def test_file_validator_directory_path(tmp_path: Path) -> None:
    folder = tmp_path / "dir"
    folder.mkdir()
    assert FileValidator(folder).validate() is False


@pytest.mark.unit
def test_file_validator_read_error(tmp_path: Path) -> None:
    sample = tmp_path / "locked.bin"
    sample.write_bytes(b"A" * 64)
    sample.chmod(0o000)
    try:
        assert FileValidator(sample).validate() is False
    finally:
        sample.chmod(0o600)


@pytest.mark.unit
def test_file_validator_memory_limit_exceeded(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"A" * 64)

    original_limit = memory_manager.global_memory_monitor.limits.max_file_size_mb
    try:
        memory_manager.configure_memory_limits(max_file_size_mb=0.00001)
        assert FileValidator(sample).validate() is False
    finally:
        memory_manager.configure_memory_limits(max_file_size_mb=original_limit)
