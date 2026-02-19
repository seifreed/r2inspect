from __future__ import annotations

import pytest

from r2inspect.adapters.r2pipe_adapter import R2PipeAdapter
from r2inspect.config import Config
from r2inspect.factory import build_inspector_dependencies
from r2inspect.registry.default_registry import create_default_registry


class _FakeR2:
    def cmdj(self, _command: str) -> dict:
        return {}

    def cmd(self, _command: str) -> str:
        return ""


def test_build_inspector_dependencies_returns_three_tuple() -> None:
    r2 = _FakeR2()
    config = Config()
    adapter, registry, pipeline_builder = build_inspector_dependencies(r2, config, "test.bin")
    assert adapter is not None
    assert registry is not None
    assert pipeline_builder is not None


def test_build_inspector_dependencies_adapter_type() -> None:
    r2 = _FakeR2()
    config = Config()
    adapter, registry, pipeline_builder = build_inspector_dependencies(r2, config, "test.bin")
    assert isinstance(adapter, R2PipeAdapter)


def test_build_inspector_dependencies_registry_has_analyzers() -> None:
    r2 = _FakeR2()
    config = Config()
    adapter, registry, pipeline_builder = build_inspector_dependencies(r2, config, "test.bin")
    assert registry is not None
    assert len(list(registry)) > 0


def test_build_inspector_dependencies_pipeline_builder_stores_filename() -> None:
    r2 = _FakeR2()
    config = Config()
    adapter, registry, pipeline_builder = build_inspector_dependencies(r2, config, "myfile.exe")
    assert pipeline_builder.filename == "myfile.exe"


def test_build_inspector_dependencies_pipeline_builder_stores_config() -> None:
    r2 = _FakeR2()
    config = Config()
    adapter, registry, pipeline_builder = build_inspector_dependencies(r2, config, "test.bin")
    assert pipeline_builder.config is config


def test_create_inspector_nonexistent_file_raises_value_error() -> None:
    from r2inspect.factory import create_inspector

    with pytest.raises(ValueError, match="File validation failed"):
        create_inspector("/nonexistent/path/to/file.bin")


def test_create_inspector_with_default_config_raises_on_bad_file() -> None:
    from r2inspect.factory import create_inspector

    with pytest.raises(ValueError):
        create_inspector("")


def test_create_inspector_empty_file_raises_value_error(tmp_path) -> None:
    from r2inspect.factory import create_inspector

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")

    with pytest.raises(ValueError, match="File validation failed"):
        create_inspector(str(empty))
