from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, Self

import pytest

from r2inspect import factory
from r2inspect.core import inspector_runtime
from r2inspect.infrastructure import command_runner
from tests.helpers import env_vars


class _Inspector:
    def analyze(self, **_options):
        return {}

    def close(self) -> None:
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args) -> Literal[False]:
        return False


def test_factory_builds_consensus_and_validates_backends() -> None:
    original = factory.create_inspector
    original_resolve_backend = factory.resolve_backend
    try:
        factory.create_inspector = lambda *_args, **_kwargs: _Inspector()
        assert original("sample", backend="consensus").analyze()["backend"] == "consensus"

        factory.resolve_backend = lambda _name: None
        with pytest.raises(ValueError, match="Unknown backend"):
            original("sample", backend="missing")
        factory.resolve_backend = lambda _name: lambda **_kwargs: object()
        with pytest.raises(TypeError, match="does not implement BinaryInspector"):
            original("sample", backend="invalid")
    finally:
        factory.create_inspector = original
        factory.resolve_backend = original_resolve_backend


def test_inspector_runtime_handles_missing_dependencies_and_forensic_errors() -> None:
    inspector = SimpleNamespace()
    deps = SimpleNamespace(config_factory=None, memory_monitor=None)
    with pytest.raises(ValueError, match="config_factory"):
        inspector_runtime._assign_inspector_config(inspector, None, deps)
    with pytest.raises(ValueError, match="memory_monitor"):
        inspector_runtime._initialize_inspector(
            inspector,
            filename="sample",
            config=None,
            verbose=False,
            deps=deps,
            _logger=SimpleNamespace(),
        )

    adapter = SimpleNamespace(_cache={"key": "value"})
    inspector_runtime._clear_adapter_cache(adapter)
    assert adapter._cache == {}

    original_create_forensic_bundle = inspector_runtime.create_forensic_bundle
    try:
        inspector_runtime.create_forensic_bundle = lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("disk full")
        )
        logger = SimpleNamespace(warning=lambda _message: None)
        inspector = SimpleNamespace(filename="sample", adapter=object(), config={})
        results: dict[str, object] = {}
        inspector_runtime._attach_forensic_bundle(
            inspector, {"forensic_evidence": True}, results, "now", logger
        )
        assert results["warnings"] == ["Forensic evidence preservation failed: disk full"]
        results = {"warnings": "existing"}
        inspector_runtime._attach_forensic_bundle(
            inspector, {"forensic_evidence": True}, results, "now", logger
        )
        assert results["warnings"] == [
            "existing",
            "Forensic evidence preservation failed: disk full",
        ]
    finally:
        inspector_runtime.create_forensic_bundle = original_create_forensic_bundle


def test_command_runner_validates_environment_and_cleans_failed_spawns(
    tmp_path: Path,
) -> None:
    with env_vars(
        R2INSPECT_CMD_TIMEOUT_SECONDS="invalid",
        R2INSPECT_CMD_MAX_PROCESSES="invalid",
    ):
        assert command_runner.resolve_timeout(2) == 2
        assert command_runner._env_int("R2INSPECT_CMD_MAX_PROCESSES", 3) == 3

    original_which = command_runner.shutil.which
    original_popen = command_runner.subprocess.Popen
    try:
        command_runner.shutil.which = lambda _name: None
        with pytest.raises(FileNotFoundError):
            command_runner._argv(["missing"])

        command_runner.shutil.which = lambda name: f"/bin/{name}"
        with env_vars(R2INSPECT_CMD_SANDBOX_PREFIX="   "):
            with pytest.raises(ValueError, match="SANDBOX_PREFIX is empty"):
                command_runner._argv(["echo"])

        command_runner.shutil.which = lambda name: "/bin/echo" if name == "echo" else None
        with env_vars(R2INSPECT_CMD_SANDBOX_PREFIX="missing-wrapper"):
            with pytest.raises(FileNotFoundError):
                command_runner._argv(["echo"])

        command_runner.shutil.which = lambda _name: os.devnull
        command_runner.subprocess.Popen = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("spawn failed")
        )
        with env_vars(R2INSPECT_CMD_SANDBOX_PREFIX=None):
            with pytest.raises(OSError, match="spawn failed"):
                command_runner.run_command(["command"], cwd=str(tmp_path), timeout=1)
    finally:
        command_runner.shutil.which = original_which
        command_runner.subprocess.Popen = original_popen
