#!/usr/bin/env python3
"""Phase 2 branch-path tests for r2inspect/modules/ssdeep_analyzer.py."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

from r2inspect.modules import ssdeep_analyzer as module
from r2inspect.modules.ssdeep_analyzer import SSDeepAnalyzer


class _MockSSDeepModule:
    def __init__(
        self,
        hash_value: str | None = "3:aa:bb",
        *,
        fail_hash: bool = False,
        fail_file: bool = False,
    ) -> None:
        self.hash_value = hash_value
        self.fail_hash = fail_hash
        self.fail_file = fail_file

    def hash(self, _data: bytes) -> str:
        if self.fail_hash:
            raise OSError("forced hash fail")
        assert self.hash_value is not None
        return self.hash_value

    def hash_from_file(self, _path: str) -> str:
        if self.fail_file:
            raise RuntimeError("forced file hash fail")
        assert self.hash_value is not None
        return self.hash_value


class _DummyRunResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _monkeypatch_no_binary(monkeypatch: Any) -> None:
    monkeypatch.setattr(module.SSDeepAnalyzer, "_resolve_ssdeep_binary", staticmethod(lambda: None))


def test_calculate_hash_library_hash_raises_then_hash_from_file_fallback(
    tmp_path: Path, monkeypatch: Any
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload")
    monkeypatch.setattr(
        module,
        "get_ssdeep",
        lambda: _MockSSDeepModule(fail_hash=True, fail_file=False, hash_value="3:aa:bb"),
    )
    analyzer = SSDeepAnalyzer(filepath=str(sample))
    hash_value, method, error = analyzer._calculate_hash()

    assert hash_value == "3:aa:bb"
    assert method == "python_library"
    assert error is None


def test_calculate_hash_library_fails_falls_back_to_binary_and_reports_no_hash(
    tmp_path: Path, monkeypatch: Any
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload")
    monkeypatch.setattr(
        module,
        "get_ssdeep",
        lambda: _MockSSDeepModule(fail_hash=True, fail_file=True, hash_value=None),
    )
    monkeypatch.setattr(
        module.SSDeepAnalyzer,
        "_calculate_with_binary",
        lambda self: (None, None),
    )

    analyzer = SSDeepAnalyzer(filepath=str(sample))
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert method is None
    assert error == "SSDeep binary calculation returned no hash"


def test_calculate_hash_library_generic_exception_falls_back_to_binary(
    tmp_path: Path, monkeypatch: Any
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload")

    class _GenericModule:
        def hash(self, _data: bytes) -> str:
            raise RuntimeError("generic hash error")

        def hash_from_file(self, _path: str) -> str:
            raise RuntimeError("generic hash file error")

    monkeypatch.setattr(module, "get_ssdeep", lambda: _GenericModule())
    monkeypatch.setattr(
        module.SSDeepAnalyzer,
        "_calculate_with_binary",
        lambda self: (None, None),
    )

    analyzer = SSDeepAnalyzer(filepath=str(sample))
    hash_value, method, error = analyzer._calculate_hash()
    assert hash_value is None
    assert method is None
    assert error == "SSDeep binary calculation returned no hash"


def test_calculate_with_binary_returns_runtime_error_when_process_fails(
    tmp_path: Path, monkeypatch: Any
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload")
    _monkeypatch_no_binary(monkeypatch)
    monkeypatch.setattr(
        module.SSDeepAnalyzer, "_resolve_ssdeep_binary", staticmethod(lambda: "/usr/bin/ssdeep")
    )

    def _fake_run(*_args: Any, **_kwargs: Any) -> _DummyRunResult:
        return _DummyRunResult(returncode=1, stderr="command failed")

    monkeypatch.setattr(module.subprocess, "run", _fake_run)
    analyzer = SSDeepAnalyzer(filepath=str(sample))
    with pytest.raises(RuntimeError, match="ssdeep command failed"):
        analyzer._calculate_with_binary()


def test_calculate_with_binary_raises_when_output_cannot_be_parsed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload")
    monkeypatch.setattr(
        module.SSDeepAnalyzer,
        "_resolve_ssdeep_binary",
        staticmethod(lambda: "/usr/bin/ssdeep"),
    )

    def _fake_run(*_args: Any, **_kwargs: Any) -> _DummyRunResult:
        return _DummyRunResult(returncode=0, stdout="ssdeep,1.1--blocksize:hash:hash,filename\n")

    monkeypatch.setattr(module.subprocess, "run", _fake_run)
    analyzer = SSDeepAnalyzer(filepath=str(sample))
    with pytest.raises(RuntimeError, match="Could not parse ssdeep output"):
        analyzer._calculate_with_binary()


def test_calculate_with_binary_subprocess_error_path(tmp_path: Path, monkeypatch: Any) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload")
    monkeypatch.setattr(
        module.SSDeepAnalyzer,
        "_resolve_ssdeep_binary",
        staticmethod(lambda: "/usr/bin/ssdeep"),
    )

    def _boom(*_args: Any, **_kwargs: Any) -> _DummyRunResult:
        raise subprocess.SubprocessError("boom")

    monkeypatch.setattr(module.subprocess, "run", _boom)
    analyzer = SSDeepAnalyzer(filepath=str(sample))
    with pytest.raises(RuntimeError, match="ssdeep subprocess error"):
        analyzer._calculate_with_binary()


def test_compare_with_binary_returns_none_when_binary_missing(monkeypatch: Any) -> None:
    _monkeypatch_no_binary(monkeypatch)
    assert SSDeepAnalyzer._compare_with_binary("3:abc:def", "3:abc:xyz") is None


def test_compare_with_library_exception(monkeypatch: Any) -> None:
    class _BadLibrary:
        def compare(self, _left: str, _right: str) -> int:
            raise RuntimeError("bad compare")

    monkeypatch.setattr(module, "get_ssdeep", lambda: _BadLibrary())
    assert SSDeepAnalyzer._compare_with_library("3:abc:def", "3:abc:xyz") is None


def test_compare_with_binary_cleanup_failure_is_ignored_and_returns_none(
    tmp_path: Path, monkeypatch: Any
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload")
    monkeypatch.setattr(
        module.SSDeepAnalyzer,
        "_resolve_ssdeep_binary",
        staticmethod(lambda: "/usr/bin/ssdeep"),
    )

    bad_root = tempfile.mkdtemp()

    class _FailingTempDir:
        def __init__(self, prefix: str | None = None) -> None:
            self.name = bad_root

        def cleanup(self) -> None:
            raise RuntimeError("cleanup failed")

    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", _FailingTempDir)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.SubprocessError("run failed")),
    )

    assert SSDeepAnalyzer._compare_with_binary("3:abc:def", "3:abc:xyz") is None


def test_is_available_handles_subprocess_exceptions(monkeypatch: Any) -> None:
    monkeypatch.setattr(module, "get_ssdeep", lambda: None)
    monkeypatch.setattr(
        module.SSDeepAnalyzer,
        "_resolve_ssdeep_binary",
        staticmethod(lambda: "/usr/bin/ssdeep"),
    )
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.SubprocessError("unavailable")),
    )
    assert SSDeepAnalyzer.is_available() is False
