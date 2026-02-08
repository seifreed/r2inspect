from __future__ import annotations

import os
from pathlib import Path

import pytest

from r2inspect.cli import batch_processing
from r2inspect.config import Config
from r2inspect.utils.rate_limiter import BatchRateLimiter

pytestmark = pytest.mark.requires_r2


class _Magic:
    def __init__(self, mime: bool = False) -> None:
        self.mime = mime

    def from_file(self, _path: str) -> str:
        return "application/x-executable" if self.mime else "ELF executable"


class _MagicModule:
    Magic = _Magic


class _BadMagicModule:
    class Magic:
        def __init__(self, mime: bool = False) -> None:
            raise RuntimeError("boom")


def test_batch_processing_magic_detection(tmp_path: Path) -> None:
    old_magic = batch_processing.magic
    try:
        batch_processing.magic = None
        assert batch_processing._init_magic() is None

        batch_processing.magic = _BadMagicModule()
        assert batch_processing._init_magic() is None

        batch_processing.magic = _MagicModule()
        (tmp_path / "small.bin").write_bytes(b"x" * 10)
        (tmp_path / "exec.bin").write_bytes(b"x" * 100)
        files = batch_processing.find_executable_files_by_magic(
            tmp_path, recursive=False, verbose=True
        )
        assert any(f.name == "exec.bin" for f in files)
    finally:
        batch_processing.magic = old_magic


def test_batch_processing_signature_checks(tmp_path: Path) -> None:
    pe_path = tmp_path / "pe.bin"
    pe_offset = 128
    header = bytearray(b"MZ" + b"\x00" * 58 + pe_offset.to_bytes(4, "little"))
    header.extend(b"\x00" * (64 - len(header)))
    pe_path.write_bytes(bytes(header) + b"\x00" * (pe_offset - len(header)) + b"PE\x00\x00")

    assert batch_processing.check_executable_signature(pe_path) is True
    with pe_path.open("rb") as f:
        assert batch_processing.is_pe_executable(b"MZ", f) is True
    assert batch_processing.is_elf_executable(b"\x7fELF") is True
    assert batch_processing.is_macho_executable(b"\xfe\xed\xfa\xce") is True
    assert batch_processing.is_script_executable(b"#!") is True


def test_batch_processing_rate_limit_and_single_file(tmp_path: Path) -> None:
    old_env = os.environ.get("R2INSPECT_MAX_THREADS")
    os.environ["R2INSPECT_MAX_THREADS"] = "2"
    try:
        limiter = batch_processing.setup_rate_limiter(threads=10, verbose=True)
        assert limiter.max_concurrent == 2
        os.environ["R2INSPECT_MAX_THREADS"] = "bad"
        assert batch_processing._cap_threads_for_execution(5) == 5
        os.environ["R2INSPECT_MAX_THREADS"] = "0"
        assert batch_processing._cap_threads_for_execution(5) == 5
    finally:
        if old_env is None:
            os.environ.pop("R2INSPECT_MAX_THREADS", None)
        else:
            os.environ["R2INSPECT_MAX_THREADS"] = old_env

    config = Config(str(tmp_path / "r2inspect_batch.json"))
    rate_limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=5.0, burst_size=2)
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    file_path = Path("samples/fixtures/hello_pe.exe")
    processed_path, results, error = batch_processing.process_single_file(
        file_path,
        Path("samples/fixtures"),
        config,
        {"full_analysis": False},
        output_json=True,
        output_path=output_dir,
        rate_limiter=rate_limiter,
    )
    assert processed_path == file_path
    assert results is not None
    assert error is None


def test_batch_processing_parallel_and_misc(tmp_path: Path) -> None:
    config = Config(str(tmp_path / "r2inspect_batch.json"))
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    files = [Path("samples/fixtures/hello_pe.exe")]

    class _ImmediateLimiter:
        def acquire(self, timeout: float | None = None) -> bool:
            return False

        def release_success(self) -> None:
            return None

        def release_error(self, _error_type: str = "unknown") -> None:
            return None

        def get_stats(self) -> dict[str, float]:
            return {}

    rate_limiter = _ImmediateLimiter()
    all_results: dict[str, dict[str, object]] = {}
    failed: list[tuple[str, str]] = []
    batch_processing.process_files_parallel(
        files,
        all_results,
        failed,
        output_dir,
        Path("samples/fixtures"),
        config,
        {"full_analysis": False},
        output_json=False,
        threads=1,
        rate_limiter=rate_limiter,
    )
    assert failed

    rate_limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=1.0, burst_size=1)
    batch_processing.display_batch_results(
        {},
        [("a", "err")],
        elapsed_time=1.0,
        files_to_process=[],
        rate_limiter=rate_limiter,
        verbose=True,
        output_filename="out",
    )

    batch_processing.setup_batch_mode("batch", None, True, False, None)
    assert batch_processing.setup_single_file_output(True, False, None, "a.bin")
    assert batch_processing.setup_analysis_options(None, None)["full_analysis"] is True

    batch_processing.display_failed_files([("a", "err")], verbose=False)
    batch_processing.display_failed_files([("a", "err")], verbose=True)

    batch_processing.ensure_batch_shutdown(timeout=0.0)

    os.environ["R2INSPECT_DISABLE_FORCED_EXIT"] = "1"
    try:
        batch_processing.schedule_forced_exit(delay=0.01)
    finally:
        os.environ.pop("R2INSPECT_DISABLE_FORCED_EXIT", None)

    os.environ["PYTEST_CURRENT_TEST"] = "x"
    try:
        assert batch_processing._pytest_running() is True
    finally:
        os.environ.pop("PYTEST_CURRENT_TEST", None)

    batch_processing._flush_coverage_data()


def test_batch_processing_handle_main_error() -> None:
    with pytest.raises(SystemExit):
        batch_processing.handle_main_error(RuntimeError("boom"), verbose=False)
