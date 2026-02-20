from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import pytest

from r2inspect.cli import batch_processing, batch_workers


class DummyMagic:
    def __init__(self, mime: bool = False) -> None:
        self._mime = mime

    def from_file(self, _path: str) -> str:
        if self._mime:
            return "application/x-executable"
        return "ELF 64-bit"


class DummyMagicRaises:
    def __init__(self, _mime: bool = False) -> None:
        pass

    def from_file(self, _path: str) -> str:
        raise RuntimeError("boom")


class MagicModule:
    def __init__(self, raises: bool = False) -> None:
        self._raises = raises

    def Magic(self, mime: bool = False):
        if self._raises:
            raise RuntimeError("init")
        return DummyMagic(mime=mime)


class DummyRateLimiter:
    def __init__(self, acquire_ok: bool = True) -> None:
        self.acquire_ok = acquire_ok
        self.errors: list[str] = []
        self.success = 0

    def acquire(self, timeout: float = 0.0) -> bool:
        return self.acquire_ok

    def release_success(self) -> None:
        self.success += 1

    def release_error(self, error_type: str) -> None:
        self.errors.append(error_type)

    def get_stats(self) -> dict:
        return {"success_rate": 1.0, "avg_wait_time": 0.0, "current_rate": 1.0}


def test_init_magic_error_and_signature(monkeypatch) -> None:
    monkeypatch.setattr(batch_processing, "magic", None)
    assert batch_processing._init_magic() is None

    monkeypatch.setattr(batch_processing, "magic", MagicModule(raises=True))
    assert batch_processing._init_magic() is None

    assert batch_processing._is_executable_signature("application/x-executable", "") is True
    assert batch_processing._is_executable_signature("", "ELF") is True
    assert batch_processing._is_executable_signature("text/plain", "data") is False


def test_find_executable_files_by_magic(monkeypatch, tmp_path: Path) -> None:
    file_small = tmp_path / "small.bin"
    file_small.write_bytes(b"X")

    file_ok = tmp_path / "ok.bin"
    file_ok.write_bytes(b"A" * 128)

    file_bad = tmp_path / "bad.bin"
    file_bad.write_bytes(b"B" * 128)

    class MagicModuleMixed:
        def Magic(self, mime: bool = False):
            if mime:
                return DummyMagic(mime=True)

            class DescMagic:
                def from_file(self, path: str) -> str:
                    if "bad.bin" in path:
                        raise RuntimeError("boom")
                    return "ELF 64-bit"

            return DescMagic()

    monkeypatch.setattr(batch_processing, "magic", MagicModuleMixed())

    found = batch_processing.find_executable_files_by_magic(tmp_path, recursive=False, verbose=True)
    assert file_ok in found
    assert file_small not in found

    # magic unavailable path
    monkeypatch.setattr(batch_processing, "magic", None)
    assert (
        batch_processing.find_executable_files_by_magic(tmp_path, recursive=False, verbose=False)
        == []
    )


def test_check_executable_signature_paths(tmp_path: Path) -> None:
    small = tmp_path / "small"
    small.write_bytes(b"X")
    assert batch_processing.check_executable_signature(small) is False

    script = tmp_path / "script"
    script.write_bytes(b"#! /bin/sh\n")
    assert batch_processing.check_executable_signature(script) is True

    elf = tmp_path / "elf"
    elf.write_bytes(b"\x7fELF" + b"0" * 64)
    assert batch_processing.check_executable_signature(elf) is True

    macho = tmp_path / "macho"
    macho.write_bytes(b"\xfe\xed\xfa\xce" + b"0" * 64)
    assert batch_processing.check_executable_signature(macho) is True

    # Valid MZ with PE signature
    pe = tmp_path / "pe"
    header = bytearray(b"MZ" + b"0" * 58)
    header += (64).to_bytes(4, "little")
    header += b"0" * 64
    header[64:68] = b"PE\x00\x00"
    pe.write_bytes(bytes(header))
    assert batch_processing.check_executable_signature(pe) is True

    assert batch_processing.check_executable_signature(tmp_path) is False

    # Direct PE helper with seek error
    class BadFile:
        def seek(self, _off: int) -> None:
            raise ValueError("bad")

        def read(self, _n: int) -> bytes:
            return b""

    assert batch_processing.is_pe_executable(b"MZ" + b"0" * 62, BadFile()) is True
    assert batch_processing.is_pe_executable(b"ZZ", BadFile()) is False


def test_cap_threads_for_execution(monkeypatch) -> None:
    monkeypatch.delenv("R2INSPECT_MAX_THREADS", raising=False)
    assert batch_processing._cap_threads_for_execution(5) == 5

    monkeypatch.setenv("R2INSPECT_MAX_THREADS", "bad")
    assert batch_processing._cap_threads_for_execution(5) == 5

    monkeypatch.setenv("R2INSPECT_MAX_THREADS", "0")
    assert batch_processing._cap_threads_for_execution(5) == 5

    monkeypatch.setenv("R2INSPECT_MAX_THREADS", "2")
    assert batch_processing._cap_threads_for_execution(5) == 2


def test_process_single_file_rate_limit_and_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing.exe"
    from r2inspect.config import Config

    config_obj = Config(str(tmp_path / "config.json"))
    rate = DummyRateLimiter(acquire_ok=False)
    file_path, results, error = batch_processing.process_single_file(
        missing, tmp_path, config_obj, {}, False, tmp_path, rate
    )
    assert results is None
    assert error is not None

    rate2 = DummyRateLimiter(acquire_ok=True)
    file_path2, results2, error2 = batch_processing.process_single_file(
        missing, tmp_path, config_obj, {}, False, tmp_path, rate2
    )
    assert results2 is None
    assert error2 is not None
    assert rate2.errors


def test_process_files_parallel_empty_results(monkeypatch, tmp_path: Path) -> None:
    file_path = tmp_path / "one.exe"
    file_path.write_bytes(b"MZ" + b"0" * 128)

    def fake_process(*_args, **_kwargs):
        return file_path, None, None

    monkeypatch.setattr(batch_workers, "process_single_file", fake_process)
    all_results: dict[str, dict] = {}
    failed: list[tuple[str, str]] = []
    batch_processing.process_files_parallel(
        [file_path], all_results, failed, tmp_path, tmp_path, None, {}, False, 1, DummyRateLimiter()
    )
    assert failed

    # error path
    def fake_error(*_args, **_kwargs):
        return file_path, None, "boom"

    monkeypatch.setattr(batch_workers, "process_single_file", fake_error)
    all_results = {}
    failed = []
    batch_processing.process_files_parallel(
        [file_path], all_results, failed, tmp_path, tmp_path, None, {}, False, 1, DummyRateLimiter()
    )
    assert failed

    # success path
    def fake_success(*_args, **_kwargs):
        return file_path, {"file_info": {"name": "one.exe"}}, None

    monkeypatch.setattr(batch_workers, "process_single_file", fake_success)
    all_results = {}
    failed = []
    batch_processing.process_files_parallel(
        [file_path], all_results, failed, tmp_path, tmp_path, None, {}, False, 1, DummyRateLimiter()
    )
    assert all_results


def test_display_results_and_failed_files() -> None:
    all_results = {"a": {"file_info": {"name": "a"}}}
    failed = [(f"file{i}", "err") for i in range(12)]
    rate = DummyRateLimiter()
    batch_processing.display_batch_results(
        all_results,
        failed,
        elapsed_time=1.0,
        files_to_process=[Path("a")],
        rate_limiter=rate,
        verbose=True,
        output_filename="out.csv",
    )
    batch_processing.display_failed_files(failed, verbose=False)


def test_shutdown_and_forced_exit(monkeypatch) -> None:
    # prevent exit
    monkeypatch.setattr(os, "_exit", lambda _code: None)

    # create a non-daemon thread
    stop = threading.Event()

    def worker():
        stop.wait(0.1)

    thread = threading.Thread(target=worker)
    thread.start()
    batch_processing.ensure_batch_shutdown(timeout=0.05)
    batch_processing.ensure_batch_shutdown(timeout=0.0)
    stop.set()
    thread.join()

    # schedule forced exit disabled
    monkeypatch.setenv("R2INSPECT_DISABLE_FORCED_EXIT", "1")
    batch_processing.schedule_forced_exit(delay=0.0)
    monkeypatch.delenv("R2INSPECT_DISABLE_FORCED_EXIT", raising=False)

    # schedule forced exit enabled with fake Timer
    calls = {"started": False}

    class DummyTimer:
        def __init__(self, _delay, _func):
            self.daemon = False
            self._func = _func

        def start(self):
            calls["started"] = True
            self._func()

    monkeypatch.setattr(batch_processing.threading, "Timer", DummyTimer)
    batch_processing.schedule_forced_exit(delay=0.0)
    assert calls["started"] is True


def test_flush_coverage_data(monkeypatch) -> None:
    # _pytest_running baseline (force path that hits sys.modules check)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    assert batch_processing._pytest_running() is True

    # no coverage module
    monkeypatch.setitem(sys.modules, "coverage", None)
    batch_processing._flush_coverage_data()

    # fake coverage current
    class DummyCov:
        def stop(self):
            self.stopped = True

        def save(self):
            self.saved = True

    class DummyCoverageModule:
        class Coverage:
            @staticmethod
            def current():
                return DummyCov()

    monkeypatch.setitem(sys.modules, "coverage", DummyCoverageModule)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")
    batch_processing._flush_coverage_data()
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    # force non-pytest path
    monkeypatch.setattr(batch_processing, "_pytest_running", lambda: False)
    batch_processing._flush_coverage_data()

    # cov None path
    class DummyCoverageNone:
        class Coverage:
            @staticmethod
            def current():
                return None

    monkeypatch.setitem(sys.modules, "coverage", DummyCoverageNone)
    batch_processing._flush_coverage_data()

    class DummyCoverageRaises:
        class Coverage:
            @staticmethod
            def current():
                raise RuntimeError("boom")

    monkeypatch.setitem(sys.modules, "coverage", DummyCoverageRaises)
    batch_processing._flush_coverage_data()

    class DummyCovRaises:
        def stop(self):
            raise RuntimeError("stop")

        def save(self):
            raise RuntimeError("save")

    class DummyCoverageRaisesSave:
        class Coverage:
            @staticmethod
            def current():
                return DummyCovRaises()

    monkeypatch.setitem(sys.modules, "coverage", DummyCoverageRaisesSave)
    batch_processing._flush_coverage_data()


def test_setup_helpers_and_errors(tmp_path: Path) -> None:
    # rate limiter
    batch_processing.setup_rate_limiter(threads=2, verbose=True)

    recursive, auto_detect, output = batch_processing.setup_batch_mode(
        batch="x", extensions=None, output_json=True, output_csv=False, output=None
    )
    assert recursive is True
    assert auto_detect is True
    assert output == "output"

    output2 = batch_processing.setup_single_file_output(True, False, None, "foo.exe")
    assert output2 is not None

    output3 = batch_processing.setup_single_file_output(False, True, None, "foo.exe")
    assert output3 is not None

    opts = batch_processing.setup_analysis_options("yara", "xor")
    assert opts["custom_yara"] == "yara"

    batch_processing.display_rate_limiter_stats(
        {"success_rate": 0.5, "avg_wait_time": 1.0, "current_rate": 2.0}
    )
    batch_processing.display_memory_stats()

    with pytest.raises(SystemExit):
        batch_processing.handle_main_error(RuntimeError("boom"), verbose=True)


def test_batch_processing_helpers_and_run(tmp_path: Path) -> None:
    # find_files_to_process and extensions
    files = batch_processing.find_files_to_process(
        tmp_path, auto_detect=False, extensions=None, recursive=False, verbose=False, quiet=True
    )
    assert files == []

    sample_src = Path("samples/fixtures/hello_pe.exe")
    sample_dst = tmp_path / "hello_pe.exe"
    sample_dst.write_bytes(sample_src.read_bytes())

    files2 = batch_processing.find_files_to_process(
        tmp_path, auto_detect=False, extensions="exe", recursive=False, verbose=False, quiet=False
    )
    assert sample_dst in files2

    batch_processing.find_files_to_process(
        tmp_path, auto_detect=True, extensions=None, recursive=False, verbose=False, quiet=False
    )

    batch_processing.display_no_files_message(auto_detect=True, extensions=None)
    batch_processing.display_no_files_message(auto_detect=False, extensions="exe")

    # setup output directory paths
    out_dir = batch_processing.setup_batch_output_directory(
        str(tmp_path / "out.csv"), output_json=False, output_csv=True
    )
    assert out_dir.suffix == ".csv"

    out_dir3 = batch_processing.setup_batch_output_directory(
        str(tmp_path / "outdir"), output_json=False, output_csv=False
    )
    assert out_dir3.exists()

    out_dir2 = batch_processing.setup_batch_output_directory(
        None, output_json=True, output_csv=False
    )
    assert out_dir2.name == "output"
    out_dir4 = batch_processing.setup_batch_output_directory(
        None, output_json=False, output_csv=False
    )
    assert out_dir4.name == "r2inspect_batch_results"

    nested_csv = tmp_path / "nested" / "out.csv"
    batch_processing.setup_batch_output_directory(
        str(nested_csv), output_json=False, output_csv=True
    )

    # csv helpers
    result = {
        "file_info": {"name": "a", "file_type": "PE", "md5": "x", "architecture": "x86"},
        "compiler": {"detected": True, "compiler": "MSVC"},
        "packer_info": {"detected": True, "name": "UPX"},
        "crypto_info": ["AES"],
        "indicators": [{"type": "Anti", "description": "x"}],
    }
    batch_processing.write_csv_results(tmp_path / "out.csv", {"a": result})
    csv_file, csv_name = batch_processing.determine_csv_file_path(tmp_path, "t")
    assert csv_name.endswith(".csv")
    csv_file2, csv_name2 = batch_processing.determine_csv_file_path(tmp_path / "out.csv", "t")
    assert csv_name2 == "out.csv"

    stats = batch_processing.collect_batch_statistics({"a": result})
    assert stats["file_types"]

    # json summary
    batch_processing.create_json_batch_summary({"a": result}, [("b", "err")], tmp_path, "t")

    # run batch analysis with empty dir to hit early return
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    batch_processing.run_batch_analysis(
        batch_dir=str(empty_dir),
        options={},
        output_json=False,
        output_csv=False,
        output_dir=str(tmp_path / "out"),
        recursive=False,
        extensions="exe",
        verbose=False,
        config_obj=None,
        auto_detect=False,
        threads=1,
        quiet=True,
    )

    # run batch analysis with real file to exercise main path
    from r2inspect.config import Config

    config_obj = Config(str(tmp_path / "config.json"))
    batch_processing.run_batch_analysis(
        batch_dir=str(tmp_path),
        options={},
        output_json=False,
        output_csv=False,
        output_dir=str(tmp_path / "out_run"),
        recursive=False,
        extensions="exe",
        verbose=False,
        config_obj=config_obj,
        auto_detect=False,
        threads=1,
        quiet=True,
    )

    # run with quiet False to cover console lines
    batch_processing.run_batch_analysis(
        batch_dir=str(tmp_path),
        options={},
        output_json=False,
        output_csv=False,
        output_dir=str(tmp_path / "out_run2"),
        recursive=False,
        extensions="exe",
        verbose=False,
        config_obj=config_obj,
        auto_detect=False,
        threads=1,
        quiet=False,
    )


def test_process_single_file_success(tmp_path: Path) -> None:
    sample_src = Path("samples/fixtures/hello_pe.exe")
    sample_dst = tmp_path / "hello_pe.exe"
    sample_dst.write_bytes(sample_src.read_bytes())
    from r2inspect.config import Config

    config_obj = Config(str(tmp_path / "config.json"))
    rate = DummyRateLimiter(acquire_ok=True)
    file_path, results, error = batch_processing.process_single_file(
        sample_dst, tmp_path, config_obj, {}, True, tmp_path, rate
    )
    assert error is None
    assert results is not None
