from __future__ import annotations

import os
import sys
from pathlib import Path

from r2inspect.cli import batch_processing


def test_signature_checks_and_helpers(tmp_path: Path) -> None:
    pe_file = tmp_path / "sample.exe"
    # Minimal MZ + PE header offset
    data = bytearray(128)
    data[0:2] = b"MZ"
    data[60:64] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"
    pe_file.write_bytes(data)

    with open(pe_file, "rb") as f:
        header = f.read(64)
        assert batch_processing.is_pe_executable(header, f) is True

    assert batch_processing.is_elf_executable(b"\x7fELF") is True
    assert batch_processing.is_macho_executable(b"\xfe\xed\xfa\xcf") is True
    assert batch_processing.is_script_executable(b"#!") is True

    assert batch_processing.check_executable_signature(pe_file) is True


def test_magic_detection_paths(tmp_path: Path, capsys) -> None:
    class DummyMagic:
        def __init__(self, mime: bool = False) -> None:
            self.mime = mime

        def from_file(self, _path: str) -> str:
            return "application/x-dosexec" if self.mime else "PE32 executable"

    class DummyMagicModule:
        Magic = DummyMagic

    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"MZ" + b"0" * 100)

    original_magic = batch_processing.magic
    try:
        batch_processing.magic = DummyMagicModule
        found = batch_processing.find_executable_files_by_magic(
            tmp_path, recursive=False, verbose=True
        )
        assert file_path in found
    finally:
        batch_processing.magic = original_magic

    out = capsys.readouterr().out
    assert "Found executable" in out or out == ""

    original_magic = batch_processing.magic
    try:
        batch_processing.magic = None
        assert batch_processing._init_magic() is None
        assert batch_processing.find_executable_files_by_magic(tmp_path) == []
    finally:
        batch_processing.magic = original_magic


def test_find_files_by_extensions_and_auto_detect(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_text("x")
    (tmp_path / "b.exe").write_text("x")

    found = batch_processing.find_files_by_extensions(tmp_path, "bin,exe", recursive=False)
    assert len(found) == 2

    files = batch_processing.find_files_to_process(
        tmp_path, auto_detect=False, extensions=None, recursive=False, verbose=False, quiet=True
    )
    assert files == []


def test_setup_output_directory_and_csv_path(tmp_path: Path) -> None:
    output_dir = tmp_path / "outdir"
    output_path = batch_processing.setup_batch_output_directory(str(output_dir), False, False)
    assert output_path.exists()

    csv_file, csv_name = batch_processing.determine_csv_file_path(output_path, "ts")
    assert csv_file.name.endswith(".csv")
    assert csv_name.endswith(".csv")

    explicit = output_path / "report.csv"
    csv_file2, csv_name2 = batch_processing.determine_csv_file_path(explicit, "ts")
    assert csv_file2 == explicit
    assert csv_name2 == "report.csv"

    explicit_json = output_path / "report.json"
    output_path_json = batch_processing.setup_batch_output_directory(
        str(explicit_json), output_json=True, output_csv=False
    )
    assert output_path_json.parent.exists()


def test_process_files_parallel_with_rate_limit(tmp_path: Path) -> None:
    # Create a small sample file
    sample = tmp_path / "sample.exe"
    data = bytearray(128)
    data[0:2] = b"MZ"
    data[60:64] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"
    sample.write_bytes(data)

    class SimpleRateLimiter:
        def __init__(self, allow: bool = True) -> None:
            self.allow = allow
            self.success = 0
            self.errors = 0

        def acquire(self, timeout: float = 0.0) -> bool:
            return self.allow

        def release_success(self) -> None:
            self.success += 1

        def release_error(self, _err: str) -> None:
            self.errors += 1

        def get_stats(self) -> dict:
            return {"success_rate": 1.0}

    all_results: dict[str, dict[str, object]] = {}
    failed_files: list[tuple[str, str]] = []

    # First run: rate limit timeout branch
    batch_processing.process_files_parallel(
        files_to_process=[sample],
        all_results=all_results,
        failed_files=failed_files,
        output_path=tmp_path,
        batch_path=tmp_path,
        config_obj=None,
        options={},
        output_json=False,
        threads=1,
        rate_limiter=SimpleRateLimiter(allow=False),
    )

    assert failed_files


def test_thread_cap_and_pytest_detection(monkeypatch) -> None:
    monkeypatch.delenv("R2INSPECT_MAX_THREADS", raising=False)
    assert batch_processing._cap_threads_for_execution(5) == 5

    monkeypatch.setenv("R2INSPECT_MAX_THREADS", "2")
    assert batch_processing._cap_threads_for_execution(5) == 2

    monkeypatch.setenv("R2INSPECT_MAX_THREADS", "bad")
    assert batch_processing._cap_threads_for_execution(5) == 5

    monkeypatch.setenv("R2INSPECT_MAX_THREADS", "0")
    assert batch_processing._cap_threads_for_execution(5) == 5

    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")
    assert batch_processing._pytest_running() is True

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    assert batch_processing._pytest_running() == ("pytest" in sys.modules)


def test_setup_helpers_and_messages(capsys) -> None:
    recursive, auto_detect, output = batch_processing.setup_batch_mode(
        batch=".", extensions=None, output_json=True, output_csv=False, output=None
    )
    assert recursive is True and auto_detect is True and output == "output"

    output_single = batch_processing.setup_single_file_output(
        output_json=True, output_csv=False, output=None, filename="sample.exe"
    )
    assert str(output_single).endswith("sample_analysis.json")

    batch_processing.display_no_files_message(True, None)
    batch_processing.display_no_files_message(False, "bin")

    out = capsys.readouterr().out
    assert "No executable files" in out


def test_display_rate_and_failed_files(capsys) -> None:
    batch_processing.display_rate_limiter_stats(
        {"success_rate": 0.5, "avg_wait_time": 0.1, "current_rate": 1.0}
    )
    batch_processing.display_failed_files([("f", "err")], verbose=False)
    batch_processing.display_failed_files(
        [(f"file{i}", "e" * 200) for i in range(12)], verbose=True
    )

    out = capsys.readouterr().out
    assert "Rate limiter stats" in out
    assert "Failed" in out


def test_schedule_forced_exit_disabled(monkeypatch) -> None:
    monkeypatch.setenv("R2INSPECT_DISABLE_FORCED_EXIT", "1")
    batch_processing.schedule_forced_exit(delay=0.01)


def test_display_memory_stats_safe(capsys) -> None:
    batch_processing.display_memory_stats()
    out = capsys.readouterr().out
    assert "Memory stats" in out or out == ""
