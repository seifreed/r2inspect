"""Tests covering branch paths in r2inspect/cli/batch_processing.py."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from r2inspect.cli import batch_processing
from r2inspect.cli.batch_processing import (
    _flush_coverage_data,
    _is_executable_signature,
    check_executable_signature,
    ensure_batch_shutdown,
    find_executable_files_by_magic,
    find_files_to_process,
    is_elf_executable,
    is_macho_executable,
    is_pe_executable,
    is_script_executable,
    run_batch_analysis,
    schedule_forced_exit,
    setup_batch_output_directory,
)


# ---------------------------------------------------------------------------
# Simple PE-style file used across several tests
# ---------------------------------------------------------------------------

def _write_pe_file(path: Path) -> Path:
    """Write a minimal MZ+PE header file to *path* and return it."""
    data = bytearray(128)
    data[0:2] = b"MZ"
    data[60:64] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\x00\x00"
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# Executable signature wrapper tests (lines 96, 101, 105, 109, 113, 117)
# ---------------------------------------------------------------------------

def test_check_executable_signature_pe_file(tmp_path: Path) -> None:
    """check_executable_signature wrapper returns True for a PE file."""
    pe = _write_pe_file(tmp_path / "sample.exe")
    assert check_executable_signature(pe) is True


def test_is_executable_signature_pe_mime() -> None:
    """_is_executable_signature wrapper returns True for PE MIME type."""
    assert _is_executable_signature("application/x-dosexec", "") is True


def test_is_pe_executable_with_pe_header(tmp_path: Path) -> None:
    """is_pe_executable wrapper returns True for a valid PE header."""
    pe = _write_pe_file(tmp_path / "sample.exe")
    with open(pe, "rb") as fh:
        header = fh.read(64)
        assert is_pe_executable(header, fh) is True


def test_is_elf_executable_with_elf_magic() -> None:
    """is_elf_executable wrapper returns True for ELF magic bytes."""
    assert is_elf_executable(b"\x7fELF\x00\x00") is True


def test_is_macho_executable_with_macho_magic() -> None:
    """is_macho_executable wrapper returns True for Mach-O magic bytes."""
    assert is_macho_executable(b"\xfe\xed\xfa\xcf") is True


def test_is_script_executable_with_shebang() -> None:
    """is_script_executable wrapper returns True for shebang bytes."""
    assert is_script_executable(b"#!") is True


# ---------------------------------------------------------------------------
# find_executable_files_by_magic – init_errors branches (131-136)
# ---------------------------------------------------------------------------

def test_find_executable_files_by_magic_no_magic_returns_empty_and_logs(
    tmp_path: Path, capsys
) -> None:
    """find_executable_files_by_magic returns [] and prints warning when magic is None."""
    (tmp_path / "sample.bin").write_bytes(b"MZ" + b"\x00" * 100)
    original = batch_processing.magic
    try:
        batch_processing.magic = None
        result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=False)
    finally:
        batch_processing.magic = original
    assert result == []
    out = capsys.readouterr().out
    assert "python-magic" in out or "not available" in out


def test_find_executable_files_by_magic_broken_magic_logs_fallback(
    tmp_path: Path, capsys
) -> None:
    """find_executable_files_by_magic logs fallback message when magic init raises."""

    class _BrokenMagic:
        """Simulates a magic module whose Magic() constructor always raises."""

        def Magic(self, mime: bool = False) -> None:
            raise RuntimeError("initialization failure")

    (tmp_path / "sample.bin").write_bytes(b"MZ" + b"\x00" * 100)
    original = batch_processing.magic
    try:
        batch_processing.magic = _BrokenMagic()
        result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=False)
    finally:
        batch_processing.magic = original
    assert result == []
    out = capsys.readouterr().out
    assert "Falling back" in out


# ---------------------------------------------------------------------------
# find_executable_files_by_magic – verbose output (139, 142-143, 146-147)
# ---------------------------------------------------------------------------

def test_find_executable_files_by_magic_verbose_prints_scan_count(
    tmp_path: Path, capsys
) -> None:
    """find_executable_files_by_magic prints scan count when verbose=True."""

    class _NoOpMagicObj:
        def from_file(self, path: str) -> str:
            return ""

    class _FakeMagicModule:
        @staticmethod
        def Magic(mime: bool = False) -> _NoOpMagicObj:
            return _NoOpMagicObj()

    (tmp_path / "sample.bin").write_bytes(b"\x00" * 100)
    original = batch_processing.magic
    try:
        batch_processing.magic = _FakeMagicModule()
        find_executable_files_by_magic(tmp_path, recursive=False, verbose=True)
    finally:
        batch_processing.magic = original
    out = capsys.readouterr().out
    assert "Scanning" in out


def test_find_executable_files_by_magic_verbose_prints_file_error(
    tmp_path: Path, capsys
) -> None:
    """find_executable_files_by_magic prints file errors in verbose mode."""

    class _ErrorMagicObj:
        def from_file(self, path: str) -> str:
            raise RuntimeError("cannot read")

    class _ErrorMagicModule:
        @staticmethod
        def Magic(mime: bool = False) -> _ErrorMagicObj:
            return _ErrorMagicObj()

    big_file = tmp_path / "sample.bin"
    big_file.write_bytes(b"\x00" * 100)
    original = batch_processing.magic
    try:
        batch_processing.magic = _ErrorMagicModule()
        find_executable_files_by_magic(tmp_path, recursive=False, verbose=True)
    finally:
        batch_processing.magic = original
    out = capsys.readouterr().out
    assert "Error checking" in out


def test_find_executable_files_by_magic_verbose_prints_found_executable(
    tmp_path: Path, capsys
) -> None:
    """find_executable_files_by_magic prints found executable paths when verbose=True."""

    class _PeMagicMimeObj:
        def from_file(self, path: str) -> str:
            return "application/x-dosexec"

    class _PeMagicDescObj:
        def from_file(self, path: str) -> str:
            return "PE32 executable"

    class _PeMagicModule:
        @staticmethod
        def Magic(mime: bool = False) -> Any:
            return _PeMagicMimeObj() if mime else _PeMagicDescObj()

    pe_file = tmp_path / "sample.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)
    original = batch_processing.magic
    try:
        batch_processing.magic = _PeMagicModule()
        result = find_executable_files_by_magic(tmp_path, recursive=False, verbose=True)
    finally:
        batch_processing.magic = original
    assert pe_file in result
    out = capsys.readouterr().out
    assert "Found executable" in out


# ---------------------------------------------------------------------------
# find_files_to_process – verbose/not-quiet paths (394, 398)
# ---------------------------------------------------------------------------

def test_find_files_to_process_auto_detect_not_quiet_prints_message(
    tmp_path: Path, capsys
) -> None:
    """find_files_to_process with auto_detect=True and quiet=False prints detection message."""
    find_files_to_process(
        tmp_path,
        auto_detect=True,
        extensions=None,
        recursive=False,
        verbose=False,
        quiet=False,
    )
    out = capsys.readouterr().out
    assert "Auto-detecting" in out


def test_find_files_to_process_extensions_not_quiet_prints_message(
    tmp_path: Path, capsys
) -> None:
    """find_files_to_process with extensions and quiet=False prints searching message."""
    (tmp_path / "file.exe").touch()
    find_files_to_process(
        tmp_path,
        auto_detect=False,
        extensions="exe",
        recursive=False,
        verbose=False,
        quiet=False,
    )
    out = capsys.readouterr().out
    assert "Searching for files" in out


# ---------------------------------------------------------------------------
# setup_batch_output_directory – parent mkdir branch (433)
# ---------------------------------------------------------------------------

def test_setup_batch_output_directory_creates_nonexistent_parent_for_csv(
    tmp_path: Path,
) -> None:
    """setup_batch_output_directory creates missing parent directories for a .csv path."""
    csv_file = tmp_path / "subdir" / "nested" / "results.csv"
    assert not csv_file.parent.exists()
    setup_batch_output_directory(str(csv_file), output_json=False, output_csv=True)
    assert csv_file.parent.exists()


# ---------------------------------------------------------------------------
# _flush_coverage_data – current error branch (245, 258-259)
# ---------------------------------------------------------------------------

def test_flush_coverage_data_coverage_current_raises(tmp_path: Path) -> None:
    """_flush_coverage_data silently handles Coverage.current() raising an exception."""
    os.environ["R2INSPECT_TEST_COVERAGE_CURRENT_ERROR"] = "1"
    try:
        _flush_coverage_data()
    finally:
        del os.environ["R2INSPECT_TEST_COVERAGE_CURRENT_ERROR"]


# ---------------------------------------------------------------------------
# ensure_batch_shutdown – break branch and force-exit branch (207, 212-215)
# ---------------------------------------------------------------------------

def test_ensure_batch_shutdown_zero_timeout_raises_system_exit() -> None:
    """ensure_batch_shutdown raises SystemExit when timeout expires with lingering threads."""
    done = threading.Event()

    def _long_running() -> None:
        done.wait(timeout=10.0)

    t = threading.Thread(target=_long_running, daemon=False, name="test-lingering")
    t.start()
    try:
        with pytest.raises(SystemExit):
            ensure_batch_shutdown(timeout=0.0)
    finally:
        done.set()
        t.join(timeout=2.0)


# ---------------------------------------------------------------------------
# schedule_forced_exit – inner _exit function (224-227)
# ---------------------------------------------------------------------------

def test_schedule_forced_exit_inner_exit_function_executes() -> None:
    """schedule_forced_exit schedules a timer whose inner _exit function runs."""
    saved = os.environ.pop("R2INSPECT_DISABLE_FORCED_EXIT", None)
    try:
        schedule_forced_exit(delay=0.05)
        # Allow the daemon timer thread to fire and run _exit(); SystemExit raised
        # inside a daemon thread is swallowed by the threading machinery.
        time.sleep(0.15)
    finally:
        if saved is not None:
            os.environ["R2INSPECT_DISABLE_FORCED_EXIT"] = saved
        else:
            os.environ.setdefault("R2INSPECT_DISABLE_FORCED_EXIT", "1")


# ---------------------------------------------------------------------------
# run_batch_analysis – inner function definitions (466-499)
# ---------------------------------------------------------------------------

def test_run_batch_analysis_inner_functions_defined_on_call(tmp_path: Path) -> None:
    """run_batch_analysis defines its inner functions and builds deps on every call."""
    run_batch_analysis(
        batch_dir=str(tmp_path),
        options={},
        output_json=False,
        output_csv=False,
        output_dir=None,
        recursive=False,
        extensions="exe",
        verbose=False,
        config_obj=None,
        auto_detect=False,
        threads=1,
        quiet=True,
    )
