from __future__ import annotations

from pathlib import Path
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.helpers import write_minimal_pe_file

from r2inspect.cli import batch_processing
from r2inspect.cli.batch_processing import (
    determine_csv_file_path,
    find_executable_files_by_magic,
    find_files_by_extensions,
    is_elf_executable,
    is_macho_executable,
    is_pe_executable,
    is_script_executable,
    setup_rate_limiter,
    setup_batch_mode,
    setup_analysis_options,
    setup_single_file_output,
)


def test_cli_batch_processing_signature_and_extension_helpers(tmp_path: Path) -> None:
    pe_file = write_minimal_pe_file(tmp_path / "sample.exe")
    dll_file = tmp_path / "sample.dll"
    dll_file.write_text("x")

    assert is_elf_executable(b"\x7fELF" + b"\x00" * 4) is True
    assert is_macho_executable(b"\xfe\xed\xfa\xce" + b"\x00") is True
    assert is_script_executable(b"#!/bin/sh") is True

    with pe_file.open("rb") as handle:
        header = handle.read(64)
        assert is_pe_executable(header, handle) is True

    files = find_files_by_extensions(tmp_path, "exe,dll", recursive=False)
    assert sorted(path.name for path in files) == ["sample.dll", "sample.exe"]


def test_cli_batch_processing_output_setup_behaviors(tmp_path: Path) -> None:
    recursive, auto_detect, output = setup_batch_mode("batch", None, False, True, None)
    assert recursive is True
    assert auto_detect is True
    assert output == "output"

    single_output = setup_single_file_output(True, False, None, str(tmp_path / "sample.exe"))
    assert str(single_output).endswith("_analysis.json")

    explicit_csv = tmp_path / "results.csv"
    csv_file, csv_name = determine_csv_file_path(explicit_csv, "ts")
    assert csv_file == explicit_csv
    assert csv_name == "results.csv"


def test_cli_batch_processing_handle_main_error_exits() -> None:
    with pytest.raises(SystemExit):
        batch_processing.handle_main_error(RuntimeError("boom"), verbose=False)


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


def test_cli_batch_processing_magic_and_rate_limit_behaviors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_magic = batch_processing.magic
    try:
        batch_processing.magic = None
        assert batch_processing._init_magic() is None

        batch_processing.magic = _BadMagicModule()
        assert batch_processing._init_magic() is None

        batch_processing.magic = _MagicModule()
        (tmp_path / "small.bin").write_bytes(b"x" * 10)
        (tmp_path / "exec.bin").write_bytes(b"x" * 100)
        files = find_executable_files_by_magic(tmp_path, recursive=False, verbose=True)
        assert any(path.name == "exec.bin" for path in files)
    finally:
        batch_processing.magic = original_magic

    monkeypatch.setenv("R2INSPECT_MAX_THREADS", "2")
    limiter = setup_rate_limiter(threads=10, verbose=False)
    assert limiter.max_concurrent == 2

    options = setup_analysis_options(None, None)
    assert options["full_analysis"] is True
