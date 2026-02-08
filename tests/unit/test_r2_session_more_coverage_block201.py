from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from r2inspect.core import constants
from r2inspect.core.r2_session import R2Session


@pytest.mark.requires_r2
def test_select_flags_and_fat_macho_detection(tmp_path: Path) -> None:
    fat_path = tmp_path / "fat.bin"
    header = struct.pack(">I", 0xCAFEBABE) + struct.pack(">I", 2)
    entry_x86 = struct.pack(">I", 0x01000007) + b"\x00" * 16
    entry_arm = struct.pack(">I", 0x0100000C) + b"\x00" * 16
    fat_path.write_bytes(header + entry_x86 + entry_arm)

    session = R2Session(str(fat_path))
    arches = session._detect_fat_macho_arches()
    assert "x86_64" in arches
    assert "arm64" in arches

    os.environ["R2INSPECT_DISABLE_PLUGINS"] = "1"
    try:
        flags = session._select_r2_flags()
        assert "-2" in flags
        assert "-NN" in flags
    finally:
        os.environ.pop("R2INSPECT_DISABLE_PLUGINS", None)


@pytest.mark.requires_r2
def test_open_timeout_and_cleanup(samples_dir: Path) -> None:
    target = samples_dir / "hello_pe.exe"
    session = R2Session(str(target))
    with pytest.raises((TimeoutError, PermissionError)):
        session._open_with_timeout(["-2"], timeout=0.0)


@pytest.mark.requires_r2
def test_run_cmd_timeout_and_error_paths(samples_dir: Path) -> None:
    target = samples_dir / "hello_pe.exe"
    session = R2Session(str(target))
    session.open(file_size_mb=target.stat().st_size / (1024 * 1024))
    assert session._run_cmd_with_timeout("i", 0.0) is False
    # Trigger error path by sending invalid type to r2.cmd
    assert session._run_cmd_with_timeout(None, 1.0) is False  # type: ignore[arg-type]
    session.close()


def test_basic_info_check_requires_r2() -> None:
    session = R2Session("/nonexistent/file")
    with pytest.raises(RuntimeError):
        session._run_basic_info_check()


@pytest.mark.requires_r2
def test_initial_analysis_size_branches(samples_dir: Path) -> None:
    target = samples_dir / "hello_pe.exe"
    session = R2Session(str(target))
    session.open(file_size_mb=target.stat().st_size / (1024 * 1024))

    assert session._perform_initial_analysis(constants.HUGE_FILE_THRESHOLD_MB + 1) is True

    os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "aa,aaa"
    try:
        # Large branch with forced command error
        assert session._perform_initial_analysis(constants.LARGE_FILE_THRESHOLD_MB + 1) is False

        # Normal branch with forced command error
        assert session._perform_initial_analysis(0.1) is False
    finally:
        os.environ.pop("R2INSPECT_FORCE_CMD_TIMEOUT", None)

    session.close()


@pytest.mark.requires_r2
def test_initial_analysis_exception_path(samples_dir: Path) -> None:
    target = samples_dir / "hello_pe.exe"
    session = R2Session(str(target))
    session.r2 = None
    assert session._perform_initial_analysis(0.1) is True
