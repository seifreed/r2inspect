from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from r2inspect.core.r2_session import R2Session


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


@pytest.mark.unit
def test_detect_fat_macho_and_select_flags(tmp_path: Path) -> None:
    fat = tmp_path / "fat.bin"
    # CAFEBABE, 2 architectures: x86_64 and arm64
    data = struct.pack(">I", 0xCAFEBABE) + struct.pack(">I", 2)
    data += struct.pack(">I", 0x01000007) + b"\x00" * 16
    data += struct.pack(">I", 0x0100000C) + b"\x00" * 16
    fat.write_bytes(data)

    session = R2Session(str(fat))
    arches = session._detect_fat_macho_arches()
    assert "x86_64" in arches
    assert "arm64" in arches

    original = os.environ.get("R2INSPECT_DISABLE_PLUGINS")
    try:
        os.environ["R2INSPECT_DISABLE_PLUGINS"] = "1"
        flags = session._select_r2_flags()
        assert "-NN" in flags
    finally:
        if original is None:
            os.environ.pop("R2INSPECT_DISABLE_PLUGINS", None)
        else:
            os.environ["R2INSPECT_DISABLE_PLUGINS"] = original


@pytest.mark.unit
def test_r2_session_open_reopen_and_basic_checks() -> None:
    sample = _sample_path()
    session = R2Session(str(sample))
    original = os.environ.get("R2INSPECT_FORCE_CMD_TIMEOUT")
    try:
        os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "i"
        r2 = session.open(file_size_mb=1.0)
        assert r2 is not None
        assert session.is_open
    finally:
        session.close()
        if original is None:
            os.environ.pop("R2INSPECT_FORCE_CMD_TIMEOUT", None)
        else:
            os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = original


@pytest.mark.unit
def test_r2_session_basic_info_and_cmd_timeout() -> None:
    sample = _sample_path()
    session = R2Session(str(sample))

    assert session._run_cmd_with_timeout("i", timeout=0.1) is False

    r2 = session.open(file_size_mb=1.0)
    assert r2 is not None

    original = os.environ.get("R2INSPECT_FORCE_CMD_TIMEOUT")
    try:
        os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "i"
        assert session._run_cmd_with_timeout("i", timeout=0.1) is False
        assert session._run_basic_info_check() is False
    finally:
        if original is None:
            os.environ.pop("R2INSPECT_FORCE_CMD_TIMEOUT", None)
        else:
            os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = original

    # Call after closing r2 to trigger error path.
    session.close()
    with pytest.raises(RuntimeError):
        session._run_basic_info_check()


@pytest.mark.unit
def test_r2_session_initial_analysis_branches() -> None:
    sample = _sample_path()
    session = R2Session(str(sample))
    session.open(file_size_mb=1.0)

    assert session._perform_initial_analysis(file_size_mb=100000.0) is True

    original = os.environ.get("R2INSPECT_FORCE_CMD_TIMEOUT")
    try:
        os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "aa"
        assert session._perform_initial_analysis(file_size_mb=5.0) is False
        os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "aaa"
        assert session._perform_initial_analysis(file_size_mb=1.0) is False
    finally:
        if original is None:
            os.environ.pop("R2INSPECT_FORCE_CMD_TIMEOUT", None)
        else:
            os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = original

    session.r2 = None
    assert session._perform_initial_analysis(file_size_mb=1.0) is True


@pytest.mark.unit
def test_r2_session_context_and_close() -> None:
    sample = _sample_path()
    with R2Session(str(sample)) as session:
        session.open(file_size_mb=1.0)
        assert session.is_open
    assert session.is_open is False


@pytest.mark.unit
def test_r2_session_open_failure(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    session = R2Session(str(missing))
    assert session.open(file_size_mb=0.1) == ""
