from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.core.r2_session import R2Session

pytestmark = pytest.mark.requires_r2


def test_r2_session_real_open_and_analysis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = Path("samples/fixtures/hello_pe.exe")
    session = R2Session(str(fixture))

    monkeypatch.setenv("R2INSPECT_TEST_MODE", "1")
    monkeypatch.setenv("R2INSPECT_ANALYSIS_DEPTH", "0")
    file_size_mb = fixture.stat().st_size / (1024 * 1024)

    r2 = session.open(file_size_mb=file_size_mb)
    assert r2 is not None
    assert session.is_open is True

    assert session._get_open_timeout() > 0
    assert session._get_cmd_timeout() > 0
    assert session._get_analysis_timeout(full_analysis=True) > 0
    assert session._get_large_file_threshold() > 0
    assert session._get_huge_file_threshold() > 0

    assert session._run_basic_info_check() is True
    assert session._perform_initial_analysis(file_size_mb) is True

    monkeypatch.setenv("R2INSPECT_FORCE_CMD_TIMEOUT", "i")
    assert session._run_cmd_with_timeout("i", 0.001) is False

    session.close()
    assert session.is_open is False


def test_r2_session_real_fat_header_detect(tmp_path: Path) -> None:
    data = bytearray()
    data += (0xCAFEBABE).to_bytes(4, "big")
    data += (1).to_bytes(4, "big")
    data += (0x01000007).to_bytes(4, "big") + b"\x00" * 16
    fat_path = tmp_path / "fat.bin"
    fat_path.write_bytes(data)

    session = R2Session(str(fat_path))
    arches = session._detect_fat_macho_arches()
    assert "x86_64" in arches
