from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.core.r2_session import R2Session


def _sample_path() -> Path:
    sample = Path("samples/fixtures/hello_pe.exe")
    if not sample.exists():
        pytest.skip("sample binary missing")
    return sample


def test_r2_session_basic_info_requires_open():
    session = R2Session("/nonexistent")
    with pytest.raises(RuntimeError):
        session._run_basic_info_check()


def test_r2_session_open_close_and_flags():
    sample = _sample_path()
    session = R2Session(str(sample))
    file_size_mb = sample.stat().st_size / (1024 * 1024)

    r2 = session.open(file_size_mb)
    assert r2 is not None
    assert session.is_open is True
    assert session._select_r2_flags() == ["-2"]

    session.close()
    assert session.is_open is False


def test_r2_session_initial_analysis_branches():
    sample = _sample_path()
    session = R2Session(str(sample))
    file_size_mb = sample.stat().st_size / (1024 * 1024)

    session.open(file_size_mb)
    try:
        # Huge file path skips analysis
        session._perform_initial_analysis(file_size_mb + 10_000)
        # Large file path runs "aa"
        session._perform_initial_analysis(file_size_mb + 200)
        # Small file path runs "aaa"
        session._perform_initial_analysis(max(file_size_mb, 0.1))
    finally:
        session.close()
