from __future__ import annotations

from pathlib import Path

from r2inspect.core.r2_session import R2Session


def test_r2_session_open_and_close():
    sample = Path("samples/fixtures/hello_pe.exe")
    assert sample.exists()

    session = R2Session(str(sample))
    r2 = session.open(file_size_mb=0.01)
    assert r2 is not None
    assert session.is_open is True

    session.close()
    assert session.is_open is False
