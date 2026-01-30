import types

import pytest

import r2inspect.core.r2_session as r2_session
from r2inspect.core.r2_session import R2Session


class FakeR2:
    def __init__(self):
        self.commands = []
        self.quit_called = False

    def cmd(self, command):
        self.commands.append(command)
        if command == "i":
            return "info"
        return ""

    def quit(self):
        self.quit_called = True


def test_r2_session_open_and_close(monkeypatch, tmp_path):
    fake = FakeR2()

    def fake_open(_filename, flags=None):
        return fake

    monkeypatch.setattr(r2_session.r2pipe, "open", fake_open)
    session = R2Session(str(tmp_path / "sample.bin"))
    r2 = session.open(file_size_mb=0.0)
    assert r2 is fake
    assert session.is_open is True
    session.close()
    assert fake.quit_called is True
    assert session.is_open is False


def test_r2_session_analysis_modes(monkeypatch, tmp_path):
    fake = FakeR2()

    def fake_open(_filename, flags=None):
        return fake

    monkeypatch.setattr(r2_session.r2pipe, "open", fake_open)

    session = R2Session(str(tmp_path / "sample.bin"))
    session.open(file_size_mb=r2_session.LARGE_FILE_THRESHOLD_MB + 1)
    assert "aa" in fake.commands

    fake.commands.clear()
    session.close()

    session = R2Session(str(tmp_path / "sample.bin"))
    session.open(file_size_mb=r2_session.HUGE_FILE_THRESHOLD_MB + 1)
    assert "aaa" not in fake.commands
