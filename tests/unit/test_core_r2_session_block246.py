import os
import struct
import time
from pathlib import Path

import pytest

from r2inspect.core.r2_session import R2Session


class DummyR2:
    def __init__(self):
        self.commands = []

    def cmd(self, command: str):
        self.commands.append(command)
        if command == "sleep":
            time.sleep(0.05)
        return "ok"


def _write_fat_macho(path: Path, arches: list[int]) -> None:
    header = struct.pack(">I", 0xCAFEBABE) + struct.pack(">I", len(arches))
    entries = b""
    for cputype in arches:
        entries += struct.pack(">IIIII", cputype, 0, 0, 0, 0)
    path.write_bytes(header + entries)


def test_detect_fat_macho_and_select_flags(tmp_path: Path, monkeypatch):
    fat = tmp_path / "fat.bin"
    _write_fat_macho(fat, [0x01000007])

    session = R2Session(str(fat))
    arches = session._detect_fat_macho_arches()
    assert "x86_64" in arches

    monkeypatch.setenv("R2INSPECT_DISABLE_PLUGINS", "true")
    flags = session._select_r2_flags()
    assert "-2" in flags
    assert "-NN" in flags

    monkeypatch.delenv("R2INSPECT_DISABLE_PLUGINS", raising=False)


def test_run_cmd_with_timeout_forced(monkeypatch, tmp_path: Path):
    file_path = tmp_path / "dummy.bin"
    file_path.write_bytes(b"A" * 64)

    session = R2Session(str(file_path))
    session.r2 = DummyR2()

    monkeypatch.setenv("R2INSPECT_FORCE_CMD_TIMEOUT", "sleep")
    assert session._run_cmd_with_timeout("sleep", timeout=0.01) is False

    monkeypatch.delenv("R2INSPECT_FORCE_CMD_TIMEOUT", raising=False)
    assert session._run_cmd_with_timeout("sleep", timeout=0.01) is False

    session.r2 = None
    assert session._run_cmd_with_timeout("any", timeout=0.01) is False
