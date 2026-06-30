import struct
import threading
import time
from pathlib import Path


from r2inspect.infrastructure.r2_session import R2Session

from tests.helpers import env_vars


class DummyR2:
    def __init__(self, release: threading.Event | None = None):
        self.commands = []
        self.release = release

    def cmd(self, command: str):
        self.commands.append(command)
        if command == "sleep":
            if self.release is not None:
                self.release.wait(5.0)
            else:
                time.sleep(0.05)
        return "ok"


def _write_fat_macho(path: Path, arches: list[int]) -> None:
    header = struct.pack(">I", 0xCAFEBABE) + struct.pack(">I", len(arches))
    entries = b""
    for cputype in arches:
        entries += struct.pack(">IIIII", cputype, 0, 0, 0, 0)
    path.write_bytes(header + entries)


def test_detect_fat_macho_and_select_flags(tmp_path: Path):
    fat = tmp_path / "fat.bin"
    _write_fat_macho(fat, [0x01000007])

    session = R2Session(str(fat))
    arches = session._detect_fat_macho_arches()
    assert "x86_64" in arches

    with env_vars(R2INSPECT_DISABLE_PLUGINS="true"):
        flags = session._select_r2_flags()
        assert "-2" in flags
        assert "-NN" in flags


def test_run_cmd_with_timeout_forced(tmp_path: Path):
    file_path = tmp_path / "dummy.bin"
    file_path.write_bytes(b"A" * 64)

    session = R2Session(str(file_path))
    release = threading.Event()
    session.r2 = DummyR2(release)

    try:
        with env_vars(R2INSPECT_FORCE_CMD_TIMEOUT="sleep"):
            assert session._run_cmd_with_timeout("sleep", timeout=0.01) is False

        with env_vars(R2INSPECT_FORCE_CMD_TIMEOUT=None):
            assert session._run_cmd_with_timeout("sleep", timeout=0.01) is False
    finally:
        release.set()

    session.r2 = None
    assert session._run_cmd_with_timeout("any", timeout=0.01) is False
