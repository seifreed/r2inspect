import os
import time
from pathlib import Path

import pytest

from r2inspect.core.constants import HUGE_FILE_THRESHOLD_MB, LARGE_FILE_THRESHOLD_MB
from r2inspect.core.r2_session import R2Session


class DummyR2:
    def __init__(self, response: str = "info") -> None:
        self.response = response
        self.commands: list[str] = []
        self.quit_called = False

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        return self.response

    def quit(self) -> None:
        self.quit_called = True


def _write_fat_macho(path: Path, arches: list[int]) -> None:
    import struct

    path.write_bytes(b"")
    with path.open("wb") as handle:
        handle.write(struct.pack(">I", 0xCAFEBABE))
        handle.write(struct.pack(">I", len(arches)))
        for arch in arches:
            handle.write(struct.pack(">I", arch))
            handle.write(b"\x00" * 16)


def test_select_r2_flags_for_fat_macho(tmp_path):
    arm_file = tmp_path / "arm.bin"
    _write_fat_macho(arm_file, [0x0100000C])
    session = R2Session(str(arm_file))
    flags = session._select_r2_flags()
    assert "-NN" in flags

    x86_file = tmp_path / "x86.bin"
    _write_fat_macho(x86_file, [0x01000007])
    session = R2Session(str(x86_file))
    flags = session._select_r2_flags()
    assert "-2" in flags

    os.environ["R2INSPECT_DISABLE_PLUGINS"] = "1"
    try:
        flags = session._select_r2_flags()
        assert "-NN" in flags
    finally:
        os.environ.pop("R2INSPECT_DISABLE_PLUGINS", None)


def test_detect_fat_macho_arches_errors(tmp_path):
    missing = R2Session(str(tmp_path / "missing.bin"))
    assert missing._detect_fat_macho_arches() == set()

    other = tmp_path / "plain.bin"
    other.write_bytes(b"abcd")
    session = R2Session(str(other))
    assert session._detect_fat_macho_arches() == set()

    short = tmp_path / "short.bin"
    import struct

    with short.open("wb") as handle:
        handle.write(struct.pack(">I", 0xBEBAFECA))
        handle.write(struct.pack("<I", 1))
        handle.write(b"\x00" * 2)
    session = R2Session(str(short))
    assert session._detect_fat_macho_arches() == set()


def test_open_with_timeout_and_terminate(tmp_path):
    target = tmp_path / "file.bin"
    target.write_bytes(b"abcd")

    def slow_open(_filename, flags=None):  # noqa: ANN001
        time.sleep(0.05)
        return DummyR2()

    class DummyProc:
        def __init__(self) -> None:
            self.info = {"name": "radare2", "cmdline": [str(target)]}
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

    class DummyDenied:
        @property
        def info(self):  # type: ignore[override]
            raise session_module.psutil.AccessDenied()

    class DummyOther:
        def __init__(self) -> None:
            self.info = {"name": "other", "cmdline": []}

    dummy_proc = DummyProc()

    from r2inspect.core import r2_session as session_module

    original_open = session_module.r2pipe.open
    original_iter = session_module.psutil.process_iter
    session_module.r2pipe.open = slow_open
    session_module.psutil.process_iter = lambda _attrs: [
        dummy_proc,
        DummyOther(),
        DummyDenied(),
    ]

    session = R2Session(str(target))
    try:
        with pytest.raises(TimeoutError):
            session._open_with_timeout(["-2"], timeout=0.001)
        assert dummy_proc.terminated is True
    finally:
        session_module.r2pipe.open = original_open
        session_module.psutil.process_iter = original_iter


def test_run_cmd_with_timeout_variants(tmp_path):
    target = tmp_path / "file.bin"
    target.write_bytes(b"abcd")
    session = R2Session(str(target))
    assert session._run_cmd_with_timeout("i", 0.01) is False

    session.r2 = DummyR2()
    os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "i"
    try:
        assert session._run_cmd_with_timeout("i", 0.01) is False
    finally:
        os.environ.pop("R2INSPECT_FORCE_CMD_TIMEOUT", None)

    class BoomR2(DummyR2):
        def cmd(self, command: str) -> str:
            raise RuntimeError("boom")

    session.r2 = BoomR2()
    assert session._run_cmd_with_timeout("i", 0.01) is False

    class SlowR2(DummyR2):
        def cmd(self, command: str) -> str:
            time.sleep(0.05)
            return "ok"

    session.r2 = SlowR2()
    assert session._run_cmd_with_timeout("i", 0.001) is False


def test_basic_info_check_paths(tmp_path):
    target = tmp_path / "file.bin"
    target.write_bytes(b"abcd")
    session = R2Session(str(target))
    with pytest.raises(RuntimeError):
        session._run_basic_info_check()

    session.r2 = DummyR2(response="x")
    os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "i"
    try:
        assert session._run_basic_info_check() is False
    finally:
        os.environ.pop("R2INSPECT_FORCE_CMD_TIMEOUT", None)

    session.r2 = DummyR2(response="ok")
    assert session._run_basic_info_check() is True

    class ErrR2(DummyR2):
        def cmd(self, command: str) -> str:
            raise RuntimeError("fail")

    class AlwaysTrueSession(R2Session):
        def _run_cmd_with_timeout(self, command: str, timeout: float) -> bool:
            return True

    session = AlwaysTrueSession(str(target))
    session.r2 = ErrR2()
    with pytest.raises(RuntimeError):
        session._run_basic_info_check()


def test_perform_initial_analysis_paths(tmp_path):
    target = tmp_path / "file.bin"
    target.write_bytes(b"abcd")
    session = R2Session(str(target))
    session.r2 = DummyR2()

    assert session._perform_initial_analysis(HUGE_FILE_THRESHOLD_MB + 1) is True

    os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "aa"
    try:
        assert session._perform_initial_analysis(LARGE_FILE_THRESHOLD_MB + 1) is False
    finally:
        os.environ.pop("R2INSPECT_FORCE_CMD_TIMEOUT", None)

    assert session._perform_initial_analysis(LARGE_FILE_THRESHOLD_MB + 1) is True

    os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "aaa"
    try:
        assert session._perform_initial_analysis(1.0) is False
    finally:
        os.environ.pop("R2INSPECT_FORCE_CMD_TIMEOUT", None)

    session.r2 = None
    assert session._perform_initial_analysis(1.0) is True


def test_close_and_reopen_safe_mode(tmp_path):
    target = tmp_path / "file.bin"
    target.write_bytes(b"abcd")

    from r2inspect.core import r2_session as session_module

    original_open = session_module.r2pipe.open
    session_module.r2pipe.open = lambda *_args, **_kw: DummyR2()

    session = R2Session(str(target))
    session.r2 = DummyR2()
    session._cleanup_required = True
    session.close()
    assert session.r2 is None

    try:
        reopened = session._reopen_safe_mode()
        assert isinstance(reopened, DummyR2)
    finally:
        session_module.r2pipe.open = original_open


def test_open_reopen_paths(tmp_path):
    target = tmp_path / "file.bin"
    target.write_bytes(b"abcd")

    from r2inspect.core import r2_session as session_module

    original_open = session_module.r2pipe.open
    session_module.r2pipe.open = lambda *_args, **_kw: DummyR2()
    try:

        class BasicTimeout(R2Session):
            def _open_with_timeout(self, flags, timeout):  # type: ignore[override]
                return DummyR2()

            def _run_basic_info_check(self) -> bool:
                return False

            def _perform_initial_analysis(self, file_size_mb: float) -> bool:
                return True

        session = BasicTimeout(str(target))
        result = session.open(1.0)
        assert isinstance(result, DummyR2)

        class AnalysisTimeout(BasicTimeout):
            def _run_basic_info_check(self) -> bool:
                return True

            def _perform_initial_analysis(self, file_size_mb: float) -> bool:
                return False

        session = AnalysisTimeout(str(target))
        result = session.open(1.0)
        assert isinstance(result, DummyR2)

        class CrashSession(BasicTimeout):
            def _run_basic_info_check(self) -> bool:
                raise RuntimeError("boom")

        session = CrashSession(str(target))
        assert session.open(1.0) == ""
    finally:
        session_module.r2pipe.open = original_open


def test_close_variants_and_context(tmp_path):
    target = tmp_path / "file.bin"
    target.write_bytes(b"abcd")
    session = R2Session(str(target))
    session.r2 = DummyR2()
    session._cleanup_required = True
    assert session.is_open is True
    session.close()
    assert session.is_open is False

    class BadQuit(DummyR2):
        def quit(self) -> None:
            raise RuntimeError("boom")

    session.r2 = BadQuit()
    session._cleanup_required = True
    session.close()

    with R2Session(str(target)) as entered:
        assert entered is not None
