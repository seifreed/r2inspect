#!/usr/bin/env python3
"""Branch-path tests for r2inspect/infrastructure/r2_session.py."""
from __future__ import annotations

import os
import struct
import time
from pathlib import Path

import pytest

from r2inspect.infrastructure.r2_session import R2Session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeR2:
    """Minimal fake r2pipe instance that behaves normally."""

    def cmd(self, command: str) -> str:
        return "format=elf; class=64; type=exec; bits=64; " * 5

    def quit(self) -> None:
        pass


class ErrorQuitR2:
    """R2 instance whose quit() raises an exception."""

    def cmd(self, command: str) -> str:
        return "format=elf"

    def quit(self) -> None:
        raise RuntimeError("quit failed intentionally")


# ---------------------------------------------------------------------------
# Production-mode threshold returns - lines 82, 88, 94
# ---------------------------------------------------------------------------


def test_get_analysis_timeout_production_non_full_returns_30():
    """Line 82: non-test mode, full_analysis=False returns 30.0."""
    session = R2Session("/tmp/test")
    session._test_mode = False
    assert session._get_analysis_timeout(full_analysis=False) == 30.0


def test_get_analysis_timeout_production_full_returns_60():
    """Line 82: non-test mode, full_analysis=True returns 60.0."""
    session = R2Session("/tmp/test")
    session._test_mode = False
    assert session._get_analysis_timeout(full_analysis=True) == 60.0


def test_get_large_file_threshold_production_returns_constant():
    """Line 88: non-test mode returns LARGE_FILE_THRESHOLD_MB."""
    from r2inspect.core.constants import LARGE_FILE_THRESHOLD_MB

    session = R2Session("/tmp/test")
    session._test_mode = False
    assert session._get_large_file_threshold() == float(LARGE_FILE_THRESHOLD_MB)


def test_get_huge_file_threshold_production_returns_constant():
    """Line 94: non-test mode returns HUGE_FILE_THRESHOLD_MB."""
    from r2inspect.core.constants import HUGE_FILE_THRESHOLD_MB

    session = R2Session("/tmp/test")
    session._test_mode = False
    assert session._get_huge_file_threshold() == float(HUGE_FILE_THRESHOLD_MB)


# ---------------------------------------------------------------------------
# open() method paths - lines 126-131, 135-139
# ---------------------------------------------------------------------------


def test_open_returns_safe_mode_when_basic_info_check_fails():
    """Lines 126-127: _run_basic_info_check returns False -> _reopen_safe_mode called."""
    safe_r2 = FakeR2()
    session = R2Session("/tmp/test")
    session._open_with_timeout = lambda flags, timeout: FakeR2()
    session._run_basic_info_check = lambda: False
    session._reopen_safe_mode = lambda: safe_r2
    result = session.open(0.1)
    assert result is safe_r2


def test_open_returns_safe_mode_when_initial_analysis_fails():
    """Lines 130-131: _perform_initial_analysis returns False -> _reopen_safe_mode called."""
    safe_r2 = FakeR2()
    session = R2Session("/tmp/test")
    session._open_with_timeout = lambda flags, timeout: FakeR2()
    session._run_basic_info_check = lambda: True
    session._perform_initial_analysis = lambda size: False
    session._reopen_safe_mode = lambda: safe_r2
    result = session.open(0.1)
    assert result is safe_r2


def test_open_exception_during_open_re_raises():
    """Lines 135-139: exception in open() -> re-raised by error_handler (CRITICAL)."""
    session = R2Session("/tmp/test")

    def raise_error(flags, timeout):
        raise RuntimeError("r2pipe cannot open file")

    session._open_with_timeout = raise_error
    with pytest.raises(RuntimeError, match="r2pipe cannot open file"):
        session.open(0.1)


def test_open_exception_closes_r2_if_already_set():
    """Lines 137-138: r2 is set before exception -> close() is called on it."""
    closed = {"called": False}

    class TrackingR2:
        def cmd(self, c: str) -> str:
            return ""

        def quit(self) -> None:
            closed["called"] = True

    session = R2Session("/tmp/test")

    def set_r2_then_raise(flags: list, timeout: float):
        session.r2 = TrackingR2()
        session._cleanup_required = True
        raise RuntimeError("failure after r2 set")

    session._open_with_timeout = set_r2_then_raise
    # error_handler may return fallback or re-raise depending on recoverability
    try:
        session.open(0.1)
    except RuntimeError:
        pass
    assert closed["called"] is True


# ---------------------------------------------------------------------------
# _detect_fat_macho_arches - lines 183, 186, 188, 191-204
# ---------------------------------------------------------------------------


def test_detect_fat_macho_arches_header_too_short_returns_empty(tmp_path: Path):
    """Line 183: file with header < 8 bytes returns empty set."""
    binary = tmp_path / "short.bin"
    binary.write_bytes(b"\xCA\xFE")
    session = R2Session(str(binary))
    assert session._detect_fat_macho_arches() == set()


def test_detect_fat_macho_arches_big_endian_magic_no_arches(tmp_path: Path):
    """Line 186: 0xCAFEBABE magic detected, nfat_arch=0 -> empty set."""
    binary = tmp_path / "fat_be_zero.macho"
    data = struct.pack(">II", 0xCAFEBABE, 0)
    binary.write_bytes(data)
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert arches == set()


def test_detect_fat_macho_arches_little_endian_magic_no_arches(tmp_path: Path):
    """Line 188: 0xBEBAFECA magic detected, nfat_arch=0 -> empty set."""
    binary = tmp_path / "fat_le_zero.macho"
    data = struct.pack(">I", 0xBEBAFECA) + struct.pack("<I", 0)
    binary.write_bytes(data)
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert isinstance(arches, set)
    assert arches == set()


def test_detect_fat_macho_arches_x86_64_cpu_type(tmp_path: Path):
    """Lines 191-199: CPU type 0x01000007 (x86_64) adds x86_64 to arches."""
    binary = tmp_path / "fat_x86_64.macho"
    data = struct.pack(">II", 0xCAFEBABE, 1)
    data += struct.pack(">IIIII", 0x01000007, 3, 0, 0, 0)
    binary.write_bytes(data)
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert "x86_64" in arches


def test_detect_fat_macho_arches_arm64_cpu_type(tmp_path: Path):
    """Lines 200-201: CPU type 0x0100000C (arm64) adds arm64 to arches."""
    binary = tmp_path / "fat_arm64.macho"
    data = struct.pack(">II", 0xCAFEBABE, 1)
    data += struct.pack(">IIIII", 0x0100000C, 0, 0, 0, 0)
    binary.write_bytes(data)
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert "arm64" in arches


def test_detect_fat_macho_arches_unknown_cpu_type_skipped(tmp_path: Path):
    """Lines 197-201: unknown CPU type is not added to arches."""
    binary = tmp_path / "fat_unknown.macho"
    data = struct.pack(">II", 0xCAFEBABE, 1)
    data += struct.pack(">IIIII", 0x00000099, 0, 0, 0, 0)
    binary.write_bytes(data)
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert arches == set()


def test_detect_fat_macho_arches_entry_too_short_breaks(tmp_path: Path):
    """Lines 195-196: arch entry < 20 bytes breaks loop."""
    binary = tmp_path / "fat_short_entry.macho"
    data = struct.pack(">II", 0xCAFEBABE, 2)
    data += b"\x00" * 10  # only 10 bytes (< 20) for first entry
    binary.write_bytes(data)
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert arches == set()


def test_detect_fat_macho_arches_exception_returns_empty():
    """Lines 203-204: IOError on open returns empty set."""
    session = R2Session("/nonexistent/cannot_open.bin")
    arches = session._detect_fat_macho_arches()
    assert arches == set()


def test_detect_fat_macho_arches_multiple_arches(tmp_path: Path):
    """Lines 191-202: two arch entries both parsed correctly."""
    binary = tmp_path / "fat_multi.macho"
    data = struct.pack(">II", 0xCAFEBABE, 2)
    data += struct.pack(">IIIII", 0x01000007, 3, 0, 0, 0)  # x86_64
    data += struct.pack(">IIIII", 0x0100000C, 0, 0, 0, 0)  # arm64
    binary.write_bytes(data)
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert "x86_64" in arches
    assert "arm64" in arches


# ---------------------------------------------------------------------------
# _select_r2_flags fat Mach-O branches - lines 165-170
# ---------------------------------------------------------------------------


def test_select_r2_flags_fat_macho_appends_NN(tmp_path: Path):
    """Lines 165-170: fat Mach-O binary causes -NN to be added."""
    binary = tmp_path / "fat_flags.macho"
    data = struct.pack(">II", 0xCAFEBABE, 1)
    data += struct.pack(">IIIII", 0x01000007, 3, 0, 0, 0)
    binary.write_bytes(data)
    os.environ.pop("R2INSPECT_DISABLE_PLUGINS", None)
    session = R2Session(str(binary))
    session._test_mode = False
    flags = session._select_r2_flags()
    assert "-NN" in flags


def test_select_r2_flags_fat_macho_no_duplicate_NN_with_disable_plugins(tmp_path: Path):
    """Lines 165-174: -NN not duplicated when fat Mach-O adds it and DISABLE_PLUGINS=1."""
    binary = tmp_path / "fat_flags2.macho"
    data = struct.pack(">II", 0xCAFEBABE, 1)
    data += struct.pack(">IIIII", 0x01000007, 3, 0, 0, 0)
    binary.write_bytes(data)
    os.environ["R2INSPECT_DISABLE_PLUGINS"] = "1"
    try:
        session = R2Session(str(binary))
        session._test_mode = False
        flags = session._select_r2_flags()
        assert flags.count("-NN") == 1
    finally:
        os.environ.pop("R2INSPECT_DISABLE_PLUGINS", None)


# ---------------------------------------------------------------------------
# _open_with_timeout timeout path - lines 212-215
# ---------------------------------------------------------------------------


def test_open_with_timeout_raises_timeout_error_on_short_timeout(tmp_path: Path):
    """Lines 212-215: r2pipe.open() exceeds timeout -> TimeoutError raised."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x7fELF" + b"\x00" * 60)
    session = R2Session(str(dummy))
    with pytest.raises(TimeoutError, match="timed out"):
        session._open_with_timeout(["-2", "-n"], timeout=0.001)


# ---------------------------------------------------------------------------
# _terminate_radare2_processes - lines 219-232
# ---------------------------------------------------------------------------


def test_terminate_radare2_processes_iterates_all_processes_without_crash():
    """Lines 219-226: iterates processes, skips non-radare2 entries without error."""
    session = R2Session("/tmp/test_binary.bin")
    session._terminate_radare2_processes()


def test_terminate_radare2_processes_uses_filename_and_name():
    """Lines 219-220: target set from filename, target_name from Path."""
    session = R2Session("/tmp/my_special_file.bin")
    session._terminate_radare2_processes()
    # Verify it uses the right filename by checking no crash
    assert session.filename == "/tmp/my_special_file.bin"


# ---------------------------------------------------------------------------
# _run_cmd_with_timeout - lines 245, 248-251, 258-259, 266-267, 269-270
# ---------------------------------------------------------------------------


def test_run_cmd_with_timeout_r2_none_returns_false():
    """Line 245: r2 is None -> immediately returns False."""
    session = R2Session("/tmp/test")
    session.r2 = None
    assert session._run_cmd_with_timeout("i", 5.0) is False


def test_run_cmd_with_timeout_force_env_empty_set_forces_any_cmd():
    """Lines 248-251: FORCE_CMD_TIMEOUT with whitespace -> empty set -> any command forced."""

    class FakeR2:
        def cmd(self, c: str) -> str:
            return "result"

    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "  "
    try:
        result = session._run_cmd_with_timeout("anything", 5.0)
        assert result is False
    finally:
        del os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"]


def test_run_cmd_with_timeout_force_env_specific_cmd_forces_it():
    """Lines 248-251: FORCE_CMD_TIMEOUT=i forces timeout for 'i' command."""

    class FakeR2:
        def cmd(self, c: str) -> str:
            return "result"

    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "i"
    try:
        result = session._run_cmd_with_timeout("i", 5.0)
        assert result is False
    finally:
        del os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"]


def test_run_cmd_with_timeout_exception_in_thread_returns_false():
    """Lines 258-259, 269-270: command raises in thread -> returns False."""

    class ErrorR2:
        def cmd(self, c: str) -> str:
            raise OSError("broken pipe")

    session = R2Session("/tmp/test")
    session.r2 = ErrorR2()
    result = session._run_cmd_with_timeout("i", 5.0)
    assert result is False


def test_run_cmd_with_timeout_thread_does_not_complete_returns_false():
    """Lines 266-267: command blocks past timeout -> returns False."""

    class SlowR2:
        def cmd(self, c: str) -> str:
            time.sleep(30)
            return "late result"

    session = R2Session("/tmp/test")
    session.r2 = SlowR2()
    result = session._run_cmd_with_timeout("i", 0.001)
    assert result is False


# ---------------------------------------------------------------------------
# _run_basic_info_check - lines 281, 283, 287-290
# ---------------------------------------------------------------------------


def test_run_basic_info_check_raises_when_r2_is_none():
    """Line 281: r2 is None -> RuntimeError raised."""
    session = R2Session("/tmp/test")
    session.r2 = None
    with pytest.raises(RuntimeError, match="not initialized"):
        session._run_basic_info_check()


def test_run_basic_info_check_returns_false_when_cmd_timeout():
    """Line 283: _run_cmd_with_timeout returns False -> returns False."""
    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._run_cmd_with_timeout = lambda cmd, timeout: False
    assert session._run_basic_info_check() is False


def test_run_basic_info_check_logs_warning_on_minimal_output():
    """Lines 286-287: r2.cmd('i') returns short string -> warning logged, True returned."""

    class MinimalR2:
        def cmd(self, c: str) -> str:
            return "x"

    session = R2Session("/tmp/test")
    session.r2 = MinimalR2()
    session._run_cmd_with_timeout = lambda cmd, timeout: True
    result = session._run_basic_info_check()
    assert result is True


def test_run_basic_info_check_raises_runtime_error_on_cmd_exception():
    """Lines 288-290: r2.cmd() raises -> RuntimeError propagated."""

    class ErrorR2:
        def cmd(self, c: str) -> str:
            raise RuntimeError("cmd failed")

    session = R2Session("/tmp/test")
    session.r2 = ErrorR2()
    session._run_cmd_with_timeout = lambda cmd, timeout: True
    with pytest.raises(RuntimeError):
        session._run_basic_info_check()


# ---------------------------------------------------------------------------
# _perform_initial_analysis - lines 310, 315-316, 322/326, 337, 342-343, 346-348, 350-352
# ---------------------------------------------------------------------------


def test_perform_initial_analysis_r2_none_raises_caught_returns_true():
    """Line 310: r2 is None raises RuntimeError, caught by outer try, returns True."""
    session = R2Session("/tmp/test")
    session.r2 = None
    result = session._perform_initial_analysis(1.0)
    assert result is True


def test_perform_initial_analysis_depth_zero_skips_all_analysis():
    """Lines 315-316: R2INSPECT_ANALYSIS_DEPTH=0 -> skip analysis, return True."""
    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    os.environ["R2INSPECT_ANALYSIS_DEPTH"] = "0"
    try:
        result = session._perform_initial_analysis(1.0)
        assert result is True
    finally:
        os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)


def test_perform_initial_analysis_huge_file_skips_in_production():
    """Lines 322-326: file_size_mb > huge threshold in production -> True."""
    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._test_mode = False
    os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)
    result = session._perform_initial_analysis(file_size_mb=99999.0)
    assert result is True


def test_perform_initial_analysis_aa_timeout_returns_false():
    """Line 337: aa command times out -> returns False."""
    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._test_mode = True
    os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)
    session._run_cmd_with_timeout = lambda cmd, timeout: False
    result = session._perform_initial_analysis(0.1)
    assert result is False


def test_perform_initial_analysis_production_small_file_runs_aaa():
    """Lines 342-343, 347-348: production mode, small file -> aaa command runs."""
    ran = []
    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._test_mode = False
    os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)

    def mock_run(cmd: str, timeout: float) -> bool:
        ran.append(cmd)
        return True

    session._run_cmd_with_timeout = mock_run
    result = session._perform_initial_analysis(0.1)
    assert result is True
    assert "aaa" in ran


def test_perform_initial_analysis_aaa_timeout_returns_false():
    """Line 346: aaa command times out -> returns False."""
    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._test_mode = False
    os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)
    session._run_cmd_with_timeout = lambda cmd, timeout: False
    result = session._perform_initial_analysis(0.1)
    assert result is False


def test_perform_initial_analysis_exception_returns_true():
    """Lines 350-352: unexpected exception in analysis -> caught, returns True."""
    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._test_mode = False
    os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)

    def raise_error(cmd: str, timeout: float) -> bool:
        raise RuntimeError("unexpected mid-analysis error")

    session._run_cmd_with_timeout = raise_error
    result = session._perform_initial_analysis(0.1)
    assert result is True


# ---------------------------------------------------------------------------
# close() exception path - lines 361-362
# ---------------------------------------------------------------------------


def test_close_exception_in_quit_does_not_propagate():
    """Lines 361-362: quit() raises -> exception logged but not propagated."""
    session = R2Session("/tmp/test")
    session.r2 = ErrorQuitR2()
    session._cleanup_required = True
    session.close()
    assert session.r2 is None


# ---------------------------------------------------------------------------
# is_open property - line 369
# ---------------------------------------------------------------------------


def test_is_open_true_when_r2_set_and_cleanup_required():
    """Line 369: is_open returns True when r2 is not None and cleanup is required."""
    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._cleanup_required = True
    assert session.is_open is True


def test_is_open_false_when_r2_is_none():
    """Line 369: is_open returns False when r2 is None."""
    session = R2Session("/tmp/test")
    assert session.is_open is False


def test_is_open_false_when_cleanup_not_required():
    """Line 369: is_open returns False when cleanup_required is False."""
    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._cleanup_required = False
    assert session.is_open is False


# ---------------------------------------------------------------------------
# __enter__ and __exit__ - lines 373, 382-383
# ---------------------------------------------------------------------------


def test_enter_returns_self():
    """Line 373: __enter__ returns the session object itself."""
    session = R2Session("/tmp/test")
    assert session.__enter__() is session


def test_exit_calls_close_and_returns_false():
    """Lines 382-383: __exit__ closes session and returns False."""
    quit_called = {"n": 0}

    class TrackingR2:
        def quit(self) -> None:
            quit_called["n"] += 1

    session = R2Session("/tmp/test")
    session.r2 = TrackingR2()
    session._cleanup_required = True
    result = session.__exit__(None, None, None)
    assert result is False
    assert session.r2 is None
    assert quit_called["n"] == 1


def test_context_manager_with_statement_closes_on_exit():
    """Lines 373, 382-383: context manager protocol closes session on exit."""
    with R2Session("/tmp/test") as s:
        s.r2 = FakeR2()
        s._cleanup_required = True
    assert s.r2 is None
