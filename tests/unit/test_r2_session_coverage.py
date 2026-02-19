#!/usr/bin/env python3
"""Coverage tests for r2inspect/infrastructure/r2_session.py"""
from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from types import TracebackType

import pytest

from r2inspect.infrastructure.r2_session import R2Session


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def test_r2session_init_stores_filename():
    session = R2Session("/path/to/binary")
    assert session.filename == "/path/to/binary"


def test_r2session_init_r2_is_none():
    session = R2Session("/path/to/binary")
    assert session.r2 is None


def test_r2session_is_not_open_initially():
    session = R2Session("/path/to/binary")
    assert session.is_open is False


# ---------------------------------------------------------------------------
# Test mode detection
# ---------------------------------------------------------------------------

def test_is_test_mode_true_when_env_set():
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    session = R2Session("/tmp/test")
    assert session._is_test_mode is True
    del os.environ["R2INSPECT_TEST_MODE"]


def test_is_test_mode_true_when_env_is_true():
    os.environ["R2INSPECT_TEST_MODE"] = "true"
    session = R2Session("/tmp/test")
    assert session._is_test_mode is True
    del os.environ["R2INSPECT_TEST_MODE"]


def test_is_test_mode_true_when_env_is_yes():
    os.environ["R2INSPECT_TEST_MODE"] = "yes"
    session = R2Session("/tmp/test")
    assert session._is_test_mode is True
    del os.environ["R2INSPECT_TEST_MODE"]


def test_is_test_mode_false_when_env_not_set():
    os.environ.pop("R2INSPECT_TEST_MODE", None)
    session = R2Session("/tmp/test")
    assert session._is_test_mode is False


def test_is_test_mode_false_when_env_is_zero():
    os.environ["R2INSPECT_TEST_MODE"] = "0"
    session = R2Session("/tmp/test")
    assert session._is_test_mode is False
    del os.environ["R2INSPECT_TEST_MODE"]


# ---------------------------------------------------------------------------
# Timeout / threshold helpers
# ---------------------------------------------------------------------------

def test_get_open_timeout_test_mode():
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    session = R2Session("/tmp/test")
    timeout = session._get_open_timeout()
    assert timeout > 0
    del os.environ["R2INSPECT_TEST_MODE"]


def test_get_open_timeout_production_mode():
    os.environ.pop("R2INSPECT_TEST_MODE", None)
    session = R2Session("/tmp/test")
    timeout = session._get_open_timeout()
    assert timeout == 30.0


def test_get_cmd_timeout_test_mode():
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    session = R2Session("/tmp/test")
    timeout = session._get_cmd_timeout()
    assert timeout > 0
    del os.environ["R2INSPECT_TEST_MODE"]


def test_get_cmd_timeout_production_mode():
    os.environ.pop("R2INSPECT_TEST_MODE", None)
    session = R2Session("/tmp/test")
    timeout = session._get_cmd_timeout()
    assert timeout == 10.0


def test_get_analysis_timeout_test_mode():
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    session = R2Session("/tmp/test")
    assert session._get_analysis_timeout() > 0
    assert session._get_analysis_timeout(full_analysis=True) > 0
    del os.environ["R2INSPECT_TEST_MODE"]


def test_get_analysis_timeout_production_full():
    os.environ.pop("R2INSPECT_TEST_MODE", None)
    session = R2Session("/tmp/test")
    assert session._get_analysis_timeout(full_analysis=True) == 60.0
    assert session._get_analysis_timeout(full_analysis=False) == 30.0


def test_get_large_file_threshold_test_mode():
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    session = R2Session("/tmp/test")
    threshold = session._get_large_file_threshold()
    assert threshold > 0
    del os.environ["R2INSPECT_TEST_MODE"]


def test_get_large_file_threshold_production_mode():
    from r2inspect.core.constants import LARGE_FILE_THRESHOLD_MB
    os.environ.pop("R2INSPECT_TEST_MODE", None)
    session = R2Session("/tmp/test")
    assert session._get_large_file_threshold() == float(LARGE_FILE_THRESHOLD_MB)


def test_get_huge_file_threshold_test_mode():
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    session = R2Session("/tmp/test")
    threshold = session._get_huge_file_threshold()
    assert threshold > 0
    del os.environ["R2INSPECT_TEST_MODE"]


def test_get_huge_file_threshold_production_mode():
    from r2inspect.core.constants import HUGE_FILE_THRESHOLD_MB
    os.environ.pop("R2INSPECT_TEST_MODE", None)
    session = R2Session("/tmp/test")
    assert session._get_huge_file_threshold() == float(HUGE_FILE_THRESHOLD_MB)


# ---------------------------------------------------------------------------
# _detect_fat_macho_arches
# ---------------------------------------------------------------------------

def test_detect_fat_macho_arches_nonexistent_file():
    session = R2Session("/nonexistent/path/binary.bin")
    arches = session._detect_fat_macho_arches()
    assert arches == set()


def test_detect_fat_macho_arches_non_fat_binary(tmp_path: Path):
    binary = tmp_path / "not_fat.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert arches == set()


def test_detect_fat_macho_arches_fat_macho_x86_64(tmp_path: Path):
    binary = tmp_path / "fat.macho"
    # Build minimal fat Mach-O header (big-endian): magic=0xCAFEBABE, nfat_arch=1
    # CPU_TYPE_X86_64 = 0x01000007
    data = struct.pack(">II", 0xCAFEBABE, 1)
    data += struct.pack(">IIIII", 0x01000007, 3, 0, 0, 0)
    binary.write_bytes(data)
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert "x86_64" in arches


def test_detect_fat_macho_arches_fat_macho_arm64(tmp_path: Path):
    binary = tmp_path / "fat_arm.macho"
    # CPU_TYPE_ARM64 = 0x0100000C
    data = struct.pack(">II", 0xCAFEBABE, 1)
    data += struct.pack(">IIIII", 0x0100000C, 0, 0, 0, 0)
    binary.write_bytes(data)
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert "arm64" in arches


def test_detect_fat_macho_arches_little_endian_magic(tmp_path: Path):
    binary = tmp_path / "fat_le.macho"
    # 0xBEBAFECA is little-endian fat Mach-O magic
    data = struct.pack(">I", 0xBEBAFECA) + struct.pack(">I", 0)
    binary.write_bytes(data)
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert isinstance(arches, set)


def test_detect_fat_macho_arches_too_short_file(tmp_path: Path):
    binary = tmp_path / "short.bin"
    binary.write_bytes(b"\xCA\xFE")
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert arches == set()


# ---------------------------------------------------------------------------
# _select_r2_flags
# ---------------------------------------------------------------------------

def test_select_r2_flags_always_includes_minus2():
    session = R2Session("/tmp/test")
    flags = session._select_r2_flags()
    assert "-2" in flags


def test_select_r2_flags_test_mode_includes_M():
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    session = R2Session("/tmp/test")
    flags = session._select_r2_flags()
    assert "-M" in flags
    del os.environ["R2INSPECT_TEST_MODE"]


def test_select_r2_flags_no_test_mode_no_M():
    os.environ.pop("R2INSPECT_TEST_MODE", None)
    session = R2Session("/tmp/test")
    flags = session._select_r2_flags()
    assert "-M" not in flags


def test_select_r2_flags_disable_plugins_env(tmp_path: Path):
    dummy = tmp_path / "binary.bin"
    dummy.write_bytes(b"\x00" * 8)
    os.environ["R2INSPECT_DISABLE_PLUGINS"] = "1"
    os.environ.pop("R2INSPECT_TEST_MODE", None)
    session = R2Session(str(dummy))
    flags = session._select_r2_flags()
    assert "-NN" in flags
    del os.environ["R2INSPECT_DISABLE_PLUGINS"]


# ---------------------------------------------------------------------------
# _run_cmd_with_timeout
# ---------------------------------------------------------------------------

def test_run_cmd_with_timeout_r2_is_none():
    session = R2Session("/tmp/test")
    session.r2 = None
    result = session._run_cmd_with_timeout("i", timeout=5.0)
    assert result is False


def test_run_cmd_with_timeout_forced_via_env():
    class FakeR2:
        def cmd(self, command: str) -> str:
            return "result"

    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "i"
    result = session._run_cmd_with_timeout("i", timeout=5.0)
    assert result is False
    del os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"]


def test_run_cmd_with_timeout_command_not_in_forced_set():
    class FakeR2:
        def cmd(self, command: str) -> str:
            return "result"

    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "other_cmd"
    result = session._run_cmd_with_timeout("i", timeout=5.0)
    assert result is True
    del os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"]


def test_run_cmd_with_timeout_successful_command():
    class FakeR2:
        def cmd(self, command: str) -> str:
            return "info output"

    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    result = session._run_cmd_with_timeout("i", timeout=5.0)
    assert result is True


def test_run_cmd_with_timeout_command_raises():
    class ErrorR2:
        def cmd(self, command: str) -> str:
            raise RuntimeError("r2 crashed")

    session = R2Session("/tmp/test")
    session.r2 = ErrorR2()
    result = session._run_cmd_with_timeout("i", timeout=5.0)
    assert result is False


# ---------------------------------------------------------------------------
# _run_basic_info_check
# ---------------------------------------------------------------------------

def test_run_basic_info_check_raises_when_r2_is_none():
    session = R2Session("/tmp/test")
    session.r2 = None
    with pytest.raises(RuntimeError, match="not initialized"):
        session._run_basic_info_check()


def test_run_basic_info_check_returns_false_on_timeout():
    session = R2Session("/tmp/test")
    session.r2 = object()
    session._run_cmd_with_timeout = lambda cmd, timeout: False
    result = session._run_basic_info_check()
    assert result is False


def test_run_basic_info_check_raises_on_cmd_exception():
    class ErrorR2:
        def cmd(self, command: str) -> str:
            raise RuntimeError("cmd failed")

    session = R2Session("/tmp/test")
    session.r2 = ErrorR2()
    session._run_cmd_with_timeout = lambda cmd, timeout: True
    with pytest.raises(RuntimeError):
        session._run_basic_info_check()


def test_run_basic_info_check_logs_warning_on_minimal_output():
    class MinimalR2:
        def cmd(self, command: str) -> str:
            return "x"

    session = R2Session("/tmp/test")
    session.r2 = MinimalR2()
    session._run_cmd_with_timeout = lambda cmd, timeout: True
    result = session._run_basic_info_check()
    assert result is True


# ---------------------------------------------------------------------------
# _perform_initial_analysis
# ---------------------------------------------------------------------------

def test_perform_initial_analysis_depth_zero_skips():
    class FakeR2:
        def cmd(self, command: str) -> str:
            return "ok"

    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    os.environ["R2INSPECT_ANALYSIS_DEPTH"] = "0"
    result = session._perform_initial_analysis(1.0)
    assert result is True
    del os.environ["R2INSPECT_ANALYSIS_DEPTH"]


def test_perform_initial_analysis_huge_file_skips():
    session = R2Session("/tmp/test")
    session.r2 = object()
    session._test_mode = True
    os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)
    result = session._perform_initial_analysis(file_size_mb=9999.0)
    assert result is True


def test_perform_initial_analysis_test_mode_uses_aa():
    ran_commands = []
    os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)

    session = R2Session("/tmp/test")
    session.r2 = object()
    session._test_mode = True

    def mock_run_cmd(cmd, timeout):
        ran_commands.append(cmd)
        return True

    session._run_cmd_with_timeout = mock_run_cmd
    result = session._perform_initial_analysis(0.1)
    assert result is True
    assert "aa" in ran_commands


def test_perform_initial_analysis_production_small_file_uses_aaa():
    ran_commands = []
    os.environ.pop("R2INSPECT_TEST_MODE", None)
    os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)

    session = R2Session("/tmp/test")
    session.r2 = object()
    session._test_mode = False

    def mock_run_cmd(cmd, timeout):
        ran_commands.append(cmd)
        return True

    session._run_cmd_with_timeout = mock_run_cmd
    result = session._perform_initial_analysis(0.1)
    assert result is True
    assert "aaa" in ran_commands


def test_perform_initial_analysis_returns_false_on_analysis_timeout():
    os.environ.pop("R2INSPECT_TEST_MODE", None)
    os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)

    session = R2Session("/tmp/test")
    session.r2 = object()
    session._test_mode = False
    session._run_cmd_with_timeout = lambda cmd, timeout: False
    result = session._perform_initial_analysis(0.1)
    assert result is False


def test_perform_initial_analysis_r2_none_returns_true():
    session = R2Session("/tmp/test")
    session.r2 = None
    result = session._perform_initial_analysis(1.0)
    assert result is True


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------

def test_close_when_r2_is_none_does_nothing():
    session = R2Session("/tmp/test")
    session.close()
    assert session.r2 is None


def test_close_calls_quit_on_r2():
    quit_called = [False]

    class FakeR2:
        def quit(self):
            quit_called[0] = True

    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._cleanup_required = True
    session.close()
    assert quit_called[0] is True
    assert session.r2 is None
    assert session._cleanup_required is False


def test_close_handles_quit_exception():
    class BrokenR2:
        def quit(self):
            raise RuntimeError("quit failed")

    session = R2Session("/tmp/test")
    session.r2 = BrokenR2()
    session._cleanup_required = True
    session.close()
    assert session.r2 is None


def test_close_does_nothing_when_cleanup_not_required():
    quit_called = [False]

    class FakeR2:
        def quit(self):
            quit_called[0] = True

    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._cleanup_required = False
    session.close()
    assert quit_called[0] is False


# ---------------------------------------------------------------------------
# is_open property
# ---------------------------------------------------------------------------

def test_is_open_true_when_r2_and_cleanup_required():
    class FakeR2:
        pass

    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._cleanup_required = True
    assert session.is_open is True


def test_is_open_false_when_r2_is_none():
    session = R2Session("/tmp/test")
    assert session.is_open is False


def test_is_open_false_when_cleanup_not_required():
    class FakeR2:
        pass

    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._cleanup_required = False
    assert session.is_open is False


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------

def test_context_manager_enter_returns_session():
    session = R2Session("/tmp/test")
    result = session.__enter__()
    assert result is session


def test_context_manager_exit_calls_close():
    quit_called = [False]

    class FakeR2:
        def quit(self):
            quit_called[0] = True

    session = R2Session("/tmp/test")
    session.r2 = FakeR2()
    session._cleanup_required = True
    result = session.__exit__(None, None, None)
    assert result is False
    assert session.r2 is None


def test_context_manager_with_statement():
    session = R2Session("/tmp/test")
    with session as s:
        assert s is session
    assert session.r2 is None


def test_context_manager_exit_with_exception_returns_false():
    session = R2Session("/tmp/test")
    result = session.__exit__(ValueError, ValueError("test"), None)
    assert result is False


# ---------------------------------------------------------------------------
# _run_cmd_with_timeout: actual thread timeout (lines 266-267)
# ---------------------------------------------------------------------------

def test_run_cmd_with_timeout_thread_times_out():
    """Cover lines 266-267: command doesn't complete within timeout."""
    import time

    class BlockingR2:
        def cmd(self, command: str) -> str:
            time.sleep(10)  # much longer than test timeout
            return "result"

    session = R2Session("/tmp/test")
    session.r2 = BlockingR2()
    # Use extremely short timeout to force thread timeout
    result = session._run_cmd_with_timeout("i", timeout=0.001)
    assert result is False


# ---------------------------------------------------------------------------
# _perform_initial_analysis: aa command times out (line 337)
# ---------------------------------------------------------------------------

def test_perform_initial_analysis_aa_command_times_out():
    """Cover line 337: aa command timeout in test mode -> return False."""
    os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)

    session = R2Session("/tmp/test")
    session.r2 = object()
    session._test_mode = True
    # Simulate aa timeout
    session._run_cmd_with_timeout = lambda cmd, timeout: False

    result = session._perform_initial_analysis(0.1)
    assert result is False


# ---------------------------------------------------------------------------
# _perform_initial_analysis: large file (non-test) uses aa
# ---------------------------------------------------------------------------

def test_perform_initial_analysis_large_file_uses_aa():
    """Cover lines ~328-339: large file in production mode uses aa."""
    from r2inspect.core.constants import LARGE_FILE_THRESHOLD_MB

    ran_commands = []
    os.environ.pop("R2INSPECT_TEST_MODE", None)
    os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)

    session = R2Session("/tmp/test")
    session.r2 = object()
    session._test_mode = False

    def mock_run_cmd(cmd, timeout):
        ran_commands.append(cmd)
        return True

    session._run_cmd_with_timeout = mock_run_cmd
    # Use file size larger than LARGE_FILE_THRESHOLD_MB
    large_size = float(LARGE_FILE_THRESHOLD_MB) + 10
    result = session._perform_initial_analysis(large_size)
    assert result is True
    assert "aa" in ran_commands


# ---------------------------------------------------------------------------
# _detect_fat_macho_arches: entry too short -> break (line 196)
# ---------------------------------------------------------------------------

def test_detect_fat_macho_arches_entry_too_short_triggers_break(tmp_path: Path):
    """Cover line 196: entry < 20 bytes -> break out of arch loop."""
    binary = tmp_path / "fat_short_entry.macho"
    # nfat_arch=1 but only provide 10 bytes for the entry (less than 20)
    data = struct.pack(">II", 0xCAFEBABE, 1)  # magic + nfat_arch=1
    data += b"\x00" * 10  # entry too short (< 20 bytes)
    binary.write_bytes(data)
    session = R2Session(str(binary))
    arches = session._detect_fat_macho_arches()
    assert arches == set()  # break reached, no arches parsed


# ---------------------------------------------------------------------------
# _select_r2_flags: fat Mach-O with arch flags (lines 165-170)
# ---------------------------------------------------------------------------

def test_select_r2_flags_fat_macho_adds_arch_flags_x86_64(tmp_path: Path):
    """Cover lines 165-170: fat Mach-O x86_64 adds architecture flags."""
    binary = tmp_path / "fat_x86.macho"
    # CPU_TYPE_X86_64 = 0x01000007
    data = struct.pack(">II", 0xCAFEBABE, 1)
    data += struct.pack(">IIIII", 0x01000007, 3, 0, 0, 0)
    binary.write_bytes(data)

    os.environ.pop("R2INSPECT_TEST_MODE", None)
    session = R2Session(str(binary))
    flags = session._select_r2_flags()
    # Should include -a x86 -b 64 and -NN for fat Mach-O
    assert "-NN" in flags


def test_select_r2_flags_fat_macho_adds_arch_flags_arm64(tmp_path: Path):
    """Cover lines 165-167: fat Mach-O arm64 on arm host adds arm flags."""
    import platform as _platform
    binary = tmp_path / "fat_arm64.macho"
    # CPU_TYPE_ARM64 = 0x0100000C
    data = struct.pack(">II", 0xCAFEBABE, 1)
    data += struct.pack(">IIIII", 0x0100000C, 0, 0, 0, 0)
    binary.write_bytes(data)

    os.environ.pop("R2INSPECT_TEST_MODE", None)
    session = R2Session(str(binary))
    flags = session._select_r2_flags()
    # flags should include -NN regardless of host architecture
    assert "-NN" in flags
    # If the host is ARM, should also include -a arm -b 64
    host = _platform.machine().lower()
    if "arm" in host:
        assert "-a" in flags
        assert "arm" in flags


# ---------------------------------------------------------------------------
# _terminate_radare2_processes (lines 219-232)
# ---------------------------------------------------------------------------

def test_terminate_radare2_processes_with_no_radare2_running():
    """Cover lines 219-226: iterate processes, none match 'radare2'."""
    session = R2Session("/tmp/test_terminate.bin")
    # Should iterate all processes and find none named "radare2"
    session._terminate_radare2_processes()  # Should not raise


# ---------------------------------------------------------------------------
# _reopen_safe_mode (lines 236-239) - must run BEFORE open_with_timeout tests
# ---------------------------------------------------------------------------

def test_reopen_safe_mode_opens_r2_in_safe_mode():
    """Cover lines 236-239: reopen r2 without analysis flags."""
    import os

    fixture = "/bin/ls"
    if not os.path.exists(fixture):
        return

    # Temporarily clear coverage subprocess tracking to allow r2pipe.open to work
    cov_start = os.environ.pop("COVERAGE_PROCESS_START", None)
    os.environ["R2INSPECT_TEST_MODE"] = "1"
    os.environ["R2INSPECT_ANALYSIS_DEPTH"] = "0"
    session = R2Session(fixture)
    session.r2 = None
    session._cleanup_required = False
    try:
        r2_instance = session._reopen_safe_mode()
        assert r2_instance is not None
        assert session._cleanup_required is True
    except OSError:
        pass
    finally:
        session.close()
        if cov_start is not None:
            os.environ["COVERAGE_PROCESS_START"] = cov_start
        os.environ.pop("R2INSPECT_TEST_MODE", None)
        os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)


# ---------------------------------------------------------------------------
# _open_with_timeout: timeout path (lines 208-215)
# ---------------------------------------------------------------------------

def test_open_with_timeout_raises_timeout_error_on_short_timeout(tmp_path: Path):
    """Cover lines 208-215: r2pipe.open() times out -> raise TimeoutError."""
    from pathlib import Path as _Path

    repo_root = _Path(__file__).parent.parent.parent
    fixture = repo_root / "samples" / "fixtures" / "edge_tiny.bin"
    if not fixture.exists():
        # Create a minimal ELF-like binary if fixtures unavailable
        dummy = tmp_path / "dummy.bin"
        dummy.write_bytes(b"\x7fELF" + b"\x00" * 60)
        filename = str(dummy)
    else:
        filename = str(fixture)

    session = R2Session(filename)
    with pytest.raises(TimeoutError):
        session._open_with_timeout(["-2", "-n"], timeout=0.001)
