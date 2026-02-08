from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from r2inspect.core.r2_session import R2Session
from r2inspect.utils import memory_manager
from r2inspect.utils.output import OutputFormatter


class FakeR2:
    def __init__(self, response: str = "i\n"):
        self.response = response
        self.commands: list[str] = []
        self.quit_called = False

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        return self.response

    def quit(self) -> None:
        self.quit_called = True


class FakeR2Error(FakeR2):
    def cmd(self, command: str) -> str:
        raise RuntimeError("boom")


class FakeR2Slow(FakeR2):
    def cmd(self, command: str) -> str:
        time.sleep(0.05)
        return "ok"


class FakeR2Dual(FakeR2):
    def __init__(self) -> None:
        super().__init__(response="ok")
        self._calls = 0

    def cmd(self, command: str) -> str:
        self._calls += 1
        if self._calls == 1:
            return "ok"
        raise RuntimeError("boom")


class TestSession(R2Session):
    def __init__(self, filename: str, fake_r2: FakeR2) -> None:
        super().__init__(filename)
        self._fake_r2 = fake_r2
        self._basic_ok = True
        self._analysis_ok = True

    def _open_with_timeout(self, flags: list[str], timeout: float) -> FakeR2:
        self._last_flags = list(flags)
        self._last_timeout = timeout
        return self._fake_r2

    def _run_basic_info_check(self) -> bool:
        return self._basic_ok

    def _perform_initial_analysis(self, file_size_mb: float) -> bool:
        return self._analysis_ok

    def _reopen_safe_mode(self) -> FakeR2:
        self._reopened = True
        self.r2 = self._fake_r2
        self._cleanup_required = True
        return self._fake_r2


class ErrorSession(TestSession):
    def _run_basic_info_check(self) -> bool:
        raise RuntimeError("basic error")


def _write_fat_macho(path: Path, arch_count: int = 2) -> None:
    # Fat Mach-O magic 0xCAFEBABE, big-endian
    data = bytearray()
    data += (0xCAFEBABE).to_bytes(4, "big")
    data += arch_count.to_bytes(4, "big")
    # Write 2 arch entries (20 bytes each): cputype + 16 bytes padding
    # x86_64 = 0x01000007, arm64 = 0x0100000C
    data += (0x01000007).to_bytes(4, "big") + b"\x00" * 16
    data += (0x0100000C).to_bytes(4, "big") + b"\x00" * 16
    path.write_bytes(data)


def test_r2_session_flags_and_fat_arches(tmp_path: Path, monkeypatch) -> None:
    test_file = tmp_path / "fat.bin"
    _write_fat_macho(test_file)

    session = R2Session(str(test_file))
    monkeypatch.setenv("R2INSPECT_DISABLE_PLUGINS", "1")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    flags = session._select_r2_flags()
    assert "-NN" in flags
    assert "-a" in flags and "-b" in flags

    arches = session._detect_fat_macho_arches()
    assert "x86_64" in arches
    assert "arm64" in arches


def test_r2_session_flags_arm_host(tmp_path: Path, monkeypatch) -> None:
    test_file = tmp_path / "fat_arm.bin"
    _write_fat_macho(test_file)
    session = R2Session(str(test_file))
    monkeypatch.setattr("platform.machine", lambda: "arm64")
    flags = session._select_r2_flags()
    assert "-a" in flags and "-b" in flags


def test_r2_session_open_paths(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"TEST")

    fake = FakeR2()
    session = TestSession(str(test_file), fake)
    opened = session.open(file_size_mb=1.0)
    assert opened is fake
    assert session.is_open is True

    session._basic_ok = False
    session.open(file_size_mb=1.0)
    assert getattr(session, "_reopened", False) is True

    session._basic_ok = True
    session._analysis_ok = False
    session.open(file_size_mb=1.0)
    assert getattr(session, "_reopened", False) is True


def test_r2_session_open_error_path(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"TEST")

    fake = FakeR2()
    session = ErrorSession(str(test_file), fake)
    assert session.open(file_size_mb=1.0) == ""
    assert session.is_open is False


def test_r2_session_cmd_timeouts_and_basic_info(monkeypatch) -> None:
    session = R2Session("/tmp/sample")
    session.r2 = FakeR2(response="i\n")
    session._cleanup_required = True

    monkeypatch.setenv("R2INSPECT_FORCE_CMD_TIMEOUT", "i")
    assert session._run_cmd_with_timeout("i", 0.01) is False

    monkeypatch.delenv("R2INSPECT_FORCE_CMD_TIMEOUT", raising=False)
    assert session._run_cmd_with_timeout("i", 0.5) is True

    # Basic info check should pass with minimal response
    assert session._run_basic_info_check() is True

    # Error path when command raises
    session.r2 = FakeR2Error()
    assert session._run_cmd_with_timeout("i", 0.1) is False


def test_r2_session_basic_info_errors() -> None:
    session = R2Session("/tmp/sample")
    with pytest.raises(RuntimeError):
        session._run_basic_info_check()

    session.r2 = FakeR2Error()
    assert session._run_basic_info_check() is False

    session.r2 = FakeR2Dual()
    with pytest.raises(RuntimeError):
        session._run_basic_info_check()


def test_r2_session_initial_analysis_paths(monkeypatch) -> None:
    session = R2Session("/tmp/sample")
    session.r2 = FakeR2()

    # Large sizes should short-circuit to True
    assert session._perform_initial_analysis(file_size_mb=10_000) is True
    assert session._perform_initial_analysis(file_size_mb=1_000) is True
    assert session._perform_initial_analysis(file_size_mb=10) is True
    assert session._perform_initial_analysis(file_size_mb=1) is True

    # Force command timeouts to hit False path
    monkeypatch.setenv("R2INSPECT_FORCE_CMD_TIMEOUT", "aa,aaa")
    assert session._perform_initial_analysis(file_size_mb=1) is False
    assert session._perform_initial_analysis(file_size_mb=10) is False

    # None r2 path
    session.r2 = None
    assert session._perform_initial_analysis(file_size_mb=1) is True


def test_r2_session_close_and_context_manager() -> None:
    session = R2Session("/tmp/sample")
    session.r2 = FakeR2()
    session._cleanup_required = True

    assert session.is_open is True
    session.close()
    assert session.is_open is False

    with R2Session("/tmp/sample") as ctx:
        assert ctx.is_open is False


def test_r2_session_run_cmd_timeout() -> None:
    session = R2Session("/tmp/sample")
    session.r2 = FakeR2Slow()
    assert session._run_cmd_with_timeout("i", 0.001) is False
    session.r2 = None
    assert session._run_cmd_with_timeout("i", 0.1) is False


def test_r2_session_close_error() -> None:
    class BadQuit(FakeR2):
        def quit(self) -> None:
            raise RuntimeError("boom")

    session = R2Session("/tmp/sample")
    session.r2 = BadQuit()
    session._cleanup_required = True
    session.close()
    assert session.r2 is None


def test_r2_session_open_with_timeout_failure(tmp_path: Path) -> None:
    test_file = tmp_path / "slow.bin"
    test_file.write_bytes(b"MZ" + b"0" * 128)

    session = R2Session(str(test_file))
    with pytest.raises(TimeoutError):
        session._open_with_timeout(flags=["-2"], timeout=0.0)

    # Should not raise if no matching processes
    session._terminate_radare2_processes()
    # Exercise safe reopen path
    session.r2 = FakeR2()
    reopened = session._reopen_safe_mode()
    assert reopened is not None


def test_r2_session_terminate_process_exceptions(monkeypatch) -> None:
    class DummyProc:
        def __init__(self, name: str, cmdline: list[str]) -> None:
            self.info = {"name": name, "cmdline": cmdline}

        def terminate(self) -> None:
            import psutil

            raise psutil.AccessDenied(pid=123, name="radare2")

    def fake_iter(_fields):
        return [DummyProc("radare2", ["/tmp/sample"])]

    monkeypatch.setattr("psutil.process_iter", fake_iter)
    session = R2Session("/tmp/sample")
    session._terminate_radare2_processes()


def test_r2_session_detect_fat_macho_variants(tmp_path: Path, monkeypatch) -> None:
    # Little-endian magic with truncated arch entry
    test_file = tmp_path / "fat_le.bin"
    data = bytearray()
    data += (0xBEBAFECA).to_bytes(4, "big")
    data += (2).to_bytes(4, "little")
    data += (0x01000007).to_bytes(4, "little") + b"\x00" * 4
    test_file.write_bytes(data)

    session = R2Session(str(test_file))
    arches = session._detect_fat_macho_arches()
    assert isinstance(arches, set)

    missing = R2Session(str(tmp_path / "missing.bin"))
    assert missing._detect_fat_macho_arches() == set()

    invalid_magic = tmp_path / "not_fat.bin"
    invalid_magic.write_bytes(b"\x00" * 8)
    invalid = R2Session(str(invalid_magic))
    assert invalid._detect_fat_macho_arches() == set()

    monkeypatch.setenv("R2INSPECT_DISABLE_PLUGINS", "true")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    flags = session._select_r2_flags()
    assert "-a" not in flags and "-b" not in flags


def test_r2_session_basic_info_timeout(monkeypatch) -> None:
    session = R2Session("/tmp/sample")
    session.r2 = FakeR2()
    monkeypatch.setenv("R2INSPECT_FORCE_CMD_TIMEOUT", "i")
    assert session._run_basic_info_check() is False
    monkeypatch.delenv("R2INSPECT_FORCE_CMD_TIMEOUT", raising=False)


def test_memory_manager_thresholds_and_helpers(monkeypatch) -> None:
    limits = memory_manager.MemoryLimits(
        max_process_memory_mb=1,
        memory_warning_threshold=0.1,
        memory_critical_threshold=0.2,
        gc_trigger_threshold=0.05,
        max_file_size_mb=0.0001,
        section_size_limit_mb=0.0001,
    )
    monitor = memory_manager.MemoryMonitor(limits=limits)

    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"warning", "critical", "normal"}

    assert monitor.validate_file_size(1024 * 1024) is False
    assert monitor.validate_section_size(1024 * 1024) is False

    collection = list(range(10))
    assert monitor.limit_collection_size(collection, 3) == [0, 1, 2]

    called = {"warn": 0, "crit": 0}

    def warn_cb(_stats):
        called["warn"] += 1

    def crit_cb(_stats):
        called["crit"] += 1

    monitor.set_callbacks(warn_cb, crit_cb)
    monitor._handle_warning_memory(stats)
    monitor._handle_critical_memory(stats)
    assert called["warn"] >= 1
    assert called["crit"] >= 1

    assert monitor.is_memory_available(0.001) in {True, False}

    # Global helpers
    memory_manager.configure_memory_limits(max_file_size_mb=1)
    memory_manager.cleanup_memory()


def test_memory_manager_cached_and_error_paths() -> None:
    limits = memory_manager.MemoryLimits(max_process_memory_mb=1)
    monitor = memory_manager.MemoryMonitor(limits=limits)
    # Cached path
    stats_cached = monitor.check_memory(force=False)
    assert stats_cached["status"] in {"cached", "warning", "critical", "normal"}

    class BadProcess:
        def memory_info(self) -> object:
            raise RuntimeError("boom")

    monitor.process = BadProcess()  # type: ignore[assignment]
    stats_error = monitor.check_memory(force=True)
    assert stats_error["status"] == "error"

    stats_cached_error = monitor._get_cached_stats()
    assert stats_cached_error["status"] == "error"


def test_output_formatter_branches() -> None:
    results = {
        "file_info": {"name": "sample", "size": 0, "file_type": "PE32 executable, 7 sections"},
        "pe_info": {"compile_time": "2026", "imphash": "imphash"},
        "ssdeep": {"hash_value": "ss"},
        "tlsh": {
            "binary_tlsh": "bt",
            "text_section_tlsh": "tt",
            "stats": {"functions_with_tlsh": 1},
        },
        "telfhash": {"telfhash": "th", "filtered_symbols": 2},
        "rich_header": {
            "xor_key": 1,
            "checksum": 2,
            "richpe_hash": "rh",
            "compilers": [{"compiler_name": "MSVC", "count": 2}],
        },
        "imports": [{"name": "CreateFileA"}],
        "exports": ["Export"],
        "sections": [{"name": ".text", "raw_size": 1, "flags": "r-x", "entropy": 4.0}],
        "anti_analysis": {"anti_debug": True, "anti_vm": False, "anti_sandbox": False},
        "compiler": {"compiler": "MSVC", "version": "1", "confidence": 0.5},
        "functions": {"total_functions": 2, "machoc_hashes": {"a": "h1", "b": "h1"}},
        "yara_matches": [{"rule": "rule1"}],
        "indicators": [{"type": "Anti", "description": "x"}],
        "packer": {"is_packed": True, "packer_type": "UPX", "confidence": 0.9},
    }

    formatter = OutputFormatter(results)
    json_text = formatter.to_json()
    assert "sample" in json_text

    csv_text = formatter.to_csv()
    assert "ssdeep_hash" in csv_text

    # format table/sections/imports and summary
    table = formatter.format_table({"a": 1})
    sections_table = formatter.format_sections(results["sections"])
    imports_table = formatter.format_imports(
        [
            {
                "name": "CreateFileA",
                "library": "KERNEL32",
                "category": "File",
                "risk_score": 90,
                "risk_level": "Critical",
                "risk_tags": ["a", "b", "c"],
            }
        ]
    )
    assert table is not None
    assert sections_table is not None
    assert imports_table is not None

    summary = formatter.format_summary()
    assert "YARA Matches" in summary

    # error in _extract_csv_data fallback
    bad_formatter = OutputFormatter({"file_info": object()})
    csv_bad = bad_formatter.to_csv()
    assert "CSV Export Failed" in csv_bad

    # summary error path
    formatter_error = OutputFormatter({"file_info": object()})
    summary_error = formatter_error.format_summary()
    assert "Error generating summary" in summary_error
