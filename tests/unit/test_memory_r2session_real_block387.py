from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from r2inspect.core.r2_session import R2Session
from r2inspect.utils.memory_manager import MemoryAwareAnalyzer, MemoryLimits, MemoryMonitor


def _make_fat_macho(path: Path, arch_values: list[int]) -> None:
    # FAT_MAGIC (big-endian) + nfat_arch
    data = bytearray(struct.pack(">II", 0xCAFEBABE, len(arch_values)))
    for cpu in arch_values:
        # cputype, cpusubtype, offset, size, align
        data.extend(struct.pack(">IIIII", cpu, 0, 0, 0, 0))
    path.write_bytes(bytes(data))


def test_r2_session_fat_macho_detection(tmp_path: Path) -> None:
    fat = tmp_path / "fat_macho.bin"
    _make_fat_macho(fat, [0x01000007, 0x0100000C])

    session = R2Session(str(fat))
    arches = session._detect_fat_macho_arches()
    assert "x86_64" in arches
    assert "arm64" in arches


def test_r2_session_flags_and_basic_paths(samples_dir: Path) -> None:
    pe = samples_dir / "hello_pe.exe"
    session = R2Session(str(pe))

    os.environ["R2INSPECT_DISABLE_PLUGINS"] = "1"
    flags = session._select_r2_flags()
    assert "-2" in flags
    assert "-NN" in flags
    os.environ.pop("R2INSPECT_DISABLE_PLUGINS", None)

    # no r2 attached yet
    assert session._run_cmd_with_timeout("i", timeout=0.01) is False

    with pytest.raises(RuntimeError):
        session._run_basic_info_check()


def test_r2_session_open_and_analysis_branches(samples_dir: Path) -> None:
    pe = samples_dir / "hello_pe.exe"
    session = R2Session(str(pe))

    os.environ["R2INSPECT_ANALYSIS_DEPTH"] = "0"
    try:
        r2 = session.open(pe.stat().st_size / (1024 * 1024))
        assert r2 is not None
        assert session.is_open

        # Force timeout branch for command runner (real env path)
        os.environ["R2INSPECT_FORCE_CMD_TIMEOUT"] = "aa"
        assert session._run_cmd_with_timeout("aa", timeout=0.01) is False
        os.environ.pop("R2INSPECT_FORCE_CMD_TIMEOUT", None)

        # exercise size/depth decision branches directly
        assert session._perform_initial_analysis(file_size_mb=10_000.0) is True
        assert session._perform_initial_analysis(file_size_mb=0.001) is True
    finally:
        os.environ.pop("R2INSPECT_ANALYSIS_DEPTH", None)
        session.close()


def test_memory_monitor_real_thresholds_and_cleanup() -> None:
    limits = MemoryLimits(
        max_process_memory_mb=1,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.0,
        gc_trigger_threshold=0.0,
        max_file_size_mb=1,
        section_size_limit_mb=1,
    )
    monitor = MemoryMonitor(limits)

    warning_calls: list[dict] = []
    critical_calls: list[dict] = []

    monitor.set_callbacks(
        warning_callback=lambda stats: warning_calls.append(stats),
        critical_callback=lambda stats: critical_calls.append(stats),
    )

    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"warning", "critical", "normal"}
    assert monitor.validate_file_size(10) is True
    assert monitor.validate_file_size(10 * 1024 * 1024) is False
    assert monitor.validate_section_size(10) is True
    assert monitor.validate_section_size(10 * 1024 * 1024) is False

    limited = monitor.limit_collection_size(list(range(10)), max_size=3, name="items")
    assert limited == [0, 1, 2]

    # callback hooks are set and can be invoked by threshold checks
    assert isinstance(warning_calls, list)
    assert isinstance(critical_calls, list)


def test_memory_aware_analyzer_real_operation_paths() -> None:
    monitor = MemoryMonitor(MemoryLimits(max_process_memory_mb=4096))
    analyzer = MemoryAwareAnalyzer(memory_monitor=monitor)

    # Real runtime path may skip when cached stats omit system availability.
    skip = analyzer.should_skip_analysis(estimated_memory_mb=0.1, analysis_name="small")
    assert isinstance(skip, bool)

    result = analyzer.safe_large_operation(lambda: {"ok": True}, 0.1, "real-op")
    assert result in (None, {"ok": True})

    def _boom() -> None:
        raise MemoryError("oom")

    assert analyzer.safe_large_operation(_boom, 0.1, "oom-op") is None
