from __future__ import annotations

import time
from pathlib import Path

import pytest

from r2inspect.config import Config
from r2inspect.factory import create_inspector
from r2inspect.utils import magic_detector
from r2inspect.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    R2CommandCircuitBreaker,
)
from r2inspect.utils.memory_manager import (
    MemoryAwareAnalyzer,
    MemoryLimits,
    MemoryMonitor,
    check_memory_limits,
    cleanup_memory,
    configure_memory_limits,
    get_memory_stats,
)


class _BoomR2:
    def cmdj(self, _command: str) -> None:
        raise RuntimeError("boom")

    def cmd(self, _command: str) -> None:
        raise RuntimeError("boom")


def _write_file(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def test_circuit_breaker_states_and_reset() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01, name="test")

    with pytest.raises(ValueError):
        breaker.call(lambda: (_ for _ in ()).throw(ValueError("fail")))

    assert breaker.state == CircuitState.OPEN

    with pytest.raises(CircuitBreakerError):
        breaker.call(lambda: "ok")

    time.sleep(0.02)
    assert breaker.call(lambda: "ok") == "ok"
    assert breaker.state == CircuitState.CLOSED

    stats = breaker.get_stats()
    assert stats["state"] == "closed"

    breaker.reset()
    assert breaker.failure_count == 0

    @breaker
    def _ok() -> str:
        return "ok"

    assert _ok() == "ok"


def test_r2_command_circuit_breaker_stats() -> None:
    circuit = R2CommandCircuitBreaker()

    _ = circuit.get_breaker("analysis")
    _ = circuit.get_breaker("/x")

    result = circuit.execute_command(_BoomR2(), "ij", command_type="info")
    assert result is None

    result = circuit.execute_command(_BoomR2(), "i", command_type="info")
    assert result == ""

    stats = circuit.get_stats()
    assert "command_info" in stats

    circuit.reset_all()
    assert circuit.command_stats == {}


def test_magic_detector_formats_and_fallback(tmp_path: Path) -> None:
    detector = magic_detector.MagicByteDetector()

    pe_file = tmp_path / "sample.exe"
    pe_header = bytearray(b"MZ" + b"\x00" * 62)
    pe_offset = 0x80
    pe_header[60:64] = pe_offset.to_bytes(4, "little")
    pe_data = pe_header + bytearray(pe_offset - len(pe_header)) + b"PE\x00\x00" + b"\x64\x86"
    _write_file(pe_file, bytes(pe_data))

    pe_result = detector.detect_file_type(str(pe_file))
    assert pe_result["file_format"].startswith("PE")
    assert pe_result["is_executable"] is True

    elf_file = tmp_path / "sample.elf"
    elf_header = bytearray(b"\x7fELF\x02\x01" + b"\x00" * 12)
    elf_header[18:20] = (0x3E).to_bytes(2, "little")
    _write_file(elf_file, bytes(elf_header))

    elf_result = detector.detect_file_type(str(elf_file))
    assert elf_result["file_format"].startswith("ELF")
    assert elf_result["architecture"] in {"x86-64", "Unknown-003e"}

    macho_file = tmp_path / "sample.macho"
    macho_header = bytearray(b"\xfe\xed\xfa\xce") + (7).to_bytes(4, "big")
    _write_file(macho_file, bytes(macho_header))
    macho_result = detector.detect_file_type(str(macho_file))
    assert "MACHO" in macho_result["file_format"]

    docx_file = tmp_path / "sample.docx"
    _write_file(docx_file, b"PK\x03\x04word/[Content_Types].xml")
    docx_result = detector.detect_file_type(str(docx_file))
    assert docx_result["file_format"] in {"DOCX", "ZIP"}

    script_file = tmp_path / "script.bat"
    _write_file(script_file, b"#!/bin/sh\neval('x')\n")
    script_result = detector.detect_file_type(str(script_file))
    assert script_result["format_category"] in {"Script", "Executable"}

    unknown_file = tmp_path / "unknown.bin"
    _write_file(unknown_file, b"\x00\x01\x02")
    unknown_result = detector.detect_file_type(str(unknown_file))
    assert unknown_result["file_format"] == "Unknown"

    cached = detector.detect_file_type(str(unknown_file))
    assert cached["file_format"] == "Unknown"

    missing = detector.detect_file_type(str(tmp_path / "missing.bin"))
    assert missing["file_size"] == 0

    assert magic_detector.is_executable_file(str(pe_file)) is True
    assert magic_detector.get_file_threat_level(str(pe_file)) == "High"


def test_memory_manager_thresholds_and_helpers() -> None:
    limits = MemoryLimits(
        max_process_memory_mb=1000,
        max_file_size_mb=1,
        memory_warning_threshold=0.0,
        memory_critical_threshold=2.0,
        gc_trigger_threshold=0.0,
    )
    monitor = MemoryMonitor(limits=limits)

    warned = {"called": False}

    def _warn_callback(_stats: dict[str, object]) -> None:
        warned["called"] = True

    monitor.set_callbacks(warning_callback=_warn_callback)
    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"warning", "critical"}
    assert warned["called"] is True

    critical_limits = MemoryLimits(
        max_process_memory_mb=1,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.0,
    )
    critical_monitor = MemoryMonitor(limits=critical_limits)
    crit_stats = critical_monitor.check_memory(force=True)
    assert crit_stats["status"] == "critical"

    assert monitor.validate_file_size(2 * 1024 * 1024) is False
    assert monitor.validate_section_size(200 * 1024 * 1024) is False

    assert monitor.limit_collection_size([1, 2, 3], 2, "test") == [1, 2]

    analyzer = MemoryAwareAnalyzer(memory_monitor=monitor)
    assert analyzer.should_skip_analysis(estimated_memory_mb=10.0, analysis_name="test") is True

    ok = analyzer.safe_large_operation(lambda: 42, estimated_memory_mb=0.0, operation_name="ok")
    assert ok == 42

    def _raise_mem() -> None:
        raise MemoryError("boom")

    assert analyzer.safe_large_operation(_raise_mem, estimated_memory_mb=0.0) is None

    assert isinstance(get_memory_stats(), dict)
    configure_memory_limits(max_file_size_mb=1)
    assert check_memory_limits(file_size_bytes=2 * 1024 * 1024) is False

    configure_memory_limits(max_file_size_mb=2, unknown_limit=1)  # type: ignore[arg-type]
    assert cleanup_memory()["status"] in {"normal", "warning", "critical", "cached", "error"}


@pytest.mark.requires_r2
def test_r2_command_circuit_breaker_success_path(tmp_path: Path) -> None:
    config = Config(str(tmp_path / "r2inspect_cb.json"))
    with create_inspector(
        filename="samples/fixtures/hello_pe.exe",
        config=config,
        verbose=False,
    ) as inspector:
        adapter = inspector.adapter
        circuit = R2CommandCircuitBreaker()
        result = circuit.execute_command(adapter, "ij", command_type="info")
        assert result is not None
