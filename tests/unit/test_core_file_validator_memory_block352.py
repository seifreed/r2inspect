from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.core.constants import MIN_EXECUTABLE_SIZE_BYTES
from r2inspect.core.file_validator import FileValidator
from r2inspect.utils import memory_manager


def test_file_validator_basic(tmp_path: Path) -> None:
    missing = FileValidator(tmp_path / "missing.bin")
    assert missing.validate() is False

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert FileValidator(empty).validate() is False

    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"\x00" * (MIN_EXECUTABLE_SIZE_BYTES - 1))
    assert FileValidator(tiny).validate() is False

    good = tmp_path / "good.bin"
    good.write_bytes(b"\x00" * MIN_EXECUTABLE_SIZE_BYTES)
    assert FileValidator(good).validate() is True


def test_memory_limits_and_monitor(tmp_path: Path) -> None:
    original_limits = memory_manager.global_memory_monitor.limits
    try:
        memory_manager.configure_memory_limits(max_file_size_mb=0.0001)
        assert memory_manager.check_memory_limits(file_size_bytes=10**6) is False
    finally:
        memory_manager.global_memory_monitor.limits = original_limits

    monitor = memory_manager.MemoryMonitor(
        limits=memory_manager.MemoryLimits(
            max_process_memory_mb=1,
            memory_warning_threshold=0.0,
            memory_critical_threshold=0.0,
        )
    )

    warnings: list[str] = []
    criticals: list[str] = []

    def _warn(_stats: dict) -> None:
        warnings.append("warn")

    def _crit(_stats: dict) -> None:
        criticals.append("crit")

    monitor.set_callbacks(_warn, _crit)
    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"critical", "warning", "normal", "cached"}
    assert criticals or warnings

    assert monitor.validate_file_size(1) is True
    assert monitor.validate_section_size(1) is True
    assert monitor.limit_collection_size([1, 2, 3], 2, name="items") == [1, 2]

    analyzer = memory_manager.MemoryAwareAnalyzer(memory_monitor=monitor)
    assert analyzer.should_skip_analysis(estimated_memory_mb=0.1, analysis_name="x") is True

    def _op() -> str:
        return "ok"

    assert analyzer.safe_large_operation(_op, estimated_memory_mb=0.1, operation_name="op") is None

    assert memory_manager.cleanup_memory()["status"] in {
        "critical",
        "warning",
        "normal",
        "cached",
        "error",
    }
