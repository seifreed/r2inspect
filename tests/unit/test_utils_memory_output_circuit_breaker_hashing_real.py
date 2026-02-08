from __future__ import annotations

import time
from pathlib import Path

import pytest

from r2inspect.utils import hashing, ssdeep_loader
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
from r2inspect.utils.output import OutputFormatter
from r2inspect.utils.ssdeep_loader import get_ssdeep


def test_hashing_utils_real(tmp_path: Path) -> None:
    data_path = tmp_path / "data.bin"
    data_path.write_bytes(b"abcd" * 10)

    hashes = hashing.calculate_hashes(str(data_path))
    assert hashes["md5"]
    assert hashes["sha256"]

    missing = hashing.calculate_hashes(str(tmp_path / "missing.bin"))
    assert missing["md5"] == ""

    imphash = hashing.calculate_imphash([{"library": "KERNEL32.dll", "name": "CreateFileA"}])
    assert imphash
    assert hashing.calculate_imphash([]) is None
    assert hashing.calculate_imphash([{"library": "", "name": ""}]) is None

    ssdeep = hashing.calculate_ssdeep(str(data_path))
    assert ssdeep is None or isinstance(ssdeep, str)

    error_hashes = hashing.calculate_hashes(str(tmp_path))
    assert error_hashes["md5"].startswith("Error:")

    class BadImport:
        def get(self, *_args: object, **_kwargs: object) -> str:
            raise RuntimeError("boom")

    assert hashing.calculate_imphash([BadImport()]) is None

    ssdeep_module = get_ssdeep()
    if ssdeep_module is not None:
        ssdeep_error = hashing.calculate_ssdeep(str(tmp_path))
        assert ssdeep_error is None

    original_ssdeep = ssdeep_loader._ssdeep_module

    class BadSsdeep:
        def hash_from_file(self, _path: str) -> str:
            raise RuntimeError("boom")

    ssdeep_loader._ssdeep_module = BadSsdeep()
    try:
        assert hashing.calculate_ssdeep(str(data_path)) is None
    finally:
        ssdeep_loader._ssdeep_module = original_ssdeep


def test_memory_monitor_and_analyzer_branches() -> None:
    limits = MemoryLimits(
        max_process_memory_mb=1,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.0,
        gc_trigger_threshold=0.0,
    )
    monitor = MemoryMonitor(limits=limits)

    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"warning", "critical"}

    assert monitor.validate_file_size(1) is True
    assert monitor.validate_section_size(1) is True
    assert monitor.limit_collection_size([1, 2, 3], 2, name="items") == [1, 2]

    def op() -> int:
        return 1

    analyzer = MemoryAwareAnalyzer(monitor)
    assert analyzer.safe_large_operation(op, 0.0, "op") is None

    relaxed_limits = MemoryLimits(
        max_process_memory_mb=4096,
        memory_warning_threshold=1.0,
        memory_critical_threshold=1.0,
        gc_trigger_threshold=1.0,
    )
    relaxed_monitor = MemoryMonitor(limits=relaxed_limits)
    relaxed_analyzer = MemoryAwareAnalyzer(relaxed_monitor)
    assert relaxed_analyzer.safe_large_operation(op, 0.0, "op") == 1

    def mem_error() -> int:
        raise MemoryError("boom")

    assert analyzer.safe_large_operation(mem_error, 0.0, "mem") is None

    def generic_error() -> int:
        raise RuntimeError("boom")

    assert analyzer.safe_large_operation(generic_error, 0.0, "generic") is None
    assert relaxed_analyzer.safe_large_operation(mem_error, 0.0, "mem") is None
    assert relaxed_analyzer.safe_large_operation(generic_error, 0.0, "generic") is None


def test_memory_monitor_callbacks_and_errors() -> None:
    warning_hits: list[str] = []
    critical_hits: list[str] = []

    def warning_cb(_stats: dict[str, object]) -> None:
        warning_hits.append("warn")
        raise RuntimeError("warn")

    def critical_cb(_stats: dict[str, object]) -> None:
        critical_hits.append("crit")
        raise RuntimeError("crit")

    warning_limits = MemoryLimits(
        max_process_memory_mb=100000,
        memory_warning_threshold=0.0,
        memory_critical_threshold=1.0,
        gc_trigger_threshold=1.5,
    )
    warning_monitor = MemoryMonitor(limits=warning_limits)
    warning_monitor.set_callbacks(warning_callback=warning_cb)
    warning_stats = warning_monitor.check_memory(force=True)
    assert warning_stats["status"] == "warning"
    assert warning_hits

    critical_limits = MemoryLimits(
        max_process_memory_mb=1,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.0,
        gc_trigger_threshold=0.0,
    )
    critical_monitor = MemoryMonitor(limits=critical_limits)
    critical_monitor.set_callbacks(critical_callback=critical_cb)
    critical_stats = critical_monitor.check_memory(force=True)
    assert critical_stats["status"] == "critical"
    assert critical_hits

    gc_limits = MemoryLimits(
        max_process_memory_mb=4096,
        memory_warning_threshold=1.0,
        memory_critical_threshold=1.0,
        gc_trigger_threshold=0.0,
    )
    gc_monitor = MemoryMonitor(limits=gc_limits)
    gc_before = gc_monitor.gc_count
    gc_monitor.check_memory(force=True)
    assert gc_monitor.gc_count > gc_before

    class BadProcess:
        def memory_info(self) -> object:
            raise RuntimeError("boom")

    warning_monitor.process = BadProcess()
    cached_stats = warning_monitor._get_cached_stats()
    assert cached_stats["status"] == "error"

    warning_monitor.process = BadProcess()
    error_stats = warning_monitor.check_memory(force=True)
    assert error_stats["status"] == "error"

    warning_monitor._trigger_gc(aggressive=True)
    assert warning_monitor.gc_count >= 1

    assert warning_monitor.is_memory_available(1024 * 1024) is False

    assert warning_monitor.validate_file_size(10**12) is False
    assert warning_monitor.validate_section_size(10**12) is False
    assert warning_monitor.limit_collection_size([1], 2, name="items") == [1]

    stats = get_memory_stats()
    assert "process_memory_mb" in stats

    assert check_memory_limits(file_size_bytes=10**12, estimated_analysis_mb=0) is False
    assert check_memory_limits(file_size_bytes=0, estimated_analysis_mb=0) is True

    configure_memory_limits(unknown_limit=123)
    configure_memory_limits(max_process_memory_mb=2048)
    cleanup = cleanup_memory()
    assert cleanup["status"] in {"normal", "warning", "critical", "cached", "error"}


def test_circuit_breaker_branches() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=60.0)

    def ok() -> int:
        return 1

    def fail() -> int:
        raise RuntimeError("boom")

    assert breaker.call(ok) == 1
    with pytest.raises(RuntimeError):
        breaker.call(fail)

    with pytest.raises(CircuitBreakerError):
        breaker.call(ok)

    breaker.reset()
    assert breaker.call(ok) == 1

    assert breaker._should_attempt_reset() is False


def test_circuit_breaker_decorator_and_half_open() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.0)

    @breaker
    def ok() -> int:
        return 1

    def fail() -> int:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        breaker.call(fail)

    assert ok() == 1


def test_r2_command_circuit_breaker_real() -> None:
    from r2inspect.core.r2_session import R2Session

    fixture = Path("samples/fixtures/hello_pe.exe")
    session = R2Session(str(fixture))
    r2 = session.open(fixture.stat().st_size / (1024 * 1024))

    breaker = R2CommandCircuitBreaker()
    assert breaker.execute_command(r2, "ij", "analysis") is not None
    assert breaker.execute_command(r2, "i", "generic") != ""

    r2.quit()
    # After quit, command should fail and return safe default
    result = breaker.execute_command(r2, "ij", "analysis")
    assert result is None or result == {}

    stats = breaker.get_stats()
    assert any(key.startswith("command_") for key in stats)
    breaker.reset_all()


def test_r2_command_circuit_breaker_error_paths() -> None:
    breaker = R2CommandCircuitBreaker()

    class BadR2:
        def cmd(self, _command: str) -> str:
            raise RuntimeError("boom")

        def cmdj(self, _command: str) -> dict[str, object]:
            raise RuntimeError("boom")

    bad_r2 = BadR2()
    assert breaker.execute_command(bad_r2, "i", "generic") == ""
    assert breaker.execute_command(bad_r2, "ij", "search") is None

    search_breaker = breaker.get_breaker("/x")
    assert search_breaker.failure_threshold == 7

    generic_breaker = breaker.get_breaker("generic")
    generic_breaker.state = CircuitState.OPEN
    generic_breaker.last_failure_time = time.time()
    generic_breaker.recovery_timeout = 1000.0
    result = breaker.execute_command(bad_r2, "ij", "generic")
    assert result is None


def test_output_formatter_more_edges() -> None:
    results = {
        "file_info": {
            "name": "sample",
            "size": 0,
            "file_type": "PE32 executable, 7 sections",
            "md5": "m",
        },
        "imports": ["CreateFileA"],
        "exports": [{"name": "Export"}],
        "sections": [{"name": ".text"}],
        "anti_analysis": {"anti_debug": True, "anti_vm": False, "anti_sandbox": True},
        "compiler": {"compiler": "MSVC", "version": "1", "confidence": 0.5},
        "functions": {"total_functions": 2, "machoc_hashes": {"a": "h1", "b": "h1"}},
    }
    formatter = OutputFormatter(results)
    csv_text = formatter.to_csv()
    assert "sample" in csv_text

    table = formatter.format_table({"key": {"nested": 1}}, title="t")
    assert table is not None

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
    assert imports_table is not None

    summary = formatter.format_summary()
    assert "ANALYSIS SUMMARY" in summary


def test_output_formatter_error_branches() -> None:
    class BadStr:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    formatter = OutputFormatter({"file_info": {"name": BadStr()}})
    json_text = formatter.to_json()
    assert "JSON serialization failed" in json_text

    class BadMapping:
        def get(self, *_args: object, **_kwargs: object) -> object:
            raise RuntimeError("boom")

    formatter = OutputFormatter(BadMapping())  # type: ignore[arg-type]
    csv_text = formatter.to_csv()
    assert "CSV Export Failed" in csv_text

    formatter = OutputFormatter({"imports": "bad"})
    assert formatter._extract_names_from_list({"imports": "bad"}, "imports") == ""

    assert formatter._format_file_size("bad") == "bad"

    assert formatter._format_file_size(0) == "0 B"
    assert formatter._format_file_size(1024) == "1.0 KB"
    assert formatter._format_file_size(1) == "1 B"

    class BadType:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    formatter = OutputFormatter({"file_info": {"file_type": BadType()}})
    bad_type = BadType()
    assert formatter._clean_file_type(bad_type) is bad_type

    formatter = OutputFormatter(
        {
            "pe_info": {"compile_time": "123"},
            "elf_info": {"compile_time": "456"},
            "macho_info": {"compile_time": "789"},
            "file_info": {"compile_time": "000"},
        }
    )
    assert formatter._extract_compile_time(formatter.results) == "123"
    assert formatter._extract_compile_time({"elf_info": {"compile_time": "456"}}) == "456"
    assert formatter._extract_compile_time({"macho_info": {"compile_time": "789"}}) == "789"
    assert formatter._extract_compile_time({"file_info": {"compile_time": "000"}}) == "000"
    assert formatter._extract_imphash({"pe_info": {"imphash": "abc"}}) == "abc"

    formatter = OutputFormatter(
        {
            "rich_header": {
                "xor_key": 1,
                "checksum": 2,
                "richpe_hash": "hash",
                "compilers": [{"compiler_name": "MSC", "count": 2}],
            }
        }
    )
    csv_row = formatter._extract_csv_data(formatter.results)
    assert csv_row["rich_header_compilers"] == "MSC(2)"

    sections_table = formatter.format_sections(
        [{"name": ".text", "raw_size": 1, "flags": "r-x", "entropy": 1.23}]
    )
    assert sections_table is not None

    imports_table = formatter.format_imports(
        [
            {"name": "A", "library": "K", "category": "C", "risk_score": 10, "risk_level": "Low"},
            {
                "name": "B",
                "library": "K",
                "category": "C",
                "risk_score": 55,
                "risk_level": "Medium",
                "risk_tags": ["x", "y", "z"],
            },
            {
                "name": "C",
                "library": "K",
                "category": "C",
                "risk_score": 80,
                "risk_level": "High",
                "risk_tags": [],
            },
            {
                "name": "D",
                "library": "K",
                "category": "C",
                "risk_score": 1,
                "risk_level": "Minimal",
                "risk_tags": [],
            },
        ]
    )
    assert imports_table is not None

    class BadSummary:
        def get(self, *_args: object, **_kwargs: object) -> object:
            raise RuntimeError("boom")

    formatter = OutputFormatter(BadSummary())  # type: ignore[arg-type]
    summary = formatter.format_summary()
    assert "Error generating summary" in summary

    formatter = OutputFormatter(
        {
            "file_info": {"name": "x", "size": 1, "file_type": "PE", "md5": "m"},
            "indicators": [{"type": "a", "description": "b"}] * 6,
            "packer": {"is_packed": True, "packer_type": "p", "confidence": 0.5},
            "yara_matches": [{"rule": "r"}] * 4,
        }
    )
    summary = formatter.format_summary()
    assert "Packer Detected" in summary

    formatter = OutputFormatter({"imports": []})
    summary = formatter.format_summary()
    assert "ANALYSIS SUMMARY" in summary

    table = formatter.format_table({"answer": 42}, title="T")
    assert table is not None
