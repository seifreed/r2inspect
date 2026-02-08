from __future__ import annotations

import hashlib

import pytest

from r2inspect.core.result_aggregator import ResultAggregator
from r2inspect.utils.hashing import calculate_hashes, calculate_imphash, calculate_ssdeep
from r2inspect.utils.memory_manager import (
    MemoryAwareAnalyzer,
    MemoryLimits,
    MemoryMonitor,
    cleanup_memory,
    configure_memory_limits,
)
from r2inspect.utils.output import OutputFormatter
from r2inspect.utils.ssdeep_loader import get_ssdeep

pytestmark = pytest.mark.unit


def test_result_aggregator_summary_and_indicators() -> None:
    aggregator = ResultAggregator()
    results = {
        "file_info": {
            "name": "sample.bin",
            "file_type": "PE32",
            "size": 1234,
            "architecture": "x86",
            "md5": "md5",
            "sha256": "sha256",
        },
        "pe_info": {"compilation_timestamp": "2020-01-01"},
        "security": {"authenticode": False, "aslr": True, "dep": False},
        "packer": {"is_packed": True, "packer_type": "upx"},
        "anti_analysis": {"anti_debug": True, "anti_vm": True},
        "imports": [{"name": "VirtualAlloc"}, {"name": "CreateRemoteThread"}],
        "yara_matches": [{"rule": "test_rule"}],
        "sections": [{"entropy": 7.5, "name": ".textbss", "suspicious_indicators": True}],
        "crypto": {"matches": [{"name": "AES"}]},
        "functions": {"count": 5},
        "rich_header": {
            "available": True,
            "compilers": [{"compiler_name": "MSC", "build_number": 1900}],
        },
    }

    summary = aggregator.generate_executive_summary(results)
    assert summary["file_overview"]["filename"] == "sample.bin"
    assert summary["security_assessment"]["is_packed"] is True
    assert summary["threat_indicators"]["yara_matches"] == 1
    assert summary["recommendations"]

    indicators = aggregator.generate_indicators(results)
    assert any(indicator["type"] == "Packer" for indicator in indicators)
    assert any(indicator["type"] == "YARA Match" for indicator in indicators)

    clean_summary = aggregator.generate_executive_summary(
        {
            "security": {"authenticode": True},
            "packer": {"is_packed": False},
            "crypto": {"matches": []},
            "anti_analysis": {"anti_debug": False},
        }
    )
    assert "No immediate concerns" in clean_summary["recommendations"][0]


def test_memory_monitor_thresholds_and_callbacks() -> None:
    warnings: list[dict[str, object]] = []
    criticals: list[dict[str, object]] = []

    limits = MemoryLimits(
        max_process_memory_mb=1,
        memory_warning_threshold=0.0,
        memory_critical_threshold=0.0,
    )
    monitor = MemoryMonitor(limits)
    monitor.set_callbacks(
        warning_callback=lambda stats: warnings.append(stats),
        critical_callback=lambda stats: criticals.append(stats),
    )
    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"warning", "critical"}
    assert warnings or criticals

    cached = monitor.check_memory()
    assert cached["status"] == "cached"

    warn_limits = MemoryLimits(
        max_process_memory_mb=1024,
        memory_warning_threshold=0.0,
        memory_critical_threshold=2.0,
    )
    warn_monitor = MemoryMonitor(warn_limits)
    warned: list[dict[str, object]] = []
    warn_monitor.set_callbacks(warning_callback=lambda stats: warned.append(stats))
    warn_stats = warn_monitor.check_memory(force=True)
    assert warn_stats["status"] == "warning"
    assert warned

    assert warn_monitor.validate_file_size(warn_limits.max_file_size_mb * 1024 * 1024 + 1) is False
    assert (
        warn_monitor.validate_section_size(warn_limits.section_size_limit_mb * 1024 * 1024 + 1)
        is False
    )
    assert warn_monitor.limit_collection_size(list(range(5)), 2) == [0, 1]
    assert warn_monitor.is_memory_available(1000000.0) is False


def test_memory_aware_analyzer_operations() -> None:
    monitor = MemoryMonitor(MemoryLimits(max_process_memory_mb=1024))
    monitor.check_interval = 0
    analyzer = MemoryAwareAnalyzer(monitor)

    def ok_operation() -> str:
        return "ok"

    def mem_error() -> None:
        raise MemoryError("boom")

    def generic_error() -> None:
        raise ValueError("boom")

    assert analyzer.safe_large_operation(ok_operation, 0.1, "ok") == "ok"
    assert analyzer.safe_large_operation(mem_error, 0.1, "mem") is None
    assert analyzer.safe_large_operation(generic_error, 0.1, "err") is None


def test_hashing_utils_real_file(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    hashes = calculate_hashes(str(sample))
    assert hashes["md5"] == hashlib.md5(b"abc", usedforsecurity=False).hexdigest()
    assert hashes["sha1"] == hashlib.sha1(b"abc", usedforsecurity=False).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(b"abc").hexdigest()
    assert hashes["sha512"] == hashlib.sha512(b"abc").hexdigest()

    missing = calculate_hashes(str(sample) + ".missing")
    assert missing == {"md5": "", "sha1": "", "sha256": "", "sha512": ""}

    assert calculate_imphash([]) is None
    assert calculate_imphash([{"library": "", "name": ""}]) is None
    assert calculate_imphash([{"library": "KERNEL32.dll", "name": "CreateFileA"}])

    ssdeep_value = calculate_ssdeep(str(sample))
    if get_ssdeep() is None:
        assert ssdeep_value is None
    else:
        assert isinstance(ssdeep_value, str) and ssdeep_value


def test_output_formatter_real_paths() -> None:
    results = {
        "file_info": {
            "name": "sample.bin",
            "size": 123,
            "file_type": "PE32, 7 sections",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
        },
        "pe_info": {"compile_time": "2020-01-01"},
        "imports": [
            {
                "name": "CreateRemoteThread",
                "library": "kernel32.dll",
                "category": "Process",
                "risk_score": 95,
                "risk_level": "Critical",
                "risk_tags": ["inject", "thread", "rce"],
            },
            {
                "name": "OpenProcess",
                "library": "kernel32.dll",
                "category": "Process",
                "risk_score": 40,
                "risk_level": "Medium",
                "risk_tags": ["proc"],
            },
        ],
        "sections": [
            {"name": ".text", "raw_size": 10, "flags": "r-x", "entropy": 6.1},
            {
                "name": ".data",
                "raw_size": 20,
                "flags": "rw-",
                "entropy": 7.6,
                "suspicious_indicators": ["high_entropy"],
            },
        ],
        "yara_matches": [{"rule": "rule1"}, {"rule": "rule2"}],
        "indicators": [
            {"type": "Packer", "description": "packed"},
            {"type": "YARA Match", "description": "rule"},
        ],
        "packer": {"is_packed": True, "packer_type": "upx", "confidence": 0.9},
        "rich_header": {
            "xor_key": 1,
            "checksum": 2,
            "richpe_hash": "hash",
            "compilers": [{"compiler_name": "MSC", "count": 2}],
        },
        "functions": {
            "total_functions": 2,
            "machoc_hashes": {"f1": "h1", "f2": "h1"},
        },
        "exports": [{"name": "exp"}],
        "anti_analysis": {"anti_debug": True, "anti_vm": False, "anti_sandbox": True},
    }
    formatter = OutputFormatter(results)

    assert "sample.bin" in formatter.to_json()
    csv_output = formatter.to_csv()
    assert "name" in csv_output and "sample.bin" in csv_output

    table = formatter.format_table({"key": "value"}, title="Test")
    assert table.row_count == 1
    sections_table = formatter.format_sections(results["sections"])
    assert sections_table.row_count == 2
    imports_table = formatter.format_imports(results["imports"])
    assert imports_table.row_count == 2
    summary = formatter.format_summary()
    assert "R2INSPECT ANALYSIS SUMMARY" in summary

    assert formatter._format_file_size("bad") == "bad"
    assert formatter._clean_file_type("PE32, 7 sections") == "PE32"

    broken_formatter = OutputFormatter({"file_info": object()})
    broken_data = broken_formatter._extract_csv_data({"file_info": object()})
    assert "error" in broken_data

    circular = {}
    circular["self"] = circular
    circular_formatter = OutputFormatter(circular)
    assert "JSON serialization failed" in circular_formatter.to_json()

    configure_memory_limits(unknown_key=1)
    cleanup_stats = cleanup_memory()
    assert "status" in cleanup_stats
