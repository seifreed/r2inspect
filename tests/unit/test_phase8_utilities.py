from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest
import r2pipe

from r2inspect.utils.magic_detector import MagicByteDetector
from r2inspect.utils.memory_manager import MemoryLimits, MemoryMonitor
from r2inspect.utils.output import OutputFormatter
from r2inspect.utils.r2_helpers import parse_pe_header_text, validate_r2_data
from r2inspect.utils.rate_limiter import BatchRateLimiter, cleanup_memory
from r2inspect.utils.retry_manager import RetryConfig, RetryManager, RetryStrategy

PE_FIXTURE = "samples/fixtures/hello_pe.exe"


def _write_bytes(path: Path, content: bytes) -> None:
    path.write_bytes(content)


def test_magic_detector_handles_unknown_and_rare_formats(tmp_path: Path) -> None:
    detector = MagicByteDetector()

    empty_file = tmp_path / "empty.bin"
    _write_bytes(empty_file, b"")
    empty_result = detector.detect_file_type(str(empty_file))
    assert empty_result["file_format"] == "Unknown"
    assert empty_result["confidence"] == 0.0

    pdf_file = tmp_path / "sample.pdf"
    _write_bytes(pdf_file, b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    pdf_result = detector.detect_file_type(str(pdf_file))
    assert pdf_result["file_format"] == "PDF"
    assert pdf_result["is_document"] is True

    docx_file = tmp_path / "sample.docx"
    _write_bytes(
        docx_file,
        b"PK\x03\x04" + b"word/" + b"[Content_Types].xml" + b"_rels/",
    )
    docx_result = detector.detect_file_type(str(docx_file))
    assert docx_result["file_format"] == "DOCX"
    assert docx_result["is_document"] is True


def test_rate_limiter_concurrency_and_error_accounting() -> None:
    limiter = BatchRateLimiter(max_concurrent=1, rate_per_second=100.0, burst_size=10)

    assert limiter.acquire(timeout=0.2) is True

    blocked = {"value": None}

    def _try_acquire():
        blocked["value"] = limiter.acquire(timeout=0.1)

    thread = threading.Thread(target=_try_acquire)
    thread.start()
    thread.join(timeout=1)
    assert blocked["value"] is False

    limiter.release_error("timeout")
    stats_after_error = limiter.get_stats()
    assert stats_after_error["files_failed"] == 1

    assert limiter.acquire(timeout=0.2) is True
    limiter.release_success()
    stats = limiter.get_stats()
    assert stats["files_processed"] == 1
    assert stats["success_rate"] >= 0.0


def test_memory_monitor_limits_and_truncation() -> None:
    limits = MemoryLimits(max_process_memory_mb=1, max_file_size_mb=1)
    monitor = MemoryMonitor(limits=limits)

    warning_seen = {"value": False}
    critical_seen = {"value": False}

    def _warn(_stats):
        warning_seen["value"] = True

    def _critical(_stats):
        critical_seen["value"] = True

    monitor.set_callbacks(warning_callback=_warn, critical_callback=_critical)

    stats = monitor.check_memory(force=True)
    assert stats["status"] in {"warning", "critical"}
    assert monitor.gc_count >= 1
    assert warning_seen["value"] or critical_seen["value"]

    assert monitor.validate_file_size(2 * 1024 * 1024) is False
    assert monitor.validate_section_size(1) is True

    data = list(range(10))
    truncated = monitor.limit_collection_size(data, 5, name="test")
    assert truncated == [0, 1, 2, 3, 4]


def test_output_formatter_empty_and_serialization_errors() -> None:
    formatter = OutputFormatter({})
    csv_output = formatter.to_csv()
    assert csv_output.startswith("name,size,compile_time")

    class BadRepr:
        def __str__(self):
            raise ValueError("boom")

    formatter = OutputFormatter({"bad": BadRepr()})
    json_output = formatter.to_json()
    parsed = json.loads(json_output)
    assert "JSON serialization failed" in parsed["error"]
    assert "partial_results" in parsed


@pytest.mark.requires_r2
def test_r2_helpers_validate_and_parse_text() -> None:
    cleaned = validate_r2_data(
        [
            {"name": "Foo&nbsp;Bar&amp;Baz"},
            {"name": "Keep"},
            123,
        ],
        "list",
    )
    assert cleaned == [
        {"name": "Foo Bar&Baz"},
        {"name": "Keep"},
    ]

    r2 = r2pipe.open(PE_FIXTURE)
    try:
        parsed = parse_pe_header_text(r2)
    finally:
        r2.quit()

    assert parsed is not None
    assert "nt_headers" in parsed
    assert "file_header" in parsed
    assert "optional_header" in parsed


def test_retry_manager_jitter_and_timeout_behavior() -> None:
    manager = RetryManager()

    config = RetryConfig(
        max_attempts=3,
        base_delay=0.01,
        max_delay=0.05,
        strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
        jitter=True,
    )

    attempts = {"count": 0}

    def _sometimes_fails():
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise TimeoutError("timeout")
        return "ok"

    result = manager.retry_operation(_sometimes_fails, config=config)
    assert result == "ok"

    delay = manager.calculate_delay(2, config)
    assert 0.01 <= delay <= 0.05

    config_timeout = RetryConfig(
        max_attempts=5,
        base_delay=0.01,
        max_delay=0.02,
        strategy=RetryStrategy.FIXED_DELAY,
        timeout=0.01,
    )

    def _always_fails():
        raise TimeoutError("timeout")

    with pytest.raises(TimeoutError):
        manager.retry_operation(_always_fails, config=config_timeout)


def test_cleanup_memory_reports_usage() -> None:
    stats = cleanup_memory()
    if stats is not None:
        assert "rss_mb" in stats
        assert "vms_mb" in stats
