from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import pytest

from r2inspect.utils.logger import configure_batch_logging, reset_logging_levels, setup_logger
from r2inspect.utils.output import OutputFormatter
from r2inspect.utils.rate_limiter import (
    AdaptiveRateLimiter,
    BatchRateLimiter,
    TokenBucket,
    cleanup_memory,
)
from r2inspect.utils.retry_manager import (
    RetryConfig,
    RetryManager,
    RetryStrategy,
    configure_retry_for_command,
    get_retry_stats,
    reset_retry_stats,
    retry_on_failure,
    retry_r2_operation,
)


class _BadStr:
    def __str__(self) -> str:
        raise ValueError("boom")


def _sample_results() -> dict[str, object]:
    return {
        "file_info": {
            "name": "sample.bin",
            "size": 1024,
            "file_type": "PE32 executable, 3 sections",
            "md5": "a" * 32,
            "sha1": "b" * 40,
            "sha256": "c" * 64,
            "sha512": "d" * 128,
        },
        "pe_info": {"compile_time": "2024-01-01", "imphash": "deadbeef"},
        "ssdeep": {"hash_value": "3:abc:xyz"},
        "tlsh": {
            "binary_tlsh": "T1",
            "text_section_tlsh": "T2",
            "stats": {"functions_with_tlsh": 1},
        },
        "telfhash": {"telfhash": "TF", "filtered_symbols": 7},
        "rich_header": {
            "xor_key": 0x1122,
            "checksum": 0x3344,
            "richpe_hash": "RH",
            "compilers": [{"compiler_name": "MSVC", "count": 2}],
        },
        "imports": [{"name": "CreateFileA"}, {"name": "ReadFile"}],
        "exports": [{"name": "ExportedFunc"}],
        "sections": [{"name": ".text"}],
        "anti_analysis": {"anti_debug": True, "anti_vm": False, "anti_sandbox": True},
        "yara_matches": [{"rule": "rule_one"}],
        "compiler": {"compiler": "MSVC", "version": "19", "confidence": 0.9},
        "functions": {"total_functions": 3, "machoc_hashes": {"f1": "A", "f2": "A", "f3": "B"}},
    }


def test_output_formatter_json_csv_and_summary() -> None:
    results = _sample_results()
    formatter = OutputFormatter(results)

    json_text = formatter.to_json()
    assert "sample.bin" in json_text

    csv_text = formatter.to_csv()
    assert csv_text.splitlines()[0].startswith("name,")
    assert "sample.bin" in csv_text

    summary = formatter.format_summary()
    assert "R2INSPECT ANALYSIS SUMMARY" in summary
    assert "Packer" not in summary


def test_output_formatter_json_error_and_summary_error() -> None:
    formatter = OutputFormatter({"bad": _BadStr(), "indicators": ["not-a-dict"]})
    json_text = formatter.to_json()
    assert "JSON serialization failed" in json_text

    summary = formatter.format_summary()
    assert "Error generating summary" in summary


def test_output_formatter_tables_and_helpers() -> None:
    formatter = OutputFormatter(_sample_results())

    table = formatter.format_table({"alpha": 1, "beta": {"nested": True}})
    assert len(table.rows) == 2

    sections_table = formatter.format_sections(
        [
            {"name": ".text", "raw_size": 10, "flags": "r-x", "entropy": 6.4},
            {
                "name": ".data",
                "raw_size": 5,
                "flags": "rw-",
                "entropy": 1.2,
                "suspicious_indicators": ["x"],
            },
        ]
    )
    assert len(sections_table.rows) == 2

    imports_table = formatter.format_imports(
        [
            {
                "name": "CreateFileA",
                "library": "KERNEL32",
                "category": "file",
                "risk_score": 80,
                "risk_level": "High",
                "risk_tags": ["fs", "write", "priv"],
            },
            {
                "name": "GetVersion",
                "library": "KERNEL32",
                "category": "info",
                "risk_score": 5,
                "risk_level": "Minimal",
                "risk_tags": [],
            },
        ]
    )
    assert len(imports_table.rows) == 2

    assert formatter._format_file_size(0) == "0 B"
    assert formatter._format_file_size("bad") == "bad"
    assert formatter._clean_file_type(123) == 123


def test_logger_setup_reinit_and_fallback(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    old_home = os.environ.get("HOME")
    os.environ["HOME"] = str(home_dir)

    try:
        logger = setup_logger("r2inspect.test.reinit", thread_safe=True)
        file_handler = next(
            handler for handler in logger.handlers if hasattr(handler, "baseFilename")
        )
        file_handler.close()

        logger_reinit = setup_logger("r2inspect.test.reinit", thread_safe=True)
        assert logger_reinit.handlers
        assert any(hasattr(handler, "baseFilename") for handler in logger_reinit.handlers)
    finally:
        if old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old_home

    restricted = tmp_path / "restricted_home"
    restricted.mkdir()
    restricted.chmod(0)
    old_home = os.environ.get("HOME")
    os.environ["HOME"] = str(restricted)

    try:
        fallback_logger = setup_logger("r2inspect.test.fallback", thread_safe=False)
        assert len(fallback_logger.handlers) == 1
    finally:
        restricted.chmod(0o700)
        if old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old_home


def test_logger_batch_levels() -> None:
    configure_batch_logging()
    assert logging.getLogger("r2inspect").level == logging.WARNING
    reset_logging_levels()
    assert logging.getLogger("r2inspect").level == logging.INFO


def test_rate_limiter_token_bucket_and_batch() -> None:
    bucket = TokenBucket(capacity=1, refill_rate=0.0)
    assert bucket.acquire(tokens=1, timeout=0.05) is True
    assert bucket.acquire(tokens=1, timeout=0.02) is False

    limiter = BatchRateLimiter(
        max_concurrent=1, rate_per_second=50.0, burst_size=1, enable_adaptive=False
    )
    assert limiter.acquire(timeout=0.1) is True
    limiter.release_success()
    stats = limiter.get_stats()
    assert stats["files_processed"] == 1
    assert stats["success_rate"] == 1.0


def test_adaptive_rate_limiter_adjustments() -> None:
    limiter = AdaptiveRateLimiter(
        base_rate=10.0, max_rate=20.0, min_rate=1.0, memory_threshold=0.0, cpu_threshold=0.0
    )
    limiter.system_check_interval = 0.0
    limiter.last_system_check = 0.0
    limiter._check_system_load()

    for _ in range(4):
        limiter.record_error("TimeoutError")
    limiter.record_success()

    stats = limiter.get_stats()
    assert stats["recent_operations"] >= 5
    assert limiter.current_rate <= limiter.base_rate

    low_error = AdaptiveRateLimiter(base_rate=2.0, max_rate=4.0, min_rate=1.0)
    for _ in range(6):
        low_error.record_success()
    assert low_error.current_rate > low_error.base_rate


def test_cleanup_memory_returns_stats() -> None:
    stats = cleanup_memory()
    assert stats is None or ("rss_mb" in stats and "vms_mb" in stats)


def test_retry_manager_strategies_and_retry_flow() -> None:
    manager = RetryManager()
    fixed = RetryConfig(
        base_delay=0.05, max_delay=1.0, strategy=RetryStrategy.FIXED_DELAY, jitter=False
    )
    assert manager.calculate_delay(1, fixed) == 0.05

    exp = RetryConfig(
        base_delay=0.05, max_delay=1.0, strategy=RetryStrategy.EXPONENTIAL_BACKOFF, jitter=False
    )
    assert manager.calculate_delay(2, exp) == 0.1

    linear = RetryConfig(
        base_delay=0.05, max_delay=1.0, strategy=RetryStrategy.LINEAR_BACKOFF, jitter=False
    )
    assert manager.calculate_delay(2, linear) == 0.1

    jitter = RetryConfig(
        base_delay=0.1, max_delay=1.0, strategy=RetryStrategy.RANDOM_JITTER, jitter=False
    )
    delay = manager.calculate_delay(1, jitter)
    assert 0.1 <= delay <= 0.2

    attempts = {"count": 0}

    def flaky() -> str:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise TimeoutError("timeout")
        return "ok"

    result = manager.retry_operation(
        flaky,
        command_type="generic",
        config=RetryConfig(max_attempts=2, base_delay=0.0, jitter=False),
    )
    assert result == "ok"

    with pytest.raises(ValueError):
        manager.retry_operation(
            lambda: (_ for _ in ()).throw(ValueError("bad")),
            command_type="generic",
            config=RetryConfig(max_attempts=2, base_delay=0.0, jitter=False),
        )

    with pytest.raises(TimeoutError):
        manager.retry_operation(
            lambda: "ok",
            command_type="generic",
            config=RetryConfig(max_attempts=1, base_delay=0.0, timeout=-0.001, jitter=False),
        )


def test_retry_decorator_and_global_helpers() -> None:
    calls = {"count": 0}

    @retry_on_failure(
        command_type="analysis",
        config=RetryConfig(max_attempts=2, base_delay=0.0, jitter=False),
        auto_retry=True,
    )
    def _unstable(*_args: object, **_kwargs: object) -> str:
        calls["count"] += 1
        if calls["count"] == 1:
            raise TimeoutError("timeout")
        return "ok"

    assert _unstable(object(), "aaa") == "ok"
    assert calls["count"] == 2

    calls["count"] = 0

    @retry_on_failure(
        command_type="analysis",
        config=RetryConfig(max_attempts=1, base_delay=0.0, jitter=False),
        auto_retry=True,
    )
    def _stable(*_args: object, **_kwargs: object) -> str:
        calls["count"] += 1
        raise TimeoutError("timeout")

    with pytest.raises(TimeoutError):
        _stable(object(), "zz")
    assert calls["count"] == 1

    assert retry_r2_operation(lambda cmd: f"ran:{cmd}", "aaa", command_type="analysis") == "ran:aaa"

    old_config = RetryManager.DEFAULT_CONFIGS.get("custom")
    try:
        configure_retry_for_command("custom", RetryConfig(max_attempts=1, jitter=False))
        stats_before = get_retry_stats()
        reset_retry_stats()
        stats_after = get_retry_stats()
        assert stats_before["total_retries"] >= 0
        assert stats_after["total_retries"] == 0
    finally:
        if old_config is None:
            RetryManager.DEFAULT_CONFIGS.pop("custom", None)
        else:
            RetryManager.DEFAULT_CONFIGS["custom"] = old_config
