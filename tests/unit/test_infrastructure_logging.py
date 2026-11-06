"""Canonical tests for the production logging contract."""

from __future__ import annotations

import json
import io
import logging
import stat
import threading
from pathlib import Path

from r2inspect.infrastructure.logging import (
    _handler_is_closed,
    TRACE,
    bind_log_context,
    command_name,
    configure_batch_logging,
    current_log_context,
    parse_traceparent,
    get_logger,
    redact,
    reset_logging_levels,
    sanitize_text,
    setup_logger,
)


def test_infrastructure_logging_exports_work() -> None:
    logger = setup_logger("r2inspect.test.infrastructure.logging")

    assert get_logger("r2inspect.test.infrastructure.logging") is logger
    assert _handler_is_closed(logger.handlers[0]) is False

    configure_batch_logging()
    reset_logging_levels()


def _close_logger(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)


def test_json_logging_has_stable_utc_schema_context_and_redaction(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    logger = setup_logger(
        "r2inspect.test.json",
        level=TRACE,
        format_name="json",
        destination="file",
        log_file=path,
    )
    try:
        with bind_log_context(correlation_id="corr-1", operation="unit_test"):
            logger.error(
                "request failed token=top-secret\nforged",
                extra={"event_name": "test.failed", "api_key": "also-secret"},
            )
        for handler in logger.handlers:
            handler.flush()
    finally:
        _close_logger(logger)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["timestamp"].endswith("+00:00")
    assert event["level"] == "ERROR"
    assert event["service"] == "r2inspect"
    assert event["component"] == "r2inspect.test.json"
    assert event["event_name"] == "test.failed"
    assert event["operation"] == "unit_test"
    assert event["correlation_id"] == "corr-1"
    assert event["api_key"] == "[REDACTED]"
    assert "top-secret" not in lines[0]
    assert "forged" in event["message"] and "\n" not in event["message"]


def test_exception_event_preserves_diagnostics_without_secret(tmp_path: Path) -> None:
    path = tmp_path / "exception.jsonl"
    logger = setup_logger(
        "r2inspect.test.exception",
        format_name="json",
        destination="file",
        log_file=path,
    )
    try:
        try:
            raise RuntimeError("password=hunter2")
        except RuntimeError:
            logger.exception("operation failed", extra={"event_name": "operation.failed"})
        for handler in logger.handlers:
            handler.flush()
    finally:
        _close_logger(logger)

    event = json.loads(path.read_text(encoding="utf-8"))
    assert event["error_type"] == "RuntimeError"
    assert "RuntimeError" in event["stack_trace"]
    assert "hunter2" not in event["stack_trace"]


def test_context_is_isolated_and_logging_is_concurrent_safe(tmp_path: Path) -> None:
    path = tmp_path / "concurrent.jsonl"
    logger = setup_logger(
        "r2inspect.test.concurrent",
        format_name="json",
        destination="file",
        log_file=path,
    )

    def worker(worker_id: int) -> None:
        with bind_log_context(correlation_id=f"worker-{worker_id}"):
            for sequence in range(20):
                logger.info("item", extra={"sequence": sequence})

    threads = [threading.Thread(target=worker, args=(worker_id,)) for worker_id in range(8)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for handler in logger.handlers:
            handler.flush()
    finally:
        _close_logger(logger)

    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(events) == 160
    assert {event["correlation_id"] for event in events} == {
        f"worker-{worker_id}" for worker_id in range(8)
    }
    assert current_log_context() == {}


def test_trace_context_and_sanitizers_reject_unsafe_input() -> None:
    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    span_id = "00f067aa0ba902b7"
    assert parse_traceparent(f"00-{trace_id}-{span_id}-01") == (trace_id, span_id)
    assert parse_traceparent("00-00000000000000000000000000000000-0000000000000000-00") == (
        None,
        None,
    )
    assert parse_traceparent("invalid") == (None, None)
    assert redact({"password": "secret", "nested": {"token": "secret"}}) == {
        "password": "[REDACTED]",
        "nested": {"token": "[REDACTED]"},
    }
    assert sanitize_text("safe\r\nforged") == r"safe\r\nforged"
    assert "dictionary-secret" not in sanitize_text("{'api_key': 'dictionary-secret'}")
    for key in ("auth_token", "accessToken", "client_secret", "db_password"):
        sanitized = sanitize_text(f"{key}=credential-value")
        assert "credential-value" not in sanitized
        assert sanitized.endswith("[REDACTED]")
    assert command_name("/x confidential-pattern") == "/x"
    assert command_name("psz @ 0x401000") == "psz"
    assert command_name("") == "unknown"


def test_environment_controls_level_format_and_destination(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "configured.jsonl"
    monkeypatch.setenv("R2INSPECT_LOG_LEVEL", "TRACE")
    monkeypatch.setenv("R2INSPECT_LOG_FORMAT", "json")
    monkeypatch.setenv("R2INSPECT_LOG_DESTINATION", "file")
    monkeypatch.setenv("R2INSPECT_LOG_FILE", str(path))
    logger = setup_logger("r2inspect.test.environment")
    try:
        logger.log(TRACE, "trace event")
        for handler in logger.handlers:
            handler.flush()
    finally:
        _close_logger(logger)

    assert logger.level == TRACE
    assert json.loads(path.read_text(encoding="utf-8"))["level"] == "TRACE"


def test_text_logging_includes_correlation_and_escapes_injection(tmp_path: Path) -> None:
    path = tmp_path / "events.log"
    logger = setup_logger(
        "r2inspect.test.text",
        destination="file",
        log_file=path,
        format_name="text",
    )
    try:
        with bind_log_context(correlation_id="corr-text"):
            logger.warning("unsafe\nline password=secret")
        for handler in logger.handlers:
            handler.flush()
    finally:
        _close_logger(logger)

    rendered = path.read_text(encoding="utf-8")
    assert "correlation_id=corr-text" in rendered
    assert "password=[REDACTED]" in rendered
    assert "secret" not in rendered
    assert len(rendered.splitlines()) == 1


def test_rotating_file_retention_is_bounded(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "rotating.log"
    monkeypatch.setenv("R2INSPECT_LOG_MAX_BYTES", "256")
    monkeypatch.setenv("R2INSPECT_LOG_BACKUP_COUNT", "2")
    logger = setup_logger(
        "r2inspect.test.rotation",
        destination="file",
        log_file=path,
        thread_safe=True,
    )
    try:
        for sequence in range(100):
            logger.warning("rotation event %s %s", sequence, "x" * 40)
        for handler in logger.handlers:
            handler.flush()
    finally:
        _close_logger(logger)

    assert path.is_file()
    assert path.with_name("rotating.log.1").is_file()
    assert path.with_name("rotating.log.2").is_file()
    assert not path.with_name("rotating.log.3").exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.with_name("rotating.log.1").stat().st_mode) == 0o600


def test_rotation_limits_cannot_be_disabled_with_negative_values(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("R2INSPECT_LOG_MAX_BYTES", "-1")
    monkeypatch.setenv("R2INSPECT_LOG_BACKUP_COUNT", "-1")
    logger = setup_logger(
        "r2inspect.test.rotation_limits",
        destination="file",
        log_file=tmp_path / "bounded.log",
    )
    try:
        handler = logger.handlers[0]
        assert isinstance(handler, logging.handlers.RotatingFileHandler)
        assert handler.maxBytes == 1
        assert handler.backupCount == 1
    finally:
        _close_logger(logger)


def test_runtime_destination_failure_does_not_escape() -> None:
    class BrokenStream(io.StringIO):
        def write(self, _text: str) -> int:
            raise OSError("destination failed")

    logger = setup_logger(
        "r2inspect.test.destination_failure",
        destination="file",
        file_handler_factory=lambda: logging.StreamHandler(BrokenStream()),
    )
    try:
        logger.error("operation failed safely")
    finally:
        _close_logger(logger)
