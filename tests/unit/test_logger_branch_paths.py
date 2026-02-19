from __future__ import annotations

import logging

from r2inspect.utils.logger import (
    configure_batch_logging,
    get_logger,
    reset_logging_levels,
    setup_logger,
)


def _cleanup_logger(name: str) -> None:
    """Close and remove all handlers from a logger to prevent shutdown hangs."""
    logger = logging.getLogger(name)
    for handler in list(logger.handlers):
        try:
            handler.flush()
            handler.close()
        except Exception:
            pass
        logger.removeHandler(handler)


def test_setup_logger_thread_safe_true_creates_handlers() -> None:
    name = "r2inspect.test.bp.thread_safe_true"
    try:
        logger = setup_logger(name, level=logging.DEBUG, thread_safe=True)
        assert logger is not None
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) > 0
    finally:
        _cleanup_logger(name)


def test_setup_logger_thread_safe_false_creates_handlers() -> None:
    name = "r2inspect.test.bp.thread_safe_false"
    try:
        logger = setup_logger(name, level=logging.INFO, thread_safe=False)
        assert logger is not None
        assert len(logger.handlers) > 0
    finally:
        _cleanup_logger(name)


def test_setup_logger_returns_same_logger_when_already_initialized() -> None:
    name = "r2inspect.test.bp.already_init"
    try:
        logger1 = setup_logger(name, level=logging.INFO, thread_safe=False)
        logger2 = setup_logger(name, level=logging.INFO, thread_safe=False)
        assert logger1 is logger2
    finally:
        _cleanup_logger(name)


def test_setup_logger_reinitializes_after_closed_handlers() -> None:
    name = "r2inspect.test.bp.closed_handlers"
    try:
        logger = setup_logger(name, level=logging.DEBUG, thread_safe=False)
        assert len(logger.handlers) > 0

        for handler in list(logger.handlers):
            handler.close()

        logger2 = setup_logger(name, level=logging.DEBUG, thread_safe=False)
        assert len(logger2.handlers) > 0
    finally:
        _cleanup_logger(name)


def test_get_logger_returns_logging_logger() -> None:
    logger = get_logger("r2inspect.test.bp.get")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "r2inspect.test.bp.get"


def test_get_logger_default_name() -> None:
    logger = get_logger()
    assert isinstance(logger, logging.Logger)


def test_configure_batch_logging_sets_warning_level() -> None:
    configure_batch_logging()
    assert get_logger("r2inspect").level == logging.WARNING
    assert get_logger("r2inspect.core").level == logging.WARNING
    assert get_logger("r2inspect.pipeline").level == logging.WARNING
    assert get_logger("r2inspect.modules").level == logging.WARNING
    assert get_logger("r2inspect.utils").level == logging.WARNING
    reset_logging_levels()


def test_reset_logging_levels_restores_info() -> None:
    configure_batch_logging()
    reset_logging_levels()
    assert get_logger("r2inspect").level == logging.INFO
    assert get_logger("r2inspect.core").level == logging.INFO
    assert get_logger("r2inspect.pipeline").level == logging.INFO
    assert get_logger("r2inspect.modules").level == logging.INFO
    assert get_logger("r2inspect.utils").level == logging.INFO


def test_setup_logger_warning_level() -> None:
    name = "r2inspect.test.bp.warn_level"
    try:
        logger = setup_logger(name, level=logging.WARNING, thread_safe=False)
        assert logger.level == logging.WARNING
    finally:
        _cleanup_logger(name)


def test_setup_logger_error_level() -> None:
    name = "r2inspect.test.bp.error_level"
    try:
        logger = setup_logger(name, level=logging.ERROR, thread_safe=False)
        assert logger.level == logging.ERROR
    finally:
        _cleanup_logger(name)
