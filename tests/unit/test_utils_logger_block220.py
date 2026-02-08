from __future__ import annotations

import logging

from r2inspect.utils.logger import (
    configure_batch_logging,
    get_logger,
    reset_logging_levels,
    setup_logger,
)


def test_setup_logger_and_levels() -> None:
    logger = setup_logger("r2inspect.test", level=logging.INFO, thread_safe=True)
    assert logger.level == logging.INFO
    assert logger.handlers

    configure_batch_logging()
    assert get_logger("r2inspect").level == logging.WARNING
    reset_logging_levels()
    assert get_logger("r2inspect").level == logging.INFO


def test_setup_logger_reinitializes_closed_handlers() -> None:
    name = "r2inspect.test.closed"
    logger = setup_logger(name, level=logging.DEBUG, thread_safe=False)
    for handler in list(logger.handlers):
        handler.close()
    logger = setup_logger(name, level=logging.DEBUG, thread_safe=False)
    assert logger.handlers
