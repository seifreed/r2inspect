"""Canonical import tests for infrastructure logging helpers."""

from r2inspect.infrastructure.logging import (
    _handler_is_closed,
    configure_batch_logging,
    get_logger,
    reset_logging_levels,
    setup_logger,
)


def test_infrastructure_logging_exports_work() -> None:
    logger = setup_logger("r2inspect.test.infrastructure.logging")

    assert get_logger("r2inspect.test.infrastructure.logging") is logger
    assert _handler_is_closed(logger.handlers[0]) is False

    configure_batch_logging()
    reset_logging_levels()
