import logging

from r2inspect.utils.logger import (
    configure_batch_logging,
    get_logger,
    reset_logging_levels,
    setup_logger,
)


def test_setup_logger_returns_logger():
    logger = setup_logger(name="r2inspect.test", level=logging.INFO, thread_safe=False)
    assert logger.name == "r2inspect.test"
    assert logger.level == logging.INFO


def test_get_logger_returns_existing():
    logger = setup_logger(name="r2inspect.test2", level=logging.DEBUG, thread_safe=True)
    fetched = get_logger("r2inspect.test2")
    assert fetched is logger


def test_batch_logging_levels_toggle():
    setup_logger(name="r2inspect.core", level=logging.INFO, thread_safe=False)
    setup_logger(name="r2inspect.modules", level=logging.INFO, thread_safe=False)
    setup_logger(name="r2inspect.utils", level=logging.INFO, thread_safe=False)

    configure_batch_logging()
    assert logging.getLogger("r2inspect.core").level == logging.WARNING
    assert logging.getLogger("r2inspect.modules").level == logging.WARNING
    assert logging.getLogger("r2inspect.utils").level == logging.WARNING

    reset_logging_levels()
    assert logging.getLogger("r2inspect.core").level == logging.INFO
    assert logging.getLogger("r2inspect.modules").level == logging.INFO
    assert logging.getLogger("r2inspect.utils").level == logging.INFO
