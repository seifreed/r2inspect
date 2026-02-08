from __future__ import annotations

import logging

from r2inspect.utils.logger import configure_batch_logging, reset_logging_levels, setup_logger


def test_configure_and_reset_batch_logging_levels():
    # ensure loggers exist
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
