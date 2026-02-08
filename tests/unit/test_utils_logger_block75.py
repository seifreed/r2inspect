from __future__ import annotations

import logging
import os

from r2inspect.utils import logger as logger_mod


def test_setup_logger_handlers_and_levels(tmp_path):
    # Force home dir to a temp path to avoid touching user home
    original_home = os.environ.get("HOME")
    os.environ["HOME"] = str(tmp_path)
    try:
        log = logger_mod.setup_logger(name="r2inspect.test", thread_safe=True)
        assert isinstance(log, logging.Logger)
        assert log.level == logging.INFO
        assert log.handlers

        # Second call should return same logger without adding handlers
        log2 = logger_mod.setup_logger(name="r2inspect.test", thread_safe=True)
        assert log2 is log
    finally:
        if original_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = original_home


def test_configure_and_reset_batch_logging():
    core = logging.getLogger("r2inspect.core")
    modules = logging.getLogger("r2inspect.modules")
    utils = logging.getLogger("r2inspect.utils")

    logger_mod.configure_batch_logging()
    assert core.level == logging.WARNING
    assert modules.level == logging.WARNING
    assert utils.level == logging.WARNING

    logger_mod.reset_logging_levels()
    assert core.level == logging.INFO
    assert modules.level == logging.INFO
    assert utils.level == logging.INFO
