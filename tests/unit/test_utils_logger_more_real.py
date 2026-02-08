from __future__ import annotations

import io
import logging
import os
from pathlib import Path

from r2inspect.utils.logger import _handler_is_closed, setup_logger


def test_logger_thread_safe_false_file_handler(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    old_home = os.environ.get("HOME")
    os.environ["HOME"] = str(home_dir)

    try:
        logger = setup_logger("r2inspect.test.non_thread_safe", thread_safe=False)
        assert any(isinstance(handler, logging.FileHandler) for handler in logger.handlers)
    finally:
        if old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old_home


def test_handler_is_closed_reinit(tmp_path: Path) -> None:
    home_dir = tmp_path / "home2"
    home_dir.mkdir()
    old_home = os.environ.get("HOME")
    os.environ["HOME"] = str(home_dir)

    try:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        stream.close()
        assert _handler_is_closed(handler) is True

        logger = logging.getLogger("r2inspect.test.closed")
        logger.addHandler(handler)
        logger = setup_logger("r2inspect.test.closed", thread_safe=True)
        assert logger.handlers
    finally:
        if old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old_home
