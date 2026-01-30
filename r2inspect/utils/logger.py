#!/usr/bin/env python3
"""
Thread-safe logging utilities for r2inspect
"""

import logging
import logging.handlers
import sys
import threading
from pathlib import Path

# Global lock for thread-safe logger setup
_logger_lock = threading.Lock()
_loggers_initialized = set()


def setup_logger(
    name: str = "r2inspect", level: int = logging.INFO, thread_safe: bool = True
) -> logging.Logger:
    """Setup thread-safe logger with console and file handlers"""

    with _logger_lock:
        # Check if logger already initialized
        if name in _loggers_initialized:
            return logging.getLogger(name)

        logger = logging.getLogger(name)
        logger.setLevel(level)

        # Avoid duplicate handlers
        if logger.handlers:
            _loggers_initialized.add(name)
            return logger

        # Thread-safe console handler
        console_handler = logging.StreamHandler(
            sys.stderr
        )  # Use stderr to avoid conflicts with output
        console_handler.setLevel(level)

        # Add thread safety with a lock if requested
        if thread_safe:
            console_handler.lock = threading.Lock()

        # File handler (optional, thread-safe)
        try:
            log_dir = Path.home() / ".r2inspect" / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)

            # Use RotatingFileHandler for better thread safety and log management
            if thread_safe:
                file_handler: logging.Handler = logging.handlers.RotatingFileHandler(
                    log_dir / "r2inspect.log",
                    maxBytes=10 * 1024 * 1024,  # 10MB
                    backupCount=5,
                )
            else:
                file_handler = logging.FileHandler(log_dir / "r2inspect.log")

            file_handler.setLevel(logging.DEBUG)

            # Thread-safe formatter with thread ID
            if thread_safe:
                formatter = logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - [%(thread)d] - %(message)s"
                )
            else:
                formatter = logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )

            console_handler.setFormatter(formatter)
            file_handler.setFormatter(formatter)

            logger.addHandler(console_handler)
            logger.addHandler(file_handler)

        except Exception:
            # Fallback to console only
            formatter = logging.Formatter(
                "%(levelname)s - [%(thread)d] - %(message)s"
                if thread_safe
                else "%(levelname)s - %(message)s"
            )
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        # Mark as initialized
        _loggers_initialized.add(name)

        return logger


def get_logger(name: str = "r2inspect") -> logging.Logger:
    """Get thread-safe logger instance"""
    return logging.getLogger(name)


def configure_batch_logging():
    """Configure logging for batch processing to reduce noise"""
    with _logger_lock:
        # Set higher log levels for batch processing
        logging.getLogger("r2inspect.core").setLevel(logging.WARNING)
        logging.getLogger("r2inspect.modules").setLevel(logging.WARNING)
        logging.getLogger("r2inspect.utils").setLevel(logging.WARNING)


def reset_logging_levels():
    """Reset logging levels to normal"""
    with _logger_lock:
        logging.getLogger("r2inspect.core").setLevel(logging.INFO)
        logging.getLogger("r2inspect.modules").setLevel(logging.INFO)
        logging.getLogger("r2inspect.utils").setLevel(logging.INFO)
