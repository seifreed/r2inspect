#!/usr/bin/env python3
"""
Configuration persistence utilities for r2inspect.

This module encapsulates file IO for loading and saving configuration data,
keeping the Config model focused on validation and accessors.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .infrastructure.logging import get_logger

logger = get_logger(__name__)


class ConfigStore:
    """Load and save configuration dictionaries to disk."""

    @staticmethod
    def load(path: str) -> dict[str, Any] | None:
        """Load configuration from a JSON file path."""
        started = time.perf_counter()
        try:
            with open(path) as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                logger.debug(
                    "Configuration loaded",
                    extra={
                        "event_name": "configuration.loaded",
                        "operation": "load_configuration",
                        "config_file": Path(path).name,
                        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                        "outcome": "success",
                    },
                )
                return data
            logger.warning(
                "Configuration root must be an object",
                extra={
                    "event_name": "configuration.rejected",
                    "operation": "load_configuration",
                    "config_file": Path(path).name,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "outcome": "rejected",
                    "error_code": "invalid_root_type",
                },
            )
        except Exception as exc:
            # Diagnostics go to the logger (stderr), never stdout -- a stray
            # warning there corrupts -j/-c machine output piped to a parser.
            logger.warning(
                "Could not load config: %s",
                type(exc).__name__,
                extra={
                    "event_name": "configuration.load_failed",
                    "operation": "load_configuration",
                    "config_file": Path(path).name,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "outcome": "failed",
                    "error_type": type(exc).__name__,
                },
            )
        return None

    @staticmethod
    def save(path: str, payload: dict[str, Any]) -> None:
        """Save configuration to a JSON file path."""
        started = time.perf_counter()
        try:
            config_dir = Path(path).parent
            config_dir.mkdir(exist_ok=True)
            with open(path, "w") as handle:
                json.dump(payload, handle, indent=2)
        except Exception as exc:
            logger.warning(
                "Could not save config: %s",
                type(exc).__name__,
                extra={
                    "event_name": "configuration.save_failed",
                    "operation": "save_configuration",
                    "config_file": Path(path).name,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "outcome": "failed",
                    "error_type": type(exc).__name__,
                },
            )
        else:
            logger.debug(
                "Configuration saved",
                extra={
                    "event_name": "configuration.saved",
                    "operation": "save_configuration",
                    "config_file": Path(path).name,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "outcome": "success",
                },
            )
