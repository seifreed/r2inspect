#!/usr/bin/env python3
"""
Configuration persistence utilities for r2inspect.

This module encapsulates file IO for loading and saving configuration data,
keeping the Config model focused on validation and accessors.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ConfigStore:
    """Load and save configuration dictionaries to disk."""

    @staticmethod
    def load(path: str) -> dict[str, Any] | None:
        """Load configuration from a JSON file path."""
        try:
            with open(path) as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                return data
        except Exception as exc:
            print(f"Warning: Could not load config from {path}: {exc}")
        return None

    @staticmethod
    def save(path: str, payload: dict[str, Any]) -> None:
        """Save configuration to a JSON file path."""
        try:
            config_dir = Path(path).parent
            config_dir.mkdir(exist_ok=True)
            with open(path, "w") as handle:
                json.dump(payload, handle, indent=2)
        except Exception as exc:
            print(f"Warning: Could not save config to {path}: {exc}")
