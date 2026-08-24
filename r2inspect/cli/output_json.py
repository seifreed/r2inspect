#!/usr/bin/env python3
"""JSON output formatting helpers."""

from __future__ import annotations

import json
import logging
from typing import Any

from ..infrastructure.json_serialization import dumps

logger = logging.getLogger(__name__)


class JsonOutputFormatter:
    """Format analysis results to JSON."""

    def __init__(self, results: dict[str, Any]):
        self.results = results

    def to_json(self, indent: int = 2) -> str:
        try:
            return dumps(self.results, indent=indent)
        except Exception as exc:
            # The user gets an error blob instead of their results; make sure the
            # reason is in the log rather than only in the returned JSON.
            logger.error("JSON serialization of analysis results failed: %s", exc)
            payload: dict[str, Any] = {
                "error": f"JSON serialization failed: {str(exc)}",
                "partial_results": {},
            }
            if isinstance(self.results, dict):
                for key, value in self.results.items():
                    try:
                        payload[key] = [str(value)]
                    except Exception:
                        payload[key] = {"type": type(value).__name__}
            return json.dumps(payload, indent=indent)


__all__ = ["JsonOutputFormatter"]
