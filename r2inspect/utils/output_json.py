#!/usr/bin/env python3
"""JSON output formatting helpers."""

from __future__ import annotations

import json
from typing import Any


class JsonOutputFormatter:
    """Format analysis results to JSON."""

    def __init__(self, results: dict[str, Any]):
        self.results = results

    def to_json(self, indent: int = 2) -> str:
        """Convert results to JSON format."""
        try:
            return json.dumps(self.results, indent=indent, default=str)
        except Exception as e:
            return json.dumps(
                {
                    "error": f"JSON serialization failed: {str(e)}",
                    "partial_results": {},
                },
                indent=indent,
            )
