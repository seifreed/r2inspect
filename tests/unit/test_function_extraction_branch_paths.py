"""Branch-path tests for function_extraction.py."""

from __future__ import annotations

import logging
from typing import Any

from r2inspect.modules.function_extraction import collect_valid_functions


class _Host:
    def __init__(self, functions: list[Any], *, analyze_all: bool = False) -> None:
        self.adapter = self if analyze_all else None
        self._functions = functions
        self.analyze_all_called = False

    def analyze_all(self) -> None:
        self.analyze_all_called = True

    def _cmd_list(self, command: str) -> list[Any]:
        return self._functions


def test_collect_valid_functions_skips_malformed_entries() -> None:
    host = _Host(
        [
            "bad",
            {"addr": 0x1000, "size": "32", "name": "good"},
            {"addr": 0x2000, "size": 0, "name": "zero"},
        ]
    )
    result = collect_valid_functions(host, logging.getLogger("test"))
    assert len(result) == 1
    assert result[0]["addr"] == 0x1000
    assert result[0]["size"] == 32


def test_collect_valid_functions_runs_analyze_all_and_cleans_names() -> None:
    host = _Host([{"addr": "4096", "size": "8", "name": "A&amp;B"}], analyze_all=True)
    result = collect_valid_functions(
        host,
        logging.getLogger("test"),
        run_analyze_all=True,
        clean_names=True,
    )
    assert host.analyze_all_called is True
    assert result[0]["addr"] == 4096
    assert result[0]["size"] == 8
    assert result[0]["name"] == "A&B"
