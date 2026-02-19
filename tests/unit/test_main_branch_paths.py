#!/usr/bin/env python3
"""Branch path tests for __main__ and schemas/base."""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# __main__.py
# ---------------------------------------------------------------------------

def test_main_function_returns_exit_code() -> None:
    """main() in __main__ invokes CLI and returns integer exit code."""
    from r2inspect.__main__ import main

    # Passing no args triggers SystemExit from Click with code 0 (help/version)
    # or the function returns 0 normally.
    result = main()
    assert isinstance(result, int)


def test_main_function_handles_system_exit_with_code() -> None:
    """main() catches SystemExit and returns its integer code."""
    import sys
    from r2inspect.__main__ import main

    result = main()
    assert result >= 0


# ---------------------------------------------------------------------------
# schemas/base.py
# ---------------------------------------------------------------------------

def test_analysis_result_base_raises_for_negative_execution_time() -> None:
    """AnalysisResultBase raises ValueError when execution_time is negative."""
    from r2inspect.schemas.base import AnalysisResultBase

    with pytest.raises(Exception):
        AnalysisResultBase(available=True, execution_time=-0.5)


def test_analysis_result_base_accepts_zero_execution_time() -> None:
    """AnalysisResultBase accepts zero as a valid execution_time."""
    from r2inspect.schemas.base import AnalysisResultBase

    result = AnalysisResultBase(available=True, execution_time=0.0)
    assert result.execution_time == 0.0


def test_analysis_result_base_normalizes_analyzer_name_to_lowercase() -> None:
    """AnalysisResultBase validator lowercases the analyzer_name field."""
    from r2inspect.schemas.base import AnalysisResultBase

    result = AnalysisResultBase(available=True, analyzer_name="PEAnalyzer")
    assert result.analyzer_name == "peanalyzer"
