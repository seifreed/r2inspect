"""Domain models for analysis execution workflows."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AnalysisRuntimeStats:
    """Runtime statistics collected during analysis."""

    error_stats: dict[str, Any]
    retry_stats: dict[str, Any]
    circuit_breaker_stats: dict[str, Any]


@dataclass(frozen=True)
class BatchRunResult:
    """Pure batch execution result before presentation/output formatting.

    ``all_results`` maps file paths to their analysis result dicts.
    The batch worker converts each ``AnalysisResult`` to a plain dict
    before storing it here so that downstream output formatters and
    summary generators continue to work unchanged.
    """

    files_to_process: list[Path]
    all_results: dict[str, dict[str, Any]]
    failed_files: list[tuple[str, str]]
    elapsed_time: float
    output_path: Path
