#!/usr/bin/env python3
"""Application models for batch analysis orchestration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BatchDependencies:
    find_files_to_process: Callable[..., list[Path]]
    setup_rate_limiter: Callable[[int, bool], Any]
    process_files_parallel: Callable[..., None]
    display_no_files_message: Callable[[bool, str | None], None] | None = None
    setup_output_directory: Callable[[str | None, bool, bool], Path] | None = None
    create_batch_summary: Callable[..., str | None] | None = None
    display_batch_results: Callable[..., None] | None = None
    display_found_files: Callable[[int, int], None] | None = None
    configure_batch_logging: Callable[[], None] | None = None
    configure_quiet_logging: Callable[[], None] | None = None
    now: Callable[[], float] | None = None


@dataclass(frozen=True)
class BatchExecutionPlan:
    batch_path: Path
    output_path: Path
    files_to_process: list[Path]
