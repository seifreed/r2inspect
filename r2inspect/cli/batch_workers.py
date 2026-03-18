#!/usr/bin/env python3
"""Batch processing workers for CLI execution."""

from __future__ import annotations

import os
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeRemainingColumn

from ..application.use_cases import AnalyzeBinaryUseCase
from ..factory import create_inspector
from ..infrastructure.logging import get_logger
from ..cli.output_formatters import OutputFormatter

console = Console()
logger = get_logger(__name__)


def _cap_threads_for_execution(threads: int) -> int:
    import os

    cap_text = os.getenv("R2INSPECT_MAX_THREADS", "").strip()
    if not cap_text:
        return threads
    try:
        cap = int(cap_text)
    except ValueError:
        return threads
    if cap <= 0:
        return threads
    return min(threads, cap)


def process_single_file(
    file_path: Path,
    batch_path: Path,
    config_obj: Any,
    options: dict[str, Any],
    output_json: bool,
    output_path: Path,
    rate_limiter: Any,
) -> tuple[Path, dict | None, str | None]:
    """Process a single file with rate limiting."""
    if not rate_limiter.acquire(timeout=30.0):
        return file_path, None, "Rate limit timeout - system overloaded"

    try:
        with create_inspector(
            filename=str(file_path),
            config=config_obj,
            verbose=False,
        ) as inspector:
            analysis_options = {**options, "batch_mode": True}
            result = AnalyzeBinaryUseCase().run(inspector, analysis_options)
            results = result.to_dict()
            results["filename"] = str(file_path)
            results["relative_path"] = str(file_path.relative_to(batch_path))

            if output_json:
                formatter = OutputFormatter(results)
                json_output = formatter.to_json()
                json_file = output_path / f"{file_path.stem}_analysis.json"
                # Write atomically: write to temp file then rename to prevent partial files
                tmp_file = json_file.with_suffix(".json.tmp")
                try:
                    with open(tmp_file, "w", encoding="utf-8") as f:
                        f.write(json_output)
                    try:
                        os.replace(str(tmp_file), str(json_file))
                    except OSError:
                        shutil.move(str(tmp_file), str(json_file))
                except Exception:
                    # Clean up partial temp file on failure
                    try:
                        tmp_file.unlink(missing_ok=True)
                    except OSError:
                        pass
                    raise

            rate_limiter.release_success()
            return file_path, results, None

    except Exception as e:
        error_type = type(e).__name__
        rate_limiter.release_error(error_type)
        return file_path, None, str(e)


def process_files_parallel(
    files_to_process: list[Path],
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    output_path: Path,
    batch_path: Path,
    config_obj: Any,
    options: dict[str, Any],
    output_json: bool,
    threads: int,
    rate_limiter: Any,
) -> None:
    """Process files in parallel with progress tracking."""
    results_lock = threading.Lock()
    progress_lock = threading.Lock()
    effective_threads = _cap_threads_for_execution(threads)

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Processing files...", total=len(files_to_process))
        completed_count = 0

        with ThreadPoolExecutor(max_workers=effective_threads) as executor:
            future_to_file = {
                executor.submit(
                    process_single_file,
                    file_path,
                    batch_path,
                    config_obj,
                    options,
                    output_json,
                    output_path,
                    rate_limiter,
                ): file_path
                for file_path in files_to_process
            }

            for future in as_completed(future_to_file):
                file_path, results, error = future.result()

                with progress_lock:
                    completed_count += 1
                    progress.update(
                        task,
                        completed=completed_count,
                        description=f"Processing files... ({file_path.name[:30]}{'...' if len(file_path.name) > 30 else ''})",
                    )

                with results_lock:
                    if error:
                        failed_files.append((str(file_path), error))
                    else:
                        if results is None:
                            failed_files.append((str(file_path), "Empty results"))
                        else:
                            # Use full path as key to avoid collisions
                            # between files with the same basename in different dirs
                            file_key = str(file_path)
                            all_results[file_key] = results
        progress.stop()
