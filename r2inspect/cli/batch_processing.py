#!/usr/bin/env python3
"""
r2inspect CLI Batch Processing Module

Provides batch file discovery, processing, and parallel execution functions.
Extracted from cli_utils.py for better modularity.

Copyright (C) 2025 Marc Rivero López

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

from rich.console import Console

from ..application.batch_discovery import _is_executable_signature as core_is_executable_signature
from ..application.batch_discovery import (
    check_executable_signature as core_check_executable_signature,
)
from ..application.batch_discovery import discover_executables_by_magic
from ..application.batch_discovery import find_files_by_extensions as core_find_files_by_extensions
from ..application.batch_discovery import is_elf_executable as core_is_elf_executable
from ..application.batch_discovery import is_macho_executable as core_is_macho_executable
from ..application.batch_discovery import is_pe_executable as core_is_pe_executable
from ..application.batch_discovery import is_script_executable as core_is_script_executable
from ..application.batch_service import BatchDependencies, default_batch_service
from ..application.batch_stats import (  # noqa: F401
    collect_batch_statistics,
    update_compiler_stats,
    update_crypto_stats,
    update_file_type_stats,
    update_indicator_stats,
    update_packer_stats,
)
from ..application.options import build_analysis_options
from ..utils.logger import get_logger
from .batch_output import (  # noqa: F401
    create_json_batch_summary,
    determine_csv_file_path,
    get_csv_fieldnames,
    write_csv_results,
)
from .batch_workers import _cap_threads_for_execution, process_files_parallel, process_single_file

console = Console()
logger = get_logger(__name__)

_MAGIC_UNINITIALIZED = object()
magic: Any = _MAGIC_UNINITIALIZED


def _resolve_magic_module() -> Any | None:
    """Resolve python-magic lazily to avoid import-time native crashes on Windows."""
    global magic
    if magic is not _MAGIC_UNINITIALIZED:
        return magic

    if sys.platform == "win32":
        magic = None
        return None

    try:
        import magic as _magic_import

        magic = _magic_import
    except Exception:
        magic = None

    return magic


def _init_magic() -> tuple[Any, Any] | None:
    """Initialize magic detectors using the module-level magic import."""
    if magic is _MAGIC_UNINITIALIZED:
        return None
    if magic is None:
        return None
    try:
        return magic.Magic(mime=True), magic.Magic()
    except Exception:
        return None


def setup_rate_limiter(threads: int, verbose: bool) -> Any:
    """Setup rate limiter for batch processing"""
    from ..utils.rate_limiter import BatchRateLimiter

    effective_threads = _cap_threads_for_execution(threads)
    base_rate = min(effective_threads * 1.5, 25.0)
    rate_limiter = BatchRateLimiter(
        max_concurrent=effective_threads,
        rate_per_second=base_rate,
        burst_size=effective_threads * 3,
        enable_adaptive=True,
    )

    if verbose:
        console.print(
            f"[blue]Rate limiting: {base_rate:.1f} files/sec, adaptive mode enabled[/blue]"
        )

    return rate_limiter


def check_executable_signature(file_path: Path) -> bool:
    """Check for executable signatures in file header (PE, ELF, Mach-O)"""
    return core_check_executable_signature(file_path)


def _is_executable_signature(mime_type: str, description: str) -> bool:
    """Check for executable signatures based on mime and description."""
    return core_is_executable_signature(mime_type, description)


def is_pe_executable(header: bytes, file_handle: Any) -> bool:
    return core_is_pe_executable(header, file_handle)


def is_elf_executable(header: bytes) -> bool:
    return core_is_elf_executable(header)


def is_macho_executable(header: bytes) -> bool:
    return core_is_macho_executable(header)


def is_script_executable(header: bytes) -> bool:
    return core_is_script_executable(header)


def find_executable_files_by_magic(
    directory: str | Path, recursive: bool = False, verbose: bool = False
) -> list[Path]:
    """Find executable files using magic bytes detection (PE, ELF, Mach-O, etc.)"""
    magic_module = _resolve_magic_module()
    files, init_errors, file_errors, scanned = discover_executables_by_magic(
        directory,
        recursive=recursive,
        magic_module=magic_module,
    )

    for message in init_errors:
        if message.startswith("Error initializing magic:"):
            console.print(f"[red]{message}[/red]")
            console.print("[yellow]Falling back to file extension detection[/yellow]")
        else:
            console.print(f"[yellow]{message}[/yellow]")
        return []

    if verbose:
        console.print(f"[blue]Scanning {scanned} files for executable signatures...[/blue]")

    for file_path, error in file_errors:
        if verbose:
            console.print(f"[yellow]Error checking {file_path}: {error}[/yellow]")

    if verbose:
        for file_path in files:
            console.print(f"[green]Found executable: {file_path}[/green]")

    return files


def display_batch_results(
    all_results: dict[str, dict[str, Any]],
    failed_files: list[tuple[str, str]],
    elapsed_time: float,
    files_to_process: list[Path],
    rate_limiter: Any,
    verbose: bool,
    output_filename: str | None,
) -> None:
    """Display final batch analysis results"""
    # Get rate limiter statistics
    rate_stats = rate_limiter.get_stats()

    # Clean final report
    success_count = len(all_results)
    total_count = len(files_to_process)

    console.print("\n[bold green]Analysis Complete![/bold green]")
    console.print(f"[green]Processed: {success_count}/{total_count} files[/green]")
    console.print(f"[blue]Time: {elapsed_time:.1f}s[/blue]")
    console.print(f"[cyan]Rate: {success_count / elapsed_time:.1f} files/sec[/cyan]")

    if verbose and rate_stats:
        display_rate_limiter_stats(rate_stats)
        display_memory_stats()

    if output_filename:
        console.print(f"[cyan]Output: {output_filename}[/cyan]")

    if failed_files:
        display_failed_files(failed_files, verbose)


def _safe_exit(code: int = 0) -> None:
    if os.getenv("R2INSPECT_TEST_SAFE_EXIT"):
        raise SystemExit(code)
    os._exit(code)  # pragma: no cover


def ensure_batch_shutdown(timeout: float = 2.0) -> None:
    """Ensure batch execution does not hang on lingering non-daemon threads."""
    deadline = time.time() + timeout
    current = threading.current_thread()

    def _remaining_threads() -> list[threading.Thread]:
        return [
            thread
            for thread in threading.enumerate()
            if thread is not current and not thread.daemon
        ]

    remaining = _remaining_threads()
    for thread in remaining:
        remaining_time = max(0.0, deadline - time.time())
        if remaining_time <= 0:
            break
        thread.join(timeout=remaining_time)

    remaining = _remaining_threads()
    if remaining:
        names = ", ".join(thread.name for thread in remaining)
        logger.warning("Forcing batch shutdown with lingering threads: %s", names)
        _flush_coverage_data()
        _safe_exit(0)


def schedule_forced_exit(delay: float = 2.0) -> None:
    """Schedule a forced process exit to prevent batch hangs."""
    if os.getenv("R2INSPECT_DISABLE_FORCED_EXIT"):
        return

    def _exit() -> None:
        sys.stdout.flush()
        sys.stderr.flush()
        _flush_coverage_data()
        _safe_exit(0)

    timer = threading.Timer(delay, _exit)
    timer.daemon = True
    timer.start()


def _flush_coverage_data() -> None:
    """Persist coverage data when running under coverage."""
    cov: Any | None = None
    try:
        if os.getenv("R2INSPECT_TEST_COVERAGE_IMPORT_ERROR"):
            raise ImportError("Simulated coverage import error")
        import coverage
    except Exception:
        return
    try:
        if os.getenv("R2INSPECT_TEST_COVERAGE_CURRENT_ERROR"):
            raise RuntimeError("Simulated coverage current error")
        if os.getenv("R2INSPECT_TEST_COVERAGE_DUMMY"):

            class _DummyCoverage:
                def stop(self) -> None:  # pragma: no cover
                    return None

                def save(self) -> None:
                    return None

            cov = _DummyCoverage()
        else:
            cov = coverage.Coverage.current()
    except Exception:
        return
    if os.getenv("R2INSPECT_TEST_COVERAGE_NONE"):
        cov = None
    if cov is None:
        return
    try:
        if os.getenv("R2INSPECT_TEST_COVERAGE_SAVE_ERROR"):
            raise RuntimeError("Simulated coverage save error")
        if _pytest_running():
            cov.save()
            return
        cov.save()  # pragma: no cover
    except Exception:
        pass


def _pytest_running() -> bool:
    """Detect pytest runtime to avoid stopping coverage from background threads."""
    if os.getenv("R2INSPECT_TEST_MODE", "").lower() in {"1", "true", "yes"}:
        return True
    if os.getenv("R2INSPECT_TEST_SAFE_EXIT"):
        return True
    if os.getenv("PYTEST_CURRENT_TEST"):
        return True
    if any(key.startswith("R2INSPECT_TEST_COVERAGE_") for key in os.environ):
        return True
    if any("pytest" in arg for arg in sys.argv):
        return True
    return "pytest" in sys.modules  # pragma: no cover


def setup_batch_mode(
    batch: str,
    extensions: str | None,
    output_json: bool,
    output_csv: bool,
    output: str | None,
) -> tuple[bool, bool, str | None]:
    """Setup batch mode parameters"""
    recursive = True  # Always recursive
    use_auto_detect = not extensions  # Auto-detect if no extensions specified

    # Set default output directory if not specified but JSON/CSV requested
    if (output_json or output_csv) and not output:
        output = "output"

    return recursive, use_auto_detect, output


def setup_single_file_output(
    output_json: bool, output_csv: bool, output: str | None, filename: str
) -> str | Path | None:
    """Setup output file for single file mode"""
    if (output_json or output_csv) and not output:
        # Create output directory if it doesn't exist
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

        # Generate filename based on input file
        input_path = Path(filename)
        base_name = input_path.stem

        if output_json:
            output = str(output_dir / f"{base_name}_analysis.json")
        elif output_csv:
            output = str(output_dir / f"{base_name}_analysis.csv")

    return output


def setup_analysis_options(yara: str | None, sanitized_xor: str | None) -> dict[str, Any]:
    """Setup analysis options with all modules enabled by default"""
    return build_analysis_options(yara, sanitized_xor)


def display_rate_limiter_stats(rate_stats: dict[str, Any]) -> None:
    """Display rate limiter statistics"""
    console.print("[dim]Rate limiter stats:[/dim]")
    console.print(f"[dim]  Success rate: {rate_stats.get('success_rate', 0):.1%}[/dim]")
    console.print(f"[dim]  Avg wait time: {rate_stats.get('avg_wait_time', 0):.2f}s[/dim]")
    console.print(f"[dim]  Final rate: {rate_stats.get('current_rate', 0):.1f} files/sec[/dim]")


def display_memory_stats() -> None:
    """Display memory statistics if available"""
    from ..utils.memory_manager import get_memory_stats

    memory_stats = get_memory_stats()
    if memory_stats.get("status") != "error":
        console.print("[dim]Memory stats:[/dim]")
        console.print(f"[dim]  Peak usage: {memory_stats.get('peak_memory_mb', 0):.1f}MB[/dim]")
        console.print(
            f"[dim]  Current usage: {memory_stats.get('process_memory_mb', 0):.1f}MB[/dim]"
        )
        console.print(f"[dim]  GC cycles: {memory_stats.get('gc_count', 0)}[/dim]")


def display_failed_files(failed_files: list[tuple[str, str]], verbose: bool) -> None:
    """Display failed files information"""
    console.print(f"[red]Failed: {len(failed_files)} files[/red]")
    if verbose:
        console.print("\n[red]Failed files details:[/red]")
        for failed_file, error in failed_files[:10]:  # Show first 10 errors
            console.print(
                f"[dim]{failed_file}: {error[:100]}{'...' if len(error) > 100 else ''}[/dim]"
            )
        if len(failed_files) > 10:
            console.print(f"[dim]... and {len(failed_files) - 10} more[/dim]")
    else:
        console.print("[dim]Use --verbose to see error details[/dim]")


def handle_main_error(e: Exception, verbose: bool) -> None:
    """Handle errors in main function"""
    console.print(f"[red]Error: {str(e)}[/red]")
    if verbose:
        import traceback

        traceback.print_exc()
    sys.exit(1)


def find_files_to_process(
    batch_path: Path,
    auto_detect: bool,
    extensions: str | None,
    recursive: bool,
    verbose: bool,
    quiet: bool = False,
) -> list[Path]:
    """Find files to process based on auto-detection or extensions"""
    files_to_process: list[Path] = []

    if auto_detect:
        if not quiet:
            console.print("[blue]Auto-detecting executable files (default behavior)...[/blue]")
        files_to_process = find_executable_files_by_magic(batch_path, recursive, verbose)
    else:
        if not quiet:
            console.print(f"[blue]Searching for files with extensions: {extensions}[/blue]")
        if not extensions:
            return []
        files_to_process = find_files_by_extensions(batch_path, extensions, recursive)

    return files_to_process


def find_files_by_extensions(batch_path: Path, extensions: str, recursive: bool) -> list[Path]:
    """Find files by specified extensions"""
    return core_find_files_by_extensions(batch_path, extensions, recursive)


def display_no_files_message(auto_detect: bool, extensions: str | None) -> None:
    """Display appropriate message when no files are found"""
    if auto_detect:
        console.print("[yellow]No executable files detected in the directory[/yellow]")
        console.print("[dim]Tip: Files might not be executable format or may be corrupted[/dim]")
    else:
        console.print(f"[yellow]No files found with extensions: {extensions}[/yellow]")
        console.print("[dim]Tip: Use without --extensions for auto-detection[/dim]")


def setup_batch_output_directory(
    output_dir: str | None, output_json: bool, output_csv: bool
) -> Path:
    """Setup the output directory for batch processing"""
    if output_dir:
        output_path = Path(output_dir)

        # Check if user specified a filename with extension
        if output_path.suffix in [".csv", ".json"]:
            # User provided a specific filename - ensure parent directory exists
            parent_dir = output_path.parent
            if not parent_dir.exists():
                parent_dir.mkdir(parents=True, exist_ok=True)
        else:
            # User provided a directory - create it if needed
            if not output_path.exists():
                output_path.mkdir(parents=True, exist_ok=True)
    elif output_json or output_csv:
        # Default output directory when formats are specified
        output_path = Path("output")
        output_path.mkdir(exist_ok=True)
    else:
        # Fallback directory when no formats specified
        output_path = Path("r2inspect_batch_results")
        output_path.mkdir(exist_ok=True)

    return output_path


def run_batch_analysis(
    batch_dir: str,
    options: dict[str, Any],
    output_json: bool,
    output_csv: bool,
    output_dir: str | None,
    recursive: bool,
    extensions: str | None,
    verbose: bool,
    config_obj: Any,
    auto_detect: bool,
    threads: int = 10,
    quiet: bool = False,
) -> None:
    """Run batch analysis on multiple files in a directory"""

    def _display_found_files(count: int, thread_count: int) -> None:
        if quiet:
            return
        console.print(f"[bold green]Found {count} files to process[/bold green]")
        console.print(f"[blue]Using {thread_count} parallel threads[/blue]")

    def _configure_quiet_logging() -> None:
        import logging as _logging

        _logging.getLogger("r2inspect").setLevel(_logging.CRITICAL)
        _logging.getLogger("r2inspect.modules").setLevel(_logging.CRITICAL)

    def _configure_batch_logging() -> None:
        from ..utils.logger import configure_batch_logging

        configure_batch_logging()

    from .batch_output import create_batch_summary

    deps = BatchDependencies(
        find_files_to_process=find_files_to_process,
        display_no_files_message=display_no_files_message,
        setup_output_directory=setup_batch_output_directory,
        setup_rate_limiter=setup_rate_limiter,
        process_files_parallel=process_files_parallel,
        create_batch_summary=create_batch_summary,
        display_batch_results=display_batch_results,
        display_found_files=_display_found_files,
        configure_batch_logging=_configure_batch_logging,
        configure_quiet_logging=_configure_quiet_logging,
        now=time.time,
    )

    default_batch_service.run_batch_analysis(
        batch_dir=batch_dir,
        options=options,
        output_json=output_json,
        output_csv=output_csv,
        output_dir=output_dir,
        recursive=recursive,
        extensions=extensions,
        verbose=verbose,
        config_obj=config_obj,
        auto_detect=auto_detect,
        threads=threads,
        quiet=quiet,
        deps=deps,
    )
