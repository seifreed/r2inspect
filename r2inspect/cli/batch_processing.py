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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeRemainingColumn

from ..adapters.magic_adapter import MagicAdapter
from ..application.batch_stats import (  # noqa: F401
    collect_batch_statistics,
    update_compiler_stats,
    update_crypto_stats,
    update_file_type_stats,
    update_indicator_stats,
    update_packer_stats,
)
from ..application.options import build_analysis_options
from ..factory import create_inspector
from ..utils.logger import get_logger
from ..utils.output import OutputFormatter
from .batch_output import (  # noqa: F401
    create_json_batch_summary,
    determine_csv_file_path,
    get_csv_fieldnames,
    write_csv_results,
)

console = Console()
logger = get_logger(__name__)
magic_adapter = MagicAdapter()

EXECUTABLE_SIGNATURES = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-pie-executable",
    "application/octet-stream",
}

EXECUTABLE_DESCRIPTIONS = (
    "PE32 executable",
    "PE32+ executable",
    "MS-DOS executable",
    "Microsoft Portable Executable",
    "ELF",
    "Mach-O",
    "executable",
    "shared object",
    "dynamically linked",
)


def _init_magic() -> tuple[Any, Any] | None:
    if not magic_adapter.available:
        console.print("[yellow]python-magic not available; skipping magic-based detection[/yellow]")
        return None
    try:
        return magic_adapter.create_detectors()
    except Exception as e:
        console.print(f"[red]Error initializing magic: {e}[/red]")
        console.print("[yellow]Falling back to file extension detection[/yellow]")
        return None


def _is_executable_signature(mime_type: str, description: str) -> bool:
    if mime_type in EXECUTABLE_SIGNATURES:
        return True
    return any(desc in description for desc in EXECUTABLE_DESCRIPTIONS)


def _iter_files(directory: Path, recursive: bool) -> list[Path]:
    return list(directory.rglob("*")) if recursive else list(directory.glob("*"))


def find_executable_files_by_magic(
    directory: str | Path, recursive: bool = False, verbose: bool = False
) -> list[Path]:
    """Find executable files using magic bytes detection (PE, ELF, Mach-O, etc.)"""
    executable_files: list[Path] = []
    directory = Path(directory)

    magic_tuple = _init_magic()
    if magic_tuple is None:
        return []
    mime_magic, desc_magic = magic_tuple

    regular_files = [f for f in _iter_files(directory, recursive) if f.is_file()]

    if verbose:
        console.print(
            f"[blue]Scanning {len(regular_files)} files for executable signatures...[/blue]"
        )

    for file_path in regular_files:
        try:
            if file_path.stat().st_size < 64:
                continue

            mime_type = mime_magic.from_file(str(file_path))
            description = desc_magic.from_file(str(file_path))
        except Exception as e:
            if verbose:
                console.print(f"[yellow]Error checking {file_path}: {e}[/yellow]")
            continue

        if _is_executable_signature(mime_type, description):
            executable_files.append(file_path)
            if verbose:
                console.print(f"[green]Found executable: {file_path}[/green]")

    return executable_files


def check_executable_signature(file_path: Path) -> bool:
    """Check for executable signatures in file header (PE, ELF, Mach-O)"""
    try:
        with open(file_path, "rb") as f:
            header = f.read(64)
            if len(header) < 4:
                return False

            # Check signatures
            return (
                is_pe_executable(header, f)
                or is_elf_executable(header)
                or is_macho_executable(header)
                or is_script_executable(header)
            )

    except Exception:
        return False


def is_pe_executable(header: bytes, file_handle: Any) -> bool:
    """Check if file has PE (Windows) executable signature"""
    if header[:2] != b"MZ":
        return False

    if len(header) >= 64:
        try:
            pe_offset = int.from_bytes(header[60:64], byteorder="little")
            file_handle.seek(pe_offset)
            pe_signature = file_handle.read(4)
            if pe_signature == b"PE\x00\x00":
                return True
        except (OSError, ValueError):
            # Failed to read PE header - not a valid PE file
            pass
    return True  # MZ header is good enough indication


def is_elf_executable(header: bytes) -> bool:
    """Check if file has ELF (Linux/Unix) executable signature"""
    return header[:4] == b"\x7fELF"


def is_macho_executable(header: bytes) -> bool:
    """Check if file has Mach-O (macOS) executable signature"""
    mach_o_magics = [
        b"\xfe\xed\xfa\xce",  # 32-bit big endian
        b"\xce\xfa\xed\xfe",  # 32-bit little endian
        b"\xfe\xed\xfa\xcf",  # 64-bit big endian
        b"\xcf\xfa\xed\xfe",  # 64-bit little endian
        b"\xca\xfe\xba\xbe",  # Universal binary
    ]
    return header[:4] in mach_o_magics


def is_script_executable(header: bytes) -> bool:
    """Check if file has script shebang"""
    return header[:2] == b"#!"


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


def process_single_file(
    file_path: Path,
    batch_path: Path,
    config_obj: Any,
    options: dict[str, Any],
    output_json: bool,
    output_path: Path,
    rate_limiter: Any,
) -> tuple[Path, dict | None, str | None]:
    """Process a single file with rate limiting"""

    if not rate_limiter.acquire(timeout=30.0):
        return file_path, None, "Rate limit timeout - system overloaded"

    try:
        with create_inspector(
            filename=str(file_path),
            config=config_obj,
            verbose=False,
        ) as inspector:
            analysis_options = {**options, "batch_mode": True}
            results = inspector.analyze(**analysis_options)
            results["filename"] = str(file_path)
            results["relative_path"] = str(file_path.relative_to(batch_path))

            if output_json:
                formatter = OutputFormatter(results)
                json_output = formatter.to_json()
                json_file = output_path / f"{file_path.stem}_analysis.json"
                with open(json_file, "w") as f:
                    f.write(json_output)

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
    """Process files in parallel with progress tracking"""
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
                            file_key = file_path.name
                            all_results[file_key] = results
        progress.stop()


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
    os._exit(code)


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
                def stop(self) -> None:
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
        cov.save()
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
    return "pytest" in sys.modules


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
    files_to_process: list[Path] = []
    ext_list = [ext.strip().lower() for ext in extensions.split(",")]

    for ext in ext_list:
        pattern = f"**/*.{ext}" if recursive else f"*.{ext}"
        files_to_process.extend(batch_path.glob(pattern))

    return files_to_process


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
    batch_path = Path(batch_dir)

    # Find files to process
    files_to_process = find_files_to_process(
        batch_path, auto_detect, extensions, recursive, verbose, quiet
    )

    if not files_to_process:
        display_no_files_message(auto_detect, extensions)
        return

    if not quiet:
        console.print(f"[bold green]Found {len(files_to_process)} files to process[/bold green]")
        console.print(f"[blue]Using {threads} parallel threads[/blue]")

    # Configure logging for batch processing
    if not verbose:
        from ..utils.logger import configure_batch_logging

        configure_batch_logging()

    # If quiet mode, suppress even more logging
    if quiet:
        import logging as _logging

        _logging.getLogger("r2inspect").setLevel(_logging.CRITICAL)
        _logging.getLogger("r2inspect.modules").setLevel(_logging.CRITICAL)

    # Setup output directory
    output_path = setup_batch_output_directory(output_dir, output_json, output_csv)

    # Results storage
    all_results: dict[str, dict[str, Any]] = {}
    failed_files: list[tuple[str, str]] = []

    # Start timing
    start_time = time.time()

    # Process files in parallel
    rate_limiter = setup_rate_limiter(threads, verbose)
    process_files_parallel(
        files_to_process,
        all_results,
        failed_files,
        output_path,
        batch_path,
        config_obj,
        options,
        output_json,
        threads,
        rate_limiter,
    )

    # Calculate elapsed time
    elapsed_time = time.time() - start_time

    # Create summary report and get output filename
    from .batch_output import create_batch_summary

    output_filename = create_batch_summary(
        all_results, failed_files, output_path, output_json, output_csv
    )

    # Display final results
    display_batch_results(
        all_results,
        failed_files,
        elapsed_time,
        files_to_process,
        rate_limiter,
        verbose,
        output_filename,
    )
