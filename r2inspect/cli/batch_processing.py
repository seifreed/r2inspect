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

import csv
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

try:
    import magic
except Exception:  # pragma: no cover - optional dependency
    magic = None
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeRemainingColumn

from ..core import R2Inspector
from ..utils.output import OutputFormatter

console = Console()

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


def _init_magic() -> tuple[magic.Magic, magic.Magic] | None:
    if magic is None:
        console.print("[yellow]python-magic not available; skipping magic-based detection[/yellow]")
        return None
    try:
        return magic.Magic(mime=True), magic.Magic()
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


def is_pe_executable(header: bytes, file_handle) -> bool:
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


def setup_rate_limiter(threads: int, verbose: bool):
    """Setup rate limiter for batch processing"""
    from ..utils.rate_limiter import BatchRateLimiter

    base_rate = min(threads * 1.5, 25.0)
    rate_limiter = BatchRateLimiter(
        max_concurrent=threads,
        rate_per_second=base_rate,
        burst_size=threads * 3,
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
    config_obj,
    options: dict,
    output_json: bool,
    output_path: Path,
    rate_limiter,
) -> tuple[Path, dict | None, str | None]:
    """Process a single file with rate limiting"""

    if not rate_limiter.acquire(timeout=30.0):
        return file_path, None, "Rate limit timeout - system overloaded"

    try:
        with R2Inspector(
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
    all_results: dict,
    failed_files: list,
    output_path: Path,
    batch_path: Path,
    config_obj,
    options: dict,
    output_json: bool,
    threads: int,
    rate_limiter,
) -> None:
    """Process files in parallel with progress tracking"""
    results_lock = threading.Lock()
    progress_lock = threading.Lock()

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Processing files...", total=len(files_to_process))
        completed_count = 0

        with ThreadPoolExecutor(max_workers=threads) as executor:
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
                        file_key = file_path.name
                        all_results[file_key] = results


def display_batch_results(
    all_results: dict,
    failed_files: list,
    elapsed_time: float,
    files_to_process: list[Path],
    rate_limiter,
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


def setup_analysis_options(yara: str | None, sanitized_xor: str | None) -> dict:
    """Setup analysis options with all modules enabled by default"""
    return {
        "detect_packer": True,
        "detect_crypto": True,
        "detect_av": True,
        "full_analysis": True,
        "custom_yara": yara,
        "xor_search": sanitized_xor,
    }


def display_rate_limiter_stats(rate_stats: dict) -> None:
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


def display_failed_files(failed_files: list, verbose: bool) -> None:
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


def get_csv_fieldnames() -> list[str]:
    """Get CSV fieldnames for batch output"""
    return [
        "name",
        "size",
        "compile_time",
        "file_type",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "imphash",
        "ssdeep_hash",
        "tlsh_binary",
        "tlsh_text_section",
        "tlsh_functions_with_hash",
        "telfhash",
        "telfhash_symbols_used",
        "rich_header_xor_key",
        "rich_header_checksum",
        "richpe_hash",
        "rich_header_compilers",
        "rich_header_entries",
        "compiler",
        "compiler_version",
        "compiler_confidence",
        "imports",
        "exports",
        "sections",
        "anti_debug",
        "anti_vm",
        "anti_sandbox",
        "yara_matches",
        "num_functions",
        "num_unique_machoc",
        "num_duplicate_functions",
        "num_imports",
        "num_exports",
        "num_sections",
    ]


def write_csv_results(csv_file: Path, all_results: dict) -> None:
    """Write analysis results to CSV file"""
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        fieldnames = get_csv_fieldnames()
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for file_key, result in all_results.items():
            formatter = OutputFormatter(result)
            csv_data = formatter._extract_csv_data(result)
            writer.writerow(csv_data)


def determine_csv_file_path(output_path: Path, timestamp: str) -> tuple[Path, str]:
    """Determine the CSV file path based on output configuration"""
    if output_path.suffix == ".csv":
        # User provided specific CSV filename
        return output_path, output_path.name
    else:
        # User provided directory, create CSV with timestamp
        csv_filename = f"r2inspect_{timestamp}.csv"
        csv_file = output_path / csv_filename
        return csv_file, csv_filename


def update_packer_stats(stats: dict, file_key: str, result: dict) -> None:
    """Update packer statistics"""
    if "packer_info" in result and result["packer_info"].get("detected"):
        stats["packers_detected"].append(
            {
                "file": file_key,
                "packer": result["packer_info"].get("name", "Unknown"),
            }
        )


def update_crypto_stats(stats: dict, file_key: str, result: dict) -> None:
    """Update crypto pattern statistics"""
    if "crypto_info" in result and result["crypto_info"]:
        for crypto in result["crypto_info"]:
            stats["crypto_patterns"].append({"file": file_key, "pattern": crypto})


def update_indicator_stats(stats: dict, file_key: str, result: dict) -> None:
    """Update suspicious indicator statistics"""
    if "indicators" in result and result["indicators"]:
        stats["suspicious_indicators"].extend(
            [{"file": file_key, **indicator} for indicator in result["indicators"]]
        )


def update_file_type_stats(stats: dict, result: dict) -> None:
    """Update file type and architecture statistics"""
    if "file_info" in result:
        file_type = result["file_info"].get("file_type", "Unknown")
        stats["file_types"][file_type] = stats["file_types"].get(file_type, 0) + 1

        architecture = result["file_info"].get("architecture", "Unknown")
        stats["architectures"][architecture] = stats["architectures"].get(architecture, 0) + 1


def update_compiler_stats(stats: dict, result: dict) -> None:
    """Update compiler statistics"""
    if "compiler" in result:
        compiler_info = result["compiler"]
        compiler_name = compiler_info.get("compiler", "Unknown")
        if compiler_info.get("detected", False):
            stats["compilers"][compiler_name] = stats["compilers"].get(compiler_name, 0) + 1


def collect_batch_statistics(all_results: dict) -> dict:
    """Collect statistics from batch analysis results"""
    stats: dict[str, Any] = {
        "packers_detected": [],
        "crypto_patterns": [],
        "suspicious_indicators": [],
        "file_types": {},
        "architectures": {},
        "compilers": {},
    }

    for file_key, result in all_results.items():
        update_packer_stats(stats, file_key, result)
        update_crypto_stats(stats, file_key, result)
        update_indicator_stats(stats, file_key, result)
        update_file_type_stats(stats, result)
        update_compiler_stats(stats, result)

    return stats


def create_json_batch_summary(
    all_results: dict, failed_files: list, output_path: Path, timestamp: str
) -> str:
    """Create JSON batch summary file"""
    from datetime import datetime

    summary = {
        "batch_summary": {
            "total_files": len(all_results) + len(failed_files),
            "successful_analyses": len(all_results),
            "failed_analyses": len(failed_files),
            "timestamp": datetime.now().isoformat(),
            "processed_files": list(all_results.keys()),
        },
        "results": all_results,
        "failed_files": [{"file": f[0], "error": f[1]} for f in failed_files],
    }

    # Add aggregated statistics
    summary["statistics"] = collect_batch_statistics(all_results)

    # Save batch summary JSON
    summary_file = output_path / f"r2inspect_batch_{timestamp}.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)

    return f"{summary_file.name} + individual JSONs"


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
    options: dict,
    output_json: bool,
    output_csv: bool,
    output_dir: str | None,
    recursive: bool,
    extensions: str | None,
    verbose: bool,
    config_obj,
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
    failed_files: list[str] = []

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
