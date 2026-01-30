#!/usr/bin/env python3
"""
r2inspect CLI Batch Output Module

Provides CSV and JSON batch output functions.
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
import re
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from ..utils.output import OutputFormatter

console = Console()


def get_csv_fieldnames():
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


def write_csv_results(csv_file, all_results):
    """Write analysis results to CSV file"""
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        fieldnames = get_csv_fieldnames()
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for file_key, result in all_results.items():
            formatter = OutputFormatter(result)
            csv_data = formatter._extract_csv_data(result)
            writer.writerow(csv_data)


def determine_csv_file_path(output_path, timestamp):
    """Determine the CSV file path based on output configuration"""
    if output_path.suffix == ".csv":
        # User provided specific CSV filename
        return output_path, output_path.name
    else:
        # User provided directory, create CSV with timestamp
        csv_filename = f"r2inspect_{timestamp}.csv"
        csv_file = output_path / csv_filename
        return csv_file, csv_filename


def update_packer_stats(stats, file_key, result):
    """Update packer statistics"""
    if "packer_info" in result and result["packer_info"].get("detected"):
        stats["packers_detected"].append(
            {
                "file": file_key,
                "packer": result["packer_info"].get("name", "Unknown"),
            }
        )


def update_crypto_stats(stats, file_key, result):
    """Update crypto pattern statistics"""
    if "crypto_info" in result and result["crypto_info"]:
        for crypto in result["crypto_info"]:
            stats["crypto_patterns"].append({"file": file_key, "pattern": crypto})


def update_indicator_stats(stats, file_key, result):
    """Update suspicious indicator statistics"""
    if "indicators" in result and result["indicators"]:
        stats["suspicious_indicators"].extend(
            [{"file": file_key, **indicator} for indicator in result["indicators"]]
        )


def update_file_type_stats(stats, result):
    """Update file type and architecture statistics"""
    if "file_info" in result:
        file_type = result["file_info"].get("file_type", "Unknown")
        stats["file_types"][file_type] = stats["file_types"].get(file_type, 0) + 1

        architecture = result["file_info"].get("architecture", "Unknown")
        stats["architectures"][architecture] = stats["architectures"].get(architecture, 0) + 1


def update_compiler_stats(stats, result):
    """Update compiler statistics"""
    if "compiler" in result:
        compiler_info = result["compiler"]
        compiler_name = compiler_info.get("compiler", "Unknown")
        if compiler_info.get("detected", False):
            stats["compilers"][compiler_name] = stats["compilers"].get(compiler_name, 0) + 1


def collect_batch_statistics(all_results):
    """Collect statistics from batch analysis results"""
    stats = {
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


def create_json_batch_summary(all_results, failed_files, output_path, timestamp):
    """Create JSON batch summary file"""
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


def find_files_to_process(batch_path, auto_detect, extensions, recursive, verbose, quiet=False):
    """Find files to process based on auto-detection or extensions"""
    files_to_process = []

    if auto_detect:
        if not quiet:
            console.print("[blue]Auto-detecting executable files (default behavior)...[/blue]")
        from .batch_processing import find_executable_files_by_magic

        files_to_process = find_executable_files_by_magic(batch_path, recursive, verbose)
    else:
        if not quiet:
            console.print(f"[blue]Searching for files with extensions: {extensions}[/blue]")
        files_to_process = find_files_by_extensions(batch_path, extensions, recursive)

    return files_to_process


def find_files_by_extensions(batch_path, extensions, recursive):
    """Find files by specified extensions"""
    files_to_process = []
    ext_list = [ext.strip().lower() for ext in extensions.split(",")]

    for ext in ext_list:
        pattern = f"**/*.{ext}" if recursive else f"*.{ext}"
        files_to_process.extend(batch_path.glob(pattern))

    return files_to_process


def display_no_files_message(auto_detect, extensions):
    """Display appropriate message when no files are found"""
    if auto_detect:
        console.print("[yellow]No executable files detected in the directory[/yellow]")
        console.print("[dim]Tip: Files might not be executable format or may be corrupted[/dim]")
    else:
        console.print(f"[yellow]No files found with extensions: {extensions}[/yellow]")
        console.print("[dim]Tip: Use without --extensions for auto-detection[/dim]")


def setup_batch_output_directory(output_dir, output_json, output_csv):
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


def _configure_batch_logging(verbose: bool, quiet: bool) -> None:
    if not verbose:
        from .utils.logger import configure_batch_logging

        configure_batch_logging()

    if quiet:
        import logging

        logging.getLogger("r2inspect").setLevel(logging.CRITICAL)
        logging.getLogger("r2inspect.modules").setLevel(logging.CRITICAL)


def _prepare_batch_run(
    batch_path: Path,
    auto_detect: bool,
    extensions: str | None,
    recursive: bool,
    verbose: bool,
    quiet: bool,
    output_dir: str | None,
    output_json: bool,
    output_csv: bool,
    threads: int,
) -> tuple[list[Path], Path] | None:
    files_to_process = find_files_to_process(
        batch_path, auto_detect, extensions, recursive, verbose, quiet
    )

    if not files_to_process:
        display_no_files_message(auto_detect, extensions)
        return None

    if not quiet:
        console.print(f"[bold green]Found {len(files_to_process)} files to process[/bold green]")
        console.print(f"[blue]Using {threads} parallel threads[/blue]")

    _configure_batch_logging(verbose, quiet)
    output_path = setup_batch_output_directory(output_dir, output_json, output_csv)
    return files_to_process, output_path


def _init_batch_results() -> tuple[dict, list]:
    return {}, []


def run_batch_analysis(
    batch_dir,
    options,
    output_json,
    output_csv,
    output_dir,
    recursive,
    extensions,
    verbose,
    config_obj,
    auto_detect,
    threads=10,
    quiet=False,
):
    """Run batch analysis on multiple files in a directory"""
    batch_path = Path(batch_dir)

    prepared = _prepare_batch_run(
        batch_path,
        auto_detect,
        extensions,
        recursive,
        verbose,
        quiet,
        output_dir,
        output_json,
        output_csv,
        threads,
    )
    if prepared is None:
        return
    files_to_process, output_path = prepared

    all_results, failed_files = _init_batch_results()

    # Start timing
    import time

    start_time = time.time()

    # Process files in parallel
    from .batch_processing import display_batch_results, process_files_parallel, setup_rate_limiter

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


def create_batch_summary(all_results, failed_files, output_path, output_json, output_csv):
    """Create summary report for batch analysis with custom output behavior"""
    # Generate timestamp for CSV filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = None

    # Handle different output combinations
    if output_csv and not output_json:
        # Case 1: Solo CSV (-c) - Use user-specified filename or default with timestamp
        csv_file, output_filename = determine_csv_file_path(output_path, timestamp)
        write_csv_results(csv_file, all_results)

    elif output_json and output_csv:
        # Case 2: JSON + CSV (-j -c) - CSV summary + individual JSON files
        csv_file, csv_filename = determine_csv_file_path(output_path, timestamp)
        if output_path.suffix == ".csv":
            output_filename = f"{output_path.name} + individual JSONs"
        else:
            output_filename = f"{csv_filename} + individual JSONs"
        write_csv_results(csv_file, all_results)

    elif output_json and not output_csv:
        # Case 3: Solo JSON (-j) - Individual JSON files + batch summary
        output_filename = create_json_batch_summary(
            all_results, failed_files, output_path, timestamp
        )

    # Show summary table
    _show_summary_table(all_results)

    return output_filename


def _show_summary_table(all_results):
    """Show a summary table of all analyzed files"""
    if len(all_results) > 10:
        table = _build_summary_table_small(all_results)
        console.print(table)
        console.print(
            f"[dim]... and {len(all_results) - 10} more files (see CSV output for complete list)[/dim]"
        )
        return

    table = _build_summary_table_large(all_results)
    console.print(table)


def _simplify_file_type(file_type: str) -> str:
    cleaned = re.sub(r",\s*\d+\s+sections?", "", file_type)
    cleaned = re.sub(r"\d+\s+sections?,?\s*", "", cleaned)
    cleaned = re.sub(r",\s*$", "", cleaned.strip())

    if "PE32+" in cleaned:
        return "PE32+ (x64)"
    if "PE32" in cleaned:
        return "PE32 (x86)"
    if "ELF" in cleaned:
        return "ELF"
    if "Mach-O" in cleaned:
        return "Mach-O"
    return cleaned or "Unknown"


def _extract_compile_time(result: dict) -> str:
    for key in ("pe_info", "elf_info", "macho_info"):
        compile_time = result.get(key, {}).get("compile_time")
        if compile_time:
            return compile_time
    return "N/A"


def _compiler_name(result: dict) -> str:
    compiler_info = result.get("compiler", {})
    if compiler_info.get("detected", False):
        compiler = compiler_info.get("compiler", "Unknown")
        version = compiler_info.get("version", "")
        if version and version != "Unknown":
            return f"{compiler} {version}"
        return compiler
    return "Unknown"


def _collect_yara_matches(result: dict) -> str:
    matches = result.get("yara_matches", [])
    if not isinstance(matches, list):
        return "None"

    yara_matches: list[str] = []
    for match in matches:
        if isinstance(match, dict) and "rule" in match:
            yara_matches.append(match["rule"])
        elif hasattr(match, "rule"):
            yara_matches.append(match.rule)
        else:
            yara_matches.append(str(match))

    return ", ".join(yara_matches) if yara_matches else "None"


def _build_small_row(file_key: str, result: dict) -> tuple[str, str, str, str]:
    try:
        file_info = result.get("file_info", {})
        filename = file_info.get("name", file_key)
        file_type = _simplify_file_type(file_info.get("file_type", "Unknown"))
        compile_time = _extract_compile_time(result)
        compiler_name = _compiler_name(result)
        return filename, file_type, compiler_name, compile_time
    except Exception:
        return file_key, "Error", "Error", "Error"


def _build_large_row(file_key: str, result: dict) -> tuple[str, str, str, str, str]:
    try:
        file_info = result.get("file_info", {})
        md5 = file_info.get("md5", "N/A")
        file_type = _simplify_file_type(file_info.get("file_type", "Unknown"))
        compile_time = _extract_compile_time(result)
        compiler_name = _compiler_name(result)
        yara_str = _collect_yara_matches(result)
        return md5, file_type, compiler_name, compile_time, yara_str
    except Exception:
        return file_key, "Error", "Error", "Error", "Error"


def _build_summary_table_small(all_results):
    table = Table(title="Analysis Summary")
    table.add_column("Filename", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Compiler", style="magenta")
    table.add_column("Compile Time", style="green")

    for files_shown, (file_key, result) in enumerate(all_results.items()):
        if files_shown >= 10:
            break
        table.add_row(*_build_small_row(file_key, result))

    return table


def _build_summary_table_large(all_results):
    table = Table(title="Analysis Summary")
    table.add_column("MD5", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Compiler", style="magenta")
    table.add_column("Compile Time", style="green")
    table.add_column("YARA Matches", style="red")

    for file_key, result in all_results.items():
        table.add_row(*_build_large_row(file_key, result))

    return table
