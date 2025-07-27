#!/usr/bin/env python3
"""
r2inspect CLI - Command Line Interface
"""

import sys
import os
import json
import csv
import glob
from pathlib import Path
import click
import magic
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import pyfiglet

from .core import R2Inspector
from .utils.output import OutputFormatter
from .utils.logger import setup_logger
from .utils.error_handler import get_error_stats, reset_error_stats
from .utils.r2_helpers import get_retry_stats, get_circuit_breaker_stats
from .config import Config

console = Console()
# Initialize logger without thread_safe flag initially
logger = setup_logger(thread_safe=False)

# Constants
UNKNOWN_ERROR = "Unknown error"
NOT_AVAILABLE = "Not Available"
HTML_AMP = "&amp;"


def format_hash_display(hash_value, max_length=32):
    """Standardize hash display format"""
    if not hash_value or hash_value == "N/A":
        return "N/A"
    hash_str = str(hash_value)
    if len(hash_str) > max_length:
        return f"{hash_str[:max_length]}..."
    return hash_str


def create_info_table(title, prop_width=15, value_min_width=50):
    """Create a standardized info table with proper sizing"""
    table = Table(title=title, show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=prop_width, no_wrap=True)
    table.add_column("Value", style="green", min_width=value_min_width, overflow="fold")
    return table


def print_banner():
    """Print r2inspect banner"""
    try:
        banner = pyfiglet.figlet_format("r2inspect", font="slant")
        console.print(f"[bold blue]{banner}[/bold blue]")
        console.print("[bold]Advanced Malware Analysis Tool using Radare2[/bold]")
        console.print("[dim]Professional malware analysis powered by radare2[/dim]\n")
    except Exception:
        # Fallback simple banner if pyfiglet/rich fails
        print("r2inspect - Advanced Malware Analysis Tool using Radare2")
        print("Professional malware analysis powered by radare2")
        print()


def validate_inputs(filename, batch, output, yara, config, extensions, threads):
    """Validate all user inputs"""
    errors = []

    errors.extend(validate_file_input(filename))
    errors.extend(validate_batch_input(batch))
    errors.extend(validate_output_input(output))
    errors.extend(validate_yara_input(yara))
    errors.extend(validate_config_input(config))
    errors.extend(validate_extensions_input(extensions))
    errors.extend(validate_threads_input(threads))

    return errors


def validate_file_input(filename):
    """Validate file input parameter"""
    errors = []
    if filename:
        file_path = Path(filename)
        if not file_path.exists():
            errors.append(f"File does not exist: {filename}")
        elif not file_path.is_file():
            errors.append(f"Path is not a file: {filename}")
        elif file_path.stat().st_size == 0:
            errors.append(f"File is empty: {filename}")
        elif file_path.stat().st_size > 1024 * 1024 * 1024:  # 1GB limit
            errors.append(f"File too large (>1GB): {filename}")
    return errors


def validate_batch_input(batch):
    """Validate batch directory input"""
    errors = []
    if batch:
        batch_path = Path(batch)
        if not batch_path.exists():
            errors.append(f"Batch directory does not exist: {batch}")
        elif not batch_path.is_dir():
            errors.append(f"Batch path is not a directory: {batch}")
    return errors


def validate_output_input(output):
    """Validate output path input"""
    errors = []
    if output:
        output_path = Path(output)
        if output_path.exists() and output_path.is_file():
            try:
                with open(output_path, "a"):
                    # Test file writability by opening in append mode
                    # This ensures we have write permissions without modifying the file
                    pass
            except PermissionError:
                errors.append(f"Cannot write to output file: {output}")
        elif output_path.suffix == "":
            parent = output_path.parent
            if parent.exists() and not parent.is_dir():
                errors.append(f"Output parent path is not a directory: {parent}")
    return errors


def validate_yara_input(yara):
    """Validate YARA rules directory input"""
    errors = []
    if yara:
        yara_path = Path(yara)
        if not yara_path.exists():
            errors.append(f"YARA rules directory does not exist: {yara}")
        elif not yara_path.is_dir():
            errors.append(f"YARA path is not a directory: {yara}")
    return errors


def validate_config_input(config):
    """Validate config file input"""
    errors = []
    if config:
        config_path = Path(config)
        if not config_path.exists():
            errors.append(f"Config file does not exist: {config}")
        elif not config_path.is_file():
            errors.append(f"Config path is not a file: {config}")
        elif config_path.suffix.lower() not in [".json", ".yaml", ".yml", ".toml"]:
            errors.append(f"Config file must be JSON, YAML, or TOML: {config}")
    return errors


def validate_extensions_input(extensions):
    """Validate file extensions input"""
    errors = []
    if extensions:
        ext_list = [ext.strip() for ext in extensions.split(",")]
        for ext in ext_list:
            if not ext.replace(".", "").replace("_", "").replace("-", "").isalnum():
                errors.append(f"Invalid file extension: {ext}")
            if len(ext) > 10:
                errors.append(f"File extension too long: {ext}")
    return errors


def validate_threads_input(threads):
    """Validate threads input"""
    errors = []
    if threads:
        if not isinstance(threads, int) or threads < 1:
            errors.append("Threads must be a positive integer")
        elif threads > 50:
            errors.append("Too many threads (max 50)")
    return errors


def display_validation_errors(validation_errors):
    """Display validation errors and exit"""
    for error in validation_errors:
        console.print(f"[red]Error: {error}[/red]")


def handle_list_yara_option(config, yara):
    """Handle the --list-yara option"""
    config_obj = Config(config)
    from .modules.yara_analyzer import YaraAnalyzer

    # Initialize a dummy r2 object
    class DummyR2:
        pass

    yara_analyzer = YaraAnalyzer(DummyR2(), config_obj)
    rules_path = yara or getattr(config_obj, "yara_rules_path", "r2inspect/rules/yara")

    available_rules = yara_analyzer.list_available_rules(rules_path)

    if available_rules:
        display_yara_rules_table(available_rules, rules_path)
    else:
        console.print(f"[yellow]No YARA rules found in: {rules_path}[/yellow]")
        console.print(
            "[blue]You can place any .yar, .yara, .rule, or .rules files in this directory[/blue]"
        )


def display_yara_rules_table(available_rules, rules_path):
    """Display YARA rules in a table format"""
    table = Table(title=f"Available YARA Rules in: {rules_path}")
    table.add_column("Rule File", style="cyan")
    table.add_column("Size", style="yellow")
    table.add_column("Path", style="green")

    for rule in available_rules:
        size_kb = rule["size"] / 1024
        table.add_row(
            rule["name"],
            f"{size_kb:.1f} KB",
            rule.get("relative_path", rule["path"]),
        )

    console.print(table)
    console.print(
        f"\n[green]Total: {len(available_rules)} YARA rule file(s) found[/green]"
    )
    console.print(
        "[blue]All these files will be automatically loaded when running analysis[/blue]"
    )


def validate_input_mode(filename, batch):
    """Validate that either filename or batch mode is provided"""
    if not filename and not batch:
        console.print(
            "[red]Error: Must provide either a filename or --batch directory[/red]"
        )
        sys.exit(1)

    if filename and batch:
        console.print(
            "[red]Error: Cannot use both filename and --batch mode simultaneously[/red]"
        )
        sys.exit(1)

    if filename:
        validate_single_file(filename)


def validate_single_file(filename):
    """Validate that the single file exists and is valid"""
    file_path = Path(filename)
    if not file_path.exists():
        console.print(f"[red]Error: File does not exist: {filename}[/red]")
        console.print(
            "[yellow]Please provide the full path to the file you want to analyze[/yellow]"
        )
        sys.exit(1)
    elif not file_path.is_file():
        console.print(f"[red]Error: Path is not a file: {filename}[/red]")
        sys.exit(1)


def handle_xor_input(xor):
    """Handle and sanitize XOR input"""
    sanitized_xor = sanitize_xor_string(xor)
    if xor and not sanitized_xor:
        console.print(
            "[yellow]Warning: XOR string contains invalid characters and was filtered[/yellow]"
        )
    return sanitized_xor


def sanitize_xor_string(xor_input):
    """Sanitize XOR search string input"""
    if not xor_input:
        return None

    # Remove potentially dangerous characters
    safe_chars = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-."
    )
    sanitized = "".join(c for c in xor_input if c in safe_chars)

    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]

    return sanitized if sanitized else None


@click.command()
@click.argument(
    "filename", type=click.Path(), required=False
)  # Remove exists=True for better error handling
@click.option("-i", "--interactive", is_flag=True, help="Interactive mode")
@click.option(
    "-j",
    "--json",
    "output_json",
    is_flag=True,
    help="Full output analysis in JSON format",
)
@click.option(
    "-c", "--csv", "output_csv", is_flag=True, help="Output analysis in CSV format"
)
@click.option("-o", "--output", help="Output file path or directory for batch mode")
@click.option("-x", "--xor", help="Search XORed string")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--config", help="Custom config file path")
@click.option("--yara", help="Custom YARA rules directory")
@click.option(
    "--batch",
    "--directory",
    type=click.Path(),
    help="Process all files in directory (batch mode - recursive by default)",
)
@click.option(
    "--extensions",
    help="File extensions to process in batch mode (comma-separated). Default: auto-detect executable files",
)
@click.option(
    "--list-yara", is_flag=True, help="List all available YARA rules and exit"
)
@click.option(
    "--threads",
    default=10,
    type=click.IntRange(1, 50),
    help="Number of parallel threads for batch processing (1-50, default: 10)",
)
def main(
    filename,
    interactive,
    output_json,
    output_csv,
    output,
    xor,
    verbose,
    config,
    yara,
    batch,
    extensions,
    list_yara,
    threads,
):
    """r2inspect - Advanced malware analysis tool using radare2 and r2pipe"""

    try:
        # Validate inputs first
        validation_errors = validate_inputs(
            filename, batch, output, yara, config, extensions, threads
        )
        if validation_errors:
            display_validation_errors(validation_errors)
            sys.exit(1)

        # Handle --list-yara option first
        if list_yara:
            handle_list_yara_option(config, yara)
            sys.exit(0)

        # Check input mode
        validate_input_mode(filename, batch)

        # Print banner if not in quiet mode
        if not output_json and not output_csv:
            print_banner()

        # Load configuration
        config_obj = Config(config)

        # Sanitize XOR input
        sanitized_xor = handle_xor_input(xor)

        # Configure analysis options
        analysis_options = setup_analysis_options(yara, sanitized_xor)

        if batch:
            # Batch mode setup
            recursive, use_auto_detect, output = setup_batch_mode(
                batch, extensions, output_json, output_csv, output
            )

            run_batch_analysis(
                batch,
                analysis_options,
                output_json,
                output_csv,
                output,
                recursive,
                extensions,
                verbose,
                config_obj,
                use_auto_detect,
                threads,
            )
        else:
            # Single file mode with proper cleanup
            try:
                console.print(f"[blue]Initializing analysis for: {filename}[/blue]")

                with R2Inspector(
                    filename=filename, config=config_obj, verbose=verbose
                ) as inspector:
                    if interactive:
                        run_interactive_mode(inspector, analysis_options)
                    else:
                        # Setup output file for single file mode
                        output = setup_single_file_output(
                            output_json, output_csv, output, filename
                        )

                        run_analysis(
                            inspector,
                            analysis_options,
                            output_json,
                            output_csv,
                            output,
                            verbose,
                        )
            except Exception as e:
                logger.error(f"Error during analysis: {e}")
                raise

    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        handle_main_error(e, verbose)


def run_analysis(
    inspector, options, output_json, output_csv, output_file, verbose=False
):
    """Run complete analysis and display results"""
    reset_error_stats()

    print_status_if_appropriate(output_json, output_csv, output_file)

    # Perform analysis
    results = inspector.analyze(**options)

    # Add statistics to results
    add_statistics_to_results(results)

    # Output results in appropriate format
    output_results(results, output_json, output_csv, output_file, verbose)


def print_status_if_appropriate(output_json, output_csv, output_file):
    """Print status message if appropriate based on output options"""
    if not output_json and not output_csv:
        console.print("[bold green]Starting analysis...[/bold green]")
    elif (output_json or output_csv) and output_file:
        console.print("[bold green]Starting analysis...[/bold green]")


def add_statistics_to_results(results):
    """Add error, retry, and circuit breaker statistics to results"""
    error_stats = get_error_stats()
    retry_stats = get_retry_stats()
    circuit_stats = get_circuit_breaker_stats()

    if error_stats["total_errors"] > 0:
        results["error_statistics"] = error_stats

    if retry_stats["total_retries"] > 0:
        results["retry_statistics"] = retry_stats

    if has_circuit_breaker_data(circuit_stats):
        results["circuit_breaker_statistics"] = circuit_stats


def has_circuit_breaker_data(circuit_stats):
    """Check if circuit breaker statistics contain any meaningful data"""
    if not circuit_stats:
        return False

    for k, v in circuit_stats.items():
        if isinstance(v, (int, float)) and v > 0:
            return True
    return False


def output_results(results, output_json, output_csv, output_file, verbose):
    """Output results in the appropriate format"""
    formatter = OutputFormatter(results)

    if output_json:
        output_json_results(formatter, output_file)
    elif output_csv:
        output_csv_results(formatter, output_file)
    else:
        output_console_results(results, verbose)


def output_json_results(formatter, output_file):
    """Output results in JSON format"""
    json_output = formatter.to_json()
    if output_file:
        with open(output_file, "w") as f:
            f.write(json_output)
        console.print(f"[green]JSON results saved to: {output_file}[/green]")
    else:
        print(json_output)


def output_csv_results(formatter, output_file):
    """Output results in CSV format"""
    csv_output = formatter.to_csv()
    if output_file:
        with open(output_file, "w") as f:
            f.write(csv_output)
        console.print(f"[green]CSV results saved to: {output_file}[/green]")
    else:
        print(csv_output)


def output_console_results(results, verbose):
    """Output results to console with optional verbose statistics"""
    display_results(results)

    if verbose:
        error_stats = get_error_stats()
        if error_stats["total_errors"] > 0:
            display_error_statistics(error_stats)

        retry_stats = get_retry_stats()
        circuit_stats = get_circuit_breaker_stats()

        if retry_stats["total_retries"] > 0 or has_circuit_breaker_data(circuit_stats):
            display_performance_statistics(retry_stats, circuit_stats)


def display_error_statistics(error_stats):
    """Display error statistics in verbose mode"""
    console.print("\n[bold yellow]Error Statistics[/bold yellow]")

    # Create error statistics table
    table = Table(title="Analysis Error Summary", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="red")

    table.add_row("Total Errors", str(error_stats["total_errors"]))
    table.add_row("Recent Errors", str(error_stats["recent_errors"]))
    table.add_row(
        "Recovery Strategies Available",
        str(error_stats["recovery_strategies_available"]),
    )

    console.print(table)

    # Show errors by category if available
    if error_stats["errors_by_category"]:
        category_table = Table(title="Errors by Category", show_header=True)
        category_table.add_column("Category", style="cyan")
        category_table.add_column("Count", style="red")

        for category, count in error_stats["errors_by_category"].items():
            category_table.add_row(category.replace("_", " ").title(), str(count))

        console.print(category_table)

    # Show errors by severity if available
    if error_stats["errors_by_severity"]:
        severity_table = Table(title="Errors by Severity", show_header=True)
        severity_table.add_column("Severity", style="cyan")
        severity_table.add_column("Count", style="red")

        for severity, count in error_stats["errors_by_severity"].items():
            if severity == "critical":
                color = "red"
            elif severity == "high":
                color = "yellow"
            else:
                color = "dim"
            severity_table.add_row(f"[{color}]{severity.title()}[/{color}]", str(count))

        console.print(severity_table)

    console.print()


def display_performance_statistics(retry_stats, circuit_stats):
    """Display retry and circuit breaker statistics in verbose mode"""
    console.print("\n[bold cyan]Performance Statistics[/bold cyan]")

    _display_retry_statistics(retry_stats)
    _display_circuit_breaker_statistics(circuit_stats)
    console.print()


def _display_retry_statistics(retry_stats):
    """Display retry statistics table"""
    if retry_stats["total_retries"] <= 0:
        return

    # Main retry statistics
    retry_table = Table(title="Retry Statistics", show_header=True)
    retry_table.add_column("Metric", style="cyan")
    retry_table.add_column("Value", style="green")

    retry_table.add_row("Total Retries", str(retry_stats["total_retries"]))
    retry_table.add_row("Successful Retries", str(retry_stats["successful_retries"]))
    retry_table.add_row(
        "Failed After Retries", str(retry_stats["failed_after_retries"])
    )
    retry_table.add_row("Success Rate", f"{retry_stats['success_rate']:.1f}%")

    console.print(retry_table)

    # Most retried commands
    _display_most_retried_commands(retry_stats)


def _display_most_retried_commands(retry_stats):
    """Display table of most retried commands"""
    if not retry_stats["commands_retried"]:
        return

    cmd_table = Table(title="Most Retried Commands", show_header=True)
    cmd_table.add_column("Command", style="cyan")
    cmd_table.add_column("Retry Count", style="yellow")

    # Sort by retry count and show top 5
    sorted_commands = sorted(
        retry_stats["commands_retried"].items(),
        key=lambda x: x[1],
        reverse=True,
    )[:5]

    for command, count in sorted_commands:
        cmd_table.add_row(command, str(count))

    console.print(cmd_table)


def _display_circuit_breaker_statistics(circuit_stats):
    """Display circuit breaker statistics table"""
    if not circuit_stats:
        return

    cb_entries = []
    for metric, value in circuit_stats.items():
        if isinstance(value, (int, float)) and value > 0:
            cb_entries.append((metric, value))

    if not cb_entries:
        return

    cb_table = Table(title="Circuit Breaker Statistics", show_header=True)
    cb_table.add_column("Metric", style="cyan")
    cb_table.add_column("Value", style="green")

    for metric, value in cb_entries:
        cb_table.add_row(metric.replace("_", " ").title(), str(value))

    console.print(cb_table)


def display_results(results):
    """Display analysis results in a formatted table"""

    # File Information
    if "file_info" in results:
        file_info = results["file_info"]
        table = create_info_table("File Information", prop_width=14, value_min_width=60)

        # Basic file info only (no redundant architecture/format data)
        basic_info = {
            "size": file_info.get("size"),
            "path": file_info.get("path"),
            "name": file_info.get("name"),
            "mime_type": file_info.get("mime_type"),
            "file_type": file_info.get("file_type"),
            "md5": file_info.get("md5"),
            "sha1": file_info.get("sha1"),
            "sha256": file_info.get("sha256"),
            "sha512": file_info.get("sha512"),
        }

        # Parse Enhanced Detection into readable format
        enhanced = file_info.get("enhanced_detection", {})
        if enhanced:
            table.add_row("Format", enhanced.get("file_format", "Unknown"))
            table.add_row("Category", enhanced.get("format_category", "Unknown"))
            table.add_row(
                "Architecture",
                f"{enhanced.get('architecture', 'Unknown')} ({enhanced.get('bits', 'Unknown')} bits)",
            )
            table.add_row("Endianness", enhanced.get("endianness", "Unknown"))
            table.add_row("Confidence", f"{enhanced.get('confidence', 0):.2%}")
            table.add_row("Threat Level", file_info.get("threat_level", "Unknown"))

        # Add basic info
        for key, value in basic_info.items():
            if value is not None:
                display_key = key.replace("_", " ").title()
                if key in ["sha256", "sha512"]:
                    # Show full hash for these critical hash types
                    value = str(value)
                table.add_row(display_key, str(value))

        console.print(table)
        console.print()

    # PE Information
    if "pe_info" in results:
        pe_info = results["pe_info"]
        table = Table(title="PE Analysis", show_header=True, expand=True)
        table.add_column("Property", style="cyan", width=15, no_wrap=True)
        table.add_column("Value", style="yellow", min_width=30, overflow="fold")

        # Exclude redundant architecture/bits and security_features dict
        excluded_keys = {
            "architecture",
            "bits",
            "format",
            "security_features",
            "machine",
            "endian",
        }

        for key, value in pe_info.items():
            if key not in excluded_keys:
                if isinstance(value, list):
                    value = ", ".join(map(str, value))
                elif isinstance(value, dict):
                    # Skip dict values (like security_features)
                    continue
                table.add_row(key.replace("_", " ").title(), str(value))

        console.print(table)
        console.print()

    # Security Features
    if "security" in results:
        security = results["security"]
        table = Table(title="Security Features", show_header=True)
        table.add_column("Feature", style="cyan")
        table.add_column("Status", style="magenta")

        for key, value in security.items():
            status = "[green]✓[/green]" if value else "[red]✗[/red]"
            table.add_row(key.replace("_", " ").title(), status)

        console.print(table)
        console.print()

    # SSDeep Information
    if "ssdeep" in results:
        ssdeep_info = results["ssdeep"]
        table = Table(title="SSDeep Fuzzy Hash", show_header=True, expand=True)
        table.add_column("Property", style="cyan", width=10, no_wrap=True)
        table.add_column("Value", style="yellow", min_width=50, overflow="fold")

        if ssdeep_info.get("available"):
            table.add_row("Hash", ssdeep_info.get("ssdeep_hash", "N/A"))
            table.add_row("Method", ssdeep_info.get("method_used", "Unknown"))
            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if ssdeep_info.get("error"):
                table.add_row("Error", ssdeep_info.get("error", UNKNOWN_ERROR))

        console.print(table)
        console.print()

    # TLSH Information
    if "tlsh" in results:
        tlsh_info = results["tlsh"]
        table = Table(
            title="TLSH Locality Sensitive Hash", show_header=True, expand=True
        )
        table.add_column("Property", style="cyan", width=21, no_wrap=True)
        table.add_column("Value", style="yellow", min_width=70, overflow="fold")

        if tlsh_info.get("available"):
            # Binary TLSH
            binary_tlsh = tlsh_info.get("binary_tlsh")
            if binary_tlsh:
                table.add_row("Binary TLSH", binary_tlsh)
            else:
                table.add_row("Binary TLSH", "[red]Not Available[/red]")

            # Text section TLSH
            text_tlsh = tlsh_info.get("text_section_tlsh")
            if text_tlsh:
                table.add_row("Text Section TLSH", text_tlsh)
            else:
                table.add_row("Text Section TLSH", "[red]Not Available[/red]")

            # Function statistics
            stats = tlsh_info.get("stats", {})
            table.add_row("Functions Analyzed", str(stats.get("functions_analyzed", 0)))
            table.add_row(
                "Functions with TLSH", str(stats.get("functions_with_tlsh", 0))
            )

            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if tlsh_info.get("error"):
                table.add_row("Error", tlsh_info.get("error", UNKNOWN_ERROR))

        console.print(table)
        console.print()

    # Telfhash Information (ELF only)
    if "telfhash" in results:
        telfhash_info = results["telfhash"]
        table = Table(title="Telfhash (ELF Symbol Hash)", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")

        if telfhash_info.get("available"):
            if telfhash_info.get("is_elf"):
                # Telfhash value
                telfhash_value = telfhash_info.get("telfhash")
                if telfhash_value:
                    table.add_row("Telfhash", telfhash_value)
                else:
                    table.add_row("Telfhash", "[red]Not Available[/red]")

                # Symbol statistics
                table.add_row(
                    "Total Symbols", str(telfhash_info.get("symbol_count", 0))
                )
                table.add_row(
                    "Filtered Symbols", str(telfhash_info.get("filtered_symbols", 0))
                )

                # Show some symbols used
                symbols_used = telfhash_info.get("symbols_used", [])
                if symbols_used:
                    symbols_preview = ", ".join(symbols_used[:5])
                    if len(symbols_used) > 5:
                        symbols_preview += f" (+ {len(symbols_used) - 5} more)"
                    table.add_row("Symbols Used", symbols_preview)

                table.add_row("Status", "[green]✓ Available[/green]")
            else:
                table.add_row("Status", "[yellow]⚠ Not ELF File[/yellow]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if telfhash_info.get("error"):
                table.add_row("Error", telfhash_info.get("error", UNKNOWN_ERROR))

        console.print(table)
        console.print()

    # Rich Header Information (PE only)
    if "rich_header" in results:
        rich_header_info = results["rich_header"]
        table = Table(title="Rich Header (PE Build Environment)", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")

        if rich_header_info.get("available"):
            if rich_header_info.get("is_pe"):
                # XOR Key and Checksum
                xor_key = rich_header_info.get("xor_key")
                if xor_key is not None:
                    table.add_row("XOR Key", f"0x{xor_key:08X}")

                checksum = rich_header_info.get("checksum")
                if checksum is not None:
                    table.add_row("Checksum", f"0x{checksum:08X}")

                # RichPE Hash
                richpe_hash = rich_header_info.get("richpe_hash")
                if richpe_hash:
                    table.add_row("RichPE Hash", richpe_hash)

                # Compiler statistics
                compilers = rich_header_info.get("compilers", [])
                table.add_row("Compiler Entries", str(len(compilers)))

                # Show compiler details
                if compilers:
                    compiler_summary = []
                    for compiler in compilers[:5]:  # Show first 5
                        name = compiler.get("compiler_name", "Unknown")
                        count = compiler.get("count", 0)
                        build = compiler.get("build_number", 0)
                        compiler_summary.append(f"{name} (Build {build}): {count}")

                    if len(compilers) > 5:
                        compiler_summary.append(f"... and {len(compilers) - 5} more")

                    table.add_row("Compilers Used", "\n".join(compiler_summary))

                table.add_row("Status", "[green]✓ Available[/green]")
            else:
                table.add_row("Status", "[yellow]⚠ Not PE File[/yellow]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if rich_header_info.get("error"):
                table.add_row("Error", rich_header_info.get("error", UNKNOWN_ERROR))

        console.print(table)
        console.print()

    # Impfuzzy Information (PE only)
    if "impfuzzy" in results:
        impfuzzy_info = results["impfuzzy"]
        table = Table(
            title="Impfuzzy (PE Import Fuzzy Hash)", show_header=True, expand=True
        )
        table.add_column("Property", style="cyan", width=16, no_wrap=True)
        table.add_column("Value", style="yellow", min_width=80, overflow="fold")

        if impfuzzy_info.get("available"):
            # Impfuzzy Hash
            impfuzzy_hash = impfuzzy_info.get("impfuzzy_hash")
            if impfuzzy_hash:
                table.add_row("Impfuzzy Hash", impfuzzy_hash)

            # Import statistics
            import_count = impfuzzy_info.get("import_count", 0)
            table.add_row("Total Imports", str(import_count))

            dll_count = impfuzzy_info.get("dll_count", 0)
            table.add_row("DLL Count", str(dll_count))

            # Show sample imports
            imports_processed = impfuzzy_info.get("imports_processed", [])
            if imports_processed:
                sample_imports = imports_processed[:10]  # Show first 10
                if len(imports_processed) > 10:
                    sample_imports.append(f"... and {len(imports_processed) - 10} more")
                table.add_row("Sample Imports", "\n".join(sample_imports))

            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if impfuzzy_info.get("error"):
                table.add_row("Error", impfuzzy_info.get("error", UNKNOWN_ERROR))
            if not impfuzzy_info.get("library_available"):
                table.add_row("Note", "pyimpfuzzy library not installed")

        console.print(table)
        console.print()

    # CCBHash Information (Control Flow Graph Hash)
    if "ccbhash" in results:
        ccbhash_info = results["ccbhash"]
        table = Table(
            title="CCBHash (Control Flow Graph Hash)", show_header=True, expand=True
        )
        table.add_column("Property", style="cyan", width=25, no_wrap=True)
        table.add_column("Value", style="yellow", min_width=50, overflow="fold")

        if ccbhash_info.get("available"):
            # Binary CCBHash
            binary_hash = ccbhash_info.get("binary_ccbhash")
            if binary_hash:
                table.add_row(
                    "Binary CCBHash", format_hash_display(binary_hash, max_length=64)
                )

            # Function statistics
            total_functions = ccbhash_info.get("total_functions", 0)
            table.add_row("Total Functions", str(total_functions))

            analyzed_functions = ccbhash_info.get("analyzed_functions", 0)
            table.add_row("Analyzed Functions", str(analyzed_functions))

            unique_hashes = ccbhash_info.get("unique_hashes", 0)
            table.add_row("Unique CCBHashes", str(unique_hashes))

            # Similar functions
            similar_functions = ccbhash_info.get("similar_functions", [])
            if similar_functions:
                table.add_row("Similar Function Groups", str(len(similar_functions)))
                # Show the largest group
                largest_group = similar_functions[0] if similar_functions else None
                if largest_group:
                    table.add_row(
                        "Largest Similar Group", f"{largest_group['count']} functions"
                    )
                    # Show sample function names from the largest group
                    sample_funcs = largest_group["functions"][:3].copy()
                    # Clean HTML entities and corrupted patterns from function names
                    import re

                    clean_sample_funcs = [
                        re.sub(r"&nbsp;?", " ", func).replace(HTML_AMP, "&")
                        for func in sample_funcs
                    ]
                    if len(largest_group["functions"]) > 3:
                        clean_sample_funcs.append(
                            f"... and {len(largest_group['functions']) - 3} more"
                        )
                    table.add_row("Sample Functions", ", ".join(clean_sample_funcs))

            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if ccbhash_info.get("error"):
                table.add_row("Error", ccbhash_info.get("error", UNKNOWN_ERROR))

        console.print(table)
        console.print()

    # Binlex Information (N-gram Lexical Analysis)
    if "binlex" in results:
        binlex_info = results["binlex"]
        table = Table(
            title="Binlex (N-gram Lexical Analysis)", show_header=True, expand=True
        )
        table.add_column("Property", style="cyan", width=26, no_wrap=True)
        table.add_column("Value", style="yellow", min_width=40, overflow="fold")

        if binlex_info.get("available"):
            # Basic statistics
            total_functions = binlex_info.get("total_functions", 0)
            table.add_row("Total Functions", str(total_functions))

            analyzed_functions = binlex_info.get("analyzed_functions", 0)
            table.add_row("Analyzed Functions", str(analyzed_functions))

            # N-gram sizes analyzed
            ngram_sizes = binlex_info.get("ngram_sizes", [])
            table.add_row("N-gram Sizes", ", ".join(map(str, ngram_sizes)))

            # Unique signatures for each n-gram size
            unique_signatures = binlex_info.get("unique_signatures", {})
            for n in ngram_sizes:
                if n in unique_signatures:
                    table.add_row(
                        f"Unique {n}-gram Signatures", str(unique_signatures[n])
                    )

            # Similar functions
            similar_functions = binlex_info.get("similar_functions", {})
            for n in ngram_sizes:
                if n in similar_functions and similar_functions[n]:
                    groups = similar_functions[n]
                    table.add_row(f"Similar {n}-gram Groups", str(len(groups)))
                    # Show largest group
                    if groups:
                        largest_group = groups[0]
                        table.add_row(
                            f"Largest {n}-gram Group",
                            f"{largest_group['count']} functions",
                        )

            # Binary signatures
            binary_signature = binlex_info.get("binary_signature", {})
            for n in ngram_sizes:
                if n in binary_signature:
                    sig = binary_signature[n]
                    table.add_row(
                        f"Binary {n}-gram Signature",
                        format_hash_display(sig, max_length=64),
                    )

            # Top n-grams
            top_ngrams = binlex_info.get("top_ngrams", {})
            for n in ngram_sizes:
                if n in top_ngrams and top_ngrams[n]:
                    # Show top 3 most common n-grams, clean up encoding issues
                    top_3 = top_ngrams[n][:3]
                    ngram_strs = []
                    for ngram, count in top_3:
                        # Clean up any HTML entities and normalize whitespace
                        clean_ngram = (
                            ngram.replace("&nbsp;", " ").replace(HTML_AMP, "&").strip()
                        )
                        # Limit length to avoid very long display
                        if len(clean_ngram) > 50:
                            clean_ngram = clean_ngram[:47] + "..."
                        ngram_strs.append(f"• {clean_ngram} ({count})")
                    table.add_row(f"Top {n}-grams", "\n".join(ngram_strs))

            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if binlex_info.get("error"):
                table.add_row("Error", binlex_info.get("error", UNKNOWN_ERROR))

        console.print(table)
        console.print()

    # Binbloom Information (Bloom Filter Analysis)
    if "binbloom" in results:
        binbloom_info = results["binbloom"]
        table = Table(
            title="Binbloom (Bloom Filter Analysis)", show_header=True, width=120
        )
        table.add_column("Property", style="cyan", width=25)
        table.add_column("Value", style="yellow", width=90, overflow="fold")

        if binbloom_info.get("available"):
            # Basic statistics
            total_functions = binbloom_info.get("total_functions", 0)
            table.add_row("Total Functions", str(total_functions))

            analyzed_functions = binbloom_info.get("analyzed_functions", 0)
            table.add_row("Analyzed Functions", str(analyzed_functions))

            # Bloom filter configuration
            capacity = binbloom_info.get("capacity", 0)
            error_rate = binbloom_info.get("error_rate", 0.0)
            table.add_row("Bloom Filter Capacity", str(capacity))
            table.add_row(
                "False Positive Rate", f"{error_rate:.4f} ({error_rate * 100:.2f}%)"
            )

            # Unique signatures
            unique_signatures = binbloom_info.get("unique_signatures", 0)
            diversity_ratio = (
                (unique_signatures / analyzed_functions * 100)
                if analyzed_functions > 0
                else 0
            )
            table.add_row(
                "Unique Function Signatures",
                f"{unique_signatures} ({diversity_ratio:.1f}% diversity)",
            )

            # Function signatures details
            function_signatures = binbloom_info.get("function_signatures", {})
            if function_signatures:
                # Calculate instruction statistics
                total_instructions = sum(
                    sig.get("instruction_count", 0)
                    for sig in function_signatures.values()
                )
                avg_instructions = (
                    total_instructions / len(function_signatures)
                    if function_signatures
                    else 0
                )

                unique_instructions = sum(
                    sig.get("unique_instructions", 0)
                    for sig in function_signatures.values()
                )
                avg_unique = (
                    unique_instructions / len(function_signatures)
                    if function_signatures
                    else 0
                )

                table.add_row("Avg Instructions/Function", f"{avg_instructions:.1f}")
                table.add_row("Avg Unique Instructions", f"{avg_unique:.1f}")

            # Similar functions
            similar_functions = binbloom_info.get("similar_functions", [])
            if similar_functions:
                table.add_row("Similar Function Groups", str(len(similar_functions)))

                # Show details for each group
                for i, group in enumerate(similar_functions[:3]):  # Show first 3 groups
                    group_size = group.get("count", 0)
                    group_signature = group.get("signature", "")

                    # Format signature for better display
                    if len(group_signature) > 32:
                        group_sig = group_signature[:32] + "..."
                    else:
                        group_sig = group_signature

                    table.add_row(f"Group {i + 1} Size", f"{group_size} functions")
                    table.add_row(f"Group {i + 1} Signature", group_sig)

                    # Show sample functions from this group
                    if group.get("functions"):
                        sample_funcs = group["functions"][:5]  # Show first 5
                        func_display = []
                        for func in sample_funcs:
                            # Truncate very long function names
                            func_name = func if len(func) <= 30 else func[:27] + "..."
                            func_display.append(f"• {func_name}")

                        if len(group["functions"]) > 5:
                            func_display.append(
                                f"• ... and {len(group['functions']) - 5} more"
                            )

                        table.add_row(
                            f"Group {i + 1} Functions", "\n".join(func_display)
                        )

                if len(similar_functions) > 3:
                    table.add_row(
                        "Additional Groups",
                        f"... and {len(similar_functions) - 3} more groups",
                    )
            else:
                table.add_row("Similar Function Groups", "0 (all functions unique)")

            # Binary-wide signature
            binary_signature = binbloom_info.get("binary_signature")
            if binary_signature:
                table.add_row(
                    "Binary Bloom Signature",
                    format_hash_display(binary_signature, max_length=64),
                )

            # Bloom filter statistics
            bloom_stats = binbloom_info.get("bloom_stats", {})
            if bloom_stats:
                avg_fill_rate = bloom_stats.get("average_fill_rate", 0.0)
                table.add_row(
                    "Average Fill Rate",
                    f"{avg_fill_rate:.4f} ({avg_fill_rate * 100:.2f}%)",
                )

                total_filters = bloom_stats.get("total_filters", 0)
                table.add_row("Total Bloom Filters", str(total_filters))

            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if binbloom_info.get("error"):
                table.add_row("Error", binbloom_info.get("error", UNKNOWN_ERROR))
            elif not binbloom_info.get("library_available", True):
                table.add_row("Error", "pybloom-live library not installed")
                table.add_row("Install Command", "pip install pybloom-live")

        console.print(table)

        # Show additional details if there are unique signatures
        if (
            binbloom_info.get("available")
            and binbloom_info.get("unique_signatures", 0) > 1
        ):
            # Create signature details table
            sig_table = Table(
                title="Binbloom Signature Details",
                show_header=True,
                header_style="bold cyan",
                title_style="bold cyan",
                expand=True,
            )
            sig_table.add_column("Signature #", style="yellow", no_wrap=True, width=13)
            sig_table.add_column("Hash", style="green", min_width=50, overflow="fold")
            sig_table.add_column(
                "Functions", style="blue", min_width=45, overflow="fold"
            )

            # Show top unique function signatures
            function_signatures = binbloom_info.get("function_signatures", {})
            signatures_by_hash = {}

            for func_name, sig_data in function_signatures.items():
                sig_hash = sig_data.get("signature", "")
                if sig_hash not in signatures_by_hash:
                    signatures_by_hash[sig_hash] = []
                signatures_by_hash[sig_hash].append(func_name)

            # Show unique signatures (limit to first 5)
            unique_sigs = list(signatures_by_hash.keys())[:5]
            for i, sig_hash in enumerate(unique_sigs):
                funcs = signatures_by_hash[sig_hash]
                # Clean HTML entities and corrupted patterns from function names
                import re

                clean_funcs = [
                    re.sub(r"&nbsp;?", " ", func).replace(HTML_AMP, "&")
                    for func in funcs[:3]
                ]
                func_list = ", ".join(clean_funcs) + ("..." if len(funcs) > 3 else "")
                sig_table.add_row(
                    f"Signature {i + 1}",
                    f"{sig_hash[:64]}{'...' if len(sig_hash) > 64 else ''}",
                    f"Functions ({len(funcs)}): {func_list}",
                )

            console.print()
            console.print(sig_table)

        console.print()

    # SimHash Information (Similarity Hashing)
    if "simhash" in results:
        simhash_info = results["simhash"]
        table = Table(title="SimHash (Similarity Hashing)", show_header=True, width=120)
        table.add_column("Property", style="cyan", width=25)
        table.add_column("Value", style="yellow", width=90, overflow="fold")

        if simhash_info.get("available"):
            # Feature statistics
            feature_stats = simhash_info.get("feature_stats", {})
            total_features = feature_stats.get("total_features", 0)
            total_strings = feature_stats.get("total_strings", 0)
            total_opcodes = feature_stats.get("total_opcodes", 0)

            table.add_row("Total Features", str(total_features))
            table.add_row("String Features", str(total_strings))
            table.add_row("Opcode Features", str(total_opcodes))

            # Feature diversity
            feature_diversity = feature_stats.get("feature_diversity", 0.0)
            table.add_row("Feature Diversity", f"{feature_diversity:.3f}")

            # Combined SimHash (main binary signature)
            combined_simhash = simhash_info.get("combined_simhash")
            if combined_simhash:
                hash_hex = combined_simhash.get("hex", "")
                # Show full SimHash with line breaks for better readability
                if len(hash_hex) > 32:
                    hash_display = f"{hash_hex[:32]}\n{hash_hex[32:]}"
                else:
                    hash_display = hash_hex
                table.add_row("Binary SimHash", hash_display)
                table.add_row(
                    "Combined Features", str(combined_simhash.get("feature_count", 0))
                )

            # Strings-only SimHash
            strings_simhash = simhash_info.get("strings_simhash")
            if strings_simhash:
                hash_hex = strings_simhash.get("hex", "")
                if len(hash_hex) > 32:
                    hash_display = f"{hash_hex[:32]}\n{hash_hex[32:]}"
                else:
                    hash_display = hash_hex
                table.add_row("Strings SimHash", hash_display)

            # Opcodes-only SimHash
            opcodes_simhash = simhash_info.get("opcodes_simhash")
            if opcodes_simhash:
                hash_hex = opcodes_simhash.get("hex", "")
                if len(hash_hex) > 32:
                    hash_display = f"{hash_hex[:32]}\n{hash_hex[32:]}"
                else:
                    hash_display = hash_hex
                table.add_row("Opcodes SimHash", hash_display)

            # Function-level analysis
            function_simhashes = simhash_info.get("function_simhashes", {})
            if function_simhashes:
                total_functions = simhash_info.get("total_functions", 0)
                analyzed_functions = simhash_info.get("analyzed_functions", 0)

                table.add_row("Total Functions", str(total_functions))
                table.add_row("Analyzed Functions", str(analyzed_functions))

                # Similar function groups
                similarity_groups = simhash_info.get("similarity_groups", [])
                if similarity_groups:
                    table.add_row(
                        "Similar Function Groups", str(len(similarity_groups))
                    )

                    # Show details for largest groups
                    for i, group in enumerate(similarity_groups[:3]):
                        group_size = group.get("count", 0)
                        group_hash = group.get("representative_hash", "")
                        # Show more of the hash for better identification
                        if len(group_hash) > 24:
                            hash_display = f"{group_hash[:24]}...{group_hash[-8:]}"
                        else:
                            hash_display = group_hash

                        table.add_row(f"Group {i + 1} Size", f"{group_size} functions")
                        table.add_row(f"Group {i + 1} Hash", hash_display)

                        # Show sample functions
                        if group.get("functions"):
                            sample_funcs = group["functions"][:5]
                            func_display = []
                            for func in sample_funcs:
                                func_name = (
                                    func if len(func) <= 30 else func[:27] + "..."
                                )
                                func_display.append(f"• {func_name}")

                            if len(group["functions"]) > 5:
                                func_display.append(
                                    f"• ... and {len(group['functions']) - 5} more"
                                )

                            table.add_row(
                                f"Group {i + 1} Functions", "\n".join(func_display)
                            )

                    if len(similarity_groups) > 3:
                        table.add_row(
                            "Additional Groups",
                            f"... and {len(similarity_groups) - 3} more groups",
                        )
                else:
                    table.add_row("Similar Function Groups", "0 (all functions unique)")

            # Most common features
            most_common = feature_stats.get("most_common_features", [])
            if most_common:
                top_features = []
                for feature, count in most_common[:5]:
                    # Clean feature name for display
                    clean_feature = (
                        feature.replace("STR:", "")
                        .replace("OP:", "")
                        .replace("OPTYPE:", "")
                    )
                    if len(clean_feature) > 40:
                        clean_feature = clean_feature[:37] + "..."
                    top_features.append(f"• {clean_feature} ({count})")

                table.add_row("Top Features", "\n".join(top_features))

            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if simhash_info.get("error"):
                table.add_row("Error", simhash_info.get("error", UNKNOWN_ERROR))
            elif not simhash_info.get("library_available", True):
                table.add_row("Error", "simhash library not installed")
                table.add_row("Install Command", "pip install simhash")

        console.print(table)
        console.print()

    # BinDiff Information (Binary Comparison Features)
    if "bindiff" in results:
        bindiff_info = results["bindiff"]
        table = Table(title="BinDiff (Binary Comparison Features)", show_header=True)
        table.add_column("Property", style="cyan", width=25)
        table.add_column("Value", style="yellow", no_wrap=False)

        if bindiff_info.get("comparison_ready"):
            # File information
            table.add_row("Filename", bindiff_info.get("filename", "Unknown"))

            # Structural features
            structural = bindiff_info.get("structural_features", {})
            if structural:
                table.add_row("File Type", structural.get("file_type", "Unknown"))
                table.add_row("File Size", f"{structural.get('file_size', 0):,} bytes")
                table.add_row("Sections", str(structural.get("section_count", 0)))
                if structural.get("section_names"):
                    section_names = structural["section_names"]
                    if len(section_names) <= 7:
                        # Show all sections if 7 or fewer
                        table.add_row("Section Names", ", ".join(section_names))
                    else:
                        # Show first 5 and indicate there are more
                        displayed = section_names[:5]
                        remaining = len(section_names) - 5
                        table.add_row(
                            "Section Names",
                            f"{', '.join(displayed)}\n... and {remaining} more",
                        )
                table.add_row("Imports", str(structural.get("import_count", 0)))
                table.add_row("Exports", str(structural.get("export_count", 0)))

            # Function features
            function_features = bindiff_info.get("function_features", {})
            if function_features:
                table.add_row(
                    "Functions", str(function_features.get("function_count", 0))
                )
                if function_features.get("cfg_features"):
                    cfg_count = len(function_features["cfg_features"])
                    table.add_row("CFG Analysis", f"{cfg_count} functions analyzed")

            # String features
            string_features = bindiff_info.get("string_features", {})
            if string_features:
                table.add_row("Strings", str(string_features.get("total_strings", 0)))
                if string_features.get("categorized_strings"):
                    categories = list(string_features["categorized_strings"].keys())[:3]
                    table.add_row("String Types", ", ".join(categories))

            # Signatures
            signatures = bindiff_info.get("signatures", {})
            if signatures:
                structural_hash = signatures.get("structural", "N/A")
                function_hash = signatures.get("function", "N/A")
                string_hash = signatures.get("string", "N/A")

                # Show full hash or N/A if not available
                table.add_row(
                    "Structural Hash",
                    structural_hash if structural_hash != "N/A" else NOT_AVAILABLE,
                )
                table.add_row(
                    "Function Hash",
                    function_hash if function_hash != "N/A" else NOT_AVAILABLE,
                )
                table.add_row(
                    "String Hash",
                    string_hash if string_hash != "N/A" else NOT_AVAILABLE,
                )

            table.add_row("Status", "[green]✓ Comparison Ready[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if bindiff_info.get("error"):
                table.add_row("Error", bindiff_info.get("error", UNKNOWN_ERROR))

        console.print(table)
        console.print()

    # Function Analysis (MACHOC)
    if "functions" in results:
        functions_info = results["functions"]
        table = Table(title="Function Analysis (MACHOC)", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")

        table.add_row("Total Functions", str(functions_info.get("total_functions", 0)))

        machoc_hashes = functions_info.get("machoc_hashes", {})
        unique_hashes = len(set(machoc_hashes.values())) if machoc_hashes else 0
        table.add_row("Unique MACHOC Hashes", str(unique_hashes))

        # Calculate duplicates
        if machoc_hashes:
            hash_counts = {}
            for func_name, machoc_hash in machoc_hashes.items():
                hash_counts[machoc_hash] = hash_counts.get(machoc_hash, 0) + 1
            duplicates = sum(count - 1 for count in hash_counts.values() if count > 1)
            table.add_row("Duplicate Functions", str(duplicates))

        console.print(table)
        console.print()

    # Suspicious Indicators
    if "indicators" in results and results["indicators"]:
        table = Table(title="Suspicious Indicators", show_header=True)
        table.add_column("Type", style="red")
        table.add_column("Description", style="yellow")
        table.add_column("Severity", style="magenta")

        for indicator in results["indicators"]:
            table.add_row(
                indicator.get("type", "Unknown"),
                indicator.get("description", "N/A"),
                indicator.get("severity", "Unknown"),
            )

        console.print(table)
        console.print()


def show_strings_only(inspector):
    """Show only strings analysis"""
    console.print("[bold green]Extracting strings...[/bold green]")
    strings = inspector.get_strings()

    for string in strings:
        console.print(string)


def run_interactive_mode(inspector, options):
    """Run interactive analysis mode"""
    console.print("[bold blue]Interactive Mode - r2inspect[/bold blue]")
    console.print("Available commands:")
    console.print("  analyze - Run full analysis")
    console.print("  strings - Show strings")
    console.print("  info    - Show file info")
    console.print("  pe      - Show PE info")
    console.print("  imports - Show imports")
    console.print("  exports - Show exports")
    console.print("  sections - Show sections")
    console.print("  quit    - Exit")

    while True:
        try:
            cmd = input("\nr2inspect> ").strip().lower()

            if cmd == "quit" or cmd == "exit":
                break
            elif cmd == "analyze":
                results = inspector.analyze(**options)
                display_results(results)
            elif cmd == "strings":
                show_strings_only(inspector)
            elif cmd == "info":
                info = inspector.get_file_info()
                formatter = OutputFormatter({"file_info": info})
                console.print(formatter.format_table(info, "File Information"))
            elif cmd == "pe":
                pe_info = inspector.get_pe_info()
                formatter = OutputFormatter({"pe_info": pe_info})
                console.print(formatter.format_table(pe_info, "PE Information"))
            elif cmd == "imports":
                imports = inspector.get_imports()
                for imp in imports:
                    console.print(imp)
            elif cmd == "exports":
                exports = inspector.get_exports()
                for exp in exports:
                    console.print(exp)
            elif cmd == "sections":
                sections = inspector.get_sections()
                formatter = OutputFormatter({"sections": sections})
                console.print(formatter.format_sections(sections))
            elif cmd == "help":
                console.print(
                    "Available commands: analyze, strings, info, pe, imports, exports, sections, quit"
                )
            elif cmd == "":
                continue
            else:
                console.print(f"[red]Unknown command: {cmd}[/red]")
                console.print("Type 'help' for available commands")

        except KeyboardInterrupt:
            break
        except EOFError:
            break

    console.print("[yellow]Exiting interactive mode...[/yellow]")


def find_executable_files_by_magic(directory, recursive=False, verbose=False):
    """Find executable files using magic bytes detection (PE, ELF, Mach-O, etc.)"""
    executable_files = []
    directory = Path(directory)

    # Initialize magic
    try:
        mime_magic = magic.Magic(mime=True)
        desc_magic = magic.Magic()
    except Exception as e:
        console.print(f"[red]Error initializing magic: {e}[/red]")
        console.print("[yellow]Falling back to file extension detection[/yellow]")
        return []

    # Executable file signatures and descriptions to look for
    executable_signatures = [
        "application/x-dosexec",  # PE executables (Windows)
        "application/x-msdownload",  # Windows executables
        "application/x-executable",  # Generic executables
        "application/x-sharedlib",  # Shared libraries
        "application/x-pie-executable",  # Position Independent Executables
        "application/octet-stream",  # Sometimes executables show as this
    ]

    executable_descriptions = [
        "PE32 executable",  # Windows PE32
        "PE32+ executable",  # Windows PE32+
        "MS-DOS executable",  # DOS executables
        "Microsoft Portable Executable",  # Microsoft PE
        "ELF",  # Linux/Unix ELF
        "Mach-O",  # macOS Mach-O
        "executable",  # Generic executable
        "shared object",  # Shared libraries (.so, .dll)
        "dynamically linked",  # Dynamically linked executables
    ]

    # Get all files
    if recursive:
        all_files = directory.rglob("*")
    else:
        all_files = directory.glob("*")

    # Filter to regular files only
    regular_files = [f for f in all_files if f.is_file()]

    if verbose:
        console.print(
            f"[blue]Scanning {len(regular_files)} files for executable signatures...[/blue]"
        )

    for file_path in regular_files:
        try:
            # Skip very small files (less than 64 bytes - minimum PE size)
            if file_path.stat().st_size < 64:
                continue

            # Check MIME type
            mime_type = mime_magic.from_file(str(file_path))

            # Check file description
            description = desc_magic.from_file(str(file_path))

            # Check if it's an executable file
            is_executable = False

            # Check MIME type
            if any(sig in mime_type.lower() for sig in executable_signatures):
                is_executable = True

            # Check description
            if any(
                desc.lower() in description.lower() for desc in executable_descriptions
            ):
                is_executable = True

            # Additional checks for specific executable formats
            if not is_executable:
                is_executable = check_executable_signature(file_path)

            if is_executable:
                executable_files.append(file_path)
                if verbose:
                    console.print(
                        f"[green]✓[/green] Executable file detected: {file_path.name} ({description})"
                    )
            elif verbose and file_path.suffix.lower() in [
                ".exe",
                ".dll",
                ".scr",
                ".com",
                ".so",
                ".dylib",
                ".app",
            ]:
                # Show files with executable extensions that weren't detected as executables
                console.print(f"[yellow]?[/yellow] {file_path.name} ({description})")

        except Exception as e:
            if verbose:
                console.print(f"[red]Error checking {file_path.name}: {e}[/red]")
            continue

    console.print(f"[green]Found {len(executable_files)} executable files[/green]")
    return executable_files


def check_executable_signature(file_path):
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


def is_pe_executable(header, file_handle):
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
        except Exception:  # noqa: B110
            # Failed to read PE header - not a valid PE file
            pass
    return True  # MZ header is good enough indication


def is_elf_executable(header):
    """Check if file has ELF (Linux/Unix) executable signature"""
    return header[:4] == b"\x7fELF"


def is_macho_executable(header):
    """Check if file has Mach-O (macOS) executable signature"""
    mach_o_magics = [
        b"\xfe\xed\xfa\xce",  # 32-bit big endian
        b"\xce\xfa\xed\xfe",  # 32-bit little endian
        b"\xfe\xed\xfa\xcf",  # 64-bit big endian
        b"\xcf\xfa\xed\xfe",  # 64-bit little endian
        b"\xca\xfe\xba\xbe",  # Universal binary
    ]
    return header[:4] in mach_o_magics


def is_script_executable(header):
    """Check if file has script shebang"""
    return header[:2] == b"#!"


def setup_rate_limiter(threads, verbose):
    """Setup rate limiter for batch processing"""
    from .utils.rate_limiter import BatchRateLimiter

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
    file_path, batch_path, config_obj, options, output_json, output_path, rate_limiter
):
    """Process a single file with rate limiting"""
    from .output_formatter import OutputFormatter
    from .inspector import R2Inspector

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
):
    """Process files in parallel with progress tracking"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading
    from rich.progress import (
        Progress,
        TextColumn,
        BarColumn,
        TaskProgressColumn,
        TimeRemainingColumn,
    )

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
    all_results,
    failed_files,
    elapsed_time,
    files_to_process,
    rate_limiter,
    verbose,
    output_filename,
):
    """Display final batch analysis results"""
    # Get rate limiter statistics
    rate_stats = rate_limiter.get_stats()

    # Clean final report
    success_count = len(all_results)
    total_count = len(files_to_process)

    console.print(f"\n[bold green]Analysis Complete![/bold green]")
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


def setup_batch_mode(batch, extensions, output_json, output_csv, output):
    """Setup batch mode parameters"""
    recursive = True  # Always recursive
    use_auto_detect = not extensions  # Auto-detect if no extensions specified

    # Set default output directory if not specified but JSON/CSV requested
    if (output_json or output_csv) and not output:
        output = "output"

    return recursive, use_auto_detect, output


def setup_single_file_output(output_json, output_csv, output, filename):
    """Setup output file for single file mode"""
    if (output_json or output_csv) and not output:
        # Create output directory if it doesn't exist
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

        # Generate filename based on input file
        input_path = Path(filename)
        base_name = input_path.stem

        if output_json:
            output = output_dir / f"{base_name}_analysis.json"
        elif output_csv:
            output = output_dir / f"{base_name}_analysis.csv"

    return output


def setup_analysis_options(yara, sanitized_xor):
    """Setup analysis options with all modules enabled by default"""
    return {
        "detect_packer": True,
        "detect_crypto": True,
        "detect_av": True,
        "full_analysis": True,
        "custom_yara": yara,
        "xor_search": sanitized_xor,
    }


def display_rate_limiter_stats(rate_stats):
    """Display rate limiter statistics"""
    console.print("[dim]Rate limiter stats:[/dim]")
    console.print(f"[dim]  Success rate: {rate_stats.get('success_rate', 0):.1%}[/dim]")
    console.print(
        f"[dim]  Avg wait time: {rate_stats.get('avg_wait_time', 0):.2f}s[/dim]"
    )
    console.print(
        f"[dim]  Final rate: {rate_stats.get('current_rate', 0):.1f} files/sec[/dim]"
    )


def display_memory_stats():
    """Display memory statistics if available"""
    from .utils.memory_manager import get_memory_stats

    memory_stats = get_memory_stats()
    if memory_stats.get("status") != "error":
        console.print("[dim]Memory stats:[/dim]")
        console.print(
            f"[dim]  Peak usage: {memory_stats.get('peak_memory_mb', 0):.1f}MB[/dim]"
        )
        console.print(
            f"[dim]  Current usage: {memory_stats.get('process_memory_mb', 0):.1f}MB[/dim]"
        )
        console.print(f"[dim]  GC cycles: {memory_stats.get('gc_count', 0)}[/dim]")


def display_failed_files(failed_files, verbose):
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


def handle_main_error(e, verbose):
    """Handle errors in main function"""
    console.print(f"[red]Error: {str(e)}[/red]")
    if verbose:
        import traceback

        traceback.print_exc()
    sys.exit(1)


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
    from .output_formatter import OutputFormatter

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
        stats["architectures"][architecture] = (
            stats["architectures"].get(architecture, 0) + 1
        )


def update_compiler_stats(stats, result):
    """Update compiler statistics"""
    if "compiler" in result:
        compiler_info = result["compiler"]
        compiler_name = compiler_info.get("compiler", "Unknown")
        if compiler_info.get("detected", False):
            stats["compilers"][compiler_name] = (
                stats["compilers"].get(compiler_name, 0) + 1
            )


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


def find_files_to_process(batch_path, auto_detect, extensions, recursive, verbose):
    """Find files to process based on auto-detection or extensions"""
    files_to_process = []

    if auto_detect:
        console.print(
            "[blue]Auto-detecting executable files (default behavior)...[/blue]"
        )
        files_to_process = find_executable_files_by_magic(
            batch_path, recursive, verbose
        )
    else:
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
        console.print(
            "[dim]Tip: Files might not be executable format or may be corrupted[/dim]"
        )
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
):
    """Run batch analysis on multiple files in a directory"""
    batch_path = Path(batch_dir)

    # Find files to process
    files_to_process = find_files_to_process(
        batch_path, auto_detect, extensions, recursive, verbose
    )

    if not files_to_process:
        display_no_files_message(auto_detect, extensions)
        return

    console.print(
        f"[bold green]Found {len(files_to_process)} files to process[/bold green]"
    )
    console.print(f"[blue]Using {threads} parallel threads[/blue]")

    # Configure logging for batch processing
    if not verbose:
        from .utils.logger import configure_batch_logging

        configure_batch_logging()

    # Setup output directory
    output_path = setup_batch_output_directory(output_dir, output_json, output_csv)

    # Results storage
    all_results = {}
    failed_files = []

    # Start timing
    import time

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


def create_batch_summary(
    all_results, failed_files, output_path, output_json, output_csv
):
    """Create summary report for batch analysis with custom output behavior"""
    from datetime import datetime

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
    from rich.table import Table
    import re

    # If more than 10 files, show simplified table with max 10 entries
    if len(all_results) > 10:
        table = Table(title="Analysis Summary")
        table.add_column("Filename", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Compiler", style="magenta")
        table.add_column("Compile Time", style="green")

        # Show only first 10 files
        files_shown = 0
        for file_key, result in all_results.items():
            if files_shown >= 10:
                break

            try:
                # File info
                file_info = result.get("file_info", {})

                # Filename
                filename = file_info.get("name", file_key)

                # File type (clean and simplified)
                file_type = file_info.get("file_type", "Unknown")
                # Clean file type - remove section info and simplify
                file_type = re.sub(r",\s*\d+\s+sections?", "", file_type)
                file_type = re.sub(r"\d+\s+sections?,?\s*", "", file_type)
                file_type = re.sub(r",\s*$", "", file_type.strip())

                # Simplify common file types
                if "PE32+" in file_type:
                    file_type = "PE32+ (x64)"
                elif "PE32" in file_type:
                    file_type = "PE32 (x86)"
                elif "ELF" in file_type:
                    file_type = "ELF"
                elif "Mach-O" in file_type:
                    file_type = "Mach-O"

                # Compile time (extract and format)
                compile_time = ""
                if "pe_info" in result and "compile_time" in result["pe_info"]:
                    compile_time = result["pe_info"]["compile_time"]
                elif "elf_info" in result and "compile_time" in result["elf_info"]:
                    compile_time = result["elf_info"]["compile_time"]
                elif "macho_info" in result and "compile_time" in result["macho_info"]:
                    compile_time = result["macho_info"]["compile_time"]

                if not compile_time:
                    compile_time = "N/A"

                # Compiler information
                compiler_info = result.get("compiler", {})
                compiler_name = "Unknown"
                if compiler_info.get("detected", False):
                    compiler_name = compiler_info.get("compiler", "Unknown")
                    version = compiler_info.get("version", "")
                    if version and version != "Unknown":
                        compiler_name = f"{compiler_name} {version}"

                table.add_row(filename, file_type, compiler_name, compile_time)
                files_shown += 1

            except Exception as e:
                # If there's an error with any file, show minimal info
                table.add_row(file_key, "Error", "Error", "Error")
                files_shown += 1

        # Add a note about remaining files
        if len(all_results) > 10:
            console.print(table)
            console.print(
                f"[dim]... and {len(all_results) - 10} more files (see CSV output for complete list)[/dim]"
            )
        else:
            console.print(table)
    else:
        # For 10 or fewer files, show detailed table
        table = Table(title="Analysis Summary")
        table.add_column("MD5", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Compile Time", style="green")
        table.add_column("YARA Matches", style="red")

        for file_key, result in all_results.items():
            try:
                # File info
                file_info = result.get("file_info", {})

                # MD5 (full hash)
                md5 = file_info.get("md5", "N/A")

                # File type (clean and simplified)
                file_type = file_info.get("file_type", "")
                # Clean file type - remove section info and simplify
                file_type = re.sub(r",\s*\d+\s+sections?", "", file_type)
                file_type = re.sub(r"\d+\s+sections?,?\s*", "", file_type)
                file_type = re.sub(r",\s*$", "", file_type.strip())

                # Simplify common file types
                if "PE32+" in file_type:
                    file_type = "PE32+ (x64)"
                elif "PE32" in file_type:
                    file_type = "PE32 (x86)"
                elif "ELF" in file_type:
                    file_type = "ELF"
                elif "Mach-O" in file_type:
                    file_type = "Mach-O"

                # Compile time (extract and format)
                compile_time = ""
                if "pe_info" in result and "compile_time" in result["pe_info"]:
                    compile_time = result["pe_info"]["compile_time"]
                elif "elf_info" in result and "compile_time" in result["elf_info"]:
                    compile_time = result["elf_info"]["compile_time"]
                elif "macho_info" in result and "compile_time" in result["macho_info"]:
                    compile_time = result["macho_info"]["compile_time"]

                if not compile_time:
                    compile_time = "N/A"

                # YARA matches - show rule names
                yara_matches = []
                if "yara_matches" in result and isinstance(
                    result["yara_matches"], list
                ):
                    for match in result["yara_matches"]:
                        if isinstance(match, dict) and "rule" in match:
                            yara_matches.append(match["rule"])
                        elif hasattr(match, "rule"):
                            yara_matches.append(match.rule)
                        else:
                            yara_matches.append(str(match))

                yara_str = ", ".join(yara_matches) if yara_matches else "None"

                table.add_row(md5, file_type, compile_time, yara_str)

            except Exception:
                # If there's an error with any file, show minimal info
                table.add_row("Error", "Error", "Error", "Error")

        console.print(table)


if __name__ == "__main__":
    main()
