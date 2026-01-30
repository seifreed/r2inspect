#!/usr/bin/env python3
"""
r2inspect CLI Display Module

Provides output formatting and display functions for analysis results.
Extracted from cli_utils.py for better modularity.

This is the largest module as it handles all the rich formatted output tables
for various analysis results (PE, ELF, Mach-O, hashes, etc.).

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

import re

try:
    import pyfiglet
except Exception:  # pragma: no cover - optional dependency
    pyfiglet = None
from rich.console import Console
from rich.table import Table

from ..config import Config

console = Console()

# Constants
UNKNOWN_ERROR = "Unknown error"
NOT_AVAILABLE = "Not Available"
HTML_AMP = "&amp;"
STATUS_AVAILABLE = "[green]✓ Available[/green]"
STATUS_NOT_AVAILABLE = "[red]✗ Not Available[/red]"
STATUS_NOT_AVAILABLE_SIMPLE = "[red]Not Available[/red]"
TOTAL_FUNCTIONS_LABEL = "Total Functions"
ANALYZED_FUNCTIONS_LABEL = "Analyzed Functions"
SIMILAR_GROUPS_LABEL = "Similar Function Groups"


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
        if pyfiglet is not None:
            banner = pyfiglet.figlet_format("r2inspect", font="slant")
            console.print(f"[bold blue]{banner}[/bold blue]")
        else:
            console.print("[bold blue]r2inspect[/bold blue]")
        console.print("[bold]Advanced Malware Analysis Tool using Radare2[/bold]")
        console.print("[dim]Professional malware analysis powered by radare2[/dim]\n")
    except Exception:
        # Fallback simple banner if pyfiglet/rich fails
        print("r2inspect - Advanced Malware Analysis Tool using Radare2")
        print("Professional malware analysis powered by radare2")
        print()


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
    console.print(f"\n[green]Total: {len(available_rules)} YARA rule file(s) found[/green]")
    console.print("[blue]All these files will be automatically loaded when running analysis[/blue]")


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
    retry_table.add_row("Failed After Retries", str(retry_stats["failed_after_retries"]))
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
        if isinstance(value, int | float) and value > 0:
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
    for handler in (
        _display_file_info,
        _display_pe_info,
        _display_security,
        _display_ssdeep,
        _display_tlsh,
        _display_telfhash,
        _display_rich_header,
        _display_impfuzzy,
        _display_ccbhash,
        _display_binlex,
        _display_binbloom,
        _display_simhash,
        _display_bindiff,
        _display_machoc_functions,
        _display_indicators,
    ):
        handler(results)


def _display_file_info(results):
    if "file_info" not in results:
        return

    file_info = results["file_info"]
    table = create_info_table("File Information", prop_width=14, value_min_width=60)

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

    for key, value in basic_info.items():
        if value is not None:
            display_key = key.replace("_", " ").title()
            if key in ["sha256", "sha512"]:
                value = str(value)
            table.add_row(display_key, str(value))

    console.print(table)
    console.print()


def _display_pe_info(results):
    if "pe_info" not in results:
        return

    pe_info = results["pe_info"]
    table = Table(title="PE Analysis", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=15, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=30, overflow="fold")

    excluded_keys = {
        "architecture",
        "bits",
        "format",
        "security_features",
        "machine",
        "endian",
    }

    for key, value in pe_info.items():
        if key in excluded_keys:
            continue
        if isinstance(value, list):
            value = ", ".join(map(str, value))
        elif isinstance(value, dict):
            continue
        table.add_row(key.replace("_", " ").title(), str(value))

    console.print(table)
    console.print()


def _display_security(results):
    if "security" not in results:
        return

    security = results["security"]
    table = Table(title="Security Features", show_header=True)
    table.add_column("Feature", style="cyan")
    table.add_column("Status", style="magenta")

    for key, value in security.items():
        status = "[green]✓[/green]" if value else "[red]✗[/red]"
        table.add_row(key.replace("_", " ").title(), status)

    console.print(table)
    console.print()


def _display_ssdeep(results):
    if "ssdeep" not in results:
        return

    ssdeep_info = results["ssdeep"]
    table = Table(title="SSDeep Fuzzy Hash", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=10, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=50, overflow="fold")

    if ssdeep_info.get("available"):
        table.add_row("Hash", ssdeep_info.get("ssdeep_hash", "N/A"))
        table.add_row("Method", ssdeep_info.get("method_used", "Unknown"))
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if ssdeep_info.get("error"):
            table.add_row("Error", ssdeep_info.get("error", UNKNOWN_ERROR))

    console.print(table)
    console.print()


def _display_tlsh(results):
    if "tlsh" not in results:
        return

    tlsh_info = results["tlsh"]
    table = Table(title="TLSH Locality Sensitive Hash", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=21, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=70, overflow="fold")

    if tlsh_info.get("available"):
        _add_tlsh_entries(table, tlsh_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if tlsh_info.get("error"):
            table.add_row("Error", tlsh_info.get("error", UNKNOWN_ERROR))

    console.print(table)
    console.print()


def _add_tlsh_entries(table, tlsh_info):
    binary_tlsh = tlsh_info.get("binary_tlsh")
    table.add_row("Binary TLSH", binary_tlsh if binary_tlsh else STATUS_NOT_AVAILABLE_SIMPLE)

    text_tlsh = tlsh_info.get("text_section_tlsh")
    table.add_row("Text Section TLSH", text_tlsh if text_tlsh else STATUS_NOT_AVAILABLE_SIMPLE)

    stats = tlsh_info.get("stats", {})
    table.add_row("Functions Analyzed", str(stats.get("functions_analyzed", 0)))
    table.add_row("Functions with TLSH", str(stats.get("functions_with_tlsh", 0)))


def _display_telfhash(results):
    if "telfhash" not in results:
        return

    telfhash_info = results["telfhash"]
    table = Table(title="Telfhash (ELF Symbol Hash)", show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")

    if telfhash_info.get("available"):
        if telfhash_info.get("is_elf"):
            _add_telfhash_entries(table, telfhash_info)
            table.add_row("Status", STATUS_AVAILABLE)
        else:
            table.add_row("Status", "[yellow]⚠ Not ELF File[/yellow]")
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if telfhash_info.get("error"):
            table.add_row("Error", telfhash_info.get("error", UNKNOWN_ERROR))

    console.print(table)
    console.print()


def _add_telfhash_entries(table, telfhash_info):
    telfhash_value = telfhash_info.get("telfhash")
    table.add_row("Telfhash", telfhash_value if telfhash_value else STATUS_NOT_AVAILABLE_SIMPLE)
    table.add_row("Total Symbols", str(telfhash_info.get("symbol_count", 0)))
    table.add_row("Filtered Symbols", str(telfhash_info.get("filtered_symbols", 0)))

    symbols_used = telfhash_info.get("symbols_used", [])
    if symbols_used:
        symbols_preview = ", ".join(symbols_used[:5])
        if len(symbols_used) > 5:
            symbols_preview += f" (+ {len(symbols_used) - 5} more)"
        table.add_row("Symbols Used", symbols_preview)


def _display_rich_header(results):
    if "rich_header" not in results:
        return

    rich_header_info = results["rich_header"]
    table = Table(title="Rich Header (PE Build Environment)", show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")

    if rich_header_info.get("available"):
        if rich_header_info.get("is_pe"):
            _add_rich_header_entries(table, rich_header_info)
            table.add_row("Status", STATUS_AVAILABLE)
        else:
            table.add_row("Status", "[yellow]⚠ Not PE File[/yellow]")
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if rich_header_info.get("error"):
            table.add_row("Error", rich_header_info.get("error", UNKNOWN_ERROR))

    console.print(table)
    console.print()


def _add_rich_header_entries(table, rich_header_info):
    xor_key = rich_header_info.get("xor_key")
    if xor_key is not None:
        table.add_row("XOR Key", f"0x{xor_key:08X}")

    checksum = rich_header_info.get("checksum")
    if checksum is not None:
        table.add_row("Checksum", f"0x{checksum:08X}")

    richpe_hash = rich_header_info.get("richpe_hash")
    if richpe_hash:
        table.add_row("RichPE Hash", richpe_hash)

    compilers = rich_header_info.get("compilers", [])
    table.add_row("Compiler Entries", str(len(compilers)))

    if compilers:
        compiler_summary = []
        for compiler in compilers[:5]:
            name = compiler.get("compiler_name", "Unknown")
            count = compiler.get("count", 0)
            build = compiler.get("build_number", 0)
            compiler_summary.append(f"{name} (Build {build}): {count}")

        if len(compilers) > 5:
            compiler_summary.append(f"... and {len(compilers) - 5} more")

        table.add_row("Compilers Used", "\n".join(compiler_summary))


def _display_impfuzzy(results):
    if "impfuzzy" not in results:
        return

    impfuzzy_info = results["impfuzzy"]
    table = Table(title="Impfuzzy (PE Import Fuzzy Hash)", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=16, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=80, overflow="fold")

    if impfuzzy_info.get("available"):
        _add_impfuzzy_entries(table, impfuzzy_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if impfuzzy_info.get("error"):
            table.add_row("Error", impfuzzy_info.get("error", UNKNOWN_ERROR))
        if not impfuzzy_info.get("library_available"):
            table.add_row("Note", "pyimpfuzzy library not installed")

    console.print(table)
    console.print()


def _add_impfuzzy_entries(table, impfuzzy_info):
    impfuzzy_hash = impfuzzy_info.get("impfuzzy_hash")
    if impfuzzy_hash:
        table.add_row("Impfuzzy Hash", impfuzzy_hash)

    import_count = impfuzzy_info.get("import_count", 0)
    table.add_row("Total Imports", str(import_count))

    dll_count = impfuzzy_info.get("dll_count", 0)
    table.add_row("DLL Count", str(dll_count))

    imports_processed = impfuzzy_info.get("imports_processed", [])
    if imports_processed:
        sample_imports = imports_processed[:10]
        if len(imports_processed) > 10:
            sample_imports.append(f"... and {len(imports_processed) - 10} more")
        table.add_row("Sample Imports", "\n".join(sample_imports))


def _display_ccbhash(results):
    if "ccbhash" not in results:
        return

    ccbhash_info = results["ccbhash"]
    table = Table(title="CCBHash (Control Flow Graph Hash)", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=25, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=50, overflow="fold")

    if ccbhash_info.get("available"):
        _add_ccbhash_entries(table, ccbhash_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if ccbhash_info.get("error"):
            table.add_row("Error", ccbhash_info.get("error", UNKNOWN_ERROR))

    console.print(table)
    console.print()


def _add_ccbhash_entries(table, ccbhash_info):
    binary_hash = ccbhash_info.get("binary_ccbhash")
    if binary_hash:
        table.add_row("Binary CCBHash", format_hash_display(binary_hash, max_length=64))

    total_functions = ccbhash_info.get("total_functions", 0)
    table.add_row(TOTAL_FUNCTIONS_LABEL, str(total_functions))

    analyzed_functions = ccbhash_info.get("analyzed_functions", 0)
    table.add_row(ANALYZED_FUNCTIONS_LABEL, str(analyzed_functions))

    unique_hashes = ccbhash_info.get("unique_hashes", 0)
    table.add_row("Unique CCBHashes", str(unique_hashes))

    similar_functions = ccbhash_info.get("similar_functions", [])
    if not similar_functions:
        return

    table.add_row(SIMILAR_GROUPS_LABEL, str(len(similar_functions)))
    largest_group = similar_functions[0] if similar_functions else None
    if not largest_group:
        return

    table.add_row("Largest Similar Group", f"{largest_group['count']} functions")
    sample_funcs = largest_group["functions"][:3].copy()
    clean_sample_funcs = [
        re.sub(r"&nbsp;?", " ", func).replace(HTML_AMP, "&") for func in sample_funcs
    ]
    if len(largest_group["functions"]) > 3:
        clean_sample_funcs.append(f"... and {len(largest_group['functions']) - 3} more")
    table.add_row("Sample Functions", ", ".join(clean_sample_funcs))


def _display_binlex(results):
    if "binlex" not in results:
        return

    binlex_info = results["binlex"]
    table = Table(title="Binlex (N-gram Lexical Analysis)", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=26, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=40, overflow="fold")

    if binlex_info.get("available"):
        _add_binlex_entries(table, binlex_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if binlex_info.get("error"):
            table.add_row("Error", binlex_info.get("error", UNKNOWN_ERROR))

    console.print(table)
    console.print()


def _add_binlex_entries(table, binlex_info):
    ngram_sizes = _add_binlex_basic_stats(table, binlex_info)
    _add_binlex_unique_signatures(table, ngram_sizes, binlex_info.get("unique_signatures", {}))
    _add_binlex_similarity_groups(table, ngram_sizes, binlex_info.get("similar_functions", {}))
    _add_binlex_binary_signatures(table, ngram_sizes, binlex_info.get("binary_signature", {}))
    _add_binlex_top_ngrams(table, ngram_sizes, binlex_info.get("top_ngrams", {}))


def _add_binlex_basic_stats(table, binlex_info):
    total_functions = binlex_info.get("total_functions", 0)
    table.add_row(TOTAL_FUNCTIONS_LABEL, str(total_functions))

    analyzed_functions = binlex_info.get("analyzed_functions", 0)
    table.add_row(ANALYZED_FUNCTIONS_LABEL, str(analyzed_functions))

    ngram_sizes = binlex_info.get("ngram_sizes", [])
    table.add_row("N-gram Sizes", ", ".join(map(str, ngram_sizes)))
    return ngram_sizes


def _add_binlex_unique_signatures(table, ngram_sizes, unique_signatures):
    for n in ngram_sizes:
        if n in unique_signatures:
            table.add_row(f"Unique {n}-gram Signatures", str(unique_signatures[n]))


def _add_binlex_similarity_groups(table, ngram_sizes, similar_functions):
    for n in ngram_sizes:
        if n in similar_functions and similar_functions[n]:
            groups = similar_functions[n]
            table.add_row(f"Similar {n}-gram Groups", str(len(groups)))
            if groups:
                largest_group = groups[0]
                table.add_row(
                    f"Largest {n}-gram Group",
                    f"{largest_group['count']} functions",
                )


def _add_binlex_binary_signatures(table, ngram_sizes, binary_signature):
    for n in ngram_sizes:
        if n in binary_signature:
            sig = binary_signature[n]
            table.add_row(
                f"Binary {n}-gram Signature",
                format_hash_display(sig, max_length=64),
            )


def _add_binlex_top_ngrams(table, ngram_sizes, top_ngrams):
    for n in ngram_sizes:
        if n in top_ngrams and top_ngrams[n]:
            top_3 = top_ngrams[n][:3]
            ngram_strs = []
            for ngram, count in top_3:
                clean_ngram = ngram.replace("&nbsp;", " ").replace(HTML_AMP, "&").strip()
                if len(clean_ngram) > 50:
                    clean_ngram = clean_ngram[:47] + "..."
                ngram_strs.append(f"• {clean_ngram} ({count})")
            table.add_row(f"Top {n}-grams", "\n".join(ngram_strs))


def _display_binbloom(results):
    if "binbloom" not in results:
        return

    binbloom_info = results["binbloom"]
    table = Table(title="Binbloom (Bloom Filter Analysis)", show_header=True, width=120)
    table.add_column("Property", style="cyan", width=25)
    table.add_column("Value", style="yellow", width=90, overflow="fold")

    if binbloom_info.get("available"):
        _add_binbloom_stats(table, binbloom_info)
        _add_binbloom_similar_groups(table, binbloom_info)
        _add_binbloom_binary_signature(table, binbloom_info)
        _add_binbloom_bloom_stats(table, binbloom_info)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if binbloom_info.get("error"):
            table.add_row("Error", binbloom_info.get("error", UNKNOWN_ERROR))
        elif not binbloom_info.get("library_available", True):
            table.add_row("Error", "pybloom-live library not installed")
            table.add_row("Install Command", "pip install pybloom-live")

    console.print(table)
    _display_binbloom_signature_details(binbloom_info)
    console.print()


def _add_binbloom_stats(table, binbloom_info):
    total_functions = binbloom_info.get("total_functions", 0)
    table.add_row(TOTAL_FUNCTIONS_LABEL, str(total_functions))

    analyzed_functions = binbloom_info.get("analyzed_functions", 0)
    table.add_row(ANALYZED_FUNCTIONS_LABEL, str(analyzed_functions))

    capacity = binbloom_info.get("capacity", 0)
    error_rate = binbloom_info.get("error_rate", 0.0)
    table.add_row("Bloom Filter Capacity", str(capacity))
    table.add_row("False Positive Rate", f"{error_rate:.4f} ({error_rate * 100:.2f}%)")

    unique_signatures = binbloom_info.get("unique_signatures", 0)
    diversity_ratio = (unique_signatures / analyzed_functions * 100) if analyzed_functions else 0
    table.add_row(
        "Unique Function Signatures",
        f"{unique_signatures} ({diversity_ratio:.1f}% diversity)",
    )

    function_signatures = binbloom_info.get("function_signatures", {})
    if not function_signatures:
        return

    total_instructions = sum(
        sig.get("instruction_count", 0) for sig in function_signatures.values()
    )
    avg_instructions = total_instructions / len(function_signatures) if function_signatures else 0
    unique_instructions = sum(
        sig.get("unique_instructions", 0) for sig in function_signatures.values()
    )
    avg_unique = unique_instructions / len(function_signatures) if function_signatures else 0

    table.add_row("Avg Instructions/Function", f"{avg_instructions:.1f}")
    table.add_row("Avg Unique Instructions", f"{avg_unique:.1f}")


def _add_binbloom_similar_groups(table, binbloom_info):
    similar_functions = binbloom_info.get("similar_functions", [])
    if not similar_functions:
        table.add_row(SIMILAR_GROUPS_LABEL, "0 (all functions unique)")
        return

    table.add_row(SIMILAR_GROUPS_LABEL, str(len(similar_functions)))
    for i, group in enumerate(similar_functions[:3]):
        _add_binbloom_group(table, i + 1, group)

    if len(similar_functions) > 3:
        table.add_row(
            "Additional Groups",
            f"... and {len(similar_functions) - 3} more groups",
        )


def _add_binbloom_group(table, index, group):
    group_size = group.get("count", 0)
    group_signature = group.get("signature", "")
    group_sig = group_signature[:32] + "..." if len(group_signature) > 32 else group_signature

    table.add_row(f"Group {index} Size", f"{group_size} functions")
    table.add_row(f"Group {index} Signature", group_sig)

    if not group.get("functions"):
        return

    sample_funcs = group["functions"][:5]
    func_display = []
    for func in sample_funcs:
        func_name = func if len(func) <= 30 else func[:27] + "..."
        func_display.append(f"• {func_name}")

    if len(group["functions"]) > 5:
        func_display.append(f"• ... and {len(group['functions']) - 5} more")

    table.add_row(f"Group {index} Functions", "\n".join(func_display))


def _add_binbloom_binary_signature(table, binbloom_info):
    binary_signature = binbloom_info.get("binary_signature")
    if binary_signature:
        table.add_row(
            "Binary Bloom Signature",
            format_hash_display(binary_signature, max_length=64),
        )


def _add_binbloom_bloom_stats(table, binbloom_info):
    bloom_stats = binbloom_info.get("bloom_stats", {})
    if not bloom_stats:
        return

    avg_fill_rate = bloom_stats.get("average_fill_rate", 0.0)
    table.add_row("Average Fill Rate", f"{avg_fill_rate:.4f} ({avg_fill_rate * 100:.2f}%)")

    total_filters = bloom_stats.get("total_filters", 0)
    table.add_row("Total Bloom Filters", str(total_filters))


def _display_binbloom_signature_details(binbloom_info):
    if not binbloom_info.get("available"):
        return
    if binbloom_info.get("unique_signatures", 0) <= 1:
        return

    function_signatures = binbloom_info.get("function_signatures", {})
    signatures_by_hash: dict[str, list[str]] = {}
    for func_name, sig_data in function_signatures.items():
        sig_hash = sig_data.get("signature", "")
        signatures_by_hash.setdefault(sig_hash, []).append(func_name)

    sig_table = Table(
        title="Binbloom Signature Details",
        show_header=True,
        header_style="bold cyan",
        title_style="bold cyan",
        expand=True,
    )
    sig_table.add_column("Signature #", style="yellow", no_wrap=True, width=13)
    sig_table.add_column("Hash", style="green", min_width=50, overflow="fold")
    sig_table.add_column("Functions", style="blue", min_width=45, overflow="fold")

    unique_sigs = list(signatures_by_hash.keys())[:5]
    for i, sig_hash in enumerate(unique_sigs):
        funcs = signatures_by_hash[sig_hash]
        clean_funcs = [re.sub(r"&nbsp;?", " ", func).replace(HTML_AMP, "&") for func in funcs[:3]]
        func_list = ", ".join(clean_funcs) + ("..." if len(funcs) > 3 else "")
        sig_table.add_row(
            f"Signature {i + 1}",
            f"{sig_hash[:64]}{'...' if len(sig_hash) > 64 else ''}",
            f"Functions ({len(funcs)}): {func_list}",
        )

    console.print()
    console.print(sig_table)


def _display_simhash(results):
    if "simhash" not in results:
        return

    simhash_info = results["simhash"]
    table = Table(title="SimHash (Similarity Hashing)", show_header=True, width=120)
    table.add_column("Property", style="cyan", width=25)
    table.add_column("Value", style="yellow", width=90, overflow="fold")

    if simhash_info.get("available"):
        feature_stats = simhash_info.get("feature_stats", {})
        _add_simhash_feature_stats(table, feature_stats)
        _add_simhash_hashes(table, simhash_info)
        _add_simhash_function_analysis(table, simhash_info)
        _add_simhash_top_features(table, feature_stats)
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if simhash_info.get("error"):
            table.add_row("Error", simhash_info.get("error", UNKNOWN_ERROR))
        elif not simhash_info.get("library_available", True):
            table.add_row("Error", "simhash library not installed")
            table.add_row("Install Command", "pip install simhash")

    console.print(table)
    console.print()


def _add_simhash_feature_stats(table, feature_stats):
    total_features = feature_stats.get("total_features", 0)
    total_strings = feature_stats.get("total_strings", 0)
    total_opcodes = feature_stats.get("total_opcodes", 0)

    table.add_row("Total Features", str(total_features))
    table.add_row("String Features", str(total_strings))
    table.add_row("Opcode Features", str(total_opcodes))

    feature_diversity = feature_stats.get("feature_diversity", 0.0)
    table.add_row("Feature Diversity", f"{feature_diversity:.3f}")


def _format_simhash_hex(hash_hex: str) -> str:
    if len(hash_hex) > 32:
        return f"{hash_hex[:32]}\n{hash_hex[32:]}"
    return hash_hex


def _add_simhash_hashes(table, simhash_info):
    combined_simhash = simhash_info.get("combined_simhash")
    if combined_simhash:
        hash_hex = combined_simhash.get("hex", "")
        table.add_row("Binary SimHash", _format_simhash_hex(hash_hex))
        table.add_row("Combined Features", str(combined_simhash.get("feature_count", 0)))

    strings_simhash = simhash_info.get("strings_simhash")
    if strings_simhash:
        hash_hex = strings_simhash.get("hex", "")
        table.add_row("Strings SimHash", _format_simhash_hex(hash_hex))

    opcodes_simhash = simhash_info.get("opcodes_simhash")
    if opcodes_simhash:
        hash_hex = opcodes_simhash.get("hex", "")
        table.add_row("Opcodes SimHash", _format_simhash_hex(hash_hex))


def _add_simhash_function_analysis(table, simhash_info):
    function_simhashes = simhash_info.get("function_simhashes", {})
    if not function_simhashes:
        return

    total_functions = simhash_info.get("total_functions", 0)
    analyzed_functions = simhash_info.get("analyzed_functions", 0)
    table.add_row(TOTAL_FUNCTIONS_LABEL, str(total_functions))
    table.add_row(ANALYZED_FUNCTIONS_LABEL, str(analyzed_functions))

    similarity_groups = simhash_info.get("similarity_groups", [])
    if not similarity_groups:
        table.add_row(SIMILAR_GROUPS_LABEL, "0 (all functions unique)")
        return

    _add_simhash_similarity_groups(table, similarity_groups)


def _add_simhash_similarity_groups(table, similarity_groups):
    table.add_row(SIMILAR_GROUPS_LABEL, str(len(similarity_groups)))
    for i, group in enumerate(similarity_groups[:3]):
        _add_simhash_similarity_group(table, i + 1, group)

    if len(similarity_groups) > 3:
        table.add_row(
            "Additional Groups",
            f"... and {len(similarity_groups) - 3} more groups",
        )


def _add_simhash_similarity_group(table, index, group):
    group_size = group.get("count", 0)
    group_hash = group.get("representative_hash", "")
    hash_display = f"{group_hash[:24]}...{group_hash[-8:]}" if len(group_hash) > 24 else group_hash

    table.add_row(f"Group {index} Size", f"{group_size} functions")
    table.add_row(f"Group {index} Hash", hash_display)

    if not group.get("functions"):
        return

    sample_funcs = group["functions"][:5]
    func_display = []
    for func in sample_funcs:
        func_name = func if len(func) <= 30 else func[:27] + "..."
        func_display.append(f"• {func_name}")

    if len(group["functions"]) > 5:
        func_display.append(f"• ... and {len(group['functions']) - 5} more")

    table.add_row(f"Group {index} Functions", "\n".join(func_display))


def _add_simhash_top_features(table, feature_stats):
    most_common = feature_stats.get("most_common_features", [])
    if not most_common:
        return

    top_features = []
    for feature, count in most_common[:5]:
        clean_feature = feature.replace("STR:", "").replace("OP:", "").replace("OPTYPE:", "")
        if len(clean_feature) > 40:
            clean_feature = clean_feature[:37] + "..."
        top_features.append(f"• {clean_feature} ({count})")

    table.add_row("Top Features", "\n".join(top_features))


def _display_bindiff(results):
    if "bindiff" not in results:
        return

    bindiff_info = results["bindiff"]
    table = Table(title="BinDiff (Binary Comparison Features)", show_header=True)
    table.add_column("Property", style="cyan", width=25)
    table.add_column("Value", style="yellow", no_wrap=False)

    if bindiff_info.get("comparison_ready"):
        _add_bindiff_entries(table, bindiff_info)
        table.add_row("Status", "[green]✓ Comparison Ready[/green]")
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if bindiff_info.get("error"):
            table.add_row("Error", bindiff_info.get("error", UNKNOWN_ERROR))

    console.print(table)
    console.print()


def _add_bindiff_entries(table, bindiff_info):
    table.add_row("Filename", bindiff_info.get("filename", "Unknown"))

    _add_bindiff_structural(table, bindiff_info.get("structural_features", {}))
    _add_bindiff_functions(table, bindiff_info.get("function_features", {}))
    _add_bindiff_strings(table, bindiff_info.get("string_features", {}))
    _add_bindiff_signatures(table, bindiff_info.get("signatures", {}))


def _add_bindiff_structural(table, structural):
    if not structural:
        return
    table.add_row("File Type", structural.get("file_type", "Unknown"))
    table.add_row("File Size", f"{structural.get('file_size', 0):,} bytes")
    table.add_row("Sections", str(structural.get("section_count", 0)))
    if structural.get("section_names"):
        section_names = structural["section_names"]
        if len(section_names) <= 7:
            table.add_row("Section Names", ", ".join(section_names))
        else:
            displayed = section_names[:5]
            remaining = len(section_names) - 5
            table.add_row(
                "Section Names",
                f"{', '.join(displayed)}\n... and {remaining} more",
            )
    table.add_row("Imports", str(structural.get("import_count", 0)))
    table.add_row("Exports", str(structural.get("export_count", 0)))


def _add_bindiff_functions(table, function_features):
    if not function_features:
        return
    table.add_row("Functions", str(function_features.get("function_count", 0)))
    if function_features.get("cfg_features"):
        cfg_count = len(function_features["cfg_features"])
        table.add_row("CFG Analysis", f"{cfg_count} functions analyzed")


def _add_bindiff_strings(table, string_features):
    if not string_features:
        return
    table.add_row("Strings", str(string_features.get("total_strings", 0)))
    if string_features.get("categorized_strings"):
        categories = list(string_features["categorized_strings"].keys())[:3]
        table.add_row("String Types", ", ".join(categories))


def _add_bindiff_signatures(table, signatures):
    if not signatures:
        return
    structural_hash = signatures.get("structural", "N/A")
    function_hash = signatures.get("function", "N/A")
    string_hash = signatures.get("string", "N/A")

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


def _display_machoc_functions(results):
    if "functions" not in results:
        return

    functions_info = results["functions"]
    table = Table(title="Function Analysis (MACHOC)", show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")

    table.add_row(TOTAL_FUNCTIONS_LABEL, str(functions_info.get("total_functions", 0)))

    machoc_hashes = functions_info.get("machoc_hashes", {})
    unique_hashes = len(set(machoc_hashes.values())) if machoc_hashes else 0
    table.add_row("Unique MACHOC Hashes", str(unique_hashes))

    if machoc_hashes:
        hash_counts = {}
        for _, machoc_hash in machoc_hashes.items():
            hash_counts[machoc_hash] = hash_counts.get(machoc_hash, 0) + 1
        duplicates = sum(count - 1 for count in hash_counts.values() if count > 1)
        table.add_row("Duplicate Functions", str(duplicates))

    console.print(table)
    console.print()


def _display_indicators(results):
    indicators = results.get("indicators")
    if not indicators:
        return

    table = Table(title="Suspicious Indicators", show_header=True)
    table.add_column("Type", style="red")
    table.add_column("Description", style="yellow")
    table.add_column("Severity", style="magenta")

    for indicator in indicators:
        table.add_row(
            indicator.get("type", "Unknown"),
            indicator.get("description", "N/A"),
            indicator.get("severity", "Unknown"),
        )

    console.print(table)
    console.print()
