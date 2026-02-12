#!/usr/bin/env python3
"""r2inspect CLI Display Sections Module."""

from __future__ import annotations

import re
from typing import Any, cast

from rich.console import Console
from rich.table import Table

from .display_base import (
    ANALYZED_FUNCTIONS_LABEL,
    HTML_AMP,
    NOT_AVAILABLE,
    SIMILAR_GROUPS_LABEL,
    STATUS_AVAILABLE,
    STATUS_NOT_AVAILABLE,
    STATUS_NOT_AVAILABLE_SIMPLE,
    TOTAL_FUNCTIONS_LABEL,
    UNKNOWN_ERROR,
    format_hash_display,
)
from .display_sections_file import _display_file_info, _display_pe_info, _display_security
from .display_sections_helpers import (  # noqa: F401
    _add_bindiff_entries,
    _add_bindiff_functions,
    _add_bindiff_signatures,
    _add_bindiff_strings,
    _add_bindiff_structural,
    _add_simhash_feature_stats,
    _add_simhash_function_analysis,
    _add_simhash_hashes,
    _add_simhash_similarity_group,
    _add_simhash_similarity_groups,
    _add_simhash_top_features,
    _format_simhash_hex,
)
from .display_statistics import (
    _display_circuit_breaker_statistics,
    _display_most_retried_commands,
    _display_retry_statistics,
)
from .presenter import get_section as _get_section

Results = dict[str, Any]


def _get_console() -> Console:
    from . import display as display_module

    return display_module.console


def _display_ssdeep(results: Results) -> None:
    ssdeep_info, present = _get_section(results, "ssdeep", {})
    if not present:
        return
    table = Table(title="SSDeep Fuzzy Hash", show_header=True, expand=True)
    table.add_column("Property", style="cyan", width=10, no_wrap=True)
    table.add_column("Value", style="yellow", min_width=50, overflow="fold")

    if ssdeep_info.get("available"):
        table.add_row("Hash", ssdeep_info.get("hash_value", "N/A"))
        table.add_row("Method", ssdeep_info.get("method_used", "Unknown"))
        table.add_row("Status", STATUS_AVAILABLE)
    else:
        table.add_row("Status", STATUS_NOT_AVAILABLE)
        if ssdeep_info.get("error"):
            table.add_row("Error", ssdeep_info.get("error", UNKNOWN_ERROR))

    _get_console().print(table)
    _get_console().print()


def _display_tlsh(results: Results) -> None:
    tlsh_info, present = _get_section(results, "tlsh", {})
    if not present:
        return
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

    _get_console().print(table)
    _get_console().print()


def _add_tlsh_entries(table: Table, tlsh_info: dict[str, Any]) -> None:
    binary_tlsh = tlsh_info.get("binary_tlsh")
    table.add_row("Binary TLSH", binary_tlsh if binary_tlsh else STATUS_NOT_AVAILABLE_SIMPLE)

    text_tlsh = tlsh_info.get("text_section_tlsh")
    table.add_row("Text Section TLSH", text_tlsh if text_tlsh else STATUS_NOT_AVAILABLE_SIMPLE)

    stats = tlsh_info.get("stats", {})
    table.add_row("Functions Analyzed", str(stats.get("functions_analyzed", 0)))
    table.add_row("Functions with TLSH", str(stats.get("functions_with_tlsh", 0)))


def _display_telfhash(results: Results) -> None:
    telfhash_info, present = _get_section(results, "telfhash", {})
    if not present:
        return
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

    _get_console().print(table)
    _get_console().print()


def _add_telfhash_entries(table: Table, telfhash_info: dict[str, Any]) -> None:
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


def _display_rich_header(results: Results) -> None:
    rich_header_info, present = _get_section(results, "rich_header", {})
    if not present:
        return
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

    _get_console().print(table)
    _get_console().print()


def _add_rich_header_entries(table: Table, rich_header_info: dict[str, Any]) -> None:
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


def _display_impfuzzy(results: Results) -> None:
    impfuzzy_info, present = _get_section(results, "impfuzzy", {})
    if not present:
        return
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

    _get_console().print(table)
    _get_console().print()


def _add_impfuzzy_entries(table: Table, impfuzzy_info: dict[str, Any]) -> None:
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


def _display_ccbhash(results: Results) -> None:
    ccbhash_info, present = _get_section(results, "ccbhash", {})
    if not present:
        return
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

    _get_console().print(table)
    _get_console().print()


def _add_ccbhash_entries(table: Table, ccbhash_info: dict[str, Any]) -> None:
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


def _display_binlex(results: Results) -> None:
    binlex_info, present = _get_section(results, "binlex", {})
    if not present:
        return
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

    _get_console().print(table)
    _get_console().print()


def _add_binlex_entries(table: Table, binlex_info: dict[str, Any]) -> None:
    ngram_sizes = _add_binlex_basic_stats(table, binlex_info)
    _add_binlex_unique_signatures(table, ngram_sizes, binlex_info.get("unique_signatures", {}))
    _add_binlex_similarity_groups(table, ngram_sizes, binlex_info.get("similar_functions", {}))
    _add_binlex_binary_signatures(table, ngram_sizes, binlex_info.get("binary_signature", {}))
    _add_binlex_top_ngrams(table, ngram_sizes, binlex_info.get("top_ngrams", {}))


def _add_binlex_basic_stats(table: Table, binlex_info: dict[str, Any]) -> list[Any]:
    total_functions = binlex_info.get("total_functions", 0)
    table.add_row(TOTAL_FUNCTIONS_LABEL, str(total_functions))

    analyzed_functions = binlex_info.get("analyzed_functions", 0)
    table.add_row(ANALYZED_FUNCTIONS_LABEL, str(analyzed_functions))

    ngram_sizes = cast(list[Any], binlex_info.get("ngram_sizes", []))
    table.add_row("N-gram Sizes", ", ".join(map(str, ngram_sizes)))
    return ngram_sizes


def _add_binlex_unique_signatures(
    table: Table, ngram_sizes: list[Any], unique_signatures: dict[str, Any]
) -> None:
    for n in ngram_sizes:
        if n in unique_signatures:
            table.add_row(f"Unique {n}-gram Signatures", str(unique_signatures[n]))


def _add_binlex_similarity_groups(
    table: Table, ngram_sizes: list[Any], similar_functions: dict[str, Any]
) -> None:
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


def _add_binlex_binary_signatures(
    table: Table, ngram_sizes: list[Any], binary_signature: dict[str, Any]
) -> None:
    for n in ngram_sizes:
        if n in binary_signature:
            sig = binary_signature[n]
            table.add_row(
                f"Binary {n}-gram Signature",
                format_hash_display(sig, max_length=64),
            )


def _add_binlex_top_ngrams(
    table: Table, ngram_sizes: list[Any], top_ngrams: dict[str, Any]
) -> None:
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


def _display_binbloom(results: Results) -> None:
    binbloom_info, present = _get_section(results, "binbloom", {})
    if not present:
        return
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

    _get_console().print(table)
    _display_binbloom_signature_details(binbloom_info)
    _get_console().print()


def _add_binbloom_stats(table: Table, binbloom_info: dict[str, Any]) -> None:
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


def _add_binbloom_similar_groups(table: Table, binbloom_info: dict[str, Any]) -> None:
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


def _add_binbloom_group(table: Table, index: int, group: dict[str, Any]) -> None:
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


def _add_binbloom_binary_signature(table: Table, binbloom_info: dict[str, Any]) -> None:
    binary_signature = binbloom_info.get("binary_signature")
    if binary_signature:
        table.add_row(
            "Binary Bloom Signature",
            format_hash_display(binary_signature, max_length=64),
        )


def _add_binbloom_bloom_stats(table: Table, binbloom_info: dict[str, Any]) -> None:
    bloom_stats = binbloom_info.get("bloom_stats", {})
    if not bloom_stats:
        return

    avg_fill_rate = bloom_stats.get("average_fill_rate", 0.0)
    table.add_row("Average Fill Rate", f"{avg_fill_rate:.4f} ({avg_fill_rate * 100:.2f}%)")

    total_filters = bloom_stats.get("total_filters", 0)
    table.add_row("Total Bloom Filters", str(total_filters))


def _display_binbloom_signature_details(binbloom_info: dict[str, Any]) -> None:
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

    _get_console().print()
    _get_console().print(sig_table)


def _display_simhash(results: Results) -> None:
    simhash_info, present = _get_section(results, "simhash", {})
    if not present:
        return
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

    _get_console().print(table)
    _get_console().print()


def _display_bindiff(results: Results) -> None:
    bindiff_info, present = _get_section(results, "bindiff", {})
    if not present:
        return
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

    _get_console().print(table)
    _get_console().print()


def _display_machoc_functions(results: Results) -> None:
    functions_info, present = _get_section(results, "functions", {})
    if not present:
        return
    table = Table(title="Function Analysis (MACHOC)", show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")

    table.add_row(TOTAL_FUNCTIONS_LABEL, str(functions_info.get("total_functions", 0)))

    machoc_hashes = functions_info.get("machoc_hashes", {})
    unique_hashes = len(set(machoc_hashes.values())) if machoc_hashes else 0
    table.add_row("Unique MACHOC Hashes", str(unique_hashes))

    if machoc_hashes:
        hash_counts: dict[str, int] = {}
        for _, machoc_hash in machoc_hashes.items():
            hash_counts[machoc_hash] = hash_counts.get(machoc_hash, 0) + 1
        duplicates = sum(count - 1 for count in hash_counts.values() if count > 1)
        table.add_row("Duplicate Functions", str(duplicates))

    _get_console().print(table)
    _get_console().print()


def _display_indicators(results: Results) -> None:
    indicators, present = _get_section(results, "indicators", [])
    if not present or not indicators:
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

    _get_console().print(table)
    _get_console().print()
