"""Facade re-export for function analysis support seams."""

from __future__ import annotations

from .function_analyzer_extraction_support import (
    extract_function_mnemonics,
    get_file_size_mb,
    should_run_full_analysis,
    try_basic_pdj_extraction,
    try_pdfj_extraction,
    try_pdj_extraction,
    try_pi_extraction,
)
from .function_analyzer_machoc_support import (
    generate_machoc_hashes,
    generate_machoc_summary,
    get_function_similarity,
    process_single_function_hash,
)
from .function_analyzer_metrics_support import (
    analyze_function_coverage,
    calculate_std_dev,
    generate_function_stats,
)

__all__ = [
    "analyze_function_coverage",
    "calculate_std_dev",
    "extract_function_mnemonics",
    "generate_function_stats",
    "generate_machoc_hashes",
    "generate_machoc_summary",
    "get_file_size_mb",
    "get_function_similarity",
    "process_single_function_hash",
    "should_run_full_analysis",
    "try_basic_pdj_extraction",
    "try_pdfj_extraction",
    "try_pdj_extraction",
    "try_pi_extraction",
]
