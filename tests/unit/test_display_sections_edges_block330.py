from __future__ import annotations

import io

import pytest
from rich.table import Table

from r2inspect.cli import display as display_module
from r2inspect.cli import display_sections


@pytest.mark.unit
def test_display_sections_edge_branches() -> None:
    buffer = io.StringIO()
    original_file = display_module.console.file
    try:
        display_module.console.file = buffer

        # Retry/circuit early returns.
        display_sections._display_retry_statistics(
            {
                "total_retries": 0,
                "successful_retries": 0,
                "failed_after_retries": 0,
                "success_rate": 0.0,
                "commands_retried": {},
            }
        )
        display_sections._display_retry_statistics(
            {
                "total_retries": 1,
                "successful_retries": 0,
                "failed_after_retries": 1,
                "success_rate": 0.0,
                "commands_retried": {},
            }
        )
        display_sections._display_circuit_breaker_statistics({})

        # Telfhash symbols preview with "more".
        display_sections._display_telfhash(
            {
                "telfhash": {
                    "available": True,
                    "is_elf": True,
                    "telfhash": "hash",
                    "symbol_count": 6,
                    "filtered_symbols": 1,
                    "symbols_used": ["a", "b", "c", "d", "e", "f", "g"],
                }
            }
        )

        # Rich header not PE.
        display_sections._display_rich_header({"rich_header": {"available": True, "is_pe": False}})

        # CCBHash similar group missing.
        display_sections._display_ccbhash(
            {
                "ccbhash": {
                    "available": True,
                    "total_functions": 1,
                    "analyzed_functions": 1,
                    "unique_hashes": 1,
                    "similar_functions": [None],
                }
            }
        )

        # Binbloom error branch.
        display_sections._display_binbloom({"binbloom": {"available": False, "error": "boom"}})

        # Binbloom early returns (no signatures / no groups / no stats / unique <= 1).
        display_sections._display_binbloom(
            {
                "binbloom": {
                    "available": True,
                    "total_functions": 1,
                    "analyzed_functions": 1,
                    "capacity": 1,
                    "error_rate": 0.0,
                    "unique_signatures": 1,
                    "function_signatures": {},
                    "similar_functions": [],
                    "bloom_stats": {},
                }
            }
        )

        # Simhash error branch.
        display_sections._display_simhash({"simhash": {"available": False, "error": "boom"}})

        # Simhash empty groups and no top features.
        display_sections._display_simhash(
            {
                "simhash": {
                    "available": True,
                    "feature_stats": {"most_common_features": []},
                    "function_simhashes": {"f1": "x"},
                    "total_functions": 1,
                    "analyzed_functions": 1,
                    "similarity_groups": [],
                }
            }
        )

        # Simhash top features with truncation.
        display_sections._add_simhash_top_features(
            Table(title="SimHash"), {"most_common_features": [("X" * 80, 1)]}
        )

        # Bindiff empty structural, string, signatures and short section names.
        display_sections._add_bindiff_structural(Table(), {})
        display_sections._add_bindiff_strings(Table(), {})
        display_sections._add_bindiff_signatures(Table(), {})
        display_sections._add_bindiff_structural(
            Table(),
            {
                "file_type": "PE",
                "file_size": 1,
                "section_count": 2,
                "section_names": [".text", ".data"],
                "import_count": 0,
                "export_count": 0,
            },
        )
    finally:
        display_module.console.file = original_file

    output = buffer.getvalue()
    assert "Rich Header" in output
