from __future__ import annotations

import builtins
import io
from pathlib import Path

from rich.console import Console
from rich.table import Table

from r2inspect.cli import display as display_module
from r2inspect.cli import display_base, display_sections, interactive, presenter
from r2inspect.utils.output import OutputFormatter


class _DummyInspector:
    def analyze(self, **_options: object) -> dict[str, object]:
        return {"file_info": {"name": "sample.bin"}}

    def get_strings(self) -> list[str]:
        return ["alpha", "beta"]

    def get_file_info(self) -> dict[str, object]:
        return {"name": "sample.bin", "size": 64}

    def get_pe_info(self) -> dict[str, object]:
        return {"format": "PE32", "sections": 3}

    def get_imports(self) -> list[dict[str, object]]:
        return [{"name": "LoadLibraryA"}]

    def get_exports(self) -> list[dict[str, object]]:
        return [{"name": "ExportedFunc"}]

    def get_sections(self) -> list[dict[str, object]]:
        return [{"name": ".text", "size": 10}]


def _swap_console() -> Console:
    console = Console(file=io.StringIO(), force_terminal=False, color_system=None, width=120)
    display_module.console = console
    return console


def test_display_sections_and_base_full_coverage(tmp_path: Path) -> None:
    original_console = display_module.console
    try:
        _swap_console()
        assert display_base.format_hash_display(None) == "N/A"
        assert display_base.format_hash_display("x" * 40, max_length=10).endswith("...")
        display_base.pyfiglet = type("Fig", (), {"figlet_format": lambda *_args, **_kwargs: "x"})()
        display_base.print_banner()
        display_base.pyfiglet = None
        display_base.print_banner()

        results_present = {
            "file_info": {
                "size": 123,
                "path": "/tmp/sample.bin",
                "name": "sample.bin",
                "mime_type": "application/octet-stream",
                "file_type": "ELF 64-bit",
                "md5": "md5",
                "sha1": "sha1",
                "sha256": "sha256",
                "sha512": "sha512",
                "enhanced_detection": {
                    "file_format": "ELF64",
                    "format_category": "Executable",
                    "architecture": "x86-64",
                    "bits": 64,
                    "endianness": "Little",
                    "confidence": 0.91,
                    "potential_threat": True,
                },
                "threat_level": "High",
            },
            "pe_info": {
                "magic": 111,
                "list_value": ["a", "b"],
                "dict_value": {"skip": True},
                "format": "PE32",
            },
            "security": {"aslr": True, "dep": False},
            "ssdeep": {"available": True, "hash_value": "3:abc:def", "method_used": "ssdeep"},
            "tlsh": {
                "available": True,
                "binary_tlsh": "",
                "text_section_tlsh": "T1",
                "stats": {"functions_analyzed": 4, "functions_with_tlsh": 1},
            },
            "telfhash": {
                "available": True,
                "is_elf": True,
                "telfhash": "deadbeef",
                "symbol_count": 3,
                "filtered_symbols": 1,
                "symbols_used": ["a", "b", "c", "d", "e", "f"],
            },
            "rich_header": {
                "available": True,
                "is_pe": True,
                "xor_key": 0x1234,
                "checksum": 0x5678,
                "richpe_hash": "richhash",
                "compilers": [
                    {"compiler_name": "MSVC", "count": 2, "build_number": 19},
                    {"compiler_name": "VS", "count": 1, "build_number": 15},
                    {"compiler_name": "X", "count": 1, "build_number": 12},
                    {"compiler_name": "Y", "count": 1, "build_number": 12},
                    {"compiler_name": "Z", "count": 1, "build_number": 12},
                    {"compiler_name": "A", "count": 1, "build_number": 12},
                ],
            },
            "impfuzzy": {
                "available": True,
                "impfuzzy_hash": "imp",
                "import_count": 12,
                "dll_count": 3,
                "imports_processed": [f"imp{i}" for i in range(12)],
            },
            "ccbhash": {
                "available": True,
                "binary_ccbhash": "c" * 70,
                "total_functions": 10,
                "analyzed_functions": 9,
                "unique_hashes": 4,
                "similar_functions": [
                    {
                        "count": 4,
                        "functions": [
                            "func&nbsp;1",
                            "func&amp;2",
                            "func3",
                            "func4",
                        ],
                    }
                ],
            },
            "binlex": {
                "available": True,
                "total_functions": 12,
                "analyzed_functions": 11,
                "ngram_sizes": [2, 3],
                "unique_signatures": {2: 4, 3: 2},
                "similar_functions": {2: [{"count": 2}], 3: [{"count": 1}]},
                "binary_signature": {2: "sig2", 3: "sig3"},
                "top_ngrams": {
                    2: [("a&nbsp;bc", 3), ("x" * 60, 2)],
                    3: [("OP:mov", 2)],
                },
            },
            "binbloom": {
                "available": True,
                "total_functions": 6,
                "analyzed_functions": 5,
                "capacity": 100,
                "error_rate": 0.01,
                "unique_signatures": 2,
                "function_signatures": {
                    "func1": {
                        "signature": "sig1",
                        "instruction_count": 10,
                        "unique_instructions": 7,
                    },
                    "func2": {
                        "signature": "sig2",
                        "instruction_count": 8,
                        "unique_instructions": 5,
                    },
                },
                "similar_functions": [
                    {
                        "count": 3,
                        "signature": "a" * 40,
                        "functions": [f"func{i}" for i in range(7)],
                    },
                    {"count": 2, "signature": "b", "functions": ["a"]},
                    {"count": 1, "signature": "c", "functions": ["b"]},
                    {"count": 1, "signature": "d", "functions": ["c"]},
                ],
                "binary_signature": "bb" * 40,
                "bloom_stats": {"average_fill_rate": 0.5, "total_filters": 2},
            },
            "simhash": {
                "available": True,
                "feature_stats": {
                    "total_features": 10,
                    "total_strings": 4,
                    "total_opcodes": 6,
                    "feature_diversity": 0.55,
                    "most_common_features": [
                        ("STR:abc", 2),
                        ("OP:mov", 1),
                        ("OPTYPE:arith", 1),
                    ],
                },
                "combined_simhash": {"hex": "a" * 64, "feature_count": 5},
                "strings_simhash": {"hex": "b" * 16},
                "opcodes_simhash": {"hex": "c" * 16},
                "function_simhashes": {"f1": "hash1"},
                "total_functions": 6,
                "analyzed_functions": 5,
                "similarity_groups": [
                    {
                        "count": 4,
                        "representative_hash": "h" * 32,
                        "functions": [f"func{i}" for i in range(7)],
                    },
                    {"count": 1, "representative_hash": "x", "functions": ["a"]},
                    {"count": 1, "representative_hash": "y", "functions": ["b"]},
                    {"count": 1, "representative_hash": "z", "functions": ["c"]},
                ],
            },
            "bindiff": {
                "comparison_ready": True,
                "filename": "sample.bin",
                "structural_features": {
                    "file_type": "PE",
                    "file_size": 1234,
                    "section_count": 10,
                    "section_names": [f".sec{i}" for i in range(10)],
                    "import_count": 2,
                    "export_count": 1,
                },
                "function_features": {"function_count": 3, "cfg_features": [1, 2]},
                "string_features": {"total_strings": 2, "categorized_strings": {"url": 1}},
                "signatures": {"structural": "N/A", "function": "abc", "string": "N/A"},
            },
            "functions": {
                "total_functions": 5,
                "machoc_hashes": {"f1": "h1", "f2": "h1", "f3": "h2"},
            },
            "indicators": [
                {"type": "Packer", "description": "packed", "severity": "High"},
            ],
        }

        display_base.display_results(results_present)

        results_absent = {"__present__": set()}
        display_sections._display_file_info(results_absent)
        display_sections._display_pe_info(results_absent)
        display_sections._display_security(results_absent)
        display_sections._display_ssdeep(results_absent)
        display_sections._display_tlsh(results_absent)
        display_sections._display_telfhash(results_absent)
        display_sections._display_rich_header(results_absent)
        display_sections._display_impfuzzy(results_absent)
        display_sections._display_ccbhash(results_absent)
        display_sections._display_binlex(results_absent)
        display_sections._display_binbloom(results_absent)
        display_sections._display_simhash(results_absent)
        display_sections._display_bindiff(results_absent)
        display_sections._display_machoc_functions(results_absent)
        display_sections._display_indicators(results_absent)

        display_sections._display_ssdeep({"ssdeep": {"available": False, "error": "missing"}})
        display_sections._display_tlsh({"tlsh": {"available": False, "error": "missing"}})
        display_sections._display_telfhash(
            {"telfhash": {"available": True, "is_elf": False, "error": "no elf"}}
        )
        display_sections._display_telfhash(
            {"telfhash": {"available": False, "error": "unavailable"}}
        )
        display_sections._display_rich_header({"rich_header": {"available": True, "is_pe": False}})
        display_sections._display_rich_header(
            {"rich_header": {"available": False, "error": "missing"}}
        )
        display_sections._display_impfuzzy(
            {"impfuzzy": {"available": False, "error": "missing", "library_available": False}}
        )
        display_sections._display_ccbhash({"ccbhash": {"available": False, "error": "missing"}})
        display_sections._display_binlex({"binlex": {"available": False, "error": "missing"}})
        display_sections._display_binbloom(
            {"binbloom": {"available": False, "library_available": False}}
        )
        display_sections._display_simhash({"simhash": {"available": False, "error": "missing"}})
        display_sections._display_bindiff({"bindiff": {"comparison_ready": False}})
        display_sections._display_bindiff(
            {"bindiff": {"comparison_ready": False, "error": "missing"}}
        )
        display_sections._display_indicators({"indicators": []})

        display_sections._display_retry_statistics({"total_retries": 0, "commands_retried": {}})
        display_sections._display_retry_statistics(
            {
                "total_retries": 3,
                "successful_retries": 2,
                "failed_after_retries": 1,
                "success_rate": 66.6,
                "commands_retried": {"i": 2, "aa": 1},
            }
        )
        display_sections._display_most_retried_commands({"commands_retried": {"i": 2, "aa": 1}})
        display_sections._display_most_retried_commands({"commands_retried": {}})

        display_sections._display_circuit_breaker_statistics({})
        display_sections._display_circuit_breaker_statistics(
            {"total_failures": 0, "open_timeouts": 2}
        )
        display_sections._display_circuit_breaker_statistics({"total_failures": 0})

        display_sections._add_simhash_function_analysis(
            Table(), {"function_simhashes": {}, "similarity_groups": []}
        )
        display_sections._add_simhash_function_analysis(
            Table(),
            {
                "function_simhashes": {"f1": "h"},
                "total_functions": 1,
                "analyzed_functions": 1,
                "similarity_groups": [],
            },
        )
        display_sections._add_simhash_similarity_group(Table(), 1, {"count": 1, "functions": []})
        display_sections._add_simhash_top_features(Table(), {})
        display_sections._add_simhash_top_features(
            Table(),
            {"most_common_features": [("STR:" + ("x" * 50), 1)]},
        )

        display_sections._format_simhash_hex("a" * 40)

        display_sections._display_binbloom_signature_details(
            {
                "available": True,
                "unique_signatures": 2,
                "function_signatures": {
                    "func": {"signature": "s"},
                    "func2": {"signature": "s"},
                },
            }
        )
        display_sections._display_binbloom_signature_details(
            {"available": True, "unique_signatures": 1}
        )

        display_sections._display_ccbhash({"ccbhash": {"available": True, "similar_functions": []}})
        display_sections._add_ccbhash_entries(
            Table(), {"total_functions": 0, "analyzed_functions": 0, "similar_functions": [None]}
        )

        display_sections._display_binbloom({"binbloom": {"available": False, "error": "boom"}})
        display_sections._add_binbloom_stats(Table(), {"function_signatures": {}})
        display_sections._add_binbloom_similar_groups(Table(), {"similar_functions": []})
        display_sections._add_binbloom_group(Table(), 1, {"count": 1, "signature": "s"})
        display_sections._add_binbloom_bloom_stats(Table(), {"bloom_stats": {}})

        display_sections._display_simhash(
            {"simhash": {"available": False, "library_available": False}}
        )

        display_sections._add_bindiff_structural(Table(), {})
        display_sections._add_bindiff_structural(
            Table(),
            {
                "file_type": "PE",
                "file_size": 1,
                "section_count": 2,
                "section_names": ["a", "b"],
                "import_count": 0,
                "export_count": 0,
            },
        )
        display_sections._add_bindiff_functions(Table(), {})
        display_sections._add_bindiff_strings(Table(), {})
        display_sections._add_bindiff_signatures(Table(), {})

        display_base.display_validation_errors(["bad"])
        display_base.display_error_statistics(
            {
                "total_errors": 3,
                "recent_errors": 1,
                "recovery_strategies_available": 2,
                "errors_by_category": {"analysis": 1},
                "errors_by_severity": {"critical": 1, "high": 1, "low": 1},
            }
        )
        display_base.display_performance_statistics(
            {
                "total_retries": 1,
                "successful_retries": 1,
                "failed_after_retries": 0,
                "success_rate": 100.0,
                "commands_retried": {"i": 1},
            },
            {"open_timeouts": 1},
        )

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "rule.yar").write_text("rule test { condition: true }")
        display_base.handle_list_yara_option(None, str(rules_dir))
        display_base.handle_list_yara_option(None, str(tmp_path / "missing_rules"))

        formatter = OutputFormatter({})
        display_base._get_console().print(formatter.format_table({"k": "v"}, "T"))

    finally:
        display_module.console = original_console


def test_interactive_mode_and_helpers() -> None:
    original_input = builtins.input
    original_console = display_module.console
    try:
        _swap_console()
        inspector = _DummyInspector()
        inputs = iter(
            [
                "",
                "analyze",
                "strings",
                "info",
                "pe",
                "imports",
                "exports",
                "sections",
                "help",
                "unknown",
                "quit",
            ]
        )
        builtins.input = lambda _prompt="": next(inputs)
        interactive.run_interactive_mode(inspector, options={})
        builtins.input = lambda _prompt="": (_ for _ in ()).throw(KeyboardInterrupt())
        interactive.run_interactive_mode(inspector, options={})
        builtins.input = lambda _prompt="": (_ for _ in ()).throw(EOFError())
        interactive.run_interactive_mode(inspector, options={})
        interactive.show_strings_only(inspector)
        interactive._print_help()
        interactive._show_info_table("Info", {"a": 1}, OutputFormatter({}))
    finally:
        builtins.input = original_input
        display_module.console = original_console


def test_presenter_sections() -> None:
    data = presenter.normalize_display_results({"a": 1})
    assert "a" in data["__present__"]

    missing = {"__present__": {"a"}}
    section, present = presenter.get_section(missing, "b", {})
    assert present is False
    assert section == {}

    section, present = presenter.get_section({"__present__": "bad"}, "b", 1)
    assert present is False
    assert section == 1
