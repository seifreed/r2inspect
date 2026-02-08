from __future__ import annotations

from rich.console import Console

from r2inspect.cli import display, display_base
from r2inspect.cli.display_sections import (
    _display_circuit_breaker_statistics,
    _display_retry_statistics,
    _format_simhash_hex,
)


def _install_console() -> Console:
    console = Console(record=True, width=120)
    display.console = console
    return console


def test_display_results_full_branches() -> None:
    console = _install_console()

    results = {
        "file_info": {
            "size": 123,
            "path": "/tmp/sample.exe",
            "name": "sample.exe",
            "mime_type": "application/octet-stream",
            "file_type": "PE",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
            "enhanced_detection": {
                "file_format": "PE",
                "format_category": "Executable",
                "architecture": "x86-64",
                "bits": 64,
                "endianness": "Little",
                "confidence": 0.95,
            },
            "threat_level": "High",
        },
        "pe_info": {"compile_time": "2026-01-30", "imphash": "imphash", "is_executable": True},
        "security": {"aslr": True, "dep": True, "seh": False},
        "ssdeep": {"available": True, "hash_value": "ss", "method_used": "python"},
        "tlsh": {
            "available": True,
            "binary_tlsh": "bt",
            "text_section_tlsh": "",
            "stats": {"functions_analyzed": 10, "functions_with_tlsh": 2},
        },
        "telfhash": {
            "available": True,
            "is_elf": True,
            "telfhash": "th",
            "symbol_count": 10,
            "filtered_symbols": 2,
            "symbols_used": ["a", "b", "c", "d", "e", "f"],
        },
        "rich_header": {
            "available": True,
            "is_pe": True,
            "xor_key": 0x1234,
            "checksum": 0x1234,
            "richpe_hash": "rh",
            "compilers": [
                {"compiler_name": "MSVC", "count": 2, "build_number": 19},
                {"compiler_name": "GCC", "count": 1, "build_number": 12},
            ],
        },
        "impfuzzy": {
            "available": True,
            "impfuzzy_hash": "if",
            "import_count": 5,
            "dll_count": 2,
            "imports_processed": ["k32!CreateFileA"],
        },
        "ccbhash": {
            "available": True,
            "binary_ccbhash": "cc",
            "total_functions": 10,
            "analyzed_functions": 10,
            "unique_hashes": 2,
            "similar_functions": [{"count": 3, "functions": ["f1", "f2", "f3", "f4"]}],
        },
        "binlex": {
            "available": True,
            "total_functions": 4,
            "analyzed_functions": 4,
            "ngram_sizes": [3],
            "unique_signatures": {3: 2},
            "similar_functions": {3: [{"count": 2}]},
            "binary_signature": {3: "abcd"},
            "top_ngrams": {3: [("abc", 2)]},
        },
        "binbloom": {
            "available": True,
            "binary_fingerprint": "bb",
            "functions_analyzed": 5,
            "unique_signatures": 3,
            "similar_function_groups": [{"count": 2, "functions": ["a", "b", "c", "d"]}],
            "signature_details": {
                "function_hashes": {"f1": "h1"},
                "group_signatures": {"g1": "g"},
                "binary_signature": "sig",
            },
        },
        "simhash": {
            "available": True,
            "binary_simhash": "0x1",
            "feature_diversity": 0.5,
            "features": {"strings": 10, "opcodes": 0},
            "top_features": ["A", "B"],
        },
        "bindiff": {
            "available": True,
            "filename": "sample.exe",
            "structural_features": {
                "file_type": "PE",
                "file_size": 10,
                "section_count": 2,
                "section_names": [".text", ".data", ".rdata", ".rsrc", ".reloc", ".tls"],
                "import_count": 1,
                "export_count": 0,
            },
            "function_features": {"function_count": 10, "cfg_features": [1]},
            "string_features": {"total_strings": 2, "categorized_strings": {"ascii": 1}},
            "signatures": {"structural": "s", "function": "f", "string": "t"},
        },
        "functions": {
            "total_functions": 10,
            "machoc_hashes": {"f1": "h1", "f2": "h1"},
        },
        "indicators": [{"type": "Anti-Debug", "description": "Detected", "severity": "High"}],
    }

    display_base.display_results(results)
    output = console.export_text()
    assert "File Information" in output
    assert "PE Analysis" in output
    assert "SSDeep" in output or "SSDeep Fuzzy Hash" in output


def test_display_results_unavailable_branches() -> None:
    console = _install_console()

    results = {
        "ssdeep": {"available": False, "error": "nope"},
        "tlsh": {"available": False, "error": "nope"},
        "telfhash": {"available": True, "is_elf": False},
        "rich_header": {"available": True, "is_pe": False},
        "impfuzzy": {"available": False, "error": "nope", "library_available": False},
        "ccbhash": {"available": False, "error": "nope"},
        "binlex": {"available": False, "error": "nope"},
        "binbloom": {"available": False, "error": "nope"},
        "simhash": {"available": False, "error": "nope"},
        "bindiff": {"available": False, "error": "nope"},
    }

    display_base.display_results(results)
    output = console.export_text()
    assert "Not Available" in output or "Error" in output


def test_display_performance_sections() -> None:
    console = _install_console()

    retry_stats = {
        "total_retries": 2,
        "successful_retries": 1,
        "failed_after_retries": 1,
        "success_rate": 50.0,
        "commands_retried": {"ij": 2, "iSj": 1},
    }
    circuit_stats = {"open_count": 1, "half_open_count": 0}

    display_base.display_performance_statistics(retry_stats, circuit_stats)
    output = console.export_text()
    assert "Performance Statistics" in output

    # Direct helpers
    _display_retry_statistics(retry_stats)
    _display_circuit_breaker_statistics(circuit_stats)
    assert console.export_text()


def test_format_simhash_hex() -> None:
    assert _format_simhash_hex("0x1") == "0x1"
    assert "\n" in _format_simhash_hex("0x" + "f" * 40)
