from __future__ import annotations

from pathlib import Path

import pytest

from r2inspect.cli import display_base
from r2inspect.cli import display_sections as ds
from r2inspect.cli.validators import (
    display_validation_errors,
    handle_xor_input,
    sanitize_xor_string,
    validate_batch_input,
    validate_config_input,
    validate_extensions_input,
    validate_file_input,
    validate_input_mode,
    validate_output_input,
    validate_single_file,
    validate_threads_input,
    validate_yara_input,
)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _fixture_path(name: str) -> Path:
    return _project_root() / "samples" / "fixtures" / name


def test_validate_file_input_errors(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    errors = validate_file_input(str(missing))
    assert errors

    directory = tmp_path / "dir"
    directory.mkdir()
    errors = validate_file_input(str(directory))
    assert any("regular file" in err for err in errors)

    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    errors = validate_file_input(str(empty_file))
    assert any("empty" in err for err in errors)

    large_file = tmp_path / "large.bin"
    large_file.write_bytes(b"x")
    import os

    os.truncate(large_file, 1024 * 1024 * 1024 + 1)
    errors = validate_file_input(str(large_file))
    assert any("too large" in err for err in errors)


def test_validate_batch_and_output_inputs(tmp_path: Path) -> None:
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    assert validate_batch_input(str(batch_dir)) == []

    batch_file = tmp_path / "batch.bin"
    batch_file.write_text("data", encoding="utf-8")
    errors = validate_batch_input(str(batch_file))
    assert errors

    output_file = tmp_path / "out.json"
    output_file.write_text("data", encoding="utf-8")
    assert validate_output_input(str(output_file)) == []

    output_parent = tmp_path / "not_dir"
    output_parent.write_text("data", encoding="utf-8")
    errors = validate_output_input(str(output_parent / "out"))
    assert errors


def test_validate_yara_and_config_inputs(tmp_path: Path) -> None:
    missing = tmp_path / "rules"
    assert validate_yara_input(str(missing))

    file_path = tmp_path / "rules.yar"
    file_path.write_text("rule dummy { condition: true }", encoding="utf-8")
    assert validate_yara_input(str(file_path))

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    assert validate_config_input(str(config_dir))

    bad_config = tmp_path / "config.txt"
    bad_config.write_text("oops", encoding="utf-8")
    assert validate_config_input(str(bad_config))


def test_validate_extensions_and_threads() -> None:
    assert validate_extensions_input(".exe,.dll") == []
    assert validate_extensions_input("bad!ext")
    assert validate_extensions_input(".toolongextension")

    assert validate_threads_input(None) == []
    assert validate_threads_input(0)
    assert validate_threads_input(51)


def test_validate_input_mode_and_single_file(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        validate_input_mode(None, None)

    with pytest.raises(SystemExit):
        validate_input_mode("file", "batch")

    sample = _fixture_path("hello_pe.exe")
    validate_input_mode(str(sample), None)

    with pytest.raises(SystemExit):
        validate_single_file(str(tmp_path / "missing.bin"))

    directory = tmp_path / "dir"
    directory.mkdir()
    with pytest.raises(SystemExit):
        validate_single_file(str(directory))


def test_xor_sanitization_and_warning() -> None:
    assert sanitize_xor_string(None) is None
    assert sanitize_xor_string("valid") == "valid"
    assert handle_xor_input("!!!") is None
    assert handle_xor_input("valid") == "valid"


def test_display_base_helpers(tmp_path: Path) -> None:
    assert display_base.format_hash_display(None) == "N/A"
    assert display_base.format_hash_display("N/A") == "N/A"
    assert display_base.format_hash_display("a" * 40, max_length=10) == "a" * 10 + "..."

    table = display_base.create_info_table("Title")
    assert table.title == "Title"

    display_base.print_banner()

    rules_dir = _project_root() / "r2inspect" / "rules" / "yara"
    display_base.handle_list_yara_option(None, str(rules_dir))

    display_base.display_yara_rules_table(
        [{"name": "a.yar", "size": 2048, "path": "/tmp/a.yar", "relative_path": "a.yar"}],
        "/tmp",
    )

    display_base.display_error_statistics(
        {
            "total_errors": 2,
            "recent_errors": 1,
            "recovery_strategies_available": 1,
            "errors_by_category": {"input_validation": 1},
            "errors_by_severity": {"critical": 1, "high": 1, "low": 1},
        }
    )

    display_base.display_performance_statistics(
        {
            "total_retries": 2,
            "successful_retries": 1,
            "failed_after_retries": 1,
            "success_rate": 50.0,
            "commands_retried": {"aa": 2},
        },
        {"open": 1, "half_open": 0, "closed": 0},
    )

    display_validation_errors(["err1", "err2"])


def test_display_sections_branches() -> None:
    ds._display_retry_statistics(
        {
            "total_retries": 2,
            "successful_retries": 1,
            "failed_after_retries": 1,
            "success_rate": 50.0,
            "commands_retried": {"cmd": 2},
        }
    )
    ds._display_circuit_breaker_statistics({"open": 2, "closed": 0})

    ds._display_file_info(
        {
            "__present__": {"file_info"},
            "file_info": {
                "size": 123,
                "path": "file.bin",
                "name": "file.bin",
                "mime_type": "application/octet-stream",
                "file_type": "data",
                "md5": "md5",
                "sha1": "sha1",
                "sha256": "sha256",
                "sha512": "sha512",
                "threat_level": "Low",
                "enhanced_detection": {
                    "file_format": "PE32",
                    "format_category": "Executable",
                    "architecture": "x86-64",
                    "bits": 64,
                    "endianness": "Little",
                    "confidence": 0.95,
                },
            },
        }
    )

    ds._display_pe_info(
        {"__present__": {"pe_info"}, "pe_info": {"type": "EXE", "list": ["a"], "dict": {"x": 1}}}
    )
    ds._display_security({"__present__": {"security"}, "security": {"aslr": True, "dep": False}})

    ds._display_ssdeep(
        {
            "__present__": {"ssdeep"},
            "ssdeep": {"available": True, "hash_value": "abc", "method_used": "py"},
        }
    )
    ds._display_ssdeep({"__present__": {"ssdeep"}, "ssdeep": {"available": False, "error": "boom"}})

    ds._display_tlsh(
        {
            "__present__": {"tlsh"},
            "tlsh": {
                "available": True,
                "binary_tlsh": "b",
                "text_section_tlsh": None,
                "stats": {"functions_analyzed": 2, "functions_with_tlsh": 1},
            },
        }
    )
    ds._display_tlsh({"__present__": {"tlsh"}, "tlsh": {"available": False, "error": "no"}})

    ds._display_telfhash(
        {
            "__present__": {"telfhash"},
            "telfhash": {
                "available": True,
                "is_elf": True,
                "telfhash": "hash",
                "symbol_count": 2,
                "filtered_symbols": 1,
                "symbols_used": ["a", "b", "c", "d", "e", "f"],
            },
        }
    )
    ds._display_telfhash(
        {"__present__": {"telfhash"}, "telfhash": {"available": True, "is_elf": False}}
    )
    ds._display_telfhash(
        {"__present__": {"telfhash"}, "telfhash": {"available": False, "error": "no"}}
    )

    ds._display_rich_header(
        {
            "__present__": {"rich_header"},
            "rich_header": {
                "available": True,
                "is_pe": True,
                "xor_key": 1,
                "checksum": 2,
                "richpe_hash": "hash",
                "compilers": [{"compiler_name": "a", "count": 1, "build_number": 1}] * 6,
            },
        }
    )
    ds._display_rich_header(
        {"__present__": {"rich_header"}, "rich_header": {"available": True, "is_pe": False}}
    )
    ds._display_rich_header(
        {"__present__": {"rich_header"}, "rich_header": {"available": False, "error": "no"}}
    )

    ds._display_impfuzzy(
        {
            "__present__": {"impfuzzy"},
            "impfuzzy": {
                "available": True,
                "impfuzzy_hash": "hash",
                "import_count": 2,
                "dll_count": 1,
                "imports_processed": ["a", "b", "c"],
            },
        }
    )
    ds._display_impfuzzy(
        {
            "__present__": {"impfuzzy"},
            "impfuzzy": {"available": False, "error": "no", "library_available": False},
        }
    )

    ds._display_ccbhash(
        {
            "__present__": {"ccbhash"},
            "ccbhash": {
                "available": True,
                "binary_ccbhash": "h" * 70,
                "total_functions": 3,
                "analyzed_functions": 2,
                "unique_hashes": 1,
                "similar_functions": [
                    {
                        "count": 2,
                        "functions": ["f&amp;1", "f&nbsp;2", "f3", "f4"],
                    }
                ],
            },
        }
    )
    ds._display_ccbhash(
        {"__present__": {"ccbhash"}, "ccbhash": {"available": False, "error": "no"}}
    )

    ds._display_binlex(
        {
            "__present__": {"binlex"},
            "binlex": {
                "available": True,
                "total_functions": 2,
                "analyzed_functions": 2,
                "ngram_sizes": [2, 3],
                "unique_signatures": {2: 1, 3: 2},
                "similar_functions": {2: [{"count": 2}], 3: []},
                "binary_signature": {2: "hash"},
                "top_ngrams": {2: [("a&nbsp;bc", 3)]},
            },
        }
    )
    ds._display_binlex({"__present__": {"binlex"}, "binlex": {"available": False, "error": "no"}})

    ds._display_binbloom(
        {
            "__present__": {"binbloom"},
            "binbloom": {
                "available": True,
                "total_functions": 2,
                "analyzed_functions": 2,
                "capacity": 10,
                "error_rate": 0.01,
                "unique_signatures": 2,
                "function_signatures": {
                    "f1": {"instruction_count": 2, "unique_instructions": 1, "signature": "sig1"},
                    "f2": {"instruction_count": 3, "unique_instructions": 2, "signature": "sig2"},
                },
                "similar_functions": [
                    {
                        "count": 2,
                        "signature": "sig",
                        "functions": ["f1", "f2", "f3", "f4", "f5", "f6"],
                    }
                ],
                "binary_signature": "sig",
                "bloom_stats": {"average_fill_rate": 0.5, "total_filters": 1},
            },
        }
    )
    ds._display_binbloom(
        {
            "__present__": {"binbloom"},
            "binbloom": {"available": False, "error": "no", "library_available": False},
        }
    )

    ds._display_simhash(
        {
            "__present__": {"simhash"},
            "simhash": {
                "available": True,
                "feature_stats": {
                    "total_features": 10,
                    "total_strings": 9,
                    "total_opcodes": 1,
                    "feature_diversity": 0.5,
                    "most_common_features": [("STR:abc", 2), ("OP:xyz", 1)],
                },
                "combined_simhash": {"hex": "a" * 40, "feature_count": 10},
                "strings_simhash": {"hex": "b" * 16},
                "opcodes_simhash": {"hex": "c" * 16},
                "function_simhashes": {"f1": "h"},
                "total_functions": 2,
                "analyzed_functions": 2,
                "similarity_groups": [
                    {"count": 2, "representative_hash": "h" * 30, "functions": ["f1", "f2"]}
                ],
            },
        }
    )
    ds._display_simhash(
        {
            "__present__": {"simhash"},
            "simhash": {"available": False, "error": "no", "library_available": False},
        }
    )

    ds._display_bindiff(
        {
            "__present__": {"bindiff"},
            "bindiff": {
                "comparison_ready": True,
                "filename": "file",
                "structural_features": {
                    "file_type": "PE",
                    "file_size": 10,
                    "section_count": 2,
                    "section_names": [".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc"],
                    "import_count": 1,
                    "export_count": 0,
                },
                "function_features": {"function_count": 2, "cfg_features": {"f": {}}},
                "string_features": {"total_strings": 1, "categorized_strings": {"api": []}},
                "signatures": {"structural": "s", "function": "f", "string": "N/A"},
            },
        }
    )
    ds._display_bindiff(
        {"__present__": {"bindiff"}, "bindiff": {"comparison_ready": False, "error": "no"}}
    )

    ds._display_machoc_functions(
        {
            "__present__": {"functions"},
            "functions": {"total_functions": 2, "machoc_hashes": {"f1": "h", "f2": "h"}},
        }
    )

    ds._display_indicators(
        {
            "__present__": {"indicators"},
            "indicators": [{"type": "Anti-VM", "description": "test", "severity": "High"}],
        }
    )
