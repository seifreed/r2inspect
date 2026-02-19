"""Comprehensive tests for r2inspect/utils/output_csv.py (15% coverage)"""

from __future__ import annotations

from typing import Any

import pytest

from r2inspect.utils.output_csv import CsvOutputFormatter


def test_csv_formatter_basic():
    results = {
        "file_info": {
            "name": "test.exe",
            "size": 1024,
            "file_type": "PE32",
            "md5": "abc123",
            "sha1": "def456",
            "sha256": "ghi789",
            "sha512": "jkl012",
        }
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "test.exe" in csv_output
    assert "abc123" in csv_output


def test_csv_formatter_with_pe_info():
    results = {
        "file_info": {"name": "test.exe", "size": 1024, "file_type": "PE32"},
        "pe_info": {
            "compile_time": "2024-01-01 12:00:00",
            "imphash": "imphash123",
        },
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "2024-01-01 12:00:00" in csv_output
    assert "imphash123" in csv_output


def test_csv_formatter_with_ssdeep():
    results = {
        "file_info": {"name": "test.exe"},
        "ssdeep": {"hash_value": "ssdeep_hash_value"},
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "ssdeep_hash_value" in csv_output


def test_csv_formatter_with_tlsh():
    results = {
        "file_info": {"name": "test.exe"},
        "tlsh": {
            "binary_tlsh": "tlsh_binary_hash",
            "text_section_tlsh": "tlsh_text_hash",
            "stats": {"functions_with_tlsh": 42},
        },
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "tlsh_binary_hash" in csv_output
    assert "tlsh_text_hash" in csv_output
    assert "42" in csv_output


def test_csv_formatter_with_telfhash():
    results = {
        "file_info": {"name": "test.elf"},
        "telfhash": {"telfhash": "telfhash_value", "filtered_symbols": 100},
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "telfhash_value" in csv_output
    assert "100" in csv_output


def test_csv_formatter_with_rich_header():
    results = {
        "file_info": {"name": "test.exe"},
        "rich_header": {
            "xor_key": 0x12345678,
            "checksum": 0xABCDEF00,
            "richpe_hash": "richpe123",
            "compilers": [
                {"compiler_name": "MSVC 19.0", "count": 5},
                {"compiler_name": "MSVC 18.0", "count": 3},
            ],
        },
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "0x12345678" in csv_output
    assert "0xabcdef00" in csv_output
    assert "richpe123" in csv_output
    assert "MSVC 19.0(5)" in csv_output
    assert "MSVC 18.0(3)" in csv_output


def test_csv_formatter_with_imports_exports_sections():
    results = {
        "file_info": {"name": "test.exe"},
        "imports": [{"name": "CreateFileA"}, {"name": "ReadFile"}],
        "exports": [{"name": "ExportFunc1"}, {"name": "ExportFunc2"}],
        "sections": [{"name": ".text"}, {"name": ".data"}],
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "CreateFileA" in csv_output
    assert "ReadFile" in csv_output
    assert "ExportFunc1" in csv_output
    assert ".text" in csv_output


def test_csv_formatter_with_anti_analysis():
    results = {
        "file_info": {"name": "test.exe"},
        "anti_analysis": {
            "anti_debug": True,
            "anti_vm": False,
            "anti_sandbox": True,
        },
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "True" in csv_output
    assert "False" in csv_output


def test_csv_formatter_with_yara_matches():
    results = {
        "file_info": {"name": "test.exe"},
        "yara_matches": [
            {"rule": "MalwareRule1"},
            {"rule": "MalwareRule2"},
        ],
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "MalwareRule1" in csv_output
    assert "MalwareRule2" in csv_output


def test_csv_formatter_with_compiler_info():
    results = {
        "file_info": {"name": "test.exe"},
        "compiler": {
            "compiler": "GCC",
            "version": "9.3.0",
            "confidence": 0.95,
        },
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "GCC" in csv_output
    assert "9.3.0" in csv_output
    assert "0.95" in csv_output


def test_csv_formatter_with_functions_info():
    results = {
        "file_info": {"name": "test.exe"},
        "functions": {
            "total_functions": 150,
            "machoc_hashes": {
                "func1": "hash1",
                "func2": "hash2",
                "func3": "hash1",
                "func4": "hash1",
            },
        },
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "150" in csv_output


def test_csv_formatter_format_file_size():
    formatter = CsvOutputFormatter({})
    
    assert formatter._format_file_size(0) == "0 B"
    assert formatter._format_file_size(512) == "512 B"
    assert formatter._format_file_size(1024) == "1.0 KB"
    assert formatter._format_file_size(1024 * 1024) == "1.0 MB"
    assert formatter._format_file_size(1024 * 1024 * 1024) == "1.0 GB"
    assert formatter._format_file_size(1024 * 1024 * 1024 * 1024) == "1.0 TB"


def test_csv_formatter_format_file_size_edge_cases():
    formatter = CsvOutputFormatter({})
    
    assert formatter._format_file_size(1023) == "1023 B"
    assert formatter._format_file_size(1536) == "1.5 KB"
    assert formatter._format_file_size("invalid") == "invalid"


def test_csv_formatter_clean_file_type():
    formatter = CsvOutputFormatter({})
    
    assert formatter._clean_file_type("PE32, 5 sections") == "PE32"
    assert formatter._clean_file_type("ELF64, 10 sections") == "ELF64"
    assert formatter._clean_file_type("PE32") == "PE32"


def test_csv_formatter_extract_names_from_list():
    formatter = CsvOutputFormatter({})
    data = {"items": [{"name": "item1"}, {"name": "item2"}]}
    
    result = formatter._extract_names_from_list(data, "items")
    assert result == "item1, item2"


def test_csv_formatter_extract_names_custom_separator():
    formatter = CsvOutputFormatter({})
    data = {"items": [{"name": "item1"}, {"name": "item2"}]}
    
    result = formatter._extract_names_from_list(data, "items", separator="; ")
    assert result == "item1; item2"


def test_csv_formatter_extract_names_custom_field():
    formatter = CsvOutputFormatter({})
    data = {"items": [{"id": "id1"}, {"id": "id2"}]}
    
    result = formatter._extract_names_from_list(data, "items", name_field="id")
    assert result == "id1, id2"


def test_csv_formatter_extract_names_not_list():
    formatter = CsvOutputFormatter({})
    data = {"items": "not a list"}
    
    result = formatter._extract_names_from_list(data, "items")
    assert result == ""


def test_csv_formatter_extract_names_string_items():
    formatter = CsvOutputFormatter({})
    data = {"items": ["string1", "string2"]}
    
    result = formatter._extract_names_from_list(data, "items")
    assert result == "string1, string2"


def test_csv_formatter_count_duplicate_machoc():
    formatter = CsvOutputFormatter({})
    
    machoc = {"f1": "h1", "f2": "h2", "f3": "h1", "f4": "h1", "f5": "h2"}
    result = formatter._count_duplicate_machoc(machoc)
    assert result == 3


def test_csv_formatter_count_duplicate_machoc_empty():
    formatter = CsvOutputFormatter({})
    
    result = formatter._count_duplicate_machoc({})
    assert result == 0


def test_csv_formatter_count_duplicate_machoc_no_duplicates():
    formatter = CsvOutputFormatter({})
    
    machoc = {"f1": "h1", "f2": "h2", "f3": "h3"}
    result = formatter._count_duplicate_machoc(machoc)
    assert result == 0


def test_csv_formatter_compile_time_from_elf_info():
    results = {
        "file_info": {"name": "test.elf"},
        "elf_info": {"compile_time": "2024-02-01 10:00:00"},
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "2024-02-01 10:00:00" in csv_output


def test_csv_formatter_compile_time_from_macho_info():
    results = {
        "file_info": {"name": "test.macho"},
        "macho_info": {"compile_time": "2024-03-01 11:00:00"},
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "2024-03-01 11:00:00" in csv_output


def test_csv_formatter_compile_time_from_file_info():
    results = {
        "file_info": {
            "name": "test.bin",
            "compile_time": "2024-04-01 12:00:00",
        },
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "2024-04-01 12:00:00" in csv_output


def test_csv_formatter_empty_results():
    results = {}
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "name" in csv_output
    assert "md5" in csv_output


def test_csv_formatter_error_handling():
    results = None
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "Error" in csv_output or "CSV Export Failed" in csv_output


def test_csv_formatter_rich_header_no_compilers():
    results = {
        "file_info": {"name": "test.exe"},
        "rich_header": {
            "xor_key": 0x12345678,
            "compilers": [],
        },
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "0x12345678" in csv_output


def test_csv_formatter_rich_header_no_xor_key():
    results = {
        "file_info": {"name": "test.exe"},
        "rich_header": {
            "compilers": [{"compiler_name": "MSVC", "count": 1}],
        },
    }
    
    formatter = CsvOutputFormatter(results)
    csv_output = formatter.to_csv()
    
    assert "MSVC(1)" in csv_output


def test_csv_formatter_all_counts():
    results = {
        "file_info": {"name": "test.exe"},
        "imports": [{"name": "func1"}, {"name": "func2"}, {"name": "func3"}],
        "exports": [{"name": "exp1"}, {"name": "exp2"}],
        "sections": [{"name": ".text"}],
    }
    
    formatter = CsvOutputFormatter(results)
    csv_data = formatter._extract_csv_data(results)
    
    assert csv_data["num_imports"] == 3
    assert csv_data["num_exports"] == 2
    assert csv_data["num_sections"] == 1


def test_csv_formatter_counts_not_lists():
    results = {
        "file_info": {"name": "test.exe"},
        "imports": "not a list",
        "exports": None,
        "sections": 123,
    }
    
    formatter = CsvOutputFormatter(results)
    csv_data = formatter._extract_csv_data(results)
    
    assert csv_data["num_imports"] == 0
    assert csv_data["num_exports"] == 0
    assert csv_data["num_sections"] == 0


def test_csv_formatter_file_size_edge():
    results = {
        "file_info": {
            "name": "test.exe",
            "size": 1536,
        },
    }
    
    formatter = CsvOutputFormatter(results)
    csv_data = formatter._extract_csv_data(results)
    
    assert "1.5 KB" in csv_data["size"]


def test_csv_formatter_clean_file_type_sections():
    results = {
        "file_info": {
            "name": "test.exe",
            "file_type": "PE32 executable, 10 sections",
        },
    }
    
    formatter = CsvOutputFormatter(results)
    csv_data = formatter._extract_csv_data(results)
    
    assert "sections" not in csv_data["file_type"].lower() or csv_data["file_type"] == "PE32 executable"


def test_csv_formatter_extract_compile_time_empty():
    results = {
        "file_info": {"name": "test.exe"},
    }
    
    formatter = CsvOutputFormatter(results)
    csv_data = formatter._extract_csv_data(results)
    
    assert csv_data["compile_time"] == ""


def test_csv_formatter_extract_imphash_empty():
    results = {
        "file_info": {"name": "test.exe"},
    }
    
    formatter = CsvOutputFormatter(results)
    csv_data = formatter._extract_csv_data(results)
    
    assert csv_data["imphash"] == ""


def test_csv_formatter_ssdeep_empty():
    results = {
        "file_info": {"name": "test.exe"},
        "ssdeep": {},
    }
    
    formatter = CsvOutputFormatter(results)
    csv_data = formatter._extract_csv_data(results)
    
    assert csv_data["ssdeep_hash"] == ""
