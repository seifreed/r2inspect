#!/usr/bin/env python3
"""Shared extraction helpers for CSV output."""

from __future__ import annotations

from typing import Any

FIELDNAMES = [
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
    "ssdeep_available",
    "tlsh_binary",
    "tlsh_text_section",
    "tlsh_available",
    "tlsh_functions_with_hash",
    "telfhash",
    "telfhash_available",
    "telfhash_symbols_used",
    "rich_header_available",
    "rich_header_xor_key",
    "rich_header_checksum",
    "richpe_hash",
    "rich_header_compilers",
    "rich_header_entries",
    "imports",
    "exports",
    "sections",
    "anti_debug",
    "anti_vm",
    "anti_sandbox",
    "yara_matches",
    "compiler",
    "compiler_version",
    "compiler_confidence",
    "num_functions",
    "num_unique_machoc",
    "num_duplicate_functions",
    "num_imports",
    "num_exports",
    "num_sections",
]


def add_file_info(formatter: Any, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    file_info = data.get("file_info", {})
    csv_row["name"] = file_info.get("name", "")
    csv_row["size"] = formatter._format_file_size(file_info.get("size", 0))
    csv_row["file_type"] = formatter._clean_file_type(file_info.get("file_type", ""))
    csv_row["md5"] = file_info.get("md5", "")
    csv_row["sha1"] = file_info.get("sha1", "")
    csv_row["sha256"] = file_info.get("sha256", "")
    csv_row["sha512"] = file_info.get("sha512", "")


def extract_compile_time(data: dict[str, Any]) -> str:
    for key in ("pe_info", "elf_info", "macho_info", "file_info"):
        if key in data and "compile_time" in data[key]:
            value = data[key]["compile_time"]
            return str(value) if value else ""
    return ""


def extract_imphash(data: dict[str, Any]) -> str:
    return str(data.get("pe_info", {}).get("imphash", "") or "")


def add_ssdeep(csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    csv_row["ssdeep_hash"] = data.get("ssdeep", {}).get("hash_value", "")


def add_tlsh(csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    tlsh_info = data.get("tlsh", {})
    csv_row["tlsh_binary"] = tlsh_info.get("binary_tlsh", "")
    csv_row["tlsh_text_section"] = tlsh_info.get("text_section_tlsh", "")
    csv_row["tlsh_functions_with_hash"] = tlsh_info.get("stats", {}).get("functions_with_tlsh", 0)


def add_telfhash(csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    telfhash_info = data.get("telfhash", {})
    csv_row["telfhash"] = telfhash_info.get("telfhash", "")
    csv_row["telfhash_symbols_used"] = telfhash_info.get("filtered_symbols", 0)


def format_rich_header_compilers(rich_header_info: dict[str, Any]) -> str:
    compilers_list = []
    if isinstance(rich_header_info.get("compilers"), list):
        for compiler in rich_header_info["compilers"]:
            if isinstance(compiler, dict):
                compiler_name = compiler.get("compiler_name", "")
                count = compiler.get("count", 0)
                if compiler_name:
                    compilers_list.append(f"{compiler_name}({count})")
    return ", ".join(compilers_list)


def add_rich_header(formatter: Any, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    rich = data.get("rich_header", {})
    csv_row["rich_header_xor_key"] = hex(rich.get("xor_key", 0)) if rich.get("xor_key") else ""
    csv_row["rich_header_checksum"] = hex(rich.get("checksum", 0)) if rich.get("checksum") else ""
    csv_row["richpe_hash"] = rich.get("richpe_hash", "")
    csv_row["rich_header_compilers"] = formatter._format_rich_header_compilers(rich)
    csv_row["rich_header_entries"] = len(rich.get("compilers", []))


def add_imports_exports_sections(
    formatter: Any, csv_row: dict[str, Any], data: dict[str, Any]
) -> None:
    csv_row["imports"] = formatter._extract_names_from_list(data, "imports")
    csv_row["exports"] = formatter._extract_names_from_list(data, "exports")
    csv_row["sections"] = formatter._extract_names_from_list(data, "sections")


def add_anti_analysis(csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    anti_analysis = data.get("anti_analysis", {})
    csv_row["anti_debug"] = anti_analysis.get("anti_debug", False)
    csv_row["anti_vm"] = anti_analysis.get("anti_vm", False)
    csv_row["anti_sandbox"] = anti_analysis.get("anti_sandbox", False)


def add_compiler_info(csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    compiler_info = data.get("compiler", {})
    csv_row["compiler"] = compiler_info.get("compiler", "Unknown")
    csv_row["compiler_version"] = compiler_info.get("version", "Unknown")
    csv_row["compiler_confidence"] = compiler_info.get("confidence", 0.0)


def add_function_info(formatter: Any, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    functions_info = data.get("functions", {})
    csv_row["num_functions"] = functions_info.get("total_functions", 0)
    machoc_hashes = functions_info.get("machoc_hashes", {})
    csv_row["num_unique_machoc"] = len(set(machoc_hashes.values())) if machoc_hashes else 0
    csv_row["num_duplicate_functions"] = formatter._count_duplicate_machoc(machoc_hashes)


def add_counts(csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    imports = data.get("imports", [])
    exports = data.get("exports", [])
    sections = data.get("sections", [])
    csv_row["num_imports"] = len(imports) if isinstance(imports, list) else 0
    csv_row["num_exports"] = len(exports) if isinstance(exports, list) else 0
    csv_row["num_sections"] = len(sections) if isinstance(sections, list) else 0
    csv_row["ssdeep_available"] = bool(data.get("ssdeep", {}).get("available"))
    csv_row["tlsh_available"] = bool(data.get("tlsh", {}).get("available"))
    csv_row["telfhash_available"] = bool(data.get("telfhash", {}).get("available"))
    csv_row["rich_header_available"] = bool(data.get("rich_header", {}).get("available"))
