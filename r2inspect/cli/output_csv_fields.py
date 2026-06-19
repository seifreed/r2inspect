#!/usr/bin/env python3
"""Shared extraction helpers for CSV output."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def escape_csv_formula(value: Any) -> Any:
    """Neutralize spreadsheet formula injection (CWE-1236).

    Filenames, section/import names and YARA rule names are attacker-controlled
    and flow verbatim into CSV cells; a leading ``= + - @`` would be evaluated as
    a formula when the report is opened in a spreadsheet. Prefix such cells with
    a single quote so they are treated as literal text.
    """
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


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
    file_info = data.get("file_info")
    if file_info is None:
        file_info = {}
    elif not isinstance(file_info, dict):
        raise TypeError("file_info must be a dict or None")
    csv_row["name"] = file_info.get("name", "")
    csv_row["size"] = formatter._format_file_size(file_info.get("size", 0))
    csv_row["file_type"] = formatter._clean_file_type(file_info.get("file_type", ""))
    csv_row["md5"] = file_info.get("md5", "")
    csv_row["sha1"] = file_info.get("sha1", "")
    csv_row["sha256"] = file_info.get("sha256", "")
    csv_row["sha512"] = file_info.get("sha512", "")


def extract_compile_time(data: dict[str, Any]) -> str:
    for key in ("pe_info", "elf_info", "macho_info", "file_info"):
        section = _as_dict(data.get(key))
        if "compile_time" in section:
            value = section["compile_time"]
            return str(value) if value else ""
    return ""


def extract_imphash(data: dict[str, Any]) -> str:
    return str(_as_dict(data.get("pe_info")).get("imphash", "") or "")


def add_ssdeep(csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    csv_row["ssdeep_hash"] = _as_dict(data.get("ssdeep")).get("hash_value", "")


def add_tlsh(csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    tlsh_info = _as_dict(data.get("tlsh"))
    csv_row["tlsh_binary"] = tlsh_info.get("binary_tlsh", "")
    csv_row["tlsh_text_section"] = tlsh_info.get("text_section_tlsh", "")
    csv_row["tlsh_functions_with_hash"] = _as_dict(tlsh_info.get("stats")).get(
        "functions_with_tlsh", 0
    )


def add_telfhash(csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    telfhash_info = _as_dict(data.get("telfhash"))
    csv_row["telfhash"] = telfhash_info.get("telfhash", "")
    csv_row["telfhash_symbols_used"] = telfhash_info.get("filtered_symbols", 0)


def format_rich_header_compilers(rich_header_info: dict[str, Any]) -> str:
    compilers_list = []
    compilers = rich_header_info.get("compilers", [])
    if isinstance(compilers, list):
        compiler_source = compilers
    elif isinstance(compilers, (dict, str, bytes)) or not isinstance(compilers, Iterable):
        compiler_source = []
    else:
        compiler_source = list(compilers)
    for compiler in compiler_source:
        if isinstance(compiler, dict):
            compiler_name = compiler.get("compiler_name", "")
            count = compiler.get("count", 0)
            if compiler_name:
                compilers_list.append(f"{compiler_name}({count})")
    return ", ".join(compilers_list)


def add_rich_header(formatter: Any, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    rich = _as_dict(data.get("rich_header"))
    csv_row["rich_header_xor_key"] = hex(rich.get("xor_key", 0)) if rich.get("xor_key") else ""
    csv_row["rich_header_checksum"] = hex(rich.get("checksum", 0)) if rich.get("checksum") else ""
    csv_row["richpe_hash"] = rich.get("richpe_hash", "")
    csv_row["rich_header_compilers"] = formatter._format_rich_header_compilers(rich)
    compilers = rich.get("compilers", [])
    if isinstance(compilers, list):
        csv_row["rich_header_entries"] = len(compilers)
    elif isinstance(compilers, (dict, str, bytes)) or not isinstance(compilers, Iterable):
        csv_row["rich_header_entries"] = 0
    else:
        csv_row["rich_header_entries"] = len(list(compilers))


def add_imports_exports_sections(
    formatter: Any, csv_row: dict[str, Any], data: dict[str, Any]
) -> None:
    csv_row["imports"] = formatter._extract_names_from_list(data, "imports")
    csv_row["exports"] = formatter._extract_names_from_list(data, "exports")
    csv_row["sections"] = formatter._extract_names_from_list(data, "sections")


def add_anti_analysis(csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    anti_analysis = _as_dict(data.get("anti_analysis"))
    csv_row["anti_debug"] = anti_analysis.get("anti_debug", False)
    csv_row["anti_vm"] = anti_analysis.get("anti_vm", False)
    csv_row["anti_sandbox"] = anti_analysis.get("anti_sandbox", False)


def add_compiler_info(csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    compiler_info = _as_dict(data.get("compiler"))
    csv_row["compiler"] = compiler_info.get("compiler", "Unknown")
    csv_row["compiler_version"] = compiler_info.get("version", "Unknown")
    csv_row["compiler_confidence"] = compiler_info.get("confidence", 0.0)


def add_function_info(formatter: Any, csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    functions_info = _as_dict(data.get("functions"))
    csv_row["num_functions"] = functions_info.get("total_functions", 0)
    machoc_hashes = _as_dict(functions_info.get("machoc_hashes"))
    csv_row["num_unique_machoc"] = (
        len({value for value in machoc_hashes.values() if isinstance(value, str) and value})
        if machoc_hashes
        else 0
    )
    csv_row["num_duplicate_functions"] = formatter._count_duplicate_machoc(machoc_hashes)


def add_counts(csv_row: dict[str, Any], data: dict[str, Any]) -> None:
    imports = data.get("imports", [])
    exports = data.get("exports", [])
    sections = data.get("sections", [])
    csv_row["num_imports"] = len(imports) if isinstance(imports, list) else len(list(imports)) if isinstance(imports, Iterable) and not isinstance(imports, (dict, str, bytes)) else 0
    csv_row["num_exports"] = len(exports) if isinstance(exports, list) else len(list(exports)) if isinstance(exports, Iterable) and not isinstance(exports, (dict, str, bytes)) else 0
    csv_row["num_sections"] = len(sections) if isinstance(sections, list) else len(list(sections)) if isinstance(sections, Iterable) and not isinstance(sections, (dict, str, bytes)) else 0
    csv_row["ssdeep_available"] = bool(_as_dict(data.get("ssdeep")).get("available"))
    csv_row["tlsh_available"] = bool(_as_dict(data.get("tlsh")).get("available"))
    csv_row["telfhash_available"] = bool(_as_dict(data.get("telfhash")).get("available"))
    csv_row["rich_header_available"] = bool(_as_dict(data.get("rich_header")).get("available"))
