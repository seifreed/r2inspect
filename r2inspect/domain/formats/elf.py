#!/usr/bin/env python3
"""ELF parsing helpers."""

from __future__ import annotations

import re
from typing import Any


def parse_comment_compiler_info(comment_data: str) -> dict[str, Any]:
    info: dict[str, Any] = {}
    compiler_match = re.search(r"GCC:\s*\(([^)]+)\)\s*([0-9.]+)", comment_data)
    if compiler_match:
        info["compiler"] = f"GCC {compiler_match.group(2)}"
        info["compiler_version"] = compiler_match.group(2)
        info["build_environment"] = compiler_match.group(1)
    clang_match = re.search(r"clang\s+version\s+([0-9.]+)", comment_data)
    if clang_match:
        info["compiler"] = f"Clang {clang_match.group(1)}"
        info["compiler_version"] = clang_match.group(1)
    return info


def parse_dwarf_info(dwarf_lines: list[str]) -> dict[str, Any]:
    info: dict[str, Any] = {}
    for line in dwarf_lines:
        producer = parse_dwarf_producer(line)
        if producer:
            info.update(producer)
        compile_time = parse_dwarf_compile_time(line)
        if compile_time:
            info["compile_time"] = compile_time
    return info


def parse_dwarf_producer(line: str) -> dict[str, Any] | None:
    if "DW_AT_producer" not in line:
        return None
    producer_match = re.search(r"DW_AT_producer\s*:\s*(.+)", line)
    if not producer_match:
        return None
    producer = producer_match.group(1).strip()
    info: dict[str, Any] = {"dwarf_producer": producer}
    if "GNU C" in producer:
        gcc_match = re.search(r"GNU C\D*([0-9.]+)", producer)
        if gcc_match:
            info["compiler"] = f"GCC {gcc_match.group(1)}"
            info["compiler_version"] = gcc_match.group(1)
    elif "clang" in producer.lower():
        clang_match = re.search(r"clang\D*([0-9.]+)", producer)
        if clang_match:
            info["compiler"] = f"Clang {clang_match.group(1)}"
            info["compiler_version"] = clang_match.group(1)
    return info


def parse_dwarf_compile_time(line: str) -> str | None:
    if "DW_AT_comp_dir" not in line and "compilation" not in line.lower():
        return None
    date_match = re.search(r"(\d{4}-\d{2}-\d{2})", line)
    if not date_match:
        date_match = re.search(
            r"(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})",
            line,
        )
    return date_match.group(1) if date_match else None


def parse_build_id_data(build_id_data: str | None) -> str | None:
    if not build_id_data:
        return None
    for line in build_id_data.split("\n"):
        if not line.strip():
            continue
        hex_match = re.findall(r"([0-9a-fA-F]{2})", line)
        if len(hex_match) > 4:
            return "".join(hex_match[4:])
    return None


def find_section_by_name(sections: list[dict[str, Any]], name_substr: str) -> dict[str, Any] | None:
    target = name_substr.lower()
    for section in sections or []:
        name = section.get("name", "")
        if target in str(name).lower():
            return section
    return None


def build_section_read_commands(section: dict[str, Any], cmd: str) -> tuple[str, str] | None:
    vaddr = section.get("vaddr", 0)
    size = section.get("size", 0)
    if not vaddr or not size:
        return None
    return f"s {vaddr}", f"{cmd} {size}"
