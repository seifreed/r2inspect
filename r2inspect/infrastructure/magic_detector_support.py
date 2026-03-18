#!/usr/bin/env python3
"""Support helpers for magic-byte detection."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, BinaryIO


def read_at_offset(file_handle: BinaryIO, offset: int, size: int) -> bytes:
    position = file_handle.tell()
    file_handle.seek(offset)
    data = file_handle.read(size)
    file_handle.seek(position)
    return data


def validate_pe_format(header: bytes, file_handle: BinaryIO, logger: Any) -> float:
    try:
        if len(header) < 64 or header[:2] != b"MZ":
            return 0.0
        pe_offset = struct.unpack("<I", header[60:64])[0]
        pe_sig = read_at_offset(file_handle, pe_offset, 4)
        return 0.95 if pe_sig == b"PE\0\0" else 0.0
    except Exception as exc:
        logger.debug("PE validation failed: %s", exc)
        return 0.3


def validate_docx_format(file_handle: BinaryIO, logger: Any) -> float:
    try:
        file_handle.seek(0)
        payload = file_handle.read(4096)
        if not payload.startswith(b"PK"):
            return 0.0
        office_indicators = (
            b"word/",
            b"xl/",
            b"ppt/",
            b"[Content_Types].xml",
        )
        matches = sum(1 for marker in office_indicators if marker in payload)
        if matches >= 2:
            return 0.9
        if matches == 1:
            return 0.6
        return 0.1
    except Exception as exc:
        logger.debug("DOCX validation failed: %s", exc)
        return 0.0


def analyze_elf_details(header: bytes) -> dict[str, Any]:
    unknown = {"architecture": "Unknown", "bits": "Unknown", "endianness": "Unknown"}
    if len(header) < 8:
        return unknown
    ei_class = header[4]
    ei_data = header[5]
    bits: int | str = 64 if ei_class == 2 else 32 if ei_class == 1 else "Unknown"
    endianness = "Little" if ei_data == 1 else "Big" if ei_data == 2 else "Unknown"
    if len(header) < 20:
        return {"architecture": "Unknown", "bits": bits, "endianness": endianness}
    machine_bytes = header[18:20]
    machine = (
        struct.unpack("<H", machine_bytes)[0]
        if ei_data == 1
        else struct.unpack(">H", machine_bytes)[0] if ei_data == 2 else None
    )
    arch_map = {
        0x03: "x86",
        0x3E: "x86-64",
        0x14: "PowerPC",
        0xB7: "AArch64",
        0x28: "ARM",
    }
    return {
        "architecture": arch_map.get(machine, hex(machine)) if machine is not None else "Unknown",
        "bits": bits,
        "endianness": endianness,
    }


def analyze_macho_details(header: bytes) -> dict[str, Any]:
    unknown = {
        "architecture": "Unknown",
        "bits": "Unknown",
        "endianness": "Unknown",
    }
    if len(header) < 8:
        return unknown

    raw = header[:4]
    magic_le = struct.unpack("<I", raw)[0]
    little_map = {
        0xCEFAEDFE: (32, "Little"),
        0xCFFAEDFE: (64, "Little"),
        0xBEBAFECA: ("Universal", "Little"),
    }
    big_map = {
        0xFEEDFACE: (32, "Big"),
        0xFEEDFACF: (64, "Big"),
        0xCAFEBABE: ("Universal", "Big"),
    }
    if magic_le in little_map:
        bits, endianness = little_map[magic_le]
        cpu = struct.unpack("<I", header[4:8])[0]
    elif magic_le in big_map:
        bits, endianness = big_map[magic_le]
        cpu = struct.unpack(">I", header[4:8])[0]
    else:
        return unknown

    arch_map = {
        7: "x86",
        0x01000007: "x86-64",
        12: "ARM",
        0x0100000C: "AArch64",
        18: "PowerPC",
        0x01000012: "PowerPC64",
    }
    return {
        "architecture": arch_map.get(cpu, "Unknown"),
        "bits": bits,
        "endianness": endianness,
    }


def analyze_pe_details(header: bytes, file_handle: BinaryIO, logger: Any) -> dict[str, Any]:
    unknown = {
        "architecture": "Unknown",
        "bits": "Unknown",
        "endianness": "Unknown",
    }
    try:
        if len(header) < 64:
            return unknown
        pe_offset = struct.unpack("<I", header[60:64])[0]
        pe_data = read_at_offset(file_handle, pe_offset, 24)
        if len(pe_data) < 24 or pe_data[:4] != b"PE\0\0":
            return unknown
        machine = struct.unpack("<H", pe_data[4:6])[0]
        arch_map = {
            0x014C: ("x86", 32),
            0x8664: ("x86-64", 64),
            0x01C0: ("ARM", 32),
            0xAA64: ("AArch64", 64),
            0x0200: ("Intel Itanium", 64),
        }
        architecture, bits = arch_map.get(machine, ("Unknown", "Unknown"))
        return {"architecture": architecture, "bits": bits, "endianness": "Little"}
    except Exception as exc:
        logger.debug("PE detail analysis failed: %s", exc)
        return unknown


def fallback_detection(header: bytes, file_path: Path) -> dict[str, Any]:
    suffix = file_path.suffix.lower()
    if suffix in {".exe", ".dll"}:
        return {
            "file_format": "PE32",
            "format_category": "Executable",
            "is_executable": True,
            "potential_threat": True,
        }
    if suffix in {".elf", ".so"} or header[:4] == b"\x7fELF":
        return {
            "file_format": "ELF",
            "format_category": "Executable",
            "is_executable": True,
            "potential_threat": True,
        }
    if suffix in {".zip", ".jar"}:
        return {
            "file_format": "ZIP",
            "format_category": "Archive",
            "is_archive": True,
            "potential_threat": header.startswith(b"MZ"),
        }
    if suffix in {".pdf", ".doc", ".docx", ".rtf"}:
        return {
            "file_format": suffix[1:].upper(),
            "format_category": "Document",
            "is_document": True,
            "potential_threat": True,
        }
    if header.startswith(b"#!") or suffix in {".ps1", ".sh", ".bat"}:
        return {
            "file_format": "SCRIPT",
            "format_category": "Script",
            "potential_threat": True,
        }
    if header.startswith(b"MZ"):
        return {"potential_threat": True}
    return {"file_format": "Unknown", "format_category": "Unknown"}
