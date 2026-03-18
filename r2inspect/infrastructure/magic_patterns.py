#!/usr/bin/env python3
"""Magic byte patterns for file type detection."""

from typing import Any

MAGIC_PATTERNS: dict[str, dict[str, Any]] = {
    "PE32": {
        "signatures": [(0, b"MZ")],
        "pe_check": True,
        "description": "Windows PE32 Executable",
        "extensions": [".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv"],
    },
    "ELF32": {
        "signatures": [(0, b"\x7fELF\x01")],
        "description": "Linux ELF 32-bit Executable",
        "extensions": [".so", ".o", ".ko"],
    },
    "ELF64": {
        "signatures": [(0, b"\x7fELF\x02")],
        "description": "Linux ELF 64-bit Executable",
        "extensions": [".so", ".o", ".ko"],
    },
    "MACHO32": {
        "signatures": [(0, b"\xfe\xed\xfa\xce"), (0, b"\xce\xfa\xed\xfe")],
        "description": "macOS Mach-O 32-bit Executable",
        "extensions": [".dylib", ".bundle", ".o"],
    },
    "MACHO64": {
        "signatures": [(0, b"\xfe\xed\xfa\xcf"), (0, b"\xcf\xfa\xed\xfe")],
        "description": "macOS Mach-O 64-bit Executable",
        "extensions": [".dylib", ".bundle", ".o"],
    },
    "MACHO_UNIVERSAL": {
        "signatures": [(0, b"\xca\xfe\xba\xbe"), (0, b"\xbe\xba\xfe\xca")],
        "description": "macOS Universal Binary",
        "extensions": [],
    },
    "ZIP": {
        "signatures": [(0, b"PK\x03\x04"), (0, b"PK\x05\x06"), (0, b"PK\x07\x08")],
        "description": "ZIP Archive (may contain executables)",
        "extensions": [".zip", ".jar", ".war", ".ear", ".apk", ".ipa"],
    },
    "RAR": {
        "signatures": [(0, b"Rar!\x1a\x07\x00"), (0, b"Rar!\x1a\x07\x01\x00")],
        "description": "RAR Archive",
        "extensions": [".rar"],
    },
    "7ZIP": {
        "signatures": [(0, b"7z\xbc\xaf\x27\x1c")],
        "description": "7-Zip Archive",
        "extensions": [".7z"],
    },
    "PDF": {
        "signatures": [(0, b"%PDF-")],
        "description": "PDF Document (may contain embedded executables)",
        "extensions": [".pdf"],
    },
    "RTF": {
        "signatures": [(0, b"{\\rtf")],
        "description": "Rich Text Format Document",
        "extensions": [".rtf"],
    },
    "DOC": {
        "signatures": [(0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")],
        "description": "Microsoft Office Document (OLE format)",
        "extensions": [".doc", ".xls", ".ppt", ".msi"],
    },
    "DOCX": {
        "signatures": [(0, b"PK\x03\x04")],
        "docx_check": True,
        "description": "Microsoft Office Open XML Document",
        "extensions": [".docx", ".xlsx", ".pptx"],
    },
    "UPX": {
        "signatures": [(0, b"UPX!")],
        "description": "UPX Packed Executable",
        "extensions": [],
    },
    "NSIS": {
        "signatures": [(4, b"\xef\xbe\xad\xde")],
        "description": "NSIS Installer",
        "extensions": [".exe"],
    },
    "JAVA_CLASS": {
        "signatures": [(0, b"\xca\xfe\xba\xbe")],
        "description": "Java Class File",
        "extensions": [".class"],
    },
    "DEX": {
        "signatures": [(0, b"dex\n")],
        "description": "Android DEX File",
        "extensions": [".dex"],
    },
    "SWF": {
        "signatures": [(0, b"FWS"), (0, b"CWS"), (0, b"ZWS")],
        "description": "Adobe Flash SWF File",
        "extensions": [".swf"],
    },
}

__all__ = ["MAGIC_PATTERNS"]
