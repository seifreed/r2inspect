#!/usr/bin/env python3
"""Magic byte patterns for file type detection."""

from typing import Any

MAGIC_PATTERNS: dict[str, dict[str, Any]] = {
    # PE (Portable Executable) - Windows
    "PE32": {
        "signatures": [
            (0, b"MZ"),  # DOS header
            # PE signature will be checked at offset specified in DOS header + 0x3C
        ],
        "pe_check": True,
        "description": "Windows PE32 Executable",
        "extensions": [".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv"],
    },
    # ELF (Executable and Linkable Format) - Linux/Unix
    "ELF32": {
        "signatures": [
            (0, b"\x7fELF\x01"),  # ELF32
        ],
        "description": "Linux ELF 32-bit Executable",
        "extensions": [".so", ".o", ".ko"],
    },
    "ELF64": {
        "signatures": [
            (0, b"\x7fELF\x02"),  # ELF64
        ],
        "description": "Linux ELF 64-bit Executable",
        "extensions": [".so", ".o", ".ko"],
    },
    # Mach-O (Mach Object) - macOS
    "MACHO32": {
        "signatures": [
            (0, b"\xfe\xed\xfa\xce"),  # Mach-O 32-bit big-endian
            (0, b"\xce\xfa\xed\xfe"),  # Mach-O 32-bit little-endian
        ],
        "description": "macOS Mach-O 32-bit Executable",
        "extensions": [".dylib", ".bundle", ".o"],
    },
    "MACHO64": {
        "signatures": [
            (0, b"\xfe\xed\xfa\xcf"),  # Mach-O 64-bit big-endian
            (0, b"\xcf\xfa\xed\xfe"),  # Mach-O 64-bit little-endian
        ],
        "description": "macOS Mach-O 64-bit Executable",
        "extensions": [".dylib", ".bundle", ".o"],
    },
    "MACHO_UNIVERSAL": {
        "signatures": [
            (0, b"\xca\xfe\xba\xbe"),  # Universal binary big-endian
            (0, b"\xbe\xba\xfe\xca"),  # Universal binary little-endian
        ],
        "description": "macOS Universal Binary",
        "extensions": [],
    },
    # Archive formats that may contain executables
    "ZIP": {
        "signatures": [
            (0, b"PK\x03\x04"),  # ZIP file
            (0, b"PK\x05\x06"),  # Empty ZIP
            (0, b"PK\x07\x08"),  # ZIP with data descriptor
        ],
        "description": "ZIP Archive (may contain executables)",
        "extensions": [".zip", ".jar", ".war", ".ear", ".apk", ".ipa"],
    },
    "RAR": {
        "signatures": [
            (0, b"Rar!\x1a\x07\x00"),  # RAR 1.5+
            (0, b"Rar!\x1a\x07\x01\x00"),  # RAR 5.0+
        ],
        "description": "RAR Archive",
        "extensions": [".rar"],
    },
    "7ZIP": {
        "signatures": [
            (0, b"7z\xbc\xaf\x27\x1c"),  # 7-Zip
        ],
        "description": "7-Zip Archive",
        "extensions": [".7z"],
    },
    # Script formats that can be malicious
    "PDF": {
        "signatures": [
            (0, b"%PDF-"),  # PDF document
        ],
        "description": "PDF Document (may contain embedded executables)",
        "extensions": [".pdf"],
    },
    "RTF": {
        "signatures": [
            (0, b"{\\rtf"),  # RTF document
        ],
        "description": "Rich Text Format Document",
        "extensions": [".rtf"],
    },
    "DOC": {
        "signatures": [
            (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),  # OLE/COM document
        ],
        "description": "Microsoft Office Document (OLE format)",
        "extensions": [".doc", ".xls", ".ppt", ".msi"],
    },
    "DOCX": {
        "signatures": [
            (0, b"PK\x03\x04"),  # DOCX is ZIP-based
            # Additional check for specific DOCX content will be done
        ],
        "docx_check": True,
        "description": "Microsoft Office Open XML Document",
        "extensions": [".docx", ".xlsx", ".pptx"],
    },
    # Specific malware/packer signatures
    "UPX": {
        "signatures": [
            (0, b"UPX!"),  # UPX packed
        ],
        "description": "UPX Packed Executable",
        "extensions": [],
    },
    "NSIS": {
        "signatures": [
            (4, b"\xef\xbe\xad\xde"),  # NSIS installer
        ],
        "description": "NSIS Installer",
        "extensions": [".exe"],
    },
    # Java formats
    "JAVA_CLASS": {
        "signatures": [
            (0, b"\xca\xfe\xba\xbe"),  # Java class file
        ],
        "description": "Java Class File",
        "extensions": [".class"],
    },
    # Android formats
    "DEX": {
        "signatures": [
            (0, b"dex\n"),  # Android DEX file
        ],
        "description": "Android DEX File",
        "extensions": [".dex"],
    },
    # Flash/ActionScript
    "SWF": {
        "signatures": [
            (0, b"FWS"),  # Flash SWF uncompressed
            (0, b"CWS"),  # Flash SWF compressed
            (0, b"ZWS"),  # Flash SWF LZMA compressed
        ],
        "description": "Adobe Flash SWF File",
        "extensions": [".swf"],
    },
}
