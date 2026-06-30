"""Executable header-signature predicates (PE / ELF / Mach-O / script)."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def check_executable_signature(file_path: Path) -> bool:
    """Check for executable signatures in file header (PE, ELF, Mach-O)."""
    if not file_path.is_file():
        return False
    try:
        with open(file_path, "rb") as f:
            header = f.read(64)
            if len(header) < 4:
                return False

            return (
                is_pe_executable(header, f)
                or is_elf_executable(header)
                or is_macho_executable(header)
                or is_script_executable(header)
            )

    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        return False


def is_pe_executable(header: bytes, file_handle: Any) -> bool:
    """Check if file has PE (Windows) executable signature."""
    if header[:2] != b"MZ":
        return False

    if len(header) >= 64:
        try:
            pe_offset = int.from_bytes(header[60:64], byteorder="little")
            file_handle.seek(pe_offset)
            pe_signature = file_handle.read(4)
            if pe_signature == b"PE\x00\x00":
                return True
        except (OSError, ValueError):
            pass
    # The MZ magic alone marks a DOS/PE executable; for batch *discovery*
    # an MZ file is worth analyzing even when the PE signature could not be
    # confirmed at e_lfanew (truncated/packed headers). 8f3da63 silently
    # flipped this fallback to False, hiding such files from discovery.
    return True


def is_elf_executable(header: bytes) -> bool:
    """Check if file has ELF (Linux/Unix) executable signature."""
    return header[:4] == b"\x7fELF"


def is_macho_executable(header: bytes) -> bool:
    """Check if file has Mach-O (macOS) executable signature."""
    mach_o_magics = [
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    ]
    return header[:4] in mach_o_magics


def is_script_executable(header: bytes) -> bool:
    """Check if file has script shebang."""
    return header[:2] == b"#!"
