"""Batch discovery helpers for executable detection and filtering."""

from __future__ import annotations

from pathlib import Path
from typing import Any

EXECUTABLE_SIGNATURES = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-pie-executable",
    "application/octet-stream",
}

EXECUTABLE_DESCRIPTIONS = (
    "PE32 executable",
    "PE32+ executable",
    "MS-DOS executable",
    "Microsoft Portable Executable",
    "ELF",
    "Mach-O",
    "executable",
    "shared object",
    "dynamically linked",
)


def _is_executable_signature(mime_type: str, description: str) -> bool:
    if mime_type in EXECUTABLE_SIGNATURES:
        return True
    return any(desc in description for desc in EXECUTABLE_DESCRIPTIONS)


def _iter_files(directory: Path, recursive: bool) -> list[Path]:
    return list(directory.rglob("*")) if recursive else list(directory.glob("*"))


def init_magic_detectors(
    magic_module: Any | None,
) -> tuple[Any, Any] | None:
    if magic_module is None:
        return None
    return magic_module.Magic(mime=True), magic_module.Magic()


def discover_executables_by_magic(
    directory: str | Path,
    *,
    recursive: bool = False,
    magic_module: Any | None = None,
) -> tuple[list[Path], list[str], list[tuple[Path, str]], int]:
    """Discover executables using magic signatures without CLI output."""
    init_errors: list[str] = []
    file_errors: list[tuple[Path, str]] = []

    directory = Path(directory)
    try:
        magic_tuple = init_magic_detectors(magic_module)
    except Exception as exc:
        init_errors.append(f"Error initializing magic: {exc}")
        return [], init_errors, file_errors, 0

    if magic_tuple is None:
        init_errors.append("python-magic not available; skipping magic-based detection")
        return [], init_errors, file_errors, 0

    mime_magic, desc_magic = magic_tuple
    regular_files = [f for f in _iter_files(directory, recursive) if f.is_file()]

    executable_files: list[Path] = []
    for file_path in regular_files:
        try:
            if file_path.stat().st_size < 64:
                continue

            mime_type = mime_magic.from_file(str(file_path))
            description = desc_magic.from_file(str(file_path))
        except Exception as exc:
            file_errors.append((file_path, str(exc)))
            continue

        if _is_executable_signature(mime_type, description):
            executable_files.append(file_path)

    return executable_files, init_errors, file_errors, len(regular_files)


def check_executable_signature(file_path: Path) -> bool:
    """Check for executable signatures in file header (PE, ELF, Mach-O)."""
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

    except Exception:
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


def find_files_by_extensions(batch_path: Path, extensions: str, recursive: bool) -> list[Path]:
    """Find files by specified extensions."""
    files_to_process: list[Path] = []
    ext_list = [ext.strip().lower() for ext in extensions.split(",")]

    for ext in ext_list:
        pattern = f"**/*.{ext}" if recursive else f"*.{ext}"
        files_to_process.extend(batch_path.glob(pattern))

    return files_to_process
