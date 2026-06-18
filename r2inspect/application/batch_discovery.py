"""Batch discovery helpers for executable detection and filtering."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .batch_signatures import (
    check_executable_signature,
    is_elf_executable,
    is_macho_executable,
    is_pe_executable,
    is_script_executable,
)

__all__ = [
    "EXECUTABLE_SIGNATURES",
    "EXECUTABLE_DESCRIPTIONS",
    "discover_executables_by_header",
    "init_magic_detectors",
    "discover_executables_by_magic",
    "check_executable_signature",
    "is_pe_executable",
    "is_elf_executable",
    "is_macho_executable",
    "is_script_executable",
    "find_files_by_extensions",
]

EXECUTABLE_SIGNATURES = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/vnd.microsoft.portable-executable",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-pie-executable",
    "application/x-mach-binary",
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


def discover_executables_by_header(
    directory: str | Path,
    *,
    recursive: bool = False,
) -> tuple[list[Path], list[tuple[Path, str]], int]:
    """Discover executables by reading header bytes (no libmagic dependency).

    This is the fallback used when python-magic is unavailable so batch mode
    still finds PE/ELF/Mach-O/script files instead of silently scanning none.
    """
    directory = Path(directory)
    regular_files = [f for f in _iter_files(directory, recursive) if f.is_file()]

    executable_files: list[Path] = []
    file_errors: list[tuple[Path, str]] = []
    for file_path in regular_files:
        try:
            if file_path.stat().st_size < 64:
                continue
            if check_executable_signature(file_path):
                executable_files.append(file_path)
        except OSError as exc:
            file_errors.append((file_path, str(exc)))

    return executable_files, file_errors, len(regular_files)


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
        header_files, header_errors, scanned = discover_executables_by_header(
            directory, recursive=recursive
        )
        init_errors.append("python-magic not available; using header-signature detection")
        return header_files, init_errors, file_errors + header_errors, scanned

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

        # libmagic output drifts between versions (e.g. PE files now report
        # ``application/vnd.microsoft.portable-executable`` / "PE with unknown
        # signature" instead of "PE32 executable"). The header-byte check is
        # version-independent and authoritative, so it backs up the magic
        # classification rather than the discovery silently dropping the file.
        if _is_executable_signature(mime_type, description) or check_executable_signature(
            file_path
        ):
            executable_files.append(file_path)

    return executable_files, init_errors, file_errors, len(regular_files)


def find_files_by_extensions(batch_path: Path, extensions: str, recursive: bool) -> list[Path]:
    """Find files by specified extensions."""
    files_to_process: list[Path] = []
    ext_list = [ext.strip().lower().lstrip(".") for ext in extensions.split(",") if ext.strip()]

    for ext in ext_list:
        pattern = f"**/*.{ext}" if recursive else f"*.{ext}"
        files_to_process.extend(batch_path.glob(pattern))

    return files_to_process
