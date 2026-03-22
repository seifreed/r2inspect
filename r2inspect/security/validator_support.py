"""Helper operations for security validators."""

from __future__ import annotations

import re
from pathlib import Path


def validate_basic_path(
    filepath: str,
    max_path_length: int,
    dangerous_chars: frozenset[str],
    check_dangerous_chars,
) -> None:
    if not filepath:
        raise ValueError("File path cannot be empty")
    if len(filepath) > max_path_length:
        raise ValueError(
            f"Path length exceeds maximum allowed ({max_path_length}): {len(filepath)}"
        )
    if "\x00" in filepath:
        raise ValueError("Path contains null byte")
    dangerous_found = check_dangerous_chars(filepath)
    if dangerous_found:
        raise ValueError(f"Path contains dangerous characters: {dangerous_found}")


def resolve_path(filepath: str, check_exists: bool) -> Path:
    try:
        path = Path(filepath)
        if check_exists:
            return path.resolve(strict=True)
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"Path resolution failed: {exc}") from exc


def validate_allowed_directory(resolved_path: Path, allowed_directory: Path | None) -> None:
    if not allowed_directory:
        return
    try:
        resolved_path.relative_to(allowed_directory)
    except ValueError as exc:
        raise ValueError(
            f"Path is outside allowed directory: {resolved_path} not in {allowed_directory}"
        ) from exc


def validate_existing_path(original_path: str, resolved_path: Path, check_exists: bool) -> None:
    if not (check_exists and resolved_path.exists()):
        return
    if not resolved_path.is_file() and not resolved_path.is_dir():
        raise ValueError(f"Path is not a regular file or directory: {resolved_path}")
    _ = original_path


def sanitize_for_subprocess(filepath: Path, check_dangerous_chars) -> str:
    if not isinstance(filepath, Path):
        raise TypeError("filepath must be a Path object from validate_path()")
    abs_path = str(filepath.absolute())
    dangerous = check_dangerous_chars(abs_path)
    if dangerous:
        raise ValueError(f"Path contains dangerous characters after validation: {dangerous}")
    return abs_path


def validate_yara_rule_content(content: str, max_size: int = 10 * 1024 * 1024) -> None:
    if not content:
        raise ValueError("YARA rule content cannot be empty")
    if len(content) > max_size:
        raise ValueError(f"YARA rule content exceeds maximum size: {len(content)} > {max_size}")

    dangerous_patterns = [
        r'include\s+"',
        r'import\s+"(?!pe|elf|cuckoo|magic|hash|math|dotnet)[^"]*"',
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            raise ValueError(f"YARA rule contains potentially dangerous pattern: {pattern}")

    regex_chars = content.count("*") + content.count("+") + content.count("?")
    if regex_chars > 10000:
        raise ValueError(f"YARA rule appears too complex (regex chars: {regex_chars})")

    max_line_length = 10000
    for index, line in enumerate(content.split("\n"), 1):
        if len(line) > max_line_length:
            raise ValueError(
                f"YARA rule line {index} exceeds maximum length: {len(line)} > {max_line_length}"
            )
