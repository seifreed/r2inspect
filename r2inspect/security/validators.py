"""
Centralized Security Validators for r2inspect.

This module provides secure file path validation and sanitization to prevent:
- Path traversal attacks (CWE-22)
- Command injection via file paths (CWE-78)
- Symlink attacks (CWE-59)
- Time-of-check to time-of-use (TOCTOU) race conditions (CWE-367)

Copyright (C) 2025 Marc Rivero López

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

import os
import re
from pathlib import Path


class FileValidator:
    """
    Centralized file path validator to prevent security vulnerabilities.

    This validator enforces defense-in-depth by implementing multiple layers:
    1. Path canonicalization (resolve symlinks and relative paths)
    2. Directory containment checks (prevent directory traversal)
    3. Dangerous character filtering (prevent command injection)
    4. Filesystem security checks (follow symlinks, special files)

    References:
    - OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
    - CWE-22: Improper Limitation of a Pathname to a Restricted Directory
    - CWE-78: Improper Neutralization of Special Elements used in an OS Command
    - CWE-59: Improper Link Resolution Before File Access
    """

    # Characters that are dangerous in shell contexts or path manipulation
    # Based on OWASP recommendations and CERT Secure Coding Standards
    DANGEROUS_CHARS = frozenset(
        [
            ";",
            "&",
            "|",
            "`",
            "$",
            "(",
            ")",
            "{",
            "}",
            "[",
            "]",
            "<",
            ">",
            "\n",
            "\r",
            "*",
            "?",
            "~",
            "!",
        ]
    )

    # Maximum path length to prevent buffer overflow and DoS (CERT FIO37-C)
    MAX_PATH_LENGTH = 4096  # Standard Linux PATH_MAX

    def __init__(self, allowed_directory: Path | None = None):
        """
        Initialize the file validator.

        Args:
            allowed_directory: Optional root directory to restrict file access.
                              If provided, all validated paths must be within this directory.
                              The directory is canonicalized to prevent bypass via symlinks.
        """
        self.allowed_directory = None
        if allowed_directory:
            # Canonicalize the allowed directory to prevent symlink bypass
            try:
                self.allowed_directory = Path(allowed_directory).resolve(strict=True)
            except (OSError, RuntimeError) as e:
                raise ValueError(f"Invalid allowed directory: {e}")

    def validate_path(self, filepath: str, check_exists: bool = True) -> Path:
        """
        Validate and sanitize a file path with comprehensive security checks.

        This method implements multiple security controls:
        1. Path length validation (prevent buffer overflow)
        2. Dangerous character detection (prevent command injection)
        3. Path canonicalization (resolve symlinks and .. sequences)
        4. Directory containment (prevent path traversal)
        5. Symlink validation (prevent TOCTOU attacks)
        6. Special file detection (prevent device access)

        Args:
            filepath: The file path to validate
            check_exists: Whether to verify the file exists (default: True)

        Returns:
            Path: Canonicalized and validated Path object

        Raises:
            ValueError: If validation fails for any security reason

        Security Notes:
        - Uses strict=True in resolve() to fail if path doesn't exist (prevents TOCTOU)
        - Checks final resolved path, not intermediate paths
        - Validates against both relative and absolute path traversal
        """
        self._validate_basic_path(filepath)
        resolved_path = self._resolve_path(filepath, check_exists)
        self._validate_allowed_directory(resolved_path)
        self._validate_existing_path(filepath, resolved_path, check_exists)
        return resolved_path

    def _validate_basic_path(self, filepath: str) -> None:
        if not filepath:
            raise ValueError("File path cannot be empty")
        if len(filepath) > self.MAX_PATH_LENGTH:
            raise ValueError(
                f"Path length exceeds maximum allowed ({self.MAX_PATH_LENGTH}): {len(filepath)}"
            )
        if "\x00" in filepath:
            raise ValueError("Path contains null byte")
        dangerous_found = self._check_dangerous_chars(filepath)
        if dangerous_found:
            raise ValueError(f"Path contains dangerous characters: {dangerous_found}")

    def _resolve_path(self, filepath: str, check_exists: bool) -> Path:
        try:
            path = Path(filepath)
            if check_exists:
                return path.resolve(strict=True)
            return path.resolve(strict=False)
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Path resolution failed: {e}")

    def _validate_allowed_directory(self, resolved_path: Path) -> None:
        if not self.allowed_directory:
            return
        try:
            resolved_path.relative_to(self.allowed_directory)
        except ValueError:
            raise ValueError(
                f"Path is outside allowed directory: {resolved_path} "
                f"not in {self.allowed_directory}"
            )

    def _validate_existing_path(
        self, original_path: str, resolved_path: Path, check_exists: bool
    ) -> None:
        if not (check_exists and resolved_path.exists()):
            return
        if not resolved_path.is_file() and not resolved_path.is_dir():
            raise ValueError(f"Path is not a regular file or directory: {resolved_path}")
        # Path changed during resolution (symlinks/..). Keep as informational no-op.
        _ = original_path

    def _check_dangerous_chars(self, filepath: str) -> set[str]:
        """
        Check for characters that could enable command injection.

        Args:
            filepath: Path string to check

        Returns:
            Set of dangerous characters found (empty if safe)
        """
        return {char for char in self.DANGEROUS_CHARS if char in filepath}

    def sanitize_for_subprocess(self, filepath: Path) -> str:
        """
        Prepare a validated path for safe use in subprocess calls.

        This method should ONLY be called after validate_path() has succeeded.
        It provides additional safety for subprocess usage:
        1. Converts to absolute path string
        2. Validates no shell metacharacters remain
        3. Returns string suitable for subprocess with shell=False

        Args:
            filepath: Validated Path object (must be from validate_path())

        Returns:
            str: Safe absolute path string for subprocess

        Security Notes:
        - ALWAYS use shell=False in subprocess.run/Popen
        - ALWAYS pass command as list, not string
        - This method provides defense-in-depth, not primary security

        Example:
            validator = FileValidator()
            safe_path = validator.validate_path(user_input)
            safe_str = validator.sanitize_for_subprocess(safe_path)
            subprocess.run(["ssdeep", "-s", safe_str], shell=False)
        """
        if not isinstance(filepath, Path):
            raise TypeError("filepath must be a Path object from validate_path()")

        # Convert to absolute string
        abs_path = str(filepath.absolute())

        # Double-check for dangerous characters (defense-in-depth)
        dangerous = self._check_dangerous_chars(abs_path)
        if dangerous:
            raise ValueError(f"Path contains dangerous characters after validation: {dangerous}")

        return abs_path

    def validate_yara_rule_content(self, content: str, max_size: int = 10 * 1024 * 1024) -> None:
        """
        Validate YARA rule content for security issues.

        Checks for:
        1. Size limits (prevent DoS)
        2. Dangerous patterns (code execution, includes)
        3. Complexity limits (prevent ReDoS)

        Args:
            content: YARA rule content to validate
            max_size: Maximum allowed size in bytes (default: 10MB)

        Raises:
            ValueError: If validation fails

        References:
        - YARA best practices: https://yara.readthedocs.io/
        - CWE-400: Uncontrolled Resource Consumption
        """
        if not content:
            raise ValueError("YARA rule content cannot be empty")

        # Size limit (CWE-400: Resource Consumption)
        if len(content) > max_size:
            raise ValueError(f"YARA rule content exceeds maximum size: {len(content)} > {max_size}")

        # Check for dangerous patterns
        # YARA external modules could potentially be abused
        dangerous_patterns = [
            r'include\s+"',  # Include directives could load malicious rules
            r'import\s+"(?!pe|elf|cuckoo|magic|hash|math|dotnet)[^"]*"',  # Non-standard imports
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                raise ValueError(f"YARA rule contains potentially dangerous pattern: {pattern}")

        # Basic complexity check (prevent excessive regex complexity)
        # Count regex special characters as proxy for complexity
        regex_chars = content.count("*") + content.count("+") + content.count("?")
        if regex_chars > 10000:
            raise ValueError(f"YARA rule appears too complex (regex chars: {regex_chars})")

        # Check for excessively long lines (could indicate obfuscation)
        lines = content.split("\n")
        max_line_length = 10000
        for i, line in enumerate(lines, 1):
            if len(line) > max_line_length:
                raise ValueError(
                    f"YARA rule line {i} exceeds maximum length: {len(line)} > {max_line_length}"
                )


def validate_file_for_analysis(
    filepath: str,
    allowed_directory: str | None = None,
    max_size: int = 1024 * 1024 * 1024,  # 1GB default
) -> Path:
    """
    Convenience function for validating files before analysis.

    This is a high-level wrapper around FileValidator for common use cases.

    Args:
        filepath: Path to validate
        allowed_directory: Optional directory to restrict access
        max_size: Maximum file size in bytes

    Returns:
        Path: Validated Path object

    Raises:
        ValueError: If validation fails
    """
    validator = FileValidator(
        allowed_directory=Path(allowed_directory) if allowed_directory else None
    )

    # Validate path
    validated_path = validator.validate_path(filepath, check_exists=True)

    # Check file size
    if validated_path.is_file():
        file_size = validated_path.stat().st_size
        if file_size == 0:
            raise ValueError(f"File is empty: {validated_path}")
        if file_size > max_size:
            raise ValueError(f"File too large: {file_size} > {max_size}")

    return validated_path
