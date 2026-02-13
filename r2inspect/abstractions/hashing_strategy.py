#!/usr/bin/env python3
"""Template method base for hashing analyzers."""

import os
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..domain import HashResult


class HashingStrategy(ABC):
    """Abstract base class for hashing strategies."""

    def __init__(
        self,
        filepath: str,
        r2_instance: Any | None = None,
        max_file_size: int = 100 * 1024 * 1024,
        min_file_size: int = 1,
    ):
        """
        Initialize the hashing strategy.

        Args:
            filepath: Path to the file to analyze
            r2_instance: Optional r2pipe instance for binary analysis
            max_file_size: Maximum allowed file size in bytes
            min_file_size: Minimum required file size in bytes

        Raises:
            ValueError: If filepath is empty or size limits are invalid
        """
        if not filepath:
            raise ValueError("filepath cannot be empty")

        if max_file_size <= 0 or min_file_size < 0:
            raise ValueError("File size limits must be positive")

        if min_file_size > max_file_size:
            raise ValueError("min_file_size cannot exceed max_file_size")

        self._filepath = Path(filepath)
        self.filepath: Path = self._filepath
        self.r2: Any = r2_instance
        self.max_file_size = max_file_size
        self.min_file_size = min_file_size

    def analyze(self) -> dict[str, Any]:
        """
        Template method defining the analysis workflow.

        This method orchestrates the complete hash analysis process:
        1. Validates the file
        2. Checks library availability
        3. Calculates hash
        4. Formats results

        Subclasses should not override this method; instead, they should
        implement the abstract methods called within this template.

        Returns:
            Dictionary containing analysis results with standardized structure:
            {
                'available': bool,
                'hash_type': str,
                'hash_value': str | None,
                'file_size': int,
                'execution_time': float,
                'error': str | None,
                'method_used': str | None
            }
        """
        start_time = time.time()

        result = HashResult(hash_type=self._get_hash_type())

        try:
            # Step 1: Validate file
            validation_error = self._validate_file()
            if validation_error:
                result.error = validation_error
                result.execution_time = time.time() - start_time
                return result.to_dict()

            result.file_size = self._filepath.stat().st_size

            # Step 2: Check library availability
            library_available, error_message = self._check_library_availability()
            if not library_available:
                result.error = error_message or "Required library not available"
                result.execution_time = time.time() - start_time
                return result.to_dict()

            result.available = True

            # Step 3: Calculate hash
            hash_value, method_used, error = self._calculate_hash()
            if error:
                result.error = error
            else:
                result.hash_value = hash_value
                result.method_used = method_used

        except Exception as e:
            result.error = f"Unexpected error in {self._get_hash_type()} analysis: {str(e)}"

        finally:
            result.execution_time = time.time() - start_time

        return result.to_dict()

    def _validate_file(self) -> str | None:
        """
        Validate file for hashing analysis.

        Performs common validation checks:
        - File existence
        - File size within limits
        - Read permissions

        Returns:
            Error message string if validation fails, None if successful
        """
        try:
            # Check file existence
            if not self._filepath.exists():
                return f"File does not exist: {self.filepath}"

            # Check if path is a file (not directory)
            if not self._filepath.is_file():
                return f"Path is not a regular file: {self.filepath}"

            # Check file size
            file_size = self._filepath.stat().st_size

            if file_size < self.min_file_size:
                return (
                    f"File too small for analysis ({file_size} bytes, "
                    f"minimum: {self.min_file_size} bytes)"
                )

            if file_size > self.max_file_size:
                return (
                    f"File too large for analysis ({file_size} bytes, "
                    f"maximum: {self.max_file_size} bytes)"
                )

        except OSError as e:
            return f"Cannot access file statistics: {str(e)}"

        # Check read permissions
        if not os.access(self._filepath, os.R_OK):
            return f"File is not readable: {self.filepath}"

        return None

    @abstractmethod
    def _check_library_availability(self) -> tuple[bool, str | None]:
        """
        Check if the required hashing library is available.

        Subclasses must implement this method to verify that all dependencies
        required for hash calculation are present and functional.

        Returns:
            Tuple of (is_available, error_message):
            - is_available: True if library is available and functional
            - error_message: None if available, error description otherwise

        Example:
            >>> def _check_library_availability(self) -> tuple[bool, str | None]:
            ...     try:
            ...         import tlsh
            ...         return True, None
            ...     except ImportError:
            ...         return False, "TLSH library not installed. Install with: pip install python-tlsh"
        """
        pass

    @abstractmethod
    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        """
        Calculate the hash value for the file.

        Subclasses must implement this method to perform the actual hash
        calculation using their specific library or algorithm.

        Returns:
            Tuple of (hash_value, method_used, error_message):
            - hash_value: Calculated hash string, or None if calculation failed
            - method_used: Description of method used (e.g., 'python_library', 'system_binary')
            - error_message: None if successful, error description otherwise

        Example:
            >>> def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
            ...     try:
            ...         import tlsh
            ...         with open(self.filepath, 'rb') as f:
            ...             data = f.read()
            ...         hash_value = tlsh.hash(data)
            ...         return hash_value, 'python_library', None
            ...     except Exception as e:
            ...         return None, None, f"Hash calculation failed: {str(e)}"
        """
        pass

    @abstractmethod
    def _get_hash_type(self) -> str:
        """
        Return the hash type identifier.

        Subclasses must implement this method to specify the type of hash
        being calculated (e.g., 'tlsh', 'ssdeep', 'impfuzzy').

        Returns:
            String identifier for the hash type

        Example:
            >>> def _get_hash_type(self) -> str:
            ...     return "tlsh"
        """
        pass

    @staticmethod
    @abstractmethod
    def compare_hashes(hash1: str, hash2: str) -> Any | None:
        """
        Compare two hashes and return a similarity metric.

        Subclasses must implement this static method to enable hash comparison.
        The return type and semantics depend on the specific hash algorithm:
        - TLSH: Returns integer distance (lower = more similar)
        - SSDeep: Returns integer percentage (higher = more similar)
        - Impfuzzy: Returns integer percentage (higher = more similar)

        Args:
            hash1: First hash value
            hash2: Second hash value

        Returns:
            Similarity metric (type and semantics depend on hash algorithm),
            or None if comparison fails

        Example:
            >>> @staticmethod
            >>> def compare_hashes(hash1: str, hash2: str) -> int | None:
            ...     try:
            ...         import tlsh
            ...         if not hash1 or not hash2:
            ...             return None
            ...         return tlsh.diff(hash1, hash2)
            ...     except Exception:
            ...         return None
        """
        pass

    @staticmethod
    @abstractmethod
    def is_available() -> bool:
        """
        Check if the hashing library is available for use.

        Subclasses must implement this static method to allow library
        availability checking without instantiation.

        Returns:
            True if the hashing library is available, False otherwise

        Example:
            >>> @staticmethod
            >>> def is_available() -> bool:
            ...     try:
            ...         import tlsh
            ...         return True
            ...     except ImportError:
            ...         return False
        """
        pass

    def get_file_size(self) -> int | None:
        """
        Get the size of the file being analyzed.

        Returns:
            File size in bytes, or None if file doesn't exist or is inaccessible
        """
        try:
            return self.filepath.stat().st_size
        except OSError:
            return None

    def get_file_extension(self) -> str:
        """
        Get the file extension.

        Returns:
            File extension (lowercase, without dot), or empty string if none
        """
        return self.filepath.suffix.lstrip(".").lower()

    def __str__(self) -> str:
        """
        Return human-readable string representation.

        Returns:
            String description of the hashing strategy
        """
        return f"{self.__class__.__name__}(type={self._get_hash_type()}, file={self.filepath.name})"

    def __repr__(self) -> str:
        """
        Return detailed string representation for debugging.

        Returns:
            Detailed string representation
        """
        return (
            f"{self.__class__.__name__}("
            f"filepath={self.filepath!r}, "
            f"max_file_size={self.max_file_size}, "
            f"min_file_size={self.min_file_size})"
        )


class R2HashingStrategy(HashingStrategy):
    """Hashing strategy that standardizes r2 adapter access."""

    def __init__(
        self,
        adapter: Any,
        filepath: str,
        max_file_size: int = 100 * 1024 * 1024,
        min_file_size: int = 1,
    ) -> None:
        self.adapter = adapter
        self.r2 = adapter
        super().__init__(
            filepath=filepath,
            r2_instance=adapter,
            max_file_size=max_file_size,
            min_file_size=min_file_size,
        )
