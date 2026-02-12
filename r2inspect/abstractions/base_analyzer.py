#!/usr/bin/env python3
"""Base analyzer interface and shared utilities."""

import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger
from .result_builder import init_result, mark_unavailable

logger = get_logger(__name__)


class BaseAnalyzer(ABC):
    """Abstract base class for analyzers with shared helpers."""

    def __init__(
        self,
        adapter: Any | None = None,
        config: Any | None = None,
        filepath: Any | None = None,
        **kwargs: Any,
    ):
        """Initialize base analyzer with adapter/config/filepath."""
        self.adapter: Any = adapter
        self.r2: Any = adapter
        self.config: Any = config

        # Normalize filepath to Path object if provided
        if filepath:
            self.filepath: Path | None = (
                Path(filepath) if not isinstance(filepath, Path) else filepath
            )
        else:
            self.filepath = None

        # Store additional kwargs for subclass access
        self._extra_params = kwargs

        # Cached metadata
        self._cached_name: str | None = None
        self._cached_category: str | None = None

    @abstractmethod
    def analyze(self) -> dict[str, Any]:
        """
        Perform the analysis and return results.

        This is the primary interface method that all analyzers must implement.
        It should perform the analyzer's core functionality and return a dictionary
        containing the analysis results.

        Result Structure Guidelines:
            - Use descriptive keys that indicate the data type/purpose
            - Include an "error" key (str | None) for error reporting
            - Include metadata about analysis success/failure
            - Follow consistent naming conventions (snake_case)

        Returns:
            Dictionary containing analysis results. Structure varies by analyzer
            but should follow these common patterns:
            {
                "available": bool,  # Whether analysis could be performed
                "error": str | None,  # Error message if analysis failed
                "data": Any,  # Analyzer-specific results
                # ... additional analyzer-specific fields
            }

        Raises:
            Should generally not raise exceptions; instead return error info
            in the result dictionary. Critical exceptions can be raised for
            programming errors (not analysis failures).

        Example:
            >>> def analyze(self) -> dict[str, Any]:
            ...     result = self._init_result_structure()
            ...     try:
            ...         # Perform analysis using self.r2, self.config, etc.
            ...         data = self._extract_pe_headers()
            ...         result["data"] = data
            ...         result["available"] = True
            ...     except Exception as e:
            ...         result["error"] = f"Analysis failed: {str(e)}"
            ...         self._log_error(f"PE analysis error: {e}")
            ...     return result
        """
        pass

    def _init_result_structure(
        self, additional_fields: dict[str, Any | None] | None = None
    ) -> dict[str, Any]:
        """
        Initialize a standardized result dictionary structure.

        Creates a base result dictionary with common fields that most analyzers
        need. Subclasses can extend this with analyzer-specific fields.

        Args:
            additional_fields: Optional dictionary of additional fields to include

        Returns:
            Dictionary with standard result structure:
            {
                "available": False,
                "error": None,
                "analyzer": <analyzer_name>,
                "execution_time": 0.0,
                # ... additional_fields if provided
            }

        Example:
            >>> result = self._init_result_structure({
            ...     "hash_value": None,
            ...     "hash_type": "ssdeep"
            ... })
        """
        return init_result(self.get_name(), additional_fields)

    def _mark_unavailable(
        self,
        result: dict[str, Any],
        error: str,
        *,
        library_available: bool | None = None,
    ) -> dict[str, Any]:
        """Mark a result as unavailable with an error message."""
        return mark_unavailable(result, error, library_available=library_available)

    def get_name(self) -> str:
        """
        Get the analyzer name.

        Returns a human-readable name for this analyzer. By default, derives
        the name from the class name by converting CamelCase to snake_case
        and removing the "Analyzer" suffix.

        Subclasses can override this to provide custom names.

        Returns:
            Analyzer name in snake_case

        Example:
            >>> class PEAnalyzer(BaseAnalyzer):
            ...     pass
            >>> analyzer = PEAnalyzer()
            >>> analyzer.get_name()
            'pe'
        """
        if self._cached_name:
            return self._cached_name

        # Convert CamelCase to snake_case
        class_name = self.__class__.__name__

        # Remove "Analyzer" suffix if present
        if class_name.endswith(("Analyzer", "Detector")):
            class_name = class_name[:-8]  # Remove suffix

        # Convert to snake_case
        import re

        name = re.sub(r"(?<!^)(?=[A-Z])", "_", class_name).lower()

        self._cached_name = name
        return name

    def get_category(self) -> str:
        """
        Get the analyzer category.

        Returns a category identifier for this analyzer. Categories are used
        by the AnalyzerRegistry for organizing and filtering analyzers.

        Standard categories:
            - format: Format-specific analyzers (PE, ELF, Mach-O)
            - hashing: Hash computation (SSDeep, TLSH, Impfuzzy)
            - detection: Pattern matching (Packer, Crypto, YARA)
            - metadata: Structural metadata (Sections, Imports, Exports)
            - security: Security features (Mitigations, Authenticode)
            - similarity: Code similarity (BinDiff, SimHash, Binbloom)
            - behavioral: Behavioral analysis (Strings, Functions)

        Subclasses should override this to return their specific category.

        Returns:
            Category identifier string

        Example:
            >>> class SSDeepAnalyzer(BaseAnalyzer):
            ...     def get_category(self) -> str:
            ...         return "hashing"
        """
        if self._cached_category:
            return self._cached_category

        # Default to "unknown" - subclasses should override
        return "unknown"

    def get_description(self) -> str:
        """
        Get a human-readable description of this analyzer.

        Returns a brief description of what this analyzer does. Used for
        documentation, help text, and user interfaces.

        Subclasses should override this to provide meaningful descriptions.

        Returns:
            Human-readable description string

        Example:
            >>> class SSDeepAnalyzer(BaseAnalyzer):
            ...     def get_description(self) -> str:
            ...         return "SSDeep fuzzy hashing for file similarity detection"
        """
        return f"{self.__class__.__name__} - No description provided"

    def supports_format(self, _file_format: str) -> bool:
        """
        Check if this analyzer supports a specific file format.

        Determines whether this analyzer can analyze binaries of the specified
        format. By default, returns True (supports all formats). Subclasses
        should override to restrict to specific formats.

        Args:
            file_format: File format identifier (e.g., "PE", "ELF", "MACH0")

        Returns:
            True if format is supported, False otherwise

        Example:
            >>> class PEAnalyzer(BaseAnalyzer):
            ...     def supports_format(self, file_format: str) -> bool:
            ...         return file_format.upper() in {"PE", "PE32", "PE32+"}
            >>>
            >>> analyzer = PEAnalyzer()
            >>> analyzer.supports_format("PE")
            True
            >>> analyzer.supports_format("ELF")
            False
        """
        # Default: support all formats
        # Subclasses should override to specify supported formats
        return True

    def get_supported_formats(self) -> set[str]:
        """
        Get the set of file formats supported by this analyzer.

        Returns a set of format identifiers that this analyzer can process.
        Empty set indicates support for all formats.

        Subclasses should override this if they support only specific formats.

        Returns:
            Set of supported format identifiers (empty = all formats)

        Example:
            >>> class ImpfuzzyAnalyzer(BaseAnalyzer):
            ...     def get_supported_formats(self) -> set[str]:
            ...         return {"PE", "PE32", "PE32+"}
        """
        # Default: empty set = supports all formats
        return set()

    @classmethod
    def is_available(cls) -> bool:
        """
        Check if this analyzer is available for use.

        Class method that checks whether all dependencies required by this
        analyzer are available (libraries, tools, etc.). This allows the
        registry and pipeline to determine which analyzers can be used
        without instantiating them.

        Subclasses should override this to check for their specific dependencies.

        Returns:
            True if analyzer can be used, False if dependencies are missing

        Example:
            >>> class SSDeepAnalyzer(BaseAnalyzer):
            ...     @classmethod
            ...     def is_available(cls) -> bool:
            ...         try:
            ...             import ssdeep
            ...             return True
            ...         except ImportError:
            ...             return False
            >>>
            >>> if SSDeepAnalyzer.is_available():
            ...     analyzer = SSDeepAnalyzer(filepath="binary.exe")
        """
        # Default: assume available
        # Subclasses should override to check dependencies
        return True

    def _log_debug(self, message: str) -> None:
        """
        Log a debug message with analyzer context.

        Args:
            message: Debug message to log

        Example:
            >>> self._log_debug("Starting PE header extraction")
        """
        logger.debug(f"[{self.get_name()}] {message}")

    def _log_info(self, message: str) -> None:
        """
        Log an info message with analyzer context.

        Args:
            message: Info message to log

        Example:
            >>> self._log_info("Successfully extracted 50 imports")
        """
        logger.info(f"[{self.get_name()}] {message}")

    def _log_warning(self, message: str) -> None:
        """
        Log a warning message with analyzer context.

        Args:
            message: Warning message to log

        Example:
            >>> self._log_warning("Suspicious section entropy detected")
        """
        logger.warning(f"[{self.get_name()}] {message}")

    def _log_error(self, message: str) -> None:
        """
        Log an error message with analyzer context.

        Args:
            message: Error message to log

        Example:
            >>> self._log_error(f"Failed to parse PE headers: {e}")
        """
        logger.error(f"[{self.get_name()}] {message}")

    def _measure_execution_time(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """
        Decorator to measure execution time of analysis methods.

        This can be used as a decorator on methods to automatically track
        execution time and add it to results.

        Args:
            func: Function to measure

        Returns:
            Wrapped function that measures execution time

        Example:
            >>> @self._measure_execution_time
            ... def _extract_headers(self):
            ...     # ... extraction logic ...
            ...     pass
        """

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.time()
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time

            if isinstance(result, dict):
                result["execution_time"] = elapsed

            return result

        return wrapper

    @contextmanager
    def _analysis_context(
        self,
        result: dict[str, Any],
        *,
        error_message: str,
        set_available: bool = True,
    ) -> Iterator[None]:
        """
        Standardize analyzer error handling for top-level analysis.

        This helper centralizes the common try/except pattern while allowing
        callers to opt out of automatically setting availability.
        """
        try:
            yield
            if set_available:
                result["available"] = True
        except Exception as e:
            result["error"] = str(e)
            self._log_error(f"{error_message}: {e}")

    def get_file_size(self) -> int | None:
        """
        Get the size of the file being analyzed.

        Returns:
            File size in bytes, or None if filepath not set or file inaccessible

        Example:
            >>> size = self.get_file_size()
            >>> if size and size > 100 * 1024 * 1024:
            ...     self._log_warning(f"Large file: {size} bytes")
        """
        if not self.filepath:
            return None

        try:
            return self.filepath.stat().st_size
        except OSError:
            return None

    def get_file_extension(self) -> str:
        """
        Get the file extension.

        Returns:
            File extension (lowercase, without dot), or empty string if none

        Example:
            >>> ext = self.get_file_extension()
            >>> if ext == "exe":
            ...     # Likely a Windows executable
        """
        if not self.filepath:
            return ""

        return self.filepath.suffix.lstrip(".").lower()

    def file_exists(self) -> bool:
        """
        Check if the file being analyzed exists.

        Returns:
            True if file exists and is accessible, False otherwise

        Example:
            >>> if not self.file_exists():
            ...     return {"error": "File not found", "available": False}
        """
        if not self.filepath:
            return False

        return self.filepath.exists() and self.filepath.is_file()

    def __str__(self) -> str:
        """
        Return human-readable string representation.

        Returns:
            String description of the analyzer instance

        Example:
            >>> str(analyzer)
            'PEAnalyzer(name=pe, category=format, file=sample.exe)'
        """
        filename = self.filepath.name if self.filepath else "no_file"
        return (
            f"{self.__class__.__name__}("
            f"name={self.get_name()}, "
            f"category={self.get_category()}, "
            f"file={filename})"
        )

    def __repr__(self) -> str:
        """
        Return detailed string representation for debugging.

        Returns:
            Detailed string representation

        Example:
            >>> repr(analyzer)
            "PEAnalyzer(filepath=PosixPath('/path/to/sample.exe'), r2=<r2pipe>, config=<Config>)"
        """
        return (
            f"{self.__class__.__name__}("
            f"filepath={self.filepath!r}, "
            f"r2={'<r2pipe>' if self.r2 else None}, "
            f"config={'<Config>' if self.config else None})"
        )
