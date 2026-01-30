#!/usr/bin/env python3
"""
Base Analyzer Abstract Base Class

This module provides the foundational interface for all r2inspect analyzers.
It implements a flexible, dependency-injection-friendly base class that enforces
consistent structure across the entire analyzer ecosystem while supporting
diverse initialization patterns.

The BaseAnalyzer establishes:
- Unified analyze() method interface for all analyzers
- Flexible constructor supporting multiple dependency injection patterns
- Common utility methods for logging, result formatting, and metadata
- Integration with AnalysisResult for standardized output
- Compatibility with existing HashingStrategy template method pattern

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger
from .analysis_result import AnalysisResult

logger = get_logger(__name__)


class BaseAnalyzer(ABC):
    """
    Abstract base class for all r2inspect analyzers.

    This class provides a unified interface and common functionality for all
    analyzers in the r2inspect ecosystem. It supports multiple constructor
    patterns through flexible dependency injection while enforcing consistent
    analyze() method semantics.

    Design Philosophy:
        - Flexibility: Support diverse analyzer requirements through **kwargs
        - Consistency: Enforce uniform analyze() interface across all implementations
        - Utility: Provide common helper methods to reduce code duplication
        - Integration: Work seamlessly with AnalyzerRegistry and AnalysisResult
        - Extensibility: Easy to subclass without breaking existing implementations

    Constructor Patterns Supported:
        1. r2 + config: Most format analyzers (PEAnalyzer, ELFAnalyzer)
        2. r2 only: Simple analyzers (AuthenticodeAnalyzer, OverlayAnalyzer)
        3. r2 + filepath: Hash/similarity analyzers (BinlexAnalyzer, SimHashAnalyzer)
        4. filepath + r2 (optional): Hashing strategy pattern (SSDeepAnalyzer)
        5. r2 + config + filepath: Complex analyzers (YaraAnalyzer, PEAnalyzer)

    Common Attributes:
        r2: Optional r2pipe instance for binary analysis
        config: Optional configuration object
        filepath: Optional Path to the file being analyzed
        name: Analyzer name (derived from class name)
        category: Analyzer category (must be set by subclass)
        supported_formats: Set of supported file formats (empty = all formats)

    Abstract Methods:
        analyze(): Primary analysis method returning dict[str, Any]

    Optional Override Methods:
        get_name(): Return analyzer name (default: class name in snake_case)
        get_category(): Return analyzer category (default: "unknown")
        get_description(): Return analyzer description
        supports_format(): Check if analyzer supports a file format
        is_available(): Check if analyzer dependencies are available

    Example Usage:
        >>> class CustomAnalyzer(BaseAnalyzer):
        ...     def __init__(self, r2, config):
        ...         super().__init__(r2=r2, config=config)
        ...
        ...     def analyze(self) -> dict[str, Any]:
        ...         result = self._init_result_structure()
        ...         # Perform analysis...
        ...         result["data"] = self._extract_data()
        ...         return result
        ...
        ...     def get_category(self) -> str:
        ...         return "metadata"
        ...
        ...     def supports_format(self, file_format: str) -> bool:
        ...         return file_format.upper() in {"PE", "PE32", "PE32+"}

    Integration with HashingStrategy:
        HashingStrategy subclasses should NOT inherit from BaseAnalyzer directly
        since HashingStrategy already provides a complete template method pattern.
        Instead, HashingStrategy can be viewed as a specialized BaseAnalyzer
        for the hashing domain.

    Integration with Registry:
        The AnalyzerRegistry stores analyzer classes and metadata. When instantiating
        analyzers from the registry, use the flexible constructor:

        >>> analyzer_class = registry.get_analyzer_class("pe_analyzer")
        >>> analyzer = analyzer_class(r2=r2_instance, config=config_obj, filepath=path)
    """

    def __init__(
        self,
        r2: Any | None = None,
        config: Any | None = None,
        filepath: Any | None = None,
        **kwargs: Any,
    ):
        """
        Initialize the base analyzer with flexible dependency injection.

        This constructor accepts common dependencies as named parameters and
        stores any additional parameters via **kwargs for subclass access.
        This pattern supports all existing analyzer constructor signatures.

        Args:
            r2: Optional r2pipe instance for binary analysis
            config: Optional configuration object (varies by analyzer)
            filepath: Optional file path (str or Path) to the binary being analyzed
            **kwargs: Additional analyzer-specific parameters

        Example:
            >>> # Pattern 1: r2 + config
            >>> analyzer = PEAnalyzer(r2=r2_instance, config=config)
            >>>
            >>> # Pattern 2: r2 only
            >>> analyzer = AuthenticodeAnalyzer(r2=r2_instance)
            >>>
            >>> # Pattern 3: r2 + filepath
            >>> analyzer = BinlexAnalyzer(r2=r2_instance, filepath="/path/to/binary")
            >>>
            >>> # Pattern 4: filepath + optional r2
            >>> analyzer = SSDeepAnalyzer(filepath="/path/to/binary", r2=None)
            >>>
            >>> # Pattern 5: All parameters
            >>> analyzer = YaraAnalyzer(r2=r2_instance, config=config, filepath=path)
        """
        # Core dependencies - these are the most common across all analyzers
        self.r2: Any = r2
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
        result = {
            "available": False,
            "error": None,
            "analyzer": self.get_name(),
            "execution_time": 0.0,
        }

        if additional_fields:
            result.update(additional_fields)

        return result

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

    def to_analysis_result(
        self, analysis_dict: dict[str, Any], file_format: str = "unknown"
    ) -> AnalysisResult:
        """
        Convert analysis dictionary to standardized AnalysisResult.

        This utility method converts the dictionary returned by analyze()
        into a standardized AnalysisResult object for consistency across
        the r2inspect framework.

        Args:
            analysis_dict: Dictionary returned by analyze()
            file_format: Detected file format (PE, ELF, Mach-O, etc.)

        Returns:
            AnalysisResult object with analysis information populated

        Raises:
            ValueError: If filepath is not set or analysis_dict is invalid

        Example:
            >>> def analyze(self) -> dict[str, Any]:
            ...     result = self._init_result_structure()
            ...     # ... perform analysis ...
            ...     return result
            >>>
            >>> # Convert to AnalysisResult for pipeline integration
            >>> analysis_dict = analyzer.analyze()
            >>> analysis_result = analyzer.to_analysis_result(
            ...     analysis_dict, file_format="PE"
            ... )
        """
        if not self.filepath:
            raise ValueError("Cannot create AnalysisResult: filepath not set")

        result = AnalysisResult(
            file_path=self.filepath,
            file_format=file_format,
            execution_time=analysis_dict.get("execution_time"),
        )

        # Add error if present
        if analysis_dict.get("error"):
            result.add_error(analysis_dict["error"], context=self.get_name())

        # Add warning if not available
        if not analysis_dict.get("available"):
            result.add_warning(
                f"{self.get_name()} analyzer not available or analysis failed",
                context=self.get_name(),
            )

        return result

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

    def _measure_execution_time(self, func):
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

        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time

            if isinstance(result, dict):
                result["execution_time"] = elapsed

            return result

        return wrapper

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
