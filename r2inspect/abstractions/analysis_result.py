#!/usr/bin/env python3
"""
Analysis Result Data Transfer Object

This module provides a standardized dataclass for representing analysis results
across all r2inspect analyzers. It enforces consistency and provides utility
methods for result manipulation and serialization.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    from datetime import UTC
except ImportError:  # Python 3.10 compatibility
    UTC = timezone.utc
from pathlib import Path
from typing import Any


@dataclass
class AnalysisResult:
    """
    Standardized data structure for analysis results.

    This dataclass provides a unified format for all analyzer outputs,
    ensuring consistency across the r2inspect framework and facilitating
    result aggregation, comparison, and serialization.

    Attributes:
        file_path: Absolute path to the analyzed binary file
        file_format: Detected file format (PE, ELF, Mach-O, etc.)
        timestamp: ISO 8601 timestamp of when the analysis was performed
        file_info: Basic file information (size, permissions, metadata)
        format_info: Format-specific information (headers, sections, etc.)
        security: Security-related findings (mitigations, vulnerabilities)
        hashes: Dictionary of hash type to hash value mappings
        detections: List of detections (YARA matches, signatures, etc.)
        errors: List of errors encountered during analysis
        warnings: List of warnings generated during analysis
        execution_time: Time taken to perform the analysis in seconds
    """

    file_path: Path | str
    file_format: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    file_info: dict[str, Any] = field(default_factory=dict)
    format_info: dict[str, Any] = field(default_factory=dict)
    security: dict[str, Any] = field(default_factory=dict)
    hashes: dict[str, str] = field(default_factory=dict)
    detections: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    execution_time: float | None = None

    def __post_init__(self) -> None:
        """
        Validate and normalize fields after initialization.

        Ensures file_path is a Path object and performs basic validation
        on required fields.
        """
        if not isinstance(self.file_path, Path):
            self.file_path = Path(self.file_path)

        if not self.file_format:
            raise ValueError("file_format is required and cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the analysis result to a dictionary representation.

        Returns:
            Dictionary containing all analysis result fields with Path
            objects converted to strings for JSON serialization.
        """
        path = Path(self.file_path)
        result = {
            "file_path": str(path.absolute()),
            "file_format": self.file_format,
            "timestamp": self.timestamp,
            "file_info": self.file_info,
            "format_info": self.format_info,
            "security": self.security,
            "hashes": self.hashes,
            "detections": self.detections,
            "errors": self.errors,
            "warnings": self.warnings,
            "execution_time": self.execution_time,
        }
        return result

    def to_json(self, indent: int | None = 2) -> str:
        """
        Serialize the analysis result to a JSON string.

        Args:
            indent: Number of spaces for JSON indentation. None for compact output.

        Returns:
            JSON string representation of the analysis result.
        """
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def add_hash(self, hash_type: str, hash_value: str) -> None:
        """
        Add or update a hash value in the results.

        Args:
            hash_type: Type of hash (e.g., 'md5', 'sha256', 'tlsh', 'ssdeep')
            hash_value: The computed hash value

        Raises:
            ValueError: If hash_type or hash_value are empty strings
        """
        if not hash_type or not hash_value:
            raise ValueError("hash_type and hash_value cannot be empty")

        self.hashes[hash_type.lower()] = hash_value

    def add_detection(
        self,
        detection_type: str,
        name: str,
        severity: str = "unknown",
        metadata: dict[str, Any | None] | None = None,
    ) -> None:
        """
        Add a detection finding to the results.

        Args:
            detection_type: Type of detection (e.g., 'yara', 'signature', 'pattern')
            name: Name or identifier of the detection
            severity: Severity level ('critical', 'high', 'medium', 'low', 'info')
            metadata: Additional metadata about the detection

        Raises:
            ValueError: If detection_type or name are empty strings
        """
        if not detection_type or not name:
            raise ValueError("detection_type and name cannot be empty")

        detection: dict[str, Any] = {
            "type": detection_type,
            "name": name,
            "severity": severity.lower(),
            "timestamp": datetime.now(UTC).isoformat(),
        }

        if metadata:
            detection["metadata"] = metadata

        self.detections.append(detection)

    def add_error(self, error_message: str, context: str | None = None) -> None:
        """
        Add an error message to the results.

        Args:
            error_message: Description of the error
            context: Optional context information (analyzer name, operation, etc.)
        """
        if not error_message:
            return

        error_entry = error_message
        if context:
            error_entry = f"[{context}] {error_message}"

        self.errors.append(error_entry)

    def add_warning(self, warning_message: str, context: str | None = None) -> None:
        """
        Add a warning message to the results.

        Args:
            warning_message: Description of the warning
            context: Optional context information (analyzer name, operation, etc.)
        """
        if not warning_message:
            return

        warning_entry = warning_message
        if context:
            warning_entry = f"[{context}] {warning_message}"

        self.warnings.append(warning_entry)

    def has_errors(self) -> bool:
        """
        Check if any errors were encountered during analysis.

        Returns:
            True if errors exist, False otherwise
        """
        return len(self.errors) > 0

    def has_warnings(self) -> bool:
        """
        Check if any warnings were generated during analysis.

        Returns:
            True if warnings exist, False otherwise
        """
        return len(self.warnings) > 0

    def has_detections(self) -> bool:
        """
        Check if any detections were found during analysis.

        Returns:
            True if detections exist, False otherwise
        """
        return len(self.detections) > 0

    def get_hash(self, hash_type: str) -> str | None:
        """
        Retrieve a specific hash value by type.

        Args:
            hash_type: Type of hash to retrieve (case-insensitive)

        Returns:
            Hash value if found, None otherwise
        """
        return self.hashes.get(hash_type.lower())

    def get_detections_by_type(self, detection_type: str) -> list[dict[str, Any]]:
        """
        Retrieve all detections of a specific type.

        Args:
            detection_type: Type of detection to filter by

        Returns:
            List of detection dictionaries matching the specified type
        """
        return [d for d in self.detections if d.get("type") == detection_type]

    def get_detections_by_severity(self, severity: str) -> list[dict[str, Any]]:
        """
        Retrieve all detections of a specific severity level.

        Args:
            severity: Severity level to filter by

        Returns:
            List of detection dictionaries matching the specified severity
        """
        return [d for d in self.detections if d.get("severity") == severity.lower()]

    def merge(self, other: "AnalysisResult") -> None:
        """
        Merge another AnalysisResult into this one.

        This method combines results from multiple analyzers, ensuring
        no data loss. Conflicts are resolved by keeping existing values.

        Args:
            other: Another AnalysisResult to merge into this one

        Raises:
            ValueError: If attempting to merge results from different files
        """
        if self.file_path != other.file_path:
            raise ValueError(
                f"Cannot merge results from different files: {self.file_path} != {other.file_path}"
            )

        # Merge dictionaries (no overwrites)
        self.file_info = {**self.file_info, **other.file_info}
        self.format_info = {**self.format_info, **other.format_info}
        self.security = {**self.security, **other.security}
        self.hashes = {**self.hashes, **other.hashes}

        # Extend lists
        self.detections.extend(other.detections)
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)

        # Update execution time (cumulative)
        if other.execution_time:
            if self.execution_time:
                self.execution_time += other.execution_time
            else:
                self.execution_time = other.execution_time

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnalysisResult":
        """
        Create an AnalysisResult instance from a dictionary.

        Args:
            data: Dictionary containing analysis result data

        Returns:
            New AnalysisResult instance

        Raises:
            KeyError: If required fields are missing
        """
        return cls(
            file_path=Path(data["file_path"]),
            file_format=data["file_format"],
            timestamp=data.get("timestamp", datetime.now(UTC).isoformat()),
            file_info=data.get("file_info", {}),
            format_info=data.get("format_info", {}),
            security=data.get("security", {}),
            hashes=data.get("hashes", {}),
            detections=data.get("detections", []),
            errors=data.get("errors", []),
            warnings=data.get("warnings", []),
            execution_time=data.get("execution_time"),
        )

    @classmethod
    def from_json(cls, json_string: str) -> "AnalysisResult":
        """
        Create an AnalysisResult instance from a JSON string.

        Args:
            json_string: JSON string containing analysis result data

        Returns:
            New AnalysisResult instance

        Raises:
            json.JSONDecodeError: If JSON string is malformed
            KeyError: If required fields are missing
        """
        data = json.loads(json_string)
        return cls.from_dict(data)

    def __str__(self) -> str:
        """
        Return a human-readable string representation.

        Returns:
            String summary of the analysis result
        """
        return (
            f"AnalysisResult(file={Path(self.file_path).name}, "
            f"format={self.file_format}, "
            f"hashes={len(self.hashes)}, "
            f"detections={len(self.detections)}, "
            f"errors={len(self.errors)}, "
            f"warnings={len(self.warnings)})"
        )

    def __repr__(self) -> str:
        """
        Return a detailed string representation for debugging.

        Returns:
            Detailed string representation
        """
        return (
            f"AnalysisResult("
            f"file_path={self.file_path!r}, "
            f"file_format={self.file_format!r}, "
            f"timestamp={self.timestamp!r}, "
            f"hashes={list(self.hashes.keys())}, "
            f"detections={len(self.detections)}, "
            f"errors={len(self.errors)}, "
            f"warnings={len(self.warnings)}, "
            f"execution_time={self.execution_time})"
        )
