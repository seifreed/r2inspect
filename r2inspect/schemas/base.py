#!/usr/bin/env python3
"""
Base Pydantic Schemas for Type-Safe Results

This module provides the foundational Pydantic models for all r2inspect analyzers,
ensuring type safety, validation, and IDE support.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AnalysisResultBase(BaseModel):
    """
    Base result model for all analyzers.

    This is the foundational schema that all analyzer results inherit from.
    It provides common fields and validation that apply to every analysis.

    Attributes:
        available: Whether the analyzer executed successfully
        error: Error message if analyzer failed
        execution_time: Execution time in seconds
        timestamp: When the analysis was performed
        analyzer_name: Name of the analyzer that produced this result

    Example:
        >>> result = AnalysisResultBase(
        ...     available=True,
        ...     execution_time=0.5,
        ...     analyzer_name="pe"
        ... )
        >>> print(result.available)
        True
    """

    available: bool = Field(..., description="Whether the analyzer executed successfully")

    error: str | None = Field(None, description="Error message if analyzer failed")

    execution_time: float | None = Field(None, ge=0.0, description="Execution time in seconds")

    timestamp: datetime | None = Field(
        default_factory=datetime.utcnow, description="When the analysis was performed"
    )

    analyzer_name: str | None = Field(
        None, description="Name of the analyzer that produced this result"
    )

    class Config:
        """Pydantic configuration"""

        # Allow extra fields for backward compatibility
        extra = "allow"
        # Use JSON serialization
        json_encoders = {datetime: lambda v: v.isoformat()}
        # Enable validation on assignment
        validate_assignment = True
        # Use enum values instead of enum objects
        use_enum_values = True

    @field_validator("execution_time")
    @classmethod
    def validate_execution_time(cls, v: float | None) -> float | None:
        """Validate that execution time is non-negative"""
        if v is not None and v < 0:
            raise ValueError("execution_time must be non-negative")
        return v

    @field_validator("analyzer_name")
    @classmethod
    def validate_analyzer_name(cls, v: str | None) -> str | None:
        """Normalize analyzer name to lowercase"""
        if v is not None:
            return v.lower().strip()
        return v

    def model_dump_safe(self, **kwargs) -> dict[str, Any]:
        """
        Safely dump model to dict, handling None values appropriately.

        Args:
            **kwargs: Additional arguments to pass to model_dump

        Returns:
            Dictionary representation of the model
        """
        return self.model_dump(exclude_none=True, **kwargs)

    def to_json(self, **kwargs) -> str:
        """
        Convert model to JSON string.

        Args:
            **kwargs: Additional arguments to pass to model_dump_json

        Returns:
            JSON string representation
        """
        return self.model_dump_json(exclude_none=True, **kwargs)


class FileInfoBase(BaseModel):
    """
    Base file information that may be included in analysis results.

    Attributes:
        file_size: Size of file in bytes
        file_path: Path to the analyzed file
        file_extension: File extension (without dot)
    """

    file_size: int | None = Field(None, ge=0, description="Size of file in bytes")

    file_path: str | None = Field(None, description="Path to the analyzed file")

    file_extension: str | None = Field(None, description="File extension (without dot)")

    @field_validator("file_extension")
    @classmethod
    def normalize_extension(cls, v: str | None) -> str | None:
        """Normalize file extension to lowercase without dot"""
        if v is not None:
            # Remove dots and spaces, convert to lowercase
            cleaned = v.strip()
            while cleaned.startswith("."):
                cleaned = cleaned[1:]
            return cleaned.lower().strip()
        return v
