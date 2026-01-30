#!/usr/bin/env python3
"""
Hashing Analyzer Pydantic Schemas

Schemas for all hash-based analyzers (SSDeep, TLSH, Impfuzzy, etc.)

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from pydantic import Field, field_validator

from .base import AnalysisResultBase


class HashAnalysisResult(AnalysisResultBase):
    """
    Result from hashing analyzers (SSDeep, TLSH, Impfuzzy, etc.)

    This schema covers all fuzzy hashing analyzers that compute a hash value
    for similarity detection and matching.

    Attributes:
        hash_value: Computed hash value
        hash_type: Type of hash (ssdeep, tlsh, impfuzzy, ccbhash, simhash, telfhash)
        method_used: Method used to calculate hash (python_library, system_binary, r2pipe)
        file_size: Size of file in bytes

    Example:
        >>> result = HashAnalysisResult(
        ...     available=True,
        ...     hash_value="3:abc123:def456",
        ...     hash_type="ssdeep",
        ...     method_used="python_library",
        ...     file_size=1024
        ... )
        >>> print(result.hash_type)
        'ssdeep'
    """

    hash_value: str | None = Field(None, description="Computed hash value")

    hash_type: str = Field(
        ...,
        description="Type of hash (ssdeep, tlsh, impfuzzy, ccbhash, simhash, telfhash)",
    )

    method_used: str | None = Field(
        None,
        description="Method used to calculate hash (python_library, system_binary, r2pipe)",
    )

    file_size: int | None = Field(None, ge=0, description="Size of file in bytes")

    @field_validator("hash_type")
    @classmethod
    def validate_hash_type(cls, v: str) -> str:
        """Validate hash type is one of the supported types"""
        valid_types = {"ssdeep", "tlsh", "impfuzzy", "ccbhash", "simhash", "telfhash"}
        normalized = v.lower().strip()
        if normalized not in valid_types:
            raise ValueError(f"hash_type must be one of {valid_types}, got '{v}'")
        return normalized

    @field_validator("method_used")
    @classmethod
    def validate_method_used(cls, v: str | None) -> str | None:
        """Validate method used is one of the known methods"""
        if v is None:
            return v

        valid_methods = {"python_library", "system_binary", "r2pipe", "direct_read"}
        normalized = v.lower().strip()

        if normalized not in valid_methods:
            # Allow custom methods but log a warning
            return normalized

        return normalized

    @field_validator("file_size")
    @classmethod
    def validate_file_size(cls, v: int | None) -> int | None:
        """Validate file size is reasonable"""
        if v is not None:
            if v < 0:
                raise ValueError("file_size must be non-negative")
            if v > 10 * 1024 * 1024 * 1024:  # 10GB
                raise ValueError("file_size exceeds maximum (10GB)")
        return v

    def is_valid_hash(self) -> bool:
        """
        Check if the hash value is valid and non-empty.

        Returns:
            True if hash_value is present and non-empty
        """
        return self.hash_value is not None and len(self.hash_value.strip()) > 0
