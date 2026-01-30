#!/usr/bin/env python3
"""
Format Analyzer Pydantic Schemas

Schemas for binary format analyzers (PE, ELF, Mach-O)

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from pydantic import BaseModel, Field, field_validator

from .base import AnalysisResultBase


class SectionInfo(BaseModel):
    """
    Information about a binary section.

    Represents a single section in a PE, ELF, or Mach-O binary.

    Attributes:
        name: Section name (e.g., ".text", ".data")
        virtual_address: Virtual address in memory
        virtual_size: Virtual size in memory
        raw_size: Raw size on disk
        entropy: Section entropy (0.0-8.0)
        permissions: Permission flags (e.g., "r-x")
        is_executable: Whether section is executable
        is_writable: Whether section is writable
        is_readable: Whether section is readable
        flags: Raw permission flags
        suspicious_indicators: List of suspicious characteristics
    """

    name: str = Field(..., description="Section name")

    virtual_address: int = Field(0, ge=0, description="Virtual address in memory")

    virtual_size: int = Field(0, ge=0, description="Virtual size in memory")

    raw_size: int = Field(0, ge=0, description="Raw size on disk")

    entropy: float | None = Field(None, ge=0.0, le=8.0, description="Section entropy (0.0-8.0)")

    permissions: str | None = Field(None, description="Permission flags (e.g., 'r-x')")

    is_executable: bool = Field(False, description="Whether section is executable")

    is_writable: bool = Field(False, description="Whether section is writable")

    is_readable: bool = Field(False, description="Whether section is readable")

    flags: str | None = Field(None, description="Raw permission flags")

    suspicious_indicators: list[str] = Field(
        default_factory=list, description="List of suspicious characteristics"
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate section name is not empty"""
        if not v or not v.strip():
            raise ValueError("Section name cannot be empty")
        return v.strip()

    @field_validator("entropy")
    @classmethod
    def validate_entropy(cls, v: float | None) -> float | None:
        """Validate entropy is within valid range"""
        if v is not None and (v < 0.0 or v > 8.0):
            raise ValueError("Entropy must be between 0.0 and 8.0")
        return v

    def is_suspicious(self) -> bool:
        """Check if section has any suspicious indicators"""
        return len(self.suspicious_indicators) > 0

    def has_permission(self, permission: str) -> bool:
        """
        Check if section has a specific permission.

        Args:
            permission: Permission to check ('r', 'w', or 'x')

        Returns:
            True if section has the permission
        """
        perm_map = {
            "r": self.is_readable,
            "w": self.is_writable,
            "x": self.is_executable,
        }
        return perm_map.get(permission.lower(), False)


class SecurityFeatures(BaseModel):
    """
    Security features detected in binary.

    Attributes:
        aslr: Address Space Layout Randomization enabled
        dep: Data Execution Prevention (NX) enabled
        nx: No Execute bit set (ELF)
        seh: Structured Exception Handling enabled
        guard_cf: Control Flow Guard enabled
        authenticode: Authenticode signature present
        stack_canary: Stack canary protection enabled
        pie: Position Independent Executable (ELF)
        relro: RELRO protection enabled (ELF)
        rpath: RPATH present (ELF)
        runpath: RUNPATH present (ELF)
    """

    # PE security features
    aslr: bool = Field(False, description="ASLR enabled")
    dep: bool = Field(False, description="DEP/NX enabled")
    seh: bool = Field(False, description="SEH enabled")
    guard_cf: bool = Field(False, description="Control Flow Guard enabled")
    authenticode: bool = Field(False, description="Authenticode signature present")

    # ELF security features
    nx: bool = Field(False, description="NX bit set (ELF)")
    stack_canary: bool = Field(False, description="Stack canary enabled")
    pie: bool = Field(False, description="PIE enabled (ELF)")
    relro: bool = Field(False, description="RELRO enabled (ELF)")
    rpath: bool = Field(False, description="RPATH present (ELF)")
    runpath: bool = Field(False, description="RUNPATH present (ELF)")

    def get_enabled_features(self) -> list[str]:
        """Get list of enabled security features"""
        return [field_name for field_name, value in self.model_dump().items() if value is True]

    def security_score(self) -> int:
        """
        Calculate security score (0-100) based on enabled features.

        Returns:
            Security score as integer
        """
        enabled = len(self.get_enabled_features())
        total = len(self.model_fields)
        return int((enabled / total) * 100) if total > 0 else 0


class FormatAnalysisResult(AnalysisResultBase):
    """
    Result from format analyzers (PE, ELF, Mach-O).

    Represents the analysis of binary file format information.

    Attributes:
        format: Binary format (PE, ELF, Mach-O, PE32, PE32+, ELF32, ELF64)
        architecture: CPU architecture (x86, x64, arm, etc.)
        bits: Architecture bit width (32 or 64)
        endian: Endianness (little, big)
        machine: Machine type
        type: Binary type (exe, dll, shared object, etc.)
        entry_point: Entry point address
        image_base: Image base address
        sections: List of sections
        security_features: Security features detected
        compile_time: Compilation timestamp
        compiler: Compiler information
    """

    format: str = Field(..., description="Binary format (PE, ELF, Mach-O)")

    architecture: str | None = Field(None, description="CPU architecture")

    bits: int | None = Field(None, description="32 or 64 bit")

    endian: str | None = Field(None, description="Endianness (little/big)")

    machine: str | None = Field(None, description="Machine type")

    type: str | None = Field(None, description="Binary type (exe, dll, shared object)")

    entry_point: int | None = Field(None, ge=0, description="Entry point address")

    image_base: int | None = Field(None, ge=0, description="Image base address")

    sections: list[SectionInfo] = Field(default_factory=list, description="List of sections")

    security_features: SecurityFeatures | None = Field(
        None, description="Security features detected"
    )

    compile_time: str | None = Field(None, description="Compilation timestamp")

    compiler: str | None = Field(None, description="Compiler information")

    subsystem: str | None = Field(None, description="Subsystem (Windows)")

    is_dll: bool | None = Field(None, description="Whether binary is a DLL")

    is_executable: bool | None = Field(None, description="Whether binary is executable")

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        """Validate format is one of the known types"""
        valid_formats = {
            "PE",
            "ELF",
            "MACH-O",
            "MACHO",
            "PE32",
            "PE32+",
            "ELF32",
            "ELF64",
            "MACH-O32",
            "MACH-O64",
        }
        normalized = v.upper().strip()
        if normalized not in valid_formats:
            raise ValueError(f"format must be one of {valid_formats}, got '{v}'")
        return normalized

    @field_validator("bits")
    @classmethod
    def validate_bits(cls, v: int | None) -> int | None:
        """Validate bits is 32 or 64"""
        if v is not None and v not in {32, 64}:
            raise ValueError("bits must be 32 or 64")
        return v

    @field_validator("endian")
    @classmethod
    def validate_endian(cls, v: str | None) -> str | None:
        """Validate endianness"""
        if v is not None:
            normalized = v.lower().strip()
            if normalized not in {"little", "big", "le", "be"}:
                raise ValueError("endian must be 'little', 'big', 'le', or 'be'")
            return normalized
        return v

    def get_executable_sections(self) -> list[SectionInfo]:
        """Get all executable sections"""
        return [s for s in self.sections if s.is_executable]

    def get_writable_sections(self) -> list[SectionInfo]:
        """Get all writable sections"""
        return [s for s in self.sections if s.is_writable]

    def get_suspicious_sections(self) -> list[SectionInfo]:
        """Get all sections with suspicious indicators"""
        return [s for s in self.sections if s.is_suspicious()]

    def is_64bit(self) -> bool:
        """Check if binary is 64-bit"""
        return self.bits == 64

    def is_pe(self) -> bool:
        """Check if binary is PE format"""
        return self.format.startswith("PE")

    def is_elf(self) -> bool:
        """Check if binary is ELF format"""
        return self.format.startswith("ELF")

    def is_macho(self) -> bool:
        """Check if binary is Mach-O format"""
        return "MACH" in self.format.upper()
