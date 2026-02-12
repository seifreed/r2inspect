#!/usr/bin/env python3
"""Binary format analyzer schemas."""

from pydantic import BaseModel, Field, field_validator

from .base import AnalysisResultBase


class SectionInfo(BaseModel):
    """Information about a binary section."""

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
        """Check if section has a specific permission."""
        perm_map = {
            "r": self.is_readable,
            "w": self.is_writable,
            "x": self.is_executable,
        }
        return perm_map.get(permission.lower(), False)

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        return self.model_dump()


class SecurityFeatures(BaseModel):
    """Security features detected in a binary."""

    # PE security features
    aslr: bool = Field(False, description="ASLR enabled")
    dep: bool = Field(False, description="DEP/NX enabled")
    seh: bool = Field(False, description="SEH enabled")
    guard_cf: bool = Field(False, description="Control Flow Guard enabled")
    authenticode: bool = Field(False, description="Authenticode signature present")

    # ELF security features
    nx: bool = Field(False, description="NX bit set (ELF)")
    stack_canary: bool = Field(False, description="Stack canary enabled")
    canary: bool = Field(False, description="Stack canary protection (alias)")
    pie: bool = Field(False, description="PIE enabled (ELF)")
    relro: str | bool = Field(False, description="RELRO enabled (ELF)")
    rpath: bool = Field(False, description="RPATH present (ELF)")
    runpath: bool = Field(False, description="RUNPATH present (ELF)")
    fortify: bool = Field(False, description="Fortify source enabled (ELF)")
    high_entropy_va: bool = Field(False, description="High entropy VA enabled")

    def get_enabled_features(self) -> list[str]:
        """Get list of enabled security features"""
        enabled: list[str] = []
        for field_name, value in self.model_dump().items():
            if field_name == "relro":
                if isinstance(value, str) and value in ("partial", "full"):
                    enabled.append(f"relro_{value}")
                elif value is True:
                    enabled.append("relro")
                continue
            if value is True:
                enabled.append(field_name)
        return enabled

    def security_score(self) -> int:
        """Calculate a basic security score (0-100)."""
        score = 0
        weights = {
            "nx": 15,
            "pie": 15,
            "canary": 15,
            "aslr": 15,
            "guard_cf": 10,
            "seh": 5,
            "authenticode": 10,
            "fortify": 5,
            "high_entropy_va": 5,
        }

        for feature, weight in weights.items():
            if getattr(self, feature, False):
                score += weight

        # RELRO scoring
        if self.relro == "full":
            score += 5
        elif self.relro == "partial" or self.relro is True:
            score += 2

        return min(score, 100)

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        return self.model_dump()


class FormatAnalysisResult(AnalysisResultBase):
    """Result from format analyzers (PE, ELF, Mach-O)."""

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
