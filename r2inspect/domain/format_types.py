"""Domain format types - pure data structures for binary formats.

These dataclasses represent format-specific concepts (PE, ELF, Mach-O).
They use only stdlib imports to maintain domain isolation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class SectionInfo:
    """Information about a binary section."""

    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    entropy: float | None = None
    permissions: str | None = None
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = False
    flags: str | None = None
    suspicious_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def is_suspicious(self) -> bool:
        """Check if section has any suspicious indicators."""
        return len(self.suspicious_indicators) > 0

    def has_permission(self, permission: str) -> bool:
        """Check if section has a specific permission."""
        perm_map = {
            "r": self.is_readable,
            "w": self.is_writable,
            "x": self.is_executable,
        }
        return perm_map.get(permission.lower(), False)


@dataclass
class SecurityFeatures:
    """Security features detected in a binary."""

    aslr: bool = False
    dep: bool = False
    seh: bool = False
    guard_cf: bool = False
    authenticode: bool = False
    nx: bool = False
    stack_canary: bool = False
    canary: bool = False
    pie: bool = False
    relro: str | bool = False
    rpath: bool = False
    runpath: bool = False
    fortify: bool = False
    high_entropy_va: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def get_enabled_features(self) -> list[str]:
        """Get list of enabled security features."""
        enabled: list[str] = []
        data = asdict(self)
        for field_name, value in data.items():
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

        if self.relro == "full":
            score += 5
        elif self.relro == "partial" or self.relro is True:
            score += 2

        return min(score, 100)


__all__ = ["SectionInfo", "SecurityFeatures"]
