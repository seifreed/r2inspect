"""Domain entities - pure business data structures.

These dataclasses represent core domain concepts with no external dependencies.
They form the innermost layer of Clean Architecture and should not import
from any outer layer (infrastructure, adapters, schemas, etc.).

This module contains only stdlib imports to ensure domain isolation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, cast

from .text_helpers import has_text

if TYPE_CHECKING:
    from _typeshed import DataclassInstance


class _ToDictMixin:
    def to_dict(self) -> dict[str, Any]:
        return asdict(cast("DataclassInstance", self))


@dataclass
class FileInfo(_ToDictMixin):
    """Basic file metadata."""

    name: str = ""
    path: str = ""
    size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    file_type: str = ""
    architecture: str = ""
    bits: int = 0
    endian: str = ""
    mime_type: str = ""


@dataclass
class HashingResult(_ToDictMixin):
    """Hash values from various algorithms."""

    ssdeep: str = ""
    tlsh: str = ""
    imphash: str = ""
    impfuzzy: str = ""
    ccbhash: str = ""
    simhash: str = ""
    telfhash: str = ""
    rich_hash: str = ""
    machoc_hash: str = ""

    def has_hash(self, hash_type: str) -> bool:
        value = getattr(self, hash_type, "")
        return has_text(value)


@dataclass
class ImportInfo(_ToDictMixin):
    """Imported function information."""

    name: str = ""
    library: str = ""
    address: str = ""
    ordinal: int = 0
    category: str = ""
    risk_score: int = 0
    risk_level: str = "Low"
    risk_tags: list[str] = field(default_factory=list)


@dataclass
class ExportInfo(_ToDictMixin):
    """Exported function information."""

    name: str = ""
    address: str = ""
    ordinal: int = 0
    size: int = 0


@dataclass
class YaraMatch(_ToDictMixin):
    """YARA rule match result."""

    rule: str = ""
    namespace: str = ""
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class StringInfo(_ToDictMixin):
    """Extracted string information."""

    value: str = ""
    address: str = ""
    length: int = 0
    encoding: str = ""
    is_suspicious: bool = False


@dataclass
class FunctionInfo(_ToDictMixin):
    """Function analysis result."""

    name: str = ""
    address: int = 0
    size: int = 0
    complexity: int = 0
    basic_blocks: int = 0
    call_refs: int = 0
    data_refs: int = 0


@dataclass
class AntiAnalysisResult(_ToDictMixin):
    """Anti-analysis detection results."""

    anti_debug: bool = False
    anti_vm: bool = False
    anti_sandbox: bool = False
    timing_checks: bool = False
    techniques: list[dict[str, Any]] = field(default_factory=list)

    def has_evasion(self) -> bool:
        return self.anti_debug or self.anti_vm or self.anti_sandbox or self.timing_checks


@dataclass
class PackerResult(_ToDictMixin):
    """Packer detection result."""

    is_packed: bool = False
    packer_type: str = ""
    confidence: int = 0
    indicators: list[str] = field(default_factory=list)


@dataclass
class CryptoResult(_ToDictMixin):
    """Cryptographic detection result."""

    algorithms: list[dict[str, Any]] = field(default_factory=list)
    constants: list[dict[str, Any]] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)

    def has_crypto(self) -> bool:
        return bool(self.algorithms or self.constants)


@dataclass
class Indicator(_ToDictMixin):
    """Security indicator."""

    type: str = ""
    description: str = ""
    severity: str = "Low"


__all__ = [
    "FileInfo",
    "HashingResult",
    "ImportInfo",
    "ExportInfo",
    "YaraMatch",
    "StringInfo",
    "FunctionInfo",
    "AntiAnalysisResult",
    "PackerResult",
    "CryptoResult",
    "Indicator",
]
