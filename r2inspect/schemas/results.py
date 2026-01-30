#!/usr/bin/env python3
"""
Dataclass-based Analysis Result Schemas

This module provides dataclasses for type-safe analysis results using Python's
dataclasses module. These complement the existing Pydantic schemas by offering
a lighter-weight alternative with built-in dict conversion.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)

Usage:
    from r2inspect.schemas.results import (
        FileInfo,
        HashingResult,
        SecurityFeatures,
        AnalysisResult,
    )

    # Create typed result
    file_info = FileInfo(
        name="malware.exe",
        path="/path/to/malware.exe",
        size=1024,
        md5="abc123...",
        sha256="def456...",
    )

    # Convert to dict
    data = file_info.to_dict()
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class FileInfo:
    """
    Basic file information from analysis.

    Attributes:
        name: File name
        path: Full file path
        size: File size in bytes
        md5: MD5 hash
        sha1: SHA1 hash
        sha256: SHA256 hash
        file_type: Detected file type (PE, ELF, Mach-O, etc.)
        architecture: CPU architecture (x86, x64, arm, etc.)
        bits: Architecture bit width (32 or 64)
        endian: Byte order (little or big)
        mime_type: MIME type of the file
    """

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

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class HashingResult:
    """
    Results from all hashing analyzers.

    Contains results from fuzzy hashing and similarity detection algorithms.

    Attributes:
        ssdeep: SSDeep fuzzy hash
        tlsh: TLSH locality-sensitive hash
        imphash: Import hash (PE files)
        impfuzzy: Import fuzzy hash (PE files)
        ccbhash: Control flow graph hash
        simhash: Similarity hash
        telfhash: Telfhash (ELF files)
        rich_hash: Rich header hash (PE files)
        machoc_hash: MACHOC function hash
    """

    ssdeep: str = ""
    tlsh: str = ""
    imphash: str = ""
    impfuzzy: str = ""
    ccbhash: str = ""
    simhash: str = ""
    telfhash: str = ""
    rich_hash: str = ""
    machoc_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)

    def has_hash(self, hash_type: str) -> bool:
        """Check if a specific hash type has a value."""
        value = getattr(self, hash_type, "")
        return bool(value and value.strip())


@dataclass
class SecurityFeatures:
    """
    Security features detected in the binary.

    Represents exploit mitigations and security characteristics.

    Attributes:
        nx: No Execute / DEP enabled
        pie: Position Independent Executable
        canary: Stack canary protection
        relro: Relocation Read-Only (none, partial, full)
        aslr: Address Space Layout Randomization
        seh: Structured Exception Handling (PE)
        guard_cf: Control Flow Guard (PE)
        authenticode: Authenticode signature present (PE)
        fortify: Fortify source enabled (ELF)
        rpath: RPATH present (ELF) - can be security issue
        runpath: RUNPATH present (ELF)
        high_entropy_va: High entropy VA enabled (ASLR enhancement)
    """

    nx: bool = False
    pie: bool = False
    canary: bool = False
    relro: str = ""
    aslr: bool = False
    seh: bool = False
    guard_cf: bool = False
    authenticode: bool = False
    fortify: bool = False
    rpath: bool = False
    runpath: bool = False
    high_entropy_va: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)

    def get_enabled_features(self) -> list[str]:
        """Get list of enabled security features."""
        enabled = []
        for name, value in asdict(self).items():
            if isinstance(value, bool) and value:
                enabled.append(name)
            elif name == "relro" and value in ("partial", "full"):
                enabled.append(f"relro_{value}")
        return enabled

    def security_score(self) -> int:
        """
        Calculate a basic security score (0-100).

        Higher score indicates better security posture.
        """
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
        elif self.relro == "partial":
            score += 2

        return min(score, 100)


@dataclass
class SectionInfo:
    """
    Information about a binary section.

    Attributes:
        name: Section name (e.g., .text, .data)
        virtual_address: Virtual address in memory
        virtual_size: Size in memory
        raw_size: Size on disk
        entropy: Section entropy (0.0-8.0)
        permissions: Permission string (e.g., r-x)
        is_executable: Whether section is executable
        is_writable: Whether section is writable
        is_readable: Whether section is readable
        suspicious_indicators: List of suspicious characteristics
    """

    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    entropy: float = 0.0
    permissions: str = ""
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = False
    suspicious_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)

    def is_suspicious(self) -> bool:
        """Check if section has any suspicious indicators."""
        return len(self.suspicious_indicators) > 0


@dataclass
class ImportInfo:
    """
    Information about an imported function.

    Attributes:
        name: Function name
        library: Library/DLL name
        address: Import address
        ordinal: Import ordinal (if applicable)
        category: API category (e.g., file, network, process)
        risk_score: Risk score (0-100)
        risk_level: Risk level (Minimal, Low, Medium, High, Critical)
        risk_tags: List of risk tags
    """

    name: str = ""
    library: str = ""
    address: str = ""
    ordinal: int = 0
    category: str = ""
    risk_score: int = 0
    risk_level: str = "Low"
    risk_tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class ExportInfo:
    """
    Information about an exported function.

    Attributes:
        name: Function name
        address: Export address
        ordinal: Export ordinal
        size: Function size (if known)
    """

    name: str = ""
    address: str = ""
    ordinal: int = 0
    size: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class YaraMatch:
    """
    Information about a YARA rule match.

    Attributes:
        rule: Rule name that matched
        namespace: Rule namespace
        tags: Rule tags
        meta: Rule metadata
        strings: List of matched strings with offsets
    """

    rule: str = ""
    namespace: str = ""
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class StringInfo:
    """
    Information about a string found in the binary.

    Attributes:
        value: String value
        address: Address where string was found
        length: String length
        encoding: String encoding (ascii, unicode, etc.)
        is_suspicious: Whether string appears suspicious
    """

    value: str = ""
    address: str = ""
    length: int = 0
    encoding: str = ""
    is_suspicious: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class FunctionInfo:
    """
    Information about a function in the binary.

    Attributes:
        name: Function name
        address: Function start address
        size: Function size in bytes
        complexity: Cyclomatic complexity
        basic_blocks: Number of basic blocks
        call_refs: Number of call references
        data_refs: Number of data references
    """

    name: str = ""
    address: int = 0
    size: int = 0
    complexity: int = 0
    basic_blocks: int = 0
    call_refs: int = 0
    data_refs: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class AntiAnalysisResult:
    """
    Results from anti-analysis detection.

    Attributes:
        anti_debug: Anti-debugging techniques detected
        anti_vm: Anti-virtualization techniques detected
        anti_sandbox: Anti-sandbox techniques detected
        timing_checks: Timing-based evasion detected
        techniques: List of specific techniques found
    """

    anti_debug: bool = False
    anti_vm: bool = False
    anti_sandbox: bool = False
    timing_checks: bool = False
    techniques: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)

    def has_evasion(self) -> bool:
        """Check if any evasion technique was detected."""
        return self.anti_debug or self.anti_vm or self.anti_sandbox or self.timing_checks


@dataclass
class PackerResult:
    """
    Results from packer detection.

    Attributes:
        is_packed: Whether the file appears packed
        packer_type: Detected packer name/type
        confidence: Detection confidence (0-100)
        indicators: List of packer indicators found
    """

    is_packed: bool = False
    packer_type: str = ""
    confidence: int = 0
    indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class CryptoResult:
    """
    Results from cryptographic detection.

    Attributes:
        algorithms: List of detected crypto algorithms
        constants: List of crypto constants found
        functions: List of crypto-related functions
    """

    algorithms: list[dict[str, Any]] = field(default_factory=list)
    constants: list[dict[str, Any]] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)

    def has_crypto(self) -> bool:
        """Check if any cryptography was detected."""
        return bool(self.algorithms or self.constants)


@dataclass
class Indicator:
    """
    A suspicious indicator found during analysis.

    Attributes:
        type: Indicator type (e.g., Packer, Anti-Debug, Suspicious API)
        description: Human-readable description
        severity: Severity level (Low, Medium, High, Critical)
    """

    type: str = ""
    description: str = ""
    severity: str = "Low"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class AnalysisResult:
    """
    Complete analysis result containing all analysis data.

    This is the top-level result dataclass that aggregates all analysis
    results from various analyzers.

    Attributes:
        file_info: Basic file information
        hashing: Hash values from various algorithms
        security: Security features detected
        imports: List of imported functions
        exports: List of exported functions
        sections: List of binary sections
        strings: List of interesting strings
        yara_matches: List of YARA rule matches
        functions: List of analyzed functions
        anti_analysis: Anti-analysis detection results
        packer: Packer detection results
        crypto: Cryptographic detection results
        indicators: List of suspicious indicators
        error: Error message if analysis failed
        timestamp: When analysis was performed
        execution_time: Total analysis time in seconds
    """

    file_info: FileInfo = field(default_factory=FileInfo)
    hashing: HashingResult = field(default_factory=HashingResult)
    security: SecurityFeatures = field(default_factory=SecurityFeatures)
    imports: list[ImportInfo] = field(default_factory=list)
    exports: list[ExportInfo] = field(default_factory=list)
    sections: list[SectionInfo] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    yara_matches: list[YaraMatch] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    anti_analysis: AntiAnalysisResult = field(default_factory=AntiAnalysisResult)
    packer: PackerResult = field(default_factory=PackerResult)
    crypto: CryptoResult = field(default_factory=CryptoResult)
    indicators: list[Indicator] = field(default_factory=list)
    error: str | None = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    execution_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary representation.

        Handles nested dataclasses and datetime serialization.
        """
        result: dict[str, Any] = {}

        # Convert file_info
        result["file_info"] = self.file_info.to_dict()

        # Convert hashing
        result["hashing"] = self.hashing.to_dict()

        # Convert security
        result["security"] = self.security.to_dict()

        # Convert imports list
        result["imports"] = [imp.to_dict() for imp in self.imports]

        # Convert exports list
        result["exports"] = [exp.to_dict() for exp in self.exports]

        # Convert sections list
        result["sections"] = [sec.to_dict() for sec in self.sections]

        # Strings are already plain strings
        result["strings"] = self.strings

        # Convert yara_matches list
        result["yara_matches"] = [match.to_dict() for match in self.yara_matches]

        # Convert functions list
        result["functions"] = [func.to_dict() for func in self.functions]

        # Convert anti_analysis
        result["anti_analysis"] = self.anti_analysis.to_dict()

        # Convert packer
        result["packer"] = self.packer.to_dict()

        # Convert crypto
        result["crypto"] = self.crypto.to_dict()

        # Convert indicators list
        result["indicators"] = [ind.to_dict() for ind in self.indicators]

        # Error (optional)
        result["error"] = self.error

        # Timestamp - convert to ISO format string
        result["timestamp"] = self.timestamp.isoformat()

        # Execution time
        result["execution_time"] = self.execution_time

        return result

    def has_error(self) -> bool:
        """Check if analysis encountered an error."""
        return self.error is not None

    def is_suspicious(self) -> bool:
        """Check if the binary has any suspicious indicators."""
        return len(self.indicators) > 0 or self.anti_analysis.has_evasion() or self.packer.is_packed

    def get_high_severity_indicators(self) -> list[Indicator]:
        """Get all high or critical severity indicators."""
        return [ind for ind in self.indicators if ind.severity in ("High", "Critical")]

    def summary(self) -> dict[str, Any]:
        """
        Generate a brief summary of the analysis.

        Returns:
            Dictionary with key findings
        """
        return {
            "file_name": self.file_info.name,
            "file_type": self.file_info.file_type,
            "file_size": self.file_info.size,
            "md5": self.file_info.md5,
            "sha256": self.file_info.sha256,
            "is_packed": self.packer.is_packed,
            "packer_type": self.packer.packer_type if self.packer.is_packed else None,
            "has_crypto": self.crypto.has_crypto(),
            "has_evasion": self.anti_analysis.has_evasion(),
            "security_score": self.security.security_score(),
            "total_imports": len(self.imports),
            "total_exports": len(self.exports),
            "total_sections": len(self.sections),
            "yara_matches_count": len(self.yara_matches),
            "indicators_count": len(self.indicators),
            "high_severity_count": len(self.get_high_severity_indicators()),
        }


# Convenience function for creating AnalysisResult from raw dict
def from_dict(data: dict[str, Any]) -> AnalysisResult:
    """
    Create an AnalysisResult from a dictionary.

    This is useful for deserializing analysis results from JSON or
    converting legacy dict-based results.

    Args:
        data: Dictionary containing analysis data

    Returns:
        AnalysisResult instance
    """
    result = AnalysisResult()
    _load_file_info(result, data)
    _load_hashing(result, data)
    _load_security(result, data)
    _load_imports(result, data)
    _load_exports(result, data)
    _load_sections(result, data)
    _load_strings(result, data)
    _load_yara_matches(result, data)
    _load_functions(result, data)
    _load_anti_analysis(result, data)
    _load_packer(result, data)
    _load_crypto(result, data)
    _load_indicators(result, data)
    _load_error(result, data)
    _load_timestamp(result, data)
    _load_execution_time(result, data)
    return result


def _load_file_info(result: AnalysisResult, data: dict[str, Any]) -> None:
    fi = data.get("file_info")
    if not fi:
        return
    result.file_info = FileInfo(
        name=fi.get("name", ""),
        path=fi.get("path", ""),
        size=fi.get("size", 0),
        md5=fi.get("md5", ""),
        sha1=fi.get("sha1", ""),
        sha256=fi.get("sha256", ""),
        file_type=fi.get("file_type", ""),
        architecture=fi.get("architecture", ""),
        bits=fi.get("bits", 0),
        endian=fi.get("endian", ""),
        mime_type=fi.get("mime_type", ""),
    )


def _load_hashing(result: AnalysisResult, data: dict[str, Any]) -> None:
    h = data.get("hashing")
    if not h:
        return
    result.hashing = HashingResult(
        ssdeep=h.get("ssdeep", ""),
        tlsh=h.get("tlsh", ""),
        imphash=h.get("imphash", ""),
        impfuzzy=h.get("impfuzzy", ""),
        ccbhash=h.get("ccbhash", ""),
        simhash=h.get("simhash", ""),
        telfhash=h.get("telfhash", ""),
        rich_hash=h.get("rich_hash", ""),
        machoc_hash=h.get("machoc_hash", ""),
    )


def _load_security(result: AnalysisResult, data: dict[str, Any]) -> None:
    s = data.get("security")
    if not s:
        return
    result.security = SecurityFeatures(
        nx=s.get("nx", False),
        pie=s.get("pie", False),
        canary=s.get("canary", False),
        relro=s.get("relro", ""),
        aslr=s.get("aslr", False),
        seh=s.get("seh", False),
        guard_cf=s.get("guard_cf", False),
        authenticode=s.get("authenticode", False),
        fortify=s.get("fortify", False),
        rpath=s.get("rpath", False),
        runpath=s.get("runpath", False),
        high_entropy_va=s.get("high_entropy_va", False),
    )


def _load_imports(result: AnalysisResult, data: dict[str, Any]) -> None:
    imports = data.get("imports")
    if not imports:
        return
    result.imports = [
        ImportInfo(
            name=imp.get("name", ""),
            library=imp.get("library", ""),
            address=imp.get("address", ""),
            ordinal=imp.get("ordinal", 0),
            category=imp.get("category", ""),
            risk_score=imp.get("risk_score", 0),
            risk_level=imp.get("risk_level", "Low"),
            risk_tags=imp.get("risk_tags", []),
        )
        for imp in imports
    ]


def _load_exports(result: AnalysisResult, data: dict[str, Any]) -> None:
    exports = data.get("exports")
    if not exports:
        return
    result.exports = [
        ExportInfo(
            name=exp.get("name", ""),
            address=exp.get("address", ""),
            ordinal=exp.get("ordinal", 0),
            size=exp.get("size", 0),
        )
        for exp in exports
    ]


def _load_sections(result: AnalysisResult, data: dict[str, Any]) -> None:
    sections = data.get("sections")
    if not sections:
        return
    result.sections = [
        SectionInfo(
            name=sec.get("name", ""),
            virtual_address=sec.get("virtual_address", 0),
            virtual_size=sec.get("virtual_size", 0),
            raw_size=sec.get("raw_size", 0),
            entropy=sec.get("entropy", 0.0),
            permissions=sec.get("permissions", ""),
            is_executable=sec.get("is_executable", False),
            is_writable=sec.get("is_writable", False),
            is_readable=sec.get("is_readable", False),
            suspicious_indicators=sec.get("suspicious_indicators", []),
        )
        for sec in sections
    ]


def _load_strings(result: AnalysisResult, data: dict[str, Any]) -> None:
    if "strings" in data:
        result.strings = data["strings"]


def _load_yara_matches(result: AnalysisResult, data: dict[str, Any]) -> None:
    matches = data.get("yara_matches")
    if not matches:
        return
    result.yara_matches = [
        YaraMatch(
            rule=match.get("rule", ""),
            namespace=match.get("namespace", ""),
            tags=match.get("tags", []),
            meta=match.get("meta", {}),
            strings=match.get("strings", []),
        )
        for match in matches
    ]


def _load_functions(result: AnalysisResult, data: dict[str, Any]) -> None:
    functions = data.get("functions")
    if not functions:
        return
    result.functions = [
        FunctionInfo(
            name=func.get("name", ""),
            address=func.get("address", 0),
            size=func.get("size", 0),
            complexity=func.get("complexity", 0),
            basic_blocks=func.get("basic_blocks", 0),
            call_refs=func.get("call_refs", 0),
            data_refs=func.get("data_refs", 0),
        )
        for func in functions
    ]


def _load_anti_analysis(result: AnalysisResult, data: dict[str, Any]) -> None:
    aa = data.get("anti_analysis")
    if not aa:
        return
    result.anti_analysis = AntiAnalysisResult(
        anti_debug=aa.get("anti_debug", False),
        anti_vm=aa.get("anti_vm", False),
        anti_sandbox=aa.get("anti_sandbox", False),
        timing_checks=aa.get("timing_checks", False),
        techniques=aa.get("techniques", []),
    )


def _load_packer(result: AnalysisResult, data: dict[str, Any]) -> None:
    p = data.get("packer")
    if not p:
        return
    result.packer = PackerResult(
        is_packed=p.get("is_packed", False),
        packer_type=p.get("packer_type", ""),
        confidence=p.get("confidence", 0),
        indicators=p.get("indicators", []),
    )


def _load_crypto(result: AnalysisResult, data: dict[str, Any]) -> None:
    c = data.get("crypto")
    if not c:
        return
    result.crypto = CryptoResult(
        algorithms=c.get("algorithms", []),
        constants=c.get("constants", []),
        functions=c.get("functions", []),
    )


def _load_indicators(result: AnalysisResult, data: dict[str, Any]) -> None:
    indicators = data.get("indicators")
    if not indicators:
        return
    result.indicators = [
        Indicator(
            type=ind.get("type", ""),
            description=ind.get("description", ""),
            severity=ind.get("severity", "Low"),
        )
        for ind in indicators
    ]


def _load_error(result: AnalysisResult, data: dict[str, Any]) -> None:
    result.error = data.get("error")


def _load_timestamp(result: AnalysisResult, data: dict[str, Any]) -> None:
    ts = data.get("timestamp")
    if ts is None:
        return
    if isinstance(ts, str):
        try:
            result.timestamp = datetime.fromisoformat(ts)
        except ValueError:
            return
    elif isinstance(ts, datetime):
        result.timestamp = ts


def _load_execution_time(result: AnalysisResult, data: dict[str, Any]) -> None:
    result.execution_time = data.get("execution_time", 0.0)
