"""Dataclass-based result schemas for analysis output."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .results_summary import (
    analysis_result_to_dict as _analysis_result_to_dict,
    build_summary as _build_summary,
    high_severity_indicators as _high_severity_indicators,
    is_suspicious as _is_suspicious,
)
from ..domain.entities import (
    AntiAnalysisResult,
    CryptoResult,
    ExportInfo,
    FileInfo,
    FunctionInfo,
    HashingResult,
    ImportInfo,
    Indicator,
    PackerResult,
    YaraMatch,
)
from ..domain.format_types import SecurityFeatures
from .format import SectionInfo


def _default_security_features() -> SecurityFeatures:
    return SecurityFeatures(
        aslr=False,
        dep=False,
        seh=False,
        guard_cf=False,
        authenticode=False,
        nx=False,
        stack_canary=False,
        canary=False,
        pie=False,
        relro=False,
        rpath=False,
        runpath=False,
        fortify=False,
        high_entropy_va=False,
    )


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
    security: SecurityFeatures = field(default_factory=_default_security_features)
    imports: list[ImportInfo] = field(default_factory=list)
    exports: list[ExportInfo] = field(default_factory=list)
    sections: list[SectionInfo] = field(default_factory=list)
    strings: list[Any] = field(default_factory=list)
    yara_matches: list[YaraMatch] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    anti_analysis: AntiAnalysisResult = field(default_factory=AntiAnalysisResult)
    packer: PackerResult = field(default_factory=PackerResult)
    crypto: CryptoResult = field(default_factory=CryptoResult)
    indicators: list[Indicator] = field(default_factory=list)
    error: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    execution_time: float = 0.0
    _raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Return the original pipeline dict when available, else serialize typed fields."""
        if self._raw:
            return dict(self._raw)
        return _analysis_result_to_dict(self)

    def has_error(self) -> bool:
        """Check if analysis encountered an error."""
        return self.error is not None

    def is_suspicious(self) -> bool:
        """Check if the binary has any suspicious indicators."""
        return _is_suspicious(self)

    def get_high_severity_indicators(self) -> list[Indicator]:
        """Get all high or critical severity indicators."""
        return _high_severity_indicators(self)

    def summary(self) -> dict[str, Any]:
        return _build_summary(self)
