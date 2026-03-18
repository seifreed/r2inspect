"""Overlay data analyzer."""

from typing import Any, cast

from ..abstractions import BaseAnalyzer
from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..domain.services.hashing import calculate_hashes_for_bytes
from ..domain.services.overlay_analysis import (
    build_overlay_suspicious_indicators,
    calculate_overlay_entropy,
    detect_embedded_files,
    detect_overlay_patterns,
    determine_overlay_type,
    find_all_patterns,
    has_pattern,
    looks_encrypted,
)
from ..infrastructure.logging import get_logger
from .overlay_content_support import analyze_overlay_content as _analyze_overlay_content_impl
from .overlay_parsing_support import (
    calculate_pe_end as _calculate_pe_end_impl,
    extend_end_with_certificate as _extend_end_with_certificate_impl,
    get_file_size as _get_file_size_impl,
    get_max_section_end as _get_max_section_end_impl,
    get_sections as _get_sections_impl,
    get_valid_pe_end as _get_valid_pe_end_impl,
)
from .overlay_result_support import (
    OverlayResult,
    default_overlay_result as _default_overlay_result_impl,
    populate_overlay_metadata as _populate_overlay_metadata_impl,
)
from .string_extraction import extract_ascii_from_bytes

logger = get_logger(__name__)


class OverlayAnalyzer(CommandHelperMixin, BaseAnalyzer):
    """Analyze overlay data in PE files."""

    def __init__(self, adapter: Any) -> None:
        """Initialize the analyzer."""
        super().__init__(adapter=adapter)

    def analyze(self) -> OverlayResult:  # type: ignore[override]
        """Analyze overlay data."""
        result = self._default_result()

        try:
            file_size = self._get_file_size()
            if not file_size:
                return result

            pe_end = self._get_valid_pe_end(file_size)
            if not pe_end:
                return result

            overlay_size = file_size - pe_end
            if overlay_size <= 0:
                return result

            self._populate_overlay_metadata(result, file_size, pe_end, overlay_size)
            self._analyze_overlay_content(result, pe_end, overlay_size)
            self._check_suspicious_indicators(result)
            return result

        except Exception as e:
            logger.error("Error analyzing overlay data: %s", e)
            result = self._default_result()
            result["available"] = False
            result["has_overlay"] = False
            result["error"] = str(e)
            return result

    def _default_result(self) -> OverlayResult:
        return _default_overlay_result_impl(self._init_result_structure)

    def _get_file_size(self) -> int | None:
        return _get_file_size_impl(self._cmdj)

    def _get_valid_pe_end(self, file_size: int) -> int | None:
        return _get_valid_pe_end_impl(self._calculate_pe_end, file_size)

    @staticmethod
    def _populate_overlay_metadata(
        result: OverlayResult, file_size: int, pe_end: int, overlay_size: int
    ) -> None:
        _populate_overlay_metadata_impl(result, file_size, pe_end, overlay_size)

    def _calculate_pe_end(self) -> int:
        """Calculate where the PE structure ends."""
        return _calculate_pe_end_impl(
            self._cmdj,
            logger=logger,
            get_sections_fn=self._get_sections,
            get_max_section_end_fn=self._get_max_section_end,
            extend_end_with_certificate_fn=self._extend_end_with_certificate,
        )

    def _get_sections(self) -> list[dict[str, Any]]:
        return _get_sections_impl(self._cmdj)

    @staticmethod
    def _get_max_section_end(sections: list[dict[str, Any]]) -> int:
        return _get_max_section_end_impl(sections)

    def _extend_end_with_certificate(self, max_end: int) -> int:
        return _extend_end_with_certificate_impl(self._cmdj, max_end)

    def _analyze_overlay_content(self, result: OverlayResult, offset: int, size: int) -> None:
        """Analyze the content of the overlay data."""
        _analyze_overlay_content_impl(
            cmdj=self._cmdj,
            result=cast(dict[str, Any], result),
            offset=offset,
            size=size,
            logger=logger,
            calculate_entropy_fn=self._calculate_entropy,
            calculate_hashes_fn=calculate_hashes_for_bytes,
            check_patterns_fn=self._check_patterns,
            determine_overlay_type_fn=self._determine_overlay_type,
            extract_strings_fn=self._extract_strings,
            check_file_signatures_fn=self._check_file_signatures,
        )

    def _calculate_entropy(self, data: list[int]) -> float:
        """Calculate Shannon entropy."""
        return calculate_overlay_entropy(data)

    def _check_patterns(self, data: list[int]) -> list[dict[str, Any]]:
        """Check for known patterns in overlay data."""
        return detect_overlay_patterns(data)

    def _determine_overlay_type(self, patterns: list[dict[str, Any]], data: list[int]) -> str:
        """Determine the most likely type of overlay data."""
        return determine_overlay_type(patterns, data)

    def _check_file_signatures(self, data: list[int]) -> list[dict[str, Any]]:
        """Check for embedded file signatures."""
        return detect_embedded_files(data)

    def _looks_encrypted(self, data: list[int]) -> bool:
        """Check if data looks encrypted based on entropy and patterns."""
        return looks_encrypted(data)

    def _extract_strings(self, data: list[int], min_length: int = 4) -> list[str]:
        """Extract readable strings from data."""
        return extract_ascii_from_bytes(data, min_length=min_length, limit=50)

    def _find_pattern(self, data: list[int], pattern: list[int]) -> bool:
        """Find a byte pattern in data."""
        return has_pattern(data, pattern)

    def _find_all_patterns(self, data: list[int], pattern: list[int]) -> list[int]:
        """Find all occurrences of a byte pattern in data."""
        return find_all_patterns(data, pattern)

    def _check_suspicious_indicators(self, result: OverlayResult) -> None:
        """Check for suspicious indicators in overlay data."""
        result["suspicious_indicators"] = build_overlay_suspicious_indicators(
            cast(dict[str, Any], result)
        )

    def _check_large_overlay(self, result: OverlayResult, suspicious: list[dict[str, Any]]) -> None:
        if result["overlay_size"] > 1024 * 1024:
            suspicious.append(
                {
                    "indicator": "Large overlay",
                    "details": f"Overlay size: {result['overlay_size']} bytes",
                    "severity": "medium",
                }
            )

    def _check_entropy(self, result: OverlayResult, suspicious: list[dict[str, Any]]) -> None:
        if result["overlay_entropy"] > 7.5:
            suspicious.append(
                {
                    "indicator": "High entropy",
                    "details": f"Entropy: {result['overlay_entropy']}",
                    "severity": "high",
                }
            )

    def _check_embedded_executables(
        self, result: OverlayResult, suspicious: list[dict[str, Any]]
    ) -> None:
        for embedded in result.get("embedded_files", []):
            if embedded.get("type") in ["PE", "ELF"]:
                suspicious.append(
                    {
                        "indicator": "Embedded executable",
                        "details": f"{embedded['type']} at offset {embedded['offset']}",
                        "severity": "high",
                    }
                )

    def _check_autoit(self, result: OverlayResult, suspicious: list[dict[str, Any]]) -> None:
        for pattern in result.get("patterns_found", []):
            if pattern.get("name") == "AutoIt":
                suspicious.append(
                    {
                        "indicator": "AutoIt script",
                        "details": "AutoIt compiled script detected",
                        "severity": "medium",
                    }
                )

    def _check_suspicious_strings(
        self, result: OverlayResult, suspicious: list[dict[str, Any]]
    ) -> None:
        suspicious_strings = [
            "cmd.exe",
            "powershell",
            "WScript.Shell",
            "HKEY_",
            "\\System32\\",
            "\\Windows\\",
            "CreateProcess",
            "VirtualAlloc",
            "WriteProcessMemory",
        ]

        found_suspicious = []
        for string in result.get("extracted_strings", []):
            for sus_str in suspicious_strings:
                if sus_str.lower() in string.lower():
                    found_suspicious.append(string)
                    break

        if found_suspicious:
            suspicious.append(
                {
                    "indicator": "Suspicious strings",
                    "details": f"Found: {', '.join(found_suspicious[:5])}",
                    "severity": "medium",
                }
            )
