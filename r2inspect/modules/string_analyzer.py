#!/usr/bin/env python3
"""String analysis module."""

from typing import Any

from ..abstractions import BaseAnalyzer
from ..utils.command_helpers import cmdj as cmdj_helper
from ..utils.logger import get_logger
from .search_helpers import search_hex
from .string_domain import (
    build_xor_matches,
    decode_base64,
    decode_hex,
    filter_strings,
    find_suspicious,
)
from .string_extraction import extract_strings_from_entries

logger = get_logger(__name__)


class StringAnalyzer(BaseAnalyzer):
    """String extraction and analysis using backend data."""

    def __init__(self, adapter: Any, config: Any) -> None:
        super().__init__(adapter=adapter, config=config)
        strings_cfg = config.typed_config.strings
        general_cfg = config.typed_config.general
        self.min_length = strings_cfg.min_length
        self.max_length = strings_cfg.max_length
        self.max_strings = general_cfg.max_strings

    def get_category(self) -> str:
        return "metadata"

    def get_description(self) -> str:
        return "Extracts and analyzes strings from binary files including ASCII, Unicode, and encoded strings"

    def analyze(self) -> dict[str, Any]:
        """Perform string analysis"""
        result = self._init_result_structure(
            {
                "total_strings": 0,
                "strings": [],
                "suspicious_strings": [],
                "decoded_strings": [],
                "statistics": {},
            }
        )

        try:
            self._log_info("Starting string analysis")
            strings = self.extract_strings()
            result["strings"] = strings
            result["total_strings"] = len(strings)
            result["available"] = True
            self._log_info(f"Extracted {len(strings)} strings")
        except Exception as e:
            result["error"] = str(e)
            self._log_error(f"String analysis failed: {e}")

        return result

    def extract_strings(self) -> list[str]:
        """Extract strings from binary"""
        strings = []

        try:
            # Extract ASCII strings
            if self.config.typed_config.strings.extract_ascii:
                ascii_strings = self._extract_ascii_strings()
                strings.extend(ascii_strings)

            # Extract Unicode strings
            if self.config.typed_config.strings.extract_unicode:
                unicode_strings = self._extract_unicode_strings()
                strings.extend(unicode_strings)

            # Remove duplicates and filter
            strings = list(set(strings))
            strings = filter_strings(strings, self.min_length, self.max_length)

            # Limit number of strings
            if len(strings) > self.max_strings:
                strings = strings[: self.max_strings]

        except Exception as e:
            logger.error(f"Error extracting strings: {e}")

        return strings

    def _extract_ascii_strings(self) -> list[str]:
        """Extract ASCII strings using radare2"""
        try:
            result = self._fetch_string_entries("izj")
            return extract_strings_from_entries(result, self.min_length)
        except Exception as e:
            logger.error(f"Error extracting ASCII strings: {e}")
        return []

    def _extract_unicode_strings(self) -> list[str]:
        """Extract Unicode strings using radare2"""
        try:
            result = self._fetch_string_entries("izuj")
            return extract_strings_from_entries(result, self.min_length)
        except Exception as e:
            logger.error(f"Error extracting Unicode strings: {e}")
        return []

    def _fetch_string_entries(self, cmd: str) -> list[dict[str, Any]]:
        result = cmdj_helper(self.adapter, self.r2, cmd, [])
        return result if isinstance(result, list) else []

    def search_xor(self, search_string: str) -> list[dict[str, Any]]:
        """Search for XOR'd strings"""
        try:

            def _search_hex(pattern: str) -> str:
                return search_hex(self.adapter, self.r2, pattern)

            return build_xor_matches(search_string, _search_hex)
        except Exception as e:
            logger.error(f"Error in XOR search: {e}")

        return []

    def get_suspicious_strings(self) -> list[dict[str, Any]]:
        """Find suspicious strings that might indicate malware"""
        strings = self.extract_strings()
        return find_suspicious(strings)

    def decode_strings(self) -> list[dict[str, Any]]:
        """Attempt to decode encoded strings"""
        decoded = []
        strings = self.extract_strings()

        for string in strings:
            decoded_entry = decode_base64(string)
            if decoded_entry:
                decoded.append(decoded_entry)

            decoded_entry = decode_hex(string)
            if decoded_entry:
                decoded.append(decoded_entry)

        return decoded

    def _decode_base64(self, value: str) -> dict[str, Any] | None:
        """Decode a base64-encoded string if possible."""
        return decode_base64(value)

    def _decode_hex(self, value: str) -> dict[str, Any] | None:
        """Decode a hex-encoded string if possible."""
        return decode_hex(value)

    def get_string_statistics(self) -> dict[str, Any]:
        """Get statistics about extracted strings"""
        strings = self.extract_strings()

        stats = {
            "total_strings": len(strings),
            "avg_length": sum(len(s) for s in strings) / len(strings) if strings else 0,
            "min_length": min(len(s) for s in strings) if strings else 0,
            "max_length": max(len(s) for s in strings) if strings else 0,
            "charset_analysis": self._analyze_charset(strings),
        }

        return stats

    def _analyze_charset(self, strings: list[str]) -> dict[str, int]:
        """Analyze character sets used in strings"""
        charset_count = {"ascii": 0, "unicode": 0, "printable": 0, "alphanumeric": 0}

        for string in strings:
            if all(ord(c) < 128 for c in string):
                charset_count["ascii"] += 1
            else:
                charset_count["unicode"] += 1

            if string.isprintable():
                charset_count["printable"] += 1

            if string.isalnum():
                charset_count["alphanumeric"] += 1

        return charset_count
