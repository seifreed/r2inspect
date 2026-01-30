#!/usr/bin/env python3
"""
Template: String-Based Analyzer
Category: Metadata/Behavioral
Description: Template for analyzers that process strings, text, or textual patterns

This template is for creating analyzers that extract, filter, and analyze string
data from binaries. These analyzers work with textual content including ASCII/Unicode
strings, comments, metadata, and pattern matching.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0
See LICENSE file for details

Usage:
    1. Copy this file to r2inspect/modules/your_analyzer.py
    2. Replace all [PLACEHOLDER] values with your specific implementation
    3. Implement the _extract_strings() and _analyze_strings() methods
    4. Add filtering and pattern matching logic as needed
    5. Update metadata methods
    6. Add tests in tests/unit/analyzers/test_your_analyzer.py

Example Use Cases:
    - String extraction analyzer
    - URL/IP extraction analyzer
    - Crypto pattern detection analyzer
    - API call name analyzer
    - Comment/metadata analyzer
    - Suspicious string detector

Template Pattern:
    1. Initialize with r2, config, and optional parameters
    2. Extract strings using r2 commands
    3. Filter strings based on criteria
    4. Analyze patterns in strings
    5. Return structured results with statistics
"""

import re
from typing import Any, Dict, List, Set

from ..abstractions import BaseAnalyzer
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd, safe_cmdj

logger = get_logger(__name__)


class [ANALYZER_NAME]Analyzer(BaseAnalyzer):
    """
    [Short description of string analysis performed]

    This analyzer extracts and analyzes [type of strings/text] from binaries.
    It provides [description of analysis output] including pattern detection,
    filtering, and classification of textual content.

    Features:
        - [Feature 1: e.g., ASCII string extraction]
        - [Feature 2: e.g., Pattern matching]
        - [Feature 3: e.g., Statistics and classification]

    Configuration Options:
        - min_length: Minimum string length (default: [VALUE])
        - max_length: Maximum string length (default: [VALUE])
        - max_strings: Maximum number of strings (default: [VALUE])
        - [other options]

    Attributes:
        r2: R2Pipe instance for binary analysis
        config: Configuration dictionary
        min_length: Minimum string length
        max_length: Maximum string length
        max_strings: Maximum number of strings to extract

    Example:
        >>> analyzer = [ANALYZER_NAME]Analyzer(r2=r2, config=config)
        >>> result = analyzer.analyze()
        >>> print(f"Found {result['total_strings']} strings")
        >>> print(f"Matched {len(result['matches'])} patterns")
    """

    def __init__(self, r2=None, config=None, filepath=None, **kwargs):
        """
        Initialize the [ANALYZER_NAME] analyzer.

        Args:
            r2: R2Pipe instance for binary analysis (required)
            config: Configuration dictionary (optional)
            filepath: Path to binary file (optional)
            **kwargs: Additional arguments
        """
        super().__init__(r2=r2, config=config, filepath=filepath, **kwargs)

        # [TODO: Configure parameters from config]
        # Extract configuration values with defaults
        if config:
            self.min_length = config.get("[section]", "min_length", 4)
            self.max_length = config.get("[section]", "max_length", 100)
            self.max_strings = config.get("[section]", "max_strings", 1000)
        else:
            self.min_length = 4
            self.max_length = 100
            self.max_strings = 1000

        # [TODO: Define patterns for matching]
        # Example patterns for detection
        self.patterns = {
            # [TODO: Add your patterns here]
            # "pattern_name": r"regex_pattern",
        }

    def analyze(self) -> Dict[str, Any]:
        """
        Perform string analysis on the binary.

        Extracts strings, applies filters, detects patterns, and computes statistics.

        Returns:
            Dict containing:
                - available: bool - Whether analyzer executed successfully
                - total_strings: int - Total number of strings found
                - strings: List[str] - Extracted strings
                - matches: List[Dict] - Pattern matches found
                - statistics: Dict - String statistics
                - error: str - Error message if analysis failed (optional)

        Example:
            >>> result = analyzer.analyze()
            >>> if result['available']:
            ...     for match in result['matches']:
            ...         print(f"Pattern: {match['pattern']}, Found: {match['value']}")
        """
        result = self._init_result_structure({
            'total_strings': 0,
            'strings': [],
            'matches': [],
            'statistics': {}
        })

        # Prerequisite checks
        if not self.r2:
            result['error'] = "R2Pipe instance required for string analysis"
            self._log_error("R2Pipe instance not provided")
            return result

        try:
            # Step 1: Extract strings
            self._log_debug("Extracting strings from binary")
            strings = self._extract_strings()

            if not strings:
                self._log_warning("No strings extracted from binary")
                result['available'] = True  # Still successful, just no data
                return result

            # Step 2: Filter strings
            self._log_debug(f"Filtering {len(strings)} strings")
            filtered_strings = self._filter_strings(strings)

            # Step 3: Analyze patterns
            self._log_debug("Analyzing string patterns")
            matches = self._analyze_strings(filtered_strings)

            # Step 4: Compute statistics
            statistics = self._compute_statistics(filtered_strings, matches)

            # Populate result
            result['available'] = True
            result['total_strings'] = len(filtered_strings)
            result['strings'] = filtered_strings[:self.max_strings]  # Limit output
            result['matches'] = matches
            result['statistics'] = statistics

            self._log_info(
                f"String analysis completed: {len(filtered_strings)} strings, "
                f"{len(matches)} pattern matches"
            )

        except Exception as e:
            self._log_error(f"String analysis failed: {e}")
            result['error'] = str(e)

        return result

    def _extract_strings(self) -> List[str]:
        """
        Extract strings from binary using r2 commands.

        [TODO: Implement string extraction logic]

        Returns:
            List of extracted strings

        Example Implementation:
            >>> def _extract_strings(self) -> List[str]:
            ...     strings = []
            ...
            ...     # Extract ASCII strings
            ...     string_data = safe_cmdj(self.r2, "izj", [])
            ...     for entry in string_data:
            ...         if 'string' in entry:
            ...             strings.append(entry['string'])
            ...
            ...     # Extract Unicode strings
            ...     unicode_data = safe_cmdj(self.r2, "izuj", [])
            ...     for entry in unicode_data:
            ...         if 'string' in entry:
            ...             strings.append(entry['string'])
            ...
            ...     return strings
        """
        # [TODO: Implement string extraction]
        raise NotImplementedError(
            "You must implement _extract_strings() method. "
            "See docstring above for implementation guidance."
        )

        # [TODO: Example template - replace with your implementation]
        # strings = []
        #
        # # Extract strings using r2 command
        # string_data = safe_cmdj(self.r2, "izj", [])
        #
        # for entry in string_data:
        #     if isinstance(entry, dict) and 'string' in entry:
        #         string_val = entry['string']
        #         if string_val:
        #             strings.append(string_val)
        #
        # return strings

    def _filter_strings(self, strings: List[str]) -> List[str]:
        """
        Filter strings based on length and content criteria.

        Args:
            strings: Raw list of extracted strings

        Returns:
            Filtered list of strings
        """
        filtered = []

        for string in strings:
            # Length filter
            if len(string) < self.min_length or len(string) > self.max_length:
                continue

            # [TODO: Add additional filtering criteria]
            # Example: Filter non-printable characters
            cleaned = ''.join(c for c in string if c.isprintable())
            if len(cleaned) >= self.min_length:
                filtered.append(cleaned)

        return filtered

    def _analyze_strings(self, strings: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze strings for patterns and interesting content.

        [TODO: Implement pattern matching and analysis logic]

        Args:
            strings: Filtered list of strings

        Returns:
            List of matches with pattern information

        Example Implementation:
            >>> def _analyze_strings(self, strings: List[str]) -> List[Dict[str, Any]]:
            ...     matches = []
            ...
            ...     for string in strings:
            ...         for pattern_name, pattern in self.patterns.items():
            ...             found = re.findall(pattern, string, re.IGNORECASE)
            ...             if found:
            ...                 matches.append({
            ...                     'pattern': pattern_name,
            ...                     'string': string,
            ...                     'matches': found
            ...                 })
            ...
            ...     return matches
        """
        # [TODO: Implement pattern analysis]
        matches = []

        # [TODO: Example template - replace with your implementation]
        # for string in strings:
        #     for pattern_name, pattern in self.patterns.items():
        #         found = re.findall(pattern, string, re.IGNORECASE)
        #         if found:
        #             matches.append({
        #                 'pattern': pattern_name,
        #                 'string': string,
        #                 'value': found[0] if len(found) == 1 else found,
        #                 'count': len(found)
        #             })

        return matches

    def _compute_statistics(
        self, strings: List[str], matches: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Compute statistics about extracted strings and matches.

        Args:
            strings: Filtered strings
            matches: Pattern matches

        Returns:
            Dictionary with statistics
        """
        if not strings:
            return {
                'total': 0,
                'avg_length': 0,
                'min_length': 0,
                'max_length': 0
            }

        stats = {
            'total': len(strings),
            'avg_length': sum(len(s) for s in strings) / len(strings),
            'min_length': min(len(s) for s in strings),
            'max_length': max(len(s) for s in strings),
            'total_matches': len(matches),
            # [TODO: Add more statistics as needed]
        }

        # [TODO: Add pattern-specific statistics]
        # Example: Count matches by pattern type
        # pattern_counts = {}
        # for match in matches:
        #     pattern = match['pattern']
        #     pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        # stats['pattern_distribution'] = pattern_counts

        return stats

    # Metadata methods

    def get_name(self) -> str:
        """Return analyzer name."""
        return "[analyzer_name]"  # [TODO: Update to snake_case name, e.g., "suspicious_strings"]

    def get_category(self) -> str:
        """Return analyzer category."""
        return "metadata"  # [TODO: Update if needed - options: "metadata", "behavioral", "detection"]

    def get_description(self) -> str:
        """Return analyzer description."""
        return "[Description of string analysis performed]"  # [TODO: Update with clear description]

    def supports_format(self, file_format: str) -> bool:
        """
        Check if analyzer supports given file format.

        String analyzers typically work with all formats.
        """
        return True  # [TODO: Update if you need format restrictions]

    def get_supported_formats(self) -> Set[str]:
        """
        Return set of supported file formats.

        Returns:
            Empty set indicates all formats supported
        """
        return set()  # [TODO: Add specific formats if needed]

    @staticmethod
    def is_available() -> bool:
        """
        Check if required dependencies are available.

        String analyzers typically only need r2pipe.
        """
        # [TODO: Add dependency checks if needed]
        return True
