#!/usr/bin/env python3
"""
Template: Simple Format Analyzer
Category: Format
Description: Template for analyzers that extract basic file format information

This template is for creating analyzers that extract structural information from
specific file formats (PE, ELF, Mach-O, etc.). These analyzers read format-specific
headers, metadata, and structural elements.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0
See LICENSE file for details

Usage:
    1. Copy this file to r2inspect/modules/your_analyzer.py
    2. Replace all [PLACEHOLDER] values with your specific implementation
    3. Implement the _perform_analysis() method with format-specific logic
    4. Update metadata methods (get_name, get_category, etc.)
    5. Add dependency checks in is_available() if needed
    6. Add tests in tests/unit/analyzers/test_your_analyzer.py
    7. Register in registry by importing in r2inspect/modules/__init__.py

Example Use Cases:
    - PE DOS header analyzer
    - ELF program header analyzer
    - Mach-O load command analyzer
    - ZIP archive analyzer
    - PDF header analyzer

Template Pattern:
    1. Initialize with r2 and config
    2. Validate r2 instance is available
    3. Extract format-specific data using r2 commands
    4. Parse and structure the data
    5. Return standardized dictionary result
"""

from typing import Any, Dict, Set

from ..abstractions import BaseAnalyzer
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd, safe_cmdj

logger = get_logger(__name__)


class [ANALYZER_NAME]Analyzer(BaseAnalyzer):
    """
    [Short description of what this analyzer extracts]

    This analyzer extracts [detailed description of data extracted] from
    [file format(s)] using radare2 commands. It provides structured information
    about [specific format features].

    The analyzer focuses on:
        - [Feature 1: e.g., Header fields]
        - [Feature 2: e.g., Metadata extraction]
        - [Feature 3: e.g., Structural information]

    Attributes:
        r2: R2Pipe instance for binary analysis
        config: Configuration dictionary (optional)

    Example:
        >>> analyzer = [ANALYZER_NAME]Analyzer(r2=r2, config=config)
        >>> result = analyzer.analyze()
        >>> print(result['available'])
        True
        >>> print(result['[data_field]'])
        {...}
    """

    def __init__(self, r2=None, config=None, filepath=None, **kwargs):
        """
        Initialize the [ANALYZER_NAME] analyzer.

        Args:
            r2: R2Pipe instance for binary analysis (required)
            config: Configuration dictionary (optional)
            filepath: Path to binary file (optional, for logging)
            **kwargs: Additional arguments passed to base class
        """
        super().__init__(r2=r2, config=config, filepath=filepath, **kwargs)

        # [TODO: Add your initialization here]
        # Example: self.max_items = config.get("max_items", 100) if config else 100

    def analyze(self) -> Dict[str, Any]:
        """
        Perform [ANALYZER_NAME] analysis on the binary.

        Extracts [description of extracted data] and returns structured results.

        Returns:
            Dict containing:
                - available: bool - Whether analyzer executed successfully
                - [field1]: [type] - [description]
                - [field2]: [type] - [description]
                - error: str - Error message if analysis failed (optional)

        Example:
            >>> result = analyzer.analyze()
            >>> if result['available']:
            ...     print(f"Found {len(result['items'])} items")
        """
        result = self._init_result_structure()

        # Prerequisite checks
        if not self.r2:
            result['error'] = "R2Pipe instance required for [ANALYZER_NAME] analysis"
            self._log_error("R2Pipe instance not provided")
            return result

        try:
            # Perform the analysis
            analysis_data = self._perform_analysis()

            if analysis_data:
                result.update(analysis_data)
                result['available'] = True
                self._log_info(f"Successfully completed [ANALYZER_NAME] analysis")
            else:
                result['error'] = "No data extracted from [ANALYZER_NAME] analysis"
                self._log_warning("Analysis returned no data")

        except Exception as e:
            self._log_error(f"Analysis failed: {e}")
            result['error'] = str(e)

        return result

    def _perform_analysis(self) -> Dict[str, Any]:
        """
        Core analysis logic - extract format-specific information.

        [TODO: Implement your analysis logic here]

        This method should:
            1. Execute r2 commands to extract format data
            2. Parse the command output
            3. Structure the data into a dictionary
            4. Return the structured results

        Returns:
            Dict with analysis results containing format-specific fields

        Example Implementation:
            >>> def _perform_analysis(self) -> Dict[str, Any]:
            ...     data = {}
            ...
            ...     # Extract header information
            ...     header_info = safe_cmdj(self.r2, "iHj", {})
            ...     if header_info:
            ...         data['magic'] = header_info.get('magic')
            ...         data['arch'] = header_info.get('arch')
            ...
            ...     # Extract additional format data
            ...     sections = safe_cmdj(self.r2, "iSj", [])
            ...     data['section_count'] = len(sections)
            ...
            ...     return data
        """
        # [TODO: Implement your analysis logic]
        raise NotImplementedError(
            "You must implement _perform_analysis() method. "
            "See docstring above for implementation guidance."
        )

        # [TODO: Example template - replace with your implementation]
        # data = {}
        #
        # # Step 1: Extract primary format data
        # format_info = safe_cmdj(self.r2, "[R2_COMMAND]", {})
        # if format_info:
        #     data['[field1]'] = format_info.get('[key1]')
        #     data['[field2]'] = format_info.get('[key2]')
        #
        # # Step 2: Extract secondary data
        # secondary_data = safe_cmdj(self.r2, "[R2_COMMAND]", [])
        # data['[field3]'] = self._process_secondary_data(secondary_data)
        #
        # # Step 3: Add computed fields
        # data['[computed_field]'] = self._compute_value(data)
        #
        # return data

    # [TODO: Add helper methods as needed]
    # Example helper methods:

    # def _process_secondary_data(self, raw_data: List[Dict]) -> Any:
    #     """Process and filter secondary data."""
    #     processed = []
    #     for item in raw_data:
    #         if self._is_valid_item(item):
    #             processed.append(self._format_item(item))
    #     return processed
    #
    # def _is_valid_item(self, item: Dict) -> bool:
    #     """Check if item meets validation criteria."""
    #     return item.get('size', 0) > 0
    #
    # def _format_item(self, item: Dict) -> Dict:
    #     """Format item for output."""
    #     return {
    #         'name': item.get('name', 'unknown'),
    #         'size': item.get('size', 0),
    #         'offset': item.get('offset', 0)
    #     }

    # Metadata methods

    def get_name(self) -> str:
        """Return analyzer name."""
        return "[analyzer_name]"  # [TODO: Update to snake_case name, e.g., "dos_header"]

    def get_category(self) -> str:
        """Return analyzer category."""
        return "format"  # [TODO: Keep as "format" or change if needed]

    def get_description(self) -> str:
        """Return analyzer description."""
        return "[Description of what this analyzer does]"  # [TODO: Update with clear description]

    def supports_format(self, file_format: str) -> bool:
        """
        Check if analyzer supports given file format.

        Args:
            file_format: File format identifier (e.g., "PE", "ELF", "MACH0")

        Returns:
            True if format is supported, False otherwise
        """
        supported = self.get_supported_formats()
        return file_format.upper() in supported

    def get_supported_formats(self) -> Set[str]:
        """
        Return set of supported file formats.

        Returns:
            Set of format identifiers (uppercase)
        """
        return {"[FORMAT1]", "[FORMAT2]"}  # [TODO: Update with supported formats, e.g., {"PE", "PE32", "PE32+"}]

    @staticmethod
    def is_available() -> bool:
        """
        Check if required dependencies are available.

        Returns:
            True if analyzer can be used, False if dependencies missing

        Note:
            Simple format analyzers typically only need r2pipe, which is
            always available. Override this if you need additional libraries.
        """
        # [TODO: Add dependency checks if needed]
        # Example:
        # try:
        #     import some_library
        #     return True
        # except ImportError:
        #     return False

        return True  # Most format analyzers only need r2pipe
