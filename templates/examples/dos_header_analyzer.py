#!/usr/bin/env python3
"""
Example Analyzer: DOS Header Analyzer
Category: Format
Description: Complete example implementation extracting DOS header from PE files

This is a complete, working example of a Simple Format Analyzer that extracts
and analyzes the DOS header (IMAGE_DOS_HEADER) from PE executables.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0
See LICENSE file for details

Purpose:
    - Demonstrates format-specific data extraction
    - Shows proper error handling
    - Illustrates r2 command usage
    - Provides complete documentation

Usage:
    >>> from r2inspect.modules.dos_header_analyzer import DOSHeaderAnalyzer
    >>> analyzer = DOSHeaderAnalyzer(r2=r2_instance)
    >>> result = analyzer.analyze()
    >>> print(f"DOS Signature: {result['dos_signature']}")
    >>> print(f"PE Offset: 0x{result['pe_offset']:x}")
"""

from typing import Any, Dict, Set

from ..abstractions import BaseAnalyzer
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj

logger = get_logger(__name__)


class DOSHeaderAnalyzer(BaseAnalyzer):
    """
    Extract and analyze DOS header from PE files.

    The DOS header (IMAGE_DOS_HEADER) is the first structure in every PE file.
    It begins with the magic number "MZ" (0x5A4D) and contains information for
    MS-DOS compatibility, including the offset to the PE header.

    This analyzer extracts:
        - DOS signature ("MZ")
        - Bytes on last page
        - Pages in file
        - Relocations
        - Header size in paragraphs
        - PE header offset (e_lfanew)
        - DOS stub presence and size

    Attributes:
        r2: R2Pipe instance for binary analysis

    Example:
        >>> analyzer = DOSHeaderAnalyzer(r2=r2)
        >>> result = analyzer.analyze()
        >>> if result['available']:
        ...     print(f"Valid DOS header: {result['valid_dos_header']}")
        ...     print(f"PE offset: 0x{result['pe_offset']:x}")
        ...     print(f"DOS stub size: {result['dos_stub_size']} bytes")
    """

    # DOS header constants
    DOS_SIGNATURE = "MZ"
    DOS_HEADER_SIZE = 64  # Size of IMAGE_DOS_HEADER structure

    def __init__(self, r2=None, config=None, filepath=None, **kwargs):
        """
        Initialize the DOS header analyzer.

        Args:
            r2: R2Pipe instance for binary analysis (required)
            config: Configuration dictionary (optional, not used)
            filepath: Path to binary file (optional, for logging)
            **kwargs: Additional arguments passed to base class
        """
        super().__init__(r2=r2, config=config, filepath=filepath, **kwargs)

    def analyze(self) -> Dict[str, Any]:
        """
        Perform DOS header analysis on the PE file.

        Extracts DOS header fields and validates the header structure.

        Returns:
            Dict containing:
                - available: bool - Whether analysis completed successfully
                - valid_dos_header: bool - Whether DOS header is valid
                - dos_signature: str - DOS signature (should be "MZ")
                - bytes_on_last_page: int - Bytes on last page
                - pages_in_file: int - Number of pages in file
                - relocations: int - Number of relocations
                - header_paragraphs: int - Size of header in paragraphs
                - pe_offset: int - Offset to PE header (e_lfanew)
                - dos_stub_present: bool - Whether DOS stub exists
                - dos_stub_size: int - Size of DOS stub in bytes
                - error: str - Error message if analysis failed (optional)

        Example:
            >>> result = analyzer.analyze()
            >>> if result['available'] and result['valid_dos_header']:
            ...     print(f"PE starts at offset: 0x{result['pe_offset']:x}")
        """
        result = self._init_result_structure({
            'valid_dos_header': False,
            'dos_signature': None,
            'bytes_on_last_page': 0,
            'pages_in_file': 0,
            'relocations': 0,
            'header_paragraphs': 0,
            'pe_offset': 0,
            'dos_stub_present': False,
            'dos_stub_size': 0,
        })

        # Prerequisite checks
        if not self.r2:
            result['error'] = "R2Pipe instance required for DOS header analysis"
            self._log_error("R2Pipe instance not provided")
            return result

        try:
            # Perform the analysis
            analysis_data = self._perform_analysis()

            if analysis_data:
                result.update(analysis_data)
                result['available'] = True
                self._log_info("DOS header analysis completed successfully")
            else:
                result['error'] = "No DOS header data extracted"
                self._log_warning("Analysis returned no data")

        except Exception as e:
            self._log_error(f"DOS header analysis failed: {e}")
            result['error'] = str(e)

        return result

    def _perform_analysis(self) -> Dict[str, Any]:
        """
        Core analysis logic - extract DOS header information.

        Returns:
            Dict with DOS header fields
        """
        data = {}

        # Get binary info to access DOS header
        bin_info = safe_cmdj(self.r2, "ij", {})
        if not bin_info or 'bin' not in bin_info:
            self._log_error("Failed to get binary information")
            return data

        # Check if it's a PE file
        file_format = bin_info.get('bin', {}).get('class', '')
        if not file_format.startswith('PE'):
            self._log_warning(f"Not a PE file: {file_format}")
            return data

        # Read DOS header (first 64 bytes)
        # Seek to offset 0
        self.r2.cmd("s 0")

        # Read DOS header as JSON array of bytes
        dos_header_bytes = safe_cmdj(self.r2, f"pxj {self.DOS_HEADER_SIZE} @ 0", [])
        if not dos_header_bytes or len(dos_header_bytes) < self.DOS_HEADER_SIZE:
            self._log_error("Failed to read DOS header bytes")
            return data

        # Parse DOS header fields
        # Offset 0x00: e_magic (2 bytes) - "MZ" signature
        e_magic = dos_header_bytes[0] | (dos_header_bytes[1] << 8)
        dos_signature = chr(dos_header_bytes[0]) + chr(dos_header_bytes[1])
        data['dos_signature'] = dos_signature
        data['valid_dos_header'] = (dos_signature == self.DOS_SIGNATURE)

        if not data['valid_dos_header']:
            self._log_warning(f"Invalid DOS signature: {dos_signature} (expected MZ)")
            return data

        # Offset 0x02: e_cblp (2 bytes) - Bytes on last page
        data['bytes_on_last_page'] = dos_header_bytes[2] | (dos_header_bytes[3] << 8)

        # Offset 0x04: e_cp (2 bytes) - Pages in file
        data['pages_in_file'] = dos_header_bytes[4] | (dos_header_bytes[5] << 8)

        # Offset 0x06: e_crlc (2 bytes) - Relocations
        data['relocations'] = dos_header_bytes[6] | (dos_header_bytes[7] << 8)

        # Offset 0x08: e_cparhdr (2 bytes) - Size of header in paragraphs
        data['header_paragraphs'] = dos_header_bytes[8] | (dos_header_bytes[9] << 8)

        # Offset 0x3C: e_lfanew (4 bytes) - Offset to PE header
        # This is the most important field - it points to the real PE header
        pe_offset = (
            dos_header_bytes[0x3C]
            | (dos_header_bytes[0x3D] << 8)
            | (dos_header_bytes[0x3E] << 16)
            | (dos_header_bytes[0x3F] << 24)
        )
        data['pe_offset'] = pe_offset

        # Calculate DOS stub size
        # DOS stub is between end of DOS header and start of PE header
        dos_stub_size = pe_offset - self.DOS_HEADER_SIZE
        data['dos_stub_present'] = dos_stub_size > 0
        data['dos_stub_size'] = max(0, dos_stub_size)

        if data['dos_stub_present']:
            self._log_debug(f"DOS stub found: {dos_stub_size} bytes")

        # Validate PE offset is reasonable
        if pe_offset < self.DOS_HEADER_SIZE or pe_offset > 0x1000:
            self._log_warning(f"Unusual PE offset: 0x{pe_offset:x}")

        return data

    # Metadata methods

    def get_name(self) -> str:
        """Return analyzer name."""
        return "dos_header"

    def get_category(self) -> str:
        """Return analyzer category."""
        return "format"

    def get_description(self) -> str:
        """Return analyzer description."""
        return "Extract and analyze DOS header (IMAGE_DOS_HEADER) from PE files"

    def supports_format(self, file_format: str) -> bool:
        """
        Check if analyzer supports given file format.

        Args:
            file_format: File format identifier

        Returns:
            True if format is PE/PE32/PE32+, False otherwise
        """
        supported = self.get_supported_formats()
        return file_format.upper() in supported

    def get_supported_formats(self) -> Set[str]:
        """
        Return set of supported file formats.

        Returns:
            Set of PE format identifiers
        """
        return {"PE", "PE32", "PE32+"}

    @staticmethod
    def is_available() -> bool:
        """
        Check if required dependencies are available.

        DOS header analyzer only requires r2pipe, which is always available.

        Returns:
            True (always available)
        """
        return True
