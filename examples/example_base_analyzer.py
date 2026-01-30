#!/usr/bin/env python3
"""
Example BaseAnalyzer Implementation

This module demonstrates how to create a custom analyzer using the BaseAnalyzer
abstract base class. It shows best practices, common patterns, and proper
integration with the r2inspect framework.

This example can be used as a template for creating new analyzers.

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

# Add parent directory to path for imports (when running as standalone)
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from r2inspect.abstractions import BaseAnalyzer
from r2inspect.utils.logger import get_logger

logger = get_logger(__name__)


class ExampleMetadataAnalyzer(BaseAnalyzer):
    """
    Example analyzer that demonstrates BaseAnalyzer usage.

    This analyzer extracts basic metadata from PE binaries including:
    - File size and type information
    - Basic header information
    - Architecture and bit-ness
    - Entry point address

    This serves as a reference implementation showing:
    1. How to inherit from BaseAnalyzer
    2. How to use the flexible constructor
    3. How to implement the analyze() method
    4. How to use utility methods
    5. How to provide metadata for registry integration
    """

    def __init__(self, r2, config, filepath=None):
        """
        Initialize the example analyzer.

        Args:
            r2: r2pipe instance for binary analysis
            config: Configuration object with user preferences
            filepath: Optional path to the binary file

        Example:
            >>> analyzer = ExampleMetadataAnalyzer(r2_instance, config, "/path/to/binary.exe")
            >>> result = analyzer.analyze()
        """
        # Call parent constructor with dependency injection
        super().__init__(r2=r2, config=config, filepath=filepath)

        # Extract configuration values with defaults
        self.extract_headers = config.get("example", "extract_headers", True)
        self.extract_sections = config.get("example", "extract_sections", True)
        self.max_sections = config.get("example", "max_sections", 100)

        self._log_debug("ExampleMetadataAnalyzer initialized")

    def analyze(self) -> dict[str, Any]:
        """
        Perform metadata extraction analysis.

        This method demonstrates the standard analysis pattern:
        1. Initialize result structure
        2. Validate prerequisites (r2, file, etc.)
        3. Extract data using helper methods
        4. Handle errors gracefully
        5. Return standardized result dictionary

        Returns:
            Dictionary containing analysis results:
            {
                "available": bool,
                "error": Optional[str],
                "analyzer": str,
                "execution_time": float,
                "file_info": dict,
                "headers": dict,
                "architecture": dict,
                "sections": list
            }
        """
        # Step 1: Initialize result structure with analyzer-specific fields
        result = self._init_result_structure(
            {"file_info": {}, "headers": {}, "architecture": {}, "sections": []}
        )

        try:
            # Step 2: Validate prerequisites
            if not self.r2:
                result["error"] = "r2pipe instance not available"
                self._log_error("Cannot analyze without r2pipe instance")
                return result

            self._log_debug("Starting metadata extraction")

            # Step 3: Extract file information
            result["file_info"] = self._extract_file_info()

            # Step 4: Extract headers (if configured)
            if self.extract_headers:
                result["headers"] = self._extract_headers()

            # Step 5: Extract architecture information
            result["architecture"] = self._extract_architecture()

            # Step 6: Extract sections (if configured)
            if self.extract_sections:
                result["sections"] = self._extract_sections()

            # Mark as successful
            result["available"] = True

            self._log_info(
                f"Successfully extracted metadata: "
                f"{len(result['sections'])} sections, "
                f"arch={result['architecture'].get('arch', 'unknown')}"
            )

        except Exception as e:
            # Step 7: Handle errors gracefully (don't raise)
            result["error"] = f"Metadata extraction failed: {str(e)}"
            self._log_error(f"Analysis error: {e}")

        return result

    def _extract_file_info(self) -> dict[str, Any]:
        """
        Extract basic file information.

        Uses BaseAnalyzer utility methods to get file metadata.

        Returns:
            Dictionary with file information
        """
        info = {}

        # Use BaseAnalyzer utilities
        if self.filepath:
            info["path"] = str(self.filepath.absolute())
            info["name"] = self.filepath.name
            info["extension"] = self.get_file_extension()
            info["exists"] = self.file_exists()

        # Get file size using utility method
        file_size = self.get_file_size()
        if file_size:
            info["size_bytes"] = file_size
            info["size_mb"] = round(file_size / (1024 * 1024), 2)

            # Warn about large files
            if file_size > 50 * 1024 * 1024:
                self._log_warning(f"Large file detected: {info['size_mb']} MB")

        return info

    def _extract_headers(self) -> dict[str, Any]:
        """
        Extract binary headers using r2pipe.

        This demonstrates how to use r2pipe commands safely.

        Returns:
            Dictionary with header information
        """
        headers = {}

        try:
            # Get binary information from r2
            bin_info = self.r2.cmdj("ij")

            if bin_info and "bin" in bin_info:
                bin_data = bin_info["bin"]
                headers["format"] = bin_data.get("class", "Unknown")
                headers["machine"] = bin_data.get("machine", "Unknown")
                headers["os"] = bin_data.get("os", "Unknown")
                headers["subsystem"] = bin_data.get("subsys", "Unknown")

                self._log_debug(f"Extracted headers: format={headers['format']}")

        except Exception as e:
            self._log_error(f"Header extraction failed: {e}")
            headers["error"] = str(e)

        return headers

    def _extract_architecture(self) -> dict[str, Any]:
        """
        Extract architecture information.

        Returns:
            Dictionary with architecture details
        """
        arch_info = {}

        try:
            bin_info = self.r2.cmdj("ij")

            if bin_info and "bin" in bin_info:
                bin_data = bin_info["bin"]
                arch_info["arch"] = bin_data.get("arch", "Unknown")
                arch_info["bits"] = bin_data.get("bits", 0)
                arch_info["endian"] = bin_data.get("endian", "Unknown")
                arch_info["has_crypto"] = bin_data.get("crypto", False)

                self._log_debug(
                    f"Architecture: {arch_info['arch']} "
                    f"({arch_info['bits']}-bit, {arch_info['endian']})"
                )

        except Exception as e:
            self._log_error(f"Architecture extraction failed: {e}")
            arch_info["error"] = str(e)

        return arch_info

    def _extract_sections(self) -> list[dict[str, Any]]:
        """
        Extract section information from the binary.

        This demonstrates working with lists of data.

        Returns:
            list of section dictionaries
        """
        sections = []

        try:
            # Get sections from r2
            sections_data = self.r2.cmdj("iSj")

            if not sections_data:
                self._log_debug("No sections found")
                return sections

            # Limit number of sections (from config)
            sections_data = sections_data[: self.max_sections]

            for section in sections_data:
                section_info = {
                    "name": section.get("name", ""),
                    "size": section.get("size", 0),
                    "vsize": section.get("vsize", 0),
                    "paddr": section.get("paddr", 0),
                    "vaddr": section.get("vaddr", 0),
                    "permissions": section.get("perm", ""),
                    "flags": section.get("flags", ""),
                }
                sections.append(section_info)

            self._log_debug(f"Extracted {len(sections)} sections")

        except Exception as e:
            self._log_error(f"Section extraction failed: {e}")

        return sections

    # =========================================================================
    # Metadata Methods (for Registry Integration)
    # =========================================================================

    def get_category(self) -> str:
        """
        Return the analyzer category.

        This is used by the AnalyzerRegistry to organize analyzers.

        Returns:
            Category identifier: "metadata"
        """
        return "metadata"

    def supports_format(self, file_format: str) -> bool:
        """
        Check if this analyzer supports a specific file format.

        This example analyzer only works with PE files.

        Args:
            file_format: File format identifier (e.g., "PE", "ELF")

        Returns:
            True if format is PE, False otherwise
        """
        return file_format.upper() in {"PE", "PE32", "PE32+"}

    def get_supported_formats(self) -> set[str]:
        """
        Get the set of supported file formats.

        Returns:
            set of format identifiers
        """
        return {"PE", "PE32", "PE32+"}

    def get_description(self) -> str:
        """
        Get human-readable description of this analyzer.

        Returns:
            Description string
        """
        return "Example metadata analyzer demonstrating BaseAnalyzer usage"

    @classmethod
    def is_available(cls) -> bool:
        """
        Check if this analyzer's dependencies are available.

        This analyzer only requires r2pipe, which is a core dependency,
        so it's always available.

        Returns:
            True (always available)
        """
        return True


class ExampleFileAnalyzer(BaseAnalyzer):
    """
    Example analyzer that works primarily with file-based analysis.

    This demonstrates the filepath-focused pattern used by hash analyzers
    and other file-based tools.
    """

    def __init__(self, filepath, r2=None):
        """
        Initialize file analyzer.

        Note the parameter order: filepath first, r2 optional.
        This is the pattern used by hash analyzers.

        Args:
            filepath: Path to the file to analyze
            r2: Optional r2pipe instance
        """
        super().__init__(filepath=filepath, r2=r2)

    def analyze(self) -> dict[str, Any]:
        """
        Perform file-based analysis.

        Returns:
            Analysis results dictionary
        """
        result = self._init_result_structure(
            {"file_hash": None, "file_type": None, "magic_bytes": None}
        )

        try:
            # Validate file exists
            if not self.file_exists():
                result["error"] = f"File not found: {self.filepath}"
                return result

            # Get file size
            file_size = self.get_file_size()
            if file_size == 0:
                result["error"] = "Empty file"
                return result

            # Read magic bytes
            with open(self.filepath, "rb") as f:
                magic = f.read(4)
                result["magic_bytes"] = magic.hex()

                # Determine file type from magic bytes
                if magic[:2] == b"MZ":
                    result["file_type"] = "PE"
                elif magic[:4] == b"\x7fELF":
                    result["file_type"] = "ELF"
                elif magic[:4] in [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"]:
                    result["file_type"] = "MACH0"
                else:
                    result["file_type"] = "Unknown"

            # Calculate simple hash
            import hashlib

            with open(self.filepath, "rb") as f:
                result["file_hash"] = hashlib.sha256(f.read()).hexdigest()

            result["available"] = True
            self._log_info(f"Analyzed file: type={result['file_type']}")

        except Exception as e:
            result["error"] = f"File analysis failed: {str(e)}"
            self._log_error(f"Analysis error: {e}")

        return result

    def get_category(self) -> str:
        return "hashing"

    def get_description(self) -> str:
        return "Example file analyzer demonstrating filepath-based analysis"


# =============================================================================
# Demo / Test Code
# =============================================================================


def demo_analyzer():
    """
    Demonstrate the example analyzers.

    This function shows how to use the analyzers and can be run standalone.
    """
    print("BaseAnalyzer Example Demo")
    print("=" * 60)

    # Example 1: File-based analyzer (no r2pipe needed)
    print("\n1. File-Based Analyzer Example:")
    print("-" * 60)

    try:
        # Create a temporary test file
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            # Write PE magic bytes
            tmp.write(b"MZ\x90\x00" + b"\x00" * 100)
            tmp_path = tmp.name

        # Analyze the file
        file_analyzer = ExampleFileAnalyzer(filepath=tmp_path)
        result = file_analyzer.analyze()

        print(f"Analyzer: {file_analyzer.get_name()}")
        print(f"Category: {file_analyzer.get_category()}")
        print(f"Description: {file_analyzer.get_description()}")
        print(f"Available: {result['available']}")
        print(f"File Type: {result['file_type']}")
        print(f"Magic Bytes: {result['magic_bytes']}")

        # Cleanup
        import os

        os.unlink(tmp_path)

    except Exception as e:
        print(f"Error in file analyzer demo: {e}")

    print("\n" + "=" * 60)
    print("Demo completed!")


if __name__ == "__main__":
    # Run the demo when executed directly
    demo_analyzer()
