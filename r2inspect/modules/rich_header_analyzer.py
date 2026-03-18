#!/usr/bin/env python3
"""Rich Header analysis for PE files."""

from typing import Any, cast

from ..abstractions import BaseAnalyzer
from ..adapters.file_system import default_file_system
from ..domain.services.rich_header import (
    calculate_richpe_hash,
    parse_compiler_entries,
)
from ..adapters.analyzer_runner import run_analyzer_on_file
from ..infrastructure.command_helpers import cmdj as cmdj_helper
from ..infrastructure.logging import get_logger
from .rich_header_debug import RichHeaderDebugMixin
from .rich_header_direct import RichHeaderDirectMixin
from .rich_header_pefile import PEFILE_AVAILABLE, RichHeaderPefileMixin
from .rich_header_search import RichHeaderSearchMixin

logger = get_logger(__name__)

# Try to import pefile for better Rich Header support
try:
    import pefile

    PEFILE_AVAILABLE = True
    logger.debug("pefile library available for Rich Header analysis")
except ImportError:  # pragma: no cover
    PEFILE_AVAILABLE = False
    logger.debug("pefile library not available, using r2pipe fallback")


class RichHeaderAnalyzer(
    RichHeaderPefileMixin,
    RichHeaderDirectMixin,
    RichHeaderDebugMixin,
    RichHeaderSearchMixin,
    BaseAnalyzer,
):
    """Rich Header extraction and analysis for PE files"""

    def __init__(
        self,
        adapter: Any | None = None,
        filepath: str | None = None,
        r2_instance: Any | None = None,
    ) -> None:
        if adapter is None:
            adapter = r2_instance
        super().__init__(adapter=adapter, filepath=filepath)

    def analyze(self) -> dict[str, Any]:
        """Run Rich Header analysis on a PE file."""
        logger.debug("Starting Rich Header analysis for %s", self.filepath)

        results: dict[str, Any] = self._init_result_structure(
            {
                "rich_header": None,
                "compilers": [],
                "xor_key": None,
                "checksum": None,
                "richpe_hash": None,
                "error": None,
                "is_pe": False,
                "method_used": None,
            }
        )

        try:
            # Check if file is PE
            if not self._is_pe_file():
                results["error"] = "File is not a PE binary"
                logger.debug("File %s is not a PE binary", self.filepath)
                return results

            results["is_pe"] = True
            logger.debug("File confirmed as PE binary")

            # Try pefile method first (most reliable)
            if PEFILE_AVAILABLE:
                logger.debug("Attempting Rich Header extraction using pefile library")
                rich_data = self._extract_rich_header_pefile()
                if rich_data:
                    results["method_used"] = "pefile"
                    logger.debug("Successfully extracted Rich Header using pefile")
                else:
                    logger.debug("pefile method failed, falling back to r2pipe")

            # Fall back to r2pipe method if pefile failed or not available
            if not rich_data:
                logger.debug("Attempting Rich Header extraction using r2pipe")
                rich_data = self._extract_rich_header_r2pipe()
                if rich_data:
                    results["method_used"] = "r2pipe"
                    logger.debug("Successfully extracted Rich Header using r2pipe")

            if not rich_data:
                results["error"] = "Rich Header not found"
                logger.debug("Rich Header not found with any method")
                return results

            results["available"] = True
            results["rich_header"] = rich_data
            results["xor_key"] = rich_data.get("xor_key")
            results["checksum"] = rich_data.get("checksum")

            logger.debug(
                f"Rich Header extracted successfully: XOR key=0x{rich_data.get('xor_key', 0):08x}"
            )

            # Parse compiler entries
            entries = cast(list[dict[str, Any]], rich_data.get("entries", []))
            compilers = parse_compiler_entries(entries)
            results["compilers"] = compilers
            logger.debug("Parsed %s compiler entries", len(compilers))

            # Calculate RichPE hash
            richpe_hash = calculate_richpe_hash(rich_data)
            if richpe_hash:
                results["richpe_hash"] = richpe_hash
                logger.debug("Calculated RichPE hash: %s", richpe_hash)

        except Exception as e:
            logger.error("Rich Header analysis failed: %s", e)
            results["error"] = str(e)

        return results

    def _extract_rich_header_r2pipe(self) -> dict[str, Any] | None:
        """
        Extract Rich Header using r2pipe (fallback method).

        Returns:
            Dictionary containing Rich Header data or None if not found
        """
        try:
            # Extract Rich Header with detailed debugging
            rich_data = self._extract_rich_header()
            if not rich_data:
                # Try additional debugging
                logger.debug("Standard extraction failed, trying hex dump analysis...")
                self._debug_file_structure()
                return None

            return rich_data

        except Exception as e:
            logger.error("r2pipe Rich Header extraction failed: %s", e)
            return None

    @staticmethod
    def is_available() -> bool:
        """
        Check if Rich Header analysis is available.
        Always returns True as it only depends on r2pipe.

        Returns:
            True if Rich Header analysis is available
        """
        return True

    @staticmethod
    def calculate_richpe_hash_from_file(filepath: str) -> str | None:
        """Calculate RichPE hash directly from a file path."""
        results = run_analyzer_on_file(RichHeaderAnalyzer, filepath)
        if results is None:
            logger.error("Error calculating RichPE hash from file")
            return None
        return cast(str | None, results.get("richpe_hash"))
