"""Telfhash analyzer for ELF binaries."""

from typing import Any, cast

# Try to import telfhash library
try:
    from telfhash import telfhash

    TELFHASH_AVAILABLE = True
except ImportError:
    TELFHASH_AVAILABLE = False

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..abstractions.hashing_strategy import R2HashingStrategy
from ..infrastructure.file_type import is_elf_file, is_pe_file
from ..infrastructure.logging import get_logger
from ..infrastructure.ssdeep_loader import get_ssdeep
from .telfhash_analysis import (
    analyze_symbols as _analyze_symbols_impl,
    is_elf_binary as _is_elf_binary_impl,
)
from ..domain.formats.telfhash import (
    extract_symbol_names as _extract_symbol_names_impl,
    filter_symbols_for_telfhash as _filter_symbols_for_telfhash_impl,
    normalize_telfhash_value as _normalize_telfhash_value_impl,
    parse_telfhash_result as _parse_telfhash_result_impl,
    should_skip_symbol as _should_skip_symbol_impl,
)

logger = get_logger(__name__)


class TelfhashAnalyzer(CommandHelperMixin, R2HashingStrategy):
    """Telfhash analyzer for ELF files."""

    def __init__(self, adapter: Any, filepath: str) -> None:
        """
        Initialize Telfhash analyzer.

        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the file being analyzed
        """
        super().__init__(adapter=adapter, filepath=filepath)

    def _check_library_availability(self) -> tuple[bool, str | None]:
        """
        Check if telfhash library is available.

        Returns:
            Tuple of (is_available, error_message)
        """
        if TELFHASH_AVAILABLE:
            return True, None
        return (
            False,
            "telfhash library not available. Install with: pip install telfhash",
        )

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        """
        Calculate telfhash for the ELF file.

        Returns:
            Tuple of (hash_value, method_used, error_message)
        """
        try:
            # Check if file is ELF
            if not self._is_elf_file():
                return None, None, "File is not an ELF binary"

            # Calculate telfhash using the official telfhash library
            telfhash_result = telfhash(str(self.filepath))
            logger.debug(
                "Telfhash function returned: %s = %s", type(telfhash_result), telfhash_result
            )

            hash_value, message = _parse_telfhash_result_impl(telfhash_result)

            if message and not hash_value:
                return None, None, message

            if hash_value:
                logger.debug("Telfhash calculated: %s", hash_value)
                return hash_value, "python_library", None
            return None, None, "Telfhash calculation returned no hash"

        except Exception as e:
            logger.error("Error calculating telfhash: %s", e)
            return None, None, f"Telfhash calculation failed: {str(e)}"

    def _get_hash_type(self) -> str:
        """
        Return the hash type identifier.

        Returns:
            Hash type string
        """
        return "telfhash"

    def analyze(self) -> dict[str, Any]:
        """Run telfhash analysis and include a telfhash field for compatibility."""
        result = super().analyze()
        if "telfhash" not in result:
            result["telfhash"] = result.get("hash_value")
        return result

    def analyze_symbols(self) -> dict[str, Any]:
        """
        Perform detailed telfhash analysis on ELF file including symbol statistics.

        This method provides detailed symbol analysis in addition to the
        telfhash value provided by analyze().

        Returns:
            Dictionary containing detailed telfhash analysis results
        """
        return _analyze_symbols_impl(
            self,
            telfhash_available=TELFHASH_AVAILABLE,
            telfhash_fn=telfhash,
            logger=logger,
        )

    def _is_elf_file(self) -> bool:
        """
        Check if the file is an ELF binary.

        Returns:
            True if file is ELF, False otherwise
        """
        return _is_elf_binary_impl(
            self,
            logger=logger,
            is_elf_file_fn=is_elf_file,
            is_pe_file_fn=is_pe_file,
        )

    def _has_elf_symbols(self, info_cmd: dict[str, Any] | None) -> bool:
        try:
            symbols = self._cmd_list("isj")
            if not symbols:
                return False
            if not info_cmd or "bin" not in info_cmd:
                return False
            os_info = str(info_cmd["bin"].get("os", "")).lower()
            return "linux" in os_info or "unix" in os_info
        except Exception as exc:
            logger.debug("Failed to inspect ELF symbols: %s", exc)
            return False

    def _get_elf_symbols(self) -> list[dict[str, Any]]:
        """
        Get all symbols from the ELF file.

        Returns:
            List of symbol dictionaries
        """
        try:
            logger.debug("Extracting symbols from ELF file")
            symbols = self._cmd_list("isj")
            if not symbols:
                logger.warning("No symbols found in ELF file")
                return []

            logger.debug("Found %s total symbols", len(symbols))
            return symbols

        except Exception as e:
            logger.error("Failed to extract symbols: %s", e)
            return []

    def _filter_symbols_for_telfhash(self, symbols: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Filter symbols suitable for telfhash calculation.

        Telfhash uses:
        - FUNC (functions) and OBJECT (data objects) types
        - Non-LOCAL bindings (GLOBAL, WEAK are preferred)
        - Named symbols only

        Args:
            symbols: List of all symbols

        Returns:
            List of filtered symbols suitable for telfhash
        """
        filtered = _filter_symbols_for_telfhash_impl(symbols)
        logger.debug("Filtered %s symbols from %s total", len(filtered), len(symbols))
        return filtered

    def _should_skip_symbol(self, symbol_name: str) -> bool:
        """
        Check if a symbol should be skipped for telfhash calculation.

        Args:
            symbol_name: Name of the symbol

        Returns:
            True if symbol should be skipped, False otherwise
        """
        return _should_skip_symbol_impl(symbol_name)

    def _extract_symbol_names(self, symbols: list[dict[str, Any]]) -> list[str]:
        """
        Extract and sort symbol names for telfhash calculation.

        Args:
            symbols: List of filtered symbols

        Returns:
            Sorted list of symbol names
        """
        names = _extract_symbol_names_impl(symbols)
        logger.debug("Extracted %s symbol names for telfhash", len(names))
        return names

    @staticmethod
    def _normalize_telfhash_value(value: Any) -> str | None:
        return _normalize_telfhash_value_impl(value)

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> int | None:
        """
        Compare two telfhash values and return similarity score.

        Telfhash uses SSDeep-based comparison internally, returning a percentage
        (0-100) where higher values indicate greater similarity.

        Args:
            hash1: First telfhash value
            hash2: Second telfhash value

        Returns:
            Similarity score (0-100, higher is more similar) or None if comparison fails

        Example:
            >>> hash1 = "T1234..."
            >>> hash2 = "T1235..."
            >>> similarity = TelfhashAnalyzer.compare_hashes(hash1, hash2)
            >>> if similarity is not None and similarity > 70:
            ...     print("Very similar ELF binaries")
        """
        if not TELFHASH_AVAILABLE:
            return None

        if not hash1 or not hash2:
            return None

        try:
            # Telfhash uses SSDeep comparison internally
            ssdeep_module = get_ssdeep()
            if ssdeep_module is None:
                logger.warning("ssdeep library required for telfhash comparison")
                return None
            return cast(int, ssdeep_module.compare(hash1, hash2))
        except Exception as e:
            logger.warning("Telfhash comparison failed: %s", e)
            return None

    @staticmethod
    def is_available() -> bool:
        """
        Check if telfhash library is available.

        Returns:
            True if telfhash library can be imported, False otherwise
        """
        return TELFHASH_AVAILABLE

    @staticmethod
    def calculate_telfhash_from_file(filepath: str) -> str | None:
        """
        Calculate telfhash from a file path.

        Args:
            filepath: Path to the ELF file

        Returns:
            Telfhash string or None if calculation fails
        """
        if not TELFHASH_AVAILABLE:
            return None

        try:
            result = telfhash(filepath)
            if isinstance(result, list) and len(result) > 0:
                return TelfhashAnalyzer._normalize_telfhash_value(result[0].get("telfhash"))
            elif isinstance(result, dict):
                return TelfhashAnalyzer._normalize_telfhash_value(result.get("telfhash"))
            return TelfhashAnalyzer._normalize_telfhash_value(result)
        except Exception as e:
            logger.warning("Failed to calculate telfhash: %s", e)
            return None
