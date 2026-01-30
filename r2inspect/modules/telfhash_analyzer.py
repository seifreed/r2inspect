"""
Telfhash Analyzer Module

This module provides telfhash capabilities for ELF files.
Telfhash is a fuzzy hash for ELF files based on exported/imported symbols,
similar to imphash for PE files but adapted for ELF binary structure.

Telfhash is particularly useful for:
- Clustering ELF malware families
- Identifying similar ELF binaries with slight variations
- Grouping binaries compiled with different compilers but same source

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0 (GPLv3)
"""

from typing import Any, cast

# Try to import telfhash library
try:
    from telfhash import telfhash

    TELFHASH_AVAILABLE = True
except ImportError:
    TELFHASH_AVAILABLE = False

from ..abstractions.hashing_strategy import HashingStrategy
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd_list, safe_cmdj

logger = get_logger(__name__)


class TelfhashAnalyzer(HashingStrategy):
    """Telfhash analyzer for ELF files."""

    def __init__(self, r2_instance, filepath: str):
        """
        Initialize Telfhash analyzer.

        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the file being analyzed
        """
        # Initialize parent with filepath
        super().__init__(filepath=filepath, r2_instance=r2_instance)

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
            logger.debug(f"Telfhash function returned: {type(telfhash_result)} = {telfhash_result}")

            # Parse result based on return type
            hash_value = None
            if isinstance(telfhash_result, list) and len(telfhash_result) > 0:
                # telfhash returns a list with one dictionary for single file
                result_dict = telfhash_result[0]
                hash_value = result_dict.get("telfhash")
                if result_dict.get("msg"):
                    return None, None, result_dict.get("msg")
            elif isinstance(telfhash_result, dict):
                # Extract the actual hash from the result dictionary
                hash_value = telfhash_result.get("telfhash")
                if telfhash_result.get("msg"):
                    return None, None, telfhash_result.get("msg")
            else:
                hash_value = cast(str | None, telfhash_result)

            if hash_value:
                logger.debug(f"Telfhash calculated: {hash_value}")
                return hash_value, "python_library", None
            return None, None, "Telfhash calculation returned no hash"

        except Exception as e:
            logger.error(f"Error calculating telfhash: {e}")
            return None, None, f"Telfhash calculation failed: {str(e)}"

    def _get_hash_type(self) -> str:
        """
        Return the hash type identifier.

        Returns:
            Hash type string
        """
        return "telfhash"

    def analyze_symbols(self) -> dict[str, Any]:
        """
        Perform detailed telfhash analysis on ELF file including symbol statistics.

        This method provides detailed symbol analysis in addition to the
        telfhash value provided by analyze().

        Returns:
            Dictionary containing detailed telfhash analysis results
        """
        logger.debug(f"Starting detailed telfhash analysis for {self.filepath}")

        results: dict[str, Any] = {
            "available": TELFHASH_AVAILABLE,
            "telfhash": None,
            "symbol_count": 0,
            "filtered_symbols": 0,
            "symbols_used": [],
            "error": None,
            "is_elf": False,
        }

        if not TELFHASH_AVAILABLE:
            results["error"] = "telfhash library not available"
            logger.error("telfhash library not available")
            return results

        try:
            # Check if file is ELF
            if not self._is_elf_file():
                results["error"] = "File is not an ELF binary"
                logger.warning(f"File {self.filepath} is not an ELF binary")
                return results

            results["is_elf"] = True

            # Get symbols from ELF
            symbols = self._get_elf_symbols()
            results["symbol_count"] = len(symbols)

            # Filter symbols for telfhash calculation
            filtered_symbols = self._filter_symbols_for_telfhash(symbols)
            results["filtered_symbols"] = len(filtered_symbols)

            # Extract symbol names and sort them
            symbol_names = self._extract_symbol_names(filtered_symbols)
            results["symbols_used"] = symbol_names[:20]  # Store first 20 for reference

            # Calculate telfhash using the official telfhash library
            try:
                telfhash_result = telfhash(str(self.filepath))
                logger.debug(
                    f"Telfhash function returned: {type(telfhash_result)} = {telfhash_result}"
                )

                if isinstance(telfhash_result, list) and len(telfhash_result) > 0:
                    # telfhash returns a list with one dictionary for single file
                    result_dict = telfhash_result[0]
                    results["telfhash"] = result_dict.get("telfhash")
                    if result_dict.get("msg"):
                        results["error"] = result_dict.get("msg")
                    logger.debug(f"Telfhash calculated: {results['telfhash']}")
                elif isinstance(telfhash_result, dict):
                    # Extract the actual hash from the result dictionary
                    results["telfhash"] = telfhash_result.get("telfhash")
                    if telfhash_result.get("msg"):
                        results["error"] = telfhash_result.get("msg")
                    logger.debug(f"Telfhash calculated: {results['telfhash']}")
                else:
                    results["telfhash"] = cast(str | None, telfhash_result)
                    logger.debug(f"Telfhash calculated: {results['telfhash']}")

            except Exception as e:
                logger.error(f"Error calling telfhash function: {e}")
                results["error"] = f"Telfhash calculation failed: {e}"

        except Exception as e:
            logger.error(f"Telfhash analysis failed: {e}")
            results["error"] = str(e)

        return results

    def _is_elf_file(self) -> bool:
        """
        Check if the file is an ELF binary.

        Returns:
            True if file is ELF, False otherwise
        """
        try:
            # Try multiple methods to detect ELF format

            # Method 1: Check file info command
            if self.r2 is None:
                return False
            info_text = self.r2.cmd("i")
            if "elf" in info_text.lower():
                return True

            # Method 2: Check binary info via ij command
            info_cmd = safe_cmdj(self.r2, "ij", {})
            if info_cmd and "bin" in info_cmd:
                bin_info = info_cmd["bin"]

                # Check format field
                bin_format = bin_info.get("format", "").lower()
                if "elf" in bin_format:
                    return True

                # Check type field
                bin_type = bin_info.get("type", "").lower()
                if "elf" in bin_type:
                    return True

                # Check class field (ELF32/ELF64)
                bin_class = bin_info.get("class", "").lower()
                if "elf" in bin_class:
                    return True

            # Method 3: Check file magic bytes directly
            try:
                with open(self.filepath, "rb") as f:
                    magic = f.read(4)
                    # ELF magic: 0x7F followed by 'ELF'
                    if magic == b"\x7fELF":
                        return True
            except Exception as exc:
                logger.debug(f"Failed to read ELF magic bytes: {exc}")

            # Method 4: Check if we can get ELF symbols (if it has symbols, likely ELF)
            try:
                symbols = safe_cmd_list(self.r2, "isj")
                if symbols and len(symbols) > 0:
                    # If we can get symbols and file info suggests it's some kind of executable
                    if info_cmd and "bin" in info_cmd:
                        os_info = info_cmd["bin"].get("os", "").lower()
                        if "linux" in os_info or "unix" in os_info:
                            return True
            except Exception as exc:
                logger.debug(f"Failed to inspect ELF symbols: {exc}")

            return False

        except Exception as e:
            logger.error(f"Error checking if file is ELF: {e}")
            return False

    def _get_elf_symbols(self) -> list[dict[str, Any]]:
        """
        Get all symbols from the ELF file.

        Returns:
            List of symbol dictionaries
        """
        try:
            logger.debug("Extracting symbols from ELF file")
            symbols = safe_cmd_list(self.r2, "isj")
            if not symbols:
                logger.warning("No symbols found in ELF file")
                return []

            logger.debug(f"Found {len(symbols)} total symbols")
            return symbols

        except Exception as e:
            logger.error(f"Failed to extract symbols: {e}")
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
        filtered: list[dict[str, Any]] = []

        for sym in symbols:
            sym_type = sym.get("type", "").upper()
            sym_bind = sym.get("bind", "").upper()
            sym_name = sym.get("name", "")

            # Filter by type: FUNC (functions) and OBJECT (data objects)
            if sym_type not in {"FUNC", "OBJECT"}:
                continue

            # Filter by binding: exclude LOCAL symbols
            if sym_bind == "LOCAL":
                continue

            # Must have a name
            if not sym_name or sym_name.strip() == "":
                continue

            # Skip some common unwanted symbols
            if self._should_skip_symbol(sym_name):
                continue

            filtered.append(sym)

        logger.debug(f"Filtered {len(filtered)} symbols from {len(symbols)} total")
        return filtered

    def _should_skip_symbol(self, symbol_name: str) -> bool:
        """
        Check if a symbol should be skipped for telfhash calculation.

        Args:
            symbol_name: Name of the symbol

        Returns:
            True if symbol should be skipped, False otherwise
        """
        # Skip empty or very short names
        if len(symbol_name) < 2:
            return True

        # Skip some common unwanted prefixes/patterns
        skip_patterns = [
            "__",  # Internal symbols
            "_GLOBAL_",  # Global offset table entries
            "_DYNAMIC",  # Dynamic section symbols
            ".L",  # Local labels
            "_edata",  # End of data
            "_end",  # End of program
            "_start",  # Program start (sometimes too generic)
        ]

        for pattern in skip_patterns:
            if symbol_name.startswith(pattern):
                return True

        return False

    def _extract_symbol_names(self, symbols: list[dict[str, Any]]) -> list[str]:
        """
        Extract and sort symbol names for telfhash calculation.

        Args:
            symbols: List of filtered symbols

        Returns:
            Sorted list of symbol names
        """
        names: list[str] = []

        for sym in symbols:
            name = sym.get("name", "").strip()
            if name:
                names.append(name)

        # Sort names for consistent hash calculation
        names.sort()

        logger.debug(f"Extracted {len(names)} symbol names for telfhash")
        return names

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
            import ssdeep

            return cast(int, ssdeep.compare(hash1, hash2))
        except ImportError:
            logger.warning("ssdeep library required for telfhash comparison")
            return None
        except Exception as e:
            logger.warning(f"Telfhash comparison failed: {e}")
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
                return cast(str | None, result[0].get("telfhash"))
            elif isinstance(result, dict):
                return cast(str | None, result.get("telfhash"))
            return cast(str | None, result)
        except Exception as e:
            logger.warning(f"Failed to calculate telfhash: {e}")
            return None
