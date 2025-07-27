"""
Telfhash Analyzer Module

This module provides telfhash capabilities for ELF files.
Telfhash is a fuzzy hash for ELF files based on exported/imported symbols,
similar to imphash for PE files but adapted for ELF binary structure.

Telfhash is particularly useful for:
- Clustering ELF malware families
- Identifying similar ELF binaries with slight variations
- Grouping binaries compiled with different compilers but same source
"""

from typing import Dict, List, Any, Optional

# Try to import telfhash library
try:
    from telfhash import telfhash

    TELFHASH_AVAILABLE = True
except ImportError:
    TELFHASH_AVAILABLE = False

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj, safe_cmd_list

logger = get_logger(__name__)


class TelfhashAnalyzer:
    """Telfhash analyzer for ELF files."""

    def __init__(self, r2_instance, filepath: str):
        """
        Initialize Telfhash analyzer.

        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the file being analyzed
        """
        self.r2 = r2_instance
        self.filepath = filepath

    def analyze(self) -> Dict[str, Any]:
        """
        Perform telfhash analysis on ELF file.

        Returns:
            Dictionary containing telfhash analysis results
        """
        logger.debug(f"Starting telfhash analysis for {self.filepath}")

        results = {
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
            # Note: telfhash() takes a filepath, not a symbol string
            try:
                telfhash_result = telfhash(self.filepath)
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
                    results["telfhash"] = telfhash_result
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
            except Exception:
                pass

            # Method 4: Check if we can get ELF symbols (if it has symbols, likely ELF)
            try:
                symbols = safe_cmd_list(self.r2, "isj")
                if symbols and len(symbols) > 0:
                    # If we can get symbols and file info suggests it's some kind of executable
                    if info_cmd and "bin" in info_cmd:
                        os_info = info_cmd["bin"].get("os", "").lower()
                        if "linux" in os_info or "unix" in os_info:
                            return True
            except Exception:
                pass

            return False

        except Exception as e:
            logger.error(f"Error checking if file is ELF: {e}")
            return False

    def _get_elf_symbols(self) -> List[Dict[str, Any]]:
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

    def _filter_symbols_for_telfhash(
        self, symbols: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
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
        filtered = []

        for sym in symbols:
            # Check if symbol has required fields
            if not isinstance(sym, dict):
                continue

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

    def _extract_symbol_names(self, symbols: List[Dict[str, Any]]) -> List[str]:
        """
        Extract and sort symbol names for telfhash calculation.

        Args:
            symbols: List of filtered symbols

        Returns:
            Sorted list of symbol names
        """
        names = []

        for sym in symbols:
            name = sym.get("name", "").strip()
            if name:
                names.append(name)

        # Sort names for consistent hash calculation
        names.sort()

        logger.debug(f"Extracted {len(names)} symbol names for telfhash")
        return names

    @staticmethod
    def is_available() -> bool:
        """
        Check if telfhash is available.

        Returns:
            True if telfhash is available, False otherwise
        """
        return TELFHASH_AVAILABLE

    @staticmethod
    def calculate_telfhash_from_file(filepath: str) -> Optional[str]:
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
                return result[0].get("telfhash")
            elif isinstance(result, dict):
                return result.get("telfhash")
            return result
        except Exception as e:
            logger.warning(f"Failed to calculate telfhash: {e}")
            return None
