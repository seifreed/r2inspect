#!/usr/bin/env python3
"""Impfuzzy hash calculation for PE imports."""

from collections import defaultdict
from typing import Any, cast

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..abstractions.hashing_strategy import HashingStrategy
from ..utils.file_type import is_pe_file
from ..utils.logger import get_logger
from ..utils.ssdeep_loader import get_ssdeep

logger = get_logger(__name__)

# Try to import impfuzzy library
try:
    import pyimpfuzzy

    IMPFUZZY_AVAILABLE = True
    logger.debug("pyimpfuzzy library available")
except ImportError:
    try:
        import impfuzzy as pyimpfuzzy

        IMPFUZZY_AVAILABLE = True
        logger.debug("impfuzzy library available")
    except ImportError:
        IMPFUZZY_AVAILABLE = False
        logger.debug("impfuzzy library not available")


class ImpfuzzyAnalyzer(CommandHelperMixin, HashingStrategy):
    """Impfuzzy hash calculation from PE import table"""

    def __init__(self, adapter: Any, filepath: str) -> None:
        """
        Initialize Impfuzzy analyzer.

        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the PE file being analyzed
        """
        # Initialize parent with filepath
        super().__init__(filepath=filepath, r2_instance=adapter)
        self.adapter: Any = adapter

    def _check_library_availability(self) -> tuple[bool, str | None]:
        """
        Check if impfuzzy library is available.

        Returns:
            Tuple of (is_available, error_message)
        """
        if ImpfuzzyAnalyzer.is_available():
            return True, None
        return (
            False,
            "pyimpfuzzy library not available. Install with: pip install pyimpfuzzy",
        )

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        """
        Calculate impfuzzy hash for the PE file.

        Returns:
            Tuple of (hash_value, method_used, error_message)
        """
        try:
            # Check if file is PE
            if not self._is_pe_file():
                return None, None, "File is not a PE binary"

            # Calculate impfuzzy hash directly from file
            impfuzzy_hash = pyimpfuzzy.get_impfuzzy(str(self.filepath))

            if impfuzzy_hash:
                logger.debug(f"Impfuzzy hash calculated: {impfuzzy_hash}")
                return impfuzzy_hash, "python_library", None
            else:
                return (
                    None,
                    None,
                    "No imports found or failed to calculate impfuzzy hash",
                )

        except Exception as e:
            logger.error(f"Error calculating impfuzzy hash: {e}")
            return None, None, f"Impfuzzy calculation failed: {str(e)}"

    def _get_hash_type(self) -> str:
        """
        Return the hash type identifier.

        Returns:
            Hash type string
        """
        return "impfuzzy"

    def analyze_imports(self) -> dict[str, Any]:
        """
        Perform detailed impfuzzy analysis on PE file including import statistics.

        This method provides detailed import analysis in addition to the
        impfuzzy hash provided by analyze().

        Returns:
            Dictionary containing detailed impfuzzy analysis results
        """
        logger.debug(f"Starting detailed impfuzzy analysis for {self.filepath}")

        results: dict[str, Any] = {
            "available": False,
            "impfuzzy_hash": None,
            "import_count": 0,
            "dll_count": 0,
            "imports_processed": [],
            "error": None,
            "library_available": IMPFUZZY_AVAILABLE,
        }

        if not IMPFUZZY_AVAILABLE:
            results["error"] = "pyimpfuzzy library not available"
            logger.warning("pyimpfuzzy library not available for impfuzzy calculation")
            return results

        try:
            # Check if file is PE
            if not self._is_pe_file():
                results["error"] = "File is not a PE binary"
                logger.debug(f"File {self.filepath} is not a PE binary")
                return results

            # Extract imports using r2pipe
            imports_data = self._extract_imports()
            if not imports_data:
                results["error"] = "No imports found or failed to extract imports"
                logger.debug("No imports found in PE file")
                return results

            # Process imports into dll.function format
            processed_imports = self._process_imports(imports_data)
            if not processed_imports:
                results["error"] = "No valid imports found after processing"
                logger.debug("No valid imports found after processing")
                return results

            # Calculate impfuzzy hash
            impfuzzy_hash = pyimpfuzzy.get_impfuzzy(str(self.filepath))
            if not impfuzzy_hash:
                results["error"] = "Failed to calculate impfuzzy hash"
                logger.debug("Failed to calculate impfuzzy hash")
                return results

            # Count unique DLLs
            unique_dlls = set()
            for imp_str in processed_imports:
                dll_name = imp_str.split(".")[0]
                unique_dlls.add(dll_name)

            results.update(
                {
                    "available": True,
                    "impfuzzy_hash": impfuzzy_hash,
                    "import_count": len(processed_imports),
                    "dll_count": len(unique_dlls),
                    "imports_processed": processed_imports[:50],  # Limit to first 50 for display
                    "total_imports": len(processed_imports),
                }
            )

            logger.debug(f"Impfuzzy calculated successfully: {impfuzzy_hash}")
            logger.debug(f"Processed {len(processed_imports)} imports from {len(unique_dlls)} DLLs")

        except Exception as e:
            logger.error(f"Impfuzzy analysis failed: {e}")
            results["error"] = str(e)

        return results

    def _is_pe_file(self) -> bool:
        """
        Check if the file is a PE binary.

        Returns:
            True if file is PE, False otherwise
        """
        return is_pe_file(self.filepath, self.adapter, self.r2, logger=logger)

    def _extract_imports(self) -> list[dict[str, Any]]:
        """
        Extract imports from PE file using r2pipe.

        Returns:
            List of import dictionaries or None if extraction fails
        """
        try:
            # Get import information in JSON format
            imports: list[dict[str, Any]] = []
            if self.adapter is not None and hasattr(self.adapter, "get_imports"):
                raw_imports = self.adapter.get_imports()
            else:
                raw_imports = self._cmdj("iij", [])

            if isinstance(raw_imports, list):
                imports = [imp for imp in raw_imports if isinstance(imp, dict)]
            elif isinstance(raw_imports, dict):
                imports = [raw_imports]

            if not imports:
                logger.debug("No imports found with 'iij' command")
                # Try alternative command
                raw_imports = self._cmdj("ii", [])
                if isinstance(raw_imports, list):
                    imports = [imp for imp in raw_imports if isinstance(imp, dict)]
                elif isinstance(raw_imports, dict):
                    imports = [raw_imports]

            if not imports:
                logger.debug("No imports found with any method")
                return []

            logger.debug(f"Extracted {len(imports)} import entries")
            return imports

        except Exception as e:
            logger.error(f"Error extracting imports: {e}")
            return []

    def _process_imports(self, imports_data: list[dict[str, Any]]) -> list[str]:
        """
        Process import data into dll.function format required by impfuzzy.

        Args:
            imports_data: List of import dictionaries from r2pipe

        Returns:
            List of strings in format "dll.function"
        """
        processed_imports: list[str] = []
        dll_funcs = defaultdict(list)

        try:
            for imp in imports_data:
                # Extract DLL name
                dll = (
                    imp.get("libname")
                    or imp.get("lib")
                    or imp.get("library")
                    or imp.get("module")
                    or "unknown"
                )

                # Extract function name
                func_name = (
                    imp.get("name") or imp.get("func") or imp.get("function") or imp.get("symbol")
                )

                if func_name and func_name != "unknown":
                    # Normalize names to lowercase
                    dll_clean = dll.lower().replace(".dll", "")
                    func_clean = func_name.lower()

                    # Remove ordinals and prefixes
                    if func_clean.startswith("ord_"):
                        continue  # Skip ordinal imports

                    # Add to dll_funcs mapping
                    dll_funcs[dll_clean].append(func_clean)

            # Convert to flat list in dll.function format
            for dll, functions in dll_funcs.items():
                for func in functions:
                    processed_imports.append(f"{dll}.{func}")

            # Sort imports for consistency
            processed_imports.sort()

            logger.debug(f"Processed imports into {len(processed_imports)} dll.function entries")

            return processed_imports

        except Exception as e:
            logger.error(f"Error processing imports: {e}")
            return []

    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> int | None:
        """
        Compare two impfuzzy hashes and return similarity score.

        Impfuzzy uses SSDeep-based comparison, returning a percentage (0-100)
        where higher values indicate greater similarity.

        Args:
            hash1: First impfuzzy hash
            hash2: Second impfuzzy hash

        Returns:
            Similarity score (0-100, higher is more similar) or None if comparison fails

        Example:
            >>> hash1 = "3:abcd..."
            >>> hash2 = "3:abce..."
            >>> similarity = ImpfuzzyAnalyzer.compare_hashes(hash1, hash2)
            >>> if similarity is not None and similarity > 70:
            ...     print("Very similar")
        """
        if not IMPFUZZY_AVAILABLE:
            return None

        if not hash1 or not hash2:
            return None

        try:
            # pyimpfuzzy uses ssdeep comparison internally
            ssdeep_module = get_ssdeep()
            if ssdeep_module is None:
                logger.warning("ssdeep library required for impfuzzy comparison")
                return None
            return cast(int, ssdeep_module.compare(hash1, hash2))
        except Exception as e:
            logger.warning(f"Impfuzzy comparison failed: {e}")
            return None

    @staticmethod
    def is_available() -> bool:
        """
        Check if impfuzzy library is available.

        Returns:
            True if impfuzzy library can be imported, False otherwise
        """
        return IMPFUZZY_AVAILABLE

    @staticmethod
    def calculate_impfuzzy_from_file(filepath: str) -> str | None:
        """
        Calculate impfuzzy hash directly from a file path.

        Args:
            filepath: Path to the PE file

        Returns:
            Impfuzzy hash string or None if calculation fails
        """
        if not IMPFUZZY_AVAILABLE:
            return None

        try:
            return cast(str | None, pyimpfuzzy.get_impfuzzy(filepath))
        except Exception as e:
            logger.error(f"Error calculating impfuzzy from file: {e}")
            return None
