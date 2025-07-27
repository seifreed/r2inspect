#!/usr/bin/env python3
"""
Impfuzzy Analyzer Module

This module calculates impfuzzy hash from import API of PE files.
Impfuzzy is a fuzzy hash that's more tolerant to small changes compared to imphash.

Based on research from JPCERT/CC:
- https://github.com/JPCERTCC/impfuzzy
- https://www.jpcert.or.jp/magazine/acreport-impfuzzy.html
- http://blog.jpcert.or.jp/2016/05/classifying-mal-a988.html
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict
from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj

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


class ImpfuzzyAnalyzer:
    """Impfuzzy hash calculation from PE import table"""

    def __init__(self, r2_instance, filepath: str):
        """
        Initialize Impfuzzy analyzer.

        Args:
            r2_instance: Active r2pipe instance
            filepath: Path to the PE file being analyzed
        """
        self.r2 = r2_instance
        self.filepath = filepath

    def analyze(self) -> Dict[str, Any]:
        """
        Perform impfuzzy analysis on PE file.

        Returns:
            Dictionary containing impfuzzy analysis results
        """
        logger.debug(f"Starting impfuzzy analysis for {self.filepath}")

        results = {
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
            impfuzzy_hash = self._calculate_impfuzzy(processed_imports)
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
                    "imports_processed": processed_imports[
                        :50
                    ],  # Limit to first 50 for display
                    "total_imports": len(processed_imports),
                }
            )

            logger.debug(f"Impfuzzy calculated successfully: {impfuzzy_hash}")
            logger.debug(
                f"Processed {len(processed_imports)} imports from {len(unique_dlls)} DLLs"
            )

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
        try:
            # Check file magic bytes directly first (most reliable)
            try:
                with open(self.filepath, "rb") as f:
                    magic = f.read(2)
                    if magic == b"MZ":
                        logger.debug("Found MZ header - likely PE file")
                        return True
            except Exception as e:
                logger.debug(f"Could not read file magic bytes: {e}")

            # Check via r2pipe
            try:
                info_cmd = safe_cmdj(self.r2, "ij", {})
                if info_cmd and "bin" in info_cmd:
                    bin_format = info_cmd["bin"].get("format", "").lower()
                    if "pe" in bin_format:
                        logger.debug("PE detected via r2pipe")
                        return True
            except Exception as e:
                logger.debug(f"Error checking PE via r2pipe: {e}")

            return False

        except Exception as e:
            logger.error(f"Error checking if file is PE: {e}")
            return False

    def _extract_imports(self) -> Optional[List[Dict[str, Any]]]:
        """
        Extract imports from PE file using r2pipe.

        Returns:
            List of import dictionaries or None if extraction fails
        """
        try:
            # Get import information in JSON format
            imports = safe_cmdj(self.r2, "iij", [])

            if not imports:
                logger.debug("No imports found with 'iij' command")
                # Try alternative command
                imports = safe_cmdj(self.r2, "ii", [])
                if isinstance(imports, dict):
                    # Convert single import to list
                    imports = [imports]

            if not imports:
                logger.debug("No imports found with any method")
                return None

            logger.debug(f"Extracted {len(imports)} import entries")
            return imports

        except Exception as e:
            logger.error(f"Error extracting imports: {e}")
            return None

    def _process_imports(self, imports_data: List[Dict[str, Any]]) -> List[str]:
        """
        Process import data into dll.function format required by impfuzzy.

        Args:
            imports_data: List of import dictionaries from r2pipe

        Returns:
            List of strings in format "dll.function"
        """
        processed_imports = []
        dll_funcs = defaultdict(list)

        try:
            for imp in imports_data:
                # Skip if import is not a dictionary (malformed data)
                if not isinstance(imp, dict):
                    logger.debug(f"Skipping malformed import data: {type(imp)} - {imp}")
                    continue

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
                    imp.get("name")
                    or imp.get("func")
                    or imp.get("function")
                    or imp.get("symbol")
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

            logger.debug(
                f"Processed imports into {len(processed_imports)} dll.function entries"
            )

            return processed_imports

        except Exception as e:
            logger.error(f"Error processing imports: {e}")
            return []

    def _calculate_impfuzzy(self, imports_list: List[str]) -> Optional[str]:
        """
        Calculate impfuzzy hash directly from PE file.

        Args:
            imports_list: List of strings in format "dll.function" (used for validation)

        Returns:
            Impfuzzy hash string or None if calculation fails
        """
        try:
            if not imports_list:
                logger.debug("Empty imports list, cannot calculate impfuzzy")
                return None

            # Calculate impfuzzy hash directly from file
            # pyimpfuzzy.get_impfuzzy() expects a file path, not a list
            impfuzzy_hash = pyimpfuzzy.get_impfuzzy(self.filepath)

            if impfuzzy_hash:
                logger.debug(f"Impfuzzy hash calculated: {impfuzzy_hash}")
                return impfuzzy_hash
            else:
                logger.debug("Impfuzzy calculation returned empty result")
                return None

        except Exception as e:
            logger.error(f"Error calculating impfuzzy hash: {e}")
            return None

    @staticmethod
    def is_available() -> bool:
        """
        Check if impfuzzy analysis is available.

        Returns:
            True if impfuzzy library is available
        """
        return IMPFUZZY_AVAILABLE

    @staticmethod
    def calculate_impfuzzy_from_file(filepath: str) -> Optional[str]:
        """
        Calculate impfuzzy hash directly from a file path.

        Args:
            filepath: Path to the PE file

        Returns:
            Impfuzzy hash string or None if calculation fails
        """
        try:
            import r2pipe

            with r2pipe.open(filepath, flags=["-2"]) as r2:
                analyzer = ImpfuzzyAnalyzer(r2, filepath)
                results = analyzer.analyze()
                return results.get("impfuzzy_hash")

        except Exception as e:
            logger.error(f"Error calculating impfuzzy from file: {e}")
            return None
