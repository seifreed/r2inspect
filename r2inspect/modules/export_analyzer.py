#!/usr/bin/env python3
"""
Export Analysis Module using r2pipe
"""

from typing import Any, Dict, List

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd_list, safe_cmdj

logger = get_logger(__name__)


class ExportAnalyzer:
    """Export table analysis using radare2"""

    def __init__(self, r2, config):
        self.r2 = r2
        self.config = config

    def get_exports(self) -> List[Dict[str, Any]]:
        """Get all exported functions with analysis"""
        exports_info = []

        try:
            # Get exports from radare2
            exports = safe_cmd_list(self.r2, "iEj")

            if exports:
                for exp in exports:
                    # Skip if export is not a dictionary (malformed data)
                    if not isinstance(exp, dict):
                        logger.debug(f"Skipping malformed export data: {type(exp)} - {exp}")
                        continue
                    export_analysis = self._analyze_export(exp)
                    exports_info.append(export_analysis)

        except Exception as e:
            logger.error(f"Error getting exports: {e}")

        return exports_info

    def _analyze_export(self, exp: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single export"""
        analysis = {
            "name": exp.get("name", "unknown"),
            "address": hex(exp.get("vaddr", 0)),
            "ordinal": exp.get("ordinal", 0),
            "type": exp.get("type", "unknown"),
            "size": exp.get("size", 0),
            "is_forwarded": exp.get("forwarded", False),
            "forwarder": exp.get("forwarder", ""),
            "characteristics": {},
        }

        try:
            # Analyze export characteristics
            analysis["characteristics"] = self._get_export_characteristics(exp)

        except Exception as e:
            logger.error(f"Error analyzing export: {e}")
            analysis["error"] = str(e)

        return analysis

    def _get_export_characteristics(self, exp: Dict[str, Any]) -> Dict[str, Any]:
        """Get characteristics of an export"""
        characteristics = {}

        try:
            name = exp.get("name", "")
            vaddr = exp.get("vaddr", 0)

            # Check if export is a common DLL export
            if name.startswith("Dll"):
                characteristics["dll_export"] = True

            # Check for suspicious export names
            suspicious_patterns = [
                "install",
                "uninstall",
                "execute",
                "run",
                "start",
                "inject",
                "hook",
                "patch",
                "bypass",
                "disable",
            ]

            for pattern in suspicious_patterns:
                if pattern.lower() in name.lower():
                    characteristics["suspicious_name"] = True
                    characteristics["suspicious_pattern"] = pattern
                    break

            # Check if function has code (not just a data export)
            if vaddr > 0:
                # Try to analyze the function at this address
                func_info = safe_cmdj(self.r2, f"afij @ {vaddr}", [])
                if func_info and len(func_info) > 0:
                    func = func_info[0]
                    # Validate that func is a dictionary before using .get()
                    if isinstance(func, dict):
                        characteristics["function_size"] = func.get("size", 0)
                        characteristics["complexity"] = func.get("cc", 0)  # Cyclomatic complexity
                        characteristics["is_function"] = True
                    else:
                        logger.debug(f"Function info returned non-dict: {type(func)} - {func}")
                        characteristics["is_function"] = False
                else:
                    characteristics["is_function"] = False

        except Exception as e:
            logger.error(f"Error getting export characteristics: {e}")

        return characteristics

    def get_export_statistics(self) -> Dict[str, Any]:
        """Get statistics about exports"""
        stats = {
            "total_exports": 0,
            "function_exports": 0,
            "data_exports": 0,
            "forwarded_exports": 0,
            "suspicious_exports": 0,
            "export_names": [],
        }

        try:
            exports = self.get_exports()

            if exports:
                stats["total_exports"] = len(exports)

                for exp in exports:
                    # Skip if export is not a dictionary (malformed data)
                    if not isinstance(exp, dict):
                        logger.debug(
                            f"Skipping malformed export data in statistics: {type(exp)} - {exp}"
                        )
                        continue

                    stats["export_names"].append(exp.get("name", "unknown"))

                    if exp.get("is_forwarded"):
                        stats["forwarded_exports"] += 1

                    if exp.get("characteristics", {}).get("is_function"):
                        stats["function_exports"] += 1
                    else:
                        stats["data_exports"] += 1

                    if exp.get("characteristics", {}).get("suspicious_name"):
                        stats["suspicious_exports"] += 1

        except Exception as e:
            logger.error(f"Error getting export statistics: {e}")

        return stats
