#!/usr/bin/env python3
"""Import analysis module."""

import re
from typing import Any

from ..abstractions import BaseAnalyzer
from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..domain.services.import_analysis import (
    analyze_dll_dependencies as analyze_dll_dependencies_domain,
    build_import_statistics,
    detect_api_obfuscation as detect_api_obfuscation_domain,
    detect_import_anomalies as detect_import_anomalies_domain,
)
from ..infrastructure.logging import get_logger
from .import_analyzer_collection_support import (
    collect_imports as _collect_imports_impl,
    safe_len as _safe_len_impl,
)
from .import_analyzer_result_support import (
    collect_import_dlls as _collect_import_dlls_impl,
    init_import_result as _init_import_result_impl,
    populate_import_statistics as _populate_import_statistics_impl,
)
from .import_analyzer_support import (
    analyze_import as _analyze_import_impl,
    check_import_forwarding as _check_import_forwarding_impl,
    count_suspicious_indicators as _count_suspicious_indicators_impl,
    get_function_description as _get_function_description_impl,
    get_risk_level as _get_risk_level_impl,
    is_candidate_api_string as _is_candidate_api_string_impl,
    matches_known_api as _matches_known_api_impl,
)
from ..domain.services.binary_helpers import clamp_score
from .import_categories import get_api_categories
from ..domain.formats.import_analysis import (
    NETWORK_CATEGORY,
    assess_api_risk,
    build_api_categories,
    categorize_apis,
    find_max_risk_score,
    risk_level_from_score,
)

logger = get_logger(__name__)


class ImportAnalyzer(CommandHelperMixin, BaseAnalyzer):
    """Import table analysis using backend data."""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        super().__init__(adapter=adapter, config=config)
        self._setup_api_categories()
        self._risk_categories = build_api_categories()

    def get_category(self) -> str:
        return "metadata"

    def get_description(self) -> str:
        return "Analyzes imported functions and DLL dependencies with risk assessment and suspicious pattern detection"

    def supports_format(self, file_format: str) -> bool:
        return file_format.upper() in {"PE", "PE32", "PE32+", "DLL", "EXE"}

    def _setup_api_categories(self) -> None:
        """Initialize API categorization data"""
        self.api_categories = get_api_categories()

    def analyze(self) -> dict[str, Any]:
        """Run complete import analysis"""
        result = _init_import_result_impl(self._init_result_structure)

        with self._analysis_context(result, error_message="Import analysis failed"):
            self._log_info("Starting import analysis")

            imports = self.get_imports()
            dlls = _collect_import_dlls_impl(imports)

            result["imports"] = imports
            result["dlls"] = dlls
            result["total_imports"] = len(imports)
            result["total_dlls"] = len(dlls)

            result["api_analysis"] = self.analyze_api_usage(imports)
            result["obfuscation"] = self.detect_api_obfuscation(imports)
            result["dll_analysis"] = self.analyze_dll_dependencies(dlls)
            result["anomalies"] = self.detect_import_anomalies(imports)
            result["forwarding"] = self.check_import_forwarding()
            _populate_import_statistics_impl(
                result,
                get_risk_level_fn=self._get_risk_level,
                count_suspicious_indicators_fn=self._count_suspicious_indicators,
            )

            self._log_info(f"Analyzed {len(imports)} imports from {len(dlls)} DLLs")

        return result

    def _get_risk_level(self, total_risk: float) -> str:
        return _get_risk_level_impl(total_risk)

    def _count_suspicious_indicators(self, result: dict[str, Any]) -> int:
        return _count_suspicious_indicators_impl(result)

    def get_imports(self) -> list[dict[str, Any]]:
        """Get all imported functions with analysis"""
        return _collect_imports_impl(
            cmdj=self._cmdj,
            analyze_import_fn=self._analyze_import,
            logger=logger,
        )

    def _analyze_import(self, imp: dict[str, Any]) -> dict[str, Any]:
        """Analyze a single import"""
        return _analyze_import_impl(imp, self, logger=logger)

    def _calculate_risk_score(self, func_name: str) -> dict[str, Any]:
        """Calculate detailed risk score (0-100) with specific tags"""
        max_score, tags = find_max_risk_score(func_name, self._risk_categories)
        risk_level = risk_level_from_score(max_score)

        return {
            "risk_score": max_score,
            "risk_level": risk_level,
            "risk_tags": tags,
        }

    def _get_function_description(self, func_name: str) -> str:
        """Get description for common functions"""
        return _get_function_description_impl(func_name)

    def get_import_statistics(self) -> dict[str, Any]:
        """Get statistics about imports"""
        imports: list[dict[str, Any]] = []
        try:
            imports = self.get_imports()
            return build_import_statistics(imports)
        except Exception as exc:
            logger.error("Error getting import statistics for %s imports: %s", len(imports), exc)
            return build_import_statistics([])

    def get_missing_imports(self) -> list[str]:
        missing = []

        try:
            # Get all string references that look like API calls
            strings = self._get_via_adapter("get_strings", "izj")
            imported_apis = [imp["name"] for imp in self.get_imports()]

            if strings:
                for string_info in strings:
                    string_val = string_info.get("string", "")
                    if not self._is_candidate_api_string(string_val, imported_apis):
                        continue
                    if self._matches_known_api(string_val):
                        missing.append(string_val)

        except Exception as exc:
            logger.error("Error detecting missing imports: %s", exc)

        return list(set(missing))  # Remove duplicates

    def _is_candidate_api_string(self, string_val: str, imported_apis: list[str]) -> bool:
        return _is_candidate_api_string_impl(string_val, imported_apis)

    def _matches_known_api(self, string_val: str) -> bool:
        return _matches_known_api_impl(string_val, self.api_categories)

    def analyze_api_usage(self, imports: list[dict]) -> dict[str, Any]:
        try:
            if not imports:
                return {"categories": {}, "suspicious_apis": [], "risk_score": 0}

            categories = categorize_apis(imports, self.api_categories)
            suspicious_apis, risk_score = assess_api_risk(categories)

            return {
                "categories": categories,
                "suspicious_apis": suspicious_apis,
                "risk_score": clamp_score(risk_score),
            }

        except Exception as exc:
            logger.error("Error analyzing API usage for %s imports: %s", len(imports), exc)
            return {"categories": {}, "suspicious_apis": [], "risk_score": 0}

    def detect_api_obfuscation(self, imports: list[dict]) -> dict[str, Any]:
        try:
            return detect_api_obfuscation_domain(imports)
        except Exception as exc:
            logger.error(
                "Error detecting API obfuscation for %s imports: %s", len(imports or []), exc
            )
            return {"detected": False, "indicators": [], "score": 0}

    def analyze_dll_dependencies(self, dlls: list[str]) -> dict[str, Any]:
        try:
            return analyze_dll_dependencies_domain(dlls)
        except Exception as exc:
            logger.error(
                "Error analyzing DLL dependencies for %s DLLs: %s", _safe_len_impl(dlls), exc
            )
            return {"common_dlls": [], "suspicious_dlls": [], "analysis": {}}

    def detect_import_anomalies(self, imports: list[dict[str, Any]]) -> dict[str, Any]:
        """Detect anomalies in import table"""
        try:
            return detect_import_anomalies_domain(imports)
        except Exception as exc:
            logger.error(
                "Error detecting import anomalies for %s imports: %s", _safe_len_impl(imports), exc
            )
            return {"anomalies": [], "count": 0}

    def check_import_forwarding(self) -> dict[str, Any]:
        """Check for import forwarding"""
        try:
            strings = self._cmdj("izj", [])
            return _check_import_forwarding_impl(strings, logger=logger)
        except Exception as exc:
            logger.error("Error checking import forwarding from strings: %s", exc)
            return {"detected": False, "forwards": []}
