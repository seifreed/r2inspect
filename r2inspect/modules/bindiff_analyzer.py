#!/usr/bin/env python3
"""Binary diffing and comparison analyzer."""

import hashlib
from pathlib import Path
from typing import Any

from ..utils.command_helpers import cmd as cmd_helper
from ..utils.logger import get_logger
from .bindiff_domain import (
    build_behavioral_signature,
    build_function_signature,
    build_string_signature,
    build_struct_signature,
    calculate_cyclomatic_complexity,
    calculate_overall_similarity,
    calculate_rolling_hash,
    categorize_similarity,
    compare_behavioral_features,
    compare_byte_features,
    compare_function_features,
    compare_string_features,
    compare_structural_features,
    has_crypto_indicators,
    has_network_indicators,
    has_persistence_indicators,
    is_crypto_api,
    is_network_api,
    is_suspicious_api,
)
from .string_classification import is_api_string, is_path_string, is_registry_string, is_url_string

logger = get_logger(__name__)


class BinDiffAnalyzer:
    """Binary diffing and comparison analyzer"""

    def __init__(self, adapter: Any, filepath: str) -> None:
        self.adapter = adapter
        self.r2 = adapter
        self.filepath = filepath
        self.filename = Path(filepath).name

    def analyze(self) -> dict[str, Any]:
        """Perform binary diffing analysis"""
        try:
            logger.debug(f"Starting binary diff analysis for {self.filename}")

            results = {
                "filename": self.filename,
                "filepath": self.filepath,
                "structural_features": self._extract_structural_features(),
                "function_features": self._extract_function_features(),
                "string_features": self._extract_string_features(),
                "byte_features": self._extract_byte_features(),
                "behavioral_features": self._extract_behavioral_features(),
                "comparison_ready": True,
            }

            # Generate comparison signatures
            results["signatures"] = self._generate_comparison_signatures(results)

            logger.debug(f"Binary diff analysis completed for {self.filename}")
            return results

        except Exception as e:
            logger.error(f"Error in binary diff analysis for {self.filename}: {e}")
            return {
                "filename": self.filename,
                "filepath": self.filepath,
                "error": str(e),
                "comparison_ready": False,
            }

    def compare_with(self, other_results: dict[str, Any]) -> dict[str, Any]:
        """Compare this binary with another binary's analysis results"""
        try:
            # Get our own analysis results first
            our_results = self.analyze()

            if not our_results.get("comparison_ready") or not other_results.get("comparison_ready"):
                return {
                    "error": "One or both binaries are not ready for comparison",
                    "similarity_score": 0.0,
                }

            comparison = {
                "binary_a": our_results["filename"],
                "binary_b": other_results["filename"],
                "structural_similarity": self._compare_structural(our_results, other_results),
                "function_similarity": self._compare_functions(our_results, other_results),
                "string_similarity": self._compare_strings(our_results, other_results),
                "byte_similarity": self._compare_bytes(our_results, other_results),
                "behavioral_similarity": self._compare_behavioral(our_results, other_results),
            }

            # Calculate overall similarity score
            overall_score = calculate_overall_similarity(
                comparison["structural_similarity"],
                comparison["function_similarity"],
                comparison["string_similarity"],
                comparison["byte_similarity"],
                comparison["behavioral_similarity"],
            )

            comparison["overall_similarity"] = overall_score
            comparison["similarity_level"] = categorize_similarity(overall_score)

            return comparison

        except Exception as e:
            logger.error(f"Error comparing binaries: {e}")
            return {"error": str(e), "similarity_score": 0.0}

    def _extract_structural_features(self) -> dict[str, Any]:
        """Extract structural features for comparison"""
        features: dict[str, Any] = {}

        try:
            # Get file info
            file_info = self.adapter.get_file_info() if self.adapter else {}
            if file_info:
                features["file_type"] = file_info.get("core", {}).get("format", "")
                features["architecture"] = file_info.get("bin", {}).get("arch", "")
                features["bits"] = file_info.get("bin", {}).get("bits", 0)
                features["endian"] = file_info.get("bin", {}).get("endian", "")
                features["file_size"] = file_info.get("core", {}).get("size", 0)

            # Get sections info
            sections = self.adapter.get_sections() if self.adapter else []
            if sections:
                features["section_count"] = len(sections)
                features["section_names"] = sorted(
                    [s.get("name", "") for s in sections if s.get("name")]
                )
                features["section_sizes"] = [s.get("size", 0) for s in sections]
                features["executable_sections"] = len(
                    [s for s in sections if s.get("perm", "").find("x") != -1]
                )
                features["writable_sections"] = len(
                    [s for s in sections if s.get("perm", "").find("w") != -1]
                )

            # Get imports info
            imports = self.adapter.get_imports() if self.adapter else []
            if imports:
                features["import_count"] = len(imports)
                features["imported_dlls"] = list(
                    {imp.get("libname", "") for imp in imports if imp.get("libname")}
                )
                features["imported_functions"] = [
                    imp.get("name", "") for imp in imports if imp.get("name")
                ]

            # Get exports info
            exports = self.adapter.get_exports() if self.adapter else []
            if exports:
                features["export_count"] = len(exports)
                features["exported_functions"] = [
                    exp.get("name", "") for exp in exports if exp.get("name")
                ]

        except Exception as e:
            logger.debug(f"Error extracting structural features: {e}")

        return features

    def _extract_function_features(self) -> dict[str, Any]:
        """Extract function-level features for comparison"""
        features: dict[str, Any] = {}

        try:
            # Analyze functions
            cmd_helper(self.adapter, self.r2, "aaa")

            # Get function list
            functions = self.adapter.get_functions() if self.adapter else []
            if functions:
                features["function_count"] = len(functions)
                features["function_sizes"] = [f.get("size", 0) for f in functions]
                features["function_names"] = [f.get("name", "") for f in functions if f.get("name")]

                # Analyze a subset of functions for CFG similarity
                cfg_features = []
                for func in functions[:10]:  # Limit to first 10 functions
                    func_addr = func.get("offset", 0)
                    if func_addr:
                        cfg = self.adapter.get_cfg(func_addr) if self.adapter else {}
                        if cfg and isinstance(cfg, list) and cfg:
                            cfg_data = cfg[0]
                        elif isinstance(cfg, dict):
                            cfg_data = cfg
                        else:
                            cfg_data = {}
                        if cfg_data:
                            cfg_features.append(
                                {
                                    "nodes": len(cfg_data.get("blocks", [])),
                                    "edges": len(cfg_data.get("edges", [])),
                                    "complexity": calculate_cyclomatic_complexity(cfg_data),
                                }
                            )

                features["cfg_features"] = cfg_features

        except Exception as e:
            logger.debug(f"Error extracting function features: {e}")

        return features

    def _extract_string_features(self) -> dict[str, Any]:
        """Extract string-based features for comparison"""
        features: dict[str, Any] = {}

        try:
            # Get strings
            strings = self.adapter.get_strings() if self.adapter else []
            if strings:
                string_values = [s.get("string", "") for s in strings if s.get("string")]
                features["total_strings"] = len(string_values)
                features["unique_strings"] = len(set(string_values))
                features["string_lengths"] = [len(s) for s in string_values]

                # Categorize strings
                api_strings = [s for s in string_values if is_api_string(s)]
                path_strings = [s for s in string_values if is_path_string(s)]
                url_strings = [s for s in string_values if is_url_string(s)]
                registry_strings = [s for s in string_values if is_registry_string(s)]

                features["api_strings"] = api_strings
                features["path_strings"] = path_strings
                features["url_strings"] = url_strings
                features["registry_strings"] = registry_strings

                # Create categorized strings dictionary for CLI display
                features["categorized_strings"] = {}
                if api_strings:
                    features["categorized_strings"]["API"] = len(api_strings)
                if path_strings:
                    features["categorized_strings"]["Paths"] = len(path_strings)
                if url_strings:
                    features["categorized_strings"]["URLs"] = len(url_strings)
                if registry_strings:
                    features["categorized_strings"]["Registry"] = len(registry_strings)

                # Create string signature (hash of sorted unique strings)
                unique_sorted = sorted(set(string_values))
                features["string_signature"] = hashlib.md5(
                    "|".join(unique_sorted).encode(), usedforsecurity=False
                ).hexdigest()

        except Exception as e:
            logger.debug(f"Error extracting string features: {e}")

        return features

    def _extract_byte_features(self) -> dict[str, Any]:
        """Extract byte-level features for comparison"""
        features: dict[str, Any] = {}

        try:
            # Get entropy info
            entropy_info = cmd_helper(self.adapter, self.r2, "p=e 100")
            if entropy_info:
                features["entropy_pattern"] = entropy_info.strip()

            # Calculate rolling hash for similarity
            try:
                with open(self.filepath, "rb") as f:
                    data = f.read(8192)  # Read first 8KB
                    if data:
                        features["rolling_hash"] = calculate_rolling_hash(data)
            except Exception as exc:
                logger.debug(f"Failed to compute rolling hash: {exc}")

        except Exception as e:
            logger.debug(f"Error extracting byte features: {e}")

        return features

    def _extract_behavioral_features(self) -> dict[str, Any]:
        """Extract behavioral pattern features"""
        features: dict[str, Any] = {}

        try:
            # Look for common behavioral patterns in strings and imports
            strings = self.adapter.get_strings() if self.adapter else []
            imports = self.adapter.get_imports() if self.adapter else []

            if strings:
                string_values = [s.get("string", "") for s in strings if s.get("string")]
                features["crypto_indicators"] = len(
                    [s for s in string_values if has_crypto_indicators(s)]
                )
                features["network_indicators"] = len(
                    [s for s in string_values if has_network_indicators(s)]
                )
                features["persistence_indicators"] = len(
                    [s for s in string_values if has_persistence_indicators(s)]
                )

            if imports:
                import_names = [imp.get("name", "") for imp in imports if imp.get("name")]
                features["suspicious_apis"] = len(
                    [api for api in import_names if is_suspicious_api(api)]
                )
                features["crypto_apis"] = len([api for api in import_names if is_crypto_api(api)])
                features["network_apis"] = len([api for api in import_names if is_network_api(api)])

        except Exception as e:
            logger.debug(f"Error extracting behavioral features: {e}")

        return features

    def _generate_comparison_signatures(self, results: dict[str, Any]) -> dict[str, str]:
        """Generate signatures for quick comparison"""
        signatures = {}

        try:
            # Structural signature
            struct_features = results.get("structural_features", {})
            struct_data = build_struct_signature(struct_features)
            signatures["structural"] = hashlib.md5(
                struct_data.encode(), usedforsecurity=False
            ).hexdigest()

            # Function signature
            func_features = results.get("function_features", {})
            func_data = build_function_signature(func_features)
            signatures["function"] = hashlib.md5(
                func_data.encode(), usedforsecurity=False
            ).hexdigest()

            # String signature (already calculated)
            string_features = results.get("string_features", {})
            string_data = build_string_signature(string_features)
            signatures["string"] = hashlib.md5(
                string_data.encode(), usedforsecurity=False
            ).hexdigest()

            # Behavioral signature
            behav_features = results.get("behavioral_features", {})
            behav_data = build_behavioral_signature(behav_features)
            signatures["behavioral"] = hashlib.md5(
                behav_data.encode(), usedforsecurity=False
            ).hexdigest()

        except Exception as e:
            logger.debug(f"Error generating signatures: {e}")

        return signatures

    def _compare_structural(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare structural features between two binaries"""
        try:
            return compare_structural_features(
                a.get("structural_features", {}), b.get("structural_features", {})
            )

        except Exception as e:
            logger.debug(f"Error comparing structural features: {e}")
            return 0.0

    def _compare_functions(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare function-level features between two binaries"""
        try:
            return compare_function_features(
                a.get("function_features", {}), b.get("function_features", {})
            )

        except Exception as e:
            logger.debug(f"Error comparing function features: {e}")
            return 0.0

    def _compare_strings(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare string-based features between two binaries"""
        try:
            return compare_string_features(
                a.get("string_features", {}), b.get("string_features", {})
            )

        except Exception as e:
            logger.debug(f"Error comparing string features: {e}")
            return 0.0

    def _compare_bytes(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare byte-level features between two binaries"""
        try:
            return compare_byte_features(a.get("byte_features", {}), b.get("byte_features", {}))

        except Exception as e:
            logger.debug(f"Error comparing byte features: {e}")
            return 0.0

    def _compare_behavioral(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare behavioral features between two binaries"""
        try:
            return compare_behavioral_features(
                a.get("behavioral_features", {}), b.get("behavioral_features", {})
            )

        except Exception as e:
            logger.debug(f"Error comparing behavioral features: {e}")
            return 0.0
