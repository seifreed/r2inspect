#!/usr/bin/env python3
"""Binary diffing and comparison analyzer."""

import hashlib
from pathlib import Path
from typing import Any

from ..adapters.file_system import default_file_system
from ..infrastructure.command_helpers import cmd as cmd_helper
from ..infrastructure.logging import get_logger
from .bindiff_analysis_support import (
    build_analysis,
    compare_with_results,
    extract_behavioral_features,
    extract_byte_features,
    extract_function_features,
    extract_string_features,
    extract_structural_features,
    generate_signatures,
)
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
        self.filepath = filepath
        self.filename = Path(filepath).name

    def analyze(self) -> dict[str, Any]:
        """Perform binary diffing analysis"""
        try:
            return build_analysis(self, logger)
        except Exception as e:
            logger.error("Error in binary diff analysis for %s: %s", self.filename, e)
            return {
                "filename": self.filename,
                "filepath": self.filepath,
                "error": str(e),
                "comparison_ready": False,
            }

    def compare_with(self, other_results: dict[str, Any]) -> dict[str, Any]:
        """Compare this binary with another binary's analysis results"""
        try:
            return compare_with_results(self, other_results)
        except Exception as e:
            logger.error("Error comparing binaries: %s", e)
            return {"error": str(e), "similarity_score": 0.0}

    def _extract_structural_features(self) -> dict[str, Any]:
        """Extract structural features for comparison"""
        return extract_structural_features(self, logger)

    def _extract_function_features(self) -> dict[str, Any]:
        """Extract function-level features for comparison"""
        return extract_function_features(self, logger)

    def _extract_string_features(self) -> dict[str, Any]:
        """Extract string-based features for comparison"""
        return extract_string_features(self, logger)

    def _extract_byte_features(self) -> dict[str, Any]:
        """Extract byte-level features for comparison"""
        return extract_byte_features(self, logger)

    def _extract_behavioral_features(self) -> dict[str, Any]:
        """Extract behavioral pattern features"""
        return extract_behavioral_features(self, logger)

    def _generate_comparison_signatures(self, results: dict[str, Any]) -> dict[str, str]:
        """Generate signatures for quick comparison"""
        return generate_signatures(results, self, logger)

    def _run_analysis_command(self) -> Any:
        return cmd_helper(self.adapter, self.adapter, "aaa")

    def _get_entropy_pattern(self) -> str:
        if self.adapter and hasattr(self.adapter, "get_entropy_pattern"):
            return str(self.adapter.get_entropy_pattern())
        return str(cmd_helper(self.adapter, self.adapter, "p=e 100"))

    def _read_file_head(self) -> bytes:
        return default_file_system.read_bytes(self.filepath, size=8192)

    @staticmethod
    def _calculate_rolling_hash(data: bytes) -> list[int]:
        return calculate_rolling_hash(data)

    @staticmethod
    def _calculate_cyclomatic_complexity(cfg_data: dict[str, Any]) -> int:
        return calculate_cyclomatic_complexity(cfg_data)

    @staticmethod
    def _build_struct_signature(struct_features: dict[str, Any]) -> str:
        return build_struct_signature(struct_features)

    @staticmethod
    def _build_function_signature(func_features: dict[str, Any]) -> str:
        return build_function_signature(func_features)

    @staticmethod
    def _build_string_signature(string_features: dict[str, Any]) -> str:
        return build_string_signature(string_features)

    @staticmethod
    def _build_behavioral_signature(behav_features: dict[str, Any]) -> str:
        return build_behavioral_signature(behav_features)

    @staticmethod
    def _calculate_overall_similarity(comparison: dict[str, Any]) -> float:
        return calculate_overall_similarity(
            comparison["structural_similarity"],
            comparison["function_similarity"],
            comparison["string_similarity"],
            comparison["byte_similarity"],
            comparison["behavioral_similarity"],
        )

    @staticmethod
    def _categorize_similarity(score: float) -> str:
        return categorize_similarity(score)

    @staticmethod
    def _has_crypto_indicators(value: str) -> bool:
        return has_crypto_indicators(value)

    @staticmethod
    def _has_network_indicators(value: str) -> bool:
        return has_network_indicators(value)

    @staticmethod
    def _has_persistence_indicators(value: str) -> bool:
        return has_persistence_indicators(value)

    @staticmethod
    def _is_suspicious_api(value: str) -> bool:
        return is_suspicious_api(value)

    @staticmethod
    def _is_crypto_api(value: str) -> bool:
        return is_crypto_api(value)

    @staticmethod
    def _is_network_api(value: str) -> bool:
        return is_network_api(value)

    @staticmethod
    def _is_api_string(value: str) -> bool:
        return is_api_string(value)

    @staticmethod
    def _is_path_string(value: str) -> bool:
        return is_path_string(value)

    @staticmethod
    def _is_url_string(value: str) -> bool:
        return is_url_string(value)

    @staticmethod
    def _is_registry_string(value: str) -> bool:
        return is_registry_string(value)

    def _compare_structural(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare structural features between two binaries"""
        try:
            return compare_structural_features(
                a.get("structural_features", {}), b.get("structural_features", {})
            )

        except Exception as e:
            logger.debug("Error comparing structural features: %s", e)
            return 0.0

    def _compare_functions(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare function-level features between two binaries"""
        try:
            return compare_function_features(
                a.get("function_features", {}), b.get("function_features", {})
            )

        except Exception as e:
            logger.debug("Error comparing function features: %s", e)
            return 0.0

    def _compare_strings(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare string-based features between two binaries"""
        try:
            return compare_string_features(
                a.get("string_features", {}), b.get("string_features", {})
            )

        except Exception as e:
            logger.debug("Error comparing string features: %s", e)
            return 0.0

    def _compare_bytes(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare byte-level features between two binaries"""
        try:
            return compare_byte_features(a.get("byte_features", {}), b.get("byte_features", {}))

        except Exception as e:
            logger.debug("Error comparing byte features: %s", e)
            return 0.0

    def _compare_behavioral(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Compare behavioral features between two binaries"""
        try:
            return compare_behavioral_features(
                a.get("behavioral_features", {}), b.get("behavioral_features", {})
            )

        except Exception as e:
            logger.debug("Error comparing behavioral features: %s", e)
            return 0.0
