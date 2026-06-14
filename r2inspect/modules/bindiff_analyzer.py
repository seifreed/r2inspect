#!/usr/bin/env python3
"""Binary diffing and comparison analyzer."""

from pathlib import Path
from typing import Any

from ..domain.formats.bindiff import (
    calculate_overall_similarity,
    categorize_similarity,
    compare_behavioral_features,
    compare_byte_features,
    compare_function_features,
    compare_string_features,
    compare_structural_features,
)
from ..infrastructure.logging import get_logger
from ..interfaces.binary_analyzer import BinaryAnalyzerInterface
from .bindiff_feature_extraction import BinDiffFeatureExtractor

logger = get_logger(__name__)


class BinDiffAnalyzer:
    """Binary diffing and comparison analyzer."""

    def __init__(self, adapter: BinaryAnalyzerInterface | None, filepath: str) -> None:
        self.adapter = adapter
        self.filepath = filepath
        self.filename = Path(filepath).name
        self._extractor = BinDiffFeatureExtractor(adapter, filepath)

    def analyze(self) -> dict[str, Any]:
        """Perform binary diffing analysis."""
        try:
            logger.debug("Starting binary diff analysis for %s", self.filename)
            results: dict[str, Any] = {
                "filename": self.filename,
                "filepath": self.filepath,
                "structural_features": self._extract_structural_features(),
                "function_features": self._extract_function_features(),
                "string_features": self._extract_string_features(),
                "byte_features": self._extract_byte_features(),
                "behavioral_features": self._extract_behavioral_features(),
                "comparison_ready": True,
            }
            results["signatures"] = self._generate_comparison_signatures(results)
            logger.debug("Binary diff analysis completed for %s", self.filename)
            return results
        except Exception as e:
            logger.error("Error in binary diff analysis for %s: %s", self.filename, e)
            return {
                "filename": self.filename,
                "filepath": self.filepath,
                "error": str(e),
                "comparison_ready": False,
            }

    def compare_with(self, other_results: dict[str, Any]) -> dict[str, Any]:
        """Compare this binary with another binary's analysis results."""
        try:
            our_results = self.analyze()
            if not our_results.get("comparison_ready") or not other_results.get("comparison_ready"):
                return {
                    "error": "One or both binaries are not ready for comparison",
                    "similarity_score": 0.0,
                }
            comparison: dict[str, Any] = {
                "binary_a": our_results["filename"],
                "binary_b": other_results["filename"],
                "structural_similarity": self._compare_structural(our_results, other_results),
                "function_similarity": self._compare_functions(our_results, other_results),
                "string_similarity": self._compare_strings(our_results, other_results),
                "byte_similarity": self._compare_bytes(our_results, other_results),
                "behavioral_similarity": self._compare_behavioral(our_results, other_results),
            }
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
            logger.error("Error comparing binaries: %s", e)
            return {"error": str(e), "similarity_score": 0.0}

    def _extract_structural_features(self) -> dict[str, Any]:
        return self._extractor.extract_structural()

    def _extract_function_features(self) -> dict[str, Any]:
        return self._extractor.extract_functions()

    def _extract_string_features(self) -> dict[str, Any]:
        return self._extractor.extract_strings()

    def _extract_byte_features(self) -> dict[str, Any]:
        return self._extractor.extract_bytes()

    def _extract_behavioral_features(self) -> dict[str, Any]:
        return self._extractor.extract_behavioral()

    def _generate_comparison_signatures(self, results: dict[str, Any]) -> dict[str, str]:
        return self._extractor.generate_signatures(results)

    def _compare_structural(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        try:
            return compare_structural_features(
                a.get("structural_features", {}), b.get("structural_features", {})
            )
        except Exception as e:
            logger.debug("Error comparing structural features: %s", e)
            return 0.0

    def _compare_functions(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        try:
            return compare_function_features(
                a.get("function_features", {}), b.get("function_features", {})
            )
        except Exception as e:
            logger.debug("Error comparing function features: %s", e)
            return 0.0

    def _compare_strings(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        try:
            return compare_string_features(
                a.get("string_features", {}), b.get("string_features", {})
            )
        except Exception as e:
            logger.debug("Error comparing string features: %s", e)
            return 0.0

    def _compare_bytes(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        try:
            return compare_byte_features(a.get("byte_features", {}), b.get("byte_features", {}))
        except Exception as e:
            logger.debug("Error comparing byte features: %s", e)
            return 0.0

    def _compare_behavioral(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        try:
            return compare_behavioral_features(
                a.get("behavioral_features", {}), b.get("behavioral_features", {})
            )
        except Exception as e:
            logger.debug("Error comparing behavioral features: %s", e)
            return 0.0
