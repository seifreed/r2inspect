#!/usr/bin/env python3
"""SimHash-based binary similarity analysis."""

from typing import Any, cast

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..abstractions.hashing_strategy import HashingStrategy
from ..abstractions.result_builder import init_result, mark_unavailable
from ..adapters.analyzer_runner import run_analyzer_on_file
from ..domain.services.simhash import (
    build_similarity_groups,
    classify_opcode_type,
    extract_opcodes_from_ops,
    extract_printable_strings,
    get_length_category,
    interpret_similarity_distance,
)
from ..infrastructure.logging import get_logger
from .simhash_compare_support import compare_hashes as _compare_hashes_impl
from .simhash_data_access_support import (
    extract_ops_from_disasm as _extract_ops_from_disasm_impl,
    get_functions as _get_functions_impl2,
    get_sections as _get_sections_impl2,
    get_strings_data as _get_strings_data_impl2,
)
from .simhash_support import (
    add_string_feature_set as _add_string_feature_set_impl,
    append_data_section_string as _append_data_section_string_impl,
    calculate_similarity as _calculate_similarity_impl,
    collect_string_features as _collect_string_features_impl,
    find_similar_functions as _find_similar_functions_impl,
    is_useful_string as _is_useful_string_impl,
)
from .simhash_features import (
    extract_function_features as _extract_function_features_impl,
    extract_function_opcodes as _extract_function_opcodes_impl,
    extract_opcodes_features as _extract_opcodes_features_impl,
    extract_string_features as _extract_string_features_impl,
)
from .string_classification import classify_string_type

logger = get_logger(__name__)

NO_FEATURES_ERROR = "No features could be extracted for SimHash"
# Try to import simhash, fall back to error handling
try:
    from simhash import Simhash

    SIMHASH_AVAILABLE = True
except ImportError:  # pragma: no cover
    logger.warning("simhash not available. Install with: pip install simhash")
    SIMHASH_AVAILABLE = False
    Simhash = None


class SimHashAnalyzer(CommandHelperMixin, HashingStrategy):
    """SimHash-based binary similarity analysis"""

    def __init__(self, adapter: Any, filepath: str) -> None:
        """Initialize SimHash analyzer."""
        # Initialize parent with filepath
        super().__init__(filepath=filepath, r2_instance=adapter)
        self.adapter: Any = adapter
        self.min_string_length = 4  # Minimum string length to consider
        self.max_instructions_per_function = 500  # Limit instructions per function

    def _check_library_availability(self) -> tuple[bool, str | None]:
        """Check if the simhash library is available."""
        if SimHashAnalyzer.is_available():
            return True, None
        return False, "simhash library not available. Install with: pip install simhash"

    def _calculate_hash(self) -> tuple[str | None, str | None, str | None]:
        """Calculate combined SimHash from strings and opcodes."""
        try:
            # Extract features
            strings_features = self._extract_string_features()
            opcodes_features = self._extract_opcodes_features()

            if not strings_features and not opcodes_features:
                return None, None, NO_FEATURES_ERROR

            # Combined SimHash (strings + opcodes)
            combined_features = strings_features + opcodes_features
            if combined_features:
                combined_simhash = Simhash(combined_features)
                hash_hex = hex(combined_simhash.value)
                logger.debug("SimHash calculated: %s", hash_hex)
                return hash_hex, "feature_extraction", None

            return None, None, "Failed to calculate SimHash from features"  # pragma: no cover

        except Exception as e:
            logger.error("Error calculating SimHash: %s", e)
            return None, None, f"SimHash calculation failed: {str(e)}"

    def _get_hash_type(self) -> str:
        """Return the hash type identifier."""
        return "simhash"

    def analyze_detailed(self) -> dict[str, Any]:
        """Run detailed SimHash analysis with separate feature sets."""
        from .simhash_detailed import run_detailed_simhash_analysis

        return run_detailed_simhash_analysis(
            filepath=self.filepath,
            simhash_available=SIMHASH_AVAILABLE,
            no_features_error=NO_FEATURES_ERROR,
            extract_string_features=self._extract_string_features,
            extract_opcodes_features=self._extract_opcodes_features,
            extract_function_features=self._extract_function_features,
            find_similar_functions=self._find_similar_functions,
            log_debug=logger.debug,
            log_error=logger.error,
        )

    def _extract_string_features(self) -> list[str]:
        """Extract string features from the binary."""
        return _extract_string_features_impl(self, logger=logger)

    def _collect_string_features(self, strings_data: list[Any], string_features: list[str]) -> None:
        _collect_string_features_impl(self, strings_data, string_features)

    def _add_string_feature_set(self, string_features: list[str], string_value: str) -> None:
        _add_string_feature_set_impl(self, string_features, string_value)

    def _extract_opcodes_features(self) -> list[str]:
        """Extract opcode/instruction features from the binary."""
        return _extract_opcodes_features_impl(self, logger=logger)

    def _extract_function_features(self) -> dict[str, dict[str, Any]]:
        """Extract per-function SimHash features."""
        return _extract_function_features_impl(self, Simhash, logger=logger)

    def _extract_function_opcodes(self, func_addr: int, func_name: str) -> list[str]:
        """Extract opcodes from a specific function."""
        return _extract_function_opcodes_impl(self, func_addr, func_name, logger=logger)

    def _extract_opcodes_from_ops(self, ops: list[Any]) -> list[str]:
        return extract_opcodes_from_ops(ops, max_instructions=self.max_instructions_per_function)

    def _get_prev_mnemonic(self, ops: list[Any], index: int) -> str | None:
        if index <= 0 or index >= len(ops):
            return None
        prev_op = ops[index - 1]
        if isinstance(prev_op, dict) and "mnemonic" in prev_op:
            return str(prev_op["mnemonic"]).strip().lower()
        return None

    def _extract_data_section_strings(self) -> list[str]:
        """Extract strings from data sections."""
        data_strings: list[str] = []

        try:
            sections = self._get_sections()
            if isinstance(sections, list):
                for section in sections:
                    self._append_data_section_string(section, data_strings)

        except Exception as e:
            logger.debug("Error extracting data section strings: %s", e)

        return data_strings

    def _append_data_section_string(self, section: Any, data_strings: list[str]) -> None:
        _append_data_section_string_impl(self, section, data_strings)

    def _is_useful_string(self, string_value: str) -> bool:
        return _is_useful_string_impl(string_value)

    def _get_strings_data(self) -> list[Any]:
        return _get_strings_data_impl2(self)

    def _get_functions(self) -> list[dict[str, Any]]:
        return _get_functions_impl2(self)

    def _get_sections(self) -> list[dict[str, Any]]:
        return _get_sections_impl2(self)

    def _extract_ops_from_disasm(self, disasm: Any) -> list[Any]:
        return _extract_ops_from_disasm_impl(disasm)

    def _extract_printable_strings(self, data: bytes) -> list[str]:
        return extract_printable_strings(data, min_length=self.min_string_length)

    def _get_length_category(self, length: int) -> str:
        """Categorize string length."""
        return get_length_category(length)

    def _classify_string_type(self, string_value: str) -> str | None:
        """Classify string type for feature extraction."""
        return classify_string_type(string_value)

    def _classify_opcode_type(self, mnemonic: str) -> str | None:
        """Classify opcode type for feature extraction."""
        return classify_opcode_type(mnemonic)

    def _find_similar_functions(
        self, function_features: dict[str, dict[str, Any]], max_distance: int = 10
    ) -> list[dict[str, Any]]:
        """Find groups of similar functions based on SimHash distance."""
        try:
            return _find_similar_functions_impl(
                SIMHASH_AVAILABLE,
                Simhash,
                function_features,
                max_distance=max_distance,
                build_similarity_groups=build_similarity_groups,
            )

        except Exception as e:
            logger.error("Error finding similar functions: %s", e)
            return []

    def calculate_similarity(
        self, other_simhash_value: int, hash_type: str = "combined"
    ) -> dict[str, Any]:
        """Calculate similarity between this binary and another SimHash value."""
        try:
            return _calculate_similarity_impl(
                self,
                SIMHASH_AVAILABLE,
                Simhash,
                other_simhash_value,
                hash_type,
                interpret_similarity_distance,
            )

        except Exception as e:
            logger.error("Error calculating similarity: %s", e)
            return {"error": str(e)}

    @staticmethod
    def compare_hashes(hash1: str | int, hash2: str | int) -> int | None:
        """Compare two SimHash values and return the Hamming distance."""
        return _compare_hashes_impl(
            simhash_available=SIMHASH_AVAILABLE,
            simhash_class=Simhash,
            hash1=hash1,
            hash2=hash2,
            logger=logger,
        )

    @staticmethod
    def is_available() -> bool:
        """Return True when simhash can be imported."""
        return SIMHASH_AVAILABLE

    @staticmethod
    def calculate_simhash_from_file(filepath: str) -> dict[str, Any] | None:
        """Calculate SimHash directly from a file path."""
        result = run_analyzer_on_file(SimHashAnalyzer, filepath)
        if result is None:
            logger.error("Error calculating SimHash from file")
        return result
