"""Function-level analysis helpers."""

import logging
from pathlib import Path
from typing import Any

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..domain.constants import VERY_LARGE_FILE_THRESHOLD_MB
from ..domain.services.function_analysis import (
    build_function_stats,
    calculate_cyclomatic_complexity_from_blocks,
    classify_function_type,
    extract_mnemonics_from_ops,
    extract_mnemonics_from_text,
    machoc_hash_from_mnemonics,
)
from .function_analyzer_support import (
    analyze_function_coverage as _analyze_function_coverage_impl,
    calculate_std_dev as _calculate_std_dev_impl,
    extract_function_mnemonics as _extract_function_mnemonics_impl,
    generate_function_stats as _generate_function_stats_impl,
    generate_machoc_hashes as _generate_machoc_hashes_impl,
    generate_machoc_summary as _generate_machoc_summary_impl,
    get_file_size_mb as _get_file_size_mb_impl,
    get_function_similarity as _get_function_similarity_impl,
    process_single_function_hash as _process_single_function_hash_impl,
    should_run_full_analysis as _should_run_full_analysis_impl,
    try_basic_pdj_extraction as _try_basic_pdj_extraction_impl,
    try_pdfj_extraction as _try_pdfj_extraction_impl,
    try_pdj_extraction as _try_pdj_extraction_impl,
    try_pi_extraction as _try_pi_extraction_impl,
)

logger = logging.getLogger(__name__)


def _normalize_function_list(functions: Any) -> list[dict[str, Any]]:
    if not isinstance(functions, list):
        return []
    return [func for func in functions if isinstance(func, dict)]


class FunctionAnalyzer(CommandHelperMixin):
    """Analyzer for function-level analysis and hashing"""

    def __init__(
        self, adapter: Any, config: Any | None = None, filename: str | None = None
    ) -> None:
        self.adapter = adapter
        self.config = config
        self._file_size_mb = self._get_file_size_mb(filename)
        self.functions_cache: list[dict[str, Any]] | None = None

    def analyze_functions(self) -> dict[str, Any]:
        """
        Perform comprehensive function analysis

        Returns:
            Dict containing function analysis results including MACHOC hashes
        """
        try:
            logger.debug("Starting function analysis...")

            # Get all functions
            functions = self._get_functions()
            if not functions:
                logger.debug("No functions found for analysis")
                return {
                    "total_functions": 0,
                    "machoc_hashes": {},
                    "function_stats": {},
                    "error": "No functions detected",
                }

            logger.debug("Found %s functions for analysis", len(functions))

            # Generate MACHOC hashes
            machoc_hashes = self._generate_machoc_hashes(functions)

            # Generate function statistics
            function_stats = self._generate_function_stats(functions)

            return {
                "total_functions": len(functions),
                "machoc_hashes": machoc_hashes,
                "function_stats": function_stats,
                "functions_analyzed": len(machoc_hashes),
            }

        except Exception as e:
            logger.error(
                "Error in function analysis (cached=%s, size_mb=%s): %s",
                self.functions_cache is not None,
                self._file_size_mb,
                str(e),
            )
            return {
                "total_functions": 0,
                "machoc_hashes": {},
                "function_stats": {},
                "error": f"Function analysis failed: {str(e)}",
            }

    def _get_functions(self) -> list[dict[str, Any]]:
        """Get all functions from the binary"""
        try:
            if self.functions_cache is None:
                # Prefer existing analysis results before triggering heavy analysis.
                functions = _normalize_function_list(self._cmd_list("aflj"))
                if not functions:
                    if self._should_run_full_analysis():
                        self._cmd("aaa")
                    else:
                        self._cmd("aa")
                    functions = _normalize_function_list(self._cmd_list("aflj"))
                self.functions_cache = functions

            return self.functions_cache or []

        except Exception as e:
            logger.error("Error getting functions: %s", str(e))
            return []

    def _get_file_size_mb(self, filename: str | None) -> float | None:
        return _get_file_size_mb_impl(filename)

    def _should_run_full_analysis(self) -> bool:
        return _should_run_full_analysis_impl(self.config, self._file_size_mb)

    def _generate_machoc_hashes(self, functions: list[dict[str, Any]]) -> dict[str, str]:
        """
        Generate MACHOC hashes for all functions

        MACHOC hash is based on the sequence of instruction mnemonics,
        ignoring operands, addresses, and other specifics.

        Args:
            functions: List of function dictionaries from radare2

        Returns:
            Dict mapping function names to their MACHOC hashes
        """
        return _generate_machoc_hashes_impl(self, functions, logger)

    def _process_single_function_hash(
        self, func: dict[str, Any], index: int, total: int
    ) -> tuple[str, str] | None:
        """Process a single function to generate its MACHOC hash"""
        return _process_single_function_hash_impl(
            self,
            func,
            index,
            total,
            logger,
            machoc_hash_fn=machoc_hash_from_mnemonics,
        )

    def _extract_function_mnemonics(
        self, func_name: str, func_size: int, func_addr: int
    ) -> list[str]:
        """Extract mnemonics from function using multiple methods"""
        return _extract_function_mnemonics_impl(self, func_name, func_size, func_addr)

    def _try_pdfj_extraction(self, func_name: str, func_addr: int) -> list[str]:
        """Try extracting mnemonics using pdfj command"""
        return _try_pdfj_extraction_impl(self, func_name, func_addr, logger)

    def _try_pdj_extraction(self, func_name: str, func_size: int, func_addr: int) -> list[str]:
        """Try extracting mnemonics using pdj with size limit"""
        return _try_pdj_extraction_impl(self, func_name, func_size, func_addr, logger)

    def _try_basic_pdj_extraction(self, func_name: str, func_addr: int) -> list[str]:
        """Try extracting mnemonics using basic pdj"""
        return _try_basic_pdj_extraction_impl(self, func_name, func_addr, logger)

    def _try_pi_extraction(self, func_name: str, func_addr: int) -> list[str]:
        """Try extracting mnemonics using pi command"""
        return _try_pi_extraction_impl(self, func_name, func_addr, logger)

    def _extract_mnemonics_from_ops(self, ops: list[dict[str, Any]]) -> list[str]:
        """Extract mnemonics from operation list"""
        return extract_mnemonics_from_ops(ops)

    def _generate_function_stats(self, functions: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate statistics about functions"""
        return _generate_function_stats_impl(functions, logger)

    def get_function_similarity(self, machoc_hashes: dict[str, str]) -> dict[str, list[str]]:
        """
        Find functions with identical MACHOC hashes (potential duplicates or similar functions)

        Args:
            machoc_hashes: Dict of function names to MACHOC hashes

        Returns:
            Dict mapping MACHOC hashes to lists of function names that share that hash
        """
        return _get_function_similarity_impl(machoc_hashes, logger)

    def generate_machoc_summary(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        """Generate a summary of MACHOC analysis results"""
        return _generate_machoc_summary_impl(
            analysis_results,
            logger,
            similarity_fn=self.get_function_similarity,
        )

    def _calculate_cyclomatic_complexity(self, func: dict[str, Any]) -> int:
        """Calculate cyclomatic complexity for a function."""

        def _compute() -> int:
            func_addr = func.get("addr")
            if not func_addr:
                return 0
            cfg_info = (
                self.adapter.get_cfg(func_addr)
                if self.adapter is not None and hasattr(self.adapter, "get_cfg")
                else self._cmdj(f"agj @ {func_addr}", {})
            )
            if not cfg_info:
                return 0
            if isinstance(cfg_info, list):
                blocks = cfg_info
            elif isinstance(cfg_info, dict) and "blocks" in cfg_info:
                blocks = cfg_info.get("blocks", [])
            else:
                return 0
            return calculate_cyclomatic_complexity_from_blocks(blocks)

        return self._safe_call(
            _compute,
            default=0,
            error_msg="Error calculating cyclomatic complexity",
        )

    def _classify_function_type(self, func_name: str, func: dict[str, Any]) -> str:
        """Classify function type based on name and characteristics."""
        return self._safe_call(
            lambda: classify_function_type(func_name, func),
            default="unknown",
            error_msg=f"Error classifying function type for {func_name}",
        )

    def _calculate_std_dev(self, values: list[float]) -> float:
        """Calculate standard deviation"""
        return _calculate_std_dev_impl(values)

    def _analyze_function_coverage(self, functions: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze function coverage and detection quality"""
        return _analyze_function_coverage_impl(functions)
