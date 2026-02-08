"""Function-level analysis helpers."""

import logging
from pathlib import Path
from typing import Any

from ..core.constants import VERY_LARGE_FILE_THRESHOLD_MB
from ..utils.command_helpers import cmd as cmd_helper
from ..utils.command_helpers import cmd_list as cmd_list_helper
from ..utils.command_helpers import cmdj as cmdj_helper
from .function_domain import (
    extract_mnemonics_from_ops,
    extract_mnemonics_from_text,
    machoc_hash_from_mnemonics,
)

logger = logging.getLogger(__name__)


class FunctionAnalyzer:
    """Analyzer for function-level analysis and hashing"""

    def __init__(
        self, adapter: Any, config: Any | None = None, filename: str | None = None
    ) -> None:
        self.adapter = adapter
        self.r2 = adapter
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

            logger.debug(f"Found {len(functions)} functions for analysis")

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
            logger.error(f"Error in function analysis: {str(e)}")
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
                functions = self._cmd_list("aflj")
                if not functions:
                    if self._should_run_full_analysis():
                        self._cmd("aaa")
                    else:
                        self._cmd("aa")
                    functions = self._cmd_list("aflj")
                self.functions_cache = functions

            return self.functions_cache or []

        except Exception as e:
            logger.error(f"Error getting functions: {str(e)}")
            return []

    def _get_file_size_mb(self, filename: str | None) -> float | None:
        if not filename:
            return None
        try:
            return Path(filename).stat().st_size / (1024 * 1024)
        except OSError:
            return None

    def _should_run_full_analysis(self) -> bool:
        try:
            if self.config and getattr(self.config, "typed_config", None):
                if self.config.typed_config.analysis.deep_analysis:
                    return True
        except Exception:
            pass
        if self._file_size_mb is not None:
            return self._file_size_mb <= VERY_LARGE_FILE_THRESHOLD_MB
        return True

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
        machoc_hashes: dict[str, str] = {}
        failed_functions = 0

        logger.debug(f"Starting MACHOC hash generation for {len(functions)} functions")

        for i, func in enumerate(functions):
            try:
                result = self._process_single_function_hash(func, i, len(functions))
                if result:
                    func_name, machoc_hash = result
                    machoc_hashes[func_name] = machoc_hash
                else:
                    failed_functions += 1

            except Exception as e:
                logger.error(
                    f"Error generating MACHOC hash for function {func.get('name', 'unknown')}: {str(e)}"
                )
                failed_functions += 1
                continue

        success_count = len(machoc_hashes)
        logger.debug(
            f"Generated MACHOC hashes for {success_count}/{len(functions)} functions ({failed_functions} failed)"
        )

        return machoc_hashes

    def _process_single_function_hash(
        self, func: dict[str, Any], index: int, total: int
    ) -> tuple[str, str] | None:
        """Process a single function to generate its MACHOC hash"""
        func_name = func.get("name", f"func_{func.get('addr', 'unknown')}")
        func_offset = func.get("addr")
        func_size = func.get("size", 0)

        if func_offset is None:
            logger.warning(f"No address found for function {func_name}")
            return None

        logger.debug(
            f"Processing function {index + 1}/{total}: {func_name} at 0x{func_offset:x} (size: {func_size})"
        )

        # Extract mnemonics using multiple methods
        mnemonics = self._extract_function_mnemonics(func_name, func_size, func_offset)

        if not mnemonics:
            logger.warning(f"No mnemonics found for function {func_name} (size: {func_size})")
            return None

        # Generate MACHOC hash
        machoc_hash = machoc_hash_from_mnemonics(mnemonics)
        if not machoc_hash:
            return None

        logger.debug(
            f"Generated MACHOC hash for {func_name}: {machoc_hash[:16]}... ({len(mnemonics)} mnemonics)"
        )

        return func_name, machoc_hash

    def _extract_function_mnemonics(
        self, func_name: str, func_size: int, func_addr: int
    ) -> list[str]:
        """Extract mnemonics from function using multiple methods"""
        # Try method 1: pdfj
        mnemonics = self._try_pdfj_extraction(func_name, func_addr)
        if mnemonics:
            return mnemonics

        # Try method 2: pdj with size limit
        if func_size > 0:
            mnemonics = self._try_pdj_extraction(func_name, func_size, func_addr)
            if mnemonics:
                return mnemonics

        # Try method 3: basic pdj
        mnemonics = self._try_basic_pdj_extraction(func_name, func_addr)
        if mnemonics:
            return mnemonics

        # Try method 4: text-based pi command
        return self._try_pi_extraction(func_name, func_addr)

    def _try_pdfj_extraction(self, func_name: str, func_addr: int) -> list[str]:
        """Try extracting mnemonics using pdfj command"""
        try:
            disasm = (
                self.adapter.get_disasm(address=func_addr)
                if self.adapter is not None and hasattr(self.adapter, "get_disasm")
                else self._cmdj(f"pdfj @ {func_addr}", {})
            )
            if isinstance(disasm, dict) and "ops" in disasm:
                logger.debug(
                    f"pdfj succeeded for {func_name}, got {len(disasm['ops'])} instructions"
                )
                return self._extract_mnemonics_from_ops(disasm["ops"])
        except Exception as e:
            logger.debug(f"pdfj failed for {func_name}: {str(e)}")
        return []

    def _try_pdj_extraction(self, func_name: str, func_size: int, func_addr: int) -> list[str]:
        """Try extracting mnemonics using pdj with size limit"""
        try:
            max_instructions = min(func_size // 4, 1000)
            disasm_list = (
                self.adapter.get_disasm(address=func_addr, size=max_instructions)
                if self.adapter is not None and hasattr(self.adapter, "get_disasm")
                else self._cmd_list(f"pdj {max_instructions} @ {func_addr}")
            )
            if isinstance(disasm_list, list):
                logger.debug(f"pdj succeeded for {func_name}, got {len(disasm_list)} instructions")
                return self._extract_mnemonics_from_ops(disasm_list)
        except Exception as e:
            logger.debug(f"pdj failed for {func_name}: {str(e)}")
        return []

    def _try_basic_pdj_extraction(self, func_name: str, func_addr: int) -> list[str]:
        """Try extracting mnemonics using basic pdj"""
        try:
            disasm_list = (
                self.adapter.get_disasm(address=func_addr, size=50)
                if self.adapter is not None and hasattr(self.adapter, "get_disasm")
                else self._cmd_list(f"pdj 50 @ {func_addr}")
            )
            if isinstance(disasm_list, list):
                logger.debug(
                    f"Basic pdj succeeded for {func_name}, got {len(disasm_list)} instructions"
                )
                return self._extract_mnemonics_from_ops(disasm_list)
        except Exception as e:
            logger.debug(f"Basic pdj failed for {func_name}: {str(e)}")
        return []

    def _try_pi_extraction(self, func_name: str, func_addr: int) -> list[str]:
        """Try extracting mnemonics using pi command"""
        try:
            instructions_text = self._cmd(f"pi 100 @ {func_addr}")
            if instructions_text and instructions_text.strip():
                lines = instructions_text.strip().split("\n")
                logger.debug(f"pi succeeded for {func_name}, got {len(lines)} instruction lines")
                return extract_mnemonics_from_text(instructions_text)
        except Exception as e:
            logger.debug(f"pi failed for {func_name}: {str(e)}")
        return []

    def _extract_mnemonics_from_ops(self, ops: list[dict[str, Any]]) -> list[str]:
        """Extract mnemonics from operation list"""
        return extract_mnemonics_from_ops(ops)

    def _generate_function_stats(self, functions: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate statistics about functions"""
        try:
            if not functions:
                return {}

            # Basic statistics
            total_functions = len(functions)
            sizes = [func.get("size", 0) for func in functions if func.get("size")]

            stats: dict[str, Any] = {
                "total_functions": total_functions,
                "functions_with_size": len(sizes),
            }

            if sizes:
                stats.update(
                    {
                        "avg_function_size": sum(sizes) / len(sizes),
                        "min_function_size": min(sizes),
                        "max_function_size": max(sizes),
                        "total_code_size": sum(sizes),
                    }
                )

            # Function types/categories
            function_types: dict[str, int] = {}
            for func in functions:
                func_type = func.get("type", "unknown")
                function_types[func_type] = function_types.get(func_type, 0) + 1

            stats["function_types"] = function_types

            # Top functions by size (if available)
            if sizes:
                functions_with_sizes: list[tuple[str, int]] = [
                    (
                        str(f.get("name", f"func_{f.get('offset', '?')}")),
                        int(f.get("size", 0)),
                    )
                    for f in functions
                    if f.get("size")
                ]
                functions_with_sizes.sort(key=lambda x: x[1], reverse=True)
                stats["largest_functions"] = functions_with_sizes[:10]  # Top 10

            return stats

        except Exception as e:
            logger.error(f"Error generating function stats: {str(e)}")
            return {"error": f"Stats generation failed: {str(e)}"}

    def get_function_similarity(self, machoc_hashes: dict[str, str]) -> dict[str, list[str]]:
        """
        Find functions with identical MACHOC hashes (potential duplicates or similar functions)

        Args:
            machoc_hashes: Dict of function names to MACHOC hashes

        Returns:
            Dict mapping MACHOC hashes to lists of function names that share that hash
        """
        try:
            hash_to_functions: dict[str, list[str]] = {}

            for func_name, machoc_hash in machoc_hashes.items():
                if machoc_hash not in hash_to_functions:
                    hash_to_functions[machoc_hash] = []
                hash_to_functions[machoc_hash].append(func_name)

            # Only return hashes that have multiple functions (similarities)
            similarities = {h: funcs for h, funcs in hash_to_functions.items() if len(funcs) > 1}

            if similarities:
                logger.debug(
                    f"Found {len(similarities)} MACHOC hash collisions indicating similar functions"
                )

            return similarities

        except Exception as e:
            logger.error(f"Error calculating function similarity: {str(e)}")
            return {}

    def generate_machoc_summary(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        """Generate a summary of MACHOC analysis results"""
        try:
            machoc_hashes = analysis_results.get("machoc_hashes", {})

            if not machoc_hashes:
                return {"error": "No MACHOC hashes available"}

            # Find similarities
            similarities = self.get_function_similarity(machoc_hashes)

            # Generate summary
            summary: dict[str, Any] = {
                "total_functions_hashed": len(machoc_hashes),
                "unique_machoc_hashes": len(set(machoc_hashes.values())),
                "duplicate_function_groups": len(similarities),
                "total_duplicate_functions": sum(len(funcs) for funcs in similarities.values()),
            }

            # Add similarity details if found
            if similarities:
                summary["similarities"] = similarities

                # Most common patterns
                pattern_counts: list[tuple[int, str]] = [
                    (len(funcs), hash_val[:16]) for hash_val, funcs in similarities.items()
                ]
                pattern_counts.sort(reverse=True)
                summary["most_common_patterns"] = pattern_counts[:5]  # Top 5

            return summary

        except Exception as e:
            logger.error(f"Error generating MACHOC summary: {str(e)}")
            return {"error": f"Summary generation failed: {str(e)}"}

    def _calculate_cyclomatic_complexity(self, func: dict[str, Any]) -> int:
        """Calculate cyclomatic complexity for a function"""
        try:
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

            edges = 0
            nodes = len(blocks)

            for block in blocks:
                if isinstance(block, dict) and "jump" in block:
                    edges += 1
                if isinstance(block, dict) and "fail" in block:
                    edges += 1

            # Cyclomatic complexity = E - N + 2P (where P=1 for single component)
            # Simplified: edges - nodes + 2
            complexity = max(edges - nodes + 2, 1)
            return complexity

        except Exception as e:
            logger.debug(f"Error calculating cyclomatic complexity: {e}")
            return 0

    def _cmd(self, command: str) -> str:
        return cmd_helper(self.adapter, self.r2, command)

    def _cmdj(self, command: str, default: Any) -> Any:
        return cmdj_helper(self.adapter, self.r2, command, default)

    def _cmd_list(self, command: str) -> list[Any]:
        return cmd_list_helper(self.adapter, self.r2, command)

    def _classify_function_type(self, func_name: str, func: dict[str, Any]) -> str:
        """Classify function type based on name and characteristics"""
        try:
            name = func_name.lower()

            # Library functions
            if any(prefix in name for prefix in ["lib", "msvcrt", "kernel32", "ntdll", "user32"]):
                return "library"

            # Thunk functions
            if "thunk" in name or name.startswith("j_") or func.get("size", 0) < 10:
                return "thunk"

            # User functions (main, custom names)
            if any(keyword in name for keyword in ["main", "sub_", "fcn.", "func_"]):
                return "user"

            return "unknown"

        except Exception:
            return "unknown"

    def _calculate_std_dev(self, values: list[float]) -> float:
        """Calculate standard deviation"""
        try:
            if len(values) < 2:
                return 0.0

            mean = sum(values) / len(values)
            variance: float = sum((x - mean) ** 2 for x in values) / len(values)
            return float(variance**0.5)

        except Exception:
            return 0.0

    def _analyze_function_coverage(self, functions: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze function coverage and detection quality"""
        try:
            coverage: dict[str, Any] = {
                "total_functions": len(functions),
                "functions_with_size": 0,
                "functions_with_blocks": 0,
                "total_code_coverage": 0,
                "avg_function_size": 0,
            }

            sizes = []
            for func in functions:
                size = func.get("size", 0)
                if size > 0:
                    coverage["functions_with_size"] += 1
                    sizes.append(size)

                if func.get("nbbs", 0) > 0:
                    coverage["functions_with_blocks"] += 1

            if sizes:
                coverage["total_code_coverage"] = sum(sizes)
                coverage["avg_function_size"] = sum(sizes) / len(sizes)

            # Calculate coverage percentage
            if coverage["total_functions"] > 0:
                coverage["size_coverage_percent"] = (
                    coverage["functions_with_size"] / coverage["total_functions"]
                ) * 100
                coverage["block_coverage_percent"] = (
                    coverage["functions_with_blocks"] / coverage["total_functions"]
                ) * 100

            return coverage

        except Exception as e:
            logger.debug(f"Error analyzing function coverage: {e}")
            return {}
