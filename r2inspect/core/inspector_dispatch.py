#!/usr/bin/env python3
"""Query, analysis, and dispatch mixins for the public inspector facade.

This module consolidates all inspector mixin behaviour that deals with
running individual analyzers / pipeline stages and exposing convenience
query methods to callers.
"""

from __future__ import annotations

from typing import Any, cast

from ..interfaces import BinaryAnalyzerInterface, ConfigLike
from .analyzer_factory import create_analyzer, run_analysis_method
from ..error_handling.classifier import ErrorCategory, ErrorSeverity, error_handler
from ..infrastructure.hashing import calculate_hashes
from ..infrastructure.logging import get_logger
from ..infrastructure.magic_detector import detect_file_type
from ..pipeline.stages import FileInfoStage, FormatDetectionStage

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Base dispatch layer (was InspectorAnalyzerDispatchMixin)
# ---------------------------------------------------------------------------


class InspectorDispatchMixin:
    """Analyzer dispatch, query, analysis and stage helpers for R2Inspector."""

    adapter: BinaryAnalyzerInterface
    config: ConfigLike
    filename: str
    registry: Any
    _result_aggregator: Any

    # -- static normalization helpers ----------------------------------------

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _as_bool_dict(value: Any) -> dict[str, bool]:
        if isinstance(value, dict):
            return {str(key): bool(val) for key, val in value.items()}
        return {}

    @staticmethod
    def _as_str(value: Any, default: str = "") -> str:
        return value if isinstance(value, str) else default

    # -- core executor -------------------------------------------------------

    def _execute_analyzer(
        self,
        analyzer_name: str,
        method_name: str = "analyze",
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        analyzer_class = self.registry.get_analyzer_class(analyzer_name)
        if not analyzer_class:
            logger.debug("Analyzer '%s' not found in registry", analyzer_name)
            return {}

        try:
            analyzer = create_analyzer(
                analyzer_class,
                adapter=self.adapter,
                config=self.config,
                filename=self.filename,
            )
            if method_name != "analyze":
                method = getattr(analyzer, method_name, None)
                if not method:
                    logger.warning(
                        "Method '%s' not found on analyzer '%s'",
                        method_name,
                        analyzer_name,
                    )
                    return {}
                return method(*args, **kwargs)
            if args or kwargs:
                return analyzer.analyze(*args, **kwargs)
            return run_analysis_method(analyzer, ("analyze",))
        except Exception as exc:
            logger.error("Error executing %s.%s(): %s", analyzer_name, method_name, exc)
            return {}

    def _execute_list(
        self,
        analyzer_name: str,
        method_name: str = "analyze",
        *args: Any,
        **kwargs: Any,
    ) -> list[Any]:
        result = self._execute_analyzer(analyzer_name, method_name, *args, **kwargs)
        return result if isinstance(result, list) else []

    def _execute_dict(
        self,
        analyzer_name: str,
        method_name: str = "analyze",
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return self._as_dict(self._execute_analyzer(analyzer_name, method_name, *args, **kwargs))

    # -- analysis / similarity helpers (was InspectorAnalysisMixin) ----------

    def generate_indicators(self, analysis_results: dict[str, Any]) -> list[dict[str, Any]]:
        result = self._result_aggregator.generate_indicators(analysis_results)
        return result if isinstance(result, list) else []

    def analyze_functions(self) -> dict[str, Any]:
        return self._execute_dict("function_analyzer", "analyze_functions")

    def _analyze_similarity(self, analyzer_name: str) -> dict[str, Any]:
        """Run a similarity-style analyzer that exposes the default analyze path."""
        return self._execute_dict(analyzer_name)

    def analyze_ssdeep(self) -> dict[str, Any]:
        return self._analyze_similarity("ssdeep")

    def analyze_tlsh(self) -> dict[str, Any]:
        return self._analyze_similarity("tlsh")

    def analyze_telfhash(self) -> dict[str, Any]:
        return self._analyze_similarity("telfhash")

    def analyze_rich_header(self) -> dict[str, Any]:
        return self._analyze_similarity("rich_header")

    def analyze_impfuzzy(self) -> dict[str, Any]:
        return self._analyze_similarity("impfuzzy")

    def analyze_ccbhash(self) -> dict[str, Any]:
        return self._analyze_similarity("ccbhash")

    def analyze_binlex(self) -> dict[str, Any]:
        return self._analyze_similarity("binlex")

    def analyze_binbloom(self) -> dict[str, Any]:
        return self._analyze_similarity("binbloom")

    def analyze_simhash(self) -> dict[str, Any]:
        return self._analyze_similarity("simhash")

    def analyze_bindiff(self) -> dict[str, Any]:
        return self._analyze_similarity("bindiff")

    def generate_executive_summary(self, analysis_results: dict[str, Any]) -> dict[str, Any]:
        result = self._result_aggregator.generate_executive_summary(analysis_results)
        return self._as_dict(result)

    # -- stage-backed queries (was InspectorStageQueryMixin) -----------------

    @error_handler(
        category=ErrorCategory.FILE_ACCESS,
        severity=ErrorSeverity.HIGH,
        context={"analysis_type": "file_info"},
        fallback_result={},
    )
    def get_file_info(self) -> dict[str, Any]:
        stage = FileInfoStage(
            self.adapter,
            self.filename,
            calculate_hashes,
            detect_file_type,
        )
        context: dict[str, Any] = {"options": {}, "results": {}}
        result_context = stage.execute(context)
        return self._as_dict(result_context.get("file_info"))

    def _detect_file_format(self) -> str:
        stage = FormatDetectionStage(
            self.adapter,
            self.filename,
            detect_file_type,
        )
        context: dict[str, Any] = {"options": {}, "results": {}, "metadata": {}}
        result_context = stage.execute(context)
        metadata = cast(dict[str, Any], result_context.get("metadata", {}))
        return self._as_str(metadata.get("file_format"), "Unknown")

    # -- query methods (was InspectorQueryMixin) -----------------------------

    def get_pe_info(self) -> dict[str, Any]:
        return self._execute_dict("pe_analyzer")

    def get_elf_info(self) -> dict[str, Any]:
        return self._execute_dict("elf_analyzer")

    def get_macho_info(self) -> dict[str, Any]:
        return self._execute_dict("macho_analyzer")

    def get_strings(self) -> list[str]:
        return self._execute_list("string_analyzer", "extract_strings")

    def get_security_features(self) -> dict[str, bool]:
        return self._as_bool_dict(self._execute_analyzer("pe_analyzer", "get_security_features"))

    def get_imports(self) -> list[dict[str, Any]]:
        return self._execute_list("import_analyzer", "get_imports")

    def get_exports(self) -> list[dict[str, Any]]:
        return self._execute_list("export_analyzer", "get_exports")

    def get_sections(self) -> list[dict[str, Any]]:
        return self._execute_list("section_analyzer", "analyze_sections")

    def detect_packer(self) -> dict[str, Any]:
        return self._execute_dict("packer_detector", "detect")

    @error_handler(
        category=ErrorCategory.ANALYSIS,
        severity=ErrorSeverity.MEDIUM,
        context={"analysis_type": "crypto_detection"},
        fallback_result={
            "algorithms": [],
            "constants": [],
            "error": "Crypto detection failed",
        },
    )
    def detect_crypto(self) -> dict[str, Any]:
        result = self._execute_analyzer("crypto_analyzer", "detect")
        if not result:
            return {"algorithms": [], "constants": [], "error": "Analyzer not found"}
        return self._as_dict(result)

    def detect_anti_analysis(self) -> dict[str, Any]:
        return self._execute_dict("anti_analysis", "detect")

    def detect_compiler(self) -> dict[str, Any]:
        return self._execute_dict("compiler_detector", "detect_compiler")

    def run_yara_rules(self, custom_rules_path: str | None = None) -> list[dict[str, Any]]:
        return self._execute_list("yara_analyzer", "scan", custom_rules_path)

    def search_xor(self, search_string: str) -> list[dict[str, Any]]:
        return self._execute_list("string_analyzer", "search_xor", search_string)
