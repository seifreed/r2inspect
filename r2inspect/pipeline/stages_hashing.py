#!/usr/bin/env python3
"""Hashing-related pipeline stages."""

from __future__ import annotations

import logging
from typing import Any

from ..interfaces import HashingAnalyzerInterface
from ..domain.results import AnalyzerStatus
from ..registry.analyzer_registry import AnalyzerCategory
from .pipeline_runtime_common import detected_file_format
from .analyzer_execution import (
    _typed_result,
    record_analyzer_execution,
    record_skipped_execution,
)
from .results_bucket import _results_bucket
from .stages_common import ConfiguredRegistryStage

logger = logging.getLogger(__name__)


class HashingStage(ConfiguredRegistryStage):
    """Execute hashing analyzers for similarity detection."""

    stage_name = "hashing"
    stage_description = "Execute fuzzy and similarity hashing"
    stage_dependencies = ["file_info"]

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        file_format = detected_file_format(context)
        hashing_analyzers = self.registry.get_by_category(AnalyzerCategory.HASHING)

        results: dict[str, Any] = {}
        for name, analyzer_class in hashing_analyzers.items():
            try:
                if not self._supports_format(name, file_format):
                    logger.debug("Skipping %s: doesn't support %s", name, file_format)
                    record_skipped_execution(
                        self,
                        context,
                        name,
                        AnalyzerStatus.NOT_APPLICABLE,
                        f"analyzer does not apply to {file_format}",
                    )
                    continue
                analyzer = self._build_hashing_analyzer(analyzer_class)
                result = self._run_hashing_analyzer(name, analyzer)
                result = _typed_result(name, result)
                self._store_hashing_result(context, results, name, result)
                record_analyzer_execution(
                    self,
                    context,
                    name,
                    result,
                    status=getattr(result, "status", None),
                    error=getattr(result, "error", None),
                )
            except Exception as e:
                logger.warning("Hashing analyzer '%s' failed: %s", name, e)
                _results_bucket(context)[name] = _typed_result(
                    name, {"error": str(e)}, status="failed", error=str(e)
                )
                record_analyzer_execution(
                    self,
                    context,
                    name,
                    _results_bucket(context)[name],
                    status=AnalyzerStatus.FAILED,
                    error=str(e),
                )

        return results

    def _supports_format(self, name: str, file_format: str) -> bool:
        metadata = self.registry.get_metadata(name)
        return metadata is None or metadata.supports_format(file_format)

    def _build_hashing_analyzer(self, analyzer_class: type[Any]) -> Any:
        return self.analyzer_factory(
            analyzer_class,
            adapter=self.adapter,
            config=self.config,
            filename=self.filename,
        )

    def _run_hashing_analyzer(self, name: str, analyzer: HashingAnalyzerInterface) -> Any:
        detailed_method = {
            "tlsh": "analyze_sections",
            "ccbhash": "analyze_functions",
            "simhash": "analyze_detailed",
        }.get(name)
        if detailed_method is not None:
            method = getattr(analyzer, detailed_method, None)
            if callable(method):
                return method()
        return analyzer.analyze()

    def _store_hashing_result(
        self, context: dict[str, Any], results: dict[str, Any], name: str, result: Any
    ) -> None:
        _results_bucket(context)[name] = result
        results[name] = result
