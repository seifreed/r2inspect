#!/usr/bin/env python3
"""Security-related pipeline stages."""

from __future__ import annotations

import logging
from typing import Any

from .pipeline_runtime_common import detected_file_format
from .stages_common import ConfiguredRegistryStage, _results_bucket

logger = logging.getLogger(__name__)


def _bucket(context: dict[str, Any], key: str) -> dict[str, Any]:
    results = _results_bucket(context)
    value = results.get(key)
    if isinstance(value, dict):
        return value
    value = {}
    results[key] = value
    return value


class SecurityStage(ConfiguredRegistryStage):
    """Analyze security features and exploit mitigations."""

    stage_name = "security"
    stage_description = "Security feature and mitigation analysis"
    stage_dependencies = ["format_detection"]

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        file_format = detected_file_format(context)

        results: dict[str, Any] = {}
        if file_format == "PE":
            res = self._analyze_pe_security(context)
            if res is not None:
                results.update(res)

        res = self._analyze_mitigations(context)
        if res is not None:
            results.update(res)

        return results

    def _analyze_pe_security(self, context: dict[str, Any]) -> dict[str, Any] | None:
        pe_analyzer_class = self.registry.get_analyzer_class("pe_analyzer")
        if pe_analyzer_class:
            try:
                analyzer = self.analyzer_factory(
                    pe_analyzer_class,
                    adapter=self.adapter,
                    config=self.config,
                    filename=self.filename,
                )
                data = analyzer.get_security_features()
                _bucket(context, "security").update(data)
                return {"security": data}
            except Exception as e:
                logger.warning("PE security analysis failed: %s", e)
                _bucket(context, "security")["error"] = str(e)
                return {"security": {"error": str(e)}}
        return None

    def _analyze_mitigations(self, context: dict[str, Any]) -> dict[str, Any] | None:
        mitigation_class = self.registry.get_analyzer_class("exploit_mitigation")
        if mitigation_class:
            try:
                analyzer = self.analyzer_factory(
                    mitigation_class, adapter=self.adapter, config=self.config
                )
                mitigations = analyzer.analyze()
                _bucket(context, "security").update(mitigations)
            except Exception as e:
                logger.debug("Mitigation analysis failed: %s", e)
                return None
            return {"security": _results_bucket(context).get("security", {})}
        return None
