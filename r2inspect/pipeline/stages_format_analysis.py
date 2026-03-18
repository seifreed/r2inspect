#!/usr/bin/env python3
"""Format-specific analysis stage support.

The stage is intentionally isolated from ``stages_format`` because it owns
format-dependent analyzer dispatch, while the base module keeps file-info and
format-detection concerns.
"""

from __future__ import annotations

import logging
from typing import Any

from ..interfaces import AnalyzerBackend, AnalyzerFactoryLike, AnalyzerRegistryLike
from .analysis_pipeline import AnalysisStage
from .stages_common import default_analyzer_factory

logger = logging.getLogger(__name__)

PE_OPTIONAL_ANALYZERS: tuple[tuple[str, str, str], ...] = (
    ("analyze_authenticode", "authenticode", "authenticode"),
    ("analyze_overlay", "overlay_analyzer", "overlay"),
    ("analyze_resources", "resource_analyzer", "resources"),
    ("analyze_mitigations", "exploit_mitigation", "exploit_mitigations"),
)
FORMAT_HANDLERS = {
    "PE": "_analyze_pe",
    "ELF": "_analyze_elf",
    "Mach-O": "_analyze_macho",
}


class FormatAnalysisStage(AnalysisStage):
    """Perform format-specific deep analysis."""

    def __init__(
        self,
        registry: AnalyzerRegistryLike,
        adapter: AnalyzerBackend,
        config: Any,
        filename: str,
        analyzer_factory: AnalyzerFactoryLike = default_analyzer_factory,
    ) -> None:
        super().__init__(
            name="format_analysis",
            description="Format-specific deep analysis",
            optional=True,
            dependencies=["format_detection"],
            condition=lambda ctx: ctx.get("metadata", {}).get("file_format")
            in {"PE", "ELF", "Mach-O"},
        )
        self.registry = registry
        self.adapter = adapter
        self.config = config
        self.filename = filename
        self.analyzer_factory = analyzer_factory

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        file_format = context.get("metadata", {}).get("file_format", "Unknown")
        results = self._analyze_known_format(file_format, context)
        if results:
            return results
        logger.info("No format-specific analyzer for: %s", file_format)
        return {}

    def _analyze_known_format(self, file_format: str, context: dict[str, Any]) -> dict[str, Any]:
        handler_name = FORMAT_HANDLERS.get(file_format)
        if handler_name is None:
            return {}
        result = getattr(self, handler_name)(context)
        return result or {}

    def _run_analyzer(
        self,
        analyzer_name: str,
        *,
        include_filename: bool = False,
    ) -> Any | None:
        analyzer_class = self.registry.get_analyzer_class(analyzer_name)
        if not analyzer_class:
            return None
        kwargs: dict[str, Any] = {"adapter": self.adapter, "config": self.config}
        if include_filename:
            kwargs["filename"] = self.filename
        return self.analyzer_factory(analyzer_class, **kwargs)

    def _analyze_pe(self, context: dict[str, Any]) -> dict[str, Any] | None:
        analyzer = self._run_analyzer("pe_analyzer", include_filename=True)
        if analyzer is not None:
            data = analyzer.analyze()
            self._run_optional_pe_analyzers(data)
            return self._store_result(context, "pe_info", data)
        return None

    def _analyze_elf(self, context: dict[str, Any]) -> dict[str, Any] | None:
        analyzer = self._run_analyzer("elf_analyzer")
        if analyzer is not None:
            data = analyzer.analyze()
            return self._store_result(context, "elf_info", data)
        return None

    def _analyze_macho(self, context: dict[str, Any]) -> dict[str, Any] | None:
        analyzer = self._run_analyzer("macho_analyzer")
        if analyzer is not None:
            data = analyzer.analyze()
            return self._store_result(context, "macho_info", data)
        return None

    def _run_optional_pe_analyzers(self, pe_info: dict[str, Any]) -> None:
        """Run optional PE-only analyzers enabled in the current config."""
        for config_key, analyzer_name, result_key in PE_OPTIONAL_ANALYZERS:
            if not getattr(self.config, config_key, False):
                continue
            analyzer = self._run_analyzer(analyzer_name, include_filename=True)
            if analyzer is None:
                continue
            try:
                pe_info[result_key] = analyzer.analyze()
            except Exception as exc:
                logger.warning(
                    "Optional PE analyzer %s failed and was skipped: %s",
                    analyzer_name,
                    exc,
                )

    @staticmethod
    def _store_result(
        context: dict[str, Any], result_key: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        """Persist a format analysis payload in the shared execution context."""
        context["results"][result_key] = data
        return {result_key: data}


__all__ = ["FormatAnalysisStage"]
