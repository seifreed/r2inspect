#!/usr/bin/env python3
"""Detection-related pipeline stages."""

from __future__ import annotations

from typing import Any

from ..domain.results import AnalyzerStatus
from .analyzer_execution import record_skipped_execution, run_registered_analyzer
from .stages_common import OptionsRegistryStage


class DetectionStage(OptionsRegistryStage):
    """Execute detection analyzers for patterns and signatures."""

    stage_name = "detection"
    stage_description = "Pattern and signature detection"
    stage_dependencies = ["format_detection"]

    def _execute(self, context: dict[str, Any]) -> dict[str, Any]:
        results: dict[str, Any] = {}
        if self.options.get("detect_packer", True):
            res = self._run_packer_detection(context)
            if res is not None:
                results.update(res)
        else:
            self._record_profile_skip(context, "packer_detector")

        if self.options.get("detect_crypto", True):
            res = self._run_crypto_detection(context)
            if res is not None:
                results.update(res)
        else:
            self._record_profile_skip(context, "crypto_analyzer")

        if self.options.get("detect_anti_analysis", True):
            res = self._run_anti_analysis_detection(context)
            if res is not None:
                results.update(res)
        else:
            self._record_profile_skip(context, "anti_analysis")

        if self.options.get("detect_compiler", True):
            res = self._run_compiler_detection(context)
            if res is not None:
                results.update(res)
        else:
            self._record_profile_skip(context, "compiler_detector")

        if self.options.get("detect_yara", True):
            res = self._run_yara_analysis(context)
            if res is not None:
                results.update(res)
        else:
            self._record_profile_skip(context, "yara_analyzer")

        if self.options.get("detect_capa", False):
            res = self._run_analyzer(
                context,
                "capa",
                "capa",
                analyze_args=(bool(self.options.get("forensic_evidence")),),
            )
            if res is not None:
                results.update(res)
        else:
            self._record_profile_skip(context, "capa")

        if self.options.get("detect_floss", False):
            res = self._run_analyzer(
                context,
                "floss",
                "floss",
                analyze_args=(bool(self.options.get("forensic_evidence")),),
            )
            if res is not None:
                results.update(res)
        else:
            self._record_profile_skip(context, "floss")

        return results

    def _record_profile_skip(self, context: dict[str, Any], analyzer_name: str) -> None:
        record_skipped_execution(
            self,
            context,
            analyzer_name,
            AnalyzerStatus.SKIPPED_BY_PROFILE,
            "analyzer disabled by the selected profile",
        )

    def _run_analyzer(
        self,
        context: dict[str, Any],
        analyzer_name: str,
        result_key: str,
        *,
        analyze_args: tuple[Any, ...] = (),
        error_default: Any = None,
    ) -> dict[str, Any] | None:
        return run_registered_analyzer(
            self,
            context,
            analyzer_name,
            result_key,
            invoke=lambda analyzer: analyzer.analyze(*analyze_args),
            error_default=lambda e: (
                error_default if error_default is not None else {"error": str(e)}
            ),
            log_label=f"Analyzer '{analyzer_name}'",
        )

    def _run_packer_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer(context, "packer_detector", "packer")

    def _run_crypto_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer(context, "crypto_analyzer", "crypto")

    def _run_anti_analysis_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer(context, "anti_analysis", "anti_analysis")

    def _run_compiler_detection(self, context: dict[str, Any]) -> dict[str, Any] | None:
        return self._run_analyzer(context, "compiler_detector", "compiler")

    def _run_yara_analysis(self, context: dict[str, Any]) -> dict[str, Any] | None:
        custom_rules = self.options.get("custom_yara")
        return self._run_analyzer(
            context,
            "yara_analyzer",
            "yara_matches",
            analyze_args=(custom_rules,),
            error_default=[],
        )
