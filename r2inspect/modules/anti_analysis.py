#!/usr/bin/env python3
"""Anti-analysis detection module."""

from typing import Any, cast

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..infrastructure.logging import get_logger
from .anti_analysis_support import (
    build_anti_analysis_report,
    detect_anti_debug,
    detect_anti_sandbox,
    detect_anti_vm,
    detect_environment_fingerprinting,
    detect_evasion_techniques as build_evasion_techniques,
    detect_timing_checks,
    find_suspicious_apis,
)
from ..domain.formats.anti_analysis import (
    ANTI_DEBUG_APIS,
    ENVIRONMENT_CHECK_COMMANDS,
    INJECTION_APIS,
    SANDBOX_INDICATORS,
    SUSPICIOUS_API_CATEGORIES,
    TIMING_APIS,
    VM_ARTIFACTS,
)
from .anti_analysis_helpers import (
    add_simple_evidence,
    collect_artifact_strings,
    detect_api_hashing,
    detect_environment_checks,
    detect_injection_apis,
    detect_obfuscation,
    detect_self_modifying,
    match_suspicious_api,
)
from .search_helpers import search_text

logger = get_logger(__name__)


def _error_evidence(detail: str) -> list[dict[str, str]]:
    return [{"type": "Error", "detail": detail}]


def _run_detail_detector(
    label: str,
    detector: Any,
    fallback: Any,
) -> Any:
    try:
        return detector()
    except Exception as exc:
        logger.error("Error in %s: %s", label, exc)
        return fallback(exc) if callable(fallback) else fallback


class AntiAnalysisDetector(CommandHelperMixin):
    """Anti-analysis techniques detection using a backend interface."""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        self.adapter = adapter
        self.config = config

        self.anti_debug_apis = ANTI_DEBUG_APIS
        self.vm_artifacts = VM_ARTIFACTS
        self.sandbox_indicators = SANDBOX_INDICATORS

    def detect(self) -> dict[str, Any]:
        """Detect anti-analysis techniques with detailed evidence"""
        anti_analysis = _run_detail_detector(
            "anti-analysis detection",
            lambda: build_anti_analysis_report(self),
            lambda exc: {
                "anti_debug": False,
                "anti_vm": False,
                "anti_sandbox": False,
                "evasion_techniques": [],
                "suspicious_apis": [],
                "timing_checks": False,
                "environment_checks": [],
                "detection_details": {
                    "anti_debug_evidence": [],
                    "anti_vm_evidence": [],
                    "anti_sandbox_evidence": [],
                    "timing_evidence": [],
                },
                "error": str(exc),
            },
        )
        return cast(dict[str, Any], anti_analysis)

    def _detect_anti_debug_detailed(self) -> dict[str, Any]:
        """Detect anti-debugging techniques with detailed evidence"""
        return cast(
            dict[str, Any],
            _run_detail_detector(
                "anti-debug detection",
                lambda: detect_anti_debug(self),
                lambda exc: {
                    "detected": False,
                    "evidence": _error_evidence(f"Detection error: {exc}"),
                },
            ),
        )

    def _detect_anti_vm_detailed(self) -> dict[str, Any]:
        """Detect anti-VM techniques with detailed evidence"""
        return cast(
            dict[str, Any],
            _run_detail_detector(
                "anti-VM detection",
                lambda: detect_anti_vm(self),
                lambda exc: {
                    "detected": False,
                    "evidence": _error_evidence(f"Detection error: {exc}"),
                },
            ),
        )

    def _detect_anti_sandbox_detailed(self) -> dict[str, Any]:
        """Detect sandbox evasion techniques with detailed evidence"""
        return cast(
            dict[str, Any],
            _run_detail_detector(
                "anti-sandbox detection",
                lambda: detect_anti_sandbox(self),
                lambda exc: {
                    "detected": False,
                    "evidence": _error_evidence(f"Detection error: {exc}"),
                },
            ),
        )

    def _detect_evasion_techniques(self) -> list[dict[str, Any]]:
        """Detect various evasion techniques"""
        return cast(
            list[dict[str, Any]],
            _run_detail_detector(
                "evasion technique detection", lambda: build_evasion_techniques(self), []
            ),
        )

    def _find_suspicious_apis(self) -> list[dict[str, Any]]:
        """Find suspicious API calls"""
        return cast(
            list[dict[str, Any]],
            _run_detail_detector(
                "suspicious API detection", lambda: find_suspicious_apis(self), []
            ),
        )

    def _detect_timing_checks_detailed(self) -> dict[str, Any]:
        """Detect timing-based evasion techniques with detailed evidence"""
        return cast(
            dict[str, Any],
            _run_detail_detector(
                "timing-check detection",
                lambda: detect_timing_checks(self),
                lambda exc: {
                    "detected": False,
                    "evidence": _error_evidence(f"Detection error: {exc}"),
                },
            ),
        )

    def _detect_environment_checks(self) -> list[dict[str, Any]]:
        """Detect environment fingerprinting"""
        return cast(
            list[dict[str, Any]],
            _run_detail_detector(
                "environment-check detection",
                lambda: detect_environment_fingerprinting(self),
                [],
            ),
        )

    def _search_opcode(self, pattern: str) -> str:
        return search_text(self.adapter, pattern)

    def _get_imports(self) -> list[dict[str, Any]]:
        return self._coerce_dict_list(self._get_via_adapter("get_imports", "iij"))

    def _get_strings(self) -> list[dict[str, Any]]:
        return self._coerce_dict_list(self._get_via_adapter("get_strings", "izj"))
