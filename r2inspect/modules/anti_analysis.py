#!/usr/bin/env python3
"""Anti-analysis detection module."""

from typing import Any

from ..abstractions.command_helper_mixin import CommandHelperMixin
from ..utils.logger import get_logger
from .anti_analysis_domain import (
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


class AntiAnalysisDetector(CommandHelperMixin):
    """Anti-analysis techniques detection using a backend interface."""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        self.adapter = adapter
        self.r2 = adapter
        self.config = config

        self.anti_debug_apis = ANTI_DEBUG_APIS
        self.vm_artifacts = VM_ARTIFACTS
        self.sandbox_indicators = SANDBOX_INDICATORS

    def detect(self) -> dict[str, Any]:
        """Detect anti-analysis techniques with detailed evidence"""
        anti_analysis: dict[str, Any] = {
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
        }

        try:
            # Check for anti-debug techniques with details
            debug_result = self._detect_anti_debug_detailed()
            anti_analysis["anti_debug"] = debug_result["detected"]
            anti_analysis["detection_details"]["anti_debug_evidence"] = debug_result["evidence"]

            # Check for anti-VM techniques with details
            vm_result = self._detect_anti_vm_detailed()
            anti_analysis["anti_vm"] = vm_result["detected"]
            anti_analysis["detection_details"]["anti_vm_evidence"] = vm_result["evidence"]

            # Check for sandbox evasion with details
            sandbox_result = self._detect_anti_sandbox_detailed()
            anti_analysis["anti_sandbox"] = sandbox_result["detected"]
            anti_analysis["detection_details"]["anti_sandbox_evidence"] = sandbox_result["evidence"]

            # Detect evasion techniques
            anti_analysis["evasion_techniques"] = self._detect_evasion_techniques()

            # Find suspicious API calls
            anti_analysis["suspicious_apis"] = self._find_suspicious_apis()

            # Check for timing-based evasion with details
            timing_result = self._detect_timing_checks_detailed()
            anti_analysis["timing_checks"] = timing_result["detected"]
            anti_analysis["detection_details"]["timing_evidence"] = timing_result["evidence"]

            # Environment checks
            anti_analysis["environment_checks"] = self._detect_environment_checks()

        except Exception as e:
            logger.error(f"Error in anti-analysis detection: {e}")
            anti_analysis["error"] = str(e)

        return anti_analysis

    def _detect_anti_debug_detailed(self) -> dict[str, Any]:
        """Detect anti-debugging techniques with detailed evidence"""
        result: dict[str, Any] = {"detected": False, "evidence": []}

        try:
            # Check for anti-debug API imports
            imports = self._get_imports()
            if imports:
                for imp in imports:
                    func_name = imp.get("name", "")
                    if func_name in self.anti_debug_apis:
                        result["detected"] = True
                        result["evidence"].append(
                            {
                                "type": "API Call",
                                "detail": f"Anti-debug API: {func_name}",
                                "address": hex(imp.get("plt", 0)),
                                "library": imp.get("libname", "unknown"),
                            }
                        )

            # Check for PEB BeingDebugged flag access
            peb_checks = self._search_opcode("fs:[0x30]")  # PEB access
            if peb_checks and peb_checks.strip():
                result["detected"] = True
                addresses = peb_checks.strip().split("\n")
                result["evidence"].append(
                    {
                        "type": "PEB Access",
                        "detail": f"PEB BeingDebugged flag access at {len(addresses)} locations",
                        "addresses": addresses[:3],  # Limit to first 3
                    }
                )

            # Check for int 3 instructions (breakpoint detection)
            int3_checks = self._search_opcode("cc")  # int3 opcode
            if int3_checks and int3_checks.strip():
                addresses = int3_checks.strip().split("\n")
                count = len(addresses)
                if count > 5:  # Multiple int3 might indicate detection
                    result["detected"] = True
                    result["evidence"].append(
                        {
                            "type": "Breakpoint Detection",
                            "detail": f"{count} INT3 instructions found (possible breakpoint detection)",
                            "addresses": addresses[:5],  # Limit to first 5
                        }
                    )

            # Check for RDTSC timing checks
            rdtsc_checks = self._search_opcode("rdtsc")
            if rdtsc_checks and rdtsc_checks.strip():
                result["detected"] = True
                addresses = rdtsc_checks.strip().split("\n")
                result["evidence"].append(
                    {
                        "type": "Timing Check",
                        "detail": f"RDTSC instruction at {len(addresses)} locations",
                        "addresses": addresses[:3],  # Limit to first 3
                    }
                )

        except Exception as e:
            logger.error(f"Error detecting anti-debug: {e}")
            result["evidence"].append({"type": "Error", "detail": f"Detection error: {str(e)}"})

        return result

    def _detect_anti_vm_detailed(self) -> dict[str, Any]:
        """Detect anti-VM techniques with detailed evidence"""
        result: dict[str, Any] = {"detected": False, "evidence": []}

        try:
            vm_strings = collect_artifact_strings(self._get_strings(), self.vm_artifacts)
            if vm_strings:
                result["detected"] = True
                result["evidence"].append(
                    {
                        "type": "VM Artifact Strings",
                        "detail": f"Found {len(vm_strings)} VM-related strings",
                        "strings": vm_strings[:5],
                    }
                )

            add_simple_evidence(
                result,
                checks=self._search_opcode("cpuid"),
                evidence_type="CPUID Detection",
                detail_prefix="CPUID instruction at",
                field="addresses",
                limit=3,
            )
            add_simple_evidence(
                result,
                checks=self._cmd("iz~mac"),
                evidence_type="MAC Address Query",
                detail_prefix="MAC address strings found (VM fingerprinting)",
                field="strings",
                limit=3,
            )
            add_simple_evidence(
                result,
                checks=self._cmd("iz~HKEY.*VMware|HKEY.*VirtualBox|HKEY.*VBOX"),
                evidence_type="Registry VM Check",
                detail_prefix="VM-related registry keys found",
                field="keys",
                limit=3,
            )

        except Exception as e:
            logger.error(f"Error detecting anti-VM: {e}")
            result["evidence"].append({"type": "Error", "detail": f"Detection error: {str(e)}"})

        return result

    def _detect_anti_sandbox_detailed(self) -> dict[str, Any]:
        """Detect sandbox evasion techniques with detailed evidence"""
        result: dict[str, Any] = {"detected": False, "evidence": []}

        try:
            sandbox_strings = collect_artifact_strings(self._get_strings(), self.sandbox_indicators)
            if sandbox_strings:
                result["detected"] = True
                result["evidence"].append(
                    {
                        "type": "Sandbox Indicator Strings",
                        "detail": f"Found {len(sandbox_strings)} sandbox-related strings",
                        "strings": sandbox_strings[:5],
                    }
                )

            add_simple_evidence(
                result,
                checks=self._cmd("ii~Sleep|ii~Delay"),
                evidence_type="Sleep/Delay Calls",
                detail_prefix="Sleep or delay functions found (sandbox evasion)",
                field="functions",
                limit=3,
            )
            add_simple_evidence(
                result,
                checks=self._cmd("ii~FindFirst|ii~Process32|ii~Module32"),
                evidence_type="Environment Enumeration",
                detail_prefix="File/process enumeration APIs found (fingerprinting)",
                field="functions",
                limit=3,
            )

        except Exception as e:
            logger.error(f"Error detecting anti-sandbox: {e}")
            result["evidence"].append({"type": "Error", "detail": f"Detection error: {str(e)}"})

        return result

    def _detect_evasion_techniques(self) -> list[dict[str, Any]]:
        """Detect various evasion techniques"""
        techniques = []

        try:
            techniques.extend(detect_obfuscation(self._search_opcode))
            techniques.extend(detect_self_modifying(self._cmd))
            techniques.extend(detect_api_hashing(self._cmd))
            techniques.extend(detect_injection_apis(self._get_imports(), set(INJECTION_APIS)))

        except Exception as e:
            logger.error(f"Error detecting evasion techniques: {e}")

        return techniques

    def _find_suspicious_apis(self) -> list[dict[str, Any]]:
        """Find suspicious API calls"""
        suspicious = []

        try:
            imports = self._get_imports()

            if imports:
                for imp in imports:
                    match = match_suspicious_api(imp, SUSPICIOUS_API_CATEGORIES)
                    if match:
                        suspicious.append(match)

        except Exception as e:
            logger.error(f"Error finding suspicious APIs: {e}")

        return suspicious

    def _detect_timing_checks_detailed(self) -> dict[str, Any]:
        """Detect timing-based evasion techniques with detailed evidence"""
        result: dict[str, Any] = {"detected": False, "evidence": []}

        try:
            # Check for timing APIs
            imports = self._get_imports()
            if imports:
                timing_imports = []
                for imp in imports:
                    func_name = imp.get("name", "")
                    if func_name in TIMING_APIS:
                        timing_imports.append(
                            {
                                "function": func_name,
                                "description": TIMING_APIS[func_name],
                                "address": hex(imp.get("plt", 0)),
                                "library": imp.get("libname", "unknown"),
                            }
                        )
                        result["detected"] = True

                if timing_imports:
                    result["evidence"].append(
                        {
                            "type": "Timing API Calls",
                            "detail": f"Found {len(timing_imports)} timing-related APIs",
                            "apis": timing_imports,
                        }
                    )

            # Check for RDTSC usage
            rdtsc_usage = self._search_opcode("rdtsc")
            if rdtsc_usage and rdtsc_usage.strip():
                result["detected"] = True
                addresses = rdtsc_usage.strip().split("\n")
                result["evidence"].append(
                    {
                        "type": "RDTSC Instruction",
                        "detail": f"RDTSC (Read Time-Stamp Counter) at {len(addresses)} locations",
                        "addresses": addresses[:5],
                    }
                )

        except Exception as e:
            logger.error(f"Error detecting timing checks: {e}")
            result["evidence"].append({"type": "Error", "detail": f"Detection error: {str(e)}"})

        return result

    def _detect_environment_checks(self) -> list[dict[str, Any]]:
        """Detect environment fingerprinting"""
        checks = []

        try:
            checks = detect_environment_checks(self._cmd, ENVIRONMENT_CHECK_COMMANDS)
        except Exception as e:
            logger.error(f"Error detecting environment checks: {e}")

        return checks

    def _search_opcode(self, pattern: str) -> str:
        return search_text(self.adapter, self.r2, pattern)

    @staticmethod
    def _coerce_dict_list(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value]
        return []

    def _get_imports(self) -> list[dict[str, Any]]:
        if self.adapter is not None and hasattr(self.adapter, "get_imports"):
            return self._coerce_dict_list(self.adapter.get_imports())
        return self._coerce_dict_list(self._cmd_list("iij"))

    def _get_strings(self) -> list[dict[str, Any]]:
        if self.adapter is not None and hasattr(self.adapter, "get_strings"):
            return self._coerce_dict_list(self.adapter.get_strings())
        return self._coerce_dict_list(self._cmd_list("izj"))
