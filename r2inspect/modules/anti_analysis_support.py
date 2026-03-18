"""Helpers for anti-analysis detection flows."""

from __future__ import annotations

from typing import Any

from .anti_analysis_domain import (
    ENVIRONMENT_CHECK_COMMANDS,
    INJECTION_APIS,
    SUSPICIOUS_API_CATEGORIES,
    TIMING_APIS,
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


def build_anti_analysis_report(detector: Any) -> dict[str, Any]:
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
    debug_result = detector._detect_anti_debug_detailed()
    anti_analysis["anti_debug"] = debug_result["detected"]
    anti_analysis["detection_details"]["anti_debug_evidence"] = debug_result["evidence"]
    vm_result = detector._detect_anti_vm_detailed()
    anti_analysis["anti_vm"] = vm_result["detected"]
    anti_analysis["detection_details"]["anti_vm_evidence"] = vm_result["evidence"]
    sandbox_result = detector._detect_anti_sandbox_detailed()
    anti_analysis["anti_sandbox"] = sandbox_result["detected"]
    anti_analysis["detection_details"]["anti_sandbox_evidence"] = sandbox_result["evidence"]
    anti_analysis["evasion_techniques"] = detector._detect_evasion_techniques()
    anti_analysis["suspicious_apis"] = detector._find_suspicious_apis()
    timing_result = detector._detect_timing_checks_detailed()
    anti_analysis["timing_checks"] = timing_result["detected"]
    anti_analysis["detection_details"]["timing_evidence"] = timing_result["evidence"]
    anti_analysis["environment_checks"] = detector._detect_environment_checks()
    return anti_analysis


def detect_anti_debug(detector: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"detected": False, "evidence": []}
    imports = detector._get_imports()
    if imports:
        for imp in imports:
            func_name = imp.get("name", "")
            if func_name in detector.anti_debug_apis:
                result["detected"] = True
                result["evidence"].append(
                    {
                        "type": "API Call",
                        "detail": f"Anti-debug API: {func_name}",
                        "address": hex(imp.get("plt", 0)),
                        "library": imp.get("libname") or imp.get("library", "unknown"),
                    }
                )
    peb_checks = detector._search_opcode("fs:[0x30]")
    if peb_checks and peb_checks.strip():
        result["detected"] = True
        addresses = peb_checks.strip().split("\n")
        result["evidence"].append(
            {
                "type": "PEB Access",
                "detail": f"PEB BeingDebugged flag access at {len(addresses)} locations",
                "addresses": addresses[:3],
            }
        )
    int3_checks = detector._search_opcode("cc")
    if int3_checks and int3_checks.strip():
        addresses = int3_checks.strip().split("\n")
        if len(addresses) > 5:
            result["detected"] = True
            result["evidence"].append(
                {
                    "type": "Breakpoint Detection",
                    "detail": f"{len(addresses)} INT3 instructions found (possible breakpoint detection)",
                    "addresses": addresses[:5],
                }
            )
    rdtsc_checks = detector._search_opcode("rdtsc")
    if rdtsc_checks and rdtsc_checks.strip():
        result["detected"] = True
        addresses = rdtsc_checks.strip().split("\n")
        result["evidence"].append(
            {
                "type": "Timing Check",
                "detail": f"RDTSC instruction at {len(addresses)} locations",
                "addresses": addresses[:3],
            }
        )
    return result


def detect_anti_vm(detector: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"detected": False, "evidence": []}
    vm_strings = collect_artifact_strings(detector._get_strings(), detector.vm_artifacts)
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
        detector._search_opcode("cpuid"),
        "CPUID Detection",
        "CPUID instruction at",
        "addresses",
        3,
    )
    add_simple_evidence(
        result,
        detector._cmd("iz~mac"),
        "MAC Address Query",
        "MAC address strings found (VM fingerprinting)",
        "strings",
        3,
    )
    add_simple_evidence(
        result,
        detector._cmd("iz~HKEY.*VMware|HKEY.*VirtualBox|HKEY.*VBOX"),
        "Registry VM Check",
        "VM-related registry keys found",
        "keys",
        3,
    )
    return result


def detect_anti_sandbox(detector: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"detected": False, "evidence": []}
    sandbox_strings = collect_artifact_strings(detector._get_strings(), detector.sandbox_indicators)
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
        detector._cmd("ii~Sleep|ii~Delay"),
        "Sleep/Delay Calls",
        "Sleep or delay functions found (sandbox evasion)",
        "functions",
        3,
    )
    add_simple_evidence(
        result,
        detector._cmd("ii~FindFirst|ii~Process32|ii~Module32"),
        "Environment Enumeration",
        "File/process enumeration APIs found (fingerprinting)",
        "functions",
        3,
    )
    return result


def detect_evasion_techniques(detector: Any) -> list[dict[str, Any]]:
    techniques: list[dict[str, Any]] = []
    techniques.extend(detect_obfuscation(detector._search_opcode))
    techniques.extend(detect_self_modifying(detector._cmd))
    techniques.extend(detect_api_hashing(detector._cmd))
    techniques.extend(detect_injection_apis(detector._get_imports(), set(INJECTION_APIS)))
    return techniques


def find_suspicious_apis(detector: Any) -> list[dict[str, Any]]:
    suspicious: list[dict[str, Any]] = []
    imports = detector._get_imports()
    if imports:
        for imp in imports:
            match = match_suspicious_api(imp, SUSPICIOUS_API_CATEGORIES)
            if match:
                suspicious.append(match)
    return suspicious


def detect_timing_checks(detector: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"detected": False, "evidence": []}
    imports = detector._get_imports()
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
                        "library": imp.get("libname") or imp.get("library", "unknown"),
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
    rdtsc_usage = detector._search_opcode("rdtsc")
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
    return result


def detect_environment_fingerprinting(detector: Any) -> list[dict[str, Any]]:
    return detect_environment_checks(detector._cmd, ENVIRONMENT_CHECK_COMMANDS)
