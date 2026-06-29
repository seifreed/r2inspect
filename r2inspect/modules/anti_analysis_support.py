"""Helpers for anti-analysis detection flows."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..abstractions.coercion_support import coerce_int, coerce_text
from ..domain.formats.anti_analysis import (
    ENVIRONMENT_CHECK_COMMANDS,
    INJECTION_APIS,
    SUSPICIOUS_API_CATEGORIES,
    TIMING_APIS,
    VM_MAC_OUIS,
)
from ..domain.text_helpers import has_text
from .anti_analysis_helpers import (
    add_simple_evidence,
    collect_artifact_strings,
    detect_environment_checks,
    detect_injection_apis,
    detect_obfuscation,
    match_suspicious_api,
)


def _evidence_list(result: Any) -> list[Any]:
    if isinstance(result, dict):
        evidence = result.get("evidence")
        if isinstance(evidence, list):
            return evidence
        if isinstance(evidence, (dict, str, bytes)) or not isinstance(evidence, Iterable):
            return []
        try:
            return list(evidence)
        except TypeError:
            return []
    return []


def _detected_flag(result: Any) -> bool:
    return bool(result.get("detected")) if isinstance(result, dict) else False


def empty_anti_analysis_report() -> dict[str, Any]:
    """Return the default anti-analysis report skeleton with no detections."""
    return {
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


def build_anti_analysis_report(detector: Any) -> dict[str, Any]:
    anti_analysis = empty_anti_analysis_report()
    debug_result = detector._detect_anti_debug_detailed()
    anti_analysis["anti_debug"] = _detected_flag(debug_result)
    anti_analysis["detection_details"]["anti_debug_evidence"] = _evidence_list(debug_result)
    vm_result = detector._detect_anti_vm_detailed()
    anti_analysis["anti_vm"] = _detected_flag(vm_result)
    anti_analysis["detection_details"]["anti_vm_evidence"] = _evidence_list(vm_result)
    sandbox_result = detector._detect_anti_sandbox_detailed()
    anti_analysis["anti_sandbox"] = _detected_flag(sandbox_result)
    anti_analysis["detection_details"]["anti_sandbox_evidence"] = _evidence_list(sandbox_result)
    anti_analysis["evasion_techniques"] = detector._detect_evasion_techniques()
    anti_analysis["suspicious_apis"] = detector._find_suspicious_apis()
    timing_result = detector._detect_timing_checks_detailed()
    anti_analysis["timing_checks"] = _detected_flag(timing_result)
    anti_analysis["detection_details"]["timing_evidence"] = _evidence_list(timing_result)
    anti_analysis["environment_checks"] = detector._detect_environment_checks()
    return anti_analysis


def _anti_debug_import_evidence(detector: Any) -> list[dict[str, Any]]:
    imports = detector._get_imports()
    if not imports:
        return []
    evidence: list[dict[str, Any]] = []
    for imp in imports:
        if not isinstance(imp, dict):
            continue
        func_name = coerce_text(imp.get("name"))
        if func_name in detector.anti_debug_apis:
            evidence.append(
                {
                    "type": "API Call",
                    "detail": f"Anti-debug API: {func_name}",
                    "address": hex(coerce_int(imp.get("plt", 0))),
                    "library": imp.get("libname") or imp.get("library", "unknown"),
                }
            )
    return evidence


def _peb_access_evidence(detector: Any) -> list[dict[str, Any]]:
    peb_checks = detector._search_opcode("fs:[0x30]")
    if not isinstance(peb_checks, str) or not peb_checks.strip():
        return []
    addresses = peb_checks.strip().split("\n")
    return [
        {
            "type": "PEB Access",
            "detail": f"PEB BeingDebugged flag access at {len(addresses)} locations",
            "addresses": addresses[:3],
        }
    ]


def _int3_breakpoint_evidence(detector: Any) -> list[dict[str, Any]]:
    int3_checks = detector._search_opcode("cc")
    if not isinstance(int3_checks, str) or not int3_checks.strip():
        return []
    addresses = int3_checks.strip().split("\n")
    if len(addresses) <= 5:
        return []
    return [
        {
            "type": "Breakpoint Detection",
            "detail": f"{len(addresses)} INT3 instructions found (possible breakpoint detection)",
            "addresses": addresses[:5],
        }
    ]


def _rdtsc_timing_evidence(detector: Any) -> list[dict[str, Any]]:
    rdtsc_checks = detector._search_opcode("rdtsc")
    if not isinstance(rdtsc_checks, str) or not rdtsc_checks.strip():
        return []
    addresses = rdtsc_checks.strip().split("\n")
    return [
        {
            "type": "Timing Check",
            "detail": f"RDTSC instruction at {len(addresses)} locations",
            "addresses": addresses[:3],
        }
    ]


def detect_anti_debug(detector: Any) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    for evidence_fn in (
        _anti_debug_import_evidence,
        _peb_access_evidence,
        _int3_breakpoint_evidence,
        _rdtsc_timing_evidence,
    ):
        evidence.extend(evidence_fn(detector))
    return {"detected": bool(evidence), "evidence": evidence}


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
        # add_simple_evidence appends " at N locations" for address fields, so the
        # prefix must not already end in "at" (avoids "CPUID instruction at at N").
        "CPUID instruction",
        "addresses",
        3,
    )
    mac_strings = collect_artifact_strings(detector._get_strings(), VM_MAC_OUIS)
    if mac_strings:
        result["detected"] = True
        result["evidence"].append(
            {
                "type": "MAC Address Query",
                "detail": "VM-vendor MAC address prefixes found (VM fingerprinting)",
                "strings": mac_strings[:5],
            }
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
        # Match Sleep/SleepEx and the native NtDelayExecution timing API, NOT a
        # bare "Delay" substring -- that hit the DLL delay-LOAD runtime imports
        # (ResolveDelayLoadedAPI, DelayLoadFailureHook), which are present in
        # ordinary binaries and have nothing to do with sandbox-evasion sleeps.
        detector._cmd("ii~Sleep,NtDelayExecution"),
        "Sleep/Delay Calls",
        "Sleep or delay functions found (sandbox evasion)",
        "functions",
        3,
    )
    add_simple_evidence(
        result,
        detector._cmd("ii~FindFirst,Process32,Module32"),
        "Environment Enumeration",
        "File/process enumeration APIs found (fingerprinting)",
        "functions",
        3,
    )
    return result


def detect_evasion_techniques(detector: Any) -> list[dict[str, Any]]:
    techniques: list[dict[str, Any]] = []
    techniques.extend(detect_obfuscation(detector._search_opcode))
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
            if not isinstance(imp, dict):
                continue
            func_name = coerce_text(imp.get("name"))
            if func_name in TIMING_APIS:
                timing_imports.append(
                    {
                        "function": func_name,
                        "description": TIMING_APIS[func_name],
                        "address": hex(coerce_int(imp.get("plt", 0))),
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
    if has_text(rdtsc_usage):
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
