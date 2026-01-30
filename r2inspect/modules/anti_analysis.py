#!/usr/bin/env python3
# mypy: ignore-errors
"""
Anti-Analysis Detection Module using r2pipe
"""

from typing import Any

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmd, safe_cmdj

logger = get_logger(__name__)


class AntiAnalysisDetector:
    """Anti-analysis techniques detection using radare2"""

    def __init__(self, r2, config):
        self.r2 = r2
        self.config = config

        # Anti-debug API calls
        self.anti_debug_apis = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "ZwQueryInformationProcess",
            "OutputDebugStringA",
            "OutputDebugStringW",
            "GetTickCount",
            "QueryPerformanceCounter",
            "NtSetInformationThread",
            "SetThreadHideFromDebugger",
            "NtQueryObject",
            "NtClose",
        ]

        # Anti-VM artifacts
        self.vm_artifacts = [
            "VMware",
            "VirtualBox",
            "vbox",
            "vmtoolsd",
            "vmwaretray",
            "vmwareuser",
            "VBoxService",
            "VBoxTray",
            "xenservice",
            "qemu",
            "bochs",
            "sandboxie",
            "wireshark",
            "fiddler",
            "regmon",
            "procmon",
            "vmx",
            "vhd",
        ]

        # Sandbox evasion patterns
        self.sandbox_indicators = [
            "sample",
            "virus",
            "malware",
            "sandbox",
            "cuckoo",
            "anubis",
            "joesandbox",
            "threatanalyzer",
            "gfilogger",
            "cwsandbox",
        ]

    def detect(self) -> dict[str, Any]:
        """Detect anti-analysis techniques with detailed evidence"""
        anti_analysis = {
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
        result = {"detected": False, "evidence": []}

        try:
            # Check for anti-debug API imports
            imports = safe_cmdj(self.r2, "iij")
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
            peb_checks = safe_cmd(self.r2, "/c fs:[0x30]")  # PEB access
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
            int3_checks = safe_cmd(self.r2, "/c cc")  # int3 opcode
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
            rdtsc_checks = safe_cmd(self.r2, "/c rdtsc")
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
        result = {"detected": False, "evidence": []}

        try:
            vm_strings = self._collect_artifact_strings(self.vm_artifacts)
            if vm_strings:
                result["detected"] = True
                result["evidence"].append(
                    {
                        "type": "VM Artifact Strings",
                        "detail": f"Found {len(vm_strings)} VM-related strings",
                        "strings": vm_strings[:5],
                    }
                )

            self._add_simple_evidence(
                result,
                cmd="/c cpuid",
                evidence_type="CPUID Detection",
                detail_prefix="CPUID instruction at",
                field="addresses",
                limit=3,
            )
            self._add_simple_evidence(
                result,
                cmd="iz~mac",
                evidence_type="MAC Address Query",
                detail_prefix="MAC address strings found (VM fingerprinting)",
                field="strings",
                limit=3,
            )
            self._add_simple_evidence(
                result,
                cmd="iz~HKEY.*VMware|HKEY.*VirtualBox|HKEY.*VBOX",
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
        result = {"detected": False, "evidence": []}

        try:
            sandbox_strings = self._collect_artifact_strings(self.sandbox_indicators)
            if sandbox_strings:
                result["detected"] = True
                result["evidence"].append(
                    {
                        "type": "Sandbox Indicator Strings",
                        "detail": f"Found {len(sandbox_strings)} sandbox-related strings",
                        "strings": sandbox_strings[:5],
                    }
                )

            self._add_simple_evidence(
                result,
                cmd="ii~Sleep|ii~Delay",
                evidence_type="Sleep/Delay Calls",
                detail_prefix="Sleep or delay functions found (sandbox evasion)",
                field="functions",
                limit=3,
            )
            self._add_simple_evidence(
                result,
                cmd="ii~FindFirst|ii~Process32|ii~Module32",
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
            techniques.extend(self._detect_obfuscation())
            techniques.extend(self._detect_self_modifying())
            techniques.extend(self._detect_api_hashing())
            techniques.extend(self._detect_injection_apis())

        except Exception as e:
            logger.error(f"Error detecting evasion techniques: {e}")

        return techniques

    def _find_suspicious_apis(self) -> list[dict[str, Any]]:
        """Find suspicious API calls"""
        suspicious = []

        try:
            imports = safe_cmdj(self.r2, "iij")

            if imports:
                for imp in imports:
                    match = self._match_suspicious_api(imp)
                    if match:
                        suspicious.append(match)

        except Exception as e:
            logger.error(f"Error finding suspicious APIs: {e}")

        return suspicious

    def _collect_artifact_strings(self, artifacts: list[str]) -> list[dict[str, Any]]:
        strings_result = safe_cmdj(self.r2, "izj")
        if not strings_result:
            return []
        matches: list[dict[str, Any]] = []
        for string_info in strings_result:
            string_val = string_info.get("string", "")
            for artifact in artifacts:
                if artifact.lower() in string_val.lower():
                    matches.append(
                        {
                            "artifact": artifact,
                            "string": string_val,
                            "address": hex(string_info.get("vaddr", 0)),
                        }
                    )
        return matches

    def _add_simple_evidence(
        self,
        result: dict[str, Any],
        cmd: str,
        evidence_type: str,
        detail_prefix: str,
        field: str,
        limit: int,
    ) -> None:
        checks = safe_cmd(self.r2, cmd)
        if not checks or not checks.strip():
            return
        result["detected"] = True
        items = checks.strip().split("\n")[:limit]
        detail = (
            f"{detail_prefix} at {len(checks.strip().splitlines())} locations"
            if field == "addresses"
            else detail_prefix
        )
        result["evidence"].append({"type": evidence_type, "detail": detail, field: items})

    def _detect_obfuscation(self) -> list[dict[str, Any]]:
        techniques: list[dict[str, Any]] = []
        jmp_count = self._count_opcode_occurrences("/c jmp")
        call_count = self._count_opcode_occurrences("/c call")
        if jmp_count > 100 or call_count > 200:
            techniques.append(
                {
                    "technique": "Code Obfuscation",
                    "description": f"High number of jumps ({jmp_count}) and calls ({call_count})",
                    "severity": "Medium",
                }
            )
        return techniques

    def _count_opcode_occurrences(self, cmd: str) -> int:
        output = safe_cmd(self.r2, cmd)
        if not output or not output.strip():
            return 0
        return len(output.strip().split("\n"))

    def _detect_self_modifying(self) -> list[dict[str, Any]]:
        modify_patterns = safe_cmd(self.r2, "/c mov.*cs:|/c mov.*ds:")
        if modify_patterns and modify_patterns.strip():
            return [
                {
                    "technique": "Self-Modifying Code",
                    "description": "Code segment modifications detected",
                    "severity": "High",
                }
            ]
        return []

    def _detect_api_hashing(self) -> list[dict[str, Any]]:
        hash_patterns = safe_cmd(self.r2, "iz~hash|iz~crc32|iz~fnv")
        if hash_patterns and hash_patterns.strip():
            return [
                {
                    "technique": "API Hashing",
                    "description": "Hash-based API resolution detected",
                    "severity": "Medium",
                }
            ]
        return []

    def _detect_injection_apis(self) -> list[dict[str, Any]]:
        injection_apis = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
        imports = safe_cmdj(self.r2, "iij")
        injection_found = 0
        if imports:
            for imp in imports:
                if imp.get("name") in injection_apis:
                    injection_found += 1
        if injection_found >= 2:
            return [
                {
                    "technique": "DLL Injection",
                    "description": f"Process injection APIs detected ({injection_found})",
                    "severity": "High",
                }
            ]
        return []

    def _match_suspicious_api(self, imp: dict[str, Any]) -> dict[str, Any] | None:
        suspicious_categories = {
            "Process/Thread": [
                "CreateProcess",
                "CreateThread",
                "OpenProcess",
                "TerminateProcess",
            ],
            "Memory": [
                "VirtualAlloc",
                "VirtualProtect",
                "HeapAlloc",
                "MapViewOfFile",
            ],
            "File System": [
                "CreateFile",
                "DeleteFile",
                "MoveFile",
                "FindFirstFile",
            ],
            "Registry": [
                "RegOpenKey",
                "RegSetValue",
                "RegDeleteKey",
                "RegEnumKey",
            ],
            "Network": ["WSAStartup", "socket", "connect", "HttpOpenRequest"],
            "Crypto": ["CryptAcquireContext", "CryptCreateHash", "CryptEncrypt"],
            "Service": ["CreateService", "StartService", "OpenSCManager"],
        }
        imp_name = imp.get("name", "")
        for category, apis in suspicious_categories.items():
            for api in apis:
                if api in imp_name:
                    return {
                        "api": imp_name,
                        "category": category,
                        "address": hex(imp.get("plt", 0)),
                    }
        return None

    def _detect_timing_checks_detailed(self) -> dict[str, Any]:
        """Detect timing-based evasion techniques with detailed evidence"""
        result = {"detected": False, "evidence": []}

        try:
            # Check for timing APIs
            timing_apis = {
                "GetTickCount": "Basic timing check",
                "QueryPerformanceCounter": "High-resolution timing",
                "timeGetTime": "Multimedia timer",
                "GetSystemTimeAsFileTime": "File time check",
                "NtQuerySystemTime": "Native timing check",
            }

            imports = safe_cmdj(self.r2, "iij")
            if imports:
                timing_imports = []
                for imp in imports:
                    func_name = imp.get("name", "")
                    if func_name in timing_apis:
                        timing_imports.append(
                            {
                                "function": func_name,
                                "description": timing_apis[func_name],
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
            rdtsc_usage = safe_cmd(self.r2, "/c rdtsc")
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
            # Check for username queries
            username_checks = safe_cmd(self.r2, "iz~GetUserName|iz~USER")
            if username_checks and username_checks.strip():
                checks.append(
                    {
                        "type": "Username Check",
                        "description": "Username enumeration detected",
                    }
                )

            # Check for computer name queries
            computer_checks = safe_cmd(self.r2, "iz~GetComputerName|iz~COMPUTERNAME")
            if computer_checks and computer_checks.strip():
                checks.append(
                    {
                        "type": "Computer Name Check",
                        "description": "Computer name enumeration detected",
                    }
                )

            # Check for system info queries
            sysinfo_checks = safe_cmd(self.r2, "ii~GetSystemInfo|ii~GlobalMemoryStatus")
            if sysinfo_checks and sysinfo_checks.strip():
                checks.append(
                    {
                        "type": "System Info Check",
                        "description": "System information queries detected",
                    }
                )

            # Check for process enumeration
            proc_checks = safe_cmd(self.r2, "ii~CreateToolhelp32Snapshot|ii~Process32")
            if proc_checks and proc_checks.strip():
                checks.append(
                    {
                        "type": "Process Enumeration",
                        "description": "Process enumeration detected",
                    }
                )

        except Exception as e:
            logger.error(f"Error detecting environment checks: {e}")

        return checks
