#!/usr/bin/env python3
"""Import analysis module."""

import re
from collections import Counter
from typing import Any

from ..abstractions import BaseAnalyzer
from ..utils.command_helpers import cmdj as cmdj_helper
from ..utils.logger import get_logger
from .domain_helpers import clamp_score
from .import_domain import (
    NETWORK_CATEGORY,
    assess_api_risk,
    build_api_categories,
    categorize_apis,
    find_max_risk_score,
    find_suspicious_patterns,
    risk_level_from_score,
)

logger = get_logger(__name__)


class ImportAnalyzer(BaseAnalyzer):
    """Import table analysis using backend data."""

    def __init__(self, adapter: Any, config: Any | None = None) -> None:
        super().__init__(adapter=adapter, config=config)
        self._setup_api_categories()
        self._risk_categories = build_api_categories()

    def get_category(self) -> str:
        return "metadata"

    def get_description(self) -> str:
        return "Analyzes imported functions and DLL dependencies with risk assessment and suspicious pattern detection"

    def supports_format(self, file_format: str) -> bool:
        return file_format.upper() in {"PE", "PE32", "PE32+", "DLL", "EXE"}

    def _setup_api_categories(self) -> None:
        """Initialize API categorization data"""
        # Categorized suspicious APIs
        self.api_categories = {
            "Process/Thread Management": [
                "CreateProcess",
                "CreateProcessA",
                "CreateProcessW",
                "CreateThread",
                "CreateRemoteThread",
                "OpenProcess",
                "TerminateProcess",
                "ExitProcess",
                "GetCurrentProcess",
                "SetThreadContext",
                "GetThreadContext",
                "SuspendThread",
                "ResumeThread",
                "WaitForSingleObject",
            ],
            "Memory Management": [
                "VirtualAlloc",
                "VirtualAllocEx",
                "VirtualProtect",
                "VirtualProtectEx",
                "HeapAlloc",
                "HeapCreate",
                "MapViewOfFile",
                "UnmapViewOfFile",
                "VirtualFree",
                "VirtualFreeEx",
                "WriteProcessMemory",
                "ReadProcessMemory",
            ],
            "File System": [
                "CreateFile",
                "CreateFileA",
                "CreateFileW",
                "DeleteFile",
                "MoveFile",
                "CopyFile",
                "FindFirstFile",
                "FindNextFile",
                "GetFileAttributes",
                "SetFileAttributes",
                "WriteFile",
                "ReadFile",
                "CreateDirectory",
                "RemoveDirectory",
            ],
            "Registry": [
                "RegOpenKey",
                "RegOpenKeyEx",
                "RegCreateKey",
                "RegCreateKeyEx",
                "RegSetValue",
                "RegSetValueEx",
                "RegQueryValue",
                "RegQueryValueEx",
                "RegDeleteKey",
                "RegDeleteValue",
                "RegEnumKey",
                "RegEnumValue",
                "RegCloseKey",
            ],
            NETWORK_CATEGORY: [
                "WSAStartup",
                "WSACleanup",
                "socket",
                "connect",
                "bind",
                "listen",
                "accept",
                "send",
                "recv",
                "closesocket",
                "InternetOpen",
                "InternetConnect",
                "HttpOpenRequest",
                "HttpSendRequest",
                "InternetReadFile",
                "URLDownloadToFile",
                "WinHttpOpen",
                "WinHttpConnect",
            ],
            "Cryptography": [
                "CryptAcquireContext",
                "CryptCreateHash",
                "CryptHashData",
                "CryptDeriveKey",
                "CryptEncrypt",
                "CryptDecrypt",
                "CryptGenKey",
                "CryptReleaseContext",
                "CryptDestroyHash",
                "BCryptOpenAlgorithmProvider",
                "BCryptCreateHash",
            ],
            "Service Management": [
                "OpenSCManager",
                "CreateService",
                "OpenService",
                "StartService",
                "ControlService",
                "DeleteService",
                "CloseServiceHandle",
                "QueryServiceStatus",
            ],
            "Dynamic Loading": [
                "LoadLibrary",
                "LoadLibraryA",
                "LoadLibraryW",
                "LoadLibraryEx",
                "GetProcAddress",
                "FreeLibrary",
                "GetModuleHandle",
                "GetModuleFileName",
            ],
            "Anti-Analysis": [
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
                "OutputDebugString",
                "GetTickCount",
                "QueryPerformanceCounter",
                "NtQueryInformationProcess",
                "ZwQueryInformationProcess",
            ],
            "Persistence": [
                "RegSetValueEx",
                "CreateService",
                "SetWindowsHookEx",
                "SetFileAttributes",
                "CopyFile",
                "MoveFile",
            ],
        }

    def analyze(self) -> dict[str, Any]:
        """Run complete import analysis"""
        result = self._init_result_structure(
            {
                "total_imports": 0,
                "total_dlls": 0,
                "imports": [],
                "dlls": [],
                "statistics": {},
                "api_analysis": {},
                "obfuscation": {},
                "dll_analysis": {},
                "anomalies": {},
                "forwarding": {},
            }
        )

        try:
            self._log_info("Starting import analysis")

            # Get basic import information
            imports = self.get_imports()
            dlls = list({imp.get("library", "") for imp in imports if imp.get("library")})

            result["imports"] = imports
            result["dlls"] = dlls
            result["total_imports"] = len(imports)
            result["total_dlls"] = len(dlls)

            # Perform various analyses
            result["api_analysis"] = self.analyze_api_usage(imports)
            result["obfuscation"] = self.detect_api_obfuscation(imports)
            result["dll_analysis"] = self.analyze_dll_dependencies(dlls)
            result["anomalies"] = self.detect_import_anomalies(imports)
            result["forwarding"] = self.check_import_forwarding()

            # Calculate overall risk score
            total_risk = (
                result["api_analysis"].get("risk_score", 0) * 0.4
                + result["obfuscation"].get("score", 0) * 0.3
                + (result["anomalies"].get("count", 0) * 10) * 0.2
                + (len(result["dll_analysis"].get("suspicious_dlls", [])) * 5) * 0.1
            )

            risk_level = self._get_risk_level(total_risk)
            suspicious_indicators = self._count_suspicious_indicators(result)

            result["statistics"] = {
                "total_risk_score": min(total_risk, 100),
                "risk_level": risk_level,
                "suspicious_indicators": suspicious_indicators,
            }

            result["available"] = True
            self._log_info(f"Analyzed {len(imports)} imports from {len(dlls)} DLLs")

        except Exception as e:
            result["error"] = str(e)
            self._log_error(f"Import analysis failed: {e}")

        return result

    def _get_risk_level(self, total_risk: float) -> str:
        if total_risk >= 70:
            return "HIGH"
        if total_risk >= 40:
            return "MEDIUM"
        return "LOW"

    def _count_suspicious_indicators(self, result: dict[str, Any]) -> int:
        api_analysis = result.get("api_analysis", {})
        obfuscation = result.get("obfuscation", {})
        anomalies = result.get("anomalies", {})
        return (
            len(api_analysis.get("suspicious_apis", []))
            + len(obfuscation.get("indicators", []))
            + int(anomalies.get("count", 0))
        )

    def get_imports(self) -> list[dict[str, Any]]:
        """Get all imported functions with analysis"""
        imports_info = []

        try:
            # Get imports from radare2
            imports = self._cmdj("iij", [])

            if imports:
                for imp in imports:
                    import_analysis = self._analyze_import(imp)
                    imports_info.append(import_analysis)

        except Exception as e:
            logger.error(f"Error getting imports: {e}")

        return imports_info

    def _analyze_import(self, imp: dict[str, Any]) -> dict[str, Any]:
        """Analyze a single import"""
        analysis = {
            "name": imp.get("name", "unknown"),
            "address": hex(imp.get("plt", 0)),
            "ordinal": imp.get("ordinal", 0),
            "library": imp.get("libname", "unknown"),
            "type": imp.get("type", "unknown"),
            "category": "Unknown",
            "risk_score": 0,
            "risk_level": "Low",
            "risk_tags": [],
            "description": "",
        }

        try:
            func_name = imp.get("name", "")

            # Calculate detailed risk score
            risk_analysis = self._calculate_risk_score(func_name)
            analysis.update(risk_analysis)

            # Categorize the function
            for category, functions in self.api_categories.items():
                if any(api in func_name for api in functions):
                    analysis["category"] = category
                    analysis["description"] = self._get_function_description(func_name)
                    break

        except Exception as e:
            logger.error(f"Error analyzing import: {e}")
            analysis["error"] = str(e)

        return analysis

    def _calculate_risk_score(self, func_name: str) -> dict[str, Any]:
        """Calculate detailed risk score (0-100) with specific tags"""
        max_score, tags = find_max_risk_score(func_name, self._risk_categories)
        risk_level = risk_level_from_score(max_score)

        return {
            "risk_score": max_score,
            "risk_level": risk_level,
            "risk_tags": tags,
        }

    def _get_function_description(self, func_name: str) -> str:
        """Get description for common functions"""
        descriptions = {
            "CreateProcess": "Creates a new process",
            "CreateRemoteThread": "Creates thread in another process (DLL injection)",
            "WriteProcessMemory": "Writes to another process memory",
            "VirtualAlloc": "Allocates virtual memory",
            "VirtualAllocEx": "Allocates memory in another process",
            "LoadLibrary": "Loads a DLL dynamically",
            "GetProcAddress": "Gets address of exported function",
            "RegSetValue": "Sets registry value",
            "CreateFile": "Creates or opens file",
            "IsDebuggerPresent": "Checks if debugger is present",
            "CreateService": "Creates a Windows service",
            "CryptEncrypt": "Encrypts data",
            "InternetOpen": "Initializes WinINet",
            "URLDownloadToFile": "Downloads file from URL",
        }

        for api, desc in descriptions.items():
            if api in func_name:
                return desc

        return ""

    def get_import_statistics(self) -> dict[str, Any]:
        """Get statistics about imports"""
        stats = {
            "total_imports": 0,
            "unique_libraries": 0,
            "category_distribution": {},
            "risk_distribution": {},
            "library_distribution": {},
            "suspicious_patterns": [],
        }

        try:
            imports = self.get_imports()

            if imports:
                stats["total_imports"] = len(imports)

                # Count categories and risks
                categories = [imp["category"] for imp in imports]
                risks = [imp["risk_level"] for imp in imports]
                libraries = [imp["library"] for imp in imports]

                stats["category_distribution"] = dict(Counter(categories))
                stats["risk_distribution"] = dict(Counter(risks))
                stats["library_distribution"] = dict(Counter(libraries))
                stats["unique_libraries"] = len(set(libraries))

                stats["suspicious_patterns"] = find_suspicious_patterns(imports)

        except Exception as e:
            logger.error(f"Error getting import statistics: {e}")

        return stats

    def get_missing_imports(self) -> list[str]:
        missing = []

        try:
            # Get all string references that look like API calls
            if self.adapter is not None and hasattr(self.adapter, "get_strings"):
                strings = self.adapter.get_strings()
            else:
                strings = self._cmdj("izj", [])
            imported_apis = [imp["name"] for imp in self.get_imports()]

            if strings:
                for string_info in strings:
                    string_val = string_info.get("string", "")
                    if not self._is_candidate_api_string(string_val, imported_apis):
                        continue
                    if self._matches_known_api(string_val):
                        missing.append(string_val)

        except Exception as e:
            logger.error(f"Error detecting missing imports: {e}")

        return list(set(missing))  # Remove duplicates

    def _is_candidate_api_string(self, string_val: str, imported_apis: list[str]) -> bool:
        return (
            len(string_val) > 3
            and string_val[0].isupper()
            and any(c.islower() for c in string_val)
            and string_val not in imported_apis
        )

    def _matches_known_api(self, string_val: str) -> bool:
        for _, apis in self.api_categories.items():
            if any(api in string_val for api in apis):
                return True
        return False

    def analyze_api_usage(self, imports: list[dict]) -> dict[str, Any]:
        try:
            if not imports:
                return {"categories": {}, "suspicious_apis": [], "risk_score": 0}

            categories = categorize_apis(imports, self.api_categories)
            suspicious_apis, risk_score = assess_api_risk(categories)

            return {
                "categories": categories,
                "suspicious_apis": suspicious_apis,
                "risk_score": clamp_score(risk_score),
            }

        except Exception as e:
            logger.error(f"Error analyzing API usage: {e}")
            return {"categories": {}, "suspicious_apis": [], "risk_score": 0}

    def detect_api_obfuscation(self, imports: list[dict]) -> dict[str, Any]:
        try:
            obfuscation_indicators = []

            # Check for GetProcAddress usage (dynamic API loading)
            getproc_count = sum(1 for imp in imports if "GetProcAddress" in imp.get("name", ""))
            if getproc_count > 0:
                obfuscation_indicators.append(
                    {
                        "type": "dynamic_loading",
                        "description": "GetProcAddress usage detected - possible dynamic API loading",
                        "count": getproc_count,
                    }
                )

            # Check for LoadLibrary usage
            loadlib_count = sum(1 for imp in imports if "LoadLibrary" in imp.get("name", ""))
            if loadlib_count > 0:
                obfuscation_indicators.append(
                    {
                        "type": "dynamic_library_loading",
                        "description": "LoadLibrary usage detected - possible dynamic library loading",
                        "count": loadlib_count,
                    }
                )

            # Check for very few imports (possible static linking or packing)
            if len(imports) < 10:
                obfuscation_indicators.append(
                    {
                        "type": "few_imports",
                        "description": f"Very few imports ({len(imports)}) - possible static linking or packing",
                        "count": len(imports),
                    }
                )

            # Check for ordinal-only imports
            ordinal_only = sum(
                1 for imp in imports if not imp.get("name") and imp.get("ordinal", 0) > 0
            )
            if ordinal_only > 0:
                obfuscation_indicators.append(
                    {
                        "type": "ordinal_imports",
                        "description": "Ordinal-only imports detected - possible obfuscation",
                        "count": ordinal_only,
                    }
                )

            return {
                "detected": len(obfuscation_indicators) > 0,
                "indicators": obfuscation_indicators,
                "score": min(len(obfuscation_indicators) * 20, 100),
            }

        except Exception as e:
            logger.error(f"Error detecting API obfuscation: {e}")
            return {"detected": False, "indicators": [], "score": 0}

    def analyze_dll_dependencies(self, dlls: list[str]) -> dict[str, Any]:
        try:
            if not dlls:
                return {"common_dlls": [], "suspicious_dlls": [], "analysis": {}}

            # Common system DLLs
            common_system_dlls = [
                "kernel32.dll",
                "user32.dll",
                "advapi32.dll",
                "ntdll.dll",
                "msvcrt.dll",
                "shell32.dll",
                "ole32.dll",
                "oleaut32.dll",
                "ws2_32.dll",
                "wininet.dll",
                "urlmon.dll",
                "shlwapi.dll",
            ]

            # Suspicious DLLs that might indicate malicious behavior
            suspicious_dlls = [
                "psapi.dll",  # Process enumeration
                "imagehlp.dll",  # PE manipulation
                "dbghelp.dll",  # Debugging
                "winsock.dll",  # Older networking
                "rasapi32.dll",  # Remote access
                "netapi32.dll",  # Network management
                "secur32.dll",  # Security
                "crypt32.dll",  # Cryptography
                "wintrust.dll",  # Trust verification
                "version.dll",  # Version info
                "setupapi.dll",  # Setup/installation
                "cfgmgr32.dll",  # Configuration management
            ]

            common_found = []
            suspicious_found = []

            for dll in dlls:
                dll_lower = dll.lower()
                if dll_lower in [d.lower() for d in common_system_dlls]:
                    common_found.append(dll)
                if dll_lower in [d.lower() for d in suspicious_dlls]:
                    suspicious_found.append(dll)

            # Analysis
            analysis = {
                "total_dlls": len(dlls),
                "common_ratio": len(common_found) / len(dlls) if dlls else 0,
                "suspicious_ratio": len(suspicious_found) / len(dlls) if dlls else 0,
                "unique_dlls": len({dll.lower() for dll in dlls}),
            }

            return {
                "common_dlls": common_found,
                "suspicious_dlls": suspicious_found,
                "analysis": analysis,
                "all_dlls": dlls,
            }

        except Exception as e:
            logger.error(f"Error analyzing DLL dependencies: {e}")
            return {"common_dlls": [], "suspicious_dlls": [], "analysis": {}}

    def detect_import_anomalies(self, imports: list[dict[str, Any]]) -> dict[str, Any]:
        """Detect anomalies in import table"""
        try:
            anomalies: list[dict[str, Any]] = []

            if not imports:
                anomalies.append(
                    {
                        "type": "no_imports",
                        "description": "No imports found - possible packing or static linking",
                        "severity": "HIGH",
                    }
                )
                return {"anomalies": anomalies, "count": len(anomalies)}

            # Check for duplicate imports
            import_names = [imp.get("name", "") for imp in imports if imp.get("name")]
            duplicates = [name for name, count in Counter(import_names).items() if count > 1]

            if duplicates:
                anomalies.append(
                    {
                        "type": "duplicate_imports",
                        "description": f"Duplicate imports found: {', '.join(duplicates[:5])}",
                        "severity": "MEDIUM",
                        "count": len(duplicates),
                    }
                )

            # Check for imports from unusual DLLs
            unusual_dlls: list[str] = []
            for imp in imports:
                dll = imp.get("dll", "").lower()
                if (
                    dll
                    and dll not in unusual_dlls
                    and not any(
                        common in dll
                        for common in [
                            "kernel32",
                            "user32",
                            "advapi32",
                            "ntdll",
                            "msvcrt",
                        ]
                    )
                ):
                    unusual_dlls.append(dll)

            if len(unusual_dlls) > 5:
                anomalies.append(
                    {
                        "type": "many_unusual_dlls",
                        "description": f"Many unusual DLLs: {len(unusual_dlls)} found",
                        "severity": "MEDIUM",
                        "dlls": unusual_dlls[:10],  # Show first 10
                    }
                )

            # Check for very high number of imports
            if len(imports) > 500:
                anomalies.append(
                    {
                        "type": "excessive_imports",
                        "description": f"Excessive number of imports: {len(imports)}",
                        "severity": "MEDIUM",
                    }
                )

            return {"anomalies": anomalies, "count": len(anomalies)}

        except Exception as e:
            logger.error(f"Error detecting import anomalies: {e}")
            return {"anomalies": [], "count": 0}

    def check_import_forwarding(self) -> dict[str, Any]:
        """Check for import forwarding"""
        try:
            # Look for forwarded imports in strings
            strings = self._cmdj("izj", [])
            if not strings:
                return {"detected": False, "forwards": []}

            forwards = []
            for string_entry in strings:
                if isinstance(string_entry, dict) and "string" in string_entry:
                    string_value = string_entry["string"]
                    # Look for DLL.function pattern (typical forwarding)
                    if re.match(r"^\\w+\\.\\w+$", string_value):
                        forwards.append(
                            {
                                "forward": string_value,
                                "address": string_entry.get("vaddr", 0),
                            }
                        )

            return {
                "detected": len(forwards) > 0,
                "forwards": forwards,
                "count": len(forwards),
            }

        except Exception as e:
            logger.error(f"Error checking import forwarding: {e}")
            return {"detected": False, "forwards": []}

    def _cmdj(self, command: str, default: Any) -> Any:
        return cmdj_helper(self.adapter, self.r2, command, default)
