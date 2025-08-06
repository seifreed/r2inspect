#!/usr/bin/env python3
"""
Import Analysis Module using r2pipe
"""

import re
from collections import Counter
from typing import Any, Dict, List

from ..utils.logger import get_logger
from ..utils.r2_helpers import safe_cmdj

logger = get_logger(__name__)


class ImportAnalyzer:
    """Import table analysis using radare2"""

    def __init__(self, r2, config):
        self.r2 = r2
        self.config = config

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
            "Network/Internet": [
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

    def get_imports(self) -> List[Dict[str, Any]]:
        """Get all imported functions with analysis"""
        imports_info = []

        try:
            # Get imports from radare2
            imports = safe_cmdj(self.r2, "iij")

            if imports:
                for imp in imports:
                    import_analysis = self._analyze_import(imp)
                    imports_info.append(import_analysis)

        except Exception as e:
            logger.error(f"Error getting imports: {e}")

        return imports_info

    def _analyze_import(self, imp: Dict[str, Any]) -> Dict[str, Any]:
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

    def _calculate_risk_score(self, func_name: str) -> Dict[str, Any]:
        """Calculate detailed risk score (0-100) with specific tags"""
        risk_analysis = {"risk_score": 0, "risk_level": "Low", "risk_tags": []}

        # High-risk injection/manipulation APIs (80-100 points)
        injection_apis = {
            "CreateRemoteThread": (95, "Remote Thread Injection"),
            "WriteProcessMemory": (90, "Process Memory Manipulation"),
            "VirtualAllocEx": (85, "Remote Memory Allocation"),
            "SetThreadContext": (90, "Thread Context Manipulation"),
            "QueueUserAPC": (85, "APC Injection"),
            "NtMapViewOfSection": (90, "Section Mapping Injection"),
        }

        # Anti-analysis APIs (70-90 points)
        anti_analysis_apis = {
            "IsDebuggerPresent": (75, "Anti-Debug"),
            "CheckRemoteDebuggerPresent": (80, "Remote Debug Detection"),
            "NtQueryInformationProcess": (85, "Process Information Query"),
            "QueryPerformanceCounter": (60, "Timing Check"),
            "GetTickCount": (50, "Timing Check"),
            "OutputDebugString": (65, "Debug String Check"),
        }

        # Cryptography APIs (50-80 points)
        crypto_apis = {
            "CryptEncrypt": (70, "Data Encryption"),
            "CryptDecrypt": (65, "Data Decryption"),
            "CryptCreateHash": (55, "Hash Creation"),
            "BCryptEncrypt": (75, "Modern Encryption"),
            "CryptGenKey": (60, "Key Generation"),
        }

        # Persistence APIs (60-80 points)
        persistence_apis = {
            "CreateService": (80, "Service Creation"),
            "SetWindowsHookEx": (75, "Hook Installation"),
            "RegSetValueEx": (65, "Registry Modification"),
            "CopyFile": (40, "File Copy"),
            "MoveFile": (35, "File Move"),
        }

        # Network APIs (40-70 points)
        network_apis = {
            "URLDownloadToFile": (70, "File Download"),
            "InternetOpen": (50, "Internet Access"),
            "WinHttpSendRequest": (60, "HTTP Request"),
            "socket": (45, "Network Socket"),
            "connect": (50, "Network Connection"),
        }

        # Process/Thread APIs (50-80 points)
        process_apis = {
            "CreateProcess": (65, "Process Creation"),
            "OpenProcess": (60, "Process Access"),
            "TerminateProcess": (70, "Process Termination"),
            "CreateThread": (45, "Thread Creation"),
            "SuspendThread": (55, "Thread Suspension"),
        }

        # Memory APIs (40-70 points)
        memory_apis = {
            "VirtualAlloc": (50, "Memory Allocation"),
            "VirtualProtect": (65, "Memory Protection Change"),
            "HeapAlloc": (30, "Heap Allocation"),
            "MapViewOfFile": (55, "File Mapping"),
        }

        # Dynamic loading APIs (30-60 points)
        loading_apis = {
            "LoadLibrary": (45, "Dynamic Library Loading"),
            "GetProcAddress": (50, "Function Address Resolution"),
            "FreeLibrary": (25, "Library Unloading"),
        }

        # Check all API categories
        api_categories = [
            injection_apis,
            anti_analysis_apis,
            crypto_apis,
            persistence_apis,
            network_apis,
            process_apis,
            memory_apis,
            loading_apis,
        ]

        max_score = 0
        for api_dict in api_categories:
            for api_name, (score, tag) in api_dict.items():
                if api_name in func_name:
                    if score > max_score:
                        max_score = score
                        risk_analysis["risk_tags"] = [tag]
                    elif score == max_score:
                        risk_analysis["risk_tags"].append(tag)

        risk_analysis["risk_score"] = max_score

        # Determine risk level based on score
        if max_score >= 80:
            risk_analysis["risk_level"] = "Critical"
        elif max_score >= 65:
            risk_analysis["risk_level"] = "High"
        elif max_score >= 45:
            risk_analysis["risk_level"] = "Medium"
        elif max_score >= 25:
            risk_analysis["risk_level"] = "Low"
        else:
            risk_analysis["risk_level"] = "Minimal"

        return risk_analysis

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

    def get_import_statistics(self) -> Dict[str, Any]:
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

                # Find suspicious patterns
                stats["suspicious_patterns"] = self._find_suspicious_patterns(imports)

        except Exception as e:
            logger.error(f"Error getting import statistics: {e}")

        return stats

    def _find_suspicious_patterns(self, imports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find suspicious import patterns"""
        patterns = []

        try:
            import_names = [imp["name"] for imp in imports]
            categories = [imp["category"] for imp in imports]

            # Check for DLL injection pattern
            injection_apis = [
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
            ]
            injection_count = sum(
                1 for name in import_names if any(api in name for api in injection_apis)
            )

            if injection_count >= 2:
                patterns.append(
                    {
                        "pattern": "DLL Injection",
                        "description": "APIs commonly used for DLL injection detected",
                        "severity": "High",
                        "count": injection_count,
                    }
                )

            # Check for process hollowing pattern
            hollowing_apis = [
                "CreateProcess",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "SetThreadContext",
                "ResumeThread",
            ]
            hollowing_count = sum(
                1 for name in import_names if any(api in name for api in hollowing_apis)
            )

            if hollowing_count >= 3:
                patterns.append(
                    {
                        "pattern": "Process Hollowing",
                        "description": "APIs commonly used for process hollowing detected",
                        "severity": "High",
                        "count": hollowing_count,
                    }
                )

            # Check for keylogging pattern
            keylog_apis = ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState"]
            keylog_count = sum(
                1 for name in import_names if any(api in name for api in keylog_apis)
            )

            if keylog_count >= 1:
                patterns.append(
                    {
                        "pattern": "Keylogging",
                        "description": "APIs commonly used for keylogging detected",
                        "severity": "Medium",
                        "count": keylog_count,
                    }
                )

            # Check for network communication
            network_count = categories.count("Network/Internet")
            if network_count > 5:
                patterns.append(
                    {
                        "pattern": "Heavy Network Usage",
                        "description": f"Many network-related APIs ({network_count})",
                        "severity": "Medium",
                        "count": network_count,
                    }
                )

            # Check for anti-analysis
            anti_count = categories.count("Anti-Analysis")
            if anti_count > 0:
                patterns.append(
                    {
                        "pattern": "Anti-Analysis",
                        "description": f"Anti-analysis APIs detected ({anti_count})",
                        "severity": "High",
                        "count": anti_count,
                    }
                )

            # Check for excessive crypto usage
            crypto_count = categories.count("Cryptography")
            if crypto_count > 3:
                patterns.append(
                    {
                        "pattern": "Heavy Cryptography",
                        "description": f"Many cryptographic APIs ({crypto_count})",
                        "severity": "Medium",
                        "count": crypto_count,
                    }
                )

        except Exception as e:
            logger.error(f"Error finding suspicious patterns: {e}")

        return patterns

    def get_missing_imports(self) -> List[str]:
        """Detect potentially missing imports (APIs called but not imported)"""
        missing = []

        try:
            # Get all string references that look like API calls
            strings = safe_cmdj(self.r2, "izj")
            imported_apis = [imp["name"] for imp in self.get_imports()]

            if strings:
                for string_info in strings:
                    string_val = string_info.get("string", "")

                    # Check if string looks like an API name but isn't imported
                    if (
                        len(string_val) > 3
                        and string_val[0].isupper()
                        and any(c.islower() for c in string_val)
                        and string_val not in imported_apis
                    ):
                        # Check if it matches known API patterns
                        for category, apis in self.api_categories.items():
                            if any(api in string_val for api in apis):
                                missing.append(string_val)
                                break

        except Exception as e:
            logger.error(f"Error detecting missing imports: {e}")

        return list(set(missing))  # Remove duplicates

    def analyze_api_usage(self, imports: List[Dict]) -> Dict[str, Any]:
        """Analyze API usage patterns"""
        try:
            if not imports:
                return {"categories": {}, "suspicious_apis": [], "risk_score": 0}

            # Categorize APIs
            categories = {}
            suspicious_apis = []

            for category, apis in self.api_categories.items():
                category_count = 0
                category_apis = []

                for imp in imports:
                    api_name = imp.get("name", "")
                    if any(api.lower() in api_name.lower() for api in apis):
                        category_count += 1
                        category_apis.append(api_name)

                if category_count > 0:
                    categories[category] = {
                        "count": category_count,
                        "apis": category_apis,
                    }

            # Identify suspicious API combinations
            risk_score = 0

            # High-risk combinations
            if "Anti-Analysis" in categories and categories["Anti-Analysis"]["count"] >= 2:
                suspicious_apis.append("Multiple anti-debug APIs detected")
                risk_score += 20

            if "DLL Injection" in categories and categories["DLL Injection"]["count"] >= 3:
                suspicious_apis.append("DLL injection pattern detected")
                risk_score += 30

            if "Process/Thread Management" in categories and "Memory Management" in categories:
                if (
                    categories["Process/Thread Management"]["count"] >= 3
                    and categories["Memory Management"]["count"] >= 3
                ):
                    suspicious_apis.append("Process manipulation pattern detected")
                    risk_score += 25

            if "Registry" in categories and categories["Registry"]["count"] >= 4:
                suspicious_apis.append("Extensive registry manipulation")
                risk_score += 15

            if "Network/Internet" in categories and categories["Network/Internet"]["count"] >= 3:
                suspicious_apis.append("Network communication capabilities")
                risk_score += 10

            return {
                "categories": categories,
                "suspicious_apis": suspicious_apis,
                "risk_score": min(risk_score, 100),
            }

        except Exception as e:
            logger.error(f"Error analyzing API usage: {e}")
            return {"categories": {}, "suspicious_apis": [], "risk_score": 0}

    def detect_api_obfuscation(self, imports: List[Dict]) -> Dict[str, Any]:
        """Detect API obfuscation techniques"""
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

    def analyze_dll_dependencies(self, dlls: List[str]) -> Dict[str, Any]:
        """Analyze DLL dependencies"""
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

    def detect_import_anomalies(self, imports: List[Dict]) -> Dict[str, Any]:
        """Detect anomalies in import table"""
        try:
            anomalies = []

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
            unusual_dlls = []
            for imp in imports:
                dll = imp.get("dll", "").lower()
                if dll and not any(
                    common in dll
                    for common in ["kernel32", "user32", "advapi32", "ntdll", "msvcrt"]
                ):
                    if dll not in unusual_dlls:
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

    def check_import_forwarding(self) -> Dict[str, Any]:
        """Check for import forwarding"""
        try:
            # Look for forwarded imports in strings
            strings = safe_cmdj(self.r2, "izj")
            if not strings:
                return {"detected": False, "forwards": []}

            forwards = []
            for string_entry in strings:
                if isinstance(string_entry, dict) and "string" in string_entry:
                    string_value = string_entry["string"]
                    # Look for DLL.function pattern (typical forwarding)
                    if re.match(r"^[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+$", string_value):
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

    def analyze(self) -> Dict[str, Any]:
        """Run complete import analysis"""
        try:
            # Get basic import information
            import_info = self.get_imports()
            imports = import_info["imports"]
            dlls = import_info["dlls"]

            # Perform various analyses
            api_analysis = self.analyze_api_usage(imports)
            obfuscation_analysis = self.detect_api_obfuscation(imports)
            dll_analysis = self.analyze_dll_dependencies(dlls)
            anomaly_analysis = self.detect_import_anomalies(imports)
            forwarding_analysis = self.check_import_forwarding()

            # Calculate overall risk score
            total_risk = (
                api_analysis.get("risk_score", 0) * 0.4
                + obfuscation_analysis.get("score", 0) * 0.3
                + (anomaly_analysis.get("count", 0) * 10) * 0.2
                + (len(dll_analysis.get("suspicious_dlls", [])) * 5) * 0.1
            )

            return {
                "basic_info": import_info,
                "api_analysis": api_analysis,
                "obfuscation": obfuscation_analysis,
                "dll_analysis": dll_analysis,
                "anomalies": anomaly_analysis,
                "forwarding": forwarding_analysis,
                "summary": {
                    "total_risk_score": min(total_risk, 100),
                    "risk_level": (
                        "HIGH" if total_risk >= 70 else "MEDIUM" if total_risk >= 40 else "LOW"
                    ),
                    "total_imports": len(imports),
                    "total_dlls": len(dlls),
                    "suspicious_indicators": (
                        len(api_analysis.get("suspicious_apis", []))
                        + len(obfuscation_analysis.get("indicators", []))
                        + anomaly_analysis.get("count", 0)
                    ),
                },
            }

        except Exception as e:
            logger.error(f"Error in import analysis: {e}")
            return {
                "basic_info": {"imports": [], "dlls": [], "total_imports": 0},
                "api_analysis": {
                    "categories": {},
                    "suspicious_apis": [],
                    "risk_score": 0,
                },
                "obfuscation": {"detected": False, "indicators": [], "score": 0},
                "dll_analysis": {
                    "common_dlls": [],
                    "suspicious_dlls": [],
                    "analysis": {},
                },
                "anomalies": {"anomalies": [], "count": 0},
                "forwarding": {"detected": False, "forwards": []},
                "summary": {"total_risk_score": 0, "risk_level": "UNKNOWN"},
            }
