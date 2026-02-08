from __future__ import annotations

from pathlib import Path

from r2inspect.config import Config
from r2inspect.modules.import_analyzer import NETWORK_CATEGORY, ImportAnalyzer


def test_import_analyzer_helpers(tmp_path: Path):
    config = Config(str(tmp_path / "config.json"))
    analyzer = ImportAnalyzer(adapter=None, config=config)

    imports = [
        {"name": "IsDebuggerPresent", "library": "kernel32.dll"},
        {"name": "CheckRemoteDebuggerPresent", "library": "kernel32.dll"},
        {"name": "CreateProcess", "library": "kernel32.dll"},
        {"name": "CreateThread", "library": "kernel32.dll"},
        {"name": "OpenProcess", "library": "kernel32.dll"},
        {"name": "VirtualAlloc", "library": "kernel32.dll"},
        {"name": "VirtualProtect", "library": "kernel32.dll"},
        {"name": "HeapAlloc", "library": "kernel32.dll"},
        {"name": "RegSetValueEx", "library": "advapi32.dll"},
        {"name": "RegCreateKeyEx", "library": "advapi32.dll"},
        {"name": "RegOpenKeyEx", "library": "advapi32.dll"},
        {"name": "RegCloseKey", "library": "advapi32.dll"},
        {"name": "InternetOpen", "library": "wininet.dll"},
        {"name": "socket", "library": "ws2_32.dll"},
        {"name": "connect", "library": "ws2_32.dll"},
        {"name": "GetProcAddress", "library": "kernel32.dll"},
    ]

    analysis = analyzer.analyze_api_usage(imports)
    assert analysis["risk_score"] > 0

    obfuscation = analyzer.detect_api_obfuscation(imports)
    assert obfuscation["detected"] is True

    patterns = analyzer._find_suspicious_patterns(
        [
            {"name": "VirtualAllocEx", "category": "Process/Thread Management"},
            {"name": "WriteProcessMemory", "category": "Process/Thread Management"},
            {"name": "CreateRemoteThread", "category": "Process/Thread Management"},
            {"name": "InternetOpen", "category": NETWORK_CATEGORY},
            {"name": "socket", "category": NETWORK_CATEGORY},
            {"name": "connect", "category": NETWORK_CATEGORY},
            {"name": "IsDebuggerPresent", "category": "Anti-Analysis"},
        ]
    )
    assert any(p["pattern"] == "DLL Injection" for p in patterns)
    assert any(p["pattern"] == "Anti-Analysis" for p in patterns)

    dlls = ["kernel32.dll", "psapi.dll", "custom.dll"]
    deps = analyzer.analyze_dll_dependencies(dlls)
    assert "kernel32.dll" in deps["common_dlls"]
    assert "psapi.dll" in deps["suspicious_dlls"]

    anomalies = analyzer.detect_import_anomalies([])
    assert anomalies["count"] == 1

    assert analyzer._is_candidate_api_string("CreateProcess", []) is True
    assert analyzer._matches_known_api("CreateProcess") is True
